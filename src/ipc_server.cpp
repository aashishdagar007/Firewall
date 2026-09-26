#include "ipc_server.hpp"
#include "config_parser.hpp"
#include "logger.hpp"
#include <sstream>
#include <iostream>
#include <vector>
#include <algorithm>

namespace fw {

IpcServer::IpcServer(RuleEngine& engine, LiveStats& stats, Logger* logger,
                     const std::string& pipe_name,
                     const std::wstring& authorized_client_name)
    : engine_(engine), stats_(stats), logger_(logger),
      pipe_name_(pipe_name), authorized_client_name_(authorized_client_name) {
#ifdef _WIN32
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
#endif
}

IpcServer::~IpcServer() {
    stop();
#ifdef _WIN32
    if (stop_event_) {
        CloseHandle(stop_event_);
        stop_event_ = nullptr;
    }
#endif
}

void IpcServer::start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread(&IpcServer::worker_loop, this);
}

void IpcServer::stop() {
    if (!running_.exchange(false)) return;
#ifdef _WIN32
    if (stop_event_) {
        SetEvent(stop_event_);
    }
    if (pipe_handle_ != INVALID_HANDLE_VALUE) {
        // Cancel synchronous I/O and disconnect
        CancelIoEx(pipe_handle_, nullptr);
        DisconnectNamedPipe(pipe_handle_);
    }
#endif
    if (thread_.joinable()) {
        thread_.join();
    }
}

void IpcServer::worker_loop() {
    // Drop elevated privileges on this IPC listener worker thread
    if (!drop_thread_privileges()) {
        if (logger_) {
            logger_->log(LogLevel::LOG_WARN, "[IPC] Failed to drop worker thread privileges; proceeding in restricted mode");
        }
    } else {
        if (logger_) {
            logger_->log(LogLevel::LOG_INFO, "[IPC] Worker thread privileges dropped successfully");
        }
    }

#ifdef _WIN32
    // Convert pipe name to wide string
    int wlen = MultiByteToWideChar(CP_UTF8, 0, pipe_name_.c_str(), -1, nullptr, 0);
    std::wstring wpipe(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, pipe_name_.c_str(), -1, &wpipe[0], wlen);

    // Build strict Security Attributes: SYSTEM (SY) and Administrators (BA) only
    PSECURITY_DESCRIPTOR pSD = nullptr;
    const wchar_t* sddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)";
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, nullptr)) {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = FALSE;
        sa.lpSecurityDescriptor = pSD;

        while (running_) {
            pipe_handle_ = CreateNamedPipeW(
                wpipe.c_str(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096, 4096, 5000,
                &sa);

            if (pipe_handle_ == INVALID_HANDLE_VALUE) {
                if (logger_) logger_->log(LogLevel::LOG_ERROR, "[IPC] CreateNamedPipe failed");
                break;
            }

            OVERLAPPED ov{};
            ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            BOOL connected = ConnectNamedPipe(pipe_handle_, &ov);
            if (!connected && GetLastError() == ERROR_IO_PENDING) {
                HANDLE events[2] = { ov.hEvent, stop_event_ };
                DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
                if (wait == WAIT_OBJECT_0 + 1 || !running_) {
                    CloseHandle(ov.hEvent);
                    CloseHandle(pipe_handle_);
                    pipe_handle_ = INVALID_HANDLE_VALUE;
                    break;
                }
            }
            CloseHandle(ov.hEvent);

            if (!running_) {
                CloseHandle(pipe_handle_);
                pipe_handle_ = INVALID_HANDLE_VALUE;
                break;
            }

            // ── Dynamic Client Identity Check ──────────────────────────────────
            // Verify that the connecting process is the authorized Qt GUI client
            bool authorized = verify_pipe_client_identity(pipe_handle_, authorized_client_name_);
            if (!authorized) {
                ULONG clientPid = 0;
                GetNamedPipeClientProcessId(pipe_handle_, &clientPid);
                if (logger_) {
                    logger_->log(LogLevel::LOG_WARN,
                                 "[IPC] REJECTED unauthorized named pipe client connection (PID: " +
                                 std::to_string(clientPid) + ")");
                }
                DisconnectNamedPipe(pipe_handle_);
                CloseHandle(pipe_handle_);
                pipe_handle_ = INVALID_HANDLE_VALUE;
                continue;
            }

            // Read command from verified client
            char buffer[2048] = {0};
            DWORD bytesRead = 0;
            BOOL readOk = ReadFile(pipe_handle_, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
            if (readOk && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                std::string cmd(buffer);
                // Strip trailing newline / carriage return
                while (!cmd.empty() && (cmd.back() == '\r' || cmd.back() == '\n')) {
                    cmd.pop_back();
                }

                std::string response = process_command(cmd) + "\n";
                DWORD bytesWritten = 0;
                WriteFile(pipe_handle_, response.c_str(), static_cast<DWORD>(response.size()), &bytesWritten, nullptr);
                FlushFileBuffers(pipe_handle_);
            }

            DisconnectNamedPipe(pipe_handle_);
            CloseHandle(pipe_handle_);
            pipe_handle_ = INVALID_HANDLE_VALUE;
        }

        LocalFree(pSD);
    }
#endif
}

std::string IpcServer::process_command(const std::string& cmd) {
    std::istringstream ss(cmd);
    std::string action;
    if (!(ss >> action)) {
        return "{\"ok\":false,\"error\":\"empty command\"}";
    }

    std::string remaining;
    std::getline(ss, remaining);
    if (!remaining.empty() && remaining[0] == ' ') {
        remaining = remaining.substr(1);
    }

    if (action == "ADD_RULE") {
        return handle_add_rule(remaining);
    } else if (action == "DELETE_RULE") {
        return handle_delete_rule(remaining);
    } else if (action == "SET_POLICY") {
        return handle_set_policy(remaining);
    } else if (action == "GET_RULES") {
        return handle_get_rules();
    } else if (action == "GET_STATS") {
        return handle_get_stats();
    }

    return "{\"ok\":false,\"error\":\"unknown command\"}";
}

std::string IpcServer::handle_add_rule(const std::string& params) {
    Rule r;
    // Atomically validate every single field
    if (!ConfigParser::parse_line(params, r)) {
        if (logger_) logger_->log(LogLevel::LOG_WARN, "[IPC] Rejected malformed rule from IPC: " + params);
        return "{\"ok\":false,\"error\":\"invalid rule format or malformed field\"}";
    }

    engine_.add_rule(std::move(r));
    if (logger_) logger_->log(LogLevel::LOG_INFO, "[IPC] Added rule via IPC: " + params);
    return "{\"ok\":true}";
}

std::string IpcServer::handle_delete_rule(const std::string& params) {
    if (params.empty()) {
        return "{\"ok\":false,\"error\":\"missing rule id\"}";
    }

    // Wrap numeric parsing in try/catch for std::invalid_argument / std::out_of_range
    uint32_t id = 0;
    try {
        id = std::stoul(params);
    } catch (const std::invalid_argument&) {
        return "{\"ok\":false,\"error\":\"invalid rule id: non-numeric value\"}";
    } catch (const std::out_of_range&) {
        return "{\"ok\":false,\"error\":\"invalid rule id: out of integer range\"}";
    } catch (...) {
        return "{\"ok\":false,\"error\":\"invalid rule id\"}";
    }

    bool ok = engine_.remove_rule(id);
    if (ok) {
        if (logger_) logger_->log(LogLevel::LOG_INFO, "[IPC] Deleted rule ID " + std::to_string(id));
        return "{\"ok\":true}";
    }
    return "{\"ok\":false,\"error\":\"rule not found\"}";
}

std::string IpcServer::handle_set_policy(const std::string& params) {
    if (params == "ALLOW") {
        engine_.set_default_policy(Action::ALLOW);
        if (logger_) logger_->log(LogLevel::LOG_INFO, "[IPC] Default policy set to ALLOW");
        return "{\"ok\":true,\"policy\":\"ALLOW\"}";
    } else if (params == "BLOCK") {
        engine_.set_default_policy(Action::BLOCK);
        if (logger_) logger_->log(LogLevel::LOG_INFO, "[IPC] Default policy set to BLOCK");
        return "{\"ok\":true,\"policy\":\"BLOCK\"}";
    }
    return "{\"ok\":false,\"error\":\"invalid policy: must be ALLOW or BLOCK\"}";
}

std::string IpcServer::handle_get_rules() {
    auto rules = engine_.get_rules();
    std::ostringstream oss;
    oss << "{\"ok\":true,\"rules\":[";
    for (size_t i = 0; i < rules.size(); ++i) {
        if (i > 0) oss << ",";
        const auto& r = rules[i];
        oss << "{"
            << "\"id\":" << r.id << ","
            << "\"action\":\"" << action_name(r.action) << "\","
            << "\"proto\":\"" << proto_name(r.proto) << "\","
            << "\"src_ip\":\"" << (r.src_ip ? ip4_to_string(r.src_ip) : "*") << "\","
            << "\"dst_ip\":\"" << (r.dst_ip ? ip4_to_string(r.dst_ip) : "*") << "\","
            << "\"dst_port\":" << r.dst_port << ","
            << "\"desc\":\"" << r.description << "\""
            << "}";
    }
    oss << "]}";
    return oss.str();
}

std::string IpcServer::handle_get_stats() {
    std::ostringstream oss;
    oss << "{"
        << "\"ok\":true,"
        << "\"total_packets\":" << stats_.total.load() << ","
        << "\"allowed_packets\":" << stats_.allowed.load() << ","
        << "\"blocked_packets\":" << stats_.blocked.load() << ","
        << "\"total_bytes\":" << stats_.bytes_total.load()
        << "}";
    return oss.str();
}

} // namespace fw
