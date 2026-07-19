#include "ipc_server.hpp"
#include "../util/logger.hpp"
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace fw {
namespace ipc {

IpcServer::IpcServer(fw::RuleEngine& engine, fw::LiveStats& stats)
    : m_engine(engine), m_stats(stats), m_running(false) {}

IpcServer::~IpcServer() {
    stop();
}

bool IpcServer::start() {
    if (m_running) return true;
    m_running = true;
    m_listener = std::thread(&IpcServer::listen_loop, this);
    return true;
}

void IpcServer::stop() {
    m_running = false;
#ifdef _WIN32
    // Connect to own pipe to wake up the blocking ConnectNamedPipe
    HANDLE hPipe = CreateFileA(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
    }
#endif
    if (m_listener.joinable()) {
        m_listener.join();
    }
}

void IpcServer::listen_loop() {
#ifdef _WIN32
    while (m_running) {
        HANDLE hPipe = CreateNamedPipeA(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096, 4096, 0, NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        bool connected = ConnectNamedPipe(hPipe, NULL) ? true : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!m_running) {
            CloseHandle(hPipe);
            break;
        }

        if (connected) {
            // Spawn thread for client
            std::thread(&IpcServer::handle_client, this, (void*)hPipe).detach();
        } else {
            CloseHandle(hPipe);
        }
    }
#else
    // Linux local socket implementation would go here (omitted for brevity as per Windows SCM focus)
#endif
}

void IpcServer::handle_client(void* pipe_handle) {
#ifdef _WIN32
    HANDLE hPipe = (HANDLE)pipe_handle;
    while (m_running) {
        MsgHeader header;
        DWORD bytesRead;
        if (!ReadFile(hPipe, &header, sizeof(header), &bytesRead, NULL) || bytesRead == 0) {
            break; // Client disconnected
        }

        std::vector<uint8_t> payload;
        if (header.length > 0) {
            payload.resize(header.length);
            if (!ReadFile(hPipe, payload.data(), header.length, &bytesRead, NULL) || bytesRead != header.length) {
                break;
            }
        }

        if (header.type == MsgType::GET_STATS) {
            StatsPayload sp;
            sp.total_packets = m_stats.total.load();
            sp.blocked_packets = m_stats.blocked.load();
            sp.bytes_transferred = m_stats.bytes_total.load();
            sp.active_connections = 0; // no direct field in LiveStats

            MsgHeader reply_hdr = {MsgType::STATS_REPLY, sizeof(StatsPayload)};
            DWORD bytesWritten;
            WriteFile(hPipe, &reply_hdr, sizeof(reply_hdr), &bytesWritten, NULL);
            WriteFile(hPipe, &sp, sizeof(sp), &bytesWritten, NULL);
        }
        else if (header.type == MsgType::PING) {
            MsgHeader reply_hdr = {MsgType::PONG, 0};
            DWORD bytesWritten;
            WriteFile(hPipe, &reply_hdr, sizeof(reply_hdr), &bytesWritten, NULL);
        }
    }
    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
#endif
}

} // namespace ipc
} // namespace fw
