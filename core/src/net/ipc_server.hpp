#pragma once

#include "platform.hpp"
#include "rule_engine.hpp"
#include "types.hpp"
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <memory>

namespace fw {

class Logger;

// ──────────────────────────────────────────────────────────────
//  ipc_server.hpp  –  Hardened Windows Named Pipe IPC Server
//
//  Security Features:
//    1. Custom DACL on \\.\pipe\aegix_ipc (SYSTEM + Admins only)
//    2. Dynamic Client Process Identity Check on connection:
//       Queries client PID via GetNamedPipeClientProcessId and
//       verifies client executable name/path before processing.
//    3. Reduced Token Worker Thread: drops elevated privileges.
//    4. Robust numeric & rule parsing with atomic rejection.
//    5. Error output sanitization (zero address/trace leakage).
// ──────────────────────────────────────────────────────────────

class IpcServer {
public:
    IpcServer(RuleEngine& engine, LiveStats& stats, Logger* logger,
              const std::string& pipe_name = "\\\\.\\pipe\\aegix_ipc",
              const std::wstring& authorized_client_name = L"aegix-ui.exe");
    ~IpcServer();

    // Start background listening thread
    void start();

    // Stop server and disconnect pipe
    void stop();

    bool is_running() const { return running_; }

    // Execute an IPC command string (also exposed for unit testing)
    std::string process_command(const std::string& cmd);

private:
    void worker_loop();
    std::string handle_add_rule(const std::string& params);
    std::string handle_delete_rule(const std::string& params);
    std::string handle_set_policy(const std::string& params);
    std::string handle_get_rules();
    std::string handle_get_stats();

    RuleEngine&         engine_;
    LiveStats&          stats_;
    Logger*             logger_;
    std::string         pipe_name_;
    std::wstring        authorized_client_name_;
    std::atomic<bool>   running_{false};
    std::thread         thread_;

#ifdef _WIN32
    HANDLE              pipe_handle_{INVALID_HANDLE_VALUE};
    HANDLE              stop_event_{nullptr};
#endif
};

} // namespace fw
