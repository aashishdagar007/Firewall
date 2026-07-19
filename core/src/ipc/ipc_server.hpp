#pragma once
#include <functional>
#include <thread>
#include <atomic>
#include <vector>
#include "shared/messages.h"
#include "engine/rule_engine.hpp"
#include "net/nfq_capture.hpp"

namespace fw {
namespace ipc {

class IpcServer {
public:
    IpcServer(fw::RuleEngine& engine, fw::LiveStats& stats);
    ~IpcServer();

    bool start();
    void stop();

private:
    void listen_loop();
    void handle_client(void* pipe_handle);
    
    fw::RuleEngine& m_engine;
    fw::LiveStats&  m_stats;
    std::atomic<bool> m_running;
    std::thread       m_listener;
};

} // namespace ipc
} // namespace fw
