#pragma once

#include "types.hpp"
#include "process_monitor.hpp"
#include "nfq_capture.hpp"
#include "rule_engine.hpp"
#include <mutex>
#include <thread>
#include <atomic>
#include <queue>
#include <condition_variable>

namespace fw {

class CorrelationEngine {
public:
    CorrelationEngine(RuleEngine& rule_engine, ProcessMonitor& proc_mon);
    ~CorrelationEngine();

    void start();
    void stop();

    void push_network_event(const PacketRecord& record);

private:
    void worker_loop();
    void evaluate_heuristics(const PacketRecord& record);

    RuleEngine& rule_engine_;
    ProcessMonitor& proc_mon_;

    std::atomic<bool> running_{false};
    std::thread worker_thread_;

    std::mutex mtx_;
    std::condition_variable cv_;
    std::queue<PacketRecord> net_events_;
};

} // namespace fw
