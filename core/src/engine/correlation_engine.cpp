#include "engine/correlation_engine.hpp"
#include <iostream>
#include <algorithm>

namespace fw {

CorrelationEngine::CorrelationEngine(RuleEngine& rule_engine, ProcessMonitor& proc_mon)
    : rule_engine_(rule_engine), proc_mon_(proc_mon) {}

CorrelationEngine::~CorrelationEngine() {
    stop();
}

void CorrelationEngine::start() {
    if (running_.exchange(true)) return;
    worker_thread_ = std::thread([this]() { worker_loop(); });
}

void CorrelationEngine::stop() {
    if (!running_.exchange(false)) return;
    cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void CorrelationEngine::push_network_event(const PacketRecord& record) {
    if (!running_) return;
    std::lock_guard<std::mutex> lock(mtx_);
    net_events_.push(record);
    cv_.notify_one();
}

void CorrelationEngine::worker_loop() {
    while (running_) {
        PacketRecord record;
        {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait(lock, [this]() { return !net_events_.empty() || !running_; });
            if (!running_ && net_events_.empty()) break;
            record = net_events_.front();
            net_events_.pop();
        }
        evaluate_heuristics(record);
    }
}

void CorrelationEngine::evaluate_heuristics(const PacketRecord& record) {
    if (record.pid == 0) return;

    // 1. Get process details
    auto snapshot = proc_mon_.snapshot();
    ProcessNetInfo pinfo;
    bool found = false;
    for (const auto& info : snapshot) {
        if (info.pid == record.pid) {
            pinfo = info;
            found = true;
            break;
        }
    }
    if (!found) return;

    // 2. IOA Heuristics
    bool is_malicious = false;
    std::string reason;

    std::string cmd_lower = pinfo.command_line;
    std::transform(cmd_lower.begin(), cmd_lower.end(), cmd_lower.begin(), ::tolower);
    std::string exe_lower = pinfo.exe_name;
    std::transform(exe_lower.begin(), exe_lower.end(), exe_lower.begin(), ::tolower);
    
    if (exe_lower == "powershell.exe" || exe_lower == "cmd.exe") {
        if (cmd_lower.find("-enc") != std::string::npos || 
            cmd_lower.find("bypass") != std::string::npos ||
            cmd_lower.find("hidden") != std::string::npos) {
            is_malicious = true;
            reason = "Suspicious script execution with network connection";
        }
    }

    if (cmd_lower.find("malware_test") != std::string::npos) {
        is_malicious = true;
        reason = "Process command line matched malware signature";
    }

    // 3. Enforcement
    if (is_malicious) {
        // Block the IP
        rule_engine_.ban_ip(record.info.dst_ip, "EDR Verdict: " + reason);
        
        // Block the process dynamically
        proc_mon_.set_app_blocked(pinfo.exe_name, true);
        
        // Push a persistent rule
        Rule dynamic_rule;
        dynamic_rule.action = Action::BLOCK;
        dynamic_rule.process_name = pinfo.exe_name;
        dynamic_rule.description = "XDR Auto-Block: " + reason;
        rule_engine_.add_rule(dynamic_rule);
    }
}

} // namespace fw
