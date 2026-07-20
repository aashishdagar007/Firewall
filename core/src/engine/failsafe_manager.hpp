#pragma once

#include "rule_engine.hpp"
#include <string>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include <chrono>

namespace fw {

enum class NetworkState {
    TRUSTED,
    UNTRUSTED_WIFI,
    UNTRUSTED_BLUETOOTH,
    SILENT_MONITORING
};

struct SuspiciousActivity {
    std::string id;
    std::string description;
    std::string source_ip;
    uint32_t pid;
    bool is_destructive;
    std::chrono::steady_clock::time_point detection_time;
};

class FailsafeManager {
public:
    FailsafeManager(RuleEngine& rule_engine);
    ~FailsafeManager();

    void start();
    void stop();

    // Set network state
    void set_network_state(NetworkState state);
    NetworkState get_network_state() const;

    // Report suspicious activity (triggers UI prompt or kill-switch)
    void report_activity(const SuspiciousActivity& activity);

    // Callbacks for UI interaction
    using PromptCallback = std::function<void(const SuspiciousActivity&)>;
    void set_ui_prompt_callback(PromptCallback cb);

    // UI response receiver
    void resolve_prompt(const std::string& activity_id, bool terminate);

private:
    void failsafe_loop();
    void execute_kill_switch(const SuspiciousActivity& activity);

    RuleEngine& rule_engine_;
    NetworkState current_state_{NetworkState::TRUSTED};
    
    std::mutex mtx_;
    std::vector<SuspiciousActivity> pending_activities_;
    PromptCallback ui_callback_;

    std::atomic<bool> running_{false};
    std::thread monitor_thread_;
};

} // namespace fw
