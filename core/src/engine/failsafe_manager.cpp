#include "failsafe_manager.hpp"
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fw {

FailsafeManager::FailsafeManager(RuleEngine& rule_engine)
    : rule_engine_(rule_engine) {}

FailsafeManager::~FailsafeManager() {
    stop();
}

void FailsafeManager::start() {
    if (running_.exchange(true)) return;
    monitor_thread_ = std::thread(&FailsafeManager::failsafe_loop, this);
}

void FailsafeManager::stop() {
    running_ = false;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

void FailsafeManager::set_network_state(NetworkState state) {
    std::lock_guard<std::mutex> lock(mtx_);
    current_state_ = state;
    if (state == NetworkState::UNTRUSTED_WIFI || state == NetworkState::UNTRUSTED_BLUETOOTH) {
        std::cout << "[FailsafeManager] Entered SILENT MONITORING Mode.\n";
    }
}

NetworkState FailsafeManager::get_network_state() const {
    return current_state_; // Atomic enough for this scope, or use lock
}

void FailsafeManager::report_activity(const SuspiciousActivity& activity) {
    std::lock_guard<std::mutex> lock(mtx_);
    
    // If destructive, engage Emergency Kill-Switch immediately
    if (activity.is_destructive) {
        std::cout << "[FailsafeManager] DESTRUCTIVE BEHAVIOR DETECTED. ENGAGING EMERGENCY KILL-SWITCH.\n";
        execute_kill_switch(activity);
        return;
    }
    
    // Otherwise, pend for 30s timeout and prompt user
    pending_activities_.push_back(activity);
    
    if (ui_callback_) {
        ui_callback_(activity);
    } else {
        std::cout << "[FailsafeManager] UI Not attached. Awaiting 30s failsafe timeout...\n";
    }
}

void FailsafeManager::set_ui_prompt_callback(PromptCallback cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    ui_callback_ = std::move(cb);
}

void FailsafeManager::resolve_prompt(const std::string& activity_id, bool terminate) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = pending_activities_.begin(); it != pending_activities_.end(); ++it) {
        if (it->id == activity_id) {
            if (terminate) {
                std::cout << "[FailsafeManager] User elected to terminate activity: " << activity_id << "\n";
                execute_kill_switch(*it);
            } else {
                std::cout << "[FailsafeManager] User elected to allow activity: " << activity_id << "\n";
            }
            pending_activities_.erase(it);
            break;
        }
    }
}

void FailsafeManager::failsafe_loop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        std::lock_guard<std::mutex> lock(mtx_);
        auto now = std::chrono::steady_clock::now();
        
        for (auto it = pending_activities_.begin(); it != pending_activities_.end(); ) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->detection_time).count();
            if (elapsed >= 30) {
                // 30 second timeout reached - apply safe defaults
                std::cout << "[FailsafeManager] 30s TIMEOUT REACHED for " << it->id << ". Enforcing termination.\n";
                execute_kill_switch(*it);
                it = pending_activities_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void FailsafeManager::execute_kill_switch(const SuspiciousActivity& activity) {
    // 1. Block Network Traffic
    if (!activity.source_ip.empty()) {
        struct in_addr addr;
        if (inet_pton(AF_INET, activity.source_ip.c_str(), &addr) == 1) {
            rule_engine_.ban_ip(ntohl(addr.s_addr), "Emergency Kill-Switch: " + activity.description);
        }
    }

    // 2. Terminate Process
#ifdef _WIN32
    if (activity.pid != 0) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, activity.pid);
        if (hProcess != NULL) {
            TerminateProcess(hProcess, 1);
            CloseHandle(hProcess);
            std::cout << "[FailsafeManager] Terminated Process PID: " << activity.pid << "\n";
        }
    }
#endif
    
    // 3. (Optional) Disable Network Interface for catastrophic events
    // if (activity.is_destructive) { system("netsh interface set interface \"Wi-Fi\" admin=disable"); }
}

} // namespace fw
