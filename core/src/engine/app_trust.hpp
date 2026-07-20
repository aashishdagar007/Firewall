#pragma once

#include "failsafe_manager.hpp"
#include <string>
#include <unordered_set>
#include <vector>

namespace fw {

// Structure defining a behavioral rule for a trusted application
struct BehavioralRule {
    std::string parent_exe;      // e.g., "chrome.exe"
    std::string blocked_child;   // e.g., "cmd.exe", "powershell.exe"
    std::string description;     // e.g., "Browser spawned shell"
    bool trigger_kill_switch;
};

class AppTrustManager {
public:
    AppTrustManager(FailsafeManager& failsafe_manager);
    ~AppTrustManager();

    // Verify if an application has a valid, globally trusted signature
    // (e.g., Microsoft, Google, Mozilla).
    bool is_globally_trusted(const std::string& exe_path);

    // Monitor a process event to ensure a trusted app hasn't been hijacked
    // Returns true if behavior is clean, false if malicious behavior detected
    bool evaluate_behavior(const std::string& parent_exe, const std::string& child_exe, uint32_t pid, const std::string& source_ip);

    // Load behavioral heuristics
    void load_heuristics();

private:
    FailsafeManager& failsafe_manager_;
    std::vector<BehavioralRule> rules_;
    std::unordered_set<std::string> known_trusted_publishers_;
};

} // namespace fw
