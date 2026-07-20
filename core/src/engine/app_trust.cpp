#include "app_trust.hpp"
#include <iostream>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#ifdef _MSC_VER
#pragma comment(lib, "wintrust.lib")
#endif
#endif

namespace fw {

AppTrustManager::AppTrustManager(FailsafeManager& failsafe_manager)
    : failsafe_manager_(failsafe_manager) {
    
    known_trusted_publishers_ = {
        "Microsoft Corporation",
        "Google LLC",
        "Mozilla Corporation",
        "Apple Inc.",
        "Canonical Ltd."
    };
    
    load_heuristics();
}

AppTrustManager::~AppTrustManager() {}

void AppTrustManager::load_heuristics() {
    // 1. Browsers should never spawn shell interpreters directly
    rules_.push_back({"chrome.exe", "cmd.exe", "Browser spawned command shell", true});
    rules_.push_back({"chrome.exe", "powershell.exe", "Browser spawned PowerShell", true});
    rules_.push_back({"msedge.exe", "cmd.exe", "Browser spawned command shell", true});
    rules_.push_back({"msedge.exe", "powershell.exe", "Browser spawned PowerShell", true});
    rules_.push_back({"firefox.exe", "cmd.exe", "Browser spawned command shell", true});
    
    // 2. Office apps shouldn't spawn shells (Macro malware)
    rules_.push_back({"winword.exe", "cmd.exe", "Word spawned command shell (Macro/Exploit)", true});
    rules_.push_back({"excel.exe", "powershell.exe", "Excel spawned PowerShell (Macro/Exploit)", true});
    rules_.push_back({"powerpnt.exe", "cmd.exe", "PowerPoint spawned command shell", true});
}

bool AppTrustManager::is_globally_trusted(const std::string& exe_path) {
#ifdef _WIN32
    // In a real implementation, this would use WinVerifyTrust to check the digital signature
    // and extract the publisher name to match against known_trusted_publishers_.
    // For this simulation, we'll mock the check based on known executable names.
    
    std::string lower_path = exe_path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
    
    if (lower_path.find("chrome.exe") != std::string::npos ||
        lower_path.find("msedge.exe") != std::string::npos ||
        lower_path.find("firefox.exe") != std::string::npos ||
        lower_path.find("explorer.exe") != std::string::npos ||
        lower_path.find("svchost.exe") != std::string::npos) {
        return true;
    }
    return false;
#else
    // Linux/Mac fallback mock
    return false;
#endif
}

bool AppTrustManager::evaluate_behavior(const std::string& parent_exe, const std::string& child_exe, uint32_t pid, const std::string& source_ip) {
    std::string p_exe = parent_exe;
    std::string c_exe = child_exe;
    std::transform(p_exe.begin(), p_exe.end(), p_exe.begin(), ::tolower);
    std::transform(c_exe.begin(), c_exe.end(), c_exe.begin(), ::tolower);

    for (const auto& rule : rules_) {
        if (p_exe.find(rule.parent_exe) != std::string::npos && 
            c_exe.find(rule.blocked_child) != std::string::npos) {
            
            // Suspicious behavior detected from a trusted app
            SuspiciousActivity activity;
            activity.id = "act_" + std::to_string(pid) + "_" + std::to_string(std::time(nullptr));
            activity.description = "Behavior Anomaly: " + rule.description + " (" + parent_exe + " -> " + child_exe + ")";
            activity.source_ip = source_ip;
            activity.pid = pid;
            activity.is_destructive = rule.trigger_kill_switch;
            activity.detection_time = std::chrono::steady_clock::now();
            
            std::cout << "[AppTrust] Violation detected: " << activity.description << "\n";
            failsafe_manager_.report_activity(activity);
            return false;
        }
    }
    
    return true; // Behavior is clean
}

} // namespace fw
