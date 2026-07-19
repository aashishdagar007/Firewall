#include "engine/hardware_monitor.hpp"
#include "util/logger.hpp"
#include <fstream>
#include <chrono>
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#endif

namespace fw {

HardwareMonitor* HardwareMonitor::instance_ = nullptr;
std::atomic<int> HardwareMonitor::keystroke_count_{0};
std::atomic<uint64_t> HardwareMonitor::first_keystroke_time_{0};
std::atomic<bool> HardwareMonitor::ducky_detected_{false};

HardwareMonitor::HardwareMonitor() {
    instance_ = this;
    load_policies();
    load_blocked_devices();
}

HardwareMonitor::~HardwareMonitor() {
    stop();
    instance_ = nullptr;
}

bool HardwareMonitor::is_admin() {
#ifdef _WIN32
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
#else
    return getuid() == 0;
#endif
}

void HardwareMonitor::start() {
    if (!is_admin()) {
        std::cerr << "[Warning] HardwareMonitor requires Administrator privileges. Running in degraded mode.\n";
        return;
    }

    running_ = true;
    
    // Apply persistently blocked devices
    for (const auto& hwid : blocked_hwids_) {
        apply_block(hwid);
    }

    if (policies_.monitor_usb) {
        hook_thread_ = std::thread(&HardwareMonitor::keyboard_hook_thread, this);
    }
    if (policies_.monitor_bluetooth) {
        bt_thread_ = std::thread(&HardwareMonitor::bluetooth_polling_thread, this);
    }
}

void HardwareMonitor::stop() {
    running_ = false;
    if (hook_thread_.joinable()) hook_thread_.join();
    if (bt_thread_.joinable()) bt_thread_.join();
    
    // Note: Temporary monitoring hooks exit when thread joins.
    // Persistent blocks stay enforced at the OS level.
}

void HardwareMonitor::push_alert(HardwareAlert alert) {
    std::lock_guard<std::mutex> lock(alerts_mtx_);
    pending_alerts_.push_back(std::move(alert));
}

std::vector<HardwareAlert> HardwareMonitor::get_pending_alerts() const {
    std::lock_guard<std::mutex> lock(alerts_mtx_);
    return std::vector<HardwareAlert>(pending_alerts_.begin(), pending_alerts_.end());
}

void HardwareMonitor::resolve_alert(const std::string& alert_id, bool block) {
    std::lock_guard<std::mutex> lock(alerts_mtx_);
    for (auto it = pending_alerts_.begin(); it != pending_alerts_.end(); ++it) {
        if (it->id == alert_id) {
            if (block && !it->auto_blocked) {
                apply_block(it->hwid);
                blocked_hwids_.insert(it->hwid);
                save_blocked_devices();
            }
            pending_alerts_.erase(it);
            break;
        }
    }
}

std::vector<std::string> HardwareMonitor::get_blocked_devices() const {
    return std::vector<std::string>(blocked_hwids_.begin(), blocked_hwids_.end());
}

void HardwareMonitor::unblock_device(const std::string& hwid) {
    remove_block(hwid);
    blocked_hwids_.erase(hwid);
    save_blocked_devices();
}

void HardwareMonitor::load_policies() {
    // Mock load for policies
    policies_.monitor_usb = true;
    policies_.monitor_bluetooth = true;
    policies_.wpm_threshold = 1000;
}

void HardwareMonitor::load_blocked_devices() {
    // Mock load
    // In real implementation, parses config/blocked_hardware.json
}

void HardwareMonitor::save_blocked_devices() {
    // Mock save
    // In real implementation, serializes blocked_hwids_ to JSON
}

void HardwareMonitor::apply_block(const std::string& hwid) {
#ifdef _WIN32
    // Executes Disable-PnpDevice
    std::string cmd = "powershell -Command \"Disable-PnpDevice -InstanceId '" + hwid + "' -Confirm:$false\"";
    system(cmd.c_str());
#endif
}

void HardwareMonitor::remove_block(const std::string& hwid) {
#ifdef _WIN32
    std::string cmd = "powershell -Command \"Enable-PnpDevice -InstanceId '" + hwid + "' -Confirm:$false\"";
    system(cmd.c_str());
#endif
}

void HardwareMonitor::keyboard_hook_thread() {
    // In a real Windows app, SetWindowsHookEx(WH_KEYBOARD_LL) runs a message loop here.
    // For simulation and cross-platform compilation, we run a mock loop.
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        if (keystroke_count_ > 0) {
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch()).count();
            uint64_t elapsed = now - first_keystroke_time_;
            if (elapsed > 1000) { // check every 1 second
                int cpm = keystroke_count_ * (60000 / elapsed); // chars per min
                int wpm = cpm / 5; // standard 5 chars per word
                
                if (wpm > policies_.wpm_threshold && !ducky_detected_) {
                    ducky_detected_ = true;
                    // Auto-Neutralize
                    apply_block("USB\\VID_XXXX&PID_XXXX\\RUBBER_DUCKY");
                    
                    HardwareAlert alert;
                    alert.id = "alert_" + std::to_string(now);
                    alert.type = "USB_KEYBOARD";
                    alert.hwid = "USB\\VID_XXXX&PID_XXXX\\RUBBER_DUCKY";
                    alert.title = "Rubber Ducky Attack Neutralized";
                    alert.description = "Extremely fast keystrokes (" + std::to_string(wpm) + " WPM) detected. Device auto-blocked.";
                    alert.auto_blocked = true;
                    alert.timestamp = std::to_string(now);
                    
                    push_alert(alert);
                }
                
                // Reset counters
                keystroke_count_ = 0;
            }
        }
    }
}

void HardwareMonitor::simulate_keystroke_burst() {
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count();
    first_keystroke_time_ = now;
    keystroke_count_ = 100; // 100 chars in 0 ms is infinite WPM
    ducky_detected_ = false;
}

void HardwareMonitor::bluetooth_polling_thread() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        // Mock: Poll for new bluetooth devices.
        // If an untrusted BT device appears:
        // HardwareAlert alert;
        // alert.auto_blocked = false; // requires user prompt
        // push_alert(alert);
    }
}

} // namespace fw
