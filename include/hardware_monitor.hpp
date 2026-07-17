#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <deque>
#include <unordered_set>

namespace fw {

struct HardwareAlert {
    std::string id;          // UUID for the alert
    std::string type;        // "USB_KEYBOARD", "BLUETOOTH", "NFC"
    std::string hwid;        // Hardware ID to block if requested
    std::string title;
    std::string description;
    bool        auto_blocked; // true if already neutralized, false if awaiting user choice
    std::string timestamp;
};

struct OsPolicies {
    bool monitor_usb = true;
    bool monitor_bluetooth = true;
    bool monitor_nfc = true;
    int  wpm_threshold = 1000;
};

class HardwareMonitor {
public:
    HardwareMonitor();
    ~HardwareMonitor();

    // Startup and Shutdown
    void start();
    void stop();

    // Check if running as Admin
    static bool is_admin();

    // API Server interactions
    std::vector<HardwareAlert> get_pending_alerts() const;
    void resolve_alert(const std::string& alert_id, bool block);
    
    // Persistent block management
    std::vector<std::string> get_blocked_devices() const;
    void unblock_device(const std::string& hwid);

    // Testing hook
    void simulate_keystroke_burst();

private:
    void load_policies();
    void load_blocked_devices();
    void save_blocked_devices();
    
    // OS interactions
    void apply_block(const std::string& hwid);
    void remove_block(const std::string& hwid);

    // Monitoring threads
    void keyboard_hook_thread();
    void bluetooth_polling_thread();

    // State
    OsPolicies policies_;
    std::unordered_set<std::string> blocked_hwids_;
    
    mutable std::mutex alerts_mtx_;
    std::deque<HardwareAlert> pending_alerts_;
    
    std::atomic<bool> running_{false};
    std::thread hook_thread_;
    std::thread bt_thread_;

    // Keyboard hook state (accessible from static hook callback)
    static std::atomic<int> keystroke_count_;
    static std::atomic<uint64_t> first_keystroke_time_;
    static std::atomic<bool> ducky_detected_;
    
    // Pointer for the static hook to push alerts
    static HardwareMonitor* instance_;
    void push_alert(HardwareAlert alert);
};

} // namespace fw
