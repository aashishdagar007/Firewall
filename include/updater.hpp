#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <chrono>

namespace fw {

class AutoUpdater {
public:
    AutoUpdater(const std::string& update_url, std::chrono::hours check_interval = std::chrono::hours(24));
    ~AutoUpdater();

    // Start background polling thread
    void start();
    void stop();

    // Set callback invoked when an update is successfully found and "downloaded"
    void set_on_update_callback(std::function<void(const std::string& version)> cb);

    // Force an immediate update check (blocking)
    bool check_for_updates_now();

private:
    std::string update_url_;
    std::chrono::hours check_interval_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::function<void(const std::string&)> on_update_;

    void polling_loop();
};

} // namespace fw
