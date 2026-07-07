#include "updater.hpp"
#include <iostream>
#include "httplib.h" // We use httplib to fetch updates

namespace fw {

AutoUpdater::AutoUpdater(const std::string& update_url, std::chrono::hours check_interval)
    : update_url_(update_url), check_interval_(check_interval) {}

AutoUpdater::~AutoUpdater() {
    stop();
}

void AutoUpdater::start() {
    if (running_) return;
    running_ = true;
    thread_ = std::thread(&AutoUpdater::polling_loop, this);
}

void AutoUpdater::stop() {
    running_ = false;
    if (thread_.joinable()) {
        thread_.join();
    }
}

void AutoUpdater::set_on_update_callback(std::function<void(const std::string&)> cb) {
    on_update_ = cb;
}

bool AutoUpdater::check_for_updates_now() {
    try {
        // Parse host and path from update_url_
        // For simulation purposes, we assume update_url_ is formatted like "https://example.com/api/updates"
        size_t pos = update_url_.find("://");
        if (pos == std::string::npos) return false;
        
        bool is_https = (update_url_.substr(0, pos) == "https");
        (void)is_https;
        std::string host_path = update_url_.substr(pos + 3);
        size_t path_pos = host_path.find("/");
        
        std::string host = (path_pos == std::string::npos) ? host_path : host_path.substr(0, path_pos);
        std::string path = (path_pos == std::string::npos) ? "/" : host_path.substr(path_pos);

        std::unique_ptr<httplib::Client> cli;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        if (is_https) {
            cli = std::make_unique<httplib::SSLClient>(host);
            cli->enable_server_certificate_verification(false); // Disable for sim
        } else {
            cli = std::make_unique<httplib::Client>(host);
        }
#else
        cli = std::make_unique<httplib::Client>(host);
#endif

        auto res = cli->Get(path.c_str());
        if (res && res->status == 200) {
            std::cout << "[Updater] Successfully fetched updates from " << update_url_ << "\n";
            // Simulated version string
            std::string version = "v2.1.0-secure";
            if (on_update_) {
                on_update_(version);
            }
            return true;
        } else {
            std::cerr << "[Updater] Failed to fetch updates. HTTP Status: " << (res ? res->status : 0) << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[Updater] Exception during update check: " << e.what() << "\n";
    }
    return false;
}

void AutoUpdater::polling_loop() {
    while (running_) {
        // Sleep in small increments to allow responsive stopping
        for (int i = 0; i < std::chrono::duration_cast<std::chrono::seconds>(check_interval_).count() && running_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!running_) break;

        check_for_updates_now();
    }
}

} // namespace fw
