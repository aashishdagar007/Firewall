#pragma once
#include "vpn_manager.hpp"
#include "rule_engine.hpp"
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

namespace fw {

// Represents an exit node for IP dodging
struct ExitNode {
    std::string country_code;
    std::string endpoint; // IP or hostname
    VpnProtocol protocol;
    uint32_t virtual_ip;
};

class IpDodger {
public:
    IpDodger(VpnManager& vpn_manager, RuleEngine& rule_engine);
    ~IpDodger();

    // Start the automatic rotation logic
    void start();
    void stop();

    // Add a potential exit node to the pool
    void add_exit_node(const ExitNode& node);

    // Trigger an immediate evasion (e.g., when a severe threat is detected)
    void trigger_evasion();

    // Manually set rotation interval
    void set_rotation_interval(std::chrono::seconds interval);

private:
    void rotation_loop();
    void switch_to_random_node();

    VpnManager& vpn_manager_;
    RuleEngine& rule_engine_;

    std::vector<ExitNode> exit_nodes_;
    std::string current_vpn_id_;
    int current_node_index_ = -1;

    std::chrono::seconds rotation_interval_{300}; // default 5 mins
    std::atomic<bool> evasion_triggered_{false};
    
    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    mutable std::mutex mtx_;
};

} // namespace fw
