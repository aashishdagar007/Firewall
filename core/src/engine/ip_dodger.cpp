#include "ip_dodger.hpp"
#include <iostream>
#include <random>

namespace fw {

IpDodger::IpDodger(VpnManager& vpn_manager, RuleEngine& rule_engine)
    : vpn_manager_(vpn_manager), rule_engine_(rule_engine) {
}

IpDodger::~IpDodger() {
    stop();
}

void IpDodger::start() {
    if (running_.exchange(true)) return;
    
    // Auto-populate some sample nodes if empty
    if (exit_nodes_.empty()) {
        add_exit_node({"CH", "185.10.20.30", VpnProtocol::WIREGUARD, 0x0A080002}); // Swiss
        add_exit_node({"IS", "103.45.67.89", VpnProtocol::OPENVPN,   0x0A080003}); // Iceland
        add_exit_node({"PA", "192.16.4.55",  VpnProtocol::WIREGUARD, 0x0A080004}); // Panama
    }

    worker_thread_ = std::thread(&IpDodger::rotation_loop, this);
}

void IpDodger::stop() {
    running_ = false;
    evasion_triggered_ = true; // Wake up the loop if sleeping
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void IpDodger::add_exit_node(const ExitNode& node) {
    std::lock_guard<std::mutex> lock(mtx_);
    exit_nodes_.push_back(node);
}

void IpDodger::trigger_evasion() {
    std::cout << "[IpDodger] Evasion triggered! Attempting immediate IP mask/rotation.\n";
    evasion_triggered_ = true;
}

void IpDodger::set_rotation_interval(std::chrono::seconds interval) {
    rotation_interval_ = interval;
}

void IpDodger::switch_to_random_node() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (exit_nodes_.empty()) return;

    // Disconnect current
    if (!current_vpn_id_.empty()) {
        vpn_manager_.disconnect(current_vpn_id_);
        vpn_manager_.remove_connection(current_vpn_id_);
        current_vpn_id_.clear();
    }

    // Pick a new node (avoiding the same one if possible)
    int next_index = 0;
    if (exit_nodes_.size() > 1) {
        static std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(0, exit_nodes_.size() - 1);
        do {
            next_index = dist(rng);
        } while (next_index == current_node_index_);
    }
    
    current_node_index_ = next_index;
    const auto& node = exit_nodes_[current_node_index_];

    // Establish new connection
    current_vpn_id_ = vpn_manager_.add_connection(
        node.protocol, node.endpoint, node.virtual_ip, 0xFFFFFF00
    );
    
    if (vpn_manager_.connect(current_vpn_id_)) {
        std::cout << "[IpDodger] Masked IP. Now routing through: " << node.country_code 
                  << " (" << node.endpoint << ")\n";
                  
        // Inject rule to block traffic going directly to WAN, enforcing tunnel
        Rule enforce_tunnel;
        enforce_tunnel.action = Action::ALLOW; // Mock: Actually we would allow tunnel, block rest
        enforce_tunnel.description = "Enforce tunnel to " + node.country_code;
        rule_engine_.add_rule(enforce_tunnel);
    } else {
        std::cerr << "[IpDodger] Failed to connect to node " << node.country_code << "\n";
    }
}

void IpDodger::rotation_loop() {
    while (running_) {
        // Sleep in chunks so we can interrupt it for an evasion trigger
        for (int i = 0; i < rotation_interval_.count() * 10; ++i) {
            if (!running_) break;
            if (evasion_triggered_.exchange(false)) {
                // Immediate switch requested
                switch_to_random_node();
                break; // Restart sleep interval
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Timer expired, normal rotation
        if (running_ && !evasion_triggered_) {
            switch_to_random_node();
        }
    }
}

} // namespace fw
