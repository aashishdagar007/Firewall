#include "vpn_manager.hpp"
#include <iostream>

namespace fw {

VpnManager::VpnManager() {}
VpnManager::~VpnManager() {}

std::string VpnManager::add_connection(VpnProtocol protocol, const std::string& endpoint, uint32_t vip, uint32_t mask) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::string id = "vpn_" + std::to_string(next_id_++);
    
    VpnConnection conn;
    conn.id = id;
    conn.protocol = protocol;
    conn.remote_endpoint = endpoint;
    conn.virtual_ip = vip;
    conn.subnet_mask = mask;
    conn.active = false;

    connections_.push_back(conn);
    return id;
}

bool VpnManager::remove_connection(const std::string& id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = connections_.begin(); it != connections_.end(); ++it) {
        if (it->id == id) {
            connections_.erase(it);
            return true;
        }
    }
    return false;
}

bool VpnManager::connect(const std::string& id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto& conn : connections_) {
        if (conn.id == id) {
            if (!conn.active) {
                // Simulate establishing connection
                conn.active = true;
                std::cout << "[VPN] Connected to " << conn.remote_endpoint << " via ID " << conn.id << "\n";
            }
            return true;
        }
    }
    return false;
}

bool VpnManager::disconnect(const std::string& id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto& conn : connections_) {
        if (conn.id == id) {
            if (conn.active) {
                // Simulate disconnecting
                conn.active = false;
                std::cout << "[VPN] Disconnected from " << conn.remote_endpoint << " (ID " << conn.id << ")\n";
            }
            return true;
        }
    }
    return false;
}

std::vector<VpnConnection> VpnManager::get_active_connections() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<VpnConnection> active;
    for (const auto& conn : connections_) {
        if (conn.active) {
            active.push_back(conn);
        }
    }
    return active;
}

} // namespace fw
