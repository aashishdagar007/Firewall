#include "nat_engine.hpp"

namespace fw {

NatEngine::NatEngine() {}
NatEngine::~NatEngine() {}

void NatEngine::add_rule(NatRule rule) {
    std::lock_guard<std::mutex> lock(mtx_);
    rules_.push_back(rule);
}

bool NatEngine::remove_rule(uint32_t original_ip, uint16_t original_port) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = rules_.begin(); it != rules_.end(); ++it) {
        if (it->original_ip == original_ip && it->original_port == original_port) {
            rules_.erase(it);
            return true;
        }
    }
    return false;
}

bool NatEngine::apply_nat(PacketInfo& pkt) {
    std::lock_guard<std::mutex> lock(mtx_);
    bool modified = false;

    for (const auto& rule : rules_) {
        if (rule.type == NatType::SNAT) {
            // Check if packet matches SNAT original source
            if ((rule.original_ip == 0 || pkt.src_ip == rule.original_ip) &&
                (rule.original_port == 0 || pkt.src_port == rule.original_port)) {
                
                if (rule.translated_ip != 0) pkt.src_ip = rule.translated_ip;
                if (rule.translated_port != 0) pkt.src_port = rule.translated_port;
                modified = true;
                break; // Only apply one NAT rule
            }
        } else if (rule.type == NatType::DNAT) {
            // Check if packet matches DNAT original destination
            if ((rule.original_ip == 0 || pkt.dst_ip == rule.original_ip) &&
                (rule.original_port == 0 || pkt.dst_port == rule.original_port)) {
                
                if (rule.translated_ip != 0) pkt.dst_ip = rule.translated_ip;
                if (rule.translated_port != 0) pkt.dst_port = rule.translated_port;
                modified = true;
                break; // Only apply one NAT rule
            }
        }
    }

    // In a real implementation, we would recalculate IPv4 header checksums 
    // and TCP/UDP checksums here. For now, we just modify the PacketInfo struct.
    return modified;
}

} // namespace fw
