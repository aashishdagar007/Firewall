#pragma once
#include "util/types.hpp"
#include <unordered_map>
#include <mutex>
#include <string>
#include <vector>

namespace fw {

enum class NatType {
    SNAT, // Source NAT
    DNAT  // Destination NAT
};

struct NatRule {
    uint32_t original_ip;
    uint32_t translated_ip;
    uint16_t original_port;
    uint16_t translated_port;
    NatType type;
};

class NatEngine {
public:
    NatEngine();
    ~NatEngine();

    void add_rule(NatRule rule);
    bool remove_rule(uint32_t original_ip, uint16_t original_port);

    // Apply NAT to a packet. Modifies packet if a rule matches.
    // Returns true if packet was modified.
    bool apply_nat(PacketInfo& pkt);

private:
    std::mutex mtx_;
    std::vector<NatRule> rules_;
};

} // namespace fw
