#pragma once
#include <cstdint>
#include <string>

// ──────────────────────────────────────────────────────────────
//  types.hpp  –  shared enums and plain structs used everywhere
// ──────────────────────────────────────────────────────────────

namespace fw {

    // ── Protocol ────────────────────────────────────────────────
    enum class Proto : uint8_t {
        ANY  = 0,
        TCP  = 6,    // matches IPPROTO_TCP
        UDP  = 17,   // matches IPPROTO_UDP
        ICMP = 1     // matches IPPROTO_ICMP
    };

    inline const char* proto_name(Proto p) {
        switch (p) {
            case Proto::TCP:  return "TCP";
            case Proto::UDP:  return "UDP";
            case Proto::ICMP: return "ICMP";
            default:          return "ANY";
        }
    }

    // ── Verdict ──────────────────────────────────────────────────
    enum class Action { ALLOW, BLOCK };

    inline const char* action_name(Action a) {
        return a == Action::ALLOW ? "ALLOW" : "BLOCK";
    }

    // ── Direction ────────────────────────────────────────────────
    enum class Direction { ANY, INBOUND, OUTBOUND };

    // ── Parsed packet summary ────────────────────────────────────
    struct PacketInfo {
        Proto    proto     = Proto::ANY;
        uint32_t src_ip    = 0;   // host byte order
        uint32_t dst_ip    = 0;
        uint16_t src_port  = 0;
        uint16_t dst_port  = 0;
        Direction dir      = Direction::ANY;

        // Raw byte count (for logging/stats)
        int      size      = 0;
    };

    // ── Firewall rule ────────────────────────────────────────────
    struct Rule {
        uint32_t    id          = 0;
        Action      action      = Action::BLOCK;
        Proto       proto       = Proto::ANY;
        Direction   direction   = Direction::ANY;

        uint32_t    src_ip      = 0;  // 0 = wildcard
        uint32_t    dst_ip      = 0;
        uint16_t    src_port    = 0;  // 0 = wildcard
        uint16_t    dst_port    = 0;

        std::string description;

        // Stats
        mutable uint64_t hit_count = 0;
    };

} // namespace fw