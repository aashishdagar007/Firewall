#pragma once
#include "util/types.hpp"
#include <cstdint>

// ──────────────────────────────────────────────────────────────
//  packet.hpp  –  raw-byte → PacketInfo parser
// ──────────────────────────────────────────────────────────────

namespace fw {

    class PacketParser {
    public:
        // Parse a raw IP packet from a buffer captured via a raw socket.
        // Returns true on success and fills `out`.
        // Returns false if the buffer is malformed or truncated. Unknown
        // IPv4 protocols parse as Proto::ANY and are rejected by v1 policy.
        static bool parse(const uint8_t* buf, int len, PacketInfo& out);

        // Linux v1 only enforces unfragmented IPv4 TCP, UDP, and ICMP. This
        // rejects traffic that cannot yet receive equivalent rule semantics.
        static bool is_supported_by_v1(const PacketInfo& packet);

        // Human-readable form of a PacketInfo (used by logger)
        static std::string to_string(const PacketInfo& pkt);
    };

} // namespace fw
