#pragma once
#include "types.hpp"
#include <cstdint>

// ──────────────────────────────────────────────────────────────
//  packet.hpp  –  raw-byte → PacketInfo parser
// ──────────────────────────────────────────────────────────────

namespace fw {

    class PacketParser {
    public:
        // Parse a raw IP packet from a buffer captured via a raw socket.
        // Returns true on success and fills `out`.
        // Returns false if the buffer is too short or the protocol
        // is unsupported.
        static bool parse(const uint8_t* buf, int len, PacketInfo& out);

        // Human-readable form of a PacketInfo (used by logger)
        static std::string to_string(const PacketInfo& pkt);
    };

} // namespace fw