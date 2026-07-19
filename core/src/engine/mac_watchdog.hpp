#pragma once
// ──────────────────────────────────────────────────────────────
//  mac_watchdog.hpp  –  Layer-2 ARP / MAC Spoofing Detector
//
//  AEGIS XII Pillar P5: MAC Randomization Watchdog
//
//  Detects:
//    • ARP poisoning / MitM: IP→MAC binding changes mid-session
//    • Broadcast MAC flood (FF:FF:FF:FF:FF:FF storm)
//    • Locally Administered Address (LAA) bit changes — signals
//      an attacker switching to a spoofed/randomized MAC
//    • MAC address reuse across different IPs (MAC spoofing)
//
//  Threats addressed: 10 (probe request sniffing), 12 (BLE/BT scanning),
//                     28 (evil twin), general MitM network attacks.
//
//  Thread safety: all public methods are thread-safe.
// ──────────────────────────────────────────────────────────────

#include "util/types.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace fw {

// ── MAC address type alias ────────────────────────────────────
using MacAddr = std::array<uint8_t, 6>;

// ── MAC conflict event ────────────────────────────────────────
struct MacConflictEvent {
    std::string timestamp;
    std::string src_ip;      // IP address involved
    std::string old_mac;     // Previously known MAC for this IP
    std::string new_mac;     // New (conflicting) MAC
    std::string threat_type; // "ARP_Poison", "MAC_Flood", "LAA_Change", "MAC_Reuse"
    std::string detail;
    bool        auto_banned = false;
};

// ── Helper: format a MAC address as "aa:bb:cc:dd:ee:ff" ──────
inline std::string mac_to_string(const MacAddr& mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

// ── Helper: check if a MAC is broadcast ──────────────────────
inline bool is_broadcast_mac(const MacAddr& mac) {
    return mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
           mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF;
}

// ── Helper: check Locally Administered Address bit ───────────
// Bit 1 of the first octet: 1 = locally administered (spoofed/randomized)
inline bool is_locally_administered(const MacAddr& mac) {
    return (mac[0] & 0x02) != 0;
}

// ── Helper: check Multicast MAC bit ──────────────────────────
inline bool is_multicast_mac(const MacAddr& mac) {
    return (mac[0] & 0x01) != 0;
}

// ── Callback type: fired when a conflict is detected ─────────
using MacConflictCallback = std::function<void(const MacConflictEvent&)>;

// ── Main MAC Watchdog class ───────────────────────────────────
class MacWatchdog {
public:
    MacWatchdog() = default;

    // Set a callback fired on every conflict detection.
    // The callback may call back into the RuleEngine to ban the source IP.
    void set_callback(MacConflictCallback cb);

    // Feed a packet's source MAC and source IP.
    // Returns true if an ARP spoofing / MitM anomaly is detected.
    // If a conflict is detected, fires the registered callback.
    bool record(const MacAddr& src_mac, uint32_t src_ip);

    // Snapshot of all recent conflict events (for the API)
    std::vector<MacConflictEvent> get_conflicts() const;

    // How many distinct IPs are being spoofed right now
    size_t active_conflict_count() const;

    // Periodic cleanup of stale entries (call every ~120 sec)
    void cleanup_stale();

private:
    // ── Broadcast flood tracking ──────────────────────────────
    struct BroadcastState {
        uint32_t count = 0;
        std::chrono::steady_clock::time_point window_start;
    };

    // ── LAA tracking per IP ───────────────────────────────────
    // Tracks whether an IP was previously using a globally-assigned MAC
    // and has switched to a locally-administered one (possible spoofing).
    struct MacHistory {
        MacAddr  last_mac = {};
        bool     was_laa  = false;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;
    };

    void emit_event(const std::string& src_ip, const MacAddr& old_mac,
                    const MacAddr& new_mac, const std::string& type,
                    const std::string& detail, bool banned = false);

    static constexpr uint32_t BCAST_FLOOD_THRESHOLD  = 100; // pkts per window
    static constexpr uint32_t BCAST_FLOOD_WINDOW_SEC  = 2;
    static constexpr size_t   MAX_EVENTS              = 500;

    mutable std::mutex mtx_;

    // ip (host-byte-order) → MAC history
    std::unordered_map<uint32_t, MacHistory> ip_to_mac_;

    // MAC → list of IPs it has been seen on (detect MAC reuse/spoofing)
    std::unordered_map<uint64_t, uint32_t> mac_to_ip_; // mac hash → first ip

    // Broadcast flood state (keyed by src_ip)
    std::unordered_map<uint32_t, BroadcastState> bcast_states_;

    std::deque<MacConflictEvent> events_; // recent conflict events

    MacConflictCallback callback_;
};

} // namespace fw
