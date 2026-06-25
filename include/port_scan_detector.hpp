#pragma once
#include "types.hpp"
#include <cstdint>
#include <string>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <deque>
#include <chrono>
#include <mutex>
#include <functional>

// ──────────────────────────────────────────────────────────────
//  port_scan_detector.hpp
//
//  Cross-port correlation layer that detects:
//    • SYN sweeps   (>THRESH distinct TCP dst_ports in WINDOW_SEC)
//    • UDP sweeps   (>THRESH distinct UDP dst_ports in WINDOW_SEC)
//    • Stealth scans (NULL / FIN / XMAS already blocked by rule_engine;
//                     we detect the cross-port pattern here too)
//    • Mixed sweeps  (any protocol hitting >THRESH distinct ports)
//
//  Works AFTER the rule engine verdict — every packet seen (allowed
//  or blocked) is fed in. This catches slow scanners that space out
//  probes enough to slip under per-packet anomaly rules.
// ──────────────────────────────────────────────────────────────

namespace fw {

// ── Scan type classification ──────────────────────────────────
enum class ScanType : uint8_t {
    SYN_SWEEP,      // Many SYN probes across ports
    UDP_SWEEP,      // Many UDP probes across ports
    STEALTH_PROBE,  // NULL / FIN / XMAS flags across ports
    MIXED_SWEEP,    // Mixed protocol sweep
    ICMP_SWEEP,     // ICMP echo to many hosts (ping sweep)
};

inline const char* scan_type_name(ScanType t) {
    switch (t) {
        case ScanType::SYN_SWEEP:     return "SYN Sweep";
        case ScanType::UDP_SWEEP:     return "UDP Sweep";
        case ScanType::STEALTH_PROBE: return "Stealth Probe (NULL/FIN/XMAS)";
        case ScanType::MIXED_SWEEP:   return "Mixed Port Sweep";
        case ScanType::ICMP_SWEEP:    return "ICMP Ping Sweep";
        default:                      return "Unknown Scan";
    }
}

// ── Scan event emitted when a scan is detected ────────────────
struct ScanEvent {
    uint32_t    src_ip;           // Scanner IP (host byte order)
    std::string ip_str;           // Human-readable IP
    ScanType    scan_type;
    uint32_t    ports_probed;     // Distinct ports seen in the window
    std::string timestamp;        // ISO-like string: epoch milliseconds
    bool        auto_banned;      // true if IP was immediately banned
};

// ── Per-IP rolling state ──────────────────────────────────────
struct ScanState {
    // Sliding window of (dst_port, time_point) per protocol
    struct PortHit {
        uint16_t port;
        std::chrono::steady_clock::time_point when;
    };

    std::deque<PortHit> tcp_hits;
    std::deque<PortHit> udp_hits;
    std::deque<PortHit> icmp_hits; // stores icmp_type as "port"

    std::unordered_set<uint16_t> tcp_unique;
    std::unordered_set<uint16_t> udp_unique;

    std::chrono::steady_clock::time_point last_seen;
    bool already_reported = false; // suppress duplicate alerts per scan burst
};

// ── Main detector class ───────────────────────────────────────
class PortScanDetector {
public:
    // Callback type: fired when a scan is detected
    using Callback = std::function<void(ScanEvent)>;

    // --- Configuration knobs ---
    // A scan is flagged when a single src_ip hits more than
    // PORT_THRESHOLD distinct destination ports within WINDOW_SEC seconds.
    static constexpr uint32_t PORT_THRESHOLD  = 15;   // distinct ports
    static constexpr uint32_t WINDOW_SEC      = 3;    // sliding window
    static constexpr uint32_t COOLDOWN_SEC    = 30;   // re-alert cooldown per IP
    static constexpr uint32_t CLEANUP_SEC     = 60;   // prune stale entries

    explicit PortScanDetector() = default;

    // Called for EVERY packet (before or after verdict).
    // Returns a ScanEvent if a new scan burst is detected for the src_ip,
    // or std::nullopt if everything is normal.
    std::optional<ScanEvent> record(const PacketInfo& pkt);

    // Register a callback invoked whenever a scan event fires.
    void set_callback(Callback cb);

    // Periodic cleanup — call from a maintenance thread every ~30 sec.
    void cleanup_stale();

    // Snapshot of all recent scan events (for the API)
    std::vector<ScanEvent> get_recent_events() const;

private:
    mutable std::mutex          mtx_;
    std::unordered_map<uint32_t, ScanState> states_; // src_ip -> state
    std::deque<ScanEvent>       recent_events_;       // last 200
    Callback                    callback_;

    std::chrono::steady_clock::time_point last_cleanup_{std::chrono::steady_clock::now()};

    // Trim hits outside the sliding window and rebuild the unique-port set
    static void trim_window(std::deque<ScanState::PortHit>& hits,
                             std::unordered_set<uint16_t>& unique_set,
                             std::chrono::steady_clock::time_point cutoff);

    // Build and push a ScanEvent
    void emit_event(uint32_t src_ip, ScanType type, uint32_t ports, bool banned);
};

} // namespace fw
