#pragma once
// ──────────────────────────────────────────────────────────────
//  dns_firewall.hpp  –  Layer-7 DNS Inspection Engine
//
//  AEGIS XII Pillar P4: DNS Firewall
//
//  Detects and blocks:
//    • DNS AXFR zone transfer requests  (threat 21)
//    • DNS ANY amplification queries    (DDoS vector)
//    • DGA (Domain Generation Algorithm) C2 beaconing
//    • DNS tunneling / data exfiltration
//    • PTR (reverse lookup) floods      (recon pattern, threat 15)
//    • Oversized TXT records            (tunneling)
//    • Queries to non-allowlisted resolvers
//
//  Usage:
//    DnsFirewall dns_fw;
//    std::string reason;
//    if (dns_fw.inspect(payload, len, reason) == Action::BLOCK)
//        // drop the packet
//
//  Thread safety: all public methods are thread-safe.
// ──────────────────────────────────────────────────────────────

#include "util/types.hpp"
#include <array>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace fw {

// ── DNS wire-format constants ────────────────────────────────
constexpr uint16_t DNS_QTYPE_A     = 1;
constexpr uint16_t DNS_QTYPE_NS    = 2;
constexpr uint16_t DNS_QTYPE_CNAME = 5;
constexpr uint16_t DNS_QTYPE_SOA   = 6;
constexpr uint16_t DNS_QTYPE_PTR   = 12;
constexpr uint16_t DNS_QTYPE_MX    = 15;
constexpr uint16_t DNS_QTYPE_TXT   = 16;
constexpr uint16_t DNS_QTYPE_AAAA  = 28;
constexpr uint16_t DNS_QTYPE_AXFR  = 252;  // Zone transfer — always block
constexpr uint16_t DNS_QTYPE_ANY   = 255;  // ANY — amplification vector

// ── DNS threat event ─────────────────────────────────────────
struct DnsThreatEvent {
    std::string timestamp;   // epoch ms string
    std::string src_ip;
    std::string domain;      // queried/zone name
    std::string threat_type; // "AXFR", "ANY", "DGA", "Tunnel", "PTR_Flood"
    std::string detail;      // human-readable reason
};

// ── Main DNS Firewall class ───────────────────────────────────
class DnsFirewall {
public:
    DnsFirewall();

    // Inspect a raw UDP DNS payload.
    // src_ip is passed in host-byte-order for rate-limiting.
    // Returns Action::BLOCK and populates reason if the query is malicious.
    // Returns Action::ALLOW otherwise.
    Action inspect(const uint8_t* payload, uint16_t len,
                   uint32_t src_ip, std::string& reason);

    // Block a specific domain suffix (e.g. "malware.example.com" or ".ru")
    void block_domain(const std::string& suffix);

    // Allow a specific domain (overrides suffix blocks)
    void allow_domain(const std::string& domain);

    // Snapshot of recent DNS threat events (for the API)
    std::vector<DnsThreatEvent> get_recent_events() const;

    // Periodic cleanup — call every ~60 sec from a maintenance thread
    void cleanup_stale();

private:
    // ── Domain extraction helpers ─────────────────────────────
    // Parse a DNS question name from wire format starting at offset.
    // Returns the decoded FQDN and advances offset past the qtype/qclass.
    static bool parse_question(const uint8_t* buf, uint16_t len,
                               uint16_t& offset, std::string& name,
                               uint16_t& qtype);

    // Decode a single DNS label sequence (no pointer support — we don't
    // follow pointers since we only inspect the question section).
    static std::string decode_name(const uint8_t* buf, uint16_t len,
                                    uint16_t& offset);

    // ── Detection algorithms ──────────────────────────────────

    // Shannon entropy of a string (bits per character).
    // A normal hostname averages ~2.5 bits/char; DGA averages ~3.5+.
    static double shannon_entropy(const std::string& s);

    // Returns true if the label looks like a DGA-generated name:
    //   • entropy > DGA_ENTROPY_THRESHOLD
    //   • length > DGA_MIN_LENGTH
    //   • mostly consonants (no vowel clusters typical of real words)
    bool detect_dga(const std::string& label) const;

    // Returns true if the query looks like DNS tunneling:
    //   • total label length > TUNNEL_LABEL_THRESHOLD
    //   • base64/hex charset ratio > TUNNEL_CHARSET_RATIO
    static bool detect_tunneling(const std::string& name);

    // Returns true if the domain suffix is in the blocklist
    bool is_blocked_domain(const std::string& name) const;

    // ── PTR flood rate limiting ───────────────────────────────
    struct PtrState {
        uint32_t count = 0;
        std::chrono::steady_clock::time_point window_start;
    };

    // ── Threat event ring buffer ──────────────────────────────
    void push_event(const std::string& src_ip_str, const std::string& domain,
                    const std::string& type, const std::string& detail);

    // ── Configuration thresholds ──────────────────────────────
    static constexpr double   DGA_ENTROPY_THRESHOLD  = 3.5;  // bits/char
    static constexpr size_t   DGA_MIN_LENGTH          = 10;   // chars
    static constexpr size_t   TUNNEL_LABEL_THRESHOLD  = 52;   // chars in longest label
    static constexpr double   TUNNEL_CHARSET_RATIO    = 0.70; // fraction of base64 chars
    static constexpr uint32_t PTR_FLOOD_THRESHOLD     = 30;   // queries per window
    static constexpr uint32_t PTR_FLOOD_WINDOW_SEC    = 5;    // sliding window

    // ── State ─────────────────────────────────────────────────
    mutable std::mutex mtx_;

    std::vector<std::string> blocked_suffixes_;
    std::vector<std::string> allowed_domains_;

    std::unordered_map<uint32_t, PtrState> ptr_states_; // src_ip → PTR rate state

    std::deque<DnsThreatEvent> events_; // recent threat events (max 500)
    static constexpr size_t MAX_EVENTS = 500;
};

} // namespace fw
