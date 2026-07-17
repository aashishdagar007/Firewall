// ──────────────────────────────────────────────────────────────
//  dns_firewall.cpp  –  Layer-7 DNS Inspection Engine
//
//  AEGIS XII Pillar P4: DNS Firewall
// ──────────────────────────────────────────────────────────────

#include "dns_firewall.hpp"
#include "platform.hpp" // ip4_to_string

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstring>
#include <sstream>

namespace fw {

// ── Constructor ───────────────────────────────────────────────

DnsFirewall::DnsFirewall() {
    // Pre-populate known bad domain suffixes / TLDs abused for C2
    blocked_suffixes_ = {
        ".onion",   // Tor hidden services (not resolvable via normal DNS,
                    // but if someone is trying it's suspicious)
        ".bit",     // Namecoin / blockchain DNS (malware C2)
        ".lib",     // OpenNIC alternative (common in malware)
        ".bazar",   // BazarLoader C2 TLD
        ".coin",    // Blockchain DNS abuse
        ".emc",     // Alternative DNS (malware use)
        ".chan",    // Anonymous board C2
    };
}

// ── Public: inspect ──────────────────────────────────────────

Action DnsFirewall::inspect(const uint8_t* payload, uint16_t len,
                             uint32_t src_ip, std::string& reason) {
    if (!payload || len < 12)
        return Action::ALLOW; // Too short to be a valid DNS message

    // ── Parse DNS header ──────────────────────────────────────
    // Byte 2-3: Flags
    // Bit 15 (QR): 0=query, 1=response
    // We inspect both queries (detect AXFR/ANY) and large responses (detect tunneling)
    [[maybe_unused]] uint16_t flags = static_cast<uint16_t>((payload[2] << 8) | payload[3]);
    uint16_t qdcount = static_cast<uint16_t>((payload[4] << 8) | payload[5]);

    if (qdcount == 0)
        return Action::ALLOW; // No questions — might be a response-only, skip

    // Parse the first question
    uint16_t offset = 12; // DNS header is always 12 bytes
    std::string name;
    uint16_t qtype = 0;

    if (!parse_question(payload, len, offset, name, qtype))
        return Action::ALLOW; // Malformed, let it pass (don't block on parse errors)

    std::string src_str = ip4_to_string(src_ip);

    // ── Check 1: AXFR Zone Transfer (threat 21) ───────────────
    if (qtype == DNS_QTYPE_AXFR) {
        reason = "DNS: Zone Transfer (AXFR) attempt for \"" + name + "\"";
        push_event(src_str, name, "AXFR", reason);
        return Action::BLOCK;
    }

    // ── Check 2: ANY query (amplification vector) ─────────────
    if (qtype == DNS_QTYPE_ANY) {
        reason = "DNS: ANY query (amplification vector) for \"" + name + "\"";
        push_event(src_str, name, "ANY", reason);
        return Action::BLOCK;
    }

    // ── Check 3: Blocked domain suffix ───────────────────────
    if (is_blocked_domain(name)) {
        reason = "DNS: Blocked domain suffix in \"" + name + "\"";
        push_event(src_str, name, "Blocklist", reason);
        return Action::BLOCK;
    }

    // ── Check 4: DNS Tunneling detection ─────────────────────
    if (detect_tunneling(name)) {
        reason = "DNS: Tunneling/exfiltration pattern detected in \"" + name + "\"";
        push_event(src_str, name, "Tunnel", reason);
        return Action::BLOCK;
    }

    // ── Check 5: DGA / C2 domain detection ───────────────────
    // Extract the leftmost subdomain label (highest entropy in DGA names)
    {
        std::string label = name;
        auto dot = name.find('.');
        if (dot != std::string::npos)
            label = name.substr(0, dot);

        if (detect_dga(label)) {
            reason = "DNS: DGA-pattern C2 domain detected: \"" + name + "\"";
            push_event(src_str, name, "DGA", reason);
            return Action::BLOCK;
        }
    }

    // ── Check 6: PTR (reverse lookup) flood ──────────────────
    if (qtype == DNS_QTYPE_PTR) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto now = std::chrono::steady_clock::now();
        auto& state = ptr_states_[src_ip];

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - state.window_start).count();

        if (elapsed > static_cast<long long>(PTR_FLOOD_WINDOW_SEC)) {
            state.count = 0;
            state.window_start = now;
        }
        state.count++;

        if (state.count > PTR_FLOOD_THRESHOLD) {
            reason = "DNS: Reverse lookup (PTR) flood from " + src_str;
            // Push event without holding lock — copy locals first
            std::string r = reason;
            std::string s = src_str;
            std::string n = name;
            // Unlock before push_event which also acquires the lock
            // (We already hold it here, so inline the push)
            DnsThreatEvent ev;
            auto tp = std::chrono::steady_clock::now().time_since_epoch();
            ev.timestamp = std::to_string(
                std::chrono::duration_cast<std::chrono::milliseconds>(tp).count());
            ev.src_ip     = s;
            ev.domain     = n;
            ev.threat_type = "PTR_Flood";
            ev.detail     = r;
            if (events_.size() >= MAX_EVENTS) events_.pop_front();
            events_.push_back(std::move(ev));
            return Action::BLOCK;
        }
    }

    // ── Check 7: Oversized TXT record (tunneling via response) ──
    // A legitimate TXT record is rarely > 255 bytes.
    // If the entire DNS packet is > 400 bytes and contains TXT, flag it.
    if (qtype == DNS_QTYPE_TXT && len > 400) {
        reason = "DNS: Oversized TXT response — possible tunneling (len=" +
                 std::to_string(len) + ")";
        push_event(src_str, name, "Tunnel", reason);
        return Action::BLOCK;
    }

    return Action::ALLOW;
}

// ── Public: configuration ─────────────────────────────────────

void DnsFirewall::block_domain(const std::string& suffix) {
    std::lock_guard<std::mutex> lock(mtx_);
    blocked_suffixes_.push_back(suffix);
}

void DnsFirewall::allow_domain(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mtx_);
    allowed_domains_.push_back(domain);
}

std::vector<DnsThreatEvent> DnsFirewall::get_recent_events() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return std::vector<DnsThreatEvent>(events_.begin(), events_.end());
}

void DnsFirewall::cleanup_stale() {
    std::lock_guard<std::mutex> lock(mtx_);
    auto now = std::chrono::steady_clock::now();
    for (auto it = ptr_states_.begin(); it != ptr_states_.end(); ) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.window_start).count();
        if (elapsed > 120)
            it = ptr_states_.erase(it);
        else
            ++it;
    }
}

// ── Private: DNS wire-format parsing ─────────────────────────

bool DnsFirewall::parse_question(const uint8_t* buf, uint16_t len,
                                  uint16_t& offset, std::string& name,
                                  uint16_t& qtype) {
    name = decode_name(buf, len, offset);
    if (name.empty() && offset >= len)
        return false;

    // qtype is 2 bytes after the name
    if (offset + 4 > len)
        return false;

    qtype = static_cast<uint16_t>((buf[offset] << 8) | buf[offset + 1]);
    offset += 4; // skip qtype (2) + qclass (2)
    return true;
}

std::string DnsFirewall::decode_name(const uint8_t* buf, uint16_t len,
                                      uint16_t& offset) {
    std::string result;
    bool first = true;

    while (offset < len) {
        uint8_t label_len = buf[offset++];

        // DNS pointer (compression) — 0xC0 prefix
        if ((label_len & 0xC0) == 0xC0) {
            // We don't follow pointers in the question section during inspection;
            // just stop here to avoid infinite loops on malformed packets.
            offset++; // consume the second byte of the pointer
            break;
        }

        if (label_len == 0)
            break; // root label — end of name

        if (offset + label_len > len)
            break; // truncated

        if (!first) result += '.';
        first = false;

        // Append the label, lowercased
        for (uint16_t i = 0; i < label_len; ++i) {
            result += static_cast<char>(
                std::tolower(static_cast<unsigned char>(buf[offset++])));
        }
    }

    return result;
}

// ── Private: detection algorithms ────────────────────────────

double DnsFirewall::shannon_entropy(const std::string& s) {
    if (s.empty()) return 0.0;

    uint32_t freq[256] = {};
    for (unsigned char c : s)
        freq[c]++;

    double entropy = 0.0;
    double len = static_cast<double>(s.size());
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = freq[i] / len;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

bool DnsFirewall::detect_dga(const std::string& label) const {
    if (label.size() < DGA_MIN_LENGTH)
        return false;

    double entropy = shannon_entropy(label);
    if (entropy < DGA_ENTROPY_THRESHOLD)
        return false;

    // Additional heuristic: count vowels.
    // Real English words have ~38% vowels; DGA names often have <15% or >60%
    static const std::string vowels = "aeiou";
    size_t vowel_count = 0;
    for (char c : label)
        if (vowels.find(c) != std::string::npos)
            vowel_count++;

    double vowel_ratio = static_cast<double>(vowel_count) / label.size();
    // Flag if vowel ratio is anomalously low (< 10%) or high (> 70%)
    // combined with high entropy — strong DGA signal
    if (vowel_ratio < 0.10 || vowel_ratio > 0.70)
        return true;

    // Secondary: digit ratio > 40% in a long label is also suspicious
    size_t digit_count = 0;
    for (char c : label)
        if (std::isdigit(static_cast<unsigned char>(c)))
            digit_count++;

    double digit_ratio = static_cast<double>(digit_count) / label.size();
    if (digit_ratio > 0.40)
        return true;

    return false;
}

bool DnsFirewall::detect_tunneling(const std::string& name) {
    if (name.empty()) return false;

    // Split into labels and inspect the longest one
    size_t max_label_len = 0;
    std::string longest_label;
    size_t pos = 0;
    while (pos < name.size()) {
        auto dot = name.find('.', pos);
        std::string label = (dot == std::string::npos)
                             ? name.substr(pos)
                             : name.substr(pos, dot - pos);
        if (label.size() > max_label_len) {
            max_label_len = label.size();
            longest_label = label;
        }
        pos = (dot == std::string::npos) ? name.size() : dot + 1;
    }

    // Rule 1: longest label > threshold (base64-encoded data)
    if (max_label_len < TUNNEL_LABEL_THRESHOLD)
        return false;

    // Rule 2: label consists mostly of base64/hex charset
    // base64 chars: A-Z a-z 0-9 + / =
    static const std::string b64_chars =
        "abcdefghijklmnopqrstuvwxyz0123456789+/=-_";
    size_t b64_count = 0;
    for (char c : longest_label)
        if (b64_chars.find(std::tolower(static_cast<unsigned char>(c)))
            != std::string::npos)
            b64_count++;

    double ratio = static_cast<double>(b64_count) / longest_label.size();
    return ratio >= TUNNEL_CHARSET_RATIO;
}

bool DnsFirewall::is_blocked_domain(const std::string& name) const {
    // Check allowlist first
    for (const auto& allowed : allowed_domains_) {
        if (name == allowed || name.find(allowed) == name.size() - allowed.size())
            return false;
    }
    // Check blocklist suffixes
    for (const auto& suffix : blocked_suffixes_) {
        if (name.size() >= suffix.size()) {
            if (name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0)
                return true;
        }
    }
    return false;
}

void DnsFirewall::push_event(const std::string& src_ip_str,
                              const std::string& domain,
                              const std::string& type,
                              const std::string& detail) {
    std::lock_guard<std::mutex> lock(mtx_);
    DnsThreatEvent ev;
    auto tp = std::chrono::steady_clock::now().time_since_epoch();
    ev.timestamp   = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(tp).count());
    ev.src_ip      = src_ip_str;
    ev.domain      = domain;
    ev.threat_type = type;
    ev.detail      = detail;
    if (events_.size() >= MAX_EVENTS)
        events_.pop_front();
    events_.push_back(std::move(ev));
}

} // namespace fw
