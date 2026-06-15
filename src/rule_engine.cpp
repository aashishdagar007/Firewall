#include "rule_engine.hpp"
#include "packet.hpp"
#include "platform.hpp"   // ip4_to_string
#include <iostream>
#include <iomanip>

// ──────────────────────────────────────────────────────────────
//  rule_engine.cpp
// ──────────────────────────────────────────────────────────────

namespace fw {

RuleEngine::RuleEngine(Action default_policy)
    : default_policy_(default_policy) {}

void RuleEngine::add_rule(Rule r) {
    r.id = next_id_++;
    rules_.push_back(std::move(r));
}

bool RuleEngine::remove_rule(uint32_t id) {
    for (auto it = rules_.begin(); it != rules_.end(); ++it) {
        if (it->id == id) {
            rules_.erase(it);
            return true;
        }
    }
    return false;
}

EvalResult RuleEngine::evaluate(const PacketInfo& pkt) {
    // 1. Connection Tracking (Stateful Inspection)
    if (pkt.proto == Proto::TCP || pkt.proto == Proto::UDP || pkt.proto == Proto::ICMP) {
        ConnectionKey key{pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto};
        ConnectionKey rev_key{pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.proto};

        std::lock_guard<std::mutex> lock(state_mtx_);

        bool is_tcp = (pkt.proto == Proto::TCP);
        bool tcp_syn = is_tcp && (pkt.tcp_flags & TCP_SYN);
        bool tcp_ack = is_tcp && (pkt.tcp_flags & TCP_ACK);
        bool tcp_fin_rst = is_tcp && (pkt.tcp_flags & (TCP_FIN | TCP_RST));

        // Check if this packet belongs to an established connection
        auto it = state_table_.find(key);
        auto rev_it = state_table_.find(rev_key);

        if (it != state_table_.end()) {
            // Forward direction packet
            if (is_tcp && tcp_fin_rst) {
                // Connection teardown
                state_table_.erase(it);
                return {Action::ALLOW, nullptr};
            }
            it->second.last_seen = std::chrono::steady_clock::now();
            it->second.bytes_transferred += pkt.size;
            return {Action::ALLOW, nullptr};
        } else if (rev_it != state_table_.end()) {
            // Reverse direction packet
            if (is_tcp) {
                if (tcp_fin_rst) {
                    state_table_.erase(rev_it);
                    return {Action::ALLOW, nullptr};
                }
                if (tcp_syn && tcp_ack && rev_it->second.state == FlowState::NEW) {
                    rev_it->second.state = FlowState::ESTABLISHED;
                }
            } else {
                // UDP/ICMP: First reply promotes to ESTABLISHED
                if (rev_it->second.state == FlowState::NEW) {
                    rev_it->second.state = FlowState::ESTABLISHED;
                }
            }
            rev_it->second.last_seen = std::chrono::steady_clock::now();
            rev_it->second.bytes_transferred += pkt.size;
            return {Action::ALLOW, nullptr};
        }

        // --- INVALID State Check ---
        // If we reach here, no existing flow matches.
        if (is_tcp && !tcp_syn) {
            // Bare ACK or other non-SYN packets with no matching flow are INVALID.
            // This drops state-exhaustion probes.
            static Rule invalid_rule{0, Action::BLOCK, Proto::TCP, Direction::ANY, 0, 0, 0, 0, "INVALID TCP State (Auto-Drop)", 0};
            invalid_rule.hit_count++;
            return {Action::BLOCK, &invalid_rule};
        }
    }

    // 2. Threat Detection (Heuristics)
    {
        std::lock_guard<std::mutex> lock(state_mtx_);
        auto now = std::chrono::steady_clock::now();
        auto& tstate = threat_table_[pkt.src_ip];
        
        // Check if IP is currently banned
        if (tstate.is_banned) {
            if (now > tstate.ban_expires) {
                // Ban expired
                tstate.is_banned = false;
                tstate.packet_count = 0;
                tstate.window_start = now;
            } else {
                threat_rule_.hit_count++;
                return {Action::BLOCK, &threat_rule_};
            }
        }

        // Rate tracking (protects against port scans / SYN floods)
        if (now - tstate.window_start > std::chrono::seconds(1)) {
            tstate.window_start = now;
            tstate.packet_count = 1;
        } else {
            tstate.packet_count++;
            if (tstate.packet_count > MAX_PACKETS_PER_SEC) {
                tstate.is_banned = true;
                tstate.ban_expires = now + BAN_DURATION;
                threat_rule_.description = "Threat Detected: High-Frequency Scanning (Auto-Ban)";
                threat_rule_.hit_count++;
                return {Action::BLOCK, &threat_rule_};
            }
        }
        
        // Suspicious Ports Check (Known malware/vulnerability ports)
        if (pkt.dst_port == 445 || pkt.dst_port == 135 || pkt.dst_port == 23) {
            threat_rule_.description = "Threat Detected: Probing Vulnerable Port";
            threat_rule_.hit_count++;
            return {Action::BLOCK, &threat_rule_};
        }
    }

    // 2. Stateless Rule Evaluation
    for (const auto& rule : rules_) {
        if (matches(rule, pkt)) {
            // We use mutable for hit_count, so this is safe
            rule.hit_count++;
            
            // If allowed, add to connection tracking
            if (rule.action == Action::ALLOW && (pkt.proto == Proto::TCP || pkt.proto == Proto::UDP || pkt.proto == Proto::ICMP)) {
                ConnectionKey key{pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto};
                std::lock_guard<std::mutex> lock(state_mtx_);
                bool create_state = true;
                if (pkt.proto == Proto::TCP && !(pkt.tcp_flags & TCP_SYN)) {
                    create_state = false; // Only SYN packets can start a NEW TCP flow
                }
                if (create_state && state_table_.find(key) == state_table_.end()) {
                    state_table_[key] = {FlowState::NEW, std::chrono::steady_clock::now(), static_cast<uint64_t>(pkt.size)};
                }
            }

            return { rule.action, &rule };
        }
    }

    // Default policy — no rule matched
    return { default_policy_, nullptr };
}

void RuleEngine::purge_stale_connections(std::chrono::seconds timeout) {
    std::lock_guard<std::mutex> lock(state_mtx_);
    auto now = std::chrono::steady_clock::now();
    for (auto it = state_table_.begin(); it != state_table_.end(); ) {
        if (now - it->second.last_seen > timeout) {
            it = state_table_.erase(it);
        } else {
            ++it;
        }
    }
}

// ── Private: field-by-field matching ────────────────────────

bool RuleEngine::matches(const Rule& rule, const PacketInfo& pkt) {
    // Protocol (ANY matches everything)
    if (rule.proto != Proto::ANY && rule.proto != pkt.proto)
        return false;

    // Source IP  (0 = wildcard)
    if (rule.src_ip != 0 && rule.src_ip != pkt.src_ip)
        return false;

    // Dest IP
    if (rule.dst_ip != 0 && rule.dst_ip != pkt.dst_ip)
        return false;

    // Source port (0 = wildcard)
    if (rule.src_port != 0 && rule.src_port != pkt.src_port)
        return false;

    // Dest port
    if (rule.dst_port != 0 && rule.dst_port != pkt.dst_port)
        return false;

    // Direction
    if (rule.direction != Direction::ANY && rule.direction != pkt.dir)
        return false;

    return true;
}

// ── Debug: print rule table ──────────────────────────────────

void RuleEngine::print_rules() const {
    std::cout << "\n┌────┬────────┬──────┬──────────────────┬──────────────────┬──────┬──────────────────────────────┐\n";
    std::cout <<   "│ ID │ Action │ Proto│ Src IP           │ Dst IP           │ Port │ Description                  │\n";
    std::cout <<   "├────┼────────┼──────┼──────────────────┼──────────────────┼──────┼──────────────────────────────┤\n";

    auto ip_str = [](uint32_t ip) -> std::string {
        if (ip == 0) return "*";
        return ip4_to_string(ip);
    };

    for (const auto& r : rules_) {
        std::string dport = r.dst_port ? std::to_string(r.dst_port) : "*";
        std::cout << "│ "   << std::setw(2) << r.id
                  << " │ "  << std::setw(6) << action_name(r.action)
                  << " │ "  << std::setw(4) << proto_name(r.proto)
                  << " │ "  << std::setw(16) << ip_str(r.src_ip)
                  << " │ "  << std::setw(16) << ip_str(r.dst_ip)
                  << " │ "  << std::setw(4)  << dport
                  << " │ "  << std::setw(28) << r.description.substr(0,28)
                  << " │\n";
    }
    std::cout << "└────┴────────┴──────┴──────────────────┴──────────────────┴──────┴──────────────────────────────┘\n";
    std::cout << "  Default policy: " << action_name(default_policy_) << "\n\n";
}

} // namespace fw