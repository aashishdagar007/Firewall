#include "rule_engine.hpp"
#include "packet.hpp"
#include "platform.hpp" // ip4_to_string
#include <iomanip>
#include <iostream>


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

EvalResult RuleEngine::evaluate(const PacketInfo &pkt) {
  // 0. Static Anomaly Detection (RFC Axioms)
  static Rule anomaly_rule{
      0, Action::BLOCK,      Proto::ANY, Direction::ANY, 0, 0, 0,
      0, "Anomaly Detected", 0};

  // Layer 3: Land attack (src IP == dst IP)
  if (pkt.src_ip != 0 && pkt.src_ip == pkt.dst_ip) {
    anomaly_rule.description = "Anomaly: Land Attack (src == dst)";
    anomaly_rule.hit_count++;
    return {Action::BLOCK, &anomaly_rule};
  }

  // Layer 3: Invalid TTL
  if (pkt.ttl > 0 &&
      pkt.ttl < 5) { // ttl is 0 if not extracted correctly, so only check > 0
    anomaly_rule.description = "Anomaly: Unusually low TTL (< 5)";
    anomaly_rule.hit_count++;
    return {Action::BLOCK, &anomaly_rule};
  }

  // Layer 3: Bogon Check (excluding common LAN subnets 10, 192.168, 172.16, 127)
  if (pkt.src_ip != 0) {
    uint8_t b1 = (pkt.src_ip >> 24) & 0xFF;
    uint8_t b2 = (pkt.src_ip >> 16) & 0xFF;
    if (b1 == 0 || b1 == 224 || b1 == 240 || (b1 == 169 && b2 == 254)) {
      anomaly_rule.description = "Anomaly: Bogon Source IP";
      anomaly_rule.hit_count++;
      return {Action::BLOCK, &anomaly_rule};
    }
  }

  // Layer 3: Fragment Validation (Strict drop for unreassembled fragments)
  if (pkt.is_frag_offset || pkt.has_more_frags) {
    anomaly_rule.description = "Anomaly: IP Fragmentation not supported";
    anomaly_rule.hit_count++;
    return {Action::BLOCK, &anomaly_rule};
  }

  // Layer 4: ICMP Validation
  if (pkt.proto == Proto::ICMP) {
    bool valid = false;
    if (pkt.icmp_type == 0 && pkt.icmp_code == 0) valid = true; // Echo Reply
    else if (pkt.icmp_type == 8 && pkt.icmp_code == 0) valid = true; // Echo Request
    else if (pkt.icmp_type == 3 && pkt.icmp_code <= 15) valid = true; // Dest Unreach
    else if (pkt.icmp_type == 11 && pkt.icmp_code <= 1) valid = true; // Time Exceeded
    
    if (!valid) {
      anomaly_rule.description = "Anomaly: Invalid ICMP Type/Code";
      anomaly_rule.hit_count++;
      return {Action::BLOCK, &anomaly_rule};
    }
  }

  // Layer 4: TCP Anomalies
  if (pkt.proto == Proto::TCP) {
    // NULL scan
    if (pkt.tcp_flags == 0) {
      anomaly_rule.description = "Anomaly: TCP NULL Scan";
      anomaly_rule.hit_count++;
      return {Action::BLOCK, &anomaly_rule};
    }
    // XMAS scan
    if ((pkt.tcp_flags & (TCP_FIN | TCP_PSH | TCP_URG)) ==
        (TCP_FIN | TCP_PSH | TCP_URG)) {
      anomaly_rule.description = "Anomaly: TCP XMAS Scan";
      anomaly_rule.hit_count++;
      return {Action::BLOCK, &anomaly_rule};
    }
    // SYN-FIN combination
    if ((pkt.tcp_flags & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN)) {
      anomaly_rule.description = "Anomaly: TCP SYN-FIN combination";
      anomaly_rule.hit_count++;
      return {Action::BLOCK, &anomaly_rule};
    }
    // SYN-RST combination
    if ((pkt.tcp_flags & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST)) {
      anomaly_rule.description = "Anomaly: TCP SYN-RST combination";
      anomaly_rule.hit_count++;
      return {Action::BLOCK, &anomaly_rule};
    }
  }

  // Layer 4: UDP Anomalies
  if (pkt.proto == Proto::UDP) {
    if (pkt.dst_port == 53 && pkt.size > 4096) {
      anomaly_rule.description = "Anomaly: Oversized DNS UDP packet";
      anomaly_rule.hit_count++;
      return {Action::BLOCK, &anomaly_rule};
    }
  }

  // 1. Connection Tracking (Stateful Inspection)
  if (pkt.proto == Proto::TCP || pkt.proto == Proto::UDP ||
      pkt.proto == Proto::ICMP) {
    ConnectionKey key{pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
                      pkt.proto};
    ConnectionKey rev_key{pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port,
                          pkt.proto};

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
      static Rule invalid_rule{0,
                               Action::BLOCK,
                               Proto::TCP,
                               Direction::ANY,
                               0,
                               0,
                               0,
                               0,
                               "INVALID TCP State (Auto-Drop)",
                               0};
      invalid_rule.hit_count++;
      return {Action::BLOCK, &invalid_rule};
    }
  }

  // 2. Threat Detection (Heuristics)
  {
    static constexpr uint32_t MAX_PACKETS_PER_SEC = 1000;
    static constexpr std::chrono::seconds BAN_DURATION{60};
    std::lock_guard<std::mutex> lock(state_mtx_);
    auto now = std::chrono::steady_clock::now();
    auto &tstate = threat_table_[pkt.src_ip];

    // Check if IP is currently banned
    if (tstate.is_banned) {
      if (now > tstate.ban_expires) {
        // Ban expired
        tstate.is_banned = false;
        tstate.packet_count = 0;
        tstate.syn_count = 0;
        tstate.window_start = now;
      } else {
        threat_rule_.hit_count++;
        return {Action::BLOCK, &threat_rule_};
      }
    }

    // Rate tracking (protects against port scans / SYN floods / DDoS)
    if (now - tstate.window_start > std::chrono::seconds(1)) {
      tstate.window_start = now;
      tstate.packet_count = 1;
      tstate.syn_count = (is_tcp && tcp_syn) ? 1 : 0;
    } else {
      tstate.packet_count++;
      if (is_tcp && tcp_syn)
        tstate.syn_count++;

      if (tstate.packet_count > 1000) {
        tstate.is_banned = true;
        tstate.ban_expires = now + std::chrono::seconds(60);
        threat_rule_.description =
            "Threat Detected: Rate Limit Exceeded (Auto-Ban)";
        threat_rule_.hit_count++;
        return {Action::BLOCK, &threat_rule_};
      }

      // SYN Flood / Port Scan protection
      if (tstate.syn_count > 20) {
        tstate.is_banned = true;
        tstate.ban_expires = now + std::chrono::seconds(60);
        threat_rule_.description =
            "Threat Detected: SYN Flood / Port Scan (Auto-Ban)";
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
  for (const auto &rule : rules_) {
    if (matches(rule, pkt)) {
      // We use mutable for hit_count, so this is safe
      rule.hit_count++;

      // If allowed, add to connection tracking
      if (rule.action == Action::ALLOW &&
          (pkt.proto == Proto::TCP || pkt.proto == Proto::UDP ||
           pkt.proto == Proto::ICMP)) {
        ConnectionKey key{pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
                          pkt.proto};
        std::lock_guard<std::mutex> lock(state_mtx_);
        bool create_state = true;
        if (pkt.proto == Proto::TCP && !(pkt.tcp_flags & TCP_SYN)) {
          create_state = false; // Only SYN packets can start a NEW TCP flow
        }
        if (create_state && state_table_.find(key) == state_table_.end()) {
          state_table_[key] = {FlowState::NEW, std::chrono::steady_clock::now(),
                               static_cast<uint64_t>(pkt.size)};
        }
      }

      return {rule.action, &rule};
    }
  }

  // Default policy — no rule matched
  return {default_policy_, nullptr};
}

void RuleEngine::purge_stale_connections(std::chrono::seconds timeout) {
  std::lock_guard<std::mutex> lock(state_mtx_);
  auto now = std::chrono::steady_clock::now();
  for (auto it = state_table_.begin(); it != state_table_.end();) {
    if (now - it->second.last_seen > timeout) {
      it = state_table_.erase(it);
    } else {
      ++it;
    }
  }
}

// ── Private: field-by-field matching ────────────────────────

bool RuleEngine::matches(const Rule &rule, const PacketInfo &pkt) {
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

  // Process Name (empty = wildcard)
  if (!rule.process_name.empty() && rule.process_name != pkt.process_name)
    return false;

  // Direction
  if (rule.direction != Direction::ANY && rule.direction != pkt.dir)
    return false;

  return true;
}

// ── Debug: print rule table ──────────────────────────────────

void RuleEngine::print_rules() const {
  std::cout << "\n┌────┬────────┬──────┬──────────────────┬──────────────────┬──────┬────────────────┬──────────────────────────────┐\n";
  std::cout << "│ ID │ Action │ Proto│ Src IP           │ Dst IP           │ Port │ Process        │ Description                  │\n";
  std::cout << "├────┼────────┼──────┼──────────────────┼──────────────────┼──────┼────────────────┼──────────────────────────────┤\n";

  auto ip_str = [](uint32_t ip) -> std::string {
    if (ip == 0)
      return "*";
    return ip4_to_string(ip);
  };

  for (const auto &r : rules_) {
    std::string dport = r.dst_port ? std::to_string(r.dst_port) : "*";
    std::string proc = r.process_name.empty() ? "*" : r.process_name;
    std::cout << "│ " << std::setw(2) << r.id << " │ " << std::setw(6)
              << action_name(r.action) << " │ " << std::setw(4)
              << proto_name(r.proto) << " │ " << std::setw(16)
              << ip_str(r.src_ip) << " │ " << std::setw(16) << ip_str(r.dst_ip)
              << " │ " << std::setw(4) << dport << " │ " << std::setw(14)
              << proc.substr(0, 14) << " │ " << std::setw(28)
              << r.description.substr(0, 28) << " │\n";
  }
  std::cout << "└────┴────────┴──────┴──────────────────┴──────────────────┴──────┴────────────────┴──────────────────────────────┘\n";
  std::cout << "  Default policy: " << action_name(default_policy_) << "\n\n";
}

} // namespace fw