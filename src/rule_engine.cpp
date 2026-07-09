#include "rule_engine.hpp"
#include "packet.hpp"
#include "platform.hpp" // ip4_to_string
#include <iomanip>
#include <iostream>
#include <fstream>

// ──────────────────────────────────────────────────────────────
//  rule_engine.cpp
// ──────────────────────────────────────────────────────────────

namespace fw {

RuleEngine::RuleEngine(Action default_policy)
    : default_policy_(default_policy) {
  state_table_.reserve(4096); // pre-allocate to avoid rehash under burst
  heuristic_thread_ = std::thread(&RuleEngine::heuristic_worker, this);
}

RuleEngine::~RuleEngine() {
  stop_heuristics_ = true;
  if (heuristic_thread_.joinable()) {
    heuristic_thread_.join();
  }
}

void RuleEngine::set_default_policy(Action a) { default_policy_ = a; }

void RuleEngine::set_local_ip(uint32_t ip) { local_ip_ = ip; }

void RuleEngine::add_rule(Rule r) {
  std::unique_lock<std::shared_mutex> lock(rules_mtx_);
  r.id = next_id_++;
  rules_.push_back(std::move(r));
  rebuild_port_index();
  std::lock_guard<std::shared_mutex> clock(cache_mtx_);
  eval_cache_.clear();
}

bool RuleEngine::remove_rule(uint32_t id) {
  std::unique_lock<std::shared_mutex> lock(rules_mtx_);
  for (auto it = rules_.begin(); it != rules_.end(); ++it) {
    if (it->id == id) {
      rules_.erase(it);
      rebuild_port_index();
      std::lock_guard<std::shared_mutex> clock(cache_mtx_);
      eval_cache_.clear();
      return true;
    }
  }
  return false;
}

EvalResult RuleEngine::evaluate(const PacketInfo &pkt) {
  // Build canonical (always src < dst) 5-tuple once — reused for conntrack
  // lookup, cache read, and cache write.
  auto make_key = [&]() {
    ConnectionKey k;
    k.proto = pkt.proto;
    if (pkt.src_ip < pkt.dst_ip) {
      k.src_ip = pkt.src_ip; k.dst_ip = pkt.dst_ip;
      k.src_port = pkt.src_port; k.dst_port = pkt.dst_port;
    } else {
      k.src_ip = pkt.dst_ip; k.dst_ip = pkt.src_ip;
      k.src_port = pkt.dst_port; k.dst_port = pkt.src_port;
    }
    return k;
  };

  // ── Traffic Shaping (QoS) ──
  if (pkt.src_ip != 0 && !traffic_shaper_.consume(pkt.src_ip, pkt.size)) {
    qos_drop_rule_.hit_count++;
    return {Action::BLOCK, &qos_drop_rule_};
  }

  // Layer 3: Land attack (src IP == dst IP)
  if (pkt.src_ip != 0 && pkt.src_ip == pkt.dst_ip) {
    anomaly_land_.hit_count++;
    return {Action::BLOCK, &anomaly_land_};
  }

  // Layer 3: Invalid TTL
  if (pkt.ttl > 0 &&
      pkt.ttl < 5) { // ttl is 0 if not extracted correctly, so only check > 0
    anomaly_ttl_.hit_count++;
    return {Action::BLOCK, &anomaly_ttl_};
  }

  // Layer 3: Strict Bogon Check (Unroutable and Multicast only)
  // Bypassed if packet originates from our own local IP
  if (pkt.src_ip != 0 && pkt.src_ip != local_ip_) {
    uint8_t b1 = (pkt.src_ip >> 24) & 0xFF;
    bool is_bogon = false;
    // 0.0.0.0/8, 224.0.0.0/4 (Multicast), 240.0.0.0/4 (Reserved)
    // 127.0.0.0/8 (Loopback) is allowed for local inter-process communication
    if (b1 == 0 || b1 == 224 || b1 == 240)
      is_bogon = true;

    if (is_bogon) {
      anomaly_bogon_.hit_count++;
      return {Action::BLOCK, &anomaly_bogon_};
    }
  }

  // Layer 3: Geo-Block CIDR check
  if (pkt.src_ip != 0 && pkt.src_ip != local_ip_) {
    if (is_geo_blocked(pkt.src_ip)) {
      std::lock_guard<std::mutex> lock(state_mtx_);
      threat_rule_.description = "Geo-Block: CIDR range blocked";
      threat_rule_.hit_count++;
      return {Action::BLOCK, &threat_rule_};
    }
  }

  // Layer 3: Fragment Validation (Strict drop for unreassembled fragments)
  if (pkt.is_frag_offset || pkt.has_more_frags) {
    anomaly_frag_.hit_count++;
    return {Action::BLOCK, &anomaly_frag_};
  }

  // Layer 4: ICMP Validation (Echo Reply/Req, Dest-Unreach, Time-Exceeded only)
  if (pkt.proto == Proto::ICMP) {
    const bool valid =
        (pkt.icmp_type == 0  && pkt.icmp_code == 0)         || // Echo Reply
        (pkt.icmp_type == 8  && pkt.icmp_code == 0)         || // Echo Request
        (pkt.icmp_type == 3  && pkt.icmp_code <= 15)        || // Dest Unreach
        (pkt.icmp_type == 11 && pkt.icmp_code <= 1);           // Time Exceeded
    if (!valid) {
      anomaly_icmp_.hit_count++;
      return {Action::BLOCK, &anomaly_icmp_};
    }
  }

  // Layer 4: TCP Anomalies
  if (pkt.proto == Proto::TCP) {
    // NULL scan
    if (pkt.tcp_flags == 0) {
      anomaly_tcp_null_.hit_count++;
      return {Action::BLOCK, &anomaly_tcp_null_};
    }
    // FIN scan
    if ((pkt.tcp_flags & TCP_FIN) && !(pkt.tcp_flags & TCP_ACK)) {
      anomaly_tcp_fin_.hit_count++;
      return {Action::BLOCK, &anomaly_tcp_fin_};
    }
    // XMAS scan
    if ((pkt.tcp_flags & (TCP_FIN | TCP_PSH | TCP_URG)) ==
        (TCP_FIN | TCP_PSH | TCP_URG)) {
      anomaly_tcp_xmas_.hit_count++;
      return {Action::BLOCK, &anomaly_tcp_xmas_};
    }
    // SYN-FIN combination
    if ((pkt.tcp_flags & (TCP_SYN | TCP_FIN)) == (TCP_SYN | TCP_FIN)) {
      anomaly_tcp_synfin_.hit_count++;
      return {Action::BLOCK, &anomaly_tcp_synfin_};
    }
    // SYN-RST combination
    if ((pkt.tcp_flags & (TCP_SYN | TCP_RST)) == (TCP_SYN | TCP_RST)) {
      anomaly_tcp_synrst_.hit_count++;
      return {Action::BLOCK, &anomaly_tcp_synrst_};
    }
    // Strict SYN: Should not have PSH or URG
    if ((pkt.tcp_flags & TCP_SYN) && (pkt.tcp_flags & (TCP_PSH | TCP_URG))) {
      anomaly_tcp_syn_flags_.hit_count++;
      return {Action::BLOCK, &anomaly_tcp_syn_flags_};
    }
    // Strict SYN: Should not contain payload data (mitigates SYN floods with
    // data)
    if ((pkt.tcp_flags & TCP_SYN) && pkt.payload_len > 0) {
      anomaly_tcp_syn_data_.hit_count++;
      return {Action::BLOCK, &anomaly_tcp_syn_data_};
    }
  }

  // Layer 4: Port 0 Validation
  if (pkt.proto == Proto::TCP || pkt.proto == Proto::UDP) {
    if (pkt.src_port == 0 || pkt.dst_port == 0) {
      anomaly_port_zero_.hit_count++;
      return {Action::BLOCK, &anomaly_port_zero_};
    }
  }

  // Layer 4: UDP Anomalies
  if (pkt.proto == Proto::UDP) {
    if (pkt.dst_port == 53 && pkt.size > 4096) {
      anomaly_udp_dns_.hit_count++;
      return {Action::BLOCK, &anomaly_udp_dns_};
    }
  }

  // 0.5 Layer 7 Deep Packet Inspection (DPI)
  std::string dpi_threat_name;
  if (dpi_.scan(pkt.payload_ptr, pkt.payload_len, dpi_threat_name) ==
      Action::BLOCK) {
    std::lock_guard<std::mutex> lock(state_mtx_);
    dpi_rule_.description = dpi_threat_name;
    dpi_rule_.hit_count++;
    return {Action::BLOCK, &dpi_rule_};
  }

  // 1. Connection Tracking (Stateful Inspection)
  if (pkt.proto == Proto::TCP || pkt.proto == Proto::UDP ||
      pkt.proto == Proto::ICMP) {

    const ConnectionKey canonical_key = make_key();

    std::lock_guard<std::mutex> lock(state_mtx_);

    bool is_tcp = (pkt.proto == Proto::TCP);
    bool tcp_syn = is_tcp && (pkt.tcp_flags & TCP_SYN);
    bool tcp_ack = is_tcp && (pkt.tcp_flags & TCP_ACK);
    bool tcp_fin_rst = is_tcp && (pkt.tcp_flags & (TCP_FIN | TCP_RST));

    // O(1) single map lookup for bidirectional connection state
    auto it = state_table_.find(canonical_key);

    if (it != state_table_.end()) {
      auto &state = it->second;
      bool is_originator = (pkt.src_ip == state.originator_ip);

      if (is_tcp) {
        if (tcp_fin_rst) {
          state_table_.erase(it);
          return {Action::ALLOW, nullptr};
        }
        if (is_originator) {
          // TCP Sequence Window Validation (Session Hijacking check)
          int32_t seq_diff =
              static_cast<int32_t>(pkt.tcp_seq - state.expected_seq);
          if (seq_diff < -131072 || seq_diff > 131072) {
            hijack_rule_.hit_count++;
            return {Action::BLOCK, &hijack_rule_};
          }
          state.expected_seq = pkt.tcp_seq + pkt.size; // approximation
        } else {
          if (tcp_syn && tcp_ack && state.state == FlowState::NEW) {
            state.state = FlowState::ESTABLISHED;
            state.expected_ack = pkt.tcp_seq;
          } else {
            int32_t seq_diff =
                static_cast<int32_t>(pkt.tcp_seq - state.expected_ack);
            if (state.state == FlowState::ESTABLISHED &&
                (seq_diff < -131072 || seq_diff > 131072)) {
              hijack_rule_.hit_count++;
              return {Action::BLOCK, &hijack_rule_};
            }
            state.expected_ack = pkt.tcp_seq + pkt.size;
          }
        }
      } else {
        // UDP/ICMP: First reply promotes to ESTABLISHED
        if (!is_originator && state.state == FlowState::NEW) {
          state.state = FlowState::ESTABLISHED;
        }
      }

      state.last_seen = std::chrono::steady_clock::now();
      state.bytes_transferred += pkt.size;
      if (is_originator)
        state.bytes_out += pkt.payload_len;
      else
        state.bytes_in += pkt.payload_len;

      return {Action::ALLOW, nullptr};
    }

    // --- INVALID State Check ---
    // If we reach here, no existing flow matches.
    if (is_tcp && !tcp_syn) {
      // Bare ACK or other non-SYN packets with no matching flow are INVALID.
      // This drops state-exhaustion probes.
      invalid_rule_.hit_count++;
      return {Action::BLOCK, &invalid_rule_};
    }
  }

  // 2. Threat Detection (Heuristics)
  {
    std::lock_guard<std::mutex> lock(state_mtx_);
    auto now = std::chrono::steady_clock::now();
    auto &tstate = threat_table_[pkt.src_ip];

    bool is_tcp_pkt = (pkt.proto == Proto::TCP);
    bool is_syn_pkt = is_tcp_pkt && (pkt.tcp_flags & TCP_SYN);
    bool is_udp_pkt = (pkt.proto == Proto::UDP);
    bool is_icmp_pkt = (pkt.proto == Proto::ICMP);

    // Check if IP is currently banned
    if (tstate.is_banned) {
      if (now > tstate.ban_expires) {
        // Ban expired
        tstate.is_banned = false;
        tstate.packet_count = 0;
        tstate.syn_count = 0;
        tstate.udp_count = 0;
        tstate.icmp_count = 0;
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
      tstate.syn_count = is_syn_pkt ? 1 : 0;
      tstate.udp_count = is_udp_pkt ? 1 : 0;
      tstate.icmp_count = is_icmp_pkt ? 1 : 0;
    } else {
      tstate.packet_count++;
      if (is_syn_pkt) tstate.syn_count++;
      if (is_udp_pkt) tstate.udp_count++;
      if (is_icmp_pkt) tstate.icmp_count++;

      if (tstate.packet_count > rate_limit_pps_.load()) {
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
        tstate.ban_count++;
        // Escalating bans: if banned > 2 times, ban for 24 hours
        auto duration = (tstate.ban_count > 2) ? std::chrono::hours(24)
                                               : std::chrono::seconds(60);
        tstate.ban_expires = now + duration;
        threat_rule_.description =
            (tstate.ban_count > 2)
                ? "Threat Detected: SYN Flood (Permanent Ban Escalate)"
                : "Threat Detected: SYN Flood / Port Scan (Auto-Ban)";
        threat_rule_.hit_count++;
        return {Action::BLOCK, &threat_rule_};
      }

      // UDP Flood protection (excluding DNS and QUIC)
      if (tstate.udp_count > 100 && pkt.dst_port != 53 && pkt.dst_port != 443) {
        tstate.is_banned = true;
        tstate.ban_count++;
        tstate.ban_expires = now + std::chrono::seconds(120);
        anomaly_udp_flood_.hit_count++;
        return {Action::BLOCK, &anomaly_udp_flood_};
      }

      // ICMP (Ping) Flood / Smurf protection
      if (tstate.icmp_count > 50) {
        tstate.is_banned = true;
        tstate.ban_count++;
        tstate.ban_expires = now + std::chrono::seconds(300);
        anomaly_icmp_flood_.hit_count++;
        return {Action::BLOCK, &anomaly_icmp_flood_};
      }
    }

    // Suspicious Ports Check (Known malware/vulnerability ports)
    if (pkt.dst_port == 445 || pkt.dst_port == 135 || pkt.dst_port == 23) {
      threat_rule_.description = "Threat Detected: Probing Vulnerable Port";
      threat_rule_.hit_count++;
      return {Action::BLOCK, &threat_rule_};
    }
  }

  // 2. Stateless Rule Evaluation — port-indexed O(1) lookup
  const ConnectionKey canonical_key = make_key();

  {
    std::shared_lock<std::shared_mutex> clock(cache_mtx_);
    auto cit = eval_cache_.find(canonical_key);
    if (cit != eval_cache_.end()) {
      // NOTE: We don't have the matched Rule* anymore, but we have the Action.
      return {cit->second, nullptr};
    }
  }

  Action final_action = default_policy_;
  const Rule* matched_ptr = nullptr;

  {
    std::shared_lock<std::shared_mutex> rule_lock(rules_mtx_);

    // Collect candidate rule indices: specific-port bucket + all wildcards
    // Use a local lambda to evaluate a rule by its index
    auto try_rule = [&](size_t idx) -> bool {
      if (idx >= rules_.size()) return false;
      const auto& rule = rules_[idx];
      if (matches(rule, pkt)) {
        rule.hit_count++;
        if (rule.action == Action::ALLOW &&
            (pkt.proto == Proto::TCP || pkt.proto == Proto::UDP ||
             pkt.proto == Proto::ICMP)) {
          std::lock_guard<std::mutex> lock(state_mtx_);
          bool create_state = true;
          if (pkt.proto == Proto::TCP && !(pkt.tcp_flags & TCP_SYN))
            create_state = false;
          if (create_state &&
              state_table_.find(canonical_key) == state_table_.end()) {
            state_table_[canonical_key] = {
                FlowState::NEW,
                std::chrono::steady_clock::now(),
                pkt.src_ip,
                static_cast<uint64_t>(pkt.size),
                static_cast<uint64_t>(pkt.payload_len),
                0,
                pkt.tcp_seq + static_cast<uint32_t>(pkt.size),
                0};
          }
        }
        return true;
      }
      return false;
    };

    bool found = false;
    // Check rules matching the exact dst_port first (port-indexed)
    if (pkt.dst_port != 0) {
      auto range = port_index_.equal_range(pkt.dst_port);
      for (auto it = range.first; it != range.second; ++it) {
        if (try_rule(it->second)) {
          matched_ptr = &rules_[it->second];
          final_action = matched_ptr->action;
          found = true;
          break;
        }
      }
    }

    if (!found) {
      // Then check wildcard (dst_port == 0) rules in order
      for (size_t idx : wildcard_rule_indices_) {
        if (try_rule(idx)) {
          matched_ptr = &rules_[idx];
          final_action = matched_ptr->action;
          found = true;
          break;
        }
      }
    }
  }

  // Update Cache
  {
    std::lock_guard<std::shared_mutex> clock(cache_mtx_);
    if (eval_cache_.size() > 100000) eval_cache_.clear(); // basic LRU protection
    eval_cache_[canonical_key] = final_action;
  }

  auto default_result = EvalResult{final_action, matched_ptr};

  // ── Port Scan Detection (runs for every packet regardless of verdict) ─
  // We pass the packet through the detector AFTER the main evaluation so
  // that we catch cross-port patterns even when individual packets are
  // already blocked by anomaly rules.
  {
    auto scan_opt = scan_detector_.record(pkt);
    if (scan_opt.has_value()) {
      // Auto-ban the scanner's IP immediately
      {
        std::lock_guard<std::mutex> lock(state_mtx_);
        auto now = std::chrono::steady_clock::now();
        auto& tstate = threat_table_[pkt.src_ip];
        tstate.is_banned   = true;
        tstate.ban_count  += 5; // escalate ban count to mark as port-scanner
        tstate.ban_expires = now + std::chrono::hours(24);
      }
      // Fire the dashboard callback (non-blocking: callback queues the event)
      if (scan_callback_) {
        scan_callback_(scan_opt.value());
      }
    }
  }

  return default_result;
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

void RuleEngine::heuristic_worker() {
  while (!stop_heuristics_) {
    std::this_thread::sleep_for(std::chrono::seconds(5));

    std::lock_guard<std::mutex> lock(state_mtx_);
    auto now = std::chrono::steady_clock::now();

    // 1. Kill asymmetric flows (potential data exfiltration)
    for (auto it = state_table_.begin(); it != state_table_.end();) {
      if (it->second.bytes_out > 2000000 && it->second.bytes_in < 5000) {
        auto &tstate = threat_table_[it->first.src_ip];
        tstate.is_banned   = true;
        tstate.ban_count  += 5;
        tstate.ban_expires = now + std::chrono::hours(24);
        it = state_table_.erase(it);
      } else {
        ++it;
      }
    }

    // 2. Prune expired/inactive threat table entries
    for (auto it = threat_table_.begin(); it != threat_table_.end();) {
      const auto& ts = it->second;
      // Remove if ban has expired AND the window is older than 60 seconds
      bool ban_expired = !ts.is_banned ||
                         (ts.is_banned && now > ts.ban_expires);
      bool window_stale = (now - ts.window_start) > std::chrono::seconds(60);
      if (ban_expired && window_stale) {
        it = threat_table_.erase(it);
      } else {
        ++it;
      }
    }
  }
}

// ── Private: field-by-field matching ────────────────────────

bool RuleEngine::matches(const Rule &rule, const PacketInfo &pkt) {
  // Protocol (ANY matches everything)
  if (rule.proto != Proto::ANY && rule.proto != pkt.proto)
    return false;

  // Source IP with Mask
  if (rule.src_ip != 0) {
    if ((pkt.src_ip & rule.src_ip_mask) != (rule.src_ip & rule.src_ip_mask))
      return false;
  }

  // Dest IP with Mask
  if (rule.dst_ip != 0) {
    if ((pkt.dst_ip & rule.dst_ip_mask) != (rule.dst_ip & rule.dst_ip_mask))
      return false;
  }

  // Source port range
  if (rule.src_port_start != 0) {
    if (pkt.src_port < rule.src_port_start || pkt.src_port > rule.src_port_end)
      return false;
  }

  // Dest port range
  if (rule.dst_port_start != 0) {
    if (pkt.dst_port < rule.dst_port_start || pkt.dst_port > rule.dst_port_end)
      return false;
  }

  // Source MAC Address
  if (rule.src_mac[0] != 0 || rule.src_mac[1] != 0 || rule.src_mac[2] != 0 ||
      rule.src_mac[3] != 0 || rule.src_mac[4] != 0 || rule.src_mac[5] != 0) {
    if (pkt.src_mac != rule.src_mac)
      return false;
  }

  // Dest MAC Address
  if (rule.dst_mac[0] != 0 || rule.dst_mac[1] != 0 || rule.dst_mac[2] != 0 ||
      rule.dst_mac[3] != 0 || rule.dst_mac[4] != 0 || rule.dst_mac[5] != 0) {
    if (pkt.dst_mac != rule.dst_mac)
      return false;
  }

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
  std::cout << "\n┌────┬────────┬──────┬──────────────────┬──────────────────┬─"
               "─────┬────────────────┬──────────────────────────────┐\n";
  std::cout << "│ ID │ Action │ Proto│ Src IP           │ Dst IP           │ "
               "Port │ Process        │ Description                  │\n";
  std::cout << "├────┼────────┼──────┼──────────────────┼──────────────────┼───"
               "───┼────────────────┼──────────────────────────────┤\n";

  auto ip_str = [](uint32_t ip, uint32_t mask) -> std::string {
    if (ip == 0 && mask == 0xFFFFFFFF) return "*";
    std::string res = ip4_to_string(ip);
    if (mask != 0xFFFFFFFF) {
        uint32_t m = mask;
        int bits = 0;
        while (m) { bits += (m & 1); m >>= 1; }
        res += "/" + std::to_string(bits);
    }
    return res;
  };

  std::shared_lock<std::shared_mutex> lock(rules_mtx_);
  for (const auto &r : rules_) {
    std::string dport = "*";
    if (r.dst_port_start != 0) {
      if (r.dst_port_start == r.dst_port_end) dport = std::to_string(r.dst_port_start);
      else dport = std::to_string(r.dst_port_start) + "-" + std::to_string(r.dst_port_end);
    }
    std::string proc = r.process_name.empty() ? "*" : r.process_name;
    std::cout << "│ " << std::setw(2) << r.id << " │ " << std::setw(6)
              << action_name(r.action) << " │ " << std::setw(4)
              << proto_name(r.proto) << " │ " << std::setw(16)
              << ip_str(r.src_ip, r.src_ip_mask).substr(0, 16) << " │ " << std::setw(16) << ip_str(r.dst_ip, r.dst_ip_mask).substr(0, 16)
              << " │ " << std::setw(8) << dport.substr(0, 8) << " │ " << std::setw(14)
              << proc.substr(0, 14) << " │ " << std::setw(28)
              << r.description.substr(0, 28) << " │\n";
  }
  std::cout << "└────┴────────┴──────┴──────────────────┴──────────────────┴───"
               "───┴────────────────┴──────────────────────────────┘\n";
  std::cout << "  Default policy: " << action_name(default_policy_) << "\n\n";
}

// ── Additional method implementations ────────────────────────

// ── Stealth Mode ──────────────────────────────────────────────

void RuleEngine::set_stealth_mode(bool enabled) {
  stealth_mode_.store(enabled);
}

// ── Port Scan Detection ───────────────────────────────────────

void RuleEngine::set_scan_callback(std::function<void(ScanEvent)> cb) {
  scan_detector_.set_callback(std::move(cb));
}

std::vector<ScanEvent> RuleEngine::get_scan_events() const {
  return scan_detector_.get_recent_events();
}

// ── Port index ───────────────────────────────────────────────

void RuleEngine::rebuild_port_index() {
  // Called under rules_mtx_ write lock — no additional locking needed
  port_index_.clear();
  wildcard_rule_indices_.clear();
  for (size_t i = 0; i < rules_.size(); ++i) {
    if (rules_[i].dst_port_start == 0 || rules_[i].dst_port_start != rules_[i].dst_port_end) {
      wildcard_rule_indices_.push_back(i);
    } else {
      port_index_.emplace(rules_[i].dst_port_start, i);
    }
  }
}

// ── Geo-Block ────────────────────────────────────────────────

bool RuleEngine::is_geo_blocked(uint32_t ip) const {
  // No lock needed — geo_blocks_ only modified under state_mtx_ or rules_mtx_
  // and reads here are safe since we hold nothing that prevents a race;
  // caller holds state_mtx_ indirectly via evaluate(). We protect with a
  // separate read here via the same state_mtx_ — check callers first.
  // NOTE: this is called from evaluate() before any state lock; geo_blocks_
  // is only written under state_mtx_, so we use it here consistently.
  for (const auto& g : geo_blocks_) {
    if ((ip & g.mask) == (g.network & g.mask))
      return true;
  }
  return false;
}

void RuleEngine::block_cidr(uint32_t network, uint32_t mask,
                             const std::string& label) {
  std::lock_guard<std::mutex> lock(state_mtx_);
  geo_blocks_.push_back({network, mask, label});
}

bool RuleEngine::unblock_cidr(size_t index) {
  std::lock_guard<std::mutex> lock(state_mtx_);
  if (index >= geo_blocks_.size())
    return false;
  geo_blocks_.erase(geo_blocks_.begin() + static_cast<ptrdiff_t>(index));
  return true;
}

std::vector<GeoEntry> RuleEngine::get_geo_blocks() const {
  std::lock_guard<std::mutex> lock(state_mtx_);
  return geo_blocks_;
}

// ── Rate Limit ───────────────────────────────────────────────

void RuleEngine::set_rate_limit(uint32_t pps) {
  rate_limit_pps_.store(pps);
}

uint32_t RuleEngine::get_rate_limit() const {
  return rate_limit_pps_.load();
}

// ── Threat Table ─────────────────────────────────────────────

std::vector<ThreatSnapshot> RuleEngine::get_threat_table_snapshot() const {
  std::lock_guard<std::mutex> lock(state_mtx_);
  std::vector<ThreatSnapshot> out;
  out.reserve(threat_table_.size());
  for (const auto& [ip, ts] : threat_table_) {
    if (!ts.is_banned) continue;
    ThreatSnapshot snap;
    snap.src_ip     = ip;
    snap.ip_str     = ip4_to_string(ip);
    snap.ban_count  = ts.ban_count;
    snap.ban_expires = ts.ban_expires;
    // Derive reason from ban_count escalation level
    if (ts.ban_count >= 100)
      snap.reason = "Manual Ban";
    else if (ts.ban_count >= 10)
      snap.reason = "Protocol Tampering Attack (HMAC Failed)";
    else if (ts.ban_count >= 5)
      snap.reason = "Data Exfiltration (Heuristic)";
    else if (ts.ban_count > 2)
      snap.reason = "SYN Flood — Escalated Ban";
    else
      snap.reason = "Rate Limit / SYN Flood";
    out.push_back(std::move(snap));
  }
  return out;
}

bool RuleEngine::unban_ip(uint32_t src_ip) {
  std::lock_guard<std::mutex> lock(state_mtx_);
  auto it = threat_table_.find(src_ip);
  if (it == threat_table_.end())
    return false;
  it->second.is_banned    = false;
  it->second.ban_count    = 0;
  it->second.packet_count = 0;
  it->second.syn_count    = 0;
  return true;
}

bool RuleEngine::ban_ip(uint32_t src_ip, const std::string& reason) {
  std::lock_guard<std::mutex> lock(state_mtx_);
  auto now = std::chrono::steady_clock::now();
  auto &tstate = threat_table_[src_ip];

  // Manual bans are permanent; ban_count=100 triggers "Manual Ban" label
  tstate.is_banned   = true;
  tstate.ban_count   = 100;
  tstate.ban_expires = now + std::chrono::hours(24 * 365);
  return true;
}

void RuleEngine::report_tampering_attempt(uint32_t src_ip) {
  std::lock_guard<std::mutex> lock(state_mtx_);
  auto now = std::chrono::steady_clock::now();
  auto &tstate = threat_table_[src_ip];

  // Instantly lock down the IP permanently; ban_count=10 → tampering label
  tstate.is_banned   = true;
  tstate.ban_count   = 10;
  tstate.ban_expires = now + std::chrono::hours(24 * 365);
}

// ── Anomaly Snapshot ─────────────────────────────────────────

std::vector<AnomalySnapshot> RuleEngine::get_anomaly_snapshot() const {
  // Returns hit counts for all 16 built-in anomaly rules
  return {
    { anomaly_land_.description,       static_cast<uint32_t>(anomaly_land_.hit_count)       },
    { anomaly_ttl_.description,        static_cast<uint32_t>(anomaly_ttl_.hit_count)        },
    { anomaly_bogon_.description,      static_cast<uint32_t>(anomaly_bogon_.hit_count)      },
    { anomaly_frag_.description,       static_cast<uint32_t>(anomaly_frag_.hit_count)       },
    { anomaly_icmp_.description,       static_cast<uint32_t>(anomaly_icmp_.hit_count)       },
    { anomaly_tcp_null_.description,   static_cast<uint32_t>(anomaly_tcp_null_.hit_count)   },
    { anomaly_tcp_fin_.description,    static_cast<uint32_t>(anomaly_tcp_fin_.hit_count)    },
    { anomaly_tcp_xmas_.description,   static_cast<uint32_t>(anomaly_tcp_xmas_.hit_count)   },
    { anomaly_tcp_synfin_.description, static_cast<uint32_t>(anomaly_tcp_synfin_.hit_count) },
    { anomaly_tcp_synrst_.description, static_cast<uint32_t>(anomaly_tcp_synrst_.hit_count) },
    { anomaly_tcp_syn_flags_.description, static_cast<uint32_t>(anomaly_tcp_syn_flags_.hit_count) },
    { anomaly_tcp_syn_data_.description,  static_cast<uint32_t>(anomaly_tcp_syn_data_.hit_count)  },
    { anomaly_udp_dns_.description,    static_cast<uint32_t>(anomaly_udp_dns_.hit_count)    },
    { anomaly_udp_flood_.description,  static_cast<uint32_t>(anomaly_udp_flood_.hit_count)  },
    { anomaly_icmp_flood_.description, static_cast<uint32_t>(anomaly_icmp_flood_.hit_count) },
    { anomaly_port_zero_.description,  static_cast<uint32_t>(anomaly_port_zero_.hit_count)  },
    { invalid_rule_.description,       static_cast<uint32_t>(invalid_rule_.hit_count)       },
    { hijack_rule_.description,        static_cast<uint32_t>(hijack_rule_.hit_count)        },
    { dpi_rule_.description,           static_cast<uint32_t>(dpi_rule_.hit_count)           },
    { threat_rule_.description,        static_cast<uint32_t>(threat_rule_.hit_count)        },
    { qos_drop_rule_.description,      static_cast<uint32_t>(qos_drop_rule_.hit_count)      },
  };
}

// ── Connection Snapshot ──────────────────────────────────────

std::vector<ConnectionSnapshot> RuleEngine::get_connection_snapshot() const {
  std::lock_guard<std::mutex> lock(state_mtx_);
  std::vector<ConnectionSnapshot> out;
  out.reserve(state_table_.size());

  auto now = std::chrono::steady_clock::now();

  for (const auto& [key, cs] : state_table_) {
    ConnectionSnapshot snap;
    snap.src_ip     = ip4_to_string(key.src_ip);
    snap.dst_ip     = ip4_to_string(key.dst_ip);
    snap.src_port   = key.src_port;
    snap.dst_port   = key.dst_port;

    switch (key.proto) {
      case Proto::TCP:  snap.proto = "TCP";  break;
      case Proto::UDP:  snap.proto = "UDP";  break;
      case Proto::ICMP: snap.proto = "ICMP"; break;
      default:          snap.proto = "ANY";  break;
    }

    snap.state      = (cs.state == FlowState::ESTABLISHED) ? "ESTABLISHED" : "NEW";
    snap.bytes_in   = cs.bytes_in;
    snap.bytes_out  = cs.bytes_out;
    snap.bytes_total = cs.bytes_transferred;
    snap.age_sec    = std::chrono::duration<double>(now - cs.last_seen).count();
    out.push_back(std::move(snap));
  }
  return out;
}

bool RuleEngine::save_state(const std::string& filepath) const {
    std::ofstream out(filepath, std::ios::binary);
    if (!out) return false;

    std::lock_guard<std::mutex> lock(state_mtx_);
    uint64_t count = state_table_.size();
    out.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (const auto& [key, state] : state_table_) {
        out.write(reinterpret_cast<const char*>(&key), sizeof(ConnectionKey));
        // We do not save `last_seen` as it is session-relative and machine-uptime dependent.
        out.write(reinterpret_cast<const char*>(&state.state), sizeof(FlowState));
        out.write(reinterpret_cast<const char*>(&state.originator_ip), sizeof(uint32_t));
        out.write(reinterpret_cast<const char*>(&state.bytes_transferred), sizeof(uint64_t));
        out.write(reinterpret_cast<const char*>(&state.bytes_out), sizeof(uint64_t));
        out.write(reinterpret_cast<const char*>(&state.bytes_in), sizeof(uint64_t));
        out.write(reinterpret_cast<const char*>(&state.expected_seq), sizeof(uint32_t));
        out.write(reinterpret_cast<const char*>(&state.expected_ack), sizeof(uint32_t));
    }
    return true;
}

bool RuleEngine::load_state(const std::string& filepath) {
    std::ifstream in(filepath, std::ios::binary);
    if (!in) return false;

    std::lock_guard<std::mutex> lock(state_mtx_);
    state_table_.clear();

    uint64_t count = 0;
    if (!in.read(reinterpret_cast<char*>(&count), sizeof(count))) return false;

    auto now = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < count; ++i) {
        ConnectionKey key;
        ConnectionState state;
        
        in.read(reinterpret_cast<char*>(&key), sizeof(ConnectionKey));
        in.read(reinterpret_cast<char*>(&state.state), sizeof(FlowState));
        in.read(reinterpret_cast<char*>(&state.originator_ip), sizeof(uint32_t));
        in.read(reinterpret_cast<char*>(&state.bytes_transferred), sizeof(uint64_t));
        in.read(reinterpret_cast<char*>(&state.bytes_out), sizeof(uint64_t));
        in.read(reinterpret_cast<char*>(&state.bytes_in), sizeof(uint64_t));
        in.read(reinterpret_cast<char*>(&state.expected_seq), sizeof(uint32_t));
        in.read(reinterpret_cast<char*>(&state.expected_ack), sizeof(uint32_t));
        
        state.last_seen = now;
        
        if (in.good()) {
            state_table_[key] = state;
        } else {
            break;
        }
    }
    return true;
}

} // namespace fw