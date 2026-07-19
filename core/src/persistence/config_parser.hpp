#pragma once
#include "util/types.hpp"
#include <string>
#include <vector>

// ──────────────────────────────────────────────────────────────
//  config_parser.hpp  –  parse rules.conf into Rule objects
//
//  Rule file syntax (one rule per line):
//
//    <action> <proto> <src_ip>[/mask] <dst_ip>[/mask] <dst_port>[-end] "<description>"
//
//  Fields:
//    action      : ALLOW | BLOCK
//    proto       : TCP | UDP | ICMP | ANY
//    src_ip      : dotted-quad or *  (wildcard), optional /CIDR
//    dst_ip      : dotted-quad or *, optional /CIDR
//    dst_port    : 0-65535 or * or start-end range
//    description : quoted string
//
//  Lines beginning with # are comments.
// ──────────────────────────────────────────────────────────────

namespace fw {

class ConfigParser {
public:
  // Load rules from a file path.
  // Returns parsed rules; skips malformed lines (with a warning).
  static std::vector<Rule> load(const std::string &path);

  // Save rules to a file path.
  static bool save(const std::string &path, const std::vector<Rule> &rules);

  // Parse a single rule line (exposed for unit-testing)
  static bool parse_line(const std::string &line, Rule &out);

  // Parse a single dotted-quad IP
  static uint32_t parse_ip(const std::string &s);

  // Parse IP with optional CIDR mask (e.g., 192.168.1.0/24)
  static void parse_ip_cidr(const std::string &s, uint32_t &ip, uint32_t &mask);
  // Parse Port with optional range (e.g., 80-443)
  static void parse_port_range(const std::string &s, uint16_t &p_start, uint16_t &p_end);
  
  // Parse MAC address (e.g., AA:BB:CC:DD:EE:FF)
  static std::array<uint8_t, 6> parse_mac(const std::string &s);

  static Proto parse_proto(const std::string &s);
  static Action parse_action(const std::string &s);
};

} // namespace fw
