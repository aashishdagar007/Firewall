#pragma once
#include "types.hpp"
#include <string>
#include <vector>

// ──────────────────────────────────────────────────────────────
//  config_parser.hpp  –  parse rules.conf into Rule objects
//
//  Rule file syntax (one rule per line):
//
//    <action> <proto> <src_ip> <dst_ip> <dst_port> "<description>"
//
//  Fields:
//    action      : ALLOW | BLOCK
//    proto       : TCP | UDP | ICMP | ANY
//    src_ip      : dotted-quad or *  (wildcard)
//    dst_ip      : dotted-quad or *
//    dst_port    : 0-65535 or *
//    description : quoted string
//
//  Lines beginning with # are comments.
//
//  Example:
//    BLOCK  TCP   192.168.1.66  *  *   "Block attacker"
//    ALLOW  TCP   *             *  443 "HTTPS"
//    ALLOW  ICMP  *             *  *   "Allow ping"
// ──────────────────────────────────────────────────────────────

namespace fw {

class ConfigParser {
public:
  // Load rules from a file path.
  // Returns parsed rules; skips malformed lines (with a warning).
  static std::vector<Rule> load(const std::string &path);

  // Parse a single rule line (exposed for unit-testing)
  static bool parse_line(const std::string &line, Rule &out);

  static uint32_t parse_ip(const std::string &s);   // returns 0 for "*"
  static uint16_t parse_port(const std::string &s); // returns 0 for "*"
  static Proto parse_proto(const std::string &s);
  static Action parse_action(const std::string &s);
};

} // namespace fw