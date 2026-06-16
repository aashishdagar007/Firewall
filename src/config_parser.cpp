#include "config_parser.hpp"
#include "platform.hpp"   // string_to_ip4, cross-platform inet
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

// ──────────────────────────────────────────────────────────────
//  config_parser.cpp
//
//  Rule line format (whitespace-delimited):
//    ACTION  PROTO  SRC_IP  DST_IP  DST_PORT  "description"
//
//  Examples:
//    BLOCK  TCP   192.168.1.66  *    *    "Block attacker"
//    ALLOW  TCP   *             *    443  "HTTPS"
//    ALLOW  ICMP  *             *    *    "Allow ping"
// ──────────────────────────────────────────────────────────────

namespace fw {

std::vector<Rule> ConfigParser::load(const std::string& path) {
    std::vector<Rule> rules;
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[ConfigParser] Cannot open: " << path << "\n";
        return rules;
    }

    std::string line;
    int line_no = 0;
    while (std::getline(file, line)) {
        ++line_no;

        // Strip comments and blank lines
        auto hash_pos = line.find('#');
        if (hash_pos != std::string::npos) line = line.substr(0, hash_pos);
        if (line.find_first_not_of(" \t\r\n") == std::string::npos) continue;

        Rule r;
        if (parse_line(line, r)) {
            rules.push_back(std::move(r));
        } else {
            std::cerr << "[ConfigParser] Skipping bad rule at line "
                      << line_no << ": " << line << "\n";
        }
    }

    std::cout << "[ConfigParser] Loaded " << rules.size()
              << " rules from " << path << "\n";
    return rules;
}

bool ConfigParser::parse_line(const std::string& line, Rule& out) {
    std::istringstream ss(line);
    std::string action_s;
    if (!(ss >> action_s)) return false;

    if (action_s == "BLOCK_PROCESS" || action_s == "ALLOW_PROCESS") {
        out.action = (action_s == "BLOCK_PROCESS") ? Action::BLOCK : Action::ALLOW;
        out.proto = Proto::ANY;
        out.src_ip = 0;
        out.dst_ip = 0;
        out.src_port = 0;
        out.dst_port = 0;

        std::string proc;
        ss >> std::quoted(proc);
        out.process_name = proc;

        std::string desc;
        std::getline(ss, desc);
        size_t start = desc.find_first_not_of(" \t\"");
        size_t end   = desc.find_last_not_of(" \t\"");
        if (start != std::string::npos)
            out.description = desc.substr(start, end - start + 1);
        else
            out.description = action_s + " " + proc;
        return true;
    }

    std::string proto_s, src_ip_s, dst_ip_s, dst_port_s, desc;
    if (!(ss >> proto_s >> src_ip_s >> dst_ip_s >> dst_port_s))
        return false;

    std::getline(ss, desc);
    size_t start = desc.find_first_not_of(" \t\"");
    size_t end   = desc.find_last_not_of(" \t\"");
    if (start != std::string::npos)
        desc = desc.substr(start, end - start + 1);

    try {
        out.action   = parse_action(action_s);
        out.proto    = parse_proto(proto_s);
        out.src_ip   = parse_ip(src_ip_s);
        out.dst_ip   = parse_ip(dst_ip_s);
        out.dst_port = parse_port(dst_port_s);
        out.description = desc;
    } catch (...) {
        return false;
    }

    return true;
}

// ── Private helpers ──────────────────────────────────────────

uint32_t ConfigParser::parse_ip(const std::string& s) {
    if (s == "*" || s == "any") return 0;
    uint32_t ip = string_to_ip4(s.c_str());
    if (ip == 0 && s != "0.0.0.0")
        throw std::invalid_argument("bad IP: " + s);
    return ip;  // already in host byte order
}

uint16_t ConfigParser::parse_port(const std::string& s) {
    if (s == "*" || s == "any") return 0;
    int p;
    try {
        p = std::stoi(s);
    } catch (...) {
        throw std::invalid_argument("bad port: " + s);
    }
    if (p < 0 || p > 65535) throw std::out_of_range("port out of range");
    return static_cast<uint16_t>(p);
}

Proto ConfigParser::parse_proto(const std::string& s) {
    if (s == "TCP")  return Proto::TCP;
    if (s == "UDP")  return Proto::UDP;
    if (s == "ICMP") return Proto::ICMP;
    if (s == "ANY" || s == "*") return Proto::ANY;
    throw std::invalid_argument("unknown proto: " + s);
}

Action ConfigParser::parse_action(const std::string& s) {
    if (s == "ALLOW") return Action::ALLOW;
    if (s == "BLOCK") return Action::BLOCK;
    throw std::invalid_argument("unknown action: " + s);
}

} // namespace fw