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

static bool s_fail_open_on_crash = false; // Default: fail-secure (BLOCK all on crash)

bool ConfigParser::get_fail_open_on_crash() {
    return s_fail_open_on_crash;
}

void ConfigParser::set_fail_open_on_crash(bool enable) {
    s_fail_open_on_crash = enable;
}

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

        // Check for configuration directives
        if (line.find("fail_open_on_crash") != std::string::npos) {
            if (line.find("true") != std::string::npos || line.find("1") != std::string::npos) {
                s_fail_open_on_crash = true;
                std::cout << "[ConfigParser] Setting: fail_open_on_crash = TRUE (fail-open enabled)\n";
            } else if (line.find("false") != std::string::npos || line.find("0") != std::string::npos) {
                s_fail_open_on_crash = false;
                std::cout << "[ConfigParser] Setting: fail_open_on_crash = FALSE (fail-secure enforced)\n";
            }
            continue;
        }

        Rule r;
        if (parse_line(line, r)) {
            rules.push_back(std::move(r));
        } else {
            std::cerr << "[ConfigParser] Atomically rejecting malformed rule at line "
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
        if (!(ss >> std::quoted(proc)) || proc.empty()) return false;
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
    } catch (const std::invalid_argument& ex) {
        std::cerr << "[ConfigParser] Validation error (" << ex.what() << ") in: " << line << "\n";
        return false;
    } catch (const std::out_of_range& ex) {
        std::cerr << "[ConfigParser] Out of range error (" << ex.what() << ") in: " << line << "\n";
        return false;
    } catch (...) {
        std::cerr << "[ConfigParser] Unexpected validation error in: " << line << "\n";
        return false;
    }

    return true;
}

// ── Private helpers ──────────────────────────────────────────

uint32_t ConfigParser::parse_ip(const std::string& s) {
    if (s == "*" || s == "any") return 0;

    std::string ip_part = s;
    auto slash = s.find('/');
    if (slash != std::string::npos) {
        ip_part = s.substr(0, slash);
        std::string mask_part = s.substr(slash + 1);
        try {
            int cidr = std::stoi(mask_part);
            if (cidr < 0 || cidr > 32) throw std::out_of_range("invalid CIDR prefix");
        } catch (const std::invalid_argument&) {
            throw std::invalid_argument("malformed CIDR: " + s);
        } catch (const std::out_of_range&) {
            throw std::out_of_range("CIDR prefix out of range [0, 32]: " + s);
        }
    }

    int dots = 0;
    for (char c : ip_part) {
        if (c == '.') dots++;
        else if (!isdigit(static_cast<unsigned char>(c))) {
            throw std::invalid_argument("invalid character in IP address: " + s);
        }
    }
    if (dots != 3) {
        throw std::invalid_argument("malformed IPv4 dotted-quad format: " + s);
    }

    uint32_t ip = string_to_ip4(ip_part.c_str());
    if (ip == 0 && ip_part != "0.0.0.0")
        throw std::invalid_argument("bad IP: " + s);
    return ip;  // already in host byte order
}

uint16_t ConfigParser::parse_port(const std::string& s) {
    if (s == "*" || s == "any") return 0;

    for (char c : s) {
        if (!isdigit(static_cast<unsigned char>(c))) {
            throw std::invalid_argument("non-digit character in port: " + s);
        }
    }

    int p = 0;
    try {
        p = std::stoi(s);
    } catch (const std::invalid_argument&) {
        throw std::invalid_argument("bad port: " + s);
    } catch (const std::out_of_range&) {
        throw std::out_of_range("port out of integer range: " + s);
    }

    if (p < 0 || p > 65535) throw std::out_of_range("port out of range [0, 65535]: " + s);
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