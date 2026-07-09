#include "config_parser.hpp"
#include "platform.hpp"   // string_to_ip4, cross-platform inet
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <regex>

// ──────────────────────────────────────────────────────────────
//  config_parser.cpp
//
//  Rule line format (whitespace-delimited):
//    ACTION  PROTO  SRC_IP[/MASK]  DST_IP[/MASK]  DST_PORT[-END]  "description"
//
//  Examples:
//    BLOCK  TCP   192.168.1.0/24  *          *      "Block subnet"
//    ALLOW  TCP   *               *          443    "HTTPS"
//    ALLOW  TCP   *               *          80-88  "HTTP range"
// ──────────────────────────────────────────────────────────────

namespace fw {

// Returns the number of set bits in a subnet mask (host byte order).
static int count_mask_bits(uint32_t m) {
  int bits = 0;
  for (; m; m >>= 1) bits += (m & 1);
  return bits;
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

bool ConfigParser::save(const std::string &path, const std::vector<Rule> &rules) {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "# Firewall Rules Configuration\n";
    file << "# ACTION  PROTO  SRC_IP[/MASK]  DST_IP[/MASK]  DST_PORT[-END]  \"description\"\n\n";

    for (const auto& r : rules) {
        if (r.action == Action::BLOCK && !r.process_name.empty() && r.src_ip == 0 && r.dst_ip == 0 && r.dst_port_start == 0) {
            file << "BLOCK_PROCESS \"" << r.process_name << "\" \"" << r.description << "\"\n";
            continue;
        }
        if (r.action == Action::ALLOW && !r.process_name.empty() && r.src_ip == 0 && r.dst_ip == 0 && r.dst_port_start == 0) {
            file << "ALLOW_PROCESS \"" << r.process_name << "\" \"" << r.description << "\"\n";
            continue;
        }

        file << (r.action == Action::ALLOW ? "ALLOW" : "BLOCK") << " ";
        file << proto_name(r.proto) << " ";
        
        // SRC IP / MASK
        if (r.src_ip == 0 && r.src_ip_mask == 0xFFFFFFFF) {
            file << "* ";
        } else {
            file << ip4_to_string(r.src_ip);
            if (r.src_ip_mask != 0xFFFFFFFF)
                file << "/" << count_mask_bits(r.src_ip_mask);
            file << " ";
        }

        // DST IP / MASK
        if (r.dst_ip == 0 && r.dst_ip_mask == 0xFFFFFFFF) {
            file << "* ";
        } else {
            file << ip4_to_string(r.dst_ip);
            if (r.dst_ip_mask != 0xFFFFFFFF)
                file << "/" << count_mask_bits(r.dst_ip_mask);
            file << " ";
        }

        // DST PORT
        if (r.dst_port_start == 0 && r.dst_port_end == 0) {
            file << "* ";
        } else if (r.dst_port_start == r.dst_port_end) {
            file << r.dst_port_start << " ";
        } else {
            file << r.dst_port_start << "-" << r.dst_port_end << " ";
        }

        file << "\"" << r.description << "\"\n";
    }

    return true;
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
        out.src_port_start = 0;
        out.src_port_end = 0;
        out.dst_port_start = 0;
        out.dst_port_end = 0;

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
        parse_ip_cidr(src_ip_s, out.src_ip, out.src_ip_mask);
        parse_ip_cidr(dst_ip_s, out.dst_ip, out.dst_ip_mask);
        parse_port_range(dst_port_s, out.dst_port_start, out.dst_port_end);
        out.description = desc;
    } catch (...) {
        return false;
    }

    return true;
}

// ── Private helpers ──────────────────────────────────────────

// Parse a single dotted-quad IP
uint32_t ConfigParser::parse_ip(const std::string &s) {
  if (s == "*" || s.empty())
    return 0;
  struct sockaddr_in sa;
  if (inet_pton(AF_INET, s.c_str(), &sa.sin_addr) == 1) {
    return ntohl(sa.sin_addr.s_addr);
  }
  return 0;
}

void ConfigParser::parse_ip_cidr(const std::string& s, uint32_t &ip, uint32_t &mask) {
    if (s == "*" || s == "any") {
        ip = 0;
        mask = 0xFFFFFFFF; // Wait, for wildcard, mask should be 0 to match anything? No, rule_engine handles `if(src_ip == 0)` specifically, but mask=0 is safer. Let's keep 0xFFFFFFFF and let rule_engine handle `0` as wildcard, OR use mask=0. Actually, if mask=0, `(addr & mask) == (ip & mask)` is `0 == 0`, which is always true. We will set mask to 0 for wildcard.
        mask = 0;
        return;
    }

    auto slash = s.find('/');
    std::string ip_part = s.substr(0, slash);
    ip = string_to_ip4(ip_part.c_str());
    if (ip == 0 && ip_part != "0.0.0.0")
        throw std::invalid_argument("bad IP: " + s);

    if (slash != std::string::npos) {
        int bits = std::stoi(s.substr(slash + 1));
        if (bits < 0 || bits > 32) throw std::out_of_range("invalid CIDR");
        mask = (bits == 0) ? 0 : ~((1ULL << (32 - bits)) - 1);
    } else {
        mask = 0xFFFFFFFF; // /32
    }
}

void ConfigParser::parse_port_range(const std::string& s, uint16_t &p_start, uint16_t &p_end) {
    if (s == "*" || s == "any") {
        p_start = 0;
        p_end = 0;
        return;
    }
    auto dash = s.find('-');
    if (dash != std::string::npos) {
        int start = std::stoi(s.substr(0, dash));
        int end = std::stoi(s.substr(dash + 1));
        if (start < 0 || start > 65535 || end < 0 || end > 65535 || start > end)
            throw std::out_of_range("bad port range");
        p_start = static_cast<uint16_t>(start);
        p_end = static_cast<uint16_t>(end);
    } else {
        int p = std::stoi(s);
        if (p < 0 || p > 65535) throw std::out_of_range("port out of range");
        p_start = p_end = static_cast<uint16_t>(p);
    }
}

std::array<uint8_t, 6> ConfigParser::parse_mac(const std::string &s) {
    std::array<uint8_t, 6> mac = {0};
    if (s == "*" || s == "any") return mac;

    unsigned int m[6];
#if defined(_WIN32)
    if (sscanf_s(s.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
        for (int i=0; i<6; i++) mac[i] = static_cast<uint8_t>(m[i]);
    } else if (sscanf_s(s.c_str(), "%02x-%02x-%02x-%02x-%02x-%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
        for (int i=0; i<6; i++) mac[i] = static_cast<uint8_t>(m[i]);
    }
#else
    if (sscanf(s.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
        for (int i=0; i<6; i++) mac[i] = static_cast<uint8_t>(m[i]);
    } else if (sscanf(s.c_str(), "%02x-%02x-%02x-%02x-%02x-%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
        for (int i=0; i<6; i++) mac[i] = static_cast<uint8_t>(m[i]);
    }
#endif
    return mac;
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