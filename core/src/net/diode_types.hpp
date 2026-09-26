#pragma once
#include "types.hpp"
#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <unordered_map>

namespace fw {

// ── The 6 Core Threat Classes (NTRO SIH26145) ─────────────────
enum class ThreatClass : uint8_t {
    VOLUMETRIC_DDOS     = 0, // a. Volumetric / protocol DDoS (SYN, UDP amplification, low source entropy)
    BOTNET_C2_BEACONING = 1, // b. Botnet C2 beaconing (Periodicity & IAT analysis to small destination sets)
    DNS_DGA_TUNNEL      = 2, // c. DGA domains & DNS tunnelling (Entropy/n-gram, query-length, record anomalies)
    ENCRYPTED_MALWARE   = 3, // d. Malware inside encrypted sessions (JA3/JA4, SPLT sequences - zero decryption)
    RECON_SCAN          = 4, // e. Reconnaissance and port scanning (Fan-out across destination ports/hosts)
    DATA_EXFILTRATION   = 5  // f. Data exfiltration (Asymmetric flow-volume anomalies, high outbound ratios)
};

inline const char* threat_class_code(ThreatClass tc) {
    switch (tc) {
        case ThreatClass::VOLUMETRIC_DDOS:     return "VOLUMETRIC_DDOS";
        case ThreatClass::BOTNET_C2_BEACONING: return "BOTNET_C2_BEACONING";
        case ThreatClass::DNS_DGA_TUNNEL:      return "DNS_DGA_TUNNEL";
        case ThreatClass::ENCRYPTED_MALWARE:   return "ENCRYPTED_MALWARE";
        case ThreatClass::RECON_SCAN:          return "RECON_SCAN";
        case ThreatClass::DATA_EXFILTRATION:   return "DATA_EXFILTRATION";
        default:                               return "UNKNOWN_THREAT";
    }
}

inline const char* threat_class_title(ThreatClass tc) {
    switch (tc) {
        case ThreatClass::VOLUMETRIC_DDOS:     return "Volumetric / Protocol DDoS";
        case ThreatClass::BOTNET_C2_BEACONING: return "Botnet C2 Beaconing";
        case ThreatClass::DNS_DGA_TUNNEL:      return "DGA Domain & DNS Tunnelling";
        case ThreatClass::ENCRYPTED_MALWARE:   return "Malware in Encrypted Session (TLS/QUIC)";
        case ThreatClass::RECON_SCAN:          return "Reconnaissance & Fan-out Scan";
        case ThreatClass::DATA_EXFILTRATION:   return "Asymmetric Data Exfiltration";
        default:                               return "Unknown Threat";
    }
}

// ── Severity ──────────────────────────────────────────────────
enum class ThreatSeverity : uint8_t {
    LOW = 0,
    MEDIUM = 1,
    HIGH = 2,
    CRITICAL = 3
};

inline const char* severity_str(ThreatSeverity s) {
    switch (s) {
        case ThreatSeverity::LOW:      return "LOW";
        case ThreatSeverity::MEDIUM:   return "MEDIUM";
        case ThreatSeverity::HIGH:     return "HIGH";
        case ThreatSeverity::CRITICAL: return "CRITICAL";
        default:                       return "INFO";
    }
}

// ── 5-Tuple Flow Identifier ───────────────────────────────────
struct FlowId {
    uint32_t    src_ip   = 0;
    uint32_t    dst_ip   = 0;
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    std::string proto    = "TCP";

    bool operator==(const FlowId& o) const {
        return src_ip == o.src_ip && dst_ip == o.dst_ip &&
               src_port == o.src_port && dst_port == o.dst_port &&
               proto == o.proto;
    }
};

struct FlowIdHash {
    size_t operator()(const FlowId& k) const {
        return (static_cast<size_t>(k.src_ip) * 2654435761u) ^
               (static_cast<size_t>(k.dst_ip) * 2246822519u) ^
               (static_cast<size_t>(k.src_port) << 16) ^
               k.dst_port ^
               std::hash<std::string>{}(k.proto);
    }
};

// ── Standardized Alert Record ─────────────────────────────────
struct DiodeAlert {
    std::string    alert_id;
    std::string    timestamp;       // ISO 8601 or ms timestamp
    ThreatClass    threat_class;
    std::string    threat_name;
    ThreatSeverity severity;
    float          confidence_score; // 0.00 to 1.00
    FlowId         flow;
    std::string    src_ip_str;
    std::string    dst_ip_str;
    std::string    evidence_json;    // Formatted JSON object of supporting features
    std::string    recommendation;

    std::string to_json() const {
        std::ostringstream ss;
        ss << "{"
           << "\"alert_id\":\"" << alert_id << "\","
           << "\"timestamp\":\"" << timestamp << "\","
           << "\"threat_class\":\"" << threat_class_code(threat_class) << "\","
           << "\"threat_title\":\"" << threat_class_title(threat_class) << "\","
           << "\"threat_name\":\"" << threat_name << "\","
           << "\"severity\":\"" << severity_str(severity) << "\","
           << "\"confidence_score\":" << std::fixed << std::setprecision(2) << confidence_score << ","
           << "\"flow\":{"
           << "\"src_ip\":\"" << src_ip_str << "\","
           << "\"dst_ip\":\"" << dst_ip_str << "\","
           << "\"src_port\":" << flow.src_port << ","
           << "\"dst_port\":" << flow.dst_port << ","
           << "\"proto\":\"" << flow.proto << "\""
           << "},"
           << "\"evidence\":" << (evidence_json.empty() ? "{}" : evidence_json) << ","
           << "\"recommendation\":\"" << recommendation << "\""
           << "}";
        return ss.str();
    }
};

// ── Diode Enclave Telemetry ───────────────────────────────────
struct DiodeTelemetry {
    double   flows_per_sec       = 0.0;
    double   packets_per_sec     = 0.0;
    double   mbps                = 0.0;
    uint64_t total_packets       = 0;
    uint64_t total_flows_tracked = 0;
    uint64_t total_alerts_raised = 0;
    bool     diode_mode_active   = true;
    bool     read_only_verified  = true; // Enclave guarantees no return path
    bool     zero_return_path    = true;
    uint64_t class_counts[6]     = {0, 0, 0, 0, 0, 0};
};

} // namespace fw
