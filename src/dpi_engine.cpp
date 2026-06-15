#include "dpi_engine.hpp"
#include <cstring>

namespace fw {

DpiEngine::DpiEngine() {
    // Basic L7 Application-layer signatures
    auto add_sig = [this](const std::string& name, const std::string& pattern_str) {
        std::vector<uint8_t> pat(pattern_str.begin(), pattern_str.end());
        signatures_.push_back({name, pat});
    };

    // SQL Injection basics
    add_sig("SQLi: OR 1=1", "OR 1=1");
    add_sig("SQLi: DROP TABLE", "DROP TABLE");
    add_sig("SQLi: UNION SELECT", "UNION SELECT");
    
    // Directory Traversal
    add_sig("Dir Traversal: ../..", "../..");
    add_sig("Dir Traversal: %2E%2E%2F", "%2E%2E%2F");
    
    // XSS
    add_sig("XSS: <script>", "<script>");
    
    // Shellcode NOP sled (x86)
    signatures_.push_back({"Shellcode: NOP Sled", {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}});
}

bool DpiEngine::naive_search(const uint8_t* payload, uint16_t len, const std::vector<uint8_t>& pattern) const {
    if (pattern.empty() || len < pattern.size()) return false;
    
    // Simple naive substring search (adequate for small payloads/patterns)
    // For high performance, this should be upgraded to Aho-Corasick or Hyperscan.
    for (uint16_t i = 0; i <= len - pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (payload[i+j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

Action DpiEngine::scan(const uint8_t* payload, uint16_t len, std::string& threat_name) {
    if (!payload || len == 0) return Action::ALLOW;

    for (const auto& sig : signatures_) {
        if (naive_search(payload, len, sig.pattern)) {
            threat_name = "DPI Threat: " + sig.name;
            return Action::BLOCK;
        }
    }
    return Action::ALLOW;
}

} // namespace fw
