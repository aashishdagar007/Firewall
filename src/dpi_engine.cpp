#include "dpi_engine.hpp"
#include <cctype>
#include <cstring>

namespace fw {

DpiEngine::DpiEngine() {
  // Basic L7 Application-layer signatures
  auto add_sig = [this](const std::string &name, const std::string &pattern_str,
                        bool ci = true) {
    std::vector<uint8_t> pat;
    for (char c : pattern_str) {
      pat.push_back(
          ci ? static_cast<uint8_t>(std::tolower(static_cast<unsigned char>(c)))
             : static_cast<uint8_t>(c));
    }
    signatures_.push_back({name, pat, ci});
  };

  // ── Exploitation & Malware Signatures ──
  add_sig("Shellcode: NOP Sled", "\x90\x90\x90\x90\x90\x90\x90\x90", false);
  add_sig("Windows: Command Execution", "cmd.exe /c", true);
  add_sig("Windows: PowerShell Execution", "powershell.exe -enc", true);
  add_sig("Windows: WMI Execution", "wmic process call create", true);
  add_sig("Linux: Reverse Shell", "/bin/bash -i", false);
  add_sig("Linux: Shell pipe", "nc -e /bin/sh", false);

  // ── Web Vulnerability Signatures (SQLi, XSS, Path Traversal) ──
  add_sig("SQLi: UNION SELECT", "UNION SELECT", true);
  add_sig("SQLi: Generic Boolean", "OR 1=1", true);
  add_sig("SQLi: Generic Boolean Hex", "OR '1'='1'", true);
  add_sig("SQLi: WAITFOR DELAY", "WAITFOR DELAY", true);
  add_sig("SQLi: DROP TABLE", "DROP TABLE", true);
  add_sig("XSS: Script Tag", "<script>", true);
  add_sig("XSS: Alert Payload", "alert(1)", true);
  add_sig("XSS: Document Cookie", "document.cookie", true);
  add_sig("Path Traversal: Windows", "..\\..\\", false);
  add_sig("Path Traversal: Linux", "../..", false);
  add_sig("LFI: Passwd Access", "/etc/passwd", false);
  add_sig("LFI: Shadow Access", "/etc/shadow", false);

  // ── HTTP Anomalies / Web Shells ──
  add_sig("WebShell: PHP eval", "eval($_POST", false);
  add_sig("WebShell: JSP Execute", "Runtime.getRuntime().exec", false);
}

bool DpiEngine::bmh_search(const uint8_t *payload, uint16_t len,
                           const std::vector<uint8_t> &pattern,
                           bool case_insensitive) const {
  if (pattern.empty() || len < pattern.size())
    return false;

  // Build Boyer-Moore-Horspool bad character table
  size_t m = pattern.size();
  size_t bad_char[256];
  for (size_t i = 0; i < 256; ++i) {
    bad_char[i] = m;
  }

  for (size_t i = 0; i < m - 1; ++i) {
    bad_char[pattern[i]] = m - 1 - i;
    if (case_insensitive && std::isalpha(pattern[i])) {
      bad_char[std::toupper(pattern[i])] = m - 1 - i;
    }
  }

  size_t s = 0;
  while (s <= len - m) {
    int j = m - 1;
    while (j >= 0) {
      uint8_t p_byte = payload[s + j];
      if (case_insensitive) {
        p_byte = static_cast<uint8_t>(std::tolower(p_byte));
      }
      if (p_byte != pattern[j]) {
        break;
      }
      j--;
    }

    if (j < 0)
      return true; // Match found

    uint8_t skip_byte = payload[s + m - 1];
    s += bad_char[skip_byte];
  }
  return false;
}

Action DpiEngine::scan(const uint8_t *payload, uint16_t len,
                       std::string &threat_name) {
  if (!payload || len == 0)
    return Action::ALLOW;

  for (const auto &sig : signatures_) {
    if (bmh_search(payload, len, sig.pattern, sig.case_insensitive)) {
      threat_name = "DPI Threat: " + sig.name;
      return Action::BLOCK;
    }
  }
  return Action::ALLOW;
}

} // namespace fw
