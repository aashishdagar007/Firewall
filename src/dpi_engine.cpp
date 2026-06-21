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

  // ── IoT & Router Device Vulnerabilities ──
  add_sig("IoT: Mirai Botnet Payload", "/bin/busybox", true);
  add_sig("IoT: Router Command Injection (/cgi-bin/)", "/cgi-bin/", true);
  add_sig("IoT: Wget Execution", "wget http", true);
  add_sig("IoT: Curl Execution", "curl -O", true);
  add_sig("IoT: Netcat Reverse Shell", "nc -e", true);
  add_sig("Device Exploit: Default Telnet Creds (root)", "root\r\nroot\r\n", true);
  add_sig("Device Exploit: Default Telnet Creds (admin)", "admin\r\nadmin\r\n", true);
  add_sig("Device Exploit: UPnP SOAP Injection", "urn:schemas-upnp-org:service", true);

  // ── Phase 5: Ransomware / Lateral Movement ──
  add_sig("SMB: EternalBlue MS17-010 (IPC$ Tree Connect)", "\\\\IPC$", true);
  add_sig("SMB: PsExec Execution Artifact", "PSEXESVC.exe", true);

  // ── Phase 5: C2 Frameworks / Post-Exploitation ──
  add_sig("C2: Cobalt Strike Beacon (Default Malleable)", "default.prof", true);
  add_sig("C2: Meterpreter Reverse HTTP", "Meterpreter", true);

  // ── Phase 5: Exploit Frameworks ──
  add_sig("Exploit: Log4Shell (JNDI Injection)", "${jndi:ldap://", true);
  add_sig("Exploit: Log4Shell (RMI Injection)", "${jndi:rmi://", true);

  // ── Phase 5: Suspicious User-Agents (Outbound/Inbound anomaly) ──
  add_sig("User-Agent: curl (Suspicious)", "User-Agent: curl", true);
  add_sig("User-Agent: Wget (Suspicious)", "User-Agent: Wget", true);
  add_sig("User-Agent: PowerShell (Suspicious)", "User-Agent: WindowsPowerShell", true);
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
    if (case_insensitive && std::isalpha(static_cast<unsigned char>(pattern[i]))) {
      bad_char[std::toupper(static_cast<unsigned char>(pattern[i]))] = m - 1 - i;
    }
  }

  size_t s = 0;
  while (s <= len - m) {
    int j = m - 1;
    while (j >= 0) {
      uint8_t p_byte = payload[s + j];
      if (case_insensitive) {
        p_byte = static_cast<uint8_t>(std::tolower(static_cast<unsigned char>(p_byte)));
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

  // ── Vulnerable Protocol Checks (SSLv3, TLS 1.0, TLS 1.1) ──
  // Check for TLS Handshake Record (Content Type 22)
  if (len >= 11 && payload[0] == 0x16) {
    [[maybe_unused]] uint16_t record_version = (payload[1] << 8) | payload[2];
    uint8_t handshake_type = payload[5];
    
    // Check if it's a Client Hello (1) or Server Hello (2)
    if (handshake_type == 0x01 || handshake_type == 0x02) {
      uint16_t handshake_version = (payload[9] << 8) | payload[10];
      
      // 0x0300 = SSLv3, 0x0301 = TLS 1.0, 0x0302 = TLS 1.1
      // If the maximum version supported by client (or selected by server) is <= TLS 1.1, block it.
      if (handshake_version <= 0x0302) {
        threat_name = "DPI Threat: Vulnerable TLS Version (SSLv3/TLS1.0/TLS1.1)";
        return Action::BLOCK;
      }
    }
  }

  for (const auto &sig : signatures_) {
    if (bmh_search(payload, len, sig.pattern, sig.case_insensitive)) {
      threat_name = "DPI Threat: " + sig.name;
      return Action::BLOCK;
    }
  }
  return Action::ALLOW;
}

} // namespace fw
