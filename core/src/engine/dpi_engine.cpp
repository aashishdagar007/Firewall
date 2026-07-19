#include "engine/dpi_engine.hpp"
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

  // ── Phase 6: Network Recon / Banner Grabbing (threats 19, 20, 23, 24) ──
  add_sig("Scanner: Nmap Service Probe",       "Nmap service detection",   true);
  add_sig("Scanner: Nmap HTTP Probe",          "GET / HTTP/1.0\r\n\r\n",   false);
  add_sig("Scanner: Nmap SYN Probe Header",    "nmaplowercheck",           true);
  add_sig("Scanner: Masscan Probe",            "masscan",                  true);
  add_sig("Scanner: ZMap Probe",               "zmap",                     true);
  add_sig("Scanner: gobuster User-Agent",      "User-Agent: gobuster",     true);
  add_sig("Scanner: ffuf User-Agent",          "User-Agent: ffuf",         true);
  add_sig("Scanner: dirbuster User-Agent",     "User-Agent: DirBuster",    true);
  add_sig("Scanner: nikto User-Agent",         "User-Agent: Nikto",        true);
  add_sig("Scanner: sqlmap User-Agent",        "User-Agent: sqlmap",       true);
  add_sig("Scanner: nuclei User-Agent",        "User-Agent: nuclei",       true);
  add_sig("Scanner: wfuzz User-Agent",         "User-Agent: Wfuzz",        true);
  add_sig("Scanner: Acunetix User-Agent",      "User-Agent: Acunetix",     true);
  add_sig("Scanner: Burp Suite Probe",         "User-Agent: BurpSuite",    true);
  add_sig("Scanner: OpenVAS Probe",            "User-Agent: OpenVAS",      true);

  // ── Phase 6: SMB / NetBIOS Enumeration (threat 23) ──────────────────────
  // SMB1 negotiate request magic bytes
  add_sig("SMB: Negotiate Protocol Request",
          "\xff\x53\x4d\x42\x72\x00\x00\x00", false);
  // SMB2 negotiate
  add_sig("SMB2: Negotiate Request",
          "\xfe\x53\x4d\x42\x40\x00\x00\x00", false);
  // WannaCry / EternalBlue specific SMB patterns
  add_sig("SMB: EternalBlue NTLM Blob",         "NTLMSSP\x00\x01\x00\x00\x00", false);
  // NetBIOS name query
  add_sig("NetBIOS: Name Query (NBNS)",          "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false);

  // ── Phase 6: Web Fingerprinting / Tech Discovery (threats 25, 27) ────────
  add_sig("Fingerprint: WhatWeb Scanner",        "User-Agent: WhatWeb",      true);
  add_sig("Fingerprint: Wappalyzer Extension",   "wappalyzer",               true);
  add_sig("Fingerprint: .git directory probe",   "GET /.git/config",         true);
  add_sig("Fingerprint: .git HEAD probe",        "GET /.git/HEAD",           true);
  add_sig("Fingerprint: .env file probe",        "GET /.env",                true);
  add_sig("Fingerprint: docker-compose probe",   "GET /docker-compose.yml",  true);
  add_sig("Fingerprint: package.json probe",     "GET /package.json",        true);
  add_sig("Fingerprint: webpack config probe",   "GET /webpack.config.js",   true);
  add_sig("Fingerprint: AWS credentials probe",  "GET /.aws/credentials",    true);
  add_sig("Fingerprint: SSH key probe",          "GET /.ssh/id_rsa",         true);
  add_sig("Fingerprint: wp-config probe",        "GET /wp-config.php",       true);
  add_sig("Fingerprint: phpinfo probe",          "phpinfo()",                true);
  add_sig("Fingerprint: robots.txt recon",       "GET /robots.txt",          true);
  add_sig("Fingerprint: sitemap.xml recon",      "GET /sitemap.xml",         true);

  // ── Phase 6: LOLBin C2 / Post-Exploitation Patterns (threat 38) ──────────
  add_sig("LOLBin: certutil URL download",
          "certutil -urlcache",                                               true);
  add_sig("LOLBin: certutil -decode",
          "certutil -decode",                                                 true);
  add_sig("LOLBin: bitsadmin transfer",
          "bitsadmin /transfer",                                              true);
  add_sig("LOLBin: regsvr32 scrobj",
          "regsvr32 /s /n /u /i:",                                           true);
  add_sig("LOLBin: mshta VBScript",
          "mshta vbscript:",                                                  true);
  add_sig("LOLBin: mshta JavaScript",
          "mshta javascript:",                                                true);
  add_sig("LOLBin: installutil AppDomain",
          "AppDomain.CurrentDomain",                                          true);
  add_sig("LOLBin: rundll32 javascript",
          "rundll32 javascript:",                                             true);
  add_sig("LOLBin: cmstp INF launch",
          "cmstp /ni /s",                                                     true);
  add_sig("LOLBin: wmic /node remote exec",
          "wmic /node:",                                                       true);

  // ── Phase 6: Credential Dumping / Lateral Movement (threats 39-41) ───────
  add_sig("Mimikatz: sekurlsa module",           "sekurlsa::",               true);
  add_sig("Mimikatz: lsadump module",            "lsadump::",                true);
  add_sig("Mimikatz: kerberos module",           "kerberos::",               true);
  add_sig("Mimikatz: privilege::debug",          "privilege::debug",         true);
  add_sig("Mimikatz: token::elevate",            "token::elevate",           true);
  add_sig("BloodHound: LDAP computer query",
          "(&(objectCategory=computer)",                                       true);
  add_sig("BloodHound: LDAP user query",
          "(&(objectCategory=person)(objectClass=user)",                       true);
  add_sig("BloodHound: LDAP group query",
          "(objectClass=group)",                                               true);
  add_sig("PsExec: Remote service install",      "PSEXESVC",                 true);
  add_sig("WCE: Windows Credential Editor",      "wce.exe",                  true);
  add_sig("DCSync: DRS replication request",     "DRS_MSG_GETCHGREQ",        false);

  // ── Phase 6: Process Injection / DLL Sideloading (threats 39-40) ─────────
  add_sig("Injection: VirtualAllocEx marker",    "VirtualAllocEx",           true);
  add_sig("Injection: WriteProcessMemory",        "WriteProcessMemory",       true);
  add_sig("Injection: CreateRemoteThread",        "CreateRemoteThread",       true);
  add_sig("DLL Hijack: DLL search order abuse",  "LoadLibraryA",             false);
  add_sig("Reflective DLL: ReflectiveDLL magic",
          "ReflectiveLoader",                                                  false);

  // ── Phase 6: Supply Chain / Dependency Confusion (threat 42) ─────────────
  add_sig("Supply Chain: npm install over HTTP",
          "GET /npm/",                                                         true);
  add_sig("Supply Chain: PyPI HTTP endpoint",
          "GET /simple/",                                                      true);
  add_sig("Supply Chain: Typosquatting npm UA",
          "npm/",                                                              true);
  // Malicious package install usually POSTs credentials or telemetry
  add_sig("Supply Chain: NPM token exfil pattern",
          "npm_authToken",                                                     true);

  // ── Phase 6: Insecure Update Channel (threat 43) ──────────────────────────
  add_sig("Insecure Update: HTTP Content-Disposition attachment",
          "Content-Disposition: attachment",                                   true);
  add_sig("Insecure Update: HTTP firmware download",
          "firmware.bin",                                                      true);
  add_sig("Insecure Update: HTTP OTA pattern",
          "/ota/update",                                                       true);

  // ── Phase 6: SDR / RF Tool Fingerprints (threat 14) ──────────────────────
  add_sig("SDR Tool: RTL-SDR web server UA",
          "RTL-SDR",                                                           true);
  add_sig("SDR Tool: GNU Radio HTTP UA",
          "GNU Radio",                                                         true);
  add_sig("SDR Tool: HackRF web interface",
          "HackRF",                                                            true);
  add_sig("SDR Tool: gqrx web endpoint",
          "gqrx",                                                              true);

  // ── Phase 6: C2 Frameworks — Extended (threats 38-41) ────────────────────
  add_sig("C2: Empire framework indicator",      "EmPyre",                   true);
  add_sig("C2: Sliver C2 HTTP indicator",        "X-Sliver-",                false);
  add_sig("C2: Havoc C2 beacon header",          "X-Havoc-",                 false);
  add_sig("C2: Brute Ratel indicator",           "BRC4",                     false);
  add_sig("C2: Covenant C2 indicator",           "Covenant",                 true);
  add_sig("C2: Merlin C2 indicator",             "X-Merlin-Id",              false);
  add_sig("C2: Poshc2 Payload Pattern",          "Poshc2",                   true);
  add_sig("C2: TrevorC2 pattern",               "Trevor C2",                 true);
  add_sig("C2: Deimos C2 header",               "X-Deimos-",                 false);
  add_sig("C2: Chisel tunnel indicator",         "chisel-",                   true);

  // ── Phase 6: Tunnel / Proxy Evasion (threats 9, 14) ─────────────────────
  add_sig("Tunnel: ngrok HTTP header",           "X-Forwarded-For: ngrok",   true);
  add_sig("Tunnel: Cloudflare tunnel UA",        "cloudflared",               true);
  add_sig("Tunnel: frp tunnel header",           "X-Frp-",                    false);
  add_sig("Tunnel: SSH -D SOCKS in payload",     "SSH-2.0-OpenSSH",           false);
  add_sig("Tunnel: Tor SOCKS greeting",
          "\x05\x01\x00",                                                      false); // SOCKS5 no-auth
  add_sig("Tunnel: I2P HTTP header",             "X-I2P-",                    false);

  // ── Phase 6: Ransomware patterns ──────────────────────────────────────────
  add_sig("Ransomware: CryptoLocker extension",  ".encrypted",                true);
  add_sig("Ransomware: LockBit beacon",          "LockBit",                   true);
  add_sig("Ransomware: REvil beacon",            "REvil",                     true);
  add_sig("Ransomware: Ryuk marker",             "RYUK",                      true);
  add_sig("Ransomware: CONTI HTTP C2",           "CONTI_",                    true);
  add_sig("Ransomware: RDP note drop",           "readme.txt",                true);
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

  // ── WAF HTTP Parsing ──
  if (len > 4 && (memcmp(payload, "GET ", 4) == 0 || memcmp(payload, "POST", 4) == 0 || memcmp(payload, "PUT ", 4) == 0)) {
      // Basic HTTP request found
      // Basic HTTP request found
      const char* p = reinterpret_cast<const char*>(payload);
      const char* end = p + len;
      
      // Find the end of the URI
      const char* uri_start = p;
      while (uri_start < end && *uri_start != ' ') uri_start++; // Skip method
      if (uri_start < end) uri_start++; // Skip space
      
      const char* uri_end = uri_start;
      while (uri_end < end && *uri_end != ' ' && *uri_end != '\r' && *uri_end != '\n') uri_end++;
      
      size_t uri_len = static_cast<size_t>(uri_end - uri_start);
      if (uri_len > 2048 || uri_len == 0) {
          threat_name = "WAF: URI too long or malformed (Buffer Overflow Attempt)";
          return Action::BLOCK;
      }

      // Safe extraction
      std::string uri(uri_start, uri_len);
      
      // Check for directory traversal specifically in URI
      if (uri.find("../") != std::string::npos || uri.find("..\\") != std::string::npos || uri.find("%2e%2e%2f") != std::string::npos) {
          threat_name = "WAF: Directory Traversal in URI";
          return Action::BLOCK;
      }
      
      // SQLi specifically in URI
      std::string lower_uri = uri;
      for (char& c : lower_uri) c = std::tolower(static_cast<unsigned char>(c));
      if (lower_uri.find("union select") != std::string::npos || lower_uri.find("select * from") != std::string::npos) {
          threat_name = "WAF: SQL Injection in URI";
          return Action::BLOCK;
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
