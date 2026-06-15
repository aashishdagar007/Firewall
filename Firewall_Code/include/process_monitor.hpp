#pragma once
#include "platform.hpp"
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ──────────────────────────────────────────────────────────────────────────────
//  process_monitor.hpp
//
//  Windows: maps TCP/UDP local-port → PID → process name using iphlpapi.
//  Also enumerates browser window titles (Edge, Chrome, Firefox, Brave, Opera).
//
//  Linux: stub — returns empty strings (use /proc/net/tcp for a real impl).
// ──────────────────────────────────────────────────────────────────────────────

namespace fw {

// Information about one running process that has network activity
struct ProcessNetInfo {
  uint32_t pid = 0;
  std::string exe_name;     // "chrome.exe"
  std::string display_name; // "Google Chrome"
  uint64_t bytes_rx = 0;    // updated by NfqCapture per packet
  uint64_t bytes_tx = 0;
  uint32_t pkt_count = 0;
  bool is_browser = false;
  bool is_blocked = false; // whether the application is administratively blocked
  std::vector<std::string> browser_tabs; // window titles for this PID
  std::vector<uint16_t> tcp_ports;       // local TCP ports owned by PID
  std::vector<uint16_t> udp_ports;
};

class ProcessMonitor {
public:
  ProcessMonitor();
  ~ProcessMonitor();

  void start(); // begin background refresh thread (every 2s)
  void stop();

  // --- Called from packet path (fast path, lock-free lookup) ---

  // Returns process exe name for a local port ("chrome.exe" or "")
  std::string process_name_for_port(uint16_t local_port) const;
  uint32_t pid_for_port(uint16_t local_port) const;

  // --- Application Blocking ---
  void set_app_blocked(const std::string& exe_name, bool blocked);
  bool is_app_blocked(const std::string& exe_name) const;

  // --- Called from API endpoints ---

  // Snapshot of all tracked processes (sorted by bytes_rx desc)
  std::vector<ProcessNetInfo> snapshot() const;

  // All browser tabs across all browsers (flat list)
  struct TabInfo {
    std::string browser; // "msedge.exe"
    std::string title;   // "Stack Overflow - ..."
    uint32_t pid = 0;
  };
  std::vector<TabInfo> browser_tabs() const;

  // --- Called from NfqCapture to credit packet bytes to a process ---
  void add_bytes(uint16_t local_port, uint32_t bytes, bool outbound);

private:
  void poll_loop();
  void refresh_connections();  // rebuild port→pid map
  void refresh_processes();    // update exe names & browser tabs
  void refresh_browser_tabs(); // enumerate visible windows

  std::string resolve_exe(uint32_t pid) const;
  std::string friendly_name(const std::string &exe) const;
  bool is_browser_exe(const std::string &exe) const;

  mutable std::mutex mtx_;

  // port → pid  (rebuilt every refresh)
  std::unordered_map<uint16_t, uint32_t> port_to_pid_;

  // pid → ProcessNetInfo
  std::unordered_map<uint32_t, ProcessNetInfo> procs_;

  std::unordered_set<std::string> blocked_apps_;

  std::thread thread_;
  std::atomic<bool> running_{false};
};

} // namespace fw
