// ──────────────────────────────────────────────────────────────────────────────
//  process_monitor.cpp
//
//  Windows: real implementation using iphlpapi.
//    - GetExtendedTcpTable / GetExtendedUdpTable → port→PID map
//    - OpenProcess + QueryFullProcessImageName  → EXE path
//    - EnumWindows                              → browser window titles
//
//  Linux: stub that always returns empty strings.
//         A real impl would parse /proc/net/tcp and /proc/PID/exe.
// ──────────────────────────────────────────────────────────────────────────────

#include "process_monitor.hpp"
#include "platform.hpp"

#ifdef _WIN32
// iphlpapi must come after winsock2.h (pulled in by platform.hpp)
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#endif

#include <algorithm>
#include <chrono>
#include <iostream>
#include <thread>

namespace fw {

// ── Constructor / Destructor ─────────────────────────────────────────────────

ProcessMonitor::ProcessMonitor() = default;

ProcessMonitor::~ProcessMonitor() { stop(); }

void ProcessMonitor::start() {
  if (running_.exchange(true))
    return; // already running
  thread_ = std::thread([this]() { poll_loop(); });
}

void ProcessMonitor::stop() {
  if (!running_.exchange(false))
    return;
  if (thread_.joinable())
    thread_.join();
}

// ── Public fast-path lookups ─────────────────────────────────────────────────

std::string ProcessMonitor::process_name_for_port(uint16_t local_port) const {
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = port_to_pid_.find(local_port);
  if (it == port_to_pid_.end())
    return "";
  auto pit = procs_.find(it->second);
  if (pit == procs_.end())
    return "";
  return pit->second.exe_name;
}

uint32_t ProcessMonitor::pid_for_port(uint16_t local_port) const {
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = port_to_pid_.find(local_port);
  return (it != port_to_pid_.end()) ? it->second : 0;
}

std::vector<ProcessNetInfo> ProcessMonitor::snapshot() const {
  std::lock_guard<std::mutex> lock(mtx_);
  std::vector<ProcessNetInfo> out;
  out.reserve(procs_.size());
  for (auto &[pid, info] : procs_) {
    out.push_back(info);
  }
  // Sort by total bytes descending
  std::sort(out.begin(), out.end(),
            [](const ProcessNetInfo &a, const ProcessNetInfo &b) {
              return (a.bytes_rx + a.bytes_tx) > (b.bytes_rx + b.bytes_tx);
            });
  return out;
}

std::vector<ProcessMonitor::TabInfo> ProcessMonitor::browser_tabs() const {
  std::lock_guard<std::mutex> lock(mtx_);
  std::vector<TabInfo> out;
  for (auto &[pid, info] : procs_) {
    if (!info.is_browser)
      continue;
    for (auto &title : info.browser_tabs) {
      TabInfo t;
      t.browser = info.exe_name;
      t.title = title;
      t.pid = pid;
      out.push_back(std::move(t));
    }
  }
  return out;
}

void ProcessMonitor::add_bytes(uint16_t local_port, uint32_t bytes,
                               bool outbound) {
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = port_to_pid_.find(local_port);
  if (it == port_to_pid_.end())
    return;
  auto pit = procs_.find(it->second);
  if (pit == procs_.end())
    return;
  if (outbound)
    pit->second.bytes_tx += bytes;
  else
    pit->second.bytes_rx += bytes;
  pit->second.pkt_count++;
}

void ProcessMonitor::set_app_blocked(const std::string& exe_name, bool blocked) {
  std::lock_guard<std::mutex> lock(mtx_);
  if (blocked) {
    blocked_apps_.insert(exe_name);
  } else {
    blocked_apps_.erase(exe_name);
  }
  // Sync immediately to tracked processes
  for (auto &[pid, info] : procs_) {
    if (info.exe_name == exe_name) {
      info.is_blocked = blocked;
    }
  }
}

bool ProcessMonitor::is_app_blocked(const std::string& exe_name) const {
  std::lock_guard<std::mutex> lock(mtx_);
  return blocked_apps_.find(exe_name) != blocked_apps_.end();
}

// ── Background poll loop ─────────────────────────────────────────────────────

void ProcessMonitor::poll_loop() {
  while (running_) {
    refresh_connections();
    refresh_processes();
    refresh_browser_tabs();
    // Sleep 2 seconds between refreshes
    for (int i = 0; i < 20 && running_; ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

// ── Platform implementations ─────────────────────────────────────────────────

#ifdef _WIN32

void ProcessMonitor::refresh_connections() {
  // ── Step 1: Clear stale entries under lock ─────────────────────────────
  {
    std::lock_guard<std::mutex> lock(mtx_);
    port_to_pid_.clear();
    for (auto &[pid, info] : procs_) {
      info.tcp_ports.clear();
      info.udp_ports.clear();
    }
  }

  // ── Step 2: TCP connections ────────────────────────────────────────────
  ULONG size = 0;
  GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL,
                      0);
  if (size == 0)
    size = 65536; // safety fallback
  std::vector<uint8_t> buf(size);
  if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                          TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
    auto *table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(buf.data());
    std::lock_guard<std::mutex> lock(mtx_);
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
      auto &row = table->table[i];
      uint16_t local_port = ntohs(static_cast<uint16_t>(row.dwLocalPort));
      uint32_t pid = row.dwOwningPid;
      port_to_pid_[local_port] = pid;
      if (procs_.find(pid) == procs_.end()) {
        ProcessNetInfo info;
        info.pid = pid;
        procs_[pid] = std::move(info);
      }
      procs_[pid].tcp_ports.push_back(local_port);
    }
  }

  // ── Step 3: UDP endpoints ──────────────────────────────────────────────
  size = 0;
  GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
  if (size == 0)
    size = 65536;
  std::vector<uint8_t> ubuf(size);
  if (GetExtendedUdpTable(ubuf.data(), &size, FALSE, AF_INET,
                          UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
    auto *utable = reinterpret_cast<MIB_UDPTABLE_OWNER_PID *>(ubuf.data());
    std::lock_guard<std::mutex> lock(mtx_);
    for (DWORD i = 0; i < utable->dwNumEntries; ++i) {
      auto &row = utable->table[i];
      uint16_t local_port = ntohs(static_cast<uint16_t>(row.dwLocalPort));
      uint32_t pid = row.dwOwningPid;
      port_to_pid_[local_port] = pid;
      if (procs_.find(pid) == procs_.end()) {
        ProcessNetInfo info;
        info.pid = pid;
        procs_[pid] = std::move(info);
      }
      procs_[pid].udp_ports.push_back(local_port);
    }
  }
}

void ProcessMonitor::refresh_processes() {
  std::lock_guard<std::mutex> lock(mtx_);
  for (auto &[pid, info] : procs_) {
    if (info.exe_name.empty()) {
      info.exe_name = resolve_exe(pid);
      info.display_name = friendly_name(info.exe_name);
      info.is_browser = is_browser_exe(info.exe_name);
      // Inherit blocked status if the app is already in the blocklist
      if (blocked_apps_.find(info.exe_name) != blocked_apps_.end()) {
        info.is_blocked = true;
      }
    }
    // Clear port lists — they'll be rebuilt next refresh_connections()
    info.tcp_ports.clear();
    info.udp_ports.clear();
  }
}

// EnumWindows callback data
struct EnumData {
  std::unordered_map<uint32_t, std::vector<std::string>> *pid_tabs;
};

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
  auto *data = reinterpret_cast<EnumData *>(lParam);
  if (!IsWindowVisible(hwnd))
    return TRUE;

  DWORD pid = 0;
  GetWindowThreadProcessId(hwnd, &pid);

  // Only collect titles for PIDs we are tracking
  auto it = data->pid_tabs->find(pid);
  if (it == data->pid_tabs->end())
    return TRUE;

  char title[512] = {};
  GetWindowTextA(hwnd, title, sizeof(title));
  if (title[0] == '\0')
    return TRUE;

  it->second.push_back(std::string(title));
  return TRUE;
}

void ProcessMonitor::refresh_browser_tabs() {
  // Build a pid→titles map for browser PIDs only
  std::unordered_map<uint32_t, std::vector<std::string>> pid_tabs;
  {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto &[pid, info] : procs_) {
      if (info.is_browser)
        pid_tabs[pid] = {};
    }
  }
  if (pid_tabs.empty())
    return;

  EnumData data{&pid_tabs};
  EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&data));

  std::lock_guard<std::mutex> lock(mtx_);
  for (auto &[pid, titles] : pid_tabs) {
    auto it = procs_.find(pid);
    if (it == procs_.end())
      continue;
    it->second.browser_tabs = std::move(titles);
  }
}

std::string ProcessMonitor::resolve_exe(uint32_t pid) const {
  if (pid == 0)
    return "System";
  HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                             static_cast<DWORD>(pid));
  if (!hProc)
    return "Unknown";
  char path[MAX_PATH] = {};
  DWORD size = MAX_PATH;
  if (!QueryFullProcessImageNameA(hProc, 0, path, &size)) {
    CloseHandle(hProc);
    return "Unknown";
  }
  CloseHandle(hProc);
  // Extract just the filename (e.g. "chrome.exe")
  std::string full(path);
  auto slash = full.find_last_of("\\/");
  return (slash != std::string::npos) ? full.substr(slash + 1) : full;
}

#else
// ── Linux stub ───────────────────────────────────────────────────────────────
void ProcessMonitor::refresh_connections() {
  // TODO: parse /proc/net/tcp and /proc/net/udp
  // Each line gives: local_addr (hex:port), inode
  // Then match inode in /proc/<pid>/fd/ symlinks pointing to socket:[inode]
}

void ProcessMonitor::refresh_processes() {
  // TODO: iterate /proc/<pid>/exe for exe names
}

void ProcessMonitor::refresh_browser_tabs() {
  // TODO: Use xdotool or DBus for browser tab titles on Linux
}

std::string ProcessMonitor::resolve_exe(uint32_t /*pid*/) const { return ""; }
#endif

// ── Helpers (shared) ─────────────────────────────────────────────────────────

std::string ProcessMonitor::friendly_name(const std::string &exe) const {
  // Map well-known exe names to display names
  static const std::unordered_map<std::string, std::string> names = {
      {"chrome.exe", "Google Chrome"},
      {"msedge.exe", "Microsoft Edge"},
      {"firefox.exe", "Mozilla Firefox"},
      {"brave.exe", "Brave Browser"},
      {"opera.exe", "Opera"},
      {"iexplore.exe", "Internet Explorer"},
      {"svchost.exe", "Windows Service Host"},
      {"lsass.exe", "Local Security Authority"},
      {"explorer.exe", "Windows Explorer"},
      {"discord.exe", "Discord"},
      {"slack.exe", "Slack"},
      {"zoom.exe", "Zoom"},
      {"teams.exe", "Microsoft Teams"},
      {"spotify.exe", "Spotify"},
      {"steam.exe", "Steam"},
      {"code.exe", "VS Code"},
      {"devenv.exe", "Visual Studio"},
      {"clion64.exe", "CLion"},
      {"idea64.exe", "IntelliJ IDEA"},
      {"python.exe", "Python"},
      {"python3.exe", "Python 3"},
      {"node.exe", "Node.js"},
      {"java.exe", "Java"},
      {"javaw.exe", "Java (Window)"},
      {"curl.exe", "cURL"},
      {"git.exe", "Git"},
      {"ssh.exe", "SSH"},
      {"powershell.exe", "PowerShell"},
      {"cmd.exe", "Command Prompt"},
      {"wt.exe", "Windows Terminal"},
      {"OneDrive.exe", "OneDrive"},
      {"dropbox.exe", "Dropbox"},
      {"googledrivesync.exe", "Google Drive"},
      {"vmware.exe", "VMware"},
      {"VirtualBox.exe", "VirtualBox"},
      {"nginx.exe", "nginx"},
      {"httpd.exe", "Apache HTTPD"},
      {"mongod.exe", "MongoDB"},
      {"mysqld.exe", "MySQL"},
      {"postgres.exe", "PostgreSQL"},
      {"redis-server.exe", "Redis"},
      {"outlook.exe", "Microsoft Outlook"},
      {"winword.exe", "Microsoft Word"},
      {"excel.exe", "Microsoft Excel"},
      {"acrobat.exe", "Adobe Acrobat"},
      {"vlc.exe", "VLC Media Player"},
  };

  // Convert to lowercase for lookup
  std::string lower = exe;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  auto it = names.find(lower);
  if (it != names.end())
    return it->second;

  // Strip .exe suffix for a reasonable display name
  std::string name = exe;
  if (name.size() > 4 && (name.substr(name.size() - 4) == ".exe" ||
                          name.substr(name.size() - 4) == ".EXE"))
    name = name.substr(0, name.size() - 4);
  return name;
}

bool ProcessMonitor::is_browser_exe(const std::string &exe) const {
  static const std::vector<std::string> browsers = {
      "chrome.exe", "msedge.exe",   "firefox.exe", "brave.exe",
      "opera.exe",  "iexplore.exe", "vivaldi.exe", "waterfox.exe"};
  std::string lower = exe;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  for (auto &b : browsers)
    if (lower == b)
      return true;
  return false;
}

} // namespace fw
