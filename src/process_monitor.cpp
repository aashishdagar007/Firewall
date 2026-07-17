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
#include "sha256.hpp"
#include "local_graph_store.hpp"

#ifdef _WIN32
// iphlpapi must come after winsock2.h (pulled in by platform.hpp)
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#ifdef _MSC_VER
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#endif
#endif

#include <algorithm>
#include <chrono>
#include <iostream>
#include <thread>

namespace fw {

// ── Constructor / Destructor ─────────────────────────────────────────────────

ProcessMonitor::ProcessMonitor(LocalGraphStore* graph_store) : graph_store_(graph_store) {}

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

// ── LOLBin Detection ─────────────────────────────────────────────────────────

// Curated list of Living-Off-the-Land binaries known to be abused for
// network C2, lateral movement, and payload download/execution.
// Sources: LOLBAS Project (https://lolbas-project.github.io/)
bool ProcessMonitor::is_lolbin(const std::string& exe_name) {
  // Normalize to lowercase for case-insensitive comparison
  std::string lower = exe_name;
  for (char& c : lower)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

  // Strip path — only compare the basename
  auto slash = lower.rfind('\\');
  if (slash == std::string::npos) slash = lower.rfind('/');
  if (slash != std::string::npos) lower = lower.substr(slash + 1);

  static const std::unordered_set<std::string> lolbins = {
    // Download / execution via trusted binary
    "certutil.exe",      // -urlcache download, -decode base64
    "bitsadmin.exe",     // /transfer download
    "mshta.exe",         // HTA execution, VBScript/JScript
    "regsvr32.exe",      // scrobj.dll COM scriptlet execution
    "rundll32.exe",      // arbitrary DLL loading
    "installutil.exe",   // .NET assembly execution via InstallUtil
    "cmstp.exe",         // INF file execution (UAC bypass)
    "msiexec.exe",       // remote MSI / /q silent install
    "wscript.exe",       // Windows Script Host execution
    "cscript.exe",       // Console Script Host execution
    "powershell.exe",    // Encoded commands, download cradles
    "pwsh.exe",          // PowerShell Core
    "cmd.exe",           // Command shell (when spawned by Office/browser)
    "wmic.exe",          // /node: remote execution
    "forfiles.exe",      // /c parameter code execution
    "pcalua.exe",        // Program Compatibility Assistant LOLBin
    "msdeploy.exe",      // Web deployment tool abuse
    "appsyncpublishingserver.exe", // XSLT transformation execution
    "dnscmd.exe",        // DNS server enumeration + DLL injection
    "ieexec.exe",        // IE-based download execution
    "extrac32.exe",      // CAB file extraction download abuse
    "findstr.exe",       // /S file search for credential harvest
    "gpscript.exe",      // Group Policy script execution
  };

  return lolbins.count(lower) > 0;
}

void ProcessMonitor::log_lolbin_event(const std::string& exe_name, uint32_t pid,
                                       uint32_t dst_ip, uint16_t dst_port) {
  std::lock_guard<std::mutex> lock(mtx_);

  LolBinEvent ev;
  auto tp = std::chrono::steady_clock::now().time_since_epoch();
  ev.timestamp    = std::to_string(
      std::chrono::duration_cast<std::chrono::milliseconds>(tp).count());
  ev.pid          = pid;
  ev.exe_name     = exe_name;
  ev.dst_ip       = ip4_to_string(dst_ip);
  ev.dst_port     = dst_port;
  ev.threat_detail = "LOLBin network access: " + exe_name +
                     " (PID " + std::to_string(pid) +
                     ") → " + ev.dst_ip + ":" + std::to_string(dst_port);

  if (lolbin_events_.size() >= MAX_LOLBIN_EVENTS)
    lolbin_events_.pop_front();
  lolbin_events_.push_back(std::move(ev));
}

std::vector<LolBinEvent> ProcessMonitor::get_lolbin_events() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return std::vector<LolBinEvent>(lolbin_events_.begin(), lolbin_events_.end());
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

#ifdef _WIN32
#include <winternl.h>
typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

static uint32_t get_ppid(uint32_t pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    uint32_t ppid = 0;
    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return ppid;
}

static std::string hash_file(const std::string& path) {
    if (path.empty() || path == "System" || path == "Unknown") return "";
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) return "";
    SHA256 sha;
    uint8_t buf[4096];
    size_t bytesRead;
    while ((bytesRead = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha.update(buf, bytesRead);
    }
    fclose(f);

    auto digest = sha.finalize();
    return SHA256::to_hex(digest);
}

static std::string get_cmdline(HANDLE hProc) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return "";
    auto pNtQuery = (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pNtQuery) return "";

    PROCESS_BASIC_INFORMATION pbi;
    ULONG len = 0;
    if (pNtQuery(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &len) != 0) return "";
    
    PEB peb;
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) return "";

    RTL_USER_PROCESS_PARAMETERS upp;
    if (!ReadProcessMemory(hProc, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead)) return "";

    std::wstring cmdW(upp.CommandLine.Length / 2, L'\0');
    if (!ReadProcessMemory(hProc, upp.CommandLine.Buffer, &cmdW[0], upp.CommandLine.Length, &bytesRead)) return "";

    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, cmdW.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8_len <= 0) return "";
    std::string cmdA(utf8_len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, cmdW.c_str(), -1, &cmdA[0], utf8_len, nullptr, nullptr);
    if (!cmdA.empty() && cmdA.back() == '\0') cmdA.pop_back();
    return cmdA;
}

struct ProcessDetails {
    std::string exe_name;
    std::string full_path;
    std::string command_line;
};

static ProcessDetails resolve_details(uint32_t pid) {
    ProcessDetails pd{"Unknown", "", ""};
    if (pid == 0) {
        pd.exe_name = "System";
        return pd;
    }
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));
    if (!hProc) {
        // Fallback with less permissions
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
        if (!hProc) return pd;
    }
    char path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameA(hProc, 0, path, &size)) {
        pd.full_path = path;
        std::string full(path);
        auto slash = full.find_last_of("\\/");
        pd.exe_name = (slash != std::string::npos) ? full.substr(slash + 1) : full;
    }
    pd.command_line = get_cmdline(hProc);
    CloseHandle(hProc);
    return pd;
}
#endif

void ProcessMonitor::refresh_processes() {
  std::lock_guard<std::mutex> lock(mtx_);
  for (auto &[pid, info] : procs_) {
    if (info.exe_name.empty()) {
#ifdef _WIN32
      ProcessDetails pd = resolve_details(pid);
      info.exe_name = pd.exe_name;
      info.ppid = get_ppid(pid);
      info.image_hash = hash_file(pd.full_path);
      info.command_line = pd.command_line;
#else
      info.exe_name = resolve_exe(pid);
#endif
      info.display_name = friendly_name(info.exe_name);
      info.is_browser = is_browser_exe(info.exe_name);
      // Inherit blocked status if the app is already in the blocklist
      if (blocked_apps_.find(info.exe_name) != blocked_apps_.end()) {
        info.is_blocked = true;
      }
      if (graph_store_) {
          graph_store_->log_process(info);
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
