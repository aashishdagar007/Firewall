#pragma once

// ──────────────────────────────────────────────────────────────────────────────
//  platform.hpp  –  Cross-platform socket / network API abstractions
//
//  Include this BEFORE any other network or project headers.
//  It reconciles POSIX (Linux/macOS) vs Winsock2 (Windows) APIs so the
//  rest of the code can use a single set of portable names.
// ──────────────────────────────────────────────────────────────────────────────

#include <cstdint> // uint32_t, etc.
#include <string>  // std::string  — must come before Windows headers

#ifdef _WIN32
// ── Windows ─────────────────────────────────────────────────────────────────

// Must be set before winsock2.h AND before httplib.h (which requires >= 0x0A00)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 // Windows 10+
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <sddl.h>
#include <aclapi.h>
#include <accctrl.h>
#include <psapi.h>
#include <wincrypt.h>

// #pragma comment is MSVC-only; MinGW/GCC links ws2_32, advapi32, crypt32 via CMake
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#endif

// MinGW may not define ssize_t (MSVC's winsock path does it in httplib.h)
#if (defined(__MINGW32__) || defined(__MINGW64__)) && !defined(_SSIZE_T_DEFINED)
using ssize_t = long long;
#define _SSIZE_T_DEFINED
#endif

// Winsock uses SOCKET (uintptr_t), POSIX uses int
using sock_t = SOCKET;
static constexpr sock_t INVALID_SOCK = INVALID_SOCKET;

inline void close_socket(sock_t s) { closesocket(s); }
inline bool socket_valid(sock_t s) { return s != INVALID_SOCKET; }

// WSAStartup / WSACleanup helpers (no-ops on Linux)
inline bool wsa_init() {
  WSADATA wsa;
  return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}
inline void wsa_cleanup() { WSACleanup(); }

// ── Privilege & Security Helpers ─────────────────────────────────────────────

// Check whether current process token is in BUILTIN\Administrators or Local SYSTEM
inline bool check_is_elevated_admin() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt_authority, 2,
                                  SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0,
                                  &admin_group)) {
        if (!CheckTokenMembership(nullptr, admin_group, &is_admin)) {
            is_admin = FALSE;
        }
        FreeSid(admin_group);
    }
    return is_admin == TRUE;
}

// Drop/strip dangerous privileges on worker threads (logging, IPC)
inline bool drop_thread_privileges() {
    HANDLE hToken = nullptr;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
        if (GetLastError() == ERROR_NO_TOKEN) {
            if (!ImpersonateSelf(SecurityImpersonation)) {
                return false;
            }
            if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
                return false;
            }
        } else {
            return false;
        }
    }

    // Disable all privileges in this thread token
    BOOL ok = AdjustTokenPrivileges(hToken, TRUE, nullptr, 0, nullptr, nullptr);
    CloseHandle(hToken);
    return ok != FALSE;
}

// Lock a file to SYSTEM and BUILTIN\Administrators only (protected DACL)
inline bool apply_strict_file_security(const std::string& path) {
    PSECURITY_DESCRIPTOR pSD = nullptr;
    ULONG sdSize = 0;
    // SDDL: Protected DACL (no inheritance), Grant All to SYSTEM (SY) and Administrators (BA)
    const wchar_t* sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &pSD, &sdSize)) {
        return false;
    }
    PACL pDacl = nullptr;
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted);

    int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    std::wstring wpath(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], wlen);

    DWORD res = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(wpath.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, pDacl, nullptr);

    LocalFree(pSD);
    return res == ERROR_SUCCESS;
}

// Verify that file DACL has not been weakened to permit non-admin write access
inline bool verify_file_security(const std::string& path) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    std::wstring wpath(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], wlen);

    PSECURITY_DESCRIPTOR pSD = nullptr;
    PACL pDacl = nullptr;
    DWORD res = GetNamedSecurityInfoW(
        wpath.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &pDacl, nullptr, &pSD);

    if (res != ERROR_SUCCESS || !pSD) {
        return false;
    }

    if (!pDacl) {
        LocalFree(pSD);
        return false; // NULL DACL is insecure
    }

    PSID pAdminSid = nullptr;
    PSID pSystemSid = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSid);
    AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid);

    bool secure = true;
    for (WORD i = 0; i < pDacl->AceCount; ++i) {
        LPVOID pAce = nullptr;
        if (!GetAce(pDacl, i, &pAce)) continue;
        PACE_HEADER header = (PACE_HEADER)pAce;
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE* pAllowed = (ACCESS_ALLOWED_ACE*)pAce;
            PSID aceSid = (PSID)&pAllowed->SidStart;
            // Any principal other than SYSTEM or Administrators must NOT have write access
            if (!EqualSid(aceSid, pAdminSid) && !EqualSid(aceSid, pSystemSid)) {
                ACCESS_MASK writeMask = FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
                if ((pAllowed->Mask & writeMask) != 0) {
                    secure = false;
                    break;
                }
            }
        }
    }

    if (pAdminSid) FreeSid(pAdminSid);
    if (pSystemSid) FreeSid(pSystemSid);
    LocalFree(pSD);
    return secure;
}

// Verify connected named pipe client process identity
inline bool verify_pipe_client_identity(HANDLE hPipe, const std::wstring& expected_process_substring = L"aegix-ui.exe") {
    ULONG clientPid = 0;
    if (!GetNamedPipeClientProcessId(hPipe, &clientPid)) {
        return false;
    }
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, clientPid);
    if (!hProcess) {
        return false;
    }
    wchar_t exePath[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    BOOL queryOk = QueryFullProcessImageNameW(hProcess, 0, exePath, &size);
    CloseHandle(hProcess);

    if (!queryOk) {
        return false;
    }

    if (expected_process_substring.empty()) return true;

    auto to_lower = [](std::wstring s) {
        for (auto& c : s) c = towlower(c);
        return s;
    };
    std::wstring lowerPath = to_lower(std::wstring(exePath));
    std::wstring lowerExpected = to_lower(expected_process_substring);

    return (lowerPath.find(lowerExpected) != std::wstring::npos);
}

// errno equivalent
inline int last_net_error() { return WSAGetLastError(); }

// Windows inet helpers (ws2tcpip.h provides inet_pton / inet_ntop)
inline std::string ip4_to_string(uint32_t host_order_ip) {
  struct in_addr a{};
  a.s_addr = htonl(host_order_ip);
  char buf[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &a, buf, sizeof(buf));
  return std::string(buf);
}

inline uint32_t string_to_ip4(const char *s) {
  struct in_addr a{};
  if (inet_pton(AF_INET, s, &a) != 1)
    return 0;
  return ntohl(a.s_addr);
}

// POSIX-style sleep shim
inline void sleep_ms(int ms) { Sleep(static_cast<DWORD>(ms)); }

// ── Linux / macOS ────────────────────────────────────────────────────────────
#else

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

using sock_t = int;
static constexpr sock_t INVALID_SOCK = -1;

inline void close_socket(sock_t s) { close(s); }
inline bool socket_valid(sock_t s) { return s >= 0; }

inline bool wsa_init() { return true; }
inline void wsa_cleanup() {}

inline int last_net_error() { return errno; }

inline std::string ip4_to_string(uint32_t host_order_ip) {
  struct in_addr a{};
  a.s_addr = htonl(host_order_ip);
  char buf[INET_ADDRSTRLEN]{};
  inet_ntop(AF_INET, &a, buf, sizeof(buf));
  return std::string(buf);
}

inline uint32_t string_to_ip4(const char *s) {
  struct in_addr a{};
  if (inet_aton(s, &a) == 0)
    return 0;
  return ntohl(a.s_addr);
}

inline void sleep_ms(int ms) {
  struct timeval tv{ms / 1000, (ms % 1000) * 1000};
  select(0, nullptr, nullptr, nullptr, &tv);
}

inline bool check_is_elevated_admin() {
  return geteuid() == 0;
}

inline bool drop_thread_privileges() {
  return true;
}

inline bool apply_strict_file_security(const std::string& path) {
  (void)path;
  return true;
}

inline bool verify_file_security(const std::string& path) {
  (void)path;
  return true;
}

inline bool verify_pipe_client_identity(int fd, const std::string& expected = "") {
  (void)fd;
  (void)expected;
  return true;
}

#endif // _WIN32
