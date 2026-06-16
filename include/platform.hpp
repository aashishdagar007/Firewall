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

// #pragma comment is MSVC-only; MinGW/GCC links ws2_32 via CMake
// target_link_libraries
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
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

#endif // _WIN32
