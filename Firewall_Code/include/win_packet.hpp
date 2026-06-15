#pragma once

// ──────────────────────────────────────────────────────────────────────────────
//  win_packet.hpp  –  Windows-native IP/TCP/UDP/ICMP header structs
//
//  On Linux these come from <netinet/ip.h>, <netinet/tcp.h>, etc.
//  On Windows we define compatible equivalents (packed to match wire format).
//
//  Only included on Windows (_WIN32).  packet.cpp selects the right path.
// ──────────────────────────────────────────────────────────────────────────────

#ifdef _WIN32

#include "platform.hpp"   // pulls in winsock2.h / windows.h
#include <cstdint>

#pragma pack(push, 1)

// ── IPv4 header ──────────────────────────────────────────────────────────────
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD) || defined(_WIN32)
    uint8_t  ihl    : 4;   // header length (in 32-bit words)
    uint8_t  version: 4;
#else
    uint8_t  version: 4;
    uint8_t  ihl    : 4;
#endif
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

// ── TCP header ───────────────────────────────────────────────────────────────
struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD) || defined(_WIN32)
    uint8_t  res1  : 4;
    uint8_t  doff  : 4;   // data offset (header len in 32-bit words)
#else
    uint8_t  doff  : 4;
    uint8_t  res1  : 4;
#endif
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

// ── UDP header ───────────────────────────────────────────────────────────────
struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

// ── ICMP header (echo) ───────────────────────────────────────────────────────
struct icmphdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

#pragma pack(pop)

// Protocol constants (mirror POSIX values)
#ifndef IPPROTO_TCP
#  define IPPROTO_TCP  6
#endif
#ifndef IPPROTO_UDP
#  define IPPROTO_UDP  17
#endif
#ifndef IPPROTO_ICMP
#  define IPPROTO_ICMP 1
#endif

#endif // _WIN32
