#pragma once
#include <atomic>
#include <cstdint>
#include <string>


// ──────────────────────────────────────────────────────────────
//  types.hpp  –  shared enums and plain structs used everywhere
// ──────────────────────────────────────────────────────────────

namespace fw {

// ── Protocol ────────────────────────────────────────────────
enum class Proto : uint8_t {
  ANY = 0,
  TCP = 6,  // matches IPPROTO_TCP
  UDP = 17, // matches IPPROTO_UDP
  ICMP = 1  // matches IPPROTO_ICMP
};

inline const char *proto_name(Proto p) {
  switch (p) {
  case Proto::TCP:
    return "TCP";
  case Proto::UDP:
    return "UDP";
  case Proto::ICMP:
    return "ICMP";
  default:
    return "ANY";
  }
}

// ── TCP Flags ────────────────────────────────────────────────
constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_PSH = 0x08;
constexpr uint8_t TCP_ACK = 0x10;
constexpr uint8_t TCP_URG = 0x20;

// ── Flow State ───────────────────────────────────────────────
enum class FlowState { NEW, ESTABLISHED, RELATED, INVALID };

// ── Verdict ──────────────────────────────────────────────────
enum class Action { ALLOW, BLOCK };

inline const char *action_name(Action a) {
  return a == Action::ALLOW ? "ALLOW" : "BLOCK";
}

// ── Direction ────────────────────────────────────────────────
enum class Direction { ANY, INBOUND, OUTBOUND };

// ── Parsed packet summary ────────────────────────────────────
struct PacketInfo {
  Proto proto = Proto::ANY;
  uint32_t src_ip = 0; // host byte order
  uint32_t dst_ip = 0;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  Direction dir = Direction::ANY;
  uint8_t tcp_flags = 0; // Contains SYN, ACK, FIN, RST, etc. if proto == TCP
  uint32_t tcp_seq = 0;
  uint32_t tcp_ack = 0;
  uint8_t ttl = 0; // Time-to-Live field from IP header

  // Fragment Info
  bool is_frag_offset = false;
  bool has_more_frags = false;
  uint16_t frag_offset_bytes = 0;

  // ICMP Info
  uint8_t icmp_type = 0;
  uint8_t icmp_code = 0;

  bool is_ipv6 = false;     // Set by capture layer for IPv6 packets (groundwork)
  std::string process_name; // Looked up via ProcessMonitor before evaluation

  // Raw payload for DPI
  const uint8_t *payload_ptr = nullptr;
  uint16_t payload_len = 0;

  // Raw byte count (for logging/stats)
  int size = 0;
};

// ── Firewall rule ────────────────────────────────────────────
struct Rule {
  uint32_t id = 0;
  Action action = Action::BLOCK;
  Proto proto = Proto::ANY;
  Direction direction = Direction::ANY;

  uint32_t src_ip = 0; // 0 = wildcard
  uint32_t dst_ip = 0;
  uint16_t src_port = 0; // 0 = wildcard
  uint16_t dst_port = 0;

  std::string process_name; // empty = wildcard
  std::string description;

  // Stats
  mutable std::atomic<uint64_t> hit_count{0};

  Rule() = default;
  Rule(const Rule &o)
      : id(o.id), action(o.action), proto(o.proto), direction(o.direction),
        src_ip(o.src_ip), dst_ip(o.dst_ip), src_port(o.src_port),
        dst_port(o.dst_port), process_name(o.process_name),
        description(o.description), hit_count(o.hit_count.load()) {}
  Rule(Rule &&o) noexcept
      : id(o.id), action(o.action), proto(o.proto), direction(o.direction),
        src_ip(o.src_ip), dst_ip(o.dst_ip), src_port(o.src_port),
        dst_port(o.dst_port), process_name(std::move(o.process_name)),
        description(std::move(o.description)), hit_count(o.hit_count.load()) {}
  Rule &operator=(const Rule &o) {
    if (this != &o) {
      id = o.id;
      action = o.action;
      proto = o.proto;
      direction = o.direction;
      src_ip = o.src_ip;
      dst_ip = o.dst_ip;
      src_port = o.src_port;
      dst_port = o.dst_port;
      process_name = o.process_name;
      description = o.description;
      hit_count.store(o.hit_count.load());
    }
    return *this;
  }
  Rule &operator=(Rule &&o) noexcept {
    if (this != &o) {
      id = o.id;
      action = o.action;
      proto = o.proto;
      direction = o.direction;
      src_ip = o.src_ip;
      dst_ip = o.dst_ip;
      src_port = o.src_port;
      dst_port = o.dst_port;
      process_name = std::move(o.process_name);
      description = std::move(o.description);
      hit_count.store(o.hit_count.load());
    }
    return *this;
  }

  Rule(uint32_t i, Action a, Proto p, Direction d, uint32_t si, uint32_t di,
       uint16_t sp, uint16_t dp, std::string desc, uint64_t hc)
      : id(i), action(a), proto(p), direction(d), src_ip(si), dst_ip(di),
        src_port(sp), dst_port(dp), description(std::move(desc)),
        hit_count(hc) {}
};

} // namespace fw