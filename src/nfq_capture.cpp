#include "nfq_capture.hpp"
#include "packet.hpp"
#include "platform.hpp"

#ifdef _WIN32
#include "win_packet.hpp"
#else
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

// Conditionally include NFQ headers (Linux only)
#ifdef HAVE_NFQUEUE
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#endif

// ──────────────────────────────────────────────────────────────
//  nfq_capture.cpp  –  cross-platform  (Linux NFQ + Windows raw socket)
//
//  Mode selection:
//    Linux  + HAVE_NFQUEUE  → Real kernel-level packet blocking via NFQUEUE
//    Linux  (no NFQ)        → Raw socket observer (AF_INET, SOCK_RAW)
//    Windows                → Raw socket observer via Winsock2
//                             (Upgrade: use WinDivert for real blocking)
// ──────────────────────────────────────────────────────────────

namespace fw {

static constexpr int BUFSIZE = 65535;

NfqCapture::NfqCapture(RuleEngine& engine, LiveStats& stats,
                       RingBuffer<PacketRecord>& ring,
                       ProcessMonitor* proc_mon,
                       int queue_num)
    : engine_(engine), stats_(stats), ring_(ring),
      proc_mon_(proc_mon), queue_num_(queue_num) {}

NfqCapture::~NfqCapture() {
  stop();
#ifdef HAVE_NFQUEUE
  if (qh_) {
    nfq_destroy_queue(qh_);
    qh_ = nullptr;
  }
  if (h_) {
    nfq_close(h_);
    h_ = nullptr;
  }
#endif
  if (socket_valid(tcp_sock_))
    close_socket(tcp_sock_);
  if (socket_valid(udp_sock_))
    close_socket(udp_sock_);
  if (socket_valid(icmp_sock_))
    close_socket(icmp_sock_);
}

// ── open() ───────────────────────────────────────────────────
bool NfqCapture::open() {
#ifdef HAVE_NFQUEUE
  // ── Linux NFQ path ────────────────────────────────────────
  h_ = nfq_open();
  if (!h_) {
    std::cerr << "[NFQ] nfq_open() failed, falling back to raw sockets\n";
    goto fallback;
  }
  if (nfq_unbind_pf(h_, AF_INET) < 0) {
    std::cerr << "[NFQ] nfq_unbind_pf() failed\n";
  }
  if (nfq_bind_pf(h_, AF_INET) < 0) {
    std::cerr << "[NFQ] nfq_bind_pf() failed, falling back\n";
    nfq_close(h_);
    h_ = nullptr;
    goto fallback;
  }
  qh_ = nfq_create_queue(h_, queue_num_, &NfqCapture::nfq_callback, this);
  if (!qh_) {
    std::cerr << "[NFQ] nfq_create_queue() failed, falling back\n";
    nfq_close(h_);
    h_ = nullptr;
    goto fallback;
  }
  if (nfq_set_mode(qh_, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
    std::cerr << "[NFQ] nfq_set_mode() failed\n";
    goto fallback;
  }
  fd_ = nfq_fd(h_);
  nfq_mode_ = true;
  std::cout << "[NFQ] NFQUEUE mode active on queue " << queue_num_ << "\n";
  return true;

fallback:
#endif // HAVE_NFQUEUE

  // ── Raw socket observer fallback (Linux + Windows) ────────
  return open_raw_sockets();
}

bool NfqCapture::open_raw_sockets() {
#ifdef _WIN32
  // ── Step 1: Resolve primary local NIC IP ─────────────────────────────────
  // SIO_RCVALL CANNOT be applied to a socket bound to INADDR_ANY (0.0.0.0).
  // It MUST be bound to a specific local adapter IP address.
  // We resolve the primary IP via gethostname → getaddrinfo.
  SOCKADDR_IN bind_addr{};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = 0;
  bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // fallback

  char hostname[256] = {};
  if (gethostname(hostname, sizeof(hostname)) == 0) {
    struct addrinfo hints{};
    hints.ai_family = AF_INET; // IPv4 only
    hints.ai_socktype = SOCK_RAW;
    struct addrinfo *res = nullptr;
    if (getaddrinfo(hostname, nullptr, &hints, &res) == 0 && res) {
      // Use the first IPv4 result
      bind_addr.sin_addr =
          reinterpret_cast<SOCKADDR_IN *>(res->ai_addr)->sin_addr;
      freeaddrinfo(res);
      char ip_buf[INET_ADDRSTRLEN] = {};
      inet_ntop(AF_INET, &bind_addr.sin_addr, ip_buf, sizeof(ip_buf));
      std::cout << "[Capture] Binding to local adapter IP: " << ip_buf << "\n";
    } else {
      std::cerr << "[Capture] getaddrinfo failed — falling back to loopback\n";
    }
  }

  // ── Step 2: Create raw socket ─────────────────────────────────────────────
  tcp_sock_ = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
  if (!socket_valid(tcp_sock_)) {
    int err = last_net_error();
    std::cerr << "[Capture] socket(AF_INET, SOCK_RAW, IPPROTO_IP) failed.\n"
              << "          WSA error: " << err << "\n"
              << "          >>> Run as Administrator (WSA 10013 = access "
                 "denied) <<<\n";
    return false;
  }

  // ── Step 3: Bind to specific local IP (required for SIO_RCVALL) ──────────
  if (bind(tcp_sock_, reinterpret_cast<SOCKADDR *>(&bind_addr),
           sizeof(bind_addr)) == SOCKET_ERROR) {
    int err = last_net_error();
    std::cerr << "[Capture] bind() failed (WSA " << err << ").\n"
              << "          Ensure the IP is a valid local adapter address.\n";
    close_socket(tcp_sock_);
    tcp_sock_ = INVALID_SOCK;
    return false;
  }

  // ── Step 4: Enable promiscuous mode (SIO_RCVALL) ──────────────────────────
  // This captures ALL inbound IP packets on the bound adapter.
  // Requires Administrator and a non-INADDR_ANY bind address.
  DWORD opt = RCVALL_ON;
  DWORD ret = 0;
  if (WSAIoctl(tcp_sock_, SIO_RCVALL, &opt, sizeof(opt), nullptr, 0, &ret,
               nullptr, nullptr) == SOCKET_ERROR) {
    int err = last_net_error();
    std::cerr << "[Capture] SIO_RCVALL failed (WSA " << err << ").\n"
              << "          Common causes:\n"
              << "            - Not running as Administrator (WSA 10013)\n"
              << "            - Wi-Fi adapter may not support SIO_RCVALL\n"
              << "              (use an Ethernet/LAN adapter instead)\n"
              << "          See: "
                 "https://docs.microsoft.com/en-us/windows/win32/winsock/"
                 "sio-rcvall\n";
    close_socket(tcp_sock_);
    tcp_sock_ = INVALID_SOCK;
    return false;
  }

  // Single promiscuous socket captures all IP traffic
  udp_sock_ = INVALID_SOCK;
  icmp_sock_ = INVALID_SOCK;

  nfq_mode_ = false;
  std::cout
      << "[Capture] Windows raw-socket observer mode — active.\n"
      << "[Capture] Tip: for real packet blocking, integrate WinDivert.\n";
  return true;

#else
  // Linux raw sockets (fallback without NFQ)
  tcp_sock_ = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  udp_sock_ = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  icmp_sock_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

  if (!socket_valid(tcp_sock_) || !socket_valid(udp_sock_) ||
      !socket_valid(icmp_sock_)) {
    std::cerr << "[Capture] Failed to open raw sockets. Run as root?\n";
    return false;
  }

  nfq_mode_ = false;
  std::cout << "[Capture] Raw socket observer mode (run as root; "
               "build with HAVE_NFQUEUE for real blocking)\n";
  return true;
#endif
}

// ── run() ─────────────────────────────────────────────────────
void NfqCapture::run() {
  running_ = true;
#ifdef HAVE_NFQUEUE
  if (nfq_mode_) {
    static uint8_t buf[4096] __attribute__((aligned));
    while (running_) {
      int rv = recv(fd_, buf, sizeof(buf), 0);
      if (rv < 0) {
        if (errno == EINTR)
          continue;
        if (!running_)
          break;
        perror("[NFQ] recv");
        break;
      }
      nfq_handle_packet(h_, reinterpret_cast<char *>(buf), rv);
    }
    std::cout << "[Capture] Stopped.\n";
    return;
  }
#endif
  run_raw_fallback();
  std::cout << "[Capture] Stopped.\n";
}

void NfqCapture::stop() { running_ = false; }

// ── NFQ static callback (Linux only) ─────────────────────────
#ifdef HAVE_NFQUEUE
int NfqCapture::nfq_callback(nfq_q_handle *qh, nfgenmsg * /*nfmsg*/,
                             nfq_data *nfa, void *data) {
  auto *self = static_cast<NfqCapture *>(data);
  uint32_t pkt_id = 0;
  nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  if (ph)
    pkt_id = ntohl(ph->packet_id);
  uint8_t *payload = nullptr;
  int len = nfq_get_payload(nfa, &payload);
  if (len < 0 || !payload)
    return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
  self->process_packet(payload, len, pkt_id);
  return 0;
}
#endif

// ── process_packet ────────────────────────────────────────────
void NfqCapture::process_packet(const uint8_t *buf, int len, uint32_t pkt_id) {
  // pkt_id is only used when HAVE_NFQUEUE is defined (Linux kernel verdicts)
#ifndef HAVE_NFQUEUE
  (void)pkt_id;
#endif
  PacketInfo pkt{};
  if (!PacketParser::parse(buf, len, pkt)) {
#ifdef HAVE_NFQUEUE
    if (nfq_mode_ && qh_)
      nfq_set_verdict(qh_, pkt_id, NF_ACCEPT, 0, nullptr);
#endif
    return;
  }

  EvalResult result = engine_.evaluate(pkt);

  // ── Update live stats ──────────────────────────────────────
  stats_.total++;
  stats_.bytes_total += pkt.size;
  if (result.verdict == Action::ALLOW)
    stats_.allowed++;
  else
    stats_.blocked++;
  switch (pkt.proto) {
  case Proto::TCP:
    stats_.tcp++;
    break;
  case Proto::UDP:
    stats_.udp++;
    break;
  case Proto::ICMP:
    stats_.icmp++;
    break;
  default:
    break;
  }

  PacketRecord rec;
  rec.info      = pkt;
  rec.result    = result;
  rec.timestamp = make_timestamp();
  rec.src_ip_str = ip4_to_string(pkt.src_ip);
  rec.dst_ip_str = ip4_to_string(pkt.dst_ip);
  rec.seq       = ++seq_counter_;

  // ── Process attribution (real OS lookup via ProcessMonitor) ──
  if (proc_mon_) {
    // Try src_port first (outbound), then dst_port (inbound service)
    uint16_t probe_port = pkt.src_port ? pkt.src_port : pkt.dst_port;
    rec.process_name    = proc_mon_->process_name_for_port(probe_port);
    rec.pid             = proc_mon_->pid_for_port(probe_port);
    if (rec.process_name.empty() && pkt.dst_port) {
      // Try the destination port too (inbound to a local service)
      rec.process_name = proc_mon_->process_name_for_port(pkt.dst_port);
      rec.pid          = proc_mon_->pid_for_port(pkt.dst_port);
    }
    // Credit bytes to the process
    if (rec.pid)
      proc_mon_->add_bytes(probe_port,
                           static_cast<uint32_t>(pkt.size),
                           /*outbound=*/ (pkt.dir == Direction::OUTBOUND));

    // Override verdict if this application is explicitly blocked
    if (!rec.process_name.empty() && proc_mon_->is_app_blocked(rec.process_name)) {
      result.verdict = Action::BLOCK;
      result.matched_rule = nullptr; // Treat it as an explicit app block, no specific IP/Port rule matched
      rec.result = result;
    }
  }

  ring_.push(rec);

  // ── Stdout logging (Disabled for performance) ────────────────
  // const char *vs = (result.verdict == Action::ALLOW) ? "ALLOW" : "BLOCK";
  // std::cout << rec.timestamp << "  " << vs << "  "
  //           << PacketParser::to_string(pkt);
  // if (result.matched_rule)
  //   std::cout << "  [rule #" << result.matched_rule->id << ": "
  //             << result.matched_rule->description << "]";
  // else
  //   std::cout << "  [default policy]";
  // std::cout << "\n";

#ifdef HAVE_NFQUEUE
  if (nfq_mode_ && qh_) {
    uint32_t kv = (result.verdict == Action::ALLOW) ? NF_ACCEPT : NF_DROP;
    nfq_set_verdict(qh_, pkt_id, kv, 0, nullptr);
  }
#endif
}

// ── Raw socket fallback loop ──────────────────────────────────
void NfqCapture::run_raw_fallback() {
#ifdef _WIN32
  // Windows: single promiscuous socket
  static uint8_t buf[BUFSIZE];
  while (running_) {
    int len = recv(tcp_sock_, reinterpret_cast<char *>(buf), sizeof(buf), 0);
    if (len <= 0) {
      int err = last_net_error();
      if (err == WSAEINTR || err == WSAEWOULDBLOCK)
        continue;
      if (!running_)
        break;
      std::cerr << "[Capture] recv error " << err << "\n";
      break;
    }
    process_packet(buf, len, 0);
  }
#else
  // Linux: three raw sockets (TCP/UDP/ICMP), select for timeout
  while (running_) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(tcp_sock_, &fds);
    FD_SET(udp_sock_, &fds);
    FD_SET(icmp_sock_, &fds);
    int maxfd = std::max({tcp_sock_, udp_sock_, icmp_sock_});

    struct timeval tv{1, 0};
    int ready = select(maxfd + 1, &fds, nullptr, nullptr, &tv);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      perror("select");
      break;
    }
    if (FD_ISSET(tcp_sock_, &fds))
      receive_one_raw(tcp_sock_);
    if (FD_ISSET(udp_sock_, &fds))
      receive_one_raw(udp_sock_);
    if (FD_ISSET(icmp_sock_, &fds))
      receive_one_raw(icmp_sock_);
  }
#endif
}

void NfqCapture::receive_one_raw(sock_t sock) {
  static thread_local uint8_t buf[BUFSIZE];
  int len = recv(sock, reinterpret_cast<char *>(buf), sizeof(buf), 0);
  if (len <= 0)
    return;
  process_packet(buf, len, 0);
}

// ── Helpers ───────────────────────────────────────────────────
std::string NfqCapture::make_timestamp() {
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;
  std::ostringstream oss;
  oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S") << "."
      << std::setfill('0') << std::setw(3) << ms.count();
  return oss.str();
}

} // namespace fw
