#pragma once
#include "platform.hpp"   // sock_t, INVALID_SOCK, etc. — MUST come first
#include "types.hpp"
#include "rule_engine.hpp"
#include "ring_buffer.hpp"
#include "process_monitor.hpp"
#include <functional>
#include <atomic>
#include <string>

// ──────────────────────────────────────────────────────────────
//  nfq_capture.hpp  –  cross-platform packet capture front-end
//
//  Linux  + HAVE_NFQUEUE  → Kernel-level blocking via Netfilter NFQUEUE
//  Linux  (no NFQ)        → Raw socket observer (SOCK_RAW)
//  Windows                → Winsock2 promiscuous socket observer
//                           (needs Administrator; real blocking via WinDivert)
// ──────────────────────────────────────────────────────────────

// Forward-declare NFQ types so the header compiles without the lib
struct nfq_handle;
struct nfq_q_handle;
struct nfgenmsg;
struct nfq_data;

namespace fw {

// ── Extended packet record (stored in the ring buffer) ────────
struct PacketRecord {
    PacketInfo  info;
    EvalResult  result;
    std::string timestamp;
    std::string src_ip_str;
    std::string dst_ip_str;
    uint64_t    seq        = 0;   // global monotonic sequence number
    // Process attribution (filled by ProcessMonitor)
    std::string process_name;     // "chrome.exe"
    std::string process_display;  // "Google Chrome"
    uint32_t    pid        = 0;
};

// ── Live statistics exposed via REST API ─────────────────────
struct LiveStats {
    std::atomic<uint64_t> total      {0};
    std::atomic<uint64_t> allowed    {0};
    std::atomic<uint64_t> blocked    {0};
    std::atomic<uint64_t> tcp        {0};
    std::atomic<uint64_t> udp        {0};
    std::atomic<uint64_t> icmp       {0};
    std::atomic<uint64_t> ipv6       {0}; // IPv6 packets seen (groundwork)
    std::atomic<uint64_t> bytes_total{0};
};

using PacketCallback = std::function<void(const PacketRecord&)>;

class NfqCapture {
public:
    explicit NfqCapture(RuleEngine&        engine,
                        LiveStats&         stats,
                        RingBuffer<PacketRecord>& ring,
                        ProcessMonitor*    proc_mon = nullptr,
                        int                queue_num = 0);
    ~NfqCapture();

    /// Opens the capture handle.
    /// On Linux+NFQ → NFQUEUE; otherwise raw sockets.
    /// Returns false if all modes fail (need elevated privileges).
    bool open();

    /// Blocking capture loop.  Call stop() from another thread to exit.
    void run();
    void stop();

    bool is_nfq_mode() const { return nfq_mode_; }

private:
    RuleEngine&              engine_;
    LiveStats&               stats_;
    RingBuffer<PacketRecord>& ring_;
    ProcessMonitor*          proc_mon_  = nullptr; // optional — may be null
    int                      queue_num_;

    // ── Linux NFQ handles ──────────────────────────────────────
    nfq_handle*   h_   = nullptr;
    nfq_q_handle* qh_  = nullptr;
    int           fd_  = -1;       // nfq_fd(), Linux only

    // ── Shared state ───────────────────────────────────────────
    std::atomic<bool> running_{false};
    bool              nfq_mode_    = false;
    uint64_t          seq_counter_ = 0;

    // ── Raw / promiscuous sockets ──────────────────────────────
    //    Linux: three separate sockets (TCP/UDP/ICMP)
    //    Windows: single SIO_RCVALL socket
    sock_t tcp_sock_  = INVALID_SOCK;
    sock_t udp_sock_  = INVALID_SOCK;
    sock_t icmp_sock_ = INVALID_SOCK;

    // ── Internal helpers ───────────────────────────────────────
    bool open_raw_sockets();

#ifdef HAVE_NFQUEUE
    static int nfq_callback(nfq_q_handle* qh, nfgenmsg* nfmsg,
                             nfq_data* nfa, void* data);
#endif

    void process_packet(const uint8_t* buf, int len, uint32_t pkt_id);
    void run_raw_fallback();
    void receive_one_raw(sock_t sock);

    static std::string make_timestamp();
    // ip4_to_string is now a free function in platform.hpp
};

} // namespace fw
