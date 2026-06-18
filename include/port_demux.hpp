#pragma once
// ──────────────────────────────────────────────────────────────
//  port_demux.hpp  –  DPI Port Demultiplexer
//
//  AEGIS XII Pillar 1: The Kernel Interceptor
//
//  Intercepts every UDP packet on a configured set of "shared"
//  ports.  Inspects the first 8 bytes for BVUDP_MAGIC.
//
//  Routing decision (zero-copy, sub-microsecond):
//    ┌─ BVUDP magic detected ──▶ strip from OS stack,
//    │                            feed to BVUDPReceiver
//    └─ Standard traffic     ──▶ reinject into OS (zero latency)
//
//  On Windows:
//    Requires WinDivert (WINDIVERT_DIR set in CMake).
//    Falls back to observer-only mode if WinDivert not found.
//
//  On Linux:
//    Uses raw socket + iptables NFQUEUE; BVUDPReceiver listens
//    on its own UDP socket independently.
// ──────────────────────────────────────────────────────────────

#include "platform.hpp"
#include "bvudp.hpp"

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

// WinDivert integration (optional, compile-time)
#ifdef HAVE_WINDIVERT
#include <windivert.h>
#endif

namespace fw {

// ─────────────────────────────────────────────────────────────
//  DemuxStats  –  real-time counters visible on dashboard
// ─────────────────────────────────────────────────────────────
struct DemuxStats {
    std::atomic<uint64_t> total_inspected{0};   // all packets seen on mux port
    std::atomic<uint64_t> bvudp_pulled{0};      // BVUDP packets extracted
    std::atomic<uint64_t> http_reinjected{0};   // standard traffic reinjected
    std::atomic<uint64_t> batches_verified{0};  // fully verified BVUDP batches
    std::atomic<uint64_t> batches_rejected{0};  // hash-failed batches
};

// ─────────────────────────────────────────────────────────────
//  PortDemux  –  the actual interceptor
// ─────────────────────────────────────────────────────────────
class PortDemux {
public:
    // mux_ports: which UDP ports to intercept and demultiplex
    // bvudp_rx:  BVUDP receiver that handles extracted packets
    explicit PortDemux(std::vector<uint16_t> mux_ports,
                       BVUDPReceiver&         bvudp_rx)
        : mux_ports_(std::move(mux_ports)),
          bvudp_rx_(bvudp_rx),
          running_(false)
    {}

    ~PortDemux() { stop(); }

    bool start() {
        if (running_) return true;
#ifdef HAVE_WINDIVERT
        return start_windivert();
#else
        // Observer mode: BVUDPReceiver listens on its own port directly
        // No OS-level interception without WinDivert
        observer_mode_ = true;
        running_ = true;
        return true;
#endif
    }

    void stop() {
        running_ = false;
#ifdef HAVE_WINDIVERT
        if (divert_handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(divert_handle_);
            divert_handle_ = INVALID_HANDLE_VALUE;
        }
#endif
        if (thread_.joinable()) thread_.join();
    }

    bool is_observer_mode() const { return observer_mode_; }
    const DemuxStats& stats() const { return stats_; }

    // Inspect a raw IP packet (called from NfqCapture on observer path)
    // Returns true if the packet was consumed by BVUDP (should not be
    // processed further by the standard firewall pipeline).
    bool inspect_and_route(const uint8_t* ip_packet, int len) {
        if (!is_udp_on_mux_port(ip_packet, len)) return false;

        // Locate UDP payload start
        int ip_hdr_len = (ip_packet[0] & 0x0F) * 4;
        if (len < ip_hdr_len + 8) return false;  // too short for UDP header
        const uint8_t* udp_payload = ip_packet + ip_hdr_len + 8; // UDP hdr = 8 bytes
        int  udp_payload_len = len - ip_hdr_len - 8;

        stats_.total_inspected++;

        if (BVUDPReceiver::is_bvudp(udp_payload, udp_payload_len)) {
            // ── BVUDP path ────────────────────────────────────
            stats_.bvudp_pulled++;

            // Reconstruct sender address from IP header
            sockaddr_in sender{};
            sender.sin_family = AF_INET;
            // Source IP at offset 12, src port at ip_hdr_len
            std::memcpy(&sender.sin_addr.s_addr, ip_packet + 12, 4);
            uint16_t src_port;
            std::memcpy(&src_port, ip_packet + ip_hdr_len, 2);
            sender.sin_port = src_port; // already network byte order
            bvudp_rx_.feed(udp_payload, udp_payload_len, sender);
            return true; // consumed — do NOT pass to standard firewall
        }

        // Standard traffic — reinject (on WinDivert) or just let through
        stats_.http_reinjected++;
        return false; // not consumed
    }

    // Build the WinDivert filter string for the configured ports
    std::string build_filter() const {
        if (mux_ports_.empty()) return "false";
        std::string f = "(udp.DstPort == ";
        f += std::to_string(mux_ports_[0]);
        for (size_t i = 1; i < mux_ports_.size(); ++i) {
            f += " or udp.DstPort == ";
            f += std::to_string(mux_ports_[i]);
        }
        f += ")";
        return f;
    }

private:
    std::vector<uint16_t>  mux_ports_;
    BVUDPReceiver&         bvudp_rx_;
    std::atomic<bool>      running_;
    bool                   observer_mode_ = false;
    std::thread            thread_;
    DemuxStats             stats_;

#ifdef HAVE_WINDIVERT
    HANDLE divert_handle_ = INVALID_HANDLE_VALUE;

    bool start_windivert() {
        std::string filter = build_filter();
        divert_handle_ = WinDivertOpen(filter.c_str(),
                                       WINDIVERT_LAYER_NETWORK, 0, 0);
        if (divert_handle_ == INVALID_HANDLE_VALUE) {
            observer_mode_ = true;
            running_ = true;
            return true; // graceful fallback
        }
        running_ = true;
        thread_ = std::thread([this]{ divert_loop(); });
        return true;
    }

    void divert_loop() {
        static constexpr UINT BUFSIZE = 65535;
        // Zero-allocation hot path: pre-allocated thread-local array
        thread_local std::array<uint8_t, BUFSIZE> buf;
        WINDIVERT_ADDRESS    addr;
        UINT                 recv_len = 0;

        while (running_) {
            if (!WinDivertRecv(divert_handle_,
                               reinterpret_cast<PVOID>(buf.data()),
                               BUFSIZE, &recv_len, &addr)) {
                // Graceful shutdown: WinDivertClose in stop() aborts this blocking call
                if (!running_) break;
                continue;
            }

            bool consumed = inspect_and_route(buf.data(),
                                              static_cast<int>(recv_len));
            if (!consumed) {
                // Reinject — standard OS stack handles it
                WinDivertSend(divert_handle_,
                              reinterpret_cast<PVOID>(buf.data()),
                              recv_len, nullptr, &addr);
            }
        }
    }
#endif // HAVE_WINDIVERT

    // Check if a raw IP packet is UDP and targets one of our mux ports
    bool is_udp_on_mux_port(const uint8_t* ip, int len) const {
        if (len < 20) return false;
        if ((ip[0] >> 4) != 4) return false;   // IPv4 only
        if (ip[9] != 17) return false;          // proto = UDP

        int ip_hdr = (ip[0] & 0x0F) * 4;
        if (len < ip_hdr + 8) return false;
        uint16_t dst_port = (static_cast<uint16_t>(ip[ip_hdr + 2]) << 8) |
                             ip[ip_hdr + 3];

        for (uint16_t p : mux_ports_)
            if (dst_port == p) return true;
        return false;
    }
};

} // namespace fw
