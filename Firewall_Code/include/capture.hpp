#pragma once
#include "types.hpp"
#include <functional>
#include <atomic>

// ──────────────────────────────────────────────────────────────
//  capture.hpp  –  raw-socket packet capture loop
//
//  Opens AF_INET / SOCK_RAW sockets for TCP, UDP, and ICMP,
//  reads packets in a loop, parses each one via PacketParser,
//  and dispatches the result to a user-supplied callback.
// ──────────────────────────────────────────────────────────────

namespace fw {

    // Callback signature: (parsed packet) → void
    using PacketCallback = std::function<void(const PacketInfo&)>;

    class Capture {
    public:
        Capture();
        ~Capture();

        // Open raw sockets. Returns false on failure (need root).
        bool open();

        // Block and dispatch packets to cb until stop() is called.
        void run(PacketCallback cb);

        // Signal the run() loop to exit cleanly (safe from signal handler).
        void stop();

        bool is_open() const { return tcp_sock_ >= 0; }

    private:
        int tcp_sock_  = -1;
        int udp_sock_  = -1;
        int icmp_sock_ = -1;

        std::atomic<bool> running_{false};

        static int open_raw_socket(int protocol);
        void receive_one(int sock, PacketCallback& cb);
    };

} // namespace fw