#include "capture.hpp"
#include "packet.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sys/select.h>

// ──────────────────────────────────────────────────────────────
//  capture.cpp
//
//  Opens three raw sockets (TCP, UDP, ICMP) so all common
//  IP traffic is captured.  Uses select() with a 1-second
//  timeout to allow clean shutdown via stop().
// ──────────────────────────────────────────────────────────────

namespace fw {

static constexpr int BUFSIZE = 65535;

Capture::Capture() = default;

Capture::~Capture() {
    if (tcp_sock_  >= 0) close(tcp_sock_);
    if (udp_sock_  >= 0) close(udp_sock_);
    if (icmp_sock_ >= 0) close(icmp_sock_);
}

bool Capture::open() {
    tcp_sock_  = open_raw_socket(IPPROTO_TCP);
    udp_sock_  = open_raw_socket(IPPROTO_UDP);
    icmp_sock_ = open_raw_socket(IPPROTO_ICMP);

    if (tcp_sock_ < 0 || udp_sock_ < 0 || icmp_sock_ < 0) {
        std::cerr << "[Capture] Failed to open raw sockets. "
                     "Are you running as root?\n";
        return false;
    }
    return true;
}

void Capture::run(PacketCallback cb) {
    running_ = true;

    while (running_) {
        // Build fd_set from our three sockets
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(tcp_sock_,  &fds);
        FD_SET(udp_sock_,  &fds);
        FD_SET(icmp_sock_, &fds);
        int maxfd = std::max({tcp_sock_, udp_sock_, icmp_sock_});

        // 1-second timeout so we can check running_ periodically
        struct timeval tv{ 1, 0 };
        int ready = select(maxfd + 1, &fds, nullptr, nullptr, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;  // signal interrupt, retry
            perror("select");
            break;
        }

        if (FD_ISSET(tcp_sock_,  &fds)) receive_one(tcp_sock_,  cb);
        if (FD_ISSET(udp_sock_,  &fds)) receive_one(udp_sock_,  cb);
        if (FD_ISSET(icmp_sock_, &fds)) receive_one(icmp_sock_, cb);
    }

    std::cout << "[Capture] Stopped.\n";
}

void Capture::stop() {
    running_ = false;
}

// ── Private ──────────────────────────────────────────────────

int Capture::open_raw_socket(int protocol) {
    int s = socket(AF_INET, SOCK_RAW, protocol);
    if (s < 0) {
        std::cerr << "[Capture] socket(" << protocol << ") error: "
                  << strerror(errno) << "\n";
    }
    return s;
}

void Capture::receive_one(int sock, PacketCallback& cb) {
    static thread_local uint8_t buf[BUFSIZE];
    int len = recv(sock, buf, sizeof(buf), 0);
    if (len < 0) return;

    PacketInfo pkt{};
    if (PacketParser::parse(buf, len, pkt)) {
        cb(pkt);
    }
}

} // namespace fw