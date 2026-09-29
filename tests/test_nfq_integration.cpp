#include "engine/rule_engine.hpp"
#include "net/nfq_capture.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>

namespace {

struct Listener {
    int fd = -1;
    uint16_t port = 0;
};

Listener make_listener() {
    Listener listener;
    listener.fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listener.fd < 0) return listener;

    int reuse = 1;
    ::setsockopt(listener.fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(listener.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 ||
        ::listen(listener.fd, 8) < 0) {
        ::close(listener.fd);
        listener.fd = -1;
        return listener;
    }

    socklen_t address_len = sizeof(address);
    if (::getsockname(listener.fd, reinterpret_cast<sockaddr*>(&address), &address_len) < 0) {
        ::close(listener.fd);
        listener.fd = -1;
        return listener;
    }
    listener.port = ntohs(address.sin_port);
    return listener;
}

bool connect_with_timeout(uint16_t port, int timeout_ms) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;

    const int old_flags = ::fcntl(fd, F_GETFL, 0);
    if (old_flags < 0 || ::fcntl(fd, F_SETFL, old_flags | O_NONBLOCK) < 0) {
        ::close(fd);
        return false;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    const int connect_result = ::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (connect_result == 0) {
        ::close(fd);
        return true;
    }
    if (errno != EINPROGRESS) {
        ::close(fd);
        return false;
    }

    pollfd event{fd, POLLOUT, 0};
    const int poll_result = ::poll(&event, 1, timeout_ms);
    bool connected = false;
    if (poll_result > 0) {
        int socket_error = 0;
        socklen_t error_len = sizeof(socket_error);
        connected = ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) == 0 &&
                    socket_error == 0;
    }
    ::close(fd);
    return connected;
}

bool wait_until_ready(fw::LiveStats& stats) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        if (stats.enforcement_ready.load()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

} // namespace

int main() {
    if (::geteuid() != 0) {
        std::cerr << "NFQUEUE integration test must run as root\n";
        return 2;
    }

    Listener allowed_listener = make_listener();
    Listener blocked_listener = make_listener();
    if (allowed_listener.fd < 0 || blocked_listener.fd < 0) {
        std::cerr << "Could not create loopback test listeners\n";
        if (allowed_listener.fd >= 0) ::close(allowed_listener.fd);
        if (blocked_listener.fd >= 0) ::close(blocked_listener.fd);
        return 2;
    }

    fw::RuleEngine engine(fw::Action::ALLOW);
    fw::Rule block_port;
    block_port.action = fw::Action::BLOCK;
    block_port.proto = fw::Proto::TCP;
    block_port.dst_port_start = blocked_listener.port;
    block_port.dst_port_end = blocked_listener.port;
    block_port.description = "NFQUEUE integration blocked port";
    engine.add_rule(std::move(block_port));

    fw::LiveStats stats;
    fw::RingBuffer<fw::PacketRecord> ring(256);
    fw::NfqCapture capture(engine, stats, ring);
    if (!capture.open() || !capture.is_nfq_mode()) {
        std::cerr << "NFQUEUE capture did not enter enforcing mode\n";
        ::close(allowed_listener.fd);
        ::close(blocked_listener.fd);
        return 2;
    }

    std::thread capture_thread([&capture] { capture.run(); });
    if (!wait_until_ready(stats)) {
        std::cerr << "NFQUEUE capture never reported enforcement ready\n";
        capture.stop();
        capture_thread.join();
        ::close(allowed_listener.fd);
        ::close(blocked_listener.fd);
        return 2;
    }

    const bool allowed_connected = connect_with_timeout(allowed_listener.port, 2000);
    if (allowed_connected) {
        pollfd event{allowed_listener.fd, POLLIN, 0};
        if (::poll(&event, 1, 1000) > 0) {
            const int accepted = ::accept(allowed_listener.fd, nullptr, nullptr);
            if (accepted >= 0) ::close(accepted);
        }
    }

    const bool blocked_connected = connect_with_timeout(blocked_listener.port, 350);
    capture.stop();
    capture_thread.join();
    ::close(allowed_listener.fd);
    ::close(blocked_listener.fd);

    if (!allowed_connected) {
        std::cerr << "Default-ALLOW TCP traffic did not pass through NFQUEUE\n";
        return 1;
    }
    if (blocked_connected) {
        std::cerr << "Configured BLOCK TCP traffic passed through NFQUEUE\n";
        return 1;
    }
    if (stats.allowed.load() == 0 || stats.blocked.load() == 0) {
        std::cerr << "NFQUEUE verdict counters did not record both ALLOW and BLOCK\n";
        return 1;
    }
    bool block_rule_matched = false;
    for (const auto& rule : engine.rules()) {
        if (rule.description == "NFQUEUE integration blocked port" &&
            rule.hit_count.load() > 0) {
            block_rule_matched = true;
            break;
        }
    }
    if (!block_rule_matched) {
        std::cerr << "Configured BLOCK rule did not match a captured packet\n";
        return 1;
    }

    std::cout << "NFQUEUE loopback integration passed: allow=" << stats.allowed.load()
              << " block=" << stats.blocked.load() << "\n";
    return 0;
}
