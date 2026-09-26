#include "diode_streamer.hpp"
#include <chrono>
#include <random>

namespace fw {

DiodeStreamer::DiodeStreamer(DiodeThreatEngine& engine)
    : engine_(engine) {}

DiodeStreamer::~DiodeStreamer() {
    stop_stream();
}

void DiodeStreamer::start_stream(int target_pps) {
    if (running_) return;
    running_ = true;
    worker_thread_ = std::thread(&DiodeStreamer::stream_worker, this, target_pps);
}

void DiodeStreamer::stop_stream() {
    if (running_) {
        running_ = false;
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }
}

void DiodeStreamer::trigger_scenario(ThreatClass tc, int count) {
    engine_.inject_simulated_scenario(tc, count);
}

double DiodeStreamer::benchmark(size_t packets) {
    return engine_.run_throughput_benchmark(packets);
}

void DiodeStreamer::stream_worker(int target_pps) {
    std::mt19937 rng(1337);
    std::uniform_int_distribution<uint32_t> ip_dist(0x0A000001, 0x0A00FFFF); // 10.0.x.x
    std::uniform_int_distribution<uint16_t> port_dist(1024, 65530);
    std::uniform_int_distribution<int> size_dist(64, 1460);

    const int interval_us = (target_pps > 0) ? (1000000 / target_pps) : 100;

    // Normal DNS payload for benign stream
    static const uint8_t benign_dns[] = {
        0x56, 0x78, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        6, 'g', 'o', 'o', 'g', 'l', 'e',
        3, 'c', 'o', 'm',
        0x00,
        0x00, 0x01, // QTYPE = A
        0x00, 0x01
    };

    while (running_) {
        auto t0 = std::chrono::steady_clock::now();

        // Generate a benign background packet
        PacketInfo pkt;
        uint32_t r = rng();
        int proto_choice = r % 10;

        if (proto_choice < 7) {
            // TCP HTTPS / HTTP
            pkt.proto = Proto::TCP;
            pkt.src_ip = ip_dist(rng);
            pkt.dst_ip = 0x8EFA4801 + (r % 256); // 142.250.72.x (Google CDN range)
            pkt.src_port = port_dist(rng);
            pkt.dst_port = (r % 2 == 0) ? 443 : 80;
            pkt.tcp_flags = TCP_ACK;
            pkt.size = size_dist(rng);
        } else if (proto_choice < 9) {
            // UDP DNS query
            pkt.proto = Proto::UDP;
            pkt.src_ip = ip_dist(rng);
            pkt.dst_ip = 0x08080808; // 8.8.8.8
            pkt.src_port = port_dist(rng);
            pkt.dst_port = 53;
            pkt.payload_ptr = benign_dns;
            pkt.payload_len = sizeof(benign_dns);
            pkt.size = sizeof(benign_dns) + 28;
        } else {
            // NTP or other benign UDP
            pkt.proto = Proto::UDP;
            pkt.src_ip = ip_dist(rng);
            pkt.dst_ip = 0xD8EF2301 + (r % 256);
            pkt.src_port = port_dist(rng);
            pkt.dst_port = 123;
            pkt.size = 76;
        }

        engine_.process_packet(pkt);

        if (interval_us > 200) {
            auto t1 = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
            if (interval_us > elapsed) {
                std::this_thread::sleep_for(std::chrono::microseconds(interval_us - elapsed));
            }
        }
    }
}

} // namespace fw
