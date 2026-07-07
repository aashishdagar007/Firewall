#include <iostream>
#include <chrono>
#include <vector>
#include "rule_engine.hpp"

using namespace fw;

uint32_t make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

int main() {
    std::cout << "=======================================\n";
    std::cout << " Firewall RuleEngine Benchmark\n";
    std::cout << "=======================================\n";

    RuleEngine engine(Action::ALLOW);
    
    // Add some complex rules to force rule evaluation
    for (int i = 0; i < 50; ++i) {
        Rule r;
        r.action = Action::BLOCK;
        r.proto = Proto::TCP;
        r.src_ip = make_ip(10, 0, 0, i);
        r.src_ip_mask = 0xFFFFFFFF;
        r.dst_port_start = 8000 + i;
        r.dst_port_end = 8000 + i;
        engine.add_rule(r);
    }

    const int PACKET_COUNT = 1000000;
    std::vector<PacketInfo> packets(PACKET_COUNT);

    // Pre-generate packets to exclude generation time from the benchmark
    for (int i = 0; i < PACKET_COUNT; ++i) {
        packets[i].proto = Proto::TCP;
        packets[i].src_ip = make_ip(192, 168, 1, i % 255);
        packets[i].dst_ip = make_ip(8, 8, 8, 8);
        packets[i].src_port = 10000 + (i % 50000); // Many different connections
        packets[i].dst_port = 80;
        packets[i].tcp_flags = TCP_ACK;
        packets[i].size = 64; // Bypass 0-size traffic shaper drops
        // Randomly set SYN to create new states, but mostly ACK to hit cache/state tracking
        if (i % 100 == 0) {
            packets[i].tcp_flags = TCP_SYN;
        }
    }

    std::cout << "Starting benchmark with " << PACKET_COUNT << " packets...\n";

    auto start_time = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < PACKET_COUNT; ++i) {
        engine.evaluate(packets[i]);
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = end_time - start_time;

    double pps = PACKET_COUNT / diff.count();

    std::cout << "\nResults:\n";
    std::cout << "Total Time: " << diff.count() << " seconds\n";
    std::cout << "Throughput: " << (long long)pps << " packets/second\n";
    std::cout << "Latency:    " << (diff.count() * 1000000.0 / PACKET_COUNT) << " microseconds/packet\n";
    std::cout << "=======================================\n";

    return 0;
}
