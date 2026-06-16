#include "rule_engine.hpp"
#include "packet.hpp"
#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>

using namespace fw;

// Dummy IPv4 helper for tests
uint32_t make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

void test_default_policy() {
    RuleEngine engine(Action::BLOCK); // Default BLOCK
    
    PacketInfo pkt;
    pkt.proto = Proto::TCP;
    pkt.src_ip = make_ip(198, 51, 100, 55);
    pkt.dst_ip = make_ip(8, 8, 8, 8);
    pkt.src_port = 50000;
    pkt.dst_port = 80;
    pkt.tcp_flags = TCP_SYN;
    pkt.dir = Direction::OUTBOUND;
    pkt.ttl = 64;

    EvalResult result = engine.evaluate(pkt);
    assert(result.verdict == Action::BLOCK && "Default policy should drop unallowed packet");
    std::cout << "[PASS] Default policy blocking\n";
}

void test_process_name_matching() {
    RuleEngine engine(Action::ALLOW);
    
    Rule r;
    r.action = Action::BLOCK;
    r.proto = Proto::ANY;
    r.process_name = "BitTorrent.exe";
    r.description = "Block torrents";
    engine.add_rule(r);
    
    PacketInfo pkt;
    pkt.proto = Proto::TCP;
    pkt.src_ip = make_ip(198, 51, 100, 55);
    pkt.dst_ip = make_ip(8, 8, 8, 8);
    pkt.src_port = 5555;
    pkt.dst_port = 80;
    pkt.tcp_flags = TCP_SYN;
    pkt.ttl = 64;
    pkt.process_name = "BitTorrent.exe";
    
    EvalResult result = engine.evaluate(pkt);
    assert(result.verdict == Action::BLOCK && "Should block BitTorrent.exe by name");
    
    pkt.process_name = "chrome.exe";
    result = engine.evaluate(pkt);
    assert(result.verdict == Action::ALLOW && "Should allow chrome.exe");
    
    std::cout << "[PASS] Process Name matching\n";
}

void test_syn_flood_detection() {
    RuleEngine engine(Action::ALLOW);
    
    PacketInfo pkt;
    pkt.proto = Proto::TCP;
    pkt.src_ip = make_ip(203, 0, 113, 5); // Some external IP
    pkt.dst_ip = make_ip(198, 51, 100, 10);
    pkt.dst_port = 80;
    pkt.tcp_flags = TCP_SYN;
    pkt.dir = Direction::INBOUND;
    pkt.ttl = 64;
    
    // Send 25 SYNs from same source within 1 second to trigger SYN flood auto-ban (threshold is >20)
    for (int i = 0; i < 21; ++i) {
        pkt.src_port = 10000 + i;
        EvalResult res = engine.evaluate(pkt);
        if (i == 20) {
            assert(res.verdict == Action::BLOCK && "21st SYN should be blocked by SYN flood guard");
        } else {
            assert(res.verdict == Action::ALLOW && "Initial SYNs should be allowed");
        }
    }
    std::cout << "[PASS] SYN Flood detection\n";
}

void test_dpi_sql_injection() {
    RuleEngine engine(Action::ALLOW);
    
    PacketInfo pkt;
    pkt.proto = Proto::TCP;
    pkt.src_ip = make_ip(203, 0, 113, 5); 
    pkt.dst_ip = make_ip(198, 51, 100, 10);
    pkt.dst_port = 80;
    pkt.tcp_flags = TCP_PSH | TCP_ACK;
    pkt.dir = Direction::INBOUND;
    
    // Simulate a payload with SQL injection
    std::string malicious_payload = "GET /login?user=admin' OR 1=1;-- HTTP/1.1\r\n";
    pkt.payload_ptr = reinterpret_cast<const uint8_t*>(malicious_payload.data());
    pkt.payload_len = malicious_payload.length();
    
    EvalResult res = engine.evaluate(pkt);
    assert(res.verdict == Action::BLOCK && "DPI should block 'OR 1=1' payload");
    std::cout << "[PASS] DPI SQL Injection Block\n";
}

void test_strict_anomalies() {
    RuleEngine engine(Action::ALLOW);
    
    PacketInfo pkt;
    pkt.proto = Proto::TCP;
    pkt.src_ip = make_ip(203, 0, 113, 5);
    pkt.dst_ip = make_ip(198, 51, 100, 10);
    pkt.src_port = 50000;
    pkt.dst_port = 80;
    pkt.dir = Direction::INBOUND;
    pkt.ttl = 64;

    // 1. TCP NULL Scan
    pkt.tcp_flags = 0;
    EvalResult res = engine.evaluate(pkt);
    assert(res.verdict == Action::BLOCK && "TCP NULL scan should be blocked");

    // 2. TCP XMAS Scan
    pkt.tcp_flags = TCP_FIN | TCP_URG | TCP_PSH;
    res = engine.evaluate(pkt);
    assert(res.verdict == Action::BLOCK && "TCP XMAS scan should be blocked");

    // 3. TCP SYN-FIN Anomaly
    pkt.tcp_flags = TCP_SYN | TCP_FIN;
    res = engine.evaluate(pkt);
    assert(res.verdict == Action::BLOCK && "TCP SYN-FIN should be blocked");

    // 4. TCP SYN with payload
    pkt.tcp_flags = TCP_SYN;
    pkt.payload_len = 100; // SYN should not have payload
    res = engine.evaluate(pkt);
    assert(res.verdict == Action::BLOCK && "TCP SYN with data should be blocked");
    pkt.payload_len = 0; // Reset

    // 5. Port 0 Traffic
    pkt.tcp_flags = TCP_SYN;
    pkt.src_port = 0;
    res = engine.evaluate(pkt);
    assert(res.verdict == Action::BLOCK && "Traffic from Port 0 should be blocked");
    
    std::cout << "[PASS] Strict Protocol Anomalies\n";
}

int main() {
    std::cout << "Running RuleEngine Tests...\n";
    test_default_policy();
    test_process_name_matching();
    test_syn_flood_detection();
    test_dpi_sql_injection();
    test_strict_anomalies();
    std::cout << "All tests passed successfully.\n";
    return 0;
}
