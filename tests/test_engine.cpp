#include "rule_engine.hpp"
#include "packet.hpp"
#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>
#include <array>

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

void test_rule_result_survives_rule_removal() {
    RuleEngine engine(Action::ALLOW);
    Rule rule;
    rule.action = Action::BLOCK;
    rule.proto = Proto::TCP;
    rule.dst_port = 443;
    rule.description = "Block HTTPS";
    engine.add_rule(rule);

    PacketInfo pkt;
    pkt.proto = Proto::TCP;
    pkt.src_ip = make_ip(198, 51, 100, 7);
    pkt.dst_ip = make_ip(203, 0, 113, 9);
    pkt.src_port = 50000;
    pkt.dst_port = 443;
    pkt.tcp_flags = TCP_SYN;
    pkt.ttl = 64;
    const auto result = engine.evaluate(pkt);
    assert(result.verdict == Action::BLOCK && result.matched_rule);
    const auto id = result.matched_rule->id;
    assert(engine.remove_rule(id));
    assert(result.matched_rule->description == "Block HTTPS");
}

void test_icmp_sweep_counts_distinct_destinations() {
    PortScanDetector detector;
    bool callback_can_read_events = false;
    detector.set_callback([&](ScanEvent) {
        callback_can_read_events = !detector.get_recent_events().empty();
    });
    PacketInfo pkt;
    pkt.proto = Proto::ICMP;
    pkt.src_ip = make_ip(198, 51, 100, 7);
    pkt.icmp_type = 8;
    // Repeated pings to one host are not a sweep.
    pkt.dst_ip = make_ip(203, 0, 113, 1);
    for (unsigned i = 0; i < 40; ++i)
        assert(!detector.record(pkt));
    // A sweep is based on distinct destination hosts in the time window.
    std::optional<ScanEvent> event;
    for (unsigned i = 2; i <= PortScanDetector::PORT_THRESHOLD + 1; ++i) {
        pkt.dst_ip = make_ip(203, 0, 113, static_cast<uint8_t>(i));
        event = detector.record(pkt);
    }
    assert(event && event->scan_type == ScanType::ICMP_SWEEP);
    assert(event->ports_probed == PortScanDetector::PORT_THRESHOLD + 1);
    assert(callback_can_read_events);
}

void test_blocked_packets_still_feed_scan_detection() {
    RuleEngine engine(Action::BLOCK);
    bool callback_read_succeeded = false;
    engine.set_scan_callback([&](ScanEvent) {
        callback_read_succeeded = !engine.get_scan_events().empty();
    });
    PacketInfo pkt;
    pkt.proto = Proto::TCP;
    pkt.src_ip = make_ip(198, 51, 100, 7);
    pkt.dst_ip = make_ip(203, 0, 113, 9);
    pkt.src_port = 50000;
    pkt.ttl = 64;
    pkt.tcp_flags = 0; // Every probe is rejected by the NULL-scan rule.
    for (unsigned port = 1; port <= PortScanDetector::PORT_THRESHOLD + 1; ++port) {
        pkt.dst_port = static_cast<uint16_t>(port);
        assert(engine.evaluate(pkt).verdict == Action::BLOCK);
    }
    const auto events = engine.get_scan_events();
    assert(events.size() == 1 && events.front().scan_type == ScanType::STEALTH_PROBE);
    assert(callback_read_succeeded);
}

void test_packet_parser_bounds_and_udp_lengths() {
    std::array<uint8_t, 36> packet{};
    packet[0] = 0x45; // IPv4, 20-byte header
    packet[2] = 0;
    packet[3] = 28; // IP length: 20-byte header + 8-byte UDP header
    packet[8] = 64;
    packet[9] = 17; // UDP
    packet[12] = 198; packet[13] = 51; packet[14] = 100; packet[15] = 1;
    packet[16] = 203; packet[17] = 0; packet[18] = 113; packet[19] = 2;
    packet[20] = 0xC3; packet[21] = 0x50; // source port 50000
    packet[22] = 0; packet[23] = 53;      // destination port 53
    packet[24] = 0; packet[25] = 8;       // UDP length

    PacketInfo parsed;
    parsed.src_port = 1234; // parser must reset reused output on failure
    assert(PacketParser::parse(packet.data(), 36, parsed)); // trailing padding ignored
    assert(parsed.size == 28 && parsed.src_port == 50000 && parsed.dst_port == 53);
    assert(parsed.payload_len == 0);

    assert(!PacketParser::parse(packet.data(), 27, parsed)); // truncated IP packet
    assert(parsed.src_port == 0 && parsed.proto == Proto::ANY);

    packet[3] = 28;
    packet[25] = 7; // UDP length smaller than UDP header
    assert(!PacketParser::parse(packet.data(), 28, parsed));
    packet[25] = 8;
    packet[0] = 0x65; // IPv6 version with an IPv4 header shape
    assert(!PacketParser::parse(packet.data(), 28, parsed));

    packet[0] = 0x45;
    packet[7] = 1; // Non-initial fragment: payload is not a UDP header.
    assert(PacketParser::parse(packet.data(), 28, parsed));
    assert(parsed.is_frag_offset && parsed.proto == Proto::UDP && parsed.src_port == 0);
}

void test_tls_version_parser_bounds() {
    DpiEngine dpi;
    std::array<uint8_t, 11> hello{};
    hello[0] = 0x16; // TLS handshake record
    hello[1] = 0x03; hello[2] = 0x03;
    hello[4] = 6;    // Record body length
    hello[5] = 1;    // ClientHello
    hello[8] = 2;    // Minimal handshake body length
    hello[9] = 0x03; hello[10] = 0x02; // TLS 1.1

    std::string threat;
    assert(dpi.scan(hello.data(), static_cast<uint16_t>(hello.size()), threat) == Action::BLOCK);
    assert(!threat.empty());
    hello[10] = 0x03; // TLS 1.2
    assert(dpi.scan(hello.data(), static_cast<uint16_t>(hello.size()), threat) == Action::ALLOW);
    assert(threat.empty());
    hello[4] = 5; // Declared record too short for version field
    assert(dpi.scan(hello.data(), static_cast<uint16_t>(hello.size()), threat) == Action::ALLOW);
}

int main() {
    std::cout << "Running RuleEngine Tests...\n";
    test_default_policy();
    test_process_name_matching();
    test_syn_flood_detection();
    test_dpi_sql_injection();
    test_strict_anomalies();
    test_rule_result_survives_rule_removal();
    test_icmp_sweep_counts_distinct_destinations();
    test_blocked_packets_still_feed_scan_detection();
    test_packet_parser_bounds_and_udp_lengths();
    test_tls_version_parser_bounds();
    std::cout << "All tests passed successfully.\n";
    return 0;
}
