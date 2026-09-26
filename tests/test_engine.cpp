#include <gtest/gtest.h>
#include "rule_engine.hpp"
#include "packet.hpp"
#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>
#include <array>
#include <atomic>
#include <optional>

using namespace fw;

uint32_t make_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

class RuleEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup can go here
    }

    void TearDown() override {
        // Teardown can go here
    }
};

TEST_F(RuleEngineTest, DefaultPolicyBlocking) {
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
    EXPECT_EQ(result.verdict, Action::BLOCK) << "Default policy should drop unallowed packet";
}

TEST_F(RuleEngineTest, ProcessNameMatching) {
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
    EXPECT_EQ(result.verdict, Action::BLOCK) << "Should block BitTorrent.exe by name";
    
    pkt.process_name = "chrome.exe";
    pkt.src_port = 5556; // Change port to avoid evaluation cache hit
    result = engine.evaluate(pkt);
    EXPECT_EQ(result.verdict, Action::ALLOW) << "Should allow chrome.exe";
}

TEST_F(RuleEngineTest, SynFloodDetection) {
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
            EXPECT_EQ(res.verdict, Action::BLOCK) << "21st SYN should be blocked by SYN flood guard";
        } else {
            EXPECT_EQ(res.verdict, Action::ALLOW) << "Initial SYNs should be allowed";
        }
    }
}

TEST_F(RuleEngineTest, DpiSqlInjection) {
    RuleEngine engine(Action::ALLOW);
    
    PacketInfo pkt;
    pkt.proto = Proto::TCP;
    pkt.src_ip = make_ip(203, 0, 113, 5); 
    pkt.dst_ip = make_ip(198, 51, 100, 10);
    pkt.dst_port = 80;
    pkt.tcp_flags = TCP_PSH | TCP_ACK;
    pkt.dir = Direction::INBOUND;
    
    std::string malicious_payload = "GET /login?user=admin' OR 1=1;-- HTTP/1.1\r\n";
    pkt.payload_ptr = reinterpret_cast<const uint8_t*>(malicious_payload.data());
    pkt.payload_len = malicious_payload.length();
    
    EvalResult res = engine.evaluate(pkt);
    EXPECT_EQ(res.verdict, Action::BLOCK) << "DPI should block 'OR 1=1' payload";
}

TEST_F(RuleEngineTest, StrictAnomalies) {
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
    EXPECT_EQ(res.verdict, Action::BLOCK) << "TCP NULL scan should be blocked";

    // 2. TCP XMAS Scan
    pkt.tcp_flags = TCP_FIN | TCP_URG | TCP_PSH;
    res = engine.evaluate(pkt);
    EXPECT_EQ(res.verdict, Action::BLOCK) << "TCP XMAS scan should be blocked";

    // 3. TCP SYN-FIN Anomaly
    pkt.tcp_flags = TCP_SYN | TCP_FIN;
    res = engine.evaluate(pkt);
    EXPECT_EQ(res.verdict, Action::BLOCK) << "TCP SYN-FIN should be blocked";

    // 4. TCP SYN with payload
    pkt.tcp_flags = TCP_SYN;
    pkt.payload_len = 100; // SYN should not have payload
    res = engine.evaluate(pkt);
    EXPECT_EQ(res.verdict, Action::BLOCK) << "TCP SYN with data should be blocked";
    pkt.payload_len = 0; // Reset

    // 5. Port 0 Traffic
    pkt.tcp_flags = TCP_SYN;
    pkt.src_port = 0;
    res = engine.evaluate(pkt);
    EXPECT_EQ(res.verdict, Action::BLOCK) << "Traffic from Port 0 should be blocked";
    
    std::cout << "[PASS] Strict Protocol Anomalies\n";
}

TEST_F(RuleEngineTest, RuleResultSurvivesRuleRemoval) {
    RuleEngine engine(Action::ALLOW);
    Rule rule;
    rule.action = Action::BLOCK;
    rule.proto = Proto::TCP;
    rule.dst_port_start = 443;
    rule.dst_port_end = 443;
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
    ASSERT_EQ(result.verdict, Action::BLOCK);
    ASSERT_TRUE(result.matched_rule);
    ASSERT_TRUE(result.has_matched_rule());
    const auto id = result.matched_rule->id;
    EXPECT_EQ(result.matched_rule_id, id);
    EXPECT_EQ(result.matched_rule_desc, "Block HTTPS");
    EXPECT_TRUE(engine.remove_rule(id));
    EXPECT_EQ(result.matched_rule->description, "Block HTTPS");
}

TEST_F(RuleEngineTest, CidrAndPortRangeRulesMatchTheirFullRanges) {
    RuleEngine engine(Action::ALLOW);
    Rule rule;
    rule.action = Action::BLOCK;
    rule.proto = Proto::TCP;
    rule.src_ip = make_ip(198, 51, 100, 0);
    rule.src_ip_mask = 0xFFFFFF00;
    rule.dst_port_start = 8080;
    rule.dst_port_end = 8090;
    rule.description = "CIDR and port-range block";
    engine.add_rule(rule);

    PacketInfo pkt;
    pkt.proto = Proto::TCP;
    pkt.src_ip = make_ip(198, 51, 100, 42);
    pkt.dst_ip = make_ip(203, 0, 113, 9);
    pkt.src_port = 50000;
    pkt.dst_port = 8085;
    pkt.tcp_flags = TCP_SYN;
    pkt.ttl = 64;
    EXPECT_EQ(engine.evaluate(pkt).verdict, Action::BLOCK);

    pkt.dst_port = 8091;
    EXPECT_EQ(engine.evaluate(pkt).verdict, Action::ALLOW);
    pkt.dst_port = 8085;
    pkt.src_ip = make_ip(198, 51, 101, 42);
    EXPECT_EQ(engine.evaluate(pkt).verdict, Action::ALLOW);
}

TEST_F(RuleEngineTest, BuiltInAnomalyRuleIsReportedDespiteZeroId) {
    RuleEngine engine(Action::ALLOW);
    PacketInfo pkt;
    pkt.proto = Proto::TCP;
    pkt.src_ip = make_ip(198, 51, 100, 7);
    pkt.dst_ip = pkt.src_ip;
    pkt.src_port = 50000;
    pkt.dst_port = 443;
    pkt.tcp_flags = TCP_SYN;
    pkt.ttl = 64;

    const auto result = engine.evaluate(pkt);
    EXPECT_EQ(result.verdict, Action::BLOCK);
    EXPECT_TRUE(result.has_matched_rule());
    EXPECT_EQ(result.matched_rule_id, 0u);
    EXPECT_FALSE(result.matched_rule_desc.empty());
}

TEST_F(RuleEngineTest, ConcurrentRuleUpdatesAndEvaluation) {
    RuleEngine engine(Action::ALLOW);
    PacketInfo pkt;
    pkt.proto = Proto::TCP;
    pkt.src_ip = make_ip(198, 51, 100, 7);
    pkt.dst_ip = make_ip(203, 0, 113, 9);
    pkt.src_port = 50000;
    pkt.dst_port = 8443;
    pkt.tcp_flags = TCP_SYN;
    pkt.ttl = 64;

    std::atomic<bool> start{false};
    std::atomic<unsigned> evaluations{0};
    std::thread evaluator([&] {
        while (!start.load(std::memory_order_acquire)) {}
        for (unsigned i = 0; i < 3000; ++i) {
            const auto result = engine.evaluate(pkt);
            EXPECT_TRUE(result.verdict == Action::ALLOW || result.verdict == Action::BLOCK);
            ++evaluations;
        }
    });
    std::thread mutator([&] {
        start.store(true, std::memory_order_release);
        for (unsigned i = 0; i < 300; ++i) {
            Rule rule;
            rule.action = Action::BLOCK;
            rule.proto = Proto::TCP;
            rule.dst_port_start = 8443;
            rule.dst_port_end = 8443;
            rule.description = "concurrent-index-rule";
            engine.add_rule(std::move(rule));
            for (const auto& current : engine.rules()) {
                if (current.description == "concurrent-index-rule")
                    engine.remove_rule(current.id);
            }
        }
    });
    evaluator.join();
    mutator.join();
    EXPECT_EQ(evaluations.load(), 3000u);
}

TEST_F(RuleEngineTest, IcmpSweepCountsDistinctDestinationsAndCallsBackUnlocked) {
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
        EXPECT_FALSE(detector.record(pkt));
    // A sweep is based on distinct destination hosts in the time window.
    std::optional<ScanEvent> event;
    for (unsigned i = 2; i <= PortScanDetector::PORT_THRESHOLD + 1; ++i) {
        pkt.dst_ip = make_ip(203, 0, 113, static_cast<uint8_t>(i));
        event = detector.record(pkt);
    }
    ASSERT_TRUE(event);
    EXPECT_EQ(event->scan_type, ScanType::ICMP_SWEEP);
    EXPECT_EQ(event->ports_probed, PortScanDetector::PORT_THRESHOLD + 1);
    EXPECT_TRUE(callback_can_read_events);
}

TEST_F(RuleEngineTest, BlockedPacketsStillFeedScanDetection) {
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
        EXPECT_EQ(engine.evaluate(pkt).verdict, Action::BLOCK);
    }
    const auto events = engine.get_scan_events();
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events.front().scan_type, ScanType::STEALTH_PROBE);
    EXPECT_TRUE(callback_read_succeeded);
}

TEST_F(RuleEngineTest, PacketParserChecksBoundsAndUdpLengths) {
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
    ASSERT_TRUE(PacketParser::parse(packet.data(), 36, parsed)); // trailing padding ignored
    EXPECT_EQ(parsed.size, 28);
    EXPECT_EQ(parsed.src_port, 50000);
    EXPECT_EQ(parsed.dst_port, 53);
    EXPECT_EQ(parsed.payload_len, 0);

    EXPECT_FALSE(PacketParser::parse(packet.data(), 27, parsed)); // truncated IP packet
    EXPECT_EQ(parsed.src_port, 0);
    EXPECT_EQ(parsed.proto, Proto::ANY);

    packet[3] = 28;
    packet[25] = 7; // UDP length smaller than UDP header
    EXPECT_FALSE(PacketParser::parse(packet.data(), 28, parsed));
    packet[25] = 8;
    packet[0] = 0x65; // IPv6 version with an IPv4 header shape
    EXPECT_FALSE(PacketParser::parse(packet.data(), 28, parsed));

    packet[0] = 0x45;
    packet[7] = 1; // Non-initial fragment: payload is not a UDP header.
    ASSERT_TRUE(PacketParser::parse(packet.data(), 28, parsed));
    EXPECT_TRUE(parsed.is_frag_offset);
    EXPECT_EQ(parsed.proto, Proto::UDP);
    EXPECT_EQ(parsed.src_port, 0);
}

TEST_F(RuleEngineTest, TlsVersionParserValidatesLengthsAndClearsThreatName) {
    DpiEngine dpi;
    std::array<uint8_t, 11> hello{};
    hello[0] = 0x16; // TLS handshake record
    hello[1] = 0x03; hello[2] = 0x03;
    hello[4] = 6;    // Record body length
    hello[5] = 1;    // ClientHello
    hello[8] = 2;    // Minimal handshake body length
    hello[9] = 0x03; hello[10] = 0x02; // TLS 1.1

    std::string threat;
    EXPECT_EQ(dpi.scan(hello.data(), static_cast<uint16_t>(hello.size()), threat), Action::BLOCK);
    EXPECT_FALSE(threat.empty());
    hello[10] = 0x03; // TLS 1.2
    EXPECT_EQ(dpi.scan(hello.data(), static_cast<uint16_t>(hello.size()), threat), Action::ALLOW);
    EXPECT_TRUE(threat.empty());
    hello[4] = 7; // TLS record declares one byte beyond captured record.
    EXPECT_EQ(dpi.scan(hello.data(), static_cast<uint16_t>(hello.size()), threat), Action::ALLOW);
    hello[4] = 6;
    hello[8] = 3; // Handshake body exceeds the bytes available in this record.
    EXPECT_EQ(dpi.scan(hello.data(), static_cast<uint16_t>(hello.size()), threat), Action::ALLOW);
    hello[8] = 2;
    hello[4] = 5; // Declared record too short for version field
    EXPECT_EQ(dpi.scan(hello.data(), static_cast<uint16_t>(hello.size()), threat), Action::ALLOW);
}
