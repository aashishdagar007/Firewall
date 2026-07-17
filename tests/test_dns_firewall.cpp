#include "../include/dns_firewall.hpp"
#include <gtest/gtest.h>

TEST(DnsFirewallTest, DgaDetection) {
    fw::DnsFirewall dns_fw;
    
    // Test normal domain
    EXPECT_EQ(dns_fw.inspect_query("www.google.com", 53, "192.168.1.100"), fw::EvalResult::ALLOW);
    
    // Test DGA domain (high entropy + vowel ratio)
    EXPECT_EQ(dns_fw.inspect_query("xkqzjwvbnp.com", 53, "192.168.1.100"), fw::EvalResult::BLOCK);
    EXPECT_EQ(dns_fw.inspect_query("12398547asdf.net", 53, "192.168.1.100"), fw::EvalResult::BLOCK);
}

TEST(DnsFirewallTest, TunnelingDetection) {
    fw::DnsFirewall dns_fw;
    
    // Base64-like long label (DNS tunneling)
    EXPECT_EQ(dns_fw.inspect_query("AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ.example.com", 53, "192.168.1.100"), fw::EvalResult::BLOCK);
}

TEST(DnsFirewallTest, RateLimiting) {
    fw::DnsFirewall dns_fw;
    
    // Send 60 PTR queries (flood)
    for (int i = 0; i < 50; ++i) {
        dns_fw.inspect_query("1.0.0.127.in-addr.arpa", 53, "192.168.1.101");
    }
    
    // 51st should be blocked
    EXPECT_EQ(dns_fw.inspect_query("1.0.0.127.in-addr.arpa", 53, "192.168.1.101"), fw::EvalResult::BLOCK);
}
