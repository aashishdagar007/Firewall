#include <gtest/gtest.h>
#include "traffic_shaper.hpp"
#include <thread>
#include <chrono>

using namespace fw;

TEST(TrafficShaperTest, DefaultRateLimiting) {
    TrafficShaper shaper;
    shaper.set_global_rate_limit(1000); // 1000 bytes/sec
    
    uint32_t ip = 0xC0A80101; // 192.168.1.1
    
    // First packet should succeed (bucket is initialized to capacity = 2000 bytes)
    EXPECT_TRUE(shaper.consume(ip, 500));
    EXPECT_TRUE(shaper.consume(ip, 1000));
    
    // Bucket is now at 500 tokens. Requesting 600 should fail.
    EXPECT_FALSE(shaper.consume(ip, 600));
    
    // Requesting 500 should succeed.
    EXPECT_TRUE(shaper.consume(ip, 500));
    
    // Bucket is empty.
    EXPECT_FALSE(shaper.consume(ip, 100));
    
    // Wait for 1.1 seconds to refill tokens (should refill ~1000 tokens)
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    
    EXPECT_TRUE(shaper.consume(ip, 500));
}

TEST(TrafficShaperTest, CustomIpRateLimiting) {
    TrafficShaper shaper;
    shaper.set_global_rate_limit(100);
    
    uint32_t ip1 = 0xC0A80101;
    uint32_t ip2 = 0xC0A80102;
    
    shaper.set_ip_rate_limit(ip2, 5000); // Higher limit for IP2
    
    // IP1 has 200 capacity
    EXPECT_TRUE(shaper.consume(ip1, 150));
    EXPECT_FALSE(shaper.consume(ip1, 100));
    
    // IP2 has 10000 capacity
    EXPECT_TRUE(shaper.consume(ip2, 5000));
    EXPECT_TRUE(shaper.consume(ip2, 4000));
    EXPECT_FALSE(shaper.consume(ip2, 2000));
}
