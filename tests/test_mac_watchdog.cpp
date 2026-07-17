#include "../include/mac_watchdog.hpp"
#include <gtest/gtest.h>
#include <thread>
#include <chrono>

TEST(MacWatchdogTest, ArpPoisoning) {
    fw::MacWatchdog watchdog;
    
    std::array<uint8_t, 6> mac1 = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::array<uint8_t, 6> mac2 = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    
    watchdog.record(mac1, 0xC0A8010A); // 192.168.1.10
    
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    bool event_fired = false;
    watchdog.set_callback([&event_fired](const fw::MacConflictEvent& ev) {
        if (ev.threat_type == "ARP_Poison") {
            event_fired = true;
        }
    });
    
    watchdog.record(mac2, 0xC0A8010A); // 192.168.1.10
    
    EXPECT_TRUE(event_fired);
}

TEST(MacWatchdogTest, LaaChange) {
    fw::MacWatchdog watchdog;
    
    std::array<uint8_t, 6> mac1 = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::array<uint8_t, 6> mac2 = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    
    watchdog.record(mac1, 0xC0A8010B); // 192.168.1.11
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    bool event_fired = false;
    watchdog.set_callback([&event_fired](const fw::MacConflictEvent& ev) {
        if (ev.threat_type == "LAA_Change") {
            event_fired = true;
        }
    });
    
    watchdog.record(mac2, 0xC0A8010B); // 192.168.1.11
    
    EXPECT_TRUE(event_fired);
}
