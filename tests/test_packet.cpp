#include <gtest/gtest.h>
#include "packet.hpp"

using namespace fw;

TEST(PacketParserTest, ValidTcpPacket) {
    // Basic IP + TCP Header (40 bytes total)
    // We mock the raw bytes here to verify PacketParser bounds checking and header parsing
    uint8_t raw_packet[] = {
        0x45, 0x00, 0x00, 0x28, // IPv4, Header Length=5 (20 bytes), Total Length=40
        0x00, 0x00, 0x40, 0x00, // Id=0, Flags=DF, FragOff=0
        0x40, 0x06, 0x00, 0x00, // TTL=64, Proto=6 (TCP), Checksum=0
        0xC0, 0xA8, 0x01, 0x01, // Src IP: 192.168.1.1
        0x08, 0x08, 0x08, 0x08, // Dst IP: 8.8.8.8
        
        0x04, 0xD2, 0x00, 0x50, // Src Port=1234, Dst Port=80
        0x00, 0x00, 0x00, 0x00, // Seq
        0x00, 0x00, 0x00, 0x00, // Ack
        0x50, 0x02, 0x20, 0x00, // Data Offset=5 (20 bytes), Flags=SYN
        0x00, 0x00, 0x00, 0x00  // Checksum, Urg Ptr
    };

    PacketInfo pkt;
    bool success = PacketParser::parse(raw_packet, sizeof(raw_packet), pkt);
    
    EXPECT_TRUE(success);
    EXPECT_EQ(pkt.proto, Proto::TCP);
    EXPECT_EQ(pkt.src_port, 1234);
    EXPECT_EQ(pkt.dst_port, 80);
    EXPECT_EQ(pkt.tcp_flags, TCP_SYN);
    EXPECT_EQ(pkt.size, 40);
    EXPECT_EQ(pkt.payload_len, 0); // No payload
}

TEST(PacketParserTest, ShortPacketBoundsCheck) {
    uint8_t raw_packet[10] = {0}; // Only 10 bytes, too short for IPv4 header
    PacketInfo pkt;
    bool success = PacketParser::parse(raw_packet, sizeof(raw_packet), pkt);
    EXPECT_FALSE(success) << "Parser should reject extremely short packets";
}

TEST(PacketParserTest, InvalidIHLBoundsCheck) {
    uint8_t raw_packet[40] = {0};
    raw_packet[0] = 0x41; // IHL = 1 (4 bytes), invalid for IPv4
    PacketInfo pkt;
    bool success = PacketParser::parse(raw_packet, sizeof(raw_packet), pkt);
    EXPECT_FALSE(success) << "Parser should reject invalid IHL < 5";
}
