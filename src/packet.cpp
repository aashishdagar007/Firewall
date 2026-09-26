#include "packet.hpp"
#include "platform.hpp"

#ifdef _WIN32
#  include "win_packet.hpp"          // packed iphdr / tcphdr / udphdr
#else
#  include <netinet/ip.h>
#  include <netinet/tcp.h>
#  include <netinet/udp.h>
#  include <netinet/ip_icmp.h>
#  include <arpa/inet.h>
#endif

#include <sstream>
#include <cstring>
#include <algorithm>

// ──────────────────────────────────────────────────────────────
//  packet.cpp  –  cross-platform (Linux + Windows)
// ──────────────────────────────────────────────────────────────

namespace fw {

bool PacketParser::parse(const uint8_t* buf, int len, PacketInfo& out) {
    out = PacketInfo{};
    if (!buf || len < (int)sizeof(struct iphdr)) return false;

    struct iphdr ip_header{};
    std::memcpy(&ip_header, buf, sizeof(ip_header));
    const int ip_hdr_len = ip_header.ihl * 4;
    if (ip_header.version != 4 || ip_hdr_len < 20 || len < ip_hdr_len) return false;

    // Reject truncated packets and ignore trailing capture-buffer padding.
    const uint16_t tot_len = ntohs(ip_header.tot_len);
    if (tot_len < ip_hdr_len) return false;
    if (len < tot_len) return false;
    len = tot_len;

    out.src_ip   = ntohl(ip_header.saddr);
    out.dst_ip   = ntohl(ip_header.daddr);
    out.size     = len;
    out.ttl      = ip_header.ttl;

    const uint16_t frag_off = ntohs(ip_header.frag_off);
    out.is_frag_offset = (frag_off & 0x1FFF) != 0;
    out.has_more_frags = (frag_off & 0x2000) != 0;
    out.frag_offset_bytes = (frag_off & 0x1FFF) * 8;

    if (out.is_frag_offset) {
        switch (ip_header.protocol) {
            case IPPROTO_TCP: out.proto = Proto::TCP; break;
            case IPPROTO_UDP: out.proto = Proto::UDP; break;
            case IPPROTO_ICMP: out.proto = Proto::ICMP; break;
            default: out.proto = Proto::ANY; break;
        }
        return true; // Non-initial fragments do not contain transport headers.
    }

    switch (ip_header.protocol) {

        case IPPROTO_TCP: {
            out.proto = Proto::TCP;
            if (len < ip_hdr_len + (int)sizeof(struct tcphdr)) return false;
            struct tcphdr tcp_header{};
            std::memcpy(&tcp_header, buf + ip_hdr_len, sizeof(tcp_header));
            const auto* tcp_bytes = buf + ip_hdr_len;
            out.src_port = ntohs(tcp_header.source);
            out.dst_port = ntohs(tcp_header.dest);
            out.tcp_seq  = ntohl(tcp_header.seq);
            out.tcp_ack  = ntohl(tcp_header.ack_seq);
            // Safely grab the TCP flags (14th byte of the TCP header) to avoid struct differences across platforms
            out.tcp_flags = tcp_bytes[13];
            
            int tcp_hdr_len = (tcp_bytes[12] >> 4) * 4;
            // Mitigate TCP Header underflow vulnerability (minimum valid TCP header is 20 bytes)
            if (tcp_hdr_len < 20 || len < ip_hdr_len + tcp_hdr_len) {
                return false;
            }
            
            out.payload_ptr = buf + ip_hdr_len + tcp_hdr_len;
            out.payload_len = len - (ip_hdr_len + tcp_hdr_len);
            break;
        }

        case IPPROTO_UDP: {
            out.proto = Proto::UDP;
            if (len < ip_hdr_len + (int)sizeof(struct udphdr)) return false;
            struct udphdr udp_header{};
            std::memcpy(&udp_header, buf + ip_hdr_len, sizeof(udp_header));
            out.src_port = ntohs(udp_header.source);
            out.dst_port = ntohs(udp_header.dest);
            const uint16_t udp_len = ntohs(udp_header.len);
            const int ip_payload_len = len - ip_hdr_len;
            if (udp_len < sizeof(struct udphdr) ||
                (!out.has_more_frags && udp_len > ip_payload_len)) return false;
            out.payload_ptr = buf + ip_hdr_len + sizeof(struct udphdr);
            out.payload_len = static_cast<uint16_t>(std::min<int>(
                ip_payload_len - static_cast<int>(sizeof(struct udphdr)),
                udp_len - static_cast<int>(sizeof(struct udphdr))));
            break;
        }

        case IPPROTO_ICMP:
            out.proto = Proto::ICMP;
            if (len < ip_hdr_len + 8) return false;
            out.icmp_type = *(buf + ip_hdr_len);
            out.icmp_code = *(buf + ip_hdr_len + 1);
            break;

        default:
            out.proto = Proto::ANY;
            break;
    }

    return true;
}

std::string PacketParser::to_string(const PacketInfo& pkt) {
    std::ostringstream oss;
    oss << proto_name(pkt.proto) << "  "
        << ip4_to_string(pkt.src_ip) << ":" << pkt.src_port
        << " -> "
        << ip4_to_string(pkt.dst_ip) << ":" << pkt.dst_port
        << "  (" << pkt.size << " bytes)";
    return oss.str();
}

} // namespace fw
