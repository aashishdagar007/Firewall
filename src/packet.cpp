#include "packet.hpp"
#include "platform.hpp"

#ifdef _WIN32
#  include "win_packet.hpp"          // packed iphdr / tcphdr / udphdr
#else
#  include <netinet/ip.h>
#  include <netinet/tcp.h>
#  include <netinet/udp.h>
#  include <arpa/inet.h>
#endif

#include <sstream>

// ──────────────────────────────────────────────────────────────
//  packet.cpp  –  cross-platform (Linux + Windows)
// ──────────────────────────────────────────────────────────────

namespace fw {

bool PacketParser::parse(const uint8_t* buf, int len, PacketInfo& out) {
    if (len < (int)sizeof(struct iphdr)) return false;

    const auto* iph = reinterpret_cast<const struct iphdr*>(buf);
    int ip_hdr_len  = iph->ihl * 4;
    if (ip_hdr_len < 20 || len < ip_hdr_len) return false;

    // Prevent out-of-bounds reads and padding evasion
    uint16_t tot_len = ntohs(iph->tot_len);
    if (tot_len < ip_hdr_len) return false;
    if (len > tot_len) len = tot_len;

    out.src_ip   = ntohl(iph->saddr);
    out.dst_ip   = ntohl(iph->daddr);
    out.src_port = 0;
    out.dst_port = 0;
    out.size     = len;
    out.ttl      = iph->ttl;

    uint16_t frag_off = ntohs(iph->frag_off);
    out.is_frag_offset = (frag_off & 0x1FFF) != 0;
    out.has_more_frags = (frag_off & 0x2000) != 0;
    out.frag_offset_bytes = (frag_off & 0x1FFF) * 8;

    switch (iph->protocol) {

        case IPPROTO_TCP: {
            out.proto = Proto::TCP;
            if (len < ip_hdr_len + (int)sizeof(struct tcphdr)) return false;
            const auto* th = reinterpret_cast<const struct tcphdr*>(buf + ip_hdr_len);
            out.src_port = ntohs(th->source);
            out.dst_port = ntohs(th->dest);
            out.tcp_seq  = ntohl(th->seq);
            out.tcp_ack  = ntohl(th->ack_seq);
            // Safely grab the TCP flags (14th byte of the TCP header) to avoid struct differences across platforms
            out.tcp_flags = *(reinterpret_cast<const uint8_t*>(th) + 13);
            
            int tcp_hdr_len = ((*(reinterpret_cast<const uint8_t*>(th) + 12)) >> 4) * 4;
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
            const auto* uh = reinterpret_cast<const struct udphdr*>(buf + ip_hdr_len);
            out.src_port = ntohs(uh->source);
            out.dst_port = ntohs(uh->dest);
            if (len >= ip_hdr_len + (int)sizeof(struct udphdr)) {
                out.payload_ptr = buf + ip_hdr_len + sizeof(struct udphdr);
                out.payload_len = len - (ip_hdr_len + sizeof(struct udphdr));
            }
            break;
        }

        case IPPROTO_ICMP:
            out.proto = Proto::ICMP;
            if (len >= ip_hdr_len + 2) {
                out.icmp_type = *(buf + ip_hdr_len);
                out.icmp_code = *(buf + ip_hdr_len + 1);
            }
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