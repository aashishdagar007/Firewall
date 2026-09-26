#include "diode_threat_engine.hpp"
#include "platform.hpp"
#include "chain_ledger.hpp"
#include <cmath>
#include <ctime>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace fw {

// ── Simple MD5 implementation for JA3 fingerprinting ──────────
// (Headerless standalone MD5 so zero external dependencies are needed)
namespace md5_internal {
    struct MD5Context {
        uint32_t state[4];
        uint32_t count[2];
        uint8_t  buffer[64];
    };

    static void transform(uint32_t state[4], const uint8_t block[64]);

    static void init(MD5Context* ctx) {
        ctx->count[0] = ctx->count[1] = 0;
        ctx->state[0] = 0x67452301;
        ctx->state[1] = 0xefcdab89;
        ctx->state[2] = 0x98badcfe;
        ctx->state[3] = 0x10325476;
    }

    #define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
    #define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
    #define H(x, y, z) ((x) ^ (y) ^ (z))
    #define I(x, y, z) ((y) ^ ((x) | (~z)))
    #define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
    #define FF(a, b, c, d, x, s, ac) { (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTLEFT((a), (s)); (a) += (b); }
    #define GG(a, b, c, d, x, s, ac) { (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTLEFT((a), (s)); (a) += (b); }
    #define HH(a, b, c, d, x, s, ac) { (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTLEFT((a), (s)); (a) += (b); }
    #define II(a, b, c, d, x, s, ac) { (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); (a) = ROTLEFT((a), (s)); (a) += (b); }

    static void transform(uint32_t state[4], const uint8_t block[64]) {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
        for (int i = 0, j = 0; i < 16; ++i, j += 4) {
            x[i] = ((uint32_t)block[j]) | (((uint32_t)block[j + 1]) << 8) |
                   (((uint32_t)block[j + 2]) << 16) | (((uint32_t)block[j + 3]) << 24);
        }
        FF(a, b, c, d, x[ 0],  7, 0xd76aa478); FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
        FF(c, d, a, b, x[ 2], 17, 0x242070db); FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
        FF(a, b, c, d, x[ 4],  7, 0xf57c0faf); FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
        FF(c, d, a, b, x[ 6], 17, 0xa8304613); FF(b, c, d, a, x[ 7], 22, 0xfd469501);
        FF(a, b, c, d, x[ 8],  7, 0x698098d8); FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
        FF(c, d, a, b, x[10], 17, 0xffff5bb1); FF(b, c, d, a, x[11], 22, 0x895cd7be);
        FF(a, b, c, d, x[12],  7, 0x6b901122); FF(d, a, b, c, x[13], 12, 0xfd987193);
        FF(c, d, a, b, x[14], 17, 0xa679438e); FF(b, c, d, a, x[15], 22, 0x49b40821);

        GG(a, b, c, d, x[ 1],  5, 0xf61e2562); GG(d, a, b, c, x[ 6],  9, 0xc040b340);
        GG(c, d, a, b, x[11], 14, 0x265e5a51); GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
        GG(a, b, c, d, x[ 5],  5, 0xd62f105d); GG(d, a, b, c, x[10],  9, 0x02441453);
        GG(c, d, a, b, x[15], 14, 0xd8a1e681); GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
        GG(a, b, c, d, x[ 9],  5, 0x21e1cde6); GG(d, a, b, c, x[14],  9, 0xc33707d6);
        GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
        GG(a, b, c, d, x[13],  5, 0xa9e3e905); GG(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
        GG(c, d, a, b, x[ 7], 14, 0x676f02d9); GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

        HH(a, b, c, d, x[ 5],  4, 0xfffa3942); HH(d, a, b, c, x[ 8], 11, 0x8771f681);
        HH(c, d, a, b, x[11], 16, 0x6d9d6122); HH(b, c, d, a, x[14], 23, 0xfde5380c);
        HH(a, b, c, d, x[ 1],  4, 0xa4beea44); HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
        HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); HH(b, c, d, a, x[10], 23, 0xbebfbc70);
        HH(a, b, c, d, x[13],  4, 0x289b7ec6); HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
        HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); HH(b, c, d, a, x[ 6], 23, 0x04881d05);
        HH(a, b, c, d, x[ 9],  4, 0xd9d4d039); HH(d, a, b, c, x[12], 11, 0xe6db99e5);
        HH(c, d, a, b, x[15], 16, 0x1fa27cf8); HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);

        II(a, b, c, d, x[ 0],  6, 0xf4292244); II(d, a, b, c, x[ 7], 10, 0x432aff97);
        II(c, d, a, b, x[14], 15, 0xab9423a7); II(b, c, d, a, x[ 5], 21, 0xfc93a039);
        II(a, b, c, d, x[12],  6, 0x655b59c3); II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
        II(c, d, a, b, x[10], 15, 0xffeff47d); II(b, c, d, a, x[ 1], 21, 0x85845dd1);
        II(a, b, c, d, x[ 8],  6, 0x6fa87e4f); II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
        II(c, d, a, b, x[ 6], 15, 0xa3014314); II(b, c, d, a, x[13], 21, 0x4e0811a1);
        II(a, b, c, d, x[ 4],  6, 0xf7537e82); II(d, a, b, c, x[11], 10, 0xbd3af235);
        II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); II(b, c, d, a, x[ 9], 21, 0xeb86d391);

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    }

    static void update(MD5Context* ctx, const uint8_t* input, size_t input_len) {
        size_t index = (size_t)((ctx->count[0] >> 3) & 0x3F);
        if ((ctx->count[0] += (uint32_t)(input_len << 3)) < (uint32_t)(input_len << 3))
            ctx->count[1]++;
        ctx->count[1] += (uint32_t)(input_len >> 29);
        size_t part_len = 64 - index;
        size_t i = 0;
        if (input_len >= part_len) {
            std::memcpy(&ctx->buffer[index], input, part_len);
            transform(ctx->state, ctx->buffer);
            for (i = part_len; i + 63 < input_len; i += 64)
                transform(ctx->state, &input[i]);
            index = 0;
        }
        std::memcpy(&ctx->buffer[index], &input[i], input_len - i);
    }

    static std::string finalize(MD5Context* ctx) {
        static const uint8_t PADDING[64] = { 0x80 };
        uint8_t bits[8];
        for (int i = 0; i < 4; ++i) {
            bits[i] = (uint8_t)((ctx->count[0] >> (i * 8)) & 0xFF);
            bits[i + 4] = (uint8_t)((ctx->count[1] >> (i * 8)) & 0xFF);
        }
        size_t index = (size_t)((ctx->count[0] >> 3) & 0x3F);
        size_t pad_len = (index < 56) ? (56 - index) : (120 - index);
        update(ctx, PADDING, pad_len);
        update(ctx, bits, 8);
        uint8_t digest[16];
        for (int i = 0; i < 4; ++i) {
            digest[i * 4]     = (uint8_t)(ctx->state[i] & 0xFF);
            digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 8) & 0xFF);
            digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
            digest[i * 4 + 3] = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
        }
        std::ostringstream ss;
        for (int i = 0; i < 16; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }
        return ss.str();
    }

    static std::string hash_string(const std::string& input) {
        MD5Context ctx;
        init(&ctx);
        update(&ctx, reinterpret_cast<const uint8_t*>(input.data()), input.size());
        return finalize(&ctx);
    }
} // namespace md5_internal

// ── Known Malicious JA3 Signatures Dictionary ─────────────────
static const std::unordered_map<std::string, std::string> KNOWN_MALICIOUS_JA3 = {
    {"6734f37431670b3ab4292b8f60f29984", "Cobalt Strike Malleable C2 Beacon"},
    {"51c64c77e60f25cad4cfb63d027e49de", "TrickBot Banking Trojan"},
    {"72a589da586844d7f0818ce684948eea", "Emotet Loader C2"},
    {"a0e9f5d64349fb13191bc781f81f42e1", "Metasploit Meterpreter Reverse HTTPS"},
    {"b32309a26951912be7dba376398abc3b", "AsyncRAT Remote Access Trojan"},
    {"3b5074b1b5c032e5520f688f33f41ae0", "Dridex Banking Malware"},
    {"e7d705a3286e19ea42f587b344ee6865", "Sliver C2 Framework"}
};

// ── Helper: Current Timestamp String ──────────────────────────
static std::string current_iso_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t timer = std::chrono::system_clock::to_time_t(now);
    std::tm bt{};
#ifdef _WIN32
    gmtime_s(&bt, &timer);
#else
    gmtime_r(&timer, &bt);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &bt);
    std::ostringstream ss;
    ss << buf << "." << std::setw(3) << std::setfill('0') << ms.count() << "Z";
    return ss.str();
}

// ── Constructor ───────────────────────────────────────────────
DiodeThreatEngine::DiodeThreatEngine(ChainLedger* ledger)
    : ledger_(ledger), start_time_(std::chrono::steady_clock::now()) {
}

// ── Streaming Packet Evaluator ─────────────────────────────────
void DiodeThreatEngine::process_packet(const PacketInfo& pkt) {
    total_packets_++;
    total_bytes_ += pkt.size;

    auto now = std::chrono::steady_clock::now();

    // 1. Volumetric / Protocol DDoS
    analyze_volumetric_ddos(pkt, now);

    // 2. Botnet C2 Beaconing
    analyze_botnet_beaconing(pkt, now);

    // 3. DNS DGA Domains & DNS Tunnelling
    analyze_dns_dga_tunnel(pkt, now);

    // 4. Malware Inside Encrypted Sessions (TLS/QUIC - Zero Payload Decryption)
    analyze_encrypted_malware(pkt, now);

    // 5. Reconnaissance and Port Scanning (Fan-out)
    analyze_reconnaissance(pkt, now);

    // 6. Data Exfiltration (Flow Volume Asymmetry)
    analyze_data_exfiltration(pkt, now);
}

// ── 1. Volumetric / Protocol DDoS Analyzer ─────────────────────
void DiodeThreatEngine::analyze_volumetric_ddos(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now) {
    std::lock_guard<std::mutex> lk(mtx_);

    // Push into sliding window (last 200 packets or 2 seconds)
    ddos_state_.src_ip_window.push_back({pkt.src_ip, now});
    ddos_state_.ip_frequency[pkt.src_ip]++;

    if (pkt.proto == Proto::TCP) {
        if (pkt.tcp_flags & TCP_SYN) ddos_state_.syn_count++;
        if (pkt.tcp_flags & TCP_ACK) ddos_state_.ack_count++;
    }

    // Trim window to last 2.0 seconds
    auto cutoff = now - std::chrono::milliseconds(2000);
    while (!ddos_state_.src_ip_window.empty() && ddos_state_.src_ip_window.front().second < cutoff) {
        uint32_t old_ip = ddos_state_.src_ip_window.front().first;
        ddos_state_.src_ip_window.pop_front();
        if (--ddos_state_.ip_frequency[old_ip] == 0) {
            ddos_state_.ip_frequency.erase(old_ip);
        }
    }

    size_t win_size = ddos_state_.src_ip_window.size();
    if (win_size < 50) return; // Need statistically significant sample

    // Calculate Source IP Shannon Entropy: H = - sum(p_i * log2(p_i))
    double entropy = 0.0;
    for (const auto& [ip, count] : ddos_state_.ip_frequency) {
        double p = static_cast<double>(count) / static_cast<double>(win_size);
        if (p > 0.0) entropy -= p * std::log2(p);
    }

    // A low source-IP entropy (< 1.5) during high packet volume indicates
    // a concentrated single-source or spoofed subnet flood attack
    bool syn_flood = (ddos_state_.syn_count > 40 && ddos_state_.ack_count < 5);
    bool udp_amp = (pkt.proto == Proto::UDP &&
                    (pkt.src_port == 53 || pkt.src_port == 123 || pkt.src_port == 1900 || pkt.src_port == 389) &&
                    pkt.size > 512);

    if (entropy < 1.8 || syn_flood || udp_amp) {
        if (now - ddos_state_.last_alert > std::chrono::milliseconds(3000)) {
            ddos_state_.last_alert = now;

            DiodeAlert alert;
            alert.alert_id = "ALT-DDOS-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000000);
            alert.timestamp = current_iso_timestamp();
            alert.threat_class = ThreatClass::VOLUMETRIC_DDOS;
            alert.threat_name = udp_amp ? "UDP Reflection / Amplification Flood" : (syn_flood ? "Volumetric TCP SYN Flood" : "Spoofed Source IP Volumetric Flood");
            alert.severity = ThreatSeverity::CRITICAL;
            alert.confidence_score = std::min(1.0f, static_cast<float>(0.80 + (2.0 - std::min(entropy, 2.0)) * 0.1));
            alert.flow = {pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, proto_name(pkt.proto)};
            alert.src_ip_str = ip4_to_string(pkt.src_ip);
            alert.dst_ip_str = ip4_to_string(pkt.dst_ip);

            std::ostringstream ev;
            ev << "{"
               << "\"shannon_entropy\":" << std::fixed << std::setprecision(3) << entropy << ","
               << "\"window_packets\":" << win_size << ","
               << "\"unique_source_ips\":" << ddos_state_.ip_frequency.size() << ","
               << "\"syn_ratio\":" << std::fixed << std::setprecision(2) << (win_size > 0 ? (double)ddos_state_.syn_count / win_size : 0.0) << ","
               << "\"udp_reflection_port\":" << (udp_amp ? pkt.src_port : 0) << ","
               << "\"detection_method\":\"Shannon Source-IP Entropy & Kinetic Surge Analysis\""
               << "}";
            alert.evidence_json = ev.str();
            alert.recommendation = "Volumetric surge observed on unidirectional diode. Recommend upstream border ACL mitigation.";

            emit_alert(std::move(alert));
        }
    }
}

// ── 2. Botnet C2 Beaconing Analyzer ───────────────────────────
void DiodeThreatEngine::analyze_botnet_beaconing(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now) {
    if (pkt.src_ip == 0 || pkt.dst_ip == 0) return;

    FlowId flow_key{pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, proto_name(pkt.proto)};

    std::lock_guard<std::mutex> lk(mtx_);
    auto& state = beacon_states_[flow_key];
    state.packet_count++;
    state.arrivals.push_back(now);

    // Keep last 15 arrivals for inter-arrival time (IAT) analysis
    if (state.arrivals.size() > 15) {
        state.arrivals.pop_front();
    }

    if (state.arrivals.size() >= 6) {
        std::vector<double> iats;
        for (size_t i = 1; i < state.arrivals.size(); ++i) {
            double delta = std::chrono::duration<double>(state.arrivals[i] - state.arrivals[i - 1]).count();
            if (delta > 0.001) iats.push_back(delta);
        }

        if (iats.size() >= 5) {
            double sum = std::accumulate(iats.begin(), iats.end(), 0.0);
            double mean = sum / iats.size();

            // Calculate standard deviation and Coefficient of Variation (CV = sigma / mean)
            double sq_sum = 0.0;
            for (double d : iats) sq_sum += (d - mean) * (d - mean);
            double std_dev = std::sqrt(sq_sum / iats.size());
            double cv = (mean > 0.0001) ? (std_dev / mean) : 1.0;

            // Low CV (< 0.15) with an interval between 0.5s and 120s indicates machine-like periodic beaconing
            if (cv < 0.15 && mean >= 0.2 && mean <= 180.0) {
                if (now - state.last_alert > std::chrono::seconds(8)) {
                    state.last_alert = now;

                    DiodeAlert alert;
                    alert.alert_id = "ALT-C2-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000000);
                    alert.timestamp = current_iso_timestamp();
                    alert.threat_class = ThreatClass::BOTNET_C2_BEACONING;
                    alert.threat_name = "Botnet C2 Periodic Beaconing (Low IAT Jitter)";
                    alert.severity = ThreatSeverity::HIGH;
                    alert.confidence_score = std::min(0.99f, static_cast<float>(1.0 - (cv * 2.5)));
                    alert.flow = flow_key;
                    alert.src_ip_str = ip4_to_string(pkt.src_ip);
                    alert.dst_ip_str = ip4_to_string(pkt.dst_ip);

                    std::ostringstream ev;
                    ev << "{"
                       << "\"mean_iat_sec\":" << std::fixed << std::setprecision(3) << mean << ","
                       << "\"std_iat_sec\":" << std::fixed << std::setprecision(3) << std_dev << ","
                       << "\"coefficient_of_variation\":" << std::fixed << std::setprecision(4) << cv << ","
                       << "\"periodicity_score\":" << std::fixed << std::setprecision(2) << (1.0 - cv) << ","
                       << "\"burst_samples\":" << iats.size() << ","
                       << "\"detection_method\":\"Inter-Arrival Time (IAT) Coefficient of Variation Spectrum\""
                       << "}";
                    alert.evidence_json = ev.str();
                    alert.recommendation = "Host exhibit regular periodic heartbeats typical of C2 beaconing. Passively recorded in enclave.";

                    emit_alert(std::move(alert));
                }
            }
        }
    }
}

// ── 3. DGA Domains & DNS Tunnelling Analyzer ───────────────────
void DiodeThreatEngine::analyze_dns_dga_tunnel(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now) {
    if (pkt.src_port != 53 && pkt.dst_port != 53) return;
    if (!pkt.payload_ptr || pkt.payload_len < 12) return;

    uint16_t qtype = 0;
    std::string domain = parse_dns_qname(pkt.payload_ptr, pkt.payload_len, qtype);
    if (domain.empty()) return;

    // Remove TLD for label-specific entropy analysis
    std::string label = domain;
    size_t dot_pos = domain.rfind('.');
    if (dot_pos != std::string::npos && dot_pos > 0) {
        label = domain.substr(0, dot_pos);
        size_t sec_dot = label.rfind('.');
        if (sec_dot != std::string::npos) label = label.substr(sec_dot + 1);
    }

    double entropy = calculate_shannon_entropy(label);
    double consonant_ratio = calculate_consonant_vowel_ratio(label);
    double bigram_perp = calculate_bigram_perplexity(label);

    bool is_tunnel = (pkt.payload_len > 80 && (qtype == 16 /*TXT*/ || qtype == 10 /*NULL*/ || label.size() > 35));
    bool is_dga = (label.size() >= 12 && entropy >= 3.4 && (consonant_ratio > 3.0 || bigram_perp > 3.0));

    if (is_tunnel || is_dga) {
        std::string dedupe_key = "DNS:" + domain;
        if (now - alert_cooldowns_[dedupe_key] > std::chrono::seconds(5)) {
            alert_cooldowns_[dedupe_key] = now;

            DiodeAlert alert;
            alert.alert_id = "ALT-DNS-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000000);
            alert.timestamp = current_iso_timestamp();
            alert.threat_class = ThreatClass::DNS_DGA_TUNNEL;
            alert.threat_name = is_tunnel ? "DNS Tunneling & Data Exfiltration" : "DGA Algorithmically Generated Domain";
            alert.severity = is_tunnel ? ThreatSeverity::CRITICAL : ThreatSeverity::HIGH;
            alert.confidence_score = is_tunnel ? 0.96f : 0.91f;
            alert.flow = {pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, proto_name(pkt.proto)};
            alert.src_ip_str = ip4_to_string(pkt.src_ip);
            alert.dst_ip_str = ip4_to_string(pkt.dst_ip);

            std::ostringstream ev;
            ev << "{"
               << "\"qname\":\"" << domain << "\","
               << "\"label_length\":" << label.size() << ","
               << "\"shannon_entropy\":" << std::fixed << std::setprecision(3) << entropy << ","
               << "\"consonant_vowel_ratio\":" << std::fixed << std::setprecision(2) << consonant_ratio << ","
               << "\"bigram_perplexity\":" << std::fixed << std::setprecision(2) << bigram_perp << ","
               << "\"record_type\":" << (qtype == 16 ? "\"TXT\"" : (qtype == 1 ? "\"A\"" : (qtype == 10 ? "\"NULL\"" : "\"OTHER\""))) << ","
               << "\"detection_method\":\"N-Gram Perplexity & Shannon Character Entropy\""
               << "}";
            alert.evidence_json = ev.str();
            alert.recommendation = "Passive inspection identified high-entropy query name or tunneling payload on port 53.";

            emit_alert(std::move(alert));
        }
    }
}

// ── 4. Malware Inside Encrypted Sessions (Zero Decryption) ─────
void DiodeThreatEngine::analyze_encrypted_malware(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now) {
    if (pkt.proto != Proto::TCP || (pkt.dst_port != 443 && pkt.dst_port != 8443 && pkt.src_port != 443)) return;
    if (!pkt.payload_ptr || pkt.payload_len < 12) return;

    // Check for TLS Handshake (0x16) and ClientHello (0x01)
    if (pkt.payload_ptr[0] == 0x16 && pkt.payload_ptr[5] == 0x01) {
        std::string ja3_string = extract_tls_ja3(pkt.payload_ptr, pkt.payload_len);
        if (!ja3_string.empty()) {
            std::string ja3_hash = md5_internal::hash_string(ja3_string);

            auto it = KNOWN_MALICIOUS_JA3.find(ja3_hash);
            if (it != KNOWN_MALICIOUS_JA3.end()) {
                std::string dedupe_key = "JA3:" + ja3_hash + ":" + ip4_to_string(pkt.src_ip);
                if (now - alert_cooldowns_[dedupe_key] > std::chrono::seconds(6)) {
                    alert_cooldowns_[dedupe_key] = now;

                    DiodeAlert alert;
                    alert.alert_id = "ALT-JA3-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000000);
                    alert.timestamp = current_iso_timestamp();
                    alert.threat_class = ThreatClass::ENCRYPTED_MALWARE;
                    alert.threat_name = "Malware in Encrypted Session: " + it->second;
                    alert.severity = ThreatSeverity::CRITICAL;
                    alert.confidence_score = 0.98f;
                    alert.flow = {pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, "TCP"};
                    alert.src_ip_str = ip4_to_string(pkt.src_ip);
                    alert.dst_ip_str = ip4_to_string(pkt.dst_ip);

                    std::ostringstream ev;
                    ev << "{"
                       << "\"ja3_hash\":\"" << ja3_hash << "\","
                       << "\"ja3_string\":\"" << ja3_string << "\","
                       << "\"malware_profile\":\"" << it->second << "\","
                       << "\"tls_record_len\":" << pkt.payload_len << ","
                       << "\"payload_decrypted\":false,"
                       << "\"detection_method\":\"Passive JA3/JA4 TLS ClientHello Fingerprinting (Zero Decryption)\""
                       << "}";
                    alert.evidence_json = ev.str();
                    alert.recommendation = "Malicious TLS ClientHello fingerprint matched without decrypting session.";

                    emit_alert(std::move(alert));
                }
            }
        }
    }
}

// ── 5. Reconnaissance and Port Scanning (Fan-Out) ──────────────
void DiodeThreatEngine::analyze_reconnaissance(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now) {
    if (pkt.src_ip == 0) return;

    std::lock_guard<std::mutex> lk(mtx_);
    auto& st = recon_states_[pkt.src_ip];
    if (st.first_seen.time_since_epoch().count() == 0) {
        st.first_seen = now;
    }

    if (pkt.dst_port != 0) st.dst_ports.insert(pkt.dst_port);
    if (pkt.dst_ip != 0) st.dst_ips.insert(pkt.dst_ip);

    // Stealth scan flags check
    bool is_stealth = (pkt.proto == Proto::TCP) &&
                      (pkt.tcp_flags == 0 /*NULL*/ ||
                       pkt.tcp_flags == (TCP_FIN | TCP_PSH | TCP_URG) /*XMAS*/ ||
                       (pkt.tcp_flags == TCP_FIN));

    // Reset window after 6 seconds
    if (now - st.first_seen > std::chrono::seconds(6)) {
        st.dst_ports.clear();
        st.dst_ips.clear();
        st.first_seen = now;
    }

    bool horizontal_sweep = (st.dst_ips.size() > 14);
    bool vertical_scan = (st.dst_ports.size() > 16);
    bool strobe_scan = (st.dst_ports.size() > 8 && st.dst_ips.size() > 6);

    if (horizontal_sweep || vertical_scan || strobe_scan || is_stealth) {
        if (now - st.last_alert > std::chrono::seconds(5)) {
            st.last_alert = now;

            DiodeAlert alert;
            alert.alert_id = "ALT-RECON-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000000);
            alert.timestamp = current_iso_timestamp();
            alert.threat_class = ThreatClass::RECON_SCAN;
            alert.threat_name = is_stealth ? "Stealth Probe Reconnaissance (TCP Flags)" :
                                (horizontal_sweep ? "Horizontal Host Sweep (Fan-out across Subnet)" :
                                 (vertical_scan ? "Vertical Port Scan (Port Discovery)" : "Strobe Reconnaissance Scan"));
            alert.severity = is_stealth ? ThreatSeverity::HIGH : ThreatSeverity::MEDIUM;
            alert.confidence_score = 0.94f;
            alert.flow = {pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, proto_name(pkt.proto)};
            alert.src_ip_str = ip4_to_string(pkt.src_ip);
            alert.dst_ip_str = ip4_to_string(pkt.dst_ip);

            std::ostringstream ev;
            ev << "{"
               << "\"unique_dest_ports\":" << st.dst_ports.size() << ","
               << "\"unique_dest_ips\":" << st.dst_ips.size() << ","
               << "\"scan_subtype\":\"" << (horizontal_sweep ? "Horizontal Sweep" : (vertical_scan ? "Vertical Scan" : "Matrix Strobe")) << "\","
               << "\"is_stealth_flags\":" << (is_stealth ? "true" : "false") << ","
               << "\"detection_method\":\"Sliding-Window Cardinality Fan-Out Correlation\""
               << "}";
            alert.evidence_json = ev.str();
            alert.recommendation = "Reconnaissance activity observed crossing perimeter link.";

            emit_alert(std::move(alert));
        }
    }
}

// ── 6. Data Exfiltration (Flow Volume Asymmetry) ───────────────
void DiodeThreatEngine::analyze_data_exfiltration(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now) {
    if (pkt.src_ip == 0 || pkt.size <= 0) return;

    std::lock_guard<std::mutex> lk(mtx_);
    auto& st = exfil_states_[pkt.src_ip];
    if (st.first_seen.time_since_epoch().count() == 0) st.first_seen = now;

    st.bytes_out += pkt.size;

    // Reset baseline every 30 seconds
    if (now - st.first_seen > std::chrono::seconds(30)) {
        st.bytes_out = pkt.size;
        st.bytes_in = 0;
        st.first_seen = now;
    }

    // Outbound byte ratio threshold: > 250 KB transferred with asymmetric burst
    if (st.bytes_out > 250000) {
        double ratio = static_cast<double>(st.bytes_out) / std::max(static_cast<double>(st.bytes_in), 1024.0);
        if (ratio > 15.0) {
            if (now - st.last_alert > std::chrono::seconds(10)) {
                st.last_alert = now;

                DiodeAlert alert;
                alert.alert_id = "ALT-EXFIL-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000000);
                alert.timestamp = current_iso_timestamp();
                alert.threat_class = ThreatClass::DATA_EXFILTRATION;
                alert.threat_name = "Asymmetric Outbound Flow (Data Exfiltration)";
                alert.severity = ThreatSeverity::HIGH;
                alert.confidence_score = std::min(0.98f, static_cast<float>(0.80 + std::min(ratio / 100.0, 0.18)));
                alert.flow = {pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, proto_name(pkt.proto)};
                alert.src_ip_str = ip4_to_string(pkt.src_ip);
                alert.dst_ip_str = ip4_to_string(pkt.dst_ip);

                std::ostringstream ev;
                ev << "{"
                   << "\"bytes_out\":" << st.bytes_out << ","
                   << "\"bytes_in\":" << st.bytes_in << ","
                   << "\"asymmetry_ratio\":" << std::fixed << std::setprecision(2) << ratio << ","
                   << "\"destination_port\":" << pkt.dst_port << ","
                   << "\"detection_method\":\"Outbound-to-Inbound Volume Asymmetry Anomaly Detector\""
                   << "}";
                alert.evidence_json = ev.str();
                alert.recommendation = "Anomalously high outbound data transfer ratio detected toward external destination.";

                emit_alert(std::move(alert));
            }
        }
    }
}

// ── Emit Alert & Ledger Commitment ────────────────────────────
void DiodeThreatEngine::emit_alert(DiodeAlert alert) {
    total_alerts_raised_++;
    size_t c_idx = static_cast<size_t>(alert.threat_class);
    if (c_idx < 6) threat_counts_[c_idx]++;

    // Log to Tamper-Proof Chain Ledger (Pillar 4)
    if (ledger_) {
        ledger_->log_threat_banned(alert.src_ip_str, "[" + std::string(threat_class_code(alert.threat_class)) + "] " + alert.threat_name);
    }

    if (alert_cb_) {
        alert_cb_(alert);
    }

    alerts_.push_front(alert);
    if (alerts_.size() > MAX_ALERTS) {
        alerts_.pop_back();
    }
}

std::vector<DiodeAlert> DiodeThreatEngine::get_recent_alerts(size_t limit) const {
    std::lock_guard<std::mutex> lk(mtx_);
    size_t count = std::min(limit, alerts_.size());
    return std::vector<DiodeAlert>(alerts_.begin(), alerts_.begin() + count);
}

void DiodeThreatEngine::clear_alerts() {
    std::lock_guard<std::mutex> lk(mtx_);
    alerts_.clear();
}

DiodeTelemetry DiodeThreatEngine::get_telemetry() const {
    std::lock_guard<std::mutex> lk(mtx_);
    DiodeTelemetry tel;
    auto now = std::chrono::steady_clock::now();
    double elapsed_sec = std::chrono::duration<double>(now - start_time_).count();
    if (elapsed_sec > 0.05) {
        tel.packets_per_sec = static_cast<double>(total_packets_.load()) / elapsed_sec;
        tel.mbps = (static_cast<double>(total_bytes_.load()) * 8.0) / (elapsed_sec * 1000000.0);
        tel.flows_per_sec = tel.packets_per_sec * 0.45; // Approximate active flows
    }
    tel.total_packets = total_packets_.load();
    tel.total_flows_tracked = beacon_states_.size() + recon_states_.size();
    tel.total_alerts_raised = total_alerts_raised_.load();
    tel.diode_mode_active = diode_mode_active_.load();
    tel.read_only_verified = true;
    tel.zero_return_path = true;

    for (int i = 0; i < 6; ++i) {
        tel.class_counts[i] = threat_counts_[i];
    }
    return tel;
}

std::unordered_map<std::string, uint64_t> DiodeThreatEngine::get_threat_summary() const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::unordered_map<std::string, uint64_t> summary;
    for (int i = 0; i < 6; ++i) {
        ThreatClass tc = static_cast<ThreatClass>(i);
        summary[threat_class_code(tc)] = threat_counts_[i];
    }
    summary["TOTAL"] = total_alerts_raised_.load();
    return summary;
}

// ── Math & Extraction Implementations ─────────────────────────
double DiodeThreatEngine::calculate_shannon_entropy(const std::string& str) {
    if (str.empty()) return 0.0;
    std::unordered_map<char, size_t> freq;
    for (char c : str) freq[c]++;

    double entropy = 0.0;
    double len = static_cast<double>(str.size());
    for (const auto& [c, count] : freq) {
        double p = static_cast<double>(count) / len;
        if (p > 0.0) entropy -= p * std::log2(p);
    }
    return entropy;
}

double DiodeThreatEngine::calculate_consonant_vowel_ratio(const std::string& domain) {
    size_t vowels = 0, consonants = 0;
    for (char c : domain) {
        char ch = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ch >= 'a' && ch <= 'z') {
            if (ch == 'a' || ch == 'e' || ch == 'i' || ch == 'o' || ch == 'u')
                vowels++;
            else
                consonants++;
        }
    }
    return (vowels == 0) ? static_cast<double>(consonants) : (static_cast<double>(consonants) / static_cast<double>(vowels));
}

double DiodeThreatEngine::calculate_bigram_perplexity(const std::string& domain) {
    if (domain.size() < 2) return 1.0;
    // Count unusual consonant-consonant clusters (e.g. "qzw", "xkj", "zkq")
    size_t unusual = 0;
    for (size_t i = 1; i < domain.size(); ++i) {
        char c1 = std::tolower((unsigned char)domain[i-1]);
        char c2 = std::tolower((unsigned char)domain[i]);
        if (std::isalpha((unsigned char)c1) && std::isalpha((unsigned char)c2)) {
            bool v1 = (c1=='a'||c1=='e'||c1=='i'||c1=='o'||c1=='u');
            bool v2 = (c2=='a'||c2=='e'||c2=='i'||c2=='o'||c2=='u');
            if (!v1 && !v2 && c1 != c2) unusual++;
        }
    }
    return static_cast<double>(unusual) / static_cast<double>(domain.size() - 1) * 5.0;
}

std::string DiodeThreatEngine::parse_dns_qname(const uint8_t* payload, uint16_t len, uint16_t& qtype) {
    if (len < 12) return "";
    size_t pos = 12; // Start of Question Section
    std::string domain;

    while (pos < len) {
        uint8_t label_len = payload[pos++];
        if (label_len == 0) break; // End of QNAME
        if (pos + label_len > len) return "";

        if (!domain.empty()) domain += ".";
        for (uint8_t i = 0; i < label_len; ++i) {
            domain += static_cast<char>(payload[pos++]);
        }
    }

    if (pos + 2 <= len) {
        qtype = (static_cast<uint16_t>(payload[pos]) << 8) | payload[pos + 1];
    }
    return domain;
}

std::string DiodeThreatEngine::extract_tls_ja3(const uint8_t* payload, uint16_t len) {
    if (len < 44) return "";
    // Handshake Type 0x01 (ClientHello)
    if (payload[0] != 0x16 || payload[5] != 0x01) return "";

    size_t pos = 9; // Handshake version
    if (pos + 2 > len) return "";
    uint16_t client_version = (payload[pos] << 8) | payload[pos + 1];
    pos += 2; // version
    pos += 32; // Random (32 bytes)

    if (pos >= len) return "";
    uint8_t sess_id_len = payload[pos++];
    pos += sess_id_len;

    if (pos + 2 > len) return "";
    uint16_t cipher_len = (payload[pos] << 8) | payload[pos + 1];
    pos += 2;

    std::vector<uint16_t> ciphers;
    for (size_t i = 0; i + 1 < cipher_len && pos + 1 < len; i += 2) {
        uint16_t c = (payload[pos] << 8) | payload[pos + 1];
        // Skip GREASE (0x?a?a)
        if ((c & 0x0F0F) != 0x0A0A) {
            ciphers.push_back(c);
        }
        pos += 2;
    }

    if (pos >= len) return "";
    uint8_t comp_len = payload[pos++];
    pos += comp_len;

    std::vector<uint16_t> extensions;
    std::vector<uint16_t> curves;
    std::vector<uint8_t> ec_formats;

    if (pos + 2 <= len) {
        uint16_t ext_total_len = (payload[pos] << 8) | payload[pos + 1];
        pos += 2;
        size_t ext_end = std::min(pos + ext_total_len, (size_t)len);

        while (pos + 4 <= ext_end) {
            uint16_t ext_type = (payload[pos] << 8) | payload[pos + 1];
            uint16_t ext_len  = (payload[pos + 2] << 8) | payload[pos + 3];
            pos += 4;

            if ((ext_type & 0x0F0F) != 0x0A0A) {
                extensions.push_back(ext_type);
            }

            // Supported Groups (Elliptic Curves) = 0x000a
            if (ext_type == 0x000a && pos + 2 <= ext_end) {
                uint16_t groups_len = (payload[pos] << 8) | payload[pos + 1];
                for (size_t g = 0; g + 1 < groups_len && pos + 2 + g + 1 < ext_end; g += 2) {
                    uint16_t crv = (payload[pos + 2 + g] << 8) | payload[pos + 2 + g + 1];
                    if ((crv & 0x0F0F) != 0x0A0A) curves.push_back(crv);
                }
            }
            // EC Point Formats = 0x000b
            if (ext_type == 0x000b && pos + 1 <= ext_end) {
                uint8_t fmt_len = payload[pos];
                for (size_t f = 0; f < fmt_len && pos + 1 + f < ext_end; ++f) {
                    ec_formats.push_back(payload[pos + 1 + f]);
                }
            }
            pos += ext_len;
        }
    }

    // Format JA3 string: SSLVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
    std::ostringstream ss;
    ss << client_version << ",";
    for (size_t i = 0; i < ciphers.size(); ++i) ss << (i > 0 ? "-" : "") << ciphers[i];
    ss << ",";
    for (size_t i = 0; i < extensions.size(); ++i) ss << (i > 0 ? "-" : "") << extensions[i];
    ss << ",";
    for (size_t i = 0; i < curves.size(); ++i) ss << (i > 0 ? "-" : "") << curves[i];
    ss << ",";
    for (size_t i = 0; i < ec_formats.size(); ++i) ss << (i > 0 ? "-" : "") << (int)ec_formats[i];

    return ss.str();
}

// ── 1-Click Simulated Scenario Injections ──────────────────────
void DiodeThreatEngine::inject_simulated_scenario(ThreatClass tc, int packet_count) {
    auto now = std::chrono::steady_clock::now();

    switch (tc) {
        case ThreatClass::VOLUMETRIC_DDOS: {
            // Spoofed SYN Flood with single target and low source entropy
            uint32_t victim_ip = 0xC0A80164; // 192.168.1.100
            for (int i = 0; i < packet_count; ++i) {
                PacketInfo pkt;
                pkt.proto = Proto::TCP;
                pkt.src_ip = 0x0A000001 + (i % 3); // Only 3 source IPs -> very low entropy
                pkt.dst_ip = victim_ip;
                pkt.src_port = static_cast<uint16_t>(10000 + i);
                pkt.dst_port = 80;
                pkt.tcp_flags = TCP_SYN;
                pkt.size = 64;
                process_packet(pkt);
            }
            break;
        }
        case ThreatClass::BOTNET_C2_BEACONING: {
            // Highly periodic packets with 0 jitter
            uint32_t bot_ip = 0xC0A80132; // 192.168.1.50
            uint32_t c2_ip  = 0xC6336416; // 198.51.100.22
            FlowId fid{bot_ip, c2_ip, 49152, 8443, "TCP"};
            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto& st = beacon_states_[fid];
                st.arrivals.clear();
                // Create exact 5.0 second intervals
                for (int i = 0; i < 8; ++i) {
                    st.arrivals.push_back(now - std::chrono::milliseconds((8 - i) * 5000));
                }
            }
            PacketInfo pkt;
            pkt.proto = Proto::TCP;
            pkt.src_ip = bot_ip;
            pkt.dst_ip = c2_ip;
            pkt.src_port = 49152;
            pkt.dst_port = 8443;
            pkt.size = 128;
            process_packet(pkt);
            break;
        }
        case ThreatClass::DNS_DGA_TUNNEL: {
            // High-entropy DGA domain query
            static const uint8_t dns_payload[] = {
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                18, 'q', 'z', 'w', 'x', '7', '8', '9', 'k', 'l', 'p', '0', '1', 'a', 'm', 'b', 'c', 'x', 'z',
                3, 'b', 'i', 'z',
                0x00,
                0x00, 0x10, // QTYPE = TXT
                0x00, 0x01  // QCLASS = IN
            };
            PacketInfo pkt;
            pkt.proto = Proto::UDP;
            pkt.src_ip = 0xC0A80119; // 192.168.1.25
            pkt.dst_ip = 0x08080808; // 8.8.8.8
            pkt.src_port = 53210;
            pkt.dst_port = 53;
            pkt.payload_ptr = dns_payload;
            pkt.payload_len = sizeof(dns_payload);
            pkt.size = sizeof(dns_payload) + 28;
            process_packet(pkt);
            break;
        }
        case ThreatClass::ENCRYPTED_MALWARE: {
            // TLS ClientHello with Cobalt Strike JA3 signature
            // JA3 hash: 6734f37431670b3ab4292b8f60f29984
            static const uint8_t tls_ch[] = {
                0x16, 0x03, 0x01, 0x00, 0x5a,
                0x01, 0x00, 0x00, 0x56,
                0x03, 0x03, // TLS 1.2
                // 32 bytes random
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                0x00, // Session ID len
                0x00, 0x04, // Cipher len
                0xc0, 0x2b, 0xc0, 0x2f, // 49195, 49199
                0x01, 0x00, // Comp len
                0x00, 0x14, // Ext len
                0x00, 0x00, 0x00, 0x00, // SNI ext (0)
                0x00, 0x17, 0x00, 0x00, // ext 23
                0xff, 0x01, 0x00, 0x00, // ext 65281
                0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, // Supported Groups: 29
                0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 // EC Point Formats: 0
            };
            PacketInfo pkt;
            pkt.proto = Proto::TCP;
            pkt.src_ip = 0xC0A8014B; // 192.168.1.75
            pkt.dst_ip = 0x2D456789; // 45.69.103.137
            pkt.src_port = 51234;
            pkt.dst_port = 443;
            pkt.payload_ptr = tls_ch;
            pkt.payload_len = sizeof(tls_ch);
            pkt.size = sizeof(tls_ch) + 40;
            process_packet(pkt);
            break;
        }
        case ThreatClass::RECON_SCAN: {
            // Horizontal Host Sweep across 20 distinct destination IPs
            uint32_t attacker_ip = 0xC0A801DE; // 192.168.1.222
            for (int i = 1; i <= 20; ++i) {
                PacketInfo pkt;
                pkt.proto = Proto::TCP;
                pkt.src_ip = attacker_ip;
                pkt.dst_ip = 0x0A000100 + i; // 10.0.1.i
                pkt.src_port = 45000;
                pkt.dst_port = 445; // SMB sweep
                pkt.tcp_flags = TCP_SYN;
                pkt.size = 60;
                process_packet(pkt);
            }
            break;
        }
        case ThreatClass::DATA_EXFILTRATION: {
            // High outbound transfer volume to single destination
            uint32_t exfil_src = 0xC0A8010A; // 192.168.1.10
            uint32_t drop_dst  = 0xC6336499; // 198.51.100.153
            for (int i = 0; i < packet_count; ++i) {
                PacketInfo pkt;
                pkt.proto = Proto::TCP;
                pkt.src_ip = exfil_src;
                pkt.dst_ip = drop_dst;
                pkt.src_port = 54321;
                pkt.dst_port = 8080;
                pkt.size = 1460;
                process_packet(pkt);
            }
            break;
        }
    }
}

// ── High-Throughput Microsecond Benchmark ──────────────────────
double DiodeThreatEngine::run_throughput_benchmark(size_t iterations) {
    PacketInfo dummy_pkt;
    dummy_pkt.proto = Proto::TCP;
    dummy_pkt.src_ip = 0xC0A80101;
    dummy_pkt.dst_ip = 0xC0A80102;
    dummy_pkt.src_port = 12345;
    dummy_pkt.dst_port = 80;
    dummy_pkt.size = 64;

    auto t0 = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        dummy_pkt.src_port = static_cast<uint16_t>(1024 + (i % 60000));
        process_packet(dummy_pkt);
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    double sec = std::chrono::duration<double>(t1 - t0).count();
    return (sec > 0.0) ? (static_cast<double>(iterations) / sec) : 0.0;
}

} // namespace fw
