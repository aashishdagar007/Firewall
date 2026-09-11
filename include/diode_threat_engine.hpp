#pragma once
#include "diode_types.hpp"
#include "packet.hpp"
#include <vector>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <functional>
#include <memory>
#include <atomic>

namespace fw {

class ChainLedger; // Forward declaration

class DiodeThreatEngine {
public:
    DiodeThreatEngine(ChainLedger* ledger = nullptr);
    ~DiodeThreatEngine() = default;

    // ── Passive Streaming Ingest ───────────────────────────────
    // Evaluates a single passive packet incrementally with bounded latency
    void process_packet(const PacketInfo& pkt);

    // ── Mode Toggle ───────────────────────────────────────────
    void set_diode_mode(bool active) { diode_mode_active_ = active; }
    bool is_diode_mode() const { return diode_mode_active_; }

    // ── Alert Callbacks & Queries ─────────────────────────────
    using AlertCallback = std::function<void(const DiodeAlert&)>;
    void set_alert_callback(AlertCallback cb) { alert_cb_ = std::move(cb); }

    std::vector<DiodeAlert> get_recent_alerts(size_t limit = 100) const;
    DiodeTelemetry get_telemetry() const;
    std::unordered_map<std::string, uint64_t> get_threat_summary() const;
    void clear_alerts();

    // ── Throughput Benchmark & Test Injections ────────────────
    void inject_simulated_scenario(ThreatClass tc, int packet_count = 50);
    double run_throughput_benchmark(size_t iterations = 100000);

private:
    // ── Internal Threat Analyzers ─────────────────────────────
    void analyze_volumetric_ddos(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now);
    void analyze_botnet_beaconing(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now);
    void analyze_dns_dga_tunnel(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now);
    void analyze_encrypted_malware(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now);
    void analyze_reconnaissance(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now);
    void analyze_data_exfiltration(const PacketInfo& pkt, const std::chrono::steady_clock::time_point& now);

    // Helper to emit alert with deduplication cooldown
    void emit_alert(DiodeAlert alert);

    // ── Math & Heuristic Utilities ────────────────────────────
    static double calculate_shannon_entropy(const std::string& str);
    static double calculate_consonant_vowel_ratio(const std::string& domain);
    static double calculate_bigram_perplexity(const std::string& domain);
    static std::string extract_tls_ja3(const uint8_t* payload, uint16_t len);
    static std::string parse_dns_qname(const uint8_t* payload, uint16_t len, uint16_t& qtype);

    // ── State Structures ──────────────────────────────────────
    ChainLedger* ledger_ = nullptr;
    std::atomic<bool> diode_mode_active_{true};
    AlertCallback alert_cb_;

    mutable std::mutex mtx_;
    std::deque<DiodeAlert> alerts_;
    static constexpr size_t MAX_ALERTS = 500;

    // Telemetry stats
    std::atomic<uint64_t> total_packets_{0};
    std::atomic<uint64_t> total_bytes_{0};
    std::atomic<uint64_t> total_alerts_raised_{0};
    uint64_t threat_counts_[6] = {0, 0, 0, 0, 0, 0};
    std::chrono::steady_clock::time_point start_time_;

    // Volumetric DDoS state: rolling window of source IPs
    struct DDoSTracker {
        std::deque<std::pair<uint32_t, std::chrono::steady_clock::time_point>> src_ip_window;
        std::unordered_map<uint32_t, size_t> ip_frequency;
        size_t syn_count = 0;
        size_t ack_count = 0;
        std::chrono::steady_clock::time_point last_alert;
    } ddos_state_;

    // Botnet C2 Beaconing state per flow
    struct BeaconFlowState {
        std::deque<std::chrono::steady_clock::time_point> arrivals;
        std::chrono::steady_clock::time_point last_alert;
        size_t packet_count = 0;
    };
    std::unordered_map<FlowId, BeaconFlowState, FlowIdHash> beacon_states_;

    // Reconnaissance Fan-Out state
    struct ReconState {
        std::unordered_set<uint16_t> dst_ports;
        std::unordered_set<uint32_t> dst_ips;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_alert;
    };
    std::unordered_map<uint32_t, ReconState> recon_states_;

    // Data Exfiltration state: per internal host tracking
    struct ExfilState {
        uint64_t bytes_out = 0;
        uint64_t bytes_in  = 0;
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_alert;
    };
    std::unordered_map<uint32_t, ExfilState> exfil_states_;

    // Alert deduplication: hash of (threat_class, src_ip, dst_ip) -> last_time
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> alert_cooldowns_;
};

} // namespace fw
