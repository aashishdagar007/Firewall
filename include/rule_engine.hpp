#pragma once
#include "types.hpp"
#include "port_scan_detector.hpp"
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <thread>
#include <atomic>
#include <shared_mutex>
#include <functional>
#include "dpi_engine.hpp"

// ──────────────────────────────────────────────────────────────
//  rule_engine.hpp  –  rule chain management and matching
// ──────────────────────────────────────────────────────────────

namespace fw {

    // Result of evaluating a packet against the rule chain
    struct EvalResult {
        Action      verdict;
        const Rule* matched_rule;   // nullptr = default policy or established connection
    };

    // CIDR geo-block entry
    struct GeoEntry {
        uint32_t    network;  // network address (host byte order)
        uint32_t    mask;     // subnet mask (host byte order)
        std::string label;    // human-readable label e.g. "CN 1.0.0.0/8"
    };

    // Snapshot of a banned IP for the dashboard
    struct ThreatSnapshot {
        uint32_t    src_ip;
        std::string ip_str;
        std::string reason;
        uint32_t    ban_count;
        std::chrono::steady_clock::time_point ban_expires;
    };

    // Snapshot of a single anomaly rule hit count
    struct AnomalySnapshot {
        std::string name;       // human-readable anomaly label
        uint32_t    hit_count;  // cumulative hits since startup
    };

    // Snapshot of a single live connection flow
    struct ConnectionSnapshot {
        std::string src_ip;
        std::string dst_ip;
        uint16_t    src_port;
        uint16_t    dst_port;
        std::string proto;      // "TCP", "UDP", "ICMP"
        std::string state;      // "NEW" or "ESTABLISHED"
        uint64_t    bytes_in;
        uint64_t    bytes_out;
        uint64_t    bytes_total;
        double      age_sec;    // seconds since last seen
    };

    // Connection Tracking Key (5-tuple)
    struct ConnectionKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        Proto    proto;

        bool operator==(const ConnectionKey& o) const {
            return src_ip == o.src_ip && dst_ip == o.dst_ip &&
                   src_port == o.src_port && dst_port == o.dst_port &&
                   proto == o.proto;
        }
    };

    // Hash function for Connection Tracking Key (FNV-1a)
    struct ConnectionKeyHash {
        std::size_t operator()(const ConnectionKey& k) const noexcept {
            std::size_t h = 14695981039346656037ULL;
            auto mix = [&](std::size_t v){ h ^= v; h *= 1099511628211ULL; };
            mix(k.src_ip); mix(k.dst_ip);
            mix(k.src_port); mix(k.dst_port);
            mix(static_cast<int>(k.proto));
            return h;
        }
    };

    struct ConnectionState {
        FlowState state;
        std::chrono::steady_clock::time_point last_seen;
        uint32_t originator_ip;
        uint64_t bytes_transferred = 0;
        uint64_t bytes_out = 0; // from originator
        uint64_t bytes_in = 0;  // to originator
        uint32_t expected_seq = 0;
        uint32_t expected_ack = 0;
    };

    // Threat Tracking State
    struct ThreatState {
        std::chrono::steady_clock::time_point window_start;
        uint32_t packet_count = 0;
        uint32_t syn_count = 0;
        uint32_t udp_count = 0;
        uint32_t icmp_count = 0;
        uint32_t ban_count = 0; // Number of times banned
        bool is_banned = false;
        std::chrono::steady_clock::time_point ban_expires;
    };

    class RuleEngine {
    public:
        // Default policy applied when no rule matches
        explicit RuleEngine(Action default_policy = Action::BLOCK);
        ~RuleEngine();

        // Add a rule to the END of the chain
        void add_rule(Rule r);

        // Remove a rule by its id
        bool remove_rule(uint32_t id);

        // Evaluate a packet: checks stateful connections first, then rules, then default policy
        EvalResult evaluate(const PacketInfo& pkt);

        // Set default policy dynamically
        void set_default_policy(Action a);

        // Set local IP to bypass Bogon check for local outbound
        void set_local_ip(uint32_t ip);

        // Read-only access to the rule list (for printing / debugging)
        const std::vector<Rule>& rules() const { return rules_; }

        // Print the full rule table to stdout
        void print_rules() const;

        // Cleanup stale connections from the state table
        void purge_stale_connections(std::chrono::seconds timeout = std::chrono::seconds(300));

        // ── Rate Limiting ─────────────────────────────────────────────────
        void set_rate_limit(uint32_t pps);      // set packets-per-second threshold
        uint32_t get_rate_limit() const;         // read current threshold

        // ── Geo-Blocking (CIDR) ───────────────────────────────────────────
        void block_cidr(uint32_t network, uint32_t mask, const std::string& label);
        bool unblock_cidr(size_t index);         // remove by index
        std::vector<GeoEntry> get_geo_blocks() const;

        // ── Threat Table ─────────────────────────────────────────────────
        std::vector<ThreatSnapshot> get_threat_table_snapshot() const;
        bool ban_ip(uint32_t src_ip, const std::string& reason); // manually ban an IP
        bool unban_ip(uint32_t src_ip);          // manually lift a ban
        
        // ── Active Threat Ban ─────────────────────────────────────────────
        void report_tampering_attempt(uint32_t src_ip); // instantly severe-ban IP

        // ── Anomaly & Connection Analytics ───────────────────────────────
        std::vector<AnomalySnapshot>    get_anomaly_snapshot()    const;
        std::vector<ConnectionSnapshot> get_connection_snapshot() const;

        // ── Stealth Mode (silent drop — no RST/ICMP sent back) ────────────
        void set_stealth_mode(bool enabled);
        bool get_stealth_mode() const { return stealth_mode_.load(); }

        // ── Port Scan Detection ───────────────────────────────────────────
        // Register callback fired whenever a port scan is detected.
        // Callback is invoked from within evaluate() — keep it fast.
        void set_scan_callback(std::function<void(ScanEvent)> cb);

        // Snapshot of recent scan events (for the API)
        std::vector<ScanEvent> get_scan_events() const;

    private:
        std::vector<Rule> rules_;
        Action            default_policy_;
        uint32_t          next_id_ = 1;

        // Connection Tracking Table
        std::unordered_map<ConnectionKey, ConnectionState, ConnectionKeyHash> state_table_;
        
        // Threat Detection Table
        std::unordered_map<uint32_t, ThreatState> threat_table_; // src_ip -> state

        // ── Performance: port-indexed rule lookup ─────────────────────────
        // Maps dst_port -> index into rules_. Port 0 entries = wildcard rules.
        std::unordered_multimap<uint16_t, size_t> port_index_;
        std::vector<size_t> wildcard_rule_indices_; // rules with dst_port == 0
        void rebuild_port_index();

        // ── Geo-Block list (sorted for binary search) ─────────────────────
        std::vector<GeoEntry> geo_blocks_;
        bool is_geo_blocked(uint32_t ip) const; // internal check

        // ── Configurable rate limit ───────────────────────────────────────
        std::atomic<uint32_t> rate_limit_pps_{1000};
        
        // Static rule instances promoted to members to avoid data races
        Rule anomaly_land_{0, Action::BLOCK, Proto::ANY, Direction::ANY, 0, 0, 0, 0, "Anomaly: Land Attack (src == dst)", 0};
        Rule anomaly_ttl_{0, Action::BLOCK, Proto::ANY, Direction::ANY, 0, 0, 0, 0, "Anomaly: Unusually low TTL (< 5)", 0};
        Rule anomaly_bogon_{0, Action::BLOCK, Proto::ANY, Direction::ANY, 0, 0, 0, 0, "Anomaly: Spoofed/Bogon Source IP", 0};
        Rule anomaly_frag_{0, Action::BLOCK, Proto::ANY, Direction::ANY, 0, 0, 0, 0, "Anomaly: IP Fragmentation not supported", 0};
        Rule anomaly_icmp_{0, Action::BLOCK, Proto::ICMP, Direction::ANY, 0, 0, 0, 0, "Anomaly: Invalid ICMP Type/Code", 0};
        Rule anomaly_tcp_null_{0, Action::BLOCK, Proto::TCP, Direction::ANY, 0, 0, 0, 0, "Anomaly: TCP NULL Scan", 0};
        Rule anomaly_tcp_fin_{0, Action::BLOCK, Proto::TCP, Direction::ANY, 0, 0, 0, 0, "Anomaly: TCP FIN Scan (No ACK)", 0};
        Rule anomaly_tcp_xmas_{0, Action::BLOCK, Proto::TCP, Direction::ANY, 0, 0, 0, 0, "Anomaly: TCP XMAS Scan", 0};
        Rule anomaly_tcp_synfin_{0, Action::BLOCK, Proto::TCP, Direction::ANY, 0, 0, 0, 0, "Anomaly: TCP SYN-FIN combination", 0};
        Rule anomaly_tcp_synrst_{0, Action::BLOCK, Proto::TCP, Direction::ANY, 0, 0, 0, 0, "Anomaly: TCP SYN-RST combination", 0};
        Rule anomaly_tcp_syn_flags_{0, Action::BLOCK, Proto::TCP, Direction::ANY, 0, 0, 0, 0, "Anomaly: TCP SYN with PSH/URG", 0};
        Rule anomaly_tcp_syn_data_{0, Action::BLOCK, Proto::TCP, Direction::ANY, 0, 0, 0, 0, "Anomaly: TCP SYN contains payload", 0};
        Rule anomaly_udp_dns_{0, Action::BLOCK, Proto::UDP, Direction::ANY, 0, 0, 0, 0, "Anomaly: Oversized DNS UDP packet", 0};
        Rule anomaly_udp_flood_{0, Action::BLOCK, Proto::UDP, Direction::ANY, 0, 0, 0, 0, "Anomaly: UDP Flood Detected", 0};
        Rule anomaly_icmp_flood_{0, Action::BLOCK, Proto::ICMP, Direction::ANY, 0, 0, 0, 0, "Anomaly: ICMP (Ping) Flood Detected", 0};
        Rule anomaly_port_zero_{0, Action::BLOCK, Proto::ANY, Direction::ANY, 0, 0, 0, 0, "Anomaly: Traffic to/from Port 0", 0};

        Rule invalid_rule_{0, Action::BLOCK, Proto::TCP, Direction::ANY, 0, 0, 0, 0, "INVALID TCP State (Auto-Drop)", 0};
        Rule hijack_rule_{0, Action::BLOCK, Proto::TCP, Direction::ANY, 0, 0, 0, 0, "Hijack Attempt (Seq Out of Window)", 0};
        Rule dpi_rule_{0, Action::BLOCK, Proto::ANY, Direction::ANY, 0, 0, 0, 0, "DPI: Threat signature match", 0};
        Rule threat_rule_{0, Action::BLOCK, Proto::ANY, Direction::ANY, 0, 0, 0, 0, "Threat Detected (Auto-Block)", 0};
        
        static constexpr uint32_t MAX_PACKETS_PER_SEC = 1000;
        static constexpr std::chrono::seconds BAN_DURATION{300}; // 5 minutes

        mutable std::mutex state_mtx_;
        mutable std::shared_mutex rules_mtx_;
        DpiEngine  dpi_;
        uint32_t local_ip_ = 0;

        // ── Stealth Mode ──────────────────────────────────────────────────
        // When true, the capture layer must drop packets silently (no RST).
        // The API server reads this flag to set the appropriate WinDivert
        // verdict (DROP vs REJECT).
        std::atomic<bool> stealth_mode_{true}; // ON by default

        // ── Port Scan Detector ────────────────────────────────────────────
        PortScanDetector            scan_detector_;
        std::function<void(ScanEvent)> scan_callback_;

        std::thread heuristic_thread_;
        std::atomic<bool> stop_heuristics_{false};

        void heuristic_worker();
        static bool matches(const Rule& rule, const PacketInfo& pkt);
    };

} // namespace fw