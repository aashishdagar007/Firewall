#pragma once
#include "types.hpp"
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>

// ──────────────────────────────────────────────────────────────
//  rule_engine.hpp  –  rule chain management and matching
// ──────────────────────────────────────────────────────────────

namespace fw {

    // Result of evaluating a packet against the rule chain
    struct EvalResult {
        Action      verdict;
        const Rule* matched_rule;   // nullptr = default policy or established connection
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

    // Hash function for Connection Tracking Key
    struct ConnectionKeyHash {
        std::size_t operator()(const ConnectionKey& k) const {
            return std::hash<uint32_t>()(k.src_ip) ^ 
                   (std::hash<uint32_t>()(k.dst_ip) << 1) ^
                   (std::hash<uint16_t>()(k.src_port) << 2) ^
                   (std::hash<uint16_t>()(k.dst_port) << 3) ^
                   std::hash<int>()(static_cast<int>(k.proto));
        }
    };

    // Connection Tracking State
    struct ConnectionState {
        FlowState state;
        std::chrono::steady_clock::time_point last_seen;
        uint64_t bytes_transferred = 0;
    };

    // Threat Tracking State
    struct ThreatState {
        std::chrono::steady_clock::time_point window_start;
        uint32_t packet_count = 0;
        uint32_t syn_count = 0;
        bool is_banned = false;
        std::chrono::steady_clock::time_point ban_expires;
    };

    class RuleEngine {
    public:
        // Default policy applied when no rule matches
        explicit RuleEngine(Action default_policy = Action::BLOCK);

        // Add a rule to the END of the chain
        void add_rule(Rule r);

        // Remove a rule by its id
        bool remove_rule(uint32_t id);

        // Evaluate a packet: checks stateful connections first, then rules, then default policy
        EvalResult evaluate(const PacketInfo& pkt);

        // Read-only access to the rule list (for printing / debugging)
        const std::vector<Rule>& rules() const { return rules_; }

        // Print the full rule table to stdout
        void print_rules() const;

        // Cleanup stale connections from the state table
        void purge_stale_connections(std::chrono::seconds timeout = std::chrono::seconds(300));

    private:
        std::vector<Rule> rules_;
        Action            default_policy_;
        uint32_t          next_id_ = 1;

        // Connection Tracking Table
        std::unordered_map<ConnectionKey, ConnectionState, ConnectionKeyHash> state_table_;
        
        // Threat Detection Table
        std::unordered_map<uint32_t, ThreatState> threat_table_; // src_ip -> state
        Rule threat_rule_{0, Action::BLOCK, Proto::ANY, Direction::ANY, 0, 0, 0, 0, "Threat Detected (Auto-Block)", 0};
        
        static constexpr uint32_t MAX_PACKETS_PER_SEC = 200;
        static constexpr std::chrono::seconds BAN_DURATION{300}; // 5 minutes

        std::mutex state_mtx_;

        static bool matches(const Rule& rule, const PacketInfo& pkt);
    };

} // namespace fw