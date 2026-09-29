#pragma once
// ──────────────────────────────────────────────────────────────
//  control_plane.hpp  –  Cloud Control Plane Client
//
//  AEGIS XII Pillar 3: Distributed Cloud Control
//
//  AEGIS XII nodes periodically poll a JSON endpoint for:
//    • Updated firewall rules
//    • New geo-block CIDR ranges
//    • BVUDP magic bytes rotation
//    • Rate limit overrides
//    • Emergency shutdown signal
//
//  JSON Config Format (example):
//  {
//    "schema": 1,
//    "magic_bytes": "ae61571c70b2d4f8",  ← 8-byte hex BVUDP magic
//    "rate_limit_pps": 1000,
//    "default_policy": "BLOCK",
//    "rules": [
//      {"action":"ALLOW","proto":"TCP","src_ip":"*","dst_ip":"*",
//       "dst_port":443,"description":"HTTPS"},
//      ...
//    ],
//    "geo_blocks": [
//      {"cidr":"1.0.0.0/8","label":"APNIC Block 1"},
//      ...
//    ]
//  }
//
//  Endpoint sources (tried in order):
//    1. Remote URL  (requires httplib + network access)
//    2. Local file  config/cloud_config.json  (always works)
//
//  Thread safety: all public methods are safe to call from any thread.
// ──────────────────────────────────────────────────────────────

#include "persistence/chain_ledger.hpp"
#include "persistence/config_parser.hpp"
#include "engine/rule_engine.hpp"
#include "util/sha256.hpp"
#include "net/httplib.h"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <initializer_list>
#include <fstream>
#include <functional>
#include <limits>
#include <mutex>
#include <string>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace fw {

// ─────────────────────────────────────────────────────────────
//  CloudConfig  –  parsed snapshot from remote/local JSON
// ─────────────────────────────────────────────────────────────
struct CloudConfig {
    int          schema          = 0;
    std::string  magic_hex;             // 16-char hex BVUDP magic
    uint32_t     rate_limit_pps  = 0;   // 0 = no override
    std::string  default_policy;        // "ALLOW" | "BLOCK" | ""
    std::vector<Rule> rules;
    struct GeoEntry { std::string cidr; std::string label; };
    std::vector<GeoEntry> geo_blocks;
    bool         emergency_shutdown = false;
    std::string  config_hash;           // SHA-256 of raw JSON text
};

inline constexpr std::size_t kMaxCloudConfigBytes = 1024 * 1024;

class CloudConfigParser {
public:
    static bool parse(const std::string& text, CloudConfig& cfg) {
        if (text.empty() || text.size() > kMaxCloudConfigBytes) return false;

        try {
            bool duplicate_key = false;
            std::vector<std::unordered_set<std::string>> object_keys;
            const auto parse_event = [&](int, Json::parse_event_t event, Json& value) {
                if (event == Json::parse_event_t::object_start) {
                    object_keys.emplace_back();
                } else if (event == Json::parse_event_t::key && !object_keys.empty()) {
                    if (!object_keys.back().insert(value.get<std::string>()).second)
                        duplicate_key = true;
                } else if (event == Json::parse_event_t::object_end && !object_keys.empty()) {
                    object_keys.pop_back();
                }
                return true;
            };
            const Json root = Json::parse(text, parse_event, false);
            if (duplicate_key) return false;
            if (root.is_discarded() || !root.is_object() ||
                !has_only_keys(root, {"_comment", "schema", "magic_bytes",
                                      "rate_limit_pps", "default_policy",
                                      "rules", "geo_blocks", "emergency_shutdown"}))
                return false;

            if (!root.contains("schema") || !root["schema"].is_number_integer() ||
                root["schema"].get<int>() != 1)
                return false;

            CloudConfig parsed;
            parsed.schema = 1;
            parsed.config_hash = SHA256::to_hex(SHA256::hash(text));

            if (!optional_string(root, "_comment", nullptr) ||
                !optional_string(root, "magic_bytes", &parsed.magic_hex) ||
                !optional_string(root, "default_policy", &parsed.default_policy))
                return false;
            if (root.contains("magic_bytes") &&
                (parsed.magic_hex.size() != 16 ||
                 !std::all_of(parsed.magic_hex.begin(), parsed.magic_hex.end(),
                     [](unsigned char c) { return std::isxdigit(c) != 0; })))
                return false;
            if (!parsed.default_policy.empty() && parsed.default_policy != "ALLOW" &&
                parsed.default_policy != "BLOCK")
                return false;

            if (root.contains("rate_limit_pps")) {
                const Json& rate = root["rate_limit_pps"];
                std::uint64_t value = 0;
                if (rate.is_number_unsigned()) {
                    value = rate.get<std::uint64_t>();
                } else if (rate.is_number_integer()) {
                    const auto signed_value = rate.get<std::int64_t>();
                    if (signed_value < 0) return false;
                    value = static_cast<std::uint64_t>(signed_value);
                } else {
                    return false;
                }
                if (value > std::numeric_limits<std::uint32_t>::max()) return false;
                parsed.rate_limit_pps = static_cast<std::uint32_t>(value);
            }

            if (root.contains("emergency_shutdown")) {
                if (!root["emergency_shutdown"].is_boolean()) return false;
                parsed.emergency_shutdown = root["emergency_shutdown"].get<bool>();
            }

            if (root.contains("rules")) {
                const Json& rules = root["rules"];
                if (!rules.is_array()) return false;
                for (const auto& value : rules) {
                    Rule rule;
                    if (!parse_rule(value, rule)) return false;
                    parsed.rules.push_back(std::move(rule));
                }
            }

            if (root.contains("geo_blocks")) {
                const Json& blocks = root["geo_blocks"];
                if (!blocks.is_array()) return false;
                for (const auto& value : blocks) {
                    if (!value.is_object() ||
                        !has_only_keys(value, {"cidr", "label"}) ||
                        !value.contains("cidr") || !value["cidr"].is_string())
                        return false;
                    CloudConfig::GeoEntry entry;
                    entry.cidr = value["cidr"].get<std::string>();
                    if (entry.cidr.find('/') == std::string::npos ||
                        entry.cidr == "*" || entry.cidr == "any" ||
                        !valid_cidr(entry.cidr) ||
                        !optional_string(value, "label", &entry.label))
                        return false;
                    parsed.geo_blocks.push_back(std::move(entry));
                }
            }

            cfg = std::move(parsed);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

private:
    using Json = nlohmann::json;

    static bool has_only_keys(const Json& object,
                              std::initializer_list<const char*> allowed) {
        for (auto it = object.begin(); it != object.end(); ++it) {
            if (std::none_of(allowed.begin(), allowed.end(),
                             [&](const char* key) { return it.key() == key; }))
                return false;
        }
        return true;
    }

    static bool optional_string(const Json& object, const char* key,
                                std::string* output) {
        if (!object.contains(key)) return true;
        if (!object[key].is_string()) return false;
        if (output) *output = object[key].get<std::string>();
        return true;
    }

    static bool valid_cidr(const std::string& value) {
        if (value == "*" || value == "any") return true;
        const auto slash = value.find('/');
        if (slash != std::string::npos && value.find('/', slash + 1) != std::string::npos)
            return false;
        const std::string address = value.substr(0, slash);
        if (address.empty()) return false;
        if (ConfigParser::parse_ip(address) == 0 && address != "0.0.0.0") return false;
        if (slash == std::string::npos) return true;

        const std::string prefix_text = value.substr(slash + 1);
        if (prefix_text.empty()) return false;
        int prefix = -1;
        const auto parsed = std::from_chars(prefix_text.data(),
                                            prefix_text.data() + prefix_text.size(),
                                            prefix);
        return parsed.ec == std::errc{} &&
               parsed.ptr == prefix_text.data() + prefix_text.size() &&
               prefix >= 0 && prefix <= 32;
    }

    static bool parse_rule(const Json& value, Rule& rule) {
        if (!value.is_object() ||
            !has_only_keys(value, {"action", "proto", "src_ip", "dst_ip",
                                   "dst_port", "description"}) ||
            !value.contains("action") || !value["action"].is_string() ||
            !value.contains("proto") || !value["proto"].is_string() ||
            !value.contains("src_ip") || !value["src_ip"].is_string() ||
            !value.contains("dst_ip") || !value["dst_ip"].is_string())
            return false;

        const auto action = value["action"].get<std::string>();
        if (action == "ALLOW") rule.action = Action::ALLOW;
        else if (action == "BLOCK") rule.action = Action::BLOCK;
        else return false;

        const auto proto = value["proto"].get<std::string>();
        if (proto == "ANY") rule.proto = Proto::ANY;
        else if (proto == "TCP") rule.proto = Proto::TCP;
        else if (proto == "UDP") rule.proto = Proto::UDP;
        else if (proto == "ICMP") rule.proto = Proto::ICMP;
        else return false;

        const auto source = value["src_ip"].get<std::string>();
        const auto destination = value["dst_ip"].get<std::string>();
        if (!valid_cidr(source) || !valid_cidr(destination)) return false;
        ConfigParser::parse_ip_cidr(source, rule.src_ip, rule.src_ip_mask);
        ConfigParser::parse_ip_cidr(destination, rule.dst_ip, rule.dst_ip_mask);

        if (value.contains("dst_port")) {
            const Json& port = value["dst_port"];
            if (port.is_string() &&
                (port.get<std::string>() == "*" || port.get<std::string>() == "any")) {
                rule.dst_port_start = rule.dst_port_end = 0;
            } else if (port.is_number_unsigned()) {
                const auto number = port.get<std::uint64_t>();
                if (number > 65535) return false;
                rule.dst_port_start = rule.dst_port_end = static_cast<std::uint16_t>(number);
            } else if (port.is_number_integer()) {
                const auto number = port.get<std::int64_t>();
                if (number < 0 || number > 65535) return false;
                rule.dst_port_start = rule.dst_port_end = static_cast<std::uint16_t>(number);
            } else {
                return false;
            }
        }
        return optional_string(value, "description", &rule.description);
    }
};

// ─────────────────────────────────────────────────────────────
//  ControlPlaneClient
// ─────────────────────────────────────────────────────────────
class ControlPlaneClient {
public:
    static constexpr std::size_t kMaxConfigBytes = kMaxCloudConfigBytes;
    using OnSyncCallback = std::function<void(const CloudConfig&)>;

    explicit ControlPlaneClient(RuleEngine&     engine,
                                ChainLedger&    ledger,
                                std::string     remote_url   = "",
                                std::string     local_config = "config/cloud_config.json",
                                int             poll_sec     = 60)
        : engine_(engine), ledger_(ledger),
          remote_url_(std::move(remote_url)),
          local_config_(std::move(local_config)),
          poll_sec_(poll_sec),
          running_(false)
    {}

    ~ControlPlaneClient() { stop(); }

    // Set a callback fired after every successful sync
    void set_callback(OnSyncCallback cb) {
        std::lock_guard<std::mutex> lk(callback_mtx_);
        callback_ = std::move(cb);
    }

    // Start background polling thread
    void start() {
        std::lock_guard<std::mutex> lifecycle_lk(lifecycle_mtx_);
        if (running_.exchange(true)) return;
        const auto generation = run_generation_.fetch_add(1) + 1;
        thread_ = std::thread([this, generation]{
            sync_once();
            while (running_ && run_generation_.load() == generation) {
                for (int i = 0; i < poll_sec_ * 10 && running_ &&
                                run_generation_.load() == generation; ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (running_ && run_generation_.load() == generation) sync_once();
            }
        });
    }

    void stop() {
        std::thread worker;
        {
            std::lock_guard<std::mutex> lifecycle_lk(lifecycle_mtx_);
            running_ = false;
            run_generation_.fetch_add(1);
            if (thread_.joinable()) worker = std::move(thread_);
        }
        if (!worker.joinable()) return;
        if (worker.get_id() == std::this_thread::get_id()) {
            worker.detach();
        } else {
            worker.join();
        }
    }

    // Force an immediate sync (blocking)
    bool sync_once() {
        std::unique_lock<std::mutex> sync_lk(sync_mtx_);
        std::string json;

        // 1. Try remote URL first
        if (!remote_url_.empty()) {
            json = fetch_remote();
        }

        // 2. Fall back to local file
        if (json.empty()) {
            json = read_local_file(local_config_);
        }

        if (json.empty()) return false;

        CloudConfig cfg;
        if (!CloudConfigParser::parse(json, cfg)) return false;

        // Skip if identical to last applied config
        if (cfg.config_hash == last_hash_) return true;

        try {
            apply_config(cfg);
        } catch (const std::exception&) {
            return false;
        }
        last_hash_ = cfg.config_hash;

        ledger_.log_cloud_sync(
            remote_url_.empty() ? local_config_ : remote_url_,
            cfg.rules.size());

        sync_lk.unlock();
        OnSyncCallback callback;
        {
            std::lock_guard<std::mutex> callback_lk(callback_mtx_);
            callback = callback_;
        }
        if (callback) callback(cfg);
        return true;
    }

    std::string last_config_hash() const {
        std::lock_guard<std::mutex> lk(sync_mtx_);
        return last_hash_;
    }

private:
    RuleEngine&    engine_;
    ChainLedger&   ledger_;
    std::string    remote_url_;
    std::string    local_config_;
    int            poll_sec_;
    std::atomic<bool> running_;
    std::atomic<std::uint64_t> run_generation_{0};
    std::mutex     lifecycle_mtx_;
    std::thread    thread_;
    OnSyncCallback callback_;
    std::string    last_hash_;
    mutable std::mutex sync_mtx_;
    std::mutex callback_mtx_;
    std::mutex     apply_mtx_;
    std::vector<std::uint32_t> cloud_rule_ids_;

    // ── Remote fetch via httplib ──────────────────────────────
    std::string fetch_remote() {
        // Firewall policy is security-sensitive: never downgrade remote sync
        // to plaintext HTTP, including builds without TLS support.
        if (remote_url_.rfind("https://", 0) != 0) return "";
#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
        return "";
#else
        int backoff_ms = 1000;
        for (int attempt = 0; attempt < 3; ++attempt) {
            try {
                // Parse URL: https://host[:port]/path
                std::string url = remote_url_;
                size_t start = 8;
                size_t slash = url.find('/', start);
                std::string host = (slash == std::string::npos)
                                   ? url.substr(start)
                                   : url.substr(start, slash - start);
                std::string path = (slash == std::string::npos) ? "/" : url.substr(slash);
                int port = 443;
                auto colon = host.rfind(':');
                if (colon != std::string::npos) {
                    port = std::stoi(host.substr(colon+1));
                    host = host.substr(0, colon);
                }
                if (host.empty() || port < 1 || port > 65535) return "";

                httplib::SSLClient cli(host, port);
                cli.enable_server_certificate_verification(true);
                cli.set_connection_timeout(5);
                cli.set_read_timeout(5);
                cli.set_write_timeout(5);
                cli.set_follow_location(false);
                cli.set_payload_max_length(kMaxConfigBytes);
                auto res = cli.Get(path.c_str());
                if (res && res->status == 200) return res->body;
            } catch (...) {}
            
            // Exponential backoff
            if (attempt < 2 && running_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
                backoff_ms *= 2;
            }
        }
        return "";
#endif
    }

    // ── Local file read ───────────────────────────────────────
    static std::string read_local_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f.is_open()) return "";
        const auto end = f.tellg();
        if (end <= std::streampos(0)) return "";
        const auto size = static_cast<std::streamoff>(end);
        if (static_cast<std::uint64_t>(size) > kMaxConfigBytes) return "";
        std::string contents(static_cast<std::size_t>(size), '\0');
        f.seekg(0, std::ios::beg);
        f.read(contents.data(), static_cast<std::streamsize>(contents.size()));
        if (!f || f.gcount() != static_cast<std::streamsize>(contents.size()))
            return "";
        return contents;
    }

    // ── Apply config to running RuleEngine ───────────────────
    void apply_config(const CloudConfig& cfg) {
        std::lock_guard<std::mutex> lk(apply_mtx_);

        // Swap cloud-managed rules as one engine transaction. Local and API
        // rules are preserved; packet evaluation sees the old or new set.
        cloud_rule_ids_ = engine_.replace_rules(cloud_rule_ids_, cfg.rules);

        if (cfg.rate_limit_pps > 0)
            engine_.set_rate_limit(cfg.rate_limit_pps);

        if (cfg.default_policy == "ALLOW")
            engine_.set_default_policy(Action::ALLOW);
        else if (cfg.default_policy == "BLOCK")
            engine_.set_default_policy(Action::BLOCK);

        std::vector<GeoEntry> cloud_geo_blocks;
        cloud_geo_blocks.reserve(cfg.geo_blocks.size());
        for (const auto& g : cfg.geo_blocks) {
            auto slash = g.cidr.find('/');
            // The parser validates this input before policy application. Keep
            // conversion strict here too: silently skipping a malformed range
            // would leave a partially applied cloud policy.
            if (slash == std::string::npos)
                throw std::invalid_argument("cloud geo block must include a CIDR prefix");
            const auto net = ConfigParser::parse_ip(g.cidr.substr(0, slash));
            std::size_t consumed = 0;
            const int prefix = std::stoi(g.cidr.substr(slash + 1), &consumed);
            if (consumed != g.cidr.size() - slash - 1 || prefix < 0 || prefix > 32)
                throw std::invalid_argument("invalid cloud geo block prefix");
            const uint32_t mask = (prefix == 0) ? 0u : (~0u << (32-prefix));
            cloud_geo_blocks.push_back({net, mask, g.label.empty() ? g.cidr : g.label});
        }
        engine_.replace_cloud_geo_blocks(std::move(cloud_geo_blocks));
    }
};

} // namespace fw
