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

#include "chain_ledger.hpp"
#include "config_parser.hpp"
#include "rule_engine.hpp"
#include "sha256.hpp"
#include "httplib.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
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

// ─────────────────────────────────────────────────────────────
//  ControlPlaneClient
// ─────────────────────────────────────────────────────────────
class ControlPlaneClient {
public:
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
    void set_callback(OnSyncCallback cb) { callback_ = std::move(cb); }

    // Start background polling thread
    void start() {
        if (running_) return;
        running_ = true;
        // Sync immediately on first start
        sync_once();
        thread_ = std::thread([this]{
            while (running_) {
                for (int i = 0; i < poll_sec_ * 10 && running_; ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (running_) sync_once();
            }
        });
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }

    // Force an immediate sync (blocking)
    bool sync_once() {
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
        if (!parse_json(json, cfg)) return false;

        // Skip if identical to last applied config
        if (cfg.config_hash == last_hash_) return true;

        apply_config(cfg);
        last_hash_ = cfg.config_hash;

        ledger_.log_cloud_sync(
            remote_url_.empty() ? local_config_ : remote_url_,
            cfg.rules.size());

        if (callback_) callback_(cfg);
        return true;
    }

    const std::string& last_config_hash() const { return last_hash_; }

private:
    RuleEngine&    engine_;
    ChainLedger&   ledger_;
    std::string    remote_url_;
    std::string    local_config_;
    int            poll_sec_;
    std::atomic<bool> running_;
    std::thread    thread_;
    OnSyncCallback callback_;
    std::string    last_hash_;
    std::mutex     apply_mtx_;

    // ── Remote fetch via httplib ──────────────────────────────
    std::string fetch_remote() {
        int backoff_ms = 1000;
        for (int attempt = 0; attempt < 3; ++attempt) {
            try {
                // Parse URL: http://host[:port]/path
                std::string url = remote_url_;
                bool https = url.find("https://") == 0;
                size_t start = https ? 8 : 7;
                size_t slash = url.find('/', start);
                std::string host = (slash == std::string::npos)
                                   ? url.substr(start)
                                   : url.substr(start, slash - start);
                std::string path = (slash == std::string::npos) ? "/" : url.substr(slash);
                int port = https ? 443 : 80;
                auto colon = host.rfind(':');
                if (colon != std::string::npos) {
                    port = std::stoi(host.substr(colon+1));
                    host = host.substr(0, colon);
                }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
                if (https) {
                    httplib::SSLClient cli(host, port);
                    cli.set_connection_timeout(5);
                    auto res = cli.Get(path.c_str());
                    if (res && res->status == 200) return res->body;
                } else
#endif
                {
                    httplib::Client cli(host, port);
                    cli.set_connection_timeout(5);
                    auto res = cli.Get(path.c_str());
                    if (res && res->status == 200) return res->body;
                }
            } catch (...) {}
            
            // Exponential backoff
            if (attempt < 2 && running_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
                backoff_ms *= 2;
            }
        }
        return "";
    }

    // ── Local file read ───────────────────────────────────────
    static std::string read_local_file(const std::string& path) {
        std::ifstream f(path);
        if (!f.is_open()) return "";
        return std::string(std::istreambuf_iterator<char>(f),
                           std::istreambuf_iterator<char>());
    }

    // ── Minimal JSON parser ───────────────────────────────────
    // Hand-rolled to avoid external JSON dependencies.
    static bool parse_json(const std::string& json, CloudConfig& cfg) {
        if (json.empty()) return false;

        // Compute fingerprint
        cfg.config_hash = SHA256::to_hex(SHA256::hash(json));

        auto get_str = [&](const std::string& key) -> std::string {
            std::string search = "\"" + key + "\":\"";
            auto pos = json.find(search);
            if (pos == std::string::npos) return "";
            pos += search.size();
            auto end = json.find('"', pos);
            return (end == std::string::npos) ? "" : json.substr(pos, end - pos);
        };
        auto get_int = [&](const std::string& key) -> int {
            std::string search = "\"" + key + "\":";
            auto pos = json.find(search);
            if (pos == std::string::npos) return 0;
            pos += search.size();
            try { return std::stoi(json.substr(pos)); } catch (...) { return 0; }
        };
        auto get_bool = [&](const std::string& key) -> bool {
            std::string search = "\"" + key + "\":";
            auto pos = json.find(search);
            if (pos == std::string::npos) return false;
            pos += search.size();
            while (pos < json.size() && std::isspace(json[pos])) ++pos;
            return json.substr(pos, 4) == "true";
        };

        cfg.schema           = get_int("schema");
        if (cfg.schema != 1) return false; // Strict schema validation

        cfg.magic_hex        = get_str("magic_bytes");
        cfg.rate_limit_pps   = static_cast<uint32_t>(get_int("rate_limit_pps"));
        cfg.default_policy   = get_str("default_policy");
        cfg.emergency_shutdown = get_bool("emergency_shutdown");

        // Parse rules array
        auto rules_start = json.find("\"rules\"");
        if (rules_start != std::string::npos) {
            auto arr_start = json.find('[', rules_start);
            auto arr_end   = json.find(']', arr_start);
            if (arr_start != std::string::npos && arr_end != std::string::npos) {
                std::string arr = json.substr(arr_start+1, arr_end - arr_start - 1);
                parse_rules_array(arr, cfg.rules);
            }
        }

        // Parse geo_blocks array
        auto geo_start = json.find("\"geo_blocks\"");
        if (geo_start != std::string::npos) {
            auto arr_start = json.find('[', geo_start);
            auto arr_end   = json.find(']', arr_start);
            if (arr_start != std::string::npos && arr_end != std::string::npos) {
                std::string arr = json.substr(arr_start+1, arr_end - arr_start - 1);
                parse_geo_array(arr, cfg.geo_blocks);
            }
        }

        return true;
    }

    static void parse_rules_array(const std::string& arr,
                                  std::vector<Rule>& out) {
        // Find each {...} object in the array
        size_t pos = 0;
        while (pos < arr.size()) {
            auto ob = arr.find('{', pos);
            if (ob == std::string::npos) break;
            auto oe = arr.find('}', ob);
            if (oe == std::string::npos) break;
            std::string obj = arr.substr(ob+1, oe - ob - 1);
            pos = oe + 1;

            auto gf = [&](const std::string& k) -> std::string {
                std::string s = "\"" + k + "\":\"";
                auto p = obj.find(s);
                if (p == std::string::npos) return "";
                p += s.size();
                auto e = obj.find('"', p);
                return (e == std::string::npos) ? "" : obj.substr(p, e-p);
            };
            auto gi = [&](const std::string& k) -> int {
                std::string s = "\"" + k + "\":";
                auto p = obj.find(s);
                if (p == std::string::npos) return 0;
                p += s.size();
                if (p < obj.size() && obj[p] == '"') {
                    p++;
                    auto e = obj.find('"', p);
                    if (e != std::string::npos && obj.substr(p, e-p) == "*") return 0;
                }
                try { return std::stoi(obj.substr(p)); } catch (...) { return 0; }
            };

            try {
                Rule r;
                r.action      = ConfigParser::parse_action(gf("action"));
                r.proto       = ConfigParser::parse_proto(gf("proto"));
                r.src_ip      = ConfigParser::parse_ip(gf("src_ip"));
                r.dst_ip      = ConfigParser::parse_ip(gf("dst_ip"));
                r.dst_port    = static_cast<uint16_t>(gi("dst_port"));
                r.description = gf("description");
                out.push_back(std::move(r));
            } catch (...) {}
        }
    }

    static void parse_geo_array(const std::string& arr,
                                std::vector<CloudConfig::GeoEntry>& out) {
        size_t pos = 0;
        while (pos < arr.size()) {
            auto ob = arr.find('{', pos);
            if (ob == std::string::npos) break;
            auto oe = arr.find('}', ob);
            if (oe == std::string::npos) break;
            std::string obj = arr.substr(ob+1, oe - ob - 1);
            pos = oe + 1;
            auto gf = [&](const std::string& k) -> std::string {
                std::string s = "\"" + k + "\":\"";
                auto p = obj.find(s);
                if (p == std::string::npos) return "";
                p += s.size();
                auto e = obj.find('"', p);
                return (e == std::string::npos) ? "" : obj.substr(p, e-p);
            };
            CloudConfig::GeoEntry g;
            g.cidr  = gf("cidr");
            g.label = gf("label");
            if (!g.cidr.empty()) out.push_back(std::move(g));
        }
    }

    // ── Apply config to running RuleEngine ───────────────────
    void apply_config(const CloudConfig& cfg) {
        std::lock_guard<std::mutex> lk(apply_mtx_);

        if (cfg.rate_limit_pps > 0)
            engine_.set_rate_limit(cfg.rate_limit_pps);

        if (cfg.default_policy == "ALLOW")
            engine_.set_default_policy(Action::ALLOW);
        else if (cfg.default_policy == "BLOCK")
            engine_.set_default_policy(Action::BLOCK);

        for (auto& r : cfg.rules) {
            Rule copy = r;
            engine_.add_rule(std::move(copy));
        }

        for (auto& g : cfg.geo_blocks) {
            auto slash = g.cidr.find('/');
            if (slash == std::string::npos) continue;
            try {
                uint32_t net = ConfigParser::parse_ip(g.cidr.substr(0, slash));
                int prefix   = std::stoi(g.cidr.substr(slash+1));
                if (prefix < 0 || prefix > 32) continue;
                uint32_t mask = (prefix == 0) ? 0u : (~0u << (32-prefix));
                engine_.block_cidr(net, mask, g.label.empty() ? g.cidr : g.label);
            } catch (...) {}
        }
    }
};

} // namespace fw
