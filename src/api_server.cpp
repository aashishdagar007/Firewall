#include "api_server.hpp"
#include "packet.hpp"
#include "platform.hpp"   // cross-platform inet helpers
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <random>
#include <fstream>
#include <filesystem>

// cpp-httplib — header-only, single include
#include "httplib.h"

// ──────────────────────────────────────────────────────────────
//  api_server.cpp
//
//  REST API server for the live firewall dashboard.
//  All JSON is hand-built (no external JSON library needed).
// ──────────────────────────────────────────────────────────────

namespace fw {

ApiServer::ApiServer(RuleEngine& engine,
                     LiveStats& stats,
                     RingBuffer<PacketRecord>& ring,
                     ProcessMonitor& proc_mon,
                     const std::string& dashboard_root,
                     int port)
    : engine_(engine), stats_(stats), ring_(ring),
      proc_mon_(proc_mon),
      dashboard_root_(dashboard_root), port_(port),
      server_(std::make_unique<httplib::Server>()) {
    
    api_token_ = generate_token();
    
    // Ensure logs directory exists
    std::filesystem::create_directories("logs");
    
    std::ofstream out("logs/api.token");
    if (out.is_open()) {
        out << api_token_ << "\n";
    }
    
    std::cout << "\n======================================================\n";
    std::cout << "  API Token Generated: " << api_token_ << "\n";
    std::cout << "  (Saved to logs/api.token)\n";
    std::cout << "======================================================\n\n";
}

ApiServer::~ApiServer() { stop(); }

void ApiServer::start() {
    setup_routes();
    running_ = true;
    thread_ = std::thread([this]() {
        std::cout << "[API] Dashboard at http://localhost:" << port_ << "\n";
        server_->listen("0.0.0.0", port_);
        running_ = false;
    });
}

void ApiServer::stop() {
    if (running_) {
        server_->stop();
        if (thread_.joinable()) thread_.join();
        running_ = false;
    }
}

// ── Route setup ───────────────────────────────────────────────

void ApiServer::setup_routes() {
    // CORS headers for all responses
    auto cors = [](httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin",  "*");
        res.set_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
    };

    // Preflight and Authorization middleware
    server_->set_pre_routing_handler([this, cors](const httplib::Request& req, httplib::Response& res) {
        if (req.method == "OPTIONS") {
            cors(res);
            res.status = 204;
            return httplib::Server::HandlerResponse::Handled;
        }
        
        // Protect all /api/ routes
        if (req.path.find("/api/") == 0) {
            auto it = req.headers.find("Authorization");
            if (it == req.headers.end() || it->second != "Bearer " + api_token_) {
                cors(res);
                res.status = 401;
                res.set_content("{\"error\":\"Unauthorized - Invalid or missing Bearer token\"}", "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // ── GET /api/stats ─────────────────────────────────────────
    server_->Get("/api/stats", [this, cors](const httplib::Request&, httplib::Response& res) {
        cors(res);
        res.set_content(handle_stats(), "application/json");
    });

    // ── GET /api/packets?n=100 ─────────────────────────────────
    server_->Get("/api/packets", [this, cors](const httplib::Request& req, httplib::Response& res) {
        cors(res);
        int n = 100;
        if (req.has_param("n")) {
            try { n = std::stoi(req.get_param_value("n")); } catch (...) {}
        }
        res.set_content(handle_packets(n), "application/json");
    });

    // ── GET /api/rules ─────────────────────────────────────────
    server_->Get("/api/rules", [this, cors](const httplib::Request&, httplib::Response& res) {
        cors(res);
        res.set_content(handle_get_rules(), "application/json");
    });

    // ── POST /api/rules ────────────────────────────────────────
    server_->Post("/api/rules", [this, cors](const httplib::Request& req, httplib::Response& res) {
        cors(res);
        std::string body = handle_add_rule(req.body);
        res.set_content(body, "application/json");
    });

    // ── DELETE /api/rules/:id ──────────────────────────────────
    server_->Delete(R"(/api/rules/(\d+))", [this, cors](const httplib::Request& req, httplib::Response& res) {
        cors(res);
        uint32_t id = std::stoul(req.matches[1].str());
        bool ok = handle_delete_rule(id);
        res.set_content(ok ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"not found\"}",
                        "application/json");
        if (!ok) res.status = 404;
    });

    // ── POST /api/policy ───────────────────────────────────────
    server_->Post("/api/policy", [this, cors](const httplib::Request& req, httplib::Response& res) {
        cors(res);
        res.set_content(handle_set_policy(req.body), "application/json");
    });

    // ── GET /api/processes ───────────────────────────────────
    server_->Get("/api/processes", [this, cors](const httplib::Request&, httplib::Response& res) {
        cors(res);
        res.set_content(handle_processes(), "application/json");
    });

    // ── GET /api/processes/tabs ──────────────────────────────
    server_->Get("/api/processes/tabs", [this, cors](const httplib::Request&, httplib::Response& res) {
        cors(res);
        res.set_content(handle_browser_tabs(), "application/json");
    });

    // ── POST /api/apps/block ──────────────────────────────────
    server_->Post("/api/apps/block", [this, cors](const httplib::Request& req, httplib::Response& res) {
        cors(res);
        res.set_content(handle_block_app(req.body), "application/json");
    });

    // ── POST /api/apps/allow ──────────────────────────────────
    server_->Post("/api/apps/allow", [this, cors](const httplib::Request& req, httplib::Response& res) {
        cors(res);
        res.set_content(handle_allow_app(req.body), "application/json");
    });

    // ── Static file serving (dashboard) ────────────────────────
    if (!dashboard_root_.empty()) {
        server_->set_mount_point("/", dashboard_root_);
    }

    // ── Fallback 404 ──────────────────────────────────────
    server_->set_error_handler([cors](const httplib::Request&, httplib::Response& res) {
        cors(res);
        res.set_content("{\"error\":\"not found\"}", "application/json");
    });
}

// ── Handler implementations ───────────────────────────────────

std::string ApiServer::generate_token() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    const char* hex = "0123456789abcdef";
    std::string token;
    for (int i = 0; i < 32; ++i) token += hex[dis(gen)];
    return token;
}

std::string ApiServer::handle_stats() const {
    std::ostringstream o;
    o << "{"
      << "\"total\":"       << stats_.total.load()       << ","
      << "\"allowed\":"     << stats_.allowed.load()     << ","
      << "\"blocked\":"     << stats_.blocked.load()     << ","
      << "\"tcp\":"         << stats_.tcp.load()         << ","
      << "\"udp\":"         << stats_.udp.load()         << ","
      << "\"icmp\":"        << stats_.icmp.load()        << ","
#if defined(HAVE_WINDIVERT) || defined(HAVE_NFQUEUE)
      << "\"enforcement_mode\":true,"
#else
      << "\"enforcement_mode\":false,"
#endif
      << "\"bytes_total\":" << stats_.bytes_total.load()
      << "}";
    return o.str();
}

std::string ApiServer::handle_packets(int n) const {
    auto records = ring_.tail(static_cast<size_t>(n));
    std::ostringstream o;
    o << "[";
    for (size_t i = 0; i < records.size(); ++i) {
        if (i) o << ",";
        o << record_to_json(records[i]);
    }
    o << "]";
    return o.str();
}

std::string ApiServer::handle_get_rules() const {
    std::lock_guard<std::mutex> lock(engine_mtx_);
    const auto& rules = engine_.rules();
    std::ostringstream o;
    o << "[";
    for (size_t i = 0; i < rules.size(); ++i) {
        if (i) o << ",";
        o << rule_to_json(rules[i]);
    }
    o << "]";
    return o.str();
}

std::string ApiServer::handle_add_rule(const std::string& body) {
    // Simple JSON parse — expects:
    // {"action":"ALLOW","proto":"TCP","src_ip":"*","dst_ip":"*","dst_port":443,"description":"HTTPS"}
    auto get_field = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":\"";
        auto pos = body.find(search);
        if (pos == std::string::npos) return "";
        pos += search.size();
        auto end = body.find('"', pos);
        return (end == std::string::npos) ? "" : body.substr(pos, end - pos);
    };
    auto get_int_field = [&](const std::string& key) -> int {
        std::string search = "\"" + key + "\":";
        auto pos = body.find(search);
        if (pos == std::string::npos) return 0;
        pos += search.size();
        // skip quotes if present
        if (pos < body.size() && body[pos] == '"') pos++;
        int val = 0;
        try { val = std::stoi(body.substr(pos)); } catch (...) {}
        return val;
    };

    Rule r;
    std::string action_s = get_field("action");
    std::string proto_s  = get_field("proto");
    std::string src_ip_s = get_field("src_ip");
    std::string dst_ip_s = get_field("dst_ip");
    std::string desc     = get_field("description");
    int dst_port         = get_int_field("dst_port");

    r.action = (action_s == "ALLOW") ? Action::ALLOW : Action::BLOCK;

    if      (proto_s == "TCP")  r.proto = Proto::TCP;
    else if (proto_s == "UDP")  r.proto = Proto::UDP;
    else if (proto_s == "ICMP") r.proto = Proto::ICMP;
    else                        r.proto = Proto::ANY;

    auto parse_ip = [](const std::string& s) -> uint32_t {
        if (s.empty() || s == "*" || s == "any") return 0;
        return string_to_ip4(s.c_str());
    };

    r.src_ip      = parse_ip(src_ip_s);
    r.dst_ip      = parse_ip(dst_ip_s);
    r.dst_port    = static_cast<uint16_t>(dst_port);
    r.description = desc;

    {
        std::lock_guard<std::mutex> lock(engine_mtx_);
        engine_.add_rule(std::move(r));
    }

    return "{\"ok\":true}";
}

bool ApiServer::handle_delete_rule(uint32_t id) {
    std::lock_guard<std::mutex> lock(engine_mtx_);
    return engine_.remove_rule(id);
}

std::string ApiServer::handle_set_policy(const std::string& body) {
    // Body: {"policy":"BLOCK"} or {"policy":"ALLOW"}
    // NOTE: RuleEngine's default_policy_ is private; we expose a setter
    // by rebuilding the engine is not feasible without API change.
    // For now just acknowledge — a full impl requires adding set_default_policy().
    (void)body;
    return "{\"ok\":true,\"note\":\"Add set_default_policy() to RuleEngine for live changes\"}";
}

std::string ApiServer::handle_processes() const {
    auto procs = proc_mon_.snapshot();
    std::ostringstream o;
    o << "[";
    for (size_t i = 0; i < procs.size(); ++i) {
        if (i) o << ",";
        const auto& p = procs[i];
        o << "{"
          << "\"pid\":"           << p.pid                           << ","
          << "\"exe\":\""         << escape_json(p.exe_name)         << "\","
          << "\"app\":\""         << escape_json(p.display_name.empty() ? p.exe_name : p.display_name) << "\","
          << "\"is_browser\":"    << (p.is_browser ? "true" : "false") << ","
          << "\"is_blocked\":"    << (p.is_blocked ? "true" : "false") << ","
          << "\"bytes_rx\":"      << p.bytes_rx                      << ","
          << "\"bytes_tx\":"      << p.bytes_tx                      << ","
          << "\"pkt_count\":"     << p.pkt_count                     << ","
          << "\"tcp_ports\":["    ;
        for (size_t j = 0; j < p.tcp_ports.size(); ++j) {
            if (j) o << ",";
            o << p.tcp_ports[j];
        }
        o << "],"
          << "\"udp_ports\":["    ;
        for (size_t j = 0; j < p.udp_ports.size(); ++j) {
            if (j) o << ",";
            o << p.udp_ports[j];
        }
        o << "]"
          << "}";
    }
    o << "]";
    return o.str();
}

std::string ApiServer::handle_browser_tabs() const {
    auto tabs = proc_mon_.browser_tabs();
    std::ostringstream o;
    o << "[";
    for (size_t i = 0; i < tabs.size(); ++i) {
        if (i) o << ",";
        const auto& t = tabs[i];
        o << "{"
          << "\"pid\":"       << t.pid                      << ","
          << "\"browser\":\"" << escape_json(t.browser)     << "\","
          << "\"title\":\""   << escape_json(t.title)       << "\""
          << "}";
    }
    o << "]";
    return o.str();
}

std::string ApiServer::handle_block_app(const std::string& body) {
    std::string search = "\"app\":\"";
    auto pos = body.find(search);
    if (pos == std::string::npos) return "{\"ok\":false,\"error\":\"missing app field\"}";
    pos += search.size();
    auto end = body.find('"', pos);
    if (end == std::string::npos) return "{\"ok\":false,\"error\":\"invalid json\"}";
    
    std::string app = body.substr(pos, end - pos);
    proc_mon_.set_app_blocked(app, true);
    return "{\"ok\":true}";
}

std::string ApiServer::handle_allow_app(const std::string& body) {
    std::string search = "\"app\":\"";
    auto pos = body.find(search);
    if (pos == std::string::npos) return "{\"ok\":false,\"error\":\"missing app field\"}";
    pos += search.size();
    auto end = body.find('"', pos);
    if (end == std::string::npos) return "{\"ok\":false,\"error\":\"invalid json\"}";
    
    std::string app = body.substr(pos, end - pos);
    proc_mon_.set_app_blocked(app, false);
    return "{\"ok\":true}";
}

// ── JSON helpers ─────────────────────────────────────────────

std::string ApiServer::rule_to_json(const Rule& r) {
    auto ip_str = [](uint32_t ip) -> std::string {
        if (ip == 0) return "*";
        return ip4_to_string(ip);
    };

    std::ostringstream o;
    o << "{"
      << "\"id\":"          << r.id                            << ","
      << "\"action\":\""    << action_name(r.action)           << "\","
      << "\"proto\":\""     << proto_name(r.proto)             << "\","
      << "\"src_ip\":\""    << ip_str(r.src_ip)                << "\","
      << "\"dst_ip\":\""    << ip_str(r.dst_ip)                << "\","
      << "\"src_port\":"    << r.src_port                      << ","
      << "\"dst_port\":"    << r.dst_port                      << ","
      << "\"process\":\""   << escape_json(r.process_name)     << "\","
      << "\"hit_count\":"   << r.hit_count                     << ","
      << "\"description\":\"" << escape_json(r.description)    << "\""
      << "}";
    return o.str();
}

std::string ApiServer::record_to_json(const PacketRecord& pr) const {
    std::string rule_desc;
    if (pr.result.matched_rule) {
        rule_desc = escape_json(pr.result.matched_rule->description);
    } else if (pr.result.verdict == Action::BLOCK && !pr.process_name.empty() && proc_mon_.is_app_blocked(pr.process_name)) {
        rule_desc = "Application Blocked";
    } else {
        rule_desc = "default policy";
    }

    std::ostringstream o;
    o << "{"
      << "\"seq\":"          << pr.seq                                        << ","
      << "\"ts\":\""         << escape_json(pr.timestamp)                     << "\","
      << "\"verdict\":\""    << action_name(pr.result.verdict)                << "\","
      << "\"proto\":\""      << proto_name(pr.info.proto)                     << "\","
      << "\"src_ip\":\""     << escape_json(pr.src_ip_str)                    << "\","
      << "\"src_port\":"     << pr.info.src_port                              << ","
      << "\"dst_ip\":\""     << escape_json(pr.dst_ip_str)                    << "\","
      << "\"dst_port\":"     << pr.info.dst_port                              << ","
      << "\"size\":"          << pr.info.size                                  << ","
      << "\"pid\":"           << pr.pid                                        << ","
      << "\"process\":\""    << escape_json(pr.process_name)                 << "\","
      << "\"app\":\""         << escape_json(pr.process_display.empty()
                                   ? pr.process_name : pr.process_display)   << "\","
      << "\"rule_id\":"      << (pr.result.matched_rule ? (int)pr.result.matched_rule->id : -1) << ","
      << "\"rule_desc\":\""  << rule_desc << "\""
      << "}";
    return o.str();
}

std::string ApiServer::escape_json(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:   o << c;
        }
    }
    return o.str();
}

} // namespace fw
