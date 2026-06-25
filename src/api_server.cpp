#include "api_server.hpp"
#include "config_parser.hpp"
#include "packet.hpp"
#include "platform.hpp" // cross-platform inet helpers
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>

// cpp-httplib — header-only, single include
#include "httplib.h"

// ──────────────────────────────────────────────────────────────
//  api_server.cpp
//
//  REST API server for the live firewall dashboard.
//  All JSON is hand-built (no external JSON library needed).
// ──────────────────────────────────────────────────────────────

namespace fw {

ApiServer::ApiServer(RuleEngine &engine, LiveStats &stats,
                     RingBuffer<PacketRecord> &ring, ProcessMonitor &proc_mon,
                     const std::string &dashboard_root, int port)
    : engine_(engine), stats_(stats), ring_(ring), proc_mon_(proc_mon),
      dashboard_root_(dashboard_root), port_(port) {

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  server_ = std::make_unique<httplib::SSLServer>("./config/cert.pem", "./config/key.pem");
  if (!server_->is_valid()) {
    std::cerr << "[API] Warning: Failed to load ./config/cert.pem and key.pem for HTTPS. Please generate them.\n";
  }
#else
  server_ = std::make_unique<httplib::Server>();
#endif

  api_token_ = generate_token();

  // Ensure logs directory exists
  std::filesystem::create_directories("logs");

  std::ofstream out("logs/api.token");
  if (out.is_open()) {
    out << api_token_ << "\n";
    out.flush();
    if (out.fail()) {
      std::cerr << "[API] Warning: could not write token file properly (disk full?)\n";
    }
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
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    std::cout << "[API] Dashboard at https://localhost:" << port_ << "\n";
#else
    std::cout << "[API] Dashboard at http://localhost:" << port_ << "\n";
#endif
    server_->listen("0.0.0.0", port_);
    running_ = false;
  });

  // Start rolling stats history ticker (1-sample/sec, max 60 samples)
  history_running_ = true;
  history_thread_ = std::thread(&ApiServer::run_history_ticker, this);
}

void ApiServer::stop() {
  if (running_) {
    server_->stop();
    if (thread_.joinable())
      thread_.join();
    running_ = false;
  }
  history_running_ = false;
  if (history_thread_.joinable())
    history_thread_.join();
}

// ── Route setup ───────────────────────────────────────────────

void ApiServer::setup_routes() {
  // CORS headers for all responses
  auto cors = [](httplib::Response &res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type");
  };

  // Preflight and Authorization middleware
  server_->set_pre_routing_handler([this, cors](const httplib::Request &req,
                                                httplib::Response &res) {
    if (req.method == "OPTIONS") {
      cors(res);
      res.status = 204;
      return httplib::Server::HandlerResponse::Handled;
    }

    // Protect all /api/ routes EXCEPT /api/token (used for auto-auth)
    if (req.path.find("/api/") == 0 && req.path != "/api/token") {
      auto it = req.headers.find("Authorization");
      if (it == req.headers.end() || it->second != "Bearer " + api_token_) {
        cors(res);
        res.status = 401;
        res.set_content(
            "{\"error\":\"Unauthorized - Invalid or missing Bearer token\"}",
            "application/json");
        return httplib::Server::HandlerResponse::Handled;
      }
    }
    return httplib::Server::HandlerResponse::Unhandled;
  });

  // ── GET /api/stats ─────────────────────────────────────────
  server_->Get("/api/stats",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_stats(), "application/json");
               });

  // ── GET /api/packets?n=100 ─────────────────────────────────
  server_->Get("/api/packets", [this, cors](const httplib::Request &req,
                                            httplib::Response &res) {
    cors(res);
    int n = 100;
    if (req.has_param("n")) {
      try {
        n = std::stoi(req.get_param_value("n"));
      } catch (...) {
      }
    }
    n = std::max(1, std::min(n, 1000));
    res.set_content(handle_packets(n), "application/json");
  });

  // ── GET /api/rules ─────────────────────────────────────────
  server_->Get("/api/rules",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_get_rules(), "application/json");
               });

  // ── POST /api/rules ────────────────────────────────────────
  server_->Post("/api/rules", [this, cors](const httplib::Request &req,
                                           httplib::Response &res) {
    cors(res);
    std::string body = handle_add_rule(req.body);
    res.set_content(body, "application/json");
  });

  // ── DELETE /api/rules/:id ──────────────────────────────────
  server_->Delete(
      R"(/api/rules/(\d+))",
      [this, cors](const httplib::Request &req, httplib::Response &res) {
        cors(res);
        uint32_t id = std::stoul(req.matches[1].str());
        bool ok = handle_delete_rule(id);
        res.set_content(ok ? "{\"ok\":true}"
                           : "{\"ok\":false,\"error\":\"not found\"}",
                        "application/json");
        if (!ok)
          res.status = 404;
      });

  // ── POST /api/policy ───────────────────────────────────────
  server_->Post("/api/policy", [this, cors](const httplib::Request &req,
                                            httplib::Response &res) {
    cors(res);
    res.set_content(handle_set_policy(req.body), "application/json");
  });

  // ── GET /api/processes ───────────────────────────────────
  server_->Get("/api/processes",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_processes(), "application/json");
               });

  // ── GET /api/processes/tabs ──────────────────────────────
  server_->Get("/api/processes/tabs",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_browser_tabs(), "application/json");
               });

  // ── POST /api/apps/block ──────────────────────────────────
  server_->Post("/api/apps/block", [this, cors](const httplib::Request &req,
                                                httplib::Response &res) {
    cors(res);
    res.set_content(handle_block_app(req.body), "application/json");
  });

  // ── POST /api/apps/allow ──────────────────────────────────
  server_->Post("/api/apps/allow", [this, cors](const httplib::Request &req,
                                                httplib::Response &res) {
    cors(res);
    res.set_content(handle_allow_app(req.body), "application/json");
  });

  // ── GET /api/token — self-service token for dashboard auto-auth ──────────
  server_->Get("/api/token", [this, cors](const httplib::Request &,
                                          httplib::Response &res) {
    cors(res);
    res.set_content("{\"token\":\"" + api_token_ + "\"}", "application/json");
  });

  // ── GET /api/threats ─────────────────────────────────────
  server_->Get("/api/threats",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_get_threats(), "application/json");
               });

  // ── POST /api/threats (body: {"ip":"1.2.3.4", "reason":"manual"}) ──
  server_->Post("/api/threats",
                  [this, cors](const httplib::Request &req,
                               httplib::Response &res) {
                    cors(res);
                    res.set_content(handle_ban_ip(req.body),
                                    "application/json");
                  });

  // ── DELETE /api/threats (body: {"ip":"1.2.3.4"}) ──────────
  server_->Delete("/api/threats",
                  [this, cors](const httplib::Request &req,
                               httplib::Response &res) {
                    cors(res);
                    res.set_content(handle_unban_ip(req.body),
                                    "application/json");
                  });

  // ── GET /api/geoblocks ───────────────────────────────────
  server_->Get("/api/geoblocks",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_get_geoblocks(), "application/json");
               });

  // ── POST /api/geoblocks ──────────────────────────────────
  server_->Post("/api/geoblocks",
                [this, cors](const httplib::Request &req,
                             httplib::Response &res) {
                  cors(res);
                  res.set_content(handle_add_geoblock(req.body),
                                  "application/json");
                });

  // ── DELETE /api/geoblocks/:idx ───────────────────────────
  server_->Delete(
      R"(/api/geoblocks/(\d+))",
      [this, cors](const httplib::Request &req, httplib::Response &res) {
        cors(res);
        size_t idx = std::stoul(req.matches[1].str());
        std::string body = handle_delete_geoblock(idx);
        res.set_content(body, "application/json");
        if (body.find("false") != std::string::npos)
          res.status = 404;
      });

  // ── GET /api/ratelimit ───────────────────────────────────
  server_->Get("/api/ratelimit",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_get_ratelimit(), "application/json");
               });

  // ── POST /api/ratelimit ──────────────────────────────────
  server_->Post("/api/ratelimit",
                [this, cors](const httplib::Request &req,
                             httplib::Response &res) {
                  cors(res);
                  res.set_content(handle_set_ratelimit(req.body),
                                  "application/json");
                });

  // ── GET /api/anomalies ─────────────────────────────────
  server_->Get("/api/anomalies",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_anomalies(), "application/json");
               });

  // ── GET /api/connections ──────────────────────────────
  server_->Get("/api/connections",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_connections(), "application/json");
               });

  // ── GET /api/ledger?n=N ──────────────────────────────
  server_->Get("/api/ledger", [this, cors](const httplib::Request &req,
                                           httplib::Response &res) {
    cors(res);
    int n = 50;
    if (req.has_param("n")) {
      try { n = std::stoi(req.get_param_value("n")); } catch (...) {}
    }
    n = std::max(1, std::min(n, 500));
    res.set_content(handle_ledger(n), "application/json");
  });

  // ── GET /api/stats/history ───────────────────────────
  server_->Get("/api/stats/history",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_stats_history(), "application/json");
               });

  // ── GET /api/scans ────────────────────────────────────
  server_->Get("/api/scans",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_get_scans(), "application/json");
               });

  // ── GET /api/stealth ──────────────────────────────────
  server_->Get("/api/stealth",
               [this, cors](const httplib::Request &, httplib::Response &res) {
                 cors(res);
                 res.set_content(handle_get_stealth(), "application/json");
               });

  // ── POST /api/stealth ─────────────────────────────────
  server_->Post("/api/stealth",
                [this, cors](const httplib::Request &req, httplib::Response &res) {
                  cors(res);
                  res.set_content(handle_set_stealth(req.body), "application/json");
                });

  // ── Static file serving (dashboard) ────────────────────────
  if (!dashboard_root_.empty()) {
    server_->set_mount_point("/", dashboard_root_);
  }

  // ── Fallback 404 ──────────────────────────────────────
  server_->set_error_handler(
      [cors](const httplib::Request &, httplib::Response &res) {
        cors(res);
        res.set_content("{\"error\":\"not found\"}", "application/json");
      });
}

// ── Handler implementations ───────────────────────────────────

std::string ApiServer::generate_token() {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 15);
  const char *hex = "0123456789abcdef";
  std::string token;
  for (int i = 0; i < 32; ++i)
    token += hex[dis(gen)];
  return token;
}

std::string ApiServer::handle_stats() const {
  std::ostringstream o;
  o << "{"
    << "\"total\":" << stats_.total.load() << ","
    << "\"allowed\":" << stats_.allowed.load() << ","
    << "\"blocked\":" << stats_.blocked.load() << ","
    << "\"tcp\":" << stats_.tcp.load() << ","
    << "\"udp\":" << stats_.udp.load() << ","
    << "\"icmp\":" << stats_.icmp.load() << ","
    << "\"ipv6\":" << stats_.ipv6.load() << ","
#if defined(HAVE_WINDIVERT) || defined(HAVE_NFQUEUE)
    << "\"enforcement_mode\":true,"
#else
    << "\"enforcement_mode\":false,"
#endif
    << "\"bytes_total\":" << stats_.bytes_total.load() << "}";
  return o.str();
}

std::string ApiServer::handle_packets(int n) const {
  auto records = ring_.tail(static_cast<size_t>(n));
  std::ostringstream o;
  o << "[";
  for (size_t i = 0; i < records.size(); ++i) {
    if (i)
      o << ",";
    o << record_to_json(records[i]);
  }
  o << "]";
  return o.str();
}

std::string ApiServer::handle_get_rules() const {
  std::lock_guard<std::mutex> lock(engine_mtx_);
  const auto &rules = engine_.rules();
  std::ostringstream o;
  o << "[";
  for (size_t i = 0; i < rules.size(); ++i) {
    if (i)
      o << ",";
    o << rule_to_json(rules[i]);
  }
  o << "]";
  return o.str();
}

std::string ApiServer::handle_add_rule(const std::string &body) {
  // Simple JSON parse — expects:
  // {"action":"ALLOW","proto":"TCP","src_ip":"*","dst_ip":"*","dst_port":443,"description":"HTTPS"}
  auto get_field = [&](const std::string &key) -> std::string {
    std::string search = "\"" + key + "\":\"";
    auto pos = body.find(search);
    if (pos == std::string::npos)
      return "";
    pos += search.size();
    auto end = body.find('"', pos);
    return (end == std::string::npos) ? "" : body.substr(pos, end - pos);
  };


  std::string action_s = get_field("action");
  std::string proto_s = get_field("proto");
  std::string src_ip_s = get_field("src_ip");
  std::string dst_ip_s = get_field("dst_ip");
  std::string desc = get_field("description");

  // Extract dst_port as string manually since it could be "*" or int
  std::string port_search = "\"dst_port\":";
  std::string dst_port_s = "*";
  auto port_pos = body.find(port_search);
  if (port_pos != std::string::npos) {
    port_pos += port_search.size();
    if (port_pos < body.size() && body[port_pos] == '"') {
      auto port_end = body.find('"', port_pos + 1);
      if (port_end != std::string::npos)
        dst_port_s = body.substr(port_pos + 1, port_end - port_pos - 1);
    } else {
      auto port_end = body.find_first_of(",}", port_pos);
      if (port_end != std::string::npos)
        dst_port_s = body.substr(port_pos, port_end - port_pos);
    }
  }

  Rule r;
  try {
    r.action = ConfigParser::parse_action(action_s);
    r.proto = ConfigParser::parse_proto(proto_s);
    r.src_ip = ConfigParser::parse_ip(src_ip_s);
    r.dst_ip = ConfigParser::parse_ip(dst_ip_s);
    r.dst_port = ConfigParser::parse_port(dst_port_s);
    r.description = desc.length() > 256 ? desc.substr(0, 256) : desc;
  } catch (const std::exception &e) {
    return "{\"ok\":false,\"error\":\"Invalid rule format\"}";
  }

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

std::string ApiServer::handle_set_policy(const std::string &body) {
  // Body: {"policy":"BLOCK"} or {"policy":"ALLOW"}
  std::string search = "\"policy\":\"";
  auto pos = body.find(search);
  if (pos != std::string::npos) {
    pos += search.size();
    auto end = body.find('"', pos);
    if (end != std::string::npos) {
      std::string pol = body.substr(pos, end - pos);
      std::lock_guard<std::mutex> lock(engine_mtx_);
      if (pol == "ALLOW")
        engine_.set_default_policy(Action::ALLOW);
      else if (pol == "BLOCK")
        engine_.set_default_policy(Action::BLOCK);
      else
        return "{\"ok\":false,\"error\":\"Invalid policy\"}";
      return "{\"ok\":true}";
    }
  }
  return "{\"ok\":false,\"error\":\"Missing policy field\"}";
}

std::string ApiServer::handle_processes() const {
  auto procs = proc_mon_.snapshot();
  std::ostringstream o;
  o << "[";
  for (size_t i = 0; i < procs.size(); ++i) {
    if (i)
      o << ",";
    const auto &p = procs[i];
    o << "{"
      << "\"pid\":" << p.pid << ","
      << "\"exe\":\"" << escape_json(p.exe_name) << "\","
      << "\"app\":\""
      << escape_json(p.display_name.empty() ? p.exe_name : p.display_name)
      << "\","
      << "\"is_browser\":" << (p.is_browser ? "true" : "false") << ","
      << "\"is_blocked\":" << (p.is_blocked ? "true" : "false") << ","
      << "\"bytes_rx\":" << p.bytes_rx << ","
      << "\"bytes_tx\":" << p.bytes_tx << ","
      << "\"pkt_count\":" << p.pkt_count << ","
      << "\"tcp_ports\":[";
    for (size_t j = 0; j < p.tcp_ports.size(); ++j) {
      if (j)
        o << ",";
      o << p.tcp_ports[j];
    }
    o << "],"
      << "\"udp_ports\":[";
    for (size_t j = 0; j < p.udp_ports.size(); ++j) {
      if (j)
        o << ",";
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
    if (i)
      o << ",";
    const auto &t = tabs[i];
    o << "{"
      << "\"pid\":" << t.pid << ","
      << "\"browser\":\"" << escape_json(t.browser) << "\","
      << "\"title\":\"" << escape_json(t.title) << "\""
      << "}";
  }
  o << "]";
  return o.str();
}

std::string ApiServer::handle_block_app(const std::string &body) {
  std::string search = "\"app\":\"";
  auto pos = body.find(search);
  if (pos == std::string::npos)
    return "{\"ok\":false,\"error\":\"missing app field\"}";
  pos += search.size();
  auto end = body.find('"', pos);
  if (end == std::string::npos)
    return "{\"ok\":false,\"error\":\"invalid json\"}";

  std::string app = body.substr(pos, end - pos);
  proc_mon_.set_app_blocked(app, true);
  return "{\"ok\":true}";
}

std::string ApiServer::handle_allow_app(const std::string &body) {
  std::string search = "\"app\":\"";
  auto pos = body.find(search);
  if (pos == std::string::npos)
    return "{\"ok\":false,\"error\":\"missing app field\"}";
  pos += search.size();
  auto end = body.find('"', pos);
  if (end == std::string::npos)
    return "{\"ok\":false,\"error\":\"invalid json\"}";

  std::string app = body.substr(pos, end - pos);
  proc_mon_.set_app_blocked(app, false);
  return "{\"ok\":true}";
}

// ── JSON helpers ─────────────────────────────────────────────

std::string ApiServer::rule_to_json(const Rule &r) {
  auto ip_str = [](uint32_t ip) -> std::string {
    if (ip == 0)
      return "*";
    return ip4_to_string(ip);
  };

  std::ostringstream o;
  o << "{"
    << "\"id\":" << r.id << ","
    << "\"action\":\"" << action_name(r.action) << "\","
    << "\"proto\":\"" << proto_name(r.proto) << "\","
    << "\"src_ip\":\"" << ip_str(r.src_ip) << "\","
    << "\"dst_ip\":\"" << ip_str(r.dst_ip) << "\","
    << "\"src_port\":" << r.src_port << ","
    << "\"dst_port\":" << r.dst_port << ","
    << "\"process\":\"" << escape_json(r.process_name) << "\","
    << "\"hit_count\":" << r.hit_count << ","
    << "\"description\":\"" << escape_json(r.description) << "\""
    << "}";
  return o.str();
}

std::string ApiServer::record_to_json(const PacketRecord &pr) const {
  std::string rule_desc;
  if (pr.result.matched_rule) {
    rule_desc = escape_json(pr.result.matched_rule->description);
  } else if (pr.result.verdict == Action::BLOCK && !pr.process_name.empty() &&
             proc_mon_.is_app_blocked(pr.process_name)) {
    rule_desc = "Application Blocked";
  } else {
    rule_desc = "default policy";
  }

  std::ostringstream o;
  o << "{"
    << "\"seq\":" << pr.seq << ","
    << "\"ts\":\"" << escape_json(pr.timestamp) << "\","
    << "\"verdict\":\"" << action_name(pr.result.verdict) << "\","
    << "\"proto\":\"" << proto_name(pr.info.proto) << "\","
    << "\"src_ip\":\"" << escape_json(pr.src_ip_str) << "\","
    << "\"src_port\":" << pr.info.src_port << ","
    << "\"dst_ip\":\"" << escape_json(pr.dst_ip_str) << "\","
    << "\"dst_port\":" << pr.info.dst_port << ","
    << "\"size\":" << pr.info.size << ","
    << "\"pid\":" << pr.pid << ","
    << "\"process\":\"" << escape_json(pr.process_name) << "\","
    << "\"app\":\""
    << escape_json(pr.process_display.empty() ? pr.process_name
                                              : pr.process_display)
    << "\","
    << "\"rule_id\":"
    << (pr.result.matched_rule ? (int)pr.result.matched_rule->id : -1) << ","
    << "\"rule_desc\":\"" << rule_desc << "\""
    << "}";
  return o.str();
}

std::string ApiServer::escape_json(const std::string &s) {
  std::ostringstream o;
  for (char c : s) {
    switch (c) {
    case '"':
      o << "\\\"";
      break;
    case '\\':
      o << "\\\\";
      break;
    case '\n':
      o << "\\n";
      break;
    case '\r':
      o << "\\r";
      break;
    case '\t':
      o << "\\t";
      break;
    default:
      o << c;
    }
  }
  return o.str();
}

} // namespace fw

// ── New handler implementations ──────────────────────────────

namespace fw {

// ── Threats ──────────────────────────────────────────────────

std::string ApiServer::handle_get_threats() const {
  auto threats = engine_.get_threat_table_snapshot();
  std::ostringstream o;
  o << "[";
  for (size_t i = 0; i < threats.size(); ++i) {
    if (i) o << ",";
    const auto& t = threats[i];
    // Calculate seconds remaining on ban
    auto now = std::chrono::steady_clock::now();
    auto secs_left = std::chrono::duration_cast<std::chrono::seconds>(
                         t.ban_expires - now).count();
    if (secs_left < 0) secs_left = 0;
    o << "{"
      << "\"ip\":\"" << escape_json(t.ip_str) << "\","
      << "\"reason\":\"" << escape_json(t.reason) << "\","
      << "\"ban_count\":" << t.ban_count << ","
      << "\"expires_in_sec\":" << secs_left
      << "}";
  }
  o << "]";
  return o.str();
}

std::string ApiServer::handle_ban_ip(const std::string& body) {
  // Body: {"ip":"1.2.3.4", "reason":"manual"}
  std::string search_ip = "\"ip\":\"";
  auto pos = body.find(search_ip);
  if (pos == std::string::npos)
    return "{\"ok\":false,\"error\":\"missing ip field\"}";
  pos += search_ip.size();
  auto end = body.find('"', pos);
  if (end == std::string::npos)
    return "{\"ok\":false,\"error\":\"invalid json\"}";
  std::string ip_str = body.substr(pos, end - pos);

  std::string reason = "Manual Ban";
  std::string search_reason = "\"reason\":\"";
  auto rpos = body.find(search_reason);
  if (rpos != std::string::npos) {
      rpos += search_reason.size();
      auto rend = body.find('"', rpos);
      if (rend != std::string::npos) {
          reason = body.substr(rpos, rend - rpos);
      }
  }

  // Parse the IP string back to uint32_t
  uint32_t ip = 0;
  try { ip = ConfigParser::parse_ip(ip_str); }
  catch (...) {
    return "{\"ok\":false,\"error\":\"invalid IP\"}";
  }
  if (ip == 0)
    return "{\"ok\":false,\"error\":\"invalid IP\"}";

  bool ok = engine_.ban_ip(ip, reason);
  return ok ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"Failed to ban IP\"}";
}

std::string ApiServer::handle_unban_ip(const std::string& body) {
  // Body: {"ip":"1.2.3.4"}
  std::string search = "\"ip\":\"";
  auto pos = body.find(search);
  if (pos == std::string::npos)
    return "{\"ok\":false,\"error\":\"missing ip field\"}";
  pos += search.size();
  auto end = body.find('"', pos);
  if (end == std::string::npos)
    return "{\"ok\":false,\"error\":\"invalid json\"}";
  std::string ip_str = body.substr(pos, end - pos);

  // Parse the IP string back to uint32_t
  uint32_t ip = 0;
  try { ip = ConfigParser::parse_ip(ip_str); }
  catch (...) {
    return "{\"ok\":false,\"error\":\"invalid IP\"}";
  }
  if (ip == 0)
    return "{\"ok\":false,\"error\":\"invalid IP\"}";

  bool ok = engine_.unban_ip(ip);
  return ok ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"IP not found in ban list\"}";
}

// ── Geo-Blocking ─────────────────────────────────────────────

std::string ApiServer::handle_get_geoblocks() const {
  auto blocks = engine_.get_geo_blocks();
  std::ostringstream o;
  o << "[";
  for (size_t i = 0; i < blocks.size(); ++i) {
    if (i) o << ",";
    const auto& g = blocks[i];
    // Convert network/mask back to CIDR notation
    uint32_t net = g.network;
    uint32_t mask = g.mask;
    // Count prefix bits
    int prefix = 0;
    uint32_t m = mask;
    while (m & 0x80000000u) { ++prefix; m <<= 1; }
    o << "{"
      << "\"idx\":" << i << ","
      << "\"cidr\":\"" << ip4_to_string(net) << "/" << prefix << "\","
      << "\"label\":\"" << escape_json(g.label) << "\""
      << "}";
  }
  o << "]";
  return o.str();
}

std::string ApiServer::handle_add_geoblock(const std::string& body) {
  // Body: {"cidr":"1.2.3.0/24","label":"China ranges"}
  auto get_field = [&](const std::string& key) -> std::string {
    std::string search = "\"" + key + "\":\"";
    auto pos = body.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    auto end = body.find('"', pos);
    return (end == std::string::npos) ? "" : body.substr(pos, end - pos);
  };

  std::string cidr = get_field("cidr");
  std::string label = get_field("label");
  if (cidr.empty())
    return "{\"ok\":false,\"error\":\"missing cidr field\"}";

  // Parse CIDR: "a.b.c.d/prefix"
  auto slash = cidr.find('/');
  if (slash == std::string::npos)
    return "{\"ok\":false,\"error\":\"invalid CIDR — use a.b.c.d/prefix\"}";

  std::string ip_part = cidr.substr(0, slash);
  int prefix = 0;
  try { prefix = std::stoi(cidr.substr(slash + 1)); }
  catch (...) {
    return "{\"ok\":false,\"error\":\"invalid prefix\"}";
  }
  if (prefix < 0 || prefix > 32)
    return "{\"ok\":false,\"error\":\"prefix must be 0-32\"}";

  uint32_t network = 0;
  try { network = ConfigParser::parse_ip(ip_part); }
  catch (...) {
    return "{\"ok\":false,\"error\":\"invalid IP in CIDR\"}";
  }

  uint32_t mask = (prefix == 0) ? 0u : (~0u << (32 - prefix));
  if (label.length() > 64) label = label.substr(0, 64);

  engine_.block_cidr(network, mask, label.empty() ? cidr : label);
  return "{\"ok\":true}";
}

std::string ApiServer::handle_delete_geoblock(size_t index) {
  bool ok = engine_.unblock_cidr(index);
  return ok ? "{\"ok\":true}" : "{\"ok\":false,\"error\":\"index out of range\"}";
}

// ── Rate Limit ────────────────────────────────────────────────

std::string ApiServer::handle_get_ratelimit() const {
  std::ostringstream o;
  o << "{\"pps\":" << engine_.get_rate_limit() << "}";
  return o.str();
}

std::string ApiServer::handle_set_ratelimit(const std::string& body) {
  // Body: {"pps":500}
  std::string search = "\"pps\":";
  auto pos = body.find(search);
  if (pos == std::string::npos)
    return "{\"ok\":false,\"error\":\"missing pps field\"}";
  pos += search.size();
  int pps = 0;
  try { pps = std::stoi(body.substr(pos)); }
  catch (...) {
    return "{\"ok\":false,\"error\":\"invalid pps value\"}";
  }
  if (pps < 1 || pps > 100000)
    return "{\"ok\":false,\"error\":\"pps must be 1-100000\"}";
  engine_.set_rate_limit(static_cast<uint32_t>(pps));
  return "{\"ok\":true,\"pps\":" + std::to_string(pps) + "}";
}

// ── Analytics: Anomalies ─────────────────────────────────────

std::string ApiServer::handle_anomalies() const {
  auto snaps = engine_.get_anomaly_snapshot();
  std::ostringstream o;
  o << "[";
  for (size_t i = 0; i < snaps.size(); ++i) {
    if (i) o << ",";
    o << "{"
      << "\"name\":\"" << escape_json(snaps[i].name) << "\","
      << "\"hits\":" << snaps[i].hit_count
      << "}";
  }
  o << "]";
  return o.str();
}

// ── Analytics: Live Connections ──────────────────────────────

std::string ApiServer::handle_connections() const {
  auto conns = engine_.get_connection_snapshot();
  std::ostringstream o;
  o << "[";
  for (size_t i = 0; i < conns.size(); ++i) {
    if (i) o << ",";
    const auto& c = conns[i];
    o << "{"
      << "\"src_ip\":\"" << escape_json(c.src_ip) << "\","
      << "\"dst_ip\":\"" << escape_json(c.dst_ip) << "\","
      << "\"src_port\":" << c.src_port << ","
      << "\"dst_port\":" << c.dst_port << ","
      << "\"proto\":\"" << c.proto << "\","
      << "\"state\":\"" << c.state << "\","
      << "\"bytes_in\":" << c.bytes_in << ","
      << "\"bytes_out\":" << c.bytes_out << ","
      << "\"bytes_total\":" << c.bytes_total << ","
      << "\"age_sec\":" << static_cast<int>(c.age_sec)
      << "}";
  }
  o << "]";
  return o.str();
}

// ── Analytics: Ledger ────────────────────────────────────────

std::string ApiServer::handle_ledger(int n) const {
  // Read the last N lines from logs/ledger.json
  std::ifstream f("logs/ledger.json");
  if (!f.is_open())
    return "[]";

  // Buffer all lines
  std::vector<std::string> lines;
  std::string line;
  while (std::getline(f, line)) {
    if (!line.empty())
      lines.push_back(line);
  }

  // Take the last N
  size_t start = (lines.size() > static_cast<size_t>(n))
                 ? lines.size() - static_cast<size_t>(n)
                 : 0;

  std::ostringstream o;
  o << "[";
  bool first = true;
  for (size_t i = start; i < lines.size(); ++i) {
    if (!first) o << ",";
    o << lines[i];
    first = false;
  }
  o << "]";
  return o.str();
}

// ── Analytics: Stats History ─────────────────────────────────

std::string ApiServer::handle_stats_history() const {
  std::lock_guard<std::mutex> lock(history_mtx_);
  std::ostringstream o;
  o << "[";
  bool first = true;
  for (const auto& e : stats_history_) {
    if (!first) o << ",";
    o << "{"
      << "\"ts\":\"" << escape_json(e.ts) << "\","
      << "\"total\":" << e.total << ","
      << "\"blocked\":" << e.blocked << ","
      << "\"allowed\":" << e.allowed << ","
      << "\"bytes\":" << e.bytes
      << "}";
    first = false;
  }
  o << "]";
  return o.str();
}

// ── Stats History Ticker ─────────────────────────────────────

void ApiServer::run_history_ticker() {
  // Sample stats every second; keep last 60 samples
  while (history_running_) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    if (!history_running_) break;

    // Build a simple timestamp string (seconds since epoch)
    auto now = std::chrono::system_clock::now();
    auto epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now.time_since_epoch()).count();

    StatsEntry e;
    e.ts      = std::to_string(epoch_ms);
    e.total   = stats_.total.load();
    e.blocked = stats_.blocked.load();
    e.allowed = stats_.allowed.load();
    e.bytes   = stats_.bytes_total.load();

    std::lock_guard<std::mutex> lock(history_mtx_);
    stats_history_.push_back(std::move(e));
    if (stats_history_.size() > 60)
      stats_history_.pop_front();
  }
}

} // namespace fw

// ── Port Scan Alerts & Stealth Mode ──────────────────────────────

namespace fw {

void ApiServer::push_scan_alert(ScanEvent ev) {
  std::lock_guard<std::mutex> lock(scan_mtx_);
  scan_alerts_.push_back(std::move(ev));
  if (scan_alerts_.size() > 100)
    scan_alerts_.pop_front();
}

std::string ApiServer::handle_get_scans() const {
  std::lock_guard<std::mutex> lock(scan_mtx_);
  std::ostringstream o;
  o << "[";
  bool first = true;
  for (const auto& ev : scan_alerts_) {
    if (!first) o << ",";
    o << "{"
      << "\"ip\":\""         << escape_json(ev.ip_str)              << "\","
      << "\"scan_type\":\""  << escape_json(scan_type_name(ev.scan_type)) << "\","
      << "\"ports_probed\":" << ev.ports_probed                    << ","
      << "\"timestamp\":\"" << escape_json(ev.timestamp)           << "\","
      << "\"auto_banned\":"  << (ev.auto_banned ? "true" : "false")
      << "}";
    first = false;
  }
  o << "]";
  return o.str();
}

std::string ApiServer::handle_get_stealth() const {
  bool mode = engine_.get_stealth_mode();
  std::ostringstream o;
  o << "{\"stealth\":" << (mode ? "true" : "false") << "}";
  return o.str();
}

std::string ApiServer::handle_set_stealth(const std::string& body) {
  // Body: {"stealth":true} or {"stealth":false}
  std::string search = "\"stealth\":";
  auto pos = body.find(search);
  if (pos == std::string::npos)
    return "{\"ok\":false,\"error\":\"missing stealth field\"}";
  pos += search.size();
  // Skip whitespace
  while (pos < body.size() && body[pos] == ' ') ++pos;
  bool enabled = (body.substr(pos, 4) == "true");
  engine_.set_stealth_mode(enabled);
  return std::string("{\"ok\":true,\"stealth\":") + (enabled ? "true" : "false") + "}";
}

} // namespace fw
