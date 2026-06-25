#pragma once
#include "types.hpp"
#include "rule_engine.hpp"
#include "ring_buffer.hpp"
#include "nfq_capture.hpp"
#include "process_monitor.hpp"
#include "port_scan_detector.hpp"
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <deque>
#include <mutex>
#include <chrono>

// ──────────────────────────────────────────────────────────────
//  api_server.hpp
//
//  Embedded HTTP REST API server (cpp-httplib, header-only).
//  Serves:
//    GET  /api/stats           – live packet counters (JSON)
//    GET  /api/packets         – last N packets from ring buffer
//    GET  /api/rules           – current rule chain
//    POST /api/rules           – add a new rule
//    DELETE /api/rules/:id     – remove a rule by ID
//    POST /api/policy          – set default policy (ALLOW|BLOCK)
//    GET  /api/processes       – all processes with network activity
//    GET  /api/processes/apps  – process snapshot sorted by traffic
//    GET  /api/anomalies       – hit counts for all 20 anomaly rules
//    GET  /api/connections     – snapshot of live connection tracking table
//    GET  /api/ledger?n=N      – last N lines from ledger.json
//    GET  /api/stats/history   – 60-second rolling stats history
//    GET  /                    – serves dashboard/index.html
// ──────────────────────────────────────────────────────────────

// One snapshot of rolling stats per second
struct StatsEntry {
    std::string ts;       // ISO-like timestamp string
    uint64_t    total;
    uint64_t    blocked;
    uint64_t    allowed;
    uint64_t    bytes;
};

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
namespace httplib { class SSLServer; }
#else
namespace httplib { class Server; }
#endif

namespace fw {

class ApiServer {
public:
    ApiServer(RuleEngine&              engine,
              LiveStats&               stats,
              RingBuffer<PacketRecord>& ring,
              ProcessMonitor&          proc_mon,
              const std::string&       dashboard_root,
              int                      port = 8080);
    ~ApiServer();

    // Start listening (non-blocking — runs in a background thread)
    void start();

    // Signal shutdown and wait for thread to join
    void stop();

    bool is_running() const { return running_; }

    // push_scan_alert() is called from the rule engine callback (any thread)
    void        push_scan_alert(ScanEvent ev);

private:
    RuleEngine&              engine_;
    LiveStats&               stats_;
    RingBuffer<PacketRecord>& ring_;
    ProcessMonitor&          proc_mon_;
    std::string              dashboard_root_;
    int                      port_;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    std::unique_ptr<httplib::SSLServer> server_;
#else
    std::unique_ptr<httplib::Server> server_;
#endif
    std::thread                      thread_;
    std::atomic<bool>                running_{false};
    mutable std::mutex               engine_mtx_; // guard rule mutations

    std::string                      api_token_;
    std::string                      generate_token();

    void setup_routes();

    // ── Route handlers ─────────────────────────────────────────────
    std::string handle_stats()         const;
    std::string handle_packets(int n)  const;
    std::string handle_get_rules()     const;
    std::string handle_add_rule(const std::string& body);
    bool        handle_delete_rule(uint32_t id);
    std::string handle_set_policy(const std::string& body);
    std::string handle_processes()     const;
    std::string handle_browser_tabs()  const;
    std::string handle_block_app(const std::string& body);
    std::string handle_allow_app(const std::string& body);

    // ── New: Threats (ban list) ─────────────────────────────────
    std::string handle_get_threats()   const;
    std::string handle_ban_ip(const std::string& body);
    std::string handle_unban_ip(const std::string& body);

    // ── New: Geo-Blocking ───────────────────────────────────────
    std::string handle_get_geoblocks() const;
    std::string handle_add_geoblock(const std::string& body);
    std::string handle_delete_geoblock(size_t index);

    // ── New: Rate Limit ─────────────────────────────────────────
    std::string handle_get_ratelimit() const;
    std::string handle_set_ratelimit(const std::string& body);

    // ── New: Analytics ─────────────────────────────────────────────
    std::string handle_anomalies()        const;  // GET /api/anomalies
    std::string handle_connections()      const;  // GET /api/connections
    std::string handle_ledger(int n)      const;  // GET /api/ledger?n=N
    std::string handle_stats_history()    const;  // GET /api/stats/history

    // ── New: Port Scan Alerts ──────────────────────────────────────
    std::string handle_get_scans()        const;  // GET /api/scans
    std::string handle_get_stealth()      const;  // GET /api/stealth
    std::string handle_set_stealth(const std::string& body); // POST /api/stealth

    // Rolling 60-second stats history (filled by background ticker)
    mutable std::mutex          history_mtx_;
    std::deque<StatsEntry>      stats_history_;
    std::thread                 history_thread_;
    std::atomic<bool>           history_running_{false};
    void                        run_history_ticker();

    // ── Scan alert queue (filled by push_scan_alert, drained by GET /api/scans)
    mutable std::mutex          scan_mtx_;
    std::deque<ScanEvent>       scan_alerts_;   // max 100 entries

    // ── JSON helpers ────────────────────────────────────────────
    static std::string rule_to_json(const Rule& r);
    std::string record_to_json(const PacketRecord& pr) const;
    static std::string escape_json(const std::string& s);
};

} // namespace fw
