#pragma once
#include "types.hpp"
#include "rule_engine.hpp"
#include "ring_buffer.hpp"
#include "nfq_capture.hpp"
#include "process_monitor.hpp"
#include <string>
#include <thread>
#include <atomic>
#include <memory>

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
//    GET  /                    – serves dashboard/index.html
// ──────────────────────────────────────────────────────────────

namespace httplib { class Server; }

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

private:
    RuleEngine&              engine_;
    LiveStats&               stats_;
    RingBuffer<PacketRecord>& ring_;
    ProcessMonitor&          proc_mon_;
    std::string              dashboard_root_;
    int                      port_;

    std::unique_ptr<httplib::Server> server_;
    std::thread                      thread_;
    std::atomic<bool>                running_{false};
    mutable std::mutex               engine_mtx_; // guard rule mutations

    void setup_routes();

    // ── Route handlers ─────────────────────────────────────────────
    std::string handle_stats()         const;
    std::string handle_packets(int n)  const;
    std::string handle_get_rules()     const;
    std::string handle_add_rule(const std::string& body);
    bool        handle_delete_rule(uint32_t id);
    std::string handle_set_policy(const std::string& body);
    std::string handle_processes()     const;  // NEW
    std::string handle_browser_tabs()  const;  // NEW
    std::string handle_block_app(const std::string& body);
    std::string handle_allow_app(const std::string& body);

    // ── JSON helpers ────────────────────────────────────────────
    static std::string rule_to_json(const Rule& r);
    std::string record_to_json(const PacketRecord& pr) const;
    static std::string escape_json(const std::string& s);
};

} // namespace fw
