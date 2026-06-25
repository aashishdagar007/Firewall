#include "platform.hpp"       // MUST be first — pulls in winsock2.h on Windows
#include "nfq_capture.hpp"
#include "rule_engine.hpp"
#include "logger.hpp"
#include "config_parser.hpp"
#include "api_server.hpp"
#include "ring_buffer.hpp"
#include "process_monitor.hpp"
// ── Phase 2: Four Pillars ─────────────────────────────────────
#include "sha256.hpp"          // Pillar 2+4: cryptographic primitive
#include "bvudp.hpp"           // Pillar 2:   Batch-Verified UDP protocol
#include "port_demux.hpp"      // Pillar 1:   DPI port demultiplexer
#include "chain_ledger.hpp"    // Pillar 4:   tamper-proof event ledger
#include "control_plane.hpp"   // Pillar 3:   cloud control plane client
#include <csignal>
#include <atomic>
#include <thread>
#include <string>
#include <vector>
#include <cstdlib>

#ifdef _WIN32
#include <shellapi.h>
#endif
// ──────────────────────────────────────────────────────────────
//  main.cpp  (v2 — Real Firewall + GUI  |  Windows + Linux)
//
//  Architecture:
//    Thread 1 (main)     → Packet capture loop (kernel verdicts on Linux)
//    Thread 2 (detached) → HTTP API server (dashboard backend)
//
//  Usage:
//    [sudo] ./firewall [config] [log] [dashboard_dir] [api_port]
//
//    config        default: config/rules.conf
//    log           default: logs/firewall.log
//    dashboard_dir default: dashboard/
//    api_port      default: 8080
//
//  Windows notes:
//    • Linked as /SUBSYSTEM:WINDOWS — no console window appears.
//    • All diagnostic output goes to logs/firewall.log.
//    • Run as Administrator (raw socket / SIO_RCVALL needs it).
//    • For real packet blocking on Windows, integrate WinDivert.
// ──────────────────────────────────────────────────────────────

static fw::NfqCapture* g_capture = nullptr;

static void signal_handler(int) {
    if (g_capture) g_capture->stop();
}

// ── Open a URL in the default browser without flashing a console window ──
[[maybe_unused]] static void open_browser(const std::string& url) {
#ifdef _WIN32
    // Convert to wide string for ShellExecuteW
    int wlen = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
    std::wstring wurl(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, &wurl[0], wlen);

    // Try Chrome in app mode (frameless standalone window)
    std::wstring chrome_args = L"--app=\"" + wurl + L"\" --new-window";
    HINSTANCE rc = ShellExecuteW(nullptr, L"open", L"chrome", chrome_args.c_str(), nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(rc) > 32) return;

    // Fallback: Edge in app mode
    std::wstring edge_args = L"--app=\"" + wurl + L"\" --new-window";
    rc = ShellExecuteW(nullptr, L"open", L"msedge", edge_args.c_str(), nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(rc) > 32) return;

    // Final fallback: system default browser
    ShellExecuteW(nullptr, L"open", wurl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#else
    std::string cmd = "xdg-open '" + url + "' 2>/dev/null &";
    std::system(cmd.c_str());
#endif
}

#ifdef _WIN32
// WinMain entry point for /SUBSYSTEM:WINDOWS (no console)
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    int    argc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    // Convert wide args to narrow for uniform handling below
    std::vector<std::string> args_storage;
    if (wargv) {
        for (int i = 0; i < argc; ++i) {
            int len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
            std::string s(len, '\0');
            WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, &s[0], len, nullptr, nullptr);
            args_storage.push_back(s);
        }
        LocalFree(wargv);
    }
    std::vector<const char*> argv_ptrs;
    for (auto& s : args_storage) argv_ptrs.push_back(s.c_str());
    char** argv = const_cast<char**>(argv_ptrs.data());
#else
int main(int argc, char* argv[]) {
#endif

    // ── 0. Platform init (Winsock on Windows, no-op on Linux) ──
    if (!wsa_init()) {
        // No console — failure is silent; firewall simply won't start.
        return 1;
    }

    const std::string config_path    = (argc > 1) ? argv[1] : "config/rules.conf";
    const std::string log_path       = (argc > 2) ? argv[2] : "logs/firewall.log";
    const std::string dashboard_root = (argc > 3) ? argv[3] : "dashboard/";
    int               api_port       = 8080;
    if (argc > 4) {
        try { api_port = std::stoi(argv[4]); } catch (...) {}
    }

    // ── 1. Load rules ──────────────────────────────────────────
    auto loaded_rules = fw::ConfigParser::load(config_path);
    fw::RuleEngine engine(fw::Action::BLOCK);
    for (auto& r : loaded_rules)
        engine.add_rule(std::move(r));

    // ── 2. Shared state ────────────────────────────────────────
    fw::LiveStats                     stats;
    fw::RingBuffer<fw::PacketRecord>  ring(500);

    // ── 3. Logger ──────────────────────────────────────────────
    fw::Logger logger(log_path, fw::LogLevel::LOG_INFO);
    logger.log(fw::LogLevel::LOG_INFO, "Firewall v2 starting");

    // ── P2-A: Tamper-Proof Hash-Chain Ledger (Pillar 4) ──────
    fw::ChainLedger ledger("logs/ledger.chain", "logs/ledger.json");
    if (ledger.open()) {
        ledger.log_firewall_start();
        logger.log(fw::LogLevel::LOG_INFO, "[Pillar 4] Chain ledger initialized");
    } else {
        logger.log(fw::LogLevel::LOG_ERROR, "[Pillar 4] Failed to open chain ledger");
    }

    // ── P2-B: BVUDP Receiver (Pillar 2) ─────────────────────
    //   Listens on UDP port 9000 for Batch-Verified protocol traffic.
    //   The magic-byte check ensures only BVUDP packets are processed.
    fw::BVUDPReceiver bvudp_rx(9000);
    bvudp_rx.start(
        [&ledger, &logger](uint32_t batch_id, std::vector<uint8_t> payload, sockaddr_in /*sender*/) {
            ledger.log_bvudp_batch(batch_id, payload.size(), /*ok=*/true);
            logger.log(fw::LogLevel::LOG_INFO,
                       "[Pillar 2] BVUDP batch " + std::to_string(batch_id) +
                       " verified " + std::to_string(payload.size()) + " bytes");
            // TODO: dispatch payload to internal application handler
        },
        [&engine, &ledger, &logger](sockaddr_in sender) {
            uint32_t src_ip = ntohl(sender.sin_addr.s_addr);
            // 1. Report to engine to immediately auto-ban the IP
            engine.report_tampering_attempt(src_ip);
            
            // 2. Log tampering event to immutable ledger
            ledger.log_threat_banned(ip4_to_string(src_ip), "Protocol Tampering Attack (HMAC mismatch)");
            logger.log(fw::LogLevel::LOG_WARN, "[Pillar 2] HMAC Mismatch! Autobanning attacker.");
        }
    );
    logger.log(fw::LogLevel::LOG_INFO, "[Pillar 2] BVUDP receiver on UDP:9000");

    // ── P2-C: Port Demultiplexer / WinDivert (Pillar 1) ─────
    //   Intercepts UDP port 80 and 443. BVUDP traffic is pulled
    //   off the OS stack; HTTP/HTTPS is transparently reinjected.
    fw::PortDemux demux({80, 443, 9000}, bvudp_rx);
    demux.start();
    logger.log(fw::LogLevel::LOG_INFO,
               std::string("[Pillar 1] Port demux started — ") +
               (demux.is_observer_mode() ? "observer (no WinDivert)" : "WinDivert active"));

    // ── P2-D: Cloud Control Plane (Pillar 3) ─────────────────
    //   Remote URL is empty by default — uses local cloud_config.json.
    //   Set AEGIS_CONTROL_URL env var to enable remote endpoint.
    std::string cloud_url;
    if (const char* env = std::getenv("AEGIS_CONTROL_URL")) cloud_url = env;
    fw::ControlPlaneClient control_plane(engine, ledger, cloud_url,
                                         "config/cloud_config.json", 60);
    control_plane.set_callback([&logger](const fw::CloudConfig& cfg) {
        logger.log(fw::LogLevel::LOG_INFO,
                   "[Pillar 3] Cloud config applied — " +
                   std::to_string(cfg.rules.size()) + " rules, " +
                   std::to_string(cfg.geo_blocks.size()) + " geo-blocks");
    });
    control_plane.start();
    logger.log(fw::LogLevel::LOG_INFO, "[Pillar 3] Control plane started");

    // ── 4. Start process monitor ──────────────────────────────
    fw::ProcessMonitor proc_mon;
    proc_mon.start();
    logger.log(fw::LogLevel::LOG_INFO, "ProcessMonitor started (port->PID->process mapping active)");

    // ── 5. Start API server ──────────────────────────────────
    fw::ApiServer api(engine, stats, ring, proc_mon, dashboard_root, api_port);
    api.start();

    // ── 5.1 Wire port scan alerts: engine → API → dashboard ──
    // The callback is called from within evaluate() when a scan burst is
    // detected. It simply queues the event in the API server; the dashboard
    // polls GET /api/scans every 3 seconds to display alerts.
    engine.set_scan_callback([&api](fw::ScanEvent ev) {
        api.push_scan_alert(std::move(ev));
    });

    // ── 5.5 Conntrack cleanup thread ─────────────────────────
    std::atomic<bool> conntrack_running{true};
    std::thread conntrack_thread([&]() {
        while (conntrack_running) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            if (!conntrack_running) break;
            engine.purge_stale_connections(std::chrono::seconds(300));
        }
    });

    // ── 6. Open packet capture ─────────────────────────────────
    fw::NfqCapture capture(engine, stats, ring, &proc_mon);
    g_capture = &capture;

    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    if (!capture.open()) {
        logger.log(fw::LogLevel::LOG_ERROR, "Failed to open capture (need elevated privileges)");
        api.stop();
        conntrack_running = false;
        if (conntrack_thread.joinable()) conntrack_thread.join();
        wsa_cleanup();
        return 1;
    }

    const char* mode = capture.is_nfq_mode()
        ? "NFQUEUE (real blocking — active firewall)"
        : "Raw socket observer (passive — log & stats only)";
    logger.log(fw::LogLevel::LOG_INFO, std::string("Capture mode: ") + mode);

    // ── 6.5 Auto-launch dashboard in the browser ──────────────
    {
        std::string url = "http://localhost:" + std::to_string(api_port);
        logger.log(fw::LogLevel::LOG_INFO, "Dashboard API available at " + url);

        // (Auto-opening browser disabled, using standalone UI instead)
    }

    // ── 7. Blocking capture loop (main thread) ─────────────────
    capture.run();

    // ── 8. Shutdown ───────────────────────────────────────────
    api.stop();
    proc_mon.stop();
    conntrack_running = false;
    if (conntrack_thread.joinable()) conntrack_thread.join();

    // Phase 2 shutdown (order: control plane → demux → bvudp → ledger)
    control_plane.stop();
    demux.stop();
    bvudp_rx.stop();

    logger.log(fw::LogLevel::LOG_INFO, "Firewall stopped");
    logger.print_stats();

    // Commit final ledger block before closing
    ledger.log_firewall_stop();
    ledger.close();

    wsa_cleanup();
    return 0;
}
