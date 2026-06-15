#include "platform.hpp"       // MUST be first — pulls in winsock2.h on Windows
#include "nfq_capture.hpp"
#include "rule_engine.hpp"
#include "logger.hpp"
#include "config_parser.hpp"
#include "api_server.hpp"
#include "ring_buffer.hpp"
#include "process_monitor.hpp"
#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <string>

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
//    • Run as Administrator (raw socket / SIO_RCVALL needs it)
//    • Build with MinGW-w64 or MSVC via CLion + CMake
//    • For real packet blocking on Windows, integrate WinDivert
// ──────────────────────────────────────────────────────────────

static fw::NfqCapture* g_capture = nullptr;

static void signal_handler(int) {
    std::cout << "\n[Signal] Shutting down firewall...\n";
    if (g_capture) g_capture->stop();
}

int main(int argc, char* argv[]) {
    // ── 0. Platform init (Winsock on Windows, no-op on Linux) ──
    if (!wsa_init()) {
        std::cerr << "[Error] WSAStartup failed — cannot use sockets.\n";
        return 1;
    }

    const std::string config_path    = (argc > 1) ? argv[1] : "config/rules.conf";
    const std::string log_path       = (argc > 2) ? argv[2] : "logs/firewall.log";
    const std::string dashboard_root = (argc > 3) ? argv[3] : "dashboard/";
    const int         api_port       = (argc > 4) ? std::stoi(argv[4]) : 8080;

    std::cout << R"(
  ███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗
  ██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║
  █████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║
  ██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║
  ██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗
  ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
  Real Kernel Firewall + Live Dashboard  |  Aashish Dagar
)" << "\n";

#ifdef _WIN32
    std::cout << "  [Platform] Windows — observer mode (run as Administrator)\n\n";
#else
    std::cout << "  [Platform] Linux — NFQ blocking mode available\n\n";
#endif

    // ── 1. Load rules ──────────────────────────────────────────
    auto loaded_rules = fw::ConfigParser::load(config_path);
    fw::RuleEngine engine(fw::Action::BLOCK);
    for (auto& r : loaded_rules)
        engine.add_rule(std::move(r));
    engine.print_rules();

    // ── 2. Shared state ────────────────────────────────────────
    fw::LiveStats                     stats;
    fw::RingBuffer<fw::PacketRecord>  ring(500);   // keep last 500 packets

    // ── 3. Logger ──────────────────────────────────────────────
    fw::Logger logger(log_path, fw::LogLevel::LOG_INFO);
    logger.log(fw::LogLevel::LOG_INFO, "Firewall v2 starting");

    // ── 4. Start process monitor ──────────────────────────────
    fw::ProcessMonitor proc_mon;
    proc_mon.start();
    std::cout << "[ProcessMonitor] Started (port→PID→process mapping active)\n";

    // ── 5. Start API server ──────────────────────────────────
    fw::ApiServer api(engine, stats, ring, proc_mon, dashboard_root, api_port);
    api.start();

    // ── 5.5 Start Conntrack Cleanup Thread ───────────────────
    std::atomic<bool> conntrack_running{true};
    std::thread conntrack_thread([&]() {
        while (conntrack_running) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            if (!conntrack_running) break;
            // Purge connections idle for > 300 seconds (5 mins)
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

    std::cout << "\nOpen http://localhost:" << api_port
              << " in your browser for the live dashboard.\n"
              << "Press Ctrl-C to stop.\n\n";

    // ── 7. Blocking capture loop (main thread) ─────────────────
    capture.run();

    // ── 8. Shutdown ─────────────────────────────────────────
    api.stop();
    proc_mon.stop();
    conntrack_running = false;
    if (conntrack_thread.joinable()) conntrack_thread.join();
    
    logger.log(fw::LogLevel::LOG_INFO, "Firewall stopped");
    logger.print_stats();

    wsa_cleanup();   // no-op on Linux
    return 0;
}