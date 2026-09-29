#include "platform.hpp"       // MUST be first — pulls in winsock2.h on Windows
#include "shared/messages.h"
#include "nfq_capture.hpp"
#include "rule_engine.hpp"
#include "logger.hpp"
#include "config_parser.hpp"
#include "api_server.hpp"
#include "ring_buffer.hpp"
#include "process_monitor.hpp"
#include "window.hpp"
#include "engine/correlation_engine.hpp"
#include "engine/dns_firewall.hpp"
#include "engine/failsafe_manager.hpp"
#include "engine/hardware_monitor.hpp"
#include "engine/ip_dodger.hpp"
#include "engine/mac_watchdog.hpp"
#include "engine/vpn_manager.hpp"
#include "engine/app_trust.hpp"
#include "persistence/local_graph_store.hpp"
#include "kernel/driver_comm.hpp"
// ── Phase 2: Four Pillars ─────────────────────────────────────
#include "sha256.hpp"          // Pillar 2+4: cryptographic primitive
#include "bvudp.hpp"           // Pillar 2:   Batch-Verified UDP protocol
#include "port_demux.hpp"      // Pillar 1:   DPI port demultiplexer
#include "chain_ledger.hpp"    // Pillar 4:   tamper-proof event ledger
#include "control_plane.hpp"   // Pillar 3:   cloud control plane client
// ── NTRO SIH26145: Unidirectional Diode AI/ML Threat Engine ──
#include "diode_threat_engine.hpp"
#include "diode_streamer.hpp"
// ── Security Hardening Modules ────────────────────────────────
#include "ipc_server.hpp"
#ifdef _WIN32
#include "ipc_client/ipc_client.hpp"
#endif
#include "rate_limiter.hpp"
#include "updater.hpp"
#include <csignal>
#include <atomic>
#include <chrono>
#include <thread>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>

static fw::Logger* g_logger = nullptr;
static bool g_fail_open_on_crash = false;

#ifdef _WIN32
#include <windows.h>
#include <winsvc.h>
#include <shellapi.h>

static LONG WINAPI aegix_crash_handler(EXCEPTION_POINTERS* ep) {
    (void)ep;
    if (g_logger) {
        g_logger->log_fail_transition(g_fail_open_on_crash, "Unhandled Exception Crash Trigger");
        g_logger->flush();
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

// ──────────────────────────────────────────────────────────────
// Globals for Service Control
// ──────────────────────────────────────────────────────────────
static fw::NfqCapture* g_capture = nullptr;
static std::atomic<bool> g_service_running{false};

static void signal_handler(int) {
    if (g_capture) g_capture->stop();
    g_service_running = false;
}

// ──────────────────────────────────────────────────────────────
// Core Firewall Service Logic
// ──────────────────────────────────────────────────────────────
int run_firewall(int argc, char* argv[]);

void run_core_service() {
    char executable[] = "AegisXII";
    char* service_argv[] = {executable};
    (void)run_firewall(1, service_argv);
}

int run_firewall(int argc, char* argv[]) {

    // ── 0. Platform init (Winsock on Windows, no-op on Linux) ──
    if (!wsa_init()) {
        // No console — failure is silent; firewall simply won't start.
        return 1;
    }

    const std::string config_path    = (argc > 1) ? argv[1] : "config/rules.conf";
    const std::string log_path       = (argc > 2) ? argv[2] : "logs/aegix.log";
    const std::string dashboard_root = (argc > 3) ? argv[3] : "dashboard/";
    int               api_port       = 8080;
    if (argc > 4) {
        try { api_port = std::stoi(argv[4]); } catch (...) {}
    }

    // ── Phase 1.1: Mandatory Privilege Enforcement (Fail-Closed) ──
    if (!check_is_elevated_admin()) {
        fw::Logger err_logger(log_path, fw::LogLevel::LOG_ERROR);
        err_logger.log(fw::LogLevel::LOG_ERROR,
                       "[Security] FATAL: Aegix Firewall requires elevated Administrator or SYSTEM privileges. Failing closed immediately.");
        err_logger.flush();
        return 5; // ERROR_ACCESS_DENIED
    }

    // ── Phase 1.3: Enforce and Verify File ACL Security ────────────
    apply_strict_file_security(config_path);
    apply_strict_file_security(log_path);

    if (!verify_file_security(config_path) || !verify_file_security(log_path)) {
        fw::Logger err_logger(log_path, fw::LogLevel::LOG_ERROR);
        err_logger.log(fw::LogLevel::LOG_ERROR,
                       "[Security] FATAL: File ACL verification failed. Weakened permissions detected on " +
                       config_path + " or " + log_path + ". Failing closed.");
        err_logger.flush();
        return 5;
    }

    // ── 1. Load rules ──────────────────────────────────────────
    auto loaded_rules = fw::ConfigParser::load(config_path);
    fw::RuleEngine engine(fw::Action::BLOCK);
    for (auto& r : loaded_rules) engine.add_rule(std::move(r));

    fw::LiveStats stats;
    fw::RingBuffer<fw::PacketRecord> ring(500);
    fw::Logger logger(log_path, fw::LogLevel::LOG_INFO);
    g_logger = &logger;
    logger.log(fw::LogLevel::LOG_INFO, "Aegix Firewall starting with elevated privileges");

    // ── Phase 3.1: Fail-Secure Architecture & Crash Handler ───────
    g_fail_open_on_crash = fw::ConfigParser::get_fail_open_on_crash();
    logger.log(fw::LogLevel::LOG_INFO,
               std::string("[Security] Engine crash policy initialized: ") +
               (g_fail_open_on_crash ? "FAIL_OPEN" : "FAIL_SECURE (BLOCK all)"));

#ifdef _WIN32
    SetUnhandledExceptionFilter(aegix_crash_handler);
#endif

    // ── Phase 1.4: Hardened Named Pipe IPC Server ─────────────────
    fw::IpcServer ipc_server(engine, stats, &logger, fw::ipc::PIPE_NAME, L"AegisXII.exe");
    ipc_server.start();
    logger.log(fw::LogLevel::LOG_INFO, "[IPC] Hardened Named Pipe IPC server active on \\\\.\\pipe\\AegisXII_IPC");

    fw::ChainLedger ledger("logs/ledger.chain", "logs/ledger.json");
    if (!ledger.open()) {
        logger.log(fw::LogLevel::LOG_ERROR,
                   "Audit ledger unavailable; refusing to start firewall" +
                   (ledger.failure_reason().empty()
                        ? std::string{}
                        : ": " + ledger.failure_reason()));
        logger.flush();
        ipc_server.stop();
        g_service_running = false;
        wsa_cleanup();
        return 1;
    }
    ledger.log_firewall_start();

    fw::BVUDPReceiver bvudp_rx(9000);
    bvudp_rx.start(
        [&](uint32_t batch_id, std::vector<uint8_t> payload, sockaddr_in) {
            ledger.log_bvudp_batch(batch_id, payload.size(), true);
        },
        [&](sockaddr_in sender) {
            uint32_t src_ip = ntohl(sender.sin_addr.s_addr);
            engine.report_tampering_attempt(src_ip);
            ledger.log_threat_banned(ip4_to_string(src_ip), "Protocol Tampering Attack");
        }
    );

    fw::PortDemux demux({80, 443, 9000}, bvudp_rx);
    demux.start();

    std::string cloud_url;
    if (const char* env = std::getenv("AEGIS_CONTROL_URL")) cloud_url = env;
    fw::ControlPlaneClient control_plane(engine, ledger, cloud_url, "config/cloud_config.json", 60);
    control_plane.start();

    fw::LocalGraphStore graph_store("logs/xdr_graph.db");
    graph_store.open();

    fw::ProcessMonitor proc_mon(&graph_store);
    proc_mon.start();
    fw::CorrelationEngine correlation(engine, proc_mon);
    correlation.start();

    // ── 4.5 NTRO SIH26145: Unidirectional Diode Threat Engine ────
    fw::DiodeThreatEngine diode_engine(&ledger);
    fw::DiodeStreamer diode_streamer(diode_engine);
    engine.set_diode_engine(&diode_engine);
    engine.set_diode_mode(true); // Passive Unidirectional Enclave Mode
    logger.log(fw::LogLevel::LOG_INFO, "[NTRO SIH26145] Diode Threat Engine initialized (Passive Enclave Mode)");

    // ── 5. Start API server ──────────────────────────────────
    fw::ApiServer api(engine, stats, ring, proc_mon, dashboard_root, api_port,
                      &diode_engine, &diode_streamer, &ledger);
    api.start();

    fw::DnsFirewall dns_fw;
    fw::MacWatchdog mac_watchdog;
    mac_watchdog.set_callback([&](const fw::MacConflictEvent& ev) {
        if (ev.threat_type == "ARP_Poison" || ev.threat_type == "LAA_Change") {
            struct in_addr addr;
            if (inet_pton(AF_INET, ev.src_ip.c_str(), &addr) == 1) {
                engine.ban_ip(ntohl(addr.s_addr), "MAC Watchdog: " + ev.threat_type);
                ledger.log_threat_banned(ev.src_ip, ev.detail);
            }
        }
    });

    fw::HardwareMonitor hw_mon;
    if (fw::HardwareMonitor::is_admin()) hw_mon.start();

    // ── Instantiate New Pillars (IP Dodger, Failsafe, App Trust, DriverComm) ──
    fw::VpnManager vpn_mgr;
    fw::IpDodger ip_dodger(vpn_mgr, engine);
    ip_dodger.start();

    fw::FailsafeManager failsafe_mgr(engine);
    failsafe_mgr.start();

    fw::AppTrustManager app_trust(failsafe_mgr);

    fw::kernel::DriverComm driver_comm;
    if (driver_comm.initialize()) {
        logger.log(fw::LogLevel::LOG_INFO, "Driver communication initialized.");
        driver_comm.set_event_callback([&](const fw::kernel::EventMeta& ev) {
            if (ev.type == fw::kernel::EventType::PROCESS_CREATE) {
                // In full implementation, map event pid/names and call app_trust.evaluate_behavior
            }
            return fw::kernel::KernelVerdict::ALLOW;
        });
    }

    engine.set_scan_callback([&](fw::ScanEvent /* ev */) {
        // (Optional) Push event to IPC clients if needed
    });

    std::atomic<bool> conntrack_running{true};
    std::thread conntrack_thread([&]() {
        while (conntrack_running && g_service_running) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            engine.purge_stale_connections(std::chrono::seconds(300));
        }
    });

    fw::NfqCapture capture(engine, stats, ring, &proc_mon, &correlation, &graph_store);
    g_capture = &capture;

    capture.set_callback([&](const fw::PacketRecord& rec) {
        if (rec.pid != 0) {
            auto snapshot = proc_mon.snapshot();
            for (const auto& info : snapshot) {
                if (info.pid == rec.pid) {
                    graph_store.log_process(info);
                    break;
                }
            }
        }
        graph_store.log_connection(rec);
        correlation.push_network_event(rec);

        if (!rec.process_name.empty() && fw::ProcessMonitor::is_lolbin(rec.process_name)) {
            proc_mon.log_lolbin_event(rec.process_name, rec.pid, rec.info.dst_ip, rec.info.dst_port);
        }

        bool mac_nonzero = false;
        for (auto b : rec.info.src_mac) if (b) { mac_nonzero = true; break; }
        if (mac_nonzero) mac_watchdog.record(rec.info.src_mac, rec.info.src_ip);
    });

    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    if (!capture.open()) {
        logger.log(fw::LogLevel::LOG_ERROR, "Failed to open capture (need elevated privileges)");
        ipc_server.stop();
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
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        std::string url = "https://127.0.0.1:" + std::to_string(api_port);
#else
        std::string url = "http://127.0.0.1:" + std::to_string(api_port);
#endif
        logger.log(fw::LogLevel::LOG_INFO, "Dashboard API available at " + url);

        // (Auto-opening browser disabled, using standalone UI instead)
    }

    // ── 7. Blocking capture loop (main thread) ─────────────────
    capture.run();

    // ── 8. Shutdown ───────────────────────────────────────────
    ipc_server.stop();
    api.stop();
    proc_mon.stop();
    correlation.stop();
    conntrack_running = false;
    if (conntrack_thread.joinable()) conntrack_thread.join();

    graph_store.close();
    control_plane.stop();
    demux.stop();
    bvudp_rx.stop();

    logger.log(fw::LogLevel::LOG_INFO, "Firewall stopped");
    logger.print_stats();
    logger.flush();

    // Commit final ledger block before closing
    ledger.log_firewall_stop();
    ledger.close();
    wsa_cleanup();
    return 0;
}


#ifdef _WIN32
// ──────────────────────────────────────────────────────────────
// Windows SCM Integration
// ──────────────────────────────────────────────────────────────
SERVICE_STATUS        g_ServiceStatus = {};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;

void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    if (CtrlCode == SERVICE_CONTROL_STOP) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        signal_handler(0); // Stop capture and exit loop
    }
}

void WINAPI ServiceMain(DWORD /* argc */, LPTSTR* /* argv */) {
    g_StatusHandle = RegisterServiceCtrlHandlerA("AegisXII", ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    // Windows services start with System32 as their working directory. All
    // runtime assets (config, dashboard, and logs) are installed beside the
    // executable, so use that directory before starting the backend.
    char executable_path[MAX_PATH] = {};
    const DWORD executable_path_size =
        GetModuleFileNameA(nullptr, executable_path, static_cast<DWORD>(sizeof(executable_path)));
    if (executable_path_size > 0 && executable_path_size < static_cast<DWORD>(sizeof(executable_path))) {
        char* separator = std::strrchr(executable_path, '\\');
        if (separator) {
            *separator = '\0';
            SetCurrentDirectoryA(executable_path);
        }
    }

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    run_core_service(); // Blocks until stopped

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

bool InstallService() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) return false;

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string binPath = std::string("\"") + path + "\" --service";

    SC_HANDLE hService = CreateServiceA(
        hSCManager, "AegisXII", "Aegis XII Firewall Service",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        binPath.c_str(), NULL, NULL, NULL, NULL, NULL
    );

    if (hService) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }
    CloseServiceHandle(hSCManager);
    return false;
}
#endif

#ifdef _WIN32
// The installer build runs this mode once to verify that the actual GUI IPC
// client can exchange requests with the production service IPC server.
static int run_ipc_smoke_test() {
    fw::RuleEngine engine(fw::Action::BLOCK);
    fw::LiveStats stats;
    stats.total = 17;
    stats.blocked = 3;
    stats.bytes_total = 42;

    fw::Logger logger("ipc-smoke-server.log", fw::LogLevel::LOG_DEBUG);
    fw::IpcServer server(engine, stats, &logger);
    server.start();
    std::string result = server.is_running() ? "pipe-connect-timeout" : "server-start-failed";

    fw::gui::IpcClient client;
    bool connected = false;
    for (int attempt = 0; attempt < 100 && server.is_running() && !connected; ++attempt) {
        connected = client.connect();
        if (!connected) std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    fw::ipc::StatsPayload snapshot{};
    bool handshake_ok = connected;
    if (connected) {
        const bool got_stats = client.get_stats(snapshot);
        result = got_stats ? "stats-payload-mismatch" : "stats-request-failed";
        handshake_ok = got_stats && snapshot.total_packets == 17 &&
            snapshot.blocked_packets == 3 && snapshot.bytes_transferred == 42;
        if (handshake_ok) {
            const bool ping_ok = client.ping();
            result = ping_ok ? "passed" : "ping-failed";
            handshake_ok = ping_ok;
        }
    }
    client.disconnect();
    server.stop();
    logger.flush();
    std::ofstream result_file("ipc-smoke-test-result.txt", std::ios::trunc);
    result_file << result << '\n';
    return handshake_ok ? 0 : 1;
}
#endif

// ──────────────────────────────────────────────────────────────
// Dual-Mode Entry Point
// ──────────────────────────────────────────────────────────────
#ifdef _WIN32
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR /* lpCmdLine */, int) {
    int argc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        int len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
        std::string s(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, &s[0], len, nullptr, nullptr);
        args.push_back(s);
    }
    LocalFree(wargv);
#else
int main(int argc, char* argv[]) {
    std::vector<std::string> args;
    for(int i = 0; i < argc; i++) args.push_back(argv[i]);
#endif

    if (args.size() > 1) {
        if (args[1] == "--service") {
#ifdef _WIN32
            SERVICE_TABLE_ENTRYA ServiceTable[] = {
                {(LPSTR)"AegisXII", (LPSERVICE_MAIN_FUNCTIONA)ServiceMain},
                {NULL, NULL}
            };
            StartServiceCtrlDispatcherA(ServiceTable);
#else
            run_core_service(); // Linux daemon mode
#endif
            return 0;
        }
#ifdef _WIN32
        if (args[1] == "--ipc-smoke-test") {
            return run_ipc_smoke_test();
        }
        if (args[1] == "--install") {
            if (InstallService()) MessageBoxA(NULL, "Service Installed Successfully", "Aegis XII", MB_OK);
            else MessageBoxA(NULL, "Failed to Install Service (Run as Admin)", "Aegis XII", MB_ICONERROR);
            return 0;
        }
#endif
    }

    // Default mode: Un-elevated GUI Client
    return fw::gui::run_gui();
}
