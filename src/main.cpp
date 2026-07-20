#include "util/platform.hpp"       
#include "net/nfq_capture.hpp"
#include "engine/rule_engine.hpp"
#include "util/logger.hpp"
#include "persistence/config_parser.hpp"
#include "util/ring_buffer.hpp"
#include "engine/process_monitor.hpp"
#include "persistence/local_graph_store.hpp"
#include "engine/correlation_engine.hpp"
#include "util/sha256.hpp"          
#include "net/bvudp.hpp"           
#include "net/port_demux.hpp"      
#include "persistence/chain_ledger.hpp"    
#include "engine/control_plane.hpp"   
#include "engine/dns_firewall.hpp"    
#include "engine/mac_watchdog.hpp"    
#include "engine/hardware_monitor.hpp" 
#include "ipc/ipc_server.hpp"
#include "engine/ip_dodger.hpp"
#include "engine/failsafe_manager.hpp"
#include "engine/app_trust.hpp"
#include "kernel/driver_comm.hpp"
#include "engine/vpn_manager.hpp"
#include "../../gui/src/window.hpp"

#include <csignal>
#include <atomic>
#include <thread>
#include <string>
#include <vector>
#include <cstdlib>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <winsvc.h>
#include <shellapi.h>
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
void run_core_service() {
    if (!wsa_init()) return;
    g_service_running = true;

    // Hardcoded paths since service runs from system32 typically; in prod use absolute paths
    const std::string config_path = "config/rules.conf";
    const std::string log_path    = "logs/firewall.log";

    auto loaded_rules = fw::ConfigParser::load(config_path);
    fw::RuleEngine engine(fw::Action::BLOCK);
    for (auto& r : loaded_rules) engine.add_rule(std::move(r));

    fw::LiveStats stats;
    fw::RingBuffer<fw::PacketRecord> ring(500);
    fw::Logger logger(log_path, fw::LogLevel::LOG_INFO);
    logger.log(fw::LogLevel::LOG_INFO, "Aegis XII Core Service starting");

    fw::ChainLedger ledger("logs/ledger.chain", "logs/ledger.json");
    if (ledger.open()) ledger.log_firewall_start();

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

    // ── Start IPC Server (Replaces API Server) ──
    fw::ipc::IpcServer ipc(engine, stats);
    ipc.start();
    logger.log(fw::LogLevel::LOG_INFO, "IPC Server listening on Named Pipe");

    engine.set_scan_callback([&](fw::ScanEvent ev) {
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

    if (capture.open()) {
        logger.log(fw::LogLevel::LOG_INFO, "Capture started. Entering blocking loop.");
        capture.run(); // Blocks until capture is stopped
    } else {
        logger.log(fw::LogLevel::LOG_ERROR, "Failed to open capture (needs admin).");
    }

    // Shutdown
    driver_comm.shutdown();
    failsafe_mgr.stop();
    ip_dodger.stop();
    ipc.stop();
    hw_mon.stop();
    proc_mon.stop();
    correlation.stop();
    conntrack_running = false;
    if (conntrack_thread.joinable()) conntrack_thread.join();

    graph_store.close();
    control_plane.stop();
    demux.stop();
    bvudp_rx.stop();

    ledger.log_firewall_stop();
    ledger.close();
    wsa_cleanup();
}


#ifdef _WIN32
// ──────────────────────────────────────────────────────────────
// Windows SCM Integration
// ──────────────────────────────────────────────────────────────
SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;

void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    if (CtrlCode == SERVICE_CONTROL_STOP) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        signal_handler(0); // Stop capture and exit loop
    }
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandlerA("AegisXII", ServiceCtrlHandler);
    if (!g_StatusHandle) return;

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

// ──────────────────────────────────────────────────────────────
// Dual-Mode Entry Point
// ──────────────────────────────────────────────────────────────
#ifdef _WIN32
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
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
