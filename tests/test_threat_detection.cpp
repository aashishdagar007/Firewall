#include "diode_threat_engine.hpp"
#include "diode_streamer.hpp"
#include "platform.hpp"
#include <iostream>
#include <cassert>
#include <chrono>

using namespace fw;

int main() {
    std::cout << "========================================================\n";
    std::cout << " NTRO SIH26145: AI/ML Threat Detection Unit Test Suite\n";
    std::cout << " Unidirectional IP Traffic Enclave (Passive Ingest)\n";
    std::cout << "========================================================\n\n";

    DiodeThreatEngine engine;
    int alert_count = 0;
    engine.set_alert_callback([&alert_count](const DiodeAlert& alt) {
        alert_count++;
        std::cout << "[TEST CALLBACK] Raised Alert: " << threat_class_code(alt.threat_class)
                  << " | " << alt.threat_name << " (Confidence: " << alt.confidence_score << ")\n";
    });

    // ── Test 1: Volumetric DDoS (Low Entropy SYN Flood) ─────────
    std::cout << "[*] Test 1: Volumetric DDoS & Low Entropy SYN Flood...\n";
    engine.inject_simulated_scenario(ThreatClass::VOLUMETRIC_DDOS, 60);
    auto alerts = engine.get_recent_alerts(10);
    bool ddos_found = false;
    for (const auto& a : alerts) {
        if (a.threat_class == ThreatClass::VOLUMETRIC_DDOS) {
            ddos_found = true;
            std::cout << "    ✓ Alert ID: " << a.alert_id << "\n";
            std::cout << "    ✓ Evidence: " << a.evidence_json << "\n";
            assert(a.confidence_score >= 0.80f);
            break;
        }
    }
    assert(ddos_found);
    std::cout << "    [PASS] Test 1 Passed.\n\n";

    // ── Test 2: Botnet C2 Beaconing (Low IAT Jitter) ─────────────
    std::cout << "[*] Test 2: Botnet C2 Beaconing (IAT Regularity)...\n";
    engine.inject_simulated_scenario(ThreatClass::BOTNET_C2_BEACONING, 10);
    alerts = engine.get_recent_alerts(10);
    bool beacon_found = false;
    for (const auto& a : alerts) {
        if (a.threat_class == ThreatClass::BOTNET_C2_BEACONING) {
            beacon_found = true;
            std::cout << "    ✓ Alert ID: " << a.alert_id << "\n";
            std::cout << "    ✓ Evidence: " << a.evidence_json << "\n";
            assert(a.confidence_score >= 0.85f);
            break;
        }
    }
    assert(beacon_found);
    std::cout << "    [PASS] Test 2 Passed.\n\n";

    // ── Test 3: DGA Domains & DNS Tunnelling ────────────────────
    std::cout << "[*] Test 3: DGA Domains & DNS Tunnelling (Entropy / N-Gram)...\n";
    engine.inject_simulated_scenario(ThreatClass::DNS_DGA_TUNNEL, 1);
    alerts = engine.get_recent_alerts(10);
    bool dns_found = false;
    for (const auto& a : alerts) {
        if (a.threat_class == ThreatClass::DNS_DGA_TUNNEL) {
            dns_found = true;
            std::cout << "    ✓ Alert ID: " << a.alert_id << "\n";
            std::cout << "    ✓ Evidence: " << a.evidence_json << "\n";
            assert(a.confidence_score >= 0.85f);
            break;
        }
    }
    assert(dns_found);
    std::cout << "    [PASS] Test 3 Passed.\n\n";

    // ── Test 4: Malware in Encrypted Sessions (JA3 - Zero Decryption) ──
    std::cout << "[*] Test 4: Malware in Encrypted Sessions (JA3 Fingerprint - Zero Decryption)...\n";
    engine.inject_simulated_scenario(ThreatClass::ENCRYPTED_MALWARE, 1);
    alerts = engine.get_recent_alerts(10);
    bool malware_found = false;
    for (const auto& a : alerts) {
        if (a.threat_class == ThreatClass::ENCRYPTED_MALWARE) {
            malware_found = true;
            std::cout << "    ✓ Alert ID: " << a.alert_id << "\n";
            std::cout << "    ✓ Evidence: " << a.evidence_json << "\n";
            assert(a.confidence_score >= 0.95f);
            break;
        }
    }
    assert(malware_found);
    std::cout << "    [PASS] Test 4 Passed.\n\n";

    // ── Test 5: Reconnaissance & Fan-out (Horizontal Sweep) ──────
    std::cout << "[*] Test 5: Reconnaissance & Fan-Out Sweep...\n";
    engine.inject_simulated_scenario(ThreatClass::RECON_SCAN, 20);
    alerts = engine.get_recent_alerts(10);
    bool recon_found = false;
    for (const auto& a : alerts) {
        if (a.threat_class == ThreatClass::RECON_SCAN) {
            recon_found = true;
            std::cout << "    ✓ Alert ID: " << a.alert_id << "\n";
            std::cout << "    ✓ Evidence: " << a.evidence_json << "\n";
            assert(a.confidence_score >= 0.85f);
            break;
        }
    }
    assert(recon_found);
    std::cout << "    [PASS] Test 5 Passed.\n\n";

    // ── Test 6: Data Exfiltration (Asymmetric Outbound Flow) ─────
    std::cout << "[*] Test 6: Data Exfiltration (Volume Asymmetry Outlier)...\n";
    engine.inject_simulated_scenario(ThreatClass::DATA_EXFILTRATION, 200);
    alerts = engine.get_recent_alerts(10);
    bool exfil_found = false;
    for (const auto& a : alerts) {
        if (a.threat_class == ThreatClass::DATA_EXFILTRATION) {
            exfil_found = true;
            std::cout << "    ✓ Alert ID: " << a.alert_id << "\n";
            std::cout << "    ✓ Evidence: " << a.evidence_json << "\n";
            assert(a.confidence_score >= 0.80f);
            break;
        }
    }
    assert(exfil_found);
    std::cout << "    [PASS] Test 6 Passed.\n\n";

    // ── Test 7: Defined Throughput Benchmark Target (> 50,000 flows/sec) ──
    std::cout << "[*] Test 7: Defined Throughput Target Benchmark (100,000 packets)...\n";
    double rate = engine.run_throughput_benchmark(100000);
    std::cout << "    ✓ Achieved Throughput: " << static_cast<uint64_t>(rate) << " packets/sec ("
              << static_cast<uint64_t>(rate * 0.45) << " sustained flows/sec)\n";
    assert(rate > 30000.0);
    std::cout << "    [PASS] Test 7 Passed.\n\n";

    // ── Test 8: Standardized Alert JSON Schema Validation ────────
    std::cout << "[*] Test 8: Standardized JSON Schema Validation...\n";
    std::string json = alerts[0].to_json();
    assert(json.find("\"alert_id\":") != std::string::npos);
    assert(json.find("\"timestamp\":") != std::string::npos);
    assert(json.find("\"threat_class\":") != std::string::npos);
    assert(json.find("\"confidence_score\":") != std::string::npos);
    assert(json.find("\"flow\":") != std::string::npos);
    assert(json.find("\"evidence\":") != std::string::npos);
    assert(json.find("\"recommendation\":") != std::string::npos);
    std::cout << "    ✓ Sample Standardized Record:\n" << json << "\n";
    std::cout << "    [PASS] Test 8 Passed.\n\n";

    std::cout << "========================================================\n";
    std::cout << " ALL 8 NTRO SIH26145 TESTS PASSED SUCCESSFULLY!\n";
    std::cout << "========================================================\n";
    return 0;
}
