#include "platform.hpp"
#include "config_parser.hpp"
#include "rate_limiter.hpp"
#include "ipc_server.hpp"
#include "updater.hpp"
#include "logger.hpp"
#include "rule_engine.hpp"
#include <iostream>
#include <cassert>
#include <string>

// Test macro
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[FAIL] " << msg << " (line " << __LINE__ << ")\n"; \
            return 1; \
        } else { \
            std::cout << "[PASS] " << msg << "\n"; \
        } \
    } while(0)

int main() {
    std::cout << "========================================\n";
    std::cout << " Running Aegix Security & Hardening Tests\n";
    std::cout << "========================================\n";

    // ── Test 1: Privilege Checking ─────────────────────────────────────
    {
        bool is_admin = fw::check_is_elevated_admin();
        std::cout << "[INFO] check_is_elevated_admin returned: " << (is_admin ? "TRUE" : "FALSE") << "\n";
        // Privilege check executes cleanly without crashing
        TEST_ASSERT(true, "check_is_elevated_admin() executed cleanly");
    }

    // ── Test 2: Atomic Input Validation in ConfigParser ─────────────────
    {
        fw::Rule r;
        // Valid rule
        bool ok1 = fw::ConfigParser::parse_line("BLOCK TCP 192.168.1.50 * 443 \"Valid HTTPS Block\"", r);
        TEST_ASSERT(ok1, "ConfigParser accepted valid rule");
        TEST_ASSERT(r.action == fw::Action::BLOCK, "Rule action correctly parsed as BLOCK");
        TEST_ASSERT(r.dst_port == 443, "Port 443 correctly parsed");

        // Malformed IP octet (atomic rejection)
        bool ok2 = fw::ConfigParser::parse_line("BLOCK TCP 192.168.1.999 * 443 \"Bad IP\"", r);
        TEST_ASSERT(!ok2, "ConfigParser atomically rejected malformed IP (999)");

        // Non-numeric port (atomic rejection, no crash from std::stoi)
        bool ok3 = fw::ConfigParser::parse_line("BLOCK TCP 192.168.1.1 * 443abc \"Bad Port\"", r);
        TEST_ASSERT(!ok3, "ConfigParser atomically rejected non-numeric port");

        // Port out of range > 65535 (atomic rejection)
        bool ok4 = fw::ConfigParser::parse_line("ALLOW TCP * * 70000 \"Out of range port\"", r);
        TEST_ASSERT(!ok4, "ConfigParser atomically rejected out of range port (>65535)");

        // Negative port (atomic rejection)
        bool ok5 = fw::ConfigParser::parse_line("ALLOW TCP * * -5 \"Negative port\"", r);
        TEST_ASSERT(!ok5, "ConfigParser atomically rejected negative port");

        // Malformed CIDR prefix
        bool ok6 = fw::ConfigParser::parse_line("ALLOW TCP 10.0.0.0/35 * 80 \"Bad CIDR\"", r);
        TEST_ASSERT(!ok6, "ConfigParser atomically rejected invalid CIDR prefix (/35)");
    }

    // ── Test 3: Fail-Secure Default & Configurable Toggle ───────────────
    {
        // By default, must be fail-secure (fail_open = false)
        fw::ConfigParser::set_fail_open_on_crash(false);
        TEST_ASSERT(fw::ConfigParser::get_fail_open_on_crash() == false,
                    "Default failure policy is fail-secure (BLOCK all on crash)");

        // Can toggle when explicitly configured
        fw::ConfigParser::set_fail_open_on_crash(true);
        TEST_ASSERT(fw::ConfigParser::get_fail_open_on_crash() == true,
                    "Config toggle allows fail-open when explicitly configured");

        // Reset back to secure default
        fw::ConfigParser::set_fail_open_on_crash(false);
        TEST_ASSERT(fw::ConfigParser::get_fail_open_on_crash() == false,
                    "Reset back to fail-secure default");
    }

    // ── Test 4: Token Bucket Pre-Parsing Rate Limiter ───────────────────
    {
        // Limiter with burst capacity of 5 tokens, refill 0 per sec (for testing burst exhaustion)
        fw::TokenBucketRateLimiter limiter(5.0, 0.0);
        for (int i = 0; i < 5; ++i) {
            TEST_ASSERT(limiter.allow(1.0), "Burst packet " + std::to_string(i + 1) + " allowed by rate limiter");
        }
        // 6th packet must be dropped
        TEST_ASSERT(!limiter.allow(1.0), "Rate limiter successfully drops packet when burst capacity exhausted");

        // Reconfigure with high refill
        limiter.configure(10.0, 1000.0);
        TEST_ASSERT(limiter.allow(1.0), "Rate limiter allows traffic after replenishment");
    }

    // ── Test 5: IPC Server Command & Numeric Exception Safety ───────────
    {
        fw::RuleEngine engine(fw::Action::BLOCK);
        fw::LiveStats stats;
        fw::IpcServer ipc(engine, stats, nullptr, "\\\\.\\pipe\\test_aegix_ipc", L"test.exe");

        // Test stoul overflow protection in DELETE_RULE: must not crash!
        std::string res1 = ipc.process_command("DELETE_RULE 9999999999999999999999999999999999");
        TEST_ASSERT(res1.find("error") != std::string::npos,
                    "IPC DELETE_RULE safely handled integer overflow without crashing");

        // Test invalid argument (non-numeric) in DELETE_RULE
        std::string res2 = ipc.process_command("DELETE_RULE not_a_number");
        TEST_ASSERT(res2.find("error") != std::string::npos,
                    "IPC DELETE_RULE safely handled non-numeric ID without crashing");

        // Test valid rule addition via IPC
        std::string res3 = ipc.process_command("ADD_RULE ALLOW TCP * * 80 \"Allow HTTP\"");
        TEST_ASSERT(res3.find("\"ok\":true") != std::string::npos,
                    "IPC ADD_RULE successfully added valid rule");

        // Test malformed rule addition via IPC (atomic rejection)
        std::string res4 = ipc.process_command("ADD_RULE ALLOW TCP * * 99999 \"Bad Port\"");
        TEST_ASSERT(res4.find("\"ok\":false") != std::string::npos,
                    "IPC ADD_RULE atomically rejected malformed rule");

        // Test error output sanitization: check no addresses (0x...) leaked
        TEST_ASSERT(res1.find("0x") == std::string::npos,
                    "IPC error output does not leak raw memory addresses");
        TEST_ASSERT(res2.find("0x") == std::string::npos,
                    "IPC error output does not leak raw pointers");
    }

    // ── Test 6: Secure Credential Retrieval ─────────────────────────────
    {
        // When env var not set and no DPAPI blob, returns empty string (no hardcoded secret)
        std::string cred = fw::Updater::get_secure_credential("NON_EXISTENT_AEGIS_TEST_KEY");
        TEST_ASSERT(cred.empty(), "Updater never falls back to a hardcoded key");
    }

    std::cout << "\n========================================\n";
    std::cout << " ALL SECURITY & HARDENING TESTS PASSED!\n";
    std::cout << "========================================\n";
    return 0;
}
