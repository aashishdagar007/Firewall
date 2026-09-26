#pragma once

#include <string>
#include <vector>
#include <functional>

namespace fw {

class Logger;

// ──────────────────────────────────────────────────────────────
//  updater.hpp  –  Secure Update & Threat-Intel Client
//
//  Security Guarantees:
//    1. Strict TLS verification (system root trust store + hostname check).
//    2. No insecure flags (all WINHTTP_OPTION_SECURITY_FLAGS bypasses cleared).
//    3. Optional certificate / public-key SHA-256 fingerprint pinning.
//    4. API keys resolved exclusively via environment variables or
//       DPAPI-encrypted blob (never hardcoded in binary).
// ──────────────────────────────────────────────────────────────

struct UpdateCheckResult {
    bool        success = false;
    bool        update_available = false;
    std::string new_version;
    std::string download_url;
    std::string sha256_hash;
    std::string error_message;
};

class Updater {
public:
    Updater(Logger* logger,
            const std::string& update_host = "update.aegix-firewall.internal",
            uint16_t port = 443,
            const std::string& pinned_sha256 = "");

    // Securely retrieve API / threat-intel key from env var or DPAPI
    static std::string get_secure_credential(const std::string& env_var_name,
                                             const std::vector<uint8_t>& dpapi_blob = {});

    // Perform authenticated HTTPS check for updates with strict TLS verification
    UpdateCheckResult check_for_updates(const std::string& current_version);

private:
    Logger*     logger_;
    std::string update_host_;
    uint16_t    port_;
    std::string pinned_sha256_;

#ifdef _WIN32
    UpdateCheckResult check_winhttp(const std::string& current_version, const std::string& api_key);
#endif
};

} // namespace fw
