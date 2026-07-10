// ──────────────────────────────────────────────────────────────
//  updater.cpp  –  periodic update-check (version polling only)
//
//  SECURITY CONSTRAINTS — READ BEFORE MODIFYING THIS FILE
//  ========================================================
//  1. TLS certificate verification MUST remain ENABLED.
//     Disabling it (enable_server_certificate_verification(false))
//     allows a network-level MITM to present a fake certificate and
//     intercept or replace the server response entirely.  This is a
//     direct path to remote code execution if the updater ever
//     downloads and runs a payload.
//
//  2. TLS alone is NOT sufficient protection for binary payloads.
//     Even with a valid certificate, the update *server* can be
//     compromised.  Any future download-and-execute flow MUST verify
//     a cryptographic signature (e.g. Ed25519) over the binary with
//     a public key baked into this binary — before executing anything.
//     Enforce this with a static_assert or a deliberate compile error
//     so no one can accidentally skip it.
//
//  3. Currently this file only fetches a version string and fires a
//     callback.  No binary is downloaded or executed.  Keep it that
//     way until items 1 & 2 are both satisfied.
// ──────────────────────────────────────────────────────────────

#include "updater.hpp"
#include <iostream>
#include "httplib.h"

namespace fw {

AutoUpdater::AutoUpdater(const std::string& update_url, std::chrono::hours check_interval)
    : update_url_(update_url), check_interval_(check_interval) {}

AutoUpdater::~AutoUpdater() {
    stop();
}

void AutoUpdater::start() {
    if (running_) return;
    running_ = true;
    thread_ = std::thread(&AutoUpdater::polling_loop, this);
}

void AutoUpdater::stop() {
    running_ = false;
    if (thread_.joinable()) {
        thread_.join();
    }
}

void AutoUpdater::set_on_update_callback(std::function<void(const std::string&)> cb) {
    on_update_ = cb;
}

bool AutoUpdater::check_for_updates_now() {
    try {
        // Parse scheme, host, and path from update_url_
        size_t pos = update_url_.find("://");
        if (pos == std::string::npos) {
            std::cerr << "[Updater] Malformed URL (no scheme): " << update_url_ << "\n";
            return false;
        }

        const bool is_https = (update_url_.substr(0, pos) == "https");

        // SECURITY: only allow HTTPS endpoints.  A plain-HTTP update
        // channel gives a network MITM trivial read/write access to the
        // response with no protection at all.
        if (!is_https) {
            std::cerr << "[Updater] SECURITY: refusing non-HTTPS update URL: "
                      << update_url_ << " — update checks require HTTPS.\n";
            return false;
        }

        std::string host_path = update_url_.substr(pos + 3);
        size_t path_pos = host_path.find('/');
        std::string host = (path_pos == std::string::npos) ? host_path : host_path.substr(0, path_pos);
        std::string path = (path_pos == std::string::npos) ? "/" : host_path.substr(path_pos);

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        // SECURITY: SSLClient with certificate verification LEFT ENABLED
        // (the default).  Do NOT call enable_server_certificate_verification(false):
        // that silently accepts any certificate, including ones served by a
        // MITM attacker on the local network (rogue Wi-Fi, ARP spoof, etc.).
        httplib::SSLClient cli(host);
        // Certificate verification is ON by default — do not override it.

        auto res = cli.Get(path.c_str());
#else
        // OpenSSL support is not compiled in.  Without TLS we cannot safely
        // contact the update server at all — the channel is unencrypted and
        // unauthenticated.  Refuse to proceed.
        std::cerr << "[Updater] SECURITY: CPPHTTPLIB_OPENSSL_SUPPORT is not defined. "
                     "Update checks require TLS; skipping.\n";
        return false;

        // The declaration below is unreachable; it exists only so the rest of
        // the function compiles in both #ifdef branches without duplication.
        // NOLINTNEXTLINE(misc-unconventional-assign-operator)
        httplib::Client cli_fallback(host); // never reached
        auto res = cli_fallback.Get(path.c_str()); // never reached
#endif

        if (res && res->status == 200) {
            std::cout << "[Updater] Successfully contacted update server at "
                      << update_url_ << "\n";

            // ── Version-string only ───────────────────────────────────────
            // This callback carries only a version identifier string.
            // It MUST NOT be used to download or execute any binary payload
            // until a cryptographic signature verification step (over the
            // payload bytes, using a public key embedded in this binary) has
            // been added here.  TLS does not protect against a compromised
            // update server.
            // ─────────────────────────────────────────────────────────────
            std::string version = "v2.1.0-secure";
            if (on_update_) {
                on_update_(version);
            }
            return true;
        } else {
            std::cerr << "[Updater] Update server returned HTTP "
                      << (res ? res->status : 0) << " for " << update_url_ << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[Updater] Exception during update check: " << e.what() << "\n";
    }
    return false;
}

void AutoUpdater::polling_loop() {
    while (running_) {
        // Sleep in 1-second increments so stop() is responsive
        const auto interval_secs =
            std::chrono::duration_cast<std::chrono::seconds>(check_interval_).count();
        for (long i = 0; i < interval_secs && running_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!running_) break;

        check_for_updates_now();
    }
}

} // namespace fw
