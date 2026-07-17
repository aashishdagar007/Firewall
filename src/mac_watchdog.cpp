// ──────────────────────────────────────────────────────────────
//  mac_watchdog.cpp  –  Layer-2 ARP / MAC Spoofing Detector
//
//  AEGIS XII Pillar P5: MAC Randomization Watchdog
// ──────────────────────────────────────────────────────────────

#include "mac_watchdog.hpp"
#include "platform.hpp" // ip4_to_string

#include <chrono>
#include <cstring>
#include <functional>
#include <iostream>

namespace fw {

// ── Public: set_callback ──────────────────────────────────────

void MacWatchdog::set_callback(MacConflictCallback cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    callback_ = std::move(cb);
}

// ── Public: record ────────────────────────────────────────────

bool MacWatchdog::record(const MacAddr& src_mac, uint32_t src_ip) {
    // Ignore zero IPs and zero MACs (unresolved entries)
    if (src_ip == 0) return false;
    bool all_zero = true;
    for (auto b : src_mac) if (b) { all_zero = false; break; }
    if (all_zero) return false;

    auto now = std::chrono::steady_clock::now();
    std::string ip_str = ip4_to_string(src_ip);

    // ── Check 1: Broadcast MAC flood ─────────────────────────
    if (is_broadcast_mac(src_mac)) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto& bs = bcast_states_[src_ip];
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - bs.window_start).count();

        if (elapsed > static_cast<long long>(BCAST_FLOOD_WINDOW_SEC)) {
            bs.count = 0;
            bs.window_start = now;
        }
        bs.count++;

        if (bs.count > BCAST_FLOOD_THRESHOLD) {
            static const MacAddr bcast_mac = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
            emit_event(ip_str, bcast_mac, bcast_mac,
                       "MAC_Flood",
                       "Broadcast (FF:FF:FF:FF:FF:FF) MAC flood from " + ip_str);
            return true;
        }
        return false; // Broadcast packets are normal at low rates
    }

    // Compute a compact 64-bit hash of the MAC for reverse lookups
    uint64_t mac_hash = 0;
    for (int i = 0; i < 6; ++i)
        mac_hash = (mac_hash << 8) | src_mac[i];

    std::lock_guard<std::mutex> lock(mtx_);

    // ── Check 2: MAC reuse (same MAC, different IP) ───────────
    auto mac_it = mac_to_ip_.find(mac_hash);
    if (mac_it != mac_to_ip_.end() && mac_it->second != src_ip) {
        // This MAC was previously bound to a different IP — spoofing signal
        MacAddr zero_mac = {};
        emit_event(ip_str, src_mac, src_mac,
                   "MAC_Reuse",
                   "MAC " + mac_to_string(src_mac) +
                   " seen on multiple IPs: prev=" +
                   ip4_to_string(mac_it->second) + " now=" + ip_str);
        // Update to new IP (allow continued monitoring)
        mac_it->second = src_ip;
        return true;
    }
    mac_to_ip_[mac_hash] = src_ip;

    // ── Check 3: ARP poisoning / IP→MAC rebinding ────────────
    auto it = ip_to_mac_.find(src_ip);
    if (it != ip_to_mac_.end()) {
        MacAddr& old_mac = it->second.last_mac;
        bool was_laa     = it->second.was_laa;
        bool now_laa     = is_locally_administered(src_mac);

        if (old_mac != src_mac) {
            // The MAC for this IP has changed — possible ARP poisoning
            std::string type = "ARP_Poison";
            std::string detail = "IP " + ip_str +
                " MAC changed: " + mac_to_string(old_mac) +
                " → " + mac_to_string(src_mac);

            // If the old MAC was globally-assigned and new is LAA → stronger signal
            if (!was_laa && now_laa) {
                type   = "LAA_Change";
                detail = "IP " + ip_str +
                    " switched to Locally-Administered MAC: " +
                    mac_to_string(old_mac) + " → " + mac_to_string(src_mac) +
                    " (possible MAC spoofing/anonymization attack)";
            }

            emit_event(ip_str, old_mac, src_mac, type, detail);

            // Update binding
            old_mac           = src_mac;
            it->second.was_laa  = now_laa;
            it->second.last_seen = now;
            return true;
        }

        it->second.last_seen = now;
        return false;
    }

    // ── First time we see this IP → record binding ────────────
    MacHistory hist;
    hist.last_mac  = src_mac;
    hist.was_laa   = is_locally_administered(src_mac);
    hist.first_seen = now;
    hist.last_seen  = now;
    ip_to_mac_[src_ip] = hist;

    return false;
}

// ── Public: get_conflicts ─────────────────────────────────────

std::vector<MacConflictEvent> MacWatchdog::get_conflicts() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return std::vector<MacConflictEvent>(events_.begin(), events_.end());
}

size_t MacWatchdog::active_conflict_count() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return events_.size();
}

// ── Public: cleanup_stale ─────────────────────────────────────

void MacWatchdog::cleanup_stale() {
    std::lock_guard<std::mutex> lock(mtx_);
    auto now = std::chrono::steady_clock::now();
    constexpr long long STALE_SEC = 600; // 10 minutes

    for (auto it = ip_to_mac_.begin(); it != ip_to_mac_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_seen).count();
        if (age > STALE_SEC) {
            // Also remove from mac_to_ip_
            uint64_t mac_hash = 0;
            for (int i = 0; i < 6; ++i)
                mac_hash = (mac_hash << 8) | it->second.last_mac[i];
            mac_to_ip_.erase(mac_hash);
            it = ip_to_mac_.erase(it);
        } else {
            ++it;
        }
    }

    // Trim broadcast states older than 60 seconds
    for (auto it = bcast_states_.begin(); it != bcast_states_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.window_start).count();
        if (age > 60)
            it = bcast_states_.erase(it);
        else
            ++it;
    }
}

// ── Private: emit_event ───────────────────────────────────────

void MacWatchdog::emit_event(const std::string& src_ip,
                              const MacAddr& old_mac,
                              const MacAddr& new_mac,
                              const std::string& type,
                              const std::string& detail,
                              bool banned) {
    // Called with mtx_ already held
    MacConflictEvent ev;
    auto tp = std::chrono::steady_clock::now().time_since_epoch();
    ev.timestamp   = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(tp).count());
    ev.src_ip      = src_ip;
    ev.old_mac     = mac_to_string(old_mac);
    ev.new_mac     = mac_to_string(new_mac);
    ev.threat_type = type;
    ev.detail      = detail;
    ev.auto_banned = banned;

    if (events_.size() >= MAX_EVENTS)
        events_.pop_front();
    events_.push_back(ev);

    // Fire callback (release lock first to avoid deadlock with RuleEngine)
    MacConflictCallback cb_copy = callback_;
    MacConflictEvent ev_copy = ev;
    // NOTE: callback_ is read under the lock; we invoke it after releasing.
    // This is safe because the callback is set once at startup.
    // We store the copy to invoke after the lock scope if needed.
    // For now, invoke while holding the lock (caller must not re-enter record()).
    if (cb_copy)
        cb_copy(ev_copy);
}

} // namespace fw
