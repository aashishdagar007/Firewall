#include "port_scan_detector.hpp"
#include "platform.hpp"   // ip4_to_string
#include <chrono>
#include <sstream>

// ──────────────────────────────────────────────────────────────
//  port_scan_detector.cpp
//
//  Sliding-window cross-port correlation detector.
//
//  Algorithm:
//    For each packet from src_ip:
//      1. Append (dst_port, now) to the per-IP, per-protocol deque.
//      2. Trim hits older than WINDOW_SEC from the front.
//      3. Rebuild the unique-port set from the trimmed deque.
//      4. If |unique_ports| > PORT_THRESHOLD and not in cooldown:
//           → classify scan type
//           → emit ScanEvent
//           → fire registered callback
// ──────────────────────────────────────────────────────────────

namespace fw {

// ── Helpers ───────────────────────────────────────────────────

static std::string now_ms_str() {
    auto now = std::chrono::system_clock::now();
    auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                   now.time_since_epoch()).count();
    return std::to_string(ms);
}

/*static*/ void PortScanDetector::trim_window(
    std::deque<ScanState::PortHit>& hits,
    std::unordered_set<uint16_t>&   unique_set,
    std::chrono::steady_clock::time_point cutoff)
{
    // Drop entries older than cutoff from the front
    while (!hits.empty() && hits.front().when < cutoff) {
        hits.pop_front();
    }
    // Rebuild unique set from what remains
    unique_set.clear();
    for (const auto& h : hits) {
        unique_set.insert(h.port);
    }
}

void PortScanDetector::emit_event(uint32_t src_ip, ScanType type,
                                   uint32_t ports, bool banned)
{
    ScanEvent ev;
    ev.src_ip      = src_ip;
    ev.ip_str      = ip4_to_string(src_ip);
    ev.scan_type   = type;
    ev.ports_probed = ports;
    ev.timestamp   = now_ms_str();
    ev.auto_banned = banned;

    recent_events_.push_back(ev);
    if (recent_events_.size() > 200)
        recent_events_.pop_front();

    if (callback_) {
        callback_(ev);
    }
}

// ── Main record() ─────────────────────────────────────────────

std::optional<ScanEvent> PortScanDetector::record(const PacketInfo& pkt) {
    // Skip packets with no useful port info
    if (pkt.src_ip == 0) return std::nullopt;
    // Skip loopback
    uint8_t b1 = static_cast<uint8_t>((pkt.src_ip >> 24) & 0xFF);
    if (b1 == 127) return std::nullopt;

    auto now    = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(WINDOW_SEC);

    std::lock_guard<std::mutex> lock(mtx_);

    // Periodic cleanup
    if (now - last_cleanup_ > std::chrono::seconds(CLEANUP_SEC)) {
        cleanup_stale();
        last_cleanup_ = now;
    }

    auto& st = states_[pkt.src_ip];
    st.last_seen = now;

    bool is_tcp  = (pkt.proto == Proto::TCP);
    bool is_udp  = (pkt.proto == Proto::UDP);
    bool is_icmp = (pkt.proto == Proto::ICMP);

    // Detect stealth scan flags (even if rule engine already blocked them,
    // we still want cross-port correlation)
    bool is_stealth_scan = is_tcp && (
        pkt.tcp_flags == 0                                         ||  // NULL
        ((pkt.tcp_flags & TCP_FIN) && !(pkt.tcp_flags & TCP_ACK)) ||  // FIN
        ((pkt.tcp_flags & (TCP_FIN | TCP_PSH | TCP_URG)) ==
         (TCP_FIN | TCP_PSH | TCP_URG))                               // XMAS
    );

    // ── Record the hit ────────────────────────────────────────
    if (is_tcp && pkt.dst_port != 0) {
        st.tcp_hits.push_back({pkt.dst_port, now});
        trim_window(st.tcp_hits, st.tcp_unique, cutoff);
    }
    if (is_udp && pkt.dst_port != 0) {
        st.udp_hits.push_back({pkt.dst_port, now});
        trim_window(st.udp_hits, st.udp_unique, cutoff);
    }
    if (is_icmp) {
        // Track ICMP type as a "port" for ICMP sweep detection
        st.icmp_hits.push_back({pkt.icmp_type, now});
        // Trim ICMP hits too (reuse tcp_unique trimmer with a temp set)
        while (!st.icmp_hits.empty() && st.icmp_hits.front().when < cutoff)
            st.icmp_hits.pop_front();
    }

    // ── Check thresholds ─────────────────────────────────────
    uint32_t tcp_ports  = static_cast<uint32_t>(st.tcp_unique.size());
    uint32_t udp_ports  = static_cast<uint32_t>(st.udp_unique.size());
    uint32_t total_ports = tcp_ports + udp_ports;

    // Already reported in this burst — suppress duplicates
    if (st.already_reported) return std::nullopt;

    ScanType detected_type;
    uint32_t detected_ports = 0;
    bool     scan_detected  = false;

    if (is_stealth_scan && tcp_ports > PORT_THRESHOLD) {
        detected_type  = ScanType::STEALTH_PROBE;
        detected_ports = tcp_ports;
        scan_detected  = true;
    } else if (tcp_ports > PORT_THRESHOLD && udp_ports <= 3) {
        detected_type  = ScanType::SYN_SWEEP;
        detected_ports = tcp_ports;
        scan_detected  = true;
    } else if (udp_ports > PORT_THRESHOLD && tcp_ports <= 3) {
        detected_type  = ScanType::UDP_SWEEP;
        detected_ports = udp_ports;
        scan_detected  = true;
    } else if (total_ports > PORT_THRESHOLD) {
        detected_type  = ScanType::MIXED_SWEEP;
        detected_ports = total_ports;
        scan_detected  = true;
    } else if (!st.icmp_hits.empty() &&
               st.icmp_hits.size() > PORT_THRESHOLD * 2) {
        // Many ICMP echo requests — possible ping sweep
        detected_type  = ScanType::ICMP_SWEEP;
        detected_ports = static_cast<uint32_t>(st.icmp_hits.size());
        scan_detected  = true;
    }

    if (!scan_detected) return std::nullopt;

    // Mark as reported so we don't spam for the same burst
    st.already_reported = true;

    // Emit the event (callback fires here, inside the lock — brief)
    emit_event(pkt.src_ip, detected_type, detected_ports, /*banned=*/true);

    // Return the last emitted event
    return recent_events_.back();
}

// ── Callback registration ─────────────────────────────────────

void PortScanDetector::set_callback(Callback cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    callback_ = std::move(cb);
}

// ── Periodic cleanup ──────────────────────────────────────────

void PortScanDetector::cleanup_stale() {
    // Must be called under mtx_ lock
    auto now     = std::chrono::steady_clock::now();
    auto cutoff  = now - std::chrono::seconds(COOLDOWN_SEC);

    for (auto it = states_.begin(); it != states_.end(); ) {
        if (it->second.last_seen < cutoff) {
            it = states_.erase(it);
        } else {
            // Reset the "already_reported" flag after cooldown
            auto& st = it->second;
            if (st.already_reported &&
                now - st.last_seen > std::chrono::seconds(COOLDOWN_SEC))
            {
                st.already_reported = false;
                st.tcp_hits.clear();
                st.udp_hits.clear();
                st.icmp_hits.clear();
                st.tcp_unique.clear();
                st.udp_unique.clear();
            }
            ++it;
        }
    }
}

// ── Snapshot for API ──────────────────────────────────────────

std::vector<ScanEvent> PortScanDetector::get_recent_events() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return std::vector<ScanEvent>(recent_events_.begin(), recent_events_.end());
}

} // namespace fw
