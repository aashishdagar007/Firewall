#include "traffic_shaper.hpp"
#include <algorithm>

namespace fw {

TrafficShaper::TrafficShaper() {
}

void TrafficShaper::set_global_rate_limit(uint64_t bytes_per_sec) {
    global_rate_limit_.store(bytes_per_sec);
}

uint64_t TrafficShaper::get_global_rate_limit() const {
    return global_rate_limit_.load();
}

void TrafficShaper::set_ip_rate_limit(uint32_t ip, uint64_t bytes_per_sec) {
    std::lock_guard<std::mutex> lock(mtx_);
    custom_rates_[ip] = bytes_per_sec;
}

bool TrafficShaper::consume(uint32_t ip, uint32_t packet_size) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mtx_);

    uint64_t rate = global_rate_limit_.load();
    if (auto it = custom_rates_.find(ip); it != custom_rates_.end()) {
        rate = it->second;
    }

    // If rate is 0, no limit
    if (rate == 0) return true;

    uint64_t capacity = rate * BURST_MULTIPLIER;

    auto& bucket = buckets_[ip];
    if (bucket.last_update.time_since_epoch().count() == 0) {
        // Initialize bucket to full capacity
        bucket.tokens = capacity;
        bucket.last_update = now;
    } else {
        // Refill tokens based on elapsed time
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - bucket.last_update).count();
        if (elapsed > 0) {
            uint64_t generated = (rate * elapsed) / 1000;
            bucket.tokens = std::min(capacity, bucket.tokens + generated);
            bucket.last_update = now;
        }
    }

    if (bucket.tokens >= packet_size) {
        bucket.tokens -= packet_size;
        return true;
    }

    // Not enough tokens, packet should be dropped or delayed
    return false;
}

void TrafficShaper::purge_stale_entries(std::chrono::seconds max_idle_time) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = buckets_.begin(); it != buckets_.end(); ) {
        if (now - it->second.last_update > max_idle_time) {
            it = buckets_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace fw
