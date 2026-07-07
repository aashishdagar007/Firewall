#pragma once
#include <cstdint>
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace fw {

// A simple Token Bucket for rate limiting bandwidth per IP
struct TokenBucket {
    uint64_t tokens;       // Current bytes available
    std::chrono::steady_clock::time_point last_update;
};

class TrafficShaper {
public:
    TrafficShaper();
    ~TrafficShaper() = default;

    // Initialize global default rate in bytes per second
    void set_global_rate_limit(uint64_t bytes_per_sec);
    uint64_t get_global_rate_limit() const;

    // Set custom rate limit for a specific IP
    void set_ip_rate_limit(uint32_t ip, uint64_t bytes_per_sec);

    // Consume tokens for a packet. Returns true if packet is allowed (enough tokens).
    // Returns false if packet should be dropped (exceeds bandwidth).
    bool consume(uint32_t ip, uint32_t packet_size);

    // Periodic cleanup of stale IPs from the shaper map
    void purge_stale_entries(std::chrono::seconds max_idle_time);

private:
    std::mutex mtx_;
    std::unordered_map<uint32_t, TokenBucket> buckets_;
    
    // Configurable rate limit maps
    std::unordered_map<uint32_t, uint64_t> custom_rates_;
    std::atomic<uint64_t> global_rate_limit_{1024 * 1024}; // Default: 1 MB/s
    
    // Bucket capacity is usually a multiple of the rate (e.g. 1 second burst)
    const uint64_t BURST_MULTIPLIER = 2; 
};

} // namespace fw
