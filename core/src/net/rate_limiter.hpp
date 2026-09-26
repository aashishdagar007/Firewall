#pragma once

#include <chrono>
#include <mutex>
#include <algorithm>
#include <cstdint>

namespace fw {

// ──────────────────────────────────────────────────────────────
//  rate_limiter.hpp  –  Token-Bucket Rate Limiter
//
//  Positioned ahead of the packet parser to protect CPU resources
//  from malformed packet floods and volumetric denial-of-service.
// ──────────────────────────────────────────────────────────────

class TokenBucketRateLimiter {
public:
    // capacity: maximum token burst
    // refill_rate_per_sec: tokens replenished each second
    TokenBucketRateLimiter(double capacity = 100000.0, double refill_rate_per_sec = 50000.0)
        : capacity_(capacity),
          tokens_(capacity),
          refill_rate_(refill_rate_per_sec),
          last_update_(std::chrono::steady_clock::now()) {}

    void configure(double capacity, double refill_rate_per_sec) {
        std::lock_guard<std::mutex> lock(mtx_);
        capacity_ = capacity;
        refill_rate_ = refill_rate_per_sec;
        tokens_ = std::min(tokens_, capacity_);
    }

    // Returns true if packet is allowed through to parsing, false if rate limit exceeded
    bool allow(double tokens = 1.0) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto now = std::chrono::steady_clock::now();
        double elapsed_sec = std::chrono::duration<double>(now - last_update_).count();
        last_update_ = now;

        // Replenish tokens
        tokens_ = std::min(capacity_, tokens_ + elapsed_sec * refill_rate_);

        if (tokens_ >= tokens) {
            tokens_ -= tokens;
            return true;
        }
        return false;
    }

private:
    double capacity_;
    double tokens_;
    double refill_rate_;
    std::chrono::steady_clock::time_point last_update_;
    std::mutex mtx_;
};

} // namespace fw
