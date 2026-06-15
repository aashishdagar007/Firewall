#pragma once
#include <deque>
#include <mutex>
#include <vector>
#include <functional>

// ──────────────────────────────────────────────────────────────
//  ring_buffer.hpp
//
//  A thread-safe circular buffer that keeps the last N items.
//  Used to expose the live packet feed via the REST API.
// ──────────────────────────────────────────────────────────────

namespace fw {

template<typename T>
class RingBuffer {
public:
    explicit RingBuffer(size_t capacity) : capacity_(capacity) {}

    void push(T item) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (buf_.size() >= capacity_)
            buf_.pop_front();
        buf_.push_back(std::move(item));
    }

    // Returns a snapshot of all current items (newest last)
    std::vector<T> snapshot() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return std::vector<T>(buf_.begin(), buf_.end());
    }

    // Returns up to `n` most recent items (newest last)
    std::vector<T> tail(size_t n) const {
        std::lock_guard<std::mutex> lock(mtx_);
        size_t start = (buf_.size() > n) ? buf_.size() - n : 0;
        return std::vector<T>(buf_.begin() + start, buf_.end());
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return buf_.size();
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mtx_);
        buf_.clear();
    }

private:
    mutable std::mutex mtx_;
    std::deque<T>      buf_;
    size_t             capacity_;
};

} // namespace fw
