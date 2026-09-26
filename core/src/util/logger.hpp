#pragma once
#include "util/types.hpp"
#include "engine/rule_engine.hpp"
#include <string>
#include <fstream>
#include <mutex>
#include <deque>
#include <condition_variable>
#include <thread>
#include <atomic>

// ──────────────────────────────────────────────────────────────
//  logger.hpp  –  thread-safe verdict + event logger
// ──────────────────────────────────────────────────────────────

namespace fw {

    // Note: avoid 'ERROR' and 'DEBUG' — Windows SDK defines them as macros.
    enum class LogLevel { LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR };

    class Logger {
    public:
        // log_path = "" means stdout only
        explicit Logger(const std::string& log_path = "",
                        LogLevel min_level = LogLevel::LOG_INFO);
        ~Logger();

        // Log a firewall verdict for a packet
        void log_verdict(const PacketInfo& pkt, const EvalResult& result);

        // General-purpose log line
        void log(LogLevel level, const std::string& msg);

        // Print running statistics (packets seen, allowed, blocked)
        void print_stats();

        // Audit log a transition between fail-secure and fail-open
        void log_fail_transition(bool fail_open, const std::string& trigger_reason);

        // Explicitly flush queued log lines to disk
        void flush();

    private:
        std::string   log_path_;
        std::ofstream file_;
        LogLevel      min_level_;
        mutable std::mutex mtx_;

        // Async log queue & worker thread
        std::deque<std::string> queue_;
        std::condition_variable cv_;
        std::thread             worker_thread_;
        std::atomic<bool>       running_{false};
        void worker_loop();

        // Running counters
        uint64_t total_   = 0;
        uint64_t allowed_ = 0;
        uint64_t blocked_ = 0;

        size_t   current_file_size_ = 0;
        static constexpr size_t MAX_LOG_SIZE = 50 * 1024 * 1024; // 50MB

        void write_immediate(const std::string& line);
        void enqueue(std::string line);
        void rotate_if_needed();
        static std::string timestamp();
        static const char* level_string(LogLevel l);
        static std::string escape_json(const std::string& s);
    };

} // namespace fw
