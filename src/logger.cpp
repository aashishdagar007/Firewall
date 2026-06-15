#include "logger.hpp"
#include "packet.hpp"
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

// ──────────────────────────────────────────────────────────────
//  logger.cpp
// ──────────────────────────────────────────────────────────────

namespace fw {

Logger::Logger(const std::string& log_path, LogLevel min_level)
    : log_path_(log_path), min_level_(min_level) {
    if (!log_path_.empty()) {
        file_.open(log_path_, std::ios::app);
        if (!file_.is_open()) {
            std::cerr << "[Logger] WARNING: could not open log file: "
                      << log_path_ << "\n";
        }
    }
}

Logger::~Logger() {
    if (file_.is_open()) file_.close();
}

// ── Verdict logging ──────────────────────────────────────────

void Logger::log_verdict(const PacketInfo& pkt, const EvalResult& result) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_++;
    if (result.verdict == Action::ALLOW) allowed_++; else blocked_++;

    std::ostringstream oss;
    oss << timestamp() << "  "
        << std::setw(5) << action_name(result.verdict) << "  "
        << PacketParser::to_string(pkt);

    if (result.matched_rule) {
        oss << "  [rule #" << result.matched_rule->id
            << ": " << result.matched_rule->description << "]";
    } else {
        oss << "  [default policy]";
    }

    write(oss.str());
}

// ── General log line ─────────────────────────────────────────

void Logger::log(LogLevel level, const std::string& msg) {
    if (level < min_level_) return;
    std::lock_guard<std::mutex> lock(mtx_);
    write(timestamp() + "  " + level_tag(level) + "  " + msg);
}

// ── Statistics ───────────────────────────────────────────────

void Logger::print_stats() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::cout << "\n─── Firewall Statistics ───────────────────────\n"
              << "  Total packets : " << total_   << "\n"
              << "  Allowed       : " << allowed_ << "\n"
              << "  Blocked       : " << blocked_ << "\n"
              << "───────────────────────────────────────────────\n\n";
}

// ── Private helpers ──────────────────────────────────────────

void Logger::write(const std::string& line) {
    std::cout << line << "\n";
    if (file_.is_open())
        file_ << line << "\n";
}

std::string Logger::timestamp() {
    auto now  = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms   = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()) % 1000;

    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

const char* Logger::level_tag(LogLevel l) {
    switch (l) {
        case LogLevel::LOG_DEBUG: return "[DBG]";
        case LogLevel::LOG_INFO:  return "[INF]";
        case LogLevel::LOG_WARN:  return "[WRN]";
        case LogLevel::LOG_ERROR: return "[ERR]";
    }
    return "[???]";
}

} // namespace fw