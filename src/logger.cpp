#include "logger.hpp"
#include "packet.hpp"
#include "platform.hpp"
#include <chrono>
#include <cstdio> // for std::rename, std::remove
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>


// ──────────────────────────────────────────────────────────────
//  logger.cpp (Structured JSON + Rotation)
// ──────────────────────────────────────────────────────────────

namespace fw {

Logger::Logger(const std::string &log_path, LogLevel min_level)
    : log_path_(log_path), min_level_(min_level) {
  if (!log_path_.empty()) {
    file_.open(log_path_, std::ios::app);
    if (!file_.is_open()) {
      std::cerr << "[Logger] WARNING: could not open log file: " << log_path_
                << "\n";
    } else {
      file_.seekp(0, std::ios::end);
      current_file_size_ = file_.tellp();
    }
  }
  running_ = true;
  worker_thread_ = std::thread(&Logger::worker_loop, this);
}

Logger::~Logger() {
  flush();
  running_ = false;
  cv_.notify_all();
  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }
  if (file_.is_open())
    file_.close();
}

void Logger::worker_loop() {
  // Strip privileges from the logging worker thread
  drop_thread_privileges();

  while (running_ || !queue_.empty()) {
    std::deque<std::string> batch;
    {
      std::unique_lock<std::mutex> lock(mtx_);
      cv_.wait_for(lock, std::chrono::milliseconds(50), [this]() {
        return !queue_.empty() || !running_;
      });
      if (queue_.empty() && !running_) break;
      batch.swap(queue_);
    }

    for (const auto &line : batch) {
      write_immediate(line);
    }
  }
}

void Logger::enqueue(std::string line) {
  {
    std::lock_guard<std::mutex> lock(mtx_);
    if (queue_.size() < 10000) {
      queue_.push_back(std::move(line));
    }
  }
  cv_.notify_one();
}

void Logger::flush() {
  std::deque<std::string> batch;
  {
    std::lock_guard<std::mutex> lock(mtx_);
    batch.swap(queue_);
  }
  for (const auto &line : batch) {
    write_immediate(line);
  }
  if (file_.is_open()) {
    file_.flush();
  }
}

// ── Verdict logging ──────────────────────────────────────────

void Logger::log_verdict(const PacketInfo &pkt, const EvalResult &result) {
#ifdef NDEBUG
  if (min_level_ > LogLevel::LOG_INFO) return;
#endif
  total_++;
  if (result.verdict == Action::ALLOW)
    allowed_++;
  else
    blocked_++;

  std::ostringstream oss;
  oss << "{"
      << "\"timestamp\":\"" << timestamp() << "\","
      << "\"level\":\"INFO\","
      << "\"type\":\"verdict\","
      << "\"verdict\":\"" << action_name(result.verdict) << "\","
      << "\"proto\":\"" << proto_name(pkt.proto) << "\","
      << "\"src_ip\":\"" << ip4_to_string(pkt.src_ip) << "\","
      << "\"dst_ip\":\"" << ip4_to_string(pkt.dst_ip) << "\","
      << "\"src_port\":" << pkt.src_port << ","
      << "\"dst_port\":" << pkt.dst_port << ","
      << "\"size\":" << pkt.size;

  if (result.matched_rule) {
    oss << ",\"rule_id\":" << result.matched_rule->id << ",\"rule_desc\":\""
        << escape_json(result.matched_rule->description) << "\"";
  } else {
    oss << ",\"rule_id\":-1,\"rule_desc\":\"default policy\"";
  }

  if (!pkt.process_name.empty()) {
    oss << ",\"process\":\"" << escape_json(pkt.process_name) << "\"";
  }

  oss << "}";

  enqueue(oss.str());
}

// ── General log line ─────────────────────────────────────────

void Logger::log(LogLevel level, const std::string &msg) {
#ifdef NDEBUG
  if (level == LogLevel::LOG_DEBUG)
    return;
#endif
  if (level < min_level_)
    return;

  std::ostringstream oss;
  oss << "{"
      << "\"timestamp\":\"" << timestamp() << "\","
      << "\"level\":\"" << level_string(level) << "\","
      << "\"type\":\"event\","
      << "\"message\":\"" << escape_json(msg) << "\""
      << "}";
  enqueue(oss.str());
}

// ── Audit transition logging ─────────────────────────────────

void Logger::log_fail_transition(bool fail_open, const std::string &trigger_reason) {
  std::ostringstream oss;
  oss << "{"
      << "\"timestamp\":\"" << timestamp() << "\","
      << "\"level\":\"CRITICAL\","
      << "\"type\":\"fail_transition\","
      << "\"mode\":\"" << (fail_open ? "FAIL_OPEN" : "FAIL_SECURE") << "\","
      << "\"reason\":\"" << escape_json(trigger_reason) << "\""
      << "}";
  write_immediate(oss.str());
}

// ── Statistics ───────────────────────────────────────────────

void Logger::print_stats() {
  std::ostringstream oss;
  oss << "{"
      << "\"timestamp\":\"" << timestamp() << "\","
      << "\"level\":\"INFO\","
      << "\"type\":\"stats\","
      << "\"total\":" << total_ << ","
      << "\"allowed\":" << allowed_ << ","
      << "\"blocked\":" << blocked_ << "}";
  write_immediate(oss.str());
}

// ── Private helpers ──────────────────────────────────────────

void Logger::write_immediate(const std::string &line) {
  std::cout << line << "\n";
  if (file_.is_open()) {
    rotate_if_needed();
    file_ << line << "\n";
    if (file_.fail()) {
      std::cerr << "[Logger] WARNING: failed to write to log file (disk full?): "
                << log_path_ << "\n";
      file_.clear();
    } else {
      current_file_size_ += line.size() + 1;
    }
  }
}

void Logger::rotate_if_needed() {
  if (!file_.is_open() || log_path_.empty())
    return;

  if (current_file_size_ >= MAX_LOG_SIZE) {
    file_.close();

    // Keep up to 5 rotated logs (.1 to .5)
    for (int i = 5; i >= 2; --i) {
      std::string src = log_path_ + "." + std::to_string(i - 1);
      std::string dst = log_path_ + "." + std::to_string(i);
      std::remove(dst.c_str());
      std::rename(src.c_str(), dst.c_str());
    }

    std::string first_dst = log_path_ + ".1";
    std::remove(first_dst.c_str());
    std::rename(log_path_.c_str(), first_dst.c_str());

    file_.open(log_path_, std::ios::out | std::ios::trunc);
    current_file_size_ = 0;

    if (!file_.is_open()) {
      std::cerr << "[Logger] ERROR: could not reopen log file after rotation: "
                << log_path_ << "\n";
      return;
    }

    // Output a rotation event directly to the new file
    std::ostringstream oss;
    oss << "{"
        << "\"timestamp\":\"" << timestamp() << "\","
        << "\"level\":\"INFO\","
        << "\"type\":\"event\","
        << "\"message\":\"Log rotated\""
        << "}";
    file_ << oss.str() << "\n";
    if (file_.fail()) {
      std::cerr << "[Logger] WARNING: failed to write rotation event to new log file\n";
      file_.clear();
    } else {
      current_file_size_ += oss.str().size() + 1;
    }
  }
}

std::string Logger::timestamp() {
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;

  std::ostringstream oss;
  oss << std::put_time(std::localtime(&time), "%Y-%m-%dT%H:%M:%S") << "."
      << std::setfill('0') << std::setw(3) << ms.count() << "Z";
  return oss.str();
}

const char *Logger::level_string(LogLevel l) {
  switch (l) {
  case LogLevel::LOG_DEBUG:
    return "DEBUG";
  case LogLevel::LOG_INFO:
    return "INFO";
  case LogLevel::LOG_WARN:
    return "WARN";
  case LogLevel::LOG_ERROR:
    return "ERROR";
  }
  return "UNKNOWN";
}

std::string Logger::escape_json(const std::string &s) {
  std::ostringstream o;
  for (char c : s) {
    switch (c) {
    case '"':
      o << "\\\"";
      break;
    case '\\':
      o << "\\\\";
      break;
    case '\n':
      o << "\\n";
      break;
    case '\r':
      o << "\\r";
      break;
    case '\t':
      o << "\\t";
      break;
    default:
      o << c;
    }
  }
  return o.str();
}

} // namespace fw