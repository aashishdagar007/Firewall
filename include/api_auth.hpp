#pragma once

#include <chrono>
#include <cstddef>
#include <mutex>
#include <string_view>

namespace fw {

inline bool constant_time_equal(std::string_view expected,
                                std::string_view supplied) {
  size_t difference = expected.size() ^ supplied.size();
  for (size_t i = 0; i < expected.size(); ++i) {
    const unsigned char supplied_byte =
        i < supplied.size() ? static_cast<unsigned char>(supplied[i]) : 0;
    difference |= static_cast<unsigned char>(expected[i]) ^ supplied_byte;
  }
  return difference == 0;
}

class ApiAuthenticationGuard {
 public:
  enum class Result { Authorized, Unauthorized, LockedOut };

  Result authorize(std::string_view expected, std::string_view supplied) {
    const bool token_valid = constant_time_equal(expected, supplied);
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = std::chrono::steady_clock::now();
    if (now < lockout_until_) return Result::LockedOut;

    if (lockout_until_ != std::chrono::steady_clock::time_point{}) {
      failed_attempts_ = 0;
      lockout_until_ = {};
    }

    if (token_valid) {
      failed_attempts_ = 0;
      return Result::Authorized;
    }

    ++failed_attempts_;
    if (failed_attempts_ >= kMaxFailedAttempts) {
      failed_attempts_ = 0;
      lockout_until_ = now + kLockoutDuration;
      return Result::LockedOut;
    }
    return Result::Unauthorized;
  }

 private:
  static constexpr unsigned int kMaxFailedAttempts = 5;
  static constexpr std::chrono::seconds kLockoutDuration{60};

  std::mutex mutex_;
  unsigned int failed_attempts_ = 0;
  std::chrono::steady_clock::time_point lockout_until_{};
};

}  // namespace fw
