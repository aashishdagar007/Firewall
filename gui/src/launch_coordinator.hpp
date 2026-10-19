#pragma once

#include <chrono>
#include <string>

namespace fw::gui {

enum class LaunchStatus {
  Ready,
  ServiceNotInstalled,
  ServiceStartDenied,
  ServiceStartFailed,
  ServiceStartTimedOut,
  ServiceUnhealthy,
  UnsupportedPlatform,
};

struct LaunchResult {
  LaunchStatus status = LaunchStatus::ServiceUnhealthy;
  std::string detail;

  bool ready() const { return status == LaunchStatus::Ready; }
};

// Coordinates the interactive client with the AegisXII service.  The UI is
// opened only after the service reaches a healthy, authenticated IPC state.
class LaunchCoordinator {
 public:
  explicit LaunchCoordinator(
      std::chrono::milliseconds timeout = std::chrono::seconds(15));

  LaunchResult ensure_service_ready() const;

 private:
  std::chrono::milliseconds timeout_;
};

const char* launch_status_message(LaunchStatus status);

}  // namespace fw::gui
