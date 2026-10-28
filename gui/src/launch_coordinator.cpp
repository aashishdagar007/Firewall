#include "launch_coordinator.hpp"

#include "ipc_client/ipc_client.hpp"

#include <algorithm>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <winsvc.h>
#endif

namespace fw::gui {

namespace {

#ifdef _WIN32
constexpr char kServiceName[] = "AegisXII";

LaunchResult win32_error(LaunchStatus status, DWORD error) {
  return {status, "Windows error " + std::to_string(error)};
}

bool service_is_running(SC_HANDLE service, DWORD& error) {
  SERVICE_STATUS_PROCESS status{};
  DWORD bytes_needed = 0;
  if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                            reinterpret_cast<LPBYTE>(&status), sizeof(status),
                            &bytes_needed)) {
    error = GetLastError();
    return false;
  }
  error = ERROR_SUCCESS;
  return status.dwCurrentState == SERVICE_RUNNING;
}
#endif

}  // namespace

LaunchCoordinator::LaunchCoordinator(std::chrono::milliseconds timeout)
    : timeout_((std::max)(timeout, std::chrono::milliseconds(1))) {}

LaunchResult LaunchCoordinator::ensure_service_ready() const {
#ifdef _WIN32
  SC_HANDLE manager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager)
    return win32_error(LaunchStatus::ServiceStartDenied, GetLastError());

  SC_HANDLE service = OpenServiceA(
      manager, kServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
  if (!service) {
    const DWORD error = GetLastError();
    CloseServiceHandle(manager);
    return win32_error(error == ERROR_SERVICE_DOES_NOT_EXIST
                           ? LaunchStatus::ServiceNotInstalled
                           : LaunchStatus::ServiceStartDenied,
                       error);
  }

  DWORD status_error = ERROR_SUCCESS;
  if (!service_is_running(service, status_error)) {
    if (status_error != ERROR_SUCCESS) {
      CloseServiceHandle(service);
      CloseServiceHandle(manager);
      return win32_error(LaunchStatus::ServiceStartFailed, status_error);
    }
    if (!StartServiceA(service, 0, nullptr)) {
      const DWORD error = GetLastError();
      if (error != ERROR_SERVICE_ALREADY_RUNNING) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return win32_error(LaunchStatus::ServiceStartFailed, error);
      }
    }
  }

  const auto deadline = std::chrono::steady_clock::now() + timeout_;
  while (std::chrono::steady_clock::now() < deadline) {
    if (service_is_running(service, status_error)) {
      IpcClient client;
      if (client.connect()) {
        const bool healthy = client.ping();
        client.disconnect();
        if (healthy) {
          CloseServiceHandle(service);
          CloseServiceHandle(manager);
          return {LaunchStatus::Ready, "Service and IPC are ready"};
        }
      }
    } else if (status_error != ERROR_SUCCESS) {
      CloseServiceHandle(service);
      CloseServiceHandle(manager);
      return win32_error(LaunchStatus::ServiceStartFailed, status_error);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return {LaunchStatus::ServiceStartTimedOut,
          "The Aegis XII service did not become healthy before the timeout"};
#else
  return {LaunchStatus::UnsupportedPlatform,
          "The Windows service launch coordinator is unavailable on this platform"};
#endif
}

const char* launch_status_message(LaunchStatus status) {
  switch (status) {
    case LaunchStatus::Ready:
      return "Protection service is ready.";
    case LaunchStatus::ServiceNotInstalled:
      return "Aegis XII is not installed correctly. Repair the installation.";
    case LaunchStatus::ServiceStartDenied:
      return "Windows denied access to start the Aegis XII service.";
    case LaunchStatus::ServiceStartFailed:
      return "The Aegis XII service could not start.";
    case LaunchStatus::ServiceStartTimedOut:
      return "The Aegis XII service did not become ready in time.";
    case LaunchStatus::ServiceUnhealthy:
      return "The Aegis XII service is running but not healthy.";
    case LaunchStatus::UnsupportedPlatform:
      return "Service launch coordination is unavailable on this platform.";
  }
  return "The Aegis XII service state is unknown.";
}

}  // namespace fw::gui
