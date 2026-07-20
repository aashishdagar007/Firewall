#pragma once

#include "kernel_shared.hpp"
#include <string>
#include <functional>
#include <thread>
#include <atomic>

// ──────────────────────────────────────────────────────────────
//  driver_comm.hpp  –  User-mode Client for Ring-0 Driver
//
//  Handles the setup of shared memory and IOCTL communication
//  with the Ring-0 NDIS / Minifilter driver.
// ──────────────────────────────────────────────────────────────

namespace fw {
namespace kernel {

class DriverComm {
public:
    DriverComm();
    ~DriverComm();

    // Opens a handle to the driver and initializes shared memory
    bool initialize();
    void shutdown();

    // Callback fired when an event (network/process/file) needs evaluation
    using EventCallback = std::function<KernelVerdict(const EventMeta&)>;
    void set_event_callback(EventCallback cb);

    // Provide policy updates to the driver
    bool update_kernel_policy(const std::string& policy_data);

private:
    void event_loop();

    void* driver_handle_ = nullptr; // HANDLE
    SharedRingBuffer* shared_mem_ = nullptr;
    
    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    EventCallback callback_;
};

} // namespace kernel
} // namespace fw
