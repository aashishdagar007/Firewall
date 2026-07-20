#include "driver_comm.hpp"
#include <iostream>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fw {
namespace kernel {

DriverComm::DriverComm() {}

DriverComm::~DriverComm() {
    shutdown();
}

bool DriverComm::initialize() {
    if (running_) return true;

#ifdef _WIN32
    // Attempt to open handle to the Ring-0 driver device
    HANDLE hDevice = CreateFileA(
        "\\\\.\\AegisXIIDriver",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[DriverComm] Failed to open handle to kernel driver. Error: " << GetLastError() << "\n";
        // Fallback or exit
        // return false; 
    }
    driver_handle_ = hDevice;
    
    // Simulate shared memory mapping if driver isn't actually loaded during dev
    if (driver_handle_ == INVALID_HANDLE_VALUE) {
        std::cerr << "[DriverComm] Running in mock mode (driver not present)\n";
        shared_mem_ = new SharedRingBuffer();
        shared_mem_->magic = SHARED_MEMORY_MAGIC;
        shared_mem_->version = SHARED_MEMORY_VERSION;
        shared_mem_->head = 0;
        shared_mem_->tail = 0;
    } else {
        // Request shared memory mapping from driver
        DWORD bytesReturned = 0;
        void* mapped_addr = nullptr;
        
        BOOL result = DeviceIoControl(
            hDevice,
            IOCTL_AEGIS_GET_SHARED_MEM,
            NULL, 0,
            &mapped_addr, sizeof(mapped_addr),
            &bytesReturned,
            NULL
        );
        
        if (result && mapped_addr) {
            shared_mem_ = static_cast<SharedRingBuffer*>(mapped_addr);
        } else {
            std::cerr << "[DriverComm] Failed to map shared memory.\n";
            return false;
        }
    }
#else
    // Linux equivalent (netlink or eBPF maps) goes here. 
    // For now, mock it.
    shared_mem_ = new SharedRingBuffer();
    shared_mem_->magic = SHARED_MEMORY_MAGIC;
    shared_mem_->head = 0;
    shared_mem_->tail = 0;
#endif

    running_ = true;
    worker_thread_ = std::thread(&DriverComm::event_loop, this);
    return true;
}

void DriverComm::shutdown() {
    running_ = false;
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    
#ifdef _WIN32
    if (driver_handle_ && driver_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(driver_handle_);
        driver_handle_ = nullptr;
    } else {
        delete shared_mem_;
    }
#else
    delete shared_mem_;
#endif
    shared_mem_ = nullptr;
}

void DriverComm::set_event_callback(EventCallback cb) {
    callback_ = std::move(cb);
}

bool DriverComm::update_kernel_policy(const std::string& policy_data) {
#ifdef _WIN32
    if (driver_handle_ && driver_handle_ != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            driver_handle_,
            IOCTL_AEGIS_SET_POLICY,
            (LPVOID)policy_data.data(), (DWORD)policy_data.size(),
            NULL, 0,
            &bytesReturned,
            NULL
        );
        return result == TRUE;
    }
#endif
    return false;
}

void DriverComm::event_loop() {
    while (running_) {
        if (!shared_mem_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        uint32_t head = shared_mem_->head;
        uint32_t tail = shared_mem_->tail;

        if (head != tail) {
            // Process new events from driver
            EventMeta& ev = shared_mem_->events[tail % RING_BUFFER_SIZE];
            
            KernelVerdict verdict = KernelVerdict::ALLOW;
            if (callback_) {
                verdict = callback_(ev);
            }
            
            // Set the verdict. In a real implementation, the driver might be waiting on an event 
            // object or periodically polling this field for async packets.
            ev.verdict = verdict;
            
            shared_mem_->tail = (tail + 1) % RING_BUFFER_SIZE;
        } else {
            // Backoff when idle to save CPU cycles
            // Real implementation might use WaitForSingleObject on an event signalled by the driver
            std::this_thread::sleep_for(std::chrono::microseconds(50));
        }
    }
}

} // namespace kernel
} // namespace fw
