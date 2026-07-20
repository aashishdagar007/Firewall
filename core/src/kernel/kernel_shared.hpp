#pragma once
#include <cstdint>

// ──────────────────────────────────────────────────────────────
//  kernel_shared.hpp  –  Kernel-User Shared Memory Interface
//
//  Defines the communication structures between the Ring-0 NDIS
//  Lightweight Filter (LWF) / Minifilter and the Ring-3 AegisXII 
//  user-mode service.
// ──────────────────────────────────────────────────────────────

namespace fw {
namespace kernel {

// Magic number to verify shared memory compatibility
constexpr uint32_t SHARED_MEMORY_MAGIC = 0xAE61571C;
constexpr uint32_t SHARED_MEMORY_VERSION = 1;

// Maximum number of packets in the shared ring buffer
constexpr size_t RING_BUFFER_SIZE = 4096;

// Action verdict from user-mode to kernel-mode
enum class KernelVerdict : uint8_t {
    PENDING = 0, // Not yet evaluated by user-mode
    ALLOW = 1,   // Forward packet
    DROP = 2,    // Drop packet silently (Firewall Block)
    REDIRECT = 3 // Route to different interface/VPN (IP Dodging)
};

// Event type to multiplex Network vs File System events
enum class EventType : uint8_t {
    NETWORK = 0,
    PROCESS_CREATE = 1,
    FILE_MODIFY = 2
};

// Simplified packet/event metadata passed from Ring-0 to Ring-3
struct alignas(8) EventMeta {
    uint64_t event_id;         // Unique identifier for the event
    uint64_t timestamp_ns;     // Capture time in nanoseconds
    EventType type;            // Network vs Process vs File

    // Network-specific fields
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;         // TCP=6, UDP=17, ICMP=1
    uint8_t  direction;        // 0=Inbound, 1=Outbound
    
    // Process/File specific fields (PID, etc.)
    uint32_t pid;

    // Verdict set by user-mode service
    volatile KernelVerdict verdict;
};

// Lock-free Shared Ring Buffer structure
struct SharedRingBuffer {
    uint32_t magic;
    uint32_t version;
    
    // Head and Tail indices for the lock-free ring buffer
    alignas(64) volatile uint32_t head;
    alignas(64) volatile uint32_t tail;
    
    EventMeta events[RING_BUFFER_SIZE];
};

// Control IOCTLs for driver communication
#define AEGIS_DEVICE_TYPE 0x8000
#define IOCTL_AEGIS_REGISTER_EVENT \
    (0x80000000 | (AEGIS_DEVICE_TYPE << 16) | (0x801 << 2))
#define IOCTL_AEGIS_GET_SHARED_MEM \
    (0x80000000 | (AEGIS_DEVICE_TYPE << 16) | (0x802 << 2))
#define IOCTL_AEGIS_SET_POLICY \
    (0x80000000 | (AEGIS_DEVICE_TYPE << 16) | (0x803 << 2))

} // namespace kernel
} // namespace fw
