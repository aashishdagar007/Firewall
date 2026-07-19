#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace fw {
namespace ipc {

// Pipe name for Aegis XII
constexpr const char* PIPE_NAME = "\\\\.\\pipe\\AegisXII_IPC";

// Message Types
enum class MsgType : uint32_t {
    PING = 1,
    PONG = 2,
    GET_STATS = 3,
    STATS_REPLY = 4,
    GET_RULES = 5,
    RULES_REPLY = 6,
    ADD_RULE = 7,
    DEL_RULE = 8,
    GET_LOGS = 9,
    LOGS_REPLY = 10,
    SHUTDOWN = 99
};

// Standard Message Header
#pragma pack(push, 1)
struct MsgHeader {
    MsgType  type;
    uint32_t length; // Length of the payload following the header
};
#pragma pack(pop)

// Example Payload: Live Stats
#pragma pack(push, 1)
struct StatsPayload {
    uint64_t total_packets;
    uint64_t blocked_packets;
    uint64_t bytes_transferred;
    uint32_t active_connections;
};
#pragma pack(pop)

} // namespace ipc
} // namespace fw
