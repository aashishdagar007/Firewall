#pragma once
#include <string>
#include <vector>
#include <mutex>
#include "shared/messages.h"

namespace fw {
namespace gui {

class IpcClient {
public:
    IpcClient();
    ~IpcClient();

    bool connect();
    void disconnect();
    bool is_connected() const { return m_connected; }

    bool get_stats(fw::ipc::StatsPayload& out_stats);
    bool ping();

private:
    bool send_header(fw::ipc::MsgType type, uint32_t length = 0);
    bool read_header(fw::ipc::MsgHeader& out_header);
    bool read_payload(void* buffer, uint32_t length);

    bool m_connected;
    void* m_pipe_handle; // HANDLE on Windows
    mutable std::mutex m_mutex;
};

} // namespace gui
} // namespace fw
