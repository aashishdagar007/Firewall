#include "ipc_client.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

namespace fw {
namespace gui {

IpcClient::IpcClient() : m_connected(false), m_pipe_handle(nullptr) {
}

IpcClient::~IpcClient() {
    disconnect();
}

bool IpcClient::connect() {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_connected) return true;

    HANDLE hPipe = CreateFileA(
        fw::ipc::PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD mode = PIPE_READMODE_MESSAGE;
        SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
        m_pipe_handle = (void*)hPipe;
        m_connected = true;
        return true;
    }
    return false;
#else
    return false;
#endif
}

void IpcClient::disconnect() {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_connected && m_pipe_handle) {
        CloseHandle((HANDLE)m_pipe_handle);
        m_pipe_handle = nullptr;
        m_connected = false;
    }
#endif
}

bool IpcClient::send_header(fw::ipc::MsgType type, uint32_t length) {
#ifdef _WIN32
    fw::ipc::MsgHeader hdr = {type, length};
    DWORD written;
    if (!WriteFile((HANDLE)m_pipe_handle, &hdr, sizeof(hdr), &written, NULL)) {
        m_connected = false;
        return false;
    }
    return true;
#else
    return false;
#endif
}

bool IpcClient::read_header(fw::ipc::MsgHeader& out_header) {
#ifdef _WIN32
    DWORD bytesRead;
    if (!ReadFile((HANDLE)m_pipe_handle, &out_header, sizeof(out_header), &bytesRead, NULL) || bytesRead == 0) {
        m_connected = false;
        return false;
    }
    return true;
#else
    return false;
#endif
}

bool IpcClient::read_payload(void* buffer, uint32_t length) {
#ifdef _WIN32
    DWORD bytesRead;
    if (!ReadFile((HANDLE)m_pipe_handle, buffer, length, &bytesRead, NULL) || bytesRead != length) {
        m_connected = false;
        return false;
    }
    return true;
#else
    return false;
#endif
}

bool IpcClient::get_stats(fw::ipc::StatsPayload& out_stats) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_connected) return false;

    if (!send_header(fw::ipc::MsgType::GET_STATS)) return false;

    fw::ipc::MsgHeader reply_hdr;
    if (!read_header(reply_hdr)) return false;
    if (reply_hdr.type != fw::ipc::MsgType::STATS_REPLY || reply_hdr.length != sizeof(fw::ipc::StatsPayload)) return false;

    return read_payload(&out_stats, reply_hdr.length);
}

bool IpcClient::ping() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_connected) return false;

    if (!send_header(fw::ipc::MsgType::PING)) return false;

    fw::ipc::MsgHeader reply_hdr;
    if (!read_header(reply_hdr)) return false;
    return reply_hdr.type == fw::ipc::MsgType::PONG;
}

} // namespace gui
} // namespace fw
