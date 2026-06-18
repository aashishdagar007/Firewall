#pragma once
// ──────────────────────────────────────────────────────────────
//  bvudp.hpp  –  Batch-Verified UDP Protocol Stack
//
//  A hybrid reliable/efficient transport built on top of raw UDP.
//  Rather than ACKing every packet (TCP overhead) it transmits
//  an entire batch, then sends a SHA-256 Manifest.  The receiver
//  verifies the entire batch in one pass and sends a single
//  BATCH_ACK or NACK for any missing chunk.
//
//  Wire Format (all integers big-endian):
//
//  ┌─────────────────────────────────────────────────────────┐
//  │  MAGIC   8 bytes  0xAE 0x61 0x57 0x1C 0x70 0xB2 0xD4 0xF8
//  │  VERSION 1 byte   = 0x01
//  │  TYPE    1 byte   (see BVUDPPacketType)
//  │  BATCH_ID  4 bytes uint32
//  │  (type-specific payload — see below)
//  └─────────────────────────────────────────────────────────┘
//
//  DATA packet (TYPE=0x01):
//    SEQ      2 bytes  chunk index (0-based)
//    TOTAL    2 bytes  total chunks in this batch
//    PAY_LEN  2 bytes  payload byte count
//    PAYLOAD  PAY_LEN bytes
//
//  MANIFEST packet (TYPE=0x02):
//    TOTAL    2 bytes  total chunks
//    HASH     32 bytes SHA-256 of all payloads in sequence order
//
//  BATCH_ACK packet (TYPE=0x03):
//    (no extra fields)
//
//  NACK packet (TYPE=0x04):
//    MISSING  2 bytes  chunk sequence number to retransmit
//
//  Port-Mux Demux:
//    Any UDP packet whose payload starts with BVUDP_MAGIC is
//    pulled out of the standard network stack by PortDemux and
//    routed here instead of the OS.
// ──────────────────────────────────────────────────────────────

#include "platform.hpp"
#include "sha256.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <vector>

namespace fw {

// ── Magic Bytes ───────────────────────────────────────────────
//  8-byte secret handshake embedded at the start of every BVUDP
//  UDP payload.  Looks like random noise to standard firewalls.
//  CHANGEABLE at runtime via control_plane (Phase 3).
constexpr uint8_t BVUDP_MAGIC[8] = {
    0xAE, 0x61, 0x57, 0x1C, 0x70, 0xB2, 0xD4, 0xF8
};

// ── Packet Type Codes ─────────────────────────────────────────
enum class BVUDPType : uint8_t {
    DATA     = 0x01,  // chunked payload
    MANIFEST = 0x02,  // batch completion + SHA-256 hash
    BATCH_ACK= 0x03,  // receiver: whole batch verified OK
    NACK     = 0x04,  // receiver: specific chunk missing
};

// ── Protocol Constants ────────────────────────────────────────
static constexpr uint16_t BVUDP_MTU        = 1400;  // max payload per chunk
static constexpr uint16_t BVUDP_MAX_CHUNKS = 1024;  // max chunks per batch
static constexpr int      BVUDP_RETRIES    = 5;     // NACK retransmit limit
static constexpr int      BVUDP_TIMEOUT_MS = 2000;  // ACK wait timeout

// ── Wire Header (fixed prefix, 14 bytes) ─────────────────────
#pragma pack(push, 1)
struct BVUDPHeader {
    uint8_t  magic[8];
    uint8_t  version;   // = 0x01
    uint8_t  type;      // BVUDPType
    uint32_t batch_id;  // big-endian

    static BVUDPHeader make(BVUDPType t, uint32_t bid) {
        BVUDPHeader h{};
        std::memcpy(h.magic, BVUDP_MAGIC, 8);
        h.version  = 0x01;
        h.type     = static_cast<uint8_t>(t);
        // Store big-endian
        h.batch_id = htonl(bid);
        return h;
    }

    uint32_t batch_id_host() const { return ntohl(batch_id); }
};

struct BVUDPDataPayload {
    uint16_t seq;       // big-endian chunk index
    uint16_t total;     // big-endian total chunks
    uint16_t pay_len;   // big-endian byte count
    // followed by pay_len bytes of payload
};

struct BVUDPManifest {
    uint16_t        total;     // big-endian total chunks
    uint8_t         hash[32];  // SHA-256 of all payloads in order
};

struct BVUDPNack {
    uint16_t missing; // big-endian chunk index to retransmit
};
#pragma pack(pop)

// ─────────────────────────────────────────────────────────────
//  Sender  –  chunks a buffer, sends it as a batch over UDP,
//             waits for BATCH_ACK, retransmits NACKed chunks.
// ─────────────────────────────────────────────────────────────
class BVUDPSender {
public:
    explicit BVUDPSender(std::string session_key = "DEFAULT_AEGIS_KEY") 
        : batch_counter_(1), 
          session_key_(session_key.begin(), session_key.end()) {
        sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
    ~BVUDPSender() {
        if (socket_valid(sock_)) close_socket(sock_);
    }

    void set_session_key(const std::string& key) {
        session_key_ = std::vector<uint8_t>(key.begin(), key.end());
    }

    // Send `data` (len bytes) to `dest` over BVUDP.
    // Blocks until BATCH_ACK received or retries exhausted.
    // Returns true on verified delivery.
    bool send(const uint8_t* data, size_t len,
              const sockaddr_in& dest,
              int retries = BVUDP_RETRIES) {
        if (!socket_valid(sock_)) return false;

        uint32_t bid = batch_counter_++;

        // ── 1. Chunk the payload ──────────────────────────────
        std::vector<std::vector<uint8_t>> chunks;
        for (size_t off = 0; off < len; off += BVUDP_MTU) {
            size_t sz = std::min(static_cast<size_t>(BVUDP_MTU), len - off);
            chunks.emplace_back(data + off, data + off + sz);
        }
        if (chunks.size() > BVUDP_MAX_CHUNKS) return false;
        uint16_t total = static_cast<uint16_t>(chunks.size());

        // ── 2. Build HMAC-SHA256 of the full payload ──────────
        SHA256::Digest batch_hash = SHA256::hmac(
            session_key_.data(), session_key_.size(),
            data, len
        );

        // ── 3. Send all chunks ────────────────────────────────
        auto send_chunk = [&](uint16_t seq) -> bool {
            auto& payload = chunks[seq];
            std::vector<uint8_t> pkt;
            pkt.reserve(sizeof(BVUDPHeader) + sizeof(BVUDPDataPayload) + payload.size());

            auto hdr = BVUDPHeader::make(BVUDPType::DATA, bid);
            pkt.insert(pkt.end(),
                       reinterpret_cast<uint8_t*>(&hdr),
                       reinterpret_cast<uint8_t*>(&hdr) + sizeof(hdr));

            BVUDPDataPayload dp{};
            dp.seq     = htons(seq);
            dp.total   = htons(total);
            dp.pay_len = htons(static_cast<uint16_t>(payload.size()));
            pkt.insert(pkt.end(),
                       reinterpret_cast<uint8_t*>(&dp),
                       reinterpret_cast<uint8_t*>(&dp) + sizeof(dp));
            pkt.insert(pkt.end(), payload.begin(), payload.end());

            return sendto(sock_, reinterpret_cast<const char*>(pkt.data()),
                          static_cast<int>(pkt.size()), 0,
                          reinterpret_cast<const sockaddr*>(&dest),
                          sizeof(dest)) > 0;
        };

        for (uint16_t i = 0; i < total; ++i)
            if (!send_chunk(i)) return false;

        // ── 4. Send Manifest ──────────────────────────────────
        auto send_manifest = [&]() -> bool {
            std::vector<uint8_t> pkt;
            auto hdr = BVUDPHeader::make(BVUDPType::MANIFEST, bid);
            pkt.insert(pkt.end(),
                       reinterpret_cast<uint8_t*>(&hdr),
                       reinterpret_cast<uint8_t*>(&hdr) + sizeof(hdr));
            BVUDPManifest m{};
            m.total = htons(total);
            std::memcpy(m.hash, batch_hash.data(), 32);
            pkt.insert(pkt.end(),
                       reinterpret_cast<uint8_t*>(&m),
                       reinterpret_cast<uint8_t*>(&m) + sizeof(m));
            return sendto(sock_, reinterpret_cast<const char*>(pkt.data()),
                          static_cast<int>(pkt.size()), 0,
                          reinterpret_cast<const sockaddr*>(&dest),
                          sizeof(dest)) > 0;
        };
        send_manifest();

        // ── 5. Wait for BATCH_ACK / NACKs ────────────────────
        set_recv_timeout(BVUDP_TIMEOUT_MS);
        uint8_t rbuf[256];
        for (int attempt = 0; attempt < retries; ++attempt) {
            sockaddr_in from{}; int fromlen = sizeof(from);
            int rlen = recvfrom(sock_, reinterpret_cast<char*>(rbuf),
                                sizeof(rbuf), 0,
                                reinterpret_cast<sockaddr*>(&from),
                                &fromlen);
            if (rlen < static_cast<int>(sizeof(BVUDPHeader))) {
                send_manifest(); // resend manifest on timeout
                continue;
            }
            if (!is_bvudp(rbuf)) continue;

            auto* rhdr = reinterpret_cast<BVUDPHeader*>(rbuf);
            if (rhdr->batch_id_host() != bid) continue;

            BVUDPType rt = static_cast<BVUDPType>(rhdr->type);
            if (rt == BVUDPType::BATCH_ACK) return true;
            if (rt == BVUDPType::NACK && rlen >= static_cast<int>(sizeof(BVUDPHeader) + sizeof(BVUDPNack))) {
                auto* nack = reinterpret_cast<BVUDPNack*>(rbuf + sizeof(BVUDPHeader));
                uint16_t missing = ntohs(nack->missing);
                if (missing < total) send_chunk(missing);
                send_manifest();
            }
        }
        return false; // no verified ACK
    }

    // Check if a raw UDP payload starts with BVUDP magic bytes
    static bool is_bvudp(const uint8_t* payload) {
        return std::memcmp(payload, BVUDP_MAGIC, 8) == 0;
    }

private:
    sock_t       sock_;
    std::atomic<uint32_t> batch_counter_;
    std::vector<uint8_t>  session_key_;

    void set_recv_timeout(int ms) {
#ifdef _WIN32
        DWORD tv = static_cast<DWORD>(ms);
        setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
        struct timeval tv{ ms/1000, (ms%1000)*1000 };
        setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }
};

// ─────────────────────────────────────────────────────────────
//  ReceiverSession  –  buffers one in-flight batch
// ─────────────────────────────────────────────────────────────
struct BVUDPBatchSession {
    uint32_t batch_id   = 0;
    uint16_t total      = 0;
    
    // Fixed-allocation buffer: sized exactly once when session is created
    std::vector<uint8_t> payload;
    std::vector<bool>    chunk_received;
    std::vector<uint16_t> chunk_sizes;
    uint16_t             received_count = 0;

    std::chrono::steady_clock::time_point created;
    std::chrono::steady_clock::time_point last_updated;

    bool complete() const {
        return total > 0 && received_count == total;
    }

    // Verify HMAC and assemble payload; returns assembled data or empty on mismatch
    std::optional<std::vector<uint8_t>> verify_and_assemble(
            const SHA256::Digest& expected_hash,
            const std::vector<uint8_t>& session_key) const {
        
        // Assemble first
        std::vector<uint8_t> out;
        out.reserve(total * BVUDP_MTU);
        size_t offset = 0;
        for (uint16_t i = 0; i < total; ++i) {
            if (!chunk_received[i]) return std::nullopt;
            out.insert(out.end(), payload.data() + offset, payload.data() + offset + chunk_sizes[i]);
            offset += BVUDP_MTU;
        }

        // Verify HMAC mathematically bound to the secret key
        SHA256::Digest actual_hash = SHA256::hmac(
            session_key.data(), session_key.size(),
            out.data(), out.size()
        );

        if (actual_hash != expected_hash) return std::nullopt;

        return out;
    }

    uint16_t first_missing() const {
        for (uint16_t i = 0; i < total; ++i)
            if (!chunk_received[i]) return i;
        return total; // all present
    }
};

// ─────────────────────────────────────────────────────────────
//  Receiver  –  listens on a UDP port, assembles batches,
//               fires callback on verified delivery.
// ─────────────────────────────────────────────────────────────
class BVUDPReceiver {
public:
    static constexpr size_t MAX_SESSIONS = 256; // Anti-DoS limit

    // callback(batch_id, payload, sender)
    using BatchCallback = std::function<void(uint32_t batch_id,
                                             std::vector<uint8_t> payload,
                                             sockaddr_in sender)>;

    // tamper_callback(sender_ip)
    using TamperCallback = std::function<void(sockaddr_in sender)>;

    explicit BVUDPReceiver(uint16_t port, std::string session_key = "DEFAULT_AEGIS_KEY")
        : port_(port),
          session_key_(session_key.begin(), session_key.end()),
          sock_(INVALID_SOCK),
          running_(false) {}

    ~BVUDPReceiver() { stop(); }

    void set_session_key(const std::string& key) {
        session_key_ = std::vector<uint8_t>(key.begin(), key.end());
    }

    // Start listening; callbacks fired on verified batch or tampering detection
    bool start(BatchCallback cb, TamperCallback tamper_cb = nullptr) {
        if (running_) return true;
        callback_ = std::move(cb);
        tamper_callback_ = std::move(tamper_cb);

        sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (!socket_valid(sock_)) return false;

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port_);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            close_socket(sock_); sock_ = INVALID_SOCK;
            return false;
        }

        running_ = true;
        thread_  = std::thread([this]{ recv_loop(); });
        return true;
    }

    void stop() {
        running_ = false;
        if (socket_valid(sock_)) close_socket(sock_);
        if (thread_.joinable()) thread_.join();
    }

    // Feed a raw UDP payload directly (used by PortDemux on the same process)
    void feed(const uint8_t* data, int len, const sockaddr_in& from) {
        handle_packet(data, len, from);
    }

    static bool is_bvudp(const uint8_t* payload, int len) {
        return len >= static_cast<int>(sizeof(BVUDP_MAGIC)) &&
               std::memcmp(payload, BVUDP_MAGIC, 8) == 0;
    }

private:
    uint16_t     port_;
    std::vector<uint8_t> session_key_;
    sock_t       sock_;
    std::atomic<bool> running_;
    std::thread  thread_;
    BatchCallback callback_;
    TamperCallback tamper_callback_;

    std::mutex   sessions_mtx_;
    std::unordered_map<uint32_t, BVUDPBatchSession> sessions_;

    void recv_loop() {
        static constexpr int BUFSIZE = 65535;
        std::vector<uint8_t> buf(BUFSIZE);
        sockaddr_in from{}; int fromlen = sizeof(from);
        
        while (running_) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(sock_, &fds);
            
            struct timeval tv{ 0, 500000 }; // 500ms timeout for graceful exit checking
            int ready = select(static_cast<int>(sock_ + 1), &fds, nullptr, nullptr, &tv);
            
            if (ready < 0) {
#ifndef _WIN32
                if (errno == EINTR) continue;
#endif
                break; // Socket error
            }
            if (ready == 0) continue; // Timeout, check running_ again

            int n = recvfrom(sock_, reinterpret_cast<char*>(buf.data()),
                             BUFSIZE, 0,
                             reinterpret_cast<sockaddr*>(&from), &fromlen);
            if (n <= 0) continue;
            if (!is_bvudp(buf.data(), n)) continue;
            handle_packet(buf.data(), n, from);
        }
    }

    void handle_packet(const uint8_t* data, int len, const sockaddr_in& from) {
        if (len < static_cast<int>(sizeof(BVUDPHeader))) return;
        auto* hdr = reinterpret_cast<const BVUDPHeader*>(data);
        if (hdr->version != 0x01) return;

        uint32_t bid = hdr->batch_id_host();
        BVUDPType type = static_cast<BVUDPType>(hdr->type);
        int off = sizeof(BVUDPHeader);

        std::lock_guard<std::mutex> lk(sessions_mtx_);

        if (type == BVUDPType::DATA) {
            if (len < off + static_cast<int>(sizeof(BVUDPDataPayload))) return;
            auto* dp = reinterpret_cast<const BVUDPDataPayload*>(data + off);
            uint16_t seq     = ntohs(dp->seq);
            uint16_t total   = ntohs(dp->total);
            uint16_t pay_len = ntohs(dp->pay_len);
            off += sizeof(BVUDPDataPayload);
            if (len < off + pay_len) return;
            if (total == 0 || total > BVUDP_MAX_CHUNKS) return;
            if (seq >= total) return;

            // Enforce Anti-DoS Session Limit
            if (sessions_.find(bid) == sessions_.end()) {
                if (sessions_.size() >= MAX_SESSIONS) {
                    // Evict oldest session (LRU)
                    auto oldest = sessions_.begin();
                    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
                        if (it->second.last_updated < oldest->second.last_updated) {
                            oldest = it;
                        }
                    }
                    sessions_.erase(oldest);
                }
            }

            auto& session = sessions_[bid];
            session.batch_id = bid;
            session.total    = total;
            
            auto now = std::chrono::steady_clock::now();
            if (!session.created.time_since_epoch().count()) {
                session.created = now;
                // Pre-allocate buffer based on reported total to avoid dynamic reallocations
                session.payload.resize(total * BVUDP_MTU);
                session.chunk_received.resize(total, false);
                session.chunk_sizes.resize(total, 0);
            }
            session.last_updated = now;

            if (!session.chunk_received[seq]) {
                std::memcpy(session.payload.data() + (seq * BVUDP_MTU), data + off, pay_len);
                session.chunk_sizes[seq] = pay_len;
                session.chunk_received[seq] = true;
                session.received_count++;
            }

        } else if (type == BVUDPType::MANIFEST) {
            if (len < off + static_cast<int>(sizeof(BVUDPManifest))) return;
            auto* mf = reinterpret_cast<const BVUDPManifest*>(data + off);
            SHA256::Digest expected;
            std::memcpy(expected.data(), mf->hash, 32);

            auto it = sessions_.find(bid);
            if (it == sessions_.end()) return;
            BVUDPBatchSession& s = it->second;

            if (!s.complete()) {
                // Send NACK for first missing chunk
                uint16_t missing = s.first_missing();
                send_nack(bid, missing, from);
                return;
            }

            auto result = s.verify_and_assemble(expected, session_key_);
            if (!result) {
                // HMAC mismatch — highly indicative of active alteration/tampering!
                if (tamper_callback_) {
                    tamper_callback_(from);
                }
                
                // Clear the corrupted chunks
                std::fill(s.chunk_received.begin(), s.chunk_received.end(), false);
                s.received_count = 0;
                send_nack(bid, 0, from);
                return;
            }

            // Success — fire callback
            send_ack(bid, from);
            sessions_.erase(it);
            if (callback_)
                callback_(bid, std::move(*result), from);
        }

        // Purge stale sessions (> 30 seconds old)
        auto now = std::chrono::steady_clock::now();
        for (auto it2 = sessions_.begin(); it2 != sessions_.end(); ) {
            if (std::chrono::duration_cast<std::chrono::seconds>(
                    now - it2->second.created).count() > 30)
                it2 = sessions_.erase(it2);
            else
                ++it2;
        }
    }

    void send_ack(uint32_t bid, const sockaddr_in& dest) {
        sock_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (!socket_valid(s)) return;
        auto hdr = BVUDPHeader::make(BVUDPType::BATCH_ACK, bid);
        sendto(s, reinterpret_cast<const char*>(&hdr), sizeof(hdr), 0,
               reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
        close_socket(s);
    }

    void send_nack(uint32_t bid, uint16_t missing, const sockaddr_in& dest) {
        sock_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (!socket_valid(s)) return;
        uint8_t pkt[sizeof(BVUDPHeader) + sizeof(BVUDPNack)];
        auto hdr = BVUDPHeader::make(BVUDPType::NACK, bid);
        std::memcpy(pkt, &hdr, sizeof(hdr));
        BVUDPNack nk{}; nk.missing = htons(missing);
        std::memcpy(pkt + sizeof(hdr), &nk, sizeof(nk));
        sendto(s, reinterpret_cast<const char*>(pkt), sizeof(pkt), 0,
               reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
        close_socket(s);
    }
};

} // namespace fw
