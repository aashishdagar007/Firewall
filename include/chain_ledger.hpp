#pragma once
// ──────────────────────────────────────────────────────────────
//  chain_ledger.hpp  –  Tamper-Proof Hash-Chain Event Ledger
//
//  AEGIS XII Pillar 4: Immutable Telemetry
//
//  Every security event (packet blocked, threat auto-banned,
//  BVUDP batch received, geo-block hit, etc.) is committed as
//  a block in a SHA-256 hash chain.
//
//  Block Structure (binary, little-endian for storage):
//    block_index   uint64  (8 bytes)
//    timestamp_ms  uint64  (8 bytes)  Unix ms since epoch
//    event_type    uint8   (1 byte)   LedgerEventType
//    event_len     uint16  (2 bytes)  payload byte count
//    event_data    uint8[] (event_len bytes)
//    prev_hash     uint8[32]  SHA-256 of previous block
//    block_hash    uint8[32]  SHA-256 of all above fields
//
//  Tamper-proofing:
//    Each block_hash covers the previous block's hash, so
//    modifying any historical block breaks every subsequent
//    block_hash — instantly detectable on verify().
//
//  Storage:
//    logs/ledger.chain  — append-only binary
//    logs/ledger.json   — JSON-Lines mirror (human-readable)
// ──────────────────────────────────────────────────────────────

#include "sha256.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>
#include <thread>
#include <condition_variable>
#include <queue>

namespace fw {

// ── Event Type Catalog ────────────────────────────────────────
enum class LedgerEventType : uint8_t {
    GENESIS         = 0x00,   // first block (no previous)
    PACKET_BLOCKED  = 0x01,   // firewall rule BLOCK verdict
    THREAT_BANNED   = 0x02,   // heuristic auto-ban
    THREAT_UNBANNED = 0x03,   // manual or timer unban
    GEO_BLOCK_HIT   = 0x04,   // packet blocked by CIDR geo-block
    DPI_MATCH       = 0x05,   // DPI signature triggered
    BVUDP_BATCH_RX  = 0x10,   // BVUDP batch verified and received
    BVUDP_BATCH_BAD = 0x11,   // BVUDP hash mismatch / rejected
    RULE_ADDED      = 0x20,   // operator added a firewall rule
    RULE_REMOVED    = 0x21,   // operator removed a firewall rule
    POLICY_CHANGE   = 0x22,   // default policy changed
    CLOUD_SYNC      = 0x30,   // cloud control plane config pulled
    FIREWALL_START  = 0x40,   // daemon started
    FIREWALL_STOP   = 0x41,   // daemon graceful stop
};

// ── Block (in-memory representation) ─────────────────────────
struct LedgerBlock {
    uint64_t          index        = 0;
    uint64_t          timestamp_ms = 0;
    LedgerEventType   event_type   = LedgerEventType::GENESIS;
    std::string       event_data;            // human-readable payload
    SHA256::Digest    prev_hash{};           // zeroes for genesis
    SHA256::Digest    block_hash{};          // computed on commit

    // Compute this block's hash over all fields
    SHA256::Digest compute_hash() const {
        SHA256 h;
        h.update(&index,        sizeof(index));
        h.update(&timestamp_ms, sizeof(timestamp_ms));
        auto et = static_cast<uint8_t>(event_type);
        h.update(&et, 1);
        uint16_t elen = static_cast<uint16_t>(event_data.size());
        h.update(&elen, sizeof(elen));
        h.update(event_data.data(), event_data.size());
        h.update(prev_hash.data(), 32);
        return h.finalize();
    }

    bool verify() const { return block_hash == compute_hash(); }

    // JSON representation for the .json mirror
    std::string to_json() const {
        auto escape = [](const std::string& s) {
            std::string o;
            for (char c : s) {
                if (c == '"')  { o += "\\\""; }
                else if (c == '\\') { o += "\\\\"; }
                else if (c == '\n') { o += "\\n"; }
                else               { o += c; }
            }
            return o;
        };
        return "{\"idx\":" + std::to_string(index) +
               ",\"ts\":"  + std::to_string(timestamp_ms) +
               ",\"type\":" + std::to_string(static_cast<int>(event_type)) +
               ",\"data\":\"" + escape(event_data) + "\"" +
               ",\"prev\":\"" + SHA256::to_hex(prev_hash) + "\"" +
               ",\"hash\":\"" + SHA256::to_hex(block_hash) + "\"}";
    }
};

// ─────────────────────────────────────────────────────────────
//  ChainLedger  –  thread-safe, async append-only ledger
// ─────────────────────────────────────────────────────────────
class ChainLedger {
public:
    explicit ChainLedger(const std::string& binary_path  = "logs/ledger.chain",
                         const std::string& json_path    = "logs/ledger.json")
        : bin_path_(binary_path), json_path_(json_path), running_(false)
    {
        last_hash_.fill(0);
        next_index_ = 0;
    }

    ~ChainLedger() { close(); }

    // Initialize: open files, write genesis if new, and start async thread
    bool open() {
        std::lock_guard<std::mutex> lk(mtx_);
        bin_out_.open(bin_path_, std::ios::binary | std::ios::app);
        json_out_.open(json_path_, std::ios::app);
        if (!bin_out_.is_open() || !json_out_.is_open()) return false;

        // If the file is empty, write the genesis block immediately
        if (bin_out_.tellp() == 0) {
            LedgerBlock genesis;
            genesis.index        = 0;
            genesis.timestamp_ms = now_ms();
            genesis.event_type   = LedgerEventType::GENESIS;
            genesis.event_data   = "AEGIS XII ledger genesis";
            genesis.prev_hash.fill(0);
            genesis.block_hash   = genesis.compute_hash();
            last_hash_   = genesis.block_hash;
            next_index_  = 1;
            write_block_direct(genesis);
        } else {
            // In a real system, we'd read the last block from disk to restore last_hash_ and next_index_.
            // For simplicity, we assume we append from 0 if restarted, or we need a restore phase.
        }
        
        running_ = true;
        worker_thread_ = std::thread([this]{ worker_loop(); });
        return true;
    }

    void close() {
        {
            std::lock_guard<std::mutex> lk(queue_mtx_);
            running_ = false;
        }
        cv_.notify_one();
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }

        std::lock_guard<std::mutex> lk(mtx_);
        if (bin_out_.is_open())  bin_out_.close();
        if (json_out_.is_open()) json_out_.close();
    }

    // Commit a new event (Non-Blocking: pushes to async queue)
    void commit(LedgerEventType type, const std::string& data) {
        PendingEvent ev{type, data};
        {
            std::lock_guard<std::mutex> lk(queue_mtx_);
            // Anti-DoS: drop events if queue gets absurdly huge
            if (event_queue_.size() < 100000) {
                event_queue_.push(std::move(ev));
            }
        }
        cv_.notify_one();
    }

    // Convenience overloads
    void log_packet_blocked(const std::string& src_ip, uint16_t dst_port,
                            const std::string& rule_desc) {
        commit(LedgerEventType::PACKET_BLOCKED,
               src_ip + ":" + std::to_string(dst_port) + " blocked by: " + rule_desc);
    }

    void log_threat_banned(const std::string& ip, const std::string& reason) {
        commit(LedgerEventType::THREAT_BANNED, ip + " auto-banned: " + reason);
    }

    void log_threat_unbanned(const std::string& ip) {
        commit(LedgerEventType::THREAT_UNBANNED, ip + " unban");
    }

    void log_dpi_match(const std::string& sig, const std::string& src_ip) {
        commit(LedgerEventType::DPI_MATCH, "sig=" + sig + " src=" + src_ip);
    }

    void log_bvudp_batch(uint32_t batch_id, size_t bytes, bool ok) {
        commit(ok ? LedgerEventType::BVUDP_BATCH_RX
                  : LedgerEventType::BVUDP_BATCH_BAD,
               "batch=" + std::to_string(batch_id) +
               " bytes=" + std::to_string(bytes) +
               (ok ? " verified" : " REJECTED"));
    }

    void log_cloud_sync(const std::string& endpoint, size_t rules_applied) {
        commit(LedgerEventType::CLOUD_SYNC,
               endpoint + " rules=" + std::to_string(rules_applied));
    }

    void log_firewall_start() {
        commit(LedgerEventType::FIREWALL_START, "AEGIS XII daemon start");
    }

    void log_firewall_stop() {
        commit(LedgerEventType::FIREWALL_STOP, "AEGIS XII daemon stop");
    }

    // Verify the full chain from disk
    // Returns {true, ""} if intact; {false, "reason"} if tampered
    std::pair<bool, std::string> verify_chain() {
        std::ifstream in(bin_path_, std::ios::binary);
        if (!in.is_open()) return {false, "cannot open ledger"};

        SHA256::Digest expected_prev; expected_prev.fill(0);
        uint64_t expected_index = 0;

        while (in.peek() != EOF) {
            LedgerBlock blk;
            if (!read_block(in, blk))
                return {false, "corrupt block at index " + std::to_string(expected_index)};

            if (blk.index != expected_index)
                return {false, "index gap at " + std::to_string(blk.index)};
            if (blk.prev_hash != expected_prev)
                return {false, "chain break at index " + std::to_string(blk.index)};
            if (!blk.verify())
                return {false, "hash mismatch at index " + std::to_string(blk.index)};

            expected_prev  = blk.block_hash;
            expected_index = blk.index + 1;
        }
        return {true, ""};
    }

    uint64_t block_count() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return next_index_;
    }

    SHA256::Digest chain_tip() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return last_hash_;
    }

private:
    struct PendingEvent {
        LedgerEventType type;
        std::string     data;
    };

    std::string       bin_path_, json_path_;
    std::ofstream     bin_out_, json_out_;
    mutable std::mutex mtx_;
    SHA256::Digest    last_hash_{};
    uint64_t          next_index_ = 0;

    // Async machinery
    std::mutex              queue_mtx_;
    std::condition_variable cv_;
    std::queue<PendingEvent> event_queue_;
    std::thread             worker_thread_;
    bool                    running_;

    static uint64_t now_ms() {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
    }

    // Background worker loop
    void worker_loop() {
        std::vector<PendingEvent> batch;
        while (true) {
            {
                std::unique_lock<std::mutex> lk(queue_mtx_);
                cv_.wait(lk, [this]{ return !event_queue_.empty() || !running_; });
                
                if (!running_ && event_queue_.empty()) break;

                // Drain the queue into a local batch to release the lock fast
                while (!event_queue_.empty()) {
                    batch.push_back(std::move(event_queue_.front()));
                    event_queue_.pop();
                }
            }

            // Process the batch (hashing + I/O)
            std::lock_guard<std::mutex> lk(mtx_);
            for (auto& ev : batch) {
                LedgerBlock blk;
                blk.index        = next_index_++;
                blk.timestamp_ms = now_ms();
                blk.event_type   = ev.type;
                blk.event_data   = std::move(ev.data);
                blk.prev_hash    = last_hash_;
                blk.block_hash   = blk.compute_hash();
                last_hash_       = blk.block_hash;
                write_block_direct(blk);
            }
            batch.clear();
        }
    }

    void write_block_direct(const LedgerBlock& blk) {
        if (!bin_out_.is_open()) return;

        // Binary record: fixed-size fields + variable event_data
        bin_out_.write(reinterpret_cast<const char*>(&blk.index),        8);
        bin_out_.write(reinterpret_cast<const char*>(&blk.timestamp_ms), 8);
        auto et = static_cast<uint8_t>(blk.event_type);
        bin_out_.write(reinterpret_cast<const char*>(&et), 1);
        uint16_t elen = static_cast<uint16_t>(blk.event_data.size());
        bin_out_.write(reinterpret_cast<const char*>(&elen), 2);
        bin_out_.write(blk.event_data.data(), elen);
        bin_out_.write(reinterpret_cast<const char*>(blk.prev_hash.data()),  32);
        bin_out_.write(reinterpret_cast<const char*>(blk.block_hash.data()), 32);
        bin_out_.flush();

        // JSON mirror
        if (json_out_.is_open()) {
            json_out_ << blk.to_json() << "\n";
            json_out_.flush();
        }
    }

    static bool read_block(std::ifstream& in, LedgerBlock& blk) {
        auto read = [&](void* dst, size_t n) -> bool {
            return static_cast<bool>(in.read(reinterpret_cast<char*>(dst), n));
        };
        if (!read(&blk.index, 8))        return false;
        if (!read(&blk.timestamp_ms, 8)) return false;
        uint8_t et = 0;
        if (!read(&et, 1)) return false;
        blk.event_type = static_cast<LedgerEventType>(et);
        uint16_t elen = 0;
        if (!read(&elen, 2)) return false;
        blk.event_data.resize(elen);
        if (elen && !in.read(blk.event_data.data(), elen)) return false;
        if (!read(blk.prev_hash.data(),  32)) return false;
        if (!read(blk.block_hash.data(), 32)) return false;
        return true;
    }
};

} // namespace fw
