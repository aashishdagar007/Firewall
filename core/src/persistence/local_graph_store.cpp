#include "persistence/local_graph_store.hpp"
#include <iostream>

namespace fw {

LocalGraphStore::LocalGraphStore(const std::string& db_path) : db_path_(db_path) {}

LocalGraphStore::~LocalGraphStore() {
    close();
}

bool LocalGraphStore::open() {
    std::lock_guard<std::mutex> lock(db_mtx_);
    if (sqlite3_open(db_path_.c_str(), &db_) != SQLITE_OK) {
        return false;
    }
    
    // Enable WAL mode for better concurrency
    char* err_msg = nullptr;
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &err_msg);
    if (err_msg) {
        sqlite3_free(err_msg);
    }
    
    return init_schema();
}

void LocalGraphStore::close() {
    std::lock_guard<std::mutex> lock(db_mtx_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool LocalGraphStore::init_schema() {
    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS process_nodes (
            pid INTEGER PRIMARY KEY,
            ppid INTEGER,
            exe_name TEXT,
            image_hash TEXT,
            command_line TEXT,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS network_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            src_ip TEXT,
            dst_ip TEXT,
            dst_port INTEGER,
            proto TEXT,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(pid) REFERENCES process_nodes(pid)
        );
    )";
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, schema, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        if (err_msg) sqlite3_free(err_msg);
        return false;
    }
    return true;
}

void LocalGraphStore::log_process(const ProcessNetInfo& info) {
    if (!db_) return;
    std::lock_guard<std::mutex> lock(db_mtx_);
    
    const char* sql = "INSERT OR IGNORE INTO process_nodes (pid, ppid, exe_name, image_hash, command_line) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, info.pid);
        sqlite3_bind_int(stmt, 2, info.ppid);
        sqlite3_bind_text(stmt, 3, info.exe_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, info.image_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, info.command_line.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

void LocalGraphStore::log_connection(const PacketRecord& record) {
    if (!db_) return;
    std::lock_guard<std::mutex> lock(db_mtx_);
    
    const char* sql = "INSERT INTO network_edges (pid, src_ip, dst_ip, dst_port, proto, action) VALUES (?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, record.pid);
        sqlite3_bind_text(stmt, 2, record.src_ip_str.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, record.dst_ip_str.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, record.info.dst_port);
        sqlite3_bind_text(stmt, 5, proto_name(record.info.proto), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, action_name(record.result.verdict), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

} // namespace fw
