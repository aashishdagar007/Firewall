#pragma once

#include "types.hpp"
#include "process_monitor.hpp"
#include "nfq_capture.hpp"
#include <sqlite3.h>
#include <string>
#include <mutex>

namespace fw {

class LocalGraphStore {
public:
    explicit LocalGraphStore(const std::string& db_path);
    ~LocalGraphStore();

    bool open();
    void close();

    void log_process(const ProcessNetInfo& info);
    void log_connection(const PacketRecord& record);

private:
    std::string db_path_;
    sqlite3* db_ = nullptr;
    std::mutex db_mtx_;

    bool init_schema();
};

} // namespace fw
