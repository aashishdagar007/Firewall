#pragma once
#include "diode_threat_engine.hpp"
#include <thread>
#include <atomic>
#include <memory>

namespace fw {

class DiodeStreamer {
public:
    DiodeStreamer(DiodeThreatEngine& engine);
    ~DiodeStreamer();

    void start_stream(int target_pps = 2000);
    void stop_stream();
    bool is_streaming() const { return running_; }

    void trigger_scenario(ThreatClass tc, int count = 50);
    double benchmark(size_t packets = 100000);

private:
    void stream_worker(int target_pps);

    DiodeThreatEngine& engine_;
    std::atomic<bool> running_{false};
    std::thread worker_thread_;
};

} // namespace fw
