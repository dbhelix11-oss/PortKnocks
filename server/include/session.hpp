#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "derive.hpp"

namespace knockd {

struct SessionConfig {
    std::vector<uint8_t> secret;
    int n_ports = 6;
    uint16_t port_low = 20000;
    uint16_t port_high = 60000;
    int time_step_seconds = 30;
    std::chrono::seconds inactivity_timeout{5};
    std::chrono::seconds replay_ttl{90}; // ~3*T by default
};

// Called once a source IP has completed a verified, non-replayed knock
// sequence on some channel. `on_match` is injected so unit tests can run
// this whole state machine without touching nftables or exec'ing
// anything -- SessionTracker itself has no idea what a channel *does*,
// only that one matched. channel_id 0 conventionally means "open the
// primary port"; 1..kNumChannels-1 mean "run that channel's configured
// command" -- but that mapping lives in main.cpp's dispatch, not here.
using MatchCallback = std::function<void(const std::string &source_ip, int channel_id)>;

class SessionTracker {
public:
    SessionTracker(SessionConfig config, MatchCallback on_match);

    // Feed one observed (source_ip, dest_port) pair, along with the wall-clock
    // time it was captured. Internally drives the candidate-sequence state
    // machine described in spec/derivation.md. Also opportunistically sweeps
    // expired candidates and replay-cache entries.
    void on_packet(const std::string &source_ip, uint16_t dest_port,
                    std::chrono::system_clock::time_point captured_at,
                    std::chrono::steady_clock::time_point now);

    // Test/introspection helper: number of tracked in-progress candidates.
    size_t candidate_count() const { return candidates_.size(); }

private:
    struct Candidate {
        std::vector<uint16_t> ports;
        std::chrono::system_clock::time_point first_seen_wall;
        std::chrono::steady_clock::time_point last_seen_mono;
    };

    void sweep_expired(std::chrono::steady_clock::time_point now);
    void sweep_replay_cache(std::chrono::steady_clock::time_point now);

    SessionConfig config_;
    MatchCallback on_match_;
    std::unordered_map<std::string, Candidate> candidates_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> replay_cache_; // key: "ip|window|channel"
};

} // namespace knockd
