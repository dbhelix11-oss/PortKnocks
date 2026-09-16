#include "session.hpp"

#include <vector>

#include "log.hpp"

namespace knockd {
namespace {

uint64_t time_counter_for(std::chrono::system_clock::time_point t, int step_seconds) {
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
    if (secs < 0) secs = 0;
    return static_cast<uint64_t>(secs) / static_cast<uint64_t>(step_seconds);
}

std::vector<uint64_t> candidate_windows(uint64_t anchor) {
    std::vector<uint64_t> windows;
    if (anchor > 0) windows.push_back(anchor - 1);
    windows.push_back(anchor);
    windows.push_back(anchor + 1);
    return windows;
}

} // namespace

SessionTracker::SessionTracker(SessionConfig config, MatchCallback on_match)
    : config_(std::move(config)), on_match_(std::move(on_match)) {}

void SessionTracker::sweep_expired(std::chrono::steady_clock::time_point now) {
    for (auto it = candidates_.begin(); it != candidates_.end();) {
        if (now - it->second.last_seen_mono > config_.inactivity_timeout) {
            it = candidates_.erase(it);
        } else {
            ++it;
        }
    }
}

void SessionTracker::sweep_replay_cache(std::chrono::steady_clock::time_point now) {
    for (auto it = replay_cache_.begin(); it != replay_cache_.end();) {
        if (now - it->second > config_.replay_ttl) {
            it = replay_cache_.erase(it);
        } else {
            ++it;
        }
    }
}

void SessionTracker::on_packet(const std::string &source_ip, uint16_t dest_port,
                                 std::chrono::system_clock::time_point captured_at,
                                 std::chrono::steady_clock::time_point now) {
    sweep_expired(now);
    sweep_replay_cache(now);

    auto it = candidates_.find(source_ip);
    if (it == candidates_.end()) {
        LOG_DEBUG("session: %s started a new candidate with port %u", source_ip.c_str(), dest_port);
        candidates_.emplace(source_ip, Candidate{{dest_port}, captured_at, now});
        return;
    }

    Candidate &cand = it->second;
    std::vector<uint16_t> extended = cand.ports;
    extended.push_back(dest_port);

    uint64_t anchor = time_counter_for(cand.first_seen_wall, config_.time_step_seconds);

    bool extended_ok = false;
    bool have_full_match = false;
    uint64_t matched_window = 0;
    int matched_channel = 0;

    for (uint64_t window : candidate_windows(anchor)) {
        for (int channel = 0; channel < kNumChannels; ++channel) {
            auto full = derive_ports(config_.secret, window, config_.n_ports, config_.port_low,
                                      config_.port_high, static_cast<uint8_t>(channel));
            bool prefix_ok = true;
            for (size_t i = 0; i < extended.size(); ++i) {
                if (i >= full.size() || full[i] != extended[i]) {
                    prefix_ok = false;
                    break;
                }
            }
            if (!prefix_ok) continue;
            extended_ok = true;
            if (extended.size() == full.size()) {
                have_full_match = true;
                matched_window = window;
                matched_channel = channel;
                break;
            }
        }
        if (have_full_match) break;
    }

    if (!extended_ok) {
        // Strict ordering broken against every candidate window: fail closed
        // on this candidate, but treat the current packet as a fresh start
        // rather than dropping it outright.
        LOG_DEBUG("session: %s broke sequence at step %zu (anchor window %llu), resetting",
                  source_ip.c_str(), extended.size(), static_cast<unsigned long long>(anchor));
        cand = Candidate{{dest_port}, captured_at, now};
        return;
    }

    cand.ports = std::move(extended);
    cand.last_seen_mono = now;

    if (!have_full_match) {
        return;
    }

    std::string replay_key = source_ip + "|" + std::to_string(matched_window) + "|" + std::to_string(matched_channel);
    bool already_spent = replay_cache_.find(replay_key) != replay_cache_.end();
    candidates_.erase(it);

    if (already_spent) {
        LOG_WARN("session: %s replayed an already-spent window %llu channel %d, rejecting",
                 source_ip.c_str(), static_cast<unsigned long long>(matched_window), matched_channel);
        return; // fail closed, no signal to the sender
    }

    replay_cache_[replay_key] = now;
    on_match_(source_ip, matched_channel);
}

} // namespace knockd
