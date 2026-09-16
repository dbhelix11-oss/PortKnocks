#include "session.hpp"

#include <chrono>
#include <cstdio>
#include <utility>
#include <vector>

using namespace knockd;
using namespace std::chrono;

namespace {

int failures = 0;

void check(bool cond, const char *msg) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", msg);
        ++failures;
    }
}

} // namespace

int main() {
    SessionConfig cfg;
    cfg.secret = std::vector<uint8_t>(32, 0);
    cfg.n_ports = 3;
    cfg.port_low = 20000;
    cfg.port_high = 60000;
    cfg.time_step_seconds = 30;
    cfg.inactivity_timeout = seconds(5);
    cfg.replay_ttl = seconds(90);

    std::vector<std::pair<std::string, int>> matches;
    SessionTracker tracker(cfg, [&matches](const std::string &ip, int channel) {
        matches.emplace_back(ip, channel);
    });

    auto wall_now = system_clock::now();
    uint64_t window = static_cast<uint64_t>(duration_cast<seconds>(wall_now.time_since_epoch()).count()) /
                       static_cast<uint64_t>(cfg.time_step_seconds);
    auto expected = derive_ports(cfg.secret, window, cfg.n_ports, cfg.port_low, cfg.port_high, 0);

    auto steady_now = steady_clock::now();

    // --- Test 1: a correctly ordered channel-0 sequence matches exactly once ---
    for (uint16_t port : expected) {
        tracker.on_packet("10.0.0.1", port, wall_now, steady_now);
        steady_now += milliseconds(50);
    }
    check(matches.size() == 1 && matches[0].first == "10.0.0.1" && matches[0].second == 0,
          "valid channel-0 sequence should match once, on channel 0");

    // --- Test 2: replaying the exact same sequence in the same window is rejected ---
    for (uint16_t port : expected) {
        tracker.on_packet("10.0.0.1", port, wall_now, steady_now);
        steady_now += milliseconds(50);
    }
    check(matches.size() == 1, "replay within the same window must not match again");

    // --- Test 3: out-of-order knocks never complete a match ---
    std::vector<std::pair<std::string, int>> matches2;
    SessionTracker tracker2(cfg, [&matches2](const std::string &ip, int channel) {
        matches2.emplace_back(ip, channel);
    });
    check(expected.size() == 3, "test assumes n_ports == 3");
    tracker2.on_packet("10.0.0.2", expected[1], wall_now, steady_now);
    steady_now += milliseconds(50);
    tracker2.on_packet("10.0.0.2", expected[0], wall_now, steady_now);
    steady_now += milliseconds(50);
    tracker2.on_packet("10.0.0.2", expected[2], wall_now, steady_now);
    check(matches2.empty(), "out-of-order sequence must never match");

    // --- Test 4: after the replay cache TTL elapses, the same sequence can match again ---
    auto far_future = steady_now + seconds(91);
    for (uint16_t port : expected) {
        tracker.on_packet("10.0.0.1", port, wall_now, far_future);
        far_future += milliseconds(50);
    }
    check(matches.size() == 2, "replay cache entries should expire after replay_ttl");

    // --- Test 5: a channel-3 sequence matches on channel 3, not channel 0 ---
    // This is the concrete regression test for the aliasing bug the
    // channel_id design change exists to close: channel 3's sequence must
    // be its own independent thing, never confusable with channel 0's.
    std::vector<std::pair<std::string, int>> matches3;
    SessionTracker tracker3(cfg, [&matches3](const std::string &ip, int channel) {
        matches3.emplace_back(ip, channel);
    });
    auto wall_now3 = system_clock::now();
    uint64_t window3 = static_cast<uint64_t>(duration_cast<seconds>(wall_now3.time_since_epoch()).count()) /
                        static_cast<uint64_t>(cfg.time_step_seconds);
    auto expected_ch3 = derive_ports(cfg.secret, window3, cfg.n_ports, cfg.port_low, cfg.port_high, 3);
    check(expected_ch3 != expected, "channel 3's sequence must differ from channel 0's");
    auto steady_now3 = steady_clock::now();
    for (uint16_t port : expected_ch3) {
        tracker3.on_packet("10.0.0.3", port, wall_now3, steady_now3);
        steady_now3 += milliseconds(50);
    }
    check(matches3.size() == 1 && matches3[0].first == "10.0.0.3" && matches3[0].second == 3,
          "channel-3 sequence should match exactly once, on channel 3");

    // --- Test 6: replay cache is scoped per channel, not just per window ---
    // Spending channel 1's window must not block channel 2 in that same window.
    std::vector<std::pair<std::string, int>> matches4;
    SessionTracker tracker4(cfg, [&matches4](const std::string &ip, int channel) {
        matches4.emplace_back(ip, channel);
    });
    auto wall_now4 = system_clock::now();
    uint64_t window4 = static_cast<uint64_t>(duration_cast<seconds>(wall_now4.time_since_epoch()).count()) /
                        static_cast<uint64_t>(cfg.time_step_seconds);
    auto expected_ch1 = derive_ports(cfg.secret, window4, cfg.n_ports, cfg.port_low, cfg.port_high, 1);
    auto expected_ch2 = derive_ports(cfg.secret, window4, cfg.n_ports, cfg.port_low, cfg.port_high, 2);
    auto steady_now4 = steady_clock::now();
    for (uint16_t port : expected_ch1) {
        tracker4.on_packet("10.0.0.4", port, wall_now4, steady_now4);
        steady_now4 += milliseconds(50);
    }
    for (uint16_t port : expected_ch2) {
        tracker4.on_packet("10.0.0.4", port, wall_now4, steady_now4);
        steady_now4 += milliseconds(50);
    }
    check(matches4.size() == 2 && matches4[0].second == 1 && matches4[1].second == 2,
          "channel 1 and channel 2 must both match independently in the same window");

    if (failures == 0) {
        std::printf("all session tests passed\n");
        return 0;
    }
    std::fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
}
