#include "derive.hpp"
#include "testvectors.hpp"

#include <cstdio>
#include <cstdlib>
#include <stdexcept>

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
    for (size_t vi = 0; vi < kTestVectors.size(); ++vi) {
        const auto &v = kTestVectors[vi];
        auto got = knockd::derive_ports(v.secret, v.time_counter, v.n, v.port_low, v.port_high, v.channel_id);
        bool match = (got.size() == v.expected_ports.size());
        if (match) {
            for (size_t i = 0; i < got.size(); ++i) {
                if (got[i] != v.expected_ports[i]) {
                    match = false;
                    break;
                }
            }
        }
        if (!match) {
            std::fprintf(stderr, "vector %zu mismatch: got [", vi);
            for (auto p : got) std::fprintf(stderr, "%u ", p);
            std::fprintf(stderr, "]\n");
        }
        check(match, "vector mismatch");
    }

    bool threw = false;
    try {
        knockd::derive_ports(kTestVectors[0].secret, 0, 17, 20000, 60000);
    } catch (const std::invalid_argument &) {
        threw = true;
    }
    check(threw, "n=17 should throw invalid_argument");

    threw = false;
    try {
        knockd::derive_ports(kTestVectors[0].secret, 0, 6, 20000, 60000,
                              static_cast<uint8_t>(knockd::kNumChannels));
    } catch (const std::invalid_argument &) {
        threw = true;
    }
    check(threw, "channel_id == kNumChannels should throw invalid_argument");

    // Every channel must give a genuinely distinct sequence -- this is the
    // whole point of hashing channel_id in rather than offsetting
    // time_counter (see docs/channel-signaling-design.html).
    {
        std::vector<std::vector<uint16_t>> seqs;
        for (int c = 0; c < knockd::kNumChannels; ++c) {
            seqs.push_back(knockd::derive_ports(kTestVectors[0].secret, 56230123, 6, 20000, 60000,
                                                 static_cast<uint8_t>(c)));
        }
        bool all_distinct = true;
        for (size_t a = 0; a < seqs.size() && all_distinct; ++a) {
            for (size_t b = a + 1; b < seqs.size(); ++b) {
                if (seqs[a] == seqs[b]) {
                    all_distinct = false;
                    break;
                }
            }
        }
        check(all_distinct, "expected all channels to produce distinct sequences");
    }

    if (failures == 0) {
        std::printf("all tests passed (%zu vectors)\n", kTestVectors.size());
        return 0;
    }
    std::fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
}
