#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace knockd {

constexpr int kNumChannels = 11; // valid channel_id values: 0..10

// Mirrors client/knockc/derive.py and spec/derivation.md byte-for-byte.
// `secret` must be exactly 32 bytes. HMAC message is time_counter (8
// bytes, big-endian) concatenated with channel_id (1 byte) -- protocol
// v2. Throws std::invalid_argument on bad arguments (n out of [1,16],
// port_high <= port_low, or channel_id out of [0, kNumChannels)).
std::vector<uint16_t> derive_ports(const std::vector<uint8_t> &secret,
                                    uint64_t time_counter,
                                    int n,
                                    uint16_t port_low,
                                    uint16_t port_high,
                                    uint8_t channel_id = 0);

} // namespace knockd
