#include "derive.hpp"
#include "hmac_verify.hpp"

#include <stdexcept>

namespace knockd {

std::vector<uint16_t> derive_ports(const std::vector<uint8_t> &secret,
                                    uint64_t time_counter,
                                    int n,
                                    uint16_t port_low,
                                    uint16_t port_high,
                                    uint8_t channel_id) {
    if (n < 1 || n > 16) {
        throw std::invalid_argument("n must be between 1 and 16");
    }
    if (port_high <= port_low) {
        throw std::invalid_argument("port_high must be greater than port_low");
    }
    if (channel_id >= kNumChannels) {
        throw std::invalid_argument("channel_id must be less than kNumChannels");
    }

    std::vector<uint8_t> msg(9);
    for (int i = 0; i < 8; ++i) {
        msg[7 - i] = static_cast<uint8_t>((time_counter >> (8 * i)) & 0xFF);
    }
    msg[8] = channel_id;

    std::array<uint8_t, 32> digest = hmac_sha256(secret, msg);

    uint32_t span = static_cast<uint32_t>(port_high) - static_cast<uint32_t>(port_low) + 1;
    std::vector<uint16_t> ports;
    ports.reserve(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        uint16_t raw16 = static_cast<uint16_t>((digest[2 * i] << 8) | digest[2 * i + 1]);
        ports.push_back(static_cast<uint16_t>(port_low + (raw16 % span)));
    }
    return ports;
}

} // namespace knockd
