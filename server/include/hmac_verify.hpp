#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace knockd {

// Thin wrapper over OpenSSL's HMAC-SHA256 (EVP API). No hand-rolled crypto.
std::array<uint8_t, 32> hmac_sha256(const std::vector<uint8_t> &key,
                                     const std::vector<uint8_t> &message);

} // namespace knockd
