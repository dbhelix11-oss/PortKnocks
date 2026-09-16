#include "hmac_verify.hpp"

#include <openssl/evp.h>
#include <stdexcept>

namespace knockd {

std::array<uint8_t, 32> hmac_sha256(const std::vector<uint8_t> &key,
                                     const std::vector<uint8_t> &message) {
    std::array<uint8_t, 32> out{};
    size_t out_len = 0;

    unsigned char *result = EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr,
                                       key.data(), key.size(),
                                       message.data(), message.size(),
                                       out.data(), out.size(), &out_len);
    if (result == nullptr || out_len != out.size()) {
        throw std::runtime_error("HMAC-SHA256 computation failed");
    }
    return out;
}

} // namespace knockd
