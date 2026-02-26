#include "crypto.h"

namespace rtlc2 {
namespace crypto {

std::vector<uint8_t> XOREncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    if (key.empty()) return data;

    std::vector<uint8_t> result(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

std::vector<uint8_t> XORDecrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    return XOREncrypt(data, key); // XOR is symmetric
}

} // namespace crypto
} // namespace rtlc2
