#ifndef RTLC2_CRYPTO_H
#define RTLC2_CRYPTO_H

#include <string>
#include <vector>
#include <cstdint>

namespace rtlc2 {
namespace crypto {

// AES-256-GCM encryption/decryption
class AES256 {
public:
    AES256();
    ~AES256();

    // Initialize with hex-encoded key (64 hex chars = 32 bytes)
    bool Init(const std::string& hex_key);

    // Encrypt: returns nonce || ciphertext || tag
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> Encrypt(const std::string& plaintext);

    // Decrypt: expects nonce || ciphertext || tag
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& data);

    bool IsInitialized() const { return initialized_; }

private:
    std::vector<uint8_t> key_;
    bool initialized_;
};

// XOR encryption (simple obfuscation layer)
std::vector<uint8_t> XOREncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
std::vector<uint8_t> XORDecrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);

// Hex encode/decode
std::string HexEncode(const std::vector<uint8_t>& data);
std::vector<uint8_t> HexDecode(const std::string& hex);

// Base64 encode/decode
std::string Base64Encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> Base64Decode(const std::string& encoded);

} // namespace crypto
} // namespace rtlc2

#endif // RTLC2_CRYPTO_H
