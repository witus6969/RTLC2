#include "crypto.h"
#include <cstring>
#include <random>

#ifdef RTLC2_WINDOWS
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

namespace rtlc2 {
namespace crypto {

AES256::AES256() : initialized_(false) {}
AES256::~AES256() {
    // Zero out the key
    if (!key_.empty()) {
        volatile uint8_t* p = key_.data();
        for (size_t i = 0; i < key_.size(); i++) p[i] = 0;
    }
}

bool AES256::Init(const std::string& hex_key) {
    key_ = HexDecode(hex_key);
    if (key_.size() != 32) {
        key_.clear();
        return false;
    }
    initialized_ = true;
    return true;
}

std::vector<uint8_t> AES256::Encrypt(const std::string& plaintext) {
    return Encrypt(std::vector<uint8_t>(plaintext.begin(), plaintext.end()));
}

#ifndef RTLC2_WINDOWS
// ======================== OpenSSL Implementation ========================

std::vector<uint8_t> AES256::Encrypt(const std::vector<uint8_t>& plaintext) {
    if (!initialized_) return {};

    const int NONCE_SIZE = 12;
    const int TAG_SIZE = 16;

    // Generate random nonce
    std::vector<uint8_t> nonce(NONCE_SIZE);
    RAND_bytes(nonce.data(), NONCE_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(TAG_SIZE);
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size()));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);

    // Format: nonce || ciphertext || tag
    std::vector<uint8_t> result;
    result.reserve(NONCE_SIZE + ciphertext_len + TAG_SIZE);
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
}

std::vector<uint8_t> AES256::Decrypt(const std::vector<uint8_t>& data) {
    if (!initialized_) return {};

    const int NONCE_SIZE = 12;
    const int TAG_SIZE = 16;

    if (data.size() < static_cast<size_t>(NONCE_SIZE + TAG_SIZE)) return {};

    size_t ciphertext_len = data.size() - NONCE_SIZE - TAG_SIZE;
    const uint8_t* nonce = data.data();
    const uint8_t* ciphertext = data.data() + NONCE_SIZE;
    const uint8_t* tag = data.data() + NONCE_SIZE + ciphertext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> plaintext(ciphertext_len);
    int len = 0, plaintext_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, static_cast<int>(ciphertext_len));
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag);

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) return {}; // Authentication failed

    plaintext_len += len;
    plaintext.resize(plaintext_len);
    return plaintext;
}

#else
// ======================== Windows BCrypt Implementation ========================

std::vector<uint8_t> AES256::Encrypt(const std::vector<uint8_t>& plaintext) {
    if (!initialized_) return {};

    const ULONG NONCE_SIZE = 12;
    const ULONG TAG_SIZE = 16;

    // Generate random nonce
    std::vector<uint8_t> nonce(NONCE_SIZE);
    BCryptGenRandom(NULL, nonce.data(), NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key_.data(), (ULONG)key_.size(), 0);

    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(TAG_SIZE);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce.data();
    authInfo.cbNonce = NONCE_SIZE;
    authInfo.pbTag = tag.data();
    authInfo.cbTag = TAG_SIZE;

    ULONG cbResult = 0;
    BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
                  &authInfo, NULL, 0, ciphertext.data(), (ULONG)ciphertext.size(), &cbResult, 0);

    ciphertext.resize(cbResult);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Format: nonce || ciphertext || tag
    std::vector<uint8_t> result;
    result.reserve(NONCE_SIZE + cbResult + TAG_SIZE);
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
}

std::vector<uint8_t> AES256::Decrypt(const std::vector<uint8_t>& data) {
    if (!initialized_) return {};

    const ULONG NONCE_SIZE = 12;
    const ULONG TAG_SIZE = 16;

    if (data.size() < NONCE_SIZE + TAG_SIZE) return {};

    ULONG ciphertext_len = (ULONG)(data.size() - NONCE_SIZE - TAG_SIZE);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key_.data(), (ULONG)key_.size(), 0);

    std::vector<uint8_t> plaintext(ciphertext_len);
    std::vector<uint8_t> nonce(data.begin(), data.begin() + NONCE_SIZE);
    std::vector<uint8_t> tag(data.end() - TAG_SIZE, data.end());

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce.data();
    authInfo.cbNonce = NONCE_SIZE;
    authInfo.pbTag = tag.data();
    authInfo.cbTag = TAG_SIZE;

    ULONG cbResult = 0;
    NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)(data.data() + NONCE_SIZE), ciphertext_len,
                                     &authInfo, NULL, 0, plaintext.data(), ciphertext_len, &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != 0) return {}; // Auth failed

    plaintext.resize(cbResult);
    return plaintext;
}

#endif // RTLC2_WINDOWS

// ======================== Utility Functions ========================

std::string HexEncode(const std::vector<uint8_t>& data) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t b : data) {
        result += hex[b >> 4];
        result += hex[b & 0x0f];
    }
    return result;
}

std::vector<uint8_t> HexDecode(const std::string& hex) {
    std::vector<uint8_t> result;
    if (hex.length() % 2 != 0) return result;
    result.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t byte = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[i + j];
            byte <<= 4;
            if (c >= '0' && c <= '9') byte |= (c - '0');
            else if (c >= 'a' && c <= 'f') byte |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') byte |= (c - 'A' + 10);
        }
        result.push_back(byte);
    }
    return result;
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(const std::vector<uint8_t>& data) {
    std::string result;
    size_t i = 0;
    uint8_t a3[3], a4[4];

    size_t len = data.size();
    while (len--) {
        a3[i++] = data[data.size() - len - 1];
        if (i == 3) {
            a4[0] = (a3[0] & 0xfc) >> 2;
            a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
            a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
            a4[3] = a3[2] & 0x3f;
            for (i = 0; i < 4; i++) result += b64_table[a4[i]];
            i = 0;
        }
    }

    if (i) {
        for (size_t j = i; j < 3; j++) a3[j] = 0;
        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
        a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
        for (size_t j = 0; j < i + 1; j++) result += b64_table[a4[j]];
        while (i++ < 3) result += '=';
    }

    return result;
}

static uint8_t b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 255;
}

std::vector<uint8_t> Base64Decode(const std::string& encoded) {
    std::vector<uint8_t> result;
    if (encoded.empty()) return result;

    size_t len = encoded.size();
    size_t i = 0;
    uint8_t a4[4], a3[3];
    int j = 0;

    while (i < len && encoded[i] != '=') {
        a4[j++] = b64_decode_char(encoded[i++]);
        if (j == 4) {
            a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
            a3[1] = ((a4[1] & 0x0f) << 4) + ((a4[2] & 0x3c) >> 2);
            a3[2] = ((a4[2] & 0x03) << 6) + a4[3];
            for (j = 0; j < 3; j++) result.push_back(a3[j]);
            j = 0;
        }
    }

    if (j) {
        for (int k = j; k < 4; k++) a4[k] = 0;
        a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
        a3[1] = ((a4[1] & 0x0f) << 4) + ((a4[2] & 0x3c) >> 2);
        for (int k = 0; k < j - 1; k++) result.push_back(a3[k]);
    }

    return result;
}

} // namespace crypto
} // namespace rtlc2
