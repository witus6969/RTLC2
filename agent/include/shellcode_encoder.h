#ifndef RTLC2_SHELLCODE_ENCODER_H
#define RTLC2_SHELLCODE_ENCODER_H

#include <vector>
#include <cstdint>
#include <string>

namespace rtlc2 {
namespace crypto {

enum class EncoderType {
    XOR_ROLLING,   // XOR with 16-byte rolling key
    AES_CTR,       // AES-256-CTR with embedded key
    RC4_STREAM,    // RC4 stream cipher
    SGN_POLY       // SGN-style polymorphic encoder
};

// Encode shellcode with a self-decoding stub prepended
// Returns: [decoder_stub][encoded_payload] as position-independent shellcode
std::vector<uint8_t> EncodeShellcode(const std::vector<uint8_t>& shellcode, EncoderType type);

// Chain multiple encoders (e.g., XOR then SGN)
std::vector<uint8_t> EncodeShellcodeChain(const std::vector<uint8_t>& shellcode,
                                            const std::vector<EncoderType>& chain);

} // namespace crypto
} // namespace rtlc2

#endif
