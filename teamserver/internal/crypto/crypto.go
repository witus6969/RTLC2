package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"
)

// AESCipher handles AES-256-GCM encryption/decryption for agent comms.
type AESCipher struct {
	key []byte
}

// NewAESCipher creates a new AES cipher with the given hex-encoded key.
// Key must be 32 bytes (64 hex chars) for AES-256.
func NewAESCipher(hexKey string) (*AESCipher, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("AES key must be 32 bytes")
	}
	return &AESCipher{key: key}, nil
}

// GenerateKey generates a random 32-byte AES key and returns it hex-encoded.
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
func (c *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts AES-256-GCM encrypted data.
// Expects: nonce (12 bytes) || ciphertext || tag (16 bytes)
func (c *AESCipher) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// XOREncrypt applies XOR with the given key (for obfuscation layer).
func XOREncrypt(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	keyLen := len(key)
	for i := range data {
		result[i] = data[i] ^ key[i%keyLen]
	}
	return result
}

// XORDecrypt is the same as XOREncrypt (XOR is symmetric).
func XORDecrypt(data []byte, key []byte) []byte {
	return XOREncrypt(data, key)
}

// DoubleEncrypt applies XOR then AES encryption (layered).
func (c *AESCipher) DoubleEncrypt(plaintext []byte, xorKey []byte) ([]byte, error) {
	xored := XOREncrypt(plaintext, xorKey)
	return c.Encrypt(xored)
}

// DoubleDecrypt applies AES then XOR decryption.
func (c *AESCipher) DoubleDecrypt(data []byte, xorKey []byte) ([]byte, error) {
	decrypted, err := c.Decrypt(data)
	if err != nil {
		return nil, err
	}
	return XORDecrypt(decrypted, xorKey), nil
}

// HMACSHA256 computes HMAC-SHA256 for message integrity.
func HMACSHA256(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// VerifyHMAC verifies HMAC-SHA256 signature.
func VerifyHMAC(message, signature, key []byte) bool {
	expected := HMACSHA256(message, key)
	return hmac.Equal(signature, expected)
}

// GenerateNonce creates a cryptographically random nonce.
func GenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// DeriveNextKey uses HMAC-SHA256 to derive a new session key from the current one.
// This is a simplified HKDF-Extract style derivation using only standard library packages.
func DeriveNextKey(currentKey []byte, salt []byte) ([]byte, error) {
	if len(currentKey) == 0 {
		return nil, fmt.Errorf("current key cannot be empty")
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(currentKey)
	mac.Write([]byte("rtlc2-key-rotation-v1"))
	derived := mac.Sum(nil)
	return derived, nil
}

// RotationDue checks if key rotation is needed based on checkin count or time elapsed.
// Rotation triggers after 100 checkins or 4 hours since last rotation, whichever comes first.
func RotationDue(checkinCount int, lastRotation time.Time) bool {
	if checkinCount >= 100 {
		return true
	}
	if time.Since(lastRotation) > 4*time.Hour {
		return true
	}
	return false
}
