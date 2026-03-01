#ifdef RTLC2_WINDOWS

#include "agent.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <string>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

namespace rtlc2 {
namespace modules {

static std::string GetIntegrityLevel() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return "unknown";
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    if (dwSize == 0) {
        CloseHandle(hToken);
        return "unknown";
    }

    TOKEN_MANDATORY_LABEL* pTIL = (TOKEN_MANDATORY_LABEL*)malloc(dwSize);
    if (!pTIL) {
        CloseHandle(hToken);
        return "unknown";
    }

    GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize);
    DWORD ridLevel = *GetSidSubAuthority(pTIL->Label.Sid,
        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    free(pTIL);
    CloseHandle(hToken);

    if (ridLevel >= SECURITY_MANDATORY_SYSTEM_RID) return "system";
    if (ridLevel >= SECURITY_MANDATORY_HIGH_RID)   return "high";
    if (ridLevel >= SECURITY_MANDATORY_MEDIUM_RID)  return "medium";
    return "low";
}

static std::string GetLocalIP() {
    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    struct addrinfo hints = {0}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        return "0.0.0.0";
    }

    char ip[INET_ADDRSTRLEN];
    struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    freeaddrinfo(result);

    return std::string(ip);
}

SystemInfo GetSystemInfo() {
    SystemInfo info;

    // Hostname
    char hostname[256];
    DWORD hostnameLen = sizeof(hostname);
    GetComputerNameA(hostname, &hostnameLen);
    info.hostname = hostname;

    // Username
    char username[256];
    DWORD usernameLen = sizeof(username);
    GetUserNameA(username, &usernameLen);
    info.username = username;

    // OS
    OSVERSIONINFOEXA osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    // Note: GetVersionEx deprecated, but works for basic info
    #pragma warning(suppress: 4996)
    GetVersionExA((LPOSVERSIONINFOA)&osvi);
    info.os_name = "Windows " + std::to_string(osvi.dwMajorVersion) + "." + std::to_string(osvi.dwMinorVersion);

    // Architecture
    SYSTEM_INFO si;
    ::GetSystemInfo(&si);
    switch (si.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: info.arch = "x64"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: info.arch = "x86"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: info.arch = "arm64"; break;
        default: info.arch = "unknown"; break;
    }

    // Process name
    char proc_path[MAX_PATH];
    GetModuleFileNameA(NULL, proc_path, MAX_PATH);
    char* proc_name = strrchr(proc_path, '\\');
    info.process_name = proc_name ? proc_name + 1 : proc_path;

    // PID
    info.pid = static_cast<int>(GetCurrentProcessId());

    // Internal IP
    info.internal_ip = GetLocalIP();

    // Integrity
    info.integrity = GetIntegrityLevel();

    return info;
}

} // namespace modules
} // namespace rtlc2

#endif // RTLC2_WINDOWS
