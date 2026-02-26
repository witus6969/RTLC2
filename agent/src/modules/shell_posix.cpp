#ifndef RTLC2_WINDOWS

#include "agent.h"
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <array>
#include <memory>

namespace rtlc2 {
namespace modules {

std::string ExecuteShell(const std::string& command) {
    std::array<char, 4096> buffer;
    std::string result;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        return "Error: Failed to execute command";
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    return result;
}

std::string GetProcessList() {
    return ExecuteShell("ps aux");
}

std::string ListDirectory(const std::string& path) {
    return ExecuteShell("ls -la " + path);
}

std::string GetCurrentDir() {
    char buf[4096];
    if (getcwd(buf, sizeof(buf))) {
        return std::string(buf);
    }
    return "Error: getcwd failed";
}

bool ChangeDir(const std::string& path) {
    return chdir(path.c_str()) == 0;
}

std::string GetWhoami() {
    return ExecuteShell("whoami");
}

std::string GetIPConfig() {
#ifdef RTLC2_MACOS
    return ExecuteShell("ifconfig");
#else
    return ExecuteShell("ip addr show");
#endif
}

} // namespace modules
} // namespace rtlc2

#endif // !RTLC2_WINDOWS
