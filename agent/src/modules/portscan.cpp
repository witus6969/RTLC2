// Port Scanner - TCP connect scan with threading
// Cross-platform implementation for network reconnaissance
#include "agent.h"
#include <cstring>
#include <string>
#include <sstream>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>

#ifdef RTLC2_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#define CLOSESOCKET closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSESOCKET close
#endif

namespace rtlc2 {
namespace modules {

struct ScanResult {
    std::string host;
    int port;
    bool open;
};

static std::mutex g_scanMutex;
static std::vector<ScanResult> g_scanResults;

// Check if a single port is open
static bool IsPortOpen(const std::string& host, int port, int timeout_ms) {
    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%d", port);

    if (getaddrinfo(host.c_str(), portStr, &hints, &result) != 0)
        return false;

    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        return false;
    }

    // Set non-blocking
#ifdef RTLC2_WINDOWS
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    int ret = connect(sock, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);

    bool open = false;
    if (ret == 0) {
        open = true;
    } else {
        // Wait for connection with timeout
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        if (select((int)sock + 1, NULL, &writefds, NULL, &tv) > 0) {
            int err = 0;
            socklen_t errLen = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &errLen);
            open = (err == 0);
        }
    }

    CLOSESOCKET(sock);
    return open;
}

// Scan a range of ports on a host
static void ScanWorker(const std::string& host, const std::vector<int>& ports, int timeout_ms) {
    for (int port : ports) {
        if (IsPortOpen(host, port, timeout_ms)) {
            std::lock_guard<std::mutex> lock(g_scanMutex);
            g_scanResults.push_back({host, port, true});
        }
    }
}

// Parse port range "80,443,8080" or "1-1024"
static std::vector<int> ParsePorts(const std::string& portSpec) {
    std::vector<int> ports;

    std::istringstream stream(portSpec);
    std::string token;
    while (std::getline(stream, token, ',')) {
        size_t dash = token.find('-');
        if (dash != std::string::npos) {
            int start = std::stoi(token.substr(0, dash));
            int end = std::stoi(token.substr(dash + 1));
            for (int p = start; p <= end && p <= 65535; p++) {
                ports.push_back(p);
            }
        } else {
            int p = std::stoi(token);
            if (p > 0 && p <= 65535) ports.push_back(p);
        }
    }
    return ports;
}

// Parse target(s): "192.168.1.1" or "192.168.1.0/24"
static std::vector<std::string> ParseTargets(const std::string& target) {
    std::vector<std::string> hosts;

    size_t slash = target.find('/');
    if (slash != std::string::npos) {
        // CIDR notation
        std::string baseIP = target.substr(0, slash);
        int mask = std::stoi(target.substr(slash + 1));
        if (mask < 0 || mask > 32) return hosts;

        uint32_t ip = 0;
        struct in_addr addr;
        if (inet_pton(AF_INET, baseIP.c_str(), &addr) == 1) {
            ip = ntohl(addr.s_addr);
        }

        uint32_t hostBits = 32 - mask;
        uint32_t numHosts = (1U << hostBits);
        uint32_t network = ip & (~((1U << hostBits) - 1));

        // Skip network and broadcast for /24 and larger
        uint32_t start = (numHosts > 2) ? 1 : 0;
        uint32_t end = (numHosts > 2) ? numHosts - 1 : numHosts;

        for (uint32_t i = start; i < end && i < 256; i++) { // Cap at 256 hosts
            uint32_t hostIP = network + i;
            struct in_addr a;
            a.s_addr = htonl(hostIP);
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, ipStr, sizeof(ipStr));
            hosts.push_back(ipStr);
        }
    } else {
        hosts.push_back(target);
    }
    return hosts;
}

std::string PortScan(const std::string& target, const std::string& portSpec,
                     int timeout_ms, int threads) {
#ifdef RTLC2_WINDOWS
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    std::vector<int> ports = ParsePorts(portSpec);
    std::vector<std::string> hosts = ParseTargets(target);

    if (ports.empty()) return "No valid ports specified";
    if (hosts.empty()) return "No valid targets specified";

    g_scanResults.clear();

    // Distribute work across threads
    std::vector<std::thread> workers;
    int portsPerThread = (int)ports.size() / threads;
    if (portsPerThread < 1) portsPerThread = 1;

    for (const auto& host : hosts) {
        for (int t = 0; t < threads && t * portsPerThread < (int)ports.size(); t++) {
            int start = t * portsPerThread;
            int end = (t == threads - 1) ? (int)ports.size() : start + portsPerThread;
            std::vector<int> chunk(ports.begin() + start, ports.begin() + end);
            workers.emplace_back(ScanWorker, host, chunk, timeout_ms);
        }
    }

    for (auto& w : workers) w.join();

    // Format results
    std::ostringstream out;
    out << "Scan complete: " << hosts.size() << " host(s), " << ports.size() << " port(s)\n\n";

    if (g_scanResults.empty()) {
        out << "No open ports found\n";
    } else {
        out << "HOST\t\t\tPORT\tSTATE\n";
        out << "----\t\t\t----\t-----\n";
        for (const auto& r : g_scanResults) {
            out << r.host;
            int pad = 24 - (int)r.host.length();
            for (int i = 0; i < pad; i++) out << " ";
            out << r.port << "\topen\n";
        }
    }

    return out.str();
}

} // namespace modules
} // namespace rtlc2
