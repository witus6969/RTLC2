#include "jobs.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace rtlc2 {

std::string JobManager::generateId() {
    static std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
    std::ostringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(8) << dist(rng);
    return ss.str();
}

std::string JobManager::StartJob(JobType type, const std::string& description,
                                  std::function<void(JobInfo&)> fn) {
    std::lock_guard<std::mutex> lock(mu_);
    auto id = generateId();
    auto info = std::make_shared<JobInfo>();
    info->id = id;
    info->type = type;
    info->description = description;
    info->startTime = std::time(nullptr);
    info->running.store(true);

    jobs_[id] = info;

    // Capture shared_ptr by value to keep info alive
    threads_[id] = std::thread([info, fn]() {
        fn(*info);
    });

    return id;
}

bool JobManager::StopJob(const std::string& jobId) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = jobs_.find(jobId);
    if (it == jobs_.end()) return false;

    it->second->running.store(false);

    auto tit = threads_.find(jobId);
    if (tit != threads_.end() && tit->second.joinable()) {
        tit->second.join();
        threads_.erase(tit);
    }

    jobs_.erase(it);
    return true;
}

void JobManager::StopAll() {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& [id, info] : jobs_) {
        info->running.store(false);
    }
    for (auto& [id, t] : threads_) {
        if (t.joinable()) t.join();
    }
    jobs_.clear();
    threads_.clear();
}

std::vector<std::pair<std::string, std::string>> JobManager::ListJobs() {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<std::pair<std::string, std::string>> result;
    for (const auto& [id, info] : jobs_) {
        if (info->running.load()) {
            result.emplace_back(id, info->description);
        }
    }
    return result;
}

std::string JobManager::GetJobOutput(const std::string& jobId) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = jobs_.find(jobId);
    if (it == jobs_.end()) return "(job not found)";
    return it->second->GetOutput();
}

std::string JobManager::FormatJobList() {
    auto list = ListJobs();
    if (list.empty()) return "No active jobs.";

    std::ostringstream ss;
    ss << "Active Jobs:\n";
    ss << std::left << std::setw(12) << "Job ID" << std::setw(30) << "Description" << "\n";
    ss << std::string(42, '-') << "\n";
    for (const auto& [id, desc] : list) {
        ss << std::left << std::setw(12) << id << std::setw(30) << desc << "\n";
    }
    return ss.str();
}

} // namespace rtlc2
