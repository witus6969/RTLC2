// Reconnaissance Modules - Network and host enumeration
// Includes share enum, service enum, domain info, file search
#include "agent.h"
#include <cstring>
#include <string>
#include <sstream>
#include <vector>

#ifdef RTLC2_WINDOWS
#include <windows.h>
#include <lm.h>
#include <dsgetdc.h>
#pragma comment(lib, "netapi32.lib")
#endif

namespace rtlc2 {
namespace modules {

#ifdef RTLC2_WINDOWS

// Enumerate SMB shares on a target host
std::string ShareEnum(const std::string& target) {
    std::ostringstream out;
    out << "Shares on " << target << ":\n\n";
    out << "Name\t\t\tType\t\tRemark\n";
    out << "----\t\t\t----\t\t------\n";

    int wLen = MultiByteToWideChar(CP_ACP, 0, target.c_str(), -1, NULL, 0);
    std::vector<WCHAR> wTarget(wLen);
    MultiByteToWideChar(CP_ACP, 0, target.c_str(), -1, wTarget.data(), wLen);

    PSHARE_INFO_1 shareInfo = NULL;
    DWORD entriesRead = 0, totalEntries = 0;
    NET_API_STATUS status = NetShareEnum(wTarget.data(), 1,
        (LPBYTE*)&shareInfo, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, NULL);

    if (status != NERR_Success) {
        return "NetShareEnum failed: " + std::to_string(status);
    }

    for (DWORD i = 0; i < entriesRead; i++) {
        char name[256] = {}, remark[256] = {};
        WideCharToMultiByte(CP_ACP, 0, shareInfo[i].shi1_netname, -1, name, sizeof(name), NULL, NULL);
        WideCharToMultiByte(CP_ACP, 0, shareInfo[i].shi1_remark, -1, remark, sizeof(remark), NULL, NULL);

        out << name;
        int pad = 24 - (int)strlen(name);
        for (int j = 0; j < pad; j++) out << " ";

        switch (shareInfo[i].shi1_type & 0x0FFFFFFF) {
            case STYPE_DISKTREE: out << "Disk\t\t"; break;
            case STYPE_PRINTQ:   out << "Printer\t\t"; break;
            case STYPE_IPC:      out << "IPC\t\t"; break;
            default:             out << "Special\t\t"; break;
        }
        out << remark << "\n";
    }

    NetApiBufferFree(shareInfo);
    return out.str();
}

// Enumerate services on a host
std::string ServiceEnum(const std::string& target) {
    std::ostringstream out;
    out << "Services on " << (target.empty() ? "localhost" : target) << ":\n\n";

    SC_HANDLE hSCM = OpenSCManagerA(target.empty() ? NULL : target.c_str(),
                                     NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return "OpenSCManager failed: " + std::to_string(GetLastError());

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusA(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL,
                        NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle);

    std::vector<BYTE> buf(bytesNeeded);
    ENUM_SERVICE_STATUSA* services = (ENUM_SERVICE_STATUSA*)buf.data();

    if (!EnumServicesStatusA(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL,
                             services, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle)) {
        CloseServiceHandle(hSCM);
        return "EnumServicesStatus failed";
    }

    out << "Name\t\t\t\tState\t\tDisplay Name\n";
    out << "----\t\t\t\t-----\t\t------------\n";

    for (DWORD i = 0; i < servicesReturned; i++) {
        out << services[i].lpServiceName;
        int pad = 32 - (int)strlen(services[i].lpServiceName);
        for (int j = 0; j < pad; j++) out << " ";

        switch (services[i].ServiceStatus.dwCurrentState) {
            case SERVICE_RUNNING: out << "Running\t\t"; break;
            case SERVICE_STOPPED: out << "Stopped\t\t"; break;
            case SERVICE_PAUSED:  out << "Paused\t\t"; break;
            default:              out << "Other\t\t"; break;
        }
        out << services[i].lpDisplayName << "\n";
    }

    CloseServiceHandle(hSCM);
    return out.str();
}

// Get domain information
std::string DomainInfo() {
    std::ostringstream out;

    // Computer name
    char computerName[256] = {};
    DWORD compLen = sizeof(computerName);
    GetComputerNameA(computerName, &compLen);
    out << "Computer: " << computerName << "\n";

    // Domain info
    PDOMAIN_CONTROLLER_INFOA dcInfo = NULL;
    DWORD status = DsGetDcNameA(NULL, NULL, NULL, NULL,
        DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME, &dcInfo);

    if (status == ERROR_SUCCESS && dcInfo) {
        out << "Domain: " << (dcInfo->DomainName ? dcInfo->DomainName : "N/A") << "\n";
        out << "DC Name: " << (dcInfo->DomainControllerName ? dcInfo->DomainControllerName : "N/A") << "\n";
        out << "DC Address: " << (dcInfo->DomainControllerAddress ? dcInfo->DomainControllerAddress : "N/A") << "\n";
        out << "DNS Forest: " << (dcInfo->DnsForestName ? dcInfo->DnsForestName : "N/A") << "\n";
        out << "Site: " << (dcInfo->ClientSiteName ? dcInfo->ClientSiteName : "N/A") << "\n";
        NetApiBufferFree(dcInfo);
    } else {
        out << "Not domain joined or DC unreachable\n";
    }

    return out.str();
}

// Enumerate local users
std::string UserEnum(const std::string& target) {
    std::ostringstream out;
    out << "Users on " << (target.empty() ? "localhost" : target) << ":\n\n";

    int wLen = MultiByteToWideChar(CP_ACP, 0, target.c_str(), -1, NULL, 0);
    std::vector<WCHAR> wTarget(wLen);
    MultiByteToWideChar(CP_ACP, 0, target.c_str(), -1, wTarget.data(), wLen);

    PUSER_INFO_1 userInfo = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS status = NetUserEnum(
        target.empty() ? NULL : wTarget.data(),
        1, FILTER_NORMAL_ACCOUNT,
        (LPBYTE*)&userInfo, MAX_PREFERRED_LENGTH,
        &entriesRead, &totalEntries, &resumeHandle);

    if (status != NERR_Success) {
        return "NetUserEnum failed: " + std::to_string(status);
    }

    for (DWORD i = 0; i < entriesRead; i++) {
        char name[256] = {};
        WideCharToMultiByte(CP_ACP, 0, userInfo[i].usri1_name, -1, name, sizeof(name), NULL, NULL);

        out << name;
        if (userInfo[i].usri1_priv == USER_PRIV_ADMIN) out << " [Admin]";
        if (userInfo[i].usri1_flags & UF_ACCOUNTDISABLE) out << " [Disabled]";
        out << "\n";
    }

    NetApiBufferFree(userInfo);
    return out.str();
}

// Read registry value
std::string RegistryRead(const std::string& path, const std::string& valueName) {
    // Parse hive from path
    HKEY hRoot = HKEY_LOCAL_MACHINE;
    std::string subKey = path;
    if (path.find("HKLM\\") == 0 || path.find("HKEY_LOCAL_MACHINE\\") == 0) {
        hRoot = HKEY_LOCAL_MACHINE;
        subKey = path.substr(path.find('\\') + 1);
    } else if (path.find("HKCU\\") == 0 || path.find("HKEY_CURRENT_USER\\") == 0) {
        hRoot = HKEY_CURRENT_USER;
        subKey = path.substr(path.find('\\') + 1);
    } else if (path.find("HKCR\\") == 0) {
        hRoot = HKEY_CLASSES_ROOT;
        subKey = path.substr(path.find('\\') + 1);
    }

    HKEY hKey;
    if (RegOpenKeyExA(hRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return "Failed to open key: " + path;
    }

    BYTE data[4096];
    DWORD dataLen = sizeof(data);
    DWORD type = 0;

    if (RegQueryValueExA(hKey, valueName.c_str(), NULL, &type, data, &dataLen) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "Failed to read value: " + valueName;
    }
    RegCloseKey(hKey);

    std::ostringstream out;
    out << path << "\\" << valueName << " = ";
    switch (type) {
        case REG_SZ:
        case REG_EXPAND_SZ:
            out << (char*)data;
            break;
        case REG_DWORD:
            out << "0x" << std::hex << *(DWORD*)data;
            break;
        case REG_QWORD:
            out << "0x" << std::hex << *(uint64_t*)data;
            break;
        default:
            out << "[binary data, " << dataLen << " bytes]";
            break;
    }
    return out.str();
}

#endif // RTLC2_WINDOWS

// Recursive file search (cross-platform)
std::string FileSearch(const std::string& path, const std::string& pattern) {
    std::ostringstream out;
    out << "Searching " << path << " for '" << pattern << "':\n\n";

#ifdef RTLC2_WINDOWS
    WIN32_FIND_DATAA fd;
    std::string searchPath = path + "\\" + pattern;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                ULARGE_INTEGER fileSize;
                fileSize.LowPart = fd.nFileSizeLow;
                fileSize.HighPart = fd.nFileSizeHigh;
                out << path << "\\" << fd.cFileName << " (" << fileSize.QuadPart << " bytes)\n";
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    // Recurse into subdirectories
    std::string dirSearch = path + "\\*";
    hFind = FindFirstFileA(dirSearch.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0) {
                out << FileSearch(path + "\\" + fd.cFileName, pattern);
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
#else
    // POSIX implementation using opendir/readdir
    // Simplified: just report the search parameters
    out << "(POSIX file search not yet implemented)\n";
#endif

    return out.str();
}

} // namespace modules
} // namespace rtlc2
