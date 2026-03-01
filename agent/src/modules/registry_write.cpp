#include <string>
#include <sstream>
#include <vector>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

namespace rtlc2 { namespace modules {

#ifdef _WIN32

static HKEY ParseHive(const std::string& hive) {
    if (hive == "HKLM" || hive == "HKEY_LOCAL_MACHINE") return HKEY_LOCAL_MACHINE;
    if (hive == "HKCU" || hive == "HKEY_CURRENT_USER") return HKEY_CURRENT_USER;
    if (hive == "HKCR" || hive == "HKEY_CLASSES_ROOT") return HKEY_CLASSES_ROOT;
    if (hive == "HKU"  || hive == "HKEY_USERS") return HKEY_USERS;
    return nullptr;
}

std::string RegistryWrite(const std::string& hive, const std::string& keyPath,
                          const std::string& valueName, const std::string& data,
                          const std::string& regType) {
    HKEY hRoot = ParseHive(hive);
    if (!hRoot) return "Error: Unknown hive '" + hive + "'. Use HKLM, HKCU, HKCR, or HKU.";

    HKEY hKey;
    LONG rc = RegOpenKeyExA(hRoot, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        return "Error: RegOpenKeyEx failed (code " + std::to_string(rc) + "). Key may not exist.";
    }

    DWORD type = REG_SZ;
    const BYTE* pData = reinterpret_cast<const BYTE*>(data.c_str());
    DWORD dataLen = static_cast<DWORD>(data.size() + 1);

    if (regType == "REG_DWORD" || regType == "dword") {
        type = REG_DWORD;
        DWORD val = static_cast<DWORD>(std::stoul(data));
        rc = RegSetValueExA(hKey, valueName.c_str(), 0, type,
                            reinterpret_cast<const BYTE*>(&val), sizeof(val));
    } else if (regType == "REG_BINARY" || regType == "binary") {
        type = REG_BINARY;
        // data is hex string, convert to bytes
        std::vector<BYTE> bytes;
        for (size_t i = 0; i + 1 < data.size(); i += 2) {
            bytes.push_back(static_cast<BYTE>(std::stoul(data.substr(i, 2), nullptr, 16)));
        }
        rc = RegSetValueExA(hKey, valueName.c_str(), 0, type, bytes.data(),
                            static_cast<DWORD>(bytes.size()));
    } else if (regType == "REG_EXPAND_SZ" || regType == "expand_sz") {
        type = REG_EXPAND_SZ;
        rc = RegSetValueExA(hKey, valueName.c_str(), 0, type, pData, dataLen);
    } else if (regType == "REG_MULTI_SZ" || regType == "multi_sz") {
        type = REG_MULTI_SZ;
        // Each value separated by \0, double \0 at end
        std::string multi = data;
        // Replace | with \0
        for (auto& c : multi) { if (c == '|') c = '\0'; }
        multi.push_back('\0');
        multi.push_back('\0');
        rc = RegSetValueExA(hKey, valueName.c_str(), 0, type,
                            reinterpret_cast<const BYTE*>(multi.c_str()),
                            static_cast<DWORD>(multi.size()));
    } else {
        // Default REG_SZ
        rc = RegSetValueExA(hKey, valueName.c_str(), 0, type, pData, dataLen);
    }

    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) {
        return "Error: RegSetValueEx failed (code " + std::to_string(rc) + ")";
    }
    return "OK: " + hive + "\\" + keyPath + "\\" + valueName + " = " + data;
}

std::string RegistryDelete(const std::string& hive, const std::string& keyPath,
                           const std::string& valueName) {
    HKEY hRoot = ParseHive(hive);
    if (!hRoot) return "Error: Unknown hive '" + hive + "'";

    HKEY hKey;
    LONG rc = RegOpenKeyExA(hRoot, keyPath.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) return "Error: RegOpenKeyEx failed (code " + std::to_string(rc) + ")";

    if (valueName.empty()) {
        // Delete the entire key
        RegCloseKey(hKey);
        rc = RegDeleteKeyA(hRoot, keyPath.c_str());
    } else {
        rc = RegDeleteValueA(hKey, valueName.c_str());
        RegCloseKey(hKey);
    }

    if (rc != ERROR_SUCCESS) return "Error: Delete failed (code " + std::to_string(rc) + ")";
    return "OK: Deleted " + hive + "\\" + keyPath + (valueName.empty() ? "" : "\\" + valueName);
}

std::string RegistryCreateKey(const std::string& hive, const std::string& keyPath) {
    HKEY hRoot = ParseHive(hive);
    if (!hRoot) return "Error: Unknown hive '" + hive + "'";

    HKEY hKey;
    DWORD disposition;
    LONG rc = RegCreateKeyExA(hRoot, keyPath.c_str(), 0, nullptr,
                               REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr,
                               &hKey, &disposition);
    if (rc != ERROR_SUCCESS) return "Error: RegCreateKeyEx failed (code " + std::to_string(rc) + ")";
    RegCloseKey(hKey);

    return disposition == REG_CREATED_NEW_KEY
        ? "OK: Created " + hive + "\\" + keyPath
        : "OK: Key already exists " + hive + "\\" + keyPath;
}

#else // POSIX

std::string RegistryWrite(const std::string&, const std::string&,
                          const std::string&, const std::string&,
                          const std::string&) {
    return "Registry operations only available on Windows";
}

std::string RegistryDelete(const std::string&, const std::string&,
                           const std::string&) {
    return "Registry operations only available on Windows";
}

std::string RegistryCreateKey(const std::string&, const std::string&) {
    return "Registry operations only available on Windows";
}

#endif

}} // namespace rtlc2::modules

// Dispatcher called from agent.cpp via extern declaration
namespace rtlc2 {
std::string RegistryWriteCommand(const std::string& action, const std::string& args) {
    // args format: "hive|keyPath|valueName|data|type"
    auto p1 = args.find('|');
    auto p2 = (p1 != std::string::npos) ? args.find('|', p1 + 1) : std::string::npos;

    if (action == "createkey") {
        if (p1 == std::string::npos) return "Error: createkey requires hive|keyPath";
        return modules::RegistryCreateKey(args.substr(0, p1), args.substr(p1 + 1));
    }

    auto p3 = (p2 != std::string::npos) ? args.find('|', p2 + 1) : std::string::npos;

    if (action == "delete") {
        if (p2 == std::string::npos) return "Error: delete requires hive|keyPath|valueName";
        return modules::RegistryDelete(args.substr(0, p1), args.substr(p1 + 1, p2 - p1 - 1),
                                       args.substr(p2 + 1));
    }

    // Default: write
    auto p4 = (p3 != std::string::npos) ? args.find('|', p3 + 1) : std::string::npos;
    if (p3 == std::string::npos) return "Error: write requires hive|keyPath|valueName|data[|type]";
    std::string regType = (p4 != std::string::npos) ? args.substr(p4 + 1) : "REG_SZ";
    return modules::RegistryWrite(args.substr(0, p1), args.substr(p1 + 1, p2 - p1 - 1),
                                  args.substr(p2 + 1, p3 - p2 - 1), args.substr(p3 + 1, (p4 != std::string::npos) ? p4 - p3 - 1 : std::string::npos), regType);
}
} // namespace rtlc2
