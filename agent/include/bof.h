#ifndef RTLC2_BOF_H
#define RTLC2_BOF_H

#include <string>
#include <vector>
#include <cstdint>
#include <cstdarg>

#ifdef RTLC2_WINDOWS
#include <windows.h>
#endif

namespace rtlc2 {
namespace bof {

// BOF (Beacon Object File) loader
// Compatible with Cobalt Strike and Sliver BOFs

struct BOFResult {
    bool success;
    std::string output;
    int exit_code;
};

// Load and execute a BOF in memory
// bof_data: raw COFF object file bytes
// function_name: entry function to call (default: "go")
// args: packed arguments buffer
BOFResult Execute(const std::vector<uint8_t>& bof_data,
                  const std::string& function_name = "go",
                  const std::vector<uint8_t>& args = {});

// Pack arguments for BOF execution (Cobalt Strike compatible format)
class ArgPacker {
public:
    ArgPacker();

    void AddShort(uint16_t value);
    void AddInt(uint32_t value);
    void AddString(const std::string& value);
    void AddWString(const std::wstring& value);
    void AddData(const uint8_t* data, size_t length);

    std::vector<uint8_t> GetBuffer() const;

private:
    std::vector<uint8_t> buffer_;
};

} // namespace bof
} // namespace rtlc2

// Beacon API declarations (extern "C" so BOFs can link to them)
extern "C" {

// Output functions
void BeaconOutput(int type, const char* data, int len);
void BeaconPrintf(int type, const char* fmt, ...);

// Data parsing functions
void BeaconDataParse(void* parser, char* buffer, int size);
int BeaconDataInt(void* parser);
short BeaconDataShort(void* parser);
char* BeaconDataExtract(void* parser, int* out_len);
int BeaconDataLength(void* parser);

// Token functions (stubs for compatibility)
int BeaconUseToken(void* token);
void BeaconRevertToken(void);

// Utility functions
int BeaconIsAdmin(void);
void BeaconGetSpawnTo(int x86, char* buffer, int length);
void BeaconCleanupProcess(void* process_info);

// Format functions for Cobalt Strike compatibility
void BeaconFormatAlloc(void* format, int maxsz);
void BeaconFormatReset(void* format);
void BeaconFormatFree(void* format);
void BeaconFormatAppend(void* format, const char* data, int len);
void BeaconFormatPrintf(void* format, const char* fmt, ...);
char* BeaconFormatToString(void* format, int* size);
void BeaconFormatInt(void* format, int value);

// Inline-execute functions (stubs)
int BeaconSpawnTemporaryProcess(int x86, int ignoreToken, void* startupInfo, void* processInfo);
void BeaconInjectProcess(void* processInfo, int pid, char* payload, int payloadLen, int offset, char* arg, int argLen);
void BeaconInjectTemporaryProcess(void* processInfo, char* payload, int payloadLen, int offset, char* arg, int argLen);

// toWideChar helper
int toWideChar(const char* src, wchar_t* dst, int max);

} // extern "C"

#endif // RTLC2_BOF_H
