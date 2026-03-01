#pragma once

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <winternl.h>

namespace rtlc2 {
namespace syscalls {

enum class SyscallMethod {
    None,       // Fall back to normal ntdll imports
    Direct,     // Inline syscall instruction
    Indirect,   // Jump to syscall;ret gadget in ntdll
    HellsGate   // Resolve SSN via Hell's/Halo's Gate + indirect
};

struct SyscallEntry {
    DWORD ssn;
    PVOID gadget_addr;    // syscall;ret gadget address (for indirect)
    bool resolved;
};

bool Initialize(SyscallMethod method);
bool IsInitialized();
SyscallMethod GetMethod();

// NT API wrappers - identical signatures to ntdll Nt* functions
NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
    PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList);

NTSTATUS NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine,
    PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID ClientId);

NTSTATUS NtClose(HANDLE Handle);

NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);

NTSTATUS NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
NTSTATUS NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

NTSTATUS NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);

NTSTATUS NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG InheritDisposition,
    ULONG AllocationType, ULONG Win32Protect);

NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType);

NTSTATUS NtQuerySystemInformation(ULONG SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength);

} // namespace syscalls
} // namespace rtlc2

#endif // RTLC2_WINDOWS
