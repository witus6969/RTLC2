// Syscall dispatch wrappers - call NT APIs via direct/indirect syscalls
#include "syscalls.h"

#ifdef RTLC2_WINDOWS

#include <windows.h>
#include <cstring>

namespace rtlc2 {
namespace syscalls {

// Forward declaration from resolver.cpp
struct SyscallEntry;
extern SyscallEntry* GetEntry(const char* name);
extern SyscallMethod GetMethod();
extern bool IsInitialized();

// For MinGW x64: use inline assembly to perform syscalls
// The DoSyscall function takes SSN, gadget address, and up to 12 arguments
// Uses the Windows x64 calling convention: rcx, rdx, r8, r9, stack
extern "C" NTSTATUS DoDirectSyscall(DWORD ssn, ULONG_PTR arg1, ULONG_PTR arg2,
    ULONG_PTR arg3, ULONG_PTR arg4, ULONG_PTR arg5, ULONG_PTR arg6,
    ULONG_PTR arg7, ULONG_PTR arg8, ULONG_PTR arg9, ULONG_PTR arg10,
    ULONG_PTR arg11);

extern "C" NTSTATUS DoIndirectSyscall(DWORD ssn, PVOID gadget, ULONG_PTR arg1,
    ULONG_PTR arg2, ULONG_PTR arg3, ULONG_PTR arg4, ULONG_PTR arg5,
    ULONG_PTR arg6, ULONG_PTR arg7, ULONG_PTR arg8, ULONG_PTR arg9,
    ULONG_PTR arg10, ULONG_PTR arg11);

// Fallback: call the real Nt* function from ntdll
template<typename FnT>
static FnT GetNtFunc(const char* name) {
    return (FnT)GetProcAddress(GetModuleHandleA("ntdll.dll"), name);
}

// Macro to define each wrapper function
#define DEFINE_SYSCALL_0(name) \
NTSTATUS name() { \
    if (GetMethod() == SyscallMethod::None) { \
        typedef NTSTATUS(NTAPI* fn_t)(); \
        return GetNtFunc<fn_t>(#name)(); \
    } \
    auto* e = GetEntry(#name); \
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001; \
    if (GetMethod() == SyscallMethod::Direct) \
        return DoDirectSyscall(e->ssn, 0,0,0,0,0,0,0,0,0,0,0); \
    return DoIndirectSyscall(e->ssn, e->gadget_addr, 0,0,0,0,0,0,0,0,0,0,0); \
}

// ============= Wrapper implementations =============

NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        return GetNtFunc<fn_t>("NtAllocateVirtualMemory")(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }
    auto* e = GetEntry("NtAllocateVirtualMemory");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, ZeroBits, (ULONG_PTR)RegionSize, AllocationType, Protect, 0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, ZeroBits, (ULONG_PTR)RegionSize, AllocationType, Protect, 0,0,0,0,0);
}

NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        return GetNtFunc<fn_t>("NtWriteVirtualMemory")(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
    }
    auto* e = GetEntry("NtWriteVirtualMemory");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)Buffer, NumberOfBytesToWrite, (ULONG_PTR)NumberOfBytesWritten, 0,0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)Buffer, NumberOfBytesToWrite, (ULONG_PTR)NumberOfBytesWritten, 0,0,0,0,0,0);
}

NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        return GetNtFunc<fn_t>("NtProtectVirtualMemory")(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    }
    auto* e = GetEntry("NtProtectVirtualMemory");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)RegionSize, NewProtect, (ULONG_PTR)OldProtect, 0,0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)RegionSize, NewProtect, (ULONG_PTR)OldProtect, 0,0,0,0,0,0);
}

NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
    PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
        return GetNtFunc<fn_t>("NtCreateThreadEx")(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    }
    auto* e = GetEntry("NtCreateThreadEx");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)ThreadHandle, DesiredAccess, (ULONG_PTR)ObjectAttributes, (ULONG_PTR)ProcessHandle, (ULONG_PTR)StartRoutine, (ULONG_PTR)Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, (ULONG_PTR)AttributeList);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)ThreadHandle, DesiredAccess, (ULONG_PTR)ObjectAttributes, (ULONG_PTR)ProcessHandle, (ULONG_PTR)StartRoutine, (ULONG_PTR)Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, (ULONG_PTR)AttributeList);
}

NTSTATUS NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine,
    PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(HANDLE, PVOID, PVOID, PVOID, PVOID);
        return GetNtFunc<fn_t>("NtQueueApcThread")(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    }
    auto* e = GetEntry("NtQueueApcThread");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)ThreadHandle, (ULONG_PTR)ApcRoutine, (ULONG_PTR)ApcArgument1, (ULONG_PTR)ApcArgument2, (ULONG_PTR)ApcArgument3, 0,0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)ThreadHandle, (ULONG_PTR)ApcRoutine, (ULONG_PTR)ApcArgument1, (ULONG_PTR)ApcArgument2, (ULONG_PTR)ApcArgument3, 0,0,0,0,0,0);
}

NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID ClientId) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
        return GetNtFunc<fn_t>("NtOpenProcess")(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    auto* e = GetEntry("NtOpenProcess");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)ProcessHandle, DesiredAccess, (ULONG_PTR)ObjectAttributes, (ULONG_PTR)ClientId, 0,0,0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)ProcessHandle, DesiredAccess, (ULONG_PTR)ObjectAttributes, (ULONG_PTR)ClientId, 0,0,0,0,0,0,0);
}

NTSTATUS NtClose(HANDLE Handle) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(HANDLE);
        return GetNtFunc<fn_t>("NtClose")(Handle);
    }
    auto* e = GetEntry("NtClose");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)Handle, 0,0,0,0,0,0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)Handle, 0,0,0,0,0,0,0,0,0,0);
}

NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
        return GetNtFunc<fn_t>("NtWaitForSingleObject")(Handle, Alertable, Timeout);
    }
    auto* e = GetEntry("NtWaitForSingleObject");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)Handle, Alertable, (ULONG_PTR)Timeout, 0,0,0,0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)Handle, Alertable, (ULONG_PTR)Timeout, 0,0,0,0,0,0,0,0);
}

NTSTATUS NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(HANDLE, PULONG);
        return GetNtFunc<fn_t>("NtResumeThread")(ThreadHandle, PreviousSuspendCount);
    }
    auto* e = GetEntry("NtResumeThread");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)ThreadHandle, (ULONG_PTR)PreviousSuspendCount, 0,0,0,0,0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)ThreadHandle, (ULONG_PTR)PreviousSuspendCount, 0,0,0,0,0,0,0,0,0);
}

NTSTATUS NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(HANDLE, PULONG);
        return GetNtFunc<fn_t>("NtSuspendThread")(ThreadHandle, PreviousSuspendCount);
    }
    auto* e = GetEntry("NtSuspendThread");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)ThreadHandle, (ULONG_PTR)PreviousSuspendCount, 0,0,0,0,0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)ThreadHandle, (ULONG_PTR)PreviousSuspendCount, 0,0,0,0,0,0,0,0,0);
}

NTSTATUS NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
        return GetNtFunc<fn_t>("NtCreateSection")(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    }
    auto* e = GetEntry("NtCreateSection");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)SectionHandle, DesiredAccess, (ULONG_PTR)ObjectAttributes, (ULONG_PTR)MaximumSize, SectionPageProtection, AllocationAttributes, (ULONG_PTR)FileHandle, 0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)SectionHandle, DesiredAccess, (ULONG_PTR)ObjectAttributes, (ULONG_PTR)MaximumSize, SectionPageProtection, AllocationAttributes, (ULONG_PTR)FileHandle, 0,0,0,0);
}

NTSTATUS NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG InheritDisposition,
    ULONG AllocationType, ULONG Win32Protect) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
        return GetNtFunc<fn_t>("NtMapViewOfSection")(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
    }
    auto* e = GetEntry("NtMapViewOfSection");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)SectionHandle, (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, ZeroBits, CommitSize, (ULONG_PTR)SectionOffset, (ULONG_PTR)ViewSize, InheritDisposition, AllocationType, Win32Protect, 0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)SectionHandle, (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, ZeroBits, CommitSize, (ULONG_PTR)SectionOffset, (ULONG_PTR)ViewSize, InheritDisposition, AllocationType, Win32Protect, 0);
}

NTSTATUS NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(HANDLE, PVOID*, PSIZE_T, ULONG);
        return GetNtFunc<fn_t>("NtFreeVirtualMemory")(ProcessHandle, BaseAddress, RegionSize, FreeType);
    }
    auto* e = GetEntry("NtFreeVirtualMemory");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)RegionSize, FreeType, 0,0,0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)ProcessHandle, (ULONG_PTR)BaseAddress, (ULONG_PTR)RegionSize, FreeType, 0,0,0,0,0,0,0);
}

NTSTATUS NtQuerySystemInformation(ULONG SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(ULONG, PVOID, ULONG, PULONG);
        return GetNtFunc<fn_t>("NtQuerySystemInformation")(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    }
    auto* e = GetEntry("NtQuerySystemInformation");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, SystemInformationClass, (ULONG_PTR)SystemInformation, SystemInformationLength, (ULONG_PTR)ReturnLength, 0,0,0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, SystemInformationClass, (ULONG_PTR)SystemInformation, SystemInformationLength, (ULONG_PTR)ReturnLength, 0,0,0,0,0,0,0);
}

NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength) {
    if (GetMethod() == SyscallMethod::None) {
        typedef NTSTATUS(NTAPI* fn_t)(HANDLE, ULONG, PVOID, ULONG);
        return GetNtFunc<fn_t>("NtSetInformationThread")(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
    }
    auto* e = GetEntry("NtSetInformationThread");
    if (!e || !e->resolved) return (NTSTATUS)0xC0000001;
    if (GetMethod() == SyscallMethod::Direct)
        return DoDirectSyscall(e->ssn, (ULONG_PTR)ThreadHandle, ThreadInformationClass, (ULONG_PTR)ThreadInformation, ThreadInformationLength, 0,0,0,0,0,0,0);
    return DoIndirectSyscall(e->ssn, e->gadget_addr, (ULONG_PTR)ThreadHandle, ThreadInformationClass, (ULONG_PTR)ThreadInformation, ThreadInformationLength, 0,0,0,0,0,0,0);
}

} // namespace syscalls
} // namespace rtlc2

#endif // RTLC2_WINDOWS
