# x86 GAS assembly - Syscall gate for direct and indirect syscalls
# x86 Windows uses int 0x2e or sysenter for syscalls
# Arguments passed on stack (cdecl-like): [ret_addr][ssn][arg1][arg2]...
#
# On x86 Windows, the syscall convention is:
#   EAX = System Service Number (SSN)
#   EDX = pointer to arguments on the user stack
#   Invoke via: int 0x2e (legacy) or sysenter (fast path)
#
# int 0x2e is the traditional method and works on all x86 Windows versions.
.intel_syntax noprefix
# sysenter is faster but requires a specific return mechanism via SYSEXIT,
# which expects return address in EDX -- using it directly is fragile.
# We use int 0x2e for maximum compatibility.

.text

# ============================================================================
# DoDirectSyscall - Direct syscall via int 0x2e
# ============================================================================
# C prototype: NTSTATUS DoDirectSyscall(DWORD ssn, ...);
# Stack layout at entry:
#   [esp+0]  = return address
#   [esp+4]  = SSN (System Service Number)
#   [esp+8]  = arg1
#   [esp+12] = arg2
#   [esp+16] = arg3
#   ...
#
# The int 0x2e handler expects:
#   EAX = SSN
#   EDX = pointer to first argument on the user stack
#

.global _DoDirectSyscall
.global DoDirectSyscall
_DoDirectSyscall:
DoDirectSyscall:
    mov eax, [esp+4]        # eax = System Service Number
    lea edx, [esp+8]        # edx = pointer to first argument
    int 0x2e                 # Windows x86 syscall interrupt
    ret

# ============================================================================
# DoIndirectSyscall - Indirect syscall via gadget in ntdll
# ============================================================================
# C prototype: NTSTATUS DoIndirectSyscall(DWORD ssn, PVOID gadget, ...);
# Stack layout at entry:
#   [esp+0]  = return address
#   [esp+4]  = SSN
#   [esp+8]  = gadget address (points to "int 0x2e; ret" or "sysenter; ret" in ntdll)
#   [esp+12] = arg1
#   [esp+16] = arg2
#   ...
#
# This performs an indirect syscall by jumping to a syscall;ret gadget
# found within ntdll.dll. This makes the syscall appear to originate
# from ntdll's memory space, evading syscall origin checks by EDR.
#

.global _DoIndirectSyscall
.global DoIndirectSyscall
_DoIndirectSyscall:
DoIndirectSyscall:
    mov eax, [esp+4]        # eax = SSN
    mov ecx, [esp+8]        # ecx = gadget address
    lea edx, [esp+12]       # edx = pointer to first argument
    jmp ecx                 # jump to syscall gadget in ntdll
                             # gadget does: int 0x2e; ret (or sysenter;ret)
                             # ret in gadget returns to our caller
