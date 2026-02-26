# ARM64 (AArch64) syscall gate for direct and indirect syscalls
#
# ARM64 syscall convention:
#   x8  = syscall number (SSN)
#   x0-x5 = arguments (up to 6 arguments)
#   svc #0 to invoke the supervisor call (syscall)
#   Return value in x0
#
# ARM64 calling convention (AAPCS64):
#   x0-x7 = function arguments
#   x8    = indirect result location register / syscall number
#   x9-x15 = temporary (caller-saved)
#   x16-x17 = intra-procedure-call temporary (platform use)
#   x19-x28 = callee-saved
#   x29 = frame pointer, x30 = link register (return address)
#
# On ARM64 Windows (WoA), syscalls also use svc #0 with x8 as the SSN.
# On ARM64 Linux, the convention is identical.

.text

# ============================================================================
# DoDirectSyscall - Direct syscall via svc #0
# ============================================================================
# C prototype:
#   NTSTATUS DoDirectSyscall(DWORD ssn, arg1, arg2, arg3, arg4, arg5, arg6);
#
# Input register mapping:
#   x0 = SSN (System Service Number)
#   x1 = arg1
#   x2 = arg2
#   x3 = arg3
#   x4 = arg4
#   x5 = arg5
#   x6 = arg6
#
# We need to shift arguments: SSN -> x8, arg1 -> x0, arg2 -> x1, etc.

.global DoDirectSyscall
DoDirectSyscall:
    mov x8, x0              // x8 = System Service Number
    mov x0, x1              // shift args: x0 = arg1
    mov x1, x2              // x1 = arg2
    mov x2, x3              // x2 = arg3
    mov x3, x4              // x3 = arg4
    mov x4, x5              // x4 = arg5
    mov x5, x6              // x5 = arg6
    svc #0                  // supervisor call (syscall)
    ret                     // return to caller (x30 / LR)

# ============================================================================
# DoIndirectSyscall - Indirect syscall via gadget
# ============================================================================
# C prototype:
#   NTSTATUS DoIndirectSyscall(DWORD ssn, PVOID gadget, arg1, arg2, arg3, arg4, arg5, arg6);
#
# Input register mapping:
#   x0 = SSN
#   x1 = gadget address (points to "svc #0; ret" in ntdll or target library)
#   x2 = arg1
#   x3 = arg2
#   x4 = arg3
#   x5 = arg4
#   x6 = arg5
#   x7 = arg6
#
# This performs an indirect syscall by branching to a svc;ret gadget
# within the target library (ntdll.dll on Windows, libc on Linux).
# On ARM64, the return address is in x30 (LR), so a simple BR to the
# gadget will cause the gadget's RET to return to our caller since
# we haven't modified x30.
#
# We use x16 as the branch target register since it's designated as
# an intra-procedure-call scratch register and won't be preserved.

.global DoIndirectSyscall
DoIndirectSyscall:
    mov x8, x0              // x8 = SSN
    mov x16, x1             // x16 = gadget address (scratch register)
    mov x0, x2              // shift args: x0 = arg1
    mov x1, x3              // x1 = arg2
    mov x2, x4              // x2 = arg3
    mov x3, x5              // x3 = arg4
    mov x4, x6              // x4 = arg5
    mov x5, x7              // x5 = arg6
    br x16                  // branch to gadget (svc #0; ret)
                             // gadget's ret returns to our caller via x30
