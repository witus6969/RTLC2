# x64 GAS assembly - Syscall gate for direct and indirect syscalls
# Windows x64 calling convention: rcx, rdx, r8, r9, stack
#
# DoDirectSyscall(DWORD ssn, arg1..arg11)
#   - ssn in ecx (1st param)
#   - args shifted: arg1=rdx, arg2=r8, arg3=r9, arg4-11=stack
#
# DoIndirectSyscall(DWORD ssn, PVOID gadget, arg1..arg11)
#   - ssn in ecx, gadget in rdx
#   - args shifted: arg1=r8, arg2=r9, arg3-11=stack

# Use Intel syntax for x64 Windows syscall gates
.intel_syntax noprefix
.text

.global DoDirectSyscall
DoDirectSyscall:
    # rcx = SSN
    # rdx = arg1, r8 = arg2, r9 = arg3
    # [rsp+0x28] = arg4, [rsp+0x30] = arg5, ...

    mov r10, rdx            # r10 = arg1 (Windows syscall: r10 replaces rcx)
    mov eax, ecx            # eax = SSN

    # Shift arguments: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4
    mov rcx, rdx            # arg1
    mov rdx, r8             # arg2
    mov r8, r9              # arg3
    mov r9, [rsp+0x28]      # arg4

    # The syscall expects args 5+ at [rsp+0x28] onwards
    # Our args 5+ are at [rsp+0x30] onwards (offset by the return address + shadow)
    # Since we're about to do syscall (not call), just execute
    syscall
    ret

.global DoIndirectSyscall
DoIndirectSyscall:
    # rcx = SSN
    # rdx = gadget address (points to syscall;ret in ntdll)
    # r8 = arg1, r9 = arg2
    # [rsp+0x28] = arg3, [rsp+0x30] = arg4, ...

    mov r10, r8             # r10 = arg1
    mov eax, ecx            # eax = SSN
    push rdx                # save gadget address

    # Shift arguments
    mov rcx, r8             # arg1
    mov rdx, r9             # arg2
    mov r8, [rsp+0x38]      # arg3 (adjusted for push)
    mov r9, [rsp+0x40]      # arg4

    # Jump to the gadget (syscall;ret inside ntdll)
    # This makes the return address appear to come from ntdll
    pop rax                 # restore gadget address
    # We need to overwrite our return address with the gadget
    # Then the gadget's ret will return to our actual caller
    jmp rax
