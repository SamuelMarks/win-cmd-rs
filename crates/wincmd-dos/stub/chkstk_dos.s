/* -----------------------------------------------------------------------------
 * crates/wincmd-dos/stub/chkstk_dos.s
 *
 * 32-bit x86 COFF stack-allocation helper (`__alloca` / `___chkstk`) and 1 MiB
 * DPMI stack configuration (`__stklen`) for DJGPP Protected-Mode MS-DOS builds.
 *
 * Input:  %eax = stack frame byte count to allocate.
 * Output: %esp = caller_esp - %eax; %ecx/%edx/%ebx/%esi/%edi/%ebp preserved.
 * ----------------------------------------------------------------------------- */
    .text
    .globl __alloca
    .globl ___chkstk
    .globl ___chkstk_ms
__alloca:
___chkstk:
___chkstk_ms:
    pushl   %ecx
    leal    8(%esp), %ecx
    subl    %eax, %ecx
    xchgl   %ecx, %esp
    movl    (%ecx), %eax
    movl    4(%ecx), %ecx
    pushl   %ecx
    movl    %eax, %ecx
    ret

    .data
    .balign 4
    .globl __stklen
__stklen:
    .long 1048576
