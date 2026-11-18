; -----------------------------------------------------------------------------
; crates/wincmd-dos/stub/cpu_guard_stub.asm
;
; 16-bit Real-Mode MS-DOS MZ CPU Guard Stub for WINCMD.EXE and WINCHECK.EXE.
;
; Verifies an 80386 or newer processor BEFORE attempting any 32-bit instruction
; or invoking CWSDPMI.EXE:
;   - On 8086/8088/80186: FLAGS bits 12..15 are hardwired to 1 (0xF000).
;   - On 80286 real mode: FLAGS bits 12..15 are hardwired to 0 (0x0000).
;   - On 80386+ real/V86 mode: FLAGS bits 12..14 can be set and read back.
;
; Assemble flat MZ image with:
;   nasm -f bin crates/wincmd-dos/stub/cpu_guard_stub.asm -o cpu_guard_stub.exe
; -----------------------------------------------------------------------------

BITS 16
ORG 0

mz_header:
    dw 0x5A4D                   ; 00h: e_magic   ("MZ")
    dw (stub_end - mz_header) % 512 ; 02h: e_cblp    (bytes on last 512-byte page)
    dw ((stub_end - mz_header) + 511) / 512 ; 04h: e_cp (512-byte pages)
    dw 0                        ; 06h: e_crlc    (0 relocations)
    dw (code_start - mz_header) / 16 ; 08h: e_cparhdr (header size in 16-byte paragraphs)
    dw 0x0010                   ; 0Ah: e_minalloc (256 bytes stack/BSS)
    dw 0xFFFF                   ; 0Ch: e_maxalloc
    dw 0x0000                   ; 0Eh: e_ss
    dw 0x0100                   ; 10h: e_sp
    dw 0x0000                   ; 12h: e_csum
    dw 0x0000                   ; 14h: e_ip
    dw 0x0000                   ; 16h: e_cs
    dw 0x001C                   ; 18h: e_lfarlc
    dw 0x0000                   ; 1Ah: e_ovno
    times 4 db 0                ; Pad header to 32 bytes (2 paragraphs)

code_start:
    push cs
    pop ds                      ; DS = CS for INT 21h AH=09h message pointer

    ; --- Step 1: Reject 8086 / 8088 / 80186 (bits 12..15 stuck at 1) ---
    pushf
    pop ax
    and ax, 0x0FFF              ; Clear bits 12..15
    push ax
    popf
    pushf
    pop ax
    and ax, 0xF000
    cmp ax, 0xF000
    je not_386_cpu              ; Bits 12..15 stayed 1 -> 8086/80186

    ; --- Step 2: Reject 80286 in real mode (bits 12..15 stuck at 0) ---
    pushf
    pop ax
    or ax, 0x7000               ; Attempt to set IOPL/NT bits 12..14
    push ax
    popf
    pushf
    pop ax
    test ax, 0x7000
    jz not_386_cpu              ; Bits 12..14 stayed 0 -> 80286

    ; --- 80386+ confirmed (DJGPP stubify chains COFF / CWSDPMI payload here) ---
    mov ax, 0x4C00
    int 0x21

not_386_cpu:
    mov dx, msg_need_386 - code_start
    mov ah, 0x09                ; DOS Print $-terminated string
    int 0x21
    mov ax, 0x4C01              ; Terminate with exit code 1
    int 0x21

msg_need_386:
    db "This program requires an 80386 or newer processor.", 13, 10, "$"

ALIGN 16, db 0
stub_end:
