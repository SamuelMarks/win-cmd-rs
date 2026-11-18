/* -----------------------------------------------------------------------------
 * crates/wincmd-dos/stub/djgpp-rust.ld
 *
 * Custom GNU ld (`i386go32`) COFF linker script for Rust + DJGPP `libc` builds.
 *
 * DJGPP's `go32stub` COFF loader maps strictly `.text`, `.data`, and `.bss`,
 * placing the protected-mode stack immediately at `_end` (end of `.bss`).
 * Because LLVM COFF codegen emits Rust constants, string literals, and trait
 * vtables into `.rdata` / `.rdata$*` (rather than ELF `.rodata*`), merging
 * `*(.rdata)` and `*(.rdata*)` into `.text` ensures every read-only constant
 * and vtable is loaded in `.text`, while `/DISCARD/` strips LLVM bitcode
 * (`.llvmbc*`) and PE linker directives (`.drectve*`).
 * ----------------------------------------------------------------------------- */
OUTPUT_FORMAT("coff-go32-exe")
ENTRY(start)
SECTIONS
{
  .text 0x1000 + SIZEOF_HEADERS : {
    *(.text)
    *(.text.*)
    *(.text$*)
    *(.gnu.linkonce.t*)
    *(.const*)
    *(.ro*)
    *(.rdata)
    *(.rdata.*)
    *(.rdata$*)
    *(.gnu.linkonce.r*)
    etext = . ; PROVIDE(_etext = .) ;
    . = ALIGN(0x200);
  }
  .data ALIGN(0x200) : {
    djgpp_first_ctor = . ;
    *(SORT(.ctors.*))
    *(.ctor)
    *(.ctors)
    djgpp_last_ctor = . ;
    djgpp_first_dtor = . ;
    *(SORT(.dtors.*))
    *(.dtor)
    *(.dtors)
    djgpp_last_dtor = . ;
    __environ = . ;
    PROVIDE(_environ = .) ;
    LONG(0) ;
    *(.data)
    *(.data.*)
    *(.data$*)
    *(.bss.*)
    *(.gcc_exc*)
    ___EH_FRAME_BEGIN__ = . ;
    *(.eh_fram*)
    ___EH_FRAME_END__ = . ;
    LONG(0);
    *(.gnu.linkonce.d*)
    edata = . ; PROVIDE(_edata = .) ;
    . = ALIGN(0x200);
  }
  .bss SIZEOF(.data) + ADDR(.data) : {
    *(.bss .gnu.linkonce.b.*)
    *(COMMON)
    end = . ; PROVIDE(_end = .) ;
    . = ALIGN(0x200);
  }
  /DISCARD/ : {
    *(gnu.lto_*)
    *(.llvmbc)
    *(.llvmbc*)
    *(.llvmcmd)
    *(.llvmcmd*)
    *(.drectve)
    *(.drectve*)
    *(.pdata*)
    *(.xdata*)
  }
  .stab 0 : { *(.stab) }
  .stabstr 0 : { *(.stabstr) }
  .debug 0 : { *(.debug) }
  .line 0 : { *(.line) }
  .debug_srcinfo 0 : { *(.debug_srcinfo) }
  .debug_sfnames 0 : { *(.debug_sfnames) }
  .debug_aranges 0 : { *(.debug_aranges) }
  .debug_pubnames 0 : { *(.debug_pubnames) }
  .debug_info 0 : { *(.debug_info .gnu.linkonce.wi.*) }
  .debug_abbrev 0 : { *(.debug_abbrev) }
  .debug_line 0 : { *(.debug_line .debug_line.* .debug_line_end) }
  .debug_frame 0 : { *(.debug_frame) }
  .debug_str 0 : { *(.debug_str) }
  .debug_loc 0 : { *(.debug_loc) }
  .debug_macinfo 0 : { *(.debug_macinfo) }
  .debug_weaknames 0 : { *(.debug_weaknames) }
  .debug_funcnames 0 : { *(.debug_funcnames) }
  .debug_typenames 0 : { *(.debug_typenames) }
  .debug_varnames 0 : { *(.debug_varnames) }
  .debug_pubtypes 0 : { *(.debug_pubtypes) }
  .debug_ranges 0 : { *(.debug_ranges) }
  .debug_macro 0 : { *(.debug_macro) }
  .debug_addr 0 : { *(.debug_addr) }
}
