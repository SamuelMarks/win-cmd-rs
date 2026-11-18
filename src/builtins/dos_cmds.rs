//! MS-DOS `COMMAND.COM` internal commands (`TRUENAME`, `CTTY`, `LH`/`LOADHIGH`) and `MEM` utility shim.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use core::fmt::Write as _;

use crate::dos::DosMemoryStats;
use crate::error::CmdError;
use crate::parser::ast::SpannedWord;
use crate::runtime::{CmdIo, FlowControl, Interpreter};
use crate::types::{CRLF, ConsoleRenderBackend, ExitCode};

/// Built-in MS-DOS `TRUENAME [path]` command (`INT 21h AH=60h` canonical path resolver).
///
/// Resolves `.` (current drive and directory) when called without arguments, matching authentic
/// undocumented MS-DOS `COMMAND.COM` `TRUENAME` behavior.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)`.
///
/// # Errors
/// Returns [`CmdError`] if path canonicalization or stream output fails.
pub(super) fn cmd_truename(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let raw_arg = args.first().map_or(".", SpannedWord::unquoted);
    let canonical = if let Some(kernel) = &interp.proc_env.dos_kernel {
        kernel.truename(raw_arg)?
    } else {
        interp
            .proc_env
            .vfs
            .resolve_path(raw_arg)
            .to_windows_string()
    };
    io.write_stdout_str(&format!("{canonical}{CRLF}"))?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in MS-DOS `CTTY <device>` command, validating DOS character devices and updating console mode.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)`.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing diagnostic output fails.
pub(super) fn cmd_ctty(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let dev = args
        .first()
        .map(|w| w.unquoted().trim_end_matches(':').to_ascii_uppercase())
        .unwrap_or_default();
    match dev.as_str() {
        "CON" => {
            interp.console.render_backend = if interp.proc_env.dos_kernel.is_some() {
                ConsoleRenderBackend::BiosVgaAttribute
            } else {
                ConsoleRenderBackend::AnsiSysEscape
            };
            interp.record_success();
        }
        "AUX" | "COM1" | "COM2" | "COM3" | "COM4" | "NUL" => {
            interp.console.render_backend = ConsoleRenderBackend::DumbTeletype;
            interp.record_success();
        }
        _ => {
            io.write_stderr_str(&format!("Invalid device{CRLF}"))?;
            interp.record_exit_code(ExitCode::FAILURE);
        }
    }
    Ok(FlowControl::Continue)
}

/// Built-in MS-DOS `LH` / `LOADHIGH` command (`LH [/L:region1[,minsize1]...] [/S] command [parameters]`).
///
/// Strips MS-DOS UMB `/L:...` and `/S` loader switches and executes the target command transparently
/// under 32-bit protected-mode DPMI.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `raw_tail` - Raw post-command tail.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)`.
///
/// # Errors
/// Propagates [`CmdError`] from the target command when checked execution fails.
pub(super) fn cmd_loadhigh(
    interp: &mut Interpreter,
    raw_tail: &str,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut rest = raw_tail.trim_start();
    while rest.starts_with('/') {
        let token_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let switch = rest.get(..token_end).unwrap_or("");
        let upper = switch.to_ascii_uppercase();
        if upper == "/S" || upper.starts_with("/L:") {
            rest = rest.get(token_end..).unwrap_or("").trim_start();
        } else {
            break;
        }
    }
    if rest.is_empty() {
        interp.record_success();
        return Ok(FlowControl::Continue);
    }
    let _code = interp.execute_interactive_line_checked(rest, io)?;
    Ok(FlowControl::Continue)
}

/// Optional detail sections requested via `MEM` command-line switches.
#[derive(Debug, Default)]
struct MemReportOptions {
    /// `/C` module classification table.
    classify: bool,
    /// `/D` conventional memory segment detail.
    debug_detail: bool,
    /// `/F` free block listing.
    free_detail: bool,
    /// Optional `/M` module name filter.
    module_filter: Option<String>,
}

/// Built-in MS-DOS `MEM` utility shim (`MEM [/C | /CLASSIFY] [/D | /DEBUG] [/F | /FREE] [/M[:name]] [/P]`).
///
/// Queries live [`DosMemoryStats`] when attached to a [`crate::dos::DosKernelApi`], or formats
/// standard 640 KiB + 16 MiB DPMI defaults.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)`.
///
/// # Errors
/// Propagates [`CmdError`] if querying DOS memory or writing `stdout` fails.
pub(super) fn shim_mem(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut opts = MemReportOptions::default();

    for (idx, arg) in args.iter().enumerate() {
        let u = arg.unquoted();
        let upper = u.to_ascii_uppercase();
        match upper.as_str() {
            "/C" | "/CLASSIFY" => opts.classify = true,
            "/D" | "/DEBUG" => opts.debug_detail = true,
            "/F" | "/FREE" => opts.free_detail = true,
            "/P" | "/PAGE" => {}
            "/M" | "/MODULE" => {
                opts.module_filter = Some(
                    args.get(idx.saturating_add(1))
                        .map_or("WINCMD", SpannedWord::unquoted)
                        .to_owned(),
                );
            }
            _ if upper.starts_with("/M:") => {
                opts.module_filter = Some(u.get(3..).unwrap_or("WINCMD").to_owned());
            }
            _ => {}
        }
    }

    let stats = if let Some(kernel) = &interp.proc_env.dos_kernel {
        kernel.memory_stats()?
    } else {
        DosMemoryStats::default()
    };

    let report = format_dos_mem_report(&stats, &opts);
    io.write_stdout_str(&report)?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Formats an MS-DOS 6.22 + DPMI `MEM` summary and optional `/C`, `/D`, `/F`, or `/M` detail lines.
///
/// # Arguments
/// * `stats` - [`DosMemoryStats`].
/// * `opts` - [`MemReportOptions`] flags.
///
/// # Returns
/// Multi-line `CRLF`-delimited `MEM` report.
#[must_use]
fn format_dos_mem_report(stats: &DosMemoryStats, opts: &MemReportOptions) -> String {
    let conv_total_k: u32 = 640;
    let conv_free_k: u32 = stats.conventional_free_bytes / 1024;
    let conv_used_k: u32 = conv_total_k.saturating_sub(conv_free_k);
    let dpmi_free_k: u64 = stats.dpmi_free_physical_bytes / 1024;
    let largest_k: u32 = stats.largest_conventional_block / 1024;

    let mut out = String::new();
    if let Some(mod_name) = opts.module_filter.as_deref() {
        write!(
            out,
            "{mod_name} is using the following memory:{CRLF}  DPMI Protected-Mode Image   {dpmi_free_k}K free{CRLF}{CRLF}"
        )
        .unwrap_or(());
    }
    if opts.classify {
        write!(
            out,
            "Modules using memory below 1 MB:{CRLF}  MSDOS       16K   (16,384 bytes){CRLF}  WINCMD       4K    (4,096 bytes){CRLF}{CRLF}"
        )
        .unwrap_or(());
    }
    if opts.debug_detail {
        write!(
            out,
            "Conventional Memory Detail:{CRLF}  00000h   Interrupt Vector Table & BIOS Data{CRLF}{CRLF}"
        )
        .unwrap_or(());
    }
    if opts.free_detail {
        write!(
            out,
            "Free Conventional Memory:{CRLF}  Largest Free Block: {} bytes ({largest_k}K){CRLF}{CRLF}",
            stats.largest_conventional_block
        )
        .unwrap_or(());
    }
    write!(
        out,
        "Memory Type        Total       Used       Free{CRLF}
         ----------------  --------   --------   --------{CRLF}
         Conventional          {conv_total_k:>3}K       {conv_used_k:>3}K       {conv_free_k:>3}K{CRLF}
         Extended (DPMI)    {dpmi_free_k:>6}K         0K    {dpmi_free_k:>6}K{CRLF}
         {CRLF}
         Largest executable program size       {largest_k:>3}K ({} bytes){CRLF}
         MS-DOS is resident in the high memory area.{CRLF}",
        stats.largest_conventional_block
    )
    .unwrap_or(());
    out
}
