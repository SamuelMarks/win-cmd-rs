//! Interactive Read-Eval-Print Loop (REPL) drivers and stream writing helpers.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::io::{BufRead, Write};

use crate::error::CmdError;
use crate::parser::peg::compute_lossless_paren_balance;
use crate::reader::char_map::LogicalLineBuffer;
use crate::runtime::{
    ByteStreamBufRead, ByteStreamIo, ByteStreamWrite, InMemoryByteReader, Interpreter, IoStreams,
    write_byte_stream_gracefully,
};
use crate::span::{ByteOffset, SourceId};
use crate::types::{
    CR_CHAR, CRLF, CompletionScope, ConsoleColor, ESC_CHAR, EchoState, ExitCode, LF_CHAR,
};

/// Control character `Ctrl+C` (`0x03`, ETX) triggering interactive interrupt cancellation.
const CTRL_C_CHAR: char = '\x03';
/// Control character `Ctrl+D` (`0x04`, EOT) triggering `/F:ON` directory-only completion.
const CTRL_D_COMPLETE_CHAR: char = '\x04';
/// Control character `Ctrl+F` (`0x06`, ACK) triggering `/F:ON` file-and-directory completion.
const CTRL_F_COMPLETE_CHAR: char = '\x06';

/// Computes the net unclosed compound-block parenthesis depth for `pending_buf` using the
/// lexer-aware parser scanner (ignoring `(`, `)` inside `"..."`, `REM`, `::`, `ECHO(`, and `^(`).
///
/// # Arguments
/// * `pending_buf` - Accumulated REPL command buffer.
///
/// # Returns
/// Net parenthesis depth (`> 0` when `More? ` continuation is required).
#[must_use]
pub fn repl_open_paren_depth(pending_buf: &str) -> i32 {
    let spanned = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), pending_buf);
    compute_lossless_paren_balance(&spanned.chars)
}

/// Checks whether `line` ends with an odd number of `^` carets indicating a physical line continuation.
///
/// # Arguments
/// * `line` - Physical REPL line without trailing `CR`/`LF`.
///
/// # Returns
/// `Some(prefix_without_last_caret)` when odd trailing carets exist, or `None`.
#[must_use]
pub fn strip_odd_trailing_caret(line: &str) -> Option<&str> {
    let caret_count = line.chars().rev().take_while(|&c| c == '^').count();
    if caret_count.is_multiple_of(2) {
        None
    } else {
        line.strip_suffix('^')
    }
}

/// Applies `/F:ON` interactive completion control keys (`Ctrl+F` files+dirs, `Ctrl+D` dirs only)
/// embedded in `raw_line` via [`Interpreter::complete_line_at_cursor`].
///
/// Consecutive completion control characters cycle through sorted candidate matches (`0, 1, 2, ...`).
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `line` - Physical input line without trailing `CR`/`LF`.
///
/// # Returns
/// Line after expanding any `Ctrl+F` / `Ctrl+D` completion sequences.
#[must_use]
fn expand_repl_line_completions(interp: &Interpreter, line: &str) -> String {
    if !line.contains([CTRL_F_COMPLETE_CHAR, CTRL_D_COMPLETE_CHAR]) {
        return line.to_owned();
    }
    let chars: Vec<char> = line.chars().collect();
    let mut prefix = String::with_capacity(line.len());
    let mut i = 0usize;
    while let Some(&ch) = chars.get(i) {
        if ch == CTRL_F_COMPLETE_CHAR || ch == CTRL_D_COMPLETE_CHAR {
            let scope = if ch == CTRL_D_COMPLETE_CHAR {
                CompletionScope::DirectoriesOnly
            } else {
                CompletionScope::FilesAndDirectories
            };
            let mut count = 1usize;
            while chars.get(i.saturating_add(count)) == Some(&ch) {
                count = count.saturating_add(1);
            }
            prefix = interp.complete_line_at_cursor(&prefix, scope, count.saturating_sub(1));
            i = i.saturating_add(count);
        } else {
            prefix.push(ch);
            i = i.saturating_add(1);
        }
    }
    prefix
}

/// Synchronizes ANSI SGR terminal colors (`COLOR` / `/T:bf`) to `stdout` whenever
/// `interp.console.console_color` changes.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `last_color` - Previously emitted [`ConsoleColor`] state.
/// * `stdout` - Output stream receiving the ANSI SGR escape sequence.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns [`CmdError`] on non-`BrokenPipe` write failures.
fn sync_console_ansi_color(
    interp: &Interpreter,
    last_color: &mut Option<ConsoleColor>,
    stdout: &mut dyn ByteStreamWrite,
) -> Result<(), CmdError> {
    if interp.console.render_backend != crate::types::ConsoleRenderBackend::AnsiSysEscape {
        *last_color = interp.console.console_color;
        return Ok(());
    }
    if interp.console.console_color != *last_color {
        match interp.console.console_color {
            Some(color) => write_byte_stream_gracefully(stdout, color.to_ansi_sgr().as_bytes())?,
            None => write_byte_stream_gracefully(stdout, format!("{ESC_CHAR}[0m").as_bytes())?,
        }
        *last_color = interp.console.console_color;
    }
    Ok(())
}

/// Runs the interactive Read-Eval-Print Loop (REPL) over `io` using a `#![no_std]` [`InMemoryByteReader`].
///
/// Adapts `io.stdin` to [`run_interactive_repl_byte_streams`] so interactive commands (`SET /P`,
/// `PAUSE`, `CHOICE`, `MORE`, `FIND`, `SORT`) read subsequent `stdin` lines live without pre-draining.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `io` - Mutable [`IoStreams`] providing `stdin` lines and capturing `stdout`/`stderr`.
///
/// # Returns
/// Final [`ExitCode`] of the session.
pub fn run_interactive_repl(interp: &mut Interpreter, io: &mut IoStreams) -> ExitCode {
    let raw_stdin = core::mem::take(&mut io.stdin).into_bytes();
    let mut reader = InMemoryByteReader::new(raw_stdin);
    let mut out_buf = Vec::new();
    let mut err_buf = Vec::new();
    let code = run_interactive_repl_byte_streams(interp, &mut reader, &mut out_buf, &mut err_buf)
        .unwrap_or(ExitCode::FAILURE);
    io.stdout.push_str(&String::from_utf8_lossy(&out_buf));
    io.stderr.push_str(&String::from_utf8_lossy(&err_buf));
    let rem = reader.into_remaining();
    if !rem.is_empty() {
        io.stdin = String::from_utf8_lossy(&rem).into_owned();
    }
    code
}

/// Runs the `#![no_std]`-compatible streaming interactive REPL over [`ByteStreamBufRead`] and [`ByteStreamWrite`].
///
/// Supports:
/// - Live `stdin` handoff to `SET /P`, `PAUSE`, `CHOICE`, `MORE`, `FIND`, and `SORT`
/// - Multi-line `More? ` continuation on trailing `^` and unclosed `(` (flushing/diagnosing pending buffers on EOF)
/// - `/F:ON` completion (`Ctrl+F` / `Ctrl+D`) via [`Interpreter::complete_line_at_cursor`]
/// - `Ctrl+C` (`0x03`) line cancellation via [`Interpreter::trigger_ctrl_c`]
/// - `/T:bf` and `COLOR` ANSI SGR emission via [`ConsoleColor::to_ansi_sgr`]
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `stdin` - Streaming buffered input reader.
/// * `stdout` - Standard output writer.
/// * `stderr` - Standard error writer.
///
/// # Returns
/// `Ok(ExitCode)` when `EXIT` or EOF is reached.
///
/// # Errors
/// Returns [`CmdError`] on non-`BrokenPipe` stream I/O errors.
pub fn run_interactive_repl_byte_streams(
    interp: &mut Interpreter,
    stdin: &mut dyn ByteStreamBufRead,
    stdout: &mut dyn ByteStreamWrite,
    stderr: &mut dyn ByteStreamWrite,
) -> Result<ExitCode, CmdError> {
    let mut last_color: Option<ConsoleColor> = None;
    sync_console_ansi_color(interp, &mut last_color, stdout)?;

    let banner = format!(
        "{}{CRLF}(c) Microsoft Corporation. All rights reserved.{CRLF}{CRLF}",
        interp.config.version_banner
    );
    write_byte_stream_gracefully(stdout, banner.as_bytes())?;

    let mut pending_buf = String::new();
    let mut raw_bytes = Vec::new();

    loop {
        sync_console_ansi_color(interp, &mut last_color, stdout)?;
        if pending_buf.is_empty() {
            if interp.console.echo_state == EchoState::On {
                let prompt = interp.format_prompt();
                write_byte_stream_gracefully(stdout, prompt.as_bytes())?;
            }
        } else {
            write_byte_stream_gracefully(stdout, b"More? ")?;
        }

        raw_bytes.clear();
        let bytes_read = stdin.read_line_bytes(&mut raw_bytes)?;
        if bytes_read == 0 {
            if !pending_buf.is_empty() {
                let trailing_cmd = core::mem::take(&mut pending_buf);
                let mut eof_io = ByteStreamIo::new(
                    stdin,
                    stdout,
                    stderr,
                    interp.console.codepage,
                    interp.config.unicode_output_mode,
                );
                let _eof_code = interp.execute_interactive_line(&trailing_cmd, &mut eof_io);
                eof_io.check_error()?;
            }
            break;
        }

        let raw_line = String::from_utf8_lossy(&raw_bytes);
        if raw_line.contains(CTRL_C_CHAR) {
            interp.trigger_ctrl_c();
            pending_buf.clear();
            let mut ctrl_io = ByteStreamIo::new(
                stdin,
                stdout,
                stderr,
                interp.console.codepage,
                interp.config.unicode_output_mode,
            );
            let _ctrl_flow = interp.handle_ctrl_c_interrupt(&mut ctrl_io);
            ctrl_io.check_error()?;
            write_byte_stream_gracefully(stdout, format!("^C{CRLF}").as_bytes())?;
            continue;
        }

        let trimmed_line = raw_line.trim_end_matches([CR_CHAR, LF_CHAR]);
        let completed = expand_repl_line_completions(interp, trimmed_line);
        let line = completed.as_str();
        if repl_open_paren_depth(&pending_buf) > 0 {
            pending_buf.push(LF_CHAR);
        }

        if let Some(without_caret) = strip_odd_trailing_caret(line) {
            pending_buf.push_str(without_caret);
            continue;
        }

        pending_buf.push_str(line);
        if repl_open_paren_depth(&pending_buf) > 0 {
            continue;
        }

        let full_cmd = core::mem::take(&mut pending_buf);
        let mut live_io = ByteStreamIo::new(
            stdin,
            stdout,
            stderr,
            interp.console.codepage,
            interp.config.unicode_output_mode,
        );
        let _line_code = interp.execute_interactive_line(&full_cmd, &mut live_io);
        live_io.check_error()?;
        sync_console_ansi_color(interp, &mut last_color, stdout)?;

        if let Some(exit_code) = interp.exec.exited() {
            return Ok(exit_code);
        }
    }

    Ok(interp.last_exit_code())
}

/// Runs the unified streaming interactive REPL reading lines on demand from `stdin` (`BufRead`)
/// and flushing prompts, ANSI color updates, and command output to `stdout` and `stderr`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `stdin` - Streaming buffered input reader.
/// * `stdout` - Standard output writer.
/// * `stderr` - Standard error writer.
///
/// # Returns
/// `Ok(ExitCode)` when `EXIT` or EOF is reached.
///
/// # Errors
/// Returns [`CmdError`] on non-`BrokenPipe` stream I/O errors.
#[cfg(feature = "std")]
pub fn run_interactive_repl_streaming(
    interp: &mut Interpreter,
    stdin: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CmdError> {
    let mut sin = crate::runtime::StdBufReadAdapter(stdin);
    let mut sout = crate::runtime::StdWriteAdapter::new(stdout, "write");
    let mut serr = crate::runtime::StdWriteAdapter::new(stderr, "write");
    run_interactive_repl_byte_streams(interp, &mut sin, &mut sout, &mut serr)
}

/// Writes `bytes` to `writer` and flushes, treating `BrokenPipe` as a clean early termination.
///
/// # Arguments
/// * `writer` - Destination output stream.
/// * `bytes` - Byte slice to write.
///
/// # Returns
/// `Ok(())` on success or `BrokenPipe`.
///
/// # Errors
/// Returns [`CmdError`] mapped from any non-`BrokenPipe` [`std::io::Error`].
#[cfg(feature = "std")]
pub fn write_stream_gracefully(writer: &mut dyn Write, bytes: &[u8]) -> Result<(), CmdError> {
    crate::runtime::io::write_and_flush_gracefully(writer, bytes, "write")
}
