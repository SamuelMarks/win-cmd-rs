//! Console, display, codepage, and history built-in commands (`ECHO`, `CLS`, `COLOR`, `TITLE`,
//! `VER`, `VOL`, `DATE`, `TIME`, `VERIFY`, `CHCP`, `MODE`, `DOSKEY`).
//!
//! Operates against [`Interpreter`]'s [`crate::runtime::ConsoleState`] and [`crate::runtime::SessionConfig`],
//! streaming interactive prompts and output over [`CmdIo`].

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::error::CmdError;
use crate::parser::ast::SpannedWord;
use crate::reader::encoding::decode_script_bytes;
use crate::runtime::{CmdIo, FlowControl, Interpreter};
use crate::types::{
    CR_CHAR, CRLF, CodePage, ConsoleColor, DoskeyEditMode, DriveLetter, ESC_CHAR, EchoState,
    ExitCode, TAB_CHAR, VerifyCopyMode,
};

/// Built-in `ECHO` command (`ECHO`, `ECHO ON`, `ECHO OFF`, `ECHO.message`, `ECHO message`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `echo_delimiter` - Optional delimiter character immediately following `ECHO` (`'.'`, `'('`, `'/'`, etc.).
/// * `raw_tail` - Raw post-command tail.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing to `io` fails.
pub(super) fn cmd_echo(
    interp: &mut Interpreter,
    echo_delimiter: Option<char>,
    raw_tail: &str,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let is_ws_delim = matches!(echo_delimiter, None | Some(' ' | TAB_CHAR));
    if !is_ws_delim {
        io.write_stdout_str(&format!("{raw_tail}{CRLF}"))?;
        interp.mark_cmd_succeeded();
        return Ok(FlowControl::Continue);
    }

    let trimmed_for_state = raw_tail.trim();
    if trimmed_for_state.is_empty() {
        let state_str = match interp.console.echo_state {
            EchoState::On => "on",
            EchoState::Off => "off",
        };
        io.write_stdout_str(&format!("ECHO is {state_str}.{CRLF}"))?;
    } else if trimmed_for_state.eq_ignore_ascii_case("ON") {
        interp.console.echo_state = EchoState::On;
    } else if trimmed_for_state.eq_ignore_ascii_case("OFF") {
        interp.console.echo_state = EchoState::Off;
    } else {
        io.write_stdout_str(&format!("{raw_tail}{CRLF}"))?;
    }

    interp.mark_cmd_succeeded();
    Ok(FlowControl::Continue)
}

/// Built-in `VER` command (`VER [/R]`), displaying the configured Windows or MS-DOS version banner.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words (optional `/R` revision flag on MS-DOS).
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing to `io` fails.
pub(super) fn cmd_ver(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    io.write_stdout_str(&format!("{CRLF}{}{CRLF}", interp.config.version_banner))?;
    if args.iter().any(|w| w.unquoted().eq_ignore_ascii_case("/R")) {
        io.write_stdout_str(&format!(
            "Revision A{CRLF}DOS is in HMA (32-bit DPMI){CRLF}"
        ))?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `VOL` command (`VOL [drive:]`), displaying volume label and serial number.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if `drive` is invalid/unmounted or if writing to `io` fails.
pub(super) fn cmd_vol(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let drive = match args.first() {
        Some(w) => {
            let s = w.unquoted().trim_end_matches(':');
            let ch = s.chars().next().unwrap_or(' ');
            DriveLetter::try_from_char(ch)?
        }
        None => interp.proc_env.vfs.current_drive(),
    };
    let vol = interp.proc_env.vfs.volume_info(drive)?;
    let d_ch = drive.as_char();
    let mut out = String::new();
    if vol.label.is_empty() {
        write!(out, " Volume in drive {d_ch} has no label.{CRLF}").unwrap_or(());
    } else {
        write!(out, " Volume in drive {d_ch} is {}{CRLF}", vol.label).unwrap_or(());
    }
    write!(out, " Volume Serial Number is {}{CRLF}", vol.serial_number).unwrap_or(());
    io.write_stdout_str(&out)?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `CLS` command, clearing via BIOS VGA attributes, ANSI CSI escapes, or plain teletype newline.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing to `io` or clearing the BIOS screen fails.
pub(super) fn cmd_cls(
    interp: &mut Interpreter,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    match interp.console.render_backend {
        crate::types::ConsoleRenderBackend::AnsiSysEscape => {
            io.write_stdout_str(&format!("{ESC_CHAR}[2J{ESC_CHAR}[H"))?;
        }
        crate::types::ConsoleRenderBackend::BiosVgaAttribute => {
            let attr = interp
                .console
                .console_color
                .map_or(0x07, ConsoleColor::to_vga_attribute_byte);
            if let Some(kernel) = &mut interp.proc_env.dos_kernel {
                kernel.clear_console_screen(attr)?;
            }
        }
        crate::types::ConsoleRenderBackend::DumbTeletype => {
            io.write_stdout_str(CRLF)?;
        }
    }
    interp.mark_cmd_succeeded();
    Ok(FlowControl::Continue)
}

/// Built-in `COLOR` command (`COLOR [attr]`), validating distinct foreground/background nibbles.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on valid or empty color attribute.
///
/// # Errors
/// Returns [`CmdError`] (`InvalidColorAttribute` or `IoFailure`) if `attr` is invalid or BIOS clearing fails.
pub(super) fn cmd_color(
    interp: &mut Interpreter,
    args: &[SpannedWord],
) -> Result<FlowControl, CmdError> {
    if let Some(first) = args.first() {
        let color = ConsoleColor::parse_hex(first.unquoted())?;
        interp.console.console_color = Some(color);
    } else {
        interp.console.console_color = None;
    }
    if interp.console.render_backend == crate::types::ConsoleRenderBackend::BiosVgaAttribute
        && let Some(kernel) = &mut interp.proc_env.dos_kernel
    {
        let attr = interp
            .console
            .console_color
            .map_or(0x07, ConsoleColor::to_vga_attribute_byte);
        kernel.clear_console_screen(attr)?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `TITLE` command (`TITLE [string]`), updating `interp.console.console_title`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `raw_tail` - Raw post-command tail.
///
/// # Returns
/// [`FlowControl::Continue`].
pub(super) fn cmd_title(interp: &mut Interpreter, raw_tail: &str) -> FlowControl {
    raw_tail
        .trim_start_matches([' ', TAB_CHAR])
        .clone_into(&mut interp.console.console_title);
    interp.mark_cmd_succeeded();
    FlowControl::Continue
}

/// Built-in `DATE` command (`DATE [/T | date]`), supporting interactive `stdin` prompting.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if writing or reading `io` fails.
pub(super) fn cmd_date(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    if args
        .first()
        .is_some_and(|a| a.unquoted().eq_ignore_ascii_case("/T"))
    {
        io.write_stdout_str(&format!("{}{CRLF}", interp.proc_env.env.virtual_date))?;
    } else if let Some(new_d) = args.first() {
        apply_new_virtual_date(interp, new_d.unquoted())?;
    } else {
        let fmt_hint = match interp.config.locale.date_format {
            crate::types::DateFormatStyle::DayMonthDateYearUs => "(mm-dd-yy)",
            crate::types::DateFormatStyle::Iso8601 => "(yyyy-mm-dd)",
            crate::types::DateFormatStyle::DayMonthYearEuro => "(dd-mm-yy)",
        };
        io.write_stdout_str(&format!(
            "The current date is: {}{CRLF}Enter the new date: {fmt_hint} ",
            interp.proc_env.env.virtual_date
        ))?;
        let line = io.read_stdin_line()?.unwrap_or_default();
        if !line.trim().is_empty() {
            apply_new_virtual_date(interp, line.trim())?;
        }
        io.write_stdout_str(CRLF)?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Updates `virtual_date` and synchronizes [`crate::dos::DosKernelApi::set_current_date`] if `raw` parses as `YYYY-MM-DD` or `MM-DD-YYYY`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`].
/// * `raw` - Date string entered by user.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Propagates [`CmdError`] if an attached DOS kernel rejects the date.
fn apply_new_virtual_date(interp: &mut Interpreter, raw: &str) -> Result<(), CmdError> {
    if let Some(kernel) = &mut interp.proc_env.dos_kernel {
        let mut parts = raw.split(['-', '/']);
        if let (Some(a), Some(b), Some(c)) = (parts.next(), parts.next(), parts.next())
            && parts.next().is_none()
        {
            let parsed_ymd = if a.len() == 4 {
                a.parse::<u16>()
                    .ok()
                    .zip(b.parse::<u8>().ok())
                    .zip(c.parse::<u8>().ok())
            } else {
                c.parse::<u16>()
                    .ok()
                    .zip(a.parse::<u8>().ok())
                    .zip(b.parse::<u8>().ok())
            };
            if let Some(((y, m), d)) = parsed_ymd {
                kernel.set_current_date(y, m, d)?;
            }
        }
    }
    raw.clone_into(&mut interp.proc_env.env.virtual_date);
    Ok(())
}

/// Built-in `TIME` command (`TIME [/T | time]`), supporting interactive `stdin` prompting.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if writing or reading `io` fails.
pub(super) fn cmd_time(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    if args
        .first()
        .is_some_and(|a| a.unquoted().eq_ignore_ascii_case("/T"))
    {
        io.write_stdout_str(&format!("{}{CRLF}", interp.proc_env.env.virtual_time))?;
    } else if let Some(new_t) = args.first() {
        apply_new_virtual_time(interp, new_t.unquoted())?;
    } else {
        io.write_stdout_str(&format!(
            "The current time is: {}{CRLF}Enter the new time: ",
            interp.proc_env.env.virtual_time
        ))?;
        let line = io.read_stdin_line()?.unwrap_or_default();
        if !line.trim().is_empty() {
            apply_new_virtual_time(interp, line.trim())?;
        }
        io.write_stdout_str(CRLF)?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Updates `virtual_time` and synchronizes [`crate::dos::DosKernelApi::set_current_time`] if `raw` parses as `HH:MM[:SS[.CC]]`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`].
/// * `raw` - Time string entered by user.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Propagates [`CmdError`] if an attached DOS kernel rejects the time.
fn apply_new_virtual_time(interp: &mut Interpreter, raw: &str) -> Result<(), CmdError> {
    if let Some(kernel) = &mut interp.proc_env.dos_kernel {
        let (hms, cc_str) = raw.split_once('.').unwrap_or((raw, "0"));
        let mut parts = hms.split(':');
        if let (Some(h_s), Some(m_s)) = (parts.next(), parts.next()) {
            let s_s = parts.next().unwrap_or("0");
            if parts.next().is_none()
                && let (Ok(h), Ok(m), Ok(s), Ok(cc)) = (
                    h_s.parse::<u8>(),
                    m_s.parse::<u8>(),
                    s_s.parse::<u8>(),
                    cc_str.parse::<u8>(),
                )
            {
                kernel.set_current_time(h, m, s, cc)?;
            }
        }
    }
    raw.clone_into(&mut interp.proc_env.env.virtual_time);
    Ok(())
}

/// Built-in `VERIFY` command (`VERIFY [ON | OFF]`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing to `io` fails.
pub(super) fn cmd_verify(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    match args
        .first()
        .map(|a| a.unquoted().to_ascii_uppercase())
        .as_deref()
    {
        None => {
            let s = match interp.config.verify_state {
                VerifyCopyMode::Verified => "on",
                VerifyCopyMode::Unverified => "off",
            };
            io.write_stdout_str(&format!("VERIFY is {s}.{CRLF}"))?;
        }
        Some("ON") => {
            interp.config.verify_state = VerifyCopyMode::Verified;
            if let Some(kernel) = &mut interp.proc_env.dos_kernel {
                kernel.set_verify_flag(VerifyCopyMode::Verified);
            }
        }
        Some("OFF") => {
            interp.config.verify_state = VerifyCopyMode::Unverified;
            if let Some(kernel) = &mut interp.proc_env.dos_kernel {
                kernel.set_verify_flag(VerifyCopyMode::Unverified);
            }
        }
        Some(_) => {
            io.write_stderr_str(&format!("Must specify ON or OFF.{CRLF}"))?;
            interp.record_failure(ExitCode::FAILURE);
            return Ok(FlowControl::Continue);
        }
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `CHCP` command (`CHCP [nnn]`), preserving offending non-numeric tokens via
/// [`CmdError::ParameterFormatNotCorrect`] and unsupported integer IDs via [`CmdError::InvalidCodePage`].
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::ParameterFormatNotCorrect`] on non-numeric tokens, [`CmdError::InvalidCodePage`]
/// on unsupported numeric codepages, or [`CmdError::IoFailure`] on `io` write error.
pub(super) fn cmd_chcp(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    if let Some(first) = args.first() {
        let raw_tok = first.unquoted();
        let id =
            raw_tok
                .parse::<u32>()
                .map_err(|_parse_err| CmdError::ParameterFormatNotCorrect {
                    span: first.span,
                    param: raw_tok.to_owned(),
                })?;
        let cp = CodePage::from_id(id)?;
        if let Some(kernel) = &mut interp.proc_env.dos_kernel {
            kernel.set_active_codepage(cp)?;
        }
        interp.console.codepage = cp;
    } else if let Some(kernel) = &interp.proc_env.dos_kernel {
        interp.console.codepage = kernel.active_codepage()?;
    }
    io.write_stdout_str(&format!(
        "Active code page: {}{CRLF}",
        interp.console.codepage.id()
    ))?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `MODE` utility shim (`MODE [CON[:] [COLS=c] [LINES=n]]`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing status output to `io` fails.
pub(super) fn cmd_mode(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut updated = false;
    let mut numeric_pair: Vec<u16> = Vec::new();
    let mut idx = 0usize;
    while let Some(arg) = args.get(idx) {
        let u = arg.unquoted();
        let upper = u.to_ascii_uppercase();
        if let Some(val) = upper
            .strip_prefix("COLS=")
            .or_else(|| upper.strip_prefix("CO="))
        {
            if let Ok(cols) = val.parse::<u16>() {
                interp.console.console_cols = cols.max(1);
                updated = true;
            }
        } else if (upper == "COLS" || upper == "CO")
            && let Some(next_w) = args.get(idx.saturating_add(1))
            && let Ok(cols) = next_w.unquoted().parse::<u16>()
        {
            interp.console.console_cols = cols.max(1);
            updated = true;
            idx = idx.saturating_add(2);
            continue;
        } else if let Some(val) = upper
            .strip_prefix("LINES=")
            .or_else(|| upper.strip_prefix("LI="))
        {
            if let Ok(lines) = val.parse::<u16>() {
                interp.console.console_lines = lines.max(1);
                updated = true;
            }
        } else if (upper == "LINES" || upper == "LI")
            && let Some(next_w) = args.get(idx.saturating_add(1))
            && let Ok(lines) = next_w.unquoted().parse::<u16>()
        {
            interp.console.console_lines = lines.max(1);
            updated = true;
            idx = idx.saturating_add(2);
            continue;
        } else if !upper.starts_with("CON")
            && let Some((c_str, l_str)) = u.split_once(',')
        {
            if let Ok(c) = c_str.trim().parse::<u16>() {
                interp.console.console_cols = c.max(1);
                updated = true;
            }
            if let Ok(l) = l_str.trim().parse::<u16>() {
                interp.console.console_lines = l.max(1);
                updated = true;
            }
        } else if let Ok(num) = u.parse::<u16>() {
            numeric_pair.push(num.max(1));
        }
        idx = idx.saturating_add(1);
    }
    if let [cols, lines, ..] = numeric_pair.as_slice() {
        interp.console.console_cols = *cols;
        interp.console.console_lines = *lines;
        updated = true;
    }

    if !updated {
        write_mode_status(interp, io)?;
    }

    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Writes the `MODE` `CON:` device status table to `io`.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing to `io` fails.
fn write_mode_status(interp: &Interpreter, io: &mut dyn CmdIo) -> Result<(), CmdError> {
    let status = format!(
        "{CRLF}Status for device CON:{CRLF}\
         ----------------------{CRLF}\
         \x20   Lines:          {}{CRLF}\
         \x20   Columns:        {}{CRLF}\
         \x20   Keyboard rate:  31{CRLF}\
         \x20   Keyboard delay: 1{CRLF}\
         \x20   Code page:      {}{CRLF}{CRLF}",
        interp.console.console_lines,
        interp.console.console_cols,
        interp.console.codepage.id()
    );
    io.write_stdout_str(&status)
}

/// Built-in `DOSKEY` utility (`DOSKEY name=def`, `/HISTORY`, `/MACROS`, `/REINSTALL`, `/LISTSIZE=n`, `/MACROFILE=path`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `raw_tail` - Raw post-command tail.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if `/MACROFILE` cannot be read or decoded, or if writing to `io` fails.
pub(super) fn cmd_doskey(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    raw_tail: &str,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let trimmed = raw_tail.trim();
    if trimmed.is_empty() {
        interp.record_success();
        return Ok(FlowControl::Continue);
    }

    for arg in args {
        let u = arg.unquoted();
        let upper = u.to_ascii_uppercase();
        if upper == "/MACROS" || upper == "/M" || upper.starts_with("/MACROS:") {
            let mut out = String::new();
            for (k, v) in &interp.console.doskey_macros {
                write!(out, "{k}={v}{CRLF}").unwrap_or(());
            }
            io.write_stdout_str(&out)?;
            interp.record_success();
            return Ok(FlowControl::Continue);
        }
        if upper == "/HISTORY" || upper == "/H" {
            let mut out = String::new();
            for h in interp.console.history() {
                write!(out, "{h}{CRLF}").unwrap_or(());
            }
            io.write_stdout_str(&out)?;
            interp.record_success();
            return Ok(FlowControl::Continue);
        }
        if upper == "/REINSTALL" {
            interp.console.clear_history();
            interp.console.doskey_macros.clear();
            interp.record_success();
            return Ok(FlowControl::Continue);
        }
        if upper == "/INSERT" {
            interp.console.doskey_edit_mode = DoskeyEditMode::Insert;
            interp.record_success();
            return Ok(FlowControl::Continue);
        }
        if upper == "/OVERSTRIKE" {
            interp.console.doskey_edit_mode = DoskeyEditMode::Overstrike;
            interp.record_success();
            return Ok(FlowControl::Continue);
        }
        if let Some(sz_str) = upper.strip_prefix("/LISTSIZE=") {
            if let Ok(sz) = sz_str.parse::<usize>() {
                interp.console.set_history_list_size(sz);
            }
            interp.record_success();
            return Ok(FlowControl::Continue);
        }
        if upper.starts_with("/MACROFILE=") {
            let path = u.get("/MACROFILE=".len()..).unwrap_or("").trim_matches('"');
            let bytes = interp.proc_env.vfs.read_bytes(path)?;
            let text = decode_script_bytes(&bytes, interp.console.codepage)?;
            for line in text.lines() {
                let l = line.trim_end_matches(CR_CHAR).trim();
                if let Some((mk, mv)) = l.split_once('=') {
                    apply_doskey_definition(interp, mk, mv);
                }
            }
            interp.record_success();
            return Ok(FlowControl::Continue);
        }
    }

    if let Some((name, def)) = trimmed.split_once('=') {
        apply_doskey_definition(interp, name, def);
    }

    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Inserts or removes (`def` empty) a `DOSKEY` macro definition in `interp.console.doskey_macros`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `raw_name` - Macro name token.
/// * `raw_def` - Macro expansion template (empty removes the macro).
fn apply_doskey_definition(interp: &mut Interpreter, raw_name: &str, raw_def: &str) {
    let key = raw_name.trim().to_owned();
    let val = raw_def.trim();
    if val.is_empty() {
        interp.console.doskey_macros.remove(&key);
    } else {
        interp.console.doskey_macros.insert(key, val.to_owned());
    }
}
