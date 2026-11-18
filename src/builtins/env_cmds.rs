//! Environment and association built-in commands (`SET`, `SETLOCAL`, `ENDLOCAL`, `PATH`, `PROMPT`, `ASSOC`, `FTYPE`).
//!
//! Operates against [`Interpreter`]'s encapsulated [`crate::runtime::ProcessEnvironment`]
//! (`env`, `vfs`, and unified `registry_store`) and streams output/prompts over [`CmdIo`].

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::error::CmdError;
use crate::parser::ast::SpannedWord;
use crate::runtime::arithmetic::evaluate_set_a;
use crate::runtime::registry::{RegistryDeleteTarget, RegistryValueType};
use crate::runtime::{CmdIo, FlowControl, Interpreter};
use crate::span::Span;
use crate::types::{
    CRLF, DelayedExpansionMode, ExecutionContext, ExitCode, ExtensionsMode, TAB_CHAR,
};
use crate::vfs::path::WindowsPath;

/// Built-in `SET` command (`SET`, `SET prefix`, `SET var=val`, `SET "var=val"`, `SET /A`, `SET /P`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `raw_tail` - Raw post-command tail string.
/// * `cmd_span` - Source [`Span`] of the `SET` command.
/// * `exec_ctx` - Active [`ExecutionContext`].
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] on `SET /A` arithmetic failure, invalid syntax, `EnvironmentVariableNotDefined`,
/// or `CmdIo` stream failure.
pub(super) fn cmd_set(
    interp: &mut Interpreter,
    raw_tail: &str,
    cmd_span: Span,
    exec_ctx: ExecutionContext,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let trimmed_start = raw_tail.trim_start_matches([' ', TAB_CHAR]);
    if trimmed_start.is_empty() {
        let mut buf = String::new();
        for (k, v) in interp.proc_env.env.list_visible() {
            write!(buf, "{k}={v}{CRLF}").unwrap_or(());
        }
        io.write_stdout_str(&buf)?;
        interp.record_success();
        return Ok(FlowControl::Continue);
    }

    let upper_prefix: String = trimmed_start
        .chars()
        .take(2)
        .collect::<String>()
        .to_ascii_uppercase();
    if upper_prefix == "/A" {
        let expr_raw = trimmed_start.get(2..).unwrap_or("").trim();
        let cwd = interp.current_cwd_string();
        let exit_code = interp.last_exit_code();
        let pending_updates: core::cell::RefCell<Vec<(String, i32)>> =
            core::cell::RefCell::new(Vec::new());
        let val = {
            let env_ref = &interp.proc_env.env;
            evaluate_set_a(
                expr_raw,
                cmd_span,
                |name| {
                    pending_updates
                        .borrow()
                        .iter()
                        .rev()
                        .find(|(k, _)| k.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.to_string())
                        .or_else(|| env_ref.get_with_dynamics(name, &cwd, exit_code))
                },
                |name, new_v| {
                    pending_updates.borrow_mut().push((name.to_owned(), new_v));
                },
            )?
        };
        for (k, v) in pending_updates.into_inner() {
            interp.proc_env.env.set(&k, &v.to_string());
        }
        if exec_ctx == ExecutionContext::InteractiveRepl {
            io.write_stdout_str(&val.to_string())?;
        }
        interp.record_success();
        return Ok(FlowControl::Continue);
    }

    if upper_prefix == "/P" {
        return cmd_set_prompt(interp, trimmed_start.get(2..).unwrap_or(""), cmd_span, io);
    }

    cmd_set_assignment_or_query(interp, trimmed_start, cmd_span, io)
}

/// Handles `SET /P var=[prompt]` interactive prompt flushing and single-line `stdin` reading.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `after_flag` - Substring following `/P`.
/// * `cmd_span` - Source [`Span`] of the `SET` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] if `=` is missing or variable name is empty, or [`CmdError`] on I/O failure.
fn cmd_set_prompt(
    interp: &mut Interpreter,
    after_flag: &str,
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let rest = after_flag.trim_start_matches([' ', TAB_CHAR]);
    let unquoted = crate::parser::modifiers::strip_set_outer_quotes(rest);
    let Some((var_name, prompt_str)) = unquoted.split_once('=') else {
        return Err(CmdError::SyntaxError { span: cmd_span });
    };
    let clean_var = var_name.trim();
    if clean_var.is_empty() {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }
    if !prompt_str.is_empty() {
        io.write_stdout_str(prompt_str)?;
    }
    let Some(line) = io.read_stdin_line()? else {
        interp.record_failure(ExitCode::FAILURE);
        return Ok(FlowControl::Continue);
    };
    if line.is_empty() {
        interp.record_failure(ExitCode::FAILURE);
    } else {
        interp.proc_env.env.set(clean_var, &line);
        interp.record_success();
    }
    Ok(FlowControl::Continue)
}

/// Handles `SET var=val`, `SET "var=val"`, and `SET prefix` queries.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `trimmed_start` - Leading-whitespace-trimmed `SET` tail.
/// * `cmd_span` - Source [`Span`] of the `SET` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] on empty variable name or [`CmdError::EnvironmentVariableNotDefined`]
/// when no variable matches a `SET prefix` query.
fn cmd_set_assignment_or_query(
    interp: &mut Interpreter,
    trimmed_start: &str,
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let effective = crate::parser::modifiers::strip_set_outer_quotes(trimmed_start);

    if let Some((var_name, value)) = effective.split_once('=') {
        let clean_name = var_name.trim_start();
        if clean_name.is_empty() {
            return Err(CmdError::SyntaxError { span: cmd_span });
        }
        interp.proc_env.env.set(clean_name, value);
    } else {
        let prefix = effective.trim();
        let matches = interp.proc_env.env.list_by_prefix(prefix);
        if matches.is_empty() {
            return Err(CmdError::EnvironmentVariableNotDefined {
                name: prefix.to_owned(),
            });
        }
        let mut buf = String::new();
        for (k, v) in matches {
            write!(buf, "{k}={v}{CRLF}").unwrap_or(());
        }
        io.write_stdout_str(&buf)?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `SETLOCAL` command (`EnableDelayedExpansion`, `DisableDelayedExpansion`,
/// `EnableExtensions`, `DisableExtensions`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `SETLOCAL` command.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on success.
///
/// # Errors
/// Returns [`CmdError::ParameterFormatNotCorrect`] on unrecognized option tokens.
pub(super) fn cmd_setlocal(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
) -> Result<FlowControl, CmdError> {
    let mut new_delayed = None;
    let mut new_ext = None;
    for arg in args {
        match arg.unquoted().to_ascii_uppercase().as_str() {
            "ENABLEDELAYEDEXPANSION" => {
                new_delayed = Some(DelayedExpansionMode::Enabled);
            }
            "DISABLEDELAYEDEXPANSION" => {
                new_delayed = Some(DelayedExpansionMode::Disabled);
            }
            "ENABLEEXTENSIONS" => {
                new_ext = Some(ExtensionsMode::Enabled);
            }
            "DISABLEEXTENSIONS" => {
                new_ext = Some(ExtensionsMode::Disabled);
            }
            other => {
                return Err(CmdError::ParameterFormatNotCorrect {
                    span: cmd_span,
                    param: other.to_owned(),
                });
            }
        }
    }

    let drive = interp.proc_env.vfs.current_drive();
    let fallback_root = WindowsPath::root(drive);
    let cwd = interp
        .proc_env
        .vfs
        .drive_cwd(drive)
        .unwrap_or(fallback_root);
    interp.proc_env.env.push_setlocal(drive, cwd);
    if let Some(delayed) = new_delayed {
        interp.proc_env.env.delayed_expansion = delayed;
    }
    if let Some(ext) = new_ext {
        interp.proc_env.env.extensions = ext;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `ENDLOCAL` command, restoring saved environment variables, modes, drive, and CWD.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
///
/// # Returns
/// [`FlowControl::Continue`].
pub(super) fn cmd_endlocal(interp: &mut Interpreter) -> FlowControl {
    if let Some((saved_drive, saved_cwd)) = interp.proc_env.env.pop_endlocal()
        && interp
            .proc_env
            .vfs
            .set_drive_cwd(&saved_cwd)
            .and_then(|()| interp.proc_env.vfs.set_current_drive(saved_drive))
            .is_ok()
    {
        interp.sync_active_host_cwd();
    }
    interp.mark_cmd_succeeded();
    FlowControl::Continue
}

/// Built-in `PATH` command (`PATH`, `PATH ;`, `PATH [=]dirs`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `raw_tail` - Raw post-command tail.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing to `io` fails.
pub(super) fn cmd_path(
    interp: &mut Interpreter,
    raw_tail: &str,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let trimmed = raw_tail.trim();
    if trimmed.is_empty() {
        let p = interp.lookup_var("PATH").unwrap_or_default();
        io.write_stdout_str(&format!("PATH={p}{CRLF}"))?;
    } else if trimmed == ";" {
        interp.proc_env.env.remove("PATH");
    } else {
        let val = trimmed.strip_prefix('=').unwrap_or(trimmed).trim();
        interp.proc_env.env.set("PATH", val);
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `PROMPT` command (`PROMPT [text]`, defaulting to `$P$G`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `raw_tail` - Raw post-command tail.
///
/// # Returns
/// [`FlowControl::Continue`].
pub(super) fn cmd_prompt(interp: &mut Interpreter, raw_tail: &str) -> FlowControl {
    let trimmed = raw_tail.trim_start_matches([' ', TAB_CHAR]);
    if trimmed.is_empty() {
        interp.proc_env.env.set("PROMPT", "$P$G");
    } else {
        interp.proc_env.env.set("PROMPT", trimmed);
    }
    interp.record_success();
    FlowControl::Continue
}

/// Built-in `ASSOC` command backed directly by `interp.proc_env.registry_store` (`HKCR/.ext`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `raw_tail` - Raw post-command tail.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if Registry mutation or `io` writing fails.
pub(super) fn cmd_assoc(
    interp: &mut Interpreter,
    raw_tail: &str,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let trimmed = raw_tail.trim();
    if trimmed.is_empty() {
        let mut buf = String::new();
        for (ext, ftype) in interp.proc_env.registry_store.file_associations() {
            write!(buf, "{ext}={ftype}{CRLF}").unwrap_or(());
        }
        io.write_stdout_str(&buf)?;
    } else if let Some((ext, ftype)) = trimmed.split_once('=') {
        let e = normalize_dot_ext(ext.trim());
        let ft = ftype.trim();
        if ft.is_empty() {
            interp
                .proc_env
                .registry_store
                .delete_entry(&format!("HKCR/{e}"), RegistryDeleteTarget::EntireKey);
        } else {
            interp.proc_env.registry_store.set_value(
                &format!("HKCR/{e}"),
                "",
                RegistryValueType::Sz,
                ft,
            )?;
            io.write_stdout_str(&format!("{e}={ft}{CRLF}"))?;
        }
    } else {
        let q = normalize_dot_ext(trimmed);
        if let Some(ft) = interp.proc_env.registry_store.get_file_association(&q) {
            io.write_stdout_str(&format!("{q}={ft}{CRLF}"))?;
        } else {
            io.write_stderr_str(&format!(
                "File association not found for extension {q}{CRLF}"
            ))?;
            interp.record_failure(ExitCode::FAILURE);
            return Ok(FlowControl::Continue);
        }
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `FTYPE` command backed directly by `interp.proc_env.registry_store` (`HKCR/<ftype>/shell/open/command`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `raw_tail` - Raw post-command tail.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if Registry mutation or `io` writing fails.
pub(super) fn cmd_ftype(
    interp: &mut Interpreter,
    raw_tail: &str,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let trimmed = raw_tail.trim();
    if trimmed.is_empty() {
        let mut buf = String::new();
        for (ft, cmd_str) in interp.proc_env.registry_store.file_types() {
            write!(buf, "{ft}={cmd_str}{CRLF}").unwrap_or(());
        }
        io.write_stdout_str(&buf)?;
    } else if let Some((ft, cmd_str)) = trimmed.split_once('=') {
        let key = ft.trim();
        let val = cmd_str.trim();
        if val.is_empty() {
            interp.proc_env.registry_store.delete_entry(
                &format!("HKCR/{key}/shell/open/command"),
                RegistryDeleteTarget::EntireKey,
            );
        } else {
            interp.proc_env.registry_store.set_value(
                &format!("HKCR/{key}/shell/open/command"),
                "",
                RegistryValueType::ExpandSz,
                val,
            )?;
            io.write_stdout_str(&format!("{key}={val}{CRLF}"))?;
        }
    } else if let Some(cmd_str) = interp.proc_env.registry_store.get_file_type(trimmed) {
        io.write_stdout_str(&format!("{trimmed}={cmd_str}{CRLF}"))?;
    } else {
        io.write_stderr_str(&format!(
            "File type '{trimmed}' not found or no open command associated with it.{CRLF}"
        ))?;
        interp.record_failure(ExitCode::FAILURE);
        return Ok(FlowControl::Continue);
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Ensures an extension token begins with `.` (e.g., `".txt"`).
///
/// # Arguments
/// * `raw_ext` - Raw extension string.
///
/// # Returns
/// Extension string guaranteed to start with `.`.
#[must_use]
fn normalize_dot_ext(raw_ext: &str) -> String {
    if raw_ext.starts_with('.') {
        raw_ext.to_owned()
    } else {
        format!(".{raw_ext}")
    }
}
