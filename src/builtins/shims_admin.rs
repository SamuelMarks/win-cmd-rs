//! Administrative, file-replication, prompt, and Registry utility shims
//! (`XCOPY`, `ROBOCOPY`, `ATTRIB`, `CHOICE`, `TIMEOUT`, `REG`, `HOSTNAME`, `WHOAMI`).
//!
//! Eliminates all silent `.unwrap_or_default()` and ignored-result error erasures so unreadable
//! source files in `XCOPY`/`ROBOCOPY` never overwrite destinations with 0-byte files, validates
//! `CHOICE /C` & `/D` and `TIMEOUT /T <seconds>` strictly, and syncs live `Command Processor`
//! Registry settings on `REG ADD`, `REG DELETE`, and `REG IMPORT`.

use std::fmt::Write as _;

use crate::error::CmdError;
use crate::parser::ast::SpannedWord;
use crate::reader::encoding::decode_script_bytes;
use crate::runtime::registry::{
    RegistryDeleteTarget, RegistryHive, RegistryKeyPath, RegistryValueType,
};
use crate::runtime::{CmdIo, FlowControl, Interpreter};
use crate::span::Span;
use crate::types::{
    AttributeMutation, BS_STR, CRLF, CaseSensitivity, DirCreationDepth, DirRemovalMode, ExitCode,
    OverwritePolicy, PromptConfirmMode, ReadOnlyDeletePolicy, TraversalDepth, VerifyCopyMode,
};
use crate::vfs::glob::{contains_wildcards, matches_win32_glob};
use crate::vfs::path::WindowsPath;
use crate::vfs::{FileAttributeFlags, FileAttributes};

use super::fs_cmds::{confirm_overwrite_if_needed, write_and_verify_bytes};

/// Built-in `HOSTNAME` utility shim.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing to `io` fails.
pub(super) fn shim_hostname(
    interp: &mut Interpreter,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let host = interp
        .lookup_var("COMPUTERNAME")
        .unwrap_or_else(|| "WINCMD-HOST".to_owned());
    io.write_stdout_str(&format!("{host}{CRLF}"))?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `WHOAMI` utility shim.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing to `io` fails.
pub(super) fn shim_whoami(
    interp: &mut Interpreter,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let domain = interp
        .lookup_var("USERDOMAIN")
        .unwrap_or_else(|| "wincmd".to_owned())
        .to_ascii_lowercase();
    let user = interp
        .lookup_var("USERNAME")
        .unwrap_or_else(|| "user".to_owned())
        .to_ascii_lowercase();
    io.write_stdout_str(&format!("{domain}{BS_STR}{user}{CRLF}"))?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Parsed options for `CHOICE`.
struct ChoiceOptions {
    /// Allowed choice characters (default `"YN"`).
    choices: String,
    /// Whether `/N` suppresses `[A,B]? ` display.
    hide_choices: bool,
    /// Whether `/CS` enables case-sensitive choice matching.
    case_sensitive: bool,
    /// Optional `/D` default choice character.
    default_ch: Option<char>,
    /// Optional `/M` prompt message.
    message: Option<String>,
}

/// Parses and validates `CHOICE` switches (`/C`, `/N`, `/CS`, `/T`, `/D`, `/M`).
///
/// # Arguments
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `CHOICE` command.
///
/// # Returns
/// `Ok(ChoiceOptions)` when valid.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] on missing/invalid switch operands or `/D` not in `/C`.
fn parse_choice_options(args: &[SpannedWord], cmd_span: Span) -> Result<ChoiceOptions, CmdError> {
    let mut opts = ChoiceOptions {
        choices: "YN".to_owned(),
        hide_choices: false,
        case_sensitive: false,
        default_ch: None,
        message: None,
    };

    let mut i = 0usize;
    while let Some(arg) = args.get(i) {
        let u = arg.unquoted();
        let upper = u.to_ascii_uppercase();
        if upper == "/N" {
            opts.hide_choices = true;
        } else if upper == "/CS" {
            opts.case_sensitive = true;
        } else if upper == "/C" {
            let Some(next) = args.get(i.saturating_add(1)) else {
                return Err(CmdError::SyntaxError { span: cmd_span });
            };
            let val = next.unquoted();
            if val.is_empty() || val.starts_with('/') {
                return Err(CmdError::SyntaxError { span: cmd_span });
            }
            val.clone_into(&mut opts.choices);
            i = i.saturating_add(2);
            continue;
        } else if upper.starts_with("/C") {
            let val = u.get(2..).unwrap_or("").trim_start_matches(':');
            if val.is_empty() {
                return Err(CmdError::SyntaxError { span: cmd_span });
            }
            val.clone_into(&mut opts.choices);
        } else if upper == "/D" {
            let Some(next) = args.get(i.saturating_add(1)) else {
                return Err(CmdError::SyntaxError { span: cmd_span });
            };
            let val = next.unquoted();
            if val.chars().count() != 1 || val.starts_with('/') {
                return Err(CmdError::SyntaxError { span: cmd_span });
            }
            opts.default_ch = val.chars().next();
            i = i.saturating_add(2);
            continue;
        } else if upper.starts_with("/D") {
            let val = u.get(2..).unwrap_or("").trim_start_matches(':');
            if val.chars().count() != 1 {
                return Err(CmdError::SyntaxError { span: cmd_span });
            }
            opts.default_ch = val.chars().next();
        } else if upper == "/T" {
            let Some(next) = args.get(i.saturating_add(1)) else {
                return Err(CmdError::SyntaxError { span: cmd_span });
            };
            if next.unquoted().parse::<u32>().is_err() {
                return Err(CmdError::SyntaxError { span: cmd_span });
            }
            i = i.saturating_add(2);
            continue;
        } else if upper == "/M" {
            let Some(next) = args.get(i.saturating_add(1)) else {
                return Err(CmdError::SyntaxError { span: cmd_span });
            };
            opts.message = Some(next.unquoted().to_owned());
            i = i.saturating_add(2);
            continue;
        } else {
            return Err(CmdError::SyntaxError { span: cmd_span });
        }
        i = i.saturating_add(1);
    }

    if let Some(def_c) = opts.default_ch {
        let valid_def = opts.choices.chars().any(|c| {
            if opts.case_sensitive {
                c == def_c
            } else {
                c.eq_ignore_ascii_case(&def_c)
            }
        });
        if !valid_def {
            return Err(CmdError::SyntaxError { span: cmd_span });
        }
    }
    Ok(opts)
}

/// Built-in `CHOICE` utility shim (`CHOICE [/C choices] [/N] [/CS] [/T timeout /D choice] [/M text]`).
///
/// Strictly validates `/C` and `/D` operands instead of falling back to `"/C"` or `'/'`!
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `CHOICE` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` with 1-based `ERRORLEVEL` matching the chosen character.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] on missing/empty `/C`, `/D`, `/T`, or `/M` arguments or when
/// `/D` is not in `/C`, or [`CmdError`] on stream I/O failure.
pub(super) fn shim_choice(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let opts = parse_choice_options(args, cmd_span)?;

    let mut prompt = String::new();
    if let Some(msg) = &opts.message {
        prompt.push_str(msg);
        if !opts.hide_choices {
            prompt.push(' ');
        }
    }
    if !opts.hide_choices {
        let disp_choices: Vec<String> = opts
            .choices
            .chars()
            .map(|c| {
                if opts.case_sensitive {
                    c.to_string()
                } else {
                    c.to_ascii_uppercase().to_string()
                }
            })
            .collect();
        write!(prompt, "[{}]? ", disp_choices.join(",")).unwrap_or(());
    }
    if !prompt.is_empty() {
        io.write_stdout_str(&prompt)?;
    }

    let input_line = io.read_stdin_line()?.unwrap_or_default();
    let chosen_opt = input_line.trim().chars().next().or(opts.default_ch);
    if let Some(ch) = chosen_opt {
        for (idx, valid_ch) in opts.choices.chars().enumerate() {
            let matched = if opts.case_sensitive {
                ch == valid_ch
            } else {
                ch.eq_ignore_ascii_case(&valid_ch)
            };
            if matched {
                io.write_stdout_str(&format!("{ch}{CRLF}"))?;
                let code_i32 = i32::try_from(idx.saturating_add(1)).unwrap_or(1);
                interp.record_exit_code(ExitCode::new(code_i32));
                return Ok(FlowControl::Continue);
            }
        }
    }

    interp.record_failure(ExitCode::new(255));
    Ok(FlowControl::Continue)
}

/// Built-in `TIMEOUT` utility shim (`TIMEOUT [/T] timeout [/NOBREAK]`).
///
/// Validates numeric range `-1..=99999` and rejects unknown flags with [`CmdError::SyntaxError`]!
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `TIMEOUT` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] on missing, out-of-range (`-1..=99999`), or unrecognized
/// flags, or [`CmdError::IoFailure`] on output error.
pub(super) fn shim_timeout(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut seconds_opt: Option<i32> = None;
    let mut nobreak = false;
    let mut i = 0usize;

    while let Some(arg) = args.get(i) {
        let u = arg.unquoted();
        let upper = u.to_ascii_uppercase();
        if upper == "/NOBREAK" {
            nobreak = true;
        } else if upper == "/T" {
            let Some(next) = args.get(i.saturating_add(1)) else {
                return Err(CmdError::SyntaxError { span: cmd_span });
            };
            if seconds_opt.is_some() {
                return Err(CmdError::SyntaxError { span: cmd_span });
            }
            let Ok(secs) = next.unquoted().parse::<i32>() else {
                return Err(CmdError::SyntaxError { span: cmd_span });
            };
            seconds_opt = Some(secs);
            i = i.saturating_add(2);
            continue;
        } else if let Some(val_s) = upper.strip_prefix("/T:") {
            if seconds_opt.is_some() {
                return Err(CmdError::SyntaxError { span: cmd_span });
            }
            let Ok(secs) = val_s.parse::<i32>() else {
                return Err(CmdError::SyntaxError { span: cmd_span });
            };
            seconds_opt = Some(secs);
        } else if !u.starts_with('/') && seconds_opt.is_none() {
            let Ok(secs) = u.parse::<i32>() else {
                return Err(CmdError::SyntaxError { span: cmd_span });
            };
            seconds_opt = Some(secs);
        } else {
            return Err(CmdError::SyntaxError { span: cmd_span });
        }
        i = i.saturating_add(1);
    }

    let Some(secs) = seconds_opt else {
        return Err(CmdError::SyntaxError { span: cmd_span });
    };
    if !(-1..=99_999).contains(&secs) {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }

    let key_msg = if nobreak {
        "press CTRL+C to quit ..."
    } else {
        "press a key to continue ..."
    };
    if secs == -1 {
        io.write_stdout_str(&format!("{CRLF}Waiting indefinitely, {key_msg}{CRLF}"))?;
    } else {
        io.write_stdout_str(&format!(
            "{CRLF}Waiting for {secs} seconds, {key_msg}{CRLF}"
        ))?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `ATTRIB` utility shim (`[+R | -R] [+A | -A] [+S | -S] [+H | -H] [path] [/S] [/D]`).
///
/// Propagates `set_attributes` errors to `stderr` and sets non-zero exit status when failing!
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
pub(super) fn shim_attrib(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut set_r: Option<bool> = None;
    let mut set_h: Option<bool> = None;
    let mut set_s: Option<bool> = None;
    let mut set_a: Option<bool> = None;
    let mut recursive = false;
    let mut include_dirs = false;
    let mut target_opt: Option<&str> = None;

    for arg in args {
        let u = arg.unquoted();
        match u.to_ascii_uppercase().as_str() {
            "+R" => set_r = Some(true),
            "-R" => set_r = Some(false),
            "+H" => set_h = Some(true),
            "-H" => set_h = Some(false),
            "+S" => set_s = Some(true),
            "-S" => set_s = Some(false),
            "+A" => set_a = Some(true),
            "-A" => set_a = Some(false),
            "/S" => recursive = true,
            "/D" => include_dirs = true,
            _ if u.starts_with('/') => {}
            _ => target_opt = Some(u),
        }
    }

    let is_query = set_r.is_none() && set_h.is_none() && set_s.is_none() && set_a.is_none();
    let target = target_opt.unwrap_or("*");
    let resolved = interp.proc_env.vfs.resolve_path(target);
    let (base_dir, pat) = if contains_wildcards(target) {
        (resolved.parent(), resolved.file_name().unwrap_or("*"))
    } else if interp
        .proc_env
        .vfs
        .stat(&resolved.to_windows_string())
        .is_ok_and(|m| m.attributes.is_directory())
        && is_query
    {
        (resolved, "*")
    } else {
        (resolved.parent(), resolved.file_name().unwrap_or("*"))
    };

    let dirs = if recursive {
        collect_admin_dirs(interp, &base_dir)
    } else {
        vec![base_dir]
    };

    let mut matched_any = false;
    let mut out = String::new();

    for d in dirs {
        let Ok(entries) = interp.proc_env.vfs.read_dir(&d.to_windows_string()) else {
            continue;
        };
        for entry in entries {
            if entry.attributes.is_directory() && !include_dirs && !is_query {
                continue;
            }
            if !matches_win32_glob(
                pat,
                &entry.name,
                Some(&entry.short_name),
                CaseSensitivity::Insensitive,
            ) {
                continue;
            }
            matched_any = true;
            let full_s = entry.full_path.to_windows_string();
            if is_query {
                format_attrib_line(entry.attributes, &full_s, &mut out);
            } else {
                let mut new_attrs: FileAttributes = entry.attributes;
                for &(opt_val, flag) in &[
                    (set_r, FileAttributeFlags::READ_ONLY),
                    (set_h, FileAttributeFlags::HIDDEN),
                    (set_s, FileAttributeFlags::SYSTEM),
                    (set_a, FileAttributeFlags::ARCHIVE),
                ] {
                    if let Some(v) = opt_val {
                        new_attrs.set_flag(
                            flag,
                            if v {
                                AttributeMutation::Set
                            } else {
                                AttributeMutation::Clear
                            },
                        );
                    }
                }
                interp.proc_env.vfs.set_attributes(&full_s, new_attrs)?;
            }
        }
    }

    if !out.is_empty() {
        io.write_stdout_str(&out)?;
    }
    if matched_any {
        interp.record_success();
    } else {
        io.write_stdout_str(&format!("File not found - {pat}{CRLF}"))?;
        interp.record_failure(ExitCode::FAILURE);
    }
    Ok(FlowControl::Continue)
}

/// Appends a single `ATTRIB` query output line for `(attrs, full_s)` into `out`.
///
/// # Arguments
/// * `attrs` - [`FileAttributes`] of the entry.
/// * `full_s` - Full Windows path string.
/// * `out` - Destination output buffer.
fn format_attrib_line(attrs: FileAttributes, full_s: &str, out: &mut String) {
    let a_ch = if attrs.is_archive() { 'A' } else { ' ' };
    let s_ch = if attrs.is_system() { 'S' } else { ' ' };
    let h_ch = if attrs.is_hidden() { 'H' } else { ' ' };
    let r_ch = if attrs.is_read_only() { 'R' } else { ' ' };
    write!(out, "{a_ch}  {s_ch}{h_ch}{r_ch}       {full_s}{CRLF}").unwrap_or(());
}

/// Recursively collects directory paths under `root`.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `root` - Starting [`WindowsPath`].
///
/// # Returns
/// Vector of visited directory paths.
fn collect_admin_dirs(interp: &Interpreter, root: &WindowsPath) -> Vec<WindowsPath> {
    let mut out = vec![root.clone()];
    for e in interp
        .proc_env
        .vfs
        .read_dir(&root.to_windows_string())
        .unwrap_or_default()
    {
        if e.attributes.is_directory() {
            out.extend(collect_admin_dirs(interp, &e.full_path));
        }
    }
    out
}

/// Bitmask flags controlling `XCOPY` traversal and output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct XcopyFlags(
    /// Packed `XCOPY` switch bitmask.
    u8,
);

impl XcopyFlags {
    /// `/S` or `/E` copy subdirectories.
    const RECURSIVE: Self = Self(1 << 0);
    /// `/E` copy empty subdirectories too.
    const INCLUDE_EMPTY: Self = Self(1 << 1);
    /// `/I` assume destination is a directory.
    const ASSUME_DIR: Self = Self(1 << 2);
    /// `/Q` quiet (do not display copied filenames).
    const QUIET: Self = Self(1 << 3);
    /// `/T` create directory structure only without copying files.
    const TREE_ONLY: Self = Self(1 << 4);

    /// Checks whether all bits in `other` are set.
    ///
    /// # Arguments
    /// * `other` - Flag mask to test.
    ///
    /// # Returns
    /// `true` if set.
    #[must_use]
    const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Inserts all bits in `other`.
    ///
    /// # Arguments
    /// * `other` - Flag mask to set.
    const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// Strongly typed options for `XCOPY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct XcopyOptions {
    /// Traversal and display bitmask flags (`/S`, `/E`, `/I`, `/Q`, `/T`).
    flags: XcopyFlags,
    /// `/Y`, `/-Y`, or `%COPYCMD%` destination overwrite policy.
    overwrite_policy: OverwritePolicy,
    /// `/V` or `VERIFY ON` post-write byte verification mode.
    verify_mode: VerifyCopyMode,
    /// `/P` per-file `(Y/N)` confirmation prompt mode.
    prompt_mode: PromptConfirmMode,
}

/// Prompts `"{src_display} (Y/N)? "` when `prompt_mode` is [`PromptConfirmMode::PromptEach`].
///
/// # Arguments
/// * `src_display` - Source path shown in the prompt.
/// * `prompt_mode` - Active [`PromptConfirmMode`].
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(true)` if copying should proceed, `Ok(false)` if declined.
///
/// # Errors
/// Returns [`CmdError`] if writing to or reading from `io` fails.
fn confirm_xcopy_source_if_needed(
    src_display: &str,
    prompt_mode: PromptConfirmMode,
    io: &mut dyn CmdIo,
) -> Result<bool, CmdError> {
    if prompt_mode == PromptConfirmMode::PromptEach {
        io.write_stdout_str(&format!("{src_display} (Y/N)? "))?;
        let ans = io.read_stdin_line()?.unwrap_or_default();
        return Ok(ans.trim().to_ascii_uppercase().starts_with('Y'));
    }
    Ok(true)
}

/// Parses `XCOPY` arguments into [`XcopyOptions`] and positional `(source, dest)` slices.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session (for `%COPYCMD%` and `VERIFY` defaults).
/// * `args` - Parsed argument words passed to `XCOPY`.
///
/// # Returns
/// `(XcopyOptions, positional_paths)`.
#[must_use]
fn parse_xcopy_args<'a>(
    interp: &Interpreter,
    args: &'a [SpannedWord],
) -> (XcopyOptions, Vec<&'a str>) {
    let mut opts = XcopyOptions {
        flags: XcopyFlags::default(),
        overwrite_policy: OverwritePolicy::from_copycmd_env(
            interp.lookup_var("COPYCMD").as_deref(),
        ),
        verify_mode: interp.config.verify_state,
        prompt_mode: PromptConfirmMode::Silent,
    };
    let mut positional: Vec<&'a str> = Vec::new();

    for arg in args {
        let u = arg.unquoted();
        match u.to_ascii_uppercase().as_str() {
            "/S" => opts.flags.insert(XcopyFlags::RECURSIVE),
            "/E" => {
                opts.flags.insert(XcopyFlags::RECURSIVE);
                opts.flags.insert(XcopyFlags::INCLUDE_EMPTY);
            }
            "/I" => opts.flags.insert(XcopyFlags::ASSUME_DIR),
            "/Q" => opts.flags.insert(XcopyFlags::QUIET),
            "/T" => opts.flags.insert(XcopyFlags::TREE_ONLY),
            "/Y" => opts.overwrite_policy = OverwritePolicy::AlwaysOverwrite,
            "/-Y" => opts.overwrite_policy = OverwritePolicy::Prompt,
            "/V" => opts.verify_mode = VerifyCopyMode::Verified,
            "/P" => opts.prompt_mode = PromptConfirmMode::PromptEach,
            _ if u.starts_with('/') => {}
            _ => positional.push(u),
        }
    }
    (opts, positional)
}

/// Built-in `XCOPY` utility shim (`/S`, `/E`, `/I`, `/Y`, `/-Y`, `/P`, `/V`, `/Q`, `/F`, `/T`, `/C`, `/D`).
///
/// Propagates VFS read/write errors cleanly so unreadable source files NEVER overwrite
/// destinations with 0-byte empty buffers!
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
pub(super) fn shim_xcopy(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let (mut opts, positional) = parse_xcopy_args(interp, args);

    let Some(&src_raw) = positional.first() else {
        io.write_stderr_str(&format!("Invalid number of parameters{CRLF}"))?;
        interp.record_failure(ExitCode::new(4));
        return Ok(FlowControl::Continue);
    };
    let dst_raw = positional.get(1).copied().unwrap_or(".");

    let src_p = interp.proc_env.vfs.resolve_path(src_raw);
    let dst_p = interp.proc_env.vfs.resolve_path(dst_raw);

    let src_is_dir = interp
        .proc_env
        .vfs
        .stat(&src_p.to_windows_string())
        .is_ok_and(|m| m.attributes.is_directory());

    if src_is_dir && opts.flags.contains(XcopyFlags::RECURSIVE) && is_strict_subpath(&dst_p, &src_p)
    {
        let err = CmdError::CyclicCopy {
            path: src_raw.to_owned(),
        };
        io.write_stderr_str(&format!("{}{CRLF}", err.cmd_exe_message()))?;
        interp.record_failure(err.exit_code());
        return Ok(FlowControl::Continue);
    }

    let mut copied = 0usize;
    if src_is_dir {
        if let Err(err) = xcopy_dir_recursive(interp, &src_p, &dst_p, &mut opts, &mut copied, io) {
            io.write_stderr_str(&format!("{}{CRLF}", err.cmd_exe_message()))?;
            interp.record_failure(ExitCode::new(4));
            return Ok(FlowControl::Continue);
        }
    } else if interp.proc_env.vfs.exists(src_raw) {
        if opts.flags.contains(XcopyFlags::ASSUME_DIR)
            && let Err(err) = interp
                .proc_env
                .vfs
                .create_dir(&dst_p.to_windows_string(), DirCreationDepth::CreateParents)
        {
            io.write_stderr_str(&format!("{}{CRLF}", err.cmd_exe_message()))?;
            interp.record_failure(ExitCode::new(4));
            return Ok(FlowControl::Continue);
        }
        let final_dst = if interp
            .proc_env
            .vfs
            .stat(&dst_p.to_windows_string())
            .is_ok_and(|m| m.attributes.is_directory())
        {
            dst_p
                .join_component(src_p.file_name().unwrap_or(""))
                .to_windows_string()
        } else {
            dst_p.to_windows_string()
        };
        let src_win = src_p.to_windows_string();
        if !opts.flags.contains(XcopyFlags::TREE_ONLY)
            && confirm_xcopy_source_if_needed(&src_win, opts.prompt_mode, io)?
            && confirm_overwrite_if_needed(interp, &final_dst, &mut opts.overwrite_policy, io)?
        {
            match interp.proc_env.vfs.read_bytes(src_raw).and_then(|bytes| {
                write_and_verify_bytes(interp, &final_dst, &bytes, opts.verify_mode, io)
            }) {
                Ok(()) => {
                    copied = 1;
                    if !opts.flags.contains(XcopyFlags::QUIET) {
                        io.write_stdout_str(&format!("{src_win}{CRLF}"))?;
                    }
                }
                Err(err) => {
                    io.write_stderr_str(&format!("{}{CRLF}", err.cmd_exe_message()))?;
                    interp.record_failure(ExitCode::new(4));
                    return Ok(FlowControl::Continue);
                }
            }
        }
    } else {
        io.write_stderr_str(&format!("File not found - {src_raw}{CRLF}"))?;
        interp.record_failure(ExitCode::new(4));
        return Ok(FlowControl::Continue);
    }

    io.write_stdout_str(&format!("{copied} File(s) copied{CRLF}"))?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Recursively copies files and subdirectories for `XCOPY`, propagating VFS errors via `?`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `src_dir` - Source [`WindowsPath`].
/// * `dst_dir` - Destination [`WindowsPath`].
/// * `opts` - Mutable [`XcopyOptions`] (`All` overwrite answer updates `overwrite_policy`).
/// * `copied` - Mutable counter of copied files.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns [`CmdError`] if reading source entries/files or writing destination directories/files fails.
fn xcopy_dir_recursive(
    interp: &mut Interpreter,
    src_dir: &WindowsPath,
    dst_dir: &WindowsPath,
    opts: &mut XcopyOptions,
    copied: &mut usize,
    io: &mut dyn CmdIo,
) -> Result<(), CmdError> {
    let entries = interp.proc_env.vfs.read_dir(&src_dir.to_windows_string())?;
    let has_files = entries.iter().any(|e| !e.attributes.is_directory());
    if has_files || opts.flags.contains(XcopyFlags::INCLUDE_EMPTY) {
        let dst_s = dst_dir.to_windows_string();
        if !interp.proc_env.vfs.exists(&dst_s) {
            interp
                .proc_env
                .vfs
                .create_dir(&dst_s, DirCreationDepth::CreateParents)?;
        }
    }
    for entry in entries {
        if entry.attributes.is_directory() {
            if opts.flags.contains(XcopyFlags::RECURSIVE) {
                let sub_dst = dst_dir.join_component(&entry.name);
                xcopy_dir_recursive(interp, &entry.full_path, &sub_dst, opts, copied, io)?;
            }
        } else if !opts.flags.contains(XcopyFlags::TREE_ONLY) {
            let src_s = entry.full_path.to_windows_string();
            let dst_file = dst_dir.join_component(&entry.name).to_windows_string();
            if !confirm_xcopy_source_if_needed(&src_s, opts.prompt_mode, io)?
                || !confirm_overwrite_if_needed(interp, &dst_file, &mut opts.overwrite_policy, io)?
            {
                continue;
            }
            let data = interp.proc_env.vfs.read_bytes(&src_s)?;
            write_and_verify_bytes(interp, &dst_file, &data, opts.verify_mode, io)?;
            *copied = copied.saturating_add(1);
            if !opts.flags.contains(XcopyFlags::QUIET) {
                io.write_stdout_str(&format!("{src_s}{CRLF}"))?;
            }
        }
    }
    Ok(())
}

/// Bitmask flags for `ROBOCOPY` (`/S`, `/E`, `/PURGE`, `/MIR`, `/MOV`, `/MOVE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct RobocopyFlags(
    /// Packed `ROBOCOPY` switch bitmask.
    u8,
);

impl RobocopyFlags {
    /// `/S` or `/E` recurse into subdirectories.
    const RECURSIVE: Self = Self(1 << 0);
    /// `/E` or `/MIR` include empty subdirectories.
    const INCLUDE_EMPTY: Self = Self(1 << 1);
    /// `/PURGE` or `/MIR` delete destination entries absent in source.
    const PURGE: Self = Self(1 << 2);
    /// `/MOV` or `/MOVE` delete source files after copying.
    const MOVE_FILES: Self = Self(1 << 3);

    /// Checks whether all bits in `other` are set.
    ///
    /// # Arguments
    /// * `other` - Flag mask to test.
    ///
    /// # Returns
    /// `true` if set.
    #[must_use]
    const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Inserts all bits in `other`.
    ///
    /// # Arguments
    /// * `other` - Flag mask to set.
    const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// Built-in `ROBOCOPY` utility shim (`/S`, `/E`, `/MIR`, `/PURGE`, `/MOV`, `/MOVE`).
///
/// Propagates VFS read/write errors into `ROBOCOPY` failure bit `8` instead of overwriting
/// destination files with empty buffers!
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
pub(super) fn shim_robocopy(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut flags = RobocopyFlags::default();
    let mut positional: Vec<&str> = Vec::new();

    for arg in args {
        let u = arg.unquoted();
        match u.to_ascii_uppercase().as_str() {
            "/S" => flags.insert(RobocopyFlags::RECURSIVE),
            "/E" => {
                flags.insert(RobocopyFlags::RECURSIVE);
                flags.insert(RobocopyFlags::INCLUDE_EMPTY);
            }
            "/MIR" => {
                flags.insert(RobocopyFlags::RECURSIVE);
                flags.insert(RobocopyFlags::INCLUDE_EMPTY);
                flags.insert(RobocopyFlags::PURGE);
            }
            "/PURGE" => flags.insert(RobocopyFlags::PURGE),
            "/MOV" | "/MOVE" => flags.insert(RobocopyFlags::MOVE_FILES),
            _ if u.starts_with('/') => {}
            _ => positional.push(u),
        }
    }

    if positional.len() < 2 {
        io.write_stderr_str(&format!(
            "ERROR : Invalid Parameter / Missing Source or Destination.{CRLF}"
        ))?;
        interp.record_failure(ExitCode::new(16));
        return Ok(FlowControl::Continue);
    }

    let src_raw = positional.first().copied().unwrap_or(".");
    let dst_raw = positional.get(1).copied().unwrap_or(".");
    let file_masks: Vec<&str> = if positional.len() > 2 {
        positional.get(2..).unwrap_or(&[]).to_vec()
    } else {
        vec!["*"]
    };

    let src_p = interp.proc_env.vfs.resolve_path(src_raw);
    let dst_p = interp.proc_env.vfs.resolve_path(dst_raw);
    if !interp.proc_env.vfs.exists(&src_p.to_windows_string()) {
        io.write_stderr_str(&format!(
            "ERROR 2 (0x00000002) Accessing Source Directory {}{CRLF}",
            src_p.to_windows_string()
        ))?;
        interp.record_failure(ExitCode::new(16));
        return Ok(FlowControl::Continue);
    }
    if flags.contains(RobocopyFlags::RECURSIVE) && is_strict_subpath(&dst_p, &src_p) {
        let err = CmdError::CyclicCopy {
            path: src_raw.to_owned(),
        };
        io.write_stderr_str(&format!("{}{CRLF}", err.cmd_exe_message()))?;
        interp.record_failure(ExitCode::new(16));
        return Ok(FlowControl::Continue);
    }

    let mut status_bits: i32 = 0;
    robocopy_sync_dir(
        interp,
        &src_p,
        &dst_p,
        &file_masks,
        flags,
        &mut status_bits,
        io,
    )?;

    interp.record_exit_code(ExitCode::new(status_bits));
    Ok(FlowControl::Continue)
}

/// Purges destination entries absent from `src_entries` when `ROBOCOPY /PURGE` or `/MIR` is active.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `dst_s` - Destination directory path string.
/// * `src_entries` - Source directory [`crate::vfs::VfsMetadata`] entries.
/// * `status_bits` - Mutable `ROBOCOPY` exit bitmask (`2` extras, `8` failed).
fn robocopy_purge_extras(
    interp: &mut Interpreter,
    dst_s: &str,
    src_entries: &[crate::vfs::VfsMetadata],
    status_bits: &mut i32,
) {
    for de in interp.proc_env.vfs.read_dir(dst_s).unwrap_or_default() {
        let in_src = src_entries
            .iter()
            .any(|se| se.name.eq_ignore_ascii_case(&de.name));
        if !in_src {
            let dp = de.full_path.to_windows_string();
            let res = if de.attributes.is_directory() {
                interp
                    .proc_env
                    .vfs
                    .remove_dir(&dp, DirRemovalMode::RecursiveSubtree)
            } else {
                interp
                    .proc_env
                    .vfs
                    .delete_file(&dp, ReadOnlyDeletePolicy::ForceDeleteReadOnly)
            };
            if res.is_ok() {
                *status_bits |= 2;
            } else {
                *status_bits |= 8;
            }
        }
    }
}

/// Synchronizes a single directory level (and subdirectories when `RECURSIVE`) for `ROBOCOPY`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `src_dir` - Source [`WindowsPath`].
/// * `dst_dir` - Destination [`WindowsPath`].
/// * `masks` - Filename wildcard masks.
/// * `flags` - Active [`RobocopyFlags`].
/// * `status_bits` - Mutable `ROBOCOPY` bitmask (`1` copied, `2` extras, `8` failed).
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing error diagnostics to `io` fails.
fn robocopy_sync_dir(
    interp: &mut Interpreter,
    src_dir: &WindowsPath,
    dst_dir: &WindowsPath,
    masks: &[&str],
    flags: RobocopyFlags,
    status_bits: &mut i32,
    io: &mut dyn CmdIo,
) -> Result<(), CmdError> {
    let src_s = src_dir.to_windows_string();
    let dst_s = dst_dir.to_windows_string();

    let src_entries = match interp.proc_env.vfs.read_dir(&src_s) {
        Ok(e) => e,
        Err(err) => {
            io.write_stderr_str(&format!("ROBOCOPY ERROR: {}{CRLF}", err.cmd_exe_message()))?;
            *status_bits |= 8;
            return Ok(());
        }
    };

    if (!src_entries.is_empty() || flags.contains(RobocopyFlags::INCLUDE_EMPTY))
        && !interp.proc_env.vfs.exists(&dst_s)
        && let Err(err) = interp
            .proc_env
            .vfs
            .create_dir(&dst_s, DirCreationDepth::CreateParents)
    {
        io.write_stderr_str(&format!("ROBOCOPY ERROR: {}{CRLF}", err.cmd_exe_message()))?;
        *status_bits |= 8;
        return Ok(());
    }

    if flags.contains(RobocopyFlags::PURGE) {
        robocopy_purge_extras(interp, &dst_s, &src_entries, status_bits);
    }

    for entry in src_entries {
        if entry.attributes.is_directory() {
            if flags.contains(RobocopyFlags::RECURSIVE) {
                let sub_dst = dst_dir.join_component(&entry.name);
                robocopy_sync_dir(
                    interp,
                    &entry.full_path,
                    &sub_dst,
                    masks,
                    flags,
                    status_bits,
                    io,
                )?;
            }
            continue;
        }
        let matched = masks.iter().any(|m| {
            matches_win32_glob(
                m,
                &entry.name,
                Some(&entry.short_name),
                CaseSensitivity::Insensitive,
            )
        });
        if !matched {
            continue;
        }

        let src_file = entry.full_path.to_windows_string();
        let dst_file = dst_dir.join_component(&entry.name).to_windows_string();

        let src_data = match interp.proc_env.vfs.read_bytes(&src_file) {
            Ok(b) => b,
            Err(err) => {
                io.write_stderr_str(&format!("ROBOCOPY ERROR: {}{CRLF}", err.cmd_exe_message()))?;
                *status_bits |= 8;
                continue;
            }
        };
        let identical = interp
            .proc_env
            .vfs
            .read_bytes(&dst_file)
            .is_ok_and(|existing| existing == src_data);
        if !identical {
            match interp.proc_env.vfs.write_bytes(&dst_file, &src_data) {
                Ok(()) => *status_bits |= 1,
                Err(err) => {
                    io.write_stderr_str(&format!(
                        "ROBOCOPY ERROR: {}{CRLF}",
                        err.cmd_exe_message()
                    ))?;
                    *status_bits |= 8;
                    continue;
                }
            }
        }
        if flags.contains(RobocopyFlags::MOVE_FILES)
            && let Err(err) = interp
                .proc_env
                .vfs
                .delete_file(&src_file, ReadOnlyDeletePolicy::ForceDeleteReadOnly)
        {
            io.write_stderr_str(&format!("ROBOCOPY ERROR: {}{CRLF}", err.cmd_exe_message()))?;
            *status_bits |= 8;
        }
    }
    Ok(())
}

/// Checks whether `candidate` is a strict subdirectory underneath `ancestor`.
///
/// # Arguments
/// * `candidate` - Destination [`WindowsPath`].
/// * `ancestor` - Source directory [`WindowsPath`].
///
/// # Returns
/// `true` if `candidate` is strictly inside `ancestor` on the same drive/share.
#[must_use]
fn is_strict_subpath(candidate: &WindowsPath, ancestor: &WindowsPath) -> bool {
    let same_root = match (&candidate.unc_prefix, &ancestor.unc_prefix) {
        (Some((cs, csh)), Some((asrv, ash))) => {
            cs.eq_ignore_ascii_case(asrv) && csh.eq_ignore_ascii_case(ash)
        }
        (None, None) => candidate.drive == ancestor.drive,
        _ => false,
    };
    same_root
        && candidate.components.len() > ancestor.components.len()
        && candidate
            .components
            .iter()
            .zip(&ancestor.components)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Built-in `REG` utility shim (`QUERY`, `ADD`, `DELETE`, `COPY`, `EXPORT`, `IMPORT`).
///
/// Dynamically synchronizes `Interpreter` `Command Processor` settings (`EnableExtensions`,
/// `DelayedExpansion`, `DefaultColor`) whenever `ADD`, `DELETE`, `COPY`, or `IMPORT` mutates
/// `interp.proc_env.registry_store` at root `SETLOCAL` depth!
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
/// Returns [`CmdError`] on invalid key syntax, missing/undecodable `IMPORT` file, VFS write failure
/// on `EXPORT`, or stream I/O error.
pub(super) fn shim_reg(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let Some(sub_word) = args.first() else {
        io.write_stderr_str(&format!("ERROR: Invalid syntax.{CRLF}"))?;
        interp.record_failure(ExitCode::FAILURE);
        return Ok(FlowControl::Continue);
    };
    let sub = sub_word.unquoted().to_ascii_uppercase();
    let rest = args.get(1..).unwrap_or(&[]);

    match sub.as_str() {
        "QUERY" => reg_query(interp, rest, io),
        "ADD" => reg_add(interp, rest, io),
        "DELETE" => reg_delete(interp, rest, io),
        "COPY" => reg_copy(interp, rest, io),
        "EXPORT" => reg_export(interp, rest, io),
        "IMPORT" => reg_import(interp, rest, io),
        _ => {
            io.write_stderr_str(&format!("ERROR: Invalid Argument/Option - '{sub}'.{CRLF}"))?;
            interp.record_failure(ExitCode::FAILURE);
            Ok(FlowControl::Continue)
        }
    }
}

/// Handles `REG QUERY KeyName [/v ValueName | /ve] [/s]`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `rest` - Arguments following `QUERY`.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] on output failure.
fn reg_query(
    interp: &mut Interpreter,
    rest: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let Some(key_w) = rest.first() else {
        io.write_stderr_str(&format!("ERROR: Invalid syntax.{CRLF}"))?;
        interp.record_failure(ExitCode::FAILURE);
        return Ok(FlowControl::Continue);
    };
    let key_name = key_w.unquoted();
    let mut val_filter: Option<String> = None;
    let mut recursive = false;
    let mut i = 1usize;
    while let Some(arg) = rest.get(i) {
        let u = arg.unquoted();
        match u.to_ascii_uppercase().as_str() {
            "/S" => recursive = true,
            "/VE" => val_filter = Some(String::new()),
            "/V" => {
                if let Some(nw) = rest.get(i.saturating_add(1)) {
                    val_filter = Some(nw.unquoted().to_owned());
                    i = i.saturating_add(2);
                    continue;
                }
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }

    let depth = if recursive {
        TraversalDepth::Recursive
    } else {
        TraversalDepth::Shallow
    };
    if let Some(out) = format_registry_query(
        &interp.proc_env.registry_store,
        key_name,
        val_filter.as_deref(),
        depth,
    ) {
        io.write_stdout_str(&out)?;
        interp.record_success();
    } else {
        io.write_stderr_str(&format!(
            "ERROR: The system was unable to find the specified registry key or value.{CRLF}"
        ))?;
        interp.record_failure(ExitCode::FAILURE);
    }
    Ok(FlowControl::Continue)
}

/// Formats `REG QUERY` output against `store`.
///
/// # Arguments
/// * `store` - [`crate::runtime::registry::RegistryStore`] to query.
/// * `raw_key` - Target key path string.
/// * `val_filter` - Optional value name (`Some("")` for `(Default)`).
/// * `depth` - [`TraversalDepth`] (`Shallow` vs `Recursive` for `/s`).
///
/// # Returns
/// `Some(String)` formatted output if matched, or `None` if missing.
#[must_use]
fn format_registry_query(
    store: &crate::runtime::registry::RegistryStore,
    raw_key: &str,
    val_filter: Option<&str>,
    depth: TraversalDepth,
) -> Option<String> {
    let recursive = depth == TraversalDepth::Recursive;
    let kp = RegistryKeyPath::parse(raw_key).ok()?;
    let lk = kp.lookup_key();
    if let Some(vf) = val_filter
        && !recursive
    {
        let val = store.get_value(raw_key, vf)?;
        let disp_v = if val.name.is_empty() {
            "(Default)"
        } else {
            &val.name
        };
        let out = format!(
            "{CRLF}{}{CRLF}    {disp_v}    {}    {}{CRLF}{CRLF}",
            kp.to_full_string(),
            val.kind,
            val.data
        );
        return Some(out);
    }

    let nodes: Vec<_> = store
        .keys
        .iter()
        .filter(|((h, comps), _)| {
            *h == lk.0 && (comps == &lk.1 || (recursive && comps.starts_with(&lk.1)))
        })
        .map(|(_, node)| node)
        .collect();
    if nodes.is_empty() {
        return None;
    }

    let mut out = String::new();
    for node in nodes {
        write!(out, "{CRLF}{}{CRLF}", node.path.to_full_string()).unwrap_or(());
        for val in node.values.values() {
            if let Some(vf) = val_filter
                && !val.name.eq_ignore_ascii_case(vf)
            {
                continue;
            }
            let disp_v = if val.name.is_empty() {
                "(Default)"
            } else {
                &val.name
            };
            write!(out, "    {disp_v}    {}    {}{CRLF}", val.kind, val.data).unwrap_or(());
        }
    }
    out.push_str(CRLF);
    Some(out)
}

/// Handles `REG ADD KeyName [/v ValueName | /ve] [/t Type] [/d Data] [/f]`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `rest` - Arguments following `ADD`.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] on invalid key or I/O error.
fn reg_add(
    interp: &mut Interpreter,
    rest: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let Some(key_w) = rest.first() else {
        io.write_stderr_str(&format!("ERROR: Invalid syntax.{CRLF}"))?;
        interp.record_failure(ExitCode::FAILURE);
        return Ok(FlowControl::Continue);
    };
    let key_name = key_w.unquoted();
    let parsed_kp = match RegistryKeyPath::parse(key_name) {
        Ok(kp) => kp,
        Err(err) => {
            io.write_stderr_str(&format!("{}{CRLF}", err.cmd_exe_message()))?;
            interp.record_failure(err.exit_code());
            return Ok(FlowControl::Continue);
        }
    };

    let mut val_name: Option<String> = None;
    let mut val_type = RegistryValueType::Sz;
    let mut data = String::new();
    let mut i = 1usize;
    while let Some(arg) = rest.get(i) {
        let u = arg.unquoted();
        match u.to_ascii_uppercase().as_str() {
            "/VE" => val_name = Some(String::new()),
            "/V" => {
                if let Some(nw) = rest.get(i.saturating_add(1)) {
                    val_name = Some(nw.unquoted().to_owned());
                    i = i.saturating_add(2);
                    continue;
                }
            }
            "/T" => {
                if let Some(tw) = rest.get(i.saturating_add(1)) {
                    let parsed_t = match RegistryValueType::parse_for_key(key_name, tw.unquoted()) {
                        Ok(vt) => vt,
                        Err(err) => {
                            io.write_stderr_str(&format!("{}{CRLF}", err.cmd_exe_message()))?;
                            interp.record_failure(err.exit_code());
                            return Ok(FlowControl::Continue);
                        }
                    };
                    val_type = parsed_t;
                    i = i.saturating_add(2);
                    continue;
                }
            }
            "/D" => {
                if let Some(dw) = rest.get(i.saturating_add(1)) {
                    dw.unquoted().clone_into(&mut data);
                    i = i.saturating_add(2);
                    continue;
                }
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }

    if let Some(vn) = val_name {
        interp
            .proc_env
            .registry_store
            .set_value(key_name, &vn, val_type, &data)?;
    } else {
        interp.proc_env.registry_store.ensure_key(&parsed_kp);
    }
    sync_live_cmd_processor_if_root(interp);
    io.write_stdout_str(&format!("The operation completed successfully.{CRLF}"))?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Handles `REG DELETE KeyName [/v ValueName | /ve | /va] [/f]`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `rest` - Arguments following `DELETE`.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] on output error.
fn reg_delete(
    interp: &mut Interpreter,
    rest: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let Some(key_w) = rest.first() else {
        io.write_stderr_str(&format!("ERROR: Invalid syntax.{CRLF}"))?;
        interp.record_failure(ExitCode::FAILURE);
        return Ok(FlowControl::Continue);
    };
    let key_name = key_w.unquoted();
    let mut del_mode = 0u8;
    let mut named_val = String::new();
    let mut i = 1usize;
    while let Some(arg) = rest.get(i) {
        match arg.unquoted().to_ascii_uppercase().as_str() {
            "/VA" => del_mode = 1,
            "/VE" => {
                del_mode = 2;
                named_val.clear();
            }
            "/V" => {
                if let Some(nw) = rest.get(i.saturating_add(1)) {
                    del_mode = 2;
                    nw.unquoted().clone_into(&mut named_val);
                    i = i.saturating_add(2);
                    continue;
                }
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }

    let target = match del_mode {
        1 => RegistryDeleteTarget::AllValues,
        2 => RegistryDeleteTarget::Value(&named_val),
        _ => RegistryDeleteTarget::EntireKey,
    };
    if interp
        .proc_env
        .registry_store
        .delete_entry(key_name, target)
    {
        sync_live_cmd_processor_if_root(interp);
        io.write_stdout_str(&format!("The operation completed successfully.{CRLF}"))?;
        interp.record_success();
    } else {
        io.write_stderr_str(&format!(
            "ERROR: The system was unable to find the specified registry key or value.{CRLF}"
        ))?;
        interp.record_failure(ExitCode::FAILURE);
    }
    Ok(FlowControl::Continue)
}

/// Handles `REG COPY KeyName1 KeyName2 [/s] [/f]`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `rest` - Arguments following `COPY`.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] on output error.
fn reg_copy(
    interp: &mut Interpreter,
    rest: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    if rest.len() < 2 {
        io.write_stderr_str(&format!("ERROR: Invalid syntax.{CRLF}"))?;
        interp.record_failure(ExitCode::FAILURE);
        return Ok(FlowControl::Continue);
    }
    let src = rest.first().map_or("", SpannedWord::unquoted);
    let dst = rest.get(1).map_or("", SpannedWord::unquoted);
    let recursive = rest
        .iter()
        .skip(2)
        .any(|a| a.unquoted().eq_ignore_ascii_case("/S"));
    let depth = if recursive {
        TraversalDepth::Recursive
    } else {
        TraversalDepth::Shallow
    };
    if interp.proc_env.registry_store.copy_key(src, dst, depth) {
        sync_live_cmd_processor_if_root(interp);
        io.write_stdout_str(&format!("The operation completed successfully.{CRLF}"))?;
        interp.record_success();
    } else {
        io.write_stderr_str(&format!(
            "ERROR: The system was unable to find the specified registry key or value.{CRLF}"
        ))?;
        interp.record_failure(ExitCode::FAILURE);
    }
    Ok(FlowControl::Continue)
}

/// Handles `REG EXPORT KeyName FileName [/y]`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `rest` - Arguments following `EXPORT`.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if writing the exported `.reg` file or output stream fails.
fn reg_export(
    interp: &mut Interpreter,
    rest: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    if rest.len() < 2 {
        io.write_stderr_str(&format!("ERROR: Invalid syntax.{CRLF}"))?;
        interp.record_failure(ExitCode::FAILURE);
        return Ok(FlowControl::Continue);
    }
    let key_name = rest.first().map_or("", SpannedWord::unquoted);
    let out_file = rest.get(1).map_or("", SpannedWord::unquoted);
    if let Some(reg_text) = interp.proc_env.registry_store.export_reg_text(key_name) {
        interp
            .proc_env
            .vfs
            .write_bytes(out_file, reg_text.as_bytes())?;
        io.write_stdout_str(&format!("The operation completed successfully.{CRLF}"))?;
        interp.record_success();
    } else {
        io.write_stderr_str(&format!(
            "ERROR: The system was unable to find the specified registry key or value.{CRLF}"
        ))?;
        interp.record_failure(ExitCode::FAILURE);
    }
    Ok(FlowControl::Continue)
}

/// Handles `REG IMPORT FileName`, propagating `decode_script_bytes` errors via `?` and
/// synchronizing live `Command Processor` settings!
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `rest` - Arguments following `IMPORT`.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::EncodingFailure`] on invalid `.reg` encoding or [`CmdError::IoFailure`] on output error.
fn reg_import(
    interp: &mut Interpreter,
    rest: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let Some(file_w) = rest.first() else {
        io.write_stderr_str(&format!("ERROR: Invalid syntax.{CRLF}"))?;
        interp.record_failure(ExitCode::FAILURE);
        return Ok(FlowControl::Continue);
    };
    let in_file = file_w.unquoted();
    let Ok(bytes) = interp.proc_env.vfs.read_bytes(in_file) else {
        io.write_stderr_str(&format!(
            "ERROR: Error opening the file. There may be a disk or file system error.{CRLF}"
        ))?;
        interp.record_failure(ExitCode::FAILURE);
        return Ok(FlowControl::Continue);
    };
    let text = decode_script_bytes(&bytes, interp.console.codepage)?;
    interp
        .proc_env
        .registry_store
        .import_reg_text(&text, RegistryHive::LocalMachine);
    sync_live_cmd_processor_if_root(interp);
    io.write_stdout_str(&format!("The operation completed successfully.{CRLF}"))?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Synchronizes `EnableExtensions`, `DelayedExpansion`, and `DefaultColor` from `RegistryStore`
/// onto `interp` when at root `SETLOCAL` depth (`depth == 0`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
fn sync_live_cmd_processor_if_root(interp: &mut Interpreter) {
    if interp.proc_env.env.depth() == 0 {
        interp.sync_processor_settings_from_registry();
    }
}
