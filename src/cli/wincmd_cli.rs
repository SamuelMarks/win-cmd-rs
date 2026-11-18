//! `wincmd` (`cmd.exe`) CLI argument parser, `/C` quote heuristic, and process driver.

use alloc::borrow::ToOwned;
#[cfg(feature = "std")]
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;
#[cfg(feature = "std")]
use std::io::{BufRead, Write};

use crate::error::{CliErrorReason, CliTool, CliUsageFailure, CmdError};
use crate::runtime::{
    ByteStreamBufRead, ByteStreamIo, ByteStreamWrite, Interpreter, IoStreams,
    write_byte_stream_gracefully,
};
use crate::types::{
    AutoRunMode, BS_STR, CRLF, ConsoleColor, DelayedExpansionMode, EchoState, ExitCode,
    ExtensionsMode, FileCompletionMode, HostBindingMode, NativeBackingPath, OutputUnicodeMode,
    PermanentShellMode, QuoteStripMode, ShellDialect, VfsBackendMode,
};
#[cfg(feature = "std")]
use crate::vfs::HostOsVfs;

use super::repl::{run_interactive_repl, run_interactive_repl_byte_streams};

/// Execution mode parsed from `wincmd` (`cmd.exe`) command-line arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinCmdAction {
    /// Start an interactive REPL session.
    InteractiveRepl,
    /// Execute a command string via `/C` and terminate.
    RunCommandAndExit(String),
    /// Execute a command string via `/K` and then enter the interactive REPL.
    RunCommandAndStay(String),
    /// Execute a `.bat` / `.cmd` script file from the VFS or host.
    RunScriptFile {
        /// Path of the script file.
        path: String,
        /// Positional arguments passed to the script.
        args: Vec<String>,
    },
    /// Print help message and exit.
    ShowHelp,
    /// Print version message and exit.
    ShowVersion,
}

/// Parsed configuration for invoking `wincmd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinCmdCliConfig {
    /// Action to perform.
    pub action: WinCmdAction,
    /// `/S` outer quote stripping policy on `/C` or `/K`.
    pub quote_strip_mode: QuoteStripMode,
    /// `/Q` optional initial `ECHO` state override (`Some(EchoState::Off)` when `/Q` is passed).
    pub initial_echo_override: Option<EchoState>,
    /// `/D` Registry `AutoRun` execution mode.
    pub autorun_mode: AutoRunMode,
    /// `/A` vs `/U` internal command output encoding mode for pipes and redirected files.
    pub unicode_output_mode: OutputUnicodeMode,
    /// `/F:ON` vs `/F:OFF` interactive file/directory tab completion mode.
    pub file_completion: FileCompletionMode,
    /// `/E:ON` or `/E:OFF` command extensions mode.
    pub extensions: ExtensionsMode,
    /// `/V:ON` or `/V:OFF` delayed expansion mode.
    pub delayed_expansion: DelayedExpansionMode,
    /// `/T:fg` initial console color.
    pub initial_color: Option<ConsoleColor>,
    /// Optional `--host-root <dir>` mounting `HostOsVfs` onto `C:`.
    pub host_root: Option<NativeBackingPath>,
    /// VFS backend selection (`--in-memory` vs `--host-native`).
    pub vfs_backend_mode: VfsBackendMode,
    /// Host working directory synchronization mode (`Isolated` vs `Synchronized`).
    pub host_binding_mode: HostBindingMode,
    /// Optional `--dialect <cmd|dos622|freedos>` compatibility dialect override.
    pub dialect: Option<ShellDialect>,
    /// Primary permanent shell policy (`COMMAND.COM /P`).
    pub permanent_shell: PermanentShellMode,
    /// Optional MS-DOS `/E:nnnnn` environment paragraph size (`160..=32768` bytes).
    pub dos_env_bytes: Option<u16>,
    /// Optional `COMMAND.COM` command directory (`COMMAND C:\DOS /P`).
    pub command_dir: Option<String>,
    /// Explicit `/E:ON` or `/E:OFF` override supplied on the CLI (preserved over dialect defaults).
    pub explicit_extensions: Option<ExtensionsMode>,
    /// Original unstripped `/C` or `/K` command string for live VFS/`%PATH%`/`%PATHEXT%` executable probing.
    pub raw_command_string: Option<String>,
}

impl Default for WinCmdCliConfig {
    /// Returns the default hermetic library CLI configuration (`InMemoryHermetic`).
    ///
    /// Note: The standalone `wincmd` binary overrides `vfs_backend_mode` to `HostNative`
    /// unless `--in-memory` / `--hermetic` is explicitly passed.
    ///
    /// # Returns
    /// Default [`WinCmdCliConfig`].
    fn default() -> Self {
        Self {
            action: WinCmdAction::InteractiveRepl,
            quote_strip_mode: QuoteStripMode::Heuristic,
            initial_echo_override: None,
            autorun_mode: AutoRunMode::Run,
            unicode_output_mode: OutputUnicodeMode::Ansi,
            file_completion: FileCompletionMode::Enabled,
            extensions: ExtensionsMode::Enabled,
            delayed_expansion: DelayedExpansionMode::Disabled,
            initial_color: None,
            host_root: None,
            vfs_backend_mode: VfsBackendMode::InMemoryHermetic,
            host_binding_mode: HostBindingMode::Isolated,
            dialect: None,
            permanent_shell: PermanentShellMode::Transient,
            dos_env_bytes: None,
            command_dir: None,
            explicit_extensions: None,
            raw_command_string: None,
        }
    }
}

/// Unquotes a `/C` or `/K` command string according to `/S` or the 5-rule `cmd.exe` heuristic.
///
/// # Arguments
/// * `raw_cmd` - Raw command string following `/C` or `/K`.
/// * `strip_mode` - [`QuoteStripMode`] (`AlwaysStrip` when `/S` was specified, `Heuristic` otherwise).
///
/// # Returns
/// Command string after applying outer quote stripping.
#[must_use]
pub fn unquote_cmd_c_command_string(raw_cmd: &str, strip_mode: QuoteStripMode) -> String {
    apply_cmd_c_quote_heuristic(raw_cmd, strip_mode)
}

/// Applies `cmd.exe`'s authentic `/C` and `/K` outer quote stripping heuristic.
///
/// In `cmd.exe`, when `/C` or `/K` is followed by a command string:
/// Outer quotes are preserved ONLY if:
/// 1. `/S` (`QuoteStripMode::AlwaysStrip`) was NOT specified.
/// 2. There are EXACTLY two `"` characters.
/// 3. There are NO special characters (`& < > ( ) @ ^ |`) between the two quotes.
/// 4. There is at least one whitespace character between the two quotes.
/// 5. The string between the two quotes is the name of an executable file.
///
/// # Arguments
/// * `raw_cmd` - Raw command string following `/C` or `/K`.
/// * `strip_mode` - [`QuoteStripMode`] (`/S` vs heuristic).
///
/// # Returns
/// Command string after applying the `cmd.exe` `/C` quote heuristic.
#[must_use]
pub fn apply_cmd_c_quote_heuristic(raw_cmd: &str, strip_mode: QuoteStripMode) -> String {
    apply_cmd_c_quote_heuristic_with_probe(raw_cmd, strip_mode, |cand| {
        let lower = cand.to_ascii_lowercase();
        cand.contains([crate::types::BS_CHAR, '/', ':'])
            && [".exe", ".com", ".bat", ".cmd"]
                .into_iter()
                .any(|ext| lower.ends_with(ext))
    })
}

/// Resolves a `/C` or `/K` command string against `interp`'s live VFS, `%PATH%`, and `%PATHEXT%`
/// via [`Interpreter::resolve_external_or_batch_target`].
///
/// # Arguments
/// * `cfg` - Parsed [`WinCmdCliConfig`].
/// * `fallback_cmd` - Pre-parsed command string when `cfg.raw_command_string` is `None`.
/// * `interp` - Configured [`Interpreter`] session.
///
/// # Returns
/// Command string after live executable probing.
#[must_use]
fn resolve_cmd_c_against_interpreter(
    cfg: &WinCmdCliConfig,
    fallback_cmd: &str,
    interp: &Interpreter,
) -> String {
    cfg.raw_command_string.as_deref().map_or_else(
        || fallback_cmd.to_owned(),
        |raw_c| {
            apply_cmd_c_quote_heuristic_with_probe(raw_c, cfg.quote_strip_mode, |cand| {
                interp.resolve_external_or_batch_target(cand).is_some()
            })
        },
    )
}

/// Applies the 5-rule `cmd.exe` `/C` and `/K` outer quote heuristic using a custom executable probe.
///
/// # Arguments
/// * `raw_cmd` - Raw command string following `/C` or `/K`.
/// * `strip_mode` - [`QuoteStripMode`] (`/S` vs heuristic).
/// * `is_executable` - Closure returning `true` if the inner token resolves to an executable/script.
///
/// # Returns
/// Processed command string.
#[must_use]
pub fn apply_cmd_c_quote_heuristic_with_probe<F>(
    raw_cmd: &str,
    strip_mode: QuoteStripMode,
    is_executable: F,
) -> String
where
    F: FnOnce(&str) -> bool,
{
    let trimmed = raw_cmd.trim();
    let Some(inner) = trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return trimmed.to_owned();
    };

    if strip_mode == QuoteStripMode::AlwaysStrip {
        return inner.to_owned();
    }

    let quote_count = trimmed.chars().filter(|&c| c == '"').count();
    let has_special = inner.contains(['&', '<', '>', '(', ')', '@', '^', '|']);
    let has_whitespace = inner.chars().any(char::is_whitespace);

    if quote_count == 2 && !has_special && has_whitespace && is_executable(inner) {
        trimmed.to_owned()
    } else {
        inner.to_owned()
    }
}

/// Reconstructs a command-line tail from OS `argv` tokens, preserving quotes around multi-word
/// arguments when multiple OS arguments follow `/C`, `/K`, or a script path.
///
/// # Arguments
/// * `tokens` - Slice of OS `argv` tokens.
///
/// # Returns
/// Reconstructed command string.
#[must_use]
pub fn join_argv_preserving_quotes(tokens: &[String]) -> String {
    if let [single] = tokens {
        return single.clone();
    }
    let mut out = String::new();
    for (idx, tok) in tokens.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        let already_quoted = tok.starts_with('"') && tok.ends_with('"') && tok.len() >= 2;
        let needs_quotes = !already_quoted
            && tok
                .chars()
                .any(|c| c.is_whitespace() || matches!(c, '&' | '|' | '<' | '>'));
        if needs_quotes {
            write!(out, r#""{tok}""#).unwrap_or(());
        } else {
            out.push_str(tok);
        }
    }
    out
}

/// Parses `wincmd` (`cmd.exe`) command-line arguments into a [`WinCmdCliConfig`].
///
/// Supports attached switches like `/c"echo hi"` or `/k"set a=1"`.
///
/// # Arguments
/// * `args` - Slice of command-line arguments (excluding `argv[0]`).
///
/// # Returns
/// `Ok(WinCmdCliConfig)` if valid.
///
/// # Errors
/// Returns [`CmdError::CliUsage`] or [`CmdError::ParameterFormatNotCorrect`] on invalid flags.
pub fn parse_wincmd_args(args: &[String]) -> Result<WinCmdCliConfig, CmdError> {
    parse_wincmd_args_with_default_backend(args, VfsBackendMode::InMemoryHermetic)
}

/// Constructs a [`CmdError::CliUsage`] for `wincmd` argument errors.
///
/// # Arguments
/// * `flag` - Offending switch or flag token.
/// * `reason` - Structured [`CliErrorReason`].
///
/// # Returns
/// Unified [`CmdError::CliUsage`] value.
#[must_use]
fn wincmd_cli_err(flag: impl Into<String>, reason: CliErrorReason) -> CmdError {
    CmdError::from(CliUsageFailure::new(CliTool::WinCmd, flag, reason))
}

/// Parses `wincmd` arguments using `default_backend` unless overridden by `--in-memory` / `--host-native`.
///
/// # Arguments
/// * `args` - Slice of command-line arguments (excluding `argv[0]`).
/// * `default_backend` - Initial [`VfsBackendMode`] (`HostNative` for CLI binary, `InMemoryHermetic` for hermetic embedding).
///
/// # Returns
/// `Ok(WinCmdCliConfig)` if valid.
///
/// # Errors
/// Returns [`CmdError`] on missing switch arguments or unknown flags.
pub fn parse_wincmd_args_with_default_backend(
    args: &[String],
    default_backend: VfsBackendMode,
) -> Result<WinCmdCliConfig, CmdError> {
    let mut cfg = WinCmdCliConfig {
        vfs_backend_mode: default_backend,
        host_binding_mode: if default_backend == VfsBackendMode::HostNative {
            HostBindingMode::Synchronized
        } else {
            HostBindingMode::Isolated
        },
        ..WinCmdCliConfig::default()
    };
    let mut i = 0usize;

    while let Some(arg) = args.get(i) {
        let upper = arg.to_ascii_uppercase();
        match upper.as_str() {
            "/?" | "-H" | "--HELP" => {
                cfg.action = WinCmdAction::ShowHelp;
                return Ok(cfg);
            }
            "--VERSION" | "-V" => {
                cfg.action = WinCmdAction::ShowVersion;
                return Ok(cfg);
            }
            _ if apply_simple_wincmd_flag(&upper, &mut cfg) => {}
            "/C" | "/K" => {
                let rest = args.get(i.saturating_add(1)..).unwrap_or(&[]);
                if rest.is_empty() {
                    return Err(wincmd_cli_err(upper, CliErrorReason::MissingValue));
                }
                let joined = join_argv_preserving_quotes(rest);
                let processed = apply_cmd_c_quote_heuristic(&joined, cfg.quote_strip_mode);
                cfg.raw_command_string = Some(joined);
                cfg.action = if upper == "/C" {
                    WinCmdAction::RunCommandAndExit(processed)
                } else {
                    WinCmdAction::RunCommandAndStay(processed)
                };
                return Ok(cfg);
            }
            _ if matches!(upper.get(..2), Some("/C" | "/K")) => {
                let mut parts = vec![arg.get(2..).unwrap_or("").to_owned()];
                parts.extend_from_slice(args.get(i.saturating_add(1)..).unwrap_or(&[]));
                let joined = join_argv_preserving_quotes(&parts);
                let processed = apply_cmd_c_quote_heuristic(&joined, cfg.quote_strip_mode);
                cfg.raw_command_string = Some(joined);
                cfg.action = if upper.starts_with("/C") {
                    WinCmdAction::RunCommandAndExit(processed)
                } else {
                    WinCmdAction::RunCommandAndStay(processed)
                };
                return Ok(cfg);
            }
            _ if upper.starts_with("/T:")
                || upper.starts_with("/E:")
                || upper.starts_with("--DIALECT=") =>
            {
                apply_inline_wincmd_flag(arg, &upper, &mut cfg)?;
            }
            "--DIALECT" | "--HOST-ROOT" => {
                let val = args
                    .get(i.saturating_add(1))
                    .ok_or_else(|| wincmd_cli_err(arg.clone(), CliErrorReason::MissingValue))?;
                apply_two_arg_wincmd_flag(&upper, arg, val, &mut cfg)?;
                i = i.saturating_add(2);
                continue;
            }
            "--SCRIPT" => {
                let script_path = args
                    .get(i.saturating_add(1))
                    .ok_or_else(|| wincmd_cli_err(arg.clone(), CliErrorReason::MissingValue))?;
                cfg.action = WinCmdAction::RunScriptFile {
                    path: normalize_cli_script_path(script_path, cfg.vfs_backend_mode),
                    args: args.get(i.saturating_add(2)..).unwrap_or(&[]).to_vec(),
                };
                return Ok(cfg);
            }
            _ if is_unrecognized_cli_flag(arg, cfg.vfs_backend_mode) => {
                return Err(wincmd_cli_err(arg.clone(), CliErrorReason::UnknownFlag));
            }
            _ if args
                .get(i.saturating_add(1)..)
                .unwrap_or(&[])
                .iter()
                .any(|t| t.eq_ignore_ascii_case("/P")) =>
            {
                cfg.command_dir = Some(arg.clone());
            }
            _ => {
                cfg.action = WinCmdAction::RunScriptFile {
                    path: normalize_cli_script_path(arg, cfg.vfs_backend_mode),
                    args: args.get(i.saturating_add(1)..).unwrap_or(&[]).to_vec(),
                };
                return Ok(cfg);
            }
        }
        i = i.saturating_add(1);
    }

    Ok(cfg)
}

/// Applies two-token `--dialect <val>` and `--host-root <dir>` `wincmd` options.
///
/// # Arguments
/// * `upper` - Uppercased flag name (`"--DIALECT"` or `"--HOST-ROOT"`).
/// * `flag` - Original flag string.
/// * `val` - Following operand value.
/// * `cfg` - Mutable [`WinCmdCliConfig`].
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns [`CmdError`] if `--dialect` receives an unknown dialect name.
fn apply_two_arg_wincmd_flag(
    upper: &str,
    flag: &str,
    val: &str,
    cfg: &mut WinCmdCliConfig,
) -> Result<(), CmdError> {
    if upper == "--DIALECT" {
        cfg.dialect = Some(ShellDialect::parse_cli_value(val).ok_or_else(|| {
            wincmd_cli_err(
                flag.to_owned(),
                CliErrorReason::InvalidModeValue(val.to_owned()),
            )
        })?);
    } else {
        cfg.host_root = Some(NativeBackingPath::from_string(val));
        cfg.vfs_backend_mode = VfsBackendMode::HostNative;
    }
    Ok(())
}

/// Applies inline `KEY:VALUE` / `--key=value` `wincmd` flags (`/T:`, `/E:<bytes>`, `--dialect=`).
///
/// # Arguments
/// * `arg` - Original argument string.
/// * `upper` - Uppercased argument string.
/// * `cfg` - Mutable [`WinCmdCliConfig`].
///
/// # Returns
/// `Ok(())` on valid value.
///
/// # Errors
/// Returns [`CmdError`] on invalid hex color, environment size, or dialect name.
fn apply_inline_wincmd_flag(
    arg: &str,
    upper: &str,
    cfg: &mut WinCmdCliConfig,
) -> Result<(), CmdError> {
    if upper.starts_with("/T:") {
        cfg.initial_color = Some(ConsoleColor::parse_hex(arg.get(3..).unwrap_or(""))?);
    } else if upper.starts_with("/E:") {
        let raw_e = arg.get(3..).unwrap_or("");
        let bytes = raw_e
            .parse::<u16>()
            .ok()
            .filter(|&n| (160..=32768).contains(&n))
            .ok_or_else(|| {
                wincmd_cli_err(
                    arg.to_owned(),
                    CliErrorReason::InvalidModeValue(raw_e.to_owned()),
                )
            })?;
        cfg.dos_env_bytes = Some(bytes);
    } else {
        let val = arg.get("--dialect=".len()..).unwrap_or("");
        cfg.dialect = Some(ShellDialect::parse_cli_value(val).ok_or_else(|| {
            wincmd_cli_err(
                "--dialect".to_owned(),
                CliErrorReason::InvalidModeValue(val.to_owned()),
            )
        })?);
    }
    Ok(())
}

/// Applies zero-operand `wincmd` mode switches (`/Q`, `/S`, `/D`, `/A`, `/U`, `/F:*`, `/E:*`, `/V:*`, backend flags).
///
/// # Arguments
/// * `upper` - Uppercased argument token.
/// * `cfg` - Mutable [`WinCmdCliConfig`] to update.
///
/// # Returns
/// `true` if `upper` matched a zero-operand mode switch.
fn apply_simple_wincmd_flag(upper: &str, cfg: &mut WinCmdCliConfig) -> bool {
    match upper {
        "/Q" => cfg.initial_echo_override = Some(EchoState::Off),
        "/S" => cfg.quote_strip_mode = QuoteStripMode::AlwaysStrip,
        "/D" => cfg.autorun_mode = AutoRunMode::Skip,
        "/A" => cfg.unicode_output_mode = OutputUnicodeMode::Ansi,
        "/U" => cfg.unicode_output_mode = OutputUnicodeMode::Utf16Le,
        "/F:ON" => cfg.file_completion = FileCompletionMode::Enabled,
        "/F:OFF" => cfg.file_completion = FileCompletionMode::Disabled,
        "/E:ON" => {
            cfg.extensions = ExtensionsMode::Enabled;
            cfg.explicit_extensions = Some(ExtensionsMode::Enabled);
        }
        "/E:OFF" => {
            cfg.extensions = ExtensionsMode::Disabled;
            cfg.explicit_extensions = Some(ExtensionsMode::Disabled);
        }
        "/P" => cfg.permanent_shell = PermanentShellMode::Permanent,
        "/MSG" => {}
        "/V:ON" => cfg.delayed_expansion = DelayedExpansionMode::Enabled,
        "/V:OFF" => cfg.delayed_expansion = DelayedExpansionMode::Disabled,
        "--IN-MEMORY" | "--HERMETIC" => {
            cfg.vfs_backend_mode = VfsBackendMode::InMemoryHermetic;
            cfg.host_binding_mode = HostBindingMode::Isolated;
        }
        "--HOST-NATIVE" => {
            cfg.vfs_backend_mode = VfsBackendMode::HostNative;
            cfg.host_binding_mode = HostBindingMode::Synchronized;
        }
        _ => return false,
    }
    true
}

/// Determines whether `arg` is an unknown CLI flag rather than a POSIX slash-rooted script path.
///
/// # Arguments
/// * `arg` - Candidate command-line argument.
/// * `backend` - Active [`VfsBackendMode`].
///
/// # Returns
/// `true` if `arg` should be rejected as an unknown CLI switch.
#[must_use]
fn is_unrecognized_cli_flag(arg: &str, backend: VfsBackendMode) -> bool {
    if arg.starts_with('-') {
        return true;
    }
    if !arg.starts_with('/') {
        return false;
    }
    if backend == VfsBackendMode::HostNative && is_posix_script_path(arg) {
        return false;
    }
    true
}

/// Checks whether a `/`-prefixed string looks like a POSIX file path rather than a `cmd.exe` switch.
///
/// # Arguments
/// * `arg` - Slash-prefixed argument string.
///
/// # Returns
/// `true` if `arg` contains additional `/` separators or ends with `.bat` / `.cmd`.
#[must_use]
fn is_posix_script_path(arg: &str) -> bool {
    let tail = arg.get(1..).unwrap_or("");
    tail.contains('/')
        || tail
            .rsplit_once('.')
            .filter(|(stem, _)| !stem.is_empty())
            .is_some_and(|(_, ext)| {
                ext.eq_ignore_ascii_case("bat") || ext.eq_ignore_ascii_case("cmd")
            })
}

/// Maps POSIX absolute script paths (`/tmp/foo.bat`) onto `Z:` when running in `HostNative` mode.
///
/// # Arguments
/// * `raw_path` - Raw CLI script path argument.
/// * `backend` - Active [`VfsBackendMode`].
///
/// # Returns
/// VFS-resolvable script path string.
#[must_use]
fn normalize_cli_script_path(raw_path: &str, backend: VfsBackendMode) -> String {
    if backend == VfsBackendMode::HostNative
        && raw_path.starts_with('/')
        && is_posix_script_path(raw_path)
    {
        format!("Z:{raw_path}")
    } else {
        raw_path.to_owned()
    }
}

/// Applies non-VFS session flags from `cfg` onto `interp`.
///
/// # Arguments
/// * `cfg` - Parsed [`WinCmdCliConfig`].
/// * `interp` - Mutable [`Interpreter`] to configure.
pub fn apply_cli_session_flags(cfg: &WinCmdCliConfig, interp: &mut Interpreter) {
    if let Some(echo_ov) = cfg.initial_echo_override {
        interp.console.echo_state = echo_ov;
    }
    interp.config.unicode_output_mode = cfg.unicode_output_mode;
    interp.config.file_completion = cfg.file_completion;
    interp.config.host_binding_mode = cfg.host_binding_mode;
    interp.config.permanent_shell = cfg.permanent_shell;
    interp.config.dos_env_bytes = cfg.dos_env_bytes;
    if let Some(dialect) = cfg.dialect {
        interp.apply_shell_dialect(dialect);
    }
    if let Some(exp_ext) = cfg.explicit_extensions {
        interp.proc_env.env.extensions = exp_ext;
    }
    if let Some(cmd_dir) = &cfg.command_dir {
        let trimmed = cmd_dir.trim_end_matches([crate::types::BS_CHAR, '/']);
        interp
            .proc_env
            .env
            .set("COMSPEC", &format!("{trimmed}{BS_STR}COMMAND.COM"));
    }
    interp.proc_env.env.delayed_expansion = cfg.delayed_expansion;
    if cfg.initial_color.is_some() {
        interp.console.console_color = cfg.initial_color;
    }
}

/// Mounts `HostOsVfs` when `--host-root` or `--host-native` is selected under `std` builds,
/// and applies all session flags from `cfg` onto `interp`.
///
/// # Arguments
/// * `cfg` - Parsed [`WinCmdCliConfig`].
/// * `interp` - Mutable [`Interpreter`] to configure.
#[cfg(feature = "std")]
fn configure_interpreter_from_cli(cfg: &WinCmdCliConfig, interp: &mut Interpreter) {
    if let Some(root) = &cfg.host_root {
        interp.proc_env.vfs = Box::new(HostOsVfs::new(root.to_path_buf()));
    } else if cfg.vfs_backend_mode == VfsBackendMode::HostNative {
        interp.proc_env.vfs = Box::new(HostOsVfs::from_host_env());
    }
    apply_cli_session_flags(cfg, interp);
}

/// Applies session flags from `cfg` onto `interp` in `#![no_std]` builds (preserving the caller's VFS).
///
/// # Arguments
/// * `cfg` - Parsed [`WinCmdCliConfig`].
/// * `interp` - Mutable [`Interpreter`] to configure.
#[cfg(not(feature = "std"))]
fn configure_interpreter_from_cli(cfg: &WinCmdCliConfig, interp: &mut Interpreter) {
    apply_cli_session_flags(cfg, interp);
}

/// Builds the `wincmd /?` / `--help` usage banner.
///
/// # Returns
/// Formatted multi-line help text terminated with [`CRLF`].
#[must_use]
fn format_wincmd_help_banner() -> String {
    format!(
        "Starts a new instance of the cross-platform Windows & MS-DOS command interpreter (wincmd).{CRLF}\
         WINCMD [drive:\\path] [/A | /U] [/Q] [/D] [/P] [/MSG] [/E:ON | /E:OFF | /E:nnnnn] [/F:ON | /F:OFF] [/V:ON | /V:OFF] [/T:bf] [[/S] [/C | /K] string]{CRLF}\
         Options: --dialect <cmd|dos622|freedos> | --in-memory | --hermetic | --host-native | --host-root <dir> | --script <file> [args...]{CRLF}"
    )
}

/// Executes a configured [`WinCmdCliConfig`] on `interp`, reading interactive lines from
/// `io.stdin` when in REPL mode and writing output to `io.stdout` / `io.stderr`.
///
/// # Arguments
/// * `cfg` - Parsed [`WinCmdCliConfig`].
/// * `interp` - Mutable [`Interpreter`] instance.
/// * `io` - Mutable [`IoStreams`].
///
/// # Returns
/// `Ok(ExitCode)` when execution finishes.
///
/// # Errors
/// Returns [`CmdError`] if script reading fails.
pub fn run_wincmd_with_config(
    cfg: &WinCmdCliConfig,
    interp: &mut Interpreter,
    io: &mut IoStreams,
) -> Result<ExitCode, CmdError> {
    configure_interpreter_from_cli(cfg, interp);

    if !matches!(
        cfg.action,
        WinCmdAction::ShowHelp | WinCmdAction::ShowVersion
    ) {
        interp.run_autorun_if_enabled(cfg.autorun_mode, io);
        if cfg.permanent_shell == PermanentShellMode::Permanent
            && interp.proc_env.vfs.exists("C:/AUTOEXEC.BAT")
        {
            let _auto = interp.execute_batch_file(
                "C:\\AUTOEXEC.BAT",
                "C:\\AUTOEXEC.BAT",
                Vec::new(),
                String::new(),
                io,
            );
        }
    }

    match &cfg.action {
        WinCmdAction::ShowHelp => {
            io.stdout.push_str(&format_wincmd_help_banner());
            Ok(ExitCode::SUCCESS)
        }
        WinCmdAction::ShowVersion => {
            write!(io.stdout, "{}{CRLF}", interp.config.version_banner).unwrap_or(());
            Ok(ExitCode::SUCCESS)
        }
        WinCmdAction::RunCommandAndExit(cmd) => {
            let effective = resolve_cmd_c_against_interpreter(cfg, cmd, interp);
            Ok(interp.execute_interactive_line(&effective, io))
        }
        WinCmdAction::RunCommandAndStay(cmd) => {
            let effective = resolve_cmd_c_against_interpreter(cfg, cmd, interp);
            let _init_code = interp.execute_interactive_line(&effective, io);
            if let Some(code) = interp.exec.exited() {
                return Ok(code);
            }
            Ok(run_interactive_repl(interp, io))
        }
        WinCmdAction::RunScriptFile { path, args } => {
            let raw_tail = join_argv_preserving_quotes(args);
            interp.execute_batch_file(path, path, args.clone(), raw_tail, io)
        }
        WinCmdAction::InteractiveRepl => Ok(run_interactive_repl(interp, io)),
    }
}

/// Executes the `wincmd` CLI process over portable `#![no_std]` [`ByteStreamBufRead`] and [`ByteStreamWrite`] streams
/// against a caller-supplied [`Interpreter`] (e.g., MS-DOS `DosFatVfs` + `DosProcessSpawner`).
///
/// # Arguments
/// * `args` - Command-line arguments excluding `argv[0]`.
/// * `default_backend` - Default [`VfsBackendMode`] when neither `--in-memory` nor `--host-native` is passed.
/// * `interp` - Mutable [`Interpreter`] session pre-configured with VFS and spawner.
/// * `stdin` - Live buffered input stream.
/// * `stdout` - Live standard output stream.
/// * `stderr` - Live standard error stream.
///
/// # Returns
/// Process exit status byte (`0..=255`).
pub fn execute_wincmd_over_streams(
    args: &[String],
    default_backend: VfsBackendMode,
    interp: &mut Interpreter,
    stdin: &mut dyn ByteStreamBufRead,
    stdout: &mut dyn ByteStreamWrite,
    stderr: &mut dyn ByteStreamWrite,
) -> u8 {
    let cfg = match parse_wincmd_args_with_default_backend(args, default_backend) {
        Ok(c) => c,
        Err(err) => {
            let msg = format!("{}{CRLF}", err.cmd_exe_message());
            if write_byte_stream_gracefully(stderr, msg.as_bytes()).is_err() {
                return 1;
            }
            return exit_code_to_u8(ExitCode::FAILURE);
        }
    };
    execute_wincmd_with_interpreter_streams(&cfg, interp, stdin, stdout, stderr)
        .map_or(1, exit_code_to_u8)
}

/// Executes the standalone `wincmd` CLI process over live `stdin`, `stdout`, and `stderr` streams.
///
/// Defaults to [`VfsBackendMode::HostNative`] so host batch files and directories are accessible
/// out of the box unless `--in-memory` / `--hermetic` is passed.
///
/// # Arguments
/// * `args` - Command-line arguments excluding `argv[0]`.
/// * `stdin` - Live buffered standard input reader.
/// * `stdout` - Live standard output writer.
/// * `stderr` - Live standard error writer.
///
/// # Returns
/// Process exit status byte (`0..=255`).
#[cfg(feature = "std")]
pub fn execute_wincmd_process(
    args: &[String],
    stdin: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    execute_wincmd_process_inner(args, stdin, stdout, stderr).map_or(1, exit_code_to_u8)
}

/// Fallible inner implementation of [`execute_wincmd_process`].
///
/// # Arguments
/// * `args` - Command-line arguments excluding `argv[0]`.
/// * `stdin` - Live buffered standard input reader.
/// * `stdout` - Live standard output writer.
/// * `stderr` - Live standard error writer.
///
/// # Returns
/// `Ok(ExitCode)` when execution and stream flushing succeed.
///
/// # Errors
/// Returns [`CmdError`] on CLI argument errors or non-`BrokenPipe` stream write/read failures.
#[cfg(feature = "std")]
fn execute_wincmd_process_inner(
    args: &[String],
    stdin: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CmdError> {
    let cfg = match parse_wincmd_args_with_default_backend(args, VfsBackendMode::HostNative) {
        Ok(c) => c,
        Err(err) => {
            let msg = format!("{}{CRLF}", err.cmd_exe_message());
            super::repl::write_stream_gracefully(stderr, msg.as_bytes())?;
            return Ok(ExitCode::FAILURE);
        }
    };

    let mut interp =
        if cfg.vfs_backend_mode == VfsBackendMode::HostNative && cfg.host_root.is_none() {
            Interpreter::new_host_native()
        } else {
            Interpreter::default()
        };
    execute_wincmd_with_interpreter(&cfg, &mut interp, stdin, stdout, stderr)
}

/// Runs a parsed [`WinCmdCliConfig`] against an existing [`Interpreter`] over live `std::io` streams.
///
/// # Arguments
/// * `cfg` - Parsed [`WinCmdCliConfig`].
/// * `interp` - Mutable [`Interpreter`] session.
/// * `stdin` - Buffered input reader.
/// * `stdout` - Standard output writer.
/// * `stderr` - Standard error writer.
///
/// # Returns
/// `Ok(ExitCode)` when execution and stream flushing succeed.
///
/// # Errors
/// Returns [`CmdError`] on non-`BrokenPipe` stream read/write failures.
#[cfg(feature = "std")]
pub(super) fn execute_wincmd_with_interpreter(
    cfg: &WinCmdCliConfig,
    interp: &mut Interpreter,
    stdin: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CmdError> {
    let mut sin = crate::runtime::StdBufReadAdapter(stdin);
    let mut sout = crate::runtime::StdWriteAdapter::new(stdout, "write");
    let mut serr = crate::runtime::StdWriteAdapter::new(stderr, "write");
    execute_wincmd_with_interpreter_streams(cfg, interp, &mut sin, &mut sout, &mut serr)
}

/// Runs a parsed [`WinCmdCliConfig`] against an existing [`Interpreter`] over portable [`ByteStreamBufRead`] / [`ByteStreamWrite`] streams.
///
/// # Arguments
/// * `cfg` - Parsed [`WinCmdCliConfig`].
/// * `interp` - Mutable [`Interpreter`] session.
/// * `stdin` - Buffered input reader.
/// * `stdout` - Standard output writer.
/// * `stderr` - Standard error writer.
///
/// # Returns
/// `Ok(ExitCode)` when execution and stream flushing succeed.
///
/// # Errors
/// Returns [`CmdError`] on non-`BrokenPipe` stream read/write failures.
pub fn execute_wincmd_with_interpreter_streams(
    cfg: &WinCmdCliConfig,
    interp: &mut Interpreter,
    stdin: &mut dyn ByteStreamBufRead,
    stdout: &mut dyn ByteStreamWrite,
    stderr: &mut dyn ByteStreamWrite,
) -> Result<ExitCode, CmdError> {
    configure_interpreter_from_cli(cfg, interp);

    if !matches!(
        cfg.action,
        WinCmdAction::ShowHelp | WinCmdAction::ShowVersion
    ) {
        let mut ar_io = ByteStreamIo::new(
            stdin,
            stdout,
            stderr,
            interp.console.codepage,
            interp.config.unicode_output_mode,
        );
        interp.run_autorun_if_enabled(cfg.autorun_mode, &mut ar_io);
        if cfg.permanent_shell == PermanentShellMode::Permanent
            && interp.proc_env.vfs.exists("C:/AUTOEXEC.BAT")
        {
            let _auto = interp.execute_batch_file(
                "C:\\AUTOEXEC.BAT",
                "C:\\AUTOEXEC.BAT",
                Vec::new(),
                String::new(),
                &mut ar_io,
            );
        }
        ar_io.check_error()?;
    }

    match &cfg.action {
        WinCmdAction::InteractiveRepl => {
            run_interactive_repl_byte_streams(interp, stdin, stdout, stderr)
        }
        WinCmdAction::RunCommandAndStay(cmd) => {
            let effective = resolve_cmd_c_against_interpreter(cfg, cmd, interp);
            {
                let mut cmd_io = ByteStreamIo::new(
                    stdin,
                    stdout,
                    stderr,
                    interp.console.codepage,
                    interp.config.unicode_output_mode,
                );
                let _init_code = interp.execute_interactive_line(&effective, &mut cmd_io);
                cmd_io.check_error()?;
            }
            if let Some(code) = interp.exec.exited() {
                return Ok(code);
            }
            run_interactive_repl_byte_streams(interp, stdin, stdout, stderr)
        }
        WinCmdAction::ShowHelp => {
            let help_msg = format_wincmd_help_banner();
            write_byte_stream_gracefully(stdout, help_msg.as_bytes())?;
            Ok(ExitCode::SUCCESS)
        }
        WinCmdAction::ShowVersion => {
            let ver_msg = format!("{}{CRLF}", interp.config.version_banner);
            write_byte_stream_gracefully(stdout, ver_msg.as_bytes())?;
            Ok(ExitCode::SUCCESS)
        }
        WinCmdAction::RunCommandAndExit(cmd) => {
            let effective = resolve_cmd_c_against_interpreter(cfg, cmd, interp);
            let mut cmd_io = ByteStreamIo::new(
                stdin,
                stdout,
                stderr,
                interp.console.codepage,
                interp.config.unicode_output_mode,
            );
            let code = interp.execute_interactive_line(&effective, &mut cmd_io);
            cmd_io.check_error()?;
            Ok(code)
        }
        WinCmdAction::RunScriptFile { path, args: sargs } => {
            let raw_tail = join_argv_preserving_quotes(sargs);
            let mut script_io = ByteStreamIo::new(
                stdin,
                stdout,
                stderr,
                interp.console.codepage,
                interp.config.unicode_output_mode,
            );
            let res =
                interp.execute_batch_file(path, path, sargs.clone(), raw_tail, &mut script_io);
            script_io.check_error()?;
            match res {
                Ok(c) => Ok(c),
                Err(err) => {
                    let msg = format!("{}{CRLF}", err.cmd_exe_message());
                    write_byte_stream_gracefully(stderr, msg.as_bytes())?;
                    Ok(err.exit_code())
                }
            }
        }
    }
}

/// Converts a 32-bit [`ExitCode`] into a POSIX/OS `u8` status code (`0..=255`).
///
/// # Arguments
/// * `code` - Interpreter [`ExitCode`].
///
/// # Returns
/// Unsigned 8-bit exit status (`code.0.rem_euclid(256)`).
#[must_use]
pub(super) const fn exit_code_to_u8(code: ExitCode) -> u8 {
    let [low_byte, _, _, _] = code.0.rem_euclid(256).to_le_bytes();
    low_byte
}
