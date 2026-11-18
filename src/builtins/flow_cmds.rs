//! Control-flow and subshell built-in commands (`CALL`, `GOTO`, `EXIT`, `SHIFT`, `PAUSE`, `CMD`, `START`).
//!
//! Implements twice-expansion `CALL`, `:subroutine` invocation, `GOTO :label` / `:EOF`,
//! `SHIFT /n`, interactive `PAUSE`, nested `CMD` subshells (honoring live Registry settings),
//! and lossless `START` tail slicing (preserving multi-space and quoted arguments verbatim).

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::CmdError;
use crate::parser::ast::SpannedWord;
use crate::parser::phase1::{Phase1Context, expand_phase1};
use crate::reader::char_map::LogicalLineBuffer;
use crate::runtime::{CmdIo, FlowControl, Interpreter};
use crate::span::{ByteOffset, Span};
use crate::types::{
    AutoRunMode, CRLF, DelayedExpansionMode, EchoState, ExecutionContext, ExitCode, ExtensionsMode,
    LabelName, OutputUnicodeMode, QuoteStripMode,
};

/// Built-in `CALL` command (`CALL :label [args]`, `CALL script.bat [args]`, or `CALL command [args]`).
///
/// Performs authentic `cmd.exe` twice-expansion on `CALL <command>` when the target is not a
/// subroutine `:label` or `.bat`/`.cmd` script.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `raw_tail` - Raw post-command tail.
/// * `raw_tail_base` - Starting [`ByteOffset`] of `raw_tail` in its source buffer.
/// * `cmd_span` - Source [`Span`] of the `CALL` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if `:label` is invalid when `/E:OFF`, if `:label` or script lookup fails,
/// or if [`crate::runtime::ExecutionLimits::max_call_depth`] is exceeded.
pub(super) fn cmd_call(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    raw_tail: &str,
    raw_tail_base: ByteOffset,
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let Some(target_word) = args.first() else {
        interp.record_success();
        return Ok(FlowControl::Continue);
    };
    let target_str = target_word.unquoted();

    let remaining_args = args.get(1..).unwrap_or(&[]);
    let sub_tail = if remaining_args.is_empty() {
        String::new()
    } else {
        slice_tail_from_arg(raw_tail, raw_tail_base, remaining_args)
    };
    let sub_args: Vec<String> = remaining_args
        .iter()
        .map(|w| w.unquoted().to_owned())
        .collect();

    if let Some(label_raw) = target_str.strip_prefix(':') {
        if interp.proc_env.env.extensions == ExtensionsMode::Disabled {
            return Err(CmdError::SyntaxError { span: cmd_span });
        }
        let label = LabelName::new(label_raw);
        let code = interp.call_subroutine_label(&label, sub_args, sub_tail, cmd_span, io)?;
        interp.record_exit_code(code);
        return Ok(FlowControl::Continue);
    }

    if let Some(resolved_bat) = resolve_batch_script(interp, target_str) {
        let code = interp.execute_batch_file(&resolved_bat, target_str, sub_args, sub_tail, io)?;
        interp.record_exit_code(code);
        return Ok(FlowControl::Continue);
    }

    let trimmed_tail = raw_tail.trim_start();
    let call_src_id = interp
        .exec
        .allocate_ephemeral_source("<call>", trimmed_tail);
    let raw_buf = LogicalLineBuffer::from_str_at(call_src_id, ByteOffset(0), trimmed_tail);
    let second_pass_line = {
        let cwd = interp.current_cwd_string();
        let exit_code = interp.last_exit_code();
        let (exec_ctx, arg0_str, pos_args_vec, all_raw_str) =
            interp.exec.call_stack().last().map_or_else(
                || {
                    (
                        ExecutionContext::InteractiveRepl,
                        "cmd".to_owned(),
                        Vec::new(),
                        String::new(),
                    )
                },
                |frame| {
                    (
                        ExecutionContext::BatchFile,
                        frame.arg0.clone(),
                        frame.positional_args.clone(),
                        frame.all_args_raw.clone(),
                    )
                },
            );
        let env_ref = &interp.proc_env.env;
        let vfs_ref = interp.proc_env.vfs.as_ref();
        let p1_ctx = Phase1Context {
            exec_context: exec_ctx,
            arg0: &arg0_str,
            positional_args: &pos_args_vec,
            all_args_raw: &all_raw_str,
            vfs: vfs_ref,
            env_lookup: |k| env_ref.get_with_dynamics(k, &cwd, exit_code),
        };
        expand_phase1(&raw_buf, &p1_ctx)?.to_plain_string()
    };

    let code = interp.execute_interactive_line_checked(&second_pass_line, io)?;
    interp.record_exit_code(code);
    if let Some(exit_shell_code) = interp.exec.exited() {
        return Ok(FlowControl::ExitShell(exit_shell_code));
    }
    Ok(FlowControl::Continue)
}

/// Resolves `prog` to a `.bat` or `.cmd` script path on the VFS, if present.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `prog` - Candidate script name or path.
///
/// # Returns
/// `Some(String)` VFS path if a `.bat` or `.cmd` file matched.
#[must_use]
pub(super) fn resolve_batch_script(interp: &Interpreter, prog: &str) -> Option<String> {
    match interp.resolve_external_or_batch_target(prog) {
        Some(crate::runtime::ResolvedCommandTarget::BatchScript { full_path }) => {
            Some(full_path.to_windows_string())
        }
        Some(
            crate::runtime::ResolvedCommandTarget::ExternalExecutable { .. }
            | crate::runtime::ResolvedCommandTarget::AssociatedDocument { .. },
        )
        | None => None,
    }
}

/// Built-in `GOTO` command (`GOTO [:]label` or `GOTO :EOF`).
///
/// # Arguments
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `GOTO` command.
///
/// # Returns
/// `Ok(FlowControl::Goto { target, span })` when a label argument is provided.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] if no label argument is supplied.
pub(super) fn cmd_goto(args: &[SpannedWord], cmd_span: Span) -> Result<FlowControl, CmdError> {
    let Some(first) = args.first() else {
        return Err(CmdError::SyntaxError { span: cmd_span });
    };
    let target = LabelName::new(first.unquoted());
    Ok(FlowControl::Goto {
        target,
        span: cmd_span,
    })
}

/// Built-in `SHIFT` command (`SHIFT [/0..8]`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
///
/// # Returns
/// [`FlowControl::Continue`].
pub(super) fn cmd_shift(interp: &mut Interpreter, args: &[SpannedWord]) -> FlowControl {
    let start_idx: usize = if let Some(first) = args.first()
        && let Some(num_str) = first.unquoted().strip_prefix('/')
        && let Ok(n) = num_str.parse::<usize>()
        && n <= 8
    {
        n
    } else {
        1
    };

    if let Some(frame) = interp.exec.top_call_frame_mut() {
        if start_idx == 0 {
            if let Some(first_pos) = frame.positional_args.first().cloned() {
                frame.arg0 = first_pos;
                frame.positional_args.remove(0);
            }
        } else {
            let vec_idx = start_idx.saturating_sub(1);
            if vec_idx < frame.positional_args.len() {
                frame.positional_args.remove(vec_idx);
            }
        }
    }
    interp.mark_cmd_succeeded();
    FlowControl::Continue
}

/// Built-in `EXIT` command (`EXIT [/B] [exitCode]`).
///
/// Matches `cmd.exe`'s `_tcstol` coercion: when no `exitCode` token is supplied, preserves
/// `interp.last_exit_code()`; when an `exitCode` token is supplied, parses its integer value
/// (coercing non-numeric strings such as `EXIT abc` to `0`).
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `exec_ctx` - Active [`ExecutionContext`].
///
/// # Returns
/// [`FlowControl::ExitBatchFrame`] when `/B` is specified in batch context, or [`FlowControl::ExitShell`].
#[must_use]
pub(super) fn cmd_exit(
    interp: &Interpreter,
    args: &[SpannedWord],
    exec_ctx: ExecutionContext,
) -> FlowControl {
    let mut batch_only = false;
    let mut explicit_code: Option<ExitCode> = None;

    for arg in args {
        let u = arg.unquoted();
        if u.eq_ignore_ascii_case("/B") {
            batch_only = true;
        } else {
            let n = u.trim().parse::<i32>().unwrap_or(0);
            explicit_code = Some(ExitCode::new(n));
        }
    }

    let code = explicit_code.unwrap_or_else(|| interp.last_exit_code());
    if batch_only && exec_ctx == ExecutionContext::BatchFile {
        FlowControl::ExitBatchFrame(code)
    } else if !batch_only
        && interp.exec.call_stack().is_empty()
        && interp.config.permanent_shell == crate::types::PermanentShellMode::Permanent
    {
        FlowControl::Continue
    } else {
        FlowControl::ExitShell(code)
    }
}

/// Built-in `PAUSE` command, flushing `"Press any key to continue . . . "` and reading a line from `stdin`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if writing or reading `io` fails.
pub(super) fn cmd_pause(
    interp: &mut Interpreter,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    io.write_stdout_str("Press any key to continue . . . ")?;
    io.read_stdin_line()?;
    io.write_stdout_str(CRLF)?;
    interp.mark_cmd_succeeded();
    Ok(FlowControl::Continue)
}

/// Strongly typed launch options parsed from `START` switches.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StartOptions {
    /// Optional `/D` working directory override.
    start_dir: Option<String>,
    /// `/WAIT` / `/W` vs asynchronous `Detached`.
    wait_mode: crate::types::WaitMode,
    /// `/B`, `/MIN`, `/MAX`, or `Normal` window creation mode.
    window_mode: crate::types::StartWindowMode,
    /// `/I` startup environment inheritance vs `CurrentEnv`.
    env_mode: crate::types::StartEnvMode,
    /// Scheduling priority class (`/LOW`, `/NORMAL`, `/HIGH`, `/REALTIME`, etc.).
    priority: crate::types::ProcessPriority,
    /// Index of the first non-switch command token, if any.
    first_cmd_idx: Option<usize>,
}

/// Parses `START` switches and optional `"Title"` argument into [`StartOptions`].
///
/// # Arguments
/// * `args` - Parsed argument words passed to `START`.
/// * `cmd_span` - Source [`Span`] of the `START` command.
///
/// # Returns
/// `Ok(StartOptions)` on valid switches.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] if `/D` lacks its required directory argument.
fn parse_start_options(args: &[SpannedWord], cmd_span: Span) -> Result<StartOptions, CmdError> {
    let mut idx = 0usize;
    let mut title_consumed = false;
    let mut opts = StartOptions {
        start_dir: None,
        wait_mode: crate::types::WaitMode::Detached,
        window_mode: crate::types::StartWindowMode::Normal,
        env_mode: crate::types::StartEnvMode::CurrentEnv,
        priority: crate::types::ProcessPriority::Normal,
        first_cmd_idx: None,
    };

    while let Some(arg) = args.get(idx) {
        let raw = &arg.text;
        let u = arg.unquoted();
        let upper = u.to_ascii_uppercase();

        if !title_consumed && raw.starts_with('"') && raw.ends_with('"') {
            title_consumed = true;
            idx = idx.saturating_add(1);
            continue;
        }
        match upper.as_str() {
            "/B" => opts.window_mode = crate::types::StartWindowMode::BackgroundNoWindow,
            "/MIN" => opts.window_mode = crate::types::StartWindowMode::Minimized,
            "/MAX" => opts.window_mode = crate::types::StartWindowMode::Maximized,
            "/WAIT" | "/W" => opts.wait_mode = crate::types::WaitMode::Wait,
            "/LOW" => opts.priority = crate::types::ProcessPriority::Low,
            "/NORMAL" => opts.priority = crate::types::ProcessPriority::Normal,
            "/HIGH" => opts.priority = crate::types::ProcessPriority::High,
            "/REALTIME" => opts.priority = crate::types::ProcessPriority::Realtime,
            "/ABOVENORMAL" => opts.priority = crate::types::ProcessPriority::AboveNormal,
            "/BELOWNORMAL" => opts.priority = crate::types::ProcessPriority::BelowNormal,
            "/SEPARATE" | "/SHARED" => {}
            "/I" => opts.env_mode = crate::types::StartEnvMode::InitialStartupEnv,
            "/D" => {
                let Some(next_dir) = args.get(idx.saturating_add(1)) else {
                    return Err(CmdError::SyntaxError { span: cmd_span });
                };
                opts.start_dir = Some(next_dir.unquoted().to_owned());
                idx = idx.saturating_add(2);
                continue;
            }
            "/NODE" | "/AFFINITY" => {
                idx = idx.saturating_add(2);
                continue;
            }
            _ if upper.starts_with("/D") => {
                opts.start_dir = Some(u.get(2..).unwrap_or("").trim_matches('"').to_owned());
            }
            _ => {
                opts.first_cmd_idx = Some(idx);
                break;
            }
        }
        idx = idx.saturating_add(1);
    }
    Ok(opts)
}

/// Built-in `START` command (`["title"] [/D path] [/I] [/MIN] [/MAX] [/WAIT | /W] [/B] [command] [args]`).
///
/// Slices `raw_tail` directly at the exact byte offset of the first non-switch command token so
/// multi-space strings and embedded quotes in `command [args]` are never collapsed or corrupted,
/// moves the VFS in `O(1)` without cloning files, restores parent drive/CWD isolation upon return,
/// and honors `/I` via [`crate::runtime::env::EnvironmentStack::restore_snapshot`].
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `raw_tail` - Raw post-command tail string.
/// * `raw_tail_base` - Starting [`ByteOffset`] of `raw_tail` in its source buffer.
/// * `cmd_span` - Source [`Span`] of the `START` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] if `/D` lacks a directory argument or [`CmdError`] if `/D` resolution fails.
pub(super) fn cmd_start(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    raw_tail: &str,
    raw_tail_base: ByteOffset,
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let opts = parse_start_options(args, cmd_span)?;
    let Some(cmd_start_idx) = opts.first_cmd_idx else {
        interp.record_success();
        return Ok(FlowControl::Continue);
    };
    let tail_args = args.get(cmd_start_idx..).unwrap_or(&[]);
    let cmd_line = slice_tail_from_arg(raw_tail, raw_tail_base, tail_args);

    let saved_cwds = crate::runtime::snapshot_vfs_cwds(interp.proc_env.vfs.as_ref());
    let startup_snap: Vec<(String, String)> = interp
        .proc_env
        .startup_env
        .list_visible()
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    let mut sub = interp.fork_subshell_taking_vfs();
    sub.config.start_wait_mode = opts.wait_mode;
    sub.config.start_window_mode = opts.window_mode;
    sub.config.start_env_mode = opts.env_mode;
    sub.config.start_priority = opts.priority;
    if opts.env_mode == crate::types::StartEnvMode::InitialStartupEnv {
        sub.proc_env.env.restore_snapshot(&startup_snap);
    }
    if let Some(dir_str) = opts.start_dir {
        let resolved = sub.proc_env.vfs.resolve_path(&dir_str);
        if let Err(err) = sub
            .proc_env
            .vfs
            .set_drive_cwd(&resolved)
            .and_then(|()| sub.proc_env.vfs.set_current_drive(resolved.drive))
        {
            interp.reclaim_subshell_vfs(sub, &saved_cwds);
            return Err(err);
        }
        sub.proc_env
            .env
            .set_drive_cwd_var(resolved.drive, &resolved);
    }

    let exec_res = sub.execute_interactive_line_checked(&cmd_line, io);
    interp.reclaim_subshell_vfs(sub, &saved_cwds);
    let code = exec_res?;
    interp.record_exit_code(code);
    Ok(FlowControl::Continue)
}

/// Extracts the exact lossless command tail substring starting at `remaining_args[0]`.
///
/// # Arguments
/// * `raw_tail` - Full post-program tail string.
/// * `raw_tail_base` - [`ByteOffset`] corresponding to byte `0` of `raw_tail`.
/// * `remaining_args` - Remaining command tokens starting with the target command.
///
/// # Returns
/// Exact substring of `raw_tail` preserving original quotes and spacing.
#[must_use]
fn slice_tail_from_arg(
    raw_tail: &str,
    raw_tail_base: ByteOffset,
    remaining_args: &[SpannedWord],
) -> String {
    let rel_start = remaining_args.first().map_or(0, |first| {
        first.span.start.0.saturating_sub(raw_tail_base.0)
    });
    raw_tail.get(rel_start..).unwrap_or("").to_owned()
}

/// Execution mode selected by nested `CMD` switches (`/C`, `/K`, or interactive).
#[derive(Debug, Clone, PartialEq, Eq)]
enum CmdSubshellAction {
    /// Interactive nested `CMD` session (prints version banner, then reads `stdin` until `EXIT` or EOF).
    Interactive,
    /// `/C <cmd>` — run command and terminate subshell immediately.
    RunAndExit(String),
    /// `/K <cmd>` — run command and remain open reading `stdin` until `EXIT` or EOF.
    RunAndStay(String),
}

/// Nested `CMD` / `CMD.EXE` subshell invocation (`/C`, `/K`, `/S`, `/Q`, `/D`, `/A`, `/U`, `/E`, `/V`).
///
/// Moves the VFS in `O(1)` without cloning files, restores parent drive/CWD isolation on exit,
/// reads live Registry `Command Processor` settings, and supports `/C`, `/K`, and bare interactive `CMD`.
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
/// Returns [`CmdError`] if writing version banner or executing the subshell fails.
pub(super) fn shim_cmd_subshell(
    interp: &mut Interpreter,
    raw_tail: &str,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let saved_cwds = crate::runtime::snapshot_vfs_cwds(interp.proc_env.vfs.as_ref());
    let mut sub = interp.fork_subshell_taking_vfs();
    sub.sync_processor_settings_from_registry();
    let mut strip_mode = QuoteStripMode::Heuristic;
    let mut autorun_mode = AutoRunMode::Run;
    let mut rest = raw_tail.trim_start();
    let mut action = CmdSubshellAction::Interactive;

    while !rest.is_empty() {
        let Some(after_slash) = rest.strip_prefix('/') else {
            break;
        };
        let flag_end = after_slash
            .find(|c: char| c.is_whitespace() || c == '/')
            .unwrap_or(after_slash.len());
        let flag_tok = after_slash.get(..flag_end).unwrap_or("");
        let upper = flag_tok.to_ascii_uppercase();
        let after_flag = after_slash.get(flag_end..).unwrap_or("").trim_start();

        match upper.as_str() {
            "C" => {
                action = CmdSubshellAction::RunAndExit(crate::cli::apply_cmd_c_quote_heuristic(
                    after_flag, strip_mode,
                ));
                break;
            }
            "K" => {
                action = CmdSubshellAction::RunAndStay(crate::cli::apply_cmd_c_quote_heuristic(
                    after_flag, strip_mode,
                ));
                break;
            }
            "S" => strip_mode = QuoteStripMode::AlwaysStrip,
            "Q" => sub.console.echo_state = EchoState::Off,
            "D" => autorun_mode = AutoRunMode::Skip,
            "A" => sub.config.unicode_output_mode = OutputUnicodeMode::Ansi,
            "U" => sub.config.unicode_output_mode = OutputUnicodeMode::Utf16Le,
            "E:ON" => sub.proc_env.env.extensions = ExtensionsMode::Enabled,
            "E:OFF" => sub.proc_env.env.extensions = ExtensionsMode::Disabled,
            "V:ON" => sub.proc_env.env.delayed_expansion = DelayedExpansionMode::Enabled,
            "V:OFF" => sub.proc_env.env.delayed_expansion = DelayedExpansionMode::Disabled,
            _ => {}
        }
        rest = after_flag;
    }

    let run_res = run_cmd_subshell_body(&mut sub, action, autorun_mode, io);
    interp.reclaim_subshell_vfs(sub, &saved_cwds);
    let code = run_res?;
    interp.record_exit_code(code);
    Ok(FlowControl::Continue)
}

/// Executes the configured `AutoRun` commands and `/C`, `/K`, or interactive body of `sub`.
///
/// # Arguments
/// * `sub` - Child [`Interpreter`] session.
/// * `action` - Parsed [`CmdSubshellAction`].
/// * `autorun_mode` - Whether Registry `AutoRun` executes.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(ExitCode)` produced by the subshell.
///
/// # Errors
/// Returns [`CmdError`] on fatal safety-limit aborts or stream I/O errors.
fn run_cmd_subshell_body(
    sub: &mut Interpreter,
    action: CmdSubshellAction,
    autorun_mode: AutoRunMode,
    io: &mut dyn CmdIo,
) -> Result<ExitCode, CmdError> {
    sub.run_autorun_if_enabled(autorun_mode, io);
    match action {
        CmdSubshellAction::RunAndExit(cmd_str) => {
            sub.execute_interactive_line_checked(&cmd_str, io)
        }
        CmdSubshellAction::RunAndStay(cmd_str) => {
            let mut last = sub.execute_interactive_line_checked(&cmd_str, io)?;
            if sub.exec.exited().is_none() {
                last = run_subshell_interactive_lines(sub, last, io)?;
            }
            Ok(last)
        }
        CmdSubshellAction::Interactive => {
            io.write_stdout_str(&format!("{}{CRLF}", sub.config.version_banner))?;
            run_subshell_interactive_lines(sub, ExitCode::SUCCESS, io)
        }
    }
}

/// Reads and executes lines from `io` inside an interactive `CMD` or `CMD /K` subshell until `EXIT` or EOF.
///
/// # Arguments
/// * `sub` - Child [`Interpreter`] session.
/// * `initial_code` - [`ExitCode`] returned if `stdin` immediately hits EOF.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// Final [`ExitCode`] of the subshell.
///
/// # Errors
/// Returns [`CmdError`] on `stdin` read failure or safety-limit abort.
fn run_subshell_interactive_lines(
    sub: &mut Interpreter,
    initial_code: ExitCode,
    io: &mut dyn CmdIo,
) -> Result<ExitCode, CmdError> {
    let mut last = initial_code;
    while let Some(line) = io.read_stdin_line()? {
        if line.trim().is_empty() {
            continue;
        }
        last = sub.execute_interactive_line_checked(&line, io)?;
        if let Some(exit_code) = sub.exec.exited() {
            return Ok(exit_code);
        }
    }
    Ok(last)
}
