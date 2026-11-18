//! Built-in command router (`BuiltinInvocation` & `dispatch_builtin`) and domain submodules.
//!
//! Decomposed into cohesive modules:
//! - `env_cmds`: `SET`, `SETLOCAL`, `ENDLOCAL`, `PATH`, `PROMPT`, `ASSOC`, `FTYPE`.
//! - `flow_cmds`: `CALL`, `GOTO`, `EXIT`, `SHIFT`, `PAUSE`, `CMD` subshell, `START`.
//! - `fs_cmds`: `DIR`, `CD`/`CHDIR`, `MD`/`MKDIR`, `RD`/`RMDIR`, `PUSHD`, `POPD`, `COPY`, `DEL`/`ERASE`, `REN`/`RENAME`, `MOVE`, `TYPE`, `MKLINK`.
//! - `console_cmds`: `ECHO`, `CLS`, `COLOR`, `TITLE`, `VER`, `VOL`, `DATE`, `TIME`, `VERIFY`, `CHCP`, `MODE`, `DOSKEY`.
//! - `dos_cmds`: MS-DOS `TRUENAME`, `CTTY`, `LH`/`LOADHIGH`, and `MEM` (`/C`, `/D`, `/F`, `/M`, `/P`).
//! - `shims_search`: `WHERE`, `FIND`, `FINDSTR`, `SORT`, `MORE`, `FC`, `COMP`, `TREE`.
//! - `shims_admin`: `XCOPY`, `ROBOCOPY`, `ATTRIB`, `CHOICE`, `TIMEOUT`, `REG`, `HOSTNAME`, `WHOAMI`.

mod console_cmds;
mod dos_cmds;
mod env_cmds;
mod flow_cmds;
mod fs_cmds;
mod shims_admin;
mod shims_search;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::CmdError;
use crate::parser::ast::SpannedWord;
use crate::parser::modifiers::strip_surrounding_quotes;
use crate::runtime::{
    CmdIo, ExternalSpawnRequest, FlowControl, Interpreter, ResolvedCommandTarget,
    parse_windows_command_line_argv,
};
use crate::span::{ByteOffset, Span};
use crate::types::{BS_CHAR, DriveLetter, ExecutionContext};
use crate::vfs::path::WindowsPath;

use self::console_cmds::{
    cmd_chcp, cmd_cls, cmd_color, cmd_date, cmd_doskey, cmd_echo, cmd_mode, cmd_time, cmd_title,
    cmd_ver, cmd_verify, cmd_vol,
};
use self::dos_cmds::{cmd_ctty, cmd_loadhigh, cmd_truename, shim_mem};
use self::env_cmds::{
    cmd_assoc, cmd_endlocal, cmd_ftype, cmd_path, cmd_prompt, cmd_set, cmd_setlocal,
};
use self::flow_cmds::{
    cmd_call, cmd_exit, cmd_goto, cmd_pause, cmd_shift, cmd_start, shim_cmd_subshell,
};
use self::fs_cmds::{
    cmd_cd, cmd_copy, cmd_del, cmd_dir, cmd_mkdir, cmd_mklink, cmd_move, cmd_popd, cmd_pushd,
    cmd_rename, cmd_rmdir, cmd_type,
};
use self::shims_admin::{
    shim_attrib, shim_choice, shim_hostname, shim_reg, shim_robocopy, shim_timeout, shim_whoami,
    shim_xcopy,
};
use self::shims_search::{
    shim_comp, shim_fc, shim_find, shim_findstr, shim_more, shim_sort, shim_tree, shim_where,
};

/// Bundled invocation descriptor passed to [`dispatch_builtin`].
#[derive(Debug, Clone, Copy)]
pub struct BuiltinInvocation<'a> {
    /// Expanded command name token (`ECHO`, `SET`, `C:`, `script.bat`, etc.).
    pub program: &'a str,
    /// Optional immediate delimiter character following `ECHO` (`'.'`, `'('`, `'/'`, etc.).
    pub echo_delimiter: Option<char>,
    /// Expanded argument tokens.
    pub args: &'a [SpannedWord],
    /// Expanded raw argument tail string.
    pub raw_tail: &'a str,
    /// Starting [`ByteOffset`] of `raw_tail` in its source buffer.
    pub raw_tail_start: ByteOffset,
    /// Source [`Span`] of the entire command invocation.
    pub cmd_span: Span,
    /// Active [`ExecutionContext`].
    pub exec_ctx: ExecutionContext,
}

/// Dispatches an expanded command invocation to a drive switch, internal `cmd.exe` command,
/// utility shim, VFS `.bat`/`.cmd` script, associated document (`ASSOC`/`FTYPE`), or external binary.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `inv` - [`BuiltinInvocation`] descriptor.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl)` upon command completion.
///
/// # Errors
/// Returns [`CmdError`] if drive switching, internal command validation, script execution,
/// or external process spawning fails.
pub fn dispatch_builtin(
    interp: &mut Interpreter,
    inv: &BuiltinInvocation<'_>,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let prog_unquoted = strip_surrounding_quotes(inv.program);
    let was_quoted = inv.program.starts_with('"');

    if !was_quoted
        && prog_unquoted.len() == 2
        && prog_unquoted.ends_with(':')
        && let Ok(drive) = DriveLetter::try_from_char(
            prog_unquoted
                .as_bytes()
                .first()
                .copied()
                .map_or(' ', char::from),
        )
    {
        interp.proc_env.vfs.set_current_drive(drive)?;
        interp.sync_active_host_cwd();
        interp.record_success();
        return Ok(FlowControl::Continue);
    }

    let upper = prog_unquoted.to_ascii_uppercase();
    if !was_quoted && let Some(flow) = try_dispatch_internal(interp, &upper, inv, io)? {
        return Ok(flow);
    }

    let has_path_sep = prog_unquoted.contains([BS_CHAR, '/']);
    let vfs_override = has_path_sep
        && interp
            .resolve_external_or_batch_target(prog_unquoted)
            .is_some();

    if !vfs_override && can_dispatch_shim_for_path(interp, prog_unquoted) {
        let leaf_raw = upper.rsplit([BS_CHAR, '/']).next().unwrap_or(&upper);
        let leaf_upper = leaf_raw
            .strip_suffix(".EXE")
            .or_else(|| leaf_raw.strip_suffix(".COM"))
            .unwrap_or(leaf_raw);
        if let Some(flow) = try_dispatch_shim(interp, leaf_upper, inv, io)? {
            return Ok(flow);
        }
    }

    dispatch_external_or_batch(interp, prog_unquoted, inv, io)
}

/// Checks whether `prog_unquoted` may resolve to a built-in utility shim.
///
/// Bare command names (`find`, `whoami.exe`) always qualify; explicit paths (`C:\dir\whoami.exe`)
/// qualify only when the parent directory is a standard Windows system root (`C:\Windows`,
/// `C:\Windows\System32`) or an existing directory on the active VFS!
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `prog_unquoted` - Unquoted program path or name.
///
/// # Returns
/// `true` if shim lookup is permitted for `prog_unquoted`.
#[must_use]
fn can_dispatch_shim_for_path(interp: &Interpreter, prog_unquoted: &str) -> bool {
    if !prog_unquoted.contains([BS_CHAR, '/']) {
        return true;
    }
    let resolved = interp.proc_env.vfs.resolve_path(prog_unquoted);
    let parent = resolved.parent();
    let parent_win = parent.to_windows_string();
    if parent_win.eq_ignore_ascii_case(r"C:\Windows\System32")
        || parent_win.eq_ignore_ascii_case(r"C:\Windows")
    {
        return true;
    }
    interp
        .proc_env
        .vfs
        .stat(&parent_win)
        .is_ok_and(|m| m.attributes.is_directory())
}

/// Attempts to dispatch `upper` as a core `cmd.exe` internal command.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `upper` - Uppercase unquoted command name.
/// * `inv` - [`BuiltinInvocation`] descriptor.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(Some(FlowControl))` if matched as an internal command, or `Ok(None)` otherwise.
///
/// # Errors
/// Propagates any [`CmdError`] returned by the matched internal command.
fn try_dispatch_internal(
    interp: &mut Interpreter,
    upper: &str,
    inv: &BuiltinInvocation<'_>,
    io: &mut dyn CmdIo,
) -> Result<Option<FlowControl>, CmdError> {
    let flow = match upper {
        "ECHO" => cmd_echo(interp, inv.echo_delimiter, inv.raw_tail, io)?,
        "SET" => cmd_set(interp, inv.raw_tail, inv.cmd_span, inv.exec_ctx, io)?,
        "SETLOCAL" => cmd_setlocal(interp, inv.args, inv.cmd_span)?,
        "ENDLOCAL" => cmd_endlocal(interp),
        "CD" | "CHDIR" => cmd_cd(interp, inv.raw_tail, io)?,
        "MD" | "MKDIR" => cmd_mkdir(interp, inv.args, inv.cmd_span)?,
        "RD" | "RMDIR" => cmd_rmdir(interp, inv.args, inv.cmd_span, io)?,
        "PUSHD" => cmd_pushd(interp, inv.raw_tail, io)?,
        "POPD" => cmd_popd(interp),
        "DIR" => cmd_dir(interp, inv.args, io)?,
        "TYPE" => cmd_type(interp, inv.args, inv.cmd_span, io)?,
        "COPY" => cmd_copy(interp, inv.args, inv.cmd_span, io)?,
        "DEL" | "ERASE" => cmd_del(interp, inv.args, inv.cmd_span, io)?,
        "REN" | "RENAME" => cmd_rename(interp, inv.args, inv.cmd_span)?,
        "MOVE" => cmd_move(interp, inv.args, inv.cmd_span, io)?,
        "MKLINK" => cmd_mklink(interp, inv.args, inv.cmd_span, io)?,
        "CALL" => cmd_call(
            interp,
            inv.args,
            inv.raw_tail,
            inv.raw_tail_start,
            inv.cmd_span,
            io,
        )?,
        "GOTO" => cmd_goto(inv.args, inv.cmd_span)?,
        "SHIFT" => cmd_shift(interp, inv.args),
        "EXIT" => cmd_exit(interp, inv.args, inv.exec_ctx),
        "VER" => cmd_ver(interp, inv.args, io)?,
        "VOL" => cmd_vol(interp, inv.args, io)?,
        "CLS" => cmd_cls(interp, io)?,
        "COLOR" => cmd_color(interp, inv.args)?,
        "TITLE" => cmd_title(interp, inv.raw_tail),
        "PAUSE" => cmd_pause(interp, io)?,
        "PATH" => cmd_path(interp, inv.raw_tail, io)?,
        "PROMPT" => cmd_prompt(interp, inv.raw_tail),
        "DATE" => cmd_date(interp, inv.args, io)?,
        "TIME" => cmd_time(interp, inv.args, io)?,
        "VERIFY" => cmd_verify(interp, inv.args, io)?,
        "TRUENAME" => cmd_truename(interp, inv.args, io)?,
        "CTTY" => cmd_ctty(interp, inv.args, io)?,
        "LH" | "LOADHIGH" => cmd_loadhigh(interp, inv.raw_tail, io)?,
        "ASSOC" => cmd_assoc(interp, inv.raw_tail, io)?,
        "FTYPE" => cmd_ftype(interp, inv.raw_tail, io)?,
        "START" => cmd_start(
            interp,
            inv.args,
            inv.raw_tail,
            inv.raw_tail_start,
            inv.cmd_span,
            io,
        )?,
        "CHCP" => cmd_chcp(interp, inv.args, io)?,
        "DOSKEY" => cmd_doskey(interp, inv.args, inv.raw_tail, io)?,
        "MODE" => cmd_mode(interp, inv.args, io)?,
        _ => return Ok(None),
    };
    Ok(Some(flow))
}

/// Attempts to dispatch `leaf_upper` as a cross-platform Windows utility shim.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `leaf_upper` - Uppercase executable stem without `.EXE`.
/// * `inv` - [`BuiltinInvocation`] descriptor.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(Some(FlowControl))` if matched as a built-in utility shim, or `Ok(None)` otherwise.
///
/// # Errors
/// Propagates any [`CmdError`] returned by the matched utility shim.
fn try_dispatch_shim(
    interp: &mut Interpreter,
    leaf_upper: &str,
    inv: &BuiltinInvocation<'_>,
    io: &mut dyn CmdIo,
) -> Result<Option<FlowControl>, CmdError> {
    let flow = match leaf_upper {
        "CMD" => shim_cmd_subshell(interp, inv.raw_tail, io)?,
        "REG" => shim_reg(interp, inv.args, io)?,
        "WHERE" => shim_where(interp, inv.args, inv.cmd_span, io)?,
        "FIND" => shim_find(interp, inv.args, inv.cmd_span, io)?,
        "FINDSTR" => shim_findstr(interp, inv.args, inv.cmd_span, io)?,
        "MORE" => shim_more(interp, inv.args, io)?,
        "SORT" => shim_sort(interp, inv.args, io)?,
        "CHOICE" => shim_choice(interp, inv.args, inv.cmd_span, io)?,
        "TIMEOUT" => shim_timeout(interp, inv.args, inv.cmd_span, io)?,
        "ATTRIB" => shim_attrib(interp, inv.args, io)?,
        "XCOPY" => shim_xcopy(interp, inv.args, io)?,
        "ROBOCOPY" => shim_robocopy(interp, inv.args, io)?,
        "FC" => shim_fc(interp, inv.args, inv.cmd_span, io)?,
        "COMP" => shim_comp(interp, inv.args, inv.cmd_span, io)?,
        "TREE" => shim_tree(interp, inv.args, io)?,
        "HOSTNAME" => shim_hostname(interp, io)?,
        "WHOAMI" => shim_whoami(interp, io)?,
        "MEM" => shim_mem(interp, inv.args, io)?,
        _ => return Ok(None),
    };
    Ok(Some(flow))
}

/// Resolves and executes a `.bat`/`.cmd` script, `ASSOC`/`FTYPE` document, or external OS process.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `prog_unquoted` - Unquoted program name.
/// * `inv` - [`BuiltinInvocation`] descriptor.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl)` on completion.
///
/// # Errors
/// Returns [`CmdError::CommandNotRecognized`] if unrecognized or [`CmdError`] on execution failure.
fn dispatch_external_or_batch(
    interp: &mut Interpreter,
    prog_unquoted: &str,
    inv: &BuiltinInvocation<'_>,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    if let Some(resolved) = interp.resolve_external_or_batch_target(prog_unquoted) {
        match resolved {
            ResolvedCommandTarget::BatchScript { full_path } => {
                let bat_path = full_path.to_windows_string();
                let pos_args: Vec<String> =
                    inv.args.iter().map(|w| w.unquoted().to_owned()).collect();
                if inv.exec_ctx == ExecutionContext::BatchFile {
                    return Ok(FlowControl::TransferBatchFrame {
                        script_path: bat_path,
                        arg0: prog_unquoted.to_owned(),
                        positional_args: pos_args,
                        all_args_raw: inv.raw_tail.to_owned(),
                    });
                }
                let code = interp.execute_batch_file(
                    &bat_path,
                    prog_unquoted,
                    pos_args,
                    inv.raw_tail.to_owned(),
                    io,
                )?;
                interp.record_exit_code(code);
                return Ok(FlowControl::Continue);
            }
            ResolvedCommandTarget::AssociatedDocument {
                full_path,
                command_template,
                ..
            } => {
                let doc_str = full_path.to_windows_string();
                let cmd_str = expand_ftype_command_template(
                    &command_template,
                    &doc_str,
                    inv.args,
                    inv.raw_tail,
                );
                let code = interp.execute_interactive_line_checked(&cmd_str, io)?;
                interp.record_exit_code(code);
                return Ok(FlowControl::Continue);
            }
            ResolvedCommandTarget::ExternalExecutable {
                full_path,
                host_path,
            } => {
                let cur_drive = interp.proc_env.vfs.current_drive();
                let fallback_root = WindowsPath::root(cur_drive);
                let cwd_vfs = interp
                    .proc_env
                    .vfs
                    .drive_cwd(cur_drive)
                    .unwrap_or(fallback_root);
                let cwd_host = interp.proc_env.vfs.resolve_host_path(&cwd_vfs);
                let env_vars: Vec<(String, String)> = interp
                    .proc_env
                    .env
                    .build_child_process_env(
                        interp.proc_env.vfs.as_ref(),
                        interp.exec.last_exit_code(),
                    )
                    .into_iter()
                    .collect();
                let argv = parse_windows_command_line_argv(inv.raw_tail);
                let stdin_bytes = io.read_stdin_bytes(interp.console.codepage)?;
                let stdin_text = String::from_utf8_lossy(&stdin_bytes).into_owned();

                let req = ExternalSpawnRequest {
                    program_vfs_path: full_path,
                    program_host_path: host_path,
                    args: argv,
                    raw_tail: inv.raw_tail.to_owned(),
                    cwd_vfs,
                    cwd_host,
                    env_vars,
                    stdin: stdin_text,
                    stdin_bytes,
                    wait_mode: interp.config.start_wait_mode,
                    window_mode: interp.config.start_window_mode,
                    env_mode: interp.config.start_env_mode,
                    priority: interp.config.start_priority,
                };
                let res = interp.proc_env.spawner.spawn_external(&req)?;
                if !res.stdout.is_empty() {
                    io.write_stdout_str(&res.stdout)?;
                }
                if !res.stderr.is_empty() {
                    io.write_stderr_str(&res.stderr)?;
                }
                interp.record_exit_code(res.exit_code);
                return Ok(FlowControl::Continue);
            }
        }
    }

    Err(CmdError::CommandNotRecognized {
        span: inv.cmd_span,
        command: prog_unquoted.to_owned(),
    })
}

/// Expands an `FTYPE` open-command template (`%0`, `%1`, `%2`..`%9`, `%*`, `%%`) in a single pass
/// so `%1` never corrupts `%10` and substituted paths containing `%` tokens are never re-expanded.
///
/// # Arguments
/// * `template` - Raw `FTYPE` command template string.
/// * `doc_str` - Resolved Windows path of the associated document (`%0` / `%1`).
/// * `args` - Parsed trailing arguments (`%2`..`%9`).
/// * `raw_tail` - Raw post-document argument tail (`%*`).
///
/// # Returns
/// Expanded command line ready for execution.
#[must_use]
fn expand_ftype_command_template(
    template: &str,
    doc_str: &str,
    args: &[SpannedWord],
    raw_tail: &str,
) -> String {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::with_capacity(template.len().saturating_add(doc_str.len()));
    let mut idx = 0usize;
    let mut in_quotes = false;

    while let Some(&ch) = chars.get(idx) {
        if ch == '"' {
            in_quotes = !in_quotes;
            out.push('"');
            idx = idx.saturating_add(1);
            continue;
        }
        if ch == '%'
            && let Some(&next) = chars.get(idx.saturating_add(1))
        {
            match next {
                '%' => {
                    out.push('%');
                    idx = idx.saturating_add(2);
                    continue;
                }
                '*' => {
                    out.push_str(raw_tail.trim());
                    idx = idx.saturating_add(2);
                    continue;
                }
                '0'..='9'
                    if !chars
                        .get(idx.saturating_add(2))
                        .is_some_and(char::is_ascii_digit) =>
                {
                    if next == '0' || next == '1' {
                        if !in_quotes && doc_str.contains(' ') {
                            out.push('"');
                            out.push_str(doc_str);
                            out.push('"');
                        } else {
                            out.push_str(doc_str);
                        }
                    } else {
                        let arg_idx = (next as usize).saturating_sub('2' as usize);
                        if let Some(w) = args.get(arg_idx) {
                            out.push_str(w.unquoted());
                        }
                    }
                    idx = idx.saturating_add(2);
                    continue;
                }
                _ => {}
            }
        }
        out.push(ch);
        idx = idx.saturating_add(1);
    }
    out
}

#[cfg(test)]
/// Unit tests for built-in `cmd.exe` commands and cross-platform Windows utility shims.
mod tests {
    use crate::runtime::{Interpreter, IoStreams};
    use crate::types::{BS_STR, CRLF, DriveLetter, ExitCode, ExtensionsMode, TAB_CHAR};
    use crate::vfs::FileTimestamp;

    /// Helper executing `cmd` on `interp` with fresh `IoStreams` and returning `(ExitCode, stdout, stderr)`.
    ///
    /// # Arguments
    /// * `interp` - Mutable [`Interpreter`] session.
    /// * `cmd` - Interactive command line to execute.
    ///
    /// # Returns
    /// Tuple of `(ExitCode, stdout, stderr)`.
    fn run_cmd(interp: &mut Interpreter, cmd: &str) -> (ExitCode, String, String) {
        let mut io = IoStreams::new();
        let code = interp.execute_interactive_line(cmd, &mut io);
        (code, io.stdout, io.stderr)
    }

    /// Helper executing `cmd` with pre-populated `stdin` and returning `(ExitCode, stdout, stderr)`.
    ///
    /// # Arguments
    /// * `interp` - Mutable [`Interpreter`] session.
    /// * `cmd` - Interactive command line to execute.
    /// * `stdin` - Pre-populated standard input buffer.
    ///
    /// # Returns
    /// Tuple of `(ExitCode, stdout, stderr)`.
    fn run_cmd_with_stdin(
        interp: &mut Interpreter,
        cmd: &str,
        stdin: &str,
    ) -> (ExitCode, String, String) {
        let mut io = IoStreams::with_stdin(stdin.to_owned());
        let code = interp.execute_interactive_line(cmd, &mut io);
        (code, io.stdout, io.stderr)
    }

    /// Verifies `SET`, `SET /A`, `SET /P`, `SETLOCAL`, `ENDLOCAL`, `PATH`, `PROMPT`, `ASSOC`, and `FTYPE`.
    #[test]
    fn test_env_and_association_builtins() {
        let mut interp = Interpreter::new();
        assert_eq!(
            run_cmd(&mut interp, r#"set "FOO=hello world""#),
            (ExitCode::SUCCESS, String::new(), String::new())
        );
        assert_eq!(interp.lookup_var("FOO"), Some("hello world".to_owned()));

        let (code_all, out_all, _) = run_cmd(&mut interp, "set");
        assert_eq!(code_all, ExitCode::SUCCESS);
        assert!(out_all.contains("FOO=hello world"));

        assert_eq!(
            run_cmd(&mut interp, "set FO"),
            (
                ExitCode::SUCCESS,
                format!("FOO=hello world{CRLF}"),
                String::new()
            )
        );
        assert_eq!(
            run_cmd(&mut interp, "set NONEXISTENT_XYZ"),
            (
                ExitCode::FAILURE,
                String::new(),
                format!("Environment variable NONEXISTENT_XYZ not defined{CRLF}")
            )
        );
        assert_eq!(
            run_cmd(&mut interp, "set =bad"),
            (
                ExitCode::FAILURE,
                String::new(),
                format!("The syntax of the command is incorrect.{CRLF}")
            )
        );
        assert_eq!(
            run_cmd(&mut interp, r#"set "UNCLOSED=val"#),
            (ExitCode::SUCCESS, String::new(), String::new())
        );
        assert_eq!(interp.lookup_var("UNCLOSED"), Some("val".to_owned()));

        assert_eq!(
            run_cmd(&mut interp, "set /a RES=6*7"),
            (ExitCode::SUCCESS, "42".to_owned(), String::new())
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                r#"set /p "USER_IN=Name: ""#,
                &format!("Alice{CRLF}")
            ),
            (ExitCode::SUCCESS, "Name: ".to_owned(), String::new())
        );
        assert_eq!(interp.lookup_var("USER_IN"), Some("Alice".to_owned()));
        assert_eq!(
            run_cmd_with_stdin(&mut interp, r#"set /p "Q_IN=Ask: ""#, CRLF),
            (ExitCode::FAILURE, "Ask: ".to_owned(), String::new())
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "set /p EOF_IN=", ""),
            (ExitCode::FAILURE, String::new(), String::new())
        );
        assert_eq!(run_cmd(&mut interp, "set /p NO_EQ").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "set /p =Prompt").0, ExitCode::FAILURE);

        assert_eq!(
            run_cmd(
                &mut interp,
                "setlocal EnableDelayedExpansion EnableExtensions"
            ),
            (ExitCode::SUCCESS, String::new(), String::new())
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                "setlocal DisableDelayedExpansion DisableExtensions"
            ),
            (ExitCode::SUCCESS, String::new(), String::new())
        );
        assert_eq!(
            run_cmd(&mut interp, "setlocal BOGUS_OPT").0,
            ExitCode::FAILURE
        );
        assert_eq!(run_cmd(&mut interp, "endlocal").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "endlocal").0, ExitCode::FAILURE);
    }

    /// Verifies `PATH`, `PROMPT`, `ASSOC`, and `FTYPE` built-ins.
    #[test]
    fn test_path_prompt_assoc_and_ftype_builtins() {
        let mut interp = Interpreter::new();
        assert_eq!(run_cmd(&mut interp, "path ;").0, ExitCode::SUCCESS);
        assert_eq!(interp.lookup_var("PATH"), None);
        assert_eq!(run_cmd(&mut interp, "path =C:/Tools").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, "path"),
            (
                ExitCode::SUCCESS,
                format!("PATH=C:/Tools{CRLF}"),
                String::new()
            )
        );
        assert_eq!(run_cmd(&mut interp, "prompt $P$G").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "prompt").0, ExitCode::SUCCESS);

        assert!(run_cmd(&mut interp, "assoc").1.contains(".bat=batfile"));
        assert_eq!(
            run_cmd(&mut interp, "assoc .xyz=xyzfile"),
            (
                ExitCode::SUCCESS,
                format!(".xyz=xyzfile{CRLF}"),
                String::new()
            )
        );
        assert_eq!(
            run_cmd(&mut interp, "assoc xyz"),
            (
                ExitCode::SUCCESS,
                format!(".xyz=xyzfile{CRLF}"),
                String::new()
            )
        );
        assert_eq!(run_cmd(&mut interp, "assoc .xyz=").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "assoc .xyz").0, ExitCode::FAILURE);

        assert!(run_cmd(&mut interp, "ftype").1.contains("batfile="));
        assert_eq!(
            run_cmd(&mut interp, "ftype xyzfile=app.exe %1"),
            (
                ExitCode::SUCCESS,
                format!("xyzfile=app.exe %1{CRLF}"),
                String::new()
            )
        );
        assert_eq!(
            run_cmd(&mut interp, "ftype xyzfile"),
            (
                ExitCode::SUCCESS,
                format!("xyzfile=app.exe %1{CRLF}"),
                String::new()
            )
        );
        assert_eq!(run_cmd(&mut interp, "ftype xyzfile=").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "ftype xyzfile").0, ExitCode::FAILURE);
    }

    /// Verifies `CALL` (indirect `%^PTR%` twice-expansion, `:label`, script, tail-call),
    /// `GOTO`, `SHIFT`, `EXIT`, `PAUSE`, `CMD`, and lossless `START` multi-space preservation.
    #[test]
    fn test_flow_and_subshell_builtins() {
        let mut interp = Interpreter::new();
        assert_eq!(run_cmd(&mut interp, "call").0, ExitCode::SUCCESS);

        // Indirect twice-expansion in batch `call echo %%%PTR%%%` (pass 1 -> %REAL_VAR%, pass 2 -> indirect_ok)
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/indirect.bat",
                format!(
                    "@echo off{CRLF}set REAL_VAR=indirect_ok{CRLF}set PTR=REAL_VAR{CRLF}call echo %%%PTR%%%{CRLF}"
                )
                .as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "C:/indirect.bat"),
            (
                ExitCode::SUCCESS,
                format!("indirect_ok{CRLF}"),
                String::new()
            )
        );

        // Lossless START preserving multiple internal spaces & `/D` / `/I` / switches
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/st_dir", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"start "My Title" /B /WAIT /MIN /NODE 0 /D C:/st_dir echo a   b   "c   d""#
            ),
            (
                ExitCode::SUCCESS,
                format!(r#"a   b   "c   d"{CRLF}"#),
                String::new()
            )
        );
        assert_eq!(
            run_cmd(&mut interp, r#"start "Only Title""#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "start /I /DC:/st_dir cd"),
            (
                ExitCode::SUCCESS,
                format!("C:{BS_STR}st_dir{CRLF}"),
                String::new()
            )
        );
        assert_eq!(run_cmd(&mut interp, "start /D").0, ExitCode::FAILURE);
    }

    /// Verifies `CMD` subshell flags, `PAUSE`, `EXIT /B`, and unknown-command dispatch.
    #[test]
    fn test_cmd_subshell_pause_and_exit_builtins() {
        let mut interp = Interpreter::new();
        // CMD subshell flags and banner
        assert!(run_cmd(&mut interp, "cmd").1.contains("Microsoft Windows"));
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"cmd /S /Q /D /A /U /E:OFF /E:ON /V:OFF /V:ON /C "set Z=sub_ok& echo !Z!""#
            ),
            (ExitCode::SUCCESS, format!("sub_ok{CRLF}"), String::new())
        );

        assert_eq!(
            run_cmd_with_stdin(&mut interp, "pause", CRLF),
            (
                ExitCode::SUCCESS,
                format!("Press any key to continue . . . {CRLF}"),
                String::new()
            )
        );
        assert_eq!(run_cmd(&mut interp, "goto").0, ExitCode::FAILURE);

        // Batch CALL :sub, SHIFT /0 & /1, tail-call chaining without CALL, EXIT /B
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/tail.bat",
                format!("@echo off{CRLF}echo tail:%1{CRLF}").as_bytes()
            ),
            Ok(())
        );
        let main_bat = [
            "@echo off",
            "call :sub first second third",
            "C:/tail.bat chained_arg",
            "echo unreachable_after_tail",
            "goto :EOF",
            ":sub",
            "shift /1",
            "echo sub_after_shift1:%0:%1:%2",
            "shift /0",
            "echo sub_after_shift0:%0:%1",
            "exit /b 0",
        ]
        .join(CRLF);
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/main.bat", main_bat.as_bytes()),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "C:/main.bat"),
            (
                ExitCode::SUCCESS,
                format!(
                    "sub_after_shift1::sub:second:third{CRLF}sub_after_shift0:second:third{CRLF}tail:chained_arg{CRLF}"
                ),
                String::new()
            )
        );

        // CALL :sub rejected when `/E:OFF`
        interp.proc_env.env.extensions = ExtensionsMode::Disabled;
        assert_eq!(run_cmd(&mut interp, "call :sub").0, ExitCode::FAILURE);
        interp.proc_env.env.extensions = ExtensionsMode::Enabled;

        // CALL exit 9 propagates ExitShell
        assert_eq!(run_cmd(&mut interp, "call exit 9").0, ExitCode::new(9));
        interp.exec.clear_exited();
    }

    /// Verifies `DIR` chronological `/O:D` sorting, `CD`, `MD`, `RD`, `PUSHD`/`POPD` (including UNC),
    /// `TYPE` encoding error propagation, `COPY`, `DEL`, `REN`, `MOVE`, and `MKLINK`.
    #[test]
    fn test_filesystem_builtins_chronological_dir_and_error_propagation() {
        let mut interp = Interpreter::new();
        assert_eq!(run_cmd(&mut interp, "D:").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "C:").0, ExitCode::SUCCESS);

        assert_eq!(run_cmd(&mut interp, "md").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "md C:/fs/sub").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "cd").1, format!("C:{BS_STR}{CRLF}"));
        assert_eq!(run_cmd(&mut interp, "cd C:").1, format!("C:{BS_STR}{CRLF}"));
        assert_eq!(run_cmd(&mut interp, "cd /d C:/fs").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "cd ..").0, ExitCode::SUCCESS);

        // PUSHD / POPD including UNC temporary drive mount
        let unc = format!("{BS_STR}{BS_STR}filesrv{BS_STR}share{BS_STR}docs");
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir(&unc, crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, &format!("pushd {unc}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(interp.proc_env.vfs.current_drive(), DriveLetter::Z);
        assert!(run_cmd(&mut interp, "pushd").1.contains("C:"));
        assert_eq!(run_cmd(&mut interp, "popd").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "pushd C:/fs").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "popd").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "popd").0, ExitCode::FAILURE);

        // Chronological DIR /O:D (1999 before 2025, even though "12/31/1999" > "01/02/2025" lexicographically!)
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/fs/old_dec99.txt", b"old"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.touch_file(
                "C:/fs/old_dec99.txt",
                FileTimestamp::from_civil_utc(1999, 12, 31, 23, 59).unwrap_or_default()
            ),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/fs/new_jan25.txt", b"new_longer"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.touch_file(
                "C:/fs/new_jan25.txt",
                FileTimestamp::from_civil_utc(2025, 1, 2, 8, 0).unwrap_or_default()
            ),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "dir /b /o:d /a:-d C:/fs"),
            (
                ExitCode::SUCCESS,
                format!("old_dec99.txt{CRLF}new_jan25.txt{CRLF}"),
                String::new()
            )
        );
        assert_eq!(
            run_cmd(&mut interp, "dir /b /o:-d /a:-d C:/fs"),
            (
                ExitCode::SUCCESS,
                format!("new_jan25.txt{CRLF}old_dec99.txt{CRLF}"),
                String::new()
            )
        );
        interp.proc_env.env.set("DIRCMD", "/L");
        assert!(
            run_cmd(&mut interp, "dir /w /o:s C:/fs")
                .1
                .contains("[sub]")
        );
        assert!(
            run_cmd(&mut interp, "dir /x /o:e /s C:/fs")
                .1
                .contains("old_dec99.txt")
        );
        assert!(
            run_cmd(&mut interp, "dir /o:g /a:d C:/fs")
                .1
                .contains("sub")
        );
        assert_eq!(
            run_cmd(&mut interp, "dir C:/fs/*.nope").0,
            ExitCode::FAILURE
        );
        interp.proc_env.env.remove("DIRCMD");

        // TYPE reports EncodingFailure on invalid UTF-8 instead of empty output!
        assert_eq!(run_cmd(&mut interp, "type").0, ExitCode::FAILURE);
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/fs/bad_enc.txt", &[0xFF, 0xFE, 0x00]),
            Ok(())
        );
        let (type_err_code, type_out, type_err) = run_cmd(&mut interp, "type C:/fs/bad_enc.txt");
        assert_eq!(type_err_code, ExitCode::FAILURE);
        assert_eq!(type_out, "");
        assert!(type_err.contains("Encoding failure"));
        assert_eq!(
            interp.proc_env.vfs.delete_file(
                "C:/fs/bad_enc.txt",
                crate::types::ReadOnlyDeletePolicy::ForceDeleteReadOnly
            ),
            Ok(())
        );

        let (_, multi_type_out, multi_type_err) =
            run_cmd(&mut interp, "type C:/fs/old_dec99.txt C:/fs/new_jan25.txt");
        assert_eq!(multi_type_out, "oldnew_longer");
        assert!(multi_type_err.contains("old_dec99.txt"));
    }

    /// Verifies `COPY`, `REN`, `MOVE`, `MKLINK`, `DEL`, and `RD` built-ins.
    #[test]
    fn test_copy_ren_move_mklink_del_and_rd_builtins() {
        let mut interp = Interpreter::new();
        assert_eq!(run_cmd(&mut interp, "md C:/fs/sub").0, ExitCode::SUCCESS);
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/fs/old_dec99.txt", b"old"),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/fs/new_jan25.txt", b"new_longer"),
            Ok(())
        );

        // COPY (/A, /V, /-Y, + concat, wildcards, self-copy), REN, MOVE, MKLINK, DEL, RD
        assert_eq!(run_cmd(&mut interp, "copy").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd(&mut interp, "copy C:/fs/old_dec99.txt C:/fs/old_dec99.txt").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, "copy C:/fs/*.txt C:/fs").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                "copy /a /v C:/fs/old_dec99.txt+C:/fs/new_jan25.txt C:/fs/cat.txt"
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "copy /a /v C:/fs/cat.txt C:/fs/cat2.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "copy /-y C:/fs/cat.txt C:/fs/cat2.txt",
                &format!("N{CRLF}")
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "copy /b /y C:/fs/*.txt C:/fs/sub").0,
            ExitCode::SUCCESS
        );

        assert_eq!(
            run_cmd(&mut interp, "ren C:/fs/cat2.txt").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, "ren C:/fs/cat2.txt C:/bad.txt").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, "ren C:/fs/cat2.txt ?at_ren.*").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "ren C:/fs/*.nope *.bak").0,
            ExitCode::FAILURE
        );

        assert_eq!(
            run_cmd(&mut interp, "move C:/fs/cat_ren.txt").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "move /-y C:/fs/cat_ren.txt C:/fs/cat.txt",
                &format!("N{CRLF}")
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "move /y C:/fs/cat_ren.txt C:/fs/cat.txt").0,
            ExitCode::SUCCESS
        );

        assert_eq!(
            run_cmd(&mut interp, "mklink C:/fs/only_one").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, "mklink C:/fs/sym.txt C:/fs/cat.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "mklink /h C:/fs/hard.txt C:/fs/cat.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "mklink /d C:/fs/symd C:/fs/sub").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "mklink /j C:/fs/junc C:/fs/sub").0,
            ExitCode::SUCCESS
        );

        assert_eq!(run_cmd(&mut interp, "del").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "del /p C:/fs/sym.txt", &format!("N{CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert!(interp.proc_env.vfs.exists("C:/fs/sym.txt"));
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "del C:/fs/sub/*", &format!("Y{CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "del /f /q C:/fs/sym.txt").0,
            ExitCode::SUCCESS
        );

        assert_eq!(run_cmd(&mut interp, "rd").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "rd /s C:/fs/sub", &format!("N{CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(run_cmd(&mut interp, "rd /s /q C:/fs").0, ExitCode::SUCCESS);
    }

    /// Verifies `ECHO`, `CLS`, `COLOR`, `TITLE`, `VER`, `VOL`, `DATE`, `TIME`, `VERIFY`,
    /// `CHCP` (`ParameterFormatNotCorrect` vs `InvalidCodePage`), `MODE`, and `DOSKEY`.
    #[test]
    fn test_console_builtins_and_chcp_error_fidelity() {
        let mut interp = Interpreter::new();
        assert_eq!(run_cmd(&mut interp, "echo").1, format!("ECHO is on.{CRLF}"));
        assert_eq!(run_cmd(&mut interp, "echo off").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, "echo").1,
            format!("ECHO is off.{CRLF}")
        );
        assert_eq!(run_cmd(&mut interp, "echo on").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, "echo.dot_line").1,
            format!("dot_line{CRLF}")
        );

        assert!(run_cmd(&mut interp, "ver").1.contains("Microsoft Windows"));
        assert!(
            run_cmd(&mut interp, "vol")
                .1
                .contains("Volume Serial Number")
        );
        assert!(
            run_cmd(&mut interp, "vol C:")
                .1
                .contains("Volume Serial Number")
        );
        assert_eq!(run_cmd(&mut interp, "cls").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "color 0A").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "color").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "color AA").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd(&mut interp, "title Custom Console").0,
            ExitCode::FAILURE
        );
        assert!(interp.last_cmd_succeeded());
        assert_eq!(interp.console.console_title, "Custom Console");
        assert_eq!(run_cmd(&mut interp, "color 07").0, ExitCode::SUCCESS);

        assert_eq!(run_cmd(&mut interp, "date /t").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "date 02/03/2026").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "date", &format!("03/04/2026{CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(interp.proc_env.env.virtual_date, "03/04/2026");

        assert_eq!(run_cmd(&mut interp, "time /t").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, "time 09:15:00.00").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "time", &format!("10:30:00.00{CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(interp.proc_env.env.virtual_time, "10:30:00.00");

        assert_eq!(run_cmd(&mut interp, "verify on").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, "verify").1,
            format!("VERIFY is on.{CRLF}")
        );
        assert_eq!(run_cmd(&mut interp, "verify off").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "verify bogus").0, ExitCode::FAILURE);
    }

    /// Verifies `CHCP` numeric/non-numeric error fidelity, `MODE`, and `DOSKEY` macros/history.
    #[test]
    fn test_chcp_mode_and_doskey_builtins() {
        let mut interp = Interpreter::new();
        // CHCP non-numeric preserves offending parameter (`Parameter format not correct - abc.`)
        // while numeric unsupported preserves code (`Invalid code page`)!
        assert_eq!(
            run_cmd(&mut interp, "chcp"),
            (
                ExitCode::SUCCESS,
                format!("Active code page: 65001{CRLF}"),
                String::new()
            )
        );
        assert_eq!(
            run_cmd(&mut interp, "chcp abc"),
            (
                ExitCode::FAILURE,
                String::new(),
                format!("Parameter format not correct - abc.{CRLF}")
            )
        );
        assert_eq!(
            run_cmd(&mut interp, "chcp 99999"),
            (
                ExitCode::FAILURE,
                String::new(),
                format!("Invalid code page{CRLF}")
            )
        );
        assert_eq!(run_cmd(&mut interp, "chcp 437").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "chcp 65001").0, ExitCode::SUCCESS);

        assert!(
            run_cmd(&mut interp, "mode")
                .1
                .contains("Status for device CON:")
        );
        assert_eq!(
            run_cmd(&mut interp, "mode con: cols=100 lines=40").0,
            ExitCode::SUCCESS
        );
        assert_eq!(run_cmd(&mut interp, "mode 120,50").0, ExitCode::SUCCESS);
        assert_eq!(interp.console.console_cols, 120);
        assert_eq!(interp.console.console_lines, 50);

        assert_eq!(run_cmd(&mut interp, "doskey").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, "doskey ll=dir /b").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "doskey /macros").1,
            format!("ll=dir /b{CRLF}")
        );
        assert!(run_cmd(&mut interp, "doskey /history").1.contains("doskey"));
        assert_eq!(
            run_cmd(&mut interp, "doskey /listsize=10").0,
            ExitCode::SUCCESS
        );
        assert_eq!(run_cmd(&mut interp, "doskey ll=").0, ExitCode::SUCCESS);
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/macros.txt",
                format!("hi=echo macro_hi{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "doskey /macrofile=C:/macros.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "doskey /reinstall").0,
            ExitCode::SUCCESS
        );
    }

    /// Verifies `WHERE`, `FIND`, `FINDSTR /R` regex character classes & word boundaries,
    /// `MORE`, `SORT`, `FC` & `COMP` accurate missing-file reporting, and `TREE`.
    #[test]
    fn test_search_and_comparison_shims_findstr_regex_and_fc_comp_blame() {
        let mut interp = Interpreter::new();
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/s/sub", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/s/lines.txt",
                format!("err_42_end{CRLF}warn_abc_end{CRLF}plain text word_hit!{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/s/tool.bat", b"@echo hi"),
            Ok(())
        );

        // WHERE
        assert_eq!(run_cmd(&mut interp, "where").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "where /R").0, ExitCode::FAILURE);
        assert!(
            run_cmd(&mut interp, "where /R C:/s /F /T tool")
                .1
                .contains("tool.bat")
        );
        assert_eq!(
            run_cmd(&mut interp, "where /Q nonexistent_xyz").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, "where nonexistent_xyz").0,
            ExitCode::FAILURE
        );

        // FIND
        assert_eq!(run_cmd(&mut interp, "find").0, ExitCode::FAILURE);
        assert!(
            run_cmd(&mut interp, r#"find /i /n "ERR_42" C:/s/lines.txt"#)
                .1
                .contains("[1]err_42_end")
        );
        assert!(
            run_cmd(&mut interp, r#"find /c /v "ERR_42" C:/s/lines.txt"#)
                .1
                .contains(": 3")
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                r#"find /n "hit""#,
                &format!("no{CRLF}yes_hit{CRLF}")
            ),
            (
                ExitCode::SUCCESS,
                format!("[2]yes_hit{CRLF}"),
                String::new()
            )
        );
        assert_eq!(
            run_cmd(&mut interp, r#"find "x" C:/s/missing.txt"#).0,
            ExitCode::FAILURE
        );
    }

    /// Verifies `FINDSTR /R` regex character classes, word boundaries, `/L` literal mode, and `/G:` pattern files.
    #[test]
    fn test_findstr_regex_classes_word_boundaries_and_pattern_files() {
        let mut interp = Interpreter::new();
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/s/sub", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/s/lines.txt",
                format!("err_42_end{CRLF}warn_abc_end{CRLF}plain text word_hit!{CRLF}").as_bytes()
            ),
            Ok(())
        );

        // FINDSTR /R genuine regex character classes (`[0-9]`, `[^0-9]`, `.*`, `^`, `$`, word boundaries)!
        assert_eq!(run_cmd(&mut interp, "findstr").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"findstr /R "^err_[0-9][0-9]*_end$" C:/s/lines.txt"#
            ),
            (
                ExitCode::SUCCESS,
                format!("err_42_end{CRLF}"),
                String::new()
            )
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                &format!(r#"findstr /R "{BS_STR}<word_hit{BS_STR}>" C:/s/lines.txt"#)
            ),
            (
                ExitCode::SUCCESS,
                format!("plain text word_hit!{CRLF}"),
                String::new()
            )
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"findstr /R "^warn_[^0-9]*_end$" C:/s/lines.txt"#
            ),
            (
                ExitCode::SUCCESS,
                format!("warn_abc_end{CRLF}"),
                String::new()
            )
        );
        // Literal `/L` disables regex metacharacters!
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /L "[0-9]" C:/s/lines.txt"#).0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "findstr /I /B /E /N /C:Alpha",
                &format!("alpha{CRLF}beta{CRLF}")
            ),
            (ExitCode::SUCCESS, format!("1:alpha{CRLF}"), String::new())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/s/pats.list", format!("warn{CRLF}").as_bytes()),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "findstr /M /S /G:C:/s/pats.list C:/s/*.txt"),
            (
                ExitCode::SUCCESS,
                format!("C:{BS_STR}s{BS_STR}lines.txt{CRLF}"),
                String::new()
            )
        );
    }

    /// Verifies `MORE`, `SORT`, `FC` & `COMP` accurate missing-file reporting, and `TREE`.
    #[test]
    fn test_more_sort_fc_comp_blame_and_tree_shims() {
        let mut interp = Interpreter::new();
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/s/sub", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/s/lines.txt", format!("err_42{CRLF}").as_bytes()),
            Ok(())
        );

        // MORE & SORT
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/s/unsorted.txt",
                format!("b_line{TAB_CHAR}1{CRLF}{CRLF}{CRLF}a_line{TAB_CHAR}2{CRLF}a_line{TAB_CHAR}2{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert!(
            run_cmd(&mut interp, "more /s /t2 +1 C:/s/unsorted.txt")
                .1
                .contains("a_line  2")
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "sort /r /+2 /unique",
                &format!("x1{CRLF}x2{CRLF}x1{CRLF}")
            ),
            (
                ExitCode::SUCCESS,
                format!("x2{CRLF}x1{CRLF}"),
                String::new()
            )
        );
        assert_eq!(
            run_cmd(&mut interp, "sort C:/s/unsorted.txt /o C:/s/sorted.txt").0,
            ExitCode::SUCCESS
        );
    }

    /// Verifies `FC` & `COMP` accurate missing-file blame reporting and `TREE` rendering.
    #[test]
    fn test_fc_comp_missing_file_blame_and_tree_shims() {
        let mut interp = Interpreter::new();
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/s/sub", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/s/lines.txt", format!("err_42{CRLF}").as_bytes()),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/s/unsorted.txt",
                format!("b_line{CRLF}a_line{CRLF}").as_bytes()
            ),
            Ok(())
        );

        // FC & COMP: verify missing `f2` blames `f2` and NOT `f1`!
        assert_eq!(
            run_cmd(&mut interp, "fc C:/s/lines.txt").0,
            ExitCode::FAILURE
        );
        let (fc_f1_code, _, fc_f1_err) =
            run_cmd(&mut interp, "fc C:/s/missing_first.txt C:/s/lines.txt");
        assert_eq!(fc_f1_code, ExitCode::new(2));
        assert!(fc_f1_err.contains("missing_first.txt"));

        let (fc_f2_code, _, fc_f2_err) =
            run_cmd(&mut interp, "fc C:/s/lines.txt C:/s/missing_second.txt");
        assert_eq!(fc_f2_code, ExitCode::new(2));
        assert!(fc_f2_err.contains("missing_second.txt"));
        assert!(!fc_f2_err.contains("cannot open C:/s/lines.txt"));

        assert_eq!(
            run_cmd(&mut interp, "fc /c /w /n C:/s/lines.txt C:/s/lines.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "fc /n C:/s/lines.txt C:/s/unsorted.txt").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, "fc /b C:/s/lines.txt C:/s/unsorted.txt").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, "fc /b C:/s/lines.txt C:/s/lines.txt").0,
            ExitCode::SUCCESS
        );

        assert_eq!(
            run_cmd(&mut interp, "comp C:/s/lines.txt").0,
            ExitCode::FAILURE
        );
        let (comp_f2_code, _, comp_f2_err) =
            run_cmd(&mut interp, "comp C:/s/lines.txt C:/s/missing_comp2.txt");
        assert_eq!(comp_f2_code, ExitCode::FAILURE);
        assert_eq!(
            comp_f2_err,
            format!("The system cannot find the file specified.{CRLF}")
        );
        assert_eq!(
            run_cmd(&mut interp, "comp /c C:/s/lines.txt C:/s/lines.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "comp C:/s/lines.txt C:/s/unsorted.txt").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/s/b1.bin", b"abc"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/s/b2.bin", b"abd"),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "comp C:/s/b1.bin C:/s/b2.bin").0,
            ExitCode::FAILURE
        );

        // TREE
        assert!(
            run_cmd(&mut interp, "tree /f /a C:/s")
                .1
                .contains("+---sub")
        );
        assert!(run_cmd(&mut interp, "tree C:/s").1.contains("├───sub"));
    }

    /// Verifies `CHOICE` strict `/C` & `/D` validation, `TIMEOUT /T` validation, `ATTRIB`,
    /// `XCOPY`, `ROBOCOPY`, `HOSTNAME`, `WHOAMI`, and live `REG` `Command Processor` updates.
    #[test]
    fn test_admin_shims_choice_timeout_xcopy_robocopy_and_live_reg() {
        let mut interp = Interpreter::new();

        assert_eq!(
            run_cmd(&mut interp, "hostname").1,
            format!("WINCMD-HOST{CRLF}")
        );
        assert_eq!(
            run_cmd(&mut interp, "whoami").1,
            format!("wincmd{BS_STR}user{CRLF}")
        );

        // CHOICE: missing `/C` or `/D` operand MUST fail with SyntaxError!
        assert_eq!(run_cmd(&mut interp, "choice /C").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "choice /C:").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "choice /D").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "choice /D:ZZ").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd(&mut interp, "choice /C AB /D Z").0,
            ExitCode::FAILURE
        );
        assert_eq!(run_cmd(&mut interp, "choice /T").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "choice /T bad").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "choice /M").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "choice /BOGUS").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                r#"choice /C ABC /CS /M "Pick""#,
                &format!("B{CRLF}")
            ),
            (
                ExitCode::new(2),
                format!("Pick [A,B,C]? B{CRLF}"),
                String::new()
            )
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "choice /C:YN /N /T 5 /D Y", ""),
            (ExitCode::new(1), format!("Y{CRLF}"), String::new())
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "choice /C YN", &format!("Z{CRLF}")).0,
            ExitCode::new(255)
        );

        // TIMEOUT: strict `/T` and `-1..=99999` validation!
        assert_eq!(run_cmd(&mut interp, "timeout").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "timeout /T").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "timeout /T abc").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "timeout /T:abc").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "timeout abc").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "timeout 1 2").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd(&mut interp, "timeout /T 1 /T:2").0,
            ExitCode::FAILURE
        );
        assert_eq!(run_cmd(&mut interp, "timeout /T -2").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd(&mut interp, "timeout /T 100000").0,
            ExitCode::FAILURE
        );
        assert!(
            run_cmd(&mut interp, "timeout /T 5 /NOBREAK")
                .1
                .contains("Waiting for 5 seconds")
        );
        assert!(
            run_cmd(&mut interp, "timeout /T:-1")
                .1
                .contains("Waiting indefinitely")
        );
        assert!(
            run_cmd(&mut interp, "timeout 0")
                .1
                .contains("Waiting for 0 seconds")
        );
    }

    /// Verifies `ATTRIB`, `XCOPY`, `ROBOCOPY`, and live `REG` `Command Processor` updates.
    #[test]
    fn test_attrib_xcopy_robocopy_and_live_reg_shims() {
        let mut interp = Interpreter::new();

        // ATTRIB, XCOPY, ROBOCOPY
        assert_eq!(
            interp.proc_env.vfs.create_dir(
                "C:/xc/sub/empty",
                crate::types::DirCreationDepth::CreateParents
            ),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/xc/a.txt", b"payload"),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/xc/sub/b.txt", b"subpayload"),
            Ok(())
        );

        assert_eq!(
            run_cmd(&mut interp, "attrib +R +H +S +A C:/xc/a.txt").0,
            ExitCode::SUCCESS
        );
        assert!(run_cmd(&mut interp, "attrib C:/xc/a.txt").1.contains("SH"));
        assert_eq!(
            run_cmd(&mut interp, "attrib -R -H -S -A /S /D C:/xc/*").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "attrib C:/xc/missing.xyz").0,
            ExitCode::FAILURE
        );

        assert_eq!(run_cmd(&mut interp, "xcopy").0, ExitCode::new(4));
        assert_eq!(
            run_cmd(&mut interp, "xcopy C:/xc C:/xc/sub /E").0,
            ExitCode::new(4)
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy C:/xc/missing.txt C:/xc_dst").0,
            ExitCode::new(4)
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy C:/xc C:/xc_dst /E /I").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy C:/xc/a.txt C:/xc_single /I /Q").0,
            ExitCode::SUCCESS
        );

        assert_eq!(
            run_cmd(&mut interp, "robocopy C:/only_one").0,
            ExitCode::new(16)
        );
        assert_eq!(
            run_cmd(&mut interp, "robocopy C:/no_src C:/rb_dst").0,
            ExitCode::new(16)
        );
        let cyclic_rb = run_cmd(&mut interp, "robocopy C:/xc C:/xc/sub /S");
        assert_eq!(cyclic_rb.0, ExitCode::new(16));
        assert!(cyclic_rb.2.contains("Cannot perform a cyclic copy"));
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/rb_dst", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/rb_dst/stale.txt", b"old"),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "robocopy C:/xc C:/rb_dst /MIR").0,
            ExitCode::new(3)
        );
        assert!(!interp.proc_env.vfs.exists("C:/rb_dst/stale.txt"));
        assert_eq!(
            run_cmd(&mut interp, "robocopy C:/xc_single C:/rb_mov /MOV").0,
            ExitCode::new(1)
        );

        // Live REG updates dynamically toggle DelayedExpansion on the running Interpreter!
        assert_eq!(run_cmd(&mut interp, "reg").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "reg bogus").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"reg add "HKCU/Software/Microsoft/Command Processor" /v DelayedExpansion /t REG_DWORD /d 1 /f"#
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"set "LIVE_V=dynamic_reg" & echo !LIVE_V!"#),
            (
                ExitCode::SUCCESS,
                format!("dynamic_reg{CRLF}"),
                String::new()
            )
        );
        assert!(
            run_cmd(
                &mut interp,
                r#"reg query "HKCU/Software/Microsoft/Command Processor" /v DelayedExpansion"#
            )
            .1
            .contains("0x1")
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"reg export "HKCU/Software/Microsoft/Command Processor" C:/cp.reg"#
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"reg copy "HKCU/Software/Microsoft/Command Processor" HKCU/BackupCP /s /f"#
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"reg delete "HKCU/Software/Microsoft/Command Processor" /v DelayedExpansion /f"#
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "echo !LIVE_V!"),
            (ExitCode::SUCCESS, format!("!LIVE_V!{CRLF}"), String::new())
        );
        assert_eq!(
            run_cmd(&mut interp, "reg import C:/cp.reg").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "echo !LIVE_V!"),
            (
                ExitCode::SUCCESS,
                format!("dynamic_reg{CRLF}"),
                String::new()
            )
        );
    }

    /// Exercises dispatch quoting, `SET /A` multi-expression lookups & batch silence, `ENDLOCAL`,
    /// `CALL` batch files, `SHIFT`, `EXIT`, and `START` switch permutations.
    #[test]
    fn test_dispatch_env_and_flow_builtin_branch_edges() {
        let mut interp = Interpreter::new();
        assert_eq!(run_cmd(&mut interp, "endlocal").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, r#""echo" quoted_prog"#).0,
            ExitCode::new(9009)
        );
        assert_eq!(run_cmd(&mut interp, "1:").0, ExitCode::new(9009));
        assert_eq!(run_cmd(&mut interp, "123_not_drive").0, ExitCode::new(9009));
        assert_eq!(run_cmd(&mut interp, r#""""#).0, ExitCode::new(9009));
        assert_eq!(
            run_cmd(&mut Interpreter::new(), "exit /b 4").0,
            ExitCode::new(4)
        );

        // Silent external process spawner (empty stdout and empty stderr)
        let mut mock = crate::runtime::MockProcessSpawner::new();
        mock.register_binary("quiet.exe", ExitCode::SUCCESS, "", "");
        mock.register_binary("started.exe", ExitCode::SUCCESS, "started_out", "");
        interp.proc_env.spawner = Box::new(mock);
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/quiet.exe", b"MZ"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/started.exe", b"MZ"),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "C:/quiet.exe"),
            (ExitCode::SUCCESS, String::new(), String::new())
        );

        // SET /A multi-expression reading pending + existing env variable + error
        assert_eq!(
            run_cmd(&mut interp, "set PRE_X=5 & set /a A=4, B=A+PRE_X").1,
            "9"
        );
        assert_eq!(run_cmd(&mut interp, "set /a 1/0").0, ExitCode::FAILURE);

        // Batch CALL, SHIFT (/N, /0 on empty, /x, non-slash, out-of-range, REPL), START & CMD permutations
        let sub_bat = format!(
            "@echo off{CRLF}set /a Z=2+3{CRLF}shift{CRLF}shift /5{CRLF}shift /9{CRLF}shift /x{CRLF}shift noslash{CRLF}echo %1{CRLF}"
        );
        let empty_shift = format!("@echo off{CRLF}shift /0{CRLF}shift{CRLF}");
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/sub.bat", sub_bat.as_bytes()),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/empty_sh.bat", empty_shift.as_bytes()),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "call C:/sub.bat a b c d e").1,
            format!("e{CRLF}")
        );
        assert_eq!(
            run_cmd(&mut interp, "call C:/empty_sh.bat").0,
            ExitCode::SUCCESS
        );
        assert_eq!(run_cmd(&mut interp, "shift").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, "start /WAIT /I /MAX C:/started.exe a1").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "start /DC:/ C:/started.exe").0,
            ExitCode::SUCCESS
        );
        assert_eq!(run_cmd(&mut interp, "start /d").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd(&mut interp, "start \"unclosed_quote").0,
            ExitCode::new(9009)
        );
        assert_eq!(run_cmd(&mut interp, "cmd /Z /C ver").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, "cmd non_slash_arg").0,
            ExitCode::SUCCESS
        );
        assert_eq!(run_cmd(&mut interp, "start /Z").0, ExitCode::new(9009));
        assert_eq!(run_cmd(&mut interp, "exit not_num").0, ExitCode::SUCCESS);
    }

    /// Verifies subshell CWD isolation (`START /D`, `CMD /C`, `CMD /K`), `START /I`, and `CALL` caret
    /// raw-tail slicing.
    #[test]
    fn test_subshell_cwd_isolation_cmd_k_and_call_caret_slicing() {
        let mut interp = Interpreter::new();
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/sub", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/caret_tail.bat",
                format!("@echo off{CRLF}echo TAIL:%*{CRLF}").as_bytes()
            ),
            Ok(())
        );

        assert_eq!(
            run_cmd(&mut interp, "start /D C:/missing_start_dir echo hi").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, r#"start /D C:/sub cmd /c "cd""#),
            (
                ExitCode::SUCCESS,
                format!("C:{BS_STR}sub{CRLF}"),
                String::new()
            )
        );
        assert_eq!(interp.current_cwd_string(), format!("C:{BS_STR}"));

        let cmd_k_out = run_cmd_with_stdin(
            &mut interp,
            r#"cmd /k "set "KVAR=live" & cd C:\sub""#,
            &format!("{CRLF}echo %KVAR%{CRLF}exit 7{CRLF}"),
        );
        assert_eq!(cmd_k_out.0, ExitCode::new(7));
        assert_eq!(cmd_k_out.1, format!("live{CRLF}"));
        assert_eq!(interp.current_cwd_string(), format!("C:{BS_STR}"));

        let cmd_k_early_exit =
            run_cmd_with_stdin(&mut interp, r#"cmd /k "exit""#, &format!("echo nope{CRLF}"));
        assert_eq!(cmd_k_early_exit.0, ExitCode::new(7));

        assert_eq!(
            run_cmd(
                &mut interp,
                r#"call C:/c^aret_tail.bat   "two  spaces"  end"#
            )
            .1,
            format!(r#"TAIL:"two  spaces"  end{CRLF}"#)
        );
    }

    /// Verifies shim directory/extension precedence, single-pass `FTYPE` placeholder expansion,
    /// and `FOR` wildcard directory-prefix preservation.
    #[test]
    fn test_shim_path_precedence_ftype_single_pass_and_for_wildcard_prefix() {
        let mut interp = Interpreter::new();
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/sub", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/My Docs", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/sub/item.txt", b"payload"),
            Ok(())
        );

        assert_eq!(
            run_cmd(&mut interp, r"C:\Windows\System32\whoami.exe").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r"C:\Windows\whoami.exe").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r"C:\sub\whoami.exe").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/sub/whoami.bat",
                format!("@echo off{CRLF}echo CUSTOM_WHOAMI{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, r"C:\sub\whoami").1,
            format!("CUSTOM_WHOAMI{CRLF}")
        );
        assert_eq!(
            run_cmd(&mut interp, r"C:\nonexistent_dir\whoami.exe").0,
            ExitCode::new(9009)
        );
        assert_eq!(
            run_cmd(&mut interp, "whoami.exe.exe").0,
            ExitCode::new(9009)
        );

        // 5. Single-pass FTYPE template (`%%`, `%1` spaced vs quoted, `%2`, `%10`/`%20`/trailing `%`, `%*`)
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/My Docs/report.zdoc", b"z"),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "assoc .zdoc=ZDocType").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"ftype ZDocType=echo %% %1 "%0" %2 %3 %10 %20 %* %"#
            )
            .0,
            ExitCode::SUCCESS
        );
        let ftype_res = run_cmd(&mut interp, r#""C:/My Docs/report.zdoc" alpha"#);
        assert_eq!(ftype_res.0, ExitCode::SUCCESS);
        assert!(ftype_res.1.contains(r#"% "C:\My Docs\report.zdoc""#));
        assert!(ftype_res.1.contains("%10 %20 alpha %"));
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/sub/nospace.zdoc", b"z"),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "C:/sub/nospace.zdoc").0,
            ExitCode::SUCCESS
        );

        // 6. FOR wildcard preserves directory/drive prefix (`C:/sub/*.txt`, `C:*.txt`, `*.txt`, `1:*.log`)
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/root_only.log", b"r"),
            Ok(())
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                "for %F in (C:/sub/*.txt C:*.log *.log 1:*.log) do @echo %F"
            )
            .1,
            format!("C:/sub/item.txt{CRLF}C:root_only.log{CRLF}root_only.log{CRLF}")
        );
    }

    /// Verifies non-`CALL` `.bat` frame transfer unwinding `&` chains, self-`MOVE` preservation,
    /// and `ENDLOCAL` resilience when the saved working directory was removed.
    #[test]
    fn test_non_call_batch_chaining_self_move_and_endlocal_deleted_cwd() {
        let mut interp = Interpreter::new();
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/callee.bat",
                format!("@echo off{CRLF}echo CALLEE:%1:%2{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/chain_inline.bat",
                format!("@echo off{CRLF}C:/callee.bat p q & echo INLINE_SHOULD_NOT_RUN{CRLF}")
                    .as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/chain_caller.bat",
                format!("@echo off{CRLF}C:/callee.bat x y{CRLF}echo CALLER_AFTER_LINE{CRLF}")
                    .as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "call C:/chain_inline.bat").1,
            format!("CALLEE:p:q{CRLF}")
        );
        assert_eq!(
            run_cmd(&mut interp, "call C:/chain_caller.bat").1,
            format!("CALLEE:x:y{CRLF}")
        );

        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/self_mv.txt", b"keep"),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "move /Y C:/self_mv.txt C:/self_mv.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.proc_env.vfs.read_bytes("C:/self_mv.txt"),
            Ok(b"keep".to_vec())
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                "md C:\\gone_el & cd C:\\gone_el & setlocal & cd C:\\ & rd C:\\gone_el & endlocal"
            )
            .0,
            ExitCode::SUCCESS
        );
    }

    /// Exercises `VOL` unlabeled drives, `DATE`/`TIME` formats & blank stdin, `VERIFY`, `MODE`
    /// `COLS=`/`LINES=`/`80,25` forms, and `DOSKEY` `/M`, `/H`, `/LISTSIZE`, `/MACROFILE`.
    #[test]
    fn test_console_mode_and_doskey_branch_edges() {
        let mut vfs = crate::vfs::InMemoryVfs::new();
        vfs.mount_empty_drive(DriveLetter::D, "", "0000-0000");
        let mut interp = Interpreter::with_vfs(Box::new(vfs));
        assert!(run_cmd(&mut interp, "vol D:").1.contains("has no label"));

        interp.config.locale.date_format = crate::types::DateFormatStyle::Iso8601;
        assert!(
            run_cmd_with_stdin(&mut interp, "date", &format!("   {CRLF}"))
                .1
                .contains("(yyyy-mm-dd)")
        );
        interp.config.locale.date_format = crate::types::DateFormatStyle::DayMonthYearEuro;
        assert!(
            run_cmd_with_stdin(&mut interp, "date", &format!("   {CRLF}"))
                .1
                .contains("(dd-mm-yy)")
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "time", &format!("   {CRLF}")).0,
            ExitCode::SUCCESS
        );

        assert!(
            run_cmd(&mut interp, "verify off & verify")
                .1
                .contains("off")
        );
        assert_eq!(
            run_cmd(&mut interp, r#"mode con: "cols=100" "lines=40""#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            (interp.console.console_cols, interp.console.console_lines),
            (100, 40)
        );
        assert_eq!(
            run_cmd(&mut interp, "mode co 90 li 30 cols bad lines bad li co").0,
            ExitCode::SUCCESS
        );
        assert_eq!(run_cmd(&mut interp, "mode li").0, ExitCode::SUCCESS);
        assert_eq!(
            (interp.console.console_cols, interp.console.console_lines),
            (90, 30)
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"mode "cols=bad" "lines=bad" "bad,bad" "95,bad""#
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(interp.console.console_cols, 95);
        assert_eq!(
            run_cmd(&mut interp, r#"mode "120,50""#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            (interp.console.console_cols, interp.console.console_lines),
            (120, 50)
        );

        interp.console.record_history("echo hist_1");
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/macros.txt",
                format!("m1=echo one{CRLF}comment{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, r#"doskey "/listsize=25""#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"doskey "/listsize=bad""#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"doskey "/macrofile=C:/macros.txt""#).0,
            ExitCode::SUCCESS
        );
        assert!(run_cmd(&mut interp, "doskey /m").1.contains("m1=echo one"));
        assert!(
            run_cmd(&mut interp, "doskey /macros:all")
                .1
                .contains("m1=echo one")
        );
        assert!(run_cmd(&mut interp, "doskey /h").1.contains("echo hist_1"));
        assert_eq!(
            run_cmd(&mut interp, "doskey no_equals_token").0,
            ExitCode::SUCCESS
        );
    }

    /// Exercises `DIR` sort/attribute/format switches, `PUSHD` UNC non-directory errors,
    /// `COPY` `COPYCMD=/-Y` & Ctrl-Z ASCII truncation, `DEL` `/S`/`/A`, `REN`, and `MOVE`.
    #[test]
    fn test_fs_cmds_dir_copy_del_ren_and_move_branch_edges() {
        let mut interp = Interpreter::new();
        assert_eq!(
            interp.proc_env.vfs.create_dir(
                "C:/fs_edge/sub",
                crate::types::DirCreationDepth::CreateParents
            ),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/fs_edge/Abc.txt", b"hello\x1Aignored"),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/fs_edge/sub/Read.txt", b"ro"),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "attrib +r +h +s +a C:/fs_edge/sub/Read.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.proc_env.vfs.create_symlink(
                "C:/fs_edge/lnk.txt",
                "C:/fs_edge/Abc.txt",
                crate::types::MklinkKind::FileSymlink,
            ),
            Ok(())
        );

        // DIR switches: bare `dir`, `/w`, `/d`, `/on`, `/og`, `/ox`, `/s /l`, `/ar /ah /as /aa /al /az`
        assert_eq!(run_cmd(&mut interp, "dir").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, "dir C:/fs_edge /w /on").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "dir C:/fs_edge /d /og").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "dir C:/fs_edge /ox").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "dir C:/fs_edge /s /l /b").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "dir C:/fs_edge /al").0,
            ExitCode::SUCCESS
        );
        for af in ["/ar", "/ah", "/as", "/aa", "/az"] {
            assert_eq!(
                run_cmd(&mut interp, &format!("dir C:/fs_edge/sub {af}")).0,
                ExitCode::SUCCESS
            );
        }
        assert_eq!(
            run_cmd(&mut interp, "dir C:/fs_edge/Abc.txt /l").0,
            ExitCode::SUCCESS
        );

        // PUSHD UNC file (not directory) + RD /S declined with 'N'
        let unc_f = format!("{BS_STR}{BS_STR}srv{BS_STR}sh{BS_STR}file.txt");
        assert_eq!(interp.proc_env.vfs.write_bytes(&unc_f, b"u"), Ok(()));
        assert_eq!(
            run_cmd(&mut interp, &format!("pushd {unc_f}")).0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "rd /s C:/fs_edge/sub", &format!("N{CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert!(interp.proc_env.vfs.exists("C:/fs_edge/sub"));

        // COPY with COPYCMD=/-Y ('Y' and 'A' responses), /A + /V Ctrl-Z truncation, 0-match wildcard
        interp.proc_env.env.set("COPYCMD", "/-Y");
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "copy /a /v /x C:/fs_edge/Abc.txt+C:/fs_edge/Abc.txt C:/fs_edge/out.txt",
                &format!("Y{CRLF}"),
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.proc_env.vfs.read_bytes("C:/fs_edge/out.txt"),
            Ok(b"hellohello\x1A".to_vec())
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "copy C:/fs_edge/*.txt C:/fs_edge/sub",
                &format!("N{CRLF}A{CRLF}")
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "copy C:/fs_edge/*.nomatch C:/fs_edge/sub").0,
            ExitCode::FAILURE
        );
        interp.proc_env.env.remove("COPYCMD");

        // Non-wildcard REN, MOVE /-Y confirmed, DEL directory /S /AR + 'N' abort
        assert_eq!(
            run_cmd(&mut interp, "ren C:/fs_edge/out.txt renamed.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "move /-y C:/fs_edge/renamed.txt C:/fs_edge/Abc.txt",
                &format!("Y{CRLF}")
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "del C:/fs_edge", &format!("N{CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "del /s /ar /f /q /z C:/fs_edge").0,
            ExitCode::SUCCESS
        );
    }

    /// Exercises remaining `CD /D`, `POPD` unmounted drive, `DIR /O`, `DEL /P` & `*.*`, `REN`
    /// extension/question masks, `MOVE /-Y` decline, and `MKLINK` unknown switch branches.
    #[test]
    fn test_fs_cmds_cd_popd_del_ren_move_and_mklink_extra_edges() {
        let mut vfs = crate::vfs::InMemoryVfs::new();
        vfs.mount_empty_drive(DriveLetter::D, "DATA", "1111-2222");
        let mut interp = Interpreter::with_vfs(Box::new(vfs));

        assert_eq!(run_cmd(&mut interp, "cd /d C:/").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "cd /d C:").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, r#"cd """#).0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "cd 1:").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "cd /dX").0, ExitCode::FAILURE);

        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/goners", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/rm_yes", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.create_dir(
                "C:/plain_empty",
                crate::types::DirCreationDepth::CreateParents
            ),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "rd C:/plain_empty").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "cd C:/goners & pushd C:/ & rd /s /q C:/goners").0,
            ExitCode::SUCCESS
        );
        assert_eq!(run_cmd(&mut interp, "popd").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "rd /s C:/rm_yes", &format!("Y{CRLF}")).0,
            ExitCode::SUCCESS
        );
        interp.proc_env.env.extensions = ExtensionsMode::Disabled;
        assert_eq!(
            run_cmd(
                &mut interp,
                &format!("pushd {BS_STR}{BS_STR}srv{BS_STR}sh{BS_STR}missing")
            )
            .0,
            ExitCode::FAILURE
        );
        interp.proc_env.env.extensions = ExtensionsMode::Enabled;

        assert_eq!(interp.proc_env.vfs.write_bytes("C:/m1.txt", b"1"), Ok(()));
        assert_eq!(interp.proc_env.vfs.write_bytes("C:/m2.txt", b"2"), Ok(()));
        assert_eq!(run_cmd(&mut interp, "dir /o /z").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, "dir C:/no_dir/*.txt").0,
            ExitCode::FAILURE
        );
        assert_eq!(run_cmd(&mut interp, "type C:/m2.txt").1, "2");

        interp.proc_env.env.set("COPYCMD", "/Y");
        assert_eq!(
            run_cmd(&mut interp, "copy /a C:/m1.txt C:/asc1.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "copy C:/m1.txt+C:/m2.txt C:/cat_b.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "copy /a C:/m1.txt+C:/m2.txt C:/cat_a.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/wc_dst", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/wc_dst/m1.txt", b"old"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/wc_dst/m2.txt", b"old2"),
            Ok(())
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "copy /-y C:/m*.txt C:/wc_dst",
                &format!("N{CRLF}A{CRLF}")
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "copy /-y C:/m1.txt C:/m2.txt",
                &format!("Y{CRLF}")
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "copy /-y C:/m1.txt C:/m2.txt",
                &format!("A{CRLF}")
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "ren C:/wc_dst/m*.txt *").0,
            ExitCode::SUCCESS
        );
        interp.proc_env.env.remove("COPYCMD");

        assert_eq!(
            run_cmd(&mut interp, "ren C:/m1.txt ?????.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "ren C:/m1.txt *.").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "ren C:/m1 m1_noext").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "move /-y C:/m1_noext C:/m1_moved").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "move /-y C:/m1_moved C:/m2.txt",
                &format!("N{CRLF}")
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "move /-y C:/m1_moved C:/m2.txt",
                &format!("A{CRLF}")
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "del /s C:/asc1.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "del C:/no_dir/*.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(run_cmd(&mut interp, "del C:/*.zzzz").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "del /p C:/*",
                &format!("N{CRLF}N{CRLF}N{CRLF}N{CRLF}")
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "del /p C:/m2.txt", &format!("Y{CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "del C:/*.*", &format!("Y{CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(interp.proc_env.vfs.write_bytes("C:/target", b"t"), Ok(()));
        assert_eq!(
            run_cmd(&mut interp, "mklink /z C:/lnk C:/target").0,
            ExitCode::SUCCESS
        );
    }

    /// Exercises `WHERE`, `FIND`, `FINDSTR` regex/class/escape/anchor switches, `MORE` stdin,
    /// `SORT` `/REC`/`/UNIQ`, `FC`, `COMP`, and `TREE` switch branches.
    #[test]
    fn test_search_shims_where_find_findstr_more_sort_fc_edges() {
        let mut interp = Interpreter::new();
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/f1.txt",
                format!("Alpha 123{CRLF}beta [x]{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/f2.txt", format!("ALPHA 999{CRLF}").as_bytes()),
            Ok(())
        );
        assert_eq!(interp.proc_env.vfs.write_bytes("C:/empty.txt", b""), Ok(()));
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/tool.exe", b"MZ"),
            Ok(())
        );

        // WHERE without /F or /T, wildcard, and unset PATH/PATHEXT
        interp.proc_env.env.remove("PATHEXT");
        interp.proc_env.env.remove("PATH");
        assert_eq!(run_cmd(&mut interp, "where *.exe").0, ExitCode::SUCCESS);
        assert_eq!(run_cmd(&mut interp, "where /q *.exe").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(&mut interp, "where /q missing_xyz").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, "where missing_xyz").0,
            ExitCode::FAILURE
        );

        // FIND /C count-only + quoted switch-like needle + 0-match file + unquoted needle
        assert!(
            run_cmd(&mut interp, r#"find /c /i /z "alpha" C:/f1.txt"#)
                .1
                .contains(": 1")
        );
        assert_eq!(
            run_cmd(&mut interp, r#"find "/i" C:/f1.txt"#).0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, r#"find "nomatch" C:/f1.txt"#).0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, "find /i alpha C:/f1.txt").0,
            ExitCode::FAILURE
        );
        assert!(
            run_cmd(&mut interp, r#"find /c "nomatch" < C:/f1.txt"#)
                .1
                .contains('0')
        );

        // FINDSTR /I /R (`\*`, `.`, `*`, `[\x]`, `[a-z]`, `[z-a]`, `[unclosed`, `\<...\>`), `/S`, `/G:`
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/pats.txt", format!("Alpha{CRLF}{CRLF}").as_bytes()),
            Ok(())
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"findstr /i /r /z "a.*a.[0-9]*" C:/f1.txt C:/f2.txt"#
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /i /r "^Alpha.*$" C:/f1.txt"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"findstr /i /r "[a-z] [z-a] \<Alpha\> \<999\>" C:/f1.txt"#
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /r "a$b []a] [a-] [\" C:/f1.txt"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /r "a\" C:/f1.txt"#).0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr "a" C:/no_dir/*.txt"#).0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, r#"findstr /m "a""#, &format!("abc  {CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, r#"findstr /n "a""#, &format!("abc{CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                r#"findstr /r "x\<w\>""#,
                &format!("  w  {CRLF}")
            )
            .0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, r#"findstr /r "w\>""#, &format!("ww{CRLF}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, r#"findstr /r "/c: \>""#, &format!("a b{CRLF}")).0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /r "[unclosed" C:/f1.txt"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /i /r /b "alpha" C:/f1.txt"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /i /r /e "123" C:/f1.txt"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.proc_env.vfs.create_symlink(
                "C:/dangle.txt",
                "C:/missing_target.txt",
                crate::types::MklinkKind::FileSymlink
            ),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr "a" C:/dangle.txt"#).0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /i /s "alpha" C:/f1.txt"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "findstr /g:C:/pats.txt C:/f1.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /i /r "\[x\]*" C:/f1.txt"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /i /r "[\x][b]" C:/f1.txt"#).0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /i /x "/c:alpha 999" C:/f2.txt"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /i /l /b "alpha" C:/f2.txt"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /i /l /e "999" C:/f2.txt"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr /v "999" C:/*.txt"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"findstr "a" C:/no_such_file.txt"#).0,
            ExitCode::FAILURE
        );

        // MORE, SORT, FC /B identical, COMP, TREE
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "more /tbad +bad /z", &format!("st_line{CRLF}")).1,
            format!("st_line{CRLF}")
        );
        assert_eq!(run_cmd_with_stdin(&mut interp, "more", "").1, String::new());
        assert_eq!(
            run_cmd(
                &mut interp,
                "sort /z /+bad /rec1024 /uniq C:/f1.txt C:/f2.txt /o"
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(run_cmd(&mut interp, "sort C:/empty.txt").1, String::new());
        assert_eq!(interp.proc_env.vfs.write_bytes("C:/b1.bin", b"ax"), Ok(()));
        assert_eq!(interp.proc_env.vfs.write_bytes("C:/b2.bin", b"ay"), Ok(()));
        assert_eq!(
            run_cmd(&mut interp, "fc /b C:/b1.bin C:/b2.bin").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, "fc /b C:/f1.txt C:/f1.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "fc /z C:/f1.txt C:/f2.txt").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd_with_stdin(
                &mut interp,
                "comp /z C:/f1.txt C:/f2.txt",
                &format!("N{CRLF}")
            )
            .0,
            ExitCode::FAILURE
        );
        assert_eq!(run_cmd(&mut interp, "tree /z C:/").0, ExitCode::SUCCESS);
    }

    /// Exercises `CHOICE`, `TIMEOUT`, `ATTRIB`, `XCOPY`, `ROBOCOPY`, and `REG` error/switch branches.
    #[test]
    fn test_admin_shims_choice_attrib_xcopy_robocopy_and_reg_edges() {
        let mut interp = Interpreter::new();
        assert_eq!(run_cmd(&mut interp, "choice /c").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "choice /c /n").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "choice /d AB").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "choice /d /n").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, r#"choice /d """#).0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "choice /c YN /m Prompt", &format!("Z{CRLF}")).0,
            ExitCode::new(255)
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "choice /c YN /cs /n /t 0 /d N", "").0,
            ExitCode::new(2)
        );
        assert_eq!(
            run_cmd(&mut interp, "timeout /t 1 /t 2").0,
            ExitCode::FAILURE
        );
        assert_eq!(run_cmd(&mut interp, "timeout 1 2").0, ExitCode::FAILURE);

        // ATTRIB individual flags + XCOPY /Q + ROBOCOPY UNC & /MOV + REG trailing-flag edge cases
        assert_eq!(
            interp.proc_env.vfs.create_dir(
                "C:/adm_src/sub/extra_dir",
                crate::types::DirCreationDepth::CreateParents
            ),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/adm_src/a.txt", b"v1"),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/adm_src/skip.log", b"lg"),
            Ok(())
        );
        for fl in ["+r", "+h", "+s", "+a", "-r -h -s -a"] {
            assert_eq!(
                run_cmd(&mut interp, &format!("attrib {fl} C:/adm_src/a.txt")).0,
                ExitCode::SUCCESS
            );
        }
        assert_eq!(
            run_cmd(&mut interp, "attrib /z C:/adm_src").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy /s /t /i /z C:/adm_src C:/xc_tree").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy /y C:/adm_src/a.txt C:/xc_single.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy /y /q C:/adm_src/a.txt C:/xc_single.txt").0,
            ExitCode::SUCCESS
        );
        let unc_rc = format!("{BS_STR}{BS_STR}rcsrv{BS_STR}sh{BS_STR}src");
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir(&unc_rc, crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                &format!("xcopy /s /e {unc_rc} {unc_rc}{BS_STR}sub")
            )
            .0,
            ExitCode::new(4)
        );
        assert_eq!(
            run_cmd(&mut interp, &format!("xcopy /s /e {unc_rc} C:/rc_unc_dst")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.proc_env.vfs.create_dir(
                "C:/rc_dst/obsolete_dir",
                crate::types::DirCreationDepth::CreateParents
            ),
            Ok(())
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                "robocopy C:/adm_src C:/rc_dst *.txt /e /purge /z"
            )
            .0,
            ExitCode::new(3)
        );
        assert!(!interp.proc_env.vfs.exists("C:/rc_dst/obsolete_dir"));
        assert_eq!(
            run_cmd(&mut interp, "robocopy C:/adm_src C:/rc_dst *.txt /s /mov").0,
            ExitCode::SUCCESS
        );
        assert!(run_cmd(&mut interp, "robocopy C:/no_src_dir C:/rc_dst").0.0 >= 8);
    }

    /// Verifies `REG` subcommand syntax errors, `/S`/`/VE`/`/VA` queries/deletes, and `SETLOCAL` registry scoping.
    #[test]
    fn test_reg_shim_subcommands_errors_and_setlocal_scoping() {
        let mut interp = Interpreter::new();
        // REG syntax errors, missing keys, /S, /VE, /VA, key-only ADD, and setlocal-scoped REG
        for bad_reg in [
            "reg query",
            "reg query HKCU/NoSuchKey99",
            "reg add",
            "reg add BAD_HIVE/Key",
            "reg add HKCU/TestK /t BAD_TYPE",
            "reg delete",
            "reg delete HKCU/NoSuchKey99 /f",
            "reg copy",
            "reg copy HKCU/NoSuchKey99 HKCU/Dst /f",
            "reg export",
            "reg export HKCU/NoSuchKey99 C:/out.reg",
            "reg import",
            "reg import C:/no_such.reg",
        ] {
            assert_eq!(
                run_cmd(&mut interp, bad_reg).0,
                ExitCode::FAILURE,
                "cmd: {bad_reg}"
            );
        }
        assert_eq!(
            run_cmd(&mut interp, "reg add HKCU/TestK /f").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"reg add HKCU/TestK /ve /d "def_val" /z /f"#).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                r#"reg add HKCU/TestK/Sub /v Named /d "sub_val" /f"#
            )
            .0,
            ExitCode::SUCCESS
        );
        assert!(
            run_cmd(&mut interp, "reg query HKCU/TestK /ve")
                .1
                .contains("(Default)")
        );
        assert!(
            run_cmd(&mut interp, "reg query HKCU/TestK /s /z")
                .1
                .contains("sub_val")
        );
        assert!(
            run_cmd(&mut interp, "reg query HKCU/TestK /s /v Named")
                .1
                .contains("sub_val")
        );
        assert_eq!(
            run_cmd(&mut interp, "reg query HKCU/TestK /v").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "reg add HKCU/TestK /f /v").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "reg add HKCU/TestK /f /t").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "reg add HKCU/TestK /f /d").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "reg delete HKCU/TestK /ve /z /f").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "reg delete HKCU/TestK /va /f").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "reg delete HKCU/TestK /f /v").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, r#"setlocal & reg add "HKCU/Software/Microsoft/Command Processor" /v DelayedExpansion /t REG_DWORD /d 0 /f & endlocal"#).0,
            ExitCode::SUCCESS
        );
    }

    /// Exercises VFS error-handling paths in `ATTRIB`, `XCOPY`, `ROBOCOPY`, and `CHOICE` inline flags.
    #[test]
    fn test_admin_shims_vfs_failure_paths_and_choice_inline_flags() {
        let mut interp = Interpreter::new();
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/err_src", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/err_src/f.txt", b"data"),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/blocker", b"file_not_dir"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/ro_dst.txt", b"ro"),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "attrib +r C:/ro_dst.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.proc_env.vfs.create_symlink(
                "C:/err_src/dangle.txt",
                "C:/nowhere.txt",
                crate::types::MklinkKind::FileSymlink,
            ),
            Ok(())
        );

        assert_eq!(
            run_cmd(&mut interp, "attrib +r C:/err_src/*").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "attrib +r C:/err_src").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd(&mut interp, "attrib C:/no_dir/*.txt").0,
            ExitCode::FAILURE
        );
        assert_eq!(run_cmd(&mut interp, "attrib +r NUL").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd(&mut interp, "xcopy /e C:/err_src C:/blocker").0,
            ExitCode::new(4)
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy /i C:/err_src/f.txt C:/blocker").0,
            ExitCode::new(4)
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy /y C:/err_src/f.txt C:/ro_dst.txt").0,
            ExitCode::new(4)
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy /t C:/err_src/f.txt C:/t_single").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.proc_env.vfs.create_dir(
                "C:/err_src/sub",
                crate::types::DirCreationDepth::CreateParents
            ),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.delete_file(
                "C:/err_src/dangle.txt",
                crate::types::ReadOnlyDeletePolicy::ForceDeleteReadOnly
            ),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy C:/err_src C:/xc_nonrec").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy /s /q C:/err_src C:/xc_qsub").0,
            ExitCode::SUCCESS
        );
        let unc_s1_a = format!("{BS_STR}{BS_STR}s1{BS_STR}a{BS_STR}src");
        let unc_s1_b = format!("{BS_STR}{BS_STR}s1{BS_STR}b{BS_STR}dst");
        let unc_s2_a = format!("{BS_STR}{BS_STR}s2{BS_STR}a{BS_STR}dst");
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir(&unc_s1_a, crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, &format!("xcopy /s /e {unc_s1_a} {unc_s1_b}")).0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, &format!("xcopy /s /e {unc_s1_a} {unc_s2_a}")).0,
            ExitCode::SUCCESS
        );

        assert!(run_cmd(&mut interp, "robocopy C:/blocker C:/rc_out").0.0 >= 8);
        assert!(
            run_cmd(&mut interp, "robocopy C:/err_src C:/blocker/sub")
                .0
                .0
                >= 8
        );
        assert!(run_cmd(&mut interp, "robocopy C:/err_src C:/rc_nonrec").0.0 < 8);
        assert_eq!(
            interp.proc_env.vfs.create_symlink(
                "C:/err_src/dangle2.txt",
                "C:/nowhere2.txt",
                crate::types::MklinkKind::FileSymlink,
            ),
            Ok(())
        );
        assert!(
            run_cmd(&mut interp, "robocopy C:/err_src C:/rc_ro /purge")
                .0
                .0
                >= 8
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/rc_ro2", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/rc_ro2/f.txt", b"old"),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "attrib +r C:/rc_ro2/f.txt").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.proc_env.vfs.delete_file(
                "C:/err_src/dangle2.txt",
                crate::types::ReadOnlyDeletePolicy::ForceDeleteReadOnly
            ),
            Ok(())
        );
        assert!(
            run_cmd(&mut interp, "robocopy C:/err_src C:/rc_ro2 /purge")
                .0
                .0
                >= 8
        );

        assert_eq!(run_cmd(&mut interp, r#"choice /c """#).0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "choice /d /").0, ExitCode::FAILURE);
        assert_eq!(run_cmd(&mut interp, "choice /d:AB").0, ExitCode::FAILURE);
        assert_eq!(
            run_cmd(&mut interp, "timeout /z /t 0 extra_pos").0,
            ExitCode::FAILURE
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "choice /c YN /n /m Msg", &format!("Y{CRLF}")).0,
            ExitCode::new(1)
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "choice /c YN", "").0,
            ExitCode::new(255)
        );
        assert_eq!(
            run_cmd_with_stdin(&mut interp, "choice /c:YN /d:Y /t 0", "").0,
            ExitCode::new(1)
        );
    }

    /// Exercises OS-level permission and dangling-symlink failures in `ATTRIB` and `ROBOCOPY` on `HostOsVfs`.
    #[cfg(unix)]
    #[test]
    fn test_host_os_vfs_attrib_and_robocopy_permission_failures() {
        use std::os::unix::fs::PermissionsExt;

        let base = std::env::temp_dir().join(format!("wincmd_adm_err_{}", std::process::id()));
        assert!(std::fs::create_dir_all(&base).is_ok());
        assert!(std::fs::remove_dir_all(&base).is_ok());
        assert!(std::fs::create_dir_all(base.join("src")).is_ok());
        assert!(std::fs::create_dir_all(base.join("dst")).is_ok());
        assert!(std::fs::write(base.join("src/mov_me.txt"), b"mv").is_ok());
        assert!(std::fs::write(base.join("dst/purge_me.txt"), b"pg").is_ok());
        assert!(
            std::os::unix::fs::symlink(base.join("missing"), base.join("src/dangling")).is_ok()
        );

        let host_vfs = crate::vfs::HostOsVfs::new(base.clone());
        let mut interp = Interpreter::with_vfs(Box::new(host_vfs));

        // 1. `src` locked 0o555: `attrib +h` fails writing sidecar (`had_error = true`),
        //    and `robocopy /mov` copies `mov_me.txt` to writable `dst` then fails deleting `src/mov_me.txt`!
        assert!(std::fs::remove_file(base.join("src/dangling")).is_ok());
        assert!(
            std::fs::set_permissions(base.join("src"), std::fs::Permissions::from_mode(0o555))
                .is_ok()
        );
        assert!(
            run_cmd(&mut interp, "robocopy C:/src C:/dst mov_me.txt /mov")
                .0
                .0
                >= 8
        );

        // 2. `dst` locked 0o555: `robocopy /purge` fails deleting `dst/purge_me.txt`!
        assert!(
            std::fs::set_permissions(base.join("src"), std::fs::Permissions::from_mode(0o755))
                .is_ok()
        );
        assert!(
            std::fs::set_permissions(base.join("dst"), std::fs::Permissions::from_mode(0o555))
                .is_ok()
        );
        assert!(run_cmd(&mut interp, "robocopy C:/src C:/dst /purge").0.0 >= 8);

        assert!(
            std::fs::set_permissions(base.join("dst"), std::fs::Permissions::from_mode(0o755))
                .is_ok()
        );
        assert!(std::fs::remove_dir_all(&base).is_ok());
    }

    /// Verifies `DOSKEY` edit modes, `DIR /C` & `/-C`, `START` launch options on `ExternalSpawnRequest`,
    /// and `PipeExecutionMode::OsStreamingPipe`.
    #[test]
    fn test_phase3_doskey_dir_thousands_start_options_and_streaming_pipe() {
        /// Shared spy [`crate::runtime::ProcessSpawner`] recording [`ExternalSpawnRequest`]s across `START` subshells.
        #[derive(Debug, Clone, Default)]
        struct SpyStartSpawner {
            /// Shared recorded spawn requests.
            calls: std::sync::Arc<std::sync::Mutex<Vec<crate::runtime::ExternalSpawnRequest>>>,
        }
        impl crate::runtime::ProcessSpawner for SpyStartSpawner {
            /// Records `req` and returns a successful mock spawn result.
            ///
            /// # Arguments
            /// * `req` - [`crate::runtime::ExternalSpawnRequest`] to record.
            ///
            /// # Returns
            /// `Ok(ExternalSpawnResult)` with `"ok"` stdout.
            ///
            /// # Errors
            /// Never returns [`crate::error::CmdError`]; signature satisfies [`crate::runtime::ProcessSpawner`].
            fn spawn_external(
                &mut self,
                req: &crate::runtime::ExternalSpawnRequest,
            ) -> Result<crate::runtime::ExternalSpawnResult, crate::error::CmdError> {
                self.calls
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(req.clone());
                Ok(crate::runtime::ExternalSpawnResult {
                    exit_code: ExitCode::SUCCESS,
                    stdout: "ok".to_owned(),
                    stderr: String::new(),
                })
            }
            /// Clones this [`SpyStartSpawner`] sharing the underlying `Arc` call log.
            ///
            /// # Returns
            /// Boxed clone of `self`.
            fn clone_box(&self) -> Box<dyn crate::runtime::ProcessSpawner> {
                Box::new(self.clone())
            }
        }

        let mut interp = Interpreter::default();
        assert_eq!(
            run_cmd(&mut interp, "doskey /overstrike").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.console.doskey_edit_mode,
            crate::types::DoskeyEditMode::Overstrike
        );
        assert_eq!(run_cmd(&mut interp, "doskey /insert").0, ExitCode::SUCCESS);
        assert_eq!(
            interp.console.doskey_edit_mode,
            crate::types::DoskeyEditMode::Insert
        );

        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/big.bin", &[b'x'; 1234]),
            Ok(())
        );
        let (_, grouped_out, _) = run_cmd(&mut interp, "dir /c C:/big.bin");
        assert!(grouped_out.contains("1,234"));
        let (_, plain_out, _) = run_cmd(&mut interp, "dir /-c C:/big.bin");
        assert!(plain_out.contains("1234"));

        assert_eq!(interp.proc_env.vfs.write_bytes("C:/app.exe", b"MZ"), Ok(()));
        let spy = SpyStartSpawner::default();
        let calls_ref = std::sync::Arc::clone(&spy.calls);
        interp.proc_env.spawner = Box::new(spy);
        for cmd in [
            "start /b /wait /low /separate C:/app.exe",
            "start /min /normal C:/app.exe",
            "start /max /high C:/app.exe",
            "start /realtime C:/app.exe",
            "start /abovenormal C:/app.exe",
            "start /belownormal C:/app.exe",
        ] {
            assert_eq!(run_cmd(&mut interp, cmd).0, ExitCode::SUCCESS);
        }
        let calls = calls_ref.lock().map(|g| g.clone()).unwrap_or_default();
        assert_eq!(calls.len(), 6);
        assert_eq!(
            calls
                .first()
                .map(|c| (c.window_mode, c.wait_mode, c.priority)),
            Some((
                crate::types::StartWindowMode::BackgroundNoWindow,
                crate::types::WaitMode::Wait,
                crate::types::ProcessPriority::Low,
            ))
        );
        assert_eq!(
            calls.get(2).map(|c| (c.window_mode, c.priority)),
            Some((
                crate::types::StartWindowMode::Maximized,
                crate::types::ProcessPriority::High,
            ))
        );

        interp.config.pipe_execution_mode = crate::types::PipeExecutionMode::OsStreamingPipe;
        assert_eq!(
            run_cmd(&mut interp, "echo stream_ok | find \"stream_ok\"").0,
            ExitCode::SUCCESS
        );
    }

    /// Verifies `%COPYCMD%` (`/-Y`, `/N`, `All`), `COPY /A` wildcards, `COPY /V`, `verify_readback_matches`,
    /// and `XCOPY /P`, `/-Y`, `/Y`, `/V`.
    #[test]
    fn test_phase3_copycmd_ascii_verify_and_xcopy_prompts() {
        let mut interp = Interpreter::default();
        assert_eq!(
            super::fs_cmds::verify_readback_matches("C:/x", b"ab", b"ab"),
            Ok(())
        );
        assert!(super::fs_cmds::verify_readback_matches("C:/x", b"ab", b"cd").is_err());

        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/wsrc", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/wdst", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/wsrc/a1.txt", b"hi\x1Aignored"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/wsrc/a2.txt", b"plain"),
            Ok(())
        );
        assert_eq!(
            run_cmd(&mut interp, "copy /a /v C:/wsrc/*.txt C:/wdst").0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.proc_env.vfs.read_bytes("C:/wdst/a1.txt"),
            Ok(b"hi\x1A".to_vec())
        );
        assert_eq!(
            interp.proc_env.vfs.read_bytes("C:/wdst/a2.txt"),
            Ok(b"plain\x1A".to_vec())
        );
        assert_eq!(
            run_cmd(&mut interp, "copy /v C:/wsrc/a2.txt NUL").0,
            ExitCode::SUCCESS
        );

        let nl = crate::types::LF_CHAR;
        let mut all_io = crate::runtime::BufferedIoStreams::with_stdin(format!("All{nl}"));
        assert_eq!(
            interp.execute_interactive_line("copy /-y C:/wsrc/*.txt C:/wdst", &mut all_io),
            ExitCode::SUCCESS
        );
        assert_eq!(run_cmd(&mut interp, "set COPYCMD=/N").0, ExitCode::SUCCESS);
        assert_eq!(
            run_cmd(
                &mut interp,
                "copy C:/wsrc/a1.txt+C:/wsrc/a2.txt C:/wdst/a1.txt"
            )
            .0,
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(
                &mut interp,
                "copy C:/wsrc/a1.txt+C:/wsrc/a2.txt C:/wsrc/a1.txt"
            )
            .0,
            ExitCode::SUCCESS
        );

        assert_eq!(run_cmd(&mut interp, "set COPYCMD=").0, ExitCode::SUCCESS);
        let mut xc_no = crate::runtime::BufferedIoStreams::with_stdin(format!("N{nl}"));
        assert_eq!(
            interp.execute_interactive_line("xcopy /p C:/wsrc/a2.txt C:/wdst/", &mut xc_no),
            ExitCode::SUCCESS
        );
        let mut xc_ow_no = crate::runtime::BufferedIoStreams::with_stdin(format!("N{nl}"));
        assert_eq!(
            interp.execute_interactive_line("xcopy /-y C:/wsrc/a2.txt C:/wdst/", &mut xc_ow_no),
            ExitCode::SUCCESS
        );
        let mut xc_yes =
            crate::runtime::BufferedIoStreams::with_stdin(format!("N{nl}Y{nl}N{nl}Y{nl}Y{nl}"));
        assert_eq!(
            interp.execute_interactive_line("xcopy /s /p /-y /v C:/wsrc C:/wdst", &mut xc_yes),
            ExitCode::SUCCESS
        );
        assert_eq!(
            run_cmd(&mut interp, "xcopy /y /v C:/wsrc/a2.txt C:/wdst/").0,
            ExitCode::SUCCESS
        );
        let (con_code, con_out, _) = run_cmd(&mut interp, "copy /b C:/wsrc/a2.txt CON");
        assert_eq!(con_code, ExitCode::SUCCESS);
        assert!(con_out.contains("plain"));
        assert_eq!(
            run_cmd(
                &mut interp,
                "setlocal disableextensions & md C:/ext_off_ok & endlocal"
            )
            .0,
            ExitCode::SUCCESS
        );
    }

    /// Verifies MS-DOS `TRUENAME`, `CTTY`, `LH`, `MEM`, `VER /R`, `VERIFY`, `CHOICE /S /T:c,n`, `DEL <dir>`, and `/P` `EXIT`.
    #[test]
    fn test_msdos_builtins_truename_ctty_lh_mem_choice_and_permanent_exit() {
        use crate::dos::SimulatedDosKernel;
        use crate::runtime::BufferedIoStreams;
        use crate::types::{ConsoleRenderBackend, ShellDialect};

        let (mut dos_interp, _) = Interpreter::with_dos_kernel(SimulatedDosKernel::new());
        dos_interp.apply_shell_dialect(ShellDialect::MsDos622);
        assert_eq!(dos_interp.config.dialect, ShellDialect::MsDos622);
        dos_interp.apply_shell_dialect(ShellDialect::FreeDos);
        dos_interp.apply_shell_dialect(ShellDialect::WindowsNtCmd);
        dos_interp.apply_shell_dialect(ShellDialect::MsDos622);

        let mut io = BufferedIoStreams::new();
        assert_eq!(
            dos_interp.execute_interactive_line("truename", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(io.stdout, format!("C:\\{CRLF}"));
        io.stdout.clear();
        assert_eq!(
            dos_interp.execute_interactive_line("truename ver_long_name.text", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(io.stdout, format!("C:\\VER_LONG.TEX{CRLF}"));

        assert_eq!(
            dos_interp.execute_interactive_line("ctty COM1:", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            dos_interp.console.render_backend,
            ConsoleRenderBackend::DumbTeletype
        );
        assert_eq!(
            dos_interp.execute_interactive_line("ctty CON", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            dos_interp.console.render_backend,
            ConsoleRenderBackend::BiosVgaAttribute
        );
        assert_eq!(
            dos_interp.execute_interactive_line("ctty PRN", &mut io),
            ExitCode::FAILURE
        );
        assert_eq!(
            dos_interp.execute_interactive_line("ctty CON", &mut io),
            ExitCode::SUCCESS
        );

        io.stdout.clear();
        assert_eq!(
            dos_interp.execute_interactive_line("lh /L:1,4096 /S echo loaded_high", &mut io),
            ExitCode::SUCCESS
        );
        assert!(io.stdout.contains("loaded_high"));
        assert_eq!(
            dos_interp.execute_interactive_line("loadhigh /S", &mut io),
            ExitCode::SUCCESS
        );
        assert_ne!(
            dos_interp.execute_interactive_line("lh /X", &mut io),
            ExitCode::SUCCESS
        );

        io.stdout.clear();
        assert_eq!(
            dos_interp.execute_interactive_line("mem", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            dos_interp.execute_interactive_line("mem.com /c /d /f /p /m:MOUSE /x", &mut io),
            ExitCode::SUCCESS
        );
        assert!(io.stdout.contains("MOUSE is using the following memory:"));
        assert!(io.stdout.contains("Modules using memory below 1 MB:"));
        assert!(io.stdout.contains("Conventional Memory Detail:"));
        assert!(io.stdout.contains("Free Conventional Memory:"));
    }

    /// Verifies MS-DOS `VER /R`, `VERIFY` kernel sync, and `DATE`/`TIME` kernel synchronization.
    #[test]
    fn test_msdos_ver_verify_and_rtc_sync() {
        use crate::dos::{DosKernelApi, SimulatedDosKernel};
        use crate::runtime::BufferedIoStreams;
        use crate::types::{ShellDialect, VerifyCopyMode};

        let (mut dos_interp, shared) = Interpreter::with_dos_kernel(SimulatedDosKernel::new());
        dos_interp.apply_shell_dialect(ShellDialect::MsDos622);
        let mut io = BufferedIoStreams::new();
        assert_eq!(
            dos_interp.execute_interactive_line("ver /r", &mut io),
            ExitCode::SUCCESS
        );
        assert!(io.stdout.contains("DOS is in HMA"));

        assert_eq!(
            dos_interp.execute_interactive_line("verify on", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            shared.with(DosKernelApi::verify_flag),
            VerifyCopyMode::Verified
        );
        assert_eq!(
            dos_interp.execute_interactive_line("verify off", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            shared.with(DosKernelApi::verify_flag),
            VerifyCopyMode::Unverified
        );
        for rtc_cmd in [
            "date 1995-08-24",
            "date 08-25-1995",
            "date freeform",
            "date 08-25-1995-extra",
            "date 08-xx-1995",
            "time 14:30:20.50",
            "time freeform",
            "time 1:2:3:4",
            "time 14:xx",
        ] {
            assert_eq!(
                dos_interp.execute_interactive_line(rtc_cmd, &mut io),
                ExitCode::SUCCESS
            );
        }

        let mut rtc_in = BufferedIoStreams::with_stdin("1995-08-26\r\n09:15\r\n".to_owned());
        assert_eq!(
            dos_interp.execute_interactive_line("date", &mut rtc_in),
            ExitCode::SUCCESS
        );
        assert_eq!(
            dos_interp.execute_interactive_line("time", &mut rtc_in),
            ExitCode::SUCCESS
        );
    }

    /// Verifies MS-DOS `CHOICE /S /T:c,n`, `DEL <dir>`, `/P` `EXIT`, and host fallback DOS commands.
    #[test]
    fn test_msdos_choice_del_dir_and_permanent_exit() {
        use crate::dos::SimulatedDosKernel;
        use crate::runtime::BufferedIoStreams;
        use crate::types::{PermanentShellMode, ShellDialect};

        let (mut dos_interp, _shared) = Interpreter::with_dos_kernel(SimulatedDosKernel::new());
        dos_interp.apply_shell_dialect(ShellDialect::MsDos622);
        let mut io = BufferedIoStreams::new();

        let mut ch_io = BufferedIoStreams::with_stdin("y\r\nY\r\n\r\n".to_owned());
        assert_eq!(
            dos_interp.execute_interactive_line("choice /c:YN /s /t:Y,5 Continue", &mut ch_io),
            ExitCode::new(255)
        );
        assert_eq!(
            dos_interp.execute_interactive_line("choice /c:YN /s /t:Y,5 Continue", &mut ch_io),
            ExitCode::new(1)
        );
        assert_eq!(
            dos_interp.execute_interactive_line("choice /c:YN \"/t:N,3\"", &mut ch_io),
            ExitCode::new(2)
        );
        assert!(ch_io.stdout.contains("Continue [Y,N]?"));
        for bad_ch in [
            "choice /t:Y",
            "choice /t:Y,bad",
            "choice \"/t:Y,bad\"",
            "choice /t:YY,5",
            "choice \"/t:YY,5\"",
            "choice Msg1 Msg2",
        ] {
            assert_ne!(
                dos_interp.execute_interactive_line(bad_ch, &mut io),
                ExitCode::SUCCESS
            );
        }

        assert_eq!(
            dos_interp.execute_interactive_line("md C:\\WIPE", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            dos_interp.execute_interactive_line("echo hi > C:\\WIPE\\A.TXT", &mut io),
            ExitCode::SUCCESS
        );
        let mut del_io = BufferedIoStreams::with_stdin("Y\r\n".to_owned());
        assert_eq!(
            dos_interp.execute_interactive_line("del C:\\WIPE", &mut del_io),
            ExitCode::SUCCESS
        );
        assert!(
            del_io
                .stdout
                .contains("All files in directory will be deleted!")
        );

        dos_interp.config.permanent_shell = PermanentShellMode::Permanent;
        assert_eq!(
            dos_interp.execute_interactive_line("exit 9", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(dos_interp.exec.exited(), None);

        let mut host_interp = Interpreter::new();
        assert_eq!(
            host_interp.execute_interactive_line("truename C:/", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            host_interp.execute_interactive_line("ctty CON", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            host_interp.execute_interactive_line("mem /m", &mut io),
            ExitCode::SUCCESS
        );
        host_interp.apply_shell_dialect(ShellDialect::MsDos622);
        assert_eq!(host_interp.config.version_banner, "MS-DOS Version 6.22");
    }
}
