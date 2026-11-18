//! AST statement, pipeline, redirection, `FOR` / `IF` control-flow, and batch-frame execution engine.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::builtins::{BuiltinInvocation, dispatch_builtin};
use crate::error::{CmdError, ExecutionLimitFailure, LimitKind};
use crate::parser::ast::{
    CommandExpr, CompoundBlock, ForFOptions, ForStatement, ForVariant, IfCondition, IfStatement,
    Redirection, RedirectionKind, SimpleCommand, Statement, TokenSelector,
};
use crate::parser::phase1::{Phase1Context, expand_phase1};
use crate::parser::phase2::{
    parse_logical_line_statement, read_and_parse_next_statement_bytes, tokenize_command_arguments,
};
use crate::parser::phase3::expand_phase3;
use crate::parser::phase4::expand_phase4;
use crate::reader::char_map::LogicalLineBuffer;
use crate::reader::encoding::{decode_script_bytes, encode_output_bytes_with_codepage};
use crate::reader::stream::BatchFrameReader;
use crate::span::{ByteOffset, Span};
use crate::types::{
    BS_CHAR, BS_STR, CR_CHAR, CRLF, CaseSensitivity, CompletionScope, EchoState, EchoSuppression,
    ExecutionContext, ExitCode, ExtensionsMode, ForVarName, InterruptState, LabelName,
    NegationMode, PipeExecutionMode, TAB_CHAR,
};
use crate::vfs::InMemoryVfs;
use crate::vfs::glob::matches_win32_glob;
use crate::vfs::path::WindowsPath;

use super::interpreter::{BatchCallFrame, FdSink, FlowControl, Interpreter};
use super::io::{
    BufferedIoStreams, CapturedOutputChunk, CmdIo, OutputCaptureMode, OutputStreamId, RedirectedIo,
};
use super::{restore_vfs_cwds, snapshot_vfs_cwds};

/// ASCII Single-Quote character (`'`).
const SINGLE_QUOTE_CHAR: char = '\'';

/// Extracts the directory or drive prefix from a wildcard pattern (`sub\*.txt` -> `sub\`,
/// `C:/sub/*.txt` -> `C:/sub/`, `C:*.txt` -> `C:`, `*.txt` -> `""`).
///
/// # Arguments
/// * `pattern` - Expanded wildcard pattern string.
///
/// # Returns
/// Borrowed prefix slice to prepend to each matched directory entry name.
#[must_use]
fn wildcard_directory_prefix(pattern: &str) -> &str {
    if let Some(sep_idx) = pattern.rfind([BS_CHAR, '/']) {
        return pattern.get(..sep_idx.saturating_add(1)).unwrap_or("");
    }
    if pattern.as_bytes().get(1) == Some(&b':')
        && pattern
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
    {
        return pattern.get(..2).unwrap_or("");
    }
    ""
}

impl Interpreter {
    /// Executes an interactive command line, returning a typed [`CmdError`] if an execution safety
    /// budget ([`super::ExecutionLimits`]) is exceeded.
    ///
    /// # Arguments
    /// * `line` - Raw interactive command string.
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// `Ok(ExitCode)` when the command finishes within configured safety budgets.
    ///
    /// # Errors
    /// Returns [`CmdError::ExecutionLimitExceeded`] if step, loop, or recursion budgets are exceeded.
    pub fn execute_interactive_line_checked(
        &mut self,
        line: &str,
        io: &mut dyn CmdIo,
    ) -> Result<ExitCode, CmdError> {
        self.exec.reset_step_counter();
        self.console.record_history(line.trim());

        let expanded_doskey = self.expand_doskey_line(line);
        let src_id = self
            .exec
            .allocate_ephemeral_source("<interactive>", &expanded_doskey);
        let raw_buf = LogicalLineBuffer::from_str_at(src_id, ByteOffset(0), &expanded_doskey);
        let cwd = self.current_cwd_string();
        let exit_code = self.exec.last_exit_code();
        let env_ref = &self.proc_env.env;
        let vfs_ref = self.proc_env.vfs.as_ref();
        let p1_ctx = Phase1Context {
            exec_context: ExecutionContext::InteractiveRepl,
            arg0: "cmd",
            positional_args: &[],
            all_args_raw: "",
            vfs: vfs_ref,
            env_lookup: |k| env_ref.get_with_dynamics(k, &cwd, exit_code),
        };
        let phase1_buf = expand_phase1(&raw_buf, &p1_ctx).unwrap_or(raw_buf);

        let stmt = match parse_logical_line_statement(&phase1_buf, src_id, ByteOffset(0)) {
            Ok(s) => s,
            Err(err) => {
                self.emit_cmd_error(&err, io);
                return Ok(self.exec.last_exit_code());
            }
        };

        match self.execute_statement(&stmt, ExecutionContext::InteractiveRepl, io) {
            FlowControl::ExitShell(code) => {
                self.exec.terminate_shell(code);
            }
            FlowControl::Abort(err) => {
                self.record_failure(err.exit_code());
                return Err(err);
            }
            FlowControl::Continue
            | FlowControl::Goto { .. }
            | FlowControl::TransferBatchFrame { .. }
            | FlowControl::ExitBatchFrame(_) => {}
        }
        Ok(self.exec.last_exit_code())
    }

    /// Executes an interactive command line (or `cmd /C "..."` line), rendering any [`CmdError`]
    /// to `io` stderr and returning the resulting [`ExitCode`].
    ///
    /// # Arguments
    /// * `line` - Raw interactive command string.
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// Resulting [`ExitCode`].
    pub fn execute_interactive_line(&mut self, line: &str, io: &mut dyn CmdIo) -> ExitCode {
        match self.execute_interactive_line_checked(line, io) {
            Ok(code) => code,
            Err(err) => {
                self.emit_cmd_error(&err, io);
                self.exec.last_exit_code()
            }
        }
    }

    /// Executes an entire batch file located at `script_path` on the VFS using raw-byte line reading.
    ///
    /// Distinguishes [`CmdError::MissingBatchFile`] (`FileNotFound`/`PathNotFound`) from
    /// [`CmdError::AccessDenied`], [`CmdError::SharingViolation`], [`CmdError::EncodingFailure`],
    /// and [`CmdError::ExecutionLimitExceeded`].
    ///
    /// # Arguments
    /// * `script_path` - Path of the `.bat` or `.cmd` file on the VFS.
    /// * `arg0` - `%0` display name.
    /// * `positional_args` - Positional arguments `%1`..`%9`+.
    /// * `all_args_raw` - Raw `%*` argument string.
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// `Ok(ExitCode)` upon script completion.
    ///
    /// # Errors
    /// Returns [`CmdError::MissingBatchFile`], [`CmdError::AccessDenied`], [`CmdError::EncodingFailure`],
    /// or [`CmdError::ExecutionLimitExceeded`] if opening, decoding, or executing fails.
    pub fn execute_batch_file(
        &mut self,
        script_path: &str,
        arg0: &str,
        positional_args: Vec<String>,
        all_args_raw: String,
        io: &mut dyn CmdIo,
    ) -> Result<ExitCode, CmdError> {
        if self.exec.call_stack().is_empty() {
            self.exec.reset_step_counter();
        }
        let raw_bytes = self.proc_env.vfs.read_bytes(script_path).map_err(|err| {
            if matches!(
                err,
                CmdError::FileNotFound { .. } | CmdError::PathNotFound { .. }
            ) {
                CmdError::MissingBatchFile {
                    path: script_path.to_owned(),
                }
            } else {
                err
            }
        })?;
        let preview_text = String::from_utf8_lossy(&raw_bytes).into_owned();
        let src_id = self
            .exec
            .allocate_batch_source(script_path, raw_bytes, preview_text);

        let base_depth = self.proc_env.env.depth();
        self.exec.push_call_frame(
            BatchCallFrame {
                script_path: script_path.to_owned(),
                arg0: arg0.to_owned(),
                positional_args,
                all_args_raw,
                reader: BatchFrameReader::new(src_id),
                base_setlocal_depth: base_depth,
            },
            self.config.limits,
            Span::new(src_id, ByteOffset(0), ByteOffset(0)),
        )?;

        let run_res = self.run_top_batch_frame(io);
        self.exec.pop_call_frame();
        self.unwind_setlocal_to(base_depth);
        run_res?;
        Ok(self.exec.last_exit_code())
    }

    /// Executes a `CALL :label [args...]` subroutine within the currently active batch script frame.
    ///
    /// # Arguments
    /// * `target` - Target `:label` name.
    /// * `args` - Subroutine positional arguments `%1`..`%9`+.
    /// * `all_args_raw` - Raw `%*` tail for the subroutine.
    /// * `call_span` - Source [`Span`] of the `CALL` statement.
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// `Ok(ExitCode)` when the subroutine returns via `GOTO :EOF` or `EXIT /B`.
    ///
    /// # Errors
    /// Returns [`CmdError::BatchLabelNotFound`], [`CmdError::ExecutionLimitExceeded`], or VFS/encoding
    /// [`CmdError`] variants if label lookup or execution fails.
    pub fn call_subroutine_label(
        &mut self,
        target: &LabelName,
        args: Vec<String>,
        all_args_raw: String,
        call_span: Span,
        io: &mut dyn CmdIo,
    ) -> Result<ExitCode, CmdError> {
        let Some(caller) = self.exec.call_stack().last() else {
            return Err(CmdError::BatchLabelNotFound {
                span: call_span,
                label: target.clone(),
            });
        };
        let script_path = caller.script_path.clone();
        let src_id = caller.reader.source_id;
        let current_reader = caller.reader.clone();

        let raw_bytes = self.proc_env.vfs.read_bytes(&script_path)?;
        let label_offset = current_reader.find_label_offset_bytes(
            &raw_bytes,
            self.console.codepage,
            target,
            call_span,
        )?;

        let mut sub_reader = BatchFrameReader::new(src_id);
        sub_reader.seek(label_offset);
        let base_depth = self.proc_env.env.depth();

        self.exec.push_call_frame(
            BatchCallFrame {
                script_path,
                arg0: format!(":{}", target.as_str()),
                positional_args: args,
                all_args_raw,
                reader: sub_reader,
                base_setlocal_depth: base_depth,
            },
            self.config.limits,
            call_span,
        )?;

        let run_res = self.run_top_batch_frame(io);
        self.exec.pop_call_frame();
        self.unwind_setlocal_to(base_depth);
        run_res?;
        Ok(self.exec.last_exit_code())
    }

    /// Runs the statement loop for the top [`BatchCallFrame`] using raw-byte offsets so self-modifying
    /// batch scripts and mid-script `CHCP` switches work identically to `cmd.exe`.
    ///
    /// # Arguments
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// `Ok(())` when the batch frame completes.
    ///
    /// # Errors
    /// Returns [`CmdError::EncodingFailure`] or [`CmdError::ExecutionLimitExceeded`] on fatal errors.
    fn run_top_batch_frame(&mut self, io: &mut dyn CmdIo) -> Result<(), CmdError> {
        let mut last_known_raw_len: usize = 0;
        while let Some(top_frame) = self.exec.call_stack().last().cloned() {
            self.poll_dos_ctrl_break();
            if self.exec.interrupt_state == InterruptState::Pending {
                self.exec.interrupt_state = InterruptState::Clear;
                let _interrupt_flow = self.handle_ctrl_c_interrupt(io);
                continue;
            }

            let script_path = top_frame.script_path;
            let arg0 = top_frame.arg0;
            let pos_args = top_frame.positional_args;
            let all_args_raw = top_frame.all_args_raw;
            let mut reader = top_frame.reader;

            let Ok(raw_bytes) = self.proc_env.vfs.read_bytes(&script_path) else {
                if reader.cursor.0 >= last_known_raw_len.max(1) {
                    break;
                }
                let err = CmdError::MissingBatchFile { path: script_path };
                self.emit_cmd_error(&err, io);
                break;
            };
            last_known_raw_len = raw_bytes.len();

            let mut labels_discard = Vec::new();
            let mut carets_discard = Vec::new();
            let cwd = self.current_cwd_string();
            let exit_code = self.exec.last_exit_code();
            let env_ref = &self.proc_env.env;
            let vfs_ref = self.proc_env.vfs.as_ref();
            let active_cp = self.console.codepage;

            let next_stmt_res = read_and_parse_next_statement_bytes(
                &mut reader,
                &raw_bytes,
                active_cp,
                &mut labels_discard,
                &mut carets_discard,
                &mut |raw_line| {
                    let p1_ctx = Phase1Context {
                        exec_context: ExecutionContext::BatchFile,
                        arg0: &arg0,
                        positional_args: &pos_args,
                        all_args_raw: &all_args_raw,
                        vfs: vfs_ref,
                        env_lookup: |k| env_ref.get_with_dynamics(k, &cwd, exit_code),
                    };
                    expand_phase1(raw_line, &p1_ctx)
                },
            );

            self.exec.sync_top_frame_reader(&reader);

            let stmt = match next_stmt_res {
                Ok(Some(s)) => s,
                Ok(None) | Err(CmdError::MissingBatchFile { .. }) => break,
                Err(
                    err @ (CmdError::EncodingFailure { .. }
                    | CmdError::EncodingByteOffsetMismatch { .. }),
                ) => {
                    self.record_failure(err.exit_code());
                    return Err(err);
                }
                Err(err) => {
                    self.emit_cmd_error(&err, io);
                    break;
                }
            };

            let flow = self.execute_statement(&stmt, ExecutionContext::BatchFile, io);
            if !self.apply_batch_flow_control(flow, &script_path, &reader, io)? {
                break;
            }
        }
        Ok(())
    }

    /// Applies the [`FlowControl`] outcome of a statement executed within `run_top_batch_frame`.
    ///
    /// # Arguments
    /// * `flow` - [`FlowControl`] returned by statement execution.
    /// * `script_path` - Active batch script path on the VFS.
    /// * `reader` - Current [`BatchFrameReader`] snapshot used for label lookup.
    /// * `io` - Mutable [`CmdIo`] stream for error reporting.
    ///
    /// # Returns
    /// `Ok(true)` to continue reading statements in the current frame, or `Ok(false)` to exit the frame loop.
    ///
    /// # Errors
    /// Returns [`CmdError`] on fatal VFS read failure during `GOTO`/transfer or when [`FlowControl::Abort`] occurs.
    fn apply_batch_flow_control(
        &mut self,
        flow: FlowControl,
        script_path: &str,
        reader: &BatchFrameReader,
        io: &mut dyn CmdIo,
    ) -> Result<bool, CmdError> {
        match flow {
            FlowControl::Continue => Ok(true),
            FlowControl::TransferBatchFrame {
                script_path: next_path,
                arg0,
                positional_args,
                all_args_raw,
            } => {
                let raw_bytes = self.proc_env.vfs.read_bytes(&next_path)?;
                let preview = String::from_utf8_lossy(&raw_bytes).into_owned();
                let new_sid = self
                    .exec
                    .allocate_batch_source(&next_path, raw_bytes, preview);
                self.exec.transfer_top_frame(
                    &next_path,
                    new_sid,
                    &arg0,
                    &positional_args,
                    &all_args_raw,
                );
                Ok(true)
            }
            FlowControl::Goto { target, span } => {
                if target.is_eof() && self.proc_env.env.extensions == ExtensionsMode::Enabled {
                    return Ok(false);
                }
                let latest_bytes = self.proc_env.vfs.read_bytes(script_path)?;
                match reader.find_label_offset_bytes(
                    &latest_bytes,
                    self.console.codepage,
                    &target,
                    span,
                ) {
                    Ok(new_offset) => {
                        self.exec.seek_top_frame(new_offset);
                        Ok(true)
                    }
                    Err(err) => {
                        self.emit_cmd_error(&err, io);
                        Ok(false)
                    }
                }
            }
            FlowControl::ExitBatchFrame(code) => {
                self.exec.last_exit_code = code;
                Ok(false)
            }
            FlowControl::ExitShell(code) => {
                self.exec.terminate_shell(code);
                Ok(false)
            }
            FlowControl::Abort(err) => {
                self.record_failure(err.exit_code());
                Err(err)
            }
        }
    }

    /// Executes a single AST [`Statement`], checking [`super::ExecutionLimits::max_steps`].
    ///
    /// # Arguments
    /// * `stmt` - AST [`Statement`] to execute.
    /// * `ctx` - Active [`ExecutionContext`].
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// Resulting [`FlowControl`].
    pub fn execute_statement(
        &mut self,
        stmt: &Statement,
        ctx: ExecutionContext,
        io: &mut dyn CmdIo,
    ) -> FlowControl {
        match stmt {
            Statement::Empty(_) | Statement::Label(_) => FlowControl::Continue,
            Statement::Rem(rem) => {
                if let Err(err) = self.exec.consume_step_budget(self.config.limits, rem.span) {
                    return FlowControl::Abort(err);
                }
                if self.console.echo_state == EchoState::On
                    && rem.echo_suppression == EchoSuppression::NotSuppressed
                {
                    let prompt = self.format_prompt();
                    let line = format!("{prompt}REM {}{CRLF}", rem.comment_text);
                    io.write_stdout_str(&line).unwrap_or(());
                }
                self.mark_cmd_succeeded();
                FlowControl::Continue
            }
            Statement::Command(expr) => self.execute_command_expr(expr, ctx, io),
        }
    }

    /// Executes a [`CommandExpr`] node (`Simple`, `Block`, `If`, `For`, `Pipe`, `And`, `Or`, `Seq`).
    ///
    /// # Arguments
    /// * `expr` - [`CommandExpr`] AST node.
    /// * `ctx` - Active [`ExecutionContext`].
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// Resulting [`FlowControl`].
    pub fn execute_command_expr(
        &mut self,
        expr: &CommandExpr,
        ctx: ExecutionContext,
        io: &mut dyn CmdIo,
    ) -> FlowControl {
        match expr {
            CommandExpr::Simple(simple) => self.execute_simple_command(simple, ctx, io),
            CommandExpr::Block(block) => self.execute_compound_block(block, ctx, io),
            CommandExpr::If(if_stmt) => self.execute_if_statement(if_stmt, ctx, io),
            CommandExpr::For(for_stmt) => self.execute_for_statement(for_stmt, ctx, io),
            CommandExpr::Seq { left, right, .. } => {
                let flow = self.execute_command_expr(left, ctx, io);
                if flow != FlowControl::Continue {
                    return flow;
                }
                self.execute_command_expr(right, ctx, io)
            }
            CommandExpr::And { left, right, .. } => {
                let flow = self.execute_command_expr(left, ctx, io);
                if flow != FlowControl::Continue {
                    return flow;
                }
                if self.exec.last_cmd_succeeded() {
                    self.execute_command_expr(right, ctx, io)
                } else {
                    FlowControl::Continue
                }
            }
            CommandExpr::Or { left, right, .. } => {
                let flow = self.execute_command_expr(left, ctx, io);
                if flow != FlowControl::Continue {
                    return flow;
                }
                if self.exec.last_cmd_succeeded() {
                    FlowControl::Continue
                } else {
                    self.execute_command_expr(right, ctx, io)
                }
            }
            CommandExpr::Pipe { left, right, .. } => self.execute_pipeline(left, right, io),
        }
    }

    /// Executes `left | right` under authentic `cmd.exe /S /D /c` child subshell semantics:
    /// shares VFS file mutations sequentially in `O(1)` without cloning VFS trees, restores
    /// drive/CWD isolation between `left`, `right`, and parent, and honors `/A` vs `/U` pipe encoding.
    ///
    /// # Arguments
    /// * `left` - Upstream [`CommandExpr`].
    /// * `right` - Downstream [`CommandExpr`].
    /// * `io` - Parent [`CmdIo`] stream.
    ///
    /// # Returns
    /// [`FlowControl::Continue`] (or [`FlowControl::Abort`] if safety limits trigger).
    fn execute_pipeline(
        &mut self,
        left: &CommandExpr,
        right: &CommandExpr,
        io: &mut dyn CmdIo,
    ) -> FlowControl {
        let saved_cwds = snapshot_vfs_cwds(self.proc_env.vfs.as_ref());
        let upstream_stdin = io
            .read_stdin_bytes(self.console.codepage)
            .unwrap_or_default();

        let mut left_shell = self.fork_subshell_taking_vfs();
        let mut left_io = BufferedIoStreams::with_pipe_bytes(upstream_stdin, self.console.codepage);
        let left_flow =
            left_shell.execute_command_expr(left, ExecutionContext::PipeSubshell, &mut left_io);
        self.proc_env.vfs =
            core::mem::replace(&mut left_shell.proc_env.vfs, Box::new(InMemoryVfs::new()));
        restore_vfs_cwds(self.proc_env.vfs.as_mut(), &saved_cwds);

        if !left_io.stderr.is_empty() {
            io.write_stderr_str(&left_io.stderr).unwrap_or(());
        }
        if let FlowControl::Abort(err) = left_flow {
            return FlowControl::Abort(err);
        }
        self.poll_dos_ctrl_break();
        if self.exec.interrupt_state == InterruptState::Pending {
            return self.handle_ctrl_c_interrupt(io);
        }

        let (pipe_bytes, pipe_cp) = match self.config.pipe_execution_mode {
            PipeExecutionMode::InMemoryBuffered | PipeExecutionMode::OsStreamingPipe => left_io
                .into_encoded_pipe_output(self.config.unicode_output_mode, self.console.codepage),
        };
        if self.config.pipe_execution_mode == PipeExecutionMode::OsStreamingPipe {
            io.flush_outputs().unwrap_or(());
        }

        let mut right_shell = self.fork_subshell_taking_vfs();
        let mut right_io = BufferedIoStreams::with_pipe_bytes(pipe_bytes, pipe_cp);
        let right_flow =
            right_shell.execute_command_expr(right, ExecutionContext::PipeSubshell, &mut right_io);
        self.proc_env.vfs =
            core::mem::replace(&mut right_shell.proc_env.vfs, Box::new(InMemoryVfs::new()));
        restore_vfs_cwds(self.proc_env.vfs.as_mut(), &saved_cwds);

        self.exec.last_exit_code = right_shell.exec.last_exit_code();
        self.exec.last_cmd_succeeded = right_shell.exec.last_cmd_succeeded();
        if !right_io.stdout.is_empty() {
            io.write_stdout_str(&right_io.stdout).unwrap_or(());
        }
        if !right_io.stderr.is_empty() {
            io.write_stderr_str(&right_io.stderr).unwrap_or(());
        }
        if let FlowControl::Abort(err) = right_flow {
            return FlowControl::Abort(err);
        }
        FlowControl::Continue
    }

    /// Executes a `( ... )` [`CompoundBlock`], opening and validating block-level redirections
    /// BEFORE executing the block body so failed `< missing.txt` or `> missing_dir/out.txt`
    /// skips the block body and reports the exact `cmd.exe` error to `stderr`.
    ///
    /// # Arguments
    /// * `block` - [`CompoundBlock`] AST node.
    /// * `ctx` - Active [`ExecutionContext`].
    /// * `io` - Parent [`CmdIo`] stream.
    ///
    /// # Returns
    /// Resulting [`FlowControl`].
    fn execute_compound_block(
        &mut self,
        block: &CompoundBlock,
        ctx: ExecutionContext,
        io: &mut dyn CmdIo,
    ) -> FlowControl {
        let new_inputs = match self.prepare_input_redirections(&block.redirections) {
            Ok(inp) => inp,
            Err(err) => {
                self.emit_cmd_error(&err, io);
                return FlowControl::Continue;
            }
        };
        let sinks = match self.prepare_output_redirections(&block.redirections) {
            Ok(s) => s,
            Err(err) => {
                self.emit_cmd_error(&err, io);
                return FlowControl::Continue;
            }
        };

        let saved_inputs = new_inputs
            .as_ref()
            .map(|m| core::mem::replace(&mut self.exec.active_input_handles, m.clone()));
        let saved_sinks = sinks
            .as_ref()
            .map(|s| core::mem::replace(&mut self.exec.active_output_sinks, s.clone()));

        let stdin_override = new_inputs.and_then(|mut m| m.remove(&0).flatten());
        let needs_capture = sinks.as_ref().is_some_and(|s| {
            s.get(&1) != Some(&FdSink::ConsoleStdout) || s.get(&2) != Some(&FdSink::ConsoleStderr)
        });
        let mut redir_io = RedirectedIo::new(
            io,
            stdin_override,
            if needs_capture {
                OutputCaptureMode::BufferedForSinks
            } else {
                OutputCaptureMode::PassThrough
            },
        );
        let mut final_flow = FlowControl::Continue;
        for stmt in &block.body {
            let flow = self.execute_statement(stmt, ctx, &mut redir_io);
            if flow != FlowControl::Continue {
                final_flow = flow;
                break;
            }
        }

        if let Some(prev_in) = saved_inputs {
            self.exec.active_input_handles = prev_in;
        }
        if let Some(prev_out) = saved_sinks {
            self.exec.active_output_sinks = prev_out;
        }

        let chunks = core::mem::take(&mut redir_io.output_chunks);
        if let Some(active_sinks) = sinks
            && !chunks.is_empty()
            && let Err(err) = self.flush_output_sinks(&active_sinks, &chunks, io)
        {
            self.emit_cmd_error(&err, io);
        }
        final_flow
    }

    /// Executes an [`IfStatement`], applying Phase 3 and Phase 4 expansions at evaluation time.
    ///
    /// # Arguments
    /// * `if_stmt` - [`IfStatement`] AST node.
    /// * `ctx` - Active [`ExecutionContext`].
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// Resulting [`FlowControl`].
    fn execute_if_statement(
        &mut self,
        if_stmt: &IfStatement,
        ctx: ExecutionContext,
        io: &mut dyn CmdIo,
    ) -> FlowControl {
        if let Err(err) = self
            .exec
            .consume_step_budget(self.config.limits, if_stmt.span)
        {
            return FlowControl::Abort(err);
        }
        let raw_cond = match &if_stmt.condition {
            IfCondition::ErrorLevel { raw_token, .. } => {
                let expanded = self.expand_word_phase3_and_4(&raw_token.text, raw_token.span);
                let thresh = crate::parser::var_ops::parse_cmd_int(&expanded)
                    .and_then(|v| i32::try_from(v).ok())
                    .unwrap_or(0);
                self.exec.last_exit_code().code() >= thresh
            }
            IfCondition::Exist { path_pattern } => {
                let expanded =
                    self.expand_word_phase3_and_4(path_pattern.unquoted(), path_pattern.span);
                self.proc_env.vfs.exists(&expanded)
            }
            IfCondition::Defined { var_name } => {
                let expanded = self.expand_word_phase3_and_4(var_name.unquoted(), var_name.span);
                self.proc_env.env.is_defined(&expanded)
            }
            IfCondition::CmdExtVersion { raw_token, .. } => {
                let expanded = self.expand_word_phase3_and_4(&raw_token.text, raw_token.span);
                let ver = expanded.parse::<u32>().unwrap_or(0);
                2 >= ver
            }
            IfCondition::Compare {
                left, op, right, ..
            } => {
                let l_exp = self.expand_word_phase3_and_4(&left.text, left.span);
                let r_exp = self.expand_word_phase3_and_4(&right.text, right.span);
                IfCondition::evaluate_comparison(&l_exp, *op, &r_exp, if_stmt.case_sensitivity)
            }
        };

        let cond_holds = match if_stmt.negated {
            NegationMode::Normal => raw_cond,
            NegationMode::Negated => !raw_cond,
        };

        if cond_holds {
            self.execute_command_expr(&if_stmt.then_branch, ctx, io)
        } else if let Some(else_expr) = &if_stmt.else_branch {
            self.execute_command_expr(else_expr, ctx, io)
        } else {
            FlowControl::Continue
        }
    }

    /// Executes a [`ForStatement`] (`StandardFiles`, `DirectoriesOnly`, `Recursive`, `NumericSequence`, `ParsedLines`).
    ///
    /// # Arguments
    /// * `for_stmt` - [`ForStatement`] AST node.
    /// * `ctx` - Active [`ExecutionContext`].
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// Resulting [`FlowControl`].
    fn execute_for_statement(
        &mut self,
        for_stmt: &ForStatement,
        ctx: ExecutionContext,
        io: &mut dyn CmdIo,
    ) -> FlowControl {
        if let Err(err) = self
            .exec
            .consume_step_budget(self.config.limits, for_stmt.span)
        {
            return FlowControl::Abort(err);
        }
        match &for_stmt.variant {
            ForVariant::StandardFiles => {
                let items = self
                    .expand_for_file_set(&for_stmt.in_set, CompletionScope::FilesAndDirectories);
                for item in items {
                    let flow =
                        self.run_for_iteration(for_stmt.variable, item, &for_stmt.body, ctx, io);
                    if flow != FlowControl::Continue {
                        return flow;
                    }
                }
            }
            ForVariant::DirectoriesOnly => {
                let items =
                    self.expand_for_file_set(&for_stmt.in_set, CompletionScope::DirectoriesOnly);
                for item in items {
                    let flow =
                        self.run_for_iteration(for_stmt.variable, item, &for_stmt.body, ctx, io);
                    if flow != FlowControl::Continue {
                        return flow;
                    }
                }
            }
            ForVariant::Recursive { root_path } => {
                return self.execute_for_recursive(for_stmt, root_path.as_ref(), ctx, io);
            }
            ForVariant::NumericSequence => {
                return self.execute_for_numeric(for_stmt, ctx, io);
            }
            ForVariant::ParsedLines(opts) => {
                return self.execute_for_f(for_stmt, opts, ctx, io);
            }
        }
        FlowControl::Continue
    }

    /// Executes `FOR /R [root]` directory-tree traversal.
    ///
    /// # Arguments
    /// * `for_stmt` - [`ForStatement`] AST node.
    /// * `root_path` - Optional root directory token.
    /// * `ctx` - Active [`ExecutionContext`].
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// Resulting [`FlowControl`].
    fn execute_for_recursive(
        &mut self,
        for_stmt: &ForStatement,
        root_path: Option<&crate::parser::ast::SpannedWord>,
        ctx: ExecutionContext,
        io: &mut dyn CmdIo,
    ) -> FlowControl {
        let base_dir = match root_path {
            Some(rp) => {
                let exp = self.expand_word_phase3_and_4(rp.unquoted(), rp.span);
                self.proc_env.vfs.resolve_path(&exp)
            }
            None => self.proc_env.vfs.resolve_path("."),
        };
        let dirs = self.collect_recursive_dirs(&base_dir);
        for dir in dirs {
            for pat_word in &for_stmt.in_set {
                let pat = self.expand_word_phase3_and_4(pat_word.unquoted(), pat_word.span);
                if pat == "." {
                    let dot_val = format!("{}{BS_STR}.", dir.to_windows_string());
                    let flow =
                        self.run_for_iteration(for_stmt.variable, dot_val, &for_stmt.body, ctx, io);
                    if flow != FlowControl::Continue {
                        return flow;
                    }
                } else if crate::vfs::glob::contains_wildcards(&pat) {
                    let entries = self
                        .proc_env
                        .vfs
                        .read_dir(&dir.to_windows_string())
                        .unwrap_or_default();
                    for entry in entries {
                        if !entry.attributes.is_directory()
                            && matches_win32_glob(
                                &pat,
                                &entry.name,
                                Some(&entry.short_name),
                                CaseSensitivity::Insensitive,
                            )
                        {
                            let val = entry.full_path.to_windows_string();
                            let flow = self.run_for_iteration(
                                for_stmt.variable,
                                val,
                                &for_stmt.body,
                                ctx,
                                io,
                            );
                            if flow != FlowControl::Continue {
                                return flow;
                            }
                        }
                    }
                } else {
                    let full = dir.join_component(&pat).to_windows_string();
                    let flow =
                        self.run_for_iteration(for_stmt.variable, full, &for_stmt.body, ctx, io);
                    if flow != FlowControl::Continue {
                        return flow;
                    }
                }
            }
        }
        FlowControl::Continue
    }

    /// Executes `FOR /L %I IN (start, step, end)` with authentic `step == 0` semantics
    /// (`cur <= end` when `step >= 0`, `cur >= end` when `step < 0`) gated by [`super::ExecutionLimits::max_loop_iterations`].
    ///
    /// # Arguments
    /// * `for_stmt` - [`ForStatement`] AST node.
    /// * `ctx` - Active [`ExecutionContext`].
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// Resulting [`FlowControl`].
    fn execute_for_numeric(
        &mut self,
        for_stmt: &ForStatement,
        ctx: ExecutionContext,
        io: &mut dyn CmdIo,
    ) -> FlowControl {
        let mut expanded_tokens = Vec::new();
        for word in &for_stmt.in_set {
            let expanded = self.expand_word_phase3_and_4(&word.text, word.span);
            for sub in expanded.split([' ', TAB_CHAR, ',', ';', '=']) {
                let clean = crate::parser::modifiers::strip_surrounding_quotes(sub);
                if !clean.is_empty() {
                    expanded_tokens.push(clean.to_owned());
                }
            }
        }
        let (start, step, end) = ForStatement::parse_numeric_bounds(&expanded_tokens);
        let mut cur = start;
        let mut iterations: usize = 0;

        loop {
            if (step >= 0 && cur > end) || (step < 0 && cur < end) {
                break;
            }
            if let Some(limit) = self.config.limits.max_loop_iterations
                && iterations >= limit
            {
                return FlowControl::Abort(CmdError::from(ExecutionLimitFailure {
                    kind: LimitKind::MaxLoopIterations,
                    limit,
                    span: for_stmt.span,
                }));
            }
            iterations = iterations.saturating_add(1);

            let flow =
                self.run_for_iteration(for_stmt.variable, cur.to_string(), &for_stmt.body, ctx, io);
            if flow != FlowControl::Continue {
                return flow;
            }
            let Some(next_cur) = cur.checked_add(step) else {
                break;
            };
            cur = next_cur;
        }
        FlowControl::Continue
    }

    /// Executes a `FOR /F` loop over literal strings, command outputs (zero-clone VFS sharing), or files.
    ///
    /// # Arguments
    /// * `for_stmt` - [`ForStatement`] AST node.
    /// * `opts` - Parsed [`ForFOptions`].
    /// * `ctx` - Active [`ExecutionContext`].
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// Resulting [`FlowControl`].
    fn execute_for_f(
        &mut self,
        for_stmt: &ForStatement,
        opts: &ForFOptions,
        ctx: ExecutionContext,
        io: &mut dyn CmdIo,
    ) -> FlowControl {
        let expanded_set =
            self.expand_word_phase3_and_4(&for_stmt.in_set_raw, for_stmt.in_set_span);
        let raw_set = expanded_set.trim().to_owned();

        let literal_quote = if opts.use_backq {
            SINGLE_QUOTE_CHAR
        } else {
            '"'
        };
        let command_quote = if opts.use_backq {
            '`'
        } else {
            SINGLE_QUOTE_CHAR
        };

        let lines_to_parse: Vec<String> = if let Some(inner) = raw_set
            .strip_prefix(literal_quote)
            .and_then(|s| s.strip_suffix(literal_quote))
        {
            vec![inner.to_owned()]
        } else if let Some(cmd_str) = raw_set
            .strip_prefix(command_quote)
            .and_then(|s| s.strip_suffix(command_quote))
        {
            let saved_cwds = snapshot_vfs_cwds(self.proc_env.vfs.as_ref());
            let mut sub = self.fork_subshell_taking_vfs();
            let mut sub_io = BufferedIoStreams::new();
            let res = sub.execute_interactive_line_checked(cmd_str, &mut sub_io);
            self.proc_env.vfs =
                core::mem::replace(&mut sub.proc_env.vfs, Box::new(InMemoryVfs::new()));
            restore_vfs_cwds(self.proc_env.vfs.as_mut(), &saved_cwds);
            if let Err(err) = res {
                return FlowControl::Abort(err);
            }
            sub_io
                .stdout
                .lines()
                .map(|l| l.trim_end_matches(CR_CHAR).to_owned())
                .collect()
        } else {
            let mut file_lines = Vec::new();
            let set_buf = LogicalLineBuffer::from_str_at(
                for_stmt.in_set_span.source_id,
                for_stmt.in_set_span.start,
                &raw_set,
            );
            for item in tokenize_command_arguments(&set_buf.chars) {
                let path_str = item.unquoted();
                let Ok(bytes) = self.proc_env.vfs.read_bytes(path_str) else {
                    let err = CmdError::FileNotFound {
                        path: path_str.to_owned(),
                    };
                    self.emit_cmd_error(&err, io);
                    continue;
                };
                match decode_script_bytes(&bytes, self.console.codepage) {
                    Ok(text) => {
                        for l in text.lines() {
                            file_lines.push(l.trim_end_matches(CR_CHAR).to_owned());
                        }
                    }
                    Err(err) => {
                        self.emit_cmd_error(&err, io);
                    }
                }
            }
            file_lines
        };

        for (line_idx, line) in lines_to_parse.iter().enumerate() {
            if line_idx < opts.skip {
                continue;
            }
            let Some(bindings) = tokenize_for_f_line(line, for_stmt.variable, opts) else {
                continue;
            };
            let prev_len = self.exec.for_vars.len();
            self.exec.for_vars.extend(bindings);
            let flow = self.execute_command_expr(&for_stmt.body, ctx, io);
            self.exec.for_vars.truncate(prev_len);
            if flow != FlowControl::Continue {
                return flow;
            }
        }

        FlowControl::Continue
    }

    /// Runs a single iteration of a `FOR` loop with `var` bound to `val`.
    ///
    /// # Arguments
    /// * `var` - Loop [`ForVarName`].
    /// * `val` - Bound iteration value.
    /// * `body` - Loop body [`CommandExpr`].
    /// * `ctx` - Active [`ExecutionContext`].
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// Resulting [`FlowControl`].
    fn run_for_iteration(
        &mut self,
        var: ForVarName,
        val: String,
        body: &CommandExpr,
        ctx: ExecutionContext,
        io: &mut dyn CmdIo,
    ) -> FlowControl {
        self.exec.for_vars.push((var, val));
        let flow = self.execute_command_expr(body, ctx, io);
        self.exec.for_vars.pop();
        flow
    }

    /// Expands items in a standard `FOR` or `FOR /D` set (performing Win32 globbing on wildcards).
    ///
    /// # Arguments
    /// * `in_set` - Raw set tokens.
    /// * `scope` - [`CompletionScope`] (`DirectoriesOnly` for `FOR /D`, `FilesAndDirectories` for file `FOR`).
    ///
    /// # Returns
    /// Expanded item strings.
    fn expand_for_file_set(
        &mut self,
        in_set: &[crate::parser::ast::SpannedWord],
        scope: CompletionScope,
    ) -> Vec<String> {
        let directories_only = scope == CompletionScope::DirectoriesOnly;
        let mut results = Vec::new();
        for item in in_set {
            let expanded = self.expand_word_phase3_and_4(item.unquoted(), item.span);
            if crate::vfs::glob::contains_wildcards(&expanded) {
                let prefix = wildcard_directory_prefix(&expanded);
                let resolved = self.proc_env.vfs.resolve_path(&expanded);
                let parent = resolved.parent();
                let leaf_pat = resolved.file_name().unwrap_or("*");
                for entry in self
                    .proc_env
                    .vfs
                    .read_dir(&parent.to_windows_string())
                    .unwrap_or_default()
                {
                    if entry.attributes.is_directory() == directories_only
                        && matches_win32_glob(
                            leaf_pat,
                            &entry.name,
                            Some(&entry.short_name),
                            CaseSensitivity::Insensitive,
                        )
                    {
                        results.push(format!("{prefix}{}", entry.name));
                    }
                }
            } else {
                results.push(expanded);
            }
        }
        results
    }

    /// Recursively collects all directories starting at `root` for `FOR /R`.
    ///
    /// # Arguments
    /// * `root` - Root [`WindowsPath`] directory.
    ///
    /// # Returns
    /// Ordered list of visited directory paths.
    fn collect_recursive_dirs(&self, root: &WindowsPath) -> Vec<WindowsPath> {
        let mut dirs = vec![root.clone()];
        for entry in self
            .proc_env
            .vfs
            .read_dir(&root.to_windows_string())
            .unwrap_or_default()
        {
            if entry.attributes.is_directory() {
                dirs.extend(self.collect_recursive_dirs(&entry.full_path));
            }
        }
        dirs
    }

    /// Expands a text fragment in `PipeSubshell` (`/S /D /c` Phase 1) followed by Phase 3 and Phase 4.
    ///
    /// # Arguments
    /// * `text` - Raw command fragment.
    /// * `span` - Source [`Span`].
    /// * `ctx` - Active [`ExecutionContext`].
    ///
    /// # Returns
    /// Expanded string.
    fn expand_for_simple_command(
        &mut self,
        text: &str,
        span: Span,
        ctx: ExecutionContext,
    ) -> String {
        if ctx == ExecutionContext::PipeSubshell && text.contains('%') {
            let raw_buf = LogicalLineBuffer::from_str_at(span.source_id, span.start, text);
            let cwd = self.current_cwd_string();
            let exit_code = self.exec.last_exit_code();
            let env_ref = &self.proc_env.env;
            let vfs_ref = self.proc_env.vfs.as_ref();
            let p1_ctx = Phase1Context {
                exec_context: ExecutionContext::PipeSubshell,
                arg0: "cmd",
                positional_args: &[],
                all_args_raw: "",
                vfs: vfs_ref,
                env_lookup: |k| env_ref.get_with_dynamics(k, &cwd, exit_code),
            };
            let after_p1 = expand_phase1(&raw_buf, &p1_ctx)
                .unwrap_or(raw_buf)
                .to_plain_string();
            return self.expand_word_phase3_and_4(&after_p1, span);
        }
        self.expand_word_phase3_and_4(text, span)
    }

    /// Executes a [`SimpleCommand`], running Phase 3 (`FOR` vars) and Phase 4 (`!VAR!`)
    /// expansion (plus child `/S /D /c` Phase 1 when in `PipeSubshell`), streaming unredirected
    /// handles directly to `io` via [`RedirectedIo`], and enforcing [`super::ExecutionLimits::max_steps`].
    ///
    /// # Arguments
    /// * `simple` - [`SimpleCommand`] AST node.
    /// * `ctx` - Active [`ExecutionContext`].
    /// * `io` - Parent [`CmdIo`] stream.
    ///
    /// # Returns
    /// Resulting [`FlowControl`].
    fn execute_simple_command(
        &mut self,
        simple: &SimpleCommand,
        ctx: ExecutionContext,
        io: &mut dyn CmdIo,
    ) -> FlowControl {
        if let Err(err) = self
            .exec
            .consume_step_budget(self.config.limits, simple.span)
        {
            return FlowControl::Abort(err);
        }

        let prog_expanded =
            self.expand_for_simple_command(&simple.program.text, simple.program.span, ctx);
        let raw_tail_expanded =
            self.expand_for_simple_command(&simple.raw_tail, simple.raw_tail_span, ctx);

        let arg_buf = LogicalLineBuffer::from_str_at(
            simple.raw_tail_span.source_id,
            simple.raw_tail_span.start,
            &raw_tail_expanded,
        );
        let expanded_args = tokenize_command_arguments(&arg_buf.chars);

        if self.console.echo_state == EchoState::On
            && simple.echo_suppression == EchoSuppression::NotSuppressed
            && ctx == ExecutionContext::BatchFile
        {
            let prompt = self.format_prompt();
            let echoed = if raw_tail_expanded.is_empty() {
                format!("{prompt}{prog_expanded}{CRLF}")
            } else {
                let delim = simple.echo_delimiter.unwrap_or(' ');
                format!("{prompt}{prog_expanded}{delim}{raw_tail_expanded}{CRLF}")
            };
            io.write_stdout_str(&echoed).unwrap_or(());
        }

        let new_inputs = match self.prepare_input_redirections(&simple.redirections) {
            Ok(inp) => inp,
            Err(err) => {
                self.emit_cmd_error(&err, io);
                return FlowControl::Continue;
            }
        };
        let sinks = match self.prepare_output_redirections(&simple.redirections) {
            Ok(s) => s,
            Err(err) => {
                self.emit_cmd_error(&err, io);
                return FlowControl::Continue;
            }
        };

        let saved_inputs = new_inputs
            .as_ref()
            .map(|m| core::mem::replace(&mut self.exec.active_input_handles, m.clone()));
        let saved_sinks = sinks
            .as_ref()
            .map(|s| core::mem::replace(&mut self.exec.active_output_sinks, s.clone()));

        let stdin_override = new_inputs.and_then(|mut m| m.remove(&0).flatten());
        let needs_capture = sinks.as_ref().is_some_and(|s| {
            s.get(&1) != Some(&FdSink::ConsoleStdout) || s.get(&2) != Some(&FdSink::ConsoleStderr)
        });
        let mut redir_io = RedirectedIo::new(
            io,
            stdin_override,
            if needs_capture {
                OutputCaptureMode::BufferedForSinks
            } else {
                OutputCaptureMode::PassThrough
            },
        );
        let invocation = BuiltinInvocation {
            program: &prog_expanded,
            echo_delimiter: simple.echo_delimiter,
            args: &expanded_args,
            raw_tail: &raw_tail_expanded,
            raw_tail_start: simple.raw_tail_span.start,
            cmd_span: simple.span,
            exec_ctx: ctx,
        };
        let flow = match dispatch_builtin(self, &invocation, &mut redir_io) {
            Ok(f) => f,
            Err(err @ CmdError::ExecutionLimitExceeded(_)) => FlowControl::Abort(err),
            Err(err) => {
                let msg = format!("{}{CRLF}", err.cmd_exe_message());
                redir_io.write_stderr_str(&msg).unwrap_or(());
                self.record_failure(err.exit_code());
                FlowControl::Continue
            }
        };

        if let Some(prev_in) = saved_inputs {
            self.exec.active_input_handles = prev_in;
        }
        if let Some(prev_out) = saved_sinks {
            self.exec.active_output_sinks = prev_out;
        }

        let chunks = core::mem::take(&mut redir_io.output_chunks);
        if let Some(active_sinks) = sinks
            && !chunks.is_empty()
            && let Err(err) = self.flush_output_sinks(&active_sinks, &chunks, io)
        {
            self.emit_cmd_error(&err, io);
        }
        flow
    }

    /// Applies Phase 3 (`FOR` variable) and Phase 4 (`!VAR!` delayed expansion) to a raw text fragment.
    ///
    /// # Arguments
    /// * `text` - Raw word or tail string.
    /// * `span` - Source [`Span`] for diagnostics.
    ///
    /// # Returns
    /// Expanded plain string.
    pub fn expand_word_phase3_and_4(&mut self, text: &str, span: Span) -> String {
        let buf = LogicalLineBuffer::from_str_at(span.source_id, span.start, text);
        let cwd = self.current_cwd_string();
        let exit_code = self.exec.last_exit_code();
        let env_ref = &self.proc_env.env;
        let vfs_ref = self.proc_env.vfs.as_ref();
        let p3 = expand_phase3(&buf, &self.exec.for_vars, vfs_ref, |k| {
            env_ref.get_with_dynamics(k, &cwd, exit_code)
        })
        .unwrap_or(buf);
        let p4 = expand_phase4(&p3, self.proc_env.env.delayed_expansion, |k| {
            env_ref.get_with_dynamics(k, &cwd, exit_code)
        });
        p4.to_plain_string()
    }

    /// Resolves `< file` and `n<&m` input redirections, inheriting outer handles `0..=9` from
    /// `self.exec.active_input_handles`!
    ///
    /// # Arguments
    /// * `redirections` - Slice of AST [`Redirection`]s.
    ///
    /// # Returns
    /// `Ok(Some(handle_map))` when input redirections exist, or `Ok(None)` when unredirected.
    ///
    /// # Errors
    /// Returns [`CmdError::RedirectionFailed`] or [`CmdError::EncodingFailure`] if reading or decoding any input redirection file fails.
    fn prepare_input_redirections(
        &mut self,
        redirections: &[Redirection],
    ) -> Result<Option<BTreeMap<u8, Option<String>>>, CmdError> {
        let has_input_redir = redirections.iter().any(|r| {
            matches!(
                r.kind,
                RedirectionKind::ReadFromFile(_) | RedirectionKind::DuplicateInput(_)
            )
        });
        if !has_input_redir {
            return Ok(None);
        }

        let mut fd_inputs: BTreeMap<u8, Option<String>> = self.exec.active_input_handles.clone();

        for redir in redirections {
            let slot = redir.source_handle.index();
            match &redir.kind {
                RedirectionKind::ReadFromFile(target) => {
                    let path = self.expand_word_phase3_and_4(target.unquoted(), target.span);
                    if path.eq_ignore_ascii_case("CON") {
                        fd_inputs.insert(slot, None);
                    } else {
                        let bytes = self.proc_env.vfs.read_bytes(&path).map_err(|err| {
                            CmdError::RedirectionFailed {
                                span: redir.span,
                                fd: redir.source_handle,
                                target: path.clone(),
                                reason: err.cmd_exe_message(),
                            }
                        })?;
                        let decoded = decode_script_bytes(&bytes, self.console.codepage)?;
                        fd_inputs.insert(slot, Some(decoded));
                    }
                }
                RedirectionKind::DuplicateInput(target_fd) => {
                    let dup_entry = fd_inputs
                        .get(&target_fd.index())
                        .cloned()
                        .unwrap_or_else(|| Some(String::new()));
                    fd_inputs.insert(slot, dup_entry);
                }
                RedirectionKind::WriteTruncate(_)
                | RedirectionKind::WriteAppend(_)
                | RedirectionKind::DuplicateOutput(_) => {}
            }
        }
        Ok(Some(fd_inputs))
    }

    /// Opens/truncates `> file`, `>> file`, and `n>&m` output redirections in left-to-right order
    /// BEFORE running the command/block body, inheriting outer handles `0..=9` from
    /// `self.exec.active_output_sinks`!
    ///
    /// # Arguments
    /// * `redirections` - Slice of AST [`Redirection`]s.
    ///
    /// # Returns
    /// `Ok(None)` when no output redirections exist, or `Ok(Some(sink_map))` when active.
    ///
    /// # Errors
    /// Returns [`CmdError::RedirectionFailed`] if creating or truncating a redirected file fails.
    fn prepare_output_redirections(
        &mut self,
        redirections: &[Redirection],
    ) -> Result<Option<BTreeMap<u8, FdSink>>, CmdError> {
        let has_output_redir = redirections.iter().any(|r| {
            matches!(
                r.kind,
                RedirectionKind::WriteTruncate(_)
                    | RedirectionKind::WriteAppend(_)
                    | RedirectionKind::DuplicateOutput(_)
            )
        });
        if !has_output_redir {
            return Ok(None);
        }

        let mut sinks: BTreeMap<u8, FdSink> = self.exec.active_output_sinks.clone();

        for redir in redirections {
            let slot = redir.source_handle.index();
            match &redir.kind {
                RedirectionKind::WriteTruncate(target) => {
                    let path = self.expand_word_phase3_and_4(target.unquoted(), target.span);
                    if path.eq_ignore_ascii_case("CON") {
                        sinks.insert(slot, FdSink::ConsoleStdout);
                    } else {
                        self.proc_env.vfs.write_bytes(&path, &[]).map_err(|err| {
                            CmdError::RedirectionFailed {
                                span: redir.span,
                                fd: redir.source_handle,
                                target: path.clone(),
                                reason: err.cmd_exe_message(),
                            }
                        })?;
                        sinks.insert(
                            slot,
                            FdSink::File {
                                path,
                                span: redir.span,
                                fd: redir.source_handle,
                            },
                        );
                    }
                }
                RedirectionKind::WriteAppend(target) => {
                    let path = self.expand_word_phase3_and_4(target.unquoted(), target.span);
                    if path.eq_ignore_ascii_case("CON") {
                        sinks.insert(slot, FdSink::ConsoleStdout);
                    } else {
                        self.proc_env.vfs.append_bytes(&path, &[]).map_err(|err| {
                            CmdError::RedirectionFailed {
                                span: redir.span,
                                fd: redir.source_handle,
                                target: path.clone(),
                                reason: err.cmd_exe_message(),
                            }
                        })?;
                        sinks.insert(
                            slot,
                            FdSink::File {
                                path,
                                span: redir.span,
                                fd: redir.source_handle,
                            },
                        );
                    }
                }
                RedirectionKind::DuplicateOutput(target_fd) => {
                    let cloned_sink = sinks
                        .get(&target_fd.index())
                        .cloned()
                        .unwrap_or(FdSink::Discard);
                    sinks.insert(slot, cloned_sink);
                }
                RedirectionKind::ReadFromFile(_) | RedirectionKind::DuplicateInput(_) => {}
            }
        }
        Ok(Some(sinks))
    }

    /// Flushes chronologically ordered [`CapturedOutputChunk`]s into their configured [`FdSink`]
    /// targets, preserving interleaved `stdout`/`stderr` order (`2>&1`, `1>&2`) and raw binary bytes!
    ///
    /// # Arguments
    /// * `sinks` - Resolved handle-to-[`FdSink`] table.
    /// * `chunks` - Chronologically ordered [`CapturedOutputChunk`] events.
    /// * `parent_io` - Parent [`CmdIo`] stream for console sinks.
    ///
    /// # Returns
    /// `Ok(())` when all redirected files and console streams succeed.
    ///
    /// # Errors
    /// Returns [`CmdError::RedirectionFailed`] or [`CmdError::IoFailure`] if writing to a redirected file or parent stream fails.
    fn flush_output_sinks(
        &mut self,
        sinks: &BTreeMap<u8, FdSink>,
        chunks: &[CapturedOutputChunk],
        parent_io: &mut dyn CmdIo,
    ) -> Result<(), CmdError> {
        for chunk in chunks {
            let stream = match chunk {
                CapturedOutputChunk::Text { stream, .. }
                | CapturedOutputChunk::RawBytes { stream, .. } => *stream,
            };
            let fd_idx = match stream {
                OutputStreamId::Stdout => 1u8,
                OutputStreamId::Stderr => 2u8,
            };
            let sink = sinks.get(&fd_idx).cloned().unwrap_or(FdSink::Discard);
            match (sink, chunk) {
                (FdSink::Discard, _) => {}
                (FdSink::ConsoleStdout, CapturedOutputChunk::Text { text, .. }) => {
                    parent_io.write_stdout_str(text)?;
                }
                (FdSink::ConsoleStdout, CapturedOutputChunk::RawBytes { bytes, .. }) => {
                    parent_io.write_stdout_bytes(bytes)?;
                }
                (FdSink::ConsoleStderr, CapturedOutputChunk::Text { text, .. }) => {
                    parent_io.write_stderr_str(text)?;
                }
                (FdSink::ConsoleStderr, CapturedOutputChunk::RawBytes { bytes, .. }) => {
                    parent_io.write_stderr_str(&String::from_utf8_lossy(bytes))?;
                }
                (FdSink::File { path, span, fd }, CapturedOutputChunk::Text { text, .. }) => {
                    let encoded = encode_output_bytes_with_codepage(
                        text,
                        self.config.unicode_output_mode,
                        self.console.codepage,
                    );
                    self.proc_env
                        .vfs
                        .append_bytes(&path, &encoded)
                        .map_err(|err| CmdError::RedirectionFailed {
                            span,
                            fd,
                            target: path,
                            reason: err.cmd_exe_message(),
                        })?;
                }
                (FdSink::File { path, span, fd }, CapturedOutputChunk::RawBytes { bytes, .. }) => {
                    self.proc_env
                        .vfs
                        .append_bytes(&path, bytes)
                        .map_err(|err| CmdError::RedirectionFailed {
                            span,
                            fd,
                            target: path,
                            reason: err.cmd_exe_message(),
                        })?;
                }
            }
        }
        Ok(())
    }
}

/// Tokenizes a single line for `FOR /F` according to [`ForFOptions`] (`eol`, `delims`, `tokens`).
///
/// # Arguments
/// * `line` - Input line (without CR/LF).
/// * `base_var` - Base [`ForVarName`] (`%%I`).
/// * `opts` - Parsed [`ForFOptions`].
///
/// # Returns
/// `Some(Vec<(ForVarName, String)>)` if the line is non-empty and does not start with `eol`, else `None`.
fn tokenize_for_f_line(
    line: &str,
    base_var: ForVarName,
    opts: &ForFOptions,
) -> Option<Vec<(ForVarName, String)>> {
    let trimmed = if opts.delims.is_empty() {
        line
    } else {
        line.trim_start_matches(|c| opts.delims.contains(&c))
    };
    if trimmed.is_empty() || opts.eol.is_some_and(|eol_ch| trimmed.starts_with(eol_ch)) {
        return None;
    }

    let mut token_spans: Vec<(usize, usize)> = Vec::new();
    if opts.delims.is_empty() {
        token_spans.push((0, trimmed.len()));
    } else {
        let mut in_tok = false;
        let mut tok_start = 0usize;
        for (idx, ch) in trimmed.char_indices() {
            if opts.delims.contains(&ch) && in_tok {
                token_spans.push((tok_start, idx));
                in_tok = false;
            } else if !opts.delims.contains(&ch) && !in_tok {
                tok_start = idx;
                in_tok = true;
            }
        }
        if in_tok {
            token_spans.push((tok_start, trimmed.len()));
        }
    }

    let mut bindings = Vec::new();
    let mut var_offset: u8 = 0;
    let mut highest_selected_1based: usize = 0;

    for sel in &opts.tokens {
        match *sel {
            TokenSelector::Single(n) => {
                highest_selected_1based = highest_selected_1based.max(n);
                let val = token_spans
                    .get(n.saturating_sub(1))
                    .and_then(|&(s, e)| trimmed.get(s..e))
                    .unwrap_or("")
                    .to_owned();
                let v = base_var.offset_by(var_offset).unwrap_or(base_var);
                bindings.push((v, val));
                var_offset = var_offset.saturating_add(1);
            }
            TokenSelector::Range(start, end) => {
                highest_selected_1based = highest_selected_1based.max(end);
                for n in start..=end {
                    let val = token_spans
                        .get(n.saturating_sub(1))
                        .and_then(|&(s, e)| trimmed.get(s..e))
                        .unwrap_or("")
                        .to_owned();
                    let v = base_var.offset_by(var_offset).unwrap_or(base_var);
                    bindings.push((v, val));
                    var_offset = var_offset.saturating_add(1);
                }
            }
            TokenSelector::RemainderStar => {
                let rem_val = if highest_selected_1based == 0 {
                    trimmed.to_owned()
                } else if let Some(&(_, last_end)) =
                    token_spans.get(highest_selected_1based.saturating_sub(1))
                {
                    let after = trimmed.get(last_end..).unwrap_or("");
                    after
                        .trim_start_matches(|c| opts.delims.contains(&c))
                        .to_owned()
                } else {
                    String::new()
                };
                let v = base_var.offset_by(var_offset).unwrap_or(base_var);
                bindings.push((v, rem_val));
                var_offset = var_offset.saturating_add(1);
            }
        }
    }

    Some(bindings)
}
