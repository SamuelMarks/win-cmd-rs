//! Stateful `Interpreter` session struct, safety limits, console history, `AutoRun`, and tab completion.

use std::collections::{BTreeMap, VecDeque};

use crate::error::{CmdError, ExecutionLimitFailure, LimitKind};
use crate::reader::stream::BatchFrameReader;
use crate::span::{ByteOffset, SourceId, SourceMap, Span};
use crate::types::{
    AutoRunMode, BS_CHAR, CRLF, CmdLocaleConfig, CodePage, CompletionScope, ConsoleColor,
    DelayedExpansionMode, DoskeyEditMode, DriveLetter, ESC_CHAR, EchoState, ExitCode,
    ExtensionsMode, FileCompletionMode, ForVarName, HostBindingMode, InterruptState, LabelName,
    OutputUnicodeMode, PipeExecutionMode, ProcessPriority, StartEnvMode, StartWindowMode, TAB_CHAR,
    VerifyCopyMode, WaitMode,
};
use crate::vfs::path::WindowsPath;
use crate::vfs::{HostOsVfs, InMemoryVfs, VirtualFileSystem};

use super::env::EnvironmentStack;
use super::io::{CmdIo, HostProcessSpawner, ProcessSpawner, consume_buffered_line};
use super::registry::RegistryStore;
use super::{VfsCwdSnapshot, restore_vfs_cwds};

/// Number of reusable [`SourceId`] slots in the ephemeral interactive ring buffer.
pub(super) const EPHEMERAL_RING_CAPACITY: usize = 8;

/// Entry on the `PUSHD` / `POPD` directory stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushdEntry {
    /// Saved working directory to restore on `POPD`.
    pub saved_path: WindowsPath,
    /// Optional temporary drive letter allocated for a UNC path (`//server/share`) to unmount on `POPD`.
    pub temp_unc_drive: Option<DriveLetter>,
}

/// Control flow signal returned after executing a statement or command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowControl {
    /// Continue normal sequential execution.
    Continue,
    /// Jump to `target` (or `:EOF`) in the current batch script frame (`GOTO`).
    Goto {
        /// Target label name.
        target: LabelName,
        /// Span of the `GOTO` statement.
        span: Span,
    },
    /// Transfer the current batch frame to `script_path` at byte `0` without pushing a `CALL`
    /// frame (authentic non-`CALL` `.bat` chaining, unwinding active `&`, `IF`, and `FOR` scopes).
    TransferBatchFrame {
        /// Resolved VFS path of the target batch script.
        script_path: String,
        /// Raw `arg0` invocation string (`%0`).
        arg0: String,
        /// Positional arguments (`%1`..`%N`).
        positional_args: Vec<String>,
        /// Raw post-command tail (`%*`).
        all_args_raw: String,
    },
    /// Exit the current batch script or `:subroutine` frame (`EXIT /B [code]`).
    ExitBatchFrame(ExitCode),
    /// Terminate the entire `cmd.exe` interpreter session (`EXIT [code]`).
    ExitShell(ExitCode),
    /// Abort execution immediately due to an unrecoverable [`CmdError`] (such as [`CmdError::ExecutionLimitExceeded`]).
    Abort(CmdError),
}

/// Active batch script or `:subroutine` invocation frame on the call stack.
#[derive(Debug, Clone)]
pub struct BatchCallFrame {
    /// Virtual path of the batch script on VFS.
    pub script_path: String,
    /// Value of `%0` (e.g., `"script.bat"` or `":my_sub"`).
    pub arg0: String,
    /// Positional parameters `%1`..`%9`+ (shifted via `SHIFT`).
    pub positional_args: Vec<String>,
    /// Raw argument tail `%*` (not mutated by `SHIFT` in `cmd.exe`).
    pub all_args_raw: String,
    /// Byte-offset stream reader for this frame.
    pub reader: BatchFrameReader,
    /// `SETLOCAL` stack depth when this frame started (for automatic implicit `ENDLOCAL` on return).
    pub base_setlocal_depth: usize,
}

/// Configurable execution safety budgets preventing runaway `GOTO` loops, `FOR /L (1,0,5)`,
/// and unbounded `CALL` recursion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionLimits {
    /// Maximum statements executed before failing with [`LimitKind::MaxSteps`] (`None` = unlimited).
    pub max_steps: Option<usize>,
    /// Maximum nested batch/`CALL` stack depth before failing with [`LimitKind::MaxCallDepth`] (`None` = unlimited).
    pub max_call_depth: Option<usize>,
    /// Maximum iterations in a single `FOR /L` loop before failing with [`LimitKind::MaxLoopIterations`] (`None` = unlimited).
    pub max_loop_iterations: Option<usize>,
}

impl Default for ExecutionLimits {
    /// Returns generous hermetic/sandbox safety budgets (`100_000` steps, `256` call depth, `100_000` loop iterations).
    ///
    /// # Returns
    /// Default sandboxed [`ExecutionLimits`].
    fn default() -> Self {
        Self::sandboxed()
    }
}

impl ExecutionLimits {
    /// Returns generous safety budgets suitable for embedded/sandboxed interpreter execution.
    ///
    /// # Returns
    /// Sandboxed [`ExecutionLimits`].
    #[must_use]
    pub const fn sandboxed() -> Self {
        Self {
            max_steps: Some(100_000),
            max_call_depth: Some(256),
            max_loop_iterations: Some(100_000),
        }
    }

    /// Returns CLI-appropriate limits (`None` step/loop cap, `1_024` call-stack recursion cap).
    ///
    /// # Returns
    /// CLI [`ExecutionLimits`].
    #[must_use]
    pub const fn cli_default() -> Self {
        Self {
            max_steps: None,
            max_call_depth: Some(1_024),
            max_loop_iterations: None,
        }
    }

    /// Returns completely unbounded [`ExecutionLimits`].
    ///
    /// # Returns
    /// Unlimited [`ExecutionLimits`].
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_steps: None,
            max_call_depth: None,
            max_loop_iterations: None,
        }
    }
}

/// Process environment, filesystem, external spawner, unified Registry, and `PUSHD` stack.
#[derive(Debug)]
pub struct ProcessEnvironment {
    /// Environment variable table and `SETLOCAL` stack.
    pub env: EnvironmentStack,
    /// Snapshot of the initial startup environment (used by `START /I`).
    pub startup_env: EnvironmentStack,
    /// Virtual file system backing all drives and files.
    pub vfs: Box<dyn VirtualFileSystem>,
    /// External process spawner (`HostProcessSpawner` or `MockProcessSpawner`).
    pub spawner: Box<dyn ProcessSpawner>,
    /// Unified Registry store (`HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`) backing `Command Processor`, `ASSOC`, `FTYPE`, and `REG`.
    pub registry_store: RegistryStore,
    /// Stack of directories (and optional temporary UNC drives) pushed by `PUSHD`.
    pub pushd_stack: Vec<PushdEntry>,
}

/// Session-wide execution policies, locale formatting, output encoding, and safety limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// Host working directory synchronization mode (`Isolated` vs `Synchronized`).
    pub host_binding_mode: HostBindingMode,
    /// Configurable locale formatting rules for `DATE`, `TIME`, and `DIR`.
    pub locale: CmdLocaleConfig,
    /// Current disk write verification mode (`VERIFY ON` / `VERIFY OFF`).
    pub verify_state: VerifyCopyMode,
    /// Redirected file and pipe output encoding mode (`/A` vs `/U`).
    pub unicode_output_mode: OutputUnicodeMode,
    /// Pipeline execution mode (`InMemoryBuffered` vs `OsStreamingPipe`).
    pub pipe_execution_mode: PipeExecutionMode,
    /// Active process wait mode inherited by child launches (`Wait` vs `Detached`).
    pub start_wait_mode: WaitMode,
    /// Active window creation mode inherited by `START` launches.
    pub start_window_mode: StartWindowMode,
    /// Active environment inheritance mode inherited by `START` launches.
    pub start_env_mode: StartEnvMode,
    /// Active scheduling priority class inherited by `START` launches.
    pub start_priority: ProcessPriority,
    /// Interactive file/directory tab completion mode (`/F:ON` vs `/F:OFF`).
    pub file_completion: FileCompletionMode,
    /// Windows version string displayed by `VER`.
    pub version_banner: String,
    /// Configurable execution safety budgets (`max_steps`, `max_call_depth`, `max_loop_iterations`).
    pub limits: ExecutionLimits,
}

impl Default for SessionConfig {
    /// Creates the default hermetic [`SessionConfig`].
    ///
    /// # Returns
    /// Initialized [`SessionConfig`].
    fn default() -> Self {
        Self {
            host_binding_mode: HostBindingMode::Isolated,
            locale: CmdLocaleConfig::default(),
            verify_state: VerifyCopyMode::Unverified,
            unicode_output_mode: OutputUnicodeMode::Ansi,
            pipe_execution_mode: PipeExecutionMode::InMemoryBuffered,
            start_wait_mode: WaitMode::Wait,
            start_window_mode: StartWindowMode::Normal,
            start_env_mode: StartEnvMode::CurrentEnv,
            start_priority: ProcessPriority::Normal,
            file_completion: FileCompletionMode::Enabled,
            version_banner: "Microsoft Windows [Version 10.0.19045.5011]".to_owned(),
            limits: ExecutionLimits::sandboxed(),
        }
    }
}

/// Console display properties, active codepage, `ECHO` mode, `DOSKEY` macros, and `VecDeque` history.
#[derive(Debug, Clone)]
pub struct ConsoleState {
    /// Current command echo state (`ECHO ON` / `ECHO OFF`).
    pub echo_state: EchoState,
    /// Active character encoding codepage (`CHCP`).
    pub codepage: CodePage,
    /// Tracked console screen width in columns (`MODE CON COLS=c`).
    pub console_cols: u16,
    /// Tracked console screen height in lines (`MODE CON LINES=n`).
    pub console_lines: u16,
    /// Current terminal window title (`TITLE`).
    pub console_title: String,
    /// Current console color pair (`COLOR`).
    pub console_color: Option<ConsoleColor>,
    /// Line editing cursor mode (`DOSKEY /INSERT` vs `/OVERSTRIKE`).
    pub doskey_edit_mode: DoskeyEditMode,
    /// Defined `DOSKEY` macros (`name -> definition`).
    pub doskey_macros: BTreeMap<String, String>,
    /// Bounded `O(1)` ring-queue interactive command history (`DOSKEY /HISTORY`).
    command_history: VecDeque<String>,
    /// Maximum number of history entries retained (`DOSKEY /LISTSIZE=size`).
    history_list_size: usize,
}

impl Default for ConsoleState {
    /// Creates the default 80x25 UTF-8 [`ConsoleState`] with a 50-entry `VecDeque` history buffer.
    ///
    /// # Returns
    /// Initialized [`ConsoleState`].
    fn default() -> Self {
        Self {
            echo_state: EchoState::On,
            codepage: CodePage::Utf8,
            console_cols: 80,
            console_lines: 25,
            console_title: "Command Prompt".to_owned(),
            console_color: None,
            doskey_edit_mode: DoskeyEditMode::Insert,
            doskey_macros: BTreeMap::new(),
            command_history: VecDeque::new(),
            history_list_size: 50,
        }
    }
}

impl ConsoleState {
    /// Appends a non-empty command line to the `O(1)` `VecDeque` history buffer, evicting oldest entries.
    ///
    /// # Arguments
    /// * `trimmed_line` - Trimmed interactive command string.
    pub fn record_history(&mut self, trimmed_line: &str) {
        if !trimmed_line.is_empty() && self.history_list_size > 0 {
            while self.command_history.len() >= self.history_list_size {
                self.command_history.pop_front();
            }
            self.command_history.push_back(trimmed_line.to_owned());
        }
    }

    /// Clears all recorded interactive history entries (`DOSKEY /REINSTALL`).
    pub fn clear_history(&mut self) {
        self.command_history.clear();
    }

    /// Returns an immutable reference to the `VecDeque` command history.
    ///
    /// # Returns
    /// Reference to the command history queue.
    #[must_use]
    pub const fn history(&self) -> &VecDeque<String> {
        &self.command_history
    }

    /// Returns the configured maximum history buffer capacity.
    ///
    /// # Returns
    /// Maximum history list size.
    #[must_use]
    pub const fn history_list_size(&self) -> usize {
        self.history_list_size
    }

    /// Sets the maximum history buffer capacity (`DOSKEY /LISTSIZE=n`), trimming excess oldest items.
    ///
    /// # Arguments
    /// * `new_size` - Desired maximum number of history lines.
    pub fn set_history_list_size(&mut self, new_size: usize) {
        self.history_list_size = new_size;
        while self.command_history.len() > self.history_list_size {
            self.command_history.pop_front();
        }
    }
}

/// Destination sink for an output file descriptor (`0..=9`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum FdSink {
    /// Route to parent `stdout` (`handle 1`).
    ConsoleStdout,
    /// Route to parent `stderr` (`handle 2`).
    ConsoleStderr,
    /// Discard output written to an unbound handle (`1>&4`).
    Discard,
    /// Append encoded or raw bytes to a VFS file path.
    File {
        /// Destination Windows path.
        path: String,
        /// Source [`Span`] of the redirection operator.
        span: Span,
        /// Redirected [`crate::types::FileDescriptor`].
        fd: crate::types::FileDescriptor,
    },
}

/// Encapsulated control-flow state, call stack, `FOR` variable stack, exit status, and bounded [`SourceMap`].
#[derive(Debug)]
pub struct ExecutionState {
    /// Source map registering loaded scripts and bounded ephemeral interactive buffers.
    pub source_map: SourceMap,
    /// Ring buffer of reusable [`SourceId`] slots for interactive/ephemeral command lines.
    ephemeral_ring: [Option<SourceId>; EPHEMERAL_RING_CAPACITY],
    /// Next slot index in `ephemeral_ring`.
    ephemeral_cursor: usize,
    /// Reusable [`SourceId`] slots keyed by uppercase batch script path when inactive.
    batch_source_slots: BTreeMap<String, SourceId>,
    /// Call stack of active batch scripts and `:subroutine` frames.
    call_stack: Vec<BatchCallFrame>,
    /// Stack of active `FOR` loop variable bindings (`(ForVarName, value)`).
    pub(super) for_vars: Vec<(ForVarName, String)>,
    /// Active inherited output redirection handle table (`0..=9`) across nested compound blocks.
    pub(super) active_output_sinks: BTreeMap<u8, FdSink>,
    /// Active inherited input redirection handle table (`0..=9`) across nested compound blocks.
    pub(super) active_input_handles: BTreeMap<u8, Option<String>>,
    /// Current `ERRORLEVEL` exit code.
    pub(super) last_exit_code: ExitCode,
    /// Whether the most recently executed command succeeded (drives `&&` and `||`).
    pub(super) last_cmd_succeeded: bool,
    /// Terminal shell exit code set by `EXIT` (without `/B`).
    exited: Option<ExitCode>,
    /// Pending `Ctrl+C` (`SIGINT`) interrupt flag.
    pub(super) interrupt_state: InterruptState,
    /// Total statements executed in the current top-level invocation (checked against [`ExecutionLimits::max_steps`]).
    steps_executed: usize,
}

impl Default for ExecutionState {
    /// Creates an idle [`ExecutionState`] with `ERRORLEVEL = 0` and default console handles `0..=2`.
    ///
    /// # Returns
    /// Initialized [`ExecutionState`].
    fn default() -> Self {
        let mut active_output_sinks = BTreeMap::new();
        active_output_sinks.insert(1, FdSink::ConsoleStdout);
        active_output_sinks.insert(2, FdSink::ConsoleStderr);
        let mut active_input_handles = BTreeMap::new();
        active_input_handles.insert(0, None);
        Self {
            source_map: SourceMap::new(),
            ephemeral_ring: [None; EPHEMERAL_RING_CAPACITY],
            ephemeral_cursor: 0,
            batch_source_slots: BTreeMap::new(),
            call_stack: Vec::new(),
            for_vars: Vec::new(),
            active_output_sinks,
            active_input_handles,
            last_exit_code: ExitCode::SUCCESS,
            last_cmd_succeeded: true,
            exited: None,
            interrupt_state: InterruptState::Clear,
            steps_executed: 0,
        }
    }
}

impl ExecutionState {
    /// Returns the current `ERRORLEVEL` [`ExitCode`].
    ///
    /// # Returns
    /// Current [`ExitCode`].
    #[must_use]
    pub const fn last_exit_code(&self) -> ExitCode {
        self.last_exit_code
    }

    /// Returns whether the last executed command succeeded (`&&` / `||` predicate).
    ///
    /// # Returns
    /// `true` if the previous command succeeded.
    #[must_use]
    pub const fn last_cmd_succeeded(&self) -> bool {
        self.last_cmd_succeeded
    }

    /// Records a command completion with `code`, setting `last_cmd_succeeded = code.is_success()`.
    ///
    /// # Arguments
    /// * `code` - Resulting [`ExitCode`].
    pub const fn record_exit_code(&mut self, code: ExitCode) {
        self.last_exit_code = code;
        self.last_cmd_succeeded = code.is_success();
    }

    /// Records `ExitCode::SUCCESS` and `last_cmd_succeeded = true`.
    pub const fn record_success(&mut self) {
        self.last_exit_code = ExitCode::SUCCESS;
        self.last_cmd_succeeded = true;
    }

    /// Records a failed command with `code` and `last_cmd_succeeded = false`.
    ///
    /// # Arguments
    /// * `code` - Non-zero failure [`ExitCode`].
    pub const fn record_failure(&mut self, code: ExitCode) {
        self.last_exit_code = code;
        self.last_cmd_succeeded = false;
    }

    /// Marks the command as succeeded (`&&` runs) while preserving the prior `ERRORLEVEL`
    /// (authentic `cmd.exe` behavior for `ECHO`, `REM`, `TITLE`, `CLS`, `PAUSE`).
    pub const fn mark_cmd_succeeded_preserving_exit_code(&mut self) {
        self.last_cmd_succeeded = true;
    }

    /// Returns `Some(ExitCode)` if the session has been terminated via `EXIT`.
    ///
    /// # Returns
    /// Optional terminal [`ExitCode`].
    #[must_use]
    pub const fn exited(&self) -> Option<ExitCode> {
        self.exited
    }

    /// Clears any terminal `exited` status (used when re-entering REPL or subshells).
    pub const fn clear_exited(&mut self) {
        self.exited = None;
    }

    /// Marks the entire interpreter session as terminated with `code`.
    ///
    /// # Arguments
    /// * `code` - Terminal [`ExitCode`].
    pub const fn terminate_shell(&mut self, code: ExitCode) {
        self.last_exit_code = code;
        self.exited = Some(code);
    }

    /// Returns a slice of active [`BatchCallFrame`]s on the call stack.
    ///
    /// # Returns
    /// Active call stack slice.
    #[must_use]
    pub fn call_stack(&self) -> &[BatchCallFrame] {
        &self.call_stack
    }

    /// Returns a mutable reference to the top [`BatchCallFrame`] if a batch script is active.
    ///
    /// # Returns
    /// Optional mutable top [`BatchCallFrame`].
    pub fn top_call_frame_mut(&mut self) -> Option<&mut BatchCallFrame> {
        self.call_stack.last_mut()
    }

    /// Pushes a new [`BatchCallFrame`] after verifying `limits.max_call_depth`.
    ///
    /// # Arguments
    /// * `frame` - [`BatchCallFrame`] to push.
    /// * `limits` - Active [`ExecutionLimits`].
    /// * `span` - Call-site [`Span`] reported on overflow.
    ///
    /// # Returns
    /// `Ok(())` when within `limits.max_call_depth`.
    ///
    /// # Errors
    /// Returns [`CmdError::ExecutionLimitExceeded`] with [`LimitKind::MaxCallDepth`] if depth is exceeded.
    pub fn push_call_frame(
        &mut self,
        frame: BatchCallFrame,
        limits: ExecutionLimits,
        span: Span,
    ) -> Result<(), CmdError> {
        if let Some(limit) = limits.max_call_depth
            && self.call_stack.len() >= limit
        {
            return Err(CmdError::from(ExecutionLimitFailure {
                kind: LimitKind::MaxCallDepth,
                limit,
                span,
            }));
        }
        self.call_stack.push(frame);
        Ok(())
    }

    /// Pops and returns the top [`BatchCallFrame`].
    ///
    /// # Returns
    /// Popped [`BatchCallFrame`], if any.
    pub fn pop_call_frame(&mut self) -> Option<BatchCallFrame> {
        self.call_stack.pop()
    }

    /// Clears the entire batch call stack (used on `Ctrl+C` termination).
    pub fn clear_call_stack(&mut self) {
        self.call_stack.clear();
    }

    /// Returns active `FOR` loop variable bindings.
    ///
    /// # Returns
    /// Slice of `(ForVarName, String)` pairs.
    #[must_use]
    pub fn for_vars(&self) -> &[(ForVarName, String)] {
        &self.for_vars
    }

    /// Updates the [`BatchFrameReader`] of the active top [`BatchCallFrame`].
    ///
    /// # Arguments
    /// * `reader` - Updated [`BatchFrameReader`] cursor state.
    pub fn sync_top_frame_reader(&mut self, reader: &BatchFrameReader) {
        self.call_stack
            .iter_mut()
            .rev()
            .take(1)
            .for_each(|top| top.reader = reader.clone());
    }

    /// Seeks the active top [`BatchCallFrame`]'s reader to `offset`.
    ///
    /// # Arguments
    /// * `offset` - Target physical [`ByteOffset`].
    pub fn seek_top_frame(&mut self, offset: ByteOffset) {
        self.call_stack
            .iter_mut()
            .rev()
            .take(1)
            .for_each(|top| top.reader.seek(offset));
    }

    /// Replaces the active top [`BatchCallFrame`] target script and arguments in place at byte `0`.
    ///
    /// # Arguments
    /// * `script_path` - Resolved VFS path of the target batch script.
    /// * `source_id` - Registered [`SourceId`] for the target script.
    /// * `arg0` - Invocation string (`%0`).
    /// * `positional_args` - Positional arguments (`%1`..`%N`).
    /// * `all_args_raw` - Raw post-command tail (`%*`).
    pub fn transfer_top_frame(
        &mut self,
        script_path: &str,
        source_id: SourceId,
        arg0: &str,
        positional_args: &[String],
        all_args_raw: &str,
    ) {
        self.call_stack.iter_mut().rev().take(1).for_each(|top| {
            script_path.clone_into(&mut top.script_path);
            arg0.clone_into(&mut top.arg0);
            positional_args.clone_into(&mut top.positional_args);
            all_args_raw.clone_into(&mut top.all_args_raw);
            top.reader = BatchFrameReader::new(source_id);
        });
    }

    /// Allocates or reuses a bounded ring-buffer [`SourceId`] slot in `self.source_map` for
    /// interactive REPL, `CALL`, and `FOR /F` command strings so memory stays `O(1)`.
    ///
    /// # Arguments
    /// * `name` - Buffer label (`"<interactive>"`).
    /// * `text` - Decoded command text.
    ///
    /// # Returns
    /// Reusable [`SourceId`] containing `text`.
    pub fn allocate_ephemeral_source(&mut self, name: &str, text: &str) -> SourceId {
        let slot_idx = self.ephemeral_cursor % EPHEMERAL_RING_CAPACITY;
        self.ephemeral_cursor = self.ephemeral_cursor.wrapping_add(1);
        let raw_bytes = text.as_bytes().to_vec();
        let owned_text = text.to_owned();
        if let Some(existing_id) = self.ephemeral_ring.get(slot_idx).copied().flatten() {
            self.source_map
                .replace_file(existing_id, name.to_owned(), raw_bytes, owned_text);
            return existing_id;
        }
        let id = self
            .source_map
            .add_file(name.to_owned(), raw_bytes, owned_text);
        self.ephemeral_ring
            .iter_mut()
            .skip(slot_idx)
            .take(1)
            .for_each(|s| *s = Some(id));
        id
    }

    /// Allocates or reuses a [`SourceId`] for `script_path` when `script_path` is not currently active
    /// on `self.call_stack`, preventing unbounded `SourceMap` growth when calling batch files in loops.
    ///
    /// # Arguments
    /// * `script_path` - VFS path of the batch script.
    /// * `raw_bytes` - Raw undecoded script bytes.
    /// * `display_text` - Decoded UTF-8 preview text for diagnostic rendering.
    ///
    /// # Returns
    /// Allocated or reused [`SourceId`].
    pub fn allocate_batch_source(
        &mut self,
        script_path: &str,
        raw_bytes: Vec<u8>,
        display_text: String,
    ) -> SourceId {
        let key = script_path.to_ascii_uppercase();
        let active_on_stack = self
            .call_stack
            .iter()
            .any(|f| f.script_path.eq_ignore_ascii_case(script_path));
        if !active_on_stack && let Some(&existing_id) = self.batch_source_slots.get(&key) {
            self.source_map.replace_file(
                existing_id,
                script_path.to_owned(),
                raw_bytes,
                display_text,
            );
            return existing_id;
        }
        let id = self
            .source_map
            .add_file(script_path.to_owned(), raw_bytes, display_text);
        self.batch_source_slots.insert(key, id);
        id
    }

    /// Increments the executed statement counter and validates against `limits.max_steps`.
    ///
    /// # Arguments
    /// * `limits` - Active [`ExecutionLimits`].
    /// * `span` - Statement [`Span`] reported on budget exhaustion.
    ///
    /// # Returns
    /// `Ok(())` when within `limits.max_steps`.
    ///
    /// # Errors
    /// Returns [`CmdError::ExecutionLimitExceeded`] with [`LimitKind::MaxSteps`] if exceeded.
    pub fn consume_step_budget(
        &mut self,
        limits: ExecutionLimits,
        span: Span,
    ) -> Result<(), CmdError> {
        self.steps_executed = self.steps_executed.saturating_add(1);
        if let Some(limit) = limits.max_steps
            && self.steps_executed > limit
        {
            return Err(CmdError::from(ExecutionLimitFailure {
                kind: LimitKind::MaxSteps,
                limit,
                span,
            }));
        }
        Ok(())
    }

    /// Resets the statement step counter before starting a new top-level interactive command.
    pub const fn reset_step_counter(&mut self) {
        self.steps_executed = 0;
    }
}

/// Complete stateful `cmd.exe` interpreter session composed of four cohesive sub-components.
#[derive(Debug)]
pub struct Interpreter {
    /// Process environment variables, VFS, external spawner, Registry store, and `PUSHD` stack.
    pub proc_env: ProcessEnvironment,
    /// Session policies, locale, unicode output mode, completion mode, banner, and safety limits.
    pub config: SessionConfig,
    /// Console display properties, echo state, codepage, `DOSKEY` macros, and `VecDeque` history.
    pub console: ConsoleState,
    /// Encapsulated control-flow state, call stack, `FOR` variables, exit status, and `SourceMap`.
    pub exec: ExecutionState,
}

impl Default for Interpreter {
    /// Creates a hermetic [`Interpreter`] backed by [`InMemoryVfs`].
    ///
    /// # Returns
    /// Default [`Interpreter`].
    fn default() -> Self {
        Self::new()
    }
}

impl Interpreter {
    /// Constructs a new hermetic [`Interpreter`] backed by [`InMemoryVfs`].
    ///
    /// # Returns
    /// Ready-to-run [`Interpreter`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_vfs(Box::new(InMemoryVfs::new()))
    }

    /// Constructs a new [`Interpreter`] backed by [`HostOsVfs::from_host_env()`] and
    /// populated with the current OS process environment (`std::env::vars()`).
    ///
    /// # Returns
    /// Host-native [`Interpreter`].
    #[must_use]
    pub fn new_host_native() -> Self {
        let mut interp = Self::with_vfs(Box::new(HostOsVfs::from_host_env()));
        interp.proc_env.env = EnvironmentStack::from_host_iter(std::env::vars());
        interp.proc_env.startup_env = interp.proc_env.env.clone();
        interp.config.limits = ExecutionLimits::cli_default();
        interp
    }

    /// Constructs a new [`Interpreter`] with a custom [`VirtualFileSystem`].
    ///
    /// # Arguments
    /// * `vfs` - Boxed [`VirtualFileSystem`] implementation.
    ///
    /// # Returns
    /// Initialized [`Interpreter`].
    #[must_use]
    pub fn with_vfs(vfs: Box<dyn VirtualFileSystem>) -> Self {
        let env = EnvironmentStack::new();
        let startup_env = env.clone();
        Self {
            proc_env: ProcessEnvironment {
                env,
                startup_env,
                vfs,
                spawner: Box::new(HostProcessSpawner),
                registry_store: RegistryStore::new(),
                pushd_stack: Vec::new(),
            },
            config: SessionConfig::default(),
            console: ConsoleState::default(),
            exec: ExecutionState::default(),
        }
    }

    /// Returns the current `ERRORLEVEL` [`ExitCode`].
    ///
    /// # Returns
    /// Current [`ExitCode`].
    #[must_use]
    pub const fn last_exit_code(&self) -> ExitCode {
        self.exec.last_exit_code()
    }

    /// Returns whether the most recent command succeeded (`&&` / `||` condition).
    ///
    /// # Returns
    /// `true` if the previous command succeeded.
    #[must_use]
    pub const fn last_cmd_succeeded(&self) -> bool {
        self.exec.last_cmd_succeeded()
    }

    /// Records `ExitCode::SUCCESS` and `last_cmd_succeeded = true`.
    pub const fn record_success(&mut self) {
        self.exec.record_success();
    }

    /// Records a failed command `code` and `last_cmd_succeeded = false`.
    ///
    /// # Arguments
    /// * `code` - Failure [`ExitCode`].
    pub const fn record_failure(&mut self, code: ExitCode) {
        self.exec.record_failure(code);
    }

    /// Records `code` and sets `last_cmd_succeeded = code.is_success()`.
    ///
    /// # Arguments
    /// * `code` - Resulting [`ExitCode`].
    pub const fn record_exit_code(&mut self, code: ExitCode) {
        self.exec.record_exit_code(code);
    }

    /// Marks the command as succeeded (`&&` runs) without modifying `last_exit_code`.
    pub const fn mark_cmd_succeeded(&mut self) {
        self.exec.mark_cmd_succeeded_preserving_exit_code();
    }

    /// Synchronizes `EnableExtensions`, `DelayedExpansion`, and `DefaultColor` directly from
    /// `self.proc_env.registry_store` (`HKLM` and `HKCU` `Software/Microsoft/Command Processor`).
    pub fn sync_processor_settings_from_registry(&mut self) {
        self.proc_env.env.extensions = self
            .proc_env
            .registry_store
            .command_processor_extensions()
            .unwrap_or(ExtensionsMode::Enabled);
        self.proc_env.env.delayed_expansion = self
            .proc_env
            .registry_store
            .command_processor_delayed_expansion()
            .unwrap_or(DelayedExpansionMode::Disabled);
        if self.console.console_color.is_none() {
            self.console.console_color = self
                .proc_env
                .registry_store
                .command_processor_default_color();
        }
    }

    /// Flags a pending `Ctrl+C` (`SIGINT`) interrupt to be processed at the next statement boundary.
    pub const fn trigger_ctrl_c(&mut self) {
        self.exec.interrupt_state = InterruptState::Pending;
    }

    /// Constructs a child subshell (`CMD`, `START`, `FOR /F`, or pipe) by temporarily moving
    /// `self.proc_env.vfs` into the child in `O(1)` time without cloning any VFS files or inodes.
    ///
    /// # Returns
    /// Child [`Interpreter`] owning the live VFS.
    pub(crate) fn fork_subshell_taking_vfs(&mut self) -> Self {
        let vfs = std::mem::replace(&mut self.proc_env.vfs, Box::new(InMemoryVfs::new()));
        let mut exec = ExecutionState::default();
        exec.source_map = self.exec.source_map.clone();
        exec.for_vars.clone_from(&self.exec.for_vars);
        exec.last_exit_code = self.exec.last_exit_code;
        exec.last_cmd_succeeded = self.exec.last_cmd_succeeded;
        exec.interrupt_state = self.exec.interrupt_state;

        let mut console = self.console.clone();
        console.echo_state = EchoState::Off;
        console.clear_history();

        Self {
            proc_env: ProcessEnvironment {
                env: self.proc_env.env.clone(),
                startup_env: self.proc_env.startup_env.clone(),
                vfs,
                spawner: self.proc_env.spawner.clone_box(),
                registry_store: self.proc_env.registry_store.clone(),
                pushd_stack: Vec::new(),
            },
            config: self.config.clone(),
            console,
            exec,
        }
    }

    /// Reclaims the live [`VirtualFileSystem`] from a finished child subshell and restores
    /// the parent session's active drive and per-drive working directories.
    ///
    /// # Arguments
    /// * `sub` - Completed child [`Interpreter`] owning the live VFS.
    /// * `saved_cwds` - Parent [`VfsCwdSnapshot`] captured prior to forking.
    pub(crate) fn reclaim_subshell_vfs(&mut self, sub: Self, saved_cwds: &VfsCwdSnapshot) {
        self.proc_env.vfs = sub.proc_env.vfs;
        restore_vfs_cwds(self.proc_env.vfs.as_mut(), saved_cwds);
    }

    /// Executes configured Registry `AutoRun` commands (`HKLM` then `HKCU`) from
    /// `self.proc_env.registry_store` unless `autorun_mode` is [`AutoRunMode::Skip`] (`/D`).
    ///
    /// # Arguments
    /// * `autorun_mode` - [`AutoRunMode`] policy.
    /// * `io` - Mutable [`CmdIo`] stream.
    pub fn run_autorun_if_enabled(&mut self, autorun_mode: AutoRunMode, io: &mut dyn CmdIo) {
        self.exec.clear_exited();
        if self.console.console_color.is_none() {
            self.console.console_color = self
                .proc_env
                .registry_store
                .command_processor_default_color();
        }
        if autorun_mode == AutoRunMode::Skip {
            return;
        }
        let (hklm_opt, hkcu_opt) = self.proc_env.registry_store.command_processor_autorun();
        if let Some(hklm_cmd) = hklm_opt {
            let _hklm_code = self.execute_interactive_line(&hklm_cmd, io);
        }
        if let Some(hkcu_cmd) = hkcu_opt.filter(|_| self.exec.exited().is_none()) {
            let _hkcu_code = self.execute_interactive_line(&hkcu_cmd, io);
        }
    }

    /// Completes the file or directory token at the end of `line` using `/F:ON` semantics.
    ///
    /// # Arguments
    /// * `line` - Current interactive input line.
    /// * `scope` - [`CompletionScope`] (`FilesAndDirectories` vs `DirectoriesOnly`).
    /// * `cycle_index` - 0-based index when cycling through multiple matches on repeated Tab presses.
    ///
    /// # Returns
    /// Completed command line string (or `line` unchanged if `/F:OFF` or no matches exist).
    #[must_use]
    pub fn complete_line_at_cursor(
        &self,
        line: &str,
        scope: CompletionScope,
        cycle_index: usize,
    ) -> String {
        if self.config.file_completion == FileCompletionMode::Disabled {
            return line.to_owned();
        }

        let trimmed_end = line.trim_end_matches([' ', TAB_CHAR]);
        let split_pos = trimmed_end
            .rfind([' ', TAB_CHAR])
            .map_or(0, |idx| idx.saturating_add(1));
        let prefix_cmd = trimmed_end.get(..split_pos).unwrap_or("");
        let raw_token = trimmed_end.get(split_pos..).unwrap_or("");
        let clean_token = raw_token.trim_matches('"');

        let (dir_prefix_display, search_dir, file_prefix) = clean_token
            .rfind([BS_CHAR, '/'])
            .map_or(("", ".", clean_token), |sep_idx| {
                let d_disp = clean_token.get(..=sep_idx).unwrap_or("");
                let f_pref = clean_token.get(sep_idx.saturating_add(1)..).unwrap_or("");
                (d_disp, d_disp, f_pref)
            });

        let Ok(entries) = self.proc_env.vfs.read_dir(search_dir) else {
            return line.to_owned();
        };

        let upper_pref = file_prefix.to_ascii_uppercase();
        let matches: Vec<&str> = entries
            .iter()
            .filter(|e| {
                let scope_ok = match scope {
                    CompletionScope::FilesAndDirectories => true,
                    CompletionScope::DirectoriesOnly => e.attributes.is_directory(),
                };
                scope_ok && e.name.to_ascii_uppercase().starts_with(&upper_pref)
            })
            .map(|e| e.name.as_str())
            .collect();

        let Some(&chosen) = cycle_index
            .checked_rem(matches.len())
            .and_then(|idx| matches.get(idx))
        else {
            return line.to_owned();
        };

        let full_candidate = format!("{dir_prefix_display}{chosen}");
        let formatted = if full_candidate.contains(' ') {
            format!(r#""{full_candidate}""#)
        } else {
            full_candidate
        };
        format!("{prefix_cmd}{formatted}")
    }

    /// Handles a `Ctrl+C` (`SIGINT`) interrupt during batch or interactive execution.
    ///
    /// # Arguments
    /// * `io` - Mutable [`CmdIo`] stream.
    ///
    /// # Returns
    /// [`FlowControl::ExitShell`] if terminated (`Y`), or [`FlowControl::Continue`] if resumed (`N`).
    pub fn handle_ctrl_c_interrupt(&mut self, io: &mut dyn CmdIo) -> FlowControl {
        self.exec.interrupt_state = InterruptState::Clear;
        if self.exec.call_stack().is_empty() {
            self.record_failure(ExitCode::CTRL_C);
            return FlowControl::Continue;
        }

        io.write_stdout_str("Terminate batch job (Y/N)? ")
            .unwrap_or(());
        let answer_line = io.read_stdin_line().ok().flatten().unwrap_or_default();
        let ans = answer_line.trim().chars().next().unwrap_or('Y');
        if ans.eq_ignore_ascii_case(&'N') {
            FlowControl::Continue
        } else {
            self.exec.clear_call_stack();
            self.unwind_setlocal_to(0);
            self.record_failure(ExitCode::CTRL_C);
            self.exec.terminate_shell(ExitCode::CTRL_C);
            FlowControl::ExitShell(ExitCode::CTRL_C)
        }
    }

    /// Consumes and returns a single line from a mutable `stdin` buffer string.
    ///
    /// # Arguments
    /// * `stdin_buf` - Mutable `stdin` string.
    ///
    /// # Returns
    /// The consumed line (trimmed of trailing CR/LF), or empty string if `stdin_buf` was empty.
    pub fn consume_stdin_line(stdin_buf: &mut String) -> String {
        consume_buffered_line(stdin_buf)
    }

    /// Returns the formatted current working directory string (`C:/path`) of the active drive.
    ///
    /// # Returns
    /// Current working directory string.
    #[must_use]
    pub fn current_cwd_string(&self) -> String {
        let drive = self.proc_env.vfs.current_drive();
        let fallback = WindowsPath::root(drive);
        self.proc_env
            .vfs
            .drive_cwd(drive)
            .unwrap_or(fallback)
            .to_windows_string()
    }

    /// Looks up an environment or dynamic variable in the current interpreter context.
    ///
    /// # Arguments
    /// * `name` - Variable name to resolve.
    ///
    /// # Returns
    /// `Some(String)` if defined, else `None`.
    #[must_use]
    pub fn lookup_var(&self, name: &str) -> Option<String> {
        let cwd = self.current_cwd_string();
        self.proc_env
            .env
            .get_with_dynamics(name, &cwd, self.exec.last_exit_code())
    }

    /// Formats the interactive prompt string according to `%PROMPT%` (`$P$G` -> `C:/>`).
    ///
    /// # Returns
    /// Rendered prompt string.
    #[must_use]
    pub fn format_prompt(&self) -> String {
        let raw_prompt = self.lookup_var("PROMPT").unwrap_or_default();
        let mut out = String::with_capacity(raw_prompt.len().saturating_add(16));
        let mut chars = raw_prompt.chars();

        while let Some(ch) = chars.next() {
            if ch != '$' {
                out.push(ch);
                continue;
            }
            let Some(code) = chars.next() else {
                out.push('$');
                break;
            };
            match code.to_ascii_uppercase() {
                'A' => out.push('&'),
                'B' => out.push('|'),
                'C' => out.push('('),
                'D' => out.push_str(&self.proc_env.env.virtual_date),
                'E' => out.push(ESC_CHAR),
                'F' => out.push(')'),
                'G' => out.push('>'),
                'H' => {
                    out.pop();
                }
                'L' => out.push('<'),
                'N' => out.push(self.proc_env.vfs.current_drive().as_char()),
                'P' => out.push_str(&self.current_cwd_string()),
                'Q' => out.push('='),
                'S' => out.push(' '),
                'T' => out.push_str(&self.proc_env.env.virtual_time),
                'V' => out.push_str(&self.config.version_banner),
                '_' => out.push_str(CRLF),
                '$' => out.push('$'),
                '+' => {
                    for _ in 0..self.proc_env.pushd_stack.len() {
                        out.push('+');
                    }
                }
                'M' => {}
                other => {
                    out.push('$');
                    out.push(other);
                }
            }
        }
        out
    }

    /// Synchronizes the host OS process working directory when `HostBindingMode::Synchronized` is active.
    pub fn sync_active_host_cwd(&self) {
        self.proc_env
            .vfs
            .sync_host_cwd(self.config.host_binding_mode)
            .unwrap_or(());
    }

    /// Writes `err.cmd_exe_message()` + `CRLF` to `io` stderr and updates failure exit state.
    ///
    /// # Arguments
    /// * `err` - [`CmdError`] to report.
    /// * `io` - Mutable [`CmdIo`] stream.
    pub fn emit_cmd_error(&mut self, err: &CmdError, io: &mut dyn CmdIo) {
        let msg = format!("{}{CRLF}", err.cmd_exe_message());
        io.write_stderr_str(&msg).unwrap_or(());
        self.record_failure(err.exit_code());
    }

    /// Unwinds any `SETLOCAL` frames pushed during a batch script or subroutine back to `target_depth`.
    ///
    /// # Arguments
    /// * `target_depth` - Target `SETLOCAL` nesting depth.
    pub fn unwind_setlocal_to(&mut self, target_depth: usize) {
        let count = self.proc_env.env.depth().saturating_sub(target_depth);
        let popped: Vec<_> = (0..count)
            .filter_map(|_| self.proc_env.env.pop_endlocal())
            .collect();
        for (saved_drive, saved_cwd) in popped {
            self.proc_env
                .vfs
                .set_current_drive(saved_drive)
                .unwrap_or(());
            self.proc_env.vfs.set_drive_cwd(&saved_cwd).unwrap_or(());
            self.sync_active_host_cwd();
        }
    }

    /// Expands `DOSKEY` macros at the start of an interactive command line.
    ///
    /// # Arguments
    /// * `line` - Raw interactive input line.
    ///
    /// # Returns
    /// Macro-expanded line (or `line` unchanged if no macro matched).
    pub(super) fn expand_doskey_line(&self, line: &str) -> String {
        let trimmed = line.trim_start();
        let first_end = trimmed.find([' ', TAB_CHAR]).unwrap_or(trimmed.len());
        let first_word = trimmed.get(..first_end).unwrap_or("");
        let tail = trimmed.get(first_end..).unwrap_or("").trim_start();

        let Some(macro_def) = self
            .console
            .doskey_macros
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(first_word))
            .map(|(_, v)| v)
        else {
            return line.to_owned();
        };

        let macro_args: Vec<&str> = tail.split_whitespace().collect();
        let mut out = String::with_capacity(macro_def.len());
        let mut chars = macro_def.chars();
        while let Some(ch) = chars.next() {
            if ch != '$' {
                out.push(ch);
                continue;
            }
            let Some(code) = chars.next() else {
                out.push('$');
                break;
            };
            match code {
                '1'..='9' => {
                    let idx = usize::from((code as u8).saturating_sub(b'1'));
                    if let Some(&arg) = macro_args.get(idx) {
                        out.push_str(arg);
                    }
                }
                '*' => out.push_str(tail),
                'T' | 't' => out.push_str(" & "),
                'G' | 'g' => out.push('>'),
                'L' | 'l' => out.push('<'),
                'B' | 'b' => out.push('|'),
                '$' => out.push('$'),
                other => {
                    out.push('$');
                    out.push(other);
                }
            }
        }
        out
    }
}
