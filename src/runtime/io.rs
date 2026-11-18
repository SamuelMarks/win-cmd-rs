//! Streaming and buffered standard I/O channels ([`CmdIo`]) and external process spawners.
//!
//! Provides:
//! - [`CmdIo`]: Unified trait for interactive/streaming and in-memory standard I/O.
//! - [`BufferedIoStreams`] ([`IoStreams`]): Hermetic in-memory `stdin`/`stdout`/`stderr` buffers.
//! - [`StdIoStreams`]: Live terminal/pipe streaming adapter flushing prompts before blocking reads.
//! - [`RedirectedIo`]: Per-command / per-block handle redirection overlay (`<`, `>`, `>>`, `n>&m`).
//! - [`ProcessSpawner`], [`HostProcessSpawner`], and [`MockProcessSpawner`]: Deadlock-free process execution.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
#[cfg(feature = "std")]
use alloc::string::ToString;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::ffi::OsString;
#[cfg(feature = "std")]
use std::io::{BufRead, Read, Write};
#[cfg(feature = "std")]
use std::process::{Command, Stdio};

use crate::error::CmdError;
use crate::reader::encoding::{
    decode_script_bytes, encode_codepage_bytes, encode_output_bytes_with_codepage,
};
#[cfg(feature = "std")]
use crate::types::IoErrorKind;
use crate::types::{
    CR_CHAR, CodePage, ExitCode, LF_CHAR, NativeBackingPath, OutputUnicodeMode, ProcessPriority,
    StartEnvMode, StartWindowMode, WaitMode,
};
use crate::vfs::path::WindowsPath;

/// Request parameters passed to [`ProcessSpawner::spawn_external`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSpawnRequest {
    /// Resolved executable VFS path.
    pub program_vfs_path: WindowsPath,
    /// Optional resolved native backing path (when running against [`crate::vfs::HostOsVfs`] or `DosFatVfs`).
    pub program_host_path: Option<NativeBackingPath>,
    /// Tokenized command-line arguments (unquoted).
    pub args: Vec<String>,
    /// Raw unexpanded/expanded command-line tail.
    pub raw_tail: String,
    /// Active working directory on the VFS.
    pub cwd_vfs: WindowsPath,
    /// Optional native working directory.
    pub cwd_host: Option<NativeBackingPath>,
    /// Visible environment variables (`(key, value)`).
    pub env_vars: Vec<(String, String)>,
    /// Standard input text piped to the process.
    pub stdin: String,
    /// Optional raw byte payload piped to standard input (used when `/U` or binary pipe output is active).
    pub stdin_bytes: Vec<u8>,
    /// Process wait mode (`Wait` for synchronous execution or `START /WAIT`, `Detached` for async `START`).
    pub wait_mode: WaitMode,
    /// Window creation style configured via `START` (`/B`, `/MIN`, `/MAX`, or `Normal`).
    pub window_mode: StartWindowMode,
    /// Environment inheritance policy (`CurrentEnv` vs `START /I` `InitialStartupEnv`).
    pub env_mode: StartEnvMode,
    /// Process scheduling priority class (`/LOW`, `/NORMAL`, `/HIGH`, `/REALTIME`, etc.).
    pub priority: ProcessPriority,
}

/// Output and exit status returned by [`ProcessSpawner::spawn_external`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSpawnResult {
    /// Process exit status (`ERRORLEVEL`).
    pub exit_code: ExitCode,
    /// Captured standard output text.
    pub stdout: String,
    /// Captured standard error text.
    pub stderr: String,
}

/// Trait abstracting external OS process creation (`CreateProcessW` / `std::process::Command` / DOS `INT 21h AH=4Bh`).
pub trait ProcessSpawner: core::fmt::Debug {
    /// Spawns an external executable and waits for completion.
    ///
    /// # Arguments
    /// * `req` - [`ExternalSpawnRequest`] describing the executable, arguments, environment, and stdin.
    ///
    /// # Returns
    /// `Ok(ExternalSpawnResult)` with exit code, stdout, and stderr.
    ///
    /// # Errors
    /// Returns [`CmdError::ChildProcessFailure`] or [`CmdError::AccessDenied`] if spawning or pipe I/O fails.
    fn spawn_external(
        &mut self,
        req: &ExternalSpawnRequest,
    ) -> Result<ExternalSpawnResult, CmdError>;

    /// Clones this spawner into a boxed trait object.
    ///
    /// # Returns
    /// Boxed clone of this [`ProcessSpawner`].
    fn clone_box(&self) -> Box<dyn ProcessSpawner>;
}

/// Maps an OS [`std::io::Error`] during child process execution into [`CmdError::ChildProcessFailure`].
///
/// # Arguments
/// * `program` - Display name or path of the external executable.
/// * `err` - Underlying OS [`std::io::Error`].
///
/// # Returns
/// Typed [`CmdError::ChildProcessFailure`] preserving [`IoErrorKind`].
#[cfg(feature = "std")]
#[must_use]
pub fn map_child_process_io_error(program: &str, err: &std::io::Error) -> CmdError {
    CmdError::ChildProcessFailure {
        program: program.to_owned(),
        kind: IoErrorKind::from(err.kind()),
        message: err.to_string(),
    }
}

/// Writes `payload` to a child `stdin` pipe, treating [`std::io::ErrorKind::BrokenPipe`] as graceful early EOF.
///
/// # Arguments
/// * `writer` - Destination [`Write`] sink (such as [`std::process::ChildStdin`]).
/// * `payload` - Raw bytes to write.
///
/// # Returns
/// `Ok(())` when all bytes are written or when the child closes its `stdin` pipe early.
///
/// # Errors
/// Returns [`std::io::Error`] for any non-`BrokenPipe` I/O failure.
#[cfg(feature = "std")]
pub fn write_child_stdin_bytes(
    writer: &mut dyn Write,
    payload: &[u8],
) -> Result<(), std::io::Error> {
    if payload.is_empty() {
        return Ok(());
    }
    match writer.write_all(payload) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(err),
    }
}

/// Real OS process spawner backed by [`std::process::Command`] with scoped-thread pipe pumping.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Default)]
pub struct HostProcessSpawner;

#[cfg(feature = "std")]
impl ProcessSpawner for HostProcessSpawner {
    /// Spawns a host executable using `OsStr` path semantics and pumps `stdin`, `stdout`, and
    /// `stderr` concurrently via [`std::thread::scope`] to eliminate >64 KiB OS pipe deadlocks.
    ///
    /// # Arguments
    /// * `req` - [`ExternalSpawnRequest`] describing the executable, arguments, environment, and stdin.
    ///
    /// # Returns
    /// `Ok(ExternalSpawnResult)` with exit status and decoded streams.
    ///
    /// # Errors
    /// Returns [`CmdError::ChildProcessFailure`] if process creation, non-`BrokenPipe` stdin writing,
    /// pipe reading, or waiting fails.
    fn spawn_external(
        &mut self,
        req: &ExternalSpawnRequest,
    ) -> Result<ExternalSpawnResult, CmdError> {
        let exe_os: OsString = req.program_host_path.as_ref().map_or_else(
            || OsString::from(req.program_vfs_path.to_windows_string()),
            |p| p.as_path().as_os_str().to_os_string(),
        );
        let exe_display = req.program_host_path.as_ref().map_or_else(
            || req.program_vfs_path.to_windows_string(),
            |p| p.as_str().to_owned(),
        );

        let mut cmd = Command::new(&exe_os);
        cmd.args(&req.args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(host_cwd) = req.cwd_host.as_ref().filter(|p| p.as_path().is_dir()) {
            cmd.current_dir(host_cwd.as_path());
        }
        for (k, v) in &req.env_vars {
            cmd.env(k, v);
        }

        let mut child = cmd
            .spawn()
            .map_err(|err| map_child_process_io_error(&exe_display, &err))?;

        let child_stdin = child.stdin.take();
        let child_stdout = child.stdout.take();
        let child_stderr = child.stderr.take();
        let stdin_payload: &[u8] = if req.stdin_bytes.is_empty() {
            req.stdin.as_bytes()
        } else {
            &req.stdin_bytes
        };

        let (stdin_res, stdout_res, stderr_res) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || -> Result<(), std::io::Error> {
                child_stdin.map_or(Ok(()), |mut sin| {
                    write_child_stdin_bytes(&mut sin, stdin_payload)
                })
            });
            let out_reader = scope.spawn(move || -> Result<Vec<u8>, std::io::Error> {
                child_stdout.map_or(Ok(Vec::new()), |mut sout| {
                    let mut buf = Vec::new();
                    sout.read_to_end(&mut buf)?;
                    Ok(buf)
                })
            });
            let err_reader = scope.spawn(move || -> Result<Vec<u8>, std::io::Error> {
                child_stderr.map_or(Ok(Vec::new()), |mut serr| {
                    let mut buf = Vec::new();
                    serr.read_to_end(&mut buf)?;
                    Ok(buf)
                })
            });
            (
                writer.join().unwrap_or(Ok(())),
                out_reader.join().unwrap_or(Ok(Vec::new())),
                err_reader.join().unwrap_or(Ok(Vec::new())),
            )
        });

        let wait_code_res = child.wait().map(|st| st.code());
        collect_spawn_outcome(
            &exe_display,
            wait_code_res,
            stdin_res,
            stdout_res,
            stderr_res,
        )
    }

    /// Clones this [`HostProcessSpawner`] into a boxed trait object.
    ///
    /// # Returns
    /// Boxed clone of [`HostProcessSpawner`].
    fn clone_box(&self) -> Box<dyn ProcessSpawner> {
        Box::new(self.clone())
    }
}

/// Converts raw child wait and pipe I/O results into an [`ExternalSpawnResult`].
///
/// # Arguments
/// * `exe_display` - Display path of the child executable.
/// * `wait_code_res` - Result of `child.wait().map(|st| st.code())`.
/// * `stdin_res` - Result of writing `stdin` bytes to the child.
/// * `stdout_res` - Result of reading `stdout` bytes from the child.
/// * `stderr_res` - Result of reading `stderr` bytes from the child.
///
/// # Returns
/// [`ExternalSpawnResult`] on success.
///
/// # Errors
/// Returns [`CmdError`] mapped via [`map_child_process_io_error`] if any child I/O operation failed.
#[cfg(feature = "std")]
fn collect_spawn_outcome(
    exe_display: &str,
    wait_code_res: Result<Option<i32>, std::io::Error>,
    stdin_res: Result<(), std::io::Error>,
    stdout_res: Result<Vec<u8>, std::io::Error>,
    stderr_res: Result<Vec<u8>, std::io::Error>,
) -> Result<ExternalSpawnResult, CmdError> {
    let code_opt = match wait_code_res {
        Ok(c) => c,
        Err(err) => return Err(map_child_process_io_error(exe_display, &err)),
    };
    if let Err(err) = stdin_res {
        return Err(map_child_process_io_error(exe_display, &err));
    }
    let stdout_bytes = match stdout_res {
        Ok(b) => b,
        Err(err) => return Err(map_child_process_io_error(exe_display, &err)),
    };
    let stderr_bytes = match stderr_res {
        Ok(b) => b,
        Err(err) => return Err(map_child_process_io_error(exe_display, &err)),
    };
    Ok(ExternalSpawnResult {
        exit_code: ExitCode::new(code_opt.unwrap_or(1)),
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
    })
}

/// Deterministic in-memory mock [`ProcessSpawner`] for hermetic unit testing.
#[derive(Debug, Clone, Default)]
pub struct MockProcessSpawner {
    /// Registered mock handlers keyed by uppercase filename (`"TOOL.EXE" -> (exit_code, stdout_tmpl, stderr_tmpl)`).
    pub handlers: BTreeMap<String, (ExitCode, String, String)>,
    /// Log of all [`ExternalSpawnRequest`]s received.
    pub recorded_requests: Vec<ExternalSpawnRequest>,
}

impl MockProcessSpawner {
    /// Creates an empty [`MockProcessSpawner`].
    ///
    /// # Returns
    /// A new [`MockProcessSpawner`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a deterministic mock response for an executable leaf name (e.g. `"git.exe"`).
    ///
    /// # Arguments
    /// * `exe_leaf` - Executable filename (matched case-insensitively).
    /// * `exit_code` - [`ExitCode`] to return.
    /// * `stdout` - Standard output template (`$ARGS` and `$STDIN` are expanded).
    /// * `stderr` - Standard error string to emit.
    pub fn register_binary(
        &mut self,
        exe_leaf: &str,
        exit_code: ExitCode,
        stdout: &str,
        stderr: &str,
    ) {
        self.handlers.insert(
            exe_leaf.to_ascii_uppercase(),
            (exit_code, stdout.to_owned(), stderr.to_owned()),
        );
    }
}

impl ProcessSpawner for MockProcessSpawner {
    /// Executes a deterministic mock response if `req.program_vfs_path` is registered.
    ///
    /// # Arguments
    /// * `req` - [`ExternalSpawnRequest`] to record and dispatch.
    ///
    /// # Returns
    /// `Ok(ExternalSpawnResult)` when registered.
    ///
    /// # Errors
    /// Returns [`CmdError::AccessDenied`] if no mock handler is registered for the executable leaf.
    fn spawn_external(
        &mut self,
        req: &ExternalSpawnRequest,
    ) -> Result<ExternalSpawnResult, CmdError> {
        self.recorded_requests.push(req.clone());
        let leaf = req
            .program_vfs_path
            .file_name()
            .unwrap_or("")
            .to_ascii_uppercase();
        if let Some((code, out, err)) = self.handlers.get(&leaf) {
            let stdout = out
                .replace("$ARGS", &req.args.join(" "))
                .replace("$STDIN", &req.stdin);
            Ok(ExternalSpawnResult {
                exit_code: *code,
                stdout,
                stderr: err.clone(),
            })
        } else {
            Err(CmdError::AccessDenied {
                path: req.program_vfs_path.to_windows_string(),
            })
        }
    }

    /// Clones this [`MockProcessSpawner`] into a boxed trait object.
    ///
    /// # Returns
    /// Boxed clone of [`MockProcessSpawner`].
    fn clone_box(&self) -> Box<dyn ProcessSpawner> {
        Box::new(self.clone())
    }
}

/// Consumes and returns a single line from a mutable `stdin` string buffer.
///
/// # Arguments
/// * `stdin_buf` - Mutable `stdin` string buffer.
///
/// # Returns
/// The consumed line (trimmed of trailing CR/LF), or an empty string if `stdin_buf` was empty.
pub fn consume_buffered_line(stdin_buf: &mut String) -> String {
    if let Some(nl_pos) = stdin_buf.find(LF_CHAR) {
        let line = stdin_buf
            .get(..nl_pos)
            .unwrap_or("")
            .trim_end_matches(CR_CHAR)
            .to_owned();
        let rest = stdin_buf
            .get(nl_pos.saturating_add(1)..)
            .unwrap_or("")
            .to_owned();
        *stdin_buf = rest;
        line
    } else {
        let line = stdin_buf.trim_end_matches(CR_CHAR).to_owned();
        stdin_buf.clear();
        line
    }
}

/// Trait abstracting streaming and buffered standard I/O channels (`stdin`, `stdout`, `stderr`).
pub trait CmdIo {
    /// Writes UTF-8 text to standard output (`handle 1`).
    ///
    /// # Arguments
    /// * `text` - UTF-8 text to write.
    ///
    /// # Returns
    /// `Ok(())` when the text is written to standard output.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if writing to the underlying output stream fails.
    fn write_stdout_str(&mut self, text: &str) -> Result<(), CmdError>;

    /// Writes raw encoded bytes to standard output (`handle 1`).
    ///
    /// # Arguments
    /// * `bytes` - Raw byte slice to write.
    ///
    /// # Returns
    /// `Ok(())` when the bytes are written to standard output.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if writing to the underlying output stream fails.
    fn write_stdout_bytes(&mut self, bytes: &[u8]) -> Result<(), CmdError>;

    /// Writes UTF-8 text to standard error (`handle 2`).
    ///
    /// # Arguments
    /// * `text` - UTF-8 error text to write.
    ///
    /// # Returns
    /// `Ok(())` when the error text is written to standard error.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if writing to the underlying error stream fails.
    fn write_stderr_str(&mut self, text: &str) -> Result<(), CmdError>;

    /// Flushes buffered `stdout` and `stderr` output prior to blocking interactive prompts.
    ///
    /// # Returns
    /// `Ok(())` when output streams have been flushed.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if flushing fails with a non-`BrokenPipe` OS error.
    fn flush_outputs(&mut self) -> Result<(), CmdError>;

    /// Reads a single line from `stdin` (`handle 0`), flushing pending prompts first.
    ///
    /// # Returns
    /// `Ok(Some(line))` trimmed of trailing CR/LF, or `Ok(None)` on EOF.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] or [`CmdError::EncodingFailure`] if reading fails.
    fn read_stdin_line(&mut self) -> Result<Option<String>, CmdError>;

    /// Reads all remaining text from `stdin` (`handle 0`) until EOF.
    ///
    /// # Arguments
    /// * `codepage` - Active [`CodePage`] used when decoding raw byte input.
    ///
    /// # Returns
    /// Decoded `stdin` text.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] or [`CmdError::EncodingFailure`] if reading or decoding fails.
    fn read_stdin_to_string(&mut self, codepage: CodePage) -> Result<String, CmdError>;

    /// Reads all remaining raw bytes from `stdin` (`handle 0`) until EOF.
    ///
    /// # Arguments
    /// * `codepage` - Active [`CodePage`] used if only UTF-8 text `stdin` is buffered.
    ///
    /// # Returns
    /// Raw byte buffer from `stdin`.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if reading fails.
    fn read_stdin_bytes(&mut self, codepage: CodePage) -> Result<Vec<u8>, CmdError>;
}

/// In-memory buffered implementation of [`CmdIo`] for hermetic tests and internal pipes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BufferedIoStreams {
    /// Queued UTF-8 lines on `stdin` (handle `0`).
    pub stdin: String,
    /// Optional raw byte payload on `stdin` (used by `/U` UTF-16LE or codepage-encoded internal pipes).
    pub stdin_bytes: Vec<u8>,
    /// Encoding of `stdin_bytes` when populated by an internal pipe.
    pub stdin_encoding: Option<CodePage>,
    /// Accumulated UTF-8 output written to `stdout` (handle `1`).
    pub stdout: String,
    /// Optional raw bytes written directly via [`CmdIo::write_stdout_bytes`].
    pub stdout_raw: Vec<u8>,
    /// Accumulated UTF-8 error output written to `stderr` (handle `2`).
    pub stderr: String,
}

/// Type alias preserving `IoStreams` naming alongside [`BufferedIoStreams`].
pub type IoStreams = BufferedIoStreams;

impl BufferedIoStreams {
    /// Creates empty [`BufferedIoStreams`].
    ///
    /// # Returns
    /// New [`BufferedIoStreams`] with empty buffers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates [`BufferedIoStreams`] pre-populated with UTF-8 `stdin` text.
    ///
    /// # Arguments
    /// * `stdin` - Input text available for commands reading `stdin`.
    ///
    /// # Returns
    /// Initialized [`BufferedIoStreams`].
    #[must_use]
    pub const fn with_stdin(stdin: String) -> Self {
        Self {
            stdin,
            stdin_bytes: Vec::new(),
            stdin_encoding: None,
            stdout: String::new(),
            stdout_raw: Vec::new(),
            stderr: String::new(),
        }
    }

    /// Creates [`BufferedIoStreams`] pre-populated with raw pipe bytes and their [`CodePage`].
    ///
    /// # Arguments
    /// * `bytes` - Raw encoded pipe bytes.
    /// * `encoding` - [`CodePage`] used to encode `bytes` (`CodePage::Utf16Le` when `/U` is active).
    ///
    /// # Returns
    /// Initialized [`BufferedIoStreams`].
    #[must_use]
    pub const fn with_pipe_bytes(bytes: Vec<u8>, encoding: CodePage) -> Self {
        Self {
            stdin: String::new(),
            stdin_bytes: bytes,
            stdin_encoding: Some(encoding),
            stdout: String::new(),
            stdout_raw: Vec::new(),
            stderr: String::new(),
        }
    }

    /// Encodes captured `stdout` into pipe bytes honoring `unicode_mode` (`/A` vs `/U`) and `codepage`.
    ///
    /// # Arguments
    /// * `unicode_mode` - Active [`OutputUnicodeMode`] (`/A` vs `/U`).
    /// * `codepage` - Active [`CodePage`] when `unicode_mode` is `Ansi`.
    ///
    /// # Returns
    /// Pair of `(raw_bytes, effective_pipe_codepage)`.
    #[must_use]
    pub fn into_encoded_pipe_output(
        self,
        unicode_mode: OutputUnicodeMode,
        codepage: CodePage,
    ) -> (Vec<u8>, CodePage) {
        if !self.stdout_raw.is_empty() {
            return (self.stdout_raw, codepage);
        }
        let eff_cp = match unicode_mode {
            OutputUnicodeMode::Utf16Le => CodePage::Utf16Le,
            OutputUnicodeMode::Ansi => codepage,
        };
        let bytes = encode_output_bytes_with_codepage(&self.stdout, unicode_mode, codepage);
        (bytes, eff_cp)
    }

    /// Ensures `self.stdin` is materialized from `self.stdin_bytes` if raw pipe bytes are pending.
    ///
    /// # Arguments
    /// * `fallback_codepage` - Fallback [`CodePage`] when `self.stdin_encoding` is `None`.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::EncodingFailure`] if `stdin_bytes` cannot be decoded.
    fn materialize_stdin_text(&mut self, fallback_codepage: CodePage) -> Result<(), CmdError> {
        if self.stdin.is_empty() && !self.stdin_bytes.is_empty() {
            let cp = self.stdin_encoding.unwrap_or(fallback_codepage);
            let raw = core::mem::take(&mut self.stdin_bytes);
            self.stdin = decode_script_bytes(&raw, cp)?;
        }
        Ok(())
    }
}

impl CmdIo for BufferedIoStreams {
    /// Appends `text` to `self.stdout`.
    ///
    /// # Arguments
    /// * `text` - UTF-8 text to append.
    ///
    /// # Returns
    /// Always `Ok(())`.
    ///
    /// # Errors
    /// Never returns [`CmdError`] on in-memory buffers.
    fn write_stdout_str(&mut self, text: &str) -> Result<(), CmdError> {
        self.stdout.push_str(text);
        Ok(())
    }

    /// Appends raw `bytes` to `self.stdout_raw` and lossily mirrors text to `self.stdout`.
    ///
    /// # Arguments
    /// * `bytes` - Raw byte slice to append.
    ///
    /// # Returns
    /// Always `Ok(())`.
    ///
    /// # Errors
    /// Never returns [`CmdError`] on in-memory buffers.
    fn write_stdout_bytes(&mut self, bytes: &[u8]) -> Result<(), CmdError> {
        self.stdout_raw.extend_from_slice(bytes);
        self.stdout.push_str(&String::from_utf8_lossy(bytes));
        Ok(())
    }

    /// Appends `text` to `self.stderr`.
    ///
    /// # Arguments
    /// * `text` - UTF-8 error text to append.
    ///
    /// # Returns
    /// Always `Ok(())`.
    ///
    /// # Errors
    /// Never returns [`CmdError`] on in-memory buffers.
    fn write_stderr_str(&mut self, text: &str) -> Result<(), CmdError> {
        self.stderr.push_str(text);
        Ok(())
    }

    /// No-op flush for in-memory buffers.
    ///
    /// # Returns
    /// Always `Ok(())`.
    ///
    /// # Errors
    /// Never returns [`CmdError`] on in-memory buffers.
    fn flush_outputs(&mut self) -> Result<(), CmdError> {
        Ok(())
    }

    /// Reads and removes a single line from `self.stdin` (decoding `self.stdin_bytes` first if needed).
    ///
    /// # Returns
    /// `Ok(Some(line))` if input remains, or `Ok(None)` when empty.
    ///
    /// # Errors
    /// Returns [`CmdError::EncodingFailure`] if pending `stdin_bytes` cannot be decoded.
    fn read_stdin_line(&mut self) -> Result<Option<String>, CmdError> {
        self.materialize_stdin_text(CodePage::Utf8)?;
        if self.stdin.is_empty() {
            return Ok(None);
        }
        Ok(Some(consume_buffered_line(&mut self.stdin)))
    }

    /// Reads and consumes all remaining `stdin` text.
    ///
    /// # Arguments
    /// * `codepage` - Fallback [`CodePage`] when decoding `stdin_bytes`.
    ///
    /// # Returns
    /// Remaining `stdin` string.
    ///
    /// # Errors
    /// Returns [`CmdError::EncodingFailure`] if pending `stdin_bytes` cannot be decoded.
    fn read_stdin_to_string(&mut self, codepage: CodePage) -> Result<String, CmdError> {
        self.materialize_stdin_text(codepage)?;
        Ok(core::mem::take(&mut self.stdin))
    }

    /// Reads and consumes all remaining raw `stdin` bytes.
    ///
    /// # Arguments
    /// * `codepage` - [`CodePage`] used to encode `self.stdin` if `self.stdin_bytes` is empty.
    ///
    /// # Returns
    /// Raw byte vector.
    ///
    /// # Errors
    /// Never returns [`CmdError`] on in-memory buffers.
    fn read_stdin_bytes(&mut self, codepage: CodePage) -> Result<Vec<u8>, CmdError> {
        if !self.stdin_bytes.is_empty() {
            return Ok(core::mem::take(&mut self.stdin_bytes));
        }
        let text = core::mem::take(&mut self.stdin);
        Ok(encode_codepage_bytes(&text, codepage))
    }
}

/// Portable `#![no_std]`-compatible byte-stream reader trait returning [`CmdError`].
pub trait ByteStreamRead {
    /// Reads up to `buf.len()` bytes into `buf`, returning `0` on EOF.
    ///
    /// # Arguments
    /// * `buf` - Destination byte slice.
    ///
    /// # Returns
    /// `Ok(count)` of bytes read into `buf`.
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading from the underlying stream fails.
    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize, CmdError>;

    /// Appends all remaining bytes from this stream until EOF onto `out`.
    ///
    /// # Arguments
    /// * `out` - Destination `Vec<u8>` receiving all remaining bytes.
    ///
    /// # Returns
    /// `Ok(total)` count of bytes appended to `out`.
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading fails prior to EOF.
    fn read_all_bytes(&mut self, out: &mut Vec<u8>) -> Result<usize, CmdError> {
        let mut scratch = [0u8; 4096];
        let mut total = 0usize;
        loop {
            let n = self.read_chunk(&mut scratch)?;
            if n == 0 {
                return Ok(total);
            }
            out.extend_from_slice(scratch.get(..n).unwrap_or(&[]));
            total = total.saturating_add(n);
        }
    }
}

/// Portable `#![no_std]`-compatible line-buffered byte-stream reader trait.
pub trait ByteStreamBufRead: ByteStreamRead {
    /// Reads bytes up through the next `0x0A` (`LF`) byte or EOF, appending them to `out`.
    ///
    /// # Arguments
    /// * `out` - Destination byte buffer.
    ///
    /// # Returns
    /// `Ok(count)` of bytes appended (`0` at EOF).
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading from the underlying stream fails.
    fn read_line_bytes(&mut self, out: &mut Vec<u8>) -> Result<usize, CmdError>;
}

/// Portable `#![no_std]`-compatible byte-stream writer trait returning [`CmdError`].
pub trait ByteStreamWrite {
    /// Writes a partial or complete chunk of `buf` into the stream.
    ///
    /// # Arguments
    /// * `buf` - Source byte slice.
    ///
    /// # Returns
    /// `Ok(count)` of bytes accepted by the stream.
    ///
    /// # Errors
    /// Returns [`CmdError`] (`BrokenPipe` or `IoFailure`) on write failure.
    fn write_chunk(&mut self, buf: &[u8]) -> Result<usize, CmdError>;

    /// Writes the entirety of `buf` into the stream.
    ///
    /// # Arguments
    /// * `buf` - Source byte slice to write completely.
    ///
    /// # Returns
    /// `Ok(())` when all bytes have been written.
    ///
    /// # Errors
    /// Returns [`CmdError`] (`BrokenPipe` or `IoFailure`) on write failure.
    fn write_all_bytes(&mut self, buf: &[u8]) -> Result<(), CmdError>;

    /// Flushes any buffered output bytes to the underlying device or sink.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] (`BrokenPipe` or `IoFailure`) on flush failure.
    fn flush_stream(&mut self) -> Result<(), CmdError>;
}

/// In-memory `#![no_std]` byte cursor implementing [`ByteStreamRead`] and [`ByteStreamBufRead`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InMemoryByteReader {
    /// Backing byte vector.
    data: Vec<u8>,
    /// Current read offset (`0..=data.len()`).
    pos: usize,
}

impl InMemoryByteReader {
    /// Creates a new [`InMemoryByteReader`] positioned at byte offset `0`.
    ///
    /// # Arguments
    /// * `data` - Backing input bytes.
    ///
    /// # Returns
    /// Initialized [`InMemoryByteReader`].
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns the current read cursor offset in bytes.
    ///
    /// # Returns
    /// Current byte position (`0..=len`).
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Consumes this reader and returns the unread remainder slice as a `Vec<u8>`.
    ///
    /// # Returns
    /// Unread trailing bytes starting at [`Self::position`].
    #[must_use]
    pub fn into_remaining(self) -> Vec<u8> {
        self.data.get(self.pos..).unwrap_or(&[]).to_vec()
    }
}

impl ByteStreamRead for InMemoryByteReader {
    /// Copies up to `buf.len()` unread bytes from `self` into `buf`.
    ///
    /// # Arguments
    /// * `buf` - Destination byte slice.
    ///
    /// # Returns
    /// `Ok(count)` of bytes copied (`0` when exhausted).
    ///
    /// # Errors
    /// Never returns [`CmdError`] on in-memory buffers.
    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize, CmdError> {
        let rem = self.data.get(self.pos..).unwrap_or(&[]);
        let n = buf
            .iter_mut()
            .zip(rem.iter())
            .map(|(dst, &src)| *dst = src)
            .count();
        self.pos = self.pos.saturating_add(n);
        Ok(n)
    }
}

impl ByteStreamBufRead for InMemoryByteReader {
    /// Reads bytes up through the next `0x0A` (`LF`) or end of buffer into `out`.
    ///
    /// # Arguments
    /// * `out` - Destination `Vec<u8>` buffer.
    ///
    /// # Returns
    /// `Ok(count)` of bytes appended (`0` at EOF).
    ///
    /// # Errors
    /// Never returns [`CmdError`] on in-memory buffers.
    fn read_line_bytes(&mut self, out: &mut Vec<u8>) -> Result<usize, CmdError> {
        let rem = self.data.get(self.pos..).unwrap_or(&[]);
        if rem.is_empty() {
            return Ok(0);
        }
        let take_len = rem
            .iter()
            .position(|&b| b == b'\n')
            .map_or(rem.len(), |idx| idx.saturating_add(1));
        out.extend_from_slice(rem.get(..take_len).unwrap_or(&[]));
        self.pos = self.pos.saturating_add(take_len);
        Ok(take_len)
    }
}

/// Type alias for an in-memory `#![no_std]` [`ByteStreamWrite`] buffer (`Vec<u8>`).
pub type InMemoryByteWriter = Vec<u8>;

impl ByteStreamWrite for Vec<u8> {
    /// Appends `buf` onto this `Vec<u8>`.
    ///
    /// # Arguments
    /// * `buf` - Byte slice to append.
    ///
    /// # Returns
    /// `Ok(buf.len())`.
    ///
    /// # Errors
    /// Never returns [`CmdError`] on `Vec<u8>`.
    fn write_chunk(&mut self, buf: &[u8]) -> Result<usize, CmdError> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Appends all bytes of `buf` onto this `Vec<u8>`.
    ///
    /// # Arguments
    /// * `buf` - Byte slice to append.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Never returns [`CmdError`] on `Vec<u8>`.
    fn write_all_bytes(&mut self, buf: &[u8]) -> Result<(), CmdError> {
        self.extend_from_slice(buf);
        Ok(())
    }

    /// No-op flush on an in-memory `Vec<u8>`.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Never returns [`CmdError`] on `Vec<u8>`.
    fn flush_stream(&mut self) -> Result<(), CmdError> {
        Ok(())
    }
}

/// Writes `bytes` to `stream` and flushes it, treating [`CmdError::BrokenPipe`] as graceful EOF.
///
/// # Arguments
/// * `stream` - Target [`ByteStreamWrite`] sink.
/// * `bytes` - Byte slice to write.
///
/// # Returns
/// `Ok(())` on success or `BrokenPipe` EOF.
///
/// # Errors
/// Returns [`CmdError`] on any non-`BrokenPipe` write or flush failure.
pub fn write_byte_stream_gracefully(
    stream: &mut dyn ByteStreamWrite,
    bytes: &[u8],
) -> Result<(), CmdError> {
    if bytes.is_empty() {
        return Ok(());
    }
    if let Err(err) = stream.write_all_bytes(bytes) {
        return if err.is_broken_pipe() {
            Ok(())
        } else {
            Err(err)
        };
    }
    flush_byte_stream_gracefully(stream)
}

/// Flushes `stream`, treating [`CmdError::BrokenPipe`] as graceful EOF.
///
/// # Arguments
/// * `stream` - Target [`ByteStreamWrite`] sink.
///
/// # Returns
/// `Ok(())` on success or `BrokenPipe` EOF.
///
/// # Errors
/// Returns [`CmdError`] on any non-`BrokenPipe` flush failure.
pub fn flush_byte_stream_gracefully(stream: &mut dyn ByteStreamWrite) -> Result<(), CmdError> {
    match stream.flush_stream() {
        Ok(()) => Ok(()),
        Err(err) if err.is_broken_pipe() => Ok(()),
        Err(err) => Err(err),
    }
}

/// Portable `#![no_std]` live streaming [`CmdIo`] adapter over [`ByteStreamBufRead`] and [`ByteStreamWrite`].
pub struct ByteStreamIo<'a> {
    /// Live buffered standard input reader.
    pub stdin: &'a mut dyn ByteStreamBufRead,
    /// Live standard output writer.
    pub stdout: &'a mut dyn ByteStreamWrite,
    /// Live standard error writer.
    pub stderr: &'a mut dyn ByteStreamWrite,
    /// Active console [`CodePage`] for byte decoding.
    pub codepage: CodePage,
    /// Active [`OutputUnicodeMode`] (`/A` vs `/U`) for raw byte output.
    pub unicode_mode: OutputUnicodeMode,
    /// First non-`BrokenPipe` stream [`CmdError`] encountered during execution, if any.
    pub last_error: Option<CmdError>,
}

impl<'a> ByteStreamIo<'a> {
    /// Creates a new portable [`ByteStreamIo`] adapter.
    ///
    /// # Arguments
    /// * `stdin` - Live buffered input stream.
    /// * `stdout` - Live standard output stream.
    /// * `stderr` - Live standard error stream.
    /// * `codepage` - Active [`CodePage`].
    /// * `unicode_mode` - Active [`OutputUnicodeMode`].
    ///
    /// # Returns
    /// Configured [`ByteStreamIo`].
    #[must_use]
    pub fn new(
        stdin: &'a mut dyn ByteStreamBufRead,
        stdout: &'a mut dyn ByteStreamWrite,
        stderr: &'a mut dyn ByteStreamWrite,
        codepage: CodePage,
        unicode_mode: OutputUnicodeMode,
    ) -> Self {
        Self {
            stdin,
            stdout,
            stderr,
            codepage,
            unicode_mode,
            last_error: None,
        }
    }

    /// Takes and returns any recorded stream [`CmdError`].
    ///
    /// # Returns
    /// `Ok(())` when no stream failure occurred.
    ///
    /// # Errors
    /// Returns the recorded [`CmdError`] if a live read/write/flush failed.
    pub fn check_error(&mut self) -> Result<(), CmdError> {
        self.last_error.take().map_or(Ok(()), Err)
    }

    /// Records `err` as the first sticky I/O failure and returns `err`.
    ///
    /// # Arguments
    /// * `err` - [`CmdError`] encountered during live stream I/O.
    ///
    /// # Returns
    /// The passed `err`.
    fn record_err(&mut self, err: CmdError) -> CmdError {
        if self.last_error.is_none() {
            self.last_error = Some(err.clone());
        }
        err
    }
}

impl CmdIo for ByteStreamIo<'_> {
    /// Writes UTF-8 `text` directly to live `self.stdout` and flushes immediately.
    ///
    /// # Arguments
    /// * `text` - UTF-8 text to write.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] on non-`BrokenPipe` write failure.
    fn write_stdout_str(&mut self, text: &str) -> Result<(), CmdError> {
        write_byte_stream_gracefully(self.stdout, text.as_bytes())
            .map_err(|err| self.record_err(err))
    }

    /// Writes raw `bytes` directly to live `self.stdout` and flushes immediately.
    ///
    /// # Arguments
    /// * `bytes` - Raw byte slice to write.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] on non-`BrokenPipe` write failure.
    fn write_stdout_bytes(&mut self, bytes: &[u8]) -> Result<(), CmdError> {
        write_byte_stream_gracefully(self.stdout, bytes).map_err(|err| self.record_err(err))
    }

    /// Writes UTF-8 error `text` directly to live `self.stderr` and flushes immediately.
    ///
    /// # Arguments
    /// * `text` - UTF-8 error text to write.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] on non-`BrokenPipe` write failure.
    fn write_stderr_str(&mut self, text: &str) -> Result<(), CmdError> {
        write_byte_stream_gracefully(self.stderr, text.as_bytes())
            .map_err(|err| self.record_err(err))
    }

    /// Flushes both `self.stdout` and `self.stderr`.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] on non-`BrokenPipe` flush failure.
    fn flush_outputs(&mut self) -> Result<(), CmdError> {
        flush_byte_stream_gracefully(self.stdout)
            .and_then(|()| flush_byte_stream_gracefully(self.stderr))
            .map_err(|err| self.record_err(err))
    }

    /// Flushes pending prompts and reads a single interactive line from `self.stdin`.
    ///
    /// # Returns
    /// `Ok(Some(line))` without trailing CR/LF, or `Ok(None)` at EOF.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if reading from `self.stdin` fails.
    fn read_stdin_line(&mut self) -> Result<Option<String>, CmdError> {
        self.flush_outputs()?;
        let mut raw = Vec::new();
        let n = match self.stdin.read_line_bytes(&mut raw) {
            Ok(count) => count,
            Err(err) => return Err(self.record_err(err)),
        };
        if n == 0 {
            return Ok(None);
        }
        let decoded = String::from_utf8_lossy(&raw);
        Ok(Some(
            decoded.trim_end_matches([CR_CHAR, LF_CHAR]).to_owned(),
        ))
    }

    /// Reads all remaining bytes from `self.stdin` and decodes them with `codepage`.
    ///
    /// # Arguments
    /// * `codepage` - Active [`CodePage`] for decoding.
    ///
    /// # Returns
    /// Decoded `stdin` text.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] or [`CmdError::EncodingFailure`] on read or decode error.
    fn read_stdin_to_string(&mut self, codepage: CodePage) -> Result<String, CmdError> {
        let bytes = self.read_stdin_bytes(codepage)?;
        decode_script_bytes(&bytes, codepage)
    }

    /// Reads all remaining raw bytes from `self.stdin` until EOF.
    ///
    /// # Arguments
    /// * `_codepage` - Unused on raw byte stream.
    ///
    /// # Returns
    /// Raw byte buffer read from `self.stdin`.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if reading from `self.stdin` fails.
    fn read_stdin_bytes(&mut self, _codepage: CodePage) -> Result<Vec<u8>, CmdError> {
        self.flush_outputs()?;
        let mut buf = Vec::new();
        if let Err(err) = self.stdin.read_all_bytes(&mut buf) {
            return Err(self.record_err(err));
        }
        Ok(buf)
    }
}

/// Adapter bridging [`std::io::Read`] onto [`ByteStreamRead`].
#[cfg(feature = "std")]
pub struct StdReadAdapter<'a>(
    /// Wrapped mutable [`std::io::Read`] trait object.
    pub &'a mut dyn Read,
);

#[cfg(feature = "std")]
impl ByteStreamRead for StdReadAdapter<'_> {
    /// Reads a chunk from the wrapped [`std::io::Read`] stream.
    ///
    /// # Arguments
    /// * `buf` - Destination byte buffer.
    ///
    /// # Returns
    /// `Ok(count)` of bytes read.
    ///
    /// # Errors
    /// Returns [`CmdError`] mapped via [`CmdError::from_io_error`].
    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize, CmdError> {
        self.0
            .read(buf)
            .map_err(|err| CmdError::from_io_error(&err, "-", "read"))
    }
}

/// Adapter bridging [`std::io::BufRead`] onto [`ByteStreamRead`] and [`ByteStreamBufRead`].
#[cfg(feature = "std")]
pub struct StdBufReadAdapter<'a>(
    /// Wrapped mutable [`std::io::BufRead`] trait object.
    pub &'a mut dyn BufRead,
);

#[cfg(feature = "std")]
impl ByteStreamRead for StdBufReadAdapter<'_> {
    /// Reads a chunk from the wrapped [`std::io::BufRead`] stream.
    ///
    /// # Arguments
    /// * `buf` - Destination byte buffer.
    ///
    /// # Returns
    /// `Ok(count)` of bytes read.
    ///
    /// # Errors
    /// Returns [`CmdError`] mapped via [`map_stream_io_error`].
    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize, CmdError> {
        self.0
            .read(buf)
            .map_err(|err| map_stream_io_error(&err, "read stdin"))
    }
}

#[cfg(feature = "std")]
impl ByteStreamBufRead for StdBufReadAdapter<'_> {
    /// Reads up through `0x0A` (`LF`) or EOF from the wrapped [`std::io::BufRead`] stream.
    ///
    /// # Arguments
    /// * `out` - Destination byte vector.
    ///
    /// # Returns
    /// `Ok(count)` of bytes read.
    ///
    /// # Errors
    /// Returns [`CmdError`] mapped via [`map_stream_io_error`].
    fn read_line_bytes(&mut self, out: &mut Vec<u8>) -> Result<usize, CmdError> {
        self.0
            .read_until(b'\n', out)
            .map_err(|err| map_stream_io_error(&err, "read stdin"))
    }
}

/// Adapter bridging [`std::io::Write`] onto [`ByteStreamWrite`].
#[cfg(feature = "std")]
pub struct StdWriteAdapter<'a> {
    /// Wrapped mutable [`std::io::Write`] trait object.
    pub inner: &'a mut dyn Write,
    /// Diagnostic operation label (`"write"`, `"write stdout"`, `"write stderr"`).
    pub op_name: &'a str,
}

#[cfg(feature = "std")]
impl<'a> StdWriteAdapter<'a> {
    /// Constructs a new [`StdWriteAdapter`] around `inner` with diagnostic label `op_name`.
    ///
    /// # Arguments
    /// * `inner` - Mutable [`std::io::Write`] sink.
    /// * `op_name` - Operation label reported on failure.
    ///
    /// # Returns
    /// Configured [`StdWriteAdapter`].
    #[must_use]
    pub fn new(inner: &'a mut dyn Write, op_name: &'a str) -> Self {
        Self { inner, op_name }
    }
}

#[cfg(feature = "std")]
impl ByteStreamWrite for StdWriteAdapter<'_> {
    /// Writes a partial or full chunk to `self.inner`.
    ///
    /// # Arguments
    /// * `buf` - Source byte slice.
    ///
    /// # Returns
    /// `Ok(count)` of bytes written.
    ///
    /// # Errors
    /// Returns [`CmdError`] mapped via [`map_stream_io_error`].
    fn write_chunk(&mut self, buf: &[u8]) -> Result<usize, CmdError> {
        self.inner
            .write(buf)
            .map_err(|err| map_stream_io_error(&err, self.op_name))
    }

    /// Writes all bytes of `buf` to `self.inner`.
    ///
    /// # Arguments
    /// * `buf` - Source byte slice.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] mapped via [`map_stream_io_error`].
    fn write_all_bytes(&mut self, buf: &[u8]) -> Result<(), CmdError> {
        self.inner
            .write_all(buf)
            .map_err(|err| map_stream_io_error(&err, self.op_name))
    }

    /// Flushes `self.inner`.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] mapped via [`map_stream_io_error`].
    fn flush_stream(&mut self) -> Result<(), CmdError> {
        self.inner
            .flush()
            .map_err(|err| map_stream_io_error(&err, self.op_name))
    }
}

/// Maps a live stream [`std::io::Error`] into [`CmdError::BrokenPipe`] or [`CmdError::IoFailure`].
///
/// # Arguments
/// * `err` - Underlying stream [`std::io::Error`].
/// * `op_name` - Diagnostic operation label (`"write stdout"`, `"write stderr"`).
///
/// # Returns
/// [`CmdError::BrokenPipe`] when `err.kind() == BrokenPipe`, otherwise [`CmdError::IoFailure`].
#[cfg(feature = "std")]
#[must_use]
pub fn map_stream_io_error(err: &std::io::Error, op_name: &str) -> CmdError {
    if err.kind() == std::io::ErrorKind::BrokenPipe {
        CmdError::BrokenPipe
    } else {
        CmdError::IoFailure {
            operation: op_name.to_owned(),
            message: err.to_string(),
        }
    }
}

/// Writes `bytes` to `stream` and flushes it, treating [`CmdError::BrokenPipe`] as graceful EOF.
///
/// # Arguments
/// * `stream` - Target [`Write`] sink.
/// * `bytes` - Byte slice to write.
/// * `op_name` - Diagnostic operation label (`"write stdout"`, `"write stderr"`).
///
/// # Returns
/// `Ok(())` on success or `BrokenPipe` EOF.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] on any non-`BrokenPipe` write or flush error.
#[cfg(feature = "std")]
pub fn write_and_flush_gracefully(
    stream: &mut dyn Write,
    bytes: &[u8],
    op_name: &str,
) -> Result<(), CmdError> {
    let mut adapter = StdWriteAdapter::new(stream, op_name);
    write_byte_stream_gracefully(&mut adapter, bytes)
}

/// Flushes `stream`, treating [`CmdError::BrokenPipe`] as graceful EOF.
///
/// # Arguments
/// * `stream` - Target [`Write`] sink.
/// * `op_name` - Diagnostic operation label.
///
/// # Returns
/// `Ok(())` on success or `BrokenPipe` EOF.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] on any non-`BrokenPipe` flush error.
#[cfg(feature = "std")]
pub fn flush_stream_gracefully(stream: &mut dyn Write, op_name: &str) -> Result<(), CmdError> {
    let mut adapter = StdWriteAdapter::new(stream, op_name);
    flush_byte_stream_gracefully(&mut adapter)
}

/// Live streaming [`CmdIo`] adapter wrapping `BufRead` `stdin` and `Write` `stdout`/`stderr`.
#[cfg(feature = "std")]
pub struct StdIoStreams<'a> {
    /// Live buffered standard input reader.
    pub stdin: &'a mut dyn BufRead,
    /// Live standard output writer.
    pub stdout: &'a mut dyn Write,
    /// Live standard error writer.
    pub stderr: &'a mut dyn Write,
    /// Active console [`CodePage`] for byte decoding.
    pub codepage: CodePage,
    /// Active [`OutputUnicodeMode`] (`/A` vs `/U`) for raw byte output.
    pub unicode_mode: OutputUnicodeMode,
    /// First non-`BrokenPipe` stream [`CmdError`] encountered during execution, if any.
    pub last_error: Option<CmdError>,
}

#[cfg(feature = "std")]
impl<'a> StdIoStreams<'a> {
    /// Creates a new live [`StdIoStreams`] adapter.
    ///
    /// # Arguments
    /// * `stdin` - Live buffered input stream.
    /// * `stdout` - Live standard output stream.
    /// * `stderr` - Live standard error stream.
    /// * `codepage` - Active [`CodePage`].
    /// * `unicode_mode` - Active [`OutputUnicodeMode`].
    ///
    /// # Returns
    /// Configured [`StdIoStreams`].
    #[must_use]
    pub fn new(
        stdin: &'a mut dyn BufRead,
        stdout: &'a mut dyn Write,
        stderr: &'a mut dyn Write,
        codepage: CodePage,
        unicode_mode: OutputUnicodeMode,
    ) -> Self {
        Self {
            stdin,
            stdout,
            stderr,
            codepage,
            unicode_mode,
            last_error: None,
        }
    }

    /// Takes and returns any recorded stream [`CmdError`].
    ///
    /// # Returns
    /// `Ok(())` when no stream failure occurred.
    ///
    /// # Errors
    /// Returns the recorded [`CmdError::IoFailure`] if a live read/write/flush failed.
    pub fn check_error(&mut self) -> Result<(), CmdError> {
        self.last_error.take().map_or(Ok(()), Err)
    }

    /// Executes `f` against a temporary [`ByteStreamIo`] adapter, propagating `last_error`.
    ///
    /// # Arguments
    /// * `f` - Closure operating on [`ByteStreamIo`].
    ///
    /// # Returns
    /// Result of `f`.
    ///
    /// # Errors
    /// Propagates any [`CmdError`] returned by `f`.
    fn with_byte_io<T>(
        &mut self,
        f: impl FnOnce(&mut ByteStreamIo<'_>) -> Result<T, CmdError>,
    ) -> Result<T, CmdError> {
        let mut sin = StdBufReadAdapter(self.stdin);
        let mut sout = StdWriteAdapter::new(self.stdout, "write stdout");
        let mut serr = StdWriteAdapter::new(self.stderr, "write stderr");
        let mut bio = ByteStreamIo {
            stdin: &mut sin,
            stdout: &mut sout,
            stderr: &mut serr,
            codepage: self.codepage,
            unicode_mode: self.unicode_mode,
            last_error: self.last_error.take(),
        };
        let res = f(&mut bio);
        self.last_error = bio.last_error;
        res
    }
}

#[cfg(feature = "std")]
impl CmdIo for StdIoStreams<'_> {
    /// Writes UTF-8 `text` directly to live `self.stdout` and flushes immediately.
    ///
    /// # Arguments
    /// * `text` - UTF-8 text to write.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] on non-`BrokenPipe` write failure.
    fn write_stdout_str(&mut self, text: &str) -> Result<(), CmdError> {
        self.with_byte_io(|bio| bio.write_stdout_str(text))
    }

    /// Writes raw `bytes` directly to live `self.stdout` and flushes immediately.
    ///
    /// # Arguments
    /// * `bytes` - Raw byte slice to write.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] on non-`BrokenPipe` write failure.
    fn write_stdout_bytes(&mut self, bytes: &[u8]) -> Result<(), CmdError> {
        self.with_byte_io(|bio| bio.write_stdout_bytes(bytes))
    }

    /// Writes UTF-8 error `text` directly to live `self.stderr` and flushes immediately.
    ///
    /// # Arguments
    /// * `text` - UTF-8 error text to write.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] on non-`BrokenPipe` write failure.
    fn write_stderr_str(&mut self, text: &str) -> Result<(), CmdError> {
        self.with_byte_io(|bio| bio.write_stderr_str(text))
    }

    /// Flushes both `self.stdout` and `self.stderr`.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] on non-`BrokenPipe` flush failure.
    fn flush_outputs(&mut self) -> Result<(), CmdError> {
        self.with_byte_io(|bio: &mut ByteStreamIo<'_>| bio.flush_outputs())
    }

    /// Flushes pending prompts and reads a single interactive line from `self.stdin`.
    ///
    /// # Returns
    /// `Ok(Some(line))` without trailing CR/LF, or `Ok(None)` at EOF.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if reading from `self.stdin` fails.
    fn read_stdin_line(&mut self) -> Result<Option<String>, CmdError> {
        self.with_byte_io(|bio: &mut ByteStreamIo<'_>| bio.read_stdin_line())
    }

    /// Reads all remaining bytes from `self.stdin` and decodes them with `codepage`.
    ///
    /// # Arguments
    /// * `codepage` - Active [`CodePage`] for decoding.
    ///
    /// # Returns
    /// Decoded `stdin` text.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] or [`CmdError::EncodingFailure`] on read or decode error.
    fn read_stdin_to_string(&mut self, codepage: CodePage) -> Result<String, CmdError> {
        self.with_byte_io(|bio| bio.read_stdin_to_string(codepage))
    }

    /// Reads all remaining raw bytes from `self.stdin` until EOF.
    ///
    /// # Arguments
    /// * `codepage` - Active [`CodePage`] passed through to [`ByteStreamIo::read_stdin_bytes`].
    ///
    /// # Returns
    /// Raw byte buffer read from `self.stdin`.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if reading from `self.stdin` fails.
    fn read_stdin_bytes(&mut self, codepage: CodePage) -> Result<Vec<u8>, CmdError> {
        self.with_byte_io(|bio| bio.read_stdin_bytes(codepage))
    }
}

/// Output buffering mode for [`RedirectedIo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputCaptureMode {
    /// Forward stdout and stderr directly to `parent` without capturing.
    PassThrough,
    /// Capture stdout and stderr into an ordered chronological log for redirection sink flushing.
    BufferedForSinks,
}

/// Standard stream identifier (`1` stdout vs `2` stderr) for [`CapturedOutputChunk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStreamId {
    /// Standard output (`handle 1`).
    Stdout,
    /// Standard error (`handle 2`).
    Stderr,
}

/// Single chronological write event captured by [`RedirectedIo`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapturedOutputChunk {
    /// UTF-8 text write (`write_stdout_str` or `write_stderr_str`), encoded via active codepage/`/U` on file flush.
    Text {
        /// Originating stream (`Stdout` or `Stderr`).
        stream: OutputStreamId,
        /// UTF-8 text payload.
        text: String,
    },
    /// Raw binary byte write (`write_stdout_bytes`), preserved verbatim without UTF-8 lossy conversion.
    RawBytes {
        /// Originating stream (`Stdout`).
        stream: OutputStreamId,
        /// Uninterpreted raw byte payload.
        bytes: Vec<u8>,
    },
}

/// Overlay [`CmdIo`] routing redirected handles (`<`, `>`, `>>`, `n>&m`) while delegating
/// unredirected handles directly to the live `parent` [`CmdIo`] stream.
pub struct RedirectedIo<'a> {
    /// Underlying parent [`CmdIo`] stream for any unredirected handle.
    pub parent: &'a mut dyn CmdIo,
    /// Optional overridden `stdin` text (`Some(...)` when `< file` or `0<&n` is present).
    pub stdin_override: Option<String>,
    /// Output buffering mode (`PassThrough` vs `BufferedForSinks`).
    pub capture_mode: OutputCaptureMode,
    /// Chronologically ordered output chunks captured when `capture_mode` is `BufferedForSinks`.
    pub output_chunks: Vec<CapturedOutputChunk>,
}

impl<'a> RedirectedIo<'a> {
    /// Constructs a [`RedirectedIo`] overlay over `parent`.
    ///
    /// # Arguments
    /// * `parent` - Parent [`CmdIo`] stream.
    /// * `stdin_override` - Optional `< file` / `0<&n` input override (`None` = read live from `parent`).
    /// * `capture_mode` - [`OutputCaptureMode`] (`BufferedForSinks` when output redirections are present).
    ///
    /// # Returns
    /// Configured [`RedirectedIo`].
    #[must_use]
    pub fn new(
        parent: &'a mut dyn CmdIo,
        stdin_override: Option<String>,
        capture_mode: OutputCaptureMode,
    ) -> Self {
        Self {
            parent,
            stdin_override,
            capture_mode,
            output_chunks: Vec::new(),
        }
    }
}

impl CmdIo for RedirectedIo<'_> {
    /// Writes UTF-8 `text` into `output_chunks` if buffered, or live to `self.parent`.
    ///
    /// # Arguments
    /// * `text` - UTF-8 text to write.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if writing to live `self.parent` fails.
    fn write_stdout_str(&mut self, text: &str) -> Result<(), CmdError> {
        if self.capture_mode == OutputCaptureMode::BufferedForSinks {
            if !text.is_empty() {
                self.output_chunks.push(CapturedOutputChunk::Text {
                    stream: OutputStreamId::Stdout,
                    text: text.to_owned(),
                });
            }
            Ok(())
        } else {
            self.parent.write_stdout_str(text)
        }
    }

    /// Writes raw `bytes` verbatim into `output_chunks` if buffered, or live to `self.parent`.
    ///
    /// # Arguments
    /// * `bytes` - Raw byte slice to write.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if writing to live `self.parent` fails.
    fn write_stdout_bytes(&mut self, bytes: &[u8]) -> Result<(), CmdError> {
        if self.capture_mode == OutputCaptureMode::BufferedForSinks {
            if !bytes.is_empty() {
                self.output_chunks.push(CapturedOutputChunk::RawBytes {
                    stream: OutputStreamId::Stdout,
                    bytes: bytes.to_vec(),
                });
            }
            Ok(())
        } else {
            self.parent.write_stdout_bytes(bytes)
        }
    }

    /// Writes UTF-8 error `text` into `output_chunks` if buffered, or live to `self.parent`.
    ///
    /// # Arguments
    /// * `text` - UTF-8 error text to write.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if writing to live `self.parent` fails.
    fn write_stderr_str(&mut self, text: &str) -> Result<(), CmdError> {
        if self.capture_mode == OutputCaptureMode::BufferedForSinks {
            if !text.is_empty() {
                self.output_chunks.push(CapturedOutputChunk::Text {
                    stream: OutputStreamId::Stderr,
                    text: text.to_owned(),
                });
            }
            Ok(())
        } else {
            self.parent.write_stderr_str(text)
        }
    }

    /// Flushes live `self.parent` outputs.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if flushing `self.parent` fails.
    fn flush_outputs(&mut self) -> Result<(), CmdError> {
        self.parent.flush_outputs()
    }

    /// Reads a line from `stdin_override` if `<` redirected, or live from `self.parent`.
    ///
    /// # Returns
    /// `Ok(Some(line))` or `Ok(None)` at EOF.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] or [`CmdError::EncodingFailure`] if reading from `self.parent` fails.
    fn read_stdin_line(&mut self) -> Result<Option<String>, CmdError> {
        if let Some(buf) = &mut self.stdin_override {
            if buf.is_empty() {
                Ok(None)
            } else {
                Ok(Some(consume_buffered_line(buf)))
            }
        } else {
            self.parent.read_stdin_line()
        }
    }

    /// Reads all remaining `stdin` text from `stdin_override` or live from `self.parent`.
    ///
    /// # Arguments
    /// * `codepage` - Active [`CodePage`].
    ///
    /// # Returns
    /// Remaining `stdin` string.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] or [`CmdError::EncodingFailure`] if reading from `self.parent` fails.
    fn read_stdin_to_string(&mut self, codepage: CodePage) -> Result<String, CmdError> {
        if let Some(buf) = &mut self.stdin_override {
            Ok(core::mem::take(buf))
        } else {
            self.parent.read_stdin_to_string(codepage)
        }
    }

    /// Reads all remaining raw `stdin` bytes from `stdin_override` or live from `self.parent`.
    ///
    /// # Arguments
    /// * `codepage` - Active [`CodePage`] used when encoding `stdin_override`.
    ///
    /// # Returns
    /// Raw byte buffer.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if reading from `self.parent` fails.
    fn read_stdin_bytes(&mut self, codepage: CodePage) -> Result<Vec<u8>, CmdError> {
        if let Some(buf) = &mut self.stdin_override {
            let text = core::mem::take(buf);
            Ok(encode_codepage_bytes(&text, codepage))
        } else {
            self.parent.read_stdin_bytes(codepage)
        }
    }
}

#[cfg(test)]
/// Unit tests for streaming [`CmdIo`], [`RedirectedIo`], and deadlock-free [`HostProcessSpawner`].
mod tests {
    use std::io::Cursor;

    use crate::types::DriveLetter;

    use super::*;

    /// Writer test double failing with a configured [`std::io::ErrorKind`] on write or flush.
    struct MockFailingWriter {
        /// Error kind to return.
        kind: std::io::ErrorKind,
        /// Whether `write` succeeds and `flush` fails instead.
        fail_on_flush: bool,
    }

    impl Write for MockFailingWriter {
        /// Fails on write unless `self.fail_on_flush` is set.
        ///
        /// # Arguments
        /// * `buf` - Input bytes to write.
        ///
        /// # Returns
        /// Number of bytes accepted or a simulated [`std::io::Error`].
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.fail_on_flush {
                Ok(buf.len())
            } else {
                Err(std::io::Error::new(self.kind, "mock write error"))
            }
        }

        /// Fails on flush when `self.fail_on_flush` is set.
        ///
        /// # Returns
        /// `Ok(())` or a simulated [`std::io::Error`].
        fn flush(&mut self) -> std::io::Result<()> {
            if self.fail_on_flush {
                Err(std::io::Error::new(self.kind, "mock flush error"))
            } else {
                Ok(())
            }
        }
    }

    /// Reader test double that always fails with `Other`.
    struct MockFailingReader;

    impl Read for MockFailingReader {
        /// Always returns an I/O read failure.
        ///
        /// # Arguments
        /// * `_buf` - Destination read buffer.
        ///
        /// # Returns
        /// Simulated [`std::io::Error`].
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("mock read error"))
        }
    }

    /// Verifies `HostProcessSpawner` large >128 KiB bidirectional pipe streaming without deadlocks,
    /// `BrokenPipe` handling when child exits early, and `ChildProcessFailure` error reporting.
    #[test]
    fn test_host_process_spawner_large_pipe_broken_pipe_and_errors() {
        let mut spawner = HostProcessSpawner;
        let _cloned = spawner.clone_box();

        // 1. >128 KiB payload through `cat` / `powershell` (exceeds 64 KiB OS pipe buffer, proving zero deadlock!)
        let large_payload = "A".repeat(131_072);
        #[cfg(unix)]
        let (cat_prog, cat_args) = (std::path::PathBuf::from("cat"), Vec::new());
        #[cfg(windows)]
        let (cat_prog, cat_args) = (
            std::path::PathBuf::from("powershell"),
            vec![
                "-NoProfile".to_owned(),
                "-NonInteractive".to_owned(),
                "-Command".to_owned(),
                "[Console]::OpenStandardInput().CopyTo([Console]::OpenStandardOutput())".to_owned(),
            ],
        );
        let cat_request = ExternalSpawnRequest {
            program_vfs_path: WindowsPath::root(DriveLetter::C).join_component("cat"),
            program_host_path: Some(NativeBackingPath::from_path_buf(cat_prog)),
            args: cat_args,
            raw_tail: String::new(),
            cwd_vfs: WindowsPath::root(DriveLetter::C),
            cwd_host: Some(NativeBackingPath::from_path_buf(std::env::temp_dir())),
            env_vars: vec![("TEST_K".to_owned(), "TEST_V".to_owned())],
            stdin: String::new(),
            stdin_bytes: large_payload.as_bytes().to_vec(),
            wait_mode: WaitMode::Wait,
            window_mode: StartWindowMode::Normal,
            env_mode: StartEnvMode::CurrentEnv,
            priority: ProcessPriority::Normal,
        };
        let cat_outcome = spawner.spawn_external(&cat_request);
        assert_eq!(
            cat_outcome,
            Ok(ExternalSpawnResult {
                exit_code: ExitCode::SUCCESS,
                stdout: large_payload,
                stderr: String::new(),
            })
        );

        // 2. Child (`echo` / `powershell`) exits immediately without reading 256 KiB stdin -> BrokenPipe handled cleanly!
        #[cfg(unix)]
        let (echo_prog, echo_args) = (
            std::path::PathBuf::from("echo"),
            vec!["ok_early".to_owned()],
        );
        #[cfg(windows)]
        let (echo_prog, echo_args) = (
            std::path::PathBuf::from("powershell"),
            vec![
                "-NoProfile".to_owned(),
                "-NonInteractive".to_owned(),
                "-Command".to_owned(),
                "[Console]::Out.Write(\"ok_early`n\")".to_owned(),
            ],
        );
        let echo_request = ExternalSpawnRequest {
            program_vfs_path: WindowsPath::root(DriveLetter::C).join_component("echo"),
            program_host_path: Some(NativeBackingPath::from_path_buf(echo_prog)),
            args: echo_args,
            raw_tail: "ok_early".to_owned(),
            cwd_vfs: WindowsPath::root(DriveLetter::C),
            cwd_host: None,
            env_vars: Vec::new(),
            stdin: "B".repeat(262_144),
            stdin_bytes: Vec::new(),
            wait_mode: WaitMode::Wait,
            window_mode: StartWindowMode::Normal,
            env_mode: StartEnvMode::CurrentEnv,
            priority: ProcessPriority::Normal,
        };
        let echo_outcome = spawner.spawn_external(&echo_request);
        assert_eq!(
            echo_outcome,
            Ok(ExternalSpawnResult {
                exit_code: ExitCode::SUCCESS,
                stdout: format!("ok_early{LF_CHAR}"),
                stderr: String::new(),
            })
        );
    }

    /// Verifies `write_child_stdin_bytes` error handling and `ChildProcessFailure` reporting for missing executables.
    #[test]
    fn test_host_process_spawner_stdin_helper_and_not_found_error() {
        let mut spawner = HostProcessSpawner;

        // 1. Direct unit checks on `write_child_stdin_bytes` (empty, BrokenPipe, real error)
        let mut sink = Vec::new();
        assert!(write_child_stdin_bytes(&mut sink, b"").is_ok());
        assert!(write_child_stdin_bytes(&mut sink, b"hi").is_ok());
        assert_eq!(sink, b"hi");

        let mut bp_writer = MockFailingWriter {
            kind: std::io::ErrorKind::BrokenPipe,
            fail_on_flush: false,
        };
        assert!(write_child_stdin_bytes(&mut bp_writer, b"hi").is_ok());

        let mut err_writer = MockFailingWriter {
            kind: std::io::ErrorKind::PermissionDenied,
            fail_on_flush: false,
        };
        assert!(write_child_stdin_bytes(&mut err_writer, b"hi").is_err());

        // 2. Nonexistent executable -> `CmdError::ChildProcessFailure` with `IoErrorKind::NotFound`
        let missing_request = ExternalSpawnRequest {
            program_vfs_path: WindowsPath::root(DriveLetter::C)
                .join_component("nonexistent_wincmd_bin_99999"),
            program_host_path: None,
            args: Vec::new(),
            raw_tail: String::new(),
            cwd_vfs: WindowsPath::root(DriveLetter::C),
            cwd_host: Some(NativeBackingPath::from_string(
                "/nonexistent_wincmd_dir_99999",
            )),
            env_vars: Vec::new(),
            stdin: String::new(),
            stdin_bytes: Vec::new(),
            wait_mode: WaitMode::Wait,
            window_mode: StartWindowMode::Normal,
            env_mode: StartEnvMode::CurrentEnv,
            priority: ProcessPriority::Normal,
        };
        let missing_outcome = spawner.spawn_external(&missing_request);
        assert!(matches!(
            missing_outcome,
            Err(CmdError::ChildProcessFailure {
                kind: IoErrorKind::NotFound,
                ..
            })
        ));
    }

    /// Verifies `BufferedIoStreams` and `StdIoStreams` across UTF-8, `/U` UTF-16LE, `BrokenPipe`, and error branches.
    #[test]
    fn test_buffered_and_live_stdio_streams_encoding_and_errors() {
        let mut buf_io = BufferedIoStreams::new();
        assert_eq!(buf_io.write_stdout_str("hello"), Ok(()));
        assert_eq!(buf_io.write_stderr_str("warn"), Ok(()));
        assert_eq!(buf_io.flush_outputs(), Ok(()));
        assert_eq!(buf_io.read_stdin_line(), Ok(None));

        let (utf16_bytes, utf16_cp) =
            buf_io.into_encoded_pipe_output(OutputUnicodeMode::Utf16Le, CodePage::Utf8);
        assert_eq!(utf16_cp, CodePage::Utf16Le);
        assert_eq!(
            utf16_bytes,
            vec![b'h', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0]
        );

        let mut pipe_in = BufferedIoStreams::with_pipe_bytes(utf16_bytes.clone(), utf16_cp);
        assert_eq!(pipe_in.read_stdin_line(), Ok(Some("hello".to_owned())));
        assert_eq!(
            pipe_in.read_stdin_to_string(CodePage::Utf8),
            Ok(String::new())
        );

        let mut pipe_raw_consumer =
            BufferedIoStreams::with_pipe_bytes(utf16_bytes.clone(), utf16_cp);
        assert_eq!(
            pipe_raw_consumer.read_stdin_bytes(CodePage::Utf8),
            Ok(utf16_bytes)
        );

        let mut text_bytes_io = BufferedIoStreams::with_stdin(format!("line1{LF_CHAR}line2"));
        assert_eq!(
            text_bytes_io.read_stdin_line(),
            Ok(Some("line1".to_owned()))
        );
        assert_eq!(
            text_bytes_io.read_stdin_bytes(CodePage::Utf8),
            Ok(b"line2".to_vec())
        );

        let mut raw_out = BufferedIoStreams::new();
        assert_eq!(raw_out.write_stdout_bytes(b"raw_payload"), Ok(()));
        let (raw_taken, raw_cp) =
            raw_out.into_encoded_pipe_output(OutputUnicodeMode::Ansi, CodePage::Utf8);
        assert_eq!(raw_taken, b"raw_payload");
        assert_eq!(raw_cp, CodePage::Utf8);

        let mut ansi_text = BufferedIoStreams::new();
        assert_eq!(ansi_text.write_stdout_str("ansi_pipe"), Ok(()));
        let (ansi_bytes, ansi_cp) =
            ansi_text.into_encoded_pipe_output(OutputUnicodeMode::Ansi, CodePage::Utf8);
        assert_eq!(ansi_bytes, b"ansi_pipe");
        assert_eq!(ansi_cp, CodePage::Utf8);

        let mut sin_cursor = Cursor::new(format!("typed_val{CR_CHAR}{LF_CHAR}rest").into_bytes());
        let mut sout_vec = Vec::new();
        let mut serr_vec = Vec::new();
        {
            let mut live = StdIoStreams::new(
                &mut sin_cursor,
                &mut sout_vec,
                &mut serr_vec,
                CodePage::Utf8,
                OutputUnicodeMode::Ansi,
            );
            assert_eq!(live.write_stdout_str("Prompt: "), Ok(()));
            assert_eq!(live.write_stdout_bytes(b""), Ok(()));
            assert_eq!(live.write_stdout_bytes(b"[raw]"), Ok(()));
            assert_eq!(live.write_stderr_str("err_live"), Ok(()));
            assert_eq!(live.read_stdin_line(), Ok(Some("typed_val".to_owned())));
            assert_eq!(
                live.read_stdin_to_string(CodePage::Utf8),
                Ok("rest".to_owned())
            );
            assert_eq!(live.read_stdin_line(), Ok(None));
            assert_eq!(live.check_error(), Ok(()));
        }
        assert_eq!(String::from_utf8_lossy(&sout_vec), "Prompt: [raw]");
        assert_eq!(String::from_utf8_lossy(&serr_vec), "err_live");
    }

    /// Verifies `BrokenPipe` suppression and `Other` I/O failure propagation on `StdIoStreams`.
    #[test]
    fn test_stdio_streams_broken_pipe_and_failing_writer_errors() {
        let mut bp_out = MockFailingWriter {
            kind: std::io::ErrorKind::BrokenPipe,
            fail_on_flush: false,
        };
        let mut bp_flush = MockFailingWriter {
            kind: std::io::ErrorKind::BrokenPipe,
            fail_on_flush: true,
        };
        assert_eq!(write_and_flush_gracefully(&mut bp_out, b"x", "out"), Ok(()));
        assert_eq!(flush_stream_gracefully(&mut bp_flush, "out"), Ok(()));

        let mut hard_out = MockFailingWriter {
            kind: std::io::ErrorKind::Other,
            fail_on_flush: false,
        };
        let mut hard_flush = MockFailingWriter {
            kind: std::io::ErrorKind::Other,
            fail_on_flush: true,
        };
        assert!(hard_out.flush().is_ok());
        assert!(write_and_flush_gracefully(&mut hard_out, b"x", "out").is_err());
        assert!(write_and_flush_gracefully(&mut hard_flush, b"x", "out").is_err());
        {
            let mut empty_in = Cursor::new(Vec::new());
            let mut ok_err = Vec::new();
            let mut s1 = StdIoStreams::new(
                &mut empty_in,
                &mut hard_out,
                &mut ok_err,
                CodePage::Utf8,
                OutputUnicodeMode::Ansi,
            );
            assert!(s1.write_stdout_bytes(b"abc").is_err());
        }
        {
            let mut empty_in = Cursor::new(Vec::new());
            let mut ok_out = Vec::new();
            let mut s2 = StdIoStreams::new(
                &mut empty_in,
                &mut ok_out,
                &mut hard_flush,
                CodePage::Utf8,
                OutputUnicodeMode::Ansi,
            );
            assert!(s2.flush_outputs().is_err());
        }
        assert!(flush_stream_gracefully(&mut hard_flush, "out").is_err());
        assert!(
            collect_spawn_outcome(
                "p",
                Err(std::io::Error::other("w")),
                Ok(()),
                Ok(vec![]),
                Ok(vec![])
            )
            .is_err()
        );
        assert!(
            collect_spawn_outcome(
                "p",
                Ok(Some(0)),
                Err(std::io::Error::other("in")),
                Ok(vec![]),
                Ok(vec![])
            )
            .is_err()
        );
        assert!(
            collect_spawn_outcome(
                "p",
                Ok(Some(0)),
                Ok(()),
                Err(std::io::Error::other("out")),
                Ok(vec![])
            )
            .is_err()
        );
        assert!(
            collect_spawn_outcome(
                "p",
                Ok(Some(0)),
                Ok(()),
                Ok(vec![]),
                Err(std::io::Error::other("err"))
            )
            .is_err()
        );

        let mut bad_buf = std::io::BufReader::new(MockFailingReader);
        let mut ok_out = Vec::new();
        let mut ok_err = Vec::new();
        let mut failing_live = StdIoStreams::new(
            &mut bad_buf,
            &mut ok_out,
            &mut ok_err,
            CodePage::Utf8,
            OutputUnicodeMode::Ansi,
        );
        assert!(failing_live.read_stdin_line().is_err());
        assert!(failing_live.read_stdin_bytes(CodePage::Utf8).is_err());
        assert!(failing_live.check_error().is_err());
    }

    /// Verifies `RedirectedIo` passthrough forwarding and capture/override isolation.
    #[test]
    fn test_redirected_io_passthrough_and_capture_modes() {
        let mut parent_buf = BufferedIoStreams::with_stdin(format!("p_line{LF_CHAR}p_tail"));
        {
            let mut pass_redir =
                RedirectedIo::new(&mut parent_buf, None, OutputCaptureMode::PassThrough);
            assert_eq!(pass_redir.write_stdout_str("p_out"), Ok(()));
            assert_eq!(pass_redir.write_stdout_bytes(b"_raw"), Ok(()));
            assert_eq!(pass_redir.write_stderr_str("p_err"), Ok(()));
            assert_eq!(pass_redir.flush_outputs(), Ok(()));
            assert_eq!(pass_redir.read_stdin_line(), Ok(Some("p_line".to_owned())));
            assert_eq!(
                pass_redir.read_stdin_to_string(CodePage::Utf8),
                Ok("p_tail".to_owned())
            );
            assert_eq!(pass_redir.read_stdin_bytes(CodePage::Utf8), Ok(Vec::new()));
        }
        assert_eq!(parent_buf.stdout, "p_out_raw");
        assert_eq!(parent_buf.stderr, "p_err");

        let mut parent_buf2 = BufferedIoStreams::new();
        let mut cap_redir = RedirectedIo::new(
            &mut parent_buf2,
            Some(format!("ov1{LF_CHAR}ov2{LF_CHAR}ov3")),
            OutputCaptureMode::BufferedForSinks,
        );
        assert_eq!(cap_redir.write_stdout_str(""), Ok(()));
        assert_eq!(cap_redir.write_stdout_bytes(b""), Ok(()));
        assert_eq!(cap_redir.write_stderr_str(""), Ok(()));
        assert_eq!(cap_redir.write_stdout_str("c_out"), Ok(()));
        assert_eq!(cap_redir.write_stdout_bytes(&[0xFF, 0x80]), Ok(()));
        assert_eq!(cap_redir.write_stderr_str("c_err"), Ok(()));
        assert_eq!(cap_redir.read_stdin_line(), Ok(Some("ov1".to_owned())));
        assert_eq!(
            cap_redir.read_stdin_to_string(CodePage::Utf8),
            Ok(format!("ov2{LF_CHAR}ov3"))
        );
        assert_eq!(cap_redir.read_stdin_line(), Ok(None));
        cap_redir.stdin_override = Some("bytes_ov".to_owned());
        assert_eq!(
            cap_redir.read_stdin_bytes(CodePage::Utf8),
            Ok(b"bytes_ov".to_vec())
        );
        assert_eq!(
            cap_redir.output_chunks,
            vec![
                CapturedOutputChunk::Text {
                    stream: OutputStreamId::Stdout,
                    text: "c_out".to_owned(),
                },
                CapturedOutputChunk::RawBytes {
                    stream: OutputStreamId::Stdout,
                    bytes: vec![0xFF, 0x80],
                },
                CapturedOutputChunk::Text {
                    stream: OutputStreamId::Stderr,
                    text: "c_err".to_owned(),
                },
            ]
        );
        assert_eq!(parent_buf2.stdout, "");

        let mut mem_reader = InMemoryByteReader::new(b"hello\nworld".to_vec());
        assert_eq!(mem_reader.position(), 0);
        let mut chunk_buf = [0u8; 3];
        assert_eq!(mem_reader.read_chunk(&mut chunk_buf), Ok(3));
        assert_eq!(&chunk_buf, b"hel");
        assert_eq!(mem_reader.position(), 3);
        let mut all_rest = Vec::new();
        assert_eq!(mem_reader.read_all_bytes(&mut all_rest), Ok(8));
        assert_eq!(all_rest, b"lo\nworld");
        assert_eq!(mem_reader.into_remaining(), Vec::<u8>::new());

        let mut mem_writer: InMemoryByteWriter = Vec::new();
        assert_eq!(mem_writer.write_chunk(b"abc"), Ok(3));
        assert_eq!(mem_writer, b"abc");

        let mut raw_std_vec = Vec::new();
        {
            let mut std_w = StdWriteAdapter::new(&mut raw_std_vec, "chunk");
            assert_eq!(std_w.write_chunk(b"xyz"), Ok(3));
        }
        assert_eq!(raw_std_vec, b"xyz");

        let mut fail_chunk_sink = MockFailingWriter {
            kind: std::io::ErrorKind::PermissionDenied,
            fail_on_flush: false,
        };
        let mut std_fail_w = StdWriteAdapter::new(&mut fail_chunk_sink, "chunk_err");
        assert!(std_fail_w.write_chunk(b"x").is_err());
    }
}
