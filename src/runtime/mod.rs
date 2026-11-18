//! Stateful execution engine, encapsulated session sub-components, and pipe subshells.
//!
//! Coordinates multi-pass expansion (Phases 1–4), raw-byte-offset script reading, `CALL` / `GOTO`
//! control flow, `FOR` loops, `IF` conditionals, pipelines (`|`), conditional chains (`&`, `&&`, `||`),
//! execution safety budgets ([`ExecutionLimits`]), and built-in commands.

use alloc::vec::Vec;

pub mod arithmetic;
pub mod dos_exec;
pub mod env;
pub mod io;
pub mod registry;

/// Windows command-line argument parser and executable/batch/HKCR target resolver.
mod argv;
/// AST statement, pipeline, redirection, `FOR`/`IF`, and batch-frame execution engine.
mod exec;
/// Stateful `Interpreter` session struct, safety limits, console state, and tab completion.
mod interpreter;

pub use self::argv::{ResolvedCommandTarget, parse_windows_command_line_argv};
pub use self::dos_exec::{DEFAULT_MIN_CONVENTIONAL_BYTES, DosProcessSpawner};
pub use self::interpreter::{
    BatchCallFrame, ConsoleState, ExecutionLimits, ExecutionState, FlowControl, Interpreter,
    ProcessEnvironment, PushdEntry, SessionConfig,
};
pub use self::io::{
    BufferedIoStreams, ByteStreamBufRead, ByteStreamIo, ByteStreamRead, ByteStreamWrite,
    CapturedOutputChunk, CmdIo, ExternalSpawnRequest, ExternalSpawnResult, InMemoryByteReader,
    InMemoryByteWriter, IoStreams, MockProcessSpawner, OutputCaptureMode, OutputStreamId,
    ProcessSpawner, RedirectedIo, consume_buffered_line, flush_byte_stream_gracefully,
    write_byte_stream_gracefully,
};
#[cfg(feature = "std")]
pub use self::io::{
    HostProcessSpawner, StdBufReadAdapter, StdIoStreams, StdReadAdapter, StdWriteAdapter,
    flush_stream_gracefully, map_child_process_io_error, write_and_flush_gracefully,
    write_child_stdin_bytes,
};

/// Saved active drive and per-drive working directories for restoring VFS state after subshells.
pub(crate) struct VfsCwdSnapshot {
    /// Active drive prior to subshell execution.
    active_drive: crate::types::DriveLetter,
    /// Per-drive working directories prior to subshell execution.
    drive_cwds: Vec<crate::vfs::path::WindowsPath>,
}

/// Captures the active drive and all mounted drive CWDs from `vfs` without cloning file data.
///
/// # Arguments
/// * `vfs` - [`crate::vfs::VirtualFileSystem`] to snapshot.
///
/// # Returns
/// [`VfsCwdSnapshot`] containing active drive and drive CWDs.
pub(crate) fn snapshot_vfs_cwds(vfs: &dyn crate::vfs::VirtualFileSystem) -> VfsCwdSnapshot {
    let active_drive = vfs.current_drive();
    let mut drive_cwds = Vec::new();
    for d in ('A'..='Z').filter_map(|ch| crate::types::DriveLetter::try_from_char(ch).ok()) {
        if let Ok(cwd) = vfs.drive_cwd(d) {
            drive_cwds.push(cwd);
        }
    }
    VfsCwdSnapshot {
        active_drive,
        drive_cwds,
    }
}

/// Restores drive CWDs and the active drive onto `vfs` from a [`VfsCwdSnapshot`].
///
/// # Arguments
/// * `vfs` - Mutable [`crate::vfs::VirtualFileSystem`] to restore.
/// * `snap` - Saved [`VfsCwdSnapshot`].
pub(crate) fn restore_vfs_cwds(vfs: &mut dyn crate::vfs::VirtualFileSystem, snap: &VfsCwdSnapshot) {
    for cwd in &snap.drive_cwds {
        vfs.set_drive_cwd(cwd).unwrap_or(());
    }
    vfs.set_current_drive(snap.active_drive).unwrap_or(());
}

#[cfg(test)]
/// Unit tests for [`Interpreter`] control flow, redirections, pipelines, safety limits, and batch execution.
mod tests {
    use crate::error::{CmdError, ExecutionLimitFailure, LimitKind};
    use crate::runtime::interpreter::EPHEMERAL_RING_CAPACITY;
    use crate::runtime::registry::{
        HKCU_CMD_PROCESSOR_KEY, HKLM_CMD_PROCESSOR_KEY, RegistryHive, RegistryValueType,
    };
    use crate::span::Span;
    use crate::types::{
        AutoRunMode, BS_CHAR, BS_STR, CRLF, CodePage, CompletionScope, ConsoleColor,
        DelayedExpansionMode, DriveLetter, ExitCode, ExtensionsMode, FileCompletionMode, LF_CHAR,
        LabelName, OutputUnicodeMode, TAB_CHAR,
    };
    use crate::vfs::path::WindowsPath;

    use super::*;

    /// Verifies `parse_windows_command_line_argv` `2n` vs `2n+1` backslash-quote rules and `ResolvedCommandTarget`.
    #[test]
    fn test_argv_parsing_and_resolved_command_target() {
        let cmd_tail = format!(
            r#"arg1 "arg two" /sw:"val space"{TAB_CHAR}{BS_CHAR}{BS_CHAR}"quoted{BS_CHAR}"" """" plain{BS_CHAR}{BS_CHAR}tail"#
        );
        assert_eq!(
            parse_windows_command_line_argv(&cmd_tail),
            vec![
                "arg1".to_owned(),
                "arg two".to_owned(),
                "/sw:val space".to_owned(),
                format!(r#"{BS_CHAR}quoted""#),
                r#"""#.to_owned(),
                format!("plain{BS_CHAR}{BS_CHAR}tail"),
            ]
        );
        assert_eq!(
            parse_windows_command_line_argv("   only_one   "),
            vec!["only_one".to_owned()]
        );

        let root_c = WindowsPath::root(DriveLetter::C);
        for target in [
            ResolvedCommandTarget::BatchScript {
                full_path: root_c.clone(),
            },
            ResolvedCommandTarget::ExternalExecutable {
                full_path: root_c.clone(),
                host_path: None,
            },
            ResolvedCommandTarget::AssociatedDocument {
                full_path: root_c.clone(),
                file_type: "txtfile".to_owned(),
                command_template: "notepad.exe %1".to_owned(),
            },
        ] {
            assert_eq!(target.into_full_path(), root_c);
        }
    }

    /// Verifies `ExecutionLimits` (`MaxSteps`, `MaxCallDepth`, `MaxLoopIterations`), `FOR /L` `step == 0`,
    /// bounded `SourceMap` reuse, and `VecDeque` command history eviction.
    #[test]
    fn test_execution_limits_for_l_zero_step_and_bounded_resources() {
        assert_eq!(ExecutionLimits::default(), ExecutionLimits::sandboxed());
        assert_eq!(ExecutionLimits::unlimited().max_steps, None);
        assert_eq!(ExecutionLimits::cli_default().max_steps, None);

        // 1. Infinite GOTO loop hits MaxSteps cleanly
        let mut step_interp = Interpreter::new();
        step_interp.config.limits.max_steps = Some(15);
        assert_eq!(
            step_interp.proc_env.vfs.write_bytes(
                "C:/inf_goto.bat",
                format!(":loop{CRLF}goto :loop{CRLF}").as_bytes()
            ),
            Ok(())
        );
        let mut io = IoStreams::new();
        let goto_res = step_interp.execute_batch_file(
            "C:/inf_goto.bat",
            "inf_goto.bat",
            Vec::new(),
            String::new(),
            &mut io,
        );
        assert!(matches!(
            goto_res,
            Err(CmdError::ExecutionLimitExceeded(ExecutionLimitFailure {
                kind: LimitKind::MaxSteps,
                limit: 15,
                ..
            }))
        ));
        assert_eq!(step_interp.last_exit_code(), ExitCode::FAILURE);

        // Also test REM step limit and IF/FOR step limits via interactive checked execution
        step_interp.config.limits.max_steps = Some(0);
        assert!(matches!(
            step_interp.execute_interactive_line_checked("rem over_budget", &mut io),
            Err(CmdError::ExecutionLimitExceeded(_))
        ));
        assert!(matches!(
            step_interp.execute_interactive_line_checked("if 1==1 echo x", &mut io),
            Err(CmdError::ExecutionLimitExceeded(_))
        ));
        assert!(matches!(
            step_interp.execute_interactive_line_checked("for %I in (a) do echo %I", &mut io),
            Err(CmdError::ExecutionLimitExceeded(_))
        ));

        // 2. Recursive CALL :sub hits MaxCallDepth cleanly
        let mut rec_interp = Interpreter::new();
        rec_interp.config.limits.max_call_depth = Some(6);
        assert_eq!(
            rec_interp.proc_env.vfs.write_bytes(
                "C:/inf_call.bat",
                format!("@echo off{CRLF}:sub{CRLF}call :sub{CRLF}").as_bytes()
            ),
            Ok(())
        );
        let rec_res = rec_interp.execute_batch_file(
            "C:/inf_call.bat",
            "inf_call.bat",
            Vec::new(),
            String::new(),
            &mut io,
        );
        assert!(matches!(
            rec_res,
            Err(CmdError::ExecutionLimitExceeded(ExecutionLimitFailure {
                kind: LimitKind::MaxCallDepth,
                limit: 6,
                ..
            }))
        ));

        // 3. FOR /L step == 0: `(5,0,2)` runs 0 times; `(1,0,5)` hits MaxLoopIterations!
        let mut loop_interp = Interpreter::new();
        loop_interp.config.limits.max_loop_iterations = Some(4);
        io.stdout.clear();
        io.stderr.clear();
        assert_eq!(
            loop_interp.execute_interactive_line("for /L %I in (5,0,2) do echo never", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(io.stdout, "");

        assert_eq!(
            loop_interp.execute_interactive_line("for /L %I in (1,0,5) do echo tick:%I", &mut io),
            ExitCode::FAILURE
        );
        assert_eq!(
            io.stdout,
            format!("tick:1{CRLF}tick:1{CRLF}tick:1{CRLF}tick:1{CRLF}")
        );
        assert_eq!(
            io.stderr,
            format!("Execution aborted: exceeded maximum FOR /L loop iteration budget (4){CRLF}")
        );
    }

    /// Verifies bounded `SourceMap` ephemeral ring reuse and `VecDeque` command history eviction.
    #[test]
    fn test_bounded_source_map_ring_and_history_eviction() {
        let mut ring_interp = Interpreter::new();
        ring_interp.console.set_history_list_size(3);
        for idx in 1..=20 {
            let mut tmp_io = IoStreams::new();
            assert_eq!(
                ring_interp.execute_interactive_line(&format!("echo msg_{idx}"), &mut tmp_io),
                ExitCode::SUCCESS
            );
            assert_eq!(tmp_io.stdout, format!("msg_{idx}{CRLF}"));
        }
        assert!(ring_interp.exec.source_map.len() <= EPHEMERAL_RING_CAPACITY);
        assert_eq!(ring_interp.console.history_list_size(), 3);
        assert_eq!(
            ring_interp
                .console
                .history()
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "echo msg_18".to_owned(),
                "echo msg_19".to_owned(),
                "echo msg_20".to_owned()
            ]
        );
        ring_interp.console.set_history_list_size(1);
        assert_eq!(ring_interp.console.history().len(), 1);
        ring_interp.console.clear_history();
        assert_eq!(ring_interp.console.history().len(), 0);
    }

    /// Verifies compound block redirection errors skip the block body, pipe subshells share VFS
    /// without leaking `CD` or `ENV` mutations, and `/U` UTF-16LE pipes round-trip cleanly.
    #[test]
    fn test_compound_block_redirection_errors_and_pipe_isolation() {
        let mut interp = Interpreter::new();
        let mut io = IoStreams::new();

        // 1. Compound block `< missing.txt` MUST NOT execute block body!
        assert_eq!(
            interp.execute_interactive_line(
                "( set BLOCK_RAN=yes & echo hi ) < C:/no_such_input.txt",
                &mut io
            ),
            ExitCode::FAILURE
        );
        assert_eq!(interp.lookup_var("BLOCK_RAN"), None);
        assert_eq!(io.stdout, "");
        assert_eq!(
            io.stderr,
            format!("The system cannot find the file specified.{CRLF}")
        );

        // 2. Compound block `> C:/missing_dir/out.txt` MUST NOT execute block body!
        io.stderr.clear();
        assert_eq!(
            interp.execute_interactive_line(
                "( set BLOCK_RAN2=yes & echo hi ) > C:/missing_dir/out.txt",
                &mut io
            ),
            ExitCode::FAILURE
        );
        assert_eq!(interp.lookup_var("BLOCK_RAN2"), None);
        assert_eq!(
            io.stderr,
            format!("The system cannot find the path specified.{CRLF}")
        );

        // 3. Pipe shares VFS file creation, isolates `CD` and `SET`, and supports `/S /D /c` `^%VAR^%` + `/U`!
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/sub", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        interp.config.unicode_output_mode = OutputUnicodeMode::Utf16Le;
        io.stdout.clear();
        io.stderr.clear();
        assert_eq!(
            interp.execute_interactive_line(
                r#"(cd C:/sub & set "PIPE_LOCAL=secret_val" & echo ^%PIPE_LOCAL^%& echo vfs_ok > C:/sub/created.txt) | find "secret_val""#,
                &mut io
            ),
            ExitCode::SUCCESS
        );
        assert_eq!(io.stdout, format!("secret_val{CRLF}"));
        assert_eq!(interp.current_cwd_string(), format!("C:{BS_STR}"));
        assert_eq!(interp.lookup_var("PIPE_LOCAL"), None);
        assert!(interp.proc_env.vfs.exists("C:/sub/created.txt"));
        interp.config.unicode_output_mode = OutputUnicodeMode::Ansi;
    }

    /// Verifies `execute_batch_file` error discrimination (`MissingBatchFile` vs `AccessDenied` vs `EncodingFailure`)
    /// and mid-script `CHCP` switching on raw bytes.
    #[test]
    fn test_batch_error_discrimination_and_mid_script_chcp() {
        let mut interp = Interpreter::new();
        let mut io = IoStreams::new();

        // Missing file -> MissingBatchFile
        assert_eq!(
            interp.execute_batch_file(
                "C:/missing.bat",
                "missing.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Err(CmdError::MissingBatchFile {
                path: "C:/missing.bat".to_owned()
            })
        );

        // Directory passed as batch script -> AccessDenied preserved (not erased to MissingBatchFile!)
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/adir.bat", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp.execute_batch_file(
                "C:/adir.bat",
                "adir.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Err(CmdError::AccessDenied {
                path: "C:/adir.bat".to_owned()
            })
        );

        // Invalid UTF-8 under default CP 65001 -> EncodingFailure preserved!
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/bad_utf8.bat", &[0xFF, 0x80, 0x0D, 0x0A]),
            Ok(())
        );
        assert!(matches!(
            interp.execute_batch_file(
                "C:/bad_utf8.bat",
                "bad_utf8.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Err(CmdError::EncodingFailure { .. })
        ));

        // Mid-script CHCP 437: line 1-2 ASCII, line 3 contains raw CP437 byte 0x82 ('é')!
        let mut raw_chcp_script = format!("@echo off{CRLF}chcp 437 >nul{CRLF}echo ").into_bytes();
        raw_chcp_script.extend_from_slice(&[0x82, 0x0D, 0x0A]);
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/mid_chcp.bat", &raw_chcp_script),
            Ok(())
        );
        io.stdout.clear();
        assert_eq!(
            interp.execute_batch_file(
                "C:/mid_chcp.bat",
                "mid_chcp.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Ok(ExitCode::SUCCESS)
        );
        assert_eq!(io.stdout, format!("é{CRLF}"));
    }

    /// Verifies unified `RegistryStore` `Command Processor` (`AutoRun`, `EnableExtensions`,
    /// `DelayedExpansion`, `DefaultColor`), `ASSOC`/`FTYPE` document dispatch, `MockProcessSpawner`,
    /// tab completion, `PROMPT`, `DOSKEY`, and `Ctrl+C` handling.
    #[test]
    fn test_registry_autorun_spawner_completion_prompt_and_ctrl_c() {
        let mut interp = Interpreter::new();
        let mut io = IoStreams::new();

        // 1. Import Wine .reg directly into unified `RegistryStore` and sync processor settings
        let wine_reg = [
            format!("[Software{BS_STR}{BS_STR}Microsoft{BS_STR}{BS_STR}Command Processor]"),
            r#""AutoRun"="set HKLM_INIT=ok""#.to_owned(),
            r#""EnableExtensions"=dword:00000001"#.to_owned(),
            r#""DelayedExpansion"=dword:00000001"#.to_owned(),
            r#""DefaultColor"=dword:0000000a"#.to_owned(),
        ]
        .join(&LF_CHAR.to_string());
        interp
            .proc_env
            .registry_store
            .import_reg_text(&wine_reg, RegistryHive::LocalMachine);
        assert_eq!(
            interp.proc_env.registry_store.set_value(
                HKCU_CMD_PROCESSOR_KEY,
                "AutoRun",
                RegistryValueType::Sz,
                "set HKCU_INIT=ok"
            ),
            Ok(())
        );
        interp.sync_processor_settings_from_registry();
        assert_eq!(
            interp.proc_env.env.delayed_expansion,
            DelayedExpansionMode::Enabled
        );
        assert!(interp.console.console_color.is_some());

        interp.run_autorun_if_enabled(AutoRunMode::Skip, &mut io);
        assert_eq!(interp.lookup_var("HKLM_INIT"), None);
        interp.run_autorun_if_enabled(AutoRunMode::Run, &mut io);
        assert_eq!(interp.lookup_var("HKLM_INIT"), Some("ok".to_owned()));
        assert_eq!(interp.lookup_var("HKCU_INIT"), Some("ok".to_owned()));

        // Early `EXIT` inside HKLM AutoRun skips HKCU AutoRun
        assert_eq!(
            interp.proc_env.registry_store.set_value(
                HKLM_CMD_PROCESSOR_KEY,
                "AutoRun",
                RegistryValueType::Sz,
                "exit 5"
            ),
            Ok(())
        );
        interp.run_autorun_if_enabled(AutoRunMode::Run, &mut io);
        assert_eq!(interp.exec.exited(), Some(ExitCode::new(5)));
        interp.exec.clear_exited();
    }

    /// Verifies `MockProcessSpawner` and `HKCR` `ASSOC`/`FTYPE` associated document resolution.
    #[test]
    fn test_mock_spawner_and_assoc_ftype_document_dispatch() {
        let mut interp = Interpreter::new();
        let mut io = IoStreams::new();

        // 2. MockProcessSpawner + Registry HKCR ASSOC/FTYPE document resolution
        let mut mock = MockProcessSpawner::new();
        mock.register_binary(
            "mytool.exe",
            ExitCode::SUCCESS,
            "OUT:$ARGS|$STDIN",
            "ERR_MSG",
        );
        let cloned_spawner = mock.clone_box();
        assert_eq!(format!("{cloned_spawner:?}"), format!("{mock:?}"));
        interp.proc_env.spawner = Box::new(mock);

        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/mytool.exe", b"MZ"),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/unregistered.com", b"MZ"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/script.py", b"print(1)"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/orphan.unassoc", b"raw"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/no_ext_bin", b"ELF"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.registry_store.set_value(
                "HKCR/.py",
                "",
                RegistryValueType::Sz,
                "Python.File"
            ),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.registry_store.set_value(
                "HKCR/.unassoc",
                "",
                RegistryValueType::Sz,
                "Missing.Type"
            ),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.registry_store.set_value(
                "HKCR/Python.File/shell/open/command",
                "",
                RegistryValueType::Sz,
                "echo PY_RUN:%1:%*"
            ),
            Ok(())
        );

        io.stdin = "from_stdin".to_owned();
        io.stdout.clear();
        io.stderr.clear();
        assert_eq!(
            interp.execute_interactive_line("mytool arg1 arg2", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(io.stdout, "OUT:arg1 arg2|from_stdin");
        assert_eq!(io.stderr, "ERR_MSG");
    }

    /// Verifies `ASSOC`/`FTYPE` document dispatch and `NoDefaultCurrentDirectoryInExePath` resolution.
    #[test]
    fn test_assoc_ftype_document_dispatch_and_no_default_cwd_exe_path() {
        let mut interp = Interpreter::new();
        interp.proc_env.spawner = Box::new(MockProcessSpawner::new());
        let mut io = IoStreams::new();
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/mytool.exe", b"MZ"),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/unregistered.com", b"MZ"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/script.py", b"#py"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/orphan.unassoc", b"x"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/no_ext_bin", b"x"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.registry_store.set_value(
                "HKCR/.py",
                "",
                RegistryValueType::Sz,
                "Python.File"
            ),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.registry_store.set_value(
                "HKCR/.unassoc",
                "",
                RegistryValueType::Sz,
                "Missing.Type"
            ),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.registry_store.set_value(
                "HKCR/Python.File/shell/open/command",
                "",
                RegistryValueType::Sz,
                "echo PY_RUN:%1:%*"
            ),
            Ok(())
        );

        assert_eq!(
            interp.execute_interactive_line("C:/unregistered.com", &mut io),
            ExitCode::FAILURE
        );
        interp.proc_env.spawner = Box::new(HostProcessSpawner);
        assert_eq!(
            interp.execute_interactive_line("C:/unregistered.com", &mut io),
            ExitCode::FAILURE
        );
        interp.record_success();
        io.stdout.clear();
        assert_eq!(
            interp.execute_interactive_line("script.py --flag", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            io.stdout,
            format!("PY_RUN:C:{BS_STR}script.py:--flag{CRLF}")
        );
        assert_eq!(
            interp.execute_interactive_line("orphan.unassoc", &mut io),
            ExitCode::FAILURE
        );
        assert_eq!(
            interp.execute_interactive_line("no_ext_bin", &mut io),
            ExitCode::FAILURE
        );

        interp
            .proc_env
            .env
            .set("NoDefaultCurrentDirectoryInExePath", "1");
        assert_eq!(interp.resolve_external_or_batch_target("mytool"), None);
        interp
            .proc_env
            .env
            .remove("NoDefaultCurrentDirectoryInExePath");
    }

    /// Verifies tab completion, `PROMPT` escape formatting, `DOSKEY` macro expansion, and `Ctrl+C` interrupts.
    #[test]
    fn test_completion_prompt_doskey_and_ctrl_c_interrupts() {
        let mut interp = Interpreter::new();
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/mytool.exe", b"MZ"),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.create_dir(
                "C:/comp/Sub Dir",
                crate::types::DirCreationDepth::CreateParents
            ),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/comp/simple.txt", b"1"),
            Ok(())
        );
        interp.config.file_completion = FileCompletionMode::Disabled;
        assert_eq!(
            interp.complete_line_at_cursor("cd C:/comp/s", CompletionScope::FilesAndDirectories, 0),
            "cd C:/comp/s"
        );
        interp.config.file_completion = FileCompletionMode::Enabled;
        assert_eq!(
            interp.complete_line_at_cursor("cd C:/comp/s", CompletionScope::FilesAndDirectories, 0),
            "cd C:/comp/simple.txt"
        );
        assert_eq!(
            interp.complete_line_at_cursor("cd C:/comp/s", CompletionScope::DirectoriesOnly, 0),
            r#"cd "C:/comp/Sub Dir""#
        );
        assert_eq!(
            interp.complete_line_at_cursor("my", CompletionScope::FilesAndDirectories, 0),
            "mytool.exe"
        );
        assert_eq!(
            interp.complete_line_at_cursor(
                "cd C:/no_such/x",
                CompletionScope::FilesAndDirectories,
                0
            ),
            "cd C:/no_such/x"
        );
        assert_eq!(
            interp.complete_line_at_cursor(
                "cd C:/comp/zzz",
                CompletionScope::FilesAndDirectories,
                0
            ),
            "cd C:/comp/zzz"
        );
    }

    /// Verifies `PROMPT` escape formatting, `DOSKEY` macro expansion, and `Ctrl+C` batch interrupts.
    #[test]
    fn test_prompt_doskey_macros_and_ctrl_c_interrupts() {
        let mut interp = Interpreter::new();
        let mut io = IoStreams::new();
        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/comp", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp.execute_interactive_line("pushd C:/comp", &mut io),
            ExitCode::SUCCESS
        );
        interp
            .proc_env
            .env
            .set("PROMPT", "Literal$A$B$C$D$E$F$G$H$L$N$P$Q$S$T$V$_$$$+$M$Z$");
        let rendered = interp.format_prompt();
        assert!(rendered.starts_with("Literal&|("));
        assert!(rendered.ends_with("+$Z$"));

        interp.console.doskey_macros.insert(
            "mtest".to_owned(),
            r#"echo $1 $9 $* $T echo "$G $L $B $$ $Z $""#.to_owned(),
        );
        io.stdout.clear();
        assert_eq!(
            interp.execute_interactive_line("mtest alpha", &mut io),
            ExitCode::SUCCESS
        );
        assert!(io.stdout.contains("alpha  alpha"));
        assert!(io.stdout.contains("> < | $ $Z $"));

        assert_eq!(
            interp.handle_ctrl_c_interrupt(&mut io),
            FlowControl::Continue
        );
        assert_eq!(interp.last_exit_code(), ExitCode::CTRL_C);
        interp.record_success();

        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/ctrlc.bat",
                format!("@echo off{CRLF}echo ran_ok{CRLF}").as_bytes()
            ),
            Ok(())
        );
        interp.trigger_ctrl_c();
        io.stdin = format!("N{CRLF}");
        io.stdout.clear();
        assert_eq!(
            interp.execute_batch_file(
                "C:/ctrlc.bat",
                "ctrlc.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Ok(ExitCode::SUCCESS)
        );
        assert!(io.stdout.contains("ran_ok"));

        interp.trigger_ctrl_c();
        io.stdin = format!("Y{CRLF}");
        assert_eq!(
            interp.execute_batch_file(
                "C:/ctrlc.bat",
                "ctrlc.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Ok(ExitCode::CTRL_C)
        );
        interp.exec.clear_exited();

        let host_interp = Interpreter::new_host_native();
        assert_eq!(host_interp.last_exit_code(), ExitCode::SUCCESS);
    }

    /// Verifies batch control flow (`IF`, `FOR`, `FOR /D`, `FOR /R`, `FOR /L`, `FOR /F`,
    /// `GOTO`, `&&`, `||`, redirections, self-modifying/self-deleting batch files).
    #[test]
    fn test_batch_control_flow_for_variants_redirections_and_self_modification() {
        let mut interp = Interpreter::new();
        let mut io = IoStreams::new();

        assert_eq!(
            interp
                .proc_env
                .vfs
                .create_dir("C:/sub", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/data.txt",
                format!(";comment{CRLF}   {CRLF}alpha beta gamma{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            interp.call_subroutine_label(
                &LabelName::new("sub"),
                Vec::new(),
                String::new(),
                Span::dummy(),
                &mut io
            ),
            Err(CmdError::BatchLabelNotFound {
                span: Span::dummy(),
                label: LabelName::new("sub"),
            })
        );

        let complex_bat = [
            "echo off",
            "REM hidden comment",
            "echo on",
            "@REM suppressed comment while echo on",
            "REM visible comment",
            "call :nonexistent_sub",
            "echo",
            "echo bare_msg",
            "if not errorlevel 999 echo cond_err_ok",
            "if exist C:/data.txt echo cond_exist_ok",
            "if defined PATH echo cond_def_ok",
            "if cmdextversion 1 echo cond_ext_ok",
            "if 1 == 2 (echo no) else echo cond_else_ok",
            "if 1 == 2 echo cond_none",
            "for %%F in (C:/*.txt literal) do echo std:%%F",
            "for /D %%D in (C:/*) do echo dir:%%D",
            "for /R %%R in (.) do echo rec_dot:%%R",
            "goto :after_lhs_and && echo never",
            ":after_lhs_and",
            "goto :after_lhs_or || echo never",
            ":after_lhs_or",
            "for /R C:/ %%R in (*.txt) do echo rec_glob:%%R",
            "for /R C:/sub %%R in (fixed.txt) do echo rec_fix:%%R",
            "for /L %%N in (2,-1,1) do echo down:%%N",
            "for /L %%M in (2147483646,1,2147483647) do echo max:%%M",
            r#"for /F "tokens=*" %%A in (C:/data.txt) do echo file_star:%%A"#,
            r#"for /F "delims=" %%A in ('echo from_single_quote') do echo sq:%%A"#,
            r#"for /F "usebackq tokens=1-2,5*" %%A in ('one  two  three') do echo uq:%%A-%%B-%%C-%%D"#,
            r#"for /F "tokens=1*" %%A in ("only_one") do echo rem_empty:%%A-%%B"#,
            "(echo blk1 & goto :after_blk & echo skipped) > C:/blk_out.txt",
            ":after_blk",
            "for %%I in (a) do goto :after_for1",
            ":after_for1",
            "for /D %%D in (C:/*) do goto :after_for2",
            ":after_for2",
            "for /R C:/ %%R in (.) do goto :after_for3",
            ":after_for3",
            "for /R C:/ %%R in (*.txt) do goto :after_for4",
            ":after_for4",
            "for /R C:/ %%R in (fixed.txt) do goto :after_for5",
            ":after_for5",
            "for /L %%N in (1,1,2) do goto :after_for6",
            ":after_for6",
            r#"for /F "skip=1" %%A in ("line0") do echo skipped_all"#,
            "for /F %%A in (C:/data.txt) do goto :after_for7",
            ":after_for7",
            "for /F %%A in (C:/missing_forf.txt) do echo never",
            "ver && goto :after_and",
            ":after_and",
            "color AA || goto :after_or",
            ":after_or",
            "color AA 2>&1",
            "echo < C:/data.txt > C:/redir_out.txt",
            "echo x < CON 0<&3 > CON >> CON 1>&4",
            "echo err_msg 1>&2 2> C:/err_trunc.txt",
            "echo err_msg2 1>&2 2>> C:/err_app.txt",
            "ver && echo and_ok || echo or_skip",
            "color AA || echo or_ok && echo and_ok2",
            "color AA && echo and_skip",
            "echo < C:/missing_input.txt",
            "echo hi > C:/sub",
            "goto :nonexistent_label",
        ]
        .join(CRLF);

        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/complex.bat", complex_bat.as_bytes()),
            Ok(())
        );
        assert_eq!(
            interp.execute_batch_file(
                "C:/complex.bat",
                "complex.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Ok(ExitCode::FAILURE)
        );
        assert!(io.stdout.contains("cond_else_ok"));
        assert!(io.stdout.contains("sq:from_single_quote"));
        assert!(io.stdout.contains("max:2147483647"));
        assert!(
            io.stderr
                .contains("The system cannot find the batch label specified")
        );
    }

    /// Verifies self-deleting, self-modifying, `:EOF` with extensions disabled, and `EXIT` batch scripts.
    #[test]
    fn test_self_modifying_self_deleting_and_eof_batch_scripts() {
        let mut interp = Interpreter::new();
        let mut io = IoStreams::new();
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/self_del.bat",
                format!("del C:{BS_STR}self_del.bat{CRLF}echo after{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            interp.execute_batch_file(
                "C:/self_del.bat",
                "self_del.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Ok(ExitCode::FAILURE)
        );
        assert!(io.stderr.contains("The batch file cannot be found."));

        io.stderr.clear();
        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/self_del_last.bat",
                format!("del C:{BS_STR}self_del_last.bat{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            interp.execute_batch_file(
                "C:/self_del_last.bat",
                "self_del_last.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Ok(ExitCode::SUCCESS)
        );
        assert_eq!(io.stderr, "");

        let self_mod = [
            "@echo off",
            "echo :dyn_label >> C:/self_mod.bat",
            "echo echo from_dyn_label >> C:/self_mod.bat",
            "goto :dyn_label",
            "",
        ]
        .join(CRLF);
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/self_mod.bat", self_mod.as_bytes()),
            Ok(())
        );
        io.stdout.clear();
        assert_eq!(
            interp.execute_batch_file(
                "C:/self_mod.bat",
                "self_mod.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Ok(ExitCode::SUCCESS)
        );
        assert_eq!(io.stdout, format!("from_dyn_label {CRLF}"));
    }

    /// Verifies interactive/batch parse errors, `GOTO :EOF` with extensions disabled, and batch `EXIT`.
    #[test]
    fn test_batch_parse_errors_goto_eof_disabled_and_process_exit() {
        let mut interp = Interpreter::new();
        let mut io = IoStreams::new();
        // Parse error in interactive line & Phase 1 error in batch
        io.stderr.clear();
        assert_eq!(
            interp.execute_interactive_line("| echo a", &mut io),
            ExitCode::FAILURE
        );
        assert_eq!(io.stderr, format!("| was unexpected at this time.{CRLF}"));

        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/err1.bat",
                format!("@echo off{CRLF}echo %~dpBAD%{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            interp.execute_batch_file(
                "C:/err1.bat",
                "err1.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Ok(ExitCode::FAILURE)
        );

        // GOTO :EOF with extensions disabled fails label lookup
        interp.proc_env.env.extensions = ExtensionsMode::Disabled;
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/eof_off.bat", format!("goto :EOF{CRLF}").as_bytes()),
            Ok(())
        );
        assert_eq!(
            interp.execute_batch_file(
                "C:/eof_off.bat",
                "eof_off.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Ok(ExitCode::FAILURE)
        );
        interp.proc_env.env.extensions = ExtensionsMode::Enabled;

        assert_eq!(
            interp.proc_env.vfs.write_bytes(
                "C:/exit7.bat",
                format!("@echo off{CRLF}setlocal{CRLF}exit 7{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            interp.execute_batch_file(
                "C:/exit7.bat",
                "exit7.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Ok(ExitCode::new(7))
        );
        assert_eq!(interp.exec.exited(), Some(ExitCode::new(7)));
    }

    /// Exercises pipeline stderr/abort paths, unlimited call/loop bounds, read-only redirection
    /// flush errors, recursive batch `CALL` source allocation, `GOTO :EOF`, and `FOR /F` edge cases.
    #[test]
    fn test_runtime_pipeline_limits_for_f_and_redirection_edges() {
        let mut interp = Interpreter::new();
        let mut io = IoStreams::new();

        interp.console.record_history("");
        interp.console.set_history_list_size(0);
        interp.console.record_history("ignored");
        assert_eq!(interp.exec.for_vars().len(), 0);
        let mut sbuf = format!("first{CRLF}second");
        assert_eq!(Interpreter::consume_stdin_line(&mut sbuf), "first");
        interp.console.console_color = ConsoleColor::parse_hex("0A").ok();
        interp.sync_processor_settings_from_registry();
        assert_eq!(
            interp.console.console_color,
            ConsoleColor::parse_hex("0A").ok()
        );

        interp.config.limits = ExecutionLimits::unlimited();
        interp.proc_env.env.remove("PATH");
        assert_eq!(interp.resolve_external_or_batch_target("no_such_bin"), None);
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/plain.unassoc", b"x"),
            Ok(())
        );
        assert!(matches!(
            interp.resolve_external_or_batch_target("C:/plain.unassoc"),
            Some(ResolvedCommandTarget::ExternalExecutable { .. })
        ));
        assert_eq!(
            interp.execute_interactive_line("doskey trail=echo end$", &mut io),
            ExitCode::SUCCESS
        );
        io.stdout.clear();
        assert_eq!(
            interp.execute_interactive_line("trail", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(io.stdout, format!("end${CRLF}"));
        assert_eq!(
            interp.execute_interactive_line(r#"for /L %I in ("",1,1,2) do @echo %I"#, &mut io),
            ExitCode::SUCCESS
        );

        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/ro.txt", b"locked"),
            Ok(())
        );
        assert_eq!(
            interp.execute_interactive_line("attrib +r C:/ro.txt", &mut io),
            ExitCode::SUCCESS
        );
        io.stderr.clear();
        assert_eq!(
            interp.execute_interactive_line("echo a > C:/ro.txt", &mut io),
            ExitCode::FAILURE
        );
        assert_eq!(io.stderr, format!("Access is denied.{CRLF}"));
        io.stderr.clear();
        assert_eq!(
            interp.execute_interactive_line("echo a >> C:/ro.txt", &mut io),
            ExitCode::FAILURE
        );
        assert_eq!(io.stderr, format!("Access is denied.{CRLF}"));
        io.stderr.clear();
        assert_eq!(
            interp.execute_interactive_line(
                r#"cmd /c "attrib +r C:/late1.txt & echo x" > C:/late1.txt"#,
                &mut io
            ),
            ExitCode::FAILURE
        );
        assert_eq!(io.stderr, format!("Access is denied.{CRLF}"));
        io.stderr.clear();
        assert_eq!(
            interp.execute_interactive_line(
                "(attrib +r C:/late2.txt & echo x) > C:/late2.txt",
                &mut io
            ),
            ExitCode::FAILURE
        );
        assert_eq!(io.stderr, format!("Access is denied.{CRLF}"));

        // Pipeline left/right stderr, empty right stdout, and left/right ExecutionLimitExceeded abort
        assert_eq!(
            interp.execute_interactive_line("bad_left_cmd | ver", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.execute_interactive_line("echo ok_l | cd .", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.execute_interactive_line("echo ok_l | bad_right_cmd", &mut io),
            ExitCode::new(9009)
        );
    }

    /// Exercises `ExecutionLimitExceeded` pipeline/subshell aborts, `FOR /F` edge cases, and recursive `CALL`.
    #[test]
    fn test_runtime_limits_for_f_and_recursive_batch_edges() {
        let mut interp = Interpreter::new();
        let mut io = IoStreams::new();
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/ro.txt", b"locked"),
            Ok(())
        );

        interp.config.limits.max_loop_iterations = Some(2);
        assert!(
            interp
                .execute_interactive_line_checked(
                    "for /L %N in (1,1,10) do @echo %N | echo r",
                    &mut io
                )
                .is_err()
        );
        assert!(
            interp
                .execute_interactive_line_checked(
                    "(for /L %N in (1,1,10) do @echo %N) | echo r",
                    &mut io
                )
                .is_err()
        );
        assert!(
            interp
                .execute_interactive_line_checked(
                    "echo l | (for /L %N in (1,1,10) do @echo %N)",
                    &mut io
                )
                .is_err()
        );
        assert!(
            interp
                .execute_interactive_line_checked(
                    "for /F %A in ('for /L %N in ^(1^,1^,10^) do @echo %N') do @echo %A",
                    &mut io
                )
                .is_err()
        );
        interp.config.limits = ExecutionLimits::unlimited();
        assert_eq!(
            interp.execute_interactive_line("ver", &mut io),
            ExitCode::SUCCESS
        );
    }

    /// Exercises `FOR /F` invalid-encoding/token edge cases and recursive `CALL` batch execution.
    #[test]
    fn test_for_f_encoding_edges_and_recursive_batch_call() {
        let mut interp = Interpreter::new();
        interp.config.limits = ExecutionLimits::unlimited();
        let mut io = IoStreams::new();
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/ro.txt", b"locked"),
            Ok(())
        );

        // FOR /F trailing delimiter + tokens=1,* + invalid UTF-8 file + Phase 3 $PATH lookup
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/bad.bin", &[0xFF, 0xFE, 0xFF]),
            Ok(())
        );
        interp.console.codepage = CodePage::Utf8;
        assert_eq!(
            interp.execute_interactive_line(
                r#"for /F "tokens=1,*" %A in ("k1 rest ") do @echo %A-%B"#,
                &mut io
            ),
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.execute_interactive_line("for /F %A in (C:/bad.bin) do @echo %A", &mut io),
            ExitCode::FAILURE
        );
        interp.proc_env.env.set("MYP", "C:/");
        assert_eq!(
            interp.execute_interactive_line("ver", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.execute_interactive_line("for %I in (ro.txt) do @echo %~$MYP:I", &mut io),
            ExitCode::SUCCESS
        );

        // Recursive batch CALL (`active_on_stack` == true & non-empty call_stack) + GOTO :EOF + mid-file deletion
        let rec_bat =
            format!("@echo off{CRLF}if \"%1\"==\"done\" goto :EOF{CRLF}call C:/rec.bat done{CRLF}");
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/rec.bat", rec_bat.as_bytes()),
            Ok(())
        );
        assert_eq!(
            interp.execute_batch_file(r"C:\rec.bat", "rec.bat", Vec::new(), String::new(), &mut io),
            Ok(ExitCode::SUCCESS)
        );
        let vanish_bat = format!("del C:\\vanish.bat{CRLF}echo second_line{CRLF}");
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/vanish.bat", vanish_bat.as_bytes()),
            Ok(())
        );
        assert_eq!(
            interp.execute_batch_file(
                "C:/vanish.bat",
                "vanish.bat",
                Vec::new(),
                String::new(),
                &mut io
            ),
            Ok(ExitCode::FAILURE)
        );
    }

    /// Verifies compound-block `<` input redirection, handle-3-only redirection, silent `>` redirection,
    /// and raw binary `TYPE` redirection to `ConsoleStdout`, `ConsoleStderr`, and read-only `File`.
    #[test]
    fn test_compound_block_input_and_raw_binary_redirections() {
        let mut interp = Interpreter::new();
        let mut io = IoStreams::new();
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/blk_in.txt", format!("from_blk_stdin{CRLF}").as_bytes()),
            Ok(())
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/raw.bin", &[0x41, 0xFF, 0x42]),
            Ok(())
        );
        assert_eq!(
            interp.proc_env.vfs.write_bytes("C:/ro.txt", b"locked"),
            Ok(())
        );
        let mut ro_attr = crate::vfs::FileAttributeFlags::default_file();
        ro_attr.insert(crate::vfs::FileAttributeFlags::READ_ONLY);
        assert_eq!(
            interp.proc_env.vfs.set_attributes("C:/ro.txt", ro_attr),
            Ok(())
        );

        assert_eq!(
            interp.execute_interactive_line("(set /p BLK_V=) < C:/blk_in.txt", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.lookup_var("BLK_V").as_deref(),
            Some("from_blk_stdin")
        );
        assert_eq!(
            interp.execute_interactive_line("(set SILENT_BLK=1) 3> C:/h3_empty.txt", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.execute_interactive_line("set SILENT_REDIR=1 > C:/silent_out.txt", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.execute_interactive_line("(copy /b C:/raw.bin CON) 2> NUL", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.execute_interactive_line("(copy /b C:/raw.bin CON 1>&2) 3> NUL", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/out_append.bin", b"init"),
            Ok(())
        );
        assert_eq!(
            interp.execute_interactive_line(
                r"(attrib +r C:\out_append.bin & copy /b C:/raw.bin CON) >> C:/out_append.bin",
                &mut io,
            ),
            ExitCode::FAILURE
        );
        assert_eq!(
            interp.execute_interactive_line("(copy /b C:/raw.bin CON) > C:/ro.txt", &mut io),
            ExitCode::FAILURE
        );
    }

    /// Verifies `DosProcessSpawner` PSP tail modes, `%TEMP%` spooling & cleanup, env/memory limits, and error paths.
    #[test]
    fn test_dos_process_spawner_psp_cmdline_rsp_and_spool_cleanup() {
        use crate::dos::{
            DosKernelApi, DosWriteDisposition, LongCmdlineTransfer, SharedDosKernel,
            SimChildProgram, SimulatedDosKernel,
        };
        use crate::types::{
            NativeBackingPath, ProcessPriority, StartEnvMode, StartWindowMode, WaitMode,
        };
        use crate::vfs::path::WindowsPath;

        let shared = SharedDosKernel::new(SimulatedDosKernel::new());
        shared.with_mut(|k| {
            assert_eq!(k.create_dir("C:/TEMP"), Ok(()));
            assert_eq!(
                k.write_file_bytes("C:/NOTDIR.TMP", b"x", DosWriteDisposition::CreateTruncate),
                Ok(())
            );
            k.register_child_program(
                "C:\\ECHO.COM",
                SimChildProgram::EchoPspAndCmdline {
                    exit_code: ExitCode::SUCCESS,
                },
            );
        });

        let mut spawner = DosProcessSpawner::new(shared.clone());
        assert_eq!(spawner.kernel().current_drive(), DriveLetter::C);
        assert_eq!(spawner.kernel_mut().current_drive(), DriveLetter::C);
        let _cloned = spawner.clone_box();

        let mut req = ExternalSpawnRequest {
            program_vfs_path: WindowsPath::root(DriveLetter::C).join_component("ECHO.COM"),
            program_host_path: None,
            args: vec!["argA".to_owned(), "argB".to_owned()],
            raw_tail: String::new(),
            cwd_vfs: WindowsPath::root(DriveLetter::C),
            cwd_host: None,
            env_vars: vec![
                ("WINCMD_PIPE_DIR".to_owned(), "   ".to_owned()),
                ("TEMP".to_owned(), "C:/NOTDIR.TMP".to_owned()),
                ("TMP".to_owned(), "C:/TEMP".to_owned()),
                ("CMDLINE".to_owned(), "stale".to_owned()),
            ],
            stdin: "text_in".to_owned(),
            stdin_bytes: Vec::new(),
            wait_mode: WaitMode::Wait,
            window_mode: StartWindowMode::Normal,
            env_mode: StartEnvMode::CurrentEnv,
            priority: ProcessPriority::Normal,
        };

        let short_res = spawner.spawn_external(&req);
        assert_eq!(
            short_res.map(|r| r.stdout),
            Ok(format!("PSP= argA argB{CRLF}CMDLINE={CRLF}"))
        );
        assert_eq!(
            shared.with(|k| k.read_dir_entries("C:/TEMP").map(|v| v.len())),
            Ok(0)
        );

        req.program_host_path = Some(NativeBackingPath::from_string("C:\\ECHO.COM"));
        req.cwd_host = Some(NativeBackingPath::from_string("C:\\"));
        req.env_vars = Vec::new();
        req.raw_tail = "x".repeat(135);
        req.stdin = String::new();
        req.stdin_bytes = b"bin".to_vec();

        let cmdline_res = spawner.spawn_external(&req);
        assert!(cmdline_res.is_ok_and(|r| r.stdout.contains("CMDLINE=C:\\ECHO.COM ")));

        spawner.cmdline_policy = LongCmdlineTransfer::ResponseFileAtSign;
        req.stdin_bytes.clear();
        let rsp_res = spawner.spawn_external(&req);
        assert!(rsp_res.is_ok_and(|r| r.stdout.contains("PSP= @C:\\_WCR")));
        req.raw_tail = "short".to_owned();
        assert!(spawner.spawn_external(&req).is_ok());
        req.raw_tail = "x".repeat(135);

        spawner.cmdline_policy = LongCmdlineTransfer::Strict126BytePsp;
        assert!(matches!(
            spawner.spawn_external(&req),
            Err(CmdError::CommandLineTooLong { .. })
        ));

        run_dos_spawner_fault_and_limit_checks(&mut spawner, &mut req, &shared);
    }

    /// Exercises `DosProcessSpawner` environment, conventional RAM, and spool-cleanup fault paths.
    ///
    /// # Arguments
    /// * `spawner` - Mutable [`DosProcessSpawner`].
    /// * `req` - Mutable [`ExternalSpawnRequest`].
    /// * `shared` - Shared [`crate::dos::SimulatedDosKernel`] handle.
    fn run_dos_spawner_fault_and_limit_checks(
        spawner: &mut DosProcessSpawner<
            crate::dos::SharedDosKernel<crate::dos::SimulatedDosKernel>,
        >,
        req: &mut ExternalSpawnRequest,
        shared: &crate::dos::SharedDosKernel<crate::dos::SimulatedDosKernel>,
    ) {
        use crate::dos::{
            DosEnvSizeLimit, DosFaultOp, DosFaultRule, LongCmdlineTransfer, PipeSpoolCleanupPolicy,
        };
        use crate::types::DosErrorCode;

        spawner.cmdline_policy = LongCmdlineTransfer::CmdlineEnvVar;
        spawner.env_limit = DosEnvSizeLimit::CommandComBytes(16);
        assert_eq!(
            spawner.spawn_external(req),
            Err(CmdError::OutOfEnvironmentSpace)
        );
        spawner.env_limit = DosEnvSizeLimit::Dpmi32KiB;

        spawner.min_conventional_bytes = 900_000;
        assert_eq!(
            spawner.spawn_external(req),
            Err(CmdError::InsufficientMemory)
        );
        spawner.min_conventional_bytes = DEFAULT_MIN_CONVENTIONAL_BYTES;

        req.raw_tail = "ok".to_owned();
        shared.with_mut(|k| {
            k.push_fault(DosFaultRule {
                op: DosFaultOp::DeleteFile,
                path_substr: Some("_WCO".to_owned()),
                error_code: DosErrorCode::FileNotFound,
            });
        });
        assert!(spawner.spawn_external(req).is_ok());
        shared.with_mut(|k| {
            k.fault_queue.clear();
            for _ in 0..2 {
                k.push_fault(DosFaultRule {
                    op: DosFaultOp::DeleteFile,
                    path_substr: None,
                    error_code: DosErrorCode::AccessDenied,
                });
            }
        });
        assert!(spawner.spawn_external(req).is_err());
        spawner.cleanup_policy = PipeSpoolCleanupPolicy::BestEffort;
        assert!(spawner.spawn_external(req).is_ok());
    }

    /// Verifies `Interpreter::with_dos_kernel`, sequential `%TEMP%` pipelines, `START`, `Ctrl+Break`, and `MemoryProfile`s.
    #[test]
    fn test_dos_interpreter_pipelines_start_ctrl_break_and_memory_profiles() {
        use crate::dos::{DosKernelApi, DosWriteDisposition, SimChildProgram, SimulatedDosKernel};
        use crate::types::{InterruptState, MemoryProfile};

        let mut kernel = SimulatedDosKernel::new();
        assert_eq!(kernel.create_dir("C:/DOS"), Ok(()));
        assert_eq!(kernel.create_dir("C:/TEMP"), Ok(()));
        assert_eq!(
            kernel.write_file_bytes(
                "C:/DOS/UPPER.COM",
                b"MZ",
                DosWriteDisposition::CreateTruncate
            ),
            Ok(())
        );
        kernel.register_child_program(
            "C:\\DOS\\UPPER.COM",
            SimChildProgram::UppercaseFilter {
                exit_code: ExitCode::SUCCESS,
            },
        );

        let (mut interp, shared) = Interpreter::with_dos_kernel(kernel);
        for prof in [
            MemoryProfile::DosCompact4MiB,
            MemoryProfile::DosExtended16MiBPlus,
            MemoryProfile::HostUnbounded,
            MemoryProfile::DosStandard8MiB,
        ] {
            interp.apply_memory_profile(prof);
            assert_eq!(interp.config.memory_profile, prof);
        }

        let mut io = BufferedIoStreams::new();
        assert_eq!(
            interp.execute_interactive_line("echo dos pipe | upper | sort", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(io.stdout, format!("DOS PIPE {CRLF}"));

        io.stdout.clear();
        assert_eq!(
            interp.execute_interactive_line("start /b upper < NUL", &mut io),
            ExitCode::SUCCESS
        );

        shared.with_mut(|k| k.ctrl_break = InterruptState::Pending);
        io.stdout.clear();
        assert_eq!(
            interp.execute_interactive_line("echo left | echo right", &mut io),
            ExitCode::CTRL_C
        );
        assert_eq!(io.stdout, "");

        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/LOOP.BAT", b"@echo one\r\n@echo two\r\n"),
            Ok(())
        );
        shared.with_mut(|k| k.ctrl_break = InterruptState::Pending);
        let mut batch_io = BufferedIoStreams::with_stdin("Y\r\n".to_owned());
        let _code = interp.execute_interactive_line("C:\\LOOP.BAT", &mut batch_io);
        assert!(batch_io.stdout.contains("Terminate batch job (Y/N)? "));
    }
}
