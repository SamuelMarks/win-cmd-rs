//! Command-line argument parsing, streaming REPL, and process drivers for `wincmd` and `wincheck`.
//!
//! Supports full `cmd.exe` flags (`/C`, `/K`, `/S`, `/Q`, `/D`, `/A`, `/U`, `/T:fg`, `/E:ON`,
//! `/E:OFF`, `/F:ON`, `/F:OFF`, `/V:ON`, `/V:OFF`, `/?`) including the authentic `/C` and `/K`
//! quote-stripping heuristic, lexer-aware `More? ` REPL continuation, `HostNative` VFS wiring,
//! `"-"` stdin linting, unified `CstRewriter` `--diff` / `--fix` handling, and graceful `BrokenPipe` I/O.

/// Interactive Read-Eval-Print Loop (REPL) drivers and graceful stream output helpers.
mod repl;
/// `wincheck` CLI argument parser, `--fix` / `--diff` runner, and process driver.
mod wincheck_cli;
/// `wincmd` (`cmd.exe`) CLI argument parser, `/C` quote heuristic, and process driver.
mod wincmd_cli;

pub use self::repl::{
    repl_open_paren_depth, run_interactive_repl, run_interactive_repl_byte_streams,
    strip_odd_trailing_caret,
};
#[cfg(feature = "std")]
pub use self::repl::{run_interactive_repl_streaming, write_stream_gracefully};
pub use self::wincheck_cli::{
    WinCheckAction, WinCheckFixMode, execute_wincheck_over_vfs_streams, load_vfs_or_stdin,
    parse_wincheck_args, run_wincheck_action, run_wincheck_action_with_vfs,
};
#[cfg(feature = "std")]
pub use self::wincheck_cli::{execute_wincheck_process, load_file_or_stdin};
#[cfg(feature = "std")]
pub use self::wincmd_cli::execute_wincmd_process;
pub use self::wincmd_cli::{
    WinCmdAction, WinCmdCliConfig, apply_cmd_c_quote_heuristic,
    apply_cmd_c_quote_heuristic_with_probe, execute_wincmd_over_streams,
    execute_wincmd_with_interpreter_streams, join_argv_preserving_quotes, parse_wincmd_args,
    parse_wincmd_args_with_default_backend, run_wincmd_with_config, unquote_cmd_c_command_string,
};

#[cfg(test)]
/// Unit tests for `wincmd` and `wincheck` CLI argument parsers, REPL, and process drivers.
mod tests {
    use std::io::{Cursor, Read, Write};

    use super::*;
    use crate::cli::wincmd_cli::execute_wincmd_with_interpreter;
    use crate::error::CmdError;
    use crate::linter::{LinterConfig, OutputFormat};
    use crate::runtime::{Interpreter, IoStreams};
    use crate::types::BS_STR as SEP;
    use crate::types::{CRLF, EchoState, ExitCode, LF_CHAR, QuoteStripMode, VfsBackendMode};

    /// Mock writer that succeeds `ok_writes` times before failing on write or flush.
    struct CountdownWriter {
        /// Remaining successful `write` calls before failing.
        ok_writes: usize,
        /// [`std::io::ErrorKind`] emitted upon failure.
        kind: std::io::ErrorKind,
        /// When `true`, `write` succeeds and `flush` fails once `ok_writes == 0`.
        fail_on_flush: bool,
    }

    impl Write for CountdownWriter {
        /// Accepts up to `self.ok_writes` writes before returning `self.kind`.
        ///
        /// # Arguments
        /// * `buf` - Byte slice to write.
        ///
        /// # Returns
        /// Accepted byte count or simulated [`std::io::Error`].
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.ok_writes > 0 {
                self.ok_writes = self.ok_writes.saturating_sub(1);
                Ok(buf.len())
            } else if self.fail_on_flush {
                Ok(buf.len())
            } else {
                Err(std::io::Error::new(self.kind, "mock write error"))
            }
        }

        /// Fails on flush once `self.ok_writes == 0` and `self.fail_on_flush` is set.
        ///
        /// # Returns
        /// `Ok(())` or simulated [`std::io::Error`].
        fn flush(&mut self) -> std::io::Result<()> {
            if self.ok_writes == 0 && self.fail_on_flush {
                Err(std::io::Error::new(self.kind, "mock flush error"))
            } else {
                Ok(())
            }
        }
    }

    /// Mock reader that returns an immediate I/O error.
    struct FailingReader;

    impl Read for FailingReader {
        /// Always returns a simulated read failure.
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

    /// Verifies `cmd /C` outer-quote stripping heuristics and OS `argv` quote reconstruction.
    #[test]
    fn test_cmd_c_quote_heuristic_and_argv_quote_preservation() {
        assert_eq!(
            unquote_cmd_c_command_string(r#""echo hi""#, QuoteStripMode::Heuristic),
            "echo hi"
        );
        assert_eq!(
            unquote_cmd_c_command_string(r#""echo hi""#, QuoteStripMode::AlwaysStrip),
            "echo hi"
        );
        let my_app = format!(r#""C:{SEP}My App{SEP}run.exe""#);
        assert_eq!(
            apply_cmd_c_quote_heuristic(&my_app, QuoteStripMode::AlwaysStrip),
            format!("C:{SEP}My App{SEP}run.exe")
        );
        assert_eq!(
            apply_cmd_c_quote_heuristic(
                r#""echo "hello" & echo world""#,
                QuoteStripMode::Heuristic
            ),
            r#"echo "hello" & echo world"#
        );
        let prog_app = format!(r#""C:{SEP}Program Files{SEP}app.exe""#);
        assert_eq!(
            apply_cmd_c_quote_heuristic(&prog_app, QuoteStripMode::Heuristic),
            prog_app
        );
        assert_eq!(
            apply_cmd_c_quote_heuristic(r#""echo ok""#, QuoteStripMode::Heuristic),
            "echo ok"
        );
        assert_eq!(
            apply_cmd_c_quote_heuristic(r#""echo a & echo b""#, QuoteStripMode::Heuristic),
            "echo a & echo b"
        );
        assert_eq!(
            apply_cmd_c_quote_heuristic(r#""app.exe""#, QuoteStripMode::Heuristic),
            "app.exe"
        );

        // Multi-token argv quoting preservation (including single `"` and unclosed quote)
        assert_eq!(
            join_argv_preserving_quotes(&[
                "echo".to_owned(),
                "two  spaces".to_owned(),
                r#""already quoted""#.to_owned(),
                r#"""#.to_owned(),
                r#""unclosed"#.to_owned(),
            ]),
            r#"echo "two  spaces" "already quoted" " "unclosed"#
        );
    }

    /// Verifies `parse_wincmd_args`, `run_wincmd_with_config`, and lexer-aware `More? ` continuation.
    #[test]
    fn test_parse_and_run_wincmd_cli_and_lexer_aware_repl() {
        let mut interp = Interpreter::default();
        let mut io = IoStreams::new();

        let cfg_help = parse_wincmd_args(&["/?".to_owned()]).unwrap_or_default();
        assert_eq!(
            run_wincmd_with_config(&cfg_help, &mut interp, &mut io),
            Ok(ExitCode::SUCCESS)
        );
        let cfg_ver = parse_wincmd_args(&["--version".to_owned()]).unwrap_or_default();
        assert_eq!(
            run_wincmd_with_config(&cfg_ver, &mut interp, &mut io),
            Ok(ExitCode::SUCCESS)
        );

        let args_c: Vec<String> = [
            "/Q",
            "/S",
            "/D",
            "/A",
            "/U",
            "/F:ON",
            "/F:OFF",
            "/E:ON",
            "/V:ON",
            "/T:0A",
            "/C",
            r#""echo ok""#,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let cfg_c = parse_wincmd_args(&args_c).unwrap_or_default();
        io.stdout.clear();
        assert_eq!(
            run_wincmd_with_config(&cfg_c, &mut interp, &mut io),
            Ok(ExitCode::SUCCESS)
        );
        assert_eq!(io.stdout, format!("ok{CRLF}"));

        let cfg_attached_c =
            parse_wincmd_args(&[r#"/c"echo attached""#.to_owned()]).unwrap_or_default();
        io.stdout.clear();
        assert_eq!(
            run_wincmd_with_config(&cfg_attached_c, &mut interp, &mut io),
            Ok(ExitCode::SUCCESS)
        );
        assert_eq!(io.stdout, format!("attached{CRLF}"));

        let cfg_attached_k = parse_wincmd_args(&["/kexit 0".to_owned()]).unwrap_or_default();
        assert_eq!(
            run_wincmd_with_config(&cfg_attached_k, &mut interp, &mut io),
            Ok(ExitCode::SUCCESS)
        );
        interp.exec.clear_exited();

        // --host-root, --in-memory, --host-native options (and HostNative without --host-root!)
        let temp_dir = std::env::temp_dir().join(format!("wincmd_cli_test_{}", std::process::id()));
        assert!(std::fs::create_dir_all(&temp_dir).is_ok());
        let cfg_host_native = parse_wincmd_args(&[
            "--host-native".to_owned(),
            "/c".to_owned(),
            "echo native_ok".to_owned(),
        ])
        .unwrap_or_default();
        assert_eq!(cfg_host_native.vfs_backend_mode, VfsBackendMode::HostNative);
        assert_eq!(
            run_wincmd_with_config(&cfg_host_native, &mut interp, &mut io),
            Ok(ExitCode::SUCCESS)
        );

        let cfg_host = parse_wincmd_args(&[
            "--in-memory".to_owned(),
            "--host-root".to_owned(),
            temp_dir.to_string_lossy().into_owned(),
            "/c".to_owned(),
            "echo host_ok".to_owned(),
        ])
        .unwrap_or_default();
        assert_eq!(cfg_host.vfs_backend_mode, VfsBackendMode::HostNative);
        assert_eq!(
            run_wincmd_with_config(&cfg_host, &mut interp, &mut io),
            Ok(ExitCode::SUCCESS)
        );
        interp.proc_env.vfs = Box::new(crate::vfs::InMemoryVfs::new());
        assert!(std::fs::remove_dir_all(&temp_dir).is_ok());

        let args_k_exit: Vec<String> = ["/K", "exit 3"].into_iter().map(str::to_owned).collect();
        let cfg_k_exit = parse_wincmd_args(&args_k_exit).unwrap_or_default();
        assert_eq!(
            run_wincmd_with_config(&cfg_k_exit, &mut interp, &mut io),
            Ok(ExitCode::new(3))
        );
        interp.exec.clear_exited();
    }

    /// Verifies lexer-aware interactive REPL continuations, script execution, and CLI error cases.
    #[test]
    fn test_lexer_aware_repl_script_and_wincmd_arg_errors() {
        let mut interp = Interpreter::default();

        // Interactive REPL: verify `echo "("` and `rem (` do NOT hang waiting for `)`!
        interp.console.echo_state = EchoState::On;
        let args_k: Vec<String> = ["/E:OFF", "/V:OFF", "/K", "echo init"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let cfg_k = parse_wincmd_args(&args_k).unwrap_or_default();
        let repl_script = [
            r#"echo "(""#,
            "rem ( unclosed in comment",
            "echo cont ^",
            "line",
            "echo literal^^",
            "(",
            "echo in_block",
            ")",
            "exit 0",
        ]
        .join(CRLF);
        let mut repl_io = IoStreams::with_stdin(repl_script);
        assert_eq!(
            run_wincmd_with_config(&cfg_k, &mut interp, &mut repl_io),
            Ok(ExitCode::SUCCESS)
        );
        assert!(repl_io.stdout.contains("More?"));
        assert!(repl_io.stdout.contains("cont line"));
        assert!(repl_io.stdout.contains("in_block"));

        interp.exec.clear_exited();
        assert!(
            interp
                .proc_env
                .vfs
                .write_bytes(
                    "C:/cli_test.bat",
                    format!("@echo off{CRLF}echo arg:%1{CRLF}").as_bytes()
                )
                .is_ok()
        );
        let cfg_s = parse_wincmd_args(&["C:/cli_test.bat".to_owned(), "val1".to_owned()])
            .unwrap_or_default();
        let mut s_io = IoStreams::new();
        assert_eq!(
            run_wincmd_with_config(&cfg_s, &mut interp, &mut s_io),
            Ok(ExitCode::SUCCESS)
        );
        assert_eq!(s_io.stdout, format!("arg:val1{CRLF}"));

        let cfg_eof = parse_wincmd_args(&[]).unwrap_or_default();
        interp.console.echo_state = EchoState::Off;
        let mut eof_io = IoStreams::with_stdin(format!("echo eof_test{CRLF}"));
        assert_eq!(
            run_wincmd_with_config(&cfg_eof, &mut interp, &mut eof_io),
            Ok(ExitCode::SUCCESS)
        );

        assert!(parse_wincmd_args(&["/?'".to_owned()]).is_err());
        assert!(parse_wincmd_args(&["/C".to_owned()]).is_err());
        assert!(parse_wincmd_args(&["/T:ZZ".to_owned()]).is_err());
        assert!(parse_wincmd_args(&["--host-root".to_owned()]).is_err());
        assert!(parse_wincmd_args(&["--script".to_owned()]).is_err());
        assert!(parse_wincmd_args(&["/bogus".to_owned()]).is_err());
        assert!(parse_wincmd_args(&["--bogus".to_owned()]).is_err());
        assert!(parse_wincmd_args(&["--script".to_owned(), "C:/cli_test.bat".to_owned()]).is_ok());
    }

    /// Verifies streaming `execute_wincmd_process` and `execute_wincheck_process` with `BrokenPipe` and I/O errors.
    #[test]
    fn test_streaming_repl_and_process_drivers_with_broken_pipe_and_errors() {
        // Streaming wincmd process: REPL, /K + REPL, /K + EXIT, /C, script, invalid flag, missing script
        let repl_input = format!(
            r#"echo "(" & ({CRLF}echo streamed_blk{CRLF}){CRLF}echo a^{CRLF}b{CRLF}exit 2{CRLF}"#
        );
        let mut stdin = Cursor::new(repl_input.into_bytes());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            execute_wincmd_process(
                &["--hermetic".to_owned()],
                &mut stdin,
                &mut stdout,
                &mut stderr
            ),
            2
        );
        let out_str = String::from_utf8_lossy(&stdout);
        assert!(out_str.contains("More? "));
        assert!(out_str.contains("streamed_blk"));
        assert!(out_str.contains("ab"));

        // EOF termination in streaming REPL with ECHO OFF (`/Q`)
        let eof_bytes = format!("echo quiet_eof{LF_CHAR}").into_bytes();
        let mut eof_in = Cursor::new(eof_bytes);
        let mut eof_out = Vec::new();
        let mut eof_err = Vec::new();
        assert_eq!(
            execute_wincmd_process(
                &[
                    "--hermetic".to_owned(),
                    "/Q".to_owned(),
                    "/K".to_owned(),
                    "echo start".to_owned()
                ],
                &mut eof_in,
                &mut eof_out,
                &mut eof_err,
            ),
            0
        );
        assert!(String::from_utf8_lossy(&eof_out).contains("quiet_eof"));

        // /K that exits immediately without entering REPL
        let mut k_in = Cursor::new(Vec::new());
        let mut k_out = Vec::new();
        let mut k_err = Vec::new();
        assert_eq!(
            execute_wincmd_process(
                &[
                    "--hermetic".to_owned(),
                    "/K".to_owned(),
                    "exit 5".to_owned()
                ],
                &mut k_in,
                &mut k_out,
                &mut k_err,
            ),
            5
        );

        // Host-native /C, invalid CLI option, and missing script file
        let mut c_in = Cursor::new(Vec::new());
        let mut c_out = Vec::new();
        let mut c_err = Vec::new();
        assert_eq!(
            execute_wincmd_process(
                &["/C".to_owned(), "echo live_host".to_owned()],
                &mut c_in,
                &mut c_out,
                &mut c_err,
            ),
            0
        );
        assert_eq!(
            execute_wincmd_process(
                &["--bad-flag".to_owned()],
                &mut c_in,
                &mut c_out,
                &mut c_err
            ),
            1
        );
        let tmp_bat =
            std::env::temp_dir().join(format!("wincmd_ok_run_{}.bat", std::process::id()));
        assert!(std::fs::write(&tmp_bat, format!("@echo off{CRLF}echo ok_bat{CRLF}")).is_ok());
        assert_eq!(
            execute_wincmd_process(
                &[tmp_bat.to_string_lossy().into_owned()],
                &mut c_in,
                &mut c_out,
                &mut c_err,
            ),
            0
        );
        assert!(std::fs::remove_file(&tmp_bat).is_ok());
        assert_eq!(
            execute_wincmd_process(
                &[
                    "--hermetic".to_owned(),
                    "C:/no_such_script_99.bat".to_owned()
                ],
                &mut c_in,
                &mut c_out,
                &mut c_err,
            ),
            1
        );
    }

    /// Verifies POSIX script path detection and `BrokenPipe` vs `Other` stream write handling.
    #[test]
    fn test_posix_script_paths_and_broken_pipe_stream_handling() {
        let mut c_in = Cursor::new(Vec::new());
        let mut c_out = Vec::new();
        let mut c_err = Vec::new();

        // POSIX script path branches (`/root.bat`, `/root.cmd`, `--script /tmp/x.bat`, `rel.bat`, `--script /not_ext`, `/bogus`)
        assert!(
            parse_wincmd_args_with_default_backend(
                &["/root.bat".to_owned()],
                VfsBackendMode::HostNative
            )
            .is_ok()
        );
        assert!(
            parse_wincmd_args_with_default_backend(
                &["/root.cmd".to_owned()],
                VfsBackendMode::HostNative
            )
            .is_ok()
        );
        assert!(
            parse_wincmd_args_with_default_backend(
                &["rel.bat".to_owned()],
                VfsBackendMode::HostNative
            )
            .is_ok()
        );
        assert!(
            parse_wincmd_args_with_default_backend(
                &["--script".to_owned(), "/not_ext".to_owned()],
                VfsBackendMode::HostNative
            )
            .is_ok()
        );
        assert!(
            parse_wincmd_args_with_default_backend(
                &["/bogus".to_owned()],
                VfsBackendMode::HostNative
            )
            .is_err()
        );
        assert!(
            parse_wincmd_args_with_default_backend(
                &["--script".to_owned(), "/tmp/sub.bat".to_owned()],
                VfsBackendMode::HostNative
            )
            .is_ok()
        );
        assert_eq!(
            execute_wincmd_process(
                &[
                    "--host-root".to_owned(),
                    std::env::temp_dir().to_string_lossy().into_owned(),
                    "/C".to_owned(),
                    "echo root_exec".to_owned(),
                ],
                &mut c_in,
                &mut c_out,
                &mut c_err,
            ),
            0
        );

        // Stream error paths: BrokenPipe succeeds, Other write/flush/read fails cleanly with status 1
        let mut bp_write = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::BrokenPipe,
            fail_on_flush: false,
        };
        assert_eq!(write_stream_gracefully(&mut bp_write, b"ok"), Ok(()));
        let mut bp_flush = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::BrokenPipe,
            fail_on_flush: true,
        };
        assert_eq!(write_stream_gracefully(&mut bp_flush, b"ok"), Ok(()));
        assert_eq!(write_stream_gracefully(&mut bp_flush, b""), Ok(()));

        let mut fail_w = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::Other,
            fail_on_flush: false,
        };
        let mut fail_fl = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::Other,
            fail_on_flush: true,
        };
        assert!(write_stream_gracefully(&mut fail_w, b"x").is_err());
        assert!(write_stream_gracefully(&mut fail_fl, b"x").is_err());
    }

    /// Verifies `CountdownWriter` stream failure propagation, `AutoRun`, and live `SET /P` streaming.
    #[test]
    fn test_countdown_writer_autorun_and_live_set_p_streaming() {
        let mut c_in = Cursor::new(Vec::new());
        let mut fail_w = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::Other,
            fail_on_flush: false,
        };

        // CountdownWriter exercising banner, prompt, `More? `, command stdout, and stderr failure points
        for ok_count in 0..=4 {
            let mut cw = CountdownWriter {
                ok_writes: ok_count,
                kind: std::io::ErrorKind::Other,
                fail_on_flush: false,
            };
            let mut rep_in = Cursor::new(format!("({CRLF}echo x{CRLF}){CRLF}").into_bytes());
            let mut rep_err = Vec::new();
            assert_eq!(
                execute_wincmd_process(
                    &["--hermetic".to_owned()],
                    &mut rep_in,
                    &mut cw,
                    &mut rep_err
                ),
                1
            );
        }
        // Fail on stderr write inside streaming REPL and on autorun flush in InteractiveRepl
        let mut stderr_fail = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::Other,
            fail_on_flush: false,
        };
        let mut bad_cmd_in = Cursor::new(format!("nonexistent_cmd_xyz_99{CRLF}").into_bytes());
        let mut good_out = Vec::new();
        assert_eq!(
            execute_wincmd_process(
                &["--hermetic".to_owned()],
                &mut bad_cmd_in,
                &mut good_out,
                &mut stderr_fail,
            ),
            1
        );

        let mut interp_ar = Interpreter::default();
        assert_eq!(
            interp_ar.proc_env.registry_store.set_value(
                crate::runtime::registry::HKCU_CMD_PROCESSOR_KEY,
                "AutoRun",
                crate::runtime::registry::RegistryValueType::Sz,
                "echo autorun_hi",
            ),
            Ok(())
        );
        assert!(
            execute_wincmd_with_interpreter(
                &WinCmdCliConfig::default(),
                &mut interp_ar,
                &mut c_in,
                &mut fail_w,
                &mut good_out,
            )
            .is_err()
        );

        // Verify live interactive `SET /P` prompt flushing + stdin reading over `execute_wincmd_process`!
        let mut live_p_in = Cursor::new(format!("InteractiveUser{CRLF}").into_bytes());
        let mut live_p_out = Vec::new();
        let mut live_p_err = Vec::new();
        assert_eq!(
            execute_wincmd_process(
                &[
                    "--hermetic".to_owned(),
                    "/V:ON".to_owned(),
                    "/C".to_owned(),
                    r#"set /p "WHO=Who? " & echo Hello !WHO!"#.to_owned(),
                ],
                &mut live_p_in,
                &mut live_p_out,
                &mut live_p_err,
            ),
            0
        );
        assert_eq!(
            String::from_utf8_lossy(&live_p_out),
            format!("Who? Hello InteractiveUser{CRLF}")
        );
    }

    /// Verifies `execute_wincmd_process` and `execute_wincheck_process` failure exit statuses on broken I/O streams.
    #[test]
    fn test_process_driver_io_failure_exit_codes() {
        let mut c_in = Cursor::new(Vec::new());
        let mut c_out = Vec::new();
        let mut c_err = Vec::new();
        let mut k_out = Vec::new();
        let mut fail_w = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::Other,
            fail_on_flush: false,
        };

        let mut ok_err = Vec::new();
        assert_eq!(
            execute_wincmd_process(&["--help".to_owned()], &mut c_in, &mut c_out, &mut c_err),
            0
        );
        assert_eq!(
            execute_wincmd_process(
                &["--bad-flag".to_owned()],
                &mut c_in,
                &mut c_out,
                &mut fail_w
            ),
            1
        );
        assert_eq!(
            execute_wincmd_process(
                &["--version".to_owned()],
                &mut c_in,
                &mut fail_w,
                &mut ok_err
            ),
            1
        );
        let mut fail_buf = std::io::BufReader::new(FailingReader);
        assert_eq!(
            execute_wincmd_process(
                &["--hermetic".to_owned()],
                &mut fail_buf,
                &mut k_out,
                &mut ok_err
            ),
            1
        );
        assert_eq!(
            execute_wincmd_process(
                &[
                    "--hermetic".to_owned(),
                    "/K".to_owned(),
                    "echo x".to_owned()
                ],
                &mut c_in,
                &mut fail_w,
                &mut ok_err,
            ),
            1
        );
        let mut fail_buf2 = std::io::BufReader::new(FailingReader);
        assert_eq!(
            execute_wincmd_process(
                &[
                    "--hermetic".to_owned(),
                    "/K".to_owned(),
                    "echo x".to_owned()
                ],
                &mut fail_buf2,
                &mut k_out,
                &mut ok_err,
            ),
            1
        );
    }

    /// Verifies `execute_wincheck_process` over `stdin` (`-`), file paths, invalid options, and stream errors.
    #[test]
    fn test_wincheck_process_driver_stdin_and_stream_errors() {
        let mut fail_w = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::Other,
            fail_on_flush: false,
        };

        // wincheck process driver: `-` stdin, Cargo.toml, invalid option, failing reader/writer
        let clean_stdin = format!(r#"@echo off{CRLF}setlocal{CRLF}set "A=1"{CRLF}echo(%A%{CRLF}"#);
        let mut wc_in = Cursor::new(clean_stdin.into_bytes());
        let mut wc_out = Vec::new();
        let mut wc_err = Vec::new();
        assert_eq!(
            execute_wincheck_process(&["-".to_owned()], &mut wc_in, &mut wc_out, &mut wc_err),
            0
        );
        assert_eq!(
            execute_wincheck_process(
                &["--unknown-flag".to_owned()],
                &mut wc_in,
                &mut wc_out,
                &mut wc_err,
            ),
            2
        );
        let mut fail_cli_stderr = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::Other,
            fail_on_flush: false,
        };
        assert_eq!(
            execute_wincheck_process(
                &["--unknown-flag".to_owned()],
                &mut wc_in,
                &mut wc_out,
                &mut fail_cli_stderr,
            ),
            1
        );
        assert_eq!(
            execute_wincheck_process(
                &["--explain".to_owned(), "CMD9999".to_owned()],
                &mut wc_in,
                &mut wc_out,
                &mut wc_err,
            ),
            2
        );
        assert_eq!(
            execute_wincheck_process(
                &["nonexistent_98765.bat".to_owned()],
                &mut wc_in,
                &mut wc_out,
                &mut wc_err,
            ),
            1
        );
        let mut fail_rd = FailingReader;
        assert_eq!(
            execute_wincheck_process(&["-".to_owned()], &mut fail_rd, &mut wc_out, &mut wc_err,),
            1
        );
        assert_eq!(
            execute_wincheck_process(
                &["--version".to_owned()],
                &mut wc_in,
                &mut fail_w,
                &mut wc_err,
            ),
            1
        );
        assert!(load_file_or_stdin("Cargo.toml", &mut wc_in).is_ok());
    }

    /// Verifies `parse_wincheck_args` and `run_wincheck_with_config` across formats, `--diff`, and `--fix`.
    #[test]
    fn test_parse_and_run_wincheck_cli() {
        assert_eq!(WinCheckFixMode::default(), WinCheckFixMode::ReportOnly);
        assert!(WinCheckFixMode::ReportOnly.is_report_only());
        assert_eq!(WinCheckFixMode::ShowDiff.to_string(), "diff");

        let mut io = IoStreams::new();
        let clean_src = format!(r#"@echo off{CRLF}setlocal{CRLF}set "X=1"{CRLF}echo(%X%{CRLF}"#);

        let loader = |p: &str| -> Result<Vec<u8>, CmdError> {
            match p {
                "clean.bat" => Ok(clean_src.as_bytes().to_vec()),
                "bad_utf8.bat" => Ok(vec![0xFF, 0xFF, 0xFF]),
                _ => Err(CmdError::FileNotFound { path: p.to_owned() }),
            }
        };

        for flag in [
            vec![],
            vec!["--help".to_owned()],
            vec!["--version".to_owned()],
            vec!["--list-rules".to_owned()],
            vec!["--explain".to_owned(), "CMD2001".to_owned()],
        ] {
            let act = parse_wincheck_args(&flag).unwrap_or(WinCheckAction::ShowHelp);
            assert_eq!(
                run_wincheck_action(&act, loader, &mut io),
                Ok(ExitCode::SUCCESS)
            );
        }

        let act_bad_exp = WinCheckAction::ExplainRule("CMD9999".to_owned());
        assert!(run_wincheck_action(&act_bad_exp, loader, &mut io).is_err());

        let act_missing_file = WinCheckAction::LintFiles {
            files: vec!["missing.bat".to_owned()],
            format: OutputFormat::Tty,
            config: LinterConfig::default(),
            fix_mode: WinCheckFixMode::ReportOnly,
        };
        assert!(run_wincheck_action(&act_missing_file, loader, &mut io).is_err());

        let act_bad_utf8 = WinCheckAction::LintFiles {
            files: vec!["bad_utf8.bat".to_owned()],
            format: OutputFormat::Tty,
            config: LinterConfig::default(),
            fix_mode: WinCheckFixMode::ReportOnly,
        };
        assert!(run_wincheck_action(&act_bad_utf8, loader, &mut io).is_err());

        // Clean file returns ExitCode::SUCCESS in both ReportOnly and ShowDiff
        let clean_args: Vec<String> = [
            "-f",
            "gcc",
            "-m",
            "batch",
            "-S",
            "style",
            "-i",
            "CMD2005,CMD4006",
            "-e",
            "CMD9999",
            "clean.bat",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let act_clean = parse_wincheck_args(&clean_args).unwrap_or(WinCheckAction::ShowHelp);
        assert_eq!(
            run_wincheck_action(&act_clean, loader, &mut io),
            Ok(ExitCode::SUCCESS)
        );
        let clean_diff = parse_wincheck_args(&["--diff".to_owned(), "clean.bat".to_owned()])
            .unwrap_or(WinCheckAction::ShowHelp);
        assert_eq!(
            run_wincheck_action(&clean_diff, loader, &mut io),
            Ok(ExitCode::SUCCESS)
        );
    }

    /// Verifies `wincheck --diff`, `--fix`, `--unsafe-fixes`, unfixable exit code `1`, and invalid CLI flags.
    #[test]
    fn test_wincheck_diff_fix_and_arg_validation() {
        let mut io = IoStreams::new();
        let dirty_src = format!("@echo off{CRLF}setlocal{CRLF}set X = 1{CRLF}echo(%X%{CRLF}");
        let repl_dirty_src = format!("set X = 1{CRLF}echo(%X%{CRLF}");
        let unfixable_src = format!("@echo off{CRLF}goto :missing_label_target{CRLF}");
        let loader = |p: &str| -> Result<Vec<u8>, CmdError> {
            match p {
                "dirty.bat" => Ok(dirty_src.as_bytes().to_vec()),
                "repl_dirty.bat" => Ok(repl_dirty_src.as_bytes().to_vec()),
                "unfixable.bat" => Ok(unfixable_src.as_bytes().to_vec()),
                _ => Err(CmdError::FileNotFound { path: p.to_owned() }),
            }
        };

        // Dirty file with --diff previews unified diff of CstRewriter output and returns FAILURE
        io.stdout.clear();
        let dirty_args: Vec<String> = ["--diff", "dirty.bat"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let act_dirty = parse_wincheck_args(&dirty_args).unwrap_or(WinCheckAction::ShowHelp);
        assert_eq!(
            run_wincheck_action(&act_dirty, loader, &mut io),
            Ok(ExitCode::FAILURE)
        );
        assert!(io.stdout.contains(r#"+set "X=1""#));

        // Dirty file with --fix resolves CMD2005 and returns ExitCode::SUCCESS!
        io.stdout.clear();
        let batch_fix_act = parse_wincheck_args(&[
            "--unsafe-fixes".to_owned(),
            "--fix".to_owned(),
            "dirty.bat".to_owned(),
        ])
        .unwrap_or(WinCheckAction::ShowHelp);
        assert_eq!(
            run_wincheck_action(&batch_fix_act, loader, &mut io),
            Ok(ExitCode::SUCCESS)
        );
        io.stdout.clear();
        let fix_args: Vec<String> = ["-S", "warning", "--mode", "repl", "--fix", "repl_dirty.bat"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let act_fix = parse_wincheck_args(&fix_args).unwrap_or(WinCheckAction::ShowHelp);
        assert_eq!(
            run_wincheck_action(&act_fix, loader, &mut io),
            Ok(ExitCode::SUCCESS)
        );
        assert!(io.stdout.contains(r#"set "X=1""#));

        // Unfixable file with --fix still has remaining diagnostics -> ExitCode::FAILURE
        let unfix_act = parse_wincheck_args(&["--fix".to_owned(), "unfixable.bat".to_owned()])
            .unwrap_or(WinCheckAction::ShowHelp);
        assert_eq!(
            run_wincheck_action(&unfix_act, loader, &mut io),
            Ok(ExitCode::FAILURE)
        );

        // Dirty file without --diff renders diagnostics
        let act_tty =
            parse_wincheck_args(&["dirty.bat".to_owned()]).unwrap_or(WinCheckAction::ShowHelp);
        assert_eq!(
            run_wincheck_action(&act_tty, loader, &mut io),
            Ok(ExitCode::FAILURE)
        );
        let act_miss =
            parse_wincheck_args(&["nope.bat".to_owned()]).unwrap_or(WinCheckAction::ShowHelp);
        assert!(run_wincheck_action(&act_miss, loader, &mut io).is_err());

        let mut c_in = Cursor::new(Vec::new());
        let mut c_out = Vec::new();
        let mut c_err = Vec::new();
        assert_eq!(
            execute_wincmd_process(&["--version".to_owned()], &mut c_in, &mut c_out, &mut c_err),
            0
        );
        let mut bad_utf8_in = Cursor::new(vec![0xFF, 0xFF, 0xFF]);
        let mut fail_stderr = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::Other,
            fail_on_flush: false,
        };
        assert_eq!(
            execute_wincheck_process(
                &["-".to_owned()],
                &mut bad_utf8_in,
                &mut c_out,
                &mut fail_stderr,
            ),
            1
        );

        for bad_args in [
            vec!["--explain".to_owned()],
            vec!["-f".to_owned()],
            vec!["-f".to_owned(), "invalid".to_owned()],
            vec!["-m".to_owned()],
            vec!["-m".to_owned(), "invalid_mode".to_owned()],
            vec!["-S".to_owned()],
            vec!["-S".to_owned(), "invalid".to_owned()],
            vec!["-e".to_owned()],
            vec!["-i".to_owned()],
            vec!["--unknown".to_owned()],
            vec!["-S".to_owned(), "error".to_owned()],
        ] {
            assert!(parse_wincheck_args(&bad_args).is_err());
        }
        assert!(parse_wincheck_args(&["-".to_owned()]).is_ok());
    }

    /// Verifies `wincheck` `--encoding`, `--in-place`, `--stdout`, UTF-8 BOM preservation, and multi-file validation.
    #[test]
    fn test_wincheck_inplace_bom_and_encoding_flags() {
        for enc in [
            "utf8", "ascii", "cp437", "cp850", "cp1252", "utf16le", "utf16be",
        ] {
            assert!(
                parse_wincheck_args(&[format!("--encoding={enc}"), "a.bat".to_owned()]).is_ok()
            );
        }
        assert!(
            parse_wincheck_args(&[
                "--encoding".to_owned(),
                "cp437".to_owned(),
                "--in-place".to_owned(),
                "--fix".to_owned(),
                "a.bat".to_owned(),
            ])
            .is_ok()
        );
        assert!(
            parse_wincheck_args(&[
                "--in-place".to_owned(),
                "--stdout".to_owned(),
                "a.bat".to_owned(),
            ])
            .is_ok()
        );
        for invalid_wc in [
            vec!["--encoding=bogus".to_owned(), "a.bat".to_owned()],
            vec!["--fix".to_owned(), "a.bat".to_owned(), "b.bat".to_owned()],
            vec!["--in-place".to_owned(), "-".to_owned()],
        ] {
            assert!(parse_wincheck_args(&invalid_wc).is_err());
        }

        let tmp_fix = std::env::temp_dir().join(format!("wc_inplace_{}.bat", std::process::id()));
        let bom_buggy = [
            &[0xEFu8, 0xBB, 0xBF][..],
            format!("@echo off{CRLF}set X=1   {CRLF}echo \"%X%\"{CRLF}").as_bytes(),
        ]
        .concat();
        assert!(std::fs::write(&tmp_fix, &bom_buggy).is_ok());
        let tmp_fix_str = tmp_fix.to_string_lossy().into_owned();
        let mut ip_in = Cursor::new(Vec::new());
        let mut ip_out = Vec::new();
        let mut ip_err = Vec::new();
        assert_eq!(
            execute_wincheck_process(
                &[
                    "-S".to_owned(),
                    "warning".to_owned(),
                    "-e".to_owned(),
                    "CMD1008".to_owned(),
                    "--in-place".to_owned(),
                    tmp_fix_str,
                ],
                &mut ip_in,
                &mut ip_out,
                &mut ip_err,
            ),
            0
        );
        let rewritten_disk = std::fs::read(&tmp_fix).unwrap_or_default();
        assert!(rewritten_disk.starts_with(&[0xEF, 0xBB, 0xBF]));
        assert!(String::from_utf8_lossy(&rewritten_disk).contains("set \"X=1\""));

        // Make `tmp_fix` read-only with a new fixable warning so `write_file_to_disk` exercises I/O error mapping.
        assert!(std::fs::write(&tmp_fix, format!("@echo off{CRLF}set X=2   {CRLF}")).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(
                std::fs::set_permissions(&tmp_fix, std::fs::Permissions::from_mode(0o444)).is_ok()
            );
        }
        let mut ro_in = Cursor::new(Vec::new());
        let mut ro_out = Vec::new();
        let mut ro_err = Vec::new();
        assert_ne!(
            execute_wincheck_process(
                &[
                    "--in-place".to_owned(),
                    tmp_fix.to_string_lossy().into_owned()
                ],
                &mut ro_in,
                &mut ro_out,
                &mut ro_err,
            ),
            0
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(
                std::fs::set_permissions(&tmp_fix, std::fs::Permissions::from_mode(0o644)).is_ok()
            );
        }
        assert!(std::fs::remove_file(&tmp_fix).is_ok());
    }

    /// Verifies REPL `/F:ON` (`Ctrl+F` / `Ctrl+D`), `COLOR` ANSI SGR + reset, `Ctrl+C`,
    /// unread `io.stdin` preservation after `EXIT`, and EOF flush of pending `^` buffer.
    #[test]
    fn test_repl_completion_ansi_colors_ctrl_c_and_eof_flush() {
        let manual_cfg = WinCmdCliConfig {
            action: WinCmdAction::RunCommandAndExit("echo fallback_ok".to_owned()),
            raw_command_string: None,
            ..WinCmdCliConfig::default()
        };
        let mut manual_interp = Interpreter::new();
        let mut manual_io = IoStreams::new();
        assert_eq!(
            run_wincmd_with_config(&manual_cfg, &mut manual_interp, &mut manual_io),
            Ok(ExitCode::SUCCESS)
        );
        assert!(manual_io.stdout.contains("fallback_ok"));

        let mut repl_interp = Interpreter::new();
        repl_interp.config.file_completion = crate::types::FileCompletionMode::Enabled;
        assert_eq!(
            repl_interp
                .proc_env
                .vfs
                .create_dir("C:/adir", crate::types::DirCreationDepth::CreateParents),
            Ok(())
        );
        assert_eq!(
            repl_interp.proc_env.vfs.write_bytes("C:/a1.txt", b"1"),
            Ok(())
        );
        assert_eq!(
            repl_interp.proc_env.vfs.write_bytes("C:/a2.txt", b"2"),
            Ok(())
        );
        let mut repl_io = IoStreams::with_stdin(format!(
            "echo a\x06\x06 & echo a\x04{CRLF}color 0a{CRLF}color{CRLF}aborted \x03{CRLF}exit 0{CRLF}UNREAD_TAIL"
        ));
        assert_eq!(
            run_interactive_repl(&mut repl_interp, &mut repl_io),
            ExitCode::SUCCESS
        );
        assert!(repl_io.stdout.contains("a2.txt"));
        assert!(repl_io.stdout.contains("adir"));
        let esc = crate::types::ESC_CHAR;
        assert!(repl_io.stdout.contains(&format!("{esc}[")));
        assert!(repl_io.stdout.contains(&format!("{esc}[0m")));
        assert!(repl_io.stdout.contains("^C"));
        assert_eq!(repl_io.stdin, "UNREAD_TAIL");

        let mut eof_interp = Interpreter::new();
        let mut eof_io = IoStreams::with_stdin("echo eof_flushed ^".to_owned());
        assert_eq!(
            run_interactive_repl(&mut eof_interp, &mut eof_io),
            ExitCode::SUCCESS
        );
        assert!(eof_io.stdout.contains("eof_flushed"));
    }

    /// Verifies `run_interactive_repl_streaming` and `#![no_std]` `execute_wincmd_over_streams`.
    #[test]
    fn test_portable_wincmd_over_streams_and_streaming_repl() {
        let mut stream_interp = Interpreter::new();
        let mut cur_in = Cursor::new(format!("echo stream_ok{CRLF}exit 0{CRLF}").into_bytes());
        let mut stream_out = Vec::new();
        let mut stream_err = Vec::new();
        assert_eq!(
            run_interactive_repl_streaming(
                &mut stream_interp,
                &mut cur_in,
                &mut stream_out,
                &mut stream_err
            ),
            Ok(ExitCode::SUCCESS)
        );
        assert!(String::from_utf8_lossy(&stream_out).contains("stream_ok"));

        let mut dos_interp = Interpreter::new();
        let mut empty_in = crate::runtime::InMemoryByteReader::new(Vec::new());
        let mut out_bytes = Vec::new();
        let mut err_bytes = Vec::new();
        assert_eq!(
            execute_wincmd_over_streams(
                &["/c".to_owned(), "echo dos_stream_ok".to_owned()],
                VfsBackendMode::InMemoryHermetic,
                &mut dos_interp,
                &mut empty_in,
                &mut out_bytes,
                &mut err_bytes,
            ),
            0
        );
        assert_eq!(
            String::from_utf8_lossy(&out_bytes),
            format!("dos_stream_ok{CRLF}")
        );

        let mut bad_err_buf = Vec::new();
        assert_eq!(
            execute_wincmd_over_streams(
                &["--unknown-flag".to_owned()],
                VfsBackendMode::InMemoryHermetic,
                &mut dos_interp,
                &mut empty_in,
                &mut out_bytes,
                &mut bad_err_buf,
            ),
            1
        );
        assert_ne!(bad_err_buf, Vec::<u8>::new());

        let mut raw_fail_w = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::PermissionDenied,
            fail_on_flush: false,
        };
        let mut fail_adapter = crate::runtime::StdWriteAdapter::new(&mut raw_fail_w, "stderr");
        assert_eq!(
            execute_wincmd_over_streams(
                &["--unknown-flag".to_owned()],
                VfsBackendMode::InMemoryHermetic,
                &mut dos_interp,
                &mut empty_in,
                &mut out_bytes,
                &mut fail_adapter,
            ),
            1
        );
    }

    /// Verifies `#![no_std]` `execute_wincheck_over_vfs_streams` across stdin, VFS `--in-place`, and stream errors.
    #[test]
    fn test_portable_wincheck_over_vfs_streams_and_errors() {
        use crate::vfs::VirtualFileSystem as _;
        let mut wc_vfs = crate::vfs::InMemoryVfs::new();
        assert_eq!(
            wc_vfs.write_bytes(
                "C:\\clean.bat",
                format!("@echo off{CRLF}echo hi{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            wc_vfs.write_bytes(
                "C:\\fixme.bat",
                format!("@echo off{CRLF}setlocal{CRLF}set X=1   {CRLF}echo \"%X%\"{CRLF}")
                    .as_bytes()
            ),
            Ok(())
        );
        let mut stdin_dash = crate::runtime::InMemoryByteReader::new(
            format!("@echo off{CRLF}echo stdin_ok{CRLF}").into_bytes(),
        );
        let mut wc_out = Vec::new();
        let mut wc_err = Vec::new();
        assert_eq!(
            execute_wincheck_over_vfs_streams(
                &["C:\\clean.bat".to_owned(), "-".to_owned()],
                &mut wc_vfs,
                &mut stdin_dash,
                &mut wc_out,
                &mut wc_err,
            ),
            0
        );
        let mut empty_stdin = crate::runtime::InMemoryByteReader::new(Vec::new());
        assert_eq!(
            execute_wincheck_over_vfs_streams(
                &[
                    "--fix".to_owned(),
                    "--in-place".to_owned(),
                    "C:\\fixme.bat".to_owned(),
                ],
                &mut wc_vfs,
                &mut empty_stdin,
                &mut wc_out,
                &mut wc_err,
            ),
            0
        );
        let fixed_vfs =
            String::from_utf8_lossy(&wc_vfs.read_bytes("C:\\fixme.bat").unwrap_or_default())
                .into_owned();
        assert!(fixed_vfs.contains("set \"X=1\""));
        assert_eq!(
            execute_wincheck_over_vfs_streams(
                &["--fix".to_owned(), "C:\\clean.bat".to_owned()],
                &mut wc_vfs,
                &mut empty_stdin,
                &mut wc_out,
                &mut wc_err,
            ),
            0
        );
    }

    /// Verifies `execute_wincheck_over_vfs_streams` read-only VFS failure and stream error exit codes.
    #[test]
    fn test_portable_wincheck_over_vfs_stream_failure_paths() {
        use crate::vfs::VirtualFileSystem as _;
        let mut wc_vfs = crate::vfs::InMemoryVfs::new();
        assert_eq!(
            wc_vfs.write_bytes(
                "C:\\ro.bat",
                format!("@echo off{CRLF}set Y=2   {CRLF}echo \"%Y%\"{CRLF}").as_bytes()
            ),
            Ok(())
        );
        assert!(
            wc_vfs
                .set_attributes("C:\\ro.bat", crate::vfs::FileAttributeFlags::READ_ONLY)
                .is_ok()
        );
        let mut empty_stdin = crate::runtime::InMemoryByteReader::new(Vec::new());
        let mut wc_out = Vec::new();
        let mut wc_err = Vec::new();
        assert_eq!(
            execute_wincheck_over_vfs_streams(
                &[
                    "--fix".to_owned(),
                    "--in-place".to_owned(),
                    "C:\\ro.bat".to_owned(),
                ],
                &mut wc_vfs,
                &mut empty_stdin,
                &mut wc_out,
                &mut wc_err,
            ),
            1
        );
        assert!(String::from_utf8_lossy(&wc_err).contains("Access is denied."));
        assert_eq!(
            execute_wincheck_over_vfs_streams(
                &["--bad-opt".to_owned()],
                &mut wc_vfs,
                &mut empty_stdin,
                &mut wc_out,
                &mut wc_err,
            ),
            2
        );

        let mut raw_fail_w2 = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::PermissionDenied,
            fail_on_flush: false,
        };
        let mut fail_adapter2 = crate::runtime::StdWriteAdapter::new(&mut raw_fail_w2, "stderr");
        assert_eq!(
            execute_wincheck_over_vfs_streams(
                &["--bad-opt".to_owned()],
                &mut wc_vfs,
                &mut empty_stdin,
                &mut wc_out,
                &mut fail_adapter2,
            ),
            1
        );
        let mut raw_fail_w3 = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::PermissionDenied,
            fail_on_flush: false,
        };
        let mut fail_adapter3 = crate::runtime::StdWriteAdapter::new(&mut raw_fail_w3, "stdout");
        assert_eq!(
            execute_wincheck_over_vfs_streams(
                &["--version".to_owned()],
                &mut wc_vfs,
                &mut empty_stdin,
                &mut fail_adapter3,
                &mut wc_err,
            ),
            1
        );
        let mut raw_fail_w4 = CountdownWriter {
            ok_writes: 0,
            kind: std::io::ErrorKind::PermissionDenied,
            fail_on_flush: false,
        };
        let mut fail_adapter4 = crate::runtime::StdWriteAdapter::new(&mut raw_fail_w4, "stderr");
        assert_eq!(
            execute_wincheck_over_vfs_streams(
                &["C:\\missing_file.bat".to_owned()],
                &mut wc_vfs,
                &mut empty_stdin,
                &mut wc_out,
                &mut fail_adapter4,
            ),
            1
        );
    }

    /// Verifies `BiosVgaAttribute` & `DumbTeletype` `CLS`/`COLOR` rendering and `CHCP` DOS kernel sync.
    #[test]
    fn test_dos_console_render_backends_and_chcp_kernel_sync() {
        use crate::dos::{DosKernelApi, SimulatedDosKernel};
        use crate::runtime::{BufferedIoStreams, InMemoryByteReader};
        use crate::types::{CodePage, ConsoleRenderBackend, ExitCode};

        let (mut interp, shared) = Interpreter::with_dos_kernel(SimulatedDosKernel::new());
        let mut io = BufferedIoStreams::new();
        assert_eq!(
            interp.execute_interactive_line("cls", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(io.stdout, "");
        assert_eq!(shared.with(|k| k.last_cleared_attr), Some(0x07));

        assert_eq!(
            interp.execute_interactive_line("color 1F", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(shared.with(|k| k.last_cleared_attr), Some(0x1F));
        assert_eq!(
            interp.execute_interactive_line("color", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(shared.with(|k| k.last_cleared_attr), Some(0x07));

        assert_eq!(
            interp.execute_interactive_line("chcp 866", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            shared.with(DosKernelApi::active_codepage),
            Ok(CodePage::OemCyrillic)
        );
        io.stdout.clear();
        assert_eq!(
            interp.execute_interactive_line("chcp", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(io.stdout, format!("Active code page: 866{CRLF}"));

        let mut repl_in = InMemoryByteReader::new(b"color 2E\r\nexit\r\n".to_vec());
        let mut repl_out = Vec::new();
        let mut repl_err = Vec::new();
        assert_eq!(
            run_interactive_repl_byte_streams(
                &mut interp,
                &mut repl_in,
                &mut repl_out,
                &mut repl_err
            ),
            Ok(ExitCode::SUCCESS)
        );
        assert!(!repl_out.contains(&0x1B));

        interp.proc_env.dos_kernel = None;
        assert_eq!(
            interp.execute_interactive_line("cls", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.execute_interactive_line("color 0A", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(
            interp.execute_interactive_line("color 2A", &mut io),
            ExitCode::SUCCESS
        );
        interp.console.render_backend = ConsoleRenderBackend::DumbTeletype;
        io.stdout.clear();
        assert_eq!(
            interp.execute_interactive_line("cls", &mut io),
            ExitCode::SUCCESS
        );
        assert_eq!(io.stdout, CRLF);
    }

    /// Verifies `wincmd` & `wincheck` `--dialect`, `/P` `AUTOEXEC.BAT`, `/E:nnnnn`, `/MSG`, and OEM `--encoding` flags.
    #[test]
    fn test_cli_dos_dialect_permanent_autoexec_and_wincheck_dialect() {
        use crate::runtime::{InMemoryByteReader, IoStreams};
        use crate::types::{ExitCode, ExtensionsMode, ShellDialect, VfsBackendMode};

        assert!(parse_wincmd_args(&["--dialect".to_owned()]).is_err());
        assert!(parse_wincmd_args(&["--dialect".to_owned(), "bogus".to_owned()]).is_err());
        assert!(parse_wincmd_args(&["--dialect=bogus".to_owned()]).is_err());
        assert!(parse_wincmd_args(&["/E:99".to_owned()]).is_err());

        let cfg = parse_wincmd_args(&[
            "C:\\DOS".to_owned(),
            "--dialect".to_owned(),
            "dos622".to_owned(),
            "/E:1024".to_owned(),
            "/E:ON".to_owned(),
            "/MSG".to_owned(),
            "/P".to_owned(),
        ]);
        assert!(cfg.is_ok());
        let parsed_cfg = cfg.unwrap_or_default();
        assert_eq!(parsed_cfg.dialect, Some(ShellDialect::MsDos622));
        assert_eq!(parsed_cfg.dos_env_bytes, Some(1024));
        assert_eq!(parsed_cfg.command_dir.as_deref(), Some("C:\\DOS"));

        let mut interp = Interpreter::new();
        assert_eq!(
            interp
                .proc_env
                .vfs
                .write_bytes("C:/AUTOEXEC.BAT", b"@set AUTO_RAN=yes\r\n"),
            Ok(())
        );
        let mut io = IoStreams::with_stdin("echo %AUTO_RAN%\r\n".to_owned());
        assert_eq!(
            run_wincmd_with_config(&parsed_cfg, &mut interp, &mut io),
            Ok(ExitCode::SUCCESS)
        );
        assert!(io.stdout.contains("yes"));
        assert_eq!(interp.proc_env.env.extensions, ExtensionsMode::Enabled);
        assert_eq!(
            interp.lookup_var("COMSPEC").as_deref(),
            Some("C:\\DOS\\COMMAND.COM")
        );

        let mut s_interp = Interpreter::new();
        assert_eq!(
            s_interp
                .proc_env
                .vfs
                .write_bytes("C:/AUTOEXEC.BAT", b"@echo stream_auto\r\n"),
            Ok(())
        );
        let mut s_in = InMemoryByteReader::new(Vec::new());
        let mut s_out = Vec::new();
        let mut s_err = Vec::new();
        assert_eq!(
            execute_wincmd_over_streams(
                &[
                    "--dialect=freedos".to_owned(),
                    "/E:OFF".to_owned(),
                    "/P".to_owned(),
                ],
                VfsBackendMode::InMemoryHermetic,
                &mut s_interp,
                &mut s_in,
                &mut s_out,
                &mut s_err,
            ),
            0
        );
        assert!(String::from_utf8_lossy(&s_out).contains("stream_auto"));

        let mut no_auto_interp = Interpreter::new();
        let mut no_auto_io = IoStreams::new();
        let no_auto_cfg = parse_wincmd_args(&["--dialect=dos622".to_owned(), "/P".to_owned()])
            .unwrap_or_default();
        assert_eq!(
            run_wincmd_with_config(&no_auto_cfg, &mut no_auto_interp, &mut no_auto_io),
            Ok(ExitCode::SUCCESS)
        );
        let mut s_no_auto = Interpreter::new();
        let mut s_in2 = InMemoryByteReader::new(Vec::new());
        let mut s_out2 = Vec::new();
        let mut s_err2 = Vec::new();
        assert_eq!(
            execute_wincmd_over_streams(
                &["/P".to_owned()],
                VfsBackendMode::InMemoryHermetic,
                &mut s_no_auto,
                &mut s_in2,
                &mut s_out2,
                &mut s_err2,
            ),
            0
        );
    }

    /// Verifies `wincheck` `--dialect` and OEM `--encoding` (`cp852`, `cp865`, `cp866`) CLI flags.
    #[test]
    fn test_wincheck_dos_dialect_and_oem_encoding_cli_flags() {
        use crate::runtime::InMemoryByteReader;
        use crate::vfs::{InMemoryVfs, VirtualFileSystem};

        for enc in ["cp852", "cp865", "cp866"] {
            assert!(
                parse_wincheck_args(&["--encoding".to_owned(), enc.to_owned(), "-".to_owned()])
                    .is_ok()
            );
        }
        assert!(parse_wincheck_args(&["--dialect".to_owned()]).is_err());
        assert!(
            parse_wincheck_args(&["--dialect".to_owned(), "bad".to_owned(), "-".to_owned()])
                .is_err()
        );
        assert!(parse_wincheck_args(&["--dialect=dos622".to_owned(), "-".to_owned()]).is_ok());

        let mut wc_vfs = InMemoryVfs::new();
        assert_eq!(
            wc_vfs.write_bytes("C:/BUILD.BAT", b"set /a X=1\r\n"),
            Ok(())
        );
        let mut wc_in = InMemoryByteReader::new(Vec::new());
        let mut wc_out = Vec::new();
        let mut wc_err = Vec::new();
        assert_eq!(
            execute_wincheck_over_vfs_streams(
                &[
                    "--dialect".to_owned(),
                    "dos622".to_owned(),
                    "C:/BUILD.BAT".to_owned(),
                ],
                &mut wc_vfs,
                &mut wc_in,
                &mut wc_out,
                &mut wc_err,
            ),
            1
        );
        assert!(String::from_utf8_lossy(&wc_out).contains("CMD5001"));
    }
}
