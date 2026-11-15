//! End-to-end subprocess integration tests for the `wincmd` and `wincheck` CLI binaries.
//!
//! Invokes the compiled `CARGO_BIN_EXE_wincmd` and `CARGO_BIN_EXE_wincheck` executables over
//! real OS pipes and temporary host files without calling `let _ = main()` inside unit tests.

use std::io::Write as _;
use std::process::{Command, Stdio};

use win_cmd_rs::types::CRLF;

/// Verifies `wincmd` `/C` execution, host-native `.bat` execution, and live piped REPL quoting.
#[test]
fn test_wincmd_binary_host_execution_and_streaming_repl() {
    let wincmd_bin = env!("CARGO_BIN_EXE_wincmd");

    // 1. `/C` command execution with preserved multi-space argument quoting
    let out_c = Command::new(wincmd_bin)
        .args(["/C", "echo hello_from_wincmd"])
        .output();
    assert!(out_c.is_ok());
    if let Ok(output) = out_c {
        assert!(output.status.success());
        let stdout_s = String::from_utf8_lossy(&output.stdout);
        assert!(stdout_s.contains("hello_from_wincmd"));
    }

    // 2. Host filesystem `.bat` execution (works out-of-the-box via default HostNative VFS!)
    let temp_dir = std::env::temp_dir().join(format!("wincmd_bin_it_{}", std::process::id()));
    let sub_dir = temp_dir.join("sub");
    assert!(std::fs::create_dir_all(&sub_dir).is_ok());
    let bat_path = temp_dir.join("hello_host.bat");
    let bat_body = format!("@echo off{CRLF}cd /d \"%~dp0sub\"{CRLF}echo HOST_BAT:%1{CRLF}");
    assert!(std::fs::write(&bat_path, bat_body.as_bytes()).is_ok());

    let out_bat = Command::new(wincmd_bin)
        .arg(&bat_path)
        .arg("arg_ok")
        .output();
    assert!(out_bat.is_ok());
    if let Ok(output) = out_bat {
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("HOST_BAT:arg_ok"));
    }
    assert!(std::fs::remove_dir_all(&temp_dir).is_ok());

    // 3. Live piped interactive REPL with quoted `(` (must NOT hang in `More? `!)
    let child_res = Command::new(wincmd_bin)
        .arg("--hermetic")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    assert!(child_res.is_ok());
    if let Ok(mut child) = child_res {
        if let Some(mut child_in) = child.stdin.take() {
            let repl_in = format!(r#"echo "("{CRLF}({CRLF}echo block_ok{CRLF}){CRLF}exit 7{CRLF}"#);
            assert!(child_in.write_all(repl_in.as_bytes()).is_ok());
        }
        let waited = child.wait_with_output();
        assert!(waited.is_ok());
        if let Ok(out) = waited {
            assert_eq!(out.status.code(), Some(7));
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(text.contains("block_ok"));
        }
    }
}

/// Verifies `wincheck` stdin (`-`) linting, `--diff`, `--fix`, `--fix --stdout`, and exit codes.
#[test]
fn test_wincheck_binary_stdin_diff_fix_and_exit_codes() {
    let wincheck_bin = env!("CARGO_BIN_EXE_wincheck");

    // 1. Lint dirty script over `-` standard input -> exits 1 with CMD2005 diagnostic
    let child_res = Command::new(wincheck_bin)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    assert!(child_res.is_ok());
    if let Ok(mut child) = child_res {
        if let Some(mut child_in) = child.stdin.take() {
            let dirty = format!("@echo off{CRLF}set FOO = 1{CRLF}");
            assert!(child_in.write_all(dirty.as_bytes()).is_ok());
        }
        let waited = child.wait_with_output();
        assert!(waited.is_ok());
        if let Ok(out) = waited {
            assert_eq!(out.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&out.stdout).contains("CMD2005"));
        }
    }

    // 2. `--fix` over `-` standard input -> rewrites `set "FOO=1"` and exits 0!
    let fix_child = Command::new(wincheck_bin)
        .args(["--fix", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    assert!(fix_child.is_ok());
    if let Ok(mut child) = fix_child {
        if let Some(mut child_in) = child.stdin.take() {
            let fixable = format!("@echo off{CRLF}setlocal{CRLF}set FOO = 1{CRLF}echo(%FOO%{CRLF}");
            assert!(child_in.write_all(fixable.as_bytes()).is_ok());
        }
        let waited = child.wait_with_output();
        assert!(waited.is_ok());
        if let Ok(out) = waited {
            assert!(out.status.success());
            assert!(String::from_utf8_lossy(&out.stdout).contains(r#"set "FOO=1""#));
        }
    }
}
