//! Integration tests verifying the `wincmd` (`WINCMD.EXE`) and `wincheck` (`WINCHECK.EXE`)
//! binaries inside `crates/wincmd-dos`.

use std::process::Command;

/// Verifies `wincmd /C ver` and `wincheck --explain CMD5001` exit with status `0`.
#[test]
fn test_wincmd_dos_and_wincheck_dos_binaries() {
    let wincmd_out = Command::new(env!("CARGO_BIN_EXE_wincmd"))
        .args(["/C", "ver"])
        .output();
    assert!(wincmd_out.is_ok());
    if let Ok(out) = wincmd_out {
        assert_eq!(out.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&out.stdout).contains("MS-DOS"));
    }

    let wincheck_out = Command::new(env!("CARGO_BIN_EXE_wincheck"))
        .args(["--explain", "CMD5001"])
        .output();
    assert!(wincheck_out.is_ok());
    if let Ok(out) = wincheck_out {
        assert_eq!(out.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&out.stdout).contains("CMD5001"));
    }
}
