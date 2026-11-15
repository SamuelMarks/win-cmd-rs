//! `wincmd` — Cross-platform Windows Command Prompt (`cmd.exe`) CLI entrypoint.
//!
//! Parses command-line arguments (`/C`, `/K`, `/S`, `/Q`, `/D`, `/E:ON`, `/V:ON`, `/T:fg`,
//! `--in-memory`, `--host-native`, `--host-root`, `--script`, `--help`, `--version`) and
//! dispatches to [`win_cmd_rs::cli::execute_wincmd_process`] over live standard I/O streams.

use std::process::ExitCode;

use win_cmd_rs::cli::execute_wincmd_process;

/// Entrypoint for the `wincmd` binary.
///
/// # Returns
/// [`ExitCode`] representing the final process status (`0..=255`).
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdin = std::io::stdin();
    let mut stdin_lock = stdin.lock();
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    ExitCode::from(execute_wincmd_process(
        &args,
        &mut stdin_lock,
        &mut stdout,
        &mut stderr,
    ))
}
