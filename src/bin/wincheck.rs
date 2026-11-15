//! `wincheck` — `ShellCheck`-style static analysis and linting CLI for Windows Batch (`.bat` / `.cmd`).
//!
//! Parses command-line options (`--format`, `--severity`, `--include`, `--exclude`, `--explain`,
//! `--list-rules`, `--diff`, `--fix`, `--help`, `--version`, and `"-"` stdin) and dispatches to
//! [`win_cmd_rs::cli::execute_wincheck_process`] over live standard I/O streams.

use std::process::ExitCode;

use win_cmd_rs::cli::execute_wincheck_process;

/// Entrypoint for the `wincheck` binary.
///
/// # Returns
/// [`ExitCode`] representing the final linter status (`0` when clean/fixed, `1` otherwise).
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    ExitCode::from(execute_wincheck_process(
        &args,
        &mut stdin,
        &mut stdout,
        &mut stderr,
    ))
}
