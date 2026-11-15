//! `win-cmd-rs` — Cross-platform, 100% compatible Windows Command Prompt (`cmd.exe`) interpreter
//! and `ShellCheck`-style static analysis/linting engine (`wincheck`).
//!
//! # Architecture
//! - [`span`]: Byte offsets, line/column numbers, source spans, and [`span::SourceMap`].
//! - [`types`]: Strongly typed domain primitives (`ExitCode`, `DriveLetter`, `EnvVarName`, `LabelName`, `ForVarName`, `CodePage`).
//! - [`error`]: Unified [`error::CmdError`] enum built with `derive_more`.
//! - [`reader`]: Phase 0 byte-offset script reader, character encodings, and caret line continuations.
//! - [`parser`]: Multi-pass expansion engine (Phases 1–4), `%~` modifiers, variable slicing, and AST/CST parser.
//! - [`vfs`]: Cross-platform Virtual File System (`InMemoryVfs`, `HostOsVfs`), DOS devices (`NUL`, `CON`), and Win32 globbing.
//! - [`runtime`]: Stateful execution engine, `SETLOCAL` environment stack, `SET /A` arithmetic evaluator, and pipelines.
//! - [`builtins`]: 50+ built-in `cmd.exe` commands and cross-platform Windows utility shims.
//! - [`linter`]: `ShellCheck`-style static analysis engine (`CMD0001`–`CMD4010`), inline directives, formatters, and auto-fixer.
//! - [`cli`]: CLI argument parsers and interactive REPL for `wincmd` and `wincheck`.
//!
//! # Examples
//! ```rust
//! use win_cmd_rs::runtime::{Interpreter, IoStreams};
//! use win_cmd_rs::types::ExitCode;
//!
//! let mut interp = Interpreter::new();
//! let mut io = IoStreams::new();
//! assert_eq!(interp.execute_interactive_line("set /a RESULT=6*7", &mut io), ExitCode::SUCCESS);
//! io.stdout.clear();
//! assert_eq!(interp.execute_interactive_line("echo %RESULT%", &mut io), ExitCode::SUCCESS);
//! assert_eq!(io.stdout, "42\r\n");
//! ```

pub mod builtins;
pub mod cli;
pub mod error;
pub mod linter;
pub mod parser;
pub mod reader;
pub mod runtime;
pub mod span;
pub mod types;
pub mod vfs;

#[cfg(doctest)]
/// Compile-and-run doctest harness for `README.md` and `USAGE.md` code examples.
mod markdown_doctests {
    /// Doctest verification for `README.md`.
    #[doc = include_str!("../README.md")]
    struct ReadmeDoctests;

    /// Doctest verification for `USAGE.md`.
    #[doc = include_str!("../USAGE.md")]
    struct UsageDoctests;
}
