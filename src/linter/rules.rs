//! Rule catalog, diagnostic types, and configuration for the `wincheck` linter.
//!
//! Defines [`RuleId`], [`Severity`], [`OutputFormat`], [`FixApplicability`], [`SuggestedFix`],
//! [`Diagnostic`], [`RuleMetadata`], [`LinterConfig`], and the 50-rule catalog (`CMD0001`–`CMD4010`).

use std::collections::BTreeSet;

use derive_more::{Display, IsVariant};

use crate::error::CmdError;
use crate::span::Span;
use crate::types::{CodePage, ExecutionContext};

/// Strongly typed identifier for a linter rule (e.g., `RuleId::new("CMD2001")`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[display("{_0}")]
pub struct RuleId(
    /// Canonical uppercase rule identifier string (`"CMD0001"`..`"CMD4010"`).
    pub String,
);

impl RuleId {
    /// Creates a normalized uppercase [`RuleId`].
    ///
    /// # Arguments
    /// * `code` - Rule code string (e.g., `"cmd2001"` or `"CMD2001"`).
    ///
    /// # Returns
    /// Normalized [`RuleId`].
    #[must_use]
    pub fn new(code: &str) -> Self {
        Self(code.trim().to_ascii_uppercase())
    }

    /// Returns the string slice of this rule ID.
    ///
    /// # Returns
    /// `&str` representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Diagnostic severity level (`Error > Warning > Info > Style`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display, IsVariant)]
pub enum Severity {
    /// Style or formatting suggestion.
    #[display("style")]
    Style,
    /// Informational note or portability advice.
    #[display("info")]
    Info,
    /// Likely bug or unintended behavior.
    #[display("warning")]
    Warning,
    /// Definite syntax bug or broken runtime behavior.
    #[display("error")]
    Error,
}

impl Severity {
    /// Parses a severity name (`"error"`, `"warning"`, `"info"`, `"style"`).
    ///
    /// # Arguments
    /// * `raw` - Severity string.
    ///
    /// # Returns
    /// `Some(Severity)` if valid, else `None`.
    #[must_use]
    pub fn from_str_name(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "error" | "err" => Some(Self::Error),
            "warning" | "warn" => Some(Self::Warning),
            "info" | "information" => Some(Self::Info),
            "style" => Some(Self::Style),
            _ => None,
        }
    }

    /// Maps this severity to a SARIF v2.1.0 level string (`"error"`, `"warning"`, `"note"`).
    ///
    /// # Returns
    /// SARIF level string.
    #[must_use]
    pub const fn sarif_level(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info | Self::Style => "note",
        }
    }
}

/// Safety tier controlling which auto-fixes are applied by `--fix` and previewed by `--diff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Display, IsVariant)]
pub enum FixApplicability {
    /// Strictly semantics-preserving normalizations (`SET a^&b` -> `SET "a&b"`, `::` in block -> `REM`,
    /// smart path quoting `"%VAR%"` / `"%~1"`, and `%` <-> `%%` dialect conversions).
    #[display("safe_semantics_preserving")]
    SafeSemanticsPreserving,
    /// Recommended bug-repair rewrites enabled by default in `wincheck --fix` (includes
    /// [`Self::SafeSemanticsPreserving`] plus intentional bug repairs such as `CMD2001`/`CMD2009`
    /// `!VAR!`, `CMD2004`/`CMD2005` whitespace-trimming `SET`, `CMD3003` `CALL`, `CMD4001` `CD /D`,
    /// `CMD4002` `ECHO(`, `CMD1004`, `CMD1005`, and `CMD1013`, while still guarding literal `!` safety).
    #[default]
    #[display("recommended_repair")]
    RecommendedRepair,
    /// Also apply opt-in potentially disruptive rewrites (`--unsafe-fixes`: `CMD3004` `EXIT` -> `EXIT /B`,
    /// and injecting `SETLOCAL EnableDelayedExpansion` even when literal `!` tokens exist).
    #[display("unsafe_opt_in")]
    UnsafeOptIn,
}

/// A source-code replacement suggested by a lint rule (`--fix` / `--diff`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestedFix {
    /// Human-readable description of the fix.
    pub description: String,
    /// Span in the original file to replace.
    pub span: Span,
    /// Replacement text.
    pub replacement: String,
}

/// A single static analysis diagnostic emitted by `wincheck`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Rule identifier (`CMD0001`..`CMD4010`).
    pub rule_id: RuleId,
    /// Diagnostic severity.
    pub severity: Severity,
    /// Concise diagnostic message.
    pub message: String,
    /// Primary source span where the issue occurred.
    pub primary_span: Span,
    /// Optional actionable help note.
    pub help: Option<String>,
    /// Optional automatic fix.
    pub fix: Option<SuggestedFix>,
}

/// Metadata descriptor for a rule in the `wincheck` catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMetadata {
    /// Rule identifier (`CMDxxxx`).
    pub id: RuleId,
    /// Default severity level.
    pub severity: Severity,
    /// Short kebab-case rule name.
    pub name: &'static str,
    /// One-line summary.
    pub summary: &'static str,
    /// Detailed explanation with bad/good examples for `--explain`.
    pub explanation: &'static str,
}

/// Output format for `wincheck` diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Display, IsVariant)]
pub enum OutputFormat {
    /// Human-readable Rustc/ShellCheck-style terminal output with source snippets and carets.
    #[default]
    #[display("tty")]
    Tty,
    /// Structured JSON array output.
    #[display("json")]
    Json,
    /// SARIF v2.1.0 static analysis schema output.
    #[display("sarif")]
    Sarif,
    /// Compact `file:line:col: severity: message [CMDxxxx]` GCC format.
    #[display("gcc")]
    Gcc,
}

impl OutputFormat {
    /// Parses an output format name (`"tty"`, `"json"`, `"sarif"`, `"gcc"`).
    ///
    /// # Arguments
    /// * `raw` - Format string.
    ///
    /// # Returns
    /// `Some(OutputFormat)` if recognized, else `None`.
    #[must_use]
    pub fn from_str_name(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "tty" | "text" => Some(Self::Tty),
            "json" => Some(Self::Json),
            "sarif" => Some(Self::Sarif),
            "gcc" => Some(Self::Gcc),
            _ => None,
        }
    }
}

/// Configuration options for running the `wincheck` linter and CST rewriter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinterConfig {
    /// Minimum severity threshold to report (defaults to [`Severity::Style`]).
    pub min_severity: Severity,
    /// Explicitly disabled rule IDs (`--exclude`).
    pub excluded_rules: BTreeSet<RuleId>,
    /// Explicitly enabled rule IDs (`--include`; if non-empty, only these rules + non-excluded run).
    pub included_rules: BTreeSet<RuleId>,
    /// Target execution context (`BatchFile` vs `InteractiveRepl`).
    pub exec_context: ExecutionContext,
    /// Auto-fix safety tier (`RecommendedRepair` by default; `UnsafeOptIn` with `--unsafe-fixes`).
    pub fix_safety: FixApplicability,
    /// Fallback [`CodePage`] used when decoding input scripts without a UTF-16 BOM (`Utf8` by default).
    pub codepage: CodePage,
}

impl Default for LinterConfig {
    /// Returns the default [`LinterConfig`] (`Severity::Style`, `BatchFile`, `RecommendedRepair`, `CodePage::Utf8`).
    ///
    /// # Returns
    /// Default [`LinterConfig`].
    fn default() -> Self {
        Self {
            min_severity: Severity::Style,
            excluded_rules: BTreeSet::new(),
            included_rules: BTreeSet::new(),
            exec_context: ExecutionContext::BatchFile,
            fix_safety: FixApplicability::RecommendedRepair,
            codepage: CodePage::Utf8,
        }
    }
}

/// Looks up the default catalog [`Severity`] for a rule code (`"CMD0001"`..`"CMD4010"`).
///
/// # Arguments
/// * `code` - Rule identifier string.
///
/// # Returns
/// Catalog [`Severity`] if found, or [`Severity::Warning`] as fallback.
#[must_use]
pub fn rule_default_severity(code: &str) -> Severity {
    RULE_CATALOG_ENTRIES
        .iter()
        .find(|&&(id, _, _, _, _)| id.eq_ignore_ascii_case(code))
        .map_or(Severity::Warning, |&(_, sev, _, _, _)| sev)
}

/// Constructs a single [`RuleMetadata`] entry concisely.
///
/// # Arguments
/// * `code` - Canonical rule code (`"CMDxxxx"`).
/// * `severity` - Default [`Severity`].
/// * `name` - Short kebab-case rule name.
/// * `summary` - Concise summary line.
/// * `explanation` - Detailed explanation for `--explain`.
///
/// # Returns
/// Populated [`RuleMetadata`].
#[must_use]
fn rule_meta(
    code: &str,
    severity: Severity,
    name: &'static str,
    summary: &'static str,
    explanation: &'static str,
) -> RuleMetadata {
    RuleMetadata {
        id: RuleId::new(code),
        severity,
        name,
        summary,
        explanation,
    }
}

/// Static table of `(code, severity, name, summary, explanation)` entries for all `wincheck` rules.
const RULE_CATALOG_ENTRIES: &[(&str, Severity, &str, &str, &str)] = &[
    (
        "CMD0001",
        Severity::Warning,
        "invalid-directive",
        "Unrecognized or malformed wincheck inline directive.",
        "Use `REM wincheck disable=CMD2001,CMD2003` or `REM wincheck disable=all`.",
    ),
    (
        "CMD1001",
        Severity::Error,
        "double-colon-in-block",
        "`::` label comment used inside a `( ... )` parenthesized block.",
        "In `cmd.exe`, `::` inside `(...)` breaks block parsing if placed on the last line or before another label. Use `REM` instead.",
    ),
    (
        "CMD1002",
        Severity::Error,
        "unbalanced-parentheses",
        "Unbalanced or unclosed `(` or `)` in command block.",
        "Ensure every opening `(` has a matching unescaped `)`.",
    ),
    (
        "CMD1003",
        Severity::Error,
        "unescaped-paren-in-block",
        "Unescaped `)` inside `ECHO` or command arguments inside a `( ... )` block.",
        "Unquoted `)` inside `ECHO text (foo)` inside a block prematurely closes the block. Escape it as `^)`.",
    ),
    (
        "CMD1004",
        Severity::Warning,
        "trailing-whitespace-after-caret",
        "Trailing whitespace after `^` line continuation.",
        "A `^` followed by spaces before a newline escapes the first space rather than the newline. Remove trailing spaces after `^`.",
    ),
    (
        "CMD1005",
        Severity::Error,
        "dangling-else",
        "`ELSE` keyword is not preceded by a parenthesized `(` ... `)` then-branch.",
        "`cmd.exe` only recognizes `ELSE` when the `IF` body is enclosed in parentheses: `IF cond (cmd1) ELSE (cmd2)`.",
    ),
    (
        "CMD1006",
        Severity::Error,
        "multi-char-for-var",
        "`FOR` loop variable must be a single character (e.g., `%%I`).",
        "`cmd.exe` `FOR` variables are single ASCII characters like `%%I` or `%%a`, not `%%item`.",
    ),
    (
        "CMD1007",
        Severity::Error,
        "single-percent-for-var",
        "Single `%I` used for `FOR` variable in a batch script instead of `%%I`.",
        "Inside `.bat`/`.cmd` files, `FOR` variables require double percent signs (`%%I`).",
    ),
    (
        "CMD1008",
        Severity::Warning,
        "utf8-bom",
        "UTF-8 Byte Order Mark (`EF BB BF`) at the start of batch script.",
        "When `cmd.exe` runs under an OEM codepage, a UTF-8 BOM corrupts the first command on line 1. Save as UTF-8 without BOM.",
    ),
    (
        "CMD1009",
        Severity::Info,
        "non-crlf-line-endings",
        "Script uses Unix `LF` or mixed line endings instead of Windows `CRLF`.",
        "`cmd.exe` seeks by byte offset for `GOTO` and `CALL :label`; non-CRLF endings can cause label-offset corruption.",
    ),
    (
        "CMD1010",
        Severity::Error,
        "invalid-set-a-expression",
        "Invalid `SET /A` arithmetic expression syntax or malformed octal (`08`/`09`).",
        "Check for missing operands, unbalanced parentheses, or leading-zero octal numbers `08`/`09` in `SET /A`.",
    ),
    (
        "CMD1011",
        Severity::Warning,
        "unquoted-set-a-special",
        "Unquoted bitwise shift/logic operators (`<<`, `>>`, `&`, `|`, `^`) in `SET /A`.",
        r#"Wrap the entire `SET /A "x=1<<2"` expression in double quotes so `cmd.exe` does not interpret `<`, `>`, `&`, `|` as redirections or pipes."#,
    ),
    (
        "CMD1012",
        Severity::Warning,
        "invalid-label-characters",
        "Label definition contains spaces or delimiter characters after the label name.",
        "`cmd.exe` ignores or truncates characters after the first space/delimiter in `:label name`.",
    ),
    (
        "CMD1013",
        Severity::Error,
        "probable-syntax-misuse",
        r#"Probable syntax misuse (`IF a = b`, `IF (a == b)`, missing `IN`/`DO` in `FOR`, unclosed `"`)."#,
        "Common syntax mistakes such as single `=` in `IF` conditions, C-style parentheses around `IF` conditions, missing `IN` or `DO` keywords in `FOR` loops, or unclosed quotes will fail or misbehave in `cmd.exe`.",
    ),
    (
        "CMD1014",
        Severity::Warning,
        "execution-mode-percent-mismatch",
        "Mismatch between single `%` (REPL mode) and double `%%` (batch file mode).",
        "Batch files (`.bat`/`.cmd`) require `%%I` for `FOR` variables and `%%` for literal percent signs, whereas interactive REPL / `cmd /C` requires single `%I` and `%`.",
    ),
    (
        "CMD2001",
        Severity::Error,
        "stale-percent-var-in-block",
        "Variable is modified via `SET` and read via `%VAR%` inside the same `( ... )` block.",
        "`%VAR%` is expanded once when the entire `(...)` block is read, so it evaluates to the stale value from before the block. Enable `SETLOCAL EnableDelayedExpansion` and use `!VAR!`.",
    ),
    (
        "CMD2002",
        Severity::Warning,
        "delayed-expansion-not-enabled",
        "`!VAR!` used without `SETLOCAL EnableDelayedExpansion` enabled in scope.",
        "`!VAR!` will not expand unless `SETLOCAL EnableDelayedExpansion` (or `cmd /V:ON`) is active.",
    ),
    (
        "CMD2003",
        Severity::Warning,
        "unquoted-if-comparison",
        "Unquoted variable or parameter in `IF` comparison.",
        r#"If `%VAR%` or `%1` is empty or contains spaces, `IF %VAR%==foo` fails with a syntax error. Quote both sides: `IF "%VAR%"=="foo"`."#,
    ),
    (
        "CMD2004",
        Severity::Warning,
        "trailing-whitespace-in-set",
        "Unquoted `SET VAR=value ` has trailing spaces that become part of the variable's value.",
        r#"In `SET VAR=foo & echo`, the space before `&` is stored inside `VAR`! Use `SET "VAR=value"`."#,
    ),
    (
        "CMD2005",
        Severity::Warning,
        "spaces-around-set-equals",
        r#"Spaces around `=` in `SET VAR = value` create a variable named `"VAR "`."#,
        r#"`cmd.exe` includes spaces before `=` in the variable name and spaces after `=` in its value. Write `SET "VAR=value"`."#,
    ),
    (
        "CMD2006",
        Severity::Warning,
        "unquoted-path-argument",
        "Unquoted variable/parameter path passed to file/directory command.",
        r#"Paths containing spaces will split into multiple arguments unless quoted: `"%VAR%"` or `"%~1"`."#,
    ),
    (
        "CMD2007",
        Severity::Warning,
        "double-quoted-positional-arg",
        r#"Quoting `"%1"` instead of `"%~1"` risks doubling quotes (`""path""`)."#,
        r#"Use `"%~1"` to strip any existing outer quotes before adding quotes."#,
    ),
    (
        "CMD2008",
        Severity::Warning,
        "unescaped-special-in-set",
        "Unquoted special characters in `SET` assignment.",
        r#"Wrap `SET "VAR=a&b"` in double quotes so `&`, `|`, `<`, `>` are not parsed as operators."#,
    ),
    (
        "CMD2009",
        Severity::Error,
        "stale-dynamic-var-in-block",
        "Reading `%ERRORLEVEL%`, `%RANDOM%`, or `%TIME%` via `%` inside a `( ... )` block.",
        "Dynamic variables expanded via `%...%` inside `(...)` freeze at their pre-block value. Use `!ERRORLEVEL!` / `!RANDOM!` with Delayed Expansion.",
    ),
    (
        "CMD2010",
        Severity::Warning,
        "shadowing-dynamic-variable",
        "Assigning to dynamic pseudo-variable (`CD`, `DATE`, `TIME`, `RANDOM`, `ERRORLEVEL`).",
        "Running `SET ERRORLEVEL=0` or `SET RANDOM=1` permanently shadows the dynamic pseudo-variable with a static value!",
    ),
    (
        "CMD2011",
        Severity::Info,
        "unescaped-bang-in-delayed-expansion",
        "Unescaped `!` in `ECHO` text while `EnableDelayedExpansion` is active.",
        "When delayed expansion is enabled, `!` is consumed as a variable delimiter even inside double quotes. Escape literal exclamation marks as `^!`.",
    ),
    (
        "CMD2012",
        Severity::Warning,
        "unassigned-variable-reference",
        "Variable is referenced but never assigned in this script.",
        "Check for typos in variable names or ensure the variable is initialized before use.",
    ),
    (
        "CMD2013",
        Severity::Info,
        "unused-variable-assignment",
        "Variable is assigned via `SET` but never read in this script.",
        "Remove dead `SET` assignments or export them intentionally before `ENDLOCAL`.",
    ),
    (
        "CMD2014",
        Severity::Warning,
        "invalid-modifier-on-env-var",
        "Path modifier `%~dpVAR%` used on a named environment variable instead of `%0`–`%9` or `%%I`.",
        "`%~` path modifiers only work on batch parameters (`%~dp0`) and `FOR` variables (`%%~nxI`), not environment variables.",
    ),
    (
        "CMD3001",
        Severity::Error,
        "missing-goto-label",
        "`GOTO` or `CALL` targets a `:label` that does not exist in the script.",
        "Define `:label` in the script or check for spelling mistakes.",
    ),
    (
        "CMD3002",
        Severity::Warning,
        "duplicate-label",
        "Duplicate `:label` definition in the same script.",
        "`cmd.exe` scans from the current position and jumps to the first matching `:label`, making duplicate labels error-prone.",
    ),
    (
        "CMD3003",
        Severity::Warning,
        "batch-invoked-without-call",
        "Invoking another `.bat`/`.cmd` script without `CALL` transfers control permanently.",
        "Without `CALL`, the current batch script terminates immediately when the child script finishes. Prepend `CALL `.",
    ),
    (
        "CMD3004",
        Severity::Warning,
        "exit-without-b",
        "`EXIT` without `/B` closes the entire `cmd.exe` console session.",
        "Use `EXIT /B [code]` to exit only the current batch script or subroutine.",
    ),
    (
        "CMD3005",
        Severity::Warning,
        "subroutine-fallthrough",
        "Execution falls through into a `:subroutine` label without a preceding `EXIT /B` or `GOTO :EOF`.",
        "Add `EXIT /B` or `GOTO :EOF` before subroutine definitions at the bottom of a script.",
    ),
    (
        "CMD3006",
        Severity::Warning,
        "unreachable-code",
        "Unreachable command after unconditional `GOTO` or `EXIT`.",
        "Commands immediately following `GOTO` or `EXIT` without a `:label` can never execute.",
    ),
    (
        "CMD3007",
        Severity::Error,
        "if-errorlevel-zero",
        "`IF ERRORLEVEL 0` is always true for any non-negative exit code (`ERRORLEVEL >= 0`).",
        "`IF ERRORLEVEL N` tests `ERRORLEVEL >= N`. To test for zero, use `IF %ERRORLEVEL% EQU 0` or `IF NOT ERRORLEVEL 1`.",
    ),
    (
        "CMD3008",
        Severity::Warning,
        "ascending-errorlevel-checks",
        "`IF ERRORLEVEL` checked in ascending order masks higher thresholds.",
        "Because `IF ERRORLEVEL 1` matches all codes `>= 1`, a subsequent `ELSE IF ERRORLEVEL 2` is dead code. Check highest numbers first.",
    ),
    (
        "CMD3009",
        Severity::Warning,
        "goto-inside-block",
        "`GOTO` used inside a `FOR` loop or parenthesized block.",
        "Jumping via `GOTO` inside a `FOR` loop cancels loop iteration state and can corrupt block parsing if jumping to a label inside a block.",
    ),
    (
        "CMD3010",
        Severity::Warning,
        "state-mutation-in-pipe",
        "`SET` or `CD` inside a pipeline `|` executes in a child subshell and is lost.",
        "Each side of `cmd1 | cmd2` runs in a separate `cmd.exe` process. Use `FOR /F` to capture output into parent variables.",
    ),
    (
        "CMD3011",
        Severity::Info,
        "robocopy-errorlevel-trap",
        "`ROBOCOPY` exit codes `0`–`7` indicate success (`1` means files copied).",
        "Checking `IF ERRORLEVEL 1` after `ROBOCOPY` treats successful file copies as failures! Check `IF ERRORLEVEL 8` instead.",
    ),
    (
        "CMD4001",
        Severity::Warning,
        "cd-without-d-switch",
        "`CD X:/path` with a drive letter but without `/D` does not switch the active drive.",
        "Use `CD /D X:/path` (or `PUSHD X:/path`) to change both the drive and working directory.",
    ),
    (
        "CMD4002",
        Severity::Warning,
        "echo-possibly-empty-var",
        "`ECHO %VAR%` prints `ECHO is off.` if `%VAR%` expands to empty or whitespace.",
        "Use `ECHO(%VAR%` or `ECHO.%VAR%` to safely print a blank line when the variable is empty.",
    ),
    (
        "CMD4003",
        Severity::Warning,
        "for-f-quoted-string-without-usebackq",
        r#"`FOR /F` with double-quoted path `("C:/file.txt")` without `usebackq` parses the path as a string literal."#,
        r#"Add `"usebackq"` to `FOR /F` options when quoting file paths inside `IN ("...")`."#,
    ),
    (
        "CMD4004",
        Severity::Error,
        "dangerous-root-delete",
        "Dangerous `RD /S /Q` or `DEL /S /Q` with `%VAR%/` resolves to root if `VAR` is unset!",
        "If `VAR` is empty, `RD /S /Q` with a trailing backslash wipes the entire drive! Validate `IF DEFINED VAR` first.",
    ),
    (
        "CMD4005",
        Severity::Info,
        "missing-setlocal",
        "Script modifies environment variables via `SET` without `SETLOCAL`.",
        "Add `SETLOCAL` near the top of the script so environment variables do not leak into the caller's session.",
    ),
    (
        "CMD4006",
        Severity::Style,
        "missing-echo-off",
        "Batch script does not begin with `@ECHO OFF`.",
        "Start batch scripts with `@echo off` to prevent echoing every command to stdout.",
    ),
    (
        "CMD4007",
        Severity::Warning,
        "octal-date-time-in-set-a",
        "Using `%DATE%` or `%TIME%` substrings in `SET /A` risks octal `08`/`09` errors.",
        "Months/days/hours `08` and `09` have a leading `0` and fail as invalid octal in `SET /A`. Strip leading zeros or use `1%var%-100`.",
    ),
    (
        "CMD4008",
        Severity::Warning,
        "choice-default-not-in-choices",
        "`CHOICE /D` default key is not present in the `/C` choice list.",
        "Ensure the `/D` default character is one of the characters specified in `/C`.",
    ),
    (
        "CMD4009",
        Severity::Warning,
        "ambiguous-multifile-copy-dest",
        "`COPY` or `MOVE` with multiple sources into a destination not ending with a directory separator.",
        "Append a trailing backslash to the destination directory when copying or moving multiple files so `cmd.exe` does not treat a missing destination as a file.",
    ),
    (
        "CMD4010",
        Severity::Style,
        "prefer-rem-over-double-colon",
        "Prefer standard `REM` over `::` label-comment syntax.",
        "`::` is a degenerate label rather than a true comment command and can misbehave around blocks or line continuations. Prefer `REM`.",
    ),
];

/// Returns the complete catalog of all `wincheck` rules (`CMD0001`–`CMD4010`).
///
/// # Returns
/// Vector of [`RuleMetadata`] descriptors for every rule in the linter.
#[must_use]
pub fn all_rule_metadata() -> Vec<RuleMetadata> {
    RULE_CATALOG_ENTRIES
        .iter()
        .map(|&(code, sev, name, summary, explanation)| {
            rule_meta(code, sev, name, summary, explanation)
        })
        .collect()
}

/// Looks up the [`RuleMetadata`] for `rule_id` (`--explain CMDxxxx`).
///
/// # Arguments
/// * `rule_id` - Rule code string (e.g., `"CMD2001"`).
///
/// # Returns
/// `Ok(RuleMetadata)` if found.
///
/// # Errors
/// Returns [`CmdError::LinterRuleNotFound`] if the rule code is not in the catalog.
pub fn explain_rule(rule_id: &str) -> Result<RuleMetadata, CmdError> {
    let target = RuleId::new(rule_id);
    all_rule_metadata()
        .into_iter()
        .find(|m| m.id == target)
        .ok_or_else(|| CmdError::LinterRuleNotFound {
            rule_id: rule_id.to_owned(),
        })
}
