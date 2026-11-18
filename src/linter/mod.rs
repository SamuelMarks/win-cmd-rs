//! `wincheck` — `ShellCheck`-style static analysis and linting engine for Windows Batch scripts.
//!
//! Decomposed into cohesive submodules:
//! - [`rules`] — Rule catalog (`CMD0001`–`CMD4010`), [`Diagnostic`], [`LinterConfig`], [`FixApplicability`].
//! - [`directives`] — Inline `REM wincheck disable=...` suppression directives and encoding checks.
//! - [`passes`] — AST/CST static analysis visitors and modular CST rewrite passes.
//! - [`formatters`] — `TTY`, `GCC`, `JSON`, `SARIF`, and real LCS unified `diff` formatters.
//! - [`rewriter`] — Composable lossless [`CstRewriter`] pipeline.

pub mod directives;
pub mod formatters;
pub mod passes;
pub mod rewriter;
pub mod rules;

pub use crate::linter::formatters::{
    apply_suggested_fixes, format_diagnostics, generate_unified_diff,
};
pub use crate::linter::rules::{
    Diagnostic, FixApplicability, LinterConfig, OutputFormat, RuleId, RuleMetadata, Severity,
    SuggestedFix, all_rule_metadata, explain_rule,
};

use alloc::borrow::ToOwned;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::CmdError;
use crate::linter::directives::{
    SuppressionTable, check_file_encoding_and_lines, convert_peg_diagnostics,
};
use crate::linter::rewriter::CstRewriter;
use crate::parser::peg::{lower_cst_to_ast, parse_script_cst};
use crate::reader::encoding::decode_script_bytes;
use crate::span::{SourceFile, SourceId, SourceMap};
use crate::types::{CodePage, ExecutionContext};
use crate::vfs::VirtualFileSystem;

/// Analyzes a batch script buffer and returns all triggered [`Diagnostic`]s sorted by span.
///
/// # Arguments
/// * `file_name` - Display name or path of the script.
/// * `raw_bytes` - Raw undecoded script bytes.
/// * `config` - [`LinterConfig`] filtering rules and severities.
/// * `source_map` - Mutable [`SourceMap`] to register the file for span formatting.
///
/// # Returns
/// `Ok((SourceId, Vec<Diagnostic>))` containing the registered source ID and filtered diagnostics.
///
/// # Errors
/// Returns [`CmdError`] if UTF-8 script decoding fails fatally.
pub fn lint_script(
    file_name: &str,
    raw_bytes: &[u8],
    config: &LinterConfig,
    source_map: &mut SourceMap,
) -> Result<(SourceId, Vec<Diagnostic>), CmdError> {
    lint_script_with_vfs(file_name, raw_bytes, config, source_map, None)
}

/// Analyzes a batch script buffer with an optional [`VirtualFileSystem`] for `source-path` directives.
///
/// # Arguments
/// * `file_name` - Display name or path of the script.
/// * `raw_bytes` - Raw undecoded script bytes.
/// * `config` - [`LinterConfig`] filtering rules and severities.
/// * `source_map` - Mutable [`SourceMap`] to register the file for span formatting.
/// * `vfs` - Optional [`VirtualFileSystem`] used to resolve `REM wincheck source-path=...` files.
///
/// # Returns
/// `Ok((SourceId, Vec<Diagnostic>))` containing the registered source ID and filtered diagnostics.
///
/// # Errors
/// Returns [`CmdError`] if UTF-8 script decoding fails fatally.
pub fn lint_script_with_vfs(
    file_name: &str,
    raw_bytes: &[u8],
    config: &LinterConfig,
    source_map: &mut SourceMap,
    vfs: Option<&dyn VirtualFileSystem>,
) -> Result<(SourceId, Vec<Diagnostic>), CmdError> {
    let decoded = decode_script_bytes(raw_bytes, config.codepage)?;
    Ok(lint_decoded_script_with_vfs(
        file_name,
        raw_bytes.to_vec(),
        decoded,
        config,
        source_map,
        vfs,
    ))
}

/// Analyzes an already-decoded script string without re-decoding or duplicating [`SourceFile`] allocations.
///
/// # Arguments
/// * `file_name` - Display name or path of the script.
/// * `raw_bytes` - Original raw script bytes stored in [`SourceFile`].
/// * `decoded` - Decoded UTF-8 script text.
/// * `config` - [`LinterConfig`] filtering rules and severities.
/// * `source_map` - Mutable [`SourceMap`] to register the file for span formatting.
///
/// # Returns
/// `(SourceId, Vec<Diagnostic>)` containing the registered source ID and filtered diagnostics.
pub fn lint_decoded_script(
    file_name: &str,
    raw_bytes: Vec<u8>,
    decoded: String,
    config: &LinterConfig,
    source_map: &mut SourceMap,
) -> (SourceId, Vec<Diagnostic>) {
    lint_decoded_script_with_vfs(file_name, raw_bytes, decoded, config, source_map, None)
}

/// Analyzes an already-decoded script string with an optional [`VirtualFileSystem`] for `source-path` directives.
///
/// # Arguments
/// * `file_name` - Display name or path of the script.
/// * `raw_bytes` - Original raw script bytes stored in [`SourceFile`].
/// * `decoded` - Decoded UTF-8 script text.
/// * `config` - [`LinterConfig`] filtering rules and severities.
/// * `source_map` - Mutable [`SourceMap`] to register the file for span formatting.
/// * `vfs` - Optional [`VirtualFileSystem`] used to resolve `REM wincheck source-path=...` files.
///
/// # Returns
/// `(SourceId, Vec<Diagnostic>)` containing the registered source ID and filtered diagnostics.
pub fn lint_decoded_script_with_vfs(
    file_name: &str,
    raw_bytes: Vec<u8>,
    decoded: String,
    config: &LinterConfig,
    source_map: &mut SourceMap,
    vfs: Option<&dyn VirtualFileSystem>,
) -> (SourceId, Vec<Diagnostic>) {
    let source_id = source_map.next_source_id();
    let sf = SourceFile::new(source_id, file_name.to_owned(), raw_bytes, decoded);

    let mut raw_diags = Vec::new();
    let mut suppressions = SuppressionTable::default();
    check_file_encoding_and_lines(&sf, &mut raw_diags, &mut suppressions);

    let external_vars = collect_source_path_vars(
        &sf.name,
        &suppressions.source_paths,
        config.exec_context,
        vfs,
    );
    let cst = parse_script_cst(source_id, &sf.decoded_text, config.exec_context);
    convert_peg_diagnostics(&cst.diagnostics, &mut raw_diags);
    let parsed = lower_cst_to_ast(&cst);
    passes::analyze_parsed_script_with_externals(
        &parsed,
        &sf.decoded_text,
        &external_vars,
        &mut raw_diags,
    );
    passes::dos_compat::analyze_msdos_portability(&sf.name, &parsed, config, &mut raw_diags);

    let mut filtered: Vec<Diagnostic> = raw_diags
        .into_iter()
        .filter(|d| {
            let (line_num, _) = sf.line_col(d.primary_span.start);
            let suppressed_by_line = suppressions.is_suppressed(&d.rule_id, line_num.get());
            let included =
                config.included_rules.is_empty() || config.included_rules.contains(&d.rule_id);
            d.severity >= config.min_severity
                && !config.excluded_rules.contains(&d.rule_id)
                && included
                && !suppressed_by_line
        })
        .collect();

    let _registered = source_map.push_source_file(sf);
    filtered.sort_by_key(|d| (d.primary_span.start, d.rule_id.clone()));
    (source_id, filtered)
}

/// Loads raw bytes for a `source-path` candidate from `vfs` when provided, or from `std::fs` on `std` builds.
///
/// # Arguments
/// * `candidate` - Path resolved relative to the caller script's parent directory.
/// * `raw_sp` - Unmodified `source-path` operand string.
/// * `vfs` - Optional [`VirtualFileSystem`] backend.
///
/// # Returns
/// `Some(Vec<u8>)` when readable, or `None`.
#[must_use]
fn read_sourced_script_bytes(
    candidate: &str,
    raw_sp: &str,
    vfs: Option<&dyn VirtualFileSystem>,
) -> Option<Vec<u8>> {
    if let Some(vfs_ref) = vfs {
        return vfs_ref
            .read_bytes(candidate)
            .or_else(|_| vfs_ref.read_bytes(raw_sp))
            .ok();
    }
    #[cfg(feature = "std")]
    {
        std::fs::read(candidate)
            .or_else(|_| std::fs::read(raw_sp))
            .ok()
    }
    #[cfg(not(feature = "std"))]
    {
        None
    }
}

/// Collects uppercase `SET` variable names defined in external batch scripts referenced by
/// `REM wincheck source-path=<path>` (resolved relative to `caller_file`'s directory or CWD).
///
/// # Arguments
/// * `caller_file` - File name/path of the script being linted.
/// * `source_paths` - Slice of `source-path=` strings declared in directives.
/// * `exec_ctx` - Active [`ExecutionContext`].
/// * `vfs` - Optional [`VirtualFileSystem`] backend.
///
/// # Returns
/// Set of uppercase variable names assigned in readable referenced scripts.
#[must_use]
fn collect_source_path_vars(
    caller_file: &str,
    source_paths: &[String],
    exec_ctx: ExecutionContext,
    vfs: Option<&dyn VirtualFileSystem>,
) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();
    let parent_prefix = caller_file
        .rfind([crate::types::BS_CHAR, '/'])
        .and_then(|idx| caller_file.get(..=idx));
    for sp in source_paths {
        let candidate = parent_prefix.map_or_else(|| sp.clone(), |prefix| format!("{prefix}{sp}"));
        let Some(raw) = read_sourced_script_bytes(&candidate, sp, vfs) else {
            continue;
        };
        let decoded = decode_script_bytes(&raw, CodePage::Utf8).unwrap_or_default();
        let ext_cst = parse_script_cst(SourceId(0), &decoded, exec_ctx);
        let sourced_script = lower_cst_to_ast(&ext_cst);
        let mut ext_diags = Vec::new();
        let mut ext_state = passes::AnalyzerState {
            script_text: &decoded,
            defined_labels: BTreeSet::new(),
            delayed_expansion: crate::types::DelayedExpansionMode::Disabled,
            has_setlocal: false,
            assigned_vars: BTreeMap::new(),
            referenced_vars: BTreeMap::new(),
            current_block_modified_vars: BTreeSet::new(),
            block_depth: 0,
            in_pipeline: false,
            after_robocopy: false,
            diags: &mut ext_diags,
        };
        passes::check_statement_sequence(&sourced_script.statements, &mut ext_state);
        vars.extend(ext_state.assigned_vars.into_keys());
    }
    vars
}

/// Rewrites `original_text` using the composable [`CstRewriter`] pipeline configured by `config`.
///
/// Respects `config.fix_safety` (`RecommendedRepair` by default, `UnsafeOptIn` with `--unsafe-fixes`),
/// `config.included_rules`, `config.excluded_rules`, `config.min_severity`, and inline `REM wincheck` suppressions.
///
/// # Arguments
/// * `original_text` - Original batch script or REPL command line.
/// * `exec_context` - Target [`ExecutionContext`] (`BatchFile` vs `InteractiveRepl`).
/// * `config` - [`LinterConfig`] options.
///
/// # Returns
/// `(rewritten_source, applied_count)` containing the transformed script and number of edits applied.
#[must_use]
pub fn rewrite_script(
    original_text: &str,
    exec_context: ExecutionContext,
    config: &LinterConfig,
) -> (String, usize) {
    let cst = parse_script_cst(SourceId(0), original_text, exec_context);
    let rewriter = CstRewriter::with_config(exec_context, config);
    let outcome = rewriter.rewrite(&cst);
    (outcome.rewritten_source, outcome.applied_count)
}

#[cfg(test)]
/// Unit tests for the `wincheck` linter engine, formatters, directives, and unified diff generator.
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Write as _;

    use super::*;
    use crate::linter::passes::{
        AnalyzerState, scan_word_for_var_reads, smart_quoted_word_replacement,
    };
    use crate::parser::ast::SpannedWord;
    use crate::parser::cst::PegDiagnostic;
    use crate::span::{ByteOffset, Span};
    use crate::types::{
        BS_STR as SEP, CR_CHAR as CR, CRLF, DelayedExpansionMode, LF_CHAR as LF, TAB_CHAR as TAB,
    };

    /// Verifies rule metadata, `--explain`, severity/format parsers, and Myers/LCS unified diffs.
    #[test]
    fn test_rule_metadata_explain_and_lcs_unified_diff() {
        let rules = all_rule_metadata();
        assert!(rules.len() >= 38);
        assert!(explain_rule("CMD2001").is_ok());
        assert!(explain_rule("CMD9999").is_err());

        assert_eq!(
            FixApplicability::default(),
            FixApplicability::RecommendedRepair
        );
        assert_eq!(
            FixApplicability::SafeSemanticsPreserving.to_string(),
            "safe_semantics_preserving"
        );
        assert_eq!(
            FixApplicability::RecommendedRepair.to_string(),
            "recommended_repair"
        );
        assert_eq!(FixApplicability::UnsafeOptIn.to_string(), "unsafe_opt_in");

        assert_eq!(Severity::from_str_name("error"), Some(Severity::Error));
        assert_eq!(Severity::from_str_name("warn"), Some(Severity::Warning));
        assert_eq!(Severity::from_str_name("info"), Some(Severity::Info));
        assert_eq!(Severity::from_str_name("style"), Some(Severity::Style));
        assert_eq!(Severity::from_str_name("bogus"), None);

        assert_eq!(OutputFormat::from_str_name("tty"), Some(OutputFormat::Tty));
        assert_eq!(
            OutputFormat::from_str_name("json"),
            Some(OutputFormat::Json)
        );
        assert_eq!(
            OutputFormat::from_str_name("sarif"),
            Some(OutputFormat::Sarif)
        );
        assert_eq!(OutputFormat::from_str_name("gcc"), Some(OutputFormat::Gcc));
        assert_eq!(OutputFormat::from_str_name("bogus"), None);

        // Real LCS unified diff: 1-line insertion at top of a 10-line file emits a single 4-line hunk!
        let orig_ten = (1..=10).fold(String::new(), |mut acc, i| {
            assert!(write!(acc, "echo line_{i}{LF}").is_ok());
            acc
        });
        let fixed_eleven = format!("SETLOCAL EnableDelayedExpansion{LF}{orig_ten}");
        let top_diff = generate_unified_diff("ten.bat", &orig_ten, &fixed_eleven);
        assert!(top_diff.contains("@@ -1,3 +1,4 @@"));
        assert!(top_diff.contains("+SETLOCAL EnableDelayedExpansion"));
        assert!(!top_diff.contains("echo line_5"));

        // Deletion hunk, pure insertion into empty, multi-hunk separation, and CRLF-vs-LF diff
        let deleted_mid = orig_ten.replace(&format!("echo line_2{LF}"), "");
        let del_diff = generate_unified_diff("ten.bat", &orig_ten, &deleted_mid);
        assert!(del_diff.contains("-echo line_2"));

        let two_hunk_fixed = orig_ten
            .replace(&format!("echo line_1{LF}"), &format!("echo mod_1{LF}"))
            .replace(&format!("echo line_10{LF}"), &format!("echo mod_10{LF}"));
        let two_diff = generate_unified_diff("ten.bat", &orig_ten, &two_hunk_fixed);
        assert!(two_diff.contains("@@ -1,4 +1,4 @@"));
        assert!(two_diff.contains("@@ -7,4 +7,4 @@"));

        let into_empty = generate_unified_diff("e.bat", "", &format!("echo a{LF}"));
        assert!(into_empty.contains("@@ -0,0 +1,1 @@"));
        let from_one_to_empty = generate_unified_diff("e.bat", &format!("echo a{LF}"), "");
        assert!(from_one_to_empty.contains("@@ -1,1 +0,0 @@"));

        let crlf_vs_lf =
            generate_unified_diff("eol.bat", &format!("echo a{CRLF}"), &format!("echo a{LF}"));
        assert!(crlf_vs_lf.contains("@@ -1,1 +1,1 @@"));
    }

    /// Builds a comprehensive batch script triggering all 49 `CMDxxxx` rules.
    ///
    /// # Returns
    /// Synthetic batch script exercising every linter diagnostic rule.
    fn sample_all_rules_bad_script() -> String {
        [
            format!("\u{FEFF}echo missing_at_echo_off{LF}"),
            format!(
                "REM wincheck UnknownDirective disable=CMD9999 enable=CMD4010 source-path=.{CRLF}"
            ),
            format!(":: top-level double colon comment{CRLF}"),
            format!("echo broken_caret ^   {CRLF}"),
            format!("echo %~dpMYVAR% 50%{CRLF}"),
            format!("set SPACED = val{CRLF}"),
            format!("set TRAILING=val   {CRLF}"),
            format!("set ESCAPED=a^&b{CRLF}"),
            format!(r#"set "QUOTED_OK=1"{CRLF}"#),
            format!("echo %QUOTED_OK%{CRLF}"),
            format!("set ERRORLEVEL=0{CRLF}"),
            format!("set UNUSED_VAR=123{CRLF}"),
            format!("echo %UNASSIGNED_VAR%{CRLF}"),
            format!("echo !NO_DELAYED_EXP!{CRLF}"),
            format!(r#"echo "%1"{CRLF}"#),
            format!(r#"echo "Usage: %0 %1"{CRLF}"#),
            format!("echo %PATH%{CRLF}"),
            format!("cd C:{SEP}Windows{CRLF}"),
            format!("cd %PATH%{CRLF}"),
            format!("copy C:{SEP}a.txt C:{SEP}b.txt C:{SEP}ambiguous_dest{CRLF}"),
            format!("move C:{SEP}a.txt C:{SEP}b.txt C:{SEP}ambiguous_dest{CRLF}"),
            format!(r#"rd /s /q "%EMPTY_DIR%{SEP}"{CRLF}"#),
            format!("choice /N /C AB /D Z{CRLF}"),
            format!(r#"set /A "bad=08"{CRLF}"#),
            format!("set /A x=1<<2{CRLF}"),
            format!("set /A m=%DATE:~0,2%{CRLF}"),
            format!("if %PATH% == foo echo unquoted_if{CRLF}"),
            format!("if 1==1 echo no_parens else echo dangling{CRLF}"),
            format!("if not errorlevel 0 echo neg_zero{CRLF}"),
            format!("if errorlevel 0 echo always_true{CRLF}"),
            format!("if not errorlevel 1 (echo n1) else if errorlevel 2 (echo n2){CRLF}"),
            format!("if errorlevel 1 (echo e1) else if errorlevel 2 (echo e2){CRLF}"),
            format!("if errorlevel 2 (echo e2) else if errorlevel 1 (echo e1){CRLF}"),
            format!("if errorlevel 2 (echo e2) else if 1==1 (echo e1){CRLF}"),
            format!("robocopy C:{SEP}a C:{SEP}b{CRLF}"),
            format!("if errorlevel 8 echo robo_err{CRLF}"),
            format!("robocopy C:{SEP}a C:{SEP}b{CRLF}"),
            format!("if errorlevel 1 echo robo_trap{CRLF}"),
            format!("if %PATH% = 1 echo probable_misuse_single_eq{CRLF}"),
            format!("for %s in (a) do echo %s{CRLF}"),
            format!("for %%multi in (a) do echo %%multi{CRLF}"),
            format!(r#"for /F %%L in ("C:{SEP}file.txt") do echo %%L{CRLF}"#),
            format!("for /F %%L in (plain_unquoted.txt) do echo %%L{CRLF}"),
            format!(r#"for /F "usebackq" %%L in ("C:{SEP}file.txt") do echo %%L{CRLF}"#),
            format!("echo a | set PIPED=1{CRLF}"),
            format!("setlocal EnableDelayedExpansion{CRLF}"),
            format!("({CRLF}"),
            format!("    :: comment in block{CRLF}"),
            format!("    echo ^(escaped paren in echo^){CRLF}"),
            format!(r#"    echo "(quoted paren)"{CRLF}"#),
            format!("    echo (unescaped paren in echo){CRLF}"),
            format!("    set BLOCK_VAR=2{CRLF}"),
            format!("    echo !BLOCK_VAR! esc^!{CRLF}"),
            format!("    echo !BLOCK_VAR! bang_in_delayed!{CRLF}"),
            format!("    echo %BLOCK_VAR% %ERRORLEVEL%{CRLF}"),
            format!("    goto :%DYN_LBL%{CRLF}"),
            format!("    goto :!DYN_LBL%{CRLF}"),
            format!("    call :%DYN_SUB%{CRLF}"),
            format!("    call :!DYN_SUB!{CRLF}"),
            format!("    goto :missing_label{CRLF}"),
            format!("){CRLF}"),
            format!("call :missing_sub{CRLF}"),
            format!("other.bat{CRLF}"),
            format!("echo unreachable_after_bat{CRLF}"),
            format!(":dup_label extra_junk{CRLF}"),
            format!(":dup_label{CRLF}"),
            format!("exit 0{CRLF}"),
            format!(r#"for /F %%L in ("unclosed_quote) do echo %%L{CRLF}"#),
        ]
        .concat()
    }

    /// Verifies that every single one of the 49 `CMDxxxx` rules triggers and formats across TTY/GCC/JSON/SARIF.
    #[test]
    fn test_all_lint_rules_trigger_and_formatters() {
        let bad_script = sample_all_rules_bad_script();

        let mut sm = SourceMap::new();
        let cfg = LinterConfig::default();
        let (_, diags) = lint_script("bad.bat", bad_script.as_bytes(), &cfg, &mut sm)
            .unwrap_or((SourceId(0), Vec::new()));

        let triggered_ids: BTreeSet<String> = diags
            .iter()
            .map(|d| d.rule_id.as_str().to_owned())
            .collect();

        for expected in [
            "CMD0001", "CMD1001", "CMD1003", "CMD1004", "CMD1005", "CMD1006", "CMD1007", "CMD1008",
            "CMD1009", "CMD1010", "CMD1011", "CMD1012", "CMD1013", "CMD1014", "CMD2001", "CMD2002",
            "CMD2003", "CMD2004", "CMD2005", "CMD2006", "CMD2007", "CMD2008", "CMD2009", "CMD2010",
            "CMD2011", "CMD2012", "CMD2013", "CMD2014", "CMD3001", "CMD3002", "CMD3003", "CMD3004",
            "CMD3005", "CMD3006", "CMD3007", "CMD3008", "CMD3009", "CMD3010", "CMD3011", "CMD4001",
            "CMD4002", "CMD4003", "CMD4004", "CMD4005", "CMD4006", "CMD4007", "CMD4008", "CMD4009",
            "CMD4010",
        ] {
            assert!(
                triggered_ids.contains(expected),
                "Expected rule {expected} to trigger, got: {triggered_ids:?}"
            );
        }

        let tty = format_diagnostics(&diags, &sm, OutputFormat::Tty);
        let gcc = format_diagnostics(&diags, &sm, OutputFormat::Gcc);
        let json = format_diagnostics(&diags, &sm, OutputFormat::Json);
        let sarif = format_diagnostics(&diags, &sm, OutputFormat::Sarif);
        assert!(tty.contains("CMD2001"));
        assert!(gcc.contains("[CMD2001]"));
        assert!(json.contains(r#""code":"CMD2001""#));
        assert!(sarif.contains(r#""ruleId":"CMD2001""#));

        let (fixed, count) = apply_suggested_fixes(&bad_script, &diags);
        assert!(count > 0);
        let diff = generate_unified_diff("bad.bat", &bad_script, &fixed);
        assert!(diff.contains("--- a/bad.bat"));
        assert_eq!(generate_unified_diff("bad.bat", "same", "same"), "");
    }

    /// Verifies inline `REM wincheck disable=...` and `REM shellcheck disable=...` suppressions.
    #[test]
    fn test_inline_suppressions_and_branch_edges() {
        let suppressed_script = [
            "REM wincheck disable=CMD4006,CMD4005,CMD2004",
            "REM shellcheck disable=CMD2004",
            "set X=1   ",
            "REM wincheck disable=all",
            "echo %X%",
            "",
        ]
        .join(CRLF);
        let mut sm = SourceMap::new();
        let cfg = LinterConfig::default();
        let (_, diags) = lint_script("sup.bat", suppressed_script.as_bytes(), &cfg, &mut sm)
            .unwrap_or((SourceId(0), Vec::new()));
        assert!(diags.is_empty(), "Expected 0 diagnostics, got: {diags:?}");

        let disable_all = format!("REM wincheck disable=all{CRLF}set X = 1{CRLF}");
        let (_, diags_all) = lint_script("all.bat", disable_all.as_bytes(), &cfg, &mut sm)
            .unwrap_or((SourceId(0), Vec::new()));
        assert_eq!(diags_all.len(), 0);

        let broken_syntax = format!("@echo off{CRLF}({CRLF}echo unclosed");
        let (_, diags_syn) = lint_script("syn.bat", broken_syntax.as_bytes(), &cfg, &mut sm)
            .unwrap_or((SourceId(0), Vec::new()));
        assert!(
            diags_syn
                .iter()
                .any(|d| d.rule_id == RuleId::new("CMD1002"))
        );

        let extra_script = [
            "@echo off",
            "setlocal EnableDelayedExpansion",
            "REM wincheck disable=CMD2005",
            "set SUPPRESSED_SPACED = 1",
            "set /P PROMPT_VAR=Enter:",
            "set",
            "set PREFIX_QUERY",
            "echo on & echo off && echo a || echo b",
            "echo %PROMPT_VAR% two_words",
            "echo.%PROMPT_VAR%",
            "if exist %PROMPT_VAR% if defined PROMPT_VAR if cmdextversion 2 echo ok",
            "echo a | setlocal DisableDelayedExpansion",
            &format!("echo a | cd /d C:{SEP}Windows"),
            "cd",
            &format!("del /s C:{SEP}safe.txt %PROMPT_VAR%"),
            &format!("copy %PROMPT_VAR% C:{SEP}dest"),
            r#"for %%I in (1) do set /A "x=%%I+y+1""#,
            "set /A z=%%1",
            r#"for /F %%L in ("plain.txt") do echo %%L"#,
            "choice /C:AB /D C",
            "call :my_sub",
            "echo !PROMPT_VAR! !1+1!",
            "set /P =empty_name",
            "choice /C",
            "choice /D",
            "exit /B 0",
            "goto :eof",
            ":my_sub",
            "exit",
            "",
        ]
        .join(CRLF);

        let mut filter_cfg = LinterConfig {
            min_severity: Severity::Warning,
            excluded_rules: [RuleId::new("CMD3004"), RuleId::new("CMD3009")]
                .into_iter()
                .collect(),
            included_rules: [
                RuleId::new("CMD2005"),
                RuleId::new("CMD2006"),
                RuleId::new("CMD3004"),
                RuleId::new("CMD3010"),
                RuleId::new("CMD4008"),
            ]
            .into_iter()
            .collect(),
            exec_context: ExecutionContext::BatchFile,
            fix_safety: FixApplicability::RecommendedRepair,
            codepage: CodePage::Utf8,
            dialect: crate::types::ShellDialect::WindowsNtCmd,
        };
        let (_, extra_diags) =
            lint_script("extra.bat", extra_script.as_bytes(), &filter_cfg, &mut sm)
                .unwrap_or((SourceId(0), Vec::new()));
        assert!(extra_diags.iter().any(|d| d.rule_id.as_str() == "CMD2006"));
        assert!(apply_suggested_fixes(&extra_script, &extra_diags).1 > 0);
        filter_cfg.included_rules.clear();
    }

    /// Verifies multi-line and unknown-file diagnostic formatting across TTY, JSON, and SARIF.
    #[test]
    fn test_multiline_and_unknown_source_diagnostic_formatting() {
        let mut sm = SourceMap::new();
        let src_body = format!("@echo off{CRLF}setlocal EnableDelayedExpansion{CRLF}");
        let extra_id = sm.add_file(
            "extra.bat".to_owned(),
            src_body.as_bytes().to_vec(),
            src_body,
        );

        let multi_diag = vec![Diagnostic {
            rule_id: RuleId::new("CMD1002"),
            severity: Severity::Info,
            message: format!(r#"msg with "quotes" {SEP} {LF} {CR} {TAB}"#),
            primary_span: Span::new(extra_id, ByteOffset(0), ByteOffset(35)),
            help: None,
            fix: None,
        }];
        let tty_multi = format_diagnostics(&multi_diag, &sm, OutputFormat::Tty);
        assert!(tty_multi.contains("@echo off"));
        let unknown_diag = vec![Diagnostic {
            rule_id: RuleId::new("CMD1002"),
            severity: Severity::Info,
            message: "u".to_owned(),
            primary_span: Span::new(SourceId(99), ByteOffset(0), ByteOffset(1)),
            help: None,
            fix: None,
        }];
        let tty_unk = format_diagnostics(&unknown_diag, &sm, OutputFormat::Tty);
        assert!(tty_unk.contains("<unknown>:1:1"));
        let json_multi = format_diagnostics(&multi_diag, &sm, OutputFormat::Json);
        assert!(json_multi.contains(r#""help":null"#));
        let sarif_multi = format_diagnostics(&multi_diag, &sm, OutputFormat::Sarif);
        assert!(sarif_multi.contains(r#""ruleId":"CMD1002""#));
    }

    /// Verifies REPL linting, `smart_quoted_word_replacement`, and out-of-bounds `SuggestedFix` safety.
    #[test]
    fn test_repl_linting_smart_quoting_and_oob_fix_safety() {
        let mut sm = SourceMap::new();
        let mut custom_diags = Vec::new();
        convert_peg_diagnostics(
            &[PegDiagnostic {
                span: Span::dummy(),
                message: "raw syntax error".to_owned(),
                expected: Vec::new(),
                misuse_kind: None,
                suggested_help: None,
                suggested_replacement: None,
            }],
            &mut custom_diags,
        );
        assert_eq!(custom_diags.len(), 1);

        let more_script = [
            "@echo off",
            "(echo blk) > %OUT_FILE% 2>&1",
            "echo hi 2>&1",
            "cd %1",
            "cd %*",
            r#"cd "%~1""#,
            "for %%I in (a) do cd %%I^&sub",
            "for %%I in (a) do cd %%~I",
            "set X=%%a %~1% %% %unclosed",
            "",
        ]
        .join(CRLF);
        let (_, more_diags) = lint_script(
            "more.bat",
            more_script.as_bytes(),
            &LinterConfig::default(),
            &mut sm,
        )
        .unwrap_or((SourceId(0), Vec::new()));
        assert!(more_diags.iter().any(|d| d.rule_id.as_str() == "CMD2006"));

        let repl_cfg = LinterConfig {
            exec_context: ExecutionContext::InteractiveRepl,
            ..LinterConfig::default()
        };
        let (_, repl_diags) = lint_script(
            "repl.bat",
            format!("for %I in (a) do cd %I{CRLF}").as_bytes(),
            &repl_cfg,
            &mut sm,
        )
        .unwrap_or((SourceId(0), Vec::new()));
        assert!(repl_diags.iter().any(|d| d.rule_id.as_str() == "CMD2006"));
    }

    /// Verifies `smart_quoted_word_replacement` on empty `parts` and out-of-bounds `SuggestedFix` safety.
    #[test]
    fn test_empty_parts_smart_quoting_and_oob_suggested_fixes() {
        let empty_parts_word = SpannedWord::new("%PLAIN%".to_owned(), Span::dummy());
        assert_eq!(
            smart_quoted_word_replacement(&empty_parts_word),
            r#""%PLAIN%""#
        );
        let mut dummy_diags = Vec::new();
        let mut dummy_state = AnalyzerState {
            script_text: "",
            diags: &mut dummy_diags,
            defined_labels: BTreeSet::new(),
            referenced_vars: BTreeMap::new(),
            assigned_vars: BTreeMap::new(),
            has_setlocal: true,
            delayed_expansion: DelayedExpansionMode::Disabled,
            block_depth: 0,
            current_block_modified_vars: BTreeSet::new(),
            in_pipeline: false,
            after_robocopy: false,
        };
        scan_word_for_var_reads(&empty_parts_word, &mut dummy_state);
        assert!(dummy_state.referenced_vars.contains_key("PLAIN"));

        let oob_fix = vec![
            Diagnostic {
                rule_id: RuleId::new("CMD2006"),
                severity: Severity::Warning,
                message: "oob".to_owned(),
                primary_span: Span::dummy(),
                help: None,
                fix: Some(SuggestedFix {
                    description: "oob".to_owned(),
                    span: Span::new(SourceId(0), ByteOffset(50), ByteOffset(60)),
                    replacement: "x".to_owned(),
                }),
            },
            Diagnostic {
                rule_id: RuleId::new("CMD2006"),
                severity: Severity::Warning,
                message: "inverted".to_owned(),
                primary_span: Span::dummy(),
                help: None,
                fix: Some(SuggestedFix {
                    description: "inverted".to_owned(),
                    span: Span {
                        source_id: SourceId(0),
                        start: ByteOffset(3),
                        end: ByteOffset(1),
                    },
                    replacement: "x".to_owned(),
                }),
            },
        ];
        let (res_oob, cnt_oob) = apply_suggested_fixes("short", &oob_fix);
        assert_eq!((res_oob.as_str(), cnt_oob), ("short", 0));

        let mut ctrl_sm = SourceMap::new();
        let ctrl_id = ctrl_sm.add_file(
            "ctrl.bat".to_owned(),
            b"echo \x08\x0c\x1b".to_vec(),
            "echo \x08\x0c\x1b".to_owned(),
        );
        let ctrl_json = format_diagnostics(
            &[Diagnostic {
                rule_id: RuleId::new("CMD0001"),
                severity: Severity::Warning,
                message: "ctrl \x08 \x0c \x1b".to_owned(),
                primary_span: Span::new(ctrl_id, ByteOffset(0), ByteOffset(8)),
                help: None,
                fix: None,
            }],
            &ctrl_sm,
            OutputFormat::Json,
        );
        assert!(ctrl_json.contains(r"\b \f \u001b"));
    }

    /// Verifies `@set` / `@echo` header rules and absence of false positives on clean idiomatic scripts.
    #[test]
    fn test_at_prefix_headers_and_zero_false_positives_on_clean_scripts() {
        let mut sm = SourceMap::new();
        let (_, at_set_diags) = lint_script(
            "at_set.bat",
            format!("@set X=1{CRLF}echo %X%{CRLF}").as_bytes(),
            &LinterConfig::default(),
            &mut sm,
        )
        .unwrap_or((SourceId(0), Vec::new()));
        assert!(at_set_diags.iter().any(|d| d.rule_id.as_str() == "CMD4006"));

        let (_, at_echo_msg_diags) = lint_script(
            "at_echo.bat",
            format!("@echo hello{CRLF}").as_bytes(),
            &LinterConfig::default(),
            &mut sm,
        )
        .unwrap_or((SourceId(0), Vec::new()));
        assert!(
            at_echo_msg_diags
                .iter()
                .any(|d| d.rule_id.as_str() == "CMD4006")
        );

        let clean_branches_script = [
            ":entry_label",
            "@echo off",
            "setlocal EnableDelayedExpansion",
            "set VALID_VAR=ok",
            "if errorlevel %VALID_VAR% echo dyn_errlvl",
            r#"if "%VALID_VAR%"=="ok" echo."#,
            r#"for /F %%I in ("hello world") do echo %%I"#,
            r#"for /F %%I in ("a" b) do echo %%I"#,
            r#"echo "%*""#,
            "goto",
            "goto !VALID_VAR!",
            "goto :defined_lbl",
            ":defined_lbl",
            "call",
            "call helper.exe",
            "call :eof",
            "del temp.txt",
            "cd %~dp0%VALID_VAR%",
            "cd %*%VALID_VAR%",
            "set X=%~dp0% % :%",
            "(",
            "  echo inside_blk",
            "  :lbl_inside_block",
            ")",
            "echo %X%",
            "goto :eof",
            ":sub_after_terminator",
            "exit /b 0",
            "",
        ]
        .join(CRLF);
        let (_, cb_diags) = lint_script(
            "clean_branches.bat",
            clean_branches_script.as_bytes(),
            &LinterConfig::default(),
            &mut sm,
        )
        .unwrap_or((SourceId(0), Vec::new()));
        // Verify no false-positive CMD3005, CMD2003, CMD2007, CMD3001, or CMD4003 fired!
        for absent in ["CMD3005", "CMD2003", "CMD2007", "CMD3001", "CMD4003"] {
            assert!(
                !cb_diags.iter().any(|d| d.rule_id.as_str() == absent),
                "Unexpected false positive {absent} in {cb_diags:?}"
            );
        }
        assert!(cb_diags.iter().any(|d| d.rule_id.as_str() == "CMD2006"));
    }

    /// Verifies `enable=` re-enabling, blank/comment-stacked directives, and `source-path=` imports.
    #[test]
    fn test_directives_enable_stacked_and_source_path_imports() {
        let mut sm = SourceMap::new();
        let tmp_dir = std::env::temp_dir().join(format!("wincheck_sp_{}", std::process::id()));
        assert!(std::fs::create_dir_all(&tmp_dir).is_ok());
        let defs_file = tmp_dir.join("shared_defs.bat");
        assert!(
            std::fs::write(
                &defs_file,
                format!("@echo off{CRLF}set EXT_SHARED=42{CRLF}")
            )
            .is_ok()
        );
        let defs_abs = defs_file.to_string_lossy().into_owned();

        let sp_caller = tmp_dir.join("caller.bat");
        let sp_script = [
            "REM wincheck disable=all",
            "REM wincheck enable=CMD2005",
            "REM wincheck source-path=shared_defs.bat",
            "@echo off",
            "set KEEP_WARN = 1",
            "echo %EXT_SHARED%",
        ]
        .join(CRLF);
        let (_, sp_diags) = lint_script(
            &sp_caller.to_string_lossy(),
            sp_script.as_bytes(),
            &LinterConfig::default(),
            &mut sm,
        )
        .unwrap_or((SourceId(0), Vec::new()));
        assert!(sp_diags.iter().any(|d| d.rule_id.as_str() == "CMD2005"));
        assert!(!sp_diags.iter().any(|d| d.rule_id.as_str() == "CMD2012"));

        let hdr_all = format!(
            "REM wincheck disable=CMD2005 enable=CMD2005{CRLF}REM wincheck enable=all{CRLF}@echo off{CRLF}set H = 1{CRLF}"
        );
        let (_, hdr_diags) = lint_script(
            "hdr_all.bat",
            hdr_all.as_bytes(),
            &LinterConfig::default(),
            &mut sm,
        )
        .unwrap_or((SourceId(0), Vec::new()));
        assert!(hdr_diags.iter().any(|d| d.rule_id.as_str() == "CMD2005"));

        let sp_bare_script = [
            &format!("REM wincheck disable=all source-path=\"{defs_abs}\""),
            "@echo off",
            "REM",
            "",
            "REM wincheck disable=CMD2004",
            "",
            "REM plain comment between directive and statement",
            "set SUPPRESSED_HERE = 1",
            "REM wincheck disable=CMD2005",
            "REMARK_CMD arg",
            "REM wincheck enable=CMD2005",
            "set REENABLED_ONE = 1",
            "REM wincheck enable=all",
            "set REENABLED_ALL=1   ",
            "REM wincheck enable= enable=CMD9999 source-path=\"\" bogus=123",
            "echo %EXT_SHARED% %SUPPRESSED_HERE% %REENABLED_ONE% %REENABLED_ALL%",
            "REM wincheck disable=CMD2005",
        ]
        .join(CRLF);
        let (_, bare_diags) = lint_script(
            "bare_caller.bat",
            sp_bare_script.as_bytes(),
            &LinterConfig::default(),
            &mut sm,
        )
        .unwrap_or((SourceId(0), Vec::new()));
        assert!(bare_diags.iter().any(|d| d.rule_id.as_str() == "CMD2005"));
        assert!(bare_diags.iter().any(|d| d.rule_id.as_str() == "CMD2004"));
        assert_eq!(
            bare_diags
                .iter()
                .filter(|d| d.rule_id.as_str() == "CMD0001")
                .count(),
            4
        );
        assert!(!bare_diags.iter().any(|d| d.rule_id.as_str() == "CMD2012"));
        assert!(std::fs::remove_dir_all(&tmp_dir).is_ok());
    }

    /// Verifies `lint_decoded_script` and `lint_script_with_vfs` resolving `source-path` over `VirtualFileSystem`.
    #[test]
    fn test_lint_decoded_script_and_vfs_source_path() {
        use crate::vfs::VirtualFileSystem as _;
        let mut sm = SourceMap::new();
        let (_, decoded_diags) = lint_decoded_script(
            "direct.bat",
            b"@echo off\r\n".to_vec(),
            "@echo off\r\n".to_owned(),
            &LinterConfig::default(),
            &mut sm,
        );
        assert_eq!(decoded_diags, Vec::new());

        let mut mem_vfs = crate::vfs::InMemoryVfs::new();
        assert!(
            mem_vfs
                .create_dir("C:\\dir", crate::types::DirCreationDepth::CreateParents)
                .is_ok()
        );
        assert!(
            mem_vfs
                .write_bytes("C:\\dir\\defs.bat", b"@echo off\r\nset VFS_SHARED=1\r\n")
                .is_ok()
        );
        assert!(
            mem_vfs
                .write_bytes("C:\\root_defs.bat", b"@echo off\r\nset ROOT_SHARED=1\r\n")
                .is_ok()
        );
        let vfs_caller = format!(
            "@echo off{CRLF}REM wincheck source-path=defs.bat{CRLF}REM wincheck source-path=C:\\root_defs.bat{CRLF}REM wincheck source-path=missing.bat{CRLF}echo \"%VFS_SHARED%\" \"%ROOT_SHARED%\"{CRLF}"
        );
        let (_, vfs_diags) = lint_script_with_vfs(
            "C:\\dir\\caller.bat",
            vfs_caller.as_bytes(),
            &LinterConfig::default(),
            &mut sm,
            Some(&mem_vfs),
        )
        .unwrap_or((SourceId(0), Vec::new()));
        assert_eq!(vfs_diags, Vec::new());
    }

    /// Verifies all 10 MS-DOS `COMMAND.COM` portability lint rules (`CMD5001`–`CMD5010`) and `--explain`.
    #[test]
    fn test_msdos_portability_rules_cmd5001_through_cmd5010() {
        assert_eq!(all_rule_metadata().len(), 60);
        for code in [
            "CMD5001", "CMD5002", "CMD5003", "CMD5004", "CMD5005", "CMD5006", "CMD5007", "CMD5008",
            "CMD5009", "CMD5010",
        ] {
            assert!(explain_rule(code).is_ok());
        }

        let long_tail = "a".repeat(130);
        let script = [
            "@echo off",
            ":: comment line",
            ":sub",
            "set PLAIN=1",
            "set /a X=1+2",
            "set /p ANS=Prompt:",
            "for /l %%I in (1,1,3) do echo %%I",
            "for %%F in (%~1) do echo %%~nF",
            "if \"a\"==\"b\" echo eq",
            "if /i \"%A%\" EQU \"b\" (:inner\r\necho yes) < C:\\in.txt > C:\\out.txt else echo no",
            "if defined FOO echo %FOO:~0,2%",
            "if cmdextversion 2 echo !DELAYED! %*",
            "if exist C:\\longdirectoryname\\file.txt if errorlevel 1 echo ok",
            "echo one & echo two && echo three || echo four",
            "echo pipe_left | copy /y .\\src.txt ..\\verylongdest.html",
            "call",
            "call :sub",
            "call helper.cmd",
            "1:bad",
            "\"quotedok\"",
            "\"\"",
            "app.exe",
            &format!("exttool.exe {long_tail}"),
            "goto",
            "goto sub",
            "goto :EOF",
            "exit 0",
            "exit /b 0",
            "setlocal",
            "echo err 2> C:\\err.log 2>&1",
        ]
        .join(CRLF);

        let mut sm = SourceMap::new();
        let dos_cfg = LinterConfig {
            dialect: crate::types::ShellDialect::MsDos622,
            ..LinterConfig::default()
        };
        let (_, diags_cmd) = lint_script("script.cmd", script.as_bytes(), &dos_cfg, &mut sm)
            .unwrap_or((SourceId(0), Vec::new()));
        let codes: BTreeSet<&str> = diags_cmd.iter().map(|d| d.rule_id.as_str()).collect();
        for expected in [
            "CMD5001", "CMD5002", "CMD5003", "CMD5004", "CMD5005", "CMD5006", "CMD5007", "CMD5008",
            "CMD5009", "CMD5010",
        ] {
            assert!(codes.contains(expected));
        }

        let (_, diags_long_leaf) =
            lint_script("verylongscript.bat", b"@rem\r\n", &dos_cfg, &mut sm)
                .unwrap_or((SourceId(0), Vec::new()));
        assert!(
            diags_long_leaf
                .iter()
                .any(|d| d.rule_id.as_str() == "CMD5009")
        );
        let (_, diags_empty_name) =
            lint_script("", b"@echo off\r\ngoto :EOF\r\n:EOF\r\n", &dos_cfg, &mut sm)
                .unwrap_or((SourceId(0), Vec::new()));
        assert_eq!(diags_empty_name, Vec::new());
        let (_, diags_stdin_name) = lint_script("<stdin>", b"@echo off\r\n", &dos_cfg, &mut sm)
            .unwrap_or((SourceId(0), Vec::new()));
        assert_eq!(diags_stdin_name, Vec::new());

        let mut inc_cfg = LinterConfig::default();
        inc_cfg.included_rules.insert(RuleId::new("CMD5001"));
        let (_, inc_diags) = lint_script("-", b"set /a Z=2\r\n", &inc_cfg, &mut sm)
            .unwrap_or((SourceId(0), Vec::new()));
        assert_eq!(inc_diags.len(), 1);
    }
}
