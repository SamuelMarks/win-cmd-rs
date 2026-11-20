//! AST & CST static analysis passes and CST tree-rewriter pass modules.
//!
//! Contains the static analysis visitor (`analyze_parsed_script_with_externals`) covering `CMD1001`–`CMD4010`
//! with zero `std::convert::identity` branch-masking tricks, plus the five modular CST
//! rewrite pass implementations (`delayed_exp`, `dialect`, `dos_compat`, `quoting`, `structural`).

pub mod delayed_exp;
pub mod dialect;
pub mod dos_compat;
pub mod quoting;
pub mod structural;

use alloc::borrow::ToOwned;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::linter::directives::WELL_KNOWN_ENV_VARS;
use crate::linter::rules::{Diagnostic, RuleId, Severity, SuggestedFix};
use crate::parser::ast::{
    CommandExpr, CompoundBlock, ForStatement, ForVariant, IfCondition, IfStatement, ParsedScript,
    RedirectionKind, SimpleCommand, SpannedWord, Statement, WordPartKind,
};
use crate::runtime::arithmetic::evaluate_set_a;
use crate::span::Span;
use crate::types::{
    BS_CHAR as BACKSLASH, BS_STR as BACKSLASH_STR, CR_CHAR as CR, DelayedExpansionMode,
    EchoSuppression, LabelName, NegationMode, TAB_CHAR as TAB,
};

/// Drive colon + backslash (`:\`).
const COLON_BACKSLASH: &str = r":\";

/// Percent + backslash (`%\`).
const PERCENT_BACKSLASH: &str = r"%\";

/// Mutable state tracked while walking the [`ParsedScript`] AST for static analysis.
pub struct AnalyzerState<'a> {
    /// Full script text for slicing original spans.
    pub script_text: &'a str,
    /// Set of defined label names (`:label`, excluding `::`).
    pub defined_labels: BTreeSet<String>,
    /// Current delayed expansion mode (`Disabled` or `Enabled`).
    pub delayed_expansion: DelayedExpansionMode,
    /// Whether `SETLOCAL` has been called anywhere in the script.
    pub has_setlocal: bool,
    /// Map of all variables assigned in the script (`UPPER_NAME -> Vec<(Span, is_read)>`).
    pub assigned_vars: BTreeMap<String, Vec<(Span, bool)>>,
    /// Map of all variables referenced in the script (`UPPER_NAME -> Vec<Span>`).
    pub referenced_vars: BTreeMap<String, Vec<Span>>,
    /// Variables modified via `SET` inside the currently active `( ... )` compound block.
    pub current_block_modified_vars: BTreeSet<String>,
    /// Current nesting depth inside `( ... )` blocks / `FOR` / `IF`.
    pub block_depth: usize,
    /// Whether currently inside a pipeline `cmd1 | cmd2`.
    pub in_pipeline: bool,
    /// Whether the immediately preceding statement was `ROBOCOPY`.
    pub after_robocopy: bool,
    /// Accumulated diagnostics.
    pub diags: &'a mut Vec<Diagnostic>,
}

/// Runs all AST, control-flow, and data-flow rules (`CMD1001`–`CMD4010`) on `parsed`,
/// honoring externally assigned variables imported via `REM wincheck source-path=...`.
///
/// # Arguments
/// * `parsed` - Lowered [`ParsedScript`] AST.
/// * `script_text` - Decoded script source text.
/// * `external_vars` - Uppercase variable names defined in `source-path=` scripts.
/// * `diags` - Destination buffer receiving triggered [`Diagnostic`]s.
pub fn analyze_parsed_script_with_externals(
    parsed: &ParsedScript,
    script_text: &str,
    external_vars: &BTreeSet<String>,
    diags: &mut Vec<Diagnostic>,
) {
    for &bc_span in &parsed.broken_caret_spans {
        diags.push(Diagnostic {
            rule_id: RuleId::new("CMD1004"),
            severity: Severity::Warning,
            message:
                "Trailing whitespace after `^` escapes the space instead of continuing the line."
                    .to_owned(),
            primary_span: bc_span,
            help: Some(
                "Remove all spaces and tabs between `^` and the end of the line.".to_owned(),
            ),
            fix: Some(SuggestedFix {
                description: "Strip trailing whitespace after `^`".to_owned(),
                span: bc_span,
                replacement: "^".to_owned(),
            }),
        });
    }

    let mut defined_labels = BTreeSet::new();
    for lbl in parsed.labels.iter().filter(|l| !l.is_double_colon) {
        if lbl.has_invalid_label_chars {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD1012"),
                severity: Severity::Warning,
                message: format!(
                    "Label `:{}` contains trailing spaces or delimiter characters that cmd.exe ignores.",
                    lbl.name
                ),
                primary_span: lbl.span,
                help: Some(format!("Use a single identifier `:{}`.", lbl.name)),
                fix: None,
            });
        }
        let folded = lbl.name.folded().to_owned();
        if !defined_labels.insert(folded) {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD3002"),
                severity: Severity::Warning,
                message: format!("Duplicate label definition `:{}`.", lbl.name),
                primary_span: lbl.span,
                help: Some("Give each label a unique name within the batch script.".to_owned()),
                fix: None,
            });
        }
    }

    if let Some(first_cmd_stmt) = parsed
        .statements
        .iter()
        .find(|s| matches!(s, Statement::Command(_)))
        .filter(|s| !is_at_echo_off(s))
    {
        diags.push(Diagnostic {
            rule_id: RuleId::new("CMD4006"),
            severity: Severity::Style,
            message: "Batch script does not start with `@echo off`.".to_owned(),
            primary_span: first_cmd_stmt.span(),
            help: Some(
                "Add `@echo off` at the top of the script to suppress command echoing.".to_owned(),
            ),
            fix: None,
        });
    }

    let mut state = AnalyzerState {
        script_text,
        defined_labels,
        delayed_expansion: DelayedExpansionMode::Disabled,
        has_setlocal: false,
        assigned_vars: BTreeMap::new(),
        referenced_vars: BTreeMap::new(),
        current_block_modified_vars: BTreeSet::new(),
        block_depth: 0,
        in_pipeline: false,
        after_robocopy: false,
        diags,
    };

    check_statement_sequence(&parsed.statements, &mut state);
    finalize_dataflow_diagnostics(&mut state, external_vars);
}

/// Emits `CMD2012` (unassigned variable reference) and `CMD2013` (unused variable assignment).
///
/// # Arguments
/// * `state` - Completed [`AnalyzerState`] with collected assignments and references.
/// * `external_vars` - Uppercase variable names imported via `source-path=`.
fn finalize_dataflow_diagnostics(state: &mut AnalyzerState<'_>, external_vars: &BTreeSet<String>) {
    for (var_upper, ref_spans) in &state.referenced_vars {
        if let Some(assign_list) = state.assigned_vars.get_mut(var_upper) {
            for entry in assign_list {
                entry.1 = true;
            }
        } else if !WELL_KNOWN_ENV_VARS.contains(&var_upper.as_str())
            && !external_vars.contains(var_upper)
        {
            for &r_span in ref_spans {
                state.diags.push(Diagnostic {
                    rule_id: RuleId::new("CMD2012"),
                    severity: Severity::Warning,
                    message: format!(
                        "Variable `{var_upper}` is referenced but never assigned in this script."
                    ),
                    primary_span: r_span,
                    help: Some("Initialize the variable with `SET` before referencing it, or check for typos.".to_owned()),
                    fix: None,
                });
            }
        }
    }

    for (var_upper, assign_list) in &state.assigned_vars {
        if !WELL_KNOWN_ENV_VARS.contains(&var_upper.as_str()) {
            for &(a_span, was_read) in assign_list {
                if !was_read {
                    state.diags.push(Diagnostic {
                        rule_id: RuleId::new("CMD2013"),
                        severity: Severity::Info,
                        message: format!(
                            "Variable `{var_upper}` is assigned via `SET` but never read."
                        ),
                        primary_span: a_span,
                        help: Some(
                            "Remove unused variable assignments or reference `%VAR%`.".to_owned(),
                        ),
                        fix: None,
                    });
                }
            }
        }
    }
}

/// Checks a sequence of statements for reachability (`CMD3006`), subroutine fallthrough (`CMD3005`),
/// and per-statement rules.
///
/// # Arguments
/// * `stmts` - Statement slice to analyze.
/// * `state` - Mutable [`AnalyzerState`].
pub(super) fn check_statement_sequence(stmts: &[Statement], state: &mut AnalyzerState<'_>) {
    let mut prev_terminated = false;
    let mut seen_executable = false;

    for stmt in stmts {
        match stmt {
            Statement::Empty(_) | Statement::Rem(_) => {}
            Statement::Label(lbl) => {
                if lbl.is_double_colon {
                    if state.block_depth > 0 {
                        state.diags.push(Diagnostic {
                            rule_id: RuleId::new("CMD1001"),
                            severity: Severity::Error,
                            message: "`::` label comment used inside a `( ... )` block can break block parsing.".to_owned(),
                            primary_span: lbl.span,
                            help: Some("Use `REM` instead of `::` inside parenthesized blocks.".to_owned()),
                            fix: Some(SuggestedFix {
                                description: "Replace `::` with `REM`".to_owned(),
                                span: lbl.span,
                                replacement: format!("REM {}", lbl.raw_body.trim_start_matches(':').trim_start()),
                            }),
                        });
                    } else {
                        state.diags.push(Diagnostic {
                            rule_id: RuleId::new("CMD4010"),
                            severity: Severity::Style,
                            message: "Prefer `REM` over `::` for comments.".to_owned(),
                            primary_span: lbl.span,
                            help: Some("Use `REM` for standard comments.".to_owned()),
                            fix: None,
                        });
                    }
                } else {
                    if state.block_depth == 0 && seen_executable && !prev_terminated {
                        state.diags.push(Diagnostic {
                            rule_id: RuleId::new("CMD3005"),
                            severity: Severity::Warning,
                            message: format!(
                                "Execution falls through into label `:{}` without a preceding `EXIT /B` or `GOTO :EOF`.",
                                lbl.name
                            ),
                            primary_span: lbl.span,
                            help: Some("Add `EXIT /B 0` or `GOTO :EOF` before subroutine labels.".to_owned()),
                            fix: None,
                        });
                    }
                    prev_terminated = false;
                }
            }
            Statement::Command(expr) => {
                if prev_terminated {
                    state.diags.push(Diagnostic {
                        rule_id: RuleId::new("CMD3006"),
                        severity: Severity::Warning,
                        message: "Unreachable command following an unconditional `GOTO`, `EXIT`, or direct `.bat` invocation.".to_owned(),
                        primary_span: expr.span(),
                        help: Some("Remove dead code or add a `:label` if this code is a jump target.".to_owned()),
                        fix: None,
                    });
                }
                seen_executable = true;
                check_command_expr(expr, state);
                prev_terminated = is_unconditional_terminator(expr);
            }
        }
    }
}

/// Analyzes a [`CommandExpr`] recursively.
///
/// # Arguments
/// * `expr` - Command expression node.
/// * `state` - Mutable [`AnalyzerState`].
fn check_command_expr(expr: &CommandExpr, state: &mut AnalyzerState<'_>) {
    match expr {
        CommandExpr::Simple(simple) => check_simple_command(simple, state),
        CommandExpr::Block(block) => check_compound_block(block, state),
        CommandExpr::If(if_stmt) => check_if_statement(if_stmt, state),
        CommandExpr::For(for_stmt) => check_for_statement(for_stmt, state),
        CommandExpr::Seq { left, right, .. }
        | CommandExpr::And { left, right, .. }
        | CommandExpr::Or { left, right, .. } => {
            check_command_expr(left, state);
            check_command_expr(right, state);
        }
        CommandExpr::Pipe { left, right, .. } => {
            let prev_pipe = state.in_pipeline;
            state.in_pipeline = true;
            check_command_expr(left, state);
            check_command_expr(right, state);
            state.in_pipeline = prev_pipe;
        }
    }
}

/// Analyzes a `( ... )` [`CompoundBlock`].
///
/// # Arguments
/// * `block` - Compound block AST node.
/// * `state` - Mutable [`AnalyzerState`].
fn check_compound_block(block: &CompoundBlock, state: &mut AnalyzerState<'_>) {
    for redir in &block.redirections {
        match &redir.kind {
            RedirectionKind::ReadFromFile(target)
            | RedirectionKind::WriteTruncate(target)
            | RedirectionKind::WriteAppend(target) => {
                scan_word_for_var_reads(target, state);
                check_unquoted_var_or_param(target, "redirection", state);
            }
            RedirectionKind::DuplicateOutput(_) | RedirectionKind::DuplicateInput(_) => {}
        }
    }
    let saved_vars = state.current_block_modified_vars.clone();
    state.block_depth = state.block_depth.saturating_add(1);
    check_statement_sequence(&block.body, state);
    state.block_depth = state.block_depth.saturating_sub(1);
    if state.block_depth == 0 {
        state.current_block_modified_vars.clear();
    } else {
        state.current_block_modified_vars = saved_vars;
    }
}

/// Analyzes an [`IfStatement`] (`CMD1005`, `CMD2003`, `CMD3007`, `CMD3008`, `CMD3011`).
///
/// # Arguments
/// * `if_stmt` - `IF` statement AST node.
/// * `state` - Mutable [`AnalyzerState`].
fn check_if_statement(if_stmt: &IfStatement, state: &mut AnalyzerState<'_>) {
    if if_stmt.has_dangling_else {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD1005"),
            severity: Severity::Error,
            message: "`ELSE` is not recognized unless the `IF` then-branch is enclosed in parentheses `(...)`.".to_owned(),
            primary_span: if_stmt.span,
            help: Some("Rewrite as `IF condition (command1) ELSE (command2)`.".to_owned()),
            fix: None,
        });
    }

    match &if_stmt.condition {
        IfCondition::ErrorLevel {
            threshold,
            raw_token,
        } => check_if_errorlevel_condition(if_stmt, *threshold, raw_token, state),
        IfCondition::Exist { path_pattern } => {
            scan_word_for_var_reads(path_pattern, state);
            check_unquoted_var_or_param(path_pattern, "IF EXIST", state);
        }
        IfCondition::Defined { var_name } => {
            let clean = var_name.unquoted().to_ascii_uppercase();
            state
                .referenced_vars
                .entry(clean)
                .or_default()
                .push(var_name.span);
        }
        IfCondition::CmdExtVersion { raw_token, .. } => {
            scan_word_for_var_reads(raw_token, state);
        }
        IfCondition::Compare { left, right, .. } => {
            scan_word_for_var_reads(left, state);
            scan_word_for_var_reads(right, state);

            for side in [left, right] {
                if !side.quoted && side.text.contains(['%', '!']) {
                    let smart_repl = smart_quoted_word_replacement(side);
                    state.diags.push(Diagnostic {
                        rule_id: RuleId::new("CMD2003"),
                        severity: Severity::Warning,
                        message: format!(
                            "Unquoted operand `{}` in `IF` comparison will cause a syntax error if empty or containing spaces.",
                            side.text
                        ),
                        primary_span: side.span,
                        help: Some(r#"Quote both operands in `IF` comparisons: `IF "%VAR%"=="value"`."#.to_owned()),
                        fix: Some(SuggestedFix {
                            description: "Wrap operand in double quotes".to_owned(),
                            span: side.span,
                            replacement: smart_repl,
                        }),
                    });
                }
            }
        }
    }

    state.block_depth = state.block_depth.saturating_add(1);
    check_command_expr(&if_stmt.then_branch, state);
    if let Some(else_expr) = &if_stmt.else_branch {
        check_command_expr(else_expr, state);
    }
    state.block_depth = state.block_depth.saturating_sub(1);
}

/// Checks `IF ERRORLEVEL` rules (`CMD3007`, `CMD3008`, `CMD3011`).
///
/// # Arguments
/// * `if_stmt` - Enclosing [`IfStatement`].
/// * `threshold` - Optional parsed integer threshold (`None` when unresolved `%VAR%` / `!VAR!`).
/// * `raw_token` - Raw threshold [`SpannedWord`].
/// * `state` - Mutable [`AnalyzerState`].
fn check_if_errorlevel_condition(
    if_stmt: &IfStatement,
    threshold: Option<i32>,
    raw_token: &SpannedWord,
    state: &mut AnalyzerState<'_>,
) {
    scan_word_for_var_reads(raw_token, state);
    let Some(thresh) = threshold else {
        return;
    };
    if thresh == 0 && if_stmt.negated == NegationMode::Normal {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD3007"),
            severity: Severity::Error,
            message: "`IF ERRORLEVEL 0` is always true for any exit code >= 0 (`IF ERRORLEVEL N` tests `>= N`).".to_owned(),
            primary_span: raw_token.span,
            help: Some("Use `IF %ERRORLEVEL% EQU 0` or `IF NOT ERRORLEVEL 1` to test for success.".to_owned()),
            fix: None,
        });
    }
    if state.after_robocopy && (1..8).contains(&thresh) {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD3011"),
            severity: Severity::Info,
            message: "`ROBOCOPY` returns exit codes 0–7 on success (`1` means files were copied); `IF ERRORLEVEL 1` treats success as failure.".to_owned(),
            primary_span: raw_token.span,
            help: Some("Use `IF ERRORLEVEL 8` to check for `ROBOCOPY` errors.".to_owned()),
            fix: None,
        });
    }
    if let Some(CommandExpr::If(else_if)) = if_stmt.else_branch.as_deref()
        && let IfCondition::ErrorLevel {
            threshold: Some(next_thresh),
            raw_token: next_tok,
        } = &else_if.condition
        && if_stmt.negated == NegationMode::Normal
        && *next_thresh > thresh
    {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD3008"),
            severity: Severity::Warning,
            message: format!(
                "`ELSE IF ERRORLEVEL {next_thresh}` is unreachable because `IF ERRORLEVEL {thresh}` already matched all codes >= {thresh}."
            ),
            primary_span: next_tok.span,
            help: Some("Check `IF ERRORLEVEL` thresholds in descending order (highest to lowest).".to_owned()),
            fix: None,
        });
    }
}

/// Analyzes a [`ForStatement`] (`CMD1006`, `CMD1007`, `CMD4003`).
///
/// # Arguments
/// * `for_stmt` - `FOR` loop AST node.
/// * `state` - Mutable [`AnalyzerState`].
fn check_for_statement(for_stmt: &ForStatement, state: &mut AnalyzerState<'_>) {
    let raw_tok = &for_stmt.raw_variable_token;
    let stripped = raw_tok.trim_start_matches('%');
    let pct_count = raw_tok.len().saturating_sub(stripped.len());

    if pct_count == 1 {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD1007"),
            severity: Severity::Error,
            message: format!(
                "`FOR` variable `{raw_tok}` uses a single `%`; batch scripts require double percent `%{raw_tok}`."
            ),
            primary_span: for_stmt.variable_span,
            help: Some(format!("Use `%{raw_tok}` inside `.bat`/`.cmd` files.")),
            fix: Some(SuggestedFix {
                description: "Double the `%` prefix on the FOR variable".to_owned(),
                span: for_stmt.variable_span,
                replacement: format!("%{raw_tok}"),
            }),
        });
    }

    if stripped.chars().count() > 1 {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD1006"),
            severity: Severity::Error,
            message: format!(
                "`FOR` loop variable `{raw_tok}` has multiple characters; `FOR` variables must be a single character like `%%I`."
            ),
            primary_span: for_stmt.variable_span,
            help: Some("Rename the loop variable to a single letter such as `%%I`.".to_owned()),
            fix: None,
        });
    }

    if let ForVariant::ParsedLines(opts) = &for_stmt.variant {
        let trimmed_set = for_stmt.in_set_raw.trim();
        if !opts.use_backq
            && trimmed_set.starts_with('"')
            && trimmed_set.ends_with('"')
            && (trimmed_set.contains(BACKSLASH)
                || trimmed_set.to_ascii_lowercase().ends_with(r#".txt""#))
        {
            state.diags.push(Diagnostic {
                rule_id: RuleId::new("CMD4003"),
                severity: Severity::Warning,
                message: r#"`FOR /F` with double quotes inside `IN ("...")` without `usebackq` parses the string literal instead of reading the file."#.to_owned(),
                primary_span: for_stmt.in_set_span,
                help: Some(r#"Add `"usebackq"` to `FOR /F` options when quoting file paths."#.to_owned()),
                fix: None,
            });
        }
    }

    for w in &for_stmt.in_set {
        scan_word_for_var_reads(w, state);
    }

    state.block_depth = state.block_depth.saturating_add(1);
    check_command_expr(&for_stmt.body, state);
    state.block_depth = state.block_depth.saturating_sub(1);
}

/// Analyzes a [`SimpleCommand`] across all command-specific lint rules.
///
/// # Arguments
/// * `simple` - [`SimpleCommand`] AST node.
/// * `state` - Mutable [`AnalyzerState`].
fn check_simple_command(simple: &SimpleCommand, state: &mut AnalyzerState<'_>) {
    let prog_upper = simple.program.unquoted().to_ascii_uppercase();
    state.after_robocopy = prog_upper == "ROBOCOPY";

    scan_word_for_var_reads(&simple.program, state);
    if prog_upper != "SET" {
        for arg in &simple.arguments {
            scan_word_for_var_reads(arg, state);
        }
    }
    for redir in &simple.redirections {
        match &redir.kind {
            RedirectionKind::ReadFromFile(target)
            | RedirectionKind::WriteTruncate(target)
            | RedirectionKind::WriteAppend(target) => {
                scan_word_for_var_reads(target, state);
                check_unquoted_var_or_param(target, "redirection", state);
            }
            RedirectionKind::DuplicateOutput(_) | RedirectionKind::DuplicateInput(_) => {}
        }
    }
    check_double_quoted_positional_params(&simple.arguments, state);

    match prog_upper.as_str() {
        "SETLOCAL" => {
            state.has_setlocal = true;
            if state.in_pipeline {
                emit_pipe_mutation_warning(simple.span, "SETLOCAL", state);
            }
            for arg in &simple.arguments {
                if arg
                    .unquoted()
                    .eq_ignore_ascii_case("ENABLEDELAYEDEXPANSION")
                {
                    state.delayed_expansion = DelayedExpansionMode::Enabled;
                } else {
                    state.delayed_expansion = DelayedExpansionMode::Disabled;
                }
            }
        }
        "SET" => {
            if state.in_pipeline {
                emit_pipe_mutation_warning(simple.span, "SET", state);
            }
            check_set_command(simple, state);
        }
        "ECHO" => check_echo_command(simple, state),
        "CD" | "CHDIR" => {
            if state.in_pipeline {
                emit_pipe_mutation_warning(simple.span, &prog_upper, state);
            }
            check_cd_command(simple, state);
        }
        "GOTO" => check_goto_command(simple, state),
        "CALL" => check_call_command(simple, state),
        "EXIT" => check_exit_command(simple, state),
        "RD" | "RMDIR" | "DEL" | "ERASE" => check_delete_command(simple, &prog_upper, state),
        "COPY" | "MOVE" | "TYPE" | "MD" | "MKDIR" => {
            check_file_transfer_command(simple, &prog_upper, state);
        }
        "CHOICE" => check_choice_command(simple, state),
        _ => {
            let lower_prog = prog_upper.to_ascii_lowercase();
            if [".bat", ".cmd"]
                .into_iter()
                .any(|ext| lower_prog.ends_with(ext))
            {
                state.diags.push(Diagnostic {
                    rule_id: RuleId::new("CMD3003"),
                    severity: Severity::Warning,
                    message: format!(
                        "Invoking `{}` directly without `CALL` transfers control permanently and never returns to this script.",
                        simple.program.text
                    ),
                    primary_span: simple.span,
                    help: Some(format!("Prepend `CALL ` to invoke `{}` and return.", simple.program.text)),
                    fix: Some(SuggestedFix {
                        description: "Prepend `CALL `".to_owned(),
                        span: simple.program.span,
                        replacement: format!("CALL {}", simple.program.text),
                    }),
                });
            }
        }
    }
}

/// Emits `CMD2007` when standalone `"%1"`..`"%9"` arguments risk doubling caller quotes.
///
/// # Arguments
/// * `arguments` - Slice of command [`SpannedWord`] arguments.
/// * `state` - Mutable [`AnalyzerState`].
fn check_double_quoted_positional_params(arguments: &[SpannedWord], state: &mut AnalyzerState<'_>) {
    for arg in arguments {
        if arg.quoted && !arg.unquoted().chars().any(char::is_whitespace) {
            for part in &arg.parts {
                if part.kind == WordPartKind::PositionalParam
                    && part.text.len() == 2
                    && part.text != "%*"
                {
                    let digit = part.text.chars().nth(1).unwrap_or('1');
                    state.diags.push(Diagnostic {
                        rule_id: RuleId::new("CMD2007"),
                        severity: Severity::Warning,
                        message: format!(
                            r#"Quoting `"%{digit}"` risks doubling quotes (`""arg""`) if the caller already quoted the argument."#
                        ),
                        primary_span: part.span,
                        help: Some(format!(
                            r#"Use `"%~{digit}"` to strip existing quotes before quoting."#
                        )),
                        fix: Some(SuggestedFix {
                            description: format!("Replace `%{digit}` with `%~{digit}`"),
                            span: part.span,
                            replacement: format!("%~{digit}"),
                        }),
                    });
                }
            }
        }
    }
}

/// Checks `EXIT` without `/B` (`CMD3004`).
///
/// # Arguments
/// * `simple` - `EXIT` [`SimpleCommand`].
/// * `state` - Mutable [`AnalyzerState`].
fn check_exit_command(simple: &SimpleCommand, state: &mut AnalyzerState<'_>) {
    let has_b = simple
        .arguments
        .iter()
        .any(|a| a.unquoted().eq_ignore_ascii_case("/B"));
    if !has_b {
        let replacement = if simple.raw_tail.trim().is_empty() {
            "EXIT /B".to_owned()
        } else {
            format!("EXIT /B {}", simple.raw_tail.trim())
        };
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD3004"),
            severity: Severity::Warning,
            message: "`EXIT` without `/B` terminates the entire cmd.exe console session instead of just the batch script.".to_owned(),
            primary_span: simple.span,
            help: Some("Use `EXIT /B` to exit the current batch script.".to_owned()),
            fix: Some(SuggestedFix {
                description: "Add `/B` switch to `EXIT`".to_owned(),
                span: simple.span,
                replacement,
            }),
        });
    }
}

/// Checks `COPY`, `MOVE`, `TYPE`, and `MD`/`MKDIR` path quoting (`CMD2006`) and ambiguous multi-source destination (`CMD4009`).
///
/// # Arguments
/// * `simple` - [`SimpleCommand`] node.
/// * `prog_upper` - Uppercase command name.
/// * `state` - Mutable [`AnalyzerState`].
fn check_file_transfer_command(
    simple: &SimpleCommand,
    prog_upper: &str,
    state: &mut AnalyzerState<'_>,
) {
    let non_switches: Vec<&SpannedWord> = simple
        .arguments
        .iter()
        .filter(|a| !a.text.starts_with('/'))
        .collect();
    for &arg in &non_switches {
        check_unquoted_var_or_param(arg, prog_upper, state);
    }
    if let Some(&dest) = non_switches.last().filter(|d| {
        matches!(prog_upper, "COPY" | "MOVE")
            && non_switches.len() >= 3
            && !d.unquoted().ends_with(BACKSLASH)
    }) {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD4009"),
            severity: Severity::Warning,
            message: format!(
                "`{prog_upper}` with multiple sources into `{}` without a trailing `{BACKSLASH_STR}` is ambiguous if the destination directory does not exist.",
                dest.text
            ),
            primary_span: dest.span,
            help: Some(format!("Append a trailing backslash: `{}{BACKSLASH_STR}`.", dest.text)),
            fix: None,
        });
    }
}

/// Checks `SET` command rules (`CMD1010`, `CMD1011`, `CMD2004`, `CMD2005`, `CMD2008`, `CMD2010`, `CMD4007`).
///
/// # Arguments
/// * `simple` - `SET` [`SimpleCommand`].
/// * `state` - Mutable [`AnalyzerState`].
fn check_set_command(simple: &SimpleCommand, state: &mut AnalyzerState<'_>) {
    let raw = simple.raw_tail.as_str();
    let trimmed = raw.trim_start();
    if trimmed.is_empty() {
        return;
    }

    if simple
        .arguments
        .first()
        .is_some_and(|a| a.unquoted().eq_ignore_ascii_case("/A"))
    {
        check_set_arithmetic(simple, trimmed, state);
        return;
    }

    if simple
        .arguments
        .first()
        .is_some_and(|a| a.unquoted().eq_ignore_ascii_case("/P"))
    {
        let after_p = trimmed.get(2..).unwrap_or("").trim_start();
        let unquoted = crate::parser::modifiers::strip_set_outer_quotes(after_p);
        if let Some(var_name) = unquoted
            .split('=')
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty() && unquoted.contains('='))
        {
            record_var_assignment(&var_name.to_ascii_uppercase(), simple.span, state);
        }
        return;
    }

    let is_quoted_set = trimmed.starts_with('"');
    let unquoted = crate::parser::modifiers::strip_set_outer_quotes(trimmed);
    let Some(eq_idx) = unquoted.find('=') else {
        return;
    };
    let raw_name = unquoted.get(..eq_idx).unwrap_or("");
    let raw_val = unquoted.get(eq_idx.saturating_add(1)..).unwrap_or("");

    scan_text_for_var_reads(raw_val, simple.raw_tail_span, state);

    if raw_name.ends_with(' ') {
        let clean_name = raw_name.trim();
        let clean_val = raw_val.trim();
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD2005"),
            severity: Severity::Warning,
            message: format!(
                r#"Space before `=` in `SET {raw_name}={raw_val}` defines a variable named `"{raw_name}"` with a trailing space."#
            ),
            primary_span: simple.raw_tail_span,
            help: Some(format!(r#"Remove spaces around `=`: `SET "{clean_name}={clean_val}"`"#)),
            fix: Some(SuggestedFix {
                description: "Remove spaces around `=` and quote assignment".to_owned(),
                span: simple.span,
                replacement: format!(r#"SET "{clean_name}={clean_val}""#),
            }),
        });
    }

    let raw_set_line_tail = state
        .script_text
        .get(simple.span.start.0..)
        .and_then(|s| s.lines().next())
        .map_or(raw, |l| l.trim_end_matches(CR));
    if !is_quoted_set
        && [raw, raw_set_line_tail]
            .into_iter()
            .any(|s| s.ends_with([' ', TAB]))
    {
        let clean_name = raw_name.trim();
        let clean_val = raw_val.trim_end_matches([' ', TAB]);
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD2004"),
            severity: Severity::Warning,
            message: format!(
                "Trailing whitespace in unquoted `SET {clean_name}=... ` is included in the variable's value."
            ),
            primary_span: simple.raw_tail_span,
            help: Some(format!(r#"Use quoted assignment `SET "{clean_name}={clean_val}"` to avoid trailing spaces."#)),
            fix: Some(SuggestedFix {
                description: r#"Use quoted `SET "VAR=value"` syntax"#.to_owned(),
                span: simple.span,
                replacement: format!(r#"SET "{clean_name}={clean_val}""#),
            }),
        });
    }

    let set_form = if is_quoted_set {
        SetSyntaxForm::QuotedSet
    } else {
        SetSyntaxForm::UnquotedSet
    };
    check_set_caret_and_shadowing(simple, raw_name, set_form, state);
}

/// Quoting form used on a `SET` assignment (`SET VAR=val` vs `SET "VAR=val"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetSyntaxForm {
    /// Unquoted `SET VAR=val`.
    UnquotedSet,
    /// Quoted `SET "VAR=val"`.
    QuotedSet,
}

/// Checks `CMD2008` (unquoted caret escape in `SET`), `CMD2010` (shadowing dynamic variables),
/// and records the variable assignment.
///
/// # Arguments
/// * `simple` - `SET` [`SimpleCommand`].
/// * `raw_name` - Raw variable name slice before `'='`.
/// * `set_form` - [`SetSyntaxForm`] (`UnquotedSet` vs `QuotedSet`).
/// * `state` - Mutable [`AnalyzerState`].
fn check_set_caret_and_shadowing(
    simple: &SimpleCommand,
    raw_name: &str,
    set_form: SetSyntaxForm,
    state: &mut AnalyzerState<'_>,
) {
    let raw_source_slice = state
        .script_text
        .get(simple.span.start.0..simple.span.end.0)
        .unwrap_or("");
    if set_form == SetSyntaxForm::UnquotedSet && raw_source_slice.contains('^') {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD2008"),
            severity: Severity::Warning,
            message: "Caret-escaped characters in unquoted `SET` assignment are fragile across expansion passes.".to_owned(),
            primary_span: simple.raw_tail_span,
            help: Some(r#"Wrap the assignment in double quotes: `SET "VAR=value"`."#.to_owned()),
            fix: None,
        });
    }

    let clean_upper = raw_name.trim().to_ascii_uppercase();
    if matches!(
        clean_upper.as_str(),
        "CD" | "DATE" | "TIME" | "RANDOM" | "ERRORLEVEL" | "CMDEXTVERSION" | "CMDCMDLINE"
    ) {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD2010"),
            severity: Severity::Warning,
            message: format!(
                "Assigning to `{clean_upper}` permanently shadows cmd.exe's dynamic `%{clean_upper}%` pseudo-variable."
            ),
            primary_span: simple.span,
            help: Some("Choose a different variable name (e.g., `MY_ERRORLEVEL` or `CUR_DIR`).".to_owned()),
            fix: None,
        });
    }

    record_var_assignment(&clean_upper, simple.span, state);
}

/// Validates `SET /A` arithmetic rules (`CMD1010`, `CMD1011`, `CMD4007`).
///
/// # Arguments
/// * `simple` - `SET /A` [`SimpleCommand`].
/// * `trimmed` - Trimmed `raw_tail` starting with `/A`.
/// * `state` - Mutable [`AnalyzerState`].
fn check_set_arithmetic(simple: &SimpleCommand, trimmed: &str, state: &mut AnalyzerState<'_>) {
    let expr_raw = trimmed.get(2..).unwrap_or("").trim_start();
    scan_text_for_var_reads(expr_raw, simple.raw_tail_span, state);

    let raw_set_a_src = state
        .script_text
        .get(simple.span.start.0..simple.span.end.0)
        .unwrap_or("");
    let has_unquoted_op = ["<<", ">>", "&", "|", "^"]
        .into_iter()
        .any(|op| raw_set_a_src.contains(op))
        || !simple.redirections.is_empty();
    if !expr_raw.starts_with('"') && has_unquoted_op {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD1011"),
            severity: Severity::Warning,
            message: "Unquoted bitwise operator in `SET /A` may be interpreted as redirection or command chaining.".to_owned(),
            primary_span: simple.raw_tail_span,
            help: Some(r#"Wrap the expression in quotes: `SET /A "x=1<<2"`."#.to_owned()),
            fix: None,
        });
    }

    let upper_expr = expr_raw.to_ascii_uppercase();
    if ["%DATE", "!DATE", "%TIME", "!TIME"]
        .into_iter()
        .any(|p| upper_expr.contains(p))
    {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD4007"),
            severity: Severity::Warning,
            message: "Using `%DATE%` or `%TIME%` slices in `SET /A` fails on `08` and `09` due to octal number parsing.".to_owned(),
            primary_span: simple.raw_tail_span,
            help: Some(r#"Prefix with `1` and subtract `100` (e.g., `SET /A "m=1%DATE:~3,2%-100"`)."#.to_owned()),
            fix: None,
        });
    }

    let sanitized = sanitize_vars_for_arith_check(expr_raw);
    let mut assigned_in_a = Vec::new();
    let dummy_one = Some("1".to_owned());
    if let Err(err) = evaluate_set_a(
        &sanitized,
        simple.raw_tail_span,
        |_| dummy_one.clone(),
        |k, _| assigned_in_a.push(k.to_ascii_uppercase()),
    ) {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD1010"),
            severity: Severity::Error,
            message: format!(
                "Invalid `SET /A` arithmetic expression: {}",
                err.cmd_exe_message()
            ),
            primary_span: simple.raw_tail_span,
            help: Some("Fix the arithmetic syntax or octal literal (`08`/`09`).".to_owned()),
            fix: None,
        });
    }
    for k in assigned_in_a {
        record_var_assignment(&k, simple.span, state);
    }
}

/// Records a variable assignment and updates `current_block_modified_vars` if inside a `(...)` block.
///
/// # Arguments
/// * `var_upper` - Uppercase variable name.
/// * `span` - Assignment [`Span`].
/// * `state` - Mutable [`AnalyzerState`].
fn record_var_assignment(var_upper: &str, span: Span, state: &mut AnalyzerState<'_>) {
    if !state.has_setlocal && state.assigned_vars.is_empty() {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD4005"),
            severity: Severity::Info,
            message: "Script modifies environment variables via `SET` before calling `SETLOCAL`.".to_owned(),
            primary_span: span,
            help: Some("Add `SETLOCAL` near the top of the script to avoid polluting the caller's environment.".to_owned()),
            fix: None,
        });
    }
    state
        .assigned_vars
        .entry(var_upper.to_owned())
        .or_default()
        .push((span, false));
    if state.block_depth > 0 {
        state
            .current_block_modified_vars
            .insert(var_upper.to_owned());
    }
}

/// Checks `ECHO` command rules (`CMD1003`, `CMD2011`, `CMD4002`).
///
/// # Arguments
/// * `simple` - `ECHO` [`SimpleCommand`].
/// * `state` - Mutable [`AnalyzerState`].
fn check_echo_command(simple: &SimpleCommand, state: &mut AnalyzerState<'_>) {
    let tail = simple.raw_tail.trim();
    if tail.is_empty() || tail.eq_ignore_ascii_case("ON") || tail.eq_ignore_ascii_case("OFF") {
        return;
    }

    let is_single_var = (tail.starts_with('%') && tail.ends_with('%'))
        || (tail.starts_with('!') && tail.ends_with('!'));
    if simple.echo_delimiter == Some(' ') && is_single_var && !tail.contains(' ') {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD4002"),
            severity: Severity::Warning,
            message: format!(
                "`ECHO {tail}` will print `ECHO is off.` if `{tail}` expands to empty or whitespace."
            ),
            primary_span: simple.span,
            help: Some(format!("Use `ECHO({tail}` to safely print a blank line when empty.")),
            fix: Some(SuggestedFix {
                description: "Replace `ECHO ` with `ECHO(`".to_owned(),
                span: simple.span,
                replacement: format!("ECHO({tail}"),
            }),
        });
    }

    let raw_src = state
        .script_text
        .get(simple.span.start.0..simple.span.end.0)
        .unwrap_or("");
    if state.block_depth > 0
        && raw_src.contains('(')
        && !raw_src.contains("^)")
        && !raw_src.contains('"')
    {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD1003"),
            severity: Severity::Error,
            message: "Parentheses inside unquoted `ECHO` text inside a `( ... )` block must be escaped as `^(` and `^)`.".to_owned(),
            primary_span: simple.raw_tail_span,
            help: Some("Escape literal parentheses with `^)` inside blocks.".to_owned()),
            fix: None,
        });
    }

    if state.delayed_expansion == DelayedExpansionMode::Enabled {
        let bang_count = simple.raw_tail.chars().filter(|&c| c == '!').count();
        if bang_count % 2 == 1 && !raw_src.contains("^!") {
            state.diags.push(Diagnostic {
                rule_id: RuleId::new("CMD2011"),
                severity: Severity::Info,
                message: "Unescaped `!` in `ECHO` text while `EnableDelayedExpansion` is active will be stripped.".to_owned(),
                primary_span: simple.raw_tail_span,
                help: Some("Escape literal exclamation marks as `^!` when delayed expansion is enabled.".to_owned()),
                fix: None,
            });
        }
    }
}

/// Checks `CD` / `CHDIR` rules (`CMD2006`, `CMD4001`).
///
/// # Arguments
/// * `simple` - `CD` [`SimpleCommand`].
/// * `state` - Mutable [`AnalyzerState`].
fn check_cd_command(simple: &SimpleCommand, state: &mut AnalyzerState<'_>) {
    let has_d = simple
        .arguments
        .first()
        .is_some_and(|a| a.unquoted().eq_ignore_ascii_case("/D"));
    let target_arg = if has_d {
        simple.arguments.get(1)
    } else {
        simple.arguments.first()
    };

    if let Some(targ) = target_arg {
        check_unquoted_var_or_param(targ, "CD", state);
        let u = targ.unquoted();
        if !has_d && u.get(1..3) == Some(COLON_BACKSLASH) {
            state.diags.push(Diagnostic {
                rule_id: RuleId::new("CMD4001"),
                severity: Severity::Warning,
                message: format!(
                    "`CD {}` changes the working directory of drive `{}:` but does not switch the active drive without `/D`.",
                    targ.text,
                    u.chars().next().unwrap_or('C')
                ),
                primary_span: simple.span,
                help: Some(format!("Use `CD /D {}` to switch both drive and directory.", targ.text)),
                fix: Some(SuggestedFix {
                    description: "Add `/D` switch to `CD`".to_owned(),
                    span: simple.span,
                    replacement: format!("CD /D {}", targ.text),
                }),
            });
        }
    }
}

/// Checks `GOTO` rules (`CMD3001`, `CMD3009`).
///
/// # Arguments
/// * `simple` - `GOTO` [`SimpleCommand`].
/// * `state` - Mutable [`AnalyzerState`].
fn check_goto_command(simple: &SimpleCommand, state: &mut AnalyzerState<'_>) {
    if state.block_depth > 0 {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD3009"),
            severity: Severity::Warning,
            message: "`GOTO` used inside a block or loop; jumping out of or into blocks can corrupt loop state.".to_owned(),
            primary_span: simple.span,
            help: Some("Prefer `CALL :subroutine` inside `FOR` loops instead of `GOTO`.".to_owned()),
            fix: None,
        });
    }

    if let Some(first) = simple.arguments.first() {
        let raw_target = first.unquoted();
        let lbl = LabelName::new(raw_target);
        if !raw_target.contains('%')
            && !raw_target.contains('!')
            && !lbl.is_eof()
            && !state.defined_labels.contains(lbl.folded())
        {
            state.diags.push(Diagnostic {
                rule_id: RuleId::new("CMD3001"),
                severity: Severity::Error,
                message: format!("Target label `:{lbl}` does not exist in this script."),
                primary_span: first.span,
                help: Some(format!("Define `:{lbl}` or fix the label name in `GOTO`.")),
                fix: None,
            });
        }
    }
}

/// Checks `CALL` rules (`CMD3001` missing `:label`).
///
/// # Arguments
/// * `simple` - `CALL` [`SimpleCommand`].
/// * `state` - Mutable [`AnalyzerState`].
fn check_call_command(simple: &SimpleCommand, state: &mut AnalyzerState<'_>) {
    if let Some(first) = simple.arguments.first()
        && let Some(after_colon) = first.unquoted().strip_prefix(':')
    {
        let lbl = LabelName::new(after_colon);
        if !after_colon.contains('%')
            && !after_colon.contains('!')
            && !lbl.is_eof()
            && !state.defined_labels.contains(lbl.folded())
        {
            state.diags.push(Diagnostic {
                rule_id: RuleId::new("CMD3001"),
                severity: Severity::Error,
                message: format!("Subroutine label `:{lbl}` does not exist in this script."),
                primary_span: first.span,
                help: Some(format!("Define `:{lbl}` in the script.")),
                fix: None,
            });
        }
    }
}

/// Checks `RD` / `DEL` rules (`CMD2006`, `CMD4004` dangerous root wipe).
///
/// # Arguments
/// * `simple` - `RD` or `DEL` [`SimpleCommand`].
/// * `cmd_name` - Uppercase command name.
/// * `state` - Mutable [`AnalyzerState`].
fn check_delete_command(simple: &SimpleCommand, cmd_name: &str, state: &mut AnalyzerState<'_>) {
    let has_s = simple
        .arguments
        .iter()
        .any(|a| a.unquoted().eq_ignore_ascii_case("/S"));

    for arg in simple
        .arguments
        .iter()
        .filter(|a| !a.unquoted().starts_with('/'))
    {
        check_unquoted_var_or_param(arg, cmd_name, state);
    }
    if has_s {
        for arg in &simple.arguments {
            let u = arg.unquoted();
            if u.starts_with('%') && u.ends_with(PERCENT_BACKSLASH) {
                state.diags.push(Diagnostic {
                    rule_id: RuleId::new("CMD4004"),
                    severity: Severity::Error,
                    message: format!(
                        "Dangerous `{cmd_name} /S` target `{}` resolves to root `{BACKSLASH_STR}` if the variable is empty or unset!",
                        arg.text
                    ),
                    primary_span: arg.span,
                    help: Some("Guard with `IF DEFINED VAR` or prefix with a safe base directory.".to_owned()),
                    fix: None,
                });
            }
        }
    }
}

/// Checks `CHOICE` rules (`CMD4008`: `/D` default not in `/C` choices).
///
/// # Arguments
/// * `simple` - `CHOICE` [`SimpleCommand`].
/// * `state` - Mutable [`AnalyzerState`].
fn check_choice_command(simple: &SimpleCommand, state: &mut AnalyzerState<'_>) {
    let mut choices = "YN".to_owned();
    let mut default_opt: Option<(char, Span)> = None;
    let mut i = 0usize;
    while let Some(arg) = simple.arguments.get(i) {
        let u = arg.unquoted();
        let upper = u.to_ascii_uppercase();
        if upper == "/C" {
            let next = simple.arguments.get(i.saturating_add(1)).unwrap_or(arg);
            next.unquoted().clone_into(&mut choices);
            i = i.saturating_add(2);
        } else if upper.starts_with("/C") {
            u.get(2..)
                .unwrap_or("")
                .trim_start_matches(':')
                .clone_into(&mut choices);
            i = i.saturating_add(1);
        } else if upper == "/D" {
            let next = simple.arguments.get(i.saturating_add(1)).unwrap_or(arg);
            let ch = next.unquoted().chars().next().unwrap_or(' ');
            default_opt = Some((ch, next.span));
            i = i.saturating_add(2);
        } else {
            i = i.saturating_add(1);
        }
    }

    if let Some((def_ch, def_span)) =
        default_opt.filter(|(def_ch, _)| !choices.chars().any(|c| c.eq_ignore_ascii_case(def_ch)))
    {
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD4008"),
            severity: Severity::Warning,
            message: format!("`CHOICE /D {def_ch}` default key is not present in `/C {choices}`."),
            primary_span: def_span,
            help: Some(format!("Choose a default character from `{choices}`.")),
            fix: None,
        });
    }
}

/// Emits `CMD3010` warning when `SET`, `CD`, or `SETLOCAL` is used inside a pipe `|`.
///
/// # Arguments
/// * `span` - Command [`Span`].
/// * `cmd_name` - Uppercase command name.
/// * `state` - Mutable [`AnalyzerState`].
fn emit_pipe_mutation_warning(span: Span, cmd_name: &str, state: &mut AnalyzerState<'_>) {
    state.diags.push(Diagnostic {
        rule_id: RuleId::new("CMD3010"),
        severity: Severity::Warning,
        message: format!(
            "`{cmd_name}` inside a pipeline `|` executes in a child subshell; changes are lost when the pipe finishes."
        ),
        primary_span: span,
        help: Some(r#"Use `FOR /F "delims=" %%I IN ('command') DO SET ...` instead of piping into `SET`."#.to_owned()),
        fix: None,
    });
}

/// Computes the smart-quoted replacement string for an unquoted [`SpannedWord`] (`"%~1"`, `"%%~I"`, or `"%VAR%"`).
///
/// # Arguments
/// * `word` - Unquoted [`SpannedWord`].
///
/// # Returns
/// Smart-quoted string replacement.
#[must_use]
pub fn smart_quoted_word_replacement(word: &SpannedWord) -> String {
    if word.parts.is_empty() {
        return format!(r#""{}""#, word.text);
    }
    let mut inner = String::new();
    for part in &word.parts {
        if part.kind == WordPartKind::PositionalParam
            && !part.text.contains('~')
            && part.text != "%*"
        {
            let digit = part.text.chars().nth(1).unwrap_or('1');
            write!(inner, "%~{digit}").unwrap_or(());
        } else if part.kind == WordPartKind::ForVar && !part.text.contains('~') {
            let pct_cnt = part.text.chars().take_while(|&c| c == '%').count();
            let var_ch = part.text.chars().nth(pct_cnt).unwrap_or('I');
            let prefix = if pct_cnt >= 2 { "%%" } else { "%" };
            write!(inner, "{prefix}~{var_ch}").unwrap_or(());
        } else if part.kind == WordPartKind::CaretEscape {
            let unescaped: String = part.text.chars().skip(1).collect();
            inner.push_str(&unescaped);
        } else {
            inner.push_str(&part.text);
        }
    }
    format!(r#""{inner}""#)
}

/// Emits `CMD2006` if `word` is an unquoted variable (`%VAR%`, `!VAR!`, `%1`, `%%I`) passed to a path command or redirection.
///
/// # Arguments
/// * `word` - Candidate [`SpannedWord`].
/// * `cmd_name` - Command or context description.
/// * `state` - Mutable [`AnalyzerState`].
fn check_unquoted_var_or_param(word: &SpannedWord, cmd_name: &str, state: &mut AnalyzerState<'_>) {
    let has_var_or_param = word.parts.iter().any(|p| {
        matches!(
            p.kind,
            WordPartKind::EnvVar
                | WordPartKind::DelayedVar
                | WordPartKind::ForVar
                | WordPartKind::PositionalParam
        ) && p.text != "%*"
    });

    if !word.quoted && has_var_or_param {
        let smart_repl = smart_quoted_word_replacement(word);
        state.diags.push(Diagnostic {
            rule_id: RuleId::new("CMD2006"),
            severity: Severity::Warning,
            message: format!(
                "Unquoted variable/parameter `{}` passed to `{cmd_name}` will break on paths containing spaces.",
                word.text
            ),
            primary_span: word.span,
            help: Some(format!("Quote the path argument: `{smart_repl}`.")),
            fix: Some(SuggestedFix {
                description: "Quote the path argument".to_owned(),
                span: word.span,
                replacement: smart_repl,
            }),
        });
    }
}

/// Scans a [`SpannedWord`]'s sub-word [`crate::parser::ast::WordPart`]s for `%VAR%` and `!VAR!` reads.
///
/// # Arguments
/// * `word` - [`SpannedWord`] to inspect.
/// * `state` - Mutable [`AnalyzerState`].
pub fn scan_word_for_var_reads(word: &SpannedWord, state: &mut AnalyzerState<'_>) {
    if word.parts.is_empty() {
        scan_text_for_var_reads(&word.text, word.span, state);
        return;
    }
    for part in &word.parts {
        if matches!(part.kind, WordPartKind::EnvVar | WordPartKind::DelayedVar) {
            scan_text_for_var_reads(&part.text, part.span, state);
        }
    }
}

/// Scans `text` for `%VAR%` and `!VAR!` variable references, checking `CMD2001`, `CMD2002`, and `CMD2009`.
///
/// # Arguments
/// * `text` - Raw token text.
/// * `span` - Source [`Span`] of `text`.
/// * `state` - Mutable [`AnalyzerState`].
fn scan_text_for_var_reads(text: &str, span: Span, state: &mut AnalyzerState<'_>) {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    while let Some(&ch) = chars.get(i) {
        if ch == '%' {
            if chars.get(i.saturating_add(1)) == Some(&'%') {
                i = i.saturating_add(2);
            } else if let Some(rel_close) = chars
                .get(i.saturating_add(1)..)
                .and_then(|s| s.iter().position(|&c| c == '%'))
            {
                let close_idx = i.saturating_add(1).saturating_add(rel_close);
                let inner: String = chars
                    .get(i.saturating_add(1)..close_idx)
                    .unwrap_or(&[])
                    .iter()
                    .collect();
                let var_name = inner.split(':').next().unwrap_or("").trim();
                let valid_ident = !var_name.is_empty()
                    && !var_name.starts_with('~')
                    && var_name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_');
                if valid_ident {
                    let upper = var_name.to_ascii_uppercase();
                    state
                        .referenced_vars
                        .entry(upper.clone())
                        .or_default()
                        .push(span);

                    if state.block_depth > 0 && state.current_block_modified_vars.contains(&upper) {
                        state.diags.push(Diagnostic {
                            rule_id: RuleId::new("CMD2001"),
                            severity: Severity::Error,
                            message: format!(
                                "`%{var_name}%` is read inside the same `( ... )` block where `{var_name}` was modified; it will evaluate to the stale value from before the block started."
                            ),
                            primary_span: span,
                            help: Some(format!(
                                "Enable `SETLOCAL EnableDelayedExpansion` and use `!{var_name}!` instead of `%{var_name}%`."
                            )),
                            fix: None,
                        });
                    }

                    if state.block_depth > 0
                        && matches!(upper.as_str(), "ERRORLEVEL" | "RANDOM" | "TIME")
                    {
                        state.diags.push(Diagnostic {
                            rule_id: RuleId::new("CMD2009"),
                            severity: Severity::Error,
                            message: format!(
                                "`%{upper}%` inside a `( ... )` block evaluates once before the block starts and will not reflect runtime changes."
                            ),
                            primary_span: span,
                            help: Some(format!(
                                "Use `!{upper}!` with `SETLOCAL EnableDelayedExpansion`."
                            )),
                            fix: None,
                        });
                    }
                }
                i = close_idx.saturating_add(1);
            } else {
                i = i.saturating_add(1);
            }
        } else {
            i = i.saturating_add(1);
        }
    }

    scan_delayed_var_reads(&chars, span, state);
}

/// Scans `chars` for `!VAR!` delayed expansion references and emits `CMD2002` when disabled.
///
/// # Arguments
/// * `chars` - Character slice of the token.
/// * `span` - Source [`Span`] of the token.
/// * `state` - Mutable [`AnalyzerState`].
fn scan_delayed_var_reads(chars: &[char], span: Span, state: &mut AnalyzerState<'_>) {
    let mut j = 0usize;
    while let Some(&ch) = chars.get(j) {
        if let Some(rel_close) = (ch == '!')
            .then(|| {
                chars
                    .get(j.saturating_add(1)..)
                    .and_then(|s| s.iter().position(|&c| c == '!'))
            })
            .flatten()
        {
            let close_idx = j.saturating_add(1).saturating_add(rel_close);
            let inner: String = chars
                .get(j.saturating_add(1)..close_idx)
                .unwrap_or(&[])
                .iter()
                .collect();
            let var_name = inner.split(':').next().unwrap_or("").trim();
            let upper = var_name.to_ascii_uppercase();
            state.referenced_vars.entry(upper).or_default().push(span);
            if state.delayed_expansion == DelayedExpansionMode::Disabled {
                state.diags.push(Diagnostic {
                    rule_id: RuleId::new("CMD2002"),
                    severity: Severity::Warning,
                    message: format!(
                        "Delayed expansion `!{var_name}!` used, but `SETLOCAL EnableDelayedExpansion` has not been enabled in this script."
                    ),
                    primary_span: span,
                    help: Some(
                        "Add `SETLOCAL EnableDelayedExpansion` before using `!VAR!`.".to_owned(),
                    ),
                    fix: None,
                });
            }
            j = close_idx.saturating_add(1);
        } else {
            j = j.saturating_add(1);
        }
    }
}

/// Replaces `%...%`, `!...!`, and `%%I` tokens in a `SET /A` expression with `1` so syntax can be statically verified.
///
/// # Arguments
/// * `expr` - Raw `SET /A` expression string.
///
/// # Returns
/// Sanitized expression string with macro placeholders replaced by `1`.
fn sanitize_vars_for_arith_check(expr: &str) -> String {
    let mut out = String::with_capacity(expr.len());
    let chars: Vec<char> = expr.chars().collect();
    let mut i = 0usize;
    while let Some(&ch) = chars.get(i) {
        if let Some(rel) = matches!(ch, '%' | '!')
            .then(|| {
                chars
                    .get(i.saturating_add(1)..)
                    .and_then(|s| s.iter().position(|&c| c == ch))
                    .filter(|&r| r > 0)
            })
            .flatten()
        {
            out.push('1');
            i = i.saturating_add(rel).saturating_add(2);
            continue;
        }
        if ch == '%'
            && chars.get(i.saturating_add(1)) == Some(&'%')
            && chars
                .get(i.saturating_add(2))
                .is_some_and(char::is_ascii_alphabetic)
        {
            out.push('1');
            i = i.saturating_add(3);
            continue;
        }
        out.push(ch);
        i = i.saturating_add(1);
    }
    out
}

/// Checks if a statement is `@echo off`.
///
/// # Arguments
/// * `stmt` - Candidate [`Statement`].
///
/// # Returns
/// `true` if `stmt` is `@echo off` (case-insensitively).
fn is_at_echo_off(stmt: &Statement) -> bool {
    matches!(
        stmt,
        Statement::Command(CommandExpr::Simple(simple))
            if simple.echo_suppression == EchoSuppression::Suppressed
                && simple.program.unquoted().eq_ignore_ascii_case("ECHO")
                && simple.raw_tail.trim().eq_ignore_ascii_case("OFF")
    )
}

/// Checks if `expr` unconditionally transfers control (`GOTO`, `EXIT`, or direct `.bat` invocation).
///
/// # Arguments
/// * `expr` - [`CommandExpr`] to inspect.
///
/// # Returns
/// `true` if execution never falls through sequentially past `expr`.
fn is_unconditional_terminator(expr: &CommandExpr) -> bool {
    if let CommandExpr::Simple(simple) = expr {
        let upper = simple.program.unquoted().to_ascii_uppercase();
        if ["GOTO", "EXIT"].contains(&upper.as_str()) {
            return true;
        }
        if [".BAT", ".CMD"].into_iter().any(|ext| upper.ends_with(ext)) {
            return true;
        }
    }
    false
}
