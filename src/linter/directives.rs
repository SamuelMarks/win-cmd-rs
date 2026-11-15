//! Inline `REM wincheck` / `:: wincheck` suppression directives, file-level encoding checks,
//! and PEG syntax diagnostic conversion.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{CmdError, ProbableMisuseKind};
use crate::linter::rules::{Diagnostic, RuleId, Severity, SuggestedFix, all_rule_metadata};
use crate::parser::cst::PegDiagnostic;
use crate::span::{ByteOffset, LineEndingStyle, LineNumber, SourceFile, Span};

/// Table of file-wide and line-scoped inline `wincheck` suppressions, re-enables, and `source-path` hints.
#[derive(Debug, Clone, Default)]
pub struct SuppressionTable {
    /// Rules disabled for the entire file (`disable=all` in header).
    pub file_wide_all: bool,
    /// Specific rule IDs disabled for the entire file (`disable=CMDxxxx` in header).
    pub file_wide_rules: BTreeSet<RuleId>,
    /// Specific rule IDs re-enabled across the file (`enable=CMDxxxx` in header after `disable=all`).
    pub file_wide_reenabled: BTreeSet<RuleId>,
    /// Optional 1-based line number from which `enable=all` in body re-enabled all file-wide disabled rules.
    pub reenabled_all_from_line: Option<usize>,
    /// Per-rule 1-based line number from which `enable=CMDxxxx` in body re-enabled a file-wide rule.
    pub reenabled_from_line: BTreeMap<RuleId, usize>,
    /// Line-specific `disable=all` (keyed by target 1-based executable line number).
    pub line_all: BTreeSet<usize>,
    /// Line-specific rule IDs (`line_number -> Set<RuleId>`).
    pub line_rules: BTreeMap<usize, BTreeSet<RuleId>>,
    /// Referenced external batch script paths declared via `REM wincheck source-path=<path>`.
    pub source_paths: Vec<String>,
}

impl SuppressionTable {
    /// Checks whether `rule_id` is suppressed on 1-based line `line_num`.
    ///
    /// Line-specific `disable=` directives take precedence on `line_num`, while `enable=` directives
    /// can re-enable rules previously disabled by file-wide `disable=all` or `disable=CMDxxxx`.
    ///
    /// # Arguments
    /// * `rule_id` - Candidate [`RuleId`] being checked.
    /// * `line_num` - 1-based physical line number of the diagnostic.
    ///
    /// # Returns
    /// `true` if `rule_id` is suppressed on `line_num`, else `false`.
    #[must_use]
    pub fn is_suppressed(&self, rule_id: &RuleId, line_num: usize) -> bool {
        if self.line_all.contains(&line_num) {
            return true;
        }
        if self
            .line_rules
            .get(&line_num)
            .is_some_and(|set| set.contains(rule_id))
        {
            return true;
        }
        if self.file_wide_reenabled.contains(rule_id) {
            return false;
        }
        if self
            .reenabled_all_from_line
            .is_some_and(|from_line| line_num >= from_line)
        {
            return false;
        }
        if self
            .reenabled_from_line
            .get(rule_id)
            .is_some_and(|&from_line| line_num >= from_line)
        {
            return false;
        }
        self.file_wide_all || self.file_wide_rules.contains(rule_id)
    }
}

/// Well-known standard Windows environment variables that do not trigger `CMD2012` unassigned warnings.
pub const WELL_KNOWN_ENV_VARS: &[&str] = &[
    "ALLUSERSPROFILE",
    "APPDATA",
    "CD",
    "CMDCMDLINE",
    "CMDEXTVERSION",
    "COMMONPROGRAMFILES",
    "COMPUTERNAME",
    "COMSPEC",
    "DATE",
    "ERRORLEVEL",
    "HIGHESTNUMANODENUMBER",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "LOGONSERVER",
    "NUMBER_OF_PROCESSORS",
    "OS",
    "PATH",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROMPT",
    "PUBLIC",
    "RANDOM",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TIME",
    "TMP",
    "USERDOMAIN",
    "USERNAME",
    "USERPROFILE",
    "WINDIR",
];

/// Performs file-level encoding (`CMD1008`, `CMD1009`) and inline directive parsing (`CMD0001`)
/// on `source_file`.
///
/// # Arguments
/// * `source_file` - Loaded [`SourceFile`] with BOM and line-ending metadata.
/// * `diags` - Output vector receiving file-level and directive diagnostics.
/// * `suppressions` - Mutable [`SuppressionTable`] populated with parsed directives.
pub fn check_file_encoding_and_lines(
    source_file: &SourceFile,
    diags: &mut Vec<Diagnostic>,
    suppressions: &mut SuppressionTable,
) {
    let known_ids: BTreeSet<RuleId> = all_rule_metadata().into_iter().map(|m| m.id).collect();

    if source_file.has_utf8_bom {
        diags.push(Diagnostic {
            rule_id: RuleId::new("CMD1008"),
            severity: Severity::Warning,
            message: "UTF-8 BOM detected at start of batch file; cmd.exe will fail to recognize the first command on line 1.".to_owned(),
            primary_span: Span::new(source_file.id, ByteOffset(0), ByteOffset(1)),
            help: Some("Save the script as UTF-8 without BOM (or ASCII/CRLF).".to_owned()),
            fix: None,
        });
    }

    if matches!(
        source_file.line_ending_style,
        LineEndingStyle::Lf | LineEndingStyle::Cr | LineEndingStyle::Mixed { .. }
    ) {
        diags.push(Diagnostic {
            rule_id: RuleId::new("CMD1009"),
            severity: Severity::Info,
            message: format!(
                "Script uses {} line endings instead of standard Windows CRLF.",
                source_file.line_ending_style
            ),
            primary_span: Span::new(source_file.id, ByteOffset(0), ByteOffset(1)),
            help: Some("Convert line endings to CRLF so byte-offset GOTO/CALL seeking stays accurate in cmd.exe.".to_owned()),
            fix: None,
        });
    }

    let mut seen_code_line = false;
    for (idx, &line_start) in source_file.line_starts.iter().enumerate() {
        let line_num = idx.saturating_add(1);
        let line_text = source_file
            .line_text(LineNumber::from_one_based(line_num))
            .unwrap_or("");
        let trimmed = line_text.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(c_body) = extract_comment_body(trimmed) {
            if let Some(dir_tail) = c_body
                .strip_prefix("wincheck ")
                .or_else(|| c_body.strip_prefix("shellcheck "))
            {
                let pos = if seen_code_line {
                    DirectivePosition::InlineBody
                } else {
                    DirectivePosition::FileHeader
                };
                let target_exec_line = find_next_executable_line(source_file, idx);
                parse_inline_directive(
                    dir_tail.trim(),
                    pos,
                    target_exec_line,
                    Span::new(
                        source_file.id,
                        line_start,
                        line_start.saturating_add(line_text.len()),
                    ),
                    &known_ids,
                    suppressions,
                    diags,
                );
            }
            continue;
        }

        seen_code_line = true;
    }
}

/// Extracts the trimmed comment payload when `trimmed_line` starts with `::` or `REM` (followed by
/// end-of-line or whitespace/delimiter).
///
/// # Arguments
/// * `trimmed_line` - Whitespace-trimmed physical line text.
///
/// # Returns
/// `Some(comment_body)` if `trimmed_line` is a `::` or `REM` comment line, else `None`.
#[must_use]
fn extract_comment_body(trimmed_line: &str) -> Option<&str> {
    if let Some(after_colons) = trimmed_line.strip_prefix("::") {
        return Some(after_colons.trim());
    }
    let prefix3 = trimmed_line.get(..3)?;
    if prefix3.eq_ignore_ascii_case("REM") {
        let rest = trimmed_line.get(3..).unwrap_or("");
        if rest.is_empty() || rest.starts_with([' ', '\t', '/', ';', ',', '=']) {
            return Some(rest.trim());
        }
    }
    None
}

/// Finds the 1-based line number of the next executable (non-blank, non-`REM`/`::`) statement line
/// after 0-based `directive_line_idx`.
///
/// # Arguments
/// * `source_file` - Loaded [`SourceFile`].
/// * `directive_line_idx` - 0-based index of the directive comment line.
///
/// # Returns
/// 1-based line number of the next executable statement (or `directive_line_idx + 2` if at EOF).
#[must_use]
fn find_next_executable_line(source_file: &SourceFile, directive_line_idx: usize) -> usize {
    for next_idx in directive_line_idx.saturating_add(1)..source_file.line_starts.len() {
        let candidate_num = next_idx.saturating_add(1);
        let text = source_file
            .line_text(LineNumber::from_one_based(candidate_num))
            .unwrap_or("")
            .trim();
        if text.is_empty() || extract_comment_body(text).is_some() {
            continue;
        }
        return candidate_num;
    }
    directive_line_idx.saturating_add(2)
}

/// Converts [`PegDiagnostic`] items from the PEG CST parser into structured linter [`Diagnostic`]s.
///
/// # Arguments
/// * `peg_diags` - Syntax and probable-misuse diagnostics emitted by CST parsing.
/// * `diags` - Output vector receiving converted [`Diagnostic`] items.
pub fn convert_peg_diagnostics(peg_diags: &[PegDiagnostic], diags: &mut Vec<Diagnostic>) {
    for pd in peg_diags {
        let fix = pd
            .suggested_replacement
            .as_ref()
            .map(|(span, repl)| SuggestedFix {
                description: "Apply suggested syntax fix".to_owned(),
                span: *span,
                replacement: repl.clone(),
            });

        if let Some(ref misuse) = pd.misuse_kind {
            convert_misuse_diagnostic(pd, misuse, fix, diags);
        } else {
            let expected_str = if pd.expected.is_empty() {
                String::new()
            } else {
                let list: Vec<String> = pd.expected.iter().map(ToString::to_string).collect();
                format!(" (expected: {})", list.join(", "))
            };
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD1002"),
                severity: Severity::Error,
                message: format!("{}{expected_str}", pd.message),
                primary_span: pd.span,
                help: pd.suggested_help.clone().or_else(|| {
                    Some("Fix the syntax or parenthesis balance error before execution.".to_owned())
                }),
                fix,
            });
        }
    }
}

/// Maps a single [`ProbableMisuseKind`] [`PegDiagnostic`] into one or more [`Diagnostic`] records.
///
/// # Arguments
/// * `pd` - Source [`PegDiagnostic`].
/// * `misuse` - Classified [`ProbableMisuseKind`].
/// * `fix` - Optional [`SuggestedFix`].
/// * `diags` - Destination diagnostic buffer.
fn convert_misuse_diagnostic(
    pd: &PegDiagnostic,
    misuse: &ProbableMisuseKind,
    fix: Option<SuggestedFix>,
    diags: &mut Vec<Diagnostic>,
) {
    match misuse {
        ProbableMisuseKind::SingleEqualsInIf { .. }
        | ProbableMisuseKind::ParenthesizedIfCondition { .. }
        | ProbableMisuseKind::MissingInKeywordInFor { .. }
        | ProbableMisuseKind::MissingDoKeywordInFor { .. }
        | ProbableMisuseKind::UnclosedDoubleQuote { .. } => {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD1013"),
                severity: Severity::Error,
                message: pd.message.clone(),
                primary_span: pd.span,
                help: pd.suggested_help.clone(),
                fix,
            });
        }
        ProbableMisuseKind::UnescapedClosingParenInBlock { .. } => {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD1003"),
                severity: Severity::Error,
                message: pd.message.clone(),
                primary_span: pd.span,
                help: pd.suggested_help.clone(),
                fix: fix.clone(),
            });
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD1013"),
                severity: Severity::Error,
                message: pd.message.clone(),
                primary_span: pd.span,
                help: pd.suggested_help.clone(),
                fix,
            });
        }
        ProbableMisuseKind::UnparenthesizedElseBranch { .. } => {}
        ProbableMisuseKind::MultiCharForVariable { .. } => {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD1006"),
                severity: Severity::Error,
                message: pd.message.clone(),
                primary_span: pd.span,
                help: pd.suggested_help.clone(),
                fix,
            });
        }
        ProbableMisuseKind::SinglePercentForVarInBatch { .. }
        | ProbableMisuseKind::DoublePercentForVarInRepl { .. }
        | ProbableMisuseKind::UnescapedSinglePercentInBatch { .. }
        | ProbableMisuseKind::DoublePercentLiteralInRepl { .. } => {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD1014"),
                severity: Severity::Warning,
                message: pd.message.clone(),
                primary_span: pd.span,
                help: pd.suggested_help.clone(),
                fix,
            });
        }
        ProbableMisuseKind::InvalidModifierOnNamedVar { .. } => {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD2014"),
                severity: Severity::Warning,
                message: pd.message.clone(),
                primary_span: pd.span,
                help: pd.suggested_help.clone(),
                fix,
            });
        }
    }
}

/// Scope position of an inline `REM wincheck` directive (`FileHeader` vs `InlineBody`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectivePosition {
    /// Precedes any executable statement line in the script (applies file-wide).
    FileHeader,
    /// Appears after at least one executable statement line (applies to the next statement).
    InlineBody,
}

/// Validates and applies a single rule item inside a `disable=` list.
///
/// # Arguments
/// * `item` - Rule code or `"all"`.
/// * `position` - [`DirectivePosition`] (`FileHeader` vs `InlineBody`).
/// * `target_line` - 1-based target line number.
/// * `span` - Source [`Span`] of the directive comment.
/// * `known_ids` - Valid catalog [`RuleId`] set.
/// * `suppressions` - Mutable [`SuppressionTable`].
///
/// # Returns
/// `Ok(())` when `item` is `"all"` or a valid [`RuleId`].
///
/// # Errors
/// Returns [`CmdError::LinterDirectiveError`] if `item` is an unknown rule code.
pub fn apply_disable_directive_item(
    item: &str,
    position: DirectivePosition,
    target_line: usize,
    span: Span,
    known_ids: &BTreeSet<RuleId>,
    suppressions: &mut SuppressionTable,
) -> Result<(), CmdError> {
    if item.eq_ignore_ascii_case("all") {
        match position {
            DirectivePosition::FileHeader => suppressions.file_wide_all = true,
            DirectivePosition::InlineBody => {
                suppressions.line_all.insert(target_line);
            }
        }
        return Ok(());
    }
    let id = RuleId::new(item);
    if !known_ids.contains(&id) {
        return Err(CmdError::LinterDirectiveError {
            span,
            detail: format!("Unknown rule code `{id}` in wincheck directive."),
        });
    }
    match position {
        DirectivePosition::FileHeader => {
            suppressions.file_wide_reenabled.remove(&id);
            suppressions.file_wide_rules.insert(id);
        }
        DirectivePosition::InlineBody => {
            suppressions
                .line_rules
                .entry(target_line)
                .or_default()
                .insert(id);
        }
    }
    Ok(())
}

/// Validates and applies a single rule item inside an `enable=` list.
///
/// # Arguments
/// * `item` - Rule code or `"all"`.
/// * `position` - [`DirectivePosition`] (`FileHeader` vs `InlineBody`).
/// * `target_line` - 1-based target executable line number.
/// * `span` - Source [`Span`] of the directive comment.
/// * `known_ids` - Valid catalog [`RuleId`] set.
/// * `suppressions` - Mutable [`SuppressionTable`].
///
/// # Returns
/// `Ok(())` when `item` is `"all"` or a valid [`RuleId`].
///
/// # Errors
/// Returns [`CmdError::LinterDirectiveError`] if `item` is an unknown rule code.
pub fn apply_enable_directive_item(
    item: &str,
    position: DirectivePosition,
    target_line: usize,
    span: Span,
    known_ids: &BTreeSet<RuleId>,
    suppressions: &mut SuppressionTable,
) -> Result<(), CmdError> {
    if item.eq_ignore_ascii_case("all") {
        match position {
            DirectivePosition::FileHeader => {
                suppressions.file_wide_all = false;
                suppressions.file_wide_rules.clear();
                suppressions.file_wide_reenabled.clear();
            }
            DirectivePosition::InlineBody => {
                suppressions.reenabled_all_from_line = Some(target_line);
            }
        }
        return Ok(());
    }
    let id = RuleId::new(item);
    if !known_ids.contains(&id) {
        return Err(CmdError::LinterDirectiveError {
            span,
            detail: format!("Unknown rule code `{id}` in wincheck directive."),
        });
    }
    match position {
        DirectivePosition::FileHeader => {
            suppressions.file_wide_rules.remove(&id);
            if suppressions.file_wide_all {
                suppressions.file_wide_reenabled.insert(id);
            }
        }
        DirectivePosition::InlineBody => {
            suppressions.reenabled_from_line.insert(id, target_line);
        }
    }
    Ok(())
}

/// Validates a single whitespace-delimited directive token (`disable=...`, `enable=...`, `source-path=...`).
///
/// # Arguments
/// * `part` - Directive clause token.
/// * `span` - Source [`Span`] of the directive comment.
///
/// # Returns
/// `Ok(())` when `part` starts with a recognized directive key.
///
/// # Errors
/// Returns [`CmdError::LinterDirectiveError`] when `part` is unrecognized.
pub fn ensure_recognized_directive_key(part: &str, span: Span) -> Result<(), CmdError> {
    if part.starts_with("disable=")
        || part.starts_with("enable=")
        || part.starts_with("source-path=")
    {
        Ok(())
    } else {
        Err(CmdError::LinterDirectiveError {
            span,
            detail: format!("Unrecognized wincheck directive `{part}`."),
        })
    }
}

/// Parses a single `disable=...`, `enable=...`, or `source-path=...` inline directive tail.
///
/// # Arguments
/// * `dir_tail` - Whitespace-delimited directive clauses after `REM wincheck`.
/// * `position` - [`DirectivePosition`] (`FileHeader` vs `InlineBody`).
/// * `target_line` - 1-based line number immediately following this comment.
/// * `span` - Source [`Span`] of the directive comment.
/// * `known_ids` - Set of valid catalog [`RuleId`]s.
/// * `suppressions` - Mutable [`SuppressionTable`] updated in place.
/// * `diags` - Diagnostic vector receiving `CMD0001` on unknown rule IDs or keys.
pub fn parse_inline_directive(
    dir_tail: &str,
    position: DirectivePosition,
    target_line: usize,
    span: Span,
    known_ids: &BTreeSet<RuleId>,
    suppressions: &mut SuppressionTable,
    diags: &mut Vec<Diagnostic>,
) {
    for part in dir_tail.split_whitespace() {
        if let Err(err) = ensure_recognized_directive_key(part, span) {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD0001"),
                severity: Severity::Warning,
                message: err
                    .to_string()
                    .strip_prefix("Invalid wincheck directive: ")
                    .unwrap_or("")
                    .to_owned(),
                primary_span: span,
                help: Some(
                    "Supported directives: `disable=CMDxxxx`, `disable=all`, `enable=CMDxxxx`, `source-path=...`."
                        .to_owned(),
                ),
                fix: None,
            });
            continue;
        }

        if let Some(list) = part.strip_prefix("disable=") {
            for item in list.split(',').filter(|s| !s.is_empty()) {
                if let Err(err) = apply_disable_directive_item(
                    item,
                    position,
                    target_line,
                    span,
                    known_ids,
                    suppressions,
                ) {
                    diags.push(Diagnostic {
                        rule_id: RuleId::new("CMD0001"),
                        severity: Severity::Warning,
                        message: err
                            .to_string()
                            .strip_prefix("Invalid wincheck directive: ")
                            .unwrap_or("")
                            .to_owned(),
                        primary_span: span,
                        help: Some("Run `wincheck --list-rules` to see valid rule IDs.".to_owned()),
                        fix: None,
                    });
                }
            }
        } else if let Some(list) = part.strip_prefix("enable=") {
            if list.is_empty() {
                diags.push(Diagnostic {
                    rule_id: RuleId::new("CMD0001"),
                    severity: Severity::Warning,
                    message: "Empty `enable=` directive in wincheck comment.".to_owned(),
                    primary_span: span,
                    help: Some(
                        "Specify at least one rule ID (e.g., `enable=CMD2005`) or `enable=all`."
                            .to_owned(),
                    ),
                    fix: None,
                });
            }
            for item in list.split(',').filter(|s| !s.is_empty()) {
                if let Err(err) = apply_enable_directive_item(
                    item,
                    position,
                    target_line,
                    span,
                    known_ids,
                    suppressions,
                ) {
                    diags.push(Diagnostic {
                        rule_id: RuleId::new("CMD0001"),
                        severity: Severity::Warning,
                        message: err
                            .to_string()
                            .strip_prefix("Invalid wincheck directive: ")
                            .unwrap_or("")
                            .to_owned(),
                        primary_span: span,
                        help: Some("Run `wincheck --list-rules` to see valid rule IDs.".to_owned()),
                        fix: None,
                    });
                }
            }
        } else {
            let raw_sp = part.strip_prefix("source-path=").unwrap_or("");
            let cleaned = raw_sp.trim().trim_matches('"');
            if cleaned.is_empty() {
                diags.push(Diagnostic {
                    rule_id: RuleId::new("CMD0001"),
                    severity: Severity::Warning,
                    message: "Empty `source-path=` directive in wincheck comment.".to_owned(),
                    primary_span: span,
                    help: Some("Provide a non-empty relative or absolute script path (e.g., `source-path=common.bat`).".to_owned()),
                    fix: None,
                });
            } else {
                suppressions.source_paths.push(cleaned.to_owned());
            }
        }
    }
}
