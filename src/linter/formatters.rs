//! Diagnostic output formatters (`TTY`, `GCC`, `JSON`, `SARIF`) and Longest-Common-Subsequence
//! (LCS) unified diff generation (`--diff`).

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::linter::rewrite_script;
use crate::linter::rules::{
    Diagnostic, LinterConfig, OutputFormat, SuggestedFix, all_rule_metadata,
};
use crate::span::SourceMap;
use crate::types::{ExecutionContext, LF_CHAR as LF};

/// Standard number of surrounding unchanged context lines in unified diffs.
const DIFF_CONTEXT_LINES: usize = 3;

/// Applies all [`SuggestedFix`] replacements from `diagnostics` to `original_text`.
///
/// If two or more fixes overlap in byte span, delegates to [`rewrite_script`] via
/// [`crate::linter::rewriter::CstRewriter`] so nested/overlapping tree transformations
/// compose cleanly without corrupting byte offsets.
///
/// # Arguments
/// * `original_text` - Original script string.
/// * `diagnostics` - Slice of diagnostics containing optional [`SuggestedFix`]es.
///
/// # Returns
/// `(fixed_text, applied_count)` containing the modified script and count of applied fixes.
#[must_use]
pub fn apply_suggested_fixes(original_text: &str, diagnostics: &[Diagnostic]) -> (String, usize) {
    let mut fixes: Vec<&SuggestedFix> = diagnostics.iter().filter_map(|d| d.fix.as_ref()).collect();
    fixes.sort_by_key(|b| {
        (
            core::cmp::Reverse(b.span.start),
            core::cmp::Reverse(b.span.end),
        )
    });

    let has_overlap = fixes.windows(2).any(|w| {
        w.first()
            .zip(w.get(1))
            .is_some_and(|(later, earlier)| earlier.span.end > later.span.start)
    });

    if has_overlap {
        let cfg = LinterConfig {
            included_rules: diagnostics
                .iter()
                .filter(|d| d.fix.is_some())
                .map(|d| d.rule_id.clone())
                .collect(),
            ..LinterConfig::default()
        };
        return rewrite_script(original_text, ExecutionContext::BatchFile, &cfg);
    }

    let mut result = original_text.to_owned();
    let mut applied = 0usize;

    for fix in fixes {
        let start = fix.span.start.0;
        let end = fix.span.end.0;
        if end <= result.len() && start <= end {
            result.replace_range(start..end, &fix.replacement);
            applied = applied.saturating_add(1);
        }
    }

    (result, applied)
}

/// Line-level edit operation produced by Longest-Common-Subsequence (LCS) diffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffOp<'a> {
    /// Line present unchanged in both original and fixed inputs.
    Equal(&'a str),
    /// Line deleted from original input.
    Delete(&'a str),
    /// Line inserted in fixed input.
    Insert(&'a str),
}

/// Generates a genuine LCS unified diff comparing `original_text` and `fixed_text` (`--diff`)
/// with 3 lines of context and accurate `@@ -old_start,old_len +new_start,new_len @@` hunk headers.
///
/// # Arguments
/// * `file_name` - File path for `--- a/...` and `+++ b/...` diff headers.
/// * `original_text` - Original source text.
/// * `fixed_text` - Fixed source text.
///
/// # Returns
/// Unified diff string (empty if `original_text == fixed_text`).
#[must_use]
pub fn generate_unified_diff(file_name: &str, original_text: &str, fixed_text: &str) -> String {
    if original_text == fixed_text {
        return String::new();
    }
    let orig_lines: Vec<&str> = original_text.lines().collect();
    let fixed_lines: Vec<&str> = fixed_text.lines().collect();
    let ops = compute_lcs_diff_ops(&orig_lines, &fixed_lines);
    if ops.iter().all(|op| matches!(op, DiffOp::Equal(_))) {
        // Line-ending-only difference where `.lines()` matched: show whole-line replacement
        let mut out = format!(
            "--- a/{file_name}{LF}+++ b/{file_name}{LF}@@ -1,{} +1,{} @@{LF}",
            orig_lines.len(),
            fixed_lines.len()
        );
        for l in &orig_lines {
            write!(out, "-{l}{LF}").unwrap_or(());
        }
        for l in &fixed_lines {
            write!(out, "+{l}{LF}").unwrap_or(());
        }
        return out;
    }
    format_unified_hunks(file_name, &ops, DIFF_CONTEXT_LINES)
}

/// Computes minimal line-level [`DiffOp`] sequence via prefix/suffix trimming + LCS dynamic programming.
///
/// # Arguments
/// * `orig` - Original line slice.
/// * `fixed` - Fixed line slice.
///
/// # Returns
/// Ordered [`DiffOp`] sequence transforming `orig` into `fixed`.
fn compute_lcs_diff_ops<'a>(orig: &[&'a str], fixed: &[&'a str]) -> Vec<DiffOp<'a>> {
    let mut prefix = 0usize;
    while orig.get(prefix).is_some() && orig.get(prefix) == fixed.get(prefix) {
        prefix = prefix.saturating_add(1);
    }

    let mut orig_end = orig.len();
    let mut fixed_end = fixed.len();
    while orig_end > prefix && fixed_end > prefix {
        let orig_tail = orig.get(orig_end.saturating_sub(1));
        let fixed_tail = fixed.get(fixed_end.saturating_sub(1));
        if orig_tail != fixed_tail {
            break;
        }
        orig_end = orig_end.saturating_sub(1);
        fixed_end = fixed_end.saturating_sub(1);
    }

    let mid_orig = orig.get(prefix..orig_end).unwrap_or(&[]);
    let mid_fixed = fixed.get(prefix..fixed_end).unwrap_or(&[]);
    let m = mid_orig.len();
    let n = mid_fixed.len();
    let mut rows: Vec<Vec<usize>> = Vec::with_capacity(m.saturating_add(1));
    rows.push(vec![0usize; n.saturating_add(1)]);

    for i in (0..m).rev() {
        let mut row_rev = Vec::with_capacity(n.saturating_add(1));
        row_rev.push(0usize);
        for j in (0..n).rev() {
            let next_row = rows.last();
            let val = if mid_orig.get(i) == mid_fixed.get(j) {
                next_row
                    .and_then(|r| r.get(j.saturating_add(1)))
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1)
            } else {
                let down = next_row.and_then(|r| r.get(j)).copied().unwrap_or(0);
                let right = row_rev.last().copied().unwrap_or(0);
                down.max(right)
            };
            row_rev.push(val);
        }
        row_rev.reverse();
        rows.push(row_rev);
    }
    rows.reverse();

    let dp_at = |r_idx: usize, c_idx: usize| -> usize {
        rows.get(r_idx)
            .and_then(|r| r.get(c_idx))
            .copied()
            .unwrap_or(0)
    };

    let mut ops = Vec::with_capacity(orig.len().saturating_add(fixed.len()));
    for &line in orig.get(..prefix).unwrap_or(&[]) {
        ops.push(DiffOp::Equal(line));
    }

    let mut i = 0usize;
    let mut j = 0usize;
    loop {
        match (mid_orig.get(i), mid_fixed.get(j)) {
            (Some(&lo), Some(&lf)) if lo == lf => {
                ops.push(DiffOp::Equal(lo));
                i = i.saturating_add(1);
                j = j.saturating_add(1);
            }
            (Some(_), Some(&lf))
                if dp_at(i, j.saturating_add(1)) >= dp_at(i.saturating_add(1), j) =>
            {
                ops.push(DiffOp::Insert(lf));
                j = j.saturating_add(1);
            }
            (None, Some(&lf)) => {
                ops.push(DiffOp::Insert(lf));
                j = j.saturating_add(1);
            }
            (Some(&lo), _) => {
                ops.push(DiffOp::Delete(lo));
                i = i.saturating_add(1);
            }
            (None, None) => break,
        }
    }

    for &line in orig.get(orig_end..).unwrap_or(&[]) {
        ops.push(DiffOp::Equal(line));
    }
    ops
}

/// Groups non-`Equal` [`DiffOp`] spans with `context` lines and formats unified diff hunks.
///
/// # Arguments
/// * `file_name` - File path for diff headers.
/// * `ops` - Complete [`DiffOp`] sequence.
/// * `context` - Context radius in unchanged lines.
///
/// # Returns
/// Formatted unified diff string.
fn format_unified_hunks(file_name: &str, ops: &[DiffOp<'_>], context: usize) -> String {
    let mut hunks: Vec<(usize, usize)> = Vec::new();
    for (idx, op) in ops.iter().enumerate() {
        if !matches!(op, DiffOp::Equal(_)) {
            let start = idx.saturating_sub(context);
            let end = idx.saturating_add(1).saturating_add(context).min(ops.len());
            if let Some(last) = hunks.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
                continue;
            }
            hunks.push((start, end));
        }
    }

    let mut out = format!("--- a/{file_name}{LF}+++ b/{file_name}{LF}");
    for (h_start, h_end) in hunks {
        let before_slice = ops.get(..h_start).unwrap_or(&[]);
        let hunk_slice = ops.get(h_start..h_end).unwrap_or(&[]);

        let old_before = before_slice
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Delete(_)))
            .count();
        let new_before = before_slice
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Insert(_)))
            .count();
        let old_len = hunk_slice
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Delete(_)))
            .count();
        let new_len = hunk_slice
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Insert(_)))
            .count();

        let old_start = if old_len == 0 {
            old_before
        } else {
            old_before.saturating_add(1)
        };
        let new_start = if new_len == 0 {
            new_before
        } else {
            new_before.saturating_add(1)
        };

        write!(
            out,
            "@@ -{old_start},{old_len} +{new_start},{new_len} @@{LF}"
        )
        .unwrap_or(());
        for op in hunk_slice {
            match op {
                DiffOp::Equal(l) => write!(out, " {l}{LF}").unwrap_or(()),
                DiffOp::Delete(l) => write!(out, "-{l}{LF}").unwrap_or(()),
                DiffOp::Insert(l) => write!(out, "+{l}{LF}").unwrap_or(()),
            }
        }
    }
    out
}

/// Formats a list of [`Diagnostic`]s using the requested [`OutputFormat`] (`TTY`, `JSON`, `SARIF`, `GCC`).
///
/// # Arguments
/// * `diagnostics` - Diagnostics to render.
/// * `source_map` - [`SourceMap`] for resolving spans and source snippets.
/// * `format` - Target [`OutputFormat`].
///
/// # Returns
/// Formatted output string.
#[must_use]
pub fn format_diagnostics(
    diagnostics: &[Diagnostic],
    source_map: &SourceMap,
    format: OutputFormat,
) -> String {
    match format {
        OutputFormat::Tty => format_tty(diagnostics, source_map),
        OutputFormat::Gcc => format_gcc(diagnostics, source_map),
        OutputFormat::Json => format_json(diagnostics, source_map),
        OutputFormat::Sarif => format_sarif(diagnostics, source_map),
    }
}

/// Formats diagnostics in rich `ShellCheck` / `rustc` TTY style with source snippets and `^~~~` carets.
///
/// # Arguments
/// * `diagnostics` - Diagnostics to render.
/// * `source_map` - [`SourceMap`] used to resolve spans and fetch source lines.
///
/// # Returns
/// Formatted TTY text.
fn format_tty(diagnostics: &[Diagnostic], source_map: &SourceMap) -> String {
    let mut out = String::new();
    for d in diagnostics {
        let resolved = source_map.resolve_span(d.primary_span);
        write!(
            out,
            "{}:{}:{}: {}[{}]: {}{LF}",
            resolved.file_name,
            resolved.start_line,
            resolved.start_col,
            d.severity,
            d.rule_id,
            d.message
        )
        .unwrap_or(());
        if let Some(line_str) = source_map
            .get_file(d.primary_span.source_id)
            .and_then(|sf| sf.line_text(resolved.start_line))
        {
            let lnum = resolved.start_line.get();
            write!(out, " {lnum:>4} | {line_str}{LF}").unwrap_or(());
            let col_offset = resolved.start_col.get().saturating_sub(1);
            let width = if resolved.end_line == resolved.start_line {
                resolved
                    .end_col
                    .get()
                    .saturating_sub(resolved.start_col.get())
                    .max(1)
            } else {
                line_str.chars().count().saturating_sub(col_offset).max(1)
            };
            let pad = " ".repeat(col_offset);
            let carets = format!("^{}", "~".repeat(width.saturating_sub(1)));
            write!(out, "      | {pad}{carets}{LF}").unwrap_or(());
        }
        if let Some(help) = &d.help {
            write!(out, "      = help: {help}{LF}").unwrap_or(());
        }
        if let Some(fix) = &d.fix {
            write!(
                out,
                "      = fix ({}): `{}`{LF}",
                fix.description, fix.replacement
            )
            .unwrap_or(());
        }
        out.push(LF);
    }
    out
}

/// Formats diagnostics in single-line GCC style (`file:line:col: severity: message [CMDxxxx]`).
///
/// # Arguments
/// * `diagnostics` - Diagnostics to render.
/// * `source_map` - [`SourceMap`] used to resolve spans.
///
/// # Returns
/// Formatted GCC lines.
fn format_gcc(diagnostics: &[Diagnostic], source_map: &SourceMap) -> String {
    let mut out = String::new();
    for d in diagnostics {
        let r = source_map.resolve_span(d.primary_span);
        write!(
            out,
            "{}:{}:{}: {}: {} [{}]{LF}",
            r.file_name, r.start_line, r.start_col, d.severity, d.message, d.rule_id
        )
        .unwrap_or(());
    }
    out
}

/// Formats diagnostics as a deterministic JSON array.
///
/// # Arguments
/// * `diagnostics` - Diagnostics to render.
/// * `source_map` - [`SourceMap`] used to resolve spans.
///
/// # Returns
/// Formatted JSON array string.
fn format_json(diagnostics: &[Diagnostic], source_map: &SourceMap) -> String {
    let mut items = Vec::with_capacity(diagnostics.len());
    for d in diagnostics {
        let r = source_map.resolve_span(d.primary_span);
        let help_json = d.help.as_ref().map_or_else(
            || "null".to_owned(),
            |h| format!(r#""{}""#, escape_json_str(h)),
        );
        let fix_json = d.fix.as_ref().map_or_else(
            || "null".to_owned(),
            |f| {
                format!(
                    r#"{{"description":"{}","replacement":"{}"}}"#,
                    escape_json_str(&f.description),
                    escape_json_str(&f.replacement)
                )
            },
        );
        items.push(format!(
            r#"{{"file":"{}","line":{},"column":{},"endLine":{},"endColumn":{},"code":"{}","severity":"{}","message":"{}","help":{},"fix":{}}}"#,
            escape_json_str(&r.file_name),
            r.start_line.get(),
            r.start_col.get(),
            r.end_line.get(),
            r.end_col.get(),
            escape_json_str(d.rule_id.as_str()),
            d.severity,
            escape_json_str(&d.message),
            help_json,
            fix_json
        ));
    }
    let sep = format!(",{LF}  ");
    format!("[{LF}  {}{LF}]{LF}", items.join(&sep))
}

/// Formats diagnostics according to the SARIF v2.1.0 schema.
///
/// # Arguments
/// * `diagnostics` - Diagnostics to render.
/// * `source_map` - [`SourceMap`] used to resolve spans.
///
/// # Returns
/// Formatted SARIF v2.1.0 JSON string.
fn format_sarif(diagnostics: &[Diagnostic], source_map: &SourceMap) -> String {
    let rules_meta: Vec<String> = all_rule_metadata()
        .into_iter()
        .map(|m| {
            format!(
                r#"{{"id":"{}","name":"{}","shortDescription":{{"text":"{}"}}}}"#,
                escape_json_str(m.id.as_str()),
                escape_json_str(m.name),
                escape_json_str(m.summary)
            )
        })
        .collect();
    let mut results = Vec::with_capacity(diagnostics.len());
    for d in diagnostics {
        let r = source_map.resolve_span(d.primary_span);
        results.push(format!(
            r#"{{"ruleId":"{}","level":"{}","message":{{"text":"{}"}},"locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"{}"}},"region":{{"startLine":{},"startColumn":{},"endLine":{},"endColumn":{}}}}}}}]}}"#,
            escape_json_str(d.rule_id.as_str()),
            d.severity.sarif_level(),
            escape_json_str(&d.message),
            escape_json_str(&r.file_name),
            r.start_line.get(),
            r.start_col.get(),
            r.end_line.get(),
            r.end_col.get()
        ));
    }
    format!(
        r#"{{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"wincheck","version":"0.1.0","rules":[{}]}}}},"results":[{}]}}]}}{LF}"#,
        rules_meta.join(","),
        results.join(",")
    )
}

/// Escapes special and control characters (`U+0000..=U+001F`) inside a JSON string literal per RFC 8259.
///
/// # Arguments
/// * `s` - Raw unescaped string slice.
///
/// # Returns
/// RFC 8259 JSON-escaped string.
fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str(r#"\""#),
            '\\' => out.push_str(r"\\"),
            '\x08' => out.push_str(r"\b"),
            '\x0c' => out.push_str(r"\f"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            c if (c as u32) < 0x20 => {
                let code = c as u32;
                out.push_str(r"\u00");
                out.push(char::from_digit((code >> 4) & 0xF, 16).unwrap_or('0'));
                out.push(char::from_digit(code & 0xF, 16).unwrap_or('0'));
            }
            c => out.push(c),
        }
    }
    out
}
