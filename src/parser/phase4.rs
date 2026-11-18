//! Phase 4: Delayed environment variable expansion (`!VAR!`) and the `!`-triggered caret (`^`) pass.
//!
//! In `cmd.exe`, when Delayed Expansion is enabled (`SETLOCAL EnableDelayedExpansion` or `/V:ON`):
//! - If the command line does NOT contain any `!` character, Phase 4 does nothing at all.
//! - If the command line contains at least one `!` character, `cmd.exe` performs an extra scan
//!   where `^` escapes the next character (even INSIDE double quotes `"..."`!) and unescaped
//!   `!VAR!` / `!VAR:~offset,len!` / `!VAR:old=new!` sequences are expanded.

use alloc::string::String;
use alloc::vec::Vec;

use crate::parser::phase1::push_expanded_text;
use crate::parser::var_ops::evaluate_var_expression;
use crate::reader::char_map::{ExpansionOrigin, LogicalLineBuffer, SpannedChar};
use crate::types::{DelayedExpansionMode, EnvVarName};

/// Executes Phase 4 delayed variable expansion (`!VAR!`) on `input`.
///
/// # Arguments
/// * `input` - Input [`LogicalLineBuffer`] right before simple command execution.
/// * `mode` - Current [`DelayedExpansionMode`].
/// * `env_lookup` - Closure resolving current runtime environment & dynamic variables.
///
/// # Returns
/// A new [`LogicalLineBuffer`] with Phase 4 delayed expansion and caret escaping applied.
#[must_use]
pub fn expand_phase4<F>(
    input: &LogicalLineBuffer,
    mode: DelayedExpansionMode,
    env_lookup: F,
) -> LogicalLineBuffer
where
    F: Fn(&str) -> Option<String>,
{
    if matches!(mode, DelayedExpansionMode::Disabled) {
        return input.clone();
    }

    // Authentic cmd.exe quirk: Phase 4 only runs if at least one `!` exists in the buffer!
    if !input.chars.iter().any(|sc| sc.ch == '!') {
        return input.clone();
    }

    // Step 1: Process `^` escapes across the buffer (even inside quotes) when `!` is present.
    let mut caret_processed: Vec<SpannedChar> = Vec::with_capacity(input.chars.len());
    let mut i = 0usize;
    while let Some(sc) = input.chars.get(i) {
        if sc.ch == '^'
            && !sc.escaped_by_caret
            && let Some(next_sc) = input.chars.get(i.saturating_add(1))
        {
            caret_processed.push(SpannedChar {
                ch: next_sc.ch,
                span: sc.span.merge(next_sc.span),
                escaped_by_caret: true,
                origin: next_sc.origin.clone(),
            });
            i = i.saturating_add(2);
            continue;
        }
        caret_processed.push(sc.clone());
        i = i.saturating_add(1);
    }

    // Step 2: Expand unescaped `!VAR!` pairs.
    let mut out = LogicalLineBuffer {
        chars: Vec::with_capacity(caret_processed.len()),
        broken_caret_span: input.broken_caret_span,
    };

    let mut idx = 0usize;
    while let Some(sc) = caret_processed.get(idx) {
        if sc.ch != '!' || sc.escaped_by_caret {
            out.chars.push(sc.clone());
            idx = idx.saturating_add(1);
            continue;
        }

        // Look ahead for the next unescaped `!`
        if let Some(close_idx) = find_closing_bang(&caret_processed, idx.saturating_add(1)) {
            let inner_slice = caret_processed
                .get(idx.saturating_add(1)..close_idx)
                .unwrap_or(&[]);
            let expr_str: String = inner_slice.iter().map(|c| c.ch).collect();
            let close_span = caret_processed.get(close_idx).map_or(sc.span, |c| c.span);
            let var_span = sc.span.merge(close_span);

            if !expr_str.is_empty()
                && let Some((var_name, expanded_val)) =
                    evaluate_var_expression(&expr_str, &env_lookup)
            {
                let origin = ExpansionOrigin::DelayedEnvVar {
                    var_span,
                    var_name: EnvVarName::new(&var_name),
                };
                push_expanded_text(&mut out.chars, &expanded_val, var_span, &origin);
            }
            // In cmd.exe delayed expansion, undefined `!VAR!` or empty `!!` expands to `""`
            idx = close_idx.saturating_add(1);
        } else {
            // Unmatched trailing `!` is stripped when delayed expansion is active
            idx = idx.saturating_add(1);
        }
    }

    out
}

/// Finds the next unescaped `!` character in `chars` starting at `start_idx`.
///
/// # Arguments
/// * `chars` - Slice of [`SpannedChar`].
/// * `start_idx` - Search start index.
///
/// # Returns
/// `Some(index)` of the matching unescaped `!`, or `None`.
fn find_closing_bang(chars: &[SpannedChar], start_idx: usize) -> Option<usize> {
    let tail = chars.get(start_idx..).unwrap_or(&[]);
    let rel = tail
        .iter()
        .position(|sc| sc.ch == '!' && !sc.escaped_by_caret)?;
    Some(start_idx.saturating_add(rel))
}

#[cfg(test)]
/// Unit tests for Phase 4 delayed `!VAR!` expansion and `!`-triggered caret unescaping.
mod tests {
    use super::*;
    use crate::span::{ByteOffset, SourceId, Span};

    /// Verifies delayed `!VAR!` expansion, slicing/replacement, and `!`-triggered caret unescaping.
    #[test]
    fn test_phase4_delayed_expansion_and_caret_quirk() {
        let lookup = |k: &str| {
            if k.eq_ignore_ascii_case("COUNT") {
                Some("42".to_owned())
            } else {
                None
            }
        };

        // 1. Disabled mode does nothing
        let line1 = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "echo !COUNT! ^!");
        assert_eq!(
            expand_phase4(&line1, DelayedExpansionMode::Disabled, lookup).to_plain_string(),
            "echo !COUNT! ^!"
        );

        // 2. Enabled mode with NO `!` on line leaves `^` untouched!
        let line2 = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), r#"echo "a^^b""#);
        assert_eq!(
            expand_phase4(&line2, DelayedExpansionMode::Enabled, lookup).to_plain_string(),
            r#"echo "a^^b""#
        );

        // 3. Enabled mode WITH `!` expands `!COUNT!`, strips `!UNDEF!`, strips `!!`, strips stray `!`, and processes `^!` and trailing `^`
        let mut line3 = LogicalLineBuffer::from_str_at(
            SourceId(0),
            ByteOffset(0),
            r#"echo !COUNT! !COUNT:~0,1! !UNDEF! !! "^!" stray! "#,
        );
        line3.chars.push(SpannedChar {
            ch: '^',
            span: Span::dummy(),
            escaped_by_caret: true,
            origin: ExpansionOrigin::LiteralSource,
        });
        line3.chars.push(SpannedChar::literal(' ', Span::dummy()));
        line3.chars.push(SpannedChar::literal('^', Span::dummy()));
        assert_eq!(
            expand_phase4(&line3, DelayedExpansionMode::Enabled, lookup).to_plain_string(),
            r#"echo 42 4   "!" stray ^ ^"#
        );
    }
}
