//! Phase 1: Batch positional parameter (`%0`..`%9`, `%*`, `%~dp0`) and immediate `%VAR%` expansion.
//!
//! Models the exact differences between Batch Mode (`ExecutionContext::BatchFile`) and
//! Interactive Mode (`ExecutionContext::InteractiveRepl`):
//! - In Batch Mode: `%%` collapses to a single `%`, `%0`..`%9`/`%*` expand, undefined `%VAR%`
//!   expands to `""`, and stray single `%` is stripped.
//! - In Interactive Mode: `%%` stays `%%`, `%0`..`%9` are not expanded, and undefined `%VAR%`
//!   is preserved literally as `%VAR%` (advancing past the closing `%` so `%UNDEF1%_%UNDEF2%`
//!   never falsely pairs the middle `%_%`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::CmdError;
use crate::parser::modifiers::{ParameterModifiers, parse_dollar_env_modifier};
use crate::parser::var_ops::evaluate_var_expression;
use crate::reader::char_map::{ExpansionOrigin, LogicalLineBuffer, SpannedChar};
use crate::span::Span;
use crate::types::{EnvVarName, ExecutionContext, PercentArity, TAB_CHAR};
use crate::vfs::VirtualFileSystem;

/// Context supplied to Phase 1 expansion.
pub struct Phase1Context<'a, F>
where
    F: Fn(&str) -> Option<String>,
{
    /// Whether we are expanding inside a batch file or interactive prompt.
    pub exec_context: ExecutionContext,
    /// Batch script name `%0` (e.g., `"script.bat"` or `":subroutine"`).
    pub arg0: &'a str,
    /// Positional parameters `%1`..`%9`+ (indexed from 0 for `%1`).
    pub positional_args: &'a [String],
    /// Raw tail of all positional arguments `%*`.
    pub all_args_raw: &'a str,
    /// Active VFS for `%~dp0` path and attribute resolution.
    pub vfs: &'a dyn VirtualFileSystem,
    /// Closure resolving environment & dynamic variables (`%VAR%`, `%CD%`, `%ERRORLEVEL%`, etc.).
    pub env_lookup: F,
}

/// Executes Phase 1 `%` expansion on a [`LogicalLineBuffer`].
///
/// # Arguments
/// * `input` - The input [`LogicalLineBuffer`] from Phase 0.
/// * `ctx` - The [`Phase1Context`] providing positional arguments, VFS, and environment lookup.
///
/// # Returns
/// `Ok(LogicalLineBuffer)` with Phase 1 expansions applied and full [`Span`] provenance preserved.
///
/// # Errors
/// Returns [`CmdError::InvalidParameterModifier`] if a malformed `%~` sequence is encountered in batch mode.
pub fn expand_phase1<F>(
    input: &LogicalLineBuffer,
    ctx: &Phase1Context<'_, F>,
) -> Result<LogicalLineBuffer, CmdError>
where
    F: Fn(&str) -> Option<String>,
{
    let arity = PercentArity::for_execution_context(ctx.exec_context);
    let chars = &input.chars;
    let mut out = LogicalLineBuffer {
        chars: Vec::with_capacity(chars.len()),
        broken_caret_span: input.broken_caret_span,
    };

    let mut idx = 0usize;
    while let Some(sc) = chars.get(idx) {
        if sc.ch != '%' {
            out.chars.push(sc.clone());
            idx = idx.saturating_add(1);
            continue;
        }

        // Check for `%%`
        if let Some(next_sc) = chars.get(idx.saturating_add(1))
            && next_sc.ch == '%'
        {
            match arity {
                PercentArity::DoublePercent => {
                    out.chars.push(SpannedChar {
                        ch: '%',
                        span: sc.span.merge(next_sc.span),
                        escaped_by_caret: false,
                        origin: ExpansionOrigin::LiteralSource,
                    });
                }
                PercentArity::SinglePercent => {
                    out.chars.push(sc.clone());
                    out.chars.push(next_sc.clone());
                }
            }
            idx = idx.saturating_add(2);
            continue;
        }

        // In batch mode (`PercentArity::DoublePercent`), check for `%*`, `%0`..`%9`, and `%~...`
        if arity == PercentArity::DoublePercent
            && let Some(next_idx) = try_expand_batch_parameter(chars, idx, sc, ctx, &mut out.chars)?
        {
            idx = next_idx;
            continue;
        }

        // Look ahead for a closing `%` on the same line to form `%VAR%`
        if let Some(close_idx) = find_closing_percent(chars, idx.saturating_add(1)) {
            let inner_slice = chars.get(idx.saturating_add(1)..close_idx).unwrap_or(&[]);
            let expr_str: String = inner_slice.iter().map(|c| c.ch).collect();
            let close_span = chars.get(close_idx).map_or(sc.span, |c| c.span);
            let var_span = sc.span.merge(close_span);

            if let Some((var_name, expanded_val)) =
                evaluate_var_expression(&expr_str, &ctx.env_lookup)
            {
                push_expanded_text(
                    &mut out.chars,
                    &expanded_val,
                    var_span,
                    &ExpansionOrigin::ImmediateEnvVar {
                        var_span,
                        var_name: EnvVarName::new(&var_name),
                    },
                );
                idx = close_idx.saturating_add(1);
                continue;
            }
            if arity == PercentArity::DoublePercent {
                // In batch mode, undefined `%VAR%` expands to empty string `""`
                idx = close_idx.saturating_add(1);
                continue;
            }
            if !expr_str.contains([' ', TAB_CHAR]) {
                // In interactive mode, undefined `%UNDEF%` (with no whitespace) stays literal
                // `%UNDEF%` and advances past `close_idx` so its closing `%` never pairs with
                // a subsequent `%VAR%` on the same line.
                out.chars
                    .extend_from_slice(chars.get(idx..=close_idx).unwrap_or(&[]));
                idx = close_idx.saturating_add(1);
                continue;
            }
        }

        // Unmatched `%` (stripped in batch mode, preserved in interactive/subshell mode)
        if arity == PercentArity::SinglePercent {
            out.chars.push(sc.clone());
        }
        idx = idx.saturating_add(1);
    }

    Ok(out)
}

/// Attempts to expand a batch-mode parameter token (`%*`, `%0`..`%9`, or `%~...`) at `idx`.
///
/// # Arguments
/// * `chars` - Input [`SpannedChar`] slice.
/// * `idx` - Index of the leading `%` character.
/// * `pct_sc` - Leading `%` [`SpannedChar`].
/// * `ctx` - Active [`Phase1Context`].
/// * `out_chars` - Output [`SpannedChar`] accumulator.
///
/// # Returns
/// `Ok(Some(next_idx))` if a batch parameter was expanded, or `Ok(None)` if `chars[idx..]` is not a positional parameter.
///
/// # Errors
/// Returns [`CmdError::InvalidParameterModifier`] if a malformed `%~` sequence is encountered.
fn try_expand_batch_parameter<F>(
    chars: &[SpannedChar],
    idx: usize,
    pct_sc: &SpannedChar,
    ctx: &Phase1Context<'_, F>,
    out_chars: &mut Vec<SpannedChar>,
) -> Result<Option<usize>, CmdError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(next_sc) = chars.get(idx.saturating_add(1)) else {
        return Ok(None);
    };
    if next_sc.ch == '*' {
        let param_span = pct_sc.span.merge(next_sc.span);
        push_expanded_text(
            out_chars,
            ctx.all_args_raw,
            param_span,
            &ExpansionOrigin::PositionalParam {
                param_span,
                index: 255,
            },
        );
        return Ok(Some(idx.saturating_add(2)));
    }
    if next_sc.ch.is_ascii_digit() {
        let digit = (next_sc.ch as u8).saturating_sub(b'0');
        let param_span = pct_sc.span.merge(next_sc.span);
        let val = get_positional_arg(digit, ctx.arg0, ctx.positional_args);
        push_expanded_text(
            out_chars,
            val,
            param_span,
            &ExpansionOrigin::PositionalParam {
                param_span,
                index: digit,
            },
        );
        return Ok(Some(idx.saturating_add(2)));
    }
    if next_sc.ch == '~' {
        return match try_parse_batch_param_modifier(chars, idx) {
            ModifierParseResult::Matched(matched) => {
                let raw_val = get_positional_arg(matched.digit, ctx.arg0, ctx.positional_args);
                let expanded = matched
                    .modifiers
                    .evaluate(raw_val, ctx.vfs, &ctx.env_lookup);
                push_expanded_text(
                    out_chars,
                    &expanded,
                    matched.full_span,
                    &ExpansionOrigin::PositionalParam {
                        param_span: matched.full_span,
                        index: matched.digit,
                    },
                );
                Ok(Some(matched.end_idx))
            }
            ModifierParseResult::Invalid { span, sequence } => {
                Err(CmdError::InvalidParameterModifier { span, sequence })
            }
        };
    }
    Ok(None)
}

/// Matched `%~<modifiers><0..9>` payload.
struct MatchedModifierParam {
    /// Parsed [`ParameterModifiers`].
    modifiers: ParameterModifiers,
    /// Parameter index `0..=9`.
    digit: u8,
    /// Exclusive index in `chars` after the digit.
    end_idx: usize,
    /// Merged [`Span`] of the entire `%~...n` sequence.
    full_span: Span,
}

/// Outcome of attempting to parse `%~[modifiers]n` in Phase 1.
enum ModifierParseResult {
    /// Successfully parsed `%~<modifiers><0..9>`.
    Matched(MatchedModifierParam),
    /// Invalid `%~` sequence that did not terminate in a parameter digit `0..9`.
    Invalid {
        /// Span of the invalid sequence.
        span: Span,
        /// Offending sequence text.
        sequence: String,
    },
}

/// Parses a `%~...` sequence starting at `percent_idx` in `chars`.
///
/// # Arguments
/// * `chars` - Slice of [`SpannedChar`] for the current line.
/// * `percent_idx` - Index of the leading `%`.
///
/// # Returns
/// [`ModifierParseResult`] indicating either a valid modifier + digit or an invalid modifier error.
fn try_parse_batch_param_modifier(
    chars: &[SpannedChar],
    percent_idx: usize,
) -> ModifierParseResult {
    let start_span = chars.get(percent_idx).map_or_else(Span::dummy, |c| c.span);
    let mut modifiers = ParameterModifiers::default();
    let mut cur = percent_idx.saturating_add(2);

    while let Some(sc) = chars.get(cur) {
        if sc.ch.is_ascii_digit() {
            let digit = (sc.ch as u8).saturating_sub(b'0');
            return ModifierParseResult::Matched(MatchedModifierParam {
                modifiers,
                digit,
                end_idx: cur.saturating_add(1),
                full_span: start_span.merge(sc.span),
            });
        }
        if sc.ch == '$' {
            if let Some((var_name, next_cur)) = parse_dollar_env_modifier(chars, cur) {
                modifiers.path_search_var = Some(var_name);
                cur = next_cur;
                continue;
            }
            break;
        }
        if modifiers.add_flag(sc.ch) {
            cur = cur.saturating_add(1);
        } else {
            break;
        }
    }

    let err_end = (cur.saturating_add(1)).min(chars.len());
    let slice = chars.get(percent_idx..err_end).unwrap_or(&[]);
    let seq: String = slice.iter().map(|c| c.ch).collect();
    let end_span = slice.last().map_or(start_span, |c| c.span);
    ModifierParseResult::Invalid {
        span: start_span.merge(end_span),
        sequence: seq,
    }
}

/// Retrieves the value of positional parameter `%0`..`%9`.
///
/// # Arguments
/// * `digit` - Parameter index `0..=9`.
/// * `arg0` - Value of `%0`.
/// * `positional_args` - Slice of `%1`..`%9`+ arguments.
///
/// # Returns
/// String slice for the requested positional parameter (or `""` if unset).
fn get_positional_arg<'a>(digit: u8, arg0: &'a str, positional_args: &'a [String]) -> &'a str {
    if digit == 0 {
        arg0
    } else {
        let idx = usize::from(digit.saturating_sub(1));
        positional_args.get(idx).map_or("", String::as_str)
    }
}

/// Finds the next `%` character in `chars` starting at `start_idx`.
///
/// # Arguments
/// * `chars` - Slice of [`SpannedChar`].
/// * `start_idx` - Index after the opening `%`.
///
/// # Returns
/// `Some(index)` of the matching `%`, or `None`.
fn find_closing_percent(chars: &[SpannedChar], start_idx: usize) -> Option<usize> {
    let tail = chars.get(start_idx..).unwrap_or(&[]);
    let rel = tail.iter().position(|sc| sc.ch == '%')?;
    Some(start_idx.saturating_add(rel))
}

/// Appends each character of `text` to `out` with the given `span` and `origin`.
///
/// # Arguments
/// * `out` - Output [`SpannedChar`] vector.
/// * `text` - Expanded string to append.
/// * `span` - Source [`Span`] of the macro/variable token.
/// * `origin` - [`ExpansionOrigin`] metadata.
pub fn push_expanded_text(
    out: &mut Vec<SpannedChar>,
    text: &str,
    span: Span,
    origin: &ExpansionOrigin,
) {
    out.extend(text.chars().map(|ch| SpannedChar {
        ch,
        span,
        escaped_by_caret: false,
        origin: origin.clone(),
    }));
}

#[cfg(test)]
/// Unit tests for Phase 1 `%VAR%`, positional `%1`, and `%%` expansion.
mod tests {
    use super::*;
    use crate::span::{ByteOffset, SourceId};
    use crate::types::BS_STR as SEP;
    use crate::vfs::InMemoryVfs;

    /// Verifies Phase 1 `%` expansion parity across batch files and interactive REPL sessions.
    #[test]
    fn test_phase1_batch_vs_interactive_expansion() {
        let mut vfs = InMemoryVfs::new();
        assert!(
            vfs.create_dir("C:/scripts", crate::types::DirCreationDepth::CreateParents)
                .is_ok()
        );
        assert!(vfs.write_bytes("C:/scripts/run.bat", b"@echo off").is_ok());

        let quoted_bat = format!(r#""C:{SEP}scripts{SEP}run.bat""#);
        let args = vec![quoted_bat.clone(), "arg_two".to_owned()];
        let all_raw = format!("{quoted_bat} arg_two");
        let scripts_dir = format!("C:{SEP}scripts");
        let env_lookup = |k: &str| match k.to_ascii_uppercase().as_str() {
            "GREETING" => Some("Hello".to_owned()),
            "_" => Some("HACK".to_owned()),
            "PATH" => Some(scripts_dir.clone()),
            _ => None,
        };

        // 1. Batch mode: %%, %0, %~dp1, %~$PATH:0, %*, %GREETING%, %UNDEFINED%, stray %
        let line = LogicalLineBuffer::from_str_at(
            SourceId(0),
            ByteOffset(0),
            "echo 100%% %0 %~dp1 %~$PATH:0 [%*] %GREETING% %UNDEF% stray%",
        );
        let batch_ctx = Phase1Context {
            exec_context: ExecutionContext::BatchFile,
            arg0: "run.bat",
            positional_args: &args,
            all_args_raw: &all_raw,
            vfs: &vfs,
            env_lookup,
        };
        let expanded = expand_phase1(&line, &batch_ctx);
        let expected_batch = format!(
            "echo 100% run.bat C:{SEP}scripts{SEP} C:{SEP}scripts{SEP}run.bat [{all_raw}] Hello  stray"
        );
        assert_eq!(expanded.map(|b| b.to_plain_string()), Ok(expected_batch));

        // 2. Interactive mode: %% stays %%, %1 stays %1, %UNDEF1%_%UNDEF2% does NOT expand `%_%`, while explicit `%_%` does!
        let repl_line = LogicalLineBuffer::from_str_at(
            SourceId(0),
            ByteOffset(0),
            "echo %% %1 %UNDEF1%_%UNDEF2% %_% %GREETING% %UNDEF% stray%",
        );
        let repl_ctx = Phase1Context {
            exec_context: ExecutionContext::InteractiveRepl,
            arg0: "cmd",
            positional_args: &[],
            all_args_raw: "",
            vfs: &vfs,
            env_lookup,
        };
        let repl_expanded = expand_phase1(&repl_line, &repl_ctx);
        assert_eq!(
            repl_expanded.map(|b| b.to_plain_string()),
            Ok("echo %% %1 %UNDEF1%_%UNDEF2% HACK Hello %UNDEF% stray%".to_owned())
        );

        // 3. Invalid `%~` modifier in batch mode returns InvalidParameterModifier
        let bad_mod = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "echo %~dpVAR%");
        assert!(expand_phase1(&bad_mod, &batch_ctx).is_err());

        let bad_dollar =
            LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "echo %~$UNCLOSED 1");
        assert!(expand_phase1(&bad_dollar, &batch_ctx).is_err());

        for edge in ["%~f", "%~$EOF", "%~$%1", "%~$:1"] {
            let buf = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), edge);
            let res = expand_phase1(&buf, &batch_ctx);
            assert!(res.is_err());
        }
    }
}
