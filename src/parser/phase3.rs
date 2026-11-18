//! Phase 3: `FOR` loop variable expansion (`%I`, `%~nxI`).
//!
//! After Phase 1 collapses `%%I` into `%I` inside a batch script (or directly as `%I` in
//! interactive mode), Phase 3 expands active `FOR` loop variables and their `%~` modifiers
//! immediately before command execution.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::CmdError;
use crate::parser::modifiers::{ParameterModifiers, parse_dollar_env_modifier};
use crate::parser::phase1::push_expanded_text;
use crate::reader::char_map::{ExpansionOrigin, LogicalLineBuffer, SpannedChar};
use crate::span::Span;
use crate::types::ForVarName;
use crate::vfs::VirtualFileSystem;

/// Expands active `FOR` loop variables (`%I` and `%~<modifiers>I`) in `input`.
///
/// Inner loops shadow outer loops when binding the same `FOR` variable character.
/// Note that `FOR` variable characters are **case-sensitive** (`%a` != `%A`).
///
/// # Arguments
/// * `input` - Input [`LogicalLineBuffer`].
/// * `for_vars` - Active stack of `(ForVarName, current_value)` bindings (searched from back/innermost to front).
/// * `vfs` - Active [`VirtualFileSystem`] for `%~` modifier evaluation.
/// * `env_lookup` - Closure resolving environment variables (for `%~$PATH:I`).
///
/// # Returns
/// `Ok(LogicalLineBuffer)` with all matching `FOR` variables expanded.
///
/// # Errors
/// Returns [`CmdError::InvalidParameterModifier`] if a malformed `%~` modifier is encountered.
pub fn expand_phase3<F>(
    input: &LogicalLineBuffer,
    for_vars: &[(ForVarName, String)],
    vfs: &dyn VirtualFileSystem,
    env_lookup: F,
) -> Result<LogicalLineBuffer, CmdError>
where
    F: Fn(&str) -> Option<String>,
{
    if for_vars.is_empty() {
        return Ok(input.clone());
    }

    let chars = &input.chars;
    let mut out = LogicalLineBuffer {
        chars: Vec::with_capacity(chars.len()),
        broken_caret_span: input.broken_caret_span,
    };

    let lookup_for = |var: ForVarName| -> Option<&str> {
        for_vars
            .iter()
            .rev()
            .find(|(k, _)| *k == var)
            .map(|(_, v)| v.as_str())
    };

    let mut idx = 0usize;
    while let Some(sc) = chars.get(idx) {
        if sc.ch != '%' {
            out.chars.push(sc.clone());
            idx = idx.saturating_add(1);
            continue;
        }

        if let Some(next_sc) = chars.get(idx.saturating_add(1)) {
            if next_sc.ch == '~'
                && let Some((modifiers, var, val, end_idx, full_span)) =
                    try_parse_for_modifier(chars, idx, &lookup_for)
            {
                let expanded = modifiers.evaluate(val, vfs, &env_lookup);
                push_expanded_text(
                    &mut out.chars,
                    &expanded,
                    full_span,
                    &ExpansionOrigin::ForVariable {
                        token_span: full_span,
                        var,
                    },
                );
                idx = end_idx;
                continue;
            }

            if let Some(var) = ForVarName::from_char(next_sc.ch)
                && let Some(val) = lookup_for(var)
            {
                let token_span = sc.span.merge(next_sc.span);
                push_expanded_text(
                    &mut out.chars,
                    val,
                    token_span,
                    &ExpansionOrigin::ForVariable { token_span, var },
                );
                idx = idx.saturating_add(2);
                continue;
            }
        }

        out.chars.push(sc.clone());
        idx = idx.saturating_add(1);
    }

    Ok(out)
}

/// Matched `%~[modifiers]<ForVar>` payload returned by [`try_parse_for_modifier`].
type MatchedForModifier<'a> = (ParameterModifiers, ForVarName, &'a str, usize, Span);

/// Attempts to parse `%~[modifiers]<ForVar>` using `cmd.exe`'s greedy modifier backtracking rule.
///
/// Because a `FOR` variable name can itself be one of the modifier letters (e.g., `%%d`, `%%f`, `%%x`),
/// `cmd.exe` greedily consumes modifier letters and backtracks to find the furthest position that
/// matches an active `FOR` variable in `lookup_for`.
///
/// # Arguments
/// * `chars` - Line character slice.
/// * `percent_idx` - Index of `%`.
/// * `lookup_for` - Closure checking if a [`ForVarName`] is bound in the active `FOR` scope.
///
/// # Returns
/// `Some((ParameterModifiers, ForVarName, value, next_idx, Span))` if a bound `FOR` variable matched.
fn try_parse_for_modifier<'a, L>(
    chars: &[SpannedChar],
    percent_idx: usize,
    lookup_for: &L,
) -> Option<MatchedForModifier<'a>>
where
    L: Fn(ForVarName) -> Option<&'a str>,
{
    let start_span = chars.get(percent_idx).map_or_else(Span::dummy, |c| c.span);
    let mut cur = percent_idx.saturating_add(2);
    let mut best_match: Option<MatchedForModifier<'a>> = None;
    let mut modifiers = ParameterModifiers::default();

    while let Some(sc) = chars.get(cur) {
        if let Some(var) = ForVarName::from_char(sc.ch)
            && let Some(val) = lookup_for(var)
        {
            let next_cur = cur.saturating_add(1);
            let merged_span = start_span.merge(sc.span);
            best_match = Some((modifiers.clone(), var, val, next_cur, merged_span));
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

    best_match
}

#[cfg(test)]
/// Unit tests for Phase 3 `FOR` loop variable expansion and greedy `%~` modifiers.
mod tests {
    use super::*;
    use crate::span::{ByteOffset, SourceId};
    use crate::types::BS_STR as SEP;
    use crate::vfs::InMemoryVfs;

    /// Verifies `FOR` variable expansion (`%I`, `%%I`) and longest-match `%~` modifier evaluation.
    #[test]
    fn test_phase3_for_variable_expansion_and_greedy_modifiers() {
        let mut vfs = InMemoryVfs::new();
        assert!(
            vfs.create_dir("C:/work", crate::types::DirCreationDepth::CreateParents)
                .is_ok()
        );
        assert!(vfs.write_bytes("C:/work/notes.txt", b"data").is_ok());

        let work_dir = format!("C:{SEP}work");
        let env_lookup = |k: &str| {
            if k.eq_ignore_ascii_case("SEARCH") {
                Some(work_dir.clone())
            } else {
                None
            }
        };

        let line0 = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "echo %I");
        assert_eq!(
            expand_phase3(&line0, &[], &vfs, env_lookup).map(|b| b.to_plain_string()),
            Ok("echo %I".to_owned())
        );

        let vi = ForVarName(b'I');
        let vx = ForVarName(b'x');
        let quoted_notes = format!(r#""C:{SEP}work{SEP}notes.txt""#);
        let bindings = vec![
            (vi, "old".to_owned()),
            (vi, quoted_notes.clone()),
            (vx, "notes.txt".to_owned()),
        ];

        let line = LogicalLineBuffer::from_str_at(
            SourceId(0),
            ByteOffset(0),
            "echo %I %~nxI %~dp$SEARCH:x %~$UNSET:x %~$BAD %~$% %~$:x %\u{2022} %~unmatched %Z %",
        );
        let res = expand_phase3(&line, &bindings, &vfs, env_lookup);
        assert_eq!(
            res.map(|b| b.to_plain_string()),
            Ok(format!(
                "echo {quoted_notes} notes.txt C:{SEP}work{SEP}  %~$BAD %~$% %~$:x %\u{2022} %~unmatched %Z %"
            ))
        );
        for tail_case in ["%~$EOF", "%~f"] {
            let line_eof = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), tail_case);
            assert!(expand_phase3(&line_eof, &bindings, &vfs, env_lookup).is_ok());
        }
    }
}
