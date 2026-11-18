//! Unified statement/line/word/caret/quote lexer and linear-time operator scanner.
//!
//! Shared by both the lossless Concrete Syntax Tree builder ([`super::cst_parser`]) and
//! Phase 2 runtime execution ([`super::phase2`]), guaranteeing 100% identical statement
//! boundaries, `ECHO(` parenthesis handling, `SET /A` operator precedence, and argument tokenization.

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

use crate::parser::ast::{SpannedWord, WordPart};
use crate::parser::cst::{CstToken, SyntaxKind};
use crate::reader::char_map::{ExpansionOrigin, SpannedChar};
use crate::reader::stream::BatchFrameReader;
use crate::span::{ByteOffset, SourceId, Span};
use crate::types::{CR_CHAR, LF_CHAR, QuoteMode, TAB_CHAR};

/// Controls whether lowered/tokenized [`SpannedWord`]s allocate sub-word [`WordPart`] vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordPartsMode {
    /// Populate `SpannedWord.parts` with sub-word [`WordPart`] spans (used by `wincheck` static analysis).
    PopulateSubwordParts,
    /// Leave `SpannedWord.parts` empty (`Vec::new()`) for zero-allocation runtime execution.
    Lightweight,
}

/// Binary command operator precedence tiers (`&` < `&&`/`||` < `|`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOpKind {
    /// Unconditional sequence (`&`, precedence tier `1` — lowest).
    Seq,
    /// Conditional success (`&&`, precedence tier `2`).
    And,
    /// Conditional failure (`||`, precedence tier `2`).
    Or,
    /// Pipeline (`|`, precedence tier `3` — highest binary operator).
    Pipe,
}

impl BinOpKind {
    /// Returns the numeric binding power (`1` = `&`, `2` = `&&`/`||`, `3` = `|`).
    ///
    /// # Returns
    /// Precedence tier integer (`1..=3`).
    #[must_use]
    pub const fn binding_power(self) -> u8 {
        match self {
            Self::Seq => 1,
            Self::And | Self::Or => 2,
            Self::Pipe => 3,
        }
    }

    /// Returns the literal operator text (`"&"`, `"&&"`, `"||"`, or `"|"`).
    ///
    /// # Returns
    /// Static operator string slice.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Seq => "&",
            Self::And => "&&",
            Self::Or => "||",
            Self::Pipe => "|",
        }
    }
}

/// Top-level binary operator token discovered during linear `O(N)` expression scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopLevelBinOp {
    /// Operator classification (`&`, `&&`, `||`, `|`).
    pub kind: BinOpKind,
    /// Start index in `chars`.
    pub op_start: usize,
    /// Exclusive end index in `chars`.
    pub op_end: usize,
}

/// Logical statement unit read from source text via [`BatchFrameReader`], preserving every
/// physical character, caret continuation, and trailing line-ending token.
#[derive(Debug, Clone)]
pub struct StatementUnit {
    /// Starting physical [`ByteOffset`] of this unit.
    pub start_offset: ByteOffset,
    /// Next physical [`ByteOffset`] in `raw_text` after this unit and its trailing newline.
    pub next_byte_offset: ByteOffset,
    /// Characters of the statement body (including interior newlines and `^` continuations).
    pub chars: Vec<SpannedChar>,
    /// Optional trailing newline [`CstToken`] (`CRLF`, `LF`, or `CR`).
    pub trailing_newline: Option<CstToken>,
}

/// Checks whether `ch` is a standard `cmd.exe` horizontal delimiter (`' '`, `TAB`, `','`, `';'`, `'='`, `'NBSP'`).
///
/// # Arguments
/// * `ch` - Character to test.
///
/// # Returns
/// `true` if `ch` is a standard `cmd.exe` argument delimiter.
#[must_use]
pub const fn is_cmd_delimiter(ch: char) -> bool {
    matches!(ch, ' ' | TAB_CHAR | ',' | ';' | '=' | '\u{00A0}')
}

/// Checks whether `chars[idx]` is the `^` of a physical `^CRLF` / `^LF` / `^CR` line continuation.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `idx` - Index of the candidate `^` character.
///
/// # Returns
/// `Some(end_idx)` past the newline characters if a physical continuation starts at `idx`, else `None`.
#[must_use]
pub fn is_caret_line_continuation_at(chars: &[SpannedChar], idx: usize) -> Option<usize> {
    if chars.get(idx).map(|c| c.ch) != Some('^') {
        return None;
    }
    let next = chars
        .get(idx.saturating_add(1))
        .filter(|n| matches!(n.origin, ExpansionOrigin::CaretContinuation { .. }))?;
    let is_crlf = next.ch == CR_CHAR
        && chars
            .get(idx.saturating_add(2))
            .is_some_and(|c2| c2.ch == LF_CHAR);
    Some(idx.saturating_add(if is_crlf { 3 } else { 2 }))
}

/// Checks whether `chars[idx..]` is a broken caret continuation (`^` followed only by spaces/tabs before EOL/EOF).
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `idx` - Candidate `^` index.
///
/// # Returns
/// `Some(eol_idx)` if `chars[idx..eol_idx]` is a broken caret continuation, else `None`.
#[must_use]
pub fn is_broken_caret_at(chars: &[SpannedChar], idx: usize) -> Option<usize> {
    if !chars.get(idx).is_some_and(|c| c.is_raw('^')) {
        return None;
    }
    let ws_count = chars
        .get(idx.saturating_add(1)..)
        .unwrap_or(&[])
        .iter()
        .take_while(|c| c.ch == ' ' || c.ch == TAB_CHAR)
        .count();
    let cur = idx.saturating_add(1).saturating_add(ws_count);
    let at_eol = matches!(
        chars.get(cur),
        None | Some(SpannedChar {
            ch: CR_CHAR | LF_CHAR,
            ..
        })
    );
    (ws_count > 0 && at_eol).then_some(cur)
}

/// Checks if `chars[idx..]` begins with the `REM` comment keyword followed by a valid boundary.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `idx` - Starting index.
///
/// # Returns
/// `true` if `REM` starts at `idx`.
#[must_use]
pub fn is_rem_keyword_at(chars: &[SpannedChar], idx: usize) -> bool {
    let tail = chars.get(idx..).unwrap_or(&[]);
    if tail.len() < 3 {
        return false;
    }
    let head: String = tail.iter().take(3).map(|c| c.ch).collect();
    head.eq_ignore_ascii_case("REM")
        && tail.get(3).is_none_or(|fourth| {
            is_cmd_delimiter(fourth.ch) || matches!(fourth.ch, '/' | '.' | CR_CHAR | LF_CHAR)
        })
}

/// Checks whether `chars[idx..end]` starts with ASCII keyword `kw` followed by a valid delimiter or `(`/ `/`.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `idx` - Starting index.
/// * `end` - Exclusive upper bound.
/// * `kw` - Uppercase ASCII keyword (`"IF"`, `"FOR"`, `"ELSE"`, `"IN"`, `"DO"`, `"NOT"`).
///
/// # Returns
/// `true` if `kw` matches at `idx`.
#[must_use]
pub fn is_keyword_at(chars: &[SpannedChar], idx: usize, end: usize, kw: &str) -> bool {
    let kw_end = idx.saturating_add(kw.len());
    if kw_end > end {
        return false;
    }
    let slice = chars.get(idx..kw_end).unwrap_or(&[]);
    let matches_kw = slice
        .iter()
        .zip(kw.chars())
        .all(|(sc, kc)| sc.raw_char().is_some_and(|c| c.eq_ignore_ascii_case(&kc)));
    if !matches_kw {
        return false;
    }
    if kw_end == end {
        return true;
    }
    chars.get(kw_end).is_some_and(|next| {
        is_caret_line_continuation_at(chars, kw_end).is_some()
            || is_cmd_delimiter(next.ch)
            || matches!(next.ch, '/' | '(' | CR_CHAR | LF_CHAR)
    })
}

/// Advances past a physical `^CRLF` / `^LF` / `^CR` line continuation at `idx`, skipping the
/// first character on the continued line **only** when `quote` is [`QuoteMode::Unquoted`] and
/// that character is not itself a line break (preserving closing `"` inside quotes and empty
/// continued lines!).
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `idx` - Candidate `^` index.
/// * `quote` - Active [`QuoteMode`] at `idx`.
///
/// # Returns
/// `Some(next_idx)` if `chars[idx]` begins a caret line continuation, else `None`.
#[must_use]
fn advance_past_caret_continuation(
    chars: &[SpannedChar],
    idx: usize,
    quote: QuoteMode,
) -> Option<usize> {
    let cont_end = is_caret_line_continuation_at(chars, idx)?;
    let skip_escaped_char = quote == QuoteMode::Unquoted
        && chars
            .get(cont_end)
            .is_some_and(|c| c.ch != CR_CHAR && c.ch != LF_CHAR);
    Some(if skip_escaped_char {
        cont_end.saturating_add(1)
    } else {
        cont_end
    })
}

/// Checks whether `words` (uppercase tokens on the current command segment) represents a
/// complete `IF` header immediately preceding its `then` command (`IF [/I] [NOT] <cond>`).
///
/// # Arguments
/// * `words` - Uppercase whitespace-delimited tokens preceding candidate `ECHO(`.
///
/// # Returns
/// `true` if `words` forms a complete `IF` condition header.
#[must_use]
fn is_complete_if_header_words(words: &[String]) -> bool {
    if words.first().map(String::as_str) != Some("IF") {
        return false;
    }
    let mut idx = 1usize;
    if words.get(idx).map(String::as_str) == Some("/I") {
        idx = idx.saturating_add(1);
    }
    if words.get(idx).map(String::as_str) == Some("NOT") {
        idx = idx.saturating_add(1);
    }
    let rem = words.get(idx..).unwrap_or(&[]);
    match rem {
        [kw, _]
            if matches!(
                kw.as_str(),
                "EXIST" | "DEFINED" | "ERRORLEVEL" | "CMDEXTVERSION"
            ) =>
        {
            true
        }
        [fused] => fused.contains("==") && !fused.starts_with("==") && !fused.ends_with("=="),
        [left, right] => {
            (left.ends_with("==") && left.len() > 2) || (right.starts_with("==") && right.len() > 2)
        }
        [_, op, _] => matches!(
            op.as_str(),
            "==" | "EQU" | "NEQ" | "LSS" | "LEQ" | "GTR" | "GEQ"
        ),
        _ => false,
    }
}

/// Checks whether the token sequence `words` on the current command segment places the next word
/// in **command position** (start of segment, after `DO`, `ELSE`, `CALL`, or a complete `IF` condition).
///
/// # Arguments
/// * `words` - Uppercase tokens accumulated since the start of the active command segment.
///
/// # Returns
/// `true` if the next token is in command position.
#[must_use]
fn is_command_position_after_words(words: &[String]) -> bool {
    words.is_empty()
        || matches!(words.last().map(String::as_str), Some("DO" | "ELSE"))
        || (words.len() == 1 && words.first().map(String::as_str) == Some("CALL"))
        || is_complete_if_header_words(words)
}

/// Checks whether an unquoted `'('` at `paren_idx` is the immediate `ECHO(` delimiter rather than
/// a `( ... )` compound block opener!
///
/// Verifies both that the 4 characters preceding `'('` spell `ECHO` after a token boundary AND
/// that `ECHO` itself sits in **command position** (start of line/block, or after `&`, `&&`, `||`,
/// `|`, `DO`, `ELSE`, `CALL`, `@`, or an `IF` condition), never misclassifying an ordinary argument
/// word such as `(myprog arg1 echo(arg2)`!
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `paren_idx` - Index of `'('` in `chars`.
///
/// # Returns
/// `true` if `chars[paren_idx]` is the `(` delimiter of `ECHO(`.
#[must_use]
pub fn is_echo_open_paren_at(chars: &[SpannedChar], paren_idx: usize) -> bool {
    if paren_idx < 4 {
        return false;
    }
    let echo_start = paren_idx.saturating_sub(4);
    let prev4: String = chars
        .get(echo_start..paren_idx)
        .unwrap_or(&[])
        .iter()
        .map(|c| c.ch)
        .collect();
    if !prev4.eq_ignore_ascii_case("ECHO") {
        return false;
    }
    if echo_start > 0
        && !chars.get(echo_start.saturating_sub(1)).is_some_and(|p| {
            is_cmd_delimiter(p.ch)
                || matches!(p.ch, '@' | '&' | '|' | '(' | CR_CHAR | LF_CHAR)
                || matches!(p.origin, ExpansionOrigin::CaretContinuation { .. })
        })
    {
        return false;
    }
    let words = collect_segment_words_before(chars, echo_start);
    is_command_position_after_words(&words)
}

/// Scans `chars[0..limit]` to collect uppercase tokens in the active command segment preceding `limit`.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `limit` - Exclusive end index (start of candidate `ECHO(`).
///
/// # Returns
/// Uppercase tokens accumulated since the start of the active command segment.
#[must_use]
fn collect_segment_words_before(chars: &[SpannedChar], limit: usize) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut cur_word = String::new();
    let mut quote = QuoteMode::Unquoted;
    let mut i = 0usize;
    while let Some(sc) = chars.get(i).filter(|_| i < limit) {
        if let Some(cont_end) = is_caret_line_continuation_at(chars, i) {
            if quote == QuoteMode::Unquoted
                && let Some(escaped) = chars
                    .get(cont_end)
                    .filter(|c| c.ch != CR_CHAR && c.ch != LF_CHAR && cont_end < limit)
            {
                cur_word.push(escaped.ch.to_ascii_uppercase());
                i = cont_end.saturating_add(1);
                continue;
            }
            i = cont_end;
            continue;
        }
        if sc.ch == CR_CHAR || sc.ch == LF_CHAR {
            cur_word.clear();
            words.clear();
            quote = QuoteMode::Unquoted;
            i = i.saturating_add(1);
            continue;
        }
        if sc.is_raw('"') {
            quote = quote.toggle();
            cur_word.push('"');
            i = i.saturating_add(1);
            continue;
        }
        if quote == QuoteMode::Unquoted {
            if sc.is_raw('^') {
                let esc_ch = chars.get(i.saturating_add(1)).map_or(' ', |c| c.ch);
                cur_word.push(esc_ch.to_ascii_uppercase());
                i = i.saturating_add(2);
                continue;
            }
            let is_redir_dup = i > 0
                && chars
                    .get(i.saturating_sub(1))
                    .is_some_and(|prev| prev.is_raw('>') || prev.is_raw('<'));
            if (sc.is_raw('&') && !is_redir_dup) || sc.is_raw('|') {
                cur_word.clear();
                words.clear();
                i = i.saturating_add(1);
                continue;
            }
            if sc.is_raw('(') {
                if cur_word == "ECHO" && is_command_position_after_words(&words) {
                    cur_word.push('(');
                } else {
                    cur_word.clear();
                    words.clear();
                }
                i = i.saturating_add(1);
                continue;
            }
            if matches!(sc.ch, ' ' | TAB_CHAR | ',' | ';' | '\u{00A0}') {
                if !cur_word.is_empty() {
                    words.push(core::mem::take(&mut cur_word));
                }
                i = i.saturating_add(1);
                continue;
            }
            if sc.ch == '@' && cur_word.is_empty() {
                i = i.saturating_add(1);
                continue;
            }
        }
        cur_word.push(sc.ch.to_ascii_uppercase());
        i = i.saturating_add(1);
    }
    if !cur_word.is_empty() {
        words.push(cur_word);
    }
    words
}

/// Advances `i` to the end of a `:label`, `::`, or `REM` physical line (respecting `^` continuations).
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `start` - Current cursor inside the comment/label line.
/// * `end` - Exclusive slice bound.
///
/// # Returns
/// Index of the terminating `CR`/`LF` or `end`.
#[must_use]
pub fn skip_comment_line_in_slice(chars: &[SpannedChar], start: usize, end: usize) -> usize {
    let mut i = start;
    while i < end {
        if let Some(cont_end) = is_caret_line_continuation_at(chars, i) {
            i = cont_end.min(end);
            continue;
        }
        if chars
            .get(i)
            .is_none_or(|c| c.ch == CR_CHAR || c.ch == LF_CHAR)
        {
            break;
        }
        i = i.saturating_add(1);
    }
    i
}

/// Computes net parenthesis depth (`(` minus `)`) across `chars`, respecting caret continuations,
/// double quotes, `:labels`, `::` comments, line-leading or inline `REM` comments, and `ECHO(`.
///
/// # Arguments
/// * `chars` - Spanned character slice to scan.
/// * `chars` may span multiple physical lines.
///
/// # Returns
/// Net unclosed parenthesis depth (`> 0` when compound blocks remain open).
#[must_use]
pub fn compute_lossless_paren_balance(chars: &[SpannedChar]) -> i32 {
    let mut depth: i32 = 0;
    let mut i = 0usize;
    let mut at_line_start = true;
    let mut at_cmd_start = true;
    let mut quote = QuoteMode::Unquoted;
    while let Some(sc) = chars.get(i) {
        if let Some(next_i) = advance_past_caret_continuation(chars, i, quote) {
            if quote == QuoteMode::Unquoted
                && next_i > is_caret_line_continuation_at(chars, i).unwrap_or(i)
            {
                at_line_start = false;
                at_cmd_start = false;
            }
            i = next_i;
            continue;
        }
        if sc.ch == CR_CHAR || sc.ch == LF_CHAR {
            at_line_start = true;
            at_cmd_start = true;
            quote = QuoteMode::Unquoted;
            i = i.saturating_add(1);
            continue;
        }
        if matches!(quote, QuoteMode::Unquoted) && (at_line_start || at_cmd_start) {
            if is_cmd_delimiter(sc.ch) || sc.ch == '@' {
                i = i.saturating_add(1);
                continue;
            }
            let was_line_start = at_line_start;
            at_line_start = false;
            if (was_line_start && sc.is_raw(':')) || is_rem_keyword_at(chars, i) {
                i = skip_comment_line_in_slice(chars, i, chars.len());
                continue;
            }
        }
        if sc.is_raw('"') {
            quote = quote.toggle();
            at_cmd_start = false;
            i = i.saturating_add(1);
            continue;
        }
        if matches!(quote, QuoteMode::Unquoted) {
            if sc.is_raw('^') {
                at_cmd_start = false;
                i = i.saturating_add(2);
                continue;
            }
            let is_redir_dup = i > 0
                && chars
                    .get(i.saturating_sub(1))
                    .is_some_and(|prev| prev.is_raw('>') || prev.is_raw('<'));
            if (sc.is_raw('&') && !is_redir_dup) || sc.is_raw('|') {
                at_cmd_start = true;
                i = i.saturating_add(1);
                continue;
            }
            if sc.is_raw('(') && !is_echo_open_paren_at(chars, i) {
                depth = depth.saturating_add(1);
                at_cmd_start = true;
                i = i.saturating_add(1);
                continue;
            } else if sc.is_raw(')') {
                depth = depth.saturating_sub(1);
            }
            at_cmd_start = false;
        }
        i = i.saturating_add(1);
    }
    depth
}

/// Finds the matching closing `)` in `chars[open_idx..end]` for a `(` at `open_idx`,
/// honoring quotes, caret escapes, `:labels`, line/inline `REM` comments, and `ECHO(`.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `open_idx` - Index of the opening `(`.
/// * `end` - Exclusive upper bound.
///
/// # Returns
/// `Some(close_idx)` if balanced, or `None` if unclosed.
#[must_use]
pub fn find_matching_close_paren_in_slice(
    chars: &[SpannedChar],
    open_idx: usize,
    end: usize,
) -> Option<usize> {
    let bounded = chars.get(..end).unwrap_or(chars);
    let mut depth: i32 = 0;
    let mut quote = QuoteMode::Unquoted;
    let mut at_line_start = false;
    let mut at_cmd_start = false;
    let mut i = open_idx;
    while let Some(sc) = bounded.get(i) {
        if let Some(next_i) = advance_past_caret_continuation(bounded, i, quote) {
            if next_i > is_caret_line_continuation_at(bounded, i).unwrap_or(i) {
                at_line_start = false;
                at_cmd_start = false;
            }
            i = next_i;
            continue;
        }
        if sc.ch == CR_CHAR || sc.ch == LF_CHAR {
            quote = QuoteMode::Unquoted;
            at_line_start = true;
            at_cmd_start = true;
            i = i.saturating_add(1);
            continue;
        }
        if matches!(quote, QuoteMode::Unquoted) && (at_line_start || at_cmd_start) {
            if is_cmd_delimiter(sc.ch) || sc.ch == '@' {
                i = i.saturating_add(1);
                continue;
            }
            let was_line_start = at_line_start;
            at_line_start = false;
            if (was_line_start && sc.is_raw(':')) || is_rem_keyword_at(bounded, i) {
                i = skip_comment_line_in_slice(bounded, i, bounded.len());
                continue;
            }
        }
        if sc.is_raw('"') {
            quote = quote.toggle();
            at_cmd_start = false;
            i = i.saturating_add(1);
            continue;
        }
        if matches!(quote, QuoteMode::Unquoted) {
            if sc.is_raw('^') {
                at_cmd_start = false;
                i = i.saturating_add(2);
                continue;
            }
            let is_redir_dup = i > open_idx
                && bounded
                    .get(i.saturating_sub(1))
                    .is_some_and(|prev| prev.is_raw('>') || prev.is_raw('<'));
            if (sc.is_raw('&') && !is_redir_dup) || sc.is_raw('|') {
                at_cmd_start = true;
                i = i.saturating_add(1);
                continue;
            }
            if sc.is_raw('(') && (i == open_idx || !is_echo_open_paren_at(bounded, i)) {
                depth = depth.saturating_add(1);
                at_cmd_start = true;
                i = i.saturating_add(1);
                continue;
            } else if sc.is_raw(')') {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i);
                }
            }
            at_cmd_start = false;
        }
        i = i.saturating_add(1);
    }
    None
}

/// Scans the next top-level line boundary inside a `( ... )` compound block body `chars[start..end]`.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `start` - Start of the interior statement.
/// * `end` - End of the compound block body (index of closing `)`).
///
/// # Returns
/// `(stmt_end, optional_newline_span_indices)` where `optional_newline_span_indices` is `Some((nl_start, nl_end))`.
#[must_use]
pub fn scan_next_block_line_boundary(
    chars: &[SpannedChar],
    start: usize,
    end: usize,
) -> (usize, Option<(usize, usize)>) {
    let bounded = chars.get(..end).unwrap_or(chars);
    let mut depth: i32 = 0;
    let mut quote = QuoteMode::Unquoted;
    let mut i = start;
    let mut first_non_ws = true;
    let mut at_cmd_start = true;
    while let Some(sc) = bounded.get(i) {
        if let Some(next_i) = advance_past_caret_continuation(bounded, i, quote) {
            if next_i > is_caret_line_continuation_at(bounded, i).unwrap_or(i) {
                first_non_ws = false;
                at_cmd_start = false;
            }
            i = next_i;
            continue;
        }
        if matches!(quote, QuoteMode::Unquoted) && depth <= 0 && (first_non_ws || at_cmd_start) {
            if is_cmd_delimiter(sc.ch) || sc.ch == '@' {
                i = i.saturating_add(1);
                continue;
            }
            let was_first = first_non_ws;
            first_non_ws = false;
            if (was_first && sc.is_raw(':')) || is_rem_keyword_at(bounded, i) {
                i = skip_comment_line_in_slice(bounded, i, bounded.len());
                if let Some(nl_sc) = bounded.get(i) {
                    let nl_end = if nl_sc.ch == CR_CHAR
                        && bounded
                            .get(i.saturating_add(1))
                            .is_some_and(|n| n.ch == LF_CHAR)
                    {
                        i.saturating_add(2)
                    } else {
                        i.saturating_add(1)
                    };
                    return (i, Some((i, nl_end)));
                }
                return (bounded.len(), None);
            }
        }
        if (sc.ch == CR_CHAR || sc.ch == LF_CHAR) && depth <= 0 {
            let nl_end = if sc.ch == CR_CHAR
                && bounded
                    .get(i.saturating_add(1))
                    .is_some_and(|n| n.ch == LF_CHAR)
            {
                i.saturating_add(2)
            } else {
                i.saturating_add(1)
            };
            return (i, Some((i, nl_end)));
        }
        if sc.ch == CR_CHAR || sc.ch == LF_CHAR {
            quote = QuoteMode::Unquoted;
            at_cmd_start = true;
        } else if sc.is_raw('"') {
            quote = quote.toggle();
            at_cmd_start = false;
        } else if matches!(quote, QuoteMode::Unquoted) {
            if sc.is_raw('^') {
                at_cmd_start = false;
                i = i.saturating_add(2);
                continue;
            }
            let is_redir_dup = i > start
                && bounded
                    .get(i.saturating_sub(1))
                    .is_some_and(|prev| prev.is_raw('>') || prev.is_raw('<'));
            if (sc.is_raw('&') && !is_redir_dup) || sc.is_raw('|') {
                at_cmd_start = true;
                i = i.saturating_add(1);
                continue;
            }
            if sc.is_raw('(') && !is_echo_open_paren_at(bounded, i) {
                depth = depth.saturating_add(1);
                at_cmd_start = true;
                i = i.saturating_add(1);
                continue;
            } else if sc.is_raw(')') {
                depth = depth.saturating_sub(1);
            }
            at_cmd_start = false;
        }
        i = i.saturating_add(1);
    }
    (bounded.len(), None)
}

/// Collects all top-level binary command operators (`&`, `&&`, `||`, `|`) in `chars[start..end]`
/// in a **single linear `O(N)` pass**.
///
/// Honors quotes, `^` escapes, `( ... )` blocks, `ECHO(`, redirection `>&` / `<&` handle duplications,
/// and stops scanning when a greedy statement keyword (`IF`, `FOR`, `REM`) starts a command segment.
/// Note that `SET /A` is intentionally **NOT** treated as greedy over unquoted `&` or `|`, matching
/// authentic `cmd.exe` operator-precedence rules!
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `start` - Start index.
/// * `end` - Exclusive end index.
///
/// # Returns
/// Ordered list of [`TopLevelBinOp`]s within `chars[start..end]`.
#[must_use]
pub fn scan_top_level_binary_ops(
    chars: &[SpannedChar],
    start: usize,
    end: usize,
) -> Vec<TopLevelBinOp> {
    let bounded = chars.get(..end).unwrap_or(chars);
    let mut ops = Vec::new();
    let mut depth: i32 = 0;
    let mut quote = QuoteMode::Unquoted;
    let mut at_cmd_start = true;
    let mut i = start;

    while let Some(sc) = bounded.get(i) {
        if let Some(next_i) = advance_past_caret_continuation(bounded, i, quote) {
            if next_i > is_caret_line_continuation_at(bounded, i).unwrap_or(i) {
                at_cmd_start = false;
            }
            i = next_i;
            continue;
        }
        if sc.ch == CR_CHAR || sc.ch == LF_CHAR {
            quote = QuoteMode::Unquoted;
            i = i.saturating_add(1);
            continue;
        }
        if sc.is_raw('"') {
            quote = quote.toggle();
            at_cmd_start = false;
            i = i.saturating_add(1);
            continue;
        }
        if matches!(quote, QuoteMode::Unquoted) {
            if sc.is_raw('^') {
                at_cmd_start = false;
                i = i.saturating_add(2);
                continue;
            }
            if sc.is_raw('(') && !is_echo_open_paren_at(bounded, i) {
                depth = depth.saturating_add(1);
                at_cmd_start = false;
                i = i.saturating_add(1);
                continue;
            }
            if sc.is_raw(')') {
                depth = depth.saturating_sub(1);
                at_cmd_start = false;
                i = i.saturating_add(1);
                continue;
            }
            if depth == 0 {
                if at_cmd_start {
                    if is_cmd_delimiter(sc.ch) || sc.ch == '@' {
                        i = i.saturating_add(1);
                        continue;
                    }
                    if is_keyword_at(bounded, i, bounded.len(), "IF")
                        || is_keyword_at(bounded, i, bounded.len(), "FOR")
                        || is_rem_keyword_at(bounded, i)
                    {
                        break;
                    }
                    at_cmd_start = false;
                }

                if let Some(bin_op) = match_top_level_bin_op_at(bounded, start, i, bounded.len()) {
                    ops.push(bin_op);
                    at_cmd_start = true;
                    i = bin_op.op_end;
                    continue;
                }
            }
        }
        i = i.saturating_add(1);
    }
    ops
}

/// Attempts to match an unescaped top-level binary command operator (`&`, `&&`, `|`, `||`) at `idx`,
/// ignoring `>&` and `<&` handle-duplication operators.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `start` - Segment start index.
/// * `idx` - Candidate operator index.
/// * `end` - Exclusive upper bound.
///
/// # Returns
/// `Some(TopLevelBinOp)` if a binary command operator starts at `idx`, else `None`.
#[must_use]
fn match_top_level_bin_op_at(
    chars: &[SpannedChar],
    start: usize,
    idx: usize,
    end: usize,
) -> Option<TopLevelBinOp> {
    let cur_sc = chars.get(idx)?;
    let is_redir_dup = idx > start
        && chars
            .get(idx.saturating_sub(1))
            .is_some_and(|prev| prev.is_raw('>') || prev.is_raw('<'));
    if cur_sc.is_raw('&') && !is_redir_dup {
        let is_double = chars
            .get(idx.saturating_add(1))
            .filter(|_| idx.saturating_add(1) < end)
            .is_some_and(|next| next.is_raw('&'));
        let (kind, width) = if is_double {
            (BinOpKind::And, 2)
        } else {
            (BinOpKind::Seq, 1)
        };
        return Some(TopLevelBinOp {
            kind,
            op_start: idx,
            op_end: idx.saturating_add(width),
        });
    }
    if cur_sc.is_raw('|') {
        let is_double = chars
            .get(idx.saturating_add(1))
            .filter(|_| idx.saturating_add(1) < end)
            .is_some_and(|next| next.is_raw('|'));
        let (kind, width) = if is_double {
            (BinOpKind::Or, 2)
        } else {
            (BinOpKind::Pipe, 1)
        };
        return Some(TopLevelBinOp {
            kind,
            op_start: idx,
            op_end: idx.saturating_add(width),
        });
    }
    None
}

/// Reads the next lossless [`StatementUnit`] from `raw_text` using [`BatchFrameReader`].
///
/// Joins physical lines continued with `^` and balances multi-line `( ... )` blocks while
/// preserving every physical byte in `chars` for 100% lossless CST round-tripping.
///
/// # Arguments
/// * `reader` - Mutable [`BatchFrameReader`] positioned at the start of the statement.
/// * `raw_text` - Full decoded script string.
///
/// # Returns
/// Next [`StatementUnit`] (advancing `reader.cursor` past the statement and its trailing newline).
pub fn read_next_statement_unit(reader: &mut BatchFrameReader, raw_text: &str) -> StatementUnit {
    let source_id = reader.source_id;
    let start_offset = reader.cursor;
    let mut chars: Vec<SpannedChar> = Vec::new();
    let trailing_newline: Option<CstToken>;
    let mut pending_caret_escape = false;
    let mut quote_mode = QuoteMode::Unquoted;

    loop {
        let Some((line_start, line_slice, nl_span_opt)) = reader.read_physical_line(raw_text)
        else {
            trailing_newline = None;
            break;
        };
        let cursor_after_line = reader.cursor.0;
        let nl_tok_opt = nl_span_opt.map(|sp| {
            let nl_str = raw_text.get(sp.start.0..sp.end.0).unwrap_or("");
            CstToken::new(SyntaxKind::Newline, nl_str.to_owned(), sp)
        });

        let trailing_carets = line_slice.chars().rev().take_while(|&c| c == '^').count();
        let line_continues = nl_tok_opt.is_some() && !trailing_carets.is_multiple_of(2);
        let mut next_unescaped_by_inline_caret = false;

        for (char_pos, (rel_idx, ch)) in line_slice.char_indices().enumerate() {
            let c_start = ByteOffset(line_start.0.saturating_add(rel_idx));
            let c_end = c_start.saturating_add(ch.len_utf8());
            let mut sc = SpannedChar::literal(ch, Span::new(source_id, c_start, c_end));
            if char_pos == 0 && pending_caret_escape {
                pending_caret_escape = false;
                if quote_mode == QuoteMode::InQuotes {
                    if ch == '"' {
                        quote_mode = QuoteMode::Unquoted;
                    }
                } else {
                    sc.escaped_by_caret = true;
                }
            } else if next_unescaped_by_inline_caret {
                next_unescaped_by_inline_caret = false;
                sc.escaped_by_caret = true;
            } else if ch == '"' {
                quote_mode = quote_mode.toggle();
            } else if quote_mode == QuoteMode::Unquoted
                && ch == '^'
                && !(line_continues && rel_idx.saturating_add(1) == line_slice.len())
            {
                next_unescaped_by_inline_caret = true;
            }
            chars.push(sc);
        }
        pending_caret_escape = false;

        let Some(nl_tok) = nl_tok_opt else {
            trailing_newline = None;
            break;
        };

        if line_continues {
            let caret_span = chars.last().map_or(nl_tok.span, |c| c.span);
            let mut nl_byte_off = nl_tok.span.start;
            for nl_ch in nl_tok.text.chars() {
                let nl_end = nl_byte_off.saturating_add(nl_ch.len_utf8());
                chars.push(SpannedChar {
                    ch: nl_ch,
                    span: Span::new(source_id, nl_byte_off, nl_end),
                    escaped_by_caret: true,
                    origin: ExpansionOrigin::CaretContinuation {
                        caret_span,
                        newline_span: nl_tok.span,
                    },
                });
                nl_byte_off = nl_end;
            }
            pending_caret_escape = true;
            continue;
        }

        quote_mode = QuoteMode::Unquoted;

        if compute_lossless_paren_balance(&chars) > 0
            && !is_unclosed_for_set_without_closing_paren(
                &chars,
                raw_text.get(cursor_after_line..).unwrap_or(""),
            )
            && cursor_after_line < raw_text.len()
        {
            let mut nl_byte_off = nl_tok.span.start;
            for nl_ch in nl_tok.text.chars() {
                let nl_end = nl_byte_off.saturating_add(nl_ch.len_utf8());
                chars.push(SpannedChar::literal(
                    nl_ch,
                    Span::new(source_id, nl_byte_off, nl_end),
                ));
                nl_byte_off = nl_end;
            }
            continue;
        }

        trailing_newline = Some(nl_tok);
        break;
    }

    StatementUnit {
        start_offset,
        next_byte_offset: reader.cursor,
        chars,
        trailing_newline,
    }
}

/// Checks if `chars` starts with a `FOR` header whose `IN (` set is unclosed on the current line
/// and `remaining_text` does not contain `)` on the next physical line.
///
/// # Arguments
/// * `chars` - Accumulated statement characters.
/// * `remaining_text` - Unread script tail.
///
/// # Returns
/// `true` if `FOR (...)` should terminate at EOL for recovery.
#[must_use]
fn is_unclosed_for_set_without_closing_paren(chars: &[SpannedChar], remaining_text: &str) -> bool {
    let cur = chars
        .iter()
        .take_while(|sc| matches!(sc.ch, ' ' | TAB_CHAR | '@'))
        .count();
    if !is_keyword_at(chars, cur, chars.len(), "FOR") {
        return false;
    }
    let next_line = remaining_text.lines().next().unwrap_or("");
    !next_line.contains(')')
}

/// Empty sub-word part callback for lightweight runtime tokenization.
///
/// # Arguments
/// * `_source_id` - Unused [`SourceId`].
/// * `_slice` - Unused character slice.
///
/// # Returns
/// Always returns an empty `Vec`.
const fn no_word_parts(_source_id: SourceId, _slice: &[SpannedChar]) -> Vec<WordPart> {
    Vec::new()
}

/// Tokenizes command arguments from `chars` in lightweight runtime mode (zero [`WordPart`] allocations).
///
/// # Arguments
/// * `chars` - Argument tail [`SpannedChar`] slice.
///
/// # Returns
/// Vector of [`SpannedWord`] arguments with empty `parts`.
#[must_use]
pub fn tokenize_command_arguments(chars: &[SpannedChar]) -> Vec<SpannedWord> {
    tokenize_command_arguments_dyn(chars, WordPartsMode::Lightweight, &mut no_word_parts)
}

/// Tokenizes command arguments from `chars` with configurable [`WordPartsMode`].
///
/// # Arguments
/// * `chars` - Argument tail [`SpannedChar`] slice.
/// * `mode` - [`WordPartsMode`] controlling sub-word [`WordPart`] allocation.
/// * `parts_fn` - Callback invoked when `mode == WordPartsMode::PopulateSubwordParts`.
///
/// # Returns
/// Vector of [`SpannedWord`] arguments.
pub fn tokenize_command_arguments_with_mode(
    chars: &[SpannedChar],
    mode: WordPartsMode,
    mut parts_fn: impl FnMut(SourceId, &[SpannedChar]) -> Vec<WordPart>,
) -> Vec<SpannedWord> {
    tokenize_command_arguments_dyn(chars, mode, &mut parts_fn)
}

/// Non-generic core implementation of [`tokenize_command_arguments_with_mode`].
///
/// # Arguments
/// * `chars` - Argument tail [`SpannedChar`] slice.
/// * `mode` - [`WordPartsMode`] controlling sub-word [`WordPart`] allocation.
/// * `parts_fn` - Dynamic callback invoked when `mode == WordPartsMode::PopulateSubwordParts`.
///
/// # Returns
/// Vector of [`SpannedWord`] arguments.
fn tokenize_command_arguments_dyn(
    chars: &[SpannedChar],
    mode: WordPartsMode,
    parts_fn: &mut dyn FnMut(SourceId, &[SpannedChar]) -> Vec<WordPart>,
) -> Vec<SpannedWord> {
    let mut args = Vec::new();
    let mut cursor = skip_arg_delimiters(chars, 0);
    while let Some((word, next_pos)) = lex_single_arg_word(chars, cursor, mode, parts_fn) {
        args.push(word);
        cursor = skip_arg_delimiters(chars, next_pos);
    }
    args
}

/// Skips unescaped standard `cmd.exe` argument delimiters starting at `idx`.
///
/// # Arguments
/// * `chars` - Input [`SpannedChar`] slice.
/// * `idx` - Starting cursor.
///
/// # Returns
/// First non-delimiter index (or `chars.len()`).
#[must_use]
fn skip_arg_delimiters(chars: &[SpannedChar], mut idx: usize) -> usize {
    while let Some(sc) = chars.get(idx) {
        if sc.raw_char().is_some_and(is_cmd_delimiter) {
            idx = idx.saturating_add(1);
        } else {
            break;
        }
    }
    idx
}

/// Lexes a single argument word starting at `start_idx`, honoring quotes and unquoted `^` escapes.
///
/// # Arguments
/// * `chars` - Input [`SpannedChar`] slice.
/// * `start_idx` - Starting index.
/// * `mode` - [`WordPartsMode`] (`Lightweight` vs `PopulateSubwordParts`).
/// * `parts_fn` - Sub-word parts builder when `PopulateSubwordParts` is active.
///
/// # Returns
/// `Some((SpannedWord, next_index))` if a word exists at `start_idx`, else `None`.
fn lex_single_arg_word(
    chars: &[SpannedChar],
    start_idx: usize,
    mode: WordPartsMode,
    parts_fn: &mut dyn FnMut(SourceId, &[SpannedChar]) -> Vec<WordPart>,
) -> Option<(SpannedWord, usize)> {
    let first = chars.get(start_idx)?;
    let mut text = String::new();
    let mut quote = QuoteMode::Unquoted;
    let mut quoted = false;
    let mut has_unescaped_special = false;
    let mut last_span = first.span;
    let mut i = start_idx;

    while let Some(sc) = chars.get(i) {
        if matches!(quote, QuoteMode::Unquoted) {
            if sc.is_raw('^') {
                has_unescaped_special = true;
                if let Some(next_sc) = chars.get(i.saturating_add(1)) {
                    text.push(next_sc.ch);
                    last_span = next_sc.span;
                    i = i.saturating_add(2);
                    continue;
                }
                i = i.saturating_add(1);
                continue;
            }
            if sc.is_raw('"') {
                quote = QuoteMode::InQuotes;
                quoted = true;
                text.push('"');
                last_span = sc.span;
                i = i.saturating_add(1);
                continue;
            }
            if sc.raw_char().is_some_and(is_cmd_delimiter) {
                break;
            }
        } else if sc.is_raw('"') {
            quote = QuoteMode::Unquoted;
            text.push('"');
            last_span = sc.span;
            i = i.saturating_add(1);
            continue;
        }

        text.push(sc.ch);
        last_span = sc.span;
        i = i.saturating_add(1);
    }

    let word_span = first.span.merge(last_span);
    let parts = match mode {
        WordPartsMode::Lightweight => Vec::new(),
        WordPartsMode::PopulateSubwordParts => {
            parts_fn(word_span.source_id, chars.get(start_idx..i).unwrap_or(&[]))
        }
    };
    Some((
        SpannedWord::with_parts(
            text,
            word_span,
            if quoted {
                QuoteMode::InQuotes
            } else {
                QuoteMode::Unquoted
            },
            if has_unescaped_special {
                crate::parser::ast::SpecialCharPresence::HasUnescapedSpecial
            } else {
                crate::parser::ast::SpecialCharPresence::Plain
            },
            parts,
        ),
        i,
    ))
}

#[cfg(test)]
/// Unit tests for the unified lexer and operator-precedence scanner.
mod tests {
    use super::*;
    use crate::parser::lower::parse_single_word_parts;
    use crate::reader::char_map::LogicalLineBuffer;
    use crate::types::CRLF;

    /// Exercises LF/CRLF caret continuations, broken carets, REM boundaries, statement splitting,
    /// paren balancing, and argument tokenization with and without sub-word parts.
    #[test]
    fn test_lexer_continuations_rem_paren_balance_and_arg_tokenizer() {
        let mut cont_rdr = BatchFrameReader::new(SourceId(0));
        let lf_src = format!("if^{LF_CHAR} 1==1 echo a");
        let lf_cont = read_next_statement_unit(&mut cont_rdr, &lf_src);
        assert_eq!(is_caret_line_continuation_at(&lf_cont.chars, 2), Some(4));
        assert!(is_keyword_at(&lf_cont.chars, 0, lf_cont.chars.len(), "if"));

        let broken_caret = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "echo ^ ");
        assert_eq!(is_broken_caret_at(&broken_caret.chars, 5), Some(7));
        let eof_caret = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "echo ^");
        assert_eq!(is_broken_caret_at(&eof_caret.chars, 5), None);

        let broken_lf = LogicalLineBuffer::from_str_at(
            SourceId(0),
            ByteOffset(0),
            &format!("echo ^ {LF_CHAR}"),
        );
        assert_eq!(is_broken_caret_at(&broken_lf.chars, 5), Some(7));
        let broken_cr = LogicalLineBuffer::from_str_at(
            SourceId(0),
            ByteOffset(0),
            &format!("echo ^ {CR_CHAR}"),
        );
        assert_eq!(is_broken_caret_at(&broken_cr.chars, 5), Some(7));
        let kw_slash = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "if/i");
        assert!(is_keyword_at(
            &kw_slash.chars,
            0,
            kw_slash.chars.len(),
            "if"
        ));
        let kw_miss = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "iff");
        assert!(!is_keyword_at(&kw_miss.chars, 0, kw_miss.chars.len(), "if"));
        assert_eq!(no_word_parts(SourceId(0), &[]).len(), 0);

        let cr_cmt = LogicalLineBuffer::from_str_at(
            SourceId(0),
            ByteOffset(0),
            &format!(":: c{CR_CHAR}echo a{CR_CHAR}"),
        );
        assert_eq!(
            scan_next_block_line_boundary(&cr_cmt.chars, 0, cr_cmt.chars.len()),
            (4, Some((4, 5)))
        );
        assert_eq!(
            scan_next_block_line_boundary(&cr_cmt.chars, 5, cr_cmt.chars.len()),
            (11, Some((11, 12)))
        );
        let eof_cmt = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), ":: eof");
        assert_eq!(
            scan_next_block_line_boundary(&eof_cmt.chars, 0, eof_cmt.chars.len()),
            (6, None)
        );

        for (txt, expected) in [
            ("rem/c", true),
            ("rem.", true),
            (&format!("rem{LF_CHAR}"), true),
            ("remword", false),
        ] {
            let b = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), txt);
            assert_eq!(is_rem_keyword_at(&b.chars, 0), expected, "input: {txt}");
        }
    }

    /// Verifies `read_next_statement_unit`, `find_matching_close_paren_in_slice`, and argument tokenization.
    #[test]
    fn test_statement_unit_reader_and_arg_tokenizer() {
        let mut cmt_rdr = BatchFrameReader::new(SourceId(0));
        let cmt_src = format!(":: cmt^{LF_CHAR}still{LF_CHAR}");
        let comment_cont = read_next_statement_unit(&mut cmt_rdr, &cmt_src);
        assert_eq!(
            skip_comment_line_in_slice(&comment_cont.chars, 0, comment_cont.chars.len()),
            13
        );

        let mut p_rdr = BatchFrameReader::new(SourceId(0));
        let p_src = format!("(echo a^{LF_CHAR}b)");
        let paren_cont = read_next_statement_unit(&mut p_rdr, &p_src);
        assert_eq!(
            find_matching_close_paren_in_slice(&paren_cont.chars, 0, paren_cont.chars.len()),
            Some(10)
        );
        let mut u_rdr = BatchFrameReader::new(SourceId(0));
        let u_src = format!("(echo a^{LF_CHAR}b");
        let unclosed = read_next_statement_unit(&mut u_rdr, &u_src);
        assert_eq!(
            scan_next_block_line_boundary(&unclosed.chars, 0, unclosed.chars.len()),
            (10, None)
        );
        assert_eq!(compute_lossless_paren_balance(&unclosed.chars), 1);

        let mut eof_nl_rdr = BatchFrameReader::new(SourceId(0));
        let eof_nl_src = format!("(echo eof{LF_CHAR}");
        let eof_nl_unit = read_next_statement_unit(&mut eof_nl_rdr, &eof_nl_src);
        assert!(eof_nl_unit.trailing_newline.is_some());

        let raw_no_nl = format!("{CRLF}@rem hdr{CRLF}(echo x{CRLF}echo y)");
        let mut rdr = BatchFrameReader::new(SourceId(0));
        let u1 = read_next_statement_unit(&mut rdr, &raw_no_nl);
        let u2 = read_next_statement_unit(&mut rdr, &raw_no_nl);
        let u3 = read_next_statement_unit(&mut rdr, &raw_no_nl);
        let u4 = read_next_statement_unit(&mut rdr, &raw_no_nl);
        assert!(u1.trailing_newline.is_some());
        assert!(u2.trailing_newline.is_some());
        assert!(u3.trailing_newline.is_none());
        assert_eq!(u4.chars.len(), 0);
        assert!(u4.trailing_newline.is_none());

        let mut eof_caret_rdr = BatchFrameReader::new(SourceId(0));
        assert_eq!(
            read_next_statement_unit(&mut eof_caret_rdr, "echo ^")
                .chars
                .len(),
            6
        );
        let mut eof_paren_rdr = BatchFrameReader::new(SourceId(0));
        assert_eq!(
            read_next_statement_unit(&mut eof_paren_rdr, "(echo x")
                .chars
                .len(),
            7
        );

        let arg_buf = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "  ^&lit \"q\" ^");
        let light = tokenize_command_arguments(&arg_buf.chars);
        assert_eq!(light.len(), 3);
        assert_eq!(light.first().map(|w| w.text.as_str()), Some("&lit"));
        let full = tokenize_command_arguments_with_mode(
            &arg_buf.chars,
            WordPartsMode::PopulateSubwordParts,
            parse_single_word_parts,
        );
        assert_eq!(full.len(), 3);
        assert!(!full.first().is_none_or(|w| w.parts.is_empty()));
    }

    /// Verifies [`BinOpKind`] binding powers, strings, and `scan_next_block_line_boundary` edges.
    #[test]
    fn test_bin_op_kind_and_block_comment_boundaries() {
        assert_eq!(BinOpKind::Seq.binding_power(), 1);
        assert_eq!(BinOpKind::And.binding_power(), 2);
        assert_eq!(BinOpKind::Or.binding_power(), 2);
        assert_eq!(BinOpKind::Pipe.binding_power(), 3);
        assert_eq!(BinOpKind::Seq.as_str(), "&");
        assert_eq!(BinOpKind::And.as_str(), "&&");
        assert_eq!(BinOpKind::Or.as_str(), "||");
        assert_eq!(BinOpKind::Pipe.as_str(), "|");

        let bounded_blk_cmt =
            LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "(:: cmt)");
        assert_eq!(
            scan_next_block_line_boundary(&bounded_blk_cmt.chars, 1, 7),
            (7, None)
        );
        let lf_blk_cmt = LogicalLineBuffer::from_str_at(
            SourceId(0),
            ByteOffset(0),
            &format!(":: c{LF_CHAR}echo a"),
        );
        assert_eq!(
            scan_next_block_line_boundary(&lf_blk_cmt.chars, 0, lf_blk_cmt.chars.len()),
            (4, Some((4, 5)))
        );

        // Command-position `ECHO(` vs argument-position `echo(` inside `( ... )` blocks
        for balanced_sample in [
            "(echo(hello)",
            "(call echo(hello)",
            "(^call echo(hello)",
            "(call ^ echo(hello))",
            "(call ^echo(hello))",
            "(if /i not exist foo echo(hello)",
            "(if a==b echo(hello)",
            "(if a== b echo(hello)",
            "(if a ==b echo(hello)",
            "(if a equ b echo(hello)",
            "(echo(first & @echo(second)",
            "(echo a 2>&1 | echo(piped)",
            "(myprog echo(inner_paren))",
            "(myprog arg echo(inner_paren))",
            "(myprog echo(a) echo(b))",
            "(user@host echo(inner_paren))",
            "(fooecho(inner_paren))",
            "(set x=echo(inner_paren))",
            "(if ==b echo(inner_paren))",
            "(if == rhs echo(inner_paren))",
            "(if a== echo(inner_paren))",
            "(if foo bar echo(inner_paren))",
            "(if a b c d echo(inner_paren))",
            "(if bogus echo(inner_paren))",
        ] {
            let bal_chars =
                LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), balanced_sample).chars;
            assert_eq!(
                compute_lossless_paren_balance(&bal_chars),
                0,
                "Expected balanced parens for: {balanced_sample}"
            );
            assert_eq!(
                find_matching_close_paren_in_slice(&bal_chars, 0, bal_chars.len()),
                Some(bal_chars.len().saturating_sub(1)),
                "Expected matching close paren at end for: {balanced_sample}"
            );
        }

        // Physical `^` line continuations via `read_next_statement_unit` (`ExpansionOrigin::CaretContinuation`)
        for phys_sample in [
            format!("({CRLF}  @echo hi 2>&1{CRLF}  call ^{CRLF}echo(cont{CRLF})"),
            format!("({CRLF}  ca^{CRLF}ll echo(cont2{CRLF})"),
            format!("({CRLF}  call ^{CRLF}{CRLF}echo(cont3{CRLF})"),
            format!("({LF_CHAR}  call ^{LF_CHAR}{LF_CHAR}echo(cont4{LF_CHAR})"),
            format!("({CRLF}  \"q^{CRLF}uote\" echo(arg){CRLF})"),
            format!("({CRLF}  \"q^{CRLF}\" echo(arg){CRLF})"),
        ] {
            let mut rdr = BatchFrameReader::new(SourceId(0));
            let unit = read_next_statement_unit(&mut rdr, &phys_sample);
            assert_eq!(compute_lossless_paren_balance(&unit.chars), 0);
            assert_eq!(
                find_matching_close_paren_in_slice(&unit.chars, 0, unit.chars.len()),
                Some(unit.chars.len().saturating_sub(1))
            );
            let (b_end, _) =
                scan_next_block_line_boundary(&unit.chars, 3, unit.chars.len().saturating_sub(1));
            assert!(b_end >= 3);
        }
        let blk_at = LogicalLineBuffer::from_str_at(
            SourceId(0),
            ByteOffset(0),
            &format!("({LF_CHAR} @echo x 2>&1{LF_CHAR})"),
        );
        assert_eq!(
            scan_next_block_line_boundary(&blk_at.chars, 2, blk_at.chars.len().saturating_sub(1)),
            (15, Some((15, 16)))
        );
    }
}
