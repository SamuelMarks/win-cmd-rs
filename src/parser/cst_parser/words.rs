//! `SimpleCommand`, `SET` assignment, redirection, word, and `%` / `!` / `^` sub-word CST rules.

use std::collections::BTreeSet;

use crate::error::{PegExpected, ProbableMisuseKind};
use crate::parser::cst::{CstElement, CstNode, CstToken, SyntaxKind};
use crate::parser::lexer::{is_broken_caret_at, is_caret_line_continuation_at, is_cmd_delimiter};
use crate::reader::char_map::SpannedChar;
use crate::span::{ByteOffset, Span};
use crate::types::{BS_CHAR, CR_CHAR, ForVarName, LF_CHAR, PercentArity, TAB_CHAR};

use super::{
    CstParserState, TriviaDelimiterMode, WordEqualsMode, WordParenScope, consume_horizontal_trivia,
    slice_to_token,
};

/// Parses a `SimpleCommand` CST node preserving interleaved `RedirectionNode`s, `EchoDelimiterToken`,
/// `SetAssignmentNode`, and `WordNode`s in exact source order.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `children` - Leading trivia and `@` tokens.
/// * `start` - Start index.
/// * `end` - Exclusive end index.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `SimpleCommand` or `ErrorNode` [`CstNode`].
pub(super) fn parse_simple_command_cst(
    input: &mut CstParserState<'_>,
    mut children: Vec<CstElement>,
    start: usize,
    end: usize,
    fallback_offset: ByteOffset,
) -> CstNode {
    let mut cur = start;
    let mut has_program_word = false;
    let mut has_error = false;
    let mut is_set_cmd = false;

    while cur < end {
        let delim_mode = if is_set_cmd {
            TriviaDelimiterMode::SpacesAndTabsOnly
        } else {
            TriviaDelimiterMode::IncludeCommandDelimiters
        };
        cur = consume_horizontal_trivia(input, cur, delim_mode, &mut children);
        if cur >= end {
            break;
        }
        if let Some((redir_el, next_cur)) = parse_redirection_node(input, cur, end) {
            if redir_el.kind() == SyntaxKind::ErrorNode {
                has_error = true;
            }
            children.push(redir_el);
            cur = next_cur;
            continue;
        }
        if !has_program_word {
            let (prog_el, echo_delim_opt, after_prog, prog_name_upper) =
                parse_program_head_cst(input, cur, end);
            has_program_word = true;
            is_set_cmd = prog_name_upper == "SET";
            children.push(prog_el);
            if let Some(delim_tok) = echo_delim_opt {
                children.push(CstElement::Token(delim_tok));
            }
            cur = after_prog;
            continue;
        }
        let eq_mode = if is_set_cmd {
            WordEqualsMode::KeepAllEquals
        } else {
            WordEqualsMode::SplitOnAnyEquals
        };
        if let Some((mut wn, next_cur)) =
            parse_word_node(input, cur, end, eq_mode, WordParenScope::Normal)
        {
            if is_set_cmd && wn.to_source_string().contains('=') {
                wn.kind = SyntaxKind::SetAssignmentNode;
            }
            children.push(CstElement::Node(wn));
            cur = next_cur;
        } else {
            children.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                cur,
                cur.saturating_add(1),
                SyntaxKind::Whitespace,
            )));
            cur = cur.saturating_add(1);
        }
    }

    if !has_program_word {
        let err_span = input.span_at(start, fallback_offset);
        input
            .farthest
            .record_failure(start, err_span, PegExpected::CommandName);
        input.record_syntax_error(
            err_span,
            "The syntax of the command is incorrect. Missing command name.".to_owned(),
            vec![PegExpected::CommandName],
            Some("Provide a command name alongside the I/O redirection.".to_owned()),
        );
        has_error = true;
    }

    let kind = if has_error {
        SyntaxKind::ErrorNode
    } else {
        SyntaxKind::SimpleCommand
    };
    CstNode::from_children(kind, input.source_id, fallback_offset, children)
}

/// Parses the program token at the start of a `SimpleCommand`, handling `ECHO` delimiters
/// (`ECHO.`, `ECHO(`, `ECHO:`, `ECHO/`, `ECHO `) and directory shortcuts (`CD..`, `CD/`, `MD/`).
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cur` - Program start index.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `(program_element, optional_echo_delimiter_token, next_cursor, uppercase_program_name)`.
fn parse_program_head_cst(
    input: &mut CstParserState<'_>,
    cur: usize,
    end: usize,
) -> (CstElement, Option<CstToken>, usize, String) {
    let fourth_end = cur.saturating_add(4);
    let prefix4: String = input
        .chars
        .get(cur..fourth_end.min(end))
        .unwrap_or(&[])
        .iter()
        .map(|c| c.ch)
        .collect();
    if prefix4.eq_ignore_ascii_case("ECHO") {
        let fifth_opt = input.chars.get(fourth_end).filter(|_| fourth_end < end);
        let is_delim = fifth_opt.is_some_and(|f| {
            matches!(
                f.ch,
                ' ' | TAB_CHAR
                    | '.'
                    | ':'
                    | '/'
                    | BS_CHAR
                    | '['
                    | ']'
                    | '+'
                    | '='
                    | '('
                    | ';'
                    | ','
            )
        });
        if fourth_end == end || is_delim {
            let tok = slice_to_token(
                input.source_id,
                input.chars,
                cur,
                fourth_end,
                SyntaxKind::LiteralToken,
            );
            let span = tok.span;
            let node = CstNode::new(SyntaxKind::WordNode, span, vec![CstElement::Token(tok)]);
            let delim_tok = fifth_opt
                .map(|f| CstToken::new(SyntaxKind::EchoDelimiterToken, f.ch.to_string(), f.span));
            let next_pos = fourth_end.saturating_add(usize::from(delim_tok.is_some()));
            return (
                CstElement::Node(node),
                delim_tok,
                next_pos,
                "ECHO".to_owned(),
            );
        }
    }

    if let Some(res) = try_parse_fused_builtin_head_cst(input, cur, end) {
        return res;
    }

    let fallback = (
        CstElement::Token(slice_to_token(
            input.source_id,
            input.chars,
            cur,
            end,
            SyntaxKind::LiteralToken,
        )),
        end,
    );
    let (we, nc) = parse_word_node(
        input,
        cur,
        end,
        WordEqualsMode::SplitOnAnyEquals,
        WordParenScope::Normal,
    )
    .map_or(fallback, |(wn, next_c)| (CstElement::Node(wn), next_c));
    let upper = we.to_source_string().to_ascii_uppercase();
    (we, None, nc, upper)
}

/// Attempts to split a punctuation-fused internal command head (`cd..`, `cd\`, `md/dir`, `dir/b`, `copy/y`).
///
/// # Arguments
/// * `input` - Active [`CstParserState`].
/// * `cur` - Start index of the candidate command.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `Some((prog_el, None, next_cur, upper_kw))` if matched, else `None`.
fn try_parse_fused_builtin_head_cst(
    input: &CstParserState<'_>,
    cur: usize,
    end: usize,
) -> Option<(CstElement, Option<CstToken>, usize, String)> {
    let dir_kw = ["CHDIR", "CD", "MKDIR", "MD", "RMDIR", "RD"]
        .into_iter()
        .find(|kw| {
            let kw_end = cur.saturating_add(kw.len());
            let prefix: String = input
                .chars
                .get(cur..kw_end.min(end))
                .unwrap_or(&[])
                .iter()
                .map(|c| c.ch)
                .collect();
            prefix.eq_ignore_ascii_case(kw)
                && input
                    .chars
                    .get(kw_end)
                    .filter(|_| kw_end < end)
                    .is_some_and(|n| matches!(n.ch, '.' | BS_CHAR | '/'))
        });
    let matched_kw = dir_kw.or_else(|| {
        [
            "SETLOCAL", "ENDLOCAL", "RENAME", "MKLINK", "DOSKEY", "PROMPT", "VERIFY", "ASSOC",
            "FTYPE", "START", "PUSHD", "PAUSE", "SHIFT", "COLOR", "TITLE", "ERASE", "COPY", "MOVE",
            "TYPE", "CALL", "EXIT", "POPD", "PATH", "DATE", "TIME", "CHCP", "MODE", "DIR", "DEL",
            "REN", "CLS", "VER", "VOL", "SET",
        ]
        .into_iter()
        .find(|kw| {
            let kw_end = cur.saturating_add(kw.len());
            let prefix: String = input
                .chars
                .get(cur..kw_end.min(end))
                .unwrap_or(&[])
                .iter()
                .map(|c| c.ch)
                .collect();
            prefix.eq_ignore_ascii_case(kw)
                && input
                    .chars
                    .get(kw_end)
                    .filter(|_| kw_end < end)
                    .is_some_and(|n| n.ch == '/')
        })
    })?;

    let kw_end = cur.saturating_add(matched_kw.len());
    let tok = slice_to_token(
        input.source_id,
        input.chars,
        cur,
        kw_end,
        SyntaxKind::LiteralToken,
    );
    let span = tok.span;
    let node = CstNode::new(SyntaxKind::WordNode, span, vec![CstElement::Token(tok)]);
    Some((CstElement::Node(node), None, kw_end, matched_kw.to_owned()))
}

/// Parses an I/O redirection clause (`< in`, `> out`, `>> out`, `2>&1`, `0<&3`) starting at `cursor`.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cursor` - Candidate index.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `Some((RedirectionNode_or_ErrorNode, next_cursor))` if a redirection operator starts at `cursor`.
pub fn parse_redirection_node(
    input: &mut CstParserState<'_>,
    cursor: usize,
    end: usize,
) -> Option<(CstElement, usize)> {
    let first_sc = input.chars.get(cursor).filter(|_| cursor < end)?;
    let has_digit_prefix = first_sc.raw_char().is_some_and(|c| c.is_ascii_digit())
        && input
            .chars
            .get(cursor.saturating_add(1))
            .filter(|_| cursor.saturating_add(1) < end)
            .and_then(SpannedChar::raw_char)
            .is_some_and(|c| c == '>' || c == '<');
    let op_start = if has_digit_prefix {
        cursor.saturating_add(1)
    } else if first_sc.raw_char().is_some_and(|c| c == '>' || c == '<') {
        cursor
    } else {
        return None;
    };

    let op_ch = input.chars.get(op_start).map_or('>', |c| c.ch);
    let is_input = op_ch == '<';
    let mut cur = op_start.saturating_add(1);
    let mut is_append = false;
    if input
        .chars
        .get(cur)
        .filter(|_| cur < end)
        .is_some_and(|s| s.raw_char() == Some(op_ch))
    {
        if is_input && input.recovery_mode.is_strict() {
            return Some(emit_strict_double_input_redir_error(
                input,
                cursor,
                cur,
                first_sc.span.end,
            ));
        }
        is_append = !is_input;
        cur = cur.saturating_add(1);
    }

    if !is_append
        && input
            .chars
            .get(cur)
            .filter(|_| cur < end)
            .is_some_and(|a| a.is_raw('&'))
    {
        return Some(parse_handle_dup_redirection_cst(input, cursor, cur, end));
    }

    let op_tok = slice_to_token(
        input.source_id,
        input.chars,
        cursor,
        cur,
        SyntaxKind::RedirectOpToken,
    );
    let op_span = op_tok.span;
    let mut redir_children = vec![CstElement::Token(op_tok)];
    cur = consume_horizontal_trivia(
        input,
        cur,
        TriviaDelimiterMode::IncludeCommandDelimiters,
        &mut redir_children,
    );
    let Some((target_word, next_pos)) = parse_word_node(
        input,
        cur,
        end,
        WordEqualsMode::SplitOnAnyEquals,
        WordParenScope::Normal,
    ) else {
        input
            .farthest
            .record_failure(cur, op_span, PegExpected::RedirectionTarget);
        input.record_syntax_error(
            op_span,
            "The syntax of the command is incorrect. Missing filename after redirection operator."
                .to_owned(),
            vec![PegExpected::RedirectionTarget],
            Some("Provide a target filename or device (e.g. `> out.txt` or `> NUL`).".to_owned()),
        );
        let node = CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            op_span.start,
            redir_children,
        );
        return Some((CstElement::Node(node), cur));
    };

    redir_children.push(CstElement::Node(target_word));
    let node = CstNode::from_children(
        SyntaxKind::RedirectionNode,
        input.source_id,
        op_span.start,
        redir_children,
    );
    Some((CstElement::Node(node), next_pos))
}

/// Emits a strict-mode `<<` syntax error and returns the wrapped [`SyntaxKind::ErrorNode`].
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cursor` - Start character index of the redirection operator.
/// * `second_lt_idx` - Character index of the second `<`.
/// * `fallback_end` - Fallback byte offset for span construction.
///
/// # Returns
/// `(ErrorNode element, next_cursor)`.
fn emit_strict_double_input_redir_error(
    input: &mut CstParserState<'_>,
    cursor: usize,
    second_lt_idx: usize,
    fallback_end: ByteOffset,
) -> (CstElement, usize) {
    let err_span = input.span_at(second_lt_idx, fallback_end);
    input.record_syntax_error(
        err_span,
        "< was unexpected at this time.".to_owned(),
        vec![PegExpected::RedirectionTarget],
        None,
    );
    let next_cur = second_lt_idx.saturating_add(1);
    let bad_tok = slice_to_token(
        input.source_id,
        input.chars,
        cursor,
        next_cur,
        SyntaxKind::RedirectOpToken,
    );
    let node = CstNode::new(
        SyntaxKind::ErrorNode,
        bad_tok.span,
        vec![CstElement::Token(bad_tok)],
    );
    (CstElement::Node(node), next_cur)
}

/// Parses a `>&n` or `<&n` handle duplication redirection starting at `cursor` (`&` at `amp_idx`).
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cursor` - Start of the redirection clause.
/// * `amp_idx` - Index of `&`.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `(RedirectionNode_or_ErrorNode, next_cursor)`.
fn parse_handle_dup_redirection_cst(
    input: &mut CstParserState<'_>,
    cursor: usize,
    amp_idx: usize,
    end: usize,
) -> (CstElement, usize) {
    let digit_idx = amp_idx.saturating_add(1);
    if let Some(digit_sc) = input.chars.get(digit_idx).filter(|_| digit_idx < end) {
        if digit_sc.ch.is_ascii_digit() {
            let next_pos = digit_idx.saturating_add(1);
            let op_tok = slice_to_token(
                input.source_id,
                input.chars,
                cursor,
                next_pos,
                SyntaxKind::RedirectOpToken,
            );
            let span = op_tok.span;
            let node = CstNode::new(
                SyntaxKind::RedirectionNode,
                span,
                vec![CstElement::Token(op_tok)],
            );
            return (CstElement::Node(node), next_pos);
        }
        let bad_tok = slice_to_token(
            input.source_id,
            input.chars,
            cursor,
            digit_idx.saturating_add(1),
            SyntaxKind::RedirectOpToken,
        );
        let err_span = bad_tok.span;
        input
            .farthest
            .record_failure(digit_idx, err_span, PegExpected::RedirectionTarget);
        input.record_syntax_error(
            err_span,
            format!("{} was unexpected at this time.", digit_sc.ch),
            vec![PegExpected::RedirectionTarget],
            Some(
                "Specify a valid handle digit `0`..`9` after `>&` or `<&` (e.g. `2>&1`)."
                    .to_owned(),
            ),
        );
        let node = CstNode::new(
            SyntaxKind::ErrorNode,
            err_span,
            vec![CstElement::Token(bad_tok)],
        );
        return (CstElement::Node(node), digit_idx.saturating_add(1));
    }

    let bad_tok = slice_to_token(
        input.source_id,
        input.chars,
        cursor,
        digit_idx,
        SyntaxKind::RedirectOpToken,
    );
    let err_span = bad_tok.span;
    input
        .farthest
        .record_failure(amp_idx, err_span, PegExpected::RedirectionTarget);
    input.record_syntax_error(
        err_span,
        "The syntax of the command is incorrect. Missing handle digit after `>&`.".to_owned(),
        vec![PegExpected::RedirectionTarget],
        Some("Specify a valid handle digit `0`..`9` after `>&` (e.g. `2>&1`).".to_owned()),
    );
    let node = CstNode::new(
        SyntaxKind::ErrorNode,
        err_span,
        vec![CstElement::Token(bad_tok)],
    );
    (CstElement::Node(node), digit_idx)
}

/// Parses a composite command argument or word at `cursor` into a [`SyntaxKind::WordNode`].
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cursor` - Starting index.
/// * `end` - Exclusive end index.
/// * `equals_mode` - [`WordEqualsMode`] controlling `'='` vs `'=='` splitting.
/// * `paren_scope` - [`WordParenScope`] controlling `')'` termination inside `FOR (...)` sets.
///
/// # Returns
/// `Some((WordNode, next_cursor))` if non-empty, else `None`.
pub fn parse_word_node(
    input: &mut CstParserState<'_>,
    cursor: usize,
    end: usize,
    equals_mode: WordEqualsMode,
    paren_scope: WordParenScope,
) -> Option<(CstNode, usize)> {
    let mut parts: Vec<CstElement> = Vec::new();
    let mut cur = cursor;
    let in_for_set = paren_scope == WordParenScope::InsideForSet;

    while cur < end {
        while let Some(cont_end) = is_caret_line_continuation_at(input.chars, cur) {
            parts.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                cur,
                cont_end.min(end),
                SyntaxKind::CaretLineContinuation,
            )));
            cur = cont_end.min(end);
        }
        let Some(sc) = input.chars.get(cur).filter(|_| cur < end) else {
            break;
        };
        let stop_eq = !sc.escaped_by_caret
            && sc.ch == '='
            && match equals_mode {
                WordEqualsMode::SplitOnAnyEquals => true,
                WordEqualsMode::StopAtDoubleEquals => input
                    .chars
                    .get(cur.saturating_add(1))
                    .filter(|_| cur.saturating_add(1) < end)
                    .is_some_and(|n| n.is_raw('=')),
                WordEqualsMode::KeepAllEquals => false,
            };

        let stop_delim = is_broken_caret_at(input.chars, cur).is_some()
            || (!sc.escaped_by_caret && matches!(sc.ch, CR_CHAR | LF_CHAR | '<' | '>' | '|' | '&'))
            || (!sc.escaped_by_caret && sc.ch == ')' && in_for_set)
            || stop_eq
            || (!sc.escaped_by_caret && is_cmd_delimiter(sc.ch) && sc.ch != '=');
        if stop_delim {
            break;
        }

        if sc.is_raw('"') {
            let (q_node, next_cur) = parse_quoted_string_node(input, cur, end);
            parts.push(CstElement::Node(q_node));
            cur = next_cur;
            continue;
        }
        if sc.is_raw('^') {
            let esc_end = cur.saturating_add(2).min(end);
            parts.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                cur,
                esc_end,
                SyntaxKind::CaretEscapeToken,
            )));
            cur = esc_end;
            continue;
        }
        if sc.ch == '%' {
            let (pct_tok, next_cur) = parse_percent_construct(input, cur, end);
            parts.push(CstElement::Token(pct_tok));
            cur = next_cur;
            continue;
        }
        if sc.ch == '!'
            && let Some((del_tok, next_cur)) = parse_delayed_var_token(input, cur, end)
        {
            parts.push(CstElement::Token(del_tok));
            cur = next_cur;
            continue;
        }

        let (lit_tok, next_cur) = parse_literal_word_run(input, cur, end, equals_mode, paren_scope);
        parts.push(CstElement::Token(lit_tok));
        cur = next_cur;
    }

    if parts.is_empty() {
        return None;
    }
    let first_off = parts.first().map_or(ByteOffset(0), |e| e.span().start);
    let node = CstNode::from_children(SyntaxKind::WordNode, input.source_id, first_off, parts);
    Some((node, cur))
}

/// Scans a contiguous unquoted literal sub-word run starting at `lit_start`.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `lit_start` - Start index of the literal run.
/// * `end` - Exclusive end index.
/// * `equals_mode` - [`WordEqualsMode`] controlling `'='` termination.
/// * `paren_scope` - [`WordParenScope`] (`InsideForSet` stops at `')'`).
///
/// # Returns
/// `(LiteralToken, next_cursor)`.
fn parse_literal_word_run(
    input: &mut CstParserState<'_>,
    lit_start: usize,
    end: usize,
    equals_mode: WordEqualsMode,
    paren_scope: WordParenScope,
) -> (CstToken, usize) {
    let mut cur = lit_start.saturating_add(1);
    while let Some(c) = input.chars.get(cur).filter(|_| cur < end) {
        let eq_stops = c.ch == '='
            && match equals_mode {
                WordEqualsMode::SplitOnAnyEquals => true,
                WordEqualsMode::StopAtDoubleEquals => input
                    .chars
                    .get(cur.saturating_add(1))
                    .filter(|_| cur.saturating_add(1) < end)
                    .is_some_and(|n| n.is_raw('=')),
                WordEqualsMode::KeepAllEquals => false,
            };
        let stop_lit = matches!(
            c.ch,
            '%' | '!' | '"' | '^' | CR_CHAR | LF_CHAR | '<' | '>' | '|' | '&'
        ) || (c.ch == ')' && paren_scope == WordParenScope::InsideForSet)
            || eq_stops
            || (is_cmd_delimiter(c.ch) && c.ch != '=');
        if stop_lit {
            break;
        }
        if c.ch == ')' && input.in_block_depth > 0 {
            input.record_misuse(
                c.span,
                ProbableMisuseKind::UnescapedClosingParenInBlock { span: c.span },
                "Unescaped `)` inside command/ECHO prematurely closes `( ... )` block.".to_owned(),
                "Escape literal parentheses inside `( ... )` blocks as `^(` and `^)`.".to_owned(),
                Some((c.span, "^)".to_owned())),
            );
        }
        cur = cur.saturating_add(1);
    }
    (
        slice_to_token(
            input.source_id,
            input.chars,
            lit_start,
            cur,
            SyntaxKind::LiteralToken,
        ),
        cur,
    )
}

/// Parses a quoted string (`"` + interior sub-word tokens + optional closing `"`) starting at `open_idx`.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `open_idx` - Index of opening `"`.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `(QuotedStringNode, next_cursor)`.
fn parse_quoted_string_node(
    input: &mut CstParserState<'_>,
    open_idx: usize,
    end: usize,
) -> (CstNode, usize) {
    let open_span = input.span_at(open_idx, ByteOffset(0));
    let mut children = vec![CstElement::Token(CstToken::new(
        SyntaxKind::DoubleQuote,
        r#"""#.to_owned(),
        open_span,
    ))];
    let mut cur = open_idx.saturating_add(1);
    let mut closed = false;
    let rel_eol = input
        .chars
        .get(open_idx..end)
        .unwrap_or(&[])
        .iter()
        .take_while(|c| c.escaped_by_caret || (c.ch != CR_CHAR && c.ch != LF_CHAR))
        .count();
    let line_end = open_idx.saturating_add(rel_eol);

    while let Some(sc) = input.chars.get(cur).filter(|_| cur < line_end) {
        if let Some(cont_end) = is_caret_line_continuation_at(input.chars, cur) {
            children.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                cur,
                cont_end.min(line_end),
                SyntaxKind::CaretLineContinuation,
            )));
            cur = cont_end.min(line_end);
            continue;
        }
        if sc.ch == '"' {
            children.push(CstElement::Token(CstToken::new(
                SyntaxKind::DoubleQuote,
                r#"""#.to_owned(),
                sc.span,
            )));
            cur = cur.saturating_add(1);
            closed = true;
            break;
        }
        if sc.ch == '%' {
            let (pct_tok, next_cur) = parse_percent_construct(input, cur, line_end);
            children.push(CstElement::Token(pct_tok));
            cur = next_cur;
            continue;
        }
        if sc.ch == '!'
            && let Some((del_tok, next_cur)) = parse_delayed_var_token(input, cur, line_end)
        {
            children.push(CstElement::Token(del_tok));
            cur = next_cur;
            continue;
        }

        let lit_start = cur;
        cur = cur.saturating_add(1);
        while let Some(c) = input.chars.get(cur).filter(|_| cur < line_end) {
            if is_caret_line_continuation_at(input.chars, cur).is_some()
                || matches!(c.ch, '"' | '%' | '!')
            {
                break;
            }
            cur = cur.saturating_add(1);
        }
        children.push(CstElement::Token(slice_to_token(
            input.source_id,
            input.chars,
            lit_start,
            cur,
            SyntaxKind::LiteralToken,
        )));
    }

    let node = CstNode::from_children(
        SyntaxKind::QuotedStringNode,
        input.source_id,
        open_span.start,
        children,
    );
    if !closed {
        let unclosed_span = node.span;
        input.record_misuse(
            unclosed_span,
            ProbableMisuseKind::UnclosedDoubleQuote {
                span: unclosed_span,
            },
            r#"Unclosed double quote `"` on command line."#.to_owned(),
            r#"Add a closing `"` double quote at the end of the quoted argument."#.to_owned(),
            Some((
                Span::new(input.source_id, unclosed_span.end, unclosed_span.end),
                r#"""#.to_owned(),
            )),
        );
    }
    (node, cur)
}

/// Ordered-choice rule for `%` constructs starting at `pct_idx`.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `pct_idx` - Index of `%`.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `(CstToken, next_cursor)`.
fn parse_percent_construct(
    input: &mut CstParserState<'_>,
    pct_idx: usize,
    end: usize,
) -> (CstToken, usize) {
    let has_double_pct = input
        .chars
        .get(pct_idx.saturating_add(1))
        .filter(|_| pct_idx.saturating_add(1) < end)
        .is_some_and(|c| c.ch == '%');
    if has_double_pct {
        return parse_double_percent_construct(input, pct_idx, end);
    }
    parse_single_percent_construct(input, pct_idx, end)
}

/// Parses a `%%...` construct (`%%I`, `%%~dpI`, or literal `%%`) starting at `pct_idx`.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `pct_idx` - Index of leading `%`.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `(CstToken, next_cursor)`.
fn parse_double_percent_construct(
    input: &mut CstParserState<'_>,
    pct_idx: usize,
    end: usize,
) -> (CstToken, usize) {
    let required_arity = PercentArity::for_execution_context(input.exec_context);
    let after_pcts = pct_idx.saturating_add(2);
    if let Some((tok_end, var_ch)) = match_for_var_body(input.chars, after_pcts, end) {
        let tok = slice_to_token(
            input.source_id,
            input.chars,
            pct_idx,
            tok_end,
            SyntaxKind::ForVarToken,
        );
        if required_arity == PercentArity::SinglePercent {
            let single_repl = tok.text.strip_prefix('%').unwrap_or(&tok.text).to_owned();
            input.record_misuse(
                tok.span,
                ProbableMisuseKind::DoublePercentForVarInRepl {
                    span: tok.span,
                    raw_var: tok.text.clone(),
                },
                format!(
                    "Double-percent `FOR` variable `{}` in interactive REPL mode; REPL requires single `%{var_ch}`.",
                    tok.text
                ),
                format!("Use `{single_repl}` in interactive REPL mode."),
                Some((tok.span, single_repl)),
            );
        }
        return (tok, tok_end);
    }
    let tok = slice_to_token(
        input.source_id,
        input.chars,
        pct_idx,
        after_pcts,
        SyntaxKind::PercentLiteralToken,
    );
    if required_arity == PercentArity::SinglePercent {
        input.record_misuse(
            tok.span,
            ProbableMisuseKind::DoublePercentLiteralInRepl { span: tok.span },
            "Double `%%` does not collapse to a single `%` in interactive REPL mode.".to_owned(),
            "Use a single `%` literal in interactive REPL mode.".to_owned(),
            Some((tok.span, "%".to_owned())),
        );
    }
    (tok, after_pcts)
}

/// Parses a single-`%` construct (`%~dp1`, `%1`, `%*`, `%VAR%`, `%I`, or stray `%`) at `pct_idx`.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `pct_idx` - Index of `%`.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `(CstToken, next_cursor)`.
fn parse_single_percent_construct(
    input: &mut CstParserState<'_>,
    pct_idx: usize,
    end: usize,
) -> (CstToken, usize) {
    let required_arity = PercentArity::for_execution_context(input.exec_context);
    let after_pct = pct_idx.saturating_add(1);
    let second_ch = input
        .chars
        .get(after_pct)
        .filter(|_| after_pct < end)
        .map(|c| c.ch);

    if second_ch == Some('~')
        && let Some(res) = try_parse_single_tilde_construct(input, pct_idx, end)
    {
        return res;
    }

    if second_ch.is_some_and(|ch| ch.is_ascii_digit() || ch == '*') {
        let tok_end = after_pct.saturating_add(1);
        return (
            slice_to_token(
                input.source_id,
                input.chars,
                pct_idx,
                tok_end,
                SyntaxKind::PositionalParamToken,
            ),
            tok_end,
        );
    }

    if let Some(close_pct_idx) = find_closing_percent_on_line(input.chars, after_pct, end) {
        let tok_end = close_pct_idx.saturating_add(1);
        return (
            slice_to_token(
                input.source_id,
                input.chars,
                pct_idx,
                tok_end,
                SyntaxKind::EnvVarToken,
            ),
            tok_end,
        );
    }

    if let Some(ch) = second_ch
        && ForVarName::from_char(ch).is_some()
        && ch != '~'
        && (input.active_for_vars.contains(&ch)
            || (required_arity == PercentArity::SinglePercent && ch.is_ascii_alphabetic()))
        && !matches!(
            input.chars.get(..end).and_then(|s| s.get(after_pct.saturating_add(1))),
            Some(third) if third.ch.is_ascii_alphanumeric()
        )
    {
        let tok_end = after_pct.saturating_add(1);
        let tok = slice_to_token(
            input.source_id,
            input.chars,
            pct_idx,
            tok_end,
            SyntaxKind::ForVarToken,
        );
        if required_arity == PercentArity::DoublePercent {
            let doubled = format!("%{}", tok.text);
            input.record_misuse(
                tok.span,
                ProbableMisuseKind::SinglePercentForVarInBatch {
                    span: tok.span,
                    raw_var: tok.text.clone(),
                },
                format!(
                    "Single-percent `FOR` variable `{}` in a batch file; use `{doubled}`.",
                    tok.text
                ),
                format!("Rewrite `{}` as `{doubled}`.", tok.text),
                Some((tok.span, doubled)),
            );
        }
        return (tok, tok_end);
    }

    let tok = slice_to_token(
        input.source_id,
        input.chars,
        pct_idx,
        after_pct,
        SyntaxKind::PercentLiteralToken,
    );
    if required_arity == PercentArity::DoublePercent {
        input.record_misuse(
            tok.span,
            ProbableMisuseKind::UnescapedSinglePercentInBatch { span: tok.span },
            "Unescaped single `%` in a batch file is stripped by `cmd.exe` Phase 1 expansion."
                .to_owned(),
            "Escape a literal percent sign as `%%` in `.bat`/`.cmd` files.".to_owned(),
            Some((tok.span, "%%".to_owned())),
        );
    }
    (tok, after_pct)
}

/// Attempts to parse a `%~...` tilde modifier construct and emit any misuse diagnostics.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `pct_idx` - Index of `%`.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `Some((CstToken, next_cursor))` if matched.
fn try_parse_single_tilde_construct(
    input: &mut CstParserState<'_>,
    pct_idx: usize,
    end: usize,
) -> Option<(CstToken, usize)> {
    let required_arity = PercentArity::for_execution_context(input.exec_context);
    let (kind, tok_end, is_invalid_mod, is_single_pct_for_var) =
        classify_tilde_percent_construct(input.chars, pct_idx, end, &input.active_for_vars)?;
    let tok = slice_to_token(input.source_id, input.chars, pct_idx, tok_end, kind);
    if is_invalid_mod {
        input.record_misuse(
            tok.span,
            ProbableMisuseKind::InvalidModifierOnNamedVar {
                span: tok.span,
                raw_token: tok.text.clone(),
            },
            format!(
                "`%~` path modifiers in `{}` only work on `%0`..`%9` parameters and `FOR` variables, not named environment variables.",
                tok.text
            ),
            r#"Assign the variable inside a `FOR` loop (`FOR %%I IN ("%VAR%") DO ... %%~dpI`) or call a subroutine and use `%~dp1`."#
                .to_owned(),
            None,
        );
    } else if is_single_pct_for_var && required_arity == PercentArity::DoublePercent {
        let doubled = format!("%{}", tok.text);
        input.record_misuse(
            tok.span,
            ProbableMisuseKind::SinglePercentForVarInBatch {
                span: tok.span,
                raw_var: tok.text.clone(),
            },
            format!(
                "Single-percent `FOR` variable `{}` in a batch file; use `{doubled}`.",
                tok.text
            ),
            format!("Rewrite `{}` as `{doubled}`.", tok.text),
            Some((tok.span, doubled)),
        );
    }
    Some((tok, tok_end))
}

/// Attempts to match a `FOR` variable body (`I` or `~[f|d|p|n|x|s|a|t|z|$VAR:]I`) after `%%`.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `after_pcts` - Index immediately following `%%`.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `Some((end_idx, var_char))` if matched.
fn match_for_var_body(
    chars: &[SpannedChar],
    after_pcts: usize,
    end: usize,
) -> Option<(usize, char)> {
    let first = chars.get(after_pcts).filter(|_| after_pcts < end)?;
    if first.ch == '~' {
        let mod_start = after_pcts.saturating_add(1);
        let skip_mods = chars
            .get(mod_start..end)
            .unwrap_or(&[])
            .iter()
            .enumerate()
            .take_while(|&(rel, sc)| {
                is_modifier_flag_char(sc.ch)
                    && chars
                        .get(mod_start.saturating_add(rel).saturating_add(1))
                        .is_some_and(|n| ForVarName::from_char(n.ch).is_some() || n.ch == '$')
            })
            .count();
        let cur = mod_start.saturating_add(skip_mods);
        let ch = chars.get(cur).map_or('\0', |c| c.ch);
        if ch == '$' {
            let slice = chars.get(cur.saturating_add(1)..end).unwrap_or(&[]);
            let rel_colon = slice
                .iter()
                .position(|c| c.ch == ':')
                .unwrap_or(slice.len());
            let valid_env = rel_colon > 0
                && rel_colon < slice.len()
                && slice
                    .get(..rel_colon)
                    .unwrap_or(&[])
                    .iter()
                    .all(|c| c.ch.is_ascii_alphanumeric() || c.ch == '_');
            if !valid_env {
                return None;
            }
            let var_pos = cur
                .saturating_add(1)
                .saturating_add(rel_colon)
                .saturating_add(1);
            return chars
                .get(var_pos)
                .and_then(|var_sc| ForVarName::from_char(var_sc.ch))
                .map(|v| (var_pos.saturating_add(1), v.as_char()));
        }
        return ForVarName::from_char(ch).map(|_| (cur.saturating_add(1), ch));
    }
    ForVarName::from_char(first.ch).map(|_| (after_pcts.saturating_add(1), first.ch))
}

/// Checks if `ch` is one of the 9 standard `cmd.exe` path/attribute modifier letters (`f,d,p,n,x,s,a,t,z`).
///
/// # Arguments
/// * `ch` - Character to inspect.
///
/// # Returns
/// `true` if `ch` is a modifier letter.
#[must_use]
const fn is_modifier_flag_char(ch: char) -> bool {
    matches!(
        ch.to_ascii_lowercase(),
        'f' | 'd' | 'p' | 'n' | 'x' | 's' | 'a' | 't' | 'z'
    )
}

/// Classifies a single-percent tilde construct starting at `pct_idx` (`%~...`).
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `pct_idx` - Index of `%`.
/// * `end` - Exclusive end index.
/// * `active_for_vars` - Active `FOR` variables in scope.
///
/// # Returns
/// `Some((kind, tok_end, is_invalid_mod, is_single_pct_for_var))` if matched.
fn classify_tilde_percent_construct(
    chars: &[SpannedChar],
    pct_idx: usize,
    end: usize,
    active_for_vars: &BTreeSet<char>,
) -> Option<(SyntaxKind, usize, bool, bool)> {
    let tilde_idx = pct_idx.saturating_add(1);
    let mod_start = tilde_idx.saturating_add(1);

    if let Some(close_pct) = find_closing_percent_on_line(chars, mod_start, end) {
        let inner: String = chars
            .get(mod_start..close_pct)
            .unwrap_or(&[])
            .iter()
            .map(|c| c.ch)
            .collect();
        let mod_len = inner
            .chars()
            .take_while(|&c| is_modifier_flag_char(c))
            .count();
        let rem: String = inner.chars().skip(mod_len).collect();
        let starts_with_digit = rem.chars().next().is_some_and(|c| c.is_ascii_digit());
        if mod_len > 0 && inner.chars().count() >= 2 && !starts_with_digit {
            return Some((
                SyntaxKind::InvalidModifierVarToken,
                close_pct.saturating_add(1),
                true,
                false,
            ));
        }
    }

    let mut cur = mod_start;
    while let Some(sc) = chars.get(..end).and_then(|s| s.get(cur)) {
        let next_ok = matches!(
            chars.get(..end).and_then(|s| s.get(cur.saturating_add(1))),
            Some(n) if n.ch.is_ascii_alphanumeric() || n.ch == '$'
        );
        if !(is_modifier_flag_char(sc.ch) && !active_for_vars.contains(&sc.ch) && next_ok) {
            break;
        }
        cur = cur.saturating_add(1);
    }
    let ch = chars.get(cur).map_or('\0', |c| c.ch);
    if ch == '$' {
        let slice = chars.get(cur.saturating_add(1)..end).unwrap_or(&[]);
        let rel_colon = slice
            .iter()
            .position(|c| c.ch == ':')
            .unwrap_or(slice.len());
        let valid_env = rel_colon > 0
            && rel_colon < slice.len()
            && slice
                .get(..rel_colon)
                .unwrap_or(&[])
                .iter()
                .all(|c| c.ch.is_ascii_alphanumeric() || c.ch == '_');
        if !valid_env {
            return None;
        }
        let target_pos = cur
            .saturating_add(1)
            .saturating_add(rel_colon)
            .saturating_add(1);
        let target_ch = chars.get(target_pos).map_or('\0', |c| c.ch);
        if target_ch.is_ascii_digit() {
            return Some((
                SyntaxKind::PositionalParamToken,
                target_pos.saturating_add(1),
                false,
                false,
            ));
        }
        return ForVarName::from_char(target_ch).map(|_| {
            (
                SyntaxKind::ForVarToken,
                target_pos.saturating_add(1),
                false,
                true,
            )
        });
    }
    if ch.is_ascii_digit() {
        return Some((
            SyntaxKind::PositionalParamToken,
            cur.saturating_add(1),
            false,
            false,
        ));
    }
    ForVarName::from_char(ch).map(|_| (SyntaxKind::ForVarToken, cur.saturating_add(1), false, true))
}

/// Finds the index of the closing `%` for an environment variable expansion starting at `after_open_pct`.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `after_open_pct` - Index immediately following opening `%`.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `Some(close_pct_idx)` if found on the same line.
fn find_closing_percent_on_line(
    chars: &[SpannedChar],
    after_open_pct: usize,
    end: usize,
) -> Option<usize> {
    let mut cur = after_open_pct;
    while let Some(sc) = chars.get(cur).filter(|_| cur < end) {
        if matches!(sc.ch, CR_CHAR | LF_CHAR | '"') {
            return None;
        }
        if sc.ch == '%' {
            return (cur > after_open_pct).then_some(cur);
        }
        if (sc.ch == ' ' || sc.ch == TAB_CHAR)
            && !chars
                .get(after_open_pct..cur)
                .unwrap_or(&[])
                .iter()
                .any(|c| c.ch == ':')
        {
            return None;
        }
        cur = cur.saturating_add(1);
    }
    None
}

/// Attempts to parse a `!VAR!` or `!VAR:...!` delayed expansion token starting at `bang_idx`.
///
/// # Arguments
/// * `input` - Immutable [`CstParserState`].
/// * `bang_idx` - Index of opening `!`.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `Some((DelayedVarToken, next_cursor))` if closed on the same line, else `None`.
fn parse_delayed_var_token(
    input: &CstParserState<'_>,
    bang_idx: usize,
    end: usize,
) -> Option<(CstToken, usize)> {
    let after_bang = bang_idx.saturating_add(1);
    let mut cur = after_bang;
    while let Some(sc) = input.chars.get(cur).filter(|_| cur < end) {
        if matches!(sc.ch, CR_CHAR | LF_CHAR | '"') {
            return None;
        }
        if sc.ch == '!' {
            if cur == after_bang {
                return None;
            }
            let tok_end = cur.saturating_add(1);
            return Some((
                slice_to_token(
                    input.source_id,
                    input.chars,
                    bang_idx,
                    tok_end,
                    SyntaxKind::DelayedVarToken,
                ),
                tok_end,
            ));
        }
        if (sc.ch == ' ' || sc.ch == TAB_CHAR)
            && !input
                .chars
                .get(after_bang..cur)
                .unwrap_or(&[])
                .iter()
                .any(|c| c.ch == ':')
        {
            return None;
        }
        cur = cur.saturating_add(1);
    }
    None
}
