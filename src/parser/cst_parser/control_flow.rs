//! Compound `( ... )` block, `IF` conditional, and `FOR` loop rules for the lossless CST parser.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::{PegExpected, ProbableMisuseKind};
use crate::parser::cst::{CstElement, CstNode, CstToken, SyntaxKind};
use crate::parser::lexer::{
    find_matching_close_paren_in_slice, is_caret_line_continuation_at, is_cmd_delimiter,
    is_echo_open_paren_at, is_keyword_at, scan_next_block_line_boundary,
};
use crate::reader::char_map::SpannedChar;
use crate::span::{ByteOffset, Span};
use crate::types::{CR_CHAR, ForVarName, LF_CHAR, PercentArity, QuoteMode, RecoveryMode, TAB_CHAR};

use super::TriviaDelimiterMode::{IncludeCommandDelimiters, SpacesAndTabsOnly};
use super::words::{parse_redirection_node, parse_word_node};
use super::{
    CstParserState, WordEqualsMode, WordParenScope, append_comment_or_raw_with_continuations,
    consume_horizontal_trivia, parse_command_expr_slice_cst, parse_statement_range_cst,
    slice_has_non_trivia, slice_to_token,
};

/// Parses a `( ... )` compound block and any trailing block-level redirections.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `children` - Leading trivia and `@` tokens.
/// * `open_idx` - Index of `(`.
/// * `end` - Exclusive end index.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `CompoundBlock` or `ErrorNode` [`CstNode`].
pub(super) fn parse_compound_block_cst(
    input: &mut CstParserState<'_>,
    mut children: Vec<CstElement>,
    open_idx: usize,
    end: usize,
    fallback_offset: ByteOffset,
) -> CstNode {
    let open_span = input.span_at(open_idx, fallback_offset);
    children.push(CstElement::Token(CstToken::new(
        SyntaxKind::OpenParen,
        "(".to_owned(),
        open_span,
    )));
    let Some(close_idx) = find_matching_close_paren_in_slice(input.chars, open_idx, end) else {
        input
            .farthest
            .record_failure(open_idx, open_span, PegExpected::ClosingParen);
        input.record_syntax_error(
            open_span,
            "Unclosed `(` compound command block; expected matching `)`.".to_owned(),
            vec![PegExpected::ClosingParen],
            Some("Add a matching `)` to close the compound block.".to_owned()),
        );
        input.in_block_depth = input.in_block_depth.saturating_add(1);
        parse_block_interior_lines_cst(
            input,
            open_idx.saturating_add(1),
            end,
            open_span.end,
            &mut children,
        );
        input.in_block_depth = input.in_block_depth.saturating_sub(1);
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            children,
        );
    };

    input.in_block_depth = input.in_block_depth.saturating_add(1);
    let interior_err = parse_block_interior_lines_cst(
        input,
        open_idx.saturating_add(1),
        close_idx,
        open_span.end,
        &mut children,
    );
    input.in_block_depth = input.in_block_depth.saturating_sub(1);

    let close_span = input.span_at(close_idx, open_span.end);
    children.push(CstElement::Token(CstToken::new(
        SyntaxKind::CloseParen,
        ")".to_owned(),
        close_span,
    )));

    let has_trailing_error = parse_compound_block_trailing_cst(
        input,
        open_idx,
        close_idx,
        close_span,
        end,
        &mut children,
    );
    let strict_err = interior_err && input.recovery_mode.is_strict();
    let kind = if has_trailing_error || strict_err {
        SyntaxKind::ErrorNode
    } else {
        SyntaxKind::CompoundBlock
    };
    CstNode::from_children(kind, input.source_id, fallback_offset, children)
}

/// Parses trailing trivia, block-level redirections, or unexpected tokens following `)`.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `open_idx` - Index of opening `(`.
/// * `close_idx` - Index of matching `)`.
/// * `close_span` - [`Span`] of matching `)`.
/// * `end` - Exclusive end index.
/// * `children` - Destination child element vector for the compound block.
///
/// # Returns
/// `true` if a redirection error or unexpected trailing token occurred after `)`.
fn parse_compound_block_trailing_cst(
    input: &mut CstParserState<'_>,
    open_idx: usize,
    close_idx: usize,
    close_span: Span,
    end: usize,
    children: &mut Vec<CstElement>,
) -> bool {
    let mut cur = close_idx.saturating_add(1);
    let mut has_trailing_error = false;
    while cur < end {
        cur = consume_horizontal_trivia(input, cur, SpacesAndTabsOnly, children);
        if cur >= end {
            break;
        }
        if let Some((redir_el, next_cur)) = parse_redirection_node(input, cur, end) {
            if redir_el.kind() == SyntaxKind::ErrorNode {
                has_trailing_error = true;
            }
            children.push(redir_el);
            cur = next_cur;
            continue;
        }
        has_trailing_error = true;
        if find_unescaped_echo_paren_misuse(input.chars, open_idx.saturating_add(1), close_idx, end)
        {
            input.record_misuse(
                close_span,
                ProbableMisuseKind::UnescapedClosingParenInBlock { span: close_span },
                "Unescaped `)` inside command/ECHO prematurely closed the `( ... )` block."
                    .to_owned(),
                "Escape literal parentheses inside `( ... )` blocks as `^(` and `^)`.".to_owned(),
                Some((close_span, "^)".to_owned())),
            );
        } else {
            let unexp_span = input.span_at(cur, close_span.end);
            let unexp_ch = input.chars.get(cur).map_or('?', |c| c.ch);
            input.record_syntax_error(
                unexp_span,
                format!("{unexp_ch} was unexpected at this time."),
                vec![PegExpected::RedirectionTarget],
                Some(
                    "Only I/O redirections or command operators (`&`, `&&`, `||`, `|`) may follow `)`."
                        .to_owned(),
                ),
            );
        }
        append_comment_or_raw_with_continuations(
            input,
            cur,
            end,
            SyntaxKind::LiteralToken,
            children,
        );
        break;
    }
    has_trailing_error
}

/// Checks if `close_idx` prematurely closed a block on an `ECHO` line while another `)` follows.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `inner_start` - Index after opening `(`.
/// * `close_idx` - Index of matched `)`.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `true` if `UnescapedClosingParenInBlock` applies.
#[must_use]
fn find_unescaped_echo_paren_misuse(
    chars: &[SpannedChar],
    inner_start: usize,
    close_idx: usize,
    end: usize,
) -> bool {
    let slice_before = chars.get(inner_start..close_idx).unwrap_or(&[]);
    let line_tail_len = slice_before
        .iter()
        .rev()
        .take_while(|c| !matches!(c.ch, CR_CHAR | LF_CHAR))
        .count();
    let line_start = close_idx.saturating_sub(line_tail_len);
    let line_slice = chars.get(line_start..close_idx).unwrap_or(&[]);
    let trimmed: String = line_slice
        .iter()
        .skip_while(|c| matches!(c.ch, ' ' | TAB_CHAR | '@'))
        .take(4)
        .map(|c| c.ch)
        .collect();
    let is_echo_line = trimmed.eq_ignore_ascii_case("ECHO");
    let has_later_close = chars
        .get(close_idx.saturating_add(1)..end)
        .is_some_and(|tail| tail.iter().any(|c| c.is_raw(')')));
    is_echo_line || has_later_close
}

/// Splits `input.chars[start..end]` into top-level logical lines inside `(...)` and parses each.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `start` - Start of interior content.
/// * `end` - Exclusive end of interior content.
/// * `fallback_offset` - Fallback [`ByteOffset`].
/// * `out` - Destination child vector.
///
/// # Returns
/// `true` if any interior statement parsed as `SyntaxKind::ErrorNode` or block was empty in strict mode.
fn parse_block_interior_lines_cst(
    input: &mut CstParserState<'_>,
    start: usize,
    end: usize,
    fallback_offset: ByteOffset,
    out: &mut Vec<CstElement>,
) -> bool {
    let mut cursor = start;
    let mut any_err = false;
    let mut non_empty_stmt_count = 0usize;

    while cursor < end {
        let (line_end, nl_opt) = scan_next_block_line_boundary(input.chars, cursor, end);
        if line_end > cursor {
            let line_off = input.span_at(cursor, fallback_offset).start;
            let line_node = parse_statement_range_cst(input, cursor, line_end, line_off);
            if line_node.kind == SyntaxKind::ErrorNode {
                any_err = true;
            }
            if !matches!(
                line_node.kind,
                SyntaxKind::EmptyStatement
                    | SyntaxKind::DoubleColonComment
                    | SyntaxKind::LabelStatement
            ) {
                non_empty_stmt_count = non_empty_stmt_count.saturating_add(1);
            }
            out.push(CstElement::Node(line_node));
        }
        if let Some((nl_start, nl_end)) = nl_opt {
            out.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                nl_start,
                nl_end,
                SyntaxKind::Newline,
            )));
            cursor = nl_end;
        } else {
            cursor = line_end.max(cursor.saturating_add(1));
        }
    }

    if input.recovery_mode.is_strict() && non_empty_stmt_count == 0 {
        let err_span = input.span_at(end, fallback_offset);
        input.record_syntax_error(
            err_span,
            ") was unexpected at this time.".to_owned(),
            vec![PegExpected::Statement],
            None,
        );
        any_err = true;
    }
    any_err
}

/// Parses an `IF` statement (`IF [/I] [NOT] IfConditionNode ThenBranch [ElseClauseNode]`).
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `children` - Leading trivia and `@` tokens.
/// * `if_idx` - Index of `IF`.
/// * `end` - Exclusive end index.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `IfStatement` or `ErrorNode` [`CstNode`].
pub(super) fn parse_if_statement_cst(
    input: &mut CstParserState<'_>,
    mut children: Vec<CstElement>,
    if_idx: usize,
    end: usize,
    fallback_offset: ByteOffset,
) -> CstNode {
    let if_end = if_idx.saturating_add(2);
    let if_tok = slice_to_token(
        input.source_id,
        input.chars,
        if_idx,
        if_end,
        SyntaxKind::Keyword,
    );
    let if_span = if_tok.span;
    children.push(CstElement::Token(if_tok));
    let mut cur = consume_horizontal_trivia(input, if_end, IncludeCommandDelimiters, &mut children);

    if is_keyword_at(input.chars, cur, end, "/I") {
        let sw_end = cur.saturating_add(2);
        children.push(CstElement::Token(slice_to_token(
            input.source_id,
            input.chars,
            cur,
            sw_end,
            SyntaxKind::SwitchToken,
        )));
        cur = consume_horizontal_trivia(input, sw_end, IncludeCommandDelimiters, &mut children);
    }
    if is_keyword_at(input.chars, cur, end, "NOT") {
        let not_end = cur.saturating_add(3);
        children.push(CstElement::Token(slice_to_token(
            input.source_id,
            input.chars,
            cur,
            not_end,
            SyntaxKind::Keyword,
        )));
        cur = consume_horizontal_trivia(input, not_end, IncludeCommandDelimiters, &mut children);
    }

    let Some((cond_node, after_cond, cond_ok)) =
        parse_if_condition_node_cst(input, cur, end, if_span.end)
    else {
        let err_span = input.span_at(cur, if_span.end);
        input
            .farthest
            .record_failure(cur, err_span, PegExpected::IfCondition);
        input.record_syntax_error(
            err_span,
            "The syntax of the command is incorrect. Missing `IF` condition.".to_owned(),
            vec![PegExpected::IfCondition],
            Some(r#"Provide a condition after `IF` (e.g. `IF "%A%"=="1" ...` or `IF EXIST file ...`)."#.to_owned()),
        );
        append_comment_or_raw_with_continuations(
            input,
            cur,
            end,
            SyntaxKind::LiteralToken,
            &mut children,
        );
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            children,
        );
    };

    let cond_end_off = cond_node.span.end;
    children.push(CstElement::Node(cond_node));
    if !cond_ok {
        append_comment_or_raw_with_continuations(
            input,
            after_cond,
            end,
            SyntaxKind::LiteralToken,
            &mut children,
        );
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            children,
        );
    }

    parse_if_branches_cst(
        input,
        children,
        after_cond,
        end,
        cond_end_off,
        fallback_offset,
    )
}

/// Parses the `then` branch and optional `ELSE` clause following a valid `IF` condition.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `children` - Accumulated `IF` header and condition child elements.
/// * `after_cond` - Cursor immediately after `IfConditionNode`.
/// * `end` - Exclusive end index.
/// * `cond_end_off` - End [`ByteOffset`] of `IfConditionNode`.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `IfStatement` or `ErrorNode` [`CstNode`].
fn parse_if_branches_cst(
    input: &mut CstParserState<'_>,
    mut children: Vec<CstElement>,
    after_cond: usize,
    end: usize,
    cond_end_off: ByteOffset,
    fallback_offset: ByteOffset,
) -> CstNode {
    let cur = consume_horizontal_trivia(input, after_cond, IncludeCommandDelimiters, &mut children);
    if !slice_has_non_trivia(input.chars, cur, end) {
        let err_span = input.span_at(cur, cond_end_off);
        input
            .farthest
            .record_failure(cur, err_span, PegExpected::IfThenBranch);
        input.record_syntax_error(
            err_span,
            "The syntax of the command is incorrect. Missing command after `IF` condition."
                .to_owned(),
            vec![PegExpected::IfThenBranch],
            Some(
                "Provide a command or `( ... )` block to execute when the `IF` condition holds."
                    .to_owned(),
            ),
        );
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            children,
        );
    }

    if let Some(else_node) = try_parse_parenthesized_if_else(
        input,
        &mut children,
        cur,
        end,
        cond_end_off,
        fallback_offset,
    ) {
        return else_node;
    }

    if let Some(dangling_else_span) = find_top_level_else_keyword_span(input.chars, cur, end) {
        input.record_misuse(
            dangling_else_span,
            ProbableMisuseKind::UnparenthesizedElseBranch {
                span: dangling_else_span,
            },
            "`ELSE` in an unparenthesized `IF` branch is swallowed as arguments to the `then` command."
                .to_owned(),
            "Wrap the `then` branch in parentheses: `IF cond (cmd1) ELSE (cmd2)`.".to_owned(),
            None,
        );
    }
    let then_node = parse_command_expr_slice_cst(input, cur, end, cond_end_off);
    let kind = if then_node.kind == SyntaxKind::ErrorNode {
        SyntaxKind::ErrorNode
    } else {
        SyntaxKind::IfStatement
    };
    children.push(CstElement::Node(then_node));
    CstNode::from_children(kind, input.source_id, fallback_offset, children)
}

/// Checks whether the `then` branch at `cur` is a `( ... )` block followed by `ELSE`, and parses both.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `children` - `IF` header children.
/// * `cur` - Start of `then` branch.
/// * `end` - Exclusive end index.
/// * `cond_end_off` - End [`ByteOffset`] of `IfConditionNode`.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `Some(CstNode)` if `( ... ) ELSE ...` matched, else `None`.
fn try_parse_parenthesized_if_else(
    input: &mut CstParserState<'_>,
    children: &mut Vec<CstElement>,
    cur: usize,
    end: usize,
    cond_end_off: ByteOffset,
    fallback_offset: ByteOffset,
) -> Option<CstNode> {
    let skip_at = input
        .chars
        .get(cur..end)
        .unwrap_or(&[])
        .iter()
        .take_while(|sc| sc.is_raw('@'))
        .count();
    let probe_at = cur.saturating_add(skip_at);
    let close_idx = input
        .chars
        .get(probe_at)
        .filter(|c| c.is_raw('(') && !is_echo_open_paren_at(input.chars, probe_at))
        .and_then(|_| find_matching_close_paren_in_slice(input.chars, probe_at, end))?;

    let mut after_block = close_idx.saturating_add(1);
    let mut then_redir_end = after_block;
    loop {
        let mut tmp_ws = Vec::new();
        let ws_cur =
            consume_horizontal_trivia(input, after_block, IncludeCommandDelimiters, &mut tmp_ws);
        if let Some((_, next_r)) = probe_redirection_span(input, ws_cur, end) {
            after_block = next_r;
            then_redir_end = next_r;
        } else {
            after_block = ws_cur;
            break;
        }
    }

    if !is_keyword_at(input.chars, after_block, end, "ELSE") {
        return None;
    }

    let then_node = parse_command_expr_slice_cst(input, cur, then_redir_end, cond_end_off);
    let then_is_err = then_node.kind == SyntaxKind::ErrorNode;
    children.push(CstElement::Node(then_node));
    consume_horizontal_trivia(input, then_redir_end, IncludeCommandDelimiters, children);

    let else_kw_end = after_block.saturating_add(4);
    let else_kw_tok = slice_to_token(
        input.source_id,
        input.chars,
        after_block,
        else_kw_end,
        SyntaxKind::Keyword,
    );
    let else_kw_span = else_kw_tok.span;
    let mut else_children = vec![CstElement::Token(else_kw_tok)];
    let else_body_start = consume_horizontal_trivia(
        input,
        else_kw_end,
        IncludeCommandDelimiters,
        &mut else_children,
    );

    if !slice_has_non_trivia(input.chars, else_body_start, end) {
        let err_span = input.span_at(else_body_start, else_kw_span.end);
        input
            .farthest
            .record_failure(else_body_start, err_span, PegExpected::ElseBranch);
        input.record_syntax_error(
            err_span,
            "The syntax of the command is incorrect. Missing command after `ELSE`.".to_owned(),
            vec![PegExpected::ElseBranch],
            Some("Provide a command or `( ... )` block after `ELSE`.".to_owned()),
        );
        let else_node = CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            else_kw_span.start,
            else_children,
        );
        children.push(CstElement::Node(else_node));
        return Some(CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            core::mem::take(children),
        ));
    }

    let else_body_node =
        parse_command_expr_slice_cst(input, else_body_start, end, else_kw_span.end);
    let has_err = then_is_err || else_body_node.kind == SyntaxKind::ErrorNode;
    else_children.push(CstElement::Node(else_body_node));
    let else_clause = CstNode::from_children(
        SyntaxKind::ElseClauseNode,
        input.source_id,
        else_kw_span.start,
        else_children,
    );
    children.push(CstElement::Node(else_clause));
    let kind = if has_err {
        SyntaxKind::ErrorNode
    } else {
        SyntaxKind::IfStatement
    };
    Some(CstNode::from_children(
        kind,
        input.source_id,
        fallback_offset,
        core::mem::take(children),
    ))
}

/// Non-mutating lookahead for a redirection clause at `cursor` (used when locating `ELSE` after `)`).
///
/// # Arguments
/// * `input` - Immutable [`CstParserState`].
/// * `cursor` - Candidate index.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `Some((cursor, next_idx))` if a redirection clause starts at `cursor`, else `None`.
fn probe_redirection_span(
    input: &CstParserState<'_>,
    cursor: usize,
    end: usize,
) -> Option<(usize, usize)> {
    let mut scratch = CstParserState::new(
        input.source_id,
        input.chars,
        input.exec_context,
        RecoveryMode::Recovering,
        ByteOffset(0),
    );
    parse_redirection_node(&mut scratch, cursor, end).map(|(_, next)| (cursor, next))
}

/// Checks if a top-level `ELSE` word appears in `chars[start..end]` and returns its [`Span`].
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `start` - Start index.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `Some(Span)` of the unparenthesized `ELSE` keyword if present.
#[must_use]
fn find_top_level_else_keyword_span(
    chars: &[SpannedChar],
    start: usize,
    end: usize,
) -> Option<Span> {
    let mut quote = QuoteMode::Unquoted;
    let mut depth: i32 = 0;
    let mut i = start;
    while let Some(sc) = chars.get(i).filter(|_| i < end) {
        if let Some(cont_end) = is_caret_line_continuation_at(chars, i) {
            i = cont_end.saturating_add(1);
            continue;
        }
        if sc.is_raw('"') {
            quote = quote.toggle();
            i = i.saturating_add(1);
            continue;
        }
        if matches!(quote, QuoteMode::Unquoted) {
            if sc.is_raw('^') {
                i = i.saturating_add(2);
                continue;
            }
            if sc.is_raw('(') && !is_echo_open_paren_at(chars, i) {
                depth = depth.saturating_add(1);
            } else if sc.is_raw(')') {
                depth = depth.saturating_sub(1);
            } else if depth == 0 {
                let at_word_start = chars
                    .get(i.saturating_sub(1))
                    .is_some_and(|p| is_cmd_delimiter(p.ch));
                if at_word_start && is_keyword_at(chars, i, end, "ELSE") {
                    let tok = slice_to_token(
                        sc.span.source_id,
                        chars,
                        i,
                        i.saturating_add(4),
                        SyntaxKind::Keyword,
                    );
                    return Some(tok.span);
                }
            }
        }
        i = i.saturating_add(1);
    }
    None
}

/// Parses an `IfConditionNode` at `cursor` within `input.chars[cursor..end]`.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cursor` - Start of condition.
/// * `end` - Exclusive end index.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `Some((cond_node, next_cursor, is_valid))` or `None` if empty.
fn parse_if_condition_node_cst(
    input: &mut CstParserState<'_>,
    cursor: usize,
    end: usize,
    fallback_offset: ByteOffset,
) -> Option<(CstNode, usize, bool)> {
    if let Some(res) = try_parse_parenthesized_if_condition_cst(input, cursor, end, fallback_offset)
    {
        return Some(res);
    }
    if let Some(res) = try_parse_unary_if_condition_cst(input, cursor, end, fallback_offset) {
        return Some(res);
    }

    let mut cond_children = Vec::new();
    let lhs_eq_mode = if input.recovery_mode.is_recovering() {
        WordEqualsMode::SplitOnAnyEquals
    } else {
        WordEqualsMode::StopAtDoubleEquals
    };
    let (lhs_node, after_lhs) =
        parse_word_node(input, cursor, end, lhs_eq_mode, WordParenScope::Normal)?;
    let lhs_end_off = lhs_node.span.end;
    cond_children.push(CstElement::Node(lhs_node));
    let op_cur = consume_horizontal_trivia(input, after_lhs, SpacesAndTabsOnly, &mut cond_children);

    let Some((op_tok, after_op)) = match_if_comparison_op_cst(input, op_cur, end) else {
        let err_span = input.span_at(op_cur, lhs_end_off);
        input
            .farthest
            .record_failure(op_cur, err_span, PegExpected::ComparisonOperator);
        let unexp = slice_first_word_text(input.chars, op_cur, end);
        let msg = if unexp.is_empty() {
            "The syntax of the command is incorrect. Expected comparison operator in `IF`."
                .to_owned()
        } else {
            format!("{unexp} was unexpected at this time.")
        };
        input.record_syntax_error(
            err_span,
            msg,
            vec![PegExpected::ComparisonOperator],
            Some("Use `==`, `EQU`, `NEQ`, `LSS`, `LEQ`, `GTR`, or `GEQ`.".to_owned()),
        );
        let node = CstNode::from_children(
            SyntaxKind::IfConditionNode,
            input.source_id,
            fallback_offset,
            cond_children,
        );
        return Some((node, op_cur, false));
    };

    let op_end_off = op_tok.span.end;
    cond_children.push(CstElement::Token(op_tok));
    let rhs_cur = consume_horizontal_trivia(
        input,
        after_op,
        IncludeCommandDelimiters,
        &mut cond_children,
    );
    let Some((rhs_el, after_rhs)) = parse_word_node(
        input,
        rhs_cur,
        end,
        WordEqualsMode::SplitOnAnyEquals,
        WordParenScope::Normal,
    ) else {
        let err_span = input.span_at(rhs_cur, op_end_off);
        input
            .farthest
            .record_failure(rhs_cur, err_span, PegExpected::ComparisonOperand);
        input.record_syntax_error(
            err_span,
            "The syntax of the command is incorrect. Missing right-hand operand in `IF` comparison."
                .to_owned(),
            vec![PegExpected::ComparisonOperand],
            Some("Provide a right-hand value after the comparison operator.".to_owned()),
        );
        let node = CstNode::from_children(
            SyntaxKind::IfConditionNode,
            input.source_id,
            fallback_offset,
            cond_children,
        );
        return Some((node, rhs_cur, false));
    };

    cond_children.push(CstElement::Node(rhs_el));
    let node = CstNode::from_children(
        SyntaxKind::IfConditionNode,
        input.source_id,
        fallback_offset,
        cond_children,
    );
    Some((node, after_rhs, true))
}

/// Attempts to parse a C-style parenthesized `IF` condition `( ... )` in recovering mode.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cursor` - Candidate `(` index.
/// * `end` - Exclusive end index.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `Some((cond_node, next_cursor, true))` if a parenthesized condition matched, else `None`.
fn try_parse_parenthesized_if_condition_cst(
    input: &mut CstParserState<'_>,
    cursor: usize,
    end: usize,
    fallback_offset: ByteOffset,
) -> Option<(CstNode, usize, bool)> {
    if !input.recovery_mode.is_recovering() {
        return None;
    }
    let close_idx = input
        .chars
        .get(cursor)
        .filter(|c| c.is_raw('('))
        .and_then(|_| find_matching_close_paren_in_slice(input.chars, cursor, end))?;

    let open_span = input.span_at(cursor, fallback_offset);
    let close_span = input.span_at(close_idx, open_span.end);
    let full_paren_span = open_span.merge(close_span);
    let mut inner_children = vec![CstElement::Token(CstToken::new(
        SyntaxKind::OpenParen,
        "(".to_owned(),
        open_span,
    ))];
    let inner_cur = consume_horizontal_trivia(
        input,
        cursor.saturating_add(1),
        IncludeCommandDelimiters,
        &mut inner_children,
    );
    if let Some((inner_cond, after_inner, true)) =
        parse_if_condition_node_cst(input, inner_cur, close_idx, open_span.end)
    {
        let trail_cur = consume_horizontal_trivia(
            input,
            after_inner,
            IncludeCommandDelimiters,
            &mut inner_children,
        );
        if trail_cur == close_idx {
            let inner_source = inner_cond.to_source_string();
            inner_children.extend(inner_cond.children);
            inner_children.push(CstElement::Token(CstToken::new(
                SyntaxKind::CloseParen,
                ")".to_owned(),
                close_span,
            )));
            input.record_misuse(
                full_paren_span,
                ProbableMisuseKind::ParenthesizedIfCondition {
                    span: full_paren_span,
                },
                "C-style parentheses `( ... )` around an `IF` condition are treated literally by `cmd.exe`."
                    .to_owned(),
                format!("Remove outer parentheses around the condition: `IF {inner_source} ...`."),
                Some((full_paren_span, inner_source)),
            );
            let node = CstNode::from_children(
                SyntaxKind::IfConditionNode,
                input.source_id,
                fallback_offset,
                inner_children,
            );
            return Some((node, close_idx.saturating_add(1), true));
        }
    }
    None
}

/// Attempts to parse a unary `IF` condition (`ERRORLEVEL`, `EXIST`, `DEFINED`, `CMDEXTVERSION`).
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cursor` - Start of condition.
/// * `end` - Exclusive end index.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `Some((cond_node, next_cursor, is_valid))` if a unary keyword matched, else `None`.
fn try_parse_unary_if_condition_cst(
    input: &mut CstParserState<'_>,
    cursor: usize,
    end: usize,
    fallback_offset: ByteOffset,
) -> Option<(CstNode, usize, bool)> {
    for unary_kw in ["ERRORLEVEL", "EXIST", "DEFINED", "CMDEXTVERSION"] {
        if is_keyword_at(input.chars, cursor, end, unary_kw) {
            let mut cond_children = Vec::new();
            let kw_end = cursor.saturating_add(unary_kw.len());
            let kw_tok = slice_to_token(
                input.source_id,
                input.chars,
                cursor,
                kw_end,
                SyntaxKind::Keyword,
            );
            let kw_span = kw_tok.span;
            cond_children.push(CstElement::Token(kw_tok));
            let arg_cur = consume_horizontal_trivia(
                input,
                kw_end,
                IncludeCommandDelimiters,
                &mut cond_children,
            );
            let Some((arg_word, after_arg)) = parse_word_node(
                input,
                arg_cur,
                end,
                WordEqualsMode::SplitOnAnyEquals,
                WordParenScope::Normal,
            ) else {
                let err_span = input.span_at(arg_cur, kw_span.end);
                input
                    .farthest
                    .record_failure(arg_cur, err_span, PegExpected::ComparisonOperand);
                input.record_syntax_error(
                    err_span,
                    format!(
                        "The syntax of the command is incorrect. Missing argument after `{unary_kw}`."
                    ),
                    vec![PegExpected::ComparisonOperand],
                    Some(format!("Provide an operand after `IF {unary_kw}`.")),
                );
                let node = CstNode::from_children(
                    SyntaxKind::IfConditionNode,
                    input.source_id,
                    fallback_offset,
                    cond_children,
                );
                return Some((node, arg_cur, false));
            };
            if unary_kw == "ERRORLEVEL" {
                let raw_arg = arg_word.to_source_string();
                let unquoted = crate::parser::modifiers::strip_command_arg_quotes(&raw_arg);
                let is_int = crate::parser::var_ops::parse_cmd_int(&unquoted)
                    .and_then(|v| i32::try_from(v).ok())
                    .is_some();
                let has_var = raw_arg.contains(['%', '!']);
                let followed_by_eq = input
                    .chars
                    .get(after_arg)
                    .filter(|_| after_arg < end)
                    .is_some_and(|c| c.is_raw('='));
                if (!is_int && !has_var) || followed_by_eq {
                    return None;
                }
            }
            cond_children.push(CstElement::Node(arg_word));
            let node = CstNode::from_children(
                SyntaxKind::IfConditionNode,
                input.source_id,
                fallback_offset,
                cond_children,
            );
            return Some((node, after_arg, true));
        }
    }
    None
}

/// Matches an `IF` comparison operator (`==`, single `=` in recovering mode, or `EQU`..`GEQ`).
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `op_cur` - Candidate operator start index.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `Some((operator_token, next_cursor))` if matched, else `None`.
fn match_if_comparison_op_cst(
    input: &mut CstParserState<'_>,
    op_cur: usize,
    end: usize,
) -> Option<(CstToken, usize)> {
    if let Some((first_eq, second_eq)) = input
        .chars
        .get(op_cur)
        .zip(input.chars.get(op_cur.saturating_add(1)))
        .filter(|(a, b)| op_cur.saturating_add(1) < end && a.is_raw('=') && b.is_raw('='))
    {
        return Some((
            CstToken::new(
                SyntaxKind::OperatorToken,
                "==".to_owned(),
                first_eq.span.merge(second_eq.span),
            ),
            op_cur.saturating_add(2),
        ));
    }
    if input.recovery_mode.is_recovering()
        && let Some(single_eq) = input
            .chars
            .get(..end)
            .and_then(|s| s.get(op_cur))
            .filter(|a| a.is_raw('='))
    {
        let eq_span = single_eq.span;
        input.record_misuse(
            eq_span,
            ProbableMisuseKind::SingleEqualsInIf { span: eq_span },
            "Single `=` is not a valid comparison operator in `IF` statements.".to_owned(),
            "Use `==` for string comparison or `EQU` for numeric/string comparison.".to_owned(),
            Some((eq_span, "==".to_owned())),
        );
        return Some((
            CstToken::new(SyntaxKind::OperatorToken, "=".to_owned(), eq_span),
            op_cur.saturating_add(1),
        ));
    }
    for kw_op in ["EQU", "NEQ", "LSS", "LEQ", "GTR", "GEQ"] {
        if is_keyword_at(input.chars, op_cur, end, kw_op) {
            let op_end = op_cur.saturating_add(3);
            return Some((
                slice_to_token(
                    input.source_id,
                    input.chars,
                    op_cur,
                    op_end,
                    SyntaxKind::Keyword,
                ),
                op_end,
            ));
        }
    }
    None
}

/// Extracts the first plain token starting at `cur` up to `end` for `UnexpectedToken` messages.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `cur` - Start index.
/// * `end` - Exclusive end index.
///
/// # Returns
/// Extracted token text (or empty string).
#[must_use]
fn slice_first_word_text(chars: &[SpannedChar], cur: usize, end: usize) -> String {
    chars
        .get(cur..end)
        .unwrap_or(&[])
        .iter()
        .take_while(|c| !is_cmd_delimiter(c.ch) && !matches!(c.ch, CR_CHAR | LF_CHAR))
        .map(|c| c.ch)
        .collect()
}

/// Parses a `FOR` statement (`FOR [/D | /R [path] | /L | /F ["opts"]] %%I IN (...) DO body`).
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `children` - Leading trivia and `@` tokens.
/// * `for_idx` - Index of `FOR`.
/// * `end` - Exclusive end index.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `ForStatement` or `ErrorNode` [`CstNode`].
pub(super) fn parse_for_statement_cst(
    input: &mut CstParserState<'_>,
    mut children: Vec<CstElement>,
    for_idx: usize,
    end: usize,
    fallback_offset: ByteOffset,
) -> CstNode {
    let for_end = for_idx.saturating_add(3);
    let for_tok = slice_to_token(
        input.source_id,
        input.chars,
        for_idx,
        for_end,
        SyntaxKind::Keyword,
    );
    let init_off = for_tok.span.end;
    children.push(CstElement::Token(for_tok));
    let init_cur =
        consume_horizontal_trivia(input, for_end, IncludeCommandDelimiters, &mut children);

    let Some((after_switches, switch_end_off)) =
        parse_for_switch_and_arg_cst(input, init_cur, end, init_off, &mut children)
    else {
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            children,
        );
    };

    let Some((var_tok, var_char_opt, after_var)) =
        parse_for_header_var_token(input, after_switches, end)
    else {
        let err_span = input.span_at(after_switches, switch_end_off);
        input
            .farthest
            .record_failure(after_switches, err_span, PegExpected::ForVariable);
        let unexp = slice_first_word_text(input.chars, after_switches, end);
        let msg = if unexp.is_empty() {
            "The syntax of the command is incorrect. Expected `FOR` loop variable.".to_owned()
        } else {
            format!("{unexp} was unexpected at this time.")
        };
        input.record_syntax_error(
            err_span,
            msg,
            vec![PegExpected::ForVariable],
            Some(
                "Specify a single-letter loop variable such as `%%I` (in batch files) or `%I` (in interactive REPL)."
                    .to_owned(),
            ),
        );
        append_comment_or_raw_with_continuations(
            input,
            after_switches,
            end,
            SyntaxKind::LiteralToken,
            &mut children,
        );
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            children,
        );
    };
    let var_end_off = var_tok.span.end;
    children.push(CstElement::Token(var_tok));
    let Some(var_ch) = var_char_opt else {
        append_comment_or_raw_with_continuations(
            input,
            after_var,
            end,
            SyntaxKind::LiteralToken,
            &mut children,
        );
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            children,
        );
    };
    let after_var_trivia =
        consume_horizontal_trivia(input, after_var, IncludeCommandDelimiters, &mut children);

    let Some((after_in, in_end_off)) =
        parse_for_in_keyword_cst(input, after_var_trivia, end, var_end_off, &mut children)
    else {
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            children,
        );
    };

    parse_for_set_and_body_cst(
        input,
        children,
        var_ch,
        after_in,
        end,
        in_end_off,
        fallback_offset,
    )
}

/// Parses an optional `FOR` switch (`/D`, `/L`, `/R [path]`, or `/F ["opts"]`) and its argument.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cur` - Candidate switch index.
/// * `end` - Exclusive end index.
/// * `last_off` - End [`ByteOffset`] of the preceding token.
/// * `children` - Destination `FOR` header child vector.
///
/// # Returns
/// `Some((next_cursor, next_end_offset))` on valid or absent switch, or `None` on invalid switch.
fn parse_for_switch_and_arg_cst(
    input: &mut CstParserState<'_>,
    cur: usize,
    end: usize,
    last_off: ByteOffset,
    children: &mut Vec<CstElement>,
) -> Option<(usize, ByteOffset)> {
    let Some((sw_el, after_sw)) = input
        .chars
        .get(cur)
        .filter(|c| c.is_raw('/'))
        .and_then(|_| {
            parse_word_node(
                input,
                cur,
                end,
                WordEqualsMode::SplitOnAnyEquals,
                WordParenScope::Normal,
            )
        })
    else {
        return Some((cur, last_off));
    };

    let sw_text = sw_el.to_source_string();
    let sw_span = sw_el.span;
    let mut next_off = sw_span.end;
    let sw_upper = sw_text.to_ascii_uppercase();
    children.push(CstElement::Token(CstToken::new(
        SyntaxKind::SwitchToken,
        sw_text.clone(),
        sw_span,
    )));
    let mut next_cur =
        consume_horizontal_trivia(input, after_sw, IncludeCommandDelimiters, children);

    if sw_upper == "/R" {
        if let Some((rp_el, after_rp)) = input
            .chars
            .get(next_cur)
            .filter(|c| !c.is_raw('%'))
            .and_then(|_| {
                parse_word_node(
                    input,
                    next_cur,
                    end,
                    WordEqualsMode::SplitOnAnyEquals,
                    WordParenScope::Normal,
                )
            })
        {
            next_off = rp_el.span.end;
            children.push(CstElement::Node(rp_el));
            next_cur =
                consume_horizontal_trivia(input, after_rp, IncludeCommandDelimiters, children);
        }
    } else if sw_upper.starts_with("/F") {
        let inline_opts = sw_text.get(2..).unwrap_or("");
        if let Some((opt_el, after_opt)) = input
            .chars
            .get(next_cur)
            .filter(|c| inline_opts.is_empty() && !c.is_raw('%'))
            .and_then(|_| {
                parse_word_node(
                    input,
                    next_cur,
                    end,
                    WordEqualsMode::SplitOnAnyEquals,
                    WordParenScope::Normal,
                )
            })
        {
            next_off = opt_el.span.end;
            children.push(CstElement::Node(opt_el));
            next_cur =
                consume_horizontal_trivia(input, after_opt, IncludeCommandDelimiters, children);
        }
    } else if sw_upper != "/D" && sw_upper != "/L" {
        input.record_syntax_error(
            sw_span,
            format!("Invalid switch - {sw_text}"),
            vec![PegExpected::ForVariable],
            Some("Valid `FOR` switches are `/D`, `/R`, `/L`, and `/F`.".to_owned()),
        );
        append_comment_or_raw_with_continuations(
            input,
            next_cur,
            end,
            SyntaxKind::LiteralToken,
            children,
        );
        return None;
    }

    Some((next_cur, next_off))
}

/// Parses the `IN` keyword (or recovers from a missing `IN` before `(`) in a `FOR` header.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cur` - Candidate `IN` index.
/// * `end` - Exclusive end index.
/// * `last_off` - End [`ByteOffset`] of the preceding token.
/// * `children` - Destination `FOR` header child vector.
///
/// # Returns
/// `Some((next_cursor, next_end_offset))` if matched or recovered, or `None` on fatal syntax error.
fn parse_for_in_keyword_cst(
    input: &mut CstParserState<'_>,
    cur: usize,
    end: usize,
    last_off: ByteOffset,
    children: &mut Vec<CstElement>,
) -> Option<(usize, ByteOffset)> {
    if is_keyword_at(input.chars, cur, end, "IN") {
        let in_end = cur.saturating_add(2);
        let in_tok = slice_to_token(
            input.source_id,
            input.chars,
            cur,
            in_end,
            SyntaxKind::Keyword,
        );
        let next_off = in_tok.span.end;
        children.push(CstElement::Token(in_tok));
        let next_cur = consume_horizontal_trivia(input, in_end, IncludeCommandDelimiters, children);
        Some((next_cur, next_off))
    } else if input.recovery_mode.is_recovering()
        && input.chars.get(cur).is_some_and(|c| c.is_raw('('))
    {
        let open_span = input.span_at(cur, last_off);
        let insert_span = Span::new(input.source_id, open_span.start, open_span.start);
        input.record_misuse(
            open_span,
            ProbableMisuseKind::MissingInKeywordInFor { span: open_span },
            "Missing `IN` keyword before `(...)` set in `FOR` loop.".to_owned(),
            "Insert `IN ` before the parenthesized set: `FOR %%I IN (...) DO ...`.".to_owned(),
            Some((insert_span, "IN ".to_owned())),
        );
        Some((cur, last_off))
    } else {
        let err_span = input.span_at(cur, last_off);
        input
            .farthest
            .record_failure(cur, err_span, PegExpected::InKeyword);
        let unexp = slice_first_word_text(input.chars, cur, end);
        let msg = if unexp.is_empty() {
            "`IN` was expected at this time in `FOR` loop.".to_owned()
        } else {
            format!("{unexp} was unexpected at this time.")
        };
        input.record_syntax_error(
            err_span,
            msg,
            vec![PegExpected::InKeyword],
            Some("Follow the `FOR` variable with `IN (set) DO command`.".to_owned()),
        );
        append_comment_or_raw_with_continuations(
            input,
            cur,
            end,
            SyntaxKind::LiteralToken,
            children,
        );
        None
    }
}

/// Parses `(` + `ForSetNode` + `)` + `DO` + loop body of a `FOR` statement.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `children` - Accumulated `FOR` header children.
/// * `var_ch` - Bound loop variable character.
/// * `cur` - Cursor positioned at expected `(`.
/// * `end` - Exclusive end index.
/// * `last_off` - Previous token's end [`ByteOffset`].
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `ForStatement` or `ErrorNode` [`CstNode`].
fn parse_for_set_and_body_cst(
    input: &mut CstParserState<'_>,
    mut children: Vec<CstElement>,
    var_ch: char,
    cur: usize,
    end: usize,
    last_off: ByteOffset,
    fallback_offset: ByteOffset,
) -> CstNode {
    let Some((after_set, set_end_off)) =
        parse_for_open_set_cst(input, cur, end, last_off, &mut children)
    else {
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            children,
        );
    };
    let Some((body_start, do_end_off)) =
        parse_for_do_keyword_cst(input, after_set, end, set_end_off, &mut children)
    else {
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            children,
        );
    };

    let prev_active = input.active_for_vars.clone();
    input.active_for_vars.insert(var_ch);
    let body_node = parse_command_expr_slice_cst(input, body_start, end, do_end_off);
    input.active_for_vars = prev_active;
    let kind = if body_node.kind == SyntaxKind::ErrorNode {
        SyntaxKind::ErrorNode
    } else {
        SyntaxKind::ForStatement
    };
    children.push(CstElement::Node(body_node));
    CstNode::from_children(kind, input.source_id, fallback_offset, children)
}

/// Parses the parenthesized `( ... )` set node in a `FOR` loop and trailing horizontal trivia.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cur` - Cursor positioned at expected `(`.
/// * `end` - Exclusive end index.
/// * `last_off` - End [`ByteOffset`] of the preceding token.
/// * `children` - Destination `FOR` statement child vector.
///
/// # Returns
/// `Some((next_cursor, set_end_offset))` on matched `( ... )`, or `None` on missing or unclosed `(`.
fn parse_for_open_set_cst(
    input: &mut CstParserState<'_>,
    cur: usize,
    end: usize,
    last_off: ByteOffset,
    children: &mut Vec<CstElement>,
) -> Option<(usize, ByteOffset)> {
    let Some(open_sc) = input.chars.get(cur).filter(|_| cur < end) else {
        let err_span = input.span_at(cur, last_off);
        input
            .farthest
            .record_failure(cur, err_span, PegExpected::ForSetOpenParen);
        input.record_syntax_error(
            err_span,
            "The syntax of the command is incorrect. Expected `(` after `IN`.".to_owned(),
            vec![PegExpected::ForSetOpenParen],
            Some("Enclose the `FOR` set in parentheses: `IN (item1 item2)`.".to_owned()),
        );
        return None;
    };
    if !open_sc.is_raw('(') {
        let err_span = open_sc.span;
        input
            .farthest
            .record_failure(cur, err_span, PegExpected::ForSetOpenParen);
        input.record_syntax_error(
            err_span,
            format!("{} was unexpected at this time.", open_sc.ch),
            vec![PegExpected::ForSetOpenParen],
            Some("Enclose the `FOR` set in parentheses: `IN (item1 item2)`.".to_owned()),
        );
        append_comment_or_raw_with_continuations(
            input,
            cur,
            end,
            SyntaxKind::LiteralToken,
            children,
        );
        return None;
    }

    let open_span = open_sc.span;
    let Some(set_close_idx) = find_matching_close_paren_in_slice(input.chars, cur, end) else {
        input
            .farthest
            .record_failure(cur, open_span, PegExpected::ForSetCloseParen);
        input.record_syntax_error(
            open_span,
            "Unclosed `(` in `FOR` loop set; expected matching `)`.".to_owned(),
            vec![PegExpected::ForSetCloseParen],
            Some("Close the `FOR` set with `)` followed by `DO command`.".to_owned()),
        );
        let set_node = parse_for_set_node_cst(input, cur, end, None, open_span.start);
        children.push(CstElement::Node(set_node));
        return None;
    };

    let set_node = parse_for_set_node_cst(
        input,
        cur,
        set_close_idx,
        Some(set_close_idx),
        open_span.start,
    );
    let next_off = set_node.span.end;
    children.push(CstElement::Node(set_node));
    let next_cur = consume_horizontal_trivia(
        input,
        set_close_idx.saturating_add(1),
        IncludeCommandDelimiters,
        children,
    );
    Some((next_cur, next_off))
}

/// Parses the `DO` keyword (or recovers from missing `DO` in recovering mode) after a `FOR` set.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cur` - Candidate `DO` index.
/// * `end` - Exclusive end index.
/// * `last_off` - End [`ByteOffset`] of the `ForSetNode`.
/// * `children` - Destination `FOR` statement child vector.
///
/// # Returns
/// `Some((body_start_cursor, do_end_offset))` if valid or recovered, or `None` on syntax error.
fn parse_for_do_keyword_cst(
    input: &mut CstParserState<'_>,
    cur: usize,
    end: usize,
    last_off: ByteOffset,
    children: &mut Vec<CstElement>,
) -> Option<(usize, ByteOffset)> {
    if is_keyword_at(input.chars, cur, end, "DO") {
        let do_end = cur.saturating_add(2);
        let do_tok = slice_to_token(
            input.source_id,
            input.chars,
            cur,
            do_end,
            SyntaxKind::Keyword,
        );
        let next_off = do_tok.span.end;
        children.push(CstElement::Token(do_tok));
        let next_cur = consume_horizontal_trivia(input, do_end, IncludeCommandDelimiters, children);
        if !slice_has_non_trivia(input.chars, next_cur, end) {
            let err_span = input.span_at(next_cur, next_off);
            input
                .farthest
                .record_failure(next_cur, err_span, PegExpected::ForBodyBranch);
            input.record_syntax_error(
                err_span,
                "The syntax of the command is incorrect. Missing command after `DO`.".to_owned(),
                vec![PegExpected::ForBodyBranch],
                Some("Provide a command or `( ... )` block after `DO`.".to_owned()),
            );
            return None;
        }
        Some((next_cur, next_off))
    } else if input.recovery_mode.is_recovering() && slice_has_non_trivia(input.chars, cur, end) {
        let cmd_span = input.span_at(cur, last_off);
        let insert_span = Span::new(input.source_id, cmd_span.start, cmd_span.start);
        input.record_misuse(
            cmd_span,
            ProbableMisuseKind::MissingDoKeywordInFor { span: cmd_span },
            "Missing `DO` keyword after `(...)` set in `FOR` loop.".to_owned(),
            "Insert `DO ` before the loop body command: `FOR %%I IN (...) DO command`.".to_owned(),
            Some((insert_span, "DO ".to_owned())),
        );
        Some((cur, last_off))
    } else {
        let err_span = input.span_at(cur, last_off);
        input
            .farthest
            .record_failure(cur, err_span, PegExpected::DoKeyword);
        let unexp = slice_first_word_text(input.chars, cur, end);
        let msg = if unexp.is_empty() {
            "The syntax of the command is incorrect. Expected `DO` after `FOR` set.".to_owned()
        } else {
            format!("{unexp} was unexpected at this time.")
        };
        input.record_syntax_error(
            err_span,
            msg,
            vec![PegExpected::DoKeyword],
            Some("Follow the `FOR (...)` set with `DO command`.".to_owned()),
        );
        append_comment_or_raw_with_continuations(
            input,
            cur,
            end,
            SyntaxKind::LiteralToken,
            children,
        );
        None
    }
}

/// Parses the loop variable declaration token in a `FOR` header (`%%I` or `%I`).
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cursor` - Candidate `%` index.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `Some((var_token, valid_var_char_opt, next_cursor))` if starting with `%`, else `None`.
fn parse_for_header_var_token(
    input: &mut CstParserState<'_>,
    cursor: usize,
    end: usize,
) -> Option<(CstToken, Option<char>, usize)> {
    if !input.chars.get(cursor).is_some_and(|c| c.is_raw('%')) {
        return None;
    }
    let mut tok_end = cursor;
    while let Some(c) = input.chars.get(..end).and_then(|s| s.get(tok_end)) {
        if is_cmd_delimiter(c.ch) || matches!(c.ch, '(' | ')') {
            break;
        }
        tok_end = tok_end.saturating_add(1);
    }
    let tok = slice_to_token(
        input.source_id,
        input.chars,
        cursor,
        tok_end,
        SyntaxKind::ForVarToken,
    );
    let raw_text = tok.text.clone();
    let pct_count = raw_text.chars().take_while(|&c| c == '%').count();
    let after_pct: String = raw_text.chars().skip(pct_count).collect();
    let Some(token_arity) =
        PercentArity::from_percent_count(pct_count).filter(|_| !after_pct.is_empty())
    else {
        input
            .farthest
            .record_failure(cursor, tok.span, PegExpected::ForVariable);
        input.record_syntax_error(
            tok.span,
            format!("{raw_text} was unexpected at this time."),
            vec![PegExpected::ForVariable],
            Some(
                "Use a single letter preceded by `%%` in batch files (e.g. `%%I`) or `%` in REPL (`%I`)."
                    .to_owned(),
            ),
        );
        return Some((tok, None, tok_end));
    };

    let required_arity = PercentArity::for_execution_context(input.exec_context);
    let var_ch = after_pct.chars().next().unwrap_or(' ');
    if after_pct.chars().count() > 1 {
        if input.recovery_mode.is_strict() {
            input.record_syntax_error(
                tok.span,
                format!("{raw_text} was unexpected at this time."),
                vec![PegExpected::ForVariable],
                None,
            );
            return Some((tok, None, tok_end));
        }
        let prefix = required_arity.prefix_str();
        input.record_misuse(
            tok.span,
            ProbableMisuseKind::MultiCharForVariable {
                span: tok.span,
                raw_var: raw_text,
            },
            "`FOR` loop variables must be a single character.".to_owned(),
            format!("Use a single-letter variable such as `{prefix}{var_ch}`."),
            Some((tok.span, format!("{prefix}{var_ch}"))),
        );
        return Some((
            tok,
            ForVarName::from_char(var_ch).map(ForVarName::as_char),
            tok_end,
        ));
    }

    let valid_char_opt = validate_single_char_for_var(
        input,
        cursor,
        tok.span,
        &raw_text,
        var_ch,
        token_arity,
        required_arity,
    );
    Some((tok, valid_char_opt, tok_end))
}

/// Validates a single-character `FOR` variable token (`var_ch`) against `token_arity` and `required_arity`.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `cursor` - Token start index in `input.chars`.
/// * `span` - Source [`Span`] of the variable token.
/// * `raw_text` - Raw variable token text.
/// * `var_ch` - Single loop variable character.
/// * `token_arity` - [`PercentArity`] written in source (`%` vs `%%`).
/// * `required_arity` - [`PercentArity`] required by `input.exec_context`.
///
/// # Returns
/// `Some(char)` if valid (or recovered), else `None`.
fn validate_single_char_for_var(
    input: &mut CstParserState<'_>,
    cursor: usize,
    span: Span,
    raw_text: &str,
    var_ch: char,
    token_arity: PercentArity,
    required_arity: PercentArity,
) -> Option<char> {
    let Some(valid_var) = ForVarName::from_char(var_ch) else {
        input
            .farthest
            .record_failure(cursor, span, PegExpected::ForVariable);
        input.record_syntax_error(
            span,
            format!("{raw_text} was unexpected at this time."),
            vec![PegExpected::ForVariable],
            Some("Use an ASCII letter for the `FOR` variable (e.g. `%%I`).".to_owned()),
        );
        return None;
    };

    if required_arity == PercentArity::DoublePercent
        && token_arity == PercentArity::SinglePercent
        && input.recovery_mode.is_recovering()
    {
        input.record_misuse(
            span,
            ProbableMisuseKind::SinglePercentForVarInBatch {
                span,
                raw_var: raw_text.to_owned(),
            },
            "Single-percent `FOR` variable in a batch file fails at runtime (`cmd.exe` requires `%%`)."
                .to_owned(),
            format!("Double the percent sign to `%%{var_ch}` in `.bat`/`.cmd` files."),
            Some((span, format!("%%{var_ch}"))),
        );
    } else if required_arity == PercentArity::SinglePercent
        && token_arity == PercentArity::DoublePercent
    {
        if input.recovery_mode.is_strict() {
            input.record_syntax_error(
                span,
                format!("{raw_text} was unexpected at this time."),
                vec![PegExpected::ForVariable],
                None,
            );
            return None;
        }
        input.record_misuse(
            span,
            ProbableMisuseKind::DoublePercentForVarInRepl {
                span,
                raw_var: raw_text.to_owned(),
            },
            "Double-percent `FOR` variable in interactive REPL mode fails (`cmd.exe` REPL requires single `%`)."
                .to_owned(),
            format!("Use a single percent sign `%{var_ch}` in interactive REPL mode."),
            Some((span, format!("%{var_ch}"))),
        );
    }
    Some(valid_var.as_char())
}

/// Parses the `( ... )` set node inside a `FOR` loop losslessly.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `open_idx` - Index of `(`.
/// * `inner_end` - Exclusive end of set interior.
/// * `close_idx` - Optional index of `)`.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `ForSetNode` [`CstNode`].
fn parse_for_set_node_cst(
    input: &mut CstParserState<'_>,
    open_idx: usize,
    inner_end: usize,
    close_idx: Option<usize>,
    fallback_offset: ByteOffset,
) -> CstNode {
    let mut children = Vec::new();
    let open_span = input.span_at(open_idx, fallback_offset);
    children.push(CstElement::Token(CstToken::new(
        SyntaxKind::OpenParen,
        "(".to_owned(),
        open_span,
    )));
    let mut cur = open_idx.saturating_add(1);
    while cur < inner_end {
        cur = consume_horizontal_trivia(input, cur, IncludeCommandDelimiters, &mut children);
        if cur >= inner_end {
            break;
        }
        let cur_ch = input.chars.get(cur).map_or('\0', |sc| sc.ch);
        if matches!(cur_ch, CR_CHAR | LF_CHAR) {
            let is_crlf = cur_ch == CR_CHAR
                && input
                    .chars
                    .get(cur.saturating_add(1))
                    .is_some_and(|n| n.ch == LF_CHAR);
            let nl_end = cur
                .saturating_add(if is_crlf { 2 } else { 1 })
                .min(inner_end);
            children.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                cur,
                nl_end,
                SyntaxKind::Newline,
            )));
            cur = nl_end;
            continue;
        }
        if let Some((word_node, next_cur)) = parse_word_node(
            input,
            cur,
            inner_end,
            WordEqualsMode::SplitOnAnyEquals,
            WordParenScope::InsideForSet,
        ) {
            children.push(CstElement::Node(word_node));
            cur = next_cur;
        } else {
            let next = cur.saturating_add(1).min(inner_end);
            children.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                cur,
                next,
                SyntaxKind::LiteralToken,
            )));
            cur = next;
        }
    }
    if let Some(c_idx) = close_idx {
        let close_span = input.span_at(c_idx, open_span.end);
        children.push(CstElement::Token(CstToken::new(
            SyntaxKind::CloseParen,
            ")".to_owned(),
            close_span,
        )));
    }
    CstNode::from_children(
        SyntaxKind::ForSetNode,
        input.source_id,
        fallback_offset,
        children,
    )
}
