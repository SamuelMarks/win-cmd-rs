//! Structural syntax and command normalization CST rewrite pass (`StructuralSyntaxFixPass`).
//!
//! Normalizes probable syntax misuse (`CMD1001`, `CMD1004`, `CMD1005`, `CMD1013`), canonicalizes
//! unquoted `SET VAR=val` assignments (`CMD2004`, `CMD2005`, `CMD2008`) without corrupting `^^`
//! or embedded quotes, upgrades `ECHO %VAR%` -> `ECHO(%VAR%` (`CMD4002`), `CD C:\...` -> `CD /D`
//! (`CMD4001`), bare `.bat` -> `CALL` (`CMD3003`), and gates `EXIT` -> `EXIT /B` (`CMD3004`)
//! behind [`crate::linter::rules::FixApplicability::UnsafeOptIn`].

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::linter::rewriter::{CstRewriteRule, RewriteContext};
use crate::linter::rules::{FixApplicability, RuleId};
use crate::parser::cst::{CstElement, CstNode, CstToken, SyntaxKind};
use crate::span::Span;
use crate::types::TAB_CHAR as TAB;

/// Structural syntax & safe command normalization rewrite pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StructuralSyntaxFixPass;

impl CstRewriteRule for StructuralSyntaxFixPass {
    /// Returns the primary [`RuleId`] (`CMD1013`) of this pass.
    ///
    /// # Returns
    /// `RuleId("CMD1013")`.
    fn rule_id(&self) -> RuleId {
        RuleId::new("CMD1013")
    }

    /// Returns the static pass name.
    ///
    /// # Returns
    /// `"StructuralSyntaxFixPass"`.
    fn name(&self) -> &'static str {
        "StructuralSyntaxFixPass"
    }

    /// Transforms structural misuse and unsafe-syntax idioms across `root`.
    ///
    /// # Arguments
    /// * `root` - Script root [`CstNode`].
    /// * `ctx` - Mutable [`RewriteContext`].
    ///
    /// # Returns
    /// Rewritten [`CstNode`].
    fn rewrite_script(&self, root: &CstNode, ctx: &mut RewriteContext) -> CstNode {
        rewrite_structural_node(root, ctx)
    }
}

/// Recursively applies structural fixes to `node`.
///
/// # Arguments
/// * `node` - Current [`CstNode`].
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_structural_node(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let mut new_children: Vec<CstElement> = Vec::with_capacity(node.children.len());

    let entering_block = node.kind == SyntaxKind::CompoundBlock;
    if entering_block {
        ctx.block_depth = ctx.block_depth.saturating_add(1);
    }

    for el in &node.children {
        match el {
            CstElement::Token(tok) => {
                if tok.kind == SyntaxKind::BrokenCaretContinuation
                    && ctx.is_rule_enabled_at(
                        "CMD1004",
                        tok.span,
                        FixApplicability::RecommendedRepair,
                    )
                {
                    ctx.record_edit(
                        RuleId::new("CMD1004"),
                        "Strip trailing horizontal whitespace after line-continuation `^`",
                        tok.span,
                        tok.text.clone(),
                        "^".to_owned(),
                    );
                    new_children.push(CstElement::Token(CstToken::new(
                        SyntaxKind::LiteralToken,
                        "^".to_owned(),
                        tok.span,
                    )));
                } else {
                    new_children.push(CstElement::Token(tok.clone()));
                }
            }
            CstElement::Node(child) => {
                let rewritten = rewrite_structural_node(child, ctx);
                new_children.push(CstElement::Node(rewritten));
            }
        }
    }

    if entering_block {
        ctx.block_depth = ctx.block_depth.saturating_sub(1);
    }

    let current = CstNode::new(node.kind, node.span, new_children);
    apply_structural_kind_rewrite(current, ctx)
}

/// Dispatches node-level structural rewrites based on `current.kind`.
///
/// # Arguments
/// * `current` - [`CstNode`] with recursively rewritten children.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn apply_structural_kind_rewrite(mut current: CstNode, ctx: &mut RewriteContext) -> CstNode {
    match current.kind {
        SyntaxKind::DoubleColonComment
            if ctx.block_depth > 0
                && ctx.is_rule_enabled_at(
                    "CMD1001",
                    current.span,
                    FixApplicability::SafeSemanticsPreserving,
                ) =>
        {
            current = rewrite_block_double_colon_to_rem(&current, ctx);
        }
        SyntaxKind::IfConditionNode
            if ctx.is_rule_enabled_at(
                "CMD1013",
                current.span,
                FixApplicability::RecommendedRepair,
            ) =>
        {
            current = rewrite_if_condition_misuse(&current, ctx);
        }
        SyntaxKind::IfStatement
            if ctx.is_rule_enabled_at(
                "CMD1005",
                current.span,
                FixApplicability::RecommendedRepair,
            ) =>
        {
            current = rewrite_if_unparenthesized_else(&current, ctx);
        }
        SyntaxKind::ForStatement
            if ctx.is_rule_enabled_at(
                "CMD1013",
                current.span,
                FixApplicability::RecommendedRepair,
            ) =>
        {
            current = rewrite_for_structural_misuse(&current, ctx);
        }
        SyntaxKind::SimpleCommand => {
            current = rewrite_simple_command_structural(&current, ctx);
        }
        SyntaxKind::Script
        | SyntaxKind::EmptyStatement
        | SyntaxKind::LabelStatement
        | SyntaxKind::DoubleColonComment
        | SyntaxKind::RemStatement
        | SyntaxKind::CompoundBlock
        | SyntaxKind::IfStatement
        | SyntaxKind::IfConditionNode
        | SyntaxKind::ElseClauseNode
        | SyntaxKind::ForStatement
        | SyntaxKind::ForSetNode
        | SyntaxKind::BinaryCommandExpr
        | SyntaxKind::RedirectionNode
        | SyntaxKind::WordNode
        | SyntaxKind::QuotedStringNode
        | SyntaxKind::SetAssignmentNode
        | SyntaxKind::ErrorNode
        | SyntaxKind::Whitespace
        | SyntaxKind::Newline
        | SyntaxKind::CaretLineContinuation
        | SyntaxKind::BrokenCaretContinuation
        | SyntaxKind::BomToken
        | SyntaxKind::AtSign
        | SyntaxKind::Colon
        | SyntaxKind::DoubleColon
        | SyntaxKind::Keyword
        | SyntaxKind::SwitchToken
        | SyntaxKind::OperatorToken
        | SyntaxKind::RedirectOpToken
        | SyntaxKind::OpenParen
        | SyntaxKind::CloseParen
        | SyntaxKind::DoubleQuote
        | SyntaxKind::EchoDelimiterToken
        | SyntaxKind::LiteralToken
        | SyntaxKind::CaretEscapeToken
        | SyntaxKind::EnvVarToken
        | SyntaxKind::DelayedVarToken
        | SyntaxKind::PositionalParamToken
        | SyntaxKind::ForVarToken
        | SyntaxKind::InvalidModifierVarToken
        | SyntaxKind::PercentLiteralToken
        | SyntaxKind::UnclosedVarToken
        | SyntaxKind::CommentTextToken => {}
    }

    current
}

/// `CMD1001`: Rewrites `:: comment` inside a `( ... )` block into `REM comment`.
///
/// # Arguments
/// * `node` - [`SyntaxKind::DoubleColonComment`] node inside a block.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`SyntaxKind::RemStatement`] node.
fn rewrite_block_double_colon_to_rem(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let mut children = Vec::with_capacity(node.children.len().saturating_add(1));
    let before = node.to_source_string();
    for tok in node.child_tokens() {
        if tok.kind == SyntaxKind::DoubleColon {
            children.push(CstElement::Token(CstToken::new(
                SyntaxKind::Keyword,
                "REM".to_owned(),
                tok.span,
            )));
            children.push(CstElement::Token(CstToken::new(
                SyntaxKind::Whitespace,
                " ".to_owned(),
                tok.span,
            )));
        } else if tok.kind == SyntaxKind::CommentTextToken {
            let trimmed = tok.text.strip_prefix(' ').unwrap_or(&tok.text).to_owned();
            children.push(CstElement::Token(CstToken::new(
                SyntaxKind::CommentTextToken,
                trimmed,
                tok.span,
            )));
        } else {
            children.push(CstElement::Token(tok.clone()));
        }
    }
    let out = CstNode::new(SyntaxKind::RemStatement, node.span, children);
    ctx.record_edit(
        RuleId::new("CMD1001"),
        "Replace `::` comment inside parenthesized block with `REM`",
        node.span,
        before,
        out.to_source_string(),
    );
    out
}

/// `CMD1013`: Rewrites `IF (a == b)` (outer parens around condition) and `IF a = b` (single `=`)
/// inside an `IfConditionNode`.
///
/// # Arguments
/// * `node` - [`SyntaxKind::IfConditionNode`] node.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_if_condition_misuse(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let mut children = node.children.clone();
    let before = node.to_source_string();
    let mut changed = false;

    let has_outer_parens = children
        .first()
        .is_some_and(|e| e.kind() == SyntaxKind::OpenParen)
        && children
            .last()
            .is_some_and(|e| e.kind() == SyntaxKind::CloseParen);
    if has_outer_parens {
        children.remove(0);
        children.pop();
        changed = true;
    }

    for el in &mut children {
        if let CstElement::Token(tok) = el
            && tok.kind == SyntaxKind::OperatorToken
            && tok.text == "="
        {
            "==".clone_into(&mut tok.text);
            changed = true;
        }
    }

    let out = CstNode::new(SyntaxKind::IfConditionNode, node.span, children);
    if changed {
        ctx.record_edit(
            RuleId::new("CMD1013"),
            "Fix probable `IF` condition syntax misuse (`==` / remove C-style parens)",
            node.span,
            before,
            out.to_source_string(),
        );
    }
    out
}

/// `CMD1005`: Rewrites `IF cond cmd1 ELSE cmd2` into `IF cond (cmd1) ELSE (cmd2)`.
///
/// # Arguments
/// * `node` - [`SyntaxKind::IfStatement`] node.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_if_unparenthesized_else(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    if node
        .child_nodes()
        .any(|n| n.kind == SyntaxKind::ElseClauseNode)
    {
        return node.clone();
    }
    let Some(then_idx) = node
        .children
        .iter()
        .position(|el| el.kind() == SyntaxKind::SimpleCommand)
    else {
        return node.clone();
    };
    let then_cmd = node
        .children
        .get(then_idx)
        .and_then(CstElement::as_node)
        .unwrap_or(node);

    let Some(else_pos) = then_cmd.children.iter().position(|el| {
        el.as_node().is_some_and(|w| {
            w.kind == SyntaxKind::WordNode
                && !w
                    .child_nodes()
                    .any(|c| c.kind == SyntaxKind::QuotedStringNode)
                && w.to_source_string().eq_ignore_ascii_case("ELSE")
        })
    }) else {
        return node.clone();
    };

    let before_if = node.to_source_string();
    let then_part_slice = then_cmd.children.get(..else_pos).unwrap_or(&[]);
    let else_part_slice = then_cmd
        .children
        .get(else_pos.saturating_add(1)..)
        .unwrap_or(&[]);

    let then_str: String = then_part_slice
        .iter()
        .map(CstElement::to_source_string)
        .collect::<String>()
        .trim_end()
        .to_owned();

    let else_str: String = else_part_slice
        .iter()
        .filter(|e| e.kind() != SyntaxKind::Newline)
        .map(CstElement::to_source_string)
        .collect::<String>()
        .trim()
        .to_owned();

    if then_str.is_empty() || else_str.is_empty() {
        return node.clone();
    }

    let mut new_if_children: Vec<CstElement> =
        node.children.get(..then_idx).unwrap_or(&[]).to_vec();
    let replacement_tail = format!("({then_str}) ELSE ({else_str})");
    new_if_children.push(CstElement::Token(CstToken::new(
        SyntaxKind::LiteralToken,
        replacement_tail,
        then_cmd.span,
    )));
    for after_el in node
        .children
        .get(then_idx.saturating_add(1)..)
        .unwrap_or(&[])
    {
        new_if_children.push(after_el.clone());
    }

    let out = CstNode::new(SyntaxKind::IfStatement, node.span, new_if_children);
    ctx.record_edit(
        RuleId::new("CMD1005"),
        "Wrap unparenthesized `IF ... ELSE ...` branches in parentheses",
        node.span,
        before_if,
        out.to_source_string(),
    );
    out
}

/// `CMD1013`: Inserts missing `IN` or `DO` keywords and fixes multi-character `FOR` variables.
///
/// # Arguments
/// * `node` - [`SyntaxKind::ForStatement`] node.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_for_structural_misuse(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let before = node.to_source_string();
    let mut children = Vec::with_capacity(node.children.len().saturating_add(4));
    let mut changed = false;

    let has_in_kw = node
        .child_tokens()
        .any(|t| t.kind == SyntaxKind::Keyword && t.text.eq_ignore_ascii_case("IN"));
    let has_do_kw = node
        .child_tokens()
        .any(|t| t.kind == SyntaxKind::Keyword && t.text.eq_ignore_ascii_case("DO"));

    let mut seen_for_set = false;
    let mut inserted_do = false;

    for el in &node.children {
        if let CstElement::Token(tok) = el
            && tok.kind == SyntaxKind::ForVarToken
        {
            let pct_cnt = tok.text.chars().take_while(|&c| c == '%').count();
            let rest: String = tok.text.chars().skip(pct_cnt).collect();
            if rest.chars().count() > 1 {
                let first_ch = rest.chars().next().unwrap_or('i');
                let prefix = if ctx.exec_context.is_batch_file() {
                    "%%"
                } else {
                    "%"
                };
                children.push(CstElement::Token(CstToken::new(
                    SyntaxKind::ForVarToken,
                    format!("{prefix}{first_ch}"),
                    tok.span,
                )));
                changed = true;
                continue;
            }
        }

        if el.kind() == SyntaxKind::ForSetNode && !has_in_kw {
            let span = el.span();
            children.push(CstElement::Token(CstToken::new(
                SyntaxKind::Keyword,
                "IN".to_owned(),
                span,
            )));
            children.push(CstElement::Token(CstToken::new(
                SyntaxKind::Whitespace,
                " ".to_owned(),
                span,
            )));
            changed = true;
        }

        if el.kind() == SyntaxKind::ForSetNode {
            seen_for_set = true;
            children.push(el.clone());
            continue;
        }

        if seen_for_set && !has_do_kw && !inserted_do && matches!(el, CstElement::Node(_)) {
            let span = el.span();
            children.push(CstElement::Token(CstToken::new(
                SyntaxKind::Keyword,
                "DO".to_owned(),
                span,
            )));
            children.push(CstElement::Token(CstToken::new(
                SyntaxKind::Whitespace,
                " ".to_owned(),
                span,
            )));
            inserted_do = true;
            changed = true;
        }

        children.push(el.clone());
    }

    let out = CstNode::new(SyntaxKind::ForStatement, node.span, children);
    if changed {
        ctx.record_edit(
            RuleId::new("CMD1013"),
            "Fix probable `FOR` loop syntax misuse (missing `IN`/`DO` or multi-char variable)",
            node.span,
            before,
            out.to_source_string(),
        );
    }
    out
}

/// Applies structural command rewrites on a `SimpleCommand`.
///
/// # Arguments
/// * `node` - [`SyntaxKind::SimpleCommand`] node.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_simple_command_structural(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let Some(prog) = node
        .child_nodes()
        .find(|n| matches!(n.kind, SyntaxKind::WordNode | SyntaxKind::SetAssignmentNode))
    else {
        return node.clone();
    };
    let prog_text = prog.to_source_string();
    let prog_unquoted = prog_text.trim_matches('"');
    let prog_upper = prog_unquoted.to_ascii_uppercase();

    if prog_upper == "SET" {
        return try_rewrite_set_command(node, ctx).unwrap_or_else(|| node.clone());
    }
    if prog_upper == "ECHO"
        && ctx.is_rule_enabled_at("CMD4002", node.span, FixApplicability::RecommendedRepair)
    {
        return try_rewrite_echo_command(node, ctx).unwrap_or_else(|| node.clone());
    }
    if matches!(prog_upper.as_str(), "CD" | "CHDIR")
        && ctx.is_rule_enabled_at("CMD4001", node.span, FixApplicability::RecommendedRepair)
    {
        return try_rewrite_cd_command(node, ctx).unwrap_or_else(|| node.clone());
    }
    if prog_upper == "EXIT"
        && ctx.exec_context.is_batch_file()
        && ctx.is_rule_enabled_at("CMD3004", node.span, FixApplicability::UnsafeOptIn)
    {
        return try_rewrite_exit_command(node, ctx).unwrap_or_else(|| node.clone());
    }

    let prog_lower = prog_unquoted.to_ascii_lowercase();
    if [".bat", ".cmd"]
        .into_iter()
        .any(|ext| prog_lower.ends_with(ext))
        && ctx.is_rule_enabled_at("CMD3003", node.span, FixApplicability::RecommendedRepair)
    {
        return rewrite_bare_batch_call(node, prog.span, ctx);
    }

    node.clone()
}

/// Reconstructs source text of a `CstElement`, unescaping only unquoted `CaretEscapeToken`s (`^X` -> `X`, `^^` -> `^`).
///
/// # Arguments
/// * `el` - CST element inside the right-hand side of an unquoted `SET` assignment.
/// * `out` - Destination string buffer.
fn append_set_unescaped_cst_element(el: &CstElement, out: &mut String) {
    match el {
        CstElement::Token(tok) if tok.kind == SyntaxKind::CaretEscapeToken => {
            out.push_str(tok.text.get(1..).unwrap_or(&tok.text));
        }
        CstElement::Token(tok) => out.push_str(&tok.text),
        CstElement::Node(n) => {
            for child in &n.children {
                append_set_unescaped_cst_element(child, out);
            }
        }
    }
}

/// Normalizes `SET` assignments (`CMD2004`, `CMD2005`, `CMD2008`) without corrupting `^^` or embedded quotes.
///
/// # Arguments
/// * `node` - [`SyntaxKind::SimpleCommand`] representing `SET ...`.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// `Some(CstNode)` if rewritten safely, or `None` if already canonical or containing embedded quotes.
fn try_rewrite_set_command(node: &CstNode, ctx: &mut RewriteContext) -> Option<CstNode> {
    let words: Vec<&CstNode> = node
        .child_nodes()
        .filter(|n| matches!(n.kind, SyntaxKind::WordNode | SyntaxKind::SetAssignmentNode))
        .collect();
    let first_arg = words.get(1)?;
    let first_arg_src = first_arg.to_source_string();
    let first_upper = first_arg_src.trim_matches('"').to_ascii_uppercase();
    if first_upper.starts_with("/A") || first_upper.starts_with("/P") {
        return None;
    }

    if first_arg_src.starts_with('"') && first_arg_src.ends_with('"') && words.len() == 2 {
        return None;
    }

    let prog_pos = node
        .children
        .iter()
        .position(|el| {
            matches!(
                el.kind(),
                SyntaxKind::WordNode | SyntaxKind::SetAssignmentNode
            )
        })
        .unwrap_or(0);

    let mut assign_start = prog_pos.saturating_add(1);
    while node
        .children
        .get(assign_start)
        .is_some_and(|el| el.kind() == SyntaxKind::Whitespace)
    {
        assign_start = assign_start.saturating_add(1);
    }

    let mut assign_end = node.children.len();
    while node
        .children
        .get(assign_end.saturating_sub(1))
        .is_some_and(|el| matches!(el.kind(), SyntaxKind::Newline | SyntaxKind::RedirectionNode))
    {
        assign_end = assign_end.saturating_sub(1);
    }

    let assign_slice = node.children.get(assign_start..assign_end).unwrap_or(&[]);
    let raw_assign: String = assign_slice
        .iter()
        .map(CstElement::to_source_string)
        .collect();
    if !raw_assign.contains('=') || raw_assign.contains('"') {
        return None;
    }

    let mut unescaped_assign = String::with_capacity(raw_assign.len());
    for el in assign_slice {
        append_set_unescaped_cst_element(el, &mut unescaped_assign);
    }
    let (raw_lhs, unescaped_rhs) = unescaped_assign.split_once('=')?;
    let (orig_lhs, orig_rhs) = raw_assign.split_once('=')?;

    let has_space_around_eq = orig_lhs.ends_with([' ', TAB]);
    let has_trailing_ws = orig_rhs.ends_with([' ', TAB]);
    let has_caret_escape = assign_slice.iter().any(|el| match el {
        CstElement::Node(n) => n
            .descendant_tokens()
            .iter()
            .any(|t| t.kind == SyntaxKind::CaretEscapeToken),
        CstElement::Token(t) => t.kind == SyntaxKind::CaretEscapeToken,
    });

    if !has_space_around_eq && !has_trailing_ws && !has_caret_escape {
        return None;
    }

    let clean_lhs = raw_lhs.trim();
    if clean_lhs.is_empty() {
        return None;
    }
    let mut clean_rhs = unescaped_rhs.trim_end_matches([' ', TAB]);
    if has_space_around_eq {
        clean_rhs = clean_rhs.trim_start_matches([' ', TAB]);
    }

    let (code, tier) = if has_space_around_eq {
        ("CMD2005", FixApplicability::RecommendedRepair)
    } else if has_trailing_ws {
        ("CMD2004", FixApplicability::RecommendedRepair)
    } else {
        ("CMD2008", FixApplicability::SafeSemanticsPreserving)
    };
    if !ctx.is_rule_enabled_at(code, node.span, tier) {
        return None;
    }
    let before = node.to_source_string();
    let out = build_quoted_set_command_node(
        node,
        assign_start,
        assign_end,
        first_arg.span,
        format!(r#""{clean_lhs}={clean_rhs}""#),
    );
    ctx.record_edit(
        RuleId::new(code),
        r#"Canonicalize `SET` assignment to quoted `SET "VAR=VALUE"` form"#,
        node.span,
        before,
        out.to_source_string(),
    );
    Some(out)
}

/// Constructs a `SimpleCommand` [`CstNode`] replacing `node.children[assign_start..assign_end]`
/// with a quoted `SetAssignmentNode`.
///
/// # Arguments
/// * `node` - Original `SET` [`CstNode`].
/// * `assign_start` - Start child index of the assignment payload.
/// * `assign_end` - Exclusive end child index of the assignment payload.
/// * `assign_span` - Source [`Span`] for the new assignment node.
/// * `quoted_assign_str` - Canonical `"VAR=value"` text.
///
/// # Returns
/// Rewritten `SimpleCommand` [`CstNode`].
#[must_use]
fn build_quoted_set_command_node(
    node: &CstNode,
    assign_start: usize,
    assign_end: usize,
    assign_span: Span,
    quoted_assign_str: String,
) -> CstNode {
    let mut new_children: Vec<CstElement> =
        node.children.get(..assign_start).unwrap_or(&[]).to_vec();
    let q_node = CstNode::new(
        SyntaxKind::QuotedStringNode,
        assign_span,
        vec![CstElement::Token(CstToken::new(
            SyntaxKind::LiteralToken,
            quoted_assign_str,
            assign_span,
        ))],
    );
    let w_node = CstNode::new(
        SyntaxKind::SetAssignmentNode,
        assign_span,
        vec![CstElement::Node(q_node)],
    );
    new_children.push(CstElement::Node(w_node));
    if node
        .children
        .get(assign_end)
        .is_some_and(|el| el.kind() == SyntaxKind::RedirectionNode)
    {
        new_children.push(CstElement::Token(CstToken::new(
            SyntaxKind::Whitespace,
            " ".to_owned(),
            assign_span,
        )));
    }
    for tail_el in node.children.get(assign_end..).unwrap_or(&[]) {
        new_children.push(tail_el.clone());
    }
    CstNode::new(SyntaxKind::SimpleCommand, node.span, new_children)
}

/// `CMD4002`: Rewrites `ECHO %VAR%` -> `ECHO(%VAR%` when the argument is a single variable/parameter.
///
/// # Arguments
/// * `node` - [`SyntaxKind::SimpleCommand`] representing `ECHO ...`.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// `Some(CstNode)` if rewritten, else `None`.
fn try_rewrite_echo_command(node: &CstNode, ctx: &mut RewriteContext) -> Option<CstNode> {
    let delim_idx = node
        .children
        .iter()
        .position(|el| el.kind() == SyntaxKind::EchoDelimiterToken)
        .unwrap_or(0);
    let delim_tok = node.children.get(delim_idx).and_then(CstElement::as_token);
    if delim_tok.is_none_or(|t| t.text != " ") {
        return None;
    }
    let delim_span = delim_tok.map_or(node.span, |t| t.span);

    let arg_nodes: Vec<&CstNode> = node
        .children
        .get(delim_idx.saturating_add(1)..)
        .unwrap_or(&[])
        .iter()
        .filter_map(CstElement::as_node)
        .filter(|n| n.kind == SyntaxKind::WordNode)
        .collect();
    if arg_nodes.len() != 1 {
        return None;
    }
    let only_arg = arg_nodes.first().copied().unwrap_or(node);
    let only_text = only_arg.to_source_string();
    if matches!(only_text.to_ascii_uppercase().as_str(), "ON" | "OFF") {
        return None;
    }
    let all_vars = only_arg.children.iter().all(|el| {
        matches!(
            el.kind(),
            SyntaxKind::EnvVarToken
                | SyntaxKind::DelayedVarToken
                | SyntaxKind::PositionalParamToken
                | SyntaxKind::ForVarToken
        )
    });
    if !all_vars {
        return None;
    }

    let before = node.to_source_string();
    let new_children: Vec<CstElement> = node
        .children
        .iter()
        .enumerate()
        .map(|(idx, el)| {
            if idx == delim_idx {
                CstElement::Token(CstToken::new(
                    SyntaxKind::EchoDelimiterToken,
                    "(".to_owned(),
                    delim_span,
                ))
            } else {
                el.clone()
            }
        })
        .collect();
    let out = CstNode::new(SyntaxKind::SimpleCommand, node.span, new_children);
    ctx.record_edit(
        RuleId::new("CMD4002"),
        "Use `ECHO(` instead of `ECHO ` for variable expansion",
        node.span,
        before,
        out.to_source_string(),
    );
    Some(out)
}

/// `CMD4001`: Rewrites `CD C:\path` -> `CD /D C:\path` when target starts with a drive letter.
///
/// # Arguments
/// * `node` - [`SyntaxKind::SimpleCommand`] representing `CD ...`.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// `Some(CstNode)` if `/D` was inserted, else `None`.
fn try_rewrite_cd_command(node: &CstNode, ctx: &mut RewriteContext) -> Option<CstNode> {
    let words: Vec<&CstNode> = node
        .child_nodes()
        .filter(|n| n.kind == SyntaxKind::WordNode)
        .collect();
    let target = words.get(1)?;
    if words
        .iter()
        .skip(1)
        .any(|w| w.to_source_string().eq_ignore_ascii_case("/D"))
    {
        return None;
    }
    let target_unquoted = target.to_source_string().trim_matches('"').to_owned();
    let has_drive = target_unquoted
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        && target_unquoted.chars().nth(1) == Some(':');
    if !has_drive {
        return None;
    }

    let prog_idx = node
        .children
        .iter()
        .position(|el| el.kind() == SyntaxKind::WordNode)
        .unwrap_or(0);
    let prog_span = node
        .children
        .get(prog_idx)
        .map_or(node.span, CstElement::span);
    let before = node.to_source_string();

    let mut new_children = Vec::with_capacity(node.children.len().saturating_add(2));
    for (idx, el) in node.children.iter().enumerate() {
        new_children.push(el.clone());
        if idx == prog_idx {
            new_children.push(CstElement::Token(CstToken::new(
                SyntaxKind::Whitespace,
                " ".to_owned(),
                prog_span,
            )));
            new_children.push(CstElement::Token(CstToken::new(
                SyntaxKind::SwitchToken,
                "/D".to_owned(),
                prog_span,
            )));
        }
    }
    let out = CstNode::new(SyntaxKind::SimpleCommand, node.span, new_children);
    ctx.record_edit(
        RuleId::new("CMD4001"),
        "Add `/D` switch to `CD` when changing drive letters",
        node.span,
        before,
        out.to_source_string(),
    );
    Some(out)
}

/// `CMD3004`: Rewrites bare `EXIT` or `EXIT 0` in `BatchFile` mode to `EXIT /B` or `EXIT /B 0`
/// when `FixApplicability::UnsafeOptIn` is enabled.
///
/// # Arguments
/// * `node` - [`SyntaxKind::SimpleCommand`] representing `EXIT ...`.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// `Some(CstNode)` if `/B` was inserted, else `None`.
fn try_rewrite_exit_command(node: &CstNode, ctx: &mut RewriteContext) -> Option<CstNode> {
    let words: Vec<&CstNode> = node
        .child_nodes()
        .filter(|n| n.kind == SyntaxKind::WordNode)
        .collect();
    if words
        .iter()
        .skip(1)
        .any(|w| w.to_source_string().eq_ignore_ascii_case("/B"))
    {
        return None;
    }
    let prog_idx = node
        .children
        .iter()
        .position(|el| el.kind() == SyntaxKind::WordNode)
        .unwrap_or(0);
    let prog_span = node
        .children
        .get(prog_idx)
        .map_or(node.span, CstElement::span);
    let before = node.to_source_string();

    let mut new_children = Vec::with_capacity(node.children.len().saturating_add(2));
    for (idx, el) in node.children.iter().enumerate() {
        new_children.push(el.clone());
        if idx == prog_idx {
            new_children.push(CstElement::Token(CstToken::new(
                SyntaxKind::Whitespace,
                " ".to_owned(),
                prog_span,
            )));
            new_children.push(CstElement::Token(CstToken::new(
                SyntaxKind::SwitchToken,
                "/B".to_owned(),
                prog_span,
            )));
        }
    }
    let out = CstNode::new(SyntaxKind::SimpleCommand, node.span, new_children);
    ctx.record_edit(
        RuleId::new("CMD3004"),
        "Add `/B` switch to `EXIT` so batch file returns without terminating parent `cmd.exe`",
        node.span,
        before,
        out.to_source_string(),
    );
    Some(out)
}

/// `CMD3003`: Prepends `CALL ` before a bare `.bat` or `.cmd` invocation.
///
/// # Arguments
/// * `node` - [`SyntaxKind::SimpleCommand`] invoking a batch file.
/// * `prog_span` - [`Span`] of the batch filename token.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`] prefixed with `CALL `.
fn rewrite_bare_batch_call(node: &CstNode, prog_span: Span, ctx: &mut RewriteContext) -> CstNode {
    let prog_idx = node
        .children
        .iter()
        .position(|el| el.kind() == SyntaxKind::WordNode)
        .unwrap_or(0);
    let before = node.to_source_string();
    let mut new_children = Vec::with_capacity(node.children.len().saturating_add(2));
    for (idx, el) in node.children.iter().enumerate() {
        if idx == prog_idx {
            let call_tok = CstToken::new(SyntaxKind::LiteralToken, "CALL".to_owned(), prog_span);
            let call_word = CstNode::new(
                SyntaxKind::WordNode,
                prog_span,
                vec![CstElement::Token(call_tok)],
            );
            new_children.push(CstElement::Node(call_word));
            new_children.push(CstElement::Token(CstToken::new(
                SyntaxKind::Whitespace,
                " ".to_owned(),
                prog_span,
            )));
        }
        new_children.push(el.clone());
    }
    let out = CstNode::new(SyntaxKind::SimpleCommand, node.span, new_children);
    ctx.record_edit(
        RuleId::new("CMD3003"),
        "Prepend `CALL ` to batch script invocation so execution returns to caller",
        node.span,
        before,
        out.to_source_string(),
    );
    out
}
