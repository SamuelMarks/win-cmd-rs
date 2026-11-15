//! Variable and path quoting CST rewrite pass (`QuoteUnquotedVariablesPass`).
//!
//! Quotes unquoted variables and parameters in path-consuming commands (`CD`, `COPY`, `DEL`, etc.),
//! `IF EXIST` conditions, `IF` comparisons (`CMD2003`, `CMD2006`), and I/O redirection targets,
//! and upgrades standalone quoted `"%1"` / `"%1\sub"` / `"%%I"` arguments to `"%~1"` / `"%%~I"`
//! (`CMD2007`) without mutating multi-word display strings like `ECHO "Usage: %0 %1"`.

use crate::linter::rewriter::{CstRewriteRule, RewriteContext};
use crate::linter::rules::{FixApplicability, RuleId};
use crate::parser::cst::{CstElement, CstNode, CstToken, SyntaxKind};
use crate::span::Span;
use crate::types::{PercentArity, QuoteInsertionStrategy};

/// Quotes unquoted variables and parameters in path-consuming commands, `IF EXIST` conditions,
/// `IF` comparisons, and I/O redirection targets (`CMD2003`, `CMD2006`, `CMD2007`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuoteUnquotedVariablesPass;

impl CstRewriteRule for QuoteUnquotedVariablesPass {
    /// Returns the primary [`RuleId`] (`CMD2006`) of this pass.
    ///
    /// # Returns
    /// `RuleId("CMD2006")`.
    fn rule_id(&self) -> RuleId {
        RuleId::new("CMD2006")
    }

    /// Returns the static pass name.
    ///
    /// # Returns
    /// `"QuoteUnquotedVariablesPass"`.
    fn name(&self) -> &'static str {
        "QuoteUnquotedVariablesPass"
    }

    /// Rewrites unquoted variable/parameter paths across `root`.
    ///
    /// # Arguments
    /// * `root` - Script root [`CstNode`].
    /// * `ctx` - Mutable [`RewriteContext`].
    ///
    /// # Returns
    /// Rewritten [`CstNode`].
    fn rewrite_script(&self, root: &CstNode, ctx: &mut RewriteContext) -> CstNode {
        rewrite_quoting_node(root, ctx)
    }
}

/// Recursively walks `node`, quoting unquoted variables/parameters in `SimpleCommand`,
/// `IfConditionNode`, and `RedirectionNode` contexts, plus upgrading standalone `"%1"` -> `"%~1"`.
///
/// # Arguments
/// * `node` - Current [`CstNode`].
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_quoting_node(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let mut children = Vec::with_capacity(node.children.len());
    for el in &node.children {
        match el {
            CstElement::Node(child) => {
                children.push(CstElement::Node(rewrite_quoting_node(child, ctx)));
            }
            CstElement::Token(tok) => {
                children.push(CstElement::Token(tok.clone()));
            }
        }
    }
    let current = CstNode::new(node.kind, node.span, children);

    match current.kind {
        SyntaxKind::QuotedStringNode => rewrite_quoted_param_without_tilde(&current, ctx),
        SyntaxKind::SimpleCommand => rewrite_simple_command_variable_quoting(&current, ctx),
        SyntaxKind::IfConditionNode => rewrite_if_condition_variable_quoting(&current, ctx),
        SyntaxKind::RedirectionNode => rewrite_redirection_variable_quoting(&current, ctx),
        SyntaxKind::Script
        | SyntaxKind::EmptyStatement
        | SyntaxKind::LabelStatement
        | SyntaxKind::DoubleColonComment
        | SyntaxKind::RemStatement
        | SyntaxKind::CompoundBlock
        | SyntaxKind::IfStatement
        | SyntaxKind::ElseClauseNode
        | SyntaxKind::ForStatement
        | SyntaxKind::ForSetNode
        | SyntaxKind::BinaryCommandExpr
        | SyntaxKind::WordNode
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
        | SyntaxKind::CommentTextToken => current,
    }
}

/// `CMD2007`: Inside an already-quoted standalone argument `QuotedStringNode` like `"%1"`,
/// `"%1\sub"`, or `"%%I"`, rewrites the leading parameter/variable token to `%~1` / `%%~I`.
///
/// Leaves multi-word display strings containing whitespace (such as `ECHO "Usage: %0 %1"`)
/// untouched so user-facing message text is never mutated.
///
/// # Arguments
/// * `node` - [`SyntaxKind::QuotedStringNode`] node.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten or unchanged [`CstNode`].
fn rewrite_quoted_param_without_tilde(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let inner_tokens: Vec<&CstToken> = node
        .child_tokens()
        .filter(|t| t.kind != SyntaxKind::DoubleQuote)
        .collect();
    let starts_with_param_or_for = inner_tokens.first().is_some_and(|first| {
        matches!(
            first.kind,
            SyntaxKind::PositionalParamToken | SyntaxKind::ForVarToken
        )
    });
    let contains_whitespace = inner_tokens
        .iter()
        .any(|t| t.text.chars().any(char::is_whitespace));
    if !starts_with_param_or_for
        || contains_whitespace
        || !ctx.is_rule_enabled_at(
            "CMD2007",
            node.span,
            FixApplicability::SafeSemanticsPreserving,
        )
    {
        return node.clone();
    }

    let mut changed = false;
    let before = node.to_source_string();
    let mut new_children = Vec::with_capacity(node.children.len());

    for tok in node.child_tokens() {
        let mut tok = tok.clone();
        if tok.kind == SyntaxKind::PositionalParamToken
            && !tok.text.contains('~')
            && tok.text != "%*"
        {
            let digit = tok.text.chars().nth(1).unwrap_or('1');
            tok.text = format!("%~{digit}");
            changed = true;
        } else if tok.kind == SyntaxKind::ForVarToken && !tok.text.contains('~') {
            let pct_cnt = tok.text.chars().take_while(|&c| c == '%').count();
            let var_ch = tok.text.chars().nth(pct_cnt).unwrap_or('I');
            let prefix = if pct_cnt >= 2 { "%%" } else { "%" };
            tok.text = format!("{prefix}~{var_ch}");
            changed = true;
        }
        new_children.push(CstElement::Token(tok));
    }

    let out = CstNode::new(SyntaxKind::QuotedStringNode, node.span, new_children);
    if changed {
        ctx.record_edit(
            RuleId::new("CMD2007"),
            "Add `~` quote-stripping modifier inside quoted parameter/variable reference",
            node.span,
            before,
            out.to_source_string(),
        );
    }
    out
}

/// Checks if `cmd_upper` is a path-consuming builtin or external command whose variable/parameter
/// arguments should be quoted (`CMD2006`).
///
/// # Arguments
/// * `cmd_upper` - Uppercase command name.
///
/// # Returns
/// `true` if path arguments to `cmd_upper` should be quoted.
fn is_path_consuming_command(cmd_upper: &str) -> bool {
    matches!(
        cmd_upper,
        "CD" | "CHDIR"
            | "MD"
            | "MKDIR"
            | "RD"
            | "RMDIR"
            | "DEL"
            | "ERASE"
            | "COPY"
            | "MOVE"
            | "REN"
            | "RENAME"
            | "TYPE"
            | "MORE"
            | "ATTRIB"
            | "XCOPY"
            | "ROBOCOPY"
            | "CALL"
            | "START"
            | "PUSHD"
    )
}

/// Quotes unquoted variable/parameter arguments in path-consuming `SimpleCommand`s (`CMD2006`).
///
/// # Arguments
/// * `node` - [`SyntaxKind::SimpleCommand`] node.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_simple_command_variable_quoting(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let prog_node = node
        .child_nodes()
        .find(|n| matches!(n.kind, SyntaxKind::WordNode | SyntaxKind::SetAssignmentNode));
    let Some(prog) = prog_node else {
        return node.clone();
    };
    let prog_upper = prog
        .to_source_string()
        .trim_matches('"')
        .to_ascii_uppercase();
    if !is_path_consuming_command(&prog_upper) {
        return node.clone();
    }

    let mut seen_prog = false;
    let mut new_children = Vec::with_capacity(node.children.len());

    for el in &node.children {
        if let Some(child) = el.as_node().filter(|c| c.kind == SyntaxKind::WordNode) {
            if !seen_prog {
                seen_prog = true;
                new_children.push(el.clone());
                continue;
            }
            if let Some(quoted_word) =
                try_quote_unquoted_word_node(child, RuleId::new("CMD2006"), ctx)
            {
                new_children.push(CstElement::Node(quoted_word));
                continue;
            }
        }
        new_children.push(el.clone());
    }

    CstNode::new(SyntaxKind::SimpleCommand, node.span, new_children)
}

/// Quotes unquoted variable/parameter operands in `IF EXIST <word>` (`CMD2006`) and
/// `IF <lhs> == <rhs>` / `IF <lhs> EQU <rhs>` (`CMD2003`).
///
/// # Arguments
/// * `node` - [`SyntaxKind::IfConditionNode`] node.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_if_condition_variable_quoting(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let is_if_exist = node
        .child_tokens()
        .any(|t| t.kind == SyntaxKind::Keyword && t.text.eq_ignore_ascii_case("EXIST"));
    if is_if_exist {
        let mut new_children = Vec::with_capacity(node.children.len());
        for el in &node.children {
            if let Some(qw) = el
                .as_node()
                .filter(|c| c.kind == SyntaxKind::WordNode)
                .and_then(|child| try_quote_unquoted_word_node(child, RuleId::new("CMD2006"), ctx))
            {
                new_children.push(CstElement::Node(qw));
                continue;
            }
            new_children.push(el.clone());
        }
        return CstNode::new(SyntaxKind::IfConditionNode, node.span, new_children);
    }

    let word_indices: Vec<usize> = node
        .children
        .iter()
        .enumerate()
        .filter_map(|(i, el)| (el.kind() == SyntaxKind::WordNode).then_some(i))
        .collect();
    if word_indices.len() != 2 {
        return node.clone();
    }
    let lhs_idx = *word_indices.first().unwrap_or(&0);
    let rhs_idx = *word_indices.get(1).unwrap_or(&0);

    let lhs_node = node
        .children
        .get(lhs_idx)
        .and_then(CstElement::as_node)
        .unwrap_or(node);
    let rhs_node = node
        .children
        .get(rhs_idx)
        .and_then(CstElement::as_node)
        .unwrap_or(node);

    let lhs_needs = word_contains_unquoted_var_or_param(lhs_node);
    let rhs_needs = word_contains_unquoted_var_or_param(rhs_node);
    let lhs_is_quoted = word_is_already_quoted(lhs_node);
    let rhs_is_quoted = word_is_already_quoted(rhs_node);

    let is_double_eq = node
        .child_tokens()
        .any(|t| t.kind == SyntaxKind::OperatorToken && matches!(t.text.as_str(), "==" | "="));

    let mismatched_eq_quotes = is_double_eq && (lhs_is_quoted != rhs_is_quoted);
    if (!lhs_needs && !rhs_needs && !mismatched_eq_quotes)
        || !ctx.is_rule_enabled_at(
            "CMD2003",
            node.span,
            FixApplicability::SafeSemanticsPreserving,
        )
    {
        return node.clone();
    }

    let mut new_children = node.children.clone();
    let before = node.to_source_string();

    for (idx, slot) in new_children.iter_mut().enumerate() {
        if idx == lhs_idx && !lhs_is_quoted {
            *slot = CstElement::Node(wrap_word_node_with_smart_quotes(lhs_node));
        } else if idx == rhs_idx && !rhs_is_quoted {
            *slot = CstElement::Node(wrap_word_node_with_smart_quotes(rhs_node));
        }
    }

    let out = CstNode::new(SyntaxKind::IfConditionNode, node.span, new_children);
    let after = out.to_source_string();
    ctx.record_edit(
        RuleId::new("CMD2003"),
        "Quote `IF` comparison operands so spaces or empty variables cannot cause syntax errors",
        node.span,
        before,
        after,
    );
    out
}

/// Quotes unquoted variable/parameter targets in `RedirectionNode`s (`> %OUT%` -> `> "%OUT%"`, `CMD2006`).
///
/// # Arguments
/// * `node` - [`SyntaxKind::RedirectionNode`] node.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_redirection_variable_quoting(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let mut new_children = Vec::with_capacity(node.children.len());
    for el in &node.children {
        if let Some(qw) = el
            .as_node()
            .filter(|c| c.kind == SyntaxKind::WordNode)
            .and_then(|child| try_quote_unquoted_word_node(child, RuleId::new("CMD2006"), ctx))
        {
            new_children.push(CstElement::Node(qw));
            continue;
        }
        new_children.push(el.clone());
    }
    CstNode::new(SyntaxKind::RedirectionNode, node.span, new_children)
}

/// Checks if `word_node` is unquoted and contains at least one variable/parameter token
/// (`%VAR%`, `!VAR!`, `%1`, `%%I`). If so, wraps it in smart quotes.
///
/// # Arguments
/// * `word_node` - Candidate [`SyntaxKind::WordNode`].
/// * `rule_id` - [`RuleId`] recorded if wrapped.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// `Some(CstNode)` when wrapped, or `None` if already quoted or plain literal.
fn try_quote_unquoted_word_node(
    word_node: &CstNode,
    rule_id: RuleId,
    ctx: &mut RewriteContext,
) -> Option<CstNode> {
    if word_is_already_quoted(word_node)
        || !word_contains_unquoted_var_or_param(word_node)
        || !ctx.is_rule_enabled_at(
            rule_id.as_str(),
            word_node.span,
            FixApplicability::SafeSemanticsPreserving,
        )
    {
        return None;
    }
    let before = word_node.to_source_string();
    let out = wrap_word_node_with_smart_quotes(word_node);
    let after = out.to_source_string();
    ctx.record_edit(
        rule_id,
        format!("Quote variable/parameter path `{before}` as `{after}`"),
        word_node.span,
        before,
        after,
    );
    Some(out)
}

/// Checks whether `word_node` already contains a `QuotedStringNode` or `DoubleQuote`.
///
/// # Arguments
/// * `word_node` - [`SyntaxKind::WordNode`] to inspect.
///
/// # Returns
/// `true` if `word_node` is already quoted.
fn word_is_already_quoted(word_node: &CstNode) -> bool {
    word_node.children.iter().any(|el| {
        matches!(
            el.kind(),
            SyntaxKind::QuotedStringNode | SyntaxKind::DoubleQuote
        )
    })
}

/// Checks whether `word_node` contains at least one `EnvVarToken`, `DelayedVarToken`,
/// `PositionalParamToken` (excluding `%*`), or `ForVarToken`.
///
/// # Arguments
/// * `word_node` - [`SyntaxKind::WordNode`] to inspect.
///
/// # Returns
/// `true` if `word_node` contains an unquoted variable or parameter reference.
fn word_contains_unquoted_var_or_param(word_node: &CstNode) -> bool {
    word_node.child_tokens().any(|tok| match tok.kind {
        SyntaxKind::EnvVarToken | SyntaxKind::DelayedVarToken | SyntaxKind::ForVarToken => true,
        SyntaxKind::PositionalParamToken => tok.text != "%*",
        SyntaxKind::Script
        | SyntaxKind::EmptyStatement
        | SyntaxKind::LabelStatement
        | SyntaxKind::DoubleColonComment
        | SyntaxKind::RemStatement
        | SyntaxKind::SimpleCommand
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
        | SyntaxKind::InvalidModifierVarToken
        | SyntaxKind::PercentLiteralToken
        | SyntaxKind::UnclosedVarToken
        | SyntaxKind::CommentTextToken => false,
    })
}

/// Selects the [`QuoteInsertionStrategy`] for an individual sub-word [`CstToken`]:
/// [`QuoteInsertionStrategy::StripAndWrapModifier`] for unstripped positional (`%1`..`%9`) or
/// `FOR` (`%%I`) variables, or [`QuoteInsertionStrategy::WrapWholeWord`] otherwise.
///
/// # Arguments
/// * `tok` - Sub-word [`CstToken`] inside an unquoted `WordNode`.
///
/// # Returns
/// Selected [`QuoteInsertionStrategy`].
#[must_use]
fn classify_token_quote_strategy(tok: &CstToken) -> QuoteInsertionStrategy {
    let needs_tilde = (tok.kind == SyntaxKind::PositionalParamToken
        && !tok.text.contains('~')
        && tok.text != "%*")
        || (tok.kind == SyntaxKind::ForVarToken && !tok.text.contains('~'));
    if needs_tilde {
        QuoteInsertionStrategy::StripAndWrapModifier
    } else {
        QuoteInsertionStrategy::WrapWholeWord
    }
}

/// Wraps an unquoted `WordNode`'s children inside a `SyntaxKind::QuotedStringNode` (`"` + children + `"`),
/// applying [`QuoteInsertionStrategy::StripAndWrapModifier`] (`%1` -> `%~1`, `%%I` -> `%%~I`) or
/// [`QuoteInsertionStrategy::WrapWholeWord`] as classified by [`classify_token_quote_strategy`].
///
/// # Arguments
/// * `word_node` - Unquoted [`SyntaxKind::WordNode`].
///
/// # Returns
/// Smart-quoted [`SyntaxKind::WordNode`].
fn wrap_word_node_with_smart_quotes(word_node: &CstNode) -> CstNode {
    let span = word_node.span;
    let mut quoted_children = Vec::with_capacity(word_node.children.len().saturating_add(2));
    quoted_children.push(CstElement::Token(CstToken::new(
        SyntaxKind::DoubleQuote,
        r#"""#.to_owned(),
        Span::new(span.source_id, span.start, span.start),
    )));

    for tok in word_node.child_tokens() {
        if classify_token_quote_strategy(tok) == QuoteInsertionStrategy::StripAndWrapModifier {
            if tok.kind == SyntaxKind::PositionalParamToken {
                let digit = tok.text.chars().nth(1).unwrap_or('1');
                quoted_children.push(CstElement::Token(CstToken::new(
                    SyntaxKind::PositionalParamToken,
                    format!("%~{digit}"),
                    tok.span,
                )));
                continue;
            }
            let pct_cnt = tok.text.chars().take_while(|&c| c == '%').count();
            let var_ch = tok.text.chars().nth(pct_cnt).unwrap_or('I');
            let prefix = PercentArity::from_percent_count(pct_cnt)
                .unwrap_or(PercentArity::DoublePercent)
                .prefix_str();
            quoted_children.push(CstElement::Token(CstToken::new(
                SyntaxKind::ForVarToken,
                format!("{prefix}~{var_ch}"),
                tok.span,
            )));
            continue;
        }
        if tok.kind == SyntaxKind::CaretEscapeToken {
            let unescaped: String = tok.text.chars().skip(1).collect();
            quoted_children.push(CstElement::Token(CstToken::new(
                SyntaxKind::LiteralToken,
                unescaped,
                tok.span,
            )));
            continue;
        }
        quoted_children.push(CstElement::Token(tok.clone()));
    }

    quoted_children.push(CstElement::Token(CstToken::new(
        SyntaxKind::DoubleQuote,
        r#"""#.to_owned(),
        Span::new(span.source_id, span.end, span.end),
    )));

    let q_node = CstNode::new(SyntaxKind::QuotedStringNode, span, quoted_children);
    CstNode::new(SyntaxKind::WordNode, span, vec![CstElement::Node(q_node)])
}
