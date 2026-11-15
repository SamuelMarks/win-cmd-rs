//! Execution-context percent dialect CST rewrite pass (`ExecutionModePercentPass`).
//!
//! Converts `FOR` loop variables and percent literals between `ExecutionContext::BatchFile`
//! (`%%I`, `%%~dpI`, `100%%`) and `ExecutionContext::InteractiveRepl` (`%I`, `%~dpI`, `100%`).

use crate::linter::rewriter::{CstRewriteRule, RewriteContext};
use crate::linter::rules::{FixApplicability, RuleId};
use crate::parser::cst::{CstElement, CstNode, CstToken, SyntaxKind};
use crate::types::PercentArity;

/// Converts single `%` vs double `%%` loop variable and literal percent syntax between
/// `ExecutionContext::BatchFile` (`.bat`/`.cmd`) and `ExecutionContext::InteractiveRepl` (`CMD1007`, `CMD1014`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecutionModePercentPass;

impl CstRewriteRule for ExecutionModePercentPass {
    /// Returns the primary [`RuleId`] (`CMD1014`) of this pass.
    ///
    /// # Returns
    /// `RuleId("CMD1014")`.
    fn rule_id(&self) -> RuleId {
        RuleId::new("CMD1014")
    }

    /// Returns the static pass name.
    ///
    /// # Returns
    /// `"ExecutionModePercentPass"`.
    fn name(&self) -> &'static str {
        "ExecutionModePercentPass"
    }

    /// Rewrites percent tokens across `root` to match `ctx.exec_context`.
    ///
    /// # Arguments
    /// * `root` - Script root [`CstNode`].
    /// * `ctx` - Mutable [`RewriteContext`].
    ///
    /// # Returns
    /// Rewritten [`CstNode`].
    fn rewrite_script(&self, root: &CstNode, ctx: &mut RewriteContext) -> CstNode {
        rewrite_percent_dialect_node(root, ctx)
    }
}

/// Recursively rewrites `ForVarToken` and `PercentLiteralToken` tokens according to `ctx.exec_context`.
///
/// # Arguments
/// * `node` - Current [`CstNode`].
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_percent_dialect_node(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    if node.kind == SyntaxKind::ForStatement {
        return rewrite_for_percent_dialect(node, ctx);
    }

    let mut new_children = Vec::with_capacity(node.children.len());
    for el in &node.children {
        match el {
            CstElement::Token(tok) => {
                let rewritten_tok = rewrite_percent_token_in_context(tok, ctx);
                new_children.push(CstElement::Token(rewritten_tok));
            }
            CstElement::Node(child) => {
                new_children.push(CstElement::Node(rewrite_percent_dialect_node(child, ctx)));
            }
        }
    }
    CstNode::new(node.kind, node.span, new_children)
}

/// Rewrites the `FOR` loop variable declaration and body references to match `ctx.exec_context`.
///
/// # Arguments
/// * `node` - [`SyntaxKind::ForStatement`] node.
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten `FOR` statement [`CstNode`].
fn rewrite_for_percent_dialect(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let required_arity = PercentArity::for_execution_context(ctx.exec_context);
    let mut new_children = Vec::with_capacity(node.children.len());
    let mut bound_var_ch: Option<char> = None;

    for el in &node.children {
        match el {
            CstElement::Token(tok) if tok.kind == SyntaxKind::ForVarToken => {
                let pct_cnt = tok.text.chars().take_while(|&c| c == '%').count();
                let tok_arity = PercentArity::from_percent_count(pct_cnt);
                let var_ch = tok.text.chars().nth(pct_cnt).unwrap_or('I');
                bound_var_ch = Some(var_ch);

                if required_arity == PercentArity::DoublePercent
                    && tok_arity == Some(PercentArity::SinglePercent)
                    && ctx.is_rule_enabled_at(
                        "CMD1007",
                        tok.span,
                        FixApplicability::SafeSemanticsPreserving,
                    )
                {
                    let after = format!("{}{var_ch}", required_arity.prefix_str());
                    ctx.record_edit(
                        RuleId::new("CMD1007"),
                        format!(
                            "Rewrite single-percent `FOR` variable `{}` to `{after}` in batch mode",
                            tok.text
                        ),
                        tok.span,
                        tok.text.clone(),
                        after.clone(),
                    );
                    new_children.push(CstElement::Token(CstToken::new(
                        SyntaxKind::ForVarToken,
                        after,
                        tok.span,
                    )));
                } else if required_arity == PercentArity::SinglePercent
                    && tok_arity == Some(PercentArity::DoublePercent)
                    && ctx.is_rule_enabled_at(
                        "CMD1014",
                        tok.span,
                        FixApplicability::SafeSemanticsPreserving,
                    )
                {
                    let after = format!("{}{var_ch}", required_arity.prefix_str());
                    ctx.record_edit(
                        RuleId::new("CMD1014"),
                        format!(
                            "Rewrite double-percent `FOR` variable `{}` to `{after}` in REPL mode",
                            tok.text
                        ),
                        tok.span,
                        tok.text.clone(),
                        after.clone(),
                    );
                    new_children.push(CstElement::Token(CstToken::new(
                        SyntaxKind::ForVarToken,
                        after,
                        tok.span,
                    )));
                } else {
                    new_children.push(CstElement::Token(tok.clone()));
                }
            }
            CstElement::Node(child) => {
                if let Some(ch) = bound_var_ch {
                    ctx.active_for_vars.insert(ch);
                }
                let rewritten = rewrite_percent_dialect_node(child, ctx);
                if let Some(ch) = bound_var_ch {
                    ctx.active_for_vars.remove(&ch);
                }
                new_children.push(CstElement::Node(rewritten));
            }
            CstElement::Token(tok) => {
                new_children.push(CstElement::Token(tok.clone()));
            }
        }
    }

    CstNode::new(SyntaxKind::ForStatement, node.span, new_children)
}

/// Rewrites an individual `ForVarToken` or `PercentLiteralToken` inside a command or word.
///
/// # Arguments
/// * `tok` - Candidate leaf [`CstToken`].
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten or cloned [`CstToken`].
fn rewrite_percent_token_in_context(tok: &CstToken, ctx: &mut RewriteContext) -> CstToken {
    if !ctx.is_rule_enabled_at(
        "CMD1014",
        tok.span,
        FixApplicability::SafeSemanticsPreserving,
    ) {
        return tok.clone();
    }
    let required_arity = PercentArity::for_execution_context(ctx.exec_context);
    if tok.kind == SyntaxKind::ForVarToken {
        let pct_cnt = tok.text.chars().take_while(|&c| c == '%').count();
        let tok_arity = PercentArity::from_percent_count(pct_cnt);
        if required_arity == PercentArity::DoublePercent
            && tok_arity == Some(PercentArity::SinglePercent)
        {
            let after = format!("%{}", tok.text);
            ctx.record_edit(
                RuleId::new("CMD1014"),
                format!(
                    "Convert `{}` to `{after}` for batch file execution",
                    tok.text
                ),
                tok.span,
                tok.text.clone(),
                after.clone(),
            );
            return CstToken::new(SyntaxKind::ForVarToken, after, tok.span);
        } else if required_arity == PercentArity::SinglePercent
            && tok_arity == Some(PercentArity::DoublePercent)
        {
            let after = tok.text.strip_prefix('%').unwrap_or(&tok.text).to_owned();
            ctx.record_edit(
                RuleId::new("CMD1014"),
                format!(
                    "Convert `{}` to `{after}` for interactive REPL execution",
                    tok.text
                ),
                tok.span,
                tok.text.clone(),
                after.clone(),
            );
            return CstToken::new(SyntaxKind::ForVarToken, after, tok.span);
        }
    } else if tok.kind == SyntaxKind::PercentLiteralToken {
        let target_str = required_arity.prefix_str();
        match required_arity {
            PercentArity::DoublePercent => {
                if tok.text == "%" {
                    ctx.record_edit(
                        RuleId::new("CMD1014"),
                        "Escape bare single `%` literal as `%%` in batch file mode",
                        tok.span,
                        "%".to_owned(),
                        target_str.to_owned(),
                    );
                    return CstToken::new(
                        SyntaxKind::PercentLiteralToken,
                        target_str.to_owned(),
                        tok.span,
                    );
                }
            }
            PercentArity::SinglePercent => {
                if tok.text == "%%" {
                    ctx.record_edit(
                        RuleId::new("CMD1014"),
                        "Collapse `%%` literal to `%` in interactive REPL mode",
                        tok.span,
                        "%%".to_owned(),
                        target_str.to_owned(),
                    );
                    return CstToken::new(
                        SyntaxKind::PercentLiteralToken,
                        target_str.to_owned(),
                        tok.span,
                    );
                }
            }
        }
    }
    tok.clone()
}
