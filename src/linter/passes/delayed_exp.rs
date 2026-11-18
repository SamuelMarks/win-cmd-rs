//! Delayed expansion block CST rewrite pass (`DelayedExpansionBlockPass`).
//!
//! Rewrites stale `%VAR%` reads of block-modified variables (`CMD2001`) and dynamic
//! pseudo-variables `%ERRORLEVEL%`, `%RANDOM%`, `%TIME%` (`CMD2009`) inside `( ... )`
//! blocks and `FOR` loops into `!VAR!`, and injects `SETLOCAL EnableDelayedExpansion`
//! when safe (checking for unescaped literal `!` characters in `Safe` mode).

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::linter::rewriter::{CstRewriteRule, RewriteContext};
use crate::linter::rules::{FixApplicability, RuleId};
use crate::parser::cst::{CstElement, CstNode, CstToken, SyntaxKind};
use crate::parser::peg::parse_script_cst;
use crate::types::{CRLF, DelayedExpansionMode};

/// Rewrites stale `%VAR%` reads inside blocks into delayed expansion `!VAR!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DelayedExpansionBlockPass;

impl CstRewriteRule for DelayedExpansionBlockPass {
    /// Returns the primary [`RuleId`] (`CMD2001`) of this pass.
    ///
    /// # Returns
    /// `RuleId("CMD2001")`.
    fn rule_id(&self) -> RuleId {
        RuleId::new("CMD2001")
    }

    /// Returns the static pass name.
    ///
    /// # Returns
    /// `"DelayedExpansionBlockPass"`.
    fn name(&self) -> &'static str {
        "DelayedExpansionBlockPass"
    }

    /// Rewrites stale block `%VAR%` reads in `root`, skipping `SETLOCAL EnableDelayedExpansion`
    /// injection in `Safe` mode when the script contains literal `!` characters that would be stripped.
    ///
    /// # Arguments
    /// * `root` - Script root [`CstNode`].
    /// * `ctx` - Mutable [`RewriteContext`].
    ///
    /// # Returns
    /// Rewritten [`CstNode`].
    fn rewrite_script(&self, root: &CstNode, ctx: &mut RewriteContext) -> CstNode {
        if ctx.fix_safety < FixApplicability::RecommendedRepair
            || ctx
                .linter_config
                .as_ref()
                .is_some_and(|c| c.dialect == crate::types::ShellDialect::MsDos622)
        {
            return root.clone();
        }
        if !ctx.has_setlocal_enable_delayed
            && !ctx.fix_safety.is_unsafe_opt_in()
            && script_contains_literal_exclamation(root)
        {
            return root.clone();
        }

        let mut rewritten = rewrite_delayed_expansion_node(root, ctx);
        if ctx.needs_setlocal_enable_delayed_injection
            && !ctx.has_setlocal_enable_delayed
            && ctx.exec_context.is_batch_file()
        {
            rewritten = inject_setlocal_enable_delayed_expansion(&rewritten, ctx);
            ctx.has_setlocal_enable_delayed = true;
            ctx.delayed_expansion = DelayedExpansionMode::Enabled;
        }
        rewritten
    }
}

/// Checks whether `root` contains any literal `!` character outside comments or `!VAR!` tokens
/// that enabling `SETLOCAL EnableDelayedExpansion` would strip or alter at runtime.
///
/// # Arguments
/// * `root` - Script root [`CstNode`].
///
/// # Returns
/// `true` if a `LiteralToken` contains `'!'`.
#[must_use]
pub fn script_contains_literal_exclamation(root: &CstNode) -> bool {
    root.descendant_tokens()
        .into_iter()
        .any(|tok| tok.kind == SyntaxKind::LiteralToken && tok.text.contains('!'))
}

/// Recursively walks `node`, tracking variables modified inside `( ... )` / `FOR` / `IF` blocks
/// and converting `%VAR%` reads of modified or dynamic pseudo-variables into `!VAR!`.
///
/// # Arguments
/// * `node` - Current [`CstNode`].
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_delayed_expansion_node(node: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let is_block_scope = matches!(
        node.kind,
        SyntaxKind::CompoundBlock | SyntaxKind::ForStatement | SyntaxKind::IfStatement
    );

    let saved_vars = if is_block_scope && ctx.block_depth == 0 {
        Some(ctx.block_modified_vars.clone())
    } else {
        None
    };

    if is_block_scope {
        ctx.block_depth = ctx.block_depth.saturating_add(1);
    }

    if node.kind == SyntaxKind::SimpleCommand {
        record_set_modified_vars_in_cst(node, ctx);
    }

    let mut new_children = Vec::with_capacity(node.children.len());
    for el in &node.children {
        match el {
            CstElement::Token(tok)
                if tok.kind == SyntaxKind::EnvVarToken && ctx.block_depth > 0 =>
            {
                if let Some((new_tok, rule_id)) = try_convert_env_var_to_delayed(tok, ctx)
                    && ctx.is_rule_enabled_at(
                        rule_id.as_str(),
                        tok.span,
                        FixApplicability::RecommendedRepair,
                    )
                {
                    ctx.needs_setlocal_enable_delayed_injection = true;
                    ctx.record_edit(
                        rule_id,
                        format!(
                            "Convert `{}` to delayed expansion `{}` inside block",
                            tok.text, new_tok.text
                        ),
                        tok.span,
                        tok.text.clone(),
                        new_tok.text.clone(),
                    );
                    new_children.push(CstElement::Token(new_tok));
                } else {
                    new_children.push(CstElement::Token(tok.clone()));
                }
            }
            CstElement::Token(tok) => {
                new_children.push(CstElement::Token(tok.clone()));
            }
            CstElement::Node(child) => {
                new_children.push(CstElement::Node(rewrite_delayed_expansion_node(child, ctx)));
            }
        }
    }

    if is_block_scope {
        ctx.block_depth = ctx.block_depth.saturating_sub(1);
        if let Some(prev) = saved_vars {
            ctx.block_modified_vars = prev;
        }
    }

    CstNode::new(node.kind, node.span, new_children)
}

/// Inspects a `SimpleCommand` CST node to see if it is a `SET` command that modifies one or more
/// environment variables inside the current block, inserting their uppercase names into `ctx.block_modified_vars`.
///
/// # Arguments
/// * `node` - [`SyntaxKind::SimpleCommand`] node.
/// * `ctx` - Mutable [`RewriteContext`].
pub fn record_set_modified_vars_in_cst(node: &CstNode, ctx: &mut RewriteContext) {
    let words: Vec<&CstNode> = node
        .child_nodes()
        .filter(|n| matches!(n.kind, SyntaxKind::WordNode | SyntaxKind::SetAssignmentNode))
        .collect();
    let Some(prog) = words.first() else {
        return;
    };
    let prog_src = prog.to_source_string();
    if !prog_src.trim_matches('"').eq_ignore_ascii_case("SET") || ctx.block_depth == 0 {
        return;
    }

    for arg in words.iter().skip(1) {
        let text = arg.to_source_string();
        let unq = text.trim_matches('"');
        if ["/A", "/P"]
            .into_iter()
            .any(|sw| unq.eq_ignore_ascii_case(sw))
        {
            continue;
        }
        let body = if unq.get(..2).is_some_and(|p| {
            ["/A", "/P"]
                .into_iter()
                .any(|sw| p.eq_ignore_ascii_case(sw))
        }) {
            unq.get(2..).unwrap_or("").trim_start()
        } else {
            unq
        };
        if let Some((var_part_raw, _)) = body.split_once('=') {
            let var_part = var_part_raw
                .trim()
                .trim_end_matches(['+', '-', '*', '/', '%', '&', '|', '^']);
            let var_clean = var_part.trim_matches('"').trim();
            ctx.block_modified_vars
                .insert(var_clean.to_ascii_uppercase());
        }
    }
}

/// Checks if an `EnvVarToken` (`%VAR%` or `%VAR:~0,2%`) inside a block reads either a
/// block-modified variable (`CMD2001`) or a dynamic pseudo-variable (`%ERRORLEVEL%`, `%RANDOM%`, `%TIME%`, `CMD2009`).
///
/// # Arguments
/// * `tok` - Candidate [`SyntaxKind::EnvVarToken`].
/// * `ctx` - Active [`RewriteContext`].
///
/// # Returns
/// `Some((DelayedVarToken, RuleId))` if conversion applies, else `None`.
fn try_convert_env_var_to_delayed(
    tok: &CstToken,
    ctx: &RewriteContext,
) -> Option<(CstToken, RuleId)> {
    let inner = tok.text.trim_matches('%');
    let base_name = inner
        .split(':')
        .next()
        .unwrap_or(inner)
        .to_ascii_uppercase();

    let is_modified = ctx.block_modified_vars.contains(&base_name);
    let is_dynamic_pseudo = matches!(base_name.as_str(), "ERRORLEVEL" | "RANDOM" | "TIME");

    if !is_modified && !is_dynamic_pseudo {
        return None;
    }

    let rule_id = if is_modified {
        RuleId::new("CMD2001")
    } else {
        RuleId::new("CMD2009")
    };
    let delayed_text = format!("!{inner}!");
    Some((
        CstToken::new(SyntaxKind::DelayedVarToken, delayed_text, tok.span),
        rule_id,
    ))
}

/// Injects `SETLOCAL EnableDelayedExpansion` at the top of `root` (immediately after `@echo off`
/// if present, or as the first statement after any BOM).
///
/// # Arguments
/// * `root` - Script root [`CstNode`].
/// * `ctx` - Mutable [`RewriteContext`].
///
/// # Returns
/// Rewritten script root [`CstNode`].
fn inject_setlocal_enable_delayed_expansion(root: &CstNode, ctx: &mut RewriteContext) -> CstNode {
    let line_ending = root
        .descendant_tokens()
        .into_iter()
        .find(|t| t.kind == SyntaxKind::Newline)
        .map_or(CRLF, |t| t.text.as_str())
        .to_owned();

    let mut insert_idx = 0usize;
    for (idx, el) in root.children.iter().enumerate() {
        if el.kind() == SyntaxKind::BomToken {
            insert_idx = idx.saturating_add(1);
            continue;
        }
        let src_lower = el.to_source_string().trim().to_ascii_lowercase();
        if ["@echo off", "echo off"].contains(&src_lower.as_str()) {
            insert_idx = idx.saturating_add(1);
            break;
        }
    }

    let setlocal_line = format!("SETLOCAL EnableDelayedExpansion{line_ending}");
    let parsed_setlocal = parse_script_cst(ctx.source_id, &setlocal_line, ctx.exec_context);
    let mut new_children = Vec::with_capacity(root.children.len().saturating_add(1));

    for (idx, el) in root.children.iter().enumerate() {
        if idx == insert_idx {
            for sl_el in &parsed_setlocal.root.children {
                new_children.push(sl_el.clone());
            }
        }
        new_children.push(el.clone());
    }

    ctx.record_edit(
        RuleId::new("CMD2001"),
        "Inject `SETLOCAL EnableDelayedExpansion` for delayed variable reads inside blocks",
        root.span,
        String::new(),
        setlocal_line,
    );

    CstNode::new(SyntaxKind::Script, root.span, new_children)
}
