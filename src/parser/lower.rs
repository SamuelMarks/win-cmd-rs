//! Deterministic CST-to-AST lowering engine (`lower_cst_to_ast`) shared by both
//! `wincmd` runtime execution (`WordPartsMode::Lightweight`) and `wincheck` static analysis
//! (`WordPartsMode::PopulateSubwordParts`).

use crate::error::CmdError;
use crate::parser::ast::{
    CommandExpr, ComparisonOp, CompoundBlock, ForFOptions, ForStatement, ForVariant, IfCondition,
    IfStatement, LabelNode, ParsedScript, Redirection, RedirectionKind, RemNode, SimpleCommand,
    SpannedWord, Statement, WordPart, WordPartKind,
};
use crate::parser::cst::{CstElement, CstNode, CstScript, CstToken, PegDiagnostic, SyntaxKind};
use crate::parser::cst_parser::{CstParserState, WordEqualsMode, WordParenScope, parse_word_node};
use crate::parser::lexer::WordPartsMode;
use crate::parser::var_ops::parse_cmd_int;
use crate::reader::char_map::SpannedChar;
use crate::span::{ByteOffset, SourceId, Span};
use crate::types::{
    CaseSensitivity, EchoSuppression, ExecutionContext, FileDescriptor, ForVarName, LabelName,
    NegationMode, RecoveryMode, TAB_CHAR,
};

/// Parses a single word character slice into sub-word [`WordPart`] items for static analysis.
///
/// # Arguments
/// * `source_id` - Source file ID.
/// * `chars` - Spanned characters of the word.
///
/// # Returns
/// Vector of [`WordPart`] items covering `chars`.
#[must_use]
pub fn parse_single_word_parts(source_id: SourceId, chars: &[SpannedChar]) -> Vec<WordPart> {
    if chars.is_empty() {
        return Vec::new();
    }
    let start_off = chars.first().map_or(ByteOffset(0), |c| c.span.start);
    let mut state = CstParserState::new(
        source_id,
        chars,
        ExecutionContext::BatchFile,
        RecoveryMode::Recovering,
        start_off,
    );
    let Some((word_node, _)) = parse_word_node(
        &mut state,
        0,
        chars.len(),
        WordEqualsMode::KeepAllEquals,
        WordParenScope::Normal,
    ) else {
        return Vec::new();
    };
    lower_word_cst_node_with_mode(&word_node, WordPartsMode::PopulateSubwordParts).parts
}

/// Lowers a lossless [`CstScript`] into a [`ParsedScript`] AST with full sub-word [`WordPart`]s.
///
/// # Arguments
/// * `cst` - Lossless [`CstScript`] produced by [`super::cst_parser::parse_script_cst`].
///
/// # Returns
/// Lowered [`ParsedScript`] AST.
#[must_use]
pub fn lower_cst_to_ast(cst: &CstScript) -> ParsedScript {
    lower_cst_to_ast_with_mode(cst, WordPartsMode::PopulateSubwordParts)
}

/// Lowers a [`CstScript`] into a [`ParsedScript`] AST using `parts_mode`.
///
/// # Arguments
/// * `cst` - Lossless [`CstScript`].
/// * `parts_mode` - [`WordPartsMode`] (`PopulateSubwordParts` vs `Lightweight`).
///
/// # Returns
/// Lowered [`ParsedScript`].
#[must_use]
pub fn lower_cst_to_ast_with_mode(cst: &CstScript, parts_mode: WordPartsMode) -> ParsedScript {
    let mut statements = Vec::new();
    let mut labels = Vec::new();
    let mut broken_carets = Vec::new();

    collect_broken_carets_recursive(&cst.root, &mut broken_carets);
    for stmt_node in cst.root.children.iter().filter_map(CstElement::as_node) {
        if let Some(stmt) = lower_statement_cst_node_with_mode(stmt_node, &mut labels, parts_mode) {
            statements.push(stmt);
        }
    }

    ParsedScript {
        source_id: cst.source_id,
        statements,
        labels,
        broken_caret_spans: broken_carets,
    }
}

/// Recursively collects all `BrokenCaretContinuation` token spans inside `node`.
///
/// # Arguments
/// * `node` - [`CstNode`] to traverse.
/// * `out` - Output [`Span`] accumulator.
pub fn collect_broken_carets_recursive(node: &CstNode, out: &mut Vec<Span>) {
    for el in &node.children {
        match el {
            CstElement::Token(tok) if tok.kind == SyntaxKind::BrokenCaretContinuation => {
                out.push(tok.span);
            }
            CstElement::Token(_) => {}
            CstElement::Node(sub) => collect_broken_carets_recursive(sub, out),
        }
    }
}

/// Converts a [`PegDiagnostic`] into a structured [`CmdError`] preserving probable-misuse
/// classifications and farthest-failure [`crate::error::PegExpected`] grammar expectations.
///
/// # Arguments
/// * `diag` - [`PegDiagnostic`] recorded during CST parsing.
///
/// # Returns
/// Corresponding [`CmdError`] variant.
#[must_use]
pub fn strict_diag_to_cmd_error(diag: &PegDiagnostic) -> CmdError {
    if let Some(ref kind) = diag.misuse_kind {
        return CmdError::ProbableSyntaxMisuse {
            span: diag.span,
            kind: Box::new(kind.clone()),
            message: diag.message.clone(),
        };
    }
    if diag.message == "The input line is too long." {
        return CmdError::LineTooLong { span: diag.span };
    }
    if let Some(sw) = diag.message.strip_prefix("Invalid switch - ") {
        return CmdError::InvalidSwitch {
            span: diag.span,
            switch: sw.to_owned(),
        };
    }
    if let Some(tok) = diag.message.strip_suffix(" was unexpected at this time.") {
        return CmdError::UnexpectedToken {
            span: diag.span,
            token: tok.trim_matches('`').to_owned(),
        };
    }
    if !diag.expected.is_empty() {
        return CmdError::PegSyntaxError {
            span: diag.span,
            found: diag.message.clone(),
            expected: diag.expected.clone(),
        };
    }
    CmdError::SyntaxError { span: diag.span }
}

/// Lowers a statement [`CstNode`] into an AST [`Statement`] with full [`WordPart`]s.
///
/// # Arguments
/// * `node` - Statement [`CstNode`].
/// * `labels_out` - Label accumulator.
///
/// # Returns
/// `Some(Statement)` if valid, or `None` for unrecoverable `ErrorNode`s.
pub fn lower_statement_cst_node(
    node: &CstNode,
    labels_out: &mut Vec<LabelNode>,
) -> Option<Statement> {
    lower_statement_cst_node_with_mode(node, labels_out, WordPartsMode::PopulateSubwordParts)
}

/// Computes `node`'s logical content [`Span`] excluding any trailing [`SyntaxKind::Newline`] token.
///
/// # Arguments
/// * `node` - Source [`CstNode`].
///
/// # Returns
/// [`Span`] from `node.span.start` through the end of the last non-newline child element.
#[must_use]
fn node_content_span(node: &CstNode) -> Span {
    let end = node
        .children
        .iter()
        .rev()
        .find(|el| el.kind() != SyntaxKind::Newline)
        .map_or(node.span.start, |el| el.span().end);
    Span::new(node.span.source_id, node.span.start, end)
}

/// Lowers a statement [`CstNode`] into an AST [`Statement`] using `parts_mode`.
///
/// # Arguments
/// * `node` - Statement [`CstNode`].
/// * `labels_out` - Label accumulator.
/// * `parts_mode` - [`WordPartsMode`] controlling sub-word allocation.
///
/// # Returns
/// `Some(Statement)` if valid, or `None` on `ErrorNode`.
pub fn lower_statement_cst_node_with_mode(
    node: &CstNode,
    labels_out: &mut Vec<LabelNode>,
    parts_mode: WordPartsMode,
) -> Option<Statement> {
    let content_span = node_content_span(node);
    match node.kind {
        SyntaxKind::EmptyStatement => Some(Statement::Empty(content_span)),
        SyntaxKind::DoubleColonComment => {
            let text = node
                .children
                .iter()
                .filter_map(CstElement::as_token)
                .find(|t| t.kind == SyntaxKind::CommentTextToken)
                .map_or_else(String::new, |t| t.text.clone());
            let raw_body = format!(":{text}");
            let lbl = LabelNode {
                name: LabelName::new(&raw_body),
                raw_body,
                is_double_colon: true,
                has_invalid_label_chars: false,
                next_line_offset: node.span.end,
                span: content_span,
            };
            labels_out.push(lbl.clone());
            Some(Statement::Label(lbl))
        }
        SyntaxKind::LabelStatement => {
            let lbl = lower_label_statement_cst_node(node, content_span);
            labels_out.push(lbl.clone());
            Some(Statement::Label(lbl))
        }
        SyntaxKind::RemStatement => {
            let suppressed = node.children.iter().any(|e| e.kind() == SyntaxKind::AtSign);
            let mut comment_text = String::new();
            for tok in node.children.iter().filter_map(CstElement::as_token) {
                if tok.kind == SyntaxKind::CommentTextToken {
                    comment_text.push_str(&tok.text);
                }
            }
            Some(Statement::Rem(RemNode {
                echo_suppression: if suppressed {
                    EchoSuppression::Suppressed
                } else {
                    EchoSuppression::NotSuppressed
                },
                comment_text,
                span: content_span,
            }))
        }
        SyntaxKind::BinaryCommandExpr
        | SyntaxKind::IfStatement
        | SyntaxKind::ForStatement
        | SyntaxKind::CompoundBlock
        | SyntaxKind::SimpleCommand => {
            lower_command_expr_cst_node(node, labels_out, parts_mode).map(Statement::Command)
        }
        SyntaxKind::Script
        | SyntaxKind::IfConditionNode
        | SyntaxKind::ElseClauseNode
        | SyntaxKind::ForSetNode
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
        | SyntaxKind::CommentTextToken => {
            for el in &node.children {
                if let CstElement::Node(sub) = el
                    && let Some(expr) = lower_command_expr_cst_node(sub, labels_out, parts_mode)
                {
                    return Some(Statement::Command(expr));
                }
            }
            None
        }
    }
}

/// Lowers a `LabelStatement` [`CstNode`] into a [`LabelNode`].
///
/// # Arguments
/// * `node` - `LabelStatement` [`CstNode`].
/// * `content_span` - Trimmed content [`Span`].
///
/// # Returns
/// Lowered [`LabelNode`].
fn lower_label_statement_cst_node(node: &CstNode, content_span: Span) -> LabelNode {
    let mut raw_body = String::new();
    let mut seen_colon = false;
    let mut name_str = String::new();
    let mut has_comment_tail = false;
    for tok in node.children.iter().filter_map(CstElement::as_token) {
        if tok.kind == SyntaxKind::Newline {
            continue;
        }
        if seen_colon {
            raw_body.push_str(&tok.text);
        } else if tok.kind == SyntaxKind::Colon {
            seen_colon = true;
        }
        if tok.kind == SyntaxKind::LiteralToken {
            name_str.clone_from(&tok.text);
        } else if tok.kind == SyntaxKind::CommentTextToken {
            has_comment_tail = true;
        }
    }
    LabelNode {
        name: LabelName::new(&name_str),
        raw_body,
        is_double_colon: false,
        has_invalid_label_chars: has_comment_tail,
        next_line_offset: node.span.end,
        span: content_span,
    }
}

/// Lowers a `BinaryCommandExpr` [`CstNode`] into a [`CommandExpr`].
///
/// # Arguments
/// * `node` - `BinaryCommandExpr` [`CstNode`].
/// * `labels_out` - Label accumulator for interior block labels.
/// * `parts_mode` - [`WordPartsMode`] controlling sub-word allocation.
///
/// # Returns
/// `Some(CommandExpr)` if valid.
fn lower_binary_expr_cst_node(
    node: &CstNode,
    labels_out: &mut Vec<LabelNode>,
    parts_mode: WordPartsMode,
) -> Option<CommandExpr> {
    let mut child_nodes = node.children.iter().filter_map(CstElement::as_node);
    let left_cst = child_nodes.next()?;
    let right_cst = child_nodes.next()?;
    let op_tok = node
        .children
        .iter()
        .filter_map(CstElement::as_token)
        .find(|t| t.kind == SyntaxKind::OperatorToken)?;
    let left = Box::new(lower_command_expr_cst_node(
        left_cst, labels_out, parts_mode,
    )?);
    let right = Box::new(lower_command_expr_cst_node(
        right_cst, labels_out, parts_mode,
    )?);
    let op_span = op_tok.span;
    let span = node_content_span(node);
    match op_tok.text.as_str() {
        "&" => Some(CommandExpr::Seq {
            left,
            right,
            op_span,
            span,
        }),
        "&&" => Some(CommandExpr::And {
            left,
            right,
            op_span,
            span,
        }),
        "||" => Some(CommandExpr::Or {
            left,
            right,
            op_span,
            span,
        }),
        "|" => Some(CommandExpr::Pipe {
            left,
            right,
            op_span,
            span,
        }),
        _ => None,
    }
}

/// Lowers a `CompoundBlock` [`CstNode`] into [`CommandExpr::Block`].
///
/// # Arguments
/// * `node` - `CompoundBlock` [`CstNode`].
/// * `labels_out` - Label accumulator for interior block labels.
/// * `parts_mode` - [`WordPartsMode`] controlling sub-word allocation.
///
/// # Returns
/// Lowered [`CommandExpr::Block`].
fn lower_compound_block_cst_node(
    node: &CstNode,
    labels_out: &mut Vec<LabelNode>,
    parts_mode: WordPartsMode,
) -> CommandExpr {
    let suppressed = node.children.iter().any(|e| e.kind() == SyntaxKind::AtSign);
    let mut body = Vec::new();
    let mut redirections = Vec::new();
    for sub in node.children.iter().filter_map(CstElement::as_node) {
        if sub.kind == SyntaxKind::RedirectionNode {
            redirections.extend(lower_redirection_cst_node(sub, parts_mode));
        } else {
            body.extend(lower_statement_cst_node_with_mode(
                sub, labels_out, parts_mode,
            ));
        }
    }
    CommandExpr::Block(CompoundBlock {
        echo_suppression: if suppressed {
            EchoSuppression::Suppressed
        } else {
            EchoSuppression::NotSuppressed
        },
        body,
        redirections,
        span: node_content_span(node),
    })
}

/// Lowers a command-expression [`CstNode`] into a [`CommandExpr`].
///
/// # Arguments
/// * `node` - Expression [`CstNode`].
/// * `labels_out` - Label accumulator for interior block labels.
/// * `parts_mode` - [`WordPartsMode`] controlling sub-word allocation.
///
/// # Returns
/// `Some(CommandExpr)` if valid.
pub fn lower_command_expr_cst_node(
    node: &CstNode,
    labels_out: &mut Vec<LabelNode>,
    parts_mode: WordPartsMode,
) -> Option<CommandExpr> {
    match node.kind {
        SyntaxKind::BinaryCommandExpr => lower_binary_expr_cst_node(node, labels_out, parts_mode),
        SyntaxKind::CompoundBlock => {
            Some(lower_compound_block_cst_node(node, labels_out, parts_mode))
        }
        SyntaxKind::IfStatement => lower_if_cst_node(node, labels_out, parts_mode),
        SyntaxKind::ForStatement => lower_for_cst_node(node, labels_out, parts_mode),
        SyntaxKind::SimpleCommand => lower_simple_command_cst_node(node, parts_mode),
        SyntaxKind::RemStatement => {
            let suppressed = node.children.iter().any(|e| e.kind() == SyntaxKind::AtSign);
            let span = node_content_span(node);
            Some(CommandExpr::Simple(SimpleCommand {
                echo_suppression: if suppressed {
                    EchoSuppression::Suppressed
                } else {
                    EchoSuppression::NotSuppressed
                },
                program: SpannedWord::new("REM".to_owned(), span),
                echo_delimiter: None,
                arguments: Vec::new(),
                raw_tail: String::new(),
                raw_tail_span: Span::new(span.source_id, span.end, span.end),
                redirections: Vec::new(),
                span,
            }))
        }
        SyntaxKind::Script
        | SyntaxKind::EmptyStatement
        | SyntaxKind::LabelStatement
        | SyntaxKind::DoubleColonComment
        | SyntaxKind::IfConditionNode
        | SyntaxKind::ElseClauseNode
        | SyntaxKind::ForSetNode
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
        | SyntaxKind::CommentTextToken => {
            for el in &node.children {
                if let CstElement::Node(sub) = el
                    && let Some(expr) = lower_command_expr_cst_node(sub, labels_out, parts_mode)
                {
                    return Some(expr);
                }
            }
            None
        }
    }
}

/// Lowers an `IfStatement` [`CstNode`] into [`CommandExpr::If`].
///
/// # Arguments
/// * `node` - `IfStatement` [`CstNode`].
/// * `labels_out` - Label accumulator.
/// * `parts_mode` - [`WordPartsMode`].
///
/// # Returns
/// `Some(CommandExpr::If)` if valid.
fn lower_if_cst_node(
    node: &CstNode,
    labels_out: &mut Vec<LabelNode>,
    parts_mode: WordPartsMode,
) -> Option<CommandExpr> {
    let suppressed = node.children.iter().any(|e| e.kind() == SyntaxKind::AtSign);
    let mut case_sensitivity = CaseSensitivity::Sensitive;
    let mut negated = NegationMode::Normal;
    let mut cond_cst: Option<&CstNode> = None;
    let mut then_cst: Option<&CstNode> = None;
    let mut else_cst: Option<&CstNode> = None;

    for el in &node.children {
        match el {
            CstElement::Token(tok) => {
                if tok.kind == SyntaxKind::SwitchToken {
                    case_sensitivity = CaseSensitivity::Insensitive;
                } else if tok.kind == SyntaxKind::Keyword && tok.text.eq_ignore_ascii_case("NOT") {
                    negated = NegationMode::Negated;
                }
            }
            CstElement::Node(sub) => {
                if sub.kind == SyntaxKind::IfConditionNode {
                    cond_cst = Some(sub);
                } else if sub.kind == SyntaxKind::ElseClauseNode {
                    else_cst = sub.children.iter().find_map(CstElement::as_node);
                } else {
                    then_cst = Some(sub);
                }
            }
        }
    }

    let condition = lower_if_condition_cst_node(cond_cst?, parts_mode)?;
    let then_branch = Box::new(lower_command_expr_cst_node(
        then_cst?, labels_out, parts_mode,
    )?);
    let else_branch = else_cst
        .and_then(|ec| lower_command_expr_cst_node(ec, labels_out, parts_mode))
        .map(Box::new);

    let has_dangling_else = else_branch.is_none() && expr_has_dangling_else_arg(&then_branch);

    Some(CommandExpr::If(Box::new(IfStatement {
        echo_suppression: if suppressed {
            EchoSuppression::Suppressed
        } else {
            EchoSuppression::NotSuppressed
        },
        case_sensitivity,
        negated,
        condition,
        then_branch,
        else_branch,
        has_dangling_else,
        span: node_content_span(node),
    })))
}

/// Checks whether an unparenthesized `then_branch` swallowed a literal `ELSE` argument (`CMD1005`).
///
/// # Arguments
/// * `expr` - Lowered `then` [`CommandExpr`].
///
/// # Returns
/// `true` if `expr` is a `SimpleCommand` with an unquoted `"ELSE"` argument.
#[must_use]
fn expr_has_dangling_else_arg(expr: &CommandExpr) -> bool {
    match expr {
        CommandExpr::Simple(sc) => sc
            .arguments
            .iter()
            .any(|a| !a.quoted && a.text.eq_ignore_ascii_case("ELSE")),
        CommandExpr::Seq { right, .. }
        | CommandExpr::And { right, .. }
        | CommandExpr::Or { right, .. }
        | CommandExpr::Pipe { right, .. } => expr_has_dangling_else_arg(right),
        CommandExpr::Block(_) | CommandExpr::If(_) | CommandExpr::For(_) => false,
    }
}

/// Lowers an `IfConditionNode` [`CstNode`] into [`IfCondition`], using `parse_cmd_int` on `ERRORLEVEL`.
///
/// # Arguments
/// * `node` - `IfConditionNode` [`CstNode`].
/// * `parts_mode` - [`WordPartsMode`].
///
/// # Returns
/// `Some(IfCondition)` if valid.
fn lower_if_condition_cst_node(node: &CstNode, parts_mode: WordPartsMode) -> Option<IfCondition> {
    let words: Vec<SpannedWord> = node
        .children
        .iter()
        .filter_map(CstElement::as_node)
        .filter(|n| n.kind == SyntaxKind::WordNode)
        .map(|wn| lower_word_cst_node_with_mode(wn, parts_mode))
        .collect();

    if let Some(first_kw) = node
        .children
        .iter()
        .filter_map(CstElement::as_token)
        .find(|t| t.kind == SyntaxKind::Keyword)
    {
        let upper = first_kw.text.to_ascii_uppercase();
        if let [word_ref] = words.as_slice() {
            let word = word_ref.clone();
            return match upper.as_str() {
                "ERRORLEVEL" => {
                    let threshold =
                        parse_cmd_int(word.unquoted()).and_then(|v| i32::try_from(v).ok());
                    Some(IfCondition::ErrorLevel {
                        threshold,
                        raw_token: word,
                    })
                }
                "EXIST" => Some(IfCondition::Exist { path_pattern: word }),
                "DEFINED" => Some(IfCondition::Defined { var_name: word }),
                _ => {
                    let version = word.unquoted().parse::<u32>().unwrap_or(u32::MAX);
                    Some(IfCondition::CmdExtVersion {
                        version,
                        raw_token: word,
                    })
                }
            };
        }
    }

    let mut w_iter = words.into_iter();
    let left = w_iter.next()?;
    let right = w_iter.next()?;
    let op_tok = node
        .children
        .iter()
        .filter_map(CstElement::as_token)
        .find(|t| matches!(t.kind, SyntaxKind::OperatorToken | SyntaxKind::Keyword))?;
    let op = if op_tok.text == "=" {
        ComparisonOp::DoubleEquals
    } else {
        ComparisonOp::from_keyword(&op_tok.text)?
    };
    Some(IfCondition::Compare {
        left,
        op,
        op_span: op_tok.span,
        right,
    })
}

/// Lowers a `ForStatement` [`CstNode`] into [`CommandExpr::For`].
///
/// # Arguments
/// * `node` - `ForStatement` [`CstNode`].
/// * `labels_out` - Label accumulator.
/// * `parts_mode` - [`WordPartsMode`].
///
/// # Returns
/// `Some(CommandExpr::For)` if valid.
fn lower_for_cst_node(
    node: &CstNode,
    labels_out: &mut Vec<LabelNode>,
    parts_mode: WordPartsMode,
) -> Option<CommandExpr> {
    let suppressed = node.children.iter().any(|e| e.kind() == SyntaxKind::AtSign);
    let mut switch_str: Option<String> = None;
    let mut header_words: Vec<SpannedWord> = Vec::new();
    let mut var_tok_opt: Option<&CstToken> = None;
    let mut set_node_opt: Option<&CstNode> = None;
    let mut body_node_opt: Option<&CstNode> = None;

    for el in &node.children {
        match el {
            CstElement::Token(tok) => {
                if tok.kind == SyntaxKind::SwitchToken {
                    switch_str = Some(tok.text.clone());
                } else if tok.kind == SyntaxKind::ForVarToken {
                    var_tok_opt = Some(tok);
                }
            }
            CstElement::Node(sub) => {
                if sub.kind == SyntaxKind::WordNode {
                    header_words.push(lower_word_cst_node_with_mode(sub, parts_mode));
                } else if sub.kind == SyntaxKind::ForSetNode {
                    set_node_opt = Some(sub);
                } else {
                    body_node_opt = Some(sub);
                }
            }
        }
    }

    let var_tok = var_tok_opt?;
    let var_letter = var_tok
        .text
        .trim_start_matches('%')
        .chars()
        .next()
        .unwrap_or('I');
    let variable = ForVarName::from_char(var_letter).unwrap_or(ForVarName(b'I'));

    let set_cst = set_node_opt?;
    let set_words: Vec<SpannedWord> = set_cst
        .children
        .iter()
        .filter_map(CstElement::as_node)
        .filter(|n| n.kind == SyntaxKind::WordNode)
        .map(|wn| lower_word_cst_node_with_mode(wn, parts_mode))
        .collect();

    let mut in_set_raw = String::new();
    for el in &set_cst.children {
        if !matches!(el.kind(), SyntaxKind::OpenParen | SyntaxKind::CloseParen) {
            append_lowered_element_text(el, &mut in_set_raw);
        }
    }

    let variant = lower_for_variant(switch_str.as_deref(), header_words)?;

    lower_command_expr_cst_node(body_node_opt?, labels_out, parts_mode).map(|body_expr| {
        CommandExpr::For(Box::new(ForStatement {
            echo_suppression: if suppressed {
                EchoSuppression::Suppressed
            } else {
                EchoSuppression::NotSuppressed
            },
            variant,
            variable,
            raw_variable_token: var_tok.text.clone(),
            variable_span: var_tok.span,
            in_set: set_words,
            in_set_raw,
            in_set_span: set_cst.span,
            body: Box::new(body_expr),
            span: node_content_span(node),
        }))
    })
}

/// Resolves the [`ForVariant`] from an optional `FOR` switch token and header option words.
///
/// # Arguments
/// * `switch_str` - Optional raw switch text (e.g., `"/D"`, `"/R"`, `"/L"`, `"/F"`).
/// * `header_words` - Lowered option/path words appearing before the loop variable.
///
/// # Returns
/// `Some(ForVariant)` when `switch_str` is empty or one of `/D`, `/R`, `/L`, `/F`; `None` on invalid switches.
#[must_use]
fn lower_for_variant(
    switch_str: Option<&str>,
    header_words: Vec<SpannedWord>,
) -> Option<ForVariant> {
    match switch_str.map(str::to_ascii_uppercase).as_deref() {
        None => Some(ForVariant::StandardFiles),
        Some("/D") => Some(ForVariant::DirectoriesOnly),
        Some("/R") => Some(ForVariant::Recursive {
            root_path: header_words.into_iter().next(),
        }),
        Some("/L") => Some(ForVariant::NumericSequence),
        Some(sw) if sw == "/F" || sw.starts_with("/F\"") => {
            let raw_sw = switch_str.unwrap_or("");
            let inline_opts = raw_sw.get(2..).unwrap_or("").trim_matches('"');
            let opt_str = if inline_opts.is_empty() {
                header_words.first().map_or("", SpannedWord::unquoted)
            } else {
                inline_opts
            };
            let opts = if opt_str.is_empty() {
                ForFOptions::default()
            } else {
                ForFOptions::parse(opt_str)
            };
            Some(ForVariant::ParsedLines(opts))
        }
        Some(_) => None,
    }
}

/// Lowers a `SimpleCommand` [`CstNode`] into [`CommandExpr::Simple`], unescaping unquoted
/// `CaretEscapeToken`s (`^c` -> `c`) in `raw_tail` while preserving quoted carets verbatim.
///
/// # Arguments
/// * `node` - `SimpleCommand` [`CstNode`].
/// * `parts_mode` - [`WordPartsMode`].
///
/// # Returns
/// `Some(CommandExpr::Simple)` if valid.
fn lower_simple_command_cst_node(node: &CstNode, parts_mode: WordPartsMode) -> Option<CommandExpr> {
    let suppressed = node.children.iter().any(|e| e.kind() == SyntaxKind::AtSign);
    let mut program_opt: Option<SpannedWord> = None;
    let mut echo_delimiter: Option<char> = None;
    let mut arguments: Vec<SpannedWord> = Vec::new();
    let mut redirections: Vec<Redirection> = Vec::new();
    let mut prog_node_idx: usize = 0;

    for (idx, el) in node.children.iter().enumerate() {
        match el {
            CstElement::Token(tok) if tok.kind == SyntaxKind::EchoDelimiterToken => {
                echo_delimiter = tok.text.chars().next();
            }
            CstElement::Token(_) => {}
            CstElement::Node(sub) => {
                if sub.kind == SyntaxKind::RedirectionNode {
                    redirections.extend(lower_redirection_cst_node(sub, parts_mode));
                } else {
                    let word = lower_word_cst_node_with_mode(sub, parts_mode);
                    if program_opt.is_none() {
                        program_opt = Some(word);
                        prog_node_idx = idx;
                    } else {
                        arguments.push(word);
                    }
                }
            }
        }
    }

    let program = program_opt?;
    let mut raw_tail = String::new();
    let mut tail_start_off: Option<ByteOffset> = None;
    let mut tail_end_off = program.span.end;
    let mut first_el = true;

    let tail_elements = node
        .children
        .get(prog_node_idx.saturating_add(1)..)
        .unwrap_or(&[]);
    for el in tail_elements {
        if matches!(
            el.kind(),
            SyntaxKind::RedirectionNode | SyntaxKind::EchoDelimiterToken
        ) {
            if el.kind() == SyntaxKind::EchoDelimiterToken {
                first_el = false;
            }
            continue;
        }
        if first_el && el.kind() == SyntaxKind::Whitespace {
            let ws_text = el.as_token().map_or("", |t| t.text.as_str());
            let ws_span = el.span();
            let trimmed = ws_text.trim_start_matches([' ', TAB_CHAR]);
            first_el = false;
            if trimmed.is_empty() {
                continue;
            }
            let skipped_bytes = ws_text.len().saturating_sub(trimmed.len());
            tail_start_off = Some(ws_span.start.saturating_add(skipped_bytes));
            tail_end_off = ws_span.end;
            raw_tail.push_str(trimmed);
            continue;
        }
        if el.kind() == SyntaxKind::Newline {
            continue;
        }
        first_el = false;
        if tail_start_off.is_none() {
            tail_start_off = Some(el.span().start);
        }
        tail_end_off = el.span().end;
        append_lowered_element_text(el, &mut raw_tail);
    }

    let raw_tail_span = match tail_start_off {
        Some(s) => Span::new(node.span.source_id, s, tail_end_off),
        None => Span::new(node.span.source_id, program.span.end, program.span.end),
    };

    Some(CommandExpr::Simple(SimpleCommand {
        echo_suppression: if suppressed {
            EchoSuppression::Suppressed
        } else {
            EchoSuppression::NotSuppressed
        },
        program,
        echo_delimiter,
        arguments,
        raw_tail,
        raw_tail_span,
        redirections,
        span: node_content_span(node),
    }))
}

/// Appends lowered text of `el` into `out`, stripping `CaretLineContinuation`s, unescaping
/// unquoted `CaretEscapeToken` (`^c` -> `c`), and preserving `QuotedStringNode` contents verbatim.
///
/// # Arguments
/// * `el` - [`CstElement`] to append.
/// * `out` - Output string buffer.
fn append_lowered_element_text(el: &CstElement, out: &mut String) {
    match el {
        CstElement::Token(tok) => {
            if matches!(
                tok.kind,
                SyntaxKind::CaretLineContinuation | SyntaxKind::BrokenCaretContinuation
            ) {
                // Physical caret continuation trivia is omitted from lowered text
            } else if tok.kind == SyntaxKind::CaretEscapeToken {
                out.push_str(tok.text.get(1..).unwrap_or(""));
            } else {
                out.push_str(&tok.text);
            }
        }
        CstElement::Node(sub) if sub.kind == SyntaxKind::QuotedStringNode => {
            append_quoted_node_text(sub, out);
        }
        CstElement::Node(sub) => {
            for child in &sub.children {
                append_lowered_element_text(child, out);
            }
        }
    }
}

/// Appends the contents of a `QuotedStringNode` into `out` (stripping only physical `CaretLineContinuation`s).
///
/// # Arguments
/// * `qnode` - `QuotedStringNode` [`CstNode`].
/// * `out` - Output string buffer.
fn append_quoted_node_text(qnode: &CstNode, out: &mut String) {
    for tok in qnode.children.iter().filter_map(CstElement::as_token) {
        if tok.kind != SyntaxKind::CaretLineContinuation {
            out.push_str(&tok.text);
        }
    }
}

/// Lowers a `RedirectionNode` [`CstNode`] into an AST [`Redirection`].
///
/// # Arguments
/// * `node` - `RedirectionNode` [`CstNode`].
/// * `parts_mode` - [`WordPartsMode`].
///
/// # Returns
/// `Some(Redirection)` if valid.
fn lower_redirection_cst_node(node: &CstNode, parts_mode: WordPartsMode) -> Option<Redirection> {
    let op_tok = node
        .children
        .iter()
        .filter_map(CstElement::as_token)
        .find(|t| t.kind == SyntaxKind::RedirectOpToken)?;
    let op_str = op_tok.text.as_str();
    let first_ch = op_str.chars().next()?;
    let (explicit_fd, op_rest) = if first_ch.is_ascii_digit() {
        let fd_num = (first_ch as u8).saturating_sub(b'0');
        (FileDescriptor::new(fd_num), op_str.get(1..).unwrap_or(""))
    } else {
        (None, op_str)
    };

    let is_input = op_rest.starts_with('<');
    let source_handle = explicit_fd.unwrap_or(if is_input {
        FileDescriptor::STDIN
    } else {
        FileDescriptor::STDOUT
    });

    if let Some(dup_digit_str) = op_rest
        .strip_prefix(">&")
        .or_else(|| op_rest.strip_prefix("<&"))
    {
        let dup_ch = dup_digit_str.chars().next()?;
        let target_fd = FileDescriptor::new((dup_ch as u8).saturating_sub(b'0'))?;
        let kind = if is_input {
            RedirectionKind::DuplicateInput(target_fd)
        } else {
            RedirectionKind::DuplicateOutput(target_fd)
        };
        return Some(Redirection {
            source_handle,
            kind,
            span: node.span,
        });
    }

    let target_cst = node
        .children
        .iter()
        .filter_map(CstElement::as_node)
        .find(|n| n.kind == SyntaxKind::WordNode)?;
    let target_word = lower_word_cst_node_with_mode(target_cst, parts_mode);
    let kind = if is_input {
        RedirectionKind::ReadFromFile(target_word)
    } else if op_rest.starts_with(">>") {
        RedirectionKind::WriteAppend(target_word)
    } else {
        RedirectionKind::WriteTruncate(target_word)
    };

    Some(Redirection {
        source_handle,
        kind,
        span: node.span,
    })
}

/// Lowers a `WordNode` or `SetAssignmentNode` into a [`SpannedWord`] with full [`WordPart`]s.
///
/// # Arguments
/// * `node` - Word [`CstNode`].
///
/// # Returns
/// Lowered [`SpannedWord`].
#[must_use]
pub fn lower_word_cst_node(node: &CstNode) -> SpannedWord {
    lower_word_cst_node_with_mode(node, WordPartsMode::PopulateSubwordParts)
}

/// Lowers a `WordNode` or `SetAssignmentNode` into a [`SpannedWord`] honoring `parts_mode`.
///
/// # Arguments
/// * `node` - Word [`CstNode`].
/// * `parts_mode` - [`WordPartsMode`] (`PopulateSubwordParts` vs `Lightweight`).
///
/// # Returns
/// Lowered [`SpannedWord`].
#[must_use]
pub fn lower_word_cst_node_with_mode(node: &CstNode, parts_mode: WordPartsMode) -> SpannedWord {
    let mut text = String::new();
    let mut quoted = false;
    let mut has_unescaped_special = false;
    let mut parts: Vec<WordPart> = Vec::new();
    let populate_parts = parts_mode == WordPartsMode::PopulateSubwordParts;

    for el in &node.children {
        match el {
            CstElement::Token(tok) => {
                if matches!(
                    tok.kind,
                    SyntaxKind::CaretLineContinuation | SyntaxKind::BrokenCaretContinuation
                ) {
                    // Omit physical caret continuation trivia
                } else if tok.kind == SyntaxKind::CaretEscapeToken {
                    has_unescaped_special = true;
                    let unescaped: String = tok.text.chars().skip(1).collect();
                    text.push_str(&unescaped);
                    if populate_parts {
                        parts.push(WordPart::new(
                            WordPartKind::CaretEscape,
                            tok.text.clone(),
                            tok.span,
                        ));
                    }
                } else {
                    text.push_str(&tok.text);
                    if populate_parts {
                        parts.push(token_to_word_part(tok));
                    }
                }
            }
            CstElement::Node(qnode) => {
                quoted = true;
                for qt in qnode.children.iter().filter_map(CstElement::as_token) {
                    if qt.kind != SyntaxKind::CaretLineContinuation {
                        text.push_str(&qt.text);
                        if populate_parts {
                            parts.push(token_to_word_part(qt));
                        }
                    }
                }
            }
        }
    }

    SpannedWord::with_parts(
        text,
        node.span,
        if quoted {
            crate::types::QuoteMode::InQuotes
        } else {
            crate::types::QuoteMode::Unquoted
        },
        if has_unescaped_special {
            crate::parser::ast::SpecialCharPresence::HasUnescapedSpecial
        } else {
            crate::parser::ast::SpecialCharPresence::Plain
        },
        parts,
    )
}

/// Converts a sub-word [`CstToken`] into an AST [`WordPart`].
///
/// # Arguments
/// * `tok` - Sub-word [`CstToken`].
///
/// # Returns
/// Lowered [`WordPart`].
#[must_use]
fn token_to_word_part(tok: &CstToken) -> WordPart {
    let kind = match tok.kind {
        SyntaxKind::DoubleQuote => WordPartKind::Quoted,
        SyntaxKind::EnvVarToken => WordPartKind::EnvVar,
        SyntaxKind::DelayedVarToken => WordPartKind::DelayedVar,
        SyntaxKind::PositionalParamToken => WordPartKind::PositionalParam,
        SyntaxKind::ForVarToken => WordPartKind::ForVar,
        SyntaxKind::InvalidModifierVarToken => WordPartKind::InvalidModifierVar,
        SyntaxKind::PercentLiteralToken => WordPartKind::PercentLiteral,
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
        | SyntaxKind::EchoDelimiterToken
        | SyntaxKind::LiteralToken
        | SyntaxKind::CaretEscapeToken
        | SyntaxKind::UnclosedVarToken
        | SyntaxKind::CommentTextToken => WordPartKind::Literal,
    };
    WordPart::new(kind, tok.text.clone(), tok.span)
}

#[cfg(test)]
/// Unit tests for deterministic CST-to-AST lowering.
mod tests {
    use super::*;
    use crate::parser::peg::parse_script_cst;
    use crate::reader::char_map::LogicalLineBuffer;
    use crate::types::CRLF;

    /// Exercises `parse_single_word_parts`, `lower_statement_cst_node`, `lower_word_cst_node`,
    /// `LineTooLong` diagnostics, `@`-suppressed blocks/`IF`/`FOR`, all `ComparisonOp` variants,
    /// dangling `ELSE` on pipelines, inline `FOR /F` options, and `CaretEscape` word parts.
    #[test]
    fn test_lower_cst_to_ast_all_constructs_and_word_parts() {
        assert_eq!(parse_single_word_parts(SourceId(0), &[]).len(), 0);
        let ws_only = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "   ");
        assert_eq!(
            parse_single_word_parts(SourceId(0), &ws_only.chars).len(),
            0
        );

        let rich_word =
            LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "\"q\"^&%V%!D!%1");
        let parts = parse_single_word_parts(SourceId(0), &rich_word.chars);
        assert!(parts.iter().any(|p| p.kind == WordPartKind::CaretEscape));
        assert!(parts.iter().any(|p| p.kind == WordPartKind::EnvVar));
        assert!(parts.iter().any(|p| p.kind == WordPartKind::DelayedVar));

        // Overlong line -> CmdError::LineTooLong via strict_diag_to_cmd_error
        let overlong_buf =
            LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), &"x".repeat(8200));
        assert!(matches!(
            crate::parser::phase2::parse_logical_line_statement(
                &overlong_buf,
                SourceId(0),
                ByteOffset(0)
            ),
            Err(CmdError::LineTooLong { .. })
        ));

        // Suppressed `@(...)`, `@if`, `@for`, blank line, comparisons, pipe dangling ELSE, FOR /F inline
        let script = [
            "",
            "@(echo blk) > NUL",
            "@if 1 equ 1 echo equ",
            "if 1 neq 2 echo neq",
            "if 1 lss 2 echo lss",
            "if 1 leq 2 echo leq",
            "if 2 geq 1 echo geq",
            "if 1 bogus_op 2 echo nope",
            "if 1==1 echo a | echo b else echo c",
            r#"if 1==1 echo a | echo "ELSE" else echo c"#,
            "if 1==1 |",
            "for %%A in (a) do |",
            r#"@for /F"tokens=1" %%A in ("hi") do echo %%A"#,
            "for /F %%A in (\"hi\") do echo %%A",
            "for /R C:\\ %%A in (*.txt) do echo %%A",
            "if 1==1 ( echo a ) trailing_err",
            "( echo a ) trailing_err",
            &format!("echo \"q^{CRLF}cont\" a^{CRLF}b ^&"),
        ]
        .join(CRLF);
        let cst = parse_script_cst(SourceId(0), &script, ExecutionContext::BatchFile);
        let ast = lower_cst_to_ast(&cst);
        assert!(
            ast.statements
                .iter()
                .any(|s| matches!(s, Statement::Empty(_)))
        );

        let mut lbls = Vec::new();
        let lowered_count = cst
            .root
            .children
            .iter()
            .filter_map(CstElement::as_node)
            .filter_map(|node| lower_statement_cst_node(node, &mut lbls))
            .count();
        assert!(lowered_count >= 10);
        assert_eq!(lbls.len(), 0);
        let word_cst = parse_script_cst(SourceId(0), "echo ^&", ExecutionContext::BatchFile);
        let mut lowered_words = Vec::new();
        for d in word_cst.root.descendant_nodes() {
            if d.kind == SyntaxKind::WordNode {
                lowered_words.push(lower_word_cst_node(d).text);
            }
        }
        assert_eq!(lowered_words, vec!["echo".to_owned(), "&".to_owned()]);
    }

    /// Verifies defensive `None` lowering on incomplete `BinaryCommandExpr` and `IfStatement` CST nodes.
    #[test]
    fn test_lower_incomplete_binary_and_if_cst_nodes() {
        let sp = Span::dummy();
        let mk_tok = |kind: SyntaxKind, txt: &str| {
            CstElement::Token(CstToken::new(kind, txt.to_owned(), sp))
        };
        let mk_word = |txt: &str| {
            CstElement::Node(CstNode::new(
                SyntaxKind::WordNode,
                sp,
                vec![mk_tok(SyntaxKind::LiteralToken, txt)],
            ))
        };

        let mut dummy_labels = Vec::new();
        for children in [
            vec![],
            vec![CstElement::Node(CstNode::new(
                SyntaxKind::ErrorNode,
                sp,
                vec![],
            ))],
            vec![
                CstElement::Node(CstNode::new(
                    SyntaxKind::SimpleCommand,
                    sp,
                    vec![mk_word("echo")],
                )),
                CstElement::Node(CstNode::new(
                    SyntaxKind::SimpleCommand,
                    sp,
                    vec![mk_word("ok")],
                )),
            ],
            vec![
                CstElement::Node(CstNode::new(SyntaxKind::ErrorNode, sp, vec![])),
                mk_tok(SyntaxKind::OperatorToken, "&"),
                CstElement::Node(CstNode::new(
                    SyntaxKind::SimpleCommand,
                    sp,
                    vec![mk_word("ok")],
                )),
            ],
            vec![
                CstElement::Node(CstNode::new(
                    SyntaxKind::SimpleCommand,
                    sp,
                    vec![mk_word("echo")],
                )),
                mk_tok(SyntaxKind::OperatorToken, "&"),
                CstElement::Node(CstNode::new(SyntaxKind::ErrorNode, sp, vec![])),
            ],
            vec![
                CstElement::Node(CstNode::new(
                    SyntaxKind::SimpleCommand,
                    sp,
                    vec![mk_word("echo")],
                )),
                mk_tok(SyntaxKind::OperatorToken, "??"),
                CstElement::Node(CstNode::new(
                    SyntaxKind::SimpleCommand,
                    sp,
                    vec![mk_word("ok")],
                )),
            ],
        ] {
            let n = CstNode::new(SyntaxKind::BinaryCommandExpr, sp, children);
            assert_eq!(
                lower_command_expr_cst_node(&n, &mut dummy_labels, WordPartsMode::Lightweight),
                None
            );
        }
    }

    /// Verifies defensive `None` lowering on incomplete `IfStatement` and `IfConditionNode` CST nodes.
    #[test]
    fn test_lower_incomplete_if_cst_nodes() {
        let sp = Span::dummy();
        let mk_tok = |kind: SyntaxKind, txt: &str| {
            CstElement::Token(CstToken::new(kind, txt.to_owned(), sp))
        };
        let mk_word = |txt: &str| {
            CstElement::Node(CstNode::new(
                SyntaxKind::WordNode,
                sp,
                vec![mk_tok(SyntaxKind::LiteralToken, txt)],
            ))
        };
        let mut dummy_labels = Vec::new();

        let empty_if = CstNode::new(SyntaxKind::IfStatement, sp, vec![]);
        assert_eq!(
            lower_command_expr_cst_node(&empty_if, &mut dummy_labels, WordPartsMode::Lightweight),
            None
        );
        let bad_cond_if = CstNode::new(
            SyntaxKind::IfStatement,
            sp,
            vec![CstElement::Node(CstNode::new(
                SyntaxKind::IfConditionNode,
                sp,
                vec![],
            ))],
        );
        assert_eq!(
            lower_command_expr_cst_node(
                &bad_cond_if,
                &mut dummy_labels,
                WordPartsMode::Lightweight
            ),
            None
        );
        let missing_then_if = CstNode::new(
            SyntaxKind::IfStatement,
            sp,
            vec![CstElement::Node(CstNode::new(
                SyntaxKind::IfConditionNode,
                sp,
                vec![mk_tok(SyntaxKind::Keyword, "EXIST"), mk_word("a.txt")],
            ))],
        );
        assert_eq!(
            lower_command_expr_cst_node(
                &missing_then_if,
                &mut dummy_labels,
                WordPartsMode::Lightweight
            ),
            None
        );
        let bad_then_if = CstNode::new(
            SyntaxKind::IfStatement,
            sp,
            vec![
                CstElement::Node(CstNode::new(
                    SyntaxKind::IfConditionNode,
                    sp,
                    vec![mk_tok(SyntaxKind::Keyword, "EXIST"), mk_word("a.txt")],
                )),
                CstElement::Node(CstNode::new(SyntaxKind::ErrorNode, sp, vec![])),
            ],
        );
        assert_eq!(
            lower_command_expr_cst_node(
                &bad_then_if,
                &mut dummy_labels,
                WordPartsMode::Lightweight
            ),
            None
        );
        let one_word_cond =
            CstNode::new(SyntaxKind::IfConditionNode, sp, vec![mk_word("lhs_only")]);
        assert_eq!(
            lower_if_condition_cst_node(&one_word_cond, WordPartsMode::Lightweight),
            None
        );
        let two_words_no_op = CstNode::new(
            SyntaxKind::IfConditionNode,
            sp,
            vec![mk_word("lhs"), mk_word("rhs")],
        );
        assert_eq!(
            lower_if_condition_cst_node(&two_words_no_op, WordPartsMode::Lightweight),
            None
        );
    }

    /// Verifies defensive `None` lowering on incomplete `ForStatement`, `SimpleCommand`, and `RedirectionNode`.
    #[test]
    fn test_lower_incomplete_for_simple_and_redirection_cst_nodes() {
        let sp = Span::dummy();
        let mk_tok = |kind: SyntaxKind, txt: &str| {
            CstElement::Token(CstToken::new(kind, txt.to_owned(), sp))
        };
        let mut dummy_labels = Vec::new();

        let empty_for = CstNode::new(SyntaxKind::ForStatement, sp, vec![]);
        assert_eq!(
            lower_command_expr_cst_node(&empty_for, &mut dummy_labels, WordPartsMode::Lightweight),
            None
        );
        let for_no_set = CstNode::new(
            SyntaxKind::ForStatement,
            sp,
            vec![mk_tok(SyntaxKind::ForVarToken, "%%I")],
        );
        assert_eq!(
            lower_command_expr_cst_node(&for_no_set, &mut dummy_labels, WordPartsMode::Lightweight),
            None
        );
        let for_bad_sw = CstNode::new(
            SyntaxKind::ForStatement,
            sp,
            vec![
                mk_tok(SyntaxKind::SwitchToken, "/Z"),
                mk_tok(SyntaxKind::ForVarToken, "%%I"),
                CstElement::Node(CstNode::new(SyntaxKind::ForSetNode, sp, vec![])),
                CstElement::Node(CstNode::new(
                    SyntaxKind::SimpleCommand,
                    sp,
                    vec![CstElement::Node(CstNode::new(
                        SyntaxKind::WordNode,
                        sp,
                        vec![mk_tok(SyntaxKind::LiteralToken, "echo")],
                    ))],
                )),
            ],
        );
        assert_eq!(
            lower_command_expr_cst_node(&for_bad_sw, &mut dummy_labels, WordPartsMode::Lightweight),
            None
        );
        let for_no_body = CstNode::new(
            SyntaxKind::ForStatement,
            sp,
            vec![
                mk_tok(SyntaxKind::ForVarToken, "%%I"),
                CstElement::Node(CstNode::new(SyntaxKind::ForSetNode, sp, vec![])),
            ],
        );
        assert_eq!(
            lower_command_expr_cst_node(
                &for_no_body,
                &mut dummy_labels,
                WordPartsMode::Lightweight
            ),
            None
        );

        let empty_sc = CstNode::new(SyntaxKind::SimpleCommand, sp, vec![]);
        assert_eq!(
            lower_command_expr_cst_node(&empty_sc, &mut dummy_labels, WordPartsMode::Lightweight),
            None
        );

        for redir_children in [
            vec![],
            vec![mk_tok(SyntaxKind::RedirectOpToken, "")],
            vec![mk_tok(SyntaxKind::RedirectOpToken, ">&")],
            vec![mk_tok(SyntaxKind::RedirectOpToken, ">&x")],
            vec![mk_tok(SyntaxKind::RedirectOpToken, ">")],
        ] {
            let rn = CstNode::new(SyntaxKind::RedirectionNode, sp, redir_children);
            assert_eq!(
                lower_redirection_cst_node(&rn, WordPartsMode::Lightweight),
                None
            );
        }

        let misuse_cst =
            parse_script_cst(SourceId(0), "if a = b echo hi", ExecutionContext::BatchFile);
        assert!(
            misuse_cst
                .first_cmd_error()
                .is_some_and(|e| e.is_probable_syntax_misuse())
        );

        let bare_diag = PegDiagnostic {
            span: sp,
            message: "custom syntax err".to_owned(),
            expected: vec![],
            misuse_kind: None,
            suggested_help: None,
            suggested_replacement: None,
        };
        assert_eq!(
            strict_diag_to_cmd_error(&bare_diag),
            CmdError::SyntaxError { span: sp }
        );
    }

    /// Verifies `@rem` suppression inside command expressions and invalid `IF` comparison keyword fallback.
    #[test]
    fn test_lower_suppressed_rem_and_non_insensitive_if_switch() {
        let rem_src = format!(
            "echo a & @rem suppressed_inline{CRLF}echo b & rem plain_inline{CRLF}if /Z 1==1 echo z"
        );
        let rem_cst = parse_script_cst(SourceId(0), &rem_src, ExecutionContext::BatchFile);
        let lowered_script = lower_cst_to_ast(&rem_cst);
        assert_eq!(lowered_script.statements.len(), 2);

        let sp = Span::dummy();
        let w = CstElement::Node(CstNode::new(
            SyntaxKind::WordNode,
            sp,
            vec![CstElement::Token(CstToken::new(
                SyntaxKind::LiteralToken,
                "a".to_owned(),
                sp,
            ))],
        ));
        let bad_cmp = CstNode::new(
            SyntaxKind::IfConditionNode,
            sp,
            vec![
                w.clone(),
                CstElement::Token(CstToken::new(
                    SyntaxKind::OperatorToken,
                    "BADOP".to_owned(),
                    sp,
                )),
                w,
            ],
        );
        assert!(lower_if_condition_cst_node(&bad_cmp, WordPartsMode::Lightweight).is_none());
    }
}
