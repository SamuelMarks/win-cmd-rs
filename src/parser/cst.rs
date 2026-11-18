//! Lossless Concrete Syntax Tree (CST) definitions for `win-cmd-rs`.
//!
//! Unlike the lowered execution [`crate::parser::ast::ParsedScript`], a [`CstScript`]
//! preserves every single byte of the original batch script or interactive REPL command line,
//! including UTF-8 BOMs, horizontal whitespace, line endings (`CRLF`, `LF`), caret line
//! continuations, broken carets, comments (`REM`, `::`), quotes, sub-word variable references
//! (`%VAR%`, `!VAR!`, `%1`, `%%I`), and syntax error recovery nodes ([`SyntaxKind::ErrorNode`]).
//!
//! # Invariant
//! For any input string `src`, `parse_script_cst(id, src, ctx).to_source_string() == src`.

use alloc::string::String;
use alloc::vec::Vec;

use derive_more::{Display, IsVariant};

use crate::error::{PegExpected, ProbableMisuseKind};
use crate::span::{ByteOffset, SourceId, Span};
use crate::types::ExecutionContext;

/// Exhaustive syntax node and token classification for the lossless `cmd.exe` CST.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display, IsVariant)]
pub enum SyntaxKind {
    // --- Interior Nodes ---
    /// Root node of a parsed batch script or REPL command line.
    #[display("Script")]
    Script,
    /// Blank or whitespace-only line statement.
    #[display("EmptyStatement")]
    EmptyStatement,
    /// A `:label` definition statement line.
    #[display("LabelStatement")]
    LabelStatement,
    /// A `::` label-comment line.
    #[display("DoubleColonComment")]
    DoubleColonComment,
    /// A `REM` comment statement.
    #[display("RemStatement")]
    RemStatement,
    /// A simple command invocation (`ECHO`, `SET`, `COPY`, external program, etc.).
    #[display("SimpleCommand")]
    SimpleCommand,
    /// A parenthesized compound command block `( ... )` with optional redirections.
    #[display("CompoundBlock")]
    CompoundBlock,
    /// An `IF` conditional statement (`IF [/I] [NOT] cond then [ELSE else]`).
    #[display("IfStatement")]
    IfStatement,
    /// The condition sub-tree of an `IF` statement (`EXIST`, `DEFINED`, `ERRORLEVEL`, `CMDEXTVERSION`, or comparison).
    #[display("IfConditionNode")]
    IfConditionNode,
    /// The `ELSE` clause sub-tree of an `IF` statement (`ELSE command`).
    #[display("ElseClauseNode")]
    ElseClauseNode,
    /// A `FOR` loop statement (`FOR [/D|/R|/L|/F] [options] %%I IN (...) DO command`).
    #[display("ForStatement")]
    ForStatement,
    /// The parenthesized `(...)` set inside a `FOR` statement.
    #[display("ForSetNode")]
    ForSetNode,
    /// A binary command chain or pipeline (`&`, `&&`, `||`, `|`).
    #[display("BinaryCommandExpr")]
    BinaryCommandExpr,
    /// An I/O stream redirection clause (`> out.txt`, `2>&1`, `< in.txt`).
    #[display("RedirectionNode")]
    RedirectionNode,
    /// A composite command word or argument token made of sub-word parts.
    #[display("WordNode")]
    WordNode,
    /// A double-quoted string segment `"..."` inside a [`SyntaxKind::WordNode`].
    #[display("QuotedStringNode")]
    QuotedStringNode,
    /// A structured `SET` assignment (`VAR=VALUE` or `"VAR=VALUE"`).
    #[display("SetAssignmentNode")]
    SetAssignmentNode,
    /// Lossless error-recovery node wrapping unparseable or malformed tokens.
    #[display("ErrorNode")]
    ErrorNode,

    // --- Leaf Tokens ---
    /// Horizontal whitespace (spaces, tabs) or argument delimiters (`,`, `;`).
    #[display("Whitespace")]
    Whitespace,
    /// Line ending token (`CRLF`, `LF`, or `CR`).
    #[display("Newline")]
    Newline,
    /// Valid caret line continuation sequence (`^` immediately before a newline).
    #[display("CaretLineContinuation")]
    CaretLineContinuation,
    /// Broken caret continuation with trailing spaces before the newline (`^   ` before newline).
    #[display("BrokenCaretContinuation")]
    BrokenCaretContinuation,
    /// Leading UTF-8 Byte Order Mark (`U+FEFF`).
    #[display("BomToken")]
    BomToken,
    /// Leading `@` echo-suppression prefix token.
    #[display("AtSign")]
    AtSign,
    /// Leading `:` prefix on a `:label` line.
    #[display("Colon")]
    Colon,
    /// Leading `::` prefix on a label-comment line.
    #[display("DoubleColon")]
    DoubleColon,
    /// Reserved grammar keyword (`IF`, `ELSE`, `NOT`, `EXIST`, `DEFINED`, `ERRORLEVEL`, `CMDEXTVERSION`, `FOR`, `IN`, `DO`, `REM`, `EQU`, `NEQ`, `LSS`, `LEQ`, `GTR`, `GEQ`).
    #[display("Keyword")]
    Keyword,
    /// Command or statement switch token (`/I`, `/D`, `/R`, `/L`, `/F`, `/A`, `/P`, `/B`).
    #[display("SwitchToken")]
    SwitchToken,
    /// Binary command or comparison operator (`&`, `&&`, `||`, `|`, `==`, `=`).
    #[display("OperatorToken")]
    OperatorToken,
    /// I/O redirection operator token (`<`, `>`, `>>`, `>&`, `<&`, `2>`, `2>&1`, etc.).
    #[display("RedirectOpToken")]
    RedirectOpToken,
    /// Opening parenthesis `(`.
    #[display("OpenParen")]
    OpenParen,
    /// Closing parenthesis `)`.
    #[display("CloseParen")]
    CloseParen,
    /// Double quote character `"`.
    #[display("DoubleQuote")]
    DoubleQuote,
    /// Single delimiter character immediately following `ECHO` (`' '`, `'.'`, `'('`, `':'`, `'/'`, etc.).
    #[display("EchoDelimiterToken")]
    EchoDelimiterToken,
    /// Contiguous run of plain unescaped literal characters inside a word.
    #[display("LiteralToken")]
    LiteralToken,
    /// Unquoted two-character caret escape sequence (`^&`, `^|`, `^)`, `^^`, etc.).
    #[display("CaretEscapeToken")]
    CaretEscapeToken,
    /// Immediate environment variable expansion token (`%VAR%`, `%VAR:~0,2%`, `%VAR:a=b%`).
    #[display("EnvVarToken")]
    EnvVarToken,
    /// Delayed environment variable expansion token (`!VAR!`, `!VAR:~0,2!`, `!VAR:a=b!`).
    #[display("DelayedVarToken")]
    DelayedVarToken,
    /// Batch positional parameter token (`%0`..`%9`, `%*`, `%~dp0`, `%~$PATH:1`).
    #[display("PositionalParamToken")]
    PositionalParamToken,
    /// `FOR` loop variable token (`%%I`, `%I`, `%%~fI`, `%~nxI`).
    #[display("ForVarToken")]
    ForVarToken,
    /// Invalid path modifier applied to a named environment variable (`%~dpMYVAR%`).
    #[display("InvalidModifierVarToken")]
    InvalidModifierVarToken,
    /// Escaped percent literal (`%%`) or bare unclosed single `%`.
    #[display("PercentLiteralToken")]
    PercentLiteralToken,
    /// Unterminated `%VAR` or `!VAR` token at end of line.
    #[display("UnclosedVarToken")]
    UnclosedVarToken,
    /// Raw text payload of a `REM` or `::` comment.
    #[display("CommentTextToken")]
    CommentTextToken,
}

impl SyntaxKind {
    /// Checks whether this [`SyntaxKind`] represents trivia (whitespace, line continuations, newlines, or BOM).
    ///
    /// # Returns
    /// `true` if this kind is trivia, otherwise `false`.
    #[must_use]
    pub const fn is_trivia(self) -> bool {
        matches!(
            self,
            Self::Whitespace
                | Self::Newline
                | Self::CaretLineContinuation
                | Self::BrokenCaretContinuation
                | Self::BomToken
        )
    }

    /// Checks whether this [`SyntaxKind`] is an interior CST node kind.
    ///
    /// # Returns
    /// `true` if this kind is an interior node, otherwise `false`.
    #[must_use]
    pub const fn is_interior_node(self) -> bool {
        matches!(
            self,
            Self::Script
                | Self::EmptyStatement
                | Self::LabelStatement
                | Self::DoubleColonComment
                | Self::RemStatement
                | Self::SimpleCommand
                | Self::CompoundBlock
                | Self::IfStatement
                | Self::IfConditionNode
                | Self::ElseClauseNode
                | Self::ForStatement
                | Self::ForSetNode
                | Self::BinaryCommandExpr
                | Self::RedirectionNode
                | Self::WordNode
                | Self::QuotedStringNode
                | Self::SetAssignmentNode
                | Self::ErrorNode
        )
    }

    /// Checks whether this [`SyntaxKind`] is a leaf token kind.
    ///
    /// # Returns
    /// `true` if this kind is a leaf token, otherwise `false`.
    #[must_use]
    pub const fn is_leaf_token(self) -> bool {
        !self.is_interior_node()
    }

    /// Checks whether this [`SyntaxKind`] represents a variable or parameter expansion token.
    ///
    /// # Returns
    /// `true` for [`Self::EnvVarToken`], [`Self::DelayedVarToken`], [`Self::PositionalParamToken`],
    /// [`Self::ForVarToken`], or [`Self::InvalidModifierVarToken`].
    #[must_use]
    pub const fn is_variable_or_param(self) -> bool {
        matches!(
            self,
            Self::EnvVarToken
                | Self::DelayedVarToken
                | Self::PositionalParamToken
                | Self::ForVarToken
                | Self::InvalidModifierVarToken
        )
    }
}

/// A leaf token in the Concrete Syntax Tree preserving exact source text and byte [`Span`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
#[display("{text}")]
pub struct CstToken {
    /// Classification of the leaf token.
    pub kind: SyntaxKind,
    /// Exact raw source text of the token.
    pub text: String,
    /// Exact physical byte span in the source buffer.
    pub span: Span,
}

impl CstToken {
    /// Constructs a new [`CstToken`].
    ///
    /// # Arguments
    /// * `kind` - Leaf [`SyntaxKind`].
    /// * `text` - Exact source text of the token.
    /// * `span` - Source [`Span`] of the token.
    ///
    /// # Returns
    /// A populated [`CstToken`].
    #[must_use]
    pub const fn new(kind: SyntaxKind, text: String, span: Span) -> Self {
        Self { kind, text, span }
    }

    /// Returns the UTF-8 byte length of this token's text.
    ///
    /// # Returns
    /// Byte length as `usize`.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.text.len()
    }

    /// Checks whether this token is trivia (whitespace, newline, line continuation, or BOM).
    ///
    /// # Returns
    /// `true` if `self.kind.is_trivia()`, else `false`.
    #[must_use]
    pub const fn is_trivia(&self) -> bool {
        self.kind.is_trivia()
    }
}

/// A child element of a [`CstNode`]: either an interior [`CstNode`] or a leaf [`CstToken`].
#[derive(Debug, Clone, PartialEq, Eq, IsVariant)]
pub enum CstElement {
    /// An interior syntax node.
    Node(CstNode),
    /// A leaf syntax token.
    Token(CstToken),
}

impl CstElement {
    /// Returns the [`SyntaxKind`] of this element.
    ///
    /// # Returns
    /// The node's or token's [`SyntaxKind`].
    #[must_use]
    pub const fn kind(&self) -> SyntaxKind {
        match self {
            Self::Node(n) => n.kind,
            Self::Token(t) => t.kind,
        }
    }

    /// Returns the bounding [`Span`] of this element.
    ///
    /// # Returns
    /// The element's [`Span`].
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Node(n) => n.span,
            Self::Token(t) => t.span,
        }
    }

    /// Borrows this element as a [`CstNode`] if it is [`CstElement::Node`].
    ///
    /// # Returns
    /// `Some(&CstNode)` for nodes, or `None` for tokens.
    #[must_use]
    pub const fn as_node(&self) -> Option<&CstNode> {
        match self {
            Self::Node(n) => Some(n),
            Self::Token(_) => None,
        }
    }

    /// Borrows this element as a [`CstToken`] if it is [`CstElement::Token`].
    ///
    /// # Returns
    /// `Some(&CstToken)` for tokens, or `None` for nodes.
    #[must_use]
    pub const fn as_token(&self) -> Option<&CstToken> {
        match self {
            Self::Node(_) => None,
            Self::Token(t) => Some(t),
        }
    }

    /// Appends the exact source text of this element and its descendants to `out`.
    ///
    /// # Arguments
    /// * `out` - Destination string buffer.
    pub fn write_source(&self, out: &mut String) {
        match self {
            Self::Node(n) => n.write_source(out),
            Self::Token(t) => out.push_str(&t.text),
        }
    }

    /// Reconstructs the exact source text of this element and its descendants.
    ///
    /// # Returns
    /// The lossless source `String`.
    #[must_use]
    pub fn to_source_string(&self) -> String {
        let mut out = String::new();
        self.write_source(&mut out);
        out
    }

    /// Recomputes byte spans of this element in-place starting at `start_offset`.
    ///
    /// # Arguments
    /// * `source_id` - [`SourceId`] to assign to all spans.
    /// * `start_offset` - Starting [`ByteOffset`] of this element.
    ///
    /// # Returns
    /// The ending [`ByteOffset`] immediately after this element.
    pub fn recompute_spans(&mut self, source_id: SourceId, start_offset: ByteOffset) -> ByteOffset {
        match self {
            Self::Node(n) => n.recompute_spans(source_id, start_offset),
            Self::Token(t) => {
                let end = ByteOffset(start_offset.0.saturating_add(t.text.len()));
                t.span = Span::new(source_id, start_offset, end);
                end
            }
        }
    }
}

/// An interior node in the Concrete Syntax Tree containing ordered child [`CstElement`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstNode {
    /// Classification of this interior node.
    pub kind: SyntaxKind,
    /// Bounding source span from first child start to last child end.
    pub span: Span,
    /// Ordered child nodes and tokens preserving all trivia.
    pub children: Vec<CstElement>,
}

impl CstNode {
    /// Constructs a [`CstNode`] with an explicit [`Span`] and child list.
    ///
    /// # Arguments
    /// * `kind` - Interior [`SyntaxKind`].
    /// * `span` - Bounding [`Span`].
    /// * `children` - Ordered child [`CstElement`]s.
    ///
    /// # Returns
    /// A new [`CstNode`].
    #[must_use]
    pub const fn new(kind: SyntaxKind, span: Span, children: Vec<CstElement>) -> Self {
        Self {
            kind,
            span,
            children,
        }
    }

    /// Constructs a [`CstNode`] and derives its bounding [`Span`] from `children`.
    ///
    /// If `children` is empty, constructs a zero-length span at `fallback_offset`.
    ///
    /// # Arguments
    /// * `kind` - Interior [`SyntaxKind`].
    /// * `source_id` - [`SourceId`] for the derived span.
    /// * `fallback_offset` - [`ByteOffset`] used when `children` is empty.
    /// * `children` - Ordered child [`CstElement`]s.
    ///
    /// # Returns
    /// A new [`CstNode`] with computed span.
    #[must_use]
    pub fn from_children(
        kind: SyntaxKind,
        source_id: SourceId,
        fallback_offset: ByteOffset,
        children: Vec<CstElement>,
    ) -> Self {
        let span = match (children.first(), children.last()) {
            (Some(first), Some(last)) => first.span().merge(last.span()),
            _ => Span::new(source_id, fallback_offset, fallback_offset),
        };
        Self {
            kind,
            span,
            children,
        }
    }

    /// Appends the exact source text of all descendant tokens in order to `out`.
    ///
    /// # Arguments
    /// * `out` - Destination string buffer.
    pub fn write_source(&self, out: &mut String) {
        self.children.iter().for_each(|c| c.write_source(out));
    }

    /// Reconstructs the exact source string represented by this node.
    ///
    /// # Returns
    /// Lossless source text `String`.
    #[must_use]
    pub fn to_source_string(&self) -> String {
        let mut out = String::new();
        self.write_source(&mut out);
        out
    }

    /// Iterates over direct child [`CstNode`]s of this node.
    ///
    /// # Returns
    /// An iterator yielding `&CstNode` for each direct child node.
    pub fn child_nodes(&self) -> impl Iterator<Item = &Self> {
        self.children.iter().filter_map(CstElement::as_node)
    }

    /// Iterates over direct child [`CstToken`]s of this node.
    ///
    /// # Returns
    /// An iterator yielding `&CstToken` for each direct child token.
    pub fn child_tokens(&self) -> impl Iterator<Item = &CstToken> {
        self.children.iter().filter_map(CstElement::as_token)
    }

    /// Collects all leaf [`CstToken`]s in this subtree in source order.
    ///
    /// # Returns
    /// A `Vec<&CstToken>` of all descendant leaf tokens.
    #[must_use]
    pub fn descendant_tokens(&self) -> Vec<&CstToken> {
        let mut out = Vec::new();
        self.collect_tokens_into(&mut out);
        out
    }

    /// Recursively appends descendant leaf tokens into `out`.
    ///
    /// # Arguments
    /// * `out` - Accumulator vector for leaf token references.
    fn collect_tokens_into<'a>(&'a self, out: &mut Vec<&'a CstToken>) {
        self.children.iter().for_each(|child| match child {
            CstElement::Node(n) => n.collect_tokens_into(out),
            CstElement::Token(t) => out.push(t),
        });
    }

    /// Collects all interior [`CstNode`]s in this subtree (including `self`) in pre-order.
    ///
    /// # Returns
    /// A `Vec<&CstNode>` of all interior nodes in pre-order.
    #[must_use]
    pub fn descendant_nodes(&self) -> Vec<&Self> {
        let mut out = Vec::new();
        self.collect_nodes_into(&mut out);
        out
    }

    /// Recursively appends `self` and descendant interior nodes into `out`.
    ///
    /// # Arguments
    /// * `out` - Accumulator vector for node references.
    fn collect_nodes_into<'a>(&'a self, out: &mut Vec<&'a Self>) {
        out.push(self);
        self.children.iter().for_each(|child| {
            if let CstElement::Node(n) = child {
                n.collect_nodes_into(out);
            }
        });
    }

    /// Returns the first non-trivia leaf [`CstToken`] in this subtree, if any.
    ///
    /// # Returns
    /// `Some(&CstToken)` for the first non-trivia token, or `None` if all tokens are trivia.
    #[must_use]
    pub fn first_non_trivia_token(&self) -> Option<&CstToken> {
        self.children.iter().find_map(|child| match child {
            CstElement::Token(t) if !t.is_trivia() => Some(t),
            CstElement::Token(_) => None,
            CstElement::Node(n) => n.first_non_trivia_token(),
        })
    }

    /// Recomputes byte spans of `self` and all descendant nodes and tokens in-place.
    ///
    /// Call this after structural CST tree-rewriting to ensure every node and token
    /// carries an accurate byte [`Span`] matching the rewritten source string.
    ///
    /// # Arguments
    /// * `source_id` - [`SourceId`] to assign to all spans.
    /// * `start_offset` - Starting [`ByteOffset`] of this node.
    ///
    /// # Returns
    /// The ending [`ByteOffset`] immediately after this node.
    pub fn recompute_spans(&mut self, source_id: SourceId, start_offset: ByteOffset) -> ByteOffset {
        let cursor = self.children.iter_mut().fold(start_offset, |acc, child| {
            child.recompute_spans(source_id, acc)
        });
        self.span = Span::new(source_id, start_offset, cursor);
        cursor
    }
}

/// A syntax error or probable-misuse diagnostic emitted by the PEG parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PegDiagnostic {
    /// Exact source span of the syntax error or misuse.
    pub span: Span,
    /// Human-readable diagnostic message.
    pub message: String,
    /// Grammar constructs expected at the failure offset.
    pub expected: Vec<PegExpected>,
    /// Probable misuse classification if matched by an ordered-choice recovery rule.
    pub misuse_kind: Option<ProbableMisuseKind>,
    /// Actionable help advice for fixing the issue.
    pub suggested_help: Option<String>,
    /// Optional suggested span replacement `(target_span, replacement_text)`.
    pub suggested_replacement: Option<(Span, String)>,
}

/// A complete lossless Concrete Syntax Tree for a parsed script or REPL line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstScript {
    /// Source buffer identifier.
    pub source_id: SourceId,
    /// Execution dialect context (`BatchFile` vs `InteractiveRepl`) used during parsing.
    pub exec_context: ExecutionContext,
    /// Root [`SyntaxKind::Script`] node preserving 100% of source bytes.
    pub root: CstNode,
    /// Syntax and probable-misuse diagnostics collected during parsing.
    pub diagnostics: Vec<PegDiagnostic>,
}

impl CstScript {
    /// Reconstructs the exact source text of the script from the CST root.
    ///
    /// # Returns
    /// Lossless source string.
    #[must_use]
    pub fn to_source_string(&self) -> String {
        self.root.to_source_string()
    }

    /// Checks whether any syntax or probable-misuse diagnostics were recorded during parsing.
    ///
    /// # Returns
    /// `true` if `self.diagnostics` is non-empty, otherwise `false`.
    #[must_use]
    pub const fn has_syntax_errors(&self) -> bool {
        !self.diagnostics.is_empty()
    }

    /// Converts the first recorded [`PegDiagnostic`] (if any) into a unified [`crate::error::CmdError`].
    ///
    /// # Returns
    /// `Some(CmdError)` if `self.diagnostics` is non-empty, otherwise `None`.
    #[must_use]
    pub fn first_cmd_error(&self) -> Option<crate::error::CmdError> {
        self.diagnostics
            .first()
            .map(crate::parser::lower::strict_diag_to_cmd_error)
    }
}

#[cfg(test)]
/// Unit tests for lossless CST node/token types, `SyntaxKind`, and span recomputation.
mod tests {
    use super::*;

    /// Verifies `SyntaxKind` interior/leaf/trivia/variable classifications and `Display` strings.
    #[test]
    fn test_syntax_kind_classifications_and_exact_display() {
        let interior_kinds = [
            (SyntaxKind::Script, "Script"),
            (SyntaxKind::EmptyStatement, "EmptyStatement"),
            (SyntaxKind::LabelStatement, "LabelStatement"),
            (SyntaxKind::DoubleColonComment, "DoubleColonComment"),
            (SyntaxKind::RemStatement, "RemStatement"),
            (SyntaxKind::SimpleCommand, "SimpleCommand"),
            (SyntaxKind::CompoundBlock, "CompoundBlock"),
            (SyntaxKind::IfStatement, "IfStatement"),
            (SyntaxKind::IfConditionNode, "IfConditionNode"),
            (SyntaxKind::ElseClauseNode, "ElseClauseNode"),
            (SyntaxKind::ForStatement, "ForStatement"),
            (SyntaxKind::ForSetNode, "ForSetNode"),
            (SyntaxKind::BinaryCommandExpr, "BinaryCommandExpr"),
            (SyntaxKind::RedirectionNode, "RedirectionNode"),
            (SyntaxKind::WordNode, "WordNode"),
            (SyntaxKind::QuotedStringNode, "QuotedStringNode"),
            (SyntaxKind::SetAssignmentNode, "SetAssignmentNode"),
            (SyntaxKind::ErrorNode, "ErrorNode"),
        ];
        for (kind, expected_name) in interior_kinds {
            assert!(kind.is_interior_node());
            assert!(!kind.is_leaf_token());
            assert!(!kind.is_trivia());
            assert!(!kind.is_variable_or_param());
            assert_eq!(kind.to_string(), expected_name);
        }

        let trivia_kinds = [
            (SyntaxKind::Whitespace, "Whitespace"),
            (SyntaxKind::Newline, "Newline"),
            (SyntaxKind::CaretLineContinuation, "CaretLineContinuation"),
            (
                SyntaxKind::BrokenCaretContinuation,
                "BrokenCaretContinuation",
            ),
            (SyntaxKind::BomToken, "BomToken"),
        ];
        for (kind, expected_name) in trivia_kinds {
            assert!(kind.is_trivia());
            assert!(kind.is_leaf_token());
            assert!(!kind.is_interior_node());
            assert!(!kind.is_variable_or_param());
            assert_eq!(kind.to_string(), expected_name);
        }

        let var_kinds = [
            (SyntaxKind::EnvVarToken, "EnvVarToken"),
            (SyntaxKind::DelayedVarToken, "DelayedVarToken"),
            (SyntaxKind::PositionalParamToken, "PositionalParamToken"),
            (SyntaxKind::ForVarToken, "ForVarToken"),
            (
                SyntaxKind::InvalidModifierVarToken,
                "InvalidModifierVarToken",
            ),
        ];
        for (kind, expected_name) in var_kinds {
            assert!(kind.is_variable_or_param());
            assert!(kind.is_leaf_token());
            assert!(!kind.is_trivia());
            assert_eq!(kind.to_string(), expected_name);
        }

        let other_leaf_kinds = [
            (SyntaxKind::AtSign, "AtSign"),
            (SyntaxKind::Colon, "Colon"),
            (SyntaxKind::DoubleColon, "DoubleColon"),
            (SyntaxKind::Keyword, "Keyword"),
            (SyntaxKind::SwitchToken, "SwitchToken"),
            (SyntaxKind::OperatorToken, "OperatorToken"),
            (SyntaxKind::RedirectOpToken, "RedirectOpToken"),
            (SyntaxKind::OpenParen, "OpenParen"),
            (SyntaxKind::CloseParen, "CloseParen"),
            (SyntaxKind::DoubleQuote, "DoubleQuote"),
            (SyntaxKind::EchoDelimiterToken, "EchoDelimiterToken"),
            (SyntaxKind::LiteralToken, "LiteralToken"),
            (SyntaxKind::CaretEscapeToken, "CaretEscapeToken"),
            (SyntaxKind::PercentLiteralToken, "PercentLiteralToken"),
            (SyntaxKind::UnclosedVarToken, "UnclosedVarToken"),
            (SyntaxKind::CommentTextToken, "CommentTextToken"),
        ];
        for (kind, expected_name) in other_leaf_kinds {
            assert!(kind.is_leaf_token());
            assert!(!kind.is_interior_node());
            assert!(!kind.is_trivia());
            assert!(!kind.is_variable_or_param());
            assert_eq!(kind.to_string(), expected_name);
        }
    }

    /// Verifies CST tree traversal, token collection, and recursive byte-span recomputation.
    #[test]
    fn test_cst_node_token_element_traversal_and_recompute_spans() {
        let src_id = SourceId(1);
        let ws = CstToken::new(
            SyntaxKind::Whitespace,
            "  ".to_owned(),
            Span::new(src_id, ByteOffset(0), ByteOffset(2)),
        );
        assert_eq!(ws.byte_len(), 2);
        assert!(ws.is_trivia());
        assert_eq!(ws.to_string(), "  ");

        let lit = CstToken::new(
            SyntaxKind::LiteralToken,
            "echo".to_owned(),
            Span::new(src_id, ByteOffset(2), ByteOffset(6)),
        );
        assert!(!lit.is_trivia());

        let word_node = CstNode::from_children(
            SyntaxKind::WordNode,
            src_id,
            ByteOffset(2),
            vec![CstElement::Token(lit.clone())],
        );
        assert_eq!(
            word_node.span,
            Span::new(src_id, ByteOffset(2), ByteOffset(6))
        );

        let empty_node =
            CstNode::from_children(SyntaxKind::EmptyStatement, src_id, ByteOffset(6), vec![]);
        let expected_empty_span = Span::new(src_id, ByteOffset(6), ByteOffset(6));
        assert_eq!(empty_node.span, expected_empty_span);
        assert_eq!(empty_node.first_non_trivia_token(), None);

        let mut root = CstNode::new(
            SyntaxKind::Script,
            Span::new(src_id, ByteOffset(0), ByteOffset(6)),
            vec![
                CstElement::Token(ws.clone()),
                CstElement::Node(empty_node),
                CstElement::Node(word_node.clone()),
            ],
        );

        assert_eq!(root.to_source_string(), "  echo");
        assert_eq!(root.child_nodes().count(), 2);
        assert_eq!(root.child_tokens().count(), 1);
        assert_eq!(root.descendant_tokens().len(), 2);
        assert_eq!(root.descendant_nodes().len(), 3);
        assert_eq!(root.first_non_trivia_token(), Some(&lit));

        let elem_node = CstElement::Node(word_node);
        let elem_tok = CstElement::Token(ws);
        assert_eq!(elem_node.kind(), SyntaxKind::WordNode);
        assert_eq!(elem_tok.kind(), SyntaxKind::Whitespace);
        assert!(elem_node.as_node().is_some());
        assert!(elem_node.as_token().is_none());
        assert!(elem_tok.as_token().is_some());
        assert!(elem_tok.as_node().is_none());
        assert_eq!(elem_node.to_source_string(), "echo");
        assert_eq!(elem_tok.to_source_string(), "  ");

        let crlf = crate::types::CRLF;
        root.children.push(CstElement::Token(CstToken::new(
            SyntaxKind::Newline,
            crlf.to_owned(),
            Span::dummy(),
        )));
        let end_offset = root.recompute_spans(SourceId(2), ByteOffset(10));
        assert_eq!(end_offset, ByteOffset(18));
        assert_eq!(
            root.span,
            Span::new(SourceId(2), ByteOffset(10), ByteOffset(18))
        );

        let script = CstScript {
            source_id: SourceId(2),
            exec_context: ExecutionContext::BatchFile,
            root,
            diagnostics: vec![PegDiagnostic {
                span: Span::new(SourceId(2), ByteOffset(10), ByteOffset(12)),
                message: "test diag".to_owned(),
                expected: vec![PegExpected::CommandName],
                misuse_kind: None,
                suggested_help: Some("help".to_owned()),
                suggested_replacement: None,
            }],
        };
        assert_eq!(script.to_source_string(), format!("  echo{crlf}"));
        assert!(script.has_syntax_errors());
        assert!(
            script
                .first_cmd_error()
                .is_some_and(|e| e.is_peg_syntax_error())
        );

        let clean_script = CstScript {
            source_id: SourceId(2),
            exec_context: ExecutionContext::BatchFile,
            root: CstNode::new(SyntaxKind::Script, Span::dummy(), vec![]),
            diagnostics: vec![],
        };
        assert_eq!(clean_script.first_cmd_error(), None);
    }
}
