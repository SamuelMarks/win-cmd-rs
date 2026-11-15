//! Lossless Concrete Syntax Tree (CST) parser with linear `O(N)` operator precedence
//! and configurable [`RecoveryMode`] (`Strict` execution vs `Recovering` linter analysis).
//!
//! Uses [`BatchFrameReader`] and [`super::lexer`] to guarantee 100% lossless round-tripping
//! (`cst.to_source_string() == raw_text`) without `O(N^2)` slice rescanning or `BTreeMap` leaf cloning.

use std::collections::BTreeSet;

use crate::error::{PegExpected, ProbableMisuseKind};
use crate::parser::cst::{CstElement, CstNode, CstScript, CstToken, PegDiagnostic, SyntaxKind};
use crate::parser::lexer::{
    TopLevelBinOp, is_broken_caret_at, is_caret_line_continuation_at, is_cmd_delimiter,
    is_echo_open_paren_at, is_keyword_at, is_rem_keyword_at, read_next_statement_unit,
    scan_top_level_binary_ops,
};
use crate::reader::char_map::SpannedChar;
use crate::reader::stream::{BatchFrameReader, MAX_CMD_LINE_LEN};
use crate::span::{ByteOffset, SourceId, Span};
use crate::types::{CR_CHAR, ExecutionContext, LF_CHAR, RecoveryMode, TAB_CHAR};

/// Compound block (`( ... )`), `IF`, and `FOR` grammar rules for the lossless CST parser.
mod control_flow;
/// `SimpleCommand`, `SET`, redirection, word, and percent/delayed sub-word grammar rules.
mod words;

use self::control_flow::{
    parse_compound_block_cst, parse_for_statement_cst, parse_if_statement_cst,
};
use self::words::parse_simple_command_cst;
pub use self::words::{parse_redirection_node, parse_word_node};

/// Tracks the farthest character index and [`ByteOffset`] reached before a parse failure,
/// accumulating all [`PegExpected`] grammar items at that frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FarthestFailure {
    /// Farthest character index reached in the input slice.
    pub cursor: usize,
    /// Farthest physical [`ByteOffset`] reached.
    pub byte_offset: ByteOffset,
    /// Exact [`Span`] at the failure frontier.
    pub span: Span,
    /// Set of expected grammar constructs at `cursor`.
    pub expected: BTreeSet<PegExpected>,
}

impl FarthestFailure {
    /// Creates a new [`FarthestFailure`] initialized at `initial_span`.
    ///
    /// # Arguments
    /// * `initial_span` - Starting [`Span`] of the input buffer.
    ///
    /// # Returns
    /// Initialized [`FarthestFailure`].
    #[must_use]
    pub const fn new(initial_span: Span) -> Self {
        Self {
            cursor: 0,
            byte_offset: initial_span.start,
            span: initial_span,
            expected: BTreeSet::new(),
        }
    }

    /// Records a rule failure at `(cursor, span)` expecting `expected_item`.
    ///
    /// # Arguments
    /// * `cursor` - Character cursor where matching failed.
    /// * `span` - Source [`Span`] at `cursor`.
    /// * `expected_item` - [`PegExpected`] construct that failed to match.
    pub fn record_failure(&mut self, cursor: usize, span: Span, expected_item: PegExpected) {
        if cursor > self.cursor || self.expected.is_empty() {
            self.cursor = cursor;
            self.byte_offset = span.start;
            self.span = span;
            self.expected.clear();
            self.expected.insert(expected_item);
        } else if cursor == self.cursor {
            self.expected.insert(expected_item);
        }
    }
}

/// Parser input state and diagnostic accumulator for CST construction.
#[derive(Debug)]
pub struct CstParserState<'a> {
    /// Identifier of the source buffer.
    pub source_id: SourceId,
    /// Character stream for the current logical unit.
    pub chars: &'a [SpannedChar],
    /// Execution context (`BatchFile` vs `InteractiveRepl`).
    pub exec_context: ExecutionContext,
    /// Error recovery mode (`Strict` for interpreter runtime, `Recovering` for `wincheck`).
    pub recovery_mode: RecoveryMode,
    /// Current parenthesis `( ... )` nesting depth.
    pub in_block_depth: usize,
    /// Currently active `FOR` loop variable characters in scope.
    pub active_for_vars: BTreeSet<char>,
    /// Farthest failure tracker for pinpoint syntax diagnostics.
    pub farthest: FarthestFailure,
    /// Collected syntax error and probable misuse diagnostics.
    pub diagnostics: Vec<PegDiagnostic>,
}

/// Controls how `'='` characters are treated inside [`parse_word_node`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordEqualsMode {
    /// Standard `cmd.exe` delimiter rule: any unescaped `'='` terminates the word.
    SplitOnAnyEquals,
    /// `IF` strict LHS rule: `'=='` terminates the word, while single `'='` stays part of the word.
    StopAtDoubleEquals,
    /// `SET` assignment rule: all `'='` characters remain inside the word.
    KeepAllEquals,
}

/// Controls whether an unquoted `')'` terminates [`parse_word_node`] (inside `FOR (...)` sets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordParenScope {
    /// Normal command word (`')'` does not terminate the word).
    Normal,
    /// Inside `FOR (...)` set (`')'` closes the set).
    InsideForSet,
}

/// Compatibility type alias for [`CstParserState`].
pub type PegInput<'a> = CstParserState<'a>;

impl<'a> CstParserState<'a> {
    /// Constructs a new [`CstParserState`] over `chars`.
    ///
    /// # Arguments
    /// * `source_id` - Source file ID.
    /// * `chars` - Spanned character slice.
    /// * `exec_context` - Active [`ExecutionContext`].
    /// * `recovery_mode` - [`RecoveryMode`] (`Strict` vs `Recovering`).
    /// * `fallback_offset` - Starting [`ByteOffset`] when `chars` is empty.
    ///
    /// # Returns
    /// Initialized [`CstParserState`].
    #[must_use]
    pub fn new(
        source_id: SourceId,
        chars: &'a [SpannedChar],
        exec_context: ExecutionContext,
        recovery_mode: RecoveryMode,
        fallback_offset: ByteOffset,
    ) -> Self {
        let init_span = chars.first().map_or_else(
            || Span::new(source_id, fallback_offset, fallback_offset),
            |c| c.span,
        );
        Self {
            source_id,
            chars,
            exec_context,
            recovery_mode,
            in_block_depth: 0,
            active_for_vars: BTreeSet::new(),
            farthest: FarthestFailure::new(init_span),
            diagnostics: Vec::new(),
        }
    }

    /// Resolves the [`Span`] at character index `cursor` (or end of buffer if at EOF).
    ///
    /// # Arguments
    /// * `cursor` - Character index in `self.chars`.
    /// * `fallback_offset` - Fallback [`ByteOffset`] if `self.chars` is empty.
    ///
    /// # Returns
    /// Exact [`Span`] at `cursor`.
    #[must_use]
    pub fn span_at(&self, cursor: usize, fallback_offset: ByteOffset) -> Span {
        self.chars.get(cursor).map_or_else(
            || {
                self.chars.last().map_or_else(
                    || Span::new(self.source_id, fallback_offset, fallback_offset),
                    |last| Span::new(self.source_id, last.span.end, last.span.end),
                )
            },
            |sc| sc.span,
        )
    }

    /// Records a [`ProbableMisuseKind`] diagnostic with message, help hint, and optional autofix.
    ///
    /// # Arguments
    /// * `span` - Source [`Span`] of the probable misuse.
    /// * `kind` - [`ProbableMisuseKind`] classification.
    /// * `message` - Human-readable diagnostic message.
    /// * `help` - Actionable remediation guidance.
    /// * `replacement` - Optional `(Span, String)` replacement edit.
    pub fn record_misuse(
        &mut self,
        span: Span,
        kind: ProbableMisuseKind,
        message: String,
        help: String,
        replacement: Option<(Span, String)>,
    ) {
        self.diagnostics.push(PegDiagnostic {
            span,
            message,
            expected: Vec::new(),
            misuse_kind: Some(kind),
            suggested_help: Some(help),
            suggested_replacement: replacement,
        });
    }

    /// Records a pure syntax error [`PegDiagnostic`].
    ///
    /// # Arguments
    /// * `span` - Exact source [`Span`] where parsing failed.
    /// * `message` - Error message.
    /// * `expected` - Expected grammar items at `span`.
    /// * `help` - Optional actionable hint.
    pub fn record_syntax_error(
        &mut self,
        span: Span,
        message: String,
        expected: Vec<PegExpected>,
        help: Option<String>,
    ) {
        self.diagnostics.push(PegDiagnostic {
            span,
            message,
            expected,
            misuse_kind: None,
            suggested_help: help,
            suggested_replacement: None,
        });
    }
}

/// Parses an entire script or interactive line into a 100% lossless [`CstScript`] using
/// [`BatchFrameReader`] and [`RecoveryMode::Recovering`].
///
/// # Arguments
/// * `source_id` - Identifier of the script in the [`crate::span::SourceMap`].
/// * `raw_text` - Raw decoded script text.
/// * `exec_context` - [`ExecutionContext`] (`BatchFile` vs `InteractiveRepl`).
///
/// # Returns
/// Lossless [`CstScript`] satisfying `cst.to_source_string() == raw_text`.
#[must_use]
pub fn parse_script_cst(
    source_id: SourceId,
    raw_text: &str,
    exec_context: ExecutionContext,
) -> CstScript {
    let mut root_children: Vec<CstElement> = Vec::new();
    let mut all_diagnostics: Vec<PegDiagnostic> = Vec::new();

    let byte_start = raw_text
        .strip_prefix('\u{FEFF}')
        .map_or(0usize, |after_bom| {
            let bom_len = raw_text.len().saturating_sub(after_bom.len());
            root_children.push(CstElement::Token(CstToken::new(
                SyntaxKind::BomToken,
                "\u{FEFF}".to_owned(),
                Span::new(source_id, ByteOffset(0), ByteOffset(bom_len)),
            )));
            bom_len
        });

    let mut reader = BatchFrameReader::new(source_id);
    reader.seek(ByteOffset(byte_start));

    while !reader.is_eof(raw_text) {
        let unit = read_next_statement_unit(&mut reader, raw_text);
        let mut state = CstParserState::new(
            source_id,
            &unit.chars,
            exec_context,
            RecoveryMode::Recovering,
            unit.start_offset,
        );
        let mut stmt_node = parse_statement_unit_cst(&mut state, unit.start_offset);
        if let Some(nl_tok) = unit.trailing_newline {
            stmt_node.children.push(CstElement::Token(nl_tok));
            let first_span = stmt_node
                .children
                .first()
                .map_or(stmt_node.span, CstElement::span);
            let last_span = stmt_node
                .children
                .last()
                .map_or(stmt_node.span, CstElement::span);
            stmt_node.span = first_span.merge(last_span);
        }
        all_diagnostics.extend(state.diagnostics);
        root_children.push(CstElement::Node(stmt_node));
    }

    let root = CstNode::from_children(SyntaxKind::Script, source_id, ByteOffset(0), root_children);
    CstScript {
        source_id,
        exec_context,
        root,
        diagnostics: all_diagnostics,
    }
}

/// Parses a single pre-assembled logical statement character buffer into `(CstNode, Vec<PegDiagnostic>)`.
///
/// # Arguments
/// * `source_id` - Source buffer ID.
/// * `chars` - Logical statement [`SpannedChar`] slice.
/// * `exec_context` - Active [`ExecutionContext`].
/// * `recovery_mode` - [`RecoveryMode::Strict`] for runtime execution or [`RecoveryMode::Recovering`].
/// * `fallback_offset` - Starting [`ByteOffset`] when `chars` is empty.
///
/// # Returns
/// Pair of `(statement_cst_node, collected_diagnostics)`.
#[must_use]
pub fn parse_statement_chars_cst(
    source_id: SourceId,
    chars: &[SpannedChar],
    exec_context: ExecutionContext,
    recovery_mode: RecoveryMode,
    fallback_offset: ByteOffset,
) -> (CstNode, Vec<PegDiagnostic>) {
    let mut state = CstParserState::new(
        source_id,
        chars,
        exec_context,
        recovery_mode,
        fallback_offset,
    );
    let node = parse_statement_unit_cst(&mut state, fallback_offset);
    (node, state.diagnostics)
}

/// Builds a [`CstToken`] from `chars[start..end]`.
///
/// # Arguments
/// * `source_id` - Source buffer ID.
/// * `chars` - Spanned character slice.
/// * `start` - Inclusive start index.
/// * `end` - Exclusive end index.
/// * `kind` - [`SyntaxKind`] to assign.
///
/// # Returns
/// Constructed [`CstToken`].
#[must_use]
pub fn slice_to_token(
    source_id: SourceId,
    chars: &[SpannedChar],
    start: usize,
    end: usize,
    kind: SyntaxKind,
) -> CstToken {
    let slice = chars.get(start..end).unwrap_or(&[]);
    let text: String = slice.iter().map(|c| c.ch).collect();
    let default_span = Span::new(source_id, ByteOffset(0), ByteOffset(0));
    let span = slice
        .first()
        .zip(slice.last())
        .map_or(default_span, |(f, l)| f.span.merge(l.span));
    CstToken::new(kind, text, span)
}

/// Consumes horizontal trivia (`Whitespace`, `CaretLineContinuation`, `BrokenCaretContinuation`)
/// starting at `cursor` and appends corresponding [`CstElement::Token`]s into `out`.
///
/// Horizontal delimiter consumption policy for [`consume_horizontal_trivia`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TriviaDelimiterMode {
    /// Consume spaces, tabs, and caret line continuations only.
    SpacesAndTabsOnly,
    /// Also consume `,`, `;`, and `=` command delimiters as trivia.
    IncludeCommandDelimiters,
}

/// Presence of a left or right operand around a binary operator (`|`, `&`, `&&`, `||`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperandPresence {
    /// Non-empty operand is present.
    Present,
    /// Operand is missing / empty.
    Missing,
}

/// Consumes horizontal whitespace (`' '`, `'\t'`, `0xA0`, optionally `,`, `;`, `=`) and caret
/// line continuations starting at `cursor`.
///
/// # Arguments
/// * `input` - Active [`CstParserState`].
/// * `cursor` - Starting index.
/// * `delimiter_mode` - [`TriviaDelimiterMode`] controlling `,`, `;`, `=` consumption.
/// * `out` - Destination child element vector.
///
/// # Returns
/// Updated cursor index past horizontal trivia.
pub(super) fn consume_horizontal_trivia(
    input: &CstParserState<'_>,
    mut cursor: usize,
    delimiter_mode: TriviaDelimiterMode,
    out: &mut Vec<CstElement>,
) -> usize {
    while cursor < input.chars.len() {
        if let Some(cont_end) = is_caret_line_continuation_at(input.chars, cursor) {
            out.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                cursor,
                cont_end,
                SyntaxKind::CaretLineContinuation,
            )));
            cursor = cont_end;
            continue;
        }
        if let Some(broken_end) = is_broken_caret_at(input.chars, cursor) {
            out.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                cursor,
                broken_end,
                SyntaxKind::BrokenCaretContinuation,
            )));
            cursor = broken_end;
            continue;
        }
        let mut ws_end = cursor;
        while let Some(sc) = input.chars.get(ws_end) {
            if is_caret_line_continuation_at(input.chars, ws_end).is_some()
                || is_broken_caret_at(input.chars, ws_end).is_some()
            {
                break;
            }
            let is_ws = matches!(sc.ch, ' ' | TAB_CHAR | '\u{00A0}')
                || (delimiter_mode == TriviaDelimiterMode::IncludeCommandDelimiters
                    && !sc.escaped_by_caret
                    && is_cmd_delimiter(sc.ch));
            if is_ws {
                ws_end = ws_end.saturating_add(1);
            } else {
                break;
            }
        }
        if ws_end > cursor {
            out.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                cursor,
                ws_end,
                SyntaxKind::Whitespace,
            )));
            cursor = ws_end;
            continue;
        }
        break;
    }
    cursor
}

/// Consumes any `@` echo-suppression prefixes and interleaved horizontal whitespace at `cursor`.
///
/// # Arguments
/// * `input` - Active [`CstParserState`].
/// * `cursor` - Starting index.
/// * `out` - Destination child element vector.
///
/// # Returns
/// Updated cursor past `@` prefixes.
pub(super) fn consume_at_prefixes(
    input: &CstParserState<'_>,
    mut cursor: usize,
    out: &mut Vec<CstElement>,
) -> usize {
    while let Some(sc) = input.chars.get(cursor) {
        if sc.is_raw('@') {
            out.push(CstElement::Token(CstToken::new(
                SyntaxKind::AtSign,
                "@".to_owned(),
                sc.span,
            )));
            cursor = cursor.saturating_add(1);
            cursor = consume_horizontal_trivia(
                input,
                cursor,
                TriviaDelimiterMode::SpacesAndTabsOnly,
                out,
            );
        } else {
            break;
        }
    }
    cursor
}

/// Checks whether `chars[start..end]` contains at least one non-trivia character.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `start` - Start index.
/// * `end` - Exclusive end index.
///
/// # Returns
/// `true` if any non-whitespace / non-continuation character exists in `chars[start..end]`.
#[must_use]
pub(super) fn slice_has_non_trivia(chars: &[SpannedChar], start: usize, end: usize) -> bool {
    let mut i = start;
    while let Some(sc) = chars.get(i).filter(|_| i < end) {
        if let Some(cont_end) = is_caret_line_continuation_at(chars, i) {
            i = cont_end;
            continue;
        }
        if let Some(broken_end) = is_broken_caret_at(chars, i) {
            i = broken_end;
            continue;
        }
        if !is_cmd_delimiter(sc.ch) {
            return true;
        }
        i = i.saturating_add(1);
    }
    false
}

/// Classifies a caret continuation or broken caret starting at `i` within a comment/raw tail.
///
/// # Arguments
/// * `chars` - Spanned character slice.
/// * `i` - Candidate index.
/// * `end` - Exclusive upper bound.
///
/// # Returns
/// `Some((token_end, SyntaxKind))` if `chars[i]` starts a caret continuation or broken caret, else `None`.
pub(super) fn classify_caret_in_comment(
    chars: &[SpannedChar],
    i: usize,
    end: usize,
) -> Option<(usize, SyntaxKind)> {
    if let Some(ce) = is_caret_line_continuation_at(chars, i) {
        return Some((ce.min(end), SyntaxKind::CaretLineContinuation));
    }
    if let Some(be) = is_broken_caret_at(chars, i) {
        return Some((be.min(end), SyntaxKind::BrokenCaretContinuation));
    }
    None
}

/// Appends `chars[start..end]` as `token_kind`, splitting out any `CaretLineContinuation`
/// or `BrokenCaretContinuation` tokens so `CMD1004` and lossless CST invariants hold.
///
/// # Arguments
/// * `input` - Active [`CstParserState`].
/// * `start` - Inclusive start index.
/// * `end` - Exclusive end index.
/// * `token_kind` - [`SyntaxKind`] for plain segments.
/// * `out` - Destination child element vector.
pub(super) fn append_comment_or_raw_with_continuations(
    input: &CstParserState<'_>,
    start: usize,
    end: usize,
    token_kind: SyntaxKind,
    out: &mut Vec<CstElement>,
) {
    let mut seg_start = start;
    let mut i = start;
    while i < end {
        if let Some((spec_end, spec_kind)) = classify_caret_in_comment(input.chars, i, end) {
            if i > seg_start {
                out.push(CstElement::Token(slice_to_token(
                    input.source_id,
                    input.chars,
                    seg_start,
                    i,
                    token_kind,
                )));
            }
            out.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                i,
                spec_end,
                spec_kind,
            )));
            i = spec_end;
            seg_start = i;
            continue;
        }
        i = i.saturating_add(1);
    }
    if seg_start < end {
        out.push(CstElement::Token(slice_to_token(
            input.source_id,
            input.chars,
            seg_start,
            end,
            token_kind,
        )));
    }
}

/// Parses a single top-level or block-interior statement slice `input.chars[start..end]` into a [`CstNode`].
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// Constructed statement [`CstNode`].
pub fn parse_statement_unit_cst(
    input: &mut CstParserState<'_>,
    fallback_offset: ByteOffset,
) -> CstNode {
    if input.chars.len() > MAX_CMD_LINE_LEN {
        let default_span = Span::new(input.source_id, fallback_offset, fallback_offset);
        let full_span = input
            .chars
            .first()
            .zip(input.chars.last())
            .map_or(default_span, |(f, l)| f.span.merge(l.span));
        input.record_syntax_error(
            full_span,
            "The input line is too long.".to_owned(),
            vec![PegExpected::Statement],
            Some(
                "Split the command line into smaller statements below 8191 characters.".to_owned(),
            ),
        );
        let tok = slice_to_token(
            input.source_id,
            input.chars,
            0,
            input.chars.len(),
            SyntaxKind::LiteralToken,
        );
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            vec![CstElement::Token(tok)],
        );
    }
    parse_statement_range_cst(input, 0, input.chars.len(), fallback_offset)
}

/// Parses a statement line range `input.chars[start..end]` (shared by top-level and `(...)` block lines).
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `start` - Start index in `input.chars`.
/// * `end` - Exclusive end index in `input.chars`.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// Statement [`CstNode`].
pub(super) fn parse_statement_range_cst(
    input: &mut CstParserState<'_>,
    start: usize,
    end: usize,
    fallback_offset: ByteOffset,
) -> CstNode {
    let mut probe_children = Vec::new();
    let cur = consume_horizontal_trivia(
        input,
        start,
        TriviaDelimiterMode::SpacesAndTabsOnly,
        &mut probe_children,
    );
    if cur >= end {
        return CstNode::from_children(
            SyntaxKind::EmptyStatement,
            input.source_id,
            fallback_offset,
            probe_children,
        );
    }

    let after_at = consume_at_prefixes(input, cur, &mut probe_children);
    let bounded = input.chars.get(..end).unwrap_or(&[]);
    if let Some(first_sc) = bounded.get(after_at).filter(|c| c.is_raw(':')) {
        return parse_colon_or_label_cst(
            input,
            probe_children,
            after_at,
            end,
            first_sc.span,
            fallback_offset,
        );
    }
    if is_rem_keyword_at(bounded, after_at) {
        return parse_rem_statement_cst(input, probe_children, after_at, end, fallback_offset);
    }
    parse_command_expr_slice_cst(input, start, end, fallback_offset)
}

/// Parses `:label` or `::` comment starting at `colon_idx`.
///
/// # Arguments
/// * `input` - Active [`CstParserState`].
/// * `probe_children` - Leading trivia and `@` tokens.
/// * `colon_idx` - Index of the leading `:`.
/// * `end` - Exclusive range bound.
/// * `first_span` - [`Span`] of the leading `:`.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `DoubleColonComment` or `LabelStatement` [`CstNode`].
fn parse_colon_or_label_cst(
    input: &CstParserState<'_>,
    mut probe_children: Vec<CstElement>,
    colon_idx: usize,
    end: usize,
    first_span: Span,
    fallback_offset: ByteOffset,
) -> CstNode {
    if let Some(second_sc) = input
        .chars
        .get(..end)
        .and_then(|s| s.get(colon_idx.saturating_add(1)))
        .filter(|c| c.ch == ':')
    {
        probe_children.push(CstElement::Token(CstToken::new(
            SyntaxKind::DoubleColon,
            "::".to_owned(),
            first_span.merge(second_sc.span),
        )));
        let body_start = colon_idx.saturating_add(2);
        if body_start < end {
            probe_children.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                body_start,
                end,
                SyntaxKind::CommentTextToken,
            )));
        }
        return CstNode::from_children(
            SyntaxKind::DoubleColonComment,
            input.source_id,
            fallback_offset,
            probe_children,
        );
    }

    probe_children.push(CstElement::Token(CstToken::new(
        SyntaxKind::Colon,
        ":".to_owned(),
        first_span,
    )));
    let after_colon = consume_horizontal_trivia(
        input,
        colon_idx.saturating_add(1),
        TriviaDelimiterMode::SpacesAndTabsOnly,
        &mut probe_children,
    );
    let mut lbl_end = after_colon;
    while let Some(c) = input.chars.get(lbl_end).filter(|_| lbl_end < end) {
        if is_cmd_delimiter(c.ch)
            || matches!(c.ch, ':' | '+' | '&' | '|' | '<' | '>' | CR_CHAR | LF_CHAR)
        {
            break;
        }
        lbl_end = lbl_end.saturating_add(1);
    }
    if lbl_end > after_colon {
        probe_children.push(CstElement::Token(slice_to_token(
            input.source_id,
            input.chars,
            after_colon,
            lbl_end,
            SyntaxKind::LiteralToken,
        )));
    }
    if lbl_end < end {
        let after_ws = consume_horizontal_trivia(
            input,
            lbl_end,
            TriviaDelimiterMode::SpacesAndTabsOnly,
            &mut probe_children,
        );
        if after_ws < end {
            probe_children.push(CstElement::Token(slice_to_token(
                input.source_id,
                input.chars,
                after_ws,
                end,
                SyntaxKind::CommentTextToken,
            )));
        }
    }
    CstNode::from_children(
        SyntaxKind::LabelStatement,
        input.source_id,
        fallback_offset,
        probe_children,
    )
}

/// Parses a `REM` comment statement starting at `rem_idx`.
///
/// # Arguments
/// * `input` - Active [`CstParserState`].
/// * `probe_children` - Leading trivia and `@` tokens.
/// * `rem_idx` - Index of `REM`.
/// * `end` - Exclusive range bound.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// `RemStatement` [`CstNode`].
fn parse_rem_statement_cst(
    input: &CstParserState<'_>,
    mut probe_children: Vec<CstElement>,
    rem_idx: usize,
    end: usize,
    fallback_offset: ByteOffset,
) -> CstNode {
    let rem_end = rem_idx.saturating_add(3);
    probe_children.push(CstElement::Token(slice_to_token(
        input.source_id,
        input.chars,
        rem_idx,
        rem_end,
        SyntaxKind::Keyword,
    )));
    let mut body_cur = rem_end;
    if let Some(fourth) = input.chars.get(body_cur).filter(|_| body_cur < end)
        && (fourth.ch == ' ' || fourth.ch == TAB_CHAR)
    {
        probe_children.push(CstElement::Token(CstToken::new(
            SyntaxKind::Whitespace,
            fourth.ch.to_string(),
            fourth.span,
        )));
        body_cur = body_cur.saturating_add(1);
    }
    if body_cur < end {
        append_comment_or_raw_with_continuations(
            input,
            body_cur,
            end,
            SyntaxKind::CommentTextToken,
            &mut probe_children,
        );
    }
    CstNode::from_children(
        SyntaxKind::RemStatement,
        input.source_id,
        fallback_offset,
        probe_children,
    )
}

/// Parses `input.chars[start..end]` into a `BinaryCommandExpr` or primary command in linear `O(N)` time.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `start` - Start index.
/// * `end` - Exclusive end index.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// Command expression [`CstNode`].
pub(super) fn parse_command_expr_slice_cst(
    input: &mut CstParserState<'_>,
    start: usize,
    end: usize,
    fallback_offset: ByteOffset,
) -> CstNode {
    let ops = scan_top_level_binary_ops(input.chars, start, end);
    build_precedence_cst(input, start, end, &ops, fallback_offset)
}

/// Recursively builds the left-associative binary precedence CST over pre-scanned `ops` (`O(|ops|)`).
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `start` - Segment start index in `input.chars`.
/// * `end` - Segment exclusive end index in `input.chars`.
/// * `ops` - Pre-scanned top-level binary operators strictly inside `start..end`.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// Constructed [`CstNode`].
fn build_precedence_cst(
    input: &mut CstParserState<'_>,
    start: usize,
    end: usize,
    ops: &[TopLevelBinOp],
    fallback_offset: ByteOffset,
) -> CstNode {
    let Some((split_idx, split_op)) = find_rightmost_lowest_bp_op(ops) else {
        return parse_primary_command_slice_cst(input, start, end, fallback_offset);
    };

    let op_tok = slice_to_token(
        input.source_id,
        input.chars,
        split_op.op_start,
        split_op.op_end,
        SyntaxKind::OperatorToken,
    );
    let op_span = op_tok.span;
    let left_has = slice_has_non_trivia(input.chars, start, split_op.op_start);
    let right_has = slice_has_non_trivia(input.chars, split_op.op_end, end);
    record_missing_binary_operand_diagnostics(
        input,
        split_op,
        op_span,
        if left_has {
            OperandPresence::Present
        } else {
            OperandPresence::Missing
        },
        if right_has {
            OperandPresence::Present
        } else {
            OperandPresence::Missing
        },
    );

    let left_ops = ops.get(..split_idx).unwrap_or(&[]);
    let right_ops = ops.get(split_idx.saturating_add(1)..).unwrap_or(&[]);

    let mut children = Vec::new();
    let mut child_has_err = false;
    if left_has {
        let left_node =
            build_precedence_cst(input, start, split_op.op_start, left_ops, fallback_offset);
        if left_node.kind == SyntaxKind::ErrorNode {
            child_has_err = true;
        }
        children.push(CstElement::Node(left_node));
    } else if split_op.op_start > start {
        append_comment_or_raw_with_continuations(
            input,
            start,
            split_op.op_start,
            SyntaxKind::Whitespace,
            &mut children,
        );
    }

    children.push(CstElement::Token(op_tok));

    if right_has {
        let right_node = if right_ops.is_empty() {
            parse_command_expr_slice_cst(input, split_op.op_end, end, op_span.end)
        } else {
            build_precedence_cst(input, split_op.op_end, end, right_ops, op_span.end)
        };
        if right_node.kind == SyntaxKind::ErrorNode {
            child_has_err = true;
        }
        children.push(CstElement::Node(right_node));
    } else if end > split_op.op_end {
        append_comment_or_raw_with_continuations(
            input,
            split_op.op_end,
            end,
            SyntaxKind::Whitespace,
            &mut children,
        );
    }

    let kind = if left_has && right_has && (!child_has_err || input.recovery_mode.is_recovering()) {
        SyntaxKind::BinaryCommandExpr
    } else {
        SyntaxKind::ErrorNode
    };
    CstNode::from_children(kind, input.source_id, fallback_offset, children)
}

/// Emits syntax diagnostics when either side of binary operator `split_op` has no command tokens.
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `split_op` - Operator descriptor.
/// * `op_span` - Byte [`Span`] of the operator token.
/// * `left_operand` - [`OperandPresence`] of the LHS slice.
/// * `right_operand` - [`OperandPresence`] of the RHS slice.
fn record_missing_binary_operand_diagnostics(
    input: &mut CstParserState<'_>,
    split_op: TopLevelBinOp,
    op_span: Span,
    left_operand: OperandPresence,
    right_operand: OperandPresence,
) {
    if left_operand == OperandPresence::Missing {
        let exp = if split_op.kind == crate::parser::lexer::BinOpKind::Pipe {
            PegExpected::PipelineLeftOperand
        } else {
            PegExpected::ChainLeftOperand
        };
        input
            .farthest
            .record_failure(split_op.op_start, op_span, exp);
        input.record_syntax_error(
            op_span,
            format!("`{}` was unexpected at this time.", split_op.kind.as_str()),
            vec![exp],
            Some(format!(
                "Provide a valid command before `{}`.",
                split_op.kind.as_str()
            )),
        );
    }
    if right_operand == OperandPresence::Missing {
        let err_span = input.span_at(split_op.op_end, op_span.end);
        let exp = if split_op.kind == crate::parser::lexer::BinOpKind::Pipe {
            PegExpected::PipelineRightOperand
        } else {
            PegExpected::ChainRightOperand
        };
        input
            .farthest
            .record_failure(split_op.op_end, err_span, exp);
        input.record_syntax_error(
            err_span,
            format!(
                "The syntax of the command is incorrect. Missing command after `{}`.",
                split_op.kind.as_str()
            ),
            vec![exp],
            Some(format!(
                "Provide a valid command after `{}` or remove the trailing operator.",
                split_op.kind.as_str()
            )),
        );
    }
}

/// Returns the `(index, TopLevelBinOp)` of the **rightmost** operator with minimum binding power
/// in `ops`, yielding left-associative binary tree grouping.
///
/// # Arguments
/// * `ops` - Slice of [`TopLevelBinOp`]s.
///
/// # Returns
/// `Some((idx, op))` if `ops` is non-empty, else `None`.
#[must_use]
fn find_rightmost_lowest_bp_op(ops: &[TopLevelBinOp]) -> Option<(usize, TopLevelBinOp)> {
    let mut best: Option<(usize, TopLevelBinOp)> = None;
    for (idx, &op) in ops.iter().enumerate() {
        match best {
            None => best = Some((idx, op)),
            Some((_, prev)) if op.kind.binding_power() <= prev.kind.binding_power() => {
                best = Some((idx, op));
            }
            Some(_) => {}
        }
    }
    best
}

/// Parses a primary command (`IfStatement`, `ForStatement`, `CompoundBlock`, or `SimpleCommand`).
///
/// # Arguments
/// * `input` - Mutable [`CstParserState`].
/// * `start` - Start index.
/// * `end` - Exclusive end index.
/// * `fallback_offset` - Fallback [`ByteOffset`].
///
/// # Returns
/// Primary command [`CstNode`].
fn parse_primary_command_slice_cst(
    input: &mut CstParserState<'_>,
    start: usize,
    end: usize,
    fallback_offset: ByteOffset,
) -> CstNode {
    let mut prefix_children = Vec::new();
    let mut cur = consume_horizontal_trivia(
        input,
        start,
        TriviaDelimiterMode::SpacesAndTabsOnly,
        &mut prefix_children,
    );
    cur = consume_at_prefixes(input, cur, &mut prefix_children);

    if cur >= end {
        let err_span = input.span_at(cur, fallback_offset);
        input
            .farthest
            .record_failure(cur, err_span, PegExpected::CommandName);
        input.record_syntax_error(
            err_span,
            "The syntax of the command is incorrect.".to_owned(),
            vec![PegExpected::CommandName],
            Some("Expected a command, `IF`, `FOR`, or `( ... )` block.".to_owned()),
        );
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            prefix_children,
        );
    }

    if let Some(first_sc) = input.chars.get(cur).filter(|c| c.is_raw(')')) {
        input
            .farthest
            .record_failure(cur, first_sc.span, PegExpected::CommandName);
        input.record_syntax_error(
            first_sc.span,
            ") was unexpected at this time.".to_owned(),
            vec![PegExpected::CommandName],
            Some("Remove the stray `)` or escape it with `^)`.".to_owned()),
        );
        prefix_children.push(CstElement::Token(CstToken::new(
            SyntaxKind::CloseParen,
            ")".to_owned(),
            first_sc.span,
        )));
        append_comment_or_raw_with_continuations(
            input,
            cur.saturating_add(1),
            end,
            SyntaxKind::LiteralToken,
            &mut prefix_children,
        );
        return CstNode::from_children(
            SyntaxKind::ErrorNode,
            input.source_id,
            fallback_offset,
            prefix_children,
        );
    }

    if is_rem_keyword_at(input.chars.get(..end).unwrap_or(input.chars), cur) {
        return parse_rem_statement_cst(input, prefix_children, cur, end, fallback_offset);
    }
    if is_keyword_at(input.chars, cur, end, "IF") {
        return parse_if_statement_cst(input, prefix_children, cur, end, fallback_offset);
    }
    if is_keyword_at(input.chars, cur, end, "FOR") {
        return parse_for_statement_cst(input, prefix_children, cur, end, fallback_offset);
    }
    if input
        .chars
        .get(cur)
        .is_some_and(|c| c.is_raw('(') && !is_echo_open_paren_at(input.chars, cur))
    {
        return parse_compound_block_cst(input, prefix_children, cur, end, fallback_offset);
    }
    parse_simple_command_cst(input, prefix_children, cur, end, fallback_offset)
}

#[cfg(test)]
/// Unit tests for lossless CST construction and strict/recovering error modes.
mod tests {
    use super::*;
    use crate::parser::peg::parse_script_cst;
    use crate::reader::char_map::LogicalLineBuffer;
    use crate::types::CRLF;

    /// Verifies losslessness, first statement [`SyntaxKind`], and expected diagnostic substring for each entry.
    ///
    /// # Arguments
    /// * `cases` - Slice of `(src, expected_kind, expected_diag_substr)` test cases.
    fn assert_cst_recovery_table(cases: &[(&str, SyntaxKind, Option<&str>)]) {
        for &(src, expected_kind, expected_diag) in cases {
            let cst = parse_script_cst(SourceId(0), src, ExecutionContext::BatchFile);
            assert_eq!(cst.to_source_string(), src, "losslessness failed on: {src}");
            let first_kind = cst
                .root
                .children
                .iter()
                .find_map(|el| match el {
                    CstElement::Node(n) => Some(n.kind),
                    CstElement::Token(_) => None,
                })
                .unwrap_or(SyntaxKind::EmptyStatement);
            assert_eq!(first_kind, expected_kind, "unexpected CST kind on: {src}");
            match expected_diag {
                Some(sub) => assert!(
                    cst.diagnostics.iter().any(|d| d
                        .message
                        .to_ascii_lowercase()
                        .contains(&sub.to_ascii_lowercase())),
                    "expected diagnostic containing {sub:?} on {src:?}, got: {:?}",
                    cst.diagnostics
                ),
                None => assert!(
                    cst.diagnostics.is_empty(),
                    "unexpected diagnostics on {src:?}: {:?}",
                    cst.diagnostics
                ),
            }
        }
    }

    /// Exercises line-length limits, `@` prefix errors, compound block trailing syntax errors,
    /// and `IF`/`ELSE` redirection & missing-body recovery structure.
    #[test]
    fn test_cst_parser_grammar_recovery_and_variable_edges() {
        let empty_state = CstParserState::new(
            SourceId(0),
            &[],
            ExecutionContext::BatchFile,
            RecoveryMode::Recovering,
            ByteOffset(5),
        );
        assert_eq!(empty_state.span_at(0, ByteOffset(5)).start, ByteOffset(5));

        let overlong = format!("echo {}", "a".repeat(8200));
        let cst_long = parse_script_cst(SourceId(0), &overlong, ExecutionContext::BatchFile);
        assert!(cst_long.has_syntax_errors());
        assert_eq!(cst_long.to_source_string(), overlong);

        let crlf_rem = format!("rem ^{CRLF}still & (echo a &{CRLF}) & (echo a &{LF_CHAR})");
        assert_cst_recovery_table(&[
            ("\u{FEFF}echo bom", SyntaxKind::SimpleCommand, None),
            ("@", SyntaxKind::ErrorNode, Some("syntax")),
            ("::", SyntaxKind::DoubleColonComment, None),
            (":", SyntaxKind::LabelStatement, None),
            (":lbl   ", SyntaxKind::LabelStatement, None),
            (":lbl trailing_comment", SyntaxKind::LabelStatement, None),
            (
                "if errorlevel 1==1 echo eq_lhs",
                SyntaxKind::ErrorNode,
                Some("unexpected"),
            ),
            (
                "if errorlevel %E% echo var_thr",
                SyntaxKind::IfStatement,
                None,
            ),
            (
                "if errorlevel foo equ bar echo cmp_non_int",
                SyntaxKind::ErrorNode,
                Some("unexpected"),
            ),
            ("rem", SyntaxKind::RemStatement, None),
            ("rem ^ ", SyntaxKind::RemStatement, None),
            ("rem/c", SyntaxKind::RemStatement, None),
            ("rem\tcomment_tab", SyntaxKind::RemStatement, None),
            ("set =val", SyntaxKind::SimpleCommand, None),
            (
                "echo a & rem b & echo c",
                SyntaxKind::BinaryCommandExpr,
                None,
            ),
            (
                crlf_rem.as_str(),
                SyntaxKind::RemStatement,
                Some("Missing command"),
            ),
            ("=leading_eq arg", SyntaxKind::SimpleCommand, None),
            (
                "echofoo arg & dir/w & echo/slash & cd.. & rd/s/q tmp",
                SyntaxKind::BinaryCommandExpr,
                None,
            ),
        ]);
    }

    /// Exercises `( ... )` trailing token errors and `IF`/`ELSE` missing-body recovery structure.
    #[test]
    fn test_cst_parser_compound_block_and_if_else_recovery_table() {
        let crlf_blk = format!("({CRLF}  |{CRLF})");
        let crlf_else = format!("if 1==1 echo a ^e ^{CRLF} else echo b");
        assert_cst_recovery_table(&[
            (
                "( echo a ) trailing_bad",
                SyntaxKind::ErrorNode,
                Some("Unescaped"),
            ),
            (
                "( set X=1 ) trailing_non_echo",
                SyntaxKind::ErrorNode,
                Some("unexpected"),
            ),
            ("( echo a ) >", SyntaxKind::ErrorNode, Some("syntax")),
            (
                crlf_blk.as_str(),
                SyntaxKind::CompoundBlock,
                Some("unexpected"),
            ),
            (
                "if ==rhs echo eq_start",
                SyntaxKind::ErrorNode,
                Some("unexpected"),
            ),
            ("if 1==1 |", SyntaxKind::ErrorNode, Some("unexpected")),
            (
                "if 1==1 ( echo a ) > > else echo b",
                SyntaxKind::ErrorNode,
                Some("syntax"),
            ),
            (
                "if 1==1 echo(hello else echo b",
                SyntaxKind::IfStatement,
                Some("ELSE"),
            ),
            (
                "if 1==1 (echo a) > NUL else",
                SyntaxKind::ErrorNode,
                Some("ELSE"),
            ),
            (
                "if 1==1 (echo a) else |",
                SyntaxKind::ErrorNode,
                Some("unexpected"),
            ),
            (crlf_else.as_str(), SyntaxKind::IfStatement, Some("ELSE")),
        ]);
    }

    /// Exercises `FOR` recovery edges, multi-line `FOR` sets, and `%`/`!` variable lexing structure.
    #[test]
    fn test_cst_parser_for_and_variable_recovery_table() {
        let lf_for = format!("for %%I in ({LF_CHAR}a) do echo %%I");
        let crlf_for = format!("for %%I in ({CRLF} a) do echo %%I");
        let crlf_for_bc = format!("for %%I in (^  {CRLF}a) do echo %%I");
        let crlf_word = format!(
            "echo a^{CRLF}=b & echo a^{CRLF} b & echo trail^{CRLF}{CRLF}( echo a(b^{CRLF})c ){CRLF}for %%I in ((a^{CRLF})b)) do echo %%I"
        );
        let tab_vars = format!("echo %bad{TAB_CHAR}v% !bad{TAB_CHAR}v! word^ ");
        assert_cst_recovery_table(&[
            ("for", SyntaxKind::ErrorNode, Some("syntax")),
            ("for %%I", SyntaxKind::ErrorNode, Some("in")),
            (
                "for %%I (a) do echo %%I",
                SyntaxKind::ForStatement,
                Some("Missing `IN`"),
            ),
            (
                "for %bad(x in (a) do echo x",
                SyntaxKind::ErrorNode,
                Some("single"),
            ),
            (
                "for %bad)x in (a) do echo x",
                SyntaxKind::ErrorNode,
                Some("single"),
            ),
            ("for %%I in (a)", SyntaxKind::ErrorNode, Some("DO")),
            (
                "for %%I in (a) echo %%I",
                SyntaxKind::ForStatement,
                Some("Missing `DO`"),
            ),
            (
                "for %%I in (   ) do echo empty_ws",
                SyntaxKind::ForStatement,
                None,
            ),
            (
                "for %%I in (a & b) do echo amp",
                SyntaxKind::ForStatement,
                None,
            ),
            (
                r#"for %%I in ((a) ("b")c) do echo nested_paren"#,
                SyntaxKind::ForStatement,
                None,
            ),
            (
                "for %%I in (a) do |",
                SyntaxKind::ErrorNode,
                Some("unexpected"),
            ),
            (
                "for %%\u{00E9} in (a) do echo x",
                SyntaxKind::ErrorNode,
                Some("unexpected"),
            ),
            (
                "for %%I in (ab) do echo %%I %I2",
                SyntaxKind::ForStatement,
                Some("Unescaped single"),
            ),
            (crlf_for.as_str(), SyntaxKind::ForStatement, None),
            (crlf_for_bc.as_str(), SyntaxKind::ForStatement, None),
            (lf_for.as_str(), SyntaxKind::ForStatement, None),
            (
                crlf_word.as_str(),
                SyntaxKind::BinaryCommandExpr,
                Some("Unclosed"),
            ),
            (
                tab_vars.as_str(),
                SyntaxKind::SimpleCommand,
                Some("Unescaped single"),
            ),
        ]);
    }

    /// Exercises `%~` tilde modifiers, `$PATH:` lookups, and delayed-expansion `!` recovery structure.
    #[test]
    fn test_cst_parser_tilde_modifier_and_delayed_var_recovery_table() {
        assert_cst_recovery_table(&[
            (
                "for %%d in (1) do echo %~dp1 %%~$PATH:d %%~$:d %%~$BAD!:d %%~$UNCLOSED",
                SyntaxKind::ForStatement,
                Some("Single-percent"),
            ),
            (
                "echo %~$:1",
                SyntaxKind::SimpleCommand,
                Some("Unescaped single"),
            ),
            (
                "echo %~$BAD!:1",
                SyntaxKind::SimpleCommand,
                Some("Unescaped single"),
            ),
            (
                "echo %~$UNCLOSED",
                SyntaxKind::SimpleCommand,
                Some("Unescaped single"),
            ),
            (
                "echo %~f% %~1% %~!",
                SyntaxKind::SimpleCommand,
                Some("Unescaped single"),
            ),
            (
                r#"echo "!!" "!unclosed" !unclosed"quote!"#,
                SyntaxKind::SimpleCommand,
                Some("Unclosed"),
            ),
            (
                "echo %~dp$PATH:I %~dpVAR% ! !! !unclosed !space var! !V:a =b! %unclosed var%",
                SyntaxKind::SimpleCommand,
                Some("modifiers"),
            ),
        ]);
    }

    /// Exercises `RecoveryMode::Strict` error-node promotion for invalid binary and `FOR` statements.
    #[test]
    fn test_cst_parser_strict_mode_errors() {
        let strict_bin_err =
            LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "( | ) & echo b");
        let (bin_err_node, _) = parse_statement_chars_cst(
            SourceId(0),
            &strict_bin_err.chars,
            ExecutionContext::BatchFile,
            RecoveryMode::Strict,
            ByteOffset(0),
        );
        assert_eq!(bin_err_node.kind, SyntaxKind::ErrorNode);

        let single_pct_for =
            LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "for %I in (a) do echo %I");
        let (strict_node, strict_diags) = parse_statement_chars_cst(
            SourceId(0),
            &single_pct_for.chars,
            ExecutionContext::BatchFile,
            RecoveryMode::Strict,
            ByteOffset(0),
        );
        assert_eq!(strict_node.kind, SyntaxKind::ForStatement);
        assert_eq!(strict_diags.len(), 1);

        let repl_dbl_for = LogicalLineBuffer::from_str_at(
            SourceId(0),
            ByteOffset(0),
            "for %%I in (a) do echo %%I",
        );
        let (repl_node, repl_diags) = parse_statement_chars_cst(
            SourceId(0),
            &repl_dbl_for.chars,
            ExecutionContext::InteractiveRepl,
            RecoveryMode::Strict,
            ByteOffset(0),
        );
        assert_eq!(repl_node.kind, SyntaxKind::ErrorNode);
        assert_eq!(repl_diags.len(), 1);

        let strict_if_eq =
            LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "if ==rhs echo eq_start");
        let (_, if_eq_diags) = parse_statement_chars_cst(
            SourceId(0),
            &strict_if_eq.chars,
            ExecutionContext::BatchFile,
            RecoveryMode::Strict,
            ByteOffset(0),
        );
        assert_eq!(if_eq_diags.len(), 1);

        let strict_if_blk_err =
            LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "if 1==1 ( | ) else echo b");
        let (if_blk_node, _) = parse_statement_chars_cst(
            SourceId(0),
            &strict_if_blk_err.chars,
            ExecutionContext::BatchFile,
            RecoveryMode::Strict,
            ByteOffset(0),
        );
        assert_eq!(if_blk_node.kind, SyntaxKind::ErrorNode);
    }

    /// Verifies `FarthestFailure` tie-breaking, caret/tilde edge cases, and binary-chain recovery.
    #[test]
    fn test_cst_parser_farthest_failure_tilde_and_binary_recovery() {
        let mut ff = FarthestFailure::new(Span::dummy());
        let sp3 = Span::new(SourceId(0), ByteOffset(3), ByteOffset(3));
        ff.record_failure(3, sp3, PegExpected::CommandName);
        ff.record_failure(3, sp3, PegExpected::RedirectionTarget);
        assert_eq!(ff.expected.len(), 2);

        let trivia_cont = format!(
            "rem head ^{CRLF}tail{CRLF}  ^{CRLF}  & echo rhs{CRLF}echo lhs &  ^ {CRLF}if (1==1 trailing) echo no_misuse{CRLF}if (only_one_word) echo x{CRLF}echo %~f$PATH:1{CRLF}echo %~"
        );
        let trivia_cst = parse_script_cst(SourceId(0), &trivia_cont, ExecutionContext::BatchFile);
        assert_eq!(trivia_cst.to_source_string(), trivia_cont);
        assert!(trivia_cst.has_syntax_errors());

        let strict_paren_if =
            LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "if (1 == 1) echo ok");
        let (sp_if_node, sp_if_diags) = parse_statement_chars_cst(
            SourceId(0),
            &strict_paren_if.chars,
            ExecutionContext::BatchFile,
            RecoveryMode::Strict,
            ByteOffset(0),
        );
        assert_eq!(sp_if_node.kind, SyntaxKind::IfStatement);
        assert_eq!(sp_if_diags.len(), 0);

        // Child error inside binary chain in Strict vs Recovering mode + missing command name & broken redir
        for (src, mode, expected_kind) in [
            ("echo ok >", RecoveryMode::Strict, SyntaxKind::ErrorNode),
            ("> out.txt", RecoveryMode::Strict, SyntaxKind::ErrorNode),
            (
                "echo a & > out.txt",
                RecoveryMode::Strict,
                SyntaxKind::ErrorNode,
            ),
            (
                "echo a & > out.txt",
                RecoveryMode::Recovering,
                SyntaxKind::BinaryCommandExpr,
            ),
            ("| echo rhs", RecoveryMode::Strict, SyntaxKind::ErrorNode),
            ("echo lhs |", RecoveryMode::Strict, SyntaxKind::ErrorNode),
            (
                "if (1 == 1) echo ok",
                RecoveryMode::Recovering,
                SyntaxKind::IfStatement,
            ),
        ] {
            let buf = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), src);
            let (node, diags) = parse_statement_chars_cst(
                SourceId(0),
                &buf.chars,
                ExecutionContext::BatchFile,
                mode,
                ByteOffset(0),
            );
            assert_eq!(node.kind, expected_kind, "case: {src} ({mode:?})");
            assert!(!diags.is_empty(), "expected diagnostic for: {src}");
        }
    }
}
