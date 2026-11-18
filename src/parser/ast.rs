//! Abstract and Concrete Syntax Tree (AST/CST) definitions for `win-cmd-rs`.
//!
//! Preserves exact source [`Span`]s, echo suppression (`@`), raw argument tails,
//! redirections, `IF` conditions, `FOR` loop variants, and `:label`/`REM` nodes
//! for both runtime execution and `wincheck` static analysis.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use derive_more::{Display, IsVariant};

use crate::span::{ByteOffset, SourceId, Span};
use crate::types::{
    CaseSensitivity, EchoSuppression, FileDescriptor, ForVarName, LabelName, NegationMode,
};

/// Classification of a sub-word token inside a [`SpannedWord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display, IsVariant)]
pub enum WordPartKind {
    /// Contiguous plain literal characters.
    #[display("Literal")]
    Literal,
    /// Double-quoted segment `"..."`.
    #[display("Quoted")]
    Quoted,
    /// Unquoted caret escape sequence `^x`.
    #[display("CaretEscape")]
    CaretEscape,
    /// Immediate environment variable expansion (`%VAR%`, `%VAR:~0,2%`, `%VAR:a=b%`).
    #[display("EnvVar")]
    EnvVar,
    /// Delayed environment variable expansion (`!VAR!`, `!VAR:~0,2!`, `!VAR:a=b!`).
    #[display("DelayedVar")]
    DelayedVar,
    /// Positional batch parameter (`%0`..`%9`, `%*`, `%~dp0`).
    #[display("PositionalParam")]
    PositionalParam,
    /// `FOR` loop variable reference (`%%I`, `%I`, `%%~fI`).
    #[display("ForVar")]
    ForVar,
    /// Invalid path modifier on a named environment variable (`%~dpMYVAR%`).
    #[display("InvalidModifierVar")]
    InvalidModifierVar,
    /// Escaped `%%` or bare `%` literal.
    #[display("PercentLiteral")]
    PercentLiteral,
}

/// A sub-word part within a [`SpannedWord`] carrying its exact byte [`Span`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
#[display("{text}")]
pub struct WordPart {
    /// Sub-word classification.
    pub kind: WordPartKind,
    /// Raw text of the sub-word token.
    pub text: String,
    /// Exact physical byte span of this sub-word part.
    pub span: Span,
}

impl WordPart {
    /// Constructs a new [`WordPart`].
    ///
    /// # Arguments
    /// * `kind` - [`WordPartKind`] classification.
    /// * `text` - Raw sub-word text.
    /// * `span` - Source [`Span`] of the sub-word token.
    ///
    /// # Returns
    /// A populated [`WordPart`].
    #[must_use]
    pub const fn new(kind: WordPartKind, text: String, span: Span) -> Self {
        Self { kind, text, span }
    }
}

/// Presence of unescaped special metacharacters outside quotes inside a [`SpannedWord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialCharPresence {
    /// Word contains no unescaped special metacharacters outside quotes.
    Plain,
    /// Word had at least one unescaped caret/special character outside quotes.
    HasUnescapedSpecial,
}

/// A word or argument token paired with its exact [`Span`] in the source file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
#[display("{text}")]
pub struct SpannedWord {
    /// Text of the word (preserving quotes if quoted).
    pub text: String,
    /// Physical source span of the word.
    pub span: Span,
    /// Whether the word contained any double quotes `"`.
    pub quoted: bool,
    /// Whether the word contained any unescaped special characters (`&`, `|`, `<`, `>`, `^`) outside quotes.
    pub has_unescaped_special: bool,
    /// Fine-grained sub-word parts (literal runs, `%VAR%`, `!VAR!`, `%1`, `%%I`, etc.) with exact spans.
    pub parts: Vec<WordPart>,
    /// Precomputed quote-stripped text when `text` contains interior composite quotes (`"C:\Dir"\app.exe`).
    interior_unquoted: Option<String>,
}

impl SpannedWord {
    /// Constructs a new [`SpannedWord`].
    ///
    /// # Arguments
    /// * `text` - Word text.
    /// * `span` - Source [`Span`].
    ///
    /// # Returns
    /// A populated [`SpannedWord`].
    #[must_use]
    pub fn new(text: String, span: Span) -> Self {
        let quoted = text.contains('"');
        let interior_unquoted = crate::parser::modifiers::strip_surrounding_quotes(&text)
            .contains('"')
            .then(|| crate::parser::modifiers::strip_command_arg_quotes(&text));
        Self {
            text,
            span,
            quoted,
            has_unescaped_special: false,
            parts: Vec::new(),
            interior_unquoted,
        }
    }

    /// Constructs a new [`SpannedWord`] with explicit sub-word [`WordPart`] metadata.
    ///
    /// # Arguments
    /// * `text` - Word text.
    /// * `span` - Source [`Span`].
    /// * `quote_mode` - [`crate::types::QuoteMode`] (`InQuotes` when word contains double quotes).
    /// * `special_presence` - [`SpecialCharPresence`] outside quotes.
    /// * `parts` - Sub-word [`WordPart`] tokens.
    ///
    /// # Returns
    /// A populated [`SpannedWord`].
    #[must_use]
    pub fn with_parts(
        text: String,
        span: Span,
        quote_mode: crate::types::QuoteMode,
        special_presence: SpecialCharPresence,
        parts: Vec<WordPart>,
    ) -> Self {
        let interior_unquoted = crate::parser::modifiers::strip_surrounding_quotes(&text)
            .contains('"')
            .then(|| crate::parser::modifiers::strip_command_arg_quotes(&text));
        Self {
            text,
            span,
            quoted: matches!(quote_mode, crate::types::QuoteMode::InQuotes),
            has_unescaped_special: matches!(
                special_presence,
                SpecialCharPresence::HasUnescapedSpecial
            ),
            parts,
            interior_unquoted,
        }
    }

    /// Returns the word text with surrounding and composite interior double quotes removed.
    ///
    /// # Returns
    /// Unquoted string slice.
    #[must_use]
    pub fn unquoted(&self) -> &str {
        self.interior_unquoted
            .as_deref()
            .unwrap_or_else(|| crate::parser::modifiers::strip_surrounding_quotes(&self.text))
    }
}

/// A parsed batch script containing top-level statements and label index entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedScript {
    /// Identifier of the source buffer.
    pub source_id: SourceId,
    /// Top-level statements in source order.
    pub statements: Vec<Statement>,
    /// All `:label` definitions discovered in the script.
    pub labels: Vec<LabelNode>,
    /// Span of any broken caret continuation (`^   \r\n`) detected in the script.
    pub broken_caret_spans: Vec<Span>,
}

/// A top-level or block-interior statement in a batch script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    /// A `:label` or `::` comment line.
    Label(LabelNode),
    /// A `REM` comment statement.
    Rem(RemNode),
    /// An empty or whitespace-only line.
    Empty(Span),
    /// An executable command expression (simple, block, `IF`, `FOR`, pipe, or chain).
    Command(CommandExpr),
}

impl Statement {
    /// Returns the bounding [`Span`] of this statement.
    ///
    /// # Returns
    /// The statement's [`Span`].
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Label(l) => l.span,
            Self::Rem(r) => r.span,
            Self::Empty(s) => *s,
            Self::Command(c) => c.span(),
        }
    }
}

/// A `:label` or `::` comment definition line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelNode {
    /// Normalized [`LabelName`].
    pub name: LabelName,
    /// Full raw text after the leading `:`.
    pub raw_body: String,
    /// Whether this line started with `::` (label comment).
    pub is_double_colon: bool,
    /// Whether the label name had trailing spaces/special delimiters (`CMD1012`).
    pub has_invalid_label_chars: bool,
    /// Byte offset immediately following this line (for `GOTO` / `CALL` jumps).
    pub next_line_offset: ByteOffset,
    /// Source span of the label line.
    pub span: Span,
}

/// A `REM` comment statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemNode {
    /// Whether prefixed with `@`.
    pub echo_suppression: EchoSuppression,
    /// Raw comment text following `REM`.
    pub comment_text: String,
    /// Source span of the `REM` statement.
    pub span: Span,
}

/// An executable command expression tree node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandExpr {
    /// A simple command invocation (`ECHO`, `SET`, `DIR`, external binary, etc.).
    Simple(SimpleCommand),
    /// A parenthesized compound command block `( stmt1 & stmt2 )`.
    Block(CompoundBlock),
    /// An `IF` conditional statement.
    If(Box<IfStatement>),
    /// A `FOR` loop statement.
    For(Box<ForStatement>),
    /// A pipeline `left | right`.
    Pipe {
        /// Left-hand command feeding stdout into the pipe.
        left: Box<Self>,
        /// Right-hand command reading stdin from the pipe.
        right: Box<Self>,
        /// Span of the `|` operator.
        op_span: Span,
        /// Full merged span.
        span: Span,
    },
    /// A conditional AND chain `left && right`.
    And {
        /// Left-hand command.
        left: Box<Self>,
        /// Right-hand command executed if `left` succeeds.
        right: Box<Self>,
        /// Span of the `&&` operator.
        op_span: Span,
        /// Full merged span.
        span: Span,
    },
    /// A conditional OR chain `left || right`.
    Or {
        /// Left-hand command.
        left: Box<Self>,
        /// Right-hand command executed if `left` fails.
        right: Box<Self>,
        /// Span of the `||` operator.
        op_span: Span,
        /// Full merged span.
        span: Span,
    },
    /// An unconditional command sequence `left & right`.
    Seq {
        /// First command.
        left: Box<Self>,
        /// Second command.
        right: Box<Self>,
        /// Span of the `&` operator.
        op_span: Span,
        /// Full merged span.
        span: Span,
    },
}

impl CommandExpr {
    /// Returns the bounding [`Span`] of this command expression.
    ///
    /// # Returns
    /// The [`Span`] of the expression.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Simple(s) => s.span,
            Self::Block(b) => b.span,
            Self::If(i) => i.span,
            Self::For(f) => f.span,
            Self::Pipe { span, .. }
            | Self::And { span, .. }
            | Self::Or { span, .. }
            | Self::Seq { span, .. } => *span,
        }
    }
}

/// A simple command invocation with arguments, raw tail, and I/O redirections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    /// Whether prefixed with `@`.
    pub echo_suppression: EchoSuppression,
    /// Program or built-in command name token.
    pub program: SpannedWord,
    /// Delimiter character immediately following `ECHO` (e.g., `'.'`, `'('`, `' '`), if any.
    pub echo_delimiter: Option<char>,
    /// Tokenized arguments (excluding redirections).
    pub arguments: Vec<SpannedWord>,
    /// Exact raw tail after the command name (with redirections stripped), preserving spaces.
    pub raw_tail: String,
    /// Source span of `raw_tail`.
    pub raw_tail_span: Span,
    /// Attached I/O redirections (`> file`, `2>&1`, `< in`).
    pub redirections: Vec<Redirection>,
    /// Full span of the simple command.
    pub span: Span,
}

/// A parenthesized compound block `( ... )` with optional block-level redirections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompoundBlock {
    /// Whether prefixed with `@`.
    pub echo_suppression: EchoSuppression,
    /// Statements inside the block.
    pub body: Vec<Statement>,
    /// Block-level I/O redirections (`( ... ) > out.txt`).
    pub redirections: Vec<Redirection>,
    /// Full span from opening `(` through closing `)` and redirections.
    pub span: Span,
}

/// An I/O stream redirection specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirection {
    /// Source file descriptor (`0` for `<`, `1` for `>`/`>>`, or explicit `0`..`9`).
    pub source_handle: FileDescriptor,
    /// Kind of redirection operation.
    pub kind: RedirectionKind,
    /// Source span of the redirection operator and target.
    pub span: Span,
}

/// Target and mode of an I/O [`Redirection`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectionKind {
    /// `< filename` — Read input from file.
    ReadFromFile(SpannedWord),
    /// `> filename` — Write output to file, truncating existing content.
    WriteTruncate(SpannedWord),
    /// `>> filename` — Append output to file.
    WriteAppend(SpannedWord),
    /// `n>&m` — Duplicate output handle `m` onto `n` (e.g., `2>&1`).
    DuplicateOutput(FileDescriptor),
    /// `n<&m` — Duplicate input handle `m` onto `n`.
    DuplicateInput(FileDescriptor),
}

/// An `IF` conditional statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfStatement {
    /// Whether prefixed with `@`.
    pub echo_suppression: EchoSuppression,
    /// `/I` case-insensitivity flag.
    pub case_sensitivity: CaseSensitivity,
    /// `NOT` negation flag.
    pub negated: NegationMode,
    /// Condition to evaluate.
    pub condition: IfCondition,
    /// Command executed when condition holds.
    pub then_branch: Box<CommandExpr>,
    /// Optional `ELSE` command branch.
    pub else_branch: Option<Box<CommandExpr>>,
    /// Whether a malformed/unrecognized `ELSE` token was detected inside `then_branch` (`CMD1005`).
    pub has_dangling_else: bool,
    /// Full span of the `IF` statement.
    pub span: Span,
}

/// Condition variants supported by `IF`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfCondition {
    /// `IF ERRORLEVEL n` (true if `ERRORLEVEL >= n`).
    ErrorLevel {
        /// Parsed numeric threshold `Some(n)` when literal, or `None` when unresolved (`%VAR%` / `!VAR!`).
        threshold: Option<i32>,
        /// Original spanned token for `n`.
        raw_token: SpannedWord,
    },
    /// `IF EXIST pattern` (true if matching file/dir/device exists).
    Exist {
        /// Path or wildcard pattern.
        path_pattern: SpannedWord,
    },
    /// `IF DEFINED var` (true if environment variable `var` is defined).
    Defined {
        /// Variable name token.
        var_name: SpannedWord,
    },
    /// `IF CMDEXTVERSION n` (true if `CMDEXTVERSION >= n`).
    CmdExtVersion {
        /// Version threshold `n`.
        version: u32,
        /// Original spanned token.
        raw_token: SpannedWord,
    },
    /// `IF left op right` (`==`, `EQU`, `NEQ`, `LSS`, `LEQ`, `GTR`, `GEQ`).
    Compare {
        /// Left operand.
        left: SpannedWord,
        /// Comparison operator.
        op: ComparisonOp,
        /// Span of the operator.
        op_span: Span,
        /// Right operand.
        right: SpannedWord,
    },
}

impl IfCondition {
    /// Evaluates a binary comparison (`==`, `EQU`, `NEQ`, `LSS`, `LEQ`, `GTR`, `GEQ`) using
    /// exact `cmd.exe` string vs 32-bit signed integer rules.
    ///
    /// # Arguments
    /// * `left` - Left operand string.
    /// * `op` - [`ComparisonOp`] to apply.
    /// * `right` - Right operand string.
    /// * `case_sensitivity` - Whether string comparison is case-insensitive (`/I`).
    ///
    /// # Returns
    /// `true` if the comparison holds, otherwise `false`.
    #[must_use]
    pub fn evaluate_comparison(
        left: &str,
        op: ComparisonOp,
        right: &str,
        case_sensitivity: CaseSensitivity,
    ) -> bool {
        if op != ComparisonOp::DoubleEquals
            && let (Some(l_int), Some(r_int)) = (parse_if_i32(left), parse_if_i32(right))
        {
            return match op {
                ComparisonOp::Equ | ComparisonOp::DoubleEquals => l_int == r_int,
                ComparisonOp::Neq => l_int != r_int,
                ComparisonOp::Lss => l_int < r_int,
                ComparisonOp::Leq => l_int <= r_int,
                ComparisonOp::Gtr => l_int > r_int,
                ComparisonOp::Geq => l_int >= r_int,
            };
        }

        let ordering = match case_sensitivity {
            CaseSensitivity::Sensitive => left.cmp(right),
            CaseSensitivity::Insensitive => {
                left.to_ascii_uppercase().cmp(&right.to_ascii_uppercase())
            }
        };

        match op {
            ComparisonOp::DoubleEquals | ComparisonOp::Equ => ordering.is_eq(),
            ComparisonOp::Neq => ordering.is_ne(),
            ComparisonOp::Lss => ordering.is_lt(),
            ComparisonOp::Leq => ordering.is_le(),
            ComparisonOp::Gtr => ordering.is_gt(),
            ComparisonOp::Geq => ordering.is_ge(),
        }
    }
}

/// Attempts to parse `s` as an unquoted 32-bit signed integer for `IF ... EQU` comparisons.
///
/// # Arguments
/// * `s` - Candidate operand string.
///
/// # Returns
/// `Some(i32)` if the entire string parses as a valid 32-bit signed integer, else `None`.
fn parse_if_i32(s: &str) -> Option<i32> {
    if s.contains('"') {
        return None;
    }
    let val = crate::parser::var_ops::parse_cmd_int(s)?;
    i32::try_from(val).ok()
}

/// Binary comparison operators in `IF` statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum ComparisonOp {
    /// `==` (string equality).
    #[display("==")]
    DoubleEquals,
    /// `EQU` (equal).
    #[display("EQU")]
    Equ,
    /// `NEQ` (not equal).
    #[display("NEQ")]
    Neq,
    /// `LSS` (less than).
    #[display("LSS")]
    Lss,
    /// `LEQ` (less than or equal).
    #[display("LEQ")]
    Leq,
    /// `GTR` (greater than).
    #[display("GTR")]
    Gtr,
    /// `GEQ` (greater than or equal).
    #[display("GEQ")]
    Geq,
}

impl ComparisonOp {
    /// Parses an uppercase/lowercase comparison keyword (`"EQU"`, `"NEQ"`, etc.).
    ///
    /// # Arguments
    /// * `token` - Candidate operator token.
    ///
    /// # Returns
    /// `Some(ComparisonOp)` if recognized, else `None`.
    #[must_use]
    pub fn from_keyword(token: &str) -> Option<Self> {
        match token.to_ascii_uppercase().as_str() {
            "==" => Some(Self::DoubleEquals),
            "EQU" => Some(Self::Equ),
            "NEQ" => Some(Self::Neq),
            "LSS" => Some(Self::Lss),
            "LEQ" => Some(Self::Leq),
            "GTR" => Some(Self::Gtr),
            "GEQ" => Some(Self::Geq),
            _ => None,
        }
    }
}

/// A `FOR` loop statement (`FOR`, `FOR /D`, `FOR /R`, `FOR /L`, `FOR /F`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForStatement {
    /// Whether prefixed with `@`.
    pub echo_suppression: EchoSuppression,
    /// Loop variant (`Standard`, `Directories`, `Recursive`, `Numeric`, `ParsedLines`).
    pub variant: ForVariant,
    /// Bound loop variable token (`%%I`).
    pub variable: ForVarName,
    /// Raw variable token text as written in source (e.g., `"%%I"` or `"%I"` or `"%%foo"`).
    pub raw_variable_token: String,
    /// Source span of the loop variable token.
    pub variable_span: Span,
    /// Tokenized items inside `IN (...)` (raw unexpanded expressions for deferred runtime evaluation).
    pub in_set: Vec<SpannedWord>,
    /// Raw text inside `IN (...)` (used by `FOR /F`).
    pub in_set_raw: String,
    /// Source span of the `(...)` set.
    pub in_set_span: Span,
    /// Loop body command following `DO`.
    pub body: Box<CommandExpr>,
    /// Full span of the `FOR` statement.
    pub span: Span,
}

impl ForStatement {
    /// Parses runtime-expanded `FOR /L` tokens into `(start, step, end)` 32-bit integers
    /// using `cmd.exe` numeric rules (decimal, `0x` hex, `0` octal, negative signs, and `0` defaults).
    ///
    /// # Arguments
    /// * `expanded_tokens` - Runtime-expanded token strings extracted from `IN (...)`.
    ///
    /// # Returns
    /// Tuple `(start, step, end)` where missing or unparseable operands default to `0` matching `cmd.exe`.
    #[must_use]
    pub fn parse_numeric_bounds(expanded_tokens: &[String]) -> (i32, i32, i32) {
        let parse_at = |idx: usize| -> i32 {
            expanded_tokens
                .get(idx)
                .and_then(|s| crate::parser::var_ops::parse_cmd_int(s))
                .and_then(|v| i32::try_from(v).ok())
                .unwrap_or(0)
        };
        (parse_at(0), parse_at(1), parse_at(2))
    }
}

/// Variants of the `FOR` loop statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForVariant {
    /// Standard `FOR %%I IN (set) DO ...`.
    StandardFiles,
    /// `FOR /D %%I IN (set) DO ...` (directories only).
    DirectoriesOnly,
    /// `FOR /R [[drive:]path] %%I IN (set) DO ...` (recursive directory walk).
    Recursive {
        /// Optional root directory path.
        root_path: Option<SpannedWord>,
    },
    /// `FOR /L %%I IN (start,step,end) DO ...` (numeric sequence evaluated at runtime from `ForStatement::in_set`).
    NumericSequence,
    /// `FOR /F ["options"] %%I IN (...) DO ...` (file/string/command line parsing).
    ParsedLines(ForFOptions),
}

/// Parsed options for `FOR /F ["options"]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForFOptions {
    /// End-of-line comment character (defaults to `Some(';')`).
    pub eol: Option<char>,
    /// Number of initial lines to skip (`skip=n`).
    pub skip: usize,
    /// Delimiter character set (defaults to `[' ', '\t']`).
    pub delims: Vec<char>,
    /// 1-based token selectors (defaults to `[TokenSelector::Single(1)]`).
    pub tokens: Vec<TokenSelector>,
    /// Whether `usebackq` is enabled.
    pub use_backq: bool,
}

impl Default for ForFOptions {
    /// Constructs default `FOR /F` options (`eol=;`, `skip=0`, `delims= \t`, `tokens=1`, `usebackq=false`).
    ///
    /// # Returns
    /// Default [`ForFOptions`] instance matching `cmd.exe`.
    fn default() -> Self {
        Self {
            eol: Some(';'),
            skip: 0,
            delims: vec![' ', '\t'],
            tokens: vec![TokenSelector::Single(1)],
            use_backq: false,
        }
    }
}

impl ForFOptions {
    /// Parses a `FOR /F` options string (e.g., `"eol=# tokens=1,2* delims=, skip=1 usebackq"`).
    ///
    /// # Arguments
    /// * `raw_opts` - Options string (with or without outer quotes).
    ///
    /// # Returns
    /// Populated [`ForFOptions`].
    #[must_use]
    pub fn parse(raw_opts: &str) -> Self {
        let mut opts = Self::default();
        let unquoted = crate::parser::modifiers::strip_surrounding_quotes(raw_opts);
        let mut rest = unquoted;

        while !rest.is_empty() {
            let trimmed = rest.trim_start();
            if trimmed.is_empty() {
                break;
            }
            let lower = trimmed.to_ascii_lowercase();
            if let Some(after_delims) = lower.strip_prefix("delims=") {
                let prefix_len = trimmed.len().saturating_sub(after_delims.len());
                let raw_after = trimmed.get(prefix_len..).unwrap_or("");
                if raw_after.is_empty() {
                    opts.delims = Vec::new();
                    break;
                } else if raw_after.trim().is_empty() {
                    opts.delims = vec![' '];
                    break;
                }
                let end = raw_after.find(' ').unwrap_or(raw_after.len());
                let d_slice = raw_after.get(..end).unwrap_or("");
                opts.delims = d_slice.chars().collect();
                rest = raw_after.get(end..).unwrap_or("");
                continue;
            }

            let tok_end = trimmed.find(' ').unwrap_or(trimmed.len());
            let token = trimmed.get(..tok_end).unwrap_or("");
            rest = trimmed.get(tok_end..).unwrap_or("");

            let tok_lower = token.to_ascii_lowercase();
            if tok_lower == "usebackq" {
                opts.use_backq = true;
            } else if tok_lower.starts_with("eol=") {
                opts.eol = token.get(4..).and_then(|s| s.chars().next());
            } else if let Some(skip_val) = tok_lower.strip_prefix("skip=") {
                opts.skip = skip_val.parse::<usize>().unwrap_or(0);
            } else if let Some(tok_spec) = tok_lower.strip_prefix("tokens=") {
                opts.tokens = parse_token_selectors(tok_spec);
            }
        }

        opts
    }
}

/// Token selection item inside `FOR /F "tokens=..."`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSelector {
    /// A single 1-based token index (e.g., `1` or `3`).
    Single(usize),
    /// An inclusive 1-based token range `start..=end` (e.g., `2-4`).
    Range(usize, usize),
    /// Trailing `*` capturing the unsplit remainder of the line after the highest selected token.
    RemainderStar,
}

/// Parses a `tokens=1,3-5*` specification into a vector of [`TokenSelector`].
///
/// # Arguments
/// * `spec` - Specification string after `tokens=`.
///
/// # Returns
/// Vector of [`TokenSelector`]s.
fn parse_token_selectors(spec: &str) -> Vec<TokenSelector> {
    let has_star = spec.ends_with('*');
    let body = spec.trim_end_matches('*');
    let mut selectors = Vec::new();

    for part in body.split(',').filter(|p| !p.is_empty()) {
        if let Some((s_str, e_str)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (s_str.parse::<usize>(), e_str.parse::<usize>())
                && (1..=e).contains(&s)
            {
                selectors.push(TokenSelector::Range(s, e));
            }
        } else if let Ok(n) = part.parse::<usize>()
            && n >= 1
        {
            selectors.push(TokenSelector::Single(n));
        }
    }

    if has_star {
        selectors.push(TokenSelector::RemainderStar);
    }
    if selectors.is_empty() {
        selectors.push(TokenSelector::Single(1));
    }
    selectors
}

#[cfg(test)]
/// Unit tests for AST node spans, `IF` comparisons, and `FOR /F` option parsing.
mod tests {
    use super::*;

    /// Verifies [`SpannedWord`], [`Statement`], and [`CommandExpr`] span accessors and formatting.
    #[test]
    fn test_spanned_word_and_statement_spans() {
        let s = Span::new(SourceId(0), ByteOffset(2), ByteOffset(8));
        let part = WordPart::new(WordPartKind::Quoted, r#""hello""#.to_owned(), s);
        assert_eq!(part.to_string(), r#""hello""#);
        assert_eq!(WordPartKind::EnvVar.to_string(), "EnvVar");
        let w_parts = SpannedWord::with_parts(
            r#""hello""#.to_owned(),
            s,
            crate::types::QuoteMode::InQuotes,
            SpecialCharPresence::Plain,
            vec![part],
        );
        assert_eq!(w_parts.parts.len(), 1);
        let w = SpannedWord::new(r#""hello""#.to_owned(), s);
        assert!(w.quoted);
        assert_eq!(w.unquoted(), "hello");
        assert_eq!(w.to_string(), r#""hello""#);

        let empty_stmt = Statement::Empty(s);
        assert_eq!(empty_stmt.span(), s);
        let rem_stmt = Statement::Rem(RemNode {
            echo_suppression: EchoSuppression::NotSuppressed,
            comment_text: "hi".to_owned(),
            span: s,
        });
        assert_eq!(rem_stmt.span(), s);
        let lbl_stmt = Statement::Label(LabelNode {
            name: LabelName::new("lbl"),
            raw_body: "lbl".to_owned(),
            is_double_colon: false,
            has_invalid_label_chars: false,
            next_line_offset: ByteOffset(10),
            span: s,
        });
        assert_eq!(lbl_stmt.span(), s);
        let blk_expr = CommandExpr::Block(CompoundBlock {
            echo_suppression: EchoSuppression::NotSuppressed,
            body: Vec::new(),
            redirections: Vec::new(),
            span: s,
        });
        assert_eq!(Statement::Command(blk_expr).span(), s);
        let if_expr = CommandExpr::If(Box::new(IfStatement {
            echo_suppression: EchoSuppression::NotSuppressed,
            case_sensitivity: CaseSensitivity::Sensitive,
            negated: NegationMode::Normal,
            condition: IfCondition::Defined { var_name: w },
            then_branch: Box::new(CommandExpr::Block(CompoundBlock {
                echo_suppression: EchoSuppression::NotSuppressed,
                body: Vec::new(),
                redirections: Vec::new(),
                span: s,
            })),
            else_branch: None,
            has_dangling_else: false,
            span: s,
        }));
        assert_eq!(if_expr.span(), s);
        let for_expr = CommandExpr::For(Box::new(ForStatement {
            echo_suppression: EchoSuppression::NotSuppressed,
            variant: ForVariant::StandardFiles,
            variable: ForVarName(b'I'),
            raw_variable_token: "%%I".to_owned(),
            variable_span: s,
            in_set: Vec::new(),
            in_set_raw: String::new(),
            in_set_span: s,
            body: Box::new(if_expr.clone()),
            span: s,
        }));
        assert_eq!(for_expr.span(), s);

        let pipe_expr = CommandExpr::Pipe {
            left: Box::new(if_expr.clone()),
            right: Box::new(for_expr.clone()),
            op_span: s,
            span: s,
        };
        assert_eq!(pipe_expr.span(), s);
        let and_expr = CommandExpr::And {
            left: Box::new(if_expr.clone()),
            right: Box::new(for_expr.clone()),
            op_span: s,
            span: s,
        };
        assert_eq!(and_expr.span(), s);
        let or_expr = CommandExpr::Or {
            left: Box::new(if_expr.clone()),
            right: Box::new(for_expr.clone()),
            op_span: s,
            span: s,
        };
        assert_eq!(or_expr.span(), s);
        let seq_expr = CommandExpr::Seq {
            left: Box::new(if_expr),
            right: Box::new(for_expr),
            op_span: s,
            span: s,
        };
        assert_eq!(seq_expr.span(), s);
    }

    /// Verifies `IF` string vs numeric (`EQU`..`GEQ`, hex/octal, quoted) comparison semantics.
    #[test]
    fn test_if_condition_comparisons() {
        assert_eq!(
            ComparisonOp::from_keyword("=="),
            Some(ComparisonOp::DoubleEquals)
        );
        assert_eq!(ComparisonOp::from_keyword("equ"), Some(ComparisonOp::Equ));
        assert_eq!(ComparisonOp::from_keyword("NEQ"), Some(ComparisonOp::Neq));
        assert_eq!(ComparisonOp::from_keyword("LSS"), Some(ComparisonOp::Lss));
        assert_eq!(ComparisonOp::from_keyword("LEQ"), Some(ComparisonOp::Leq));
        assert_eq!(ComparisonOp::from_keyword("GTR"), Some(ComparisonOp::Gtr));
        assert_eq!(ComparisonOp::from_keyword("GEQ"), Some(ComparisonOp::Geq));
        assert_eq!(ComparisonOp::from_keyword("BOGUS"), None);

        // Numeric vs string comparison in IF
        // `==` is ALWAYS string comparison (`"01" == "1"` is false)
        assert!(!IfCondition::evaluate_comparison(
            "01",
            ComparisonOp::DoubleEquals,
            "1",
            CaseSensitivity::Sensitive
        ));
        // `EQU` on valid integers (`010 EQU 8` -> octal 8 == 8 -> true!)
        assert!(IfCondition::evaluate_comparison(
            "010",
            ComparisonOp::Equ,
            "8",
            CaseSensitivity::Sensitive
        ));
        assert!(IfCondition::evaluate_comparison(
            "2",
            ComparisonOp::Lss,
            "10",
            CaseSensitivity::Sensitive
        ));
        assert!(IfCondition::evaluate_comparison(
            "2",
            ComparisonOp::Leq,
            "2",
            CaseSensitivity::Sensitive
        ));
        assert!(IfCondition::evaluate_comparison(
            "10",
            ComparisonOp::Gtr,
            "2",
            CaseSensitivity::Sensitive
        ));
        assert!(IfCondition::evaluate_comparison(
            "10",
            ComparisonOp::Geq,
            "10",
            CaseSensitivity::Sensitive
        ));
        assert!(IfCondition::evaluate_comparison(
            "1",
            ComparisonOp::Neq,
            "2",
            CaseSensitivity::Sensitive
        ));

        // Quoted strings fall back to lexicographical comparison (`"10" LSS "2"` is true!)
        assert!(IfCondition::evaluate_comparison(
            r#""10""#,
            ComparisonOp::Lss,
            r#""2""#,
            CaseSensitivity::Sensitive
        ));
        assert!(IfCondition::evaluate_comparison(
            "abc",
            ComparisonOp::Equ,
            "ABC",
            CaseSensitivity::Insensitive
        ));
        assert!(IfCondition::evaluate_comparison(
            "abc",
            ComparisonOp::Neq,
            "def",
            CaseSensitivity::Insensitive
        ));
        assert!(IfCondition::evaluate_comparison(
            "a",
            ComparisonOp::Leq,
            "b",
            CaseSensitivity::Sensitive
        ));
        assert!(IfCondition::evaluate_comparison(
            "b",
            ComparisonOp::Gtr,
            "a",
            CaseSensitivity::Sensitive
        ));
        assert!(IfCondition::evaluate_comparison(
            "b",
            ComparisonOp::Geq,
            "a",
            CaseSensitivity::Sensitive
        ));
    }

    /// Verifies `FOR /F` option string parsing (`eol`, `skip`, `tokens`, `delims`, `usebackq`).
    #[test]
    fn test_for_f_options_parsing() {
        let opts = ForFOptions::parse(r#""eol=# skip=2 tokens=1,3-4* usebackq delims=,:""#);
        assert_eq!(opts.eol, Some('#'));
        assert_eq!(opts.skip, 2);
        assert!(opts.use_backq);
        assert_eq!(opts.delims, vec![',', ':']);
        assert_eq!(
            opts.tokens,
            vec![
                TokenSelector::Single(1),
                TokenSelector::Range(3, 4),
                TokenSelector::RemainderStar
            ]
        );

        let empty_delims = ForFOptions::parse("delims=");
        assert_eq!(empty_delims.delims.len(), 0);

        let space_delims = ForFOptions::parse("delims= ");
        assert_eq!(space_delims.delims, vec![' ']);

        let default_tokens = ForFOptions::parse("tokens=invalid,1-bad,0-3,3-1,0 unknown=1   ");
        assert_eq!(default_tokens.tokens, vec![TokenSelector::Single(1)]);

        assert_eq!(ForStatement::parse_numeric_bounds(&[]), (0, 0, 0));
        assert_eq!(
            ForStatement::parse_numeric_bounds(&[
                "0x10".to_owned(),
                "-2".to_owned(),
                "010".to_owned(),
            ]),
            (16, -2, 8)
        );
        assert_eq!(
            ForStatement::parse_numeric_bounds(&[
                "99999999999999".to_owned(),
                "bad".to_owned(),
                "5".to_owned(),
            ]),
            (0, 0, 5)
        );

        let interior_word =
            SpannedWord::new(r#"C:/"Program Files"/app.exe"#.to_owned(), Span::dummy());
        assert_eq!(interior_word.unquoted(), "C:/Program Files/app.exe");
    }
}
