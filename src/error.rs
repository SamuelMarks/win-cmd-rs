//! Unified error architecture for `win-cmd-rs`.
//!
//! Instead of using `anyhow` or erased error trait objects, every fallible operation
//! across the reader, multi-pass expander, parser, VFS, arithmetic engine, runtime,
//! built-in commands, CLI, and static linter returns a single strongly typed [`CmdError`]
//! enum derived via `derive_more`.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use derive_more::{Display, Error, From, IsVariant};

use crate::span::{ByteOffset, Span};
use crate::types::{
    CodePage, DosErrorCode, DosExtendedError, DriveLetter, ExitCode, FileDescriptor, IoErrorKind,
    LabelName,
};

/// Grammar constructs expected by the PEG parser at a farthest-failure location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display, IsVariant)]
pub enum PegExpected {
    /// Expected a command name or executable token.
    #[display("command name")]
    CommandName,
    /// Expected a top-level or block statement.
    #[display("statement")]
    Statement,
    /// Expected `)` to close a compound block `(...)`.
    #[display("')' to close compound block")]
    ClosingParen,
    /// Expected `(` after `IN` in a `FOR` loop.
    #[display("'(' after IN in FOR loop")]
    ForSetOpenParen,
    /// Expected `)` to close a `FOR` loop set `(...)`.
    #[display("')' to close FOR set")]
    ForSetCloseParen,
    /// Expected `IN` keyword in a `FOR` loop.
    #[display("'IN' keyword in FOR loop")]
    InKeyword,
    /// Expected `DO` keyword after a `FOR (...)` set.
    #[display("'DO' keyword after FOR (...) set")]
    DoKeyword,
    /// Expected a `FOR` loop variable token (`%%I` or `%I`).
    #[display("FOR loop variable (e.g., %%I or %I)")]
    ForVariable,
    /// Expected an `IF` condition (`EXIST`, `DEFINED`, `ERRORLEVEL`, `CMDEXTVERSION`, or comparison).
    #[display("IF condition (EXIST, DEFINED, ERRORLEVEL, CMDEXTVERSION, or comparison)")]
    IfCondition,
    /// Expected a comparison operator (`==`, `EQU`, `NEQ`, `LSS`, `LEQ`, `GTR`, `GEQ`).
    #[display("comparison operator ('==', 'EQU', 'NEQ', 'LSS', 'LEQ', 'GTR', 'GEQ')")]
    ComparisonOperator,
    /// Expected a right-hand operand in an `IF` comparison or condition.
    #[display("right-hand operand in IF comparison")]
    ComparisonOperand,
    /// Expected a command following an `IF` condition.
    #[display("command following IF condition")]
    IfThenBranch,
    /// Expected a command following the `ELSE` keyword.
    #[display("command following ELSE keyword")]
    ElseBranch,
    /// Expected a command following the `DO` keyword in a `FOR` loop.
    #[display("command following DO keyword")]
    ForBodyBranch,
    /// Expected a command after a `|` pipe operator.
    #[display("command after '|' pipe operator")]
    PipelineRightOperand,
    /// Expected a command before a `|` pipe operator.
    #[display("command before '|' pipe operator")]
    PipelineLeftOperand,
    /// Expected a command after `&`, `&&`, or `||`.
    #[display("command after '&', '&&', or '||' operator")]
    ChainRightOperand,
    /// Expected a command before `&`, `&&`, or `||`.
    #[display("command before '&', '&&', or '||' operator")]
    ChainLeftOperand,
    /// Expected a target filename or handle after a redirection operator (`<`, `>`, `>>`, `>&`).
    #[display("filename or handle after redirection operator")]
    RedirectionTarget,
    /// Expected an arithmetic expression after `SET /A`.
    #[display("arithmetic expression after SET /A")]
    SetArithmeticExpr,
    /// Expected a closing `"` double quote.
    #[display(r#"closing '"' double quote"#)]
    ClosingDoubleQuote,
    /// Expected a closing `%` for environment variable expansion.
    #[display("closing '%' for variable expansion")]
    ClosingPercent,
    /// Expected a closing `!` for delayed environment variable expansion.
    #[display("closing '!' for delayed variable expansion")]
    ClosingExclamation,
}

/// Formats a slice of [`PegExpected`] items into a comma-separated diagnostic list.
///
/// # Arguments
/// * `expected` - Ordered slice of expected grammar constructs at the failure frontier.
///
/// # Returns
/// A human-readable list of expected items, or `"valid command syntax"` when `expected` is empty.
#[must_use]
pub fn format_peg_expected_slice(expected: &[PegExpected]) -> String {
    if expected.is_empty() {
        return "valid command syntax".to_owned();
    }
    expected
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Specific categories of probable syntax misuse recognized by ordered-choice PEG recovery rules.
#[derive(Debug, Clone, PartialEq, Eq, Display, IsVariant)]
pub enum ProbableMisuseKind {
    /// Single `=` used in an `IF` comparison (`IF a = b`) instead of `==` or `EQU`.
    #[display("single '=' used in IF comparison at {span} (use '==' or 'EQU')")]
    SingleEqualsInIf {
        /// Source span of the single `=` token.
        span: Span,
    },
    /// C-style parentheses placed around an `IF` condition (`IF (a == b) cmd`).
    #[display("parentheses around IF condition at {span}")]
    ParenthesizedIfCondition {
        /// Source span of the parenthesized condition.
        span: Span,
    },
    /// Missing `IN` keyword before `(set)` in a `FOR` loop (`FOR %%I (a b) DO ...`).
    #[display("missing 'IN' keyword in FOR loop at {span}")]
    MissingInKeywordInFor {
        /// Source span where `IN` was expected.
        span: Span,
    },
    /// Missing `DO` keyword after `(set)` in a `FOR` loop (`FOR %%I IN (a b) echo %%I`).
    #[display("missing 'DO' keyword in FOR loop at {span}")]
    MissingDoKeywordInFor {
        /// Source span where `DO` was expected.
        span: Span,
    },
    /// Unparenthesized `then` branch followed by `ELSE` (`IF cond cmd1 ELSE cmd2`).
    #[display("unparenthesized IF then-branch before ELSE at {span}")]
    UnparenthesizedElseBranch {
        /// Source span of the dangling `ELSE` keyword.
        span: Span,
    },
    /// Single-percent `FOR` variable (`%I`) used inside a `.bat`/`.cmd` file instead of `%%I`.
    #[display("single-percent FOR variable '{raw_var}' in batch file at {span}")]
    SinglePercentForVarInBatch {
        /// Source span of the `%I` token.
        span: Span,
        /// Raw token text (e.g., `"%I"`).
        raw_var: String,
    },
    /// Double-percent `FOR` variable (`%%I`) used in interactive REPL mode instead of `%I`.
    #[display("double-percent FOR variable '{raw_var}' in interactive REPL at {span}")]
    DoublePercentForVarInRepl {
        /// Source span of the `%%I` token.
        span: Span,
        /// Raw token text (e.g., `"%%I"`).
        raw_var: String,
    },
    /// Multi-character `FOR` variable (`%%item`) instead of a single character (`%%I`).
    #[display("multi-character FOR variable '{raw_var}' at {span}")]
    MultiCharForVariable {
        /// Source span of the multi-character variable token.
        span: Span,
        /// Raw token text (e.g., `"%%item"`).
        raw_var: String,
    },
    /// Unescaped `)` inside an unquoted command or `ECHO` inside a `( ... )` compound block.
    #[display("unescaped ')' inside compound block at {span}")]
    UnescapedClosingParenInBlock {
        /// Source span of the offending `)`.
        span: Span,
    },
    /// Unclosed double quote `"` on a logical line.
    #[display(r#"unclosed double quote '"' at {span}"#)]
    UnclosedDoubleQuote {
        /// Source span of the unclosed quoted string.
        span: Span,
    },
    /// Path modifier (`%~dp...`) applied to a named environment variable (`%~dpVAR%`).
    #[display("invalid path modifier on named variable '{raw_token}' at {span}")]
    InvalidModifierOnNamedVar {
        /// Source span of the invalid token.
        span: Span,
        /// Raw token text (e.g., `"%~dpMYVAR%"`).
        raw_token: String,
    },
    /// Unescaped single `%` literal in a batch file (`echo 50%` instead of `echo 50%%`).
    #[display("unescaped single '%' in batch file at {span}")]
    UnescapedSinglePercentInBatch {
        /// Source span of the bare `%` token.
        span: Span,
    },
    /// Double `%%` literal in interactive REPL mode where `%%` is not collapsed to `%`.
    #[display("double '%%' literal in interactive REPL at {span}")]
    DoublePercentLiteralInRepl {
        /// Source span of the `%%` token.
        span: Span,
    },
}

impl ProbableMisuseKind {
    /// Returns the primary source [`Span`] of this probable syntax misuse.
    ///
    /// # Returns
    /// The [`Span`] of the offending token or construct.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::SingleEqualsInIf { span }
            | Self::ParenthesizedIfCondition { span }
            | Self::MissingInKeywordInFor { span }
            | Self::MissingDoKeywordInFor { span }
            | Self::UnparenthesizedElseBranch { span }
            | Self::SinglePercentForVarInBatch { span, .. }
            | Self::DoublePercentForVarInRepl { span, .. }
            | Self::MultiCharForVariable { span, .. }
            | Self::UnescapedClosingParenInBlock { span }
            | Self::UnclosedDoubleQuote { span }
            | Self::InvalidModifierOnNamedVar { span, .. }
            | Self::UnescapedSinglePercentInBatch { span }
            | Self::DoublePercentLiteralInRepl { span } => *span,
        }
    }
}

/// CLI binary reporting a structured usage failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, IsVariant)]
pub enum CliTool {
    /// `wincmd` (`cmd.exe`-compatible interpreter binary, exit code `1` on switch errors).
    #[display("wincmd")]
    WinCmd,
    /// `wincheck` (`ShellCheck`-style linter binary, exit code `2` on CLI usage errors).
    #[display("wincheck")]
    WinCheck,
}

/// Structured reason for a CLI option or argument usage error.
#[derive(Debug, Clone, PartialEq, Eq, Display, IsVariant)]
pub enum CliErrorReason {
    /// A CLI flag requiring an argument was supplied at the end of `argv` without a value.
    #[display("requires an argument")]
    MissingValue,
    /// An unrecognized CLI option flag was supplied.
    #[display("unrecognized option")]
    UnknownFlag,
    /// An unsupported value was passed to `--format`.
    #[display("unsupported output format '{_0}'")]
    InvalidFormatValue(String),
    /// An unsupported value was passed to `--mode`.
    #[display("unsupported dialect mode '{_0}'")]
    InvalidModeValue(String),
    /// An unsupported value was passed to `--severity`.
    #[display("unsupported severity '{_0}'")]
    InvalidSeverityValue(String),
    /// An unsupported value was passed to `--encoding`.
    #[display("unsupported encoding '{_0}'")]
    InvalidEncodingValue(String),
    /// Multiple files were passed to `--fix` without `--in-place` (preventing concatenated stdout corruption).
    #[display("cannot write multiple fixed files to stdout; pass --in-place")]
    MultiFileStdoutFixRequiresInPlace,
    /// `--in-place` was combined with `'-'` standard input.
    #[display("--in-place cannot be used with '-' (stdin)")]
    InPlaceCannotUseStdin,
    /// No input files were provided when at least one file (or `'-'`) is required.
    #[display("no input files specified")]
    MissingInputFiles,
}

/// Strongly typed CLI usage error payload convertible into [`CmdError`] via `derive_more::From`.
#[derive(Debug, Clone, PartialEq, Eq, Display)]
#[display("{tool}: {flag}: {reason}")]
pub struct CliUsageFailure {
    /// CLI binary reporting the usage error (`wincmd` vs `wincheck`).
    pub tool: CliTool,
    /// Offending CLI flag, option name, or binary name.
    pub flag: String,
    /// Structured explanation of why CLI parsing failed.
    pub reason: CliErrorReason,
}

impl CliUsageFailure {
    /// Creates a structured [`CliUsageFailure`] for `tool`, `flag`, and `reason`.
    ///
    /// # Arguments
    /// * `tool` - Originating [`CliTool`] (`WinCmd` or `WinCheck`).
    /// * `flag` - Offending flag, switch, or binary label.
    /// * `reason` - Structured [`CliErrorReason`].
    ///
    /// # Returns
    /// Constructed [`CliUsageFailure`].
    #[must_use]
    pub fn new(tool: CliTool, flag: impl Into<String>, reason: CliErrorReason) -> Self {
        Self {
            tool,
            flag: flag.into(),
            reason,
        }
    }
}

/// Category of interpreter safety budget exceeded during script or loop execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, IsVariant)]
pub enum LimitKind {
    /// Total executed statement count exceeded budget (`GOTO` loop protection).
    #[display("maximum statement step budget")]
    MaxSteps,
    /// Nested `CALL` stack depth exceeded budget.
    #[display("maximum CALL recursion depth")]
    MaxCallDepth,
    /// Iteration count within a single `FOR /L` loop exceeded budget.
    #[display("maximum FOR /L loop iteration budget")]
    MaxLoopIterations,
}

/// Strongly typed execution-budget failure convertible into [`CmdError`] via `derive_more::From`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[display("Execution aborted: exceeded {kind} ({limit})")]
pub struct ExecutionLimitFailure {
    /// Which resource budget was exceeded.
    pub kind: LimitKind,
    /// Configured numeric limit that was reached.
    pub limit: usize,
    /// Source span of the statement or loop where the limit tripped.
    pub span: Span,
}

/// Single unified error enum covering all subsystems of `win-cmd-rs`.
#[derive(Debug, Clone, PartialEq, Eq, Display, Error, From, IsVariant)]
pub enum CmdError {
    /// Encountered an unexpected token during syntax parsing (`... was unexpected at this time.`).
    #[display("{token} was unexpected at this time.")]
    UnexpectedToken {
        /// Source span of the unexpected token.
        span: Span,
        /// Text of the unexpected token.
        token: String,
    },

    /// General command syntax error (`The syntax of the command is incorrect.`).
    #[display("The syntax of the command is incorrect.")]
    SyntaxError {
        /// Source span where syntax failed.
        span: Span,
    },

    /// Unbalanced or unclosed parenthesis in a compound block `(...)`.
    #[display("The syntax of the command is incorrect.")]
    UnbalancedParenthesis {
        /// Source span of the unclosed or unmatched parenthesis.
        span: Span,
    },

    /// Invalid batch-parameter or `FOR`-variable path operator sequence (`%~...`).
    #[display(
        "The following usage of the path operator in batch-parameter substitution is invalid: {sequence}"
    )]
    InvalidParameterModifier {
        /// Source span of the invalid modifier sequence.
        span: Span,
        /// The offending modifier sequence string.
        sequence: String,
    },

    /// Target label of a `GOTO` or `CALL :label` statement could not be found.
    #[display("The system cannot find the batch label specified - {label}")]
    BatchLabelNotFound {
        /// Source span of the `GOTO` or `CALL` statement.
        span: Span,
        /// Name of the missing batch label.
        label: LabelName,
    },

    /// Target batch file disappeared or could not be opened during execution.
    #[display("The batch file cannot be found.")]
    MissingBatchFile {
        /// Path of the missing batch script.
        #[error(not(source))]
        path: String,
    },

    /// Invoked command name is not an internal command, operable program, or batch file.
    #[display(
        "'{command}' is not recognized as an internal or external command,
operable program or batch file."
    )]
    CommandNotRecognized {
        /// Source span of the command token.
        span: Span,
        /// Unrecognized command name.
        command: String,
    },

    /// An unrecognized `/switch` was supplied to a built-in command.
    #[display(r#"Invalid switch - "{switch}"."#)]
    InvalidSwitch {
        /// Source span of the switch token.
        span: Span,
        /// Switch text without leading slash or with slash as reported by the command.
        switch: String,
    },

    /// A command parameter had an invalid format.
    #[display("Parameter format not correct - {param}.")]
    ParameterFormatNotCorrect {
        /// Source span of the malformed parameter.
        span: Span,
        /// Text of the malformed parameter.
        param: String,
    },

    /// An invalid numeric constant (e.g., octal `08` or `09`) was encountered in `SET /A` or a command.
    #[display(
        "Invalid number.  Numeric constants are either decimal (17), hexadecimal (0x11), or octal (021)."
    )]
    InvalidNumber {
        /// Source span of the invalid number token.
        span: Span,
        /// Text of the invalid number.
        text: String,
    },

    /// A numeric literal overflowed 32-bit signed precision.
    #[display("Invalid number.  Numbers are limited to 32-bits of precision.")]
    NumberOutOfRange {
        /// Source span of the out-of-range number literal.
        span: Span,
        /// Text of the number literal.
        text: String,
    },

    /// Division or modulo by zero inside `SET /A`.
    #[display("Divide by zero error.")]
    DivideByZero {
        /// Source span of the `/` or `%` operation.
        span: Span,
    },

    /// Missing operand in a `SET /A` arithmetic expression.
    #[display("Missing operand.")]
    MissingOperand {
        /// Source span where an operand was expected.
        span: Span,
    },

    /// Missing operator in a `SET /A` arithmetic expression.
    #[display("Missing operator.")]
    MissingOperator {
        /// Source span where an operator was expected.
        span: Span,
    },

    /// Unbalanced parentheses inside a `SET /A` arithmetic expression.
    #[display("Unbalanced parentheses.")]
    UnbalancedParensArithmetic {
        /// Source span of the unbalanced parenthesis in `SET /A`.
        span: Span,
    },

    /// Requested file does not exist on the VFS.
    #[display("The system cannot find the file specified.")]
    FileNotFound {
        /// Path of the missing file.
        #[error(not(source))]
        path: String,
    },

    /// Requested directory path does not exist on the VFS.
    #[display("The system cannot find the path specified.")]
    PathNotFound {
        /// Path of the missing directory.
        #[error(not(source))]
        path: String,
    },

    /// Malformed or incomplete UNC network path (missing server or share component).
    #[display("The network path was not found.")]
    InvalidUncPath {
        /// Raw malformed UNC path string.
        #[error(not(source))]
        raw: String,
    },

    /// UNC network share (`\\server\share`) is not mounted or reachable.
    #[display("The network path was not found.")]
    NetworkPathNotFound {
        /// Requested UNC path string.
        #[error(not(source))]
        path: String,
    },

    /// Requested drive letter is not mounted in the VFS.
    #[display("The system cannot find the drive specified.")]
    DriveNotFound {
        /// The unmounted [`DriveLetter`].
        #[error(not(source))]
        drive: DriveLetter,
    },

    /// Attempted to create a directory or file that already exists.
    #[display("A subdirectory or file {path} already exists.")]
    FileAlreadyExists {
        /// Path of the existing entry.
        #[error(not(source))]
        path: String,
    },

    /// Attempted to remove a non-empty directory without `/S`.
    #[display("The directory is not empty.")]
    DirectoryNotEmpty {
        /// Path of the non-empty directory.
        #[error(not(source))]
        path: String,
    },

    /// Permission denied (e.g., deleting or writing a Read-Only file without `/F`).
    #[display("Access is denied.")]
    AccessDenied {
        /// Path for which access was denied.
        #[error(not(source))]
        path: String,
    },

    /// File is locked or in use by another process.
    #[display("The process cannot access the file because it is being used by another process.")]
    SharingViolation {
        /// Path of the locked file.
        #[error(not(source))]
        path: String,
    },

    /// Attempted to copy a file onto itself.
    #[display("The file cannot be copied onto itself.")]
    CannotCopyOntoItself {
        /// Path of the file.
        #[error(not(source))]
        path: String,
    },

    /// Attempted a cyclic recursive copy (`XCOPY /S` into a subdirectory of source).
    #[display("Cannot perform a cyclic copy")]
    CyclicCopy {
        /// Path involved in the cycle.
        #[error(not(source))]
        path: String,
    },

    /// An invalid character was used as a drive letter.
    #[display("Invalid drive specification.")]
    InvalidDriveLetter {
        /// The invalid drive character.
        #[error(not(source))]
        ch: char,
    },

    /// `COLOR` command was invoked with identical foreground and background nibbles.
    #[display(
        "The COLOR command sets ERRORLEVEL to 1 if an attempt is made to execute the COLOR command with a foreground and background color that are the same."
    )]
    SameColorForegroundAndBackground {
        /// The duplicated 4-bit color nibble (`0x0..=0xF`).
        #[error(not(source))]
        nibble: u8,
    },

    /// `SET prefix` found no matching environment variables.
    #[display("Environment variable {name} not defined")]
    EnvironmentVariableNotDefined {
        /// Variable name or prefix that was not found.
        #[error(not(source))]
        name: String,
    },

    /// `CHCP` was given an unsupported code page number.
    #[display("Invalid code page")]
    InvalidCodePage {
        /// Unrecognized numeric code page ID.
        #[error(not(source))]
        code: u32,
    },

    /// Registry key path had an invalid hive or empty key name (`REG` command).
    #[display("ERROR: Invalid key name.")]
    InvalidRegistryKey {
        /// Offending raw registry key string.
        #[error(not(source))]
        raw: String,
    },

    /// Registry value or data specification was malformed (`REG` command).
    #[display("ERROR: Invalid syntax.")]
    InvalidRegistryValue {
        /// Target registry key path.
        key: String,
        /// Offending value or data text.
        value: String,
    },

    /// I/O stream redirection failed.
    #[display("{reason}")]
    RedirectionFailed {
        /// Source span of the redirection operator.
        span: Span,
        /// File descriptor handle involved.
        fd: FileDescriptor,
        /// Target file or handle specification.
        target: String,
        /// Human-readable `cmd.exe` error reason.
        reason: String,
    },

    /// Character decoding or encoding failed at a byte offset.
    #[display("Encoding failure at offset {offset} for codepage {codepage}: {detail}")]
    EncodingFailure {
        /// Byte offset where decoding failed.
        offset: ByteOffset,
        /// Active [`CodePage`].
        codepage: CodePage,
        /// Detailed failure description.
        detail: String,
    },

    /// Byte-offset seek landed outside valid buffer or character boundaries for the active codepage.
    #[display("Byte offset {offset} is out of bounds or misaligned for codepage {codepage}")]
    EncodingByteOffsetMismatch {
        /// Offending raw or logical byte offset.
        offset: ByteOffset,
        /// Active [`CodePage`] when seeking.
        codepage: CodePage,
    },

    /// Maximum `cmd.exe` command line length (`8191` chars) was exceeded.
    #[display("The input line is too long.")]
    LineTooLong {
        /// Source span of the overly long line.
        span: Span,
    },

    /// Downstream pipe reader closed before output write completed.
    #[display("The process tried to write to a nonexistent pipe.")]
    BrokenPipe,

    /// External child process failed to spawn or wait cleanly.
    #[display("Failed to execute '{program}' ({kind:?}): {message}")]
    ChildProcessFailure {
        /// Executable path or command name.
        program: String,
        /// Portable [`IoErrorKind`] describing the failure reason.
        kind: IoErrorKind,
        /// OS or DOS error description.
        message: String,
    },

    /// Conventional or DPMI memory was insufficient to complete an operation or load a child program.
    #[display("Program too big to fit in memory")]
    InsufficientMemory,

    /// Serialized MS-DOS environment segment exceeded configured `/E:nnnnn` or 32 KiB capacity.
    #[display("Out of environment space")]
    OutOfEnvironmentSpace,

    /// External MS-DOS command tail exceeded the 126-byte Program Segment Prefix (`PSP:0x80`) limit.
    #[display("Command line too long ({length} bytes exceeds {limit}-byte limit)")]
    CommandLineTooLong {
        /// Actual encoded byte length of the command tail.
        length: usize,
        /// Maximum permitted byte length (`126` on real-mode MS-DOS PSP).
        limit: usize,
    },

    /// Requested filesystem or OS feature is unsupported on the active backend (e.g., symlinks on MS-DOS FAT).
    #[display("The request is not supported: {operation}")]
    UnsupportedOperation {
        /// Short description of the unsupported operation.
        #[error(not(source))]
        operation: String,
    },

    /// Host or stream I/O failure.
    #[display("I/O error during {operation}: {message}")]
    IoFailure {
        /// Description of the I/O operation being performed.
        operation: String,
        /// Error message text.
        message: String,
    },

    /// Requested linter rule ID (`CMDxxxx`) does not exist in the catalog.
    #[display("Unknown linter rule ID: {rule_id}")]
    LinterRuleNotFound {
        /// Unrecognized rule identifier.
        #[error(not(source))]
        rule_id: String,
    },

    /// Malformed inline `REM wincheck` directive.
    #[display("Invalid linter directive: {detail}")]
    LinterDirectiveError {
        /// Source span of the directive comment.
        span: Span,
        /// Explanation of why the directive is invalid.
        detail: String,
    },

    /// Structured CLI option usage error converted via `derive_more::From`.
    #[display("{_0}")]
    #[from]
    CliUsage(#[error(not(source))] CliUsageFailure),

    /// Interpreter execution limit exceeded (loop/step/recursion guard), converted via `derive_more::From`.
    #[display("{_0}")]
    #[from]
    ExecutionLimitExceeded(#[error(not(source))] ExecutionLimitFailure),

    /// Exact PEG syntax error with farthest-failure location and expected grammar items.
    #[display(
        "Syntax error near '{found}': expected {}",
        format_peg_expected_slice(expected)
    )]
    PegSyntaxError {
        /// Exact byte span where parsing failed.
        span: Span,
        /// Token or character encountered at the failure point.
        found: String,
        /// Grammar constructs expected at the failure point.
        expected: Vec<PegExpected>,
    },

    /// Probable syntax misuse identified by PEG recovery rules.
    #[display("{message}")]
    ProbableSyntaxMisuse {
        /// Exact source span of the probable misuse.
        span: Span,
        /// Structured misuse category.
        #[error(not(source))]
        kind: Box<ProbableMisuseKind>,
        /// Diagnostic message describing the probable misuse.
        message: String,
    },
}

impl CmdError {
    /// Checks whether `operation` denotes a directory-level filesystem operation.
    ///
    /// # Arguments
    /// * `operation` - Short operation tag (`"mkdir"`, `"chdir"`, `"rmdir"`, etc.).
    ///
    /// # Returns
    /// `true` when `NotFound` should map to [`CmdError::PathNotFound`] rather than [`CmdError::FileNotFound`].
    #[must_use]
    pub const fn is_directory_operation(operation: &str) -> bool {
        matches!(
            operation.as_bytes(),
            b"mkdir"
                | b"chdir"
                | b"rmdir"
                | b"create_dir"
                | b"remove_dir"
                | b"read_dir"
                | b"set_current_dir"
        )
    }

    /// Maps a portable [`IoErrorKind`] and message into the closest domain-specific [`CmdError`] variant.
    ///
    /// Works identically across both `std` and `#![no_std]` MS-DOS builds.
    ///
    /// # Arguments
    /// * `kind` - Portable [`IoErrorKind`] classification.
    /// * `detail` - Error description text.
    /// * `path` - Target path associated with the operation (if applicable).
    /// * `operation` - Short name of the operation (`"read"`, `"write"`, `"mkdir"`, etc.).
    ///
    /// # Returns
    /// The mapped [`CmdError`] preserving `cmd.exe` / `COMMAND.COM` error semantics.
    #[must_use]
    pub fn from_io_kind(kind: IoErrorKind, detail: &str, path: &str, operation: &str) -> Self {
        match kind {
            IoErrorKind::NotFound => {
                if Self::is_directory_operation(operation) {
                    Self::PathNotFound {
                        path: path.to_owned(),
                    }
                } else {
                    Self::FileNotFound {
                        path: path.to_owned(),
                    }
                }
            }
            IoErrorKind::PermissionDenied
            | IoErrorKind::IsADirectory
            | IoErrorKind::ReadOnlyFilesystem => Self::AccessDenied {
                path: path.to_owned(),
            },
            IoErrorKind::AlreadyExists => Self::FileAlreadyExists {
                path: path.to_owned(),
            },
            IoErrorKind::DirectoryNotEmpty => Self::DirectoryNotEmpty {
                path: path.to_owned(),
            },
            IoErrorKind::WouldBlock => Self::SharingViolation {
                path: path.to_owned(),
            },
            IoErrorKind::BrokenPipe => Self::BrokenPipe,
            IoErrorKind::OutOfMemory => Self::InsufficientMemory,
            IoErrorKind::Unsupported => Self::UnsupportedOperation {
                operation: operation.to_owned(),
            },
            IoErrorKind::DosExtended(dos_err) => Self::from_dos_error(dos_err, path, operation),
            IoErrorKind::NotADirectory
            | IoErrorKind::InvalidInput
            | IoErrorKind::InvalidData
            | IoErrorKind::TimedOut
            | IoErrorKind::WriteZero
            | IoErrorKind::Interrupted
            | IoErrorKind::StorageFull
            | IoErrorKind::CrossesDevices
            | IoErrorKind::Other => Self::IoFailure {
                operation: operation.to_owned(),
                message: detail.to_owned(),
            },
        }
    }

    /// Maps an MS-DOS `INT 21h AH=59h` [`DosExtendedError`] into a domain-specific [`CmdError`].
    ///
    /// # Arguments
    /// * `err` - Structured [`DosExtendedError`] returned by the DOS kernel.
    /// * `path` - Target DOS path associated with the failing call.
    /// * `operation` - Short name of the operation (`"open"`, `"mkdir"`, `"exec"`, etc.).
    ///
    /// # Returns
    /// Mapped [`CmdError`] with authentic `COMMAND.COM` / `cmd.exe` semantics.
    #[must_use]
    pub fn from_dos_error(err: DosExtendedError, path: &str, operation: &str) -> Self {
        match err.code {
            DosErrorCode::FileNotFound | DosErrorCode::NoMoreFiles => {
                if Self::is_directory_operation(operation) {
                    Self::PathNotFound {
                        path: path.to_owned(),
                    }
                } else {
                    Self::FileNotFound {
                        path: path.to_owned(),
                    }
                }
            }
            DosErrorCode::PathNotFound => Self::PathNotFound {
                path: path.to_owned(),
            },
            DosErrorCode::InvalidDrive => path
                .chars()
                .next()
                .and_then(|ch| DriveLetter::try_from_char(ch).ok())
                .map_or_else(
                    || Self::InvalidDriveLetter {
                        ch: path.chars().next().unwrap_or('?'),
                    },
                    |drive| Self::DriveNotFound { drive },
                ),
            DosErrorCode::AccessDenied
            | DosErrorCode::WriteProtectedDisk
            | DosErrorCode::AttemptToRemoveCurrentDirectory
            | DosErrorCode::CannotMakeDirectoryEntry => Self::AccessDenied {
                path: path.to_owned(),
            },
            DosErrorCode::SharingViolation | DosErrorCode::LockViolation => {
                Self::SharingViolation {
                    path: path.to_owned(),
                }
            }
            DosErrorCode::FileExists => Self::FileAlreadyExists {
                path: path.to_owned(),
            },
            DosErrorCode::NotEnoughMemory
            | DosErrorCode::ArenaTrashed
            | DosErrorCode::InvalidBlock => Self::InsufficientMemory,
            DosErrorCode::BadEnvironment => Self::OutOfEnvironmentSpace,
            DosErrorCode::InvalidFunction => Self::UnsupportedOperation {
                operation: operation.to_owned(),
            },
            DosErrorCode::TooManyOpenFiles
            | DosErrorCode::InvalidHandle
            | DosErrorCode::BadFormat
            | DosErrorCode::InvalidAccess
            | DosErrorCode::InvalidData
            | DosErrorCode::NotSameDevice
            | DosErrorCode::UnknownUnit
            | DosErrorCode::DriveNotReady
            | DosErrorCode::GeneralFailure
            | DosErrorCode::UnknownCode(_) => Self::IoFailure {
                operation: operation.to_owned(),
                message: err.to_string(),
            },
        }
    }

    /// Maps a host [`std::io::Error`] into the closest domain-specific [`CmdError`] variant.
    ///
    /// Distinguishes directory operations (`"mkdir"`, `"chdir"`, `"rmdir"`, `"create_dir"`,
    /// `"remove_dir"`, `"read_dir"`, `"set_current_dir"`) from file operations when mapping
    /// [`std::io::ErrorKind::NotFound`].
    ///
    /// # Arguments
    /// * `err` - Underlying host I/O error.
    /// * `path` - Target path associated with the operation (if applicable).
    /// * `operation` - Short name of the operation (`"read"`, `"write"`, `"mkdir"`, etc.).
    ///
    /// # Returns
    /// The mapped [`CmdError`] preserving `cmd.exe` error semantics.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn from_io_error(err: &std::io::Error, path: &str, operation: &str) -> Self {
        Self::from_io_kind(
            IoErrorKind::from(err.kind()),
            &err.to_string(),
            path,
            operation,
        )
    }

    /// Returns the exact Windows `cmd.exe`-compatible error message string for this error.
    ///
    /// While `Display` on [`CmdError::PegSyntaxError`] formats pinpoint `found` and `expected`
    /// grammar details for linter/diagnostic consumers, `cmd_exe_message` emits the canonical
    /// `"The syntax of the command is incorrect."` string expected on `cmd.exe` `stderr`.
    ///
    /// # Returns
    /// The formatted message string suitable for writing to `cmd.exe` `stderr`.
    #[must_use]
    pub fn cmd_exe_message(&self) -> String {
        match self {
            Self::PegSyntaxError { .. } => "The syntax of the command is incorrect.".to_owned(),
            Self::UnexpectedToken { .. }
            | Self::SyntaxError { .. }
            | Self::UnbalancedParenthesis { .. }
            | Self::InvalidParameterModifier { .. }
            | Self::BatchLabelNotFound { .. }
            | Self::MissingBatchFile { .. }
            | Self::CommandNotRecognized { .. }
            | Self::InvalidSwitch { .. }
            | Self::ParameterFormatNotCorrect { .. }
            | Self::InvalidNumber { .. }
            | Self::NumberOutOfRange { .. }
            | Self::DivideByZero { .. }
            | Self::MissingOperand { .. }
            | Self::MissingOperator { .. }
            | Self::UnbalancedParensArithmetic { .. }
            | Self::FileNotFound { .. }
            | Self::PathNotFound { .. }
            | Self::InvalidUncPath { .. }
            | Self::NetworkPathNotFound { .. }
            | Self::DriveNotFound { .. }
            | Self::FileAlreadyExists { .. }
            | Self::DirectoryNotEmpty { .. }
            | Self::AccessDenied { .. }
            | Self::SharingViolation { .. }
            | Self::CannotCopyOntoItself { .. }
            | Self::CyclicCopy { .. }
            | Self::InvalidDriveLetter { .. }
            | Self::SameColorForegroundAndBackground { .. }
            | Self::EnvironmentVariableNotDefined { .. }
            | Self::InvalidCodePage { .. }
            | Self::InvalidRegistryKey { .. }
            | Self::InvalidRegistryValue { .. }
            | Self::RedirectionFailed { .. }
            | Self::EncodingFailure { .. }
            | Self::EncodingByteOffsetMismatch { .. }
            | Self::LineTooLong { .. }
            | Self::BrokenPipe
            | Self::ChildProcessFailure { .. }
            | Self::InsufficientMemory
            | Self::OutOfEnvironmentSpace
            | Self::CommandLineTooLong { .. }
            | Self::UnsupportedOperation { .. }
            | Self::IoFailure { .. }
            | Self::LinterRuleNotFound { .. }
            | Self::LinterDirectiveError { .. }
            | Self::CliUsage(_)
            | Self::ExecutionLimitExceeded(_)
            | Self::ProbableSyntaxMisuse { .. } => self.to_string(),
        }
    }

    /// Returns the authentic Windows `cmd.exe` or `wincheck` [`ExitCode`] associated with this error.
    ///
    /// # Returns
    /// [`ExitCode::COMMAND_NOT_FOUND`] (`9009`) for unrecognized commands, `4` for cyclic copy,
    /// `2` for `wincheck` CLI usage or unknown rule ID errors, or [`ExitCode::FAILURE`] (`1`)
    /// for all other errors.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::CommandNotRecognized { .. } => ExitCode::COMMAND_NOT_FOUND,
            Self::CyclicCopy { .. } => ExitCode(4),
            Self::CliUsage(CliUsageFailure {
                tool: CliTool::WinCheck,
                ..
            })
            | Self::LinterRuleNotFound { .. } => ExitCode(2),
            Self::CliUsage(CliUsageFailure {
                tool: CliTool::WinCmd,
                ..
            })
            | Self::UnexpectedToken { .. }
            | Self::SyntaxError { .. }
            | Self::UnbalancedParenthesis { .. }
            | Self::InvalidParameterModifier { .. }
            | Self::BatchLabelNotFound { .. }
            | Self::MissingBatchFile { .. }
            | Self::InvalidSwitch { .. }
            | Self::ParameterFormatNotCorrect { .. }
            | Self::InvalidNumber { .. }
            | Self::NumberOutOfRange { .. }
            | Self::DivideByZero { .. }
            | Self::MissingOperand { .. }
            | Self::MissingOperator { .. }
            | Self::UnbalancedParensArithmetic { .. }
            | Self::FileNotFound { .. }
            | Self::PathNotFound { .. }
            | Self::InvalidUncPath { .. }
            | Self::NetworkPathNotFound { .. }
            | Self::DriveNotFound { .. }
            | Self::FileAlreadyExists { .. }
            | Self::DirectoryNotEmpty { .. }
            | Self::AccessDenied { .. }
            | Self::SharingViolation { .. }
            | Self::CannotCopyOntoItself { .. }
            | Self::InvalidDriveLetter { .. }
            | Self::SameColorForegroundAndBackground { .. }
            | Self::EnvironmentVariableNotDefined { .. }
            | Self::InvalidCodePage { .. }
            | Self::InvalidRegistryKey { .. }
            | Self::InvalidRegistryValue { .. }
            | Self::RedirectionFailed { .. }
            | Self::EncodingFailure { .. }
            | Self::EncodingByteOffsetMismatch { .. }
            | Self::LineTooLong { .. }
            | Self::BrokenPipe
            | Self::ChildProcessFailure { .. }
            | Self::InsufficientMemory
            | Self::OutOfEnvironmentSpace
            | Self::CommandLineTooLong { .. }
            | Self::UnsupportedOperation { .. }
            | Self::IoFailure { .. }
            | Self::LinterDirectiveError { .. }
            | Self::ExecutionLimitExceeded(_)
            | Self::PegSyntaxError { .. }
            | Self::ProbableSyntaxMisuse { .. } => ExitCode::FAILURE,
        }
    }

    /// Returns the primary source [`Span`] associated with this error, if any.
    ///
    /// # Returns
    /// `Some(Span)` for syntax, expansion, arithmetic, redirection, execution-limit, and
    /// directive errors; `None` for non-spanned errors.
    #[must_use]
    pub const fn span(&self) -> Option<Span> {
        match self {
            Self::ExecutionLimitExceeded(failure) => Some(failure.span),
            Self::UnexpectedToken { span, .. }
            | Self::SyntaxError { span }
            | Self::UnbalancedParenthesis { span }
            | Self::InvalidParameterModifier { span, .. }
            | Self::BatchLabelNotFound { span, .. }
            | Self::CommandNotRecognized { span, .. }
            | Self::InvalidSwitch { span, .. }
            | Self::ParameterFormatNotCorrect { span, .. }
            | Self::InvalidNumber { span, .. }
            | Self::NumberOutOfRange { span, .. }
            | Self::DivideByZero { span }
            | Self::MissingOperand { span }
            | Self::MissingOperator { span }
            | Self::UnbalancedParensArithmetic { span }
            | Self::RedirectionFailed { span, .. }
            | Self::LineTooLong { span }
            | Self::LinterDirectiveError { span, .. }
            | Self::PegSyntaxError { span, .. }
            | Self::ProbableSyntaxMisuse { span, .. } => Some(*span),
            Self::MissingBatchFile { .. }
            | Self::FileNotFound { .. }
            | Self::PathNotFound { .. }
            | Self::InvalidUncPath { .. }
            | Self::NetworkPathNotFound { .. }
            | Self::DriveNotFound { .. }
            | Self::FileAlreadyExists { .. }
            | Self::DirectoryNotEmpty { .. }
            | Self::AccessDenied { .. }
            | Self::SharingViolation { .. }
            | Self::CannotCopyOntoItself { .. }
            | Self::CyclicCopy { .. }
            | Self::InvalidDriveLetter { .. }
            | Self::SameColorForegroundAndBackground { .. }
            | Self::EnvironmentVariableNotDefined { .. }
            | Self::InvalidCodePage { .. }
            | Self::InvalidRegistryKey { .. }
            | Self::InvalidRegistryValue { .. }
            | Self::EncodingFailure { .. }
            | Self::EncodingByteOffsetMismatch { .. }
            | Self::BrokenPipe
            | Self::ChildProcessFailure { .. }
            | Self::InsufficientMemory
            | Self::OutOfEnvironmentSpace
            | Self::CommandLineTooLong { .. }
            | Self::UnsupportedOperation { .. }
            | Self::IoFailure { .. }
            | Self::LinterRuleNotFound { .. }
            | Self::CliUsage(_) => None,
        }
    }
}

#[cfg(test)]
/// Unit tests for [`CmdError`] variants, exact `cmd.exe` messages, exit codes, and I/O mapping.
mod tests {
    use super::*;
    use crate::span::SourceId;

    /// Verifies messages, exit codes, and spans for syntax, batch, and parameter `CmdError` variants.
    #[test]
    fn test_spanned_syntax_and_parameter_cmd_errors() {
        let span = Span::new(SourceId(0), ByteOffset(1), ByteOffset(5));

        let spanned_errors = vec![
            (
                CmdError::UnexpectedToken {
                    span,
                    token: "|".to_owned(),
                },
                "| was unexpected at this time.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::SyntaxError { span },
                "The syntax of the command is incorrect.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::UnbalancedParenthesis { span },
                "The syntax of the command is incorrect.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::InvalidParameterModifier {
                    span,
                    sequence: "%~q1".to_owned(),
                },
                "The following usage of the path operator in batch-parameter substitution is invalid: %~q1",
                ExitCode::FAILURE,
            ),
            (
                CmdError::BatchLabelNotFound {
                    span,
                    label: LabelName::new("missing"),
                },
                "The system cannot find the batch label specified - missing",
                ExitCode::FAILURE,
            ),
            (
                CmdError::CommandNotRecognized {
                    span,
                    command: "foo".to_owned(),
                },
                "'foo' is not recognized as an internal or external command,
operable program or batch file.",
                ExitCode::COMMAND_NOT_FOUND,
            ),
            (
                CmdError::InvalidSwitch {
                    span,
                    switch: "Z".to_owned(),
                },
                r#"Invalid switch - "Z"."#,
                ExitCode::FAILURE,
            ),
            (
                CmdError::ParameterFormatNotCorrect {
                    span,
                    param: "xyz".to_owned(),
                },
                "Parameter format not correct - xyz.",
                ExitCode::FAILURE,
            ),
        ];

        for (err, expected_msg, expected_code) in spanned_errors {
            assert_eq!(err.cmd_exe_message(), expected_msg);
            assert_eq!(err.exit_code(), expected_code);
            assert_eq!(err.span(), Some(span));
        }
    }

    /// Verifies messages, exit codes, and spans for arithmetic and redirection `CmdError` variants.
    #[test]
    fn test_spanned_arithmetic_and_redirection_cmd_errors() {
        let span = Span::new(SourceId(0), ByteOffset(1), ByteOffset(5));
        let spanned_errors = vec![
            (
                CmdError::InvalidNumber {
                    span,
                    text: "09".to_owned(),
                },
                "Invalid number.  Numeric constants are either decimal (17), hexadecimal (0x11), or octal (021).",
                ExitCode::FAILURE,
            ),
            (
                CmdError::NumberOutOfRange {
                    span,
                    text: "99999999999".to_owned(),
                },
                "Invalid number.  Numbers are limited to 32-bits of precision.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::DivideByZero { span },
                "Divide by zero error.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::MissingOperand { span },
                "Missing operand.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::MissingOperator { span },
                "Missing operator.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::UnbalancedParensArithmetic { span },
                "Unbalanced parentheses.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::RedirectionFailed {
                    span,
                    fd: FileDescriptor::STDOUT,
                    target: "ro.txt".to_owned(),
                    reason: "Access is denied.".to_owned(),
                },
                "Access is denied.",
                ExitCode::FAILURE,
            ),
        ];

        for (err, expected_msg, expected_code) in spanned_errors {
            assert_eq!(err.cmd_exe_message(), expected_msg);
            assert_eq!(err.exit_code(), expected_code);
            assert_eq!(err.span(), Some(span));
        }
    }

    /// Verifies messages, exit codes, and spans for line-length, directive, limit, and PEG `CmdError` variants.
    #[test]
    fn test_spanned_limit_and_peg_cmd_errors() {
        let span = Span::new(SourceId(0), ByteOffset(1), ByteOffset(5));
        let limit_err = CmdError::from(ExecutionLimitFailure {
            kind: LimitKind::MaxSteps,
            limit: 10_000,
            span,
        });

        let spanned_errors = vec![
            (
                CmdError::LineTooLong { span },
                "The input line is too long.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::LinterDirectiveError {
                    span,
                    detail: "bad key".to_owned(),
                },
                "Invalid linter directive: bad key",
                ExitCode::FAILURE,
            ),
            (
                limit_err,
                "Execution aborted: exceeded maximum statement step budget (10000)",
                ExitCode::FAILURE,
            ),
            (
                CmdError::PegSyntaxError {
                    span,
                    found: "|".to_owned(),
                    expected: vec![PegExpected::PipelineRightOperand, PegExpected::CommandName],
                },
                "The syntax of the command is incorrect.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::ProbableSyntaxMisuse {
                    span,
                    kind: Box::new(ProbableMisuseKind::SingleEqualsInIf { span }),
                    message: "Single '=' used in IF comparison".to_owned(),
                },
                "Single '=' used in IF comparison",
                ExitCode::FAILURE,
            ),
        ];

        for (err, expected_msg, expected_code) in spanned_errors {
            assert_eq!(err.cmd_exe_message(), expected_msg);
            assert_eq!(err.exit_code(), expected_code);
            assert_eq!(err.span(), Some(span));
        }

        let peg_err = CmdError::PegSyntaxError {
            span,
            found: "|".to_owned(),
            expected: vec![PegExpected::PipelineRightOperand, PegExpected::CommandName],
        };
        assert_eq!(
            peg_err.to_string(),
            "Syntax error near '|': expected command after '|' pipe operator, command name"
        );
        assert_eq!(format_peg_expected_slice(&[]), "valid command syntax");
    }

    /// Verifies exact `Display` formatting for every `PegExpected` grammar expectation.
    #[test]
    fn test_peg_expected_exact_display() {
        let expected_pairs = [
            (PegExpected::CommandName, "command name"),
            (PegExpected::Statement, "statement"),
            (PegExpected::ClosingParen, "')' to close compound block"),
            (PegExpected::ForSetOpenParen, "'(' after IN in FOR loop"),
            (PegExpected::ForSetCloseParen, "')' to close FOR set"),
            (PegExpected::InKeyword, "'IN' keyword in FOR loop"),
            (PegExpected::DoKeyword, "'DO' keyword after FOR (...) set"),
            (
                PegExpected::ForVariable,
                "FOR loop variable (e.g., %%I or %I)",
            ),
            (
                PegExpected::IfCondition,
                "IF condition (EXIST, DEFINED, ERRORLEVEL, CMDEXTVERSION, or comparison)",
            ),
            (
                PegExpected::ComparisonOperator,
                "comparison operator ('==', 'EQU', 'NEQ', 'LSS', 'LEQ', 'GTR', 'GEQ')",
            ),
            (
                PegExpected::ComparisonOperand,
                "right-hand operand in IF comparison",
            ),
            (PegExpected::IfThenBranch, "command following IF condition"),
            (PegExpected::ElseBranch, "command following ELSE keyword"),
            (PegExpected::ForBodyBranch, "command following DO keyword"),
            (
                PegExpected::PipelineRightOperand,
                "command after '|' pipe operator",
            ),
            (
                PegExpected::PipelineLeftOperand,
                "command before '|' pipe operator",
            ),
            (
                PegExpected::ChainRightOperand,
                "command after '&', '&&', or '||' operator",
            ),
            (
                PegExpected::ChainLeftOperand,
                "command before '&', '&&', or '||' operator",
            ),
            (
                PegExpected::RedirectionTarget,
                "filename or handle after redirection operator",
            ),
            (
                PegExpected::SetArithmeticExpr,
                "arithmetic expression after SET /A",
            ),
            (
                PegExpected::ClosingDoubleQuote,
                r#"closing '"' double quote"#,
            ),
            (
                PegExpected::ClosingPercent,
                "closing '%' for variable expansion",
            ),
            (
                PegExpected::ClosingExclamation,
                "closing '!' for delayed variable expansion",
            ),
        ];
        for (exp, expected_text) in expected_pairs {
            assert_eq!(exp.to_string(), expected_text);
        }
    }

    /// Verifies exact `Display` formatting and source spans for every `ProbableMisuseKind`.
    #[test]
    fn test_probable_misuse_exact_display_and_spans() {
        let span = Span::new(SourceId(0), ByteOffset(1), ByteOffset(5));
        let misuse_pairs = [
            (
                ProbableMisuseKind::SingleEqualsInIf { span },
                "single '=' used in IF comparison at 0:1..5 (use '==' or 'EQU')",
            ),
            (
                ProbableMisuseKind::ParenthesizedIfCondition { span },
                "parentheses around IF condition at 0:1..5",
            ),
            (
                ProbableMisuseKind::MissingInKeywordInFor { span },
                "missing 'IN' keyword in FOR loop at 0:1..5",
            ),
            (
                ProbableMisuseKind::MissingDoKeywordInFor { span },
                "missing 'DO' keyword in FOR loop at 0:1..5",
            ),
            (
                ProbableMisuseKind::UnparenthesizedElseBranch { span },
                "unparenthesized IF then-branch before ELSE at 0:1..5",
            ),
            (
                ProbableMisuseKind::SinglePercentForVarInBatch {
                    span,
                    raw_var: "%I".to_owned(),
                },
                "single-percent FOR variable '%I' in batch file at 0:1..5",
            ),
            (
                ProbableMisuseKind::DoublePercentForVarInRepl {
                    span,
                    raw_var: "%%I".to_owned(),
                },
                "double-percent FOR variable '%%I' in interactive REPL at 0:1..5",
            ),
            (
                ProbableMisuseKind::MultiCharForVariable {
                    span,
                    raw_var: "%%foo".to_owned(),
                },
                "multi-character FOR variable '%%foo' at 0:1..5",
            ),
            (
                ProbableMisuseKind::UnescapedClosingParenInBlock { span },
                "unescaped ')' inside compound block at 0:1..5",
            ),
            (
                ProbableMisuseKind::UnclosedDoubleQuote { span },
                r#"unclosed double quote '"' at 0:1..5"#,
            ),
            (
                ProbableMisuseKind::InvalidModifierOnNamedVar {
                    span,
                    raw_token: "%~dpVAR%".to_owned(),
                },
                "invalid path modifier on named variable '%~dpVAR%' at 0:1..5",
            ),
            (
                ProbableMisuseKind::UnescapedSinglePercentInBatch { span },
                "unescaped single '%' in batch file at 0:1..5",
            ),
            (
                ProbableMisuseKind::DoublePercentLiteralInRepl { span },
                "double '%%' literal in interactive REPL at 0:1..5",
            ),
        ];
        for (misuse, expected_text) in misuse_pairs {
            assert_eq!(misuse.span(), span);
            assert_eq!(misuse.to_string(), expected_text);
        }
    }

    /// Verifies CLI usage error reason and execution limit kind `Display` formatting.
    #[test]
    fn test_cli_error_reason_and_limit_kind_display() {
        assert_eq!(
            CliErrorReason::MissingValue.to_string(),
            "requires an argument"
        );
        assert_eq!(
            CliErrorReason::UnknownFlag.to_string(),
            "unrecognized option"
        );
        assert_eq!(
            CliErrorReason::InvalidModeValue("zsh".to_owned()).to_string(),
            "unsupported dialect mode 'zsh'"
        );
        assert_eq!(
            CliErrorReason::InvalidSeverityValue("fatal".to_owned()).to_string(),
            "unsupported severity 'fatal'"
        );
        assert_eq!(
            CliErrorReason::MissingInputFiles.to_string(),
            "no input files specified"
        );
        assert_eq!(
            LimitKind::MaxCallDepth.to_string(),
            "maximum CALL recursion depth"
        );
        assert_eq!(
            LimitKind::MaxLoopIterations.to_string(),
            "maximum FOR /L loop iteration budget"
        );
    }

    /// Verifies messages, exit codes, and `None` spans for filesystem unspanned `CmdError` variants.
    #[test]
    fn test_unspanned_filesystem_cmd_errors() {
        let unspanned_errors = vec![
            (
                CmdError::MissingBatchFile {
                    path: "a.bat".to_owned(),
                },
                "The batch file cannot be found.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::FileNotFound {
                    path: "a.txt".to_owned(),
                },
                "The system cannot find the file specified.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::PathNotFound {
                    path: "C:/nope".to_owned(),
                },
                "The system cannot find the path specified.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::InvalidUncPath {
                    raw: "//server".to_owned(),
                },
                "The network path was not found.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::DriveNotFound {
                    drive: DriveLetter::D,
                },
                "The system cannot find the drive specified.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::FileAlreadyExists {
                    path: "dir".to_owned(),
                },
                "A subdirectory or file dir already exists.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::DirectoryNotEmpty {
                    path: "dir".to_owned(),
                },
                "The directory is not empty.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::AccessDenied {
                    path: "ro.txt".to_owned(),
                },
                "Access is denied.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::SharingViolation {
                    path: "lock.txt".to_owned(),
                },
                "The process cannot access the file because it is being used by another process.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::CannotCopyOntoItself {
                    path: "a.txt".to_owned(),
                },
                "The file cannot be copied onto itself.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::CyclicCopy {
                    path: "sub".to_owned(),
                },
                "Cannot perform a cyclic copy",
                ExitCode::new(4),
            ),
            (
                CmdError::InvalidDriveLetter { ch: '?' },
                "Invalid drive specification.",
                ExitCode::FAILURE,
            ),
        ];

        for (err, expected_msg, expected_code) in unspanned_errors {
            assert_eq!(err.cmd_exe_message(), expected_msg);
            assert_eq!(err.exit_code(), expected_code);
            assert_eq!(err.span(), None);
        }
    }

    /// Verifies environment, codepage, registry, and encoding unspanned `CmdError` variants.
    #[test]
    fn test_unspanned_env_registry_and_encoding_cmd_errors() {
        let unspanned_errors = vec![
            (
                CmdError::SameColorForegroundAndBackground { nibble: 0 },
                "The COLOR command sets ERRORLEVEL to 1 if an attempt is made to execute the COLOR command with a foreground and background color that are the same.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::EnvironmentVariableNotDefined {
                    name: "FOO".to_owned(),
                },
                "Environment variable FOO not defined",
                ExitCode::FAILURE,
            ),
            (
                CmdError::InvalidCodePage { code: 123 },
                "Invalid code page",
                ExitCode::FAILURE,
            ),
            (
                CmdError::InvalidRegistryKey {
                    raw: "BADHIVE".to_owned(),
                },
                "ERROR: Invalid key name.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::InvalidRegistryValue {
                    key: "HKCU/Test".to_owned(),
                    value: "bad".to_owned(),
                },
                "ERROR: Invalid syntax.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::EncodingFailure {
                    offset: ByteOffset(3),
                    codepage: CodePage::Utf8,
                    detail: "invalid utf-8".to_owned(),
                },
                "Encoding failure at offset 3 for codepage 65001: invalid utf-8",
                ExitCode::FAILURE,
            ),
            (
                CmdError::EncodingByteOffsetMismatch {
                    offset: ByteOffset(7),
                    codepage: CodePage::Utf8,
                },
                "Byte offset 7 is out of bounds or misaligned for codepage 65001",
                ExitCode::FAILURE,
            ),
        ];

        for (err, expected_msg, expected_code) in unspanned_errors {
            assert_eq!(err.cmd_exe_message(), expected_msg);
            assert_eq!(err.exit_code(), expected_code);
            assert_eq!(err.span(), None);
        }
    }

    /// Verifies process, I/O, linter, and CLI unspanned `CmdError` variants.
    #[test]
    fn test_unspanned_process_io_linter_and_cli_cmd_errors() {
        let wincheck_cli_err = CmdError::from(CliUsageFailure::new(
            CliTool::WinCheck,
            "--format",
            CliErrorReason::InvalidFormatValue("xml".to_owned()),
        ));
        let wincmd_cli_err = CmdError::from(CliUsageFailure::new(
            CliTool::WinCmd,
            "/Z",
            CliErrorReason::UnknownFlag,
        ));
        assert!(wincheck_cli_err.is_cli_usage());
        assert!(CliTool::WinCmd.is_win_cmd());
        assert!(CliTool::WinCheck.is_win_check());

        let unspanned_errors = vec![
            (
                CmdError::BrokenPipe,
                "The process tried to write to a nonexistent pipe.",
                ExitCode::FAILURE,
            ),
            (
                CmdError::ChildProcessFailure {
                    program: "ext.exe".to_owned(),
                    kind: IoErrorKind::NotFound,
                    message: "missing".to_owned(),
                },
                "Failed to execute 'ext.exe' (NotFound): missing",
                ExitCode::FAILURE,
            ),
            (
                CmdError::InsufficientMemory,
                "Program too big to fit in memory",
                ExitCode::FAILURE,
            ),
            (
                CmdError::OutOfEnvironmentSpace,
                "Out of environment space",
                ExitCode::FAILURE,
            ),
            (
                CmdError::CommandLineTooLong {
                    length: 140,
                    limit: 126,
                },
                "Command line too long (140 bytes exceeds 126-byte limit)",
                ExitCode::FAILURE,
            ),
            (
                CmdError::UnsupportedOperation {
                    operation: "symlink".to_owned(),
                },
                "The request is not supported: symlink",
                ExitCode::FAILURE,
            ),
            (
                CmdError::IoFailure {
                    operation: "write".to_owned(),
                    message: "disk full".to_owned(),
                },
                "I/O error during write: disk full",
                ExitCode::FAILURE,
            ),
            (
                CmdError::LinterRuleNotFound {
                    rule_id: "CMD9999".to_owned(),
                },
                "Unknown linter rule ID: CMD9999",
                ExitCode::new(2),
            ),
            (
                wincmd_cli_err,
                "wincmd: /Z: unrecognized option",
                ExitCode::FAILURE,
            ),
            (
                wincheck_cli_err,
                "wincheck: --format: unsupported output format 'xml'",
                ExitCode::new(2),
            ),
        ];

        for (err, expected_msg, expected_code) in unspanned_errors {
            assert_eq!(err.cmd_exe_message(), expected_msg);
            assert_eq!(err.exit_code(), expected_code);
            assert_eq!(err.span(), None);
        }
    }

    /// Verifies `CmdError::from_io_error` mapping across all `std::io::ErrorKind` branches.
    #[test]
    fn test_cmd_error_from_io_error_mapping() {
        for dir_op in [
            "mkdir",
            "chdir",
            "rmdir",
            "create_dir",
            "remove_dir",
            "read_dir",
            "set_current_dir",
        ] {
            let err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing dir");
            assert_eq!(
                CmdError::from_io_error(&err, "p", dir_op),
                CmdError::PathNotFound {
                    path: "p".to_owned()
                }
            );
        }

        let io_cases = [
            (
                std::io::ErrorKind::NotFound,
                "read",
                CmdError::FileNotFound {
                    path: "p".to_owned(),
                },
            ),
            (
                std::io::ErrorKind::PermissionDenied,
                "write",
                CmdError::AccessDenied {
                    path: "p".to_owned(),
                },
            ),
            (
                std::io::ErrorKind::IsADirectory,
                "write",
                CmdError::AccessDenied {
                    path: "p".to_owned(),
                },
            ),
            (
                std::io::ErrorKind::AlreadyExists,
                "mkdir",
                CmdError::FileAlreadyExists {
                    path: "p".to_owned(),
                },
            ),
            (
                std::io::ErrorKind::DirectoryNotEmpty,
                "rmdir",
                CmdError::DirectoryNotEmpty {
                    path: "p".to_owned(),
                },
            ),
            (
                std::io::ErrorKind::WouldBlock,
                "write",
                CmdError::SharingViolation {
                    path: "p".to_owned(),
                },
            ),
            (
                std::io::ErrorKind::BrokenPipe,
                "write",
                CmdError::BrokenPipe,
            ),
            (
                std::io::ErrorKind::Other,
                "sync",
                CmdError::IoFailure {
                    operation: "sync".to_owned(),
                    message: "custom io err".to_owned(),
                },
            ),
        ];
        for (kind, op, expected) in io_cases {
            let io_err = std::io::Error::new(kind, "custom io err");
            assert_eq!(CmdError::from_io_error(&io_err, "p", op), expected);
        }
    }

    /// Verifies `CmdError::from_io_kind` and `CmdError::from_dos_error` across all MS-DOS error codes.
    #[test]
    fn test_cmd_error_from_dos_error_mapping() {
        let cases = [
            (
                CmdError::from_io_kind(IoErrorKind::OutOfMemory, "oom", "p", "exec"),
                CmdError::InsufficientMemory,
            ),
            (
                CmdError::from_io_kind(IoErrorKind::Unsupported, "unsup", "p", "symlink"),
                CmdError::UnsupportedOperation {
                    operation: "symlink".to_owned(),
                },
            ),
            (
                CmdError::from_io_kind(
                    IoErrorKind::DosExtended(DosExtendedError::from_code(
                        DosErrorCode::FileNotFound,
                    )),
                    "",
                    "a.txt",
                    "open",
                ),
                CmdError::FileNotFound {
                    path: "a.txt".to_owned(),
                },
            ),
            (
                CmdError::from_dos_error(
                    DosExtendedError::from_code(DosErrorCode::FileNotFound),
                    "sub",
                    "mkdir",
                ),
                CmdError::PathNotFound {
                    path: "sub".to_owned(),
                },
            ),
            (
                CmdError::from_dos_error(
                    DosExtendedError::from_code(DosErrorCode::PathNotFound),
                    "dir",
                    "open",
                ),
                CmdError::PathNotFound {
                    path: "dir".to_owned(),
                },
            ),
            (
                CmdError::from_dos_error(
                    DosExtendedError::from_code(DosErrorCode::InvalidDrive),
                    "Z:\\file",
                    "open",
                ),
                CmdError::DriveNotFound {
                    drive: DriveLetter::Z,
                },
            ),
            (
                CmdError::from_dos_error(
                    DosExtendedError::from_code(DosErrorCode::InvalidDrive),
                    "1:\\file",
                    "open",
                ),
                CmdError::InvalidDriveLetter { ch: '1' },
            ),
            (
                CmdError::from_dos_error(
                    DosExtendedError::from_code(DosErrorCode::InvalidDrive),
                    "",
                    "open",
                ),
                CmdError::InvalidDriveLetter { ch: '?' },
            ),
        ];
        for (actual, expected) in cases {
            assert_eq!(actual, expected);
        }
    }

    /// Verifies remaining `CmdError::from_dos_error` permission, memory, environment, and fallback branches.
    #[test]
    fn test_cmd_error_from_dos_error_resource_and_fallback_mapping() {
        let cases = [
            (
                CmdError::from_dos_error(
                    DosExtendedError::from_code(DosErrorCode::WriteProtectedDisk),
                    "A:\\f",
                    "write",
                ),
                CmdError::AccessDenied {
                    path: "A:\\f".to_owned(),
                },
            ),
            (
                CmdError::from_dos_error(
                    DosExtendedError::from_code(DosErrorCode::SharingViolation),
                    "C:\\f",
                    "open",
                ),
                CmdError::SharingViolation {
                    path: "C:\\f".to_owned(),
                },
            ),
            (
                CmdError::from_dos_error(
                    DosExtendedError::from_code(DosErrorCode::FileExists),
                    "C:\\f",
                    "create",
                ),
                CmdError::FileAlreadyExists {
                    path: "C:\\f".to_owned(),
                },
            ),
            (
                CmdError::from_dos_error(
                    DosExtendedError::from_code(DosErrorCode::NotEnoughMemory),
                    "",
                    "exec",
                ),
                CmdError::InsufficientMemory,
            ),
            (
                CmdError::from_dos_error(
                    DosExtendedError::from_code(DosErrorCode::BadEnvironment),
                    "",
                    "exec",
                ),
                CmdError::OutOfEnvironmentSpace,
            ),
            (
                CmdError::from_dos_error(
                    DosExtendedError::from_code(DosErrorCode::InvalidFunction),
                    "",
                    "mklink",
                ),
                CmdError::UnsupportedOperation {
                    operation: "mklink".to_owned(),
                },
            ),
        ];
        for (actual, expected) in cases {
            assert_eq!(actual, expected);
        }
        assert!(matches!(
            CmdError::from_dos_error(
                DosExtendedError::from_code(DosErrorCode::DriveNotReady),
                "A:\\",
                "read"
            ),
            CmdError::IoFailure { .. }
        ));
    }
}
