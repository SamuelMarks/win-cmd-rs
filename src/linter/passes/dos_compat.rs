//! MS-DOS `COMMAND.COM` portability lint rules (`CMD5001`–`CMD5010`) and safe CST auto-fixes.

use alloc::borrow::ToOwned;
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::dos::{DosFileName8Dot3, MAX_PSP_COMMAND_TAIL_BYTES};
use crate::linter::rewriter::{CstRewriteRule, RewriteContext};
use crate::linter::rules::{
    Diagnostic, FixApplicability, LinterConfig, RuleId, Severity, SuggestedFix,
};
use crate::parser::ast::{
    CommandExpr, ComparisonOp, ForStatement, ForVariant, IfCondition, IfStatement, ParsedScript,
    Redirection, RedirectionKind, SimpleCommand, SpannedWord, Statement, WordPartKind,
};
use crate::parser::cst::{CstElement, CstNode, CstToken, SyntaxKind};
use crate::span::{ByteOffset, Span};
use crate::types::{BS_CHAR, CRLF, CaseSensitivity, ShellDialect};

/// MS-DOS `COMMAND.COM` built-in command names that do not pass through the 126-byte `PSP:0x80` child loader.
const DOS_RESIDENT_COMMANDS: &[&str] = &[
    "BREAK", "CALL", "CD", "CHCP", "CHDIR", "CLS", "COPY", "CTTY", "DATE", "DEL", "DIR", "ECHO",
    "ERASE", "EXIT", "FOR", "GOTO", "IF", "LH", "LOADHIGH", "MD", "MKDIR", "PATH", "PAUSE",
    "PROMPT", "RD", "REM", "REN", "RENAME", "RMDIR", "SET", "SHIFT", "TIME", "TRUENAME", "TYPE",
    "VER", "VERIFY", "VOL",
];

/// Runs MS-DOS `COMMAND.COM` portability checks (`CMD5001`–`CMD5010`) when `config.dialect` is
/// [`ShellDialect::MsDos622`] or any `CMD50xx` rule is explicitly requested in `config.included_rules`.
///
/// # Arguments
/// * `file_name` - Script filename or path.
/// * `parsed` - Lowered [`ParsedScript`] AST.
/// * `config` - Active [`LinterConfig`].
/// * `diags` - Destination diagnostic buffer.
pub fn analyze_msdos_portability(
    file_name: &str,
    parsed: &ParsedScript,
    config: &LinterConfig,
    diags: &mut Vec<Diagnostic>,
) {
    let explicit_5000 = config
        .included_rules
        .iter()
        .any(|r| r.as_str().starts_with("CMD50"));
    if config.dialect != ShellDialect::MsDos622 && !explicit_5000 {
        return;
    }

    if config.dialect == ShellDialect::MsDos622 {
        diags.retain(|d| !matches!(d.rule_id.as_str(), "CMD4001" | "CMD4002" | "CMD4005"));
    }

    let defined_labels: BTreeSet<String> = parsed
        .labels
        .iter()
        .filter(|l| !l.is_double_colon)
        .map(|l| l.name.folded().to_owned())
        .collect();

    check_script_filename_8_3(file_name, parsed, diags);

    for stmt in &parsed.statements {
        if let Statement::Command(expr) = stmt {
            visit_dos_command_expr(expr, &defined_labels, diags);
        }
    }
}

/// Checks `file_name` for `.cmd` extension or non-8.3 leaf naming (`CMD5009`).
///
/// # Arguments
/// * `file_name` - Script display name or path.
/// * `parsed` - [`ParsedScript`] supplying source ID for diagnostic spans.
/// * `diags` - Destination diagnostic buffer.
fn check_script_filename_8_3(file_name: &str, parsed: &ParsedScript, diags: &mut Vec<Diagnostic>) {
    let trimmed = file_name.trim();
    if trimmed.is_empty() || trimmed == "-" || trimmed.starts_with('<') {
        return;
    }
    let leaf = trimmed.rsplit([BS_CHAR, '/']).next().unwrap_or(trimmed);
    let file_span = Span::new(parsed.source_id, ByteOffset(0), ByteOffset(0));
    if leaf.to_ascii_lowercase().ends_with(".cmd") {
        diags.push(Diagnostic {
            rule_id: RuleId::new("CMD5009"),
            severity: Severity::Warning,
            message: format!(
                "Script filename `{leaf}` uses `.cmd` extension; MS-DOS COMMAND.COM executes `.bat` only."
            ),
            primary_span: file_span,
            help: Some("Rename the batch file to a strict 8.3 `.BAT` filename.".to_owned()),
            fix: None,
        });
    } else if DosFileName8Dot3::validate_strict(leaf).is_err() {
        diags.push(Diagnostic {
            rule_id: RuleId::new("CMD5009"),
            severity: Severity::Warning,
            message: format!(
                "Script filename `{leaf}` exceeds strict MS-DOS FAT 8.3 naming limits."
            ),
            primary_span: file_span,
            help: Some(
                "Use at most 8 stem characters and 3 extension characters without spaces."
                    .to_owned(),
            ),
            fix: None,
        });
    }
}

/// Recursively audits a [`CommandExpr`] against `CMD5001`–`CMD5010`.
///
/// # Arguments
/// * `expr` - Current [`CommandExpr`].
/// * `defined_labels` - Uppercase label names defined in the script.
/// * `diags` - Destination diagnostic buffer.
fn visit_dos_command_expr(
    expr: &CommandExpr,
    defined_labels: &BTreeSet<String>,
    diags: &mut Vec<Diagnostic>,
) {
    match expr {
        CommandExpr::Simple(simple) => visit_dos_simple_command(simple, defined_labels, diags),
        CommandExpr::Block(block) => {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD5004"),
                severity: Severity::Error,
                message:
                    "Parenthesized `( ... )` compound command blocks are unsupported in MS-DOS COMMAND.COM."
                        .to_owned(),
                primary_span: block.span,
                help: Some(
                    "Extract block statements into sequential lines or a secondary `.BAT` file."
                        .to_owned(),
                ),
                fix: None,
            });
            check_dos_redirections(&block.redirections, diags);
            for st in &block.body {
                if let Statement::Command(inner) = st {
                    visit_dos_command_expr(inner, defined_labels, diags);
                }
            }
        }
        CommandExpr::If(if_stmt) => visit_dos_if_statement(if_stmt, defined_labels, diags),
        CommandExpr::For(for_stmt) => visit_dos_for_statement(for_stmt, defined_labels, diags),
        CommandExpr::Pipe { left, right, .. } => {
            visit_dos_command_expr(left, defined_labels, diags);
            visit_dos_command_expr(right, defined_labels, diags);
        }
        CommandExpr::Seq {
            left,
            right,
            op_span,
            ..
        } => {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD5004"),
                severity: Severity::Error,
                message: "Unconditional `&` command chaining is unsupported in MS-DOS COMMAND.COM."
                    .to_owned(),
                primary_span: *op_span,
                help: Some("Place chained commands on separate physical lines.".to_owned()),
                fix: Some(SuggestedFix {
                    description: "Split `&` command chain onto separate lines".to_owned(),
                    span: *op_span,
                    replacement: CRLF.to_owned(),
                }),
            });
            visit_dos_command_expr(left, defined_labels, diags);
            visit_dos_command_expr(right, defined_labels, diags);
        }
        CommandExpr::And {
            left,
            right,
            op_span,
            ..
        }
        | CommandExpr::Or {
            left,
            right,
            op_span,
            ..
        } => {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD5004"),
                severity: Severity::Error,
                message:
                    "Conditional `&&` / `||` command chaining is unsupported in MS-DOS COMMAND.COM."
                        .to_owned(),
                primary_span: *op_span,
                help: Some("Use `IF ERRORLEVEL 1` checks on separate lines.".to_owned()),
                fix: None,
            });
            visit_dos_command_expr(left, defined_labels, diags);
            visit_dos_command_expr(right, defined_labels, diags);
        }
    }
}

/// Checks `IF` switches, conditions, and `ELSE` branches (`CMD5003`).
///
/// # Arguments
/// * `if_stmt` - [`IfStatement`].
/// * `defined_labels` - Defined script labels.
/// * `diags` - Destination diagnostic buffer.
fn visit_dos_if_statement(
    if_stmt: &IfStatement,
    defined_labels: &BTreeSet<String>,
    diags: &mut Vec<Diagnostic>,
) {
    if if_stmt.case_sensitivity == CaseSensitivity::Insensitive {
        push_cmd5003(
            if_stmt.span,
            "`IF /I` case-insensitive switch is unsupported in MS-DOS COMMAND.COM.",
            diags,
        );
    }
    match &if_stmt.condition {
        IfCondition::Defined { var_name } => {
            push_cmd5003(
                var_name.span,
                "`IF DEFINED` is unsupported in MS-DOS COMMAND.COM; compare `'%VAR%'==''` instead.",
                diags,
            );
        }
        IfCondition::CmdExtVersion { raw_token, .. } => {
            push_cmd5003(
                raw_token.span,
                "`IF CMDEXTVERSION` is unsupported in MS-DOS COMMAND.COM.",
                diags,
            );
        }
        IfCondition::Compare {
            left,
            op,
            op_span,
            right,
        } => {
            check_dos_word_parts(left, diags);
            check_dos_word_parts(right, diags);
            if *op != ComparisonOp::DoubleEquals {
                push_cmd5003(
                    *op_span,
                    "Extended `IF` comparison operators (`EQU`, `NEQ`, `LSS`, `LEQ`, `GTR`, `GEQ`) are unsupported in MS-DOS COMMAND.COM; only `==` is supported.",
                    diags,
                );
            }
        }
        IfCondition::Exist { path_pattern } => {
            check_dos_word_parts(path_pattern, diags);
            check_dos_path_word_8_3(path_pattern, diags);
        }
        IfCondition::ErrorLevel { raw_token, .. } => {
            check_dos_word_parts(raw_token, diags);
        }
    }
    if let Some(else_br) = &if_stmt.else_branch {
        push_cmd5003(
            else_br.span(),
            "`ELSE` clauses on `IF` statements are unsupported in MS-DOS COMMAND.COM.",
            diags,
        );
        visit_dos_command_expr(else_br, defined_labels, diags);
    }
    visit_dos_command_expr(&if_stmt.then_branch, defined_labels, diags);
}

/// Appends a `CMD5003` `IF`-portability diagnostic.
///
/// # Arguments
/// * `span` - Source [`Span`].
/// * `msg` - Diagnostic message.
/// * `diags` - Destination diagnostic buffer.
fn push_cmd5003(span: Span, msg: &str, diags: &mut Vec<Diagnostic>) {
    diags.push(Diagnostic {
        rule_id: RuleId::new("CMD5003"),
        severity: Severity::Error,
        message: msg.to_owned(),
        primary_span: span,
        help: Some(
            "Use `IF [NOT] ERRORLEVEL n`, `IF [NOT] EXIST file`, or `IF [NOT] a==b` with `GOTO` labels."
                .to_owned(),
        ),
        fix: None,
    });
}

/// Checks `FOR` loop variants and set tokens (`CMD5002`, `CMD5005`).
///
/// # Arguments
/// * `for_stmt` - [`ForStatement`].
/// * `defined_labels` - Defined script labels.
/// * `diags` - Destination diagnostic buffer.
fn visit_dos_for_statement(
    for_stmt: &ForStatement,
    defined_labels: &BTreeSet<String>,
    diags: &mut Vec<Diagnostic>,
) {
    if !matches!(for_stmt.variant, ForVariant::StandardFiles) {
        diags.push(Diagnostic {
            rule_id: RuleId::new("CMD5002"),
            severity: Severity::Error,
            message:
                "Extended `FOR` switches (`/F`, `/L`, `/R`, `/D`) are unsupported in MS-DOS COMMAND.COM."
                    .to_owned(),
            primary_span: for_stmt.span,
            help: Some("MS-DOS COMMAND.COM supports only plain `FOR %%I IN (set) DO command`.".to_owned()),
            fix: None,
        });
    }
    for tok in &for_stmt.in_set {
        check_dos_word_parts(tok, diags);
    }
    visit_dos_command_expr(&for_stmt.body, defined_labels, diags);
}

/// Audits a [`SimpleCommand`] against `CMD5001`, `CMD5005`, `CMD5006`, `CMD5007`, `CMD5008`, `CMD5009`, and `CMD5010`.
///
/// # Arguments
/// * `simple` - [`SimpleCommand`].
/// * `defined_labels` - Defined script labels.
/// * `diags` - Destination diagnostic buffer.
fn visit_dos_simple_command(
    simple: &SimpleCommand,
    defined_labels: &BTreeSet<String>,
    diags: &mut Vec<Diagnostic>,
) {
    check_dos_word_parts(&simple.program, diags);
    for arg in &simple.arguments {
        check_dos_word_parts(arg, diags);
    }
    check_dos_redirections(&simple.redirections, diags);

    let prog_unq = simple.program.unquoted();
    let upper = prog_unq.to_ascii_uppercase();

    match upper.as_str() {
        "SET" => check_dos_set_command(simple, diags),
        "CALL" => {
            if let Some(first) = simple.arguments.first() {
                if first.unquoted().starts_with(':') {
                    push_cmd5006(
                        first.span,
                        "`CALL :label` subroutine calls are unsupported in MS-DOS COMMAND.COM.",
                        None,
                        diags,
                    );
                } else {
                    check_dos_path_word_8_3(first, diags);
                }
            }
        }
        "GOTO" => {
            if let Some(first) = simple.arguments.first()
                && first.unquoted().eq_ignore_ascii_case(":EOF")
                && !defined_labels.contains("EOF")
            {
                push_cmd5006(
                    first.span,
                    "Implicit `GOTO :EOF` without an explicit `:EOF` label is unsupported in MS-DOS COMMAND.COM.",
                    Some(SuggestedFix {
                        description: "Use explicit `:EOF` label at end of batch file".to_owned(),
                        span: first.span,
                        replacement: "EOF".to_owned(),
                    }),
                    diags,
                );
            }
        }
        "EXIT" => {
            if let Some(sw) = simple
                .arguments
                .iter()
                .find(|w| w.unquoted().eq_ignore_ascii_case("/B"))
            {
                push_cmd5006(
                    sw.span,
                    "`EXIT /B` batch-only return is unsupported in MS-DOS COMMAND.COM; jump to an explicit `:EOF` label instead.",
                    None,
                    diags,
                );
            }
        }
        "SETLOCAL" | "ENDLOCAL" | "PUSHD" | "POPD" | "ASSOC" | "FTYPE" | "MKLINK" => {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD5007"),
                severity: Severity::Error,
                message: format!(
                    "`{upper}` is a Windows NT command extension unavailable in MS-DOS COMMAND.COM."
                ),
                primary_span: simple.program.span,
                help: Some(
                    "Remove NT-only directory/environment stack commands when targeting MS-DOS."
                        .to_owned(),
                ),
                fix: None,
            });
        }
        _ => {
            check_dos_external_command(simple, prog_unq, &upper, diags);
        }
    }
}

/// Checks `SET /A` and `SET /P` switches (`CMD5001`).
///
/// # Arguments
/// * `simple` - `SET` [`SimpleCommand`].
/// * `diags` - Destination diagnostic buffer.
fn check_dos_set_command(simple: &SimpleCommand, diags: &mut Vec<Diagnostic>) {
    let trimmed = simple.raw_tail.trim_start();
    let prefix2 = trimmed.get(..2).unwrap_or("");
    if prefix2.eq_ignore_ascii_case("/A") || prefix2.eq_ignore_ascii_case("/P") {
        let span = simple.arguments.first().map_or(simple.span, |w| w.span);
        diags.push(Diagnostic {
            rule_id: RuleId::new("CMD5001"),
            severity: Severity::Error,
            message: format!(
                "`SET {}` is unsupported in MS-DOS COMMAND.COM (only plain `SET VAR=value` exists).",
                prefix2.to_ascii_uppercase()
            ),
            primary_span: span,
            help: Some("Use `CHOICE` for interactive prompts or an external DOS helper for arithmetic.".to_owned()),
            fix: None,
        });
    }
}

/// Appends a `CMD5006` subroutine / `:EOF` / `EXIT /B` diagnostic.
///
/// # Arguments
/// * `span` - Source [`Span`].
/// * `msg` - Diagnostic message.
/// * `fix` - Optional [`SuggestedFix`].
/// * `diags` - Destination diagnostic buffer.
fn push_cmd5006(span: Span, msg: &str, fix: Option<SuggestedFix>, diags: &mut Vec<Diagnostic>) {
    diags.push(Diagnostic {
        rule_id: RuleId::new("CMD5006"),
        severity: Severity::Error,
        message: msg.to_owned(),
        primary_span: span,
        help: Some(
            "Define an explicit `:EOF` label at the end of the `.BAT` file and use `GOTO EOF`."
                .to_owned(),
        ),
        fix,
    });
}

/// Checks external command paths (`CMD5009`) and 126-byte PSP command-tail length (`CMD5010`).
///
/// # Arguments
/// * `simple` - [`SimpleCommand`].
/// * `prog_unq` - Unquoted program token.
/// * `upper` - Uppercase program token.
/// * `diags` - Destination diagnostic buffer.
fn check_dos_external_command(
    simple: &SimpleCommand,
    prog_unq: &str,
    upper: &str,
    diags: &mut Vec<Diagnostic>,
) {
    if DOS_RESIDENT_COMMANDS.contains(&upper) {
        for arg in &simple.arguments {
            if !arg.unquoted().starts_with('/') {
                check_dos_path_word_8_3(arg, diags);
            }
        }
        return;
    }

    check_dos_path_word_8_3(&simple.program, diags);
    let clean_tail = simple
        .raw_tail
        .trim_end_matches([crate::types::CR_CHAR, crate::types::LF_CHAR])
        .trim_start();
    let psp_len = if clean_tail.is_empty() {
        0
    } else {
        clean_tail.len().saturating_add(1)
    };
    if psp_len > MAX_PSP_COMMAND_TAIL_BYTES {
        diags.push(Diagnostic {
            rule_id: RuleId::new("CMD5010"),
            severity: Severity::Warning,
            message: format!(
                "External command `{prog_unq}` argument tail is {psp_len} bytes, exceeding the 126-byte MS-DOS PSP limit."
            ),
            primary_span: simple.raw_tail_span,
            help: Some(
                "Shorten the argument list or pass `@response.rsp` for DJGPP/DOS tools.".to_owned(),
            ),
            fix: None,
        });
    }
}

/// Checks sub-word variable expansions for `!VAR!`, `%VAR:~...%`, `%VAR:a=b%`, and `%~dpnx1` (`CMD5005`).
///
/// # Arguments
/// * `word` - [`SpannedWord`] to inspect.
/// * `diags` - Destination diagnostic buffer.
fn check_dos_word_parts(word: &SpannedWord, diags: &mut Vec<Diagnostic>) {
    for part in &word.parts {
        match part.kind {
            WordPartKind::DelayedVar => {
                push_cmd5005(
                    part.span,
                    format!(
                        "Delayed variable expansion `{}` is unsupported in MS-DOS COMMAND.COM.",
                        part.text
                    ),
                    diags,
                );
            }
            WordPartKind::EnvVar => {
                if part.text.contains(':') {
                    push_cmd5005(
                        part.span,
                        format!(
                            "Substring/replacement expansion `{}` is unsupported in MS-DOS COMMAND.COM.",
                            part.text
                        ),
                        diags,
                    );
                }
            }
            WordPartKind::PositionalParam
            | WordPartKind::ForVar
            | WordPartKind::InvalidModifierVar => {
                if part.text.contains('~') || part.text == "%*" {
                    push_cmd5005(
                        part.span,
                        format!(
                            "Extended parameter modifier `{}` is unsupported in MS-DOS COMMAND.COM.",
                            part.text
                        ),
                        diags,
                    );
                }
            }
            WordPartKind::Literal
            | WordPartKind::Quoted
            | WordPartKind::CaretEscape
            | WordPartKind::PercentLiteral => {}
        }
    }
}

/// Appends a `CMD5005` variable-syntax diagnostic.
///
/// # Arguments
/// * `span` - Source [`Span`].
/// * `msg` - Diagnostic message.
/// * `diags` - Destination diagnostic buffer.
fn push_cmd5005(span: Span, msg: String, diags: &mut Vec<Diagnostic>) {
    diags.push(Diagnostic {
        rule_id: RuleId::new("CMD5005"),
        severity: Severity::Error,
        message: msg,
        primary_span: span,
        help: Some(
            "MS-DOS COMMAND.COM supports only plain `%VAR%`, `%0`–`%9`, and `%%I`.".to_owned(),
        ),
        fix: None,
    });
}

/// Audits redirections against numeric FD prefixes (`2>`, `2>&1`, `1>&2`, `CMD5008`) and 8.3 target names (`CMD5009`).
///
/// # Arguments
/// * `redirs` - Slice of [`Redirection`]s.
/// * `diags` - Destination diagnostic buffer.
fn check_dos_redirections(redirs: &[Redirection], diags: &mut Vec<Diagnostic>) {
    for redir in redirs {
        let default_fd = match &redir.kind {
            RedirectionKind::ReadFromFile(target) => {
                check_dos_word_parts(target, diags);
                check_dos_path_word_8_3(target, diags);
                0
            }
            RedirectionKind::WriteTruncate(target) | RedirectionKind::WriteAppend(target) => {
                check_dos_word_parts(target, diags);
                check_dos_path_word_8_3(target, diags);
                1
            }
            RedirectionKind::DuplicateOutput(_) | RedirectionKind::DuplicateInput(_) => 255,
        };
        if redir.source_handle.index() != default_fd {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD5008"),
                severity: Severity::Error,
                message:
                    "Numeric file-descriptor redirection (`2>`, `2>&1`, `1>&2`) is unsupported in MS-DOS COMMAND.COM."
                        .to_owned(),
                primary_span: redir.span,
                help: Some("MS-DOS COMMAND.COM supports only `<`, `>`, and `>>` on standard input/output.".to_owned()),
                fix: None,
            });
        }
    }
}

/// Checks literal path segments inside `word` for strict FAT 8.3 validity (`CMD5009`).
///
/// # Arguments
/// * `word` - Candidate path [`SpannedWord`].
/// * `diags` - Destination diagnostic buffer.
fn check_dos_path_word_8_3(word: &SpannedWord, diags: &mut Vec<Diagnostic>) {
    let raw = word.unquoted();
    if raw.is_empty() || raw.contains(['%', '!', '*', '?']) {
        return;
    }
    let after_drive = if raw.as_bytes().get(1) == Some(&b':') {
        if !raw.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) {
            return;
        }
        raw.get(2..).unwrap_or("")
    } else if raw.contains([BS_CHAR, '/', '.']) || word.quoted {
        raw
    } else {
        return;
    };

    for seg in after_drive.split([BS_CHAR, '/']) {
        if matches!(seg, "" | "." | "..") {
            continue;
        }
        if seg.to_ascii_lowercase().ends_with(".cmd")
            || DosFileName8Dot3::validate_strict(seg).is_err()
        {
            diags.push(Diagnostic {
                rule_id: RuleId::new("CMD5009"),
                severity: Severity::Warning,
                message: format!(
                    "Path segment `{seg}` violates strict MS-DOS FAT 8.3 naming rules."
                ),
                primary_span: word.span,
                help: Some(
                    "Use 1–8 stem characters and 0–3 extension characters without spaces or `.cmd`."
                        .to_owned(),
                ),
                fix: None,
            });
            return;
        }
    }
}

/// Whether the script already defines an explicit `:EOF` label line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EofLabelStatus {
    /// Script already contains `:EOF`.
    Defined,
    /// Script does not yet define `:EOF`.
    Missing,
}

/// Safe `CstRewriter` pass for `ShellDialect::MsDos622` (`CMD5004` `&` line splitting and `CMD5006` `:EOF` footer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MsDosPortabilityPass;

impl CstRewriteRule for MsDosPortabilityPass {
    /// Returns the primary [`RuleId`] (`CMD5006`) of this pass.
    ///
    /// # Returns
    /// `RuleId("CMD5006")`.
    fn rule_id(&self) -> RuleId {
        RuleId::new("CMD5006")
    }

    /// Returns the static pass name.
    ///
    /// # Returns
    /// `"MsDosPortabilityPass"`.
    fn name(&self) -> &'static str {
        "MsDosPortabilityPass"
    }

    /// Applies lossless MS-DOS `COMMAND.COM` rewrites when `ctx.linter_config` selects [`ShellDialect::MsDos622`].
    ///
    /// # Arguments
    /// * `root` - Script root [`CstNode`].
    /// * `ctx` - Mutable [`RewriteContext`].
    ///
    /// # Returns
    /// Rewritten [`CstNode`].
    fn rewrite_script(&self, root: &CstNode, ctx: &mut RewriteContext) -> CstNode {
        let is_dos622 = ctx
            .linter_config
            .as_ref()
            .is_some_and(|c| c.dialect == ShellDialect::MsDos622);
        if !is_dos622 {
            return root.clone();
        }

        let eof_status = cst_eof_label_status(root);
        let mut need_eof_footer = false;
        let rewritten = rewrite_dos_cst_node(root, ctx, eof_status, &mut need_eof_footer, 0);
        if !need_eof_footer {
            return rewritten;
        }

        let mut children = rewritten.children;
        let footer = format!("{CRLF}:EOF{CRLF}");
        children.push(CstElement::Token(CstToken::new(
            SyntaxKind::LiteralToken,
            footer,
            rewritten.span,
        )));
        CstNode::new(rewritten.kind, rewritten.span, children)
    }
}

/// Checks whether `root` already defines an explicit `:EOF` label line.
///
/// # Arguments
/// * `root` - Script root [`CstNode`].
///
/// # Returns
/// [`EofLabelStatus::Defined`] if `:EOF` is present, else [`EofLabelStatus::Missing`].
#[must_use]
fn cst_eof_label_status(root: &CstNode) -> EofLabelStatus {
    let found = root
        .descendant_nodes()
        .into_iter()
        .filter(|n| n.kind == SyntaxKind::LabelStatement)
        .any(|lbl| {
            lbl.to_source_string()
                .trim()
                .trim_start_matches(':')
                .split_whitespace()
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("EOF"))
        });
    if found {
        EofLabelStatus::Defined
    } else {
        EofLabelStatus::Missing
    }
}

/// Recursively rewrites top-level `&` tokens (`CMD5004`) and `GOTO :EOF` targets (`CMD5006`).
///
/// # Arguments
/// * `node` - Current [`CstNode`].
/// * `ctx` - Mutable [`RewriteContext`].
/// * `eof_status` - [`EofLabelStatus`] of the script.
/// * `need_eof_footer` - Latched `true` when `GOTO :EOF` is rewritten and `:EOF` must be appended.
/// * `paren_depth` - Nesting depth inside `CompoundBlock` / `IfStatement` / `ForStatement`.
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_dos_cst_node(
    node: &CstNode,
    ctx: &mut RewriteContext,
    eof_status: EofLabelStatus,
    need_eof_footer: &mut bool,
    paren_depth: usize,
) -> CstNode {
    if node.kind == SyntaxKind::SimpleCommand {
        return rewrite_dos_goto_eof_command(node, ctx, eof_status, need_eof_footer);
    }

    let next_depth = if matches!(
        node.kind,
        SyntaxKind::CompoundBlock | SyntaxKind::IfStatement | SyntaxKind::ForStatement
    ) {
        paren_depth.saturating_add(1)
    } else {
        paren_depth
    };

    let mut out_children = Vec::with_capacity(node.children.len());
    for el in &node.children {
        match el {
            CstElement::Token(tok)
                if node.kind == SyntaxKind::BinaryCommandExpr
                    && tok.kind == SyntaxKind::OperatorToken
                    && tok.text == "&"
                    && paren_depth == 0
                    && ctx.is_rule_enabled_at(
                        "CMD5004",
                        tok.span,
                        FixApplicability::RecommendedRepair,
                    ) =>
            {
                ctx.record_edit(
                    RuleId::new("CMD5004"),
                    "Split top-level `&` command chain into sequential MS-DOS lines".to_owned(),
                    tok.span,
                    tok.text.clone(),
                    CRLF.to_owned(),
                );
                out_children.push(CstElement::Token(CstToken::new(
                    SyntaxKind::Newline,
                    CRLF.to_owned(),
                    tok.span,
                )));
            }
            CstElement::Token(tok) => out_children.push(CstElement::Token(tok.clone())),
            CstElement::Node(child) => out_children.push(CstElement::Node(rewrite_dos_cst_node(
                child,
                ctx,
                eof_status,
                need_eof_footer,
                next_depth,
            ))),
        }
    }
    CstNode::new(node.kind, node.span, out_children)
}

/// Rewrites `GOTO :EOF` into `GOTO EOF` and requests appending `:EOF` when `CMD5006` is enabled.
///
/// # Arguments
/// * `node` - [`SyntaxKind::SimpleCommand`] node.
/// * `ctx` - Mutable [`RewriteContext`].
/// * `eof_status` - [`EofLabelStatus`] of the script.
/// * `need_eof_footer` - Set to `true` when `:EOF` must be appended.
///
/// # Returns
/// Rewritten [`CstNode`].
fn rewrite_dos_goto_eof_command(
    node: &CstNode,
    ctx: &mut RewriteContext,
    eof_status: EofLabelStatus,
    need_eof_footer: &mut bool,
) -> CstNode {
    let mut word_iter = node
        .child_nodes()
        .filter(|n| n.kind == SyntaxKind::WordNode);
    let is_goto = word_iter
        .next()
        .is_some_and(|w| w.to_source_string().eq_ignore_ascii_case("GOTO"));
    if !is_goto {
        return node.clone();
    }
    let Some(target_word) = word_iter.next() else {
        return node.clone();
    };
    if !target_word.to_source_string().eq_ignore_ascii_case(":EOF")
        || eof_status == EofLabelStatus::Defined
        || !ctx.is_rule_enabled_at(
            "CMD5006",
            target_word.span,
            FixApplicability::RecommendedRepair,
        )
    {
        return node.clone();
    }

    let mut new_children = Vec::with_capacity(node.children.len());
    for el in &node.children {
        if let CstElement::Node(child) = el
            && child.span == target_word.span
        {
            *need_eof_footer = true;
            ctx.record_edit(
                RuleId::new("CMD5006"),
                "Rewrite `GOTO :EOF` to explicit `GOTO EOF` label jump".to_owned(),
                child.span,
                child.to_source_string(),
                "EOF".to_owned(),
            );
            new_children.push(CstElement::Node(CstNode::new(
                SyntaxKind::WordNode,
                child.span,
                alloc::vec![CstElement::Token(CstToken::new(
                    SyntaxKind::LiteralToken,
                    "EOF".to_owned(),
                    child.span,
                ))],
            )));
        } else {
            new_children.push(el.clone());
        }
    }
    CstNode::new(node.kind, node.span, new_children)
}
