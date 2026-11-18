//! Phase 2 runtime entrypoints backed by the unified [`super::lexer`], [`super::cst_parser`],
//! and [`super::lower`] pipeline.
//!
//! Eliminates duplicate recursive-descent parsing so `wincmd` runtime execution and
//! `wincheck` static analysis share a single canonical grammar, operator-precedence table,
//! `ECHO(` block balancer, and CST-to-AST lowerer (using [`WordPartsMode::Lightweight`] at
//! runtime to avoid sub-word [`crate::parser::ast::WordPart`] heap allocations).

use alloc::vec::Vec;

use crate::error::CmdError;
use crate::parser::ast::{LabelNode, SpannedWord, Statement};
use crate::parser::cst::SyntaxKind;
use crate::parser::cst_parser::parse_statement_chars_cst;
use crate::parser::lexer::{
    WordPartsMode, compute_lossless_paren_balance,
    tokenize_command_arguments as lex_tokenize_command_arguments,
};
use crate::parser::lower::{lower_statement_cst_node_with_mode, strict_diag_to_cmd_error};
use crate::reader::char_map::{LogicalLineBuffer, SpannedChar};
use crate::reader::stream::BatchFrameReader;
use crate::span::{ByteOffset, SourceId, Span};
use crate::types::{CodePage, ExecutionContext, LF_CHAR, RecoveryMode};

/// Tokenizes command arguments from `chars` in zero-subword-allocation [`WordPartsMode::Lightweight`] mode.
///
/// # Arguments
/// * `chars` - Argument tail [`SpannedChar`] slice.
///
/// # Returns
/// Vector of [`SpannedWord`] arguments.
#[must_use]
pub fn tokenize_command_arguments(chars: &[SpannedChar]) -> Vec<SpannedWord> {
    lex_tokenize_command_arguments(chars)
}

/// Reads and parses the next top-level [`Statement`] from raw physical `raw_bytes` using `codepage`,
/// allowing mid-script `CHCP` codepage switches to take immediate effect on subsequent lines!
///
/// # Arguments
/// * `reader` - Mutable [`BatchFrameReader`] tracking physical byte offsets.
/// * `raw_bytes` - Raw undecoded script bytes.
/// * `codepage` - Currently active [`CodePage`].
/// * `labels_out` - Accumulator for discovered `:label` declarations.
/// * `broken_carets_out` - Accumulator for broken trailing `^ ` spans.
/// * `phase1_fn` - Callback running Phase 1 `%VAR%` expansion per logical line.
///
/// # Returns
/// `Ok(Some(Statement))` if a statement was read, or `Ok(None)` at EOF / `0x1A`.
///
/// # Errors
/// Returns [`CmdError`] on decoding errors, Phase 1 errors, unclosed `(`, or Phase 2 syntax errors.
pub fn read_and_parse_next_statement_bytes(
    reader: &mut BatchFrameReader,
    raw_bytes: &[u8],
    codepage: CodePage,
    labels_out: &mut Vec<LabelNode>,
    broken_carets_out: &mut Vec<Span>,
    phase1_fn: &mut dyn FnMut(&LogicalLineBuffer) -> Result<LogicalLineBuffer, CmdError>,
) -> Result<Option<Statement>, CmdError> {
    let start_offset = reader.cursor;
    let Some(first_raw) = reader.read_logical_line_bytes(raw_bytes, codepage)? else {
        return Ok(None);
    };
    if let Some(bc) = first_raw.broken_caret_span {
        broken_caret_spans_push(broken_carets_out, bc);
    }
    let mut combined = phase1_fn(&first_raw)?;

    while compute_lossless_paren_balance(&combined.chars) > 0 {
        let Some(next_raw) = reader.read_logical_line_bytes(raw_bytes, codepage)? else {
            let unclosed_span = combined.full_span(reader.source_id, start_offset);
            return Err(CmdError::UnbalancedParenthesis {
                span: unclosed_span,
            });
        };
        if let Some(bc) = next_raw.broken_caret_span {
            broken_caret_spans_push(broken_carets_out, bc);
        }
        let next_expanded = phase1_fn(&next_raw)?;
        let sep_off = combined.chars.last().map_or(start_offset, |c| c.span.end);
        combined.chars.push(SpannedChar::literal(
            LF_CHAR,
            Span::new(reader.source_id, sep_off, sep_off),
        ));
        combined.chars.extend(next_expanded.chars);
    }

    let prev_lbl_len = labels_out.len();
    let mut stmt = parse_statement_strict(
        &combined,
        reader.source_id,
        start_offset,
        ExecutionContext::BatchFile,
        labels_out,
    )?;
    let next_off = reader.cursor;
    for lbl in labels_out.get_mut(prev_lbl_len..).unwrap_or(&mut []) {
        lbl.next_line_offset = next_off;
    }
    if let Statement::Label(ref mut lbl) = stmt {
        lbl.next_line_offset = next_off;
    }
    Ok(Some(stmt))
}

/// Parses a single pre-assembled interactive [`LogicalLineBuffer`] into an AST [`Statement`].
///
/// # Arguments
/// * `line` - Phase-1-expanded [`LogicalLineBuffer`].
/// * `source_id` - Source buffer ID.
/// * `fallback_offset` - Starting [`ByteOffset`] when `line` is empty.
///
/// # Returns
/// `Ok(Statement)` when valid.
///
/// # Errors
/// Returns [`CmdError`] on unbalanced parentheses or syntax errors.
pub fn parse_logical_line_statement(
    line: &LogicalLineBuffer,
    source_id: SourceId,
    fallback_offset: ByteOffset,
) -> Result<Statement, CmdError> {
    if compute_lossless_paren_balance(&line.chars) > 0 {
        let span = line.full_span(source_id, fallback_offset);
        return Err(CmdError::UnbalancedParenthesis { span });
    }
    let mut labels_discard = Vec::new();
    parse_statement_strict(
        line,
        source_id,
        fallback_offset,
        ExecutionContext::InteractiveRepl,
        &mut labels_discard,
    )
}

/// Parses `line` via [`parse_statement_chars_cst`] (`RecoveryMode::Strict`) and lowers to [`Statement`].
///
/// # Arguments
/// * `line` - Assembled [`LogicalLineBuffer`].
/// * `source_id` - Source buffer ID.
/// * `fallback_offset` - Fallback [`ByteOffset`].
/// * `exec_ctx` - Active [`ExecutionContext`].
/// * `labels_out` - Label accumulator.
///
/// # Returns
/// `Ok(Statement)` when valid.
///
/// # Errors
/// Returns [`CmdError`] if any syntax error diagnostic was recorded.
fn parse_statement_strict(
    line: &LogicalLineBuffer,
    source_id: SourceId,
    fallback_offset: ByteOffset,
    exec_ctx: ExecutionContext,
    labels_out: &mut Vec<LabelNode>,
) -> Result<Statement, CmdError> {
    let (cst_node, diags) = parse_statement_chars_cst(
        source_id,
        &line.chars,
        exec_ctx,
        RecoveryMode::Strict,
        fallback_offset,
    );
    if let Some(syntax_diag) = diags.iter().find(|d| d.misuse_kind.is_none()) {
        return Err(strict_diag_to_cmd_error(syntax_diag));
    }
    if cst_node.kind == SyntaxKind::ErrorNode {
        return Err(CmdError::SyntaxError {
            span: cst_node.span,
        });
    }
    lower_statement_cst_node_with_mode(&cst_node, labels_out, WordPartsMode::Lightweight).ok_or(
        CmdError::SyntaxError {
            span: cst_node.span,
        },
    )
}

/// Appends `span` to `out`.
///
/// # Arguments
/// * `out` - Destination vector.
/// * `span` - Broken caret [`Span`].
fn broken_caret_spans_push(out: &mut Vec<Span>, span: Span) {
    out.push(span);
}

#[cfg(test)]
/// Unit tests for Phase 2 runtime statement-reading and parsing entrypoints.
mod tests {
    use crate::parser::ast::{
        CommandExpr, ComparisonOp, ForVariant, IfCondition, IfStatement, ParsedScript,
    };
    use crate::types::{CRLF, CaseSensitivity, NegationMode};

    use super::*;

    /// Collects all statements, labels, and broken-caret spans from `script_text` using
    /// the canonical byte-offset [`read_and_parse_next_statement_bytes`] pipeline.
    ///
    /// # Arguments
    /// * `source_id` - Source buffer ID.
    /// * `script_text` - UTF-8 batch script text.
    ///
    /// # Returns
    /// `Ok(ParsedScript)` when valid.
    ///
    /// # Errors
    /// Returns [`CmdError`] on syntax or unbalanced-parenthesis errors.
    fn parse_bytes_script_for_test(
        source_id: SourceId,
        script_text: &str,
    ) -> Result<ParsedScript, CmdError> {
        let mut reader = BatchFrameReader::new(source_id);
        let mut statements = Vec::new();
        let mut labels = Vec::new();
        let mut broken_caret_spans = Vec::new();
        while let Some(stmt) = read_and_parse_next_statement_bytes(
            &mut reader,
            script_text.as_bytes(),
            CodePage::Utf8,
            &mut labels,
            &mut broken_caret_spans,
            &mut |line| Ok(line.clone()),
        )? {
            statements.push(stmt);
        }
        Ok(ParsedScript {
            source_id,
            statements,
            labels,
            broken_caret_spans,
        })
    }

    /// Verifies `ECHO(` inside `( ... )` blocks, operator precedence (`|` > `&&`/`||` > `&`),
    /// `SET /A` unquoted `&` splitting, `IF` / `FOR` variants, and strict syntax error reporting.
    #[test]
    fn test_unified_phase2_echo_paren_in_block_precedence_and_errors() {
        let echo_blk = parse_bytes_script_for_test(SourceId(0), &format!("( echo(hello ){CRLF}"));
        assert!(echo_blk.is_ok());

        let set_a_seq = parse_bytes_script_for_test(SourceId(0), "set /a x=1 & echo ok");
        assert!(matches!(
            set_a_seq.as_ref().ok().and_then(|p| p.statements.first()),
            Some(Statement::Command(CommandExpr::Seq { .. }))
        ));

        let script = [
            "@echo off",
            ":start_lbl",
            ":: double colon comment",
            "rem remark text",
            "if /i not a == b (echo yes) else (echo no)",
            "if errorlevel 0x10 echo hex16",
            "if cmdextversion 2 echo ext2",
            "if exist C:/file.txt echo ex",
            "if defined PATH echo def",
            "if 10 gtr 2 echo cmp",
            "for %%I in (a b) do echo %%I",
            "for /d %%D in (*) do echo %%D",
            "for /r C:/ %%R in (*.txt) do echo %%R",
            "for /l %%N in (1,1,5) do echo %%N",
            r#"for /f "tokens=1,2*" %%A in ("x y z") do echo %%A"#,
        ]
        .join(CRLF);
        let parsed = parse_bytes_script_for_test(SourceId(0), &script);
        assert!(parsed.is_ok());
        let ps = parsed.unwrap_or(ParsedScript {
            source_id: SourceId(0),
            statements: Vec::new(),
            labels: Vec::new(),
            broken_caret_spans: Vec::new(),
        });
        assert_eq!(ps.labels.iter().filter(|l| !l.is_double_colon).count(), 1);
        assert_eq!(ps.labels.iter().filter(|l| l.is_double_colon).count(), 1);
        assert!(ps.statements.iter().any(|s| matches!(
            s,
            Statement::Command(CommandExpr::If(if_box))
                if matches!(if_box.condition, IfCondition::ErrorLevel { .. })
        )));
        assert!(ps.statements.iter().any(|s| matches!(
            s,
            Statement::Command(CommandExpr::If(if_box))
                if matches!(
                    &**if_box,
                    IfStatement {
                        case_sensitivity: CaseSensitivity::Insensitive,
                        negated: NegationMode::Negated,
                        condition: IfCondition::Compare { op: ComparisonOp::DoubleEquals, .. },
                        ..
                    }
                )
        )));
        assert!(ps.statements.iter().any(|s| matches!(
            s,
            Statement::Command(CommandExpr::For(for_box))
                if matches!(for_box.variant, ForVariant::NumericSequence)
        )));

        let total_parts: usize = ps
            .statements
            .iter()
            .filter_map(|s| {
                if let Statement::Command(CommandExpr::Simple(sc)) = s {
                    Some(sc.program.parts.len())
                } else {
                    None
                }
            })
            .sum();
        assert_eq!(total_parts, 0);
    }

    /// Exercises broken carets, byte streaming readers, unbalanced parens, and strict errors.
    #[test]
    fn test_phase2_streaming_broken_carets_and_strict_errors() {
        let broken_text = format!("echo ^  {CRLF}({CRLF}echo in_blk ^  {CRLF}){CRLF}");
        let ps_bc =
            parse_bytes_script_for_test(SourceId(0), &broken_text).unwrap_or(ParsedScript {
                source_id: SourceId(0),
                statements: Vec::new(),
                labels: Vec::new(),
                broken_caret_spans: Vec::new(),
            });
        assert_eq!(ps_bc.broken_caret_spans.len(), 2);

        let mut br_unclosed = BatchFrameReader::new(SourceId(0));
        let mut lbls = Vec::new();
        let mut carets = Vec::new();
        assert!(matches!(
            read_and_parse_next_statement_bytes(
                &mut br_unclosed,
                b"(echo unclosed",
                CodePage::Utf8,
                &mut lbls,
                &mut carets,
                &mut |l| Ok(l.clone()),
            ),
            Err(CmdError::UnbalancedParenthesis { .. })
        ));

        let unclosed_line =
            LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "(echo line_unclosed");
        assert!(matches!(
            parse_logical_line_statement(&unclosed_line, SourceId(0), ByteOffset(0)),
            Err(CmdError::UnbalancedParenthesis { .. })
        ));

        for bad in [
            "| echo a",
            "echo a |",
            "echo a &",
            "( echo unclosed",
            "( )",
            "echo >",
            "echo 2>&x",
            "echo 2>&",
            "echo << in.txt",
            "if",
            "if errorlevel",
            "if a == b",
            "if a =",
            "if a == ",
            "for /z %%I in (a) do echo %%I",
            "for in (a) do echo a",
            "for %% in (a) do echo a",
            "for %%foo in (a) do echo a",
            "for %%%I in (a) do echo a",
            "for %%I foo (a) do echo %%I",
            "for %%I in",
            "for %%I in a do echo %%I",
            "for %%I in (a",
            "for %%I in (a) bar echo %%I",
            "for %%I in (a) do",
            ")",
            "(echo a) stray",
        ] {
            assert!(
                parse_bytes_script_for_test(SourceId(0), bad).is_err(),
                "Expected strict error on: {bad}"
            );
        }
    }
}
