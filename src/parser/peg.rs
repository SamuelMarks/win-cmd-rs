//! Lossless CST & AST parser facade re-exporting [`super::cst_parser`], [`super::lower`],
//! and [`super::lexer::compute_lossless_paren_balance`].

pub use super::cst_parser::{
    CstParserState, FarthestFailure, PegInput, WordEqualsMode, WordParenScope,
    parse_redirection_node, parse_script_cst, parse_statement_chars_cst, parse_statement_unit_cst,
    parse_word_node, slice_to_token,
};
pub use super::lexer::compute_lossless_paren_balance;
pub use super::lower::{
    collect_broken_carets_recursive, lower_command_expr_cst_node, lower_cst_to_ast,
    lower_cst_to_ast_with_mode, lower_statement_cst_node, lower_statement_cst_node_with_mode,
    lower_word_cst_node, lower_word_cst_node_with_mode, parse_single_word_parts,
    strict_diag_to_cmd_error,
};

#[cfg(test)]
/// Unit tests for the lossless CST facade and Phase 2 AST equivalence.
mod tests {
    use crate::error::ProbableMisuseKind;
    use crate::parser::phase2::read_and_parse_next_statement_bytes;
    use crate::reader::stream::BatchFrameReader;
    use crate::span::SourceId;
    use crate::types::{CRLF, CodePage, ExecutionContext};

    use super::*;

    /// Verifies 100% lossless round-tripping (`cst.to_source_string() == raw`), UTF-8 BOM preservation,
    /// `ECHO(` inside `( ... )` blocks, probable-misuse recovery, and AST equivalence with `phase2`.
    #[test]
    fn test_cst_losslessness_recovery_and_phase2_equivalence() {
        let bom_script = format!("\u{FEFF}@echo off{CRLF}( echo(hello & set /a x=1 ){CRLF}");
        let cst_bom = parse_script_cst(SourceId(0), &bom_script, ExecutionContext::BatchFile);
        assert_eq!(cst_bom.to_source_string(), bom_script);
        assert_eq!(cst_bom.diagnostics.len(), 0);

        let misuse_samples = [
            ("if (1 == 1) echo c_paren", true),
            ("if a = b echo single_eq", true),
            ("if 1 == 1 echo unparen else echo oops", true),
            ("for %I in (a) do echo %I", true),
            ("for %%foo in (a) do echo %%foo", true),
            ("for %%I (a b) do echo %%I", true),
            ("for %%I in (a b) echo %%I", true),
            (r#"echo "unclosed quote"#, true),
            ("echo 50%", true),
            ("echo %~dpMYVAR%", true),
            ("(echo unescaped ) trailing)", true),
        ];
        for (src, expect_misuse) in misuse_samples {
            let cst = parse_script_cst(SourceId(0), src, ExecutionContext::BatchFile);
            assert_eq!(cst.to_source_string(), src);
            assert_eq!(
                cst.diagnostics.iter().any(|d| d.misuse_kind.is_some()),
                expect_misuse,
                "Expected misuse diagnostic on: {src}"
            );
            let lowered = lower_cst_to_ast(&cst);
            assert_eq!(lowered.source_id, SourceId(0));
            assert_eq!(lowered.statements.len(), 1);
        }

        // REPL-specific `%%` misuses and non-alphabetic single-percent literal (`%{`)
        let repl_non_alpha =
            parse_script_cst(SourceId(0), "echo %{", ExecutionContext::InteractiveRepl);
        assert_eq!(repl_non_alpha.to_source_string(), "echo %{");
        let repl_cst = parse_script_cst(
            SourceId(0),
            "for %%I in (a) do echo %%I %%",
            ExecutionContext::InteractiveRepl,
        );
        assert_eq!(repl_cst.to_source_string(), "for %%I in (a) do echo %%I %%");
        assert!(repl_cst.diagnostics.iter().any(|d| matches!(
            d.misuse_kind,
            Some(ProbableMisuseKind::DoublePercentForVarInRepl { .. })
        )));
        assert!(repl_cst.diagnostics.iter().any(|d| matches!(
            d.misuse_kind,
            Some(ProbableMisuseKind::DoublePercentLiteralInRepl { .. })
        )));

        // Equivalence check between `parse_script_cst` + `lower_cst_to_ast` and `parse_full_script`
        let well_formed = [
            "@echo off",
            ":entry",
            "set X=10 & set /a X+=5 & echo !X!",
            "if errorlevel 0x0A (echo(ten) else (echo low)",
            "for /L %%I in (1,1,3) do echo %%~dpI %~$PATH:1",
        ]
        .join(CRLF);
        let cst_wf = parse_script_cst(SourceId(0), &well_formed, ExecutionContext::BatchFile);
        assert_eq!(cst_wf.to_source_string(), well_formed);
        assert_eq!(cst_wf.diagnostics.len(), 0);
        let ast_from_cst = lower_cst_to_ast(&cst_wf);

        let mut reader = BatchFrameReader::new(SourceId(0));
        let mut p2_stmts = Vec::new();
        let mut p2_labels = Vec::new();
        let mut p2_carets = Vec::new();
        while let Ok(Some(stmt)) = read_and_parse_next_statement_bytes(
            &mut reader,
            well_formed.as_bytes(),
            CodePage::Utf8,
            &mut p2_labels,
            &mut p2_carets,
            &mut |l| Ok(l.clone()),
        ) {
            p2_stmts.push(stmt);
        }
        assert_eq!(
            (p2_stmts.len(), p2_labels.len()),
            (ast_from_cst.statements.len(), ast_from_cst.labels.len())
        );
        assert_eq!(
            p2_labels
                .first()
                .map(|l| (&l.name, l.is_double_colon, l.next_line_offset)),
            ast_from_cst
                .labels
                .first()
                .map(|l| (&l.name, l.is_double_colon, l.next_line_offset))
        );
    }
}
