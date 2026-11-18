//! Composable Lossless CST Tree-Rewriting Pipeline (`CstRewriter`).
//!
//! Transforms a parsed [`CstScript`] through modular [`CstRewriteRule`] passes
//! (`DelayedExpansionBlockPass`, `StructuralSyntaxFixPass`, `ExecutionModePercentPass`,
//! `QuoteUnquotedVariablesPass`, and `MsDosPortabilityPass`) while respecting [`FixApplicability`]
//! (`SafeSemanticsPreserving`, `RecommendedRepair`, and `UnsafeOptIn`), preserving comments
//! and trivia, and recomputing exact byte [`Span`]s.

use alloc::borrow::ToOwned;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::linter::directives::{SuppressionTable, check_file_encoding_and_lines};
pub use crate::linter::passes::delayed_exp::DelayedExpansionBlockPass;
pub use crate::linter::passes::dialect::ExecutionModePercentPass;
pub use crate::linter::passes::dos_compat::MsDosPortabilityPass;
pub use crate::linter::passes::quoting::QuoteUnquotedVariablesPass;
pub use crate::linter::passes::structural::StructuralSyntaxFixPass;
use crate::linter::rules::{FixApplicability, LinterConfig, RuleId, rule_default_severity};
use crate::parser::cst::{CstNode, CstScript, SyntaxKind};
use crate::parser::peg::parse_script_cst;
use crate::span::{ByteOffset, SourceFile, SourceId, Span};
use crate::types::{DelayedExpansionMode, ExecutionContext};

/// Mutable context threaded through [`CstRewriteRule`] passes during a rewrite pipeline run.
#[derive(Debug, Clone)]
pub struct RewriteContext {
    /// Source buffer identifier used when synthesizing CST tokens and recomputing spans.
    pub source_id: SourceId,
    /// Target execution dialect (`BatchFile` vs `InteractiveRepl`).
    pub exec_context: ExecutionContext,
    /// Safety tier controlling which rewrites are permitted (`SafeSemanticsPreserving`, `RecommendedRepair`, `UnsafeOptIn`).
    pub fix_safety: FixApplicability,
    /// Optional [`LinterConfig`] filtering `--include`, `--exclude`, and `--severity`.
    pub linter_config: Option<LinterConfig>,
    /// Active [`SuppressionTable`] parsed from `REM wincheck disable=...` / `enable=...` comments.
    pub suppressions: SuppressionTable,
    /// Sorted physical line start offsets of the current source text for 1-based line resolution.
    pub line_starts: Vec<ByteOffset>,
    /// Whether `SETLOCAL EnableDelayedExpansion` is already active or present in the script.
    pub has_setlocal_enable_delayed: bool,
    /// Active delayed expansion mode at the current statement cursor.
    pub delayed_expansion: DelayedExpansionMode,
    /// Active `FOR` loop variable characters currently in scope.
    pub active_for_vars: BTreeSet<char>,
    /// Uppercase environment variable names modified via `SET` inside the current `( ... )` block.
    pub block_modified_vars: BTreeSet<String>,
    /// Current parenthesized block nesting depth (`0` at top level).
    pub block_depth: usize,
    /// Whether any block `%VAR%` -> `!VAR!` conversion requires injecting `SETLOCAL EnableDelayedExpansion`.
    pub needs_setlocal_enable_delayed_injection: bool,
    /// Structured log of all edits applied across passes.
    pub applied_edits: Vec<RewriteEditRecord>,
}

impl RewriteContext {
    /// Creates a new [`RewriteContext`] for `source_id` and `exec_context` (defaulting to `FixApplicability::UnsafeOptIn` for raw pass calls).
    ///
    /// # Arguments
    /// * `source_id` - Source file identifier.
    /// * `exec_context` - Target [`ExecutionContext`].
    ///
    /// # Returns
    /// Initialized [`RewriteContext`].
    #[must_use]
    pub fn new(source_id: SourceId, exec_context: ExecutionContext) -> Self {
        Self::with_safety(source_id, exec_context, FixApplicability::UnsafeOptIn)
    }

    /// Creates a new [`RewriteContext`] with an explicit [`FixApplicability`] tier.
    ///
    /// # Arguments
    /// * `source_id` - Source file identifier.
    /// * `exec_context` - Target [`ExecutionContext`].
    /// * `fix_safety` - [`FixApplicability`] tier.
    ///
    /// # Returns
    /// Initialized [`RewriteContext`].
    #[must_use]
    pub fn with_safety(
        source_id: SourceId,
        exec_context: ExecutionContext,
        fix_safety: FixApplicability,
    ) -> Self {
        Self {
            source_id,
            exec_context,
            fix_safety,
            linter_config: None,
            suppressions: SuppressionTable::default(),
            line_starts: vec![ByteOffset(0)],
            has_setlocal_enable_delayed: false,
            delayed_expansion: DelayedExpansionMode::Disabled,
            active_for_vars: BTreeSet::new(),
            block_modified_vars: BTreeSet::new(),
            block_depth: 0,
            needs_setlocal_enable_delayed_injection: false,
            applied_edits: Vec::new(),
        }
    }

    /// Recomputes `line_starts` and inline `REM wincheck` suppressions from `source_text`.
    ///
    /// # Arguments
    /// * `source_text` - Current serialized CST source text.
    pub fn refresh_suppressions_from_source(&mut self, source_text: &str) {
        let sf = SourceFile::new(
            self.source_id,
            String::new(),
            Vec::new(),
            source_text.to_owned(),
        );
        let mut ignored_diags = Vec::new();
        let mut supps = SuppressionTable::default();
        check_file_encoding_and_lines(&sf, &mut ignored_diags, &mut supps);
        self.line_starts = sf.line_starts;
        self.suppressions = supps;
    }

    /// Resolves the 1-based physical line number containing `offset`.
    ///
    /// # Arguments
    /// * `offset` - [`ByteOffset`] in the current source text.
    ///
    /// # Returns
    /// 1-based physical line number.
    #[must_use]
    pub fn line_number_at(&self, offset: ByteOffset) -> usize {
        match self.line_starts.binary_search(&offset) {
            Ok(exact) => exact.saturating_add(1),
            Err(ins) => ins.max(1),
        }
    }

    /// Checks whether `rule_code` is enabled at `span` under `self.fix_safety`, `self.linter_config`
    /// (`--include`, `--exclude`, `--severity`), and inline `REM wincheck` suppressions.
    ///
    /// # Arguments
    /// * `rule_code` - Canonical rule code (`"CMDxxxx"`).
    /// * `span` - Source [`Span`] of the candidate node/token.
    /// * `required_tier` - Minimum [`FixApplicability`] tier required for this rewrite.
    ///
    /// # Returns
    /// `true` if the rewrite is permitted to mutate the CST at `span`.
    #[must_use]
    pub fn is_rule_enabled_at(
        &self,
        rule_code: &str,
        span: Span,
        required_tier: FixApplicability,
    ) -> bool {
        if self.fix_safety < required_tier {
            return false;
        }
        let id = RuleId::new(rule_code);
        if let Some(cfg) = &self.linter_config {
            if cfg.dialect == crate::types::ShellDialect::MsDos622
                && matches!(
                    rule_code,
                    "CMD2001"
                        | "CMD2004"
                        | "CMD2005"
                        | "CMD2008"
                        | "CMD2009"
                        | "CMD3004"
                        | "CMD4001"
                        | "CMD4002"
                )
            {
                return false;
            }
            let sev = rule_default_severity(rule_code);
            let included = cfg.included_rules.is_empty() || cfg.included_rules.contains(&id);
            if sev < cfg.min_severity || cfg.excluded_rules.contains(&id) || !included {
                return false;
            }
        }
        let line_num = self.line_number_at(span.start);
        !self.suppressions.is_suppressed(&id, line_num)
    }

    /// Appends a [`RewriteEditRecord`] describing a CST transformation.
    ///
    /// # Arguments
    /// * `rule_id` - [`RuleId`] associated with the transformation.
    /// * `description` - Concise explanation of the rewrite.
    /// * `original_span` - Original [`Span`] prior to rewriting.
    /// * `before` - Original source fragment.
    /// * `after` - Rewritten source fragment.
    pub fn record_edit(
        &mut self,
        rule_id: RuleId,
        description: impl Into<String>,
        original_span: Span,
        before: String,
        after: String,
    ) {
        if before != after {
            self.applied_edits.push(RewriteEditRecord {
                rule_id,
                description: description.into(),
                original_span,
                before,
                after,
            });
        }
    }
}

/// Audit record of a single CST node/token rewrite applied by a [`CstRewriteRule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteEditRecord {
    /// Associated linter [`RuleId`].
    pub rule_id: RuleId,
    /// Human-readable description of the transformation.
    pub description: String,
    /// Original [`Span`] of the transformed node or token.
    pub original_span: Span,
    /// Source text prior to the rewrite.
    pub before: String,
    /// Source text after the rewrite.
    pub after: String,
}

/// Trait implemented by every composable CST tree-rewriting pass.
pub trait CstRewriteRule {
    /// Primary [`RuleId`] associated with this rewrite pass.
    ///
    /// # Returns
    /// Primary [`RuleId`].
    fn rule_id(&self) -> RuleId;

    /// Static pass identifier name.
    ///
    /// # Returns
    /// Pass name string.
    fn name(&self) -> &'static str;

    /// Transforms the root [`CstNode`] of a script and records any edits in `ctx`.
    ///
    /// # Arguments
    /// * `root` - Current [`SyntaxKind::Script`] root node.
    /// * `ctx` - Mutable [`RewriteContext`].
    ///
    /// # Returns
    /// Transformed [`CstNode`].
    fn rewrite_script(&self, root: &CstNode, ctx: &mut RewriteContext) -> CstNode;
}

/// Output of running [`CstRewriter::rewrite`] on a [`CstScript`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteOutcome {
    /// Rewritten CST root with freshly recomputed byte [`Span`]s.
    pub rewritten_cst: CstNode,
    /// Lossless serialized source string of `rewritten_cst`.
    pub rewritten_source: String,
    /// Ordered audit trail of all applied CST transformations.
    pub edits: Vec<RewriteEditRecord>,
    /// Total count of applied transformations (`edits.len()`).
    pub applied_count: usize,
}

/// Enum wrapper over all built-in composable [`CstRewriteRule`] passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinRewritePass {
    /// Structural syntax & probable-misuse fixes (`CMD1013`, `CMD1005`, `CMD1001`, `CMD1004`, `CMD2004`, `CMD2005`, `CMD2008`, `CMD3003`, `CMD3004`, `CMD4001`, `CMD4002`).
    StructuralSyntax(StructuralSyntaxFixPass),
    /// Execution-mode `%` vs `%%` dialect conversion (`CMD1007`, `CMD1014`).
    ExecutionModePercent(ExecutionModePercentPass),
    /// Block `%VAR%` / dynamic `%ERRORLEVEL%` -> `!VAR!` + `SETLOCAL EnableDelayedExpansion` (`CMD2001`, `CMD2009`).
    DelayedExpansionBlock(DelayedExpansionBlockPass),
    /// Smart variable & path quoting (`"%VAR%"`, `"%~1"`, `"%%~I"`, `CMD2003`, `CMD2006`, `CMD2007`).
    QuoteUnquotedVariables(QuoteUnquotedVariablesPass),
    /// MS-DOS 6.22 `COMMAND.COM` dialect rewrites (`CMD5004` `&` line split, `CMD5006` `:EOF` footer).
    MsDosPortability(MsDosPortabilityPass),
}

impl CstRewriteRule for BuiltinRewritePass {
    /// Returns the primary [`RuleId`] of the wrapped pass.
    ///
    /// # Returns
    /// Primary [`RuleId`].
    fn rule_id(&self) -> RuleId {
        match self {
            Self::StructuralSyntax(p) => p.rule_id(),
            Self::ExecutionModePercent(p) => p.rule_id(),
            Self::DelayedExpansionBlock(p) => p.rule_id(),
            Self::QuoteUnquotedVariables(p) => p.rule_id(),
            Self::MsDosPortability(p) => p.rule_id(),
        }
    }

    /// Returns the static name of the wrapped pass.
    ///
    /// # Returns
    /// Pass name slice.
    fn name(&self) -> &'static str {
        match self {
            Self::StructuralSyntax(p) => p.name(),
            Self::ExecutionModePercent(p) => p.name(),
            Self::DelayedExpansionBlock(p) => p.name(),
            Self::QuoteUnquotedVariables(p) => p.name(),
            Self::MsDosPortability(p) => p.name(),
        }
    }

    /// Dispatches `rewrite_script` to the wrapped pass.
    ///
    /// # Arguments
    /// * `root` - Script root [`CstNode`].
    /// * `ctx` - Mutable [`RewriteContext`].
    ///
    /// # Returns
    /// Rewritten [`CstNode`].
    fn rewrite_script(&self, root: &CstNode, ctx: &mut RewriteContext) -> CstNode {
        match self {
            Self::StructuralSyntax(p) => p.rewrite_script(root, ctx),
            Self::ExecutionModePercent(p) => p.rewrite_script(root, ctx),
            Self::DelayedExpansionBlock(p) => p.rewrite_script(root, ctx),
            Self::QuoteUnquotedVariables(p) => p.rewrite_script(root, ctx),
            Self::MsDosPortability(p) => p.rewrite_script(root, ctx),
        }
    }
}

/// Multi-pass CST tree-rewriting pipeline.
#[derive(Debug, Clone)]
pub struct CstRewriter {
    /// Target execution dialect (`BatchFile` vs `InteractiveRepl`).
    pub exec_context: ExecutionContext,
    /// Safety tier controlling which fixes are applied (`SafeSemanticsPreserving`, `RecommendedRepair`, `UnsafeOptIn`).
    pub fix_safety: FixApplicability,
    /// Optional [`LinterConfig`] rule filter (`--include`, `--exclude`, `--severity`).
    pub linter_config: Option<LinterConfig>,
    /// Ordered sequence of rewrite passes to execute.
    pub passes: Vec<BuiltinRewritePass>,
}

impl CstRewriter {
    /// Creates the full multi-pass [`CstRewriter`] pipeline (including `UnsafeOptIn` structural fixes) for `exec_context`.
    ///
    /// # Arguments
    /// * `exec_context` - Target [`ExecutionContext`] (`BatchFile` vs `InteractiveRepl`).
    ///
    /// # Returns
    /// A configured [`CstRewriter`] containing all five composable passes.
    #[must_use]
    pub fn default_for_context(exec_context: ExecutionContext) -> Self {
        Self::with_fix_safety(exec_context, FixApplicability::UnsafeOptIn)
    }

    /// Creates a recommended-repair [`CstRewriter`] (`FixApplicability::RecommendedRepair`) for `exec_context`.
    ///
    /// # Arguments
    /// * `exec_context` - Target [`ExecutionContext`] (`BatchFile` vs `InteractiveRepl`).
    ///
    /// # Returns
    /// A configured [`CstRewriter`] running safe normalizations and `!`-safe bug repairs.
    #[must_use]
    pub fn safe_for_context(exec_context: ExecutionContext) -> Self {
        Self::with_fix_safety(exec_context, FixApplicability::RecommendedRepair)
    }

    /// Creates a strictly semantics-preserving [`CstRewriter`] (`FixApplicability::SafeSemanticsPreserving`).
    ///
    /// # Arguments
    /// * `exec_context` - Target [`ExecutionContext`] (`BatchFile` vs `InteractiveRepl`).
    ///
    /// # Returns
    /// A configured [`CstRewriter`] running only semantics-preserving normalizations.
    #[must_use]
    pub fn semantics_preserving_for_context(exec_context: ExecutionContext) -> Self {
        Self::with_fix_safety(exec_context, FixApplicability::SafeSemanticsPreserving)
    }

    /// Creates a [`CstRewriter`] configured directly from a [`LinterConfig`] (`--include`, `--exclude`,
    /// `--severity`, and `fix_safety`).
    ///
    /// # Arguments
    /// * `exec_context` - Target [`ExecutionContext`].
    /// * `config` - [`LinterConfig`] governing rule filters and safety tier.
    ///
    /// # Returns
    /// A configured [`CstRewriter`].
    #[must_use]
    pub fn with_config(exec_context: ExecutionContext, config: &LinterConfig) -> Self {
        let mut rw = Self::with_fix_safety(exec_context, config.fix_safety);
        rw.linter_config = Some(config.clone());
        rw
    }

    /// Creates a [`CstRewriter`] for `exec_context` with an explicit [`FixApplicability`] tier.
    ///
    /// # Arguments
    /// * `exec_context` - Target [`ExecutionContext`] (`BatchFile` vs `InteractiveRepl`).
    /// * `fix_safety` - [`FixApplicability`] tier.
    ///
    /// # Returns
    /// A configured [`CstRewriter`].
    #[must_use]
    pub fn with_fix_safety(exec_context: ExecutionContext, fix_safety: FixApplicability) -> Self {
        Self {
            exec_context,
            fix_safety,
            linter_config: None,
            passes: vec![
                BuiltinRewritePass::DelayedExpansionBlock(DelayedExpansionBlockPass),
                BuiltinRewritePass::StructuralSyntax(StructuralSyntaxFixPass),
                BuiltinRewritePass::ExecutionModePercent(ExecutionModePercentPass),
                BuiltinRewritePass::QuoteUnquotedVariables(QuoteUnquotedVariablesPass),
                BuiltinRewritePass::MsDosPortability(MsDosPortabilityPass),
            ],
        }
    }

    /// Executes all configured rewrite passes on `cst`, respecting `LinterConfig` filters and
    /// inline `REM wincheck` suppressions while recomputing spans between passes.
    ///
    /// # Arguments
    /// * `cst` - Input [`CstScript`].
    ///
    /// # Returns
    /// A [`RewriteOutcome`] containing the rewritten [`CstNode`], source text, and edit records.
    #[must_use]
    pub fn rewrite(&self, cst: &CstScript) -> RewriteOutcome {
        let mut ctx =
            RewriteContext::with_safety(cst.source_id, self.exec_context, self.fix_safety);
        ctx.linter_config.clone_from(&self.linter_config);
        ctx.refresh_suppressions_from_source(&cst.to_source_string());
        ctx.has_setlocal_enable_delayed = detect_setlocal_enable_delayed(&cst.root);
        if ctx.has_setlocal_enable_delayed {
            ctx.delayed_expansion = DelayedExpansionMode::Enabled;
        }

        let mut current_root = cst.root.clone();
        for pass in &self.passes {
            let edits_before = ctx.applied_edits.len();
            let next_root = pass.rewrite_script(&current_root, &mut ctx);
            if ctx.applied_edits.len() > edits_before {
                let new_src = next_root.to_source_string();
                ctx.refresh_suppressions_from_source(&new_src);
                let reparsed = parse_script_cst(cst.source_id, &new_src, self.exec_context);
                current_root = reparsed.root;
            } else {
                current_root = next_root;
            }
        }

        current_root.recompute_spans(cst.source_id, ByteOffset(0));
        let rewritten_source = current_root.to_source_string();
        let applied_count = ctx.applied_edits.len();

        RewriteOutcome {
            rewritten_cst: current_root,
            rewritten_source,
            edits: ctx.applied_edits,
            applied_count,
        }
    }
}

/// Checks whether `root` already contains a `SETLOCAL EnableDelayedExpansion` command.
///
/// # Arguments
/// * `root` - Script root [`CstNode`].
///
/// # Returns
/// `true` if `SETLOCAL EnableDelayedExpansion` is present in `root`.
fn detect_setlocal_enable_delayed(root: &CstNode) -> bool {
    root.descendant_nodes()
        .into_iter()
        .filter(|n| n.kind == SyntaxKind::SimpleCommand)
        .any(|node| {
            let mut words = node
                .child_nodes()
                .filter(|n| matches!(n.kind, SyntaxKind::WordNode | SyntaxKind::SetAssignmentNode))
                .map(CstNode::to_source_string);
            let is_setlocal = words
                .next()
                .is_some_and(|first| first.eq_ignore_ascii_case("SETLOCAL"));
            let has_enable = words.any(|w| {
                w.trim_matches('"')
                    .eq_ignore_ascii_case("ENABLEDELAYEDEXPANSION")
            });
            is_setlocal && has_enable
        })
}

#[cfg(test)]
/// Unit tests for the composable lossless [`CstRewriter`] passes (`Safe` vs `UnsafeOptIn`).
mod tests {
    use super::*;
    use crate::linter::passes::delayed_exp::record_set_modified_vars_in_cst;
    use crate::types::{BS_STR as SEP, CRLF, LF_CHAR as LF};

    /// Verifies Pass 1 variable/path quoting and standalone `%~1` tilde modifier insertion.
    #[test]
    fn test_pass1_variable_and_path_quoting_and_smart_modifiers() {
        let src = [
            &format!("cd %USERPROFILE%{SEP}Documents"),
            &format!("copy %1 %2{SEP}backup.txt"),
            r#"type "%1""#,
            r#"echo "Usage: %0 %1""#,
            "for %%I in (*.txt) do del %%I",
            "if exist %TARGET_FILE% echo found > %LOG_PATH%",
            "if %MY_VAR% == foo echo match",
        ]
        .join(CRLF);

        let cst = parse_script_cst(SourceId(0), &src, ExecutionContext::BatchFile);
        let rewriter = CstRewriter::default_for_context(ExecutionContext::BatchFile);
        let outcome = rewriter.rewrite(&cst);

        let expected = [
            &format!(r#"cd "%USERPROFILE%{SEP}Documents""#),
            &format!(r#"copy "%~1" "%~2{SEP}backup.txt""#),
            r#"type "%~1""#,
            r#"echo "Usage: %0 %1""#,
            r#"for %%I in (*.txt) do del "%%~I""#,
            r#"if exist "%TARGET_FILE%" echo found > "%LOG_PATH%""#,
            r#"if "%MY_VAR%" == "foo" echo match"#,
        ]
        .join(CRLF);

        assert_eq!(outcome.rewritten_source, expected);
        assert!(outcome.applied_count >= 7);

        let cst2 = parse_script_cst(
            SourceId(0),
            &outcome.rewritten_source,
            ExecutionContext::BatchFile,
        );
        let outcome2 = rewriter.rewrite(&cst2);
        assert_eq!(outcome2.rewritten_source, expected);
        assert_eq!(outcome2.applied_count, 0);
    }

    /// Verifies Pass 2 batch (`%%I` / `%%`) vs interactive REPL (`%I` / `%`) dialect conversion.
    #[test]
    fn test_pass2_execution_mode_dialect_batch_vs_repl() {
        let repl_in_batch = format!("for %i in (*.txt) do copy %i %~ni.bak & echo 100%{CRLF}");
        let cst_batch = parse_script_cst(SourceId(0), &repl_in_batch, ExecutionContext::BatchFile);
        let batch_rewriter = CstRewriter::default_for_context(ExecutionContext::BatchFile);
        let out_batch = batch_rewriter.rewrite(&cst_batch);
        assert_eq!(
            out_batch.rewritten_source,
            format!(r#"for %%i in (*.txt) do copy "%%~i" "%%~ni.bak" & echo 100%%{CRLF}"#)
        );

        let cst_repl = parse_script_cst(
            SourceId(0),
            &out_batch.rewritten_source,
            ExecutionContext::InteractiveRepl,
        );
        let repl_rewriter = CstRewriter::default_for_context(ExecutionContext::InteractiveRepl);
        let out_repl = repl_rewriter.rewrite(&cst_repl);
        assert_eq!(
            out_repl.rewritten_source,
            format!(r#"for %i in (*.txt) do copy "%~i" "%~ni.bak" & echo 100%{CRLF}"#)
        );

        let cst_repl2 = parse_script_cst(
            SourceId(0),
            &out_repl.rewritten_source,
            ExecutionContext::InteractiveRepl,
        );
        let out_repl2 = repl_rewriter.rewrite(&cst_repl2);
        assert_eq!(out_repl2.rewritten_source, out_repl.rewritten_source);
        assert_eq!(out_repl2.applied_count, 0);
    }

    /// Verifies Pass 3 delayed-expansion `!` safety guard and `SETLOCAL EnableDelayedExpansion` injection.
    #[test]
    fn test_pass3_delayed_expansion_safe_bang_guard_and_setlocal_injection() {
        let src = [
            "@echo off",
            "(",
            "  set COUNT=1",
            "  set /a COUNT+=1",
            "  echo %COUNT% %ERRORLEVEL% %RANDOM% %TIME% %UNCHANGED%",
            ")",
        ]
        .join(CRLF);

        let cst = parse_script_cst(SourceId(0), &src, ExecutionContext::BatchFile);
        let safe_rewriter = CstRewriter::safe_for_context(ExecutionContext::BatchFile);
        let outcome = safe_rewriter.rewrite(&cst);

        let expected = [
            "@echo off",
            "SETLOCAL EnableDelayedExpansion",
            "(",
            r#"  set "COUNT=1""#,
            "  set /a COUNT+=1",
            "  echo !COUNT! !ERRORLEVEL! !RANDOM! !TIME! %UNCHANGED%",
            ")",
        ]
        .join(CRLF);
        // Note: `set COUNT=1` without spaces/carets stays `set COUNT=1`
        let expected_exact = expected.replace(r#"set "COUNT=1""#, "set COUNT=1");
        assert_eq!(outcome.rewritten_source, expected_exact);

        let cst2 = parse_script_cst(
            SourceId(0),
            &outcome.rewritten_source,
            ExecutionContext::BatchFile,
        );
        assert_eq!(safe_rewriter.rewrite(&cst2).applied_count, 0);

        let src_with_bom = format!("\u{FEFF}({LF}set X=1{LF}echo %X%{LF})");
        let cst_bom = parse_script_cst(SourceId(0), &src_with_bom, ExecutionContext::BatchFile);
        let out_bom = safe_rewriter.rewrite(&cst_bom);
        assert!(
            out_bom
                .rewritten_source
                .starts_with(&format!("\u{FEFF}SETLOCAL EnableDelayedExpansion{LF}"))
        );

        // Safe mode MUST NOT inject `SETLOCAL EnableDelayedExpansion` when literal `!` exists!
        let bang_src = [
            "@echo off",
            "echo Hello World!",
            "(",
            "  set X=1",
            "  echo %X%",
            ")",
            "exit 0",
        ]
        .join(CRLF);
        let cst_bang = parse_script_cst(SourceId(0), &bang_src, ExecutionContext::BatchFile);
        let safe_bang_out = safe_rewriter.rewrite(&cst_bang);
        assert!(
            !safe_bang_out
                .rewritten_source
                .contains("EnableDelayedExpansion")
        );
        // Safe mode also leaves `exit 0` untouched (does not inject `/B`)!
        assert!(safe_bang_out.rewritten_source.ends_with("exit 0"));

        // UnsafeOptIn mode applies both delayed expansion and `EXIT /B`
        let unsafe_rewriter = CstRewriter::default_for_context(ExecutionContext::BatchFile);
        let unsafe_bang_out = unsafe_rewriter.rewrite(&cst_bang);
        assert!(
            unsafe_bang_out
                .rewritten_source
                .contains("EnableDelayedExpansion")
        );
        assert!(unsafe_bang_out.rewritten_source.contains("exit /B 0"));
    }

    /// Verifies Pass 4 structural normalization, `^^`-safe `SET` quoting, `::` block conversion, and `ECHO(`.
    #[test]
    fn test_pass4_structural_double_caret_and_edge_cases() {
        let src = [
            "if (%A% = 1) echo yes else echo no",
            "for %%item (a b) echo %%item",
            "set FOO = bar   ",
            "set BAR=val   ",
            "set BAZ=a^&b",
            "set CARETS=a^^b",
            r#"set EMBED=a"b   "#,
            "(",
            "  :: comment in block",
            "  echo %MY_EMPTY_VAR%",
            ")",
            "echo line1 ^   ",
            "line2",
            &format!("cd D:{SEP}projects"),
            "helper.bat arg1",
            "exit 0",
        ]
        .join(CRLF);

        let cst = parse_script_cst(SourceId(0), &src, ExecutionContext::BatchFile);
        let rewriter = CstRewriter::default_for_context(ExecutionContext::BatchFile);
        let outcome = rewriter.rewrite(&cst);

        assert!(
            outcome
                .rewritten_source
                .contains(r#"if "%A%" == "1" (echo yes) ELSE (echo no)"#)
        );
        assert!(outcome.rewritten_source.contains("for %%i IN (a b) DO "));
        assert!(outcome.rewritten_source.contains(r#"set "FOO=bar""#));
        assert!(outcome.rewritten_source.contains(r#"set "BAR=val""#));
        assert!(outcome.rewritten_source.contains(r#"set "BAZ=a&b""#));
        // Escaped literal caret `^^` becomes single literal `^` inside `SET "CARETS=a^b"`!
        assert!(outcome.rewritten_source.contains(r#"set "CARETS=a^b""#));
        // Embedded quote `a"b` is NOT wrapped in corrupting outer quotes!
        assert!(outcome.rewritten_source.contains(r#"set EMBED=a"b"#));
        assert!(outcome.rewritten_source.contains("REM comment in block"));
        assert!(outcome.rewritten_source.contains("echo(%MY_EMPTY_VAR%"));
        assert!(
            outcome
                .rewritten_source
                .contains(&format!("cd /D D:{SEP}projects"))
        );
        assert!(outcome.rewritten_source.contains("CALL helper.bat arg1"));
        assert!(outcome.rewritten_source.contains("exit /B 0"));

        let expected_names = [
            ("DelayedExpansionBlockPass", "CMD2001"),
            ("StructuralSyntaxFixPass", "CMD1013"),
            ("ExecutionModePercentPass", "CMD1014"),
            ("QuoteUnquotedVariablesPass", "CMD2006"),
        ];
        for (pass, (exp_name, exp_rule)) in rewriter.passes.iter().zip(expected_names) {
            assert_eq!(pass.name(), exp_name);
            assert_eq!(pass.rule_id().as_str(), exp_rule);
        }

        let edge_src = [
            "if (1 == 1 echo half_paren",
            "if 1 == 1) echo close_only",
            "if 1==1 (echo a) else (echo b)",
            r#"if 1==1 echo "else""#,
            "if 1==1 echo else",
            "if 1==1 else echo empty_then",
            r#"for %foo in (a) do echo "%f""#,
            "for %I in (a) do copy %I %~I",
            "set",
            "set /p X=prompt",
            "set /aX=1",
            r#"set "ALREADY=1""#,
            "set =invalid",
            "set  = 1",
            "if errorlevel 1 echo err",
            "if 1 EQU 2 echo cmp",
            r#"if "a" EQU b echo eq_unq"#,
            "set PLAIN=1 > nul",
            "echo.dot",
            "echo a b",
            "echo ON",
            "echo literal_text",
            "cd",
            &format!("cd /d C:{SEP}ok"),
            "cd relative_dir",
            "exit /b 0",
            "(",
            "  set /p Y=prompt",
            "  set /aX=2",
            "  (",
            "    set Z=3",
            "    echo %X% %Z%",
            "  )",
            ")",
            "copy /y %* %VAR%^&tail",
            "if 1 == %RHS_VAR% echo rhs",
            r#"if "%LHS%" == rhs echo q_lhs"#,
            r#"if lhs == "%RHS%" echo q_rhs"#,
            "echo ok 2>&1",
        ]
        .join(CRLF);
        let cst_edge = parse_script_cst(SourceId(0), &edge_src, ExecutionContext::BatchFile);
        let out_edge = rewriter.rewrite(&cst_edge);
        assert!(out_edge.rewritten_source.contains(r#"set "PLAIN=1" > nul"#));
    }

    /// Verifies REPL percent rewriting, safe-mode branch edge cases, and no-op empty command nodes.
    #[test]
    fn test_repl_percent_and_safe_mode_branch_edges() {
        let repl_edge = [
            "for %%foo in (a) do echo %%i & echo 50%%",
            r#"for %i in (a) do echo "%i" & cd %i"#,
            "( set RX=1 & echo %RX% )",
            "exit 0",
        ]
        .join(CRLF);
        let repl_cst = parse_script_cst(SourceId(0), &repl_edge, ExecutionContext::InteractiveRepl);
        let repl_outcome =
            CstRewriter::default_for_context(ExecutionContext::InteractiveRepl).rewrite(&repl_cst);
        assert!(repl_outcome.rewritten_source.contains("for %f in (a) do "));
        assert!(
            repl_outcome
                .rewritten_source
                .contains(r#"echo "%~i" & cd "%~i""#)
        );
        assert!(repl_outcome.rewritten_source.contains("echo(!RX!"));
        assert!(
            !repl_outcome
                .rewritten_source
                .contains("EnableDelayedExpansion")
        );
        assert!(repl_outcome.rewritten_source.ends_with("exit 0"));

        let branch_edges = [
            r#"echo "%1 is missing""#,
            r#"echo "%*""#,
            "cd %~dp0%SUB%",
            "cd %*%SUB%",
            "(",
            "  set QUERY_ONLY",
            r#"  set "/A BLK_A=1""#,
            "  echo %BLK_A%",
            ")",
            r#"set EMBED_PLAIN=hello "world""#,
            r#"set "UNCLOSED=1"#,
            r#"set "FIRST=1" extra"#,
            "set QUERY_TOP",
            "set =empty_lhs_trailing   ",
            "if 1==1 set X=1 else set X=2",
        ]
        .join(CRLF);
        let safe_cst = parse_script_cst(SourceId(0), &branch_edges, ExecutionContext::BatchFile);
        let safe_outcome =
            CstRewriter::safe_for_context(ExecutionContext::BatchFile).rewrite(&safe_cst);
        assert!(
            safe_outcome
                .rewritten_source
                .contains(r#"echo "%1 is missing""#)
        );
        assert!(safe_outcome.rewritten_source.contains(r#"echo "%*""#));
        assert!(safe_outcome.rewritten_source.contains(r#"cd "%~dp0%SUB%""#));
        assert!(safe_outcome.rewritten_source.contains(r#"cd "%*%SUB%""#));
        assert!(safe_outcome.rewritten_source.contains("echo(!BLK_A!"));
        assert!(
            safe_outcome
                .rewritten_source
                .contains(r#"set EMBED_PLAIN=hello "world""#)
        );

        let empty_cmd = CstNode::new(SyntaxKind::SimpleCommand, Span::dummy(), Vec::new());
        let mut ctx = RewriteContext::new(SourceId(0), ExecutionContext::BatchFile);
        ctx.record_edit(
            RuleId::new("CMD2006"),
            "noop",
            Span::dummy(),
            "same".to_owned(),
            "same".to_owned(),
        );
        assert_eq!(
            DelayedExpansionBlockPass.rewrite_script(&empty_cmd, &mut ctx),
            empty_cmd
        );
        assert_eq!(
            StructuralSyntaxFixPass.rewrite_script(&empty_cmd, &mut ctx),
            empty_cmd
        );
        assert_eq!(
            QuoteUnquotedVariablesPass.rewrite_script(&empty_cmd, &mut ctx),
            empty_cmd
        );
        record_set_modified_vars_in_cst(&empty_cmd, &mut ctx);
        assert_eq!(ctx.applied_edits.len(), 0);
    }

    /// Verifies `min_severity` & `excluded_rules` filtering across all CST rewrite passes and
    /// `DelayedExpansionBlockPass` when `SETLOCAL EnableDelayedExpansion` is already present.
    #[test]
    fn test_rewriter_rule_exclusions_and_preexisting_delayed_expansion() {
        let already_delayed = format!(
            "@echo off{CRLF}setlocal EnableDelayedExpansion{CRLF}echo 100%%{CRLF}if 1==1 (echo blk){CRLF}({CRLF}  set A=1{CRLF}  echo %A%{CRLF}){CRLF}"
        );
        let sem_only = CstRewriter::semantics_preserving_for_context(ExecutionContext::BatchFile);
        let sem_cst = parse_script_cst(SourceId(0), &already_delayed, ExecutionContext::BatchFile);
        assert!(
            sem_only
                .rewrite(&sem_cst)
                .rewritten_source
                .contains("echo %A%")
        );

        let (ad_out, ad_edits) = crate::linter::rewrite_script(
            &already_delayed,
            ExecutionContext::BatchFile,
            &LinterConfig::default(),
        );
        assert!(ad_out.contains("echo(!A!"));
        assert_eq!(
            ad_out.matches("EnableDelayedExpansion").count(),
            1,
            "Should not inject a second SETLOCAL EnableDelayedExpansion"
        );
        assert!(ad_edits > 0);

        let all_rules_sample = [
            "@echo off",
            "for %I in (a) do echo %I 50%",
            "set X = 1   ",
            "set Y=a&b",
            "echo %USERPROFILE% \"%1\"",
            "if %USERPROFILE%==x echo q",
            "echo hi > %USERPROFILE%",
            "echo broken^   ",
            "cont",
            "(",
            "  :: block_colon",
            "  set A=1",
            "  echo %A%",
            ")",
            "if a = b echo eq",
            "cd D:/work",
            "helper.bat",
        ]
        .join(CRLF);
        let mut excl_cfg = LinterConfig {
            min_severity: crate::linter::Severity::Error,
            ..LinterConfig::default()
        };
        for code in [
            "CMD1001", "CMD1004", "CMD1005", "CMD1006", "CMD1007", "CMD1013", "CMD1014", "CMD2001",
            "CMD2002", "CMD2003", "CMD2004", "CMD2005", "CMD2006", "CMD2007", "CMD3001", "CMD3003",
            "CMD4001",
        ] {
            excl_cfg.excluded_rules.insert(RuleId::new(code));
        }
        let (unchanged_batch, batch_edits) = crate::linter::rewrite_script(
            &all_rules_sample,
            ExecutionContext::BatchFile,
            &excl_cfg,
        );
        assert_eq!(unchanged_batch, all_rules_sample);
        assert_eq!(batch_edits, 0);

        let repl_sample = "for %%I in (a) do echo %%I";
        let (unchanged_repl, repl_edits) = crate::linter::rewrite_script(
            repl_sample,
            ExecutionContext::InteractiveRepl,
            &excl_cfg,
        );
        assert_eq!(unchanged_repl, repl_sample);
        assert_eq!(repl_edits, 0);
    }

    /// Verifies `MsDosPortabilityPass` `CMD5004` `&` splitting, `CMD5006` `:EOF` footer, and idempotence.
    #[test]
    fn test_msdos_portability_pass_rewrites_and_idempotence() {
        let pass = BuiltinRewritePass::MsDosPortability(MsDosPortabilityPass);
        assert_eq!(pass.rule_id(), RuleId::new("CMD5006"));
        assert_eq!(pass.name(), "MsDosPortabilityPass");

        let dos_cfg = LinterConfig {
            dialect: crate::types::ShellDialect::MsDos622,
            ..LinterConfig::default()
        };
        let dos_src = format!(
            "echo a & echo b{CRLF}(echo in_blk & echo two){CRLF}echo c && echo d{CRLF}goto{CRLF}goto :EOF{CRLF}"
        );
        let (dos_rewritten, dos_edits) =
            crate::linter::rewrite_script(&dos_src, ExecutionContext::BatchFile, &dos_cfg);
        assert!(dos_edits >= 2);
        assert!(dos_rewritten.contains("goto EOF"));
        assert!(dos_rewritten.ends_with(&format!(":EOF{CRLF}")));

        let mut dos_excl = dos_cfg.clone();
        dos_excl.excluded_rules.insert(RuleId::new("CMD5004"));
        dos_excl.excluded_rules.insert(RuleId::new("CMD5006"));
        let (_, excl_edits) =
            crate::linter::rewrite_script(&dos_src, ExecutionContext::BatchFile, &dos_excl);
        assert_eq!(excl_edits, 0);

        let pre_eof = format!("goto :EOF{CRLF}:EOF{CRLF}");
        let (_, pre_edits) =
            crate::linter::rewrite_script(&pre_eof, ExecutionContext::BatchFile, &dos_cfg);
        assert_eq!(pre_edits, 0);

        let (dos_idempotent, second_edits) =
            crate::linter::rewrite_script(&dos_rewritten, ExecutionContext::BatchFile, &dos_cfg);
        assert_eq!(dos_idempotent, dos_rewritten);
        assert_eq!(second_edits, 0);

        let block_src = format!("({CRLF}  set A=1{CRLF}  echo %A%{CRLF}){CRLF}");
        let (dos_blk, _) =
            crate::linter::rewrite_script(&block_src, ExecutionContext::BatchFile, &dos_cfg);
        assert!(!dos_blk.contains("EnableDelayedExpansion"));
    }
}
