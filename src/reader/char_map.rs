//! Physical-to-logical character mapping and expansion provenance tracking.
//!
//! Every character processed by Phase 0 through Phase 4 carries a [`SpannedChar`]
//! descriptor recording its original [`Span`] in the physical file, whether it was
//! escaped by a caret (`^`), and which expansion pass produced it.

use derive_more::{Display, IsVariant};

use crate::span::{ByteOffset, SourceId, Span};
use crate::types::{EnvVarName, ForVarName};

/// Controls whether sub-word CST token parts are materialized during runtime lexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum ProvenanceMode {
    /// Materialize full sub-word [`crate::parser::cst::CstToken`] slices for static analysis.
    #[default]
    #[display("full")]
    Full,
    /// Skip sub-word CST token allocation during pure interpreter execution.
    #[display("compact")]
    Compact,
}

/// Provenance of a character inside a [`LogicalLineBuffer`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExpansionOrigin {
    /// Character came directly from the physical script file.
    LiteralSource,
    /// Character was joined across a physical line break via a trailing `^`.
    CaretContinuation {
        /// Span of the trailing `^` character.
        caret_span: Span,
        /// Span of the consumed newline (`CR`, `LF`, or `CRLF`).
        newline_span: Span,
    },
    /// Character was produced by expanding a batch positional parameter (`%0`..`%9`, `%*`).
    PositionalParam {
        /// Span of the `%n` or `%*` token in the source.
        param_span: Span,
        /// Parameter index (`0..=9`, or `255` for `%*`).
        index: u8,
    },
    /// Character was produced by Phase 1 immediate `%VAR%` expansion.
    ImmediateEnvVar {
        /// Span of the `%VAR%` reference in the source.
        var_span: Span,
        /// Name of the expanded environment variable.
        var_name: EnvVarName,
    },
    /// Character was produced by Phase 3 `FOR` loop variable expansion (`%%I`).
    ForVariable {
        /// Span of the `%%I` / `%I` token.
        token_span: Span,
        /// The `FOR` variable token name.
        var: ForVarName,
    },
    /// Character was produced by Phase 4 delayed `!VAR!` expansion.
    DelayedEnvVar {
        /// Span of the `!VAR!` reference.
        var_span: Span,
        /// Name of the expanded environment variable.
        var_name: EnvVarName,
    },
}

/// A single character paired with its source [`Span`], caret-escape status, and [`ExpansionOrigin`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpannedChar {
    /// The Unicode character.
    pub ch: char,
    /// Source span in the physical file.
    pub span: Span,
    /// Whether this character was immediately preceded by an unquoted `^` escape.
    pub escaped_by_caret: bool,
    /// Expansion pass that produced this character.
    pub origin: ExpansionOrigin,
}

impl SpannedChar {
    /// Constructs a literal unescaped [`SpannedChar`] from source text.
    ///
    /// # Arguments
    /// * `ch` - The literal character.
    /// * `span` - The physical [`Span`] of `ch`.
    ///
    /// # Returns
    /// A new [`SpannedChar`] with [`ExpansionOrigin::LiteralSource`].
    #[must_use]
    pub const fn literal(ch: char, span: Span) -> Self {
        Self {
            ch,
            span,
            escaped_by_caret: false,
            origin: ExpansionOrigin::LiteralSource,
        }
    }

    /// Returns `Some(self.ch)` when this character was not escaped by a caret, or `None` when escaped.
    ///
    /// # Returns
    /// `Some(char)` if unescaped, or `None` if `self.escaped_by_caret` is `true`.
    #[must_use]
    pub const fn raw_char(&self) -> Option<char> {
        if self.escaped_by_caret {
            None
        } else {
            Some(self.ch)
        }
    }

    /// Checks whether this character is unescaped and equal to `expected`.
    ///
    /// # Arguments
    /// * `expected` - Target character to match.
    ///
    /// # Returns
    /// `true` if unescaped and `self.ch == expected`.
    #[must_use]
    pub const fn is_raw(&self, expected: char) -> bool {
        !self.escaped_by_caret && self.ch == expected
    }
}

/// A buffer of [`SpannedChar`] items representing a logical line across expansion phases.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogicalLineBuffer {
    /// Sequence of spanned characters in this logical line.
    pub chars: Vec<SpannedChar>,
    /// Optional span of a trailing `^` followed by whitespace before EOL (for linter rule `CMD1004`).
    pub broken_caret_span: Option<Span>,
}

impl LogicalLineBuffer {
    /// Creates an empty [`LogicalLineBuffer`].
    ///
    /// # Returns
    /// An empty [`LogicalLineBuffer`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            chars: Vec::new(),
            broken_caret_span: None,
        }
    }

    /// Creates a [`LogicalLineBuffer`] from a plain string slice with synthetic byte offsets.
    ///
    /// # Arguments
    /// * `source_id` - The [`SourceId`] to assign to each character span.
    /// * `base_offset` - Starting [`ByteOffset`] of `text` within the source file.
    /// * `text` - The input UTF-8 string slice.
    ///
    /// # Returns
    /// A populated [`LogicalLineBuffer`].
    #[must_use]
    pub fn from_str_at(source_id: SourceId, base_offset: ByteOffset, text: &str) -> Self {
        let chars = text
            .char_indices()
            .map(|(rel_idx, ch)| {
                let start = base_offset.saturating_add(rel_idx);
                let end = start.saturating_add(ch.len_utf8());
                SpannedChar::literal(ch, Span::new(source_id, start, end))
            })
            .collect();
        Self {
            chars,
            broken_caret_span: None,
        }
    }

    /// Collects the characters of this buffer into a plain `String`.
    ///
    /// # Returns
    /// The concatenated `String` of all [`SpannedChar::ch`] values.
    #[must_use]
    pub fn to_plain_string(&self) -> String {
        self.chars.iter().map(|sc| sc.ch).collect()
    }

    /// Computes the bounding [`Span`] covering all characters in this buffer.
    ///
    /// # Arguments
    /// * `fallback_source` - [`SourceId`] to use if the buffer is empty.
    /// * `fallback_offset` - [`ByteOffset`] to use if the buffer is empty.
    ///
    /// # Returns
    /// The merged [`Span`] from the first character to the last character.
    #[must_use]
    pub fn full_span(&self, fallback_source: SourceId, fallback_offset: ByteOffset) -> Span {
        match (self.chars.first(), self.chars.last()) {
            (Some(first), Some(last)) => first.span.merge(last.span),
            _ => Span::new(fallback_source, fallback_offset, fallback_offset),
        }
    }

    /// Computes the bounding [`Span`] for a subslice of `chars` in `[start_idx..end_idx)`.
    ///
    /// # Arguments
    /// * `start_idx` - Inclusive start index in `self.chars`.
    /// * `end_idx` - Exclusive end index in `self.chars`.
    ///
    /// # Returns
    /// `Some(Span)` if the range is non-empty and within bounds, otherwise `None`.
    #[must_use]
    pub fn slice_span(&self, start_idx: usize, end_idx: usize) -> Option<Span> {
        let slice = self.chars.get(start_idx..end_idx)?;
        let first = slice.first()?;
        let last = slice.last().unwrap_or(first);
        Some(first.span.merge(last.span))
    }
}

#[cfg(test)]
/// Unit tests for [`LogicalLineBuffer`], [`SpannedChar`], and [`ProvenanceMode`].
mod tests {
    use super::*;

    /// Verifies [`ProvenanceMode`] helpers and [`LogicalLineBuffer`] span/string conversions.
    #[test]
    fn test_logical_line_buffer_and_provenance_mode() {
        assert_eq!(ProvenanceMode::default(), ProvenanceMode::Full);
        assert!(ProvenanceMode::Full.is_full());
        assert!(ProvenanceMode::Compact.is_compact());
        assert_eq!(ProvenanceMode::Full.to_string(), "full");
        assert_eq!(ProvenanceMode::Compact.to_string(), "compact");

        let empty = LogicalLineBuffer::new();
        assert_eq!(empty.to_plain_string(), "");
        assert_eq!(
            empty.full_span(SourceId(2), ByteOffset(5)),
            Span::new(SourceId(2), ByteOffset(5), ByteOffset(5))
        );
        assert_eq!(empty.slice_span(0, 1), None);

        let buf = LogicalLineBuffer::from_str_at(SourceId(1), ByteOffset(10), "echo hi");
        assert_eq!(buf.to_plain_string(), "echo hi");
        assert_eq!(
            buf.full_span(SourceId(1), ByteOffset(0)),
            Span::new(SourceId(1), ByteOffset(10), ByteOffset(17))
        );
        assert_eq!(
            buf.slice_span(0, 4),
            Some(Span::new(SourceId(1), ByteOffset(10), ByteOffset(14)))
        );
        assert_eq!(buf.slice_span(4, 4), None);

        let lit = SpannedChar::literal('x', Span::dummy());
        assert_eq!(lit.raw_char(), Some('x'));
        assert!(lit.is_raw('x'));
        assert!(!lit.is_raw('y'));
        let mut esc = lit;
        esc.escaped_by_caret = true;
        assert_eq!(esc.raw_char(), None);
        assert!(!esc.is_raw('x'));
    }
}
