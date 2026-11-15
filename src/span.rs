//! Source location, byte offsets, line/column numbers, spans, and source map primitives.
//!
//! This module provides strongly typed location primitives used across the reader,
//! multi-pass expansion engine, parser, runtime interpreter, and static linter to
//! maintain exact byte-level provenance for every token and diagnostic.

use std::num::NonZeroUsize;

use derive_more::{Constructor, Deref, Display, From, Into};

/// A 0-indexed byte offset within a [`SourceFile`].
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Display,
    From,
    Into,
    Deref,
    Constructor,
)]
pub struct ByteOffset(
    /// The underlying 0-based byte index.
    pub usize,
);

impl ByteOffset {
    /// Returns the underlying `usize` value of this byte offset.
    ///
    /// # Returns
    /// The 0-based byte offset as a `usize`.
    #[must_use]
    pub const fn value(self) -> usize {
        self.0
    }

    /// Advances the byte offset by `delta` using saturating addition.
    ///
    /// # Arguments
    /// * `delta` - The number of bytes to advance forward.
    ///
    /// # Returns
    /// A new [`ByteOffset`] advanced by `delta`.
    #[must_use]
    pub const fn saturating_add(self, delta: usize) -> Self {
        Self(self.0.saturating_add(delta))
    }

    /// Subtracts `delta` from the byte offset using saturating subtraction.
    ///
    /// # Arguments
    /// * `delta` - The number of bytes to move backward.
    ///
    /// # Returns
    /// A new [`ByteOffset`] reduced by `delta` (clamped at 0).
    #[must_use]
    pub const fn saturating_sub(self, delta: usize) -> Self {
        Self(self.0.saturating_sub(delta))
    }
}

/// A 1-indexed physical line number within a [`SourceFile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display, From, Into, Deref)]
pub struct LineNumber(
    /// The underlying 1-based line number.
    pub NonZeroUsize,
);

impl LineNumber {
    /// Creates a new [`LineNumber`] from a 1-based index, clamping `0` to `1`.
    ///
    /// # Arguments
    /// * `one_based` - The 1-based line number (if `0` is passed, it is treated as `1`).
    ///
    /// # Returns
    /// A validated [`LineNumber`].
    #[must_use]
    pub const fn from_one_based(one_based: usize) -> Self {
        match NonZeroUsize::new(one_based) {
            Some(nz) => Self(nz),
            None => Self(NonZeroUsize::MIN),
        }
    }

    /// Returns the 1-based line number as a `usize`.
    ///
    /// # Returns
    /// The 1-based line index.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

/// A 1-indexed UTF-8 character column number within a physical line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display, From, Into, Deref)]
pub struct ColumnNumber(
    /// The underlying 1-based character column number.
    pub NonZeroUsize,
);

impl ColumnNumber {
    /// Creates a new [`ColumnNumber`] from a 1-based index, clamping `0` to `1`.
    ///
    /// # Arguments
    /// * `one_based` - The 1-based column number (if `0` is passed, it is treated as `1`).
    ///
    /// # Returns
    /// A validated [`ColumnNumber`].
    #[must_use]
    pub const fn from_one_based(one_based: usize) -> Self {
        match NonZeroUsize::new(one_based) {
            Some(nz) => Self(nz),
            None => Self(NonZeroUsize::MIN),
        }
    }

    /// Returns the 1-based column number as a `usize`.
    ///
    /// # Returns
    /// The 1-based column index.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

/// A unique identifier for a loaded [`SourceFile`] inside a [`SourceMap`].
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Display,
    From,
    Into,
    Deref,
    Constructor,
)]
pub struct SourceId(
    /// The 0-based index of the source file in the [`SourceMap`].
    pub u32,
);

/// A contiguous half-open byte range `[start, end)` within a specific [`SourceFile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
#[display("{source_id}:{start}..{end}")]
pub struct Span {
    /// Identifier of the source buffer containing this span.
    pub source_id: SourceId,
    /// Inclusive starting byte offset.
    pub start: ByteOffset,
    /// Exclusive ending byte offset.
    pub end: ByteOffset,
}

impl Span {
    /// Constructs a new [`Span`], normalizing `end` so that `end >= start`.
    ///
    /// # Arguments
    /// * `source_id` - The [`SourceId`] of the file or buffer.
    /// * `start` - The inclusive start [`ByteOffset`].
    /// * `end` - The exclusive end [`ByteOffset`].
    ///
    /// # Returns
    /// A normalized [`Span`].
    #[must_use]
    pub const fn new(source_id: SourceId, start: ByteOffset, end: ByteOffset) -> Self {
        let normalized_end = if end.0 < start.0 { start } else { end };
        Self {
            source_id,
            start,
            end: normalized_end,
        }
    }

    /// Constructs a dummy zero-length [`Span`] at offset 0 of [`SourceId`] `0`.
    ///
    /// # Returns
    /// A synthetic [`Span`] for internal or non-source-backed states.
    #[must_use]
    pub const fn dummy() -> Self {
        Self {
            source_id: SourceId(0),
            start: ByteOffset(0),
            end: ByteOffset(0),
        }
    }

    /// Merges two spans into a single span covering both ranges.
    ///
    /// # Arguments
    /// * `other` - The other [`Span`] to merge with `self`.
    ///
    /// # Returns
    /// A [`Span`] spanning from `min(self.start, other.start)` to `max(self.end, other.end)`.
    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        let start = if self.start.0 < other.start.0 {
            self.start
        } else {
            other.start
        };
        let end = if self.end.0 > other.end.0 {
            self.end
        } else {
            other.end
        };
        Self {
            source_id: self.source_id,
            start,
            end,
        }
    }

    /// Returns the length of this span in bytes.
    ///
    /// # Returns
    /// The byte length `end - start`.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end.0.saturating_sub(self.start.0)
    }

    /// Checks whether the span has zero byte length.
    ///
    /// # Returns
    /// `true` if `start == end`, otherwise `false`.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Checks whether the given [`ByteOffset`] falls within `[start, end)`.
    ///
    /// # Arguments
    /// * `offset` - The [`ByteOffset`] to test.
    ///
    /// # Returns
    /// `true` if `start <= offset < end` (or `offset == start` when empty).
    #[must_use]
    pub const fn contains(self, offset: ByteOffset) -> bool {
        if self.is_empty() {
            offset.0 == self.start.0
        } else {
            offset.0 >= self.start.0 && offset.0 < self.end.0
        }
    }
}

/// A human-readable resolved source location with 1-based line and column coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
#[display("{file_name}:{start_line}:{start_col}")]
pub struct ResolvedSpan {
    /// Display name or file path of the source buffer.
    pub file_name: String,
    /// 1-based starting line number.
    pub start_line: LineNumber,
    /// 1-based starting column number.
    pub start_col: ColumnNumber,
    /// 1-based ending line number.
    pub end_line: LineNumber,
    /// 1-based ending column number.
    pub end_col: ColumnNumber,
}

/// Classification of physical line endings observed in a [`SourceFile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum LineEndingStyle {
    /// All line endings use Windows `CRLF`.
    #[display("CRLF")]
    CrLf,
    /// All line endings use Unix `LF`.
    #[display("LF")]
    Lf,
    /// All line endings use legacy `CR`.
    #[display("CR")]
    Cr,
    /// A mixture of different line-ending conventions was detected.
    #[display("Mixed(CRLF={crlf_count}, LF={lf_count}, CR={cr_count})")]
    Mixed {
        /// Count of `CRLF` sequences.
        crlf_count: usize,
        /// Count of standalone `LF` sequences.
        lf_count: usize,
        /// Count of standalone `CR` sequences.
        cr_count: usize,
    },
    /// No line endings were present in the file (single-line or empty buffer).
    #[display("None")]
    None,
}

impl LineEndingStyle {
    /// Detects the [`LineEndingStyle`] of a decoded text string.
    ///
    /// # Arguments
    /// * `text` - The text slice to inspect for `CRLF`, `LF`, and `CR`.
    ///
    /// # Returns
    /// The detected [`LineEndingStyle`].
    #[must_use]
    pub fn detect(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut crlf_count: usize = 0;
        let mut lf_count: usize = 0;
        let mut cr_count: usize = 0;
        let mut idx: usize = 0;

        while let Some(&byte) = bytes.get(idx) {
            if byte == 0x0D {
                if bytes.get(idx.saturating_add(1)) == Some(&0x0A) {
                    crlf_count = crlf_count.saturating_add(1);
                    idx = idx.saturating_add(2);
                } else {
                    cr_count = cr_count.saturating_add(1);
                    idx = idx.saturating_add(1);
                }
            } else if byte == 0x0A {
                lf_count = lf_count.saturating_add(1);
                idx = idx.saturating_add(1);
            } else {
                idx = idx.saturating_add(1);
            }
        }

        let mask = u8::from(crlf_count > 0)
            | (u8::from(lf_count > 0) << 1)
            | (u8::from(cr_count > 0) << 2);
        match mask {
            0 => Self::None,
            1 => Self::CrLf,
            2 => Self::Lf,
            4 => Self::Cr,
            _ => Self::Mixed {
                crlf_count,
                lf_count,
                cr_count,
            },
        }
    }
}

/// Detects the byte length of any leading UTF-8 or UTF-16 Byte Order Mark in `raw_bytes`.
///
/// # Arguments
/// * `raw_bytes` - Raw undecoded byte slice of the source file.
///
/// # Returns
/// `3` for UTF-8 BOM (`EF BB BF`), `2` for UTF-16LE (`FF FE`) or UTF-16BE (`FE FF`), or `0` otherwise.
#[must_use]
pub const fn detect_bom_byte_len(raw_bytes: &[u8]) -> usize {
    match raw_bytes {
        [0xEF, 0xBB, 0xBF, ..] => 3,
        [0xFF, 0xFE, ..] | [0xFE, 0xFF, ..] => 2,
        _ => 0,
    }
}

/// A loaded source file or interactive buffer with precomputed line-start offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    /// Unique identifier for this source buffer.
    pub id: SourceId,
    /// Display name or virtual path of the file.
    pub name: String,
    /// Original raw bytes prior to decoding.
    pub raw_bytes: Vec<u8>,
    /// Decoded UTF-8 text of the source buffer.
    pub decoded_text: String,
    /// Sorted list of byte offsets where each physical line starts (always begins with `0`).
    pub line_starts: Vec<ByteOffset>,
    /// Detected line-ending style of the source file.
    pub line_ending_style: LineEndingStyle,
    /// Whether the raw bytes began with a UTF-8 Byte Order Mark (`EF BB BF`).
    pub has_utf8_bom: bool,
    /// Length in bytes of any leading BOM (`0`, `2`, or `3`) stripped from `decoded_text`.
    pub bom_byte_len: usize,
}

impl SourceFile {
    /// Constructs a new [`SourceFile`] from a name, raw bytes, and decoded text.
    ///
    /// # Arguments
    /// * `id` - Unique [`SourceId`] assigned by the [`SourceMap`].
    /// * `name` - File path or buffer name.
    /// * `raw_bytes` - Raw byte vector as read from disk or input stream.
    /// * `decoded_text` - Decoded UTF-8 representation of `raw_bytes`.
    ///
    /// # Returns
    /// A populated [`SourceFile`] with computed line starts, BOM length, and line-ending metadata.
    #[must_use]
    pub fn new(id: SourceId, name: String, raw_bytes: Vec<u8>, decoded_text: String) -> Self {
        let bom_byte_len = detect_bom_byte_len(&raw_bytes);
        let has_utf8_bom = bom_byte_len == 3;
        let line_ending_style = LineEndingStyle::detect(&decoded_text);
        let mut line_starts = vec![ByteOffset(0)];
        for (idx, byte) in decoded_text.bytes().enumerate() {
            if byte == 0x0A {
                line_starts.push(ByteOffset(idx.saturating_add(1)));
            }
        }
        Self {
            id,
            name,
            raw_bytes,
            decoded_text,
            line_starts,
            line_ending_style,
            has_utf8_bom,
            bom_byte_len,
        }
    }

    /// Translates a decoded-buffer [`ByteOffset`] to a physical file byte offset accounting for BOM bytes.
    ///
    /// # Arguments
    /// * `decoded_offset` - Byte offset relative to the start of `decoded_text`.
    ///
    /// # Returns
    /// Physical [`ByteOffset`] shifted by `self.bom_byte_len`.
    #[must_use]
    pub const fn raw_byte_offset(&self, decoded_offset: ByteOffset) -> ByteOffset {
        decoded_offset.saturating_add(self.bom_byte_len)
    }

    /// Resolves a single [`ByteOffset`] into a 1-based `(LineNumber, ColumnNumber)` pair.
    ///
    /// # Arguments
    /// * `offset` - The byte offset within `decoded_text`.
    ///
    /// # Returns
    /// A tuple `(LineNumber, ColumnNumber)` corresponding to `offset`.
    #[must_use]
    pub fn line_col(&self, offset: ByteOffset) -> (LineNumber, ColumnNumber) {
        let clamped = offset.0.min(self.decoded_text.len());
        let line_idx = match self.line_starts.binary_search(&ByteOffset(clamped)) {
            Ok(exact) => exact,
            Err(insert_pos) => insert_pos.saturating_sub(1),
        };
        let line_start = self
            .line_starts
            .get(line_idx)
            .copied()
            .unwrap_or(ByteOffset(0));
        let col_chars = self
            .decoded_text
            .get(line_start.0..clamped)
            .map_or(0, |slice| slice.chars().count());
        (
            LineNumber::from_one_based(line_idx.saturating_add(1)),
            ColumnNumber::from_one_based(col_chars.saturating_add(1)),
        )
    }

    /// Resolves a [`Span`] into a [`ResolvedSpan`] with start and end line/column numbers.
    ///
    /// # Arguments
    /// * `span` - The [`Span`] to resolve against this file.
    ///
    /// # Returns
    /// A [`ResolvedSpan`] containing the file name and 1-based coordinates.
    #[must_use]
    pub fn resolve_span(&self, span: Span) -> ResolvedSpan {
        let (start_line, start_col) = self.line_col(span.start);
        let (end_line, end_col) = self.line_col(span.end);
        ResolvedSpan {
            file_name: self.name.clone(),
            start_line,
            start_col,
            end_line,
            end_col,
        }
    }

    /// Returns the text of the 1-based physical line `line_number` (without trailing `CR` or `LF`).
    ///
    /// # Arguments
    /// * `line_number` - The 1-based [`LineNumber`] to retrieve.
    ///
    /// # Returns
    /// `Some(&str)` containing the line content if `line_number` exists, or `None` if out of bounds.
    #[must_use]
    pub fn line_text(&self, line_number: LineNumber) -> Option<&str> {
        let idx = line_number.get().saturating_sub(1);
        let start = self.line_starts.get(idx)?.0;
        let end = self
            .line_starts
            .get(idx.saturating_add(1))
            .map_or(self.decoded_text.len(), |next| next.0);
        let raw_line = self.decoded_text.get(start..end).unwrap_or("");
        Some(raw_line.trim_end_matches([crate::types::CR_CHAR, crate::types::LF_CHAR]))
    }
}

/// Registry of loaded [`SourceFile`] buffers indexed by [`SourceId`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceMap {
    /// Ordered collection of source files where index matches [`SourceId`].
    files: Vec<SourceFile>,
}

impl SourceMap {
    /// Creates an empty [`SourceMap`].
    ///
    /// # Returns
    /// A new [`SourceMap`].
    #[must_use]
    pub const fn new() -> Self {
        Self { files: Vec::new() }
    }

    /// Returns the number of registered [`SourceFile`] slots in this [`SourceMap`].
    ///
    /// # Returns
    /// Total count of allocated [`SourceFile`] slots.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.files.len()
    }

    /// Checks whether the [`SourceMap`] contains zero [`SourceFile`] slots.
    ///
    /// # Returns
    /// `true` if `len() == 0`, otherwise `false`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Returns the [`SourceId`] that will be assigned to the next appended [`SourceFile`].
    ///
    /// # Returns
    /// Next sequential [`SourceId`].
    #[must_use]
    pub fn next_source_id(&self) -> SourceId {
        let next_idx = u32::try_from(self.files.len()).unwrap_or(u32::MAX);
        SourceId(next_idx)
    }

    /// Appends a pre-built [`SourceFile`] into this [`SourceMap`] and returns its [`SourceId`].
    ///
    /// # Arguments
    /// * `file` - Pre-constructed [`SourceFile`] whose `id` matches [`Self::next_source_id`].
    ///
    /// # Returns
    /// The registered [`SourceId`].
    pub fn push_source_file(&mut self, file: SourceFile) -> SourceId {
        let id = file.id;
        self.files.push(file);
        id
    }

    /// Registers a new source file in the map and returns its assigned [`SourceId`].
    ///
    /// # Arguments
    /// * `name` - Display name or path of the source buffer.
    /// * `raw_bytes` - Raw undecoded byte content.
    /// * `decoded_text` - Decoded UTF-8 string content.
    ///
    /// # Returns
    /// The newly allocated [`SourceId`].
    pub fn add_file(&mut self, name: String, raw_bytes: Vec<u8>, decoded_text: String) -> SourceId {
        let id = self.next_source_id();
        let file = SourceFile::new(id, name, raw_bytes, decoded_text);
        self.push_source_file(file)
    }

    /// Replaces or updates the latest interactive/ephemeral buffer slot when `id` exists,
    /// avoiding unbounded growth during long-running REPL or loop sessions.
    ///
    /// # Arguments
    /// * `id` - Existing [`SourceId`] slot to update.
    /// * `name` - Display name or path of the source buffer.
    /// * `raw_bytes` - Raw undecoded byte content.
    /// * `decoded_text` - Decoded UTF-8 string content.
    ///
    /// # Returns
    /// `true` if `id` existed and was updated in place, or `false` if `id` was out of bounds.
    pub fn replace_file(
        &mut self,
        id: SourceId,
        name: String,
        raw_bytes: Vec<u8>,
        decoded_text: String,
    ) -> bool {
        self.files.get_mut(id.0 as usize).is_some_and(|slot| {
            *slot = SourceFile::new(id, name, raw_bytes, decoded_text);
            true
        })
    }

    /// Retrieves a reference to a [`SourceFile`] by its [`SourceId`].
    ///
    /// # Arguments
    /// * `id` - The [`SourceId`] to look up.
    ///
    /// # Returns
    /// `Some(&SourceFile)` if found, or `None` if `id` is out of bounds.
    #[must_use]
    pub fn get_file(&self, id: SourceId) -> Option<&SourceFile> {
        self.files.get(id.0 as usize)
    }

    /// Resolves a [`Span`] using the underlying [`SourceFile`] in the map.
    ///
    /// # Arguments
    /// * `span` - The [`Span`] to resolve.
    ///
    /// # Returns
    /// A [`ResolvedSpan`] (using `"<unknown>"` and `1:1` if the [`SourceId`] is not registered).
    #[must_use]
    pub fn resolve_span(&self, span: Span) -> ResolvedSpan {
        self.get_file(span.source_id).map_or_else(
            || ResolvedSpan {
                file_name: "<unknown>".to_owned(),
                start_line: LineNumber::from_one_based(1),
                start_col: ColumnNumber::from_one_based(1),
                end_line: LineNumber::from_one_based(1),
                end_col: ColumnNumber::from_one_based(1),
            },
            |file| file.resolve_span(span),
        )
    }
}

#[cfg(test)]
/// Unit tests for [`ByteOffset`], [`LineNumber`], [`ColumnNumber`], [`Span`], and [`SourceMap`].
mod tests {
    use super::*;

    /// Verifies [`ByteOffset`] dereferencing and saturating arithmetic.
    #[test]
    fn test_byte_offset_operations() {
        let offset = ByteOffset::new(10);
        assert_eq!(offset.value(), 10);
        assert_eq!(*offset, 10);
        assert_eq!(offset.saturating_add(5), ByteOffset(15));
        assert_eq!(offset.saturating_sub(3), ByteOffset(7));
        assert_eq!(offset.saturating_sub(25), ByteOffset(0));
    }

    /// Verifies 1-based clamping on [`LineNumber`] and [`ColumnNumber`].
    #[test]
    fn test_line_and_column_number() {
        let line0 = LineNumber::from_one_based(0);
        assert_eq!(line0.get(), 1);
        let line5 = LineNumber::from_one_based(5);
        assert_eq!(line5.get(), 5);

        let col0 = ColumnNumber::from_one_based(0);
        assert_eq!(col0.get(), 1);
        let col8 = ColumnNumber::from_one_based(8);
        assert_eq!(col8.get(), 8);
    }

    /// Verifies [`Span`] clamping, containment, length, and merging.
    #[test]
    fn test_span_methods() {
        let dummy = Span::dummy();
        assert!(dummy.is_empty());
        assert_eq!(dummy.len(), 0);
        assert!(dummy.contains(ByteOffset(0)));
        assert!(!dummy.contains(ByteOffset(1)));

        let reversed = Span::new(SourceId(1), ByteOffset(10), ByteOffset(5));
        assert_eq!(reversed.start, ByteOffset(10));
        assert_eq!(reversed.end, ByteOffset(10));

        let s1 = Span::new(SourceId(1), ByteOffset(2), ByteOffset(6));
        let s2 = Span::new(SourceId(1), ByteOffset(4), ByteOffset(12));
        let s3 = Span::new(SourceId(1), ByteOffset(1), ByteOffset(3));
        assert_eq!(s1.len(), 4);
        assert!(!s1.is_empty());
        assert!(s1.contains(ByteOffset(2)));
        assert!(s1.contains(ByteOffset(5)));
        assert!(!s1.contains(ByteOffset(6)));
        assert!(!s1.contains(ByteOffset(1)));

        let merged = s1.merge(s2);
        assert_eq!(merged.start, ByteOffset(2));
        assert_eq!(merged.end, ByteOffset(12));
        assert_eq!(merged.to_string(), "1:2..12");

        let merged_rev = s2.merge(s3);
        assert_eq!(merged_rev.start, ByteOffset(1));
        assert_eq!(merged_rev.end, ByteOffset(12));
    }

    /// Verifies [`LineEndingStyle`] detection across `CRLF`, `LF`, `CR`, `Mixed`, and `None`.
    #[test]
    fn test_line_ending_detection_and_display() {
        let cr = crate::types::CR_CHAR;
        let lf = crate::types::LF_CHAR;
        assert_eq!(LineEndingStyle::detect(""), LineEndingStyle::None);
        assert_eq!(LineEndingStyle::None.to_string(), "None");
        assert_eq!(LineEndingStyle::detect("echo hi"), LineEndingStyle::None);
        assert_eq!(
            LineEndingStyle::detect(&format!("echo a{cr}{lf}echo b{cr}{lf}")),
            LineEndingStyle::CrLf
        );
        assert_eq!(LineEndingStyle::CrLf.to_string(), "CRLF");
        assert_eq!(
            LineEndingStyle::detect(&format!("echo a{lf}echo b{lf}")),
            LineEndingStyle::Lf
        );
        assert_eq!(LineEndingStyle::Lf.to_string(), "LF");
        assert_eq!(
            LineEndingStyle::detect(&format!("echo a{cr}echo b{cr}")),
            LineEndingStyle::Cr
        );
        assert_eq!(LineEndingStyle::Cr.to_string(), "CR");
        let mixed = LineEndingStyle::detect(&format!("echo a{cr}{lf}echo b{lf}echo c{cr}"));
        assert_eq!(
            mixed,
            LineEndingStyle::Mixed {
                crlf_count: 1,
                lf_count: 1,
                cr_count: 1
            }
        );
        assert_eq!(mixed.to_string(), "Mixed(CRLF=1, LF=1, CR=1)");
    }

    /// Verifies BOM-aware [`SourceFile`] offset mapping and ring-buffered [`SourceMap`] eviction.
    #[test]
    fn test_source_file_bom_and_source_map() {
        let cr = crate::types::CR_CHAR;
        let lf = crate::types::LF_CHAR;
        assert_eq!(detect_bom_byte_len(&[]), 0);
        assert_eq!(detect_bom_byte_len(b"echo"), 0);
        assert_eq!(detect_bom_byte_len(&[0xEF, 0xBB, 0xBF, b'a']), 3);
        assert_eq!(detect_bom_byte_len(&[0xFF, 0xFE, b'a', 0]), 2);
        assert_eq!(detect_bom_byte_len(&[0xFE, 0xFF, 0, b'a']), 2);

        let mut map = SourceMap::new();
        let text = format!("@echo off{cr}{lf}set x=1{cr}{lf}echo %x%");
        let mut raw = vec![0xEF, 0xBB, 0xBF];
        raw.extend_from_slice(text.as_bytes());
        let id = map.add_file("test.bat".to_owned(), raw, text);

        assert_eq!(map.get_file(id).map(|f| f.has_utf8_bom), Some(true));
        assert_eq!(map.get_file(id).map(|f| f.bom_byte_len), Some(3));
        assert_eq!(
            map.get_file(id).map(|f| f.raw_byte_offset(ByteOffset(11))),
            Some(ByteOffset(14))
        );
        assert_eq!(
            map.get_file(id).map(|f| f.line_ending_style),
            Some(LineEndingStyle::CrLf)
        );
        assert_eq!(
            map.get_file(id)
                .and_then(|f| f.line_text(LineNumber::from_one_based(1))),
            Some("@echo off")
        );
        assert_eq!(
            map.get_file(id)
                .and_then(|f| f.line_text(LineNumber::from_one_based(2))),
            Some("set x=1")
        );
        assert_eq!(
            map.get_file(id)
                .and_then(|f| f.line_text(LineNumber::from_one_based(3))),
            Some("echo %x%")
        );
        assert_eq!(
            map.get_file(id)
                .and_then(|f| f.line_text(LineNumber::from_one_based(4))),
            None
        );
        assert_eq!(
            map.get_file(id).map(|f| f.line_col(ByteOffset(0))),
            Some((
                LineNumber::from_one_based(1),
                ColumnNumber::from_one_based(1)
            ))
        );
        assert_eq!(
            map.get_file(id).map(|f| f.line_col(ByteOffset(11))),
            Some((
                LineNumber::from_one_based(2),
                ColumnNumber::from_one_based(1)
            ))
        );
        let expected_l2_c5 = Some((
            LineNumber::from_one_based(2),
            ColumnNumber::from_one_based(5),
        ));
        assert_eq!(
            map.get_file(id).map(|f| f.line_col(ByteOffset(15))),
            expected_l2_c5
        );

        let resolved = map.resolve_span(Span::new(id, ByteOffset(11), ByteOffset(18)));
        assert_eq!(resolved.to_string(), "test.bat:2:1");

        let unknown_resolved =
            map.resolve_span(Span::new(SourceId(99), ByteOffset(0), ByteOffset(2)));
        assert_eq!(unknown_resolved.to_string(), "<unknown>:1:1");

        assert!(map.replace_file(
            id,
            "updated.bat".to_owned(),
            b"rem hi".to_vec(),
            "rem hi".to_owned()
        ));
        assert_eq!(
            map.get_file(id)
                .and_then(|f| f.line_text(LineNumber::from_one_based(1))),
            Some("rem hi")
        );
        assert!(!map.replace_file(
            SourceId(99),
            "missing.bat".to_owned(),
            Vec::new(),
            String::new()
        ));
        assert!(!map.is_empty());
        assert_eq!(map.len(), 1);
        assert!(SourceMap::new().is_empty());
    }
}
