//! Byte-offset script stream reader and caret (`^`) line-continuation processor.
//!
//! `cmd.exe` reads batch scripts by maintaining a physical byte offset cursor, reading one
//! logical line or compound block at a time, and re-reading from the byte cursor on each step.
//! This module implements both raw-byte incremental reading (supporting live mid-script `CHCP`
//! switches and self-modifying batch scripts) and UTF-8 buffer reading, along with quote-aware
//! caret continuation, trailing-whitespace-after-caret detection (`CMD1004`), `,`/`;`/`=` label
//! delimiter rules, and the `8191`-character logical line limit.

use alloc::string::String;

use crate::error::CmdError;
use crate::reader::char_map::{ExpansionOrigin, LogicalLineBuffer, SpannedChar};
use crate::reader::encoding::decode_physical_line_at;
use crate::span::{ByteOffset, SourceId, Span};
use crate::types::{CodePage, LabelName, QuoteMode, TAB_CHAR};

/// Maximum logical command line length allowed by `cmd.exe` (`8191` characters).
pub const MAX_CMD_LINE_LEN: usize = 8191;

/// Characters that terminate a `:label` name token in `cmd.exe`.
const LABEL_DELIMITERS: [char; 11] = [' ', TAB_CHAR, ':', '+', '&', '|', '<', '>', ',', ';', '='];

/// Borrowed slice and byte-offset metadata for a single physical script line.
pub type PhysicalLineSlice<'a> = (ByteOffset, &'a str, Option<Span>);

/// Stateful byte-offset reader over a batch script buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchFrameReader {
    /// Identifier of the source buffer in the [`crate::span::SourceMap`].
    pub source_id: SourceId,
    /// Current physical or logical byte offset cursor within the script.
    pub cursor: ByteOffset,
}

impl BatchFrameReader {
    /// Constructs a new [`BatchFrameReader`] starting at byte offset `0`.
    ///
    /// # Arguments
    /// * `source_id` - The [`SourceId`] of the script.
    ///
    /// # Returns
    /// A [`BatchFrameReader`] positioned at the beginning of the file.
    #[must_use]
    pub const fn new(source_id: SourceId) -> Self {
        Self {
            source_id,
            cursor: ByteOffset(0),
        }
    }

    /// Seeks the reader cursor directly to `offset`.
    ///
    /// # Arguments
    /// * `offset` - The target [`ByteOffset`] in the script.
    pub const fn seek(&mut self, offset: ByteOffset) {
        self.cursor = offset;
    }

    /// Checks whether the cursor has reached or passed the end of `script_text`.
    ///
    /// # Arguments
    /// * `script_text` - Current decoded text of the script.
    ///
    /// # Returns
    /// `true` if `cursor >= script_text.len()`, otherwise `false`.
    #[must_use]
    pub const fn is_eof(&self, script_text: &str) -> bool {
        self.cursor.0 >= script_text.len()
    }

    /// Checks whether the cursor has reached or passed the end of a raw byte script buffer.
    ///
    /// # Arguments
    /// * `raw_bytes` - Raw undecoded script bytes.
    ///
    /// # Returns
    /// `true` if `cursor >= raw_bytes.len()`, otherwise `false`.
    #[must_use]
    pub const fn is_eof_bytes(&self, raw_bytes: &[u8]) -> bool {
        self.cursor.0 >= raw_bytes.len()
    }

    /// Reads the next physical line starting at `self.cursor` with strict UTF-8 boundary checking.
    ///
    /// # Arguments
    /// * `script_text` - Current decoded text of the script.
    ///
    /// # Returns
    /// `Ok(Some((line_start_offset, line_slice_without_newline, newline_span)))` if not at EOF,
    /// or `Ok(None)` when `self.cursor == script_text.len()`.
    ///
    /// # Errors
    /// Returns [`CmdError::EncodingByteOffsetMismatch`] if `self.cursor` exceeds `script_text.len()`
    /// or falls inside a multi-byte UTF-8 codepoint.
    pub fn read_physical_line_checked<'a>(
        &mut self,
        script_text: &'a str,
    ) -> Result<Option<PhysicalLineSlice<'a>>, CmdError> {
        let start = self.cursor.0;
        if start == script_text.len() {
            return Ok(None);
        }
        let Some(tail) = script_text.get(start..) else {
            return Err(CmdError::EncodingByteOffsetMismatch {
                offset: self.cursor,
                codepage: CodePage::Utf8,
            });
        };

        let bytes = tail.as_bytes();
        let mut rel_end = bytes.len();
        let mut next_cursor = start.saturating_add(bytes.len());
        let mut newline_span = None;

        for (i, &b) in bytes.iter().enumerate() {
            if b == 0x0D {
                rel_end = i;
                let nl_len = if bytes.get(i.saturating_add(1)) == Some(&0x0A) {
                    2
                } else {
                    1
                };
                let nl_start = ByteOffset(start.saturating_add(i));
                let nl_end = nl_start.saturating_add(nl_len);
                newline_span = Some(Span::new(self.source_id, nl_start, nl_end));
                next_cursor = nl_end.0;
                break;
            } else if b == 0x0A {
                rel_end = i;
                let nl_start = ByteOffset(start.saturating_add(i));
                let nl_end = nl_start.saturating_add(1);
                newline_span = Some(Span::new(self.source_id, nl_start, nl_end));
                next_cursor = nl_end.0;
                break;
            }
        }

        self.cursor = ByteOffset(next_cursor);
        let line_slice = tail.get(..rel_end).unwrap_or(tail);
        Ok(Some((ByteOffset(start), line_slice, newline_span)))
    }

    /// Reads the next physical line starting at `self.cursor`, returning `None` at EOF or invalid boundary.
    ///
    /// # Arguments
    /// * `script_text` - Current decoded text of the script.
    ///
    /// # Returns
    /// `Some((line_start_offset, line_slice_without_newline, newline_span))` if valid and non-empty, else `None`.
    pub fn read_physical_line<'a>(
        &mut self,
        script_text: &'a str,
    ) -> Option<PhysicalLineSlice<'a>> {
        self.read_physical_line_checked(script_text).ok().flatten()
    }

    /// Reads a complete logical line from `raw_bytes` at `self.cursor` using the active [`CodePage`].
    ///
    /// Decodes one physical line at a time so mid-script `CHCP` switches and self-modifying batch
    /// files seek accurately in physical file byte offsets. Tracks [`QuoteMode`] so a caret-continued
    /// line inside `"..."` does not erroneously mark a closing `"` as caret-escaped.
    ///
    /// # Arguments
    /// * `raw_bytes` - Raw undecoded script byte buffer.
    /// * `codepage` - Active [`CodePage`] for this read cycle.
    ///
    /// # Returns
    /// `Ok(Some(LogicalLineBuffer))` if a logical line was read, or `Ok(None)` at EOF / `0x1A`.
    ///
    /// # Errors
    /// Returns [`CmdError::EncodingByteOffsetMismatch`], [`CmdError::EncodingFailure`], or
    /// [`CmdError::LineTooLong`] if decoding fails or the logical line exceeds [`MAX_CMD_LINE_LEN`].
    pub fn read_logical_line_bytes(
        &mut self,
        raw_bytes: &[u8],
        codepage: CodePage,
    ) -> Result<Option<LogicalLineBuffer>, CmdError> {
        let Some(mut decoded) = decode_physical_line_at(raw_bytes, self.cursor, codepage)? else {
            return Ok(None);
        };
        self.cursor = decoded.next_cursor;

        let first_start = decoded.line_start;
        let mut buffer = LogicalLineBuffer::new();
        let mut pending_continuation: Option<(Span, Span)> = None;
        let mut quote_mode = QuoteMode::Unquoted;

        loop {
            let line_plain: String = decoded.chars_with_raw_spans.iter().map(|c| c.0).collect();
            let mut chars_iter = decoded.chars_with_raw_spans.iter().copied();

            if let Some((caret_span, newline_span)) = pending_continuation.take()
                && let Some((ch, c_start, c_end)) = chars_iter.next()
            {
                let in_quotes = quote_mode.is_in_quotes();
                if ch == '"' && in_quotes {
                    quote_mode = QuoteMode::Unquoted;
                }
                buffer.chars.push(SpannedChar {
                    ch,
                    span: Span::new(self.source_id, ByteOffset(c_start), ByteOffset(c_end)),
                    escaped_by_caret: !in_quotes,
                    origin: ExpansionOrigin::CaretContinuation {
                        caret_span,
                        newline_span,
                    },
                });
            }

            append_spanned_chars(&mut buffer, self.source_id, chars_iter, &mut quote_mode);

            if buffer.chars.len() > MAX_CMD_LINE_LEN {
                let span = buffer.full_span(self.source_id, first_start);
                return Err(CmdError::LineTooLong { span });
            }

            if let Some((nl_start, nl_end)) = decoded.newline_raw_range {
                let nl_span = Span::new(self.source_id, ByteOffset(nl_start), ByteOffset(nl_end));
                let trailing_carets = count_trailing_carets(&line_plain);
                if trailing_carets % 2 == 1 {
                    let caret_span = buffer.chars.pop().map_or(nl_span, |c| c.span);
                    if let Some(next_decoded) =
                        decode_physical_line_at(raw_bytes, self.cursor, codepage)?
                    {
                        self.cursor = next_decoded.next_cursor;
                        decoded = next_decoded;
                        pending_continuation = Some((caret_span, nl_span));
                        continue;
                    }
                } else if let Some(broken_span) = detect_caret_followed_by_whitespace_spanned(
                    self.source_id,
                    &decoded.chars_with_raw_spans,
                ) {
                    buffer.broken_caret_span = Some(broken_span);
                }
            }

            break;
        }

        Ok(Some(buffer))
    }

    /// Searches `raw_bytes` for a target batch `:label` starting from `self.cursor` and
    /// wrapping around to physical byte offset `0`, matching `cmd.exe`'s raw byte label scan.
    ///
    /// # Arguments
    /// * `raw_bytes` - Raw undecoded script bytes.
    /// * `codepage` - Active [`CodePage`] for decoding candidate label lines.
    /// * `target` - The [`LabelName`] to locate.
    /// * `call_span` - Source [`Span`] of the `GOTO` or `CALL` statement for error reporting.
    ///
    /// # Returns
    /// `Ok(ByteOffset)` pointing to the raw byte start of the line immediately after `:label`.
    ///
    /// # Errors
    /// Returns [`CmdError::BatchLabelNotFound`] if the label does not exist, or encoding errors.
    pub fn find_label_offset_bytes(
        &self,
        raw_bytes: &[u8],
        codepage: CodePage,
        target: &LabelName,
        call_span: Span,
    ) -> Result<ByteOffset, CmdError> {
        let clamped_cursor = ByteOffset(self.cursor.0.min(raw_bytes.len()));
        if let Some(found) = scan_for_label_in_raw_range(
            raw_bytes,
            codepage,
            clamped_cursor,
            ByteOffset(raw_bytes.len()),
            target,
        )? {
            return Ok(found);
        }
        if let Some(found) =
            scan_for_label_in_raw_range(raw_bytes, codepage, ByteOffset(0), clamped_cursor, target)?
        {
            return Ok(found);
        }
        Err(CmdError::BatchLabelNotFound {
            span: call_span,
            label: target.clone(),
        })
    }
}

/// Appends literal characters to `buffer` while maintaining quote state across unescaped `"` and `^`.
///
/// # Arguments
/// * `buffer` - Destination [`LogicalLineBuffer`].
/// * `source_id` - Active [`SourceId`].
/// * `iter` - Iterator of `(ch, raw_start_byte, raw_end_byte)` tuples.
/// * `quote_mode` - Mutable [`QuoteMode`] state across physical line continuations.
fn append_spanned_chars<I>(
    buffer: &mut LogicalLineBuffer,
    source_id: SourceId,
    iter: I,
    quote_mode: &mut QuoteMode,
) where
    I: Iterator<Item = (char, usize, usize)>,
{
    let mut prev_unescaped_caret = false;
    for (ch, s, e) in iter {
        if quote_mode.is_unquoted() {
            if prev_unescaped_caret {
                prev_unescaped_caret = false;
            } else if ch == '^' {
                prev_unescaped_caret = true;
            } else if ch == '"' {
                *quote_mode = QuoteMode::InQuotes;
            }
        } else if ch == '"' {
            *quote_mode = QuoteMode::Unquoted;
        }
        buffer.chars.push(SpannedChar::literal(
            ch,
            Span::new(source_id, ByteOffset(s), ByteOffset(e)),
        ));
    }
}

/// Counts how many consecutive `^` characters appear at the very end of `line`.
///
/// # Arguments
/// * `line` - Physical line slice without newline.
///
/// # Returns
/// Count of consecutive trailing `^` characters.
fn count_trailing_carets(line: &str) -> usize {
    line.chars().rev().take_while(|&c| c == '^').count()
}

/// Detects if a spanned physical line ends with an odd number of `^` followed only by spaces/tabs (`CMD1004`).
///
/// # Arguments
/// * `source_id` - Source file identifier.
/// * `chars_with_spans` - Decoded `(char, start_byte, end_byte)` sequence of the physical line.
///
/// # Returns
/// `Some(Span)` covering the offending `^` through trailing whitespace if detected, else `None`.
fn detect_caret_followed_by_whitespace_spanned(
    source_id: SourceId,
    chars_with_spans: &[(char, usize, usize)],
) -> Option<Span> {
    let non_ws_len = chars_with_spans
        .iter()
        .rposition(|&(c, _, _)| c != ' ' && c != TAB_CHAR)
        .map_or(0, |pos| pos.saturating_add(1));
    if non_ws_len == 0 || non_ws_len == chars_with_spans.len() {
        return None;
    }
    let trimmed = chars_with_spans.get(..non_ws_len)?;
    let carets = trimmed
        .iter()
        .rev()
        .take_while(|&&(c, _, _)| c == '^')
        .count();
    if carets % 2 == 1 {
        let &(_, caret_start, _) = trimmed.last()?;
        let &(_, _, line_end) = chars_with_spans.last()?;
        Some(Span::new(
            source_id,
            ByteOffset(caret_start),
            ByteOffset(line_end),
        ))
    } else {
        None
    }
}

/// Checks whether a physical line defines `:target` according to `cmd.exe` label delimiter rules.
///
/// # Arguments
/// * `line_text` - Physical line text without trailing newline.
/// * `target` - Target [`LabelName`] to match case-insensitively.
///
/// # Returns
/// `true` if `line_text` begins with `:label` matching `target` (and is not `::`).
fn line_matches_label(line_text: &str, target: &LabelName) -> bool {
    let trimmed = line_text.trim_start_matches([' ', TAB_CHAR]);
    let Some(after_colon) = trimmed.strip_prefix(':') else {
        return false;
    };
    if after_colon.starts_with(':') {
        return false;
    }
    let token_end = after_colon
        .find(LABEL_DELIMITERS)
        .unwrap_or(after_colon.len());
    let label_token = after_colon.get(..token_end).unwrap_or(after_colon);
    !label_token.is_empty() && LabelName::new(label_token) == *target
}

/// Scans a raw byte offset range `[start..limit)` of `raw_bytes` for a physical line defining `:target`.
///
/// # Arguments
/// * `raw_bytes` - Full raw script bytes.
/// * `codepage` - Active [`CodePage`].
/// * `start` - Starting physical byte offset.
/// * `limit` - Upper bound physical byte offset.
/// * `target` - Target [`LabelName`].
///
/// # Returns
/// `Ok(Some(ByteOffset))` of the physical line immediately after `:target`, or `Ok(None)`.
///
/// # Errors
/// Returns [`CmdError`] if raw line decoding fails.
fn scan_for_label_in_raw_range(
    raw_bytes: &[u8],
    codepage: CodePage,
    start: ByteOffset,
    limit: ByteOffset,
    target: &LabelName,
) -> Result<Option<ByteOffset>, CmdError> {
    let mut cursor = start;
    while cursor.0 < limit.0 {
        let Some(decoded) = decode_physical_line_at(raw_bytes, cursor, codepage)? else {
            break;
        };
        cursor = decoded.next_cursor;
        let line_text: String = decoded.chars_with_raw_spans.iter().map(|c| c.0).collect();
        if line_matches_label(&line_text, target) {
            return Ok(Some(cursor));
        }
    }
    Ok(None)
}

#[cfg(test)]
/// Unit tests for [`BatchFrameReader`] raw-byte seeking, caret continuations, and label scanning.
mod tests {
    use super::*;

    /// Verifies physical and logical line reading, `^^`, broken carets, and mid-UTF8 byte-offset errors.
    #[test]
    fn test_read_physical_and_logical_lines_with_continuations() {
        let cr = crate::types::CR_CHAR;
        let lf = crate::types::LF_CHAR;
        let script = format!(
            "echo hello ^{cr}{lf}world{lf}echo ^^not_continued{cr}{lf}echo broken ^   {cr}{lf}next"
        );
        let raw = script.as_bytes();
        let mut reader = BatchFrameReader::new(SourceId(0));
        assert!(!reader.is_eof(&script));

        let line1 = reader
            .read_logical_line_bytes(raw, CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(
            line1.as_ref().map(LogicalLineBuffer::to_plain_string),
            Some("echo hello world".to_owned())
        );
        assert_eq!(line1.as_ref().and_then(|b| b.broken_caret_span), None);
        assert_eq!(
            line1
                .as_ref()
                .and_then(|b| b.chars.get(11))
                .map(|c| c.escaped_by_caret),
            Some(true)
        );

        let line2 = reader
            .read_logical_line_bytes(raw, CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(
            line2.map(|b| b.to_plain_string()),
            Some("echo ^^not_continued".to_owned())
        );

        let line3 = reader
            .read_logical_line_bytes(raw, CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(
            line3.as_ref().map(LogicalLineBuffer::to_plain_string),
            Some("echo broken ^   ".to_owned())
        );
        assert!(line3.and_then(|b| b.broken_caret_span).is_some());

        let line4 = reader
            .read_logical_line_bytes(raw, CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(line4.map(|b| b.to_plain_string()), Some("next".to_owned()));

        assert!(reader.is_eof(&script));
        assert_eq!(
            reader.read_logical_line_bytes(raw, CodePage::Utf8),
            Ok(None)
        );
        assert_eq!(reader.read_physical_line_checked(&script), Ok(None));

        // Out-of-bounds / mid-UTF8 cursor surfaces EncodingByteOffsetMismatch on physical line reader
        let utf8_text = "echo \u{2603}";
        reader.seek(ByteOffset(6));
        assert!(matches!(
            reader.read_physical_line_checked(utf8_text),
            Err(CmdError::EncodingByteOffsetMismatch { .. })
        ));
    }

    /// Verifies caret line continuation inside double quotes and raw-byte CHCP transitions.
    #[test]
    fn test_quoted_caret_continuation_and_raw_byte_chcp_switch() {
        let cr = crate::types::CR_CHAR;
        let lf = crate::types::LF_CHAR;
        let quoted_script = format!(r#"echo ^"lit "same" ^{cr}{lf}"esc "hel^{cr}{lf}lo^{cr}{lf}""#);
        let mut qreader = BatchFrameReader::new(SourceId(0));
        let qline = qreader
            .read_logical_line_bytes(quoted_script.as_bytes(), CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(
            qline.as_ref().map(LogicalLineBuffer::to_plain_string),
            Some(r#"echo ^"lit "same" "esc "hello""#.to_owned())
        );
        assert_eq!(
            qline
                .as_ref()
                .and_then(|b| b.chars.last())
                .map(|c| c.escaped_by_caret),
            Some(false)
        );

        let mut raw = Vec::new();
        raw.extend_from_slice(&[b'r', b'e', b'm', b' ', 0xB3, 0x0D, 0x0A]);
        raw.extend_from_slice(br#"echo "same" ^"#);
        raw.extend_from_slice(&[0x0D, 0x0A]);
        raw.extend_from_slice(br#""esc "h^"#);
        raw.extend_from_slice(&[0x0D, 0x0A]);
        raw.extend_from_slice(b"i^");
        raw.extend_from_slice(&[0x0D, 0x0A]);
        raw.extend_from_slice(br#"" ^"#);
        raw.push(0x09);
        raw.extend_from_slice(&[0x0D, 0x0A]);
        raw.extend_from_slice("echo \u{2603}^".as_bytes());
        raw.push(0x0A);
        raw.extend_from_slice(b"tail");
        raw.push(0x0A);
        raw.extend_from_slice(b"echo empty_cont^");
        raw.extend_from_slice(&[0x0D, 0x0A, 0x0D, 0x0A]);

        let mut breader = BatchFrameReader::new(SourceId(1));
        assert!(!breader.is_eof_bytes(&raw));

        let b1 = breader
            .read_logical_line_bytes(&raw, CodePage::OemUnitedStates)
            .ok()
            .flatten();
        assert_eq!(
            b1.map(|b| b.to_plain_string()),
            Some("rem \u{2502}".to_owned())
        );

        let b2 = breader
            .read_logical_line_bytes(&raw, CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(
            b2.as_ref().map(LogicalLineBuffer::to_plain_string),
            Some(format!(r#"echo "same" "esc "hi" ^{TAB_CHAR}"#))
        );
        assert!(b2.and_then(|b| b.broken_caret_span).is_some());

        let b3 = breader
            .read_logical_line_bytes(&raw, CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(
            b3.map(|b| b.to_plain_string()),
            Some("echo \u{2603}tail".to_owned())
        );
        let b4 = breader
            .read_logical_line_bytes(&raw, CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(
            b4.map(|b| b.to_plain_string()),
            Some("echo empty_cont".to_owned())
        );
        assert!(breader.is_eof_bytes(&raw));
        assert_eq!(
            breader.read_logical_line_bytes(&raw, CodePage::Utf8),
            Ok(None)
        );
    }

    /// Verifies raw-byte reader edge cases including trailing spaces, line-length limits, and invalid UTF-8.
    #[test]
    fn test_raw_byte_reader_edge_cases_and_limits() {
        let mut raw_edges = Vec::new();
        raw_edges.extend_from_slice(b"   ");
        raw_edges.push(0x0A);
        raw_edges.extend_from_slice(b"echo a^^   ");
        raw_edges.push(0x0A);
        raw_edges.extend_from_slice(b"echo end^");
        raw_edges.push(0x0A);
        let mut ereader = BatchFrameReader::new(SourceId(2));
        let e1 = ereader
            .read_logical_line_bytes(&raw_edges, CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(e1.and_then(|b| b.broken_caret_span), None);
        let e2 = ereader
            .read_logical_line_bytes(&raw_edges, CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(e2.and_then(|b| b.broken_caret_span), None);
        let e3 = ereader
            .read_logical_line_bytes(&raw_edges, CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(e3.map(|b| b.to_plain_string()), Some("echo end".to_owned()));

        let huge_bytes = vec![b'x'; MAX_CMD_LINE_LEN + 2];
        let mut hreader = BatchFrameReader::new(SourceId(3));
        assert!(matches!(
            hreader.read_logical_line_bytes(&huge_bytes, CodePage::Utf8),
            Err(CmdError::LineTooLong { .. })
        ));

        let mut no_nl_reader = BatchFrameReader::new(SourceId(5));
        assert_eq!(
            no_nl_reader
                .read_logical_line_bytes(b"no_newline", CodePage::Utf8)
                .ok()
                .flatten()
                .map(|b| b.to_plain_string()),
            Some("no_newline".to_owned())
        );

        let bad_cont = [b'a', b'^', 0x0A, 0xFF];
        let mut creader = BatchFrameReader::new(SourceId(4));
        assert!(
            creader
                .read_logical_line_bytes(&bad_cont, CodePage::Utf8)
                .is_err()
        );
        assert!(
            creader
                .find_label_offset_bytes(
                    &[0xFF],
                    CodePage::Utf8,
                    &LabelName::new("x"),
                    Span::dummy()
                )
                .is_err()
        );
    }

    /// Verifies trailing `^` at EOF without a newline and bare `CR` line endings on physical and logical readers.
    #[test]
    fn test_caret_at_eof_and_cr_only_line_ending() {
        let cr = crate::types::CR_CHAR;
        let lf = crate::types::LF_CHAR;
        let script = format!("echo a{cr}echo b^{lf}echo c^");
        let mut phys_reader = BatchFrameReader::new(SourceId(0));
        assert_eq!(
            phys_reader.read_physical_line(&script).map(|(_, s, _)| s),
            Some("echo a")
        );
        assert_eq!(
            phys_reader.read_physical_line(&script).map(|(_, s, _)| s),
            Some("echo b^")
        );
        assert_eq!(
            phys_reader.read_physical_line(&script).map(|(_, s, _)| s),
            Some("echo c^")
        );
        assert_eq!(phys_reader.read_physical_line(&script), None);

        let raw = format!("echo a{cr}echo b^");
        let mut reader = BatchFrameReader::new(SourceId(0));
        let l1 = reader.read_logical_line_bytes(raw.as_bytes(), CodePage::Utf8);
        assert_eq!(
            l1.ok().flatten().map(|b| b.to_plain_string()),
            Some("echo a".to_owned())
        );
        let l2 = reader.read_logical_line_bytes(raw.as_bytes(), CodePage::Utf8);
        assert_eq!(
            l2.ok().flatten().map(|b| b.to_plain_string()),
            Some("echo b^".to_owned())
        );
    }

    /// Verifies trailing `^` immediately before a final empty line.
    #[test]
    fn test_caret_before_final_empty_line() {
        let cr = crate::types::CR_CHAR;
        let lf = crate::types::LF_CHAR;
        let script = format!("echo a^{lf}");
        let mut reader = BatchFrameReader::new(SourceId(0));
        let l1 = reader.read_logical_line_bytes(script.as_bytes(), CodePage::Utf8);
        assert_eq!(
            l1.ok().flatten().map(|b| b.to_plain_string()),
            Some("echo a".to_owned())
        );

        let script2 = format!("echo a^{cr}{lf}{cr}{lf}");
        let mut reader2 = BatchFrameReader::new(SourceId(0));
        let l2 = reader2.read_logical_line_bytes(script2.as_bytes(), CodePage::Utf8);
        assert_eq!(
            l2.ok().flatten().map(|b| b.to_plain_string()),
            Some("echo a".to_owned())
        );
    }

    /// Verifies `^^` followed by trailing spaces does not trigger broken-caret warnings.
    #[test]
    fn test_double_caret_followed_by_whitespace_is_not_broken_continuation() {
        let cr = crate::types::CR_CHAR;
        let lf = crate::types::LF_CHAR;
        let script = format!("echo a^^   {cr}{lf}");
        let mut reader = BatchFrameReader::new(SourceId(0));
        let l1 = reader
            .read_logical_line_bytes(script.as_bytes(), CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(l1.and_then(|b| b.broken_caret_span), None);
    }

    /// Verifies `CmdError::LineTooLong` when a logical line exceeds 8191 characters.
    #[test]
    fn test_line_too_long_error() {
        let huge = "a".repeat(MAX_CMD_LINE_LEN + 5);
        let mut reader = BatchFrameReader::new(SourceId(0));
        let res = reader.read_logical_line_bytes(huge.as_bytes(), CodePage::Utf8);
        assert!(res.is_err());
    }

    /// Verifies forward and wrap-around `:label` scanning across `,`, `;`, `=`, and whitespace delimiters.
    #[test]
    fn test_find_label_forward_wraparound_and_delimiters() {
        let cr = crate::types::CR_CHAR;
        let lf = crate::types::LF_CHAR;
        let script = format!(
            ":top,arg{cr}{lf}echo 1{cr}{lf}:{cr}{lf}:: comment{cr}{lf}:middle=extra{cr}{lf}:semi;tail{cr}{lf}echo 2{cr}{lf}"
        );
        let raw = script.as_bytes();
        let mut reader = BatchFrameReader::new(SourceId(0));
        let first = reader.read_logical_line_bytes(raw, CodePage::Utf8);
        assert!(first.is_ok());

        let mid_off = reader.find_label_offset_bytes(
            raw,
            CodePage::Utf8,
            &LabelName::new("MIDDLE"),
            Span::dummy(),
        );
        assert!(mid_off.is_ok());

        let semi_off = reader.find_label_offset_bytes(
            raw,
            CodePage::Utf8,
            &LabelName::new("SEMI"),
            Span::dummy(),
        );
        assert!(semi_off.is_ok());

        let top_off = reader.find_label_offset_bytes(
            raw,
            CodePage::Utf8,
            &LabelName::new(":top"),
            Span::dummy(),
        );
        assert_eq!(top_off, Ok(ByteOffset(10)));

        let mut raw_ctrl_z = raw.to_vec();
        raw_ctrl_z.push(0x1A);
        raw_ctrl_z.extend_from_slice(b":after_eof");
        assert!(
            reader
                .find_label_offset_bytes(
                    &raw_ctrl_z,
                    CodePage::Utf8,
                    &LabelName::new("after_eof"),
                    Span::dummy()
                )
                .is_err()
        );

        reader.seek(ByteOffset(10));
        let next = reader.read_logical_line_bytes(raw, CodePage::Utf8);
        assert_eq!(
            next.ok().flatten().map(|b| b.to_plain_string()),
            Some("echo 1".to_owned())
        );

        let missing = reader.find_label_offset_bytes(
            raw,
            CodePage::Utf8,
            &LabelName::new("nowhere"),
            Span::dummy(),
        );
        assert!(missing.is_err());
    }
}
