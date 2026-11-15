//! Character encoding, Byte Order Mark (BOM) detection, and OEM codepage conversion (`CHCP`).
//!
//! Supports UTF-8 (65001), UTF-16LE (1200), UTF-16BE (1201), US-ASCII (20127),
//! Windows-1252, OEM CP437, and OEM CP850, plus `0x1A` (`Ctrl+Z` / `SUB`) EOF handling
//! and incremental raw-byte single-line decoding for mid-script `CHCP` switches.

use crate::error::CmdError;
use crate::span::ByteOffset;
use crate::types::CodePage;

/// Upper half (`0x80..=0xFF`) lookup table for OEM Code Page 437.
const CP437_HIGH_TABLE: [char; 128] = [
    '\u{00C7}', '\u{00FC}', '\u{00E9}', '\u{00E2}', '\u{00E4}', '\u{00E0}', '\u{00E5}', '\u{00E7}',
    '\u{00EA}', '\u{00EB}', '\u{00E8}', '\u{00EF}', '\u{00EE}', '\u{00EC}', '\u{00C4}', '\u{00C5}',
    '\u{00C9}', '\u{00E6}', '\u{00C6}', '\u{00F4}', '\u{00F6}', '\u{00F2}', '\u{00FB}', '\u{00F9}',
    '\u{00FF}', '\u{00D6}', '\u{00DC}', '\u{00A2}', '\u{00A3}', '\u{00A5}', '\u{20A7}', '\u{0192}',
    '\u{00E1}', '\u{00ED}', '\u{00F3}', '\u{00FA}', '\u{00F1}', '\u{00D1}', '\u{00AA}', '\u{00BA}',
    '\u{00BF}', '\u{2310}', '\u{00AC}', '\u{00BD}', '\u{00BC}', '\u{00A1}', '\u{00AB}', '\u{00BB}',
    '\u{2591}', '\u{2592}', '\u{2593}', '\u{2502}', '\u{2524}', '\u{2561}', '\u{2562}', '\u{2556}',
    '\u{2555}', '\u{2563}', '\u{2551}', '\u{2557}', '\u{255D}', '\u{255C}', '\u{255B}', '\u{2510}',
    '\u{2514}', '\u{2534}', '\u{252C}', '\u{251C}', '\u{2500}', '\u{253C}', '\u{255E}', '\u{255F}',
    '\u{255A}', '\u{2554}', '\u{2569}', '\u{2566}', '\u{2560}', '\u{2550}', '\u{256C}', '\u{2567}',
    '\u{2568}', '\u{2564}', '\u{2565}', '\u{2559}', '\u{2558}', '\u{2552}', '\u{2553}', '\u{256B}',
    '\u{256A}', '\u{2518}', '\u{250C}', '\u{2588}', '\u{2584}', '\u{258C}', '\u{2590}', '\u{2580}',
    '\u{03B1}', '\u{00DF}', '\u{0393}', '\u{03C0}', '\u{03A3}', '\u{03C3}', '\u{00B5}', '\u{03C4}',
    '\u{03A6}', '\u{0398}', '\u{03A9}', '\u{03B4}', '\u{221E}', '\u{03C6}', '\u{03B5}', '\u{2229}',
    '\u{2261}', '\u{00B1}', '\u{2265}', '\u{2264}', '\u{2320}', '\u{2321}', '\u{00F7}', '\u{2248}',
    '\u{00B0}', '\u{2219}', '\u{00B7}', '\u{221A}', '\u{207F}', '\u{00B2}', '\u{25A0}', '\u{00A0}',
];

/// Upper half (`0x80..=0xFF`) lookup table for OEM Code Page 850 (Multilingual Latin 1).
const CP850_HIGH_TABLE: [char; 128] = [
    '\u{00C7}', '\u{00FC}', '\u{00E9}', '\u{00E2}', '\u{00E4}', '\u{00E0}', '\u{00E5}', '\u{00E7}',
    '\u{00EA}', '\u{00EB}', '\u{00E8}', '\u{00EF}', '\u{00EE}', '\u{00EC}', '\u{00C4}', '\u{00C5}',
    '\u{00C9}', '\u{00E6}', '\u{00C6}', '\u{00F4}', '\u{00F6}', '\u{00F2}', '\u{00FB}', '\u{00F9}',
    '\u{00FF}', '\u{00D6}', '\u{00DC}', '\u{00F8}', '\u{00A3}', '\u{00D8}', '\u{00D7}', '\u{0192}',
    '\u{00E1}', '\u{00ED}', '\u{00F3}', '\u{00FA}', '\u{00F1}', '\u{00D1}', '\u{00AA}', '\u{00BA}',
    '\u{00BF}', '\u{00AE}', '\u{00AC}', '\u{00BD}', '\u{00BC}', '\u{00A1}', '\u{00AB}', '\u{00BB}',
    '\u{2591}', '\u{2592}', '\u{2593}', '\u{2502}', '\u{2524}', '\u{00C1}', '\u{00C2}', '\u{00C0}',
    '\u{00A9}', '\u{2563}', '\u{2551}', '\u{2557}', '\u{255D}', '\u{00A2}', '\u{00A5}', '\u{2510}',
    '\u{2514}', '\u{2534}', '\u{252C}', '\u{251C}', '\u{2500}', '\u{253C}', '\u{00E3}', '\u{00C3}',
    '\u{255A}', '\u{2554}', '\u{2569}', '\u{2566}', '\u{2560}', '\u{2550}', '\u{256C}', '\u{00A4}',
    '\u{00F0}', '\u{00D0}', '\u{00CA}', '\u{00CB}', '\u{00C8}', '\u{0131}', '\u{00CD}', '\u{00CE}',
    '\u{00CF}', '\u{2518}', '\u{250C}', '\u{2588}', '\u{2584}', '\u{00A6}', '\u{00CC}', '\u{2580}',
    '\u{00D3}', '\u{00DF}', '\u{00D4}', '\u{00D2}', '\u{00F5}', '\u{00D5}', '\u{00B5}', '\u{00FE}',
    '\u{00DE}', '\u{00DA}', '\u{00DB}', '\u{00D9}', '\u{00FD}', '\u{00DD}', '\u{00AF}', '\u{00B4}',
    '\u{00AD}', '\u{00B1}', '\u{2017}', '\u{00BE}', '\u{00B6}', '\u{00A7}', '\u{00F7}', '\u{00B8}',
    '\u{00B0}', '\u{00A8}', '\u{00B7}', '\u{00B9}', '\u{00B3}', '\u{00B2}', '\u{25A0}', '\u{00A0}',
];

/// Upper half (`0x80..=0xFF`) lookup table for Windows-1252.
const WIN1252_HIGH_TABLE: [char; 128] = [
    '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}', '\u{017D}', '\u{008F}',
    '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}', '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
    '\u{00A0}', '\u{00A1}', '\u{00A2}', '\u{00A3}', '\u{00A4}', '\u{00A5}', '\u{00A6}', '\u{00A7}',
    '\u{00A8}', '\u{00A9}', '\u{00AA}', '\u{00AB}', '\u{00AC}', '\u{00AD}', '\u{00AE}', '\u{00AF}',
    '\u{00B0}', '\u{00B1}', '\u{00B2}', '\u{00B3}', '\u{00B4}', '\u{00B5}', '\u{00B6}', '\u{00B7}',
    '\u{00B8}', '\u{00B9}', '\u{00BA}', '\u{00BB}', '\u{00BC}', '\u{00BD}', '\u{00BE}', '\u{00BF}',
    '\u{00C0}', '\u{00C1}', '\u{00C2}', '\u{00C3}', '\u{00C4}', '\u{00C5}', '\u{00C6}', '\u{00C7}',
    '\u{00C8}', '\u{00C9}', '\u{00CA}', '\u{00CB}', '\u{00CC}', '\u{00CD}', '\u{00CE}', '\u{00CF}',
    '\u{00D0}', '\u{00D1}', '\u{00D2}', '\u{00D3}', '\u{00D4}', '\u{00D5}', '\u{00D6}', '\u{00D7}',
    '\u{00D8}', '\u{00D9}', '\u{00DA}', '\u{00DB}', '\u{00DC}', '\u{00DD}', '\u{00DE}', '\u{00DF}',
    '\u{00E0}', '\u{00E1}', '\u{00E2}', '\u{00E3}', '\u{00E4}', '\u{00E5}', '\u{00E6}', '\u{00E7}',
    '\u{00E8}', '\u{00E9}', '\u{00EA}', '\u{00EB}', '\u{00EC}', '\u{00ED}', '\u{00EE}', '\u{00EF}',
    '\u{00F0}', '\u{00F1}', '\u{00F2}', '\u{00F3}', '\u{00F4}', '\u{00F5}', '\u{00F6}', '\u{00F7}',
    '\u{00F8}', '\u{00F9}', '\u{00FA}', '\u{00FB}', '\u{00FC}', '\u{00FD}', '\u{00FE}', '\u{00FF}',
];

/// Detected Byte Order Mark (BOM) at the start of a byte buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectedBom {
    /// No BOM prefix was present.
    None,
    /// UTF-8 BOM (`0xEF, 0xBB, 0xBF`).
    Utf8,
    /// UTF-16 Little Endian BOM (`0xFF, 0xFE`).
    Utf16Le,
    /// UTF-16 Big Endian BOM (`0xFE, 0xFF`).
    Utf16Be,
}

impl DetectedBom {
    /// Inspects the leading bytes of `raw` to identify any BOM prefix.
    ///
    /// # Arguments
    /// * `raw` - Byte slice to inspect.
    ///
    /// # Returns
    /// The [`DetectedBom`] variant.
    #[must_use]
    pub const fn detect(raw: &[u8]) -> Self {
        match raw {
            [0xEF, 0xBB, 0xBF, ..] => Self::Utf8,
            [0xFF, 0xFE, ..] => Self::Utf16Le,
            [0xFE, 0xFF, ..] => Self::Utf16Be,
            _ => Self::None,
        }
    }

    /// Returns the length in bytes of this BOM (`0`, `2`, or `3`).
    ///
    /// # Returns
    /// Byte length of the BOM prefix.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Utf16Le | Self::Utf16Be => 2,
            Self::Utf8 => 3,
        }
    }
}

/// A single physical line decoded directly from a raw byte buffer at a specific [`ByteOffset`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPhysicalLine {
    /// Physical byte offset where this line's content began (after any BOM at offset 0).
    pub line_start: ByteOffset,
    /// Decoded Unicode characters paired with their exact physical `(start_byte, end_byte)` spans.
    pub chars_with_raw_spans: Vec<(char, usize, usize)>,
    /// Optional physical `(start_byte, end_byte)` range of the consumed line break (`CR`, `LF`, or `CRLF`).
    pub newline_raw_range: Option<(usize, usize)>,
    /// Next physical [`ByteOffset`] cursor after this line (or `raw.len()` when `0x1A`/`0x00` EOF hit).
    pub next_cursor: ByteOffset,
}

/// Decodes a single physical line starting at `raw_offset` in `raw` using the active [`CodePage`].
///
/// Because `cmd.exe` seeks in raw file bytes between statements, calling `CHCP 65001` mid-script
/// changes how subsequent physical lines are decoded from their raw byte offset without re-decoding
/// earlier lines that may have contained single-byte OEM characters.
///
/// # Arguments
/// * `raw` - Raw undecoded script byte buffer.
/// * `raw_offset` - Current physical [`ByteOffset`] cursor within `raw`.
/// * `codepage` - Active [`CodePage`] for this statement read cycle.
///
/// # Returns
/// `Ok(Some(DecodedPhysicalLine))` if a line was decoded, or `Ok(None)` at EOF / `0x1A` / `0x00`.
///
/// # Errors
/// Returns [`CmdError::EncodingByteOffsetMismatch`] if `raw_offset` exceeds `raw.len()` or is
/// misaligned for UTF-16, or [`CmdError::EncodingFailure`] if the line's bytes are invalid for `codepage`.
pub fn decode_physical_line_at(
    raw: &[u8],
    raw_offset: ByteOffset,
    codepage: CodePage,
) -> Result<Option<DecodedPhysicalLine>, CmdError> {
    if raw_offset.0 > raw.len() {
        return Err(CmdError::EncodingByteOffsetMismatch {
            offset: raw_offset,
            codepage,
        });
    }

    let bom = DetectedBom::detect(raw);
    let effective_cp = match bom {
        DetectedBom::Utf16Le => CodePage::Utf16Le,
        DetectedBom::Utf16Be => CodePage::Utf16Be,
        DetectedBom::Utf8 if raw_offset.0 == 0 => CodePage::Utf8,
        DetectedBom::Utf8 | DetectedBom::None => codepage,
    };
    let content_start = if raw_offset.0 == 0 {
        bom.byte_len()
    } else {
        raw_offset.0
    };

    if content_start >= raw.len() {
        return Ok(None);
    }

    match effective_cp {
        CodePage::Utf16Le => {
            decode_utf16_line_at(raw, content_start, crate::types::Utf16Endian::Little)
        }
        CodePage::Utf16Be => {
            decode_utf16_line_at(raw, content_start, crate::types::Utf16Endian::Big)
        }
        CodePage::Utf8 => decode_byte_line_at(raw, content_start, SingleByteCodePage::Utf8),
        CodePage::Ascii => decode_byte_line_at(raw, content_start, SingleByteCodePage::Ascii),
        CodePage::OemUnitedStates => {
            decode_byte_line_at(raw, content_start, SingleByteCodePage::OemUnitedStates)
        }
        CodePage::OemMultilingualLatin1 => decode_byte_line_at(
            raw,
            content_start,
            SingleByteCodePage::OemMultilingualLatin1,
        ),
        CodePage::WindowsLatin1 => {
            decode_byte_line_at(raw, content_start, SingleByteCodePage::WindowsLatin1)
        }
    }
}

/// 8-bit or UTF-8 codepage handled by [`decode_byte_line_at`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SingleByteCodePage {
    /// UTF-8 (`65001`).
    Utf8,
    /// Strict 7-bit US-ASCII (`20127`).
    Ascii,
    /// OEM United States (`437`).
    OemUnitedStates,
    /// OEM Multilingual Latin 1 (`850`).
    OemMultilingualLatin1,
    /// Windows-1252 Western European (`1252`).
    WindowsLatin1,
}

/// Decodes a single physical line for 8-bit/UTF-8 codepages starting at `content_start`.
///
/// # Arguments
/// * `raw` - Full raw script bytes.
/// * `content_start` - Validated starting byte index (`< raw.len()`).
/// * `codepage` - Active [`SingleByteCodePage`].
///
/// # Returns
/// `Ok(Some(DecodedPhysicalLine))` or `Ok(None)` if `content_start` immediately hits `0x1A` or `0x00`.
///
/// # Errors
/// Returns [`CmdError::EncodingFailure`] on invalid UTF-8 or non-ASCII bytes under `CodePage::Ascii`.
fn decode_byte_line_at(
    raw: &[u8],
    content_start: usize,
    codepage: SingleByteCodePage,
) -> Result<Option<DecodedPhysicalLine>, CmdError> {
    if matches!(raw.get(content_start), Some(&0x1A | &0x00) | None) {
        return Ok(None);
    }

    let mut line_end = raw.len();
    let mut newline_raw_range = None;
    let mut next_cursor = raw.len();

    let mut idx = content_start;
    while let Some(&b) = raw.get(idx) {
        if b == 0x1A || b == 0x00 {
            line_end = idx;
            next_cursor = raw.len();
            break;
        } else if b == 0x0D {
            line_end = idx;
            let nl_end = if raw.get(idx.saturating_add(1)) == Some(&0x0A) {
                idx.saturating_add(2)
            } else {
                idx.saturating_add(1)
            };
            newline_raw_range = Some((idx, nl_end));
            next_cursor = nl_end;
            break;
        } else if b == 0x0A {
            line_end = idx;
            let nl_end = idx.saturating_add(1);
            newline_raw_range = Some((idx, nl_end));
            next_cursor = nl_end;
            break;
        }
        idx = idx.saturating_add(1);
    }

    let line_bytes = raw.get(content_start..line_end).unwrap_or(&[]);
    let chars_with_raw_spans = match codepage {
        SingleByteCodePage::Utf8 => {
            let decoded =
                std::str::from_utf8(line_bytes).map_err(|err| CmdError::EncodingFailure {
                    offset: ByteOffset(content_start.saturating_add(err.valid_up_to())),
                    codepage: CodePage::Utf8,
                    detail: err.to_string(),
                })?;
            decoded
                .char_indices()
                .map(|(rel, ch)| {
                    let s = content_start.saturating_add(rel);
                    (ch, s, s.saturating_add(ch.len_utf8()))
                })
                .collect()
        }
        SingleByteCodePage::Ascii => {
            if let Some(rel_bad) = line_bytes.iter().position(|&b| b > 0x7F) {
                let bad_byte = line_bytes.get(rel_bad).copied().unwrap_or(0x80);
                return Err(CmdError::EncodingFailure {
                    offset: ByteOffset(content_start.saturating_add(rel_bad)),
                    codepage: CodePage::Ascii,
                    detail: format!("non-ASCII byte 0x{bad_byte:02X}"),
                });
            }
            line_bytes
                .iter()
                .enumerate()
                .map(|(rel, &b)| {
                    let s = content_start.saturating_add(rel);
                    (char::from(b), s, s.saturating_add(1))
                })
                .collect()
        }
        SingleByteCodePage::OemUnitedStates => {
            decode_table_spanned(line_bytes, content_start, &CP437_HIGH_TABLE)
        }
        SingleByteCodePage::OemMultilingualLatin1 => {
            decode_table_spanned(line_bytes, content_start, &CP850_HIGH_TABLE)
        }
        SingleByteCodePage::WindowsLatin1 => {
            decode_table_spanned(line_bytes, content_start, &WIN1252_HIGH_TABLE)
        }
    };

    Ok(Some(DecodedPhysicalLine {
        line_start: ByteOffset(content_start),
        chars_with_raw_spans,
        newline_raw_range,
        next_cursor: ByteOffset(next_cursor),
    }))
}

/// Maps a single byte `b` to its Unicode `char` using `high_table` for `0x80..=0xFF`.
///
/// # Arguments
/// * `b` - Input byte.
/// * `high_table` - 128-entry upper-half lookup table.
///
/// # Returns
/// Decoded Unicode `char`.
#[must_use]
fn decode_table_byte(b: u8, high_table: &[char; 128]) -> char {
    if b < 0x80 {
        char::from(b)
    } else {
        let idx = usize::from(b.saturating_sub(0x80));
        high_table.get(idx).copied().unwrap_or('\u{FFFD}')
    }
}

/// Maps each byte in `line_bytes` to `(char, raw_start, raw_end)` using `high_table`.
///
/// # Arguments
/// * `line_bytes` - Single-line byte slice without newline.
/// * `content_start` - Raw byte offset of `line_bytes[0]`.
/// * `high_table` - 128-entry upper-half lookup table.
///
/// # Returns
/// Vector of `(decoded_char, raw_start_byte, raw_end_byte)`.
fn decode_table_spanned(
    line_bytes: &[u8],
    content_start: usize,
    high_table: &[char; 128],
) -> Vec<(char, usize, usize)> {
    line_bytes
        .iter()
        .enumerate()
        .map(|(rel, &b)| {
            let s = content_start.saturating_add(rel);
            (decode_table_byte(b, high_table), s, s.saturating_add(1))
        })
        .collect()
}

/// Reads a single 16-bit code unit at byte offset `pos` in `raw` using `endianness`.
///
/// # Arguments
/// * `raw` - Raw UTF-16 byte buffer.
/// * `pos` - Byte offset.
/// * `endianness` - [`crate::types::Utf16Endian`] (`Little` vs `Big`).
///
/// # Returns
/// `Some(u16)` if two bytes are available at `pos`, else `None`.
#[must_use]
fn read_utf16_unit(raw: &[u8], pos: usize, endianness: crate::types::Utf16Endian) -> Option<u16> {
    let b0 = *raw.get(pos)?;
    let b1 = *raw.get(pos.saturating_add(1))?;
    Some(match endianness {
        crate::types::Utf16Endian::Little => u16::from_le_bytes([b0, b1]),
        crate::types::Utf16Endian::Big => u16::from_be_bytes([b0, b1]),
    })
}

/// Decodes UTF-16 `units` starting at `base_offset` into spanned characters `(char, start_byte, end_byte)`.
///
/// # Arguments
/// * `units` - 16-bit code units to decode.
/// * `base_offset` - Starting physical byte offset in the raw buffer.
/// * `codepage` - [`CodePage`] (`Utf16Le` or `Utf16Be`) for error reporting.
///
/// # Returns
/// `Ok(Vec<(char, usize, usize)>)` on valid UTF-16.
///
/// # Errors
/// Returns [`CmdError::EncodingFailure`] on unpaired surrogate code units.
fn decode_utf16_units_spanned(
    units: Vec<u16>,
    base_offset: usize,
    codepage: CodePage,
) -> Result<Vec<(char, usize, usize)>, CmdError> {
    let mut chars_with_raw_spans = Vec::with_capacity(units.len());
    let mut unit_cursor = base_offset;
    for res in char::decode_utf16(units) {
        let ch = res.map_err(|err| CmdError::EncodingFailure {
            offset: ByteOffset(unit_cursor),
            codepage,
            detail: err.to_string(),
        })?;
        let byte_width = ch.len_utf16().saturating_mul(2);
        let end_byte = unit_cursor.saturating_add(byte_width);
        chars_with_raw_spans.push((ch, unit_cursor, end_byte));
        unit_cursor = end_byte;
    }
    Ok(chars_with_raw_spans)
}

/// Decodes a single UTF-16LE or UTF-16BE physical line starting at `content_start`.
///
/// # Arguments
/// * `raw` - Full raw script bytes.
/// * `content_start` - Starting byte offset (must be 2-byte aligned).
/// * `endianness` - [`crate::types::Utf16Endian`] (`Little` for UTF-16LE, `Big` for UTF-16BE).
///
/// # Returns
/// `Ok(Some(DecodedPhysicalLine))` or `Ok(None)` on immediate `0x001A` / `0x0000`.
///
/// # Errors
/// Returns [`CmdError::EncodingByteOffsetMismatch`] on odd alignment, or
/// [`CmdError::EncodingFailure`] on truncated or unpaired surrogate units.
fn decode_utf16_line_at(
    raw: &[u8],
    content_start: usize,
    endianness: crate::types::Utf16Endian,
) -> Result<Option<DecodedPhysicalLine>, CmdError> {
    let codepage = match endianness {
        crate::types::Utf16Endian::Little => CodePage::Utf16Le,
        crate::types::Utf16Endian::Big => CodePage::Utf16Be,
    };
    if !content_start.is_multiple_of(2) {
        return Err(CmdError::EncodingByteOffsetMismatch {
            offset: ByteOffset(content_start),
            codepage,
        });
    }
    if !raw.len().saturating_sub(content_start).is_multiple_of(2) {
        return Err(CmdError::EncodingFailure {
            offset: ByteOffset(raw.len().saturating_sub(1)),
            codepage,
            detail: "odd byte length in UTF-16 stream".to_owned(),
        });
    }

    if matches!(
        read_utf16_unit(raw, content_start, endianness),
        None | Some(0x001A | 0x0000)
    ) {
        return Ok(None);
    }

    let mut units = Vec::new();
    let mut newline_raw_range = None;
    let mut next_cursor = raw.len();
    let mut idx = content_start;

    while let Some(unit) = read_utf16_unit(raw, idx, endianness) {
        if unit == 0x001A || unit == 0x0000 {
            next_cursor = raw.len();
            break;
        } else if unit == 0x000D {
            let nl_end = if read_utf16_unit(raw, idx.saturating_add(2), endianness) == Some(0x000A)
            {
                idx.saturating_add(4)
            } else {
                idx.saturating_add(2)
            };
            newline_raw_range = Some((idx, nl_end));
            next_cursor = nl_end;
            break;
        } else if unit == 0x000A {
            let nl_end = idx.saturating_add(2);
            newline_raw_range = Some((idx, nl_end));
            next_cursor = nl_end;
            break;
        }
        units.push(unit);
        idx = idx.saturating_add(2);
    }

    let chars_with_raw_spans = decode_utf16_units_spanned(units, content_start, codepage)?;

    Ok(Some(DecodedPhysicalLine {
        line_start: ByteOffset(content_start),
        chars_with_raw_spans,
        newline_raw_range,
        next_cursor: ByteOffset(next_cursor),
    }))
}

/// Decodes a raw script or stream byte buffer into a UTF-8 `String` according to the active [`CodePage`].
///
/// Stops reading immediately upon encountering ASCII `0x1A` (`Ctrl+Z` / `SUB`) or `0x00` (`NUL`)
/// in single-byte codepages, matching `cmd.exe` script reader semantics.
///
/// # Arguments
/// * `raw` - Raw byte slice from disk or memory.
/// * `codepage` - Active [`CodePage`] used when no UTF-16 BOM overrides it.
///
/// # Returns
/// `Ok(String)` containing the decoded text (with any leading BOM stripped).
///
/// # Errors
/// Returns [`CmdError::EncodingFailure`] if UTF-8, ASCII, or UTF-16 decoding encounters invalid sequences.
pub fn decode_script_bytes(raw: &[u8], codepage: CodePage) -> Result<String, CmdError> {
    let bom = DetectedBom::detect(raw);
    match (bom, codepage) {
        (DetectedBom::Utf16Le, _) | (DetectedBom::None, CodePage::Utf16Le) => {
            let payload = raw.strip_prefix(&[0xFF, 0xFE]).unwrap_or(raw);
            decode_utf16(payload, crate::types::Utf16Endian::Little)
        }
        (DetectedBom::Utf16Be, _) | (DetectedBom::None, CodePage::Utf16Be) => {
            let payload = raw.strip_prefix(&[0xFE, 0xFF]).unwrap_or(raw);
            decode_utf16(payload, crate::types::Utf16Endian::Big)
        }
        (DetectedBom::Utf8, _) | (_, CodePage::Utf8) => {
            let payload = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(raw);
            let truncated = truncate_at_eof_or_nul(payload);
            match std::str::from_utf8(truncated) {
                Ok(s) => Ok(s.to_owned()),
                Err(err) => Err(CmdError::EncodingFailure {
                    offset: ByteOffset(err.valid_up_to()),
                    codepage: CodePage::Utf8,
                    detail: err.to_string(),
                }),
            }
        }
        (_, CodePage::Ascii) => {
            let truncated = truncate_at_eof_or_nul(raw);
            if let Some(idx) = truncated.iter().position(|&b| b > 0x7F) {
                let byte = truncated.get(idx).copied().unwrap_or(0x80);
                return Err(CmdError::EncodingFailure {
                    offset: ByteOffset(idx),
                    codepage: CodePage::Ascii,
                    detail: format!("non-ASCII byte 0x{byte:02X}"),
                });
            }
            Ok(truncated.iter().map(|&b| char::from(b)).collect())
        }
        (_, CodePage::OemUnitedStates) => {
            let truncated = truncate_at_eof_or_nul(raw);
            Ok(decode_table(truncated, &CP437_HIGH_TABLE))
        }
        (_, CodePage::OemMultilingualLatin1) => {
            let truncated = truncate_at_eof_or_nul(raw);
            Ok(decode_table(truncated, &CP850_HIGH_TABLE))
        }
        (_, CodePage::WindowsLatin1) => {
            let truncated = truncate_at_eof_or_nul(raw);
            Ok(decode_table(truncated, &WIN1252_HIGH_TABLE))
        }
    }
}

/// Truncates a byte slice at the first occurrence of `0x1A` (`Ctrl+Z` EOF) or `0x00` (`NUL`).
///
/// # Arguments
/// * `bytes` - Input byte slice.
///
/// # Returns
/// Subslice up to (but excluding) the first `0x1A` or `0x00` byte.
#[must_use]
pub fn truncate_at_eof_or_nul(bytes: &[u8]) -> &[u8] {
    let limit = bytes
        .iter()
        .position(|&b| b == 0x1A || b == 0x00)
        .unwrap_or(bytes.len());
    bytes.get(..limit).unwrap_or(bytes)
}

/// Re-encodes `text` into raw script bytes preserving any BOM (`UTF-8`, `UTF-16LE`, `UTF-16BE`)
/// detected in `original_raw`, or encoding via `fallback_codepage` when no BOM was present.
///
/// # Arguments
/// * `text` - Rewritten UTF-8 script text.
/// * `original_raw` - Original raw file bytes used to detect leading BOM.
/// * `fallback_codepage` - [`CodePage`] used when `original_raw` had no BOM.
///
/// # Returns
/// Encoded byte vector preserving BOM and encoding fidelity.
#[must_use]
pub fn encode_script_preserving_bom(
    text: &str,
    original_raw: &[u8],
    fallback_codepage: CodePage,
) -> Vec<u8> {
    match DetectedBom::detect(original_raw) {
        DetectedBom::Utf8 => {
            let mut out = Vec::with_capacity(text.len().saturating_add(3));
            out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
            out.extend_from_slice(text.as_bytes());
            out
        }
        DetectedBom::Utf16Le => {
            let mut out = Vec::with_capacity(text.len().saturating_mul(2).saturating_add(2));
            out.extend_from_slice(&[0xFF, 0xFE]);
            for u in text.encode_utf16() {
                out.extend_from_slice(&u.to_le_bytes());
            }
            out
        }
        DetectedBom::Utf16Be => {
            let mut out = Vec::with_capacity(text.len().saturating_mul(2).saturating_add(2));
            out.extend_from_slice(&[0xFE, 0xFF]);
            for u in text.encode_utf16() {
                out.extend_from_slice(&u.to_be_bytes());
            }
            out
        }
        DetectedBom::None => encode_codepage_bytes(text, fallback_codepage),
    }
}

/// Encodes a text string into raw bytes according to the active [`CodePage`].
///
/// # Arguments
/// * `text` - String to encode.
/// * `codepage` - Active [`CodePage`].
///
/// # Returns
/// Encoded byte vector.
#[must_use]
pub fn encode_codepage_bytes(text: &str, codepage: CodePage) -> Vec<u8> {
    match codepage {
        CodePage::Utf8 => text.as_bytes().to_vec(),
        CodePage::Ascii => text
            .chars()
            .map(|c| if c.is_ascii() { c as u8 } else { b'?' })
            .collect(),
        CodePage::OemUnitedStates => encode_table(text, &CP437_HIGH_TABLE),
        CodePage::OemMultilingualLatin1 => encode_table(text, &CP850_HIGH_TABLE),
        CodePage::WindowsLatin1 => encode_table(text, &WIN1252_HIGH_TABLE),
        CodePage::Utf16Le => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        CodePage::Utf16Be => text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
    }
}

/// Encodes a text string into a single-byte buffer using a 128-entry high-byte (`0x80..=0xFF`) lookup table.
///
/// # Arguments
/// * `text` - Input text slice.
/// * `high_table` - Lookup table for bytes `0x80..=0xFF`.
///
/// # Returns
/// Encoded byte vector (substituting `b'?'` for unmappable characters).
fn encode_table(text: &str, high_table: &[char; 128]) -> Vec<u8> {
    text.chars()
        .map(|ch| {
            if ch.is_ascii() {
                ch as u8
            } else if let Some(idx) = high_table.iter().position(|&c| c == ch) {
                u8::try_from(idx).unwrap_or(0).saturating_add(0x80)
            } else {
                b'?'
            }
        })
        .collect()
}

/// Encodes a text string into raw bytes according to the active [`crate::types::OutputUnicodeMode`]
/// (`/A` ANSI/Codepage vs `/U` UTF-16LE) and [`CodePage`].
///
/// # Arguments
/// * `text` - String to encode.
/// * `unicode_mode` - Active [`crate::types::OutputUnicodeMode`].
/// * `codepage` - Active [`CodePage`] used when `unicode_mode` is [`crate::types::OutputUnicodeMode::Ansi`].
///
/// # Returns
/// Encoded byte vector.
#[must_use]
pub fn encode_output_bytes_with_codepage(
    text: &str,
    unicode_mode: crate::types::OutputUnicodeMode,
    codepage: CodePage,
) -> Vec<u8> {
    match unicode_mode {
        crate::types::OutputUnicodeMode::Ansi => encode_codepage_bytes(text, codepage),
        crate::types::OutputUnicodeMode::Utf16Le => encode_codepage_bytes(text, CodePage::Utf16Le),
    }
}

/// Decodes a single-byte buffer using a 128-entry high-byte (`0x80..=0xFF`) lookup table.
///
/// # Arguments
/// * `bytes` - Byte slice to decode.
/// * `high_table` - Lookup table for bytes `0x80..=0xFF`.
///
/// # Returns
/// Decoded UTF-8 `String`.
fn decode_table(bytes: &[u8], high_table: &[char; 128]) -> String {
    bytes
        .iter()
        .map(|&b| decode_table_byte(b, high_table))
        .collect()
}

/// Decodes a UTF-16 byte buffer (little-endian or big-endian) into a `String`, stopping at `0x001A` or `0x0000`.
///
/// # Arguments
/// * `bytes` - Raw UTF-16 byte slice (after BOM removal).
/// * `endianness` - [`crate::types::Utf16Endian`] (`Little` for UTF-16LE, `Big` for UTF-16BE).
///
/// # Returns
/// `Ok(String)` if valid UTF-16.
///
/// # Errors
/// Returns [`CmdError::EncodingFailure`] on odd byte length or unpaired surrogate code units.
fn decode_utf16(bytes: &[u8], endianness: crate::types::Utf16Endian) -> Result<String, CmdError> {
    let codepage = match endianness {
        crate::types::Utf16Endian::Little => CodePage::Utf16Le,
        crate::types::Utf16Endian::Big => CodePage::Utf16Be,
    };
    if !bytes.len().is_multiple_of(2) {
        return Err(CmdError::EncodingFailure {
            offset: ByteOffset(bytes.len().saturating_sub(1)),
            codepage,
            detail: "odd byte length in UTF-16 stream".to_owned(),
        });
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    let mut idx = 0usize;
    while let Some(unit) = read_utf16_unit(bytes, idx, endianness) {
        if unit == 0x001A || unit == 0x0000 {
            break;
        }
        units.push(unit);
        idx = idx.saturating_add(2);
    }
    let spanned = decode_utf16_units_spanned(units, 0, codepage)?;
    Ok(spanned.into_iter().map(|(ch, _, _)| ch).collect())
}

#[cfg(test)]
/// Unit tests for BOM detection, incremental physical-line decoding, and codepage round-tripping.
mod tests {
    use super::*;

    /// Verifies UTF-8, UTF-16LE, UTF-16BE, and absent BOM detection.
    #[test]
    fn test_bom_detection() {
        assert_eq!(
            DetectedBom::detect(&[0xEF, 0xBB, 0xBF, b'a']),
            DetectedBom::Utf8
        );
        assert_eq!(DetectedBom::Utf8.byte_len(), 3);
        assert_eq!(
            DetectedBom::detect(&[0xFF, 0xFE, b'a', 0]),
            DetectedBom::Utf16Le
        );
        assert_eq!(DetectedBom::Utf16Le.byte_len(), 2);
        assert_eq!(
            DetectedBom::detect(&[0xFE, 0xFF, 0, b'a']),
            DetectedBom::Utf16Be
        );
        assert_eq!(DetectedBom::Utf16Be.byte_len(), 2);
        assert_eq!(DetectedBom::detect(b"@echo off"), DetectedBom::None);
        assert_eq!(DetectedBom::None.byte_len(), 0);
    }

    /// Verifies UTF-8 decoding, `0x1A` Ctrl+Z EOF truncation, and invalid UTF-8 rejection.
    #[test]
    fn test_decode_utf8_and_ctrl_z_eof() {
        let mut raw = vec![0xEF, 0xBB, 0xBF];
        raw.extend_from_slice(b"@echo hi");
        raw.push(0x1A);
        raw.extend_from_slice(b"ignored");
        let decoded = decode_script_bytes(&raw, CodePage::Utf8);
        assert_eq!(decoded, Ok("@echo hi".to_owned()));

        let bad_utf8 = &[0xFF, 0xFF, 0xFF];
        assert!(decode_script_bytes(bad_utf8, CodePage::Utf8).is_err());
    }

    /// Verifies 7-bit ASCII, CP437, CP850, and Windows-1252 lookup table decoding.
    #[test]
    fn test_decode_ascii_and_tables() {
        assert_eq!(
            decode_script_bytes(&[b'h', b'e', b'l', b'l', b'o', 0x00, b'w'], CodePage::Ascii),
            Ok("hello".to_owned())
        );
        assert!(decode_script_bytes(&[0x80], CodePage::Ascii).is_err());

        let cp437 = decode_script_bytes(&[b'A', 0x80, 0xB3], CodePage::OemUnitedStates);
        assert_eq!(cp437, Ok("A\u{00C7}\u{2502}".to_owned()));

        let cp850 = decode_script_bytes(&[b'B', 0x80], CodePage::OemMultilingualLatin1);
        assert_eq!(cp850, Ok("B\u{00C7}".to_owned()));

        let win1252 = decode_script_bytes(&[b'C', 0x80], CodePage::WindowsLatin1);
        assert_eq!(win1252, Ok("C\u{20AC}".to_owned()));
    }

    /// Verifies UTF-16LE and UTF-16BE decoding with BOM, NUL, and `0x001A` handling.
    #[test]
    fn test_decode_utf16_le_and_be() {
        let le_bytes = [0xFF, 0xFE, b'h', 0x00, b'i', 0x00, 0x1A, 0x00, b'x', 0x00];
        assert_eq!(
            decode_script_bytes(&le_bytes, CodePage::Utf8),
            Ok("hi".to_owned())
        );

        let be_bytes = [0xFE, 0xFF, 0x00, b'o', 0x00, b'k', 0x00, 0x00];
        assert_eq!(
            decode_script_bytes(&be_bytes, CodePage::Utf8),
            Ok("ok".to_owned())
        );

        let odd_le = [0xFF, 0xFE, b'h'];
        assert!(decode_script_bytes(&odd_le, CodePage::Utf16Le).is_err());

        let unpaired_surrogate = [0x00, 0xD8];
        assert!(decode_script_bytes(&unpaired_surrogate, CodePage::Utf16Le).is_err());

        let unpaired_be = [0xD8, 0x00];
        assert!(decode_script_bytes(&unpaired_be, CodePage::Utf16Be).is_err());

        let ansi_encoded = encode_output_bytes_with_codepage(
            "A",
            crate::types::OutputUnicodeMode::Ansi,
            CodePage::Utf8,
        );
        assert_eq!(ansi_encoded, vec![b'A']);
        let utf16_encoded = encode_output_bytes_with_codepage(
            "A",
            crate::types::OutputUnicodeMode::Utf16Le,
            CodePage::Utf8,
        );
        assert_eq!(utf16_encoded, vec![b'A', 0x00]);

        assert_eq!(
            encode_codepage_bytes("A\u{00C7}\u{2603}", CodePage::Ascii),
            vec![b'A', b'?', b'?']
        );
        assert_eq!(
            encode_codepage_bytes("A\u{00C7}\u{2603}", CodePage::OemUnitedStates),
            vec![b'A', 0x80, b'?']
        );
        assert_eq!(
            encode_codepage_bytes("B\u{00F8}\u{2603}", CodePage::OemMultilingualLatin1),
            vec![b'B', 0x9B, b'?']
        );
        assert_eq!(
            encode_codepage_bytes("C\u{20AC}\u{2603}", CodePage::WindowsLatin1),
            vec![b'C', 0x80, b'?']
        );
        assert_eq!(
            encode_codepage_bytes("A", CodePage::Utf16Be),
            vec![0x00, b'A']
        );
    }

    /// Verifies incremental physical line decoding across mid-script CHCP switches and 8-bit codepages.
    #[test]
    fn test_decode_physical_line_at_mid_script_chcp_and_byte_codepages() {
        // Line 1: CP437 high byte 0xB3 (invalid UTF-8!) + CRLF
        // Line 2: "chcp 65001" + LF
        // Line 3: UTF-8 multi-byte "echo \u{2603}" + CR + Ctrl+Z
        let mut raw = vec![b'r', b'e', b'm', b' ', 0xB3, 0x0D, 0x0A];
        raw.extend_from_slice(b"chcp 65001");
        raw.push(0x0A);
        raw.extend_from_slice("echo \u{2603}".as_bytes());
        raw.push(0x0D);
        raw.push(0x1A);
        raw.extend_from_slice(b"after_eof");

        // Decode line 1 under CP437
        let l1 = decode_physical_line_at(&raw, ByteOffset(0), CodePage::OemUnitedStates)
            .ok()
            .flatten();
        assert_eq!(
            l1.as_ref().map(|l| l
                .chars_with_raw_spans
                .iter()
                .map(|c| c.0)
                .collect::<String>()),
            Some("rem \u{2502}".to_owned())
        );
        assert_eq!(l1.as_ref().map(|l| l.next_cursor), Some(ByteOffset(7)));

        // Decode line 2 under CP850 / Win1252 / Ascii
        let l2 = decode_physical_line_at(&raw, ByteOffset(7), CodePage::Ascii)
            .ok()
            .flatten();
        assert_eq!(l2.as_ref().map(|l| l.next_cursor), Some(ByteOffset(18)));

        // Decode line 3 under UTF-8 without re-decoding line 1!
        let l3 = decode_physical_line_at(&raw, ByteOffset(18), CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(
            l3.as_ref().map(|l| l
                .chars_with_raw_spans
                .iter()
                .map(|c| c.0)
                .collect::<String>()),
            Some("echo \u{2603}".to_owned())
        );
        let next = l3.map_or(ByteOffset(0), |l| l.next_cursor);
        // Next byte is 0x1A -> returns Ok(None)
        assert_eq!(
            decode_physical_line_at(&raw, next, CodePage::Utf8),
            Ok(None)
        );
        // At exact end -> Ok(None)
        assert_eq!(
            decode_physical_line_at(&raw, ByteOffset(raw.len()), CodePage::Utf8),
            Ok(None)
        );
        // Past end -> Err(EncodingByteOffsetMismatch)
        assert!(decode_physical_line_at(&raw, ByteOffset(raw.len() + 1), CodePage::Utf8).is_err());

        // CP850 & Win1252 single-line decode + Ctrl+Z mid-line
        let cp850_line = [0x80, 0x1A, b'x'];
        let dl850 =
            decode_physical_line_at(&cp850_line, ByteOffset(0), CodePage::OemMultilingualLatin1)
                .ok()
                .flatten();
        assert_eq!(
            dl850.map(|l| (l.chars_with_raw_spans, l.next_cursor)),
            Some((vec![('\u{00C7}', 0, 1)], ByteOffset(3)))
        );
        let win1252_line = [0x80];
        let dl1252 = decode_physical_line_at(&win1252_line, ByteOffset(0), CodePage::WindowsLatin1)
            .ok()
            .flatten();
        assert_eq!(
            dl1252.map(|l| l.chars_with_raw_spans),
            Some(vec![('\u{20AC}', 0, 1)])
        );

        // Error cases in decode_byte_line_at
        assert!(decode_physical_line_at(&[0xFF], ByteOffset(0), CodePage::Utf8).is_err());
        assert!(decode_physical_line_at(&[0x80], ByteOffset(0), CodePage::Ascii).is_err());
    }

    /// Verifies physical line decoding for BOMs, mid-line NUL bytes, and UTF-16LE/BE streams.
    #[test]
    fn test_decode_physical_line_at_bom_nul_and_utf16_streams() {
        // UTF-8 BOM at offset 0 and subsequent line at offset > 0
        let utf8_bom_only = [0xEF, 0xBB, 0xBF];
        assert_eq!(
            decode_physical_line_at(&utf8_bom_only, ByteOffset(0), CodePage::Ascii),
            Ok(None)
        );
        let ascii_bom_lines = [0xEF, 0xBB, 0xBF, b'a', 0x0A, b'b'];
        let ascii_second =
            decode_physical_line_at(&ascii_bom_lines, ByteOffset(5), CodePage::Ascii)
                .ok()
                .flatten();
        assert_eq!(
            ascii_second.map(|l| l.chars_with_raw_spans),
            Some(vec![('b', 5, 6)])
        );

        // Mid-line NUL (0x00) termination in 8-bit and UTF-16 streams
        let nul_byte_line = [b'x', 0x00, b'y'];
        let dl_nul = decode_physical_line_at(&nul_byte_line, ByteOffset(0), CodePage::Ascii)
            .ok()
            .flatten();
        assert_eq!(
            dl_nul.map(|l| (l.chars_with_raw_spans, l.next_cursor)),
            Some((vec![('x', 0, 1)], ByteOffset(3)))
        );
        let nul_utf16_line = [b'x', 0x00, 0x00, 0x00, b'y', 0x00];
        let u_nul = decode_physical_line_at(&nul_utf16_line, ByteOffset(0), CodePage::Utf16Le)
            .ok()
            .flatten();
        assert_eq!(
            u_nul.map(|l| (l.chars_with_raw_spans, l.next_cursor)),
            Some((vec![('x', 0, 2)], ByteOffset(6)))
        );
        let utf8_bom_nul_lines = [0xEF, 0xBB, 0xBF, b'a', 0x0A, b'b', 0x00, b'x'];
        let utf8_second =
            decode_physical_line_at(&utf8_bom_nul_lines, ByteOffset(5), CodePage::Utf8)
                .ok()
                .flatten();
        assert_eq!(
            utf8_second.map(|l| (l.chars_with_raw_spans, l.next_cursor)),
            Some((vec![('b', 5, 6)], ByteOffset(8)))
        );

        // UTF-16LE NUL mid-line termination
        let utf16_nul_mid = [b'q', 0x00, 0x00, 0x00, b'z', 0x00];
        let unm = decode_physical_line_at(&utf16_nul_mid, ByteOffset(0), CodePage::Utf16Le)
            .ok()
            .flatten();
        assert_eq!(
            unm.map(|l| (l.chars_with_raw_spans, l.next_cursor)),
            Some((vec![('q', 0, 2)], ByteOffset(6)))
        );

        // UTF-16LE & UTF-16BE incremental line decoding (CRLF, LF, CR, Ctrl+Z, misalignment, odd len, surrogate)
        let little_endian_script = [
            0xFF, 0xFE, b'a', 0x00, 0x0D, 0x00, 0x0A, 0x00, b'b', 0x00, 0x0A, 0x00, b'c', 0x00,
            0x0D, 0x00, b'd', 0x00, 0x1A, 0x00,
        ];
        let u1 = decode_physical_line_at(&little_endian_script, ByteOffset(0), CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(u1.as_ref().map(|l| l.next_cursor), Some(ByteOffset(8)));
        let u2 = decode_physical_line_at(&little_endian_script, ByteOffset(8), CodePage::Utf16Le)
            .ok()
            .flatten();
        assert_eq!(u2.as_ref().map(|l| l.next_cursor), Some(ByteOffset(12)));
        let u3 = decode_physical_line_at(&little_endian_script, ByteOffset(12), CodePage::Utf16Le)
            .ok()
            .flatten();
        assert_eq!(u3.as_ref().map(|l| l.next_cursor), Some(ByteOffset(16)));
        let u4 = decode_physical_line_at(&little_endian_script, ByteOffset(16), CodePage::Utf16Le)
            .ok()
            .flatten();
        assert_eq!(u4.as_ref().map(|l| l.next_cursor), Some(ByteOffset(20)));
        assert_eq!(
            decode_physical_line_at(&[0x1A, 0x00], ByteOffset(0), CodePage::Utf16Le),
            Ok(None)
        );

        let big_endian_script = [0xFE, 0xFF, 0x00, b'z'];
        let ube = decode_physical_line_at(&big_endian_script, ByteOffset(0), CodePage::Utf8)
            .ok()
            .flatten();
        assert_eq!(ube.map(|l| l.chars_with_raw_spans), Some(vec![('z', 2, 4)]));

        // Misaligned offset, odd byte len, and unpaired surrogate in UTF-16
        assert!(
            decode_physical_line_at(&little_endian_script, ByteOffset(3), CodePage::Utf16Le)
                .is_err()
        );
        assert!(
            decode_physical_line_at(&[b'a', 0x00, b'b'], ByteOffset(0), CodePage::Utf16Le).is_err()
        );
        assert!(decode_physical_line_at(&[0x00, 0xD8], ByteOffset(0), CodePage::Utf16Le).is_err());

        assert_eq!(
            encode_script_preserving_bom("hi", &[0xEF, 0xBB, 0xBF, b'x'], CodePage::Utf8),
            vec![0xEF, 0xBB, 0xBF, b'h', b'i']
        );
        assert_eq!(
            encode_script_preserving_bom("hi", &[0xFF, 0xFE, b'x', 0x00], CodePage::Utf8),
            vec![0xFF, 0xFE, b'h', 0x00, b'i', 0x00]
        );
        assert_eq!(
            encode_script_preserving_bom("hi", &[0xFE, 0xFF, 0x00, b'x'], CodePage::Utf8),
            vec![0xFE, 0xFF, 0x00, b'h', 0x00, b'i']
        );
    }
}
