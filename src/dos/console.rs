//! MS-DOS `CON` BIOS scan-code interactive line editor (`DOSKEY` / `COMMAND.COM`) and REPL driver.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use derive_more::Display;

use crate::cli::{repl_open_paren_depth, strip_odd_trailing_caret};
use crate::dos::kernel::DosKernelApi;
use crate::dos::types::{BiosKeyEvent, BiosScanCode};
use crate::error::CmdError;
use crate::reader::encoding::{decode_script_bytes, encode_codepage_bytes};
use crate::runtime::{
    ByteStreamIo, ByteStreamWrite, InMemoryByteReader, Interpreter, write_byte_stream_gracefully,
};
use crate::types::{
    CRLF, CompletionScope, DoskeyEditMode, EchoState, ExitCode, InterruptState, fold_win32_case,
};

/// Outcome of reading a single interactive command line via [`DosConsoleLineEditor`].
#[derive(Debug, Clone, PartialEq, Eq, Display)]
pub enum DosLineReadOutcome {
    /// User submitted a line with `Enter` (`0x0D` / `0x0A`).
    #[display("line({_0})")]
    Line(String),
    /// User cancelled the current line with `Ctrl+C` (`0x03`) or `Ctrl+Break`.
    #[display("interrupted")]
    Interrupted,
    /// User signaled end-of-input (`Ctrl+Z` on an empty buffer or BIOS key stream EOF).
    #[display("eof")]
    Eof,
}

/// Active completion cycle state across consecutive `Tab` / `Ctrl+F` / `Ctrl+D` presses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TabCycleState {
    /// Original line prefix before the first `Tab` press in this cycle.
    base_prefix: String,
    /// Active [`CompletionScope`] (`FilesAndDirectories` vs `DirectoriesOnly`).
    scope: CompletionScope,
    /// Next 0-based candidate index to request.
    next_index: usize,
}

/// Cursor motion direction prior to redrawing after a single-character deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeleteOrigin {
    /// `Backspace`: emit `\x08` before redrawing the shifted tail.
    Backspace,
    /// `Delete`: cursor already sits on the deleted slot.
    DeleteAtCursor,
}

/// Mutable buffer state while editing a single physical MS-DOS command line.
struct ActiveEditBuffer {
    /// Decoded characters currently in the line buffer.
    chars: Vec<char>,
    /// Current 0-based character cursor (`0..=chars.len()`).
    cursor: usize,
    /// Current index into `interp.console.history()`, if navigating history.
    history_idx: Option<usize>,
    /// Active `Tab` / `Ctrl+F` / `Ctrl+D` completion cycle.
    tab_cycle: Option<TabCycleState>,
    /// Prefix string captured at the start of an `F8` prefix-search cycle.
    f8_prefix: Option<(String, usize)>,
}

impl ActiveEditBuffer {
    /// Creates an empty [`ActiveEditBuffer`].
    ///
    /// # Returns
    /// Fresh [`ActiveEditBuffer`].
    const fn new() -> Self {
        Self {
            chars: Vec::new(),
            cursor: 0,
            history_idx: None,
            tab_cycle: None,
            f8_prefix: None,
        }
    }

    /// Collects `self.chars` into a `String`.
    ///
    /// # Returns
    /// Current buffer text.
    #[must_use]
    fn as_string(&self) -> String {
        self.chars.iter().copied().collect()
    }

    /// Replaces the entire buffer contents with `new_text`, moving the cursor to the end and
    /// echoing the visual update to `con_out`.
    ///
    /// # Arguments
    /// * `new_text` - Replacement line text.
    /// * `interp` - Immutable [`Interpreter`] for OEM encoding.
    /// * `con_out` - Console output stream.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from `con_out`.
    fn replace_entire_line(
        &mut self,
        new_text: &str,
        interp: &Interpreter,
        con_out: &mut dyn ByteStreamWrite,
    ) -> Result<(), CmdError> {
        let old_len = self.chars.len();
        let back_to_start = "\x08".repeat(self.cursor);
        let clear_spaces = " ".repeat(old_len);
        let back_again = "\x08".repeat(old_len);
        let new_bytes = encode_codepage_bytes(new_text, interp.console.codepage);
        write_byte_stream_gracefully(con_out, back_to_start.as_bytes())?;
        write_byte_stream_gracefully(con_out, clear_spaces.as_bytes())?;
        write_byte_stream_gracefully(con_out, back_again.as_bytes())?;
        write_byte_stream_gracefully(con_out, &new_bytes)?;
        con_out.flush_stream()?;
        self.chars = new_text.chars().collect();
        self.cursor = self.chars.len();
        Ok(())
    }
}

/// Interactive MS-DOS BIOS scan-code line editor implementing `COMMAND.COM` template keys (`F1`, `F3`)
/// and `DOSKEY` history/navigation (`Up`, `Down`, `PgUp`, `PgDn`, `Home`, `End`, `Ins`, `Del`, `F7`, `F8`, `F9`, `Tab`).
#[derive(Debug, Clone, Default)]
pub struct DosConsoleLineEditor {
    /// Previous submitted command line acting as the MS-DOS `F1` / `F3` / `Right` template.
    template: Vec<char>,
}

impl DosConsoleLineEditor {
    /// Creates a new [`DosConsoleLineEditor`] with an empty template buffer.
    ///
    /// # Returns
    /// Initialized [`DosConsoleLineEditor`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            template: Vec::new(),
        }
    }

    /// Reads and edits one physical line from `kernel` (`INT 16h`), echoing updates to `con_out`.
    ///
    /// # Arguments
    /// * `interp` - Mutable [`Interpreter`] session (used for `DOSKEY` history, edit mode, and `/F:ON` completion).
    /// * `kernel` - Mutable [`DosKernelApi`] supplying `poll_ctrl_break` and `read_console_key`.
    /// * `prompt` - Prompt string already written (re-displayed if `F7` or `F9` prints an inline overlay).
    /// * `con_out` - Console output byte stream.
    ///
    /// # Returns
    /// `Ok(DosLineReadOutcome)`.
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading BIOS keys or writing console output fails.
    pub fn read_line(
        &mut self,
        interp: &mut Interpreter,
        kernel: &mut dyn DosKernelApi,
        prompt: &str,
        con_out: &mut dyn ByteStreamWrite,
    ) -> Result<DosLineReadOutcome, CmdError> {
        let mut edit = ActiveEditBuffer::new();
        loop {
            if kernel.poll_ctrl_break() == InterruptState::Pending {
                write_byte_stream_gracefully(con_out, format!("^C{CRLF}").as_bytes())?;
                con_out.flush_stream()?;
                return Ok(DosLineReadOutcome::Interrupted);
            }
            let Some(ev) = kernel.read_console_key()? else {
                if edit.chars.is_empty() {
                    return Ok(DosLineReadOutcome::Eof);
                }
                let line = edit.as_string();
                self.commit_submitted_line(interp, &line);
                write_byte_stream_gracefully(con_out, CRLF.as_bytes())?;
                con_out.flush_stream()?;
                return Ok(DosLineReadOutcome::Line(line));
            };
            match ev {
                BiosKeyEvent::Char(b) => {
                    if let Some(done) = self.handle_char_key(b, &mut edit, interp, con_out)? {
                        return Ok(done);
                    }
                }
                BiosKeyEvent::Extended(scan) => {
                    edit.tab_cycle = None;
                    if scan != BiosScanCode::F8 {
                        edit.f8_prefix = None;
                    }
                    self.handle_extended_scan_code(
                        scan, &mut edit, interp, kernel, prompt, con_out,
                    )?;
                }
            }
        }
    }

    /// Updates `self.template` and `interp.console` history upon submitting `line`.
    ///
    /// # Arguments
    /// * `interp` - Mutable [`Interpreter`].
    /// * `line` - Submitted command line.
    fn commit_submitted_line(&mut self, interp: &mut Interpreter, line: &str) {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            self.template = line.chars().collect();
            interp.console.record_history(trimmed);
        }
    }

    /// Processes an ASCII / OEM single-byte key event `b`.
    ///
    /// # Arguments
    /// * `b` - Raw ASCII/OEM byte.
    /// * `edit` - Mutable [`ActiveEditBuffer`].
    /// * `interp` - Mutable [`Interpreter`].
    /// * `con_out` - Console output stream.
    ///
    /// # Returns
    /// `Ok(Some(DosLineReadOutcome))` when the line finishes, or `Ok(None)` to keep editing.
    ///
    /// # Errors
    /// Propagates [`CmdError`] on console write failure.
    fn handle_char_key(
        &mut self,
        b: u8,
        edit: &mut ActiveEditBuffer,
        interp: &mut Interpreter,
        con_out: &mut dyn ByteStreamWrite,
    ) -> Result<Option<DosLineReadOutcome>, CmdError> {
        if !matches!(b, 0x09 | 0x06 | 0x04) {
            edit.tab_cycle = None;
        }
        edit.f8_prefix = None;

        match b {
            0x03 => {
                write_byte_stream_gracefully(con_out, format!("^C{CRLF}").as_bytes())?;
                con_out.flush_stream()?;
                Ok(Some(DosLineReadOutcome::Interrupted))
            }
            0x1A if edit.chars.is_empty() => Ok(Some(DosLineReadOutcome::Eof)),
            0x0D | 0x0A => {
                let line = edit.as_string();
                self.commit_submitted_line(interp, &line);
                write_byte_stream_gracefully(con_out, CRLF.as_bytes())?;
                con_out.flush_stream()?;
                Ok(Some(DosLineReadOutcome::Line(line)))
            }
            0x08 => {
                if edit.cursor > 0 {
                    edit.cursor = edit.cursor.saturating_sub(1);
                    edit.chars.remove(edit.cursor);
                    Self::redraw_tail_after_delete(edit, interp, DeleteOrigin::Backspace, con_out)?;
                }
                Ok(None)
            }
            0x1B => {
                edit.replace_entire_line("", interp, con_out)?;
                Ok(None)
            }
            0x09 | 0x06 | 0x04 => {
                let scope = if b == 0x04 {
                    CompletionScope::DirectoriesOnly
                } else {
                    CompletionScope::FilesAndDirectories
                };
                Self::apply_tab_completion(edit, scope, interp, con_out)?;
                Ok(None)
            }
            byte if byte >= 0x20 => {
                let ch = decode_script_bytes(&[byte], interp.console.codepage)
                    .ok()
                    .and_then(|s| s.chars().next())
                    .unwrap_or('?');
                Self::insert_or_overstrike_char(ch, edit, interp, con_out)?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Inserts or overstrikes `ch` at `edit.cursor` according to `interp.console.doskey_edit_mode`.
    ///
    /// # Arguments
    /// * `ch` - Decoded character to insert.
    /// * `edit` - Mutable [`ActiveEditBuffer`].
    /// * `interp` - Immutable [`Interpreter`].
    /// * `con_out` - Console output stream.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Propagates [`CmdError`] on console write failure.
    fn insert_or_overstrike_char(
        ch: char,
        edit: &mut ActiveEditBuffer,
        interp: &Interpreter,
        con_out: &mut dyn ByteStreamWrite,
    ) -> Result<(), CmdError> {
        if interp.console.doskey_edit_mode == DoskeyEditMode::Overstrike
            && let Some(slot) = edit.chars.get_mut(edit.cursor)
        {
            *slot = ch;
            edit.cursor = edit.cursor.saturating_add(1);
            let mut tmp = [0u8; 4];
            let bytes = encode_codepage_bytes(ch.encode_utf8(&mut tmp), interp.console.codepage);
            write_byte_stream_gracefully(con_out, &bytes)?;
            return con_out.flush_stream();
        }
        edit.chars.insert(edit.cursor, ch);
        let tail: String = edit
            .chars
            .get(edit.cursor..)
            .unwrap_or(&[])
            .iter()
            .collect();
        edit.cursor = edit.cursor.saturating_add(1);
        let tail_bytes = encode_codepage_bytes(&tail, interp.console.codepage);
        let back_count = edit.chars.len().saturating_sub(edit.cursor);
        let backspaces = "\x08".repeat(back_count);
        write_byte_stream_gracefully(con_out, &tail_bytes)?;
        write_byte_stream_gracefully(con_out, backspaces.as_bytes())?;
        con_out.flush_stream()
    }

    /// Redraws the trailing characters after a `Backspace` or `Delete` removal.
    ///
    /// # Arguments
    /// * `edit` - Mutable [`ActiveEditBuffer`].
    /// * `interp` - Immutable [`Interpreter`].
    /// * `origin` - [`DeleteOrigin`] (`Backspace` steps back `\x08` first; `DeleteAtCursor` stays put).
    /// * `con_out` - Console output stream.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] on write failure.
    fn redraw_tail_after_delete(
        edit: &ActiveEditBuffer,
        interp: &Interpreter,
        origin: DeleteOrigin,
        con_out: &mut dyn ByteStreamWrite,
    ) -> Result<(), CmdError> {
        if origin == DeleteOrigin::Backspace {
            write_byte_stream_gracefully(con_out, b"\x08")?;
        }
        let tail: String = edit
            .chars
            .get(edit.cursor..)
            .unwrap_or(&[])
            .iter()
            .collect();
        let tail_bytes = encode_codepage_bytes(&tail, interp.console.codepage);
        let back_count = tail.chars().count().saturating_add(1);
        write_byte_stream_gracefully(con_out, &tail_bytes)?;
        write_byte_stream_gracefully(con_out, b" ")?;
        write_byte_stream_gracefully(con_out, "\x08".repeat(back_count).as_bytes())?;
        con_out.flush_stream()
    }

    /// Applies `/F:ON` filename completion at the current buffer end, cycling candidates on repeated presses.
    ///
    /// # Arguments
    /// * `edit` - Mutable [`ActiveEditBuffer`].
    /// * `scope` - [`CompletionScope`].
    /// * `interp` - Immutable [`Interpreter`].
    /// * `con_out` - Console output stream.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] on write failure.
    fn apply_tab_completion(
        edit: &mut ActiveEditBuffer,
        scope: CompletionScope,
        interp: &Interpreter,
        con_out: &mut dyn ByteStreamWrite,
    ) -> Result<(), CmdError> {
        let state = match edit.tab_cycle.take() {
            Some(prev) if prev.scope == scope => prev,
            _ => TabCycleState {
                base_prefix: edit.as_string(),
                scope,
                next_index: 0,
            },
        };
        let completed = interp.complete_line_at_cursor(&state.base_prefix, scope, state.next_index);
        edit.replace_entire_line(&completed, interp, con_out)?;
        edit.tab_cycle = Some(TabCycleState {
            base_prefix: state.base_prefix,
            scope,
            next_index: state.next_index.saturating_add(1),
        });
        Ok(())
    }

    /// Handles an extended two-byte BIOS scan code (`Arrows`, `Home`, `End`, `Ins`, `Del`, `PgUp`, `PgDn`, `F1`–`F9`).
    ///
    /// # Arguments
    /// * `scan` - [`BiosScanCode`].
    /// * `edit` - Mutable [`ActiveEditBuffer`].
    /// * `interp` - Mutable [`Interpreter`].
    /// * `kernel` - Mutable [`DosKernelApi`] (used by `F9` line-number prompt).
    /// * `prompt` - Active prompt string.
    /// * `con_out` - Console output stream.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`].
    fn handle_extended_scan_code(
        &self,
        scan: BiosScanCode,
        edit: &mut ActiveEditBuffer,
        interp: &mut Interpreter,
        kernel: &mut dyn DosKernelApi,
        prompt: &str,
        con_out: &mut dyn ByteStreamWrite,
    ) -> Result<(), CmdError> {
        match scan {
            BiosScanCode::Left => {
                if edit.cursor > 0 {
                    edit.cursor = edit.cursor.saturating_sub(1);
                    write_byte_stream_gracefully(con_out, b"\x08")?;
                    con_out.flush_stream()?;
                }
            }
            BiosScanCode::Right => {
                if let Some(&ch) = edit.chars.get(edit.cursor) {
                    edit.cursor = edit.cursor.saturating_add(1);
                    let mut tmp = [0u8; 4];
                    let bytes =
                        encode_codepage_bytes(ch.encode_utf8(&mut tmp), interp.console.codepage);
                    write_byte_stream_gracefully(con_out, &bytes)?;
                    con_out.flush_stream()?;
                } else if let Some(&tmpl_ch) = self.template.get(edit.cursor) {
                    Self::insert_or_overstrike_char(tmpl_ch, edit, interp, con_out)?;
                }
            }
            BiosScanCode::Home => {
                if edit.cursor > 0 {
                    let back = "\x08".repeat(edit.cursor);
                    edit.cursor = 0;
                    write_byte_stream_gracefully(con_out, back.as_bytes())?;
                    con_out.flush_stream()?;
                }
            }
            BiosScanCode::End => {
                if edit.cursor < edit.chars.len() {
                    let rest: String = edit
                        .chars
                        .get(edit.cursor..)
                        .unwrap_or(&[])
                        .iter()
                        .collect();
                    edit.cursor = edit.chars.len();
                    let bytes = encode_codepage_bytes(&rest, interp.console.codepage);
                    write_byte_stream_gracefully(con_out, &bytes)?;
                    con_out.flush_stream()?;
                }
            }
            BiosScanCode::Insert => {
                interp.console.doskey_edit_mode = match interp.console.doskey_edit_mode {
                    DoskeyEditMode::Insert => DoskeyEditMode::Overstrike,
                    DoskeyEditMode::Overstrike => DoskeyEditMode::Insert,
                };
            }
            BiosScanCode::Delete => {
                if edit.cursor < edit.chars.len() {
                    edit.chars.remove(edit.cursor);
                    Self::redraw_tail_after_delete(
                        edit,
                        interp,
                        DeleteOrigin::DeleteAtCursor,
                        con_out,
                    )?;
                }
            }
            other @ (BiosScanCode::Up
            | BiosScanCode::PageUp
            | BiosScanCode::Down
            | BiosScanCode::PageDown
            | BiosScanCode::F1
            | BiosScanCode::F3
            | BiosScanCode::F7
            | BiosScanCode::F8
            | BiosScanCode::F9
            | BiosScanCode::Other(_)) => {
                self.handle_history_and_template_keys(
                    other, edit, interp, kernel, prompt, con_out,
                )?;
            }
        }
        Ok(())
    }

    /// Handles `Up`, `Down`, `PgUp`, `PgDn`, `F1`, `F3`, `F7`, `F8`, and `F9` scan codes.
    ///
    /// # Arguments
    /// * `scan` - [`BiosScanCode`].
    /// * `edit` - Mutable [`ActiveEditBuffer`].
    /// * `interp` - Immutable [`Interpreter`].
    /// * `kernel` - Mutable [`DosKernelApi`].
    /// * `prompt` - Active prompt string.
    /// * `con_out` - Console output stream.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`].
    fn handle_history_and_template_keys(
        &self,
        scan: BiosScanCode,
        edit: &mut ActiveEditBuffer,
        interp: &Interpreter,
        kernel: &mut dyn DosKernelApi,
        prompt: &str,
        con_out: &mut dyn ByteStreamWrite,
    ) -> Result<(), CmdError> {
        let hist = interp.console.history();
        match scan {
            BiosScanCode::Up => {
                let idx = edit
                    .history_idx
                    .map_or_else(|| hist.len().saturating_sub(1), |i| i.saturating_sub(1));
                if let Some(entry) = hist.get(idx) {
                    edit.history_idx = Some(idx);
                    edit.replace_entire_line(entry, interp, con_out)?;
                }
            }
            BiosScanCode::Down => {
                if let Some(cur) = edit.history_idx {
                    let next = cur.saturating_add(1);
                    if let Some(entry) = hist.get(next) {
                        edit.history_idx = Some(next);
                        edit.replace_entire_line(entry, interp, con_out)?;
                    } else {
                        edit.history_idx = None;
                        edit.replace_entire_line("", interp, con_out)?;
                    }
                }
            }
            BiosScanCode::PageUp => {
                if let Some(entry) = hist.front() {
                    edit.history_idx = Some(0);
                    edit.replace_entire_line(entry, interp, con_out)?;
                }
            }
            BiosScanCode::PageDown => {
                if let Some(entry) = hist.back() {
                    edit.history_idx = Some(hist.len().saturating_sub(1));
                    edit.replace_entire_line(entry, interp, con_out)?;
                }
            }
            BiosScanCode::F1 => {
                if let Some(&ch) = self.template.get(edit.cursor) {
                    Self::insert_or_overstrike_char(ch, edit, interp, con_out)?;
                }
            }
            BiosScanCode::F3 => {
                if let Some(rem) = self.template.get(edit.cursor..) {
                    let mut combined: String = edit
                        .chars
                        .get(..edit.cursor)
                        .unwrap_or(&[])
                        .iter()
                        .collect();
                    combined.extend(rem.iter().copied());
                    edit.replace_entire_line(&combined, interp, con_out)?;
                }
            }
            BiosScanCode::F7 => {
                Self::render_f7_history_list(edit, interp, prompt, con_out)?;
            }
            BiosScanCode::F8 => {
                Self::cycle_f8_prefix_history(edit, interp, con_out)?;
            }
            BiosScanCode::F9 => {
                Self::prompt_f9_history_number(edit, interp, kernel, prompt, con_out)?;
            }
            BiosScanCode::Home
            | BiosScanCode::Left
            | BiosScanCode::Right
            | BiosScanCode::End
            | BiosScanCode::Insert
            | BiosScanCode::Delete
            | BiosScanCode::Other(_) => {}
        }
        Ok(())
    }

    /// Prints the numbered `F7` `DOSKEY` history listing and restores the prompt + active buffer.
    ///
    /// # Arguments
    /// * `edit` - Active [`ActiveEditBuffer`].
    /// * `interp` - Immutable [`Interpreter`].
    /// * `prompt` - Active prompt string.
    /// * `con_out` - Console output stream.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`].
    fn render_f7_history_list(
        edit: &ActiveEditBuffer,
        interp: &Interpreter,
        prompt: &str,
        con_out: &mut dyn ByteStreamWrite,
    ) -> Result<(), CmdError> {
        let mut listing = String::from(CRLF);
        for (idx, item) in interp.console.history().iter().enumerate() {
            let num = idx.saturating_add(1);
            write!(listing, "{num}: {item}{CRLF}").unwrap_or(());
        }
        listing.push_str(prompt);
        listing.push_str(&edit.as_string());
        let tail_back = edit.chars.len().saturating_sub(edit.cursor);
        let encoded = encode_codepage_bytes(&listing, interp.console.codepage);
        write_byte_stream_gracefully(con_out, &encoded)?;
        write_byte_stream_gracefully(con_out, "\x08".repeat(tail_back).as_bytes())?;
        con_out.flush_stream()
    }

    /// Cycles backward through `interp.console.history()` entries matching `edit`'s initial prefix (`F8`).
    ///
    /// # Arguments
    /// * `edit` - Mutable [`ActiveEditBuffer`].
    /// * `interp` - Immutable [`Interpreter`].
    /// * `con_out` - Console output stream.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`].
    fn cycle_f8_prefix_history(
        edit: &mut ActiveEditBuffer,
        interp: &Interpreter,
        con_out: &mut dyn ByteStreamWrite,
    ) -> Result<(), CmdError> {
        let hist = interp.console.history();
        if hist.is_empty() {
            return Ok(());
        }
        let (prefix, search_end) = edit
            .f8_prefix
            .clone()
            .unwrap_or_else(|| (fold_win32_case(&edit.as_string()), hist.len()));
        let slice_end = search_end.min(hist.len());
        let mut found: Option<(usize, String)> = None;
        for (idx, item) in hist.iter().enumerate().take(slice_end).rev() {
            if fold_win32_case(item).starts_with(&prefix) {
                found = Some((idx, item.clone()));
                break;
            }
        }
        if let Some((idx, matched)) = found {
            let next_end = if idx == 0 { hist.len() } else { idx };
            edit.f8_prefix = Some((prefix, next_end));
            edit.history_idx = Some(idx);
            edit.replace_entire_line(&matched, interp, con_out)?;
        }
        Ok(())
    }

    /// Prompts `Line number: ` (`F9`), reads digits until `Enter` or `Esc`, and loads that 1-based history entry.
    ///
    /// # Arguments
    /// * `edit` - Mutable [`ActiveEditBuffer`].
    /// * `interp` - Immutable [`Interpreter`].
    /// * `kernel` - Mutable [`DosKernelApi`].
    /// * `prompt` - Active prompt string.
    /// * `con_out` - Console output stream.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`].
    fn prompt_f9_history_number(
        edit: &mut ActiveEditBuffer,
        interp: &Interpreter,
        kernel: &mut dyn DosKernelApi,
        prompt: &str,
        con_out: &mut dyn ByteStreamWrite,
    ) -> Result<(), CmdError> {
        write_byte_stream_gracefully(con_out, format!("{CRLF}Line number: ").as_bytes())?;
        con_out.flush_stream()?;
        let mut digits = String::new();
        while let Some(ev) = kernel.read_console_key()? {
            if let BiosKeyEvent::Char(b) = ev {
                if matches!(b, 0x0D | 0x0A) {
                    break;
                } else if b == 0x1B {
                    digits.clear();
                    break;
                } else if b.is_ascii_digit() {
                    digits.push(char::from(b));
                    write_byte_stream_gracefully(con_out, &[b])?;
                    con_out.flush_stream()?;
                }
            }
        }
        write_byte_stream_gracefully(con_out, format!("{CRLF}{prompt}").as_bytes())?;
        edit.chars.clear();
        edit.cursor = 0;
        if let Ok(num) = digits.parse::<usize>()
            && num >= 1
            && let Some(chosen) = interp.console.history().get(num.saturating_sub(1))
        {
            let chosen_cloned = chosen.clone();
            edit.replace_entire_line(&chosen_cloned, interp, con_out)?;
        } else {
            con_out.flush_stream()?;
        }
        Ok(())
    }
}

/// Runs an interactive MS-DOS BIOS REPL session using [`DosConsoleLineEditor`].
///
/// Supports multi-line `^` continuations, `( ... )` `More? ` blocks, `DOSKEY` macro expansion,
/// `Ctrl+C` / `Ctrl+Break` line cancellation, and `EXIT`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `kernel` - Mutable [`DosKernelApi`] supplying BIOS key events.
/// * `con_out` - Console stdout byte stream.
/// * `con_err` - Console stderr byte stream.
///
/// # Returns
/// `Ok(ExitCode)` when the session exits or reaches `EOF`.
///
/// # Errors
/// Returns [`CmdError`] on unrecoverable console I/O failure.
pub fn run_dos_bios_repl(
    interp: &mut Interpreter,
    kernel: &mut dyn DosKernelApi,
    con_out: &mut dyn ByteStreamWrite,
    con_err: &mut dyn ByteStreamWrite,
) -> Result<ExitCode, CmdError> {
    let mut editor = DosConsoleLineEditor::new();
    let mut pending_buf = String::new();
    let mut caret_cont = false;

    loop {
        let prompt = if !pending_buf.is_empty() {
            "More? ".to_owned()
        } else if interp.console.echo_state == EchoState::On {
            interp.format_prompt()
        } else {
            String::new()
        };
        if !prompt.is_empty() {
            let prompt_bytes = encode_codepage_bytes(&prompt, interp.console.codepage);
            write_byte_stream_gracefully(con_out, &prompt_bytes)?;
            con_out.flush_stream()?;
        }

        match editor.read_line(interp, kernel, &prompt, con_out)? {
            DosLineReadOutcome::Interrupted => {
                pending_buf.clear();
                caret_cont = false;
                interp.trigger_ctrl_c();
                let mut empty_in = InMemoryByteReader::default();
                let mut ctrl_io = ByteStreamIo::new(
                    &mut empty_in,
                    con_out,
                    con_err,
                    interp.console.codepage,
                    interp.config.unicode_output_mode,
                );
                let _flow = interp.handle_ctrl_c_interrupt(&mut ctrl_io);
                ctrl_io.check_error()?;
            }
            DosLineReadOutcome::Eof => {
                if !pending_buf.trim().is_empty() {
                    let mut empty_in = InMemoryByteReader::default();
                    let mut stream_io = ByteStreamIo::new(
                        &mut empty_in,
                        con_out,
                        con_err,
                        interp.console.codepage,
                        interp.config.unicode_output_mode,
                    );
                    let _last = interp.execute_interactive_line(&pending_buf, &mut stream_io);
                    stream_io.check_error()?;
                }
                break;
            }
            DosLineReadOutcome::Line(line) => {
                if let Some(stripped) = strip_odd_trailing_caret(&line) {
                    if !caret_cont && !pending_buf.is_empty() {
                        pending_buf.push('\n');
                    }
                    pending_buf.push_str(stripped);
                    caret_cont = true;
                    continue;
                }
                if caret_cont {
                    pending_buf.push_str(&line);
                    caret_cont = false;
                } else {
                    if !pending_buf.is_empty() {
                        pending_buf.push('\n');
                    }
                    pending_buf.push_str(&line);
                }
                if repl_open_paren_depth(&pending_buf) > 0 {
                    continue;
                }
                let full_cmd = core::mem::take(&mut pending_buf);
                if full_cmd.trim().is_empty() {
                    continue;
                }
                let mut empty_in = InMemoryByteReader::default();
                let mut stream_io = ByteStreamIo::new(
                    &mut empty_in,
                    con_out,
                    con_err,
                    interp.console.codepage,
                    interp.config.unicode_output_mode,
                );
                let _code = interp.execute_interactive_line(&full_cmd, &mut stream_io);
                stream_io.check_error()?;
                if let Some(exit_code) = interp.exec.exited() {
                    return Ok(exit_code);
                }
            }
        }
    }
    Ok(interp.last_exit_code())
}
