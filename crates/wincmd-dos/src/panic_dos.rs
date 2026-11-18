//! Zero-allocation MS-DOS `#[panic_handler]` diagnostic formatter (`panic_dos`).
//!
//! If an unrecoverable Rust invariant failure or `alloc_error_handler` abort ever triggers on
//! MS-DOS, dynamic heap allocation MUST NOT be attempted (since heap exhaustion may be the cause
//! of the abort). [`StackPanicBuffer`] formats a fixed 256-byte ASCII diagnostic entirely on the
//! stack for direct `write(2, ...)` output to DOS handle `2` (`STDERR`) followed by `_exit(255)`.

#![forbid(unsafe_code)]

use core::fmt::{self, Write};

/// Capacity of the fixed stack buffer used by [`StackPanicBuffer`] (`256` bytes).
pub const PANIC_STACK_BUF_CAPACITY: usize = 256;

/// Zero-heap fixed `[u8; 256]` stack writer implementing [`core::fmt::Write`].
#[derive(Debug, Clone)]
pub struct StackPanicBuffer {
    /// Raw stack byte array.
    buf: [u8; PANIC_STACK_BUF_CAPACITY],
    /// Number of valid bytes currently written into `buf`.
    len: usize,
}

impl Default for StackPanicBuffer {
    /// Creates an empty [`StackPanicBuffer`].
    ///
    /// # Returns
    /// Empty [`StackPanicBuffer`].
    fn default() -> Self {
        Self::new()
    }
}

impl StackPanicBuffer {
    /// Creates an empty [`StackPanicBuffer`] on the stack without touching the heap.
    ///
    /// # Returns
    /// Empty [`StackPanicBuffer`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0u8; PANIC_STACK_BUF_CAPACITY],
            len: 0,
        }
    }

    /// Appends raw bytes, truncating cleanly once [`PANIC_STACK_BUF_CAPACITY`] is reached.
    ///
    /// # Arguments
    /// * `src` - Byte slice to append.
    pub fn push_bytes(&mut self, src: &[u8]) {
        for &b in src {
            let Some(slot) = self.buf.get_mut(self.len) else {
                break;
            };
            *slot = b;
            self.len = self.len.saturating_add(1);
        }
    }

    /// Returns the written byte slice (`&self.buf[..self.len]`).
    ///
    /// # Returns
    /// Formatted ASCII diagnostic bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

impl Write for StackPanicBuffer {
    /// Appends `s` to the stack buffer, replacing control bytes with `'?'`.
    ///
    /// # Arguments
    /// * `s` - UTF-8 string slice to append.
    ///
    /// # Returns
    /// `Ok(())` unconditionally (truncating cleanly at buffer capacity).
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            let safe_ascii = if b.is_ascii_graphic() || b == b' ' {
                b
            } else {
                b'?'
            };
            self.push_bytes(&[safe_ascii]);
        }
        Ok(())
    }
}

/// Formats a zero-heap MS-DOS fatal abort line (`WINCMD/WINCHECK fatal abort ...`) on the stack.
///
/// # Arguments
/// * `file_and_line` - Optional `("file.rs", line_number)` location tuple.
/// * `reason` - Displayable panic message or payload summary.
///
/// # Returns
/// Populated [`StackPanicBuffer`] terminated with `CRLF`.
#[must_use]
pub fn format_dos_panic_banner(
    file_and_line: Option<(&str, u32)>,
    reason: &dyn fmt::Display,
) -> StackPanicBuffer {
    let mut out = StackPanicBuffer::new();
    out.push_bytes(b"WINCMD/WINCHECK fatal abort");
    if let Some((file, line)) = file_and_line {
        out.push_bytes(b" at ");
        let _ignored = write!(out, "{file}:{line}");
    }
    out.push_bytes(b": ");
    let _ignored = write!(out, "{reason}");
    // Guarantee CRLF at the end even if the message saturated the 256-byte buffer.
    if out.len > PANIC_STACK_BUF_CAPACITY.saturating_sub(2) {
        out.len = PANIC_STACK_BUF_CAPACITY.saturating_sub(2);
    }
    out.push_bytes(win_cmd_rs::types::CRLF.as_bytes());
    out
}

#[cfg(not(feature = "host-sim"))]
/// Zero-heap MS-DOS `#[panic_handler]` writing directly to DOS handle `2` (`STDERR`) and exiting with `255`.
///
/// # Arguments
/// * `info` - Panic location and message metadata supplied by `core::panicking`.
///
/// # Returns
/// Diverges via DOS `INT 21h AX=4CFFh` (`_exit(255)`).
#[panic_handler]
fn dos_panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    let loc = info.location().map(|l| (l.file(), l.line()));
    let msg = info.message();
    let banner = format_dos_panic_banner(loc, &msg);
    crate::ffi::djgpp_c::abort_to_dos_stderr(banner.as_bytes())
}
