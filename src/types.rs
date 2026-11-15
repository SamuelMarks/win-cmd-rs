//! Strongly typed domain newtypes and two-state enums for `win-cmd-rs`.
//!
//! To eliminate primitive obsession, all domain concepts—exit codes, drive letters,
//! case-insensitive environment variable names, batch label names, `FOR` variable tokens,
//! file descriptors, code pages, console colors, and interpreter modes—are represented
//! as validated structs or enums.

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use derive_more::{Constructor, Deref, Display, From, Into, IsVariant};

use crate::error::CmdError;

/// Canonical Windows carriage-return + line-feed sequence (`0x0D 0x0A`).
pub const CRLF: &str = "\r\n";

/// ASCII Horizontal Tab character (`0x09`).
pub const TAB_CHAR: char = '\t';

/// ASCII Line-Feed character (`0x0A`).
pub const LF_CHAR: char = '\n';

/// ASCII Carriage-Return character (`0x0D`).
pub const CR_CHAR: char = '\r';

/// ASCII Escape character (`0x1B`).
pub const ESC_CHAR: char = '\x1b';

/// ASCII Backslash character (`0x5C`).
pub const BS_CHAR: char = '\\';

/// Single ASCII Backslash string slice.
pub const BS_STR: &str = "\\";

/// Double ASCII Backslash string slice.
pub const DOUBLE_BS_STR: &str = "\\\\";

/// MS-DOS Ctrl+Z end-of-file marker byte (`0x1A`).
pub(crate) const CTRL_Z_BYTE: u8 = 0x1A;

/// Folds a single `char` using 1:1 Win32 `RtlUpcaseUnicodeChar`-style uppercase mapping
/// (preserving 1:1 character length on codepoints like `'ß'` whose full uppercase expands to `"SS"`).
///
/// # Arguments
/// * `ch` - Input Unicode scalar value.
///
/// # Returns
/// Case-folded uppercase `char`.
#[must_use]
pub fn fold_win32_char(ch: char) -> char {
    if ch.is_ascii() {
        ch.to_ascii_uppercase()
    } else {
        let mut it = ch.to_uppercase();
        match (it.next(), it.next()) {
            (Some(u), None) => u,
            _ => ch,
        }
    }
}

/// Folds a UTF-8 string using [`fold_win32_char`] for consistent case-insensitive comparisons
/// across `WindowsPath`, `InMemoryVfs`, `HostOsVfs`, `var_ops`, and `matches_win32_glob`.
///
/// # Arguments
/// * `raw` - Input string slice.
///
/// # Returns
/// Case-folded `String`.
#[must_use]
pub fn fold_win32_case(raw: &str) -> String {
    if raw.is_ascii() {
        raw.to_ascii_uppercase()
    } else {
        raw.chars().map(fold_win32_char).collect()
    }
}

/// A strongly typed process or command exit code (`ERRORLEVEL`).
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
pub struct ExitCode(
    /// The underlying 32-bit signed integer exit code.
    pub i32,
);

impl ExitCode {
    /// Standard success exit code (`0`).
    pub const SUCCESS: Self = Self(0);
    /// Standard general failure exit code (`1`).
    pub const FAILURE: Self = Self(1);
    /// Standard syntax error exit code (`1`).
    pub const SYNTAX_ERROR: Self = Self(1);
    /// Exit code returned when a command or batch file is not recognized (`9009`).
    pub const COMMAND_NOT_FOUND: Self = Self(9009);
    /// Exit code returned when execution is terminated via `Ctrl+C` (`-1073741510` / `0xC000013A`).
    pub const CTRL_C: Self = Self(-1_073_741_510);

    /// Returns the underlying signed 32-bit integer value.
    ///
    /// # Returns
    /// The `i32` exit code value.
    #[must_use]
    pub const fn code(self) -> i32 {
        self.0
    }

    /// Checks whether this exit code represents success (`0`).
    ///
    /// # Returns
    /// `true` if `self.0 == 0`, otherwise `false`.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 == 0
    }

    /// Formats the exit code as an 8-digit uppercase hexadecimal string for `%=ExitCode%`.
    ///
    /// # Returns
    /// An 8-character uppercase hex string (e.g., `"00000000"` or `"00002331"`).
    #[must_use]
    pub fn to_hex_string(self) -> String {
        let bits = self.0.cast_unsigned();
        format!("{bits:08X}")
    }

    /// Formats the low byte of the exit code as a printable ASCII character for `%=ExitCodeAscii%`.
    ///
    /// In `cmd.exe`, `%=ExitCodeAscii%` expands to the ASCII character if the low byte
    /// is in `0x20..=0x7E`, or empty string if it is a control character (`< 0x20` or `>= 0x7F`).
    ///
    /// # Returns
    /// A `String` containing the single printable ASCII character or empty string.
    #[must_use]
    pub fn to_ascii_string(self) -> String {
        let low_byte = (self.0.cast_unsigned() & 0xFF) as u8;
        if (0x20..=0x7E).contains(&low_byte) {
            String::from(char::from(low_byte))
        } else {
            String::new()
        }
    }
}

/// A validated Windows drive letter (`A` through `Z`, stored uppercase).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[display("{}:", self.as_char())]
pub struct DriveLetter(
    /// Uppercase ASCII byte in `b'A'..=b'Z'`.
    u8,
);

impl DriveLetter {
    /// Drive `C:`.
    pub const C: Self = Self(b'C');
    /// Drive `D:`.
    pub const D: Self = Self(b'D');
    /// Drive `Z:`.
    pub const Z: Self = Self(b'Z');

    /// All 26 Windows drive letters ordered ascending from `A:` through `Z:`.
    pub const ALL_ASCENDING: [Self; 26] = [
        Self(b'A'),
        Self(b'B'),
        Self(b'C'),
        Self(b'D'),
        Self(b'E'),
        Self(b'F'),
        Self(b'G'),
        Self(b'H'),
        Self(b'I'),
        Self(b'J'),
        Self(b'K'),
        Self(b'L'),
        Self(b'M'),
        Self(b'N'),
        Self(b'O'),
        Self(b'P'),
        Self(b'Q'),
        Self(b'R'),
        Self(b'S'),
        Self(b'T'),
        Self(b'U'),
        Self(b'V'),
        Self(b'W'),
        Self(b'X'),
        Self(b'Y'),
        Self(b'Z'),
    ];

    /// All 26 Windows drive letters ordered descending from `Z:` down to `A:` (for `PUSHD` UNC allocation).
    pub const ALL_DESCENDING: [Self; 26] = [
        Self(b'Z'),
        Self(b'Y'),
        Self(b'X'),
        Self(b'W'),
        Self(b'V'),
        Self(b'U'),
        Self(b'T'),
        Self(b'S'),
        Self(b'R'),
        Self(b'Q'),
        Self(b'P'),
        Self(b'O'),
        Self(b'N'),
        Self(b'M'),
        Self(b'L'),
        Self(b'K'),
        Self(b'J'),
        Self(b'I'),
        Self(b'H'),
        Self(b'G'),
        Self(b'F'),
        Self(b'E'),
        Self(b'D'),
        Self(b'C'),
        Self(b'B'),
        Self(b'A'),
    ];

    /// Validates and constructs a [`DriveLetter`] from an ASCII character.
    ///
    /// # Arguments
    /// * `ch` - Character to validate (`'a'..='z'` or `'A'..='Z'`).
    ///
    /// # Returns
    /// `Ok(DriveLetter)` normalized to uppercase.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidDriveLetter`] if `ch` is not an ASCII alphabetic letter.
    pub const fn try_from_char(ch: char) -> Result<Self, CmdError> {
        if ch.is_ascii_alphabetic() {
            Ok(Self(ch.to_ascii_uppercase() as u8))
        } else {
            Err(CmdError::InvalidDriveLetter { ch })
        }
    }

    /// Returns the uppercase `char` representation of the drive letter (e.g., `'C'`).
    ///
    /// # Returns
    /// The uppercase drive character.
    #[must_use]
    pub const fn as_char(self) -> char {
        self.0 as char
    }

    /// Formats the hidden per-drive environment variable name (e.g., `"=C:"`).
    ///
    /// # Returns
    /// The `cmd.exe` internal per-drive variable name string.
    #[must_use]
    pub fn env_var_key(self) -> String {
        format!("={}:", self.as_char())
    }
}

/// A Windows environment variable name that preserves original casing for display
/// while performing case-insensitive comparisons and hashing.
#[derive(Debug, Clone, Display)]
#[display("{original}")]
pub struct EnvVarName {
    /// Original user-supplied casing of the variable name.
    original: String,
    /// Uppercase-folded representation used for equality, ordering, and hashing.
    folded_uppercase: String,
}

impl EnvVarName {
    /// Constructs a new [`EnvVarName`] from a string slice.
    ///
    /// # Arguments
    /// * `name` - The variable name string.
    ///
    /// # Returns
    /// A new [`EnvVarName`] preserving `name` and precomputing its uppercase key.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            original: name.to_owned(),
            folded_uppercase: name.to_ascii_uppercase(),
        }
    }

    /// Returns the original case-preserved variable name.
    ///
    /// # Returns
    /// The original name as `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Returns the uppercase-folded variable name.
    ///
    /// # Returns
    /// The uppercase key as `&str`.
    #[must_use]
    pub fn folded(&self) -> &str {
        &self.folded_uppercase
    }

    /// Checks whether this variable is a hidden `cmd.exe` internal variable (starts with `'='`).
    ///
    /// # Returns
    /// `true` if the variable name starts with `'='`, otherwise `false`.
    #[must_use]
    pub fn is_hidden(&self) -> bool {
        self.original.starts_with('=')
    }
}

impl PartialEq for EnvVarName {
    /// Compares two environment variable names case-insensitively.
    ///
    /// # Arguments
    /// * `other` - The right-hand [`EnvVarName`] to compare against `self`.
    ///
    /// # Returns
    /// `true` if both names match ignoring ASCII case, otherwise `false`.
    fn eq(&self, other: &Self) -> bool {
        self.folded_uppercase == other.folded_uppercase
    }
}

impl Eq for EnvVarName {}

impl PartialOrd for EnvVarName {
    /// Partially orders two environment variable names case-insensitively.
    ///
    /// # Arguments
    /// * `other` - The right-hand [`EnvVarName`] to compare against `self`.
    ///
    /// # Returns
    /// `Some(Ordering)` comparing uppercase-folded variable names.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EnvVarName {
    /// Totally orders two environment variable names case-insensitively.
    ///
    /// # Arguments
    /// * `other` - The right-hand [`EnvVarName`] to compare against `self`.
    ///
    /// # Returns
    /// Total [`Ordering`] of the uppercase-folded names.
    fn cmp(&self, other: &Self) -> Ordering {
        self.folded_uppercase.cmp(&other.folded_uppercase)
    }
}

impl Hash for EnvVarName {
    /// Hashes the uppercase-folded variable name so case-insensitive keys collide identically.
    ///
    /// # Arguments
    /// * `state` - Mutable [`Hasher`] receiving the folded bytes.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.folded_uppercase.hash(state);
    }
}

/// A batch label identifier (`:label` or `GOTO label`), preserving display case while
/// matching case-insensitively.
#[derive(Debug, Clone, Display)]
#[display("{original}")]
pub struct LabelName {
    /// Original label text with any leading `:` stripped.
    original: String,
    /// Uppercase-folded label text for case-insensitive matching.
    folded_uppercase: String,
}

impl LabelName {
    /// Constructs a [`LabelName`], stripping an optional leading `:` and trimming whitespace.
    ///
    /// # Arguments
    /// * `raw` - Raw label token (e.g., `":my_label"` or `"my_label"`).
    ///
    /// # Returns
    /// A normalized [`LabelName`].
    #[must_use]
    pub fn new(raw: &str) -> Self {
        let trimmed = raw.trim();
        let stripped = trimmed.strip_prefix(':').unwrap_or(trimmed).trim();
        Self {
            original: stripped.to_owned(),
            folded_uppercase: stripped.to_ascii_uppercase(),
        }
    }

    /// Returns the original case-preserved label text (without leading `:`).
    ///
    /// # Returns
    /// The label name slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.original
    }

    /// Returns the uppercase-folded label text.
    ///
    /// # Returns
    /// The uppercase label slice.
    #[must_use]
    pub fn folded(&self) -> &str {
        &self.folded_uppercase
    }

    /// Checks whether this label is the special `:EOF` return target.
    ///
    /// # Returns
    /// `true` if the folded name is `"EOF"`, otherwise `false`.
    #[must_use]
    pub fn is_eof(&self) -> bool {
        self.folded_uppercase == "EOF"
    }
}

impl PartialEq for LabelName {
    /// Compares two batch label names case-insensitively.
    ///
    /// # Arguments
    /// * `other` - The right-hand [`LabelName`] to compare against `self`.
    ///
    /// # Returns
    /// `true` if both labels match ignoring ASCII case, otherwise `false`.
    fn eq(&self, other: &Self) -> bool {
        self.folded_uppercase == other.folded_uppercase
    }
}

impl Eq for LabelName {}

impl PartialOrd for LabelName {
    /// Partially orders two batch label names case-insensitively.
    ///
    /// # Arguments
    /// * `other` - The right-hand [`LabelName`] to compare against `self`.
    ///
    /// # Returns
    /// `Some(Ordering)` comparing uppercase-folded label names.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LabelName {
    /// Totally orders two batch label names case-insensitively.
    ///
    /// # Arguments
    /// * `other` - The right-hand [`LabelName`] to compare against `self`.
    ///
    /// # Returns
    /// Total [`Ordering`] of the uppercase-folded label names.
    fn cmp(&self, other: &Self) -> Ordering {
        self.folded_uppercase.cmp(&other.folded_uppercase)
    }
}

impl Hash for LabelName {
    /// Hashes the uppercase-folded label name for case-insensitive lookup.
    ///
    /// # Arguments
    /// * `state` - Mutable [`Hasher`] receiving the folded bytes.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.folded_uppercase.hash(state);
    }
}

/// A single-character `FOR` loop variable token (e.g., `I` in `%%I`).
///
/// Unlike environment variables, `FOR` variables in `cmd.exe` are strictly **case-sensitive**
/// (`%%a` and `%%A` are distinct variables) and support sequential ASCII allocation in `FOR /F`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[display("{}", self.as_char())]
pub struct ForVarName(
    /// Underlying printable ASCII byte.
    pub u8,
);

impl ForVarName {
    /// Constructs a [`ForVarName`] from a `char` if it is a valid `cmd.exe` `FOR` variable token
    /// (printable ASCII graphic `0x21..=0x7E`, excluding `%` and command metacharacters `"`, `<`, `>`, `|`, `&`, `^`).
    ///
    /// # Arguments
    /// * `ch` - The candidate `FOR` variable character.
    ///
    /// # Returns
    /// `Some(ForVarName)` if valid, or `None` otherwise.
    #[must_use]
    pub const fn from_char(ch: char) -> Option<Self> {
        if ch.is_ascii_graphic() && !matches!(ch, '%' | '"' | '<' | '>' | '|' | '&' | '^') {
            Some(Self(ch as u8))
        } else {
            None
        }
    }

    /// Returns the character representation of this `FOR` variable.
    ///
    /// # Returns
    /// The ASCII `char`.
    #[must_use]
    pub const fn as_char(self) -> char {
        self.0 as char
    }

    /// Computes the `offset`-th sequential `FOR` variable allocated by `FOR /F "tokens=..."`.
    ///
    /// # Arguments
    /// * `offset` - 0-based token offset from the base variable (e.g., `0` -> `%%A`, `1` -> `%%B`).
    ///
    /// # Returns
    /// `Some(ForVarName)` if the resulting byte remains within printable ASCII (`<= 0x7E`), else `None`.
    #[must_use]
    pub const fn offset_by(self, offset: u8) -> Option<Self> {
        let Some(next) = self.0.checked_add(offset) else {
            return None;
        };
        if next <= 0x7E { Some(Self(next)) } else { None }
    }
}

/// A validated Win32/`cmd.exe` redirection file descriptor handle (`0..=9`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[display("{_0}")]
pub struct FileDescriptor(
    /// Handle index in `0..=9`.
    u8,
);

impl FileDescriptor {
    /// Standard input handle (`0`).
    pub const STDIN: Self = Self(0);
    /// Standard output handle (`1`).
    pub const STDOUT: Self = Self(1);
    /// Standard error handle (`2`).
    pub const STDERR: Self = Self(2);

    /// Validates and constructs a [`FileDescriptor`] from a handle index `0..=9`.
    ///
    /// # Arguments
    /// * `raw` - The numeric handle index.
    ///
    /// # Returns
    /// `Some(FileDescriptor)` if `raw <= 9`, otherwise `None`.
    #[must_use]
    pub const fn new(raw: u8) -> Option<Self> {
        if raw <= 9 { Some(Self(raw)) } else { None }
    }

    /// Returns the numeric handle index (`0..=9`).
    ///
    /// # Returns
    /// The `u8` handle number.
    #[must_use]
    pub const fn index(self) -> u8 {
        self.0
    }
}

/// Supported Windows console and script character encodings (`CHCP`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum CodePage {
    /// UTF-8 (`65001`).
    #[default]
    #[display("65001")]
    Utf8,
    /// OEM United States (`437`).
    #[display("437")]
    OemUnitedStates,
    /// OEM Multilingual Latin 1 (`850`).
    #[display("850")]
    OemMultilingualLatin1,
    /// Windows ANSI Latin 1 (`1252`).
    #[display("1252")]
    WindowsLatin1,
    /// UTF-16 Little Endian (`1200`).
    #[display("1200")]
    Utf16Le,
    /// UTF-16 Big Endian (`1201`).
    #[display("1201")]
    Utf16Be,
    /// US-ASCII (`20127`).
    #[display("20127")]
    Ascii,
}

impl CodePage {
    /// Resolves a numeric Windows code page identifier to a [`CodePage`].
    ///
    /// # Arguments
    /// * `id` - Numeric code page identifier (e.g., `65001`, `437`, `850`, `1252`).
    ///
    /// # Returns
    /// `Ok(CodePage)` if supported.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidCodePage`] if `id` is not a recognized code page number.
    pub const fn from_id(id: u32) -> Result<Self, CmdError> {
        match id {
            65001 => Ok(Self::Utf8),
            437 => Ok(Self::OemUnitedStates),
            850 => Ok(Self::OemMultilingualLatin1),
            1252 => Ok(Self::WindowsLatin1),
            1200 => Ok(Self::Utf16Le),
            1201 => Ok(Self::Utf16Be),
            20127 => Ok(Self::Ascii),
            _ => Err(CmdError::InvalidCodePage { code: id }),
        }
    }

    /// Returns the numeric Windows code page identifier.
    ///
    /// # Returns
    /// The `u32` code page number.
    #[must_use]
    pub const fn id(self) -> u32 {
        match self {
            Self::Utf8 => 65001,
            Self::OemUnitedStates => 437,
            Self::OemMultilingualLatin1 => 850,
            Self::WindowsLatin1 => 1252,
            Self::Utf16Le => 1200,
            Self::Utf16Be => 1201,
            Self::Ascii => 20127,
        }
    }
}

/// A 4-bit console color nibble (`0x0`..=`0xF`) used by the `COLOR` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
#[display("{:X}", self.as_u8())]
pub enum ColorNibble {
    /// `0` — Black.
    Black,
    /// `1` — Blue.
    Blue,
    /// `2` — Green.
    Green,
    /// `3` — Aqua / Cyan.
    Aqua,
    /// `4` — Red.
    Red,
    /// `5` — Purple / Magenta.
    Purple,
    /// `6` — Yellow / Brown.
    Yellow,
    /// `7` — White / Light Gray.
    White,
    /// `8` — Gray / Dark Gray.
    Gray,
    /// `9` — Light Blue.
    LightBlue,
    /// `A` — Light Green.
    LightGreen,
    /// `B` — Light Aqua.
    LightAqua,
    /// `C` — Light Red.
    LightRed,
    /// `D` — Light Purple.
    LightPurple,
    /// `E` — Light Yellow.
    LightYellow,
    /// `F` — Bright White.
    BrightWhite,
}

impl ColorNibble {
    /// Converts the low 4 bits (`val & 0x0F`) into a [`ColorNibble`].
    ///
    /// # Arguments
    /// * `val` - Any `u8` whose lowest 4 bits (`0..=15`) select the color nibble.
    ///
    /// # Returns
    /// The corresponding [`ColorNibble`].
    #[must_use]
    pub const fn from_low_nibble(val: u8) -> Self {
        match val & 0x0F {
            0x0 => Self::Black,
            0x1 => Self::Blue,
            0x2 => Self::Green,
            0x3 => Self::Aqua,
            0x4 => Self::Red,
            0x5 => Self::Purple,
            0x6 => Self::Yellow,
            0x7 => Self::White,
            0x8 => Self::Gray,
            0x9 => Self::LightBlue,
            0xA => Self::LightGreen,
            0xB => Self::LightAqua,
            0xC => Self::LightRed,
            0xD => Self::LightPurple,
            0xE => Self::LightYellow,
            _ => Self::BrightWhite,
        }
    }

    /// Converts a raw nibble (`0x0..=0xF`) to a [`ColorNibble`].
    ///
    /// # Arguments
    /// * `val` - Byte value in `0..=15`.
    ///
    /// # Returns
    /// `Some(ColorNibble)` if `val <= 0xF`, otherwise `None`.
    #[must_use]
    pub const fn from_u8(val: u8) -> Option<Self> {
        if val <= 0x0F {
            Some(Self::from_low_nibble(val))
        } else {
            None
        }
    }

    /// Returns the numeric value (`0x0..=0xF`) of this color nibble.
    ///
    /// # Returns
    /// The `u8` nibble value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Black => 0x0,
            Self::Blue => 0x1,
            Self::Green => 0x2,
            Self::Aqua => 0x3,
            Self::Red => 0x4,
            Self::Purple => 0x5,
            Self::Yellow => 0x6,
            Self::White => 0x7,
            Self::Gray => 0x8,
            Self::LightBlue => 0x9,
            Self::LightGreen => 0xA,
            Self::LightAqua => 0xB,
            Self::LightRed => 0xC,
            Self::LightPurple => 0xD,
            Self::LightYellow => 0xE,
            Self::BrightWhite => 0xF,
        }
    }

    /// Returns the ANSI SGR foreground parameter code (`30`–`37` or `90`–`97`) for this nibble.
    ///
    /// # Returns
    /// The `u8` ANSI foreground color parameter.
    #[must_use]
    pub const fn ansi_fg_code(self) -> u8 {
        match self {
            Self::Black => 30,
            Self::Red => 31,
            Self::Green => 32,
            Self::Yellow => 33,
            Self::Blue => 34,
            Self::Purple => 35,
            Self::Aqua => 36,
            Self::White => 37,
            Self::Gray => 90,
            Self::LightRed => 91,
            Self::LightGreen => 92,
            Self::LightYellow => 93,
            Self::LightBlue => 94,
            Self::LightPurple => 95,
            Self::LightAqua => 96,
            Self::BrightWhite => 97,
        }
    }

    /// Returns the ANSI SGR background parameter code (`40`–`47` or `100`–`107`) for this nibble.
    ///
    /// # Returns
    /// The `u8` ANSI background color parameter.
    #[must_use]
    pub const fn ansi_bg_code(self) -> u8 {
        self.ansi_fg_code().saturating_add(10)
    }
}

/// Validated console background and foreground color pair (`COLOR bf`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
#[display("{background}{foreground}")]
pub struct ConsoleColor {
    /// Background color nibble.
    pub background: ColorNibble,
    /// Foreground color nibble.
    pub foreground: ColorNibble,
}

impl ConsoleColor {
    /// Constructs a [`ConsoleColor`], ensuring `background != foreground` per `cmd.exe` rules.
    ///
    /// # Arguments
    /// * `background` - The background [`ColorNibble`].
    /// * `foreground` - The foreground [`ColorNibble`].
    ///
    /// # Returns
    /// `Ok(ConsoleColor)` if the nibbles are distinct.
    ///
    /// # Errors
    /// Returns [`CmdError::SameColorForegroundAndBackground`] if `background == foreground`.
    pub fn new(background: ColorNibble, foreground: ColorNibble) -> Result<Self, CmdError> {
        if background == foreground {
            Err(CmdError::SameColorForegroundAndBackground {
                nibble: background.as_u8(),
            })
        } else {
            Ok(Self {
                background,
                foreground,
            })
        }
    }

    /// Parses a 1- or 2-character hexadecimal `COLOR` argument (e.g., `"0A"` or `"7"`).
    ///
    /// # Arguments
    /// * `spec` - The hex specification string.
    ///
    /// # Returns
    /// `Ok(ConsoleColor)` if valid hex of 1 or 2 digits with distinct nibbles.
    ///
    /// # Errors
    /// Returns [`CmdError::SameColorForegroundAndBackground`] if both nibbles match, or
    /// [`CmdError::ParameterFormatNotCorrect`] if `spec` is not 1–2 hex digits.
    pub fn parse_hex(spec: &str) -> Result<Self, CmdError> {
        let trimmed = spec.trim();
        if trimmed.is_empty() || trimmed.len() > 2 {
            return Err(CmdError::ParameterFormatNotCorrect {
                span: crate::span::Span::dummy(),
                param: spec.to_owned(),
            });
        }
        let byte = u8::from_str_radix(trimmed, 16).map_err(|_parse_err| {
            CmdError::ParameterFormatNotCorrect {
                span: crate::span::Span::dummy(),
                param: spec.to_owned(),
            }
        })?;
        let bg = ColorNibble::from_low_nibble(byte >> 4);
        let fg = ColorNibble::from_low_nibble(byte);
        Self::new(bg, fg)
    }

    /// Formats this console color pair as an ANSI SGR escape sequence (`ESC[<bg>;<fg>m`).
    ///
    /// # Returns
    /// The ANSI SGR escape string.
    #[must_use]
    pub fn to_ansi_sgr(self) -> String {
        format!(
            "{ESC_CHAR}[{};{}m",
            self.background.ansi_bg_code(),
            self.foreground.ansi_fg_code()
        )
    }
}

/// Command echo state (`ECHO ON` vs `ECHO OFF`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum EchoState {
    /// Commands are echoed before execution (`ECHO is on.`).
    #[default]
    #[display("on")]
    On,
    /// Commands are not echoed (`ECHO is off.`).
    #[display("off")]
    Off,
}

/// Prefix `@` echo suppression on an individual command or block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum EchoSuppression {
    /// Command is prefixed with `@` (do not echo).
    #[display("suppressed")]
    Suppressed,
    /// Command is not prefixed with `@`.
    #[default]
    #[display("not_suppressed")]
    NotSuppressed,
}

/// Delayed environment variable expansion mode (`!VAR!`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum DelayedExpansionMode {
    /// Delayed expansion is active (`SETLOCAL EnableDelayedExpansion` or `/V:ON`).
    #[display("enabled")]
    Enabled,
    /// Delayed expansion is inactive (`SETLOCAL DisableDelayedExpansion` or `/V:OFF`).
    #[default]
    #[display("disabled")]
    Disabled,
}

/// Command Extensions mode (`SETLOCAL EnableExtensions` or `/E:ON`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum ExtensionsMode {
    /// Command extensions are enabled (default in modern `cmd.exe`).
    #[default]
    #[display("enabled")]
    Enabled,
    /// Command extensions are disabled (`/E:OFF` or `DisableExtensions`).
    #[display("disabled")]
    Disabled,
}

/// Double-quote lexical state during tokenization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum QuoteMode {
    /// Currently inside an unclosed double-quote pair `"..."`.
    #[display("in_quotes")]
    InQuotes,
    /// Currently outside double quotes.
    #[default]
    #[display("unquoted")]
    Unquoted,
}

impl QuoteMode {
    /// Toggles the quote mode when an unescaped `"` is encountered.
    ///
    /// # Returns
    /// [`QuoteMode::InQuotes`] if currently [`QuoteMode::Unquoted`], and vice versa.
    #[must_use]
    pub const fn toggle(self) -> Self {
        match self {
            Self::InQuotes => Self::Unquoted,
            Self::Unquoted => Self::InQuotes,
        }
    }
}

/// Case-sensitivity mode for string comparisons, regexes, and globbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum CaseSensitivity {
    /// Case-sensitive comparison.
    #[default]
    #[display("sensitive")]
    Sensitive,
    /// Case-insensitive comparison (e.g., `IF /I`, `FIND /I`, Windows filenames).
    #[display("insensitive")]
    Insensitive,
}

/// Negation state for `IF [NOT]` conditions or `FIND [/V]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum NegationMode {
    /// Condition is negated (`NOT`).
    #[display("negated")]
    Negated,
    /// Condition is not negated.
    #[default]
    #[display("normal")]
    Normal,
}

/// Execution context distinguishing batch files from interactive prompt and subshells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum ExecutionContext {
    /// Executing statements inside a `.bat` or `.cmd` file.
    #[default]
    #[display("batch_file")]
    BatchFile,
    /// Executing commands entered interactively or via `cmd /C` / `cmd /K`.
    #[display("interactive_repl")]
    InteractiveRepl,
    /// Executing one side of a pipeline `cmd1 | cmd2` in an isolated subshell.
    #[display("pipe_subshell")]
    PipeSubshell,
    /// Executing a `FOR /F` command capture subshell.
    #[display("for_f_subshell")]
    ForFSubshell,
}

/// Overwrite policy for `COPY`, `MOVE`, and `XCOPY` (`/Y`, `/-Y`, `%COPYCMD%`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum OverwritePolicy {
    /// Always overwrite existing destination files without prompting (`/Y`).
    #[default]
    #[display("always")]
    AlwaysOverwrite,
    /// Prompt interactively `(Yes/No/All)?` before overwriting existing destination files (`/-Y`).
    #[display("prompt")]
    Prompt,
    /// Never overwrite existing destination files without prompting.
    #[display("never")]
    NeverOverwrite,
}

impl OverwritePolicy {
    /// Resolves the initial [`OverwritePolicy`] from `%COPYCMD%`.
    ///
    /// Defaults to [`Self::AlwaysOverwrite`] unless `%COPYCMD%` specifies `/-Y` ([`Self::Prompt`])
    /// or `/N` ([`Self::NeverOverwrite`]).
    ///
    /// # Arguments
    /// * `copycmd` - Optional `%COPYCMD%` variable value.
    ///
    /// # Returns
    /// Initial [`OverwritePolicy`] before command-line switch overrides.
    #[must_use]
    pub fn from_copycmd_env(copycmd: Option<&str>) -> Self {
        let Some(raw) = copycmd else {
            return Self::AlwaysOverwrite;
        };
        let upper = raw.to_ascii_uppercase();
        if upper.contains("/-Y") {
            Self::Prompt
        } else if upper.contains("/N") {
            Self::NeverOverwrite
        } else {
            Self::AlwaysOverwrite
        }
    }
}

/// Output character encoding mode for redirected files and pipes (`/A` vs `/U`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum OutputUnicodeMode {
    /// Output internal command strings using the active ANSI/OEM codepage (`/A`).
    #[default]
    #[display("ansi")]
    Ansi,
    /// Output internal command strings to pipes and redirected files as UTF-16LE (`/U`).
    #[display("utf16le")]
    Utf16Le,
}

/// Interactive file and directory tab-completion mode (`/F:ON` vs `/F:OFF`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum FileCompletionMode {
    /// File and directory name completion is enabled (`/F:ON`).
    #[default]
    #[display("enabled")]
    Enabled,
    /// File and directory name completion is disabled (`/F:OFF`).
    #[display("disabled")]
    Disabled,
}

/// Registry `AutoRun` startup execution policy (default vs `/D`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum AutoRunMode {
    /// Execute Registry `AutoRun` commands on startup if configured.
    #[default]
    #[display("run")]
    Run,
    /// Ignore Registry `AutoRun` commands (`/D` switch).
    #[display("skip")]
    Skip,
}

/// Outer quote stripping policy for `/C` and `/K` (`default` vs `/S`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum QuoteStripMode {
    /// Use the 5-rule `cmd.exe` heuristic to decide whether to preserve outer quotes.
    #[default]
    #[display("heuristic")]
    Heuristic,
    /// Always strip outer quotes when `/S` is passed on the command line.
    #[display("always_strip")]
    AlwaysStrip,
}

/// Data transfer mode for `COPY` (`/A` ASCII text vs `/B` raw binary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum CopyDataMode {
    /// Binary copy mode (`/B`): copies all raw bytes without `0x1A` EOF truncation or appending.
    #[default]
    #[display("binary")]
    BinaryRaw,
    /// ASCII text copy mode (`/A`): reads up to `0x1A` on source and appends `0x1A` on destination.
    #[display("ascii")]
    AsciiText,
}

/// Disk write verification mode controlled by `VERIFY ON|OFF`, `COPY /V`, and `XCOPY /V`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum VerifyCopyMode {
    /// Do not verify written file bytes (`VERIFY OFF`).
    #[default]
    #[display("unverified")]
    Unverified,
    /// Read back and verify written destination bytes (`VERIFY ON` or `/V`).
    #[display("verified")]
    Verified,
}

/// Process wait mode for `START` (`/WAIT` vs asynchronous).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum WaitMode {
    /// Wait for the started process or command to complete (`/WAIT` / `/W`).
    #[display("wait")]
    Wait,
    /// Launch without blocking (`default` for `START`).
    #[default]
    #[display("detached")]
    Detached,
}

/// Interactive confirmation prompt policy (`DEL /P`, `DEL /Q`, `RD /Q`, `XCOPY /P`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum PromptConfirmMode {
    /// Prompt the user for `(Y/N)` confirmation on each entry.
    #[display("prompt_each")]
    PromptEach,
    /// Suppress interactive confirmation prompts (`/Q` or default silent delete).
    #[default]
    #[display("silent")]
    Silent,
}

/// Completion target scope for `/F:ON` (`Ctrl+D` directories only vs `Ctrl+F`/`Tab` files and dirs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum CompletionScope {
    /// Complete both files and directories (`Tab` / `Ctrl+F`).
    #[default]
    #[display("files_and_dirs")]
    FilesAndDirectories,
    /// Complete only directories (`Ctrl+D`).
    #[display("dirs_only")]
    DirectoriesOnly,
}

/// Link type created by the `MKLINK` built-in command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum MklinkKind {
    /// File symbolic link (default `MKLINK`).
    #[default]
    #[display("file_symlink")]
    FileSymlink,
    /// Directory symbolic link (`MKLINK /D`).
    #[display("dir_symlink")]
    DirectorySymlink,
    /// Directory junction (`MKLINK /J`).
    #[display("junction")]
    DirectoryJunction,
    /// File hard link (`MKLINK /H`).
    #[display("hardlink")]
    HardLink,
}

/// VFS backend selection mode (`InMemoryHermetic` vs `HostNative`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum VfsBackendMode {
    /// Deterministic, sandboxed in-memory VFS (`InMemoryVfs`).
    #[default]
    #[display("in_memory")]
    InMemoryHermetic,
    /// Live host OS filesystem bridge (`HostOsVfs`).
    #[display("host_native")]
    HostNative,
}

/// Host OS environment and working directory synchronization policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum HostBindingMode {
    /// Isolated virtual environment and working directory (no host mutations).
    #[default]
    #[display("isolated")]
    Isolated,
    /// Synchronize working directory and environment with the host OS process.
    #[display("synchronized")]
    Synchronized,
}

/// Console `Ctrl+C` (`SIGINT`) interrupt state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum InterruptState {
    /// No interrupt signal is pending.
    #[default]
    #[display("clear")]
    Clear,
    /// A `Ctrl+C` interrupt signal is pending handling.
    #[display("pending")]
    Pending,
}

/// Window creation style for the `START` built-in command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum StartWindowMode {
    /// Normal console/window creation (default).
    #[default]
    #[display("normal")]
    Normal,
    /// Start application without creating a new console window (`/B`).
    #[display("no_window")]
    BackgroundNoWindow,
    /// Start window minimized (`/MIN`).
    #[display("minimized")]
    Minimized,
    /// Start window maximized (`/MAX`).
    #[display("maximized")]
    Maximized,
}

/// Environment inheritance policy for the `START` built-in command (`default` vs `/I`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum StartEnvMode {
    /// Inherit the current `cmd.exe` environment directory and variables (default).
    #[default]
    #[display("current")]
    CurrentEnv,
    /// Inherit the initial environment passed to `cmd.exe` at startup (`/I`).
    #[display("initial")]
    InitialStartupEnv,
}

/// Process scheduling priority class for the `START` built-in command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum ProcessPriority {
    /// Normal priority class (`/NORMAL`).
    #[default]
    #[display("normal")]
    Normal,
    /// Idle / low priority class (`/LOW`).
    #[display("low")]
    Low,
    /// High priority class (`/HIGH`).
    #[display("high")]
    High,
    /// Realtime priority class (`/REALTIME`).
    #[display("realtime")]
    Realtime,
    /// Above normal priority class (`/ABOVENORMAL`).
    #[display("above_normal")]
    AboveNormal,
    /// Below normal priority class (`/BELOWNORMAL`).
    #[display("below_normal")]
    BelowNormal,
}

/// Pipeline execution strategy (`InMemoryBuffered` vs `OsStreamingPipe`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum PipeExecutionMode {
    /// Buffer left-hand output in memory before invoking right-hand command.
    #[default]
    #[display("in_memory_buffered")]
    InMemoryBuffered,
    /// Stream OS anonymous pipes concurrently when spawning external processes.
    #[display("os_streaming_pipe")]
    OsStreamingPipe,
}

/// Line editing cursor insertion mode for `DOSKEY` (`/INSERT` vs `/OVERSTRIKE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum DoskeyEditMode {
    /// Insert new characters at cursor (`/INSERT`).
    #[default]
    #[display("insert")]
    Insert,
    /// Overstrike existing characters at cursor (`/OVERSTRIKE`).
    #[display("overstrike")]
    Overstrike,
}

/// Date display format style for `%DATE%`, `DATE /T`, and `DIR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum DateFormatStyle {
    /// US English format with weekday (`"Wed 11/10/2026"`).
    #[default]
    #[display("us")]
    DayMonthDateYearUs,
    /// ISO-8601 format (`"2026-11-10"`).
    #[display("iso")]
    Iso8601,
    /// European day-month-year format (`"10/11/2026"`).
    #[display("euro")]
    DayMonthYearEuro,
}

/// Time clock display style (`12-hour AM/PM` vs `24-hour`) for `DIR` timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum TimeClockFormat {
    /// 12-hour clock with `AM` / `PM` (`"09:00 AM"`).
    #[default]
    #[display("12h")]
    TwelveHourAmPm,
    /// 24-hour clock (`"09:00"` / `"21:00"`).
    #[display("24h")]
    TwentyFourHour,
}

/// Thousand-separator formatting policy for `DIR` file and free-space sizes (`/C` vs `/-C`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum ThousandsSeparatorMode {
    /// Group digits with the locale's thousand separator (`/C`, default).
    #[default]
    #[display("use_separator")]
    UseSeparator,
    /// Emit plain ungrouped digits (`/-C`).
    #[display("omit_separator")]
    OmitSeparator,
}

/// Read-only file deletion policy for `VirtualFileSystem::delete_file` (`DEL` vs `DEL /F`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum ReadOnlyDeletePolicy {
    /// Reject deleting files with `READ_ONLY` set (`AccessDenied`).
    #[default]
    #[display("respect_readonly")]
    RespectReadOnly,
    /// Force-delete files even when `READ_ONLY` is set (`DEL /F`, `MOVE` overwrite).
    #[display("force_delete")]
    ForceDeleteReadOnly,
}

/// Intermediate parent directory creation policy for `VirtualFileSystem::create_dir`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum DirCreationDepth {
    /// Require the immediate parent directory to exist (`MD` with `/E:OFF`).
    #[default]
    #[display("immediate_only")]
    ImmediateParentOnly,
    /// Create missing intermediate parent directories (`MD` with `/E:ON`, `XCOPY /I`).
    #[display("create_parents")]
    CreateParents,
}

/// Directory removal recursion policy for `VirtualFileSystem::remove_dir` (`RD` vs `RD /S`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum DirRemovalMode {
    /// Remove only an empty directory (`RD`).
    #[default]
    #[display("empty_only")]
    EmptyOnly,
    /// Recursively remove a directory and all its contents (`RD /S`).
    #[display("recursive")]
    RecursiveSubtree,
}

/// Final-component symbolic link / junction resolution policy on the VFS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum SymlinkFollowPolicy {
    /// Follow reparse points on the final path component (`stat`, `read_bytes`, `write_bytes`).
    #[default]
    #[display("follow_final")]
    FollowFinalTarget,
    /// Stop on the final path component without following a reparse point (`delete_file`, `RD` on junction).
    #[display("preserve_final")]
    PreserveFinalLink,
}

/// Directory or Registry hierarchy traversal depth (`Shallow` vs `Recursive`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum TraversalDepth {
    /// Inspect or copy only the immediate target level.
    #[default]
    #[display("shallow")]
    Shallow,
    /// Recursively traverse all nested subkeys or subdirectories (`/S`).
    #[display("recursive")]
    Recursive,
}

/// Byte-order endianness for UTF-16 encoding and decoding (`LE` vs `BE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum Utf16Endian {
    /// Little-endian UTF-16 (`1200`, `FF FE` BOM).
    #[default]
    #[display("le")]
    Little,
    /// Big-endian UTF-16 (`1201`, `FE FF` BOM).
    #[display("be")]
    Big,
}

/// Character set used to render `TREE` branch connectors (`Unicode` vs `/A` 7-bit ASCII).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum TreeCharset {
    /// Box-drawing characters (`├───`, `└───`, `│`).
    #[default]
    #[display("unicode")]
    UnicodeBoxDrawing,
    /// 7-bit ASCII characters (`+---`, `\---`, `|`) selected by `TREE /A`.
    #[display("ascii")]
    Ascii7Bit,
}

/// Entry inclusion scope for `TREE` (`DirectoriesOnly` vs `/F` `IncludeFiles`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum TreeScope {
    /// Render subdirectories only (`TREE`).
    #[default]
    #[display("dirs_only")]
    DirectoriesOnly,
    /// Render files inside each subdirectory as well (`TREE /F`).
    #[display("include_files")]
    IncludeFiles,
}

/// Attribute bit mutation operation (`Set` vs `Clear`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum AttributeMutation {
    /// Set (insert) the specified attribute bit(s) (`+R`, `+H`, etc.).
    #[default]
    #[display("set")]
    Set,
    /// Clear (remove) the specified attribute bit(s) (`-R`, `-H`, etc.).
    #[display("clear")]
    Clear,
}

/// Percent prefix arity for `FOR` loop variables and literal percent escaping (`%` vs `%%`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Display, IsVariant)]
pub enum PercentArity {
    /// Single percent (`%I`, `%`) used in interactive REPL and `cmd /C` mode.
    #[display("single_percent")]
    SinglePercent,
    /// Double percent (`%%I`, `%%`) required inside `.bat` and `.cmd` batch scripts.
    #[default]
    #[display("double_percent")]
    DoublePercent,
}

impl PercentArity {
    /// Determines the required [`PercentArity`] for the given [`ExecutionContext`].
    ///
    /// # Arguments
    /// * `exec_context` - Active execution context (`BatchFile` vs `InteractiveRepl`/subshells).
    ///
    /// # Returns
    /// [`PercentArity::DoublePercent`] for [`ExecutionContext::BatchFile`], and
    /// [`PercentArity::SinglePercent`] for interactive REPL or subshells.
    #[must_use]
    pub const fn for_execution_context(exec_context: ExecutionContext) -> Self {
        match exec_context {
            ExecutionContext::BatchFile => Self::DoublePercent,
            ExecutionContext::InteractiveRepl
            | ExecutionContext::PipeSubshell
            | ExecutionContext::ForFSubshell => Self::SinglePercent,
        }
    }

    /// Converts a leading `'%'` character count (`1` or `2`) into a [`PercentArity`].
    ///
    /// # Arguments
    /// * `count` - Number of consecutive leading `'%'` characters.
    ///
    /// # Returns
    /// `Some(PercentArity)` when `count` is `1` or `2`, otherwise `None`.
    #[must_use]
    pub const fn from_percent_count(count: usize) -> Option<Self> {
        match count {
            1 => Some(Self::SinglePercent),
            2 => Some(Self::DoublePercent),
            _ => None,
        }
    }

    /// Returns the literal percent prefix string (`"%"` or `"%%"`) for this arity.
    ///
    /// # Returns
    /// `"%"` for [`PercentArity::SinglePercent`] or `"%%"` for [`PercentArity::DoublePercent`].
    #[must_use]
    pub const fn prefix_str(self) -> &'static str {
        match self {
            Self::SinglePercent => "%",
            Self::DoublePercent => "%%",
        }
    }
}

/// Parser error recovery policy (`Strict` for execution vs `Recovering` for CST/linting).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum RecoveryMode {
    /// Fail immediately on the first syntax error with [`CmdError`] (runtime interpreter).
    #[default]
    #[display("strict")]
    Strict,
    /// Record syntax diagnostics, wrap malformed tokens in `ErrorNode`, and continue parsing.
    #[display("recovering")]
    Recovering,
}

/// Strategy used by the CST tree-rewriter when quoting an unquoted variable or parameter word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum QuoteInsertionStrategy {
    /// Wrap the entire word in double quotes (`"%VAR%\sub"`).
    #[default]
    #[display("wrap_whole_word")]
    WrapWholeWord,
    /// Inject a `~` quote-stripping modifier on positional (`%1` -> `"%~1"`) or `FOR` (`%%I` -> `"%%~I"`)
    /// variables before wrapping the word in double quotes.
    #[display("strip_and_wrap_modifier")]
    StripAndWrapModifier,
}

/// Configurable locale formatting rules for `DATE`, `TIME`, `%DATE%`, `%TIME%`, and `DIR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdLocaleConfig {
    /// Date ordering and weekday style.
    pub date_format: DateFormatStyle,
    /// Date component separator character (`'/'`, `'-'`, `'.'`).
    pub date_separator: char,
    /// Time component separator character (`':'`, `'.'`).
    pub time_separator: char,
    /// Fractional seconds separator character (`'.'`, `','`).
    pub decimal_separator: char,
    /// Thousand separator character for `DIR` file sizes (`','`, `'.'`, `' '`).
    pub thousand_separator: char,
    /// 12-hour vs 24-hour display in `DIR`.
    pub time_clock_format: TimeClockFormat,
}

impl Default for CmdLocaleConfig {
    /// Returns the default US English Windows `cmd.exe` locale configuration.
    ///
    /// # Returns
    /// Default [`CmdLocaleConfig`] (`MM/DD/YYYY`, 12-hour clock, comma thousands separator).
    fn default() -> Self {
        Self {
            date_format: DateFormatStyle::DayMonthDateYearUs,
            date_separator: '/',
            time_separator: ':',
            decimal_separator: '.',
            thousand_separator: ',',
            time_clock_format: TimeClockFormat::TwelveHourAmPm,
        }
    }
}

impl CmdLocaleConfig {
    /// Formats an unsigned 64-bit integer with or without this locale's thousand separator.
    ///
    /// # Arguments
    /// * `val` - The numeric value to format.
    /// * `separator_mode` - [`ThousandsSeparatorMode`] (`/C` vs `/-C`).
    ///
    /// # Returns
    /// Formatted number string.
    #[must_use]
    pub fn format_number_with_thousands(
        &self,
        val: u64,
        separator_mode: ThousandsSeparatorMode,
    ) -> String {
        let s = val.to_string();
        if separator_mode == ThousandsSeparatorMode::OmitSeparator {
            return s;
        }
        let mut out = String::with_capacity(s.len().saturating_add(s.len() / 3));
        let len = s.len();
        for (i, ch) in s.chars().enumerate() {
            if i > 0 && len.saturating_sub(i).is_multiple_of(3) {
                out.push(self.thousand_separator);
            }
            out.push(ch);
        }
        out
    }

    /// Formats a date tuple `(weekday_short, year, month, day)` according to this locale.
    ///
    /// # Arguments
    /// * `weekday` - 3-letter weekday name (`"Wed"`).
    /// * `year` - 4-digit year (`2026`).
    /// * `month` - 1-based month (`1..=12`).
    /// * `day` - 1-based day (`1..=31`).
    ///
    /// # Returns
    /// Formatted date string.
    #[must_use]
    pub fn format_date(&self, weekday: &str, year: u32, month: u32, day: u32) -> String {
        let sep = self.date_separator;
        match self.date_format {
            DateFormatStyle::DayMonthDateYearUs => {
                format!("{weekday} {month:02}{sep}{day:02}{sep}{year:04}")
            }
            DateFormatStyle::Iso8601 => format!("{year:04}{sep}{month:02}{sep}{day:02}"),
            DateFormatStyle::DayMonthYearEuro => format!("{day:02}{sep}{month:02}{sep}{year:04}"),
        }
    }
}

#[cfg(test)]
/// Unit tests for strongly typed `cmd.exe` domain primitives and mode enums.
mod tests {
    use super::*;

    /// Verifies [`ExitCode`] predicates, hex formatting, and ASCII rendering.
    #[test]
    fn test_exit_code() {
        assert!(ExitCode::SUCCESS.is_success());
        assert!(!ExitCode::FAILURE.is_success());
        assert_eq!(ExitCode::COMMAND_NOT_FOUND.code(), 9009);
        assert_eq!(ExitCode::SUCCESS.to_hex_string(), "00000000");
        assert_eq!(ExitCode::new(65).to_hex_string(), "00000041");
        assert_eq!(ExitCode::new(65).to_ascii_string(), "A");
        assert_eq!(ExitCode::SUCCESS.to_ascii_string(), "");
        assert_eq!(ExitCode::new(127).to_ascii_string(), "");
    }

    /// Verifies [`DriveLetter`] parsing, formatting, and hidden `=C:` environment keys.
    #[test]
    fn test_drive_letter() {
        let c = DriveLetter::try_from_char('c');
        assert_eq!(c, Ok(DriveLetter::C));
        assert_eq!(DriveLetter::C.as_char(), 'C');
        assert_eq!(DriveLetter::C.to_string(), "C:");
        assert_eq!(DriveLetter::C.env_var_key(), "=C:");
        assert_eq!(
            DriveLetter::try_from_char('9'),
            Err(CmdError::InvalidDriveLetter { ch: '9' })
        );
    }

    /// Verifies case-insensitive `Eq`, `Ord`, and `Hash` on [`EnvVarName`].
    #[test]
    fn test_env_var_name_case_insensitivity() {
        let v1 = EnvVarName::new("Path");
        let v2 = EnvVarName::new("PATH");
        let v3 = EnvVarName::new("=C:");
        assert_eq!(v1, v2);
        assert_eq!(v1.as_str(), "Path");
        assert_eq!(v1.folded(), "PATH");
        assert_eq!(v1.cmp(&v2), Ordering::Equal);
        assert_eq!(v1.partial_cmp(&v2), Some(Ordering::Equal));
        assert!(!v1.is_hidden());
        assert!(v3.is_hidden());

        let mut set = std::collections::HashSet::new();
        set.insert(v1);
        assert!(set.contains(&v2));
    }

    /// Verifies case-insensitive normalization and `:EOF` detection on [`LabelName`].
    #[test]
    fn test_label_name() {
        let l1 = LabelName::new(" :MyLabel ");
        let l2 = LabelName::new("mylabel");
        let eof = LabelName::new(":eof");
        assert_eq!(l1, l2);
        assert_eq!(l1.as_str(), "MyLabel");
        assert_eq!(l1.folded(), "MYLABEL");
        assert_eq!(l1.cmp(&l2), Ordering::Equal);
        assert_eq!(l1.partial_cmp(&l2), Some(Ordering::Equal));
        assert!(!l1.is_eof());
        assert!(eof.is_eof());

        let mut set = std::collections::HashSet::new();
        set.insert(l1);
        assert!(set.contains(&l2));
    }

    /// Verifies case-sensitive [`ForVarName`] validation and `FOR /F` token-offset stepping.
    #[test]
    fn test_for_var_name() {
        let lower_a = ForVarName::from_char('a');
        let upper_a = ForVarName::from_char('A');
        assert!(lower_a.is_some());
        assert!(upper_a.is_some());
        assert_ne!(lower_a, upper_a);
        assert_eq!(ForVarName::from_char(' '), None);

        assert_eq!(upper_a.map(ForVarName::as_char), Some('A'));
        assert_eq!(
            upper_a
                .and_then(|a| a.offset_by(2))
                .map(ForVarName::as_char),
            Some('C')
        );
        assert_eq!(upper_a.and_then(|a| a.offset_by(200)), None);
        assert_eq!(
            ForVarName::from_char('~').and_then(|t| t.offset_by(1)),
            None
        );
    }

    /// Verifies bounded `0..=9` [`FileDescriptor`] construction.
    #[test]
    fn test_file_descriptor() {
        assert_eq!(FileDescriptor::new(0), Some(FileDescriptor::STDIN));
        assert_eq!(FileDescriptor::new(9).map(FileDescriptor::index), Some(9));
        assert_eq!(FileDescriptor::new(10), None);
    }

    /// Verifies [`CodePage`] numeric ID round-tripping and unknown codepage rejection.
    #[test]
    fn test_codepage() {
        for (id, expected) in [
            (65001, CodePage::Utf8),
            (437, CodePage::OemUnitedStates),
            (850, CodePage::OemMultilingualLatin1),
            (1252, CodePage::WindowsLatin1),
            (1200, CodePage::Utf16Le),
            (1201, CodePage::Utf16Be),
            (20127, CodePage::Ascii),
        ] {
            assert_eq!(CodePage::from_id(id), Ok(expected));
            assert_eq!(expected.id(), id);
        }
        assert_eq!(
            CodePage::from_id(99999),
            Err(CmdError::InvalidCodePage { code: 99999 })
        );
    }

    /// Verifies [`ColorNibble`] ANSI codes and [`ConsoleColor::parse_hex`] validation.
    #[test]
    fn test_color_nibble_and_console_color() {
        for raw in 0u8..=15u8 {
            let nibble = ColorNibble::from_u8(raw);
            assert_eq!(nibble.map(ColorNibble::as_u8), Some(raw));
            assert!(nibble.map_or(0, ColorNibble::ansi_fg_code) >= 30);
            assert!(nibble.map_or(0, ColorNibble::ansi_bg_code) >= 40);
        }
        assert_eq!(ColorNibble::from_u8(16), None);

        let valid = ConsoleColor::parse_hex("0A");
        assert_eq!(
            valid,
            Ok(ConsoleColor {
                background: ColorNibble::Black,
                foreground: ColorNibble::LightGreen
            })
        );
        assert_eq!(valid.clone().map(|c| c.to_string()), Ok("0A".to_owned()));
        assert_eq!(
            valid.map(ConsoleColor::to_ansi_sgr),
            Ok("\x1b[40;92m".to_owned())
        );

        assert_eq!(
            ConsoleColor::parse_hex("AA"),
            Err(CmdError::SameColorForegroundAndBackground { nibble: 0xA })
        );
        assert!(ConsoleColor::parse_hex("").is_err());
        assert!(ConsoleColor::parse_hex("123").is_err());
        assert!(ConsoleColor::parse_hex("ZZ").is_err());
    }

    /// Verifies [`QuoteMode`] toggling and `IsVariant` / `Default` behavior across mode enums.
    #[test]
    fn test_quote_mode_toggle() {
        let mode = QuoteMode::Unquoted;
        assert_eq!(mode.toggle(), QuoteMode::InQuotes);
        assert_eq!(mode.toggle().toggle(), QuoteMode::Unquoted);
        assert!(VfsBackendMode::default().is_in_memory_hermetic());
        assert!(VfsBackendMode::HostNative.is_host_native());
        assert!(HostBindingMode::default().is_isolated());
        assert!(HostBindingMode::Synchronized.is_synchronized());
        assert_eq!(
            OverwritePolicy::from_copycmd_env(None),
            OverwritePolicy::AlwaysOverwrite
        );
        assert_eq!(
            OverwritePolicy::from_copycmd_env(Some("/-y")),
            OverwritePolicy::Prompt
        );
        assert_eq!(
            OverwritePolicy::from_copycmd_env(Some("/n")),
            OverwritePolicy::NeverOverwrite
        );
        assert_eq!(
            OverwritePolicy::from_copycmd_env(Some("/y")),
            OverwritePolicy::AlwaysOverwrite
        );
        assert!(InterruptState::default().is_clear());
        assert!(InterruptState::Pending.is_pending());
        assert!(StartWindowMode::default().is_normal());
        assert!(StartEnvMode::default().is_current_env());
        assert!(ProcessPriority::default().is_normal());
        assert!(PipeExecutionMode::default().is_in_memory_buffered());
        assert!(DoskeyEditMode::default().is_insert());

        let mut locale = CmdLocaleConfig::default();
        assert_eq!(
            locale.format_number_with_thousands(1_234_567, ThousandsSeparatorMode::UseSeparator),
            "1,234,567"
        );
        assert_eq!(
            locale.format_number_with_thousands(1_234_567, ThousandsSeparatorMode::OmitSeparator),
            "1234567"
        );
        assert_eq!(locale.format_date("Wed", 2026, 11, 10), "Wed 11/10/2026");
        locale.date_format = DateFormatStyle::Iso8601;
        locale.date_separator = '-';
        assert_eq!(locale.format_date("Wed", 2026, 11, 10), "2026-11-10");
        locale.date_format = DateFormatStyle::DayMonthYearEuro;
        locale.date_separator = '.';
        assert_eq!(locale.format_date("Wed", 2026, 11, 10), "10.11.2026");
        assert!(TimeClockFormat::default().is_twelve_hour_am_pm());

        assert_eq!(
            PercentArity::for_execution_context(ExecutionContext::BatchFile),
            PercentArity::DoublePercent
        );
        assert_eq!(
            PercentArity::for_execution_context(ExecutionContext::InteractiveRepl),
            PercentArity::SinglePercent
        );
        assert_eq!(
            PercentArity::for_execution_context(ExecutionContext::PipeSubshell),
            PercentArity::SinglePercent
        );
        assert_eq!(
            PercentArity::for_execution_context(ExecutionContext::ForFSubshell),
            PercentArity::SinglePercent
        );
        assert_eq!(
            PercentArity::from_percent_count(1),
            Some(PercentArity::SinglePercent)
        );
        assert_eq!(
            PercentArity::from_percent_count(2),
            Some(PercentArity::DoublePercent)
        );
        assert_eq!(PercentArity::from_percent_count(3), None);
        assert_eq!(PercentArity::SinglePercent.prefix_str(), "%");
        assert_eq!(PercentArity::DoublePercent.prefix_str(), "%%");
        assert!(PercentArity::default().is_double_percent());
        assert!(PercentArity::SinglePercent.is_single_percent());

        assert!(RecoveryMode::default().is_strict());
        assert!(RecoveryMode::Recovering.is_recovering());

        assert!(QuoteInsertionStrategy::default().is_wrap_whole_word());
        assert!(QuoteInsertionStrategy::StripAndWrapModifier.is_strip_and_wrap_modifier());
        assert_eq!(fold_win32_case("caf\u{00E9}"), "CAF\u{00C9}");
    }
}
