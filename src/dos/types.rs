//! Strongly typed MS-DOS FAT timestamps, attribute bytes, 8.3 filenames, PSP command tails,
//! version descriptors, memory arena statistics, and BIOS keyboard scan codes.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use derive_more::Display;

use crate::error::CmdError;
use crate::types::{CR_CHAR, LF_CHAR};
use crate::vfs::path::generate_short_name_8_3;
use crate::vfs::{FileAttributeFlags, FileTimestamp};

/// Unix epoch seconds corresponding to the MS-DOS FAT minimum timestamp (`1980-01-01T00:00:00Z`).
pub const DOS_MIN_EPOCH_SECS: u64 = 315_532_800;

/// Unix epoch seconds corresponding to the MS-DOS FAT maximum timestamp (`2107-12-31T23:59:58Z`).
pub const DOS_MAX_EPOCH_SECS: u64 = 4_354_819_198;

/// Maximum byte length of an MS-DOS Program Segment Prefix (`PSP:0x80`) command tail (`126` bytes).
pub const MAX_PSP_COMMAND_TAIL_BYTES: usize = 126;

/// Packed 16-bit MS-DOS FAT directory date (`bits 9..=15 = year - 1980`, `bits 5..=8 = month`, `bits 0..=4 = day`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[display("{:#06x}", self.0)]
pub struct PackedDosDate(
    /// Raw 16-bit MS-DOS date word.
    pub u16,
);

impl PackedDosDate {
    /// Minimum valid MS-DOS date (`1980-01-01`, raw `0x0021`).
    pub const MIN_1980_01_01: Self = Self(0x0021);

    /// Maximum valid MS-DOS date (`2107-12-31`, raw `0xFF9F`).
    pub const MAX_2107_12_31: Self = Self(0xFF9F);

    /// Encodes `(year, month, day)` into a [`PackedDosDate`] if within valid Gregorian and FAT bounds (`1980..=2107`).
    ///
    /// # Arguments
    /// * `year` - 4-digit Gregorian year (`1980..=2107`).
    /// * `month` - 1-based month (`1..=12`).
    /// * `day` - 1-based day of month (`1..=days_in_month(year, month)`).
    ///
    /// # Returns
    /// `Some(PackedDosDate)` when calendar components are valid, or `None` otherwise.
    #[must_use]
    pub const fn encode(year: u16, month: u8, day: u8) -> Option<Self> {
        if year < 1980 || year > 2107 || day < 1 {
            return None;
        }
        let Some(max_day) = FileTimestamp::days_in_month(year as u32, month as u32) else {
            return None;
        };
        if (day as u32) > max_day {
            return None;
        }
        let y_off = year.saturating_sub(1980);
        let packed = (y_off << 9) | ((month as u16) << 5) | (day as u16);
        Some(Self(packed))
    }

    /// Extracts the 4-digit Gregorian year (`1980..=2107`).
    ///
    /// # Returns
    /// Decoded Gregorian year.
    #[must_use]
    pub const fn year(self) -> u16 {
        1980u16.saturating_add((self.0 >> 9) & 0x7F)
    }

    /// Extracts the raw 4-bit month field (`0..=15`, valid when `1..=12`).
    ///
    /// # Returns
    /// Raw month nibble.
    #[must_use]
    pub const fn month(self) -> u8 {
        let [lo, _] = ((self.0 >> 5) & 0x0F).to_le_bytes();
        lo
    }

    /// Extracts the raw 5-bit day-of-month field (`0..=31`, valid when `1..=days_in_month`).
    ///
    /// # Returns
    /// Raw day field.
    #[must_use]
    pub const fn day(self) -> u8 {
        let [lo, _] = (self.0 & 0x1F).to_le_bytes();
        lo
    }
}

/// Packed 16-bit MS-DOS FAT directory time (`bits 11..=15 = hour`, `bits 5..=10 = minute`, `bits 0..=4 = second / 2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[display("{:#06x}", self.0)]
pub struct PackedDosTime(
    /// Raw 16-bit MS-DOS time word.
    pub u16,
);

impl PackedDosTime {
    /// Midnight (`00:00:00`, raw `0x0000`).
    pub const MIDNIGHT: Self = Self(0);

    /// End of day at 2-second FAT resolution (`23:59:58`, raw `0xBF7D`).
    pub const MAX_23_59_58: Self = Self(0xBF7D);

    /// Encodes `(hour, minute, second)` into a [`PackedDosTime`] (rounding `second` down to an even second).
    ///
    /// # Arguments
    /// * `hour` - Hour in 24-hour clock (`0..=23`).
    /// * `minute` - Minute (`0..=59`).
    /// * `second` - Second (`0..=59`, stored as `second / 2`).
    ///
    /// # Returns
    /// `Some(PackedDosTime)` when `(hour, minute, second)` are in range, or `None` otherwise.
    #[must_use]
    pub const fn encode(hour: u8, minute: u8, second: u8) -> Option<Self> {
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        let sec_div2 = second / 2;
        let packed = ((hour as u16) << 11) | ((minute as u16) << 5) | (sec_div2 as u16);
        Some(Self(packed))
    }

    /// Extracts the 5-bit hour field (`0..=31`, valid when `0..=23`).
    ///
    /// # Returns
    /// Raw hour field.
    #[must_use]
    pub const fn hour(self) -> u8 {
        let [lo, _] = ((self.0 >> 11) & 0x1F).to_le_bytes();
        lo
    }

    /// Extracts the 6-bit minute field (`0..=63`, valid when `0..=59`).
    ///
    /// # Returns
    /// Raw minute field.
    #[must_use]
    pub const fn minute(self) -> u8 {
        let [lo, _] = ((self.0 >> 5) & 0x3F).to_le_bytes();
        lo
    }

    /// Extracts the even second value (`0..=62`, valid when `0..=58`).
    ///
    /// # Returns
    /// Decoded even second (`(raw & 0x1F) * 2`).
    #[must_use]
    pub const fn second(self) -> u8 {
        let [lo, _] = (self.0 & 0x1F).to_le_bytes();
        lo.saturating_mul(2)
    }
}

/// Combined 32-bit MS-DOS FAT modification timestamp (`PackedDosDate` + `PackedDosTime`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[display("{date}:{time}")]
pub struct PackedDosTimestamp {
    /// Packed 16-bit MS-DOS calendar date (`DX` in `INT 21h AX=5700h`).
    pub date: PackedDosDate,
    /// Packed 16-bit MS-DOS clock time (`CX` in `INT 21h AX=5700h`).
    pub time: PackedDosTime,
}

impl Default for PackedDosTimestamp {
    /// Returns [`PackedDosTimestamp`] encoded from [`FileTimestamp::default()`].
    ///
    /// # Returns
    /// Default [`PackedDosTimestamp`].
    fn default() -> Self {
        Self::from_file_timestamp(FileTimestamp::default())
    }
}

impl PackedDosTimestamp {
    /// Converts a [`FileTimestamp`] into a [`PackedDosTimestamp`], clamping pre-1980 timestamps to
    /// `1980-01-01 00:00:00` and post-2107 timestamps to `2107-12-31 23:59:58` with 2-second FAT resolution.
    ///
    /// # Arguments
    /// * `ts` - Source [`FileTimestamp`].
    ///
    /// # Returns
    /// Clamped [`PackedDosTimestamp`].
    #[must_use]
    pub fn from_file_timestamp(ts: FileTimestamp) -> Self {
        let secs = ts.epoch_secs();
        if secs <= DOS_MIN_EPOCH_SECS {
            return Self {
                date: PackedDosDate::MIN_1980_01_01,
                time: PackedDosTime::MIDNIGHT,
            };
        }
        if secs >= DOS_MAX_EPOCH_SECS {
            return Self {
                date: PackedDosDate::MAX_2107_12_31,
                time: PackedDosTime::MAX_23_59_58,
            };
        }

        let days_u64 = secs / 86_400;
        let rem_secs = secs % 86_400;
        let hour = u8::try_from(rem_secs / 3_600).unwrap_or(0);
        let minute = u8::try_from((rem_secs % 3_600) / 60).unwrap_or(0);
        let second = u8::try_from(rem_secs % 60).unwrap_or(0);

        let z = days_u64.saturating_add(719_468);
        let era = z / 146_097;
        let doe = z.saturating_sub(era.saturating_mul(146_097));
        let yoe = (doe
            .saturating_sub(doe / 1_460)
            .saturating_add(doe / 36_524)
            .saturating_sub(doe / 146_096))
            / 365;
        let y = yoe.saturating_add(era.saturating_mul(400));
        let doy = doe.saturating_sub(
            365u64
                .saturating_mul(yoe)
                .saturating_add(yoe / 4)
                .saturating_sub(yoe / 100),
        );
        let mp = (5u64.saturating_mul(doy).saturating_add(2)) / 153;
        let day = u8::try_from(
            doy.saturating_sub((153u64.saturating_mul(mp).saturating_add(2)) / 5)
                .saturating_add(1),
        )
        .unwrap_or(1);
        let month_u64 = if mp < 10 {
            mp.saturating_add(3)
        } else {
            mp.saturating_sub(9)
        };
        let year_u64 = if month_u64 <= 2 {
            y.saturating_add(1)
        } else {
            y
        };
        let year = u16::try_from(year_u64).unwrap_or(2107);
        let month = u8::try_from(month_u64).unwrap_or(1);

        let date = PackedDosDate::encode(year, month, day).unwrap_or(PackedDosDate::MIN_1980_01_01);
        let time = PackedDosTime::encode(hour, minute, second).unwrap_or(PackedDosTime::MIDNIGHT);
        Self { date, time }
    }

    /// Decodes this [`PackedDosTimestamp`] back into a [`FileTimestamp`], rejecting malformed bitfields.
    ///
    /// # Returns
    /// `Ok(FileTimestamp)` with 2-second precision.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if the packed month (`0` or `>12`), day (`0` or `>days_in_month`),
    /// hour (`>23`), minute (`>59`), or 2-second field (`>58`) is invalid.
    pub fn to_file_timestamp(self) -> Result<FileTimestamp, CmdError> {
        let year = u32::from(self.date.year());
        let month = u32::from(self.date.month());
        let day = u32::from(self.date.day());
        let hour = u32::from(self.time.hour());
        let minute = u32::from(self.time.minute());
        let second = self.time.second();
        if second > 58 {
            return Err(CmdError::IoFailure {
                operation: "decode DOS timestamp".to_owned(),
                message: format!("invalid packed DOS second value {second}"),
            });
        }
        let base_ts =
            FileTimestamp::from_civil_utc(year, month, day, hour, minute).ok_or_else(|| {
                CmdError::IoFailure {
                    operation: "decode DOS timestamp".to_owned(),
                    message: format!(
                        "invalid packed DOS date/time {year:04}-{month:02}-{day:02} {hour:02}:{minute:02}"
                    ),
                }
            })?;
        Ok(FileTimestamp::from_epoch_secs(
            base_ts.epoch_secs().saturating_add(u64::from(second)),
        ))
    }
}

/// Raw MS-DOS `INT 21h AH=43h` / FAT directory attribute byte (`R/H/S/V/D/A`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Display)]
#[display("{:#04x}", self.0)]
pub struct FatAttributeByte(
    /// Raw 8-bit FAT attribute bitmask.
    pub u8,
);

impl FatAttributeByte {
    /// Normal file with no attribute bits set (`0x00`).
    pub const NORMAL: Self = Self(0x00);
    /// Read-only attribute bit (`0x01`).
    pub const READ_ONLY: Self = Self(0x01);
    /// Hidden attribute bit (`0x02`).
    pub const HIDDEN: Self = Self(0x02);
    /// System attribute bit (`0x04`).
    pub const SYSTEM: Self = Self(0x04);
    /// Volume label directory entry bit (`0x08`).
    pub const VOLUME_LABEL: Self = Self(0x08);
    /// Subdirectory entry bit (`0x10`).
    pub const DIRECTORY: Self = Self(0x10);
    /// Archive (modified since last backup) bit (`0x20`).
    pub const ARCHIVE: Self = Self(0x20);

    /// Checks whether all bits in `other` are set in `self`.
    ///
    /// # Arguments
    /// * `other` - Attribute mask to test.
    ///
    /// # Returns
    /// `true` when `(self.0 & other.0) == other.0`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns the raw 8-bit FAT attribute bitmask.
    ///
    /// # Returns
    /// Raw `u8` attribute byte.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Returns `true` when the `DIRECTORY` (`0x10`) bit is set.
    ///
    /// # Returns
    /// `true` if `self` describes a directory.
    #[must_use]
    pub const fn is_directory(self) -> bool {
        self.contains(Self::DIRECTORY)
    }

    /// Returns `true` when the `READ_ONLY` (`0x01`) bit is set.
    ///
    /// # Returns
    /// `true` if `self` is marked read-only.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        self.contains(Self::READ_ONLY)
    }

    /// Converts VFS [`FileAttributeFlags`] into an MS-DOS [`FatAttributeByte`].
    ///
    /// # Arguments
    /// * `flags` - VFS [`FileAttributeFlags`].
    ///
    /// # Returns
    /// Corresponding [`FatAttributeByte`].
    #[must_use]
    pub const fn from_vfs_flags(flags: FileAttributeFlags) -> Self {
        let mut bits = 0u8;
        if flags.is_read_only() {
            bits |= Self::READ_ONLY.0;
        }
        if flags.is_hidden() {
            bits |= Self::HIDDEN.0;
        }
        if flags.is_system() {
            bits |= Self::SYSTEM.0;
        }
        if flags.is_directory() {
            bits |= Self::DIRECTORY.0;
        }
        if flags.is_archive() {
            bits |= Self::ARCHIVE.0;
        }
        Self(bits)
    }

    /// Converts an MS-DOS [`FatAttributeByte`] into VFS [`FileAttributeFlags`].
    ///
    /// # Returns
    /// Corresponding [`FileAttributeFlags`].
    #[must_use]
    pub const fn to_vfs_flags(self) -> FileAttributeFlags {
        let mut flags = FileAttributeFlags::EMPTY;
        if self.contains(Self::READ_ONLY) {
            flags.insert(FileAttributeFlags::READ_ONLY);
        }
        if self.contains(Self::HIDDEN) {
            flags.insert(FileAttributeFlags::HIDDEN);
        }
        if self.contains(Self::SYSTEM) {
            flags.insert(FileAttributeFlags::SYSTEM);
        }
        if self.contains(Self::DIRECTORY) {
            flags.insert(FileAttributeFlags::DIRECTORY);
        }
        if self.contains(Self::ARCHIVE) {
            flags.insert(FileAttributeFlags::ARCHIVE);
        }
        flags
    }
}

/// Short-name generation policy for FAT 8.3 directory entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
pub enum ShortNamePolicy {
    /// Classic MS-DOS 6.22 `COMMAND.COM` truncation: uppercase first 8 stem bytes and first 3 extension bytes,
    /// rejecting spaces, illegal FAT punctuation, and extra dots (`a.b.c`).
    #[default]
    #[display("strict_dos_truncate")]
    StrictDosTruncate,
    /// Windows 95 / DOS 7.x LFN numeric-tail generation (`LONGFI~1.TXT`, `LONGFI~2.TXT`).
    #[display("win95_numeric_tail")]
    Win95NumericTail,
}

/// Validated MS-DOS 8.3 uppercase directory entry name (`1..=8` stem + optional `.` + `1..=3` extension).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[display("{full}")]
pub struct DosFileName8Dot3 {
    /// Uppercase 1–8 character base name.
    stem: String,
    /// Optional uppercase 1–3 character extension (without leading dot).
    ext: String,
    /// Canonical `"STEM"` or `"STEM.EXT"` string.
    full: String,
}

impl DosFileName8Dot3 {
    /// Checks whether `b` is a legal non-dot ASCII byte inside an MS-DOS FAT 8.3 stem or extension.
    ///
    /// Rejects control bytes (`<= 0x1F`), space (`0x20`), `0x7F`, and FAT delimiters
    /// (`"`, `*`, `+`, `,`, `.`, `/`, `:`, `;`, `<`, `=`, `>`, `?`, `[`, `0x5C`, `]`, `|`).
    ///
    /// # Arguments
    /// * `b` - Raw byte to inspect.
    ///
    /// # Returns
    /// `true` when `b` is permitted in a strict MS-DOS 8.3 identifier.
    #[must_use]
    pub const fn is_legal_fat_8_3_byte(b: u8) -> bool {
        if b <= 0x20 || b == 0x7F {
            return false;
        }
        !matches!(
            b,
            b'"' | b'*'
                | b'+'
                | b','
                | b'.'
                | b'/'
                | b':'
                | b';'
                | b'<'
                | b'='
                | b'>'
                | b'?'
                | b'['
                | 0x5C
                | b']'
                | b'|'
        )
    }

    /// Validates a strict MS-DOS 8.3 filename without silent truncation (`<= 8` stem chars, `<= 3` ext chars,
    /// at most one `.`, non-empty stem, and only legal FAT characters).
    ///
    /// # Arguments
    /// * `raw` - Candidate filename component.
    ///
    /// # Returns
    /// `Ok(DosFileName8Dot3)` normalized to uppercase ASCII.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`] if `raw` is empty, exceeds 8.3 length bounds, contains multiple dots,
    /// or contains illegal FAT characters.
    pub fn validate_strict(raw: &str) -> Result<Self, CmdError> {
        let trimmed = raw.trim_end_matches('.');
        if trimmed.is_empty() {
            return Err(CmdError::PathNotFound {
                path: raw.to_owned(),
            });
        }
        let (stem_raw, ext_raw) = match trimmed.split_once('.') {
            Some((s, e)) => {
                if e.contains('.') {
                    return Err(CmdError::PathNotFound {
                        path: raw.to_owned(),
                    });
                }
                (s, e)
            }
            None => (trimmed, ""),
        };
        if stem_raw.is_empty()
            || stem_raw.len() > 8
            || ext_raw.len() > 3
            || !stem_raw.bytes().all(Self::is_legal_fat_8_3_byte)
            || !ext_raw.bytes().all(Self::is_legal_fat_8_3_byte)
        {
            return Err(CmdError::PathNotFound {
                path: raw.to_owned(),
            });
        }
        let stem = stem_raw.to_ascii_uppercase();
        let ext = ext_raw.to_ascii_uppercase();
        let full = if ext.is_empty() {
            stem.clone()
        } else {
            format!("{stem}.{ext}")
        };
        Ok(Self { stem, ext, full })
    }

    /// Normalizes a path component into a valid [`DosFileName8Dot3`] according to `policy`.
    ///
    /// - Under [`ShortNamePolicy::StrictDosTruncate`]: rejects illegal FAT bytes and multiple dots
    ///   (matching real MS-DOS 6.22 `INT 21h`), while truncating legal stems (`>8` -> `8`) and extensions (`>3` -> `3`).
    /// - Under [`ShortNamePolicy::Win95NumericTail`]: generates a deterministic `~N` numeric-tail 8.3 alias
    ///   via [`generate_short_name_8_3`] for any non-empty LFN component.
    ///
    /// # Arguments
    /// * `raw` - Raw filename component.
    /// * `policy` - Active [`ShortNamePolicy`].
    /// * `collision_index` - 1-based collision index (`1` for `~1`, `2` for `~2`, etc.) used in `Win95NumericTail`.
    ///
    /// # Returns
    /// `Ok(DosFileName8Dot3)` on valid conversion.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`] if `raw` cannot form a legal 8.3 name under `policy`.
    pub fn normalize(
        raw: &str,
        policy: ShortNamePolicy,
        collision_index: u8,
    ) -> Result<Self, CmdError> {
        match policy {
            ShortNamePolicy::StrictDosTruncate => {
                let trimmed = raw.trim_end_matches('.');
                let (stem_raw, ext_raw) = match trimmed.split_once('.') {
                    Some((s, e)) => {
                        if e.contains('.') {
                            return Err(CmdError::PathNotFound {
                                path: raw.to_owned(),
                            });
                        }
                        (s, e)
                    }
                    None => (trimmed, ""),
                };
                if stem_raw.is_empty()
                    || !stem_raw.bytes().all(Self::is_legal_fat_8_3_byte)
                    || !ext_raw.bytes().all(Self::is_legal_fat_8_3_byte)
                {
                    return Err(CmdError::PathNotFound {
                        path: raw.to_owned(),
                    });
                }
                let stem: String = stem_raw
                    .chars()
                    .take(8)
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                let ext: String = ext_raw
                    .chars()
                    .take(3)
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                let full = if ext.is_empty() {
                    stem.clone()
                } else {
                    format!("{stem}.{ext}")
                };
                Ok(Self { stem, ext, full })
            }
            ShortNamePolicy::Win95NumericTail => {
                let idx = collision_index.max(1);
                let generated = generate_short_name_8_3(raw, idx);
                Self::validate_strict(&generated)
            }
        }
    }

    /// Returns the uppercase 1–8 character base stem.
    ///
    /// # Returns
    /// Stem `&str`.
    #[must_use]
    pub fn stem(&self) -> &str {
        &self.stem
    }

    /// Returns the uppercase 0–3 character extension (without leading `.`).
    ///
    /// # Returns
    /// Extension `&str` (`""` when no extension is present).
    #[must_use]
    pub fn extension(&self) -> &str {
        &self.ext
    }

    /// Returns the formatted `"STEM"` or `"STEM.EXT"` 8.3 filename.
    ///
    /// # Returns
    /// Canonical 8.3 `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.full
    }
}

/// Policy for transferring external MS-DOS command lines longer than 126 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
pub enum LongCmdlineTransfer {
    /// Strict real-mode MS-DOS 126-byte PSP limit: return [`CmdError::CommandLineTooLong`] if `> 126` bytes.
    #[display("strict_126_byte_psp")]
    Strict126BytePsp,
    /// DJGPP / `FreeDOS` / 4DOS convention: truncate the `PSP:0x80` tail at 126 bytes and export the full
    /// command line in the child's `CMDLINE=` environment variable.
    #[default]
    #[display("cmdline_env_var")]
    CmdlineEnvVar,
    /// DJGPP `@file` response-file convention: write arguments exceeding 126 bytes into a temporary `.RSP` file
    /// and pass `@<path>` in the child's 126-byte `PSP:0x80` tail.
    #[display("response_file_at_sign")]
    ResponseFileAtSign,
}

/// Maximum serialized MS-DOS child environment block size (`KEY=VAL\0...\0\0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum DosEnvSizeLimit {
    /// Classic real-mode `COMMAND.COM /E:nnnnn` paragraph limit (`160..=32768` bytes).
    #[display("command_com_bytes({_0})")]
    CommandComBytes(
        /// Maximum environment block byte size.
        u16,
    ),
    /// 32-bit protected-mode DPMI transfer limit (`32_767` bytes).
    #[display("dpmi_32kib")]
    Dpmi32KiB,
}

impl Default for DosEnvSizeLimit {
    /// Defaults to [`Self::Dpmi32KiB`] (`32_767` bytes) for 32-bit DJGPP / DPMI execution.
    ///
    /// # Returns
    /// [`Self::Dpmi32KiB`].
    fn default() -> Self {
        Self::Dpmi32KiB
    }
}

impl DosEnvSizeLimit {
    /// Returns the maximum allowed byte length for the serialized environment block.
    ///
    /// # Returns
    /// Maximum byte count.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::CommandComBytes(n) => n as usize,
            Self::Dpmi32KiB => 32_767,
        }
    }

    /// Computes the exact MS-DOS serialized environment block byte length (`KEY=VALUE\0...\0\0`) and
    /// verifies that it fits within `self.max_bytes()`.
    ///
    /// # Arguments
    /// * `env_vars` - `(key, value)` environment pairs.
    ///
    /// # Returns
    /// `Ok(serialized_byte_len)` when within limit.
    ///
    /// # Errors
    /// Returns [`CmdError::OutOfEnvironmentSpace`] when the block exceeds `self.max_bytes()`.
    pub fn validate_env_block(self, env_vars: &[(String, String)]) -> Result<usize, CmdError> {
        let mut total: usize = 1;
        for (k, v) in env_vars {
            total = total
                .saturating_add(k.len())
                .saturating_add(1)
                .saturating_add(v.len())
                .saturating_add(1);
        }
        if total == 1 {
            total = 2;
        }
        if total > self.max_bytes() {
            return Err(CmdError::OutOfEnvironmentSpace);
        }
        Ok(total)
    }
}

/// Error-handling policy when deleting temporary `%TEMP%` spool files after child execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
pub enum PipeSpoolCleanupPolicy {
    /// Propagate any spool-file deletion error (except `FileNotFound` if the child removed it).
    #[default]
    #[display("strict")]
    Strict,
    /// Ignore spool-file deletion errors after child completion.
    #[display("best_effort")]
    BestEffort,
}

/// Validated MS-DOS Program Segment Prefix (`PSP:0x80`) 126-byte command-line tail.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct PspCommandTail {
    /// Raw command-tail payload (`0..=126` bytes, without trailing `0x0D`).
    tail_bytes: Vec<u8>,
}

impl PspCommandTail {
    /// Encodes `raw_tail` into a [`PspCommandTail`] (and optional full `CMDLINE=` string when overflowing).
    ///
    /// Strips any embedded `CR`/`LF` terminators prior to length checking. When `raw_tail` is non-empty
    /// and does not already start with a leading space, prepends `' '` to match authentic `COMMAND.COM`
    /// `PSP:0x81` formatting (`" arg1 arg2"`).
    ///
    /// # Arguments
    /// * `program_name` - Program token placed at the front of `CMDLINE=` when long-command-line transfer triggers.
    /// * `raw_tail` - Argument tail string following the program name.
    /// * `transfer` - [`LongCmdlineTransfer`] overflow policy.
    ///
    /// # Returns
    /// `Ok((psp_tail, optional_cmdline_env))` where `optional_cmdline_env` is `Some("prog args...")`
    /// when `transfer == CmdlineEnvVar` and the formatted PSP tail exceeded 126 bytes.
    ///
    /// # Errors
    /// Returns [`CmdError::CommandLineTooLong`] when the PSP tail exceeds 126 bytes under
    /// [`LongCmdlineTransfer::Strict126BytePsp`].
    pub fn encode(
        program_name: &str,
        raw_tail: &str,
        transfer: LongCmdlineTransfer,
    ) -> Result<(Self, Option<String>), CmdError> {
        let clean_tail = raw_tail.trim_matches([CR_CHAR, LF_CHAR]);
        let formatted = if clean_tail.is_empty() || clean_tail.starts_with(' ') {
            clean_tail.to_owned()
        } else {
            format!(" {clean_tail}")
        };
        let bytes = formatted.as_bytes();
        if bytes.len() <= MAX_PSP_COMMAND_TAIL_BYTES {
            return Ok((
                Self {
                    tail_bytes: bytes.to_vec(),
                },
                None,
            ));
        }
        match transfer {
            LongCmdlineTransfer::Strict126BytePsp | LongCmdlineTransfer::ResponseFileAtSign => {
                Err(CmdError::CommandLineTooLong {
                    length: bytes.len(),
                    limit: MAX_PSP_COMMAND_TAIL_BYTES,
                })
            }
            LongCmdlineTransfer::CmdlineEnvVar => {
                let truncated = bytes
                    .get(..MAX_PSP_COMMAND_TAIL_BYTES)
                    .unwrap_or(bytes)
                    .to_vec();
                let full_cmdline = format!("{program_name}{formatted}");
                Ok((
                    Self {
                        tail_bytes: truncated,
                    },
                    Some(full_cmdline),
                ))
            }
        }
    }

    /// Returns the length byte (`0..=126`) stored at `PSP:0x80`.
    ///
    /// # Returns
    /// Tail byte count as `u8`.
    #[must_use]
    pub fn len_byte(&self) -> u8 {
        u8::try_from(self.tail_bytes.len()).unwrap_or(126)
    }

    /// Returns `true` when the PSP tail contains zero bytes.
    ///
    /// # Returns
    /// `true` if `len_byte() == 0`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tail_bytes.is_empty()
    }

    /// Borrows the raw PSP tail bytes (`PSP:0x81..0x81+len`, excluding trailing `0x0D`).
    ///
    /// # Returns
    /// Slice of tail bytes (`<= 126` bytes).
    #[must_use]
    pub fn tail_bytes(&self) -> &[u8] {
        &self.tail_bytes
    }

    /// Serializes the complete `PSP:0x80` structure (`[len_byte, tail_bytes..., 0x0D]`).
    ///
    /// # Returns
    /// Serialized PSP command-tail block (`2..=128` bytes).
    #[must_use]
    pub fn to_psp_block(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.tail_bytes.len().saturating_add(2));
        out.push(self.len_byte());
        out.extend_from_slice(&self.tail_bytes);
        out.push(0x0D);
        out
    }
}

/// MS-DOS OEM vendor identifier reported by `INT 21h AH=30h` (`BH` register).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
pub enum DosOemVendor {
    /// IBM PC-DOS (`0x00`).
    #[display("PC-DOS")]
    PcDos,
    /// Microsoft MS-DOS (`0xFF` / `0x00`).
    #[default]
    #[display("MS-DOS")]
    MsDos,
    /// `FreeDOS` (`0xFD`).
    #[display("FreeDOS")]
    FreeDos,
    /// Novell / Caldera DR-DOS (`0xEE`).
    #[display("DR-DOS")]
    DrDos,
    /// Windows 95 / 98 / ME MS-DOS 7.x / 8.0 (`0xFF` major `7`/`8`).
    #[display("MS-DOS 7")]
    Windows9xDos7,
    /// `DOSBox` / DOSBox-X integrated DOS kernel.
    #[display("DOSBox")]
    DosBox,
    /// Unrecognized OEM vendor byte.
    #[display("OEM({_0:#04x})")]
    Unknown(
        /// Raw `BH` OEM identifier byte.
        u8,
    ),
}

/// MS-DOS kernel version descriptor (`INT 21h AH=30h` / `AX=3306h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
#[display("{oem_id} Version {major}.{minor:02}")]
pub struct DosVersion {
    /// Major version number (e.g., `6` for MS-DOS 6.22, `7` for Windows 98 DOS 7.10).
    pub major: u8,
    /// Minor version number (`0..=99`, e.g., `22` for 6.22).
    pub minor: u8,
    /// OEM kernel vendor classification.
    pub oem_id: DosOemVendor,
}

impl Default for DosVersion {
    /// Defaults to `MS-DOS Version 6.22`.
    ///
    /// # Returns
    /// `DosVersion { major: 6, minor: 22, oem_id: DosOemVendor::MsDos }`.
    fn default() -> Self {
        Self {
            major: 6,
            minor: 22,
            oem_id: DosOemVendor::MsDos,
        }
    }
}

/// Long Filename (`INT 21h AX=71xxh`) support state for a DOS logical drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
pub enum LfnSupportMode {
    /// Classic MS-DOS FAT12/FAT16 8.3-only volume (`INT 21h AX=71A0h` unsupported).
    #[default]
    #[display("8.3_only")]
    Disabled8Dot3Only,
    /// DOS 7+ / `FreeDOS` `DOSLFN` volume supporting 255-character long filenames (`INT 21h AX=71xxh`).
    #[display("lfn_int21_71h")]
    EnabledInt21Ax71,
}

/// Write-protection state of a DOS logical drive (e.g., 3.5" floppy write-protect tab).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
pub enum WriteProtectState {
    /// Media accepts read and write operations.
    #[default]
    #[display("writable")]
    Writable,
    /// Media is write-protected (`DosErrorCode::WriteProtectedDisk` on mutations).
    #[display("write_protected")]
    WriteProtected,
}

/// Media readiness state of a removable or fixed DOS logical drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
pub enum DriveMediaState {
    /// Media is inserted and ready (`Ready`).
    #[default]
    #[display("ready")]
    Ready,
    /// Drive door open or no diskette inserted (`DosErrorCode::DriveNotReady`).
    #[display("not_ready")]
    DriveNotReady,
}

/// Conventional (`640 KiB`) and DPMI extended memory statistics reported by the DOS environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DosMemoryStats {
    /// Total free conventional memory below `640 KiB` in bytes.
    pub conventional_free_bytes: u32,
    /// Largest contiguous conventional MCB block available for real-mode child `EXEC` in bytes.
    pub largest_conventional_block: u32,
    /// Free physical/extended DPMI memory in bytes (`DPMI AX=0500h`).
    pub dpmi_free_physical_bytes: u64,
    /// Largest allocatable 32-bit DPMI linear memory block in bytes.
    pub dpmi_largest_block_bytes: u64,
}

impl Default for DosMemoryStats {
    /// Returns a realistic 32-bit DJGPP + `CWSDPMI` memory profile (`580 KiB` conventional free, `8 MiB` DPMI free).
    ///
    /// # Returns
    /// Default [`DosMemoryStats`].
    fn default() -> Self {
        Self {
            conventional_free_bytes: 593_920,
            largest_conventional_block: 589_824,
            dpmi_free_physical_bytes: 8 * 1024 * 1024,
            dpmi_largest_block_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Extended IBM PC BIOS keyboard scan codes (`INT 16h AH=00h/10h` after `0x00` or `0xE0` prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum BiosScanCode {
    /// `0x47`: `Home` key.
    #[display("Home")]
    Home,
    /// `0x48`: `Up` arrow key.
    #[display("Up")]
    Up,
    /// `0x49`: `PageUp` key.
    #[display("PageUp")]
    PageUp,
    /// `0x4B`: `Left` arrow key.
    #[display("Left")]
    Left,
    /// `0x4D`: `Right` arrow key.
    #[display("Right")]
    Right,
    /// `0x4F`: `End` key.
    #[display("End")]
    End,
    /// `0x50`: `Down` arrow key.
    #[display("Down")]
    Down,
    /// `0x51`: `PageDown` key.
    #[display("PageDown")]
    PageDown,
    /// `0x52`: `Insert` key.
    #[display("Insert")]
    Insert,
    /// `0x53`: `Delete` key.
    #[display("Delete")]
    Delete,
    /// `0x3B`: `F1` function key (`DOSKEY` copy single template character).
    #[display("F1")]
    F1,
    /// `0x3D`: `F3` function key (`DOSKEY` copy remaining template).
    #[display("F3")]
    F3,
    /// `0x41`: `F7` function key (`DOSKEY` history popup/list).
    #[display("F7")]
    F7,
    /// `0x42`: `F8` function key (`DOSKEY` prefix history search).
    #[display("F8")]
    F8,
    /// `0x43`: `F9` function key (`DOSKEY` select history entry by number).
    #[display("F9")]
    F9,
    /// Any other raw extended scan code byte.
    #[display("Scan({_0:#04x})")]
    Other(
        /// Raw BIOS extended scan code byte.
        u8,
    ),
}

impl BiosScanCode {
    /// Decodes a raw IBM PC extended scan code byte (`AH` when `AL == 0x00` or `0xE0`).
    ///
    /// # Arguments
    /// * `scan` - Raw extended scan code byte.
    ///
    /// # Returns
    /// Decoded [`BiosScanCode`].
    #[must_use]
    pub const fn from_raw(scan: u8) -> Self {
        match scan {
            0x3B => Self::F1,
            0x3D => Self::F3,
            0x41 => Self::F7,
            0x42 => Self::F8,
            0x43 => Self::F9,
            0x47 => Self::Home,
            0x48 => Self::Up,
            0x49 => Self::PageUp,
            0x4B => Self::Left,
            0x4D => Self::Right,
            0x4F => Self::End,
            0x50 => Self::Down,
            0x51 => Self::PageDown,
            0x52 => Self::Insert,
            0x53 => Self::Delete,
            other => Self::Other(other),
        }
    }
}

/// Decoded single console key event returned by [`super::DosKernelApi::read_console_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum BiosKeyEvent {
    /// Standard 8-bit character (`ASCII` or active OEM codepage byte, e.g., `0x0D` Enter, `0x08` Backspace, `0x09` Tab).
    #[display("Char({_0:#04x})")]
    Char(
        /// Raw character byte in active DOS OEM codepage.
        u8,
    ),
    /// Extended two-byte BIOS keystroke (`0x00`/`0xE0` followed by scan code).
    #[display("Extended({_0})")]
    Extended(
        /// Decoded [`BiosScanCode`].
        BiosScanCode,
    ),
}
