//! Core Virtual File System traits, metadata, timestamps, attributes, and directory entry types.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use derive_more::Display;

use crate::error::CmdError;
use crate::types::{
    AttributeMutation, CmdLocaleConfig, DateFormatStyle, DirCreationDepth, DirRemovalMode,
    DriveLetter, HostBindingMode, MklinkKind, NativeBackingPath, ReadOnlyDeletePolicy,
    TimeClockFormat,
};
use crate::vfs::path::WindowsPath;

/// Maximum number of symbolic link or directory junction hops permitted while resolving a path.
pub const MAX_SYMLINK_HOPS: usize = 32;

/// Default deterministic Unix epoch timestamp (`2026-11-10T09:00:00Z` -> `"11/10/2026  09:00 AM"`).
pub const DEFAULT_VFS_EPOCH_SECS: u64 = 1_794_301_200;

/// Compact bitmask representing Windows file and directory attributes (`R`, `H`, `S`, `D`, `A`, `L`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FileAttributeFlags(
    /// Raw bitmask storage (`bits 0..=5`).
    u8,
);

/// Type alias preserving [`FileAttributes`] naming across VFS and built-in command APIs.
pub type FileAttributes = FileAttributeFlags;

impl FileAttributeFlags {
    /// Empty attribute bitmask (no attributes set).
    pub const EMPTY: Self = Self(0);
    /// Read-only attribute (`R`).
    pub const READ_ONLY: Self = Self(1 << 0);
    /// Hidden attribute (`H`).
    pub const HIDDEN: Self = Self(1 << 1);
    /// System attribute (`S`).
    pub const SYSTEM: Self = Self(1 << 2);
    /// Directory attribute (`D`).
    pub const DIRECTORY: Self = Self(1 << 3);
    /// Archive attribute (`A`).
    pub const ARCHIVE: Self = Self(1 << 4);
    /// Reparse point / symbolic link / junction attribute (`L`).
    pub const REPARSE_POINT: Self = Self(1 << 5);

    /// Default attributes for a newly created regular file (`ARCHIVE`).
    ///
    /// # Returns
    /// [`FileAttributeFlags`] with [`Self::ARCHIVE`] set.
    #[must_use]
    pub const fn default_file() -> Self {
        Self::ARCHIVE
    }

    /// Default attributes for a newly created directory (`DIRECTORY`).
    ///
    /// # Returns
    /// [`FileAttributeFlags`] with [`Self::DIRECTORY`] set.
    #[must_use]
    pub const fn default_dir() -> Self {
        Self::DIRECTORY
    }

    /// Checks whether no attribute bits are set.
    ///
    /// # Returns
    /// `true` if the bitmask equals `0`.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Checks whether all attribute bits in `other` are present in `self`.
    ///
    /// # Arguments
    /// * `other` - Attribute flag(s) to check.
    ///
    /// # Returns
    /// `true` if every bit in `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Checks whether at least one attribute bit in `other` is present in `self`.
    ///
    /// # Arguments
    /// * `other` - Attribute mask to test against.
    ///
    /// # Returns
    /// `true` if `(self & other)` is non-zero.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Inserts all attribute bits from `other` into `self`.
    ///
    /// # Arguments
    /// * `other` - Attribute flag(s) to enable.
    pub const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Removes all attribute bits in `other` from `self`.
    ///
    /// # Arguments
    /// * `other` - Attribute flag(s) to clear.
    pub const fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    /// Conditionally sets or clears `flag` according to `mutation`.
    ///
    /// # Arguments
    /// * `flag` - Attribute bit(s) to update.
    /// * `mutation` - [`AttributeMutation::Set`] to insert `flag`; [`AttributeMutation::Clear`] to remove `flag`.
    pub const fn set_flag(&mut self, flag: Self, mutation: AttributeMutation) {
        match mutation {
            AttributeMutation::Set => self.insert(flag),
            AttributeMutation::Clear => self.remove(flag),
        }
    }

    /// Returns `true` if the [`Self::DIRECTORY`] attribute is set.
    ///
    /// # Returns
    /// `true` when this entry represents a directory.
    #[must_use]
    pub const fn is_directory(self) -> bool {
        self.contains(Self::DIRECTORY)
    }

    /// Returns `true` if the [`Self::READ_ONLY`] attribute is set.
    ///
    /// # Returns
    /// `true` when this entry is marked read-only.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        self.contains(Self::READ_ONLY)
    }

    /// Returns `true` if the [`Self::ARCHIVE`] attribute is set.
    ///
    /// # Returns
    /// `true` when this entry has the archive bit set.
    #[must_use]
    pub const fn is_archive(self) -> bool {
        self.contains(Self::ARCHIVE)
    }

    /// Returns `true` if the [`Self::SYSTEM`] attribute is set.
    ///
    /// # Returns
    /// `true` when this entry is marked as a system file.
    #[must_use]
    pub const fn is_system(self) -> bool {
        self.contains(Self::SYSTEM)
    }

    /// Returns `true` if the [`Self::HIDDEN`] attribute is set.
    ///
    /// # Returns
    /// `true` when this entry is marked hidden.
    #[must_use]
    pub const fn is_hidden(self) -> bool {
        self.contains(Self::HIDDEN)
    }

    /// Returns `true` if the [`Self::REPARSE_POINT`] attribute is set.
    ///
    /// # Returns
    /// `true` when this entry is a symbolic link or directory junction.
    #[must_use]
    pub const fn is_reparse_point(self) -> bool {
        self.contains(Self::REPARSE_POINT)
    }

    /// Formats the 9-character `%~a1` attribute string (`drahscotl`, e.g., `--a------` or `d--------`).
    ///
    /// # Returns
    /// A 9-character string matching `cmd.exe`'s `%~a` expansion format.
    #[must_use]
    pub fn to_cmd_attr_string(self) -> String {
        let dir_ch = if self.is_directory() { 'd' } else { '-' };
        let ro_ch = if self.is_read_only() { 'r' } else { '-' };
        let arch_ch = if self.is_archive() { 'a' } else { '-' };
        let hid_ch = if self.is_hidden() { 'h' } else { '-' };
        let sys_ch = if self.is_system() { 's' } else { '-' };
        let link_ch = if self.is_reparse_point() { 'l' } else { '-' };
        format!("{dir_ch}{ro_ch}{arch_ch}{hid_ch}{sys_ch}---{link_ch}")
    }

    /// Checks whether this [`FileAttributeFlags`] satisfies an attribute filter string
    /// (e.g., `"H-S"`, `"D"`, `"-D"`).
    ///
    /// # Arguments
    /// * `filter` - Filter string from `DIR /A:...` or `DEL /A:...` (without leading `/A` or `:`).
    ///
    /// # Returns
    /// `true` if all required (`+`/bare) attributes are set and all excluded (`-`) attributes are clear.
    #[must_use]
    pub fn matches_filter(self, filter: &str) -> bool {
        let mut negate = false;
        for ch in filter.chars() {
            match ch.to_ascii_uppercase() {
                '-' => negate = true,
                'D' => {
                    if self.is_directory() == negate {
                        return false;
                    }
                    negate = false;
                }
                'R' => {
                    if self.is_read_only() == negate {
                        return false;
                    }
                    negate = false;
                }
                'A' => {
                    if self.is_archive() == negate {
                        return false;
                    }
                    negate = false;
                }
                'H' => {
                    if self.is_hidden() == negate {
                        return false;
                    }
                    negate = false;
                }
                'S' => {
                    if self.is_system() == negate {
                        return false;
                    }
                    negate = false;
                }
                'L' => {
                    if self.is_reparse_point() == negate {
                        return false;
                    }
                    negate = false;
                }
                _ => negate = false,
            }
        }
        true
    }
}

/// Strongly typed file modification timestamp stored as Unix epoch seconds (`UTC`).
///
/// Enables true chronological ordering (`Ord`) in `DIR /O:D` and `DIR /O:-D` while formatting
/// human-readable date/time strings via [`CmdLocaleConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
#[display("{}", self.format_default())]
pub struct FileTimestamp(
    /// Seconds elapsed since `1970-01-01T00:00:00Z`.
    u64,
);

impl Default for FileTimestamp {
    /// Returns the deterministic default VFS timestamp (`11/10/2026  09:00 AM`).
    ///
    /// # Returns
    /// `FileTimestamp(DEFAULT_VFS_EPOCH_SECS)`.
    fn default() -> Self {
        Self(DEFAULT_VFS_EPOCH_SECS)
    }
}

impl FileTimestamp {
    /// Constructs a [`FileTimestamp`] directly from Unix epoch seconds.
    ///
    /// # Arguments
    /// * `epoch_secs` - Seconds since `1970-01-01T00:00:00Z`.
    ///
    /// # Returns
    /// Wrapped [`FileTimestamp`].
    #[must_use]
    pub const fn from_epoch_secs(epoch_secs: u64) -> Self {
        Self(epoch_secs)
    }

    /// Returns the underlying Unix epoch seconds.
    ///
    /// # Returns
    /// Seconds since `1970-01-01T00:00:00Z`.
    #[must_use]
    pub const fn epoch_secs(self) -> u64 {
        self.0
    }

    /// Returns the number of days (`28..=31`) in `month` (`1..=12`) of Gregorian `year`.
    ///
    /// # Arguments
    /// * `year` - 4-digit Gregorian year.
    /// * `month` - 1-based month (`1..=12`).
    ///
    /// # Returns
    /// `Some(days)` when `month` is in `1..=12`, or `None` otherwise.
    #[must_use]
    pub const fn days_in_month(year: u32, month: u32) -> Option<u32> {
        let is_leap =
            (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
            4 | 6 | 9 | 11 => Some(30),
            2 => Some(if is_leap { 29 } else { 28 }),
            _ => None,
        }
    }

    /// Constructs a [`FileTimestamp`] from civil calendar components `(year, month, day, hour_24, minute)`,
    /// validating calendar bounds (`year >= 1970`, `month` in `1..=12`, leap-year-aware `day` in
    /// `1..=days_in_month(year, month)`, `hour_24` in `0..=23`, `minute` in `0..=59`).
    ///
    /// Uses Howard Hinnant's civil-to-days algorithm.
    ///
    /// # Arguments
    /// * `year` - 4-digit civil year (`>= 1970`).
    /// * `month` - 1-based month (`1..=12`).
    /// * `day` - 1-based day of month (`1..=days_in_month(year, month)`).
    /// * `hour_24` - Hour in 24-hour clock (`0..=23`).
    /// * `minute` - Minute (`0..=59`).
    ///
    /// # Returns
    /// `Some(FileTimestamp)` when all calendar components are valid, or `None` if out of bounds.
    #[must_use]
    pub const fn from_civil_utc(
        year: u32,
        month: u32,
        day: u32,
        hour_24: u32,
        minute: u32,
    ) -> Option<Self> {
        if year < 1970 || hour_24 > 23 || minute > 59 || day < 1 {
            return None;
        }
        let Some(max_day) = Self::days_in_month(year, month) else {
            return None;
        };
        if day > max_day {
            return None;
        }
        let y = year as u64;
        let m = month as u64;
        let d = day as u64;
        let adj_y = if m <= 2 { y.saturating_sub(1) } else { y };
        let era = adj_y / 400;
        let yoe = adj_y.saturating_sub(era.saturating_mul(400));
        let mp = if m > 2 {
            m.saturating_sub(3)
        } else {
            m.saturating_add(9)
        };
        let doy =
            ((153u64.saturating_mul(mp).saturating_add(2)) / 5).saturating_add(d.saturating_sub(1));
        let doe = yoe
            .saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100)
            .saturating_add(doy);
        let days_since_epoch = era
            .saturating_mul(146_097)
            .saturating_add(doe)
            .saturating_sub(719_468);
        let secs = days_since_epoch
            .saturating_mul(86_400)
            .saturating_add((hour_24 as u64).saturating_mul(3_600))
            .saturating_add((minute as u64).saturating_mul(60));
        Some(Self(secs))
    }

    /// Parses a virtual `DATE` / `DIR` timestamp string (such as `"Tue 11/10/2026"`,
    /// `"11/11/2026  12:00 PM"`, or `"2026-12-31"`) into a [`FileTimestamp`].
    ///
    /// Falls back to [`FileTimestamp::default()`] if no recognizable date digits are present.
    ///
    /// # Arguments
    /// * `raw` - Date or date-time string to parse.
    ///
    /// # Returns
    /// Parsed [`FileTimestamp`].
    #[must_use]
    pub fn parse_virtual_str(raw: &str) -> Self {
        let tokens: Vec<&str> = raw.split_whitespace().collect();
        let date_tok = tokens
            .iter()
            .copied()
            .find(|t| t.chars().any(|c| c.is_ascii_digit()) && t.contains(['/', '-', '.']));
        let Some(d_str) = date_tok else {
            return Self::default();
        };
        let parts: Vec<u32> = d_str
            .split(['/', '-', '.'])
            .filter_map(|p| p.parse::<u32>().ok())
            .collect();
        let (year, month, day) = match parts.as_slice() {
            [a, b, c] if *a >= 1970 => (*a, *b, *c),
            [m, d, y] => (*y, *m, *d),
            _ => return Self::default(),
        };

        let mut hour_24 = 9u32;
        let mut minute = 0u32;
        for (idx, tok) in tokens.iter().enumerate() {
            if let Some((h_str, m_str)) = tok.split_once(':')
                && let (Ok(h_val), Ok(m_val)) = (h_str.parse::<u32>(), m_str.parse::<u32>())
            {
                minute = m_val;
                let am_pm = tokens.get(idx.saturating_add(1)).copied().unwrap_or("");
                if am_pm.eq_ignore_ascii_case("PM") {
                    hour_24 = if h_val < 12 {
                        h_val.saturating_add(12)
                    } else {
                        h_val
                    };
                } else if am_pm.eq_ignore_ascii_case("AM") {
                    hour_24 = if h_val == 12 { 0 } else { h_val };
                } else {
                    hour_24 = h_val;
                }
                break;
            }
        }
        Self::from_civil_utc(year, month, day, hour_24, minute).unwrap_or_default()
    }

    /// Formats this timestamp using the default US English `cmd.exe` locale (`"MM/DD/YYYY  hh:mm AM"`).
    ///
    /// # Returns
    /// Formatted timestamp string.
    #[must_use]
    pub fn format_default(self) -> String {
        self.format_with_locale(&CmdLocaleConfig::default())
    }

    /// Formats this timestamp according to the supplied [`CmdLocaleConfig`].
    ///
    /// # Arguments
    /// * `locale` - [`CmdLocaleConfig`] specifying date ordering, separators, and 12h/24h clock.
    ///
    /// # Returns
    /// Human-readable timestamp string suitable for `DIR` and `%~t`.
    #[must_use]
    pub fn format_with_locale(self, locale: &CmdLocaleConfig) -> String {
        let days_u64 = self.0 / 86_400;
        let rem_secs = self.0 % 86_400;
        let hour_24 = rem_secs / 3_600;
        let minute = (rem_secs % 3_600) / 60;

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
        let day = doy
            .saturating_sub((153u64.saturating_mul(mp).saturating_add(2)) / 5)
            .saturating_add(1);
        let month = if mp < 10 {
            mp.saturating_add(3)
        } else {
            mp.saturating_sub(9)
        };
        let year = if month <= 2 { y.saturating_add(1) } else { y };

        let d_sep = locale.date_separator;
        let date_part = match locale.date_format {
            DateFormatStyle::DayMonthDateYearUs => {
                format!("{month:02}{d_sep}{day:02}{d_sep}{year:04}")
            }
            DateFormatStyle::Iso8601 => format!("{year:04}{d_sep}{month:02}{d_sep}{day:02}"),
            DateFormatStyle::DayMonthYearEuro => {
                format!("{day:02}{d_sep}{month:02}{d_sep}{year:04}")
            }
        };

        let t_sep = locale.time_separator;
        let time_part = match locale.time_clock_format {
            TimeClockFormat::TwelveHourAmPm => {
                let (hour_12, am_pm) = match hour_24 {
                    0 => (12, "AM"),
                    1..=11 => (hour_24, "AM"),
                    12 => (12, "PM"),
                    _ => (hour_24.saturating_sub(12), "PM"),
                };
                format!("{hour_12:02}{t_sep}{minute:02} {am_pm}")
            }
            TimeClockFormat::TwentyFourHour => format!("{hour_24:02}{t_sep}{minute:02}"),
        };

        format!("{date_part}  {time_part}")
    }
}

/// Metadata entry for a file, directory, or reparse point in the VFS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfsMetadata {
    /// Original case-preserved entry name (`file.txt`).
    pub name: String,
    /// Generated 8.3 short filename (`FILE~1.TXT`).
    pub short_name: String,
    /// Full resolved [`WindowsPath`].
    pub full_path: WindowsPath,
    /// File attribute flags (`D`, `R`, `A`, `H`, `S`, `L`).
    pub attributes: FileAttributeFlags,
    /// Size in bytes (`0` for directories).
    pub size: u64,
    /// Chronological modification timestamp.
    pub modified_timestamp: FileTimestamp,
}

/// Virtual disk volume metadata returned by `VOL` and `DIR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// Volume label (e.g., `"Windows"` or empty string if unlabeled).
    pub label: String,
    /// Volume serial number (e.g., `"1A2B-3C4D"`).
    pub serial_number: String,
}

/// Trait abstracting all filesystem, path, attribute, link, share, and drive operations.
pub trait VirtualFileSystem: core::fmt::Debug {
    /// Returns the currently active [`DriveLetter`].
    ///
    /// # Returns
    /// The active [`DriveLetter`].
    fn current_drive(&self) -> DriveLetter;

    /// Changes the currently active [`DriveLetter`] if mounted.
    ///
    /// # Arguments
    /// * `drive` - The target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] if `drive` is not mounted.
    fn set_current_drive(&mut self, drive: DriveLetter) -> Result<(), CmdError>;

    /// Returns the current working directory [`WindowsPath`] for `drive`.
    ///
    /// # Arguments
    /// * `drive` - The [`DriveLetter`] to query.
    ///
    /// # Returns
    /// `Ok(WindowsPath)` of `drive`'s current directory.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] if `drive` is not mounted.
    fn drive_cwd(&self, drive: DriveLetter) -> Result<WindowsPath, CmdError>;

    /// Sets the current working directory for `drive` (validating that the directory exists).
    ///
    /// # Arguments
    /// * `path` - Resolved [`WindowsPath`] to set as CWD for `path.drive`.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`], [`CmdError::PathNotFound`], or [`CmdError::AccessDenied`].
    fn set_drive_cwd(&mut self, path: &WindowsPath) -> Result<(), CmdError>;

    /// Resolves any raw Windows path string against the VFS's active drive and per-drive CWDs.
    ///
    /// # Arguments
    /// * `raw` - Raw path string.
    ///
    /// # Returns
    /// Canonicalized [`WindowsPath`].
    fn resolve_path(&self, raw: &str) -> WindowsPath;

    /// Returns volume information for `drive`.
    ///
    /// # Arguments
    /// * `drive` - The [`DriveLetter`] to query.
    ///
    /// # Returns
    /// `Ok(VolumeInfo)` if `drive` is mounted.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] if `drive` is not mounted.
    fn volume_info(&self, drive: DriveLetter) -> Result<VolumeInfo, CmdError>;

    /// Queries metadata for a single path (handling reserved DOS devices like `NUL`).
    ///
    /// # Arguments
    /// * `raw_path` - Raw or resolved path string.
    ///
    /// # Returns
    /// `Ok(VfsMetadata)` if the entry exists.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::PathNotFound`], [`CmdError::AccessDenied`],
    /// or [`CmdError::IoFailure`] (e.g., on symbolic link loops).
    fn stat(&self, raw_path: &str) -> Result<VfsMetadata, CmdError>;

    /// Checks whether a path or wildcard pattern matches at least one existing entry (`IF EXIST`).
    ///
    /// Supports the `IF EXIST "C:\dir\NUL"` directory-existence idiom.
    ///
    /// # Arguments
    /// * `raw_pattern` - Path or wildcard pattern.
    ///
    /// # Returns
    /// `true` if at least one matching file, directory, or valid device path exists.
    fn exists(&self, raw_pattern: &str) -> bool;

    /// Reads the raw bytes of a file (or returns `Ok(Vec::new())` for `NUL`).
    ///
    /// # Arguments
    /// * `raw_path` - Path to read.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the file contents.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn read_bytes(&self, raw_path: &str) -> Result<Vec<u8>, CmdError>;

    /// Writes `data` to `raw_path`, truncating any existing file (or discarding if `NUL`).
    ///
    /// # Arguments
    /// * `raw_path` - Destination file path.
    /// * `data` - Bytes to write.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn write_bytes(&mut self, raw_path: &str, data: &[u8]) -> Result<(), CmdError>;

    /// Appends `data` to `raw_path`, creating the file if it does not exist.
    ///
    /// # Arguments
    /// * `raw_path` - Destination file path.
    /// * `data` - Bytes to append.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn append_bytes(&mut self, raw_path: &str, data: &[u8]) -> Result<(), CmdError>;

    /// Deletes a single file or file symbolic link at `raw_path`.
    ///
    /// # Arguments
    /// * `raw_path` - File path to delete.
    /// * `access_mode` - [`ReadOnlyDeletePolicy`] controlling `READ_ONLY` deletion (`DEL /F`).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn delete_file(
        &mut self,
        raw_path: &str,
        access_mode: ReadOnlyDeletePolicy,
    ) -> Result<(), CmdError>;

    /// Creates a directory according to `parent_mode` (`MD` / `MKDIR`).
    ///
    /// # Arguments
    /// * `raw_path` - Directory path to create.
    /// * `parent_mode` - [`DirCreationDepth`] (`ImmediateParentOnly` vs `CreateParents`).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`], [`CmdError::FileAlreadyExists`], [`CmdError::PathNotFound`],
    /// or [`CmdError::AccessDenied`].
    fn create_dir(&mut self, raw_path: &str, parent_mode: DirCreationDepth)
    -> Result<(), CmdError>;

    /// Removes a directory or directory junction/symlink (`RD` / `RMDIR`).
    ///
    /// # Arguments
    /// * `raw_path` - Directory path to remove.
    /// * `removal_mode` - [`DirRemovalMode`] (`EmptyOnly` vs `RecursiveSubtree` for `RD /S`).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::DirectoryNotEmpty`], [`CmdError::AccessDenied`],
    /// or [`CmdError::IoFailure`].
    fn remove_dir(&mut self, raw_path: &str, removal_mode: DirRemovalMode) -> Result<(), CmdError>;

    /// Lists all immediate child entries inside directory `raw_dir_path`.
    ///
    /// # Arguments
    /// * `raw_dir_path` - Directory path to enumerate.
    ///
    /// # Returns
    /// `Ok(Vec<VfsMetadata>)` sorted case-insensitively by entry name.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn read_dir(&self, raw_dir_path: &str) -> Result<Vec<VfsMetadata>, CmdError>;

    /// Updates [`FileAttributeFlags`] on an existing entry (`ATTRIB`).
    ///
    /// # Arguments
    /// * `raw_path` - Target path.
    /// * `attributes` - New [`FileAttributeFlags`] to apply.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`] or [`CmdError::AccessDenied`].
    fn set_attributes(
        &mut self,
        raw_path: &str,
        attributes: FileAttributeFlags,
    ) -> Result<(), CmdError>;

    /// Returns the available free disk space in bytes on `drive` (`DIR` footer).
    ///
    /// # Arguments
    /// * `drive` - The [`DriveLetter`] to query.
    ///
    /// # Returns
    /// `Ok(u64)` free bytes.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] if `drive` is not mounted.
    fn free_disk_space(&self, drive: DriveLetter) -> Result<u64, CmdError>;

    /// Atomically moves or renames a file or directory (`REN` and `MOVE`).
    ///
    /// # Arguments
    /// * `src_raw` - Source file or directory path.
    /// * `dst_raw` - Destination file or directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::PathNotFound`], [`CmdError::FileAlreadyExists`],
    /// [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn move_entry(&mut self, src_raw: &str, dst_raw: &str) -> Result<(), CmdError>;

    /// Creates a symbolic link or directory junction (`MKLINK`, `MKLINK /D`, `MKLINK /J`).
    ///
    /// # Arguments
    /// * `link_raw` - Path of the new link to create.
    /// * `target_raw` - Target path the link points to (may be relative or not yet created).
    /// * `kind` - [`MklinkKind`] specifying file symlink, directory symlink, or junction.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::FileAlreadyExists`], [`CmdError::AccessDenied`],
    /// or [`CmdError::IoFailure`].
    fn create_symlink(
        &mut self,
        link_raw: &str,
        target_raw: &str,
        kind: MklinkKind,
    ) -> Result<(), CmdError>;

    /// Creates a hard link sharing the target file's underlying inode (`MKLINK /H`).
    ///
    /// # Arguments
    /// * `link_raw` - Path of the new hard link.
    /// * `target_raw` - Existing target file path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::PathNotFound`], [`CmdError::FileAlreadyExists`],
    /// [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn create_hardlink(&mut self, link_raw: &str, target_raw: &str) -> Result<(), CmdError>;

    /// Touches an existing file's modification timestamp in place (`COPY file + ,,`).
    ///
    /// # Arguments
    /// * `raw_path` - Target file path.
    /// * `new_timestamp` - Updated [`FileTimestamp`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn touch_file(&mut self, raw_path: &str, new_timestamp: FileTimestamp) -> Result<(), CmdError>;

    /// Allocates and mounts the highest unused drive letter (`Z:` downward to `A:`) for a UNC share (`PUSHD \server\share`).
    ///
    /// # Arguments
    /// * `unc_share` - UNC share root (`\server\share`).
    /// * `sub_components` - Optional subdirectory components under the share.
    ///
    /// # Returns
    /// `Ok(DriveLetter)` of the newly mounted temporary drive.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`] if no drive letters are available.
    fn mount_unc_drive(
        &mut self,
        unc_share: &str,
        sub_components: &[String],
    ) -> Result<DriveLetter, CmdError>;

    /// Unmounts a temporary drive letter previously allocated by `mount_unc_drive` (`POPD`).
    ///
    /// # Arguments
    /// * `drive` - The temporary [`DriveLetter`] to unmount.
    fn unmount_drive(&mut self, drive: DriveLetter);

    /// Translates a resolved [`WindowsPath`] to a native backing path ([`NativeBackingPath`]) if backed by the host OS or DOS volume.
    ///
    /// # Arguments
    /// * `win_path` - Resolved [`WindowsPath`].
    ///
    /// # Returns
    /// `Some(NativeBackingPath)` if backed by a host/DOS volume, or `None` for pure [`super::InMemoryVfs`].
    fn resolve_host_path(&self, win_path: &WindowsPath) -> Option<NativeBackingPath>;

    /// Configures the simulated free disk space (in bytes) for `drive` on [`super::InMemoryVfs`] or [`super::HostOsVfs`].
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    /// * `bytes` - Free space in bytes.
    fn set_drive_free_space(&mut self, drive: DriveLetter, bytes: u64);

    /// Synchronizes the host OS process current working directory with the VFS active drive CWD
    /// when `binding_mode` is [`HostBindingMode::Synchronized`].
    ///
    /// # Arguments
    /// * `binding_mode` - [`HostBindingMode`] controlling whether the host process CWD is mutated.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`] or [`CmdError::AccessDenied`] if changing the host directory fails.
    fn sync_host_cwd(&self, binding_mode: HostBindingMode) -> Result<(), CmdError>;

    /// Verifies that `raw_path` resolves to an existing file, directory, or valid DOS device.
    ///
    /// # Arguments
    /// * `raw_path` - Path string to validate.
    ///
    /// # Returns
    /// `Ok(())` when `raw_path` exists.
    ///
    /// # Errors
    /// Returns [`CmdError`] from [`Self::stat`] when `raw_path` (or a DOS device's parent directory) does not exist.
    fn ensure_exists(&self, raw_path: &str) -> Result<(), CmdError> {
        self.stat(raw_path).map(|_| ())
    }

    /// Clones this VFS state into a boxed trait object.
    ///
    /// # Returns
    /// A boxed clone of this [`VirtualFileSystem`].
    fn clone_box(&self) -> Box<dyn VirtualFileSystem>;
}

/// Case-folded ASCII-uppercase identifier used for case-insensitive VFS root and component keys.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CaseFoldedString(
    /// Uppercase canonical representation.
    String,
);

impl CaseFoldedString {
    /// Creates a new [`CaseFoldedString`] by folding `raw` to ASCII uppercase.
    ///
    /// # Arguments
    /// * `raw` - Original case-unfolded string.
    ///
    /// # Returns
    /// Canonical [`CaseFoldedString`].
    #[must_use]
    pub fn new(raw: &str) -> Self {
        Self(crate::types::fold_win32_case(raw))
    }

    /// Returns the canonical uppercase string slice.
    ///
    /// # Returns
    /// Uppercase `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Root namespace for an entry in [`super::InMemoryVfs`], cleanly isolating UNC shares (`\server\share`)
/// from local/mounted drive letters (`C:`, `D:`, ...).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VfsRoot {
    /// Mounted drive letter (`C:`, `D:`, `Z:`, etc.).
    Drive(DriveLetter),
    /// Network UNC share (`\server\share`).
    Unc {
        /// Case-folded UNC server hostname.
        server: CaseFoldedString,
        /// Case-folded UNC share name.
        share: CaseFoldedString,
    },
}

impl VfsRoot {
    /// Extracts the [`VfsRoot`] namespace from a resolved [`WindowsPath`].
    ///
    /// # Arguments
    /// * `path` - Resolved [`WindowsPath`].
    ///
    /// # Returns
    /// [`VfsRoot::Unc`] if `path.unc_prefix` is `Some`, otherwise [`VfsRoot::Drive`].
    #[must_use]
    pub fn from_windows_path(path: &WindowsPath) -> Self {
        if let Some((server, share)) = &path.unc_prefix {
            Self::Unc {
                server: CaseFoldedString::new(server),
                share: CaseFoldedString::new(share),
            }
        } else {
            Self::Drive(path.drive)
        }
    }
}

/// Canonical case-insensitive path key inside [`super::InMemoryVfs`].
pub type VfsKey = (VfsRoot, Vec<String>);

/// Unique identifier for an in-memory inode inside [`super::InMemoryVfs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct InodeId(
    /// Monotonically increasing inode counter.
    pub(super) u64,
);

/// Directory entry mapping a case-preserved filename and 8.3 short name to a shared [`InodeId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DirEntry {
    /// Original case-preserved entry name.
    pub(super) name: String,
    /// Allocated 8.3 short name (`PROGRA~1`).
    pub(super) short_name: String,
    /// Referenced [`InodeId`] in the backing inode table.
    pub(super) inode_id: InodeId,
}
