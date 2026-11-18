//! Windows path classification, drive-relative resolution, case-insensitive comparison, and 8.3 short names.
//!
//! Handles all Win32 path forms (`C:/abs`, `C:rel`, `/root_rel`, `rel/path`, `//server/share`),
//! enforces case-insensitive `Eq`/`Ord`/`Hash` while preserving original display casing, validates
//! UNC paths without fabricating dummy `"localhost"`/`"share"` targets, separates NT trailing-dot
//! stripping from legacy MS-DOS `...` multi-dot climbing, and implements collision-free NT 8.3
//! short filename generation (`PROGRA~1`..`PROGRA~4` and 4-hex-digit hash `PRxxxx~1` for `>=5`).

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};

use derive_more::{Display, IsVariant};

use crate::error::CmdError;
use crate::types::{BS_CHAR, BS_STR, DOUBLE_BS_STR, DriveLetter, TAB_CHAR};

/// Extended-length Win32 path prefix (`\\?\`).
const EXTENDED_PREFIX: &str = r"\\?\";

/// Controls how standalone multi-dot segments (`...`, `....`) are interpreted during path resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum MultiDotMode {
    /// Authentic Windows NT / Windows 10 / 11 `cmd.exe` behavior: trailing dots on `...` strip to no-op.
    #[default]
    #[display("nt")]
    NtTrailingDotStrip,
    /// Legacy MS-DOS / Win9x / `COMMAND.COM` behavior: `...` climbs 2 parent directories, `....` climbs 3.
    #[display("dos")]
    LegacyDosClimb,
}

/// Classification of a raw Windows path string prior to resolution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClassifiedPath {
    /// Absolute path anchored at a specific drive root (e.g., `C:\Windows\System32`).
    DriveAbsolute {
        /// Target drive letter.
        drive: DriveLetter,
        /// Normalized directory/file components.
        components: Vec<String>,
    },
    /// Relative path anchored at a specific drive's current working directory (e.g., `D:sub\file.txt`).
    DriveRelative {
        /// Target drive letter.
        drive: DriveLetter,
        /// Relative components.
        components: Vec<String>,
    },
    /// Root-relative path anchored at the current active drive's root (e.g., `/temp/out.log`).
    RootRelative {
        /// Components from the active drive's root.
        components: Vec<String>,
    },
    /// Relative path anchored at the current active drive's current directory (e.g., `foo\bar.txt`).
    Relative {
        /// Relative components.
        components: Vec<String>,
    },
    /// Universal Naming Convention (UNC) network path (e.g., `\server\share\dir\file`).
    Unc {
        /// Server hostname.
        server: String,
        /// Share name.
        share: String,
        /// Path components inside the share.
        components: Vec<String>,
    },
    /// Malformed UNC network path missing a server or share component (e.g., bare `//` or `//server`).
    InvalidUnc {
        /// Original raw malformed UNC string.
        raw: String,
    },
}

/// A fully resolved, canonicalized Windows path (`C:\dir\file.ext` or `\server\share\dir`).
///
/// Preserves original display casing in `unc_prefix` and `components` while performing
/// case-insensitive equality, ordering, and hashing in accordance with Win32/NTFS rules.
#[derive(Debug, Clone, Display)]
#[display("{}", self.to_windows_string())]
pub struct WindowsPath {
    /// Drive letter (defaults to `C:` for drive-backed paths).
    pub drive: DriveLetter,
    /// Optional `(server, share)` if this path represents a UNC share instead of a drive letter.
    /// An empty `share` indicates an incomplete/invalid UNC specification (`\\` or `\\server`).
    pub unc_prefix: Option<(String, String)>,
    /// Sequence of directory and leaf filename components from the root.
    pub components: Vec<String>,
}

impl WindowsPath {
    /// Constructs the root path of `drive` (e.g., `C:\`).
    ///
    /// # Arguments
    /// * `drive` - The [`DriveLetter`].
    ///
    /// # Returns
    /// A [`WindowsPath`] representing `X:\`.
    #[must_use]
    pub const fn root(drive: DriveLetter) -> Self {
        Self {
            drive,
            unc_prefix: None,
            components: Vec::new(),
        }
    }

    /// Checks whether this path represents a malformed UNC specification (`\\` or `\\server`).
    ///
    /// # Returns
    /// `true` if `unc_prefix` is present with an empty share component, otherwise `false`.
    #[must_use]
    pub const fn is_invalid_unc(&self) -> bool {
        matches!(&self.unc_prefix, Some((_, share)) if share.is_empty())
    }

    /// Formats the path using standard Windows backslashes (`C:\foo\bar` or `\\server\share\foo`).
    ///
    /// # Returns
    /// The formatted Windows path string.
    #[must_use]
    pub fn to_windows_string(&self) -> String {
        let sep = BS_STR;
        if let Some((server, share)) = &self.unc_prefix {
            if share.is_empty() {
                format!("{DOUBLE_BS_STR}{server}")
            } else if self.components.is_empty() {
                format!("{DOUBLE_BS_STR}{server}{sep}{share}")
            } else {
                format!(
                    "{DOUBLE_BS_STR}{server}{sep}{share}{sep}{}",
                    self.components.join(sep)
                )
            }
        } else if self.components.is_empty() {
            format!("{}{sep}", self.drive)
        } else {
            format!("{}{sep}{}", self.drive, self.components.join(sep))
        }
    }

    /// Returns the drive or UNC share prefix (`"C:"` or `"\server\share"`) for `%~d1` expansion.
    ///
    /// # Returns
    /// The drive or UNC root prefix string.
    #[must_use]
    pub fn drive_string(&self) -> String {
        if let Some((server, share)) = &self.unc_prefix {
            format!("{DOUBLE_BS_STR}{server}{BS_STR}{share}")
        } else {
            self.drive.to_string()
        }
    }

    /// Returns the directory path portion with leading and trailing backslashes for `%~p1` expansion.
    ///
    /// For `C:/dir/sub/file.txt`, `%~p1` is `/dir/sub/` (using backslashes). For `C:/file.txt`, `%~p1` is a single backslash.
    ///
    /// # Returns
    /// The directory path string with leading and trailing backslashes.
    #[must_use]
    pub fn directory_path_only(&self) -> String {
        let sep = BS_STR;
        if self.components.len() <= 1 {
            sep.to_owned()
        } else {
            let parent_slice = self
                .components
                .get(..self.components.len().saturating_sub(1))
                .unwrap_or(&[]);
            format!("{sep}{}{sep}", parent_slice.join(sep))
        }
    }

    /// Returns the parent [`WindowsPath`] (or `self` if already at the root).
    ///
    /// # Returns
    /// The parent directory [`WindowsPath`].
    #[must_use]
    pub fn parent(&self) -> Self {
        let mut p = self.clone();
        p.components.pop();
        p
    }

    /// Returns the leaf filename component (`file.ext`), if not at root.
    ///
    /// # Returns
    /// `Some(&str)` of the final component, or `None` if at root (`C:`).
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    /// Returns the filename stem without extension for `%~n1` expansion.
    ///
    /// # Returns
    /// The stem before the last `.` (or empty string if at root or dotfile with no other dot).
    #[must_use]
    pub fn file_stem(&self) -> &str {
        let Some(leaf) = self.file_name() else {
            return "";
        };
        match leaf.rfind('.') {
            Some(0) => "",
            Some(idx) => leaf.get(..idx).unwrap_or(leaf),
            None => leaf,
        }
    }

    /// Returns the file extension (including the leading `.`) for `%~x1` expansion.
    ///
    /// # Returns
    /// The extension slice starting with `.` (e.g., `".txt"`), or `""` if no `.` exists.
    #[must_use]
    pub fn extension_with_dot(&self) -> &str {
        let Some(leaf) = self.file_name() else {
            return "";
        };
        leaf.rfind('.')
            .map_or("", |idx| leaf.get(idx..).unwrap_or(""))
    }

    /// Appends a single child component to this path.
    ///
    /// # Arguments
    /// * `name` - Child directory or file name.
    ///
    /// # Returns
    /// A new [`WindowsPath`] with `name` appended.
    #[must_use]
    pub fn join_component(&self, name: &str) -> Self {
        let mut next = self.clone();
        next.components.push(name.to_owned());
        next
    }

    /// Produces a tuple of uppercase-folded root and component keys for case-insensitive comparison.
    ///
    /// # Returns
    /// Canonical uppercase key tuple `(unc_root_or_drive, folded_components)`.
    fn folded_sort_key(&self) -> (Result<(String, String), DriveLetter>, Vec<String>) {
        let root_key = match &self.unc_prefix {
            Some((srv, shr)) => Ok((
                crate::types::fold_win32_case(srv),
                crate::types::fold_win32_case(shr),
            )),
            None => Err(self.drive),
        };
        let comps = self
            .components
            .iter()
            .map(|c| crate::types::fold_win32_case(c))
            .collect();
        (root_key, comps)
    }
}

impl PartialEq for WindowsPath {
    /// Compares two [`WindowsPath`] values case-insensitively on UNC shares, drives, and components.
    ///
    /// # Arguments
    /// * `other` - Right-hand [`WindowsPath`] to compare against `self`.
    ///
    /// # Returns
    /// `true` if both paths refer to the same canonical Win32 location ignoring ASCII case.
    fn eq(&self, other: &Self) -> bool {
        self.folded_sort_key() == other.folded_sort_key()
    }
}

impl Eq for WindowsPath {}

impl PartialOrd for WindowsPath {
    /// Partially orders two [`WindowsPath`] values case-insensitively.
    ///
    /// # Arguments
    /// * `other` - Right-hand [`WindowsPath`] to compare against `self`.
    ///
    /// # Returns
    /// `Some(Ordering)` of their folded canonical representations.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WindowsPath {
    /// Totally orders two [`WindowsPath`] values case-insensitively.
    ///
    /// # Arguments
    /// * `other` - Right-hand [`WindowsPath`] to compare against `self`.
    ///
    /// # Returns
    /// Total [`Ordering`] of their folded canonical representations.
    fn cmp(&self, other: &Self) -> Ordering {
        self.folded_sort_key().cmp(&other.folded_sort_key())
    }
}

impl Hash for WindowsPath {
    /// Hashes the uppercase-folded canonical representation so case-variant paths hash identically.
    ///
    /// # Arguments
    /// * `state` - Mutable [`Hasher`] receiving the folded path key.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.folded_sort_key().hash(state);
    }
}

/// Classifies a raw path string into a [`ClassifiedPath`], returning [`ClassifiedPath::InvalidUnc`]
/// when a UNC path lacks a server or share component instead of fabricating `"localhost"`.
///
/// # Arguments
/// * `raw` - Raw input path string.
///
/// # Returns
/// The [`ClassifiedPath`] representation.
#[must_use]
pub fn classify_path(raw: &str) -> ClassifiedPath {
    let unquoted = raw.trim().trim_matches('"');
    let ns_mode = if unquoted.starts_with(EXTENDED_PREFIX) {
        PathNamespaceMode::ExtendedVerbatim
    } else {
        PathNamespaceMode::Win32Normalized
    };
    let body = unquoted.strip_prefix(EXTENDED_PREFIX).unwrap_or(unquoted);

    if let Some(unc_tail) = body
        .strip_prefix(DOUBLE_BS_STR)
        .or_else(|| body.strip_prefix("//"))
    {
        let mut parts = unc_tail.split([BS_CHAR, '/']).filter(|s| !s.is_empty());
        let (Some(server_raw), Some(share_raw)) = (parts.next(), parts.next()) else {
            return ClassifiedPath::InvalidUnc {
                raw: unquoted.to_owned(),
            };
        };
        let components = parts
            .map(|c| normalize_component_text(c, ns_mode))
            .filter(|c| !c.is_empty())
            .collect();
        return ClassifiedPath::Unc {
            server: server_raw.to_owned(),
            share: share_raw.to_owned(),
            components,
        };
    }

    let leading_drive = body
        .as_bytes()
        .get(1)
        .filter(|&&b| b == b':')
        .and_then(|_| body.chars().next())
        .and_then(|ch| DriveLetter::try_from_char(ch).ok());
    if let Some(drive) = leading_drive {
        let after_drive = body.get(2..).unwrap_or("");
        let components = split_raw_components(after_drive, ns_mode);
        return if after_drive.starts_with([BS_CHAR, '/']) {
            ClassifiedPath::DriveAbsolute { drive, components }
        } else {
            ClassifiedPath::DriveRelative { drive, components }
        };
    }

    let components = split_raw_components(body, ns_mode);
    if body.starts_with([BS_CHAR, '/']) {
        ClassifiedPath::RootRelative { components }
    } else {
        ClassifiedPath::Relative { components }
    }
}

/// Strictly classifies `raw` into a [`ClassifiedPath`], surfacing [`CmdError::InvalidUncPath`]
/// on incomplete UNC paths (`//` or `//server`).
///
/// # Arguments
/// * `raw` - Raw input path string.
///
/// # Returns
/// `Ok(ClassifiedPath)` when valid.
///
/// # Errors
/// Returns [`CmdError::InvalidUncPath`] if `raw` begins with UNC slashes without both server and share.
pub fn try_classify_path(raw: &str) -> Result<ClassifiedPath, CmdError> {
    let classified = classify_path(raw);
    if let ClassifiedPath::InvalidUnc { raw } = classified {
        Err(CmdError::InvalidUncPath { raw })
    } else {
        Ok(classified)
    }
}

/// Resolves a raw path string under authentic Windows NT trailing-dot rules ([`MultiDotMode::NtTrailingDotStrip`]).
///
/// # Arguments
/// * `raw` - The raw path string to resolve.
/// * `active_drive` - Currently active [`DriveLetter`].
/// * `drive_cwd` - Lookup closure returning the current directory components for any [`DriveLetter`].
///
/// # Returns
/// The resolved [`WindowsPath`].
#[must_use]
pub fn resolve_windows_path<F>(raw: &str, active_drive: DriveLetter, drive_cwd: F) -> WindowsPath
where
    F: Fn(DriveLetter) -> Vec<String>,
{
    resolve_windows_path_with_mode(
        raw,
        active_drive,
        MultiDotMode::NtTrailingDotStrip,
        drive_cwd,
    )
}

/// Resolves a raw path string with explicit [`MultiDotMode`] control (`NT` vs legacy `DOS` `...` climb).
///
/// # Arguments
/// * `raw` - The raw path string to resolve.
/// * `active_drive` - Currently active [`DriveLetter`].
/// * `dot_mode` - Whether `...` strips to no-op (`NT`) or climbs 2 directories (`DOS`).
/// * `drive_cwd` - Lookup closure returning the current directory components for any [`DriveLetter`].
///
/// # Returns
/// The resolved [`WindowsPath`].
#[must_use]
pub fn resolve_windows_path_with_mode<F>(
    raw: &str,
    active_drive: DriveLetter,
    dot_mode: MultiDotMode,
    drive_cwd: F,
) -> WindowsPath
where
    F: Fn(DriveLetter) -> Vec<String>,
{
    resolve_windows_path_dyn(raw, active_drive, dot_mode, &drive_cwd)
}

/// Non-generic core implementation of [`resolve_windows_path_with_mode`].
///
/// # Arguments
/// * `raw` - Raw input path string.
/// * `active_drive` - Current active [`DriveLetter`].
/// * `dot_mode` - [`MultiDotMode`] controlling 3+ dot component handling.
/// * `drive_cwd` - Callback returning CWD components for a drive.
///
/// # Returns
/// Normalized [`WindowsPath`].
fn resolve_windows_path_dyn(
    raw: &str,
    active_drive: DriveLetter,
    dot_mode: MultiDotMode,
    drive_cwd: &dyn Fn(DriveLetter) -> Vec<String>,
) -> WindowsPath {
    match classify_path(raw) {
        ClassifiedPath::DriveAbsolute { drive, components } => WindowsPath {
            drive,
            unc_prefix: None,
            components: collapse_dot_components(Vec::new(), &components, dot_mode),
        },
        ClassifiedPath::DriveRelative { drive, components } => WindowsPath {
            drive,
            unc_prefix: None,
            components: collapse_dot_components(drive_cwd(drive), &components, dot_mode),
        },
        ClassifiedPath::RootRelative { components } => WindowsPath {
            drive: active_drive,
            unc_prefix: None,
            components: collapse_dot_components(Vec::new(), &components, dot_mode),
        },
        ClassifiedPath::Relative { components } => WindowsPath {
            drive: active_drive,
            unc_prefix: None,
            components: collapse_dot_components(drive_cwd(active_drive), &components, dot_mode),
        },
        ClassifiedPath::Unc {
            server,
            share,
            components,
        } => WindowsPath {
            drive: active_drive,
            unc_prefix: Some((server, share)),
            components: collapse_dot_components(Vec::new(), &components, dot_mode),
        },
        ClassifiedPath::InvalidUnc { raw } => {
            let stripped = raw
                .strip_prefix(DOUBLE_BS_STR)
                .or_else(|| raw.strip_prefix("//"))
                .unwrap_or(&raw)
                .trim_matches([BS_CHAR, '/']);
            WindowsPath {
                drive: active_drive,
                unc_prefix: Some((stripped.to_owned(), String::new())),
                components: Vec::new(),
            }
        }
    }
}

/// Generates a deterministic Windows NT 8.3 short filename (`PROGRA~1`..`PROGRA~4`, or 2-char
/// prefix + 4-hex-digit hash `PRxxxx~1` for `collision_index >= 5`) for `long_name`.
///
/// # Arguments
/// * `long_name` - Original filename or directory name.
/// * `collision_index` - 1-based numeric collision counter (`1..=255`).
///
/// # Returns
/// The uppercase 8.3 short filename string (guaranteed `<= 8` stem chars and `<= 3` ext chars).
#[must_use]
pub fn generate_short_name_8_3(long_name: &str, collision_index: u8) -> String {
    if long_name == "." || long_name == ".." {
        return long_name.to_owned();
    }

    let (raw_stem, raw_ext) = match long_name.rsplit_once('.') {
        Some((stem, ext)) => (stem, ext),
        None => (long_name, ""),
    };

    let mut had_invalid_char = false;
    let clean_stem: String = raw_stem
        .chars()
        .filter(|&c| !matches!(c, ' ' | TAB_CHAR | '.'))
        .map(|c| {
            let valid = c.is_ascii_alphanumeric()
                || matches!(c, '_' | '-' | '$' | '~' | '!' | '#' | '%' | '&');
            if valid {
                c.to_ascii_uppercase()
            } else {
                had_invalid_char = true;
                '_'
            }
        })
        .collect();

    let clean_ext: String = raw_ext
        .chars()
        .filter(|c| !c.is_whitespace())
        .take(3)
        .map(|c| c.to_ascii_uppercase())
        .collect();

    let needs_tilde = clean_stem.len() > 8
        || raw_stem.len() != clean_stem.len()
        || raw_ext.len() > 3
        || clean_stem.is_empty()
        || had_invalid_char
        || collision_index > 1;

    let final_stem = if needs_tilde {
        let source = if clean_stem.is_empty() {
            &clean_ext
        } else {
            &clean_stem
        };
        let idx = collision_index.max(1);
        if idx <= 4 {
            let prefix: String = source.chars().take(6).collect();
            format!("{prefix}~{idx}")
        } else {
            let mut prefix: String = source.chars().take(2).collect();
            while prefix.len() < 2 {
                prefix.push('_');
            }
            let hash16 = compute_nt_short_hash(long_name, idx);
            format!("{prefix}{hash16:04X}~1")
        }
    } else {
        clean_stem
    };

    if clean_ext.is_empty() {
        final_stem
    } else {
        format!("{final_stem}.{clean_ext}")
    }
}

/// Computes a deterministic 16-bit hash for NT 8.3 short filenames when `collision_index >= 5`.
///
/// # Arguments
/// * `long_name` - Original filename (hashed case-insensitively).
/// * `collision_index` - Collision counter (`>= 5`) mixed into the seed to guarantee distinctness.
///
/// # Returns
/// 16-bit unsigned hash value formatted as 4 uppercase hex digits.
fn compute_nt_short_hash(long_name: &str, collision_index: u8) -> u16 {
    let mut hash: u32 = 0x811C_9DC5u32 ^ u32::from(collision_index);
    for ch in long_name.chars() {
        hash ^= u32::from(ch.to_ascii_uppercase());
        hash = hash.wrapping_mul(0x0100_0193);
    }
    let hi = u16::try_from(hash >> 16).unwrap_or(0);
    let lo = u16::try_from(hash & 0xFFFF).unwrap_or(0);
    hi ^ lo
}

/// Win32 vs extended-length verbatim (`\\?\`) component normalization mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathNamespaceMode {
    /// Standard Win32 namespace: strips trailing dots and spaces from non-dot segments.
    Win32Normalized,
    /// Extended-length verbatim namespace (`\\?\`): preserves trailing dots and spaces.
    ExtendedVerbatim,
}

/// Splits a raw path tail on backslash and `/` into components.
///
/// # Arguments
/// * `raw` - Path tail string.
/// * `ns_mode` - [`PathNamespaceMode`] controlling trailing dot/space preservation.
///
/// # Returns
/// Vector of non-empty component strings.
fn split_raw_components(raw: &str, ns_mode: PathNamespaceMode) -> Vec<String> {
    raw.split([BS_CHAR, '/'])
        .filter(|seg| !seg.is_empty())
        .map(|seg| normalize_component_text(seg, ns_mode))
        .filter(|seg| !seg.is_empty())
        .collect()
}

/// Normalizes a single path component according to Win32 trailing dot/space stripping rules.
///
/// # Arguments
/// * `seg` - Raw segment slice.
/// * `ns_mode` - [`PathNamespaceMode`] (`ExtendedVerbatim` preserves trailing dots and spaces).
///
/// # Returns
/// Normalized segment string.
fn normalize_component_text(seg: &str, ns_mode: PathNamespaceMode) -> String {
    if ns_mode == PathNamespaceMode::ExtendedVerbatim || seg.chars().all(|c| c == '.') {
        seg.to_owned()
    } else {
        seg.trim_end_matches(['.', ' ']).to_owned()
    }
}

/// Collapses `.`, `..`, and `...` navigation segments on top of `base` according to `dot_mode`.
///
/// # Arguments
/// * `base` - Starting component stack.
/// * `incoming` - Relative components to apply.
/// * `dot_mode` - [`MultiDotMode`] controlling standalone `...` segments (`NT` no-op vs `DOS` climb).
///
/// # Returns
/// Canonical component stack.
fn collapse_dot_components(
    mut base: Vec<String>,
    incoming: &[String],
    dot_mode: MultiDotMode,
) -> Vec<String> {
    for comp in incoming {
        if comp == "." {
            // Current directory: no-op
        } else if comp == ".." {
            base.pop();
        } else if comp.len() >= 3 && comp.chars().all(|c| c == '.') {
            if dot_mode.is_legacy_dos_climb() {
                let pops = comp.len().saturating_sub(1);
                let new_len = base.len().saturating_sub(pops);
                base.truncate(new_len);
            }
        } else {
            base.push(comp.clone());
        }
    }
    base
}

#[cfg(test)]
/// Unit tests for [`WindowsPath`] resolution, case-insensitive `Eq`/`Ord`/`Hash`, UNC validation, and 8.3 short names.
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// Verifies drive-absolute, drive-relative, root-relative, and multi-dot path resolution.
    #[test]
    fn test_resolve_drive_root_and_multidot_paths() {
        let sep = BS_STR;

        assert_eq!(MultiDotMode::default(), MultiDotMode::NtTrailingDotStrip);
        assert_eq!(MultiDotMode::NtTrailingDotStrip.to_string(), "nt");
        assert_eq!(MultiDotMode::LegacyDosClimb.to_string(), "dos");

        let cwd_fn = |drive: DriveLetter| {
            if drive == DriveLetter::C {
                vec!["Users".to_owned(), "Sam".to_owned()]
            } else {
                vec!["Work".to_owned(), "Proj".to_owned()]
            }
        };

        // 1. Drive-absolute & case-insensitive Eq/Ord/Hash
        let p1_in = format!("C:{sep}Windows{sep}System32{sep}..{sep}cmd.exe");
        let p1 = resolve_windows_path(&p1_in, DriveLetter::C, cwd_fn);
        let p1_lower = resolve_windows_path("c:/windows/cmd.EXE", DriveLetter::C, cwd_fn);
        assert_eq!(
            p1.to_windows_string(),
            format!("C:{sep}Windows{sep}cmd.exe")
        );
        assert_eq!(
            p1_lower.to_windows_string(),
            format!("C:{sep}windows{sep}cmd.EXE")
        );
        assert_eq!(p1, p1_lower);
        assert_eq!(p1.partial_cmp(&p1_lower), Some(Ordering::Equal));
        let mut set = HashSet::new();
        set.insert(p1.clone());
        assert!(set.contains(&p1_lower));

        assert_eq!(p1.drive_string(), "C:");
        assert_eq!(p1.directory_path_only(), format!("{sep}Windows{sep}"));
        assert_eq!(p1.file_name(), Some("cmd.exe"));
        assert_eq!(p1.file_stem(), "cmd");
        assert_eq!(p1.extension_with_dot(), ".exe");
        assert_eq!(p1.parent().to_windows_string(), format!("C:{sep}Windows"));

        // 2. Drive-relative on non-active drive (`D:sub\file.txt` while on `C:`)
        let p2_in = format!("D:sub{sep}.{sep}file.txt... ");
        let p2 = resolve_windows_path(&p2_in, DriveLetter::C, cwd_fn);
        assert_eq!(
            p2.to_windows_string(),
            format!("D:{sep}Work{sep}Proj{sep}sub{sep}file.txt")
        );

        // 3. Root-relative (`\temp`)
        let p3_in = format!("{sep}temp");
        let p3 = resolve_windows_path(&p3_in, DriveLetter::C, cwd_fn);
        assert_eq!(p3.to_windows_string(), format!("C:{sep}temp"));
        assert_eq!(p3.directory_path_only(), sep);

        // 4. NT mode vs Legacy DOS mode on standalone `...`
        let p4_nt_in = format!("...{sep}leaf");
        let p4_nt = resolve_windows_path(&p4_nt_in, DriveLetter::C, cwd_fn);
        assert_eq!(
            p4_nt.to_windows_string(),
            format!("C:{sep}Users{sep}Sam{sep}leaf")
        );
        let p4_dos_in = format!("...{sep}rootfile");
        let p4_dos = resolve_windows_path_with_mode(
            &p4_dos_in,
            DriveLetter::C,
            MultiDotMode::LegacyDosClimb,
            cwd_fn,
        );
        assert_eq!(p4_dos.to_windows_string(), format!("C:{sep}rootfile"));
        assert_eq!(p4_dos.file_stem(), "rootfile");
        assert_eq!(p4_dos.extension_with_dot(), "");
    }

    /// Verifies root/dotfile accessors, UNC path folding, malformed UNC rejection, and extended prefixes.
    #[test]
    fn test_resolve_unc_extended_and_special_paths() {
        let sep = BS_STR;
        let unc_pre = DOUBLE_BS_STR;
        let ext_pre = EXTENDED_PREFIX;
        let cwd_fn = |_: DriveLetter| vec!["Users".to_owned(), "Sam".to_owned()];
        assert_eq!(
            resolve_windows_path("sub", DriveLetter::C, cwd_fn).to_windows_string(),
            format!("C:{sep}Users{sep}Sam{sep}sub")
        );

        // 5. Root path properties
        let root = WindowsPath::root(DriveLetter::C);
        assert_eq!(root.to_windows_string(), format!("C:{sep}"));
        assert!(!root.is_invalid_unc());
        assert_eq!(root.file_name(), None);
        assert_eq!(root.file_stem(), "");
        assert_eq!(root.extension_with_dot(), "");
        assert_eq!(
            root.join_component("foo").to_windows_string(),
            format!("C:{sep}foo")
        );

        // 6. Dotfile stem and extension
        let dotfile = root.join_component(".gitignore");
        assert_eq!(dotfile.file_stem(), "");
        assert_eq!(dotfile.extension_with_dot(), ".gitignore");

        // 7. Valid UNC path + drive_string() returning `\\server\share` + case-insensitive Eq
        let unc_check = format!("{unc_pre}myserver{sep}myshare{sep}folder");
        assert!(try_classify_path(&unc_check).is_ok());
        let unc_in = format!("{unc_pre}MyServer{sep}MyShare{sep}folder{sep}doc.txt");
        let unc = resolve_windows_path(&unc_in, DriveLetter::C, cwd_fn);
        let unc_lower =
            resolve_windows_path("//myserver/myshare/FOLDER/DOC.TXT", DriveLetter::D, cwd_fn);
        assert_eq!(unc, unc_lower);
        assert!(!unc.is_invalid_unc());
        assert_eq!(unc.to_windows_string(), unc_in);
        assert_eq!(unc.drive_string(), format!("{unc_pre}MyServer{sep}MyShare"));

        let unc_root_in = format!("{unc_pre}myserver{sep}myshare");
        let unc_root = resolve_windows_path(&unc_root_in, DriveLetter::C, cwd_fn);
        assert_eq!(unc_root.to_windows_string(), unc_root_in);
        assert_eq!(unc_root.drive_string(), unc_root_in);

        // 8. Malformed UNC paths (`\\`, `\\onlyserver`, and `//onlyserver`) are NEVER fabricated into localhost/share
        assert!(matches!(
            try_classify_path(unc_pre),
            Err(CmdError::InvalidUncPath { .. })
        ));
        let only_srv = format!("{unc_pre}onlyserver");
        assert!(matches!(
            try_classify_path(&only_srv),
            Err(CmdError::InvalidUncPath { .. })
        ));
        let bad_unc = resolve_windows_path(&only_srv, DriveLetter::C, cwd_fn);
        assert!(bad_unc.is_invalid_unc());
        assert_eq!(bad_unc.to_windows_string(), only_srv);
        let bad_unc_fwd = resolve_windows_path("//onlyserver", DriveLetter::C, cwd_fn);
        assert!(bad_unc_fwd.is_invalid_unc());

        // 9. Extended `\\?\` path preserves trailing dots
        let ext_in = format!("{ext_pre}C:{sep}dir{sep}weird...");
        let ext = resolve_windows_path(&ext_in, DriveLetter::C, cwd_fn);
        assert_eq!(ext.to_windows_string(), format!("C:{sep}dir{sep}weird..."));
    }

    /// Verifies deterministic 8.3 short-name synthesis including `>= 5` NT hex-hash collisions.
    #[test]
    fn test_generate_short_name_8_3_all_branches_and_nt_hash() {
        assert_eq!(generate_short_name_8_3(".", 1), ".");
        assert_eq!(generate_short_name_8_3("..", 1), "..");
        assert_eq!(generate_short_name_8_3("short.txt", 1), "SHORT.TXT");
        assert_eq!(generate_short_name_8_3("short", 1), "SHORT");
        assert_eq!(generate_short_name_8_3("short.txt", 2), "SHORT~2.TXT");
        assert_eq!(generate_short_name_8_3("Program Files", 1), "PROGRA~1");
        assert_eq!(
            generate_short_name_8_3("Program Files (x86)", 2),
            "PROGRA~2"
        );
        assert_eq!(generate_short_name_8_3("index.html", 1), "INDEX~1.HTM");
        assert_eq!(generate_short_name_8_3(".gitignore", 1), "GIT~1.GIT");
        assert_eq!(generate_short_name_8_3(".env", 1), "ENV~1.ENV");
        assert_eq!(generate_short_name_8_3("a+b=c.txt", 1), "A_B_C~1.TXT");
        assert_eq!(generate_short_name_8_3("a b.txt", 1), "AB~1.TXT");
        assert_eq!(generate_short_name_8_3("a.b.c d", 1), "AB~1.CD");

        // Collision indices 5..=20 must all be distinct and strictly 8.3-compliant (`<= 8` stem chars)
        let mut seen = HashSet::new();
        for idx in 1u8..=20u8 {
            let short = generate_short_name_8_3("Program Files Variant", idx);
            let stem = short.split('.').next().unwrap_or("");
            assert!(stem.len() <= 8, "stem exceeded 8 chars: {short}");
            assert!(seen.insert(short), "duplicate short name at index {idx}");
        }
        // Single-char stem with collision >= 5 pads 2-char prefix with '_'
        let padded = generate_short_name_8_3("x", 5);
        assert!(padded.starts_with("X_"));
        assert_eq!(padded.len(), 8);
    }
}
