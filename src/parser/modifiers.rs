//! Batch parameter (`%~dp0`) and `FOR` variable (`%~nxI`) path/attribute modifier evaluation.
//!
//! Supports all `cmd.exe` modifiers via strongly typed [`ModifierFlags`] bitmasks:
//! - `~` (strip surrounding quotes)
//! - `f` (full path)
//! - `d` (drive letter or UNC share)
//! - `p` (path only)
//! - `n` (file name without extension)
//! - `x` (file extension with dot)
//! - `s` (8.3 short names queried from VFS metadata)
//! - `a` (file attributes)
//! - `t` (file timestamp)
//! - `z` (file size in bytes)
//! - `$ENVVAR:` (search directories in `%ENVVAR%` for the file)

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::reader::char_map::SpannedChar;
use crate::types::EnvVarName;
use crate::vfs::VirtualFileSystem;
use crate::vfs::path::{WindowsPath, generate_short_name_8_3};

/// Compact bitmask of `%~` path and metadata modifier flags (`f, d, p, n, x, s, a, t, z`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ModifierFlags(
    /// Raw bitmask storage (`bits 0..=8`).
    u16,
);

impl ModifierFlags {
    /// Empty modifier flag set.
    pub const EMPTY: Self = Self(0);
    /// `f` — Expand to fully qualified path name.
    pub const FULL_PATH: Self = Self(1 << 0);
    /// `d` — Expand to drive letter or UNC share root only.
    pub const DRIVE: Self = Self(1 << 1);
    /// `p` — Expand to directory path only.
    pub const PATH_ONLY: Self = Self(1 << 2);
    /// `n` — Expand to file name stem without extension.
    pub const NAME_ONLY: Self = Self(1 << 3);
    /// `x` — Expand to file extension only.
    pub const EXTENSION: Self = Self(1 << 4);
    /// `s` — Use 8.3 short names.
    pub const SHORT_NAME: Self = Self(1 << 5);
    /// `a` — Expand to file attributes.
    pub const ATTRIBUTES: Self = Self(1 << 6);
    /// `t` — Expand to file date/time.
    pub const TIMESTAMP: Self = Self(1 << 7);
    /// `z` — Expand to file size in bytes.
    pub const FILE_SIZE: Self = Self(1 << 8);
    /// Mask of explicit path-part selectors (`d | p | n | x`).
    pub const EXPLICIT_PARTS_MASK: Self =
        Self(Self::DRIVE.0 | Self::PATH_ONLY.0 | Self::NAME_ONLY.0 | Self::EXTENSION.0);

    /// Checks whether no modifier flags are set.
    ///
    /// # Returns
    /// `true` if the bitmask is `0`, otherwise `false`.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Checks whether all bits in `other` are present in `self`.
    ///
    /// # Arguments
    /// * `other` - Flag(s) to test.
    ///
    /// # Returns
    /// `true` if `(self.0 & other.0) == other.0`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Checks whether any bit in `mask` is present in `self`.
    ///
    /// # Arguments
    /// * `mask` - Mask of candidate flags.
    ///
    /// # Returns
    /// `true` if `(self.0 & mask.0) != 0`.
    #[must_use]
    pub const fn intersects(self, mask: Self) -> bool {
        (self.0 & mask.0) != 0
    }

    /// Inserts `flag` into `self` in-place.
    ///
    /// # Arguments
    /// * `flag` - Flag bit(s) to enable.
    pub const fn insert(&mut self, flag: Self) {
        self.0 |= flag.0;
    }
}

/// Set of parsed `%~` modifiers to apply to a batch parameter or `FOR` variable value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParameterModifiers {
    /// Bitmask of path and file-metadata modifier flags.
    pub flags: ModifierFlags,
    /// `$VAR:` — Environment variable whose semicolon-separated directories should be searched.
    pub path_search_var: Option<EnvVarName>,
}

impl ParameterModifiers {
    /// Checks whether no path/metadata flags (`f, d, p, n, x, s, a, t, z, $VAR:`) are set,
    /// meaning only `~` quote stripping should be performed.
    ///
    /// # Returns
    /// `true` if only `~` quote stripping was requested.
    #[must_use]
    pub const fn is_quote_strip_only(&self) -> bool {
        self.flags.is_empty() && self.path_search_var.is_none()
    }

    /// Parses a modifier character (`f, d, p, n, x, s, a, t, z`) case-insensitively.
    ///
    /// # Arguments
    /// * `ch` - Candidate modifier character.
    ///
    /// # Returns
    /// `true` if `ch` is a valid modifier flag and was recorded, `false` otherwise.
    pub const fn add_flag(&mut self, ch: char) -> bool {
        let flag = match ch.to_ascii_lowercase() {
            'f' => ModifierFlags::FULL_PATH,
            'd' => ModifierFlags::DRIVE,
            'p' => ModifierFlags::PATH_ONLY,
            'n' => ModifierFlags::NAME_ONLY,
            'x' => ModifierFlags::EXTENSION,
            's' => ModifierFlags::SHORT_NAME,
            'a' => ModifierFlags::ATTRIBUTES,
            't' => ModifierFlags::TIMESTAMP,
            'z' => ModifierFlags::FILE_SIZE,
            _ => return false,
        };
        self.flags.insert(flag);
        true
    }

    /// Evaluates the modifiers against a raw argument value using `vfs` and `env_lookup`.
    ///
    /// # Arguments
    /// * `raw_value` - The raw string value of the parameter or `FOR` variable.
    /// * `vfs` - Reference to the active [`VirtualFileSystem`].
    /// * `env_lookup` - Closure to look up environment variables (used for `%~$PATH:1`).
    ///
    /// # Returns
    /// The expanded string after applying all requested modifiers.
    #[must_use]
    pub fn evaluate<F>(&self, raw_value: &str, vfs: &dyn VirtualFileSystem, env_lookup: F) -> String
    where
        F: Fn(&str) -> Option<String>,
    {
        self.evaluate_dyn(raw_value, vfs, &env_lookup)
    }

    /// Non-generic core implementation of [`Self::evaluate`] operating on a dynamic lookup callback.
    ///
    /// # Arguments
    /// * `raw_value` - Raw parameter/variable value.
    /// * `vfs` - Active [`VirtualFileSystem`].
    /// * `env_lookup` - Case-insensitive environment lookup callback.
    ///
    /// # Returns
    /// Expanded string after applying all requested modifiers.
    fn evaluate_dyn(
        &self,
        raw_value: &str,
        vfs: &dyn VirtualFileSystem,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> String {
        let unquoted = strip_surrounding_quotes(raw_value);
        if self.is_quote_strip_only() {
            return unquoted.to_owned();
        }

        let target_raw = if unquoted.is_empty() { "." } else { unquoted };
        let resolved_opt: Option<WindowsPath> = self.path_search_var.as_ref().map_or_else(
            || Some(vfs.resolve_path(target_raw)),
            |var_name| search_in_env_path(unquoted, var_name.as_str(), vfs, env_lookup),
        );

        let Some(resolved) = resolved_opt else {
            return String::new();
        };

        let stat_opt = vfs.stat(&resolved.to_windows_string()).ok();
        let effective_path = if self.flags.contains(ModifierFlags::SHORT_NAME) {
            to_short_windows_path(&resolved, vfs)
        } else {
            resolved
        };

        let mut metadata_parts = Vec::new();
        if self.flags.contains(ModifierFlags::ATTRIBUTES) {
            let attr_str = stat_opt
                .as_ref()
                .map_or_else(String::new, |m| m.attributes.to_cmd_attr_string());
            metadata_parts.push(attr_str);
        }
        if self.flags.contains(ModifierFlags::TIMESTAMP) {
            let time_str = stat_opt
                .as_ref()
                .map_or_else(String::new, |m| m.modified_timestamp.to_string());
            metadata_parts.push(time_str);
        }
        if self.flags.contains(ModifierFlags::FILE_SIZE) {
            let size_str = stat_opt
                .as_ref()
                .map_or_else(String::new, |m| m.size.to_string());
            metadata_parts.push(size_str);
        }

        let has_explicit_part = self.flags.intersects(ModifierFlags::EXPLICIT_PARTS_MASK);
        let implicit_full = (self.flags.contains(ModifierFlags::SHORT_NAME)
            || self.path_search_var.is_some())
            && !has_explicit_part
            && metadata_parts.is_empty();

        let path_part = if self.flags.contains(ModifierFlags::FULL_PATH) || implicit_full {
            effective_path.to_windows_string()
        } else if has_explicit_part {
            let mut s = String::new();
            if self.flags.contains(ModifierFlags::DRIVE) {
                s.push_str(&effective_path.drive_string());
            }
            if self.flags.contains(ModifierFlags::PATH_ONLY) {
                s.push_str(&effective_path.directory_path_only());
            }
            if self.flags.contains(ModifierFlags::NAME_ONLY) {
                s.push_str(effective_path.file_stem());
            }
            if self.flags.contains(ModifierFlags::EXTENSION) {
                s.push_str(effective_path.extension_with_dot());
            }
            s
        } else {
            String::new()
        };

        if metadata_parts.is_empty() {
            path_part
        } else {
            if !path_part.is_empty() {
                metadata_parts.push(path_part);
            }
            metadata_parts.join(" ")
        }
    }
}

/// Parses a `$ENVVAR:` modifier clause starting at `dollar_idx` (pointing to `'$'`) in `chars`.
///
/// Shared between Phase 1 (`%~dp$PATH:0`) and Phase 3 (`%%~dp$PATH:I`) to guarantee identical
/// modifier lexing rules.
///
/// # Arguments
/// * `chars` - Slice of [`SpannedChar`] representing the logical line.
/// * `dollar_idx` - Index of the leading `'$'` character in `chars`.
///
/// # Returns
/// `Some((EnvVarName, next_idx_after_colon))` if a valid non-empty `$VAR:` clause was parsed, else `None`.
#[must_use]
pub fn parse_dollar_env_modifier(
    chars: &[SpannedChar],
    dollar_idx: usize,
) -> Option<(EnvVarName, usize)> {
    let var_start = dollar_idx.saturating_add(1);
    let mut colon_pos = None;
    let mut scan = var_start;
    while let Some(vc) = chars.get(scan) {
        if vc.ch == ':' {
            colon_pos = Some(scan);
            break;
        }
        if vc.ch.is_whitespace() || vc.ch == '%' {
            break;
        }
        scan = scan.saturating_add(1);
    }
    let c_pos = colon_pos?;
    if c_pos <= var_start {
        return None;
    }
    let v_slice = chars.get(var_start..c_pos)?;
    let v_name: String = v_slice.iter().map(|c| c.ch).collect();
    Some((EnvVarName::new(&v_name), c_pos.saturating_add(1)))
}

/// Strips a single matched pair of surrounding double quotes `"..."` from `val`, matching `%~1` behavior.
///
/// # Arguments
/// * `val` - Input string slice.
///
/// # Returns
/// Slice with the outermost `"..."` pair removed when both leading and trailing `"` are present,
/// or `val` unchanged otherwise.
#[must_use]
pub fn strip_surrounding_quotes(val: &str) -> &str {
    val.strip_prefix('"')
        .and_then(|after_open| after_open.strip_suffix('"'))
        .unwrap_or(val)
}

/// Strips an enclosing `"..."` pair up to the **last** `"` on a `SET` operand (`SET "VAR=val" ignored`),
/// or strips a leading unclosed `"` if no closing quote exists, matching `cmd.exe` `SET` semantics.
///
/// # Arguments
/// * `val` - Leading-whitespace-trimmed `SET` operand slice.
///
/// # Returns
/// Unquoted `SET` assignment slice.
#[must_use]
pub fn strip_set_outer_quotes(val: &str) -> &str {
    val.strip_prefix('"').map_or(val, |after_open| {
        after_open.rfind('"').map_or(after_open, |last_q| {
            after_open.get(..last_q).unwrap_or(after_open)
        })
    })
}

/// Strips all double-quote (`"`) delimiters from a composite command or path argument word
/// (e.g., `"C:\Program Files"\app.exe` and `C:\"Program Files"\app.exe` -> `C:\Program Files\app.exe`).
///
/// # Arguments
/// * `val` - Raw command or path word text.
///
/// # Returns
/// String with all `"` quote delimiters removed.
#[must_use]
pub fn strip_command_arg_quotes(val: &str) -> String {
    val.chars().filter(|&c| c != '"').collect()
}

/// Converts every component of `path` to its actual VFS-allocated 8.3 short name (such as
/// `PROGRA~2` when collisions exist), falling back to deterministic 8.3 synthesis for
/// non-existent path segments.
///
/// # Arguments
/// * `path` - Resolved [`WindowsPath`].
/// * `vfs` - Active [`VirtualFileSystem`] queried for collision-resolved `short_name` metadata.
///
/// # Returns
/// [`WindowsPath`] with 8.3 short components.
fn to_short_windows_path(path: &WindowsPath, vfs: &dyn VirtualFileSystem) -> WindowsPath {
    let mut prefix_path = WindowsPath {
        drive: path.drive,
        unc_prefix: path.unc_prefix.clone(),
        components: Vec::with_capacity(path.components.len()),
    };
    let mut short_comps = Vec::with_capacity(path.components.len());
    for comp in &path.components {
        prefix_path.components.push(comp.clone());
        let short_seg = vfs
            .stat(&prefix_path.to_windows_string())
            .ok()
            .map(|m| m.short_name)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| generate_short_name_8_3(comp, 1));
        short_comps.push(short_seg);
    }
    WindowsPath {
        drive: path.drive,
        unc_prefix: path.unc_prefix.clone(),
        components: short_comps,
    }
}

/// Searches directories listed in `env_var` for `file_name` and returns the first existing [`WindowsPath`].
///
/// # Arguments
/// * `file_name` - Unquoted filename to search for.
/// * `env_var` - Environment variable name (e.g., `"PATH"`).
/// * `vfs` - Active [`VirtualFileSystem`].
/// * `env_lookup` - Environment variable lookup function.
///
/// # Returns
/// `Some(WindowsPath)` of the first existing file, or `None` if not found or `file_name` is empty.
fn search_in_env_path(
    file_name: &str,
    env_var: &str,
    vfs: &dyn VirtualFileSystem,
    env_lookup: &dyn Fn(&str) -> Option<String>,
) -> Option<WindowsPath> {
    if file_name.is_empty() {
        return None;
    }
    let dirs = env_lookup(env_var)?;
    dirs.split(';')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .find_map(|dir| {
            let candidate = vfs.resolve_path(dir).join_component(file_name);
            let meta = vfs.stat(&candidate.to_windows_string()).ok()?;
            (!meta.attributes.is_directory()).then_some(meta.full_path)
        })
}

#[cfg(test)]
/// Unit tests for `%~` parameter/FOR modifier parsing, evaluation, and VFS 8.3 short paths.
mod tests {
    use super::*;
    use crate::types::BS_STR as SEP;
    use crate::vfs::InMemoryVfs;

    /// Verifies quote stripping, drive/path/name/ext selectors, and VFS 8.3 short-name collisions.
    #[test]
    fn test_parameter_modifiers_evaluation_and_vfs_short_collisions() {
        let mut vfs = InMemoryVfs::new();
        assert!(
            vfs.create_dir(
                "C:/Program Files/MyApp",
                crate::types::DirCreationDepth::CreateParents
            )
            .is_ok()
        );
        assert!(
            vfs.create_dir(
                "C:/Program Files (x86)/Tool",
                crate::types::DirCreationDepth::CreateParents
            )
            .is_ok()
        );
        assert!(
            vfs.write_bytes("C:/Program Files/MyApp/runner.bat", b"@echo hi")
                .is_ok()
        );
        assert!(
            vfs.write_bytes("C:/Program Files (x86)/Tool/app.exe", b"MZ")
                .is_ok()
        );
        let env_lookup = |_: &str| None;

        // 1. Quote strip only (`%~1`)
        let m_tilde = ParameterModifiers::default();
        let quoted_runner = format!(r#""C:{SEP}Program Files{SEP}MyApp{SEP}runner.bat""#);
        let unquoted_runner = format!("C:{SEP}Program Files{SEP}MyApp{SEP}runner.bat");
        assert_eq!(
            m_tilde.evaluate(&quoted_runner, &vfs, env_lookup),
            unquoted_runner
        );
        assert_eq!(m_tilde.evaluate("unquoted", &vfs, env_lookup), "unquoted");
        assert_eq!(strip_surrounding_quotes(r#""half"#), r#""half"#);
        assert_eq!(strip_set_outer_quotes(r#""X=1" trailing"#), "X=1");
        assert_eq!(strip_set_outer_quotes(r#""half"#), "half");
        assert_eq!(
            strip_command_arg_quotes(r#""C:/Program Files"/app.exe"#),
            "C:/Program Files/app.exe"
        );
        assert_eq!(
            strip_command_arg_quotes(r#"C:/"Program Files"/app.exe"#),
            "C:/Program Files/app.exe"
        );

        // 2. `%~dp1`
        let mut m_dp = ParameterModifiers::default();
        assert!(m_dp.add_flag('d'));
        assert!(m_dp.add_flag('p'));
        assert!(!m_dp.add_flag('?'));
        assert_eq!(
            m_dp.evaluate(&quoted_runner, &vfs, env_lookup),
            format!("C:{SEP}Program Files{SEP}MyApp{SEP}")
        );

        // 3. `%~nx1`
        let mut m_nx = ParameterModifiers::default();
        assert!(m_nx.add_flag('n'));
        assert!(m_nx.add_flag('x'));
        assert_eq!(
            m_nx.evaluate(&unquoted_runner, &vfs, env_lookup),
            "runner.bat"
        );

        // 4. `%~f1` and empty string fallback
        let mut m_f = ParameterModifiers::default();
        assert!(m_f.add_flag('f'));
        assert_eq!(m_f.evaluate("", &vfs, env_lookup), format!("C:{SEP}"));

        // 5. `%~s1` resolves actual VFS short names (`PROGRA~1` AND collided `PROGRA~2` + missing fallback!)
        let mut m_s = ParameterModifiers::default();
        assert!(m_s.add_flag('s'));
        assert_eq!(
            m_s.evaluate(&unquoted_runner, &vfs, env_lookup),
            format!("C:{SEP}PROGRA~1{SEP}MYAPP{SEP}RUNNER.BAT")
        );
        let x86_app = format!("C:{SEP}Program Files (x86){SEP}Tool{SEP}app.exe");
        assert_eq!(
            m_s.evaluate(&x86_app, &vfs, env_lookup),
            format!("C:{SEP}PROGRA~2{SEP}TOOL{SEP}APP.EXE")
        );
        let missing_long = format!("C:{SEP}Program Files (x86){SEP}NonExistentDir{SEP}file.html");
        assert_eq!(
            m_s.evaluate(&missing_long, &vfs, env_lookup),
            format!("C:{SEP}PROGRA~2{SEP}NONEXI~1{SEP}FILE~1.HTM")
        );
    }

    /// Verifies `%~ftza` file metadata modifiers and `%~$PATH:` directory search modifiers.
    #[test]
    fn test_parameter_modifiers_metadata_and_env_path_search() {
        let mut vfs = InMemoryVfs::new();
        assert!(
            vfs.create_dir(
                "C:/Program Files/MyApp",
                crate::types::DirCreationDepth::CreateParents
            )
            .is_ok()
        );
        assert!(
            vfs.write_bytes("C:/Program Files/MyApp/runner.bat", b"@echo hi")
                .is_ok()
        );
        let path_val = format!("C:{SEP}Windows;C:{SEP}Program Files{SEP}MyApp");
        let env_lookup = |k: &str| {
            if k.eq_ignore_ascii_case("PATH") {
                Some(path_val.clone())
            } else {
                None
            }
        };
        let unquoted_runner = format!("C:{SEP}Program Files{SEP}MyApp{SEP}runner.bat");

        // 1. `%~ftza1` on existing file vs missing file
        let mut m_ftza = ParameterModifiers::default();
        assert!(m_ftza.add_flag('f'));
        assert!(m_ftza.add_flag('t'));
        assert!(m_ftza.add_flag('z'));
        assert!(m_ftza.add_flag('a'));
        assert_eq!(
            m_ftza.evaluate(&unquoted_runner, &vfs, env_lookup),
            format!("--a------ 11/10/2026  09:00 AM 8 {unquoted_runner}")
        );
        let mut m_tza_missing = ParameterModifiers::default();
        assert!(m_tza_missing.add_flag('t'));
        assert!(m_tza_missing.add_flag('z'));
        assert!(m_tza_missing.add_flag('a'));
        assert_eq!(
            m_tza_missing.evaluate("C:/missing.txt", &vfs, env_lookup),
            "  "
        );

        // 2. `%~$PATH:1` and `%~dp$PATH:1`
        let mut m_path = ParameterModifiers {
            flags: ModifierFlags::EMPTY,
            path_search_var: Some(EnvVarName::new("PATH")),
        };
        assert_eq!(
            m_path.evaluate("runner.bat", &vfs, env_lookup),
            unquoted_runner
        );
        assert!(m_path.add_flag('d'));
        assert!(m_path.add_flag('p'));
        assert_eq!(
            m_path.evaluate("runner.bat", &vfs, env_lookup),
            format!("C:{SEP}Program Files{SEP}MyApp{SEP}")
        );
        assert_eq!(m_path.evaluate("nonexistent.exe", &vfs, env_lookup), "");
        assert!(
            vfs.create_dir(
                "C:/Program Files/MyApp/subdir",
                crate::types::DirCreationDepth::CreateParents
            )
            .is_ok()
        );
        assert_eq!(m_path.evaluate("subdir", &vfs, env_lookup), "");
        assert_eq!(m_path.evaluate("", &vfs, env_lookup), "");
        let m_unfound_var = ParameterModifiers {
            flags: ModifierFlags::EMPTY,
            path_search_var: Some(EnvVarName::new("UNSET_VAR")),
        };
        assert_eq!(m_unfound_var.evaluate("runner.bat", &vfs, env_lookup), "");
    }
}
