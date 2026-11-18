//! Host OS filesystem bridge (`HostOsVfs`) and Wine/POSIX drive mount translation.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::error::CmdError;
use crate::types::{
    BS_CHAR, CaseSensitivity, DriveLetter, HostBindingMode, MklinkKind, fold_win32_case,
};
use crate::vfs::devices::DosDevice;
use crate::vfs::glob::{self, matches_win32_glob};
use crate::vfs::memory::InMemoryVfs;
use crate::vfs::path::{WindowsPath, generate_short_name_8_3};
use crate::vfs::traits::{
    CaseFoldedString, DEFAULT_VFS_EPOCH_SECS, FileAttributeFlags, FileTimestamp, VfsKey,
    VfsMetadata, VirtualFileSystem, VolumeInfo,
};

/// Default host process working directory setter delegating to [`std::env::set_current_dir`].
///
/// # Arguments
/// * `path` - Target host directory [`Path`].
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns [`std::io::Error`] if changing the OS process directory fails.
fn host_os_set_current_dir(path: &Path) -> std::io::Result<()> {
    std::env::set_current_dir(path)
}

/// Converts a host [`std::io::Result`] into `Result<T, CmdError>` via [`CmdError::from_io_error`].
///
/// # Arguments
/// * `res` - Host I/O result.
/// * `raw_path` - Associated Windows path string.
/// * `operation` - Operation name for error diagnostics.
///
/// # Returns
/// `Ok(T)` or mapped [`CmdError`].
///
/// # Errors
/// Returns the [`CmdError`] produced by [`CmdError::from_io_error`] when `res` is `Err`.
fn map_io_res<T>(
    res: Result<T, std::io::Error>,
    raw_path: &str,
    operation: &str,
) -> Result<T, CmdError> {
    match res {
        Ok(val) => Ok(val),
        Err(err) => Err(CmdError::from_io_error(&err, raw_path, operation)),
    }
}

/// Symlink escape containment policy for [`HostOsVfs`] drive mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SandboxContainment {
    /// Enforce that all resolved host paths and symlink targets remain inside the mounted drive root.
    #[default]
    Contained,
    /// Allow host symlinks to traverse freely across the host OS (`wincmd` native host mode).
    Unrestricted,
}

/// Host OS filesystem bridge mapping Windows drives (`C:`, `Z:`, etc.) onto host [`PathBuf`] directories.
///
/// Supports case-insensitive path resolution on case-sensitive Unix/macOS filesystems, 8.3 short-name
/// matching, attribute sidecar tracking (`R`, `H`, `S`, `A`, `L`), reserved DOS device handling, and
/// configurable [`SandboxContainment`] preventing symlink escapes when rooted in a sandbox directory.
#[derive(Debug, Clone)]
pub struct HostOsVfs {
    /// Host root directory backing `C:`.
    pub host_root: PathBuf,
    /// Explicit per-drive host root directories (`C:` -> `host_root`, `D:` -> `d_root`, `Z:` -> `/`).
    pub drive_roots: BTreeMap<DriveLetter, PathBuf>,
    /// Explicit UNC network share mounts (`(\\SERVER, SHARE)` -> host directory), preventing silent aliasing onto `C:`.
    pub unc_mounts: BTreeMap<(CaseFoldedString, CaseFoldedString), PathBuf>,
    /// Backing [`InMemoryVfs`] for drive CWDs, volume metadata, and configurable free space.
    pub inner: InMemoryVfs,
    /// Emulated file attributes sidecar keyed by `(VfsRoot, Vec<UPPERCASE>)`.
    pub attr_sidecar: BTreeMap<VfsKey, FileAttributeFlags>,
    /// Sandbox containment policy governing symlink escape checks.
    pub containment: SandboxContainment,
    /// Host process CWD synchronization callback (`std::env::set_current_dir` by default; injectable for race-free hermetic tests).
    pub cwd_sync_fn: fn(&Path) -> std::io::Result<()>,
}

impl HostOsVfs {
    /// Creates a new sandboxed [`HostOsVfs`] rooted at `host_root` on drive `C:` only.
    ///
    /// Unlike `InMemoryVfs`, `D:` is **not** aliased onto `host_root` by default; additional drives
    /// may be mounted onto distinct host directories via [`Self::mount_drive`] or [`Self::with_mounts`].
    /// Enables [`SandboxContainment::Contained`] by default so symlinks inside `host_root` cannot
    /// escape `host_root`.
    ///
    /// # Arguments
    /// * `host_root` - Host directory path mapped to `C:`.
    ///
    /// # Returns
    /// A new [`HostOsVfs`] with `C:` mounted and [`SandboxContainment::Contained`] active.
    #[must_use]
    pub fn new(host_root: PathBuf) -> Self {
        let mut drive_roots = BTreeMap::new();
        drive_roots.insert(DriveLetter::C, host_root);
        Self::with_mounts(DriveLetter::C, drive_roots, SandboxContainment::Contained)
    }

    /// Creates a [`HostOsVfs`] from an explicit per-drive mount table and [`SandboxContainment`] policy.
    ///
    /// # Arguments
    /// * `active_drive` - Initial active [`DriveLetter`].
    /// * `drive_roots` - Per-drive host directory mount table.
    /// * `containment` - [`SandboxContainment`] policy for symlink escape checks.
    ///
    /// # Returns
    /// Configured [`HostOsVfs`].
    #[must_use]
    pub fn with_mounts(
        active_drive: DriveLetter,
        drive_roots: BTreeMap<DriveLetter, PathBuf>,
        containment: SandboxContainment,
    ) -> Self {
        let mut inner = InMemoryVfs::unmounted_placeholder();
        inner.active_drive = active_drive;
        for &drive in drive_roots.keys() {
            let label = if drive == DriveLetter::C {
                "Windows"
            } else {
                "Host"
            };
            inner.mount_empty_drive(drive, label, "CAFE-BABE");
        }
        let host_root = drive_roots
            .get(&active_drive)
            .or_else(|| drive_roots.values().next())
            .cloned()
            .unwrap_or_default();

        Self {
            host_root,
            drive_roots,
            unc_mounts: BTreeMap::new(),
            inner,
            attr_sidecar: BTreeMap::new(),
            containment,
            cwd_sync_fn: host_os_set_current_dir,
        }
    }

    /// Discovers drives from a Wine prefix directory (`$WINEPREFIX/dosdevices/a:` .. `z:`)
    /// or falls back to mounting `fallback_c_root` on `C:`.
    ///
    /// # Arguments
    /// * `wineprefix` - Optional path to a Wine prefix directory containing `dosdevices`.
    /// * `fallback_c_root` - Fallback host path for `C:` if `dosdevices/c:` is absent.
    ///
    /// # Returns
    /// Configured [`HostOsVfs`] with [`SandboxContainment::Unrestricted`].
    #[must_use]
    pub fn from_wineprefix(wineprefix: Option<&Path>, fallback_c_root: PathBuf) -> Self {
        let mut mounts = BTreeMap::new();
        mounts.insert(DriveLetter::C, fallback_c_root);
        let mut vfs = Self::with_mounts(DriveLetter::C, mounts, SandboxContainment::Unrestricted);
        let Some(dosdevices) = wineprefix
            .map(|p| p.join("dosdevices"))
            .filter(|d| d.is_dir())
        else {
            return vfs;
        };

        for b in b'a'..=b'z' {
            let letter_ch = char::from(b);
            let drive = DriveLetter::try_from_char(letter_ch).unwrap_or(DriveLetter::Z);
            let link_path = dosdevices.join(format!("{letter_ch}:"));
            if link_path.is_dir() {
                vfs.mount_drive(drive, link_path);
            }
        }
        vfs.host_root = vfs
            .drive_roots
            .get(&DriveLetter::C)
            .cloned()
            .unwrap_or(vfs.host_root);
        vfs
    }

    /// Creates a [`HostOsVfs`] initialized from the current host environment (`WINEPREFIX`,
    /// `WINCMD_C_ROOT`, and `std::env::current_dir()`).
    ///
    /// # Returns
    /// Configured [`HostOsVfs`] with `C:` and `Z:` (`/`) mounted.
    #[must_use]
    pub fn from_host_env() -> Self {
        let cwd = std::env::current_dir().unwrap_or_default();
        #[cfg(windows)]
        let mut vfs = {
            let explicit_c = std::env::var_os("WINCMD_C_ROOT").map(PathBuf::from);
            let wineprefix = std::env::var_os("WINEPREFIX").map(PathBuf::from);
            let mut v = Self::from_wineprefix(
                wineprefix.as_deref(),
                explicit_c.clone().unwrap_or_else(|| PathBuf::from(r"C:\")),
            );
            if explicit_c.is_none() && wineprefix.is_none() {
                for b in b'A'..=b'Z' {
                    let letter_ch = char::from(b);
                    let drive = DriveLetter::try_from_char(letter_ch).unwrap_or(DriveLetter::Z);
                    let root = PathBuf::from(format!(r"{letter_ch}:\"));
                    if root.is_dir() {
                        v.mount_drive(drive, root);
                    }
                }
            }
            v
        };
        #[cfg(not(windows))]
        let mut vfs = {
            let c_root =
                std::env::var_os("WINCMD_C_ROOT").map_or_else(|| cwd.clone(), PathBuf::from);
            let wineprefix = std::env::var_os("WINEPREFIX").map(PathBuf::from);
            let mut v = Self::from_wineprefix(wineprefix.as_deref(), c_root);
            v.mount_drive(DriveLetter::Z, PathBuf::from("/"));
            v
        };
        vfs.hydrate_cwd_from_host_path(&cwd);
        vfs
    }

    /// Hydrates the active drive and per-drive CWD from a host directory path.
    ///
    /// # Arguments
    /// * `host_cwd` - Host directory path.
    pub fn hydrate_cwd_from_host_path(&mut self, host_cwd: &Path) {
        #[cfg(windows)]
        {
            let matched = self
                .drive_roots
                .iter()
                .find_map(|(&d, root)| host_cwd.strip_prefix(root).ok().map(|rel| (d, rel)));
            if let Some((drive, rel)) = matched {
                let comps: Vec<String> = rel
                    .components()
                    .filter_map(|c| c.as_os_str().to_str().map(str::to_owned))
                    .collect();
                self.inner.active_drive = drive;
                self.inner.drive_cwds.insert(drive, comps);
            }
        }
        #[cfg(not(windows))]
        {
            let rel_opt = self
                .drive_roots
                .get(&DriveLetter::C)
                .and_then(|c_root| host_cwd.strip_prefix(c_root).ok());
            if let Some(rel) = rel_opt {
                let comps: Vec<String> = rel
                    .components()
                    .filter_map(|c| c.as_os_str().to_str().map(str::to_owned))
                    .collect();
                self.inner.active_drive = DriveLetter::C;
                self.inner.drive_cwds.insert(DriveLetter::C, comps);
            }
        }
    }

    /// Formats a Unix epoch timestamp (in seconds) into `cmd.exe`'s `"MM/DD/YYYY  hh:mm AM/PM"` format.
    ///
    /// # Arguments
    /// * `epoch_secs` - Seconds since `1970-01-01T00:00:00Z`.
    ///
    /// # Returns
    /// Formatted timestamp string (e.g., `"11/10/2026  09:00 AM"`).
    #[must_use]
    pub fn format_unix_epoch_secs_cmd_timestamp(epoch_secs: u64) -> String {
        FileTimestamp::from_epoch_secs(epoch_secs).format_default()
    }

    /// Mounts a host directory onto `drive`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    /// * `root` - Host [`PathBuf`] directory.
    pub fn mount_drive(&mut self, drive: DriveLetter, root: PathBuf) {
        self.drive_roots.insert(drive, root);
        self.inner.drive_cwds.entry(drive).or_default();
        self.inner
            .drive_free_space
            .entry(drive)
            .or_insert(100_000_000);
        self.inner.volumes.insert(
            drive,
            VolumeInfo {
                label: "Host".to_owned(),
                serial_number: "CAFE-BABE".to_owned(),
            },
        );
    }

    /// Registers a host directory backing a UNC network share (`\\server\share`).
    ///
    /// # Arguments
    /// * `server` - UNC server hostname.
    /// * `share` - UNC share name.
    /// * `root` - Host [`PathBuf`] directory backing `\\server\share`.
    pub fn mount_unc_share(&mut self, server: &str, share: &str, root: PathBuf) {
        self.unc_mounts.insert(
            (CaseFoldedString::new(server), CaseFoldedString::new(share)),
            root,
        );
    }

    /// Resolves the mounted host root directory for `win_path`, rejecting malformed UNC paths
    /// with [`CmdError::InvalidUncPath`] and unmounted UNC shares with [`CmdError::NetworkPathNotFound`].
    ///
    /// # Arguments
    /// * `win_path` - Resolved [`WindowsPath`].
    /// * `raw_path` - Original path string for error diagnostics.
    ///
    /// # Returns
    /// `Ok(&PathBuf)` of the mounted drive or UNC share root.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidUncPath`], [`CmdError::NetworkPathNotFound`], or [`CmdError::DriveNotFound`].
    fn mount_root_for(&self, win_path: &WindowsPath, raw_path: &str) -> Result<&PathBuf, CmdError> {
        if win_path.is_invalid_unc() {
            return Err(CmdError::InvalidUncPath {
                raw: raw_path.to_owned(),
            });
        }
        if let Some((srv, shr)) = &win_path.unc_prefix {
            return self
                .unc_mounts
                .get(&(CaseFoldedString::new(srv), CaseFoldedString::new(shr)))
                .ok_or_else(|| CmdError::NetworkPathNotFound {
                    path: raw_path.to_owned(),
                });
        }
        self.drive_roots
            .get(&win_path.drive)
            .ok_or(CmdError::DriveNotFound {
                drive: win_path.drive,
            })
    }

    /// Walks `components` beneath `base` on the host filesystem, matching each existing component
    /// case-insensitively or by collision-resolved 8.3 short name.
    ///
    /// # Arguments
    /// * `base` - Mounted root [`Path`] on the host OS.
    /// * `components` - Resolved [`WindowsPath`] components.
    ///
    /// # Returns
    /// Corresponding host [`PathBuf`].
    #[must_use]
    fn to_host_path_from_base(base: &Path, components: &[String]) -> PathBuf {
        let mut cur = base.to_path_buf();
        for comp in components {
            let fallback = cur.join(comp);
            let matched = std::fs::read_dir(&cur)
                .ok()
                .and_then(|rd| {
                    let mut names: Vec<String> = rd
                        .filter_map(Result::ok)
                        .filter_map(|e| e.file_name().into_string().ok())
                        .collect();
                    names.sort_by_key(|n| fold_win32_case(n));
                    let mut base_counts: BTreeMap<String, u8> = BTreeMap::new();
                    let comp_folded = fold_win32_case(comp);
                    for name in &names {
                        let base_short = generate_short_name_8_3(name, 1);
                        let next_col = base_counts
                            .get(&base_short)
                            .copied()
                            .unwrap_or(0)
                            .saturating_add(1);
                        base_counts.insert(base_short, next_col);
                        let short = generate_short_name_8_3(name, next_col);
                        if fold_win32_case(name) == comp_folded || short.eq_ignore_ascii_case(comp)
                        {
                            return Some(cur.join(name));
                        }
                    }
                    None
                })
                .unwrap_or(fallback);
            cur = matched;
        }
        cur
    }

    /// Computes the collision-accurate 8.3 `short_name` (`~1`, `~2`, ...) of `leaf_name` inside
    /// `parent_dir` using the exact same sorted sibling collision order as `read_dir` and `to_host_path`.
    ///
    /// # Arguments
    /// * `parent_dir` - Host parent directory containing `leaf_name`.
    /// * `leaf_name` - Case-preserved entry name.
    ///
    /// # Returns
    /// Collision-resolved 8.3 short name string.
    #[must_use]
    pub(super) fn compute_host_dir_short_name(parent_dir: &Path, leaf_name: &str) -> String {
        if let Ok(rd) = std::fs::read_dir(parent_dir) {
            let mut names: Vec<String> = rd
                .filter_map(Result::ok)
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();
            names.sort_by_key(|n| fold_win32_case(n));
            let mut base_counts: BTreeMap<String, u8> = BTreeMap::new();
            let leaf_folded = fold_win32_case(leaf_name);
            for name in &names {
                let base_short = generate_short_name_8_3(name, 1);
                let next_col = base_counts
                    .get(&base_short)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1);
                base_counts.insert(base_short, next_col);
                if fold_win32_case(name) == leaf_folded {
                    return generate_short_name_8_3(name, next_col);
                }
            }
        }
        generate_short_name_8_3(leaf_name, 1)
    }

    /// Translates a resolved [`WindowsPath`] into a host [`PathBuf`] when its drive or UNC share is mounted.
    ///
    /// Unmounted UNC paths do **not** fall back to `self.host_root` (`C:`).
    ///
    /// # Arguments
    /// * `win_path` - Resolved [`WindowsPath`].
    ///
    /// # Returns
    /// Corresponding host [`PathBuf`] (or empty [`PathBuf`] if `win_path` is an unmounted UNC path).
    #[must_use]
    pub fn to_host_path(&self, win_path: &WindowsPath) -> PathBuf {
        self.mount_root_for(win_path, "").map_or_else(
            |_| {
                if win_path.unc_prefix.is_some() {
                    PathBuf::new()
                } else {
                    Self::to_host_path_from_base(&self.host_root, &win_path.components)
                }
            },
            |base| Self::to_host_path_from_base(base, &win_path.components),
        )
    }

    /// Verifies that `host_path` (including any resolved symlink targets along its prefix)
    /// stays strictly inside `mount_root` when [`SandboxContainment::Contained`] is active.
    ///
    /// # Arguments
    /// * `mount_root` - Mounted drive or UNC share host root directory.
    /// * `host_path` - Candidate host [`Path`] to validate.
    /// * `raw_path` - Original Windows path string for [`CmdError::AccessDenied`] diagnostics.
    ///
    /// # Returns
    /// `Ok(())` when `host_path` stays strictly inside `mount_root`.
    ///
    /// # Errors
    /// Returns [`CmdError::AccessDenied`] if a symlink or path escapes the sandbox root.
    fn verify_sandbox_containment_against(
        &self,
        mount_root: &Path,
        host_path: &Path,
        raw_path: &str,
    ) -> Result<(), CmdError> {
        if self.containment == SandboxContainment::Unrestricted {
            return Ok(());
        }
        let canon_root =
            std::fs::canonicalize(mount_root).unwrap_or_else(|_| mount_root.to_path_buf());

        let mut ancestors: Vec<&Path> = host_path.ancestors().collect();
        ancestors.reverse();
        for prefix in ancestors {
            if !prefix.starts_with(mount_root) {
                continue;
            }
            if prefix.is_symlink() {
                let link_target = map_io_res(std::fs::read_link(prefix), raw_path, "stat")?;
                let resolved_target = if link_target.is_absolute() {
                    link_target
                } else {
                    prefix.parent().unwrap_or(mount_root).join(link_target)
                };
                let canon_target = std::fs::canonicalize(&resolved_target)
                    .unwrap_or_else(|_| normalize_lexical_host_path(&resolved_target));
                if !canon_target.starts_with(&canon_root) {
                    return Err(CmdError::AccessDenied {
                        path: raw_path.to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Resolves `raw_path` into `(WindowsPath, PathBuf)` and enforces UNC/drive mounting and sandbox containment.
    ///
    /// # Arguments
    /// * `raw_path` - Raw Windows path string.
    ///
    /// # Returns
    /// `Ok((WindowsPath, PathBuf))` when mounted and within sandbox bounds.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidUncPath`], [`CmdError::NetworkPathNotFound`], [`CmdError::DriveNotFound`],
    /// or [`CmdError::AccessDenied`] on containment violation.
    fn resolve_checked_host_path(
        &self,
        raw_path: &str,
    ) -> Result<(WindowsPath, PathBuf), CmdError> {
        let win_path = self.resolve_path(raw_path);
        let mount_root = self.mount_root_for(&win_path, raw_path)?;
        let host_p = Self::to_host_path_from_base(mount_root, &win_path.components);
        self.verify_sandbox_containment_against(mount_root, &host_p, raw_path)?;
        Ok((win_path, host_p))
    }

    /// Computes the sidecar [`VfsKey`] for `win_path` (resolving `PUSHD` UNC aliases via `self.inner.root_for`).
    ///
    /// # Arguments
    /// * `win_path` - Resolved [`WindowsPath`].
    ///
    /// # Returns
    /// Canonical [`VfsKey`].
    #[must_use]
    fn sidecar_key(&self, win_path: &WindowsPath) -> VfsKey {
        let folded = win_path
            .components
            .iter()
            .map(|c| fold_win32_case(c))
            .collect();
        (self.inner.root_for(win_path), folded)
    }

    /// Checks recursively whether `dir_host` (or `dir_key` in `attr_sidecar`) contains any `READ_ONLY` descendant.
    ///
    /// # Arguments
    /// * `dir_key` - Canonical [`VfsKey`] of the directory subtree.
    /// * `dir_host` - Host [`Path`] of the directory subtree.
    ///
    /// # Returns
    /// `true` if any entry in the subtree has `READ_ONLY` set.
    #[must_use]
    fn has_readonly_descendant(&self, dir_key: &VfsKey, dir_host: &Path) -> bool {
        if self.attr_sidecar.iter().any(|((r, comps), attrs)| {
            r == &dir_key.0 && comps.starts_with(&dir_key.1) && attrs.is_read_only()
        }) {
            return true;
        }
        has_host_os_readonly_recursive(dir_host)
    }

    /// Builds a [`VfsMetadata`] from a host [`std::fs::Metadata`], entry name, short name, and [`WindowsPath`].
    ///
    /// # Arguments
    /// * `win_path` - Resolved [`WindowsPath`] of the entry.
    /// * `name` - Case-preserved filename.
    /// * `short_name` - 8.3 short filename.
    /// * `meta` - Host [`std::fs::Metadata`].
    /// * `link_policy` - [`crate::types::SymlinkFollowPolicy`] (`PreserveFinalLink` marks a reparse point).
    ///
    /// # Returns
    /// Populated [`VfsMetadata`].
    fn metadata_from_host(
        &self,
        win_path: &WindowsPath,
        name: String,
        short_name: String,
        meta: &std::fs::Metadata,
        link_policy: crate::types::SymlinkFollowPolicy,
    ) -> VfsMetadata {
        let key = self.sidecar_key(win_path);
        let is_dir = meta.is_dir();
        let default_attrs = if is_dir {
            FileAttributeFlags::default_dir()
        } else {
            FileAttributeFlags::default_file()
        };
        let mut attrs = self
            .attr_sidecar
            .get(&key)
            .copied()
            .unwrap_or(default_attrs);
        attrs.set_flag(
            FileAttributeFlags::DIRECTORY,
            if is_dir {
                crate::types::AttributeMutation::Set
            } else {
                crate::types::AttributeMutation::Clear
            },
        );
        if link_policy == crate::types::SymlinkFollowPolicy::PreserveFinalLink {
            attrs.insert(FileAttributeFlags::REPARSE_POINT);
        }
        if meta.permissions().readonly() {
            attrs.insert(FileAttributeFlags::READ_ONLY);
        }
        if name.starts_with('.') && !is_dir {
            attrs.insert(FileAttributeFlags::HIDDEN);
        }
        let epoch_secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(DEFAULT_VFS_EPOCH_SECS, |d| d.as_secs());
        VfsMetadata {
            name,
            short_name,
            full_path: win_path.clone(),
            attributes: attrs,
            size: if is_dir { 0 } else { meta.len() },
            modified_timestamp: FileTimestamp::from_epoch_secs(epoch_secs),
        }
    }
}

/// Lexically resolves `.` and `..` components on a host [`Path`] and canonicalizes its deepest
/// existing ancestor prefix so dangling symlinks under OS-aliased roots (such as macOS
/// `/var` -> `/private/var`) compare accurately against canonicalized sandbox roots.
///
/// # Arguments
/// * `path` - Host [`Path`] to normalize.
///
/// # Returns
/// Canonicalized-prefix [`PathBuf`].
pub(super) fn normalize_lexical_host_path(path: &Path) -> PathBuf {
    let mut lex = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                lex.pop();
            }
            std::path::Component::Prefix(_)
            | std::path::Component::RootDir
            | std::path::Component::Normal(_) => lex.push(comp.as_os_str()),
        }
    }
    let mut tail_comps = Vec::new();
    let mut probe = lex.as_path();
    while let Some(parent) = probe.parent() {
        if let Ok(canon) = std::fs::canonicalize(probe) {
            let mut joined = canon;
            for tc in tail_comps.into_iter().rev() {
                joined.push(tc);
            }
            return joined;
        }
        tail_comps.extend(probe.file_name().map(std::ffi::OsStr::to_os_string));
        probe = parent;
    }
    lex
}

/// Recursively checks whether any entry beneath `dir_host` has OS-level `readonly` permissions.
///
/// # Arguments
/// * `dir_host` - Host directory path to inspect.
///
/// # Returns
/// `true` if `dir_host` or any non-symlink descendant has `readonly()` set.
#[must_use]
pub(super) fn has_host_os_readonly_recursive(dir_host: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir_host) else {
        return false;
    };
    for entry in rd.filter_map(Result::ok) {
        let is_sym = entry.file_type().is_ok_and(|ft| ft.is_symlink());
        if is_sym {
            continue;
        }
        if entry.metadata().is_ok_and(|meta| {
            meta.permissions().readonly()
                || (meta.is_dir() && has_host_os_readonly_recursive(&entry.path()))
        }) {
            return true;
        }
    }
    false
}

/// Removes a host file or symlink (falling back to `remove_dir` for directory symlinks on Windows).
///
/// # Arguments
/// * `host_p` - Host filesystem path to remove.
///
/// # Returns
/// `Ok(())` on removal or the underlying [`std::io::Error`].
///
/// # Errors
/// Returns [`std::io::Error`] if the underlying OS removal call fails.
fn remove_host_file_or_symlink(host_p: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        std::fs::remove_file(host_p).or_else(|_| std::fs::remove_dir(host_p))
    }
    #[cfg(not(windows))]
    {
        std::fs::remove_file(host_p)
    }
}

impl VirtualFileSystem for HostOsVfs {
    /// Returns the currently active [`DriveLetter`].
    ///
    /// # Returns
    /// The active [`DriveLetter`].
    fn current_drive(&self) -> DriveLetter {
        self.inner.current_drive()
    }

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
    fn set_current_drive(&mut self, drive: DriveLetter) -> Result<(), CmdError> {
        if self.drive_roots.contains_key(&drive) {
            self.inner.active_drive = drive;
            Ok(())
        } else {
            Err(CmdError::DriveNotFound { drive })
        }
    }

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
    fn drive_cwd(&self, drive: DriveLetter) -> Result<WindowsPath, CmdError> {
        let comps = self
            .inner
            .drive_cwds
            .get(&drive)
            .ok_or(CmdError::DriveNotFound { drive })?;
        Ok(WindowsPath {
            drive,
            unc_prefix: None,
            components: comps.clone(),
        })
    }

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
    fn set_drive_cwd(&mut self, path: &WindowsPath) -> Result<(), CmdError> {
        let raw_win = path.to_windows_string();
        let mount_root = self.mount_root_for(path, &raw_win)?.clone();
        let host_p = Self::to_host_path_from_base(&mount_root, &path.components);
        self.verify_sandbox_containment_against(&mount_root, &host_p, &raw_win)?;
        if !host_p.is_dir() {
            return Err(CmdError::PathNotFound { path: raw_win });
        }
        if path.unc_prefix.is_none() {
            self.inner
                .drive_cwds
                .insert(path.drive, path.components.clone());
        }
        Ok(())
    }

    /// Resolves any raw Windows path string against the VFS's active drive and per-drive CWDs.
    ///
    /// # Arguments
    /// * `raw` - Raw path string.
    ///
    /// # Returns
    /// Canonicalized [`WindowsPath`].
    fn resolve_path(&self, raw: &str) -> WindowsPath {
        self.inner.resolve_path(raw)
    }

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
    fn volume_info(&self, drive: DriveLetter) -> Result<VolumeInfo, CmdError> {
        if !self.drive_roots.contains_key(&drive) {
            return Err(CmdError::DriveNotFound { drive });
        }
        self.inner.volume_info(drive)
    }

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
    fn stat(&self, raw_path: &str) -> Result<VfsMetadata, CmdError> {
        if let Some((parent_opt, dev)) = DosDevice::split_path_device(raw_path) {
            if let Some(parent_raw) = parent_opt {
                let (_, host_parent) = self.resolve_checked_host_path(parent_raw)?;
                if !host_parent.is_dir() {
                    return Err(CmdError::PathNotFound {
                        path: raw_path.to_owned(),
                    });
                }
            }
            return Ok(VfsMetadata {
                name: dev.to_string(),
                short_name: dev.to_string(),
                full_path: WindowsPath::root(self.current_drive()).join_component(&dev.to_string()),
                attributes: FileAttributeFlags::default_file(),
                size: 0,
                modified_timestamp: self.inner.default_timestamp,
            });
        }

        let (win_path, host_p) = self.resolve_checked_host_path(raw_path)?;
        let sym_meta = map_io_res(std::fs::symlink_metadata(&host_p), raw_path, "stat")?;
        let is_symlink = sym_meta.file_type().is_symlink();
        let meta = std::fs::metadata(&host_p).unwrap_or(sym_meta);
        let (leaf, short) = if win_path.components.is_empty() {
            (String::new(), String::new())
        } else {
            let l = host_p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_owned();
            let s = Self::compute_host_dir_short_name(host_p.parent().unwrap_or(&host_p), &l);
            (l, s)
        };
        let lp = if is_symlink {
            crate::types::SymlinkFollowPolicy::PreserveFinalLink
        } else {
            crate::types::SymlinkFollowPolicy::FollowFinalTarget
        };
        Ok(self.metadata_from_host(&win_path, leaf, short, &meta, lp))
    }

    /// Checks whether a path or wildcard pattern matches at least one existing entry (`IF EXIST`).
    ///
    /// Supports the `IF EXIST "C:\dir\NUL"` directory-existence idiom.
    ///
    /// # Arguments
    /// * `raw_pattern` - Path or wildcard pattern.
    ///
    /// # Returns
    /// `true` if at least one matching file, directory, or valid device path exists.
    fn exists(&self, raw_pattern: &str) -> bool {
        if DosDevice::split_path_device(raw_pattern).is_some() {
            return self.stat(raw_pattern).is_ok();
        }
        let path = self.resolve_path(raw_pattern);
        path.file_name()
            .filter(|l| glob::contains_wildcards(l))
            .map_or_else(
                || self.stat(raw_pattern).is_ok(),
                |leaf| {
                    let parent = path.parent();
                    self.read_dir(&parent.to_windows_string())
                        .is_ok_and(|entries| {
                            entries.iter().any(|entry| {
                                matches_win32_glob(
                                    leaf,
                                    &entry.name,
                                    Some(&entry.short_name),
                                    CaseSensitivity::Insensitive,
                                )
                            })
                        })
                },
            )
    }

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
    fn read_bytes(&self, raw_path: &str) -> Result<Vec<u8>, CmdError> {
        if DosDevice::split_path_device(raw_path).is_some() {
            self.ensure_exists(raw_path)?;
            return Ok(Vec::new());
        }
        let (_, host_p) = self.resolve_checked_host_path(raw_path)?;
        if host_p.is_dir() {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        map_io_res(std::fs::read(&host_p), raw_path, "read")
    }

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
    fn write_bytes(&mut self, raw_path: &str, data: &[u8]) -> Result<(), CmdError> {
        if DosDevice::split_path_device(raw_path).is_some() {
            self.ensure_exists(raw_path)?;
            return Ok(());
        }
        let (win_path, host_p) = self.resolve_checked_host_path(raw_path)?;
        if win_path.components.is_empty() {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        let parent = win_path.parent();
        let mount_root = self.mount_root_for(&parent, raw_path)?;
        let host_parent = Self::to_host_path_from_base(mount_root, &parent.components);
        self.verify_sandbox_containment_against(mount_root, &host_parent, raw_path)?;
        if !host_parent.is_dir() {
            return Err(CmdError::PathNotFound {
                path: raw_path.to_owned(),
            });
        }
        let key = self.sidecar_key(&win_path);
        if self
            .attr_sidecar
            .get(&key)
            .is_some_and(|a| a.is_read_only())
        {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        if host_p.is_dir() {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        map_io_res(std::fs::write(&host_p, data), raw_path, "write")
    }

    /// Appends `data` to `raw_path` using streaming `O(1)` OS `append(true)` file I/O.
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
    fn append_bytes(&mut self, raw_path: &str, data: &[u8]) -> Result<(), CmdError> {
        if DosDevice::split_path_device(raw_path).is_some() {
            self.ensure_exists(raw_path)?;
            return Ok(());
        }
        let (win_path, host_p) = self.resolve_checked_host_path(raw_path)?;
        if win_path.components.is_empty() {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        let parent = win_path.parent();
        let mount_root = self.mount_root_for(&parent, raw_path)?;
        let host_parent = Self::to_host_path_from_base(mount_root, &parent.components);
        self.verify_sandbox_containment_against(mount_root, &host_parent, raw_path)?;
        if !host_parent.is_dir() {
            return Err(CmdError::PathNotFound {
                path: raw_path.to_owned(),
            });
        }
        let key = self.sidecar_key(&win_path);
        if self
            .attr_sidecar
            .get(&key)
            .is_some_and(|a| a.is_read_only())
        {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        if host_p.is_dir() {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        let mut file = map_io_res(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&host_p),
            raw_path,
            "append",
        )?;
        map_io_res(file.write_all(data), raw_path, "append")
    }

    /// Deletes a single file or file symbolic link at `raw_path`.
    ///
    /// # Arguments
    /// * `raw_path` - File path to delete.
    /// * `access_mode` - [`crate::types::ReadOnlyDeletePolicy`] (`RespectReadOnly` vs `ForceDeleteReadOnly`).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn delete_file(
        &mut self,
        raw_path: &str,
        access_mode: crate::types::ReadOnlyDeletePolicy,
    ) -> Result<(), CmdError> {
        let win_path = self.resolve_path(raw_path);
        let mount_root = self.mount_root_for(&win_path, raw_path)?.clone();
        let host_p = Self::to_host_path_from_base(&mount_root, &win_path.components);
        self.verify_sandbox_containment_against(
            &mount_root,
            host_p.parent().unwrap_or(&host_p),
            raw_path,
        )?;

        let key = self.sidecar_key(&win_path);
        let is_ro = self
            .attr_sidecar
            .get(&key)
            .is_some_and(|a| a.is_read_only());
        if access_mode == crate::types::ReadOnlyDeletePolicy::RespectReadOnly && is_ro {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        if host_p.is_dir() && !host_p.is_symlink() {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        map_io_res(
            remove_host_file_or_symlink(&host_p),
            raw_path,
            "delete_file",
        )?;
        self.attr_sidecar.remove(&key);
        Ok(())
    }

    /// Creates a directory (and optionally all missing parent directories when `parent_mode` is `CreateParents`).
    ///
    /// # Arguments
    /// * `raw_path` - Directory path to create.
    /// * `parent_mode` - [`crate::types::DirCreationDepth`] (`ImmediateParentOnly` vs `CreateParents`).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`], [`CmdError::FileAlreadyExists`], [`CmdError::PathNotFound`],
    /// or [`CmdError::AccessDenied`].
    fn create_dir(
        &mut self,
        raw_path: &str,
        parent_mode: crate::types::DirCreationDepth,
    ) -> Result<(), CmdError> {
        let (_, host_p) = self.resolve_checked_host_path(raw_path)?;
        if host_p.exists() || host_p.is_symlink() {
            return Err(CmdError::FileAlreadyExists {
                path: raw_path.to_owned(),
            });
        }
        let res = if parent_mode == crate::types::DirCreationDepth::CreateParents {
            std::fs::create_dir_all(&host_p)
        } else {
            std::fs::create_dir(&host_p)
        };
        map_io_res(res, raw_path, "create_dir")
    }

    /// Removes a directory or directory junction/symlink (`RD` / `RMDIR`).
    ///
    /// # Arguments
    /// * `raw_path` - Directory path to remove.
    /// * `removal_mode` - [`crate::types::DirRemovalMode`] (`EmptyOnly` vs `RecursiveSubtree`).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::DirectoryNotEmpty`], [`CmdError::SharingViolation`],
    /// [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn remove_dir(
        &mut self,
        raw_path: &str,
        removal_mode: crate::types::DirRemovalMode,
    ) -> Result<(), CmdError> {
        let win_path = self.resolve_path(raw_path);
        if win_path.components.is_empty() {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        let mount_root = self.mount_root_for(&win_path, raw_path)?.clone();
        let host_p = Self::to_host_path_from_base(&mount_root, &win_path.components);
        self.verify_sandbox_containment_against(
            &mount_root,
            host_p.parent().unwrap_or(&host_p),
            raw_path,
        )?;

        let key = self.sidecar_key(&win_path);
        let is_sym = host_p.is_symlink();
        if !host_p.is_dir() && !is_sym {
            return Err(CmdError::PathNotFound {
                path: raw_path.to_owned(),
            });
        }
        if self.inner.is_active_cwd_or_ancestor(&key) {
            return Err(CmdError::SharingViolation {
                path: raw_path.to_owned(),
            });
        }
        if is_sym {
            map_io_res(remove_host_file_or_symlink(&host_p), raw_path, "remove_dir")?;
            self.attr_sidecar.remove(&key);
            return Ok(());
        }
        self.verify_sandbox_containment_against(&mount_root, &host_p, raw_path)?;
        if self
            .attr_sidecar
            .get(&key)
            .is_some_and(|a| a.is_read_only())
        {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        if removal_mode == crate::types::DirRemovalMode::RecursiveSubtree
            && self.has_readonly_descendant(&key, &host_p)
        {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        let res = if removal_mode == crate::types::DirRemovalMode::RecursiveSubtree {
            std::fs::remove_dir_all(&host_p)
        } else {
            std::fs::remove_dir(&host_p)
        };
        map_io_res(res, raw_path, "remove_dir")?;
        self.attr_sidecar
            .retain(|(r, comps), _| !(r == &key.0 && comps.starts_with(&key.1)));
        Ok(())
    }

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
    fn read_dir(&self, raw_dir_path: &str) -> Result<Vec<VfsMetadata>, CmdError> {
        let (dir_path, host_dir) = self.resolve_checked_host_path(raw_dir_path)?;
        let mount_root = self.mount_root_for(&dir_path, raw_dir_path)?.clone();
        let rd = map_io_res(std::fs::read_dir(&host_dir), raw_dir_path, "read_dir")?;
        let mut raw_items: Vec<(String, std::fs::Metadata, bool)> = rd
            .filter_map(Result::ok)
            .filter_map(|e| {
                let is_sym = e.file_type().is_ok_and(|ft| ft.is_symlink());
                let resolved_meta = if is_sym
                    && self
                        .verify_sandbox_containment_against(&mount_root, &e.path(), raw_dir_path)
                        .is_err()
                {
                    e.metadata().ok()
                } else {
                    std::fs::metadata(e.path())
                        .ok()
                        .or_else(|| e.metadata().ok())
                };
                e.file_name()
                    .into_string()
                    .ok()
                    .zip(resolved_meta)
                    .map(|(n, m)| (n, m, is_sym))
            })
            .collect();
        raw_items.sort_by_key(|(n, _, _)| fold_win32_case(n));

        let mut results = Vec::with_capacity(raw_items.len());
        let mut base_counts: BTreeMap<String, u8> = BTreeMap::new();
        for (name, meta, is_sym) in raw_items {
            let base_short = generate_short_name_8_3(&name, 1);
            let next_col = base_counts
                .get(&base_short)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            base_counts.insert(base_short, next_col);
            let short = generate_short_name_8_3(&name, next_col);
            let child_win = dir_path.join_component(&name);
            let lp = if is_sym {
                crate::types::SymlinkFollowPolicy::PreserveFinalLink
            } else {
                crate::types::SymlinkFollowPolicy::FollowFinalTarget
            };
            results.push(self.metadata_from_host(&child_win, name, short, &meta, lp));
        }
        Ok(results)
    }

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
    ) -> Result<(), CmdError> {
        let meta = self.stat(raw_path)?;
        let key = self.sidecar_key(&meta.full_path);
        let mut updated = attributes;
        updated.set_flag(
            FileAttributeFlags::DIRECTORY,
            if meta.attributes.is_directory() {
                crate::types::AttributeMutation::Set
            } else {
                crate::types::AttributeMutation::Clear
            },
        );
        self.attr_sidecar.insert(key, updated);
        Ok(())
    }

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
    fn free_disk_space(&self, drive: DriveLetter) -> Result<u64, CmdError> {
        if self.drive_roots.contains_key(&drive) {
            self.inner.free_disk_space(drive)
        } else {
            Err(CmdError::DriveNotFound { drive })
        }
    }

    /// Atomically moves or renames a file or directory (`REN` and `MOVE`), keeping `attr_sidecar` synchronized.
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
    /// [`CmdError::SharingViolation`], [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn move_entry(&mut self, src_raw: &str, dst_raw: &str) -> Result<(), CmdError> {
        let (src_win, src_host) = self.resolve_checked_host_path(src_raw)?;
        let (dst_win, dst_host) = self.resolve_checked_host_path(dst_raw)?;
        if !src_host.exists() && !src_host.is_symlink() {
            return Err(CmdError::FileNotFound {
                path: src_raw.to_owned(),
            });
        }
        let dst_parent = dst_win.parent();
        let dst_mount_root = self.mount_root_for(&dst_parent, dst_raw)?.clone();
        let dst_parent_host = Self::to_host_path_from_base(&dst_mount_root, &dst_parent.components);
        self.verify_sandbox_containment_against(&dst_mount_root, &dst_parent_host, dst_raw)?;
        if !dst_parent_host.is_dir() {
            return Err(CmdError::PathNotFound {
                path: dst_raw.to_owned(),
            });
        }

        let src_key = self.sidecar_key(&src_win);
        let dst_key = self.sidecar_key(&dst_win);
        let src_is_real_dir = src_host.is_dir() && !src_host.is_symlink();
        if src_is_real_dir {
            if dst_key.0 == src_key.0 && dst_key.1.starts_with(&src_key.1) && dst_key != src_key {
                return Err(CmdError::AccessDenied {
                    path: dst_raw.to_owned(),
                });
            }
            if self.inner.is_active_cwd_or_ancestor(&src_key) {
                return Err(CmdError::SharingViolation {
                    path: src_raw.to_owned(),
                });
            }
        }
        if dst_host.exists() && (dst_host.is_dir() || src_host.is_dir()) && src_host != dst_host {
            return Err(CmdError::FileAlreadyExists {
                path: dst_raw.to_owned(),
            });
        }
        map_io_res(std::fs::rename(&src_host, &dst_host), src_raw, "move_entry")?;

        if src_key != dst_key {
            self.attr_sidecar.remove(&dst_key);
            if src_is_real_dir {
                let prefix_len = src_key.1.len();
                let moved_attrs: Vec<(VfsKey, FileAttributeFlags)> = self
                    .attr_sidecar
                    .iter()
                    .filter(|((r, comps), _)| r == &src_key.0 && comps.starts_with(&src_key.1))
                    .map(|(k, &v)| (k.clone(), v))
                    .collect();
                for (old_k, _) in &moved_attrs {
                    self.attr_sidecar.remove(old_k);
                }
                for ((_, old_comps), attrs) in moved_attrs {
                    let mut new_comps = dst_key.1.clone();
                    new_comps.extend_from_slice(old_comps.get(prefix_len..).unwrap_or(&[]));
                    self.attr_sidecar
                        .insert((dst_key.0.clone(), new_comps), attrs);
                }
            } else if let Some(attrs) = self.attr_sidecar.remove(&src_key) {
                self.attr_sidecar.insert(dst_key, attrs);
            }
        }
        Ok(())
    }

    /// Creates a symbolic link or directory junction (`MKLINK`, `MKLINK /D`, `MKLINK /J`),
    /// resolving relative link targets against `link_raw`'s parent directory while enforcing sandbox bounds.
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
    ) -> Result<(), CmdError> {
        let (link_win, link_host) = self.resolve_checked_host_path(link_raw)?;
        if link_win.components.is_empty() {
            return Err(CmdError::AccessDenied {
                path: link_raw.to_owned(),
            });
        }
        let link_parent = link_win.parent();
        let link_mount_root = self.mount_root_for(&link_parent, link_raw)?.clone();
        let link_parent_host =
            Self::to_host_path_from_base(&link_mount_root, &link_parent.components);
        if !link_parent_host.is_dir() {
            return Err(CmdError::PathNotFound {
                path: link_raw.to_owned(),
            });
        }
        if link_host.exists() || link_host.is_symlink() {
            return Err(CmdError::FileAlreadyExists {
                path: link_raw.to_owned(),
            });
        }

        let trimmed_target = target_raw.trim().trim_matches('"');
        let t_bytes = trimmed_target.as_bytes();
        let has_drive = t_bytes.len() >= 2
            && t_bytes.first().is_some_and(u8::is_ascii_alphabetic)
            && t_bytes.get(1) == Some(&b':');
        let is_rooted_or_unc = trimmed_target.starts_with([BS_CHAR, '/']);

        let symlink_payload: PathBuf = if has_drive || is_rooted_or_unc {
            let (_, abs_target_host) = self.resolve_checked_host_path(trimmed_target)?;
            abs_target_host
        } else {
            let sep = std::path::MAIN_SEPARATOR;
            let rel_os: String = trimmed_target
                .chars()
                .map(|c| if c == BS_CHAR || c == '/' { sep } else { c })
                .collect();
            if self.containment == SandboxContainment::Contained {
                let canon_root = normalize_lexical_host_path(&link_mount_root);
                let resolved_target_host = link_parent_host.join(&rel_os);
                let canon_target = normalize_lexical_host_path(&resolved_target_host);
                if !canon_target.starts_with(&canon_root) {
                    return Err(CmdError::AccessDenied {
                        path: target_raw.to_owned(),
                    });
                }
            }
            PathBuf::from(rel_os)
        };

        let _is_dir = matches!(
            kind,
            MklinkKind::DirectorySymlink | MklinkKind::DirectoryJunction
        );
        #[cfg(unix)]
        {
            map_io_res(
                std::os::unix::fs::symlink(&symlink_payload, &link_host),
                link_raw,
                "create_symlink",
            )?;
        }
        #[cfg(windows)]
        {
            let res = if _is_dir {
                std::os::windows::fs::symlink_dir(&symlink_payload, &link_host)
            } else {
                std::os::windows::fs::symlink_file(&symlink_payload, &link_host)
            };
            map_io_res(res, link_raw, "create_symlink")?;
        }

        let mut attrs = self
            .stat(link_raw)
            .map(|m| m.attributes)
            .unwrap_or_default();
        attrs.insert(FileAttributeFlags::REPARSE_POINT);
        self.set_attributes(link_raw, attrs)
    }

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
    fn create_hardlink(&mut self, link_raw: &str, target_raw: &str) -> Result<(), CmdError> {
        let (link_win, link_host) = self.resolve_checked_host_path(link_raw)?;
        let (_, target_host) = self.resolve_checked_host_path(target_raw)?;
        if !target_host.is_file() {
            return Err(CmdError::FileNotFound {
                path: target_raw.to_owned(),
            });
        }
        let link_parent = link_win.parent();
        let mount_root = self.mount_root_for(&link_parent, link_raw)?;
        let link_parent_host = Self::to_host_path_from_base(mount_root, &link_parent.components);
        if !link_parent_host.is_dir() {
            return Err(CmdError::PathNotFound {
                path: link_raw.to_owned(),
            });
        }
        map_io_res(
            std::fs::hard_link(&target_host, &link_host),
            link_raw,
            "create_hardlink",
        )
    }

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
    fn touch_file(&mut self, raw_path: &str, new_timestamp: FileTimestamp) -> Result<(), CmdError> {
        let (_, host_p) = self.resolve_checked_host_path(raw_path)?;
        let file = map_io_res(
            std::fs::OpenOptions::new().write(true).open(&host_p),
            raw_path,
            "touch_file",
        )?;
        let modified_time = std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(new_timestamp.epoch_secs()))
            .unwrap_or_else(std::time::SystemTime::now);
        let times = std::fs::FileTimes::new().set_modified(modified_time);
        map_io_res(file.set_times(times), raw_path, "touch_file")
    }

    /// Allocates and mounts the highest unused drive letter (`Z:` downward to `A:`) for a configured
    /// UNC share (`PUSHD \\server\share`), failing with [`CmdError::NetworkPathNotFound`] if the
    /// UNC share is not mounted on [`HostOsVfs`] rather than aliasing onto `C:`.
    ///
    /// # Arguments
    /// * `unc_share` - UNC share root (`\\server\share`).
    /// * `sub_components` - Optional subdirectory components under the share.
    ///
    /// # Returns
    /// `Ok(DriveLetter)` of the newly mounted temporary drive.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidUncPath`], [`CmdError::NetworkPathNotFound`], or [`CmdError::PathNotFound`].
    fn mount_unc_drive(
        &mut self,
        unc_share: &str,
        sub_components: &[String],
    ) -> Result<DriveLetter, CmdError> {
        let share_win = self.resolve_path(unc_share);
        let share_host_root = self.mount_root_for(&share_win, unc_share)?.clone();
        if !sub_components.is_empty() {
            let sub_host = Self::to_host_path_from_base(&share_host_root, sub_components);
            if !sub_host.is_dir() {
                return Err(CmdError::PathNotFound {
                    path: unc_share.to_owned(),
                });
            }
        }
        let Some((srv, shr)) = &share_win.unc_prefix else {
            return Err(CmdError::InvalidUncPath {
                raw: unc_share.to_owned(),
            });
        };
        let server_folded = CaseFoldedString::new(srv);
        let share_folded = CaseFoldedString::new(shr);
        for byte in (b'A'..=b'Z').rev() {
            let candidate = DriveLetter::try_from_char(char::from(byte)).unwrap_or(DriveLetter::Z);
            if let std::collections::btree_map::Entry::Vacant(vacant) =
                self.drive_roots.entry(candidate)
            {
                vacant.insert(share_host_root);
                self.inner
                    .unc_drive_aliases
                    .insert(candidate, (server_folded, share_folded));
                self.inner
                    .drive_cwds
                    .insert(candidate, sub_components.to_vec());
                self.inner.volumes.insert(
                    candidate,
                    VolumeInfo {
                        label: unc_share.to_owned(),
                        serial_number: "9U8N-7C6S".to_owned(),
                    },
                );
                self.inner.drive_free_space.insert(candidate, 100_000_000);
                return Ok(candidate);
            }
        }
        Err(CmdError::PathNotFound {
            path: unc_share.to_owned(),
        })
    }

    /// Unmounts a temporary drive letter previously allocated by `mount_unc_drive` (`POPD`).
    ///
    /// # Arguments
    /// * `drive` - The temporary [`DriveLetter`] to unmount.
    fn unmount_drive(&mut self, drive: DriveLetter) {
        self.drive_roots.remove(&drive);
        self.inner.unmount_drive(drive);
    }

    /// Translates a resolved [`WindowsPath`] to a real host [`crate::types::NativeBackingPath`] if backed by a mounted drive or UNC share.
    ///
    /// # Arguments
    /// * `win_path` - Resolved [`WindowsPath`].
    ///
    /// # Returns
    /// `Some(NativeBackingPath)` if `win_path`'s drive or UNC share is mounted, or `None` otherwise.
    fn resolve_host_path(&self, win_path: &WindowsPath) -> Option<crate::types::NativeBackingPath> {
        let base = self.mount_root_for(win_path, "").ok()?;
        Some(crate::types::NativeBackingPath::from_path_buf(
            Self::to_host_path_from_base(base, &win_path.components),
        ))
    }

    /// Configures the simulated free disk space (in bytes) for `drive` on [`InMemoryVfs`] or [`HostOsVfs`].
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    /// * `bytes` - Free space in bytes.
    fn set_drive_free_space(&mut self, drive: DriveLetter, bytes: u64) {
        self.inner.set_drive_free_space(drive, bytes);
    }

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
    fn sync_host_cwd(&self, binding_mode: HostBindingMode) -> Result<(), CmdError> {
        if binding_mode.is_isolated() {
            return Ok(());
        }
        let d = self.current_drive();
        let comps = self.inner.drive_cwds.get(&d).cloned().unwrap_or_default();
        let win_cwd = WindowsPath {
            drive: d,
            unc_prefix: None,
            components: comps,
        };
        let raw_win = win_cwd.to_windows_string();
        let mount_root = self.mount_root_for(&win_cwd, &raw_win)?;
        let host_cwd = Self::to_host_path_from_base(mount_root, &win_cwd.components);
        self.verify_sandbox_containment_against(mount_root, &host_cwd, &raw_win)?;
        map_io_res((self.cwd_sync_fn)(&host_cwd), &raw_win, "set_current_dir")
    }

    /// Clones this VFS state into a boxed trait object.
    ///
    /// # Returns
    /// A boxed clone of this [`VirtualFileSystem`].
    fn clone_box(&self) -> Box<dyn VirtualFileSystem> {
        Box::new(self.clone())
    }
}
