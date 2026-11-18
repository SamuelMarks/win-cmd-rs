//! MS-DOS FAT12/FAT16/FAT32 and DOS 7 LFN [`VirtualFileSystem`] backend over [`DosKernelApi`].

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::dos::{
    DosKernelApi, DosStatRecord, DosWriteDisposition, FatAttributeByte, PackedDosTimestamp,
};
use crate::error::CmdError;
use crate::types::{
    BS_CHAR, BS_STR, CaseSensitivity, DirCreationDepth, DirRemovalMode, DriveLetter,
    HostBindingMode, MklinkKind, NativeBackingPath, ReadOnlyDeletePolicy, VerifyCopyMode,
    fold_win32_case,
};
use crate::vfs::devices::DosDevice;
use crate::vfs::glob::{self, matches_win32_glob};
use crate::vfs::path::{WindowsPath, resolve_windows_path};
use crate::vfs::traits::{
    CaseFoldedString, FileAttributeFlags, FileTimestamp, VfsMetadata, VirtualFileSystem, VolumeInfo,
};

/// Temporary `PUSHD` network drive alias mapping an allocated [`DriveLetter`] to a mapped DOS drive root.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PushdDosAlias {
    /// Underlying DOS redirector [`DriveLetter`] (e.g., `F:`).
    backing_drive: DriveLetter,
    /// Relative working directory stack on the aliased drive.
    cwd_components: Vec<String>,
    /// UNC display label reported by `VOL` / `DIR` (e.g., `\SERVER\SHARE`).
    unc_label: String,
}

/// Translated MS-DOS kernel target produced from a [`WindowsPath`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct DosTargetPath {
    /// Backing MS-DOS [`DriveLetter`].
    backing_drive: DriveLetter,
    /// Anchored path components on `backing_drive`.
    components: Vec<String>,
    /// Formatted MS-DOS kernel path (`C:` or `C:\DIR\FILE.EXT`).
    dos_path: String,
}

/// Safe `#![no_std]` MS-DOS FAT12/16/32 and LFN [`VirtualFileSystem`] backed by any [`DosKernelApi`].
///
/// Works identically over [`crate::dos::SimulatedDosKernel`] in host tests and over real DJGPP
/// `INT 21h` / DPMI calls in `crates/wincmd-dos`.
#[derive(Debug, Clone)]
pub struct DosFatVfs<K: DosKernelApi + Clone + 'static> {
    /// Underlying safe MS-DOS kernel implementation.
    kernel: K,
    /// Active VFS drive letter (tracks both physical DOS drives and temporary `PUSHD` aliases).
    active_drive: DriveLetter,
    /// Optional MS-DOS network redirector mappings (`(\SERVER, SHARE)` -> `DriveLetter`, e.g. `NET USE F:`).
    unc_redirects: BTreeMap<(CaseFoldedString, CaseFoldedString), DriveLetter>,
    /// Temporary `PUSHD \server\share` drive aliases (`Z:` downward to `A:`).
    pushd_aliases: BTreeMap<DriveLetter, PushdDosAlias>,
    /// Optional per-drive free-space overrides set via [`VirtualFileSystem::set_drive_free_space`].
    free_space_overrides: BTreeMap<DriveLetter, u64>,
}

impl<K: DosKernelApi + Clone + 'static> DosFatVfs<K> {
    /// Wraps `kernel` in a new [`DosFatVfs`] synchronized to `kernel.current_drive()`.
    ///
    /// # Arguments
    /// * `kernel` - Initialized [`DosKernelApi`] implementation.
    ///
    /// # Returns
    /// Initialized [`DosFatVfs`].
    #[must_use]
    pub fn new(kernel: K) -> Self {
        let active_drive = kernel.current_drive();
        Self {
            kernel,
            active_drive,
            unc_redirects: BTreeMap::new(),
            pushd_aliases: BTreeMap::new(),
            free_space_overrides: BTreeMap::new(),
        }
    }

    /// Borrows the underlying [`DosKernelApi`] immutably.
    ///
    /// # Returns
    /// Reference to `K`.
    #[must_use]
    pub const fn kernel(&self) -> &K {
        &self.kernel
    }

    /// Borrows the underlying [`DosKernelApi`] mutably.
    ///
    /// # Returns
    /// Mutable reference to `K`.
    pub const fn kernel_mut(&mut self) -> &mut K {
        &mut self.kernel
    }

    /// Consumes this [`DosFatVfs`] and returns the inner [`DosKernelApi`].
    ///
    /// # Returns
    /// Owned `K`.
    #[must_use]
    pub fn into_kernel(self) -> K {
        self.kernel
    }

    /// Registers an MS-DOS network redirector drive mapping (`NET USE F: \server\share`).
    ///
    /// # Arguments
    /// * `server` - UNC server hostname.
    /// * `share` - UNC share name.
    /// * `drive` - Mounted DOS redirector [`DriveLetter`].
    pub fn map_unc_redirector(&mut self, server: &str, share: &str, drive: DriveLetter) {
        self.unc_redirects.insert(
            (CaseFoldedString::new(server), CaseFoldedString::new(share)),
            drive,
        );
    }

    /// Copies a single file from `src_raw` to `dst_raw`, setting `ARCHIVE` on the destination and
    /// honoring `verify_mode` via [`DosKernelApi::set_verify_flag`].
    ///
    /// # Arguments
    /// * `src_raw` - Source file path.
    /// * `dst_raw` - Destination file path.
    /// * `verify_mode` - [`VerifyCopyMode`] (`Verified` enables `INT 21h AH=2Eh` write-verify).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading `src_raw` or writing `dst_raw` fails.
    pub fn copy_file(
        &mut self,
        src_raw: &str,
        dst_raw: &str,
        verify_mode: VerifyCopyMode,
    ) -> Result<(), CmdError> {
        let bytes = self.read_bytes(src_raw)?;
        let prev_verify = self.kernel.verify_flag();
        self.kernel.set_verify_flag(verify_mode);
        let write_res = self.write_bytes(dst_raw, &bytes);
        self.kernel.set_verify_flag(prev_verify);
        write_res?;
        if DosDevice::split_path_device(dst_raw).is_none() {
            let dst_win = self.resolve_path(dst_raw);
            let dst_target = self.to_dos_target(&dst_win, dst_raw)?;
            let cur_attrs = self.kernel.get_attributes(&dst_target.dos_path)?;
            let mut vfs_flags = cur_attrs.to_vfs_flags();
            vfs_flags.insert(FileAttributeFlags::ARCHIVE);
            self.kernel.set_attributes(
                &dst_target.dos_path,
                FatAttributeByte::from_vfs_flags(vfs_flags),
            )?;
        }
        Ok(())
    }

    /// Formats `(drive, components)` into an MS-DOS kernel path (`C:` or `C:\DIR\FILE`).
    ///
    /// # Arguments
    /// * `drive` - Backing [`DriveLetter`].
    /// * `components` - Anchored path segments.
    ///
    /// # Returns
    /// Canonical MS-DOS path string.
    #[must_use]
    fn format_dos_path(drive: DriveLetter, components: &[String]) -> String {
        if components.is_empty() {
            format!("{}:{BS_STR}", drive.as_char())
        } else {
            format!("{}:{BS_STR}{}", drive.as_char(), components.join(BS_STR))
        }
    }

    /// Parses a DOS CWD string (`C:\DOS\BIN`) into path components (`["DOS", "BIN"]`).
    ///
    /// # Arguments
    /// * `raw_cwd` - Kernel CWD string.
    ///
    /// # Returns
    /// Component vector.
    #[must_use]
    fn parse_dos_cwd_components(raw_cwd: &str) -> Vec<String> {
        let stripped = raw_cwd
            .get(2..)
            .filter(|_| raw_cwd.as_bytes().get(1) == Some(&b':'))
            .unwrap_or(raw_cwd);
        stripped
            .split([BS_CHAR, '/'])
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    }

    /// Translates a resolved [`WindowsPath`] into a validated [`DosTargetPath`].
    ///
    /// # Arguments
    /// * `win_path` - Resolved [`WindowsPath`].
    /// * `raw_path` - Original path string for diagnostics.
    ///
    /// # Returns
    /// `Ok(DosTargetPath)` on valid physical or redirector drives.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidUncPath`], [`CmdError::NetworkPathNotFound`], or [`CmdError::DriveNotFound`].
    fn to_dos_target(
        &self,
        win_path: &WindowsPath,
        raw_path: &str,
    ) -> Result<DosTargetPath, CmdError> {
        if win_path.is_invalid_unc() {
            return Err(CmdError::InvalidUncPath {
                raw: raw_path.to_owned(),
            });
        }
        if let Some((srv, shr)) = &win_path.unc_prefix {
            let key = (CaseFoldedString::new(srv), CaseFoldedString::new(shr));
            let Some(&redir_drive) = self.unc_redirects.get(&key) else {
                return Err(CmdError::NetworkPathNotFound {
                    path: raw_path.to_owned(),
                });
            };
            if !self.kernel.is_drive_valid(redir_drive) {
                return Err(CmdError::DriveNotFound { drive: redir_drive });
            }
            let components = win_path.components.clone();
            let dos_path = Self::format_dos_path(redir_drive, &components);
            return Ok(DosTargetPath {
                backing_drive: redir_drive,
                components,
                dos_path,
            });
        }
        if let Some(alias) = self.pushd_aliases.get(&win_path.drive) {
            if !self.kernel.is_drive_valid(alias.backing_drive) {
                return Err(CmdError::DriveNotFound {
                    drive: alias.backing_drive,
                });
            }
            let components = win_path.components.clone();
            let dos_path = Self::format_dos_path(alias.backing_drive, &components);
            return Ok(DosTargetPath {
                backing_drive: alias.backing_drive,
                components,
                dos_path,
            });
        }
        if !self.kernel.is_drive_valid(win_path.drive) {
            return Err(CmdError::DriveNotFound {
                drive: win_path.drive,
            });
        }
        let components = win_path.components.clone();
        let dos_path = Self::format_dos_path(win_path.drive, &components);
        Ok(DosTargetPath {
            backing_drive: win_path.drive,
            components,
            dos_path,
        })
    }

    /// Converts a [`DosStatRecord`] and resolved [`WindowsPath`] into [`VfsMetadata`].
    ///
    /// # Arguments
    /// * `win_path` - Resolved [`WindowsPath`] preserving logical drive/UNC prefix.
    /// * `rec` - Kernel [`DosStatRecord`].
    ///
    /// # Returns
    /// `Ok(VfsMetadata)`.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if `rec.modified` holds a corrupted packed FAT date/time.
    fn record_to_metadata(
        win_path: &WindowsPath,
        rec: DosStatRecord,
    ) -> Result<VfsMetadata, CmdError> {
        let modified_timestamp = rec.modified.to_file_timestamp()?;
        let mut full_components = win_path.components.clone();
        if let Some(last) = full_components.last_mut() {
            last.clone_from(&rec.name);
        }
        let full_path = WindowsPath {
            drive: win_path.drive,
            unc_prefix: win_path.unc_prefix.clone(),
            components: full_components,
        };
        Ok(VfsMetadata {
            name: rec.name,
            short_name: rec.short_name,
            full_path,
            attributes: rec.attributes.to_vfs_flags(),
            size: rec.size,
            modified_timestamp,
        })
    }

    /// Checks whether `(backing_drive, canonical_dos_path)` is the active CWD or an ancestor of any
    /// mounted physical or `PUSHD`-aliased drive's CWD.
    ///
    /// # Arguments
    /// * `backing_drive` - Physical [`DriveLetter`].
    /// * `canonical_dos` - Canonical uppercase DOS path from `truename` (`C:\WORK`).
    ///
    /// # Returns
    /// `true` if deleting or moving `canonical_dos` would invalidate an active CWD.
    fn is_cwd_or_ancestor(&self, backing_drive: DriveLetter, canonical_dos: &str) -> bool {
        let prefix = fold_win32_case(canonical_dos.trim_end_matches(BS_CHAR));
        let drv_cwd = self.kernel.drive_cwd(backing_drive).unwrap_or_default();
        let cwd_up = fold_win32_case(drv_cwd.trim_end_matches(BS_CHAR));
        if Self::is_same_or_descendant_dos_path(&cwd_up, &prefix) {
            return true;
        }
        for alias in self.pushd_aliases.values() {
            if alias.backing_drive == backing_drive {
                let alias_dos = Self::format_dos_path(alias.backing_drive, &alias.cwd_components);
                let canon_alias = self.kernel.truename(&alias_dos).unwrap_or(alias_dos);
                let alias_up = fold_win32_case(canon_alias.trim_end_matches(BS_CHAR));
                if Self::is_same_or_descendant_dos_path(&alias_up, &prefix) {
                    return true;
                }
            }
        }
        false
    }

    /// Returns `true` when `candidate` equals `ancestor` or lies strictly beneath `ancestor`.
    ///
    /// # Arguments
    /// * `candidate` - Uppercase DOS path without trailing backslash.
    /// * `ancestor` - Uppercase ancestor DOS path without trailing backslash.
    ///
    /// # Returns
    /// `true` if `candidate` is `ancestor` or a descendant of `ancestor`.
    #[must_use]
    fn is_same_or_descendant_dos_path(candidate: &str, ancestor: &str) -> bool {
        candidate == ancestor
            || (candidate.starts_with(ancestor)
                && candidate.as_bytes().get(ancestor.len()) == Some(&0x5C))
    }

    /// Recursively verifies that neither `dir_dos` nor any descendant carries `READ_ONLY`.
    ///
    /// # Arguments
    /// * `dir_dos` - Target DOS directory path.
    /// * `raw_path` - User diagnostic path.
    ///
    /// # Returns
    /// `Ok(())` when all descendants are writable.
    ///
    /// # Errors
    /// Returns [`CmdError::AccessDenied`] if any entry in the subtree is marked `READ_ONLY`.
    fn verify_no_readonly_in_subtree(&self, dir_dos: &str, raw_path: &str) -> Result<(), CmdError> {
        let children = self.kernel.read_dir_entries(dir_dos)?;
        for child in children {
            if child.attributes.is_read_only() {
                return Err(CmdError::AccessDenied {
                    path: raw_path.to_owned(),
                });
            }
            if child.attributes.is_directory() {
                let child_dos = format!(
                    "{}{BS_STR}{}",
                    dir_dos.trim_end_matches(BS_CHAR),
                    child.name
                );
                self.verify_no_readonly_in_subtree(&child_dos, raw_path)?;
            }
        }
        Ok(())
    }

    /// Recursively deletes all files and subdirectories inside `dir_dos` followed by `dir_dos` itself.
    ///
    /// # Arguments
    /// * `dir_dos` - Target DOS directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if any child deletion or `remove_dir` fails.
    fn delete_dir_subtree_bottom_up(&mut self, dir_dos: &str) -> Result<(), CmdError> {
        let children = self.kernel.read_dir_entries(dir_dos)?;
        let base = dir_dos.trim_end_matches(BS_CHAR);
        for child in children {
            let child_dos = format!("{base}{BS_STR}{}", child.name);
            if child.attributes.is_directory() {
                self.delete_dir_subtree_bottom_up(&child_dos)?;
            } else {
                self.kernel.delete_file(&child_dos)?;
            }
        }
        self.kernel.remove_dir(dir_dos)
    }

    /// Recursively copies `src_dos` (`src_stat`) to `dst_dos` across DOS drives, preserving timestamps and FAT attributes.
    ///
    /// # Arguments
    /// * `src_dos` - Source DOS path.
    /// * `src_stat` - Source [`DosStatRecord`].
    /// * `dst_dos` - Destination DOS path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading, creating, or setting metadata fails.
    fn copy_tree_preserving_metadata(
        &mut self,
        src_dos: &str,
        src_stat: &DosStatRecord,
        dst_dos: &str,
    ) -> Result<(), CmdError> {
        if src_stat.attributes.is_directory() {
            self.kernel.create_dir(dst_dos)?;
            let children = self.kernel.read_dir_entries(src_dos)?;
            let src_base = src_dos.trim_end_matches(BS_CHAR);
            let dst_base = dst_dos.trim_end_matches(BS_CHAR);
            for child in children {
                let child_src = format!("{src_base}{BS_STR}{}", child.name);
                let child_dst = format!("{dst_base}{BS_STR}{}", child.name);
                let child_stat = DosStatRecord {
                    name: child.name,
                    short_name: child.short_name,
                    attributes: child.attributes,
                    size: child.size,
                    modified: child.modified,
                };
                self.copy_tree_preserving_metadata(&child_src, &child_stat, &child_dst)?;
            }
        } else {
            let data = self.kernel.read_file_bytes(src_dos)?;
            self.kernel
                .write_file_bytes(dst_dos, &data, DosWriteDisposition::CreateTruncate)?;
        }
        self.kernel.set_timestamp(dst_dos, src_stat.modified)?;
        self.kernel.set_attributes(dst_dos, src_stat.attributes)
    }

    /// Prepares destination path for `move_entry`, validating overwrite and ancestor constraints.
    ///
    /// # Arguments
    /// * `src_target` - Source [`DosTargetPath`].
    /// * `src_stat` - Source [`DosStatRecord`].
    /// * `dst_target` - Destination [`DosTargetPath`].
    /// * `src_raw` - Original source path string.
    /// * `dst_raw` - Original destination path string.
    ///
    /// # Returns
    /// `Ok(true)` when `src` and `dst` resolve to the exact same canonical DOS path (no-op).
    ///
    /// # Errors
    /// Returns [`CmdError`] on cyclic directory move, active CWD conflict, or illegal overwrite.
    fn validate_and_prepare_move_dst(
        &mut self,
        src_target: &DosTargetPath,
        src_stat: &DosStatRecord,
        dst_target: &DosTargetPath,
        src_raw: &str,
        dst_raw: &str,
    ) -> Result<bool, CmdError> {
        let src_canon = fold_win32_case(&self.kernel.truename(&src_target.dos_path)?);
        let dst_canon = fold_win32_case(&self.kernel.truename(&dst_target.dos_path)?);
        if src_canon == dst_canon {
            return Ok(true);
        }
        if src_stat.attributes.is_directory() {
            if Self::is_same_or_descendant_dos_path(
                dst_canon.trim_end_matches(BS_CHAR),
                src_canon.trim_end_matches(BS_CHAR),
            ) {
                return Err(CmdError::AccessDenied {
                    path: dst_raw.to_owned(),
                });
            }
            if self.is_cwd_or_ancestor(src_target.backing_drive, &src_canon) {
                return Err(CmdError::SharingViolation {
                    path: src_raw.to_owned(),
                });
            }
        }
        let dst_parent_dos = Self::format_dos_path(
            dst_target.backing_drive,
            dst_target
                .components
                .split_last()
                .map_or(&[], |(_, parents)| parents),
        );
        let parent_stat =
            self.kernel
                .stat_entry(&dst_parent_dos)
                .map_err(|_e| CmdError::PathNotFound {
                    path: dst_raw.to_owned(),
                })?;
        if !parent_stat.attributes.is_directory() {
            return Err(CmdError::PathNotFound {
                path: dst_raw.to_owned(),
            });
        }
        if let Ok(dst_existing) = self.kernel.stat_entry(&dst_target.dos_path) {
            if src_stat.attributes.is_directory() || dst_existing.attributes.is_directory() {
                return Err(CmdError::FileAlreadyExists {
                    path: dst_raw.to_owned(),
                });
            }
            if dst_existing.attributes.is_read_only() {
                return Err(CmdError::AccessDenied {
                    path: dst_raw.to_owned(),
                });
            }
            self.kernel.delete_file(&dst_target.dos_path)?;
        }
        Ok(false)
    }
}

impl<K: DosKernelApi + Clone + 'static> VirtualFileSystem for DosFatVfs<K> {
    /// Returns the currently active [`DriveLetter`].
    ///
    /// # Returns
    /// Active [`DriveLetter`].
    fn current_drive(&self) -> DriveLetter {
        self.active_drive
    }

    /// Switches the active [`DriveLetter`] if mounted on the DOS kernel or aliased via `PUSHD`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] if `drive` is neither mounted nor aliased.
    fn set_current_drive(&mut self, drive: DriveLetter) -> Result<(), CmdError> {
        if let Some(alias) = self.pushd_aliases.get(&drive) {
            self.kernel.set_current_drive(alias.backing_drive)?;
            self.active_drive = drive;
            return Ok(());
        }
        self.kernel.set_current_drive(drive)?;
        self.active_drive = drive;
        Ok(())
    }

    /// Queries the current working directory [`WindowsPath`] for `drive`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(WindowsPath)`.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] or [`CmdError::IoFailure`] (`DriveNotReady`).
    fn drive_cwd(&self, drive: DriveLetter) -> Result<WindowsPath, CmdError> {
        if let Some(alias) = self.pushd_aliases.get(&drive) {
            return Ok(WindowsPath {
                drive,
                unc_prefix: None,
                components: alias.cwd_components.clone(),
            });
        }
        if !self.kernel.is_drive_valid(drive) {
            return Err(CmdError::DriveNotFound { drive });
        }
        let raw_cwd = self.kernel.drive_cwd(drive)?;
        Ok(WindowsPath {
            drive,
            unc_prefix: None,
            components: Self::parse_dos_cwd_components(&raw_cwd),
        })
    }

    /// Updates the current working directory for `path.drive` after verifying directory existence.
    ///
    /// # Arguments
    /// * `path` - Resolved [`WindowsPath`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`], [`CmdError::PathNotFound`], or [`CmdError::NetworkPathNotFound`].
    fn set_drive_cwd(&mut self, path: &WindowsPath) -> Result<(), CmdError> {
        let win_str = path.to_windows_string();
        let target = self.to_dos_target(path, &win_str)?;
        let rec = self.kernel.stat_entry(&target.dos_path).map_err(|err| {
            if let CmdError::FileNotFound { path: p } = err {
                CmdError::PathNotFound { path: p }
            } else {
                err
            }
        })?;
        if !rec.attributes.is_directory() {
            return Err(CmdError::PathNotFound { path: win_str });
        }
        if path.unc_prefix.is_none()
            && let Some(alias) = self.pushd_aliases.get_mut(&path.drive)
        {
            let canon = self.kernel.truename(&target.dos_path)?;
            alias.cwd_components = Self::parse_dos_cwd_components(&canon);
            return Ok(());
        }
        self.kernel.set_drive_cwd(&target.dos_path)
    }

    /// Resolves `raw` against `self.active_drive` and per-drive working directories.
    ///
    /// # Arguments
    /// * `raw` - Raw Windows/DOS path string.
    ///
    /// # Returns
    /// Canonical [`WindowsPath`].
    fn resolve_path(&self, raw: &str) -> WindowsPath {
        resolve_windows_path(raw, self.active_drive, |d| {
            self.drive_cwd(d).map(|p| p.components).unwrap_or_default()
        })
    }

    /// Returns volume label and serial number for `drive`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(VolumeInfo)`.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] or [`CmdError::IoFailure`].
    fn volume_info(&self, drive: DriveLetter) -> Result<VolumeInfo, CmdError> {
        if let Some(alias) = self.pushd_aliases.get(&drive) {
            let (_, serial_number) = self.kernel.volume_label_and_serial(alias.backing_drive)?;
            return Ok(VolumeInfo {
                label: alias.unc_label.clone(),
                serial_number,
            });
        }
        let (label, serial_number) = self.kernel.volume_label_and_serial(drive)?;
        Ok(VolumeInfo {
            label,
            serial_number,
        })
    }

    /// Queries metadata for `raw_path`, intercepting MS-DOS character devices (`NUL`, `CON`, `C:\DIR\NUL`, etc.).
    ///
    /// # Arguments
    /// * `raw_path` - Raw or resolved path string.
    ///
    /// # Returns
    /// `Ok(VfsMetadata)`.
    ///
    /// # Errors
    /// Returns [`CmdError`] when the target or device parent directory does not exist.
    fn stat(&self, raw_path: &str) -> Result<VfsMetadata, CmdError> {
        if let Some((parent_opt, dev)) = DosDevice::split_path_device(raw_path) {
            if let Some(parent_raw) = parent_opt {
                let parent_meta = self.stat(parent_raw).map_err(|err| {
                    if matches!(err, CmdError::FileNotFound { .. }) {
                        CmdError::PathNotFound {
                            path: raw_path.to_owned(),
                        }
                    } else {
                        err
                    }
                })?;
                if !parent_meta.attributes.is_directory() {
                    return Err(CmdError::PathNotFound {
                        path: raw_path.to_owned(),
                    });
                }
            }
            let ts = self.kernel.current_datetime().unwrap_or_default();
            return Ok(VfsMetadata {
                name: dev.to_string(),
                short_name: dev.to_string(),
                full_path: WindowsPath::root(self.active_drive).join_component(&dev.to_string()),
                attributes: FileAttributeFlags::default_file(),
                size: 0,
                modified_timestamp: ts,
            });
        }
        let win_path = self.resolve_path(raw_path);
        let target = self.to_dos_target(&win_path, raw_path)?;
        let rec = self.kernel.stat_entry(&target.dos_path)?;
        Self::record_to_metadata(&win_path, rec)
    }

    /// Evaluates `IF EXIST` against files, directories, DOS devices (`C:\DIR\NUL`), and Win32/DOS wildcards.
    ///
    /// # Arguments
    /// * `raw_pattern` - Path or wildcard pattern.
    ///
    /// # Returns
    /// `true` if at least one matching entry exists.
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

    /// Reads raw bytes from `raw_path` (returning empty `Vec` for valid DOS devices like `NUL`).
    ///
    /// # Arguments
    /// * `raw_path` - Source path.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)`.
    ///
    /// # Errors
    /// Returns [`CmdError`] on missing file, directory target, or I/O error.
    fn read_bytes(&self, raw_path: &str) -> Result<Vec<u8>, CmdError> {
        if DosDevice::split_path_device(raw_path).is_some() {
            self.ensure_exists(raw_path)?;
            return Ok(Vec::new());
        }
        let win_path = self.resolve_path(raw_path);
        let target = self.to_dos_target(&win_path, raw_path)?;
        self.kernel.read_file_bytes(&target.dos_path)
    }

    /// Writes `data` to `raw_path`, truncating or creating the file (or discarding on DOS devices).
    ///
    /// # Arguments
    /// * `raw_path` - Destination path.
    /// * `data` - Byte slice to write.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] on `READ_ONLY` target, directory target, missing parent, or disk write-protect.
    fn write_bytes(&mut self, raw_path: &str, data: &[u8]) -> Result<(), CmdError> {
        if DosDevice::split_path_device(raw_path).is_some() {
            self.ensure_exists(raw_path)?;
            return Ok(());
        }
        let win_path = self.resolve_path(raw_path);
        let target = self.to_dos_target(&win_path, raw_path)?;
        self.kernel
            .write_file_bytes(&target.dos_path, data, DosWriteDisposition::CreateTruncate)
    }

    /// Appends `data` to `raw_path`, creating the file if absent (or discarding on DOS devices).
    ///
    /// # Arguments
    /// * `raw_path` - Destination path.
    /// * `data` - Byte slice to append.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] on `READ_ONLY` target, directory target, or I/O failure.
    fn append_bytes(&mut self, raw_path: &str, data: &[u8]) -> Result<(), CmdError> {
        if DosDevice::split_path_device(raw_path).is_some() {
            self.ensure_exists(raw_path)?;
            return Ok(());
        }
        let win_path = self.resolve_path(raw_path);
        let target = self.to_dos_target(&win_path, raw_path)?;
        self.kernel
            .write_file_bytes(&target.dos_path, data, DosWriteDisposition::CreateOrAppend)
    }

    /// Deletes a regular file at `raw_path`, clearing `READ_ONLY` first when `ForceDeleteReadOnly` is set.
    ///
    /// # Arguments
    /// * `raw_path` - File path to delete.
    /// * `access_mode` - [`ReadOnlyDeletePolicy`].
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
    ) -> Result<(), CmdError> {
        let win_path = self.resolve_path(raw_path);
        let target = self.to_dos_target(&win_path, raw_path)?;
        if access_mode == ReadOnlyDeletePolicy::ForceDeleteReadOnly {
            let attrs = self.kernel.get_attributes(&target.dos_path)?;
            if !attrs.is_directory() && attrs.is_read_only() {
                let cleared = FatAttributeByte(attrs.raw() & !FatAttributeByte::READ_ONLY.raw());
                self.kernel.set_attributes(&target.dos_path, cleared)?;
            }
        }
        self.kernel.delete_file(&target.dos_path)
    }

    /// Creates a directory at `raw_path` honoring `ImmediateParentOnly` (`/E:OFF`) and `CreateParents` (`/E:ON`).
    ///
    /// # Arguments
    /// * `raw_path` - Directory path to create.
    /// * `parent_mode` - [`DirCreationDepth`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileAlreadyExists`], [`CmdError::PathNotFound`], or [`CmdError::AccessDenied`].
    fn create_dir(
        &mut self,
        raw_path: &str,
        parent_mode: DirCreationDepth,
    ) -> Result<(), CmdError> {
        let win_path = self.resolve_path(raw_path);
        let target = self.to_dos_target(&win_path, raw_path)?;
        if target.components.is_empty() || self.kernel.stat_entry(&target.dos_path).is_ok() {
            return Err(CmdError::FileAlreadyExists {
                path: raw_path.to_owned(),
            });
        }
        match parent_mode {
            DirCreationDepth::ImmediateParentOnly => self.kernel.create_dir(&target.dos_path),
            DirCreationDepth::CreateParents => {
                let mut prefix = Vec::with_capacity(target.components.len());
                for comp in &target.components {
                    prefix.push(comp.clone());
                    let step_dos = Self::format_dos_path(target.backing_drive, &prefix);
                    if let Ok(existing) = self.kernel.stat_entry(&step_dos) {
                        if !existing.attributes.is_directory() {
                            return Err(CmdError::FileAlreadyExists { path: step_dos });
                        }
                    } else {
                        self.kernel.create_dir(&step_dos)?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Removes an empty or recursive directory tree (`RD` / `RD /S`), protecting active CWDs and `READ_ONLY` entries.
    ///
    /// # Arguments
    /// * `raw_path` - Directory path to remove.
    /// * `removal_mode` - [`DirRemovalMode`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::DirectoryNotEmpty`], [`CmdError::SharingViolation`],
    /// or [`CmdError::AccessDenied`].
    fn remove_dir(&mut self, raw_path: &str, removal_mode: DirRemovalMode) -> Result<(), CmdError> {
        let win_path = self.resolve_path(raw_path);
        let target = self.to_dos_target(&win_path, raw_path)?;
        if target.components.is_empty() {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        let rec = self.kernel.stat_entry(&target.dos_path).map_err(|err| {
            if let CmdError::FileNotFound { path: p } = err {
                CmdError::PathNotFound { path: p }
            } else {
                err
            }
        })?;
        if !rec.attributes.is_directory() {
            return Err(CmdError::PathNotFound {
                path: raw_path.to_owned(),
            });
        }
        let canon = self.kernel.truename(&target.dos_path)?;
        if self.is_cwd_or_ancestor(target.backing_drive, &canon) {
            return Err(CmdError::SharingViolation {
                path: raw_path.to_owned(),
            });
        }
        if rec.attributes.is_read_only() {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        match removal_mode {
            DirRemovalMode::EmptyOnly => self.kernel.remove_dir(&target.dos_path),
            DirRemovalMode::RecursiveSubtree => {
                self.verify_no_readonly_in_subtree(&target.dos_path, raw_path)?;
                self.delete_dir_subtree_bottom_up(&target.dos_path)
            }
        }
    }

    /// Enumerates immediate child entries inside `raw_dir_path`, sorted case-insensitively by name.
    ///
    /// # Arguments
    /// * `raw_dir_path` - Directory path to enumerate.
    ///
    /// # Returns
    /// `Ok(Vec<VfsMetadata>)`.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`] or [`CmdError::IoFailure`].
    fn read_dir(&self, raw_dir_path: &str) -> Result<Vec<VfsMetadata>, CmdError> {
        let dir_win = self.resolve_path(raw_dir_path);
        let target = self.to_dos_target(&dir_win, raw_dir_path)?;
        let entries = self.kernel.read_dir_entries(&target.dos_path)?;
        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            let modified_timestamp = entry.modified.to_file_timestamp()?;
            let full_path = dir_win.join_component(&entry.name);
            results.push(VfsMetadata {
                name: entry.name,
                short_name: entry.short_name,
                full_path,
                attributes: entry.attributes.to_vfs_flags(),
                size: entry.size,
                modified_timestamp,
            });
        }
        results.sort_by_key(|a| fold_win32_case(&a.name));
        Ok(results)
    }

    /// Updates FAT file/directory attributes (`R`, `H`, `S`, `A`) via `INT 21h AX=4301h`.
    ///
    /// # Arguments
    /// * `raw_path` - Target path.
    /// * `attributes` - New [`FileAttributeFlags`].
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
        let win_path = self.resolve_path(raw_path);
        let target = self.to_dos_target(&win_path, raw_path)?;
        self.kernel.set_attributes(
            &target.dos_path,
            FatAttributeByte::from_vfs_flags(attributes),
        )
    }

    /// Queries free disk space in bytes on `drive` (`INT 21h AH=36h` / `AX=7303h`).
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(u64)` free bytes.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] or [`CmdError::IoFailure`].
    fn free_disk_space(&self, drive: DriveLetter) -> Result<u64, CmdError> {
        if let Some(&override_bytes) = self.free_space_overrides.get(&drive) {
            return Ok(override_bytes);
        }
        let real_drive = self
            .pushd_aliases
            .get(&drive)
            .map_or(drive, |a| a.backing_drive);
        self.kernel.volume_space(real_drive).map(|s| s.free_bytes)
    }

    /// Moves or renames `src_raw` to `dst_raw` using atomic `rename_entry` on the same DOS drive and
    /// copy + attribute/timestamp preservation + deletion across drives (`C:` -> `D:`).
    ///
    /// # Arguments
    /// * `src_raw` - Source file or directory path.
    /// * `dst_raw` - Destination file or directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] on missing source, cyclic directory move, active CWD conflict, or I/O error.
    fn move_entry(&mut self, src_raw: &str, dst_raw: &str) -> Result<(), CmdError> {
        let src_win = self.resolve_path(src_raw);
        let dst_win = self.resolve_path(dst_raw);
        let src_target = self.to_dos_target(&src_win, src_raw)?;
        let dst_target = self.to_dos_target(&dst_win, dst_raw)?;
        if src_target.components.is_empty() || dst_target.components.is_empty() {
            return Err(CmdError::AccessDenied {
                path: dst_raw.to_owned(),
            });
        }
        let src_stat = self.kernel.stat_entry(&src_target.dos_path)?;
        if self.validate_and_prepare_move_dst(
            &src_target,
            &src_stat,
            &dst_target,
            src_raw,
            dst_raw,
        )? {
            return Ok(());
        }
        if src_target.backing_drive == dst_target.backing_drive {
            return self
                .kernel
                .rename_entry(&src_target.dos_path, &dst_target.dos_path);
        }
        if src_stat.attributes.is_directory() {
            self.verify_no_readonly_in_subtree(&src_target.dos_path, src_raw)?;
        } else if src_stat.attributes.is_read_only() {
            return Err(CmdError::AccessDenied {
                path: src_raw.to_owned(),
            });
        }
        self.copy_tree_preserving_metadata(&src_target.dos_path, &src_stat, &dst_target.dos_path)?;
        if src_stat.attributes.is_directory() {
            self.delete_dir_subtree_bottom_up(&src_target.dos_path)
        } else {
            self.kernel.delete_file(&src_target.dos_path)
        }
    }

    /// Explicitly rejects NTFS symbolic links and directory junctions on MS-DOS FAT volumes.
    ///
    /// # Arguments
    /// * `_link_raw` - Requested link path.
    /// * `_target_raw` - Requested target path.
    /// * `_kind` - [`MklinkKind`].
    ///
    /// # Returns
    /// Always returns `Err(CmdError::UnsupportedOperation)`.
    ///
    /// # Errors
    /// Always returns [`CmdError::UnsupportedOperation`].
    fn create_symlink(
        &mut self,
        _link_raw: &str,
        _target_raw: &str,
        _kind: MklinkKind,
    ) -> Result<(), CmdError> {
        Err(CmdError::UnsupportedOperation {
            operation:
                "MKLINK symbolic links and junctions are not supported on MS-DOS FAT volumes"
                    .to_owned(),
        })
    }

    /// Explicitly rejects NTFS hard links (`MKLINK /H`) on MS-DOS FAT volumes.
    ///
    /// # Arguments
    /// * `_link_raw` - Requested link path.
    /// * `_target_raw` - Existing target file path.
    ///
    /// # Returns
    /// Always returns `Err(CmdError::UnsupportedOperation)`.
    ///
    /// # Errors
    /// Always returns [`CmdError::UnsupportedOperation`].
    fn create_hardlink(&mut self, _link_raw: &str, _target_raw: &str) -> Result<(), CmdError> {
        Err(CmdError::UnsupportedOperation {
            operation: "MKLINK /H hard links are not supported on MS-DOS FAT volumes".to_owned(),
        })
    }

    /// Updates the FAT modification timestamp of an existing file (`COPY file + ,,`).
    ///
    /// # Arguments
    /// * `raw_path` - Target file path.
    /// * `new_timestamp` - Updated [`FileTimestamp`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`] or [`CmdError::AccessDenied`].
    fn touch_file(&mut self, raw_path: &str, new_timestamp: FileTimestamp) -> Result<(), CmdError> {
        let win_path = self.resolve_path(raw_path);
        let target = self.to_dos_target(&win_path, raw_path)?;
        let dos_ts = PackedDosTimestamp::from_file_timestamp(new_timestamp);
        self.kernel.set_timestamp(&target.dos_path, dos_ts)
    }

    /// Mounts a temporary drive letter (`Z:`..`A:`) for `PUSHD \server\share` when mapped to a DOS redirector drive.
    ///
    /// # Arguments
    /// * `unc_share` - UNC share root (`\server\share`).
    /// * `sub_components` - Optional subdirectory components under the share.
    ///
    /// # Returns
    /// `Ok(DriveLetter)` of the allocated alias drive.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidUncPath`], [`CmdError::NetworkPathNotFound`], or [`CmdError::PathNotFound`].
    fn mount_unc_drive(
        &mut self,
        unc_share: &str,
        sub_components: &[String],
    ) -> Result<DriveLetter, CmdError> {
        let share_win = self.resolve_path(unc_share);
        if share_win.is_invalid_unc() || share_win.unc_prefix.is_none() {
            return Err(CmdError::InvalidUncPath {
                raw: unc_share.to_owned(),
            });
        }
        let target = self.to_dos_target(&share_win, unc_share)?;
        let sub_dos = Self::format_dos_path(target.backing_drive, sub_components);
        let sub_stat = self
            .kernel
            .stat_entry(&sub_dos)
            .map_err(|_e| CmdError::PathNotFound {
                path: unc_share.to_owned(),
            })?;
        if !sub_stat.attributes.is_directory() {
            return Err(CmdError::PathNotFound {
                path: unc_share.to_owned(),
            });
        }
        for cand in DriveLetter::ALL_DESCENDING {
            if !self.kernel.is_drive_valid(cand) && !self.pushd_aliases.contains_key(&cand) {
                self.pushd_aliases.insert(
                    cand,
                    PushdDosAlias {
                        backing_drive: target.backing_drive,
                        cwd_components: sub_components.to_vec(),
                        unc_label: unc_share.to_owned(),
                    },
                );
                return Ok(cand);
            }
        }
        Err(CmdError::PathNotFound {
            path: unc_share.to_owned(),
        })
    }

    /// Unmounts a temporary `PUSHD` drive alias (`POPD`).
    ///
    /// # Arguments
    /// * `drive` - Temporary [`DriveLetter`] to unmount.
    fn unmount_drive(&mut self, drive: DriveLetter) {
        self.pushd_aliases.remove(&drive);
    }

    /// Translates `win_path` to a [`NativeBackingPath`] (`C:\DIR\APP.EXE`) when backed by a valid DOS drive.
    ///
    /// # Arguments
    /// * `win_path` - Resolved [`WindowsPath`].
    ///
    /// # Returns
    /// `Some(NativeBackingPath)` when backed by a mounted DOS or redirector drive, else `None`.
    fn resolve_host_path(&self, win_path: &WindowsPath) -> Option<NativeBackingPath> {
        let target = self.to_dos_target(win_path, "").ok()?;
        let canonical = self
            .kernel
            .truename(&target.dos_path)
            .unwrap_or(target.dos_path);
        Some(NativeBackingPath::from_string(&canonical))
    }

    /// Records a free-space override in bytes for `drive`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    /// * `bytes` - Simulated free disk space in bytes.
    fn set_drive_free_space(&mut self, drive: DriveLetter, bytes: u64) {
        self.free_space_overrides.insert(drive, bytes);
    }

    /// Synchronizes the DOS kernel's active drive and CWD when `binding_mode` is `Synchronized`.
    ///
    /// # Arguments
    /// * `binding_mode` - [`HostBindingMode`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] only if querying the active drive's CWD fails.
    fn sync_host_cwd(&self, binding_mode: HostBindingMode) -> Result<(), CmdError> {
        if binding_mode == HostBindingMode::Synchronized {
            let _cwd = self.drive_cwd(self.active_drive)?;
        }
        Ok(())
    }

    /// Clones this [`DosFatVfs`] into a boxed [`VirtualFileSystem`] trait object.
    ///
    /// # Returns
    /// Boxed clone of `self`.
    fn clone_box(&self) -> Box<dyn VirtualFileSystem> {
        Box::new(self.clone())
    }
}
