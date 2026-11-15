//! Deterministic in-memory multi-drive and UNC-share [`VirtualFileSystem`] implementation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::error::CmdError;
use crate::types::{
    BS_CHAR, CaseSensitivity, DriveLetter, HostBindingMode, MklinkKind, fold_win32_case,
};
use crate::vfs::devices::DosDevice;
use crate::vfs::glob::{self, matches_win32_glob};
use crate::vfs::path::{WindowsPath, generate_short_name_8_3, resolve_windows_path};
use crate::vfs::traits::{
    CaseFoldedString, DEFAULT_VFS_EPOCH_SECS, DirEntry, FileAttributeFlags, FileTimestamp, InodeId,
    MAX_SYMLINK_HOPS, VfsKey, VfsMetadata, VfsRoot, VirtualFileSystem, VolumeInfo,
};

/// Underlying storage kind of an [`InMemoryInode`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum InodePayload {
    /// Regular file holding a mutable byte buffer (shared across hard links).
    RegularFile {
        /// Raw file bytes.
        content: Vec<u8>,
    },
    /// Directory container node.
    Directory,
    /// Symbolic link or directory junction storing an unexpanded target path string.
    ReparsePoint {
        /// Target path string as passed to `MKLINK`.
        target: String,
        /// Link flavor (`FileSymlink`, `DirectorySymlink`, or `DirectoryJunction`).
        kind: MklinkKind,
    },
}

/// Shared inode record inside [`InMemoryVfs`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct InMemoryInode {
    /// File or directory attribute flags.
    attributes: FileAttributeFlags,
    /// Last-modified chronological timestamp.
    modified_timestamp: FileTimestamp,
    /// File, directory, or reparse-point payload.
    payload: InodePayload,
}

/// Deterministic in-memory multi-drive and UNC-share [`VirtualFileSystem`] implementation.
#[derive(Debug, Clone)]
pub struct InMemoryVfs {
    /// Currently active drive letter.
    pub(super) active_drive: DriveLetter,
    /// Per-drive current working directory component stacks (`C:` -> `["Users", "Default"]`).
    pub(super) drive_cwds: BTreeMap<DriveLetter, Vec<String>>,
    /// Per-drive volume info.
    pub(super) volumes: BTreeMap<DriveLetter, VolumeInfo>,
    /// Per-drive configurable free space in bytes.
    pub(super) drive_free_space: BTreeMap<DriveLetter, u64>,
    /// Temporary `PUSHD` UNC drive aliases mapping an allocated drive letter (`Z:`..`A:`) to `(server, share)`.
    pub(super) unc_drive_aliases: BTreeMap<DriveLetter, (CaseFoldedString, CaseFoldedString)>,
    /// Directory tree mapping `(VfsRoot, Vec<UPPERCASE>)` to [`DirEntry`].
    entries: BTreeMap<VfsKey, DirEntry>,
    /// Inode table keyed by [`InodeId`], enabling true shared hardlinks.
    inodes: BTreeMap<InodeId, InMemoryInode>,
    /// Next available [`InodeId`] counter.
    next_inode_id: u64,
    /// Default timestamp assigned to created/modified files.
    pub(super) default_timestamp: FileTimestamp,
}

impl Default for InMemoryVfs {
    /// Creates a default [`InMemoryVfs`] with `C:` and `D:` drives mounted.
    ///
    /// # Returns
    /// Default [`InMemoryVfs`].
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryVfs {
    /// Creates a zero-allocation unmounted [`InMemoryVfs`] placeholder used for transient
    /// zero-copy VFS handoff across subshells.
    ///
    /// # Returns
    /// An empty [`InMemoryVfs`] with zero heap allocations.
    #[must_use]
    pub const fn unmounted_placeholder() -> Self {
        Self {
            active_drive: DriveLetter::C,
            drive_cwds: BTreeMap::new(),
            volumes: BTreeMap::new(),
            drive_free_space: BTreeMap::new(),
            unc_drive_aliases: BTreeMap::new(),
            entries: BTreeMap::new(),
            inodes: BTreeMap::new(),
            next_inode_id: 1,
            default_timestamp: FileTimestamp::from_epoch_secs(DEFAULT_VFS_EPOCH_SECS),
        }
    }

    /// Creates a new [`InMemoryVfs`] with `C:` and `D:` drives mounted and `C:` as active root.
    ///
    /// # Returns
    /// An initialized [`InMemoryVfs`].
    #[must_use]
    pub fn new() -> Self {
        let mut vfs = Self::unmounted_placeholder();

        vfs.mount_empty_drive(DriveLetter::C, "Windows", "1A2B-3C4D");
        vfs.mount_empty_drive(DriveLetter::D, "Data", "5E6F-7A8B");
        vfs
    }

    /// Allocates a new [`InodeId`] and inserts `inode` into `self.inodes`.
    ///
    /// # Arguments
    /// * `inode` - [`InMemoryInode`] to store.
    ///
    /// # Returns
    /// Newly allocated [`InodeId`].
    fn alloc_inode(&mut self, inode: InMemoryInode) -> InodeId {
        let id = InodeId(self.next_inode_id);
        self.next_inode_id = self.next_inode_id.saturating_add(1);
        self.inodes.insert(id, inode);
        id
    }

    /// Mounts a fresh empty drive root onto `drive` with volume metadata.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to mount.
    /// * `label` - Volume label string.
    /// * `serial` - Volume serial string.
    pub fn mount_empty_drive(&mut self, drive: DriveLetter, label: &str, serial: &str) {
        self.drive_cwds.insert(drive, Vec::new());
        self.volumes.insert(
            drive,
            VolumeInfo {
                label: label.to_owned(),
                serial_number: serial.to_owned(),
            },
        );
        self.drive_free_space.insert(drive, 100_000_000);
        let root_inode = self.alloc_inode(InMemoryInode {
            attributes: FileAttributeFlags::default_dir(),
            modified_timestamp: self.default_timestamp,
            payload: InodePayload::Directory,
        });
        self.entries.insert(
            (VfsRoot::Drive(drive), Vec::new()),
            DirEntry {
                name: String::new(),
                short_name: String::new(),
                inode_id: root_inode,
            },
        );
    }

    /// Ensures that a [`VfsRoot::Unc`] share has a root directory entry in `self.entries`.
    ///
    /// # Arguments
    /// * `root` - Target [`VfsRoot`].
    fn ensure_unc_share_root(&mut self, root: &VfsRoot) {
        if matches!(root, VfsRoot::Unc { .. }) {
            let root_key = (root.clone(), Vec::new());
            if !self.entries.contains_key(&root_key) {
                let id = self.alloc_inode(InMemoryInode {
                    attributes: FileAttributeFlags::default_dir(),
                    modified_timestamp: self.default_timestamp,
                    payload: InodePayload::Directory,
                });
                self.entries.insert(
                    root_key,
                    DirEntry {
                        name: String::new(),
                        short_name: String::new(),
                        inode_id: id,
                    },
                );
            }
        }
    }

    /// Garbage-collects any inodes from `candidate_ids` that are no longer referenced by `self.entries`.
    ///
    /// # Arguments
    /// * `candidate_ids` - Slice of [`InodeId`]s whose directory links were just removed.
    fn gc_unreferenced_inodes(&mut self, candidate_ids: &[InodeId]) {
        let live: BTreeSet<InodeId> = self.entries.values().map(|e| e.inode_id).collect();
        for id in candidate_ids {
            if !live.contains(id) {
                self.inodes.remove(id);
            }
        }
    }

    /// Resolves the backing [`VfsRoot`] for `path`, mapping `PUSHD`-allocated UNC drive letters
    /// (`self.unc_drive_aliases`) directly onto their underlying [`VfsRoot::Unc`] share.
    ///
    /// # Arguments
    /// * `path` - Resolved [`WindowsPath`].
    ///
    /// # Returns
    /// Backing [`VfsRoot`].
    #[must_use]
    pub(super) fn root_for(&self, path: &WindowsPath) -> VfsRoot {
        if path.unc_prefix.is_none()
            && let Some((server, share)) = self.unc_drive_aliases.get(&path.drive)
        {
            return VfsRoot::Unc {
                server: server.clone(),
                share: share.clone(),
            };
        }
        VfsRoot::from_windows_path(path)
    }

    /// Checks whether `key` equals or is an ancestor directory of any mounted drive's active CWD.
    ///
    /// # Arguments
    /// * `key` - Candidate directory [`VfsKey`] being removed.
    ///
    /// # Returns
    /// `true` if `key` is in use as (or contains) a mounted drive's CWD.
    #[must_use]
    pub(super) fn is_active_cwd_or_ancestor(&self, key: &VfsKey) -> bool {
        self.drive_cwds.iter().any(|(&drive, cwd_comps)| {
            let cwd_root = self.root_for(&WindowsPath::root(drive));
            if cwd_root != key.0 || cwd_comps.len() < key.1.len() {
                return false;
            }
            cwd_comps
                .iter()
                .take(key.1.len())
                .zip(key.1.iter())
                .all(|(c, k)| fold_win32_case(c) == *k)
        })
    }

    /// Relocates a directory entry (`src_key`) and all its descendants onto `final_dst_key`.
    ///
    /// # Arguments
    /// * `src_key` - Original directory [`VfsKey`].
    /// * `final_dst_key` - Destination directory [`VfsKey`].
    /// * `new_entry` - Updated root [`DirEntry`] for `final_dst_key`.
    fn relocate_dir_subtree(
        &mut self,
        src_key: &VfsKey,
        final_dst_key: &VfsKey,
        new_entry: DirEntry,
    ) {
        let prefix_len = src_key.1.len();
        let descendants: Vec<(VfsKey, DirEntry)> = self
            .entries
            .iter()
            .filter(|((r, comps), _)| {
                r == &src_key.0 && comps.len() > prefix_len && comps.starts_with(&src_key.1)
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (old_k, _) in &descendants {
            self.entries.remove(old_k);
        }
        self.entries.remove(src_key);
        self.entries.insert(final_dst_key.clone(), new_entry);

        for ((_, old_comps), child_entry) in descendants {
            let mut new_comps = final_dst_key.1.clone();
            new_comps.extend_from_slice(old_comps.get(prefix_len..).unwrap_or(&[]));
            self.entries
                .insert((final_dst_key.0.clone(), new_comps), child_entry);
        }
    }

    /// Resolves a single component `comp` inside directory `(root, parent_folded)` by exact
    /// case-folded match or 8.3 short-name match.
    ///
    /// # Arguments
    /// * `root` - Active [`VfsRoot`].
    /// * `parent_folded` - Folded uppercase path of the parent directory.
    /// * `comp` - Component name (long or 8.3 short).
    ///
    /// # Returns
    /// Uppercase canonical child component name.
    fn match_child_component(
        &self,
        root: &VfsRoot,
        parent_folded: &[String],
        comp: &str,
    ) -> String {
        let up = fold_win32_case(comp);
        let mut direct = parent_folded.to_vec();
        direct.push(up.clone());
        if self.entries.contains_key(&(root.clone(), direct)) {
            return up;
        }
        let target_len = parent_folded.len().saturating_add(1);
        self.entries
            .iter()
            .find(|((r, comps), entry)| {
                r == root
                    && comps.len() == target_len
                    && comps.starts_with(parent_folded)
                    && entry.short_name.eq_ignore_ascii_case(comp)
            })
            .map_or(up, |(_, entry)| fold_win32_case(&entry.name))
    }

    /// Resolves `target_raw` stored inside a symbolic link located at `link_parent`.
    ///
    /// Relative symlink targets resolve against `link_parent`; drive-qualified, rooted, or UNC
    /// targets resolve via `self.resolve_path`.
    ///
    /// # Arguments
    /// * `link_parent` - Parent [`WindowsPath`] containing the symbolic link.
    /// * `target_raw` - Raw target string stored on the reparse point.
    ///
    /// # Returns
    /// Resolved [`WindowsPath`] of the link target.
    fn resolve_symlink_target_path(
        &self,
        link_parent: &WindowsPath,
        target_raw: &str,
    ) -> WindowsPath {
        let trimmed = target_raw.trim();
        let bytes = trimmed.as_bytes();
        let has_drive = bytes.len() >= 2
            && bytes.first().is_some_and(u8::is_ascii_alphabetic)
            && bytes.get(1) == Some(&b':');
        let is_rooted = trimmed.starts_with(BS_CHAR) || trimmed.starts_with('/');
        if has_drive || is_rooted {
            self.resolve_path(trimmed)
        } else {
            let base = link_parent.to_windows_string();
            let combined = format!("{base}{BS_CHAR}{trimmed}");
            self.resolve_path(&combined)
        }
    }

    /// Resolves `path` through intermediate directory symlinks/junctions and optionally final
    /// reparse points (`link_policy`), enforcing [`MAX_SYMLINK_HOPS`].
    ///
    /// # Arguments
    /// * `path` - Initial resolved [`WindowsPath`].
    /// * `link_policy` - [`crate::types::SymlinkFollowPolicy`] controlling final-component reparse dereferencing.
    ///
    /// # Returns
    /// `Ok((VfsKey, WindowsPath))` of the resolved location (which may or may not exist at the leaf).
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidUncPath`] on malformed UNC paths or [`CmdError::IoFailure`] if more
    /// than [`MAX_SYMLINK_HOPS`] reparse points are traversed.
    fn resolve_with_links(
        &self,
        path: &WindowsPath,
        link_policy: crate::types::SymlinkFollowPolicy,
    ) -> Result<(VfsKey, WindowsPath), CmdError> {
        let mut cur_path = path.clone();
        let mut hops = 0usize;

        'restart: loop {
            if cur_path.is_invalid_unc() {
                return Err(CmdError::InvalidUncPath {
                    raw: cur_path.to_windows_string(),
                });
            }
            let root = self.root_for(&cur_path);
            let mut cur_folded: Vec<String> = Vec::with_capacity(cur_path.components.len());
            let mut cur_preserved: Vec<String> = Vec::with_capacity(cur_path.components.len());

            for (idx, comp) in cur_path.components.iter().enumerate() {
                let is_last = idx.saturating_add(1) == cur_path.components.len();
                let matched_up = self.match_child_component(&root, &cur_folded, comp);
                let mut next_folded = cur_folded.clone();
                next_folded.push(matched_up);
                let next_key = (root.clone(), next_folded.clone());

                if let Some((entry, inode)) = self
                    .entries
                    .get(&next_key)
                    .and_then(|e| self.inodes.get(&e.inode_id).map(|i| (e, i)))
                {
                    if let InodePayload::ReparsePoint { target, .. } = &inode.payload
                        && (!is_last
                            || link_policy == crate::types::SymlinkFollowPolicy::FollowFinalTarget)
                    {
                        hops = hops.saturating_add(1);
                        if hops > MAX_SYMLINK_HOPS {
                            return Err(CmdError::IoFailure {
                                operation: "resolve_symlink".to_owned(),
                                message: format!(
                                    "Too many levels of symbolic links resolving '{}'",
                                    path.to_windows_string()
                                ),
                            });
                        }
                        let link_parent = WindowsPath {
                            drive: cur_path.drive,
                            unc_prefix: cur_path.unc_prefix.clone(),
                            components: cur_preserved.clone(),
                        };
                        let mut redirected = self.resolve_symlink_target_path(&link_parent, target);
                        let rest = cur_path
                            .components
                            .get(idx.saturating_add(1)..)
                            .unwrap_or(&[]);
                        for rem in rest {
                            redirected.components.push(rem.clone());
                        }
                        cur_path = redirected;
                        continue 'restart;
                    }
                    cur_preserved.push(entry.name.clone());
                } else {
                    cur_preserved.push(comp.clone());
                }
                cur_folded = next_folded;
            }

            let resolved_win = WindowsPath {
                drive: cur_path.drive,
                unc_prefix: cur_path.unc_prefix,
                components: cur_preserved,
            };
            return Ok(((root, cur_folded), resolved_win));
        }
    }

    /// Allocates the next non-colliding 8.3 short name (`~1`, `~2`, ..., NT hex hash) for `leaf_name` inside `parent_key`.
    ///
    /// # Arguments
    /// * `parent_key` - [`VfsKey`] of the parent directory.
    /// * `leaf_name` - Proposed long filename.
    ///
    /// # Returns
    /// Non-colliding 8.3 short name string.
    fn allocate_short_name(&self, parent_key: &VfsKey, leaf_name: &str) -> String {
        let target_len = parent_key.1.len().saturating_add(1);
        let next_idx = (1u8..99u8)
            .find(|&idx| {
                let candidate = generate_short_name_8_3(leaf_name, idx);
                !self.entries.iter().any(|((r, comps), entry)| {
                    r == &parent_key.0
                        && comps.len() == target_len
                        && comps.starts_with(&parent_key.1)
                        && !entry.name.eq_ignore_ascii_case(leaf_name)
                        && entry.short_name.eq_ignore_ascii_case(&candidate)
                })
            })
            .unwrap_or(99);
        generate_short_name_8_3(leaf_name, next_idx)
    }

    /// Checks whether `key` refers to an existing directory (either a native directory or an implicit UNC share root).
    ///
    /// # Arguments
    /// * `key` - Resolved [`VfsKey`] (after following directory symlinks).
    ///
    /// # Returns
    /// `true` if `key` is a valid directory container.
    fn is_existing_dir_key(&self, key: &VfsKey) -> bool {
        if matches!(key.0, VfsRoot::Unc { .. }) && key.1.is_empty() {
            return true;
        }
        self.entries
            .get(key)
            .and_then(|e| self.inodes.get(&e.inode_id))
            .is_some_and(|inode| inode.attributes.is_directory())
    }

    /// Builds [`VfsMetadata`] for `entry` and `inode` located at `display_path`, dereferencing
    /// reparse targets for size and directory status while preserving the link's own name and
    /// `REPARSE_POINT` flag.
    ///
    /// # Arguments
    /// * `display_path` - Case-preserved [`WindowsPath`] of the entry itself.
    /// * `entry` - [`DirEntry`] to project.
    /// * `inode` - Referenced [`InMemoryInode`].
    ///
    /// # Returns
    /// `Ok(VfsMetadata)` for the entry.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if resolving a reparse point hits a symlink loop.
    fn entry_to_metadata(
        &self,
        display_path: &WindowsPath,
        entry: &DirEntry,
        inode: &InMemoryInode,
    ) -> Result<VfsMetadata, CmdError> {
        match &inode.payload {
            InodePayload::RegularFile { content } => Ok(VfsMetadata {
                name: entry.name.clone(),
                short_name: entry.short_name.clone(),
                full_path: display_path.clone(),
                attributes: inode.attributes,
                size: u64::try_from(content.len()).unwrap_or(0),
                modified_timestamp: inode.modified_timestamp,
            }),
            InodePayload::Directory => Ok(VfsMetadata {
                name: entry.name.clone(),
                short_name: entry.short_name.clone(),
                full_path: display_path.clone(),
                attributes: inode.attributes,
                size: 0,
                modified_timestamp: inode.modified_timestamp,
            }),
            InodePayload::ReparsePoint { kind, .. } => {
                let (target_key, _) = self.resolve_with_links(
                    display_path,
                    crate::types::SymlinkFollowPolicy::FollowFinalTarget,
                )?;
                let mut attrs = inode.attributes;
                attrs.insert(FileAttributeFlags::REPARSE_POINT);
                let size = if let Some(target_inode) = self
                    .entries
                    .get(&target_key)
                    .and_then(|te| self.inodes.get(&te.inode_id))
                {
                    attrs.set_flag(
                        FileAttributeFlags::DIRECTORY,
                        if target_inode.attributes.is_directory() {
                            crate::types::AttributeMutation::Set
                        } else {
                            crate::types::AttributeMutation::Clear
                        },
                    );
                    match &target_inode.payload {
                        InodePayload::RegularFile { content } => {
                            u64::try_from(content.len()).unwrap_or(0)
                        }
                        InodePayload::Directory | InodePayload::ReparsePoint { .. } => 0,
                    }
                } else {
                    let kind_is_dir = matches!(
                        kind,
                        MklinkKind::DirectorySymlink | MklinkKind::DirectoryJunction
                    );
                    attrs.set_flag(
                        FileAttributeFlags::DIRECTORY,
                        if kind_is_dir {
                            crate::types::AttributeMutation::Set
                        } else {
                            crate::types::AttributeMutation::Clear
                        },
                    );
                    0
                };

                Ok(VfsMetadata {
                    name: entry.name.clone(),
                    short_name: entry.short_name.clone(),
                    full_path: display_path.clone(),
                    attributes: attrs,
                    size,
                    modified_timestamp: inode.modified_timestamp,
                })
            }
        }
    }
}

impl VirtualFileSystem for InMemoryVfs {
    /// Returns the currently active [`DriveLetter`].
    ///
    /// # Returns
    /// The active [`DriveLetter`].
    fn current_drive(&self) -> DriveLetter {
        self.active_drive
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
        if self.drive_cwds.contains_key(&drive) {
            self.active_drive = drive;
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
            .drive_cwds
            .get(&drive)
            .ok_or(CmdError::DriveNotFound { drive })?;
        let raw_path = WindowsPath {
            drive,
            unc_prefix: None,
            components: comps.clone(),
        };
        let (_, preserved) = self.resolve_with_links(
            &raw_path,
            crate::types::SymlinkFollowPolicy::FollowFinalTarget,
        )?;
        Ok(WindowsPath {
            drive,
            unc_prefix: None,
            components: preserved.components,
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
        if path.unc_prefix.is_none() && !self.drive_cwds.contains_key(&path.drive) {
            return Err(CmdError::DriveNotFound { drive: path.drive });
        }
        let (key, preserved) =
            self.resolve_with_links(path, crate::types::SymlinkFollowPolicy::FollowFinalTarget)?;
        if !self.is_existing_dir_key(&key) {
            return Err(CmdError::PathNotFound {
                path: path.to_windows_string(),
            });
        }
        if path.unc_prefix.is_none() {
            self.drive_cwds.insert(path.drive, preserved.components);
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
        resolve_windows_path(raw, self.active_drive, |d| {
            self.drive_cwds.get(&d).cloned().unwrap_or_default()
        })
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
        self.volumes
            .get(&drive)
            .cloned()
            .ok_or(CmdError::DriveNotFound { drive })
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
                let parent_path = self.resolve_path(parent_raw);
                let (parent_key, _) = self.resolve_with_links(
                    &parent_path,
                    crate::types::SymlinkFollowPolicy::FollowFinalTarget,
                )?;
                if !self.is_existing_dir_key(&parent_key) {
                    return Err(CmdError::PathNotFound {
                        path: raw_path.to_owned(),
                    });
                }
            }
            return Ok(VfsMetadata {
                name: dev.to_string(),
                short_name: dev.to_string(),
                full_path: WindowsPath::root(self.active_drive).join_component(&dev.to_string()),
                attributes: FileAttributeFlags::default_file(),
                size: 0,
                modified_timestamp: self.default_timestamp,
            });
        }

        let path = self.resolve_path(raw_path);
        let (key, display_path) =
            self.resolve_with_links(&path, crate::types::SymlinkFollowPolicy::PreserveFinalLink)?;
        if matches!(key.0, VfsRoot::Unc { .. }) && key.1.is_empty() {
            return Ok(VfsMetadata {
                name: String::new(),
                short_name: String::new(),
                full_path: display_path,
                attributes: FileAttributeFlags::default_dir(),
                size: 0,
                modified_timestamp: self.default_timestamp,
            });
        }
        let (entry, inode) = self
            .entries
            .get(&key)
            .and_then(|e| self.inodes.get(&e.inode_id).map(|i| (e, i)))
            .ok_or_else(|| CmdError::FileNotFound {
                path: raw_path.to_owned(),
            })?;
        self.entry_to_metadata(&display_path, entry, inode)
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
        let path = self.resolve_path(raw_path);
        let (key, _) =
            self.resolve_with_links(&path, crate::types::SymlinkFollowPolicy::FollowFinalTarget)?;
        let inode = self
            .entries
            .get(&key)
            .and_then(|e| self.inodes.get(&e.inode_id))
            .ok_or_else(|| CmdError::FileNotFound {
                path: raw_path.to_owned(),
            })?;
        if let InodePayload::RegularFile { content } = &inode.payload {
            Ok(content.clone())
        } else {
            Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            })
        }
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
        let initial_path = self.resolve_path(raw_path);
        let (key, resolved_path) = self.resolve_with_links(
            &initial_path,
            crate::types::SymlinkFollowPolicy::FollowFinalTarget,
        )?;
        let Some(raw_leaf) = resolved_path.file_name().map(str::to_owned) else {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        };

        self.ensure_unc_share_root(&key.0);

        if let Some(inode) = self
            .entries
            .get(&key)
            .map(|e| e.inode_id)
            .and_then(|id| self.inodes.get_mut(&id))
        {
            if inode.attributes.is_directory() || inode.attributes.is_read_only() {
                return Err(CmdError::AccessDenied {
                    path: raw_path.to_owned(),
                });
            }
            inode.payload = InodePayload::RegularFile {
                content: data.to_vec(),
            };
            inode.attributes.insert(FileAttributeFlags::ARCHIVE);
            inode.modified_timestamp = self.default_timestamp;
            return Ok(());
        }

        let parent = resolved_path.parent();
        let (parent_key, _) = self.resolve_with_links(
            &parent,
            crate::types::SymlinkFollowPolicy::FollowFinalTarget,
        )?;
        if !self.is_existing_dir_key(&parent_key) {
            return Err(CmdError::PathNotFound {
                path: raw_path.to_owned(),
            });
        }

        let short_name = self.allocate_short_name(&parent_key, &raw_leaf);
        let inode_id = self.alloc_inode(InMemoryInode {
            attributes: FileAttributeFlags::default_file(),
            modified_timestamp: self.default_timestamp,
            payload: InodePayload::RegularFile {
                content: data.to_vec(),
            },
        });
        self.entries.insert(
            key,
            DirEntry {
                name: raw_leaf,
                short_name,
                inode_id,
            },
        );
        Ok(())
    }

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
    fn append_bytes(&mut self, raw_path: &str, data: &[u8]) -> Result<(), CmdError> {
        if DosDevice::split_path_device(raw_path).is_some() {
            self.ensure_exists(raw_path)?;
            return Ok(());
        }
        let initial_path = self.resolve_path(raw_path);
        let (key, _) = self.resolve_with_links(
            &initial_path,
            crate::types::SymlinkFollowPolicy::FollowFinalTarget,
        )?;
        if let Some(inode) = self
            .entries
            .get(&key)
            .map(|e| e.inode_id)
            .and_then(|id| self.inodes.get_mut(&id))
        {
            if inode.attributes.is_read_only() {
                return Err(CmdError::AccessDenied {
                    path: raw_path.to_owned(),
                });
            }
            return match &mut inode.payload {
                InodePayload::RegularFile { content } => {
                    content.extend_from_slice(data);
                    inode.attributes.insert(FileAttributeFlags::ARCHIVE);
                    Ok(())
                }
                InodePayload::Directory | InodePayload::ReparsePoint { .. } => {
                    Err(CmdError::AccessDenied {
                        path: raw_path.to_owned(),
                    })
                }
            };
        }
        self.write_bytes(raw_path, data)
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
        let path = self.resolve_path(raw_path);
        let (key, _) =
            self.resolve_with_links(&path, crate::types::SymlinkFollowPolicy::PreserveFinalLink)?;
        let Some((inode_id, inode)) = self
            .entries
            .get(&key)
            .map(|e| e.inode_id)
            .and_then(|id| self.inodes.get(&id).map(|i| (id, i)))
        else {
            return Err(CmdError::FileNotFound {
                path: raw_path.to_owned(),
            });
        };
        let is_dir_entry = match &inode.payload {
            InodePayload::Directory => true,
            InodePayload::RegularFile { .. } => false,
            InodePayload::ReparsePoint { kind, .. } => {
                matches!(
                    kind,
                    MklinkKind::DirectorySymlink | MklinkKind::DirectoryJunction
                )
            }
        };
        if is_dir_entry
            || (inode.attributes.is_read_only()
                && access_mode == crate::types::ReadOnlyDeletePolicy::RespectReadOnly)
        {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        self.entries.remove(&key);
        self.gc_unreferenced_inodes(&[inode_id]);
        Ok(())
    }

    /// Creates a directory (and optionally all missing parent directories when `create_parents` is `true`).
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
        let path = self.resolve_path(raw_path);
        if path.is_invalid_unc() {
            return Err(CmdError::InvalidUncPath {
                raw: raw_path.to_owned(),
            });
        }
        let root = self.root_for(&path);
        if path.unc_prefix.is_none() && !self.drive_cwds.contains_key(&path.drive) {
            return Err(CmdError::DriveNotFound { drive: path.drive });
        }
        self.ensure_unc_share_root(&root);

        let (key, _) =
            self.resolve_with_links(&path, crate::types::SymlinkFollowPolicy::PreserveFinalLink)?;
        if path.components.is_empty() || self.entries.contains_key(&key) {
            return Err(CmdError::FileAlreadyExists {
                path: raw_path.to_owned(),
            });
        }

        if parent_mode == crate::types::DirCreationDepth::CreateParents {
            let mut cur_comps = Vec::new();
            for comp in &path.components {
                let parent_path = WindowsPath {
                    drive: path.drive,
                    unc_prefix: path.unc_prefix.clone(),
                    components: cur_comps.clone(),
                };
                let (parent_key, _) = self.resolve_with_links(
                    &parent_path,
                    crate::types::SymlinkFollowPolicy::FollowFinalTarget,
                )?;
                cur_comps.push(comp.clone());
                let cur_path = WindowsPath {
                    drive: path.drive,
                    unc_prefix: path.unc_prefix.clone(),
                    components: cur_comps.clone(),
                };
                let (cur_key, _) = self.resolve_with_links(
                    &cur_path,
                    crate::types::SymlinkFollowPolicy::FollowFinalTarget,
                )?;
                if self.entries.contains_key(&cur_key) {
                    if !self.is_existing_dir_key(&cur_key) {
                        return Err(CmdError::FileAlreadyExists {
                            path: cur_path.to_windows_string(),
                        });
                    }
                } else {
                    let short_name = self.allocate_short_name(&parent_key, comp);
                    let inode_id = self.alloc_inode(InMemoryInode {
                        attributes: FileAttributeFlags::default_dir(),
                        modified_timestamp: self.default_timestamp,
                        payload: InodePayload::Directory,
                    });
                    self.entries.insert(
                        cur_key,
                        DirEntry {
                            name: comp.clone(),
                            short_name,
                            inode_id,
                        },
                    );
                }
            }
            return Ok(());
        }

        let parent = path.parent();
        let (parent_key, _) = self.resolve_with_links(
            &parent,
            crate::types::SymlinkFollowPolicy::FollowFinalTarget,
        )?;
        if !self.is_existing_dir_key(&parent_key) {
            return Err(CmdError::PathNotFound {
                path: raw_path.to_owned(),
            });
        }
        let leaf = path.file_name().unwrap_or("").to_owned();
        let mut child_folded = parent_key.1.clone();
        child_folded.push(fold_win32_case(&leaf));
        let child_key = (parent_key.0.clone(), child_folded);

        let short_name = self.allocate_short_name(&parent_key, &leaf);
        let inode_id = self.alloc_inode(InMemoryInode {
            attributes: FileAttributeFlags::default_dir(),
            modified_timestamp: self.default_timestamp,
            payload: InodePayload::Directory,
        });
        self.entries.insert(
            child_key,
            DirEntry {
                name: leaf,
                short_name,
                inode_id,
            },
        );
        Ok(())
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
        let path = self.resolve_path(raw_path);
        if path.components.is_empty() {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }
        let (key, _) =
            self.resolve_with_links(&path, crate::types::SymlinkFollowPolicy::PreserveFinalLink)?;
        let Some((root_inode_id, inode)) = self
            .entries
            .get(&key)
            .map(|e| e.inode_id)
            .and_then(|id| self.inodes.get(&id).map(|i| (id, i)))
        else {
            return Err(CmdError::PathNotFound {
                path: raw_path.to_owned(),
            });
        };

        // Directory symlink or junction: remove only the reparse point without deleting target contents!
        if let InodePayload::ReparsePoint { kind, .. } = &inode.payload {
            if matches!(
                kind,
                MklinkKind::DirectorySymlink | MklinkKind::DirectoryJunction
            ) {
                if self.is_active_cwd_or_ancestor(&key) {
                    return Err(CmdError::SharingViolation {
                        path: raw_path.to_owned(),
                    });
                }
                self.entries.remove(&key);
                self.gc_unreferenced_inodes(&[root_inode_id]);
                return Ok(());
            }
            return Err(CmdError::PathNotFound {
                path: raw_path.to_owned(),
            });
        }

        if !inode.attributes.is_directory() {
            return Err(CmdError::PathNotFound {
                path: raw_path.to_owned(),
            });
        }
        if self.is_active_cwd_or_ancestor(&key) {
            return Err(CmdError::SharingViolation {
                path: raw_path.to_owned(),
            });
        }
        if inode.attributes.is_read_only() {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }

        let child_keys: Vec<VfsKey> = self
            .entries
            .keys()
            .filter(|(r, comps)| {
                r == &key.0 && comps.len() > key.1.len() && comps.starts_with(&key.1)
            })
            .cloned()
            .collect();

        if !child_keys.is_empty() && removal_mode == crate::types::DirRemovalMode::EmptyOnly {
            return Err(CmdError::DirectoryNotEmpty {
                path: raw_path.to_owned(),
            });
        }
        if child_keys.iter().any(|ck| {
            self.entries
                .get(ck)
                .and_then(|e| self.inodes.get(&e.inode_id))
                .is_some_and(|child_inode| child_inode.attributes.is_read_only())
        }) {
            return Err(CmdError::AccessDenied {
                path: raw_path.to_owned(),
            });
        }

        let mut removed_inodes = Vec::with_capacity(child_keys.len().saturating_add(1));
        removed_inodes.push(root_inode_id);
        removed_inodes.extend(
            child_keys
                .into_iter()
                .filter_map(|ck| self.entries.remove(&ck).map(|r| r.inode_id)),
        );
        self.entries.remove(&key);
        self.gc_unreferenced_inodes(&removed_inodes);
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
        let dir_path = self.resolve_path(raw_dir_path);
        let (dir_key, _) = self.resolve_with_links(
            &dir_path,
            crate::types::SymlinkFollowPolicy::FollowFinalTarget,
        )?;
        if !self.is_existing_dir_key(&dir_key) {
            return Err(CmdError::PathNotFound {
                path: raw_dir_path.to_owned(),
            });
        }

        let target_len = dir_key.1.len().saturating_add(1);
        let mut results = Vec::new();
        for (entry, inode) in self
            .entries
            .iter()
            .filter(|((root, comps), _)| {
                root == &dir_key.0 && comps.len() == target_len && comps.starts_with(&dir_key.1)
            })
            .filter_map(|(_, e)| self.inodes.get(&e.inode_id).map(|i| (e, i)))
        {
            let child_path = dir_path.join_component(&entry.name);
            results.push(self.entry_to_metadata(&child_path, entry, inode)?);
        }
        results.sort_by_key(|a| fold_win32_case(&a.name));
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
        let path = self.resolve_path(raw_path);
        let (key, _) =
            self.resolve_with_links(&path, crate::types::SymlinkFollowPolicy::PreserveFinalLink)?;
        let Some(inode) = self
            .entries
            .get(&key)
            .map(|e| e.inode_id)
            .and_then(|id| self.inodes.get_mut(&id))
        else {
            return Err(CmdError::FileNotFound {
                path: raw_path.to_owned(),
            });
        };
        let was_dir = inode.attributes.is_directory();
        let was_reparse = inode.attributes.is_reparse_point();
        let mut updated = attributes;
        updated.set_flag(
            FileAttributeFlags::DIRECTORY,
            if was_dir {
                crate::types::AttributeMutation::Set
            } else {
                crate::types::AttributeMutation::Clear
            },
        );
        if was_reparse {
            updated.insert(FileAttributeFlags::REPARSE_POINT);
        }
        inode.attributes = updated;
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
        if self.drive_cwds.contains_key(&drive) {
            Ok(self
                .drive_free_space
                .get(&drive)
                .copied()
                .unwrap_or(100_000_000))
        } else {
            Err(CmdError::DriveNotFound { drive })
        }
    }

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
    fn move_entry(&mut self, src_raw: &str, dst_raw: &str) -> Result<(), CmdError> {
        let src_path = self.resolve_path(src_raw);
        let dst_path = self.resolve_path(dst_raw);
        let (src_key, _) = self.resolve_with_links(
            &src_path,
            crate::types::SymlinkFollowPolicy::PreserveFinalLink,
        )?;
        let (dst_key, _) = self.resolve_with_links(
            &dst_path,
            crate::types::SymlinkFollowPolicy::PreserveFinalLink,
        )?;

        let Some(src_entry) = self.entries.get(&src_key).cloned() else {
            return Err(CmdError::FileNotFound {
                path: src_raw.to_owned(),
            });
        };
        if src_key == dst_key {
            return Ok(());
        }

        self.ensure_unc_share_root(&dst_key.0);
        let dst_parent = dst_path.parent();
        let (dst_parent_key, _) = self.resolve_with_links(
            &dst_parent,
            crate::types::SymlinkFollowPolicy::FollowFinalTarget,
        )?;
        if !self.is_existing_dir_key(&dst_parent_key) {
            return Err(CmdError::PathNotFound {
                path: dst_raw.to_owned(),
            });
        }

        let src_is_dir = self
            .inodes
            .get(&src_entry.inode_id)
            .is_some_and(|i| matches!(i.payload, InodePayload::Directory));

        let overwritten_inode = if let Some(dst_existing) = self.entries.get(&dst_key) {
            let dst_is_dir = self
                .inodes
                .get(&dst_existing.inode_id)
                .is_some_and(|i| i.attributes.is_directory());
            if dst_is_dir || src_is_dir {
                return Err(CmdError::FileAlreadyExists {
                    path: dst_raw.to_owned(),
                });
            }
            Some(dst_existing.inode_id)
        } else {
            None
        };

        let new_leaf = dst_path.file_name().unwrap_or(&src_entry.name).to_owned();
        let new_short = self.allocate_short_name(&dst_parent_key, &new_leaf);

        let mut target_folded = dst_parent_key.1.clone();
        target_folded.push(fold_win32_case(&new_leaf));
        let final_dst_key = (dst_parent_key.0, target_folded);

        if src_is_dir {
            if final_dst_key.0 == src_key.0 && final_dst_key.1.starts_with(&src_key.1) {
                return Err(CmdError::AccessDenied {
                    path: dst_raw.to_owned(),
                });
            }
            if self.is_active_cwd_or_ancestor(&src_key) {
                return Err(CmdError::SharingViolation {
                    path: src_raw.to_owned(),
                });
            }
            self.relocate_dir_subtree(
                &src_key,
                &final_dst_key,
                DirEntry {
                    name: new_leaf,
                    short_name: new_short,
                    inode_id: src_entry.inode_id,
                },
            );
        } else {
            self.entries.remove(&src_key);
            self.entries.insert(
                final_dst_key,
                DirEntry {
                    name: new_leaf,
                    short_name: new_short,
                    inode_id: src_entry.inode_id,
                },
            );
            if let Some(old_id) = overwritten_inode {
                self.gc_unreferenced_inodes(&[old_id]);
            }
        }
        Ok(())
    }

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
    ) -> Result<(), CmdError> {
        let link_path = self.resolve_path(link_raw);
        if link_path.is_invalid_unc() {
            return Err(CmdError::InvalidUncPath {
                raw: link_raw.to_owned(),
            });
        }
        let Some(raw_leaf) = link_path.file_name().map(str::to_owned) else {
            return Err(CmdError::AccessDenied {
                path: link_raw.to_owned(),
            });
        };
        if link_path.unc_prefix.is_none() && !self.drive_cwds.contains_key(&link_path.drive) {
            return Err(CmdError::DriveNotFound {
                drive: link_path.drive,
            });
        }
        let root = self.root_for(&link_path);
        self.ensure_unc_share_root(&root);

        let parent = link_path.parent();
        let (parent_key, _) = self.resolve_with_links(
            &parent,
            crate::types::SymlinkFollowPolicy::FollowFinalTarget,
        )?;
        if !self.is_existing_dir_key(&parent_key) {
            return Err(CmdError::PathNotFound {
                path: link_raw.to_owned(),
            });
        }

        let mut link_folded = parent_key.1.clone();
        link_folded.push(fold_win32_case(&raw_leaf));
        let link_key = (parent_key.0.clone(), link_folded);
        if self.entries.contains_key(&link_key) {
            return Err(CmdError::FileAlreadyExists {
                path: link_raw.to_owned(),
            });
        }

        let short_name = self.allocate_short_name(&parent_key, &raw_leaf);
        let is_dir_link = matches!(
            kind,
            MklinkKind::DirectorySymlink | MklinkKind::DirectoryJunction
        );
        let mut attrs = if is_dir_link {
            FileAttributeFlags::default_dir()
        } else {
            FileAttributeFlags::default_file()
        };
        attrs.insert(FileAttributeFlags::REPARSE_POINT);

        let inode_id = self.alloc_inode(InMemoryInode {
            attributes: attrs,
            modified_timestamp: self.default_timestamp,
            payload: InodePayload::ReparsePoint {
                target: target_raw.to_owned(),
                kind,
            },
        });
        self.entries.insert(
            link_key,
            DirEntry {
                name: raw_leaf,
                short_name,
                inode_id,
            },
        );
        Ok(())
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
        let target_path = self.resolve_path(target_raw);
        let (target_key, _) = self.resolve_with_links(
            &target_path,
            crate::types::SymlinkFollowPolicy::FollowFinalTarget,
        )?;
        let Some((target_inode_id, target_inode)) = self
            .entries
            .get(&target_key)
            .map(|e| e.inode_id)
            .and_then(|id| self.inodes.get(&id).map(|i| (id, i)))
        else {
            return Err(CmdError::FileNotFound {
                path: target_raw.to_owned(),
            });
        };
        if target_inode.attributes.is_directory() {
            return Err(CmdError::AccessDenied {
                path: target_raw.to_owned(),
            });
        }

        let link_path = self.resolve_path(link_raw);
        let Some(raw_leaf) = link_path.file_name().map(str::to_owned) else {
            return Err(CmdError::AccessDenied {
                path: link_raw.to_owned(),
            });
        };
        let parent = link_path.parent();
        let (parent_key, _) = self.resolve_with_links(
            &parent,
            crate::types::SymlinkFollowPolicy::FollowFinalTarget,
        )?;
        if !self.is_existing_dir_key(&parent_key) {
            return Err(CmdError::PathNotFound {
                path: link_raw.to_owned(),
            });
        }
        // Hard links cannot span distinct volumes/shares.
        if parent_key.0 != target_key.0 {
            return Err(CmdError::AccessDenied {
                path: link_raw.to_owned(),
            });
        }

        let mut link_folded = parent_key.1.clone();
        link_folded.push(fold_win32_case(&raw_leaf));
        let link_key = (parent_key.0.clone(), link_folded);
        if self.entries.contains_key(&link_key) {
            return Err(CmdError::FileAlreadyExists {
                path: link_raw.to_owned(),
            });
        }

        let short_name = self.allocate_short_name(&parent_key, &raw_leaf);
        self.entries.insert(
            link_key,
            DirEntry {
                name: raw_leaf,
                short_name,
                inode_id: target_inode_id,
            },
        );
        Ok(())
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
        let path = self.resolve_path(raw_path);
        let (key, _) =
            self.resolve_with_links(&path, crate::types::SymlinkFollowPolicy::FollowFinalTarget)?;
        let Some(inode) = self
            .entries
            .get(&key)
            .map(|e| e.inode_id)
            .and_then(|id| self.inodes.get_mut(&id))
        else {
            return Err(CmdError::FileNotFound {
                path: raw_path.to_owned(),
            });
        };
        inode.modified_timestamp = new_timestamp;
        Ok(())
    }

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
    ) -> Result<DriveLetter, CmdError> {
        let share_path = self.resolve_path(unc_share);
        let Some((srv, shr)) = &share_path.unc_prefix else {
            return Err(CmdError::InvalidUncPath {
                raw: unc_share.to_owned(),
            });
        };
        if share_path.is_invalid_unc() {
            return Err(CmdError::InvalidUncPath {
                raw: unc_share.to_owned(),
            });
        }
        let server_folded = CaseFoldedString::new(srv);
        let share_folded = CaseFoldedString::new(shr);
        let unc_root = VfsRoot::Unc {
            server: server_folded.clone(),
            share: share_folded.clone(),
        };
        self.ensure_unc_share_root(&unc_root);

        for byte in (b'A'..=b'Z').rev() {
            let candidate = DriveLetter::try_from_char(char::from(byte)).unwrap_or(DriveLetter::Z);
            if !self.drive_cwds.contains_key(&candidate) {
                self.unc_drive_aliases
                    .insert(candidate, (server_folded, share_folded));
                self.drive_cwds.insert(candidate, Vec::new());
                self.volumes.insert(
                    candidate,
                    VolumeInfo {
                        label: unc_share.to_owned(),
                        serial_number: "9U8N-7C6S".to_owned(),
                    },
                );
                self.drive_free_space.insert(candidate, 100_000_000);
                if !sub_components.is_empty() {
                    let bs_sep = crate::types::BS_STR;
                    let sub_rel = sub_components.join(bs_sep);
                    let full_sub = format!("{candidate}{bs_sep}{sub_rel}");
                    if !self.exists(&full_sub) {
                        self.create_dir(&full_sub, crate::types::DirCreationDepth::CreateParents)?;
                    }
                    self.drive_cwds.insert(candidate, sub_components.to_vec());
                }
                return Ok(candidate);
            }
        }
        Err(CmdError::PathNotFound {
            path: unc_share.to_owned(),
        })
    }

    /// Unmounts a temporary drive letter previously allocated by `mount_unc_drive` (`POPD`).
    ///
    /// When `drive` was a `PUSHD` UNC alias, removes only the drive letter binding while keeping
    /// all underlying [`VfsRoot::Unc`] share files intact!
    ///
    /// # Arguments
    /// * `drive` - The temporary [`DriveLetter`] to unmount.
    fn unmount_drive(&mut self, drive: DriveLetter) {
        self.drive_cwds.remove(&drive);
        self.volumes.remove(&drive);
        self.drive_free_space.remove(&drive);
        if self.unc_drive_aliases.remove(&drive).is_some() {
            return;
        }
        let target_root = VfsRoot::Drive(drive);
        let mut removed_inodes = Vec::new();
        self.entries.retain(|(r, _), rec| {
            if r == &target_root {
                removed_inodes.push(rec.inode_id);
                false
            } else {
                true
            }
        });
        if !removed_inodes.is_empty() {
            self.gc_unreferenced_inodes(&removed_inodes);
        }
    }

    /// Translates a resolved [`WindowsPath`] to a real host [`PathBuf`] if backed by the host OS.
    ///
    /// # Arguments
    /// * `_win_path` - Resolved [`WindowsPath`] (unused on pure [`InMemoryVfs`]).
    ///
    /// # Returns
    /// `Some(PathBuf)` if backed by [`super::HostOsVfs`], or `None` for pure [`InMemoryVfs`].
    fn resolve_host_path(&self, _win_path: &WindowsPath) -> Option<PathBuf> {
        None
    }

    /// Configures the simulated free disk space (in bytes) for `drive` on [`InMemoryVfs`] or [`super::HostOsVfs`].
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    /// * `bytes` - Free space in bytes.
    fn set_drive_free_space(&mut self, drive: DriveLetter, bytes: u64) {
        self.drive_free_space.insert(drive, bytes);
    }

    /// Synchronizes the host OS process current working directory with the VFS active drive CWD
    /// when `_binding_mode` is [`HostBindingMode::Synchronized`].
    ///
    /// # Arguments
    /// * `_binding_mode` - [`HostBindingMode`] (no-op on pure [`InMemoryVfs`]).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`] or [`CmdError::AccessDenied`] if changing the host directory fails.
    fn sync_host_cwd(&self, _binding_mode: HostBindingMode) -> Result<(), CmdError> {
        Ok(())
    }

    /// Clones this VFS state into a boxed trait object.
    ///
    /// # Returns
    /// A boxed clone of this [`VirtualFileSystem`].
    fn clone_box(&self) -> Box<dyn VirtualFileSystem> {
        Box::new(self.clone())
    }
}
