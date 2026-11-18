//! Deterministic in-memory MS-DOS FAT16/FAT32 + DPMI kernel simulator (`SimulatedDosKernel`).

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::dos::kernel::{
    DosDirRecord, DosDiskSpace, DosExecChildSpec, DosKernelApi, DosStatRecord, DosWriteDisposition,
};
use crate::dos::types::{
    BiosKeyEvent, DosFileName8Dot3, DosMemoryStats, DosVersion, DriveMediaState, FatAttributeByte,
    LfnSupportMode, PackedDosDate, PackedDosTime, PackedDosTimestamp, ShortNamePolicy,
    WriteProtectState,
};
use crate::error::CmdError;
use crate::types::{
    BS_CHAR, BS_STR, CRLF, CodePage, DosErrorCode, DosExtendedError, DriveLetter, ExitCode,
    InterruptState, VerifyCopyMode, fold_win32_case,
};
use crate::vfs::FileTimestamp;
use crate::vfs::devices::DosDevice;

/// Syscall category targeted by a scripted [`DosFaultRule`] in [`SimulatedDosKernel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DosFaultOp {
    /// Match any syscall on [`SimulatedDosKernel`].
    Any,
    /// Match `stat_entry`, `get_attributes`, or `set_attributes`.
    Stat,
    /// Match `read_file_bytes`.
    ReadFile,
    /// Match `write_file_bytes`.
    WriteFile,
    /// Match `delete_file`.
    DeleteFile,
    /// Match `create_dir`.
    CreateDir,
    /// Match `remove_dir`.
    RemoveDir,
    /// Match `rename_entry`.
    Rename,
    /// Match `read_dir_entries`.
    ReadDir,
    /// Match `exec_child`.
    ExecChild,
    /// Match `read_console_key`.
    ReadConsoleKey,
    /// Match `clear_console_screen`.
    ClearScreen,
    /// Match `memory_stats`.
    MemoryStats,
    /// Match `active_codepage` or `set_active_codepage`.
    Codepage,
    /// Match `current_datetime`, `set_current_date`, or `set_current_time`.
    Clock,
    /// Match `startup_env_vars` or `startup_argv`.
    Startup,
}

/// One-shot scripted fault rule consumed by [`SimulatedDosKernel`] when matching `op` and `path_substr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DosFaultRule {
    /// Target [`DosFaultOp`] (`DosFaultOp::Any` matches every syscall).
    pub op: DosFaultOp,
    /// Optional case-insensitive substring matched against the target path.
    pub path_substr: Option<String>,
    /// MS-DOS [`DosErrorCode`] injected when this rule triggers.
    pub error_code: DosErrorCode,
}

/// Programmable child `.COM`/`.EXE` behavior registered in [`SimulatedDosKernel`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimChildProgram {
    /// Writes fixed `stdout` and `stderr` bytes and exits with `exit_code` (checking `min_conventional_bytes`).
    FixedOutput {
        /// Child process exit status (`0..=255`).
        exit_code: ExitCode,
        /// Bytes written to `stdout_spool_path` when present.
        stdout: Vec<u8>,
        /// Bytes written to `stderr_spool_path` when present.
        stderr: Vec<u8>,
        /// Minimum `largest_conventional_block` required to load this child.
        min_conventional_bytes: u32,
    },
    /// Writes `PSP=<tail>` and `CMDLINE=<val>` lines to `stdout_spool_path` for verifying 126-byte PSP + DJGPP transfer.
    EchoPspAndCmdline {
        /// Child process exit status.
        exit_code: ExitCode,
    },
    /// Reads `stdin_spool_path`, converts ASCII letters to uppercase, and writes to `stdout_spool_path`.
    UppercaseFilter {
        /// Child process exit status.
        exit_code: ExitCode,
    },
    /// Fails immediately with a simulated [`DosErrorCode`] (e.g., `BadFormat` or `NotEnoughMemory`).
    FailWithDosError(
        /// Simulated DOS error code.
        DosErrorCode,
    ),
}

/// Payload stored inside a [`SimFatNode`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum SimFatPayload {
    /// Subdirectory or root directory node.
    Directory,
    /// Regular file byte payload.
    RegularFile(
        /// Raw file bytes.
        Vec<u8>,
    ),
}

/// Single FAT directory or file node stored in a [`SimulatedDrive`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct SimFatNode {
    /// Case-preserved LFN name (or uppercase 8.3 name in `Disabled8Dot3Only` mode).
    display_name: String,
    /// Canonical uppercase 8.3 short alias (`"PROGRA~1"`, `"FILE.TXT"`).
    short_name: String,
    /// FAT attribute byte (`R/H/S/V/D/A`).
    attributes: FatAttributeByte,
    /// Last-modified packed MS-DOS timestamp (`2`-second granularity).
    modified: PackedDosTimestamp,
    /// Directory vs. file data payload.
    payload: SimFatPayload,
}

/// Public configuration parameters for mounting a logical drive on [`SimulatedDosKernel`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedDriveConfig {
    /// Long-filename support mode (`Disabled8Dot3Only` vs `EnabledInt21Ax71`).
    pub lfn_mode: LfnSupportMode,
    /// Initial media readiness (`Ready` vs `DriveNotReady`).
    pub media_state: DriveMediaState,
    /// Initial write-protect tab state (`Writable` vs `WriteProtected`).
    pub write_protect: WriteProtectState,
    /// 11-character volume label (e.g., `"MS-DOS_6"`).
    pub volume_label: String,
    /// Volume serial number (`"1994-0622"`).
    pub serial_number: String,
    /// Free bytes reported by `volume_space`.
    pub free_bytes: u64,
    /// Total bytes reported by `volume_space`.
    pub total_bytes: u64,
}

impl Default for SimulatedDriveConfig {
    /// Returns a standard writable 32 MiB MS-DOS 6.22 FAT16 hard-disk configuration (`8.3`-only).
    ///
    /// # Returns
    /// Default [`SimulatedDriveConfig`].
    fn default() -> Self {
        Self {
            lfn_mode: LfnSupportMode::Disabled8Dot3Only,
            media_state: DriveMediaState::Ready,
            write_protect: WriteProtectState::Writable,
            volume_label: "MS-DOS_6".to_owned(),
            serial_number: "1994-0622".to_owned(),
            free_bytes: 16 * 1024 * 1024,
            total_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Internal per-drive state inside [`SimulatedDosKernel`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct SimulatedDrive {
    /// Drive configuration (`lfn_mode`, `media_state`, `write_protect`, space, label).
    cfg: SimulatedDriveConfig,
    /// Canonical uppercase key of the active working directory on this drive (`[]` = root).
    cwd_key: Vec<String>,
    /// Case-preserved display segments of the active working directory.
    cwd_display: Vec<String>,
    /// Map from canonical uppercase component path (`[]` for root) to [`SimFatNode`].
    nodes: BTreeMap<Vec<String>, SimFatNode>,
}

impl SimulatedDrive {
    /// Constructs a freshly formatted [`SimulatedDrive`] containing an empty root directory.
    ///
    /// # Arguments
    /// * `cfg` - [`SimulatedDriveConfig`].
    /// * `now` - Initial [`PackedDosTimestamp`] assigned to the root directory.
    ///
    /// # Returns
    /// Initialized [`SimulatedDrive`].
    #[must_use]
    fn new(cfg: SimulatedDriveConfig, now: PackedDosTimestamp) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            Vec::new(),
            SimFatNode {
                display_name: String::new(),
                short_name: String::new(),
                attributes: FatAttributeByte::DIRECTORY,
                modified: now,
                payload: SimFatPayload::Directory,
            },
        );
        Self {
            cfg,
            cwd_key: Vec::new(),
            cwd_display: Vec::new(),
            nodes,
        }
    }

    /// Ensures this drive is not write-protected.
    ///
    /// # Arguments
    /// * `raw_path` - Path string for error reporting.
    /// * `op_label` - Operation name.
    ///
    /// # Returns
    /// `Ok(())` when writable.
    ///
    /// # Errors
    /// Returns [`CmdError::AccessDenied`] mapped from `DosErrorCode::WriteProtectedDisk`.
    fn ensure_writable(&self, raw_path: &str, op_label: &str) -> Result<(), CmdError> {
        if self.cfg.write_protect == WriteProtectState::WriteProtected {
            return Err(CmdError::from_dos_error(
                DosExtendedError::from_code(DosErrorCode::WriteProtectedDisk),
                raw_path,
                op_label,
            ));
        }
        Ok(())
    }
}

/// Resolved directory/file key and display/8.3 names on a [`SimulatedDrive`].
#[derive(Debug, Clone)]
struct ResolvedDosTarget {
    /// Canonical uppercase path key (`[]` for drive root).
    key: Vec<String>,
    /// Case-preserved path segments.
    display_segments: Vec<String>,
    /// Case-preserved leaf filename.
    leaf_display: String,
    /// Uppercase 8.3 short alias for the leaf.
    leaf_short: String,
}

/// Deterministic in-memory [`DosKernelApi`] implementation for host-side testing and simulation.
#[derive(Debug, Clone)]
pub struct SimulatedDosKernel {
    /// Reported MS-DOS version (`MS-DOS Version 6.22` by default).
    pub version: DosVersion,
    /// Active global [`CodePage`] (`437` OEM US by default).
    pub codepage: CodePage,
    /// Current simulated RTC [`FileTimestamp`].
    pub clock: FileTimestamp,
    /// Global disk-write verification flag (`VERIFY ON|OFF`).
    pub verify_mode: VerifyCopyMode,
    /// Simulated conventional + DPMI memory statistics.
    pub memory: DosMemoryStats,
    /// Active default [`DriveLetter`].
    pub active_drive: DriveLetter,
    /// Mounted logical drives (`C:` mounted by default).
    drives: BTreeMap<DriveLetter, SimulatedDrive>,
    /// Startup environment variables inherited from parent DOS PSP.
    pub startup_env: Vec<(String, String)>,
    /// Startup command-line arguments.
    pub startup_args: Vec<String>,
    /// Programmable external `.COM`/`.EXE` child programs keyed by uppercase DOS path.
    children: BTreeMap<String, SimChildProgram>,
    /// Latched `Ctrl+Break` interrupt state.
    pub ctrl_break: InterruptState,
    /// Queued BIOS console keystrokes returned by `read_console_key`.
    pub key_queue: VecDeque<BiosKeyEvent>,
    /// Simulated BIOS screen dimensions `(columns, rows)`.
    pub screen_size: (u16, u16),
    /// Last VGA attribute byte passed to `clear_console_screen` (`None` if never cleared).
    pub last_cleared_attr: Option<u8>,
    /// One-shot scripted fault queue inspected before syscalls.
    pub fault_queue: VecDeque<DosFaultRule>,
}

impl Default for SimulatedDosKernel {
    /// Creates a standard MS-DOS 6.22 [`SimulatedDosKernel`] with drive `C:` mounted (`8.3` FAT16).
    ///
    /// # Returns
    /// Default [`SimulatedDosKernel`].
    fn default() -> Self {
        Self::new()
    }
}

impl SimulatedDosKernel {
    /// Creates a new [`SimulatedDosKernel`] with drive `C:` mounted using [`SimulatedDriveConfig::default()`].
    ///
    /// # Returns
    /// Initialized [`SimulatedDosKernel`].
    #[must_use]
    pub fn new() -> Self {
        let clock = FileTimestamp::default();
        let now_dos = PackedDosTimestamp::from_file_timestamp(clock);
        let mut drives = BTreeMap::new();
        drives.insert(
            DriveLetter::C,
            SimulatedDrive::new(SimulatedDriveConfig::default(), now_dos),
        );
        Self {
            version: DosVersion::default(),
            codepage: CodePage::OemUnitedStates,
            clock,
            verify_mode: VerifyCopyMode::Unverified,
            memory: DosMemoryStats::default(),
            active_drive: DriveLetter::C,
            drives,
            startup_env: vec![
                ("COMSPEC".to_owned(), format!("C:{BS_STR}COMMAND.COM")),
                ("PATH".to_owned(), format!("C:{BS_STR}DOS")),
            ],
            startup_args: Vec::new(),
            children: BTreeMap::new(),
            ctrl_break: InterruptState::Clear,
            key_queue: VecDeque::new(),
            screen_size: (80, 25),
            last_cleared_attr: None,
            fault_queue: VecDeque::new(),
        }
    }

    /// Mounts or reconfigures a logical `drive` with `cfg`.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to mount (`A:`..`Z:`).
    /// * `cfg` - [`SimulatedDriveConfig`] for the volume.
    pub fn mount_drive(&mut self, drive: DriveLetter, cfg: SimulatedDriveConfig) {
        let now = PackedDosTimestamp::from_file_timestamp(self.clock);
        self.drives.insert(drive, SimulatedDrive::new(cfg, now));
    }

    /// Updates media readiness (`Ready` vs `DriveNotReady`) on a mounted `drive`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    /// * `state` - New [`DriveMediaState`].
    pub fn set_drive_media_state(&mut self, drive: DriveLetter, state: DriveMediaState) {
        if let Some(d) = self.drives.get_mut(&drive) {
            d.cfg.media_state = state;
        }
    }

    /// Updates write-protection (`Writable` vs `WriteProtected`) on a mounted `drive`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    /// * `state` - New [`WriteProtectState`].
    pub fn set_drive_write_protect(&mut self, drive: DriveLetter, state: WriteProtectState) {
        if let Some(d) = self.drives.get_mut(&drive) {
            d.cfg.write_protect = state;
        }
    }

    /// Updates simulated free disk space in bytes on a mounted `drive`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    /// * `free_bytes` - Simulated free capacity in bytes.
    pub fn set_drive_free_space(&mut self, drive: DriveLetter, free_bytes: u64) {
        if let Some(d) = self.drives.get_mut(&drive) {
            d.cfg.free_bytes = free_bytes;
        }
    }

    /// Unmounts `drive` from the simulated DOS system.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to remove.
    pub fn unmount_drive(&mut self, drive: DriveLetter) {
        self.drives.remove(&drive);
    }

    /// Registers a programmable child `.COM`/`.EXE` handler at `dos_path` (e.g., `"C:\DOS\TOOL.EXE"`).
    ///
    /// # Arguments
    /// * `dos_path` - Canonical DOS path of the child executable.
    /// * `program` - [`SimChildProgram`] behavior executed by `exec_child`.
    pub fn register_child_program(&mut self, dos_path: &str, program: SimChildProgram) {
        self.children.insert(fold_win32_case(dos_path), program);
    }

    /// Enqueues a one-shot [`DosFaultRule`] triggered by the next matching syscall.
    ///
    /// # Arguments
    /// * `rule` - [`DosFaultRule`] to append to `self.fault_queue`.
    pub fn push_fault(&mut self, rule: DosFaultRule) {
        self.fault_queue.push_back(rule);
    }

    /// Peeks `self.fault_queue` for immutable syscalls, returning the mapped [`CmdError`] when matched.
    ///
    /// # Arguments
    /// * `op` - Current [`DosFaultOp`].
    /// * `path` - Target path string.
    /// * `op_label` - Short operation name.
    ///
    /// # Returns
    /// `Ok(())` when no rule matched.
    ///
    /// # Errors
    /// Returns [`CmdError`] mapped from the matching [`DosFaultRule`].
    fn peek_fault(&self, op: DosFaultOp, path: &str, op_label: &str) -> Result<(), CmdError> {
        let upper_path = fold_win32_case(path);
        if let Some(rule) = self.fault_queue.iter().find(|r| {
            (r.op == DosFaultOp::Any || r.op == op)
                && r.path_substr
                    .as_ref()
                    .is_none_or(|sub| upper_path.contains(&fold_win32_case(sub)))
        }) {
            return Err(CmdError::from_dos_error(
                DosExtendedError::from_code(rule.error_code),
                path,
                op_label,
            ));
        }
        Ok(())
    }

    /// Consumes the first matching one-shot [`DosFaultRule`] from `self.fault_queue`.
    ///
    /// # Arguments
    /// * `op` - Current [`DosFaultOp`].
    /// * `path` - Target path string.
    /// * `op_label` - Short operation name.
    ///
    /// # Returns
    /// `Ok(())` when no rule matched.
    ///
    /// # Errors
    /// Returns [`CmdError`] mapped from the consumed [`DosFaultRule`].
    fn check_fault(&mut self, op: DosFaultOp, path: &str, op_label: &str) -> Result<(), CmdError> {
        let upper_path = fold_win32_case(path);
        let pos = self.fault_queue.iter().position(|r| {
            (r.op == DosFaultOp::Any || r.op == op)
                && r.path_substr
                    .as_ref()
                    .is_none_or(|sub| upper_path.contains(&fold_win32_case(sub)))
        });
        if let Some(idx) = pos {
            let code = self
                .fault_queue
                .remove(idx)
                .map_or(DosErrorCode::GeneralFailure, |r| r.error_code);
            return Err(CmdError::from_dos_error(
                DosExtendedError::from_code(code),
                path,
                op_label,
            ));
        }
        Ok(())
    }

    /// Borrows a mounted [`SimulatedDrive`] after verifying media readiness.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    /// * `raw_path` - Diagnostic path string.
    /// * `op_label` - Operation label.
    ///
    /// # Returns
    /// Shared reference to [`SimulatedDrive`].
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] or [`CmdError::IoFailure`] (`DriveNotReady`).
    fn ready_drive<'a>(
        &'a self,
        drive: DriveLetter,
        raw_path: &str,
        op_label: &str,
    ) -> Result<&'a SimulatedDrive, CmdError> {
        let drv = self
            .drives
            .get(&drive)
            .ok_or(CmdError::DriveNotFound { drive })?;
        if drv.cfg.media_state == DriveMediaState::DriveNotReady {
            return Err(CmdError::from_dos_error(
                DosExtendedError::from_code(DosErrorCode::DriveNotReady),
                raw_path,
                op_label,
            ));
        }
        Ok(drv)
    }

    /// Mutably borrows a mounted [`SimulatedDrive`].
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    /// * `_raw_path` - Unused diagnostic path string.
    /// * `_op_label` - Unused operation label.
    ///
    /// # Returns
    /// Mutable reference to [`SimulatedDrive`].
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`].
    fn ready_drive_mut<'a>(
        &'a mut self,
        drive: DriveLetter,
        _raw_path: &str,
        _op_label: &str,
    ) -> Result<&'a mut SimulatedDrive, CmdError> {
        self.drives
            .get_mut(&drive)
            .ok_or(CmdError::DriveNotFound { drive })
    }

    /// Parses `raw_path` into `(DriveLetter, anchored_segments)`, resolving `.` and `..` against `drive`'s CWD.
    ///
    /// # Arguments
    /// * `raw_path` - Input DOS path.
    /// * `op_label` - Operation label for error mapping.
    ///
    /// # Returns
    /// `Ok((drive, segments))`.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::InvalidDriveLetter`], [`CmdError::DriveNotFound`], or [`CmdError::IoFailure`].
    fn split_and_anchor_path(
        &self,
        raw_path: &str,
        op_label: &str,
    ) -> Result<(DriveLetter, Vec<String>), CmdError> {
        let trimmed = raw_path.trim();
        if trimmed.is_empty() {
            return Err(CmdError::PathNotFound {
                path: raw_path.to_owned(),
            });
        }
        let bytes = trimmed.as_bytes();
        let (drive, rest) = if bytes.get(1) == Some(&b':') {
            let ch = char::from(bytes.first().copied().unwrap_or(b'?'));
            let d = DriveLetter::try_from_char(ch)?;
            (d, trimmed.get(2..).unwrap_or(""))
        } else {
            (self.active_drive, trimmed)
        };

        let drv = self.ready_drive(drive, raw_path, op_label)?;
        let mut stack: Vec<String> = if rest.starts_with([BS_CHAR, '/']) {
            Vec::new()
        } else {
            drv.cwd_display.clone()
        };

        for part in rest.split([BS_CHAR, '/']) {
            if part.is_empty() || part == "." {
                continue;
            }
            if part == ".." {
                stack.pop();
                continue;
            }
            if part.chars().all(|c| c == '.') {
                return Err(CmdError::PathNotFound {
                    path: raw_path.to_owned(),
                });
            }
            stack.push(part.to_owned());
        }
        Ok((drive, stack))
    }

    /// Resolves an existing entry or missing-leaf creation target on `drv`.
    ///
    /// # Arguments
    /// * `drv` - Mounted [`SimulatedDrive`].
    /// * `segments` - Anchored path segments.
    /// * `raw_path` - Diagnostic path string.
    /// * `mode` - [`LeafLookupMode`].
    ///
    /// # Returns
    /// `Ok(ResolvedDosTarget)`.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::FileNotFound`], or [`CmdError::AccessDenied`].
    fn resolve_target_on_drive(
        drv: &SimulatedDrive,
        segments: &[String],
        raw_path: &str,
        mode: LeafLookupMode,
    ) -> Result<ResolvedDosTarget, CmdError> {
        let Some((leaf, parents)) = segments.split_last() else {
            return Ok(ResolvedDosTarget {
                key: Vec::new(),
                display_segments: Vec::new(),
                leaf_display: String::new(),
                leaf_short: String::new(),
            });
        };
        let (mut cur_key, mut cur_display) = Self::resolve_parent_chain(drv, parents, raw_path)?;
        match drv.cfg.lfn_mode {
            LfnSupportMode::Disabled8Dot3Only => {
                let short =
                    DosFileName8Dot3::normalize(leaf, ShortNamePolicy::StrictDosTruncate, 1)
                        .map_err(|_bad| match mode {
                            LeafLookupMode::RequireExisting => CmdError::FileNotFound {
                                path: raw_path.to_owned(),
                            },
                            LeafLookupMode::AllowMissingLeaf => CmdError::PathNotFound {
                                path: raw_path.to_owned(),
                            },
                        })?;
                let key_comp = short.as_str().to_owned();
                cur_key.push(key_comp.clone());
                if let Some(node) = drv.nodes.get(&cur_key) {
                    cur_display.push(node.display_name.clone());
                    Ok(ResolvedDosTarget {
                        key: cur_key,
                        display_segments: cur_display,
                        leaf_display: node.display_name.clone(),
                        leaf_short: node.short_name.clone(),
                    })
                } else if mode == LeafLookupMode::AllowMissingLeaf {
                    cur_display.push(key_comp.clone());
                    Ok(ResolvedDosTarget {
                        key: cur_key,
                        display_segments: cur_display,
                        leaf_display: key_comp.clone(),
                        leaf_short: key_comp,
                    })
                } else {
                    Err(CmdError::FileNotFound {
                        path: raw_path.to_owned(),
                    })
                }
            }
            LfnSupportMode::EnabledInt21Ax71 => {
                let trimmed = leaf.trim_end_matches(['.', ' ']);
                if trimmed.is_empty() || !Self::is_legal_lfn_segment(trimmed) {
                    return Err(CmdError::PathNotFound {
                        path: raw_path.to_owned(),
                    });
                }
                if let Some((matched_key, node)) = Self::find_lfn_child(drv, &cur_key, trimmed) {
                    cur_display.push(node.display_name.clone());
                    Ok(ResolvedDosTarget {
                        key: matched_key,
                        display_segments: cur_display,
                        leaf_display: node.display_name,
                        leaf_short: node.short_name,
                    })
                } else if mode == LeafLookupMode::AllowMissingLeaf {
                    let short = Self::allocate_unique_short_name(drv, &cur_key, trimmed)?;
                    cur_key.push(fold_win32_case(trimmed));
                    cur_display.push(trimmed.to_owned());
                    Ok(ResolvedDosTarget {
                        key: cur_key,
                        display_segments: cur_display,
                        leaf_display: trimmed.to_owned(),
                        leaf_short: short,
                    })
                } else {
                    Err(CmdError::FileNotFound {
                        path: raw_path.to_owned(),
                    })
                }
            }
        }
    }

    /// Walks all ancestor directory components in `parents`, ensuring each exists and is a directory.
    ///
    /// # Arguments
    /// * `drv` - Mounted [`SimulatedDrive`].
    /// * `parents` - Ancestor segment slice.
    /// * `raw_path` - Diagnostic path string.
    ///
    /// # Returns
    /// `Ok((parent_key, parent_display_segments))`.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`] if any ancestor is missing, malformed, or a regular file.
    fn resolve_parent_chain(
        drv: &SimulatedDrive,
        parents: &[String],
        raw_path: &str,
    ) -> Result<(Vec<String>, Vec<String>), CmdError> {
        let mut cur_key: Vec<String> = Vec::new();
        let mut cur_display: Vec<String> = Vec::new();
        for seg in parents {
            match drv.cfg.lfn_mode {
                LfnSupportMode::Disabled8Dot3Only => {
                    let short =
                        DosFileName8Dot3::normalize(seg, ShortNamePolicy::StrictDosTruncate, 1)?;
                    cur_key.push(short.as_str().to_owned());
                    let node = drv
                        .nodes
                        .get(&cur_key)
                        .ok_or_else(|| CmdError::PathNotFound {
                            path: raw_path.to_owned(),
                        })?;
                    if node.payload != SimFatPayload::Directory {
                        return Err(CmdError::PathNotFound {
                            path: raw_path.to_owned(),
                        });
                    }
                    cur_display.push(node.display_name.clone());
                }
                LfnSupportMode::EnabledInt21Ax71 => {
                    let trimmed = seg.trim_end_matches(['.', ' ']);
                    if trimmed.is_empty() || !Self::is_legal_lfn_segment(trimmed) {
                        return Err(CmdError::PathNotFound {
                            path: raw_path.to_owned(),
                        });
                    }
                    let (matched_key, node) = Self::find_lfn_child(drv, &cur_key, trimmed)
                        .ok_or_else(|| CmdError::PathNotFound {
                            path: raw_path.to_owned(),
                        })?;
                    if node.payload != SimFatPayload::Directory {
                        return Err(CmdError::PathNotFound {
                            path: raw_path.to_owned(),
                        });
                    }
                    cur_key = matched_key;
                    cur_display.push(node.display_name);
                }
            }
        }
        Ok((cur_key, cur_display))
    }

    /// Searches direct children of `parent_key` on an LFN volume by either case-folded LFN or 8.3 short name.
    ///
    /// # Arguments
    /// * `drv` - Mounted [`SimulatedDrive`].
    /// * `parent_key` - Parent directory key.
    /// * `trimmed` - Trimmed segment name.
    ///
    /// # Returns
    /// `Some((child_key, child_node))` if found, else `None`.
    #[must_use]
    fn find_lfn_child(
        drv: &SimulatedDrive,
        parent_key: &[String],
        trimmed: &str,
    ) -> Option<(Vec<String>, SimFatNode)> {
        let folded = fold_win32_case(trimmed);
        let child_depth = parent_key.len().saturating_add(1);
        drv.nodes
            .iter()
            .find(|(k, node)| {
                k.len() == child_depth
                    && k.starts_with(parent_key)
                    && (k.last() == Some(&folded) || node.short_name.eq_ignore_ascii_case(trimmed))
            })
            .map(|(k, node)| (k.clone(), node.clone()))
    }

    /// Validates characters in a DOS 7 Long Filename segment.
    ///
    /// # Arguments
    /// * `seg` - Trimmed LFN component.
    ///
    /// # Returns
    /// `true` when `seg` contains no control bytes or forbidden DOS/Win32 characters.
    #[must_use]
    fn is_legal_lfn_segment(seg: &str) -> bool {
        seg.len() <= 255
            && seg.bytes().all(|b| {
                b >= 0x20
                    && !matches!(
                        b,
                        b'"' | b'*' | b'/' | b':' | b'<' | b'>' | b'?' | 0x5C | b'|'
                    )
            })
    }

    /// Allocates a collision-free DOS 8.3 short alias (`PROGRA~1`..`~9`) inside `parent_key`.
    ///
    /// # Arguments
    /// * `drv` - Target [`SimulatedDrive`].
    /// * `parent_key` - Canonical key of the parent directory.
    /// * `lfn_name` - Proposed long filename.
    ///
    /// # Returns
    /// `Ok(short_name_string)`.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`] or [`CmdError::AccessDenied`] if all numeric tails collide.
    fn allocate_unique_short_name(
        drv: &SimulatedDrive,
        parent_key: &[String],
        lfn_name: &str,
    ) -> Result<String, CmdError> {
        if let Ok(exact) = DosFileName8Dot3::validate_strict(lfn_name) {
            return Ok(exact.as_str().to_owned());
        }
        let child_depth = parent_key.len().saturating_add(1);
        for idx in 1u8..=9u8 {
            let cand =
                DosFileName8Dot3::normalize(lfn_name, ShortNamePolicy::Win95NumericTail, idx)?;
            let taken = drv.nodes.iter().any(|(k, node)| {
                k.len() == child_depth
                    && k.starts_with(parent_key)
                    && node.short_name.eq_ignore_ascii_case(cand.as_str())
            });
            if !taken {
                return Ok(cand.as_str().to_owned());
            }
        }
        Err(CmdError::AccessDenied {
            path: lfn_name.to_owned(),
        })
    }
}

/// Leaf resolution mode for [`SimulatedDosKernel::resolve_target_on_drive`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeafLookupMode {
    /// Target leaf entry must already exist.
    RequireExisting,
    /// Target leaf entry may be missing so long as its parent directory exists.
    AllowMissingLeaf,
}

impl DosKernelApi for SimulatedDosKernel {
    /// Clones this [`SimulatedDosKernel`] into a boxed [`DosKernelApi`].
    ///
    /// # Returns
    /// Boxed clone of `self`.
    fn clone_box(&self) -> Box<dyn DosKernelApi> {
        Box::new(self.clone())
    }

    /// Returns `self.version`.
    ///
    /// # Returns
    /// Active [`DosVersion`].
    fn dos_version(&self) -> DosVersion {
        self.version
    }

    /// Returns `self.codepage`.
    ///
    /// # Returns
    /// `Ok(CodePage)`.
    ///
    /// # Errors
    /// Returns [`CmdError`] if a `DosFaultOp::Codepage` fault rule is active.
    fn active_codepage(&self) -> Result<CodePage, CmdError> {
        self.peek_fault(DosFaultOp::Codepage, "", "chcp")?;
        Ok(self.codepage)
    }

    /// Sets `self.codepage` to `cp`.
    ///
    /// # Arguments
    /// * `cp` - Target [`CodePage`].
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Returns [`CmdError`] if a `DosFaultOp::Codepage` fault rule is queued.
    fn set_active_codepage(&mut self, cp: CodePage) -> Result<(), CmdError> {
        self.check_fault(DosFaultOp::Codepage, "", "chcp")?;
        self.codepage = cp;
        Ok(())
    }

    /// Returns `self.clock`.
    ///
    /// # Returns
    /// `Ok(FileTimestamp)`.
    ///
    /// # Errors
    /// Returns [`CmdError`] if a `DosFaultOp::Clock` fault rule is active.
    fn current_datetime(&self) -> Result<FileTimestamp, CmdError> {
        self.peek_fault(DosFaultOp::Clock, "", "clock")?;
        Ok(self.clock)
    }

    /// Updates the date portion of `self.clock` (`1980..=2099`).
    ///
    /// # Arguments
    /// * `year` - 4-digit year (`1980..=2099`).
    /// * `month` - Month (`1..=12`).
    /// * `day` - Day (`1..=days_in_month`).
    ///
    /// # Returns
    /// `Ok(())` on valid date.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if `(year, month, day)` is out of DOS RTC bounds.
    fn set_current_date(&mut self, year: u16, month: u8, day: u8) -> Result<(), CmdError> {
        self.check_fault(DosFaultOp::Clock, "", "set_date")?;
        if !(1980..=2099).contains(&year) {
            return Err(CmdError::IoFailure {
                operation: "set_date".to_owned(),
                message: format!("year {year} outside MS-DOS 1980..=2099 range"),
            });
        }
        let cur = PackedDosTimestamp::from_file_timestamp(self.clock);
        let date = PackedDosDate::encode(year, month, day).ok_or_else(|| CmdError::IoFailure {
            operation: "set_date".to_owned(),
            message: "invalid calendar date".to_owned(),
        })?;
        self.clock = (PackedDosTimestamp {
            date,
            time: cur.time,
        })
        .to_file_timestamp()?;
        Ok(())
    }

    /// Updates the time-of-day portion of `self.clock`.
    ///
    /// # Arguments
    /// * `hour` - Hour (`0..=23`).
    /// * `minute` - Minute (`0..=59`).
    /// * `second` - Second (`0..=59`).
    /// * `centisec` - Centiseconds (`0..=99`).
    ///
    /// # Returns
    /// `Ok(())` on valid time.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if `(hour, minute, second, centisec)` is invalid.
    fn set_current_time(
        &mut self,
        hour: u8,
        minute: u8,
        second: u8,
        centisec: u8,
    ) -> Result<(), CmdError> {
        self.check_fault(DosFaultOp::Clock, "", "set_time")?;
        if centisec > 99 {
            return Err(CmdError::IoFailure {
                operation: "set_time".to_owned(),
                message: "centiseconds > 99".to_owned(),
            });
        }
        let cur = PackedDosTimestamp::from_file_timestamp(self.clock);
        PackedDosTime::encode(hour, minute, second).ok_or_else(|| CmdError::IoFailure {
            operation: "set_time".to_owned(),
            message: "invalid clock time".to_owned(),
        })?;
        let base = (PackedDosTimestamp {
            date: cur.date,
            time: PackedDosTime::MIDNIGHT,
        })
        .to_file_timestamp()?;
        let secs = u64::from(hour)
            .saturating_mul(3_600)
            .saturating_add(u64::from(minute).saturating_mul(60))
            .saturating_add(u64::from(second));
        self.clock = FileTimestamp::from_epoch_secs(base.epoch_secs().saturating_add(secs));
        Ok(())
    }

    /// Returns `self.verify_mode`.
    ///
    /// # Returns
    /// Active [`VerifyCopyMode`].
    fn verify_flag(&self) -> VerifyCopyMode {
        self.verify_mode
    }

    /// Updates `self.verify_mode`.
    ///
    /// # Arguments
    /// * `mode` - New [`VerifyCopyMode`].
    fn set_verify_flag(&mut self, mode: VerifyCopyMode) {
        self.verify_mode = mode;
    }

    /// Returns `self.memory`.
    ///
    /// # Returns
    /// `Ok(DosMemoryStats)`.
    ///
    /// # Errors
    /// Returns [`CmdError`] if a `DosFaultOp::MemoryStats` fault rule is active.
    fn memory_stats(&self) -> Result<DosMemoryStats, CmdError> {
        self.peek_fault(DosFaultOp::MemoryStats, "", "memory_stats")?;
        Ok(self.memory)
    }

    /// Clones `self.startup_env`.
    ///
    /// # Returns
    /// `Ok(Vec<(String, String)>)`.
    ///
    /// # Errors
    /// Returns [`CmdError`] if a `DosFaultOp::Startup` fault rule is active.
    fn startup_env_vars(&self) -> Result<Vec<(String, String)>, CmdError> {
        self.peek_fault(DosFaultOp::Startup, "", "startup_env")?;
        Ok(self.startup_env.clone())
    }

    /// Clones `self.startup_args`.
    ///
    /// # Returns
    /// `Ok(Vec<String>)`.
    ///
    /// # Errors
    /// Returns [`CmdError`] if a `DosFaultOp::Startup` fault rule is active.
    fn startup_argv(&self) -> Result<Vec<String>, CmdError> {
        self.peek_fault(DosFaultOp::Startup, "", "startup_argv")?;
        Ok(self.startup_args.clone())
    }

    /// Returns `self.active_drive`.
    ///
    /// # Returns
    /// Current [`DriveLetter`].
    fn current_drive(&self) -> DriveLetter {
        self.active_drive
    }

    /// Switches `self.active_drive` if `drive` is mounted.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] if `drive` is not mounted.
    fn set_current_drive(&mut self, drive: DriveLetter) -> Result<(), CmdError> {
        if !self.drives.contains_key(&drive) {
            return Err(CmdError::DriveNotFound { drive });
        }
        self.active_drive = drive;
        Ok(())
    }

    /// Returns `true` if `drive` is mounted.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to check.
    ///
    /// # Returns
    /// `true` when `drive` exists in `self.drives`.
    fn is_drive_valid(&self, drive: DriveLetter) -> bool {
        self.drives.contains_key(&drive)
    }

    /// Returns the [`LfnSupportMode`] configured for `drive`.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to query.
    ///
    /// # Returns
    /// [`LfnSupportMode`] (`Disabled8Dot3Only` if unmounted).
    fn lfn_support_for_drive(&self, drive: DriveLetter) -> LfnSupportMode {
        self.drives
            .get(&drive)
            .map_or(LfnSupportMode::Disabled8Dot3Only, |d| d.cfg.lfn_mode)
    }

    /// Formats the active working directory on `drive` (`"C:"` or `"C:\DOS"`).
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to query.
    ///
    /// # Returns
    /// `Ok(String)` working directory path.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] or [`CmdError::IoFailure`] if `drive` is unmounted or not ready.
    fn drive_cwd(&self, drive: DriveLetter) -> Result<String, CmdError> {
        let drv = self.ready_drive(drive, &drive.to_string(), "chdir")?;
        let d_ch = drive.as_char();
        if drv.cwd_display.is_empty() {
            Ok(format!("{d_ch}:{BS_STR}"))
        } else {
            Ok(format!("{d_ch}:{BS_STR}{}", drv.cwd_display.join(BS_STR)))
        }
    }

    /// Changes the working directory on `path`'s drive (`INT 21h AH=3Bh`).
    ///
    /// # Arguments
    /// * `path` - Target directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`] if `path` does not exist or is a regular file.
    fn set_drive_cwd(&mut self, path: &str) -> Result<(), CmdError> {
        let (drive, segs) = self.split_and_anchor_path(path, "chdir")?;
        let drv = self.ready_drive_mut(drive, path, "chdir")?;
        let target =
            Self::resolve_target_on_drive(drv, &segs, path, LeafLookupMode::RequireExisting)
                .map_err(|err| {
                    if let CmdError::FileNotFound { path: p } = err {
                        CmdError::PathNotFound { path: p }
                    } else {
                        err
                    }
                })?;
        if drv
            .nodes
            .get(&target.key)
            .is_none_or(|n| n.payload != SimFatPayload::Directory)
        {
            return Err(CmdError::PathNotFound {
                path: path.to_owned(),
            });
        }
        drv.cwd_key = target.key;
        drv.cwd_display = target.display_segments;
        Ok(())
    }

    /// Returns free/total disk space for `drive`.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to inspect.
    ///
    /// # Returns
    /// `Ok(DosDiskSpace)`.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] or [`CmdError::IoFailure`] if `drive` is unmounted or not ready.
    fn volume_space(&self, drive: DriveLetter) -> Result<DosDiskSpace, CmdError> {
        let drv = self.ready_drive(drive, &drive.to_string(), "dfree")?;
        Ok(DosDiskSpace {
            free_bytes: drv.cfg.free_bytes,
            total_bytes: drv.cfg.total_bytes,
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
        })
    }

    /// Returns `(volume_label, serial_number)` for `drive`.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to inspect.
    ///
    /// # Returns
    /// `Ok((label, serial))`.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] or [`CmdError::IoFailure`] if `drive` is unmounted or not ready.
    fn volume_label_and_serial(&self, drive: DriveLetter) -> Result<(String, String), CmdError> {
        let drv = self.ready_drive(drive, &drive.to_string(), "vol")?;
        Ok((drv.cfg.volume_label.clone(), drv.cfg.serial_number.clone()))
    }

    /// Canonicalizes `raw_path` using MS-DOS `TRUENAME` (`INT 21h AH=60h`) rules.
    ///
    /// # Arguments
    /// * `raw_path` - Raw path to canonicalize.
    ///
    /// # Returns
    /// `Ok(String)` canonicalized DOS path (`"C:\DOS\MEM.EXE"` or `"C:/CON"`).
    ///
    /// # Errors
    /// Returns [`CmdError`] if the drive is invalid or a segment violates FAT naming rules.
    fn truename(&self, raw_path: &str) -> Result<String, CmdError> {
        let trimmed = raw_path.trim();
        let effective = if trimmed.is_empty() { "." } else { trimmed };
        if let Some((_, dev)) = DosDevice::split_path_device(effective) {
            let d = if effective.as_bytes().get(1) == Some(&b':') {
                let ch = char::from(effective.as_bytes().first().copied().unwrap_or(b'C'));
                DriveLetter::try_from_char(ch)?
            } else {
                self.active_drive
            };
            if !self.is_drive_valid(d) {
                return Err(CmdError::DriveNotFound { drive: d });
            }
            return Ok(format!("{}:/{dev}", d.as_char()));
        }
        let (drive, segs) = self.split_and_anchor_path(effective, "truename")?;
        let lfn_mode = self.lfn_support_for_drive(drive);
        let mut canon_segs = Vec::with_capacity(segs.len());
        for seg in &segs {
            match lfn_mode {
                LfnSupportMode::Disabled8Dot3Only => {
                    let s =
                        DosFileName8Dot3::normalize(seg, ShortNamePolicy::StrictDosTruncate, 1)?;
                    canon_segs.push(s.as_str().to_owned());
                }
                LfnSupportMode::EnabledInt21Ax71 => {
                    canon_segs.push(seg.to_ascii_uppercase());
                }
            }
        }
        let d_ch = drive.as_char();
        if canon_segs.is_empty() {
            Ok(format!("{d_ch}:{BS_STR}"))
        } else {
            Ok(format!("{d_ch}:{BS_STR}{}", canon_segs.join(BS_STR)))
        }
    }

    /// Reads raw file bytes from `path`.
    ///
    /// # Arguments
    /// * `path` - File path on a mounted DOS drive.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` file contents.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::AccessDenied`] (for directories), or [`CmdError::IoFailure`].
    fn read_file_bytes(&self, path: &str) -> Result<Vec<u8>, CmdError> {
        self.peek_fault(DosFaultOp::ReadFile, path, "read")?;
        let (drive, segs) = self.split_and_anchor_path(path, "read")?;
        let drv = self.ready_drive(drive, path, "read")?;
        let target =
            Self::resolve_target_on_drive(drv, &segs, path, LeafLookupMode::RequireExisting)?;
        match drv.nodes.get(&target.key).map(|n| &n.payload) {
            Some(SimFatPayload::RegularFile(bytes)) => Ok(bytes.clone()),
            Some(SimFatPayload::Directory) | None => Err(CmdError::AccessDenied {
                path: path.to_owned(),
            }),
        }
    }

    /// Creates, truncates, or appends bytes to a file at `path`.
    ///
    /// # Arguments
    /// * `path` - Target DOS file path.
    /// * `data` - Bytes to write.
    /// * `mode` - [`DosWriteDisposition`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::AccessDenied`] (read-only file, directory, root, or write-protected drive) or [`CmdError::PathNotFound`].
    fn write_file_bytes(
        &mut self,
        path: &str,
        data: &[u8],
        mode: DosWriteDisposition,
    ) -> Result<(), CmdError> {
        self.check_fault(DosFaultOp::WriteFile, path, "write")?;
        let (drive, segs) = self.split_and_anchor_path(path, "write")?;
        if segs.is_empty() {
            return Err(CmdError::AccessDenied {
                path: path.to_owned(),
            });
        }
        let now = PackedDosTimestamp::from_file_timestamp(self.clock);
        let drv = self.ready_drive_mut(drive, path, "write")?;
        drv.ensure_writable(path, "write")?;
        let target =
            Self::resolve_target_on_drive(drv, &segs, path, LeafLookupMode::AllowMissingLeaf)?;

        if let Some(existing) = drv.nodes.get_mut(&target.key) {
            if existing.attributes.contains(FatAttributeByte::READ_ONLY) {
                return Err(CmdError::AccessDenied {
                    path: path.to_owned(),
                });
            }
            match &mut existing.payload {
                SimFatPayload::Directory => {
                    return Err(CmdError::AccessDenied {
                        path: path.to_owned(),
                    });
                }
                SimFatPayload::RegularFile(buf) => {
                    existing.modified = now;
                    existing.attributes =
                        FatAttributeByte(existing.attributes.0 | FatAttributeByte::ARCHIVE.0);
                    match mode {
                        DosWriteDisposition::CreateTruncate => {
                            buf.clear();
                            buf.extend_from_slice(data);
                        }
                        DosWriteDisposition::CreateOrAppend => {
                            buf.extend_from_slice(data);
                        }
                    }
                    return Ok(());
                }
            }
        }

        drv.nodes.insert(
            target.key,
            SimFatNode {
                display_name: target.leaf_display,
                short_name: target.leaf_short,
                attributes: FatAttributeByte::ARCHIVE,
                modified: now,
                payload: SimFatPayload::RegularFile(data.to_vec()),
            },
        );
        Ok(())
    }

    /// Deletes a regular file at `path`.
    ///
    /// # Arguments
    /// * `path` - Target DOS file path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`] or [`CmdError::AccessDenied`].
    fn delete_file(&mut self, path: &str) -> Result<(), CmdError> {
        self.check_fault(DosFaultOp::DeleteFile, path, "delete")?;
        let (drive, segs) = self.split_and_anchor_path(path, "delete")?;
        if segs.is_empty() {
            return Err(CmdError::AccessDenied {
                path: path.to_owned(),
            });
        }
        let drv = self.ready_drive_mut(drive, path, "delete")?;
        drv.ensure_writable(path, "delete")?;
        let target =
            Self::resolve_target_on_drive(drv, &segs, path, LeafLookupMode::RequireExisting)?;
        if drv.nodes.get(&target.key).is_none_or(|n| {
            n.payload == SimFatPayload::Directory
                || n.attributes.contains(FatAttributeByte::READ_ONLY)
        }) {
            return Err(CmdError::AccessDenied {
                path: path.to_owned(),
            });
        }
        drv.nodes.remove(&target.key);
        Ok(())
    }

    /// Creates a single leaf subdirectory at `path`.
    ///
    /// # Arguments
    /// * `path` - Target DOS directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileAlreadyExists`], [`CmdError::PathNotFound`], or [`CmdError::AccessDenied`].
    fn create_dir(&mut self, path: &str) -> Result<(), CmdError> {
        self.check_fault(DosFaultOp::CreateDir, path, "mkdir")?;
        let (drive, segs) = self.split_and_anchor_path(path, "mkdir")?;
        if segs.is_empty() {
            return Err(CmdError::FileAlreadyExists {
                path: path.to_owned(),
            });
        }
        let now = PackedDosTimestamp::from_file_timestamp(self.clock);
        let drv = self.ready_drive_mut(drive, path, "mkdir")?;
        drv.ensure_writable(path, "mkdir")?;
        let target =
            Self::resolve_target_on_drive(drv, &segs, path, LeafLookupMode::AllowMissingLeaf)?;
        if drv.nodes.contains_key(&target.key) {
            return Err(CmdError::FileAlreadyExists {
                path: path.to_owned(),
            });
        }
        drv.nodes.insert(
            target.key,
            SimFatNode {
                display_name: target.leaf_display,
                short_name: target.leaf_short,
                attributes: FatAttributeByte::DIRECTORY,
                modified: now,
                payload: SimFatPayload::Directory,
            },
        );
        Ok(())
    }

    /// Removes an empty directory at `path`.
    ///
    /// # Arguments
    /// * `path` - Target DOS directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::DirectoryNotEmpty`], or [`CmdError::AccessDenied`].
    fn remove_dir(&mut self, path: &str) -> Result<(), CmdError> {
        self.check_fault(DosFaultOp::RemoveDir, path, "rmdir")?;
        let (drive, segs) = self.split_and_anchor_path(path, "rmdir")?;
        if segs.is_empty() {
            return Err(CmdError::AccessDenied {
                path: path.to_owned(),
            });
        }
        let drv = self.ready_drive_mut(drive, path, "rmdir")?;
        drv.ensure_writable(path, "rmdir")?;
        let target =
            Self::resolve_target_on_drive(drv, &segs, path, LeafLookupMode::RequireExisting)
                .map_err(|err| {
                    if let CmdError::FileNotFound { path: p } = err {
                        CmdError::PathNotFound { path: p }
                    } else {
                        err
                    }
                })?;
        let is_dir_and_ro = drv.nodes.get(&target.key).map(|n| {
            (
                n.payload == SimFatPayload::Directory,
                n.attributes.contains(FatAttributeByte::READ_ONLY),
            )
        });
        let Some((true, is_ro)) = is_dir_and_ro else {
            return Err(CmdError::PathNotFound {
                path: path.to_owned(),
            });
        };
        if drv.cwd_key.starts_with(&target.key) {
            return Err(CmdError::from_dos_error(
                DosExtendedError::from_code(DosErrorCode::AttemptToRemoveCurrentDirectory),
                path,
                "rmdir",
            ));
        }
        if is_ro {
            return Err(CmdError::AccessDenied {
                path: path.to_owned(),
            });
        }
        let has_children = drv
            .nodes
            .keys()
            .any(|k| k.len() > target.key.len() && k.starts_with(&target.key));
        if has_children {
            return Err(CmdError::DirectoryNotEmpty {
                path: path.to_owned(),
            });
        }
        drv.nodes.remove(&target.key);
        Ok(())
    }

    /// Renames or moves an entry on the same drive (`INT 21h AH=56h`).
    ///
    /// # Arguments
    /// * `src` - Source DOS path.
    /// * `dst` - Destination DOS path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] (`NotSameDevice`) across drives, [`CmdError::FileAlreadyExists`],
    /// [`CmdError::FileNotFound`], or [`CmdError::AccessDenied`].
    fn rename_entry(&mut self, src: &str, dst: &str) -> Result<(), CmdError> {
        self.check_fault(DosFaultOp::Rename, src, "rename")?;
        let (src_drive, src_segs) = self.split_and_anchor_path(src, "rename")?;
        let (dst_drive, dst_segs) = self.split_and_anchor_path(dst, "rename")?;
        if src_drive != dst_drive {
            return Err(CmdError::from_dos_error(
                DosExtendedError::from_code(DosErrorCode::NotSameDevice),
                src,
                "rename",
            ));
        }
        if src_segs.is_empty() || dst_segs.is_empty() {
            return Err(CmdError::AccessDenied {
                path: src.to_owned(),
            });
        }
        let drv = self.ready_drive_mut(src_drive, src, "rename")?;
        drv.ensure_writable(src, "rename")?;
        let src_target =
            Self::resolve_target_on_drive(drv, &src_segs, src, LeafLookupMode::RequireExisting)?;
        let dst_target =
            Self::resolve_target_on_drive(drv, &dst_segs, dst, LeafLookupMode::AllowMissingLeaf)?;
        if src_target.key == dst_target.key {
            return Ok(());
        }
        if dst_target.key.starts_with(&src_target.key) {
            return Err(CmdError::AccessDenied {
                path: dst.to_owned(),
            });
        }
        if drv.nodes.contains_key(&dst_target.key) {
            return Err(CmdError::FileAlreadyExists {
                path: dst.to_owned(),
            });
        }
        if drv.cwd_key.starts_with(&src_target.key) {
            return Err(CmdError::AccessDenied {
                path: src.to_owned(),
            });
        }

        let moved: Vec<(Vec<String>, SimFatNode)> = drv
            .nodes
            .iter()
            .filter(|(k, _)| k.starts_with(&src_target.key))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (old_key, _) in &moved {
            drv.nodes.remove(old_key);
        }
        for (old_key, mut node) in moved {
            let suffix = old_key.get(src_target.key.len()..).unwrap_or(&[]);
            let mut new_key = dst_target.key.clone();
            new_key.extend_from_slice(suffix);
            if suffix.is_empty() {
                node.display_name.clone_from(&dst_target.leaf_display);
                node.short_name.clone_from(&dst_target.leaf_short);
            }
            drv.nodes.insert(new_key, node);
        }
        Ok(())
    }

    /// Queries metadata for `path`.
    ///
    /// # Arguments
    /// * `path` - Target DOS path.
    ///
    /// # Returns
    /// `Ok(DosStatRecord)`.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::DriveNotFound`], or [`CmdError::IoFailure`].
    fn stat_entry(&self, path: &str) -> Result<DosStatRecord, CmdError> {
        self.peek_fault(DosFaultOp::Stat, path, "stat")?;
        let (drive, segs) = self.split_and_anchor_path(path, "stat")?;
        let drv = self.ready_drive(drive, path, "stat")?;
        let target =
            Self::resolve_target_on_drive(drv, &segs, path, LeafLookupMode::AllowMissingLeaf)?;
        let node = drv
            .nodes
            .get(&target.key)
            .ok_or_else(|| CmdError::FileNotFound {
                path: path.to_owned(),
            })?;
        let size = match &node.payload {
            SimFatPayload::Directory => 0,
            SimFatPayload::RegularFile(b) => u64::try_from(b.len()).unwrap_or(u64::MAX),
        };
        Ok(DosStatRecord {
            name: node.display_name.clone(),
            short_name: node.short_name.clone(),
            attributes: node.attributes,
            size,
            modified: node.modified,
        })
    }

    /// Enumerates direct child entries of `dir_path`.
    ///
    /// # Arguments
    /// * `dir_path` - Target DOS directory path.
    ///
    /// # Returns
    /// `Ok(Vec<DosDirRecord>)`.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`] or [`CmdError::IoFailure`].
    fn read_dir_entries(&self, dir_path: &str) -> Result<Vec<DosDirRecord>, CmdError> {
        self.peek_fault(DosFaultOp::ReadDir, dir_path, "read_dir")?;
        let (drive, segs) = self.split_and_anchor_path(dir_path, "read_dir")?;
        let drv = self.ready_drive(drive, dir_path, "read_dir")?;
        let target =
            Self::resolve_target_on_drive(drv, &segs, dir_path, LeafLookupMode::RequireExisting)
                .map_err(|err| {
                    if let CmdError::FileNotFound { path: p } = err {
                        CmdError::PathNotFound { path: p }
                    } else {
                        err
                    }
                })?;
        if drv
            .nodes
            .get(&target.key)
            .is_none_or(|n| n.payload != SimFatPayload::Directory)
        {
            return Err(CmdError::PathNotFound {
                path: dir_path.to_owned(),
            });
        }
        let child_len = target.key.len().saturating_add(1);
        let mut out = Vec::new();
        for (k, node) in &drv.nodes {
            if k.len() == child_len && k.starts_with(&target.key) {
                let size = match &node.payload {
                    SimFatPayload::Directory => 0,
                    SimFatPayload::RegularFile(b) => u64::try_from(b.len()).unwrap_or(u64::MAX),
                };
                out.push(DosDirRecord {
                    name: node.display_name.clone(),
                    short_name: node.short_name.clone(),
                    attributes: node.attributes,
                    size,
                    modified: node.modified,
                });
            }
        }
        Ok(out)
    }

    /// Queries the FAT attribute byte for `path`.
    ///
    /// # Arguments
    /// * `path` - Target DOS path.
    ///
    /// # Returns
    /// `Ok(FatAttributeByte)`.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`] or [`CmdError::IoFailure`].
    fn get_attributes(&self, path: &str) -> Result<FatAttributeByte, CmdError> {
        Ok(self.stat_entry(path)?.attributes)
    }

    /// Updates mutable FAT attributes (`R`, `H`, `S`, `A`) on `path`, preserving `DIRECTORY`.
    ///
    /// # Arguments
    /// * `path` - Target DOS path.
    /// * `attrs` - Desired [`FatAttributeByte`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`] or [`CmdError::AccessDenied`].
    fn set_attributes(&mut self, path: &str, attrs: FatAttributeByte) -> Result<(), CmdError> {
        self.check_fault(DosFaultOp::Stat, path, "attrib")?;
        let (drive, segs) = self.split_and_anchor_path(path, "attrib")?;
        if segs.is_empty() {
            return Err(CmdError::AccessDenied {
                path: path.to_owned(),
            });
        }
        let drv = self.ready_drive_mut(drive, path, "attrib")?;
        drv.ensure_writable(path, "attrib")?;
        let target =
            Self::resolve_target_on_drive(drv, &segs, path, LeafLookupMode::RequireExisting)?;
        drv.nodes.entry(target.key).and_modify(|node| {
            let dir_bit = node.attributes.0 & FatAttributeByte::DIRECTORY.0;
            let mutable_mask = FatAttributeByte::READ_ONLY.0
                | FatAttributeByte::HIDDEN.0
                | FatAttributeByte::SYSTEM.0
                | FatAttributeByte::ARCHIVE.0;
            node.attributes = FatAttributeByte(dir_bit | (attrs.0 & mutable_mask));
        });
        Ok(())
    }

    /// Updates the packed FAT modification timestamp on `path`.
    ///
    /// # Arguments
    /// * `path` - Target DOS path.
    /// * `ts` - Target [`PackedDosTimestamp`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`] or [`CmdError::AccessDenied`].
    fn set_timestamp(&mut self, path: &str, ts: PackedDosTimestamp) -> Result<(), CmdError> {
        let _validated = ts.to_file_timestamp()?;
        let (drive, segs) = self.split_and_anchor_path(path, "utime")?;
        if segs.is_empty() {
            return Err(CmdError::AccessDenied {
                path: path.to_owned(),
            });
        }
        let drv = self.ready_drive_mut(drive, path, "utime")?;
        drv.ensure_writable(path, "utime")?;
        let target =
            Self::resolve_target_on_drive(drv, &segs, path, LeafLookupMode::RequireExisting)?;
        drv.nodes.entry(target.key).and_modify(|node| {
            node.modified = ts;
        });
        Ok(())
    }

    /// Executes a registered [`SimChildProgram`] matching `req.program_dos_path`.
    ///
    /// # Arguments
    /// * `req` - [`DosExecChildSpec`] specifying executable, PSP tail, environment, and spool files.
    ///
    /// # Returns
    /// `Ok(ExitCode)` on child completion.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::InsufficientMemory`], or [`CmdError`] mapped from DOS errors.
    fn exec_child(&mut self, req: &DosExecChildSpec) -> Result<ExitCode, CmdError> {
        self.check_fault(DosFaultOp::ExecChild, &req.program_dos_path, "exec")?;
        let key = fold_win32_case(&req.program_dos_path);
        let prog = self
            .children
            .get(&key)
            .cloned()
            .ok_or_else(|| CmdError::FileNotFound {
                path: req.program_dos_path.clone(),
            })?;

        match prog {
            SimChildProgram::FixedOutput {
                exit_code,
                stdout,
                stderr,
                min_conventional_bytes,
            } => {
                if self.memory.largest_conventional_block < min_conventional_bytes {
                    return Err(CmdError::InsufficientMemory);
                }
                if let Some(out_path) = &req.stdout_spool_path {
                    self.write_file_bytes(out_path, &stdout, DosWriteDisposition::CreateTruncate)?;
                }
                if let Some(err_path) = &req.stderr_spool_path {
                    self.write_file_bytes(err_path, &stderr, DosWriteDisposition::CreateTruncate)?;
                }
                Ok(exit_code)
            }
            SimChildProgram::EchoPspAndCmdline { exit_code } => {
                let psp_str = String::from_utf8_lossy(req.psp_tail.tail_bytes());
                let cmdline_val = req
                    .env_vars
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("CMDLINE"))
                    .map_or("", |(_, v)| v.as_str());
                let rendered = format!("PSP={psp_str}{CRLF}CMDLINE={cmdline_val}{CRLF}");
                if let Some(out_path) = &req.stdout_spool_path {
                    self.write_file_bytes(
                        out_path,
                        rendered.as_bytes(),
                        DosWriteDisposition::CreateTruncate,
                    )?;
                }
                Ok(exit_code)
            }
            SimChildProgram::UppercaseFilter { exit_code } => {
                let input = match &req.stdin_spool_path {
                    Some(in_path) => self.read_file_bytes(in_path)?,
                    None => Vec::new(),
                };
                let upper: Vec<u8> = input.into_iter().map(|b| b.to_ascii_uppercase()).collect();
                if let Some(out_path) = &req.stdout_spool_path {
                    self.write_file_bytes(out_path, &upper, DosWriteDisposition::CreateTruncate)?;
                }
                Ok(exit_code)
            }
            SimChildProgram::FailWithDosError(code) => Err(CmdError::from_dos_error(
                DosExtendedError::from_code(code),
                &req.program_dos_path,
                "exec",
            )),
        }
    }

    /// Polls and clears `self.ctrl_break`.
    ///
    /// # Returns
    /// Previous [`InterruptState`].
    fn poll_ctrl_break(&mut self) -> InterruptState {
        core::mem::replace(&mut self.ctrl_break, InterruptState::Clear)
    }

    /// Pops the next [`BiosKeyEvent`] from `self.key_queue`.
    ///
    /// # Returns
    /// `Ok(Some(key))` or `Ok(None)` when `key_queue` is empty.
    ///
    /// # Errors
    /// Returns [`CmdError`] if a `DosFaultOp::ReadConsoleKey` fault rule is active.
    fn read_console_key(&mut self) -> Result<Option<BiosKeyEvent>, CmdError> {
        self.check_fault(DosFaultOp::ReadConsoleKey, "CON", "read_key")?;
        Ok(self.key_queue.pop_front())
    }

    /// Returns `self.screen_size`.
    ///
    /// # Returns
    /// `(columns, rows)` dimensions.
    fn console_geometry(&self) -> (u16, u16) {
        self.screen_size
    }

    /// Records `attr` into `self.last_cleared_attr`.
    ///
    /// # Arguments
    /// * `attr` - Packed VGA color attribute byte.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if a `DosFaultOp::ClearScreen` fault rule is active.
    fn clear_console_screen(&mut self, attr: u8) -> Result<(), CmdError> {
        self.check_fault(DosFaultOp::ClearScreen, "CON", "cls")?;
        self.last_cleared_attr = Some(attr);
        Ok(())
    }
}
