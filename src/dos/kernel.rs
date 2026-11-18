//! Safe MS-DOS kernel and BIOS syscall abstraction trait (`DosKernelApi`) and transfer records.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use derive_more::Display;

use crate::dos::types::{
    BiosKeyEvent, DosMemoryStats, DosVersion, FatAttributeByte, LfnSupportMode, PackedDosTimestamp,
    PspCommandTail,
};
use crate::error::CmdError;
use crate::types::{CodePage, DriveLetter, ExitCode, InterruptState, VerifyCopyMode};
use crate::vfs::FileTimestamp;

/// Write disposition for [`DosKernelApi::write_file_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display)]
pub enum DosWriteDisposition {
    /// Create a new file or truncate an existing file to zero length before writing (`INT 21h AH=3Ch`).
    #[default]
    #[display("create_truncate")]
    CreateTruncate,
    /// Create a new file or seek to EOF and append bytes (`INT 21h AH=3Dh` + `AH=42h AL=02h`).
    #[display("create_or_append")]
    CreateOrAppend,
}

/// Free and total storage capacity reported for a DOS logical drive (`INT 21h AH=36h` / `AX=7303h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DosDiskSpace {
    /// Available free bytes on the volume.
    pub free_bytes: u64,
    /// Total capacity of the volume in bytes.
    pub total_bytes: u64,
    /// Bytes per sector (typically `512`).
    pub bytes_per_sector: u16,
    /// Sectors per allocation cluster.
    pub sectors_per_cluster: u16,
}

/// Metadata record returned by [`DosKernelApi::stat_entry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DosStatRecord {
    /// Long or case-preserved entry name (`name` in LFN mode, uppercase 8.3 in strict mode).
    pub name: String,
    /// Uppercase DOS 8.3 short alias (`"PROGRA~1"`, `"AUTOEXEC.BAT"`).
    pub short_name: String,
    /// Raw FAT attribute byte (`R/H/S/V/D/A`).
    pub attributes: FatAttributeByte,
    /// File length in bytes (`0` for directories).
    pub size: u64,
    /// Packed MS-DOS modification timestamp (`2`-second FAT resolution).
    pub modified: PackedDosTimestamp,
}

/// Directory entry record returned by [`DosKernelApi::read_dir_entries`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DosDirRecord {
    /// Long or primary entry filename (`"."` and `".."` excluded).
    pub name: String,
    /// Uppercase DOS 8.3 short filename.
    pub short_name: String,
    /// Raw FAT attribute byte (`R/H/S/V/D/A`).
    pub attributes: FatAttributeByte,
    /// File length in bytes (`0` for subdirectories).
    pub size: u64,
    /// Packed MS-DOS modification timestamp.
    pub modified: PackedDosTimestamp,
}

/// Child process execution specification passed to [`DosKernelApi::exec_child`] (`INT 21h AH=4Bh AL=00h`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DosExecChildSpec {
    /// Canonical DOS executable path (`"C:\DOS\MEM.EXE"`).
    pub program_dos_path: String,
    /// Validated 126-byte Program Segment Prefix (`PSP:0x80`) command tail.
    pub psp_tail: PspCommandTail,
    /// Unquoted `argv` vector (used by DJGPP / DPMI spawn bridges).
    pub args: Vec<String>,
    /// Active DOS working directory (`"C:\WORK"`).
    pub cwd_dos_path: String,
    /// Serialized child environment variable pairs (`(KEY, VALUE)`).
    pub env_vars: Vec<(String, String)>,
    /// Optional DOS file path redirected onto child file handle `0` (`STDIN`).
    pub stdin_spool_path: Option<String>,
    /// Optional DOS file path redirected onto child file handle `1` (`STDOUT`).
    pub stdout_spool_path: Option<String>,
    /// Optional DOS file path redirected onto child file handle `2` (`STDERR`).
    pub stderr_spool_path: Option<String>,
}

/// Safe MS-DOS kernel, filesystem, process, RTC, and BIOS console abstraction trait.
///
/// Contains zero `unsafe` methods so all higher-level `DosFatVfs`, `DosProcessSpawner`, and
/// `DosConsoleIo` components live inside `win-cmd-rs` under `#![forbid(unsafe_code)]`.
pub trait DosKernelApi: core::fmt::Debug {
    /// Clones this kernel handle or state into a boxed trait object.
    ///
    /// # Returns
    /// Boxed clone of this [`DosKernelApi`].
    fn clone_box(&self) -> Box<dyn DosKernelApi>;

    /// Queries the running MS-DOS / `FreeDOS` version (`INT 21h AH=30h` / `AX=3306h`).
    ///
    /// # Returns
    /// Active [`DosVersion`].
    fn dos_version(&self) -> DosVersion;

    /// Queries the active global MS-DOS OEM codepage (`INT 21h AX=6601h`).
    ///
    /// # Returns
    /// `Ok(CodePage)` currently active on the DOS console.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `NLSFUNC` fails or reports an unsupported codepage.
    fn active_codepage(&self) -> Result<CodePage, CmdError>;

    /// Selects the active global MS-DOS OEM codepage (`INT 21h AX=6602h`).
    ///
    /// # Arguments
    /// * `cp` - Target [`CodePage`] to activate.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidCodePage`] or [`CmdError::IoFailure`] if the DOS kernel rejects `cp`.
    fn set_active_codepage(&mut self, cp: CodePage) -> Result<(), CmdError>;

    /// Reads the current MS-DOS system date and time (`INT 21h AH=2Ah` and `AH=2Ch`).
    ///
    /// # Returns
    /// `Ok(FileTimestamp)` representing current DOS RTC wall-clock time.
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading the RTC fails.
    fn current_datetime(&self) -> Result<FileTimestamp, CmdError>;

    /// Sets the MS-DOS system calendar date (`INT 21h AH=2Bh`).
    ///
    /// # Arguments
    /// * `year` - 4-digit Gregorian year (`1980..=2099` on MS-DOS).
    /// * `month` - 1-based month (`1..=12`).
    /// * `day` - 1-based day (`1..=31`).
    ///
    /// # Returns
    /// `Ok(())` when accepted by DOS.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if the date components are rejected by `INT 21h AH=2Bh`.
    fn set_current_date(&mut self, year: u16, month: u8, day: u8) -> Result<(), CmdError>;

    /// Sets the MS-DOS system clock time (`INT 21h AH=2Dh`).
    ///
    /// # Arguments
    /// * `hour` - Hour (`0..=23`).
    /// * `minute` - Minute (`0..=59`).
    /// * `second` - Second (`0..=59`).
    /// * `centisec` - Hundredths of a second (`0..=99`).
    ///
    /// # Returns
    /// `Ok(())` when accepted by DOS.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if the time components are rejected by `INT 21h AH=2Dh`.
    fn set_current_time(
        &mut self,
        hour: u8,
        minute: u8,
        second: u8,
        centisec: u8,
    ) -> Result<(), CmdError>;

    /// Queries the global MS-DOS disk-write verification flag (`INT 21h AH=54h`).
    ///
    /// # Returns
    /// Current [`VerifyCopyMode`].
    fn verify_flag(&self) -> VerifyCopyMode;

    /// Updates the global MS-DOS disk-write verification flag (`INT 21h AH=2Eh`).
    ///
    /// # Arguments
    /// * `mode` - New [`VerifyCopyMode`] to apply.
    fn set_verify_flag(&mut self, mode: VerifyCopyMode);

    /// Queries conventional (`640 KiB`) and DPMI extended memory statistics.
    ///
    /// # Returns
    /// `Ok(DosMemoryStats)` describing free and largest contiguous memory blocks.
    ///
    /// # Errors
    /// Returns [`CmdError`] if querying MCB or DPMI `AX=0500h` fails.
    fn memory_stats(&self) -> Result<DosMemoryStats, CmdError>;

    /// Reads the parent DOS environment segment inherited at process startup.
    ///
    /// # Returns
    /// `Ok(Vec<(String, String)>)` of `(KEY, VALUE)` pairs.
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading the PSP environment segment fails.
    fn startup_env_vars(&self) -> Result<Vec<(String, String)>, CmdError>;

    /// Reads the startup command-line argument vector (`argv` excluding `argv[0]`).
    ///
    /// # Returns
    /// `Ok(Vec<String>)` of startup CLI tokens.
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading PSP / `CMDLINE` arguments fails.
    fn startup_argv(&self) -> Result<Vec<String>, CmdError>;

    /// Queries the active default DOS drive (`INT 21h AH=19h`).
    ///
    /// # Returns
    /// Current [`DriveLetter`].
    fn current_drive(&self) -> DriveLetter;

    /// Sets the active default DOS drive (`INT 21h AH=0Eh`).
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`] (`A:`..`Z:`).
    ///
    /// # Returns
    /// `Ok(())` if `drive` is mounted/valid.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] if `drive` is invalid.
    fn set_current_drive(&mut self, drive: DriveLetter) -> Result<(), CmdError>;

    /// Checks whether `drive` corresponds to a valid logical DOS drive.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to probe.
    ///
    /// # Returns
    /// `true` when `drive` is present in the DOS system.
    fn is_drive_valid(&self, drive: DriveLetter) -> bool;

    /// Queries whether `drive` supports Windows 95 / DOS 7 Long Filenames (`INT 21h AX=71A0h`).
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to probe.
    ///
    /// # Returns
    /// [`LfnSupportMode`] for `drive`.
    fn lfn_support_for_drive(&self, drive: DriveLetter) -> LfnSupportMode;

    /// Queries the current working directory on `drive` (`INT 21h AH=47h` / `AX=7147h`).
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to query.
    ///
    /// # Returns
    /// `Ok(String)` formatted as `"X:\..."` (e.g., `"C:"` or `"C:\DOS"`).
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] or [`CmdError::IoFailure`] if `drive` is invalid or not ready.
    fn drive_cwd(&self, drive: DriveLetter) -> Result<String, CmdError>;

    /// Changes the current working directory for the drive prefix in `path` (`INT 21h AH=3Bh` / `AX=713Bh`).
    ///
    /// # Arguments
    /// * `path` - Absolute DOS directory path (`"C:\DOS"`).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::DriveNotFound`], or [`CmdError::IoFailure`].
    fn set_drive_cwd(&mut self, path: &str) -> Result<(), CmdError>;

    /// Queries free and total bytes on `drive` (`INT 21h AH=36h` / `AX=7303h`).
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to inspect.
    ///
    /// # Returns
    /// `Ok(DosDiskSpace)`.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] or [`CmdError::IoFailure`] if `drive` is invalid or not ready.
    fn volume_space(&self, drive: DriveLetter) -> Result<DosDiskSpace, CmdError>;

    /// Queries the 11-character FAT volume label and `"XXXX-XXXX"` hex serial number for `drive`.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to inspect.
    ///
    /// # Returns
    /// `Ok((label, serial))` tuple.
    ///
    /// # Errors
    /// Returns [`CmdError::DriveNotFound`] or [`CmdError::IoFailure`] if `drive` is invalid or not ready.
    fn volume_label_and_serial(&self, drive: DriveLetter) -> Result<(String, String), CmdError>;

    /// Resolves `raw_path` via MS-DOS `TRUENAME` (`INT 21h AH=60h` / `AX=7160h` `CL=02h`).
    ///
    /// # Arguments
    /// * `raw_path` - Relative, drive-relative, or device path to canonicalize.
    ///
    /// # Returns
    /// `Ok(String)` canonical uppercase DOS path (`"C:\DOS\MEM.EXE"` or `"C:/CON"`).
    ///
    /// # Errors
    /// Returns [`CmdError`] if the drive or syntax is rejected by `INT 21h AH=60h`.
    fn truename(&self, raw_path: &str) -> Result<String, CmdError>;

    /// Reads all raw bytes of a file at `path`.
    ///
    /// # Arguments
    /// * `path` - Canonical DOS path (`"C:\AUTOEXEC.BAT"`).
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing file contents.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::PathNotFound`], [`CmdError::AccessDenied`], or [`CmdError::IoFailure`].
    fn read_file_bytes(&self, path: &str) -> Result<Vec<u8>, CmdError>;

    /// Writes `data` to `path` using `mode` (`CreateTruncate` vs `CreateOrAppend`).
    ///
    /// # Arguments
    /// * `path` - Canonical DOS file path.
    /// * `data` - Raw byte slice to write.
    /// * `mode` - [`DosWriteDisposition`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::AccessDenied`] (for read-only files, directories, or write-protected media),
    /// [`CmdError::PathNotFound`], or [`CmdError::IoFailure`].
    fn write_file_bytes(
        &mut self,
        path: &str,
        data: &[u8],
        mode: DosWriteDisposition,
    ) -> Result<(), CmdError>;

    /// Deletes a regular file at `path` (`INT 21h AH=41h` / `AX=7141h`).
    ///
    /// # Arguments
    /// * `path` - Canonical DOS file path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`] or [`CmdError::AccessDenied`] (if `READ_ONLY` or directory).
    fn delete_file(&mut self, path: &str) -> Result<(), CmdError>;

    /// Creates a single leaf directory at `path` (`INT 21h AH=39h` / `AX=7139h`).
    ///
    /// # Arguments
    /// * `path` - Canonical DOS directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::FileAlreadyExists`], or [`CmdError::AccessDenied`].
    fn create_dir(&mut self, path: &str) -> Result<(), CmdError>;

    /// Removes an empty directory at `path` (`INT 21h AH=3Ah` / `AX=713Ah`).
    ///
    /// # Arguments
    /// * `path` - Canonical DOS directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::DirectoryNotEmpty`], or [`CmdError::AccessDenied`]
    /// (including attempting to remove the active CWD).
    fn remove_dir(&mut self, path: &str) -> Result<(), CmdError>;

    /// Renames or moves an entry on the **same** DOS logical drive (`INT 21h AH=56h` / `AX=7156h`).
    ///
    /// # Arguments
    /// * `src` - Source canonical DOS path.
    /// * `dst` - Destination canonical DOS path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] wrapping `DosErrorCode::NotSameDevice` when `src` and `dst`
    /// reside on different drives, or [`CmdError::FileNotFound`] / [`CmdError::FileAlreadyExists`] / [`CmdError::AccessDenied`].
    fn rename_entry(&mut self, src: &str, dst: &str) -> Result<(), CmdError>;

    /// Queries metadata for a file or directory at `path`.
    ///
    /// # Arguments
    /// * `path` - Canonical DOS path.
    ///
    /// # Returns
    /// `Ok(DosStatRecord)`.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::DriveNotFound`], or [`CmdError::IoFailure`].
    fn stat_entry(&self, path: &str) -> Result<DosStatRecord, CmdError>;

    /// Enumerates direct child entries of directory `dir_path` (`FindFirst`/`FindNext`, excluding `.` and `..`).
    ///
    /// # Arguments
    /// * `dir_path` - Canonical DOS directory path (`"C:"` or `"C:\DOS"`).
    ///
    /// # Returns
    /// `Ok(Vec<DosDirRecord>)`.
    ///
    /// # Errors
    /// Returns [`CmdError::PathNotFound`], [`CmdError::FileNotFound`], or [`CmdError::IoFailure`].
    fn read_dir_entries(&self, dir_path: &str) -> Result<Vec<DosDirRecord>, CmdError>;

    /// Queries the FAT attribute byte for `path` (`INT 21h AX=4300h`).
    ///
    /// # Arguments
    /// * `path` - Canonical DOS path.
    ///
    /// # Returns
    /// `Ok(FatAttributeByte)`.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`] or [`CmdError::IoFailure`].
    fn get_attributes(&self, path: &str) -> Result<FatAttributeByte, CmdError>;

    /// Updates mutable FAT attributes (`R`, `H`, `S`, `A`) on `path` (`INT 21h AX=4301h`).
    ///
    /// # Arguments
    /// * `path` - Canonical DOS path.
    /// * `attrs` - Target [`FatAttributeByte`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`] or [`CmdError::AccessDenied`].
    fn set_attributes(&mut self, path: &str, attrs: FatAttributeByte) -> Result<(), CmdError>;

    /// Sets the FAT last-modified date/time on `path` (`INT 21h AX=5701h`).
    ///
    /// # Arguments
    /// * `path` - Canonical DOS file path.
    /// * `ts` - Target [`PackedDosTimestamp`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`] or [`CmdError::AccessDenied`].
    fn set_timestamp(&mut self, path: &str, ts: PackedDosTimestamp) -> Result<(), CmdError>;

    /// Synchronously executes an external DOS `.COM`/`.EXE` child (`INT 21h AH=4Bh AL=00h`).
    ///
    /// # Arguments
    /// * `req` - [`DosExecChildSpec`] containing executable path, PSP tail, environment, and handle spool files.
    ///
    /// # Returns
    /// `Ok(ExitCode)` returned by `INT 21h AH=4Dh` (`0..=255`).
    ///
    /// # Errors
    /// Returns [`CmdError::FileNotFound`], [`CmdError::InsufficientMemory`], [`CmdError::OutOfEnvironmentSpace`],
    /// or [`CmdError::ChildProcessFailure`].
    fn exec_child(&mut self, req: &DosExecChildSpec) -> Result<ExitCode, CmdError>;

    /// Polls and clears any latched `Ctrl+C` / `Ctrl+Break` interrupt (`INT 23h`).
    ///
    /// # Returns
    /// [`InterruptState::Pending`] if a break was latched since the previous poll, else [`InterruptState::Clear`].
    fn poll_ctrl_break(&mut self) -> InterruptState;

    /// Reads the next console keystroke from BIOS/DOS (`INT 16h AH=00h`), returning `Ok(None)` on EOF.
    ///
    /// # Returns
    /// `Ok(Some(BiosKeyEvent))` or `Ok(None)` when the input stream is exhausted.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if console hardware/stream reading fails.
    fn read_console_key(&mut self) -> Result<Option<BiosKeyEvent>, CmdError>;

    /// Queries active text-mode screen dimensions `(columns, rows)` from BIOS Data Area (`80x25`, `80x50`, etc.).
    ///
    /// # Returns
    /// `(columns, rows)` pair.
    fn console_geometry(&self) -> (u16, u16);

    /// Clears the active text-mode video page using VGA attribute byte `attr` (`INT 10h AH=06h` + `AH=02h`).
    ///
    /// # Arguments
    /// * `attr` - Packed VGA color byte (`(bg << 4) | fg`, e.g., `0x07` light-gray on black).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError::IoFailure`] if video console clearing fails.
    fn clear_console_screen(&mut self, attr: u8) -> Result<(), CmdError>;
}

/// Safe `#![no_std]` reference-counted handle sharing a single [`DosKernelApi`] across [`crate::vfs::DosFatVfs`],
/// `DosProcessSpawner`, and [`crate::runtime::Interpreter`].
#[derive(Debug)]
pub struct SharedDosKernel<K: DosKernelApi + 'static> {
    /// Shared interior-mutable kernel cell.
    inner: alloc::rc::Rc<core::cell::RefCell<K>>,
}

impl<K: DosKernelApi + 'static> Clone for SharedDosKernel<K> {
    /// Clones the reference-counted pointer to the same underlying [`DosKernelApi`].
    ///
    /// # Returns
    /// New [`SharedDosKernel`] handle sharing `self`'s kernel state.
    fn clone(&self) -> Self {
        Self {
            inner: alloc::rc::Rc::clone(&self.inner),
        }
    }
}

impl<K: DosKernelApi + 'static> SharedDosKernel<K> {
    /// Wraps `kernel` in a new [`SharedDosKernel`] handle.
    ///
    /// # Arguments
    /// * `kernel` - Underlying [`DosKernelApi`] instance.
    ///
    /// # Returns
    /// Initialized [`SharedDosKernel`].
    #[must_use]
    pub fn new(kernel: K) -> Self {
        Self {
            inner: alloc::rc::Rc::new(core::cell::RefCell::new(kernel)),
        }
    }

    /// Runs `f` with an immutable borrow of the underlying kernel `K`.
    ///
    /// # Arguments
    /// * `f` - Closure inspecting `&K`.
    ///
    /// # Returns
    /// Value returned by `f`.
    pub fn with<R>(&self, f: impl FnOnce(&K) -> R) -> R {
        f(&self.inner.borrow())
    }

    /// Runs `f` with a mutable borrow of the underlying kernel `K`.
    ///
    /// # Arguments
    /// * `f` - Closure mutating `&mut K`.
    ///
    /// # Returns
    /// Value returned by `f`.
    pub fn with_mut<R>(&self, f: impl FnOnce(&mut K) -> R) -> R {
        f(&mut self.inner.borrow_mut())
    }
}

impl<K: DosKernelApi + 'static> DosKernelApi for SharedDosKernel<K> {
    /// Clones this [`SharedDosKernel`] handle as a boxed [`DosKernelApi`].
    ///
    /// # Returns
    /// Boxed [`SharedDosKernel`] sharing the same live kernel cell.
    fn clone_box(&self) -> Box<dyn DosKernelApi> {
        Box::new(self.clone())
    }

    /// Queries the underlying kernel's [`DosVersion`].
    ///
    /// # Returns
    /// Reported [`DosVersion`].
    fn dos_version(&self) -> DosVersion {
        self.inner.borrow().dos_version()
    }

    /// Queries the active MS-DOS [`CodePage`].
    ///
    /// # Returns
    /// `Ok(CodePage)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn active_codepage(&self) -> Result<CodePage, CmdError> {
        self.inner.borrow().active_codepage()
    }

    /// Updates the active MS-DOS [`CodePage`].
    ///
    /// # Arguments
    /// * `cp` - Target [`CodePage`].
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn set_active_codepage(&mut self, cp: CodePage) -> Result<(), CmdError> {
        self.inner.borrow_mut().set_active_codepage(cp)
    }

    /// Queries the MS-DOS real-time clock [`FileTimestamp`].
    ///
    /// # Returns
    /// `Ok(FileTimestamp)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn current_datetime(&self) -> Result<FileTimestamp, CmdError> {
        self.inner.borrow().current_datetime()
    }

    /// Sets the MS-DOS system date.
    ///
    /// # Arguments
    /// * `year` - Year (`1980..=2099`).
    /// * `month` - Month (`1..=12`).
    /// * `day` - Day (`1..=31`).
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn set_current_date(&mut self, year: u16, month: u8, day: u8) -> Result<(), CmdError> {
        self.inner.borrow_mut().set_current_date(year, month, day)
    }

    /// Sets the MS-DOS system time.
    ///
    /// # Arguments
    /// * `hour` - Hour (`0..=23`).
    /// * `minute` - Minute (`0..=59`).
    /// * `second` - Second (`0..=59`).
    /// * `centisec` - Hundredths (`0..=99`).
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn set_current_time(
        &mut self,
        hour: u8,
        minute: u8,
        second: u8,
        centisec: u8,
    ) -> Result<(), CmdError> {
        self.inner
            .borrow_mut()
            .set_current_time(hour, minute, second, centisec)
    }

    /// Queries the MS-DOS disk write-verify flag.
    ///
    /// # Returns
    /// Current [`VerifyCopyMode`].
    fn verify_flag(&self) -> VerifyCopyMode {
        self.inner.borrow().verify_flag()
    }

    /// Updates the MS-DOS disk write-verify flag.
    ///
    /// # Arguments
    /// * `mode` - Target [`VerifyCopyMode`].
    fn set_verify_flag(&mut self, mode: VerifyCopyMode) {
        self.inner.borrow_mut().set_verify_flag(mode);
    }

    /// Queries conventional and DPMI memory statistics.
    ///
    /// # Returns
    /// `Ok(DosMemoryStats)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn memory_stats(&self) -> Result<DosMemoryStats, CmdError> {
        self.inner.borrow().memory_stats()
    }

    /// Queries startup environment variables.
    ///
    /// # Returns
    /// `Ok(Vec<(String, String)>)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn startup_env_vars(&self) -> Result<Vec<(String, String)>, CmdError> {
        self.inner.borrow().startup_env_vars()
    }

    /// Queries startup command-line arguments.
    ///
    /// # Returns
    /// `Ok(Vec<String>)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn startup_argv(&self) -> Result<Vec<String>, CmdError> {
        self.inner.borrow().startup_argv()
    }

    /// Queries the current default [`DriveLetter`].
    ///
    /// # Returns
    /// Active [`DriveLetter`].
    fn current_drive(&self) -> DriveLetter {
        self.inner.borrow().current_drive()
    }

    /// Switches the current default [`DriveLetter`].
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn set_current_drive(&mut self, drive: DriveLetter) -> Result<(), CmdError> {
        self.inner.borrow_mut().set_current_drive(drive)
    }

    /// Checks whether `drive` is valid on the inner kernel.
    ///
    /// # Arguments
    /// * `drive` - Candidate [`DriveLetter`].
    ///
    /// # Returns
    /// `true` if mounted.
    fn is_drive_valid(&self, drive: DriveLetter) -> bool {
        self.inner.borrow().is_drive_valid(drive)
    }

    /// Queries LFN support on `drive`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// [`LfnSupportMode`].
    fn lfn_support_for_drive(&self, drive: DriveLetter) -> LfnSupportMode {
        self.inner.borrow().lfn_support_for_drive(drive)
    }

    /// Queries the current working directory on `drive`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(String)` DOS path.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn drive_cwd(&self, drive: DriveLetter) -> Result<String, CmdError> {
        self.inner.borrow().drive_cwd(drive)
    }

    /// Sets the working directory on `path`'s drive.
    ///
    /// # Arguments
    /// * `path` - Target DOS directory path.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn set_drive_cwd(&mut self, path: &str) -> Result<(), CmdError> {
        self.inner.borrow_mut().set_drive_cwd(path)
    }

    /// Queries free and total bytes on `drive`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(DosDiskSpace)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn volume_space(&self, drive: DriveLetter) -> Result<DosDiskSpace, CmdError> {
        self.inner.borrow().volume_space(drive)
    }

    /// Queries volume label and serial number on `drive`.
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok((label, serial))`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn volume_label_and_serial(&self, drive: DriveLetter) -> Result<(String, String), CmdError> {
        self.inner.borrow().volume_label_and_serial(drive)
    }

    /// Resolves `raw_path` via DOS `TRUENAME`.
    ///
    /// # Arguments
    /// * `raw_path` - Raw DOS path.
    ///
    /// # Returns
    /// `Ok(String)` canonical path.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn truename(&self, raw_path: &str) -> Result<String, CmdError> {
        self.inner.borrow().truename(raw_path)
    }

    /// Reads raw bytes of `path`.
    ///
    /// # Arguments
    /// * `path` - DOS file path.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn read_file_bytes(&self, path: &str) -> Result<Vec<u8>, CmdError> {
        self.inner.borrow().read_file_bytes(path)
    }

    /// Writes or appends `data` to `path`.
    ///
    /// # Arguments
    /// * `path` - DOS file path.
    /// * `data` - Payload bytes.
    /// * `mode` - [`DosWriteDisposition`].
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn write_file_bytes(
        &mut self,
        path: &str,
        data: &[u8],
        mode: DosWriteDisposition,
    ) -> Result<(), CmdError> {
        self.inner.borrow_mut().write_file_bytes(path, data, mode)
    }

    /// Deletes a file at `path`.
    ///
    /// # Arguments
    /// * `path` - DOS file path.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn delete_file(&mut self, path: &str) -> Result<(), CmdError> {
        self.inner.borrow_mut().delete_file(path)
    }

    /// Creates a directory at `path`.
    ///
    /// # Arguments
    /// * `path` - DOS directory path.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn create_dir(&mut self, path: &str) -> Result<(), CmdError> {
        self.inner.borrow_mut().create_dir(path)
    }

    /// Removes an empty directory at `path`.
    ///
    /// # Arguments
    /// * `path` - DOS directory path.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn remove_dir(&mut self, path: &str) -> Result<(), CmdError> {
        self.inner.borrow_mut().remove_dir(path)
    }

    /// Renames `src` to `dst` on the same DOS drive.
    ///
    /// # Arguments
    /// * `src` - Source DOS path.
    /// * `dst` - Destination DOS path.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn rename_entry(&mut self, src: &str, dst: &str) -> Result<(), CmdError> {
        self.inner.borrow_mut().rename_entry(src, dst)
    }

    /// Queries metadata for `path`.
    ///
    /// # Arguments
    /// * `path` - DOS path.
    ///
    /// # Returns
    /// `Ok(DosStatRecord)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn stat_entry(&self, path: &str) -> Result<DosStatRecord, CmdError> {
        self.inner.borrow().stat_entry(path)
    }

    /// Enumerates direct child entries of `dir_path`.
    ///
    /// # Arguments
    /// * `dir_path` - DOS directory path.
    ///
    /// # Returns
    /// `Ok(Vec<DosDirRecord>)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn read_dir_entries(&self, dir_path: &str) -> Result<Vec<DosDirRecord>, CmdError> {
        self.inner.borrow().read_dir_entries(dir_path)
    }

    /// Queries FAT attributes on `path`.
    ///
    /// # Arguments
    /// * `path` - DOS path.
    ///
    /// # Returns
    /// `Ok(FatAttributeByte)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn get_attributes(&self, path: &str) -> Result<FatAttributeByte, CmdError> {
        self.inner.borrow().get_attributes(path)
    }

    /// Updates FAT attributes on `path`.
    ///
    /// # Arguments
    /// * `path` - DOS path.
    /// * `attrs` - [`FatAttributeByte`].
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn set_attributes(&mut self, path: &str, attrs: FatAttributeByte) -> Result<(), CmdError> {
        self.inner.borrow_mut().set_attributes(path, attrs)
    }

    /// Sets the FAT timestamp on `path`.
    ///
    /// # Arguments
    /// * `path` - DOS path.
    /// * `ts` - [`PackedDosTimestamp`].
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn set_timestamp(&mut self, path: &str, ts: PackedDosTimestamp) -> Result<(), CmdError> {
        self.inner.borrow_mut().set_timestamp(path, ts)
    }

    /// Synchronously executes a DOS child executable.
    ///
    /// # Arguments
    /// * `req` - [`DosExecChildSpec`].
    ///
    /// # Returns
    /// `Ok(ExitCode)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn exec_child(&mut self, req: &DosExecChildSpec) -> Result<ExitCode, CmdError> {
        self.inner.borrow_mut().exec_child(req)
    }

    /// Polls and clears any latched `Ctrl+C` / `Ctrl+Break` interrupt.
    ///
    /// # Returns
    /// [`InterruptState`].
    fn poll_ctrl_break(&mut self) -> InterruptState {
        self.inner.borrow_mut().poll_ctrl_break()
    }

    /// Reads the next console keystroke from BIOS/DOS.
    ///
    /// # Returns
    /// `Ok(Option<BiosKeyEvent>)`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn read_console_key(&mut self) -> Result<Option<BiosKeyEvent>, CmdError> {
        self.inner.borrow_mut().read_console_key()
    }

    /// Queries `(columns, rows)` text-mode dimensions.
    ///
    /// # Returns
    /// `(columns, rows)`.
    fn console_geometry(&self) -> (u16, u16) {
        self.inner.borrow().console_geometry()
    }

    /// Clears the text-mode video console using VGA attribute `attr`.
    ///
    /// # Arguments
    /// * `attr` - Packed VGA color byte.
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Propagates [`CmdError`] from the inner kernel.
    fn clear_console_screen(&mut self, attr: u8) -> Result<(), CmdError> {
        self.inner.borrow_mut().clear_console_screen(attr)
    }
}
