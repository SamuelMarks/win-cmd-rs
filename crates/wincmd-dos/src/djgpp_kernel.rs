//! Safe [`DosKernelApi`] adapter (`DjgppDosKernel`) over [`DjgppSyscallApi`].
//!
//! Bridges DJGPP `libc` + DPMI (`INT 21h`, `INT 16h`, `INT 10h`, `INT 31h`) calls into
//! `win_cmd_rs::dos::DosKernelApi`, translating every [`DosExtendedError`](win_cmd_rs::types::DosExtendedError)
//! immediately via [`CmdError::from_dos_error`] with zero `unwrap` and zero `anyhow`.

#![forbid(unsafe_code)]

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use win_cmd_rs::dos::{
    BiosKeyEvent, DosDirRecord, DosDiskSpace, DosExecChildSpec, DosKernelApi, DosMemoryStats,
    DosStatRecord, DosVersion, DosWriteDisposition, FatAttributeByte, LfnSupportMode,
    PackedDosTimestamp,
};
use win_cmd_rs::error::CmdError;
use win_cmd_rs::types::{CodePage, DriveLetter, ExitCode, InterruptState, VerifyCopyMode};
use win_cmd_rs::vfs::FileTimestamp;

use crate::ffi::DjgppSyscallApi;

/// `DosKernelApi` implementation backed by [`DjgppSyscallApi`].
#[derive(Debug, Clone)]
pub struct DjgppDosKernel<S: DjgppSyscallApi> {
    /// Underlying DJGPP syscall provider.
    pub sys: S,
}

impl<S: DjgppSyscallApi> DjgppDosKernel<S> {
    /// Creates a new [`DjgppDosKernel`] wrapping `sys`.
    ///
    /// # Arguments
    /// * `sys` - [`DjgppSyscallApi`] implementation.
    ///
    /// # Returns
    /// Initialized [`DjgppDosKernel`].
    #[must_use]
    pub const fn new(sys: S) -> Self {
        Self { sys }
    }
}

impl<S: DjgppSyscallApi> DosKernelApi for DjgppDosKernel<S> {
    /// Clones this kernel adapter behind a boxed [`DosKernelApi`] trait object.
    ///
    /// # Returns
    /// Cloned `Box<dyn DosKernelApi>`.
    fn clone_box(&self) -> Box<dyn DosKernelApi> {
        Box::new(self.clone())
    }

    /// Queries the active MS-DOS kernel [`DosVersion`].
    ///
    /// # Returns
    /// Active [`DosVersion`].
    fn dos_version(&self) -> DosVersion {
        self.sys.sys_dos_version()
    }

    /// Queries the active MS-DOS `NLSFUNC` [`CodePage`].
    ///
    /// # Returns
    /// Active [`CodePage`].
    ///
    /// # Errors
    /// Returns [`CmdError`] mapped from [`DosExtendedError`](win_cmd_rs::types::DosExtendedError) on failure.
    fn active_codepage(&self) -> Result<CodePage, CmdError> {
        self.sys
            .sys_active_codepage()
            .map_err(|e| CmdError::from_dos_error(e, "CON", "active_codepage"))
    }

    /// Updates the active MS-DOS `NLSFUNC` [`CodePage`].
    ///
    /// # Arguments
    /// * `cp` - Target [`CodePage`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `INT 21h AX=6602h` rejects `cp`.
    fn set_active_codepage(&mut self, cp: CodePage) -> Result<(), CmdError> {
        self.sys
            .sys_set_codepage(cp)
            .map_err(|e| CmdError::from_dos_error(e, &format!("{}", cp.id()), "set_codepage"))
    }

    /// Queries the current MS-DOS real-time clock timestamp.
    ///
    /// # Returns
    /// Active [`FileTimestamp`].
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading or decoding the DOS RTC fails.
    fn current_datetime(&self) -> Result<FileTimestamp, CmdError> {
        let (d, t) = self
            .sys
            .sys_get_datetime()
            .map_err(|e| CmdError::from_dos_error(e, "CLOCK$", "current_datetime"))?;
        (PackedDosTimestamp { date: d, time: t }).to_file_timestamp()
    }

    /// Sets the MS-DOS system calendar date (`INT 21h AH=2Bh`).
    ///
    /// # Arguments
    /// * `year` - Four-digit calendar year (`1980..=2099`).
    /// * `month` - Month (`1..=12`).
    /// * `day` - Day of month (`1..=31`).
    ///
    /// # Returns
    /// `Ok(())` when accepted by DOS.
    ///
    /// # Errors
    /// Returns [`CmdError`] if DOS rejects the date.
    fn set_current_date(&mut self, year: u16, month: u8, day: u8) -> Result<(), CmdError> {
        self.sys.sys_set_date(year, month, day).map_err(|e| {
            CmdError::from_dos_error(
                e,
                &format!("{year:04}-{month:02}-{day:02}"),
                "set_current_date",
            )
        })
    }

    /// Sets the MS-DOS system wall-clock time (`INT 21h AH=2Dh`).
    ///
    /// # Arguments
    /// * `hour` - Hour (`0..=23`).
    /// * `minute` - Minute (`0..=59`).
    /// * `second` - Second (`0..=59`).
    /// * `centisec` - Centiseconds (`0..=99`).
    ///
    /// # Returns
    /// `Ok(())` when accepted by DOS.
    ///
    /// # Errors
    /// Returns [`CmdError`] if DOS rejects the time.
    fn set_current_time(
        &mut self,
        hour: u8,
        minute: u8,
        second: u8,
        centisec: u8,
    ) -> Result<(), CmdError> {
        self.sys
            .sys_set_time(hour, minute, second, centisec)
            .map_err(|e| {
                CmdError::from_dos_error(
                    e,
                    &format!("{hour:02}:{minute:02}:{second:02}.{centisec:02}"),
                    "set_current_time",
                )
            })
    }

    /// Queries the MS-DOS disk write-verification flag (`INT 21h AH=54h`).
    ///
    /// # Returns
    /// Active [`VerifyCopyMode`].
    fn verify_flag(&self) -> VerifyCopyMode {
        self.sys.sys_verify_flag()
    }

    /// Updates the MS-DOS disk write-verification flag (`INT 21h AH=2Eh`).
    ///
    /// # Arguments
    /// * `mode` - Target [`VerifyCopyMode`].
    fn set_verify_flag(&mut self, mode: VerifyCopyMode) {
        self.sys.sys_set_verify_flag(mode);
    }

    /// Queries conventional DOS and DPMI extended memory statistics.
    ///
    /// # Returns
    /// Current [`DosMemoryStats`].
    ///
    /// # Errors
    /// Returns [`CmdError`] if DPMI memory inspection fails.
    fn memory_stats(&self) -> Result<DosMemoryStats, CmdError> {
        self.sys
            .sys_memory_stats()
            .map_err(|e| CmdError::from_dos_error(e, "DPMI", "memory_stats"))
    }

    /// Reads inherited startup `(KEY, VALUE)` environment variables.
    ///
    /// # Returns
    /// Startup environment pairs.
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading the PSP environment fails.
    fn startup_env_vars(&self) -> Result<Vec<(String, String)>, CmdError> {
        self.sys
            .sys_startup_env()
            .map_err(|e| CmdError::from_dos_error(e, "PSP:ENV", "startup_env_vars"))
    }

    /// Reads inherited startup `argv[1..]` command-line tokens.
    ///
    /// # Returns
    /// Startup argument vector.
    ///
    /// # Errors
    /// Returns [`CmdError`] if reading startup arguments fails.
    fn startup_argv(&self) -> Result<Vec<String>, CmdError> {
        self.sys
            .sys_startup_argv()
            .map_err(|e| CmdError::from_dos_error(e, "PSP:ARGV", "startup_argv"))
    }

    /// Queries the default DOS logical drive (`INT 21h AH=19h`).
    ///
    /// # Returns
    /// Active [`DriveLetter`].
    fn current_drive(&self) -> DriveLetter {
        self.sys.sys_current_drive()
    }

    /// Switches the default DOS logical drive (`INT 21h AH=0Eh`).
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(())` if `drive` is valid.
    ///
    /// # Errors
    /// Returns [`CmdError`] (`InvalidDrive`) if `drive` does not exist.
    fn set_current_drive(&mut self, drive: DriveLetter) -> Result<(), CmdError> {
        self.sys
            .sys_set_drive(drive)
            .map_err(|e| CmdError::from_dos_error(e, &format!("{}:", drive.as_char()), "set_drive"))
    }

    /// Probes whether `drive` is mounted/valid in MS-DOS.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to inspect.
    ///
    /// # Returns
    /// `true` if `drive` is valid.
    fn is_drive_valid(&self, drive: DriveLetter) -> bool {
        self.sys.sys_is_drive_valid(drive)
    }

    /// Queries whether DOS 7 `INT 21h AX=71xxh` Long Filenames are active on `drive`.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to inspect.
    ///
    /// # Returns
    /// [`LfnSupportMode`] for `drive`.
    fn lfn_support_for_drive(&self, drive: DriveLetter) -> LfnSupportMode {
        self.sys.sys_lfn_mode(drive)
    }

    /// Queries the current working directory on `drive`.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to query.
    ///
    /// # Returns
    /// Canonical working directory path (`"C:\..."`).
    ///
    /// # Errors
    /// Returns [`CmdError`] if `drive` is invalid or not ready.
    fn drive_cwd(&self, drive: DriveLetter) -> Result<String, CmdError> {
        self.sys
            .sys_drive_cwd(drive)
            .map_err(|e| CmdError::from_dos_error(e, &format!("{}:", drive.as_char()), "drive_cwd"))
    }

    /// Changes the working directory (`chdir`) for the target path's drive.
    ///
    /// # Arguments
    /// * `path` - Target DOS directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `path` does not exist or is not a directory.
    fn set_drive_cwd(&mut self, path: &str) -> Result<(), CmdError> {
        self.sys
            .sys_set_drive_cwd(path)
            .map_err(|e| CmdError::from_dos_error(e, path, "set_drive_cwd"))
    }

    /// Queries free and total cluster capacity on `drive`.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to inspect.
    ///
    /// # Returns
    /// [`DosDiskSpace`] geometry and free byte counts.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `drive` is invalid or media is not ready.
    fn volume_space(&self, drive: DriveLetter) -> Result<DosDiskSpace, CmdError> {
        self.sys.sys_volume_space(drive).map_err(|e| {
            CmdError::from_dos_error(e, &format!("{}:", drive.as_char()), "volume_space")
        })
    }

    /// Queries volume label and `"XXXX-XXXX"` serial number for `drive`.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to inspect.
    ///
    /// # Returns
    /// `(label, serial)` tuple.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `drive` is invalid or media is not ready.
    fn volume_label_and_serial(&self, drive: DriveLetter) -> Result<(String, String), CmdError> {
        self.sys.sys_volume_label_and_serial(drive).map_err(|e| {
            CmdError::from_dos_error(e, &format!("{}:", drive.as_char()), "volume_label")
        })
    }

    /// Resolves `raw_path` via MS-DOS `INT 21h AH=60h` (`TRUENAME`).
    ///
    /// # Arguments
    /// * `raw_path` - Unnormalized DOS path.
    ///
    /// # Returns
    /// Canonical `X:\...` path.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `raw_path` references an invalid drive or malformed syntax.
    fn truename(&self, raw_path: &str) -> Result<String, CmdError> {
        self.sys
            .sys_truename(raw_path)
            .map_err(|e| CmdError::from_dos_error(e, raw_path, "truename"))
    }

    /// Reads the complete byte contents of `path`.
    ///
    /// # Arguments
    /// * `path` - File path on a DOS drive.
    ///
    /// # Returns
    /// Raw file bytes.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `path` is missing or unreadable.
    fn read_file_bytes(&self, path: &str) -> Result<Vec<u8>, CmdError> {
        self.sys
            .sys_read_file_bytes(path)
            .map_err(|e| CmdError::from_dos_error(e, path, "read_file"))
    }

    /// Writes `data` to `path` using `mode` (`CreateTruncate` or `CreateOrAppend`).
    ///
    /// # Arguments
    /// * `path` - Target DOS file path.
    /// * `data` - Raw byte slice to write.
    /// * `mode` - [`DosWriteDisposition`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `path` is read-only, write-protected, or out of disk space.
    fn write_file_bytes(
        &mut self,
        path: &str,
        data: &[u8],
        mode: DosWriteDisposition,
    ) -> Result<(), CmdError> {
        self.sys
            .sys_write_file_bytes(path, data, mode)
            .map_err(|e| CmdError::from_dos_error(e, path, "write_file"))
    }

    /// Deletes a regular file at `path` (`INT 21h AH=41h`).
    ///
    /// # Arguments
    /// * `path` - File path to delete.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `path` is missing, a directory, or `READ_ONLY`.
    fn delete_file(&mut self, path: &str) -> Result<(), CmdError> {
        self.sys
            .sys_delete_file(path)
            .map_err(|e| CmdError::from_dos_error(e, path, "delete_file"))
    }

    /// Creates a single directory leaf at `path` (`INT 21h AH=39h`).
    ///
    /// # Arguments
    /// * `path` - New directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if parent is missing or `path` already exists.
    fn create_dir(&mut self, path: &str) -> Result<(), CmdError> {
        self.sys
            .sys_create_dir(path)
            .map_err(|e| CmdError::from_dos_error(e, path, "create_dir"))
    }

    /// Removes an empty directory at `path` (`INT 21h AH=3Ah`).
    ///
    /// # Arguments
    /// * `path` - Empty directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `path` is non-empty, active CWD, or missing.
    fn remove_dir(&mut self, path: &str) -> Result<(), CmdError> {
        self.sys
            .sys_remove_dir(path)
            .map_err(|e| CmdError::from_dos_error(e, path, "remove_dir"))
    }

    /// Renames `src` to `dst` on the same DOS volume (`INT 21h AH=56h`).
    ///
    /// # Arguments
    /// * `src` - Existing source path.
    /// * `dst` - Target destination path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] (`CrossesDevices` on cross-drive, or `AlreadyExists` / `FileNotFound`).
    fn rename_entry(&mut self, src: &str, dst: &str) -> Result<(), CmdError> {
        self.sys
            .sys_rename_entry(src, dst)
            .map_err(|e| CmdError::from_dos_error(e, src, "rename_entry"))
    }

    /// Queries FAT directory entry metadata for `path`.
    ///
    /// # Arguments
    /// * `path` - Target DOS file or directory path.
    ///
    /// # Returns
    /// [`DosStatRecord`] metadata.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `path` does not exist.
    fn stat_entry(&self, path: &str) -> Result<DosStatRecord, CmdError> {
        self.sys
            .sys_stat_entry(path)
            .map_err(|e| CmdError::from_dos_error(e, path, "stat_entry"))
    }

    /// Enumerates direct child entries of `dir_path` via `_dos_findfirst` / `_dos_findnext`.
    ///
    /// # Arguments
    /// * `dir_path` - Canonical DOS directory path.
    ///
    /// # Returns
    /// Vector of [`DosDirRecord`] items (excluding `.` and `..`).
    ///
    /// # Errors
    /// Returns [`CmdError`] if `dir_path` does not exist.
    fn read_dir_entries(&self, dir_path: &str) -> Result<Vec<DosDirRecord>, CmdError> {
        self.sys
            .sys_read_dir_entries(dir_path)
            .map_err(|e| CmdError::from_dos_error(e, dir_path, "read_dir"))
    }

    /// Queries raw FAT attributes for `path` (`INT 21h AX=4300h`).
    ///
    /// # Arguments
    /// * `path` - Target DOS path.
    ///
    /// # Returns
    /// [`FatAttributeByte`] bitmask.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `path` does not exist.
    fn get_attributes(&self, path: &str) -> Result<FatAttributeByte, CmdError> {
        self.sys
            .sys_get_attributes(path)
            .map_err(|e| CmdError::from_dos_error(e, path, "get_attributes"))
    }

    /// Updates raw FAT attributes on `path` (`INT 21h AX=4301h`).
    ///
    /// # Arguments
    /// * `path` - Target DOS path.
    /// * `attrs` - New [`FatAttributeByte`] flags.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `path` is missing or media is write-protected.
    fn set_attributes(&mut self, path: &str, attrs: FatAttributeByte) -> Result<(), CmdError> {
        self.sys
            .sys_set_attributes(path, attrs)
            .map_err(|e| CmdError::from_dos_error(e, path, "set_attributes"))
    }

    /// Updates the packed FAT modification timestamp on `path` (`INT 21h AX=5701h`).
    ///
    /// # Arguments
    /// * `path` - Target DOS file path.
    /// * `ts` - [`PackedDosTimestamp`] to apply.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] if `path` is missing or cannot be opened for timestamp update.
    fn set_timestamp(&mut self, path: &str, ts: PackedDosTimestamp) -> Result<(), CmdError> {
        self.sys
            .sys_set_timestamp(path, ts)
            .map_err(|e| CmdError::from_dos_error(e, path, "set_timestamp"))
    }

    /// Synchronously executes an external DOS `.COM`/`.EXE` child process (`INT 21h AH=4Bh`).
    ///
    /// # Arguments
    /// * `req` - [`DosExecChildSpec`] containing target program, PSP tail, env, and spool files.
    ///
    /// # Returns
    /// Child [`ExitCode`].
    ///
    /// # Errors
    /// Returns [`CmdError`] (`InsufficientMemory`, `FileNotFound`, or `AccessDenied`) on failure.
    fn exec_child(&mut self, req: &DosExecChildSpec) -> Result<ExitCode, CmdError> {
        let code = self
            .sys
            .sys_exec_child(req)
            .map_err(|e| CmdError::from_dos_error(e, &req.program_dos_path, "exec_child"))?;
        Ok(ExitCode::from(i32::from(code)))
    }

    /// Polls and clears any latched `Ctrl+C` / `Ctrl+Break` signal.
    ///
    /// # Returns
    /// [`InterruptState`].
    fn poll_ctrl_break(&mut self) -> InterruptState {
        self.sys.sys_poll_ctrl_break()
    }

    /// Reads the next interactive BIOS keystroke (`INT 16h AH=00h`).
    ///
    /// # Returns
    /// `Ok(Some(BiosKeyEvent))` or `Ok(None)` at EOF.
    ///
    /// # Errors
    /// Returns [`CmdError`] on console fault.
    fn read_console_key(&mut self) -> Result<Option<BiosKeyEvent>, CmdError> {
        self.sys
            .sys_read_console_key()
            .map_err(|e| CmdError::from_dos_error(e, "CON", "read_console_key"))
    }

    /// Queries VGA console `(columns, rows)` geometry.
    ///
    /// # Returns
    /// `(columns, rows)` tuple.
    fn console_geometry(&self) -> (u16, u16) {
        self.sys.sys_console_geometry()
    }

    /// Clears the VGA console screen with attribute `attr` (`INT 10h AH=06h` & `AH=02h`).
    ///
    /// # Arguments
    /// * `attr` - Packed VGA color byte (`(bg << 4) | fg`).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] on console failure.
    fn clear_console_screen(&mut self, attr: u8) -> Result<(), CmdError> {
        self.sys
            .sys_clear_console_screen(attr)
            .map_err(|e| CmdError::from_dos_error(e, "CON", "clear_screen"))
    }
}
