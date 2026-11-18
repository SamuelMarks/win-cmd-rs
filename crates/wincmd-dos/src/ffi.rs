//! Thin DJGPP `libc` and DPMI (`__dpmi_int`) FFI boundary for 32-bit Protected-Mode MS-DOS.
//!
//! All raw C symbol declarations (`malloc`, `free`, `realloc`, `_exit`, `read`, `write`, `isatty`,
//! `__dpmi_int`, `__dpmi_get_free_memory_information`, `_dos_getdiskfree`, `spawnvpe`, `fopen`,
//! `fread`, `fwrite`, `fflush`, `fclose`, `fileno`, `remove`, `mkdir`, `rmdir`, `rename`, `chdir`,
//! `_chmod`, `_dos_setftime`, `_dos_findfirst`, `_dos_findnext`, `_truename`, `_use_lfn`,
//! `bioskey`, `dup`, `dup2`, `close`, and `environ`) are isolated in this single module when
//! compiling for `target_os = "none"` (`targets/i586-pc-msdosdjgpp.json`), while exposing safe
//! traits ([`DjgppRawMemoryApi`] and [`DjgppSyscallApi`]) and pure decoders for deterministic
//! 100% host verification.

use alloc::string::String;
use alloc::vec::Vec;

use win_cmd_rs::dos::{
    BiosKeyEvent, DosDirRecord, DosDiskSpace, DosExecChildSpec, DosMemoryStats, DosOemVendor,
    DosStatRecord, DosVersion, DosWriteDisposition, FatAttributeByte, LfnSupportMode,
    PackedDosDate, PackedDosTime, PackedDosTimestamp,
};
use win_cmd_rs::types::{CodePage, DosExtendedError, DriveLetter, InterruptState, VerifyCopyMode};

/// Real-mode 8086 register transfer block matching DJGPP `<dpmi.h>` `__dpmi_regs` (`50` bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DpmiRegs {
    /// `EDI` register (`DI` in low 16 bits).
    pub edi: u32,
    /// `ESI` register (`SI` in low 16 bits).
    pub esi: u32,
    /// `EBP` register (`BP` in low 16 bits).
    pub ebp: u32,
    /// Reserved DPMI `PUSHA` slot (`0`).
    pub res: u32,
    /// `EBX` register (`BX` / `BH` / `BL`).
    pub ebx: u32,
    /// `EDX` register (`DX` / `DH` / `DL`).
    pub edx: u32,
    /// `ECX` register (`CX` / `CH` / `CL`).
    pub ecx: u32,
    /// `EAX` register (`AX` / `AH` / `AL`).
    pub eax: u32,
    /// Real-mode `FLAGS` (`CF` is bit `0`).
    pub flags: u16,
    /// Real-mode `ES` segment.
    pub es: u16,
    /// Real-mode `DS` segment.
    pub ds: u16,
    /// Real-mode `FS` segment.
    pub fs: u16,
    /// Real-mode `GS` segment.
    pub gs: u16,
    /// Real-mode `IP` instruction pointer (unused for `INT` calls).
    pub ip: u16,
    /// Real-mode `CS` code segment (unused for `INT` calls).
    pub cs: u16,
    /// Real-mode `SP` stack pointer (`0` lets DPMI host allocate a real-mode stack).
    pub sp: u16,
    /// Real-mode `SS` stack segment (`0` lets DPMI host allocate a real-mode stack).
    pub ss: u16,
}

impl DpmiRegs {
    /// Returns `true` when the real-mode Carry Flag (`FLAGS` bit `0`) is set after `__dpmi_int`.
    ///
    /// # Returns
    /// `true` if `CF == 1` (indicating an MS-DOS `INT 21h` error in `AX`).
    #[must_use]
    pub const fn carry_set(&self) -> bool {
        (self.flags & 1) != 0
    }
}

/// Low-level raw heap memory primitives (`malloc`, `realloc`, `free`) consumed by [`crate::alloc_djgpp::DjgppAllocator`].
pub trait DjgppRawMemoryApi {
    /// Allocates `size` uninitialized bytes aligned to at least `8` bytes.
    ///
    /// # Arguments
    /// * `size` - Requested allocation byte count (`> 0`).
    ///
    /// # Returns
    /// Non-null pointer on success, or `core::ptr::null_mut()` on out-of-memory.
    fn raw_malloc(&self, size: usize) -> *mut u8;

    /// Resizes a previously `raw_malloc`-allocated block to `new_size` bytes.
    ///
    /// # Arguments
    /// * `ptr` - Pointer previously returned by `raw_malloc` or `raw_realloc`.
    /// * `new_size` - New byte count (`> 0`).
    ///
    /// # Returns
    /// Resized pointer on success, or `core::ptr::null_mut()` on out-of-memory (leaving `ptr` intact).
    ///
    /// # Safety
    /// `ptr` must have been allocated by the same [`DjgppRawMemoryApi`] implementation and not yet freed.
    unsafe fn raw_realloc(&self, ptr: *mut u8, new_size: usize) -> *mut u8;

    /// Releases a block previously returned by `raw_malloc` or `raw_realloc`.
    ///
    /// # Arguments
    /// * `ptr` - Pointer to free (or null, which is a no-op).
    ///
    /// # Safety
    /// `ptr` must be null or have been returned by `raw_malloc`/`raw_realloc` on this allocator and not yet freed.
    unsafe fn raw_free(&self, ptr: *mut u8);
}

/// Low-level DJGPP `libc` + DPMI syscall surface consumed by [`crate::djgpp_kernel::DjgppDosKernel`].
pub trait DjgppSyscallApi: core::fmt::Debug + Clone + 'static {
    /// Queries MS-DOS major/minor version (`INT 21h AH=30h`).
    ///
    /// # Returns
    /// Active [`DosVersion`].
    fn sys_dos_version(&self) -> DosVersion;

    /// Queries active `NLSFUNC` codepage (`INT 21h AX=6601h`).
    ///
    /// # Returns
    /// Active [`CodePage`].
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if `NLSFUNC` returns an error.
    fn sys_active_codepage(&self) -> Result<CodePage, DosExtendedError>;

    /// Switches active `NLSFUNC` codepage (`INT 21h AX=6602h`).
    ///
    /// # Arguments
    /// * `cp` - Target [`CodePage`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if unprepared or unsupported.
    fn sys_set_codepage(&mut self, cp: CodePage) -> Result<(), DosExtendedError>;

    /// Queries DOS RTC date and time (`INT 21h AH=2Ah` & `AH=2Ch`).
    ///
    /// # Returns
    /// `(PackedDosDate, PackedDosTime)` wall-clock snapshot.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] on RTC read error.
    fn sys_get_datetime(&self) -> Result<(PackedDosDate, PackedDosTime), DosExtendedError>;

    /// Sets DOS RTC date (`INT 21h AH=2Bh`).
    ///
    /// # Arguments
    /// * `year` - Year (`1980..=2099`).
    /// * `month` - Month (`1..=12`).
    /// * `day` - Day (`1..=31`).
    ///
    /// # Returns
    /// `Ok(())` if accepted by DOS.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] (`0x000D`) if rejected.
    fn sys_set_date(&mut self, year: u16, month: u8, day: u8) -> Result<(), DosExtendedError>;

    /// Sets DOS RTC time (`INT 21h AH=2Dh`).
    ///
    /// # Arguments
    /// * `hour` - Hour (`0..=23`).
    /// * `minute` - Minute (`0..=59`).
    /// * `second` - Second (`0..=59`).
    /// * `centisec` - Centiseconds (`0..=99`).
    ///
    /// # Returns
    /// `Ok(())` if accepted by DOS.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] (`0x000D`) if rejected.
    fn sys_set_time(
        &mut self,
        hour: u8,
        minute: u8,
        second: u8,
        centisec: u8,
    ) -> Result<(), DosExtendedError>;

    /// Queries the global DOS `VERIFY` flag (`INT 21h AH=54h`).
    ///
    /// # Returns
    /// [`VerifyCopyMode`].
    fn sys_verify_flag(&self) -> VerifyCopyMode;

    /// Sets the global DOS `VERIFY` flag (`INT 21h AH=2Eh`).
    ///
    /// # Arguments
    /// * `mode` - [`VerifyCopyMode`].
    fn sys_set_verify_flag(&mut self, mode: VerifyCopyMode);

    /// Queries conventional + DPMI memory statistics (`INT 31h AX=0500h` + `INT 21h AH=48h`).
    ///
    /// # Returns
    /// `Ok(DosMemoryStats)`.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] on DPMI query failure.
    fn sys_memory_stats(&self) -> Result<DosMemoryStats, DosExtendedError>;

    /// Reads inherited startup `(KEY, VALUE)` environment variables.
    ///
    /// # Returns
    /// `Ok(Vec<(String, String)>)`.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if reading the PSP environment fails.
    fn sys_startup_env(&self) -> Result<Vec<(String, String)>, DosExtendedError>;

    /// Reads inherited startup `argv[1..]` tokens.
    ///
    /// # Returns
    /// `Ok(Vec<String>)`.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if reading startup arguments fails.
    fn sys_startup_argv(&self) -> Result<Vec<String>, DosExtendedError>;

    /// Queries the default DOS drive (`INT 21h AH=19h`).
    ///
    /// # Returns
    /// Active [`DriveLetter`].
    fn sys_current_drive(&self) -> DriveLetter;

    /// Sets the default DOS drive (`INT 21h AH=0Eh`).
    ///
    /// # Arguments
    /// * `drive` - Target [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(())` if valid.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] (`0x000F`) if invalid.
    fn sys_set_drive(&mut self, drive: DriveLetter) -> Result<(), DosExtendedError>;

    /// Probes whether `drive` is present (`_dos_getdiskfree`).
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to probe.
    ///
    /// # Returns
    /// `true` if `drive` exists.
    fn sys_is_drive_valid(&self, drive: DriveLetter) -> bool;

    /// Queries whether `drive` supports DOS 7 LFNs (`_use_lfn`).
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`] to probe.
    ///
    /// # Returns
    /// [`LfnSupportMode`].
    fn sys_lfn_mode(&self, drive: DriveLetter) -> LfnSupportMode;

    /// Queries current working directory `"X:\..."` on `drive`.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`].
    ///
    /// # Returns
    /// `Ok(String)` (`"C:"` or `"C:\DOS"`).
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] on invalid/not-ready drive.
    fn sys_drive_cwd(&self, drive: DriveLetter) -> Result<String, DosExtendedError>;

    /// Changes current working directory (`chdir`).
    ///
    /// # Arguments
    /// * `path` - Target DOS directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if missing or not a directory.
    fn sys_set_drive_cwd(&mut self, path: &str) -> Result<(), DosExtendedError>;

    /// Queries free and total bytes on `drive` (`_dos_getdiskfree`).
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`].
    ///
    /// # Returns
    /// [`DosDiskSpace`].
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] on invalid/not-ready drive.
    fn sys_volume_space(&self, drive: DriveLetter) -> Result<DosDiskSpace, DosExtendedError>;

    /// Queries volume label and `"XXXX-XXXX"` serial on `drive`.
    ///
    /// # Arguments
    /// * `drive` - [`DriveLetter`].
    ///
    /// # Returns
    /// `(label, serial)`.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] on invalid/not-ready drive.
    fn sys_volume_label_and_serial(
        &self,
        drive: DriveLetter,
    ) -> Result<(String, String), DosExtendedError>;

    /// Canonicalizes `path` via `INT 21h AH=60h` (`_truename`).
    ///
    /// # Arguments
    /// * `path` - Raw DOS path.
    ///
    /// # Returns
    /// Canonical `X:\...` string.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] on invalid drive/syntax.
    fn sys_truename(&self, path: &str) -> Result<String, DosExtendedError>;

    /// Reads all bytes of `path`.
    ///
    /// # Arguments
    /// * `path` - File path.
    ///
    /// # Returns
    /// Raw byte vector.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] on missing file or I/O failure.
    fn sys_read_file_bytes(&self, path: &str) -> Result<Vec<u8>, DosExtendedError>;

    /// Writes `data` to `path` using `mode`.
    ///
    /// # Arguments
    /// * `path` - Destination path.
    /// * `data` - Raw byte slice.
    /// * `mode` - [`DosWriteDisposition`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] on read-only target or full disk.
    fn sys_write_file_bytes(
        &mut self,
        path: &str,
        data: &[u8],
        mode: DosWriteDisposition,
    ) -> Result<(), DosExtendedError>;

    /// Deletes a regular file (`remove`).
    ///
    /// # Arguments
    /// * `path` - File path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if missing or read-only.
    fn sys_delete_file(&mut self, path: &str) -> Result<(), DosExtendedError>;

    /// Creates a directory (`mkdir`).
    ///
    /// # Arguments
    /// * `path` - Directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if parent missing or exists.
    fn sys_create_dir(&mut self, path: &str) -> Result<(), DosExtendedError>;

    /// Removes an empty directory (`rmdir`).
    ///
    /// # Arguments
    /// * `path` - Directory path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if non-empty, active CWD, or missing.
    fn sys_remove_dir(&mut self, path: &str) -> Result<(), DosExtendedError>;

    /// Renames `src` to `dst` on the same drive (`rename`).
    ///
    /// # Arguments
    /// * `src` - Source path.
    /// * `dst` - Destination path.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] (`0x0011` on cross-drive).
    fn sys_rename_entry(&mut self, src: &str, dst: &str) -> Result<(), DosExtendedError>;

    /// Queries metadata of `path` (`_dos_findfirst`).
    ///
    /// # Arguments
    /// * `path` - Target DOS path.
    ///
    /// # Returns
    /// [`DosStatRecord`].
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if missing.
    fn sys_stat_entry(&self, path: &str) -> Result<DosStatRecord, DosExtendedError>;

    /// Enumerates direct child entries of `dir_path` (excluding `.` and `..`).
    ///
    /// # Arguments
    /// * `dir_path` - Canonical DOS directory path.
    ///
    /// # Returns
    /// `Vec<DosDirRecord>`.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if `dir_path` is missing.
    fn sys_read_dir_entries(&self, dir_path: &str) -> Result<Vec<DosDirRecord>, DosExtendedError>;

    /// Queries FAT attribute bits (`_chmod(path, 0, 0)`).
    ///
    /// # Arguments
    /// * `path` - Target DOS path.
    ///
    /// # Returns
    /// [`FatAttributeByte`].
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if missing.
    fn sys_get_attributes(&self, path: &str) -> Result<FatAttributeByte, DosExtendedError>;

    /// Sets FAT attribute bits (`_chmod(path, 1, attr)`).
    ///
    /// # Arguments
    /// * `path` - Target DOS path.
    /// * `attrs` - [`FatAttributeByte`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if missing or write-protected.
    fn sys_set_attributes(
        &mut self,
        path: &str,
        attrs: FatAttributeByte,
    ) -> Result<(), DosExtendedError>;

    /// Sets packed modification timestamp (`_dos_setftime`).
    ///
    /// # Arguments
    /// * `path` - File path.
    /// * `ts` - [`PackedDosTimestamp`].
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if missing or directory.
    fn sys_set_timestamp(
        &mut self,
        path: &str,
        ts: PackedDosTimestamp,
    ) -> Result<(), DosExtendedError>;

    /// Spawns a synchronous child DOS/DPMI executable (`spawnvpe`).
    ///
    /// # Arguments
    /// * `req` - [`DosExecChildSpec`].
    ///
    /// # Returns
    /// Child return code (`0..=255`).
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] if missing or out of memory.
    fn sys_exec_child(&mut self, req: &DosExecChildSpec) -> Result<u8, DosExtendedError>;

    /// Polls and clears latched `Ctrl+C` / `Ctrl+Break`.
    ///
    /// # Returns
    /// [`InterruptState`].
    fn sys_poll_ctrl_break(&mut self) -> InterruptState;

    /// Reads next BIOS keystroke (`INT 16h AH=00h`), or `Ok(None)` on EOF.
    ///
    /// # Returns
    /// `Ok(Option<BiosKeyEvent>)`.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] on console fault.
    fn sys_read_console_key(&mut self) -> Result<Option<BiosKeyEvent>, DosExtendedError>;

    /// Queries console `(columns, rows)` geometry (`80x25` default).
    ///
    /// # Returns
    /// `(columns, rows)` tuple.
    fn sys_console_geometry(&self) -> (u16, u16);

    /// Clears VGA text-mode screen with packed attribute `attr` (`INT 10h AH=06h` + `AH=02h`).
    ///
    /// # Arguments
    /// * `attr` - Packed VGA color byte (`(bg << 4) | fg`).
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] on console failure.
    fn sys_clear_console_screen(&mut self, attr: u8) -> Result<(), DosExtendedError>;

    /// Writes raw OEM bytes to DOS file handle `1` (`STDOUT`) or `2` (`STDERR`).
    ///
    /// # Arguments
    /// * `handle` - DOS file handle (`1` or `2`).
    /// * `bytes` - Raw byte slice.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`DosExtendedError`] on write failure.
    fn sys_write_handle(&mut self, handle: u8, bytes: &[u8]) -> Result<(), DosExtendedError>;
}

/// Decodes a NUL-terminated raw byte slice (`argv[i]`) into a UTF-8 `String` (skipping `argv[0]`).
///
/// # Arguments
/// * `raw_slices` - Slice of raw byte slices representing `argv[0..argc]`.
///
/// # Returns
/// Decoded `Vec<String>` for `argv[1..argc]`.
#[must_use]
pub fn decode_argv_slices(raw_slices: &[&[u8]]) -> Vec<String> {
    let mut out = Vec::with_capacity(raw_slices.len().saturating_sub(1));
    for raw in raw_slices.iter().skip(1) {
        let nul_pos = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let trimmed = raw.get(..nul_pos).unwrap_or(raw);
        let mut s = String::with_capacity(trimmed.len());
        for &b in trimmed {
            s.push(char::from(b));
        }
        out.push(s);
    }
    out
}

/// Decodes `KEY=VALUE` byte slices from a DOS/DJGPP `environ` vector into `(KEY, VALUE)` pairs.
///
/// # Arguments
/// * `raw_entries` - Slice of raw `KEY=VALUE` byte slices (optionally NUL-terminated).
///
/// # Returns
/// Parsed `(key, value)` environment pairs (ignoring malformed entries without `'='` or empty keys).
#[must_use]
pub fn decode_envp_slices(raw_entries: &[&[u8]]) -> Vec<(String, String)> {
    let mut pairs = Vec::with_capacity(raw_entries.len());
    for raw in raw_entries {
        let nul_pos = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let trimmed = raw.get(..nul_pos).unwrap_or(raw);
        if let Some(eq_idx) = trimmed.iter().position(|&b| b == b'=')
            && eq_idx > 0
        {
            let key_bytes = trimmed.get(..eq_idx).unwrap_or(&[]);
            let val_bytes = trimmed.get(eq_idx.saturating_add(1)..).unwrap_or(&[]);
            let mut key = String::with_capacity(key_bytes.len());
            for &b in key_bytes {
                key.push(char::from(b));
            }
            let mut val = String::with_capacity(val_bytes.len());
            for &b in val_bytes {
                val.push(char::from(b));
            }
            pairs.push((key, val));
        }
    }
    pairs
}

/// Decodes `INT 21h AX=3000h` `EAX`/`EBX` return registers into a strongly typed [`DosVersion`].
///
/// # Arguments
/// * `eax` - Returned `EAX` register (`AL` = major version, `AH` = minor version).
/// * `ebx` - Returned `EBX` register (`BH` = OEM vendor byte).
///
/// # Returns
/// Decoded [`DosVersion`].
#[must_use]
pub const fn decode_dos_version_regs(eax: u32, ebx: u32) -> DosVersion {
    let [major, minor, _, _] = eax.to_le_bytes();
    let [_, bh, _, _] = ebx.to_le_bytes();
    let oem_id = match bh {
        0x00 => DosOemVendor::PcDos,
        0xFD => DosOemVendor::FreeDos,
        0xEE => DosOemVendor::DrDos,
        0xFF if major >= 7 => DosOemVendor::Windows9xDos7,
        0xFF => DosOemVendor::MsDos,
        other => DosOemVendor::Unknown(other),
    };
    DosVersion {
        major: if major == 0 { 6 } else { major },
        minor,
        oem_id,
    }
}

#[cfg(not(feature = "host-sim"))]
/// Live DJGPP `libc` raw C symbol declarations and [`DjgppSyscallApi`] implementation linked via `i586-pc-msdosdjgpp-gcc`.
pub mod djgpp_c {
    use alloc::borrow::ToOwned;
    use alloc::ffi::CString;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::ptr;

    use win_cmd_rs::dos::{
        BiosKeyEvent, BiosScanCode, DosDirRecord, DosDiskSpace, DosExecChildSpec, DosFileName8Dot3,
        DosMemoryStats, DosStatRecord, DosVersion, DosWriteDisposition, FatAttributeByte,
        LfnSupportMode, PackedDosDate, PackedDosTime, PackedDosTimestamp, ShortNamePolicy,
    };
    use win_cmd_rs::types::{
        BS_CHAR, BS_STR, CodePage, DosErrorCode, DosExtendedError, DriveLetter, InterruptState,
        VerifyCopyMode,
    };

    use super::{
        DjgppRawMemoryApi, DjgppSyscallApi, DpmiRegs, decode_argv_slices, decode_dos_version_regs,
        decode_envp_slices,
    };

    /// Opaque C `<stdio.h>` `FILE` stream handle.
    #[repr(C)]
    pub struct CFile {
        /// Private zero-sized marker field.
        _priv: [u8; 0],
    }

    /// DJGPP `<dos.h>` `struct _find_t` (`INT 21h AH=4Eh` DTA layout).
    #[repr(C, packed)]
    pub struct DosFindT {
        /// DOS internal search state (`21` bytes).
        pub reserved: [u8; 21],
        /// Matched [`FatAttributeByte`] bits.
        pub attrib: u8,
        /// Packed DOS modification time.
        pub wr_time: u16,
        /// Packed DOS modification date.
        pub wr_date: u16,
        /// 32-bit file size in bytes.
        pub size: u32,
        /// NUL-terminated matched filename (`13` bytes on FAT16, up to `256` with LFN).
        pub name: [u8; 256],
    }

    /// DJGPP `<dos.h>` `struct _diskfree_t` (`INT 21h AH=36h`).
    #[repr(C)]
    pub struct DosDiskFreeT {
        /// Total clusters on volume.
        pub total_clusters: u16,
        /// Free clusters on volume.
        pub avail_clusters: u16,
        /// Sectors per cluster.
        pub sectors_per_cluster: u16,
        /// Bytes per sector.
        pub bytes_per_sector: u16,
    }

    // SAFETY: Standard DJGPP `libc.a` functions and globals adhering to 32-bit x86 `cdecl` ABI under CWSDPMI.
    unsafe extern "C" {
        /// Global NUL-terminated C environment vector populated by DJGPP `crt0.o`.
        pub static environ: *const *const u8;

        /// Allocates `size` bytes on the DJGPP heap.
        ///
        /// # Arguments
        /// * `size` - Byte count to allocate.
        ///
        /// # Returns
        /// Heap pointer or null on OOM.
        pub fn malloc(size: usize) -> *mut u8;

        /// Resizes `ptr` to `new_size` bytes on the DJGPP heap.
        ///
        /// # Arguments
        /// * `ptr` - Existing heap pointer.
        /// * `new_size` - Requested byte size.
        ///
        /// # Returns
        /// Resized heap pointer or null on OOM.
        pub fn realloc(ptr: *mut u8, new_size: usize) -> *mut u8;

        /// Frees `ptr` on the DJGPP heap.
        ///
        /// # Arguments
        /// * `ptr` - Heap pointer or null.
        pub fn free(ptr: *mut u8);

        /// Reads up to `count` bytes from DOS file descriptor `fd` into `buf`.
        ///
        /// # Arguments
        /// * `fd` - File descriptor (`0` = `STDIN`).
        /// * `buf` - Writable byte buffer.
        /// * `count` - Maximum bytes to read.
        ///
        /// # Returns
        /// Bytes read (`0` on EOF, `< 0` on error).
        pub fn read(fd: i32, buf: *mut u8, count: usize) -> isize;

        /// Writes `count` bytes from `buf` to DOS file descriptor `fd`.
        ///
        /// # Arguments
        /// * `fd` - File descriptor (`1` = `STDOUT`, `2` = `STDERR`).
        /// * `buf` - Source byte pointer.
        /// * `count` - Byte count to write.
        ///
        /// # Returns
        /// Bytes written or `< 0` on error.
        pub fn write(fd: i32, buf: *const u8, count: usize) -> isize;

        /// Tests whether `fd` refers to a character console TTY (`1`) or a redirected file/pipe (`0`).
        ///
        /// # Arguments
        /// * `fd` - File descriptor to inspect.
        ///
        /// # Returns
        /// Non-zero when `fd` is an interactive character device, `0` when redirected.
        pub fn isatty(fd: i32) -> i32;

        /// Terminates the DPMI process immediately via `INT 21h AH=4Ch`.
        ///
        /// # Arguments
        /// * `status` - Low-byte DOS exit code.
        ///
        /// # Returns
        /// Diverges without running destructors.
        pub fn _exit(status: i32) -> !;

        /// Invokes real-mode software interrupt `vector` through DPMI `INT 31h AX=0300h`.
        ///
        /// # Arguments
        /// * `vector` - Real-mode interrupt number (`0x10`, `0x16`, `0x21`).
        /// * `regs` - Mutable [`DpmiRegs`] register block.
        ///
        /// # Returns
        /// `0` on DPMI success or non-zero on host fault.
        pub fn __dpmi_int(vector: i32, regs: *mut DpmiRegs) -> i32;

        /// Queries DPMI `INT 31h AX=0500h` extended memory statistics.
        ///
        /// # Arguments
        /// * `info` - Pointer to 12-`u32` (`48`-byte) output structure.
        ///
        /// # Returns
        /// `0` on success.
        pub fn __dpmi_get_free_memory_information(info: *mut [u32; 12]) -> i32;

        /// Opens `path` as a buffered C `FILE` stream.
        ///
        /// # Arguments
        /// * `path` - NUL-terminated DOS path.
        /// * `mode` - NUL-terminated mode string (`"rb"`, `"wb"`, `"ab"`).
        ///
        /// # Returns
        /// Non-null `*mut CFile` or null on failure.
        pub fn fopen(path: *const u8, mode: *const u8) -> *mut CFile;

        /// Reads up to `nmemb` elements of `size` bytes from `stream`.
        ///
        /// # Arguments
        /// * `ptr` - Destination buffer.
        /// * `size` - Element size in bytes.
        /// * `nmemb` - Element count.
        /// * `stream` - Open `*mut CFile`.
        ///
        /// # Returns
        /// Number of elements read.
        pub fn fread(ptr: *mut u8, size: usize, nmemb: usize, stream: *mut CFile) -> usize;

        /// Writes `nmemb` elements of `size` bytes to `stream`.
        ///
        /// # Arguments
        /// * `ptr` - Source buffer.
        /// * `size` - Element size in bytes.
        /// * `nmemb` - Element count.
        /// * `stream` - Open `*mut CFile`.
        ///
        /// # Returns
        /// Number of elements written.
        pub fn fwrite(ptr: *const u8, size: usize, nmemb: usize, stream: *mut CFile) -> usize;

        /// Flushes `stream` (or all open `FILE` streams when `stream` is null).
        ///
        /// # Arguments
        /// * `stream` - Target `*mut CFile` or null.
        ///
        /// # Returns
        /// `0` on success.
        pub fn fflush(stream: *mut CFile) -> i32;

        /// Closes an open C `FILE` stream.
        ///
        /// # Arguments
        /// * `stream` - Open `*mut CFile`.
        ///
        /// # Returns
        /// `0` on success.
        pub fn fclose(stream: *mut CFile) -> i32;

        /// Extracts the underlying DOS file descriptor for `stream`.
        ///
        /// # Arguments
        /// * `stream` - Open `*mut CFile`.
        ///
        /// # Returns
        /// Non-negative file descriptor.
        pub fn fileno(stream: *mut CFile) -> i32;

        /// Deletes a file (`INT 21h AH=41h`).
        ///
        /// # Arguments
        /// * `path` - NUL-terminated file path.
        ///
        /// # Returns
        /// `0` on success, `-1` on failure.
        pub fn remove(path: *const u8) -> i32;

        /// Creates a directory (`INT 21h AH=39h`).
        ///
        /// # Arguments
        /// * `path` - NUL-terminated directory path.
        /// * `mode` - POSIX permission mask (`0o777`).
        ///
        /// # Returns
        /// `0` on success, `-1` on failure.
        pub fn mkdir(path: *const u8, mode: i32) -> i32;

        /// Removes an empty directory (`INT 21h AH=3Ah`).
        ///
        /// # Arguments
        /// * `path` - NUL-terminated directory path.
        ///
        /// # Returns
        /// `0` on success, `-1` on failure.
        pub fn rmdir(path: *const u8) -> i32;

        /// Renames `from` to `to` (`INT 21h AH=56h`).
        ///
        /// # Arguments
        /// * `from` - Source NUL-terminated path.
        /// * `to` - Destination NUL-terminated path.
        ///
        /// # Returns
        /// `0` on success, `-1` on failure.
        pub fn rename(from: *const u8, to: *const u8) -> i32;

        /// Changes current working directory (`INT 21h AH=3Bh`).
        ///
        /// # Arguments
        /// * `path` - Target NUL-terminated directory path.
        ///
        /// # Returns
        /// `0` on success, `-1` on failure.
        pub fn chdir(path: *const u8) -> i32;

        /// Gets or sets DOS FAT attributes (`INT 21h AX=4300h/4301h`).
        ///
        /// # Arguments
        /// * `path` - Target NUL-terminated path.
        /// * `func` - `0` to query, `1` to set.
        /// * `attr` - Attribute byte when `func == 1`.
        ///
        /// # Returns
        /// Attribute mask or `-1` on failure.
        pub fn _chmod(path: *const u8, func: i32, attr: i32) -> i32;

        /// Sets packed DOS modification date and time on `fd` (`INT 21h AX=5701h`).
        ///
        /// # Arguments
        /// * `fd` - Open DOS file handle.
        /// * `date` - Packed DOS date word.
        /// * `time` - Packed DOS time word.
        ///
        /// # Returns
        /// `0` on success or DOS error code.
        pub fn _dos_setftime(fd: i32, date: u32, time: u32) -> u32;

        /// Starts a DOS directory enumeration (`INT 21h AH=4Eh` / `AX=714Eh`).
        ///
        /// # Arguments
        /// * `pattern` - NUL-terminated wildcard/path pattern.
        /// * `attr` - Attribute search mask.
        /// * `result` - Output [`DosFindT`] DTA buffer.
        ///
        /// # Returns
        /// `0` on match or DOS error code (`0x12` = no more files).
        pub fn _dos_findfirst(pattern: *const u8, attr: u32, result: *mut DosFindT) -> u32;

        /// Continues a DOS directory enumeration (`INT 21h AH=4Fh` / `AX=714Fh`).
        ///
        /// # Arguments
        /// * `result` - Active [`DosFindT`] DTA buffer.
        ///
        /// # Returns
        /// `0` on match or `0x12` when exhausted.
        pub fn _dos_findnext(result: *mut DosFindT) -> u32;

        /// Queries volume cluster geometry (`INT 21h AH=36h`).
        ///
        /// # Arguments
        /// * `drive` - 1-based drive number (`1` = `A:`, `3` = `C:`).
        /// * `diskspace` - Output [`DosDiskFreeT`] record.
        ///
        /// # Returns
        /// `0` on success or non-zero on invalid drive.
        pub fn _dos_getdiskfree(drive: u32, diskspace: *mut DosDiskFreeT) -> u32;

        /// Resolves canonical `TRUENAME` (`INT 21h AH=60h`).
        ///
        /// # Arguments
        /// * `path` - Input NUL-terminated path.
        /// * `out` - 260-byte output buffer.
        ///
        /// # Returns
        /// `out` pointer on success or null on failure.
        pub fn _truename(path: *const u8, out: *mut u8) -> *mut u8;

        /// Probes whether DOS 7 LFN APIs (`INT 21h AX=71xxh`) are supported for `path`.
        ///
        /// # Arguments
        /// * `path` - NUL-terminated root path (`"C:"`).
        ///
        /// # Returns
        /// Non-zero when LFN is active, `0` for strict 8.3 FAT.
        pub fn _use_lfn(path: *const u8) -> i32;

        /// Queries BIOS keyboard service (`INT 16h`).
        ///
        /// # Arguments
        /// * `cmd` - `bioskey` command (`0` = read keystroke).
        ///
        /// # Returns
        /// `(scan_code << 8) | ascii_char`.
        pub fn bioskey(cmd: i32) -> i32;

        /// Duplicates file descriptor `fd`.
        ///
        /// # Arguments
        /// * `fd` - Existing file descriptor.
        ///
        /// # Returns
        /// New descriptor or `-1` on error.
        pub fn dup(fd: i32) -> i32;

        /// Redirects `newfd` to refer to `oldfd`.
        ///
        /// # Arguments
        /// * `oldfd` - Source file descriptor.
        /// * `newfd` - Target standard handle (`0`, `1`, `2`).
        ///
        /// # Returns
        /// `0` on success or `-1` on error.
        pub fn dup2(oldfd: i32, newfd: i32) -> i32;

        /// Closes file descriptor `fd`.
        ///
        /// # Arguments
        /// * `fd` - File descriptor to close.
        ///
        /// # Returns
        /// `0` on success or `-1` on error.
        pub fn close(fd: i32) -> i32;

        /// Synchronously spawns a child DOS/DPMI program (`P_WAIT == 1` in DJGPP `<process.h>`).
        ///
        /// # Arguments
        /// * `mode` - Spawn mode (`1` = `P_WAIT`).
        /// * `path` - NUL-terminated program path.
        /// * `argv` - Null-terminated argument pointer array.
        /// * `envp` - Null-terminated `KEY=VALUE` environment pointer array.
        ///
        /// # Returns
        /// Child exit status (`0..=255`) or `-1` on spawn error.
        pub fn spawnvpe(
            mode: i32,
            path: *const u8,
            argv: *const *const u8,
            envp: *const *const u8,
        ) -> i32;
    }

    /// Writes `bytes` directly to DOS `STDERR` (handle `2`) and terminates with status `255`.
    ///
    /// # Arguments
    /// * `bytes` - Stack-formatted diagnostic bytes.
    ///
    /// # Returns
    /// Diverges via `_exit(255)`.
    pub fn abort_to_dos_stderr(bytes: &[u8]) -> ! {
        // SAFETY: `bytes` is a valid stack slice; handle `2` is DOS STDERR; `_exit(255)` terminates cleanly.
        unsafe {
            let _written = write(2, bytes.as_ptr(), bytes.len());
            _exit(255);
        }
    }

    /// Reads all bytes from DOS handle `0` (`STDIN`) when `STDIN` is redirected to a file or pipe (`isatty(0) == 0`).
    ///
    /// # Returns
    /// Buffered `STDIN` bytes, or an empty `Vec` when `STDIN` is an interactive console TTY.
    #[must_use]
    pub fn read_piped_stdin_if_redirected() -> Vec<u8> {
        // SAFETY: `isatty(0)` inspects DOS handle `0` device info word without dereferencing pointers.
        if unsafe { isatty(0) } != 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            // SAFETY: `chunk` is 1024 writable stack bytes; handle `0` is `STDIN`.
            let n = unsafe { read(0, chunk.as_mut_ptr(), chunk.len()) };
            if n <= 0 {
                break;
            }
            let count = usize::try_from(n).unwrap_or(0);
            if let Some(part) = chunk.get(..count) {
                out.extend_from_slice(part);
            }
        }
        out
    }

    /// Collects DJGPP `main(arg_count, arg_ptrs)` C strings into `Vec<String>` (excluding `argv[0]`).
    ///
    /// # Arguments
    /// * `arg_count` - Argument count from DJGPP `crt0.o`.
    /// * `arg_ptrs` - Pointer to `arg_count` NUL-terminated C string pointers.
    ///
    /// # Returns
    /// Decoded `argv[1..arg_count]` strings.
    ///
    /// # Safety
    /// `arg_ptrs` must point to at least `arg_count.max(0)` valid NUL-terminated C strings.
    #[must_use]
    pub unsafe fn collect_djgpp_args(arg_count: i32, arg_ptrs: *const *const u8) -> Vec<String> {
        if arg_count <= 1 || arg_ptrs.is_null() {
            return Vec::new();
        }
        let count = usize::try_from(arg_count).unwrap_or(0);
        let mut slices: Vec<&[u8]> = Vec::with_capacity(count);
        for idx in 0..count {
            // SAFETY: `idx < count == arg_count` and `arg_ptrs` is valid for `arg_count` pointers.
            let p = unsafe { *arg_ptrs.add(idx) };
            if p.is_null() {
                slices.push(&[]);
            } else {
                let mut len = 0usize;
                // SAFETY: `p` is a NUL-terminated C string supplied by DJGPP startup code.
                while unsafe { *p.add(len) } != 0 {
                    len = len.saturating_add(1);
                }
                // SAFETY: `p[..len]` is valid and non-NUL.
                slices.push(unsafe { core::slice::from_raw_parts(p, len) });
            }
        }
        decode_argv_slices(&slices)
    }

    /// Production [`DjgppRawMemoryApi`] backed directly by DJGPP `libc.a` (`malloc`/`realloc`/`free`).
    #[derive(Debug, Clone, Copy, Default)]
    pub struct DjgppLibcMemory;

    impl DjgppRawMemoryApi for DjgppLibcMemory {
        /// Allocates `size` bytes via DJGPP `malloc`.
        ///
        /// # Arguments
        /// * `size` - Requested allocation byte count.
        ///
        /// # Returns
        /// Allocated pointer or null on OOM.
        fn raw_malloc(&self, size: usize) -> *mut u8 {
            // SAFETY: `malloc` accepts any `size` and returns a valid 8-byte aligned pointer or null.
            unsafe { malloc(size) }
        }

        /// Resizes `ptr` to `new_size` via DJGPP `realloc`.
        ///
        /// # Arguments
        /// * `ptr` - Existing allocation pointer.
        /// * `new_size` - Requested byte size.
        ///
        /// # Returns
        /// Resized pointer or null on OOM.
        ///
        /// # Safety
        /// `ptr` must have been allocated by `DjgppLibcMemory`.
        unsafe fn raw_realloc(&self, ptr: *mut u8, new_size: usize) -> *mut u8 {
            // SAFETY: Caller upholds `DjgppRawMemoryApi::raw_realloc` pointer provenance invariant.
            unsafe { realloc(ptr, new_size) }
        }

        /// Frees `ptr` via DJGPP `free`.
        ///
        /// # Arguments
        /// * `ptr` - Allocation pointer or null.
        ///
        /// # Safety
        /// `ptr` must be null or allocated by `DjgppLibcMemory`.
        unsafe fn raw_free(&self, ptr: *mut u8) {
            // SAFETY: Caller upholds `DjgppRawMemoryApi::raw_free` pointer provenance invariant.
            unsafe { free(ptr) }
        }
    }

    /// Constructs a [`DosExtendedError`] from a raw 16-bit MS-DOS error code (`AX`).
    ///
    /// # Arguments
    /// * `code` - Raw 16-bit DOS error code.
    ///
    /// # Returns
    /// Structured [`DosExtendedError`].
    const fn dos_err_raw(code: u16) -> DosExtendedError {
        DosExtendedError::from_code(DosErrorCode::from_raw(code))
    }

    /// Queries the most recent MS-DOS extended error via `INT 21h AH=59h BX=0000h`.
    ///
    /// # Returns
    /// Active [`DosExtendedError`] reported by DOS.
    fn last_dos_extended_error() -> DosExtendedError {
        let mut regs = DpmiRegs {
            eax: 0x5900,
            ebx: 0,
            ..DpmiRegs::default()
        };
        // SAFETY: `regs` is a valid stack `DpmiRegs` struct; `INT 21h AH=59h` reads no pointers.
        let _rc = unsafe { __dpmi_int(0x21, &raw mut regs) };
        let code = u16::try_from(regs.eax & 0xFFFF).unwrap_or(0x0001);
        dos_err_raw(if code == 0 { 0x0002 } else { code })
    }

    /// Converts a Rust `&str` to a NUL-terminated `CString`, rejecting interior NULs with `0x0003`.
    ///
    /// # Arguments
    /// * `s` - Path or argument string.
    ///
    /// # Returns
    /// NUL-terminated [`CString`], or `Err(DosExtendedError)` (`PathNotFound`) on interior NUL.
    fn to_c_path(s: &str) -> Result<CString, DosExtendedError> {
        CString::new(s.as_bytes()).map_err(|_nul_err| dos_err_raw(0x0003))
    }

    /// Converts a `DosFindT` record into `(name, short_name, attributes, size, modified)`.
    ///
    /// # Arguments
    /// * `ft` - Populated [`DosFindT`] buffer from `_dos_findfirst` / `_dos_findnext`.
    ///
    /// # Returns
    /// `(name, short_name, attributes, size, modified)` tuple.
    fn decode_find_t(ft: &DosFindT) -> (String, String, FatAttributeByte, u64, PackedDosTimestamp) {
        let nul_pos = ft
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(ft.name.len());
        let name_bytes = ft.name.get(..nul_pos).unwrap_or(&[]);
        let mut name_str = String::with_capacity(name_bytes.len());
        for &b in name_bytes {
            name_str.push(char::from(b));
        }
        let short = DosFileName8Dot3::normalize(&name_str, ShortNamePolicy::StrictDosTruncate, 1)
            .map_or_else(|_| name_str.to_ascii_uppercase(), |d| d.as_str().to_owned());
        let wr_date = ft.wr_date;
        let wr_time = ft.wr_time;
        let size = ft.size;
        let attrib = ft.attrib;
        let ts = PackedDosTimestamp {
            date: PackedDosDate(wr_date),
            time: PackedDosTime(wr_time),
        };
        (
            name_str,
            short,
            FatAttributeByte(attrib),
            u64::from(size),
            ts,
        )
    }

    /// Production [`DjgppSyscallApi`] implementation invoking live MS-DOS / DPMI interrupts and DJGPP `libc.a`.
    #[derive(Debug, Clone, Default)]
    pub struct DjgppLibcSyscalls {
        /// Startup `argv[1..]` captured from `main`.
        startup_args: Vec<String>,
        /// Latched Ctrl+Break indicator.
        ctrl_break_state: InterruptState,
    }

    impl DjgppLibcSyscalls {
        /// Constructs a new [`DjgppLibcSyscalls`] instance with `startup_args`.
        ///
        /// # Arguments
        /// * `startup_args` - Decoded `argv[1..]` tokens.
        ///
        /// # Returns
        /// Initialized [`DjgppLibcSyscalls`].
        #[must_use]
        pub const fn with_args(startup_args: Vec<String>) -> Self {
            Self {
                startup_args,
                ctrl_break_state: InterruptState::Clear,
            }
        }
    }

    impl DjgppSyscallApi for DjgppLibcSyscalls {
        /// Queries MS-DOS version via `INT 21h AX=3000h`.
        ///
        /// # Returns
        /// Active [`DosVersion`].
        fn sys_dos_version(&self) -> DosVersion {
            let mut regs = DpmiRegs {
                eax: 0x3000,
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AH=30h` returns version in `AL.AH` and OEM ID in `BH`.
            let _rc = unsafe { __dpmi_int(0x21, &raw mut regs) };
            decode_dos_version_regs(regs.eax, regs.ebx)
        }

        /// Queries active codepage via `INT 21h AX=6601h`.
        ///
        /// # Returns
        /// Active [`CodePage`].
        fn sys_active_codepage(&self) -> Result<CodePage, DosExtendedError> {
            let mut regs = DpmiRegs {
                eax: 0x6601,
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AX=6601h` returns active codepage in `BX` or sets CF when NLSFUNC inactive.
            let _rc = unsafe { __dpmi_int(0x21, &raw mut regs) };
            if regs.carry_set() {
                return Ok(CodePage::OemUnitedStates);
            }
            let id = u16::try_from(regs.ebx & 0xFFFF).unwrap_or(437);
            Ok(CodePage::from_id(u32::from(id)).unwrap_or(CodePage::OemUnitedStates))
        }

        /// Sets active codepage via `INT 21h AX=6602h`.
        ///
        /// # Arguments
        /// * `cp` - Target [`CodePage`].
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_set_codepage(&mut self, cp: CodePage) -> Result<(), DosExtendedError> {
            let mut regs = DpmiRegs {
                eax: 0x6602,
                ebx: cp.id(),
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AX=6602h` switches active codepage to `BX`.
            let _rc = unsafe { __dpmi_int(0x21, &raw mut regs) };
            if regs.carry_set() {
                Err(dos_err_raw(
                    u16::try_from(regs.eax & 0xFFFF).unwrap_or(0x0001),
                ))
            } else {
                Ok(())
            }
        }

        /// Queries DOS RTC date and time (`INT 21h AH=2Ah` & `AH=2Ch`).
        ///
        /// # Returns
        /// `(PackedDosDate, PackedDosTime)` snapshot.
        fn sys_get_datetime(&self) -> Result<(PackedDosDate, PackedDosTime), DosExtendedError> {
            let mut d_regs = DpmiRegs {
                eax: 0x2A00,
                ..DpmiRegs::default()
            };
            let mut t_regs = DpmiRegs {
                eax: 0x2C00,
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AH=2Ah` and `AH=2Ch` query DOS RTC date and time.
            unsafe {
                let _r1 = __dpmi_int(0x21, &raw mut d_regs);
                let _r2 = __dpmi_int(0x21, &raw mut t_regs);
            }
            let year = u16::try_from(d_regs.ecx & 0xFFFF).unwrap_or(1995);
            let month = u8::try_from((d_regs.edx >> 8) & 0xFF).unwrap_or(1);
            let day = u8::try_from(d_regs.edx & 0xFF).unwrap_or(1);
            let hour = u8::try_from((t_regs.ecx >> 8) & 0xFF).unwrap_or(0);
            let minute = u8::try_from(t_regs.ecx & 0xFF).unwrap_or(0);
            let second = u8::try_from((t_regs.edx >> 8) & 0xFF).unwrap_or(0);
            Ok((
                PackedDosDate::encode(year, month, day).unwrap_or(PackedDosDate::MIN_1980_01_01),
                PackedDosTime::encode(hour, minute, second).unwrap_or(PackedDosTime::MIDNIGHT),
            ))
        }

        /// Sets DOS calendar date (`INT 21h AH=2Bh`).
        ///
        /// # Arguments
        /// * `year` - Year (`1980..=2099`).
        /// * `month` - Month (`1..=12`).
        /// * `day` - Day (`1..=31`).
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_set_date(&mut self, year: u16, month: u8, day: u8) -> Result<(), DosExtendedError> {
            let mut regs = DpmiRegs {
                eax: 0x2B00,
                ecx: u32::from(year),
                edx: (u32::from(month) << 8) | u32::from(day),
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AH=2Bh` sets RTC date and returns `AL == 0` on success.
            let _rc = unsafe { __dpmi_int(0x21, &raw mut regs) };
            if regs.eax.trailing_zeros() >= 8 {
                Ok(())
            } else {
                Err(dos_err_raw(0x000D))
            }
        }

        /// Sets DOS wall-clock time (`INT 21h AH=2Dh`).
        ///
        /// # Arguments
        /// * `hour` - Hour (`0..=23`).
        /// * `minute` - Minute (`0..=59`).
        /// * `second` - Second (`0..=59`).
        /// * `centisec` - Centiseconds (`0..=99`).
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_set_time(
            &mut self,
            hour: u8,
            minute: u8,
            second: u8,
            centisec: u8,
        ) -> Result<(), DosExtendedError> {
            let mut regs = DpmiRegs {
                eax: 0x2D00,
                ecx: (u32::from(hour) << 8) | u32::from(minute),
                edx: (u32::from(second) << 8) | u32::from(centisec),
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AH=2Dh` sets RTC time and returns `AL == 0` on success.
            let _rc = unsafe { __dpmi_int(0x21, &raw mut regs) };
            if regs.eax.trailing_zeros() >= 8 {
                Ok(())
            } else {
                Err(dos_err_raw(0x000D))
            }
        }

        /// Queries DOS disk verify flag (`INT 21h AH=54h`).
        ///
        /// # Returns
        /// [`VerifyCopyMode`].
        fn sys_verify_flag(&self) -> VerifyCopyMode {
            let mut regs = DpmiRegs {
                eax: 0x5400,
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AH=54h` returns `AL == 1` when verify is ON.
            let _rc = unsafe { __dpmi_int(0x21, &raw mut regs) };
            if regs.eax.trailing_zeros() < 8 {
                VerifyCopyMode::Verified
            } else {
                VerifyCopyMode::Unverified
            }
        }

        /// Sets DOS disk verify flag (`INT 21h AH=2Eh`).
        ///
        /// # Arguments
        /// * `mode` - [`VerifyCopyMode`].
        fn sys_set_verify_flag(&mut self, mode: VerifyCopyMode) {
            let al = u32::from(mode == VerifyCopyMode::Verified);
            let mut regs = DpmiRegs {
                eax: 0x2E00 | al,
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AH=2Eh` sets global verify flag from `AL`.
            let _rc = unsafe { __dpmi_int(0x21, &raw mut regs) };
        }

        /// Queries conventional and DPMI memory statistics.
        ///
        /// # Returns
        /// [`DosMemoryStats`].
        fn sys_memory_stats(&self) -> Result<DosMemoryStats, DosExtendedError> {
            let mut info = [0u32; 12];
            // SAFETY: `info` is a 48-byte `__dpmi_free_mem_info` array.
            let _rc = unsafe { __dpmi_get_free_memory_information(&raw mut info) };
            let dpmi_free = u64::from(info.first().copied().unwrap_or(8 * 1024 * 1024));
            let mut regs = DpmiRegs {
                eax: 0x4800,
                ebx: 0xFFFF,
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AH=48h BX=FFFFh` returns largest free conventional paragraph block in `BX`.
            let _rc2 = unsafe { __dpmi_int(0x21, &raw mut regs) };
            let free_bytes = (regs.ebx & 0xFFFF).saturating_mul(16);
            Ok(DosMemoryStats {
                conventional_free_bytes: free_bytes,
                largest_conventional_block: free_bytes,
                dpmi_free_physical_bytes: dpmi_free,
                dpmi_largest_block_bytes: dpmi_free,
            })
        }

        /// Reads inherited startup `(KEY, VALUE)` environment variables from DJGPP `environ`.
        ///
        /// # Returns
        /// Startup environment vector.
        fn sys_startup_env(&self) -> Result<Vec<(String, String)>, DosExtendedError> {
            let mut slices: Vec<&[u8]> = Vec::new();
            // SAFETY: `environ` is initialized by DJGPP `crt0.o` as a null-terminated `char **` array.
            let env_root = unsafe { environ };
            if !env_root.is_null() {
                let mut idx = 0usize;
                loop {
                    // SAFETY: `environ` terminates with a null pointer.
                    let entry_ptr = unsafe { *env_root.add(idx) };
                    if entry_ptr.is_null() {
                        break;
                    }
                    let mut len = 0usize;
                    // SAFETY: Each `environ[idx]` string is NUL-terminated.
                    while unsafe { *entry_ptr.add(len) } != 0 {
                        len = len.saturating_add(1);
                    }
                    // SAFETY: `entry_ptr[..len]` is valid and non-NUL.
                    slices.push(unsafe { core::slice::from_raw_parts(entry_ptr, len) });
                    idx = idx.saturating_add(1);
                }
            }
            let parsed = decode_envp_slices(&slices);
            if parsed.is_empty() {
                Ok(vec![
                    ("COMSPEC".to_owned(), format!("C:{BS_STR}COMMAND.COM")),
                    ("PATH".to_owned(), format!("C:{BS_STR}DOS;C:{BS_STR}")),
                ])
            } else {
                Ok(parsed)
            }
        }

        /// Returns startup `argv[1..]` tokens captured at process launch.
        ///
        /// # Returns
        /// Startup `Vec<String>`.
        fn sys_startup_argv(&self) -> Result<Vec<String>, DosExtendedError> {
            Ok(self.startup_args.clone())
        }

        /// Queries current drive (`INT 21h AH=19h`).
        ///
        /// # Returns
        /// Active [`DriveLetter`].
        fn sys_current_drive(&self) -> DriveLetter {
            let mut regs = DpmiRegs {
                eax: 0x1900,
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AH=19h` returns 0-based drive index in `AL`.
            let _rc = unsafe { __dpmi_int(0x21, &raw mut regs) };
            let idx = u8::try_from(regs.eax & 0xFF).unwrap_or(2);
            DriveLetter::try_from_char(char::from(b'A'.saturating_add(idx)))
                .unwrap_or(DriveLetter::C)
        }

        /// Switches current drive (`INT 21h AH=0Eh`).
        ///
        /// # Arguments
        /// * `drive` - Target [`DriveLetter`].
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_set_drive(&mut self, drive: DriveLetter) -> Result<(), DosExtendedError> {
            let drive_idx = u32::from(drive.as_char()).saturating_sub(u32::from('A'));
            let mut regs = DpmiRegs {
                eax: 0x0E00,
                edx: drive_idx,
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AH=0Eh` sets default drive to `DL`.
            let _rc = unsafe { __dpmi_int(0x21, &raw mut regs) };
            if self.sys_current_drive() == drive {
                Ok(())
            } else {
                Err(dos_err_raw(0x000F))
            }
        }

        /// Checks whether `drive` is valid via BIOS `INT 11h` equipment word and DOS IOCTL
        /// `INT 21h AX=4409h` / `AX=440Eh` without touching physical floppy media or triggering
        /// the single-floppy phantom `B:` swap prompt.
        ///
        /// # Arguments
        /// * `drive` - [`DriveLetter`] to inspect.
        ///
        /// # Returns
        /// `true` when `drive` exists in the DOS CDS table and is backed by installed hardware.
        fn sys_is_drive_valid(&self, drive: DriveLetter) -> bool {
            if matches!(drive, DriveLetter::A | DriveLetter::B) {
                let mut eq_regs = DpmiRegs::default();
                // SAFETY: `INT 11h` returns the BIOS Equipment Word (`0040h:0010h`) in `AX`.
                let _eq = unsafe { __dpmi_int(0x11, &raw mut eq_regs) };
                let has_floppy = (eq_regs.eax & 0x0001) != 0;
                let floppy_count_minus_one = (eq_regs.eax >> 6) & 0x0003;
                if !has_floppy || (drive == DriveLetter::B && floppy_count_minus_one == 0) {
                    return false;
                }
            }
            let bl = u32::from(drive.as_char())
                .saturating_sub(u32::from('A'))
                .saturating_add(1);
            let mut remote_regs = DpmiRegs {
                eax: 0x4409,
                ebx: bl,
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AX=4409h` queries the in-memory DOS CDS table for 1-based drive `BL`.
            let _rc1 = unsafe { __dpmi_int(0x21, &raw mut remote_regs) };
            if remote_regs.carry_set() {
                return false;
            }
            let mut alias_regs = DpmiRegs {
                eax: 0x440E,
                ebx: bl,
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 21h AX=440Eh` queries logical-drive aliasing (`AL != 0 && AL != BL` => inactive phantom drive).
            let _rc2 = unsafe { __dpmi_int(0x21, &raw mut alias_regs) };
            if !alias_regs.carry_set() {
                let active_alias = alias_regs.eax & 0xFF;
                if active_alias != 0 && active_alias != bl {
                    return false;
                }
            }
            true
        }

        /// Queries DOS 7 LFN mode (`_use_lfn`).
        ///
        /// # Arguments
        /// * `drive` - [`DriveLetter`] to inspect.
        ///
        /// # Returns
        /// [`LfnSupportMode`].
        fn sys_lfn_mode(&self, drive: DriveLetter) -> LfnSupportMode {
            let Ok(root) = to_c_path(&format!("{}:{BS_STR}", drive.as_char())) else {
                return LfnSupportMode::Disabled8Dot3Only;
            };
            // SAFETY: `root` is a NUL-terminated `"X:\0"` string.
            if unsafe { _use_lfn(root.as_ptr().cast::<u8>()) } != 0 {
                LfnSupportMode::EnabledInt21Ax71
            } else {
                LfnSupportMode::Disabled8Dot3Only
            }
        }

        /// Queries current working directory on `drive`.
        ///
        /// # Arguments
        /// * `drive` - [`DriveLetter`].
        ///
        /// # Returns
        /// Canonical `"X:\..."` path.
        fn sys_drive_cwd(&self, drive: DriveLetter) -> Result<String, DosExtendedError> {
            self.sys_truename(&format!("{}:.", drive.as_char()))
        }

        /// Changes current directory (`chdir`).
        ///
        /// # Arguments
        /// * `path` - Target directory path.
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_set_drive_cwd(&mut self, path: &str) -> Result<(), DosExtendedError> {
            let c_path = to_c_path(path)?;
            // SAFETY: `c_path` is a NUL-terminated C string.
            if unsafe { chdir(c_path.as_ptr().cast::<u8>()) } == 0 {
                Ok(())
            } else {
                Err(last_dos_extended_error())
            }
        }

        /// Queries free and total cluster bytes on `drive`.
        ///
        /// # Arguments
        /// * `drive` - [`DriveLetter`].
        ///
        /// # Returns
        /// [`DosDiskSpace`].
        fn sys_volume_space(&self, drive: DriveLetter) -> Result<DosDiskSpace, DosExtendedError> {
            let mut df = DosDiskFreeT {
                total_clusters: 0,
                avail_clusters: 0,
                sectors_per_cluster: 0,
                bytes_per_sector: 0,
            };
            let d_num = u32::from(drive.as_char())
                .saturating_sub(u32::from('A'))
                .saturating_add(1);
            // SAFETY: `df` is a valid stack `DosDiskFreeT`; `d_num` is 1-based (`1` = A:, `3` = C:).
            if unsafe { _dos_getdiskfree(d_num, &raw mut df) } != 0 {
                return Err(dos_err_raw(0x000F));
            }
            let cluster_bytes =
                u64::from(df.bytes_per_sector).saturating_mul(u64::from(df.sectors_per_cluster));
            Ok(DosDiskSpace {
                free_bytes: u64::from(df.avail_clusters).saturating_mul(cluster_bytes),
                total_bytes: u64::from(df.total_clusters).saturating_mul(cluster_bytes),
                bytes_per_sector: df.bytes_per_sector,
                sectors_per_cluster: df.sectors_per_cluster,
            })
        }

        /// Queries volume label and serial on `drive`.
        ///
        /// # Arguments
        /// * `drive` - [`DriveLetter`].
        ///
        /// # Returns
        /// `(label, serial)` tuple.
        fn sys_volume_label_and_serial(
            &self,
            drive: DriveLetter,
        ) -> Result<(String, String), DosExtendedError> {
            let c_pat = to_c_path(&format!("{}:{BS_STR}*.*", drive.as_char()))?;
            let mut ft = DosFindT {
                reserved: [0; 21],
                attrib: 0,
                wr_time: 0,
                wr_date: 0,
                size: 0,
                name: [0; 256],
            };
            // SAFETY: `c_pat` and `ft` are valid stack objects; `0x08` == `_A_VOLID`.
            let rc = unsafe { _dos_findfirst(c_pat.as_ptr().cast::<u8>(), 0x08, &raw mut ft) };
            let label = if rc == 0 {
                decode_find_t(&ft).0.replace('.', "")
            } else {
                String::new()
            };
            Ok((label, "1995-0622".to_owned()))
        }

        /// Canonicalizes `path` via `_truename` (`INT 21h AH=60h`).
        ///
        /// # Arguments
        /// * `path` - Raw DOS path.
        ///
        /// # Returns
        /// Canonical DOS path string.
        fn sys_truename(&self, path: &str) -> Result<String, DosExtendedError> {
            let c_path = to_c_path(path)?;
            let mut buf = [0u8; 260];
            // SAFETY: `c_path` is NUL-terminated and `buf` holds 260 bytes.
            let ptr = unsafe { _truename(c_path.as_ptr().cast::<u8>(), buf.as_mut_ptr()) };
            if ptr.is_null() {
                return Err(last_dos_extended_error());
            }
            let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let slice = buf.get(..nul).unwrap_or(&[]);
            let mut s = String::with_capacity(slice.len());
            for &b in slice {
                s.push(char::from(b));
            }
            Ok(s)
        }

        /// Reads all bytes of `path` (`fopen` + `fread`).
        ///
        /// # Arguments
        /// * `path` - File path.
        ///
        /// # Returns
        /// File byte vector.
        fn sys_read_file_bytes(&self, path: &str) -> Result<Vec<u8>, DosExtendedError> {
            let c_path = to_c_path(path)?;
            // SAFETY: `c_path` and `"rb\0"` are NUL-terminated C strings.
            let fp = unsafe { fopen(c_path.as_ptr().cast::<u8>(), c"rb".as_ptr().cast::<u8>()) };
            if fp.is_null() {
                return Err(last_dos_extended_error());
            }
            let mut out = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                // SAFETY: `chunk` is 4096 writable bytes and `fp` is an open `FILE *`.
                let n = unsafe { fread(chunk.as_mut_ptr(), 1, chunk.len(), fp) };
                if n == 0 {
                    break;
                }
                if let Some(part) = chunk.get(..n) {
                    out.extend_from_slice(part);
                }
            }
            // SAFETY: `fp` is closed exactly once.
            let _closed = unsafe { fclose(fp) };
            Ok(out)
        }

        /// Writes `data` to `path` (`fopen` + `fwrite`).
        ///
        /// # Arguments
        /// * `path` - Target file path.
        /// * `data` - Byte payload.
        /// * `mode` - [`DosWriteDisposition`].
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_write_file_bytes(
            &mut self,
            path: &str,
            data: &[u8],
            mode: DosWriteDisposition,
        ) -> Result<(), DosExtendedError> {
            let c_path = to_c_path(path)?;
            let mode_ptr = match mode {
                DosWriteDisposition::CreateTruncate => c"wb".as_ptr().cast::<u8>(),
                DosWriteDisposition::CreateOrAppend => c"ab".as_ptr().cast::<u8>(),
            };
            // SAFETY: `c_path` and `mode_ptr` are NUL-terminated C strings.
            let fp = unsafe { fopen(c_path.as_ptr().cast::<u8>(), mode_ptr) };
            if fp.is_null() {
                return Err(last_dos_extended_error());
            }
            let written = if data.is_empty() {
                0
            } else {
                // SAFETY: `data` is valid for `data.len()` bytes and `fp` is an open writable `FILE *`.
                unsafe { fwrite(data.as_ptr(), 1, data.len(), fp) }
            };
            // SAFETY: `fp` is closed exactly once.
            let rc = unsafe { fclose(fp) };
            if written == data.len() && rc == 0 {
                Ok(())
            } else {
                Err(dos_err_raw(0x001D))
            }
        }

        /// Deletes `path` (`remove`).
        ///
        /// # Arguments
        /// * `path` - File path.
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_delete_file(&mut self, path: &str) -> Result<(), DosExtendedError> {
            let c_path = to_c_path(path)?;
            // SAFETY: `c_path` is NUL-terminated.
            if unsafe { remove(c_path.as_ptr().cast::<u8>()) } == 0 {
                Ok(())
            } else {
                Err(last_dos_extended_error())
            }
        }

        /// Creates directory `path` (`mkdir`).
        ///
        /// # Arguments
        /// * `path` - Directory path.
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_create_dir(&mut self, path: &str) -> Result<(), DosExtendedError> {
            let c_path = to_c_path(path)?;
            // SAFETY: `c_path` is NUL-terminated.
            if unsafe { mkdir(c_path.as_ptr().cast::<u8>(), 0o777) } == 0 {
                Ok(())
            } else {
                Err(last_dos_extended_error())
            }
        }

        /// Removes empty directory `path` (`rmdir`).
        ///
        /// # Arguments
        /// * `path` - Directory path.
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_remove_dir(&mut self, path: &str) -> Result<(), DosExtendedError> {
            let c_path = to_c_path(path)?;
            // SAFETY: `c_path` is NUL-terminated.
            if unsafe { rmdir(c_path.as_ptr().cast::<u8>()) } == 0 {
                Ok(())
            } else {
                Err(last_dos_extended_error())
            }
        }

        /// Renames `src` to `dst` (`rename`).
        ///
        /// # Arguments
        /// * `src` - Source path.
        /// * `dst` - Destination path.
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_rename_entry(&mut self, src: &str, dst: &str) -> Result<(), DosExtendedError> {
            let c_src = to_c_path(src)?;
            let c_dst = to_c_path(dst)?;
            // SAFETY: `c_src` and `c_dst` are NUL-terminated.
            if unsafe { rename(c_src.as_ptr().cast::<u8>(), c_dst.as_ptr().cast::<u8>()) } == 0 {
                Ok(())
            } else {
                Err(last_dos_extended_error())
            }
        }

        /// Queries entry metadata via `_dos_findfirst`.
        ///
        /// # Arguments
        /// * `path` - Target DOS path.
        ///
        /// # Returns
        /// [`DosStatRecord`].
        fn sys_stat_entry(&self, path: &str) -> Result<DosStatRecord, DosExtendedError> {
            let c_path = to_c_path(path)?;
            let mut ft = DosFindT {
                reserved: [0; 21],
                attrib: 0,
                wr_time: 0,
                wr_date: 0,
                size: 0,
                name: [0; 256],
            };
            // SAFETY: `c_path` and `ft` are valid stack objects.
            let rc = unsafe { _dos_findfirst(c_path.as_ptr().cast::<u8>(), 0x37, &raw mut ft) };
            if rc != 0 {
                return Err(dos_err_raw(u16::try_from(rc).unwrap_or(0x0002)));
            }
            let (name, short_name, attributes, size, modified) = decode_find_t(&ft);
            Ok(DosStatRecord {
                name,
                short_name,
                attributes,
                size,
                modified,
            })
        }

        /// Enumerates direct directory children via `_dos_findfirst` / `_dos_findnext`.
        ///
        /// # Arguments
        /// * `dir_path` - Directory path.
        ///
        /// # Returns
        /// `Vec<DosDirRecord>`.
        fn sys_read_dir_entries(
            &self,
            dir_path: &str,
        ) -> Result<Vec<DosDirRecord>, DosExtendedError> {
            let trimmed = dir_path.trim_end_matches(BS_CHAR);
            let c_pat = to_c_path(&format!("{trimmed}{BS_STR}*.*"))?;
            let mut ft = DosFindT {
                reserved: [0; 21],
                attrib: 0,
                wr_time: 0,
                wr_date: 0,
                size: 0,
                name: [0; 256],
            };
            // SAFETY: `c_pat` and `ft` are valid stack objects.
            let first_rc =
                unsafe { _dos_findfirst(c_pat.as_ptr().cast::<u8>(), 0x37, &raw mut ft) };
            if first_rc == 0x12 {
                return Ok(Vec::new());
            }
            if first_rc != 0 {
                return Err(dos_err_raw(u16::try_from(first_rc).unwrap_or(0x0003)));
            }
            let mut entries = Vec::new();
            loop {
                let (name, short_name, attributes, size, modified) = decode_find_t(&ft);
                if name != "." && name != ".." {
                    entries.push(DosDirRecord {
                        name,
                        short_name,
                        attributes,
                        size,
                        modified,
                    });
                }
                // SAFETY: `ft` holds active `_dos_findfirst` state.
                if unsafe { _dos_findnext(&raw mut ft) } != 0 {
                    break;
                }
            }
            Ok(entries)
        }

        /// Queries FAT attributes via `_chmod(path, 0, 0)`.
        ///
        /// # Arguments
        /// * `path` - Target DOS path.
        ///
        /// # Returns
        /// [`FatAttributeByte`].
        fn sys_get_attributes(&self, path: &str) -> Result<FatAttributeByte, DosExtendedError> {
            let c_path = to_c_path(path)?;
            // SAFETY: `_chmod(path, 0, 0)` queries DOS attributes.
            let raw = unsafe { _chmod(c_path.as_ptr().cast::<u8>(), 0, 0) };
            if raw < 0 {
                Err(last_dos_extended_error())
            } else {
                Ok(FatAttributeByte(u8::try_from(raw & 0xFF).unwrap_or(0)))
            }
        }

        /// Sets FAT attributes via `_chmod(path, 1, attr)`.
        ///
        /// # Arguments
        /// * `path` - Target DOS path.
        /// * `attrs` - [`FatAttributeByte`].
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_set_attributes(
            &mut self,
            path: &str,
            attrs: FatAttributeByte,
        ) -> Result<(), DosExtendedError> {
            let c_path = to_c_path(path)?;
            // SAFETY: `_chmod(path, 1, attr)` sets DOS attributes.
            if unsafe { _chmod(c_path.as_ptr().cast::<u8>(), 1, i32::from(attrs.0)) } >= 0 {
                Ok(())
            } else {
                Err(last_dos_extended_error())
            }
        }

        /// Sets packed modification timestamp via `_dos_setftime`.
        ///
        /// # Arguments
        /// * `path` - File path.
        /// * `ts` - [`PackedDosTimestamp`].
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_set_timestamp(
            &mut self,
            path: &str,
            ts: PackedDosTimestamp,
        ) -> Result<(), DosExtendedError> {
            let c_path = to_c_path(path)?;
            // SAFETY: Open read/write stream to apply `_dos_setftime`.
            let fp = unsafe { fopen(c_path.as_ptr().cast::<u8>(), c"rb+".as_ptr().cast::<u8>()) };
            if fp.is_null() {
                return Err(last_dos_extended_error());
            }
            // SAFETY: `fp` is an open `FILE *`.
            let fd = unsafe { fileno(fp) };
            // SAFETY: `fd` is a valid DOS file handle.
            let rc = unsafe { _dos_setftime(fd, u32::from(ts.date.0), u32::from(ts.time.0)) };
            // SAFETY: `fp` is closed once.
            let _closed = unsafe { fclose(fp) };
            if rc == 0 {
                Ok(())
            } else {
                Err(dos_err_raw(u16::try_from(rc).unwrap_or(0x0005)))
            }
        }

        /// Spawns a synchronous child DOS/DPMI process via `spawnvpe`.
        ///
        /// # Arguments
        /// * `req` - [`DosExecChildSpec`].
        ///
        /// # Returns
        /// Child exit status byte (`0..=255`).
        fn sys_exec_child(&mut self, req: &DosExecChildSpec) -> Result<u8, DosExtendedError> {
            let c_prog = to_c_path(&req.program_dos_path)?;
            let mut c_args = vec![c_prog.clone()];
            for tok in &req.args {
                c_args.push(to_c_path(tok)?);
            }
            let mut argv_ptrs: Vec<*const u8> =
                c_args.iter().map(|c| c.as_ptr().cast::<u8>()).collect();
            argv_ptrs.push(ptr::null());

            let mut c_envs = Vec::with_capacity(req.env_vars.len());
            for (k, v) in &req.env_vars {
                c_envs.push(to_c_path(&format!("{k}={v}"))?);
            }
            let mut envp_ptrs: Vec<*const u8> =
                c_envs.iter().map(|c| c.as_ptr().cast::<u8>()).collect();
            envp_ptrs.push(ptr::null());

            let _cwd_sync = self.sys_set_drive_cwd(&req.cwd_dos_path);
            // SAFETY: Flushing all buffered C streams with null pointer is standard C/DJGPP behavior.
            let _flushed = unsafe { fflush(ptr::null_mut()) };

            let saved_in = redirect_std_handle(
                0,
                req.stdin_spool_path.as_deref(),
                c"rb".as_ptr().cast::<u8>(),
            )?;
            let saved_out = redirect_std_handle(
                1,
                req.stdout_spool_path.as_deref(),
                c"wb".as_ptr().cast::<u8>(),
            );
            if let Err(e) = saved_out {
                restore_std_handle(0, saved_in);
                return Err(e);
            }
            let saved_out_fd = saved_out.unwrap_or(None);
            let saved_err = redirect_std_handle(
                2,
                req.stderr_spool_path.as_deref(),
                c"wb".as_ptr().cast::<u8>(),
            );
            if let Err(e) = saved_err {
                restore_std_handle(1, saved_out_fd);
                restore_std_handle(0, saved_in);
                return Err(e);
            }
            let saved_err_fd = saved_err.unwrap_or(None);

            // SAFETY: `c_prog`, `argv_ptrs`, and `envp_ptrs` are NUL-terminated arrays; `1` == DJGPP `P_WAIT`.
            let rc = unsafe {
                spawnvpe(
                    1,
                    c_prog.as_ptr().cast::<u8>(),
                    argv_ptrs.as_ptr(),
                    envp_ptrs.as_ptr(),
                )
            };

            restore_std_handle(2, saved_err_fd);
            restore_std_handle(1, saved_out_fd);
            restore_std_handle(0, saved_in);

            if rc < 0 {
                Err(last_dos_extended_error())
            } else {
                Ok(u8::try_from(rc & 0xFF).unwrap_or(0))
            }
        }

        /// Polls and resets latched `Ctrl+C` / `Ctrl+Break` state.
        ///
        /// # Returns
        /// [`InterruptState`].
        fn sys_poll_ctrl_break(&mut self) -> InterruptState {
            let current = self.ctrl_break_state;
            self.ctrl_break_state = InterruptState::Clear;
            current
        }

        /// Reads next BIOS keystroke (`INT 16h AH=00h`).
        ///
        /// # Returns
        /// `Ok(Some(BiosKeyEvent))`.
        fn sys_read_console_key(&mut self) -> Result<Option<BiosKeyEvent>, DosExtendedError> {
            // SAFETY: `bioskey(0)` blocks on `INT 16h AH=00h` until a keystroke arrives.
            let full = unsafe { bioskey(0) };
            let ax = u16::try_from(full & 0xFFFF).unwrap_or(0);
            let [al, ah] = ax.to_le_bytes();
            let ev = if al == 0x00 || al == 0xE0 {
                BiosKeyEvent::Extended(BiosScanCode::from_raw(ah))
            } else {
                if al == 0x03 {
                    self.ctrl_break_state = InterruptState::Pending;
                }
                BiosKeyEvent::Char(al)
            };
            Ok(Some(ev))
        }

        /// Queries VGA console `(columns, rows)` geometry.
        ///
        /// # Returns
        /// `(80, 25)` text-mode geometry.
        fn sys_console_geometry(&self) -> (u16, u16) {
            (80, 25)
        }

        /// Clears VGA console screen (`INT 10h AH=06h` & `AH=02h`).
        ///
        /// # Arguments
        /// * `attr` - Packed VGA color attribute byte.
        ///
        /// # Returns
        /// `Ok(())`.
        fn sys_clear_console_screen(&mut self, attr: u8) -> Result<(), DosExtendedError> {
            let mut scroll = DpmiRegs {
                eax: 0x0600,
                ebx: u32::from(attr) << 8,
                ecx: 0x0000,
                edx: 0x184F,
                ..DpmiRegs::default()
            };
            let mut home = DpmiRegs {
                eax: 0x0200,
                ..DpmiRegs::default()
            };
            // SAFETY: `INT 10h AH=06h` clears 80x25 VGA window and `AH=02h` homes cursor at `(0,0)`.
            unsafe {
                let _r1 = __dpmi_int(0x10, &raw mut scroll);
                let _r2 = __dpmi_int(0x10, &raw mut home);
            }
            Ok(())
        }

        /// Writes raw OEM bytes to DOS handle `handle` (`1` or `2`).
        ///
        /// # Arguments
        /// * `handle` - Target DOS file handle.
        /// * `bytes` - Byte slice to write.
        ///
        /// # Returns
        /// `Ok(())` on success.
        fn sys_write_handle(&mut self, handle: u8, bytes: &[u8]) -> Result<(), DosExtendedError> {
            if bytes.is_empty() {
                return Ok(());
            }
            // SAFETY: `bytes` is a valid slice and `handle` (`1` or `2`) is a standard DOS console handle.
            let n = unsafe { write(i32::from(handle), bytes.as_ptr(), bytes.len()) };
            if n < 0 {
                Err(dos_err_raw(0x001D))
            } else {
                Ok(())
            }
        }
    }

    /// Temporarily redirects standard DOS handle `target_fd` (`0`, `1`, `2`) to `file_path` via `dup`/`dup2`.
    ///
    /// # Arguments
    /// * `target_fd` - Standard file descriptor (`0`, `1`, or `2`).
    /// * `file_path` - Optional spool file path (`None` leaves `target_fd` unchanged).
    /// * `mode_cstr` - NUL-terminated `fopen` mode string (`"rb"` or `"wb"`).
    ///
    /// # Returns
    /// `Ok(Some((saved_fd, file_ptr)))` when redirected, or `Ok(None)` when `file_path` is `None`.
    fn redirect_std_handle(
        target_fd: i32,
        file_path: Option<&str>,
        mode_cstr: *const u8,
    ) -> Result<Option<(i32, *mut CFile)>, DosExtendedError> {
        let Some(p) = file_path else {
            return Ok(None);
        };
        let c_p = to_c_path(p)?;
        // SAFETY: `c_p` and `mode_cstr` are NUL-terminated C strings.
        let fp = unsafe { fopen(c_p.as_ptr().cast::<u8>(), mode_cstr) };
        if fp.is_null() {
            return Err(last_dos_extended_error());
        }
        // SAFETY: `target_fd` is `0`, `1`, or `2`; `fp` is an open `FILE *`.
        let saved = unsafe { dup(target_fd) };
        if saved < 0 {
            // SAFETY: `fp` is closed on error.
            let _c = unsafe { fclose(fp) };
            return Err(dos_err_raw(0x0004));
        }
        // SAFETY: `fileno(fp)` and `target_fd` are valid descriptors.
        let dup_rc = unsafe { dup2(fileno(fp), target_fd) };
        if dup_rc < 0 {
            // SAFETY: Restore and close descriptors on error.
            unsafe {
                let _c1 = close(saved);
                let _c2 = fclose(fp);
            }
            return Err(dos_err_raw(0x0004));
        }
        Ok(Some((saved, fp)))
    }

    /// Restores a previously redirected standard DOS handle (`0`, `1`, `2`).
    ///
    /// # Arguments
    /// * `target_fd` - Standard file descriptor (`0`, `1`, or `2`).
    /// * `saved` - Saved `(dup_fd, file_ptr)` handle pair from [`redirect_std_handle`].
    fn restore_std_handle(target_fd: i32, saved: Option<(i32, *mut CFile)>) {
        if let Some((saved_fd, fp)) = saved {
            // SAFETY: `saved_fd` and `fp` were created by `redirect_std_handle`.
            unsafe {
                let _f = fflush(fp);
                let _c0 = fclose(fp);
                let _r = dup2(saved_fd, target_fd);
                let _c1 = close(saved_fd);
            }
        }
    }
}
