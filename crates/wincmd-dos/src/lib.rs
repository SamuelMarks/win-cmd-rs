//! `wincmd-dos` — 32-bit Protected-Mode MS-DOS (`DJGPP` + `CWSDPMI`) target adapter crate.
//!
//! Provides:
//! - [`alloc_djgpp::DjgppAllocator`]: Alignment-safe `#[global_allocator]` over DJGPP `malloc`/`realloc`/`free`.
//! - [`panic_dos`]: Zero-heap stack-buffered `#[panic_handler]` writing directly to DOS handle `2` (`STDERR`).
//! - [`ffi`]: Thin DJGPP `libc` + `__dpmi_int` FFI surface behind mockable traits.
//! - [`djgpp_kernel::DjgppDosKernel`]: Safe [`win_cmd_rs::dos::DosKernelApi`] adapter mapping every DOS error to [`win_cmd_rs::error::CmdError`].
//! - [`stub_verify`]: Assembled 16-bit Real-Mode 8086/80286 CPU Guard MZ stub, DJGPP `.EXE` stub patcher, and `FLAGS` probe simulator.
//! - [`SyscallHandleWriter`], [`execute_dos_wincmd`], and [`execute_dos_wincheck`]: End-to-end DOS entrypoint drivers for `WINCMD.EXE` and `WINCHECK.EXE`.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod alloc_djgpp;
pub mod djgpp_kernel;
pub mod ffi;
pub mod panic_dos;
pub mod stub_verify;

use alloc::string::String;
use alloc::vec::Vec;

use win_cmd_rs::cli::{
    WinCmdAction, execute_wincheck_over_vfs_streams, execute_wincmd_over_streams,
    parse_wincmd_args_with_default_backend,
};
use win_cmd_rs::dos::{DosKernelApi, run_dos_bios_repl};
use win_cmd_rs::error::CmdError;
use win_cmd_rs::runtime::{ByteStreamWrite, InMemoryByteReader, Interpreter};
use win_cmd_rs::types::{MemoryProfile, ShellDialect, VfsBackendMode};
use win_cmd_rs::vfs::DosFatVfs;

use crate::ffi::DjgppSyscallApi;

/// [`ByteStreamWrite`] adapter forwarding raw OEM output bytes directly to a DOS file handle (`1` or `2`).
#[derive(Debug, Clone)]
pub struct SyscallHandleWriter<S: DjgppSyscallApi> {
    /// Underlying DJGPP syscall provider.
    pub sys: S,
    /// Target DOS file handle (`1` = `STDOUT`, `2` = `STDERR`).
    pub handle: u8,
}

impl<S: DjgppSyscallApi> SyscallHandleWriter<S> {
    /// Creates a new [`SyscallHandleWriter`] targeting DOS file `handle`.
    ///
    /// # Arguments
    /// * `sys` - [`DjgppSyscallApi`] implementation.
    /// * `handle` - Target DOS file handle (`1` or `2`).
    ///
    /// # Returns
    /// Initialized [`SyscallHandleWriter`].
    #[must_use]
    pub const fn new(sys: S, handle: u8) -> Self {
        Self { sys, handle }
    }
}

impl<S: DjgppSyscallApi> ByteStreamWrite for SyscallHandleWriter<S> {
    /// Writes `buf` to `self.handle` in a single DOS syscall.
    ///
    /// # Arguments
    /// * `buf` - Source byte slice.
    ///
    /// # Returns
    /// `Ok(buf.len())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] mapped from [`DosExtendedError`](win_cmd_rs::types::DosExtendedError) if writing fails.
    fn write_chunk(&mut self, buf: &[u8]) -> Result<usize, CmdError> {
        self.write_all_bytes(buf)?;
        Ok(buf.len())
    }

    /// Writes the entirety of `buf` to `self.handle`.
    ///
    /// # Arguments
    /// * `buf` - Source byte slice.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Returns [`CmdError`] mapped from [`DosExtendedError`](win_cmd_rs::types::DosExtendedError) if writing fails.
    fn write_all_bytes(&mut self, buf: &[u8]) -> Result<(), CmdError> {
        self.sys
            .sys_write_handle(self.handle, buf)
            .map_err(|e| CmdError::from_dos_error(e, "CON", "write_handle"))
    }

    /// Flushes the DOS character handle (no-op for unbuffered DOS `INT 21h AH=40h` handles).
    ///
    /// # Returns
    /// `Ok(())`.
    ///
    /// # Errors
    /// Never fails; returns [`CmdError`] only for trait signature compatibility.
    fn flush_stream(&mut self) -> Result<(), CmdError> {
        Ok(())
    }
}

/// Selects an appropriate [`MemoryProfile`] from live DPMI free physical memory statistics.
///
/// # Arguments
/// * `kernel` - Active [`DosKernelApi`] implementation.
///
/// # Returns
/// [`MemoryProfile::DosCompact4MiB`] (`< 8 MiB`), [`MemoryProfile::DosStandard8MiB`] (`<= 16 MiB`),
/// or [`MemoryProfile::DosExtended16MiBPlus`] (`> 16 MiB`).
#[must_use]
pub fn select_dos_memory_profile(kernel: &dyn DosKernelApi) -> MemoryProfile {
    let dpmi_bytes = kernel
        .memory_stats()
        .map_or(8 * 1024 * 1024, |m| m.dpmi_free_physical_bytes);
    if dpmi_bytes < 8 * 1024 * 1024 {
        MemoryProfile::DosCompact4MiB
    } else if dpmi_bytes <= 16 * 1024 * 1024 {
        MemoryProfile::DosStandard8MiB
    } else {
        MemoryProfile::DosExtended16MiBPlus
    }
}

/// Non-generic core execution driver for `WINCMD.EXE` once the [`Interpreter`] and [`DosKernelApi`] are constructed.
///
/// # Arguments
/// * `args` - Command-line arguments excluding `argv[0]`.
/// * `interp` - DOS-wired [`Interpreter`] session.
/// * `shared` - Mutable [`DosKernelApi`] handle for BIOS REPL input.
/// * `profile` - Selected [`MemoryProfile`].
/// * `stdin_bytes` - Piped `stdin` bytes (empty when interactive).
/// * `stdout` - Standard output [`ByteStreamWrite`] sink.
/// * `stderr` - Standard error [`ByteStreamWrite`] sink.
///
/// # Returns
/// Process exit status code (`0..=255`).
fn run_dos_wincmd_session(
    args: &[String],
    mut interp: Interpreter,
    shared: &mut dyn DosKernelApi,
    profile: MemoryProfile,
    stdin_bytes: Vec<u8>,
    stdout: &mut dyn ByteStreamWrite,
    stderr: &mut dyn ByteStreamWrite,
) -> u8 {
    interp.apply_memory_profile(profile);
    interp.apply_shell_dialect(ShellDialect::MsDos622);

    if let Ok(cfg) = parse_wincmd_args_with_default_backend(args, VfsBackendMode::InMemoryHermetic)
        && cfg.action == WinCmdAction::InteractiveRepl
        && stdin_bytes.is_empty()
    {
        if let Some(d) = cfg.dialect {
            interp.apply_shell_dialect(d);
        }
        return run_dos_bios_repl(&mut interp, shared, stdout, stderr).map_or(1, |c| {
            let [low, _, _, _] = c.0.rem_euclid(256).to_le_bytes();
            low
        });
    }

    let mut stdin_reader = InMemoryByteReader::new(stdin_bytes);
    execute_wincmd_over_streams(
        args,
        VfsBackendMode::InMemoryHermetic,
        &mut interp,
        &mut stdin_reader,
        stdout,
        stderr,
    )
}

/// Executes `WINCMD.EXE` (`wincmd`) over a [`DosKernelApi`] instance (wiring `DosFatVfs`,
/// `DosProcessSpawner`, memory budgets, and BIOS `CON` REPL when interactive).
///
/// # Arguments
/// * `args` - Command-line arguments excluding `argv[0]`.
/// * `kernel` - Initialized [`DosKernelApi`] implementation (`DjgppDosKernel` on DOS, `SimulatedDosKernel` in tests).
/// * `stdin_bytes` - Piped `stdin` bytes when invoked non-interactively (empty when attached to BIOS `CON`).
/// * `stdout` - Standard output [`ByteStreamWrite`] sink.
/// * `stderr` - Standard error [`ByteStreamWrite`] sink.
///
/// # Returns
/// Process exit status code (`0..=255`).
pub fn execute_dos_wincmd<K: DosKernelApi + Clone + 'static>(
    args: &[String],
    kernel: K,
    stdin_bytes: Vec<u8>,
    stdout: &mut dyn ByteStreamWrite,
    stderr: &mut dyn ByteStreamWrite,
) -> u8 {
    let profile = select_dos_memory_profile(&kernel);
    let (interp, mut shared) = Interpreter::with_dos_kernel(kernel);
    run_dos_wincmd_session(
        args,
        interp,
        &mut shared,
        profile,
        stdin_bytes,
        stdout,
        stderr,
    )
}

/// Executes `WINCHECK.EXE` (`wincheck`) over a [`DosKernelApi`]-backed [`DosFatVfs`].
///
/// # Arguments
/// * `args` - Command-line arguments excluding `argv[0]`.
/// * `kernel` - Initialized [`DosKernelApi`] implementation.
/// * `stdin_bytes` - Standard input bytes when linting `-`.
/// * `stdout` - Standard output [`ByteStreamWrite`] sink.
/// * `stderr` - Standard error [`ByteStreamWrite`] sink.
///
/// # Returns
/// Process exit status code (`0`, `1`, or `2`).
pub fn execute_dos_wincheck<K: DosKernelApi + Clone + 'static>(
    args: &[String],
    kernel: K,
    stdin_bytes: Vec<u8>,
    stdout: &mut dyn ByteStreamWrite,
    stderr: &mut dyn ByteStreamWrite,
) -> u8 {
    let mut vfs = DosFatVfs::new(kernel);
    let mut stdin_reader = InMemoryByteReader::new(stdin_bytes);
    execute_wincheck_over_vfs_streams(args, &mut vfs, &mut stdin_reader, stdout, stderr)
}

/// Unit tests for `wincmd-dos` allocator, panic formatter, FFI codecs, kernel adapter, and MZ guard stub.
#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::Cell;
    use core::hint::black_box;
    use core::ptr;

    use win_cmd_rs::dos::{
        BiosKeyEvent, DosDirRecord, DosDiskSpace, DosExecChildSpec, DosKernelApi, DosMemoryStats,
        DosOemVendor, DosStatRecord, DosVersion, DosWriteDisposition, FatAttributeByte,
        LfnSupportMode, PackedDosDate, PackedDosTime, PackedDosTimestamp, PspCommandTail,
        SimulatedDosKernel,
    };
    use win_cmd_rs::runtime::ByteStreamWrite;
    use win_cmd_rs::types::{
        CRLF, CodePage, DosErrorCode, DosExtendedError, DriveLetter, InterruptState, VerifyCopyMode,
    };

    use crate::SyscallHandleWriter;
    use crate::alloc_djgpp::DjgppAllocator;
    use crate::djgpp_kernel::DjgppDosKernel;
    use crate::ffi::{
        DjgppRawMemoryApi, DjgppSyscallApi, DpmiRegs, decode_argv_slices, decode_dos_version_regs,
        decode_envp_slices,
    };
    use crate::panic_dos::{PANIC_STACK_BUF_CAPACITY, StackPanicBuffer, format_dos_panic_banner};
    use crate::stub_verify::{
        ASSEMBLED_CPU_GUARD_MZ_STUB, CpuGuardOutcome, RealModeCpuGeneration,
        patch_djgpp_exe_with_cpu_guard, simulate_cpu_guard_flags_probe, validate_mz_cpu_guard_stub,
    };
    use crate::{execute_dos_wincheck, execute_dos_wincmd};

    /// Constructs a [`DosExtendedError`] from a raw 16-bit DOS error code.
    ///
    /// # Arguments
    /// * `code` - Raw 16-bit MS-DOS error code.
    ///
    /// # Returns
    /// Structured [`DosExtendedError`].
    const fn dos_err(code: u16) -> DosExtendedError {
        DosExtendedError::from_code(DosErrorCode::from_raw(code))
    }

    /// Fault-injection mode for [`MockDjgppMem`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MockAllocMode {
        /// Allocate normally from boxed `[usize]` words, storing word count + byte size in header.
        Normal,
        /// Return `null_mut()` on `raw_malloc` and `raw_realloc`.
        ForceOom,
        /// Return a synthetic near-`usize::MAX` pointer to exercise address-wrap guards.
        SyntheticBase(
            /// Synthetic address returned by `raw_malloc`.
            usize,
        ),
    }

    /// 64-byte-aligned test payload type providing compile-time `const` [`Layout`].
    #[repr(align(64))]
    struct Payload64 {
        /// Raw 64-byte payload array.
        _bytes: [u8; 64],
    }

    /// Double-sized 64-byte-aligned test payload type (`128` bytes).
    #[repr(align(64))]
    struct Payload128 {
        /// Raw 128-byte payload array.
        _bytes: [u8; 128],
    }

    /// Deterministic host mock of [`DjgppRawMemoryApi`] with OOM and address-wrap injection.
    struct MockDjgppMem {
        /// Current allocation fault-injection mode.
        mode: Cell<MockAllocMode>,
        /// Count of `raw_free` calls observed on synthetic high addresses.
        synthetic_frees: Cell<usize>,
    }

    impl DjgppRawMemoryApi for MockDjgppMem {
        /// Allocates `size` bytes backed by an 8-byte-aligned `Box<[usize]>` with a 2-word header.
        ///
        /// # Arguments
        /// * `size` - Requested byte count.
        ///
        /// # Returns
        /// Mock pointer or `null_mut()`.
        fn raw_malloc(&self, size: usize) -> *mut u8 {
            match self.mode.get() {
                MockAllocMode::ForceOom => ptr::null_mut(),
                MockAllocMode::SyntheticBase(addr) => ptr::without_provenance_mut(addr),
                MockAllocMode::Normal => {
                    let payload_words = size.div_ceil(size_of::<usize>()).max(1);
                    let total_words = payload_words.saturating_add(2);
                    let mut words = Vec::with_capacity(total_words);
                    words.push(total_words);
                    words.push(size);
                    words.resize(total_words, 0);
                    let raw_slice = Box::into_raw(words.into_boxed_slice());
                    let base = raw_slice.cast::<usize>();
                    // SAFETY: `total_words >= 3`, so `base.add(2)` points to the payload start.
                    unsafe { base.add(2).cast::<u8>() }
                }
            }
        }

        /// Reallocates `ptr` to `new_size` bytes.
        ///
        /// # Arguments
        /// * `ptr` - Payload pointer from `raw_malloc`.
        /// * `new_size` - New requested byte size.
        ///
        /// # Returns
        /// Resized payload pointer or `null_mut()` when `ForceOom` is active.
        ///
        /// # Safety
        /// `ptr` must have been allocated by `MockDjgppMem` in `Normal` mode.
        unsafe fn raw_realloc(&self, ptr: *mut u8, new_size: usize) -> *mut u8 {
            if self.mode.get() != MockAllocMode::Normal {
                return ptr::null_mut();
            }
            let new_ptr = self.raw_malloc(new_size);
            // SAFETY: `ptr` was preceded by a 2-`usize` header written in `raw_malloc`.
            unsafe {
                let word_bytes = size_of::<usize>();
                let size_slot = ptr.sub(word_bytes);
                let mut size_bytes = [0u8; size_of::<usize>()];
                ptr::copy_nonoverlapping(size_slot, size_bytes.as_mut_ptr(), word_bytes);
                let old_size = usize::from_ne_bytes(size_bytes);
                ptr::copy_nonoverlapping(ptr, new_ptr, old_size.min(new_size));
                self.raw_free(ptr);
            }
            new_ptr
        }

        /// Releases `ptr` (or records synthetic free when in `SyntheticBase` mode).
        ///
        /// # Arguments
        /// * `ptr` - Pointer to release.
        ///
        /// # Safety
        /// `ptr` must have been returned by `MockDjgppMem`.
        unsafe fn raw_free(&self, ptr: *mut u8) {
            if matches!(self.mode.get(), MockAllocMode::SyntheticBase(_)) {
                self.synthetic_frees
                    .set(self.synthetic_frees.get().saturating_add(1));
                return;
            }
            let word_bytes = size_of::<usize>();
            // SAFETY: `ptr` is non-null and preceded by `[total_words, size]` written by `raw_malloc`.
            unsafe {
                let base_bytes = ptr.sub(word_bytes.saturating_mul(2));
                let mut len_bytes = [0u8; size_of::<usize>()];
                ptr::copy_nonoverlapping(base_bytes, len_bytes.as_mut_ptr(), word_bytes);
                let total_words = usize::from_ne_bytes(len_bytes);
                let base_words =
                    ptr::with_exposed_provenance_mut::<usize>(base_bytes.expose_provenance());
                let raw_slice = ptr::slice_from_raw_parts_mut(base_words, total_words);
                drop(Box::from_raw(raw_slice));
            }
        }
    }

    /// Outcome mode for [`MockSyscalls`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MockOutcome {
        /// Return valid DOS success responses.
        Succeed,
        /// Return deterministic [`DosExtendedError`] failures.
        Fail,
    }

    /// Host mock of [`DjgppSyscallApi`] exercising both `Ok` and `Err` branches of `DjgppDosKernel` and `SyscallHandleWriter`.
    #[derive(Debug, Clone)]
    struct MockSyscalls {
        /// Configured success or failure outcome.
        outcome: MockOutcome,
    }

    impl MockSyscalls {
        /// Returns `Ok(val)` when `self.outcome == MockOutcome::Succeed`, else `Err(dos_err(code))`.
        ///
        /// # Arguments
        /// * `val` - Value returned in `Succeed` mode.
        /// * `code` - Raw DOS error code returned in `Fail` mode.
        ///
        /// # Returns
        /// `Result<T, DosExtendedError>`.
        fn gate<T>(&self, val: T, code: u16) -> Result<T, DosExtendedError> {
            match self.outcome {
                MockOutcome::Succeed => Ok(val),
                MockOutcome::Fail => Err(dos_err(code)),
            }
        }
    }

    impl DjgppSyscallApi for MockSyscalls {
        /// Returns default `MS-DOS 6.22` version.
        ///
        /// # Returns
        /// [`DosVersion`].
        fn sys_dos_version(&self) -> DosVersion {
            DosVersion::default()
        }

        /// Queries mock codepage.
        ///
        /// # Returns
        /// `Ok(OemUnitedStates)` or `Err`.
        fn sys_active_codepage(&self) -> Result<CodePage, DosExtendedError> {
            self.gate(CodePage::OemUnitedStates, 1)
        }

        /// Sets mock codepage.
        ///
        /// # Arguments
        /// * `cp` - Target [`CodePage`].
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_set_codepage(&mut self, cp: CodePage) -> Result<(), DosExtendedError> {
            black_box(cp);
            self.gate((), 1)
        }

        /// Queries mock RTC timestamp.
        ///
        /// # Returns
        /// `(PackedDosDate, PackedDosTime)` or `Err`.
        fn sys_get_datetime(&self) -> Result<(PackedDosDate, PackedDosTime), DosExtendedError> {
            self.gate((PackedDosDate::MIN_1980_01_01, PackedDosTime::MIDNIGHT), 1)
        }

        /// Sets mock RTC date.
        ///
        /// # Arguments
        /// * `year` - Year.
        /// * `month` - Month.
        /// * `day` - Day.
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_set_date(&mut self, year: u16, month: u8, day: u8) -> Result<(), DosExtendedError> {
            black_box((year, month, day));
            self.gate((), 13)
        }

        /// Sets mock RTC time.
        ///
        /// # Arguments
        /// * `hour` - Hour.
        /// * `minute` - Minute.
        /// * `second` - Second.
        /// * `centisec` - Centiseconds.
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_set_time(
            &mut self,
            hour: u8,
            minute: u8,
            second: u8,
            centisec: u8,
        ) -> Result<(), DosExtendedError> {
            black_box((hour, minute, second, centisec));
            self.gate((), 13)
        }

        /// Queries mock verify flag.
        ///
        /// # Returns
        /// [`VerifyCopyMode::Unverified`].
        fn sys_verify_flag(&self) -> VerifyCopyMode {
            VerifyCopyMode::Unverified
        }

        /// Sets mock verify flag.
        ///
        /// # Arguments
        /// * `mode` - [`VerifyCopyMode`].
        fn sys_set_verify_flag(&mut self, mode: VerifyCopyMode) {
            black_box(mode);
        }

        /// Queries mock memory stats.
        ///
        /// # Returns
        /// [`DosMemoryStats`] or `Err`.
        fn sys_memory_stats(&self) -> Result<DosMemoryStats, DosExtendedError> {
            self.gate(DosMemoryStats::default(), 8)
        }

        /// Queries mock startup env.
        ///
        /// # Returns
        /// Empty vector or `Err`.
        fn sys_startup_env(&self) -> Result<Vec<(String, String)>, DosExtendedError> {
            self.gate(Vec::new(), 10)
        }

        /// Queries mock startup argv.
        ///
        /// # Returns
        /// Empty vector or `Err`.
        fn sys_startup_argv(&self) -> Result<Vec<String>, DosExtendedError> {
            self.gate(Vec::new(), 10)
        }

        /// Queries mock current drive.
        ///
        /// # Returns
        /// [`DriveLetter::C`].
        fn sys_current_drive(&self) -> DriveLetter {
            DriveLetter::C
        }

        /// Sets mock drive.
        ///
        /// # Arguments
        /// * `drive` - [`DriveLetter`].
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_set_drive(&mut self, drive: DriveLetter) -> Result<(), DosExtendedError> {
            black_box(drive);
            self.gate((), 15)
        }

        /// Checks mock drive validity.
        ///
        /// # Arguments
        /// * `drive` - [`DriveLetter`].
        ///
        /// # Returns
        /// `true` in `Succeed` mode.
        fn sys_is_drive_valid(&self, drive: DriveLetter) -> bool {
            black_box(drive);
            self.outcome == MockOutcome::Succeed
        }

        /// Queries mock LFN mode.
        ///
        /// # Arguments
        /// * `drive` - [`DriveLetter`].
        ///
        /// # Returns
        /// [`LfnSupportMode::Disabled8Dot3Only`].
        fn sys_lfn_mode(&self, drive: DriveLetter) -> LfnSupportMode {
            black_box(drive);
            LfnSupportMode::Disabled8Dot3Only
        }

        /// Queries mock drive CWD.
        ///
        /// # Arguments
        /// * `drive` - [`DriveLetter`].
        ///
        /// # Returns
        /// `"C:"` or `Err`.
        fn sys_drive_cwd(&self, drive: DriveLetter) -> Result<String, DosExtendedError> {
            black_box(drive);
            self.gate(String::from("C:"), 15)
        }

        /// Sets mock drive CWD.
        ///
        /// # Arguments
        /// * `path` - Target directory path.
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_set_drive_cwd(&mut self, path: &str) -> Result<(), DosExtendedError> {
            black_box(path);
            self.gate((), 3)
        }

        /// Queries mock volume space.
        ///
        /// # Arguments
        /// * `drive` - [`DriveLetter`].
        ///
        /// # Returns
        /// [`DosDiskSpace`] or `Err`.
        fn sys_volume_space(&self, drive: DriveLetter) -> Result<DosDiskSpace, DosExtendedError> {
            black_box(drive);
            self.gate(
                DosDiskSpace {
                    free_bytes: 1_048_576,
                    total_bytes: 2_097_152,
                    bytes_per_sector: 512,
                    sectors_per_cluster: 8,
                },
                15,
            )
        }

        /// Queries mock volume label and serial.
        ///
        /// # Arguments
        /// * `drive` - [`DriveLetter`].
        ///
        /// # Returns
        /// `(label, serial)` or `Err`.
        fn sys_volume_label_and_serial(
            &self,
            drive: DriveLetter,
        ) -> Result<(String, String), DosExtendedError> {
            black_box(drive);
            self.gate((String::from("DOS"), String::from("1234-5678")), 15)
        }

        /// Resolves mock truename.
        ///
        /// # Arguments
        /// * `path` - Raw path.
        ///
        /// # Returns
        /// Canonical path or `Err`.
        fn sys_truename(&self, path: &str) -> Result<String, DosExtendedError> {
            black_box(path);
            self.gate(String::from("C:/DOS"), 3)
        }

        /// Reads mock file bytes.
        ///
        /// # Arguments
        /// * `path` - File path.
        ///
        /// # Returns
        /// Bytes or `Err`.
        fn sys_read_file_bytes(&self, path: &str) -> Result<Vec<u8>, DosExtendedError> {
            black_box(path);
            self.gate(vec![b'o', b'k'], 2)
        }

        /// Writes mock file bytes.
        ///
        /// # Arguments
        /// * `path` - File path.
        /// * `data` - Payload bytes.
        /// * `mode` - [`DosWriteDisposition`].
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_write_file_bytes(
            &mut self,
            path: &str,
            data: &[u8],
            mode: DosWriteDisposition,
        ) -> Result<(), DosExtendedError> {
            black_box((path, data, mode));
            self.gate((), 5)
        }

        /// Deletes mock file.
        ///
        /// # Arguments
        /// * `path` - File path.
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_delete_file(&mut self, path: &str) -> Result<(), DosExtendedError> {
            black_box(path);
            self.gate((), 2)
        }

        /// Creates mock directory.
        ///
        /// # Arguments
        /// * `path` - Directory path.
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_create_dir(&mut self, path: &str) -> Result<(), DosExtendedError> {
            black_box(path);
            self.gate((), 5)
        }

        /// Removes mock directory.
        ///
        /// # Arguments
        /// * `path` - Directory path.
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_remove_dir(&mut self, path: &str) -> Result<(), DosExtendedError> {
            black_box(path);
            self.gate((), 16)
        }

        /// Renames mock entry.
        ///
        /// # Arguments
        /// * `src` - Source path.
        /// * `dst` - Destination path.
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_rename_entry(&mut self, src: &str, dst: &str) -> Result<(), DosExtendedError> {
            black_box((src, dst));
            self.gate((), 17)
        }

        /// Queries mock entry metadata.
        ///
        /// # Arguments
        /// * `path` - Entry path.
        ///
        /// # Returns
        /// [`DosStatRecord`] or `Err`.
        fn sys_stat_entry(&self, path: &str) -> Result<DosStatRecord, DosExtendedError> {
            black_box(path);
            self.gate(
                DosStatRecord {
                    name: String::from("A.TXT"),
                    short_name: String::from("A.TXT"),
                    attributes: FatAttributeByte::ARCHIVE,
                    size: 2,
                    modified: PackedDosTimestamp::default(),
                },
                2,
            )
        }

        /// Reads mock directory entries.
        ///
        /// # Arguments
        /// * `dir_path` - Directory path.
        ///
        /// # Returns
        /// `Vec<DosDirRecord>` or `Err`.
        fn sys_read_dir_entries(
            &self,
            dir_path: &str,
        ) -> Result<Vec<DosDirRecord>, DosExtendedError> {
            black_box(dir_path);
            self.gate(Vec::new(), 3)
        }

        /// Queries mock FAT attributes.
        ///
        /// # Arguments
        /// * `path` - Entry path.
        ///
        /// # Returns
        /// [`FatAttributeByte`] or `Err`.
        fn sys_get_attributes(&self, path: &str) -> Result<FatAttributeByte, DosExtendedError> {
            black_box(path);
            self.gate(FatAttributeByte::ARCHIVE, 2)
        }

        /// Sets mock FAT attributes.
        ///
        /// # Arguments
        /// * `path` - Entry path.
        /// * `attrs` - [`FatAttributeByte`].
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_set_attributes(
            &mut self,
            path: &str,
            attrs: FatAttributeByte,
        ) -> Result<(), DosExtendedError> {
            black_box((path, attrs));
            self.gate((), 5)
        }

        /// Sets mock timestamp.
        ///
        /// # Arguments
        /// * `path` - Entry path.
        /// * `ts` - [`PackedDosTimestamp`].
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_set_timestamp(
            &mut self,
            path: &str,
            ts: PackedDosTimestamp,
        ) -> Result<(), DosExtendedError> {
            black_box((path, ts));
            self.gate((), 5)
        }

        /// Spawns mock child process.
        ///
        /// # Arguments
        /// * `req` - [`DosExecChildSpec`].
        ///
        /// # Returns
        /// `Ok(0)` or `Err`.
        fn sys_exec_child(&mut self, req: &DosExecChildSpec) -> Result<u8, DosExtendedError> {
            black_box(&req.program_dos_path);
            self.gate(0, 8)
        }

        /// Polls mock Ctrl+Break state.
        ///
        /// # Returns
        /// [`InterruptState::Clear`].
        fn sys_poll_ctrl_break(&mut self) -> InterruptState {
            InterruptState::Clear
        }

        /// Reads mock console keystroke.
        ///
        /// # Returns
        /// `Ok(None)` or `Err`.
        fn sys_read_console_key(&mut self) -> Result<Option<BiosKeyEvent>, DosExtendedError> {
            self.gate(None, 5)
        }

        /// Queries mock console geometry.
        ///
        /// # Returns
        /// `(80, 25)`.
        fn sys_console_geometry(&self) -> (u16, u16) {
            (80, 25)
        }

        /// Clears mock console screen.
        ///
        /// # Arguments
        /// * `attr` - VGA attribute byte.
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_clear_console_screen(&mut self, attr: u8) -> Result<(), DosExtendedError> {
            black_box(attr);
            self.gate((), 5)
        }

        /// Writes mock raw bytes to DOS handle.
        ///
        /// # Arguments
        /// * `handle` - Target DOS file handle.
        /// * `bytes` - Raw byte slice.
        ///
        /// # Returns
        /// `Ok(())` or `Err`.
        fn sys_write_handle(&mut self, handle: u8, bytes: &[u8]) -> Result<(), DosExtendedError> {
            black_box((handle, bytes));
            self.gate((), 29)
        }
    }

    /// Verifies `DjgppAllocator` standard (`<=8`), over-aligned (`64`-byte), OOM, and address-wrap paths.
    #[test]
    fn test_djgpp_allocator_aligned_and_oom_paths() {
        let alloc = DjgppAllocator::new(MockDjgppMem {
            mode: Cell::new(MockAllocMode::Normal),
            synthetic_frees: Cell::new(0),
        });
        assert_eq!(
            DjgppAllocator::<MockDjgppMem>::checked_overalloc_total(64, 64),
            Some(
                64usize
                    .saturating_add(64)
                    .saturating_add(size_of::<usize>())
            )
        );
        assert_eq!(
            DjgppAllocator::<MockDjgppMem>::checked_overalloc_total(usize::MAX, 64),
            None
        );
        assert_eq!(
            DjgppAllocator::<MockDjgppMem>::checked_overalloc_total(usize::MAX - 64, 64),
            None
        );

        let l8 = Layout::new::<[u8; 24]>();
        let l8_grown = Layout::new::<[u8; 64]>();
        let l64 = Layout::new::<Payload64>();
        let l128 = Layout::new::<Payload128>();

        // SAFETY: Valid compile-time `Layout` values allocated and freed on the same `DjgppAllocator`.
        unsafe {
            alloc.dealloc(ptr::null_mut(), l8);
            let p8 = alloc.alloc(l8);
            assert!(!p8.is_null());
            let p8_grown = alloc.realloc(p8, l8, l8_grown.size());
            assert!(!p8_grown.is_null());
            alloc.mem.mode.set(MockAllocMode::ForceOom);
            assert!(alloc.alloc(l8).is_null());
            assert!(alloc.realloc(p8_grown, l8_grown, 128).is_null());
            alloc.mem.mode.set(MockAllocMode::Normal);
            alloc.dealloc(p8_grown, l8_grown);

            let p64 = alloc.alloc(l64);
            assert!(!p64.is_null());
            assert_eq!(p64.expose_provenance() % 64, 0);
            ptr::write_bytes(p64, 0xAB, l64.size());
            let p128 = alloc.realloc(p64, l64, l128.size());
            assert!(!p128.is_null());
            assert_eq!(p128.expose_provenance() % 64, 0);
            assert_eq!(*p128, 0xAB);

            alloc.mem.mode.set(MockAllocMode::ForceOom);
            assert!(alloc.alloc(l64).is_null());
            assert!(alloc.realloc(p128, l128, 256).is_null());
            assert!(alloc.realloc(p128, l128, usize::MAX).is_null());

            alloc.mem.mode.set(MockAllocMode::SyntheticBase(usize::MAX));
            assert!(alloc.alloc(l64).is_null());
            alloc.mem.mode.set(MockAllocMode::SyntheticBase(
                usize::MAX.saturating_sub(size_of::<usize>()),
            ));
            assert!(alloc.alloc(l64).is_null());
            assert_eq!(alloc.mem.synthetic_frees.get(), 2);

            alloc.mem.mode.set(MockAllocMode::Normal);
            alloc.dealloc(p128, l128);
        }
    }

    /// Verifies `StackPanicBuffer`, `format_dos_panic_banner`, `validate_mz_cpu_guard_stub`,
    /// `patch_djgpp_exe_with_cpu_guard`, and `simulate_cpu_guard_flags_probe`.
    #[test]
    fn test_panic_banner_and_16bit_cpu_guard_mz_stub() {
        let def_buf = StackPanicBuffer::default();
        assert_eq!(def_buf.as_bytes(), b"");

        let non_ascii = core::str::from_utf8(&[
            b'o', b'u', b't', b' ', b'o', b'f', b' ', b'm', b'e', b'm', 0x01,
        ])
        .unwrap_or("");
        let b1 = format_dos_panic_banner(Some(("src/main.rs", 42)), &non_ascii);
        let s1 = core::str::from_utf8(b1.as_bytes()).unwrap_or("");
        assert!(s1.contains("src/main.rs:42: out of mem?"));
        assert!(s1.ends_with(CRLF));

        let huge = "X".repeat(400);
        let b2 = format_dos_panic_banner(None, &huge);
        assert_eq!(b2.as_bytes().len(), PANIC_STACK_BUF_CAPACITY);
        assert!(b2.as_bytes().ends_with(CRLF.as_bytes()));

        assert!(validate_mz_cpu_guard_stub(&ASSEMBLED_CPU_GUARD_MZ_STUB));
        assert!(!validate_mz_cpu_guard_stub(b"short"));
        assert!(!validate_mz_cpu_guard_stub(&[0u8; 64]));
        let mut bad_hdr = ASSEMBLED_CPU_GUARD_MZ_STUB.to_vec();
        bad_hdr.splice(8..9, [0xFF]);
        assert!(!validate_mz_cpu_guard_stub(&bad_hdr));
        let mut bad_op = ASSEMBLED_CPU_GUARD_MZ_STUB.to_vec();
        bad_op.splice(32..33, [0x90]);
        assert!(!validate_mz_cpu_guard_stub(&bad_op));

        assert!(patch_djgpp_exe_with_cpu_guard(b"short").is_none());
        assert!(patch_djgpp_exe_with_cpu_guard(&[0u8; 2050]).is_none());
        assert!(patch_djgpp_exe_with_cpu_guard(&[0u8; 2560]).is_none());

        let mut mock_djgpp_exe = vec![0u8; 2560];
        mock_djgpp_exe.splice(0..2, *b"MZ");
        mock_djgpp_exe.splice(4..6, 4u16.to_le_bytes());
        mock_djgpp_exe.splice(8..10, 32u16.to_le_bytes());
        mock_djgpp_exe.splice(20..22, 0x0054u16.to_le_bytes());
        mock_djgpp_exe.splice(512..520, *b"go32stub");
        mock_djgpp_exe.splice(2048..2052, [0x4C, 0x01, 0x03, 0x00]);

        let p_bytes = patch_djgpp_exe_with_cpu_guard(&mock_djgpp_exe).unwrap_or_default();
        assert!(validate_mz_cpu_guard_stub(&p_bytes));
        assert_eq!(p_bytes.get(512..520), Some(b"go32stub".as_slice()));
        assert_eq!(
            p_bytes.get(3072..3076),
            Some([0x4Cu8, 0x01, 0x03, 0x00].as_slice())
        );
        // Re-patching an already-patched `.EXE` (`e_cp == 6`) cleanly returns `None`.
        assert!(patch_djgpp_exe_with_cpu_guard(&p_bytes).is_none());

        let mut bad_cblp = mock_djgpp_exe.clone();
        bad_cblp.splice(2..4, 256u16.to_le_bytes());
        assert!(patch_djgpp_exe_with_cpu_guard(&bad_cblp).is_none());

        let mut bad_cparhdr = mock_djgpp_exe.clone();
        bad_cparhdr.splice(8..10, 2u16.to_le_bytes());
        assert!(patch_djgpp_exe_with_cpu_guard(&bad_cparhdr).is_none());

        let mut nonzero_cs = mock_djgpp_exe.clone();
        nonzero_cs.splice(22..24, 1u16.to_le_bytes());
        assert!(patch_djgpp_exe_with_cpu_guard(&nonzero_cs).is_none());

        let mut huge_ip = mock_djgpp_exe.clone();
        huge_ip.splice(20..22, 0x0600u16.to_le_bytes());
        assert!(patch_djgpp_exe_with_cpu_guard(&huge_ip).is_none());

        let mut no_go32 = mock_djgpp_exe;
        no_go32.splice(512..520, *b"not_go32");
        assert!(patch_djgpp_exe_with_cpu_guard(&no_go32).is_none());

        assert_eq!(
            simulate_cpu_guard_flags_probe(RealModeCpuGeneration::Intel8086),
            CpuGuardOutcome::RejectedPre386 { exit_code: 1 }
        );
        assert_eq!(
            simulate_cpu_guard_flags_probe(RealModeCpuGeneration::Intel80286),
            CpuGuardOutcome::RejectedPre386 { exit_code: 1 }
        );
        assert_eq!(
            simulate_cpu_guard_flags_probe(RealModeCpuGeneration::Intel80386OrNewer),
            CpuGuardOutcome::ProceedToProtectedMode
        );
    }

    /// Verifies `DpmiRegs`, `decode_argv_slices`, `decode_envp_slices`, and `decode_dos_version_regs`.
    #[test]
    fn test_ffi_decoders_and_dpmi_regs() {
        let mut regs = DpmiRegs::default();
        assert!(!regs.carry_set());
        regs.flags = 1;
        assert!(regs.carry_set());

        assert_eq!(
            decode_argv_slices(&[&[b'W', 0], &[b'/', b'C', 0], b"VER"]),
            vec![String::from("/C"), String::from("VER")]
        );
        assert_eq!(
            decode_envp_slices(&[
                &[b'P', b'A', b'T', b'H', b'=', b'C', b':', 0],
                b"EMPTY=",
                b"=BAD",
                b"NOEQ",
            ]),
            vec![
                (String::from("PATH"), String::from("C:")),
                (String::from("EMPTY"), String::new()),
            ]
        );

        assert_eq!(
            decode_dos_version_regs(0x1606, 0x0000).oem_id,
            DosOemVendor::PcDos
        );
        assert_eq!(
            decode_dos_version_regs(0x0A07, 0xFD00).oem_id,
            DosOemVendor::FreeDos
        );
        assert_eq!(
            decode_dos_version_regs(0x0006, 0xEE00).oem_id,
            DosOemVendor::DrDos
        );
        assert_eq!(
            decode_dos_version_regs(0x0A07, 0xFF00).oem_id,
            DosOemVendor::Windows9xDos7
        );
        assert_eq!(
            decode_dos_version_regs(0x1606, 0xFF00).oem_id,
            DosOemVendor::MsDos
        );
        assert_eq!(
            decode_dos_version_regs(0x0000, 0x4200),
            DosVersion {
                major: 6,
                minor: 0,
                oem_id: DosOemVendor::Unknown(0x42),
            }
        );
    }

    /// Verifies `SyscallHandleWriter` and `DjgppDosKernel` `Ok` + `Err` mappings across all trait methods.
    #[test]
    fn test_djgpp_dos_kernel_all_methods_ok_and_err() {
        let spec = DosExecChildSpec {
            program_dos_path: String::from("C:/APP.EXE"),
            psp_tail: PspCommandTail::default(),
            args: Vec::new(),
            cwd_dos_path: String::from("C:/"),
            env_vars: Vec::new(),
            stdin_spool_path: None,
            stdout_spool_path: None,
            stderr_spool_path: None,
        };

        for outcome in [MockOutcome::Succeed, MockOutcome::Fail] {
            let is_err = outcome == MockOutcome::Fail;
            let mut writer = SyscallHandleWriter::new(MockSyscalls { outcome }, 1);
            assert_eq!(writer.write_chunk(b"hi").is_err(), is_err);
            assert!(writer.flush_stream().is_ok());

            let mut k = DjgppDosKernel::new(MockSyscalls { outcome });
            let _boxed = k.clone_box();
            assert_eq!(k.dos_version(), DosVersion::default());
            assert_eq!(k.active_codepage().is_err(), is_err);
            assert_eq!(
                k.set_active_codepage(CodePage::OemUnitedStates).is_err(),
                is_err
            );
            assert_eq!(k.current_datetime().is_err(), is_err);
            assert_eq!(k.set_current_date(1995, 1, 1).is_err(), is_err);
            assert_eq!(k.set_current_time(0, 0, 0, 0).is_err(), is_err);
            assert_eq!(k.verify_flag(), VerifyCopyMode::Unverified);
            k.set_verify_flag(VerifyCopyMode::Verified);
            assert_eq!(k.memory_stats().is_err(), is_err);
            assert_eq!(k.startup_env_vars().is_err(), is_err);
            assert_eq!(k.startup_argv().is_err(), is_err);
            assert_eq!(k.current_drive(), DriveLetter::C);
            assert_eq!(k.set_current_drive(DriveLetter::C).is_err(), is_err);
            assert_eq!(k.is_drive_valid(DriveLetter::C), !is_err);
            assert_eq!(
                k.lfn_support_for_drive(DriveLetter::C),
                LfnSupportMode::Disabled8Dot3Only
            );
            assert_eq!(k.drive_cwd(DriveLetter::C).is_err(), is_err);
            assert_eq!(k.set_drive_cwd("C:/DOS").is_err(), is_err);
            assert_eq!(k.volume_space(DriveLetter::C).is_err(), is_err);
            assert_eq!(k.volume_label_and_serial(DriveLetter::C).is_err(), is_err);
            assert_eq!(k.truename("C:/DOS").is_err(), is_err);
            assert_eq!(k.read_file_bytes("C:/A.TXT").is_err(), is_err);
            assert_eq!(
                k.write_file_bytes("C:/A.TXT", b"x", DosWriteDisposition::CreateTruncate)
                    .is_err(),
                is_err
            );
            assert_eq!(k.delete_file("C:/A.TXT").is_err(), is_err);
            assert_eq!(k.create_dir("C:/SUB").is_err(), is_err);
            assert_eq!(k.remove_dir("C:/SUB").is_err(), is_err);
            assert_eq!(k.rename_entry("C:/A.TXT", "C:/B.TXT").is_err(), is_err);
            assert_eq!(k.stat_entry("C:/A.TXT").is_err(), is_err);
            assert_eq!(k.read_dir_entries("C:/").is_err(), is_err);
            assert_eq!(k.get_attributes("C:/A.TXT").is_err(), is_err);
            assert_eq!(
                k.set_attributes("C:/A.TXT", FatAttributeByte::ARCHIVE)
                    .is_err(),
                is_err
            );
            assert_eq!(
                k.set_timestamp("C:/A.TXT", PackedDosTimestamp::default())
                    .is_err(),
                is_err
            );
            assert_eq!(k.exec_child(&spec).is_err(), is_err);
            assert_eq!(k.poll_ctrl_break(), InterruptState::Clear);
            assert_eq!(k.read_console_key().is_err(), is_err);
            assert_eq!(k.console_geometry(), (80, 25));
            assert_eq!(k.clear_console_screen(0x07).is_err(), is_err);
        }
    }

    /// Verifies `execute_dos_wincmd` (all memory profiles + BIOS REPL + piped stdin + CLI error + `/C`) and `execute_dos_wincheck`.
    #[test]
    fn test_execute_dos_wincmd_and_wincheck_drivers() {
        for dpmi_bytes in [4 * 1024 * 1024, 8 * 1024 * 1024, 32 * 1024 * 1024] {
            let mut sim = SimulatedDosKernel::new();
            sim.memory = DosMemoryStats {
                dpmi_free_physical_bytes: dpmi_bytes,
                dpmi_largest_block_bytes: dpmi_bytes,
                ..DosMemoryStats::default()
            };
            for &b in b"exit" {
                sim.key_queue.push_back(BiosKeyEvent::Char(b));
            }
            sim.key_queue.push_back(BiosKeyEvent::Char(0x0D));
            let mut out = Vec::new();
            let mut err = Vec::new();
            assert_eq!(
                execute_dos_wincmd(&[], sim, Vec::new(), &mut out, &mut err),
                0
            );
        }

        let mut repl_dial = SimulatedDosKernel::new();
        for &b in b"ver" {
            repl_dial.key_queue.push_back(BiosKeyEvent::Char(b));
        }
        repl_dial.key_queue.push_back(BiosKeyEvent::Char(0x0D));
        for &b in b"exit" {
            repl_dial.key_queue.push_back(BiosKeyEvent::Char(b));
        }
        repl_dial.key_queue.push_back(BiosKeyEvent::Char(0x0D));
        let mut out_d = Vec::new();
        let mut err_d = Vec::new();
        assert_eq!(
            execute_dos_wincmd(
                &[String::from("--dialect=freedos")],
                repl_dial,
                Vec::new(),
                &mut out_d,
                &mut err_d,
            ),
            0
        );
        assert!(String::from_utf8_lossy(&out_d).contains("FreeDOS"));

        let mut out_piped = Vec::new();
        let mut err_piped = Vec::new();
        assert_eq!(
            execute_dos_wincmd(
                &[],
                SimulatedDosKernel::new(),
                format!("echo piped_dos{CRLF}exit{CRLF}").into_bytes(),
                &mut out_piped,
                &mut err_piped,
            ),
            0
        );
        assert!(String::from_utf8_lossy(&out_piped).contains("piped_dos"));

        let mut out_bad = Vec::new();
        let mut err_bad = Vec::new();
        assert_eq!(
            execute_dos_wincmd(
                &[String::from("--unknown-dos-flag")],
                SimulatedDosKernel::new(),
                Vec::new(),
                &mut out_bad,
                &mut err_bad,
            ),
            1
        );

        let mut out_c = Vec::new();
        let mut err_c = Vec::new();
        assert_eq!(
            execute_dos_wincmd(
                &[String::from("/C"), String::from("echo dos_ok")],
                SimulatedDosKernel::new(),
                Vec::new(),
                &mut out_c,
                &mut err_c,
            ),
            0
        );
        assert!(String::from_utf8_lossy(&out_c).contains("dos_ok"));

        let mut linter_out = Vec::new();
        let mut linter_err = Vec::new();
        assert_eq!(
            execute_dos_wincheck(
                &[String::from("--dialect=dos622"), String::from("-")],
                SimulatedDosKernel::new(),
                format!("@echo off{CRLF}").into_bytes(),
                &mut linter_out,
                &mut linter_err,
            ),
            0
        );
    }
}
