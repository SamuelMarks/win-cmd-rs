//! Safe `#![no_std]` MS-DOS hardware abstraction, FAT/PSP domain primitives, and simulated kernel.
//!
//! All MS-DOS logic in `win-cmd-rs`—packed 16-bit FAT dates/times, `INT 21h AH=43h` attribute bytes,
//! 8.3 filename validation/truncation, 126-byte Program Segment Prefix (`PSP:0x80`) command tails,
//! BIOS scan-code input, `DosFatVfs`, and single-tasking `%TEMP%` child execution—is written in
//! 100% safe Rust (`#![forbid(unsafe_code)]`) against [`DosKernelApi`].
//!
//! [`SimulatedDosKernel`] provides a deterministic in-memory FAT16/FAT32 + DPMI test oracle.
//!
//! This enables 100% function, line, and branch test coverage on any host platform, while the
//! separate `crates/wincmd-dos` target crate binds [`DosKernelApi`] to DJGPP `libc` and `INT 21h`.

pub mod console;
pub mod kernel;
pub mod sim;
pub mod types;

pub use self::console::{DosConsoleLineEditor, DosLineReadOutcome, run_dos_bios_repl};
pub use self::kernel::{
    DosDirRecord, DosDiskSpace, DosExecChildSpec, DosKernelApi, DosStatRecord, DosWriteDisposition,
    SharedDosKernel,
};
pub use self::sim::{
    DosFaultOp, DosFaultRule, SimChildProgram, SimulatedDosKernel, SimulatedDriveConfig,
};
pub use self::types::{
    BiosKeyEvent, BiosScanCode, DosEnvSizeLimit, DosFileName8Dot3, DosMemoryStats, DosOemVendor,
    DosVersion, DriveMediaState, FatAttributeByte, LfnSupportMode, LongCmdlineTransfer,
    MAX_PSP_COMMAND_TAIL_BYTES, PackedDosDate, PackedDosTime, PackedDosTimestamp,
    PipeSpoolCleanupPolicy, PspCommandTail, ShortNamePolicy, WriteProtectState,
};

#[cfg(test)]
/// Unit tests for MS-DOS domain primitives (`types`), `DosKernelApi`, and `SimulatedDosKernel`.
mod tests {
    use alloc::borrow::ToOwned;
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::dos::types::{DOS_MAX_EPOCH_SECS, DOS_MIN_EPOCH_SECS};
    use crate::error::CmdError;
    use crate::types::{
        BS_STR, CRLF, CodePage, DosErrorCode, DriveLetter, ExitCode, InterruptState, VerifyCopyMode,
    };
    use crate::vfs::{FileAttributeFlags, FileTimestamp};

    /// Verifies `PackedDosDate`, `PackedDosTime`, `PackedDosTimestamp`, and `FatAttributeByte`.
    #[test]
    fn test_packed_dos_timestamps_and_fat_attributes() {
        assert_eq!(PackedDosDate::encode(1979, 1, 1), None);
        assert_eq!(PackedDosDate::encode(2108, 1, 1), None);
        assert_eq!(PackedDosDate::encode(1980, 0, 1), None);
        assert_eq!(PackedDosDate::encode(1980, 2, 0), None);
        assert_eq!(PackedDosDate::encode(1981, 2, 29), None);
        let leap = PackedDosDate::encode(1984, 2, 29);
        assert!(leap.is_some());
        let d = leap.unwrap_or(PackedDosDate::MIN_1980_01_01);
        assert_eq!((d.year(), d.month(), d.day()), (1984, 2, 29));
        assert_eq!(d.to_string(), "0x085d");

        assert_eq!(PackedDosTime::encode(24, 0, 0), None);
        assert_eq!(PackedDosTime::encode(12, 60, 0), None);
        assert_eq!(PackedDosTime::encode(12, 0, 60), None);
        let t = PackedDosTime::encode(23, 59, 59).unwrap_or(PackedDosTime::MIDNIGHT);
        assert_eq!((t.hour(), t.minute(), t.second()), (23, 59, 58));
        assert_eq!(t.to_string(), "0xbf7d");

        let clamped_low =
            PackedDosTimestamp::from_file_timestamp(FileTimestamp::from_epoch_secs(0));
        assert_eq!(
            clamped_low.to_file_timestamp(),
            Ok(FileTimestamp::from_epoch_secs(DOS_MIN_EPOCH_SECS))
        );
        let clamped_high = PackedDosTimestamp::from_file_timestamp(FileTimestamp::from_epoch_secs(
            DOS_MAX_EPOCH_SECS.saturating_add(999),
        ));
        assert_eq!(
            clamped_high.to_file_timestamp(),
            Ok(FileTimestamp::from_epoch_secs(DOS_MAX_EPOCH_SECS))
        );

        let jan_ts = FileTimestamp::from_civil_utc(1992, 1, 15, 8, 30).unwrap_or_default();
        let jan_dos = PackedDosTimestamp::from_file_timestamp(jan_ts);
        assert_eq!(jan_dos.to_file_timestamp(), Ok(jan_ts));

        let def_dos = PackedDosTimestamp::default();
        assert!(def_dos.to_string().contains(":0x"));
        assert!(def_dos.to_file_timestamp().is_ok());

        let bad_sec = PackedDosTimestamp {
            date: PackedDosDate::MIN_1980_01_01,
            time: PackedDosTime(0x001F),
        };
        assert!(bad_sec.to_file_timestamp().is_err());
        let bad_month = PackedDosTimestamp {
            date: PackedDosDate(0x0001),
            time: PackedDosTime::MIDNIGHT,
        };
        assert!(bad_month.to_file_timestamp().is_err());

        let mut all_vfs = FileAttributeFlags::READ_ONLY;
        all_vfs.insert(FileAttributeFlags::HIDDEN);
        all_vfs.insert(FileAttributeFlags::SYSTEM);
        all_vfs.insert(FileAttributeFlags::DIRECTORY);
        all_vfs.insert(FileAttributeFlags::ARCHIVE);
        let fat_all = FatAttributeByte::from_vfs_flags(all_vfs);
        assert_eq!(fat_all.to_vfs_flags(), all_vfs);
        assert_eq!(fat_all.to_string(), "0x37");
        assert_eq!(
            FatAttributeByte::from_vfs_flags(FileAttributeFlags::EMPTY).to_vfs_flags(),
            FileAttributeFlags::EMPTY
        );
    }

    /// Verifies `DosFileName8Dot3`, `PspCommandTail`, `DosVersion`, and `BiosScanCode`.
    #[test]
    fn test_dos_8_3_filenames_psp_tail_and_bios_keys() {
        assert!(!DosFileName8Dot3::is_legal_fat_8_3_byte(0x20));
        assert!(!DosFileName8Dot3::is_legal_fat_8_3_byte(0x7F));
        assert!(!DosFileName8Dot3::is_legal_fat_8_3_byte(b'*'));
        assert!(DosFileName8Dot3::is_legal_fat_8_3_byte(b'A'));

        for invalid in [
            "...",
            "a.b.c",
            "123456789.txt",
            "a.txtx",
            ".ext",
            "a*b.c",
            "a.b*",
        ] {
            assert!(DosFileName8Dot3::validate_strict(invalid).is_err());
        }
        assert!(DosFileName8Dot3::validate_strict("autoexec").is_ok());
        let ok_file = DosFileName8Dot3::validate_strict("config.sys");
        assert_eq!(ok_file.as_ref().map(DosFileName8Dot3::stem), Ok("CONFIG"));
        assert_eq!(ok_file.as_ref().map(DosFileName8Dot3::extension), Ok("SYS"));
        assert_eq!(
            ok_file.as_ref().map(DosFileName8Dot3::as_str),
            Ok("CONFIG.SYS")
        );
        assert_eq!(
            ok_file.as_ref().map(ToString::to_string),
            Ok("CONFIG.SYS".to_owned())
        );

        for bad_trunc in ["...", "a.b.c", ".ext", "a*b", "a.b*"] {
            assert!(
                DosFileName8Dot3::normalize(bad_trunc, ShortNamePolicy::StrictDosTruncate, 1)
                    .is_err()
            );
        }
        assert_eq!(
            DosFileName8Dot3::normalize("verylongstem", ShortNamePolicy::StrictDosTruncate, 1)
                .map(|n| n.to_string()),
            Ok("VERYLONG".to_owned())
        );
        assert_eq!(
            DosFileName8Dot3::normalize("verylongstem.html", ShortNamePolicy::StrictDosTruncate, 1)
                .map(|n| n.to_string()),
            Ok("VERYLONG.HTM".to_owned())
        );
        assert!(DosFileName8Dot3::normalize(".", ShortNamePolicy::Win95NumericTail, 1).is_err());
        assert_eq!(
            DosFileName8Dot3::normalize("Program Files", ShortNamePolicy::Win95NumericTail, 1)
                .map(|n| n.to_string()),
            Ok("PROGRA~1".to_owned())
        );
        assert_eq!(
            ShortNamePolicy::default().to_string(),
            "strict_dos_truncate"
        );
    }

    /// Verifies `PspCommandTail`, `DosVersion`, `DosOemVendor`, and `BiosScanCode` decoding.
    #[test]
    fn test_psp_command_tail_versions_and_bios_scan_codes() {
        let (empty_tail, empty_env) =
            PspCommandTail::encode("MEM.EXE", "", LongCmdlineTransfer::default())
                .unwrap_or_default();
        assert!(empty_tail.is_empty());
        assert_eq!(empty_tail.len_byte(), 0);
        assert_eq!(empty_tail.to_psp_block(), vec![0, 0x0D]);
        assert_eq!(empty_env, None);

        let crlf_tail = format!("/c{CRLF}");
        let (sp_tail, _) =
            PspCommandTail::encode("MEM.EXE", &crlf_tail, LongCmdlineTransfer::Strict126BytePsp)
                .unwrap_or_default();
        assert_eq!(sp_tail.tail_bytes(), b" /c");
        let (pre_spaced, _) =
            PspCommandTail::encode("MEM.EXE", " /p", LongCmdlineTransfer::Strict126BytePsp)
                .unwrap_or_default();
        assert_eq!(pre_spaced.tail_bytes(), b" /p");
        assert!(!sp_tail.is_empty());

        let long_arg = "x".repeat(130);
        assert!(matches!(
            PspCommandTail::encode("MEM.EXE", &long_arg, LongCmdlineTransfer::Strict126BytePsp),
            Err(CmdError::CommandLineTooLong { limit: 126, .. })
        ));
        let (trunc_tail, env_opt) =
            PspCommandTail::encode("MEM.EXE", &long_arg, LongCmdlineTransfer::CmdlineEnvVar)
                .unwrap_or_default();
        assert_eq!(trunc_tail.len_byte(), 126);
        assert!(env_opt.is_some_and(|s| s.starts_with("MEM.EXE x")));
        assert_eq!(
            LongCmdlineTransfer::Strict126BytePsp.to_string(),
            "strict_126_byte_psp"
        );

        let vendor_pairs = [
            (DosOemVendor::PcDos, "PC-DOS"),
            (DosOemVendor::MsDos, "MS-DOS"),
            (DosOemVendor::FreeDos, "FreeDOS"),
            (DosOemVendor::DrDos, "DR-DOS"),
            (DosOemVendor::Windows9xDos7, "MS-DOS 7"),
            (DosOemVendor::DosBox, "DOSBox"),
            (DosOemVendor::Unknown(0x42), "OEM(0x42)"),
        ];
        for (v, expected) in vendor_pairs {
            assert_eq!(v.to_string(), expected);
        }
        assert_eq!(DosVersion::default().to_string(), "MS-DOS Version 6.22");
        assert_eq!(LfnSupportMode::default().to_string(), "8.3_only");
        assert_eq!(WriteProtectState::default().to_string(), "writable");
        assert_eq!(DriveMediaState::default().to_string(), "ready");
        assert_eq!(
            DosWriteDisposition::default().to_string(),
            "create_truncate"
        );

        let scan_pairs = [
            (0x3B, "Extended(F1)"),
            (0x3D, "Extended(F3)"),
            (0x41, "Extended(F7)"),
            (0x42, "Extended(F8)"),
            (0x43, "Extended(F9)"),
            (0x47, "Extended(Home)"),
            (0x48, "Extended(Up)"),
            (0x49, "Extended(PageUp)"),
            (0x4B, "Extended(Left)"),
            (0x4D, "Extended(Right)"),
            (0x4F, "Extended(End)"),
            (0x50, "Extended(Down)"),
            (0x51, "Extended(PageDown)"),
            (0x52, "Extended(Insert)"),
            (0x53, "Extended(Delete)"),
            (0x99, "Extended(Scan(0x99))"),
        ];
        for (scan, expected) in scan_pairs {
            assert_eq!(
                BiosKeyEvent::Extended(BiosScanCode::from_raw(scan)).to_string(),
                expected
            );
        }
        assert_eq!(BiosKeyEvent::Char(b'A').to_string(), "Char(0x41)");
    }

    /// Verifies `SimulatedDosKernel` system calls, RTC clock, drives, and fault injection.
    #[test]
    fn test_simulated_dos_kernel_system_clock_drives_and_faults() {
        let mut k = SimulatedDosKernel::default();
        let boxed = k.clone_box();
        assert_eq!(boxed.dos_version(), DosVersion::default());
        assert_eq!(k.active_codepage(), Ok(CodePage::OemUnitedStates));
        assert_eq!(
            k.set_active_codepage(CodePage::OemMultilingualLatin1),
            Ok(())
        );
        assert_eq!(k.active_codepage(), Ok(CodePage::OemMultilingualLatin1));

        assert!(k.set_current_date(1979, 1, 1).is_err());
        assert!(k.set_current_date(2100, 1, 1).is_err());
        assert!(k.set_current_date(1995, 2, 30).is_err());
        assert_eq!(k.set_current_date(1995, 8, 24), Ok(()));
        assert!(k.set_current_time(12, 0, 0, 100).is_err());
        assert!(k.set_current_time(25, 0, 0, 0).is_err());
        assert_eq!(k.set_current_time(14, 30, 20, 50), Ok(()));
        assert!(k.current_datetime().is_ok());

        assert_eq!(k.verify_flag(), VerifyCopyMode::Unverified);
        k.set_verify_flag(VerifyCopyMode::Verified);
        assert_eq!(k.verify_flag(), VerifyCopyMode::Verified);
        assert!(k.memory_stats().is_ok());
        assert_ne!(k.startup_env_vars().unwrap_or_default(), Vec::new());
        assert_eq!(k.startup_argv(), Ok(Vec::new()));

        assert_eq!(k.current_drive(), DriveLetter::C);
        assert_eq!(
            k.set_current_drive(DriveLetter::Z),
            Err(CmdError::DriveNotFound {
                drive: DriveLetter::Z
            })
        );
        k.mount_drive(DriveLetter::A, SimulatedDriveConfig::default());
        assert!(k.is_drive_valid(DriveLetter::A));
        assert_eq!(k.set_current_drive(DriveLetter::A), Ok(()));
        k.set_drive_free_space(DriveLetter::A, 730_112);
        assert_eq!(
            k.volume_space(DriveLetter::A).map(|s| s.free_bytes),
            Ok(730_112)
        );
        assert!(k.volume_label_and_serial(DriveLetter::A).is_ok());
        k.set_drive_media_state(DriveLetter::A, DriveMediaState::DriveNotReady);
        assert!(k.drive_cwd(DriveLetter::A).is_err());
        assert!(k.volume_space(DriveLetter::A).is_err());
        assert!(k.volume_label_and_serial(DriveLetter::A).is_err());
        assert!(
            k.write_file_bytes("A:/X.TXT", b"1", DosWriteDisposition::CreateTruncate)
                .is_err()
        );
        k.unmount_drive(DriveLetter::A);
        k.set_drive_media_state(DriveLetter::A, DriveMediaState::Ready);
        k.set_drive_write_protect(DriveLetter::A, WriteProtectState::Writable);
        k.set_drive_free_space(DriveLetter::A, 0);
        assert!(!k.is_drive_valid(DriveLetter::A));
        assert_eq!(
            k.lfn_support_for_drive(DriveLetter::A),
            LfnSupportMode::Disabled8Dot3Only
        );
        assert_eq!(k.set_current_drive(DriveLetter::C), Ok(()));

        k.ctrl_break = InterruptState::Pending;
        assert_eq!(k.poll_ctrl_break(), InterruptState::Pending);
        assert_eq!(k.poll_ctrl_break(), InterruptState::Clear);
        k.key_queue.push_back(BiosKeyEvent::Char(b'Y'));
        assert_eq!(k.read_console_key(), Ok(Some(BiosKeyEvent::Char(b'Y'))));
        assert_eq!(k.read_console_key(), Ok(None));
        assert_eq!(k.console_geometry(), (80, 25));
        assert_eq!(k.clear_console_screen(0x1F), Ok(()));
        assert_eq!(k.last_cleared_attr, Some(0x1F));

        k.push_fault(DosFaultRule {
            op: DosFaultOp::Any,
            path_substr: None,
            error_code: DosErrorCode::GeneralFailure,
        });
        assert!(k.active_codepage().is_err());
        assert!(k.current_datetime().is_err());
        assert!(k.memory_stats().is_err());
        assert!(k.startup_env_vars().is_err());
        assert!(k.startup_argv().is_err());
        assert!(k.clear_console_screen(0x07).is_err());
    }

    /// Verifies `SimulatedDosKernel` strict 8.3 CRUD, attributes, timestamps, `truename`, and `rename_entry`.
    #[test]
    fn test_simulated_dos_kernel_8_3_crud_rename_and_truename() {
        let mut k = SimulatedDosKernel::new();
        assert_eq!(k.truename(""), Ok(format!("C:{BS_STR}")));
        assert_eq!(k.truename("con"), Ok("C:/CON".to_owned()));
        assert_eq!(k.truename("C:NUL"), Ok("C:/NUL".to_owned()));
        assert!(k.truename("Z:NUL").is_err());
        assert!(k.truename("1:NUL").is_err());
        assert!(k.stat_entry("   ").is_err());
        assert!(k.stat_entry("C:/...").is_err());
        assert!(k.stat_entry("C:/NO_SUCH_LEAF.TXT").is_err());

        assert!(k.create_dir("C:/").is_err());
        assert_eq!(k.create_dir(&format!("C:{BS_STR}DOS")), Ok(()));
        assert!(k.create_dir("C:/DOS").is_err());
        assert!(k.create_dir("C:/MISSING/SUB").is_err());
        assert_eq!(
            k.truename("C:/dos/longfilename.text"),
            Ok(format!("C:{BS_STR}DOS{BS_STR}LONGFILE.TEX"))
        );

        assert!(
            k.write_file_bytes("C:/", b"x", DosWriteDisposition::CreateTruncate)
                .is_err()
        );
        assert!(
            k.write_file_bytes("C:/DOS", b"x", DosWriteDisposition::CreateTruncate)
                .is_err()
        );
        assert!(
            k.write_file_bytes("C:/a*b", b"x", DosWriteDisposition::CreateTruncate)
                .is_err()
        );
        assert_eq!(
            k.write_file_bytes(
                "C:/DOS/MEM.TXT",
                b"one",
                DosWriteDisposition::CreateTruncate
            ),
            Ok(())
        );
        assert_eq!(
            k.write_file_bytes(
                "C:/DOS/MEM.TXT",
                b"two",
                DosWriteDisposition::CreateTruncate
            ),
            Ok(())
        );
        assert_eq!(
            k.write_file_bytes("C:/DOS/MEM.TXT", b"!", DosWriteDisposition::CreateOrAppend),
            Ok(())
        );
        assert_eq!(k.read_file_bytes("C:/DOS/MEM.TXT"), Ok(b"two!".to_vec()));
        assert!(k.read_file_bytes("C:/DOS").is_err());
        assert!(k.read_file_bytes("C:/a*b").is_err());
        assert!(k.create_dir("C:/DOS/MEM.TXT/SUB").is_err());

        assert!(
            k.set_attributes("C:/", FatAttributeByte::READ_ONLY)
                .is_err()
        );
        assert_eq!(
            k.set_attributes("C:/DOS/MEM.TXT", FatAttributeByte::READ_ONLY),
            Ok(())
        );
        assert_eq!(
            k.get_attributes("C:/DOS/MEM.TXT"),
            Ok(FatAttributeByte::READ_ONLY)
        );
        assert!(
            k.write_file_bytes("C:/DOS/MEM.TXT", b"no", DosWriteDisposition::CreateTruncate)
                .is_err()
        );
        assert!(k.delete_file("C:/DOS/MEM.TXT").is_err());
        assert_eq!(
            k.set_attributes("C:/DOS/MEM.TXT", FatAttributeByte::ARCHIVE),
            Ok(())
        );

        let ts = PackedDosTimestamp::default();
        assert!(k.set_timestamp("C:/", ts).is_err());
        assert_eq!(k.set_timestamp("C:/DOS/MEM.TXT", ts), Ok(()));
        assert_eq!(k.stat_entry("C:/DOS").map(|s| s.size), Ok(0));
        assert_eq!(k.read_dir_entries("C:/DOS").map(|v| v.len()), Ok(1));
        assert!(k.read_dir_entries("C:/DOS/MEM.TXT").is_err());
        assert!(k.read_dir_entries("C:/NOPE").is_err());
    }

    /// Verifies directory removal, CWD guards, write-protect refusals, and same/cross-drive renames.
    #[test]
    fn test_simulated_dos_kernel_rmdir_cwd_and_rename_edges() {
        let mut k = SimulatedDosKernel::new();
        assert_eq!(k.create_dir("C:/WORK"), Ok(()));
        assert_eq!(k.create_dir("C:/WORK/SUB"), Ok(()));
        assert_eq!(
            k.write_file_bytes(
                "C:/WORK/SUB/F.TXT",
                b"ok",
                DosWriteDisposition::CreateTruncate
            ),
            Ok(())
        );

        assert!(k.set_drive_cwd("C:/WORK/SUB/F.TXT").is_err());
        assert!(k.set_drive_cwd("C:/NO_SUCH").is_err());
        assert!(k.set_drive_cwd("C:/NO_PARENT/SUB").is_err());
        assert_eq!(k.drive_cwd(DriveLetter::C), Ok(format!("C:{BS_STR}")));
        assert_eq!(k.stat_entry("C:/").map(|s| s.size), Ok(0));
        assert_eq!(k.read_dir_entries("C:/").map(|v| v.len()), Ok(1));
        assert_eq!(k.set_drive_cwd("C:/WORK"), Ok(()));
        assert_eq!(k.set_drive_cwd("C:/"), Ok(()));
        assert_eq!(k.set_drive_cwd("C:/WORK"), Ok(()));
        assert_eq!(k.drive_cwd(DriveLetter::C), Ok(format!("C:{BS_STR}WORK")));
        assert_eq!(k.read_file_bytes("./SUB/F.TXT"), Ok(b"ok".to_vec()));
        assert_eq!(k.read_dir_entries("../WORK").map(|v| v.len()), Ok(1));

        assert!(k.remove_dir("C:/").is_err());
        assert!(k.remove_dir("C:/NO_SUCH").is_err());
        assert!(k.remove_dir("C:/NO_PARENT/SUB").is_err());
        assert!(k.read_dir_entries("C:/NO_PARENT/SUB").is_err());
        assert!(k.remove_dir("C:/WORK/SUB/F.TXT").is_err());
        assert!(k.remove_dir("C:/WORK").is_err());
        assert!(k.remove_dir("C:/WORK/SUB").is_err());

        k.mount_drive(DriveLetter::D, SimulatedDriveConfig::default());
        assert!(k.rename_entry("C:/WORK/SUB", "D:/SUB").is_err());
        assert!(k.rename_entry("C:/", "C:/NEW").is_err());
        assert!(k.rename_entry("C:/WORK/SUB", "C:/").is_err());
        assert_eq!(k.rename_entry("C:/WORK/SUB", "C:/WORK/SUB"), Ok(()));
        assert!(k.rename_entry("C:/WORK/SUB", "C:/WORK/SUB/CHILD").is_err());
        assert!(k.rename_entry("C:/WORK", "C:/WORK2").is_err());
        assert_eq!(k.create_dir("C:/OTHER"), Ok(()));
        assert!(k.rename_entry("C:/WORK/SUB", "C:/OTHER").is_err());

        assert_eq!(k.rename_entry("C:/WORK/SUB", "C:/MOVED"), Ok(()));
        assert_eq!(k.read_file_bytes("C:/MOVED/F.TXT"), Ok(b"ok".to_vec()));

        assert_eq!(
            k.set_attributes("C:/OTHER", FatAttributeByte::READ_ONLY),
            Ok(())
        );
        assert!(k.remove_dir("C:/OTHER").is_err());
        assert_eq!(
            k.set_attributes("C:/OTHER", FatAttributeByte::NORMAL),
            Ok(())
        );
        assert_eq!(k.remove_dir("C:/OTHER"), Ok(()));

        k.set_drive_write_protect(DriveLetter::C, WriteProtectState::WriteProtected);
        assert!(k.delete_file("C:/MOVED/F.TXT").is_err());
        k.set_drive_write_protect(DriveLetter::C, WriteProtectState::Writable);
        assert!(k.delete_file("C:/").is_err());
        assert!(k.delete_file("C:/MOVED").is_err());
        assert_eq!(k.delete_file("C:/MOVED/F.TXT"), Ok(()));
        assert_eq!(k.remove_dir("C:/MOVED"), Ok(()));
    }

    /// Verifies DOS 7 LFN mode, 8.3 collision generation (`~1`..`~9`), and programmable child `exec_child`.
    #[test]
    fn test_simulated_dos_kernel_lfn_mode_and_exec_child() {
        let mut k = SimulatedDosKernel::new();
        k.mount_drive(
            DriveLetter::D,
            SimulatedDriveConfig {
                lfn_mode: LfnSupportMode::EnabledInt21Ax71,
                ..SimulatedDriveConfig::default()
            },
        );
        assert_eq!(k.create_dir("D:/Program Files"), Ok(()));
        assert_eq!(k.create_dir("D:/Program Files 2"), Ok(()));
        assert_eq!(
            k.write_file_bytes("D:/README.TXT", b"83", DosWriteDisposition::CreateTruncate),
            Ok(())
        );
        assert_eq!(
            k.write_file_bytes(
                "D:/PROGRA~1/Long Script.bat",
                b"@echo hi",
                DosWriteDisposition::CreateTruncate
            ),
            Ok(())
        );
        assert_eq!(
            k.write_file_bytes(
                "D:/Program Files 2/Other Long Script.bat",
                b"@echo other",
                DosWriteDisposition::CreateTruncate
            ),
            Ok(())
        );
        assert_eq!(
            k.read_dir_entries("D:/Program Files 2").map(|v| v.len()),
            Ok(1)
        );
        assert_eq!(
            k.read_dir_entries("D:/Program Files").map(|v| v.len()),
            Ok(1)
        );
        assert_eq!(
            k.truename("D:/Program Files"),
            Ok(format!("D:{BS_STR}PROGRAM FILES"))
        );
        assert!(k.create_dir("D:/bad*lfn").is_err());
        assert!(k.create_dir("D:/bad*lfn/sub").is_err());
        assert!(k.create_dir("D:/Program Files/. .").is_err());
        assert!(k.stat_entry("D:/Program Files/. .").is_err());
        assert!(k.create_dir("D:/. /sub").is_err());
        assert!(k.create_dir(&format!("D:/{}", "L".repeat(260))).is_err());
        assert!(k.create_dir("D:/ctrl\x01name").is_err());
        assert!(k.create_dir("D:/README.TXT/sub").is_err());
        assert!(k.create_dir("D:/MissingParent/sub").is_err());
        assert!(k.read_file_bytes("D:/MissingLeaf.txt").is_err());

        for n in 1u8..=9u8 {
            let alias = DosFileName8Dot3::normalize(
                "SamePrefixName10.txt",
                ShortNamePolicy::Win95NumericTail,
                n,
            )
            .map(|a| a.to_string())
            .unwrap_or_default();
            assert_eq!(
                k.write_file_bytes(
                    &format!("D:/{alias}"),
                    b"x",
                    DosWriteDisposition::CreateTruncate
                ),
                Ok(())
            );
        }
        assert!(
            k.write_file_bytes(
                "D:/SamePrefixName10.txt",
                b"x",
                DosWriteDisposition::CreateTruncate
            )
            .is_err()
        );

        run_simulated_child_exec_checks(&mut k);
    }

    /// Helper testing all `SimChildProgram` variants and `DosFaultRule` path-substring matching.
    ///
    /// # Arguments
    /// * `k` - Mutable [`SimulatedDosKernel`] instance.
    fn run_simulated_child_exec_checks(k: &mut SimulatedDosKernel) {
        let (tail, _) =
            PspCommandTail::encode("APP.EXE", "arg1", LongCmdlineTransfer::CmdlineEnvVar)
                .unwrap_or_default();
        let mut spec = DosExecChildSpec {
            program_dos_path: format!("C:{BS_STR}APP.EXE"),
            psp_tail: tail,
            args: vec!["arg1".to_owned()],
            cwd_dos_path: format!("C:{BS_STR}"),
            env_vars: vec![("CMDLINE".to_owned(), "APP.EXE arg1".to_owned())],
            stdin_spool_path: Some("C:/IN.TMP".to_owned()),
            stdout_spool_path: Some("C:/OUT.TMP".to_owned()),
            stderr_spool_path: Some("C:/ERR.TMP".to_owned()),
        };
        assert!(k.exec_child(&spec).is_err());

        k.register_child_program(
            &format!("C:{BS_STR}APP.EXE"),
            SimChildProgram::FixedOutput {
                exit_code: ExitCode::new(7),
                stdout: b"out".to_vec(),
                stderr: b"err".to_vec(),
                min_conventional_bytes: 600_000,
            },
        );
        assert_eq!(k.exec_child(&spec), Err(CmdError::InsufficientMemory));

        k.memory.largest_conventional_block = 620_000;
        assert_eq!(k.exec_child(&spec), Ok(ExitCode::new(7)));
        assert_eq!(k.read_file_bytes("C:/OUT.TMP"), Ok(b"out".to_vec()));
        assert_eq!(k.read_file_bytes("C:/ERR.TMP"), Ok(b"err".to_vec()));

        k.register_child_program(
            &format!("C:{BS_STR}ECHO.COM"),
            SimChildProgram::EchoPspAndCmdline {
                exit_code: ExitCode::SUCCESS,
            },
        );
        spec.program_dos_path = format!("C:{BS_STR}ECHO.COM");
        assert_eq!(k.exec_child(&spec), Ok(ExitCode::SUCCESS));
        assert_eq!(
            k.read_file_bytes("C:/OUT.TMP"),
            Ok(format!("PSP= arg1{CRLF}CMDLINE=APP.EXE arg1{CRLF}").into_bytes())
        );

        assert_eq!(
            k.write_file_bytes(
                "C:/IN.TMP",
                b"dos pipe",
                DosWriteDisposition::CreateTruncate
            ),
            Ok(())
        );
        k.register_child_program(
            &format!("C:{BS_STR}UPPER.COM"),
            SimChildProgram::UppercaseFilter {
                exit_code: ExitCode::SUCCESS,
            },
        );
        spec.program_dos_path = format!("C:{BS_STR}UPPER.COM");
        assert_eq!(k.exec_child(&spec), Ok(ExitCode::SUCCESS));
        assert_eq!(k.read_file_bytes("C:/OUT.TMP"), Ok(b"DOS PIPE".to_vec()));

        spec.stdin_spool_path = None;
        spec.stdout_spool_path = None;
        spec.stderr_spool_path = None;
        spec.env_vars.clear();
        assert_eq!(k.exec_child(&spec), Ok(ExitCode::SUCCESS));
        spec.program_dos_path = format!("C:{BS_STR}ECHO.COM");
        assert_eq!(k.exec_child(&spec), Ok(ExitCode::SUCCESS));
        spec.program_dos_path = format!("C:{BS_STR}APP.EXE");
        assert_eq!(k.exec_child(&spec), Ok(ExitCode::new(7)));

        k.register_child_program(
            &format!("C:{BS_STR}BAD.EXE"),
            SimChildProgram::FailWithDosError(DosErrorCode::BadFormat),
        );
        spec.program_dos_path = format!("C:{BS_STR}BAD.EXE");
        assert!(k.exec_child(&spec).is_err());

        k.push_fault(DosFaultRule {
            op: DosFaultOp::ReadFile,
            path_substr: Some("OUT.TMP".to_owned()),
            error_code: DosErrorCode::SharingViolation,
        });
        assert!(k.read_file_bytes("C:/IN.TMP").is_ok());
        assert!(k.read_file_bytes("C:/OUT.TMP").is_err());
        k.fault_queue.clear();
        k.push_fault(DosFaultRule {
            op: DosFaultOp::DeleteFile,
            path_substr: Some("OUT.TMP".to_owned()),
            error_code: DosErrorCode::AccessDenied,
        });
        assert!(k.read_file_bytes("C:/OUT.TMP").is_ok());
        assert_eq!(
            k.write_file_bytes("C:/OTHER.TMP", b"1", DosWriteDisposition::CreateTruncate),
            Ok(())
        );
        assert!(k.delete_file("C:/IN.TMP").is_ok());
        assert!(k.delete_file("C:/OUT.TMP").is_err());
    }

    /// Verifies `DosEnvSizeLimit`, `PipeSpoolCleanupPolicy`, and `ResponseFileAtSign` policies.
    #[test]
    fn test_env_limits_and_spool_cleanup_policies() {
        assert_eq!(DosEnvSizeLimit::default(), DosEnvSizeLimit::Dpmi32KiB);
        assert_eq!(DosEnvSizeLimit::Dpmi32KiB.max_bytes(), 32_767);
        assert_eq!(DosEnvSizeLimit::Dpmi32KiB.to_string(), "dpmi_32kib");
        let small = DosEnvSizeLimit::CommandComBytes(16);
        assert_eq!(small.max_bytes(), 16);
        assert_eq!(small.to_string(), "command_com_bytes(16)");
        assert_eq!(small.validate_env_block(&[]), Ok(2));
        assert_eq!(
            small.validate_env_block(&[("A".to_owned(), "1".to_owned())]),
            Ok(5)
        );
        assert_eq!(
            small.validate_env_block(&[("LONG_KEY".to_owned(), "LONG_VAL".to_owned())]),
            Err(CmdError::OutOfEnvironmentSpace)
        );
        assert_eq!(PipeSpoolCleanupPolicy::default().to_string(), "strict");
        assert_eq!(
            PipeSpoolCleanupPolicy::BestEffort.to_string(),
            "best_effort"
        );
        assert_eq!(
            LongCmdlineTransfer::ResponseFileAtSign.to_string(),
            "response_file_at_sign"
        );
        assert!(
            PspCommandTail::encode(
                "APP.EXE",
                &"x".repeat(130),
                LongCmdlineTransfer::ResponseFileAtSign
            )
            .is_err()
        );
    }

    /// Verifies `SharedDosKernel` delegation across every `DosKernelApi` method.
    #[test]
    fn test_shared_dos_kernel_delegation() {
        let mut sh = SharedDosKernel::new(SimulatedDosKernel::new());
        sh.with_mut(|k| {
            k.mount_drive(DriveLetter::D, SimulatedDriveConfig::default());
            k.register_child_program(
                &format!("C:{BS_STR}NOOP.COM"),
                SimChildProgram::EchoPspAndCmdline {
                    exit_code: ExitCode::SUCCESS,
                },
            );
        });
        assert_eq!(sh.with(DosKernelApi::current_drive), DriveLetter::C);
        let mut sh2 = sh.clone_box();
        assert_eq!(sh2.dos_version(), DosVersion::default());
        assert_eq!(
            sh2.set_active_codepage(CodePage::OemMultilingualLatin1),
            Ok(())
        );
        assert_eq!(sh2.active_codepage(), Ok(CodePage::OemMultilingualLatin1));
        assert_eq!(sh2.set_current_date(1996, 3, 14), Ok(()));
        assert_eq!(sh2.set_current_time(9, 15, 0, 0), Ok(()));
        assert!(sh2.current_datetime().is_ok());
        sh2.set_verify_flag(VerifyCopyMode::Verified);
        assert_eq!(sh2.verify_flag(), VerifyCopyMode::Verified);
        assert!(sh2.memory_stats().is_ok());
        assert!(sh2.startup_env_vars().is_ok());
        assert!(sh2.startup_argv().is_ok());
        assert_eq!(sh2.set_current_drive(DriveLetter::D), Ok(()));
        assert_eq!(sh2.current_drive(), DriveLetter::D);
        assert!(sh2.is_drive_valid(DriveLetter::D));
        assert_eq!(
            sh2.lfn_support_for_drive(DriveLetter::D),
            LfnSupportMode::Disabled8Dot3Only
        );
        assert_eq!(sh2.create_dir("D:/SUB"), Ok(()));
        assert_eq!(sh2.set_drive_cwd("D:/SUB"), Ok(()));
        assert_eq!(sh2.drive_cwd(DriveLetter::D), Ok(format!("D:{BS_STR}SUB")));
        assert_eq!(sh2.set_drive_cwd("D:/"), Ok(()));
        assert!(sh2.volume_space(DriveLetter::D).is_ok());
        assert!(sh2.volume_label_and_serial(DriveLetter::D).is_ok());
        assert!(sh2.truename("D:/SUB").is_ok());
        assert_eq!(
            sh2.write_file_bytes("D:/SUB/F.TXT", b"hi", DosWriteDisposition::CreateTruncate),
            Ok(())
        );
        assert_eq!(sh2.read_file_bytes("D:/SUB/F.TXT"), Ok(b"hi".to_vec()));
        assert!(sh2.stat_entry("D:/SUB/F.TXT").is_ok());
        assert_eq!(sh2.read_dir_entries("D:/SUB").map(|v| v.len()), Ok(1));
        assert_eq!(
            sh2.set_attributes("D:/SUB/F.TXT", FatAttributeByte::ARCHIVE),
            Ok(())
        );
        assert_eq!(
            sh2.get_attributes("D:/SUB/F.TXT"),
            Ok(FatAttributeByte::ARCHIVE)
        );
        assert_eq!(
            sh2.set_timestamp("D:/SUB/F.TXT", PackedDosTimestamp::default()),
            Ok(())
        );
        assert_eq!(sh2.rename_entry("D:/SUB/F.TXT", "D:/SUB/G.TXT"), Ok(()));
        assert_eq!(sh2.delete_file("D:/SUB/G.TXT"), Ok(()));
        assert_eq!(sh2.remove_dir("D:/SUB"), Ok(()));
        let spec = DosExecChildSpec {
            program_dos_path: format!("C:{BS_STR}NOOP.COM"),
            psp_tail: PspCommandTail::default(),
            args: Vec::new(),
            cwd_dos_path: format!("C:{BS_STR}"),
            env_vars: Vec::new(),
            stdin_spool_path: None,
            stdout_spool_path: None,
            stderr_spool_path: None,
        };
        assert_eq!(sh.exec_child(&spec), Ok(ExitCode::SUCCESS));
        assert_eq!(sh.poll_ctrl_break(), InterruptState::Clear);
        assert_eq!(sh.read_console_key(), Ok(None));
        assert_eq!(sh.console_geometry(), (80, 25));
        assert_eq!(sh.clear_console_screen(0x07), Ok(()));
    }

    /// Verifies `DosConsoleLineEditor` cursor/overstrike/template/completion/history keys (`F1`/`F3`/`F7`/`F8`/`F9`).
    #[test]
    fn test_dos_console_line_editor_scan_codes_and_history() {
        use crate::runtime::Interpreter;
        use crate::types::{DoskeyEditMode, FileCompletionMode};

        let mut kernel = SimulatedDosKernel::new();
        assert_eq!(kernel.create_dir("C:/DOCS"), Ok(()));
        assert_eq!(
            kernel.write_file_bytes(
                "C:/AUTOEXEC.BAT",
                b"@rem",
                DosWriteDisposition::CreateTruncate
            ),
            Ok(())
        );
        let (mut interp, mut shared) = Interpreter::with_dos_kernel(kernel);
        interp.config.file_completion = FileCompletionMode::Enabled;
        let mut editor = DosConsoleLineEditor::new();
        let mut out: Vec<u8> = Vec::new();

        assert_eq!(DosLineReadOutcome::Eof.to_string(), "eof");
        assert_eq!(DosLineReadOutcome::Interrupted.to_string(), "interrupted");
        assert_eq!(
            DosLineReadOutcome::Line("ver".to_owned()).to_string(),
            "line(ver)"
        );

        assert_eq!(
            editor.read_line(&mut interp, &mut shared, "C:\\>", &mut out),
            Ok(DosLineReadOutcome::Eof)
        );
        shared.with_mut(|k| k.ctrl_break = InterruptState::Pending);
        assert_eq!(
            editor.read_line(&mut interp, &mut shared, "C:\\>", &mut out),
            Ok(DosLineReadOutcome::Interrupted)
        );
        shared.with_mut(|k| k.key_queue.push_back(BiosKeyEvent::Char(0x03)));
        assert_eq!(
            editor.read_line(&mut interp, &mut shared, "C:\\>", &mut out),
            Ok(DosLineReadOutcome::Interrupted)
        );
        shared.with_mut(|k| k.key_queue.push_back(BiosKeyEvent::Char(0x1A)));
        assert_eq!(
            editor.read_line(&mut interp, &mut shared, "C:\\>", &mut out),
            Ok(DosLineReadOutcome::Eof)
        );

        shared.with_mut(|k| {
            for ev in [
                BiosKeyEvent::Char(0x08),
                BiosKeyEvent::Char(0x01),
                BiosKeyEvent::Char(b'e'),
                BiosKeyEvent::Char(0x1A),
                BiosKeyEvent::Char(b'c'),
                BiosKeyEvent::Char(b'x'),
                BiosKeyEvent::Char(0x08),
                BiosKeyEvent::Char(b'h'),
                BiosKeyEvent::Char(b'o'),
                BiosKeyEvent::Extended(BiosScanCode::Home),
                BiosKeyEvent::Extended(BiosScanCode::Home),
                BiosKeyEvent::Extended(BiosScanCode::Left),
                BiosKeyEvent::Extended(BiosScanCode::Right),
                BiosKeyEvent::Extended(BiosScanCode::Insert),
                BiosKeyEvent::Char(b'C'),
                BiosKeyEvent::Extended(BiosScanCode::End),
                BiosKeyEvent::Extended(BiosScanCode::End),
                BiosKeyEvent::Char(b'Z'),
                BiosKeyEvent::Extended(BiosScanCode::Insert),
                BiosKeyEvent::Extended(BiosScanCode::Left),
                BiosKeyEvent::Extended(BiosScanCode::Delete),
                BiosKeyEvent::Extended(BiosScanCode::Delete),
                BiosKeyEvent::Char(0x0D),
            ] {
                k.key_queue.push_back(ev);
            }
        });
        assert_eq!(
            editor.read_line(&mut interp, &mut shared, "C:\\>", &mut out),
            Ok(DosLineReadOutcome::Line("eCho".to_owned()))
        );
        assert_eq!(interp.console.doskey_edit_mode, DoskeyEditMode::Insert);

        run_dos_editor_template_history_and_tab_checks(
            &mut editor,
            &mut interp,
            &mut shared,
            &mut out,
        );
    }

    /// Exercises `F1`, `F3`, `F7`, `F8`, `F9`, `Up`/`Down`/`PgUp`/`PgDn`, `Esc`, `Tab`, and `Ctrl+D` in `DosConsoleLineEditor`.
    ///
    /// # Arguments
    /// * `editor` - Mutable [`DosConsoleLineEditor`].
    /// * `interp` - Mutable [`crate::runtime::Interpreter`].
    /// * `shared` - Shared [`SimulatedDosKernel`] handle.
    /// * `out` - Captured console output buffer.
    fn run_dos_editor_template_history_and_tab_checks(
        editor: &mut DosConsoleLineEditor,
        interp: &mut crate::runtime::Interpreter,
        shared: &mut SharedDosKernel<SimulatedDosKernel>,
        out: &mut Vec<u8>,
    ) {
        shared.with_mut(|k| {
            for ev in [
                BiosKeyEvent::Extended(BiosScanCode::F1),
                BiosKeyEvent::Extended(BiosScanCode::Right),
                BiosKeyEvent::Extended(BiosScanCode::F3),
                BiosKeyEvent::Extended(BiosScanCode::F1),
                BiosKeyEvent::Extended(BiosScanCode::Right),
                BiosKeyEvent::Char(0x1B),
                BiosKeyEvent::Char(b'v'),
                BiosKeyEvent::Char(b'e'),
                BiosKeyEvent::Char(b'r'),
            ] {
                k.key_queue.push_back(ev);
            }
        });
        assert_eq!(
            editor.read_line(interp, shared, "C:\\>", out),
            Ok(DosLineReadOutcome::Line("ver".to_owned()))
        );

        interp.console.record_history("echo second");
        shared.with_mut(|k| {
            for ev in [
                BiosKeyEvent::Extended(BiosScanCode::Up),
                BiosKeyEvent::Extended(BiosScanCode::Up),
                BiosKeyEvent::Extended(BiosScanCode::Down),
                BiosKeyEvent::Extended(BiosScanCode::Down),
                BiosKeyEvent::Extended(BiosScanCode::Down),
                BiosKeyEvent::Extended(BiosScanCode::PageUp),
                BiosKeyEvent::Extended(BiosScanCode::PageDown),
                BiosKeyEvent::Extended(BiosScanCode::F7),
                BiosKeyEvent::Char(b'x'),
                BiosKeyEvent::Char(b'y'),
                BiosKeyEvent::Extended(BiosScanCode::F3),
                BiosKeyEvent::Char(0x1B),
                BiosKeyEvent::Char(b'e'),
                BiosKeyEvent::Extended(BiosScanCode::F8),
                BiosKeyEvent::Extended(BiosScanCode::F8),
                BiosKeyEvent::Char(0x1B),
                BiosKeyEvent::Char(b'z'),
                BiosKeyEvent::Extended(BiosScanCode::F8),
                BiosKeyEvent::Extended(BiosScanCode::F9),
                BiosKeyEvent::Extended(BiosScanCode::Left),
                BiosKeyEvent::Char(b'9'),
                BiosKeyEvent::Char(0x0A),
                BiosKeyEvent::Extended(BiosScanCode::F9),
                BiosKeyEvent::Char(b'x'),
                BiosKeyEvent::Char(0x1B),
                BiosKeyEvent::Extended(BiosScanCode::F9),
                BiosKeyEvent::Char(b'0'),
                BiosKeyEvent::Char(0x0D),
                BiosKeyEvent::Extended(BiosScanCode::F9),
                BiosKeyEvent::Char(b'2'),
                BiosKeyEvent::Char(0x0D),
                BiosKeyEvent::Extended(BiosScanCode::Other(0x99)),
                BiosKeyEvent::Char(0x1B),
                BiosKeyEvent::Char(b'A'),
                BiosKeyEvent::Char(b'U'),
                BiosKeyEvent::Char(0x09),
                BiosKeyEvent::Char(0x09),
                BiosKeyEvent::Char(0x04),
                BiosKeyEvent::Char(0x0D),
            ] {
                k.key_queue.push_back(ev);
            }
        });
        let tab_line = editor.read_line(interp, shared, "C:\\>", out);
        assert!(tab_line.is_ok());

        interp.console.clear_history();
        shared.with_mut(|k| {
            for ev in [
                BiosKeyEvent::Extended(BiosScanCode::Up),
                BiosKeyEvent::Extended(BiosScanCode::Down),
                BiosKeyEvent::Extended(BiosScanCode::PageUp),
                BiosKeyEvent::Extended(BiosScanCode::PageDown),
                BiosKeyEvent::Extended(BiosScanCode::F8),
                BiosKeyEvent::Extended(BiosScanCode::F9),
            ] {
                k.key_queue.push_back(ev);
            }
        });
        assert_eq!(
            editor.read_line(interp, shared, "C:\\>", out),
            Ok(DosLineReadOutcome::Eof)
        );
    }

    /// Verifies `run_dos_bios_repl` across `^` continuations, `( ... )` `More? `, `Ctrl+C`, `ECHO OFF`, and `EXIT`.
    #[test]
    fn test_run_dos_bios_repl_continuations_blocks_and_exit() {
        use crate::runtime::Interpreter;
        use crate::types::EchoState;

        let (mut interp, mut shared) = Interpreter::with_dos_kernel(SimulatedDosKernel::new());
        let script_keys = concat!(
            "\r",
            "echo pre^\r",
            "mid^\r",
            "fix\r",
            "(\r",
            "echo in^\r",
            "blk\r",
            ")\r",
            "bad\x03",
            "echo off\r",
            "echo quiet\r",
            "exit 5\r",
        );
        shared.with_mut(|k| {
            for b in script_keys.bytes() {
                k.key_queue.push_back(BiosKeyEvent::Char(b));
            }
        });
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run_dos_bios_repl(&mut interp, &mut shared, &mut out, &mut err),
            Ok(ExitCode::new(5))
        );
        let out_str = String::from_utf8_lossy(&out);
        assert!(out_str.contains("premidfix"));
        assert!(out_str.contains("inblk"));
        assert!(out_str.contains("quiet"));
        assert_eq!(interp.console.echo_state, EchoState::Off);

        let (mut eof_interp, mut eof_sh) = Interpreter::with_dos_kernel(SimulatedDosKernel::new());
        eof_sh.with_mut(|k| {
            for b in b"echo eof_^\r" {
                k.key_queue.push_back(BiosKeyEvent::Char(*b));
            }
        });
        let mut eof_out = Vec::new();
        let mut eof_err = Vec::new();
        assert_eq!(
            run_dos_bios_repl(&mut eof_interp, &mut eof_sh, &mut eof_out, &mut eof_err),
            Ok(ExitCode::SUCCESS)
        );
        assert!(String::from_utf8_lossy(&eof_out).contains("eof_"));
        assert_eq!(
            run_dos_bios_repl(&mut eof_interp, &mut eof_sh, &mut eof_out, &mut eof_err),
            Ok(ExitCode::SUCCESS)
        );
    }
}
