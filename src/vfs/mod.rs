//! Cross-Platform Virtual File System (VFS) trait, file attributes, timestamps, and backends.
//!
//! All file, directory, attribute, drive, share, link, and device operations in `win-cmd-rs`
//! go through the [`VirtualFileSystem`] trait. Three complete implementations are provided:
//! - [`InMemoryVfs`]: 100% deterministic in-memory multi-drive and UNC-share filesystem with
//!   inode-backed shared hardlinks, bounded 32-hop symbolic link and junction resolution,
//!   8.3 short names, case-insensitive lookup, Windows attribute bitmasks, and DOS devices.
//! - [`HostOsVfs`]: Bridges Windows drive mounts onto host POSIX/Windows directories with
//!   case-insensitive resolution, full [`crate::error::CmdError`] I/O error mapping, and optional sandbox
//!   symlink containment.
//! - [`DosFatVfs`]: Safe `#![no_std]` MS-DOS FAT12/16/32 and DOS 7 LFN backend over [`crate::dos::DosKernelApi`].

pub mod devices;
pub mod dos;
pub mod glob;
pub mod path;

#[cfg(feature = "std")]
/// Host OS filesystem bridge (`HostOsVfs`) and Wine/POSIX mount translation.
mod host;
/// Deterministic in-memory multi-drive and UNC-share VFS backend (`InMemoryVfs`).
mod memory;
/// Core `VirtualFileSystem` trait, metadata, timestamps, and attribute types.
mod traits;

pub use self::dos::DosFatVfs;
#[cfg(feature = "std")]
pub use self::host::{HostOsVfs, SandboxContainment};
pub use self::memory::InMemoryVfs;
pub use self::traits::{
    CaseFoldedString, DEFAULT_VFS_EPOCH_SECS, FileAttributeFlags, FileAttributes, FileTimestamp,
    MAX_SYMLINK_HOPS, VfsKey, VfsMetadata, VfsRoot, VirtualFileSystem, VolumeInfo,
};

#[cfg(test)]
/// Unit tests for [`InMemoryVfs`], [`HostOsVfs`], [`FileAttributes`], and [`FileTimestamp`].
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::error::CmdError;
    use crate::types::AttributeMutation::{Clear, Set};
    use crate::types::DirCreationDepth::{CreateParents, ImmediateParentOnly};
    use crate::types::DirRemovalMode::{EmptyOnly, RecursiveSubtree};
    use crate::types::ReadOnlyDeletePolicy::{ForceDeleteReadOnly, RespectReadOnly};
    use crate::types::{
        CmdLocaleConfig, DateFormatStyle, DriveLetter, HostBindingMode, MklinkKind, TimeClockFormat,
    };
    use crate::vfs::host::normalize_lexical_host_path;
    use crate::vfs::path::WindowsPath;

    /// Verifies [`FileAttributeFlags`] bitmask operations, formatting, and `/A:...` filtering.
    #[test]
    fn test_file_attributes_format_and_filter() {
        assert!(FileAttributeFlags::EMPTY.is_empty());
        let mut attr = FileAttributes::default_file();
        assert!(!attr.is_empty());
        attr.insert(FileAttributeFlags::READ_ONLY);
        attr.insert(FileAttributeFlags::HIDDEN);
        attr.insert(FileAttributeFlags::SYSTEM);
        attr.insert(FileAttributeFlags::REPARSE_POINT);
        assert_eq!(attr.to_cmd_attr_string(), "-rahs---l");
        assert!(attr.matches_filter("R+H:S-D+A"));
        assert!(attr.matches_filter("-D"));
        assert!(!attr.matches_filter("D"));
        assert!(!attr.matches_filter("-R"));
        assert!(!attr.matches_filter("-A"));
        assert!(!attr.matches_filter("-H"));
        assert!(!attr.matches_filter("-S"));
        assert!(!attr.matches_filter("-L"));
        assert!(attr.matches_filter("L"));
        assert!(attr.matches_filter("X"));

        attr.set_flag(FileAttributeFlags::READ_ONLY, Clear);
        assert!(!attr.is_read_only());
        attr.set_flag(FileAttributeFlags::READ_ONLY, Set);
        assert!(attr.is_read_only());

        let dir_attr = FileAttributes::default_dir();
        assert_eq!(dir_attr.to_cmd_attr_string(), "d--------");
        assert!(dir_attr.matches_filter("D"));
    }

    /// Verifies [`FileTimestamp`] chronological ordering, civil UTC construction, virtual parsing, and locale formatting.
    #[test]
    fn test_file_timestamp_chronological_and_locales() {
        let t_dec_2025 = FileTimestamp::from_civil_utc(2025, 12, 31, 23, 59).unwrap_or_default();
        let t_jan_2026 = FileTimestamp::from_civil_utc(2026, 1, 2, 0, 5).unwrap_or_default();
        assert!(t_dec_2025 < t_jan_2026);
        assert_eq!(t_dec_2025.to_string(), "12/31/2025  11:59 PM");
        assert_eq!(t_jan_2026.to_string(), "01/02/2026  12:05 AM");

        // Strict calendar & leap-year validation on civil construction
        assert_eq!(FileTimestamp::from_civil_utc(1960, 1, 1, 0, 0), None);
        assert_eq!(FileTimestamp::from_civil_utc(2026, 0, 1, 0, 0), None);
        assert_eq!(FileTimestamp::from_civil_utc(2026, 13, 1, 0, 0), None);
        assert_eq!(FileTimestamp::from_civil_utc(2026, 4, 31, 0, 0), None);
        assert_eq!(FileTimestamp::from_civil_utc(2026, 2, 29, 0, 0), None);
        assert_eq!(FileTimestamp::from_civil_utc(2100, 2, 29, 0, 0), None);
        assert!(FileTimestamp::from_civil_utc(2024, 2, 29, 0, 0).is_some());
        assert!(FileTimestamp::from_civil_utc(2000, 2, 29, 0, 0).is_some());
        assert_eq!(FileTimestamp::from_civil_utc(2026, 1, 1, 24, 0), None);
        assert_eq!(FileTimestamp::from_civil_utc(2026, 1, 1, 12, 60), None);

        // Parse virtual date/time forms
        assert_eq!(
            FileTimestamp::parse_virtual_str("Tue 11/10/2026").format_default(),
            "11/10/2026  09:00 AM"
        );
        assert_eq!(
            FileTimestamp::parse_virtual_str("11/11/2026  12:00 PM").format_default(),
            "11/11/2026  12:00 PM"
        );
        assert_eq!(
            FileTimestamp::parse_virtual_str("11/11/2026  03:15 PM").format_default(),
            "11/11/2026  03:15 PM"
        );
        assert_eq!(
            FileTimestamp::parse_virtual_str("11/11/2026  12:30 AM").format_default(),
            "11/11/2026  12:30 AM"
        );
        assert_eq!(
            FileTimestamp::parse_virtual_str("11/11/2026  08:45 AM").format_default(),
            "11/11/2026  08:45 AM"
        );
        assert_eq!(
            FileTimestamp::parse_virtual_str("11/11/2026 bad:tok 08:45 AM").format_default(),
            "11/11/2026  08:45 AM"
        );
        assert_eq!(
            FileTimestamp::parse_virtual_str("2026-12-25 14:20").format_default(),
            "12/25/2026  02:20 PM"
        );
        assert_eq!(
            FileTimestamp::parse_virtual_str("no-digits-here"),
            FileTimestamp::default()
        );
        assert_eq!(
            FileTimestamp::parse_virtual_str("12/34"),
            FileTimestamp::default()
        );

        // Locale formatting (ISO + 24-hour, Euro + 12-hour)
        let mut locale = CmdLocaleConfig {
            date_format: DateFormatStyle::Iso8601,
            date_separator: '-',
            time_separator: ':',
            decimal_separator: '.',
            thousand_separator: ',',
            time_clock_format: TimeClockFormat::TwentyFourHour,
        };
        assert_eq!(t_dec_2025.format_with_locale(&locale), "2025-12-31  23:59");
        locale.date_format = DateFormatStyle::DayMonthYearEuro;
        locale.date_separator = '.';
        assert_eq!(t_dec_2025.format_with_locale(&locale), "31.12.2025  23:59");
    }

    /// Verifies [`InMemoryVfs`] drives, UNC isolation, shared hardlinks, symlinks/junctions, and symlink loop detection.
    #[test]
    fn test_in_memory_vfs_drives_unc_hardlinks_and_symlinks() {
        let mut vfs = InMemoryVfs::default();
        assert_eq!(vfs.current_drive(), DriveLetter::C);
        assert!(vfs.volume_info(DriveLetter::C).is_ok());
        assert!(vfs.volume_info(DriveLetter::Z).is_err());
        assert!(vfs.set_current_drive(DriveLetter::D).is_ok());
        assert_eq!(vfs.current_drive(), DriveLetter::D);
        assert!(vfs.set_current_drive(DriveLetter::Z).is_err());
        assert!(vfs.set_current_drive(DriveLetter::C).is_ok());

        // UNC paths are isolated from C:\!
        let bs = char::from(92);
        let unc_share = format!("{bs}{bs}server{bs}share");
        let unc_share_upper = format!("{bs}{bs}SERVER{bs}SHARE");
        let unc_file = format!("{unc_share}{bs}isolated.txt");
        let unc_file_2 = format!("{unc_share}{bs}second.txt");
        let unc_dir = format!("{unc_share}{bs}unc_sub");
        let unc_link = format!("{unc_share}{bs}unc_link.txt");
        let unc_file_upper = format!("{unc_share_upper}{bs}isolated.txt");
        assert!(vfs.write_bytes(r"C:\isolated.txt", b"local_c").is_ok());
        assert!(vfs.write_bytes(&unc_file, b"unc_share").is_ok());
        assert!(vfs.write_bytes(&unc_file_2, b"unc_share_2").is_ok());
        assert!(vfs.create_dir(&unc_dir, ImmediateParentOnly).is_ok());
        assert!(vfs.read_dir(&unc_dir).is_ok());
        assert!(
            vfs.create_symlink(&unc_link, "isolated.txt", MklinkKind::FileSymlink)
                .is_ok()
        );
        assert_eq!(vfs.read_bytes(&unc_link), Ok(b"unc_share".to_vec()));
        assert!(vfs.stat(&unc_file).is_ok());
        assert!(vfs.stat(&unc_dir).is_ok());
        assert_eq!(vfs.read_bytes(r"C:\isolated.txt"), Ok(b"local_c".to_vec()));
        assert_eq!(vfs.read_bytes(&unc_file_upper), Ok(b"unc_share".to_vec()));
        assert_eq!(CaseFoldedString::new("Server").as_str(), "SERVER");
        assert!(
            vfs.stat(&unc_share)
                .is_ok_and(|m| m.attributes.is_directory())
        );
        assert!(vfs.set_drive_cwd(&vfs.resolve_path(&unc_share)).is_ok());
        assert!(vfs.create_dir(r"C:\", ImmediateParentOnly).is_err());

        // Create directories with and without parents
        assert!(vfs.create_dir(r"C:\a\b\c", ImmediateParentOnly).is_err());
        assert!(vfs.create_dir(r"C:\a\b\c", CreateParents).is_ok());
        assert!(vfs.create_dir(r"C:\a\b\c", CreateParents).is_err());
        assert!(vfs.create_dir(r"C:\a\b\c\d", ImmediateParentOnly).is_ok());
        assert!(vfs.create_dir(r"C:\a\b\c\d", ImmediateParentOnly).is_err());
        assert!(vfs.create_dir(r"Z:\foo", ImmediateParentOnly).is_err());

        // Set and query CWD
        let target_cwd = vfs.resolve_path(r"C:\A\B");
        assert!(vfs.set_drive_cwd(&target_cwd).is_ok());
        assert_eq!(
            vfs.drive_cwd(DriveLetter::C).map(|p| p.to_windows_string()),
            Ok(r"C:\a\b".to_owned())
        );
        assert!(vfs.drive_cwd(DriveLetter::Z).is_err());
        assert!(
            vfs.set_drive_cwd(&WindowsPath::root(DriveLetter::Z))
                .is_err()
        );
        assert!(
            vfs.set_drive_cwd(&vfs.resolve_path(r"C:\nonexistent"))
                .is_err()
        );

        // Write, append, read, and stat files
        assert!(vfs.write_bytes(r"C:\a\b\Hello World.txt", b"first").is_ok());
        assert!(vfs.write_bytes(r"C:\a\b\Hello World.txt", b"hello").is_ok());
        assert!(
            vfs.append_bytes(r"C:\a\b\hello world.txt", b" world")
                .is_ok()
        );
        assert!(vfs.append_bytes(r"C:\a\b\new.txt", b"new").is_ok());
        assert_eq!(
            vfs.read_bytes(r"C:\A\B\HELLO WORLD.TXT"),
            Ok(b"hello world".to_vec())
        );

        // Wildcard exists and DOS device NUL checks
        assert!(vfs.exists(r"C:\a\b\*.txt"));
        assert!(vfs.exists(r"C:\a\b\new.txt"));
        assert!(vfs.exists(r"C:\"));
        assert!(!vfs.exists(r"C:\a\b\missing.txt"));
        assert!(!vfs.exists(r"C:\a\b\*.bat"));
        assert!(!vfs.exists(r"C:\no_such_dir\*.txt"));
        assert!(vfs.exists("NUL"));
        assert!(vfs.exists(r"C:\a\b\NUL"));
        assert!(!vfs.exists(r"C:\nonexistent\NUL"));
        assert_eq!(vfs.read_bytes("NUL"), Ok(Vec::new()));
        assert!(vfs.write_bytes("NUL", b"discarded").is_ok());
        assert!(vfs.append_bytes("NUL", b"discarded").is_ok());
    }

    /// Verifies [`InMemoryVfs`] error cases, read-only enforcement, `read_dir`, and `remove_dir`.
    #[test]
    fn test_in_memory_vfs_errors_readonly_and_rmdir() {
        let mut vfs = InMemoryVfs::default();
        assert!(vfs.create_dir(r"C:\a\b", CreateParents).is_ok());
        assert!(
            vfs.write_bytes(r"C:\a\b\Hello World.txt", b"hello world")
                .is_ok()
        );
        assert!(vfs.write_bytes(r"C:\a\b\new.txt", b"new").is_ok());

        // Error cases on write/read/delete/mkdir
        assert!(vfs.write_bytes(r"C:\", b"root").is_err());
        assert!(vfs.write_bytes(r"C:\a\b", b"dir").is_err());
        assert!(vfs.append_bytes(r"C:\a\b", b"dir").is_err());
        assert!(vfs.delete_file(r"C:\a\b", ForceDeleteReadOnly).is_err());
        assert!(vfs.write_bytes(r"C:\no_parent\f.txt", b"x").is_err());
        assert!(vfs.write_bytes(r"C:\a\b\new.txt\child", b"x").is_err());
        assert!(
            vfs.create_dir(r"C:\a\b\new.txt\sub", ImmediateParentOnly)
                .is_err()
        );
        assert!(
            vfs.create_dir(r"C:\a\b\new.txt\sub", CreateParents)
                .is_err()
        );
        assert!(
            vfs.create_dir(r"C:\a\b\empty_sub", ImmediateParentOnly)
                .is_ok()
        );
        assert!(vfs.remove_dir(r"C:\a\b\empty_sub", EmptyOnly).is_ok());
        assert!(vfs.read_bytes(r"C:\a\b").is_err());
        assert!(vfs.stat(r"C:\a\b\new.txt\NUL").is_err());
        assert!(vfs.read_bytes(r"C:\a\b\new.txt\NUL").is_err());
        assert!(vfs.write_bytes(r"C:\a\b\new.txt\NUL", b"x").is_err());
        assert!(vfs.append_bytes(r"C:\a\b\new.txt\NUL", b"x").is_err());
        assert!(vfs.read_bytes(r"C:\missing_file.txt").is_err());
        assert!(
            vfs.set_drive_cwd(&vfs.resolve_path(r"C:\a\b\new.txt"))
                .is_err()
        );

        // Read-only attribute enforcement
        let mut ro = FileAttributes::default_file();
        ro.insert(FileAttributeFlags::READ_ONLY);
        assert!(vfs.set_attributes(r"C:\a\b\new.txt", ro).is_ok());
        assert!(vfs.set_attributes(r"C:\missing.txt", ro).is_err());
        assert!(vfs.write_bytes(r"C:\a\b\new.txt", b"fail").is_err());
        assert!(vfs.append_bytes(r"C:\a\b\new.txt", b"fail").is_err());
        assert!(vfs.delete_file(r"C:\a\b\new.txt", RespectReadOnly).is_err());
        assert!(
            vfs.delete_file(r"C:\a\b\new.txt", ForceDeleteReadOnly)
                .is_ok()
        );
        assert!(
            vfs.delete_file(r"C:\a\b\new.txt", ForceDeleteReadOnly)
                .is_err()
        );

        // read_dir and remove_dir
        assert!(vfs.read_dir(r"C:\a\b").is_ok());
        assert!(vfs.read_dir(r"C:\no_dir").is_err());
        assert!(vfs.read_dir(r"C:\a\b\Hello World.txt").is_err());

        assert!(vfs.remove_dir(r"C:\", RecursiveSubtree).is_err());
        assert!(vfs.remove_dir(r"C:\no_dir", RecursiveSubtree).is_err());
        assert!(
            vfs.remove_dir(r"C:\a\b\Hello World.txt", RecursiveSubtree)
                .is_err()
        );
        assert!(vfs.remove_dir(r"C:\a", EmptyOnly).is_err());
        assert!(vfs.remove_dir(r"C:\a", RecursiveSubtree).is_ok());

        let cloned = vfs.clone_box();
        assert_eq!(cloned.current_drive(), DriveLetter::C);
        assert_eq!(cloned.free_disk_space(DriveLetter::C), Ok(100_000_000));
        assert!(cloned.free_disk_space(DriveLetter::Z).is_err());
        assert_eq!(
            cloned.resolve_host_path(&WindowsPath::root(DriveLetter::C)),
            None
        );
    }

    /// Verifies [`InMemoryVfs`] `move_entry` and shared-inode hardlinks.
    #[test]
    fn test_in_memory_vfs_move_and_hardlinks() {
        let mut vfs = InMemoryVfs::default();
        // Test move_entry, real shared hardlinks, real symlinks/junctions, dangling symlinks, and loop detection!
        assert!(vfs.create_dir(r"C:\mv_src\sub", CreateParents).is_ok());
        assert!(vfs.write_bytes(r"C:\mv_src\sub\f.txt", b"data").is_ok());
        assert!(vfs.move_entry(r"C:\mv_src", r"C:\mv_src").is_ok());
        assert!(vfs.move_entry(r"C:\no_such_src", r"C:\mv_dst").is_err());
        assert!(
            vfs.move_entry(r"C:\mv_src", r"C:\no_parent\mv_dst")
                .is_err()
        );
        assert!(vfs.move_entry(r"C:\mv_src", r"C:\mv_dst").is_ok());
        assert!(vfs.exists(r"C:\mv_dst\sub\f.txt"));
        assert!(vfs.write_bytes(r"C:\mv_dst\sub\f2.txt", b"old").is_ok());
        assert!(
            vfs.move_entry(r"C:\mv_dst\sub\f.txt", r"C:\mv_dst\sub\f2.txt")
                .is_ok()
        );
        assert!(
            vfs.move_entry(r"C:\mv_dst\sub\f2.txt", r"C:\mv_dst\sub")
                .is_err()
        );
        assert!(
            vfs.move_entry(r"C:\mv_dst\sub", r"C:\mv_dst\sub\f2.txt")
                .is_err()
        );

        // Real Hardlink: mutating A updates B, and deleting B preserves A!
        assert!(
            vfs.create_hardlink(r"C:\mv_dst\f_hard.txt", r"C:\mv_dst\sub\f2.txt")
                .is_ok()
        );
        assert!(
            vfs.create_hardlink(r"C:\mv_dst\f_hard.txt", r"C:\mv_dst\sub\f2.txt")
                .is_err()
        );
        assert!(
            vfs.create_hardlink(r"C:\", r"C:\mv_dst\sub\f2.txt")
                .is_err()
        );
        assert!(
            vfs.create_hardlink(r"C:\no_parent\h.txt", r"C:\mv_dst\sub\f2.txt")
                .is_err()
        );
        assert!(
            vfs.create_hardlink(r"D:\cross_drive.txt", r"C:\mv_dst\sub\f2.txt")
                .is_err()
        );
        assert!(
            vfs.create_hardlink(r"C:\mv_dst\dir_hard", r"C:\mv_dst\sub")
                .is_err()
        );
        assert!(
            vfs.create_hardlink(r"C:\mv_dst\bad_hard.txt", r"C:\missing_src.txt")
                .is_err()
        );
        assert!(
            vfs.append_bytes(r"C:\mv_dst\f_hard.txt", b"_shared")
                .is_ok()
        );
        assert_eq!(
            vfs.read_bytes(r"C:\mv_dst\sub\f2.txt"),
            Ok(b"data_shared".to_vec())
        );
        let new_ts = FileTimestamp::from_civil_utc(2026, 11, 11, 12, 0).unwrap_or_default();
        assert!(vfs.touch_file(r"C:\mv_dst\f_hard.txt", new_ts).is_ok());
        assert_eq!(
            vfs.stat(r"C:\mv_dst\sub\f2.txt")
                .map(|m| m.modified_timestamp),
            Ok(new_ts)
        );
        assert!(
            vfs.delete_file(r"C:\mv_dst\f_hard.txt", RespectReadOnly)
                .is_ok()
        );
        assert_eq!(
            vfs.read_bytes(r"C:\mv_dst\sub\f2.txt"),
            Ok(b"data_shared".to_vec())
        );
    }

    /// Verifies [`InMemoryVfs`] file/directory symlinks, relative/rooted targets, dangling links, and junctions.
    #[test]
    fn test_in_memory_vfs_symlinks_junctions_and_unc_mounts() {
        let mut vfs = InMemoryVfs::default();
        let bs = crate::types::BS_CHAR;
        assert!(
            vfs.create_dir(&format!("{bs}{bs}server{bs}share{bs}folder"), CreateParents)
                .is_ok()
        );
        assert!(vfs.create_dir(r"C:\mv_dst\sub", CreateParents).is_ok());
        assert!(
            vfs.write_bytes(r"C:\mv_dst\sub\f2.txt", b"data_shared")
                .is_ok()
        );
        let file_sym = MklinkKind::FileSymlink;
        let dir_junc = MklinkKind::DirectoryJunction;
        assert!(vfs.create_symlink(r"C:\", r"C:\mv_dst", dir_junc).is_err());
        assert!(
            vfs.create_symlink(r"Z:\sym", r"C:\mv_dst", dir_junc)
                .is_err()
        );
        assert!(
            vfs.create_symlink(r"C:\no_parent\sym", r"C:\mv_dst", file_sym)
                .is_err()
        );
        assert!(
            vfs.create_symlink(r"C:\mv_dst\f_sym.txt", r"sub\f2.txt", file_sym)
                .is_ok()
        );
        assert!(
            vfs.create_symlink(r"C:\mv_dst\f_sym.txt", r"sub\f2.txt", file_sym)
                .is_err()
        );
        assert!(
            vfs.set_attributes(r"C:\mv_dst\f_sym.txt", FileAttributeFlags::default_file())
                .is_ok()
        );
        let sym_meta = vfs.stat(r"C:\mv_dst\f_sym.txt");
        assert!(
            sym_meta
                .as_ref()
                .is_ok_and(|m| m.attributes.is_reparse_point())
        );
        assert_eq!(sym_meta.map(|m| m.size), Ok(11));
        assert!(
            vfs.write_bytes(r"C:\mv_dst\f_sym.txt", b"via_symlink")
                .is_ok()
        );
        assert_eq!(
            vfs.read_bytes(r"C:\mv_dst\sub\f2.txt"),
            Ok(b"via_symlink".to_vec())
        );
        // RD on file symlink fails; DEL on file symlink removes only the link!
        assert!(vfs.remove_dir(r"C:\mv_dst\f_sym.txt", EmptyOnly).is_err());
        assert!(
            vfs.delete_file(r"C:\mv_dst\f_sym.txt", RespectReadOnly)
                .is_ok()
        );
        assert!(vfs.exists(r"C:\mv_dst\sub\f2.txt"));

        // Exercise 1-char relative, non-alpha-colon relative, rooted backslash, and rooted slash symlink targets
        assert!(vfs.write_bytes(r"C:\mv_dst\a", b"one_char").is_ok());
        assert!(
            vfs.create_symlink(r"C:\mv_dst\sym_1char", "a", MklinkKind::FileSymlink)
                .is_ok()
        );
        assert_eq!(
            vfs.read_bytes(r"C:\mv_dst\sym_1char"),
            Ok(b"one_char".to_vec())
        );
        assert!(
            vfs.create_symlink(r"C:\mv_dst\sym_nonalpha", "1:rel", MklinkKind::FileSymlink)
                .is_ok()
        );
        assert!(vfs.read_bytes(r"C:\mv_dst\sym_nonalpha").is_err());
        assert!(
            vfs.create_symlink(
                r"C:\mv_dst\sym_rooted_bs",
                r"\mv_dst\a",
                MklinkKind::FileSymlink
            )
            .is_ok()
        );
        assert_eq!(
            vfs.read_bytes(r"C:\mv_dst\sym_rooted_bs"),
            Ok(b"one_char".to_vec())
        );
        assert!(
            vfs.create_symlink(
                r"C:\mv_dst\sym_rooted_slash",
                "/mv_dst/a",
                MklinkKind::FileSymlink
            )
            .is_ok()
        );
        assert_eq!(
            vfs.read_bytes(r"C:\mv_dst\sym_rooted_slash"),
            Ok(b"one_char".to_vec())
        );
    }

    /// Verifies [`InMemoryVfs`] dangling symlinks, junctions, 32-hop loop detection, and UNC drive mounting.
    #[test]
    fn test_in_memory_vfs_dangling_links_loops_and_unc_mounts() {
        let mut vfs = InMemoryVfs::default();
        let bs = char::from(92);
        let unc_share = format!("{bs}{bs}server{bs}share");
        assert!(
            vfs.create_dir(&format!("{unc_share}{bs}folder"), CreateParents)
                .is_ok()
        );
        assert!(vfs.create_dir(r"C:\mv_dst\sub", CreateParents).is_ok());
        assert!(
            vfs.write_bytes(r"C:\mv_dst\sub\f2.txt", b"via_symlink")
                .is_ok()
        );
        let new_ts = FileTimestamp::from_civil_utc(2026, 11, 11, 12, 0).unwrap_or_default();

        // Dangling symlink does not swallow missing target into 0-byte file!
        assert!(
            vfs.create_symlink(
                r"C:\mv_dst\dangling.txt",
                r"C:\mv_dst\not_created_yet.txt",
                MklinkKind::FileSymlink
            )
            .is_ok()
        );
        assert!(vfs.read_bytes(r"C:\mv_dst\dangling.txt").is_err());
        let dang_meta = vfs.stat(r"C:\mv_dst\dangling.txt");
        assert!(
            dang_meta
                .as_ref()
                .is_ok_and(|m| m.attributes.is_reparse_point())
        );
        assert_eq!(dang_meta.map(|m| m.size), Ok(0));
        assert!(
            vfs.create_symlink(
                r"C:\mv_dst\dangling_dir",
                r"C:\mv_dst\missing_dir",
                MklinkKind::DirectorySymlink
            )
            .is_ok()
        );
        let dang_dir_meta = vfs.stat(r"C:\mv_dst\dangling_dir");
        assert!(
            dang_dir_meta
                .as_ref()
                .is_ok_and(|m| m.attributes.is_directory())
        );
        assert!(dang_dir_meta.is_ok_and(|m| m.attributes.is_reparse_point()));

        // Directory junction traversal & RD preserving target directory
        assert!(
            vfs.create_symlink(
                r"C:\mv_dst\junc_sub",
                r"C:\mv_dst\sub",
                MklinkKind::DirectoryJunction
            )
            .is_ok()
        );
        assert_eq!(
            vfs.read_bytes(r"C:\mv_dst\junc_sub\f2.txt"),
            Ok(b"via_symlink".to_vec())
        );
        assert_eq!(
            vfs.stat(r"C:\mv_dst\junc_sub")
                .map(|m| (m.size, m.attributes.is_directory())),
            Ok((0, true))
        );
        assert!(
            vfs.delete_file(r"C:\mv_dst\junc_sub", ForceDeleteReadOnly)
                .is_err()
        );
        assert!(vfs.remove_dir(r"C:\mv_dst\junc_sub", EmptyOnly).is_ok());
        assert!(vfs.exists(r"C:\mv_dst\sub\f2.txt"));

        // Symlink loop -> bounded 32-hop CmdError::IoFailure
        assert!(
            vfs.create_symlink(r"C:\loop_a", r"C:\loop_b", MklinkKind::FileSymlink)
                .is_ok()
        );
        assert!(
            vfs.create_symlink(r"C:\loop_b", r"C:\loop_a", MklinkKind::FileSymlink)
                .is_ok()
        );
        assert!(
            vfs.read_bytes(r"C:\loop_a")
                .is_err_and(|e| e.is_io_failure())
        );
        assert!(vfs.stat(r"C:\loop_a").is_err_and(|e| e.is_io_failure()));

        assert!(vfs.touch_file(r"C:\missing.txt", new_ts).is_err());

        let drive_y = DriveLetter::try_from_char('Y').unwrap_or(DriveLetter::Z);
        let mounted = vfs.mount_unc_drive(&unc_share, &["folder".to_owned()]);
        assert_eq!(mounted, Ok(DriveLetter::Z));
        assert!(vfs.exists(r"Z:\folder"));
        let empty_mounted = vfs.mount_unc_drive(&unc_share, &[]);
        assert_eq!(empty_mounted, Ok(drive_y));
        vfs.unmount_drive(drive_y);
        vfs.unmount_drive(drive_y);
        vfs.unmount_drive(DriveLetter::Z);
        assert!(vfs.drive_cwd(DriveLetter::Z).is_err());

        for b in b'A'..=b'Z' {
            let d = DriveLetter::try_from_char(char::from(b)).unwrap_or(DriveLetter::Z);
            vfs.drive_cwds.entry(d).or_default();
        }
        assert!(vfs.mount_unc_drive(&unc_share, &[]).is_err());
    }

    /// Verifies [`HostOsVfs`] non-aliasing drive mounts, sandbox symlink containment, and full I/O error mapping.
    #[test]
    fn test_host_os_vfs_mounts_sandbox_and_error_propagation() {
        let base_temp =
            std::env::temp_dir().join(format!("wincmd_host_vfs_test_{}", std::process::id()));
        let temp_c = base_temp.join("drive_c");
        let temp_d = base_temp.join("drive_d");
        let outside_dir = base_temp.join("outside_secret");
        assert!(std::fs::create_dir_all(&base_temp).is_ok());
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
        assert!(std::fs::create_dir_all(&temp_c).is_ok());
        assert!(std::fs::create_dir_all(&temp_d).is_ok());
        assert!(std::fs::create_dir_all(&outside_dir).is_ok());
        assert!(std::fs::write(outside_dir.join("secret.txt"), b"top_secret").is_ok());

        // HostOsVfs::new mounts ONLY C:, NOT D: aliased to C:!
        let mut host = HostOsVfs::new(temp_c.clone());
        assert_eq!(host.current_drive(), DriveLetter::C);
        assert!(host.set_current_drive(DriveLetter::D).is_err());
        assert!(host.volume_info(DriveLetter::D).is_err());

        // Mount D: onto its own distinct directory and verify C:\ and D:\ never alias!
        host.mount_drive(DriveLetter::D, temp_d);
        assert!(host.set_current_drive(DriveLetter::D).is_ok());
        assert!(host.set_current_drive(DriveLetter::Z).is_err());
        assert!(host.set_current_drive(DriveLetter::C).is_ok());
        assert!(host.write_bytes(r"C:\only_c.txt", b"on_c").is_ok());
        assert!(temp_c.join("only_c.txt").is_file());
        assert!(!host.exists(r"D:\only_c.txt"));
        assert!(host.volume_info(DriveLetter::C).is_ok());
        assert_eq!(host.free_disk_space(DriveLetter::C), Ok(100_000_000));
        assert!(host.free_disk_space(DriveLetter::Z).is_err());
        assert!(
            host.resolve_host_path(&WindowsPath::root(DriveLetter::C))
                .is_some()
        );

        // Sandbox symlink escape protection: symlinks inside C: pointing to outside_dir MUST be blocked!
        #[cfg(unix)]
        {
            let escape_file_link = temp_c.join("escape_secret.txt");
            let escape_dir_link = temp_c.join("escape_dir");
            let escape_dangling = temp_c.join("escape_dangling.txt");
            assert!(
                std::os::unix::fs::symlink(outside_dir.join("secret.txt"), &escape_file_link)
                    .is_ok()
            );
            assert!(std::os::unix::fs::symlink(&outside_dir, &escape_dir_link).is_ok());
            assert!(
                std::os::unix::fs::symlink(
                    Path::new("../outside_secret/missing_out.txt"),
                    &escape_dangling
                )
                .is_ok()
            );

            assert_eq!(
                host.read_bytes(r"C:\escape_secret.txt"),
                Err(CmdError::AccessDenied {
                    path: r"C:\escape_secret.txt".to_owned()
                })
            );
            assert_eq!(
                host.stat(r"C:\escape_secret.txt"),
                Err(CmdError::AccessDenied {
                    path: r"C:\escape_secret.txt".to_owned()
                })
            );
            assert_eq!(
                host.write_bytes(r"C:\escape_dangling.txt", b"pwn"),
                Err(CmdError::AccessDenied {
                    path: r"C:\escape_dangling.txt".to_owned()
                })
            );
            assert_eq!(
                host.set_drive_cwd(&host.resolve_path(r"C:\escape_dir")),
                Err(CmdError::AccessDenied {
                    path: r"C:\escape_dir".to_owned()
                })
            );
            // Deleting the symlink itself inside C:\ is permitted without touching outside_dir!
            assert!(
                host.delete_file(r"C:\escape_secret.txt", ForceDeleteReadOnly)
                    .is_ok()
            );
            assert!(
                host.delete_file(r"C:\escape_dangling.txt", ForceDeleteReadOnly)
                    .is_ok()
            );
            assert!(outside_dir.join("secret.txt").exists());
            // Listing C:\ while escape_dir symlink is present does not follow outside target
            assert!(host.read_dir(r"C:\").is_ok());
            assert!(host.remove_dir(r"C:\escape_dir", EmptyOnly).is_ok());
            assert!(outside_dir.exists());
        }
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
    }

    /// Verifies [`HostOsVfs`] 8.3 resolution, permissions, DOS devices, and attribute sidecar enforcement.
    #[test]
    fn test_host_os_vfs_crud_permissions_devices_and_attributes() {
        let base_temp =
            std::env::temp_dir().join(format!("wincmd_host_vfs_crud_{}", std::process::id()));
        let temp_c = base_temp.join("drive_c");
        assert!(std::fs::create_dir_all(&base_temp).is_ok());
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
        assert!(std::fs::create_dir_all(&temp_c).is_ok());
        let mut host = HostOsVfs::new(temp_c.clone());
        assert!(temp_c.is_dir());

        // Create directories and files on HostOsVfs
        assert!(host.create_dir(r"Z:\bad", ImmediateParentOnly).is_err());
        assert_eq!(
            host.create_dir(r"C:\no_parent\child", ImmediateParentOnly),
            Err(CmdError::PathNotFound {
                path: r"C:\no_parent\child".to_owned()
            })
        );
        assert!(host.create_dir(r"C:\Alpha\Beta", CreateParents).is_ok());
        assert!(host.create_dir(r"C:\Alpha\Beta", CreateParents).is_err());
        assert!(
            host.create_dir(r"C:\Alpha\Gamma", ImmediateParentOnly)
                .is_ok()
        );

        // Case-insensitive & 8.3 short-name path resolution on HostOsVfs
        let cwd_path = host.resolve_path(r"C:\alpha\beta");
        assert!(host.set_drive_cwd(&cwd_path).is_ok());
        assert!(
            host.set_drive_cwd(&WindowsPath::root(DriveLetter::Z))
                .is_err()
        );
        assert!(
            host.set_drive_cwd(&host.resolve_path(r"C:\nonexistent"))
                .is_err()
        );
        assert!(host.drive_cwd(DriveLetter::C).is_ok());
        assert!(host.drive_cwd(DriveLetter::Z).is_err());

        // Write, append, read, stat, exists, devices
        assert!(
            host.write_bytes(r"C:\alpha\LongFileName.txt", b"hello")
                .is_ok()
        );
        assert!(
            host.append_bytes(r"C:\ALPHA\LONGFI~1.TXT", b" world")
                .is_ok()
        );
        assert!(
            host.append_bytes(r"C:\alpha\brand_new_append.txt", b"fresh")
                .is_ok()
        );
        assert_eq!(
            host.read_bytes(r"C:\alpha\longfilename.txt"),
            Ok(b"hello world".to_vec())
        );
        assert!(host.write_bytes(r"C:\alpha\.hidden", b"dot").is_ok());
        assert!(
            host.stat(r"C:\alpha\.hidden")
                .is_ok_and(|m| m.attributes.is_hidden())
        );
        assert!(
            host.create_dir(r"C:\alpha\.dotdir", ImmediateParentOnly)
                .is_ok()
        );
        assert!(
            host.stat(r"C:\alpha\.dotdir")
                .is_ok_and(|m| !m.attributes.is_hidden())
        );
        assert!(host.remove_dir(r"C:\alpha\.dotdir", EmptyOnly).is_ok());
        // Non-read-only delete_file with force_read_only = false, and remove_dir on regular file
        assert!(
            host.remove_dir(r"C:\alpha\brand_new_append.txt", EmptyOnly)
                .is_err()
        );
        assert!(
            host.delete_file(r"C:\alpha\brand_new_append.txt", RespectReadOnly)
                .is_ok()
        );

        // Verify OS read-only permission error propagation in HostOsVfs::write_bytes!
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let ro_host_file = temp_c.join("os_readonly.txt");
            assert!(std::fs::write(&ro_host_file, b"locked").is_ok());
            assert!(
                std::fs::set_permissions(&ro_host_file, std::fs::Permissions::from_mode(0o444))
                    .is_ok()
            );
            assert!(
                host.stat(r"C:\os_readonly.txt")
                    .is_ok_and(|m| m.attributes.is_read_only())
            );
            assert_eq!(
                host.write_bytes(r"C:\os_readonly.txt", b"overwrite"),
                Err(CmdError::AccessDenied {
                    path: r"C:\os_readonly.txt".to_owned()
                })
            );
            assert!(
                std::fs::set_permissions(&ro_host_file, std::fs::Permissions::from_mode(0o644))
                    .is_ok()
            );
        }
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
    }

    /// Verifies [`HostOsVfs`] DOS devices, error branches, and read-only attribute sidecar enforcement.
    #[test]
    fn test_host_os_vfs_devices_errors_and_attribute_sidecar() {
        let base_temp =
            std::env::temp_dir().join(format!("wincmd_host_vfs_dev_{}", std::process::id()));
        let temp_c = base_temp.join("drive_c");
        assert!(std::fs::create_dir_all(&base_temp).is_ok());
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
        assert!(std::fs::create_dir_all(&temp_c).is_ok());
        let mut host = HostOsVfs::new(temp_c);
        assert!(host.create_dir(r"C:\Alpha", CreateParents).is_ok());
        assert!(
            host.write_bytes(r"C:\Alpha\LongFileName.txt", b"hello")
                .is_ok()
        );

        assert!(host.exists("NUL"));
        assert!(host.exists(r"C:\Alpha\NUL"));
        assert!(!host.exists(r"C:\NoSuch\NUL"));
        assert!(host.exists(r"C:\Alpha\*.txt"));
        assert!(!host.exists(r"C:\Alpha\*.nomatch"));
        assert!(host.exists(r"C:\Alpha\LongFileName.txt"));
        assert_eq!(host.read_bytes("NUL"), Ok(Vec::new()));
        assert!(host.write_bytes("NUL", b"x").is_ok());
        assert!(host.append_bytes("NUL", b"x").is_ok());
        assert!(host.read_bytes(r"C:\NoSuch\NUL").is_err());
        assert!(host.write_bytes(r"C:\NoSuch\NUL", b"x").is_err());
        assert!(host.append_bytes(r"C:\NoSuch\NUL", b"x").is_err());

        // Error branches on HostOsVfs
        assert!(host.write_bytes(r"C:\", b"root").is_err());
        assert!(host.write_bytes(r"C:\NoParent\f.txt", b"x").is_err());
        assert!(host.write_bytes(r"C:\Alpha", b"dir").is_err());
        assert!(host.append_bytes(r"C:\Alpha", b"dir").is_err());
        assert!(host.read_bytes(r"C:\Alpha").is_err());
        assert!(host.read_bytes(r"C:\Missing.txt").is_err());
        assert!(
            host.delete_file(r"Z:\Missing.txt", ForceDeleteReadOnly)
                .is_err()
        );
        assert!(host.delete_file(r"C:\Alpha", ForceDeleteReadOnly).is_err());
        assert!(
            host.delete_file(r"C:\Missing.txt", ForceDeleteReadOnly)
                .is_err()
        );

        // Attributes sidecar & read-only enforcement
        let mut ro = FileAttributes::default_file();
        ro.insert(FileAttributeFlags::READ_ONLY);
        assert!(
            host.set_attributes(r"C:\Alpha\LongFileName.txt", ro)
                .is_ok()
        );
        assert!(host.set_attributes(r"C:\Missing.txt", ro).is_err());
        assert!(
            host.write_bytes(r"C:\Alpha\LongFileName.txt", b"no")
                .is_err()
        );
        assert!(
            host.delete_file(r"C:\Alpha\LongFileName.txt", RespectReadOnly)
                .is_err()
        );
        assert!(
            host.delete_file(r"C:\Alpha\LongFileName.txt", ForceDeleteReadOnly)
                .is_ok()
        );
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
    }

    /// Verifies [`HostOsVfs`] symlinks, hardlinks, `move_entry`, and directory removal.
    #[test]
    fn test_host_os_vfs_links_move_and_rmdir() {
        let base_temp =
            std::env::temp_dir().join(format!("wincmd_host_vfs_links_{}", std::process::id()));
        let temp_c = base_temp.join("drive_c");
        assert!(std::fs::create_dir_all(&base_temp).is_ok());
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
        assert!(std::fs::create_dir_all(&temp_c).is_ok());
        let mut host = HostOsVfs::new(temp_c);
        assert!(host.create_dir(r"C:\Alpha\Beta", CreateParents).is_ok());
        assert!(
            host.create_dir(r"C:\Alpha\Gamma", ImmediateParentOnly)
                .is_ok()
        );

        // Move, symlink, hardlink, touch, mount_unc_drive, remove_dir
        assert!(host.write_bytes(r"C:\Alpha\src.txt", b"src").is_ok());
        let ts = FileTimestamp::from_civil_utc(2026, 11, 10, 12, 0).unwrap_or_default();
        assert!(host.touch_file(r"C:\Alpha\src.txt", ts).is_ok());
        assert!(host.touch_file(r"C:\Alpha\missing.txt", ts).is_err());
        let file_sym = MklinkKind::FileSymlink;
        let dir_junc = MklinkKind::DirectoryJunction;
        assert!(
            host.create_symlink(r"C:\Alpha\sym.txt", r"C:\Alpha\src.txt", file_sym)
                .is_ok()
        );
        assert!(
            host.create_symlink(r"C:\Alpha\sym.txt", r"C:\Alpha\src.txt", file_sym)
                .is_err()
        );
        assert!(
            host.create_symlink(r"C:\Alpha\symdir", r"C:\Alpha\Beta", dir_junc)
                .is_ok()
        );
        // read_dir with valid in-sandbox symlink + delete_file on directory symlink
        assert!(host.read_dir(r"C:\Alpha").is_ok());
        assert!(
            host.delete_file(r"C:\Alpha\symdir", RespectReadOnly)
                .is_ok()
        );
        assert!(
            host.create_symlink(
                r"C:\Alpha\symdir",
                r"C:\Alpha\Beta",
                MklinkKind::DirectoryJunction
            )
            .is_ok()
        );
        assert!(host.remove_dir(r"C:\Alpha\symdir", EmptyOnly).is_ok());
        assert!(host.exists(r"C:\Alpha\Beta"));
        // Dangling in-sandbox symlink interactions with read_dir, create_dir, create_symlink, move_entry, and remove_dir
        assert!(
            host.create_symlink(
                r"C:\Alpha\dang_in.txt",
                r"C:\Alpha\no_target_yet.txt",
                MklinkKind::FileSymlink
            )
            .is_ok()
        );
        assert!(host.read_dir(r"C:\Alpha").is_ok());
        assert!(
            host.create_dir(r"C:\Alpha\dang_in.txt", ImmediateParentOnly)
                .is_err()
        );
        assert!(
            host.create_symlink(
                r"C:\Alpha\dang_in.txt",
                r"C:\Alpha\src.txt",
                MklinkKind::FileSymlink
            )
            .is_err()
        );
        assert!(
            host.move_entry(r"C:\Alpha\dang_in.txt", r"C:\Alpha\dang_moved.txt")
                .is_ok()
        );
        assert!(
            host.remove_dir(r"C:\Alpha\dang_moved.txt", EmptyOnly)
                .is_ok()
        );
        assert!(
            host.create_symlink(
                r"C:\NoParent\symdir",
                r"C:\Alpha\Beta",
                MklinkKind::DirectoryJunction
            )
            .is_err()
        );
        assert!(
            host.create_symlink(
                r"C:\NoParent\sym.txt",
                r"C:\Alpha\src.txt",
                MklinkKind::FileSymlink
            )
            .is_err()
        );
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
    }

    /// Verifies [`HostOsVfs`] hardlinks, `move_entry`, UNC mounts, and `remove_dir`.
    #[test]
    fn test_host_os_vfs_hardlinks_move_and_rmdir() {
        let base_temp =
            std::env::temp_dir().join(format!("wincmd_host_vfs_mv_{}", std::process::id()));
        let temp_c = base_temp.join("drive_c");
        assert!(std::fs::create_dir_all(&base_temp).is_ok());
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
        assert!(std::fs::create_dir_all(&temp_c).is_ok());
        let mut host = HostOsVfs::new(temp_c);
        assert!(host.create_dir(r"C:\Alpha\Beta", CreateParents).is_ok());
        assert!(
            host.create_dir(r"C:\Alpha\Gamma", ImmediateParentOnly)
                .is_ok()
        );
        assert!(host.write_bytes(r"C:\Alpha\src.txt", b"src").is_ok());
        assert!(
            host.create_hardlink(r"C:\Alpha\hard.txt", r"C:\Alpha\src.txt")
                .is_ok()
        );
        assert!(
            host.create_hardlink(r"C:\NoParent\hard.txt", r"C:\Alpha\src.txt")
                .is_err()
        );
        assert!(
            host.create_hardlink(r"C:\Alpha\bad_hard.txt", r"C:\Alpha\missing.txt")
                .is_err()
        );
        assert!(host.move_entry(r"C:\Alpha\Beta", r"C:\Alpha\Beta").is_ok());
        assert!(
            host.move_entry(r"C:\Alpha\src.txt", r"C:\Alpha\src.txt")
                .is_ok()
        );
        assert!(
            host.move_entry(r"C:\Alpha\src.txt", r"C:\Alpha\hard.txt")
                .is_ok()
        );
        assert!(
            host.move_entry(r"C:\Alpha\hard.txt", r"C:\Alpha\moved.txt")
                .is_ok()
        );
        assert!(
            host.move_entry(r"C:\Alpha\missing.txt", r"C:\Alpha\x.txt")
                .is_err()
        );
        assert!(
            host.move_entry(r"C:\Alpha\moved.txt", r"C:\NoParent\x.txt")
                .is_err()
        );
        assert!(
            host.move_entry(r"C:\Alpha\moved.txt", r"C:\Alpha\Beta")
                .is_err()
        );
        assert!(
            host.move_entry(r"C:\Alpha\Beta", r"C:\Alpha\moved.txt")
                .is_err()
        );

        let bs = crate::types::BS_CHAR;
        let unc_sh = format!("{bs}{bs}srv{bs}sh");
        assert!(matches!(
            host.mount_unc_drive(&unc_sh, &[]),
            Err(CmdError::NetworkPathNotFound { .. })
        ));
        assert!(matches!(
            host.stat("//onlyserver"),
            Err(CmdError::InvalidUncPath { .. })
        ));
        host.mount_unc_share("srv", "sh", base_temp.clone());
        let unc_d = host.mount_unc_drive(&unc_sh, &[]);
        assert_eq!(unc_d, Ok(DriveLetter::Z));
        host.unmount_drive(DriveLetter::Z);

        assert!(host.read_dir(r"C:\Alpha").is_ok());
        assert!(host.read_dir(r"C:\NoSuch").is_err());
        assert!(host.remove_dir(r"C:\", RecursiveSubtree).is_err());
        assert!(host.remove_dir(r"Z:\NoMount", RecursiveSubtree).is_err());
        assert!(host.remove_dir(r"C:\NoSuch", RecursiveSubtree).is_err());
        assert_eq!(
            host.remove_dir(r"C:\Alpha", EmptyOnly),
            Err(CmdError::DirectoryNotEmpty {
                path: r"C:\Alpha".to_owned()
            })
        );
        assert!(host.remove_dir(r"C:\Alpha\Gamma", EmptyOnly).is_ok());
        assert!(host.remove_dir(r"C:\Alpha", RecursiveSubtree).is_ok());
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
    }

    /// Verifies [`HostOsVfs`] timestamp formatting, `WINEPREFIX` loading, and host CWD synchronization.
    #[test]
    fn test_host_os_vfs_timestamps_wineprefix_and_cwd_sync() {
        let base_temp =
            std::env::temp_dir().join(format!("wincmd_host_vfs_sync_{}", std::process::id()));
        let temp_c = base_temp.join("drive_c");
        assert!(std::fs::create_dir_all(&base_temp).is_ok());
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
        assert!(std::fs::create_dir_all(&temp_c).is_ok());
        let mut host = HostOsVfs::new(temp_c.clone());

        // Test format_unix_epoch_secs_cmd_timestamp across AM, PM, midnight, noon, and Jan/Feb months
        assert_eq!(
            HostOsVfs::format_unix_epoch_secs_cmd_timestamp(0),
            "01/01/1970  12:00 AM"
        );
        assert_eq!(
            HostOsVfs::format_unix_epoch_secs_cmd_timestamp(9 * 3600),
            "01/01/1970  09:00 AM"
        );
        assert_eq!(
            HostOsVfs::format_unix_epoch_secs_cmd_timestamp(12 * 3600),
            "01/01/1970  12:00 PM"
        );
        assert_eq!(
            HostOsVfs::format_unix_epoch_secs_cmd_timestamp(15 * 3600 + 30 * 60),
            "01/01/1970  03:30 PM"
        );
        assert_eq!(
            HostOsVfs::format_unix_epoch_secs_cmd_timestamp(DEFAULT_VFS_EPOCH_SECS),
            "11/10/2026  09:00 AM"
        );

        // Test from_wineprefix and from_host_env
        let wp_dir = base_temp.join("wineprefix");
        let dosdevices = wp_dir.join("dosdevices");
        assert!(std::fs::create_dir_all(&dosdevices).is_ok());
        #[cfg(unix)]
        assert!(std::fs::create_dir_all(dosdevices.join("c:")).is_ok());
        let wp_vfs = HostOsVfs::from_wineprefix(Some(&wp_dir), temp_c.clone());
        assert_eq!(wp_vfs.current_drive(), DriveLetter::C);
        let wp_none = HostOsVfs::from_wineprefix(None, temp_c);
        assert_eq!(wp_none.current_drive(), DriveLetter::C);
        let host_env_vfs = HostOsVfs::from_host_env();
        assert!(host_env_vfs.drive_cwd(host_env_vfs.current_drive()).is_ok());

        // Test sync_host_cwd and set_drive_free_space via injectable race-free `cwd_sync_fn`
        host.cwd_sync_fn = |p| {
            if p.is_dir() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "missing sync dir",
                ))
            }
        };
        host.set_drive_free_space(DriveLetter::C, 42_000_000);
        assert_eq!(host.free_disk_space(DriveLetter::C), Ok(42_000_000));
        assert!(host.sync_host_cwd(HostBindingMode::Isolated).is_ok());
        let root_c = WindowsPath::root(DriveLetter::C);
        assert!(host.set_drive_cwd(&root_c).is_ok());
        assert!(host.sync_host_cwd(HostBindingMode::Synchronized).is_ok());
        host.inner
            .drive_cwds
            .insert(DriveLetter::C, vec!["missing_sync_dir".to_owned()]);
        assert!(host.sync_host_cwd(HostBindingMode::Synchronized).is_err());

        let mut unmounted_active = HostOsVfs::with_mounts(
            DriveLetter::Z,
            BTreeMap::from([(DriveLetter::D, base_temp.clone())]),
            SandboxContainment::Contained,
        );
        assert!(
            unmounted_active
                .sync_host_cwd(HostBindingMode::Synchronized)
                .is_err()
        );
        unmounted_active.containment = SandboxContainment::Unrestricted;
        assert_eq!(unmounted_active.current_drive(), DriveLetter::Z);

        let empty_mounts = HostOsVfs::with_mounts(
            DriveLetter::Z,
            BTreeMap::new(),
            SandboxContainment::Contained,
        );
        assert_eq!(empty_mounts.current_drive(), DriveLetter::Z);

        let cloned = host.clone_box();
        assert_eq!(cloned.current_drive(), DriveLetter::C);
        assert!(
            normalize_lexical_host_path(Path::new("/a/./b/../c"))
                .ends_with(Path::new("a").join("c"))
        );
        assert!(
            normalize_lexical_host_path(Path::new("./nonexistent_rel_path"))
                .ends_with("nonexistent_rel_path")
        );
        assert_eq!(normalize_lexical_host_path(Path::new("")), PathBuf::new());
        assert!(std::fs::remove_dir_all(&base_temp).is_ok());
    }

    /// Verifies 8.3 short-name collision numbering and `HostOsVfs` CWD hydration.
    #[test]
    fn test_short_name_collisions_and_host_cwd_hydration() {
        let mut vfs = InMemoryVfs::default();
        assert!(vfs.write_bytes(r"C:\LongFileNameOne.txt", b"1").is_ok());
        assert!(vfs.write_bytes(r"C:\LongFileNameTwo.txt", b"2").is_ok());
        assert_eq!(vfs.read_bytes(r"C:\LONGFI~1.TXT"), Ok(b"1".to_vec()));
        assert_eq!(vfs.read_bytes(r"C:\LONGFI~2.TXT"), Ok(b"2".to_vec()));
        for i in 3u8..=100u8 {
            assert!(
                vfs.write_bytes(&format!(r"C:\LongFileNameExtra{i}.txt"), b"x")
                    .is_ok()
            );
        }
        vfs.set_drive_free_space(DriveLetter::C, 123_456);
        assert_eq!(vfs.free_disk_space(DriveLetter::C), Ok(123_456));
        assert!(vfs.sync_host_cwd(HostBindingMode::Synchronized).is_ok());

        let mut host = HostOsVfs::new(PathBuf::from("/tmp/wincmd_nonexistent_sandbox_root"));
        assert!(host.stat(r"C:\missing.txt").is_err());
        host.hydrate_cwd_from_host_path(Path::new("/tmp/wincmd_nonexistent_sandbox_root/sub/dir"));
        assert_eq!(
            host.drive_cwd(DriveLetter::C)
                .map(|p| p.to_windows_string()),
            Ok(r"C:\sub\dir".to_owned())
        );
        host.hydrate_cwd_from_host_path(Path::new("/var/other"));
        assert_eq!(FileTimestamp::from_civil_utc(2025, 1, 0, 0, 0), None);
    }

    /// Verifies `InMemoryVfs` CWD protection, cyclic directory moves, `READ_ONLY` subtree guards, and UNC unmounts.
    #[test]
    fn test_in_memory_vfs_cwd_protection_cyclic_moves_and_unc_edges() {
        let mut mem = InMemoryVfs::new();
        mem.mount_empty_drive(DriveLetter::D, "DATA", "D000-0001");
        assert!(mem.stat(r"\\server_only").is_err());
        assert!(
            mem.create_dir(r"\\server_only", ImmediateParentOnly)
                .is_err()
        );
        assert!(
            mem.create_symlink(r"\\server_only", "C:/x", MklinkKind::FileSymlink)
                .is_err()
        );
        assert!(mem.mount_unc_drive("C:/not_unc", &[]).is_err());
        assert!(mem.mount_unc_drive(r"\\server_only", &[]).is_err());

        assert_eq!(mem.create_dir(r"C:\real_dir\sub", CreateParents), Ok(()));
        assert_eq!(
            mem.create_symlink(
                r"C:\junc_dir",
                r"C:\real_dir",
                MklinkKind::DirectoryJunction
            ),
            Ok(())
        );
        mem.drive_cwds
            .insert(DriveLetter::C, vec!["junc_dir".to_owned()]);
        assert!(mem.remove_dir(r"C:\junc_dir", EmptyOnly).is_err());

        let root_c = WindowsPath::root(DriveLetter::C);
        assert_eq!(mem.set_drive_cwd(&root_c), Ok(()));
        let real_sub_cwd = mem.resolve_path(r"C:\real_dir\sub");
        assert_eq!(mem.set_drive_cwd(&real_sub_cwd), Ok(()));
        assert!(mem.remove_dir(r"C:\real_dir", RecursiveSubtree).is_err());
        assert!(mem.move_entry(r"C:\real_dir", r"C:\moved_real").is_err());

        assert_eq!(mem.set_drive_cwd(&root_c), Ok(()));
        assert!(
            mem.move_entry(r"C:\real_dir", r"C:\real_dir\sub\into_self")
                .is_err()
        );
        assert_eq!(mem.move_entry(r"C:\real_dir", r"D:\across_drives"), Ok(()));
        assert_eq!(
            mem.move_entry(r"D:\across_drives", r"D:\renamed_ok"),
            Ok(())
        );

        assert_eq!(
            mem.create_dir(r"C:\ro_dir\child_dir", CreateParents),
            Ok(())
        );
        assert_eq!(mem.write_bytes(r"C:\ro_dir\child.txt", b"ro"), Ok(()));
        let mut ro_file_attr = FileAttributeFlags::default_file();
        ro_file_attr.insert(FileAttributeFlags::READ_ONLY);
        assert_eq!(
            mem.set_attributes(r"C:\ro_dir\child.txt", ro_file_attr),
            Ok(())
        );
        assert!(mem.remove_dir(r"C:\ro_dir", RecursiveSubtree).is_err());
        let mut ro_dir_attr = FileAttributeFlags::default_dir();
        ro_dir_attr.insert(FileAttributeFlags::READ_ONLY);
        assert_eq!(mem.set_attributes(r"C:\ro_dir", ro_dir_attr), Ok(()));
        assert!(mem.remove_dir(r"C:\ro_dir", EmptyOnly).is_err());

        assert_eq!(
            mem.create_dir(r"\\srv\shr\existing_sub", CreateParents),
            Ok(())
        );
        assert_eq!(
            mem.mount_unc_drive(r"\\srv\shr", &["existing_sub".to_owned()]),
            Ok(DriveLetter::Z)
        );
        assert_eq!(
            mem.mount_unc_drive(r"\\srv\shr", &["auto_created_sub".to_owned()]),
            DriveLetter::try_from_char('Y')
        );
        assert_eq!(mem.write_bytes(r"D:\d_file.txt", b"d"), Ok(()));
        mem.unmount_drive(DriveLetter::D);
        assert!(!mem.exists(r"D:\d_file.txt"));
    }

    /// Verifies `HostOsVfs` `to_host_path`, `append_bytes`, and relative/escaping `create_symlink` containment.
    #[test]
    fn test_host_os_vfs_symlinks_append_and_path_translation_edges() {
        let tmp_base = std::env::temp_dir().join(format!("wincmd_host_sym_{}", std::process::id()));
        let host_c = tmp_base.join("c_root");
        let host_unc = tmp_base.join("unc_share");
        assert!(std::fs::create_dir_all(&host_c).is_ok());
        assert!(std::fs::create_dir_all(host_unc.join("sub_ok")).is_ok());

        let mut host = HostOsVfs::new(host_c.clone());
        host.mount_unc_share("srv", "shr", host_unc);

        assert_eq!(
            host.to_host_path(&WindowsPath::root(DriveLetter::C)),
            host_c
        );
        assert_eq!(
            host.to_host_path(&WindowsPath::root(DriveLetter::D)),
            host_c
        );
        let unmounted_unc = host.resolve_path(r"\\other\missing\f.txt");
        assert_eq!(host.to_host_path(&unmounted_unc), PathBuf::new());

        assert_eq!(
            HostOsVfs::compute_host_dir_short_name(
                &tmp_base.join("no_such_dir"),
                "LongFileName.txt"
            ),
            "LONGFI~1.TXT"
        );
        assert_eq!(
            HostOsVfs::compute_host_dir_short_name(&host_c, "NotCreatedYetLongName.txt"),
            "NOTCRE~1.TXT"
        );
        assert!(!host::has_host_os_readonly_recursive(
            &tmp_base.join("no_such_dir")
        ));

        assert!(host.stat("C:/").is_ok());
        let mounted_unc_wp = host.resolve_path(r"\\srv\shr");
        assert_eq!(host.set_drive_cwd(&mounted_unc_wp), Ok(()));

        let mut ro_file_attr = FileAttributeFlags::default_file();
        ro_file_attr.insert(FileAttributeFlags::READ_ONLY);
        assert!(host.append_bytes("C:/", b"x").is_err());
        assert!(host.append_bytes("C:/missing_parent/a.txt", b"x").is_err());
        assert_eq!(host.write_bytes("C:/ro_app.txt", b"1"), Ok(()));
        assert_eq!(host.set_attributes("C:/ro_app.txt", ro_file_attr), Ok(()));
        assert!(host.append_bytes("C:/ro_app.txt", b"2").is_err());

        assert_eq!(host.create_dir("C:/sdir/inner", CreateParents), Ok(()));
        assert_eq!(host.write_bytes("C:/sdir/target.txt", b"ok"), Ok(()));
        assert!(
            host.create_symlink("C:/", "C:/sdir/target.txt", MklinkKind::FileSymlink)
                .is_err()
        );
        assert_eq!(
            host.create_symlink(
                "C:/sdir/abs_lnk",
                "C:/sdir/target.txt",
                MklinkKind::FileSymlink
            ),
            Ok(())
        );
        assert_eq!(
            host.create_symlink(
                "C:/sdir/rooted_lnk",
                "/sdir/target.txt",
                MklinkKind::FileSymlink
            ),
            Ok(())
        );
        assert_eq!(
            host.create_symlink(
                "C:/sdir/inner/rel_lnk",
                r"..\target.txt",
                MklinkKind::FileSymlink
            ),
            Ok(())
        );
        assert_eq!(host.read_bytes("C:/sdir/inner/rel_lnk"), Ok(b"ok".to_vec()));
        assert!(
            host.create_symlink(
                "C:/sdir/escape_lnk",
                "../../outside.txt",
                MklinkKind::FileSymlink
            )
            .is_err()
        );
        host.containment = SandboxContainment::Unrestricted;
        assert_eq!(
            host.create_symlink("C:/sdir/one_char_rel", "x", MklinkKind::FileSymlink),
            Ok(())
        );
        assert!(std::fs::remove_dir_all(&tmp_base).is_ok());
    }

    /// Verifies `HostOsVfs` CWD/readonly subtree `remove_dir`, sidecar subtree migration on `move_entry`, and UNC drive mounts.
    #[test]
    fn test_host_os_vfs_cwd_readonly_sidecar_and_unc_mount_edges() {
        let tmp_base = std::env::temp_dir().join(format!("wincmd_host_ro_{}", std::process::id()));
        let host_c = tmp_base.join("c_root");
        let host_d = tmp_base.join("d_root");
        let host_unc = tmp_base.join("unc_share");
        assert!(std::fs::create_dir_all(&host_c).is_ok());
        assert!(std::fs::create_dir_all(&host_d).is_ok());
        assert!(std::fs::create_dir_all(host_unc.join("sub_ok")).is_ok());

        let mut host = HostOsVfs::new(host_c.clone());
        host.mount_drive(DriveLetter::D, host_d);
        host.mount_unc_share("srv", "shr", host_unc);
        let root_c = WindowsPath::root(DriveLetter::C);
        let mut ro_file_attr = FileAttributeFlags::default_file();
        ro_file_attr.insert(FileAttributeFlags::READ_ONLY);
        let mut ro_dir_attr = FileAttributeFlags::default_dir();
        ro_dir_attr.insert(FileAttributeFlags::READ_ONLY);

        assert_eq!(host.write_bytes("D:/d_side.txt", b"d"), Ok(()));
        assert_eq!(
            host.set_attributes("D:/d_side.txt", FileAttributeFlags::HIDDEN),
            Ok(())
        );
        assert_eq!(host.write_bytes("C:/c_outside.txt", b"c"), Ok(()));
        assert_eq!(
            host.set_attributes("C:/c_outside.txt", FileAttributeFlags::HIDDEN),
            Ok(())
        );
        assert_eq!(host.create_dir("C:/dir_to_d", CreateParents), Ok(()));
        assert_eq!(host.move_entry("C:/dir_to_d", "D:/dir_on_d"), Ok(()));

        assert_eq!(host.create_dir("C:/sdir/inner", CreateParents), Ok(()));
        assert_eq!(host.write_bytes("C:/sdir/target.txt", b"ok"), Ok(()));
        assert_eq!(
            host.create_symlink(
                "C:/sdir/sym_child",
                "C:/sdir/target.txt",
                MklinkKind::FileSymlink
            ),
            Ok(())
        );

        let sdir_cwd = host.resolve_path("C:/sdir/inner");
        assert_eq!(host.set_drive_cwd(&sdir_cwd), Ok(()));
        assert!(host.remove_dir("C:/sdir", RecursiveSubtree).is_err());
        assert!(host.move_entry("C:/sdir", "C:/sdir_moved").is_err());
        assert_eq!(host.set_drive_cwd(&root_c), Ok(()));
        assert!(host.move_entry("C:/sdir", "C:/sdir/inner/sub").is_err());

        assert_eq!(host.set_attributes("C:/sdir", ro_dir_attr), Ok(()));
        assert!(host.remove_dir("C:/sdir", RecursiveSubtree).is_err());
        assert_eq!(
            host.set_attributes("C:/sdir", FileAttributeFlags::default_dir()),
            Ok(())
        );
        assert_eq!(
            host.set_attributes("C:/sdir/target.txt", ro_file_attr),
            Ok(())
        );
        assert!(host.remove_dir("C:/sdir", RecursiveSubtree).is_err());
        assert_eq!(
            host.set_attributes("C:/sdir/target.txt", FileAttributeFlags::default_file()),
            Ok(())
        );

        let os_ro_nested = host_c.join("sdir").join("inner").join("os_ro.txt");
        assert!(std::fs::write(&os_ro_nested, b"ro").is_ok());
        let ro_check = std::fs::metadata(&os_ro_nested).and_then(|m| {
            let writable = m.permissions();
            let mut ro = writable.clone();
            ro.set_readonly(true);
            std::fs::set_permissions(&os_ro_nested, ro)?;
            assert!(host::has_host_os_readonly_recursive(&host_c.join("sdir")));
            std::fs::set_permissions(&os_ro_nested, writable)
        });
        assert!(ro_check.is_ok());
        assert!(!host::has_host_os_readonly_recursive(&host_c.join("sdir")));

        assert_eq!(
            host.set_attributes("C:/sdir/target.txt", FileAttributeFlags::HIDDEN),
            Ok(())
        );
        assert_eq!(host.move_entry("C:/sdir", "C:/sdir_renamed"), Ok(()));
        assert!(
            host.stat("C:/sdir_renamed/target.txt")
                .is_ok_and(|m| m.attributes.contains(FileAttributeFlags::HIDDEN))
        );
        assert_eq!(host.remove_dir("C:/sdir_renamed", RecursiveSubtree), Ok(()));
        assert!(std::fs::remove_dir_all(&tmp_base).is_ok());
    }

    /// Verifies `HostOsVfs::mount_unc_drive` validation, subdirectory resolution, and drive exhaustion.
    #[test]
    fn test_host_os_vfs_unc_mount_subdirs_and_drive_exhaustion() {
        let tmp_base = std::env::temp_dir().join(format!("wincmd_host_unc_{}", std::process::id()));
        let host_c = tmp_base.join("c_root");
        let host_unc = tmp_base.join("unc_share");
        assert!(std::fs::create_dir_all(&host_c).is_ok());
        assert!(std::fs::create_dir_all(host_unc.join("sub_ok")).is_ok());

        let mut host = HostOsVfs::new(host_c.clone());
        host.mount_unc_share("srv", "shr", host_unc);
        assert!(host.mount_unc_drive("C:/not_unc", &[]).is_err());
        assert!(
            host.mount_unc_drive(r"\\srv\shr", &["missing_sub".to_owned()])
                .is_err()
        );
        assert_eq!(
            host.mount_unc_drive(r"\\srv\shr", &["sub_ok".to_owned()]),
            Ok(DriveLetter::Z)
        );
        for ch in 'A'..='Z' {
            let dl = DriveLetter::try_from_char(ch).unwrap_or(DriveLetter::C);
            host.drive_roots.insert(dl, host_c.clone());
        }
        assert!(host.mount_unc_drive(r"\\srv\shr", &[]).is_err());
        assert!(std::fs::remove_dir_all(&tmp_base).is_ok());
    }

    /// Runs shared behavioral invariants across `InMemoryVfs`, `HostOsVfs`, and `DosFatVfs` (8.3 & LFN).
    ///
    /// # Arguments
    /// * `vfs` - Mutable [`VirtualFileSystem`] backend under test.
    fn run_cross_backend_vfs_conformance(vfs: &mut dyn VirtualFileSystem) {
        assert_eq!(vfs.current_drive(), DriveLetter::C);
        assert!(vfs.volume_info(DriveLetter::C).is_ok());
        vfs.set_drive_free_space(DriveLetter::C, 4_194_304);
        assert_eq!(vfs.free_disk_space(DriveLetter::C), Ok(4_194_304));
        assert_eq!(vfs.sync_host_cwd(HostBindingMode::default()), Ok(()));
        assert_eq!(vfs.sync_host_cwd(HostBindingMode::Synchronized), Ok(()));
        assert_eq!(vfs.clone_box().current_drive(), DriveLetter::C);

        assert!(vfs.exists("NUL"));
        assert!(!vfs.exists("C:/NO_SUCH/NUL"));
        assert_eq!(vfs.write_bytes("NUL", b"discard"), Ok(()));
        assert_eq!(vfs.append_bytes("NUL", b"discard"), Ok(()));
        assert_eq!(vfs.read_bytes("NUL"), Ok(Vec::new()));

        assert_eq!(vfs.create_dir("C:/WORK/SUB", CreateParents), Ok(()));
        assert_eq!(vfs.create_dir("C:/WORK/LEAF", ImmediateParentOnly), Ok(()));
        assert!(vfs.create_dir("C:/", ImmediateParentOnly).is_err());
        assert!(vfs.create_dir("C:/WORK/LEAF", CreateParents).is_err());
        assert!(vfs.exists("C:/WORK/NUL"));

        assert_eq!(vfs.write_bytes("C:/WORK/NOTE.TXT", b"ab"), Ok(()));
        assert_eq!(vfs.append_bytes("C:/WORK/NOTE.TXT", b"cd"), Ok(()));
        assert_eq!(vfs.read_bytes("C:/WORK/NOTE.TXT"), Ok(b"abcd".to_vec()));
        assert!(!vfs.exists("C:/WORK/NOTE.TXT/NUL"));
        assert!(vfs.exists("C:/WORK/*.TXT"));
        assert!(vfs.exists("C:/WORK/????????.TXT"));

        let ts = FileTimestamp::from_civil_utc(1996, 5, 20, 10, 30).unwrap_or_default();
        assert_eq!(vfs.touch_file("C:/WORK/NOTE.TXT", ts), Ok(()));
        assert_eq!(
            vfs.stat("C:/WORK/NOTE.TXT").map(|m| m.modified_timestamp),
            Ok(ts)
        );

        let mut ro = FileAttributeFlags::default_file();
        ro.insert(FileAttributeFlags::READ_ONLY);
        assert_eq!(vfs.set_attributes("C:/WORK/NOTE.TXT", ro), Ok(()));
        assert!(
            vfs.delete_file("C:/WORK/NOTE.TXT", RespectReadOnly)
                .is_err()
        );
        assert!(vfs.remove_dir("C:/WORK", RecursiveSubtree).is_err());
        assert_eq!(
            vfs.delete_file("C:/WORK/NOTE.TXT", ForceDeleteReadOnly),
            Ok(())
        );

        let work_path = vfs.resolve_path("C:/WORK");
        assert_eq!(vfs.set_drive_cwd(&work_path), Ok(()));
        assert!(vfs.remove_dir("C:/WORK", RecursiveSubtree).is_err());
        assert!(vfs.move_entry("C:/WORK", "C:/WORK2").is_err());
        let root_path = WindowsPath::root(DriveLetter::C);
        assert_eq!(vfs.set_drive_cwd(&root_path), Ok(()));

        assert!(vfs.move_entry("C:/WORK", "C:/WORK/SUB/CYCLE").is_err());
        assert_eq!(vfs.move_entry("C:/WORK", "C:/RENWORK"), Ok(()));
        assert!(vfs.remove_dir("C:/RENWORK", EmptyOnly).is_err());
        assert_eq!(vfs.remove_dir("C:/RENWORK", RecursiveSubtree), Ok(()));
    }

    /// Executes `run_cross_backend_vfs_conformance` on `InMemoryVfs`, `HostOsVfs`, and `DosFatVfs` (8.3 + LFN).
    #[test]
    fn test_cross_backend_conformance_in_memory_host_and_dos_fat() {
        let mut mem = InMemoryVfs::new();
        run_cross_backend_vfs_conformance(&mut mem);

        let tmp = std::env::temp_dir().join(format!("wincmd_xbackend_{}", std::process::id()));
        assert!(std::fs::create_dir_all(&tmp).is_ok());
        let mut host = HostOsVfs::new(tmp.clone());
        run_cross_backend_vfs_conformance(&mut host);
        assert!(std::fs::remove_dir_all(&tmp).is_ok());

        let mut dos_83 = DosFatVfs::new(crate::dos::SimulatedDosKernel::new());
        run_cross_backend_vfs_conformance(&mut dos_83);

        let mut lfn_kernel = crate::dos::SimulatedDosKernel::new();
        lfn_kernel.mount_drive(
            DriveLetter::C,
            crate::dos::SimulatedDriveConfig {
                lfn_mode: crate::dos::LfnSupportMode::EnabledInt21Ax71,
                ..crate::dos::SimulatedDriveConfig::default()
            },
        );
        let mut dos_lfn = DosFatVfs::new(lfn_kernel);
        run_cross_backend_vfs_conformance(&mut dos_lfn);
    }

    /// Verifies `DosFatVfs` 8.3 vs LFN metadata, `copy_file` verify flag, cross-drive moves, and unsupported links.
    #[test]
    fn test_dos_fat_vfs_cross_drive_moves_copy_verify_and_unsupported_links() {
        use crate::dos::{DosKernelApi, LfnSupportMode, SimulatedDosKernel, SimulatedDriveConfig};
        use crate::types::VerifyCopyMode;

        let mut kernel = SimulatedDosKernel::new();
        kernel.mount_drive(
            DriveLetter::D,
            SimulatedDriveConfig {
                lfn_mode: LfnSupportMode::EnabledInt21Ax71,
                ..SimulatedDriveConfig::default()
            },
        );
        let mut vfs = DosFatVfs::new(kernel);
        assert_eq!(vfs.kernel().current_drive(), DriveLetter::C);
        assert_eq!(vfs.free_disk_space(DriveLetter::C), Ok(16_777_216));

        assert!(matches!(
            vfs.create_symlink("C:/LNK", "C:/TGT", MklinkKind::FileSymlink),
            Err(CmdError::UnsupportedOperation { .. })
        ));
        assert!(matches!(
            vfs.create_hardlink("C:/HLNK", "C:/TGT"),
            Err(CmdError::UnsupportedOperation { .. })
        ));

        assert_eq!(vfs.write_bytes("C:/verylongfile.html", b"dos83"), Ok(()));
        let st_83 = vfs.stat("C:/VERYLONG.HTM");
        assert_eq!(st_83.as_ref().map(|m| m.name.as_str()), Ok("VERYLONG.HTM"));
        assert_eq!(
            vfs.copy_file(
                "C:/VERYLONG.HTM",
                "D:/Long Report.html",
                VerifyCopyMode::Verified
            ),
            Ok(())
        );
        assert_eq!(
            vfs.copy_file("C:/VERYLONG.HTM", "NUL", VerifyCopyMode::Unverified),
            Ok(())
        );
        assert!(
            vfs.copy_file("C:/MISSING.TXT", "NUL", VerifyCopyMode::Unverified)
                .is_err()
        );
        assert_eq!(vfs.kernel().verify_flag(), VerifyCopyMode::Unverified);
        let st_lfn = vfs.stat("D:/Long Report.html");
        assert_eq!(
            st_lfn.as_ref().map(|m| m.short_name.as_str()),
            Ok("LONGRE~1.HTM")
        );

        let mut ro = FileAttributeFlags::default_file();
        ro.insert(FileAttributeFlags::READ_ONLY);
        assert_eq!(vfs.set_attributes("C:/VERYLONG.HTM", ro), Ok(()));
        assert!(vfs.move_entry("C:/VERYLONG.HTM", "D:/MOVED.HTM").is_err());
        assert_eq!(
            vfs.set_attributes("C:/VERYLONG.HTM", FileAttributeFlags::default_file()),
            Ok(())
        );
        assert_eq!(vfs.move_entry("C:/VERYLONG.HTM", "C:/VERYLONG.HTM"), Ok(()));
        assert_eq!(
            vfs.move_entry("C:/VERYLONG.HTM", "D:/Long Report.html"),
            Ok(())
        );
        assert_eq!(vfs.read_bytes("D:/Long Report.html"), Ok(b"dos83".to_vec()));
        assert!(!vfs.exists("C:/VERYLONG.HTM"));

        assert_eq!(vfs.create_dir("C:/TREE/SUB", CreateParents), Ok(()));
        assert_eq!(vfs.write_bytes("C:/TREE/SUB/A.TXT", b"tree"), Ok(()));
        assert_eq!(vfs.set_attributes("C:/TREE/SUB/A.TXT", ro), Ok(()));
        assert!(vfs.move_entry("C:/TREE", "D:/TREE_MOVED").is_err());
        assert_eq!(
            vfs.set_attributes("C:/TREE/SUB/A.TXT", FileAttributeFlags::default_file()),
            Ok(())
        );
        assert_eq!(vfs.move_entry("C:/TREE", "D:/TREE_MOVED"), Ok(()));
        assert_eq!(
            vfs.read_bytes("D:/TREE_MOVED/SUB/A.TXT"),
            Ok(b"tree".to_vec())
        );
        let owned = vfs.into_kernel();
        assert_eq!(owned.current_drive(), DriveLetter::C);
    }

    /// Verifies `DosFatVfs` UNC redirectors, `PUSHD` aliases, and error branches.
    #[test]
    fn test_dos_fat_vfs_unc_redirectors_pushd_and_error_edges() {
        use crate::dos::{DosKernelApi, SimulatedDosKernel, SimulatedDriveConfig};

        let mut kernel = SimulatedDosKernel::new();
        kernel.mount_drive(DriveLetter::D, SimulatedDriveConfig::default());
        assert_eq!(
            kernel.create_dir("D:/SHARED/DOCS"),
            Err(CmdError::PathNotFound {
                path: "D:/SHARED/DOCS".to_owned()
            })
        );
        assert_eq!(kernel.create_dir("D:/SHARED"), Ok(()));
        assert_eq!(kernel.create_dir("D:/SHARED/DOCS"), Ok(()));
        let mut vfs = DosFatVfs::new(kernel);

        assert!(matches!(
            vfs.stat("//bad"),
            Err(CmdError::InvalidUncPath { .. })
        ));
        assert!(matches!(
            vfs.stat("//srv/shr/DOCS"),
            Err(CmdError::NetworkPathNotFound { .. })
        ));
        assert!(
            vfs.resolve_host_path(&vfs.resolve_path("Z:/NOPE"))
                .is_none()
        );

        vfs.map_unc_redirector("srv", "shr", DriveLetter::D);
        assert!(vfs.stat("//srv/shr/SHARED/DOCS").is_ok());
        assert!(vfs.resolve_host_path(&vfs.resolve_path("C:/")).is_some());

        assert!(vfs.mount_unc_drive("C:/not_unc", &[]).is_err());
        assert!(
            vfs.mount_unc_drive("//srv/shr", &["NOPE".to_owned()])
                .is_err()
        );
        assert_eq!(vfs.write_bytes("D:/FILE.BIN", b"1"), Ok(()));
        assert!(
            vfs.mount_unc_drive("//srv/shr", &["FILE.BIN".to_owned()])
                .is_err()
        );

        let z = vfs.mount_unc_drive("//srv/shr", &["SHARED".to_owned()]);
        assert_eq!(z, Ok(DriveLetter::Z));
        let y_letter = DriveLetter::try_from_char('Y').unwrap_or(DriveLetter::Z);
        let y = vfs.mount_unc_drive("//srv/shr", &[]);
        assert_eq!(y, Ok(y_letter));
        assert!(vfs.mount_unc_drive("//bad", &[]).is_err());
        assert_eq!(vfs.set_current_drive(DriveLetter::Z), Ok(()));
        assert_eq!(vfs.current_drive(), DriveLetter::Z);
        assert_eq!(
            vfs.drive_cwd(DriveLetter::Z).map(|p| p.components),
            Ok(vec!["SHARED".to_owned()])
        );
        assert_eq!(
            vfs.volume_info(DriveLetter::Z).map(|v| v.label),
            Ok("//srv/shr".to_owned())
        );
        assert_eq!(vfs.free_disk_space(DriveLetter::Z), Ok(16_777_216));

        let z_docs = vfs.resolve_path("Z:/SHARED/DOCS");
        assert_eq!(vfs.set_drive_cwd(&z_docs), Ok(()));
        assert_eq!(
            vfs.resolve_path("REL.TXT").components,
            vec!["SHARED".to_owned(), "DOCS".to_owned(), "REL.TXT".to_owned()]
        );
        let unc_shared = vfs.resolve_path("//srv/shr/SHARED");
        assert_eq!(vfs.set_drive_cwd(&unc_shared), Ok(()));
        let d_root = vfs.resolve_path("D:/");
        assert_eq!(vfs.set_drive_cwd(&d_root), Ok(()));
        assert_eq!(vfs.create_dir("C:/C_EMPTY", ImmediateParentOnly), Ok(()));
        assert_eq!(vfs.remove_dir("C:/C_EMPTY", EmptyOnly), Ok(()));
        assert_eq!(vfs.create_dir("D:/D_EMPTY", ImmediateParentOnly), Ok(()));
        assert_eq!(vfs.remove_dir("D:/D_EMPTY", EmptyOnly), Ok(()));
        assert!(vfs.remove_dir("D:/SHARED", RecursiveSubtree).is_err());

        vfs.kernel_mut().unmount_drive(DriveLetter::D);
        assert!(vfs.stat("Z:/").is_err());
        assert!(vfs.stat("//srv/shr").is_err());
        assert_eq!(vfs.set_current_drive(DriveLetter::C), Ok(()));
        vfs.unmount_drive(DriveLetter::Z);
        vfs.unmount_drive(y_letter);
        assert!(vfs.drive_cwd(DriveLetter::Z).is_err());

        for d in DriveLetter::ALL_DESCENDING {
            vfs.kernel_mut()
                .mount_drive(d, SimulatedDriveConfig::default());
        }
        assert!(vfs.mount_unc_drive("//srv/shr", &[]).is_err());
    }

    /// Verifies `DosFatVfs` root stat, `MD`/`RD`/`MOVE`/`DEL`/`CD` error branches, and `READ_ONLY` guards.
    #[test]
    fn test_dos_fat_vfs_dir_move_delete_and_cwd_edges() {
        let mut vfs = DosFatVfs::new(crate::dos::SimulatedDosKernel::new());
        assert!(vfs.stat("C:/").is_ok_and(|m| m.attributes.is_directory()));
        assert!(vfs.stat("C:/NO_PARENT/SUB/NUL").is_err());

        assert_eq!(vfs.write_bytes("C:/F.TXT", b"f"), Ok(()));
        assert_eq!(vfs.write_bytes("C:/RO.TXT", b"r"), Ok(()));
        let mut ro_file = FileAttributeFlags::default_file();
        ro_file.insert(FileAttributeFlags::READ_ONLY);
        assert_eq!(vfs.set_attributes("C:/RO.TXT", ro_file), Ok(()));

        assert!(vfs.set_drive_cwd(&vfs.resolve_path("C:/F.TXT")).is_err());
        assert!(vfs.set_drive_cwd(&vfs.resolve_path("C:/NO_DIR")).is_err());
        assert!(
            vfs.set_drive_cwd(&vfs.resolve_path("C:/NO_PARENT/SUB"))
                .is_err()
        );

        assert_eq!(vfs.create_dir("C:/DIR1", ImmediateParentOnly), Ok(()));
        assert_eq!(vfs.create_dir("C:/DIR1/CHILD", CreateParents), Ok(()));
        assert!(vfs.create_dir("C:/F.TXT/CHILD", CreateParents).is_err());
        assert_eq!(vfs.create_dir("C:/DIR2", ImmediateParentOnly), Ok(()));

        assert!(vfs.delete_file("C:/DIR2", ForceDeleteReadOnly).is_err());
        assert_eq!(vfs.write_bytes("C:/WRITABLE.TXT", b"w"), Ok(()));
        assert_eq!(
            vfs.delete_file("C:/WRITABLE.TXT", ForceDeleteReadOnly),
            Ok(())
        );

        assert!(vfs.remove_dir("C:/", EmptyOnly).is_err());
        assert!(vfs.remove_dir("C:/NO_DIR", EmptyOnly).is_err());
        assert!(vfs.remove_dir("C:/NO_PARENT/SUB", EmptyOnly).is_err());
        assert!(vfs.remove_dir("C:/F.TXT", EmptyOnly).is_err());
        let mut ro_dir = FileAttributeFlags::default_dir();
        ro_dir.insert(FileAttributeFlags::READ_ONLY);
        assert_eq!(vfs.set_attributes("C:/DIR2", ro_dir), Ok(()));
        assert!(vfs.remove_dir("C:/DIR2", EmptyOnly).is_err());
        assert_eq!(
            vfs.set_attributes("C:/DIR2", FileAttributeFlags::default_dir()),
            Ok(())
        );

        assert!(vfs.move_entry("C:/", "C:/X").is_err());
        assert!(vfs.move_entry("C:/F.TXT", "C:/").is_err());
        assert!(vfs.move_entry("C:/F.TXT", "C:/NO_PARENT/X.TXT").is_err());
        assert!(vfs.move_entry("C:/F.TXT", "C:/F.TXT/X.TXT").is_err());
        assert!(vfs.move_entry("C:/DIR1", "C:/DIR2").is_err());
        assert!(vfs.move_entry("C:/F.TXT", "C:/DIR2").is_err());
        assert!(vfs.move_entry("C:/F.TXT", "C:/RO.TXT").is_err());
    }
}
