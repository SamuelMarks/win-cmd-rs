//! Filesystem and directory navigation built-in commands (`DIR`, `CD`/`CHDIR`, `MD`/`MKDIR`,
//! `RD`/`RMDIR`, `PUSHD`, `POPD`, `COPY`, `DEL`/`ERASE`, `REN`/`RENAME`, `MOVE`, `TYPE`, `MKLINK`).
//!
//! Uses typed option structs ([`DirOptions`], [`CopyOptions`], [`DelOptions`]) and attribute masks
//! ([`AttrFilter`]) instead of boolean clusters, sorts `DIR /O:D` chronologically via
//! [`crate::vfs::FileTimestamp`], and propagates VFS/decoding [`CmdError`]s without silent loss.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::error::CmdError;
use crate::parser::ast::SpannedWord;
use crate::reader::encoding::decode_script_bytes;
use crate::runtime::{CmdIo, FlowControl, Interpreter, PushdEntry};
use crate::span::Span;
use crate::types::{
    BS_CHAR, BS_STR, CRLF, CTRL_Z_BYTE, CaseSensitivity, CopyDataMode, DriveLetter, ExitCode,
    ExtensionsMode, MklinkKind, OverwritePolicy, PromptConfirmMode, ReadOnlyDeletePolicy,
    ThousandsSeparatorMode, TraversalDepth, VerifyCopyMode,
};
use crate::vfs::glob::{contains_wildcards, matches_win32_glob};
use crate::vfs::path::WindowsPath;
use crate::vfs::{FileAttributeFlags, VfsMetadata};

/// Sort field for `DIR /O:...`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirSortField {
    /// `/O:N` sort alphabetically by name.
    Name,
    /// `/O:S` sort by file size.
    Size,
    /// `/O:E` sort alphabetically by extension.
    Extension,
    /// `/O:D` sort chronologically by [`crate::vfs::FileTimestamp`].
    DateTime,
    /// `/O:G` group directories before files.
    DirectoriesFirst,
}

/// Bitmask flags controlling `DIR` formatting and traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct DirFlags(
    /// Packed `DIR` switch bitmask.
    u8,
);

impl DirFlags {
    /// `/B` bare filename format.
    const BARE: Self = Self(1 << 0);
    /// `/S` recursive subdirectory listing.
    const RECURSIVE: Self = Self(1 << 1);
    /// `/W` or `/D` wide multi-column format.
    const WIDE: Self = Self(1 << 2);
    /// `/L` lowercase output.
    const LOWERCASE: Self = Self(1 << 3);
    /// `/X` display 8.3 short filenames.
    const SHOW_SHORT: Self = Self(1 << 4);
    /// `/O:-...` reverse sort order.
    const SORT_REVERSE: Self = Self(1 << 5);

    /// Checks whether all bits in `other` are set.
    ///
    /// # Arguments
    /// * `other` - Flag mask to test.
    ///
    /// # Returns
    /// `true` if set.
    #[must_use]
    const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Inserts all bits in `other`.
    ///
    /// # Arguments
    /// * `other` - Flag mask to set.
    const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// Bitmask attribute inclusion/exclusion filter for `DIR /A:...` and `DEL /A:...`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct AttrFilter {
    /// Whether `/A` was explicitly supplied (disabling default hidden/system suppression in `DIR`).
    explicit: bool,
    /// Attributes that an entry MUST possess.
    must_have: FileAttributeFlags,
    /// Attributes that an entry MUST NOT possess.
    must_lack: FileAttributeFlags,
}

impl AttrFilter {
    /// Parses a `/A[:]` specification string (e.g. `"D"`, `"-D"`, `"R-H"`).
    ///
    /// # Arguments
    /// * `spec` - Attribute filter characters after `/A`.
    ///
    /// # Returns
    /// Parsed [`AttrFilter`].
    #[must_use]
    fn parse(spec: &str) -> Self {
        let mut filter = Self {
            explicit: true,
            must_have: FileAttributeFlags::EMPTY,
            must_lack: FileAttributeFlags::EMPTY,
        };
        let mut neg = false;
        for ch in spec.trim_start_matches(':').chars() {
            if ch == '-' {
                neg = true;
                continue;
            }
            let bit = match ch.to_ascii_uppercase() {
                'D' => Some(FileAttributeFlags::DIRECTORY),
                'R' => Some(FileAttributeFlags::READ_ONLY),
                'H' => Some(FileAttributeFlags::HIDDEN),
                'S' => Some(FileAttributeFlags::SYSTEM),
                'A' => Some(FileAttributeFlags::ARCHIVE),
                'L' => Some(FileAttributeFlags::REPARSE_POINT),
                _ => None,
            };
            if let Some(flag) = bit {
                if neg {
                    filter.must_lack.insert(flag);
                } else {
                    filter.must_have.insert(flag);
                }
            }
            neg = false;
        }
        filter
    }

    /// Checks whether `meta` satisfies this [`AttrFilter`].
    ///
    /// # Arguments
    /// * `meta` - Entry [`VfsMetadata`].
    /// * `hs_policy` - [`HiddenSystemPolicy`] when `self.explicit` is `false`.
    ///
    /// # Returns
    /// `true` if `meta` matches.
    #[must_use]
    fn matches(self, meta: &VfsMetadata, hs_policy: HiddenSystemPolicy) -> bool {
        let flags = meta.attributes;
        if !self.explicit && hs_policy == HiddenSystemPolicy::HideByDefault {
            return !flags.is_hidden() && !flags.is_system();
        }
        flags.contains(self.must_have) && !has_any_overlap(flags, self.must_lack)
    }
}

/// Checks whether `flags` contains any individual attribute bit present in `mask`.
///
/// # Arguments
/// * `flags` - Entry [`FileAttributeFlags`].
/// * `mask` - Disallowed [`FileAttributeFlags`] mask.
///
/// # Returns
/// `true` if at least one bit in `mask` is present on `flags`.
#[must_use]
const fn has_any_overlap(flags: FileAttributeFlags, mask: FileAttributeFlags) -> bool {
    flags.intersects(mask)
}

/// Default visibility policy for Hidden (`H`) and System (`S`) entries when `/A` is omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HiddenSystemPolicy {
    /// Exclude hidden and system entries by default (`DIR`).
    HideByDefault,
    /// Include entries unless explicitly filtered (`DEL`).
    IncludeByDefault,
}

/// Parsed options for `DIR`.
#[derive(Debug, Clone)]
struct DirOptions {
    /// Formatting and traversal bitmask flags.
    flags: DirFlags,
    /// Optional sort field (`/O:...`).
    sort_field: Option<DirSortField>,
    /// Attribute filter (`/A:...`).
    attr_filter: AttrFilter,
    /// Thousand separator policy (`/C` vs `/-C`).
    thousands_sep: ThousandsSeparatorMode,
}

/// Built-in `CD` / `CHDIR` command (`CD [/D] [path]`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `raw_tail` - Raw post-command tail.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if target directory resolution fails or writing to `io` fails.
pub(super) fn cmd_cd(
    interp: &mut Interpreter,
    raw_tail: &str,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let trimmed = raw_tail.trim();
    if trimmed.is_empty() {
        let cwd = interp.current_cwd_string();
        io.write_stdout_str(&format!("{cwd}{CRLF}"))?;
        interp.record_success();
        return Ok(FlowControl::Continue);
    }

    let mut switch_drive = false;
    let target_str = if trimmed.len() >= 2
        && trimmed.get(..2).unwrap_or("").eq_ignore_ascii_case("/D")
        && trimmed
            .chars()
            .nth(2)
            .is_none_or(|c| c.is_whitespace() || c == '"')
    {
        switch_drive = true;
        trimmed.get(2..).unwrap_or("").trim()
    } else {
        trimmed
    };

    let unquoted = target_str.trim_matches('"');
    if !switch_drive
        && unquoted.len() == 2
        && unquoted.ends_with(':')
        && let Ok(drive) =
            DriveLetter::try_from_char(unquoted.as_bytes().first().copied().map_or(' ', char::from))
    {
        let dcwd = interp.proc_env.vfs.drive_cwd(drive)?;
        io.write_stdout_str(&format!("{}{CRLF}", dcwd.to_windows_string()))?;
        interp.record_success();
        return Ok(FlowControl::Continue);
    }

    let resolved = interp.proc_env.vfs.resolve_path(unquoted);
    interp.proc_env.vfs.set_drive_cwd(&resolved)?;
    if switch_drive {
        interp.proc_env.vfs.set_current_drive(resolved.drive)?;
    }
    interp
        .proc_env
        .env
        .set_drive_cwd_var(resolved.drive, &resolved);
    interp.sync_active_host_cwd();
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `MD` / `MKDIR` command, creating intermediate directories when `/E:ON`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `MD` command.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] when no directory argument is supplied or [`CmdError`] on VFS failure.
pub(super) fn cmd_mkdir(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
) -> Result<FlowControl, CmdError> {
    if args.is_empty() {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }
    let parent_mode = if interp.proc_env.env.extensions == ExtensionsMode::Enabled {
        crate::types::DirCreationDepth::CreateParents
    } else {
        crate::types::DirCreationDepth::ImmediateParentOnly
    };
    for arg in args {
        interp
            .proc_env
            .vfs
            .create_dir(arg.unquoted(), parent_mode)?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `RD` / `RMDIR` command (`RD [/S] [/Q] path...`), prompting interactively via `io` when `/S` lacks `/Q`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `RD` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] when no target path is given or [`CmdError`] on VFS/stream failure.
pub(super) fn cmd_rmdir(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut removal_mode = crate::types::DirRemovalMode::EmptyOnly;
    let mut confirm_mode = PromptConfirmMode::PromptEach;
    let mut paths = Vec::new();
    for arg in args {
        let u = arg.unquoted();
        if u.eq_ignore_ascii_case("/S") {
            removal_mode = crate::types::DirRemovalMode::RecursiveSubtree;
        } else if u.eq_ignore_ascii_case("/Q") {
            confirm_mode = PromptConfirmMode::Silent;
        } else {
            paths.push(u);
        }
    }
    if paths.is_empty() {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }
    for p in paths {
        if removal_mode == crate::types::DirRemovalMode::RecursiveSubtree
            && confirm_mode == PromptConfirmMode::PromptEach
        {
            io.write_stdout_str(&format!("{p}, Are you sure (Y/N)? "))?;
            let ans = io.read_stdin_line()?.unwrap_or_default();
            if !ans.trim().to_ascii_uppercase().starts_with('Y') {
                continue;
            }
        }
        interp.proc_env.vfs.remove_dir(p, removal_mode)?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `PUSHD` command (`PUSHD [path | //server/share]`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `raw_tail` - Raw post-command tail.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if target directory or UNC share resolution fails or writing to `io` fails.
pub(super) fn cmd_pushd(
    interp: &mut Interpreter,
    raw_tail: &str,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let trimmed = raw_tail.trim().trim_matches('"');
    if trimmed.is_empty() {
        let mut out = String::new();
        for entry in interp.proc_env.pushd_stack.iter().rev() {
            write!(out, "{}{CRLF}", entry.saved_path.to_windows_string()).unwrap_or(());
        }
        io.write_stdout_str(&out)?;
        interp.record_success();
        return Ok(FlowControl::Continue);
    }

    let cur_drive = interp.proc_env.vfs.current_drive();
    let fallback_root = WindowsPath::root(cur_drive);
    let cur_cwd = interp
        .proc_env
        .vfs
        .drive_cwd(cur_drive)
        .unwrap_or(fallback_root);

    let is_unc = trimmed.starts_with(crate::types::DOUBLE_BS_STR) || trimmed.starts_with("//");
    if is_unc && interp.proc_env.env.extensions == ExtensionsMode::Enabled {
        let unc_meta = interp.proc_env.vfs.stat(trimmed)?;
        if !unc_meta.attributes.is_directory() {
            return Err(CmdError::PathNotFound {
                path: trimmed.to_owned(),
            });
        }
        let share_str = unc_meta.full_path.drive_string();
        let temp_drive = interp
            .proc_env
            .vfs
            .mount_unc_drive(&share_str, &unc_meta.full_path.components)?;
        let temp_root = WindowsPath::root(temp_drive);
        let temp_cwd = interp
            .proc_env
            .vfs
            .drive_cwd(temp_drive)
            .unwrap_or(temp_root);
        interp.proc_env.vfs.set_current_drive(temp_drive)?;
        interp.proc_env.env.set_drive_cwd_var(temp_drive, &temp_cwd);
        interp.proc_env.pushd_stack.push(PushdEntry {
            saved_path: cur_cwd,
            temp_unc_drive: Some(temp_drive),
        });
    } else {
        let target = interp.proc_env.vfs.resolve_path(trimmed);
        interp.proc_env.vfs.set_drive_cwd(&target)?;
        interp.proc_env.vfs.set_current_drive(target.drive)?;
        interp.proc_env.env.set_drive_cwd_var(target.drive, &target);
        interp.proc_env.pushd_stack.push(PushdEntry {
            saved_path: cur_cwd,
            temp_unc_drive: None,
        });
    }
    interp.sync_active_host_cwd();
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `POPD` command, restoring the top `PUSHD` directory and unmounting any temporary UNC drive.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
///
/// # Returns
/// [`FlowControl::Continue`].
pub(super) fn cmd_popd(interp: &mut Interpreter) -> FlowControl {
    let Some(entry) = interp.proc_env.pushd_stack.pop() else {
        interp.record_failure(ExitCode::FAILURE);
        return FlowControl::Continue;
    };
    if let Some(temp_drive) = entry.temp_unc_drive {
        interp.proc_env.vfs.unmount_drive(temp_drive);
        interp.proc_env.env.remove_drive_cwd_var(temp_drive);
    }
    if interp.proc_env.vfs.set_drive_cwd(&entry.saved_path).is_ok() {
        interp
            .proc_env
            .vfs
            .set_current_drive(entry.saved_path.drive)
            .unwrap_or(());
        interp
            .proc_env
            .env
            .set_drive_cwd_var(entry.saved_path.drive, &entry.saved_path);
        interp.sync_active_host_cwd();
        interp.record_success();
    } else {
        interp.record_failure(ExitCode::FAILURE);
    }
    FlowControl::Continue
}

/// Built-in `DIR` command (`/B`, `/S`, `/W`, `/D`, `/L`, `/X`, `/A:...`, `/O:...`).
///
/// Sorts `/O:D` and `/O:-D` chronologically using [`crate::vfs::FileTimestamp`]!
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if writing to `io` fails.
pub(super) fn cmd_dir(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut opts = DirOptions {
        flags: DirFlags::default(),
        sort_field: None,
        attr_filter: AttrFilter::default(),
        thousands_sep: ThousandsSeparatorMode::UseSeparator,
    };
    let mut targets: Vec<String> = Vec::new();

    if let Some(dircmd) = interp.lookup_var("DIRCMD") {
        for sw in dircmd.split_whitespace() {
            apply_dir_switch(sw, &mut opts);
        }
    }
    for arg in args {
        let u = arg.unquoted();
        if u.starts_with('/') {
            apply_dir_switch(u, &mut opts);
        } else {
            targets.push(u.to_owned());
        }
    }
    if targets.is_empty() {
        targets.push(".".to_owned());
    }

    let mut any_matched = false;
    for target in &targets {
        if list_dir_target(interp, target, &opts, io)? {
            any_matched = true;
        }
    }

    if any_matched {
        interp.record_success();
    } else {
        io.write_stderr_str(&format!("File Not Found{CRLF}"))?;
        interp.record_failure(ExitCode::FAILURE);
    }
    Ok(FlowControl::Continue)
}

/// Applies a single `DIR` `/switch` token onto `opts`.
///
/// # Arguments
/// * `sw` - Switch token (e.g. `"/B"`, `"/O:-D"`, `"/A:D"`).
/// * `opts` - Mutable [`DirOptions`].
fn apply_dir_switch(sw: &str, opts: &mut DirOptions) {
    let upper = sw.to_ascii_uppercase();
    if upper == "/B" {
        opts.flags.insert(DirFlags::BARE);
    } else if upper == "/S" {
        opts.flags.insert(DirFlags::RECURSIVE);
    } else if upper == "/W" || upper == "/D" {
        opts.flags.insert(DirFlags::WIDE);
    } else if upper == "/L" {
        opts.flags.insert(DirFlags::LOWERCASE);
    } else if upper == "/X" {
        opts.flags.insert(DirFlags::SHOW_SHORT);
    } else if upper == "/C" {
        opts.thousands_sep = ThousandsSeparatorMode::UseSeparator;
    } else if upper == "/-C" {
        opts.thousands_sep = ThousandsSeparatorMode::OmitSeparator;
    } else if let Some(rest) = upper.strip_prefix("/A") {
        opts.attr_filter = AttrFilter::parse(rest);
    } else if let Some(rest) = upper.strip_prefix("/O") {
        let spec = rest.trim_start_matches(':');
        let (rev, field_ch) = spec.strip_prefix('-').map_or_else(
            || (false, spec.chars().next().unwrap_or('N')),
            |s| (true, s.chars().next().unwrap_or('N')),
        );
        if rev {
            opts.flags.insert(DirFlags::SORT_REVERSE);
        }
        opts.sort_field = match field_ch {
            'S' => Some(DirSortField::Size),
            'E' => Some(DirSortField::Extension),
            'D' => Some(DirSortField::DateTime),
            'G' => Some(DirSortField::DirectoriesFirst),
            _ => Some(DirSortField::Name),
        };
    }
}

/// Lists a single `DIR` target path or wildcard specification.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `target` - Target directory or wildcard pattern.
/// * `opts` - Parsed [`DirOptions`].
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(true)` if at least one entry matched, `Ok(false)` otherwise.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing to `io` fails.
fn list_dir_target(
    interp: &Interpreter,
    target: &str,
    opts: &DirOptions,
    io: &mut dyn CmdIo,
) -> Result<bool, CmdError> {
    let resolved = interp.proc_env.vfs.resolve_path(target);
    let (base_dir, pattern) = if contains_wildcards(target) {
        (
            resolved.parent(),
            resolved.file_name().unwrap_or("*").to_owned(),
        )
    } else if interp
        .proc_env
        .vfs
        .stat(&resolved.to_windows_string())
        .is_ok_and(|m| m.attributes.is_directory())
    {
        (resolved, "*".to_owned())
    } else {
        (
            resolved.parent(),
            resolved.file_name().unwrap_or("*").to_owned(),
        )
    };

    let dirs_to_visit = if opts.flags.contains(DirFlags::RECURSIVE) {
        collect_dir_tree(interp, &base_dir)
    } else {
        vec![base_dir]
    };

    let mut matched_any = false;
    for dir_path in dirs_to_visit {
        let dir_str = dir_path.to_windows_string();
        let Ok(entries) = interp.proc_env.vfs.read_dir(&dir_str) else {
            continue;
        };
        let mut filtered: Vec<VfsMetadata> = entries
            .into_iter()
            .filter(|e| {
                matches_win32_glob(
                    &pattern,
                    &e.name,
                    Some(&e.short_name),
                    CaseSensitivity::Insensitive,
                ) && opts
                    .attr_filter
                    .matches(e, HiddenSystemPolicy::HideByDefault)
            })
            .collect();

        if filtered.is_empty() && opts.flags.contains(DirFlags::RECURSIVE) {
            continue;
        }
        sort_dir_entries(&mut filtered, opts);
        if !filtered.is_empty() {
            matched_any = true;
        }
        render_dir_entries(interp, &dir_str, &filtered, opts, io)?;
    }
    Ok(matched_any)
}

/// Recursively collects directory paths starting at `root` for `DIR /S`.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `root` - Starting [`WindowsPath`].
///
/// # Returns
/// Vector of visited directory paths.
fn collect_dir_tree(interp: &Interpreter, root: &WindowsPath) -> Vec<WindowsPath> {
    let mut out = vec![root.clone()];
    for e in interp
        .proc_env
        .vfs
        .read_dir(&root.to_windows_string())
        .unwrap_or_default()
    {
        if e.attributes.is_directory() {
            out.extend(collect_dir_tree(interp, &e.full_path));
        }
    }
    out
}

/// Sorts `DIR` entries according to `opts.sort_field` (chronological [`crate::vfs::FileTimestamp`] on `/O:D`!).
///
/// # Arguments
/// * `entries` - Mutable slice of [`VfsMetadata`] entries.
/// * `opts` - Active [`DirOptions`].
fn sort_dir_entries(entries: &mut [VfsMetadata], opts: &DirOptions) {
    let Some(field) = opts.sort_field else {
        return;
    };
    let reverse = opts.flags.contains(DirFlags::SORT_REVERSE);
    entries.sort_by(|a, b| {
        let ord = match field {
            DirSortField::Name => a
                .name
                .to_ascii_uppercase()
                .cmp(&b.name.to_ascii_uppercase()),
            DirSortField::Size => a.size.cmp(&b.size),
            DirSortField::Extension => {
                let ea = a.name.rsplit('.').next().unwrap_or("").to_ascii_uppercase();
                let eb = b.name.rsplit('.').next().unwrap_or("").to_ascii_uppercase();
                ea.cmp(&eb)
            }
            DirSortField::DateTime => a.modified_timestamp.cmp(&b.modified_timestamp),
            DirSortField::DirectoriesFirst => b
                .attributes
                .is_directory()
                .cmp(&a.attributes.is_directory())
                .then_with(|| {
                    a.name
                        .to_ascii_uppercase()
                        .cmp(&b.name.to_ascii_uppercase())
                }),
        };
        if reverse { ord.reverse() } else { ord }
    });
}

/// Formats and writes a directory's matched `DIR` entries to `io`.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `dir_str` - Display path of the directory.
/// * `filtered` - Sorted slice of matched [`VfsMetadata`].
/// * `opts` - Active [`DirOptions`].
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing to `io` fails.
fn render_dir_entries(
    interp: &Interpreter,
    dir_str: &str,
    filtered: &[VfsMetadata],
    opts: &DirOptions,
    io: &mut dyn CmdIo,
) -> Result<(), CmdError> {
    let mut out = String::new();
    if opts.flags.contains(DirFlags::BARE) {
        for entry in filtered {
            let mut disp = if opts.flags.contains(DirFlags::RECURSIVE) {
                entry.full_path.to_windows_string()
            } else {
                entry.name.clone()
            };
            if opts.flags.contains(DirFlags::LOWERCASE) {
                disp = disp.to_ascii_lowercase();
            }
            write!(out, "{disp}{CRLF}").unwrap_or(());
        }
    } else if opts.flags.contains(DirFlags::WIDE) {
        write!(out, " Directory of {dir_str}{CRLF}{CRLF}").unwrap_or(());
        let mut names = Vec::with_capacity(filtered.len());
        for entry in filtered {
            let mut n = entry.name.clone();
            if opts.flags.contains(DirFlags::LOWERCASE) {
                n = n.to_ascii_lowercase();
            }
            if entry.attributes.is_directory() {
                names.push(format!("[{n}]"));
            } else {
                names.push(n);
            }
        }
        write!(out, "{}{CRLF}", names.join("  ")).unwrap_or(());
    } else {
        write!(out, " Directory of {dir_str}{CRLF}{CRLF}").unwrap_or(());
        let mut file_count = 0usize;
        let mut dir_count = 0usize;
        let mut total_bytes = 0u64;
        for entry in filtered {
            let mut disp_name = entry.name.clone();
            if opts.flags.contains(DirFlags::LOWERCASE) {
                disp_name = disp_name.to_ascii_lowercase();
            }
            let short_col = if opts.flags.contains(DirFlags::SHOW_SHORT) {
                format!("{:<13}", entry.short_name)
            } else {
                String::new()
            };
            let ts = entry
                .modified_timestamp
                .format_with_locale(&interp.config.locale);
            if entry.attributes.is_directory() {
                dir_count = dir_count.saturating_add(1);
                write!(out, "{ts}    <DIR>          {short_col}{disp_name}{CRLF}").unwrap_or(());
            } else {
                file_count = file_count.saturating_add(1);
                total_bytes = total_bytes.saturating_add(entry.size);
                let sz = interp
                    .config
                    .locale
                    .format_number_with_thousands(entry.size, opts.thousands_sep);
                write!(out, "{ts}    {sz:>14} {short_col}{disp_name}{CRLF}").unwrap_or(());
            }
        }
        let grouped_total = interp
            .config
            .locale
            .format_number_with_thousands(total_bytes, opts.thousands_sep);
        write!(
            out,
            "{file_count:>16} File(s) {grouped_total:>14} bytes{CRLF}{dir_count:>16} Dir(s){CRLF}"
        )
        .unwrap_or(());
    }
    io.write_stdout_str(&out)
}

/// Built-in `TYPE` command (`TYPE file...`), propagating `decode_script_bytes` errors via `?`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `TYPE` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] if no file is given, [`CmdError::EncodingFailure`] on invalid
/// byte sequences, or VFS/output [`CmdError`]s.
pub(super) fn cmd_type(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    if args.is_empty() {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }
    let multi = args.len() > 1;
    for arg in args {
        let path = arg.unquoted();
        let bytes = interp.proc_env.vfs.read_bytes(path)?;
        let decoded = decode_script_bytes(&bytes, interp.console.codepage)?;
        if multi {
            io.write_stderr_str(&format!("{CRLF}{path}{CRLF}{CRLF}"))?;
        }
        io.write_stdout_str(&decoded)?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Strongly typed options for `COPY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CopyOptions {
    /// `/A` ASCII text vs `/B` raw binary transfer mode.
    data_mode: CopyDataMode,
    /// `/V` or `VERIFY ON` post-write byte verification mode.
    verify_mode: VerifyCopyMode,
    /// `/Y`, `/-Y`, or `%COPYCMD%` destination overwrite policy.
    overwrite_policy: OverwritePolicy,
}

/// Built-in `COPY` command (`/A`, `/B`, `/V`, `/Y`, `/-Y`, `/Z`, `/D`, `/L`, `a+b dst`, wildcards).
///
/// Propagates VFS read and write errors cleanly so unreadable sources never corrupt destinations!
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `COPY` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] on missing operands, self-copy, VFS read/write errors, or stream failure.
pub(super) fn cmd_copy(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut opts = CopyOptions {
        data_mode: CopyDataMode::BinaryRaw,
        verify_mode: interp.config.verify_state,
        overwrite_policy: OverwritePolicy::from_copycmd_env(
            interp.lookup_var("COPYCMD").as_deref(),
        ),
    };

    let mut non_switches: Vec<&str> = Vec::new();
    for arg in args {
        let u = arg.unquoted();
        match u.to_ascii_uppercase().as_str() {
            "/A" => opts.data_mode = CopyDataMode::AsciiText,
            "/B" | "/Z" | "/D" | "/L" => opts.data_mode = CopyDataMode::BinaryRaw,
            "/V" => opts.verify_mode = VerifyCopyMode::Verified,
            "/Y" => opts.overwrite_policy = OverwritePolicy::AlwaysOverwrite,
            "/-Y" => opts.overwrite_policy = OverwritePolicy::Prompt,
            _ if u.starts_with('/') => {}
            _ => non_switches.push(u),
        }
    }

    let Some(&src_spec) = non_switches.first() else {
        return Err(CmdError::SyntaxError { span: cmd_span });
    };
    let dst_raw = non_switches.get(1).copied().unwrap_or(".");

    if src_spec.contains('+') {
        return copy_concatenated(interp, src_spec, dst_raw, opts, io);
    }
    if contains_wildcards(src_spec) {
        return copy_wildcards(interp, src_spec, dst_raw, opts, io);
    }

    let dst_resolved = resolve_copy_dest(interp, src_spec, dst_raw);
    if !confirm_overwrite_if_needed(interp, &dst_resolved, &mut opts.overwrite_policy, io)? {
        io.write_stdout_str(&format!("        0 file(s) copied.{CRLF}"))?;
        interp.record_success();
        return Ok(FlowControl::Continue);
    }

    let src_p = interp.proc_env.vfs.resolve_path(src_spec);
    let dst_p = interp.proc_env.vfs.resolve_path(&dst_resolved);
    if src_p == dst_p {
        return Err(CmdError::CannotCopyOntoItself {
            path: src_spec.to_owned(),
        });
    }
    let mut bytes = interp.proc_env.vfs.read_bytes(src_spec)?;
    if opts.data_mode == CopyDataMode::AsciiText {
        if let Some(z_pos) = bytes.iter().position(|&b| b == CTRL_Z_BYTE) {
            bytes.truncate(z_pos);
        }
        bytes.push(CTRL_Z_BYTE);
    }
    write_and_verify_bytes(interp, &dst_resolved, &bytes, opts.verify_mode, io)?;
    io.write_stdout_str(&format!("        1 file(s) copied.{CRLF}"))?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Copies and concatenates `a+b+c` into `dst_raw`.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `src_spec` - Plus-separated source specification.
/// * `dst_raw` - Raw destination path.
/// * `opts` - Active [`CopyOptions`].
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if reading any source or writing destination fails.
fn copy_concatenated(
    interp: &mut Interpreter,
    src_spec: &str,
    dst_raw: &str,
    mut opts: CopyOptions,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let parts: Vec<&str> = src_spec
        .split('+')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let first_src = parts.first().copied().unwrap_or("out");
    let dst = resolve_copy_dest(interp, first_src, dst_raw);
    let dst_p = interp.proc_env.vfs.resolve_path(&dst);
    let is_in_place_append = parts
        .first()
        .is_some_and(|first| interp.proc_env.vfs.resolve_path(first) == dst_p);
    if !is_in_place_append
        && !confirm_overwrite_if_needed(interp, &dst, &mut opts.overwrite_policy, io)?
    {
        io.write_stdout_str(&format!("        0 file(s) copied.{CRLF}"))?;
        interp.record_success();
        return Ok(FlowControl::Continue);
    }
    let mut combined = Vec::new();
    for p in &parts {
        let mut b = interp.proc_env.vfs.read_bytes(p)?;
        if opts.data_mode == CopyDataMode::AsciiText
            && let Some(z_pos) = b.iter().position(|&byte| byte == CTRL_Z_BYTE)
        {
            b.truncate(z_pos);
        }
        combined.extend_from_slice(&b);
    }
    if opts.data_mode == CopyDataMode::AsciiText {
        combined.push(CTRL_Z_BYTE);
    }
    write_and_verify_bytes(interp, &dst, &combined, opts.verify_mode, io)?;
    io.write_stdout_str(&format!("        1 file(s) copied.{CRLF}"))?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Copies wildcard-matched files from `src_spec` to `dst_raw`, propagating read/write errors.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `src_spec` - Wildcard source pattern.
/// * `dst_raw` - Destination directory or file path.
/// * `opts` - Active [`CopyOptions`].
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] if directory listing, file copying, or output fails.
fn copy_wildcards(
    interp: &mut Interpreter,
    src_spec: &str,
    dst_raw: &str,
    mut opts: CopyOptions,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let resolved_src = interp.proc_env.vfs.resolve_path(src_spec);
    let src_dir = resolved_src.parent();
    let pat = resolved_src.file_name().unwrap_or("*");
    let entries = interp.proc_env.vfs.read_dir(&src_dir.to_windows_string())?;
    let mut copied_count = 0usize;
    for entry in entries {
        if !entry.attributes.is_directory()
            && matches_win32_glob(
                pat,
                &entry.name,
                Some(&entry.short_name),
                CaseSensitivity::Insensitive,
            )
        {
            let src_file = entry.full_path.to_windows_string();
            let dst_file = resolve_copy_dest(interp, &src_file, dst_raw);
            if entry.full_path == interp.proc_env.vfs.resolve_path(&dst_file) {
                return Err(CmdError::CannotCopyOntoItself { path: src_file });
            }
            if !confirm_overwrite_if_needed(interp, &dst_file, &mut opts.overwrite_policy, io)? {
                continue;
            }
            let mut src_bytes = interp.proc_env.vfs.read_bytes(&src_file)?;
            if opts.data_mode == CopyDataMode::AsciiText {
                if let Some(z_pos) = src_bytes.iter().position(|&b| b == CTRL_Z_BYTE) {
                    src_bytes.truncate(z_pos);
                }
                src_bytes.push(CTRL_Z_BYTE);
            }
            write_and_verify_bytes(interp, &dst_file, &src_bytes, opts.verify_mode, io)?;
            copied_count = copied_count.saturating_add(1);
        }
    }
    io.write_stdout_str(&format!("        {copied_count} file(s) copied.{CRLF}"))?;
    if copied_count > 0 {
        interp.record_success();
    } else {
        interp.record_failure(ExitCode::FAILURE);
    }
    Ok(FlowControl::Continue)
}

/// Writes `bytes` to `dst` (routing `CON` directly through `io.write_stdout_bytes`) and, when
/// `verify_mode` is [`VerifyCopyMode::Verified`], reads back the written file to verify integrity.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `dst` - Destination file or device path.
/// * `bytes` - Payload bytes to write.
/// * `verify_mode` - Active [`VerifyCopyMode`].
/// * `io` - Mutable [`CmdIo`] stream (receiving raw bytes when `dst` is `CON`).
///
/// # Returns
/// `Ok(())` when writing (and optional verification) succeeds.
///
/// # Errors
/// Returns [`CmdError`] if writing, reading back, or byte verification fails.
pub(super) fn write_and_verify_bytes(
    interp: &mut Interpreter,
    dst: &str,
    bytes: &[u8],
    verify_mode: VerifyCopyMode,
    io: &mut dyn CmdIo,
) -> Result<(), CmdError> {
    if let Some((_, dev)) = crate::vfs::devices::DosDevice::split_path_device(dst) {
        interp.proc_env.vfs.write_bytes(dst, bytes)?;
        if dev == crate::vfs::devices::DosDevice::Con {
            io.write_stdout_bytes(bytes)?;
        }
        return Ok(());
    }
    interp.proc_env.vfs.write_bytes(dst, bytes)?;
    if verify_mode == VerifyCopyMode::Verified {
        let actual = interp.proc_env.vfs.read_bytes(dst)?;
        return verify_readback_matches(dst, bytes, &actual);
    }
    Ok(())
}

/// Verifies that `actual` bytes read back from `dst` match `expected` written bytes.
///
/// # Arguments
/// * `dst` - Destination path for diagnostic reporting.
/// * `expected` - Expected byte slice written to `dst`.
/// * `actual` - Actual byte slice read back from `dst`.
///
/// # Returns
/// `Ok(())` when `expected == actual`.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] when the read-back bytes differ from `expected`.
pub(super) fn verify_readback_matches(
    dst: &str,
    expected: &[u8],
    actual: &[u8],
) -> Result<(), CmdError> {
    if expected == actual {
        Ok(())
    } else {
        Err(CmdError::IoFailure {
            operation: "verify_write".to_owned(),
            message: format!("Write verification failed for '{dst}'."),
        })
    }
}

/// Evaluates [`OverwritePolicy`] when `dst` already exists, prompting `"Overwrite <dst>? (Yes/No/All): "`
/// on [`OverwritePolicy::Prompt`] and upgrading `policy` to [`OverwritePolicy::AlwaysOverwrite`] on `'A'`.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `dst` - Resolved destination file path.
/// * `policy` - Mutable [`OverwritePolicy`] (updated to `AlwaysOverwrite` when user selects `All`).
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(true)` if writing should proceed, `Ok(false)` if skipped.
///
/// # Errors
/// Returns [`CmdError`] if prompting or reading `io` fails.
pub(super) fn confirm_overwrite_if_needed(
    interp: &Interpreter,
    dst: &str,
    policy: &mut OverwritePolicy,
    io: &mut dyn CmdIo,
) -> Result<bool, CmdError> {
    if !interp.proc_env.vfs.exists(dst) {
        return Ok(true);
    }
    match *policy {
        OverwritePolicy::AlwaysOverwrite => Ok(true),
        OverwritePolicy::NeverOverwrite => Ok(false),
        OverwritePolicy::Prompt => {
            io.write_stdout_str(&format!("Overwrite {dst}? (Yes/No/All): "))?;
            let ans = io.read_stdin_line()?.unwrap_or_default();
            let ch = ans
                .trim()
                .chars()
                .next()
                .unwrap_or('N')
                .to_ascii_uppercase();
            if ch == 'A' {
                *policy = OverwritePolicy::AlwaysOverwrite;
                Ok(true)
            } else {
                Ok(ch == 'Y')
            }
        }
    }
}

/// Resolves the target file path for `COPY` / `MOVE` when `dst` may be an existing directory.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `src` - Source file path.
/// * `dst` - Destination file or directory path.
///
/// # Returns
/// Resolved destination file path string.
#[must_use]
fn resolve_copy_dest(interp: &Interpreter, src: &str, dst: &str) -> String {
    let dst_p = interp.proc_env.vfs.resolve_path(dst);
    let src_p = interp.proc_env.vfs.resolve_path(src);
    if interp
        .proc_env
        .vfs
        .stat(&dst_p.to_windows_string())
        .is_ok_and(|m| m.attributes.is_directory())
    {
        return dst_p
            .join_component(src_p.file_name().unwrap_or(""))
            .to_windows_string();
    }
    dst_p.to_windows_string()
}

/// Strongly typed options for `DEL` / `ERASE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DelOptions {
    /// `/F` read-only deletion policy.
    read_only_policy: ReadOnlyDeletePolicy,
    /// `/S` subdirectory recursion policy.
    depth: TraversalDepth,
    /// Confirmation policy on global wildcards (`*` / `*.*`), silenced by `/Q` or `/P`.
    wildcard_confirm: PromptConfirmMode,
    /// `/P` per-file deletion confirmation policy.
    each_confirm: PromptConfirmMode,
}

/// Built-in `DEL` / `ERASE` command (`/P`, `/F`, `/S`, `/Q`, `/A:...`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `DEL` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] when no target is supplied or [`CmdError`] on VFS/stream failure.
pub(super) fn cmd_del(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut opts = DelOptions {
        read_only_policy: ReadOnlyDeletePolicy::RespectReadOnly,
        depth: TraversalDepth::Shallow,
        wildcard_confirm: PromptConfirmMode::PromptEach,
        each_confirm: PromptConfirmMode::Silent,
    };
    let mut attr_filter = AttrFilter::default();
    let mut targets: Vec<&str> = Vec::new();

    for arg in args {
        let u = arg.unquoted();
        let upper = u.to_ascii_uppercase();
        match upper.as_str() {
            "/F" => opts.read_only_policy = ReadOnlyDeletePolicy::ForceDeleteReadOnly,
            "/S" => opts.depth = TraversalDepth::Recursive,
            "/Q" => opts.wildcard_confirm = PromptConfirmMode::Silent,
            "/P" => {
                opts.each_confirm = PromptConfirmMode::PromptEach;
                opts.wildcard_confirm = PromptConfirmMode::Silent;
            }
            _ if upper.starts_with("/A") => {
                attr_filter = AttrFilter::parse(upper.get(2..).unwrap_or(""));
            }
            _ if u.starts_with('/') => {}
            _ => targets.push(u),
        }
    }

    if targets.is_empty() {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }

    for target in targets {
        delete_target_spec(interp, target, opts, attr_filter, io)?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Deletes files matching a single `DEL` target specification.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `target` - File, directory, or wildcard path.
/// * `opts` - Active [`DelOptions`].
/// * `attr_filter` - Active [`AttrFilter`].
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns [`CmdError`] if deletion or interactive prompting fails.
fn delete_target_spec(
    interp: &mut Interpreter,
    target: &str,
    opts: DelOptions,
    attr_filter: AttrFilter,
    io: &mut dyn CmdIo,
) -> Result<(), CmdError> {
    let resolved = interp.proc_env.vfs.resolve_path(target);
    let is_dir = interp
        .proc_env
        .vfs
        .stat(&resolved.to_windows_string())
        .is_ok_and(|m| m.attributes.is_directory());

    if !contains_wildcards(target) && !is_dir && opts.depth == TraversalDepth::Shallow {
        return delete_single_file(interp, target, opts, io);
    }

    let (base_dir, pat) = if is_dir {
        (resolved, "*")
    } else {
        (resolved.parent(), resolved.file_name().unwrap_or("*"))
    };

    if (pat == "*" || pat == "*.*") && opts.wildcard_confirm == PromptConfirmMode::PromptEach {
        let prompt_msg =
            if is_dir && interp.config.dialect != crate::types::ShellDialect::WindowsNtCmd {
                format!("All files in directory will be deleted!{CRLF}Are you sure (Y/N)? ")
            } else {
                format!(
                    "{}{BS_STR}*, Are you sure (Y/N)? ",
                    base_dir.to_windows_string()
                )
            };
        io.write_stdout_str(&prompt_msg)?;
        let ans = io.read_stdin_line()?.unwrap_or_default();
        if !ans.trim().to_ascii_uppercase().starts_with('Y') {
            return Ok(());
        }
    }

    let dirs = match opts.depth {
        TraversalDepth::Recursive => collect_dir_tree(interp, &base_dir),
        TraversalDepth::Shallow => vec![base_dir],
    };

    for d in dirs {
        let Ok(entries) = interp.proc_env.vfs.read_dir(&d.to_windows_string()) else {
            continue;
        };
        for entry in entries {
            if !entry.attributes.is_directory()
                && matches_win32_glob(
                    pat,
                    &entry.name,
                    Some(&entry.short_name),
                    CaseSensitivity::Insensitive,
                )
                && attr_filter.matches(&entry, HiddenSystemPolicy::IncludeByDefault)
            {
                delete_single_file(interp, &entry.full_path.to_windows_string(), opts, io)?;
            }
        }
    }
    Ok(())
}

/// Deletes a single file path honoring `/P` confirmation and `/F` read-only clearing.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `file_path` - Path of the file to delete.
/// * `opts` - Active [`DelOptions`].
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns [`CmdError`] if deletion fails or `io` fails.
fn delete_single_file(
    interp: &mut Interpreter,
    file_path: &str,
    opts: DelOptions,
    io: &mut dyn CmdIo,
) -> Result<(), CmdError> {
    if opts.each_confirm == PromptConfirmMode::PromptEach {
        io.write_stdout_str(&format!("{file_path}, Delete (Y/N)? "))?;
        let ans = io.read_stdin_line()?.unwrap_or_default();
        if !ans.trim().to_ascii_uppercase().starts_with('Y') {
            return Ok(());
        }
    }
    interp
        .proc_env
        .vfs
        .delete_file(file_path, opts.read_only_policy)
}

/// Built-in `REN` / `RENAME` command (`REN [drive:][path]filename1 filename2`), supporting wildcards.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `REN` command.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] on invalid operand count or destination directory prefix,
/// or [`CmdError`] on VFS rename failure.
pub(super) fn cmd_rename(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
) -> Result<FlowControl, CmdError> {
    if args.len() != 2 {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }
    let src = args.first().map_or("", SpannedWord::unquoted);
    let dst_leaf = args.get(1).map_or("", SpannedWord::unquoted);
    if dst_leaf.contains([BS_CHAR, '/', ':']) {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }

    let src_resolved = interp.proc_env.vfs.resolve_path(src);
    if contains_wildcards(src) || contains_wildcards(dst_leaf) {
        let parent = src_resolved.parent();
        let src_pat = src_resolved.file_name().unwrap_or("*");
        let entries = interp.proc_env.vfs.read_dir(&parent.to_windows_string())?;
        let mut renamed_any = false;
        for entry in entries {
            if matches_win32_glob(
                src_pat,
                &entry.name,
                Some(&entry.short_name),
                CaseSensitivity::Insensitive,
            ) {
                let new_leaf = apply_rename_wildcard_mask(&entry.name, dst_leaf);
                let new_full = parent.join_component(&new_leaf).to_windows_string();
                interp
                    .proc_env
                    .vfs
                    .move_entry(&entry.full_path.to_windows_string(), &new_full)?;
                renamed_any = true;
            }
        }
        if !renamed_any {
            return Err(CmdError::FileNotFound {
                path: src.to_owned(),
            });
        }
    } else {
        let dst_full = src_resolved
            .parent()
            .join_component(dst_leaf)
            .to_windows_string();
        interp.proc_env.vfs.move_entry(src, &dst_full)?;
    }

    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Applies a DOS wildcard destination mask (such as `"*.bak"` or `"new_*"`) to `src_name`.
///
/// # Arguments
/// * `src_name` - Original filename.
/// * `dst_mask` - Target filename mask containing `*` or `?`.
///
/// # Returns
/// Synthesized destination filename.
#[must_use]
fn apply_rename_wildcard_mask(src_name: &str, dst_mask: &str) -> String {
    let (src_stem, src_ext) = src_name.rfind('.').map_or((src_name, ""), |idx| {
        (
            src_name.get(..idx).unwrap_or(""),
            src_name.get(idx.saturating_add(1)..).unwrap_or(""),
        )
    });
    let (mask_stem, mask_ext) = dst_mask.rfind('.').map_or((dst_mask, None), |idx| {
        (
            dst_mask.get(..idx).unwrap_or(""),
            Some(dst_mask.get(idx.saturating_add(1)..).unwrap_or("")),
        )
    });

    let mut out = apply_part_mask(src_stem, mask_stem);
    if let Some(me) = mask_ext {
        let out_ext = apply_part_mask(src_ext, me);
        if !out_ext.is_empty() {
            out.push('.');
            out.push_str(&out_ext);
        }
    }
    out
}

/// Applies `*` and `?` substitution on a single stem or extension component.
///
/// # Arguments
/// * `src_part` - Source stem or extension.
/// * `mask_part` - Mask stem or extension.
///
/// # Returns
/// Substituted component string.
#[must_use]
fn apply_part_mask(src_part: &str, mask_part: &str) -> String {
    let mut out = String::new();
    let mut src_chars = src_part.chars();
    for mc in mask_part.chars() {
        match mc {
            '*' => {
                out.extend(src_chars.by_ref());
            }
            '?' => {
                if let Some(sc) = src_chars.next() {
                    out.push(sc);
                }
            }
            other => {
                src_chars.next();
                out.push(other);
            }
        }
    }
    out
}

/// Built-in `MOVE` command (`MOVE [/Y | /-Y] source destination`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `MOVE` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] on missing operands or [`CmdError`] on VFS/stream failure.
pub(super) fn cmd_move(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut overwrite_policy =
        OverwritePolicy::from_copycmd_env(interp.lookup_var("COPYCMD").as_deref());
    let mut paths: Vec<&str> = Vec::new();
    for arg in args {
        let u = arg.unquoted();
        if u.eq_ignore_ascii_case("/-Y") {
            overwrite_policy = OverwritePolicy::Prompt;
        } else if u.eq_ignore_ascii_case("/Y") {
            overwrite_policy = OverwritePolicy::AlwaysOverwrite;
        } else {
            paths.push(u);
        }
    }
    if paths.len() < 2 {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }
    let src = paths.first().copied().unwrap_or("");
    let dst = paths.get(1).copied().unwrap_or("");
    let dst_resolved = resolve_copy_dest(interp, src, dst);

    if !confirm_overwrite_if_needed(interp, &dst_resolved, &mut overwrite_policy, io)? {
        io.write_stdout_str(&format!("        0 file(s) moved.{CRLF}"))?;
        interp.record_success();
        return Ok(FlowControl::Continue);
    }
    let src_p = interp.proc_env.vfs.resolve_path(src);
    let dst_p = interp.proc_env.vfs.resolve_path(&dst_resolved);
    if src_p != dst_p
        && interp
            .proc_env
            .vfs
            .stat(&dst_resolved)
            .is_ok_and(|m| !m.attributes.is_directory())
    {
        interp
            .proc_env
            .vfs
            .delete_file(&dst_resolved, ReadOnlyDeletePolicy::ForceDeleteReadOnly)?;
    }
    interp.proc_env.vfs.move_entry(src, &dst_resolved)?;
    io.write_stdout_str(&format!("        1 file(s) moved.{CRLF}"))?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `MKLINK` command (`MKLINK [[/D] | [/H] | [/J]] Link Target`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `MKLINK` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] on missing operands or [`CmdError`] on VFS link creation failure.
pub(super) fn cmd_mklink(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut hardlink = false;
    let mut sym_kind = MklinkKind::FileSymlink;
    let mut positional: Vec<&str> = Vec::new();

    for arg in args {
        let u = arg.unquoted();
        match u.to_ascii_uppercase().as_str() {
            "/D" => sym_kind = MklinkKind::DirectorySymlink,
            "/J" => sym_kind = MklinkKind::DirectoryJunction,
            "/H" => hardlink = true,
            _ if u.starts_with('/') => {}
            _ => positional.push(u),
        }
    }

    if positional.len() < 2 {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }
    let link = positional.first().copied().unwrap_or("");
    let target = positional.get(1).copied().unwrap_or("");

    if hardlink {
        interp.proc_env.vfs.create_hardlink(link, target)?;
        io.write_stdout_str(&format!(
            "Hardlink created for {link} <<===>> {target}{CRLF}"
        ))?;
    } else {
        interp.proc_env.vfs.create_symlink(link, target, sym_kind)?;
        let kind_label = match sym_kind {
            MklinkKind::DirectoryJunction => "junction",
            MklinkKind::FileSymlink | MklinkKind::DirectorySymlink | MklinkKind::HardLink => {
                "symbolic link"
            }
        };
        io.write_stdout_str(&format!(
            "{kind_label} created for {link} <<===>> {target}{CRLF}"
        ))?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}
