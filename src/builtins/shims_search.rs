//! Search, comparison, paging, and tree utility shims
//! (`WHERE`, `FIND`, `FINDSTR`, `SORT`, `MORE`, `FC`, `COMP`, `TREE`).
//!
//! Includes a polynomial-time (`O(|P| * |L|)`) `FINDSTR /R` regular-expression engine
//! supporting `.`, `*`, `^`, `$`, `[a-z]` / `[^a-z]` character classes, and word boundaries,
//! propagates `decode_script_bytes` errors via `?`, and accurately reports missing files in `FC` and `COMP`.

use std::fmt::Write as _;

use crate::error::CmdError;
use crate::parser::ast::SpannedWord;
use crate::reader::encoding::decode_script_bytes;
use crate::runtime::{CmdIo, FlowControl, Interpreter};
use crate::span::Span;
use crate::types::{BS_CHAR, CR_CHAR, CRLF, CaseSensitivity, ExitCode};
use crate::vfs::VfsMetadata;
use crate::vfs::glob::{contains_wildcards, matches_win32_glob};
use crate::vfs::path::WindowsPath;

/// Built-in `WHERE` utility shim (`WHERE [/R dir] [/Q] [/F] [/T] pattern...`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `WHERE` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] if `/R` lacks a directory or no pattern is provided,
/// or [`CmdError::IoFailure`] on output failure.
pub(super) fn shim_where(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut quiet = false;
    let mut quote_out = false;
    let mut show_time_size = false;
    let mut recursive_root: Option<String> = None;
    let mut patterns: Vec<String> = Vec::new();

    let mut i = 0usize;
    while let Some(arg) = args.get(i) {
        let u = arg.unquoted();
        match u.to_ascii_uppercase().as_str() {
            "/Q" => quiet = true,
            "/F" => quote_out = true,
            "/T" => show_time_size = true,
            "/R" => {
                let Some(dir_arg) = args.get(i.saturating_add(1)) else {
                    return Err(CmdError::SyntaxError { span: cmd_span });
                };
                recursive_root = Some(dir_arg.unquoted().to_owned());
                i = i.saturating_add(2);
                continue;
            }
            _ => patterns.push(u.to_owned()),
        }
        i = i.saturating_add(1);
    }

    if patterns.is_empty() {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }

    let search_dirs = collect_where_dirs(interp, recursive_root.as_deref());
    let pathexts = collect_where_pathexts(interp);
    let mut found_any = false;
    let mut out = String::new();

    for pat in &patterns {
        let ext_mode = if pat.contains('.') {
            PatternExtensionMode::HasExtension
        } else {
            PatternExtensionMode::NeedsPathext
        };
        for dir in &search_dirs {
            let Ok(entries) = interp.proc_env.vfs.read_dir(&dir.to_windows_string()) else {
                continue;
            };
            for entry in entries {
                if entry.attributes.is_directory() {
                    continue;
                }
                if where_entry_matches(pat, ext_mode, &pathexts, &entry) {
                    found_any = true;
                    if !quiet {
                        let qm = if quote_out {
                            WhereQuoteMode::DoubleQuoted
                        } else {
                            WhereQuoteMode::Plain
                        };
                        let dm = if show_time_size {
                            WhereDetailMode::SizeAndTimestamp
                        } else {
                            WhereDetailMode::PathOnly
                        };
                        format_where_hit(interp, &entry, qm, dm, &mut out);
                    }
                }
            }
        }
    }

    if !out.is_empty() {
        io.write_stdout_str(&out)?;
    }
    if found_any {
        interp.record_success();
    } else {
        if !quiet {
            io.write_stderr_str(&format!(
                "INFO: Could not find files for the given pattern(s).{CRLF}"
            ))?;
        }
        interp.record_failure(ExitCode::FAILURE);
    }
    Ok(FlowControl::Continue)
}

/// Collects candidate search directories for `WHERE` (`recursive_root` tree or `.` + `%PATH%`).
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `recursive_root` - Optional `/R <dir>` root path.
///
/// # Returns
/// Vector of [`WindowsPath`] directories to inspect.
fn collect_where_dirs(interp: &Interpreter, recursive_root: Option<&str>) -> Vec<WindowsPath> {
    if let Some(root_str) = recursive_root {
        let base = interp.proc_env.vfs.resolve_path(root_str);
        return collect_dirs_recursive(interp, &base);
    }
    let mut dirs = vec![interp.proc_env.vfs.resolve_path(".")];
    if let Some(path_var) = interp.lookup_var("PATH") {
        for d in path_var.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            dirs.push(interp.proc_env.vfs.resolve_path(d));
        }
    }
    dirs
}

/// Recursively traverses subdirectories under `root`.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `root` - Starting [`WindowsPath`].
///
/// # Returns
/// Ordered directory list.
fn collect_dirs_recursive(interp: &Interpreter, root: &WindowsPath) -> Vec<WindowsPath> {
    let mut out = vec![root.clone()];
    for e in interp
        .proc_env
        .vfs
        .read_dir(&root.to_windows_string())
        .unwrap_or_default()
    {
        if e.attributes.is_directory() {
            out.extend(collect_dirs_recursive(interp, &e.full_path));
        }
    }
    out
}

/// Collects lowercase `%PATHEXT%` extensions for `WHERE`.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
///
/// # Returns
/// Vector of extensions (e.g. `".exe"`, `".bat"`).
fn collect_where_pathexts(interp: &Interpreter) -> Vec<String> {
    let raw = interp
        .lookup_var("PATHEXT")
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".to_owned());
    raw.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Whether a `WHERE` search pattern already contains a `.ext` suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatternExtensionMode {
    /// Pattern includes `.` (`foo.exe`).
    HasExtension,
    /// Pattern has no `.` and also probes `%PATHEXT%`.
    NeedsPathext,
}

/// Output quoting mode for `WHERE` (`default` vs `/F`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WhereQuoteMode {
    /// Emit plain path string.
    Plain,
    /// Wrap matched path in `"..."` (`/F`).
    DoubleQuoted,
}

/// Output metadata detail mode for `WHERE` (`default` vs `/T`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WhereDetailMode {
    /// Emit path only.
    PathOnly,
    /// Prepend file size and timestamp (`/T`).
    SizeAndTimestamp,
}

/// Filename prefix policy for `FINDSTR` output lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilePrefixMode {
    /// Emit matched line without `<file>:` prefix.
    OmitPrefix,
    /// Prefix matched line with `<file>:` when searching multiple files.
    IncludePrefix,
}

/// Tests whether `entry` matches a `WHERE` pattern directly or with a `%PATHEXT%` suffix.
///
/// # Arguments
/// * `pat` - Search pattern.
/// * `ext_mode` - [`PatternExtensionMode`] (`HasExtension` vs `NeedsPathext`).
/// * `pathexts` - Candidate `%PATHEXT%` suffixes.
/// * `entry` - Directory entry metadata.
///
/// # Returns
/// `true` if `entry` matches.
#[must_use]
fn where_entry_matches(
    pat: &str,
    ext_mode: PatternExtensionMode,
    pathexts: &[String],
    entry: &VfsMetadata,
) -> bool {
    if matches_win32_glob(
        pat,
        &entry.name,
        Some(&entry.short_name),
        CaseSensitivity::Insensitive,
    ) {
        return true;
    }
    ext_mode == PatternExtensionMode::NeedsPathext
        && pathexts.iter().any(|ext| {
            matches_win32_glob(
                &format!("{pat}{ext}"),
                &entry.name,
                Some(&entry.short_name),
                CaseSensitivity::Insensitive,
            )
        })
}

/// Formats a single `WHERE` match line into `out`.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `entry` - Matched [`VfsMetadata`].
/// * `quote_mode` - [`WhereQuoteMode`] (`Plain` vs `DoubleQuoted` for `/F`).
/// * `detail_mode` - [`WhereDetailMode`] (`PathOnly` vs `SizeAndTimestamp` for `/T`).
/// * `out` - Output accumulator buffer.
fn format_where_hit(
    interp: &Interpreter,
    entry: &VfsMetadata,
    quote_mode: WhereQuoteMode,
    detail_mode: WhereDetailMode,
    out: &mut String,
) {
    let p_str = entry.full_path.to_windows_string();
    let formatted_p = if quote_mode == WhereQuoteMode::DoubleQuoted {
        format!(r#""{p_str}""#)
    } else {
        p_str
    };
    if detail_mode == WhereDetailMode::SizeAndTimestamp {
        let ts = entry
            .modified_timestamp
            .format_with_locale(&interp.config.locale);
        write!(out, "{:>10}   {ts}   {formatted_p}{CRLF}", entry.size).unwrap_or(());
    } else {
        write!(out, "{formatted_p}{CRLF}").unwrap_or(());
    }
}

/// Built-in `FIND` utility shim (`FIND [/V] [/C] [/N] [/I] "string" [file...]`).
///
/// Propagates `decode_script_bytes` errors via `?` rather than silently treating invalid bytes as empty.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `FIND` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] if no quoted search string is given, [`CmdError::EncodingFailure`]
/// on undecodable file/stdin bytes, or [`CmdError::IoFailure`] on output error.
pub(super) fn shim_find(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut invert = false;
    let mut count_only = false;
    let mut show_line_nums = false;
    let mut ignore_case = false;
    let mut needle_opt: Option<String> = None;
    let mut files: Vec<&str> = Vec::new();

    for arg in args {
        let raw = &arg.text;
        let u = arg.unquoted();
        if raw.starts_with('/') {
            for ch in u.trim_start_matches('/').chars() {
                match ch.to_ascii_uppercase() {
                    'V' => invert = true,
                    'C' => count_only = true,
                    'N' => show_line_nums = true,
                    'I' => ignore_case = true,
                    _ => {}
                }
            }
        } else if needle_opt.is_none() && raw.starts_with('"') {
            needle_opt = Some(u.to_owned());
        } else {
            files.push(u);
        }
    }

    let Some(needle) = needle_opt else {
        return Err(CmdError::SyntaxError { span: cmd_span });
    };
    let needle_cmp = if ignore_case {
        needle.to_ascii_uppercase()
    } else {
        needle
    };

    let mut any_match = false;
    let mut out = String::new();
    let mut find_flags = FindstrFlags::default();
    if invert {
        find_flags.insert(FindstrFlags::INVERT);
    }
    if count_only {
        find_flags.insert(FindstrFlags::FILES_ONLY);
    }
    if show_line_nums {
        find_flags.insert(FindstrFlags::LINE_NUMS);
    }
    if ignore_case {
        find_flags.insert(FindstrFlags::IGNORE_CASE);
    }
    if files.is_empty() {
        let stdin_text = io.read_stdin_to_string(interp.console.codepage)?;
        let count = scan_find_text_lines(&stdin_text, &needle_cmp, find_flags, &mut out);
        any_match = count > 0;
        if count_only {
            write!(out, "{count}{CRLF}").unwrap_or(());
        }
    } else {
        for f in files {
            let Ok(bytes) = interp.proc_env.vfs.read_bytes(f) else {
                io.write_stderr_str(&format!("File not found - {f}{CRLF}"))?;
                continue;
            };
            let text = decode_script_bytes(&bytes, interp.console.codepage)?;
            let mut matched_lines = String::new();
            let count = scan_find_text_lines(&text, &needle_cmp, find_flags, &mut matched_lines);
            if count > 0 {
                any_match = true;
            }
            let hdr = f.to_ascii_uppercase();
            if count_only {
                write!(out, "{CRLF}---------- {hdr}: {count}{CRLF}").unwrap_or(());
            } else {
                write!(out, "{CRLF}---------- {hdr}{CRLF}{matched_lines}").unwrap_or(());
            }
        }
    }

    if !out.is_empty() {
        io.write_stdout_str(&out)?;
    }
    interp.record_exit_code(if any_match {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    });
    Ok(FlowControl::Continue)
}

/// Scans `text` for lines matching `needle_cmp` under `flags`, appending formatted matches to `out`.
///
/// # Arguments
/// * `text` - Decoded input text.
/// * `needle_cmp` - Pre-folded needle string.
/// * `flags` - [`FindstrFlags`] encoding `/V` (`INVERT`), `/C` (`FILES_ONLY`), `/N` (`LINE_NUMS`), and `/I` (`IGNORE_CASE`).
/// * `out` - Output string buffer.
///
/// # Returns
/// Number of matched lines.
fn scan_find_text_lines(
    text: &str,
    needle_cmp: &str,
    flags: FindstrFlags,
    out: &mut String,
) -> usize {
    let mut count = 0usize;
    let ignore_case = flags.contains(FindstrFlags::IGNORE_CASE);
    let invert = flags.contains(FindstrFlags::INVERT);
    let count_only = flags.contains(FindstrFlags::FILES_ONLY);
    let show_line_nums = flags.contains(FindstrFlags::LINE_NUMS);
    for (idx, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim_end_matches(CR_CHAR);
        let hay = if ignore_case {
            line.to_ascii_uppercase()
        } else {
            line.to_owned()
        };
        if hay.contains(needle_cmp) != invert {
            count = count.saturating_add(1);
            if !count_only {
                if show_line_nums {
                    write!(out, "[{}]{line}{CRLF}", idx.saturating_add(1)).unwrap_or(());
                } else {
                    write!(out, "{line}{CRLF}").unwrap_or(());
                }
            }
        }
    }
    count
}

/// Bitmask flags controlling `FINDSTR` matching and output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct FindstrFlags(
    /// Packed `FINDSTR` switch bitmask.
    u16,
);

impl FindstrFlags {
    /// `/B` match pattern at beginning of line.
    const BEGIN_LINE: Self = Self(1 << 0);
    /// `/E` match pattern at end of line.
    const END_LINE: Self = Self(1 << 1);
    /// `/L` force literal matching (disables regex metacharacters).
    const LITERAL: Self = Self(1 << 2);
    /// `/R` force regular expression matching.
    const REGEX: Self = Self(1 << 3);
    /// `/S` search subdirectories recursively.
    const RECURSIVE: Self = Self(1 << 4);
    /// `/I` case-insensitive search.
    const IGNORE_CASE: Self = Self(1 << 5);
    /// `/X` match entire line exactly.
    const EXACT_LINE: Self = Self(1 << 6);
    /// `/V` print only non-matching lines.
    const INVERT: Self = Self(1 << 7);
    /// `/N` print 1-based line numbers.
    const LINE_NUMS: Self = Self(1 << 8);
    /// `/M` print only filenames of matching files.
    const FILES_ONLY: Self = Self(1 << 9);

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

    /// Removes all bits in `other`.
    ///
    /// # Arguments
    /// * `other` - Flag mask to clear.
    const fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }
}

/// Single character-matching atom in a `FINDSTR /R` regular expression.
#[derive(Debug, Clone)]
enum FindstrAtom {
    /// `.` wildcard matching any character.
    Any,
    /// Single character literal.
    Literal(char),
    /// `[a-z0-9]` or `[^a-z]` bracket character class.
    Class {
        /// Inclusive character ranges `(low, high)`.
        ranges: Vec<(char, char)>,
        /// `true` when negated via `[^...]`.
        negated: bool,
    },
}

impl FindstrAtom {
    /// Tests whether `ch` satisfies this [`FindstrAtom`].
    ///
    /// # Arguments
    /// * `ch` - Input character.
    /// * `case_sensitivity` - [`CaseSensitivity`] (`Insensitive` for `/I`).
    ///
    /// # Returns
    /// `true` if `ch` matches.
    #[must_use]
    fn matches(&self, ch: char, case_sensitivity: CaseSensitivity) -> bool {
        let ignore_case = case_sensitivity == CaseSensitivity::Insensitive;
        let c = if ignore_case {
            ch.to_ascii_uppercase()
        } else {
            ch
        };
        match self {
            Self::Any => true,
            Self::Literal(lit) => {
                let target = if ignore_case {
                    lit.to_ascii_uppercase()
                } else {
                    *lit
                };
                c == target
            }
            Self::Class { ranges, negated } => {
                let hit = ranges.iter().any(|&(lo, hi)| {
                    if ignore_case {
                        let c_lo = ch.to_ascii_lowercase();
                        c_lo >= lo.to_ascii_lowercase() && c_lo <= hi.to_ascii_lowercase()
                    } else {
                        ch >= lo && ch <= hi
                    }
                });
                if *negated { !hit } else { hit }
            }
        }
    }
}

/// Compiled operation in a `FINDSTR /R` NFA/DP pipeline.
#[derive(Debug, Clone)]
enum FindstrOp {
    /// Beginning-of-word assertion (`\<`).
    WordStart,
    /// End-of-word assertion (`\>`).
    WordEnd,
    /// Single or Kleene-starred (`*`) character atom.
    Atom {
        /// Underlying character matcher.
        atom: FindstrAtom,
        /// `true` when followed by `*` (0 or more repetitions).
        zero_or_more: bool,
    },
}

/// Compiled `FINDSTR /R` regular expression.
#[derive(Debug, Clone)]
struct CompiledFindstrRegex {
    /// Leading `^` anchor.
    anchor_start: bool,
    /// Trailing `$` anchor.
    anchor_end: bool,
    /// Ordered sequence of DP operations.
    ops: Vec<FindstrOp>,
}

impl CompiledFindstrRegex {
    /// Compiles a `FINDSTR /R` pattern string into a polynomial-time [`CompiledFindstrRegex`].
    ///
    /// # Arguments
    /// * `pattern` - Raw `FINDSTR` regex pattern.
    ///
    /// # Returns
    /// Compiled [`CompiledFindstrRegex`].
    #[must_use]
    fn compile(pattern: &str) -> Self {
        let chars: Vec<char> = pattern.chars().collect();
        let mut idx = 0usize;
        let anchor_start = if chars.first() == Some(&'^') {
            idx = 1;
            true
        } else {
            false
        };

        let mut ops: Vec<FindstrOp> = Vec::new();
        let mut anchor_end = false;

        while let Some(&ch) = chars.get(idx) {
            let next_idx = idx.saturating_add(1);
            if ch == '$' && next_idx == chars.len() {
                anchor_end = true;
                break;
            }
            if ch == BS_CHAR
                && let Some(&next) = chars.get(next_idx)
            {
                idx = idx.saturating_add(2);
                match next {
                    '<' => {
                        ops.push(FindstrOp::WordStart);
                        continue;
                    }
                    '>' => {
                        ops.push(FindstrOp::WordEnd);
                        continue;
                    }
                    escaped => {
                        let star = chars.get(idx) == Some(&'*');
                        if star {
                            idx = idx.saturating_add(1);
                        }
                        ops.push(FindstrOp::Atom {
                            atom: FindstrAtom::Literal(escaped),
                            zero_or_more: star,
                        });
                        continue;
                    }
                }
            }
            if ch == '[' {
                let (class_atom, after_cls) = parse_findstr_class(&chars, next_idx);
                idx = after_cls;
                let star = chars.get(idx) == Some(&'*');
                if star {
                    idx = idx.saturating_add(1);
                }
                ops.push(FindstrOp::Atom {
                    atom: class_atom,
                    zero_or_more: star,
                });
                continue;
            }
            let atom = if ch == '.' {
                FindstrAtom::Any
            } else {
                FindstrAtom::Literal(ch)
            };
            idx = next_idx;
            let star = chars.get(idx) == Some(&'*');
            if star {
                idx = idx.saturating_add(1);
            }
            ops.push(FindstrOp::Atom {
                atom,
                zero_or_more: star,
            });
        }

        Self {
            anchor_start,
            anchor_end,
            ops,
        }
    }

    /// Evaluates this compiled regex against `line` in `O(|ops| * |line|)` time with zero backtracking.
    ///
    /// # Arguments
    /// * `line` - Candidate input line.
    /// * `flags` - Active [`FindstrFlags`].
    ///
    /// # Returns
    /// `true` if `line` matches.
    #[must_use]
    fn is_match(&self, line: &str, flags: FindstrFlags) -> bool {
        let chars: Vec<char> = line.chars().collect();
        let n = chars.len();
        let ignore_case = flags.contains(FindstrFlags::IGNORE_CASE);
        let must_start = self.anchor_start
            || flags.contains(FindstrFlags::BEGIN_LINE)
            || flags.contains(FindstrFlags::EXACT_LINE);
        let must_end = self.anchor_end
            || flags.contains(FindstrFlags::END_LINE)
            || flags.contains(FindstrFlags::EXACT_LINE);

        let mut active = if must_start {
            let mut v = vec![false; n.saturating_add(1)];
            v.iter_mut().take(1).for_each(|s| *s = true);
            v
        } else {
            vec![true; n.saturating_add(1)]
        };

        for op in &self.ops {
            let mut next = vec![false; n.saturating_add(1)];
            match op {
                FindstrOp::WordStart => {
                    for (j, slot) in next.iter_mut().enumerate() {
                        if active.get(j).copied().unwrap_or(false) && is_word_start(&chars, j) {
                            *slot = true;
                        }
                    }
                }
                FindstrOp::WordEnd => {
                    for (j, slot) in next.iter_mut().enumerate() {
                        if active.get(j).copied().unwrap_or(false) && is_word_end(&chars, j) {
                            *slot = true;
                        }
                    }
                }
                FindstrOp::Atom {
                    atom,
                    zero_or_more: false,
                } => {
                    for ((j, &ch_j), slot_next) in
                        chars.iter().enumerate().zip(next.iter_mut().skip(1))
                    {
                        if active.get(j).copied().unwrap_or(false)
                            && atom.matches(
                                ch_j,
                                if ignore_case {
                                    CaseSensitivity::Insensitive
                                } else {
                                    CaseSensitivity::Sensitive
                                },
                            )
                        {
                            *slot_next = true;
                        }
                    }
                }
                FindstrOp::Atom {
                    atom,
                    zero_or_more: true,
                } => {
                    next.clone_from(&active);
                    let mut carry = next.first().copied().unwrap_or(false);
                    for (&ch_j, slot_next) in chars.iter().zip(next.iter_mut().skip(1)) {
                        if carry
                            && atom.matches(
                                ch_j,
                                if ignore_case {
                                    CaseSensitivity::Insensitive
                                } else {
                                    CaseSensitivity::Sensitive
                                },
                            )
                        {
                            *slot_next = true;
                        }
                        carry = *slot_next;
                    }
                }
            }
            active = next;
        }

        if must_end {
            active.get(n).copied().unwrap_or(false)
        } else {
            active.into_iter().any(|b| b)
        }
    }
}

/// Parses `[...]` or `[^...]` character class ranges starting at `start_idx` (after `[`).
///
/// # Arguments
/// * `chars` - Full pattern character slice.
/// * `start_idx` - Index immediately following `[`.
///
/// # Returns
/// Pair of `(FindstrAtom, index_after_closing_bracket)`.
#[must_use]
fn parse_findstr_class(chars: &[char], start_idx: usize) -> (FindstrAtom, usize) {
    let mut i = start_idx;
    let negated = if chars.get(i) == Some(&'^') {
        i = i.saturating_add(1);
        true
    } else {
        false
    };
    let mut ranges = Vec::new();
    while let Some(&cur_ch) = chars.get(i) {
        if cur_ch == ']' && !ranges.is_empty() {
            return (FindstrAtom::Class { ranges, negated }, i.saturating_add(1));
        }
        let esc_idx = i.saturating_add(1);
        let lo = if cur_ch == BS_CHAR
            && let Some(&esc_ch) = chars.get(esc_idx)
        {
            i = esc_idx;
            esc_ch
        } else {
            cur_ch
        };
        if chars.get(i.saturating_add(1)) == Some(&'-')
            && let Some(&hi) = chars.get(i.saturating_add(2)).filter(|&&c| c != ']')
        {
            let (low_b, high_b) = if lo <= hi { (lo, hi) } else { (hi, lo) };
            ranges.push((low_b, high_b));
            i = i.saturating_add(3);
        } else {
            ranges.push((lo, lo));
            i = i.saturating_add(1);
        }
    }
    (FindstrAtom::Class { ranges, negated }, i)
}

/// Tests whether `ch` is a `FINDSTR` word character (`ASCII alphanumeric` or `'_'`).
///
/// # Arguments
/// * `ch` - Character to inspect.
///
/// # Returns
/// `true` if word character.
#[must_use]
const fn is_findstr_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// Tests whether position `pos` in `chars` is a beginning-of-word boundary (`\<`).
///
/// # Arguments
/// * `chars` - Line characters.
/// * `pos` - Cursor index `0..=chars.len()`.
///
/// # Returns
/// `true` if `pos` begins a word.
#[must_use]
fn is_word_start(chars: &[char], pos: usize) -> bool {
    let prev_is_word = pos
        .checked_sub(1)
        .and_then(|p| chars.get(p))
        .is_some_and(|&c| is_findstr_word_char(c));
    let cur_is_word = chars.get(pos).is_some_and(|&c| is_findstr_word_char(c));
    !prev_is_word && cur_is_word
}

/// Tests whether position `pos` in `chars` is an end-of-word boundary (`\>`).
///
/// # Arguments
/// * `chars` - Line characters.
/// * `pos` - Cursor index `0..=chars.len()`.
///
/// # Returns
/// `true` if `pos` ends a word.
#[must_use]
fn is_word_end(chars: &[char], pos: usize) -> bool {
    let prev_is_word = pos
        .checked_sub(1)
        .and_then(|p| chars.get(p))
        .is_some_and(|&c| is_findstr_word_char(c));
    let cur_is_word = chars.get(pos).is_some_and(|&c| is_findstr_word_char(c));
    prev_is_word && !cur_is_word
}

/// Built-in `FINDSTR` utility shim (`/B`, `/E`, `/L`, `/R`, `/S`, `/I`, `/X`, `/V`, `/N`, `/M`, `/C:str`, `/G:file`).
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `FINDSTR` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError`] on missing patterns, unreadable `/G:` pattern file, invalid encoding, or I/O error.
pub(super) fn shim_findstr(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut flags = FindstrFlags::default();
    let mut patterns: Vec<String> = Vec::new();
    let mut c_used = false;
    let mut positional: Vec<&str> = Vec::new();

    for arg in args {
        let u = arg.unquoted();
        let upper = u.to_ascii_uppercase();
        if upper.starts_with("/C:") {
            patterns.push(u.get(3..).unwrap_or("").to_owned());
            c_used = true;
        } else if upper.starts_with("/G:") {
            let pf = u.get(3..).unwrap_or("");
            let b = interp.proc_env.vfs.read_bytes(pf)?;
            let txt = decode_script_bytes(&b, interp.console.codepage)?;
            for l in txt.lines() {
                let cl = l.trim_end_matches(CR_CHAR);
                if !cl.is_empty() {
                    patterns.push(cl.to_owned());
                }
            }
        } else if u.starts_with('/') {
            apply_findstr_switch_chars(u, &mut flags);
        } else {
            positional.push(u);
        }
    }

    if patterns.is_empty() {
        let Some(&first_pos) = positional.first() else {
            return Err(CmdError::SyntaxError { span: cmd_span });
        };
        for sub_p in first_pos.split_whitespace() {
            patterns.push(sub_p.to_owned());
        }
        positional.remove(0);
    }

    let use_regex =
        flags.contains(FindstrFlags::REGEX) || (!flags.contains(FindstrFlags::LITERAL) && !c_used);
    let compiled_regexes: Vec<CompiledFindstrRegex> = if use_regex {
        patterns
            .iter()
            .map(|p| CompiledFindstrRegex::compile(p))
            .collect()
    } else {
        Vec::new()
    };

    let files = expand_findstr_targets(interp, &positional, flags, io)?;
    let multi_file = files.len() > 1 || flags.contains(FindstrFlags::RECURSIVE);
    let mut any_match = false;
    let mut out = String::new();

    let scan_spec = FindstrScanSpec {
        patterns: &patterns,
        regexes: &compiled_regexes,
        use_regex,
        flags,
    };

    if positional.is_empty() {
        let stdin_txt = io.read_stdin_to_string(interp.console.codepage)?;
        any_match = run_findstr_on_text(
            None,
            &stdin_txt,
            &scan_spec,
            FilePrefixMode::OmitPrefix,
            &mut out,
        );
    } else {
        for f_path in &files {
            let bytes = match interp.proc_env.vfs.read_bytes(f_path) {
                Ok(b) => b,
                Err(err) => {
                    io.write_stderr_str(&format!(
                        "FINDSTR: Cannot open {f_path}: {}{CRLF}",
                        err.cmd_exe_message()
                    ))?;
                    continue;
                }
            };
            let text = decode_script_bytes(&bytes, interp.console.codepage)?;
            let pm = if multi_file {
                FilePrefixMode::IncludePrefix
            } else {
                FilePrefixMode::OmitPrefix
            };
            if run_findstr_on_text(Some(f_path), &text, &scan_spec, pm, &mut out) {
                any_match = true;
            }
        }
    }

    if !out.is_empty() {
        io.write_stdout_str(&out)?;
    }
    interp.record_exit_code(if any_match {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    });
    Ok(FlowControl::Continue)
}

/// Applies bundled single-letter `FINDSTR` switches (`/R`, `/L`, `/I`, `/B`, `/E`, `/X`, `/V`, `/N`, `/M`, `/S`).
///
/// # Arguments
/// * `raw_switch` - Switch token starting with `'/'`.
/// * `flags` - Mutable [`FindstrFlags`] bitset.
fn apply_findstr_switch_chars(raw_switch: &str, flags: &mut FindstrFlags) {
    for ch in raw_switch.trim_start_matches('/').chars() {
        match ch.to_ascii_uppercase() {
            'B' => flags.insert(FindstrFlags::BEGIN_LINE),
            'E' => flags.insert(FindstrFlags::END_LINE),
            'L' => {
                flags.insert(FindstrFlags::LITERAL);
                flags.remove(FindstrFlags::REGEX);
            }
            'R' => {
                flags.insert(FindstrFlags::REGEX);
                flags.remove(FindstrFlags::LITERAL);
            }
            'S' => flags.insert(FindstrFlags::RECURSIVE),
            'I' => flags.insert(FindstrFlags::IGNORE_CASE),
            'X' => flags.insert(FindstrFlags::EXACT_LINE),
            'V' => flags.insert(FindstrFlags::INVERT),
            'N' => flags.insert(FindstrFlags::LINE_NUMS),
            'M' => flags.insert(FindstrFlags::FILES_ONLY),
            _ => {}
        }
    }
}

/// Expands `FINDSTR` file/wildcard targets across subdirectories when `/S` is active.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `positional` - Raw file/wildcard arguments.
/// * `flags` - Active [`FindstrFlags`].
/// * `io` - Mutable [`CmdIo`] stream for open failure diagnostics.
///
/// # Returns
/// Expanded list of target file paths.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] if writing to `stderr` fails.
fn expand_findstr_targets(
    interp: &Interpreter,
    positional: &[&str],
    flags: FindstrFlags,
    io: &mut dyn CmdIo,
) -> Result<Vec<String>, CmdError> {
    let mut files: Vec<String> = Vec::new();
    for &f_spec in positional {
        let resolved = interp.proc_env.vfs.resolve_path(f_spec);
        if contains_wildcards(f_spec) || flags.contains(FindstrFlags::RECURSIVE) {
            let base = resolved.parent();
            let pat = resolved.file_name().unwrap_or("*");
            let dirs = if flags.contains(FindstrFlags::RECURSIVE) {
                collect_dirs_recursive(interp, &base)
            } else {
                vec![base]
            };
            for d in dirs {
                if let Ok(entries) = interp.proc_env.vfs.read_dir(&d.to_windows_string()) {
                    for e in entries {
                        if !e.attributes.is_directory()
                            && matches_win32_glob(
                                pat,
                                &e.name,
                                Some(&e.short_name),
                                CaseSensitivity::Insensitive,
                            )
                        {
                            files.push(e.full_path.to_windows_string());
                        }
                    }
                }
            }
        } else if interp.proc_env.vfs.exists(f_spec) {
            files.push(f_spec.to_owned());
        } else {
            io.write_stderr_str(&format!("FINDSTR: Cannot open {f_spec}{CRLF}"))?;
        }
    }
    Ok(files)
}

/// Bundled pattern/flag specification passed to [`run_findstr_on_text`].
struct FindstrScanSpec<'a> {
    /// Literal pattern strings.
    patterns: &'a [String],
    /// Compiled regular expressions (when `use_regex` is `true`).
    regexes: &'a [CompiledFindstrRegex],
    /// Whether regex matching is active.
    use_regex: bool,
    /// Active [`FindstrFlags`].
    flags: FindstrFlags,
}

/// Scans `text` lines with literal or compiled `FINDSTR /R` patterns and appends formatted hits to `out`.
///
/// # Arguments
/// * `label` - Optional filename label.
/// * `text` - Decoded file/stdin content.
/// * `spec` - [`FindstrScanSpec`] describing patterns and flags.
/// * `prefix_mode` - [`FilePrefixMode`] controlling `label:` line prefixing.
/// * `out` - Output string buffer.
///
/// # Returns
/// `true` if at least one line matched.
#[must_use]
fn run_findstr_on_text(
    label: Option<&str>,
    text: &str,
    spec: &FindstrScanSpec<'_>,
    prefix_mode: FilePrefixMode,
    out: &mut String,
) -> bool {
    let multi_file = prefix_mode == FilePrefixMode::IncludePrefix;
    let mut file_matched = false;
    for (idx, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim_end_matches(CR_CHAR);
        let raw_hit = if spec.use_regex {
            spec.regexes.iter().any(|rx| rx.is_match(line, spec.flags))
        } else {
            findstr_literal_match(line, spec.patterns, spec.flags)
        };
        if raw_hit != spec.flags.contains(FindstrFlags::INVERT) {
            file_matched = true;
            if spec.flags.contains(FindstrFlags::FILES_ONLY) {
                if let Some(lbl) = label {
                    write!(out, "{lbl}{CRLF}").unwrap_or(());
                }
                return true;
            }
            if let Some(lbl) = label.filter(|_| multi_file) {
                write!(out, "{lbl}:").unwrap_or(());
            }
            if spec.flags.contains(FindstrFlags::LINE_NUMS) {
                write!(out, "{}:", idx.saturating_add(1)).unwrap_or(());
            }
            write!(out, "{line}{CRLF}").unwrap_or(());
        }
    }
    file_matched
}

/// Evaluates literal (`/L` or `/C:`) `FINDSTR` matching against `line`.
///
/// # Arguments
/// * `line` - Input line.
/// * `patterns` - Literal search patterns.
/// * `flags` - Active [`FindstrFlags`].
///
/// # Returns
/// `true` if any literal pattern matches.
#[must_use]
fn findstr_literal_match(line: &str, patterns: &[String], flags: FindstrFlags) -> bool {
    let ignore_case = flags.contains(FindstrFlags::IGNORE_CASE);
    let hay = if ignore_case {
        line.to_ascii_uppercase()
    } else {
        line.to_owned()
    };
    patterns.iter().any(|pat| {
        let p = if ignore_case {
            pat.to_ascii_uppercase()
        } else {
            pat.clone()
        };
        if flags.contains(FindstrFlags::EXACT_LINE) {
            hay == p
        } else if flags.contains(FindstrFlags::BEGIN_LINE) && flags.contains(FindstrFlags::END_LINE)
        {
            hay.starts_with(&p) && hay.ends_with(&p)
        } else if flags.contains(FindstrFlags::BEGIN_LINE) {
            hay.starts_with(&p)
        } else if flags.contains(FindstrFlags::END_LINE) {
            hay.ends_with(&p)
        } else {
            hay.contains(&p)
        }
    })
}

/// Built-in `MORE` utility shim (`MORE [/E] [/C] [/P] [/S] [/Tn] [+n] [files...]`).
///
/// Propagates `decode_script_bytes` errors via `?`.
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
/// Returns [`CmdError`] on unreadable/undecodable input or stream I/O failure.
pub(super) fn shim_more(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut squeeze_blanks = false;
    let mut tab_width = 8usize;
    let mut start_line = 0usize;
    let mut files: Vec<&str> = Vec::new();

    for arg in args {
        let u = arg.unquoted();
        let upper = u.to_ascii_uppercase();
        if upper == "/S" {
            squeeze_blanks = true;
        } else if let Some(tw) = upper.strip_prefix("/T") {
            if let Ok(n) = tw.parse::<usize>() {
                tab_width = n.max(1);
            }
        } else if let Some(plus) = u.strip_prefix('+') {
            if let Ok(n) = plus.parse::<usize>() {
                start_line = n;
            }
        } else if u.starts_with('/') {
        } else {
            files.push(u);
        }
    }

    let combined = if files.is_empty() {
        io.read_stdin_to_string(interp.console.codepage)?
    } else {
        let mut acc = String::new();
        for f in files {
            let bytes = interp.proc_env.vfs.read_bytes(f)?;
            let decoded = decode_script_bytes(&bytes, interp.console.codepage)?;
            acc.push_str(&decoded);
        }
        acc
    };

    let spaces = " ".repeat(tab_width);
    let mut prev_blank = false;
    let mut out = String::new();
    for (idx, raw_line) in combined.lines().enumerate() {
        if idx < start_line {
            continue;
        }
        let line = raw_line
            .trim_end_matches(CR_CHAR)
            .replace(crate::types::TAB_CHAR, &spaces);
        if squeeze_blanks {
            let is_blank = line.trim().is_empty();
            if is_blank && prev_blank {
                continue;
            }
            prev_blank = is_blank;
        }
        write!(out, "{line}{CRLF}").unwrap_or(());
    }
    if !out.is_empty() {
        io.write_stdout_str(&out)?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `SORT` utility shim (`SORT [/R] [/+n] [/UNIQUE] [/O output] [file]`).
///
/// Propagates `decode_script_bytes` errors via `?`.
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
/// Returns [`CmdError`] on unreadable/undecodable input, `/O` write failure, or stream I/O failure.
pub(super) fn shim_sort(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut reverse = false;
    let mut unique = false;
    let mut col_offset = 0usize;
    let mut out_file: Option<String> = None;
    let mut in_file: Option<&str> = None;

    let mut i = 0usize;
    while let Some(arg) = args.get(i) {
        let u = arg.unquoted();
        let upper = u.to_ascii_uppercase();
        if upper == "/R" || upper.starts_with("/REC") {
            if upper == "/R" {
                reverse = true;
            }
        } else if upper == "/UNIQUE" || upper == "/UNIQ" {
            unique = true;
        } else if let Some(col_s) = upper.strip_prefix("/+") {
            if let Ok(n) = col_s.parse::<usize>() {
                col_offset = n.saturating_sub(1);
            }
        } else if upper == "/O" {
            if let Some(next_f) = args.get(i.saturating_add(1)) {
                out_file = Some(next_f.unquoted().to_owned());
                i = i.saturating_add(2);
                continue;
            }
        } else if !u.starts_with('/') && in_file.is_none() {
            in_file = Some(u);
        }
        i = i.saturating_add(1);
    }

    let raw_text = match in_file {
        Some(f) => {
            let b = interp.proc_env.vfs.read_bytes(f)?;
            decode_script_bytes(&b, interp.console.codepage)?
        }
        None => io.read_stdin_to_string(interp.console.codepage)?,
    };

    let mut lines: Vec<String> = raw_text
        .lines()
        .map(|l| l.trim_end_matches(CR_CHAR).to_owned())
        .collect();
    lines.sort_by(|a, b| {
        let ka: String = a
            .chars()
            .skip(col_offset)
            .collect::<String>()
            .to_ascii_uppercase();
        let kb: String = b
            .chars()
            .skip(col_offset)
            .collect::<String>()
            .to_ascii_uppercase();
        let ord = ka.cmp(&kb);
        if reverse { ord.reverse() } else { ord }
    });
    if unique {
        lines.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    }

    let mut rendered = String::new();
    for l in lines {
        write!(rendered, "{l}{CRLF}").unwrap_or(());
    }
    if let Some(of) = out_file {
        interp.proc_env.vfs.write_bytes(&of, rendered.as_bytes())?;
    } else if !rendered.is_empty() {
        io.write_stdout_str(&rendered)?;
    }
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Built-in `FC` (File Compare) utility shim (`FC [/B] [/C] [/N] [/W] file1 file2`).
///
/// Checks `file1` and `file2` individually so missing `file2` reports `file2` rather than blaming `file1`!
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `FC` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion (`0` identical, `1` differs, `2` missing file).
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] on missing operands, [`CmdError::EncodingFailure`] in text mode,
/// or [`CmdError::IoFailure`] on output error.
pub(super) fn shim_fc(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut binary = false;
    let mut ignore_case = false;
    let mut compress_ws = false;
    let mut show_nums = false;
    let mut files: Vec<&str> = Vec::new();

    for arg in args {
        let u = arg.unquoted();
        match u.to_ascii_uppercase().as_str() {
            "/B" => binary = true,
            "/C" => ignore_case = true,
            "/W" => compress_ws = true,
            "/N" => show_nums = true,
            _ if u.starts_with('/') => {}
            _ => files.push(u),
        }
    }

    if files.len() < 2 {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }
    let f1 = files.first().copied().unwrap_or("");
    let f2 = files.get(1).copied().unwrap_or("");

    let Ok(b1) = interp.proc_env.vfs.read_bytes(f1) else {
        io.write_stderr_str(&format!(
            "FC: cannot open {f1} - No such file or directory{CRLF}"
        ))?;
        interp.record_failure(ExitCode::new(2));
        return Ok(FlowControl::Continue);
    };
    let Ok(b2) = interp.proc_env.vfs.read_bytes(f2) else {
        io.write_stderr_str(&format!(
            "FC: cannot open {f2} - No such file or directory{CRLF}"
        ))?;
        interp.record_failure(ExitCode::new(2));
        return Ok(FlowControl::Continue);
    };

    io.write_stdout_str(&format!("Comparing files {f1} and {f2}{CRLF}"))?;
    if binary {
        return fc_compare_binary(interp, &b1, &b2, io);
    }

    let s1 = decode_script_bytes(&b1, interp.console.codepage)?;
    let s2 = decode_script_bytes(&b2, interp.console.codepage)?;
    let norm = |s: &str| -> Vec<String> {
        s.lines()
            .map(|l| {
                let mut t = l.trim_end_matches(CR_CHAR).to_owned();
                if compress_ws {
                    t = t.split_whitespace().collect::<Vec<_>>().join(" ");
                }
                if ignore_case {
                    t = t.to_ascii_uppercase();
                }
                t
            })
            .collect()
    };
    let l1 = norm(&s1);
    let l2 = norm(&s2);
    if l1 == l2 {
        io.write_stdout_str(&format!("FC: no differences encountered{CRLF}"))?;
        interp.record_success();
    } else {
        let mut diff_out = format!("***** {f1}{CRLF}");
        for (i, line) in s1.lines().enumerate() {
            if show_nums {
                write!(diff_out, "{:>5}:  ", i.saturating_add(1)).unwrap_or(());
            }
            write!(diff_out, "{}{CRLF}", line.trim_end_matches(CR_CHAR)).unwrap_or(());
        }
        write!(diff_out, "***** {f2}{CRLF}").unwrap_or(());
        for (i, line) in s2.lines().enumerate() {
            if show_nums {
                write!(diff_out, "{:>5}:  ", i.saturating_add(1)).unwrap_or(());
            }
            write!(diff_out, "{}{CRLF}", line.trim_end_matches(CR_CHAR)).unwrap_or(());
        }
        write!(diff_out, "*****{CRLF}").unwrap_or(());
        io.write_stdout_str(&diff_out)?;
        interp.record_failure(ExitCode::FAILURE);
    }
    Ok(FlowControl::Continue)
}

/// Performs byte-by-byte `FC /B` comparison.
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `b1` - First file bytes.
/// * `b2` - Second file bytes.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::IoFailure`] on output error.
fn fc_compare_binary(
    interp: &mut Interpreter,
    b1: &[u8],
    b2: &[u8],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    if b1 == b2 {
        io.write_stdout_str(&format!("FC: no differences encountered{CRLF}"))?;
        interp.record_success();
    } else {
        let mut out = String::new();
        let max_len = b1.len().max(b2.len());
        for idx in 0..max_len {
            let v1 = b1.get(idx).copied();
            let v2 = b2.get(idx).copied();
            if v1 != v2 {
                write!(
                    out,
                    "{idx:08X}: {:02X} {:02X}{CRLF}",
                    v1.unwrap_or(0),
                    v2.unwrap_or(0)
                )
                .unwrap_or(());
            }
        }
        io.write_stdout_str(&out)?;
        interp.record_failure(ExitCode::FAILURE);
    }
    Ok(FlowControl::Continue)
}

/// Built-in `COMP` utility shim (`COMP [data1] [data2] [/D] [/A] [/L] [/N=number] [/C]`).
///
/// Opens `data1` and `data2` individually via `?` so missing `data2` accurately reports `data2`!
///
/// # Arguments
/// * `interp` - Mutable [`Interpreter`] session.
/// * `args` - Parsed argument words.
/// * `cmd_span` - Source [`Span`] of the `COMP` command.
/// * `io` - Mutable [`CmdIo`] stream.
///
/// # Returns
/// `Ok(FlowControl::Continue)` on completion.
///
/// # Errors
/// Returns [`CmdError::SyntaxError`] on missing operands or VFS/output [`CmdError`]s blaming the exact failing file.
pub(super) fn shim_comp(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    cmd_span: Span,
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut ignore_case = false;
    let mut files: Vec<&str> = Vec::new();
    for arg in args {
        let u = arg.unquoted();
        if u.eq_ignore_ascii_case("/C") {
            ignore_case = true;
        } else if !u.starts_with('/') {
            files.push(u);
        }
    }
    if files.len() < 2 {
        return Err(CmdError::SyntaxError { span: cmd_span });
    }
    let f1 = files.first().copied().unwrap_or("");
    let f2 = files.get(1).copied().unwrap_or("");

    let b1 = interp.proc_env.vfs.read_bytes(f1)?;
    let b2 = interp.proc_env.vfs.read_bytes(f2)?;

    io.write_stdout_str(&format!("Comparing {f1} and {f2}...{CRLF}"))?;
    if b1.len() != b2.len() {
        io.write_stdout_str(&format!("Files are different sizes.{CRLF}"))?;
        interp.record_failure(ExitCode::FAILURE);
        return Ok(FlowControl::Continue);
    }
    let equal = if ignore_case {
        b1.eq_ignore_ascii_case(&b2)
    } else {
        b1 == b2
    };
    if equal {
        io.write_stdout_str(&format!("Files compare OK{CRLF}"))?;
        interp.record_success();
    } else {
        io.write_stdout_str(&format!("Compare error at OFFSET 0{CRLF}"))?;
        interp.record_failure(ExitCode::FAILURE);
    }
    Ok(FlowControl::Continue)
}

/// Built-in `TREE` utility shim (`TREE [drive:][path] [/F] [/A]`).
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
/// Returns [`CmdError`] if target directory cannot be read or writing to `io` fails.
pub(super) fn shim_tree(
    interp: &mut Interpreter,
    args: &[SpannedWord],
    io: &mut dyn CmdIo,
) -> Result<FlowControl, CmdError> {
    let mut tree_scope = crate::types::TreeScope::DirectoriesOnly;
    let mut tree_charset = crate::types::TreeCharset::UnicodeBoxDrawing;
    let mut root_arg: Option<&str> = None;

    for arg in args {
        let u = arg.unquoted();
        match u.to_ascii_uppercase().as_str() {
            "/F" => tree_scope = crate::types::TreeScope::IncludeFiles,
            "/A" => tree_charset = crate::types::TreeCharset::Ascii7Bit,
            _ if u.starts_with('/') => {}
            _ => root_arg = Some(u),
        }
    }

    let root = interp.proc_env.vfs.resolve_path(root_arg.unwrap_or("."));
    let root_str = root.to_windows_string();
    let entries = interp.proc_env.vfs.read_dir(&root_str)?;

    let mut out = format!("Folder PATH listing{CRLF}{root_str}{CRLF}");
    render_tree_recursive(interp, &entries, "", tree_scope, tree_charset, &mut out);
    io.write_stdout_str(&out)?;
    interp.record_success();
    Ok(FlowControl::Continue)
}

/// Recursively renders directory/file branches for `TREE`.
///
/// # Arguments
/// * `interp` - Immutable [`Interpreter`] session.
/// * `entries` - Directory entries at the current level.
/// * `prefix` - Indentation prefix string.
/// * `tree_scope` - [`crate::types::TreeScope`] (`DirectoriesOnly` vs `IncludeFiles` for `/F`).
/// * `tree_charset` - [`crate::types::TreeCharset`] (`UnicodeBoxDrawing` vs `Ascii7Bit` for `/A`).
/// * `out` - Output buffer.
fn render_tree_recursive(
    interp: &Interpreter,
    entries: &[VfsMetadata],
    prefix: &str,
    tree_scope: crate::types::TreeScope,
    tree_charset: crate::types::TreeCharset,
    out: &mut String,
) {
    let ascii_art = tree_charset == crate::types::TreeCharset::Ascii7Bit;
    let branch = if ascii_art { "+---" } else { "├───" };
    let child_pref = if ascii_art { "|   " } else { "│   " };
    for entry in entries {
        if entry.attributes.is_directory() {
            write!(out, "{prefix}{branch}{}{CRLF}", entry.name).unwrap_or(());
            let sub_entries = interp
                .proc_env
                .vfs
                .read_dir(&entry.full_path.to_windows_string())
                .unwrap_or_default();
            let next_pref = format!("{prefix}{child_pref}");
            render_tree_recursive(
                interp,
                &sub_entries,
                &next_pref,
                tree_scope,
                tree_charset,
                out,
            );
        } else if tree_scope == crate::types::TreeScope::IncludeFiles {
            write!(out, "{prefix}{child_pref}{}{CRLF}", entry.name).unwrap_or(());
        }
    }
}
