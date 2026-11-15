//! Win32 wildcard and glob matching engine (`FsRtlIsNameInExpression`).
//!
//! Unlike POSIX globbing, Win32 / `cmd.exe` wildcard matching follows specific legacy DOS
//! rules (`DOS_STAR`, `DOS_QM`, `DOS_DOT`):
//! - `*.*` matches ALL files, even files that do NOT contain a dot!
//! - `*.` matches ONLY files that do NOT have an extension!
//! - `?` matches any single character, OR matches zero characters when immediately before
//!   a `.` or at the end of the filename (e.g., `foo??.txt` matches `foo.txt`, `fooa.txt`, and `fooab.txt`).
//!
//! Implemented via iterative dynamic-programming state transitions (`O(|pattern| * |name|)` time,
//! `O(|name|)` space) to guarantee zero exponential backtracking on pathological wildcard chains.

use crate::types::{CaseSensitivity, fold_win32_char};

/// Translated NT `FsRtlIsNameInExpression` wildcard operator token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Win32GlobOp {
    /// Exact literal character match.
    Literal(char),
    /// Standard `*` matching zero or more arbitrary characters.
    Star,
    /// `DOS_STAR` (`<` in NT, emitted for `*` immediately before `.`): matches zero or more
    /// characters up to (and not crossing) the final `.` in the candidate filename.
    DosStar,
    /// `DOS_QM` (`>` in NT, emitted for `?`): matches either 1 non-`.` character, OR 0 characters
    /// when immediately before `.` or at the end of the candidate filename.
    DosQm,
    /// `DOS_DOT` (`"` in NT, emitted for `.` adjacent to `*`/`?`): matches either a literal `.`
    /// character, OR 0 characters at the end of the candidate filename.
    DosDot,
}

/// Checks whether `pattern` contains any Win32 wildcard characters (`*` or `?`).
///
/// # Arguments
/// * `pattern` - The path or filename pattern to inspect.
///
/// # Returns
/// `true` if `pattern` contains `'*'` or `'?'`, otherwise `false`.
#[must_use]
pub fn contains_wildcards(pattern: &str) -> bool {
    pattern.contains(['*', '?'])
}

/// Evaluates whether `file_name` matches `pattern` using authentic Win32 `FsRtlIsNameInExpression`
/// / `FindFirstFile` wildcard rules (`DOS_STAR`, `DOS_QM`, `DOS_DOT`, and `STAR`).
///
/// Also supports optional matching against a file's 8.3 short name (`short_name`).
///
/// # Arguments
/// * `pattern` - The wildcard pattern (e.g., `"*.*"`, `"*.txt"`, `"foo.???"`, `"foo??.bar"`).
/// * `file_name` - The candidate filename (without directory components).
/// * `short_name` - Optional 8.3 short filename (e.g., `"DOCUME~1.HTM"`) for fallback matching.
/// * `case_sensitivity` - Whether matching is case-sensitive or case-insensitive.
///
/// # Returns
/// `true` if `file_name` (or `short_name`) matches `pattern`, otherwise `false`.
#[must_use]
pub fn matches_win32_glob(
    pattern: &str,
    file_name: &str,
    short_name: Option<&str>,
    case_sensitivity: CaseSensitivity,
) -> bool {
    let ops = compile_win32_pattern(pattern, case_sensitivity);
    if match_ops_dp(&ops, &collect_chars(file_name, case_sensitivity)) {
        return true;
    }
    if let Some(short) = short_name
        && !short.is_empty()
    {
        return match_ops_dp(&ops, &collect_chars(short, case_sensitivity));
    }
    false
}

/// Translates a Win32 `FindFirstFile` wildcard string into NT `FsRtlIsNameInExpression` operators.
///
/// Following `[MS-FSA]` 2.1.4.4 / `FindFirstFileExW` translation rules:
/// - `*` immediately followed by `.` becomes [`Win32GlobOp::DosStar`]; otherwise [`Win32GlobOp::Star`].
/// - `?` becomes [`Win32GlobOp::DosQm`].
/// - `.` immediately followed by `*` or `?`, or at the end of `pattern` immediately after `*` or `?`,
///   becomes [`Win32GlobOp::DosDot`]; otherwise `Literal('.')`.
///
/// # Arguments
/// * `pattern` - User-supplied wildcard pattern.
/// * `case_sensitivity` - Case sensitivity mode.
///
/// # Returns
/// Compiled sequence of [`Win32GlobOp`]s.
fn compile_win32_pattern(pattern: &str, case_sensitivity: CaseSensitivity) -> Vec<Win32GlobOp> {
    let chars = collect_chars(pattern, case_sensitivity);
    let mut ops = Vec::with_capacity(chars.len());
    for (idx, &ch) in chars.iter().enumerate() {
        let next = chars.get(idx.saturating_add(1)).copied();
        let prev = idx.checked_sub(1).and_then(|p| chars.get(p)).copied();
        let op = match ch {
            '*' if next == Some('.') => Win32GlobOp::DosStar,
            '*' => {
                if matches!(ops.last(), Some(Win32GlobOp::Star)) {
                    continue;
                }
                Win32GlobOp::Star
            }
            '?' => Win32GlobOp::DosQm,
            '.' if matches!(next, Some('*' | '?'))
                || (next.is_none() && matches!(prev, Some('*' | '?'))) =>
            {
                Win32GlobOp::DosDot
            }
            other => Win32GlobOp::Literal(other),
        };
        ops.push(op);
    }
    ops
}

/// Converts a string into a `Vec<char>`, applying 1:1 Unicode case-folding when `CaseSensitivity::Insensitive`.
///
/// # Arguments
/// * `text` - Input slice.
/// * `case_sensitivity` - Case sensitivity mode.
///
/// # Returns
/// Vector of characters.
fn collect_chars(text: &str, case_sensitivity: CaseSensitivity) -> Vec<char> {
    match case_sensitivity {
        CaseSensitivity::Sensitive => text.chars().collect(),
        CaseSensitivity::Insensitive => text.chars().map(fold_win32_char).collect(),
    }
}

/// Iterative `O(|ops| * |name|)` dynamic-programming evaluator for [`Win32GlobOp`].
///
/// `dp[ni]` records whether the processed prefix of `ops` can match `name[..ni]`.
///
/// # Arguments
/// * `ops` - Compiled [`Win32GlobOp`] slice.
/// * `name` - Folded candidate filename character slice.
///
/// # Returns
/// `true` if `ops` matches the entirety of `name`.
fn match_ops_dp(ops: &[Win32GlobOp], name: &[char]) -> bool {
    let n = name.len();
    let last_dot_limit = name.iter().rposition(|&c| c == '.').unwrap_or(n);
    let mut dp: Vec<bool> = (0..=n).map(|i| i == 0).collect();

    for &op in ops {
        match op {
            Win32GlobOp::Star => {
                let mut seen_true = false;
                for state in &mut dp {
                    if *state {
                        seen_true = true;
                    } else {
                        *state = seen_true;
                    }
                }
            }
            Win32GlobOp::DosStar => {
                // `DOS_STAR` can stay at any current `i` (0 chars) OR advance through `0..last_dot_limit`
                // without consuming `name[last_dot_limit]`.
                let mut carry = false;
                for (i, state) in dp.iter_mut().enumerate() {
                    let prev_true = *state;
                    if carry {
                        *state = true;
                    }
                    carry = i < last_dot_limit && (prev_true || carry);
                }
            }
            Win32GlobOp::DosQm => {
                dp = (0..=n)
                    .map(|i| {
                        let zero_match = dp.get(i).copied().unwrap_or(false)
                            && matches!(name.get(i), None | Some('.'));
                        let one_match = i > 0
                            && dp.get(i.saturating_sub(1)).copied().unwrap_or(false)
                            && name.get(i.saturating_sub(1)).is_some_and(|&nc| nc != '.');
                        zero_match || one_match
                    })
                    .collect();
            }
            Win32GlobOp::DosDot => {
                dp = (0..=n)
                    .map(|i| {
                        let zero_at_end = i == n && dp.get(n).copied().unwrap_or(false);
                        let dot_char = i > 0
                            && dp.get(i.saturating_sub(1)).copied().unwrap_or(false)
                            && name.get(i.saturating_sub(1)) == Some(&'.');
                        zero_at_end || dot_char
                    })
                    .collect();
            }
            Win32GlobOp::Literal(pc) => {
                dp = (0..=n)
                    .map(|i| {
                        i > 0
                            && dp.get(i.saturating_sub(1)).copied().unwrap_or(false)
                            && name.get(i.saturating_sub(1)) == Some(&pc)
                    })
                    .collect();
            }
        }
    }

    dp.get(n).copied().unwrap_or(false)
}

#[cfg(test)]
/// Unit tests for polynomial-time `FsRtlIsNameInExpression` Win32 wildcard matching.
mod tests {
    use std::time::Instant;

    use super::*;

    /// Verifies wildcard character detection (`*` and `?`).
    #[test]
    fn test_contains_wildcards() {
        assert!(contains_wildcards("*.txt"));
        assert!(contains_wildcards("file?.bat"));
        assert!(!contains_wildcards("plain.cmd"));
    }

    /// Verifies Win32 glob wildcard semantics for `*.*`, `*.`, `foo.*`, and `?` patterns.
    #[test]
    fn test_win32_glob_wildcard_and_dot_semantics() {
        assert!(matches_win32_glob(
            "*.*",
            "README",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "*",
            "README",
            None,
            CaseSensitivity::Insensitive
        ));

        assert!(matches_win32_glob(
            "*.",
            "MAKEFILE",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(!matches_win32_glob(
            "*.",
            "script.bat",
            None,
            CaseSensitivity::Insensitive
        ));

        assert!(matches_win32_glob(
            "foo.*",
            "foo",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "foo.*",
            "FOO.TXT",
            None,
            CaseSensitivity::Insensitive
        ));

        assert!(matches_win32_glob(
            "foo??.txt",
            "foo.txt",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "foo??.txt",
            "fooa.txt",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "foo??.txt",
            "fooab.txt",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(!matches_win32_glob(
            "foo??.txt",
            "fooabc.txt",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "bar?",
            "bar",
            None,
            CaseSensitivity::Insensitive
        ));
    }

    /// Verifies `DOS_DOT` (`foo.???`), `DOS_QM` (`*?.txt`, `a??.txt`), `DOS_STAR` (`*.txt` on multi-dot names),
    /// and 1:1 Unicode case-folding (`ü*.txt` -> `ÜBUNG.TXT`).
    #[test]
    fn test_win32_glob_dos_dot_qm_star_and_unicode() {
        assert!(matches_win32_glob(
            "foo.???",
            "foo",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "foo.?",
            "foo",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "foo.???",
            "foo.ab",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(!matches_win32_glob(
            "foo.???",
            "foo.abcd",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "*?.txt",
            "a.txt",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "a??.txt",
            "a.txt",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "*.txt",
            "archive.tar.txt",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "ü*.txt",
            "ÜBUNG.TXT",
            None,
            CaseSensitivity::Insensitive
        ));
    }

    /// Verifies short-name (8.3) matching, case sensitivity, and polynomial worst-case time bound.
    #[test]
    fn test_win32_glob_short_names_case_and_polynomial_bound() {
        assert!(matches_win32_glob(
            "**.htm",
            "index.html",
            Some("INDEX~1.HTM"),
            CaseSensitivity::Insensitive
        ));
        assert!(!matches_win32_glob(
            "**.htm",
            "index.html",
            Some("INDEX~1.TXT"),
            CaseSensitivity::Insensitive
        ));
        assert!(!matches_win32_glob(
            "Foo.txt",
            "foo.txt",
            None,
            CaseSensitivity::Sensitive
        ));
        assert!(!matches_win32_glob(
            "foo?.txt",
            "foo.bar",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(!matches_win32_glob(
            "a.b.",
            "a.b",
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(!matches_win32_glob(
            "foobar",
            "foo",
            Some(""),
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "foo**bar",
            "foobar",
            None,
            CaseSensitivity::Insensitive
        ));

        // Adversarial 32-wildcard pattern against 255-char filename must complete instantaneously
        let adversarial_pat = format!("{}z", "*a?".repeat(16));
        let adversarial_name = "a".repeat(255);
        let start = Instant::now();
        assert!(!matches_win32_glob(
            &adversarial_pat,
            &adversarial_name,
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(start.elapsed().as_millis() < 50);
    }
}
