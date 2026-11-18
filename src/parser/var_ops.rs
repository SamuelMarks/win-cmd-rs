//! Environment variable substring (`%VAR:~start,len%`) and replacement (`%VAR:old=new%`) operations.
//!
//! Shared between Phase 1 (`%VAR:...%`) and Phase 4 (`!VAR:...!`) variable expansion passes.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Evaluates a variable operation expression (`VAR`, `VAR:~offset,length`, `VAR:old=new`, `VAR:*old=new`).
///
/// # Arguments
/// * `expr` - The text inside `%...%` or `!...!` (e.g., `"PATH:~0,5"` or `"FOO:bar=baz"`).
/// * `lookup` - Closure that looks up an environment variable name (case-insensitively) and returns its value.
///
/// # Returns
/// `Some((var_name, expanded_value))` if the base variable exists in `lookup`, or `None` if undefined.
#[must_use]
pub fn evaluate_var_expression<F>(expr: &str, lookup: F) -> Option<(String, String)>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(colon_idx) = expr.find(':') {
        // Hidden per-drive variables like `%=C:%` start with `=` and end with `:`
        if expr.starts_with('=') && colon_idx == expr.len().saturating_sub(1) {
            let val = lookup(expr)?;
            return Some((expr.to_owned(), val));
        }

        let var_name = expr.get(..colon_idx).unwrap_or("");
        if var_name.is_empty() {
            return None;
        }
        let op_spec = expr.get(colon_idx.saturating_add(1)..).unwrap_or("");

        if let Some(tilde_spec) = op_spec.strip_prefix('~') {
            let base_val = lookup(var_name)?;
            if let Some(sliced) = apply_substring(&base_val, tilde_spec) {
                return Some((var_name.to_owned(), sliced));
            }
            return lookup(expr).map(|val| (expr.to_owned(), val));
        }

        if let Some(eq_idx) = op_spec.find('=') {
            let base_val = lookup(var_name)?;
            let search_raw = op_spec.get(..eq_idx).unwrap_or("");
            let replace_with = op_spec.get(eq_idx.saturating_add(1)..).unwrap_or("");
            let replaced = apply_replacement(&base_val, search_raw, replace_with);
            return Some((var_name.to_owned(), replaced));
        }

        lookup(expr).map(|val| (expr.to_owned(), val))
    } else {
        let val = lookup(expr)?;
        Some((expr.to_owned(), val))
    }
}

/// Applies `cmd.exe` substring slicing (`~offset` or `~offset,length`) to `value`.
///
/// Supports positive and negative offsets and lengths, as well as decimal, hex (`0x`), and octal (`0`) numbers,
/// returning `None` if `spec` is empty or contains non-numeric `offset` / `length` tokens.
///
/// # Arguments
/// * `value` - The variable's string value.
/// * `spec` - The specification after `:~` (e.g., `"0,5"`, `"-3"`, `"2,-1"`).
///
/// # Returns
/// `Some(String)` containing the sliced substring when valid, or `None` if malformed.
#[must_use]
pub fn apply_substring(value: &str, spec: &str) -> Option<String> {
    if spec.trim().is_empty() {
        return None;
    }
    let chars: Vec<char> = value.chars().collect();
    let total = i64::try_from(chars.len()).unwrap_or(0);

    let (offset_str, len_opt) = spec.split_once(',').map_or_else(
        || (spec.trim(), None),
        |(off, len)| (off.trim(), Some(len.trim())),
    );

    let offset = parse_cmd_int(offset_str)?;
    let start_idx = if offset < 0 {
        total.saturating_add(offset).max(0)
    } else {
        offset.min(total)
    };

    let end_idx = match len_opt {
        None => total,
        Some(len_str) => {
            let len_val = parse_cmd_int(len_str)?;
            if len_val < 0 {
                total.saturating_add(len_val).max(0)
            } else {
                start_idx.saturating_add(len_val).min(total)
            }
        }
    };

    if end_idx <= start_idx {
        return Some(String::new());
    }

    let u_start = usize::try_from(start_idx).unwrap_or(0);
    let u_end = usize::try_from(end_idx).unwrap_or(0);
    Some(chars.get(u_start..u_end).into_iter().flatten().collect())
}

/// Applies `cmd.exe` case-insensitive substring replacement (`old=new` or `*old=new`).
///
/// Uses character-indexed matching so both ASCII and multi-byte UTF-8 codepoints never slice
/// across non-character boundaries.
///
/// # Arguments
/// * `value` - The variable's string value.
/// * `search_raw` - Search pattern (if prefixed with `*`, replaces everything from index 0 through first match).
/// * `replace_with` - Replacement string.
///
/// # Returns
/// The modified string.
#[must_use]
pub fn apply_replacement(value: &str, search_raw: &str, replace_with: &str) -> String {
    if search_raw.is_empty() {
        return value.to_owned();
    }

    let val_chars: Vec<char> = value.chars().collect();
    if let Some(asterisk_target) = search_raw.strip_prefix('*') {
        if asterisk_target.is_empty() {
            return replace_with.to_owned();
        }
        let pat_chars: Vec<char> = asterisk_target.chars().collect();
        return find_case_insensitive_chars(&val_chars, &pat_chars, 0).map_or_else(
            || value.to_owned(),
            |pos| {
                let match_end = pos.saturating_add(pat_chars.len());
                let tail: String = val_chars.get(match_end..).into_iter().flatten().collect();
                format!("{replace_with}{tail}")
            },
        );
    }

    let pat_chars: Vec<char> = search_raw.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut cursor = 0usize;

    while let Some(match_start) = find_case_insensitive_chars(&val_chars, &pat_chars, cursor) {
        out.extend(
            val_chars
                .get(cursor..match_start)
                .unwrap_or(&[])
                .iter()
                .copied(),
        );
        out.push_str(replace_with);
        cursor = match_start.saturating_add(pat_chars.len());
    }
    out.extend(val_chars.get(cursor..).unwrap_or(&[]).iter().copied());
    out
}

/// Searches `haystack[from..]` for `needle` comparing characters case-insensitively (including Latin-1/Unicode lowercase).
///
/// # Arguments
/// * `haystack` - Source character slice.
/// * `needle` - Non-empty pattern character slice.
/// * `from` - Starting character index in `haystack`.
///
/// # Returns
/// `Some(char_index)` of the first match at or after `from`, or `None`.
fn find_case_insensitive_chars(haystack: &[char], needle: &[char], from: usize) -> Option<usize> {
    let n_len = needle.len();
    if haystack.len().saturating_sub(from) < n_len {
        return None;
    }
    let last_start = haystack.len().saturating_sub(n_len);
    (from..=last_start).find(|&start| {
        let window = haystack
            .get(start..start.saturating_add(n_len))
            .unwrap_or(&[]);
        window
            .iter()
            .zip(needle.iter())
            .all(|(&a, &b)| chars_eq_case_insensitive(a, b))
    })
}

/// Compares two Unicode characters case-insensitively across both ASCII and non-ASCII BMP characters.
///
/// # Arguments
/// * `a` - First character.
/// * `b` - Second character.
///
/// # Returns
/// `true` if `a` and `b` fold to the same lowercase sequence.
fn chars_eq_case_insensitive(a: char, b: char) -> bool {
    crate::types::fold_win32_char(a) == crate::types::fold_win32_char(b)
}

/// Parses a `cmd.exe` signed integer literal (decimal, `0x` hex, or leading-`0` octal).
///
/// # Arguments
/// * `raw` - Integer literal slice.
///
/// # Returns
/// `Some(i64)` if valid, else `None`.
#[must_use]
pub fn parse_cmd_int(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (sign, digits) = match (trimmed.strip_prefix('-'), trimmed.strip_prefix('+')) {
        (Some(rest), _) => (-1i64, rest.trim()),
        (None, Some(rest)) => (1i64, rest.trim()),
        (None, None) => (1i64, trimmed),
    };

    let unsigned = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()?
    } else if digits.len() > 1 && digits.starts_with('0') {
        i64::from_str_radix(digits, 8).ok()?
    } else {
        digits.parse::<i64>().ok()?
    };

    Some(unsigned.wrapping_mul(sign))
}

#[cfg(test)]
/// Unit tests for `%VAR:~...%` slicing, `%VAR:old=new%` replacement, and integer parsing.
mod tests {
    use super::*;
    use crate::types::BS_STR as SEP;

    /// Verifies positive, negative, hex, and octal substring slicing operations.
    #[test]
    fn test_substring_operations() {
        assert_eq!(apply_substring("abcdef", "2"), Some("cdef".to_owned()));
        assert_eq!(apply_substring("abcdef", "1,3"), Some("bcd".to_owned()));
        assert_eq!(apply_substring("abcdef", "-3"), Some("def".to_owned()));
        assert_eq!(apply_substring("abcdef", "1,-1"), Some("bcde".to_owned()));
        assert_eq!(apply_substring("abcdef", "-2,1"), Some("e".to_owned()));
        assert_eq!(apply_substring("abcdef", "4,-4"), Some(String::new()));
        assert_eq!(apply_substring("abcdef", "0x1,02"), Some("bc".to_owned()));
        assert_eq!(apply_substring("abcdef", ""), None);
        assert_eq!(apply_substring("abcdef", "bad"), None);
        assert_eq!(apply_substring("abcdef", "1,bad"), None);
    }

    /// Verifies case-insensitive ASCII, Unicode, and wildcard-prefix substring replacements.
    #[test]
    fn test_replacement_operations_ascii_and_unicode() {
        assert_eq!(
            apply_replacement("Hello World", "WORLD", "Rust"),
            "Hello Rust"
        );
        // Non-ASCII Latin-1 / OEM case-insensitive replacement (e.g. `ä` vs `Ä`)
        assert_eq!(
            apply_replacement("Gr\u{00FC}\u{00DF}e \u{00E4}ndern", "\u{00C4}NDERN", "ok"),
            "Gr\u{00FC}\u{00DF}e ok"
        );
        assert_eq!(apply_replacement("a-b-c", "-", ""), "abc");
        assert_eq!(apply_replacement("abc", "", "x"), "abc");
        assert_eq!(apply_replacement("ab", "abcd", "x"), "ab");
        let path_val = format!("C:{SEP}dir{SEP}sub{SEP}file.txt");
        let search_sub = format!("*{SEP}sub{SEP}");
        assert_eq!(apply_replacement(&path_val, &search_sub, ""), "file.txt");
        assert_eq!(apply_replacement("abc", "*", "Z"), "Z");
        assert_eq!(apply_replacement("abc", "*nomatch", "Z"), "abc");
    }

    /// Verifies end-to-end variable expression evaluation including hidden drive variables.
    #[test]
    fn test_evaluate_var_expression() {
        let c_users = format!("C:{SEP}Users");
        let lookup = |k: &str| match k.to_ascii_uppercase().as_str() {
            "FOO" => Some("bar_baz".to_owned()),
            "FOO:~LITERAL_KEY" => Some("tilde_literal_val".to_owned()),
            "LITERAL:COLON" => Some("exact_colon_val".to_owned()),
            "=C:" => Some(c_users.clone()),
            _ => None,
        };

        assert_eq!(
            evaluate_var_expression("FOO", lookup),
            Some(("FOO".to_owned(), "bar_baz".to_owned()))
        );
        assert_eq!(
            evaluate_var_expression("FOO:~literal_key", lookup),
            Some((
                "FOO:~literal_key".to_owned(),
                "tilde_literal_val".to_owned()
            ))
        );
        assert_eq!(
            evaluate_var_expression("FOO:~0,3", lookup),
            Some(("FOO".to_owned(), "bar".to_owned()))
        );
        assert_eq!(
            evaluate_var_expression("FOO:bar=qux", lookup),
            Some(("FOO".to_owned(), "qux_baz".to_owned()))
        );
        assert_eq!(evaluate_var_expression("FOO:unrecognized", lookup), None);
        assert_eq!(evaluate_var_expression("FOO:~bad", lookup), None);
        assert_eq!(evaluate_var_expression("FOO:~1,bad", lookup), None);
        assert_eq!(
            evaluate_var_expression("LITERAL:COLON", lookup),
            Some(("LITERAL:COLON".to_owned(), "exact_colon_val".to_owned()))
        );
        assert_eq!(
            evaluate_var_expression("=C:", lookup),
            Some(("=C:".to_owned(), c_users.clone()))
        );
        assert_eq!(evaluate_var_expression(":~0,1", lookup), None);
        assert_eq!(evaluate_var_expression("=C:extra", lookup), None);
        assert_eq!(evaluate_var_expression("MISSING", lookup), None);
        assert_eq!(evaluate_var_expression("MISSING:a=b", lookup), None);
        assert_eq!(evaluate_var_expression("=MISSING:", lookup), None);
        assert_eq!(parse_cmd_int("0xZZ"), None);
    }

    /// Verifies `cmd.exe` signed decimal, hexadecimal, and octal integer parsing.
    #[test]
    fn test_parse_cmd_int() {
        assert_eq!(parse_cmd_int(""), None);
        assert_eq!(parse_cmd_int("+10"), Some(10));
        assert_eq!(parse_cmd_int("-0x10"), Some(-16));
        assert_eq!(parse_cmd_int("0X10"), Some(16));
        assert_eq!(parse_cmd_int("010"), Some(8));
        assert_eq!(parse_cmd_int("08"), None);
    }
}
