//! Automated documentation coverage (`100%` file, module, type, field, variant, function,
//! `# Arguments`, `# Returns`, `# Errors`), embedded CI/linker Python script static compilation,
//! and architectural anti-pattern quality gates for `win-cmd-rs`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Recursively collects all `.rs` source files under `dir` in deterministic lexicographical order.
///
/// # Arguments
/// * `dir` - Root directory to traverse.
/// * `out` - Output accumulator of discovered `.rs` paths.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|entry| entry.path()))
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Extracts the contiguous `///` doc-comment block immediately preceding line `item_line_idx`,
/// skipping single-line and multi-line `#[...]` attribute annotations.
///
/// # Arguments
/// * `lines` - Source lines of the file.
/// * `item_line_idx` - 0-based line index of the item declaration.
///
/// # Returns
/// Joined `///` doc-comment lines preceding the item (empty if undocumented).
#[must_use]
fn extract_preceding_doc_block(lines: &[&str], item_line_idx: usize) -> String {
    let mut docs = Vec::new();
    let mut idx = item_line_idx;
    let mut bracket_depth: usize = 0;

    while idx > 0 {
        idx = idx.saturating_sub(1);
        let trimmed = lines.get(idx).copied().unwrap_or("").trim();

        if bracket_depth > 0 {
            for ch in trimmed.chars().rev() {
                if ch == ']' {
                    bracket_depth = bracket_depth.saturating_add(1);
                } else if ch == '[' {
                    bracket_depth = bracket_depth.saturating_sub(1);
                }
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("///") {
            docs.push(rest.trim_start());
            continue;
        }
        if trimmed.starts_with("#[") {
            continue;
        }
        if trimmed.ends_with(']') {
            bracket_depth = 1;
            for ch in trimmed
                .get(..trimmed.len().saturating_sub(1))
                .unwrap_or("")
                .chars()
                .rev()
            {
                if ch == ']' {
                    bracket_depth = bracket_depth.saturating_add(1);
                } else if ch == '[' {
                    bracket_depth = bracket_depth.saturating_sub(1);
                }
            }
            continue;
        }
        break;
    }

    docs.reverse();
    let nl = "\n";
    docs.join(nl)
}

/// Strips optional `pub(...)`, `const`, `unsafe`, and `extern "C"` qualifiers from the front
/// of a trimmed declaration line.
///
/// # Arguments
/// * `trimmed` - Trimmed source line.
///
/// # Returns
/// Remainder of `trimmed` after stripping leading visibility, `const`, `unsafe`, and `extern` modifiers.
#[must_use]
fn strip_vis_and_const(trimmed: &str) -> &str {
    let mut rest = trimmed;
    if let Some(after_pub) = rest.strip_prefix("pub") {
        if after_pub.starts_with('(') {
            if let Some(close_paren) = after_pub.find(')') {
                rest = after_pub
                    .get(close_paren.saturating_add(1)..)
                    .unwrap_or("")
                    .trim_start();
            }
        } else if after_pub.starts_with(' ') {
            rest = after_pub.trim_start();
        }
    }
    if let Some(after_const) = rest.strip_prefix("const ") {
        rest = after_const.trim_start();
    }
    if let Some(after_unsafe) = rest.strip_prefix("unsafe ") {
        rest = after_unsafe.trim_start();
    }
    if let Some(after_extern) = rest.strip_prefix("extern \"C\" ") {
        rest = after_extern.trim_start();
    }
    rest
}

/// Checks whether a trimmed source line begins a Rust `fn` item declaration.
///
/// # Arguments
/// * `trimmed` - Trimmed source line.
///
/// # Returns
/// `true` if `trimmed` declares a function or method.
#[must_use]
fn is_fn_item_start(trimmed: &str) -> bool {
    strip_vis_and_const(trimmed).starts_with("fn ")
}

/// Checks whether a trimmed source line begins a `mod`, `struct`, `enum`, `trait`, `type`,
/// `const`, or `static` item declaration.
///
/// # Arguments
/// * `trimmed` - Trimmed source line.
///
/// # Returns
/// `true` if `trimmed` declares a named module, type, or constant item.
#[must_use]
fn is_named_item_start(trimmed: &str) -> bool {
    let rest = strip_vis_and_const(trimmed);
    for kw in ["struct ", "enum ", "trait ", "type ", "static "] {
        if rest.starts_with(kw) {
            return true;
        }
    }
    if rest.starts_with("mod ") && !rest.ends_with(';') {
        return true;
    }
    // `const NAME:` (since `strip_vis_and_const` stripped `const `, check `NAME:` after `const `)
    let after_vis = trimmed.strip_prefix("pub").map_or(trimmed, |after_pub| {
        if after_pub.starts_with('(') {
            after_pub
                .find(')')
                .and_then(|cp| after_pub.get(cp.saturating_add(1)..))
                .unwrap_or("")
                .trim_start()
        } else {
            after_pub.trim_start()
        }
    });
    after_vis
        .strip_prefix("const ")
        .is_some_and(|after_c| !after_c.trim_start().starts_with("fn "))
}

/// Parses non-`self` parameter identifiers and optional non-unit return type from a signature.
///
/// # Arguments
/// * `sig` - Flattened function signature up to `{` or `;`.
///
/// # Returns
/// `(fn_name, param_names, return_type_opt)` extracted from `sig`.
#[must_use]
fn parse_fn_signature(sig: &str) -> (String, Vec<String>, Option<String>) {
    let Some(fn_pos) = sig.find("fn ") else {
        return (String::new(), Vec::new(), None);
    };
    let after_fn = sig
        .get(fn_pos.saturating_add(3)..)
        .unwrap_or("")
        .trim_start();
    let name_len = after_fn
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .count();
    let fn_name = after_fn.get(..name_len).unwrap_or("").to_owned();
    let mut cursor = after_fn.get(name_len..).unwrap_or("").trim_start();

    if cursor.starts_with('<') {
        let mut depth: usize = 0;
        let mut end_gen = 0;
        for (i, ch) in cursor.char_indices() {
            if ch == '<' {
                depth = depth.saturating_add(1);
            } else if ch == '>' {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end_gen = i.saturating_add(1);
                    break;
                }
            }
        }
        cursor = cursor.get(end_gen..).unwrap_or("").trim_start();
    }

    if !cursor.starts_with('(') {
        return (fn_name, Vec::new(), None);
    }

    let mut p_depth: usize = 0;
    let mut close_paren = 0;
    for (i, ch) in cursor.char_indices() {
        if ch == '(' {
            p_depth = p_depth.saturating_add(1);
        } else if ch == ')' {
            p_depth = p_depth.saturating_sub(1);
            if p_depth == 0 {
                close_paren = i;
                break;
            }
        }
    }

    let params_inner = cursor.get(1..close_paren).unwrap_or("");
    let params = split_top_level_params(params_inner);

    let after_params = cursor
        .get(close_paren.saturating_add(1)..)
        .unwrap_or("")
        .trim();
    let sig_tail = after_params
        .split('{')
        .next()
        .unwrap_or("")
        .trim_end_matches(';')
        .trim();
    let ret_type = sig_tail.find("->").and_then(|arrow| {
        let raw_ret = sig_tail.get(arrow.saturating_add(2)..).unwrap_or("").trim();
        let before_where = raw_ret.split("where ").next().unwrap_or(raw_ret).trim();
        if before_where.is_empty() || before_where == "()" {
            None
        } else {
            Some(before_where.to_owned())
        }
    });

    (fn_name, params, ret_type)
}

/// Splits a comma-separated parameter list at nesting depth 0 and returns non-`self` identifiers.
///
/// # Arguments
/// * `params_inner` - Substring inside `fn foo(...)`.
///
/// # Returns
/// Ordered list of non-`self` parameter names.
#[must_use]
fn split_top_level_params(params_inner: &str) -> Vec<String> {
    let mut raw_parts = Vec::new();
    let mut depth: usize = 0;
    let mut start = 0;

    for (i, ch) in params_inner.char_indices() {
        match ch {
            '(' | '<' | '[' => depth = depth.saturating_add(1),
            ')' | '>' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                raw_parts.push(params_inner.get(start..i).unwrap_or("").trim());
                start = i.saturating_add(1);
            }
            _ => {}
        }
    }
    let tail = params_inner.get(start..).unwrap_or("").trim();
    if !tail.is_empty() {
        raw_parts.push(tail);
    }

    let mut names = Vec::new();
    for part in raw_parts {
        let cleaned = part.trim();
        if cleaned == "self"
            || cleaned == "&self"
            || cleaned == "&mut self"
            || cleaned == "mut self"
            || (cleaned.starts_with("&'") && cleaned.ends_with("self"))
        {
            continue;
        }
        if let Some(colon_pos) = cleaned.find(':') {
            let pat = cleaned.get(..colon_pos).unwrap_or("").trim();
            let ident = pat.strip_prefix("mut ").unwrap_or(pat).trim();
            if !ident.is_empty() && ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                names.push(ident.to_owned());
            }
        }
    }
    names
}

/// Kind of body delimiter discovered on a `struct` or `enum` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeBodyDelimiter {
    /// Braced `{ ... }` struct or enum body.
    Brace,
    /// Tuple `(...)` struct body.
    TupleParen,
    /// Unit `;` struct or EOF without body.
    UnitOrNone,
}

/// Scans forward from `start_idx` to find the opening `{`, `(`, or `;` of a `struct` or `enum`.
///
/// # Arguments
/// * `lines` - Source lines of the file.
/// * `start_idx` - Declaration start line index.
/// * `is_struct` - Whether the declaration is a `struct` (enabling tuple `(` detection).
///
/// # Returns
/// `(header_idx, delimiter)` locating the body delimiter line and kind.
#[must_use]
fn find_type_header_open(
    lines: &[&str],
    start_idx: usize,
    is_struct: bool,
) -> (usize, TypeBodyDelimiter) {
    let mut header_idx = start_idx;
    while header_idx < lines.len() {
        let hl = lines.get(header_idx).copied().unwrap_or("").trim();
        let hl_decl = if header_idx == start_idx {
            strip_vis_and_const(hl)
        } else {
            hl
        };
        if hl_decl.contains('{') {
            return (header_idx, TypeBodyDelimiter::Brace);
        }
        if is_struct && header_idx == start_idx && hl_decl.contains('(') {
            return (header_idx, TypeBodyDelimiter::TupleParen);
        }
        if hl_decl.ends_with(';') {
            return (header_idx, TypeBodyDelimiter::UnitOrNone);
        }
        header_idx = header_idx.saturating_add(1);
    }
    (header_idx, TypeBodyDelimiter::UnitOrNone)
}

/// Audits braced `struct` fields and `enum` variants in `lines` to ensure every field and variant
/// has a preceding `///` docstring.
///
/// # Arguments
/// * `path` - File path for failure diagnostics.
/// * `lines` - Source lines of the file.
/// * `failures` - Accumulator of documentation violation messages.
fn audit_fields_and_variants(path: &Path, lines: &[&str], failures: &mut Vec<String>) {
    let mut idx = 0;
    while idx < lines.len() {
        let trimmed = lines.get(idx).copied().unwrap_or("").trim();
        let rest = strip_vis_and_const(trimmed);
        let is_struct = rest.starts_with("struct ");
        let is_enum = rest.starts_with("enum ");
        if !is_struct && !is_enum {
            idx = idx.saturating_add(1);
            continue;
        }

        let (header_idx, delim) = find_type_header_open(lines, idx, is_struct);
        match delim {
            TypeBodyDelimiter::TupleParen => {
                audit_tuple_struct_fields(path, lines, header_idx, &mut idx, failures);
                continue;
            }
            TypeBodyDelimiter::UnitOrNone => {
                idx = header_idx.saturating_add(1);
                continue;
            }
            TypeBodyDelimiter::Brace => {}
        }

        let mut brace_depth: usize = 0;
        for ch in lines.get(header_idx).copied().unwrap_or("").chars() {
            if ch == '{' {
                brace_depth = brace_depth.saturating_add(1);
            } else if ch == '}' {
                brace_depth = brace_depth.saturating_sub(1);
            }
        }

        let mut body_idx = header_idx.saturating_add(1);
        let mut attr_depth: usize = 0;
        while body_idx < lines.len() && brace_depth > 0 {
            let bl = lines.get(body_idx).copied().unwrap_or("").trim();
            let depth_at_line_start = brace_depth;
            let in_multiline_attr = attr_depth > 0;
            if attr_depth > 0 || bl.starts_with("#[") {
                for ch in bl.chars() {
                    if ch == '[' {
                        attr_depth = attr_depth.saturating_add(1);
                    } else if ch == ']' {
                        attr_depth = attr_depth.saturating_sub(1);
                    }
                }
            }
            if !in_multiline_attr && !bl.starts_with("#[") {
                for ch in bl.chars() {
                    if ch == '{' {
                        brace_depth = brace_depth.saturating_add(1);
                    } else if ch == '}' {
                        brace_depth = brace_depth.saturating_sub(1);
                    }
                }
            }

            if depth_at_line_start == 1
                && !in_multiline_attr
                && !bl.is_empty()
                && !bl.starts_with("//")
                && !bl.starts_with("#[")
                && !bl.starts_with('}')
            {
                let candidate = strip_vis_and_const(bl);
                let first_ok = candidate
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
                let looks_like_member = if is_struct {
                    first_ok && candidate.contains(':')
                } else {
                    first_ok
                };
                if looks_like_member && extract_preceding_doc_block(lines, body_idx).is_empty() {
                    failures.push(format!(
                        "{}:{}: struct field or enum variant `{bl}` lacks `///` docstring",
                        path.display(),
                        body_idx.saturating_add(1)
                    ));
                }
            }
            body_idx = body_idx.saturating_add(1);
        }
        idx = body_idx;
    }
}

/// Audits tuple `struct` fields (`pub struct Foo(\n /// doc\n pub T,\n);`) to ensure every
/// tuple field has a preceding `///` docstring (rejecting undocumented inline `struct Foo(T);`).
///
/// # Arguments
/// * `path` - File path for failure diagnostics.
/// * `lines` - Source lines of the file.
/// * `header_idx` - Line index containing the opening `(` of the tuple struct.
/// * `next_idx` - Output index advanced past the tuple struct closing `);`.
/// * `failures` - Accumulator of documentation violation messages.
fn audit_tuple_struct_fields(
    path: &Path,
    lines: &[&str],
    header_idx: usize,
    next_idx: &mut usize,
    failures: &mut Vec<String>,
) {
    let header_line = lines.get(header_idx).copied().unwrap_or("").trim();
    let decl_line = strip_vis_and_const(header_line);
    if let Some((_, after_open)) = decl_line.split_once('(') {
        let inline_body = after_open.trim();
        if !inline_body.is_empty() && !inline_body.starts_with("//") {
            let inner = inline_body
                .strip_suffix(");")
                .or_else(|| inline_body.strip_suffix(')'))
                .unwrap_or(inline_body)
                .trim();
            if !inner.is_empty() {
                failures.push(format!(
                    "{}:{}: inline tuple struct field in `{header_line}` lacks `///` docstring",
                    path.display(),
                    header_idx.saturating_add(1)
                ));
            }
            if decl_line.ends_with(';') {
                *next_idx = header_idx.saturating_add(1);
                return;
            }
        }
    }

    let mut paren_depth: usize = 0;
    for ch in decl_line.chars() {
        if ch == '(' {
            paren_depth = paren_depth.saturating_add(1);
        } else if ch == ')' {
            paren_depth = paren_depth.saturating_sub(1);
        }
    }

    let mut body_idx = header_idx.saturating_add(1);
    while body_idx < lines.len() && paren_depth > 0 {
        let bl = lines.get(body_idx).copied().unwrap_or("").trim();
        let depth_at_start = paren_depth;
        if !bl.starts_with("//") {
            for ch in bl.chars() {
                if ch == '(' {
                    paren_depth = paren_depth.saturating_add(1);
                } else if ch == ')' {
                    paren_depth = paren_depth.saturating_sub(1);
                }
            }
        }
        if depth_at_start == 1
            && !bl.is_empty()
            && !bl.starts_with("//")
            && !bl.starts_with("#[")
            && !bl.starts_with(')')
            && extract_preceding_doc_block(lines, body_idx).is_empty()
        {
            failures.push(format!(
                "{}:{}: tuple struct field `{bl}` lacks `///` docstring",
                path.display(),
                body_idx.saturating_add(1)
            ));
        }
        body_idx = body_idx.saturating_add(1);
    }
    *next_idx = body_idx;
}

/// Audits a single `.rs` file for `//!` header, named-item/field/variant `///` docstrings, and
/// complete `# Arguments` (`* `<param>` -` in order), `# Returns`, and `# Errors` (`CmdError`) sections.
///
/// # Arguments
/// * `path` - Path to the `.rs` file under audit.
/// * `failures` - Accumulator of documentation violation messages.
fn audit_file_documentation(path: &Path, failures: &mut Vec<String>) {
    let Ok(content) = fs::read_to_string(path) else {
        failures.push(format!("{}: unreadable source file", path.display()));
        return;
    };
    let lines: Vec<&str> = content.lines().collect();

    let has_module_doc = lines
        .iter()
        .take(10)
        .any(|line| line.trim_start().starts_with("//!"));
    if !has_module_doc {
        failures.push(format!(
            "{}:1: missing top-level `//!` module/file documentation header",
            path.display()
        ));
    }

    audit_fields_and_variants(path, &lines, failures);

    for (idx, raw_line) in lines.iter().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with("//") {
            continue;
        }

        if is_named_item_start(trimmed) && extract_preceding_doc_block(&lines, idx).is_empty() {
            failures.push(format!(
                "{}:{}: item `{trimmed}` lacks `///` documentation",
                path.display(),
                idx.saturating_add(1)
            ));
        }

        if !is_fn_item_start(trimmed) {
            continue;
        }

        let mut sig = String::from(trimmed);
        let mut lookahead = idx.saturating_add(1);
        while lookahead < lines.len() && !sig.contains('{') && !sig.ends_with(';') {
            sig.push(' ');
            sig.push_str(lines.get(lookahead).copied().unwrap_or("").trim());
            lookahead = lookahead.saturating_add(1);
        }

        let (fn_name, params, ret_type) = parse_fn_signature(&sig);
        if fn_name.is_empty() {
            continue;
        }

        let doc = extract_preceding_doc_block(&lines, idx);
        let line_no = idx.saturating_add(1);
        let safety = if trimmed.contains("unsafe fn ") || trimmed.contains("unsafe extern ") {
            FnSafetyKind::UnsafeFn
        } else {
            FnSafetyKind::Safe
        };
        let subject = FnAuditSubject {
            path,
            line_no,
            fn_name: &fn_name,
            params: &params,
            ret_type: ret_type.as_deref(),
            safety,
            doc: &doc,
        };
        audit_fn_doc_sections(&subject, failures);
    }
}

/// Safety classification of a Rust function declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FnSafetyKind {
    /// Safe Rust `fn` item.
    Safe,
    /// Explicit `unsafe fn` or `unsafe extern "C" fn` item requiring a `# Safety` doc section.
    UnsafeFn,
}

/// Extracted signature and preceding doc-comment context for a single Rust function item.
struct FnAuditSubject<'a> {
    /// Source file path for failure diagnostics.
    path: &'a Path,
    /// 1-based line number of the function declaration.
    line_no: usize,
    /// Parsed function identifier.
    fn_name: &'a str,
    /// Ordered list of non-`self` parameter identifiers.
    params: &'a [String],
    /// Optional non-unit return type string.
    ret_type: Option<&'a str>,
    /// Whether the declaration is an explicit `unsafe fn` requiring `# Safety`.
    safety: FnSafetyKind,
    /// Joined preceding `///` doc lines.
    doc: &'a str,
}

/// Validates `# Arguments`, `# Returns`, `# Errors`, and `# Safety` sections of a function's doc block.
///
/// # Arguments
/// * `subject` - Extracted [`FnAuditSubject`] metadata and docstring.
/// * `failures` - Accumulator of documentation violation messages.
fn audit_fn_doc_sections(subject: &FnAuditSubject<'_>, failures: &mut Vec<String>) {
    let path = subject.path;
    let line_no = subject.line_no;
    let fn_name = subject.fn_name;
    let params = subject.params;
    let ret_type = subject.ret_type;
    let doc = subject.doc;

    if doc.is_empty() {
        failures.push(format!(
            "{}:{line_no}: fn `{fn_name}` lacks `///` documentation",
            path.display()
        ));
        return;
    }

    for section in ["# Arguments", "# Returns", "# Errors", "# Safety"] {
        if doc.lines().filter(|l| l.trim() == section).count() > 1 {
            failures.push(format!(
                "{}:{line_no}: fn `{fn_name}` has duplicate `{section}` doc header",
                path.display()
            ));
        }
    }

    if subject.safety == FnSafetyKind::UnsafeFn && !doc.contains("# Safety") {
        failures.push(format!(
            "{}:{line_no}: unsafe fn `{fn_name}` lacks `# Safety` documentation section",
            path.display()
        ));
    }

    if !params.is_empty() {
        if let Some((_, args_section)) = doc.split_once("# Arguments") {
            let mut search_offset = 0;
            for p in params {
                let exact_bullet = format!("* `{p}` -");
                let tail = args_section.get(search_offset..).unwrap_or("");
                if let Some(rel_pos) = tail.find(&exact_bullet) {
                    search_offset = search_offset
                        .saturating_add(rel_pos)
                        .saturating_add(exact_bullet.len());
                } else {
                    failures.push(format!(
                        "{}:{line_no}: fn `{fn_name}` `# Arguments` missing ordered entry `{exact_bullet}`",
                        path.display()
                    ));
                }
            }
        } else {
            failures.push(format!(
                "{}:{line_no}: fn `{fn_name}` has parameters {params:?} but lacks `# Arguments`",
                path.display()
            ));
        }
    }

    if let Some(ret) = ret_type {
        if !doc.contains("# Returns") {
            failures.push(format!(
                "{}:{line_no}: fn `{fn_name}` -> `{ret}` lacks `# Returns`",
                path.display()
            ));
        }
        if ret.contains("Result<") && ret.contains("CmdError") {
            if let Some((_, err_section)) = doc.split_once("# Errors") {
                if !err_section.contains("CmdError") {
                    failures.push(format!(
                        "{}:{line_no}: fn `{fn_name}` `# Errors` does not name `CmdError`",
                        path.display()
                    ));
                }
            } else {
                failures.push(format!(
                    "{}:{line_no}: fn `{fn_name}` returns `{ret}` but lacks `# Errors`",
                    path.display()
                ));
            }
        }
    }
}

/// Enforces 100% file, module, type, field, variant, function, argument, return, safety, and error
/// documentation across every `.rs` file in `src/`, `tests/`, and `crates/wincmd-dos/`.
#[test]
fn test_hundred_percent_documentation_coverage_gate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs_files(&root.join("src"), &mut files);
    collect_rs_files(&root.join("tests"), &mut files);
    collect_rs_files(&root.join("crates/wincmd-dos/src"), &mut files);
    collect_rs_files(&root.join("crates/wincmd-dos/tests"), &mut files);
    assert!(files.len() >= 60);

    for required_rel in [
        "src/dos/mod.rs",
        "src/dos/types.rs",
        "src/dos/kernel.rs",
        "src/dos/sim.rs",
        "src/dos/console.rs",
        "src/vfs/dos.rs",
        "src/runtime/dos_exec.rs",
        "crates/wincmd-dos/src/lib.rs",
        "crates/wincmd-dos/src/alloc_djgpp.rs",
        "crates/wincmd-dos/src/panic_dos.rs",
        "crates/wincmd-dos/src/ffi.rs",
        "crates/wincmd-dos/src/djgpp_kernel.rs",
        "crates/wincmd-dos/src/stub_verify.rs",
        "crates/wincmd-dos/src/bin/wincmd.rs",
        "crates/wincmd-dos/src/bin/wincheck.rs",
        "crates/wincmd-dos/tests/dos_binaries.rs",
    ] {
        assert!(
            files.contains(&root.join(required_rel)),
            "Expected `{required_rel}` to be audited by documentation gate"
        );
    }

    let mut failures = Vec::new();
    for file in &files {
        audit_file_documentation(file, &mut failures);
    }

    let nl = "\n";
    assert_eq!(
        failures,
        Vec::<String>::new(),
        "Documentation completeness violations ({}): {}{}",
        failures.len(),
        nl,
        failures.join(nl)
    );
}

/// Strips standard (`"..."`) and raw (`r#"..."#`) Rust string literals from a single line
/// so anti-pattern scanners inspect actual code tokens rather than string test fixtures.
///
/// # Arguments
/// * `line` - Single Rust source line.
///
/// # Returns
/// Code skeleton with string literal contents replaced by empty `""`.
#[must_use]
fn strip_string_literals(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes.get(i) == Some(&b'r') {
            let mut hashes = 0usize;
            while bytes.get(i.saturating_add(1).saturating_add(hashes)) == Some(&b'#') {
                hashes = hashes.saturating_add(1);
            }
            if bytes.get(i.saturating_add(1).saturating_add(hashes)) == Some(&b'"') {
                out.push_str("\"\"");
                i = i.saturating_add(2).saturating_add(hashes);
                while i < bytes.len() {
                    if bytes.get(i) == Some(&b'"') {
                        let mut close_h = 0usize;
                        while close_h < hashes
                            && bytes.get(i.saturating_add(1).saturating_add(close_h)) == Some(&b'#')
                        {
                            close_h = close_h.saturating_add(1);
                        }
                        if close_h == hashes {
                            i = i.saturating_add(1).saturating_add(hashes);
                            break;
                        }
                    }
                    i = i.saturating_add(1);
                }
                continue;
            }
        }
        if bytes.get(i) == Some(&b'"') {
            out.push_str("\"\"");
            i = i.saturating_add(1);
            while i < bytes.len() {
                if bytes.get(i) == Some(&b'\\') {
                    i = i.saturating_add(2);
                    continue;
                }
                if bytes.get(i) == Some(&b'"') {
                    i = i.saturating_add(1);
                    break;
                }
                i = i.saturating_add(1);
            }
            continue;
        }
        let ch = line.get(i..).and_then(|s| s.chars().next()).unwrap_or(' ');
        out.push(ch);
        i = i.saturating_add(ch.len_utf8());
    }
    out
}

/// Audits `src/` source files to forbid raw `: bool` function parameters (requiring semantic
/// domain enums instead of boolean flags, while allowing `-> bool` return values on predicates).
///
/// # Arguments
/// * `path` - Source file path under `src/`.
/// * `content` - Full UTF-8 source text of `path`.
/// * `violations` - Accumulator of violation messages.
fn audit_no_raw_bool_params(path: &Path, content: &str, violations: &mut Vec<String>) {
    let lines: Vec<&str> = content.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let after_vis = strip_vis_and_const(trimmed);
        if !after_vis.starts_with("fn ") {
            continue;
        }
        let mut combined = String::new();
        for j in idx..lines.len().min(idx.saturating_add(25)) {
            let l = lines.get(j).copied().unwrap_or("").trim();
            if !l.starts_with("//") {
                combined.push_str(l);
                combined.push(' ');
            }
            if l.contains('{') || l.ends_with(';') {
                break;
            }
        }
        let Some(fn_pos) = combined.find("fn ") else {
            continue;
        };
        let after_fn = combined
            .get(fn_pos.saturating_add(3)..)
            .unwrap_or("")
            .trim_start();
        let name_len = after_fn
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .count();
        let fn_name = after_fn.get(..name_len).unwrap_or("");
        let mut cursor = after_fn.get(name_len..).unwrap_or("").trim_start();
        if cursor.starts_with('<') {
            let mut depth: usize = 0;
            let mut end_gen = 0;
            for (i, ch) in cursor.char_indices() {
                if ch == '<' {
                    depth = depth.saturating_add(1);
                } else if ch == '>' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end_gen = i.saturating_add(1);
                        break;
                    }
                }
            }
            cursor = cursor.get(end_gen..).unwrap_or("").trim_start();
        }
        if !cursor.starts_with('(') {
            continue;
        }
        let mut p_depth: usize = 0;
        let mut close_paren = 0;
        for (i, ch) in cursor.char_indices() {
            if ch == '(' {
                p_depth = p_depth.saturating_add(1);
            } else if ch == ')' {
                p_depth = p_depth.saturating_sub(1);
                if p_depth == 0 {
                    close_paren = i;
                    break;
                }
            }
        }
        let params_inner = cursor.get(1..close_paren).unwrap_or("");
        let mut depth: usize = 0;
        let mut start = 0;
        let mut parts = Vec::new();
        for (i, ch) in params_inner.char_indices() {
            match ch {
                '(' | '<' | '[' => depth = depth.saturating_add(1),
                ')' | '>' | ']' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    parts.push(params_inner.get(start..i).unwrap_or("").trim());
                    start = i.saturating_add(1);
                }
                _ => {}
            }
        }
        let tail = params_inner.get(start..).unwrap_or("").trim();
        if !tail.is_empty() {
            parts.push(tail);
        }
        for part in parts {
            if let Some((_, ty)) = part.split_once(':') {
                let t = ty.trim();
                if t == "bool" || t.contains("(bool") || t.contains("bool)") {
                    violations.push(format!(
                        "{}:{}: raw `: bool` parameter `{part}` in `fn {fn_name}` is forbidden; use a semantic enum",
                        path.display(),
                        idx.saturating_add(1)
                    ));
                }
            }
        }
    }
}

/// Enforces zero banned anti-patterns across `Cargo.toml`, `src/**`, and `tests/**`:
/// - Zero `[lints.clippy]` `= "allow"` suppressions and zero `#[allow(` / `#![allow(` / `#[expect(` attributes.
/// - Zero `anyhow`, `thiserror`, `eyre`, `snafu`, or `Box<dyn Error>` dynamic error erasure.
/// - Zero `std::convert::identity` or `let _ =` silent result/branch-coverage gaming anywhere in `src/` or `tests/`.
/// - Zero `.unwrap(`, `.expect(`, `panic!(`, `todo!(`, `unimplemented!(`, `unreachable!(`, `dbg!(`.
/// - Zero vacuous `assert_ne!(..., "")`.
#[test]
fn test_zero_banned_antipatterns_and_lint_escapes_gate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();

    for manifest_rel in ["Cargo.toml", "crates/wincmd-dos/Cargo.toml"] {
        let cargo_toml = fs::read_to_string(root.join(manifest_rel)).unwrap_or_default();
        for (idx, line) in cargo_toml.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.starts_with('#') && trimmed.contains("= \"allow\"") {
                violations.push(format!(
                    "{manifest_rel}:{}: blanket lint suppression `{trimmed}` is forbidden",
                    idx.saturating_add(1)
                ));
            }
            for crate_ban in ["anyhow", "thiserror", "eyre", "snafu"] {
                if trimmed.starts_with(crate_ban) {
                    violations.push(format!(
                        "{manifest_rel}:{}: banned error crate `{crate_ban}`",
                        idx.saturating_add(1)
                    ));
                }
            }
        }
    }

    let mut files = Vec::new();
    collect_rs_files(&root.join("src"), &mut files);
    collect_rs_files(&root.join("tests"), &mut files);
    collect_rs_files(&root.join("crates/wincmd-dos/src"), &mut files);
    collect_rs_files(&root.join("crates/wincmd-dos/tests"), &mut files);

    let banned_everywhere = [
        "#[allow(",
        "#![allow(",
        "#[expect(",
        "#![expect(",
        "convert::identity",
        "let _ =",
        ".unwrap(",
        ".expect(",
        "panic!(",
        "todo!(",
        "unimplemented!(",
        "unreachable!(",
        "dbg!(",
        "anyhow",
        "thiserror",
        "Box<dyn Error",
        "Box<dyn std::error::Error",
        "Box<dyn core::error::Error",
        "from_utf8(&[0x",
    ];

    let src_dir = root.join("src");
    let dos_src_dir = root.join("crates/wincmd-dos/src");
    for path in &files {
        let content = fs::read_to_string(path).unwrap_or_default();
        if path.starts_with(&src_dir) || path.starts_with(&dos_src_dir) {
            audit_no_raw_bool_params(path, &content, &mut violations);
        }

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            let code_only = strip_string_literals(trimmed);

            for needle in banned_everywhere {
                if code_only.contains(needle) {
                    violations.push(format!(
                        "{}:{}: banned pattern `{needle}`",
                        path.display(),
                        idx.saturating_add(1)
                    ));
                }
            }

            if code_only.contains("assert_ne!(") && trimmed.contains(", \"\")") {
                violations.push(format!(
                    "{}:{}: vacuous non-empty assertion `{trimmed}` is forbidden",
                    path.display(),
                    idx.saturating_add(1)
                ));
            }
        }
    }

    let nl = "\n";
    assert_eq!(
        violations,
        Vec::<String>::new(),
        "Anti-pattern violations ({}):{}{}",
        violations.len(),
        nl,
        violations.join(nl)
    );
}

/// Enforces that `CmdError` in `src/error.rs` is the sole `#[derive(..., Error, ...)]` type
/// across the workspace (`src/` and `crates/wincmd-dos/`) and that every `CmdError` variant
/// is constructed in non-test production code.
#[test]
fn test_unified_cmd_error_architecture_gate() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut src_files = Vec::new();
    collect_rs_files(&root.join("src"), &mut src_files);
    collect_rs_files(&root.join("crates/wincmd-dos/src"), &mut src_files);
    src_files.sort();

    let mut prod_sources: Vec<(PathBuf, String)> = Vec::new();
    let mut error_derive_count = 0usize;

    for path in &src_files {
        let full = fs::read_to_string(path).unwrap_or_default();
        let prod_part = full.split("#[cfg(test)]").next().unwrap_or("").to_owned();
        for line in prod_part.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("#[derive(")
                && trimmed
                    .trim_start_matches("#[derive(")
                    .trim_end_matches(")]")
                    .split(',')
                    .any(|item| item.trim() == "Error")
            {
                error_derive_count = error_derive_count.saturating_add(1);
                assert!(
                    path.ends_with("src/error.rs"),
                    "Unexpected #[derive(..., Error)] outside src/error.rs in {}",
                    path.display()
                );
            }
        }
        prod_sources.push((path.clone(), prod_part));
    }

    assert_eq!(
        error_derive_count, 1,
        "Expected exactly 1 #[derive(..., Error)] type (CmdError), found {error_derive_count}"
    );

    let err_prod = fs::read_to_string(root.join("src/error.rs"))
        .unwrap_or_default()
        .split("#[cfg(test)]")
        .next()
        .unwrap_or("")
        .to_owned();
    let enum_after = err_prod.split("pub enum CmdError {").nth(1).unwrap_or("");
    let enum_body = enum_after.split("\n}\n").next().unwrap_or("");

    let mut variants = Vec::new();
    for line in enum_body.lines() {
        if let Some(after_indent) = line.strip_prefix("    ") {
            let first_ch = after_indent.chars().next().unwrap_or(' ');
            if first_ch.is_ascii_uppercase() {
                let ident: String = after_indent
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !ident.is_empty() {
                    variants.push(ident);
                }
            }
        }
    }
    assert!(
        !variants.is_empty(),
        "Failed to parse CmdError variants from src/error.rs"
    );

    let mut unconstructed = Vec::new();
    for var in &variants {
        let cmd_pat = format!("CmdError::{var}");
        let self_pat = format!("Self::{var}");
        let from_wired = matches!(var.as_str(), "CliUsage" | "ExecutionLimitExceeded")
            && prod_sources.iter().any(|(p, c)| {
                !p.ends_with("src/error.rs")
                    && ((var == "CliUsage" && c.contains("CliUsageFailure::new"))
                        || (var == "ExecutionLimitExceeded" && c.contains("ExecutionLimitFailure")))
            });
        let constructed_in_prod = from_wired
            || prod_sources.iter().any(|(p, c)| {
                if p.ends_with("src/error.rs") {
                    c.contains(&self_pat)
                } else {
                    c.contains(&cmd_pat)
                }
            });
        if !constructed_in_prod {
            unconstructed.push(var.clone());
        }
    }

    assert_eq!(
        unconstructed,
        Vec::<String>::new(),
        "Unconstructed CmdError variants in production code: {unconstructed:?}"
    );
}

/// Verifies all 60 `wincheck` lint rules (`CMD0001`–`CMD4010` + `CMD5001`–`CMD5010`) have unique
/// `RuleId`s, non-empty `--explain` documentation, and deterministic test triggers for every
/// MS-DOS portability rule (`CMD5001`–`CMD5010`).
#[test]
fn test_all_sixty_lint_rules_catalog_and_dos_portability_gate() {
    use std::collections::BTreeSet;
    use win_cmd_rs::linter::{LinterConfig, RuleId, all_rule_metadata, explain_rule, lint_script};
    use win_cmd_rs::span::SourceMap;
    use win_cmd_rs::types::{CRLF, ShellDialect};

    let catalog = all_rule_metadata();
    assert_eq!(catalog.len(), 60, "Expected exactly 60 lint rules");

    let mut seen_ids = BTreeSet::new();
    let mut seen_names = BTreeSet::new();
    for meta in &catalog {
        assert!(
            seen_ids.insert(meta.id.clone()),
            "Duplicate RuleId `{}`",
            meta.id
        );
        assert!(
            seen_names.insert(meta.name),
            "Duplicate rule name `{}`",
            meta.name
        );
        assert!(meta.name.trim().len() >= 5);
        assert!(meta.summary.trim().len() >= 15);
        assert!(meta.explanation.trim().len() >= 25);
        assert_eq!(explain_rule(meta.id.as_str()), Ok(meta.clone()));
    }

    for num in 1..=10 {
        assert!(seen_ids.contains(&RuleId::new(&format!("CMD50{num:02}"))));
    }

    let long_arg = "X".repeat(132);
    let dos_fixture = [
        "@echo off",
        "set /a X=1+2",
        "for /L %%I in (1,1,3) do echo %%I",
        "if /I \"%A%\"==\"b\" echo hi",
        "echo one & echo two",
        "echo %~dp0",
        "call :sub",
        "setlocal",
        "echo err 2>NUL",
        "call C:\\verylongfilename.bat",
        &format!("exttool.exe {long_arg}"),
        ":sub",
        "exit /b 0",
    ]
    .join(CRLF)
        + CRLF;

    let dos_cfg = LinterConfig {
        dialect: ShellDialect::MsDos622,
        ..LinterConfig::default()
    };
    let mut sm = SourceMap::new();
    let (_, dos_diags) =
        lint_script("BUILD.CMD", dos_fixture.as_bytes(), &dos_cfg, &mut sm).unwrap_or_default();
    let triggered: BTreeSet<String> = dos_diags
        .iter()
        .map(|d| d.rule_id.as_str().to_owned())
        .collect();
    for code in [
        "CMD5001", "CMD5002", "CMD5003", "CMD5004", "CMD5005", "CMD5006", "CMD5007", "CMD5008",
        "CMD5009", "CMD5010",
    ] {
        assert!(
            triggered.contains(code),
            "Expected MS-DOS portability rule `{code}` to fire on DOS fixture, got: {triggered:?}"
        );
    }

    let nt_cfg = LinterConfig {
        dialect: ShellDialect::WindowsNtCmd,
        ..LinterConfig::default()
    };
    let mut sm_nt = SourceMap::new();
    let (_, nt_diags) =
        lint_script("BUILD.CMD", dos_fixture.as_bytes(), &nt_cfg, &mut sm_nt).unwrap_or_default();
    for d in &nt_diags {
        assert!(
            !d.rule_id.as_str().starts_with("CMD50"),
            "DOS rule `{}` must not fire in WindowsNtCmd dialect",
            d.rule_id
        );
    }
}

/// Extracts an indented YAML literal block scalar (`|`) starting immediately after `header_idx`.
///
/// # Arguments
/// * `lines` - Source lines of the YAML file.
/// * `header_idx` - 0-based line index of the `run: |` or `- |` block header.
///
/// # Returns
/// Dedented multi-line text content of the YAML literal block scalar.
#[must_use]
fn extract_yaml_block_scalar(lines: &[&str], header_idx: usize) -> String {
    let header_line = lines.get(header_idx).copied().unwrap_or("");
    let header_indent = header_line
        .len()
        .saturating_sub(header_line.trim_start().len());

    let mut block_indent: Option<usize> = None;
    let mut raw_block: Vec<&str> = Vec::new();
    let mut idx = header_idx.saturating_add(1);

    while idx < lines.len() {
        let line = lines.get(idx).copied().unwrap_or("");
        if line.trim().is_empty() {
            if block_indent.is_some() {
                raw_block.push("");
            }
            idx = idx.saturating_add(1);
            continue;
        }
        let indent = line.len().saturating_sub(line.trim_start().len());
        if let Some(min_indent) = block_indent {
            if indent < min_indent {
                break;
            }
            raw_block.push(line.get(min_indent..).unwrap_or(""));
        } else {
            if indent <= header_indent {
                break;
            }
            block_indent = Some(indent);
            raw_block.push(line.get(indent..).unwrap_or(""));
        }
        idx = idx.saturating_add(1);
    }

    while raw_block.last().is_some_and(|last| last.is_empty()) {
        raw_block.pop();
    }
    raw_block.join("\n")
}

/// Extracts every `shell: python3 {0}` step script from `.github/workflows/ci.yml`.
///
/// # Arguments
/// * `yaml_text` - Full UTF-8 text of `.github/workflows/ci.yml`.
///
/// # Returns
/// Ordered `(step_label, python_source)` pairs for all inline Python workflow steps.
#[must_use]
fn extract_ci_python_step_scripts(yaml_text: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = yaml_text.lines().collect();
    let mut out = Vec::new();
    let mut current_step = String::from("unnamed-step");
    let mut idx = 0usize;

    while idx < lines.len() {
        let trimmed = lines.get(idx).copied().unwrap_or("").trim();
        if let Some(step_name) = trimmed.strip_prefix("- name:") {
            current_step = step_name.trim().to_owned();
        } else if trimmed == "shell: python3 {0}" {
            let mut scan = idx.saturating_add(1);
            while scan < lines.len() {
                let st = lines.get(scan).copied().unwrap_or("").trim();
                if st.starts_with("- name:") {
                    break;
                }
                if st == "run: |" {
                    let script = extract_yaml_block_scalar(&lines, scan);
                    out.push((format!(".github/workflows/ci.yml ({current_step})"), script));
                    idx = scan;
                    break;
                }
                scan = scan.saturating_add(1);
            }
        }
        idx = idx.saturating_add(1);
    }
    out
}

/// Extracts every `entry: python3 -c` hook script from `.pre-commit-config.yaml`.
///
/// # Arguments
/// * `yaml_text` - Full UTF-8 text of `.pre-commit-config.yaml`.
///
/// # Returns
/// Ordered `(hook_label, python_source)` pairs for all Python pre-commit hooks.
#[must_use]
fn extract_precommit_python_hook_scripts(yaml_text: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = yaml_text.lines().collect();
    let mut out = Vec::new();
    let mut current_hook = String::from("unnamed-hook");
    let mut idx = 0usize;

    while idx < lines.len() {
        let trimmed = lines.get(idx).copied().unwrap_or("").trim();
        if let Some(hook_id) = trimmed.strip_prefix("- id:") {
            current_hook = hook_id.trim().to_owned();
        } else if trimmed == "entry: python3 -c" {
            let mut scan = idx.saturating_add(1);
            while scan < lines.len() {
                let st = lines.get(scan).copied().unwrap_or("").trim();
                if st.starts_with("- id:") {
                    break;
                }
                if st == "- |" {
                    let script = extract_yaml_block_scalar(&lines, scan);
                    out.push((format!(".pre-commit-config.yaml ({current_hook})"), script));
                    idx = scan;
                    break;
                }
                scan = scan.saturating_add(1);
            }
        }
        idx = idx.saturating_add(1);
    }
    out
}

/// Extracts a single-quoted shell heredoc (`<<'MARKER' ... MARKER`) payload from `sh_text`.
///
/// # Arguments
/// * `sh_text` - Full UTF-8 shell script text.
/// * `marker` - Heredoc delimiter identifier (such as `"PYLINK"`).
///
/// # Returns
/// Enclosed heredoc script body, or an empty `String` if the delimiter is absent.
#[must_use]
fn extract_heredoc_script(sh_text: &str, marker: &str) -> String {
    let open_tag = format!("<<'{marker}'");
    let Some((_, after_open)) = sh_text.split_once(&open_tag) else {
        return String::new();
    };
    let body_start = after_open
        .strip_prefix("\r\n")
        .or_else(|| after_open.strip_prefix('\n'))
        .unwrap_or(after_open);
    let mut collected = Vec::new();
    for line in body_start.lines() {
        if line == marker {
            break;
        }
        collected.push(line);
    }
    collected.join("\n")
}

/// Resolves an available Python 3 interpreter executable on the current host (`python` or `python3`).
///
/// # Returns
/// `Some(program_name)` when a working Python 3 interpreter is on `PATH`, or `None` otherwise.
#[must_use]
fn resolve_python3_binary() -> Option<&'static str> {
    let candidates = if cfg!(windows) {
        ["python", "python3"]
    } else {
        ["python3", "python"]
    };
    for bin in candidates {
        let ok = Command::new(bin)
            .args([
                "-c",
                "import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|st| st.success());
        if ok {
            return Some(bin);
        }
    }
    None
}

/// Compiles `source` via Python's built-in `compile(..., "exec")` pass without executing it,
/// catching syntax, indentation, and PEP 3104 symbol-table (`nonlocal` / `global`) errors.
///
/// # Arguments
/// * `py_bin` - Resolved Python 3 interpreter command name.
/// * `label` - Virtual filename label attached to Python compiler diagnostics.
/// * `source` - Python source text to validate.
///
/// # Returns
/// `Ok(())` when `source` compiles cleanly to Python bytecode.
///
/// # Errors
/// Returns `Err(String)` containing Python's compiler traceback if compilation fails.
fn check_python_script_compiles(py_bin: &str, label: &str, source: &str) -> Result<(), String> {
    let mut child = Command::new(py_bin)
        .args([
            "-c",
            "import sys; compile(sys.stdin.read(), sys.argv[1], 'exec')",
            label,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn `{py_bin}` for `{label}`: {err}"))?;

    if let Some(mut stdin_pipe) = child.stdin.take() {
        stdin_pipe
            .write_all(source.as_bytes())
            .map_err(|err| format!("failed writing stdin to `{py_bin}` for `{label}`: {err}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed waiting on `{py_bin}` for `{label}`: {err}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{label}:\n{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Verifies that every embedded Python script across `.github/workflows/ci.yml`,
/// `.pre-commit-config.yaml`, and `crates/wincmd-dos/stub/djgpp-linker.sh` passes Python's
/// AST + PEP 3104 symbol-table + bytecode compiler (`compile(..., "exec")`) with zero errors.
#[test]
fn test_embedded_ci_and_linker_python_scripts_compile_cleanly() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let ci_yaml = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap_or_default();
    let ci_scripts = extract_ci_python_step_scripts(&ci_yaml);
    assert_eq!(
        ci_scripts.len(),
        4,
        "Expected 4 `shell: python3 {{0}}` steps in `.github/workflows/ci.yml`, found {}",
        ci_scripts.len()
    );

    let precommit_yaml =
        fs::read_to_string(root.join(".pre-commit-config.yaml")).unwrap_or_default();
    let precommit_scripts = extract_precommit_python_hook_scripts(&precommit_yaml);
    assert_eq!(
        precommit_scripts.len(),
        3,
        "Expected 3 `entry: python3 -c` hooks in `.pre-commit-config.yaml`, found {}",
        precommit_scripts.len()
    );

    let linker_sh =
        fs::read_to_string(root.join("crates/wincmd-dos/stub/djgpp-linker.sh")).unwrap_or_default();
    let linker_py = extract_heredoc_script(&linker_sh, "PYLINK");
    assert!(
        linker_py.contains("def convert_pe_coff_to_go32"),
        "Expected `PYLINK` heredoc script in `crates/wincmd-dos/stub/djgpp-linker.sh`"
    );

    let Some(py_bin) = resolve_python3_binary() else {
        return;
    };

    // Confirm negative detection on the exact module-scope `nonlocal` bug class (PEP 3104).
    let broken_nonlocal = "next_cluster = 2\ndef add_root_entry():\n    nonlocal next_cluster\n    next_cluster += 1\n";
    let neg_res = check_python_script_compiles(py_bin, "<synthetic-nonlocal>", broken_nonlocal);
    assert!(
        neg_res
            .as_ref()
            .is_err_and(|msg| msg.contains("SyntaxError") && msg.contains("nonlocal")),
        "Expected `compile()` gate to reject module-scope `nonlocal`, got: {neg_res:?}"
    );

    let mut all_scripts = Vec::new();
    all_scripts.extend(ci_scripts);
    all_scripts.extend(precommit_scripts);
    all_scripts.push((
        String::from("crates/wincmd-dos/stub/djgpp-linker.sh (PYLINK)"),
        linker_py,
    ));

    let mut compile_errors = Vec::new();
    for (label, script) in &all_scripts {
        assert!(
            !script.trim().is_empty(),
            "Extracted empty Python script for `{label}`"
        );
        if let Err(err) = check_python_script_compiles(py_bin, label, script) {
            compile_errors.push(err);
        }
    }

    assert_eq!(
        compile_errors,
        Vec::<String>::new(),
        "Embedded Python script compilation errors:\n{}",
        compile_errors.join("\n\n")
    );
}

/// Pairing between a Debian/Ubuntu GNU C cross-compiler package and its target `glibc` development
/// sysroot package (`Scrt1.o`, `crti.o`, `crtn.o`, `libc.so`), which Debian/Ubuntu marks only as
/// `Recommends:` and therefore omits under `apt-get install --no-install-recommends`.
struct DebianCrossSysrootRule {
    /// Debian/Ubuntu `gcc-<triple>` cross-compiler package name.
    gcc_package: &'static str,
    /// Required companion `libc6-dev-<arch>-cross` package providing CRT startup objects and `libc.so`.
    libc_dev_package: &'static str,
}

/// Known Debian/Ubuntu GNU cross-compiler -> `libc6-dev-*-cross` package pairings.
const DEBIAN_CROSS_SYSROOT_RULES: &[DebianCrossSysrootRule] = &[
    DebianCrossSysrootRule {
        gcc_package: "gcc-aarch64-linux-gnu",
        libc_dev_package: "libc6-dev-arm64-cross",
    },
    DebianCrossSysrootRule {
        gcc_package: "gcc-x86-64-linux-gnu",
        libc_dev_package: "libc6-dev-amd64-cross",
    },
    DebianCrossSysrootRule {
        gcc_package: "gcc-arm-linux-gnueabihf",
        libc_dev_package: "libc6-dev-armhf-cross",
    },
    DebianCrossSysrootRule {
        gcc_package: "gcc-riscv64-linux-gnu",
        libc_dev_package: "libc6-dev-riscv64-cross",
    },
    DebianCrossSysrootRule {
        gcc_package: "gcc-powerpc64le-linux-gnu",
        libc_dev_package: "libc6-dev-ppc64el-cross",
    },
    DebianCrossSysrootRule {
        gcc_package: "gcc-s390x-linux-gnu",
        libc_dev_package: "libc6-dev-s390x-cross",
    },
];

/// Audits `.github/workflows/ci.yml` for cross-compilation sysroot completeness under
/// `--no-install-recommends`, continuous non-tag Linux cross-link coverage, and LF-clean
/// release `SHA256SUMS.txt` verification.
///
/// # Arguments
/// * `yaml_text` - Full UTF-8 text of `.github/workflows/ci.yml`.
///
/// # Returns
/// Ordered list of CI workflow invariant violation messages (empty when clean).
#[must_use]
fn audit_ci_cross_compile_and_release_workflow(yaml_text: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let lines: Vec<&str> = yaml_text.lines().collect();
    let uses_no_install_recommends = yaml_text.contains("--no-install-recommends");

    for (idx, raw_line) in lines.iter().enumerate() {
        let trimmed = raw_line.trim();
        let line_no = idx.saturating_add(1);

        if uses_no_install_recommends && let Some(pkg_spec) = trimmed.strip_prefix("apt_packages:")
        {
            let tokens: Vec<&str> = pkg_spec.split_whitespace().collect();
            for rule in DEBIAN_CROSS_SYSROOT_RULES {
                if tokens.contains(&rule.gcc_package) && !tokens.contains(&rule.libc_dev_package) {
                    violations.push(format!(
                        ".github/workflows/ci.yml:{line_no}: `apt_packages` installs `{}` under `--no-install-recommends` without `{}` (missing `Scrt1.o`/`crti.o`/`libc.so`)",
                        rule.gcc_package, rule.libc_dev_package
                    ));
                }
            }
        }

        if trimmed.starts_with("sudo apt-get install")
            && trimmed.contains("--no-install-recommends")
        {
            let mut joined = String::from(trimmed);
            let mut cont_idx = idx;
            while joined.trim_end().ends_with('\\') {
                joined = joined.trim_end().trim_end_matches('\\').to_owned();
                cont_idx = cont_idx.saturating_add(1);
                let Some(next_line) = lines.get(cont_idx) else {
                    break;
                };
                joined.push(' ');
                joined.push_str(next_line.trim());
            }
            if !joined.contains("${{") {
                let tokens: Vec<&str> = joined.split_whitespace().collect();
                for rule in DEBIAN_CROSS_SYSROOT_RULES {
                    if tokens.contains(&rule.gcc_package)
                        && !tokens.contains(&rule.libc_dev_package)
                    {
                        violations.push(format!(
                            ".github/workflows/ci.yml:{line_no}: `apt-get install --no-install-recommends` installs `{}` without `{}`",
                            rule.gcc_package, rule.libc_dev_package
                        ));
                    }
                }
            }
        }

        if trimmed.contains("Set-Content") && trimmed.contains(".sha256") {
            violations.push(format!(
                ".github/workflows/ci.yml:{line_no}: PowerShell `Set-Content` emits CRLF in `.sha256` files; use `[System.IO.File]::WriteAllText` with LF"
            ));
        }
    }

    if !yaml_text.contains("  linux-cross-build:\n") {
        violations.push(String::from(
            ".github/workflows/ci.yml: missing continuous `linux-cross-build` job for non-tag pushes and pull requests",
        ));
    } else if let Some((_, after_job)) = yaml_text.split_once("  linux-cross-build:\n") {
        let job_body = after_job
            .split("\n  build-release:\n")
            .next()
            .unwrap_or(after_job);
        if job_body.contains("refs/tags/v") {
            violations.push(String::from(
                ".github/workflows/ci.yml: `linux-cross-build` must run on `master` and `pull_request`, not only `refs/tags/v*`",
            ));
        }
        for required_snippet in [
            "--bins --target aarch64-unknown-linux-gnu",
            "--bins --target x86_64-unknown-linux-musl",
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER",
        ] {
            if !job_body.contains(required_snippet) {
                violations.push(format!(
                    ".github/workflows/ci.yml: `linux-cross-build` missing `{required_snippet}`"
                ));
            }
        }
    }

    if !yaml_text.contains("sha256sum -c SHA256SUMS.txt") {
        violations.push(String::from(
            ".github/workflows/ci.yml: `Generate combined SHA256SUMS.txt` must verify archives via `sha256sum -c SHA256SUMS.txt`",
        ));
    }

    violations
}

/// Verifies `.github/workflows/ci.yml` cross-compilation sysroot invariants, continuous Linux
/// cross-link coverage, and LF-clean `SHA256SUMS.txt` verification, including negative mutation
/// checks for the `v0.0.1` `Scrt1.o`/`crti.o` failure mode.
#[test]
fn test_ci_cross_compile_and_release_workflow_invariants_gate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let ci_yaml = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap_or_default();
    assert!(
        !ci_yaml.is_empty(),
        "Expected `.github/workflows/ci.yml` to be readable"
    );

    // Confirm negative detection on the exact v0.0.1 regression (`gcc-aarch64-linux-gnu` without `libc6-dev-arm64-cross`).
    let broken_sysroot_yaml = ci_yaml.replace(
        "apt_packages: gcc-aarch64-linux-gnu libc6-dev-arm64-cross",
        "apt_packages: gcc-aarch64-linux-gnu",
    );
    let sysroot_violations = audit_ci_cross_compile_and_release_workflow(&broken_sysroot_yaml);
    assert!(
        sysroot_violations
            .iter()
            .any(|msg| msg.contains("libc6-dev-arm64-cross")),
        "Expected audit to catch missing `libc6-dev-arm64-cross`, got: {sysroot_violations:?}"
    );

    // Confirm negative detection on CRLF PowerShell `.sha256` generation.
    let broken_crlf_yaml = ci_yaml.replace(
        "[System.IO.File]::WriteAllText(\"$ZipPath.sha256\", \"$Hash  $StageName.zip`n\", [System.Text.Encoding]::ASCII)",
        "\"$Hash  $StageName.zip\" | Set-Content -NoNewline:$false -Encoding ascii \"$ZipPath.sha256\"",
    );
    let crlf_violations = audit_ci_cross_compile_and_release_workflow(&broken_crlf_yaml);
    assert!(
        crlf_violations
            .iter()
            .any(|msg| msg.contains("Set-Content")),
        "Expected audit to catch CRLF `Set-Content` `.sha256` emission, got: {crlf_violations:?}"
    );

    let violations = audit_ci_cross_compile_and_release_workflow(&ci_yaml);
    assert_eq!(
        violations,
        Vec::<String>::new(),
        "CI workflow cross-compilation / release violations:\n{}",
        violations.join("\n")
    );
}
