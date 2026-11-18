//! Windows `CommandLineToArgvW` command-line parser and `%PATH%` / `%PATHEXT%` / `HKCR` target resolver.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::types::{BS_CHAR, NativeBackingPath, TAB_CHAR};
use crate::vfs::path::WindowsPath;

use super::Interpreter;

/// Parses a raw Windows command-line tail (`lpCommandLine`) into `argv` tokens following
/// exact `CommandLineToArgvW` / MSVCRT `2n` vs `2n+1` backslash-before-quote rules.
///
/// # Arguments
/// * `raw_tail` - Raw post-program argument tail string.
///
/// # Returns
/// Vector of unescaped argument strings.
#[must_use]
pub fn parse_windows_command_line_argv(raw_tail: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut token_started = false;
    let mut chars = raw_tail.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == BS_CHAR {
            let mut bs_count = 1usize;
            while chars.peek() == Some(&BS_CHAR) {
                chars.next();
                bs_count = bs_count.saturating_add(1);
            }
            if chars.peek() == Some(&'"') {
                chars.next();
                for _ in 0..(bs_count / 2) {
                    cur.push(BS_CHAR);
                }
                if bs_count.is_multiple_of(2) {
                    in_quotes = !in_quotes;
                } else {
                    cur.push('"');
                }
            } else {
                for _ in 0..bs_count {
                    cur.push(BS_CHAR);
                }
            }
        } else if ch == '"' {
            if in_quotes && chars.peek() == Some(&'"') {
                chars.next();
                cur.push('"');
            } else {
                in_quotes = !in_quotes;
            }
        } else if (ch == ' ' || ch == TAB_CHAR) && !in_quotes {
            if token_started {
                args.push(core::mem::take(&mut cur));
                token_started = false;
            }
            continue;
        } else {
            cur.push(ch);
        }
        token_started = true;
    }
    if token_started {
        args.push(cur);
    }
    args
}

/// Result of resolving an external command or script via `%PATH%`, `%PATHEXT%`, and `ASSOC`/`FTYPE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedCommandTarget {
    /// A `.bat` or `.cmd` batch file on the VFS.
    BatchScript {
        /// Full resolved VFS path of the batch script.
        full_path: WindowsPath,
    },
    /// An external binary executable (`.exe`, `.com`, or host binary).
    ExternalExecutable {
        /// Full resolved VFS path of the executable.
        full_path: WindowsPath,
        /// Optional resolved native backing path when backed by `HostOsVfs` or `DosFatVfs`.
        host_path: Option<NativeBackingPath>,
    },
    /// A file with an extension registered in `ASSOC` and `FTYPE`.
    AssociatedDocument {
        /// Full resolved VFS path of the document.
        full_path: WindowsPath,
        /// Registered file type name (`ASSOC`).
        file_type: String,
        /// Open command template (`FTYPE`, e.g., `python.exe "%1" %*`).
        command_template: String,
    },
}

impl ResolvedCommandTarget {
    /// Consumes this [`ResolvedCommandTarget`] and returns its resolved [`WindowsPath`].
    ///
    /// # Returns
    /// The full [`WindowsPath`] of the resolved target.
    #[must_use]
    pub fn into_full_path(self) -> WindowsPath {
        match self {
            Self::BatchScript { full_path }
            | Self::ExternalExecutable { full_path, .. }
            | Self::AssociatedDocument { full_path, .. } => full_path,
        }
    }
}

impl Interpreter {
    /// Resolves a command name against the current working directory, `%PATH%`, `%PATHEXT%`,
    /// and Registry file associations (`HKCR/.ext` and `HKCR/<ftype>/shell/open/command`).
    ///
    /// # Arguments
    /// * `prog` - Unquoted program/script token.
    ///
    /// # Returns
    /// `Some(ResolvedCommandTarget)` if an executable, batch script, or associated document is found.
    #[must_use]
    pub fn resolve_external_or_batch_target(&self, prog: &str) -> Option<ResolvedCommandTarget> {
        let default_pathext = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC".to_owned();
        let pathext_raw = self.lookup_var("PATHEXT").unwrap_or(default_pathext);
        let pathexts: Vec<String> = pathext_raw
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();

        let has_explicit_dir = prog.contains([BS_CHAR, '/', ':']);
        let mut search_dirs: Vec<Option<WindowsPath>> = Vec::new();
        if has_explicit_dir {
            search_dirs.push(None);
        } else {
            if !self
                .proc_env
                .env
                .is_defined("NoDefaultCurrentDirectoryInExePath")
            {
                search_dirs.push(Some(self.proc_env.vfs.resolve_path(".")));
            }
            if let Some(path_var) = self.lookup_var("PATH") {
                for dir_str in path_var.split(';').map(str::trim).filter(|d| !d.is_empty()) {
                    search_dirs.push(Some(self.proc_env.vfs.resolve_path(dir_str)));
                }
            }
        }

        let prog_leaf = prog.rsplit([BS_CHAR, '/', ':']).next().unwrap_or(prog);
        let prog_has_ext = prog_leaf.contains('.');

        for dir_opt in search_dirs {
            let mut candidates = Vec::new();
            if prog_has_ext {
                candidates.push(prog.to_owned());
            }
            for ext in &pathexts {
                candidates.push(format!("{prog}{ext}"));
            }
            if !prog_has_ext {
                candidates.push(prog.to_owned());
            }

            for cand in candidates {
                let full_query = match &dir_opt {
                    Some(dir_path) => dir_path.join_component(&cand).to_windows_string(),
                    None => cand,
                };
                if let Some(meta) = self
                    .proc_env
                    .vfs
                    .stat(&full_query)
                    .ok()
                    .filter(|m| !m.attributes.is_directory())
                {
                    return Some(self.classify_resolved_file(meta));
                }
            }
        }
        None
    }

    /// Classifies a non-directory [`crate::vfs::VfsMetadata`] entry into a [`ResolvedCommandTarget`].
    ///
    /// # Arguments
    /// * `meta` - Stat metadata of the matched file.
    ///
    /// # Returns
    /// Classified [`ResolvedCommandTarget`].
    #[must_use]
    fn classify_resolved_file(&self, meta: crate::vfs::VfsMetadata) -> ResolvedCommandTarget {
        let path_ext = meta
            .name
            .rsplit_once('.')
            .filter(|(stem, _)| !stem.is_empty())
            .map(|(_, ext)| ext);
        if path_ext
            .is_some_and(|ext| ext.eq_ignore_ascii_case("bat") || ext.eq_ignore_ascii_case("cmd"))
        {
            return ResolvedCommandTarget::BatchScript {
                full_path: meta.full_path,
            };
        }
        if path_ext
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("com"))
        {
            let host_p = self.proc_env.vfs.resolve_host_path(&meta.full_path);
            return ResolvedCommandTarget::ExternalExecutable {
                full_path: meta.full_path,
                host_path: host_p,
            };
        }
        let lower_name = meta.name.to_ascii_lowercase();
        if let Some(dot_idx) = lower_name.rfind('.') {
            let ext = lower_name.get(dot_idx..).unwrap_or("");
            if let Some(ftype) = self.proc_env.registry_store.get_file_association(ext)
                && let Some(cmd_tmpl) = self.proc_env.registry_store.get_file_type(&ftype)
            {
                return ResolvedCommandTarget::AssociatedDocument {
                    full_path: meta.full_path,
                    file_type: ftype,
                    command_template: cmd_tmpl,
                };
            }
        }
        let host_p = self.proc_env.vfs.resolve_host_path(&meta.full_path);
        ResolvedCommandTarget::ExternalExecutable {
            full_path: meta.full_path,
            host_path: host_p,
        }
    }
}
