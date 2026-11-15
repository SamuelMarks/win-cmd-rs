//! Environment variable table, `SETLOCAL` / `ENDLOCAL` scope stack, and dynamic pseudo-variables.
//!
//! Preserves original variable name casing for display (`SET`) while matching keys
//! case-insensitively. Evaluates dynamic variables (`%CD%`, `%DATE%`, `%TIME%`, `%RANDOM%`,
//! `%ERRORLEVEL%`, `%CMDEXTVERSION%`, `%CMDCMDLINE%`, `%HIGHESTNUMANODENUMBER%`, `%=ExitCode%`,
//! `%=ExitCodeAscii%`) when not explicitly overridden by user `SET`, advancing `%RANDOM%` on
//! every individual expansion and translating POSIX `PATH` segments on host overlay.

use std::cell::Cell;
use std::collections::BTreeMap;

use crate::types::{
    BS_STR, DelayedExpansionMode, DriveLetter, EnvVarName, ExitCode, ExtensionsMode,
};
use crate::vfs::path::WindowsPath;

/// Default Windows `COMSPEC` value (`C:\Windows\System32\cmd.exe`).
const DEFAULT_COMSPEC: &str = r"C:\Windows\System32\cmd.exe";

/// Default Windows `PATH` value (`C:\Windows\System32;C:\Windows`).
const DEFAULT_WIN_PATH: &str = r"C:\Windows\System32;C:\Windows";

/// Default Windows root (`C:\Windows`).
const DEFAULT_WINDIR: &str = r"C:\Windows";

/// Default Windows `TEMP` directory (`C:\Temp`).
const DEFAULT_TEMP: &str = r"C:\Temp";

/// A saved `SETLOCAL` snapshot frame on the [`EnvironmentStack`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvScopeFrame {
    /// Snapshot of environment variables before `SETLOCAL`.
    pub vars: BTreeMap<EnvVarName, String>,
    /// Snapshot of delayed expansion mode before `SETLOCAL`.
    pub delayed_expansion: DelayedExpansionMode,
    /// Snapshot of command extensions mode before `SETLOCAL`.
    pub extensions: ExtensionsMode,
    /// Snapshot of active drive before `SETLOCAL`.
    pub saved_drive: DriveLetter,
    /// Snapshot of active drive's CWD before `SETLOCAL`.
    pub saved_cwd: WindowsPath,
}

/// Scoped environment variable table and `SETLOCAL` / `ENDLOCAL` stack.
#[derive(Debug, Clone)]
pub struct EnvironmentStack {
    /// Active environment variable map.
    vars: BTreeMap<EnvVarName, String>,
    /// Active delayed expansion mode.
    pub delayed_expansion: DelayedExpansionMode,
    /// Active command extensions mode.
    pub extensions: ExtensionsMode,
    /// Stack of saved [`EnvScopeFrame`]s pushed by `SETLOCAL`.
    frames: Vec<EnvScopeFrame>,
    /// Current `DATE` string (configurable for deterministic tests).
    pub virtual_date: String,
    /// Current `TIME` string (configurable for deterministic tests).
    pub virtual_time: String,
    /// Raw command line used to invoke `cmd.exe` (`%CMDCMDLINE%`).
    pub cmd_cmdline: String,
    /// Interior-mutable LCG PRNG state so every `%RANDOM%` read advances the sequence.
    rng_state: Cell<u64>,
}

impl Default for EnvironmentStack {
    /// Returns a new [`EnvironmentStack`] initialized with standard Windows environment defaults.
    ///
    /// # Returns
    /// Default [`EnvironmentStack`].
    fn default() -> Self {
        Self::new()
    }
}

impl EnvironmentStack {
    /// Constructs a new [`EnvironmentStack`] populated with standard Windows environment variables.
    ///
    /// # Returns
    /// An initialized [`EnvironmentStack`].
    #[must_use]
    pub fn new() -> Self {
        let mut vars = BTreeMap::new();
        vars.insert(EnvVarName::new("COMSPEC"), DEFAULT_COMSPEC.to_owned());
        vars.insert(EnvVarName::new("PATH"), DEFAULT_WIN_PATH.to_owned());
        vars.insert(
            EnvVarName::new("PATHEXT"),
            ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC".to_owned(),
        );
        vars.insert(EnvVarName::new("PROMPT"), "$P$G".to_owned());
        vars.insert(EnvVarName::new("OS"), "Windows_NT".to_owned());
        vars.insert(EnvVarName::new("SystemDrive"), "C:".to_owned());
        vars.insert(EnvVarName::new("SystemRoot"), DEFAULT_WINDIR.to_owned());
        vars.insert(EnvVarName::new("windir"), DEFAULT_WINDIR.to_owned());
        vars.insert(EnvVarName::new("TEMP"), DEFAULT_TEMP.to_owned());
        vars.insert(EnvVarName::new("TMP"), DEFAULT_TEMP.to_owned());
        vars.insert(EnvVarName::new("=C:"), format!("C:{BS_STR}"));
        vars.insert(EnvVarName::new("=D:"), format!("D:{BS_STR}"));

        Self {
            vars,
            delayed_expansion: DelayedExpansionMode::Disabled,
            extensions: ExtensionsMode::Enabled,
            frames: Vec::new(),
            virtual_date: "Tue 11/10/2026".to_owned(),
            virtual_time: " 9:00:00.00".to_owned(),
            cmd_cmdline: format!(r#""{DEFAULT_COMSPEC}""#),
            rng_state: Cell::new(12345),
        }
    }

    /// Constructs an [`EnvironmentStack`] initialized with defaults and overlaid with key-value
    /// pairs from an iterator (such as `std::env::vars()`), translating colon-separated POSIX
    /// `PATH` entries (`/usr/bin:/bin`) into `Z:`-mapped `;`-separated Windows paths.
    ///
    /// # Arguments
    /// * `host_vars` - Iterator of `(key, value)` environment variable pairs from the host OS.
    ///
    /// # Returns
    /// A populated [`EnvironmentStack`].
    #[must_use]
    pub fn from_host_iter<I, K, V>(host_vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut stack = Self::new();
        for (k, v) in host_vars {
            let key_str = k.as_ref();
            let val_str = v.as_ref();
            if !key_str.is_empty() && !val_str.is_empty() {
                if key_str.eq_ignore_ascii_case("PATH") {
                    let translated = translate_host_path_to_windows(val_str);
                    stack.set(key_str, &translated);
                } else {
                    stack.set(key_str, val_str);
                }
            }
        }
        stack
    }

    /// Updates the hidden per-drive current working directory variable (e.g., `=C:=C:\Users`).
    ///
    /// # Arguments
    /// * `drive` - The [`DriveLetter`] whose CWD changed.
    /// * `cwd_path` - The new [`WindowsPath`] working directory on `drive`.
    pub fn set_drive_cwd_var(&mut self, drive: DriveLetter, cwd_path: &WindowsPath) {
        let key = drive.env_var_key();
        self.set(&key, &cwd_path.to_windows_string());
    }

    /// Removes the hidden per-drive current working directory variable (e.g., when unmounting a `PUSHD` UNC drive).
    ///
    /// # Arguments
    /// * `drive` - The [`DriveLetter`] being unmounted.
    pub fn remove_drive_cwd_var(&mut self, drive: DriveLetter) {
        let key = drive.env_var_key();
        self.remove(&key);
    }

    /// Sets or updates an environment variable (updating the stored key's display casing).
    ///
    /// If `value` is empty, removes the variable from the environment.
    ///
    /// # Arguments
    /// * `name` - Variable name string.
    /// * `value` - Value string (empty removes the variable).
    pub fn set(&mut self, name: &str, value: &str) {
        let key = EnvVarName::new(name);
        self.vars.remove(&key);
        if !value.is_empty() {
            self.vars.insert(key, value.to_owned());
        }
    }

    /// Removes an environment variable by name.
    ///
    /// # Arguments
    /// * `name` - Variable name to remove.
    pub fn remove(&mut self, name: &str) {
        self.vars.remove(&EnvVarName::new(name));
    }

    /// Checks whether `name` is explicitly defined in the environment map (`IF DEFINED`).
    ///
    /// Note: In `cmd.exe`, `IF DEFINED` only tests explicit environment variables, NOT dynamic
    /// pseudo-variables (unless the user explicitly ran `SET ERRORLEVEL=...`).
    ///
    /// # Arguments
    /// * `name` - Variable name to check.
    ///
    /// # Returns
    /// `true` if `name` is present in `self.vars`.
    #[must_use]
    pub fn is_defined(&self, name: &str) -> bool {
        self.vars.contains_key(&EnvVarName::new(name))
    }

    /// Looks up a variable, checking explicit variables first and falling back to dynamic
    /// `cmd.exe` pseudo-variables when Command Extensions are enabled.
    ///
    /// Evaluating `%RANDOM%` advances the internal LCG PRNG state on every call so multiple
    /// `%RANDOM%` expansions on a single line yield distinct values in `0..=32767`.
    ///
    /// # Arguments
    /// * `name` - Variable name to resolve.
    /// * `cwd` - Current working directory string (`%CD%`).
    /// * `exit_code` - Current [`ExitCode`] (`%ERRORLEVEL%`, `%=ExitCode%`, `%=ExitCodeAscii%`).
    ///
    /// # Returns
    /// `Some(String)` if defined or recognized as a dynamic variable, otherwise `None`.
    #[must_use]
    pub fn get_with_dynamics(&self, name: &str, cwd: &str, exit_code: ExitCode) -> Option<String> {
        let key = EnvVarName::new(name);
        if let Some(explicit) = self.vars.get(&key) {
            return Some(explicit.clone());
        }

        if matches!(self.extensions, ExtensionsMode::Enabled) {
            match key.folded() {
                "CD" => return Some(cwd.to_owned()),
                "DATE" => return Some(self.virtual_date.clone()),
                "TIME" => return Some(self.virtual_time.clone()),
                "ERRORLEVEL" => return Some(exit_code.code().to_string()),
                "CMDEXTVERSION" => return Some("2".to_owned()),
                "CMDCMDLINE" => return Some(self.cmd_cmdline.clone()),
                "HIGHESTNUMANODENUMBER" => return Some("0".to_owned()),
                "RANDOM" => {
                    let next_seed = self
                        .rng_state
                        .get()
                        .wrapping_mul(1_103_515_245)
                        .wrapping_add(12345);
                    self.rng_state.set(next_seed);
                    let r = (next_seed >> 16) & 0x7FFF;
                    return Some(r.to_string());
                }
                "=EXITCODE" => return Some(exit_code.to_hex_string()),
                "=EXITCODEASCII" => return Some(exit_code.to_ascii_string()),
                _ => {}
            }
        }
        None
    }

    /// Advances the internal PRNG seed by one LCG step.
    pub fn step_random(&mut self) {
        let next = self
            .rng_state
            .get()
            .wrapping_mul(1_103_515_245)
            .wrapping_add(12345);
        self.rng_state.set(next);
    }

    /// Sets the deterministic `%RANDOM%` PRNG seed.
    ///
    /// # Arguments
    /// * `seed` - New 64-bit LCG seed value.
    pub fn set_rng_seed(&mut self, seed: u64) {
        self.rng_state.set(seed);
    }

    /// Returns all non-hidden user environment variables sorted alphabetically by name (`SET`).
    ///
    /// # Returns
    /// Vector of `(&str, &str)` `(original_name, value)` pairs.
    #[must_use]
    pub fn list_visible(&self) -> Vec<(&str, &str)> {
        self.vars
            .iter()
            .filter(|(k, _)| !k.is_hidden())
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    /// Returns all visible environment variables whose names start with `prefix` (case-insensitively).
    ///
    /// # Arguments
    /// * `prefix` - Prefix string to match.
    ///
    /// # Returns
    /// Vector of `(&str, &str)` matching pairs.
    #[must_use]
    pub fn list_by_prefix(&self, prefix: &str) -> Vec<(&str, &str)> {
        let upper_prefix = prefix.to_ascii_uppercase();
        self.vars
            .iter()
            .filter(|(k, _)| !k.is_hidden() && k.folded().starts_with(&upper_prefix))
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    /// Returns a vector of all stored environment variables (including hidden `=C:` variables).
    ///
    /// # Returns
    /// Vector of `(String, String)` pairs for all defined variables.
    #[must_use]
    pub fn list_all(&self) -> Vec<(String, String)> {
        self.vars
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.clone()))
            .collect()
    }

    /// Replaces the active variable map with a snapshot (used by `START /I`).
    ///
    /// # Arguments
    /// * `snapshot` - Slice of `(String, String)` pairs to restore.
    pub fn restore_snapshot(&mut self, snapshot: &[(String, String)]) {
        self.vars.clear();
        for (k, v) in snapshot {
            self.set(k, v);
        }
    }

    /// Constructs the complete case-preserved environment map to pass to a spawned child OS process,
    /// including hidden per-drive CWDs (`=C:`, `=D:`, etc.) and `=ExitCode`.
    ///
    /// # Arguments
    /// * `vfs` - Active [`crate::vfs::VirtualFileSystem`] used to query per-drive CWDs.
    /// * `last_exit` - Current [`ExitCode`] exported as `=ExitCode`.
    ///
    /// # Returns
    /// [`BTreeMap`] of environment variable names to values.
    #[must_use]
    pub fn build_child_process_env(
        &self,
        vfs: &dyn crate::vfs::VirtualFileSystem,
        last_exit: ExitCode,
    ) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (k, v) in &self.vars {
            out.insert(k.as_str().to_owned(), v.clone());
        }
        for b in b'A'..=b'Z' {
            let d = DriveLetter::try_from_char(b as char).unwrap_or(DriveLetter::C);
            if let Ok(cwd_p) = vfs.drive_cwd(d) {
                out.insert(d.env_var_key(), cwd_p.to_windows_string());
            }
        }
        out.insert("=ExitCode".to_owned(), last_exit.to_hex_string());
        out
    }

    /// Pushes a new `SETLOCAL` frame onto the stack (`SETLOCAL`).
    ///
    /// # Arguments
    /// * `current_drive` - Active [`DriveLetter`] at the time of `SETLOCAL`.
    /// * `current_cwd` - Active [`WindowsPath`] CWD at the time of `SETLOCAL`.
    pub fn push_setlocal(&mut self, current_drive: DriveLetter, current_cwd: WindowsPath) {
        self.frames.push(EnvScopeFrame {
            vars: self.vars.clone(),
            delayed_expansion: self.delayed_expansion,
            extensions: self.extensions,
            saved_drive: current_drive,
            saved_cwd: current_cwd,
        });
    }

    /// Pops the top `SETLOCAL` frame and restores variables and mode flags (`ENDLOCAL`).
    ///
    /// # Returns
    /// `Some((saved_drive, saved_cwd))` if a frame was popped so the caller can restore VFS CWD,
    /// or `None` if the `SETLOCAL` stack was empty.
    pub fn pop_endlocal(&mut self) -> Option<(DriveLetter, WindowsPath)> {
        let frame = self.frames.pop()?;
        self.vars = frame.vars;
        self.delayed_expansion = frame.delayed_expansion;
        self.extensions = frame.extensions;
        Some((frame.saved_drive, frame.saved_cwd))
    }

    /// Returns the current number of active `SETLOCAL` frames on the stack.
    ///
    /// # Returns
    /// Current `SETLOCAL` depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.frames.len()
    }
}

/// Translates a POSIX colon-separated `PATH` (`/usr/local/bin:/usr/bin`) into semicolon-separated
/// `Z:`-mounted Windows paths while preserving native `;`-separated Windows `PATH` strings.
///
/// # Arguments
/// * `raw_path` - Host `PATH` value.
///
/// # Returns
/// Semicolon-delimited Windows `PATH` string.
fn translate_host_path_to_windows(raw_path: &str) -> String {
    let looks_windows = raw_path.contains(';')
        || (raw_path.len() >= 3
            && raw_path
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            && raw_path.as_bytes().get(1) == Some(&b':'));
    if looks_windows {
        return raw_path.to_owned();
    }

    let mut mapped: Vec<String> = raw_path
        .split(':')
        .map(str::trim)
        .filter(|seg| !seg.is_empty())
        .map(|seg| {
            let clean = seg.trim_start_matches('/').replace('/', BS_STR);
            if clean.is_empty() {
                format!("Z:{BS_STR}")
            } else {
                format!("Z:{BS_STR}{clean}")
            }
        })
        .collect();
    mapped.push(DEFAULT_WIN_PATH.to_owned());
    mapped.join(";")
}

#[cfg(test)]
/// Unit tests for [`EnvironmentStack`], `%RANDOM%` stepping, `SETLOCAL`, and POSIX `PATH` mapping.
mod tests {
    use super::*;

    /// Verifies dynamic variables (`CD`, `DATE`, `TIME`, `ERRORLEVEL`, `RANDOM`), `SETLOCAL`, and `ENDLOCAL`.
    #[test]
    fn test_environment_stack_dynamics_random_and_setlocal() {
        let mut env = EnvironmentStack::default();
        env.set_rng_seed(12345);
        assert!(env.is_defined("PATH"));
        assert!(!env.is_defined("ERRORLEVEL"));

        env.set("MyVar", "Initial");
        assert_eq!(
            env.get_with_dynamics("myvar", "C:", ExitCode::SUCCESS),
            Some("Initial".to_owned())
        );

        let c_work = format!("C:{BS_STR}Work");
        assert_eq!(
            env.get_with_dynamics("CD", &c_work, ExitCode::SUCCESS),
            Some(c_work)
        );
        assert_eq!(
            env.get_with_dynamics("DATE", "C:", ExitCode::SUCCESS),
            Some("Tue 11/10/2026".to_owned())
        );
        assert_eq!(
            env.get_with_dynamics("TIME", "C:", ExitCode::SUCCESS),
            Some(" 9:00:00.00".to_owned())
        );
        assert_eq!(
            env.get_with_dynamics("ERRORLEVEL", "C:", ExitCode::new(5)),
            Some("5".to_owned())
        );
        assert_eq!(
            env.get_with_dynamics("CMDEXTVERSION", "C:", ExitCode::SUCCESS),
            Some("2".to_owned())
        );
        assert!(
            env.get_with_dynamics("CMDCMDLINE", "C:", ExitCode::SUCCESS)
                .is_some()
        );
        assert_eq!(
            env.get_with_dynamics("HIGHESTNUMANODENUMBER", "C:", ExitCode::SUCCESS),
            Some("0".to_owned())
        );

        // Consecutive `%RANDOM%` reads on the same line MUST return distinct values!
        let r1 = env.get_with_dynamics("RANDOM", "C:", ExitCode::SUCCESS);
        let r2 = env.get_with_dynamics("RANDOM", "C:", ExitCode::SUCCESS);
        assert!(r1.is_some());
        assert!(r2.is_some());
        assert_ne!(r1, r2);

        env.step_random();
        assert_eq!(
            env.get_with_dynamics("=ExitCode", "C:", ExitCode::new(65)),
            Some("00000041".to_owned())
        );
        assert_eq!(
            env.get_with_dynamics("=ExitCodeAscii", "C:", ExitCode::new(65)),
            Some("A".to_owned())
        );

        // SETLOCAL / ENDLOCAL restoration
        env.push_setlocal(DriveLetter::C, WindowsPath::root(DriveLetter::C));
        assert_eq!(env.depth(), 1);
        env.delayed_expansion = DelayedExpansionMode::Enabled;
        env.set("MyVar", "Modified");
        env.set("=Hidden", "Secret");
        assert!(!env.list_visible().iter().any(|(k, _)| *k == "=Hidden"));
        assert_eq!(env.list_by_prefix("My").len(), 1);

        let popped = env.pop_endlocal();
        assert!(popped.is_some());
        assert!(env.pop_endlocal().is_none());
        assert_eq!(env.delayed_expansion, DelayedExpansionMode::Disabled);
        assert_eq!(
            env.get_with_dynamics("MyVar", "C:", ExitCode::SUCCESS),
            Some("Initial".to_owned())
        );

        env.set("MyVar", "");
        assert!(!env.is_defined("MyVar"));
        env.set("TempVar", "1");
        env.remove("TempVar");
        assert!(!env.is_defined("TempVar"));

        env.extensions = ExtensionsMode::Disabled;
        assert_eq!(env.get_with_dynamics("CD", "C:", ExitCode::SUCCESS), None);
    }

    /// Verifies POSIX `PATH` translation, Windows `PATH` preservation, per-drive `=Z:` variables, and child env snapshots.
    #[test]
    fn test_environment_stack_posix_path_drive_cwd_and_child_env() {
        let mut host_env = EnvironmentStack::from_host_iter([
            ("CUSTOM_HOST", "val1"),
            ("PATH", "/usr/local/bin:/:/bin:"),
            ("EMPTY_VAL", ""),
            ("", "ignored"),
        ]);
        assert_eq!(
            host_env.get_with_dynamics("CUSTOM_HOST", "C:", ExitCode::SUCCESS),
            Some("val1".to_owned())
        );
        assert_eq!(
            host_env.get_with_dynamics("PATH", "C:", ExitCode::SUCCESS),
            Some(format!(
                "Z:{BS_STR}usr{BS_STR}local{BS_STR}bin;Z:{BS_STR};Z:{BS_STR}bin;{DEFAULT_WIN_PATH}"
            ))
        );

        let win_host_env = EnvironmentStack::from_host_iter([("PATH", "C:/Tools;C:/Windows")]);
        assert_eq!(
            win_host_env.get_with_dynamics("PATH", "C:", ExitCode::SUCCESS),
            Some("C:/Tools;C:/Windows".to_owned())
        );
        let single_win_drive = EnvironmentStack::from_host_iter([("PATH", "D:/Bin")]);
        assert_eq!(
            single_win_drive.get_with_dynamics("PATH", "C:", ExitCode::SUCCESS),
            Some("D:/Bin".to_owned())
        );
        let root_posix = EnvironmentStack::from_host_iter([("PATH", "/")]);
        assert_eq!(
            root_posix.get_with_dynamics("PATH", "C:", ExitCode::SUCCESS),
            Some(format!("Z:{BS_STR};{DEFAULT_WIN_PATH}"))
        );

        let z_root = WindowsPath::root(DriveLetter::Z);
        host_env.set_drive_cwd_var(DriveLetter::Z, &z_root);
        assert_eq!(
            host_env.get_with_dynamics("=Z:", "C:", ExitCode::SUCCESS),
            Some(format!("Z:{BS_STR}"))
        );
        host_env.remove_drive_cwd_var(DriveLetter::Z);
        assert_eq!(
            host_env.get_with_dynamics("=Z:", "C:", ExitCode::SUCCESS),
            None
        );

        let snap = host_env.list_all();
        host_env.set("EXTRA_TEMP", "1");
        host_env.restore_snapshot(&snap);
        assert!(!host_env.is_defined("EXTRA_TEMP"));
        let vfs = crate::vfs::InMemoryVfs::new();
        let child_map = host_env.build_child_process_env(&vfs, ExitCode::new(7));
        assert_eq!(child_map.get("=ExitCode"), Some(&"00000007".to_owned()));
        assert_eq!(child_map.get("=C:"), Some(&format!("C:{BS_STR}")));
    }
}
