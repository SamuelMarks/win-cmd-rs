//! Cross-Platform Windows & Wine Registry Store (`HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`).
//!
//! Emulates the Windows Registry hierarchy used by `cmd.exe` (`AutoRun`, `ASSOC`, `FTYPE`,
//! `EnableExtensions`, `DelayedExpansion`, `DefaultColor`) and by the `REG` command-line
//! utility (`REG QUERY`, `REG ADD`, `REG DELETE`, `REG COPY`, `REG EXPORT`, `REG IMPORT`).
//! Also supports importing and exporting standard `.reg` files (`Windows Registry Editor Version 5.00`)
//! and Wine registry files (`WINE REGISTRY Version 2`).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use derive_more::{Display, IsVariant};

use crate::error::CmdError;
use crate::types::{
    BS_CHAR, BS_STR, ConsoleColor, DOUBLE_BS_STR, DelayedExpansionMode, ExtensionsMode, LF_CHAR,
};

/// Escaped double-quote slice (`\"`).
const ESCAPED_QUOTE_STR: &str = r#"\""#;

/// Canonical HKLM Command Processor key path.
pub const HKLM_CMD_PROCESSOR_KEY: &str = "HKLM/Software/Microsoft/Command Processor";

/// Canonical HKCU Command Processor key path.
pub const HKCU_CMD_PROCESSOR_KEY: &str = "HKCU/Software/Microsoft/Command Processor";

/// Target scope of a `REG DELETE` or `.reg` deletion operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, IsVariant)]
pub enum RegistryDeleteTarget<'a> {
    /// Delete the entire key and all recursive subkeys (`REG DELETE HKCU\Key /f`).
    EntireKey,
    /// Delete all values inside the key while keeping the key (`REG DELETE HKCU\Key /va /f`).
    AllValues,
    /// Delete a specific named value (`""` for the `(Default)` `/ve` value).
    Value(&'a str),
}

/// Top-level Windows Registry hive root (`HKEY_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display, IsVariant)]
pub enum RegistryHive {
    /// `HKEY_LOCAL_MACHINE` (`HKLM`).
    #[display("HKEY_LOCAL_MACHINE")]
    LocalMachine,
    /// `HKEY_CURRENT_USER` (`HKCU`).
    #[display("HKEY_CURRENT_USER")]
    CurrentUser,
    /// `HKEY_CLASSES_ROOT` (`HKCR`).
    #[display("HKEY_CLASSES_ROOT")]
    ClassesRoot,
    /// `HKEY_USERS` (`HKU`).
    #[display("HKEY_USERS")]
    Users,
    /// `HKEY_CURRENT_CONFIG` (`HKCC`).
    #[display("HKEY_CURRENT_CONFIG")]
    CurrentConfig,
}

impl RegistryHive {
    /// Parses a hive prefix (`HKLM`, `HKEY_LOCAL_MACHINE`, etc.) case-insensitively.
    ///
    /// # Arguments
    /// * `raw` - Raw hive token.
    ///
    /// # Returns
    /// `Some(RegistryHive)` if recognized.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => Some(Self::LocalMachine),
            "HKCU" | "HKEY_CURRENT_USER" => Some(Self::CurrentUser),
            "HKCR" | "HKEY_CLASSES_ROOT" => Some(Self::ClassesRoot),
            "HKU" | "HKEY_USERS" => Some(Self::Users),
            "HKCC" | "HKEY_CURRENT_CONFIG" => Some(Self::CurrentConfig),
            _ => None,
        }
    }
}

/// Windows Registry value data type (`REG_SZ`, `REG_DWORD`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, IsVariant)]
pub enum RegistryValueType {
    /// Null-terminated string (`REG_SZ`).
    #[default]
    #[display("REG_SZ")]
    Sz,
    /// String with unexpanded `%VAR%` references (`REG_EXPAND_SZ`).
    #[display("REG_EXPAND_SZ")]
    ExpandSz,
    /// Multi-string array (`REG_MULTI_SZ`).
    #[display("REG_MULTI_SZ")]
    MultiSz,
    /// 32-bit unsigned integer (`REG_DWORD`).
    #[display("REG_DWORD")]
    Dword,
    /// 64-bit unsigned integer (`REG_QWORD`).
    #[display("REG_QWORD")]
    Qword,
    /// Arbitrary binary data (`REG_BINARY`).
    #[display("REG_BINARY")]
    Binary,
    /// Untyped value (`REG_NONE`).
    #[display("REG_NONE")]
    None,
}

impl RegistryValueType {
    /// Parses a `REG /t` type argument case-insensitively.
    ///
    /// # Arguments
    /// * `raw` - Type string (e.g., `"REG_SZ"`, `"REG_DWORD"`).
    ///
    /// # Returns
    /// `Some(RegistryValueType)` if valid.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "REG_SZ" => Some(Self::Sz),
            "REG_EXPAND_SZ" => Some(Self::ExpandSz),
            "REG_MULTI_SZ" => Some(Self::MultiSz),
            "REG_DWORD" => Some(Self::Dword),
            "REG_QWORD" => Some(Self::Qword),
            "REG_BINARY" => Some(Self::Binary),
            "REG_NONE" => Some(Self::None),
            _ => None,
        }
    }

    /// Parses a `REG /t` value type string for `key`, returning [`CmdError::InvalidRegistryValue`] if invalid.
    ///
    /// # Arguments
    /// * `key` - Registry key path associated with the operation.
    /// * `raw` - Raw `/t` type name string.
    ///
    /// # Returns
    /// `Ok(RegistryValueType)` when recognized.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidRegistryValue`] if `raw` is not a recognized `REG_*` type.
    pub fn parse_for_key(key: &str, raw: &str) -> Result<Self, CmdError> {
        Self::parse(raw).ok_or_else(|| CmdError::InvalidRegistryValue {
            key: key.to_owned(),
            value: raw.to_owned(),
        })
    }
}

/// A single stored Registry value entry inside a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryValue {
    /// Original display name of the value (empty `""` for the `(Default)` / `/ve` value).
    pub name: String,
    /// Data type of the value.
    pub kind: RegistryValueType,
    /// String representation of the data (e.g., `"0x1"` for `REG_DWORD` or text for `REG_SZ`).
    pub data: String,
}

impl RegistryValue {
    /// Returns the display name used by `reg.exe query` (`"(Default)"` when `name` is empty).
    ///
    /// # Returns
    /// Display name string slice.
    #[must_use]
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            "(Default)"
        } else {
            &self.name
        }
    }

    /// Parses this value's data as a 32-bit unsigned integer (`0x1` hex or decimal).
    ///
    /// # Returns
    /// `Some(u32)` if the stored data represents a valid hex or decimal `u32`, else `None`.
    #[must_use]
    pub fn as_u32(&self) -> Option<u32> {
        let trimmed = self.data.trim();
        trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .map_or_else(
                || trimmed.parse::<u32>().ok(),
                |hex| u32::from_str_radix(hex, 16).ok(),
            )
    }
}

/// Canonicalized Registry key path (`Hive` + case-preserved/case-folded subkey components).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryKeyPath {
    /// Root hive (`HKLM`, `HKCU`, etc.).
    pub hive: RegistryHive,
    /// Subkey path components.
    pub components: Vec<String>,
}

impl RegistryKeyPath {
    /// Parses a full registry key path such as `HKLM/Software/Microsoft/Command Processor`
    /// or `[HKEY_CURRENT_USER/Software/Test]`.
    ///
    /// # Arguments
    /// * `raw` - Raw key path string.
    ///
    /// # Returns
    /// `Ok(RegistryKeyPath)` if the root hive is valid.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidRegistryKey`] if the hive prefix is missing or invalid.
    pub fn parse(raw: &str) -> Result<Self, CmdError> {
        let trimmed = raw
            .trim()
            .trim_matches('"')
            .trim_start_matches('[')
            .trim_end_matches(']');
        let mut parts = trimmed.split([BS_CHAR, '/']).filter(|s| !s.is_empty());
        let Some(first) = parts.next() else {
            return Err(CmdError::InvalidRegistryKey {
                raw: raw.to_owned(),
            });
        };
        let Some(hive) = RegistryHive::parse(first) else {
            return Err(CmdError::InvalidRegistryKey {
                raw: raw.to_owned(),
            });
        };
        let components: Vec<String> = parts.map(str::to_owned).collect();
        Ok(Self { hive, components })
    }

    /// Returns the uppercase lookup tuple `(RegistryHive, Vec<UPPERCASE>)`.
    ///
    /// # Returns
    /// Lookup key tuple.
    #[must_use]
    pub fn lookup_key(&self) -> (RegistryHive, Vec<String>) {
        (
            self.hive,
            self.components
                .iter()
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        )
    }

    /// Formats the full key path in `reg.exe` display format (`HKEY_LOCAL_MACHINE\Software\...`).
    ///
    /// # Returns
    /// Full key path string.
    #[must_use]
    pub fn to_full_string(&self) -> String {
        if self.components.is_empty() {
            self.hive.to_string()
        } else {
            format!("{}{BS_STR}{}", self.hive, self.components.join(BS_STR))
        }
    }
}

/// Internal node for a single Registry key in [`RegistryStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryKeyNode {
    /// Case-preserved key path.
    pub path: RegistryKeyPath,
    /// Values stored in this key, keyed by uppercase value name (`""` for default value).
    pub values: BTreeMap<String, RegistryValue>,
}

/// In-memory and `.reg`-serializable Windows/Wine Registry store.
#[derive(Debug, Clone)]
pub struct RegistryStore {
    /// Map from `(RegistryHive, Vec<UPPERCASE_SUBKEY>)` to [`RegistryKeyNode`].
    pub keys: BTreeMap<(RegistryHive, Vec<String>), RegistryKeyNode>,
}

impl Default for RegistryStore {
    /// Returns a new [`RegistryStore`] populated with standard Windows Command Processor keys.
    ///
    /// # Returns
    /// Default [`RegistryStore`].
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryStore {
    /// Constructs a new [`RegistryStore`] pre-populated with standard Windows Command Processor
    /// keys and default file associations (`.txt`, `.bat`, `.cmd`).
    ///
    /// # Returns
    /// Initialized [`RegistryStore`].
    #[must_use]
    pub fn new() -> Self {
        let mut store = Self {
            keys: BTreeMap::new(),
        };
        let cmd_proc = RegistryKeyPath {
            hive: RegistryHive::LocalMachine,
            components: vec![
                "Software".to_owned(),
                "Microsoft".to_owned(),
                "Command Processor".to_owned(),
            ],
        };
        store.set_key_path_value(
            &cmd_proc,
            "EnableExtensions",
            RegistryValueType::Dword,
            "0x1",
        );
        store.set_key_path_value(
            &cmd_proc,
            "DelayedExpansion",
            RegistryValueType::Dword,
            "0x0",
        );
        for (ext, ftype, kind, open_cmd) in [
            (
                ".txt",
                "txtfile",
                RegistryValueType::ExpandSz,
                "notepad.exe %1",
            ),
            (".bat", "batfile", RegistryValueType::Sz, r#""%1" %*"#),
            (".cmd", "cmdfile", RegistryValueType::Sz, r#""%1" %*"#),
        ] {
            let ext_kp = RegistryKeyPath {
                hive: RegistryHive::ClassesRoot,
                components: vec![ext.to_owned()],
            };
            store.set_key_path_value(&ext_kp, "", RegistryValueType::Sz, ftype);
            let open_kp = RegistryKeyPath {
                hive: RegistryHive::ClassesRoot,
                components: vec![
                    ftype.to_owned(),
                    "shell".to_owned(),
                    "open".to_owned(),
                    "command".to_owned(),
                ],
            };
            store.set_key_path_value(&open_kp, "", kind, open_cmd);
        }
        store
    }

    /// Reads the live `(machine_autorun, user_autorun)` `AutoRun` command strings from `HKLM` and `HKCU`.
    ///
    /// # Returns
    /// `(Option<String>, Option<String>)` for `(HKLM AutoRun, HKCU AutoRun)`.
    #[must_use]
    pub fn command_processor_autorun(&self) -> (Option<String>, Option<String>) {
        let machine = self
            .get_value(HKLM_CMD_PROCESSOR_KEY, "AutoRun")
            .map(|v| v.data.clone())
            .filter(|s| !s.is_empty());
        let user = self
            .get_value(HKCU_CMD_PROCESSOR_KEY, "AutoRun")
            .map(|v| v.data.clone())
            .filter(|s| !s.is_empty());
        (machine, user)
    }

    /// Queries the effective `EnableExtensions` setting (`HKCU` overriding `HKLM`).
    ///
    /// # Returns
    /// `Some(ExtensionsMode)` if configured in `HKCU` or `HKLM`, else `None`.
    #[must_use]
    pub fn command_processor_extensions(&self) -> Option<ExtensionsMode> {
        let val = self
            .get_value(HKCU_CMD_PROCESSOR_KEY, "EnableExtensions")
            .or_else(|| self.get_value(HKLM_CMD_PROCESSOR_KEY, "EnableExtensions"))?
            .as_u32()?;
        Some(if val == 0 {
            ExtensionsMode::Disabled
        } else {
            ExtensionsMode::Enabled
        })
    }

    /// Queries the effective `DelayedExpansion` setting (`HKCU` overriding `HKLM`).
    ///
    /// # Returns
    /// `Some(DelayedExpansionMode)` if configured in `HKCU` or `HKLM`, else `None`.
    #[must_use]
    pub fn command_processor_delayed_expansion(&self) -> Option<DelayedExpansionMode> {
        let val = self
            .get_value(HKCU_CMD_PROCESSOR_KEY, "DelayedExpansion")
            .or_else(|| self.get_value(HKLM_CMD_PROCESSOR_KEY, "DelayedExpansion"))?
            .as_u32()?;
        Some(if val == 0 {
            DelayedExpansionMode::Disabled
        } else {
            DelayedExpansionMode::Enabled
        })
    }

    /// Queries the effective `DefaultColor` console color (`HKCU` overriding `HKLM`).
    ///
    /// # Returns
    /// `Some(ConsoleColor)` if configured and valid (`bg != fg`, `<= 0xFF`), else `None`.
    #[must_use]
    pub fn command_processor_default_color(&self) -> Option<ConsoleColor> {
        let raw = self
            .get_value(HKCU_CMD_PROCESSOR_KEY, "DefaultColor")
            .or_else(|| self.get_value(HKLM_CMD_PROCESSOR_KEY, "DefaultColor"))?
            .as_u32()?;
        if raw == 0 || raw > 0xFF {
            return None;
        }
        ConsoleColor::parse_hex(&format!("{raw:02X}")).ok()
    }

    /// Lists all active file extension associations (`HKCR\.ext` default values) sorted by key.
    ///
    /// # Returns
    /// Ordered `(extension, file_type)` pairs.
    #[must_use]
    pub fn file_associations(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for ((hive, _), node) in &self.keys {
            if *hive == RegistryHive::ClassesRoot
                && let [ext] = node.path.components.as_slice()
                && ext.starts_with('.')
                && let Some(val) = node.values.get("")
                && !val.data.is_empty()
            {
                out.push((ext.clone(), val.data.clone()));
            }
        }
        out
    }

    /// Queries the registered file type for a file extension (`HKCR\.ext` default value).
    ///
    /// # Arguments
    /// * `ext` - File extension with or without leading `.` (e.g., `".bat"` or `"bat"`).
    ///
    /// # Returns
    /// `Some(String)` containing the registered file type name if present and non-empty.
    #[must_use]
    pub fn get_file_association(&self, ext: &str) -> Option<String> {
        let norm = if ext.starts_with('.') {
            ext.to_owned()
        } else {
            format!(".{ext}")
        };
        self.get_value(&format!("HKCR/{norm}"), "")
            .map(|v| v.data.clone())
            .filter(|s| !s.is_empty())
    }

    /// Lists all active file type open command templates (`HKCR\<ftype>\shell\open\command` default values).
    ///
    /// # Returns
    /// Ordered `(file_type, command_template)` pairs.
    #[must_use]
    pub fn file_types(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for ((hive, _), node) in &self.keys {
            if *hive == RegistryHive::ClassesRoot
                && let [ftype, sub_shell, sub_open, sub_cmd] = node.path.components.as_slice()
                && sub_shell.eq_ignore_ascii_case("SHELL")
                && sub_open.eq_ignore_ascii_case("OPEN")
                && sub_cmd.eq_ignore_ascii_case("COMMAND")
                && let Some(val) = node.values.get("")
                && !val.data.is_empty()
            {
                out.push((ftype.clone(), val.data.clone()));
            }
        }
        out
    }

    /// Queries the registered open command template for `ftype` (`HKCR\<ftype>\shell\open\command`).
    ///
    /// # Arguments
    /// * `ftype` - File type identifier (e.g., `"batfile"` or `"Python.File"`).
    ///
    /// # Returns
    /// `Some(String)` containing the open command template if present and non-empty.
    #[must_use]
    pub fn get_file_type(&self, ftype: &str) -> Option<String> {
        self.get_value(&format!("HKCR/{ftype}/shell/open/command"), "")
            .map(|v| v.data.clone())
            .filter(|s| !s.is_empty())
    }

    /// Ensures a key and all its ancestor subkeys exist in the store and returns a mutable
    /// reference to the leaf [`RegistryKeyNode`].
    ///
    /// # Arguments
    /// * `key_path` - Parsed [`RegistryKeyPath`].
    ///
    /// # Returns
    /// Mutable reference to the leaf [`RegistryKeyNode`].
    pub fn ensure_key(&mut self, key_path: &RegistryKeyPath) -> &mut RegistryKeyNode {
        let root_path = RegistryKeyPath {
            hive: key_path.hive,
            components: Vec::new(),
        };
        self.keys
            .entry(root_path.lookup_key())
            .or_insert_with(|| RegistryKeyNode {
                path: root_path,
                values: BTreeMap::new(),
            });
        let parent_count = key_path.components.len().saturating_sub(1);
        let mut cur_comps = Vec::with_capacity(parent_count);
        for comp in key_path.components.iter().take(parent_count) {
            cur_comps.push(comp.clone());
            let sub_path = RegistryKeyPath {
                hive: key_path.hive,
                components: cur_comps.clone(),
            };
            let lk = sub_path.lookup_key();
            self.keys.entry(lk).or_insert_with(|| RegistryKeyNode {
                path: sub_path,
                values: BTreeMap::new(),
            });
        }
        let leaf_lk = key_path.lookup_key();
        self.keys.entry(leaf_lk).or_insert_with(|| RegistryKeyNode {
            path: key_path.clone(),
            values: BTreeMap::new(),
        })
    }

    /// Sets a value on an already-validated [`RegistryKeyPath`] (creating parent keys if needed).
    ///
    /// # Arguments
    /// * `key_path` - Validated [`RegistryKeyPath`].
    /// * `value_name` - Value name (`""` for default value).
    /// * `kind` - [`RegistryValueType`].
    /// * `data` - Value data string.
    pub fn set_key_path_value(
        &mut self,
        key_path: &RegistryKeyPath,
        value_name: &str,
        kind: RegistryValueType,
        data: &str,
    ) {
        let formatted_data = if kind == RegistryValueType::Dword {
            data.trim()
                .parse::<u32>()
                .map_or_else(|_| data.to_owned(), |n| format!("0x{n:x}"))
        } else {
            data.to_owned()
        };
        let node = self.ensure_key(key_path);
        node.values.insert(
            value_name.to_ascii_uppercase(),
            RegistryValue {
                name: value_name.to_owned(),
                kind,
                data: formatted_data,
            },
        );
    }

    /// Sets a value on a registry key (creating the key and parent keys if needed).
    ///
    /// # Arguments
    /// * `raw_key` - Key path string.
    /// * `value_name` - Value name (`""` for default value).
    /// * `kind` - [`RegistryValueType`].
    /// * `data` - Value data string.
    ///
    /// # Returns
    /// `Ok(())` when the value was stored.
    ///
    /// # Errors
    /// Returns [`CmdError::InvalidRegistryKey`] if `raw_key` has an invalid hive.
    pub fn set_value(
        &mut self,
        raw_key: &str,
        value_name: &str,
        kind: RegistryValueType,
        data: &str,
    ) -> Result<(), CmdError> {
        let key_path = RegistryKeyPath::parse(raw_key)?;
        self.set_key_path_value(&key_path, value_name, kind, data);
        Ok(())
    }

    /// Queries a specific value on a registry key.
    ///
    /// # Arguments
    /// * `raw_key` - Key path string.
    /// * `value_name` - Value name (`""` for default value).
    ///
    /// # Returns
    /// `Some(&RegistryValue)` if the key and value exist.
    #[must_use]
    pub fn get_value(&self, raw_key: &str, value_name: &str) -> Option<&RegistryValue> {
        let key_path = RegistryKeyPath::parse(raw_key).ok()?;
        let node = self.keys.get(&key_path.lookup_key())?;
        node.values.get(&value_name.to_ascii_uppercase())
    }

    /// Deletes a registry key subtree, all values in a key, or a single named value.
    ///
    /// # Arguments
    /// * `raw_key` - Key path string.
    /// * `target` - [`RegistryDeleteTarget`] specifying key-tree, `/va`, or `/v` deletion.
    ///
    /// # Returns
    /// `true` if the target existed and was deleted.
    pub fn delete_entry(&mut self, raw_key: &str, target: RegistryDeleteTarget<'_>) -> bool {
        let Ok(key_path) = RegistryKeyPath::parse(raw_key) else {
            return false;
        };
        let lk = key_path.lookup_key();
        match target {
            RegistryDeleteTarget::EntireKey => {
                let to_remove: Vec<(RegistryHive, Vec<String>)> = self
                    .keys
                    .keys()
                    .filter(|(h, comps)| *h == lk.0 && comps.starts_with(&lk.1))
                    .cloned()
                    .collect();
                let found = !to_remove.is_empty();
                for k in to_remove {
                    self.keys.remove(&k);
                }
                found
            }
            RegistryDeleteTarget::AllValues => {
                let Some(node) = self.keys.get_mut(&lk) else {
                    return false;
                };
                node.values.clear();
                true
            }
            RegistryDeleteTarget::Value(val_name) => {
                let Some(node) = self.keys.get_mut(&lk) else {
                    return false;
                };
                node.values.remove(&val_name.to_ascii_uppercase()).is_some()
            }
        }
    }

    /// Copies a registry key (and optionally its subkeys when `depth` is [`crate::types::TraversalDepth::Recursive`]) to `dst_raw`.
    ///
    /// # Arguments
    /// * `src_raw` - Source key path.
    /// * `dst_raw` - Destination key path.
    /// * `depth` - [`crate::types::TraversalDepth`] (`Shallow` vs `Recursive` for `/s`).
    ///
    /// # Returns
    /// `true` if the source key existed and was copied.
    pub fn copy_key(
        &mut self,
        src_raw: &str,
        dst_raw: &str,
        depth: crate::types::TraversalDepth,
    ) -> bool {
        let (Ok(src_path), Ok(dst_path)) = (
            RegistryKeyPath::parse(src_raw),
            RegistryKeyPath::parse(dst_raw),
        ) else {
            return false;
        };
        let src_lk = src_path.lookup_key();
        let Some(src_node) = self.keys.get(&src_lk).cloned() else {
            return false;
        };

        let dst_node = self.ensure_key(&dst_path);
        for (k, v) in &src_node.values {
            dst_node.values.insert(k.clone(), v.clone());
        }

        if depth == crate::types::TraversalDepth::Recursive {
            let prefix_len = src_lk.1.len();
            let sub_nodes: Vec<RegistryKeyNode> = self
                .keys
                .iter()
                .filter(|((h, comps), _)| {
                    *h == src_lk.0 && comps.len() > prefix_len && comps.starts_with(&src_lk.1)
                })
                .map(|(_, n)| n.clone())
                .collect();

            for sub in sub_nodes {
                let mut new_comps = dst_path.components.clone();
                new_comps.extend_from_slice(sub.path.components.get(prefix_len..).unwrap_or(&[]));
                let new_path = RegistryKeyPath {
                    hive: dst_path.hive,
                    components: new_comps,
                };
                let target_node = self.ensure_key(&new_path);
                for (k, v) in &sub.values {
                    target_node.values.insert(k.clone(), v.clone());
                }
            }
        }
        true
    }

    /// Exports a key and its subkeys to standard Windows `.reg` file text (`REG EXPORT`).
    ///
    /// # Arguments
    /// * `raw_key` - Key path string to export.
    ///
    /// # Returns
    /// `Some(String)` containing `.reg` file content if the key exists.
    #[must_use]
    pub fn export_reg_text(&self, raw_key: &str) -> Option<String> {
        let key_path = RegistryKeyPath::parse(raw_key).ok()?;
        let lk = key_path.lookup_key();
        let matching: Vec<&RegistryKeyNode> = self
            .keys
            .iter()
            .filter(|((h, comps), _)| *h == lk.0 && comps.starts_with(&lk.1))
            .map(|(_, node)| node)
            .collect();
        if matching.is_empty() {
            return None;
        }

        let mut out = format!("Windows Registry Editor Version 5.00{LF_CHAR}{LF_CHAR}");
        for node in matching {
            write!(out, "[{}]{LF_CHAR}", node.path.to_full_string()).unwrap_or(());
            for val in node.values.values() {
                let lhs = if val.name.is_empty() {
                    "@".to_owned()
                } else {
                    format!(r#""{}""#, val.name)
                };
                let rhs = match val.kind {
                    RegistryValueType::Dword => {
                        let num = val.as_u32().unwrap_or(0);
                        format!("dword:{num:08x}")
                    }
                    RegistryValueType::Sz
                    | RegistryValueType::ExpandSz
                    | RegistryValueType::MultiSz
                    | RegistryValueType::Qword
                    | RegistryValueType::Binary
                    | RegistryValueType::None => format!(
                        r#""{}""#,
                        val.data
                            .replace(BS_CHAR, DOUBLE_BS_STR)
                            .replace('"', ESCAPED_QUOTE_STR)
                    ),
                };
                write!(out, "{lhs}={rhs}{LF_CHAR}").unwrap_or(());
            }
            out.push(LF_CHAR);
        }
        Some(out)
    }

    /// Imports keys and values from either a standard Windows `.reg` file or a Wine registry file
    /// (`WINE REGISTRY Version 2`).
    ///
    /// # Arguments
    /// * `reg_text` - Text content of the `.reg` file.
    /// * `default_wine_hive` - Default [`RegistryHive`] used for relative `[SubKey]` headers in Wine `.reg` files.
    pub fn import_reg_text(&mut self, reg_text: &str, default_wine_hive: RegistryHive) {
        let mut current_key: Option<RegistryKeyPath> = None;
        for raw_line in reg_text.lines() {
            let line = raw_line.trim();
            if is_reg_header_or_comment(line) {
                continue;
            }
            if let Some(rest) = line.strip_prefix('[') {
                let key_part = rest.split(']').next().unwrap_or("").trim();
                let unescaped_key = key_part.replace(DOUBLE_BS_STR, BS_STR);
                if let Some(stripped_del) = unescaped_key.strip_prefix('-') {
                    self.delete_entry(stripped_del, RegistryDeleteTarget::EntireKey);
                    current_key = None;
                } else {
                    let kp = RegistryKeyPath::parse(&unescaped_key).unwrap_or_else(|_| {
                        let sub_comps: Vec<String> = unescaped_key
                            .split([BS_CHAR, '/'])
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .collect();
                        RegistryKeyPath {
                            hive: default_wine_hive,
                            components: sub_comps,
                        }
                    });
                    self.ensure_key(&kp);
                    current_key = Some(kp);
                }
                continue;
            }

            let Some((active_kp, (raw_lhs, raw_rhs))) =
                current_key.clone().zip(line.split_once('='))
            else {
                continue;
            };
            let lhs_trim = raw_lhs.trim();
            let val_name = if lhs_trim == "@" {
                String::new()
            } else {
                lhs_trim.trim_matches('"').replace(DOUBLE_BS_STR, BS_STR)
            };
            let rhs_trim = raw_rhs.trim();
            if rhs_trim == "-" {
                self.delete_entry(
                    &active_kp.to_full_string(),
                    RegistryDeleteTarget::Value(&val_name),
                );
                continue;
            }
            let (kind, data) = parse_reg_value_rhs(rhs_trim);
            self.set_key_path_value(&active_kp, &val_name, kind, &data);
        }
    }
}

/// Checks whether a trimmed `.reg` line is blank, a comment (`;` / `#`), or a file header.
///
/// # Arguments
/// * `line` - Trimmed `.reg` line.
///
/// # Returns
/// `true` if the line should be skipped during `.reg` import.
fn is_reg_header_or_comment(line: &str) -> bool {
    line.is_empty()
        || line.starts_with(';')
        || line.starts_with('#')
        || line.starts_with("Windows Registry Editor")
        || line.starts_with("REGEDIT4")
        || line.starts_with("WINE REGISTRY")
}

/// Parses the right-hand side of a `.reg` `name=value` assignment into `(RegistryValueType, data)`.
///
/// # Arguments
/// * `rhs_trim` - Trimmed right-hand side text after `'='`.
///
/// # Returns
/// `(RegistryValueType, unescaped_data_string)`.
fn parse_reg_value_rhs(rhs_trim: &str) -> (RegistryValueType, String) {
    rhs_trim.strip_prefix("dword:").map_or_else(
        || {
            rhs_trim.strip_prefix("str(2):").map_or_else(
                || {
                    let clean = rhs_trim
                        .trim_matches('"')
                        .replace(ESCAPED_QUOTE_STR, r#"""#)
                        .replace(DOUBLE_BS_STR, BS_STR);
                    (RegistryValueType::Sz, clean)
                },
                |str_val| {
                    let clean = str_val
                        .trim()
                        .trim_matches('"')
                        .replace(DOUBLE_BS_STR, BS_STR);
                    (RegistryValueType::ExpandSz, clean)
                },
            )
        },
        |dw| {
            let parsed = u32::from_str_radix(dw.trim(), 16).unwrap_or(0);
            (RegistryValueType::Dword, format!("0x{parsed:x}"))
        },
    )
}

#[cfg(test)]
/// Unit tests for [`RegistryStore`], `Command Processor` live settings, and `.reg` import/export.
mod tests {
    use super::*;

    /// Verifies `Command Processor` defaults, `HKCU` over `HKLM` precedence, and invalid values.
    #[test]
    fn test_command_processor_settings_and_overrides() {
        use RegistryValueType::{Dword, Sz};

        let empty_store = RegistryStore {
            keys: BTreeMap::new(),
        };
        assert_eq!(empty_store.command_processor_extensions(), None);
        assert_eq!(empty_store.command_processor_delayed_expansion(), None);
        assert_eq!(empty_store.command_processor_default_color(), None);

        let mut store = RegistryStore::default();
        assert_eq!(
            store.command_processor_extensions(),
            Some(ExtensionsMode::Enabled)
        );
        assert_eq!(
            store.command_processor_delayed_expansion(),
            Some(DelayedExpansionMode::Disabled)
        );
        assert_eq!(store.command_processor_autorun(), (None, None));
        assert_eq!(store.command_processor_default_color(), None);

        for (key, name, kind, val) in [
            (HKCU_CMD_PROCESSOR_KEY, "EnableExtensions", Dword, "0"),
            (HKCU_CMD_PROCESSOR_KEY, "DelayedExpansion", Dword, "1"),
            (HKCU_CMD_PROCESSOR_KEY, "AutoRun", Sz, "echo user"),
            (HKLM_CMD_PROCESSOR_KEY, "AutoRun", Sz, "echo machine"),
            (HKCU_CMD_PROCESSOR_KEY, "DefaultColor", Dword, "0x0A"),
        ] {
            assert_eq!(store.set_value(key, name, kind, val), Ok(()));
        }
        assert_eq!(
            store.command_processor_extensions(),
            Some(ExtensionsMode::Disabled)
        );
        assert_eq!(
            store.command_processor_delayed_expansion(),
            Some(DelayedExpansionMode::Enabled)
        );
        assert_eq!(
            store.command_processor_autorun(),
            (
                Some("echo machine".to_owned()),
                Some("echo user".to_owned()),
            )
        );
        assert!(store.command_processor_default_color().is_some());

        for bad_color in ["0x1FF", "0"] {
            assert_eq!(
                store.set_value(HKCU_CMD_PROCESSOR_KEY, "DefaultColor", Dword, bad_color),
                Ok(())
            );
            assert_eq!(store.command_processor_default_color(), None);
        }
        for name in ["DefaultColor", "EnableExtensions", "DelayedExpansion"] {
            assert_eq!(
                store.set_value(HKCU_CMD_PROCESSOR_KEY, name, Sz, "not_a_number"),
                Ok(())
            );
        }
        assert_eq!(store.command_processor_default_color(), None);
        assert_eq!(store.command_processor_extensions(), None);
        assert_eq!(store.command_processor_delayed_expansion(), None);
    }

    /// Verifies hive/type/path parsing, value formatting, case-insensitive lookup, and `as_u32`.
    #[test]
    fn test_hive_value_type_key_path_and_value_queries() {
        use RegistryValueType::{Dword, Sz};

        for (raw, expected) in [
            ("HKLM", Some(RegistryHive::LocalMachine)),
            ("HKEY_CURRENT_USER", Some(RegistryHive::CurrentUser)),
            ("HKCR", Some(RegistryHive::ClassesRoot)),
            ("HKU", Some(RegistryHive::Users)),
            ("HKCC", Some(RegistryHive::CurrentConfig)),
            ("INVALID", None),
        ] {
            assert_eq!(RegistryHive::parse(raw), expected);
        }

        for t in [
            "REG_SZ",
            "REG_EXPAND_SZ",
            "REG_MULTI_SZ",
            "REG_DWORD",
            "REG_QWORD",
            "REG_BINARY",
            "REG_NONE",
        ] {
            assert!(RegistryValueType::parse(t).is_some());
        }
        assert!(RegistryValueType::parse("BAD_TYPE").is_none());

        let mut store = RegistryStore::default();
        assert!(RegistryKeyPath::parse("").is_err());
        assert!(RegistryKeyPath::parse("BADHIVE/Sub").is_err());
        assert!(store.set_value("BADHIVE/Sub", "v", Sz, "d").is_err());
        assert!(store.get_value("BADHIVE/Sub", "v").is_none());
        assert!(store.export_reg_text("BADHIVE/Sub").is_none());
        assert_eq!(
            RegistryKeyPath::parse("HKLM").map(|k| k.to_full_string()),
            Ok("HKEY_LOCAL_MACHINE".to_owned())
        );

        for (key, name, kind, val) in [
            ("HKCU/Software/MyApp/Settings", "Count", Dword, "42"),
            ("HKCU/Software/MyApp/Settings", "DecCount", Sz, "99"),
            ("HKCU/Software/MyApp/Settings", "HexCount", Dword, "0X10"),
            ("HKCU/Software/MyApp", "", Sz, "DefaultApp"),
        ] {
            assert_eq!(store.set_value(key, name, kind, val), Ok(()));
        }
        assert_eq!(
            store
                .get_value("HKCU/Software/MyApp/Settings", "DecCount")
                .and_then(RegistryValue::as_u32),
            Some(99)
        );
        assert_eq!(
            store
                .get_value("HKCU/Software/MyApp/Settings", "HexCount")
                .and_then(RegistryValue::as_u32),
            Some(16)
        );
        assert_eq!(
            store
                .get_value("HKCU/Software/MyApp/Settings", "count")
                .map(|v| (v.display_name(), v.data.as_str())),
            Some(("Count", "0x2a"))
        );
        assert_eq!(
            store
                .get_value("HKCU/Software/MyApp", "")
                .map(RegistryValue::display_name),
            Some("(Default)")
        );
    }

    /// Verifies recursive/shallow `copy_key` and value/all-values/subtree `delete_entry`.
    #[test]
    fn test_registry_copy_and_delete_operations() {
        let mut store = RegistryStore::default();
        assert_eq!(
            store.set_value(
                "HKCU/Software/MyApp",
                "",
                RegistryValueType::Sz,
                "DefaultApp"
            ),
            Ok(())
        );
        assert_eq!(
            store.set_value(
                "HKCU/Software/MyApp/Settings",
                "Count",
                RegistryValueType::Dword,
                "42"
            ),
            Ok(())
        );

        assert!(store.copy_key(
            "HKCU/Software/MyApp",
            "HKCU/Software/MyAppCopy",
            crate::types::TraversalDepth::Recursive
        ));
        assert!(
            store
                .get_value("HKCU/Software/MyAppCopy/Settings", "Count")
                .is_some()
        );
        assert!(store.copy_key(
            "HKCU/Software/MyApp",
            "HKCU/Software/MyAppShallow",
            crate::types::TraversalDepth::Shallow
        ));
        assert!(store.get_value("HKCU/Software/MyAppShallow", "").is_some());
        assert!(!store.copy_key(
            "HKCU/NoSuchKey",
            "HKCU/Dst",
            crate::types::TraversalDepth::Recursive
        ));
        assert!(!store.copy_key(
            "BAD_HIVE",
            "HKCU/Dst",
            crate::types::TraversalDepth::Recursive
        ));

        assert!(RegistryDeleteTarget::EntireKey.is_entire_key());
        assert!(!store.delete_entry("BAD_HIVE", RegistryDeleteTarget::EntireKey));
        assert!(!store.delete_entry("HKCU/Missing", RegistryDeleteTarget::Value("v")));
        assert!(!store.delete_entry("HKCU/Missing", RegistryDeleteTarget::AllValues));
        assert!(store.delete_entry(
            "HKCU/Software/MyApp/Settings",
            RegistryDeleteTarget::Value("Count")
        ));
        assert!(store.delete_entry(
            "HKCU/Software/MyApp/Settings",
            RegistryDeleteTarget::AllValues
        ));
        assert!(store.delete_entry("HKCU/Software/MyApp", RegistryDeleteTarget::EntireKey));
        assert!(!store.delete_entry("HKCU/Software/MyApp", RegistryDeleteTarget::EntireKey));
    }

    /// Verifies `.reg` file export and Windows/Wine `.reg` file import including deletions.
    #[test]
    fn test_registry_export_and_wine_reg_import() {
        let mut store = RegistryStore::default();
        assert_eq!(
            store.set_value(
                "HKCU/Software/MyApp",
                "",
                RegistryValueType::Sz,
                "DefaultApp"
            ),
            Ok(())
        );
        assert_eq!(
            store.set_value(
                "HKCU/Software/MyApp/Settings",
                "Count",
                RegistryValueType::Dword,
                "42"
            ),
            Ok(())
        );
        assert_eq!(
            store.set_value(
                "HKCU/Software/MyApp/Settings",
                "PathText",
                RegistryValueType::Sz,
                r#"C:\Bin\"quoted""#
            ),
            Ok(())
        );

        let exported = store
            .export_reg_text("HKCU/Software/MyApp")
            .unwrap_or_default();
        assert!(exported.contains("Windows Registry Editor Version 5.00"));
        assert!(exported.contains("dword:0000002a"));
        assert!(store.export_reg_text("HKCU/MissingKey").is_none());

        let lf = LF_CHAR.to_string();
        let wine_reg = [
            "Windows Registry Editor Version 5.00",
            "REGEDIT4",
            "WINE REGISTRY Version 2",
            "",
            ";; Comment",
            "# Hash comment",
            r#"orphan_value="ignored""#,
            "[Software/WineTest] 1700000000",
            "invalid_line_inside_key",
            r#"@="root_val""#,
            r#""Num"=dword:00000005"#,
            r#""Exp"=str(2):"%PATH%""#,
            r#""ToDelete"="temp""#,
            r#""ToDelete"=-"#,
            "[HKEY_LOCAL_MACHINE/Software/Explicit]",
            r#""Key"="Val""#,
            "[-HKEY_LOCAL_MACHINE/Software/Explicit]",
        ]
        .join(&lf);
        store.import_reg_text(&wine_reg, RegistryHive::CurrentUser);
        assert_eq!(
            store
                .get_value("HKCU/Software/WineTest", "")
                .map(|v| v.data.as_str()),
            Some("root_val")
        );
        assert_eq!(
            store
                .get_value("HKCU/Software/WineTest", "Num")
                .map(|v| v.data.as_str()),
            Some("0x5")
        );
        assert!(
            store
                .get_value("HKCU/Software/WineTest", "ToDelete")
                .is_none()
        );
        assert!(store.get_value("HKLM/Software/Explicit", "Key").is_none());
    }

    /// Verifies `HKCR` file extension associations (`ASSOC`) and open command templates (`FTYPE`).
    #[test]
    fn test_registry_hkcr_associations_and_file_types() {
        let mut store = RegistryStore::default();
        assert_eq!(
            store.get_file_association(".bat"),
            Some("batfile".to_owned())
        );
        assert_eq!(
            store.get_file_association("bat"),
            Some("batfile".to_owned())
        );
        assert_eq!(store.get_file_association(".missing"), None);
        assert_eq!(
            store.get_file_type("batfile"),
            Some(r#""%1" %*"#.to_owned())
        );
        assert_eq!(store.get_file_type("missingtype"), None);

        for (key, name, val) in [
            ("HKCR/NonDotRoot", "", "v"),
            ("HKCR/.empty", "", ""),
            ("HKCR/.namedonly", "Named", "v"),
            ("HKCR/ ftype_a/other/open/command", "", "x"),
            ("HKCR/ftype_b/shell/other/command", "", "x"),
            ("HKCR/ftype_c/shell/open/other", "", "x"),
            ("HKCR/ftype_d/shell/open/command", "Named", "x"),
            ("HKCR/ftype_e/shell/open/command", "", ""),
        ] {
            assert_eq!(
                store.set_value(key, name, RegistryValueType::Sz, val),
                Ok(())
            );
        }
        assert_eq!(store.get_file_association(".empty"), None);
        assert_eq!(store.get_file_type("ftype_e"), None);

        let assocs = store.file_associations();
        assert_eq!(assocs.len(), 3);
        let ftypes = store.file_types();
        assert_eq!(ftypes.len(), 3);
    }
}
