//! Reserved DOS device names (`NUL`, `CON`, `PRN`, `AUX`, `CLOCK$`, `COM1`..`COM9`, `LPT1`..`LPT9`).
//!
//! In Win32 and `cmd.exe`, reserved device names are intercepted regardless of directory prefix
//! or file extension (e.g., `NUL`, `NUL.txt`, `C:/temp/NUL`). Notably, `IF EXIST "C:/folder/NUL"`
//! is the classic batch idiom for testing whether `C:/folder` exists as a directory.

use derive_more::Display;

use crate::types::{BS_CHAR, BS_STR};

/// Win32 device namespace prefix (`\\.\`).
const DEVICE_NAMESPACE_PREFIX: &str = r"\\.\";

/// Enumeration of reserved Win32/DOS device names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum DosDevice {
    /// `NUL` — Null device (discards writes, returns immediate EOF on reads).
    #[display("NUL")]
    Nul,
    /// `CON` — Console input/output stream.
    #[display("CON")]
    Con,
    /// `PRN` — Printer device.
    #[display("PRN")]
    Prn,
    /// `AUX` — Auxiliary serial device.
    #[display("AUX")]
    Aux,
    /// `CLOCK$` — System real-time clock device.
    #[display("CLOCK$")]
    Clock,
    /// `COM1`..=`COM9` — Serial communication port.
    #[display("COM{_0}")]
    Com(
        /// 1-based port index (`1..=9`).
        u8,
    ),
    /// `LPT1`..=`LPT9` — Parallel printer port.
    #[display("LPT{_0}")]
    Lpt(
        /// 1-based port index (`1..=9`).
        u8,
    ),
}

impl DosDevice {
    /// Checks if a single filename component (e.g., `"NUL"`, `"nul.txt"`, `"COM1:"`) names a reserved DOS device.
    ///
    /// # Arguments
    /// * `component` - A single path segment (without directory separators).
    ///
    /// # Returns
    /// `Some(DosDevice)` if `component` matches a reserved DOS device, otherwise `None`.
    #[must_use]
    pub fn from_component(component: &str) -> Option<Self> {
        let trimmed = component.trim().trim_end_matches(':');
        let stem = trimmed
            .find('.')
            .and_then(|dot| trimmed.get(..dot))
            .unwrap_or(trimmed)
            .trim_end_matches(' ');

        let upper = stem.to_ascii_uppercase();
        match upper.as_str() {
            "NUL" => Some(Self::Nul),
            "CON" => Some(Self::Con),
            "PRN" => Some(Self::Prn),
            "AUX" => Some(Self::Aux),
            "CLOCK$" => Some(Self::Clock),
            _ => upper
                .strip_prefix("COM")
                .and_then(parse_port_digit)
                .map(Self::Com)
                .or_else(|| {
                    upper
                        .strip_prefix("LPT")
                        .and_then(parse_port_digit)
                        .map(Self::Lpt)
                }),
        }
    }

    /// Inspects a full path string (e.g., `C:/dir/NUL` or device-prefixed `CON`) and extracts
    /// any parent directory portion along with the trailing [`DosDevice`].
    ///
    /// # Arguments
    /// * `path` - Full or relative path string.
    ///
    /// # Returns
    /// `Some((optional_parent_dir, DosDevice))` if the final path segment is a reserved DOS device.
    #[must_use]
    pub fn split_path_device(path: &str) -> Option<(Option<&str>, Self)> {
        let stripped = path.strip_prefix(DEVICE_NAMESPACE_PREFIX).unwrap_or(path);
        if let Some((parent, leaf)) = stripped.rsplit_once([BS_CHAR, '/']) {
            let dev = Self::from_component(leaf)?;
            let parent_opt = Some(if parent.is_empty() { BS_STR } else { parent });
            Some((parent_opt, dev))
        } else if stripped.len() >= 2 && stripped.as_bytes().get(1) == Some(&b':') {
            let drive_part = stripped.get(..2).unwrap_or("");
            let leaf = stripped.get(2..).unwrap_or("");
            let dev = Self::from_component(leaf)?;
            Some((Some(drive_part), dev))
        } else {
            let dev = Self::from_component(stripped)?;
            Some((None, dev))
        }
    }
}

/// Parses a single ASCII digit `'1'..='9'` into `u8`.
///
/// # Arguments
/// * `s` - String slice after `"COM"` or `"LPT"`.
///
/// # Returns
/// `Some(1..=9)` if `s` is a single digit `'1'..='9'`, else `None`.
const fn parse_port_digit(s: &str) -> Option<u8> {
    if let [b] = s.as_bytes()
        && *b >= b'1'
        && *b <= b'9'
    {
        return Some(b.saturating_sub(b'0'));
    }
    None
}

#[cfg(test)]
/// Unit tests for case-insensitive Win32 DOS device component routing.
mod tests {
    use super::*;

    /// Verifies `DosDevice::from_component` across `NUL`, `CON`, `PRN`, `AUX`, `CLOCK$`, `COM1`–`COM9`, and `LPT1`–`LPT9`.
    #[test]
    fn test_dos_device_from_component() {
        assert_eq!(DosDevice::from_component("nul"), Some(DosDevice::Nul));
        assert_eq!(DosDevice::from_component("NUL.txt"), Some(DosDevice::Nul));
        assert_eq!(DosDevice::from_component("CON:"), Some(DosDevice::Con));
        assert_eq!(DosDevice::from_component("prn"), Some(DosDevice::Prn));
        assert_eq!(DosDevice::from_component("Aux.log"), Some(DosDevice::Aux));
        assert_eq!(DosDevice::from_component("CLOCK$"), Some(DosDevice::Clock));
        assert_eq!(DosDevice::from_component("com1"), Some(DosDevice::Com(1)));
        assert_eq!(
            DosDevice::from_component("LPT9.dat"),
            Some(DosDevice::Lpt(9))
        );
        assert_eq!(DosDevice::from_component("COM0"), None);
        assert_eq!(DosDevice::from_component("COM0"), None);
        assert_eq!(DosDevice::from_component("COMA"), None);
        assert_eq!(DosDevice::from_component("COM10"), None);
        assert_eq!(DosDevice::from_component("normal.txt"), None);
    }

    /// Verifies `DosDevice::split_path_device` parent-directory splitting.
    #[test]
    fn test_split_path_device() {
        let sep = BS_STR;
        let folder_nul = format!("C:{sep}folder{sep}NUL");
        let expected_parent = format!("C:{sep}folder");
        assert_eq!(
            DosDevice::split_path_device("NUL"),
            Some((None, DosDevice::Nul))
        );
        assert_eq!(
            DosDevice::split_path_device(&folder_nul),
            Some((Some(expected_parent.as_str()), DosDevice::Nul))
        );
        let root_nul = format!("{sep}NUL");
        assert_eq!(
            DosDevice::split_path_device(&root_nul),
            Some((Some(sep), DosDevice::Nul))
        );
        assert_eq!(
            DosDevice::split_path_device("C:NUL"),
            Some((Some("C:"), DosDevice::Nul))
        );
        let dev_con = format!("{DEVICE_NAMESPACE_PREFIX}CON");
        assert_eq!(
            DosDevice::split_path_device(&dev_con),
            Some((None, DosDevice::Con))
        );
        let folder_file = format!("C:{sep}folder{sep}file.txt");
        assert_eq!(DosDevice::split_path_device(&folder_file), None);
        assert_eq!(DosDevice::split_path_device("C:file.txt"), None);
        assert_eq!(DosDevice::split_path_device("x"), None);
    }
}
