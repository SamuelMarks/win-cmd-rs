//! Phase 0 script reading, character encoding, and physical-to-logical character mapping.
//!
//! Exposes [`encoding`], [`char_map`], and [`stream`] modules for byte-offset batch file reading.

pub mod char_map;
pub mod encoding;
pub mod stream;
