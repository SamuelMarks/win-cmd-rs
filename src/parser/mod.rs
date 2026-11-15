//! Multi-pass expansion and unified CST/AST parser pipeline for `win-cmd-rs`.
//!
//! Organizes:
//! - [`lexer`]: Shared statement/line/word/caret/quote/`ECHO(` lexer and linear `O(N)` operator scanner.
//! - [`cst_parser`]: Lossless Concrete Syntax Tree builder (`Strict` execution vs `Recovering` linter modes).
//! - [`lower`]: Deterministic CST-to-AST lowering (`PopulateSubwordParts` vs zero-allocation `Lightweight`).
//! - [`peg`]: Re-export facade preserving `parse_script_cst`, `lower_cst_to_ast`, and `compute_lossless_paren_balance`.
//! - [`phase1`], [`phase2`], [`phase3`], [`phase4`]: Multi-pass `cmd.exe` expansion & runtime entrypoints.
//! - [`modifiers`], [`var_ops`], [`ast`], [`cst`]: Modifiers, variable slicing, AST, and CST nodes.

pub mod ast;
pub mod cst;
pub mod cst_parser;
pub mod lexer;
pub mod lower;
pub mod modifiers;
pub mod peg;
pub mod phase1;
pub mod phase2;
pub mod phase3;
pub mod phase4;
pub mod var_ops;
