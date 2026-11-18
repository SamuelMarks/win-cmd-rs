# `win-cmd-rs`

[![doc coverage](https://img.shields.io/badge/doc%20coverage-100.0%25-brightgreen)](https://docs.rs/win-cmd-rs)
[![test coverage](https://img.shields.io/badge/test%20coverage-100.0%25-brightgreen)](#)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](#quality--engineering-standards)
[![CI](https://github.com/SamuelMarks/win-cmd-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/SamuelMarks/win-cmd-rs/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A cross-platform, bug-for-bug and quirk-for-quirk compatible **Windows Command Prompt (`cmd.exe`) & MS-DOS (`COMMAND.COM`) interpreter (`wincmd` / `WINCMD.EXE`)** and **`ShellCheck`-style static analysis & linting engine (`wincheck` / `WINCHECK.EXE`)** written in `#![no_std]` + `alloc` safe Rust.

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Installation, Building & MS-DOS Cross-Compilation](#installation-building--ms-dos-cross-compilation)
   - [MS-DOS Hardware & OS Requirements](#ms-dos-hardware--os-requirements)
   - [Cross-Compiling `WINCMD.EXE` & `WINCHECK.EXE` for MS-DOS](#cross-compiling-wincmdexe--wincheckexe-for-ms-dos)
4. [`wincmd` — The Cross-Platform `cmd.exe` & `COMMAND.COM` Interpreter](#wincmd--the-cross-platform-cmdexe--commandcom-interpreter)
   - [CLI Synopsis & Flags](#wincmd-cli-synopsis--flags)
   - [The `/C` and `/K` Quote-Stripping Heuristic](#the-c-and-k-quote-stripping-heuristic)
   - [Interactive REPL](#interactive-repl)
5. [`wincheck` — The Static Linter & Auto-Fixer for Batch](#wincheck--the-static-linter--auto-fixer-for-batch)
   - [CLI Synopsis & Options](#wincheck-cli-synopsis--options)
   - [Output Formats (`tty`, `json`, `sarif`, `gcc`)](#output-formats-tty-json-sarif-gcc)
   - [Inline Suppression Directives](#inline-suppression-directives)
   - [Complete Rule Catalog (`CMD0001` – `CMD5010`)](#complete-rule-catalog-cmd0001--cmd5010)
6. [Architecture & Authentic `cmd.exe` Pipeline](#architecture--authentic-cmdexe-pipeline)
   - [Phase 0: Byte-Offset Script Reader, Encodings & Line Continuation](#phase-0-byte-offset-script-reader-encodings--line-continuation)
   - [Phase 1: Immediate `%` Expansion, `%~` Modifiers & Variable Slicing](#phase-1-immediate--expansion--modifiers--variable-slicing)
   - [Phase 2: Special Tokenization, Quoting, Carets & Compound Blocks](#phase-2-special-tokenization-quoting-carets--compound-blocks)
   - [Phase 3: `FOR` Loop Variable Expansion](#phase-3-for-loop-variable-expansion)
   - [Phase 4: Delayed Expansion (`!VAR!`) & Caret Pass Quirk](#phase-4-delayed-expansion-var--caret-pass-quirk)
   - [`SET /A` 32-Bit Signed Arithmetic Engine](#set-a-32-bit-signed-arithmetic-engine)
   - [Virtual File System (`InMemoryVfs`, `HostOsVfs` & `DosFatVfs`), 8.3 Short Names & Win32 Globs](#virtual-file-system-inmemoryvfs-hostosvfs--dosfatvfs-83-short-names--win32-globs)
7. [Built-In Commands & Cross-Platform Utility Shims](#built-in-commands--cross-platform-utility-shims)
8. [Rust Library Usage (`win_cmd_rs`)](#rust-library-usage-win_cmd_rs)
   - [Executing Commands & Scripts in an In-Memory Sandbox](#executing-commands--scripts-in-an-in-memory-sandbox)
   - [Simulating MS-DOS (`SimulatedDosKernel`) & `#![no_std]` Embedding](#simulating-ms-dos-simulateddoskernel--no_std-embedding)
   - [Programmatic Static Analysis & Auto-Fixing](#programmatic-static-analysis--auto-fixing)
9. [Repository Structure](#repository-structure)
10. [Quality & Engineering Standards](#quality--engineering-standards)
11. [License](#license)

---

## Overview

Windows and MS-DOS Batch (`.bat` / `.cmd`) scripts power countless build systems, legacy enterprise workflows, retrocomputing environments, CI/CD pipelines, and developer toolchains, yet testing or analyzing them on Linux or macOS—or running modern static analysis directly on real MS-DOS—has historically been nearly impossible.

`win-cmd-rs` solves all of these problems in a `#![no_std]` + `alloc`, dependency-minimal Rust core (`derive_more` only):

- **`wincmd` (`WINCMD.EXE`)**: An authentic, deterministic `cmd.exe` and MS-DOS `COMMAND.COM` interpreter that reproduces multi-pass `%`/`!` expansion, byte-offset script reading (including self-modifying batch scripts!), `SETLOCAL` environment stacks, per-drive working directories, FAT 8.3 & DOS 7 LFN filenames, Win32 `FsRtlIsNameInExpression` wildcard matching, live Windows Registry (`HKLM`/`HKCU`) integration, and 55+ built-in commands (`TRUENAME`, `CTTY`, `LH`, `MEM`, etc.) across Linux, macOS, Windows, and 32-bit Protected-Mode MS-DOS (`DJGPP` + `CWSDPMI`).
- **`wincheck` (`WINCHECK.EXE`)**: A `ShellCheck`-style static analyzer and lossless CST tree-rewriting engine built specifically for `.bat`, `.cmd`, MS-DOS `COMMAND.COM`, and interactive `cmd.exe` inputs. It detects **60 distinct classes of batch bugs (`CMD0001`–`CMD5010`)**, including syntax misuses (`IF a = b`, missing `IN`/`DO` in `FOR`), `.bat` (`%%`) vs. REPL (`%`) mismatches, stale `%VAR%` reads inside `( ... )` blocks, `IF ERRORLEVEL 0` traps, `RD /S /Q "%UNSET_VAR%"` root deletions, and 10 MS-DOS `COMMAND.COM` portability rules (`CMD5001`–`CMD5010` via `--dialect dos622`).
- **`win_cmd_rs` (`#![no_std]` + `alloc` Library)**: A cleanly architected `#![forbid(unsafe_code)]` Rust library exposing the unified lexer (`parser::lexer`), multi-pass expander, lossless CST parser (`parser::cst_parser`), CST-to-AST lowerer (`parser::lower`), composable CST tree-rewriter (`linter::rewriter`), Virtual File Systems (`InMemoryVfs`, `DosFatVfs`, and `std`-gated `HostOsVfs`), `DosKernelApi` + `SimulatedDosKernel`, runtime interpreter, and linter.

> **Companion Documentation**
> - **[`USAGE.md`](USAGE.md)** — Complete CLI guide, `--dialect` & MS-DOS `COMMAND.COM` reference, batch scripting cookbook, CI/editor recipes, and `#![no_std]` Rust embedding examples.
> - **[`ARCHITECTURE.md`](ARCHITECTURE.md)** — Deep technical walkthrough with Mermaid architecture, `#![no_std]` boundary, `DosKernelApi` / `%TEMP%` spooling, DPMI memory layout, CST/AST, and VFS diagrams.

---

## Key Features

- **Authentic 5-Stage `cmd.exe` & `COMMAND.COM` Execution Pipeline**: Implements Phase 0 (raw-byte-offset seeking, mid-script `CHCP` switching across CP437/850/852/865/866/1252/UTF-8/UTF-16 & `^` line continuation), Phase 1 (`%VAR%`, `%0`–`%9`, `%*`, `%~dpnx1` modifiers, `%VAR:~start,len%`, `%VAR:old=new%`), Phase 2 (quote/caret state machine, compound `(...)` blocks, redirections), Phase 3 (`%%I` `FOR` variables), and Phase 4 (`!VAR!` delayed expansion with the authentic `!`-triggered caret pass).
- **Unified Linear-Precedence CST Parser & Lossless CST (`src/parser/cst_parser/`, `src/parser/lexer.rs`, `src/parser/lower.rs`, `src/parser/cst.rs`)**:
  - Parses scripts into a 100% lossless Concrete Syntax Tree (`parse_script_cst(id, src, exec_context).to_source_string() == src`) preserving UTF-8 BOMs, `CRLF`/`LF` line endings, `^\r\n` continuations, comments, interleaved redirections, and sub-word tokens (`%VAR%`, `!VAR!`, `%1`, `%%I`, `%~dp0`).
  - Tracks farthest-failure byte offsets and expected grammar sets (`PegExpected`) to pinpoint exact syntax error locations without aborting on the first error.
  - Recovers from probable syntax misuse (`IF a = b`, `IF (a == b)`, `FOR %%I (set) DO`, `FOR %%I IN (set) cmd`, unparenthesized `ELSE`, unclosed `"`, `%~dpVAR%`) so subsequent lines and statements are still parsed and linted.
- **Composable Lossless CST Tree-Rewriting Engine (`src/linter/rewriter.rs`)**:
  - Multi-pass structural rewriter (`CstRewriter`) that composes overlapping and nested fixes cleanly without byte-offset collisions:
    1. **Delayed Expansion Block Pass**: Converts stale `%VAR%` reads of block-modified variables (`CMD2001`) and dynamic `%ERRORLEVEL%`/`%RANDOM%`/`%TIME%` (`CMD2009`) inside blocks into `!VAR!`, automatically injecting `SETLOCAL EnableDelayedExpansion`.
    2. **Structural Syntax Fix Pass**: Repairs `IF a = b` -> `IF a == b`, `IF (a == b)` -> `IF a == b`, missing `IN`/`DO` in `FOR` loops, unparenthesized `IF ... ELSE ...` -> `IF ... (...) ELSE (...)`, `::` in blocks -> `REM`, broken carets, `SET` assignments, `CD /D`, `CALL`, `EXIT /B`, and `ECHO(`.
    3. **Execution Mode Percent Dialect Pass**: Converts `FOR` loop variables and percent literals between `.bat` mode (`%%I`, `%%~dpI`, `100%%`) and interactive REPL mode (`%I`, `%~dpI`, `100%`).
    4. **Variable & Path Quoting Pass**: Automatically quotes unquoted variables and parameters in path commands, `IF EXIST`, `IF` comparisons, and redirection targets (`> "%LOG%"`), applying smart quote-stripping modifiers (`%1` -> `"%~1"`, `"%1"` -> `"%~1"`, `%%I` -> `"%%~I"`).
    5. **MS-DOS Portability Pass**: Under `--dialect dos622`, splits unconditional `&` command chains onto sequential physical lines (`CMD5004`) and rewrites `GOTO :EOF` to an explicit `:EOF` label appended at the end of the `.BAT` file (`CMD5006`).
- **Triple Virtual File System Backends (`InMemoryVfs`, `HostOsVfs` & `DosFatVfs`)**:
  - `InMemoryVfs`: Deterministic, `#![no_std]` sandboxed multi-drive (`C:`, `D:`, ...) and UNC (`\\server\share`) filesystem with Windows file attributes, inode hardlinks & reparse-point symlinks/junctions, NT `PROGRA~1` 8.3 short names, reserved DOS devices (`NUL`, `CON`, `PRN`, `AUX`, `CLOCK$`, `COM1`–`COM9`, `LPT1`–`LPT9`), and simulated I/O fault injection.
  - `HostOsVfs`: Maps Windows drive letters onto host POSIX or Windows directories (mounting `/` on `Z:\` on Linux/macOS by default) with transparent case-insensitive path resolution and optional `--host-root` sandbox containment.
  - `DosFatVfs<K: DosKernelApi>`: Authentic MS-DOS FAT12/FAT16/FAT32 and DOS 7 `INT 21h AX=71xxh` LFN filesystem enforcing strict 8.3 truncation on pure DOS drives, 2-second `PackedDosTimestamp` granularity, native FAT attribute bits (`INT 21h AX=4300h/4301h`), cross-drive copy+delete `MOVE` fallback, and non-blocking `INT 11h`/`AX=4409h` drive probing.
- **Native 32-Bit Protected-Mode MS-DOS Port (`crates/wincmd-dos/`)**:
  - Compiles directly from `#![no_std]` + `alloc` Rust (`-Z build-std=core,alloc,panic_abort`) against DJGPP `libc` (`i586-pc-msdosdjgpp`) and `CWSDPMI.EXE`, keeping the real-mode DOS stub under ~40 KiB so ~550+ KiB of conventional memory remains free to `EXEC` (`INT 21h AH=4Bh`) real-mode `.COM`/`.EXE` child programs with `%TEMP%` single-tasking pipeline spooling and BIOS `INT 16h` scan-code `DOSKEY` line editing.
- **55+ Built-In Commands & Utility Shims**: Full implementations of `ECHO`, `SET` (`/A`, `/P`), `IF`, `FOR` (`/D`, `/R`, `/L`, `/F`), `CALL`, `GOTO`, `SETLOCAL`, `ENDLOCAL`, `SHIFT`, `EXIT`, `PAUSE`, `START`, `CD`/`CHDIR`, `PUSHD`, `POPD`, `DIR`, `COPY`, `MOVE`, `DEL`/`ERASE`, `REN`/`RENAME`, `RD`/`RMDIR`, `MD`/`MKDIR`, `MKLINK`, `TYPE`, `ASSOC`, `FTYPE`, `DOSKEY`, `PROMPT`, `PATH`, `COLOR`, `TITLE`, `CHCP`, `MODE`, `CLS`, `VER`, `VOL`, `DATE`, `TIME`, `VERIFY`, MS-DOS `TRUENAME`, `CTTY`, `LH`/`LOADHIGH`, `MEM`, plus cross-platform shims for `CMD`, `REG`, `WHERE`, `FIND`, `FINDSTR`, `CHOICE` (both NT and MS-DOS 6.x `/C[:]keys /S /T[:]c,nn` syntax), `TIMEOUT`, `ATTRIB`, `SORT`, `MORE`, `FC`, `COMP`, `TREE`, `XCOPY`, `ROBOCOPY`, `HOSTNAME`, and `WHOAMI`.
- **60 Static Analysis Rules & Safe Auto-Fixer**: `wincheck` provides rich diagnostics in `tty`, `json`, `sarif` (v2.1.0), and `gcc` formats, built-in rule documentation (`--explain CMD2001`, `--explain CMD5001`), inline `REM wincheck disable=...` suppressions, unified diff generation (`--diff`), and full BOM/encoding-preserving CST script rewriting (`--fix`, `--in-place`, `--unsafe-fixes`, `--dialect <cmd|dos622|freedos>`, `--encoding <ENC>`, and `--mode <batch|repl>`).
- **Uncompromising Safety & Quality**: `#![forbid(unsafe_code)]` across the entire core `win-cmd-rs` crate, zero `.unwrap()` / `.expect()` / `panic!()` / `slice[i]` indexing across the workspace, 100% rustdoc coverage, and 100% function, line, and branch test coverage.

---

## Installation, Building & MS-DOS Cross-Compilation

### Prerequisites (Host Linux, macOS & Windows)

- **Rust**: `1.88` or newer (Edition 2024)

### Build from Source (Host OS)

```bash
git clone https://github.com/SamuelMarks/win-cmd-rs.git
cd win-cmd-rs

# Build release binaries (`wincmd` and `wincheck`)
cargo build --release

# Verify pure `#![no_std]` + `alloc` core without `std`
cargo check --lib --no-default-features
```

The compiled host binaries will be available at `target/release/wincmd` and `target/release/wincheck` (or install via `cargo install --path .`).

### MS-DOS Hardware & OS Requirements

| Requirement | Specification |
| :--- | :--- |
| **CPU** | **Intel 80386 or newer** (32-bit x86 protected mode; soft-float ABI—no 80387 FPU required). On 16-bit 8086/8088/80286 CPUs, the embedded MZ real-mode CPU guard cleanly prints `"This program requires an 80386 or newer processor."` via `INT 21h AH=09h` and exits (`ERRORLEVEL 1`) without hanging. |
| **Memory** | **4–8 MiB XMS / DPMI RAM** (`MemoryProfile::DosCompact4MiB` / `DosStandard8MiB`); leaves **~550+ KiB** of the 640 KiB conventional memory arena free for child `.COM`/`.EXE` programs. |
| **DPMI Host** | DPMI 0.9+ provider (`CWSDPMI.EXE` in the same directory or `%PATH%`, or built-in DPMI under Windows 9x / DOSEMU2 / QDPMI / HDPMI32). |
| **Compatible DOS Environments** | MS-DOS 5.0+ / 6.22, IBM PC-DOS, DR-DOS, FreeDOS 1.2 / 1.3+, Windows 95 / 98 / ME DOS mode (including `INT 21h AX=71xxh` LFN), DOSBox-X, and QEMU (`qemu-system-i386`). |

### Cross-Compiling `WINCMD.EXE` & `WINCHECK.EXE` for MS-DOS

With the [DJGPP cross-toolchain (`i586-pc-msdosdjgpp-gcc`)](https://github.com/andrewwutw/build-djgpp) on your `PATH` and Rust `nightly` (`rustup component add --toolchain nightly rust-src`):

```bash
cargo +nightly build --manifest-path crates/wincmd-dos/Cargo.toml \
  -Z build-std=core,alloc,panic_abort \
  -Z json-target-spec \
  --target targets/i586-pc-msdosdjgpp.json \
  --no-default-features \
  --release
```

Copy `wincmd.exe` (`WINCMD.EXE`), `wincheck.exe` (`WINCHECK.EXE`), and `CWSDPMI.EXE` onto any FAT12/FAT16/FAT32 floppy or hard disk image.

---

## `wincmd` — The Cross-Platform `cmd.exe` & `COMMAND.COM` Interpreter

`wincmd` can run interactively as a Read-Eval-Print Loop (REPL), execute single command strings via `/C` or `/K`, or execute `.bat` / `.cmd` batch scripts directly. By default, the host `wincmd` binary runs against `HostOsVfs::from_host_env()` (mapping POSIX `/` onto `Z:\`); on MS-DOS, `WINCMD.EXE` runs directly against `DosFatVfs<DjgppDosKernel>`.

### `wincmd` CLI Synopsis & Flags

```text
WINCMD [drive:\path] [/A | /U] [/Q] [/D] [/P] [/MSG] [/E:ON | /E:OFF | /E:nnnnn]
       [/F:ON | /F:OFF] [/V:ON | /V:OFF] [/T:bf] [--dialect <cmd|dos622|freedos>]
       [--in-memory | --hermetic | --host-native | --host-root <dir>]
       [[/S] [/C | /K] string] [--script <file> [args...]]
```

| Flag / Option | Description |
| :--- | :--- |
| `/C <string>` | Carries out the command specified by `<string>` and then terminates. |
| `/K <string>` | Carries out the command specified by `<string>` and remains in the interactive REPL. |
| `/S` | Modifies the treatment of `<string>` after `/C` or `/K` (always strips outer quotes). |
| `/Q` | Turns `ECHO OFF` initially. |
| `/D` | Disables execution of `AutoRun` commands from `HKLM` and `HKCU` `Command Processor` registry keys. |
| `/A` / `/U` | Formats internal pipe and redirected file output as ANSI/codepage (`/A`) or UTF-16LE (`/U`). |
| `/E:ON` / `/E:OFF` | Enables (`ON`, default in `cmd`/`freedos`) or disables (`OFF`, default in `dos622`) Command Extensions. |
| `/E:nnnnn` | Sets MS-DOS `COMMAND.COM` environment size budget in bytes (`160..=32768`). |
| `/P` | Permanent primary shell mode (`COMMAND.COM /P`): runs `C:\AUTOEXEC.BAT` on startup and ignores top-level `EXIT`. |
| `/MSG` | Enables resident extended DOS error messages (`COMMAND.COM /MSG` compatibility). |
| `[drive:\path]` | Positional `COMMAND.COM` startup directory setting `%COMSPEC%` (e.g., `WINCMD C:\DOS /P`). |
| `/V:ON` / `/V:OFF` | Enables (`ON`) or disables (`OFF`, default) `!VAR!` Delayed Environment Variable Expansion. |
| `/F:ON` / `/F:OFF` | Enables or disables file and directory name completion characters. |
| `/T:bf` | Sets the initial background (`b`) and foreground (`f`) console hex color nibbles (e.g., `/T:0A`). |
| `--dialect <DIALECT>` | Selects shell dialect: `cmd` (Windows NT `cmd.exe`, default), `dos622` (MS-DOS 6.22 `COMMAND.COM`), or `freedos`. |
| `--host-native` | Mounts the host OS filesystem and imports the host environment (default for the host `wincmd` binary). |
| `--host-root <dir>` | Sandboxes `C:\` onto `<dir>` on the host OS, preventing symlink traversal outside `<dir>`. |
| `--in-memory`, `--hermetic` | Runs in a 100% isolated in-memory `InMemoryVfs` without touching the host disk. |
| `--script <file> [args...]` | Executes `<file>` as a batch script with optional positional arguments `%1`..`%9`. |
| `<file.bat> [args...]` | Directly executes a batch file with positional arguments. |
| `/?`, `-h`, `--help` | Displays help output and exits. |
| `-V`, `--version` | Displays the Windows version banner and exits. |

#### Examples

```bash
# Execute an inline command with Delayed Expansion enabled
wincmd /V:ON /C "set x=40 & set /a x+=2 & echo Answer is !x!"

# Run a batch script with arguments on the host filesystem
wincmd deploy.bat --env production "C:\Build Output"

# Run in a completely isolated in-memory sandbox
wincmd --hermetic /C "echo hello > C:\test.txt & type C:\test.txt"

# Start an interactive cmd.exe session after running an initialization command
wincmd /K "prompt $P$_$G$S & ver"
```

### The `/C` and `/K` Quote-Stripping Heuristic

`wincmd` implements `cmd.exe`'s exact outer-quote stripping rule for `/C` and `/K`:
1. If `/S` is not specified, `wincmd` preserves the first and last `"` characters **only if all** of the following hold:
   - There are **exactly two** `"` characters in the command string.
   - There are **no special characters** (`&`, `<`, `>`, `(`, `)`, `@`, `^`, `|`) between the quotes.
   - There is **at least one whitespace character** between the quotes.
   - The string between the two quotes names an executable or batch target (`.exe`, `.com`, `.bat`, `.cmd`, e.g., `wincmd /C ""C:\Program Files\app.exe""`).
2. Otherwise (or when `/S` is passed), if the first character is `"` and the last character is `"`, both outer quotes are stripped before execution (allowing `wincmd /C ""C:\My App\run.bat" --flag & echo done"` to work identically to Windows).

### Interactive REPL

Running `wincmd` with no arguments (or with `/K`) launches the interactive shell:

```text
Microsoft Windows [Version 10.0.19045.5011]
(c) Microsoft Corporation. All rights reserved.

C:\>set /a "result=(10 + 5) * 2"
30
C:\>echo %result%
30
C:\>(
More? echo Multi-line block
More? echo Errorlevel is %ERRORLEVEL%
More? )
Multi-line block
Errorlevel is 0
C:\>exit 0
```

- Supports multi-line continuation (`More? `) when a line ends with an unescaped caret `^` or contains an unclosed compound block `(`.
- Expands interactive `DOSKEY` macros (`$1`–`$9`, `$*`, `$T`, `$G`, `$L`, `$B`, `$$`) prior to Phase 1 expansion.

---

## `wincheck` — The Static Linter & Auto-Fixer for Batch

`wincheck` statically analyzes `.bat` and `.cmd` files for syntax traps, variable expansion bugs, control-flow hazards, and portability issues—without executing the script.

### `wincheck` CLI Synopsis & Options

```text
Usage: wincheck [OPTIONS] <FILES...|->
```

| Option | Description |
| :--- | :--- |
| `<FILES...>\|-` | One or more `.bat` / `.cmd` script paths to lint (or `-` for standard input). |
| `-f, --format <FMT>` | Output format: `tty` (default), `json`, `sarif`, or `gcc`. |
| `-m, --mode <batch\|repl>` | Target execution context: `batch` (`.bat`/`.cmd`, default) or `repl` (interactive REPL / `cmd /C`). |
| `--dialect <cmd\|dos622\|freedos>` | Target shell dialect: `cmd` (default), `dos622` (enables `CMD5001`–`CMD5010` MS-DOS `COMMAND.COM` checks), or `freedos`. |
| `-S, --severity <SEV>` | Minimum severity threshold to report: `error`, `warning`, `info`, or `style` (default: `style`). |
| `--encoding <ENC>` | Fallback input encoding when no BOM is present: `utf8` (default), `ascii`, `cp437`, `cp850`, `cp852`, `cp865`, `cp866`, `cp1252`, `utf16le`, `utf16be`. |
| `-i, --include <RULES>` | Comma-separated list of rule IDs to explicitly include (e.g., `CMD2001,CMD5001`). |
| `-e, --exclude <RULES>` | Comma-separated list of rule IDs to suppress (e.g., `CMD4006,CMD1009`). |
| `--explain <CMDxxxx>` | Prints detailed Markdown documentation and bad/good code examples for a rule ID. |
| `--list-rules` | Prints a formatted catalog table of all 60 rules (`CMD0001`–`CMD5010`) with severities and summaries. |
| `--diff` | Computes automatic fixes via `CstRewriter` and outputs a unified diff of the changes. |
| `--fix, --stdout` | Rewrites a single script (or `-` stdin) via `CstRewriter` preserving BOM/encoding and outputs the fixed script to `stdout`. |
| `--in-place` | Writes CST-rewritten script(s) back to disk in place preserving BOM/encoding (required when fixing multiple files). |
| `--unsafe-fixes` | Opts into behavior-altering CST auto-fixes (`FixApplicability::UnsafeOptIn`, such as `EXIT` -> `EXIT /B`) alongside `--fix`, `--in-place`, or `--diff`. |
| `-h, --help, /?` | Displays CLI usage instructions. |
| `-V, --version` | Prints `wincheck` version information. |

#### Examples

```bash
# Lint all batch files in a project with human-readable snippet output
wincheck scripts/build.bat scripts/package.cmd

# Filter to only errors and warnings, excluding line-ending info
wincheck --severity warning --exclude CMD1009 ci/*.bat

# Generate SARIF v2.1.0 report for GitHub Advanced Security / CodeQL integration
wincheck --format sarif build.bat > results.sarif

# Preview safe automatic fixes as a unified diff
wincheck --diff legacy_script.bat

# Read detailed explanation and examples for a specific rule
wincheck --explain CMD2001
```

### Output Formats (`tty`, `json`, `sarif`, `gcc`)

#### 1. `tty` (Default)
Renders Rustc/ShellCheck-style annotated code snippets with exact column carets (`^~~~`), actionable `help:` notes, and suggested auto-fix previews:

```text
deploy.bat:4:9: error[CMD2001]: Variable `COUNT` is modified via `SET` and read via `%COUNT%` inside the same `( ... )` block.
  |
4 |     echo %COUNT%
  |          ^^^^^^^
  = help: Enable `SETLOCAL EnableDelayedExpansion` and read `!COUNT!` instead of `%COUNT%`.
  = fix: Replace `%` with `!` for delayed expansion (`!COUNT!`)
```

#### 2. `gcc`
Compact one-line-per-diagnostic format ideal for Vim `quickfix`, Emacs `compile`, and generic editor integrations:

```text
deploy.bat:4:9: error: Variable `COUNT` is modified via `SET` and read via `%COUNT%` inside the same `( ... )` block. [CMD2001]
```

#### 3. `json`
Deterministic, zero-dependency JSON array containing file names, 1-based start/end lines and columns, rule IDs, severities, messages, help text, and replacement spans.

#### 4. `sarif`
Valid **SARIF v2.1.0** JSON document including `tool.driver.rules` descriptors and `results` with `physicalLocation` and `fixes`, ready for upload to GitHub Code Scanning or Azure DevOps.

### Inline Suppression Directives

`wincheck` supports inline comment directives using either `REM wincheck ...` or `:: wincheck ...` (and also accepts `shellcheck` as an alias):

```bat
@echo off
REM wincheck disable=CMD4005,CMD1009
REM ^ Placed before the first command: suppresses CMD4005 and CMD1009 for the entire file.

REM wincheck disable=CMD2003
if %1==--help goto :usage
```

Supported directive clauses:
- `disable=CMDxxxx,CMDyyyy` — Suppresses specific rules (for the next line, or file-wide if placed in the file header before any executable command).
- `disable=all` — Suppresses all rules for the next line or entire file.
- `enable=CMDxxxx,CMDyyyy` / `enable=all` — Re-enables previously disabled rule(s) or all rules.
- `source-path=...` — Declares base path metadata for cross-script `CALL` resolution.

### Complete Rule Catalog (`CMD0001` – `CMD5010`)

#### Directive & Meta Rules (`CMD0xxx`)

| Rule ID | Severity | Name | Summary | Auto-Fix |
| :--- | :--- | :--- | :--- | :---: |
| `CMD0001` | Warning | `invalid-directive` | Unrecognized or malformed `wincheck` inline directive or unknown rule ID. | — |

#### Syntax, Lexing, Encoding & Comment Pitfalls (`CMD1xxx`)

| Rule ID | Severity | Name | Summary | Auto-Fix |
| :--- | :--- | :--- | :--- | :---: |
| `CMD1001` | Error | `double-colon-in-block` | `::` label comment used inside a `( ... )` parenthesized block breaks block parsing. | `REM ...` |
| `CMD1002` | Error | `unbalanced-parentheses` | Unbalanced or unclosed `(` or `)` in command block. | — |
| `CMD1003` | Error | `unescaped-paren-in-block` | Unescaped `)` inside `ECHO` or command arguments inside a `( ... )` block prematurely closes the block. | `^)` |
| `CMD1004` | Warning | `trailing-whitespace-after-caret` | Trailing space or tab after `^` line continuation escapes the space instead of the newline. | Strip spaces |
| `CMD1005` | Error | `dangling-else` | `ELSE` keyword is not recognized unless the `IF` then-branch is enclosed in parentheses `(...)`. | `(...) ELSE (...)` |
| `CMD1006` | Error | `multi-char-for-var` | `FOR` loop variable must be a single character (e.g., `%%I`, not `%%item`). | — |
| `CMD1007` | Error | `single-percent-for-var` | Single `%I` used for `FOR` variable in a batch script instead of `%%I`. | `%%I` |
| `CMD1008` | Warning | `utf8-bom` | UTF-8 Byte Order Mark (`EF BB BF`) at start of file corrupts the first command on line 1 in `cmd.exe`. | — |
| `CMD1009` | Info | `non-crlf-line-endings` | Script uses Unix `LF` or mixed line endings instead of Windows `CRLF`, risking byte-offset `GOTO` bugs. | — |
| `CMD1010` | Error | `invalid-set-a-expression` | Invalid `SET /A` arithmetic expression syntax or malformed octal literal (`08`/`09`). | — |
| `CMD1011` | Warning | `unquoted-set-a-special` | Unquoted bitwise shift/logic operators (`<<`, `>>`, `&`, `\|`, `^`) in `SET /A` are parsed as redirections/pipes. | Quote expr |
| `CMD1012` | Warning | `invalid-label-characters` | Label definition `:name` contains spaces or delimiter characters that truncate the label name. | — |
| `CMD1013` | Error | `probable-syntax-misuse` | Probable syntax misuse (`IF a = b`, `IF (a == b)`, missing `IN`/`DO` in `FOR`, unclosed `"`). | `==`, `IN`, `DO`, `"` |
| `CMD1014` | Warning | `execution-mode-percent-mismatch` | Mismatch between single `%` (REPL mode) and double `%%` (batch file mode). | `%%` <-> `%` |

#### Variable Expansion, Delayed Expansion & Quoting Bugs (`CMD2xxx`)

| Rule ID | Severity | Name | Summary | Auto-Fix |
| :--- | :--- | :--- | :--- | :---: |
| `CMD2001` | Error | `stale-percent-var-in-block` | Variable is modified via `SET` and read via `%VAR%` inside the same `( ... )` block (reads stale pre-block value). | `!VAR!` |
| `CMD2002` | Warning | `delayed-expansion-not-enabled` | `!VAR!` delayed expansion syntax used without `SETLOCAL EnableDelayedExpansion` active in scope. | — |
| `CMD2003` | Warning | `unquoted-if-comparison` | Unquoted variable or parameter in `IF` comparison causes syntax error if empty or containing spaces. | `"%VAR%"` |
| `CMD2004` | Warning | `trailing-whitespace-in-set` | Unquoted `SET VAR=value ` has trailing spaces that become part of the variable's value. | `SET "VAR=val"` |
| `CMD2005` | Warning | `spaces-around-set-equals` | Spaces around `=` in `SET VAR = value` create a variable named `"VAR "` with a leading space in its value. | `SET "VAR=val"` |
| `CMD2006` | Warning | `unquoted-path-argument` | Unquoted variable/parameter path passed to filesystem command (`CD`, `COPY`, `MOVE`, `DEL`, `RD`, `MD`, `TYPE`, `IF EXIST`). | `"%VAR%"` |
| `CMD2007` | Warning | `double-quoted-positional-arg` | Quoting `"%1"` instead of `"%~1"` risks doubling quotes (`""path""`) if the caller already quoted the argument. | `"%~1"` |
| `CMD2008` | Warning | `unescaped-special-in-set` | Unquoted special characters (`&`, `\|`, `<`, `>`) in `SET` assignment. | `SET "VAR=val"` |
| `CMD2009` | Error | `stale-dynamic-var-in-block` | Reading `%ERRORLEVEL%`, `%RANDOM%`, or `%TIME%` via `%` inside a `( ... )` block freezes at pre-block value. | `!VAR!` |
| `CMD2010` | Warning | `shadowing-dynamic-variable` | Assigning to dynamic pseudo-variable (`CD`, `DATE`, `TIME`, `RANDOM`, `ERRORLEVEL`, `CMDEXTVERSION`) permanently breaks dynamic evaluation. | — |
| `CMD2011` | Info | `unescaped-bang-in-delayed-expansion` | Unescaped literal `!` in `ECHO` text while `EnableDelayedExpansion` is active causes `!` to be stripped/expanded. | — |
| `CMD2012` | Warning | `unassigned-variable-reference` | Variable is referenced (`%VAR%` / `!VAR!`) but never assigned in the script and is not a standard Windows env var. | — |
| `CMD2013` | Info | `unused-variable-assignment` | Variable is assigned via `SET` but never read in the script. | — |
| `CMD2014` | Warning | `invalid-modifier-on-env-var` | Path modifier `%~dpVAR%` applied to a named environment variable instead of `%0`–`%9` or `%%I`. | — |

#### Control Flow, Labels, Subroutines, Pipes & `ERRORLEVEL` (`CMD3xxx`)

| Rule ID | Severity | Name | Summary | Auto-Fix |
| :--- | :--- | :--- | :--- | :---: |
| `CMD3001` | Error | `missing-goto-label` | `GOTO` or `CALL` targets a `:label` that does not exist in the script. | — |
| `CMD3002` | Warning | `duplicate-label` | Duplicate `:label` definition in the same script (`cmd.exe` always jumps to the first match). | — |
| `CMD3003` | Warning | `batch-invoked-without-call` | Invoking another `.bat`/`.cmd` script without `CALL` transfers control permanently without returning. | `CALL ...` |
| `CMD3004` | Warning | `exit-without-b` | `EXIT` without `/B` closes the entire `cmd.exe` console session instead of just the batch script. | `EXIT /B` (`--unsafe-fixes`) |
| `CMD3005` | Warning | `subroutine-fallthrough` | Execution falls through from main script into a `:subroutine` label without a preceding `EXIT /B` or `GOTO :EOF`. | — |
| `CMD3006` | Warning | `unreachable-code` | Unreachable command immediately following an unconditional `GOTO`, `EXIT`, or direct `.bat` invocation. | — |
| `CMD3007` | Error | `if-errorlevel-zero` | `IF ERRORLEVEL 0` is always true for any exit code `>= 0` (`IF ERRORLEVEL N` tests `ERRORLEVEL >= N`). | — |
| `CMD3008` | Warning | `ascending-errorlevel-checks` | `IF ERRORLEVEL` checked in ascending order (`IF ERRORLEVEL 1 ... ELSE IF ERRORLEVEL 2`) makes higher checks unreachable. | — |
| `CMD3009` | Warning | `goto-inside-block` | `GOTO` used inside a `FOR` loop or parenthesized block cancels loop state and can corrupt block parsing. | — |
| `CMD3010` | Warning | `state-mutation-in-pipe` | `SET`, `SETLOCAL`, or `CD` inside a pipeline `cmd1 \| cmd2` executes in a child subshell and is discarded. | — |
| `CMD3011` | Info | `robocopy-errorlevel-trap` | `ROBOCOPY` exit codes `0`–`7` indicate success (`1` = files copied); checking `IF ERRORLEVEL 1` treats success as failure. | — |

#### Built-In Command Footguns, Safety & Style (`CMD4xxx`)

| Rule ID | Severity | Name | Summary | Auto-Fix |
| :--- | :--- | :--- | :--- | :---: |
| `CMD4001` | Warning | `cd-without-d-switch` | `CD X:\path` with a drive letter but without `/D` does not switch the active drive to `X:`. | `CD /D ...` |
| `CMD4002` | Warning | `echo-possibly-empty-var` | `ECHO %VAR%` prints `ECHO is off.` instead of a blank line if `%VAR%` expands to empty or whitespace. | `ECHO(%VAR%` |
| `CMD4003` | Warning | `for-f-quoted-string-without-usebackq` | `FOR /F` with double-quoted path `("C:\file.txt")` without `usebackq` parses the path as a literal string. | — |
| `CMD4004` | Error | `dangerous-root-delete` | Dangerous `RD /S /Q` or `DEL /S /Q` with `%VAR%` resolves to root `\` if `VAR` is unset, wiping the entire drive! | — |
| `CMD4005` | Info | `missing-setlocal` | Script modifies environment variables via `SET` without calling `SETLOCAL`, leaking state into the caller. | — |
| `CMD4006` | Style | `missing-echo-off` | Batch script does not begin with `@ECHO OFF`. | — |
| `CMD4007` | Warning | `octal-date-time-in-set-a` | Using `%DATE%` or `%TIME%` slices in `SET /A` without stripping leading zeros fails on `08` and `09` as invalid octal. | — |
| `CMD4008` | Warning | `choice-default-not-in-choices` | `CHOICE /D` default key is not present in the `/C` choice list. | — |
| `CMD4009` | Warning | `ambiguous-multifile-copy-dest` | `COPY` or `MOVE` with multiple sources into a destination not ending with `\` is ambiguous if the directory is missing. | — |
| `CMD4010` | Style | `prefer-rem-over-double-colon` | Prefer standard `REM` over `::` label-comment syntax. | — |

#### MS-DOS `COMMAND.COM` Portability Rules (`CMD5xxx`, active with `--dialect dos622`)

| Rule ID | Severity | Name | Summary | Auto-Fix |
| :--- | :--- | :--- | :--- | :---: |
| `CMD5001` | Error | `dos-unsupported-set-switch` | `SET /A` arithmetic and `SET /P` interactive prompts are unsupported in MS-DOS `COMMAND.COM`. | — |
| `CMD5002` | Error | `dos-unsupported-for-variant` | `FOR /F`, `FOR /L`, `FOR /R`, and `FOR /D` switches are unsupported in MS-DOS `COMMAND.COM`. | — |
| `CMD5003` | Error | `dos-unsupported-if-syntax` | `IF /I`, `IF DEFINED`, `IF CMDEXTVERSION`, `EQU`–`GEQ`, and `ELSE` are unsupported in MS-DOS `COMMAND.COM`. | — |
| `CMD5004` | Error | `dos-compound-or-chaining` | Parenthesized `( ... )` blocks and `&`, `&&`, `\|\|` command chains are unsupported in MS-DOS `COMMAND.COM`. | Split `&` lines |
| `CMD5005` | Error | `dos-extended-var-syntax` | Delayed `!VAR!`, `%VAR:~...%` / `%VAR:a=b%`, `%*`, and `%~dpnx1` modifiers are unsupported in MS-DOS `COMMAND.COM`. | — |
| `CMD5006` | Error | `dos-subroutine-or-eof` | `CALL :label`, implicit `GOTO :EOF`, and `EXIT /B` are unsupported in MS-DOS `COMMAND.COM`. | Append `:EOF` |
| `CMD5007` | Error | `dos-nt-only-builtin` | `SETLOCAL`, `ENDLOCAL`, `PUSHD`, `POPD`, `ASSOC`, `FTYPE`, and `MKLINK` are unavailable in MS-DOS `COMMAND.COM`. | — |
| `CMD5008` | Error | `dos-numeric-fd-redirect` | Numeric handle redirections (`2>`, `2>&1`, `1>&2`) are unsupported in MS-DOS `COMMAND.COM`. | — |
| `CMD5009` | Warning | `dos-non-8-3-path` | Filename or path segment violates MS-DOS FAT 8.3 limits or uses `.cmd` instead of `.bat`. | — |
| `CMD5010` | Warning | `dos-psp-tail-too-long` | External command argument tail exceeds the 126-byte MS-DOS `PSP:0x80` command-line limit. | — |

---

## Architecture & Authentic `cmd.exe` Pipeline

Unlike POSIX shells (`sh`, `bash`, `zsh`) that lex and parse a script into an AST upfront, Windows `cmd.exe` is a streaming byte-offset macro processor with four distinct expansion phases per statement. `win-cmd-rs` models every phase explicitly:

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ Phase 0: Byte-Offset Script Reader (`src/reader/`)                         │
│  • Seeks to `current_offset: ByteOffset` in VFS (supports self-modifying!) │
│  • Decodes CP437/850/852/865/866/1252 / UTF-8 / UTF-16LE/BE & `0x1A` EOF   │
│  • Joins `^` line continuations into `LogicalLineBuffer` of `SpannedChar`  │
└───────────────────────────────────────┬────────────────────────────────────┘
                                        ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Phase 1: Batch Parameter & Immediate `%` Expansion (`src/parser/phase1.rs`)│
│  • Batch vs Interactive `%` rules (`%%` -> `%`, stray `%` stripped)        │
│  • Positional args `%0`..`%9`, `%*`, and `%~dpnxfsatz$PATH:1` modifiers    │
│  • Immediate `%VAR%`, `%VAR:~start,len%`, and `%VAR:*search=replace%`      │
└───────────────────────────────────────┬────────────────────────────────────┘
                                        ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Phase 2: Special Tokenization & Compound Blocks (`src/parser/phase2.rs`)   │
│  • Quote (`"`) and Caret (`^`) escaping state machine                      │
│  • Reads multi-line `(...)` compound blocks (running Phase 1 on each line!)│
│  • Parses `IF`, `FOR`, pipes `|`, chains `&`/`&&`/`||`, and redirections   │
└───────────────────────────────────────┬────────────────────────────────────┘
                                        ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Phase 3: `FOR` Loop Variable Expansion (`src/parser/phase3.rs`)            │
│  • Expands active `%I` / `%%I` and `%~dpnxI` against `FOR` scope stack     │
└───────────────────────────────────────┬────────────────────────────────────┘
                                        ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ Phase 4: Delayed Expansion (`!VAR!`) (`src/parser/phase4.rs`)              │
│  • Active when `DelayedExpansionMode::Enabled` AND line contains `!`       │
│  • Performs second `^` escape pass (even inside `"..."`!) & expands `!VAR!`│
└────────────────────────────────────────────────────────────────────────────┘
```

### Phase 0: Byte-Offset Script Reader, Encodings & Line Continuation

- **Byte-Offset Seeking**: `BatchFrameReader` tracks `current_offset: ByteOffset`. Before fetching each statement, it reads the file from the `VirtualFileSystem` at `current_offset`. If a batch script appends commands to itself (`echo echo Added dynamically >> "%~f0"`), `wincmd` executes the newly appended lines just like native `cmd.exe`.
- **Codepages & `0x1A` SUB EOF**: Supports `CodePage::Utf8` (`65001`), `OemUnitedStates` (`437`), `OemMultilingualLatin1` (`850`), `OemLatin2` (`852`), `OemNordic` (`865`), `OemCyrillic` (`866`), `WindowsLatin1` (`1252`), `Utf16Le` (`1200`), `Utf16Be` (`1201`), and `Ascii` (`20127`), with full 256-entry lookup tables for OEM box-drawing/international characters, live `DosKernelApi` `CHCP` synchronization, and `0x1A` (`Ctrl+Z`) logical EOF truncation.
- **Physical-to-Logical Span Mapping**: Every character in `LogicalLineBuffer` is a `SpannedChar` tracking its exact `Span` and `ExpansionOrigin` (`LiteralSource`, `CaretContinuation`, `PositionalParam`, `ImmediateEnvVar`, `ForVariable`, `DelayedEnvVar`).

### Phase 1: Immediate `%` Expansion, `%~` Modifiers & Variable Slicing

- **Batch Mode vs. Interactive Mode**:
  - In **Batch Mode**, `%%` collapses to a literal `%`, `%0`–`%9` and `%*` expand positional arguments, undefined `%VAR%` expands to `""`, and a lone unmatched `%` is stripped.
  - In **Interactive Mode** (`wincmd /C` or REPL), `%%` does not collapse, undefined `%VAR%` remains literal `%VAR%`, and unmatched `%` is preserved.
- **Greedy `%~` Modifier Backtracking (`src/parser/modifiers.rs`)**:
  - Supports all `cmd.exe` parameter and `FOR`-variable modifiers and combinations (e.g., `%~dp0`, `%~dpnx1`, `%~ftza1`, `%~$PATH:1`, `%~dp$PATH:1`):
    - `~`: Strips surrounding quotes `"`
    - `f`: Full canonicalized path (`C:\dir\file.txt`)
    - `d`: Drive letter with colon (`C:`) or UNC share prefix (`\\server\share`)
    - `p`: Path with trailing backslash (`\dir\`)
    - `n`: Filename stem without extension (`file`)
    - `x`: File extension including leading dot (`.txt`)
    - `s`: Path containing 8.3 short names (`C:\PROGRA~1\FILE~1.TXT`)
    - `a`: 9-character Windows file attribute string (`drahscotl`, e.g., `--a------`)
    - `t`: Last-modified timestamp (`MM/DD/YYYY hh:mm AM/PM`)
    - `z`: File size in bytes
    - `$ENVVAR:`: Searches directories in `%ENVVAR%` and expands to full path of first match
- **Substrings & Search/Replace (`src/parser/var_ops.rs`)**:
  - `%VAR:~start,length%` with positive or negative offsets and lengths (supporting decimal, `0x` hex, and `0` octal).
  - Case-insensitive substring replacement `%VAR:old=new%` and prefix-glob replacement `%VAR:*old=new%`.

### Phase 2: Special Tokenization, Quoting, Carets & Compound Blocks

- **Compound Block Pre-Expansion**: When `(` opens a block, `cmd.exe` reads physical lines until the matching `)` and runs **Phase 1 expansion on every line as it is read**. This reproduces the classic `cmd.exe` behavior where `%VAR%` inside a `( ... )` block evaluates to the value `VAR` had before the block began.
- **Command-Specific Lexing**:
  - `REM`: Consumes the remainder of the line without interpreting `|`, `&`, `<`, `>`, `(`, or `)`.
  - `ECHO`: Preserves the exact raw tail after the delimiter character (`ECHO `, `ECHO.`, `ECHO(`, `ECHO:`, `ECHO/`, `ECHO=`, `ECHO+`, `ECHO;`, `ECHO,`, `ECHO[`, `ECHO]`) while still extracting redirections anywhere on the line (`> out.txt echo hello`).

### Phase 3: `FOR` Loop Variable Expansion

- Supports all five `FOR` variants:
  - Standard file/wildcard iteration: `FOR %%I IN (set) DO ...`
  - Directory-only iteration: `FOR /D %%I IN (set) DO ...`
  - Recursive directory walk: `FOR /R [path] %%I IN (set) DO ...`
  - Arithmetic sequence: `FOR /L %%I IN (start,step,end) DO ...`
  - Text/command line parsing: `FOR /F ["eol=; skip=n delims=... tokens=1,2-4* usebackq"] %%I IN (...) DO ...` with automatic multi-token ASCII variable allocation (`%%I`, `%%J`, `%%K`, ...).

### Phase 4: Delayed Expansion (`!VAR!`) & Caret Pass Quirk

- Runs immediately before command dispatch when `DelayedExpansionMode::Enabled` (`SETLOCAL EnableDelayedExpansion` or `wincmd /V:ON`).
- Reproduces `cmd.exe`'s exact condition: if a command line contains **no `!` character**, Phase 4 is completely skipped (leaving `^` characters inside quotes untouched). If at least one `!` is present, `^` escapes the following character even inside double quotes `"..."` and `!VAR!` (including `!VAR:~start,len!` and `!VAR:old=new!`) is expanded against the live `EnvironmentStack`.

### `SET /A` 32-Bit Signed Arithmetic Engine

`src/runtime/arithmetic.rs` implements a complete recursive-descent parser matching `cmd.exe`'s 10-level operator precedence and 32-bit signed wrapping semantics (`i32`):
1. `,` (Comma sequence separator)
2. `=`, `*=`, `/=`, `%=`, `+=`, `-=`, `&=`, `^=`, `|=`, `<<=`, `>>=` (Right-associative assignments that mutate `EnvironmentStack` immediately during expression evaluation, so `SET /A "a=2, b=a+3"` yields `a=2` and `b=5`)
3. `|` (Bitwise OR)
4. `^` (Bitwise XOR)
5. `&` (Bitwise AND)
6. `<<`, `>>` (Bitwise shifts with shift count masked by `& 0x1F`)
7. `+`, `-` (Wrapping 32-bit signed addition and subtraction)
8. `*`, `/`, `%` (Wrapping multiplication, division, and remainder with `DivideByZero` detection and safe `i32::MIN / -1` wrapping)
9. `+`, `-`, `~`, `!` (Unary plus, negation, bitwise NOT, logical NOT)
10. `( expr )` (Parenthesized grouping and implicit bare-identifier variable dereferencing)

### Virtual File System (`InMemoryVfs`, `HostOsVfs` & `DosFatVfs`), 8.3 Short Names & Win32 Globs

- **Per-Drive Working Directories**: Tracks the active drive (`C:`) plus independent current working directories for every mounted drive (`=C:`, `=D:` hidden environment variables), so `C:foo\bar` resolves relative to `C:`'s CWD even when `D:` is active.
- **Win32 & MS-DOS FAT Path Normalization**: Handles drive-absolute (`C:\a`), drive-relative (`C:a`), root-relative (`\a`), relative (`.\a`, `..\a`), UNC (`\\server\share\a`), and extended device paths (`\\?\C:\a`). On `DosFatVfs`, `LfnSupportMode::Disabled8Dot3Only` enforces authentic `COMMAND.COM` 8.3 stem/extension truncation while `LfnSupportMode::EnabledInt21Ax71` preserves DOS 7 long filenames alongside 8.3 short names.
- **Win32 `FsRtlIsNameInExpression` Globbing**: Implements `DOS_STAR` (`*`), `DOS_QM` (`?` matching 1 char, or 0 chars before `.` or at end of name), and `DOS_DOT` (`.` matching literal `.` or end of filename so `*.*` matches extensionless files and `*.` matches only extensionless files).

---

## Built-In Commands & Cross-Platform Utility Shims

### Core `cmd.exe` & MS-DOS `COMMAND.COM` Built-In Commands

| Category | Commands |
| :--- | :--- |
| **Environment & Scope** | `SET` (list, prefix filter, assign, `/A` arithmetic, `/P` prompt), `SETLOCAL` (`EnableExtensions`, `DisableExtensions`, `EnableDelayedExpansion`, `DisableDelayedExpansion`), `ENDLOCAL`, `PATH`, `PROMPT`, `ASSOC`, `FTYPE` |
| **Control Flow & Batch** | `IF` (`/I`, `NOT`, `ERRORLEVEL`, `EXIST`, `DEFINED`, `CMDEXTVERSION`, `==`, `EQU`, `NEQ`, `LSS`, `LEQ`, `GTR`, `GEQ`), `FOR` (`/D`, `/R`, `/L`, `/F`), `CALL` (batch file, `:subroutine`, command twice-expansion), `GOTO` (`:label`, `:EOF`), `SHIFT` (`/0`..`/8`), `EXIT` (`/B [code]`), `PAUSE`, `START` (`/B`, `/I`, `/WAIT`, `/MIN`, `/MAX`, `/D <dir>`), `LH` / `LOADHIGH` (`/L:...`, `/S`) |
| **Filesystem & Navigation** | `CD` / `CHDIR` (`/D`), `MD` / `MKDIR`, `RD` / `RMDIR` (`/S`, `/Q`), `PUSHD`, `POPD`, `DIR` (`/B`, `/S`, `/A`, `/O`, `/W`, `/D`, `/L`, `/X`), `COPY` (`/A`, `/B`, `/Y`, `/-Y`, `a+b` concatenation), `DEL` / `ERASE` (`/P`, `/F`, `/S`, `/Q`, `/A`), `REN` / `RENAME` (with wildcard masks), `MOVE` (`/Y`, `/-Y`), `TYPE`, `TRUENAME`, `MKLINK` (`/D`, `/H`, `/J`), `<Drive>:` (`A:`, `C:`, `D:`, `Z:`) |
| **Console, System & Shell** | `ECHO` (`ON`, `OFF`, message), `REM`, `CLS` (BIOS `INT 10h` or ANSI CSI), `COLOR`, `TITLE`, `CHCP`, `CTTY` (`CON`, `AUX`, `COM1`–`COM4`, `NUL`), `MODE` (`CON`, `COLS=c`, `LINES=n`), `VER`, `VOL`, `DATE` (`/T`), `TIME` (`/T`), `VERIFY` (`ON`, `OFF`), `DOSKEY` (`/MACROS`, `/HISTORY`, `/REINSTALL`, `/LISTSIZE=n`) |

### Cross-Platform Windows & MS-DOS Utility Shims

To allow real-world Windows and MS-DOS `.bat` scripts to run unmodified everywhere, `wincmd` includes built-in shims for standard system utilities:

| Utility Shim | Supported Switches & Behavior |
| :--- | :--- |
| `CMD` | Spawns nested `cmd.exe` subshells (`/C`, `/K`, `/S`, `/Q`, `/D`, `/A`, `/U`, `/E:ON\|OFF`, `/V:ON\|OFF`, `/T:bf`) honoring live `Command Processor` Registry defaults. |
| `MEM` | Reports conventional 640 KiB and extended XMS/DPMI memory tables (`/C`, `/D`, `/F`, `/M`, `/P`) from live `DosKernelApi::memory_stats()` or deterministic defaults. |
| `REG` | Queries and modifies the Windows/Wine Registry (`QUERY`, `ADD`, `DELETE`, `COPY`, `EXPORT`, `IMPORT` across `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`). |
| `WHERE` | Searches `%PATH%` or `/R <dir>` using `%PATHEXT%` (`/Q` quiet exit code, `/F` quoted output, `/T` size & timestamp). |
| `FIND` | Searches for literal strings in files or `stdin` (`/V` invert, `/C` count only, `/N` line numbers, `/I` case-insensitive). |
| `FINDSTR` | Searches files or `stdin` using literals or `O(\|P\| * \|L\|)` regexes (`/B`, `/E`, `/L`, `/R`, `/S`, `/I`, `/X`, `/V`, `/N`, `/M`, `/C:"..."`). |
| `CHOICE` | Prompts user to select from choice keys (both Windows NT `/C keys /N /CS /T nn /D c /M msg` and MS-DOS 6.x `/C[:]keys /S /T[:]c,nn`) and sets `ERRORLEVEL` to the 1-based key index. |
| `TIMEOUT` | Pauses execution for `/T <seconds>` (`-1..=99999`, `/NOBREAK`). |
| `ATTRIB` | Displays or modifies `R`, `A`, `S`, `H` file attributes (`+R`, `-R`, `+A`, `-A`, `+S`, `-S`, `+H`, `-H`, `/S`, `/D`). |
| `SORT` | Sorts input lines alphabetically (`/R` reverse, `/+n` start column, `/O <file>` output file, `/UNIQUE` / `/UNIQ` deduplicate). |
| `MORE` | Renders input streams with optional line skipping (`+n`), blank-line squeezing (`/S`), and tab expansion. |
| `FC` | Compares two files in text or binary mode (`/B` binary, `/C` case-insensitive, `/N` line numbers, `/W` compress whitespace). |
| `COMP` | Compares two files byte-by-byte (`/C` case-insensitive), reporting exact size or offset mismatches. |
| `TREE` | Renders recursive directory hierarchies (`/F` include files, `/A` ASCII branch characters). |
| `XCOPY` | Copies files and directory trees recursively (`/S`, `/E`, `/Y`, `/-Y`, `/I`, `/Q`). |
| `ROBOCOPY` | Copies directory trees and sets authentic `ROBOCOPY` bitmask exit codes (`1` when files are copied, `0` when no copy needed). |
| `HOSTNAME` / `WHOAMI` | Outputs host/emulated machine name (`%COMPUTERNAME%`) and domain\user identity (`%USERDOMAIN%\%USERNAME%`). |

---

## Rust Library Usage (`win_cmd_rs`)

Add `win-cmd-rs` to your `Cargo.toml` (disable default features for `#![no_std]` + `alloc` environments):

```toml
[dependencies]
win-cmd-rs = "0.0.1"
# Or for `#![no_std]` + `alloc` targets (MS-DOS DJGPP, kernels, sandboxes):
# win-cmd-rs = { version = "0.0.1", default-features = false }
```

### Executing Commands & Scripts in an In-Memory Sandbox

By default, `Interpreter::new()` initializes an isolated `InMemoryVfs` with `C:` and standard Windows environment variables (`COMSPEC`, `PATHEXT`, `SYSTEMROOT`, etc.) so scripts can be executed deterministically in memory without touching the host disk:

```rust
use win_cmd_rs::error::CmdError;
use win_cmd_rs::runtime::{Interpreter, IoStreams};
use win_cmd_rs::types::ExitCode;

fn main() -> Result<(), CmdError> {
    let mut interp = Interpreter::new();
    let mut io = IoStreams::new();

    // Write a batch script into the in-memory VFS on drive C:
    let script = b"@echo off\r\nsetlocal EnableDelayedExpansion\r\nset \"total=0\"\r\nfor /L %%i in (1,1,5) do (\r\n    set /a \"total+=%%i\"\r\n)\r\necho Sum is !total!\r\nexit /b 0\r\n";
    interp.proc_env.vfs.write_bytes(r"C:\calc.bat", script)?;

    // Execute the script and capture stdout/stderr in memory
    let exit_code = interp.execute_interactive_line(r"call C:\calc.bat", &mut io);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert_eq!(io.stdout, "Sum is 15\r\n");
    Ok(())
}
```

To run against a directory on the host OS instead (`std` feature), initialize the interpreter with `HostOsVfs`:

```rust
use std::path::PathBuf;
use win_cmd_rs::runtime::Interpreter;
use win_cmd_rs::vfs::HostOsVfs;

let vfs = HostOsVfs::new(PathBuf::from("/tmp/sandbox_c_drive"));
let mut interp = Interpreter::with_vfs(Box::new(vfs));
```

### Simulating MS-DOS (`SimulatedDosKernel`) & `#![no_std]` Embedding

Both host tests and `#![no_std]` callers can run `Interpreter` and `DosFatVfs` over `SimulatedDosKernel` (or a custom `DosKernelApi` implementation):

```rust
use win_cmd_rs::dos::SimulatedDosKernel;
use win_cmd_rs::error::CmdError;
use win_cmd_rs::runtime::{Interpreter, IoStreams};
use win_cmd_rs::types::{ExitCode, ShellDialect};

fn main() -> Result<(), CmdError> {
    let (mut interp, _kernel) = Interpreter::with_dos_kernel(SimulatedDosKernel::new());
    interp.apply_shell_dialect(ShellDialect::MsDos622);

    interp.proc_env.vfs.write_bytes(r"C:\LONGFILENAME.TXT", b"DOS83\r\n")?;
    let mut io = IoStreams::new();
    assert_eq!(interp.execute_interactive_line(r"truename .\LONGFILENAME.TXT", &mut io), ExitCode::SUCCESS);
    assert_eq!(io.stdout, "C:\\LONGFILE.TXT\r\n");
    Ok(())
}
```

### Programmatic Static Analysis & Auto-Fixing

Use `win_cmd_rs::linter` to lint batch scripts (for either Windows `cmd.exe` or MS-DOS `COMMAND.COM`), format diagnostics, or apply lossless automatic fixes in Rust:

```rust
use win_cmd_rs::linter::{
    LinterConfig, OutputFormat, format_diagnostics, lint_script, rewrite_script,
};
use win_cmd_rs::span::SourceMap;
use win_cmd_rs::types::{ExecutionContext, ShellDialect};

fn main() -> Result<(), win_cmd_rs::error::CmdError> {
    let raw_script = b"@echo off\r\nsetlocal\r\nset VAR = 42\r\nif %VAR%==42 echo %VAR%\r\n";
    let config = LinterConfig::default();
    let mut source_map = SourceMap::new();

    let (_source_id, diagnostics) =
        lint_script("example.bat", raw_script, &config, &mut source_map)?;

    // Render human-readable diagnostics
    let report = format_diagnostics(&diagnostics, &source_map, OutputFormat::Tty);
    assert!(!report.is_empty());

    // Apply semantics-preserving CST fixes (`set "VAR=42"`, `if "%VAR%"=="42"`, `echo(%VAR%`)
    let original_text = String::from_utf8_lossy(raw_script);
    let (fixed_text, applied_count) =
        rewrite_script(&original_text, ExecutionContext::BatchFile, &config);
    assert!(applied_count >= 2);
    assert!(fixed_text.contains(r#"set "VAR=42""#));

    // Audit and auto-fix an MS-DOS 6.22 batch script (`CMD5004`, `CMD5006`)
    let dos_cfg = LinterConfig {
        dialect: ShellDialect::MsDos622,
        ..LinterConfig::default()
    };
    let (dos_fixed, dos_edits) =
        rewrite_script("@echo off\r\ngoto :EOF\r\n", ExecutionContext::BatchFile, &dos_cfg);
    assert_eq!(dos_edits, 1);
    assert!(dos_fixed.ends_with(":EOF\r\n"));

    Ok(())
}
```

---

## Repository Structure

```text
win-cmd-rs/
├── .editorconfig               # Consistent workspace formatting rules
├── .gitattributes              # Line-ending normalization attributes
├── .gitignore                  # Ignored build & coverage artifacts
├── .pre-commit-config.yaml     # Automated doc, anti-pattern, no_std, lint & 100% branch coverage gates
├── .github/
│   └── workflows/
│       └── ci.yml              # Linux/macOS/Windows CI, 100% coverage, FreeDOS QEMU & release builds
├── Cargo.toml                  # Root `#![no_std]`/`std` manifest & strict rustc/clippy/rustdoc lints
├── Cargo.lock                  # Reproducible dependency lockfile
├── LICENSE-APACHE              # Apache License, Version 2.0
├── LICENSE-MIT                 # MIT License
├── README.md                   # Project overview & quick reference
├── USAGE.md                    # Comprehensive CLI, MS-DOS dialect, CI/CD & Rust API guide
├── ARCHITECTURE.md             # Deep architectural guide with Mermaid diagrams
├── targets/
│   └── i586-pc-msdosdjgpp.json # Custom 32-bit x86 soft-float COFF target spec for MS-DOS DJGPP
├── crates/
│   └── wincmd-dos/             # Isolated 32-bit Protected-Mode MS-DOS (`DJGPP` + `CWSDPMI`) crate
│       ├── Cargo.toml          # Target crate manifest & identical strict lint table
│       ├── Cargo.lock          # Target crate lockfile
│       ├── src/
│       │   ├── lib.rs          # Stream-generic DOS CLI runners & unit test suite
│       │   ├── alloc_djgpp.rs  # Alignment-safe `#[global_allocator]` over DJGPP `malloc`/`free`
│       │   ├── panic_dos.rs    # Zero-heap-allocation stack `#[panic_handler]` to DOS `STDERR`
│       │   ├── ffi.rs          # Thin `unsafe` DJGPP `libc` & DPMI `INT 10h/11h/16h/21h/31h` bindings
│       │   ├── djgpp_kernel.rs # Safe `DosKernelApi` implementation (`DjgppDosKernel`)
│       │   ├── stub_verify.rs  # Assembled 16-bit MZ CPU guard bytes & behavioral verifier
│       │   └── bin/
│       │       ├── wincmd.rs   # `WINCMD.EXE` entrypoint
│       │       └── wincheck.rs # `WINCHECK.EXE` entrypoint
│       ├── stub/
│       │   ├── cpu_guard_stub.asm # 16-bit real-mode 8086/80286 CPU guard MZ stub (`NASM`)
│       │   ├── chkstk_dos.s    # 32-bit x86 COFF stack-probe shim
│       │   ├── djgpp-rust.ld   # DJGPP COFF linker script
│       │   └── djgpp-linker.sh # `i586-pc-msdosdjgpp-gcc` + `stubify` + MZ CPU guard patcher
│       └── tests/
│           └── dos_binaries.rs # Subprocess integration tests for `wincmd-dos` binaries
├── src/
│   ├── lib.rs                  # `#![cfg_attr(not(feature = "std"), no_std)]` library root
│   ├── span.rs                 # BOM-aware ByteOffset, LineNumber, ColumnNumber, Span & SourceMap
│   ├── types.rs                # Domain primitives (ExitCode, DriveLetter, IoErrorKind, ShellDialect, etc.)
│   ├── error.rs                # Unified `no_std` derive_more CmdError enum (`cmd.exe` & DOS messages)
│   ├── bin/
│   │   ├── wincmd.rs           # Host `wincmd` CLI binary entrypoint
│   │   └── wincheck.rs         # Host `wincheck` CLI binary entrypoint
│   ├── dos/
│   │   ├── mod.rs              # Safe `#![no_std]` MS-DOS subsystem root & unit tests
│   │   ├── types.rs            # PackedDosTimestamp, FatAttributeByte, DosFileName8Dot3 & PspCommandTail
│   │   ├── kernel.rs           # Safe `DosKernelApi` hardware trait & `SharedDosKernel`
│   │   ├── sim.rs              # Deterministic in-memory `SimulatedDosKernel` (8.3/LFN, faults, `.COM` exec)
│   │   └── console.rs          # `DosConsoleLineEditor` & `run_dos_bios_repl` BIOS scan-code `DOSKEY` editor
│   ├── reader/
│   │   ├── mod.rs              # Phase 0 script reader module root
│   │   ├── encoding.rs         # Incremental decoding (CP437/850/852/865/866/1252/UTF-8/UTF-16)
│   │   ├── char_map.rs         # SpannedChar, ProvenanceMode & LogicalLineBuffer
│   │   └── stream.rs           # Raw-byte BatchFrameReader cursor, `^` continuations & label scanner
│   ├── parser/
│   │   ├── mod.rs              # Unified parser & multi-pass expansion module root
│   │   ├── lexer.rs            # Shared statement/line/word/caret/quote/`ECHO(` lexer & O(N) operator scanner
│   │   ├── cst.rs              # 100% lossless Concrete Syntax Tree (SyntaxKind, CstNode, CstToken, CstScript)
│   │   ├── cst_parser/         # Modular lossless CST builder (`Strict` & `Recovering` modes)
│   │   │   ├── mod.rs          # State, diagnostics & top-level statement/precedence dispatch
│   │   │   ├── control_flow.rs # Compound `( ... )` block, `IF` & `FOR` grammar rules
│   │   │   └── words.rs        # `SimpleCommand`, `SET`, redirections, words & `%`/`!` sub-words
│   │   ├── lower.rs            # Deterministic CST-to-AST lowerer (`PopulateSubwordParts` & `Lightweight`)
│   │   ├── peg.rs              # Lossless CST & AST parser facade
│   │   ├── phase1.rs           # Phase 1: Immediate `%` expansion (`%0`..`%9`, `%*`, `%VAR%`)
│   │   ├── modifiers.rs        # Bitflag `%~dpnxfsatz$PATH:` modifier parser & VFS 8.3 short-path resolver
│   │   ├── var_ops.rs          # `%VAR:~start,len%` slicing & `%VAR:*old=new%` substitution
│   │   ├── phase2.rs           # Phase 2: Runtime statement-reading entrypoints backed by unified CST pipeline
│   │   ├── phase3.rs           # Phase 3: Active `FOR` variable (`%%I`) expansion
│   │   ├── phase4.rs           # Phase 4: Delayed `!VAR!` expansion & `!`-triggered caret pass
│   │   └── ast.rs              # Full Span-preserving AST nodes & sub-word WordPart metadata
│   ├── vfs/
│   │   ├── mod.rs              # VFS module root & cross-backend (`InMemory`/`HostOs`/`DosFat`) conformance tests
│   │   ├── traits.rs           # VirtualFileSystem trait, VfsMetadata, FileTimestamp & FileAttributeFlags
│   │   ├── memory.rs           # Deterministic InMemoryVfs (UNC aliases, hardlinks, symlinks, 8.3 names)
│   │   ├── host.rs             # Sandboxed HostOsVfs bridge, UNC mounts & Wine/POSIX drive translation
│   │   ├── dos.rs              # MS-DOS FAT12/16/32 & DOS 7 LFN `DosFatVfs<K: DosKernelApi>`
│   │   ├── path.rs             # Case-insensitive WindowsPath, UNC validation & NT 8.3 hash generator
│   │   ├── devices.rs          # Reserved DOS device handler (NUL, CON, PRN, AUX, CLOCK$, COM1..9, LPT1..9)
│   │   └── glob.rs             # Polynomial-time Win32 FsRtlIsNameInExpression wildcard engine
│   ├── runtime/
│   │   ├── mod.rs              # Runtime module root & subshell CWD snapshot helpers
│   │   ├── interpreter.rs      # Stateful Interpreter, MemoryProfile, ExecutionLimits & completion
│   │   ├── exec.rs             # AST statement, pipeline, handle 0..=9 redirection & batch-frame engine
│   │   ├── dos_exec.rs         # Single-tasking `DosProcessSpawner` (`INT 21h AH=4Bh`) & `%TEMP%` spooler
│   │   ├── argv.rs             # CommandLineToArgvW parser & `%PATH%`/`%PATHEXT%`/HKCR target resolver
│   │   ├── io.rs               # Portable `no_std` byte streams (`ByteStreamRead`/`Write`), `CmdIo` & spawner
│   │   ├── env.rs              # EnvironmentStack, per-read `%RANDOM%` PRNG & POSIX PATH translation
│   │   ├── arithmetic.rs       # Overflow-safe `SET /A` 32-bit signed arithmetic evaluator
│   │   └── registry.rs         # Canonical Windows Registry (`HKLM`, `HKCU`) & live Command Processor settings
│   ├── builtins/
│   │   ├── mod.rs              # BuiltinInvocation & top-level `dispatch_builtin` router
│   │   ├── env_cmds.rs         # SET, SETLOCAL, ENDLOCAL, PATH, PROMPT, ASSOC, FTYPE
│   │   ├── flow_cmds.rs        # CALL, GOTO, EXIT, SHIFT, PAUSE, CMD, START
│   │   ├── fs_cmds.rs          # DIR, CD, MD, RD, PUSHD, POPD, COPY, DEL, REN, MOVE, TYPE, MKLINK
│   │   ├── console_cmds.rs     # ECHO, CLS, COLOR, TITLE, VER, VOL, DATE, TIME, VERIFY, CHCP, MODE, DOSKEY
│   │   ├── dos_cmds.rs         # MS-DOS `TRUENAME`, `CTTY`, `LH`/`LOADHIGH` & `MEM` (`/C`, `/D`, `/F`, `/M`, `/P`)
│   │   ├── shims_search.rs     # WHERE, FIND, FINDSTR (`/R` regex), SORT, MORE, FC, COMP, TREE
│   │   └── shims_admin.rs      # XCOPY, ROBOCOPY, ATTRIB, CHOICE (NT & DOS 6.x), TIMEOUT, REG, HOSTNAME, WHOAMI
│   ├── linter/
│   │   ├── mod.rs              # `wincheck` VFS-aware analyzer & `lint_script` / `rewrite_script` entrypoints
│   │   ├── rules.rs            # 60-rule catalog (`CMD0001`–`CMD5010`), RuleMetadata & FixApplicability
│   │   ├── directives.rs       # Inline `REM wincheck` disable/enable/source-path directive parser
│   │   ├── formatters.rs       # TTY, GCC, JSON, SARIF & Myers/LCS unified diff formatters
│   │   ├── rewriter.rs         # Composable 5-pass lossless CstRewriter respecting dialects & suppressions
│   │   └── passes/             # Modular AST static analysis & CST rewrite passes
│   │       ├── mod.rs
│   │       ├── delayed_exp.rs
│   │       ├── dialect.rs
│   │       ├── dos_compat.rs   # MS-DOS `COMMAND.COM` portability rules (`CMD5001`–`CMD5010`) & auto-fixes
│   │       ├── quoting.rs
│   │       └── structural.rs
│   └── cli/
│       ├── mod.rs              # `#![no_std]` + `std` CLI module root & end-to-end unit tests
│       ├── wincmd_cli.rs       # `wincmd` flag parser (`/P`, `/E:nnnnn`, `--dialect`) & stream driver
│       ├── wincheck_cli.rs     # `wincheck` flag parser (`--dialect`, VFS `--in-place`) & stream driver
│       └── repl.rs             # Unified streaming `ByteStreamBufRead` REPL, `/F:ON` completion & ANSI colors
└── tests/
    ├── cli_binaries.rs         # Subprocess integration tests for `wincmd` and `wincheck` binaries
    ├── doc_and_quality_gates.rs# 100% doc-completeness, 60-rule catalog & anti-pattern gates across workspace
    └── property_invariants.rs  # AST/CST, FAT timestamp, 8.3 name, PSP tail, OEM codepage & rewriter properties
```

---

## Quality & Engineering Standards

This repository enforces the strictest possible Rust engineering and verification standards:

1. **100% Documentation Coverage**:
   - Every module, struct, enum, variant, field, and function (both public and private) is documented with rustdoc, enforced via `#![deny(missing_docs)]`, `#![deny(clippy::missing_docs_in_private_items)]`, `#![deny(clippy::missing_errors_doc)]`, and `#![deny(clippy::missing_panics_doc)]`.
2. **100% Test Coverage**:
   - Verified across functions, lines, and branches via `cargo llvm-cov`.
3. **Zero Core `unsafe`, Zero `unwrap`, Zero `panic!`, Zero Indexing**:
   - `#![forbid(unsafe_code)]` across the entire `win-cmd-rs` library and `DjgppDosKernel` (with target-specific `unsafe` confined to `crates/wincmd-dos`: DJGPP `libc` / DPMI FFI in `ffi.rs`, `GlobalAlloc` alignment math in `alloc_djgpp.rs`, and C `main` entrypoints in `src/bin/`, all under mandatory `# Safety` invariants).
   - `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::panic_in_result_fn, clippy::indexing_slicing, clippy::string_slice, clippy::arithmetic_side_effects)]`
4. **Single Unified Error Enum**:
   - All errors across the reader, parser, VFS, DOS hardware layer, arithmetic evaluator, runtime, CLI, and linter use `win_cmd_rs::error::CmdError` powered by `derive_more`, with `.cmd_exe_message()` and `.exit_code()` producing authentic `cmd.exe` and `COMMAND.COM` diagnostics.

### Running the Verification Suite

```bash
# Verify pure `#![no_std]` + `alloc` core without `std`
cargo check --lib --no-default-features
cargo clippy --lib --no-default-features -- -D warnings

# Run all unit, integration, property, and doc tests
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc --all-features

# Run Clippy with all pedantic/nursery/restriction lints denied
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Build documentation including private items with zero warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --document-private-items

# Verify 100.00% function, line, and branch coverage
cargo +nightly llvm-cov --branch --workspace --all-targets --all-features --summary-only
```

---

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](https://www.apache.org/licenses/LICENSE-2.0))
- MIT license ([LICENSE-MIT](https://opensource.org/licenses/MIT))

at your option.
