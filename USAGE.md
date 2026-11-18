# `win-cmd-rs` Usage Guide

This guide covers day-to-day usage of the **`wincmd` (`WINCMD.EXE`)** cross-platform Windows Command Prompt (`cmd.exe`) and MS-DOS (`COMMAND.COM`) interpreter, the **`wincheck` (`WINCHECK.EXE`)** static analyzer and CST auto-fixer, CI/editor integrations, and embedding **`win_cmd_rs`** as a `#![no_std]` + `alloc` or `std` safe Rust library.

---

## Table of Contents

1. [Installation & Quickstart](#1-installation--quickstart)
2. [`wincmd` CLI Guide](#2-wincmd-cli-guide)
   - [Command-Line Switches & VFS Modes](#21-command-line-switches--vfs-modes)
   - [Running Batch Scripts on Linux, macOS & Windows](#22-running-batch-scripts-on-linux-macos--windows)
   - [Filesystem Sandboxing (`--hermetic` & `--host-root`)](#23-filesystem-sandboxing---hermetic----host-root)
   - [Interactive REPL, `PROMPT` Codes & `DOSKEY`](#24-interactive-repl-prompt-codes--doskey)
   - [Exit Codes](#25-exit-codes)
   - [MS-DOS `COMMAND.COM` Dialect (`--dialect dos622`, `/P`, `/E:nnnnn`)](#26-ms-dos-commandcom-dialect---dialect-dos622-p-ennnnn)
3. [Batch Scripting Cookbook (`cmd.exe` & `COMMAND.COM` Semantics)](#3-batch-scripting-cookbook-cmdexe--commandcom-semantics)
   - [Variables, Delayed Expansion (`!VAR!`) & Slicing](#31-variables-delayed-expansion-var--slicing)
   - [Parameters (`%0`–`%9`, `%*`) & `%~` Path Modifiers](#32-parameters-09---path-modifiers)
   - [Control Flow (`IF`, `FOR`, `CALL :label`, `GOTO :EOF`)](#33-control-flow-if-for-call-label-goto-eof)
   - [`SET /A` 32-Bit Signed Arithmetic](#34-set-a-32-bit-signed-arithmetic)
   - [Redirections, Reserved DOS Devices & Pipelines](#35-redirections-reserved-dos-devices--pipelines)
   - [Registry (`REG`), `ASSOC`, `FTYPE` & `AutoRun`](#36-registry-reg-assoc-ftype--autorun)
   - [Built-In Commands & Cross-Platform Utility Shims Reference](#37-built-in-commands--cross-platform-utility-shims-reference)
   - [MS-DOS Commands (`TRUENAME`, `CTTY`, `LH`, `MEM`, DOS `CHOICE`)](#38-ms-dos-commands-truename-ctty-lh-mem-dos-choice)
4. [`wincheck` Static Linter & Auto-Fixer Guide](#4-wincheck-static-linter--auto-fixer-guide)
   - [CLI Options & Exit Codes](#41-cli-options--exit-codes)
   - [Output Formats (`tty`, `gcc`, `json`, `sarif`)](#42-output-formats-tty-gcc-json-sarif)
   - [Previewing & Applying Fixes (`--diff`, `--fix`, `--in-place`, `--unsafe-fixes`)](#43-previewing--applying-fixes---diff---fix---in-place---unsafe-fixes)
   - [Dialect Checking & MS-DOS Portability (`--mode` & `--dialect dos622`)](#44-dialect-checking--ms-dos-portability---mode----dialect-dos622)
   - [Inline Suppression Directives](#45-inline-suppression-directives)
   - [CI/CD & Editor Integrations](#46-cicd--editor-integrations)
5. [Embedding `win_cmd_rs` in Rust (`std` & `#![no_std]` + `alloc`)](#5-embedding-win_cmd_rs-in-rust-std--no_std--alloc)
   - [Hermetic Execution & Safety Budgets (`ExecutionLimits`)](#51-hermetic-execution--safety-budgets-executionlimits)
   - [Mounting Host Directories (`HostOsVfs`)](#52-mounting-host-directories-hostosvfs)
   - [Mocking External Binaries (`MockProcessSpawner`)](#53-mocking-external-binaries-mockprocessspawner)
   - [Pre-Populating Environment & Windows Registry State](#54-pre-populating-environment--windows-registry-state)
   - [Lossless CST Parsing, AST Lowering & Programmatic Linting](#55-lossless-cst-parsing-ast-lowering--programmatic-linting)
   - [`#![no_std]` + `alloc` & MS-DOS `DosKernelApi` Embedding](#56-no_std--alloc--ms-dos-doskernelapi-embedding)

---

## 1. Installation & Quickstart

### Build or Install Binaries

Requires **Rust 1.88+** (Edition 2024):

```bash
# Install `wincmd` and `wincheck` into ~/.cargo/bin
cargo install --path .

# Or build optimized release binaries in target/release/
cargo build --release
```

### 30-Second Quickstart

```bash
# 1. Execute an inline cmd.exe command string with Delayed Expansion (/V:ON)
wincmd /V:ON /C "set total=0 & for /L %i in (1,1,5) do (set /a total+=%i) & echo Sum=!total!"

# 2. Lint a Windows batch script on any OS
wincheck scripts/deploy.bat

# 3. Preview safe CST auto-fixes as a unified diff
wincheck --diff scripts/deploy.bat

# 4. Write the fixed batch script to a new file (or replace via temp file)
wincheck --fix scripts/deploy.bat > scripts/deploy.fixed.bat
```

---

## 2. `wincmd` CLI Guide

### 2.1 Command-Line Switches & VFS Modes

```text
WINCMD [drive:\path] [/A | /U] [/Q] [/D] [/P] [/MSG] [/E:ON | /E:OFF | /E:nnnnn]
       [/F:ON | /F:OFF] [/V:ON | /V:OFF] [/T:bf] [--dialect <cmd|dos622|freedos>]
       [--in-memory | --hermetic | --host-native | --host-root <dir>]
       [[/S] [/C | /K] string] [--script <file> [args...]]
```

| Switch | Meaning | Default |
| :--- | :--- | :--- |
| `/C <string>` | Executes `<string>` and terminates immediately with its `ERRORLEVEL`. | — |
| `/K <string>` | Executes `<string>` and enters the interactive REPL in the resulting session. | — |
| `/S` | Forces stripping of outer `"` around the `/C` or `/K` command string. | Off |
| `/Q` | Starts the session with `ECHO OFF` (`EchoState::Off`). | `ECHO ON` |
| `/D` | Skips `HKLM` and `HKCU` `Software\Microsoft\Command Processor\AutoRun` commands. | Run `AutoRun` |
| `/A` | Encodes redirected file and pipe output using the active ANSI/OEM codepage. | `/A` |
| `/U` | Encodes redirected file and pipe output as UTF-16LE (`CodePage::Utf16Le`). | `/A` |
| `/E:ON` \| `/E:OFF` | Enables or disables Command Extensions (`SET /A`, `SET /P`, `FOR /F`, `CALL :label`, `%~dp0`, etc.). | `/E:ON` (`cmd`/`freedos`), `/E:OFF` (`dos622`) |
| `/E:nnnnn` | Configures MS-DOS `COMMAND.COM` environment size budget in bytes (`160..=32768`). | Unbounded / DPMI 32 KiB |
| `/P` | Permanent primary shell (`COMMAND.COM /P`): runs `C:\AUTOEXEC.BAT` on startup if present and ignores top-level `EXIT`. | Transient |
| `/MSG` | Enables extended DOS resident error messages (`COMMAND.COM /MSG` compatibility). | Off |
| `[drive:\path]` | Positional `COMMAND.COM` startup command directory setting `%COMSPEC%` (e.g., `wincmd C:\DOS /P`). | — |
| `/V:ON` \| `/V:OFF` | Enables or disables `!VAR!` Delayed Environment Variable Expansion. | `/V:OFF` |
| `/F:ON` \| `/F:OFF` | Enables or disables interactive file and directory completion mode. | `/F:ON` |
| `/T:bf` | Sets initial background (`b`) and foreground (`f`) hex color nibbles (e.g., `/T:1F`; error if `b == f`). | None |
| `--dialect <DIALECT>` | Selects compatibility dialect: `cmd` (Windows NT `cmd.exe`), `dos622` (MS-DOS 6.22), or `freedos`. | `cmd` (host), `dos622`/`freedos` (DOS) |
| `--host-native` | Mounts the host OS filesystem via `HostOsVfs::from_host_env()` and imports host env vars. | Binary default |
| `--host-root <dir>` | Mounts host `<dir>` as `C:\` with strict symlink sandbox containment (`SandboxContainment::Contained`). | — |
| `--in-memory`, `--hermetic` | Uses an isolated in-memory `InMemoryVfs` (`C:\`, `C:\Windows\System32`, `C:\Temp`) with zero host disk I/O. | — |
| `--script <file> [args...]` | Explicitly runs `<file>` as a batch script (useful if `<file>` begins with `/` or `-`). | — |
| `/?`, `-h`, `--help` | Prints CLI usage summary and exits `0`. | — |
| `-V`, `--version` | Prints `Microsoft Windows [Version 10.0.19045.5011]` and exits `0`. | — |

> **POSIX Path Note:** Because `/` introduces `cmd.exe` flags (`/C`, `/Q`, `/V:ON`), `wincmd` distinguishes short switches from POSIX filesystem paths automatically when running in `--host-native` mode: `wincmd /tmp/build.bat arg1` maps `/tmp/build.bat` to `Z:\tmp\build.bat` and executes it cleanly, whereas unrecognized flag tokens like `/Z` return a CLI error. You can also always pass `--script /tmp/build.bat arg1` explicitly.

### 2.2 Running Batch Scripts on Linux, macOS & Windows

In default `--host-native` mode on Linux and macOS:
- Host `/` is mounted at drive `Z:\`, and `C:\` is rooted at your host current working directory (or configured drive root).
- Host `PATH` (`:`-separated on POSIX) is automatically translated into `;`-separated `Z:\...` Windows paths alongside `C:\Windows\System32`, allowing batch scripts to invoke both built-in Windows shims (`findstr`, `robocopy`, `reg`, `where`) and native host tools (`git`, `cargo`, `python3`, `cmake`).
- Lookups on `HostOsVfs` perform transparent **case-insensitive** component resolution even when the underlying ext4/APFS volume is case-sensitive.

```bash
# Run a project's build.bat directly from macOS/Linux bash or zsh
wincmd scripts/build.bat --release

# Pass positional arguments containing spaces
wincmd .\ci\package.cmd "Release x64" "dist\artifacts"

# Pipe input into wincmd from a POSIX shell
printf 'alpha\r\nzebra\r\nbeta\r\n' | wincmd /C "sort /R"
```

### 2.3 Filesystem Sandboxing (`--hermetic` & `--host-root`)

When evaluating untrusted scripts or running deterministic tests:

```bash
# Completely in-memory execution: nothing on the host filesystem can be read or modified
wincmd --hermetic /C "md C:\work & echo ok > C:\work\status.txt & dir /b C:\work"

# Confine C:\ to a temporary host directory; symlinks pointing outside /tmp/job-sandbox are blocked
mkdir -p /tmp/job-sandbox
cp test.bat /tmp/job-sandbox/
wincmd --host-root /tmp/job-sandbox C:\test.bat
```

### 2.4 Interactive REPL, `PROMPT` Codes & `DOSKEY`

Launch an interactive session with `wincmd` (or `wincmd /K "title Build Shell"`):

- **Multi-Line `More? ` Continuation**: Ending a physical line with an unescaped `^` or leaving a `(` compound block open prompts `More? ` using the lexer-aware `compute_lossless_paren_balance` scanner (so `echo (` or `REM (` will not falsely trap the prompt).
- **`PROMPT` Escape Codes**: Customize `%PROMPT%` using standard `cmd.exe` `$` tokens:
  - `$P` (current drive and path), `$N` (current drive), `$G` (`>`), `$L` (`<`), `$B` (`|`), `$Q` (`=`), `$S` (space), `$$` (`$`), `$_` (CRLF newline), `$T` (current time), `$D` (current date), `$V` (Windows version), `$H` (backspace), `$E` (ESC `0x1B` for ANSI colors).
- **`DOSKEY` Macros & History**:
  ```bat
  doskey ll=dir /w $*
  doskey build=cargo build --target $1 $T echo Done $1
  doskey /macros
  doskey /history
  doskey /listsize=100
  doskey /reinstall
  ```

### 2.5 Exit Codes

- **`0`**: Command or script completed with `ERRORLEVEL 0` (or `/?`, `--help`, `--version`).
- **`1`–`255`**: Propagates the low byte of the final `ExitCode` (`EXIT /B <code>`, `EXIT <code>`, external process status, or `CmdError::exit_code()`, such as `9009` for unknown command).

### 2.6 MS-DOS `COMMAND.COM` Dialect (`--dialect dos622`, `/P`, `/E:nnnnn`)

Passing `--dialect dos622` (or `--dialect freedos`) switches `wincmd` into MS-DOS `COMMAND.COM` compatibility mode:
- **`--dialect dos622`**: Defaults `ExtensionsMode` to `/E:OFF` (unless explicitly overridden with `/E:ON`), sets default OEM codepage to `437` (`CodePage::OemUnitedStates`) or `DosKernelApi::active_codepage()`, sets `%PATHEXT%` to `.COM;.EXE;.BAT`, and formats `VER` as `MS-DOS Version 6.22`.
- **`--dialect freedos`**: Enables FreeCOM-compatible extensions while reporting `FreeDOS` version formatting and DOS path/device semantics.
- **`/P` (Permanent Primary Shell)**: Executes `C:\AUTOEXEC.BAT` automatically on startup if present and ignores top-level `EXIT` commands so the primary DOS shell never terminates accidentally.
- **`/E:nnnnn` (`160..=32768`)**: Enforces an exact MS-DOS environment block byte budget (`Out of environment space` when exceeded).
- **Positional Command Directory (`WINCMD C:\DOS /P`)**: Sets `%COMSPEC%` to `C:\DOS\COMMAND.COM` matching `SHELL=C:\DOS\COMMAND.COM C:\DOS /E:1024 /P` in `CONFIG.SYS`.

```bash
# Run a legacy MS-DOS 6.22 batch script with strict 1024-byte environment budget
wincmd --dialect dos622 /E:1024 LEGACY.BAT

# Simulate booting a primary MS-DOS shell running C:\AUTOEXEC.BAT
wincmd C:\DOS --dialect dos622 /E:2048 /P
```

---

## 3. Batch Scripting Cookbook (`cmd.exe` & `COMMAND.COM` Semantics)

### 3.1 Variables, Delayed Expansion (`!VAR!`) & Slicing

```bat
@echo off
setlocal EnableDelayedExpansion

REM Always quote SET assignments to prevent trailing whitespace capture (CMD2004)
set "MESSAGE=Hello World"

REM Substring slicing: %VAR:~offset,length% (supports negative offsets & lengths)
echo First 5: %MESSAGE:~0,5%
echo Last 5:  %MESSAGE:~-5%
echo Trim 6:  %MESSAGE:~0,-6%

REM Search & replace (case-insensitive) and prefix wildcard replace (*old=new)
echo Replaced: %MESSAGE:World=Batch%
echo After space: %MESSAGE:* =%

REM Inside (...) blocks, %VAR% expands BEFORE the block runs; use !VAR! for live values
set "COUNT=0"
for %%F in (a b c) do (
    set /a "COUNT+=1"
    echo Item !COUNT! is %%F
)
endlocal
```

Dynamic pseudo-variables evaluated on demand by `EnvironmentStack`:
- `%CD%` — Current active drive's working directory.
- `%ERRORLEVEL%` — Exit code of the last status-setting command.
- `%RANDOM%` — Independent `0..=32767` pseudo-random value generated on **each** individual token read (`echo %RANDOM% %RANDOM%` prints two distinct numbers).
- `%DATE%` / `%TIME%` — Formatted per session `CmdLocaleConfig`.
- `%CMDEXTVERSION%` — Returns `2` when Command Extensions are enabled.
- `%CMDCMDLINE%` — Original command line that invoked the interpreter.

### 3.2 Parameters (`%0`–`%9`, `%*`) & `%~` Path Modifiers

Modifiers apply to batch parameters (`%0`–`%9`) and `FOR` loop variables (`%%I`) and can be freely combined:

| Expression | Meaning | Example (`%1` = `"C:\Program Files\MyApp\tool.exe"`) |
| :--- | :--- | :--- |
| `%~1` | Strip surrounding quotes `"` | `C:\Program Files\MyApp\tool.exe` |
| `%~f1` | Full canonical path | `C:\Program Files\MyApp\tool.exe` |
| `%~d1` | Drive (`C:`) or UNC share (`\\srv\share`) | `C:` |
| `%~p1` | Directory path with trailing `\` | `\Program Files\MyApp\` |
| `%~n1` | Filename stem without extension | `tool` |
| `%~x1` | Extension including leading `.` | `.exe` |
| `%~dp0` | Script's own drive + directory | `C:\Scripts\` |
| `%~s1` | Path with collision-resolved 8.3 short names | `C:\PROGRA~1\MYAPP\TOOL.EXE` |
| `%~a1` | 9-char Windows attribute mask (`drahscotl`) | `--a------` |
| `%~t1` | Last-modified timestamp | `01/01/2025 12:00 AM` |
| `%~z1` | File size in bytes | `4096` |
| `%~$PATH:1` | First matching file along `%PATH%` | `C:\Windows\System32\cmd.exe` |
| `%*` | Raw unmodified argument tail (unaffected by `SHIFT`) | `"arg1" arg2` |

### 3.3 Control Flow (`IF`, `FOR`, `CALL :label`, `GOTO :EOF`)

```bat
@echo off
setlocal

REM Case-insensitive string comparison (/I) and extended numeric comparisons (EQU, NEQ, LSS, LEQ, GTR, GEQ)
if /I "%~1"=="clean" (
    call :clean_step "build"
    if errorlevel 1 exit /b 1
) else (
    echo Skipping clean
)

REM FOR /F parsing command output, CSV/TSV files, or literal strings
for /F "usebackq tokens=1,2* delims=:" %%A in (`findstr /N "TODO" "notes.txt"`) do (
    echo File=%%A Line=%%B Content=%%C
)

exit /b 0

:clean_step
echo Cleaning "%~1"...
goto :eof
```

### 3.4 `SET /A` 32-Bit Signed Arithmetic

Always wrap `SET /A` expressions in double quotes so `&`, `|`, `^`, `<<`, and `>>` are not parsed as shell operators (`CMD1011`):

```bat
set /a "mask = (1 << 4) | 0x03"
set /a "x = 10, y = x * 3 + 2"
set /a "quot = -2147483648 / -1"
```

Supports decimal, hexadecimal (`0xFF`), and octal (`077`) literals, implicit variable dereferencing (`x * 3` reads `%x%`, defaulting unset variables to `0`), and compound assignments (`+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `^=`, `|=`, `<<=`, `>>=`).

### 3.5 Redirections, Reserved DOS Devices & Pipelines

- **Redirections**: `< file` (stdin), `> file` / `1> file` (overwrite stdout), `>> file` (append stdout), `2> file` (stderr), `2>&1` (merge stderr into stdout), `1>&2` (send stdout to stderr). Redirections may appear before, between, or after command words (`> out.log 2>&1 echo Starting`).
- **Reserved Win32 Devices**: `NUL`, `CON`, `PRN`, `AUX`, `CLOCK$`, `COM1`–`COM9`, `LPT1`–`LPT9` (intercepted case-insensitively in any directory, including the `IF EXIST "C:\dir\NUL"` directory-existence idiom).
- **Command Chains & Pipelines**:
  - `cmd1 & cmd2` — Unconditional sequence.
  - `cmd1 && cmd2` — Run `cmd2` only if `cmd1` succeeded.
  - `cmd1 || cmd2` — Run `cmd2` only if `cmd1` failed.
  - `cmd1 | cmd2` — Executes both sides in isolated subshell environments (matching `cmd.exe`: `SET` or `CD` inside a pipe does not mutate the parent shell; flagged by `wincheck` rule `CMD3010`).

### 3.6 Registry (`REG`), `ASSOC`, `FTYPE` & `AutoRun`

`wincmd` includes an integrated `RegistryStore` supporting `HKLM`, `HKCU`, `HKCR`, `HKU`, and `HKCC` (plus `.reg` Windows Registry Editor 5.00 and Wine `WINE REGISTRY Version 2` import/export):

```bat
REM Query, add, copy, export, import, and delete Registry keys/values
reg add "HKCU\Software\MyTool" /v InstallDir /t REG_SZ /d "C:\Tools\MyTool" /f
reg query "HKCU\Software\MyTool" /v InstallDir
reg export "HKCU\Software\MyTool" "C:\Temp\backup.reg" /y

REM Register custom script/document associations executed directly by wincmd
assoc .py=Python.File
ftype Python.File=python3 "%1" %*
```

Modifying `HKCU\Software\Microsoft\Command Processor` (`DelayedExpansion`, `EnableExtensions`, `DefaultColor`, `AutoRun`) dynamically updates behavior for new `CMD` subshells.

### 3.7 Built-In Commands & Cross-Platform Utility Shims Reference

- **Environment**: `SET`, `SETLOCAL`, `ENDLOCAL`, `PATH`, `PROMPT`, `ASSOC`, `FTYPE`
- **Control Flow**: `IF`, `FOR`, `CALL`, `GOTO`, `SHIFT`, `EXIT`, `PAUSE`, `START`, `CMD`, `LH` / `LOADHIGH`
- **Filesystem**: `DIR`, `CD` / `CHDIR`, `MD` / `MKDIR`, `RD` / `RMDIR`, `PUSHD`, `POPD`, `COPY`, `DEL` / `ERASE`, `REN` / `RENAME`, `MOVE`, `TYPE`, `TRUENAME`, `MKLINK`, `<Drive>:`
- **Console**: `ECHO`, `REM`, `CLS`, `COLOR`, `TITLE`, `CHCP`, `CTTY`, `MODE`, `VER`, `VOL`, `DATE`, `TIME`, `VERIFY`, `DOSKEY`
- **Utility Shims**: `MEM`, `REG`, `WHERE`, `FIND`, `FINDSTR`, `SORT`, `MORE`, `FC`, `COMP`, `TREE`, `XCOPY`, `ROBOCOPY`, `ATTRIB`, `CHOICE`, `TIMEOUT`, `HOSTNAME`, `WHOAMI`

### 3.8 MS-DOS Commands (`TRUENAME`, `CTTY`, `LH`, `MEM`, DOS `CHOICE`)

```bat
REM Resolve canonical 8.3 or LFN drive:\path via VFS / INT 21h AH=60h
truename .\SUBDIR\..\README.TXT

REM Inspect conventional 640 KiB and extended XMS/DPMI memory (/C, /D, /F, /M, /P)
mem /C

REM Load TSR/command with UMB region switches stripped transparently under 32-bit DPMI
lh /L:1,16384 doskey

REM Classic MS-DOS 6.x CHOICE syntax (/C[:]keys, /S case-sensitive, /T[:]default,seconds)
choice /C:YN /S /T:Y,5 Continue installation

REM Redirect interactive console I/O to serial port COM1 (and restore to CON)
ctty COM1
echo Running headless over RS-232 serial
ctty CON
```

In addition, `DEL <directory>` prompts `All files in directory will be deleted! Are you sure (Y/N)?` unless `/Q` is specified, matching both `COMMAND.COM` and `cmd.exe`.

---

## 4. `wincheck` Static Linter & Auto-Fixer Guide

### 4.1 CLI Options & Exit Codes

```text
wincheck [OPTIONS] <FILES...>
```

| Option | Description |
| :--- | :--- |
| `<FILES...>` | One or more `.bat` / `.cmd` file paths, or `-` to read from `stdin`. |
| `-f, --format <FMT>` | Diagnostic output format: `tty` (default), `gcc`, `json`, or `sarif`. |
| `-m, --mode <batch\|repl>` | Execution context: `batch` (`.bat`/`.cmd`, default) or `repl` (interactive `cmd /C` / REPL). |
| `--dialect <cmd\|dos622\|freedos>` | Target shell dialect: `cmd` (default), `dos622` (enables `CMD5001`–`CMD5010` MS-DOS checks), or `freedos`. |
| `-S, --severity <SEV>` | Minimum severity threshold: `error`, `warning`, `info`, or `style` (default: `style`). |
| `-i, --include <RULES>` | Comma-separated allowlist of rule IDs (e.g., `CMD2001,CMD3007,CMD5001`). |
| `-e, --exclude <RULES>` | Comma-separated blocklist of rule IDs (e.g., `CMD1009,CMD4006`). |
| `--explain <CMDxxxx>` | Displays full Markdown explanation, rationale, and bad/good examples for `<CMDxxxx>`. |
| `--list-rules` | Prints the full 60-rule catalog (`CMD0001`–`CMD5010`) with severities and summaries. |
| `--diff` | Generates a Myers/LCS unified diff of CST auto-fixes without modifying files on disk. |
| `--fix, --stdout` | Writes the CST-rewritten script for a single file (or `-` stdin) to `stdout` preserving BOM/encoding and re-lints. |
| `--in-place` | Writes CST-rewritten scripts back to disk in place via the active VFS preserving BOM/encoding. |
| `--encoding <ENC>` | Fallback input encoding when no BOM is present: `utf8` (default), `ascii`, `cp437`, `cp850`, `cp852`, `cp865`, `cp866`, `cp1252`, `utf16le`, `utf16be`. |
| `--unsafe-fixes` | Enables opt-in behavior-altering rewrites (`FixApplicability::UnsafeOptIn`) during `--fix` / `--in-place` / `--diff`. |
| `-h, --help, /?` | Prints CLI help and exits `0`. |
| `-V, --version` | Prints `wincheck` version and exits `0`. |

**Exit Codes:**
- **`0`**: Zero diagnostics matched at or above `--severity` (or `--fix` resolved all remaining matching diagnostics, or `--diff` produced no changes, or `--explain` / `--list-rules` / `--help` succeeded).
- **`1`**: One or more diagnostics remain (or `--diff` found applicable changes, or file I/O failed).
- **`2`**: Invalid CLI option, unknown `--format` / `--severity` / `--mode` / `--dialect` / `--encoding`, unknown `--explain` rule ID, or missing `<FILES...>`.

### 4.2 Output Formats (`tty`, `gcc`, `json`, `sarif`)

```bash
# Annotated terminal snippets with line/column carets and fix hints
wincheck deploy.bat

# Single-line compiler diagnostics for editors (file:line:col: severity: msg [CMDxxxx])
wincheck --format gcc deploy.bat

# Machine-readable JSON array
wincheck --format json deploy.bat

# SARIF v2.1.0 report for GitHub Code Scanning / Azure DevOps
wincheck --format sarif ci/*.bat > wincheck.sarif

# Lint from stdin
cat deploy.bat | wincheck --format tty -
```

### 4.3 Previewing & Applying Fixes (`--diff`, `--fix`, `--in-place`, `--unsafe-fixes`)

`wincheck` classifies CST rewrites into three ordered [`FixApplicability`] tiers (all respecting `--include`, `--exclude`, `--severity`, and inline `REM wincheck disable=...` suppressions):

1. **`FixApplicability::SafeSemanticsPreserving`**:
   - Strictly semantics-preserving normalizations guaranteed to produce identical runtime behavior on well-formed inputs:
     - `SET Z=a^&b` -> `SET "Z=a&b"` (`CMD2008`, when no whitespace is trimmed)
     - `::` inside `(...)` blocks -> `REM` (`CMD1001`)
     - Smart quoting of variables/parameters in paths, `IF` comparisons, and redirections -> `"%VAR%"`, `"%~1"`, `"%%~I"` (`CMD2003`, `CMD2006`, `CMD2007`)
     - `%` <-> `%%` execution-mode dialect conversions (`CMD1007`, `CMD1014`)
2. **`FixApplicability::RecommendedRepair` (Default for `--fix` / `--diff`)**:
   - Includes all `SafeSemanticsPreserving` normalizations **plus** recommended bug repairs that intentionally fix broken `cmd.exe` footguns:
     - `SET VAR = val ` -> `SET "VAR=val"` (`CMD2004`, `CMD2005`, trimming unintended spaces around `=` and trailing whitespace)
     - Stale `%VAR%` / `%ERRORLEVEL%` inside `(...)` blocks -> `!VAR!` + `SETLOCAL EnableDelayedExpansion` *only when no literal `!` characters in scope would be stripped* (`CMD2001`, `CMD2009`)
     - `ECHO %VAR%` -> `ECHO(%VAR%` (`CMD4002`), `CD D:\dir` -> `CD /D D:\dir` (`CMD4001`), `other.bat` -> `CALL other.bat` (`CMD3003`), broken `^ ` continuations (`CMD1004`), structural `IF`/`FOR` repairs (`CMD1005`, `CMD1013`)
3. **`FixApplicability::UnsafeOptIn` (`--unsafe-fixes`)**:
   - `EXIT 1` -> `EXIT /B 1` (`CMD3004`, gated because top-level `EXIT 1` is sometimes intentional in CI wrappers)
   - Injecting `SETLOCAL EnableDelayedExpansion` even when commands in scope contain literal `!` characters

```bash
# 1. Inspect proposed safe changes as a unified diff
wincheck --diff script.bat

# 2. Apply safe fixes cleanly via a temporary file
wincheck --fix script.bat > script.bat.tmp && mv script.bat.tmp script.bat

# 3. Include opt-in behavior-altering fixes (e.g. EXIT -> EXIT /B)
wincheck --diff --unsafe-fixes script.bat
```

### 4.4 Dialect Checking & MS-DOS Portability (`--mode` & `--dialect dos622`)

Batch files require doubled `%%I` for `FOR` variables and `100%%` for literal percents, whereas interactive `cmd.exe /C` strings and REPL commands require single `%I` and `100%`:

```bash
# Lint an inline CI one-liner under interactive REPL dialect rules
printf 'for %%i in (*.txt) do echo %%i\r\n' | wincheck --mode repl -

# Automatically convert a .bat snippet into an interactive REPL / `cmd /C` command
wincheck --mode repl --fix snippet.bat
```

To statically audit `.BAT` scripts for real **MS-DOS 6.22 `COMMAND.COM`** compatibility, pass `--dialect dos622` (activating rules `CMD5001`–`CMD5010`):
- **`CMD5001`**: Flags `SET /A` arithmetic and `SET /P` interactive prompts.
- **`CMD5002`**: Flags `FOR /F`, `FOR /L`, `FOR /R`, and `FOR /D` extended loop switches.
- **`CMD5003`**: Flags `IF /I`, `IF DEFINED`, `IF CMDEXTVERSION`, `EQU`–`GEQ`, and `ELSE`.
- **`CMD5004`**: Flags `( ... )` parenthesized blocks and `&` / `&&` / `||` chains (auto-splits unconditional `&` chains into separate physical lines with `--fix`).
- **`CMD5005`**: Flags `!VAR!` delayed expansion, `%VAR:~s,l%` slicing, `%VAR:a=b%` replacement, `%*`, and `%~dpnx1` modifiers.
- **`CMD5006`**: Flags `CALL :label`, implicit `GOTO :EOF`, and `EXIT /B` (auto-rewrites `GOTO :EOF` to `GOTO EOF` and appends `:EOF` at end-of-file with `--fix`).
- **`CMD5007`**: Flags NT-only built-ins (`SETLOCAL`, `ENDLOCAL`, `PUSHD`, `POPD`, `ASSOC`, `FTYPE`, `MKLINK`).
- **`CMD5008`**: Flags numeric file-descriptor redirections (`2>`, `2>&1`, `1>&2`).
- **`CMD5009`**: Flags non-8.3 path segments and `.cmd` extensions.
- **`CMD5010`**: Flags external command invocations exceeding the 126-byte MS-DOS `PSP:0x80` tail limit.

```bash
# Audit an installer script for strict MS-DOS 6.22 COMMAND.COM compatibility in CP437
wincheck --dialect dos622 --encoding cp437 INSTALL.BAT

# Auto-fix `&` command chains and `GOTO :EOF` for MS-DOS 6.22 in place
wincheck --dialect dos622 --fix --in-place INSTALL.BAT

# Read detailed guidance for any DOS portability rule
wincheck --explain CMD5006
```

### 4.5 Inline Suppression Directives

Place `REM wincheck ...` (or `:: wincheck ...`, or `REM shellcheck ...`) comments in your batch files:

```bat
@echo off
REM wincheck disable=CMD1009,CMD4005
REM ^ Placed before the first executable statement: applies to the ENTIRE file.

REM wincheck disable=CMD3004
exit 1
REM ^ Placed immediately above a statement: suppresses CMD3004 on that line only.
```

### 4.6 CI/CD & Editor Integrations

#### GitHub Actions + SARIF Code Scanning

```yaml
name: Batch Static Analysis
on: [push, pull_request]

jobs:
  wincheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install --git https://github.com/SamuelMarks/win-cmd-rs.git
      - name: Run wincheck SARIF scan
        run: wincheck --format sarif scripts/*.bat > wincheck.sarif
        continue-on-error: true
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: wincheck.sarif
```

#### Neovim / Vim (`makeprg` / Quickfix)

```vim
autocmd FileType dosbatch setlocal makeprg=wincheck\ --format\ gcc\ %
autocmd FileType dosbatch setlocal errorformat=%f:%l:%c:\ %t%*[^:]:\ %m
```

---

## 5. Embedding `win_cmd_rs` in Rust (`std` & `#![no_std]` + `alloc`)

Add `win-cmd-rs` to your `Cargo.toml` (disable default features when targeting `#![no_std]` + `alloc`):

```toml
[dependencies]
win-cmd-rs = "0.0.1"
# For `#![no_std]` + `alloc` targets:
# win-cmd-rs = { version = "0.0.1", default-features = false }
```

### 5.1 Hermetic Execution & Safety Budgets (`ExecutionLimits`)

`Interpreter::new()` starts in an isolated `InMemoryVfs` with `ExecutionLimits::sandboxed()` (`max_steps = 100_000`, `max_call_depth = 256`, `max_loop_iterations = 100_000`). You can tighten budgets when evaluating untrusted inputs so infinite `GOTO` loops fail deterministically with `CmdError::ExecutionLimitExceeded`:

```rust
use win_cmd_rs::error::CmdError;
use win_cmd_rs::runtime::{ExecutionLimits, Interpreter, IoStreams};

fn run_sandboxed(script: &[u8]) -> Result<String, CmdError> {
    let mut interp = Interpreter::new();
    interp.config.limits = ExecutionLimits {
        max_steps: Some(1_000),
        max_call_depth: Some(16),
        max_loop_iterations: Some(500),
    };

    interp.proc_env.vfs.write_bytes(r"C:\job.bat", script)?;
    let mut io = IoStreams::new();
    let _code = interp.execute_batch_file(
        r"C:\job.bat",
        r"C:\job.bat",
        vec!["arg1".to_owned()],
        "arg1".to_owned(),
        &mut io,
    )?;
    Ok(io.stdout)
}

assert_eq!(
    run_sandboxed(b"@echo off\r\necho arg=%~1\r\n").ok().as_deref(),
    Some("arg=arg1\r\n")
);
```

### 5.2 Mounting Host Directories (`HostOsVfs`)

Mount one or more host directories onto explicit Windows drive letters while enforcing `SandboxContainment::Contained`:

```rust
use std::collections::BTreeMap;
use std::path::PathBuf;
use win_cmd_rs::runtime::Interpreter;
use win_cmd_rs::types::DriveLetter;
use win_cmd_rs::vfs::{HostOsVfs, SandboxContainment};

let mut mounts = BTreeMap::new();
mounts.insert(DriveLetter::C, PathBuf::from("/tmp/workspace_c"));
mounts.insert(DriveLetter::D, PathBuf::from("/tmp/artifacts_d"));

let vfs = HostOsVfs::with_mounts(DriveLetter::C, mounts, SandboxContainment::Contained);
let mut interp = Interpreter::with_vfs(Box::new(vfs));
assert_eq!(interp.proc_env.vfs.current_drive(), DriveLetter::C);
```

### 5.3 Mocking External Binaries (`MockProcessSpawner`)

Test `.bat` deployment or build scripts that invoke external `.exe` tools (`git.exe`, `msbuild.exe`, `cl.exe`) deterministically without installing those binaries on the host:

```rust
use win_cmd_rs::error::CmdError;
use win_cmd_rs::runtime::{Interpreter, IoStreams, MockProcessSpawner};
use win_cmd_rs::types::{DirCreationDepth, ExitCode};

fn test_build_script() -> Result<(), CmdError> {
    let mut interp = Interpreter::new();

    // Place a stub executable on %PATH% so command resolution finds `git.exe`
    interp
        .proc_env
        .vfs
        .create_dir(r"C:\Windows\System32", DirCreationDepth::CreateParents)?;
    interp
        .proc_env
        .vfs
        .write_bytes(r"C:\Windows\System32\git.exe", b"")?;

    let mut spawner = MockProcessSpawner::new();
    spawner.register_binary("git.exe", ExitCode::SUCCESS, "abc1234\r\n", "");
    interp.proc_env.spawner = Box::new(spawner);

    let mut io = IoStreams::new();
    let code = interp.execute_interactive_line(
        r#"for /F %H in ('git rev-parse --short HEAD') do @echo Commit=%H"#,
        &mut io,
    );
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(io.stdout, "Commit=abc1234\r\n");
    Ok(())
}

assert!(test_build_script().is_ok());
```

### 5.4 Pre-Populating Environment & Windows Registry State

```rust
use win_cmd_rs::error::CmdError;
use win_cmd_rs::runtime::Interpreter;
use win_cmd_rs::runtime::registry::RegistryValueType;

fn configure_env_and_registry() -> Result<Interpreter, CmdError> {
    let mut interp = Interpreter::new();
    interp.proc_env.env.set("BUILD_CONFIG", "Release");
    interp.proc_env.registry_store.set_value(
        r"HKLM\Software\MySDK",
        "SdkRoot",
        RegistryValueType::Sz,
        r"C:\SDK\v10",
    )?;
    Ok(interp)
}

assert!(configure_env_and_registry().is_ok());
```

### 5.5 Lossless CST Parsing, AST Lowering & Programmatic Linting

```rust
use win_cmd_rs::error::CmdError;
use win_cmd_rs::linter::{
    FixApplicability, LinterConfig, OutputFormat, format_diagnostics, generate_unified_diff,
    lint_script, rewrite_script,
};
use win_cmd_rs::parser::cst_parser::parse_script_cst;
use win_cmd_rs::parser::lower::lower_cst_to_ast;
use win_cmd_rs::span::{SourceId, SourceMap};
use win_cmd_rs::types::ExecutionContext;

fn analyze_and_fix(raw: &[u8]) -> Result<String, CmdError> {
    let text = std::str::from_utf8(raw).unwrap_or("");

    // 1. Parse into a 100% lossless Concrete Syntax Tree
    let cst = parse_script_cst(SourceId(0), text, ExecutionContext::BatchFile);
    assert_eq!(cst.to_source_string(), text);

    // 2. Lower CST to typed AST statements and labels
    let _ast = lower_cst_to_ast(&cst);

    // 3. Lint and format diagnostics
    let cfg = LinterConfig {
        fix_safety: FixApplicability::RecommendedRepair,
        ..LinterConfig::default()
    };
    let mut sm = SourceMap::new();
    let (_id, diags) = lint_script("ci.bat", raw, &cfg, &mut sm)?;
    let _sarif = format_diagnostics(&diags, &sm, OutputFormat::Sarif);

    // 4. Compute safe CST rewrite and unified diff
    let (rewritten, _edits) = rewrite_script(text, ExecutionContext::BatchFile, &cfg);
    Ok(generate_unified_diff("ci.bat", text, &rewritten))
}

let diff = analyze_and_fix(b"@echo off\r\nset FOO = 1\r\n");
assert!(diff.is_ok_and(|d| d.contains(r#"set "FOO=1""#)));
```

### 5.6 `#![no_std]` + `alloc` & MS-DOS `DosKernelApi` Embedding

With `default-features = false`, the entire `win_cmd_rs` core compiles without `std` (`#![no_std]` + `extern crate alloc`, `#![forbid(unsafe_code)]`). You can drive both `wincmd` (`Interpreter::with_dos_kernel`) and `wincheck` (`execute_wincheck_over_vfs_streams`) over `SimulatedDosKernel` or a custom hardware `DosKernelApi`:

```rust
use win_cmd_rs::cli::execute_wincheck_over_vfs_streams;
use win_cmd_rs::dos::{SimChildProgram, SimulatedDosKernel};
use win_cmd_rs::error::CmdError;
use win_cmd_rs::runtime::{InMemoryByteReader, Interpreter, IoStreams};
use win_cmd_rs::types::{ExitCode, MemoryProfile, ShellDialect};
use win_cmd_rs::vfs::{DosFatVfs, VirtualFileSystem};

fn run_dos_pipeline_and_linter() -> Result<(), CmdError> {
    let mut sim = SimulatedDosKernel::new();
    // Register a simulated 16-bit DOS `.COM` tool reading redirected stdin spool bytes
    sim.register_child_program(
        r"C:\UPPER.COM",
        SimChildProgram::UppercaseFilter {
            exit_code: ExitCode::SUCCESS,
        },
    );

    let (mut interp, _shared) = Interpreter::with_dos_kernel(sim);
    interp.apply_memory_profile(MemoryProfile::DosCompact4MiB);
    interp.apply_shell_dialect(ShellDialect::MsDos622);
    interp.proc_env.vfs.write_bytes(r"C:\UPPER.COM", b"\xC3")?;

    // Single-tasking `%TEMP%` spooled pipeline (`echo hello | C:\UPPER.COM`)
    let mut io = IoStreams::new();
    let rc = interp.execute_interactive_line(r"echo hello| C:\UPPER.COM", &mut io);
    assert_eq!(rc, ExitCode::SUCCESS);
    assert_eq!(io.stdout, "HELLO\r\n");

    // Run `wincheck --dialect dos622 --fix --in-place` directly over `DosFatVfs`
    let mut vfs = DosFatVfs::new(SimulatedDosKernel::new());
    vfs.write_bytes(r"C:\AUTO.BAT", b"@echo off\r\ngoto :EOF\r\n")?;
    let args = vec![
        "--dialect".to_owned(),
        "dos622".to_owned(),
        "--fix".to_owned(),
        "--in-place".to_owned(),
        r"C:\AUTO.BAT".to_owned(),
    ];
    let mut empty_stdin = InMemoryByteReader::new(Vec::new());
    let mut out = Vec::new();
    let mut err = Vec::new();
    let lint_rc =
        execute_wincheck_over_vfs_streams(&args, &mut vfs, &mut empty_stdin, &mut out, &mut err);
    assert_eq!(lint_rc, 0);
    let fixed = vfs.read_bytes(r"C:\AUTO.BAT")?;
    assert!(fixed.ends_with(b":EOF\r\n"));
    Ok(())
}

assert!(run_dos_pipeline_and_linter().is_ok());
```
