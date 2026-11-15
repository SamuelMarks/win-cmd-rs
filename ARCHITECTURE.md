# `win-cmd-rs` Architecture

`win-cmd-rs` is a single-crate Rust workspace (`#![forbid(unsafe_code)]`, sole runtime dependency `derive_more`) providing two tightly integrated engines over a shared, lossless parsing and virtual-filesystem foundation:

1. **`wincmd`** — A bug-for-bug, quirk-for-quirk cross-platform Windows Command Prompt (`cmd.exe`) interpreter.
2. **`wincheck`** — A `ShellCheck`-style 50-rule static analysis and lossless CST auto-fixing engine for `.bat`, `.cmd`, and interactive `cmd.exe` inputs.

---

## Table of Contents

1. [High-Level System & Module Dependency Graph](#1-high-level-system--module-dependency-graph)
2. [Why `cmd.exe` Is Not a POSIX Shell: The 5-Phase Streaming Pipeline](#2-why-cmdexe-is-not-a-posix-shell-the-5-phase-streaming-pipeline)
3. [Phase 0: Raw-Byte Cursor, Codepages & Span Provenance (`src/reader/`, `src/span.rs`)](#3-phase-0-raw-byte-cursor-codepages--span-provenance-srcreader-srcspanrs)
4. [Unified Lexer, Lossless CST & Dual-Mode AST Lowering (`src/parser/`)](#4-unified-lexer-lossless-cst--dual-mode-ast-lowering-srcparser)
5. [Multi-Pass Expansion & Quote/Caret State Machines (`phase1`–`phase4`)](#5-multi-pass-expansion--quotecaret-state-machines-phase1phase4)
6. [Runtime Engine & Domain Encapsulation (`src/runtime/`)](#6-runtime-engine--domain-encapsulation-srcruntime)
7. [Command Dispatch, Built-Ins, Shims & Deadlock-Free Spawning (`src/builtins/`)](#7-command-dispatch-built-ins-shims--deadlock-free-spawning-srcbuiltins)
8. [Virtual File System, Win32 Paths & Polynomial Globbing (`src/vfs/`)](#8-virtual-file-system-win32-paths--polynomial-globbing-srcvfs)
9. [`wincheck` Static Analyzer & Composable `CstRewriter` (`src/linter/`)](#9-wincheck-static-analyzer--composable-cstrewriter-srclinter)
10. [Unified `CmdError` Architecture & Verification Gates (`src/error.rs`, `tests/`)](#10-unified-cmderror-architecture--verification-gates-srcerrorrs-tests)

---

## 1. High-Level System & Module Dependency Graph

Every layer in `win-cmd-rs` is strictly acyclic: low-level location, domain, and error primitives (`span`, `types`, `error`) sit at the base; `reader`, `parser`, and `vfs` form the middle layer; `runtime`, `builtins`, and `linter` implement execution and static analysis; and `cli` plus the thin `src/bin/{wincmd,wincheck}.rs` entrypoints bind OS streams and arguments.

```mermaid
flowchart TB
    subgraph Binaries["Binary Entrypoints & CLI Layer"]
        BIN_CMD["src/bin/wincmd.rs"]
        BIN_CHK["src/bin/wincheck.rs"]
        CLI["src/cli/<br/>wincmd_cli, wincheck_cli, Streaming REPL & Fix Driver"]
    end

    subgraph Engines["Execution & Static Analysis Engines"]
        RT["src/runtime/<br/>Interpreter, EnvStack, Arithmetic, Registry, CmdIo"]
        BI["src/builtins/<br/>37 Core Built-In Dispatchers & 17 Utility Shims"]
        LINT["src/linter/<br/>50 Lint Rules, Directives, Formatters & CstRewriter"]
    end

    subgraph Frontend["Unified Parsing, Expansion & VFS Layer"]
        PARSE["src/parser/<br/>Lexer, Lossless CST, AST Lowerer & Phases 1-4"]
        READ["src/reader/<br/>BatchFrameReader, CodePages & LogicalLineBuffer"]
        VFS["src/vfs/<br/>VirtualFileSystem, InMemoryVfs, HostOsVfs, Globs & Devices"]
    end

    subgraph Core["Foundational Primitives"]
        SPAN["src/span.rs<br/>ByteOffset, Span, SourceFile & SourceMap"]
        TYPES["src/types.rs<br/>ExitCode, DriveLetter, EnvVarName, CodePage, Mode Enums"]
        ERR["src/error.rs<br/>Unified CmdError (derive_more)"]
    end

    BIN_CMD --> CLI
    BIN_CHK --> CLI
    CLI --> RT
    CLI --> LINT
    CLI --> VFS

    RT <--> BI
    RT --> PARSE
    RT --> READ
    RT --> VFS

    LINT --> PARSE
    LINT --> READ

    PARSE --> READ
    PARSE --> VFS
    READ --> SPAN
    READ --> TYPES
    READ --> ERR
    PARSE --> SPAN
    PARSE --> TYPES
    PARSE --> ERR
    VFS --> TYPES
    VFS --> ERR
    RT --> SPAN
    RT --> TYPES
    RT --> ERR
    LINT --> SPAN
    LINT --> TYPES
    LINT --> ERR
```

---

## 2. Why `cmd.exe` Is Not a POSIX Shell: The 5-Phase Streaming Pipeline

POSIX shells (`sh`, `bash`, `zsh`) parse an entire script or function into an AST before execution. Windows `cmd.exe` does **not**: it is a **stateful, raw-byte-offset macro processor** that fetches one statement (or one `( ... )` compound block) at a time from disk and runs four distinct expansion passes across each command’s lifecycle.

```mermaid
flowchart TD
    VFS_BYTES[("VirtualFileSystem<br/>Raw Script Bytes (&[u8])")]
    P0["Phase 0: Byte-Offset Reader (src/reader/)<br/>• Seek to BatchFrameReader.cursor (ByteOffset)<br/>• Decode 1 physical line via active CodePage<br/>• Truncate at 0x1A (Ctrl+Z) & join ^ continuations"]
    LLB["LogicalLineBuffer<br/>Vec&lt;SpannedChar&gt; with ExpansionOrigin"]
    P1["Phase 1: Immediate % Expansion (parser/phase1.rs)<br/>• Batch %% -> %, %0..%9, %*, %~dpnxfsatz$PATH:1<br/>• %VAR%, %VAR:~s,l%, %VAR:old=new%"]
    P2["Phase 2: Lexing, CST & Block Assembly (parser/phase2.rs)<br/>• Quote & ^ escape state machine + ECHO( exemption<br/>• Read multi-line (...) blocks (running Phase 1 per line!)<br/>• Build CstNode & lower to Statement AST"]
    DISP{"Statement Type"}
    CTRL["Control Flow & Scopes<br/>IF / FOR / GOTO / CALL :sub"]
    P3["Phase 3: FOR Variable Expansion (parser/phase3.rs)<br/>• Expand active %%I / %I & %~dpnxI against FOR stack"]
    P4{"Delayed Expansion Enabled<br/>AND line contains '!'?"}
    P4_RUN["Phase 4: Delayed Expansion (parser/phase4.rs)<br/>• Second ^ escape pass (even inside quotes!)<br/>• Expand !VAR!, !VAR:~s,l!, !VAR:old=new!"]
    P4_SKIP["Skip Phase 4<br/>(Preserve ^ inside quotes verbatim)"]
    EXEC["Redirections & Command Dispatch<br/>RedirectedIo -> Builtin / Shim / .bat / External"]

    VFS_BYTES --> P0 --> LLB --> P1 --> P2 --> DISP
    DISP -- "Compound / IF / FOR" --> CTRL
    CTRL -- "Loop iteration body" --> P3
    DISP -- "SimpleCommand / Pipe / Chain" --> P3
    P3 --> P4
    P4 -- "Yes" --> P4_RUN --> EXEC
    P4 -- "No" --> P4_SKIP --> EXEC
    EXEC -. "Advances cursor / mutates CodePage or VFS" .-> VFS_BYTES
```

### Self-Modifying Scripts, `GOTO` & Mid-Script `CHCP`

Because `BatchFrameReader` stores its file position as a raw `ByteOffset` and re-reads from `VirtualFileSystem` before every statement, three classic `cmd.exe` behaviors emerge naturally without special-case hacks:
1. **Self-modifying batch files**: Appending lines to `"%~f0"` mid-execution causes the interpreter to read and execute the newly appended bytes once `cursor` reaches them.
2. **Mid-script `CHCP` switching**: Executing `CHCP 65001` updates `interp.console.codepage`; the very next physical line is decoded from its raw byte offset using UTF-8 without re-decoding earlier OEM bytes.
3. **`GOTO :label` byte scanning**: Label resolution scans raw bytes forward from `cursor` to EOF and wraps `[0..cursor)` just like `cmd.exe`.

```mermaid
sequenceDiagram
    autonumber
    participant Interp as Interpreter
    participant Reader as BatchFrameReader
    participant Vfs as VirtualFileSystem
    participant Enc as Encoding (CodePage)

    Interp->>Vfs: read_bytes("C:\deploy.bat")
    Vfs-->>Interp: raw_bytes [0..N]
    Reader->>Enc: decode_line_at(offset=0, CodePage::Oem437)
    Enc-->>Reader: "chcp 65001 >nul\r\n" (next offset = 17)
    Reader-->>Interp: Statement 1 (cursor = 17)
    Interp->>Interp: Execute CHCP 65001 (console.codepage = Utf8)

    Interp->>Vfs: read_bytes("C:\deploy.bat")
    Vfs-->>Interp: raw_bytes [0..N]
    Reader->>Enc: decode_line_at(offset=17, CodePage::Utf8)
    Enc-->>Reader: line = echo echo Dynamic >> "%~f0" (next offset = 46)
    Reader-->>Interp: Statement 2 (cursor = 46)
    Interp->>Vfs: append_bytes("C:\deploy.bat", "echo Dynamic\r\n")

    Interp->>Vfs: read_bytes("C:\deploy.bat")
    Vfs-->>Interp: raw_bytes [0..N+14]
    Reader->>Enc: decode_line_at(offset=46, CodePage::Utf8)
    Enc-->>Reader: "echo Dynamic\r\n" (executes newly appended line!)
```

---

## 3. Phase 0: Raw-Byte Cursor, Codepages & Span Provenance (`src/reader/`, `src/span.rs`)

Every diagnostic in `wincheck` and every syntax error in `wincmd` maps expanded characters back to exact 1-based `(LineNumber, ColumnNumber)` coordinates in the original raw file—even after BOM stripping, `^\r\n` line continuations, and multi-pass variable expansions.

- **`SourceMap` & `SourceFile` (`src/span.rs`)**: Stores raw bytes, decoded text, precomputed newline byte offsets (`O(log L)` binary search for `line_col`), and BOM length (`UTF-8` 3-byte, `UTF-16LE/BE` 2-byte).
- **`CodePage` (`src/reader/encoding.rs`)**: Supports `Utf8` (`65001`), `OemUnitedStates` (`437`), `OemMultilingualLatin1` (`850`), `WindowsLatin1` (`1252`), `Utf16Le` (`1200`), `Utf16Be` (`1201`), and `Ascii` (`20127`), plus `0x1A` (`SUB` / `Ctrl+Z`) logical EOF truncation.
- **`ProvenanceMode` (`src/reader/char_map.rs`)**:
  - `ProvenanceMode::Full`: Tracks per-character `ExpansionOrigin` (`LiteralSource`, `CaretContinuation`, `PositionalParam`, `ImmediateEnvVar`, `ForVariable`, `DelayedEnvVar`).
  - `ProvenanceMode::Lightweight`: Elides heap `String` clones inside `ExpansionOrigin` on hot interpreter loops when sub-word provenance is not needed.

```mermaid
classDiagram
    class SourceMap {
        -Vec~SourceFile~ files
        +add_file(name, raw_bytes, text) SourceId
        +replace_file(id, name, raw_bytes, text) bool
        +resolve_span(span) ResolvedSpan
    }
    class SourceFile {
        +SourceId id
        +String name
        +usize bom_byte_len
        +bool has_utf8_bom
        +LineEndingStyle line_ending_style
        +line_col(offset) LineAndCol
    }
    class Span {
        +SourceId source_id
        +ByteOffset start
        +ByteOffset end
        +merge(other) Span
    }
    class LogicalLineBuffer {
        +Vec~SpannedChar~ chars
        +to_plain_string() String
    }
    class SpannedChar {
        +char ch
        +Span span
        +ExpansionOrigin origin
    }
    class ExpansionOrigin {
        <<enumeration>>
        LiteralSource
        CaretContinuation
        PositionalParam
        ImmediateEnvVar
        ForVariable
        DelayedEnvVar
    }

    SourceMap "1" *-- "*" SourceFile
    LogicalLineBuffer "1" *-- "*" SpannedChar
    SpannedChar --> Span
    SpannedChar --> ExpansionOrigin
```

---

## 4. Unified Lexer, Lossless CST & Dual-Mode AST Lowering (`src/parser/`)

`wincmd` (strict execution) and `wincheck` (fault-tolerant static analysis & CST rewriting) share a **single unified parser pipeline** (`lexer.rs` -> `cst_parser/` -> `lower.rs`) so execution semantics and static analysis never drift apart:

1. **Shared Linear-Time Lexer (`src/parser/lexer.rs`)**:
   - Tokenizes statements, words, carets, quotes, `REM`/`::` comments, `ECHO(` delimiters, and top-level binary command operators (`&`, `&&`, `||`, `|`) in $O(N)$ time without backtracking.
2. **Lossless Concrete Syntax Tree (`src/parser/cst.rs`, `src/parser/cst_parser/`)**:
   - Guarantees the round-trip invariant `parse_script_cst(id, src, exec_context).to_source_string() == src` across arbitrary whitespace, UTF-8 BOMs, `CRLF`/`LF` line endings, `^` continuations, and syntax errors.
   - Runs internal statement parsing under `RecoveryMode::Strict` for `wincmd` execution and `RecoveryMode::Recovering` for `wincheck` (recovering from `IF a = b`, `IF (a == b)`, missing `IN`/`DO` in `FOR`, unparenthesized `ELSE`, unclosed `"`, and `%~dpVAR%` while recording `PegDiagnostic`s and farthest-failure expectations).
3. **Dual-Mode CST-to-AST Lowerer (`src/parser/lower.rs`)**:
   - `WordPartsMode::Lightweight`: Lowers CST to `Statement` AST for `wincmd` with zero sub-word `Vec<WordPart>` allocations.
   - `WordPartsMode::PopulateSubwordParts`: Populates rich sub-word `WordPart` tokens (`EnvVar`, `DelayedVar`, `PositionalParam`, `ForVar`, `Quoted`) for `wincheck` static analysis rules.

```mermaid
flowchart LR
    RAW["Logical Line / Script Text"] --> LEX["parser::lexer<br/>O(N) Operator, Quote, Caret & ECHO( Scanner"]
    LEX --> CSTP["parser::cst_parser<br/>Linear-Precedence CST Parser"]

    CSTP -- "RecoveryMode::Strict" --> CST_STRICT["CstScript<br/>(Exact cmd.exe Syntax Rules)"]
    CSTP -- "RecoveryMode::Recovering" --> CST_REC["CstScript + Vec&lt;PegDiagnostic&gt;<br/>(Probable Misuse & ErrorNode Recovery)"]

    CST_STRICT -- "WordPartsMode::Lightweight" --> AST_EXEC["Statement AST<br/>(Zero Sub-Word Heap Alloc)"]
    CST_REC -- "WordPartsMode::PopulateSubwordParts" --> AST_LINT["LoweredScript<br/>(ParsedScript + Sub-Word WordParts)"]
    CST_REC <--> REW["linter::rewriter<br/>Lossless Source-Preserving Edits"]
```

### CST & AST Node Hierarchy

```mermaid
classDiagram
    class CstScript {
        +SourceId source_id
        +CstNode root
        +Vec~PegDiagnostic~ diagnostics
        +Option~FarthestFailure~ farthest_failure
        +to_source_string() String
    }
    class CstNode {
        +SyntaxKind kind
        +Span span
        +Vec~CstElement~ children
    }
    class CstElement {
        <<enumeration>>
        Node(CstNode)
        Token(CstToken)
    }
    class CstToken {
        +SyntaxKind kind
        +String text
        +Span span
    }
    class Statement {
        <<enumeration>>
        Label(LabelNode)
        Rem(RemNode)
        Empty(Span)
        Command(CommandExpr)
    }
    class CommandExpr {
        <<enumeration>>
        Simple(SimpleCommand)
        Block(CompoundBlock)
        If(Box~IfStatement~)
        For(Box~ForStatement~)
        Pipe
        And
        Or
        Seq
    }
    class SimpleCommand {
        +EchoSuppression echo_suppression
        +SpannedWord program
        +Option~char~ echo_delimiter
        +Vec~SpannedWord~ arguments
        +String raw_tail
        +Span raw_tail_span
        +Vec~Redirection~ redirections
        +Span span
    }

    CstScript *-- CstNode
    CstNode *-- CstElement
    CstElement --> CstNode
    CstElement --> CstToken
    Statement *-- CommandExpr
    CommandExpr *-- SimpleCommand
```

---

## 5. Multi-Pass Expansion & Quote/Caret State Machines (`phase1`–`phase4`)

Two state-machine subtleties are essential to authentic `cmd.exe` behavior:
1. **Phase 2 Quote vs. Caret Escaping**: Outside double quotes, `^` escapes the next character (`^&`, `^|`, `^>`, `^^`, `^"`). Inside `"..."`, `^` is treated as an **ordinary literal character** during Phase 2 (`"^&"` contains both `^` and `&`), and `""` represents an escaped quote.
2. **Phase 4 `!`-Triggered Second Caret Pass**: When `DelayedExpansionMode::Enabled` is active, `cmd.exe` scans the post-Phase-3 line for `!`. If **zero** `!` characters are present, Phase 4 does nothing at all! If **at least one** `!` is present anywhere on the line, Phase 4 runs a *second* `^` escape pass—this time honoring `^!` and `^^` **even inside double quotes**—while expanding `!VAR!`.

```mermaid
stateDiagram-v2
    [*] --> Phase2_Unquoted

    state "Phase 2 Tokenization State Machine" as P2 {
        Phase2_Unquoted --> Phase2_Caret : "Caret '^' seen"
        Phase2_Caret --> Phase2_Unquoted : "Emit escaped next char literally"
        Phase2_Unquoted --> Phase2_Quoted : "Quote (#quot;) seen -> QuoteMode::Quoted"
        Phase2_Quoted --> Phase2_Quoted : "'^', '&', '|', '(', ')' stay literal!"
        Phase2_Quoted --> Phase2_Unquoted : "Closing quote (#quot;) seen"
        Phase2_Unquoted --> OperatorSplit : "Unescaped &, &&, ||, |, <, >"
    }

    P2 --> Phase3_ForVars : "Expand %%I / %~dpI"
    Phase3_ForVars --> Phase4_Check

    state "Phase 4 Delayed Expansion Gate" as P4 {
        Phase4_Check --> FastSkip : "DelayedExpansion Disabled OR no '!' in line"
        Phase4_Check --> BangCaretScan : "DelayedExpansion Enabled AND line contains '!'"
        BangCaretScan --> ExpandBangVar : "Unescaped '!VAR!' -> live EnvironmentStack"
        BangCaretScan --> StripCaretEverywhere : "'^x' -> literal 'x' (even inside quotes!)"
    }

    FastSkip --> [*]
    ExpandBangVar --> [*]
    StripCaretEverywhere --> [*]
```

---

## 6. Runtime Engine & Domain Encapsulation (`src/runtime/`)

Rather than exposing raw mutable session fields on a monolithic god-struct, `Interpreter` is partitioned into four domain components with invariant-preserving accessors and configurable `ExecutionLimits`:

```mermaid
classDiagram
    class Interpreter {
        +ProcessEnvironment proc_env
        +SessionConfig config
        +ConsoleState console
        +ExecutionState exec
        +execute_interactive_line(line, io) ExitCode
        +execute_batch_file(path, arg0, args, raw_tail, io) Result~ExitCode, CmdError~
    }
    class ProcessEnvironment {
        +EnvironmentStack env
        +EnvironmentStack startup_env
        +Box~VirtualFileSystem~ vfs
        +Box~ProcessSpawner~ spawner
        +RegistryStore registry_store
        +Vec~PushdEntry~ pushd_stack
    }
    class SessionConfig {
        +HostBindingMode host_binding_mode
        +CmdLocaleConfig locale
        +VerifyCopyMode verify_state
        +OutputUnicodeMode unicode_output_mode
        +FileCompletionMode file_completion
        +ExecutionLimits limits
    }
    class ConsoleState {
        +EchoState echo_state
        +CodePage codepage
        +u16 console_cols
        +u16 console_lines
        +BTreeMap doskey_macros
        -VecDeque~String~ command_history
    }
    class ExecutionState {
        +SourceMap source_map
        -Option_SourceId_8 ephemeral_ring
        -Vec~BatchCallFrame~ call_stack
        -Vec~ForVarBinding~ for_vars
        -ExitCode last_exit_code
        -usize steps_executed
    }
    class ExecutionLimits {
        +Option~usize~ max_steps
        +Option~usize~ max_call_depth
        +Option~usize~ max_loop_iterations
    }

    Interpreter *-- ProcessEnvironment
    Interpreter *-- SessionConfig
    Interpreter *-- ConsoleState
    Interpreter *-- ExecutionState
    SessionConfig *-- ExecutionLimits
```

Key runtime design invariants:
- **Bounded `O(1)` Memory in Long-Running Sessions**: `ExecutionState` reuses an 8-slot ring buffer (`ephemeral_ring`) for interactive REPL, `CALL`, and `FOR /F` command strings, and reuses inactive `SourceId` slots per uppercase batch path (`batch_source_slots`) so calling `.bat` files in loops never leaks `SourceMap` entries. `ConsoleState` bounds `DOSKEY` history via a `VecDeque<String>`.
- **`SETLOCAL` / `ENDLOCAL` Stack (`src/runtime/env.rs`)**: `SETLOCAL` snapshots the current variable map, `ExtensionsMode`, `DelayedExpansionMode`, and active drive/CWD onto `EnvironmentStack`; `ENDLOCAL` (or exiting a `BatchCallFrame` via `:EOF` / `EXIT /B`) automatically unwinds all frames opened within that batch invocation.
- **Live `RegistryStore` Integration (`src/runtime/registry.rs`)**: `HKLM` and `HKCU` `Software\Microsoft\Command Processor` (`DelayedExpansion`, `EnableExtensions`, `DefaultColor`, `AutoRun`) and `HKCR` file associations (`ASSOC`, `FTYPE`) share a single canonical `RegistryStore` with the `REG` utility shim.

---

## 7. Command Dispatch, Built-Ins, Shims & Deadlock-Free Spawning (`src/builtins/`)

When a `SimpleCommand` reaches execution, `RedirectedIo` binds input/output file or stream redirections (`<`, `>`, `>>`, `2>&1`, `1>&2`, `NUL`, `CON`), and `dispatch_builtin` routes the command through a four-tier resolution chain:

```mermaid
flowchart TD
    CMD["SimpleCommand<br/>(Post Phase 3 & Phase 4)"] --> REDIR["Bind RedirectedIo<br/>(&lt;, &gt;, &gt;&gt;, 2&gt;&amp;1, 1&gt;&amp;2, DosDevice)"]
    REDIR -- "Redirection I/O Error" --> FAIL_REDIR["Emit stderr &amp; set ERRORLEVEL=1<br/>(Command body NOT executed)"]
    REDIR -- "Success" --> DRV{"Drive Switch?<br/>(e.g. 'D:')"}
    DRV -- "Yes" --> SET_DRV["vfs.set_current_drive(D:)"]
    DRV -- "No" --> INT{"Tier 1: Core Internal Built-In?<br/>(try_dispatch_internal: 37 dispatchers)"}
    INT -- "Match" --> RUN_INT["env_cmds / flow_cmds / fs_cmds / console_cmds"]
    INT -- "None" --> SHIM{"Tier 2: Cross-Platform Utility Shim?<br/>(try_dispatch_shim: 17 shims)"}
    SHIM -- "Match" --> RUN_SHIM["shims_search / shims_admin / CMD subshell"]
    SHIM -- "None" --> RESOLVE["Tier 3: Resolve via CWD + %PATH% + %PATHEXT%"]
    RESOLVE -- ".bat / .cmd" --> RUN_BAT["Push BatchCallFrame<br/>(Transfer control if no CALL; return if CALL)"]
    RESOLVE -- "ASSOC + FTYPE match" --> RUN_ASSOC["Expand FTYPE template (%1, %*) &amp; execute"]
    RESOLVE -- ".exe / .com / host binary" --> SPAWN["Tier 4: ProcessSpawner::spawn_external<br/>std::thread::scope (stdin writer + stdout/stderr readers)"]
    RESOLVE -- "Not Found" --> ERR_9009["CmdError::UnknownCommand<br/>(ERRORLEVEL = 9009)"]
```

- **Zero-Copy VFS Sharing Across Pipelines (`cmd1 | cmd2`)**: Instead of deep-cloning `InMemoryVfs` for both sides of a pipe, `execute_pipeline` snapshots only per-drive CWDs (`VfsCwdSnapshot`), runs the left and right subshells with isolated `EnvironmentStack` and `ConsoleState` instances against the shared `VirtualFileSystem`, and restores the parent's CWD snapshot afterward.
- **Deadlock-Free Child Process Spawning (`HostProcessSpawner`)**: Uses `std::thread::scope` to concurrently stream `stdin` on a writer thread (closing child `stdin` immediately upon EOF) while draining `stdout` and `stderr` on two reader threads prior to `child.wait()`, preventing OS pipe buffer deadlocks on >64 KiB payloads.

---

## 8. Virtual File System, Win32 Paths & Polynomial Globbing (`src/vfs/`)

All filesystem operations in `reader`, `parser` (`%~dpnxfsatz$PATH:`), `runtime`, and `builtins` pass through the `VirtualFileSystem` trait—never `std::fs` directly—enabling deterministic cross-platform Windows path semantics on Linux, macOS, and Windows:

```mermaid
flowchart TD
    RAW_P["Raw Path Input<br/>e.g. 'D:sub\\..\\PROGRA~1\\*.txt' or '\\\\srv\\share\\f'"] --> DEV{"DosDevice::intercept_path?<br/>NUL, CON, PRN, AUX, CLOCK$, COM1..9, LPT1..9"}
    DEV -- "Device Match" --> DEV_IO["Device Stream / IF EXIST 'dir\\NUL' Check"]
    DEV -- "Filesystem Path" --> CLASS["classify_path (vfs/path.rs)<br/>DriveAbsolute | DriveRelative | RootRelative | Relative | Unc | InvalidUnc"]
    CLASS --> NORM["Resolve against Active Drive &amp; Per-Drive CWD<br/>Strip Win32 trailing dots/spaces (MultiDotMode::NtTrailingDotStrip)<br/>Case-insensitive Eq / Ord / Hash on WindowsPath"]
    NORM --> BACKEND{"VirtualFileSystem Backend"}

    BACKEND -- "InMemoryVfs" --> MEM["Inode Graph &amp; VfsRoot (Drive | Unc)<br/>• Arc-shared hardlinks (InodeId)<br/>• 32-hop ReparsePoint symlinks/junctions<br/>• NT 8.3 names (PROGRA~1..4, PRxxxx~1 hash &gt;=5)"]
    BACKEND -- "HostOsVfs" --> HOST["Host Directory Mount Table (C:, D:, Z:)<br/>• Case-insensitive POSIX directory segment walker<br/>• FileAttributeFlags sidecar (R, H, S, A, L)<br/>• SandboxContainment::Contained symlink guard"]

    MEM --> GLOB["Win32 Glob Engine (vfs/glob.rs)<br/>FsRtlIsNameInExpression (DOS_STAR, DOS_QM, DOS_DOT)<br/>O(|P| * |N|) Iterative DP Matcher"]
    HOST --> GLOB
```

### Polynomial-Time Win32 Wildcard Engine (`src/vfs/glob.rs`)

Win32 wildcard rules (`FsRtlIsNameInExpression`) differ sharply from POSIX globs: `*.*` matches extensionless files, `*.` matches *only* extensionless files, and `?` (`DOS_QM`) matches 0 characters before `.` or end-of-name. `matches_win32_glob` evaluates both long filenames and 8.3 short filenames via an iterative dynamic-programming state vector in strictly $O(|P| \cdot |N|)$ worst-case time and $O(|N|)$ space, eliminating exponential backtracking on adversarial patterns like `*a*a*a*a*a*b`.

---

## 9. `wincheck` Static Analyzer & Composable `CstRewriter` (`src/linter/`)

`wincheck` combines file-level encoding/directive inspection, CST syntax-recovery diagnostics, AST semantic passes, and a 4-stage composable CST tree rewriter (`CstRewriter`). Crucially, **both `wincheck --diff` and `wincheck --fix` invoke the exact same `CstRewriter` pipeline**, guaranteeing 100% agreement between previewed diffs and rewritten scripts.

```mermaid
flowchart TD
    SRC["Raw Script Bytes (&[u8])"] --> DIR["directives.rs<br/>Check UTF-8 BOM (CMD1008), LF endings (CMD1009)<br/>Build SuppressionTable (REM wincheck disable=...)"]
    SRC --> CST["cst_parser::parse_script_cst<br/>(RecoveryMode::Recovering)"]
    CST --> PEG_DIAG["Convert PegDiagnostics<br/>(CMD1002, CMD1003, CMD1006, CMD1013, CMD1014, CMD2014)"]
    CST --> LOWER["lower_cst_to_ast_with_mode<br/>(PopulateSubwordParts)"]
    LOWER --> AST_PASS["passes/mod.rs<br/>50-Rule Semantic Visitors:<br/>• Block %VAR% &amp; dynamic vars (CMD2001, CMD2009)<br/>• Labels, CALL, EXIT, ROBOCOPY, pipes (CMD3xxx)<br/>• Quoting, SET, RD /S /Q root guard (CMD2xxx, CMD4xxx)"]

    DIR --> MERGE["Filter by SuppressionTable, Severity &amp; Include/Exclude<br/>Sort deterministically by Span &amp; RuleId"]
    PEG_DIAG --> MERGE
    AST_PASS --> MERGE
    MERGE --> FMT["formatters.rs<br/>TTY | GCC | JSON | SARIF v2.1.0"]

    subgraph Rewriter["Composable Lossless CstRewriter (--fix & --diff)"]
        R0["Initial CstScript"] --> P_DELAY["Pass 1: DelayedExpansionBlockPass<br/>%VAR% -> !VAR! in blocks + safe SETLOCAL injection"]
        P_DELAY --> P_STRUCT["Pass 2: StructuralSyntaxFixPass<br/>IF ==, FOR IN/DO, (...) ELSE (...), SET #quot;k=v#quot;, CD /D, CALL, ECHO("]
        P_STRUCT --> P_DIAL["Pass 3: ExecutionModePercentPass<br/>Batch (%%I, 100%%) &lt;-&gt; REPL (%I, 100%)"]
        P_DIAL --> P_QUOTE["Pass 4: QuoteUnquotedVariablesPass<br/>Quote paths/IF/redirs &amp; #quot;%1#quot; -> #quot;%~1#quot;"]
        P_QUOTE --> OUT_TXT["Recompute Spans &amp; Emit Lossless Source<br/>(Myers/LCS Unified Diff or stdout)"]
    end

    CST -. "When --diff or --fix" .-> R0
```

Why multi-pass CST re-parsing between rewrite stages matters:
- If Pass 2 repairs an unparenthesized `IF %x% = 1 echo %x% else echo no` into `IF %x% == 1 (echo(%x%) else (echo no)` and wraps `SET y = 2 ` into `SET "y=2"`, Pass 4 immediately sees the newly structured CST nodes without byte-offset collisions or corrupted spans, and `rewrite_script` is **idempotent** (`rewrite(rewrite(s)) == rewrite(s)`).

---

## 10. Unified `CmdError` Architecture & Verification Gates (`src/error.rs`, `tests/`)

Every fallible operation across all 61 source files (59 library modules and 2 binary entrypoints) returns `Result<T, CmdError>`—a single strongly typed enum powered by `derive_more::{Display, Error, From, IsVariant}` with zero `anyhow`, `thiserror`, or `Box<dyn Error>` erasure.

```mermaid
flowchart LR
    SUB["Reader / Parser / VFS / Arithmetic / Runtime / Builtins / Linter / CLI"] --> ERR["CmdError<br/>derive(Display, Error, From, IsVariant)"]
    ERR --> MSG[".cmd_exe_message()<br/>Authentic Windows stderr text"]
    ERR --> CODE[".exit_code()<br/>ExitCode (1, 2, 9009, ...)"]
    ERR --> SP[".span()<br/>Optional Source Span"]

    subgraph Gates["Automated Quality & Invariant Gates (tests/)"]
        G1["doc_and_quality_gates.rs<br/>100% File/Type/Fn/#Arguments/#Returns/#Errors<br/>Zero unwrap/expect/panic/allow/unsafe"]
        G2["property_invariants.rs<br/>CST Round-Trip Losslessness, Case-Insensitive VFS,<br/>&lt;1ms Adversarial Globbing &amp; Safe Rewriter Equivalence"]
        G3["cli_binaries.rs<br/>End-to-End wincmd &amp; wincheck Subprocess Pipe/File Tests"]
        G4["cargo +nightly llvm-cov --branch<br/>100.00% Functions, Lines &amp; Short-Circuit Branches"]
    end

    SUB -. "Verified by" .-> Gates
```
