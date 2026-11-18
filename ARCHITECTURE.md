# `win-cmd-rs` Architecture

`win-cmd-rs` is a `#![no_std]` + `alloc` core Rust architecture (`#![forbid(unsafe_code)]` across the entire core library, sole runtime dependency `derive_more`) providing two tightly integrated engines over a shared, lossless parsing and virtual-filesystem foundation across Windows, Linux, macOS, and 32-bit Protected-Mode MS-DOS (`DJGPP` + `CWSDPMI`):

1. **`wincmd` (`WINCMD.EXE`)** — A bug-for-bug, quirk-for-quirk cross-platform Windows Command Prompt (`cmd.exe`) and MS-DOS (`COMMAND.COM`) interpreter.
2. **`wincheck` (`WINCHECK.EXE`)** — A `ShellCheck`-style 60-rule static analysis (`CMD0001`–`CMD5010`) and lossless CST auto-fixing engine for `.bat`, `.cmd`, MS-DOS `COMMAND.COM`, and interactive `cmd.exe` inputs.

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
11. [`#![no_std]` + `alloc` Core, `DosKernelApi`, `%TEMP%` Spooling & DPMI Memory Layout (`src/dos/`, `crates/wincmd-dos/`)](#11-no_std--alloc-core-doskernelapi-temp-spooling--dpmi-memory-layout-srcdos-crateswincmd-dos)

---

## 1. High-Level System & Module Dependency Graph

Every layer in `win-cmd-rs` is strictly acyclic: low-level location, domain, and error primitives (`span`, `types`, `error`) sit at the base; `dos`, `reader`, `parser`, and `vfs` form the middle `#![no_std]` + `alloc` layer; `runtime`, `builtins`, and `linter` implement execution and static analysis; and `cli` plus the thin host (`src/bin/`) and DJGPP (`crates/wincmd-dos/`) binary entrypoints bind OS streams, `HostOsVfs`, or `DjgppDosKernel`.

```mermaid
flowchart TB
    subgraph Binaries["Host & MS-DOS Binary Entrypoints"]
        BIN_HOST["src/bin/{wincmd,wincheck}.rs<br/>(Host std OS)"]
        BIN_DOS["crates/wincmd-dos/<br/>WINCMD.EXE & WINCHECK.EXE (DJGPP + CWSDPMI)"]
        CLI["src/cli/<br/>Stream-Generic CLI & REPL (#![no_std] + std)"]
    end

    subgraph Engines["Execution & Static Analysis Engines (#![no_std] + alloc)"]
        RT["src/runtime/<br/>Interpreter, DosProcessSpawner, EnvStack, Arithmetic, Registry"]
        BI["src/builtins/<br/>Core Built-Ins, MS-DOS Commands (TRUENAME/CTTY/LH/MEM) & Shims"]
        LINT["src/linter/<br/>60 Lint Rules (CMD0001-CMD5010), Directives, Formatters & CstRewriter"]
    end

    subgraph Frontend["Unified Parsing, Expansion, VFS & DOS Abstraction (#![no_std] + alloc)"]
        PARSE["src/parser/<br/>Lexer, Lossless CST, AST Lowerer & Phases 1-4"]
        READ["src/reader/<br/>BatchFrameReader, OEM/UTF CodePages & LogicalLineBuffer"]
        VFS["src/vfs/<br/>VirtualFileSystem, InMemoryVfs, DosFatVfs & std HostOsVfs"]
        DOS["src/dos/<br/>DosKernelApi, SimulatedDosKernel, DosConsoleLineEditor & FAT/PSP Types"]
    end

    subgraph Core["Foundational Primitives (#![no_std] + alloc)"]
        SPAN["src/span.rs<br/>ByteOffset, Span, SourceFile & SourceMap"]
        TYPES["src/types.rs<br/>ExitCode, DriveLetter, IoErrorKind, ShellDialect, MemoryProfile"]
        ERR["src/error.rs<br/>Unified CmdError (derive_more, core::error::Error)"]
    end

    BIN_HOST --> CLI
    BIN_DOS --> CLI
    BIN_DOS --> DOS
    CLI --> RT
    CLI --> LINT
    CLI --> VFS

    RT <--> BI
    RT --> PARSE
    RT --> READ
    RT --> VFS
    RT --> DOS

    LINT --> PARSE
    LINT --> READ
    LINT --> VFS

    VFS --> DOS
    PARSE --> READ
    PARSE --> VFS
    DOS --> TYPES
    DOS --> ERR
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
    Reader->>Enc: decode_physical_line_from_bytes(offset=0, CodePage::OemUnitedStates)
    Enc-->>Reader: "chcp 65001 >nul\r\n" (next offset = 17)
    Reader-->>Interp: Statement 1 (cursor = 17)
    Interp->>Interp: Execute CHCP 65001 (console.codepage = Utf8)

    Interp->>Vfs: read_bytes("C:\deploy.bat")
    Vfs-->>Interp: raw_bytes [0..N]
    Reader->>Enc: decode_physical_line_from_bytes(offset=17, CodePage::Utf8)
    Enc-->>Reader: line = echo echo Dynamic >> "%~f0" (next offset = 46)
    Reader-->>Interp: Statement 2 (cursor = 46)
    Interp->>Vfs: append_bytes("C:\deploy.bat", "echo Dynamic\r\n")

    Interp->>Vfs: read_bytes("C:\deploy.bat")
    Vfs-->>Interp: raw_bytes [0..N+14]
    Reader->>Enc: decode_physical_line_from_bytes(offset=46, CodePage::Utf8)
    Enc-->>Reader: "echo Dynamic\r\n" (executes newly appended line!)
```

---

## 3. Phase 0: Raw-Byte Cursor, Codepages & Span Provenance (`src/reader/`, `src/span.rs`)

Every diagnostic in `wincheck` and every syntax error in `wincmd` maps expanded characters back to exact 1-based `(LineNumber, ColumnNumber)` coordinates in the original raw file—even after BOM stripping, `^\r\n` line continuations, and multi-pass variable expansions.

- **`SourceMap` & `SourceFile` (`src/span.rs`)**: Stores raw bytes, decoded text, precomputed newline byte offsets (`O(log L)` binary search for `line_col`), and BOM length (`UTF-8` 3-byte, `UTF-16LE/BE` 2-byte).
- **`CodePage` (`src/reader/encoding.rs`)**: Supports `Utf8` (`65001`), `OemUnitedStates` (`437`), `OemMultilingualLatin1` (`850`), `OemLatin2` (`852`), `OemNordic` (`865`), `OemCyrillic` (`866`), `WindowsLatin1` (`1252`), `Utf16Le` (`1200`), `Utf16Be` (`1201`), and `Ascii` (`20127`), plus `0x1A` (`SUB` / `Ctrl+Z`) logical EOF truncation.
- **`ProvenanceMode` (`src/reader/char_map.rs`)**:
  - `ProvenanceMode::Full`: Materializes sub-word `CstToken` slices alongside per-character `ExpansionOrigin` (`LiteralSource`, `CaretContinuation`, `PositionalParam`, `ImmediateEnvVar`, `ForVariable`, `DelayedEnvVar`) for static analysis.
  - `ProvenanceMode::Compact`: Skips sub-word `CstToken` allocation during pure interpreter execution (paired with `WordPartsMode::Lightweight` in `src/parser/lower.rs`) so hot loops avoid unnecessary sub-word heap allocations.

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
        +bool escaped_by_caret
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
        +Option~Box~DosKernelApi~~ dos_kernel
        +RegistryStore registry_store
        +Vec~PushdEntry~ pushd_stack
    }
    class SessionConfig {
        +HostBindingMode host_binding_mode
        +ShellDialect dialect
        +PermanentShellMode permanent_shell
        +Option~u16~ dos_env_bytes
        +MemoryProfile memory_profile
        +ProvenanceMode provenance_mode
        +CmdLocaleConfig locale
        +VerifyCopyMode verify_state
        +OutputUnicodeMode unicode_output_mode
        +PipeExecutionMode pipe_execution_mode
        +FileCompletionMode file_completion
        +ExecutionLimits limits
    }
    class ConsoleState {
        +EchoState echo_state
        +CodePage codepage
        +u16 console_cols
        +u16 console_lines
        +ConsoleRenderBackend render_backend
        +BTreeMap doskey_macros
        -VecDeque~String~ command_history
    }
    class ExecutionState {
        +SourceMap source_map
        -Option_SourceId_8 ephemeral_ring
        -BTreeMap~String, SourceId~ batch_source_slots
        -Vec~BatchCallFrame~ call_stack
        -Vec~ForVarName_String~ for_vars
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
    DRV -- "No" --> INT{"Tier 1: Core Internal Built-In?<br/>(try_dispatch_internal: 46 command names)"}
    INT -- "Match" --> RUN_INT["env_cmds / flow_cmds / fs_cmds / console_cmds / dos_cmds"]
    INT -- "None" --> SHIM{"Tier 2: Cross-Platform Utility Shim?<br/>(try_dispatch_shim: 18 shims)"}
    SHIM -- "Match" --> RUN_SHIM["shims_search / shims_admin / dos_cmds (MEM) / CMD"]
    SHIM -- "None" --> RESOLVE["Tier 3: Resolve via CWD + %PATH% + %PATHEXT%"]
    RESOLVE -- ".bat / .cmd" --> RUN_BAT["Push BatchCallFrame<br/>(Transfer control if no CALL; return if CALL)"]
    RESOLVE -- "ASSOC + FTYPE match" --> RUN_ASSOC["Expand FTYPE template (%1, %*) &amp; execute"]
    RESOLVE -- ".exe / .com / host binary" --> SPAWN["Tier 4: ProcessSpawner::spawn_external<br/>HostProcessSpawner (thread::scope) or DosProcessSpawner (%TEMP% spool)"]
    RESOLVE -- "Not Found" --> ERR_9009["CmdError::CommandNotRecognized<br/>(ERRORLEVEL = 9009)"]
```

- **Zero-Copy VFS Sharing Across Pipelines (`cmd1 | cmd2`)**: Instead of deep-cloning `InMemoryVfs` for both sides of a pipe, `execute_pipeline` snapshots only per-drive CWDs (`VfsCwdSnapshot`), runs the left and right subshells with isolated `EnvironmentStack` and `ConsoleState` instances against the shared `VirtualFileSystem`, and restores the parent's CWD snapshot afterward.
- **Deadlock-Free Host & Single-Tasking DOS Child Spawning**: On host OSes (`std`), `HostProcessSpawner` uses `std::thread::scope` to concurrently stream `stdin` on a writer thread while draining `stdout` and `stderr` on two reader threads prior to `child.wait()`, preventing OS pipe buffer deadlocks on >64 KiB payloads. On MS-DOS, `DosProcessSpawner` spools redirected handles through collision-free 8.3 `%TEMP%` files around `INT 21h AH=4Bh`.

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
    BACKEND -- "DosFatVfs<K: DosKernelApi>" --> DOSFAT["MS-DOS FAT12/16/32 &amp; DOS 7 LFN<br/>• Strict 8.3 truncation or INT 21h AX=71xxh LFN<br/>• 2-second PackedDosTimestamp &amp; FatAttributeByte<br/>• Cross-drive copy+delete MOVE fallback"]

    MEM --> GLOB["Win32 Glob Engine (vfs/glob.rs)<br/>FsRtlIsNameInExpression (DOS_STAR, DOS_QM, DOS_DOT)<br/>O(|P| * |N|) Iterative DP Matcher"]
    HOST --> GLOB
    DOSFAT --> GLOB
```

### Polynomial-Time Win32 Wildcard Engine (`src/vfs/glob.rs`)

Win32 wildcard rules (`FsRtlIsNameInExpression`) differ sharply from POSIX globs: `*.*` matches extensionless files, `*.` matches *only* extensionless files, and `?` (`DOS_QM`) matches 0 characters before `.` or end-of-name. `matches_win32_glob` evaluates both long filenames and 8.3 short filenames via an iterative dynamic-programming state vector in strictly $O(|P| \cdot |N|)$ worst-case time and $O(|N|)$ space, eliminating exponential backtracking on adversarial patterns like `*a*a*a*a*a*b`.

---

## 9. `wincheck` Static Analyzer & Composable `CstRewriter` (`src/linter/`)

`wincheck` combines file-level encoding/directive inspection, CST syntax-recovery diagnostics, AST semantic passes (including the `CMD5001`–`CMD5010` MS-DOS `COMMAND.COM` portability analyzer), and a 5-stage composable CST tree rewriter (`CstRewriter`). Crucially, **both `wincheck --diff` and `wincheck --fix` invoke the exact same `CstRewriter` pipeline**, guaranteeing 100% agreement between previewed diffs and rewritten scripts.

```mermaid
flowchart TD
    SRC["Raw Script Bytes (&[u8])"] --> DIR["directives.rs<br/>Check UTF-8 BOM (CMD1008), LF endings (CMD1009)<br/>Build SuppressionTable (REM wincheck disable=...)"]
    SRC --> CST["cst_parser::parse_script_cst<br/>(RecoveryMode::Recovering)"]
    CST --> PEG_DIAG["Convert PegDiagnostics<br/>(CMD1002, CMD1003, CMD1006, CMD1013, CMD1014, CMD2014)"]
    CST --> LOWER["lower_cst_to_ast_with_mode<br/>(PopulateSubwordParts)"]
    LOWER --> AST_PASS["passes/mod.rs &amp; passes/dos_compat.rs<br/>60-Rule Semantic Visitors (CMD0001-CMD5010):<br/>• Block %VAR% &amp; dynamic vars (CMD2001, CMD2009)<br/>• Labels, CALL, EXIT, ROBOCOPY, pipes (CMD3xxx)<br/>• Quoting, SET, RD /S /Q root guard (CMD2xxx, CMD4xxx)<br/>• MS-DOS COMMAND.COM portability (CMD5001-CMD5010)"]

    DIR --> MERGE["Filter by SuppressionTable, Dialect, Severity &amp; Include/Exclude<br/>Sort deterministically by Span &amp; RuleId"]
    PEG_DIAG --> MERGE
    AST_PASS --> MERGE
    MERGE --> FMT["formatters.rs<br/>TTY | GCC | JSON | SARIF v2.1.0"]

    subgraph Rewriter["Composable Lossless CstRewriter (--fix & --diff)"]
        R0["Initial CstScript"] --> P_DELAY["Pass 1: DelayedExpansionBlockPass<br/>%VAR% -> !VAR! in blocks + safe SETLOCAL injection"]
        P_DELAY --> P_STRUCT["Pass 2: StructuralSyntaxFixPass<br/>IF ==, FOR IN/DO, (...) ELSE (...), SET #quot;k=v#quot;, CD /D, CALL, ECHO("]
        P_STRUCT --> P_DIAL["Pass 3: ExecutionModePercentPass<br/>Batch (%%I, 100%%) &lt;-&gt; REPL (%I, 100%)"]
        P_DIAL --> P_QUOTE["Pass 4: QuoteUnquotedVariablesPass<br/>Quote paths/IF/redirs &amp; #quot;%1#quot; -> #quot;%~1#quot;"]
        P_QUOTE --> P_DOS["Pass 5: MsDosPortabilityPass (MsDos622)<br/>Split &amp; chains onto lines + append explicit :EOF"]
        P_DOS --> OUT_TXT["Recompute Spans &amp; Emit Lossless Source<br/>(Myers/LCS Unified Diff or VFS --in-place)"]
    end

    CST -. "When --diff or --fix" .-> R0
```

Why multi-pass CST re-parsing between rewrite stages matters:
- If Pass 2 repairs an unparenthesized `IF %x% = 1 echo %x% else echo no` into `IF %x% == 1 (echo(%x%) else (echo no)` and wraps `SET y = 2 ` into `SET "y=2"`, Pass 4 immediately sees the newly structured CST nodes without byte-offset collisions or corrupted spans, while under `ShellDialect::MsDos622` NT-only rewrites are gated off and Pass 5 (`MsDosPortabilityPass`) decomposes `&` chains and `GOTO :EOF` cleanly. Every `rewrite_script` configuration is **idempotent** (`rewrite(rewrite(s)) == rewrite(s)`).

---

## 10. Unified `CmdError` Architecture & Verification Gates (`src/error.rs`, `tests/`)

Every fallible operation across both the `#![no_std]` core (`src/`) and the DJGPP MS-DOS adapter (`crates/wincmd-dos/`) returns `Result<T, CmdError>`—a single strongly typed enum powered by `derive_more::{Display, Error, From, IsVariant}` implementing `core::error::Error` with zero `anyhow`, `thiserror`, or `Box<dyn Error>` erasure.

```mermaid
flowchart LR
    SUB["Reader / Parser / VFS / DOS / Arithmetic / Runtime / Builtins / Linter / CLI"] --> ERR["CmdError<br/>derive(Display, Error, From, IsVariant)"]
    ERR --> MSG[".cmd_exe_message()<br/>Authentic cmd.exe &amp; COMMAND.COM stderr text"]
    ERR --> CODE[".exit_code()<br/>ExitCode (1, 2, 9009, ...)"]
    ERR --> SP[".span()<br/>Optional Source Span"]

    subgraph Gates["Automated Quality & Invariant Gates (tests/)"]
        G1["doc_and_quality_gates.rs<br/>100% File/Type/Fn/#Arguments/#Returns/#Errors/#Safety<br/>60-Rule Catalog &amp; Zero unwrap/expect/panic/allow"]
        G2["property_invariants.rs<br/>CST Round-Trip, FAT Timestamps, 8.3 Names, PSP Tails,<br/>256-Byte OEM Codepage Bijections &amp; Rewriter Idempotence"]
        G3["cli_binaries.rs &amp; FreeDOS QEMU CI<br/>Host Subprocess Tests + Headless FreeDOS Boot Verification"]
        G4["cargo +nightly llvm-cov --branch<br/>100.00% Functions, Lines &amp; Short-Circuit Branches"]
    end

    SUB -. "Verified by" .-> Gates
```

---

## 11. `#![no_std]` + `alloc` Core, `DosKernelApi`, `%TEMP%` Spooling & DPMI Memory Layout (`src/dos/`, `crates/wincmd-dos/`)

### 11.1 100% Safe `#![no_std]` Hardware Boundary (`DosKernelApi`)

To run natively on MS-DOS without sacrificing `#![forbid(unsafe_code)]` or 100.00% host branch coverage, all MS-DOS domain logic lives in `src/dos/`, `src/vfs/dos.rs`, and `src/runtime/dos_exec.rs` against the safe `DosKernelApi` trait. Host tests execute against the deterministic in-memory `SimulatedDosKernel`, while `crates/wincmd-dos` binds `DjgppDosKernel` to DJGPP `libc` and DPMI `INT 10h`/`11h`/`16h`/`21h`/`31h`:

```mermaid
flowchart TB
    subgraph SafeCore["100% Safe #![no_std] + alloc Core (src/ — #![forbid(unsafe_code)])"]
        INTERP_DOS["Interpreter + Linter + CLI"]
        DOS_VFS["DosFatVfs&lt;K: DosKernelApi&gt;<br/>8.3 / DOS 7 LFN, FatAttributeByte, PackedDosTimestamp"]
        DOS_EXEC["DosProcessSpawner&lt;K: DosKernelApi&gt;<br/>126-byte PspCommandTail, CMDLINE=, %TEMP% Spooling"]
        DOS_CON["DosConsoleLineEditor &amp; run_dos_bios_repl<br/>BIOS Scan-Code Line Editor (F1/F3/F7/F8/F9, Tab) &amp; INT 10h CLS"]
        KTRAIT["pub trait DosKernelApi<br/>(Zero unsafe methods)"]
    end

    subgraph HostTest["Host Verification (Linux / macOS / Windows)"]
        SIM["SimulatedDosKernel (src/dos/sim.rs)<br/>• In-memory FAT16/32 &amp; strict 8.3 truncation<br/>• 2-second FAT timestamp rounding<br/>• Scripted DosFaultRule queue &amp; .COM/.EXE handlers<br/>• 100.00% fn / line / branch llvm-cov"]
    end

    subgraph TargetDos["MS-DOS Target Adapter (crates/wincmd-dos/)"]
        DJ_K["DjgppDosKernel (#![forbid(unsafe_code)])<br/>Maps DosExtendedError -> CmdError::from_dos_error"]
        DJ_FFI["ffi.rs + alloc_djgpp.rs + panic_dos.rs<br/>• DjgppAllocator (malloc/free + &gt;8B alignment header)<br/>• Zero-heap stack #[panic_handler] to fd 2<br/>• INT 21h/16h/11h/10h/31h &amp; spawnvpe"]
    end

    INTERP_DOS --> DOS_VFS & DOS_EXEC & DOS_CON
    DOS_VFS & DOS_EXEC & DOS_CON --> KTRAIT
    KTRAIT <|.. SIM
    KTRAIT <|.. DJ_K
    DJ_K --> DJ_FFI
```

### 11.2 Single-Tasking `%TEMP%` Pipeline Spooling (`src/runtime/dos_exec.rs`)

Because real-mode MS-DOS is single-tasking and has no concurrent anonymous kernel pipes, `Interpreter::execute_pipeline` (`PipeExecutionMode::InMemoryBuffered`) and `DosProcessSpawner` execute multi-stage pipelines (`prog1.com | builtin | prog2.exe`) sequentially via collision-free 8.3 temporary spool files (`_WCI0000.TMP`, `_WCO0000.TMP`, `_WCE0000.TMP`) in `%TEMP%` -> `%TMP%` -> active drive root, polling `DosKernelApi::poll_ctrl_break()` between stages and unconditionally cleaning up spool files:

```mermaid
sequenceDiagram
    participant Sh as Interpreter (execute_pipeline)
    participant Sp as DosProcessSpawner
    participant K as DosKernelApi (DjgppDosKernel)
    participant P1 as Child 1 (PROG1.COM)
    participant P2 as Child 2 (PROG2.EXE)

    Sh->>Sp: spawn_external(PROG1.COM, stdin="")
    Sp->>K: memory_stats() + pack PSP tail (&lt;=126B + CMDLINE=)
    Sp->>K: exec_child(stdout -> C:\TEMP\_WCO0000.TMP)
    K->>P1: INT 21h AH=4Bh EXEC (dup2 fd 1 -> _WCO0000.TMP)
    P1-->>K: INT 21h AH=4Ch exit + AH=4Dh return code
    Sp->>K: read_file_bytes(_WCO0000.TMP) & delete_file(_WCO0000.TMP)
    Sp-->>Sh: Stage 1 stdout bytes

    Sh->>K: poll_ctrl_break() (abort cleanly if Ctrl+C/Break)

    Sh->>Sp: spawn_external(PROG2.EXE, stdin=Stage 1 bytes)
    Sp->>K: write_file_bytes(C:\TEMP\_WCI0001.TMP, Stage 1 bytes)
    Sp->>K: exec_child(stdin -> _WCI0001.TMP, stdout -> _WCO0001.TMP)
    K->>P2: INT 21h AH=4Bh EXEC (dup2 fd 0/1)
    P2-->>K: ExitCode
    Sp->>K: read_file_bytes(_WCO0001.TMP) & delete _WCI0001/_WCO0001/_WCE0001
    Sp-->>Sh: Final pipeline output & ExitCode
```

### 11.3 32-Bit Protected-Mode DJGPP + `CWSDPMI` Memory Layout & 16-Bit CPU Guard

Compiling `WINCMD.EXE` and `WINCHECK.EXE` as 32-bit protected-mode COFF images stubbed with `CWSDPMI` solves the classic 640 KiB MS-DOS conventional memory crunch while preserving clean behavior on 16-bit 8086/286 hardware:

```mermaid
flowchart LR
    subgraph Boot["MZ Header & 16-Bit Real-Mode Entry (crates/wincmd-dos/stub/)"]
        MZ["cpu_guard_stub.asm<br/>Check FLAGS bits 12..15"]
        REJECT["8086 / 80186 / 80286:<br/>INT 21h AH=09h 'requires 80386+'<br/>Exit AX=4C01h (Never hangs!)"]
        STUB["80386+: Chain to DJGPP DPMI Stub<br/>Load CWSDPMI.EXE (DPMI 0.9+)"]
        MZ -- "Pre-386" --> REJECT
        MZ -- "386+" --> STUB
    end

    subgraph Conv["Conventional RAM (0 KiB – 640 KiB)"]
        DOS_K["MS-DOS Kernel, Drivers &amp; COMMAND.COM (~45-65 KiB)"]
        DJ_STUB["DJGPP Real-Mode Transfer Buffer &amp; DPMI Stub (~24-40 KiB)"]
        FREE_CONV["~535–570 KiB FREE Conventional Arena!<br/>Available for INT 21h AH=4Bh Child .COM / .EXE Programs"]
    end

    subgraph Ext["Extended XMS / DPMI 32-Bit Flat Memory (&gt; 1 MiB, 4–16+ MiB)"]
        CODE["WINCMD.EXE / WINCHECK.EXE<br/>32-Bit Protected-Mode Code &amp; Rodata (~550–825 KiB)"]
        HEAP["DjgppAllocator Flat 32-Bit Rust Heap<br/>AST, Lossless CST, SourceMap, VFS &amp; Pipe Buffers<br/>Bounded by MemoryProfile (DosCompact4MiB / DosStandard8MiB)"]
    end

    STUB --> DJ_STUB
    STUB --> CODE
    CODE --> HEAP
    DJ_STUB -. "INT 21h AH=4Bh EXEC" .-> FREE_CONV
```
