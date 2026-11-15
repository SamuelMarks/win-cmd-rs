//! Property-based invariant test suite for `win-cmd-rs`.
//!
//! Exercises lexer/expander invariants, Windows path normalization, `SET /A` 32-bit signed
//! integer arithmetic properties, and Win32 `FsRtlIsNameInExpression` wildcard matching
//! across hundreds of generated inputs.

use win_cmd_rs::linter::rewriter::CstRewriter;
use win_cmd_rs::parser::lexer::WordPartsMode;
use win_cmd_rs::parser::lower::lower_cst_to_ast_with_mode;
use win_cmd_rs::parser::peg::{lower_cst_to_ast, parse_script_cst};
use win_cmd_rs::parser::phase1::{Phase1Context, expand_phase1};
use win_cmd_rs::parser::phase2::read_and_parse_next_statement_bytes;
use win_cmd_rs::parser::phase4::expand_phase4;
use win_cmd_rs::reader::char_map::LogicalLineBuffer;
use win_cmd_rs::reader::stream::BatchFrameReader;
use win_cmd_rs::runtime::arithmetic::evaluate_set_a;
use win_cmd_rs::runtime::env::EnvironmentStack;
use win_cmd_rs::runtime::registry::{RegistryDeleteTarget, RegistryStore, RegistryValueType};
use win_cmd_rs::runtime::{Interpreter, IoStreams};
use win_cmd_rs::span::{ByteOffset, SourceId, Span};
use win_cmd_rs::types::{CaseSensitivity, DelayedExpansionMode, DriveLetter, ExecutionContext};
use win_cmd_rs::vfs::glob::matches_win32_glob;
use win_cmd_rs::vfs::path::{generate_short_name_8_3, resolve_windows_path};
use win_cmd_rs::vfs::{InMemoryVfs, VirtualFileSystem};

/// Deterministic `SplitMix64` generator for reproducible property-based fuzzing.
struct PropRng {
    /// Current 64-bit state.
    state: u64,
}

impl PropRng {
    /// Creates a new [`PropRng`] with the given seed.
    ///
    /// # Arguments
    /// * `seed` - Initial 64-bit seed.
    ///
    /// # Returns
    /// Initialized [`PropRng`].
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generates the next pseudorandom `u64`.
    ///
    /// # Returns
    /// Next 64-bit value.
    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Generates a pseudorandom `i32`.
    ///
    /// # Returns
    /// Signed 32-bit integer.
    const fn next_i32(&mut self) -> i32 {
        let [b0, b1, b2, b3, ..] = self.next_u64().to_le_bytes();
        i32::from_le_bytes([b0, b1, b2, b3])
    }

    /// Generates an alphanumeric ASCII string of length `0..=max_len`.
    ///
    /// # Arguments
    /// * `max_len` - Maximum length.
    ///
    /// # Returns
    /// Generated string.
    fn next_ident(&mut self, max_len: usize) -> String {
        let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.- ";
        let len = usize::try_from(self.next_u64())
            .unwrap_or(0)
            .checked_rem(max_len.saturating_add(1))
            .unwrap_or(0);
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            let idx = usize::try_from(self.next_u64())
                .unwrap_or(0)
                .checked_rem(alphabet.len())
                .unwrap_or(0);
            let ch = alphabet.get(idx).copied().unwrap_or(b'a') as char;
            out.push(ch);
        }
        out
    }
}

/// Verifies wrapping 32-bit signed arithmetic commutativity, subtraction, multiplication, and De Morgan's Law.
#[test]
fn prop_set_a_arithmetic_commutativity_and_wrapping() {
    let mut rng = PropRng::new(0x1234_5678_9ABC_DEF0);
    let get = |_: &str| -> Option<String> { None };

    for _ in 0..256 {
        let a = rng.next_i32();
        let b = rng.next_i32();

        // Wrapping addition and multiplication commutativity
        let expr_add_1 = format!("({a}) + ({b})");
        let expr_add_2 = format!("({b}) + ({a})");
        let r1 = evaluate_set_a(&expr_add_1, Span::dummy(), get, |_, _| {});
        let r2 = evaluate_set_a(&expr_add_2, Span::dummy(), get, |_, _| {});
        assert_eq!(r1, Ok(a.wrapping_add(b)));
        assert_eq!(r1, r2);

        let expr_sub = format!("({a}) - ({b})");
        assert_eq!(
            evaluate_set_a(&expr_sub, Span::dummy(), get, |_, _| {}),
            Ok(a.wrapping_sub(b))
        );

        let expr_mul = format!("({a}) * ({b})");
        assert_eq!(
            evaluate_set_a(&expr_mul, Span::dummy(), get, |_, _| {}),
            Ok(a.wrapping_mul(b))
        );

        // Bitwise De Morgan's Law: ~(a & b) == (~a) | (~b)
        let lhs = format!("~(({a}) & ({b}))");
        let rhs = format!("(~({a})) | (~({b}))");
        assert_eq!(
            evaluate_set_a(&lhs, Span::dummy(), get, |_, _| {}),
            evaluate_set_a(&rhs, Span::dummy(), get, |_, _| {})
        );
    }
}

/// Verifies Win32 `FsRtlIsNameInExpression` glob reflexivity, `DOS_DOT` / `DOS_QM` / `DOS_STAR`
/// rules across filenames with spaces, multiple dots, no extension, and 8.3 short names.
#[test]
fn prop_win32_glob_invariants() {
    let mut rng = PropRng::new(0xCAFE_BABE_0000_0001);
    for idx in 1..=256 {
        let raw_stem = rng.next_ident(10).replace('.', "_");
        let stem = if raw_stem.trim().is_empty() {
            "my report".to_owned()
        } else {
            raw_stem.trim().to_owned()
        };
        let raw_ext = rng.next_ident(3).replace(['.', ' '], "x");
        let ext = raw_ext.trim().to_owned();
        let mode = idx % 4;
        let filename = match mode {
            0 => stem,
            1 => format!("{stem} copy.{ext}a"),
            2 => format!("{stem}.tar.{ext}z"),
            _ => format!("{stem}.{ext}b"),
        };
        let short = generate_short_name_8_3(&filename, 1);

        assert!(matches_win32_glob(
            "*",
            &filename,
            Some(&short),
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            "*.*",
            &filename,
            Some(&short),
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            &filename.to_ascii_uppercase(),
            &filename.to_ascii_lowercase(),
            None,
            CaseSensitivity::Insensitive
        ));
        assert!(matches_win32_glob(
            &short,
            &filename,
            Some(&short),
            CaseSensitivity::Insensitive
        ));

        if !filename.contains('.') {
            assert!(matches_win32_glob(
                "*.",
                &filename,
                None,
                CaseSensitivity::Insensitive
            ));
            assert!(matches_win32_glob(
                &format!("{filename}.*"),
                &filename,
                None,
                CaseSensitivity::Insensitive
            ));
            assert!(matches_win32_glob(
                &format!("{filename}.???"),
                &filename,
                None,
                CaseSensitivity::Insensitive
            ));
        } else if let Some((_, last_ext)) = filename.rsplit_once('.') {
            assert!(!matches_win32_glob(
                "*.",
                &filename,
                None,
                CaseSensitivity::Insensitive
            ));
            assert!(matches_win32_glob(
                &format!("*.{last_ext}"),
                &filename,
                None,
                CaseSensitivity::Insensitive
            ));
        }
    }

    let adv_pat = format!("{}z", "*a".repeat(32));
    let adv_name = "a".repeat(255);
    let t0 = std::time::Instant::now();
    assert!(!matches_win32_glob(
        &adv_pat,
        &adv_name,
        None,
        CaseSensitivity::Insensitive
    ));
    assert!(t0.elapsed().as_micros() < 10_000);
}

/// Verifies Windows path normalization idempotence, case-insensitive `Eq`/`Ord`/`Hash`, and 8.3 short names.
#[test]
fn prop_path_normalization_and_short_names_idempotence() {
    use std::collections::HashSet;

    let mut rng = PropRng::new(0xFEED_FACE_1111_2222);
    let cwd_lookup = |_: DriveLetter| vec!["Users".to_owned(), "Sam".to_owned()];

    for idx in 1..=128 {
        let seg1 = rng.next_ident(12).replace(' ', "_");
        let seg2 = rng.next_ident(12).replace(' ', "_");
        let raw_path = format!("C:/{seg1}/./{seg2}/../{seg1}...");
        let resolved1 = resolve_windows_path(&raw_path, DriveLetter::C, cwd_lookup);
        let resolved2 =
            resolve_windows_path(&resolved1.to_windows_string(), DriveLetter::C, cwd_lookup);
        assert_eq!(resolved1, resolved2);

        // Case-insensitivity across Eq, Ord, and Hash
        let upper_raw = raw_path.to_ascii_uppercase();
        let lower_raw = raw_path.to_ascii_lowercase();
        let res_up = resolve_windows_path(&upper_raw, DriveLetter::C, cwd_lookup);
        let res_lo = resolve_windows_path(&lower_raw, DriveLetter::C, cwd_lookup);
        assert_eq!(res_up, res_lo);
        assert_eq!(res_up.cmp(&res_lo), std::cmp::Ordering::Equal);
        let mut set = HashSet::new();
        set.insert(res_up);
        assert!(set.contains(&res_lo));

        let short = generate_short_name_8_3(&format!("{seg1}.{seg2}"), idx);
        assert!(!short.contains(' '));
        assert!(short.len() <= 12);
    }
}

/// Verifies Phase 1 (`%VAR%`, `%~dpnx1`, `%VAR:~s,l%`, `%VAR:a=b%`, `%%` escaping) and Phase 4
/// (`!VAR!`, `^` escaping, no-`!` no-op) expansion invariants across generated inputs.
#[test]
fn prop_phase1_and_phase4_expansion_invariants() {
    let mut rng = PropRng::new(0xABCD_EF01_2345_6789);
    let mut vfs = InMemoryVfs::new();
    assert_eq!(
        vfs.create_dir(
            "C:/Tools",
            win_cmd_rs::types::DirCreationDepth::CreateParents
        ),
        Ok(())
    );
    assert_eq!(vfs.write_bytes("C:/Tools/build.cmd", b"@echo off"), Ok(()));

    for step in 0..128 {
        let base_val = format!("alpha_{step}_beta");
        let lookup = |k: &str| match k.to_ascii_uppercase().as_str() {
            "V" => Some(base_val.clone()),
            _ => None,
        };
        let pos_args = vec![r#""C:\Tools\build.cmd""#.to_owned()];
        let p1_ctx = Phase1Context {
            exec_context: ExecutionContext::BatchFile,
            arg0: "test.bat",
            positional_args: &pos_args,
            all_args_raw: r#""C:\Tools\build.cmd""#,
            vfs: &vfs,
            env_lookup: lookup,
        };

        // 1. Doubling `%` in any string with `%` literals collapses back to exact original in BatchFile Phase 1!
        let raw_with_pct = format!("{}%{}%", rng.next_ident(6), rng.next_ident(6));
        let doubled = raw_with_pct.replace('%', "%%");
        let d_line = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), &doubled);
        assert_eq!(
            expand_phase1(&d_line, &p1_ctx).map(|b| b.to_plain_string()),
            Ok(raw_with_pct)
        );

        // 2. Real `%V%`, `%V:~0,5%`, `%V:beta=omega%`, and `%~dpnx1` expansion
        let expr_line = LogicalLineBuffer::from_str_at(
            SourceId(0),
            ByteOffset(0),
            "%V%|%V:~0,5%|%V:beta=omega%|%~dpnx1",
        );
        let expected_p1 = format!("{base_val}|alpha|alpha_{step}_omega|C:\\Tools\\build.cmd");
        assert_eq!(
            expand_phase1(&expr_line, &p1_ctx).map(|b| b.to_plain_string()),
            Ok(expected_p1)
        );

        // 3. Phase 4 is a strict no-op when no `!` exists on the line (even with `^` carets!)
        let caret_no_bang = format!("echo a^&b ^{}", rng.next_ident(8).replace('!', "_"));
        let c_line = LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), &caret_no_bang);
        assert_eq!(
            expand_phase4(&c_line, DelayedExpansionMode::Enabled, lookup).to_plain_string(),
            caret_no_bang
        );

        // 4. Phase 4 expands `!V:~0,5!` and `!V:alpha=GAMMA!` when `!` is present
        let bang_line =
            LogicalLineBuffer::from_str_at(SourceId(0), ByteOffset(0), "!V:~0,5!:!V:alpha=GAMMA!");
        assert_eq!(
            expand_phase4(&bang_line, DelayedExpansionMode::Enabled, lookup).to_plain_string(),
            format!("alpha:GAMMA_{step}_beta")
        );
    }
}

/// Verifies 100% lossless `parse_script_cst` source round-tripping across arbitrary generated fragments.
#[test]
fn prop_peg_cst_lossless_roundtrip() {
    let mut rng = PropRng::new(0x9988_7766_5544_3322);
    let fragments = [
        "@echo off\r\n",
        "echo ",
        "%VAR%",
        "!DELAYED!",
        "%1",
        "%~dp0",
        "%%I",
        "\"quoted string\"",
        "\"unclosed quote",
        "if ",
        "==",
        " = ",
        " (echo a) else (echo b)\r\n",
        "for %%I in (a b) do echo %%I\r\n",
        "for %i (x y) echo %i\n",
        " & ",
        " && ",
        " || ",
        " | ",
        " > out.txt",
        " 2>&1",
        " ^\r\n",
        " ^   \r\n",
        ":: comment\r\n",
        "REM remark\n",
        ":label\r\n",
        "(\r\necho block\r\n)\r\n",
        ") stray\n",
        "%~dpBAD%\n",
    ];

    for step in 0..300 {
        let count = usize::try_from(rng.next_u64())
            .unwrap_or(1)
            .checked_rem(8)
            .unwrap_or(1)
            .saturating_add(1);
        let mut script = if step % 10 == 0 {
            "\u{FEFF}".to_owned()
        } else {
            String::new()
        };
        for _ in 0..count {
            let idx = usize::try_from(rng.next_u64())
                .unwrap_or(0)
                .checked_rem(fragments.len())
                .unwrap_or(0);
            script.push_str(fragments.get(idx).copied().unwrap_or("echo ok\r\n"));
            if step % 3 == 0 {
                script.push_str(&rng.next_ident(6));
            }
        }

        for mode in [
            ExecutionContext::BatchFile,
            ExecutionContext::InteractiveRepl,
        ] {
            let cst = parse_script_cst(SourceId(0), &script, mode);
            assert_eq!(
                cst.to_source_string(),
                script,
                "Lossless CST round-trip invariant violated at step {step} ({mode}):\n{script:?}"
            );
        }

        // Also check CST-to-AST equivalence on well-formed single-line scripts
        let wf = format!(
            "@echo off\r\nset \"A=1\"\r\necho {}\r\n",
            rng.next_ident(8).trim()
        );
        let cst_wf = parse_script_cst(SourceId(0), &wf, ExecutionContext::BatchFile);
        if !cst_wf.has_syntax_errors() {
            let mut rdr = BatchFrameReader::new(SourceId(0));
            let mut rt_stmts = Vec::new();
            let mut rt_labels = Vec::new();
            let mut rt_carets = Vec::new();
            let mut ok = true;
            loop {
                match read_and_parse_next_statement_bytes(
                    &mut rdr,
                    wf.as_bytes(),
                    win_cmd_rs::types::CodePage::Utf8,
                    &mut rt_labels,
                    &mut rt_carets,
                    &mut |l| Ok(l.clone()),
                ) {
                    Ok(Some(s)) => rt_stmts.push(s),
                    Ok(None) => break,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                let lowered_ast = lower_cst_to_ast(&cst_wf);
                assert_eq!(lowered_ast.statements.len(), rt_stmts.len());
            }
        }
    }
}

/// Verifies `CstRewriter` validity (zero syntax errors after rewrite) and idempotence (`R(R(x)) == R(x)`).
#[test]
fn prop_cst_rewriter_idempotence_and_validity() {
    let mut rng = PropRng::new(0x1357_9BDF_2468_ACE0);
    let templates = [
        "cd %USERPROFILE%\\sub",
        "copy %1 %2",
        "echo \"%1\"",
        "if %A% = 1 echo yes else echo no",
        "if (%B% == 2) echo ok",
        "for %i in (*.txt) do del %i & echo 50%",
        "for %%I in (*.log) do copy %%I %%~nI.bak & echo 100%%",
        "for %%a (1 2) echo %%a",
        "set X = 123   ",
        "set Y=val   ",
        "set Z=a^&b",
        "(\r\n  :: block comment\r\n  set C=1\r\n  echo %C% %ERRORLEVEL%\r\n)",
        "cd D:\\work",
        "sub.bat arg1",
        "exit 0",
    ];

    for _ in 0..256 {
        let line_count = usize::try_from(rng.next_u64())
            .unwrap_or(1)
            .checked_rem(5)
            .unwrap_or(1)
            .saturating_add(1);
        let mut lines = Vec::with_capacity(line_count);
        for _ in 0..line_count {
            let idx = usize::try_from(rng.next_u64())
                .unwrap_or(0)
                .checked_rem(templates.len())
                .unwrap_or(0);
            lines.push(*templates.get(idx).unwrap_or(&"echo ok"));
        }
        let script = lines.join("\r\n");

        for mode in [
            ExecutionContext::BatchFile,
            ExecutionContext::InteractiveRepl,
        ] {
            let rewriter = CstRewriter::default_for_context(mode);
            let cst1 = parse_script_cst(SourceId(0), &script, mode);
            let out1 = rewriter.rewrite(&cst1);

            let cst2 = parse_script_cst(SourceId(0), &out1.rewritten_source, mode);
            assert!(
                !cst2.has_syntax_errors(),
                "Rewritten script produced syntax/misuse errors in mode {mode}:\n{}\nDiagnostics: {:?}",
                out1.rewritten_source,
                cst2.diagnostics
            );

            let out2 = rewriter.rewrite(&cst2);
            assert_eq!(
                out1.rewritten_source, out2.rewritten_source,
                "CstRewriter was not idempotent in mode {mode}:\nPass 1:\n{}\nPass 2:\n{}",
                out1.rewritten_source, out2.rewritten_source
            );
            assert_eq!(out2.applied_count, 0);
        }
    }
}

/// Verifies differential equivalence between `parse_script_cst` + `lower_cst_to_ast` and
/// the canonical runtime byte-offset statement reader (`read_and_parse_next_statement_bytes`)
/// across 200 generated multi-statement batch scripts, including multi-line quoted strings
/// with `^` continuations and inline `REM` comments inside `( ... )` blocks.
#[test]
fn prop_differential_cst_lower_vs_phase2_ast_equivalence() {
    let mut rng = PropRng::new(0x2026_1114_A1B2_C3D4);
    let crlf = win_cmd_rs::types::CRLF;
    let quoted_cont_blk = format!(
        "({crlf}  echo \"hello^{crlf}\" & echo after_quote{crlf}  echo a & rem unclosed ( here{crlf})"
    );
    let empty_cont_blk = format!("({crlf}  echo line1 ^{crlf}{crlf}  echo line2{crlf})");
    let stmt_pool = [
        "@echo off",
        ":lbl_alpha",
        ":: double colon header",
        "rem comment body",
        r#"set "VAR_A=hello""#,
        "set /a NUM=10+20 & echo !NUM!",
        "echo(inside_echo_paren",
        "( echo(in_block & echo second )",
        r#"if /i "%VAR_A%"=="hello" (echo match) else (echo miss)"#,
        "if errorlevel 0x04 echo ge4",
        "for /L %%N in (1,1,3) do echo %%N",
        r#"for /F "tokens=1" %%A in ("item") do echo %%A"#,
        r#"echo left | find "left" && echo ok || echo fail"#,
        quoted_cont_blk.as_str(),
        empty_cont_blk.as_str(),
    ];

    for step in 0..200 {
        let n = usize::try_from(rng.next_u64())
            .unwrap_or(1)
            .checked_rem(6)
            .unwrap_or(1)
            .saturating_add(1);
        let mut lines = Vec::with_capacity(n);
        for _ in 0..n {
            let idx = usize::try_from(rng.next_u64())
                .unwrap_or(0)
                .checked_rem(stmt_pool.len())
                .unwrap_or(0);
            lines.push(*stmt_pool.get(idx).unwrap_or(&"@echo off"));
        }
        let script = format!("{}{crlf}", lines.join(crlf));

        let cst = parse_script_cst(SourceId(0), &script, ExecutionContext::BatchFile);
        assert_eq!(cst.to_source_string(), script, "step {step} lossless check");
        assert!(
            !cst.has_syntax_errors(),
            "step {step} unexpected CST syntax error: {:?}",
            cst.diagnostics
        );

        let lowered_light = lower_cst_to_ast_with_mode(&cst, WordPartsMode::Lightweight);
        let lowered = lower_cst_to_ast(&cst);

        let mut rdr = BatchFrameReader::new(SourceId(0));
        let mut rt_stmts = Vec::new();
        let mut rt_labels = Vec::new();
        let mut rt_carets = Vec::new();
        while let Some(stmt) = read_and_parse_next_statement_bytes(
            &mut rdr,
            script.as_bytes(),
            win_cmd_rs::types::CodePage::Utf8,
            &mut rt_labels,
            &mut rt_carets,
            &mut |l| Ok(l.clone()),
        )
        .unwrap_or_else(|err| {
            assert_eq!(err.to_string(), "", "step {step} runtime parse failed");
            None
        }) {
            rt_stmts.push(stmt);
        }

        assert_eq!(
            lowered_light.statements.len(),
            rt_stmts.len(),
            "step {step} statement count mismatch"
        );
        assert_eq!(lowered.statements.len(), rt_stmts.len());
        assert_eq!(lowered_light.labels, rt_labels);
        assert_eq!(lowered.labels, rt_labels);

        if step < 25 {
            let snap1 = run_hermetic_batch(&script);
            let snap2 = run_hermetic_batch(&script);
            assert_eq!(snap1, snap2);
        }
    }
}

/// Verifies case-insensitivity invariants across `EnvironmentStack`, `RegistryStore`, and `InMemoryVfs`.
#[test]
fn prop_case_insensitivity_env_registry_and_vfs() {
    let mut rng = PropRng::new(0x55AA_77CC_99EE_1133);
    let mut env = EnvironmentStack::new();
    let mut reg = RegistryStore::new();
    let mut vfs = InMemoryVfs::new();
    assert_eq!(
        vfs.create_dir(
            "C:/PropCi",
            win_cmd_rs::types::DirCreationDepth::CreateParents
        ),
        Ok(())
    );

    for idx in 0..128 {
        let raw = rng
            .next_ident(10)
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>();
        let key = if raw.is_empty() {
            format!("Key_{idx}")
        } else {
            format!("K{idx}_{raw}")
        };
        let upper = key.to_ascii_uppercase();
        let lower = key.to_ascii_lowercase();
        let val = format!("val_{idx}");

        env.set(&upper, &val);
        assert_eq!(
            env.get_with_dynamics(&lower, "C:/", win_cmd_rs::types::ExitCode::SUCCESS),
            Some(val.clone())
        );
        env.remove(&lower);
        assert_eq!(
            env.get_with_dynamics(&upper, "C:/", win_cmd_rs::types::ExitCode::SUCCESS),
            None
        );

        let reg_path = format!("HKCU/Software/PropTest/{upper}");
        let reg_path_lo = format!("hkcu/software/proptest/{lower}");
        assert_eq!(
            reg.set_value(&reg_path, &upper, RegistryValueType::Sz, &val),
            Ok(())
        );
        assert_eq!(
            reg.get_value(&reg_path_lo, &lower).map(|v| v.data.as_str()),
            Some(val.as_str())
        );
        assert!(reg.delete_entry(&reg_path_lo, RegistryDeleteTarget::Value(&lower)));
        assert_eq!(reg.get_value(&reg_path, &upper), None);

        let file_up = format!("C:/PROPCI/{upper}.TXT");
        let file_lo = format!("c:/propci/{lower}.txt");
        assert_eq!(vfs.write_bytes(&file_up, val.as_bytes()), Ok(()));
        assert!(vfs.exists(&file_lo));
        assert_eq!(vfs.read_bytes(&file_lo), Ok(val.as_bytes().to_vec()));
        assert_eq!(
            vfs.delete_file(
                &file_lo,
                win_cmd_rs::types::ReadOnlyDeletePolicy::ForceDeleteReadOnly
            ),
            Ok(())
        );
        assert!(!vfs.exists(&file_up));
    }
}

/// Observable state snapshot after running a batch script on a hermetic [`Interpreter`].
#[derive(Debug, PartialEq, Eq)]
struct HermeticRunSnapshot {
    /// Final integer exit status.
    exit_code: i32,
    /// Captured `stdout` text.
    stdout: String,
    /// Captured `stderr` text.
    stderr: String,
    /// Sorted `(VAR_NAME, value)` pairs for `P_*` test variables.
    vars: Vec<(String, String)>,
    /// Optional bytes written to `C:/WorkDir/out.txt`.
    out_file: Option<Vec<u8>>,
}

/// Executes a batch script on a fresh hermetic `Interpreter` and returns a [`HermeticRunSnapshot`].
///
/// # Arguments
/// * `script` - Batch script source text to execute.
///
/// # Returns
/// Captured [`HermeticRunSnapshot`] containing exit code, stdout, stderr, variables, and output file bytes.
fn run_hermetic_batch(script: &str) -> HermeticRunSnapshot {
    let mut interp = Interpreter::new();
    assert_eq!(
        interp.proc_env.vfs.create_dir(
            "C:/WorkDir",
            win_cmd_rs::types::DirCreationDepth::CreateParents
        ),
        Ok(())
    );
    assert_eq!(
        interp
            .proc_env
            .vfs
            .write_bytes("C:/WorkDir/in.txt", b"seed"),
        Ok(())
    );
    assert_eq!(
        interp
            .proc_env
            .vfs
            .write_bytes("C:/WorkDir/my in.txt", b"spaced_seed"),
        Ok(())
    );
    assert_eq!(
        interp
            .proc_env
            .vfs
            .write_bytes("C:/run.bat", script.as_bytes()),
        Ok(())
    );
    let mut io = IoStreams::new();
    let exit_code = interp
        .execute_batch_file(
            "C:/run.bat",
            "run.bat",
            vec!["arg_one".to_owned()],
            "arg_one".to_owned(),
            &mut io,
        )
        .map_or(-1, |c| c.0);
    let vars: Vec<(String, String)> = interp
        .proc_env
        .env
        .list_visible()
        .into_iter()
        .filter(|(k, _)| k.starts_with("P_"))
        .map(|(k, v)| (k.to_ascii_uppercase(), v.to_owned()))
        .collect();
    let out_file = interp.proc_env.vfs.read_bytes("C:/WorkDir/out.txt").ok();
    HermeticRunSnapshot {
        exit_code,
        stdout: io.stdout,
        stderr: io.stderr,
        vars,
        out_file,
    }
}

/// Suite 1 (Semantics-Preserving Equivalence): Exercises templates that genuinely trigger
/// `FixApplicability::SafeSemanticsPreserving` rewrites (`SET P_Z=a^&b`, `::` inside blocks,
/// quoting `%P_SRC%` / `%1`, `IF %P_A%==alpha`, and `%` <-> `%%` dialect round-trips) and asserts
/// 100% identical `HermeticRunSnapshot` before and after rewriting!
#[test]
fn prop_semantics_preserving_cst_rewriter_equivalence() {
    let mut rng = PropRng::new(0x7777_8888_9999_AAAA);
    let crlf = win_cmd_rs::types::CRLF;
    let blk_stmt = format!("({crlf}  :: comment_in_blk{crlf}  echo %P_B%{crlf})");
    let statements = [
        "set P_Z=a^&b",
        "if %P_A%==init echo matched_init",
        blk_stmt.as_str(),
        r#"copy /y "%1" C:/WorkDir/out.txt > NUL"#,
        "copy /y %P_PLAIN% C:/WorkDir/out.txt > NUL",
        "for %%I in (x y) do echo %%I",
    ];

    let sem_rewriter = CstRewriter::semantics_preserving_for_context(ExecutionContext::BatchFile);
    let repl_rewriter =
        CstRewriter::semantics_preserving_for_context(ExecutionContext::InteractiveRepl);
    let mut total_rewrites_applied = 0usize;

    for step in 0..100 {
        let mut lines = vec![
            "@echo off",
            "set P_A=init",
            "set P_B=7",
            "set P_PLAIN=C:/WorkDir/in.txt",
        ];
        let count = usize::try_from(rng.next_u64())
            .unwrap_or(1)
            .checked_rem(5)
            .unwrap_or(1)
            .saturating_add(1);
        for _ in 0..count {
            let idx = usize::try_from(rng.next_u64())
                .unwrap_or(0)
                .checked_rem(statements.len())
                .unwrap_or(0);
            lines.push(*statements.get(idx).unwrap_or(&"set P_Z=a^&b"));
        }
        let orig_script = format!("{}{crlf}", lines.join(crlf));
        let cst = parse_script_cst(SourceId(0), &orig_script, ExecutionContext::BatchFile);
        let outcome = sem_rewriter.rewrite(&cst);
        total_rewrites_applied = total_rewrites_applied.saturating_add(outcome.applied_count);

        let res_orig = run_hermetic_batch(&orig_script);
        let res_rewr = run_hermetic_batch(&outcome.rewritten_source);
        assert_eq!(
            res_orig, res_rewr,
            "SafeSemanticsPreserving CstRewriter diverged at step {step}!\nOriginal:\n{orig_script}\nRewritten:\n{}",
            outcome.rewritten_source
        );

        // Dialect round-trip (`BatchFile -> InteractiveRepl -> BatchFile`) on `FOR` statements preserves semantics!
        if step < 20 {
            let for_script = format!("@echo off{crlf}for %%I in (u v) do echo %%I 100%%{crlf}");
            let cst_b = parse_script_cst(SourceId(0), &for_script, ExecutionContext::BatchFile);
            let repl_src = repl_rewriter.rewrite(&cst_b).rewritten_source;
            assert!(repl_src.contains("for %I in (u v) do echo %I 100%"));
            let cst_r = parse_script_cst(SourceId(0), &repl_src, ExecutionContext::InteractiveRepl);
            let roundtrip_batch = sem_rewriter.rewrite(&cst_r).rewritten_source;
            assert_eq!(
                run_hermetic_batch(&for_script),
                run_hermetic_batch(&roundtrip_batch)
            );
        }
    }
    assert!(
        total_rewrites_applied > 100,
        "Expected semantics-preserving suite to trigger >100 real CST edits"
    );
}

/// Suite 2 (Bug-Repair Postcondition Suite): Exercises templates triggering `RecommendedRepair`
/// passes (`set P_X = 1  `, `(set P_C=1 & echo %P_C%)`, `cd D:/work`, `C:/sub.bat`, `if %P_X% = 1 echo eq_ok`)
/// and asserts that the rewritten script achieves every intended postcondition and lints cleanly!
#[test]
fn prop_bug_repair_cst_rewriter_postconditions() {
    let mut rng = PropRng::new(0x1357_9BDF_2468_ACE0);
    let crlf = win_cmd_rs::types::CRLF;
    let repair_rewriter = CstRewriter::safe_for_context(ExecutionContext::BatchFile);

    for step in 0..40 {
        let num = (rng.next_u64() % 9) + 1;
        let buggy_script = [
            "@echo off",
            "set \"P_FROM_SUB=no\"",
            &format!("set P_X = {num}   "),
            &format!("({crlf}  set \"P_C={num}\"{crlf}  echo LIVE:!P_C!_%P_C%{crlf})"),
            "cd D:/work",
            "C:/sub.bat",
            &format!("echo AFTER_SUB_{step}"),
            &format!(r#"if "%P_X%" = "{num}" echo EQ_OK_{num}"#),
            "echo FINAL:[%P_X%][%P_C%][%P_FROM_SUB%][%CD%]",
        ]
        .join(crlf)
            + crlf;

        let cst = parse_script_cst(SourceId(0), &buggy_script, ExecutionContext::BatchFile);
        let outcome = repair_rewriter.rewrite(&cst);
        assert!(outcome.applied_count >= 5);

        let mut vfs = InMemoryVfs::new();
        vfs.mount_empty_drive(DriveLetter::D, "DATA", "D1D2-D3D4");
        assert_eq!(
            vfs.create_dir(
                "D:/work",
                win_cmd_rs::types::DirCreationDepth::CreateParents
            ),
            Ok(())
        );
        assert_eq!(
            vfs.write_bytes(
                "C:/sub.bat",
                format!("@echo off{crlf}set \"P_FROM_SUB=yes\"{crlf}").as_bytes()
            ),
            Ok(())
        );
        assert_eq!(
            vfs.write_bytes("C:/main.bat", outcome.rewritten_source.as_bytes()),
            Ok(())
        );

        let mut interp = Interpreter::with_vfs(Box::new(vfs));
        let mut io = IoStreams::new();
        let code = interp.execute_batch_file(
            "C:/main.bat",
            "main.bat",
            Vec::new(),
            String::new(),
            &mut io,
        );
        assert_eq!(code, Ok(win_cmd_rs::types::ExitCode::SUCCESS));
        assert!(
            io.stdout
                .contains(&format!("FINAL:[{num}][{num}][yes][D:\\work]")),
            "Unexpected stdout:\n{}",
            io.stdout
        );
        assert!(io.stdout.contains(&format!("LIVE:{num}_{num}")));
        assert!(io.stdout.contains(&format!("AFTER_SUB_{step}")));
        assert!(io.stdout.contains(&format!("EQ_OK_{num}")));
        // Injected `SETLOCAL EnableDelayedExpansion` scopes mutations cleanly inside `main.bat`.
        assert_eq!(interp.lookup_var("P_X"), None);
        assert_eq!(interp.proc_env.vfs.current_drive(), DriveLetter::C);

        let mut sm = win_cmd_rs::span::SourceMap::new();
        let lint_cfg = win_cmd_rs::linter::LinterConfig {
            min_severity: win_cmd_rs::linter::Severity::Warning,
            ..win_cmd_rs::linter::LinterConfig::default()
        };
        let (_, rem_diags) = win_cmd_rs::linter::lint_script(
            "main.bat",
            outcome.rewritten_source.as_bytes(),
            &lint_cfg,
            &mut sm,
        )
        .unwrap_or_default();
        assert_eq!(
            rem_diags,
            Vec::new(),
            "Expected zero remaining warnings/errors on repaired script:\n{}",
            outcome.rewritten_source
        );
    }
}
