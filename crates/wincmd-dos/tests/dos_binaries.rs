//! Integration tests verifying the `wincmd` (`WINCMD.EXE`) and `wincheck` (`WINCHECK.EXE`)
//! binaries and the `stub/djgpp-linker.sh` COFF linker driver inside `crates/wincmd-dos`.

use std::process::Command;

/// Verifies `wincmd /C ver` and `wincheck --explain CMD5001` exit with status `0`.
#[test]
fn test_wincmd_dos_and_wincheck_dos_binaries() {
    let wincmd_out = Command::new(env!("CARGO_BIN_EXE_wincmd"))
        .args(["/C", "ver"])
        .output();
    assert!(wincmd_out.is_ok());
    if let Ok(out) = wincmd_out {
        assert_eq!(out.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&out.stdout).contains("MS-DOS"));
    }

    let wincheck_out = Command::new(env!("CARGO_BIN_EXE_wincheck"))
        .args(["--explain", "CMD5001"])
        .output();
    assert!(wincheck_out.is_ok());
    if let Ok(out) = wincheck_out {
        assert_eq!(out.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&out.stdout).contains("CMD5001"));
    }
}

/// Formats a deterministic 60-byte GNU `ar` member header for test archive fixtures.
///
/// # Arguments
/// * `name` - Archive member name field (up to 16 ASCII bytes).
/// * `size` - Member payload byte length.
///
/// # Returns
/// Exact 60-byte `ar` member header ending with `` `\n ``.
#[cfg(unix)]
#[must_use]
fn build_ar_member_header(name: &[u8], size: usize) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(60);
    for idx in 0..16usize {
        hdr.push(name.get(idx).copied().unwrap_or(b' '));
    }
    hdr.extend_from_slice(b"0           0     0     644     ");
    let size_text = size.to_string();
    for idx in 0..10usize {
        hdr.push(size_text.as_bytes().get(idx).copied().unwrap_or(b' '));
    }
    hdr.extend_from_slice(&[0x60, 0x0A]);
    hdr
}

/// Builds a minimal LLVM PE-COFF (`i386`, `@feat.00`) object defining `_rust_ext` in `.text`.
///
/// # Returns
/// Raw COFF object bytes suitable for exercising `djgpp-linker.sh` PE-to-`coff-go32` normalization.
#[cfg(unix)]
#[must_use]
fn build_synthetic_pe_coff_object() -> Vec<u8> {
    // 20-byte COFF header + 40-byte `.text` section header + 4-byte `.text` body +
    // 2 * 18-byte symbol table (`@feat.00` + `_rust_ext`) + 14-byte string table (`_rust_ext\0`).
    let symptr = 64u32;
    let nsyms = 2u32;
    let mut obj = Vec::with_capacity(114);
    obj.extend_from_slice(&0x014Cu16.to_le_bytes()); // Machine: IMAGE_FILE_MACHINE_I386
    obj.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections: 1
    obj.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    obj.extend_from_slice(&symptr.to_le_bytes()); // PointerToSymbolTable
    obj.extend_from_slice(&nsyms.to_le_bytes()); // NumberOfSymbols
    obj.extend_from_slice(&0u16.to_le_bytes()); // SizeOfOptionalHeader
    obj.extend_from_slice(&0u16.to_le_bytes()); // Characteristics

    // Section 1: `.text` at file offset 60, size 4.
    obj.extend_from_slice(b".text\0\0\0");
    obj.extend_from_slice(&0u32.to_le_bytes()); // VirtualSize
    obj.extend_from_slice(&0u32.to_le_bytes()); // VirtualAddress
    obj.extend_from_slice(&4u32.to_le_bytes()); // SizeOfRawData
    obj.extend_from_slice(&60u32.to_le_bytes()); // PointerToRawData
    obj.extend_from_slice(&0u32.to_le_bytes()); // PointerToRelocations
    obj.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
    obj.extend_from_slice(&0u16.to_le_bytes()); // NumberOfRelocations
    obj.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
    obj.extend_from_slice(&0x6000_0020u32.to_le_bytes()); // Characteristics

    // 4-byte `.text` body (`ret` + padding).
    obj.extend_from_slice(&[0xC3, 0x90, 0x90, 0x90]);

    // Symbol 0: `@feat.00` (`N_ABS = -1`, `C_STAT = 3`) marking LLVM PE-COFF output.
    obj.extend_from_slice(b"@feat.00");
    obj.extend_from_slice(&1u32.to_le_bytes());
    obj.extend_from_slice(&(-1i16).to_le_bytes());
    obj.extend_from_slice(&0u16.to_le_bytes());
    obj.extend_from_slice(&[3u8, 0u8]);

    // Symbol 1: long-name offset `4` -> `_rust_ext` (`scnum = 1`, `C_EXT = 2`).
    obj.extend_from_slice(&0u32.to_le_bytes());
    obj.extend_from_slice(&4u32.to_le_bytes());
    obj.extend_from_slice(&0u32.to_le_bytes());
    obj.extend_from_slice(&1i16.to_le_bytes());
    obj.extend_from_slice(&0u16.to_le_bytes());
    obj.extend_from_slice(&[2u8, 0u8]);

    // COFF string table: 4-byte total size (`14`) + `"_rust_ext\0"`.
    let strtab_body = b"_rust_ext\0";
    let strtab_len = 14u32;
    obj.extend_from_slice(&strtab_len.to_le_bytes());
    obj.extend_from_slice(strtab_body);
    obj
}

/// Verifies `stub/djgpp-linker.sh` normalizes LLVM PE-COFF `.rlib` archives into GNU `coff-go32`
/// archives (with `/` big-endian symbol maps and `.rmeta` stripped), strips PE-only ld flags, and
/// splices the 16-bit 8086/80286 CPU guard stub even when `i586-pc-msdosdjgpp-ar` exits `127`
/// (reproducing Ubuntu 26.04 runners without `libfl.so.2`).
#[cfg(unix)]
#[test]
fn test_djgpp_linker_normalizes_pe_rlib_without_external_ar() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use wincmd_dos::stub_verify::validate_mz_cpu_guard_stub;

    let work_dir =
        std::env::temp_dir().join(format!("wincmd_djgpp_linker_test_{}", std::process::id()));
    let poison_bin = work_dir.join("poison_bin");
    assert!(fs::create_dir_all(&poison_bin).is_ok());

    // Poison `i586-pc-msdosdjgpp-ar` on PATH to simulate missing `libfl.so.2` (exit status 127).
    let poison_ar = poison_bin.join("i586-pc-msdosdjgpp-ar");
    assert!(fs::write(&poison_ar, b"#!/usr/bin/env sh\nexit 127\n").is_ok());
    assert!(fs::set_permissions(&poison_ar, fs::Permissions::from_mode(0o755)).is_ok());

    // Build a synthetic `.rlib` containing `lib.rmeta` + our PE-COFF object member.
    let coff_obj = build_synthetic_pe_coff_object();
    let rmeta = b"rmeta_payload!";
    let mut rlib_bytes = Vec::from(b"!<arch>\n".as_slice());
    rlib_bytes.extend_from_slice(&build_ar_member_header(b"lib.rmeta/", rmeta.len()));
    rlib_bytes.extend_from_slice(rmeta);
    if (rmeta.len() & 1) == 1 {
        rlib_bytes.push(b'\n');
    }
    rlib_bytes.extend_from_slice(&build_ar_member_header(b"builtins.o/", coff_obj.len()));
    rlib_bytes.extend_from_slice(&coff_obj);
    if (coff_obj.len() & 1) == 1 {
        rlib_bytes.push(b'\n');
    }
    let rlib_path = work_dir.join("libcompiler_builtins.rlib");
    assert!(fs::write(&rlib_path, &rlib_bytes).is_ok());

    // Mock `DJGPP_GCC` verifying the normalized archive's `/` symbol map and writing a `go32stub` `.EXE`.
    let mock_gcc = work_dir.join("mock_djgpp_gcc.py");
    let mock_gcc_src = concat!(
        "#!/usr/bin/env python3\n",
        "import struct, sys\n",
        "args = sys.argv[1:]\n",
        "assert '-Wl,--nxcompat' not in args and '-Wl,--gc-sections' not in args\n",
        "rlibs = [a for a in args if a.endswith('.rlib')]\n",
        "assert len(rlibs) == 1\n",
        "ar = open(rlibs[0], 'rb').read()\n",
        "assert ar.startswith(b'!<arch>\\n')\n",
        "assert b'rmeta_payload!' not in ar\n",
        "hdr = ar[8:68]\n",
        "assert hdr[:16] == b'/               '\n",
        "sz = int(hdr[48:58].strip())\n",
        "body = ar[68:68 + sz]\n",
        "nsyms = struct.unpack_from('>I', body, 0)[0]\n",
        "assert nsyms == 1\n",
        "m_off = struct.unpack_from('>I', body, 4)[0]\n",
        "assert ar[m_off:m_off + 11] == b'm0000000.o/'\n",
        "assert body[8:].startswith(b'_rust_ext\\x00')\n",
        "out_exe = args[args.index('-o') + 1]\n",
        "stub = bytearray(2560)\n",
        "stub[0:2] = b'MZ'\n",
        "struct.pack_into('<HH', stub, 2, 0, 4)\n",
        "struct.pack_into('<H', stub, 8, 32)\n",
        "struct.pack_into('<HH', stub, 20, 0x00A8, 0)\n",
        "stub[512:520] = b'go32stub'\n",
        "open(out_exe, 'wb').write(stub)\n",
    );
    assert!(fs::write(&mock_gcc, mock_gcc_src.as_bytes()).is_ok());
    assert!(fs::set_permissions(&mock_gcc, fs::Permissions::from_mode(0o755)).is_ok());

    let out_exe = work_dir.join("wincmd.exe");
    let rsp_file = work_dir.join("link.rsp");
    let rsp_content = format!(
        "-Wl,--nxcompat -Wl,--gc-sections \"{}\" -o \"{}\"\n",
        rlib_path.display(),
        out_exe.display()
    );
    assert!(fs::write(&rsp_file, rsp_content.as_bytes()).is_ok());

    let linker_sh = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("stub")
        .join("djgpp-linker.sh");
    let old_path = std::env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{old_path}", poison_bin.display());

    let status = Command::new(&linker_sh)
        .arg(format!("@{}", rsp_file.display()))
        .env("DJGPP_GCC", &mock_gcc)
        .env("PATH", combined_path)
        .output();
    assert!(status.is_ok());
    if let Ok(out) = status {
        assert_eq!(
            out.status.code(),
            Some(0),
            "djgpp-linker.sh stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let patched_exe = fs::read(&out_exe).unwrap_or_default();
    assert_eq!(patched_exe.len(), 3584);
    assert!(validate_mz_cpu_guard_stub(&patched_exe));
    assert!(fs::remove_dir_all(&work_dir).is_ok());
}
