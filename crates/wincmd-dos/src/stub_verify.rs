//! Assembled 16-bit Real-Mode 8086/80286 CPU Guard MZ Stub & Verification (`stub_verify`).
//!
//! Embeds the exact 144-byte 16-bit MS-DOS MZ real-mode guard image assembled from
//! `crates/wincmd-dos/stub/cpu_guard_stub.asm`, provides [`patch_djgpp_exe_with_cpu_guard`]
//! to splice a register-preserving 16-bit 8086/80286 pre-flight guard ahead of DJGPP's
//! `go32stub` DPMI loader inside `WINCMD.EXE` and `WINCHECK.EXE`, and provides deterministic
//! structural + `FLAGS`-behavior simulation so host tests verify that running on an 8086, 8088,
//! 80186, or 80286 real-mode system cleanly prints
//! `"This program requires an 80386 or newer processor."` via `INT 21h AH=09h` and exits with
//! `AX=4C01h` instead of hanging on an invalid 32-bit opcode.

#![forbid(unsafe_code)]

use alloc::vec::Vec;

/// Exact DOS diagnostic emitted by the 16-bit MZ guard stub on pre-80386 CPUs (`CRLF$`-terminated).
pub const CPU_GUARD_DIAGNOSTIC_ASCII: [u8; 53] = [
    b'T', b'h', b'i', b's', b' ', b'p', b'r', b'o', b'g', b'r', b'a', b'm', b' ', b'r', b'e', b'q',
    b'u', b'i', b'r', b'e', b's', b' ', b'a', b'n', b' ', b'8', b'0', b'3', b'8', b'6', b' ', b'o',
    b'r', b' ', b'n', b'e', b'w', b'e', b'r', b' ', b'p', b'r', b'o', b'c', b'e', b's', b's', b'o',
    b'r', b'.', 0x0D, 0x0A, b'$',
];

/// Assembled 144-byte 16-bit MS-DOS MZ CPU-guard stub (`crates/wincmd-dos/stub/cpu_guard_stub.asm`).
pub const ASSEMBLED_CPU_GUARD_MZ_STUB: [u8; 144] = [
    0x4D, 0x5A, 0x90, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0E, 0x1F, 0x9C, 0x58, 0x25, 0xFF, 0x0F, 0x50, 0x9D, 0x9C, 0x58, 0x25, 0x00, 0xF0, 0x3D, 0x00,
    0xF0, 0x74, 0x13, 0x9C, 0x58, 0x0D, 0x00, 0x70, 0x50, 0x9D, 0x9C, 0x58, 0xA9, 0x00, 0x70, 0x74,
    0x05, 0xB8, 0x00, 0x4C, 0xCD, 0x21, 0xBA, 0x32, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C,
    0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x72,
    0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x73, 0x20, 0x61, 0x6E, 0x20, 0x38, 0x30, 0x33, 0x38, 0x36,
    0x20, 0x6F, 0x72, 0x20, 0x6E, 0x65, 0x77, 0x65, 0x72, 0x20, 0x70, 0x72, 0x6F, 0x63, 0x65, 0x73,
    0x73, 0x6F, 0x72, 0x2E, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Entrypoint `IP` (`0x0900`, above `go32stub`'s `0x0600..0x0870` BSS/stack) used by [`patch_djgpp_exe_with_cpu_guard`].
pub const DJGPP_GUARD_ENTRY_IP: u16 = 0x0900;

/// Patches a DJGPP `stubify`-generated MS-DOS `.EXE` image so its real-mode MZ entrypoint executes
/// a pure-8086 register-preserving CPU guard at `CS:0x0900` before jumping to `go32stub`.
///
/// Inserts two 512-byte pages (`1,024` bytes) between the 2,048-byte `go32stub` MZ image and the
/// appended COFF payload, incrementing `e_cp` from `4` to `6`, preserving `go32stub`'s `stubinfo`
/// block at `CS:0x0000` and zero-initialized runtime BSS/stack (`CS:0x0600..0x0870`), and
/// preserving `DS`/`ES` (`PSP`), `AX`, `CX`, and `FLAGS` on 80386+ CPUs.
///
/// # Arguments
/// * `exe_bytes` - Complete DJGPP stubbed `.EXE` binary bytes.
///
/// # Returns
/// `Some(patched_exe)` on a valid unpatched DJGPP `go32stub` `.EXE`, or `None` if malformed or already patched.
#[must_use]
pub fn patch_djgpp_exe_with_cpu_guard(exe_bytes: &[u8]) -> Option<Vec<u8>> {
    let stub_prefix = exe_bytes.get(..2048)?;
    let coff_payload = exe_bytes.get(2048..).unwrap_or(&[]);
    if coff_payload.len() < 4 || stub_prefix.get(..2) != Some(b"MZ") {
        return None;
    }
    let e_cblp = u16::from_le_bytes([
        stub_prefix.get(2).copied().unwrap_or(1),
        stub_prefix.get(3).copied().unwrap_or(0),
    ]);
    let e_cp = u16::from_le_bytes([
        stub_prefix.get(4).copied().unwrap_or(0),
        stub_prefix.get(5).copied().unwrap_or(0),
    ]);
    let e_cparhdr = u16::from_le_bytes([
        stub_prefix.get(8).copied().unwrap_or(0),
        stub_prefix.get(9).copied().unwrap_or(0),
    ]);
    let orig_ip = u16::from_le_bytes([
        stub_prefix.get(20).copied().unwrap_or(0),
        stub_prefix.get(21).copied().unwrap_or(0),
    ]);
    let code_segment = u16::from_le_bytes([
        stub_prefix.get(22).copied().unwrap_or(1),
        stub_prefix.get(23).copied().unwrap_or(0),
    ]);
    if e_cblp != 0
        || e_cp != 4
        || e_cparhdr != 32
        || code_segment != 0
        || orig_ip >= 0x0600
        || stub_prefix.get(512..520) != Some(b"go32stub".as_slice())
    {
        return None;
    }

    let guard_ip = DJGPP_GUARD_ENTRY_IP;
    let jmp_rel = orig_ip.wrapping_sub(guard_ip.wrapping_add(42));
    let [jmp_lo, jmp_hi] = jmp_rel.to_le_bytes();
    let msg_ip = guard_ip.wrapping_add(58);
    let [msg_lo, msg_hi] = msg_ip.to_le_bytes();

    let guard_code: [u8; 58] = [
        0x50, // +00: push ax
        0x51, // +01: push cx
        0x9C, // +02: pushf
        0x59, // +03: pop cx
        0x89, 0xC8, // +04: mov ax, cx
        0x25, 0xFF, 0x0F, // +06: and ax, 0x0FFF
        0x50, // +09: push ax
        0x9D, // +10: popf
        0x9C, // +11: pushf
        0x58, // +12: pop ax
        0x25, 0x00, 0xF0, // +13: and ax, 0xF000
        0x3D, 0x00, 0xF0, // +16: cmp ax, 0xF000
        0x74, 0x15, // +19: je .not_386 (+42)
        0x89, 0xC8, // +21: mov ax, cx
        0x0D, 0x00, 0x70, // +23: or ax, 0x7000
        0x50, // +26: push ax
        0x9D, // +27: popf
        0x9C, // +28: pushf
        0x58, // +29: pop ax
        0xA9, 0x00, 0x70, // +30: test ax, 0x7000
        0x74, 0x07, // +33: jz .not_386 (+42)
        0x51, // +35: push cx
        0x9D, // +36: popf
        0x59, // +37: pop cx
        0x58, // +38: pop ax
        0xE9, jmp_lo, jmp_hi, // +39: jmp orig_ip
        0x59,   // +42: .not_386: pop cx
        0x58,   // +43: pop ax
        0x0E,   // +44: push cs
        0x1F,   // +45: pop ds
        0xBA, msg_lo, msg_hi, // +46: mov dx, msg_ip
        0xB4, 0x09, // +49: mov ah, 0x09
        0xCD, 0x21, // +51: int 0x21
        0xB8, 0x01, 0x4C, // +53: mov ax, 0x4C01
        0xCD, 0x21, // +56: int 0x21
    ];

    let mut out = Vec::with_capacity(exe_bytes.len().saturating_add(1024));
    out.extend_from_slice(stub_prefix.get(..4).unwrap_or(&[]));
    out.extend_from_slice(&6u16.to_le_bytes());
    out.extend_from_slice(stub_prefix.get(6..20).unwrap_or(&[]));
    out.extend_from_slice(&guard_ip.to_le_bytes());
    out.extend_from_slice(stub_prefix.get(22..2048).unwrap_or(&[]));
    out.resize(512usize.saturating_add(usize::from(guard_ip)), 0);
    out.extend_from_slice(&guard_code);
    out.extend_from_slice(&CPU_GUARD_DIAGNOSTIC_ASCII);
    out.resize(3072, 0);
    out.extend_from_slice(coff_payload);
    Some(out)
}

/// x86 CPU generation simulated against the 16-bit real-mode `FLAGS` bits `12..=15` detection algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealModeCpuGeneration {
    /// Intel 8086 / 8088 / 80186 (`FLAGS` bits `12..=15` hardwired to `1`, `0xF000`).
    Intel8086,
    /// Intel 80286 in real mode (`FLAGS` bits `12..=15` hardwired to `0`, `0x0000`).
    Intel80286,
    /// Intel 80386 / 80486 / Pentium+ (`FLAGS` bits `12..=14` writable in real/V86 mode).
    Intel80386OrNewer,
}

/// Outcome of running the real-mode 16-bit MZ CPU guard check on a given [`RealModeCpuGeneration`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuGuardOutcome {
    /// CPU is 80386+; stub proceeds to `CWSDPMI.EXE` / 32-bit COFF image (`exit_code == 0` in standalone stub).
    ProceedToProtectedMode,
    /// Pre-386 CPU rejected cleanly with `INT 21h AH=09h` message and `INT 21h AX=4C01h` (`exit_code == 1`).
    RejectedPre386 {
        /// DOS `INT 21h AH=4Ch` exit code (`1`).
        exit_code: u8,
    },
}

/// Validates that `stub_bytes` is a well-formed 16-bit MS-DOS `MZ` executable containing a valid
/// 8086/80286 `PUSHF`/`POP` guard sequence and `$`-terminated diagnostic string.
///
/// # Arguments
/// * `stub_bytes` - Raw MZ executable image bytes (either standalone `cpu_guard_stub` or patched DJGPP `.EXE`).
///
/// # Returns
/// `true` if the `MZ` header, paragraph alignment, 16-bit guard opcodes at `CS:e_ip`, and diagnostic string are valid.
#[must_use]
pub fn validate_mz_cpu_guard_stub(stub_bytes: &[u8]) -> bool {
    if stub_bytes.len() < 64 || stub_bytes.get(..2) != Some(b"MZ") {
        return false;
    }
    let header_paragraphs = usize::from(u16::from_le_bytes([
        stub_bytes.get(8).copied().unwrap_or(0),
        stub_bytes.get(9).copied().unwrap_or(0),
    ]));
    let e_ip = usize::from(u16::from_le_bytes([
        stub_bytes.get(20).copied().unwrap_or(0),
        stub_bytes.get(21).copied().unwrap_or(0),
    ]));
    let e_cs = usize::from(u16::from_le_bytes([
        stub_bytes.get(22).copied().unwrap_or(0),
        stub_bytes.get(23).copied().unwrap_or(0),
    ]));
    let entry_offset = header_paragraphs
        .saturating_add(e_cs)
        .saturating_mul(16)
        .saturating_add(e_ip);
    let Some(code_and_data) = stub_bytes.get(entry_offset..) else {
        return false;
    };
    let standalone_entry = [0x0Eu8, 0x1F, 0x9C, 0x58, 0x25, 0xFF, 0x0F];
    let patched_entry = [0x50u8, 0x51, 0x9C, 0x59, 0x89, 0xC8, 0x25, 0xFF, 0x0F];
    let valid_opcodes = code_and_data.get(..standalone_entry.len()) == Some(&standalone_entry)
        || code_and_data.get(..patched_entry.len()) == Some(&patched_entry);
    if !valid_opcodes {
        return false;
    }
    code_and_data
        .windows(CPU_GUARD_DIAGNOSTIC_ASCII.len())
        .any(|w| w == CPU_GUARD_DIAGNOSTIC_ASCII)
}

/// Applies CPU-generation-specific `POPF` bitmask behavior on real-mode `FLAGS` bits `12..=15`.
///
/// # Arguments
/// * `cpu` - [`RealModeCpuGeneration`] under test.
/// * `candidate` - Candidate 16-bit `FLAGS` value pushed onto the stack.
///
/// # Returns
/// Resulting `FLAGS` register value after `POPF; PUSHF; POP AX`.
#[must_use]
const fn apply_cpu_popf(cpu: RealModeCpuGeneration, candidate: u16) -> u16 {
    match cpu {
        RealModeCpuGeneration::Intel8086 => (candidate & 0x0FFF) | 0xF000,
        RealModeCpuGeneration::Intel80286 => candidate & 0x0FFF,
        RealModeCpuGeneration::Intel80386OrNewer => candidate & 0x7FFF,
    }
}

/// Simulates the exact `FLAGS` bit `12..=15` algorithm from `cpu_guard_stub.asm` across 8086, 80286, and 80386+.
///
/// # Arguments
/// * `cpu` - [`RealModeCpuGeneration`] under test.
///
/// # Returns
/// [`CpuGuardOutcome::RejectedPre386`] (`exit_code: 1`) on 8086 and 80286, or
/// [`CpuGuardOutcome::ProceedToProtectedMode`] on 80386+.
#[must_use]
pub const fn simulate_cpu_guard_flags_probe(cpu: RealModeCpuGeneration) -> CpuGuardOutcome {
    // Step 1: Clear bits 12..15 (`AND AX, 0x0FFF; PUSH AX; POPF; PUSHF; POP AX`)
    let after_clear = apply_cpu_popf(cpu, 0x0202 & 0x0FFF);
    if (after_clear & 0xF000) == 0xF000 {
        return CpuGuardOutcome::RejectedPre386 { exit_code: 1 };
    }

    // Step 2: Set bits 12..14 (`OR AX, 0x7000; PUSH AX; POPF; PUSHF; POP AX`)
    let after_set = apply_cpu_popf(cpu, after_clear | 0x7000);
    if (after_set & 0x7000) == 0 {
        return CpuGuardOutcome::RejectedPre386 { exit_code: 1 };
    }

    CpuGuardOutcome::ProceedToProtectedMode
}
