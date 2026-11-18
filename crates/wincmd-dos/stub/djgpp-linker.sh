#!/usr/bin/env sh
# -----------------------------------------------------------------------------
# crates/wincmd-dos/stub/djgpp-linker.sh
#
# Linker driver wrapping `i586-pc-msdosdjgpp-gcc` for `rustc` COFF builds:
# 1. Filters PE-only ld flags unsupported by DJGPP's `i386go32` BFD linker.
# 2. Normalizes LLVM PE-COFF `.o` / `.rlib` inputs into DJGPP `coff-go32` format
#    inside an isolated temporary workspace (translating PE `REL32` addends,
#    folding `scnum > 0` symbol offsets into in-place immediates, and resolving
#    PE storage-class-105 weak externals without mutating Cargo's build cache).
# 3. Links `chkstk_dos.s` alongside DJGPP `crt0.o` + `libc.a` via `djgpp-rust.ld`.
# 4. Splices two 512-byte pages (`e_cp: 4 -> 6`) containing our pure-8086
#    register-preserving CPU guard at `CS:0x0900` so 8086/80186/80286 DOS
#    systems print `"This program requires an 80386 or newer processor."` via
#    `INT 21h AH=09h` and exit cleanly with `AX=4C01h`.
# -----------------------------------------------------------------------------
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 - "$SCRIPT_DIR" "$@" <<'PYLINK'
import os
import shutil
import struct
import subprocess
import sys
import tempfile

UNSUPPORTED_FLAGS = {
    "-Wl,--nxcompat",
    "-Wl,--dynamicbase",
    "-Wl,--large-address-aware",
    "-Wl,--disable-auto-image-base",
    "-Wl,--gc-sections",
}


def convert_pe_coff_to_go32(raw: bytes) -> bytes:
    if len(raw) < 20:
        return raw
    magic, nscns, _timdat, symptr, nsyms, opthdr, _flags = struct.unpack_from(
        "<HHIIIHH", raw, 0
    )
    if magic != 0x014C or symptr == 0 or nsyms == 0 or b"@feat.00" not in raw:
        return raw

    buf = bytearray(raw)
    syms = {}
    idx = 0
    while idx < nsyms:
        off = symptr + idx * 18
        if off + 18 > len(buf):
            return raw
        name8 = bytes(buf[off : off + 8])
        val, scnum, stype, sclass, naux = struct.unpack_from("<IhHBB", buf, off + 8)
        aux = bytes(buf[off + 18 : off + (1 + naux) * 18])
        syms[idx] = [name8, val, scnum, stype, sclass, naux, aux]
        idx += 1 + naux

    strtab_off = symptr + nsyms * 18

    def decode_sym_name(raw8: bytes) -> str:
        z0, s_off = struct.unpack("<II", raw8)
        if z0 == 0 and strtab_off + s_off < len(buf):
            end_i = buf.find(bytes([0]), strtab_off + s_off)
            if end_i < 0:
                end_i = len(buf)
            return bytes(buf[strtab_off + s_off : end_i]).decode("latin1")
        return raw8.rstrip(bytes([0])).decode("latin1")

    weak_redirect = {}
    for s_idx, entry in list(syms.items()):
        name8, _val, scnum, _stype, sclass, naux, aux = entry
        if sclass == 105 and scnum == 0 and naux >= 1 and len(aux) >= 4:
            sym_ident = decode_sym_name(name8)
            tag_idx = struct.unpack_from("<I", aux, 0)[0]
            while (
                tag_idx in syms
                and syms[tag_idx][4] == 105
                and syms[tag_idx][2] == 0
                and syms[tag_idx][5] >= 1
                and len(syms[tag_idx][6]) >= 4
            ):
                nxt = struct.unpack_from("<I", syms[tag_idx][6], 0)[0]
                if nxt == tag_idx:
                    break
                tag_idx = nxt
            if tag_idx in syms:
                target = syms[tag_idx]
                s_off = symptr + s_idx * 18
                if target[2] > 0 and sym_ident not in ("__alloca", "___chkstk", "___chkstk_ms"):
                    weak_redirect[s_idx] = tag_idx
                    # Promote weak alias of a defined local symbol into a real C_EXT definition.
                    struct.pack_into(
                        "<IhHBB",
                        buf,
                        s_off + 8,
                        target[1],
                        target[2],
                        target[3],
                        2,
                        0,
                    )
                    entry[1], entry[2], entry[4], entry[5] = target[1], target[2], 2, 0
                else:
                    # Demote sectionless or chkstk weak alias into N_ABS C_STAT.
                    buf[s_off : s_off + 8] = b".weakpad"
                    struct.pack_into("<IhHBB", buf, s_off + 8, 0, -1, 0, 3, 0)
                    entry[1], entry[2], entry[4], entry[5] = 0, -1, 3, 0
                for aux_k in range(1, naux + 1):
                    a_off = symptr + (s_idx + aux_k) * 18
                    buf[a_off : a_off + 8] = b".weakaux"
                    struct.pack_into("<IhHBB", buf, a_off + 8, 0, -1, 0, 3, 0)

    for sec_i in range(nscns):
        sh_off = 20 + opthdr + sec_i * 40
        if sh_off + 40 > len(buf):
            break
        (
            _sname,
            _paddr,
            sec_vaddr,
            _size,
            scnptr,
            relptr,
            _lnnoptr,
            nreloc,
            _nlnno,
            sflags,
        ) = struct.unpack_from("<8sIIIIIIHHI", buf, sh_off)
        if relptr == 0 or scnptr == 0:
            continue
        rel_count = nreloc
        rel_cursor = relptr
        if (sflags & 0x01000000) != 0 and nreloc == 0xFFFF:
            rel_count = struct.unpack_from("<I", buf, relptr)[0]
            rel_cursor += 10
        for _ in range(rel_count):
            r_vaddr, r_sym, r_type = struct.unpack_from("<IIH", buf, rel_cursor)
            if r_sym in weak_redirect:
                r_sym = weak_redirect[r_sym]
                struct.pack_into("<I", buf, rel_cursor + 4, r_sym)
            sym_info = syms.get(r_sym)
            if sym_info is not None and r_type in (6, 20):
                delta = 0
                if sym_info[2] > 0:
                    delta += sym_info[1]
                if r_type == 20:
                    delta -= sec_vaddr + r_vaddr + 4
                if delta != 0:
                    patch_pos = scnptr + r_vaddr
                    cur_imm = struct.unpack_from("<I", buf, patch_pos)[0]
                    struct.pack_into(
                        "<I", buf, patch_pos, (cur_imm + delta) & 0xFFFFFFFF
                    )
            rel_cursor += 10

    return bytes(buf)


def normalize_ar_archive(ar_path: str, work_dir: str, ar_tool: str, seq: int) -> str:
    data = open(ar_path, "rb").read()
    ar_magic = b"!<arch>" + bytes([10])
    if not data.startswith(ar_magic) or b"@feat.00" not in data:
        return ar_path

    member_dir = os.path.join(work_dir, f"ar_{seq}")
    os.makedirs(member_dir, exist_ok=True)
    pos = 8
    longnames = b""
    extracted = []
    member_idx = 0
    while pos + 60 <= len(data):
        hdr = data[pos : pos + 60]
        raw_name = hdr[0:16].decode("latin1")
        size = int(hdr[48:58].decode("ascii").strip() or "0")
        body_start = pos + 60
        body_end = body_start + size
        body = data[body_start:body_end]
        pos = body_end + (body_end & 1)

        name_stripped = raw_name.strip()
        if name_stripped in ("/", "//"):
            if name_stripped == "//":
                longnames = body
            continue
        if raw_name.startswith("/") and raw_name[1:].strip().isdigit():
            off = int(raw_name[1:].strip())
            end_sl = longnames.find(b"/", off)
            end_nl = longnames.find(bytes([10]), off)
            end_zr = longnames.find(bytes([0]), off)
            cut = min(x for x in (end_sl, end_nl, end_zr, len(longnames)) if x >= 0)
            m_name = longnames[off:cut].decode("latin1")
        else:
            m_name = raw_name.rstrip(" /" + chr(0))

        if m_name.endswith(".rmeta") or m_name.startswith("lib.rmeta"):
            continue
        converted = convert_pe_coff_to_go32(body)
        out_member = os.path.join(member_dir, f"m{member_idx}_{os.path.basename(m_name)}")
        with open(out_member, "wb") as mf:
            mf.write(converted)
        extracted.append(out_member)
        member_idx += 1

    if not extracted:
        return ar_path
    out_ar = os.path.join(work_dir, f"norm_{seq}_{os.path.basename(ar_path)}")
    subprocess.run([ar_tool, "crs", out_ar, *extracted], check=True)
    return out_ar


def patch_mz_cpu_guard(exe_path: str) -> None:
    with open(exe_path, "rb") as f:
        exe = f.read()
    if len(exe) < 2052 or exe[:2] != b"MZ" or exe[512:520] != b"go32stub":
        return
    e_cblp, e_cp = struct.unpack_from("<HH", exe, 2)
    e_cparhdr = struct.unpack_from("<H", exe, 8)[0]
    orig_ip, e_cs = struct.unpack_from("<HH", exe, 20)
    if not (e_cblp == 0 and e_cp == 4 and e_cparhdr == 32 and e_cs == 0 and orig_ip < 0x0600):
        return
    guard_ip = 0x0900
    jmp_rel = (orig_ip - (guard_ip + 42)) & 0xFFFF
    msg_ip = (guard_ip + 58) & 0xFFFF
    msg = b"This program requires an 80386 or newer processor." + bytes([13, 10, 36])
    code = bytes(
        [
            0x50, 0x51, 0x9C, 0x59,
            0x89, 0xC8, 0x25, 0xFF, 0x0F, 0x50, 0x9D, 0x9C, 0x58,
            0x25, 0x00, 0xF0, 0x3D, 0x00, 0xF0, 0x74, 0x15,
            0x89, 0xC8, 0x0D, 0x00, 0x70, 0x50, 0x9D, 0x9C, 0x58,
            0xA9, 0x00, 0x70, 0x74, 0x07,
            0x51, 0x9D, 0x59, 0x58,
            0xE9, jmp_rel & 0xFF, (jmp_rel >> 8) & 0xFF,
            0x59, 0x58, 0x0E, 0x1F,
            0xBA, msg_ip & 0xFF, (msg_ip >> 8) & 0xFF,
            0xB4, 0x09, 0xCD, 0x21,
            0xB8, 0x01, 0x4C, 0xCD, 0x21,
        ]
    )
    out = bytearray(exe[:2048] + bytes(1024) + exe[2048:])
    struct.pack_into("<H", out, 4, 6)
    struct.pack_into("<H", out, 20, guard_ip)
    guard_off = 512 + guard_ip
    out[guard_off : guard_off + len(code)] = code
    out[guard_off + len(code) : guard_off + len(code) + len(msg)] = msg
    with open(exe_path, "wb") as f:
        f.write(out)


def expand_args(raw_args: list[str]) -> list[str]:
    expanded = []
    for arg in raw_args:
        if arg.startswith("@") and os.path.isfile(arg[1:]):
            content = open(arg[1:], "r", encoding="utf-8").read()
            import shlex
            expanded.extend(shlex.split(content))
        else:
            expanded.append(arg)
    return expanded


def main() -> int:
    script_dir = sys.argv[1]
    in_args = expand_args(sys.argv[2:])
    djgpp_gcc = os.environ.get("DJGPP_GCC", "i586-pc-msdosdjgpp-gcc")
    djgpp_ar = os.environ.get("DJGPP_AR", "i586-pc-msdosdjgpp-ar")

    work_dir = tempfile.mkdtemp(prefix="wincmd_djgpp_link_")
    try:
        filtered = []
        out_exe = ""
        prev_o = False
        seq = 0
        for arg in in_args:
            if prev_o:
                out_exe = arg
                prev_o = False
                filtered.append(arg)
                continue
            if arg == "-o":
                prev_o = True
                filtered.append(arg)
                continue
            if arg in UNSUPPORTED_FLAGS:
                continue
            if os.path.isfile(arg) and arg.endswith(".o"):
                raw = open(arg, "rb").read()
                conv = convert_pe_coff_to_go32(raw)
                if conv is not raw:
                    dst = os.path.join(work_dir, f"obj_{seq}_{os.path.basename(arg)}")
                    with open(dst, "wb") as f:
                        f.write(conv)
                    filtered.append(dst)
                    seq += 1
                    continue
            if os.path.isfile(arg) and (arg.endswith(".rlib") or arg.endswith(".a")):
                filtered.append(normalize_ar_archive(arg, work_dir, djgpp_ar, seq))
                seq += 1
                continue
            filtered.append(arg)

        cmd = [
            djgpp_gcc,
            f"-Wl,-T,{os.path.join(script_dir, 'djgpp-rust.ld')}",
        ]
        if os.environ.get("DJGPP_KEEP_SYMBOLS", "0") != "1":
            cmd.append("-Wl,-s")
        cmd.append(os.path.join(script_dir, "chkstk_dos.s"))
        cmd.extend(filtered)
        subprocess.run(cmd, check=True)

        if out_exe and os.path.isfile(out_exe):
            patch_mz_cpu_guard(out_exe)
        return 0
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
PYLINK
