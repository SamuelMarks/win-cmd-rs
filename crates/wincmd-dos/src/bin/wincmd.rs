//! `WINCMD.EXE` — 32-bit Protected-Mode MS-DOS (`DJGPP` + `CWSDPMI`) shell entrypoint.

#![cfg_attr(not(feature = "host-sim"), no_std)]
#![cfg_attr(not(feature = "host-sim"), no_main)]

#[cfg(feature = "host-sim")]
/// Host-simulation binary entrypoint used when testing `wincmd-dos` on macOS/Linux/Windows.
///
/// # Returns
/// Process [`std::process::ExitCode`] matching interpreter exit status.
fn main() -> std::process::ExitCode {
    use win_cmd_rs::dos::SimulatedDosKernel;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = wincmd_dos::execute_dos_wincmd(
        &args,
        SimulatedDosKernel::new(),
        Vec::new(),
        &mut stdout,
        &mut stderr,
    );
    std::io::Write::write_all(&mut std::io::stdout(), &stdout).unwrap_or(());
    std::io::Write::write_all(&mut std::io::stderr(), &stderr).unwrap_or(());
    std::process::ExitCode::from(code)
}

#[cfg(not(feature = "host-sim"))]
/// 32-bit DJGPP `main(argc, argv)` entrypoint linked by `i586-pc-msdosdjgpp-gcc` `crt0.o`.
///
/// # Arguments
/// * `arg_count` - Argument count from DJGPP startup code.
/// * `arg_ptrs` - Argument pointer vector from DJGPP startup code.
///
/// # Returns
/// Process exit status (`0..=255`).
///
/// # Safety
/// Must only be invoked by DJGPP `crt0.o` with a valid `(arg_count, arg_ptrs)` vector.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(arg_count: i32, arg_ptrs: *const *const u8) -> i32 {
    use wincmd_dos::SyscallHandleWriter;
    use wincmd_dos::djgpp_kernel::DjgppDosKernel;
    use wincmd_dos::ffi::djgpp_c::{
        DjgppLibcSyscalls, collect_djgpp_args, read_piped_stdin_if_redirected,
    };

    // SAFETY: `arg_count` and `arg_ptrs` are supplied directly by DJGPP `crt0.o`.
    let args = unsafe { collect_djgpp_args(arg_count, arg_ptrs) };
    let stdin_bytes = read_piped_stdin_if_redirected();
    let syscalls = DjgppLibcSyscalls::with_args(args.clone());
    let kernel = DjgppDosKernel::new(syscalls.clone());
    let mut out = SyscallHandleWriter::new(syscalls.clone(), 1);
    let mut err = SyscallHandleWriter::new(syscalls, 2);
    i32::from(wincmd_dos::execute_dos_wincmd(
        &args,
        kernel,
        stdin_bytes,
        &mut out,
        &mut err,
    ))
}

#[cfg(not(feature = "host-sim"))]
extern crate alloc;
