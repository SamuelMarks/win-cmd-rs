//! Single-tasking MS-DOS child process spawner (`INT 21h AH=4Bh`) and `%TEMP%` spooler.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::dos::{
    DosEnvSizeLimit, DosExecChildSpec, DosKernelApi, DosWriteDisposition, LongCmdlineTransfer,
    PipeSpoolCleanupPolicy, PspCommandTail,
};
use crate::error::CmdError;
use crate::reader::encoding::{decode_script_bytes, encode_codepage_bytes};
use crate::types::{BS_CHAR, BS_STR, CodePage};

use super::io::{ExternalSpawnRequest, ExternalSpawnResult, ProcessSpawner};

/// Default minimum largest-free-conventional-memory block (`16 KiB`) required to load a real-mode DOS stub.
pub const DEFAULT_MIN_CONVENTIONAL_BYTES: u32 = 16_384;

/// Validated executable path, working directory, `PSP:0x80` tail, and environment block for a DOS child.
struct PreparedDosSpawn {
    /// Target DOS executable path (`C:\DOS\MEM.EXE`).
    program_dos_path: String,
    /// Target DOS working directory (`C:\`).
    cwd_dos_path: String,
    /// Validated 126-byte `PSP:0x80` command tail.
    psp_tail: PspCommandTail,
    /// Validated child environment variable pairs.
    child_env: Vec<(String, String)>,
}

/// Single-tasking `#![no_std]` MS-DOS [`ProcessSpawner`] backed by [`DosKernelApi`].
///
/// Spools redirected `stdin`, `stdout`, `stderr`, and optional `@response.rsp` files through
/// `%WINCMD_PIPE_DIR%` -> `%TEMP%` -> `%TMP%` -> active drive root using collision-free 8.3
/// filenames (`_WCIxxxx.TMP`, `_WCOxxxx.TMP`, `_WCExxxx.TMP`, `_WCRxxxx.RSP`), enforces MS-DOS
/// 126-byte `PSP:0x80` and environment-paragraph limits, and guarantees spool cleanup.
#[derive(Debug, Clone)]
pub struct DosProcessSpawner<K: DosKernelApi + Clone + 'static> {
    /// Underlying safe MS-DOS kernel handle.
    kernel: K,
    /// Policy for command-line tails longer than 126 bytes.
    pub cmdline_policy: LongCmdlineTransfer,
    /// Maximum serialized child environment block size (`KEY=VAL\0...\0\0`).
    pub env_limit: DosEnvSizeLimit,
    /// Spool-file deletion error policy.
    pub cleanup_policy: PipeSpoolCleanupPolicy,
    /// Minimum conventional memory block required before attempting `exec_child`.
    pub min_conventional_bytes: u32,
    /// Active OEM [`CodePage`] for child `stdin`/`stdout`/`stderr` byte conversion.
    pub codepage: CodePage,
    /// Monotonic 16-bit counter generating unique 8.3 spool filenames (`0000`..`FFFF`).
    spool_counter: u16,
}

impl<K: DosKernelApi + Clone + 'static> DosProcessSpawner<K> {
    /// Creates a new [`DosProcessSpawner`] over `kernel` with DJGPP-compatible defaults.
    ///
    /// # Arguments
    /// * `kernel` - Initialized [`DosKernelApi`] implementation (or [`crate::dos::SharedDosKernel`]).
    ///
    /// # Returns
    /// Configured [`DosProcessSpawner`].
    #[must_use]
    pub fn new(kernel: K) -> Self {
        let codepage = kernel
            .active_codepage()
            .unwrap_or(CodePage::OemUnitedStates);
        Self {
            kernel,
            cmdline_policy: LongCmdlineTransfer::CmdlineEnvVar,
            env_limit: DosEnvSizeLimit::Dpmi32KiB,
            cleanup_policy: PipeSpoolCleanupPolicy::Strict,
            min_conventional_bytes: DEFAULT_MIN_CONVENTIONAL_BYTES,
            codepage,
            spool_counter: 0,
        }
    }

    /// Borrows the underlying [`DosKernelApi`] immutably.
    ///
    /// # Returns
    /// Reference to `K`.
    #[must_use]
    pub const fn kernel(&self) -> &K {
        &self.kernel
    }

    /// Borrows the underlying [`DosKernelApi`] mutably.
    ///
    /// # Returns
    /// Mutable reference to `K`.
    pub const fn kernel_mut(&mut self) -> &mut K {
        &mut self.kernel
    }

    /// Allocates the next 16-bit spool sequence number (`0000`..`FFFF`).
    ///
    /// # Returns
    /// Sequence index prior to wrapping increment.
    const fn next_spool_seq(&mut self) -> u16 {
        let seq = self.spool_counter;
        self.spool_counter = self.spool_counter.wrapping_add(1);
        seq
    }

    /// Resolves the MS-DOS temporary spool directory in priority order:
    /// `%WINCMD_PIPE_DIR%` -> `%TEMP%` -> `%TMP%` -> active drive root (`C:`).
    ///
    /// # Arguments
    /// * `env_vars` - Visible child `(key, value)` environment variables.
    ///
    /// # Returns
    /// Validated MS-DOS directory path without trailing backslash (except root `"C:"`).
    #[must_use]
    fn resolve_spool_dir(&self, env_vars: &[(String, String)]) -> String {
        for var_name in ["WINCMD_PIPE_DIR", "TEMP", "TMP"] {
            if let Some((_, val)) = env_vars
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(var_name))
            {
                let trimmed = val.trim();
                if !trimmed.is_empty()
                    && self
                        .kernel
                        .stat_entry(trimmed)
                        .is_ok_and(|s| s.attributes.is_directory())
                {
                    let canon = self.kernel.truename(trimmed).unwrap_or_default();
                    return canon.trim_end_matches([BS_CHAR, '/']).to_owned();
                }
            }
        }
        format!("{}:", self.kernel.current_drive().as_char())
    }

    /// Encodes the child `PSP:0x80` tail and optional `CMDLINE=` or `@_WCRxxxx.RSP` response file.
    ///
    /// # Arguments
    /// * `program_dos_path` - Resolved child DOS executable path.
    /// * `effective_tail` - Argument tail string.
    /// * `spool_dir` - Directory prefix for optional `.RSP` creation.
    /// * `seq` - Current 16-bit spool sequence counter.
    /// * `child_env` - Mutable child environment list.
    /// * `created_spools` - Mutable cleanup list of temporary files created so far.
    ///
    /// # Returns
    /// `Ok(PspCommandTail)` ready for `DosExecChildSpec`.
    ///
    /// # Errors
    /// Returns [`CmdError::CommandLineTooLong`] or spool write [`CmdError`].
    fn prepare_cmdline_tail(
        &mut self,
        program_dos_path: &str,
        effective_tail: &str,
        spool_dir: &str,
        seq: u16,
        child_env: &mut Vec<(String, String)>,
        created_spools: &mut Vec<String>,
    ) -> Result<PspCommandTail, CmdError> {
        if self.cmdline_policy == LongCmdlineTransfer::ResponseFileAtSign
            && PspCommandTail::encode(
                program_dos_path,
                effective_tail,
                LongCmdlineTransfer::Strict126BytePsp,
            )
            .is_err()
        {
            let rsp_path = format!("{spool_dir}{BS_STR}_WCR{seq:04X}.RSP");
            let payload = encode_codepage_bytes(effective_tail, self.codepage);
            self.kernel.write_file_bytes(
                &rsp_path,
                &payload,
                DosWriteDisposition::CreateTruncate,
            )?;
            created_spools.push(rsp_path.clone());
            let at_tail = format!("@{rsp_path}");
            let (psp_tail, _) = PspCommandTail::encode(
                program_dos_path,
                &at_tail,
                LongCmdlineTransfer::Strict126BytePsp,
            )?;
            return Ok(psp_tail);
        }

        child_env.retain(|(k, _)| !k.eq_ignore_ascii_case("CMDLINE"));
        let (psp_tail, cmdline_env_opt) =
            PspCommandTail::encode(program_dos_path, effective_tail, self.cmdline_policy)?;
        if let Some(cmdline_full) = cmdline_env_opt {
            child_env.push(("CMDLINE".to_owned(), cmdline_full));
        }
        Ok(psp_tail)
    }

    /// Creates input, stdout, and stderr spool files in `spool_dir` and executes `prepared` on `self.kernel`.
    ///
    /// # Arguments
    /// * `req` - [`ExternalSpawnRequest`].
    /// * `prepared` - [`PreparedDosSpawn`] containing paths, PSP tail, and environment.
    /// * `spool_dir` - Spool directory prefix.
    /// * `seq` - 16-bit sequence number.
    /// * `created_spools` - Mutable cleanup list of created spool paths.
    ///
    /// # Returns
    /// `Ok((exit_code, stdout_bytes, stderr_bytes))`.
    ///
    /// # Errors
    /// Propagates spool I/O or child execution [`CmdError`].
    fn execute_with_spool_files(
        &mut self,
        req: &ExternalSpawnRequest,
        prepared: PreparedDosSpawn,
        spool_dir: &str,
        seq: u16,
        created_spools: &mut Vec<String>,
    ) -> Result<(crate::types::ExitCode, Vec<u8>, Vec<u8>), CmdError> {
        let stdin_spool_path = if !req.stdin_bytes.is_empty() || !req.stdin.is_empty() {
            let in_path = format!("{spool_dir}{BS_STR}_WCI{seq:04X}.TMP");
            let in_bytes = if req.stdin_bytes.is_empty() {
                encode_codepage_bytes(&req.stdin, self.codepage)
            } else {
                req.stdin_bytes.clone()
            };
            self.kernel.write_file_bytes(
                &in_path,
                &in_bytes,
                DosWriteDisposition::CreateTruncate,
            )?;
            created_spools.push(in_path.clone());
            Some(in_path)
        } else {
            None
        };

        let out_path = format!("{spool_dir}{BS_STR}_WCO{seq:04X}.TMP");
        self.kernel
            .write_file_bytes(&out_path, &[], DosWriteDisposition::CreateTruncate)?;
        created_spools.push(out_path.clone());

        let err_path = format!("{spool_dir}{BS_STR}_WCE{seq:04X}.TMP");
        self.kernel
            .write_file_bytes(&err_path, &[], DosWriteDisposition::CreateTruncate)?;
        created_spools.push(err_path.clone());

        let spec = DosExecChildSpec {
            program_dos_path: prepared.program_dos_path,
            psp_tail: prepared.psp_tail,
            args: req.args.clone(),
            cwd_dos_path: prepared.cwd_dos_path,
            env_vars: prepared.child_env,
            stdin_spool_path,
            stdout_spool_path: Some(out_path.clone()),
            stderr_spool_path: Some(err_path.clone()),
        };
        let exit_code = self.kernel.exec_child(&spec)?;
        let stdout_bytes = self.kernel.read_file_bytes(&out_path)?;
        let stderr_bytes = self.kernel.read_file_bytes(&err_path)?;
        Ok((exit_code, stdout_bytes, stderr_bytes))
    }

    /// Removes all temporary spool files recorded in `created_spools` according to `self.cleanup_policy`.
    ///
    /// # Arguments
    /// * `created_spools` - Spool file DOS paths to delete.
    ///
    /// # Returns
    /// `Ok(())` when cleanup succeeds (or `BestEffort` is active).
    ///
    /// # Errors
    /// Returns the first non-`FileNotFound` deletion [`CmdError`] when `PipeSpoolCleanupPolicy::Strict` is active.
    fn cleanup_spools(&mut self, created_spools: &[String]) -> Result<(), CmdError> {
        let mut first_err: Option<CmdError> = None;
        for path in created_spools {
            if let Err(err) = self.kernel.delete_file(path)
                && !matches!(err, CmdError::FileNotFound { .. })
            {
                first_err = Some(first_err.unwrap_or(err));
            }
        }
        if self.cleanup_policy == PipeSpoolCleanupPolicy::Strict
            && let Some(err) = first_err
        {
            return Err(err);
        }
        Ok(())
    }
}

impl<K: DosKernelApi + Clone + 'static> ProcessSpawner for DosProcessSpawner<K> {
    /// Synchronously executes an external DOS `.COM`/`.EXE` child using `%TEMP%` spool files.
    ///
    /// # Arguments
    /// * `req` - [`ExternalSpawnRequest`] describing executable, arguments, environment, and piped `stdin`.
    ///
    /// # Returns
    /// `Ok(ExternalSpawnResult)` with decoded `stdout`, `stderr`, and 8-bit `ExitCode`.
    ///
    /// # Errors
    /// Returns [`CmdError::InsufficientMemory`], [`CmdError::OutOfEnvironmentSpace`],
    /// [`CmdError::CommandLineTooLong`], or child/spool [`CmdError`].
    fn spawn_external(
        &mut self,
        req: &ExternalSpawnRequest,
    ) -> Result<ExternalSpawnResult, CmdError> {
        let mem = self.kernel.memory_stats()?;
        if mem.largest_conventional_block < self.min_conventional_bytes {
            return Err(CmdError::InsufficientMemory);
        }

        let program_dos_path = req.program_host_path.as_ref().map_or_else(
            || req.program_vfs_path.to_windows_string(),
            |p| p.as_str().to_owned(),
        );
        let cwd_dos_path = req.cwd_host.as_ref().map_or_else(
            || req.cwd_vfs.to_windows_string(),
            |p| p.as_str().to_owned(),
        );

        let effective_tail = if req.raw_tail.is_empty() && !req.args.is_empty() {
            req.args.join(" ")
        } else {
            req.raw_tail.clone()
        };

        let spool_dir = self.resolve_spool_dir(&req.env_vars);
        let seq = self.next_spool_seq();
        let mut child_env = req.env_vars.clone();
        let mut created_spools: Vec<String> = Vec::with_capacity(4);

        let run_result = (|| -> Result<(crate::types::ExitCode, Vec<u8>, Vec<u8>), CmdError> {
            let psp_tail = self.prepare_cmdline_tail(
                &program_dos_path,
                &effective_tail,
                &spool_dir,
                seq,
                &mut child_env,
                &mut created_spools,
            )?;
            self.env_limit.validate_env_block(&child_env)?;
            let prepared = PreparedDosSpawn {
                program_dos_path,
                cwd_dos_path,
                psp_tail,
                child_env,
            };
            self.execute_with_spool_files(req, prepared, &spool_dir, seq, &mut created_spools)
        })();

        let cleanup_res = self.cleanup_spools(&created_spools);
        let (exit_code, stdout_bytes, stderr_bytes) = run_result?;
        cleanup_res?;

        let stdout = decode_script_bytes(&stdout_bytes, self.codepage)?;
        let stderr = decode_script_bytes(&stderr_bytes, self.codepage)?;

        Ok(ExternalSpawnResult {
            exit_code,
            stdout,
            stderr,
        })
    }

    /// Clones this [`DosProcessSpawner`] into a boxed [`ProcessSpawner`].
    ///
    /// # Returns
    /// Boxed clone of `self`.
    fn clone_box(&self) -> Box<dyn ProcessSpawner> {
        Box::new(self.clone())
    }
}
