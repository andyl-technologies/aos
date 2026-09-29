//! Bounded descriptor-backed compression for direct staging, without file Vecs.
//!
//! Nix dump and compressor processes feed a 64 KiB copy loop into an anonymous
//! owner-private disk file. Both process exit statuses must succeed. Dropping
//! the async caller requests cooperative cancellation between pipe reads; it
//! cannot promise an immediate interruption of a blocked host filesystem read.

use std::fmt;
use std::fs::File;
use std::io::{Seek as _, Write as _};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::{Context as _, Result};
use aos_core::nix::aos_nix_env;
use sha2::{Digest as _, Sha256};

const COPY_BYTES: usize = 64 * 1024;
const MAX_SPOOL_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Retains one exact compressed descriptor and its bounded content identity.
pub struct CompressedSpool {
    file: File,
    byte_size: u64,
    sha256: String,
}

impl fmt::Debug for CompressedSpool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompressedSpool")
            .field("byte_size", &self.byte_size)
            .finish_non_exhaustive()
    }
}

impl CompressedSpool {
    /// Returns its exact content size, excluding all subprocess/control bytes.
    pub fn byte_size(&self) -> u64 {
        self.byte_size
    }

    /// Returns the original lowercase SHA-256 over complete compressed bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Transfers its pinned ordinary descriptor, exact byte size and digest.
    pub fn into_parts(self) -> (File, u64, String) {
        (self.file, self.byte_size, self.sha256)
    }
}

struct ChildCustody(Option<Child>);

impl ChildCustody {
    fn finish(&mut self) -> Result<()> {
        let child = self
            .0
            .as_mut()
            .context("cache compression process is unavailable")?;
        let status = child
            .wait()
            .context("waiting for cache compression process")?;
        self.0 = None;
        anyhow::ensure!(status.success(), "cache compression source or codec failed");
        Ok(())
    }
}

impl Drop for ChildCustody {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            // A failed/cancelled pipeline must not leave children producing
            // bytes or blocking on a pipe whose consumer disappeared.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Compresses a real Nix dump to bounded private disk storage.
///
/// Only `none`, `zstd` and `xz` codecs are admitted. The caller supplies a disk
/// bound no larger than the direct object limit, and limits concurrent spools.
/// Restart reconstructs the spool from its immutable Nix source and verifies
/// the original journaled size/digest before issuing further grants.
///
/// # Errors
/// Returns a value-free source/codec/cancellation/limit failure. Neither an
/// incomplete dump nor a successful codec over a failed dump is admitted.
pub async fn streaming_compress_to_file(
    store_path: &str,
    algorithm: &str,
    level: i32,
    maximum_bytes: u64,
) -> Result<CompressedSpool> {
    anyhow::ensure!(
        store_path.starts_with("/nix/store/")
            && store_path.len() <= 4096
            && !store_path.contains('\0'),
        "invalid cache compression source"
    );
    anyhow::ensure!(
        matches!(algorithm, "none" | "zstd" | "xz")
            && maximum_bytes > 0
            && maximum_bytes <= MAX_SPOOL_BYTES,
        "invalid cache compression codec or limit"
    );
    let mut dump = Command::new("nix-store");
    dump.envs(aos_nix_env()).args(["--dump", store_path]);
    let codec = if algorithm == "none" {
        None
    } else {
        let mut command = Command::new(algorithm);
        command.arg("-c");
        if algorithm == "xz" {
            command.arg("-T1");
        }
        command.arg(format!("-{level}"));
        Some(command)
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let _cancel_on_drop = CancelOnDrop(cancelled.clone());
    tokio::task::spawn_blocking(move || pipeline(dump, codec, maximum_bytes, &cancelled))
        .await
        .context("cache compression task failed")?
}

fn pipeline(
    mut dump_command: Command,
    codec_command: Option<Command>,
    maximum_bytes: u64,
    cancelled: &AtomicBool,
) -> Result<CompressedSpool> {
    let mut dump = ChildCustody(Some(
        dump_command
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("starting cache source dump")?,
    ));
    let stdout = dump
        .0
        .as_mut()
        .and_then(|child| child.stdout.take())
        .context("cache source pipe is unavailable")?;
    let mut codec = ChildCustody(None);
    let mut input: Box<dyn std::io::Read> = match codec_command {
        None => Box::new(stdout),
        Some(mut command) => {
            codec.0 = Some(
                command
                    .stdin(Stdio::from(stdout))
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .context("starting cache compression codec")?,
            );
            Box::new(
                codec
                    .0
                    .as_mut()
                    .and_then(|child| child.stdout.take())
                    .context("cache codec pipe is unavailable")?,
            )
        }
    };
    let result = copy_spool(&mut input, maximum_bytes, cancelled);
    // Close the last pipe before waiting/killing either producer.
    drop(input);
    let spool = result?;
    if codec.0.is_some() {
        codec.finish()?;
    }
    dump.finish()?;
    Ok(spool)
}

fn copy_spool(
    input: &mut dyn std::io::Read,
    maximum_bytes: u64,
    cancelled: &AtomicBool,
) -> Result<CompressedSpool> {
    let mut file = tempfile::tempfile().context("creating private cache spool")?;
    let mut buffer = [0u8; COPY_BYTES];
    let mut length = 0u64;
    let mut hash = Sha256::new();
    loop {
        anyhow::ensure!(
            !cancelled.load(Ordering::Acquire),
            "cache compression cancelled"
        );
        let read = input
            .read(&mut buffer)
            .context("reading cache compression output")?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(read as u64)
            .context("cache compression size overflow")?;
        anyhow::ensure!(
            length <= maximum_bytes,
            "cache compressed object exceeds disk bound"
        );
        file.write_all(&buffer[..read])
            .context("writing private cache spool")?;
        hash.update(&buffer[..read]);
    }
    file.seek(std::io::SeekFrom::Start(0))
        .context("rewinding private cache spool")?;
    Ok(CompressedSpool {
        file,
        byte_size: length,
        sha256: hex::encode(hash.finalize()),
    })
}

#[cfg(test)]
mod tests;
