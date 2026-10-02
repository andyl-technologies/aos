//! Streams exact NAR content identities through a caller-selected store tool.
//!
//! The caller authenticates the executable and configures its store environment.
//! This boundary owns the subprocess deadline, stream hash, and bounded errors.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use aos_contract::Sha256Digest;
use sha2::{Digest as _, Sha256};

const ERROR_LIMIT: u64 = 64 * 1024;

/// Selects the modern accessor from an immutable Nix tool suite.
///
/// The supplied executable identifies an installed Nix suite. Its exact sibling
/// `nix` executable addresses objects through the selected store, including
/// isolated stores whose logical paths are not host filesystem paths.
///
/// # Errors
/// Returns an error when either executable is unavailable, the supplied tool
/// does not belong to an immutable store path, or store routing is invalid.
pub fn store_command(executable: &Path) -> Result<Command> {
    ensure!(
        executable.is_absolute(),
        "store executable must be absolute"
    );
    let executable = std::fs::canonicalize(executable)
        .context("resolving the selected immutable Nix tool suite")?;
    ensure!(
        executable.starts_with("/nix/store"),
        "store executable is outside the immutable store"
    );
    let nix = executable
        .parent()
        .context("store executable has no directory")?
        .join("nix");
    ensure!(
        nix.is_file(),
        "selected Nix tool suite has no nix executable"
    );
    let mut command = Command::new(nix);
    super::configure_aos_nix_store(&mut command)?;
    command.args(["--extra-experimental-features", "nix-command"]);
    Ok(command)
}

/// Constructs a NAR dump through the selected store's accessor.
///
/// Unlike legacy `nix-store --dump`, this reads the selected store's object
/// rather than interpreting its logical identity as a host filesystem path.
///
/// # Errors
/// Returns an error when the requested root, tool suite, or store routing is
/// invalid, as described by [`store_command`].
pub fn store_nar_command(executable: &Path, store_root: &str) -> Result<Command> {
    let root = Path::new(store_root);
    ensure!(
        root.parent() == Some(Path::new("/nix/store"))
            && root.components().all(|part| !matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )),
        "NAR lookup requires an exact canonical store root"
    );
    let mut command = store_command(executable)?;
    command.args(["store", "dump-path", store_root]);
    Ok(command)
}

/// Hashes the exact NAR stream from a fully configured command.
///
/// The caller supplies the transport and all arguments. Output is streamed
/// with constant memory; stderr is drained while retaining at most 64 KiB.
///
/// # Errors
/// Returns an error for a zero deadline, process failure, timeout, byte-count
/// overflow, or a failed stream reader. The caller validates NAR structure or
/// compares the digest to an authenticated expected identity.
#[allow(
    clippy::disallowed_methods,
    reason = "subprocess deadlines use host monotonic time"
)]
pub fn hash_nar_command(mut command: Command, timeout: Duration) -> Result<(Sha256Digest, u64)> {
    ensure!(!timeout.is_zero(), "NAR verification requires a deadline");
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("NAR deadline overflow")?;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting the configured NAR stream")?;
    let Some(stdout) = child.stdout.take() else {
        terminate(&mut child);
        bail!("NAR stdout was not piped");
    };
    let Some(stderr) = child.stderr.take() else {
        terminate(&mut child);
        bail!("NAR stderr was not piped");
    };
    let digest = thread::spawn(move || hash_stream(stdout));
    let errors = thread::spawn(move || error_stream(stderr));

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => break Err(anyhow::anyhow!("NAR verification exceeded its deadline")),
            Err(error) => break Err(error).context("polling NAR verification"),
        }
    };
    if status.is_err() {
        terminate(&mut child);
    }
    let digest = digest
        .join()
        .map_err(|_| anyhow::anyhow!("NAR hash worker panicked"))?;
    let errors = errors
        .join()
        .map_err(|_| anyhow::anyhow!("NAR error worker panicked"))?;
    let status = status?;
    let errors = errors?;
    ensure!(
        status.success(),
        "NAR stream command failed: {}",
        String::from_utf8_lossy(&errors).trim()
    );
    digest
}

fn hash_stream(mut reader: impl Read) -> Result<(Sha256Digest, u64)> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .context("NAR size overflow")?;
        hasher.update(&buffer[..count]);
    }
    Ok((Sha256Digest::from_bytes(hasher.finalize().into()), size))
}

fn error_stream(mut reader: impl Read) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let retain = count.min((ERROR_LIMIT as usize).saturating_sub(output.len()));
        output.extend_from_slice(&buffer[..retain]);
    }
    Ok(output)
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_exact_stream_bytes_and_drains_bounded_errors() {
        let bytes = vec![42_u8; 200_000];
        let (digest, size) = hash_stream(bytes.as_slice()).unwrap();

        assert_eq!(digest, Sha256Digest::of_bytes(&bytes));
        assert_eq!(size, bytes.len() as u64);
        assert_eq!(
            error_stream(bytes.as_slice()).unwrap().len(),
            ERROR_LIMIT as usize
        );
    }
}
