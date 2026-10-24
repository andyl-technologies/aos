//! Exact executable validation and bounded process execution.

use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};

const MAX_OUTPUT_BYTES: u64 = 256 * 1024;

/// Distinguishes an expired command from an ordinary native-tool failure.
#[derive(Debug)]
pub(crate) struct CommandDeadlineExpired;

impl std::fmt::Display for CommandDeadlineExpired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native command deadline expired")
    }
}

impl std::error::Error for CommandDeadlineExpired {}

/// Runs an immutable executable with cleared environment and bounded I/O.
///
/// # Errors
/// Returns an error for a non-store path, unavailable executable, failed process
/// transport, output overflow, or expired deadline.
#[allow(clippy::disallowed_methods)]
pub fn run_native(path: &Path, arguments: &[&str], remaining_millis: u64) -> Result<Output> {
    ensure!(
        path.is_absolute() && path.starts_with("/nix/store"),
        "native executable is outside immutable store"
    );
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "native executable path is not normalized"
    );
    let store_root = path.components().take(4).collect::<PathBuf>();
    let canonical = fs::canonicalize(path).context("resolving native executable")?;
    ensure!(
        canonical.starts_with(&store_root),
        "native executable escapes its store artifact"
    );
    ensure!(remaining_millis > 0, "native command deadline expired");
    // Native tools have their own captured pipes. Report their lifecycle on the
    // provider's diagnostic pipe so a host can locate an incomplete operation.
    let _ = writeln!(
        std::io::stderr(),
        "storage: starting {} ({remaining_millis} ms)",
        path.display()
    );
    let mut child = Command::new(path)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting exact native command")?;
    let stdout = child
        .stdout
        .take()
        .context("native command stdout is unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("native command stderr is unavailable")?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(remaining_millis))
        .context("native command deadline overflow")?;
    let status = loop {
        if let Some(status) = child.try_wait().context("waiting for native command")? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = writeln!(
                std::io::stderr(),
                "storage: deadline expired for {}",
                path.display()
            );
            child.kill().context("terminating expired native command")?;
            let _ = child.wait();
            let _ = join_reader(stdout_reader, "stdout");
            let _ = join_reader(stderr_reader, "stderr");
            return Err(CommandDeadlineExpired.into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    let _ = writeln!(
        std::io::stderr(),
        "storage: exited {} ({status}); collecting output",
        path.display()
    );
    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;
    let _ = writeln!(
        std::io::stderr(),
        "storage: completed {} ({status})",
        path.display()
    );
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn read_bounded(reader: impl std::io::Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(MAX_OUTPUT_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_OUTPUT_BYTES as usize,
        "native command output exceeds the bound"
    );
    Ok(bytes)
}

fn join_reader(reader: thread::JoinHandle<Result<Vec<u8>>>, stream: &str) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("native command {stream} reader panicked"))?
        .with_context(|| format!("reading native command {stream}"))
}
