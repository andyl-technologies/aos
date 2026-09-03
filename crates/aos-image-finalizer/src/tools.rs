//! Bounded invocation of exact assembly-pinned executables.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read as _, Seek as _};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use tokio::process::Command;

const MAX_DIAGNOSTIC_BYTES: u64 = 256 * 1024;

/// One exact executable and its sanitized process environment.
#[derive(Clone, Debug)]
pub struct PinnedTool {
    executable: PathBuf,
    working_directory: PathBuf,
    timeout: Duration,
}

/// Bounded captured output from a successful exact-tool invocation.
#[derive(Debug)]
pub struct ToolOutput {
    /// Exact standard output bytes.
    pub stdout: Vec<u8>,
    /// Bounded standard-error evidence emitted on success.
    pub stderr: Vec<u8>,
    /// Process exit status.
    pub status: ExitStatus,
}

impl PinnedTool {
    /// Creates a command wrapper for a previously verified executable.
    ///
    /// # Errors
    ///
    /// Returns an error unless the working directory is an absolute directory.
    pub fn new(executable: PathBuf, working_directory: PathBuf, timeout: Duration) -> Result<Self> {
        if !working_directory.is_absolute() || !working_directory.is_dir() {
            bail!("exact-tool working directory must be an absolute directory");
        }
        if timeout.is_zero() || timeout > Duration::from_secs(60 * 60) {
            bail!("exact-tool timeout must be within 1ns..=1h");
        }
        Ok(Self {
            executable,
            working_directory,
            timeout,
        })
    }

    /// Runs the tool with a cleared deterministic environment and bounded
    /// stdout/stderr evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when the tool cannot run, exits unsuccessfully, or
    /// writes more than `maximum_stdout_bytes` or the diagnostic ceiling.
    pub async fn run<I, S>(&self, arguments: I, maximum_stdout_bytes: u64) -> Result<ToolOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let stdout = tempfile::tempfile()?;
        let stderr = tempfile::tempfile()?;
        let mut child = self.command(arguments, &stdout, &stderr)?.spawn()?;
        let status = match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                child.kill().await?;
                let _ = child.wait().await;
                bail!("exact tool {} timed out", self.executable.display());
            }
        };
        let stdout = read_bounded(stdout, maximum_stdout_bytes, "exact-tool stdout")?;
        let stderr = read_bounded(stderr, MAX_DIAGNOSTIC_BYTES, "exact-tool stderr")?;
        if !status.success() {
            bail!(
                "exact tool {} failed with {status}: {}",
                self.executable.display(),
                String::from_utf8_lossy(&stderr).trim()
            );
        }
        Ok(ToolOutput {
            stdout,
            stderr,
            status,
        })
    }

    fn command<I, S>(&self, arguments: I, stdout: &File, stderr: &File) -> Result<Command>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(&self.executable);
        command
            .args(arguments)
            .current_dir(&self.working_directory)
            .env_clear()
            .env("HOME", &self.working_directory)
            .env("LC_ALL", "C")
            .env("SOURCE_DATE_EPOCH", "0")
            .env("TZ", "UTC")
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout.try_clone()?))
            .stderr(Stdio::from(stderr.try_clone()?));
        Ok(command)
    }

    /// Returns the exact executable path.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

/// Converts string-like arguments into an owned vector for conditional command
/// construction.
#[must_use]
pub fn arguments(values: impl IntoIterator<Item = impl Into<OsString>>) -> Vec<OsString> {
    values.into_iter().map(Into::into).collect()
}

fn read_bounded(mut file: File, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let length = file.metadata()?.len();
    if length > maximum {
        bail!("{label} exceeds its byte limit");
    }
    file.rewind()?;
    let mut bytes = Vec::with_capacity(usize::try_from(length)?);
    file.read_to_end(&mut bytes)
        .with_context(|| format!("reading {label}"))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_working_directories() {
        assert!(
            PinnedTool::new(
                PathBuf::from("/tool"),
                PathBuf::from("relative"),
                Duration::from_secs(30),
            )
            .is_err()
        );
    }
}
