//! Bounded invocation of exact assembly-pinned executables.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read as _, Seek as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use rustix::fs::{Mode, OFlags, open};
use tokio::process::Command;

use crate::input::VerifiedTool;

const MAX_DIAGNOSTIC_BYTES: u64 = 256 * 1024;

/// One exact executable and its sanitized process environment.
#[derive(Clone, Debug)]
pub struct PinnedTool {
    executable: PathBuf,
    working_directory: PathBuf,
    timeout: Duration,
    environment: BTreeMap<String, String>,
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

/// Evidence from a successful invocation whose stdout became a file.
#[derive(Debug)]
pub struct ToolFileOutput {
    /// Exact byte length installed at the requested output path.
    pub size_bytes: u64,
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
            environment: BTreeMap::new(),
        })
    }

    /// Creates a command wrapper from an assembly-verified tool specification.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::new`]. The tool
    /// environment has already passed the assembly contract's closed allowlist.
    pub fn from_verified(
        tool: VerifiedTool,
        working_directory: PathBuf,
        timeout: Duration,
    ) -> Result<Self> {
        let mut pinned = Self::new(tool.executable, working_directory, timeout)?;
        pinned.environment = tool.environment;
        Ok(pinned)
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
        let status = self
            .execute(arguments, Stdio::null(), &stdout, &stderr)
            .await?;
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

    /// Runs with one exact regular file on stdin and bounded captured output.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as [`Self::run`], or when
    /// `input` is linked, special, or cannot be opened without following a
    /// final symbolic link.
    pub async fn run_with_input<I, S>(
        &self,
        arguments: I,
        input: &Path,
        maximum_stdout_bytes: u64,
    ) -> Result<ToolOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let input = open_regular_nofollow(input)?;
        let stdout = tempfile::tempfile()?;
        let stderr = tempfile::tempfile()?;
        let status = self
            .execute(arguments, Stdio::from(input), &stdout, &stderr)
            .await?;
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

    /// Runs with optional exact-file stdin and transactionally installs stdout.
    ///
    /// # Errors
    ///
    /// Returns an error when the destination exists, the process fails or
    /// times out, stdout is empty/oversized, or durable installation fails.
    pub async fn run_to_new_file<I, S>(
        &self,
        arguments: I,
        input: Option<&Path>,
        output: &Path,
        maximum_output_bytes: u64,
    ) -> Result<ToolFileOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        if maximum_output_bytes == 0 || output.symlink_metadata().is_ok() {
            bail!("exact-tool file output needs a nonzero limit and absent destination");
        }
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let temporary = tempfile::NamedTempFile::new_in(parent)?;
        let stderr = tempfile::tempfile()?;
        let stdin = input
            .map(open_regular_nofollow)
            .transpose()?
            .map_or_else(Stdio::null, Stdio::from);
        let status = self
            .execute(arguments, stdin, temporary.as_file(), &stderr)
            .await?;
        let stderr = read_bounded(stderr, MAX_DIAGNOSTIC_BYTES, "exact-tool stderr")?;
        if !status.success() {
            bail!(
                "exact tool {} failed with {status}: {}",
                self.executable.display(),
                String::from_utf8_lossy(&stderr).trim()
            );
        }
        let size_bytes = temporary.as_file().metadata()?.len();
        if size_bytes == 0 || size_bytes > maximum_output_bytes {
            bail!("exact-tool file output is empty or exceeds its byte limit");
        }
        temporary.as_file().sync_all()?;
        temporary
            .persist_noclobber(output)
            .map_err(|error| error.error)
            .with_context(|| format!("installing exact-tool output {}", output.display()))?;
        File::open(parent)?.sync_all()?;
        Ok(ToolFileOutput {
            size_bytes,
            stderr,
            status,
        })
    }

    async fn execute<I, S>(
        &self,
        arguments: I,
        stdin: Stdio,
        stdout: &File,
        stderr: &File,
    ) -> Result<ExitStatus>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut child = self.command(arguments, stdin, stdout, stderr)?.spawn()?;
        match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(status) => Ok(status?),
            Err(_) => {
                child.kill().await?;
                let _ = child.wait().await;
                bail!("exact tool {} timed out", self.executable.display());
            }
        }
    }

    fn command<I, S>(
        &self,
        arguments: I,
        stdin: Stdio,
        stdout: &File,
        stderr: &File,
    ) -> Result<Command>
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
            .envs(&self.environment)
            .kill_on_drop(true)
            .stdin(stdin)
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

fn open_regular_nofollow(path: &Path) -> Result<File> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening exact-tool input {}", path.display()))?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        bail!("exact-tool input must be a single-link regular file");
    }
    Ok(file)
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
