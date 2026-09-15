//! Exact executable validation and bounded process execution.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::ArtifactReference;
use serde::{Deserialize, Serialize};

const MAX_OUTPUT_BYTES: u64 = 256 * 1024;

/// Carries one resolved executable reference from a provider realization.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableReference {
    artifact: ArtifactReference,
    entry_point: String,
    arguments: Vec<String>,
}

/// Pins one exact executable path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Executable {
    artifact: ArtifactReference,
    entry_point: String,
}

impl ExecutableReference {
    /// Validates and resolves the executable without accepting preset arguments.
    pub fn resolve(self) -> Result<Executable> {
        ensure!(
            self.arguments.is_empty(),
            "executable carries undeclared arguments"
        );
        let executable = Executable {
            artifact: self.artifact,
            entry_point: self.entry_point,
        };
        executable.validate()?;
        Ok(executable)
    }
}

impl Executable {
    /// Returns the exact executable path.
    pub fn path(&self) -> PathBuf {
        Path::new(&self.artifact.store_path).join(&self.entry_point)
    }

    fn validate(&self) -> Result<()> {
        let root = Path::new(&self.artifact.store_path);
        ensure!(
            root.is_absolute() && root.starts_with("/nix/store"),
            "artifact is outside the immutable store"
        );
        let relative = Path::new(&self.entry_point);
        ensure!(
            !self.entry_point.is_empty()
                && !relative.is_absolute()
                && relative
                    .components()
                    .all(|part| matches!(part, Component::Normal(_))),
            "executable entry point is not normalized"
        );
        let canonical_root = fs::canonicalize(root).context("resolving executable artifact")?;
        let canonical = fs::canonicalize(self.path()).context("resolving executable")?;
        ensure!(
            canonical.starts_with(canonical_root),
            "executable escapes its artifact"
        );
        let metadata = fs::metadata(canonical).context("inspecting executable")?;
        ensure!(metadata.is_file(), "executable is not a regular file");
        ensure!(
            metadata.permissions().mode() & 0o111 != 0,
            "executable is not executable"
        );
        Ok(())
    }

    /// Runs the executable with a cleared environment and bounded deadline.
    // Provider command deadlines are process-local control flow and never enter
    // a deterministic Crucible state path.
    #[allow(clippy::disallowed_methods)]
    pub fn run(&self, arguments: &[&str], remaining_millis: u64) -> Result<Output> {
        ensure!(remaining_millis > 0, "native command deadline expired");
        let mut child = Command::new(self.path())
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
                child.kill().context("terminating expired native command")?;
                let _ = child.wait();
                let _ = join_reader(stdout_reader, "stdout");
                let _ = join_reader(stderr_reader, "stderr");
                bail!("native command deadline expired");
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = join_reader(stdout_reader, "stdout")?;
        let stderr = join_reader(stderr_reader, "stderr")?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
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
