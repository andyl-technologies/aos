//! Immutable artifact resolution and bounded native loader execution.

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

const MAX_COMMAND_OUTPUT_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactPathReference {
    pub(super) artifact: ArtifactReference,
    pub(super) path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutableReference {
    artifact: ArtifactReference,
    entry_point: String,
    arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Executable {
    artifact: ArtifactReference,
    entry_point: String,
}

impl ExecutableReference {
    pub(super) fn resolve(self, immutable_root: &Path) -> Result<Executable> {
        ensure!(self.arguments.is_empty(), "loader has preset arguments");
        let executable = Executable {
            artifact: self.artifact,
            entry_point: self.entry_point,
        };
        executable.validate(immutable_root)?;
        Ok(executable)
    }
}

impl Executable {
    fn path(&self) -> PathBuf {
        Path::new(&self.artifact.store_path).join(&self.entry_point)
    }

    fn validate(&self, immutable_root: &Path) -> Result<()> {
        let path = resolve_contained_path(
            &self.artifact,
            &self.entry_point,
            immutable_root,
            "loader executable",
        )?;
        let metadata = fs::metadata(path).context("inspecting BPF network loader")?;
        ensure!(
            metadata.is_file(),
            "BPF network loader is not a regular file"
        );
        ensure!(
            metadata.permissions().mode() & 0o111 != 0,
            "BPF network loader is not executable"
        );
        Ok(())
    }

    pub(super) fn run(&self, arguments: &[&str], remaining_millis: u64) -> Result<Output> {
        ensure!(remaining_millis > 0, "BPF network loader deadline expired");
        let mut child = Command::new(self.path())
            .args(arguments)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting exact BPF network loader")?;
        let stdout = child
            .stdout
            .take()
            .context("loader stdout is unavailable")?;
        let stderr = child
            .stderr
            .take()
            .context("loader stderr is unavailable")?;
        let stdout_reader = thread::spawn(move || read_bounded(stdout));
        let stderr_reader = thread::spawn(move || read_bounded(stderr));
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining_millis))
            .context("BPF network loader deadline overflow")?;
        let status = loop {
            if let Some(status) = child.try_wait().context("waiting for BPF network loader")? {
                break status;
            }
            if Instant::now() >= deadline {
                child
                    .kill()
                    .context("terminating expired BPF network loader")?;
                let _ = child.wait();
                let _ = join_reader(stdout_reader, "stdout");
                let _ = join_reader(stderr_reader, "stderr");
                bail!("BPF network loader deadline expired");
            }
            thread::sleep(Duration::from_millis(10));
        };
        Ok(Output {
            status,
            stdout: join_reader(stdout_reader, "stdout")?,
            stderr: join_reader(stderr_reader, "stderr")?,
        })
    }
}

pub(super) fn resolve_artifact_path(
    reference: &ArtifactPathReference,
    immutable_root: &Path,
) -> Result<PathBuf> {
    let path = resolve_contained_path(
        &reference.artifact,
        &reference.path,
        immutable_root,
        "policy artifact",
    )?;
    ensure!(path.is_file(), "policy artifact is not a regular file");
    Ok(path)
}

fn resolve_contained_path(
    artifact: &ArtifactReference,
    relative: &str,
    immutable_root: &Path,
    label: &str,
) -> Result<PathBuf> {
    let root = Path::new(&artifact.store_path);
    ensure!(
        root.is_absolute() && root.starts_with(immutable_root),
        "{label} is outside the immutable artifact root"
    );
    let relative_path = Path::new(relative);
    ensure!(
        !relative.is_empty()
            && !relative_path.is_absolute()
            && relative_path
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "{label} path is not normalized"
    );
    let canonical_root =
        fs::canonicalize(root).with_context(|| format!("resolving {label} root"))?;
    let canonical =
        fs::canonicalize(root.join(relative)).with_context(|| format!("resolving {label}"))?;
    ensure!(
        canonical.starts_with(canonical_root),
        "{label} escapes its artifact"
    );
    Ok(canonical)
}

fn read_bounded(reader: impl std::io::Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_COMMAND_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_COMMAND_OUTPUT_BYTES,
        "BPF network loader output exceeds its bound"
    );
    Ok(bytes)
}

fn join_reader(reader: thread::JoinHandle<Result<Vec<u8>>>, stream: &str) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("BPF network loader {stream} reader panicked"))?
        .with_context(|| format!("reading BPF network loader {stream}"))
}

pub(super) fn path_text(path: &Path) -> Result<&str> {
    path.to_str().context("BPF network path is not UTF-8")
}
