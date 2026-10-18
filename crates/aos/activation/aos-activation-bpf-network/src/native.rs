//! Immutable artifact resolution and bounded native loader execution.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use serde::{Deserialize, Serialize};

const MAX_COMMAND_OUTPUT_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Executable {
    path: PathBuf,
}

impl Executable {
    pub(super) fn from_process(immutable_root: &Path) -> Result<Self> {
        let current = std::env::current_exe().context("resolving handler executable")?;
        let package = current
            .parent()
            .and_then(Path::parent)
            .context("handler has no package root")?;
        let path = resolve_contained_path(
            package,
            "libexec/aos-ebpf-net-policy-loader",
            immutable_root,
            "loader executable",
        )?;
        let metadata = fs::metadata(&path)?;
        ensure!(
            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            "loader is not executable"
        );
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
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

pub(super) fn resolve_artifact_path(reference: &str, immutable_root: &Path) -> Result<PathBuf> {
    let path = Path::new(reference);
    let relative = path
        .strip_prefix(immutable_root)
        .context("policy is outside immutable store")?;
    let mut components = relative.components();
    let package = components.next().context("policy has no package root")?;
    ensure!(
        matches!(package, Component::Normal(_)),
        "invalid package root"
    );
    let root = immutable_root.join(package.as_os_str());
    let relative = components
        .as_path()
        .to_str()
        .context("non-UTF8 artifact path")?;
    let path = resolve_contained_path(&root, relative, immutable_root, "policy artifact")?;
    ensure!(path.is_file(), "policy artifact is not a regular file");
    Ok(path)
}

fn resolve_contained_path(
    root: &Path,
    relative: &str,
    immutable_root: &Path,
    label: &str,
) -> Result<PathBuf> {
    ensure!(
        root.is_absolute() && root.starts_with(immutable_root),
        "{label} is outside immutable root"
    );
    let relative_path = Path::new(relative);
    ensure!(
        !relative.is_empty()
            && relative_path
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
        "{label} path is not normalized"
    );
    let canonical_root = fs::canonicalize(root)?;
    ensure!(
        canonical_root.starts_with(fs::canonicalize(immutable_root)?),
        "{label} package escapes immutable root"
    );
    let canonical = fs::canonicalize(root.join(relative))?;
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
