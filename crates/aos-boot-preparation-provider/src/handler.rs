//! Executes native boot preparations with durable evidence of uncertain outcomes.
//!
//! Each effect has a marker keyed by its logical identity. A started marker is
//! written before dispatch, so a crash cannot make an arbitrary command appear
//! safe to repeat. Completion binds both the effect and its semantic revision.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use aos_contract::{Sha256Digest, limits::JsonLimits};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::process::{CommandRunner, ProcessCommandRunner};

const MARKER_ROOT: &str = "/run/aos/boot-preparations";
const MESSAGE_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 256 * 1024,
    max_depth: 64,
    max_items: 65_536,
    max_string_bytes: 128 * 1024,
};

/// Executes boot preparations and retains evidence across interrupted dispatch.
pub struct BootPreparationProvider {
    marker_root: PathBuf,
    runner: Box<dyn CommandRunner>,
    validate_executable_file: bool,
}

impl BootPreparationProvider {
    /// Constructs the production provider.
    #[must_use]
    pub fn production() -> Self {
        Self {
            marker_root: MARKER_ROOT.into(),
            runner: Box::new(ProcessCommandRunner),
            validate_executable_file: true,
        }
    }

    /// Handles one native activation invocation.
    ///
    /// # Errors
    /// Returns an error for malformed input, invalid executable paths, uncertain
    /// prior command execution, marker I/O failures, or failed command execution.
    pub fn handle(&self, operation: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        let invocation: Invocation = MESSAGE_LIMITS.decode(bytes, "boot preparation invocation")?;
        let executable: Executable = serde_json::from_value(invocation.input.clone())
            .context("decoding boot preparation input")?;
        executable.validate(self.validate_executable_file)?;

        let marker = self.read_marker(&invocation.id)?;
        let response = match operation {
            "observe" => match marker {
                MarkerRead::Valid(marker)
                    if marker.id == invocation.id
                        && marker.revision == invocation.revision
                        && marker.completed =>
                {
                    json!({"status": "current", "outputs": outputs(&invocation)})
                }
                MarkerRead::Missing if invocation.action == Action::Remove => {
                    json!({"status": "absent"})
                }
                MarkerRead::Missing => json!({"status": "retry-safe"}),
                MarkerRead::Valid(marker) if marker.completed && marker.id == invocation.id => {
                    json!({"status": "retry-safe"})
                }
                _ => json!({"status": "indeterminate"}),
            },
            "apply" => {
                ensure!(
                    invocation.action == Action::Apply,
                    "apply action differs from invocation"
                );
                match marker {
                    MarkerRead::Valid(marker)
                        if marker.id == invocation.id
                            && marker.revision == invocation.revision
                            && marker.completed => {}
                    MarkerRead::Missing => self.execute(&invocation, &executable)?,
                    MarkerRead::Valid(marker) if marker.id == invocation.id && marker.completed => {
                        self.execute(&invocation, &executable)?;
                    }
                    _ => bail!("prior boot preparation outcome is indeterminate"),
                }
                outputs(&invocation)
            }
            "remove" => {
                ensure!(
                    invocation.action == Action::Remove,
                    "remove action differs from invocation"
                );
                // Transaction cleanup retires evidence; it cannot undo arbitrary
                // command side effects. The generation receipt prevents replay.
                ensure!(
                    !matches!(marker, MarkerRead::Invalid),
                    "invalid preparation marker"
                );
                match fs::remove_file(self.marker_path(&invocation.id)) {
                    Ok(()) => self.sync_root()?,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error).context("removing preparation marker"),
                }
                json!({})
            }
            _ => bail!("unsupported boot preparation operation {operation:?}"),
        };
        serde_json::to_vec(&response).context("encoding boot preparation response")
    }

    fn execute(&self, invocation: &Invocation, executable: &Executable) -> Result<()> {
        self.record(invocation, false)?;
        self.runner.run(executable, invocation.effect.timeout_ms)?;
        self.record(invocation, true)
    }

    fn read_marker(&self, id: &str) -> Result<MarkerRead> {
        let bytes = match fs::read(self.marker_path(id)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(MarkerRead::Missing);
            }
            Err(error) => return Err(error).context("reading preparation marker"),
        };
        Ok(
            match MESSAGE_LIMITS.decode::<CompletionMarker>(&bytes, "preparation marker") {
                Ok(marker) if marker.schema == "aos.boot.preparation-marker/v2" => {
                    MarkerRead::Valid(marker)
                }
                _ => MarkerRead::Invalid,
            },
        )
    }

    fn record(&self, invocation: &Invocation, completed: bool) -> Result<()> {
        fs::create_dir_all(&self.marker_root).context("creating preparation marker directory")?;
        let metadata = fs::symlink_metadata(&self.marker_root)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "marker root is not a directory"
        );

        let path = self.marker_path(&invocation.id);
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let marker = CompletionMarker {
            schema: "aos.boot.preparation-marker/v2".into(),
            id: invocation.id.clone(),
            revision: invocation.revision.clone(),
            completed,
        };
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .context("creating preparation marker")?;
        file.write_all(&serde_json::to_vec(&marker)?)?;
        file.sync_all().context("syncing preparation marker")?;
        drop(file);
        fs::rename(&temporary, &path).context("publishing preparation marker")?;
        self.sync_root()
    }

    fn sync_root(&self) -> Result<()> {
        File::open(&self.marker_root)?
            .sync_all()
            .context("syncing preparation marker directory")
    }

    fn marker_path(&self, id: &str) -> PathBuf {
        let digest = Sha256Digest::of_bytes(id.as_bytes());
        self.marker_root
            .join(digest.to_string().trim_start_matches("sha256:"))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Executable {
    path: String,
    pub(super) arguments: Vec<String>,
}

impl Executable {
    pub(super) fn path(&self) -> &Path {
        Path::new(&self.path)
    }

    fn validate(&self, inspect_file: bool) -> Result<()> {
        let path = self.path();
        ensure!(
            path.is_absolute()
                && path.starts_with("/nix/store")
                && path
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
            "preparation executable is not an immutable normalized store path"
        );
        ensure!(
            self.arguments.len() <= 128
                && self.arguments.iter().map(String::len).sum::<usize>() <= 64 * 1024
                && self
                    .arguments
                    .iter()
                    .all(|argument| !argument.contains('\0')),
            "invalid preparation arguments"
        );
        if inspect_file {
            let resolved = fs::canonicalize(path).context("resolving preparation executable")?;
            ensure!(
                resolved.starts_with("/nix/store"),
                "preparation executable resolves outside immutable store"
            );
            let metadata = fs::metadata(resolved)?;
            ensure!(
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
                "preparation is not executable"
            );
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletionMarker {
    schema: String,
    id: String,
    revision: String,
    completed: bool,
}

enum MarkerRead {
    Missing,
    Invalid,
    Valid(CompletionMarker),
}

fn outputs(invocation: &Invocation) -> Value {
    json!({"resource": invocation.id})
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tempfile::tempdir;

    use super::*;

    struct CountingRunner(Arc<AtomicUsize>);

    impl CommandRunner for CountingRunner {
        fn run(&self, _: &Executable, _: u64) -> Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn invocation() -> Invocation {
        serde_json::from_value(json!({
            "id": "boot-preparation", "revision": "first", "action": "apply", "previous": null,
            "input": {"path": "/nix/store/00000000000000000000000000000000-prepare/bin/prepare", "arguments": []},
            "effect": {
                "owner": "boot", "identity": ["host", "prepare"], "input": {}, "inputs": {},
                "input_type": {"kind": "submodule", "open": false, "fields": {}}, "after": [],
                "results": {"resource": {"kind": "string"}}, "dependencies": [], "revision": "first",
                "lifetime": "transaction", "timeout_ms": 1000,
                "handler": {"kind": "process", "artifact": "/nix/store/00000000000000000000000000000000-handler", "executable": "/nix/store/00000000000000000000000000000000-handler/bin/handler"}
            }
        })).expect("native invocation")
    }

    #[test]
    fn completed_preparation_is_not_replayed_and_teardown_retires_evidence() {
        let directory = tempdir().expect("marker directory");
        let count = Arc::new(AtomicUsize::new(0));
        let provider = BootPreparationProvider {
            marker_root: directory.path().into(),
            runner: Box::new(CountingRunner(count.clone())),
            validate_executable_file: false,
        };
        let mut invocation = invocation();
        let bytes = serde_json::to_vec(&invocation).expect("encode invocation");

        provider.handle("apply", &bytes).expect("first apply");
        provider.handle("apply", &bytes).expect("repeated apply");
        let observation: Value =
            serde_json::from_slice(&provider.handle("observe", &bytes).expect("observe"))
                .expect("response");

        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(observation["status"], "current");
        invocation.action = Action::Remove;
        let bytes = serde_json::to_vec(&invocation).expect("encode removal");
        provider.handle("remove", &bytes).expect("remove evidence");
        let observation: Value =
            serde_json::from_slice(&provider.handle("observe", &bytes).expect("observe removal"))
                .expect("response");
        assert_eq!(observation["status"], "absent");
    }

    #[test]
    fn interrupted_dispatch_is_indeterminate_and_never_retried() {
        let directory = tempdir().expect("marker directory");
        let count = Arc::new(AtomicUsize::new(0));
        let provider = BootPreparationProvider {
            marker_root: directory.path().into(),
            runner: Box::new(CountingRunner(count.clone())),
            validate_executable_file: false,
        };
        let invocation = invocation();
        provider
            .record(&invocation, false)
            .expect("record dispatch intent");
        let bytes = serde_json::to_vec(&invocation).expect("encode invocation");

        let observation: Value =
            serde_json::from_slice(&provider.handle("observe", &bytes).expect("observe"))
                .expect("response");
        assert_eq!(observation["status"], "indeterminate");
        assert!(provider.handle("apply", &bytes).is_err());
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn preparation_rejects_mutable_or_parent_traversing_paths() {
        for path in ["/tmp/prepare", "/nix/store/../prepare"] {
            let executable = Executable {
                path: path.into(),
                arguments: vec![],
            };
            assert!(executable.validate(false).is_err(), "{path}");
        }
    }
}
