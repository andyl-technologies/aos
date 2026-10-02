//! Checked, temporary source views for pure evaluation through any selected store.
//!
//! Logical store identities remain the authority and retention keys. Nix exports
//! their NARs through its store accessor; private snapshots supply readable input
//! to fetchTree without interpreting a store URI as a host filesystem path.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, ensure};
use aos_ability_runtime::adapter::RuntimeControl;
use aos_contract::Sha256Digest;

use super::nix::{locked_evaluator_input, store_root_and_suffix};
use super::process::run_bounded_with_input_limit;

// Source modules are bounded independently of the installed payload closure.
const SOURCE_NAR_LIMIT: usize = 64 * 1024 * 1024;

struct SourceView {
    path: PathBuf,
    nar_hash: String,
}

/// Keeps original identities separate from private, hash-checked read locations.
pub(super) struct SourceViews {
    directory: tempfile::TempDir,
    roots: BTreeMap<PathBuf, SourceView>,
}

impl SourceViews {
    /// Exports and restores each distinct source root within the shared deadline.
    pub(super) fn prepare<'a>(
        nix_store: &Path,
        paths: impl IntoIterator<Item = &'a Path>,
        staging: &Path,
        control: &dyn RuntimeControl,
    ) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("evaluation-sources-")
            .tempdir_in(staging)?;
        let mut roots = BTreeMap::new();
        let selected = aos_core::nix::identity::store_command(nix_store)?;
        // Nix selects its legacy command mode from argv[0]. Resolving this
        // symlink to the multicall `nix` binary would change --restore semantics.
        let executable = Path::new(selected.get_program())
            .parent()
            .context("selected Nix suite has no directory")?
            .join("nix-store");

        for identity in paths {
            let (root, _) = store_root_and_suffix(identity)?;
            if roots.contains_key(&root) {
                continue;
            }
            let name = root.file_name().context("source root has no name")?;
            let path = directory.path().join(name);
            let mut dump = aos_core::nix::identity::store_nar_command(
                &executable,
                root.to_str().context("source root is not UTF-8")?,
            )?;
            let environment = explicit_environment(&dump);
            let nar = run_bounded_with_input_limit(
                &mut dump,
                None,
                0,
                SOURCE_NAR_LIMIT,
                control,
                &environment,
            )
            .with_context(|| format!("exporting evaluation source {}", root.display()))?;
            ensure!(
                nar.status.success(),
                "exporting evaluation source {} failed: {}",
                root.display(),
                String::from_utf8_lossy(&nar.stderr)
            );
            let nar_hash = Sha256Digest::of_bytes(&nar.stdout).to_string();

            let mut restore = Command::new(&executable);
            restore.arg("--restore").arg(&path);
            let restored = run_bounded_with_input_limit(
                &mut restore,
                Some(&nar.stdout),
                SOURCE_NAR_LIMIT,
                64 * 1024,
                control,
                &[],
            )
            .context("restoring a private evaluation source")?;
            ensure!(
                restored.status.success(),
                "restoring evaluation source {} failed: {}",
                root.display(),
                String::from_utf8_lossy(&restored.stderr)
            );
            roots.insert(root, SourceView { path, nar_hash });
        }

        Ok(Self { directory, roots })
    }

    /// Supplies the one private read prefix authorized for the pure evaluator.
    pub(super) fn directory(&self) -> &Path {
        self.directory.path()
    }

    /// Locks a readable snapshot to the exported original NAR identity.
    pub(super) fn expression(&self, identity: &Path) -> Result<String> {
        let (root, suffix) = store_root_and_suffix(identity)?;
        let view = self
            .roots
            .get(&root)
            .context("source was not prepared for evaluation")?;
        locked_evaluator_input(identity, &view.path.join(suffix), &view.nar_hash)
    }
}

fn explicit_environment(command: &Command) -> Vec<(OsString, OsString)> {
    command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
        .collect()
}
