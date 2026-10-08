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
pub(crate) struct SourceViews {
    directory: tempfile::TempDir,
    roots: BTreeMap<PathBuf, SourceView>,
}

impl SourceViews {
    /// Exports and restores each distinct source root within the shared deadline.
    pub(crate) fn prepare<'a>(
        nix_store: &Path,
        paths: impl IntoIterator<Item = &'a Path>,
        staging: &Path,
        control: &dyn RuntimeControl,
    ) -> Result<Self> {
        let directory = source_directory(staging)?;
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

    /// Returns the private read location for an original prepared identity.
    ///
    /// # Errors
    /// Returns an error for a noncanonical identity or an unprepared source root.
    pub(crate) fn read_path(&self, identity: &Path) -> Result<PathBuf> {
        let (root, suffix) = store_root_and_suffix(identity)?;
        let view = self.roots.get(&root).context("source was not prepared")?;
        Ok(view.path.join(suffix))
    }

    /// Returns the exported NAR hash for a prepared original source root.
    ///
    /// # Errors
    /// Returns an error for a noncanonical identity or an unprepared source root.
    pub(crate) fn nar_hash(&self, identity: &Path) -> Result<&str> {
        let (root, _) = store_root_and_suffix(identity)?;
        let view = self.roots.get(&root).context("source was not prepared")?;
        Ok(&view.nar_hash)
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

fn source_directory(staging: &Path) -> Result<tempfile::TempDir> {
    // fetchTree rejects symlink ancestors even for NAR-hash-pinned inputs.
    // Use one physical prefix for restoration, restricted reads, and fetching.
    let staging =
        std::fs::canonicalize(staging).context("resolving evaluation staging directory")?;
    Ok(tempfile::Builder::new()
        .prefix("evaluation-sources-")
        .tempdir_in(staging)?)
}

fn explicit_environment(command: &Command) -> Vec<(OsString, OsString)> {
    command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn symlink_profile_staging_preserves_source_identity_and_hash() {
        let temporary = tempfile::tempdir().unwrap();
        let physical = temporary.path().join("physical-profiles");
        std::fs::create_dir(&physical).unwrap();
        let profile = temporary.path().join("profiles");
        std::os::unix::fs::symlink(&physical, &profile).unwrap();
        let staging = profile.join("operation");
        std::fs::create_dir(&staging).unwrap();
        let directory = source_directory(&staging).unwrap();
        let identity = PathBuf::from(format!("/nix/store/{}-operator-source", "a".repeat(32)));
        let path = directory.path().join(identity.file_name().unwrap());
        std::fs::create_dir(&path).unwrap();
        let digest = Sha256Digest::of_bytes(b"original exported NAR");
        let nar_hash = digest.to_string();
        let nar_sri = format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(digest.as_bytes())
        );
        let views = SourceViews {
            directory,
            roots: BTreeMap::from([(
                identity.clone(),
                SourceView {
                    path: path.clone(),
                    nar_hash: nar_hash.clone(),
                },
            )]),
        };

        let expression = views.expression(&identity).unwrap();

        assert!(views.directory().starts_with(physical.join("operation")));
        assert_eq!(views.read_path(&identity).unwrap(), path);
        assert_eq!(views.nar_hash(&identity).unwrap(), nar_hash);
        assert!(expression.contains(path.to_str().unwrap()));
        assert!(expression.contains(&super::super::nix::nix_string(&nar_sri)));
        assert!(!expression.contains(profile.to_str().unwrap()));
    }
}
