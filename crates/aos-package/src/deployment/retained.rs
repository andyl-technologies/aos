//! Exports checked retained effect authority to package-owned recovery readers.
//!
//! The export contains original invocations and checked results, including
//! persistent orphans. It neither selects an ability nor executes a handler.
//! Backend recovery owns interpretation and live resource custody checks.
//!
//! ```json
//! {"schema":"aos.package.retained-effects","scope":["profile","system"],"effects":[]}
//! ```

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use aos_ability_plan::module_graph::{GRAPH_LIMITS, Handler};
use aos_ability_runtime::activation::RetainedEffect;
use aos_contract::{Sha256Digest, limits::BoundedWriter};
use serde::Serialize;

use super::retention::{ArtifactAdmission, generation_roots, verify_retained_handlers};
use super::transaction::{Snapshot, inspect, journal_limits};
use crate::native_registry::RegistryAdmission;

#[derive(Serialize)]
struct Export<'a> {
    schema: &'static str,
    scope: &'a [String],
    effects: &'a [RetainedEffect],
}

/// Holds authenticated store identities and their generation read lock.
///
/// Physical storage backends consume the identities before replacing an image.
/// The snapshot prevents pruning or publication from changing that authority
/// while the backend preserves its closure bytes.
pub(crate) struct RetainedStoreRoots {
    roots: Vec<String>,
    _snapshot: Option<Snapshot>,
}

impl RetainedStoreRoots {
    pub(crate) fn open(profile: &Path, executable: &Path) -> Result<Self> {
        let directory = profile.join("deployment");
        let generations = journal_exists(&directory.join("generations.journal"))?;
        let effects = journal_exists(&directory.join("effects.journal"))?;
        if !generations && !effects {
            return Ok(Self {
                roots: Vec::new(),
                _snapshot: None,
            });
        }
        ensure!(
            generations && effects,
            "profile journals are partially initialized"
        );

        let snapshot = inspect(&directory, journal_limits())?;
        crate::profile::deployment::current_committed_generation(profile)?;
        let mut admission = RegistryAdmission::new(
            executable.to_owned(),
            &directory.join("registry-admissions"),
        )?;
        let roots = retained_store_roots(&snapshot, &directory.join("roots"), &mut admission)?;
        Ok(Self {
            roots: roots.into_iter().collect(),
            _snapshot: Some(snapshot),
        })
    }

    /// Opens authenticated retained roots for a standalone native deployment.
    ///
    /// The paired journals remain locked while a physical backend preserves
    /// their original inputs. Unlike a profile, this scope has no publication
    /// marker; its original image catalogs supply artifact admission.
    ///
    /// # Errors
    /// Returns an error for incomplete or corrupt journals, unavailable original
    /// admission catalogs, changed store artifacts, or incorrect custody roots.
    pub(crate) fn open_deployment(directory: &Path, executable: &Path) -> Result<Self> {
        let generations = journal_exists(&directory.join("generations.journal"))?;
        let effects = journal_exists(&directory.join("effects.journal"))?;
        if !generations && !effects {
            return Ok(Self {
                roots: Vec::new(),
                _snapshot: None,
            });
        }
        ensure!(
            generations && effects,
            "deployment journals are partially initialized"
        );

        let snapshot = inspect(directory, journal_limits())?;
        let mut admission = crate::native_deployment::Admission::new(executable.to_owned())?;
        admission.load_retained(&directory.join("admissions"))?;
        let mut roots = retained_store_roots(&snapshot, &directory.join("roots"), &mut admission)?;
        // Native preparation reads every retained catalog before opening the
        // journal, including receipts whose generation has since been pruned.
        for receipt in admission.receipt_roots() {
            let root = receipt
                .to_str()
                .context("retained admission root is not UTF-8")?;
            admission.admit(root)?;
            roots.insert(root.to_owned());
        }
        Ok(Self {
            roots: roots.into_iter().collect(),
            _snapshot: Some(snapshot),
        })
    }

    pub(crate) fn roots(&self) -> &[String] {
        &self.roots
    }
}

fn retained_store_roots(
    snapshot: &Snapshot,
    directory: &Path,
    admission: &mut impl ArtifactAdmission,
) -> Result<BTreeSet<String>> {
    let mut roots = BTreeSet::new();
    let committed = snapshot.generations().values().map(|generation| {
        (
            format!("package-{}-{}", generation.sequence, generation.content),
            &generation.deployment,
        )
    });
    let pending = snapshot
        .pending()
        .map(|deployment| -> Result<_> {
            let sequence = snapshot
                .pending_sequence()
                .context("pending deployment has no durable sequence")?;
            Ok((
                format!("package-{sequence}-{}", deployment.id()?),
                deployment,
            ))
        })
        .transpose()?;

    for (identity, deployment) in committed.chain(pending) {
        for root in generation_roots(deployment) {
            let key = format!("generation:{identity}:{root}");
            let link = directory.join(Sha256Digest::of_bytes(key.as_bytes()).hex());
            ensure!(
                fs::read_link(&link)? == Path::new(root),
                "retained generation root differs from its original artifact"
            );
            if roots.insert(root.to_owned()) {
                admission.admit(root)?;
            }
        }
    }

    let retained = snapshot.activation().retained_effects();
    let effects = retained
        .iter()
        .map(|state| &state.invocation.effect)
        .collect::<Vec<_>>();
    verify_retained_handlers(directory, &effects, admission)?;
    for effect in effects {
        if let Handler::Process { artifact, .. } = &effect.handler {
            roots.insert(artifact.clone());
        }
    }
    Ok(roots)
}

/// Serializes existing retained authority while holding the profile read lock.
pub(crate) fn export(profile: &Path) -> Result<Vec<u8>> {
    let directory = profile.join("deployment");
    let generations = journal_exists(&directory.join("generations.journal"))?;
    let effects = journal_exists(&directory.join("effects.journal"))?;
    if !generations && !effects {
        return encode(&[], &[]);
    }
    ensure!(
        generations && effects,
        "profile journals are partially initialized"
    );

    let snapshot = inspect(&directory, journal_limits())?;
    // Validate the committed publication in addition to the paired journals.
    crate::profile::deployment::current_committed_generation(profile)?;
    let deployment = snapshot
        .current()
        .map(|generation| &generation.deployment)
        .or_else(|| snapshot.pending());
    let retained = snapshot.activation().retained_effects();
    let Some(deployment) = deployment else {
        ensure!(
            retained.is_empty(),
            "retained effects have no deployment authority"
        );
        return encode(&[], &[]);
    };
    let scope = deployment.scope();
    ensure!(
        retained
            .iter()
            .all(|effect| effect.invocation.effect.identity.starts_with(scope)),
        "retained effect differs from deployment scope"
    );
    if !retained.is_empty() {
        let executable = crate::install::native::packaged_path("AOS_NIX_STORE")?;
        let mut admission =
            RegistryAdmission::new(executable, &directory.join("registry-admissions"))?;
        let effects = retained
            .iter()
            .map(|effect| &effect.invocation.effect)
            .collect::<Vec<_>>();
        verify_retained_handlers(&directory.join("roots"), &effects, &mut admission)?;
    }
    encode(scope, retained)
}

fn journal_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(metadata.is_file(), "native journal is not a regular file");
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspecting native journal presence"),
    }
}

fn encode(scope: &[String], effects: &[RetainedEffect]) -> Result<Vec<u8>> {
    let export = Export {
        schema: "aos.package.retained-effects",
        scope,
        effects,
    };
    let mut bound = BoundedWriter::new(
        (2 * GRAPH_LIMITS.max_bytes) as u64,
        "retained effects export",
    );
    serde_json::to_writer(&mut bound, &export)?;
    Ok(serde_json::to_vec(&export)?)
}

#[cfg(test)]
#[path = "retained_tests.rs"]
mod inventory_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_journals_export_bootstrap_empty_without_creating_profile_state() {
        let temporary = tempfile::tempdir().unwrap();
        let profile = temporary.path().join("absent-profile");

        let bytes = export(&profile).unwrap();

        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            json!({
                "schema":"aos.package.retained-effects", "scope":[], "effects":[]
            })
        );
        assert!(!profile.exists());
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
    }

    #[test]
    fn partial_journal_initialization_is_rejected_without_creating_the_missing_pair() {
        for present in ["generations.journal", "effects.journal"] {
            let temporary = tempfile::tempdir().unwrap();
            let directory = temporary.path().join("deployment");
            fs::create_dir(&directory).unwrap();
            let path = directory.join(present);
            fs::write(&path, b"existing journal bytes").unwrap();

            let error = export(temporary.path()).unwrap_err();

            assert!(format!("{error:#}").contains("partially initialized"));
            assert_eq!(fs::read(&path).unwrap(), b"existing journal bytes");
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        }
    }

    #[test]
    fn malformed_paired_journals_are_rejected_without_repair_or_new_state() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("deployment");
        fs::create_dir(&directory).unwrap();
        let paths = [
            directory.join("generations.journal"),
            directory.join("effects.journal"),
        ];
        let invalid_complete_header = vec![0; 128];
        for path in &paths {
            fs::write(path, &invalid_complete_header).unwrap();
        }

        assert!(export(temporary.path()).is_err());

        for path in &paths {
            assert_eq!(fs::read(path).unwrap(), invalid_complete_header);
        }
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
        assert!(!directory.join("roots").exists());
        assert!(!directory.join("registry-admissions").exists());
    }
}
