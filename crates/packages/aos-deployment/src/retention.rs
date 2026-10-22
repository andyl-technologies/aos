//! Nix store roots for package generations and independently retained effects.
//!
//! Generation roots retain immutable module and payload inputs. Effect roots
//! survive removal of a generation while persistent state or recovery still
//! needs its handler. Root names are content hashes of logical ownership keys.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use aos_core::Sha256Digest;
use aos_module_format::graph::{Effect, Handler};

use super::handler::HandlerArtifacts;
use super::process::{FixedBudgetControl, ProcessOutput, run_bounded};
use super::transaction::DeploymentStore;
use aos_deployment_format::model::Deployment;

// Include argument pointers and terminators, leaving room for the executable
// and scrubbed environment even under a small exec argument budget.
const VALIDITY_ARGUMENT_BYTES: usize = 64 * 1024;

/// Reports authentication and any registration verified during that admission.
///
/// A registration proof belongs to one admission call and one selected store.
/// Retention consumes it immediately; subsequent dispatches admit again.
#[derive(Debug)]
pub struct AdmittedArtifact {
    registration: Option<StoreRegistration>,
}

#[derive(Debug, Eq, PartialEq)]
struct StoreRegistration {
    root: String,
    executable: OsString,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, Option<OsString>)>,
}

impl StoreRegistration {
    // Capture the configured store route before adding query arguments. The
    // same Nix executable can address different stores, including test stores.
    fn new(root: &str, command: &Command) -> Self {
        Self {
            root: root.to_owned(),
            executable: command.get_program().to_owned(),
            arguments: command
                .get_args()
                .map(|argument| argument.to_owned())
                .collect(),
            environment: command
                .get_envs()
                .map(|(key, value)| (key.to_owned(), value.map(|value| value.to_owned())))
                .collect(),
        }
    }
}

impl AdmittedArtifact {
    /// Reports authentication without a store-registration proof.
    ///
    /// Retention checks database validity separately for this result.
    #[must_use]
    pub const fn authenticated() -> Self {
        Self { registration: None }
    }

    /// Records authentication together with an exact selected-store registration proof.
    pub(crate) fn registered(root: &str, command: &Command) -> Self {
        Self {
            registration: Some(StoreRegistration::new(root, command)),
        }
    }

    fn registered_in(self, root: &str, executable: &Path) -> Result<bool> {
        let mut command = Command::new(executable);
        aos_nix::configure_aos_nix_store(&mut command)?;
        Ok(self.registration == Some(StoreRegistration::new(root, &command)))
    }
}

/// Admits exact output roots using authenticated registry or retained-generation evidence.
pub trait ArtifactAdmission {
    /// Admits a canonical output identity before it can be rooted or executed.
    ///
    /// # Errors
    /// Returns an error when the output is not covered by the resolver's evidence.
    fn admit(&mut self, root: &str) -> Result<AdmittedArtifact>;
}

/// Verifies existing effect roots without creating roots or executing handlers.
///
/// Admission remains bound to the original authenticated artifact. Every
/// process effect must also retain its own exact recovery root, even when
/// several effects share the same artifact.
///
/// # Errors
/// Returns an error for an unavailable retention directory, a missing or
/// substituted effect root, or an artifact rejected by its original admission.
pub fn verify_retained_handlers<A: ArtifactAdmission>(
    directory: &Path,
    effects: &[&Effect],
    admission: &mut A,
) -> Result<()> {
    ensure!(
        std::fs::symlink_metadata(directory)?.file_type().is_dir(),
        "handler retention directory is not a real directory"
    );
    let mut admitted = BTreeSet::new();
    for effect in effects {
        if let Handler::Process { artifact, .. } = &effect.handler {
            let key = NixStore::<A>::effect_key(effect, artifact)?;
            let link = directory.join(Sha256Digest::of_bytes(key.as_bytes()).hex());
            ensure!(
                std::fs::read_link(&link)? == Path::new(artifact),
                "retained handler root differs from its original artifact"
            );
            if admitted.insert(artifact) {
                admission.admit(artifact)?;
            }
        }
    }
    Ok(())
}

/// Roots admitted artifacts through an explicitly selected Nix store executable.
pub struct NixStore<A> {
    executable: PathBuf,
    directory: PathBuf,
    admission: A,
}

impl<A: ArtifactAdmission> NixStore<A> {
    /// Opens a retention directory supplied by the owning APM profile.
    ///
    /// The caller supplies its AOS-built `nix-store` executable and a private
    /// directory whose parents are controlled by the profile owner.
    ///
    /// # Errors
    /// Returns an error for a non-absolute executable or an unusable retention directory.
    pub fn open(executable: PathBuf, directory: PathBuf, admission: A) -> Result<Self> {
        ensure!(
            executable.is_absolute() && directory.is_absolute(),
            "store retention paths must be absolute"
        );
        std::fs::create_dir_all(&directory)?;
        ensure!(
            std::fs::symlink_metadata(&directory)?.file_type().is_dir(),
            "retention root is not a directory"
        );
        Ok(Self {
            executable,
            directory,
            admission,
        })
    }

    fn pin(&mut self, key: &str, root: &str) -> Result<()> {
        let admitted = self.admission.admit(root)?;
        if !admitted.registered_in(root, &self.executable)? {
            self.check_validity(&BTreeSet::from([root]))?;
        }
        self.pin_validated(key, root)
    }

    fn admit_roots(&mut self, roots: &BTreeSet<&str>) -> Result<()> {
        let mut unchecked = BTreeSet::new();
        for root in roots {
            let admitted = self.admission.admit(root)?;
            if !admitted.registered_in(root, &self.executable)? {
                unchecked.insert(*root);
            }
        }
        self.check_validity(&unchecked)
    }

    fn check_validity(&self, roots: &BTreeSet<&str>) -> Result<()> {
        let mut batch = Vec::new();
        let mut bytes = 0;
        for root in roots {
            let argument_bytes = root.len() + 1 + std::mem::size_of::<usize>();
            ensure!(
                argument_bytes <= VALIDITY_ARGUMENT_BYTES,
                "store root exceeds validity argument budget"
            );
            if bytes + argument_bytes > VALIDITY_ARGUMENT_BYTES {
                self.check_validity_batch(&batch)?;
                batch.clear();
                bytes = 0;
            }
            batch.push(*root);
            bytes += argument_bytes;
        }
        if !batch.is_empty() {
            self.check_validity_batch(&batch)?;
        }
        Ok(())
    }

    fn check_validity_batch(&self, roots: &[&str]) -> Result<()> {
        // Query the selected store's database, not the evaluator process's
        // filesystem. Large valid graphs use bounded argv chunks; every chunk
        // succeeds before any ownership link is created by the caller.
        let mut validity = Command::new(&self.executable);
        validity.arg("--check-validity").args(roots);
        let checked = run_store_command(&mut validity)?;
        ensure!(
            checked.status.success(),
            "deployment artifact has not been realized: {}",
            String::from_utf8_lossy(&checked.stderr)
        );
        Ok(())
    }

    // Admission and database validity are scoped to the current retention
    // call. No subsequent dispatch or retention call inherits these checks.
    fn pin_validated(&mut self, key: &str, root: &str) -> Result<()> {
        let link = self
            .directory
            .join(Sha256Digest::of_bytes(key.as_bytes()).hex());
        if let Ok(existing) = std::fs::read_link(&link) {
            ensure!(
                existing == Path::new(root),
                "retention key already names another artifact"
            );
            return Ok(());
        }
        let mut command = Command::new(&self.executable);
        command
            .args(["--add-root"])
            .arg(&link)
            .args(["--indirect", "--realise", root]);
        // Retention may register an existing path, but cannot fetch or build it.
        command.args([
            "--option",
            "substitute",
            "false",
            "--option",
            "max-jobs",
            "0",
            "--option",
            "builders",
            "",
        ]);
        let output = run_store_command(&mut command)?;
        ensure!(
            output.status.success(),
            "store retention command failed: {}",
            output.status
        );
        ensure!(
            std::fs::read_link(&link)? == Path::new(root),
            "store created an unexpected retention root"
        );
        std::fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    fn unpin(&self, key: &str) -> Result<()> {
        let link = self
            .directory
            .join(Sha256Digest::of_bytes(key.as_bytes()).hex());
        match std::fs::remove_file(link) {
            Ok(()) => std::fs::File::open(&self.directory)?.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn effect_key(effect: &Effect, artifact: &str) -> Result<String> {
        Ok(format!(
            "effect:{}:{artifact}",
            serde_json::to_string(&effect.identity)?
        ))
    }
}

impl<A: ArtifactAdmission> HandlerArtifacts for NixStore<A> {
    fn retain(&mut self, effect: &Effect) -> Result<()> {
        if let Handler::Process { artifact, .. } = &effect.handler {
            self.pin(&Self::effect_key(effect, artifact)?, artifact)?;
        }
        Ok(())
    }

    fn retain_batch(&mut self, effects: &[&Effect]) -> Result<()> {
        let roots = effects
            .iter()
            .filter_map(|effect| match &effect.handler {
                Handler::Process { artifact, .. } => Some(artifact.as_str()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        self.admit_roots(&roots)?;

        for effect in effects {
            if let Handler::Process { artifact, .. } = &effect.handler {
                self.pin_validated(&Self::effect_key(effect, artifact)?, artifact)?;
            }
        }
        Ok(())
    }

    fn release(&mut self, effect: &Effect) -> Result<()> {
        if let Handler::Process { artifact, .. } = &effect.handler {
            self.unpin(&Self::effect_key(effect, artifact)?)?;
        }
        Ok(())
    }
}

impl<A: ArtifactAdmission> DeploymentStore for NixStore<A> {
    fn retain_generation(&mut self, generation: &str, deployment: &Deployment) -> Result<()> {
        let roots = generation_roots(deployment);
        self.admit_roots(&roots)?;
        for root in roots {
            self.pin_validated(&format!("generation:{generation}:{root}"), root)?;
        }
        Ok(())
    }

    fn release_generation(&mut self, generation: &str, deployment: &Deployment) -> Result<()> {
        for root in generation_roots(deployment) {
            self.unpin(&format!("generation:{generation}:{root}"))?;
        }
        Ok(())
    }
}

fn run_store_command(command: &mut Command) -> Result<ProcessOutput> {
    aos_nix::configure_aos_nix_store(command)?;
    let environment = command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
        .collect::<Vec<_>>();
    run_bounded(
        command,
        None,
        64 * 1024,
        &FixedBudgetControl::new(60_000),
        &environment,
    )
    .context("accessing the selected Nix store for deployment retention")
}

/// Collects immutable payload, source, and runtime roots required by a deployment.
pub fn generation_roots(deployment: &Deployment) -> BTreeSet<&str> {
    let mut roots: BTreeSet<_> = deployment.inputs().iter().map(String::as_str).collect();
    for artifact in deployment.artifacts() {
        roots.insert(artifact.path.as_str());
    }
    for package in deployment.packages() {
        roots.insert(package.config_root.as_str());
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::ProcessAdapter;
    use aos_activation::activation::{Action, ActivationAdapter, Invocation};
    use aos_activation::adapter::CancellationToken;
    use aos_deployment_format::model::{Artifact, ResolvedPackages};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct CheckedFixture {
        members: BTreeMap<String, PathBuf>,
        calls: Arc<Mutex<Vec<String>>>,
        registration: Option<(String, PathBuf)>,
    }

    impl ArtifactAdmission for CheckedFixture {
        fn admit(&mut self, root: &str) -> Result<AdmittedArtifact> {
            self.calls.lock().unwrap().push(root.to_owned());
            let path = self
                .members
                .get(root)
                .context("unauthorized fixture artifact")?;
            ensure!(
                std::fs::read(path)? == b"admitted",
                "fixture artifact changed"
            );
            Ok(match &self.registration {
                Some((root, executable)) => {
                    let mut command = Command::new(executable);
                    aos_nix::configure_aos_nix_store(&mut command)?;
                    AdmittedArtifact::registered(root, &command)
                }
                None => AdmittedArtifact::authenticated(),
            })
        }
    }

    fn source_tool(name: &str) -> PathBuf {
        std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .filter(|directory| directory.starts_with("/nix/store"))
            .map(|directory| directory.join(name))
            .find(|path| path.is_file())
            .unwrap_or_else(|| panic!("source-built AOS {name} must be in PATH"))
    }

    fn effect(instance: &str, root: &str) -> Effect {
        serde_json::from_value(json!({
            "identity": ["fixture", "retain", instance],
            "owner": "@environment",
            "input": {},
            "inputs": {},
            "input_type": {"kind": "submodule", "open": false, "fields": {}},
            "results": {},
            "after": [],
            "dependencies": [],
            "revision": "0".repeat(64),
            "handler": {
                "kind": "process",
                "artifact": root,
                "executable": format!("{root}/bin/run")
            },
            "lifetime": "persistent",
            "timeout_ms": 1000
        }))
        .unwrap()
    }

    fn fixture(directory: &Path) -> (NixStore<CheckedFixture>, String, String) {
        let old = "/nix/store/00000000000000000000000000000000-old-provider".to_owned();
        let new = "/nix/store/11111111111111111111111111111111-new-provider".to_owned();
        let valid = directory.join("valid");
        std::fs::create_dir(&valid).unwrap();
        let members = [&old, &new]
            .into_iter()
            .map(|root| {
                let path = valid.join(Path::new(root).file_name().unwrap());
                std::fs::write(&path, b"admitted").unwrap();
                (root.clone(), path)
            })
            .collect();
        let executable = directory.join("store-protocol");
        // This unit-only protocol shim uses source-built tools and real GC-root
        // links. It models store availability, not NAR or release authentication.
        let script = format!(
            r#"#!{shell}
case "$1" in
    --check-validity)
        shift
        printf '%s\n' "$*" >> "{calls}"
        for root in "$@"; do
            test -f "{valid}/${{root##*/}}" || exit 1
            test ! -f "{invalid}/${{root##*/}}" || exit 1
        done
        ;;
    --add-root)
        "{link}" -s -- "$5" "$2"
        ;;
    *)
        exit 1
        ;;
esac
"#,
            shell = source_tool("bash").display(),
            valid = valid.display(),
            calls = directory.join("validity-calls").display(),
            invalid = directory.join("invalid").display(),
            link = source_tool("ln").display(),
        );
        std::fs::write(&executable, script).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let admission = CheckedFixture {
            members,
            calls: Arc::default(),
            registration: None,
        };
        (
            NixStore::open(executable, directory.join("roots"), admission).unwrap(),
            old,
            new,
        )
    }

    fn root_link(store: &NixStore<CheckedFixture>, effect: &Effect, artifact: &str) -> PathBuf {
        store.directory.join(
            Sha256Digest::of_bytes(
                NixStore::<CheckedFixture>::effect_key(effect, artifact)
                    .unwrap()
                    .as_bytes(),
            )
            .hex(),
        )
    }

    fn validity_calls(directory: &Path) -> Vec<Vec<String>> {
        std::fs::read_to_string(directory.join("validity-calls"))
            .unwrap_or_default()
            .lines()
            .map(|line| line.split_whitespace().map(str::to_owned).collect())
            .collect()
    }

    #[test]
    fn registration_for_the_same_executable_requires_the_same_store_route() {
        let root = "/nix/store/00000000000000000000000000000000-provider";
        let executable = source_tool("bash");

        for use_argument in [false, true] {
            let mut command = Command::new(&executable);
            aos_nix::configure_aos_nix_store(&mut command).unwrap();
            if use_argument {
                command.args(["--store", "local?root=/different-store"]);
            } else {
                command.env("NIX_STATE_DIR", "/different-store/state");
            }
            let admitted = AdmittedArtifact::registered(root, &command);

            assert!(!admitted.registered_in(root, &executable).unwrap());
        }
    }

    #[test]
    fn registered_admission_skips_duplicate_validity_but_rechecks_next_dispatch() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, old, _) = fixture(directory.path());
        store.admission.registration = Some((old.clone(), store.executable.clone()));
        let first = effect("first", &old);
        let shared = effect("shared", &old);

        store.retain_batch(&[&first, &shared]).unwrap();
        store.retain(&first).unwrap();

        assert!(validity_calls(directory.path()).is_empty());
        assert_eq!(
            *store.admission.calls.lock().unwrap(),
            [old.clone(), old.clone()]
        );
        assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 2);

        std::fs::write(&store.admission.members[&old], b"changed").unwrap();
        assert!(store.retain(&first).is_err());
        assert_eq!(store.admission.calls.lock().unwrap().len(), 3);
        assert!(validity_calls(directory.path()).is_empty());
        assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 2);
    }

    #[test]
    fn registration_proof_for_another_root_or_store_keeps_validity_fallback() {
        for other_store in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let (mut store, old, new) = fixture(directory.path());
            store.admission.registration = Some(if other_store {
                (old.clone(), directory.path().join("another-store"))
            } else {
                (new, store.executable.clone())
            });
            let invalid = directory.path().join("invalid");
            std::fs::create_dir(&invalid).unwrap();
            std::fs::write(invalid.join(Path::new(&old).file_name().unwrap()), b"").unwrap();

            assert!(store.retain(&effect("first", &old)).is_err());

            assert_eq!(validity_calls(directory.path()), [vec![old]]);
            assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 0);
        }
    }

    #[test]
    fn mixed_registration_batch_checks_unproven_roots_before_creating_any_link() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, old, new) = fixture(directory.path());
        store.admission.registration = Some((old.clone(), store.executable.clone()));
        let invalid = directory.path().join("invalid");
        std::fs::create_dir(&invalid).unwrap();
        std::fs::write(invalid.join(Path::new(&new).file_name().unwrap()), b"").unwrap();

        assert!(
            store
                .retain_batch(&[&effect("first", &old), &effect("second", &new)])
                .is_err()
        );

        assert_eq!(validity_calls(directory.path()), [vec![new]]);
        assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 0);
    }

    #[test]
    fn batch_validity_failure_precedes_roots_and_is_rechecked_after_return() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, old, new) = fixture(directory.path());
        let first = effect("first", &old);
        let shared = effect("shared", &old);
        let replacement = effect("replacement", &new);
        let invalid = directory.path().join("invalid");
        std::fs::create_dir(&invalid).unwrap();
        let unavailable = invalid.join(Path::new(&new).file_name().unwrap());
        std::fs::write(&unavailable, b"").unwrap();

        assert!(
            store
                .retain_batch(&[&first, &shared, &replacement])
                .unwrap_err()
                .to_string()
                .contains("has not been realized")
        );
        assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 0);
        assert_eq!(
            validity_calls(directory.path()),
            [vec![old.clone(), new.clone()]]
        );

        std::fs::remove_file(&unavailable).unwrap();
        store
            .retain_batch(&[&first, &shared, &replacement])
            .unwrap();
        for (effect, root) in [(&first, &old), (&shared, &old), (&replacement, &new)] {
            assert_eq!(
                std::fs::read_link(root_link(&store, effect, root)).unwrap(),
                Path::new(root)
            );
        }
        std::fs::write(&unavailable, b"").unwrap();
        assert!(
            store
                .retain_batch(&[&first, &shared, &replacement])
                .is_err()
        );

        assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 3);
        assert_eq!(
            validity_calls(directory.path()),
            vec![vec![old.clone(), new.clone()]; 3]
        );
        assert_eq!(
            *store.admission.calls.lock().unwrap(),
            [old.clone(), new.clone(), old.clone(), new.clone(), old, new]
        );
    }

    #[test]
    fn generation_batches_validity_without_sharing_generation_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, old, new) = fixture(directory.path());
        let artifact = Artifact {
            name: "old-provider".into(),
            version: "1".into(),
            path: old.clone(),
            outputs: [("out".into(), old.clone())].into(),
            main_program: None,
        };
        let resolved = ResolvedPackages {
            system: "x86_64-linux".into(),
            artifacts: vec![artifact.clone()],
            modules: vec![],
        };
        let deployment = Deployment::decode(
            &serde_json::to_vec(&json!({
                "schema":"aos.package.transaction", "scope":["profile","fixture"],
                "system":"x86_64-linux", "artifacts":[artifact], "packages":[],
                "inputs":[old,new], "retire":[],
                "graph":{"schema":"aos.activation.graph","nodes":{},"order":[]}
            }))
            .unwrap(),
            &resolved,
        )
        .unwrap();

        store.retain_generation("first", &deployment).unwrap();
        store.retain_generation("second", &deployment).unwrap();
        store.release_generation("first", &deployment).unwrap();

        assert_eq!(
            validity_calls(directory.path()),
            vec![vec![old.clone(), new.clone()]; 2]
        );
        assert_eq!(
            *store.admission.calls.lock().unwrap(),
            [old.clone(), new.clone(), old.clone(), new.clone()]
        );
        assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 2);
        for root in [&old, &new] {
            let key = format!("generation:second:{root}");
            let link = store
                .directory
                .join(Sha256Digest::of_bytes(key.as_bytes()).hex());
            assert_eq!(std::fs::read_link(link).unwrap(), Path::new(root));
        }

        std::fs::write(&store.admission.members[&old], b"changed").unwrap();
        assert!(store.retain_generation("third", &deployment).is_err());
        assert_eq!(validity_calls(directory.path()).len(), 2);
        assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 2);
    }

    #[test]
    fn empty_handler_batch_does_not_query_the_store() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, _, _) = fixture(directory.path());

        store.retain_batch(&[]).unwrap();

        assert!(validity_calls(directory.path()).is_empty());
        assert!(store.admission.calls.lock().unwrap().is_empty());
        assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 0);
    }

    #[test]
    fn large_generation_checks_all_bounded_chunks_before_creating_roots() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, _, _) = fixture(directory.path());
        let roots = (0..1_200)
            .map(|index| {
                format!(
                    "/nix/store/00000000000000000000000000000000-{index:04}-{}",
                    "p".repeat(100)
                )
            })
            .collect::<Vec<_>>();
        for root in &roots {
            let path = directory
                .path()
                .join("valid")
                .join(Path::new(root).file_name().unwrap());
            std::fs::write(&path, b"admitted").unwrap();
            store.admission.members.insert(root.clone(), path);
        }
        let unavailable = directory.path().join("invalid");
        std::fs::create_dir(&unavailable).unwrap();
        std::fs::write(
            unavailable.join(Path::new(roots.last().unwrap()).file_name().unwrap()),
            b"",
        )
        .unwrap();
        let resolved = ResolvedPackages {
            system: "x86_64-linux".into(),
            artifacts: vec![],
            modules: vec![],
        };
        let deployment = Deployment::decode(
            &serde_json::to_vec(&json!({
                "schema":"aos.package.transaction", "scope":["profile","fixture"],
                "system":"x86_64-linux", "artifacts":[], "packages":[],
                "inputs":roots, "retire":[],
                "graph":{"schema":"aos.activation.graph","nodes":{},"order":[]}
            }))
            .unwrap(),
            &resolved,
        )
        .unwrap();

        assert!(store.retain_generation("large", &deployment).is_err());

        let calls = validity_calls(directory.path());
        assert!(calls.len() > 1);
        assert_eq!(calls.iter().flatten().cloned().collect::<Vec<_>>(), roots);
        for batch in calls {
            let bytes = batch
                .iter()
                .map(|root| root.len() + 1 + std::mem::size_of::<usize>())
                .sum::<usize>();
            assert!(bytes <= VALIDITY_ARGUMENT_BYTES);
        }
        assert_eq!(*store.admission.calls.lock().unwrap(), roots);
        assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 0);
    }

    #[test]
    fn retained_verification_checks_every_root_and_deduplicates_admission_per_call() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, old, new) = fixture(directory.path());
        let first = effect("first", &old);
        let second = effect("second", &old);
        let replacement = effect("first", &new);
        store
            .retain_batch(&[&first, &second, &replacement])
            .unwrap();
        store.admission.calls.lock().unwrap().clear();

        for expected_calls in [2, 4] {
            verify_retained_handlers(
                &store.directory,
                &[&first, &second, &replacement],
                &mut store.admission,
            )
            .unwrap();
            assert_eq!(store.admission.calls.lock().unwrap().len(), expected_calls);
            for (effect, artifact) in [(&first, &old), (&second, &old), (&replacement, &new)] {
                assert_eq!(
                    std::fs::read_link(root_link(&store, effect, artifact)).unwrap(),
                    Path::new(artifact)
                );
            }
            assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 3);
        }
        assert_eq!(
            *store.admission.calls.lock().unwrap(),
            [old.clone(), new.clone(), old, new]
        );
    }

    #[test]
    fn retained_verification_never_creates_or_repairs_missing_and_substituted_roots() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, old, new) = fixture(directory.path());
        let first = effect("first", &old);
        let second = effect("second", &old);
        store.retain_batch(&[&first, &second]).unwrap();
        let second_link = root_link(&store, &second, &old);
        std::fs::remove_file(&second_link).unwrap();
        store.admission.calls.lock().unwrap().clear();

        assert!(
            verify_retained_handlers(&store.directory, &[&first, &second], &mut store.admission)
                .is_err()
        );
        assert!(std::fs::symlink_metadata(&second_link).is_err());
        assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 1);
        assert_eq!(*store.admission.calls.lock().unwrap(), [old.clone()]);

        std::os::unix::fs::symlink(&new, &second_link).unwrap();
        store.admission.calls.lock().unwrap().clear();
        assert!(
            verify_retained_handlers(&store.directory, &[&first, &second], &mut store.admission)
                .is_err()
        );
        assert_eq!(std::fs::read_link(&second_link).unwrap(), Path::new(&new));
        assert_eq!(*store.admission.calls.lock().unwrap(), [old.clone()]);
        std::fs::remove_file(&second_link).unwrap();
        std::fs::write(&second_link, b"foreign regular file").unwrap();
        assert!(
            verify_retained_handlers(&store.directory, &[&second], &mut store.admission).is_err()
        );
        assert_eq!(
            std::fs::read(&second_link).unwrap(),
            b"foreign regular file"
        );
        assert_eq!(
            std::fs::read_link(root_link(&store, &first, &old)).unwrap(),
            Path::new(&old)
        );
    }

    #[test]
    fn retained_verification_rejects_missing_or_aliased_directories_without_admission() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, old, _) = fixture(directory.path());
        let first = effect("first", &old);
        store.retain_batch(&[&first]).unwrap();
        store.admission.calls.lock().unwrap().clear();
        let absent = directory.path().join("absent");
        assert!(verify_retained_handlers(&absent, &[&first], &mut store.admission).is_err());
        assert!(!absent.exists());
        let alias = directory.path().join("aliased-roots");
        std::os::unix::fs::symlink(&store.directory, &alias).unwrap();
        assert!(verify_retained_handlers(&alias, &[&first], &mut store.admission).is_err());
        assert_eq!(std::fs::read_link(alias).unwrap(), store.directory);
        assert!(store.admission.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn retained_verification_rechecks_original_artifact_evidence_without_changing_roots() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, old, _) = fixture(directory.path());
        let first = effect("first", &old);
        store.retain_batch(&[&first]).unwrap();
        store.admission.calls.lock().unwrap().clear();
        std::fs::write(&store.admission.members[&old], b"changed").unwrap();

        assert!(
            verify_retained_handlers(&store.directory, &[&first], &mut store.admission)
                .unwrap_err()
                .to_string()
                .contains("artifact changed")
        );

        assert_eq!(*store.admission.calls.lock().unwrap(), [old.clone()]);
        assert_eq!(
            std::fs::read_link(root_link(&store, &first, &old)).unwrap(),
            Path::new(&old)
        );
        assert_eq!(
            std::fs::read(&store.admission.members[&old]).unwrap(),
            b"changed"
        );
        assert_eq!(std::fs::read_dir(&store.directory).unwrap().count(), 1);
    }

    #[test]
    fn batch_admission_preserves_independent_effect_and_replacement_roots() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, old, new) = fixture(directory.path());
        let first = effect("first", &old);
        let second = effect("second", &old);
        let replacement = effect("first", &new);

        store
            .retain_batch(&[&first, &second, &replacement])
            .unwrap();

        assert_eq!(
            *store.admission.calls.lock().unwrap(),
            [old.clone(), new.clone()]
        );
        for (effect, artifact) in [(&first, &old), (&second, &old), (&replacement, &new)] {
            assert_eq!(
                std::fs::read_link(root_link(&store, effect, artifact)).unwrap(),
                Path::new(artifact)
            );
        }
        store.release(&first).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(root_link(&store, &first, &old))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(
            std::fs::read_link(root_link(&store, &second, &old)).unwrap(),
            Path::new(&old)
        );
        assert_eq!(
            std::fs::read_link(root_link(&store, &replacement, &new)).unwrap(),
            Path::new(&new)
        );

        store.retain_batch(&[&second, &replacement]).unwrap();
        assert_eq!(
            *store.admission.calls.lock().unwrap(),
            [old.clone(), new.clone(), old, new]
        );
    }

    #[test]
    fn batch_rechecks_each_root_key_and_revalidates_after_return() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, old, new) = fixture(directory.path());
        let first = effect("first", &old);
        let second = effect("second", &old);
        let key = root_link(&store, &second, &old);
        std::os::unix::fs::symlink(&new, &key).unwrap();

        assert!(
            store
                .retain_batch(&[&first, &second])
                .unwrap_err()
                .to_string()
                .contains("another artifact")
        );
        assert_eq!(std::fs::read_link(key).unwrap(), Path::new(&new));
        std::fs::write(&store.admission.members[&old], b"changed").unwrap();
        assert!(
            store
                .retain_batch(&[&first])
                .unwrap_err()
                .to_string()
                .contains("artifact changed")
        );
        assert_eq!(*store.admission.calls.lock().unwrap(), [old.clone(), old]);
    }

    #[test]
    fn dispatch_rechecks_live_custody_after_batch_before_process_execution() {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, old, _) = fixture(directory.path());
        let first = effect("first", &old);
        store.retain_batch(&[&first]).unwrap();
        std::fs::write(&store.admission.members[&old], b"changed").unwrap();
        let calls = store.admission.calls.clone();
        let mut adapter = ProcessAdapter::new(store);
        let invocation = Invocation {
            id: "fixture".into(),
            effect: first,
            input: json!({}),
            revision: "0".repeat(64),
            action: Action::Apply,
            previous: None,
        };

        let error = adapter
            .invoke(&invocation, &CancellationToken::default())
            .unwrap_err();

        assert_eq!(error.to_string(), "fixture artifact changed");
        assert_eq!(*calls.lock().unwrap(), [old.clone(), old]);
    }

    #[test]
    fn generation_roots_keep_selected_and_referenced_outputs_only() {
        let root = |name: &str| format!("/nix/store/00000000000000000000000000000000-{name}");
        let artifact = Artifact {
            name: "slice".into(),
            version: "1".into(),
            path: root("selected"),
            outputs: [
                ("out".into(), root("selected")),
                ("tools".into(), root("used")),
                ("unused".into(), root("unused")),
            ]
            .into(),
            main_program: None,
        };
        let resolved = ResolvedPackages {
            system: "x86_64-linux".into(),
            artifacts: vec![artifact.clone()],
            modules: vec![],
        };
        let desired = Deployment::decode(
            &serde_json::to_vec(&json!({
                "schema":"aos.package.transaction", "scope":["profile","slice"],
                "system":"x86_64-linux", "artifacts":[artifact], "packages":[],
                "inputs":[root("library"),root("used")], "retire":[],
                "graph":{"schema":"aos.activation.graph","nodes":{},"order":[]}
            }))
            .unwrap(),
            &resolved,
        )
        .unwrap();

        assert_eq!(
            generation_roots(&desired),
            BTreeSet::from([
                root("library").as_str(),
                root("selected").as_str(),
                root("used").as_str()
            ])
        );
        assert!(!generation_roots(&desired).contains(root("unused").as_str()));
    }
}
