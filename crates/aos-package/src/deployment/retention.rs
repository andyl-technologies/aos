//! Nix store roots for package generations and independently retained effects.
//!
//! Generation roots retain immutable module and payload inputs. Effect roots
//! survive removal of a generation while persistent state or recovery still
//! needs its handler. Root names are content hashes of logical ownership keys.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use aos_ability_plan::module_graph::{Effect, Handler};
use aos_contract::Sha256Digest;

use super::handler::HandlerArtifacts;
use super::model::Deployment;
use super::process::{FixedBudgetControl, ProcessOutput, run_bounded};
use super::transaction::DeploymentStore;

/// Admits exact output roots using authenticated registry or retained-generation evidence.
pub trait ArtifactAdmission {
    /// Admits a canonical output identity before it can be rooted or executed.
    ///
    /// # Errors
    /// Returns an error when the output is not covered by the resolver's evidence.
    fn admit(&mut self, root: &str) -> Result<()>;
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
        self.admission.admit(root)?;
        self.pin_admitted(key, root)
    }

    // Admission is scoped to the current retention call. Each ownership key
    // still needs its own checked, durable root even when artifacts are shared.
    fn pin_admitted(&mut self, key: &str, root: &str) -> Result<()> {
        let link = self
            .directory
            .join(Sha256Digest::of_bytes(key.as_bytes()).hex());
        // Query the selected store's database, not the evaluator process's
        // filesystem: a rooted store can use different physical paths.
        let mut validity = Command::new(&self.executable);
        validity.args(["--check-validity", root]);
        let checked = run_store_command(&mut validity)?;
        ensure!(
            checked.status.success(),
            "deployment artifact has not been realized: {}",
            String::from_utf8_lossy(&checked.stderr)
        );

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
        let mut admitted = BTreeSet::new();
        for effect in effects {
            if let Handler::Process { artifact, .. } = &effect.handler {
                if admitted.insert(artifact.as_str()) {
                    self.admission.admit(artifact)?;
                }
                self.pin_admitted(&Self::effect_key(effect, artifact)?, artifact)?;
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
        for root in generation_roots(deployment) {
            self.pin(&format!("generation:{generation}:{root}"), root)?;
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
    aos_core::nix::configure_aos_nix_store(command)?;
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

fn generation_roots(deployment: &Deployment) -> BTreeSet<&str> {
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
    use crate::deployment::handler::ProcessAdapter;
    use crate::deployment::model::{Artifact, ResolvedPackages};
    use aos_ability_runtime::activation::{Action, ActivationAdapter, Invocation};
    use aos_ability_runtime::adapter::CancellationToken;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct CheckedFixture {
        members: BTreeMap<String, PathBuf>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl ArtifactAdmission for CheckedFixture {
        fn admit(&mut self, root: &str) -> Result<()> {
            self.calls.lock().unwrap().push(root.to_owned());
            let path = self
                .members
                .get(root)
                .context("unauthorized fixture artifact")?;
            ensure!(
                std::fs::read(path)? == b"admitted",
                "fixture artifact changed"
            );
            Ok(())
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
        test -f "{valid}/${{2##*/}}"
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
            link = source_tool("ln").display(),
        );
        std::fs::write(&executable, script).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let admission = CheckedFixture {
            members,
            calls: Arc::default(),
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
