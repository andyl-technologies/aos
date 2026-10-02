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
    use crate::deployment::model::{Artifact, ResolvedPackages};
    use serde_json::json;

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
