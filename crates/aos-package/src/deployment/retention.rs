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
use super::process::{FixedBudgetControl, run_bounded};
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
        if let Ok(existing) = std::fs::read_link(&link) {
            ensure!(
                existing == Path::new(root),
                "retention key already names another artifact"
            );
            ensure!(
                Path::new(root).exists(),
                "retained store artifact disappeared"
            );
            return Ok(());
        }
        ensure!(
            Path::new(root).exists(),
            "deployment artifact has not been realized"
        );
        let mut command = Command::new(&self.executable);
        command
            .args(["--add-root"])
            .arg(&link)
            .args(["--indirect", "--realise", root]);
        let output = run_bounded(
            &mut command,
            None,
            64 * 1024,
            &FixedBudgetControl::new(60_000),
            &[],
        )
        .context("retaining deployment artifact in Nix store")?;
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

fn generation_roots(deployment: &Deployment) -> BTreeSet<&str> {
    let mut roots: BTreeSet<_> = deployment.inputs().iter().map(String::as_str).collect();
    for artifact in deployment.artifacts() {
        roots.extend(artifact.outputs.values().map(String::as_str));
    }
    for package in deployment.packages() {
        roots.insert(package.config_root.as_str());
        for artifact in std::iter::once(&package.artifacts.package)
            .chain(package.artifacts.dependencies.values())
        {
            roots.extend(artifact.outputs.values().map(String::as_str));
        }
    }
    roots
}
