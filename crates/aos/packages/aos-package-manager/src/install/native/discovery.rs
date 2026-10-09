//! Supplies original admitted profile context to native companion discovery.
//!
//! Retained package catalogs satisfy exact runtime bindings independently of
//! currently configured registries. Store presence and package coordinates alone
//! never establish that authority.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

use aos_deployment_format::model::{Artifact, Deployment, Envelope};
use aos_deployment_format::input::EvaluationInput;
use crate::native_registry::{NativeRegistry, RegistryAdmission};
use crate::profile::Profile;
use aos_registry_client::registry::RegistrySet;
use aos_deployment_format::inventory::InstalledPackageRecord;

/// Holds checked current profile context and its original admission receipts.
pub(super) struct RetainedDiscovery {
    /// Retains the exact resolved packages and selected module-source choices.
    pub(super) descriptor: EvaluationInput,
    deployment: Deployment,
    executable: PathBuf,
    admission: RegistryAdmission,
}

/// Carries authenticated catalogs available for subsequent companion discovery.
pub(super) struct RetainedContext {
    /// Retains explicit installed owners and all selected module envelopes.
    pub(super) originals: Vec<Envelope>,
    /// Lists exact installed or independently admitted runtime catalogs.
    pub(super) artifacts: Vec<Artifact>,
}

impl RetainedDiscovery {
    /// Reads the current committed native identity without creating profile state.
    ///
    /// # Errors
    /// Returns an error for partial native state, invalid publication or descriptor,
    /// missing immutable inputs, or invalid retained admission receipts.
    pub(super) fn read(profile: &Profile) -> Result<Option<Self>> {
        let generation = profile.current_generation()?;
        let native = match &generation {
            Some(generation) => {
                match fs::symlink_metadata(generation.path.join("native-deployment.json")) {
                    Ok(_) => true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                    Err(error) => {
                        return Err(error).context("inspecting retained native generation");
                    }
                }
            }
            None => false,
        };
        if !native {
            for journal in ["generations.journal", "effects.journal"] {
                match fs::symlink_metadata(profile.path.join("deployment").join(journal)) {
                    Ok(_) => anyhow::bail!("native profile has no published current generation"),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error).context("inspecting retained native journal"),
                }
            }
            return Ok(None);
        }
        let generation = generation.context("retained native generation is absent")?;
        let committed =
            crate::profile::deployment::committed_generation(&profile.path, generation.number)?;
        let executable = super::packaged_path("AOS_NIX_STORE")?;
        let admission = RegistryAdmission::new(
            executable.clone(),
            &profile.path.join("deployment/registry-admissions"),
        )?;
        let (_, descriptor) = crate::native_deployment::read_retained_evaluation_in(
            &generation.path.join("evaluation.json"),
            &committed.deployment,
            &executable,
            &Default::default(),
        )?;
        Ok(Some(Self {
            descriptor,
            deployment: committed.deployment,
            executable,
            admission,
        }))
    }

    /// Authenticates original catalogs and their retained runtime bindings.
    ///
    /// # Errors
    /// Returns an error for changed original envelopes, inconsistent retained
    /// module choices, invalid installed metadata, or failed artifact admission.
    pub(super) fn authenticate(
        self,
        registries: &RegistrySet,
        installed: &[InstalledPackageRecord],
    ) -> Result<RetainedContext> {
        let mut resolver = NativeRegistry::new(registries, self.admission);
        resolver.retain_modules(&self.descriptor, &self.deployment)?;
        let mut originals = Vec::new();
        let mut artifacts = Vec::new();
        for meta in installed {
            let envelope = resolver.installed(meta)?;
            artifacts.push(envelope.package.clone());
            if meta.apm.as_ref().is_some_and(|package| package.explicit) {
                originals.push(envelope);
            }
        }
        for path in self.descriptor.module_envelopes.values() {
            let bytes = aos_deployment::document::read_regular_store_document_in(
                &path.join("deployment.json"),
                &self.executable,
                &Default::default(),
            )?;
            let envelope = Envelope::decode(&bytes)?;
            if !originals.contains(&envelope) {
                originals.push(envelope);
            }
        }
        extend_runtime_artifacts(&mut artifacts, &originals, |artifact| {
            resolver.has_output_authority(artifact)
        })?;
        Ok(RetainedContext {
            originals,
            artifacts,
        })
    }
}

/// Adds runtime catalogs only when original artifact authority is available.
///
/// # Errors
/// Returns any error from checking original output authority.
pub(super) fn extend_runtime_artifacts(
    retained: &mut Vec<Artifact>,
    originals: &[Envelope],
    mut has_authority: impl FnMut(&Artifact) -> Result<bool>,
) -> Result<()> {
    for artifact in originals
        .iter()
        .flat_map(|envelope| envelope.runtime_dependencies.values())
    {
        if has_authority(artifact)? && !retained.contains(artifact) {
            retained.push(artifact.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProfileScope;

    #[test]
    fn absent_profile_is_normal_but_partial_native_state_is_not() {
        let directory = tempfile::tempdir().unwrap();
        let profile = Profile {
            path: directory.path().join("profile"),
            scope: ProfileScope::User,
        };
        assert!(RetainedDiscovery::read(&profile).unwrap().is_none());

        fs::create_dir_all(profile.path.join("deployment")).unwrap();
        fs::write(profile.path.join("deployment/effects.journal"), b"partial").unwrap();
        assert!(RetainedDiscovery::read(&profile).is_err());
    }

    #[test]
    fn a_native_marker_does_not_replace_a_checked_committed_generation() {
        let directory = tempfile::tempdir().unwrap();
        let profile =
            Profile::open_at(directory.path().join("profile"), ProfileScope::User).unwrap();
        let generation = profile.new_generation().unwrap();
        fs::write(generation.path.join("native-deployment.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(
            format!("gen-{}", generation.number),
            profile.path.join("current"),
        )
        .unwrap();

        assert!(RetainedDiscovery::read(&profile).is_err());
    }
}
