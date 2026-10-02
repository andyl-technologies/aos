//! Admission and assembly of caller-authorized immutable bootstrap sources.
//!
//! Domain consumers verify their own original authority before calling this
//! boundary. The package runtime preserves the proof identity and exact NARs,
//! evaluates the augmented inputs before live dispatch, and publishes through
//! the ordinary native profile coordinator.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::deployment::retention::ArtifactAdmission;
use crate::runtime_modules::RuntimeModuleSnapshot;

/// Records the original domain proof for caller-authorized source artifacts.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAuthorization {
    /// Names the domain authority understood by the independent verifier policy.
    pub kind: String,
    /// Locates the immutable proof document retained by the generation.
    pub proof: PathBuf,
    /// Pins the original canonical proof bytes, independently of their locator.
    pub digest: Sha256Digest,
}

impl SourceAuthorization {
    /// Checks the immutable proof locator and its original byte binding.
    ///
    /// This check establishes integrity. The caller and independent attestation
    /// policy must authenticate the authority; the document cannot authorize itself.
    ///
    /// # Errors
    /// Returns an error for invalid kinds or locators, inaccessible or oversized
    /// proof documents, or bytes that differ from the original digest.
    pub fn verify_integrity(&self) -> Result<()> {
        ensure!(
            !self.kind.is_empty()
                && self.kind.len() <= 256
                && self.kind.bytes().all(|byte| byte.is_ascii_graphic()),
            "source authorization kind is invalid"
        );
        crate::deployment::nix::store_root_and_suffix(&self.proof)?;
        ensure!(
            Sha256Digest::of_bytes(&super::read_regular_document(&self.proof)?) == self.digest,
            "source authorization proof changed"
        );
        Ok(())
    }
}

pub(super) struct BootstrapSources<'a> {
    pub(super) runtime: &'a RuntimeModuleSnapshot,
    pub(super) configuration: &'a [PathBuf],
    pub(super) supplemental_inputs: &'a [PathBuf],
    pub(super) authority: SourceAuthorization,
    pub(super) admission: &'a mut dyn ArtifactAdmission,
}

/// Applies an image profile with authenticated sources before its first effects.
///
/// The domain caller authenticates the original proof and supplies an admission
/// implementation for every added source and supplemental root. Baseline sources
/// append in the supplied order; the sealed runtime snapshot replaces only the
/// runtime role. Supplemental artifacts and the authority proof survive later
/// operator snapshot replacement and rollback.
///
/// # Errors
/// Returns an error for invalid source authority, conflicting existing bootstrap
/// state, failed immutable evaluation or admission, or native transaction failure.
pub fn apply_with_sources<A: ArtifactAdmission>(
    command: &super::NativeDeploymentCommand,
    runtime: &RuntimeModuleSnapshot,
    configuration: &[PathBuf],
    supplemental_inputs: &[PathBuf],
    authority: SourceAuthorization,
    mut source_admission: A,
    cancellation: &aos_ability_runtime::adapter::CancellationToken,
) -> Result<()> {
    let path = command
        .profile
        .as_ref()
        .context("bootstrap source application requires an authoritative profile")?;
    let (deployment, mut admission, receipt) = super::prepare(command)?;
    std::fs::create_dir_all(&command.state_directory)?;
    super::persist_receipt(&command.state_directory.join("admissions"), &receipt)?;
    let evaluation = super::EvaluationInputs::read(&command.input.join("evaluation.json"))?;
    evaluation.admit(&deployment, &mut admission)?;
    let sources = BootstrapSources {
        runtime,
        configuration,
        supplemental_inputs,
        authority,
        admission: &mut source_admission,
    };
    super::apply_profile(
        command,
        path,
        &deployment,
        admission,
        &evaluation,
        cancellation,
        Some(sources),
    )
}

/// Resumes an interrupted profile transaction before a domain reads fresh sources.
///
/// Recovery uses the retained descriptor, NAR receipts, and exact source proof
/// from the pending generation. It does not evaluate a new image baseline.
///
/// # Errors
/// Returns an error for invalid image authority, admission or journal failure,
/// lock contention, or failed recovery effects.
pub fn resume_profile(
    command: &super::NativeDeploymentCommand,
    cancellation: &aos_ability_runtime::adapter::CancellationToken,
) -> Result<Option<u32>> {
    let path = command
        .profile
        .as_ref()
        .context("profile recovery requires an authoritative profile")?;
    let (_, _, receipt) = super::prepare(command)?;
    let inspection = crate::profile::Profile {
        path: path.clone(),
        scope: crate::types::ProfileScope::System,
    };
    let _guard = inspection.lock_mutation()?;
    if !command.state_directory.join("generations.journal").exists() {
        ensure!(
            !command.state_directory.join("effects.journal").exists(),
            "profile journal is partially initialized"
        );
        return Ok(None);
    }
    super::persist_receipt(&command.state_directory.join("admissions"), &receipt)?;
    let profile =
        crate::profile::Profile::open_at(path.clone(), crate::types::ProfileScope::System)?;
    let admission = crate::native_registry::RegistryAdmission::new(
        command.nix_store.clone(),
        &command.state_directory.join("registry-admissions"),
    )?;
    let store = crate::deployment::retention::NixStore::open(
        command.nix_store.clone(),
        command.state_directory.join("roots"),
        admission,
    )?;
    let mut consumer = crate::profile::deployment::ProfileDeployment::open(
        &profile,
        store,
        crate::deployment::transaction::journal_limits(),
    )?;
    super::configure_profile_observer(&mut consumer, &profile, None, cancellation)?;
    consumer.recover(cancellation)?;
    drop(consumer);
    crate::profile::deployment::current_committed_generation(path)
}

pub(super) fn root(path: &Path) -> Result<PathBuf> {
    crate::deployment::nix::store_root_and_suffix(path).map(|(root, _)| root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_preserves_source_roles_and_requires_supplemental_roots() {
        let root = |name: &str| PathBuf::from(format!("/nix/store/{}-{name}", "a".repeat(32)));
        let mut input = super::super::EvaluationInput {
            os_release: None,
            package_envelopes: Default::default(),
            schema: "aos.package.evaluation-input".into(),
            library: root("library").join("default.nix"),
            library_nar_hash: Sha256Digest::of_bytes(b"library NAR"),
            scope: vec!["profile".into(), "system".into()],
            packages: crate::deployment::model::ResolvedPackages {
                system: "x86_64-linux".into(),
                artifacts: Vec::new(),
                modules: Vec::new(),
            },
            module_envelopes: Default::default(),
            resolution_lock: None,
            configuration: vec![
                root("baseline").join("first.nix"),
                root("facts").join("second.nix"),
            ],
            runtime_configuration: vec![root("runtime").join("host.nix")],
            supplemental_inputs: vec![root("proof.json")],
        };
        let encoded = serde_json::to_vec(&input).unwrap();
        let decoded = super::super::EvaluationInput::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
        assert_eq!(decoded.configuration[0], root("baseline").join("first.nix"));
        assert_eq!(
            decoded.runtime_configuration,
            vec![root("runtime").join("host.nix")]
        );
        assert_eq!(decoded.supplemental_inputs, vec![root("proof.json")]);

        let envelope = crate::deployment::model::Envelope::decode(&serde_json::to_vec(&serde_json::json!({
            "schema":"aos.package.deployment", "system":"x86_64-linux",
            "package":{"name":"schema-only","version":"1", "path":root("payload"), "outputs":{"out":root("payload")}},
            "module":{"name":"schema-only","version":"1", "source":root("module"),"entrypoint":"module.nix"},
            "runtimeDependencies":{},"moduleDependencies":[]
        })).unwrap()).unwrap();
        input
            .packages
            .modules
            .push(envelope.module_record().unwrap());
        assert!(
            super::super::EvaluationInput::decode(&serde_json::to_vec(&input).unwrap()).is_err()
        );
        input
            .module_envelopes
            .insert("schema-only".into(), root("deployment"));
        let decoded =
            super::super::EvaluationInput::decode(&serde_json::to_vec(&input).unwrap()).unwrap();
        assert!(decoded.packages.artifacts.is_empty());
        assert_eq!(decoded.module_envelopes["schema-only"], root("deployment"));

        input
            .module_envelopes
            .insert("foreign".into(), root("foreign"));
        assert!(
            super::super::EvaluationInput::decode(&serde_json::to_vec(&input).unwrap()).is_err()
        );
        input.module_envelopes.remove("foreign");
        input
            .packages
            .modules
            .push(input.packages.modules[0].clone());
        assert!(
            super::super::EvaluationInput::decode(&serde_json::to_vec(&input).unwrap()).is_err()
        );
        input.packages.modules.pop();

        input.supplemental_inputs = vec![root("proof").join("member.json")];
        assert!(
            super::super::EvaluationInput::decode(&serde_json::to_vec(&input).unwrap()).is_err()
        );
    }
}
