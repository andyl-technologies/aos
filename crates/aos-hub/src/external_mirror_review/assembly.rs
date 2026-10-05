//! Exact actual-file joins for the unsigned functional-only Mirror statement.

use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use aos_hub_core::{
    direct_upload::{
        DirectProtectedProfile, DirectWorkerExecutionKind, DirectWorkerQualificationArtifact,
    },
    mirror_acceptance::external_controlled::{
        ControlledExternalMirrorArtifact, ControlledExternalMirrorExecution,
        ControlledExternalMirrorInstallation, ControlledExternalMirrorPurpose,
    },
};
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use super::{clock, domain, files, installation, provider, selection::*};

pub(super) fn read(
    base: &Path,
    selected: &MirrorReviewFile,
    limit: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        selected.byte_size > 0
            && selected.byte_size <= limit
            && aos_hub_core::direct_upload::valid_direct_digest(&selected.sha256),
        "Mirror file selection differs"
    );
    let bytes = files::private_bytes(&base.join(&selected.path), limit)?;
    ensure!(
        u64::try_from(bytes.len())? == selected.byte_size
            && files::digest(&bytes) == selected.sha256,
        "Mirror selected actual bytes differ"
    );
    Ok(bytes)
}

pub(super) fn document<T: DeserializeOwned>(base: &Path, selected: &MirrorReviewFile) -> Result<T> {
    Ok(serde_json::from_slice(&read(base, selected, 256 * 1024)?)?)
}

pub(super) fn assemble(
    selection_file: &Path,
    current: u64,
) -> Result<ExternalMirrorReviewCandidate> {
    let base = selection_file
        .parent()
        .context("Mirror selection has no parent")?;
    let selection_bytes = files::private_bytes(selection_file, 256 * 1024)?;
    let selected: ExternalMirrorReviewSelection = serde_json::from_slice(&selection_bytes)?;
    ensure!(
        selected.version == 1 && selected.issued_at <= current && current < selected.valid_until,
        "Mirror selection issue or cutoff differs"
    );
    let public = files::public_key(&read(base, &selected.reviewer_public_key, 65)?)?;
    let prerequisite_bytes = read(base, &selected.inputs.prerequisite_artifact, 256 * 1024)?;
    let prerequisite: DirectWorkerQualificationArtifact =
        serde_json::from_slice(&prerequisite_bytes)?;
    let keys: super::observations::ReviewerKeys =
        document(base, &selected.inputs.prerequisite_review_keys)?;
    ensure!(
        prerequisite.execution_kind == DirectWorkerExecutionKind::EmulatedExternal
            && prerequisite.deployment_id == selected.deployment_id
            && prerequisite.public_origin == selected.public_origin
            && prerequisite.source_digest == selected.source_digest
            && prerequisite.script_version == selected.script_version
            && prerequisite.reviewer_key_id != selected.reviewer_key_id,
        "Mirror differs from current External prerequisite or independent reviewer"
    );
    for key in keys.values() {
        aos_hub_core::mirror_acceptance::external_controlled::require_distinct_external_mirror_reviewer(&public, key)?;
    }

    // The unchanged current loader authenticates the prerequisite under its
    // separate trust map; the selection cannot manufacture an accepted profile.
    let acceptances = crate::direct_upload::authority::NativeDirectUploadAcceptances::from_files(
        &base.join(&selected.inputs.prerequisite_artifact.path),
        &base.join(&selected.inputs.prerequisite_review_keys.path),
    )?;
    let profiles =
        acceptances.profiles(&selected.deployment_id, &selected.public_origin, current)?;
    let matching = profiles
        .into_iter()
        .filter(|profile| {
            profile
                .digest()
                .is_ok_and(|digest| digest == selected.profile_digest)
        })
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "Mirror current External prerequisite is absent or ambiguous"
    );
    let DirectProtectedProfile::External {
        profile,
        runtime_qualification,
    } = matching
        .into_iter()
        .next()
        .context("Mirror selected profile absent")?
    else {
        anyhow::bail!("Mirror received a Managed prerequisite");
    };
    let protected = aos_hub_core::direct_upload::DirectProtectedExternalProfile::new(
        profile,
        runtime_qualification,
    )?;
    let (prerequisite_issue, prerequisite_expiry, direct_evidence) = acceptances
        .external_profile_window(
            &selected.deployment_id,
            &selected.public_origin,
            &selected.profile_digest,
            current,
        )?;
    ensure!(
        direct_evidence == prerequisite.evidence_sha256,
        "Mirror prerequisite evidence changed"
    );
    let issued_at = selected.issued_at.max(prerequisite_issue);
    let valid_until = selected.valid_until.min(prerequisite_expiry);
    ensure!(
        issued_at <= current && current < valid_until,
        "Mirror clipped prerequisite window differs"
    );

    installation::validate(base, &selected, &prerequisite, &public)?;
    let clock_hash = clock::validate(
        base,
        &selected,
        protected.profile.clock_uncertainty.get() as u64,
    )?;
    let installed_domain = domain::validate(base, &selected, &protected, &public)?;
    provider::validate(base, &selected, &installed_domain)?;
    let manifest: super::observations::ArtifactManifest =
        document(base, &selected.inputs.artifact_manifest)?;
    installation::validate_serving(base, &selected, &manifest)?;
    let artifact = ControlledExternalMirrorArtifact {
        version: 1,
        purpose: ControlledExternalMirrorPurpose::FullAndPullThroughFunctionalProbeV1,
        execution: ControlledExternalMirrorExecution::EmulatedExternal,
        reviewer_key_id: selected.reviewer_key_id,
        deployment_id: selected.deployment_id,
        public_origin: selected.public_origin,
        source_digest: selected.source_digest,
        script_version: selected.script_version,
        protected_profile: protected,
        direct_evidence_sha256: direct_evidence,
        external_domain_sha256: aos_hub_core::mirror_work::digest(&(
            "aos.external-mirror-installed-domain.v1",
            installed_domain,
        ))?,
        upstream_base: selected.upstream_base,
        placement_prefix: selected.placement_prefix,
        maximum_object_bytes: selected.maximum_object_bytes,
        installation: ControlledExternalMirrorInstallation {
            artifact_manifest_sha256: selected.inputs.artifact_manifest.sha256,
            wasm_sha256: selected.inputs.wasm.sha256,
            script_sha256: selected.inputs.script.sha256,
            native_executable_sha256: selected.inputs.native_serving_executable.sha256,
            configuration_sha256: selected.inputs.configuration.sha256,
            namespace_observation_sha256: selected.inputs.namespace.sha256,
            clock_observation_sha256: clock_hash,
            provider_contract_observation_sha256: selected.inputs.provider_report.sha256,
            prerequisite_artifact_sha256: selected.inputs.prerequisite_artifact.sha256,
        },
        issued_at,
        valid_until,
        signature: String::new(),
    };
    artifact.validate_unsigned(current)?;
    // Reopening after all joins prevents a replaced selection from becoming the
    // committed source of a candidate whose individual checks saw older bytes.
    ensure!(
        files::private_bytes(selection_file, 256 * 1024)?.as_slice() == selection_bytes.as_slice(),
        "Mirror selection changed during review"
    );
    Ok(ExternalMirrorReviewCandidate {
        version: 1,
        selection_sha256: files::digest(&selection_bytes),
        trusted_public_key: public,
        artifact,
    })
}
