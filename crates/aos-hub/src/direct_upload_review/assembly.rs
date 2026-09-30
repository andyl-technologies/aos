//! Candidate assembly from exact selected documents and actual deployment facts.

use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;

use super::selection::{DirectReviewCandidate, DirectReviewSelection};
use super::{files, installation, measurements, reports};

pub(super) fn assemble(path: &Path, now: u64) -> Result<DirectReviewCandidate> {
    let bytes = files::read_bytes(path, files::DOCUMENT_LIMIT)?;
    let selection: DirectReviewSelection = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("review selection is not a closed supported format"))?;
    ensure!(
        selection.version == 1,
        "review selection version unsupported"
    );
    let base = path.parent().unwrap_or(Path::new("."));
    let documents = &selection.documents;
    let trusted_public_key = files::public_key(&files::selected_bytes(
        base,
        &documents.reviewer_public_key,
        65,
    )?)?;
    let identity: DirectWorkerDeploymentIdentity =
        files::selected_document(base, &documents.deployment_identity)?;
    ensure!(
        identity.source_digest == selection.source_digest
            && identity.script_version == selection.script_version
            && identity.deployment_id == selection.deployment_id
            && identity.public_origin == selection.public_origin
            && identity.qualification_public_key == trusted_public_key,
        "review selection differs from captured installed identity"
    );

    let measured = measurements::derive(base, &selection, &identity)?;
    let clock = measured.clock;
    let runtime_measurement = measured.runtime;
    let bounds = &selection.runtime_bounds;
    let runtime = DirectRuntimeQualification {
        version: 1,
        qualification_digest: direct_qualification_digest(&runtime_measurement)?,
        maximum_object_bytes: bounds.maximum_object_bytes,
        maximum_verification_seconds: bounds.maximum_verification_seconds,
        settlement_reserve_seconds: bounds.settlement_reserve_seconds,
        maximum_parallel_objects: bounds.maximum_parallel_objects,
        maximum_parallel_provider_requests: bounds.maximum_parallel_provider_requests,
        cache_destination_policy: DirectCacheDestinationPolicy::RetainedOriginalBaseline,
    };
    let external_profiles = identity
        .external_profiles
        .iter()
        .map(|profile| DirectProtectedExternalProfile::new(profile.clone(), runtime.clone()))
        .collect::<Result<Vec<_>>>()?;
    let sdk_probe = documents
        .sdk_probe
        .as_ref()
        .map(|file| files::selected_document(base, file))
        .transpose()?;
    let privacy = documents
        .privacy
        .as_ref()
        .map(|file| files::selected_document(base, file))
        .transpose()?;
    let evidence = DirectWorkerQualificationEvidence {
        installation: installation::measure(base, &selection)?,
        clock_policy: DirectClockPolicy {
            version: 1,
            mode: identity.clock_mode,
            uncertainty_seconds: identity.clock_uncertainty_seconds,
        },
        qualification_limits: identity.qualification_limits.clone(),
        clock,
        runtime,
        runtime_measurement,
        managed_profile: identity.managed_profile.clone(),
        private_stage_policy: identity.private_stage_policy.clone(),
        external_profiles,
        sdk_probe,
        privacy,
        bulk_queue: measured.bulk,
        metadata_queue: measured.metadata,
        issued_at: selection.issued_at,
        valid_until: selection.valid_until,
    };
    let artifact = DirectWorkerQualificationArtifact {
        version: 1,
        execution_kind: selection.execution_kind,
        reviewer_key_id: selection.reviewer_key_id.clone(),
        deployment_id: selection.deployment_id.clone(),
        public_origin: selection.public_origin.clone(),
        workers_rs_version: "0.8.5".into(),
        source_digest: selection.source_digest.clone(),
        script_version: selection.script_version.clone(),
        evidence_sha256: direct_qualification_digest(&evidence)?,
        evidence,
        signature: String::new(),
    };
    artifact.validate_unsigned(&selection.deployment_id, &selection.public_origin, now)?;
    artifact.verify_deployment_identity(&identity, &trusted_public_key)?;
    reports::validate(base, &selection, &artifact)?;

    Ok(DirectReviewCandidate {
        version: 1,
        selection_sha256: files::digest(&bytes),
        trusted_public_key,
        artifact,
    })
}
