//! Normalized intent, backend selection, limits, and identity derivation.

use super::*;

pub(super) fn normalized_intent(
    verified: &VerifiedProviderAcquireRequestV1,
) -> Result<NormalizedAcquisitionIntentV1, ProviderLedgerError> {
    let request = verified.request();
    let projection = verified.ingress_projection();
    NormalizedAcquisitionIntentV1::from_acquire_request(
        request,
        projection.provider_authority().clone(),
        projection.root_mount_authority().clone(),
        request.node_id(),
        request.boot_id(),
        projection.route_id(),
        projection.route_generation(),
        projection.route_digest(),
        projection.resource_namespace_digest(),
        projection.revocation_generation(),
        projection.revocation_digest(),
    )
    .map_err(|_| ProviderLedgerError::Corrupt("normalized acquisition intent"))
}

pub(crate) fn validate_backend_selection(
    ledger: &ProviderLedgerV1<'_>,
    acquisition: &AcquisitionRecordV1,
    attempt: &crate::model::AttemptRecordV1,
    observed: &ObservedBackendAcquisitionV1,
) -> Result<(), ProviderLedgerError> {
    let resource = &observed.resource;
    let proof_class_matches = matches!(
        (&observed.proof, observed.evidence.class()),
        (
            aos_sandbox_source_provider_protocol::SourceProviderProofV1::ZfsHeldSnapshot { .. },
            crate::BackendEvidenceClassV1::ZfsHeldSnapshot
        ) | (
            aos_sandbox_source_provider_protocol::SourceProviderProofV1::LocalLiveExport { .. },
            crate::BackendEvidenceClassV1::LocalLiveExport
        ) | (
            aos_sandbox_source_provider_protocol::SourceProviderProofV1::ImmutablePublisherTree { .. },
            crate::BackendEvidenceClassV1::ImmutablePublisherTree
        ) | (
            aos_sandbox_source_provider_protocol::SourceProviderProofV1::BestEffortReplica { .. },
            crate::BackendEvidenceClassV1::BestEffortReplica
        )
    );
    if !proof_class_matches
        || resource.resource_namespace_digest()
            != acquisition.normalized_intent.resource_namespace_digest()
        || resource.catalog_generation() != ledger.recovered.catalog.catalog_generation
        || resource.catalog_digest() != ledger.recovered.catalog.catalog_digest
        || observed.evidence.class() as u8 == 0
        || observed.evidence.backend_digest().as_bytes() == &[0; 32]
        || observed.reopen_identity.class() != observed.evidence.class()
        || observed.reopen_identity.backend_id() != observed.backend_id
        || observed.reopen_identity.backend_generation() != observed.evidence.backend_generation()
        || observed.reopen_identity.backend_digest() != observed.evidence.backend_digest()
        || observed.reopen_identity.resource_id() != resource.resource_id()
        || observed.reopen_identity.resource_generation() != resource.resource_generation()
        || observed.reopen_identity.resource_digest() != resource.resource_digest()
        || observed.reopen_identity.authority_object_id() == [0; 32]
        || observed.reopen_identity.authority_generation() == 0
        || observed.reopen_identity.authority_digest().as_bytes() == &[0; 32]
        || !observed.reopen_identity.matches_proof(&observed.proof)
        || observed.observed_seconds < attempt.verified_at_seconds
        || observed.observed_seconds >= attempt.current_valid_until_seconds
    {
        return Err(ProviderLedgerError::BackendConflict);
    }
    let capability = 1_u8 << (observed.evidence.class() as u8 - 1);
    let holder_proof_matches = match &observed.proof {
        aos_sandbox_source_provider_protocol::SourceProviderProofV1::LocalLiveExport {
            proof,
            ..
        } => {
            proof.consumer_authority_id() == acquisition.holder.authority_id()
                && proof.consumer_generation() == acquisition.holder.authority_generation()
        }
        _ => true,
    };
    if ledger.recovered.authority.proof_class_capabilities & capability == 0
        || attempt.proof_class_capabilities & capability == 0
        || observed.proof.capability_bit() != capability
        || observed.proof.requires_kernel_coupled()
            != acquisition.normalized_intent.kernel_coupled()
        || (acquisition.normalized_intent.recursive()
            && (!ledger.recovered.authority.supports_recursive || !attempt.supports_recursive))
        || (acquisition.normalized_intent.kernel_coupled()
            && (!ledger.recovered.authority.supports_kernel_coupled
                || !attempt.supports_kernel_coupled))
        || observed.proof.topology().observed_submounts()
            > acquisition.normalized_intent.requested_maximum_submounts()
        || (!acquisition.normalized_intent.recursive()
            && observed.proof.topology().observed_submounts() != 0)
        || !holder_proof_matches
    {
        return Err(ProviderLedgerError::BackendConflict);
    }
    Ok(())
}

pub(super) fn enforce_acquire_limits(
    ledger: &ProviderLedgerV1<'_>,
    holder_id: [u8; 16],
) -> Result<(), ProviderLedgerError> {
    let limits = ledger.configuration.limits();
    if ledger
        .recovered
        .attempts
        .len()
        .saturating_add(ledger.recovered.acquisitions.len())
        .saturating_add(ledger.recovered.releases.len())
        .checked_add(2)
        .is_none_or(|count| count > limits.maximum_retained_identities())
    {
        return Err(ProviderLedgerError::LimitExceeded("retained identities"));
    }
    let active = ledger
        .recovered
        .acquisitions
        .values()
        .filter(|record| {
            record.holder.authority_id() == holder_id
                && matches!(
                    record.state,
                    ProviderAcquisitionStateV1::Pending
                        | ProviderAcquisitionStateV1::Active
                        | ProviderAcquisitionStateV1::Releasing
                )
        })
        .count();
    if active >= limits.maximum_active_acquisitions_per_holder() {
        return Err(ProviderLedgerError::LimitExceeded(
            "active acquisitions per holder",
        ));
    }
    Ok(())
}

pub(crate) fn derive_acquire_effect_id(
    acquisition_id: ObjectDigest,
    attempt_digest: ObjectDigest,
) -> Result<[u8; 16], ProviderLedgerError> {
    aos_sandbox_source_provider_ledger::identity::acquire_effect_id_v1(
        acquisition_id,
        attempt_digest,
    )
    .ok_or(ProviderLedgerError::Corrupt("zero derived effect ID"))
}

pub(crate) fn derive_backend_plan_id(
    intent_digest: ObjectDigest,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
) -> [u8; 32] {
    aos_sandbox_source_provider_ledger::identity::acquire_backend_plan_id_v1(
        intent_digest,
        catalog_generation,
        catalog_digest,
    )
}

pub(crate) fn derive_lease_id(
    acquisition_id: ObjectDigest,
    lease_generation: u64,
    backend_id: [u8; 32],
) -> Result<[u8; 16], ProviderLedgerError> {
    aos_sandbox_source_provider_ledger::identity::lease_id_v1(
        acquisition_id,
        lease_generation,
        backend_id,
    )
    .ok_or(ProviderLedgerError::Corrupt("zero derived lease ID"))
}
