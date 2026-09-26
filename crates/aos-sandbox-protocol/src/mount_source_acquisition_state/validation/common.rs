//! Exact record resolvers and shared cryptographic projection helpers.

use super::*;

pub(super) fn reconciliation_commitment(value: &ReconciliationV2) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.source-provider-reconciliation.v2\0");
    digest.update(value.projection_epoch.to_be_bytes());
    digest.update(value.projection_digest);
    digest.update(value.residual_count.to_be_bytes());
    digest.update(value.residual_digest);
    digest.update(value.conflict_count.to_be_bytes());
    digest.update(value.conflict_digest);
    digest.finalize().into()
}

pub(super) fn exact_session(
    table: &SourceAcquisitionTableV2,
    id: [u8; 32],
    digest: [u8; 32],
) -> Result<&SourceProviderSessionV2> {
    table
        .provider_sessions
        .get(&id)
        .filter(|session| session.record_digest == digest)
        .ok_or_else(|| state_error("provider session reference is dangling or stale"))
}

pub(super) fn exact_attempt(
    table: &SourceAcquisitionTableV2,
    reference: RecordRefV2,
) -> Result<&SourceProviderQueryAttemptV2> {
    table
        .provider_attempts
        .get(&reference.id)
        .filter(|attempt| {
            attempt.revision == reference.revision
                && attempt.record_digest == reference.record_digest
        })
        .ok_or_else(|| state_error("provider attempt reference is dangling or stale"))
}

pub(super) fn resolve_historical_attempt(
    table: &SourceAcquisitionTableV2,
    reference: RecordRefV2,
) -> Result<SourceProviderQueryAttemptV2> {
    let current = table
        .provider_attempts
        .get(&reference.id)
        .ok_or_else(|| state_error("historical provider attempt is missing"))?;
    if current.revision == reference.revision && current.record_digest == reference.record_digest {
        return Ok(current.clone());
    }
    if reference.revision != 2 || current.revision != 3 {
        return Err(state_error(
            "historical provider attempt reference has an invalid revision",
        ));
    }

    let mut historical = current.clone();
    let attempt_id = historical.attempt_id;
    let ProviderAttemptStateV2::AbandonedIndeterminate {
        recovery_root_attempt_id,
        resolution,
        ..
    } = &mut historical.state
    else {
        return Err(state_error(
            "historical provider attempt is not a resolved abandoned root",
        ));
    };
    if *recovery_root_attempt_id != attempt_id || resolution.take().is_none() {
        return Err(state_error(
            "historical provider attempt resolution is not reconstructible",
        ));
    }
    historical.revision = 2;
    historical.record_digest = record_digest(&StoredRecordV2::ProviderQueryAttempt {
        value: historical.clone(),
    })?;
    if historical.record_digest != reference.record_digest {
        return Err(state_error(
            "historical provider attempt digest does not reconstruct",
        ));
    }
    Ok(historical)
}

pub(super) fn session_holder_authority(
    session: &SourceProviderSessionV2,
) -> Result<SourceProviderAuthorityV1> {
    SourceProviderAuthorityV1::new(
        session.scope.holder_authority_id,
        session.root_mount_authority_generation,
        ObjectDigest::from_bytes(session.root_mount_authority_digest),
    )
    .map_err(|_| state_error("retained Root Mount authority is invalid"))
}

pub(super) fn session_provider_authority(
    session: &SourceProviderSessionV2,
) -> Result<SourceProviderAuthorityV1> {
    SourceProviderAuthorityV1::new(
        session.scope.provider_authority_id,
        session.provider_authority_generation,
        ObjectDigest::from_bytes(session.provider_authority_digest),
    )
    .map_err(|_| state_error("retained provider authority is invalid"))
}

pub(super) fn historical_outcome_signer(
    snapshot: &SignerSnapshotV2,
) -> Result<SourceProviderSigningKeyV1> {
    if snapshot.role != SignerRoleV2::ProviderOutcome
        || snapshot.authority_state != AuthorityAdmissionStateV2::Trusted
        || snapshot.key_state != KeyAdmissionStateV2::Eligible
        || snapshot.public_key == [0; 32]
        || (snapshot.superseded_by_key_generation != 0
            && snapshot.superseded_by_key_generation <= snapshot.key_generation)
        || <[u8; 32]>::from(Sha256::digest(snapshot.public_key)) != snapshot.public_key_fingerprint
    {
        return Err(state_error(
            "historical lease signer lacks ProviderOutcome trust",
        ));
    }
    SourceProviderSigningKeyV1::new(
        snapshot.authority_id,
        snapshot.authority_generation,
        ObjectDigest::from_bytes(snapshot.authority_digest),
        snapshot.key_id,
        snapshot.key_generation,
        ObjectDigest::from_bytes(snapshot.public_key_fingerprint),
        SourceProviderKeyUsageV1::ProviderOutcome,
    )
    .map_err(|_| state_error("historical lease signer is invalid"))
}

pub(super) fn historical_selection_floor(
    evidence: &SourceAcquisitionEvidenceV2,
) -> Result<SourceSelectionFloorV1> {
    let historical = &evidence.historical_lease_signer;
    let snapshot = &historical.selection_floor;
    let signer = historical_outcome_signer(&historical.signer)?;
    let floor = crate::mount_source_acquisition_state::protocol_selection_floor_v2(snapshot)?;
    if floor.outcome_signer() != &signer
        || floor.digest().as_bytes() != &historical.selection_floor_digest
    {
        return Err(state_error("historical selection-floor digest differs"));
    }
    Ok(floor)
}

pub(super) fn interval_contains(start: i64, end: i64, value: i64) -> bool {
    start >= 0 && start < end && start <= value && value < end
}

pub(super) fn generation_dominates_snapshot(
    old_generation: u64,
    old_digest: [u8; 32],
    current_generation: u64,
    current_digest: [u8; 32],
) -> bool {
    current_generation > old_generation
        || (current_generation == old_generation && current_digest == old_digest)
}

pub(super) fn valid_scope(scope: ProviderScopeV2) -> bool {
    scope.holder_authority_id != [0; 16]
        && scope.provider_authority_id != [0; 16]
        && scope.route_id != [0; 16]
        && scope.resource_namespace_digest != [0; 32]
}

pub(super) fn method_owner_intent_match(attempt: &SourceProviderQueryAttemptV2) -> bool {
    let method_matches = matches!(
        (&attempt.intent, attempt.method, attempt.owner),
        (
            ProviderIntentV2::Acquire { .. },
            ProviderMethodV2::Acquire,
            ProviderQueryOwnerV2::Acquire { .. }
        ) | (
            ProviderIntentV2::Release { .. },
            ProviderMethodV2::Release,
            ProviderQueryOwnerV2::Release { .. }
        ) | (
            ProviderIntentV2::Inventory { .. },
            ProviderMethodV2::Inventory,
            ProviderQueryOwnerV2::Inventory
        )
    );
    let provider_identity_matches = match attempt.method {
        ProviderMethodV2::Acquire | ProviderMethodV2::Release => {
            attempt.provider_acquisition.is_some()
        }
        ProviderMethodV2::Inventory => attempt.provider_acquisition.is_none(),
    };
    method_matches && provider_identity_matches && attempt.method.tag() == attempt.owner.tag()
}

pub(super) fn is_complete(attempt: &SourceProviderQueryAttemptV2) -> bool {
    matches!(
        &attempt.state,
        ProviderAttemptStateV2::DispositionConsumed {
            status: ProviderStatusV2::Complete,
            ..
        }
    )
}

pub(super) fn consumption_evidence_is_valid(value: &ConsumptionEvidenceV2) -> bool {
    value.holder_sequence_revision != 0
        && value.provider_head_revision != 0
        && value.transaction_id != [0; 16]
        && value.operation_id != [0; 16]
        && value.transport_request_digest != [0; 32]
        && !value.final_create_semantics.is_empty()
        && value.final_create_semantics.len() <= 2 * 1024
        && value.final_create_semantics_digest != [0; 32]
        && BrokerArgumentCommitment::for_canonical_bytes(&value.final_create_semantics).digest()
            == ObjectDigest::from_bytes(value.final_create_semantics_digest)
        && value.source_pin_record_digest != [0; 32]
        && value.create_effect_record_digest != [0; 32]
        && value.create_operation_record_digest != [0; 32]
}

pub(super) fn consumption_matches_template(
    value: &ConsumptionEvidenceV2,
    expected_template: Option<&[u8]>,
    expected_template_digest: [u8; 32],
) -> bool {
    let Ok(projected) = project_final_mount_create_semantics_v1(&value.final_create_semantics)
    else {
        return false;
    };
    expected_template.is_none_or(|expected| projected == expected)
        && prospective_mount_apply_template_digest_v1(&projected)
            .is_ok_and(|digest| *digest.as_bytes() == expected_template_digest)
}
