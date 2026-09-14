//! Canonical protected-record payload encoders.
//!
//! These helpers deliberately encode semantic records separately from the
//! generic hash-chained protected envelope. Length-bearing plan bytes were
//! already canonically encoded and bounded at admission.

use aos_sandbox_core::ObjectDescriptor;

use super::{
    AdmissionDecisionStateV1, AdmissionDecisionV1, AdmissionError, ArtifactCommitmentV1,
    AuthorityCheckpointV1, CapacityAccountV1, CatalogEvictionReceiptV1, ChallengeConsumptionV1,
    CompletionPermitStateV1, CompletionPermitV1, CompletionReceiptV1,
    RecoveryObservationKindCodeV1, RecoveryObservationReceiptV1, ReservationStateV1,
};

pub(super) fn source_release_payload(release: &super::SourceReleaseV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(release.release_digest.as_bytes());
    bytes.extend_from_slice(release.holder.as_bytes());
    bytes.extend_from_slice(release.project.as_bytes());
    bytes.extend_from_slice(release.cache_resource.as_bytes());
    bytes.push(super::source::domain_code(release.cache_domain));
    bytes.extend_from_slice(release.cache_domain.domain_id().as_bytes());
    bytes.extend_from_slice(release.content.media_type().as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(release.content.digest().as_bytes());
    bytes.extend_from_slice(&release.content.encoded_size().to_be_bytes());
    bytes.extend_from_slice(release.producer_evidence.as_bytes());
    bytes.extend_from_slice(release.release_policy.as_bytes());
    bytes.extend_from_slice(&release.not_before_seconds.to_be_bytes());
    bytes.extend_from_slice(&release.expires_seconds.to_be_bytes());
    bytes.push(match release.state {
        super::SourceReleaseStateV1::Active => 1,
        super::SourceReleaseStateV1::Revoked => 2,
    });
    bytes
}

pub(super) fn decode_plan_content(
    decision: &AdmissionDecisionV1,
) -> Result<ObjectDescriptor, AdmissionError> {
    let plan = aos_sandbox_core::format::decode_publisher_domain_plan(
        &decision.canonical_plan,
        aos_sandbox_core::DecodeLimits::default(),
    )
    .map_err(|_| AdmissionError::ArtifactMismatch)?;
    Ok(plan.fields().request.content.clone())
}

pub(super) fn challenge_key_bytes(challenge: &ChallengeConsumptionV1) -> Vec<u8> {
    [
        challenge.publisher_instance.as_bytes().as_slice(),
        challenge.challenge.as_bytes().as_slice(),
    ]
    .concat()
}

pub(super) fn challenge_payload(challenge: &ChallengeConsumptionV1) -> Vec<u8> {
    [
        challenge.request_commitment.as_bytes().as_slice(),
        challenge.operation.as_bytes().as_slice(),
        challenge.reservation.as_bytes().as_slice(),
        challenge.decision_digest.as_bytes().as_slice(),
    ]
    .concat()
}

pub(super) fn decision_payload(decision: &AdmissionDecisionV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(decision.operation.as_bytes());
    bytes.extend_from_slice(decision.reservation.as_bytes());
    bytes.extend_from_slice(decision.publisher_instance.as_bytes());
    bytes.extend_from_slice(decision.runtime_binding_digest.as_bytes());
    bytes.extend_from_slice(decision.source_release_digest.as_bytes());
    bytes.extend_from_slice(decision.root_registry_digest.as_bytes());
    bytes.extend_from_slice(&decision.root_registry_generation.to_be_bytes());
    bytes.extend_from_slice(decision.selected_root_digest.as_bytes());
    bytes.extend_from_slice(&decision.selected_root_generation.to_be_bytes());
    bytes.extend_from_slice(&decision.authority_epoch.get().to_be_bytes());
    bytes.push(decision_state_code(decision.state));
    bytes.extend_from_slice(decision.decision_digest.as_bytes());
    bytes.extend_from_slice(&(decision.canonical_request.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&decision.canonical_request);
    bytes.extend_from_slice(&(decision.canonical_plan.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&decision.canonical_plan);
    bytes
}

pub(super) fn artifact_payload(artifact: &ArtifactCommitmentV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(artifact.operation.as_bytes());
    bytes.extend_from_slice(artifact.publisher_instance.as_bytes());
    bytes.extend_from_slice(artifact.decision_digest.as_bytes());
    bytes.extend_from_slice(&artifact.root_generation.to_be_bytes());
    bytes.extend_from_slice(artifact.content.media_type().as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(artifact.content.digest().as_bytes());
    bytes.extend_from_slice(&artifact.content.encoded_size().to_be_bytes());
    bytes.extend_from_slice(&artifact.verity_sha256);
    bytes.extend_from_slice(artifact.private_name_digest.as_bytes());
    bytes.extend_from_slice(artifact.final_name_digest.as_bytes());
    bytes.extend_from_slice(&artifact.bytes.to_be_bytes());
    bytes.extend_from_slice(&artifact.allocated_bytes.to_be_bytes());
    bytes.extend_from_slice(artifact.artifact_digest.as_bytes());
    bytes
}

pub(super) fn permit_payload(permit: &CompletionPermitV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(permit.permit.as_bytes());
    bytes.extend_from_slice(permit.operation.as_bytes());
    bytes.extend_from_slice(permit.reservation.as_bytes());
    bytes.extend_from_slice(permit.artifact_digest.as_bytes());
    bytes.extend_from_slice(permit.decision_digest.as_bytes());
    bytes.extend_from_slice(permit.publisher_instance.as_bytes());
    bytes.extend_from_slice(&permit.root_generation.to_be_bytes());
    bytes.extend_from_slice(&permit.authority_epoch.get().to_be_bytes());
    bytes.push(permit_state_code(permit.state));
    bytes.extend_from_slice(permit.permit_digest.as_bytes());
    bytes
}

pub(super) fn receipt_payload(receipt: &CompletionReceiptV1) -> Vec<u8> {
    let entry = super::read_authority::encode_committed_read_entry_v1(&receipt.catalog_entry);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(receipt.permit.as_bytes());
    bytes.extend_from_slice(receipt.operation.as_bytes());
    bytes.extend_from_slice(receipt.artifact_digest.as_bytes());
    bytes.extend_from_slice(&receipt.catalog_generation.to_be_bytes());
    bytes.extend_from_slice(receipt.catalog_entry_digest.as_bytes());
    bytes.extend_from_slice(&receipt.resident_bytes.to_be_bytes());
    bytes.extend_from_slice(&(entry.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&entry);
    bytes.extend_from_slice(receipt.receipt_digest.as_bytes());
    bytes
}

pub(super) fn eviction_payload(eviction: &CatalogEvictionReceiptV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(eviction.operation.as_bytes());
    bytes.extend_from_slice(eviction.catalog_entry_digest.as_bytes());
    bytes.extend_from_slice(&eviction.prior_catalog_generation.to_be_bytes());
    bytes.extend_from_slice(&eviction.eviction_catalog_generation.to_be_bytes());
    bytes.extend_from_slice(&eviction.released_bytes.to_be_bytes());
    bytes.extend_from_slice(eviction.eviction_digest.as_bytes());
    bytes
}

pub(super) fn recovery_observation_payload(receipt: &RecoveryObservationReceiptV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(receipt.operation.as_bytes());
    bytes.push(match receipt.outcome {
        RecoveryObservationKindCodeV1::NoEffect => 1,
        RecoveryObservationKindCodeV1::PrivateArtifact => 2,
        RecoveryObservationKindCodeV1::AbsentAfterFence => 3,
        RecoveryObservationKindCodeV1::FinalCatalogAbsent => 4,
        RecoveryObservationKindCodeV1::FinalCatalogRepaired => 5,
        RecoveryObservationKindCodeV1::Committed => 6,
        RecoveryObservationKindCodeV1::Contradiction => 7,
    });
    bytes.extend_from_slice(
        receipt
            .artifact_digest
            .map_or([0; 32], |digest| *digest.as_bytes())
            .as_slice(),
    );
    bytes.extend_from_slice(
        receipt
            .catalog_entry_digest
            .map_or([0; 32], |digest| *digest.as_bytes())
            .as_slice(),
    );
    bytes.extend_from_slice(&receipt.repair_prior_catalog_generation.to_be_bytes());
    bytes.extend_from_slice(
        receipt
            .repair_authorization_digest
            .map_or([0; 32], |digest| *digest.as_bytes())
            .as_slice(),
    );
    bytes.extend_from_slice(receipt.physical_root_digest.as_bytes());
    bytes.extend_from_slice(receipt.physical_observation_digest.as_bytes());
    bytes.extend_from_slice(
        receipt
            .executor_instance
            .map_or([0; 16], |instance| *instance.as_bytes())
            .as_slice(),
    );
    bytes.extend_from_slice(
        receipt
            .executor_fence_digest
            .map_or([0; 32], |digest| *digest.as_bytes())
            .as_slice(),
    );
    bytes.extend_from_slice(receipt.receipt_digest.as_bytes());
    bytes
}

pub(super) fn accounting_payload(account: &CapacityAccountV1) -> Vec<u8> {
    let predecessor = account
        .predecessor_digest
        .map_or([0; 32], |digest| *digest.as_bytes());
    let mut bytes = Vec::new();
    bytes.extend_from_slice(account.reservation.as_bytes());
    bytes.extend_from_slice(&account.authority_epoch.get().to_be_bytes());
    bytes.extend_from_slice(account.resource.as_bytes());
    bytes.extend_from_slice(account.project.as_bytes());
    bytes.push(super::accounting::domain_code(account.domain));
    bytes.extend_from_slice(account.domain.domain_id().as_bytes());
    bytes.push(reservation_state_code(account.state));
    bytes.extend_from_slice(&account.reserved_bytes.to_be_bytes());
    bytes.extend_from_slice(&account.resident_bytes.to_be_bytes());
    bytes.extend_from_slice(&account.generation.to_be_bytes());
    bytes.extend_from_slice(&predecessor);
    bytes.extend_from_slice(account.digest.as_bytes());
    bytes
}

pub(super) fn checkpoint_payload(checkpoint: &AuthorityCheckpointV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&checkpoint.epoch.get().to_be_bytes());
    bytes.extend_from_slice(&checkpoint.sequence.to_be_bytes());
    bytes.extend_from_slice(checkpoint.state_digest.as_bytes());
    bytes.extend_from_slice(checkpoint.outstanding_digest.as_bytes());
    bytes.extend_from_slice(&checkpoint.outstanding_count.to_be_bytes());
    bytes.push(u8::from(checkpoint.poisoned));
    bytes
}

fn decision_state_code(state: AdmissionDecisionStateV1) -> u8 {
    match state {
        AdmissionDecisionStateV1::Admitted => 1,
        AdmissionDecisionStateV1::ArtifactPrepared => 2,
        AdmissionDecisionStateV1::CompletionPermitted => 3,
        AdmissionDecisionStateV1::RevocationPending => 4,
        AdmissionDecisionStateV1::Completed => 5,
        AdmissionDecisionStateV1::Aborted => 6,
        AdmissionDecisionStateV1::Uncertain => 7,
        AdmissionDecisionStateV1::Poisoned => 8,
    }
}

fn permit_state_code(state: CompletionPermitStateV1) -> u8 {
    match state {
        CompletionPermitStateV1::Outstanding => 1,
        CompletionPermitStateV1::RevocationPending => 2,
        CompletionPermitStateV1::Spent => 3,
        CompletionPermitStateV1::RetiredWithoutEffect => 4,
        CompletionPermitStateV1::Uncertain => 5,
    }
}

fn reservation_state_code(state: ReservationStateV1) -> u8 {
    match state {
        ReservationStateV1::Reserved => 1,
        ReservationStateV1::Uncertain => 2,
        ReservationStateV1::Resident => 3,
        ReservationStateV1::Released => 4,
        ReservationStateV1::Evicted => 5,
    }
}
