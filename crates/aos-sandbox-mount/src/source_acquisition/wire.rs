//! Unchanged Mount 2.0 projection of private `AOSMSA02` state.
//!
//! The public protocol deliberately keeps one provider-key projection: it is
//! the ProviderOutcome signer for the exact Acquire evidence attempt, or the
//! current referenced Acquire attempt when evidence is not yet complete. Four-key session
//! detail and attempt histories remain private durable state.

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, MountAssignmentBinding, MountOperationCorrelation,
    MountSourceAcquisitionFault, MountSourceAcquisitionPhase, MountSourceAcquisitionRecord,
    MountSourceProofClass,
};

use super::SourceAcquisitionTableV2;
use super::format::state_error;
use super::model::{
    MountOperationV2, ProviderAttemptStateV2, ReleaseProofV2, SourceAcquisitionPhaseV2,
    SourceAcquisitionProofClassV2, SourceAcquisitionRowV2,
};
use crate::Result;

pub(super) fn source_acquisition_record(
    table: &SourceAcquisitionTableV2,
    row: &SourceAcquisitionRowV2,
) -> Result<MountSourceAcquisitionRecord> {
    let acquire_reference = row
        .evidence
        .as_ref()
        .map_or(row.acquire_lineage.tail, |evidence| {
            evidence.acquire_attempt
        });
    let acquire_attempt = exact_attempt(table, acquire_reference)?;
    let session = table
        .provider_sessions
        .get(&acquire_attempt.session_id)
        .filter(|session| session.record_digest == acquire_attempt.session_record_digest)
        .ok_or_else(|| state_error("wire projection session is missing"))?;
    let provider_outcome = &session.signers[3];

    let operation = |value: MountOperationV2| MountOperationCorrelation {
        operation_id: value.operation_id.to_vec(),
        request_digest: value.request_digest.to_vec(),
        ..Default::default()
    };
    let mut record = MountSourceAcquisitionRecord {
        acquisition_id: row.acquisition_id.to_vec(),
        revision: row.revision,
        phase: source_acquisition_phase(row.phase).into(),
        acquire: Some(operation(row.acquire)).into(),
        release: row.release.map(operation).into(),
        assignment: Some(MountAssignmentBinding {
            fence: Some(AssignmentFence {
                sandbox_id: row.assignment.sandbox_id.to_vec(),
                incarnation_id: row.assignment.incarnation_id.to_vec(),
                assignment_epoch: row.assignment.assignment_epoch,
                desired_generation: row.assignment.desired_generation,
                assignment_digest: row.assignment.assignment_digest.to_vec(),
                ..Default::default()
            })
            .into(),
            namespace_generation: row.assignment.namespace_generation,
            ..Default::default()
        })
        .into(),
        prospective_mount_template_digest: row.prospective_mount_template_digest.to_vec(),
        source_binding_digest: row.source_binding_digest.to_vec(),
        provider_route_id: session.scope.route_id.to_vec(),
        provider_route_generation: session.route_generation,
        provider_route_digest: session.route_digest.to_vec(),
        provider_authority_id: session.scope.provider_authority_id.to_vec(),
        provider_authority_generation: session.provider_authority_generation,
        provider_authority_digest: session.provider_authority_digest.to_vec(),
        provider_key_id: provider_outcome.key_id.to_vec(),
        provider_key_generation: provider_outcome.key_generation,
        provider_public_key_digest: provider_outcome.public_key_fingerprint.to_vec(),
        resource_namespace_digest: session.scope.resource_namespace_digest.to_vec(),
        provider_acquire_request_digest: acquire_attempt.signed_request_digest.to_vec(),
        provider_acquire_status_digest: status_digest(Some(acquire_attempt)),
        provider_release_request_digest: row
            .release_lineage
            .as_ref()
            .map(|lineage| exact_attempt(table, lineage.tail))
            .transpose()?
            .map_or_else(Vec::new, |value| value.signed_request_digest.to_vec()),
        provider_release_status_digest: status_digest(
            row.release_lineage
                .as_ref()
                .map(|lineage| exact_attempt(table, lineage.tail))
                .transpose()?,
        ),
        provider_inventory_digest: match row.release_proof.as_ref() {
            Some(ReleaseProofV2::ProviderInventory {
                inventory_digest, ..
            }) => inventory_digest.to_vec(),
            _ => Vec::new(),
        },
        release_generation: match row.release_proof.as_ref() {
            Some(ReleaseProofV2::ProviderReceipt {
                release_generation, ..
            }) => *release_generation,
            _ => 0,
        },
        fault: row
            .faulted_from
            .zip(row.fault_digest)
            .or_else(|| row.retained_faulted_from.zip(row.retained_fault_digest))
            .map(|(from, failure_digest)| MountSourceAcquisitionFault {
                from: source_acquisition_phase(from).into(),
                failure_digest: failure_digest.to_vec(),
                ..Default::default()
            })
            .into(),
        record_digest: row.record_digest.to_vec(),
        ..Default::default()
    };
    if let Some(evidence) = &row.evidence {
        record.provider_resource_id = evidence.provider_resource_id.to_vec();
        record.provider_resource_generation = evidence.provider_resource_generation;
        record.provider_resource_digest = evidence.provider_resource_digest.to_vec();
        record.provider_catalog_generation = evidence.provider_catalog_generation;
        record.provider_catalog_digest = evidence.provider_catalog_digest.to_vec();
        record.provider_selection_generation = evidence.provider_selection_generation;
        record.provider_selection_digest = evidence.provider_selection_digest.to_vec();
        record.proof_class = match evidence.proof_class {
            SourceAcquisitionProofClassV2::ImmutableTree => {
                MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE
            }
            SourceAcquisitionProofClassV2::LocalLive => {
                MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE
            }
            SourceAcquisitionProofClassV2::BestEffortReplica => {
                MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_BEST_EFFORT_REPLICA
            }
        }
        .into();
        record.provider_proof_digest = evidence.provider_proof_digest.to_vec();
        record.lease_id = evidence.lease_id.to_vec();
        record.signed_lease_digest = evidence.signed_lease_digest.to_vec();
        record.lease_issued_seconds = evidence.lease_issued_seconds;
        record.lease_expires_seconds = evidence.lease_expires_seconds;
        record.source_realization_handle = evidence.source_realization_handle.to_vec();
        record.source_physical_proof_digest = evidence.source_physical_proof_digest.to_vec();
        record.source_kernel_boot_id = evidence.source_kernel_boot_id.to_vec();
        record.source_device = Some(evidence.source_device);
        record.source_inode = Some(evidence.source_inode);
        record.source_unique_mount_id = Some(evidence.source_unique_mount_id);
        record.descriptor_commitment = evidence.descriptor_commitment.to_vec();
    }
    Ok(record)
}

fn exact_attempt(
    table: &SourceAcquisitionTableV2,
    reference: super::model::RecordRefV2,
) -> Result<&super::model::SourceProviderQueryAttemptV2> {
    table
        .provider_attempts
        .get(&reference.id)
        .filter(|attempt| {
            attempt.revision == reference.revision
                && attempt.record_digest == reference.record_digest
        })
        .ok_or_else(|| state_error("wire projection attempt reference is stale"))
}

fn status_digest(attempt: Option<&super::model::SourceProviderQueryAttemptV2>) -> Vec<u8> {
    match attempt.map(|value| &value.state) {
        Some(ProviderAttemptStateV2::DispositionConsumed {
            signed_status_digest,
            ..
        }) => signed_status_digest.to_vec(),
        _ => Vec::new(),
    }
}

const fn source_acquisition_phase(phase: SourceAcquisitionPhaseV2) -> MountSourceAcquisitionPhase {
    match phase {
        SourceAcquisitionPhaseV2::PendingQuery => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY
        }
        SourceAcquisitionPhaseV2::DescriptorCustodied => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED
        }
        SourceAcquisitionPhaseV2::Active => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE
        }
        SourceAcquisitionPhaseV2::Consumed => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
        }
        SourceAcquisitionPhaseV2::Releasing => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
        }
        SourceAcquisitionPhaseV2::Released => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
        }
        SourceAcquisitionPhaseV2::Faulted => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
        }
    }
}
