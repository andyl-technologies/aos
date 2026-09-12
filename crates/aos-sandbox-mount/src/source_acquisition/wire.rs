//! Canonical public wire projection for durable source-acquisition rows.
//!
//! Exact signed provider envelopes and manager-custody evidence remain private
//! journal state. This module exposes only the stable facts and row digest
//! frozen by Mount source-acquisition protocol 1.0.

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, MountAssignmentBinding, MountOperationCorrelation,
    MountSourceAcquisitionFault, MountSourceAcquisitionPhase, MountSourceAcquisitionRecord,
    MountSourceProofClass,
};

use super::{
    SourceAcquisitionOperationV1, SourceAcquisitionPhaseV1, SourceAcquisitionProofClassV1,
    SourceAcquisitionRowV1,
};
use crate::Result;

pub(super) fn source_acquisition_record(
    row: &SourceAcquisitionRowV1,
) -> Result<MountSourceAcquisitionRecord> {
    row.validate()?;
    let operation = |value: SourceAcquisitionOperationV1| MountOperationCorrelation {
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
        provider_route_id: row.provider.provider_route_id.to_vec(),
        provider_route_generation: row.provider.provider_route_generation,
        provider_route_digest: row.provider.provider_route_digest.to_vec(),
        provider_authority_id: row.provider.provider_authority_id.to_vec(),
        provider_authority_generation: row.provider.provider_authority_generation,
        provider_authority_digest: row.provider.provider_authority_digest.to_vec(),
        provider_key_id: row.provider.provider_key_id.to_vec(),
        provider_key_generation: row.provider.provider_key_generation,
        provider_public_key_digest: row.provider.provider_public_key_digest.to_vec(),
        resource_namespace_digest: row.provider.resource_namespace_digest.to_vec(),
        provider_acquire_request_digest: row.provider_acquire_request_digest.to_vec(),
        provider_acquire_status_digest: row
            .acquire_checkpoint
            .as_ref()
            .or_else(|| row.acquire_history.last())
            .map_or_else(Vec::new, |checkpoint| {
                checkpoint.signed_status_digest.to_vec()
            }),
        provider_release_request_digest: row
            .provider_release_request_digest
            .map_or_else(Vec::new, |digest| digest.to_vec()),
        provider_release_status_digest: row
            .release_checkpoint
            .as_ref()
            .or_else(|| row.release_history.last())
            .map_or_else(Vec::new, |checkpoint| {
                checkpoint.signed_status_digest.to_vec()
            }),
        provider_inventory_digest: row
            .provider_inventory_digest
            .map_or_else(Vec::new, |digest| digest.to_vec()),
        release_generation: row.release_generation.unwrap_or_default(),
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
            SourceAcquisitionProofClassV1::ImmutableTree => {
                MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE
            }
            SourceAcquisitionProofClassV1::LocalLive => {
                MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE
            }
            SourceAcquisitionProofClassV1::BestEffortReplica => {
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

const fn source_acquisition_phase(phase: SourceAcquisitionPhaseV1) -> MountSourceAcquisitionPhase {
    match phase {
        SourceAcquisitionPhaseV1::PendingQuery => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_PENDING_QUERY
        }
        SourceAcquisitionPhaseV1::DescriptorCustodied => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_DESCRIPTOR_CUSTODIED
        }
        SourceAcquisitionPhaseV1::Active => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_ACTIVE
        }
        SourceAcquisitionPhaseV1::Consumed => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_CONSUMED
        }
        SourceAcquisitionPhaseV1::Releasing => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASING
        }
        SourceAcquisitionPhaseV1::Released => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_RELEASED
        }
        SourceAcquisitionPhaseV1::Faulted => {
            MountSourceAcquisitionPhase::MOUNT_SOURCE_ACQUISITION_PHASE_FAULTED
        }
    }
}
