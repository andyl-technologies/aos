//! Closed Host response builder for one original Storage output reserve.
//!
//! This owner rereads AOSEOR02/AOSHOP01 from the protected Host journal and
//! compares the original Controller AOSCIA01/AOSCIS01 fields. It produces only
//! a canonical response body. Method 48 has no production Host dispatcher or
//! Controller signer, so this body is not a signed same-session observation.

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, HostExecutionOutputReservationStatusV1, HostExecutionOutputReservationV1,
    ObserveHostStorageOutputResponseV1,
};
use aos_sandbox::runtime_execution::DormantRuntimeExecutionClaimV1;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::host_storage_output_readback::{
    ValidatedHostStorageOutputReadbackRequestV1, decode_host_storage_output_readback_response_v1,
};
use buffa::Message as _;

use crate::{HostError, Result};

/// Builds a nonauthorizing Host response from the exact protected output pair.
///
/// A future method-48 handler must verify the Controller Host-audience plan,
/// retain the authenticated Storage session, and recheck the Host journal
/// before signing this body. This function does not dispatch a method.
///
/// # Errors
///
/// Rejects a changed kernel boot, stale Host owner or assignment, absent
/// original reservation, substituted Controller/Host fields, or failed
/// canonical response self-validation.
pub fn protected_storage_output_readback_body_v1(
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    request: &ValidatedHostStorageOutputReadbackRequestV1,
    protected_boot_id: [u8; 16],
) -> Result<Vec<u8>> {
    if KernelBootId::current()
        .map_err(|_| HostError::Fence("Host readback kernel boot unavailable"))?
        .into_bytes()
        != protected_boot_id
        || claim.host_verifier().boot_id() != protected_boot_id
    {
        return Err(HostError::Fence("Host readback kernel boot changed"));
    }
    let observation = claim
        .read_host_output_for_storage_v1(request)
        .map_err(|_| HostError::Fence("protected Host output readback mismatch"))?;
    let reservation = observation.reservation();
    let assignment = request.records().assignment();
    let response = ObserveHostStorageOutputResponseV1 {
        canonical_host_output_reservation: HostExecutionOutputReservationV1 {
            status: HostExecutionOutputReservationStatusV1::HOST_EXECUTION_OUTPUT_RESERVATION_STATUS_COMMITTED.into(),
            execution_id: reservation.execution().as_bytes().to_vec(),
            create_operation_id: reservation.create_operation().as_bytes().to_vec(),
            original_reserve_request_id: reservation.original_request_id().to_vec(),
            preissue_record_digest: reservation.preissue_digest().as_bytes().to_vec(),
            output_claim_digest: reservation.claim_digest().as_bytes().to_vec(),
            reserve_source_digest: reservation.carrier_digest().as_bytes().to_vec(),
            assignment_digest: reservation.assignment_digest().as_bytes().to_vec(),
            host_boot_id: reservation.host_boot_id().to_vec(),
            original_plan_digest: reservation.plan_digest().as_bytes().to_vec(),
            original_semantic_request_digest: reservation.semantic_request_digest().as_bytes().to_vec(),
            host_correlation_record_digest: reservation.correlation_digest().as_bytes().to_vec(),
            original_host_journal_sequence: reservation.original_journal_sequence(),
            ..Default::default()
        }
        .encode_to_vec(),
        controller_storage_attempt_digest: request.controller_storage_attempt_digest().as_bytes().to_vec(),
        current_host_assignment: Some(AssignmentFence {
            sandbox_id: assignment.sandbox().as_bytes().to_vec(),
            incarnation_id: assignment.incarnation().as_bytes().to_vec(),
            assignment_epoch: assignment.epoch().get(),
            desired_generation: assignment.desired_generation().get(),
            assignment_digest: assignment.digest().as_bytes().to_vec(),
            ..Default::default()
        })
        .into(),
        host_boot_id: protected_boot_id.to_vec(),
        protected_host_journal_head_sequence: observation.journal_head_sequence(),
        protected_host_journal_head_digest: observation.journal_head_digest().as_bytes().to_vec(),
        ..Default::default()
    }
    .encode_to_vec();
    decode_host_storage_output_readback_response_v1(&response, request)?;

    claim
        .revalidate()
        .map_err(|_| HostError::Fence("protected Host output changed after readback"))?;
    if KernelBootId::current()
        .map_err(|_| HostError::Fence("Host readback kernel boot unavailable"))?
        .into_bytes()
        != protected_boot_id
    {
        return Err(HostError::Fence("Host readback kernel boot changed"));
    }
    Ok(response)
}
