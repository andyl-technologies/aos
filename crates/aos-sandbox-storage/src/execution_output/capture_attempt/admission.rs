//! Joins actual physical Capture admission, retained Host readback and output.
//!
//! The constructor is private to Storage. Its coordinator must keep the same
//! Host currentness loan and independent Storage posts live across issuance;
//! copying a wire source or an AOSEOR03 row cannot construct these sources.

use super::*;
use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};
use aos_sandbox_protocol::host_storage_output_readback::{
    decode_captured_host_storage_output_readback_request_v1,
    decode_host_storage_output_readback_response_v1,
};
use crate::authorization::VerifiedCaptureReserveOngoingAdmissionV3;
use crate::execution_capture_policy::CaptureAllocationV1;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CaptureSourceAdmissionErrorV2 {
    #[error("physical Capture sources differ from their original admission")]
    Binding,
    #[error(transparent)]
    Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
    #[error(transparent)]
    Output(#[from] ExecutionOutputLedgerErrorV1),
}

impl ExecutionOutputLedgerV1 {
    pub(crate) fn prepare_admitted_capture_ongoing_sources_v3(
        &self,
        admitted: &VerifiedCaptureReserveOngoingAdmissionV3,
        host: &AuthenticatedBrokerMethodOutcomeV1,
        requirement: &CaptureDatasetRequirementV1,
        policy: CaptureAllocationV1,
        now: u64,
    ) -> Result<VerifiedCaptureAttemptSourcesV1, CaptureSourceAdmissionErrorV2> {
        let fail = || CaptureSourceAdmissionErrorV2::Binding;
        let source = admitted.source_v3().original_source_v1();
        let lifetime = admitted.lifetime_v3();
        let (allocation, headroom, floor) = source.space_policy();
        let (admitted_bytes, stdout, stderr) = source.output_limits();
        if host.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
            || host.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || lifetime.acquisition_deadline_v3().min(lifetime.ongoing_deadline_v3()) <= now
            || requirement.execution() != source.settlement().execution()
            || requirement.create_operation() != source.settlement().create_operation()
            || requirement.claim_digest() != source.output_claim_digest()
            || requirement.storage_create_operation() != source.storage_create_operation()
            || requirement.allocation_bytes() != allocation
            || policy.allocation_for(admitted_bytes).map_err(|_| fail())? != allocation
            || policy.metadata_headroom_bytes() != headroom
            || policy.minimum_remaining_bytes() != floor
        {
            return Err(fail());
        }
        let attempt_policy = requirement.attempt_policy_digest(headroom, floor);
        if super::super::capture_candidate::joined_policy_digest(policy.digest(), attempt_policy)
            != source.dataset_policy_digest()
        {
            return Err(fail());
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = host.result() else {
            return Err(fail());
        };
        let request = host.request();
        let decoded = decode_captured_host_storage_output_readback_request_v1(
            request.exact_body(), request.peer(), request.peer_policy(), now,
        )?;
        let observed = decode_host_storage_output_readback_response_v1(exact_body, &decoded)?;
        let records = decoded.records();
        let locator = records.host_locator();
        if records != admitted.original_records_v3()
            || records.settlement() != source.settlement().canonical_bytes()
            || records.assignment() != source.assignment()
            || observed.current_assignment() != source.assignment()
            || locator.execution() != source.settlement().execution()
            || locator.create_operation() != source.settlement().create_operation()
            || locator.original_request_id() != source.original_host_request_id()
            || locator.host_boot_id() != source.host_boot_id()
            || locator.claim_digest() != source.output_claim_digest()
        {
            return Err(fail());
        }
        let output = self.read_protected_retained_output(
            *source.settlement().execution().as_bytes(),
            *source.settlement().create_operation().as_bytes(),
            source.output_record_digest(),
        )?;
        if output.assignment_digest() != source.assignment().digest()
            || output.claim_digest() != source.output_claim_digest()
            || output.admitted_bytes() != admitted_bytes
            || output.maximum_stdout_bytes() != stdout
            || output.maximum_stderr_bytes() != stderr
        {
            return Err(fail());
        }
        Ok(VerifiedCaptureAttemptSourcesV1 {
            execution: *source.settlement().execution().as_bytes(),
            create: *source.settlement().create_operation().as_bytes(),
            record_digest: source.output_record_digest(),
            controller_grant_digest: lifetime.admission_v3().effect.plan_digest(),
            host_receipt_digest: ObjectDigest::from_bytes(Sha256::digest(host.canonical_packet()).into()),
            host_correlation_digest: source.settlement().host_correlation_digest(),
            host_claim_digest: source.output_claim_digest(),
            host_request_id: source.original_host_request_id(),
            assignment_digest: source.assignment().digest(),
            storage_create_operation: *source.storage_create_operation().as_bytes(),
            // The signed grant commits the current allocation-policy join above;
            // the versioned attempt keeps its exact native policy term.
            dataset_policy_digest: attempt_policy,
            kernel_boot_id: source.host_boot_id(),
            deadline_boottime_nanoseconds: lifetime.ongoing_deadline_v3(),
            source: CaptureSourceAssociationV2 {
                digest: admitted.source_v3().source_digest_v2(),
                original_reserve_request_id: source.original_reserve_request_id(),
                acquisition_deadline: Some(lifetime.acquisition_deadline_v3()),
            },
        })
    }
}
