//! Controller signer for a read-only Storage capture candidate query.
//!
//! The source comes from current accepted Create, AOSCIS01/Host AOSEOR02,
//! and this exact protected Storage broker session. Method 41 is excluded
//! from production negotiation, and a returned candidate is informational:
//! it is neither AOSEOR03 physical backing nor a reserve/Host effect permit.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerAuthorizationArtifactsV1, ReadStorageExecutionCaptureCandidateRequestV1,
};
use aos_sandbox::controller_execution_output_settlement::{
    ProtectedControllerOutputSettlementV1, read_current_controller_output_settlement_v1,
};
use aos_sandbox::controller_execution_preissue::{
    load_controller_execution_output_attempt_v1, revalidate_historical_execution_preissue_source_v1,
};
use aos_sandbox::environment::EnvironmentProtectedJournalOwnerV1;
use aos_sandbox::execution_parent_resource::ExecutionParentResourceSourceV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox::{AuthorityPublicationStore, EffectFailure, Journal};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, ExecutionId, OperationId, ProtocolId, ProtocolVersion,
    RawPairedClockSample,
};
use aos_sandbox_protocol::storage_capture_candidate::StorageCaptureCandidateQueryV1;
use aos_sandbox_protocol::storage_capture_grant::ControllerOutputSettlementPreimageV1;
use buffa::Message as _;

use crate::DormantBrokerRequestCoordinatesV1;
use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;
use crate::dormant_handshake::ProtectedStorageSessionBindingV1;

/// Retains the exact signed method-41 query and its protected source locator.
pub(crate) struct SignedStorageCaptureCandidateQueryV1 {
    query: StorageCaptureCandidateQueryV1,
    body: Vec<u8>,
    authorization: BrokerAuthorizationArtifactsV1,
    settlement_digest: aos_sandbox_core::ObjectDigest,
    capture_limits: AcceptedCaptureLimitsV1,
}

/// Retains the exact detached ceilings derived from current accepted Create.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AcceptedCaptureLimitsV1 {
    admitted_bytes: u64,
    maximum_stdout_bytes: u64,
    maximum_stderr_bytes: u64,
}

impl AcceptedCaptureLimitsV1 {
    pub(crate) const fn matches(
        self,
        admitted_bytes: u64,
        maximum_stdout_bytes: u64,
        maximum_stderr_bytes: u64,
    ) -> bool {
        self.admitted_bytes == admitted_bytes
            && self.maximum_stdout_bytes == maximum_stdout_bytes
            && self.maximum_stderr_bytes == maximum_stderr_bytes
    }
}

impl SignedStorageCaptureCandidateQueryV1 {
    pub(crate) const fn query(&self) -> &StorageCaptureCandidateQueryV1 {
        &self.query
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) const fn authorization(&self) -> &BrokerAuthorizationArtifactsV1 {
        &self.authorization
    }

    pub(crate) const fn settlement_digest(&self) -> aos_sandbox_core::ObjectDigest {
        self.settlement_digest
    }

    pub(crate) const fn capture_limits(&self) -> AcceptedCaptureLimitsV1 {
        self.capture_limits
    }
}

/// Signs only a historical-source/current-Create Storage candidate inspection.
///
/// The original AOSCIP01 deadline is deliberately not renewed; this read-only
/// method instead uses a fresh Storage-session deadline. Storage independently
/// resolves its AOSEOR03 row by execution/Create/claim/assignment under its
/// MAC key and returns the row digest and sequence in a signed response.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_current_storage_capture_candidate_query_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    execution: ExecutionId,
    create_operation: OperationId,
    signer: &ControllerBrokerPlanSignerV1,
    session_binding: ProtectedStorageSessionBindingV1,
    coordinates: DormantBrokerRequestCoordinatesV1,
    clock: &mut T,
) -> Result<SignedStorageCaptureCandidateQueryV1, EffectFailure>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    if coordinates.request_id() == [0; 16]
        || coordinates.protocol_version() != ProtocolVersion::new(1, 0)
        || coordinates.audience() != Audience::AUDIENCE_NODE_CONTROLLER
        || coordinates.maximum_response_bytes() < 1_024
    {
        return Err(retryable(
            "Storage candidate session coordinates are incompatible",
        ));
    }
    let attempt = load_controller_execution_output_attempt_v1(controller, execution)
        .map_err(|_| retryable("protected Host output attempt is unavailable"))?
        .ok_or_else(|| retryable("protected Host output attempt is absent"))?;
    if attempt.create_operation() != create_operation {
        return Err(retryable("Storage candidate accepted Create differs"));
    }
    let preissue = attempt.source().preissue();
    revalidate_historical_execution_preissue_source_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        preissue,
        clock,
    )
    .map_err(|_| retryable("accepted Create sources changed before Storage query"))?;
    let settlement = read_current_controller_output_settlement_v1(
        controller,
        assignment,
        execution,
        create_operation,
        clock,
    )
    .map_err(|_| retryable("authenticated Host output settlement changed"))?
    .ok_or_else(|| retryable("authenticated Host output settlement is absent"))?;
    let capture_limits = validate_settlement(&settlement, &attempt)?;

    let target = parent.assignment().manifest();
    let current = AuthorityPublicationStore::new(controller)
        .current(target.sandbox())
        .map_err(|_| retryable("current Storage authority is unavailable"))?
        .ok_or_else(|| retryable("current Storage authority is absent"))?;
    let publication = current.manifest();
    let manifest = publication.manifest();
    let broker_assignment = publication
        .broker_assignment()
        .map_err(|_| retryable("current Storage assignment is invalid"))?;
    let lease_assignment = current.lease().lease().assignment();
    if manifest.sandbox() != target.sandbox()
        || manifest.incarnation() != target.incarnation()
        || manifest.node() != target.node()
        || manifest.epoch() != target.epoch()
        || manifest.desired_generation() != target.desired_generation()
        || manifest.namespace_generation() != target.namespace_generation()
        || publication.digest() != parent.assignment().digest()
        || lease_assignment.sandbox() != broker_assignment.sandbox()
        || lease_assignment.incarnation() != broker_assignment.incarnation()
        || lease_assignment.epoch() != broker_assignment.epoch()
        || lease_assignment.digest() != broker_assignment.digest()
        || current.lease().lease().node() != target.node()
    {
        return Err(retryable("Storage candidate assignment is stale"));
    }

    let sample = clock().map_err(|_| retryable("protected Controller clock is unavailable"))?;
    if sample.host_boot_id() != preissue.host_boot_id()
        || sample.boottime_nanoseconds() >= coordinates.deadline_boottime_nanoseconds()
        || coordinates.deadline_boottime_nanoseconds() > assignment.deadline_boottime_nanoseconds()
    {
        return Err(retryable(
            "Storage candidate query deadline or Host boot changed",
        ));
    }
    let settlement_bytes = settlement.canonical_bytes();
    let settlement_source =
        ControllerOutputSettlementPreimageV1::from_canonical_bytes(&settlement_bytes)
            .map_err(|_| retryable("protected Host settlement bytes are invalid"))?;
    if settlement_source.record_digest() != settlement.record_digest() {
        return Err(retryable("Storage candidate settlement digest changed"));
    }
    let query = StorageCaptureCandidateQueryV1::assemble_structural(
        &settlement_source,
        settlement.claim_digest(),
        broker_assignment,
        preissue.host_boot_id(),
        session_binding.digest(),
        coordinates.request_id(),
        coordinates.deadline_boottime_nanoseconds(),
    )
    .map_err(|_| retryable("Storage candidate query source is invalid"))?;
    let grant = query
        .broker_grant(coordinates.request_id())
        .map_err(|_| retryable("Storage candidate grant is invalid"))?;
    let template = current
        .templates()
        .iter()
        .find(|candidate| candidate.audience() == BrokerAudience::Storage)
        .ok_or_else(|| retryable("current Storage authorization template is absent"))?;
    let parent_plan = template.plan();
    if parent_plan.assignment() != broker_assignment
        || parent_plan.node() != target.node()
        || parent_plan.protocol() != ProtocolId::StorageBroker
        || parent_plan.protocol_version() != ProtocolVersion::new(1, 0)
    {
        return Err(retryable(
            "Storage candidate template differs from assignment",
        ));
    }
    let now = sample.wall_seconds();
    let expires = now
        .checked_add(30)
        .map(|limit| {
            limit
                .min(parent_plan.expires_seconds())
                .min(current.lease().lease().authority_expires_seconds())
        })
        .ok_or_else(|| retryable("Storage candidate clock overflowed"))?;
    if now < parent_plan.issued_seconds() || expires <= now {
        return Err(retryable("Storage candidate authority has expired"));
    }
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Storage,
        ProtocolId::StorageBroker,
        ProtocolVersion::new(1, 0),
        broker_assignment,
        target.node(),
        parent_plan.ownership_authority().clone(),
        vec![grant],
        parent_plan.policy_commitment(),
        parent_plan.revocation_scope(),
        now,
        expires,
        Vec::new(),
    )
    .map_err(|_| retryable("Storage candidate plan is invalid"))?;
    let signed = signer
        .sign_plan(plan, now)
        .map_err(|_| retryable("Storage candidate signature is unavailable"))?;

    revalidate_historical_execution_preissue_source_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        preissue,
        clock,
    )
    .map_err(|_| retryable("Storage candidate accepted Create changed after signing"))?;
    let reread = read_current_controller_output_settlement_v1(
        controller,
        assignment,
        execution,
        create_operation,
        clock,
    )
    .map_err(|_| retryable("Storage candidate Host settlement changed after signing"))?
    .ok_or_else(|| retryable("Storage candidate Host settlement disappeared"))?;
    if reread != settlement {
        return Err(retryable(
            "Storage candidate Host settlement changed after signing",
        ));
    }
    let final_sample =
        clock().map_err(|_| retryable("protected Controller clock is unavailable"))?;
    if final_sample.host_boot_id() != preissue.host_boot_id()
        || final_sample.boottime_nanoseconds() >= coordinates.deadline_boottime_nanoseconds()
        || final_sample.wall_seconds() >= expires
    {
        return Err(retryable("Storage candidate query expired before send"));
    }

    let body = ReadStorageExecutionCaptureCandidateRequestV1 {
        header: Some(coordinates.request_header()).into(),
        canonical_query: query.canonical_bytes().to_vec(),
        ..Default::default()
    }
    .encode_to_vec();
    Ok(SignedStorageCaptureCandidateQueryV1 {
        query,
        body,
        authorization: BrokerAuthorizationArtifactsV1 {
            broker_plan: signed.canonical_plan().to_vec(),
            broker_plan_signature: signed.canonical_signature().to_vec(),
            ownership_lease: current.lease().canonical_lease().to_vec(),
            ownership_lease_signature: current.lease().canonical_signature().to_vec(),
            ..Default::default()
        },
        settlement_digest: settlement.record_digest(),
        capture_limits,
    })
}

fn validate_settlement(
    settlement: &ProtectedControllerOutputSettlementV1,
    attempt: &aos_sandbox::controller_execution_preissue::ControllerExecutionOutputAttemptV1,
) -> Result<AcceptedCaptureLimitsV1, EffectFailure> {
    let preissue = attempt.source().preissue();
    let maximum_stdout_bytes = preissue.maximum_stdout_bytes();
    let maximum_stderr_bytes = preissue.maximum_stderr_bytes();
    let admitted_bytes = maximum_stdout_bytes
        .checked_add(maximum_stderr_bytes)
        .ok_or_else(|| retryable("Storage candidate output split overflowed"))?;
    if admitted_bytes == 0
        || settlement.execution() != preissue.execution()
        || settlement.create_operation() != preissue.create_operation()
        || settlement.claim_digest() != attempt.source().output_claim_digest()
        || settlement.correlation_digest().as_bytes() == &[0; 32]
    {
        return Err(retryable(
            "Storage candidate has no detached Host output claim",
        ));
    }
    Ok(AcceptedCaptureLimitsV1 {
        admitted_bytes,
        maximum_stdout_bytes,
        maximum_stderr_bytes,
    })
}

fn retryable(message: &'static str) -> EffectFailure {
    EffectFailure::Retryable(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::AcceptedCaptureLimitsV1;

    #[test]
    fn candidate_split_must_equal_protected_accepted_create() {
        let expected = AcceptedCaptureLimitsV1 {
            admitted_bytes: 100,
            maximum_stdout_bytes: 60,
            maximum_stderr_bytes: 40,
        };
        assert!(expected.matches(100, 60, 40));
        assert!(!expected.matches(100, 59, 41));
        assert!(!expected.matches(99, 60, 40));
        assert!(!expected.matches(101, 60, 40));
    }
}
