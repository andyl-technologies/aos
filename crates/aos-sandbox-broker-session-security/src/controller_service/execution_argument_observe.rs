//! Controller-only signer for one Host runtime-argument observation.
//!
//! The authenticated session chooses the original request ID. The signer
//! previews AOSCIA02 under current accepted-Create owners, signs its exact
//! canonical bytes with the current Host-audience authorization template,
//! then durably retains the same one-shot attempt before any request can be
//! returned for transport. An existing attempt is query-only after restart.
//! This module neither sends to Host nor admits an ExecutionSpec.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerAuthorizationArtifactsV1, ObserveHostExecutionArgumentRequestV1, RequestHeader,
};
use aos_sandbox::controller_execution_argument_attempt::{
    ControllerExecutionArgumentAttemptV1, prepare_controller_execution_argument_attempt_v1,
    retain_controller_execution_argument_attempt_v1,
};
use aos_sandbox::environment::EnvironmentProtectedJournalOwnerV1;
use aos_sandbox::execution_parent_resource::ExecutionParentResourceSourceV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox::{AuthorityPublicationStore, EffectFailure, Journal};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, ExecutionId, OperationId, ProtocolId,
    ProtocolVersion, RawPairedClockSample,
};
use aos_sandbox_protocol::semantics::host_execution_argument_observe_grant_v1;
use buffa::Message as _;

use crate::DormantBrokerRequestCoordinatesV1;
use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;

/// Retains the exact signed plan, source, and original method-37 request body.
pub(crate) struct SignedExecutionArgumentObserveV1 {
    attempt: ControllerExecutionArgumentAttemptV1,
    body: Vec<u8>,
    authorization: BrokerAuthorizationArtifactsV1,
}

impl SignedExecutionArgumentObserveV1 {
    pub(crate) const fn attempt(&self) -> &ControllerExecutionArgumentAttemptV1 {
        &self.attempt
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) const fn authorization(&self) -> &BrokerAuthorizationArtifactsV1 {
        &self.authorization
    }
}

/// Signs and durably retains the sole fresh method-37 attempt.
///
/// Signing failure before the AOSCIA02 append does not consume the attempt.
/// After append, the in-process broker exchange must retain the exact signed
/// request; a later process must use read-only method 38, never sign again.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_current_host_execution_argument_observe_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    execution: ExecutionId,
    create_operation: OperationId,
    signer: &ControllerBrokerPlanSignerV1,
    coordinates: DormantBrokerRequestCoordinatesV1,
    clock: &mut T,
) -> Result<SignedExecutionArgumentObserveV1, EffectFailure>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    if coordinates.request_id() == [0; 16]
        || coordinates.protocol_version() != ProtocolVersion::new(1, 0)
        || coordinates.audience() != Audience::AUDIENCE_NODE_CONTROLLER
    {
        return Err(retryable(
            "Host argument session coordinates are incompatible",
        ));
    }
    let proposed = prepare_controller_execution_argument_attempt_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        execution,
        create_operation,
        coordinates.request_id(),
        coordinates.deadline_boottime_nanoseconds(),
        clock,
    )
    .map_err(|_| retryable("protected Host argument attempt is unavailable"))?;

    let target = parent.assignment().manifest();
    let current = AuthorityPublicationStore::new(controller)
        .current(target.sandbox())
        .map_err(|_| retryable("current Host authority is unavailable"))?
        .ok_or_else(|| retryable("current Host authority is absent"))?;
    let publication = current.manifest();
    let manifest = publication.manifest();
    let broker_assignment = publication
        .broker_assignment()
        .map_err(|_| retryable("current Host assignment is invalid"))?;
    let lease_assignment = current.lease().lease().assignment();
    if manifest.sandbox() != target.sandbox()
        || manifest.incarnation() != target.incarnation()
        || manifest.node() != target.node()
        || manifest.epoch() != target.epoch()
        || manifest.desired_generation() != target.desired_generation()
        || manifest.namespace_generation() != target.namespace_generation()
        || publication.digest() != proposed.assignment_digest()
        || lease_assignment.sandbox() != broker_assignment.sandbox()
        || lease_assignment.incarnation() != broker_assignment.incarnation()
        || lease_assignment.epoch() != broker_assignment.epoch()
        || lease_assignment.digest() != broker_assignment.digest()
        || current.lease().lease().node() != target.node()
    {
        return Err(retryable("Host argument assignment is stale"));
    }

    let source = proposed.canonical_bytes();
    let semantics = host_execution_argument_observe_grant_v1(
        broker_assignment,
        coordinates.request_id(),
        &source,
    )
    .map_err(|_| retryable("Host argument semantics are invalid"))?;
    let template = current
        .templates()
        .iter()
        .find(|candidate| candidate.audience() == BrokerAudience::Host)
        .ok_or_else(|| retryable("current Host authorization template is absent"))?;
    let parent_plan = template.plan();
    if parent_plan.assignment() != broker_assignment || parent_plan.node() != target.node() {
        return Err(retryable("Host argument template differs from assignment"));
    }

    let sample = clock().map_err(|_| retryable("protected Controller clock is unavailable"))?;
    if sample.host_boot_id() != proposed.host_boot_id()
        || sample.boottime_nanoseconds() >= proposed.deadline_boottime_nanoseconds()
    {
        return Err(retryable("Host argument attempt expired before signing"));
    }
    let now = sample.wall_seconds();
    let expires = now
        .checked_add(30)
        .map(|limit| {
            limit
                .min(parent_plan.expires_seconds())
                .min(current.lease().lease().authority_expires_seconds())
        })
        .ok_or_else(|| retryable("Host argument clock overflowed"))?;
    if now < parent_plan.issued_seconds() || expires <= now {
        return Err(retryable("Host argument authority has expired"));
    }
    let grant = BrokerGrant::new(
        semantics.verb(),
        semantics.target(),
        semantics.commitment(),
        4 * 1_024,
        0,
    )
    .map_err(|_| retryable("Host argument grant is invalid"))?;
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Host,
        ProtocolId::HostBroker,
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
    .map_err(|_| retryable("Host argument plan is invalid"))?;
    let signed = signer
        .sign_plan(plan, now)
        .map_err(|_| retryable("Host argument signature is unavailable"))?;

    let attempt = retain_controller_execution_argument_attempt_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        execution,
        create_operation,
        coordinates.request_id(),
        coordinates.deadline_boottime_nanoseconds(),
        clock,
    )
    .map_err(|_| retryable("original Host argument attempt needs cold Query38"))?;
    if attempt != proposed {
        return Err(retryable("Host argument source changed before handoff"));
    }
    let body = ObserveHostExecutionArgumentRequestV1 {
        header: Some(RequestHeader {
            protocol_major: u32::from(coordinates.protocol_version().major()),
            protocol_minor: u32::from(coordinates.protocol_version().minor()),
            request_id: coordinates.request_id().to_vec(),
            audience: coordinates.audience().into(),
            deadline_boottime_nanoseconds: coordinates.deadline_boottime_nanoseconds(),
            maximum_response_bytes: coordinates.maximum_response_bytes(),
            ..Default::default()
        })
        .into(),
        canonical_attempt: source.to_vec(),
        ..Default::default()
    }
    .encode_to_vec();
    Ok(SignedExecutionArgumentObserveV1 {
        attempt,
        body,
        authorization: BrokerAuthorizationArtifactsV1 {
            broker_plan: signed.canonical_plan().to_vec(),
            broker_plan_signature: signed.canonical_signature().to_vec(),
            ownership_lease: current.lease().canonical_lease().to_vec(),
            ownership_lease_signature: current.lease().canonical_signature().to_vec(),
            ..Default::default()
        },
    })
}

fn retryable(message: &'static str) -> EffectFailure {
    EffectFailure::Retryable(message.to_owned())
}
