//! Controller-only signer for a provisional Host execution-output claim.
//!
//! This issuer rederives AOSCIR01 under the Controller journal writer and
//! signs one exact Host method-35 source for the request ID selected by the
//! authenticated session. It does not send a request, consume a Guest
//! challenge, or authorize public execution Create. A later exchange must
//! retain the signed request through ambiguous Host reserve/query outcomes.

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerAuthorizationArtifactsV1};
use aos_sandbox::controller_execution_preissue::{
    ControllerExecutionOutputAttemptV1, ControllerExecutionPreissueV1,
    ControllerExecutionReserveSourceV1, prepare_execution_reserve_source_v1,
    retain_controller_execution_output_attempt_v1, revalidate_accepted_execution_preissue_v1,
};
use aos_sandbox::environment::EnvironmentProtectedJournalOwnerV1;
use aos_sandbox::execution_parent_resource::ExecutionParentResourceSourceV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::runtime_scope::CurrentAssignmentTarget;
use aos_sandbox::{AuthorityPublicationStore, EffectFailure, Journal};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, ProtocolId, ProtocolVersion,
    RawPairedClockSample,
};
use aos_sandbox_protocol::semantics::host_output_reserve_grant_v1;

use crate::DormantBrokerRequestCoordinatesV1;
use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;

/// Retains a signed method-35 plan beside the exact source it authenticates.
pub(crate) struct SignedExecutionOutputReserveV1 {
    source: ControllerExecutionReserveSourceV1,
    attempt: ControllerExecutionOutputAttemptV1,
    authorization: BrokerAuthorizationArtifactsV1,
    request_id: [u8; 16],
}

impl SignedExecutionOutputReserveV1 {
    /// Borrows the exact Controller-derived reserve carrier.
    pub(crate) const fn source(&self) -> &ControllerExecutionReserveSourceV1 {
        &self.source
    }

    /// Borrows the immutable original request locator for cold Query36.
    pub(crate) const fn attempt(&self) -> &ControllerExecutionOutputAttemptV1 {
        &self.attempt
    }

    /// Borrows the signed Host plan and current ownership lease.
    pub(crate) const fn authorization(&self) -> &BrokerAuthorizationArtifactsV1 {
        &self.authorization
    }

    /// Returns the original authenticated-session request ID.
    pub(crate) const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }
}

/// Signs one current provisional Host reserve request without dispatching it.
///
/// The authenticated session supplies `coordinates`; a caller-provided request
/// ID cannot stand in for them. The corresponding broker request must preserve
/// the same ID, exact AOSCIR01 bytes, plan signature, and lease in its durable
/// session custody before any Host send.
///
/// # Errors
///
/// Returns a retryable failure when the preissue, accepted Create, assignment,
/// current Host template, session coordinates, signer, or clock is unavailable.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_current_host_output_reserve_v1<T>(
    controller: &mut Journal,
    assignment: &CurrentAssignmentTarget,
    environment_owner: &mut EnvironmentProtectedJournalOwnerV1<'_, '_>,
    parent: &ExecutionParentResourceSourceV1,
    preissue: &ControllerExecutionPreissueV1,
    signer: &ControllerBrokerPlanSignerV1,
    coordinates: DormantBrokerRequestCoordinatesV1,
    clock: &mut T,
) -> Result<SignedExecutionOutputReserveV1, EffectFailure>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    if coordinates.request_id() == [0; 16]
        || coordinates.protocol_version() != ProtocolVersion::new(1, 0)
        || coordinates.audience() != Audience::AUDIENCE_NODE_CONTROLLER
        || coordinates.deadline_boottime_nanoseconds() > preissue.deadline_boottime_nanoseconds()
    {
        return Err(retryable(
            "Host output reserve session coordinates are incompatible",
        ));
    }

    let source = prepare_execution_reserve_source_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        preissue,
        clock,
    )
    .map_err(|_| retryable("protected execution reserve source is unavailable"))?;
    let current = AuthorityPublicationStore::new(controller)
        .current(source.sandbox())
        .map_err(|_| retryable("current Host authority is unavailable"))?
        .ok_or_else(|| retryable("current Host authority is absent"))?;
    let publication = current.manifest();
    let manifest = publication.manifest();
    let broker_assignment = publication
        .broker_assignment()
        .map_err(|_| retryable("current Host assignment is invalid"))?;
    let lease_assignment = current.lease().lease().assignment();
    if manifest.sandbox() != source.sandbox()
        || manifest.incarnation() != source.incarnation()
        || manifest.node() != source.node()
        || manifest.epoch().get() != source.assignment_epoch()
        || manifest.desired_generation().get() != source.desired_generation()
        || manifest.namespace_generation().get() != source.namespace_generation()
        || publication.digest() != source.assignment_manifest_digest()
        || lease_assignment.sandbox() != broker_assignment.sandbox()
        || lease_assignment.incarnation() != broker_assignment.incarnation()
        || lease_assignment.epoch() != broker_assignment.epoch()
        || lease_assignment.digest() != broker_assignment.digest()
        || current.lease().lease().node() != source.node()
    {
        return Err(retryable("Host output reserve assignment is stale"));
    }

    let source_bytes = source.canonical_bytes();
    let semantics =
        host_output_reserve_grant_v1(broker_assignment, coordinates.request_id(), &source_bytes)
            .map_err(|_| retryable("Host output reserve semantics are invalid"))?;
    let template = current
        .templates()
        .iter()
        .find(|candidate| candidate.audience() == BrokerAudience::Host)
        .ok_or_else(|| retryable("current Host authorization template is absent"))?;
    let parent_plan = template.plan();
    if parent_plan.assignment() != broker_assignment || parent_plan.node() != source.node() {
        return Err(retryable(
            "Host output reserve template differs from assignment",
        ));
    }

    let fresh_clock = crate::controller_ownership::sample_ownership_clock()
        .map_err(|_| retryable("protected Controller clock is unavailable"))?;
    if fresh_clock.host_boot_id() != preissue.host_boot_id()
        || fresh_clock.boottime_nanoseconds() >= preissue.deadline_boottime_nanoseconds()
        || !request_deadline_is_live(
            coordinates.deadline_boottime_nanoseconds(),
            preissue.deadline_boottime_nanoseconds(),
            fresh_clock.boottime_nanoseconds(),
        )
    {
        return Err(retryable(
            "execution reserve preissue expired before signing",
        ));
    }
    let now = fresh_clock.wall_seconds();
    let expires = now
        .checked_add(30)
        .map(|limit| {
            limit
                .min(parent_plan.expires_seconds())
                .min(current.lease().lease().authority_expires_seconds())
        })
        .ok_or_else(|| retryable("Host output reserve clock overflowed"))?;
    if now < parent_plan.issued_seconds() || expires <= now {
        return Err(retryable("Host output reserve authority has expired"));
    }
    let grant = BrokerGrant::new(
        semantics.verb(),
        semantics.target(),
        semantics.commitment(),
        4 * 1_024,
        0,
    )
    .map_err(|_| retryable("Host output reserve grant is invalid"))?;
    let plan = BrokerAuthorizationPlan::new(
        BrokerAudience::Host,
        ProtocolId::HostBroker,
        ProtocolVersion::new(1, 0),
        broker_assignment,
        source.node(),
        parent_plan.ownership_authority().clone(),
        vec![grant],
        parent_plan.policy_commitment(),
        parent_plan.revocation_scope(),
        now,
        expires,
        Vec::new(),
    )
    .map_err(|_| retryable("Host output reserve plan is invalid"))?;
    let signed = signer
        .sign_plan(plan, now)
        .map_err(|_| retryable("Host output reserve signature is unavailable"))?;

    revalidate_accepted_execution_preissue_v1(
        controller,
        assignment,
        environment_owner,
        parent,
        preissue,
        clock,
    )
    .map_err(|_| retryable("execution reserve source changed before handoff"))?;
    let attempt = retain_controller_execution_output_attempt_v1(
        controller,
        &source,
        &signed,
        coordinates.request_id(),
        coordinates.deadline_boottime_nanoseconds(),
    )
    .map_err(|_| retryable("original Host output reserve attempt needs cold Query36"))?;
    Ok(SignedExecutionOutputReserveV1 {
        source,
        attempt,
        authorization: BrokerAuthorizationArtifactsV1 {
            broker_plan: signed.canonical_plan().to_vec(),
            broker_plan_signature: signed.canonical_signature().to_vec(),
            ownership_lease: current.lease().canonical_lease().to_vec(),
            ownership_lease_signature: current.lease().canonical_signature().to_vec(),
            ..Default::default()
        },
        request_id: coordinates.request_id(),
    })
}

fn retryable(message: &'static str) -> EffectFailure {
    EffectFailure::Retryable(message.to_owned())
}

fn request_deadline_is_live(
    request_deadline: u64,
    preissue_deadline: u64,
    current_boottime: u64,
) -> bool {
    current_boottime < request_deadline && request_deadline <= preissue_deadline
}

#[cfg(test)]
mod tests {
    use super::request_deadline_is_live;

    #[test]
    fn reserve_deadline_must_be_future_and_within_preissue() {
        assert!(request_deadline_is_live(99, 100, 98));
        assert!(request_deadline_is_live(100, 100, 99));
        assert!(!request_deadline_is_live(99, 100, 99));
        assert!(!request_deadline_is_live(100, 100, 100));
        assert!(!request_deadline_is_live(101, 100, 99));
    }
}
