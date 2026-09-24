//! Production lowering for authenticated public controller mutations.
//!
//! Controller-local capability transitions are completed atomically in the
//! protected journal. Mutations that require placement, ownership, or broker
//! effects remain outside this local lowering path and must be supplied by the
//! assignment compiler rather than represented by a synthetic effect.
//!
//! Capability attenuation bytes use canonical compact JSON with this shape:
//!
//! ```text
//! {"version":1,"sandbox":null,"incarnation":null,"grants":[...],
//!  "assignment_epoch":null,"not_before":0,"expires_at":1,
//!  "delegation":{...},"delegation_selector":{...}}
//! ```

use aos_proto::aos::sandbox::v1::{Capability, ObjectDescriptor, Timestamp};
use aos_sandbox_core::{
    AssignmentEpoch, AttenuationRequest, AuditId, CapabilityId, CapabilityRecord, ChannelBinding,
    DelegationLimits, Grant, IncarnationId, OperationId, PrincipalId, ProjectId, ResourceId,
    ResourceKind, SandboxId, Selector,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::controller_query::PublicOperationMethodV1;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionPlanV1, PublicProjectionResourceV1,
    PublicProjectionStoreV1, public_projection_deletion_record_v1,
};
use crate::public_mutation_compiler::{
    AuthorizedPublicMutationRequestV1, PublicMutationAuthorizationErrorV1,
    ResolvedPublicMutationRequestV1,
};
use crate::publisher_authority::{PublisherAuthorityLimits, PublisherCapabilityRegistry};
use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};
use crate::{
    ActivatedOperationCompiler, IdempotencyOutcome, Journal, OperationCompilationError,
    OperationPlan, PublicOperationAdmissionV1, PublicOperationAuthorizationV1,
};

mod execution_control;
#[cfg(target_os = "linux")]
mod operator_recovery;
mod policy_plan;
mod public_mutation;

pub use execution_control::{PublicExecutionControlDispatchV1, lower_public_execution_control_v1};
pub use public_mutation::{
    RecheckedCacheAcquisitionFenceV1, RecheckedCacheConsumerV1, RecheckedCacheRuntimeFenceV1,
    recheck_cache_consumer_projection_v1,
};

const CAPABILITY_RESOURCE_VERSION_DOMAIN: &[u8] =
    b"aos.sandbox.public-capability-resource-version.v1\0";
/// Selects the canonical public capability-attenuation schema.
pub const CAPABILITY_ATTENUATION_VERSION: u16 = 1;
const MAXIMUM_CAPABILITY_ATTENUATION_BYTES: usize = 4 * 1024 * 1024;

/// Canonical JSON carried by `AttenuateCapabilityRequest.attenuation`.
///
/// Controller-owned identity, audience, holder, channel, project, policy,
/// revocation, and audit fields are deliberately absent. The authenticated
/// request and current parent capability supply those values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCapabilityAttenuationV1 {
    /// Selects [`CAPABILITY_ATTENUATION_VERSION`].
    pub version: u16,
    /// Optionally narrows project authority to one sandbox.
    pub sandbox: Option<SandboxId>,
    /// Pairs exactly with `sandbox` when runtime scope is requested.
    pub incarnation: Option<IncarnationId>,
    /// Supplies the strictly covered child grant set.
    pub grants: Vec<Grant>,
    /// Optionally narrows authority to one assignment epoch.
    pub assignment_epoch: Option<AssignmentEpoch>,
    /// Selects the inclusive child validity start in Unix seconds.
    pub not_before: i64,
    /// Selects the exclusive child expiry in Unix seconds.
    pub expires_at: i64,
    /// Supplies strictly narrower descendant delegation ceilings.
    pub delegation: DelegationLimits,
    /// Selects the parent grant used to authorize delegation.
    pub delegation_selector: Selector,
}

/// Lowers authenticated public requests into durable production operation plans.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionOperationCompilerV1;

fn authorize_public_mutation(
    journal: &mut Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    capability_id: CapabilityId,
    canonical_request: &[u8],
) -> Result<AuthorizedPublicMutationRequestV1, OperationCompilationError> {
    AuthorizedPublicMutationRequestV1::authorize(journal, peer, capability_id, canonical_request)
        .map_err(|error| match error {
            PublicMutationAuthorizationErrorV1::Malformed => OperationCompilationError::Malformed,
            PublicMutationAuthorizationErrorV1::Rejected => OperationCompilationError::Rejected,
        })
}

/// Compiles an authorized attach with an independently authenticated Host route.
///
/// The ordinary production compiler has no route evidence and remains closed.
/// A controller worker may call this only after its separate Host route readback
/// and protected CA custody are active. The endpoint is retained in the same
/// durable operation transaction as admission, including for replay.
///
/// # Errors
///
/// Rejects malformed requests, invalid holder proof, missing public authority,
/// stale execution or Host route evidence, and invalid certificate issuance.
#[cfg(target_os = "linux")]
pub fn compile_public_attach_route_v1(
    journal: &mut Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    capability_id: CapabilityId,
    canonical_request: &[u8],
    request_digest: [u8; 32],
    pending: &crate::public_attach_pending::PublicAttachPendingV1,
    route: &crate::attach_route_issuer::AuthenticatedOpenSshRouteV1,
    issuer: &crate::attach_route_issuer::OpenSshAttachRouteIssuerV1,
) -> Result<OperationPlan, OperationCompilationError> {
    let authorized = authorize_public_mutation(journal, peer, capability_id, canonical_request)?;
    public_mutation::compile_authorized_attach_route(
        journal,
        &authorized,
        request_digest,
        pending,
        route,
        issuer,
    )
}

/// Reserves an authorized public attach identity before Host gate installation.
///
/// # Errors
///
/// Rejects malformed or unauthorized requests, stale executions, conflicting
/// idempotency keys, or unavailable protected journal custody.
#[cfg(target_os = "linux")]
pub fn reserve_public_attach_v1(
    journal: &mut Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    capability_id: CapabilityId,
    canonical_request: &[u8],
    request_digest: [u8; 32],
) -> Result<crate::public_attach_pending::PublicAttachPendingV1, OperationCompilationError> {
    let authorized = authorize_public_mutation(journal, peer, capability_id, canonical_request)?;
    public_mutation::reserve_authorized_attach(journal, &authorized, request_digest)
}

/// Prepares an authorized, read-only Host readiness query before reservation.
///
/// # Errors
///
/// Rejects malformed or unauthorized attach requests and stale execution or
/// protected Host authority without writing a public pending record.
#[cfg(target_os = "linux")]
pub fn prepare_public_attach_readiness_v1(
    journal: &mut Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    capability_id: CapabilityId,
    canonical_request: &[u8],
    node: aos_sandbox_core::NodeId,
    now_seconds: i64,
) -> Result<crate::public_attach_pending::PublicAttachHostQueryDraftV1, OperationCompilationError> {
    let authorized = authorize_public_mutation(journal, peer, capability_id, canonical_request)?;
    public_mutation::prepare_authorized_attach_readiness(journal, &authorized, node, now_seconds)
}

/// Looks up an existing pending or accepted ATTACH without another reservation.
///
/// # Errors
///
/// Rejects malformed public input, stale capability authorization, or a
/// conflicting protected idempotency/pending identity.
#[cfg(target_os = "linux")]
pub fn lookup_public_attach_existing_v1(
    journal: &mut Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    capability_id: CapabilityId,
    canonical_request: &[u8],
    request_digest: [u8; 32],
) -> Result<
    Option<(crate::public_attach_pending::PublicAttachPendingV1, bool)>,
    OperationCompilationError,
> {
    let authorized = authorize_public_mutation(journal, peer, capability_id, canonical_request)?;
    public_mutation::lookup_authorized_attach_existing(journal, &authorized, request_digest)
}

impl ActivatedOperationCompiler for ProductionOperationCompilerV1 {
    fn compile(
        &mut self,
        _journal: &mut Journal,
        _canonical_request: &[u8],
        _request_digest: [u8; 32],
    ) -> Result<OperationPlan, OperationCompilationError> {
        Err(OperationCompilationError::Rejected)
    }

    fn compile_public(
        &mut self,
        journal: &mut Journal,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        canonical_request: &[u8],
        request_digest: [u8; 32],
    ) -> Result<OperationPlan, OperationCompilationError> {
        let authorized =
            authorize_public_mutation(journal, peer, capability_id, canonical_request)?;
        let request = authorized.request();
        use crate::cli_model::DormantSandboxRequestKindV1 as Request;

        match request.request() {
            Request::CapabilityAttenuate(attenuate) => compile_capability_attenuation(
                journal,
                peer,
                &authorized,
                attenuate,
                request_digest,
            ),
            Request::CapabilityRenew(renew) => {
                compile_capability_renewal(journal, peer, &authorized, renew, request_digest)
            }
            Request::CapabilityRevoke(revoke) => {
                compile_capability_revoke(journal, peer, &authorized, revoke, request_digest)
            }
            _ => public_mutation::compile_public_mutation(
                journal,
                peer,
                &authorized,
                canonical_request,
                request_digest,
            ),
        }
    }

    #[cfg(target_os = "linux")]
    fn compile_public_operator_recovery(
        &mut self,
        journal: &mut Journal,
        peer: &crate::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        canonical_request: &[u8],
        request_digest: [u8; 32],
    ) -> Result<OperationPlan, OperationCompilationError> {
        operator_recovery::compile_public_operator_recovery(
            journal,
            peer,
            capability_id,
            canonical_request,
            request_digest,
        )
    }

    #[cfg(target_os = "linux")]
    fn plan_public_policy(
        &mut self,
        journal: &mut Journal,
        request: crate::public_policy_planner::AuthorizedPublicPolicyPlanRequestV1,
    ) -> Result<
        aos_proto::aos::sandbox::v1::PolicyPlan,
        crate::public_policy_planner::PublicPolicyPlanningErrorV1,
    > {
        policy_plan::compile_public_policy_plan(journal, &request)
    }
}

fn compile_capability_attenuation(
    journal: &mut Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    authorized: &AuthorizedPublicMutationRequestV1,
    attenuate: &aos_proto::aos::sandbox::v1::AttenuateCapabilityRequest,
    request_digest: [u8; 32],
) -> Result<OperationPlan, OperationCompilationError> {
    let request = authorized.request();
    let parent_id = PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
        .and_then(|registry| {
            registry.resolve_holder_handle(
                &attenuate.parent_capability_handle,
                peer.principal(),
                peer.key_binding(),
            )
        })
        .map_err(|_| OperationCompilationError::Rejected)?;
    let holder_binding: [u8; 32] = attenuate
        .holder_channel_binding
        .as_slice()
        .try_into()
        .map_err(|_| OperationCompilationError::Malformed)?;
    if holder_binding != *peer.key_binding().as_bytes()
        || attenuate.attenuation.is_empty()
        || attenuate.attenuation.len() > MAXIMUM_CAPABILITY_ATTENUATION_BYTES
    {
        return Err(OperationCompilationError::Malformed);
    }
    let attenuation: PublicCapabilityAttenuationV1 = serde_json::from_slice(&attenuate.attenuation)
        .map_err(|_| OperationCompilationError::Malformed)?;
    if attenuation.version != CAPABILITY_ATTENUATION_VERSION
        || serde_json::to_vec(&attenuation).map_err(|_| OperationCompilationError::Malformed)?
            != attenuate.attenuation
    {
        return Err(OperationCompilationError::Malformed);
    }

    match journal.check_idempotency(request.idempotency_key(), request_digest) {
        IdempotencyOutcome::Replay(operation_id) => {
            return replay_capability_attenuation(
                journal,
                operation_id,
                request.idempotency_key().clone(),
                request_digest,
            );
        }
        IdempotencyOutcome::Conflict => return Err(OperationCompilationError::Rejected),
        IdempotencyOutcome::Vacant => {}
    }

    let parent = PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
        .and_then(|registry| registry.resolve_current(parent_id))
        .map_err(|_| OperationCompilationError::Rejected)?;
    if parent.claims().project != peer.project()
        || attenuate.expected_parent_resource_version
            != capability_resource_version(&parent, false)?
    {
        return Err(OperationCompilationError::Rejected);
    }

    let (controller, revocation, policy) = {
        let store = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())
            .map_err(|_| OperationCompilationError::Rejected)?;
        let controller = store
            .controller_head()
            .map_err(|_| OperationCompilationError::Rejected)?
            .ok_or(OperationCompilationError::Rejected)?;
        let revocation = store
            .revocation_head(parent.claims().revocation_scope)
            .map_err(|_| OperationCompilationError::Rejected)?
            .ok_or(OperationCompilationError::Rejected)?;
        let policy = store
            .current_policy(peer.project())
            .map_err(|_| OperationCompilationError::Rejected)?
            .ok_or(OperationCompilationError::Rejected)?;
        (controller, revocation, policy)
    };
    let claims = parent.claims();
    if controller.principal != claims.audience
        || revocation.scope != claims.revocation_scope
        || revocation.generation != claims.revocation_generation.get()
        || policy.descriptor().digest() != claims.policy_digest
        || authorized.accepted_wall_seconds() < policy.not_before()
        || authorized.accepted_wall_seconds() >= policy.expires_at()
    {
        return Err(OperationCompilationError::Rejected);
    }

    let operation_id = OperationId::new();
    let context = aos_sandbox_core::AuthorizationContext {
        now: authorized.accepted_wall_seconds(),
        audience: controller.principal,
        holder: peer.principal(),
        channel_binding: peer.key_binding(),
        project: peer.project(),
        sandbox: claims.sandbox,
        incarnation: claims.incarnation,
        assignment_epoch: claims.assignment_epoch,
        revocation_generation: claims.revocation_generation,
    };
    let child = parent
        .attenuate(
            &context,
            AttenuationRequest {
                id: CapabilityId::new(),
                audience: controller.principal,
                holder: peer.principal(),
                channel_binding: ChannelBinding::new(holder_binding),
                sandbox: attenuation.sandbox,
                incarnation: attenuation.incarnation,
                grants: attenuation.grants,
                assignment_epoch: attenuation.assignment_epoch,
                not_before: attenuation.not_before,
                expires_at: attenuation.expires_at,
                delegation: attenuation.delegation,
                delegation_selector: attenuation.delegation_selector,
                parent_decision: AuditId::from_bytes(operation_id.into_bytes()),
            },
        )
        .map_err(|_| OperationCompilationError::Rejected)?;
    let authority_record =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
            .and_then(|registry| {
                registry.prepare_attenuation_from_trusted_controller(parent_id, child.clone())
            })
            .map_err(|_| OperationCompilationError::Rejected)?;

    let projection = capability_projection(&child, policy.descriptor(), false)?;
    let projection = PublicProjectionPlanV1::new(
        peer.project(),
        operation_id,
        PublicProjectionResourceV1::Capability(projection),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let (desired_key, desired_value) = projection.into_desired_state();
    let plan = OperationPlan::completed_local(
        operation_id,
        request.idempotency_key().clone(),
        request_digest,
        desired_key,
        desired_value,
        vec![authority_record],
    )
    .map_err(|_| OperationCompilationError::Rejected)?;

    attach_public_operation(plan, authorized, peer.project(), operation_id)
}

fn replay_capability_attenuation(
    journal: &mut Journal,
    operation_id: OperationId,
    idempotency_key: crate::IdempotencyKey,
    request_digest: [u8; 32],
) -> Result<OperationPlan, OperationCompilationError> {
    let projections = PublicProjectionStoreV1::new(journal)
        .list_operation(operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?;
    let [projection] = projections.as_slice() else {
        return Err(OperationCompilationError::Rejected);
    };
    let PublicProjectionResourceV1::Capability(projected_child) = projection.resource() else {
        return Err(OperationCompilationError::Rejected);
    };
    if projected_child.revoked {
        return Err(OperationCompilationError::Rejected);
    }
    let child_id = CapabilityId::from_bytes(
        projected_child
            .capability_id
            .as_slice()
            .try_into()
            .map_err(|_| OperationCompilationError::Rejected)?,
    );
    let desired = PublicProjectionPlanV1::new(
        projection.project(),
        operation_id,
        projection.resource().clone(),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let registry = PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
        .map_err(|_| OperationCompilationError::Rejected)?;
    let child = registry
        .resolve_current(child_id)
        .map_err(|_| OperationCompilationError::Rejected)?;
    if capability_resource_version(&child, false)? != projected_child.resource_version {
        return Err(OperationCompilationError::Rejected);
    }
    let authority_record = registry
        .retained_record_for_atomic_replay(child_id)
        .map_err(|_| OperationCompilationError::Rejected)?;
    let public = crate::reconciler::recovered_public_operation_admission_v1(journal, operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    let (desired_key, desired_value) = desired.into_desired_state();

    OperationPlan::completed_local(
        operation_id,
        idempotency_key,
        request_digest,
        desired_key,
        desired_value,
        vec![authority_record],
    )
    .map_err(|_| OperationCompilationError::Rejected)?
    .with_public_operation(public)
    .map_err(|_| OperationCompilationError::Rejected)
}

fn compile_capability_revoke(
    journal: &mut Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    authorized: &AuthorizedPublicMutationRequestV1,
    revoke: &aos_proto::aos::sandbox::v1::RevokeCapabilityRequest,
    request_digest: [u8; 32],
) -> Result<OperationPlan, OperationCompilationError> {
    let request = authorized.request();
    let target = CapabilityId::from_bytes(
        revoke
            .capability_id
            .as_slice()
            .try_into()
            .map_err(|_| OperationCompilationError::Malformed)?,
    );
    let mutation = revoke
        .mutation
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;

    match journal.check_idempotency(request.idempotency_key(), request_digest) {
        IdempotencyOutcome::Replay(operation_id) => {
            return replay_capability_revoke(
                journal,
                operation_id,
                target,
                request.idempotency_key().clone(),
                request_digest,
            );
        }
        IdempotencyOutcome::Conflict => return Err(OperationCompilationError::Rejected),
        IdempotencyOutcome::Vacant => {}
    }

    let (capability, authority_record) = {
        let registry =
            PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
                .map_err(|_| OperationCompilationError::Rejected)?;
        let capability = registry
            .resolve_current(target)
            .map_err(|_| OperationCompilationError::Rejected)?;
        let authority_record = registry
            .prepare_revoke_from_trusted_controller(target)
            .map_err(|_| OperationCompilationError::Rejected)?;
        (capability, authority_record)
    };
    if capability.claims().project != peer.project() {
        return Err(OperationCompilationError::Rejected);
    }

    let policy = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())
        .map_err(|_| OperationCompilationError::Rejected)?
        .current_policy(peer.project())
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    if policy.descriptor().digest() != capability.claims().policy_digest {
        return Err(OperationCompilationError::Rejected);
    }

    let expected_version = capability_resource_version(&capability, false)?;
    if mutation.expected_resource_version != expected_version {
        return Err(OperationCompilationError::Rejected);
    }

    let operation_id = OperationId::new();
    let projection = capability_projection(&capability, policy.descriptor(), true)?;
    let projection = PublicProjectionPlanV1::new(
        peer.project(),
        operation_id,
        PublicProjectionResourceV1::Capability(projection),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let (desired_key, desired_value) = projection.into_desired_state();
    let plan = OperationPlan::completed_local(
        operation_id,
        request.idempotency_key().clone(),
        request_digest,
        desired_key,
        desired_value,
        vec![authority_record],
    )
    .map_err(|_| OperationCompilationError::Rejected)?;

    attach_public_operation(plan, authorized, peer.project(), operation_id)
}

fn compile_capability_renewal(
    journal: &mut Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    authorized: &AuthorizedPublicMutationRequestV1,
    renew: &aos_proto::aos::sandbox::v1::RenewCapabilityRequest,
    request_digest: [u8; 32],
) -> Result<OperationPlan, OperationCompilationError> {
    let request = authorized.request();
    let predecessor_id =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
            .and_then(|registry| {
                registry.resolve_holder_handle(
                    &renew.capability_handle,
                    peer.principal(),
                    peer.key_binding(),
                )
            })
            .map_err(|_| OperationCompilationError::Rejected)?;
    let mutation = renew
        .mutation
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;
    let requested_expiry = renew
        .requested_expiry
        .as_option()
        .ok_or(OperationCompilationError::Malformed)?;
    if requested_expiry.nanoseconds != 0 {
        return Err(OperationCompilationError::Malformed);
    }

    match journal.check_idempotency(request.idempotency_key(), request_digest) {
        // A committed renewal atomically retires this predecessor. Replays use
        // the separate retired-handle path after exact caller/request proof.
        IdempotencyOutcome::Replay(_) => return Err(OperationCompilationError::Rejected),
        IdempotencyOutcome::Conflict => return Err(OperationCompilationError::Rejected),
        IdempotencyOutcome::Vacant => {}
    }

    let predecessor =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
            .and_then(|registry| registry.resolve_current(predecessor_id))
            .map_err(|_| OperationCompilationError::Rejected)?;
    if predecessor.claims().project != peer.project()
        || mutation.expected_resource_version != capability_resource_version(&predecessor, false)?
    {
        return Err(OperationCompilationError::Rejected);
    }

    let policy = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())
        .map_err(|_| OperationCompilationError::Rejected)?
        .current_policy(peer.project())
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    if policy.descriptor().digest() != predecessor.claims().policy_digest
        || requested_expiry.seconds <= authorized.accepted_wall_seconds()
        || requested_expiry.seconds > policy.expires_at()
    {
        return Err(OperationCompilationError::Rejected);
    }

    let operation_id = OperationId::new();
    let mut successor_draft = predecessor.claims().clone();
    successor_draft.id = CapabilityId::new();
    successor_draft.not_before = authorized.accepted_wall_seconds();
    successor_draft.expires_at = requested_expiry.seconds;
    successor_draft.parent_decision = AuditId::from_bytes(operation_id.into_bytes());
    let successor = CapabilityRecord::issue(successor_draft)
        .map_err(|_| OperationCompilationError::Rejected)?;
    let authority_records =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
            .and_then(|registry| {
                registry.prepare_renewal_from_trusted_controller(predecessor_id, successor.clone())
            })
            .map_err(|_| OperationCompilationError::Rejected)?;

    let projection = capability_projection(&successor, policy.descriptor(), false)?;
    let projection = PublicProjectionPlanV1::new(
        peer.project(),
        operation_id,
        PublicProjectionResourceV1::Capability(projection),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let predecessor_projection = public_projection_deletion_record_v1(
        PublicProjectionKindV1::Capability,
        predecessor_id.into_bytes(),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let (desired_key, desired_value) = projection.into_desired_state();
    let mut local_records = Vec::from(authority_records);
    local_records.push(predecessor_projection);
    let plan = OperationPlan::completed_local(
        operation_id,
        request.idempotency_key().clone(),
        request_digest,
        desired_key,
        desired_value,
        local_records,
    )
    .map_err(|_| OperationCompilationError::Rejected)?;

    attach_public_operation(plan, authorized, peer.project(), operation_id)
}

/// Reconstructs only an already committed renewal for its retired TLS holder.
///
/// No policy or predecessor-currentness check is bypassed for a new request:
/// the protected idempotency decision must name the exact caller-bound digest.
/// The returned plan is consumed only by the ledger's equality-checked replay.
pub(crate) fn replay_committed_capability_renewal_v1(
    journal: &mut Journal,
    holder: PrincipalId,
    project: ProjectId,
    binding: ChannelBinding,
    claimed_uid: CapabilityId,
    invoking_handle: &[u8; 32],
    canonical_request: &[u8],
    request_digest: [u8; 32],
) -> Result<OperationPlan, OperationCompilationError> {
    use crate::cli_model::DormantSandboxRequestKindV1;

    let request = ResolvedPublicMutationRequestV1::decode(canonical_request)
        .map_err(|_| OperationCompilationError::Rejected)?;
    let DormantSandboxRequestKindV1::CapabilityRenew(renew) = request.request() else {
        return Err(OperationCompilationError::Rejected);
    };
    if renew.capability_handle.as_slice() != invoking_handle {
        return Err(OperationCompilationError::Rejected);
    }
    let mutation = renew
        .mutation
        .as_option()
        .ok_or(OperationCompilationError::Rejected)?;
    let requested_expiry = renew
        .requested_expiry
        .as_option()
        .ok_or(OperationCompilationError::Rejected)?;
    if requested_expiry.nanoseconds != 0 {
        return Err(OperationCompilationError::Rejected);
    }

    let predecessor =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
            .and_then(|registry| {
                registry.retired_holder_handle_for_replay(invoking_handle, holder, binding)
            })
            .map_err(|_| OperationCompilationError::Rejected)?;
    if predecessor.id() != claimed_uid || predecessor.claims().project != project {
        return Err(OperationCompilationError::Rejected);
    }
    if mutation.expected_resource_version != capability_resource_version(&predecessor, false)? {
        return Err(OperationCompilationError::Rejected);
    }
    let IdempotencyOutcome::Replay(operation_id) =
        journal.check_idempotency(request.idempotency_key(), request_digest)
    else {
        return Err(OperationCompilationError::Rejected);
    };

    replay_capability_renewal(
        journal,
        operation_id,
        &predecessor,
        requested_expiry.seconds,
        request.idempotency_key().clone(),
        request_digest,
    )
}

fn replay_capability_renewal(
    journal: &mut Journal,
    operation_id: OperationId,
    predecessor: &CapabilityRecord,
    requested_expiry: i64,
    idempotency_key: crate::IdempotencyKey,
    request_digest: [u8; 32],
) -> Result<OperationPlan, OperationCompilationError> {
    let predecessor_id = predecessor.id();
    let projections = PublicProjectionStoreV1::new(journal)
        .list_operation(operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?;
    let [projection] = projections.as_slice() else {
        return Err(OperationCompilationError::Rejected);
    };
    let PublicProjectionResourceV1::Capability(projected_successor) = projection.resource() else {
        return Err(OperationCompilationError::Rejected);
    };
    if projected_successor.revoked {
        return Err(OperationCompilationError::Rejected);
    }
    let successor_id = CapabilityId::from_bytes(
        projected_successor
            .capability_id
            .as_slice()
            .try_into()
            .map_err(|_| OperationCompilationError::Rejected)?,
    );
    let desired = PublicProjectionPlanV1::new(
        projection.project(),
        operation_id,
        projection.resource().clone(),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let registry = PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
        .map_err(|_| OperationCompilationError::Rejected)?;
    if !matches!(
        registry.resolve_current(predecessor_id),
        Err(crate::publisher_authority::PublisherAuthorityError::Revoked)
    ) {
        return Err(OperationCompilationError::Rejected);
    }
    let successor = registry
        .resolve_current(successor_id)
        .map_err(|_| OperationCompilationError::Rejected)?;
    let mut expected_successor = predecessor.claims().clone();
    expected_successor.id = successor_id;
    expected_successor.not_before = successor.claims().not_before;
    expected_successor.expires_at = successor.claims().expires_at;
    expected_successor.parent_decision = AuditId::from_bytes(operation_id.into_bytes());
    if successor.claims() != &expected_successor {
        return Err(OperationCompilationError::Rejected);
    }
    if successor.claims().expires_at != requested_expiry {
        return Err(OperationCompilationError::Rejected);
    }
    if capability_resource_version(&successor, false)? != projected_successor.resource_version {
        return Err(OperationCompilationError::Rejected);
    }
    let mut local_records = vec![
        registry
            .retained_record_for_atomic_replay(predecessor_id)
            .map_err(|_| OperationCompilationError::Rejected)?,
        registry
            .retained_record_for_atomic_replay(successor_id)
            .map_err(|_| OperationCompilationError::Rejected)?,
    ];
    local_records.push(
        public_projection_deletion_record_v1(
            PublicProjectionKindV1::Capability,
            predecessor_id.into_bytes(),
        )
        .map_err(|_| OperationCompilationError::Rejected)?,
    );
    let public = crate::reconciler::recovered_public_operation_admission_v1(journal, operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    if public.method() != PublicOperationMethodV1::RenewCapability
        || public.authorization().project() != predecessor.claims().project
        || public.authorization().resource_kind() != ResourceKind::Capability
        || public.authorization().selector()
            != &(Selector::Resource {
                resource: ResourceId::from_bytes(predecessor_id.into_bytes()),
            })
    {
        return Err(OperationCompilationError::Rejected);
    }
    if successor.claims().not_before != public.accepted_wall_seconds() {
        return Err(OperationCompilationError::Rejected);
    }
    let (desired_key, desired_value) = desired.into_desired_state();

    OperationPlan::completed_local(
        operation_id,
        idempotency_key,
        request_digest,
        desired_key,
        desired_value,
        local_records,
    )
    .map_err(|_| OperationCompilationError::Rejected)?
    .with_public_operation(public)
    .map_err(|_| OperationCompilationError::Rejected)
}

fn attach_public_operation(
    plan: OperationPlan,
    authorized: &AuthorizedPublicMutationRequestV1,
    project: aos_sandbox_core::ProjectId,
    operation_id: OperationId,
) -> Result<OperationPlan, OperationCompilationError> {
    let request = authorized.request();
    let authorization = PublicOperationAuthorizationV1::new(
        project,
        request.resource_kind(),
        request
            .selector()
            .ok_or(OperationCompilationError::Rejected)?
            .clone(),
    );
    let authorization = authorization.map_err(|_| OperationCompilationError::Rejected)?;
    let public = PublicOperationAdmissionV1::new(
        request.operation_method(),
        1,
        operation_id.into_bytes(),
        authorized.accepted_wall_seconds(),
        authorization,
    )
    .map_err(|_| OperationCompilationError::Rejected)?;

    plan.with_public_operation(public)
        .map_err(|_| OperationCompilationError::Rejected)
}

fn replay_capability_revoke(
    journal: &mut Journal,
    operation_id: OperationId,
    capability_id: CapabilityId,
    idempotency_key: crate::IdempotencyKey,
    request_digest: [u8; 32],
) -> Result<OperationPlan, OperationCompilationError> {
    let projections = PublicProjectionStoreV1::new(journal)
        .list_operation(operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?;
    let [projection] = projections.as_slice() else {
        return Err(OperationCompilationError::Rejected);
    };
    let PublicProjectionResourceV1::Capability(capability) = projection.resource() else {
        return Err(OperationCompilationError::Rejected);
    };
    if capability.capability_id.as_slice() != capability_id.as_bytes() || !capability.revoked {
        return Err(OperationCompilationError::Rejected);
    }
    let desired = PublicProjectionPlanV1::new(
        projection.project(),
        operation_id,
        projection.resource().clone(),
    )
    .map_err(|_| OperationCompilationError::Rejected)?;
    let authority_record =
        PublisherCapabilityRegistry::load(journal, PublisherAuthorityLimits::default())
            .and_then(|registry| registry.retained_record_for_atomic_replay(capability_id))
            .map_err(|_| OperationCompilationError::Rejected)?;
    let public = crate::reconciler::recovered_public_operation_admission_v1(journal, operation_id)
        .map_err(|_| OperationCompilationError::Rejected)?
        .ok_or(OperationCompilationError::Rejected)?;
    let (desired_key, desired_value) = desired.into_desired_state();

    OperationPlan::completed_local(
        operation_id,
        idempotency_key,
        request_digest,
        desired_key,
        desired_value,
        vec![authority_record],
    )
    .map_err(|_| OperationCompilationError::Rejected)?
    .with_public_operation(public)
    .map_err(|_| OperationCompilationError::Rejected)
}

fn capability_projection(
    capability: &CapabilityRecord,
    policy: &aos_sandbox_core::ObjectDescriptor,
    revoked: bool,
) -> Result<Capability, OperationCompilationError> {
    let claims = capability.claims();
    Ok(Capability {
        capability_id: claims.id.into_bytes().to_vec(),
        project_id: claims.project.into_bytes().to_vec(),
        sandbox_id: claims
            .sandbox
            .map_or_else(Vec::new, |sandbox| sandbox.into_bytes().to_vec()),
        holder_principal_id: claims.holder.into_bytes().to_vec(),
        resource_version: capability_resource_version(capability, revoked)?,
        not_before: Some(Timestamp {
            seconds: claims.not_before,
            nanoseconds: 0,
            ..Default::default()
        })
        .into(),
        expires_at: Some(Timestamp {
            seconds: claims.expires_at,
            nanoseconds: 0,
            ..Default::default()
        })
        .into(),
        remaining_delegation_depth: claims.delegation.remaining_depth(),
        maximum_fanout: claims.delegation.maximum_fanout(),
        revoked,
        effective_policy: Some(ObjectDescriptor {
            media_type: policy.media_type().as_str().to_owned(),
            sha256: policy.digest().as_bytes().to_vec(),
            encoded_size: policy.encoded_size(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    })
}

fn capability_resource_version(
    capability: &CapabilityRecord,
    revoked: bool,
) -> Result<Vec<u8>, OperationCompilationError> {
    let claims = serde_json::to_vec(capability).map_err(|_| OperationCompilationError::Rejected)?;
    let digest: [u8; 32] = Sha256::new()
        .chain_update(CAPABILITY_RESOURCE_VERSION_DOMAIN)
        .chain_update([u8::from(revoked)])
        .chain_update((claims.len() as u64).to_be_bytes())
        .chain_update(claims)
        .finalize()
        .into();
    Ok(digest.to_vec())
}

#[cfg(test)]
mod renewal_replay_tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::PathBuf;

    use aos_proto::aos::sandbox::v1::{
        Duration, MutationContext, RenewCapabilityRequest, RevokeCapabilityRequest,
    };
    use aos_sandbox_core::{MediaType, ObjectDigest};
    use buffa::Message as _;

    use super::*;
    use crate::cli_model::{PublicApiAuditMethodV1, PublicMutationRequestV1};
    use crate::reconciler::{
        AcceptOutcome, EffectFailure, EffectObservation, EffectPlan, EffectReceipt, Reconciler,
        SingleNodeEffectExecutor,
    };
    use crate::{IdempotencyKey, JournalLimits};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-capability-renewal-replay-{}",
                OperationId::new()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn open(&self) -> Journal {
            let uid = fs::metadata(&self.0).unwrap().uid();
            Journal::open_protected_at_uid(
                &self.0,
                "renewal.journal",
                JournalLimits::default(),
                uid,
            )
            .unwrap()
            .0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct NoEffects;

    impl SingleNodeEffectExecutor for NoEffects {
        fn observe(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectObservation, EffectFailure> {
            unreachable!("controller-local renewal has no effects")
        }

        fn apply(
            &mut self,
            _operation_id: OperationId,
            _step: u32,
            _plan: &EffectPlan,
        ) -> Result<EffectReceipt, EffectFailure> {
            unreachable!("controller-local renewal has no effects")
        }
    }

    fn renewal_request(
        handle: [u8; 32],
        expiry: i64,
        key: &[u8],
        expected_resource_version: &[u8],
    ) -> Vec<u8> {
        let request = RenewCapabilityRequest {
            capability_handle: handle.to_vec(),
            requested_expiry: Some(Timestamp {
                seconds: expiry,
                ..Default::default()
            })
            .into(),
            mutation: Some(MutationContext {
                idempotency_key: key.to_vec(),
                expected_resource_version: expected_resource_version.to_vec(),
                operation_timeout: Some(Duration {
                    nanoseconds: 1,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        PublicMutationRequestV1::new(
            PublicApiAuditMethodV1::RenewCapability,
            &request.encode_to_vec(),
        )
        .unwrap()
        .encode()
    }

    #[test]
    fn committed_renewal_replays_only_for_exact_retired_holder_and_request() {
        let directory = TestDirectory::new();
        let mut reconciler = Reconciler::new(directory.open(), NoEffects);
        let predecessor_id = CapabilityId::from_bytes([41; 16]);
        let predecessor = crate::publisher_authority::tests::capability(predecessor_id, 200);
        let holder = predecessor.claims().holder;
        let binding = predecessor.claims().channel_binding;
        let project = predecessor.claims().project;
        let operation_id = OperationId::new();
        let successor_id = CapabilityId::from_bytes([42; 16]);
        let mut successor_draft = predecessor.claims().clone();
        successor_draft.id = successor_id;
        successor_draft.not_before = 150;
        successor_draft.expires_at = 300;
        successor_draft.parent_decision = AuditId::from_bytes(operation_id.into_bytes());
        let successor = CapabilityRecord::issue(successor_draft).unwrap();

        let predecessor_handle = {
            let mut registry = PublisherCapabilityRegistry::load(
                reconciler.journal_mut(),
                PublisherAuthorityLimits::default(),
            )
            .unwrap();
            registry
                .install_from_trusted_controller([41; 16], predecessor.clone())
                .unwrap();
            registry
                .holder_handle(predecessor_id, holder, binding)
                .unwrap()
        };
        let predecessor_version = capability_resource_version(&predecessor, false).unwrap();
        let request = renewal_request(
            predecessor_handle,
            300,
            b"exact-renewal",
            &predecessor_version,
        );
        let request_digest = [51; 32];
        assert!(
            replay_committed_capability_renewal_v1(
                reconciler.journal_mut(),
                holder,
                project,
                binding,
                predecessor_id,
                &predecessor_handle,
                &request,
                request_digest,
            )
            .is_err(),
            "an active handle cannot enter committed replay"
        );
        let policy = aos_sandbox_core::ObjectDescriptor::new(
            MediaType::new("application/json").unwrap(),
            ObjectDigest::from_bytes([10; 32]),
            1,
        );
        let projection = PublicProjectionPlanV1::new(
            project,
            operation_id,
            PublicProjectionResourceV1::Capability(
                capability_projection(&successor, &policy, false).unwrap(),
            ),
        )
        .unwrap();
        let (desired_key, desired_value) = projection.into_desired_state();
        let authority_records = PublisherCapabilityRegistry::load(
            reconciler.journal_mut(),
            PublisherAuthorityLimits::default(),
        )
        .unwrap()
        .prepare_renewal_from_trusted_controller(predecessor_id, successor)
        .unwrap();
        let mut local_records = Vec::from(authority_records);
        local_records.push(
            public_projection_deletion_record_v1(
                PublicProjectionKindV1::Capability,
                predecessor_id.into_bytes(),
            )
            .unwrap(),
        );
        let public = PublicOperationAdmissionV1::new(
            PublicOperationMethodV1::RenewCapability,
            1,
            operation_id.into_bytes(),
            150,
            PublicOperationAuthorizationV1::new(
                project,
                ResourceKind::Capability,
                Selector::Resource {
                    resource: ResourceId::from_bytes(predecessor_id.into_bytes()),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let plan = OperationPlan::completed_local(
            operation_id,
            IdempotencyKey::new(b"exact-renewal".to_vec()).unwrap(),
            request_digest,
            desired_key,
            desired_value,
            local_records,
        )
        .unwrap()
        .with_public_operation(public)
        .unwrap();
        assert_eq!(
            reconciler.accept(&plan).unwrap(),
            AcceptOutcome::Accepted(operation_id)
        );
        let committed_handle = PublisherCapabilityRegistry::load(
            reconciler.journal_mut(),
            PublisherAuthorityLimits::default(),
        )
        .unwrap()
        .holder_handle(successor_id, holder, binding)
        .unwrap();
        drop(reconciler);

        let mut reconciler = Reconciler::new(directory.open(), NoEffects);
        let replay = |journal: &mut Journal, holder, binding, uid, request: &[u8], digest| {
            replay_committed_capability_renewal_v1(
                journal,
                holder,
                project,
                binding,
                uid,
                &predecessor_handle,
                request,
                digest,
            )
        };
        let replayed = replay(
            reconciler.journal_mut(),
            holder,
            binding,
            predecessor_id,
            &request,
            request_digest,
        )
        .unwrap();
        assert_eq!(
            reconciler.accept(&replayed).unwrap(),
            AcceptOutcome::Replay(operation_id)
        );

        let successor_handle = PublisherCapabilityRegistry::load(
            reconciler.journal_mut(),
            PublisherAuthorityLimits::default(),
        )
        .unwrap()
        .holder_handle(successor_id, holder, binding)
        .unwrap();
        assert_eq!(successor_handle, committed_handle);
        assert_ne!(successor_handle, predecessor_handle);
        assert_eq!(successor_handle.len(), 32);

        for (wrong_holder, wrong_binding, wrong_uid, wrong_request, wrong_digest) in [
            (
                PrincipalId::from_bytes([99; 16]),
                binding,
                predecessor_id,
                request.clone(),
                request_digest,
            ),
            (
                holder,
                ChannelBinding::new([99; 32]),
                predecessor_id,
                request.clone(),
                request_digest,
            ),
            (
                holder,
                binding,
                successor_id,
                request.clone(),
                request_digest,
            ),
            (
                holder,
                binding,
                predecessor_id,
                renewal_request(
                    predecessor_handle,
                    301,
                    b"exact-renewal",
                    &predecessor_version,
                ),
                request_digest,
            ),
            (
                holder,
                binding,
                predecessor_id,
                renewal_request([77; 32], 300, b"exact-renewal", &predecessor_version),
                request_digest,
            ),
            (holder, binding, predecessor_id, request.clone(), [52; 32]),
        ] {
            assert!(
                replay(
                    reconciler.journal_mut(),
                    wrong_holder,
                    wrong_binding,
                    wrong_uid,
                    &wrong_request,
                    wrong_digest,
                )
                .is_err()
            );
        }

        assert!(
            replay_committed_capability_renewal_v1(
                reconciler.journal_mut(),
                holder,
                ProjectId::from_bytes([99; 16]),
                binding,
                predecessor_id,
                &predecessor_handle,
                &request,
                request_digest,
            )
            .is_err()
        );

        let revoke = RevokeCapabilityRequest {
            capability_id: predecessor_id.into_bytes().to_vec(),
            mutation: Some(MutationContext {
                idempotency_key: b"exact-renewal".to_vec(),
                expected_resource_version: predecessor_version,
                operation_timeout: Some(Duration {
                    nanoseconds: 1,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let wrong_method = PublicMutationRequestV1::new(
            PublicApiAuditMethodV1::RevokeCapability,
            &revoke.encode_to_vec(),
        )
        .unwrap()
        .encode();
        assert!(
            replay(
                reconciler.journal_mut(),
                holder,
                binding,
                predecessor_id,
                &wrong_method,
                request_digest,
            )
            .is_err()
        );
    }
}
