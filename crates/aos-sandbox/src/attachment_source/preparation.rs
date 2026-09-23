//! Compiles exact Mount Acquire bytes from a fresh protected source plan.
//!
//! These bytes and semantics are nonauthorizing. A later caller must bind an
//! independent Mount-signed plan, durably record source custody, and carry the
//! exact request through the retained authenticated Mount session.

use aos_proto::aos::sandbox::local::v1::{AcquireMountSourceRequest, Audience, RequestHeader};
use aos_sandbox_core::model::AttachmentConsistency;
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, ObjectDigest, OperationId, ProtocolId,
    RawPairedClockSample, RevocationScopeId,
};
use aos_sandbox_protocol::semantics::{
    CanonicalMountSourceAcquisitionSemanticsV1, canonical_acquire_mount_source_semantics_v1,
};
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_acquire_mount_source_request};
use buffa::Message as _;

use super::planning::{
    AttachmentSourceActionV1, AttachmentSourceError, CurrentAttachmentSourcePlanV1,
    source_projection,
};
use crate::Journal;
use crate::mount_preparation::current_fence;
use crate::ownership_authority::ProtectedOwnershipClockError;

const MOUNT_RESPONSE_BYTES: u32 = 16 * 1024;

/// Retains an exact Acquire request and its current nonauthorizing source plan.
#[must_use = "admit the exact source request before sending it to Mount"]
pub struct PreparedCurrentAttachmentSourceAcquireV1 {
    pub(super) plan: CurrentAttachmentSourcePlanV1,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    body: Vec<u8>,
    body_without_deadline: Vec<u8>,
    semantics: CanonicalMountSourceAcquisitionSemanticsV1,
}

impl PreparedCurrentAttachmentSourceAcquireV1 {
    /// Returns the request identifier used for exact Mount and custody replay.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns SHA-256 of the exact canonical Acquire protobuf body.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }

    /// Borrows the exact request body retained for later admission and recovery.
    #[must_use]
    pub fn exact_request_body(&self) -> &[u8] {
        &self.body
    }

    /// Borrows the deadline-free bytes used for signed dispatch-template binding.
    #[must_use]
    pub fn body_without_deadline(&self) -> &[u8] {
        &self.body_without_deadline
    }

    /// Borrows the validated portable Mount Acquire plan-match tuple.
    #[must_use]
    pub const fn semantics(&self) -> &CanonicalMountSourceAcquisitionSemanticsV1 {
        &self.semantics
    }

    /// Constructs a Mount-only plan for this exact Acquire request.
    ///
    /// The revocation scope must come from the independent Mount credential.
    /// The plan remains nonauthorizing until signed, rebound to these exact
    /// semantics, and durably admitted before broker I/O.
    ///
    /// # Errors
    ///
    /// Rejects stale Host, ownership, or source custody and unrepresentable
    /// request or grant bounds.
    pub fn plan_at<T>(
        &self,
        journal: &mut Journal,
        mount_revocation_scope: RevocationScopeId,
        clock: &mut T,
    ) -> Result<BrokerAuthorizationPlan, AttachmentSourceError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.plan.recheck(journal, clock)?;
        let scope = self.plan.target.runtime_generation().scope();
        let (lease, fresh) = scope.verified_plan_lease(journal, clock)?;
        let manifest = scope.binding().manifest().manifest();
        // The later deadline-free dispatch template budgets the maximum
        // protobuf deadline field, not only this request's current varint.
        let request_bytes = self
            .body_without_deadline
            .len()
            .checked_add(11)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(AttachmentSourceError::Capacity)?;
        let grant = BrokerGrant::new(
            self.semantics.verb(),
            self.semantics.target(),
            self.semantics.commitment(),
            request_bytes,
            0,
        )?;
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountBroker,
            aos_sandbox_core::ProtocolVersion::new(2, 0),
            scope
                .binding()
                .manifest()
                .broker_assignment()
                .map_err(|_| AttachmentSourceError::Conflict)?,
            manifest.node(),
            lease.signer().clone(),
            vec![grant],
            manifest.policy().digest(),
            mount_revocation_scope,
            fresh.wall_seconds(),
            scope.expires_wall_seconds(),
            Vec::new(),
        )?;
        self.plan.recheck(journal, clock)?;
        Ok(plan)
    }
}

pub(crate) fn prepare_current_acquire<T>(
    journal: &mut Journal,
    plan: CurrentAttachmentSourcePlanV1,
    operation_id: OperationId,
    deadline_boottime_nanoseconds: u64,
    clock: &mut T,
) -> Result<PreparedCurrentAttachmentSourceAcquireV1, AttachmentSourceError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    if plan.action != AttachmentSourceActionV1::Acquire
        || plan.desired.intent().consistency() != AttachmentConsistency::ImmutableRevision
        || operation_id.as_bytes() == &[0; 16]
    {
        return Err(AttachmentSourceError::Conflict);
    }
    plan.recheck(journal, clock)?;
    let sample = clock()?;
    if deadline_boottime_nanoseconds <= sample.boottime_nanoseconds()
        || deadline_boottime_nanoseconds
            > plan
                .target
                .runtime_generation()
                .scope()
                .deadline_boottime_nanoseconds()
    {
        return Err(AttachmentSourceError::Changed);
    }

    let (binding, template) =
        source_projection(journal, plan.desired.intent(), &plan.target, sample)?;
    if binding.digest().as_bytes() != &plan.plan.source_binding_digest
        || template.digest().as_bytes() != &plan.plan.template_digest
    {
        return Err(AttachmentSourceError::Changed);
    }
    let request = AcquireMountSourceRequest {
        header: Some(RequestHeader {
            protocol_major: 2,
            protocol_minor: 0,
            request_id: operation_id.as_bytes().to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds,
            maximum_response_bytes: MOUNT_RESPONSE_BYTES,
            ..Default::default()
        })
        .into(),
        fence: Some(current_fence(&plan.target)).into(),
        prospective_mount_template: template.canonical_bytes().to_vec(),
        prospective_mount_template_digest: template.digest().as_bytes().to_vec(),
        source_binding: binding.canonical_bytes(),
        source_binding_digest: binding.digest().as_bytes().to_vec(),
        requested_lease_seconds: plan.bounds.lease_seconds(),
        requested_maximum_submounts: plan.bounds.maximum_submounts(),
        kernel_coupled: plan.bounds.kernel_coupled(),
        ..Default::default()
    };
    let body = request.encode_to_vec();
    let mut deadline_free = request;
    deadline_free
        .header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = 0;
    let body_without_deadline = deadline_free.encode_to_vec();
    let reconstructed = crate::dispatch::durable_attempt_body(
        &body_without_deadline,
        deadline_boottime_nanoseconds,
    )
    .map_err(|_| AttachmentSourceError::Protocol)?;
    if reconstructed != body {
        return Err(AttachmentSourceError::Protocol);
    }
    let peer = PeerCredentials {
        uid: 1,
        gid: 1,
        pid: Some(1),
    };
    let validated = decode_acquire_mount_source_request(
        &body,
        peer,
        PeerPolicy {
            uid: peer.uid,
            gid: Some(peer.gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        sample.boottime_nanoseconds(),
    )
    .map_err(|_| AttachmentSourceError::Protocol)?;
    let semantics = canonical_acquire_mount_source_semantics_v1(validated.request())
        .map_err(|_| AttachmentSourceError::Protocol)?;
    if validated.source_binding().digest().as_bytes() != &plan.plan.source_binding_digest
        || validated.prospective_mount_template_digest().as_bytes() != &plan.plan.template_digest
    {
        return Err(AttachmentSourceError::Conflict);
    }
    plan.recheck(journal, clock)?;
    Ok(PreparedCurrentAttachmentSourceAcquireV1 {
        plan,
        operation_id,
        request_digest: validated.request_digest(),
        body,
        body_without_deadline,
        semantics,
    })
}
