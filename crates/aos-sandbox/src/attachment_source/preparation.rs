//! Compiles exact Mount Acquire and Release bytes from protected source plans.
//!
//! These bytes and semantics are nonauthorizing. A later caller must bind an
//! independent Mount-signed plan, durably record source custody, and carry the
//! exact request through the retained authenticated Mount session.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_proto::aos::sandbox::local::v1::{
    AcquireMountSourceRequest, Audience, ReleaseMountSourceAcquisitionRequest, RequestHeader,
};
use aos_sandbox_core::model::AttachmentConsistency;
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerGrant, ObjectDigest, OperationId, ProtocolId,
    RawPairedClockSample, RevocationScopeId,
};
use aos_sandbox_protocol::semantics::{
    CanonicalMountSourceAcquisitionSemanticsV1, canonical_acquire_mount_source_semantics_v1,
    canonical_release_mount_source_acquisition_semantics_v1,
};
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, decode_acquire_mount_source_request,
    decode_release_mount_source_acquisition_request,
};
use buffa::Message as _;

use super::custody::{self, AttachmentSourceAttemptKindV1};
use super::dispatch_custody::{self, DurableCurrentAttachmentSourceDispatchV1};
use super::planning::{
    AttachmentSourceActionV1, AttachmentSourceError, CurrentAttachmentSourcePlanV1,
    source_projection,
};
use crate::Journal;
use crate::mount_preparation::current_fence;
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::{BrokerDispatchSemanticIdentityV1, BrokerDispatchTemplateV1, SignedBrokerPlan};

const MOUNT_RESPONSE_BYTES: u32 = 16 * 1024;

/// Retains an exact Acquire request and its current nonauthorizing source plan.
#[must_use = "admit the exact source request before sending it to Mount"]
pub struct PreparedCurrentAttachmentSourceAcquireV1 {
    pub(super) plan: CurrentAttachmentSourcePlanV1,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    deadline_boottime_nanoseconds: u64,
    body: Vec<u8>,
    body_without_deadline: Vec<u8>,
    semantics: CanonicalMountSourceAcquisitionSemanticsV1,
}

/// Retains exact Acquire bytes after independently signed Mount-plan binding.
#[must_use = "durably admit the bound source request before broker I/O"]
pub struct PreparedCurrentAttachmentSourceDispatchV1 {
    prepared: PreparedCurrentAttachmentSourceAcquireV1,
    template: BrokerDispatchTemplateV1,
}

/// Retains one exact current Mount source Release request before signing.
#[must_use = "bind an independent Mount plan and durably admit Release before broker I/O"]
pub struct PreparedCurrentAttachmentSourceReleaseV1 {
    plan: CurrentAttachmentSourcePlanV1,
    operation_id: OperationId,
    request_digest: ObjectDigest,
    deadline_boottime_nanoseconds: u64,
    body: Vec<u8>,
    body_without_deadline: Vec<u8>,
    semantics: CanonicalMountSourceAcquisitionSemanticsV1,
}

/// Retains exact Release bytes after independent Mount-plan binding.
#[must_use = "durably admit the bound Release request before broker I/O"]
pub struct PreparedCurrentAttachmentSourceReleaseDispatchV1 {
    prepared: PreparedCurrentAttachmentSourceReleaseV1,
    template: BrokerDispatchTemplateV1,
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
        source_plan_at(
            journal,
            &self.plan,
            &self.semantics,
            &self.body_without_deadline,
            mount_revocation_scope,
            clock,
        )
    }

    /// Binds an independently signed Mount plan to the exact Acquire template.
    ///
    /// # Errors
    ///
    /// Rejects stale Host or ownership authority, a wrong Mount signature,
    /// revocation scope, grant, or canonical request template.
    pub fn bind_signed_plan<T>(
        self,
        journal: &mut Journal,
        signed_plan: SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<PreparedCurrentAttachmentSourceDispatchV1, AttachmentSourceError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.plan.recheck(journal, clock)?;
        self.plan
            .target
            .runtime_generation()
            .scope()
            .verify_mount_plan_version(
                journal,
                &signed_plan,
                aos_sandbox_core::ProtocolVersion::new(2, 0),
                clock,
            )?;
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            self.semantics.verb(),
            self.semantics.target(),
            self.semantics.commitment(),
        );
        let template = BrokerDispatchTemplateV1::new(
            signed_plan,
            BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE,
            self.body_without_deadline.clone(),
            Vec::new(),
            semantics,
        )?;
        self.plan.recheck(journal, clock)?;
        Ok(PreparedCurrentAttachmentSourceDispatchV1 {
            prepared: self,
            template,
        })
    }
}

fn source_plan_at<T>(
    journal: &mut Journal,
    current: &CurrentAttachmentSourcePlanV1,
    semantics: &CanonicalMountSourceAcquisitionSemanticsV1,
    body_without_deadline: &[u8],
    mount_revocation_scope: RevocationScopeId,
    clock: &mut T,
) -> Result<BrokerAuthorizationPlan, AttachmentSourceError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    current.recheck(journal, clock)?;
    let scope = current.target.runtime_generation().scope();
    let (lease, fresh) = scope.verified_plan_lease(journal, clock)?;
    let manifest = scope.binding().manifest().manifest();
    // Budget the maximum encoded deadline field, not only this request's varint.
    let request_bytes = body_without_deadline
        .len()
        .checked_add(11)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(AttachmentSourceError::Capacity)?;
    let grant = BrokerGrant::new(
        semantics.verb(),
        semantics.target(),
        semantics.commitment(),
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
    current.recheck(journal, clock)?;
    Ok(plan)
}

impl PreparedCurrentAttachmentSourceDispatchV1 {
    /// Atomically custodies exact Acquire intent and its signed Mount packet.
    ///
    /// The returned live token is the only warm-path dispatch input. Neither
    /// a recovered packet nor a durable source attempt alone can create it.
    ///
    /// # Errors
    ///
    /// Rejects changed source, Host, ownership or Mount authority; a mismatched
    /// attempt body; predecessor conflict; or any failed protected commit.
    pub fn admit_current<T>(
        self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<DurableCurrentAttachmentSourceDispatchV1, AttachmentSourceError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.prepared.plan.recheck(journal, clock)?;
        let deadline = self.prepared.deadline_boottime_nanoseconds;
        let scope = self.prepared.plan.target.runtime_generation().scope();
        let dispatch = scope.prepare_mount_attempt_version(
            journal,
            &self.template,
            deadline,
            aos_sandbox_core::ProtocolVersion::new(2, 0),
            clock,
        )?;
        if dispatch.body() != self.prepared.body
            || dispatch.deadline_boottime_nanoseconds() != deadline
        {
            return Err(AttachmentSourceError::Conflict);
        }
        let predecessor =
            custody::current_predecessor(journal, self.prepared.plan.plan.attachment_id)?;
        let (source, sidecar) = custody::record_current_attempt_with_dispatch(
            journal,
            &self.prepared.plan,
            AttachmentSourceAttemptKindV1::Acquire,
            self.prepared.operation_id,
            self.prepared.request_digest,
            self.prepared.body,
            None,
            predecessor,
            Some(dispatch.packet().to_vec()),
            clock,
        )?;
        if sidecar.is_none() {
            return Err(AttachmentSourceError::CorruptState);
        }
        let live = dispatch_custody::live_dispatch(
            source,
            dispatch,
            self.prepared.plan.target,
            self.prepared.plan.desired,
        );
        live.recheck(journal, clock)?;
        Ok(live)
    }
}

impl PreparedCurrentAttachmentSourceReleaseV1 {
    /// Returns the exact Release operation ID selected by the Mount session.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Borrows the exact canonical Release request body.
    #[must_use]
    pub fn exact_request_body(&self) -> &[u8] {
        &self.body
    }

    /// Builds the independent Mount-only plan for the exact Release grant.
    ///
    /// # Errors
    ///
    /// Rejects changed source or ownership authority and invalid grant bounds.
    pub fn plan_at<T>(
        &self,
        journal: &mut Journal,
        mount_revocation_scope: RevocationScopeId,
        clock: &mut T,
    ) -> Result<BrokerAuthorizationPlan, AttachmentSourceError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        source_plan_at(
            journal,
            &self.plan,
            &self.semantics,
            &self.body_without_deadline,
            mount_revocation_scope,
            clock,
        )
    }

    /// Binds an independently signed Mount plan to the exact Release request.
    ///
    /// # Errors
    ///
    /// Rejects changed authority, a wrong Mount signature, scope, grant, or
    /// canonical request template.
    pub fn bind_signed_plan<T>(
        self,
        journal: &mut Journal,
        signed_plan: SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<PreparedCurrentAttachmentSourceReleaseDispatchV1, AttachmentSourceError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.plan.recheck(journal, clock)?;
        self.plan
            .target
            .runtime_generation()
            .scope()
            .verify_mount_plan_version(
                journal,
                &signed_plan,
                aos_sandbox_core::ProtocolVersion::new(2, 0),
                clock,
            )?;
        let semantics = BrokerDispatchSemanticIdentityV1::new(
            self.semantics.verb(),
            self.semantics.target(),
            self.semantics.commitment(),
        );
        let template = BrokerDispatchTemplateV1::new(
            signed_plan,
            BrokerMethod::BROKER_METHOD_MOUNT_RELEASE_SOURCE_ACQUISITION,
            self.body_without_deadline.clone(),
            Vec::new(),
            semantics,
        )?;
        self.plan.recheck(journal, clock)?;
        Ok(PreparedCurrentAttachmentSourceReleaseDispatchV1 {
            prepared: self,
            template,
        })
    }
}

impl PreparedCurrentAttachmentSourceReleaseDispatchV1 {
    /// Atomically custodies the exact Release intent and signed Mount packet.
    ///
    /// # Errors
    ///
    /// Rejects stale authority, an exact packet mismatch, predecessor conflict,
    /// or any failed protected commit and readback.
    pub fn admit_current<T>(
        self,
        journal: &mut Journal,
        clock: &mut T,
    ) -> Result<DurableCurrentAttachmentSourceDispatchV1, AttachmentSourceError>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.prepared.plan.recheck(journal, clock)?;
        let deadline = self.prepared.deadline_boottime_nanoseconds;
        let scope = self.prepared.plan.target.runtime_generation().scope();
        let dispatch = scope.prepare_mount_attempt_version(
            journal,
            &self.template,
            deadline,
            aos_sandbox_core::ProtocolVersion::new(2, 0),
            clock,
        )?;
        if dispatch.body() != self.prepared.body
            || dispatch.deadline_boottime_nanoseconds() != deadline
        {
            return Err(AttachmentSourceError::Conflict);
        }
        let predecessor =
            custody::current_predecessor(journal, self.prepared.plan.plan.attachment_id)?;
        let (source, sidecar) = custody::record_current_attempt_with_dispatch(
            journal,
            &self.prepared.plan,
            AttachmentSourceAttemptKindV1::Release,
            self.prepared.operation_id,
            self.prepared.request_digest,
            self.prepared.body,
            None,
            predecessor,
            Some(dispatch.packet().to_vec()),
            clock,
        )?;
        if sidecar.is_none() {
            return Err(AttachmentSourceError::CorruptState);
        }
        let live = dispatch_custody::live_dispatch(
            source,
            dispatch,
            self.prepared.plan.target,
            self.prepared.plan.desired,
        );
        live.recheck(journal, clock)?;
        Ok(live)
    }
}

pub(crate) fn prepare_current_release<T>(
    journal: &mut Journal,
    plan: CurrentAttachmentSourcePlanV1,
    operation_id: OperationId,
    deadline_boottime_nanoseconds: u64,
    clock: &mut T,
) -> Result<PreparedCurrentAttachmentSourceReleaseV1, AttachmentSourceError>
where
    T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
{
    let AttachmentSourceActionV1::Release {
        acquisition_id,
        revision,
        record_digest,
    } = plan.action
    else {
        return Err(AttachmentSourceError::Conflict);
    };
    if operation_id.as_bytes() == &[0; 16] {
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
    let request = ReleaseMountSourceAcquisitionRequest {
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
        acquisition_id: acquisition_id.to_vec(),
        expected_revision: revision,
        expected_record_digest: record_digest.to_vec(),
        ..Default::default()
    };
    let body = request.encode_to_vec();
    let mut deadline_free = request;
    deadline_free
        .header
        .get_or_insert_default()
        .deadline_boottime_nanoseconds = 0;
    let body_without_deadline = deadline_free.encode_to_vec();
    if crate::dispatch::durable_attempt_body(&body_without_deadline, deadline_boottime_nanoseconds)
        .map_err(|_| AttachmentSourceError::Protocol)?
        != body
    {
        return Err(AttachmentSourceError::Protocol);
    }
    let peer = PeerCredentials {
        uid: 1,
        gid: 1,
        pid: Some(1),
    };
    let validated = decode_release_mount_source_acquisition_request(
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
    let semantics = canonical_release_mount_source_acquisition_semantics_v1(validated.request())
        .map_err(|_| AttachmentSourceError::Protocol)?;
    plan.recheck(journal, clock)?;
    Ok(PreparedCurrentAttachmentSourceReleaseV1 {
        plan,
        operation_id,
        request_digest: validated.request_digest(),
        deadline_boottime_nanoseconds,
        body,
        body_without_deadline,
        semantics,
    })
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
        deadline_boottime_nanoseconds,
        body,
        body_without_deadline,
        semantics,
    })
}
