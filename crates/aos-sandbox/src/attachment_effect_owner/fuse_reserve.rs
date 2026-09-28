//! Holds the real Controller writer through exact purpose-57 plan issuance.
//!
//! A borrow joins current desired Attachment/View/slot state, the original
//! namespace allocation, and retained Host runtime observation. Canonical
//! request coordinates remain comparison data until that join succeeds.
//! Signing and authenticated durable dispatch remain separate steps; this
//! borrow is not a connected Mount worker or a content-read permission.

use std::path::Path;

use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
    BrokerPlanRequest, FeatureRef, InvalidBrokerAuthorizationPlan,
    MOUNT_FUSE_PRESENTATION_FEATURE_NAMESPACE, ProtocolId, ProtocolVersion, RawPairedClockSample,
};
use aos_sandbox_protocol::mount_fuse_reserve_intent::ValidatedFuseReserveIntentRequestV1;
use aos_sandbox_protocol::semantics::mount_fuse_reserve_intent::{
    CanonicalMountFuseReserveIntentSemanticsV1, MountFuseReserveIntentSemanticErrorV1,
    canonical_mount_fuse_reserve_intent_semantics_v1,
};

use super::{PreparedCurrentFuseReserveIntentV1, ProtectedAttachmentEffectOwnerV1};
use crate::attachment_state::{self, AttachmentDesiredStateError};
use crate::ownership_authority::ProtectedOwnershipClockError;
use crate::runtime_scope::{CurrentRuntimeScopeError, NamespaceTargetError};
use crate::{Journal, JournalError, JournalLimits, SignedBrokerPlan};

const CONTROLLER_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";

mod host_worker;
#[cfg(test)]
mod host_worker_tests;

/// Reports refusal of a changed owner, request, original source or live scope.
#[derive(Debug, thiserror::Error)]
pub enum ControllerFuseIntentDispatchErrorV1 {
    /// The exact fixed Controller writer or its current names failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Current original Attachment, View, slot or accepted lease failed.
    #[error(transparent)]
    Desired(#[from] AttachmentDesiredStateError),
    /// The retained namespace allocation no longer matches current state.
    #[error(transparent)]
    Namespace(#[from] NamespaceTargetError),
    /// Signed assignment, ownership or physical Host custody is stale.
    #[error(transparent)]
    Runtime(#[from] CurrentRuntimeScopeError),
    /// The exact existing Host-scope query is not granted or cannot be encoded.
    #[error(transparent)]
    HostScope(#[from] crate::mount_preparation::MountCatalogPreparationError),
    /// Complete canonical intent semantics cannot be represented.
    #[error(transparent)]
    Semantics(#[from] MountFuseReserveIntentSemanticErrorV1),
    /// The independent signed purpose-57 grant failed structural validation.
    #[error(transparent)]
    Plan(#[from] InvalidBrokerAuthorizationPlan),
    /// Request bytes, coordinates or deadline differ from the held original cut.
    #[error("FUSE request does not match the current original Controller cut")]
    CurrentMismatch,
}

/// Keeps exact Controller custody through signing and pending dispatch.
///
/// This move-only token owns no worker, Mount reservation or Root read guard.
/// It cannot be reconstructed from a signed plan or desired-record digest.
/// The associated session must durably retain its original RequestPrepared
/// before sending; a lost reply preserves that request and Mount obligations.
/// Accepted resource lifetime comes from current desired ownership, not the
/// initiating public caller's capability/session or this dispatch deadline.
#[must_use = "retain Controller custody through signing and exact pending dispatch"]
pub struct CurrentControllerFuseIntentDispatchV1<'owner> {
    journal: &'owner mut Journal,
    prepared: PreparedCurrentFuseReserveIntentV1,
    request: ValidatedFuseReserveIntentRequestV1,
    body: Vec<u8>,
    semantics: CanonicalMountFuseReserveIntentSemanticsV1,
    owner_uid: u32,
    sequence: u64,
}

impl ProtectedAttachmentEffectOwnerV1<'_> {
    /// Holds exact current FUSE intent while borrowing the fixed Controller writer.
    ///
    /// The prepared intent must originate from current protected desired state
    /// and a live Host-bound namespace target. This method compares every
    /// request coordinate with those actual retained owners, not with a second
    /// caller-selected digest bundle.
    ///
    /// # Errors
    ///
    /// Rejects another journal, changed desired/source/slot/namespace state,
    /// stale Host or ownership lease, substituted bytes and extended deadlines.
    pub fn hold_current_fuse_reserve_intent<'owner, T>(
        &'owner mut self,
        prepared: PreparedCurrentFuseReserveIntentV1,
        request: ValidatedFuseReserveIntentRequestV1,
        body: Vec<u8>,
        clock: &mut T,
    ) -> Result<CurrentControllerFuseIntentDispatchV1<'owner>, ControllerFuseIntentDispatchErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let owner_uid = self.journal.protected_owner_uid()?;
        require_controller(self.journal, owner_uid)?;
        let semantics = canonical_mount_fuse_reserve_intent_semantics_v1(&request)?;
        let sequence = self.journal.snapshot_sequence();
        let mut held = CurrentControllerFuseIntentDispatchV1 {
            journal: self.journal,
            prepared,
            request,
            body,
            semantics,
            owner_uid,
            sequence,
        };
        held.recheck(clock)?;
        Ok(held)
    }
}

impl CurrentControllerFuseIntentDispatchV1<'_> {
    /// Prepares the original Host query while retaining this Controller writer.
    ///
    /// This reuses only an already-authorized exact ObserveMountScope grant.
    /// No signer, RPC callback, successor deadline or replacement assignment
    /// is introduced. Mount must independently authenticate the actual Host
    /// reply and retain its descriptors before its lower preparation producer.
    /// The returned bytes are an artifact carrier, not a live Mount/Root guard.
    ///
    /// # Errors
    ///
    /// Rejects stale original desired/runtime custody, a missing exact existing
    /// Host grant, malformed query coordinates or an expired original deadline.
    pub fn original_host_scope_packet_at<T>(
        &mut self,
        clock: &mut T,
    ) -> Result<Vec<u8>, ControllerFuseIntentDispatchErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.recheck(clock)?;
        let packet = crate::mount_preparation::prepare_current_host_scope_packet(
            self.journal,
            &self.prepared.target,
            *self.request.header().request_id(),
            self.request.header().deadline_boottime_nanoseconds(),
            clock,
        )?;
        self.recheck(clock)?;
        Ok(packet)
    }

    /// Borrows the exact original body; it conveys no remote effect authority.
    #[must_use]
    pub fn request_body(&self) -> &[u8] {
        &self.body
    }

    /// Borrows full canonical intent/request comparison semantics.
    #[must_use]
    pub const fn semantics(&self) -> &CanonicalMountFuseReserveIntentSemanticsV1 {
        &self.semantics
    }

    /// Borrows the exact structural request solely for authenticated cross-links.
    #[must_use]
    pub const fn request(&self) -> &ValidatedFuseReserveIntentRequestV1 {
        &self.request
    }

    /// Rechecks the fixed writer, exact current original resources and Host scope.
    ///
    /// # Errors
    ///
    /// Rejects physical writer replacement, changed journal sequence, stale
    /// namespace/Host/ownership, released or replaced source state, substituted
    /// request coordinates, expired dispatch and expanded resource lease.
    pub fn recheck<T>(&mut self, clock: &mut T) -> Result<(), ControllerFuseIntentDispatchErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        require_controller(self.journal, self.owner_uid)?;
        if self.journal.snapshot_sequence() != self.sequence {
            return Err(ControllerFuseIntentDispatchErrorV1::CurrentMismatch);
        }
        let target = &self.prepared.target;
        let desired = &self.prepared.desired;
        target.recheck(self.journal, clock)?;
        attachment_state::validate_target(target, desired.intent())?;
        let scope = target.runtime_generation().scope();
        let (now, lease_limit) = scope.attachment_lease_bounds(self.journal, clock)?;
        attachment_state::validate_current_fuse_reserve_source(self.journal, desired, now)?;

        let observed = scope.observed();
        if self.request.intent() != desired.intent()
            || self.request.desired_record_digest() != desired.record_digest().as_bytes()
            || self.request.namespace_target_generation() != target.target_generation()
            || self.request.namespace_allocation_digest() != target.allocation_digest()
            || self.request.runtime_handle() != observed.runtime_handle()
            || self.request.payload_scope_handle() != observed.payload_scope_handle()
            || self.request.fence() != observed.fence()
            || self.request.accepted_policy() != scope.binding().manifest().manifest().policy()
            || self.request.header().deadline_boottime_nanoseconds()
                > observed.request_deadline_boottime_nanoseconds()
            || desired.intent().lease().expires_seconds() > lease_limit
            || self.body.len()
                > aos_sandbox_core::MOUNT_FUSE_RESERVE_INTENT_MAXIMUM_REQUEST_BYTES_V1 as usize
            || BrokerArgumentCommitment::for_canonical_bytes(&self.body)
                .digest()
                .as_bytes()
                != self.request.request_commitment()
        {
            return Err(ControllerFuseIntentDispatchErrorV1::CurrentMismatch);
        }
        let (_, fresh) = scope.verified_plan_lease(self.journal, clock)?;
        if fresh.boottime_nanoseconds() >= self.request.header().deadline_boottime_nanoseconds() {
            return Err(ControllerFuseIntentDispatchErrorV1::CurrentMismatch);
        }
        target.recheck(self.journal, clock)?;
        require_controller(self.journal, self.owner_uid)?;
        Ok(())
    }

    /// Derives only the purpose-57 plan from the still-held current owner cut.
    ///
    /// Mount's revocation scope is taken from the scope's independently pinned
    /// deployment anchor. The result still requires the existing protected
    /// Controller signer, exact cryptographic rebind and durable session admission.
    ///
    /// # Errors
    ///
    /// Rejects changed resources, stale ownership or observation, and invalid
    /// plan bounds. It never extends the retained Host observation window.
    pub fn plan_at<T>(
        &mut self,
        clock: &mut T,
    ) -> Result<BrokerAuthorizationPlan, ControllerFuseIntentDispatchErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.recheck(clock)?;
        let scope = self.prepared.target.runtime_generation().scope();
        let (lease, fresh) = scope.verified_plan_lease(self.journal, clock)?;
        let manifest = scope.binding().manifest().manifest();
        let grant = BrokerGrant::new(
            self.semantics.verb(),
            self.semantics.target(),
            self.semantics.commitment(),
            u32::try_from(self.body.len())
                .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?,
            0,
        )?;
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Mount,
            ProtocolId::MountFuseBroker,
            ProtocolVersion::new(3, 0),
            scope
                .binding()
                .manifest()
                .broker_assignment()
                .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?,
            manifest.node(),
            lease.signer().clone(),
            vec![grant],
            manifest.policy().digest(),
            scope.mount_plan_revocation_scope(),
            fresh.wall_seconds(),
            scope
                .expires_wall_seconds()
                .min(self.prepared.desired.intent().lease().expires_seconds()),
            vec![
                FeatureRef::new(MOUNT_FUSE_PRESENTATION_FEATURE_NAMESPACE, 1, 0)
                    .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?,
            ],
        )?;
        self.recheck(clock)?;
        Ok(plan)
    }

    /// Verifies a signed exact FUSE plan without releasing Controller custody.
    ///
    /// # Errors
    ///
    /// Rejects a different signer, lease, assignment, request, protocol or grant,
    /// expired plan, or any changed current owner resource.
    pub fn verify_signed_plan<T>(
        &mut self,
        signed: &SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<(), ControllerFuseIntentDispatchErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.recheck(clock)?;
        self.prepared
            .target
            .runtime_generation()
            .scope()
            .verify_fuse_intent_plan(
                self.journal,
                signed,
                BrokerPlanRequest {
                    verb: self.semantics.verb(),
                    target: self.semantics.target(),
                    argument_commitment: self.semantics.commitment(),
                    request_bytes: u32::try_from(self.body.len())
                        .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?,
                    descriptor_count: 0,
                },
                clock,
            )?;
        self.recheck(clock)
    }

    /// Encodes the exact original signed request under current ownership custody.
    ///
    /// The authenticated session must still sign and durably reserve this
    /// envelope. No worker readiness or content permission follows from it.
    ///
    /// # Errors
    ///
    /// Rejects changed owner state, stale signature/lease or an invalid envelope.
    pub fn authorized_packet_at<T>(
        &mut self,
        signed: &SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<Vec<u8>, ControllerFuseIntentDispatchErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.verify_signed_plan(signed, clock)?;
        let (lease, _) = self
            .prepared
            .target
            .runtime_generation()
            .scope()
            .verified_plan_lease(self.journal, clock)?;
        let packet = aos_sandbox_protocol::session::encode_authorized_request_envelope(
            ProtocolId::MountFuseBroker,
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_MOUNT_FUSE_RESERVE_INTENT_V1,
            &self.body,
            &[],
            aos_sandbox_protocol::session::AuthorizationArtifactBytes {
                broker_plan: signed.canonical_plan(),
                broker_plan_signature: signed.canonical_signature(),
                ownership_lease: lease.canonical_lease(),
                ownership_lease_signature: lease.canonical_signature(),
            },
        ).map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?;
        self.recheck(clock)?;
        Ok(packet)
    }
}

fn require_controller(journal: &Journal, uid: u32) -> Result<(), JournalError> {
    journal.require_protected_named_location(
        Path::new(CONTROLLER_DIRECTORY),
        CONTROLLER_JOURNAL,
        uid,
        JournalLimits::default(),
    )
}
