//! Bridges protected lifecycle work to current broker authority.
//!
//! Lifecycle plans describe required effects but do not grant them.
//! The module selects an exact method-specific template from the protected
//! current runtime-authority publication, attenuates it with a fresh deadline,
//! and returns the request consumed by the authenticated session owner.

use aos_proto::aos::sandbox::local::v1::{
    ApplyAtomicStorageSnapshotRequest, AssignmentFence, Audience, BrokerMethod, RequestHeader,
    RuntimeAction,
};
use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerAudience, BrokerGrantTarget, BrokerVerb,
    CanonicalAssignmentManifestV1, NodeId, ObjectDigest, ProtocolVersion,
};
use aos_sandbox_protocol::semantics::ProtectedStorageCreatePreparationV1;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::lifecycle::{LifecycleAtomicDatasetSnapshotPlanV1, LiveRuntimeFenceV1};
use crate::runtime_authority::{
    RuntimeAuthorityLimits, RuntimeAuthorityStateV1, RuntimeAuthorityStore,
};
use crate::{
    AuthorityEffectAttemptTimingV1, AuthorityPublicationError, AuthorityPublicationProposalV1,
    AuthorityPublicationStore, BrokerDispatchSemanticIdentityV1, BrokerDispatchTemplateV1, Journal,
    PreparedAuthorityEffectV1, PreparedAuthorityPublicationV1, ReconcilerError,
    SignedOwnershipLease,
};
use aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan;

/// Owns an operation-specific Snapshot recipe, not dispatch or retention authority.
///
/// Construction joins genuine current lifecycle and runtime owners. Its original
/// deadline is never renewed. Completing the signed recipe does not bypass the
/// missing full Snapshot writer, Root, retention or mandatory-Thaw producers.
pub struct SnapshotDerivedStoragePreparationV3 {
    original: SnapshotSourceOriginalV3,
    plan: aos_sandbox_core::BrokerAuthorizationPlan,
    group: LifecycleAtomicDatasetSnapshotPlanV1,
    fence: LiveRuntimeFenceV1,
    timing: AuthorityEffectAttemptTimingV1,
    binding: ObjectDigest,
    publication: crate::publication::CurrentAuthorityPublicationV1,
    lease: SignedOwnershipLease,
    record: Option<DerivedSourceRecordV3>,
}

// Unbranded DATA shared only within this crate. Lifecycle's private A6 checker
// and source codec construct/check these through its existing store seam.
pub(crate) struct SnapshotSourceOriginalV3 {
    pub(crate) operation: [u8; 16],
    pub(crate) digests: [[u8; 32]; 11],
    pub(crate) admitted_operation: Vec<u8>,
}

pub(crate) struct DerivedSourceRecordV3 {
    pub(crate) stage: u8,
    pub(crate) operation: [u8; 16],
    pub(crate) digests: [[u8; 32]; 11],
    pub(crate) request_id: [u8; 16],
    pub(crate) clock: aos_sandbox_core::RawPairedClockSample,
    pub(crate) deadline: u64,
    pub(crate) original: [u8; 32],
    pub(crate) sections: [Vec<u8>; 12],
}

impl SnapshotDerivedStoragePreparationV3 {
    /// Borrows the one exact operation-specific plan for protected preparation.
    #[must_use]
    pub const fn plan(&self) -> &aos_sandbox_core::BrokerAuthorizationPlan { &self.plan }

    /// Compares a readback from the same original authenticated Session.
    ///
    /// # Errors
    ///
    /// Rejects a different immutable signed-hello/context checkpoint.
    pub fn require_checkpoint(&self, checkpoint: ObjectDigest) -> Result<(), ReconcilerError> {
        if checkpoint.as_bytes() != &self.original.digests[10] {
            return Err(ReconcilerError::InvalidPlan("Snapshot original Session changed"));
        }
        Ok(())
    }

    /// Checks a genuine later sample against the same original exclusive cut.
    ///
    /// # Errors
    ///
    /// Rejects clock discontinuity, expired original deadline or parent validity.
    pub fn check_clock(&self, clock: aos_sandbox_core::RawPairedClockSample) -> Result<(), ReconcilerError> {
        self.timing.clock().validate_later_sample(clock)
            .map_err(|_| ReconcilerError::InvalidPlan("Snapshot original clock changed"))?;
        if clock.boottime_nanoseconds() >= self.timing.deadline()
            || clock.wall_seconds() < self.plan.issued_seconds()
            || clock.wall_seconds() >= self.plan.expires_seconds()
        {
            return Err(ReconcilerError::InvalidPlan("Snapshot original deadline expired"));
        }
        Ok(())
    }

    /// Rejoins the original immutable admission and current runtime publication.
    ///
    /// # Errors
    ///
    /// Rejects changed current lifecycle, coordination, binding or publication.
    pub fn recheck(
        &self,
        journal: &mut Journal,
        current: &crate::lifecycle::CurrentLifecycleOperationV1<'_>,
        coordination: &crate::lifecycle::CurrentLifecycleCoordinationV1<'_>,
    ) -> Result<(), ReconcilerError> {
        self.original.require_current(current, coordination)
            .map_err(|_| ReconcilerError::InvalidPlan("Snapshot admitted source changed"))?;
        let binding = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())?
            .current(self.fence.sandbox())?
            .ok_or(ReconcilerError::InvalidPlan("Snapshot runtime binding is absent"))?;
        crate::reconciler::runtime_authority_claim(journal, &binding)?;
        let publication = AuthorityPublicationStore::new(journal).current(self.fence.sandbox())?
            .ok_or(ReconcilerError::InvalidPlan("Snapshot publication is absent"))?;
        if binding.digest() != self.binding || publication != self.publication {
            return Err(ReconcilerError::InvalidPlan("Snapshot original runtime cut changed"));
        }
        Ok(())
    }

    /// Prices the complete four-stage native suffix before retaining unsigned originals.
    ///
    /// The future signature bytes are fixed-width nonissuing sizing DATA, never
    /// a verified plan. Actual signed bytes are independently compiled later.
    ///
    /// # Errors
    ///
    /// Rejects a different signing recipe, retained source, protocol cap or any
    /// actual opened Journal bound, UUID, predecessor or NEXT exhaustion.
    pub fn prepare_unsigned_original(
        &mut self,
        journal: &Journal,
        preparation: &aos_sandbox_protocol::authorization_artifact::BrokerPlanPreparation,
        predecessor_packet: &[u8],
    ) -> Result<(), ReconcilerError> {
        use aos_sandbox_core::format::{encode_broker_authorization_plan, encode_signature};
        use aos_sandbox_core::model::{Signature, SignatureBytes};
        if self.record.is_some()
            || preparation.canonical_plan() != encode_broker_authorization_plan(&self.plan)
            || journal.get(crate::RecordNamespace::LifecycleAtomicSnapshotSource, &self.original.operation).is_some()
            || Sha256::digest(predecessor_packet)[..] == [0; 32]
        {
            return Err(ReconcilerError::InvalidPlan("Snapshot unsigned original is occupied or changed"));
        }
        let group = self.group.canonical_wire_bytes()
            .map_err(|_| ReconcilerError::InvalidPlan("Snapshot group is invalid"))?;
        let lease = &self.lease;
        let record = DerivedSourceRecordV3::new(journal, &self.original,
            self.timing.clock(), self.timing.deadline(), [
                &self.original.admitted_operation, &group, predecessor_packet,
                preparation.canonical_plan(), preparation.signing_request().canonical_statement(),
                lease.canonical_lease(), lease.canonical_signature(),
                lease.canonical_receipt(), lease.canonical_receipt_signature(), &[], &[], &[],
            ]).map_err(|_| ReconcilerError::InvalidPlan("Snapshot original record exceeds opened bounds"))?;
        let seed = record.digest();

        // Only byte geometry is predicted. No SignedBrokerPlan or currentness
        // brand is fabricated from this nonissuing signature-shaped DATA.
        let signature_shape = encode_signature(&Signature::new(
            preparation.signing_request().statement().clone(), SignatureBytes::new([0; 64]),
        ));
        let body_shape = atomic_snapshot_request_body(group, self.fence, [1; 16], 0).encode_to_vec();
        let mut request_shape = ApplyAtomicStorageSnapshotRequest::decode_from_slice(&body_shape)
            .map_err(|_| ReconcilerError::InvalidPlan("Snapshot body shape is invalid"))?;
        request_shape.header.as_option_mut().ok_or(ReconcilerError::InvalidPlan("Snapshot header is absent"))?
            .deadline_boottime_nanoseconds = self.timing.deadline();
        let packet_shape = aos_sandbox_protocol::encode_authorized_request_envelope(
            aos_sandbox_core::ProtocolId::StorageBroker, BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT,
            &request_shape.encode_to_vec(), &[], aos_sandbox_protocol::AuthorizationArtifactBytes {
                broker_plan: preparation.canonical_plan(), broker_plan_signature: &signature_shape,
                ownership_lease: lease.canonical_lease(), ownership_lease_signature: lease.canonical_signature(),
            },
        ).map_err(|_| ReconcilerError::InvalidPlan("Snapshot complete request exceeds protocol bounds"))?;
        let transactions = crate::lifecycle::LifecycleAtomicSnapshotSourceStoreV1::derived_suffix_v3(
            journal, &record, &body_shape, &packet_shape,
        ).map_err(|_| ReconcilerError::InvalidPlan("Snapshot complete native suffix exceeds opened bounds"))?;
        for transaction in &transactions {
            let bytes = crate::journal::encoded_transaction_append_bytes(transaction)
                .map_err(crate::journal::JournalError::from)?;
            let value = transaction.records()[0].value()
                .ok_or(ReconcilerError::InvalidPlan("Snapshot suffix is not a PUT"))?;
            if bytes != 279 + value.len() as u64 {
                return Err(ReconcilerError::InvalidPlan("Snapshot native geometry changed"));
            }
        }
        journal.preflight_transactions(&transactions)?;
        if seed == [0; 32] { return Err(ReconcilerError::InvalidPlan("Snapshot original digest is zero")); }
        self.record = Some(record);
        Ok(())
    }

    /// Appends the exact unsigned original using the existing Journal engine.
    ///
    /// # Errors
    ///
    /// Rejects non-vacancy, changed originals or uncertain native I/O. The caller
    /// must retain this complete Result before any independent observations.
    pub fn append_unsigned_original(&self, journal: &mut Journal)
        -> Result<crate::journal::CommitResult, crate::lifecycle::LifecycleAtomicSnapshotSourceErrorV1>
    {
        let record = self.record.as_ref()
            .ok_or(crate::lifecycle::LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        if record.stage != 0 {
            return Err(crate::lifecycle::LifecycleAtomicSnapshotSourceErrorV1::Stale);
        }
        record.append(journal)
    }

    /// Compiles the actual completed signature into the original attenuated request.
    ///
    /// # Errors
    ///
    /// Rejects a changed plan, lease, deadline or actual canonical request.
    pub fn complete_signed_original(&mut self, journal: &Journal, signed: SignedBrokerPlan)
        -> Result<PreparedAuthorityEffectV1, ReconcilerError>
    {
        if signed.plan() != &self.plan {
            return Err(ReconcilerError::InvalidPlan("Snapshot completed plan differs"));
        }
        let template = compile_atomic_storage_lifecycle_template_v1(&self.group, self.fence, signed)?;
        let attempt = crate::BrokerDispatchAttemptV1::new(&template, &self.lease,
            self.timing.deadline(), self.timing.clock())
            .map_err(|_| ReconcilerError::InvalidPlan("Snapshot original lease attenuation failed"))?;
        let authority = PreparedAuthorityEffectV1::new(self.binding, self.publication.digest(), self.timing.clock(), attempt);
        let request = authority.broker_request()?;
        let record = self.record.as_mut().ok_or(ReconcilerError::InvalidPlan("Snapshot unsigned original is absent"))?;
        record.retain_signed_original(
            journal, request.request_id(), template.body_without_deadline(), authority.attempt().packet(),
        ).map_err(|_| ReconcilerError::InvalidPlan("Snapshot actual signed originals exceed opened bounds"))?;
        Ok(authority)
    }

    /// Appends actual signed originals without dispatching Storage.
    ///
    /// # Errors
    ///
    /// Rejects a changed unsigned predecessor, codec bounds or native failure.
    pub fn append_signed_original(&self, journal: &mut Journal)
        -> Result<crate::journal::CommitResult, crate::lifecycle::LifecycleAtomicSnapshotSourceErrorV1>
    {
        let record = self.record.as_ref().ok_or(crate::lifecycle::LifecycleAtomicSnapshotSourceErrorV1::Stale)?;
        if record.stage != 1 { return Err(crate::lifecycle::LifecycleAtomicSnapshotSourceErrorV1::Stale); }
        record.append(journal)
    }
}

/// Joins the genuine admitted Snapshot source to a same-assignment derived recipe.
///
/// This prerequisite neither changes the current publication nor grants Freeze,
/// dispatch, retention, semantic commit or public Snapshot completion.
///
/// # Errors
///
/// Rejects missing A6 lineage, stale runtime authority, ambiguous Storage parent,
/// another original inventory/session or an independently unverifiable lease.
#[allow(clippy::too_many_arguments)]
pub fn prepare_snapshot_derived_storage_v3(
    journal: &mut Journal,
    node: NodeId,
    current: &crate::lifecycle::CurrentLifecycleOperationV1<'_>,
    coordination: &crate::lifecycle::CurrentLifecycleCoordinationV1<'_>,
    barrier: &crate::lifecycle::LifecycleSnapshotBarrierV1,
    group: &LifecycleAtomicDatasetSnapshotPlanV1,
    predecessor: &crate::lifecycle::LifecycleAuthenticatedStorageInventoryV1,
    predecessor_outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    checkpoint: ObjectDigest,
    timing: AuthorityEffectAttemptTimingV1,
    verifier: &crate::OwnershipAuthorityVerifier,
) -> Result<SnapshotDerivedStoragePreparationV3, ReconcilerError> {
    use aos_sandbox_core::{BrokerGrant, BrokerAuthorizationPlan};
    let fence = coordination.coordination().transaction().live_fence();
    let mut original = crate::lifecycle::LifecycleAtomicSnapshotSourceStoreV1::capture_original_v3(current, coordination)
        .map_err(|_| ReconcilerError::InvalidPlan("Snapshot immutable admission is absent"))?;
    if barrier.atomic_dataset_snapshot_plan(current, predecessor)
        .map_err(|_| ReconcilerError::InvalidPlan("Snapshot current group differs"))? != *group
        || !crate::lifecycle::LifecycleAtomicSnapshotSourceStoreV1::same_original_inventory_v3(
            predecessor_outcome, predecessor,
        ).map_err(|_| ReconcilerError::InvalidPlan("Snapshot signed predecessor is invalid"))?
        || checkpoint.as_bytes() == &[0; 32]
    {
        return Err(ReconcilerError::InvalidPlan("Snapshot original inventory differs"));
    }
    let binding = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())?
        .current(fence.sandbox())?.ok_or(ReconcilerError::InvalidPlan("Snapshot runtime authority is absent"))?;
    let manifest = binding.manifest().manifest();
    if binding.state() != RuntimeAuthorityStateV1::Bound || manifest.node() != node
        || manifest.sandbox() != fence.sandbox() || manifest.incarnation() != fence.incarnation()
        || manifest.epoch() != fence.assignment_epoch() || manifest.namespace_generation() != fence.namespace_generation()
        || manifest.desired_generation() != fence.desired().expected_generation()
        || binding.assignment_digest().as_bytes() != fence.desired().resource_state().digest().as_bytes()
    { return Err(ReconcilerError::InvalidPlan("Snapshot current assignment differs")); }
    let claim = crate::reconciler::runtime_authority_claim(journal, &binding)?;
    let publication = AuthorityPublicationStore::new(journal).current(fence.sandbox())?
        .ok_or(ReconcilerError::InvalidPlan("Snapshot current publication is absent"))?;
    if publication.digest() != binding.publication_digest()
        || publication.lease_generation() != binding.lease_generation()
        || publication.lease_digest() != binding.lease_digest()
    { return Err(ReconcilerError::InvalidPlan("Snapshot binding/publication differs")); }
    let lease_bytes = publication.lease();
    let response = crate::UnverifiedOwnershipLeaseResponse::from_transport(
        lease_bytes.canonical_lease().to_vec(), lease_bytes.canonical_signature().to_vec(),
        lease_bytes.canonical_receipt().to_vec(), lease_bytes.canonical_receipt_signature().to_vec(),
    ).map_err(|_| ReconcilerError::InvalidPlan("Snapshot original lease quartet is invalid"))?;
    let lease = verifier.verify_response(&claim, response, &timing.clock())
        .map_err(|_| ReconcilerError::InvalidPlan("Snapshot original lease is not current"))?;
    let assignment = binding.manifest().broker_assignment()
        .map_err(|_| ReconcilerError::InvalidPlan("Snapshot assignment is invalid"))?;
    let mut parents = publication.templates().iter().filter(|template| {
        template.audience() == BrokerAudience::Storage && template.plan().assignment() == assignment
            && template.plan().node() == node && template.plan().protocol_version() == ProtocolVersion::new(1, 0)
            && template.plan().ownership_authority() == lease.signer()
    });
    let parent = parents.next().ok_or(ReconcilerError::InvalidPlan("Snapshot Storage parent is absent"))?;
    if parents.next().is_some() { return Err(ReconcilerError::InvalidPlan("Snapshot Storage parent is ambiguous")); }
    let parent = parent.plan();
    let group_bytes = group.canonical_wire_bytes().map_err(|_| ReconcilerError::InvalidPlan("Snapshot group is invalid"))?;
    let grant = BrokerGrant::new(BrokerVerb::StorageAtomicSnapshot, BrokerGrantTarget::Assignment,
        BrokerArgumentCommitment::for_canonical_bytes(&group_bytes),
        u32::try_from(aos_sandbox_protocol::MAXIMUM_REQUEST_BYTES)
            .map_err(|_| ReconcilerError::InvalidPlan("Snapshot body ceiling is invalid"))?, 0)
        .map_err(|_| ReconcilerError::InvalidPlan("Snapshot exact grant is invalid"))?;
    let plan = BrokerAuthorizationPlan::new(BrokerAudience::Storage, aos_sandbox_core::ProtocolId::StorageBroker,
        ProtocolVersion::new(1, 0), assignment, node, parent.ownership_authority().clone(), vec![grant],
        parent.policy_commitment(), parent.revocation_scope(), parent.issued_seconds(), parent.expires_seconds(),
        parent.required_features().to_vec())
        .map_err(|_| ReconcilerError::InvalidPlan("Snapshot derived recipe is invalid"))?;
    original.digests[4] = *binding.digest().as_bytes();
    original.digests[5] = *publication.digest().as_bytes();
    original.digests[6] = *binding.source_draft_digest().as_bytes();
    original.digests[7] = *group.commitment().as_bytes();
    original.digests[8] = *predecessor.commitment().as_bytes();
    original.digests[9] = *predecessor.session().as_bytes();
    original.digests[10] = *checkpoint.as_bytes();
    let prepared = SnapshotDerivedStoragePreparationV3 {
        original, plan, group: group.clone(), fence, timing, binding: binding.digest(), publication, lease, record: None,
    };
    prepared.check_clock(timing.clock())?;
    Ok(prepared)
}

/// Reports plan compilation or complete publication validation failure.
#[derive(Debug, thiserror::Error)]
pub enum AtomicStorageLifecyclePublicationErrorV1 {
    /// The canonical lifecycle group could not be compiled for the signed plan.
    #[error("atomic Storage lifecycle template is invalid: {0}")]
    Template(#[from] ReconcilerError),
    /// The resulting complete authority publication is invalid.
    #[error("atomic Storage lifecycle publication is invalid: {0}")]
    Publication(#[from] AuthorityPublicationError),
}

/// Produces a complete authority publication containing the exact Storage group.
///
/// This keeps the snapshot template in the same signed assignment publication
/// as its companion broker templates. The publication store must still commit
/// the prepared value, and brokers independently verify its signed artifacts.
///
/// # Errors
///
/// Returns [`AtomicStorageLifecyclePublicationErrorV1`] if the group cannot be
/// compiled or the complete publication has incomplete or inconsistent grants.
#[allow(clippy::too_many_arguments)]
pub fn prepare_atomic_storage_lifecycle_publication_v1(
    manifest: CanonicalAssignmentManifestV1,
    lease: SignedOwnershipLease,
    mut required_audiences: Vec<BrokerAudience>,
    mut companion_templates: Vec<BrokerDispatchTemplateV1>,
    plan: &LifecycleAtomicDatasetSnapshotPlanV1,
    fence: LiveRuntimeFenceV1,
    signed_storage_plan: SignedBrokerPlan,
) -> Result<PreparedAuthorityPublicationV1, AtomicStorageLifecyclePublicationErrorV1> {
    let group = compile_atomic_storage_lifecycle_template_v1(plan, fence, signed_storage_plan)?;
    required_audiences.sort_unstable();
    companion_templates.push(group);
    companion_templates.sort_unstable_by_key(|template| {
        (template.signed_plan().plan().audience(), template.digest())
    });
    AuthorityPublicationProposalV1::new(manifest, lease, required_audiences, companion_templates)
        .prepare()
        .map_err(Into::into)
}

/// Compiles one exact grouped Storage request into a signed publication template.
///
/// The request ID is stable for the inventory-derived plan and exact signed
/// authority. A changed predecessor or grant selects a different ID rather
/// than aliasing an earlier attempt. This compiler does not publish or dispatch
/// the template; the source-domain controller must durably retain and recover
/// its exact attempt before the Storage method can be activated.
///
/// # Errors
///
/// Returns [`ReconcilerError`] when the plan cannot be encoded, its root target
/// differs from the live fence, or the signed Storage grant does not bind the
/// same assignment, protocol, and complete plan commitment.
pub fn compile_atomic_storage_lifecycle_template_v1(
    plan: &LifecycleAtomicDatasetSnapshotPlanV1,
    fence: LiveRuntimeFenceV1,
    signed_plan: SignedBrokerPlan,
) -> Result<BrokerDispatchTemplateV1, ReconcilerError> {
    let assignment = signed_plan.plan().assignment();
    let desired = fence.desired();
    if plan.target_sandbox() != fence.sandbox()
        || signed_plan.plan().audience() != BrokerAudience::Storage
        || signed_plan.plan().protocol_version() != ProtocolVersion::new(1, 0)
        || assignment.sandbox() != fence.sandbox()
        || assignment.incarnation() != fence.incarnation()
        || assignment.epoch() != fence.assignment_epoch()
        || assignment.desired_generation() != desired.expected_generation()
        || assignment.digest().as_bytes() != desired.resource_state().digest().as_bytes()
    {
        return Err(ReconcilerError::InvalidPlan(
            "atomic Storage template differs from its signed assignment",
        ));
    }

    let canonical_plan = plan
        .canonical_wire_bytes()
        .map_err(|_| ReconcilerError::InvalidPlan("atomic Storage plan is invalid"))?;
    let request_digest = Sha256::new()
        .chain_update(b"aos.sandbox.storage.atomic-snapshot-request-id.v1\0")
        .chain_update(plan.commitment().as_bytes())
        .chain_update(signed_plan.digest().as_bytes())
        .chain_update((signed_plan.canonical_signature().len() as u64).to_be_bytes())
        .chain_update(signed_plan.canonical_signature())
        .finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&request_digest[..16]);
    if request_id == [0; 16] {
        return Err(ReconcilerError::InvalidPlan(
            "atomic Storage request ID is invalid",
        ));
    }

    let semantics = BrokerDispatchSemanticIdentityV1::new(
        BrokerVerb::StorageAtomicSnapshot,
        BrokerGrantTarget::Assignment,
        BrokerArgumentCommitment::for_canonical_bytes(&canonical_plan),
    );
    let body = atomic_snapshot_request_body(canonical_plan, fence, request_id, 0);
    BrokerDispatchTemplateV1::new(
        signed_plan,
        BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT,
        body.encode_to_vec(),
        Vec::new(),
        semantics,
    )
    .map_err(|_| ReconcilerError::InvalidPlan("atomic Storage template grant is invalid"))
}

fn atomic_snapshot_request_body(
    canonical_plan: Vec<u8>,
    fence: LiveRuntimeFenceV1,
    request_id: [u8; 16],
    deadline: u64,
) -> ApplyAtomicStorageSnapshotRequest {
    let desired = fence.desired();
    ApplyAtomicStorageSnapshotRequest {
        header: Some(RequestHeader {
            protocol_major: 1,
            protocol_minor: 0,
            request_id: request_id.to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: deadline,
            maximum_response_bytes: 4096,
            ..Default::default()
        })
        .into(),
        canonical_plan,
        fence: Some(AssignmentFence {
            sandbox_id: fence.sandbox().as_bytes().to_vec(),
            incarnation_id: fence.incarnation().as_bytes().to_vec(),
            assignment_epoch: fence.assignment_epoch().get(),
            desired_generation: desired.expected_generation().get(),
            assignment_digest: desired.resource_state().digest().as_bytes().to_vec(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}

/// Compiles the protected Create preparation into one exact signed template.
///
/// This non-mutating template still requires a distinct signed Prepare grant.
/// Its result cannot authorize Apply; the controller must retain the signed
/// Prepare outcome and obtain a fresh independent Create Apply grant bound to
/// the broker-minted catalog.
///
/// # Errors
///
/// Returns [`ReconcilerError`] for a different current assignment or a signed
/// plan that does not grant this exact canonical preparation commitment.
pub fn compile_storage_create_preparation_template_v1(
    protected: &ProtectedStorageCreatePreparationV1,
    fence: LiveRuntimeFenceV1,
    signed_plan: SignedBrokerPlan,
) -> Result<BrokerDispatchTemplateV1, ReconcilerError> {
    let assignment = signed_plan.plan().assignment();
    let desired = fence.desired();
    if protected.assignment() != assignment
        || signed_plan.plan().audience() != BrokerAudience::Storage
        || signed_plan.plan().protocol_version() != ProtocolVersion::new(1, 0)
        || assignment.sandbox() != fence.sandbox()
        || assignment.incarnation() != fence.incarnation()
        || assignment.epoch() != fence.assignment_epoch()
        || assignment.desired_generation() != desired.expected_generation()
        || assignment.digest().as_bytes() != desired.resource_state().digest().as_bytes()
    {
        return Err(ReconcilerError::InvalidPlan(
            "Storage Create preparation differs from its signed assignment",
        ));
    }

    let request_digest = Sha256::new()
        .chain_update(b"aos.sandbox.storage.create-preparation-request-id.v1\0")
        .chain_update(protected.argument_commitment().digest().as_bytes())
        .chain_update(signed_plan.digest().as_bytes())
        .chain_update((signed_plan.canonical_signature().len() as u64).to_be_bytes())
        .chain_update(signed_plan.canonical_signature())
        .finalize();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&request_digest[..16]);
    let body = protected
        .deadline_free_request_body(request_id)
        .map_err(|_| ReconcilerError::InvalidPlan("Storage Create preparation body is invalid"))?;
    let semantics = BrokerDispatchSemanticIdentityV1::new(
        BrokerVerb::StoragePrepareCatalog,
        BrokerGrantTarget::Assignment,
        protected.argument_commitment(),
    );
    BrokerDispatchTemplateV1::new(
        signed_plan,
        BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
        body,
        Vec::new(),
        semantics,
    )
    .map_err(|_| ReconcilerError::InvalidPlan("Storage Create preparation grant is invalid"))
}

/// Selects and attenuates the current Host authority for one lifecycle effect.
///
/// The returned request retains the publication's exact request identity and
/// signed authorization quartet. It remains non-authorizing controller input:
/// the Host broker must independently verify every artifact and live fence.
///
/// # Errors
///
/// Returns [`ReconcilerError`] when protected runtime authority is absent,
/// revoked, assigned to another node or fence, lacks one exact non-launch Host
/// template for `action`, or cannot be safely attenuated to `timing`.
pub fn prepare_runtime_lifecycle_authority_effect_v1(
    journal: &mut Journal,
    node: NodeId,
    fence: LiveRuntimeFenceV1,
    action: RuntimeAction,
    timing: AuthorityEffectAttemptTimingV1,
) -> Result<PreparedAuthorityEffectV1, ReconcilerError> {
    if matches!(
        action,
        RuntimeAction::RUNTIME_ACTION_UNSPECIFIED | RuntimeAction::RUNTIME_ACTION_LAUNCH
    ) {
        return Err(ReconcilerError::InvalidPlan(
            "lifecycle runtime authority requires a non-launch action",
        ));
    }

    let binding = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())?
        .current(fence.sandbox())?
        .ok_or(ReconcilerError::InvalidPlan(
            "lifecycle runtime authority is absent",
        ))?;
    let manifest = binding.manifest().manifest();
    let desired = fence.desired();
    if binding.state() != RuntimeAuthorityStateV1::Bound
        || manifest.node() != node
        || manifest.sandbox() != fence.sandbox()
        || manifest.incarnation() != fence.incarnation()
        || manifest.epoch() != fence.assignment_epoch()
        || manifest.namespace_generation() != fence.namespace_generation()
        || manifest.desired_generation() != desired.expected_generation()
        || binding.assignment_digest().as_bytes() != desired.resource_state().digest().as_bytes()
    {
        return Err(ReconcilerError::InvalidPlan(
            "lifecycle runtime fence differs from current authority",
        ));
    }

    let current = AuthorityPublicationStore::new(journal)
        .current(fence.sandbox())?
        .ok_or(ReconcilerError::InvalidPlan(
            "current lifecycle authority publication is absent",
        ))?;
    if current.digest() != binding.publication_digest()
        || current.lease_generation() != binding.lease_generation()
        || current.lease_digest() != binding.lease_digest()
    {
        return Err(ReconcilerError::InvalidPlan(
            "current lifecycle authority publication differs from its binding",
        ));
    }

    let mut matching_templates = current.templates().iter().filter(|template| {
        if template.audience() != BrokerAudience::Host
            || template.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || !template.descriptor_roles().is_empty()
        {
            return false;
        }
        let Ok(runtime) =
            aos_sandbox_protocol::decode_runtime_template_v1(template.body_without_deadline())
        else {
            return false;
        };
        let template_fence = runtime.fence();
        runtime.action() == action
            && runtime.launch_plan().is_none()
            && runtime.guardian_arm().is_none()
            && template_fence.sandbox_id() == fence.sandbox().as_bytes()
            && template_fence.incarnation_id() == fence.incarnation().as_bytes()
            && template_fence.assignment_epoch() == fence.assignment_epoch().get()
            && template_fence.desired_generation() == desired.expected_generation().get()
            && template_fence.assignment_digest() == desired.resource_state().digest().as_bytes()
    });
    let template_digest = matching_templates
        .next()
        .ok_or(ReconcilerError::InvalidPlan(
            "current authority lacks the lifecycle runtime template",
        ))?
        .digest();
    if matching_templates.next().is_some() {
        return Err(ReconcilerError::InvalidPlan(
            "current authority has ambiguous lifecycle runtime templates",
        ));
    }

    let (publication_digest, attempt) = AuthorityPublicationStore::new(journal)
        .select_bound_current_attempt(
            fence.sandbox(),
            binding.publication_digest(),
            binding.source_draft_digest(),
            BrokerAudience::Host,
            template_digest,
            None,
            timing.deadline(),
            timing.clock(),
        )?;

    Ok(PreparedAuthorityEffectV1::new(
        binding.digest(),
        publication_digest,
        timing.clock(),
        attempt,
    ))
}

/// Selects the one signed Storage group template for the protected lifecycle plan.
///
/// This does not dispatch Storage. The exact plan and live assignment fence
/// must appear in the current signed template before its lease and deadline
/// can be attenuated into an authenticated broker request.
///
/// # Errors
///
/// Returns [`ReconcilerError`] for stale protected assignment authority,
/// missing or ambiguous exact Storage templates, or unsafe lease attenuation.
pub fn prepare_atomic_storage_lifecycle_authority_effect_v1(
    journal: &mut Journal,
    node: NodeId,
    fence: LiveRuntimeFenceV1,
    plan: &LifecycleAtomicDatasetSnapshotPlanV1,
    timing: AuthorityEffectAttemptTimingV1,
) -> Result<PreparedAuthorityEffectV1, ReconcilerError> {
    if plan.target_sandbox() != fence.sandbox() {
        return Err(ReconcilerError::InvalidPlan(
            "Storage group target differs from the live assignment",
        ));
    }
    let canonical_plan = plan
        .canonical_wire_bytes()
        .map_err(|_| ReconcilerError::InvalidPlan("Storage group plan is invalid"))?;
    let argument_commitment = BrokerArgumentCommitment::for_canonical_bytes(&canonical_plan);
    let binding = RuntimeAuthorityStore::load(journal, RuntimeAuthorityLimits::default())?
        .current(fence.sandbox())?
        .ok_or(ReconcilerError::InvalidPlan(
            "lifecycle Storage authority is absent",
        ))?;
    let manifest = binding.manifest().manifest();
    let desired = fence.desired();
    if binding.state() != RuntimeAuthorityStateV1::Bound
        || manifest.node() != node
        || manifest.sandbox() != fence.sandbox()
        || manifest.incarnation() != fence.incarnation()
        || manifest.epoch() != fence.assignment_epoch()
        || manifest.namespace_generation() != fence.namespace_generation()
        || manifest.desired_generation() != desired.expected_generation()
        || binding.assignment_digest().as_bytes() != desired.resource_state().digest().as_bytes()
    {
        return Err(ReconcilerError::InvalidPlan(
            "lifecycle Storage fence differs from current authority",
        ));
    }

    let current = AuthorityPublicationStore::new(journal)
        .current(fence.sandbox())?
        .ok_or(ReconcilerError::InvalidPlan(
            "current lifecycle Storage publication is absent",
        ))?;
    if current.digest() != binding.publication_digest()
        || current.lease_generation() != binding.lease_generation()
        || current.lease_digest() != binding.lease_digest()
    {
        return Err(ReconcilerError::InvalidPlan(
            "current lifecycle Storage publication differs from its binding",
        ));
    }

    let mut matching_templates = current.templates().iter().filter(|template| {
        if template.audience() != BrokerAudience::Storage
            || template.method() != BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT
            || !template.descriptor_roles().is_empty()
            || template.semantics().verb() != BrokerVerb::StorageAtomicSnapshot
            || template.semantics().target() != BrokerGrantTarget::Assignment
            || template.semantics().argument_commitment() != argument_commitment
        {
            return false;
        }
        let Ok(body) =
            ApplyAtomicStorageSnapshotRequest::decode_from_slice(template.body_without_deadline())
        else {
            return false;
        };
        let Some(wire_fence) = body.fence.as_option() else {
            return false;
        };
        body.__buffa_unknown_fields.is_empty()
            && body.encode_to_vec() == template.body_without_deadline()
            && body.canonical_plan == canonical_plan
            && wire_fence.sandbox_id.as_slice() == fence.sandbox().as_bytes()
            && wire_fence.incarnation_id.as_slice() == fence.incarnation().as_bytes()
            && wire_fence.assignment_epoch == fence.assignment_epoch().get()
            && wire_fence.desired_generation == desired.expected_generation().get()
            && wire_fence.assignment_digest.as_slice()
                == desired.resource_state().digest().as_bytes()
    });
    let template_digest = matching_templates
        .next()
        .ok_or(ReconcilerError::InvalidPlan(
            "current authority lacks the exact Storage group template",
        ))?
        .digest();
    if matching_templates.next().is_some() {
        return Err(ReconcilerError::InvalidPlan(
            "current authority has ambiguous Storage group templates",
        ));
    }

    let (publication_digest, attempt) = AuthorityPublicationStore::new(journal)
        .select_bound_current_attempt(
            fence.sandbox(),
            binding.publication_digest(),
            binding.source_draft_digest(),
            BrokerAudience::Storage,
            template_digest,
            None,
            timing.deadline(),
            timing.clock(),
        )?;
    Ok(PreparedAuthorityEffectV1::new(
        binding.digest(),
        publication_digest,
        timing.clock(),
        attempt,
    ))
}
