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
    CanonicalAssignmentManifestV1, NodeId, ProtocolVersion,
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
    PreparedAuthorityEffectV1, PreparedAuthorityPublicationV1, ReconcilerError, SignedBrokerPlan,
    SignedOwnershipLease,
};

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
    let body = ApplyAtomicStorageSnapshotRequest {
        header: Some(RequestHeader {
            protocol_major: 1,
            protocol_minor: 0,
            request_id: request_id.to_vec(),
            audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
            deadline_boottime_nanoseconds: 0,
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
    };
    BrokerDispatchTemplateV1::new(
        signed_plan,
        BrokerMethod::BROKER_METHOD_STORAGE_ATOMIC_SNAPSHOT,
        body.encode_to_vec(),
        Vec::new(),
        semantics,
    )
    .map_err(|_| ReconcilerError::InvalidPlan("atomic Storage template grant is invalid"))
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
