//! Bridges protected lifecycle work to current broker authority.
//!
//! Lifecycle plans describe required effects but do not grant them.
//! The module selects an exact method-specific template from the protected
//! current runtime-authority publication, attenuates it with a fresh deadline,
//! and returns the request consumed by the authenticated session owner.

use aos_proto::aos::sandbox::local::v1::{
    ApplyAtomicStorageSnapshotRequest, BrokerMethod, RuntimeAction,
};
use aos_sandbox_core::{BrokerAudience, NodeId};
use buffa::Message as _;

use crate::lifecycle::{LifecycleAtomicDatasetSnapshotPlanV1, LiveRuntimeFenceV1};
use crate::runtime_authority::{
    RuntimeAuthorityLimits, RuntimeAuthorityStateV1, RuntimeAuthorityStore,
};
use crate::{
    AuthorityEffectAttemptTimingV1, AuthorityPublicationStore, Journal, PreparedAuthorityEffectV1,
    ReconcilerError,
};

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
