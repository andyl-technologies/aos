//! Dormant projection from the existing Host broker protocol to core backend contracts.
//!
//! This module is linked for type checking but has no active service callsite.
//! It documents and implements the source-level migration seam from
//! a validated Host 1.0 request to the backend-neutral RFC-0021 contract. The
//! legacy Launch verb combines preparation and start; the projection therefore
//! returns an explicit split action rather than invoking either effect.

use aos_proto::aos::sandbox::local::v1::RuntimeAction;
use aos_sandbox_core::runtime_backend::{
    RequiredBackendCapabilitiesV1, ResolvedRuntimePlanV1, RuntimeCurrentnessV1, RuntimeModelError,
};
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, NodeId, ObjectDigest,
    SandboxId,
};
use aos_sandbox_protocol::ValidatedRuntimeRequest;

pub mod agent_session;
pub(crate) mod protected_agent_peer;
pub use protected_agent_peer::{
    DormantHostAgentPeerClaimV1, DormantHostAgentPeerOwnerV1, DormantProtectedAgentPeerErrorV1,
};

/// Supplies commitments resolved from protected Host/controller state.
///
/// None of these values may be derived from a caller-selected path. The active
/// integration must authenticate them under the same durable admission
/// transaction that reserves a backend operation sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DormantResolvedRuntimeInputsV1 {
    /// Exact node selected by the assignment.
    pub node: NodeId,
    /// Payload namespace generation observed through retained kernel handles.
    pub namespace_generation: NamespaceGeneration,
    /// Hard backend semantic requirements compiled by the controller.
    pub required_capabilities: RequiredBackendCapabilitiesV1,
    /// Protected catalog commitment for the private storage root.
    pub storage_root: ObjectDigest,
    /// Protected commitment to the complete ordered attachment set.
    pub attachment_set: ObjectDigest,
    /// Protected commitment to the prepared default-drop network.
    pub network: ObjectDigest,
    /// Protected commitment to the exact runtime enforcement profile.
    pub runtime_profile: ObjectDigest,
}

/// Names the backend-neutral operation represented by a Host 1.0 action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DormantHostBackendActionV1 {
    /// Legacy Launch must be admitted as separate Prepare then Start effects.
    PrepareThenStart,
    /// Freezes the exact running runtime.
    Freeze,
    /// Thaws the exact frozen runtime.
    Thaw,
    /// Stops the exact running or frozen runtime.
    Stop,
}

/// Carries one validated dormant projection without authorizing dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DormantHostBackendProjectionV1 {
    action: DormantHostBackendActionV1,
    plan: Option<ResolvedRuntimePlanV1>,
    currentness: RuntimeCurrentnessV1,
}

impl DormantHostBackendProjectionV1 {
    /// Returns the closed backend operation.
    #[must_use]
    pub const fn action(&self) -> DormantHostBackendActionV1 {
        self.action
    }

    /// Returns the complete resolved plan only for legacy Launch.
    #[must_use]
    pub const fn plan(&self) -> Option<&ResolvedRuntimePlanV1> {
        self.plan.as_ref()
    }

    /// Returns exact assignment and runtime currentness.
    #[must_use]
    pub const fn currentness(&self) -> &RuntimeCurrentnessV1 {
        &self.currentness
    }
}

/// Projects a fully protocol-validated Host request into the portable seam.
///
/// The result is nonauthorizing. Production integration must still atomically
/// reserve the operation sequence, authenticate the current assignment and
/// protected resource commitments, and call the backend only after its durable
/// effect record reaches Issued.
///
/// # Errors
///
/// Returns [`DormantHostProjectionError`] for the unspecified or legacy Kill
/// action, missing/unexpected launch plan, sentinel protected input, or a
/// backend-neutral model invariant violation.
pub fn project_validated_host_request_v1(
    request: &ValidatedRuntimeRequest,
    resolved: DormantResolvedRuntimeInputsV1,
) -> Result<DormantHostBackendProjectionV1, DormantHostProjectionError> {
    validate_resolved_inputs(&resolved)?;
    let fence = request.fence();
    let currentness = RuntimeCurrentnessV1::new(
        SandboxId::from_bytes(*fence.sandbox_id()),
        IncarnationId::from_bytes(*fence.incarnation_id()),
        resolved.node,
        AssignmentEpoch::new(fence.assignment_epoch()),
        ObjectDigest::from_bytes(*fence.assignment_digest()),
        DesiredGeneration::new(fence.desired_generation()),
        resolved.namespace_generation,
    )?;

    match request.action() {
        RuntimeAction::RUNTIME_ACTION_LAUNCH => {
            if request.launch_plan().is_none() {
                return Err(DormantHostProjectionError::LaunchPlanShape);
            }
            let plan = ResolvedRuntimePlanV1::new(
                currentness,
                resolved.required_capabilities,
                resolved.storage_root,
                resolved.attachment_set,
                resolved.network,
                resolved.runtime_profile,
            )?;
            Ok(DormantHostBackendProjectionV1 {
                action: DormantHostBackendActionV1::PrepareThenStart,
                plan: Some(plan),
                currentness,
            })
        }
        RuntimeAction::RUNTIME_ACTION_FREEZE => {
            no_plan(request, currentness, DormantHostBackendActionV1::Freeze)
        }
        RuntimeAction::RUNTIME_ACTION_THAW => {
            no_plan(request, currentness, DormantHostBackendActionV1::Thaw)
        }
        RuntimeAction::RUNTIME_ACTION_STOP => {
            no_plan(request, currentness, DormantHostBackendActionV1::Stop)
        }
        RuntimeAction::RUNTIME_ACTION_KILL => {
            Err(DormantHostProjectionError::KillRequiresSeparateContract)
        }
        RuntimeAction::RUNTIME_ACTION_UNSPECIFIED => {
            Err(DormantHostProjectionError::UnspecifiedAction)
        }
    }
}

fn validate_resolved_inputs(
    resolved: &DormantResolvedRuntimeInputsV1,
) -> Result<(), DormantHostProjectionError> {
    if resolved.node.as_bytes() == &[0; 16]
        || resolved.namespace_generation.get() == 0
        || [
            resolved.storage_root,
            resolved.attachment_set,
            resolved.network,
            resolved.runtime_profile,
        ]
        .iter()
        .any(|value| value.as_bytes() == &[0; 32])
    {
        return Err(DormantHostProjectionError::InvalidProtectedInput);
    }
    Ok(())
}

fn no_plan(
    request: &ValidatedRuntimeRequest,
    currentness: RuntimeCurrentnessV1,
    action: DormantHostBackendActionV1,
) -> Result<DormantHostBackendProjectionV1, DormantHostProjectionError> {
    if request.launch_plan().is_some() {
        return Err(DormantHostProjectionError::LaunchPlanShape);
    }
    Ok(DormantHostBackendProjectionV1 {
        action,
        plan: None,
        currentness,
    })
}

/// Reports failure to create the dormant Host/backend projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DormantHostProjectionError {
    /// A protected resolver supplied a sentinel commitment or identity.
    #[error("Host protected runtime input is invalid")]
    InvalidProtectedInput,
    /// The Host action uses its unspecified sentinel.
    #[error("Host runtime action is unspecified")]
    UnspecifiedAction,
    /// Launch-plan presence does not match the closed action.
    #[error("Host runtime launch-plan shape is invalid")]
    LaunchPlanShape,
    /// Legacy Kill has no backend-neutral portable operation in this tranche.
    #[error("Host Kill requires a separately admitted stop escalation contract")]
    KillRequiresSeparateContract,
    /// A portable runtime-model invariant failed.
    #[error("Host runtime projection is invalid: {0}")]
    Runtime(#[from] RuntimeModelError),
}
