//! Dormant projection from the existing Host broker protocol to core backend contracts.
//!
//! This module is linked for type checking but has no active service callsite.
//! It documents and implements the source-level migration seam from
//! a validated Host 1.0 request to the backend-neutral RFC-0021 contract. The
//! legacy Launch verb combines preparation and start; the projection therefore
//! returns an explicit split action rather than invoking either effect.

use aos_proto::aos::sandbox::local::v1::RuntimeAction;
use aos_sandbox_core::runtime_backend::{
    BackendStopDeadlineV1, RequiredBackendCapabilitiesV1, ResolvedRuntimePlanV1,
    RuntimeCurrentnessV1, RuntimeModelError,
};
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, NodeId, ObjectDigest,
    SandboxId,
};
use aos_sandbox_protocol::ValidatedRuntimeRequest;

mod backend;
mod composition;
pub use backend::{
    DormantAgentExecutionHandoffV1, DormantBackendHandoffErrorV1, DormantExecutionHandleV1,
    DormantExecutionRecoveryHandleV1, DormantForcedKillHandoffV1, DormantKillEscalationErrorV1,
    DormantKillStopOutcomeV1, DormantLifecycleRecoveryHandleV1, DormantPendingKillV1,
    DormantPreparedHandleV1, DormantProtectedRuntimeBackendV1,
    DormantRuntimeBackendReadinessEvidenceV1, DormantRuntimeHandleV1, SignedAgentOutcomeV1,
    SignedDormantKillDeadlineObservationV1, dormant_kill_deadline_signing_message_v1,
};
pub use composition::{
    DormantComposedRuntimeBackendV1, DormantRuntimeBackendCompositionErrorV1,
    DormantRuntimeBackendCompositionV1,
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
    /// Protected relative deadline for Stop and pre-escalation Kill handling.
    pub termination_deadline: BackendStopDeadlineV1,
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
    /// Stops then forcibly tears down the exact runtime after a fixed deadline.
    Kill,
}

/// Describes the closed Stop/Kill termination contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DormantHostTerminationContractV1 {
    deadline: BackendStopDeadlineV1,
    force_after_deadline: bool,
}

impl DormantHostTerminationContractV1 {
    /// Returns the protected relative termination deadline.
    #[must_use]
    pub const fn deadline(self) -> BackendStopDeadlineV1 {
        self.deadline
    }

    /// Reports whether expiry authorizes forced complete-payload teardown.
    #[must_use]
    pub const fn force_after_deadline(self) -> bool {
        self.force_after_deadline
    }
}

/// Carries one validated dormant projection without authorizing dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DormantHostBackendProjectionV1 {
    action: DormantHostBackendActionV1,
    plan: Option<ResolvedRuntimePlanV1>,
    currentness: RuntimeCurrentnessV1,
    termination: Option<DormantHostTerminationContractV1>,
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

    /// Returns the exact termination contract for Stop or Kill.
    #[must_use]
    pub const fn termination(&self) -> Option<DormantHostTerminationContractV1> {
        self.termination
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
/// Returns [`DormantHostProjectionError`] for the unspecified action,
/// missing/unexpected launch plan, sentinel protected input, or a
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
                termination: None,
            })
        }
        RuntimeAction::RUNTIME_ACTION_FREEZE => {
            no_plan(request, currentness, DormantHostBackendActionV1::Freeze)
        }
        RuntimeAction::RUNTIME_ACTION_THAW => {
            no_plan(request, currentness, DormantHostBackendActionV1::Thaw)
        }
        RuntimeAction::RUNTIME_ACTION_STOP => termination(
            request,
            currentness,
            DormantHostBackendActionV1::Stop,
            resolved.termination_deadline,
            false,
        ),
        RuntimeAction::RUNTIME_ACTION_KILL => termination(
            request,
            currentness,
            DormantHostBackendActionV1::Kill,
            resolved.termination_deadline,
            true,
        ),
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
        termination: None,
    })
}

fn termination(
    request: &ValidatedRuntimeRequest,
    currentness: RuntimeCurrentnessV1,
    action: DormantHostBackendActionV1,
    deadline: BackendStopDeadlineV1,
    force_after_deadline: bool,
) -> Result<DormantHostBackendProjectionV1, DormantHostProjectionError> {
    if request.launch_plan().is_some() {
        return Err(DormantHostProjectionError::LaunchPlanShape);
    }
    Ok(DormantHostBackendProjectionV1 {
        action,
        plan: None,
        currentness,
        termination: Some(DormantHostTerminationContractV1 {
            deadline,
            force_after_deadline,
        }),
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
    /// A portable runtime-model invariant failed.
    #[error("Host runtime projection is invalid: {0}")]
    Runtime(#[from] RuntimeModelError),
}
