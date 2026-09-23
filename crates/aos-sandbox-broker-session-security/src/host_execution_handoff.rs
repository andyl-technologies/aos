//! Protected Host execution intent admission and exact outcome readback.
//!
//! The Broker Session ClientRecord authenticates each transport attempt. This
//! owner opens only fixed root-owned Host journals, derives runtime currentness
//! and effect sequence there, and uses the stable controller operation digest
//! solely as an idempotency and readback binding. Pending work never crosses
//! the guest boundary without a separately authenticated AOSAGE route.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, HostExecutionCompletionStatusV1, HostExecutionOutcomeV1, HostExecutionPhaseV1,
};
use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionClaimV1, DormantRuntimeExecutionOwnerErrorV1,
    DormantRuntimeExecutionOwnerV1,
};
use aos_sandbox_core::runtime_backend::{
    AdmissionCommitError, AdmissionIdempotencyV1, DurableExecutionEffectV1, EffectCommitError,
    EffectCompletionStatusV1, EffectIdempotencyV1, EffectIssueV1, EffectPhaseV1,
    ExecutionAdmissionDraftV1, ExecutionAdmissionOutcomeV1, ExecutionEffectTransitionV1,
    admit_execution, prepare_effect,
};
use aos_sandbox_core::{ExecutionId, ObjectDigest};
use aos_sandbox_host::DormantHostBrokerCallsiteV1;
use aos_sandbox_host::broker::HostExecutionGrantRequestV1;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, ValidatedHostExecutionApplyV1};
use buffa::Message as _;

/// Reports a fail-closed Host execution admission or readback failure.
#[derive(Debug, thiserror::Error)]
pub enum HostExecutionHandoffErrorV1 {
    /// Shared Host signer, lease, or durable fence admission failed.
    #[error("Host execution authorization failed: {0}")]
    Authorization(#[from] aos_sandbox_host::DormantHostBrokerCallErrorV1),
    /// The session boot no longer matches the Host kernel.
    #[error("Host execution handoff kernel boot changed")]
    KernelBoot,
    /// Fixed root-owned execution custody is missing, stale, or corrupt.
    #[error("Host execution owner is unavailable: {0}")]
    Owner(#[from] DormantRuntimeExecutionOwnerErrorV1),
    /// Admission was rejected by the exact protected store.
    #[error("Host execution admission failed: {0}")]
    Admission(#[from] AdmissionCommitError),
    /// Effect preparation was rejected by the exact protected store.
    #[error("Host execution effect failed: {0}")]
    Effect(#[from] EffectCommitError),
    /// An earlier commit requires cold protected readback before another effect.
    #[error("Host execution effect requires protected recovery")]
    RecoveryRequired,
    /// The operation, execution, action, or source commitment conflicts.
    #[error("Host execution handoff conflicts with protected state")]
    Conflict,
    /// The execution has not been durably admitted by this Host.
    #[error("Host execution admission is absent")]
    MissingAdmission,
}

/// Dispatches an authenticated Host execution method into the fixed owner.
///
/// An Apply commits at most a Pending effect. Guest dispatch requires the
/// separate live AOSAGE session and route permit; until that owner is active,
/// Pending is the only successful new-effect outcome. Query never writes.
///
/// # Errors
///
/// Rejects stale boot/currentness, a malformed or conflicting request, missing
/// admission, unresolved durability, or unavailable protected Host state.
pub(crate) fn dispatch_host_execution_handoff_v1(
    host: &mut dyn DormantHostBrokerCallsiteV1,
    method: BrokerMethod,
    body: &[u8],
    request_id: [u8; 16],
    artifacts: &ValidatedUntrustedAuthorizationArtifacts,
    peer: PeerCredentials,
    policy: PeerPolicy,
    protected_boot_id: [u8; 16],
) -> Result<Vec<u8>, HostExecutionHandoffErrorV1> {
    check_kernel_boot(protected_boot_id)?;
    let mut owner = DormantRuntimeExecutionOwnerV1::open()?;
    let mut claim = owner.claim()?;
    if claim.host_verifier().boot_id() != protected_boot_id {
        return Err(HostExecutionHandoffErrorV1::KernelBoot);
    }
    let reservation = host.reserve_authenticated_execution(
        &claim,
        method,
        body,
        request_id,
        artifacts,
        peer,
        policy,
        protected_boot_id,
    )?;
    if !reservation.matches(method, request_id, body, &claim) {
        return Err(HostExecutionHandoffErrorV1::Conflict);
    }

    let result = match reservation.request() {
        HostExecutionGrantRequestV1::Apply(request) => apply_execution(&mut claim, request)?,
        HostExecutionGrantRequestV1::Query(request) => {
            let effect = claim.load_effect(&request.operation_id())?;
            let effect = match effect {
                Some(effect) => Some(validate_effect_identity(
                    effect,
                    &claim,
                    request.operation_id(),
                    request.execution_id(),
                    request.source_commitment(),
                )?),
                None => {
                    let admission = claim.load_admission(request.execution_id())?;
                    if admission.as_ref().is_some_and(|admission| {
                        admission.idempotency().operation().as_bytes() == &request.operation_id()
                            && admission.idempotency().request_digest()
                                == request.source_commitment()
                    }) {
                        return Err(HostExecutionHandoffErrorV1::RecoveryRequired);
                    }
                    None
                }
            };
            outcome(
                request.operation_id(),
                request.execution_id(),
                request.source_commitment(),
                effect.as_ref(),
            )
        }
    };
    claim.revalidate()?;
    check_kernel_boot(protected_boot_id)?;
    let encoded = result.encode_to_vec();
    host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
    Ok(encoded)
}

fn check_kernel_boot(expected: [u8; 16]) -> Result<(), HostExecutionHandoffErrorV1> {
    let current = KernelBootId::current()
        .map_err(|_| HostExecutionHandoffErrorV1::KernelBoot)?
        .into_bytes();
    if current != expected {
        return Err(HostExecutionHandoffErrorV1::KernelBoot);
    }
    Ok(())
}

fn apply_execution(
    claim: &mut DormantRuntimeExecutionClaimV1<'_>,
    request: &ValidatedHostExecutionApplyV1,
) -> Result<HostExecutionOutcomeV1, HostExecutionHandoffErrorV1> {
    let operation =
        aos_sandbox_core::runtime_backend::BackendOperationIdV1::new(request.operation_id())
            .map_err(|_| HostExecutionHandoffErrorV1::Conflict)?;
    if let Some(effect) = claim.load_effect(&request.operation_id())? {
        let effect = validate_effect_identity(
            effect,
            claim,
            request.operation_id(),
            request.execution_id(),
            request.source_commitment(),
        )?;
        if effect.issue().operation() != request.action() {
            return Err(HostExecutionHandoffErrorV1::Conflict);
        }
        return Ok(outcome(
            request.operation_id(),
            request.execution_id(),
            request.source_commitment(),
            Some(&effect),
        ));
    }

    let admission = match claim.load_admission(request.execution_id())? {
        Some(admission) => {
            if admission.currentness() != claim.currentness() {
                return Err(HostExecutionHandoffErrorV1::Conflict);
            }
            if let Some(specification) = request.specification() {
                let proposed = aos_sandbox_core::encode_execution_spec_v1(specification);
                if admission.specification_bytes() != proposed
                    || admission.idempotency().operation() != operation
                    || admission.idempotency().request_digest() != request.source_commitment()
                {
                    return Err(HostExecutionHandoffErrorV1::Conflict);
                }
            }
            admission
        }
        None => {
            let specification = request
                .specification()
                .ok_or(HostExecutionHandoffErrorV1::MissingAdmission)?;
            let idempotency = AdmissionIdempotencyV1::new(operation, request.source_commitment())?;
            let draft =
                ExecutionAdmissionDraftV1::new(specification, idempotency, *claim.currentness())?;
            match admit_execution(claim, draft)? {
                ExecutionAdmissionOutcomeV1::Admitted(admission) => admission,
                ExecutionAdmissionOutcomeV1::RecoveryRequired { .. }
                | ExecutionAdmissionOutcomeV1::NotCommitted(_) => {
                    return Err(HostExecutionHandoffErrorV1::RecoveryRequired);
                }
            }
        }
    };

    let sequence = claim.next_effect_sequence()?;
    let idempotency = EffectIdempotencyV1::new(operation, request.source_commitment())?;
    let issue = EffectIssueV1::new(request.action(), sequence, idempotency)?;
    let effect = match prepare_effect(claim, &admission, issue)? {
        ExecutionEffectTransitionV1::Committed(effect) => effect,
        ExecutionEffectTransitionV1::RecoveryRequired(_)
        | ExecutionEffectTransitionV1::NotCommitted => {
            return Err(HostExecutionHandoffErrorV1::RecoveryRequired);
        }
    };
    Ok(outcome(
        request.operation_id(),
        request.execution_id(),
        request.source_commitment(),
        Some(&effect),
    ))
}

fn validate_effect_identity(
    effect: DurableExecutionEffectV1,
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    operation_id: [u8; 16],
    execution: ExecutionId,
    source: ObjectDigest,
) -> Result<DurableExecutionEffectV1, HostExecutionHandoffErrorV1> {
    if effect.admission().currentness() != claim.currentness()
        || effect.admission().execution() != execution
        || effect.issue().idempotency().operation().as_bytes() != &operation_id
        || effect.issue().idempotency().request_digest() != source
    {
        return Err(HostExecutionHandoffErrorV1::Conflict);
    }
    Ok(effect)
}

fn outcome(
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    effect: Option<&DurableExecutionEffectV1>,
) -> HostExecutionOutcomeV1 {
    let mut result = HostExecutionOutcomeV1 {
        operation_id: operation_id.to_vec(),
        execution_id: execution_id.as_bytes().to_vec(),
        source_operation_commitment: source_commitment.as_bytes().to_vec(),
        ..Default::default()
    };
    let Some(effect) = effect else {
        result.phase = HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ABSENT.into();
        return result;
    };
    result.effect_commitment = effect.record_commitment().as_bytes().to_vec();
    result.phase = match effect.phase() {
        EffectPhaseV1::Pending => HostExecutionPhaseV1::HOST_EXECUTION_PHASE_PENDING,
        EffectPhaseV1::Issued => HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ISSUED,
        EffectPhaseV1::Indeterminate => HostExecutionPhaseV1::HOST_EXECUTION_PHASE_INDETERMINATE,
        EffectPhaseV1::Complete => HostExecutionPhaseV1::HOST_EXECUTION_PHASE_COMPLETE,
    }
    .into();
    if let Some(completion) = effect.completion() {
        result.completion_digest = completion.result_digest().as_bytes().to_vec();
        result.completion_bytes = completion.result_bytes().to_vec();
        result.observation_sequence = completion.observation_sequence().get();
        result.completion_status = match completion.status() {
            EffectCompletionStatusV1::Succeeded => {
                HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_SUCCEEDED
            }
            EffectCompletionStatusV1::RejectedBeforeEffect => {
                HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_REJECTED_BEFORE_EFFECT
            }
            EffectCompletionStatusV1::FailedPermanent => {
                HostExecutionCompletionStatusV1::HOST_EXECUTION_COMPLETION_STATUS_FAILED_PERMANENT
            }
        }.into();
    }
    result
}
