//! Applies one already-reserved Host execution grant through the sole engine.
//!
//! Durable reservation is minted by the Host lease/fence owner. This module
//! cannot manufacture that reservation, a runtime claim or a Storage hold. It
//! shares admission/effect/Agent dispatch and outcome DATA with Security's
//! existing consumer and Host's retained method59 continuation.

use std::time::{Duration, Instant};
use aos_sandbox_api::aos::sandbox::local::v1::{HostExecutionOutcomeV1,
    HostExecutionPhaseV1, HostExecutionCompletionStatusV1,
    HostExecutionOutputReservationStatusV1, HostExecutionOutputReservationV1};
use aos_sandbox_controller_domain::runtime_execution::{DormantRuntimeExecutionClaimV1,
    DormantRuntimeExecutionOwnerErrorV1, ProtectedHostOutputReservationV1, decode_observe_completion_evidence_v1};
use aos_sandbox_model::runtime_backend::{AdmissionCommitError, AdmissionIdempotencyV1,
    BackendExecutionPhaseV1, DurableExecutionEffectV1, EffectCommitError,
    EffectCompletionStatusV1, EffectIdempotencyV1, EffectIssueV1, EffectOperationV1,
    EffectPhaseV1, ExecutionAdmissionDraftV1, ExecutionAdmissionOutcomeV1,
    ExecutionEffectTransitionV1, admit_execution, prepare_effect};
use aos_sandbox_model::{ExecutionId, ObjectDigest};
use aos_sandbox_guest_protocol::{AgentExecutionOperationV1, AgentExecutionPhaseV1};
use aos_sandbox_protocol::ValidatedHostExecutionApplyV1;
use aos_sandbox_protocol::host_execution::{HostExecutionTerminalResultV1,
    decode_host_execution_terminal_result_v1};
use aos_sandbox_protocol::host_output::HostOutputReservationLocatorV1;
use buffa::Message as _;
use crate::attach_route::{HostOpenSshAttachRouteOwnerV1, HostOpenSshAttachRouteErrorV1};
use crate::live_agent::{HostAgentLiveSessionV1, HostAgentLiveErrorV1};
use crate::broker::{HostExecutionGrantReservationV1, HostExecutionGrantRequestV1};

/// Preserves the exact admission, native effect or Agent failure.
#[derive(Debug, thiserror::Error)]
pub enum HostExecutionEffectErrorV1 {
    /// The same fixed runtime owner refused currentness or native work.
    #[error(transparent)]
    Owner(#[from] DormantRuntimeExecutionOwnerErrorV1),
    /// The existing durable admission engine refused its transition.
    #[error(transparent)]
    Admission(#[from] AdmissionCommitError),
    /// The existing durable effect engine refused its transition.
    #[error(transparent)]
    Effect(#[from] EffectCommitError),
    /// An ambiguous append requires actual protected recovery.
    #[error("Host execution effect requires protected recovery")]
    RecoveryRequired,
    /// The actual admitted identities or content disagree.
    #[error("Host execution handoff conflicts with protected state")]
    Conflict,
    /// No current admission exists for the requested control.
    #[error("Host execution admission is absent")]
    MissingAdmission,
    /// The same retained Guest session refused or failed its real operation.
    #[error(transparent)]
    Agent(#[from] HostAgentLiveErrorV1),
    /// Actual OpenSSH route cancellation failed.
    #[error(transparent)]
    AttachGate(#[from] HostOpenSshAttachRouteErrorV1),
    /// The fixed original dispatch deadline expired.
    #[error("Host execution guest dispatch deadline expired")]
    Deadline,
}

/// Executes an Apply from the original durable signed Host reservation.
///
/// A retained deadline only shortens the original absolute cutoff. It does
/// not authorize an operation; the unconstructible reservation and actual
/// runtime claim remain required. Pending without a live Agent stays Pending.
///
/// # Errors
/// Preserves exact admission, effect, Agent and deadline failures.
pub fn execute_reserved_effect_v1(
    reservation: &HostExecutionGrantReservationV1,
    claim: &mut DormantRuntimeExecutionClaimV1<'_>,
    agent: Option<&mut HostAgentLiveSessionV1>,
    absolute_cutoff: u64,
    retained_deadline: Option<Instant>,
) -> Result<DurableExecutionEffectV1, HostExecutionEffectErrorV1> {
    execute_reserved_effect_engine_v2(reservation, claim, agent, absolute_cutoff,
        retained_deadline, None, None, None)
}

/// Executes the same reserved effect with native Guest custody retained.
///
/// # Errors
/// Preserves the ordinary semantic result while `original` retains reached
/// creation/send/receive native failures through the real Host posts.
#[doc(hidden)]
pub fn execute_reserved_effect_retaining_v2(
    reservation: &HostExecutionGrantReservationV1,
    claim: &mut DormantRuntimeExecutionClaimV1<'_>,
    agent: &mut HostAgentLiveSessionV1,
    absolute_cutoff: u64,
    deadline: Instant,
    original: &mut crate::live_agent::execution_original::AgentExecutionOriginalV2,
    before_native_write: &mut dyn FnMut() -> Result<(), HostAgentLiveErrorV1>,
) -> Result<DurableExecutionEffectV1, HostExecutionEffectErrorV1> {
    execute_reserved_effect_engine_v2(reservation, claim, Some(agent), absolute_cutoff,
        Some(deadline), Some(original), None, Some(before_native_write))
}

pub(crate) fn execute_reserved_effect_retaining_capture_v3(
    reservation: &HostExecutionGrantReservationV1,
    claim: &mut DormantRuntimeExecutionClaimV1<'_>,
    agent: &mut HostAgentLiveSessionV1,
    absolute_cutoff: u64,
    deadline: Instant,
    original: &mut crate::live_agent::execution_original::AgentExecutionOriginalV2,
    before_native_write: &mut dyn FnMut() -> Result<(), HostAgentLiveErrorV1>,
    pipes: &crate::storage_existing_output::capture::StorageCapturePipeLoanV2<'_>,
) -> Result<DurableExecutionEffectV1, HostExecutionEffectErrorV1> {
    execute_reserved_effect_engine_v2(reservation, claim, Some(agent), absolute_cutoff,
        Some(deadline), Some(original), Some(pipes), Some(before_native_write))
}

fn execute_reserved_effect_engine_v2(
    reservation: &HostExecutionGrantReservationV1,
    claim: &mut DormantRuntimeExecutionClaimV1<'_>,
    agent: Option<&mut HostAgentLiveSessionV1>,
    absolute_cutoff: u64,
    retained_deadline: Option<Instant>,
    original: Option<&mut crate::live_agent::execution_original::AgentExecutionOriginalV2>,
    capture: Option<&crate::storage_existing_output::capture::StorageCapturePipeLoanV2<'_>>,
    before_native_write: Option<&mut dyn FnMut() -> Result<(), HostAgentLiveErrorV1>>,
) -> Result<DurableExecutionEffectV1, HostExecutionEffectErrorV1> {
    let HostExecutionGrantRequestV1::Apply(request) = reservation.request() else {
        return Err(HostExecutionEffectErrorV1::Conflict);
    };
    let effect = apply_execution(claim, request)?;
    if effect.phase() != EffectPhaseV1::Pending { return Ok(effect); }
    match agent {
        Some(agent) => {
            let deadline = match retained_deadline {
                Some(deadline) => deadline,
                None => agent_dispatch_deadline(absolute_cutoff)?,
            };
            match original {
                Some(_) if before_native_write.is_none() => return Err(HostExecutionEffectErrorV1::Conflict),
                Some(original) => match capture {
                    Some(pipes) => agent.issue_pending_effect_retaining_capture_v3(
                        claim, &effect, deadline, absolute_cutoff, original,
                        before_native_write.ok_or(HostExecutionEffectErrorV1::Conflict)?, pipes),
                    None => agent.issue_pending_effect_retaining_v2(
                        claim, &effect, deadline, absolute_cutoff, original,
                        before_native_write.ok_or(HostExecutionEffectErrorV1::Conflict)?),
                },
                None => agent.issue_pending_effect(claim, &effect, deadline, absolute_cutoff),
            }.map_err(Into::into)
        }
        None => Ok(effect),
    }
}

pub(crate) fn execute_monitored_effect_v5(
    request: &crate::broker::HostExecutionMonitorRequestV5<'_>,
    claim: &mut DormantRuntimeExecutionClaimV1<'_>,
    agent: &mut HostAgentLiveSessionV1,
    cutoff: u64,
    deadline: Instant,
    original: &mut crate::live_agent::execution_original::AgentExecutionOriginalV2,
    deferred: &mut crate::live_agent::deferred_completion::AgentDeferredCompletionOriginalV5,
    before_native_write: &mut dyn FnMut() -> Result<(), HostAgentLiveErrorV1>,
) -> Result<DurableExecutionEffectV1, HostExecutionEffectErrorV1> {
    claim.revalidate()?;
    request.require_claim_binding_v5(claim)
        .map_err(|_| HostExecutionEffectErrorV1::Conflict)?;
    let effect = apply_execution_input_v5(claim, ExecutionApplyInputV5::Monitor(request))?;
    if effect.phase() != EffectPhaseV1::Pending {
        return Err(HostExecutionEffectErrorV1::Conflict);
    }
    agent.issue_pending_monitor_effect_v5(claim, &effect, deadline, cutoff,
        original, deferred, before_native_write).map_err(Into::into)
}

/// Revokes a prior attach route only after a genuine successful Cancel.
///
/// # Errors
/// Preserves the original owner, identity, native route or evidence failure.
pub fn revoke_route_after_successful_cancel(
    effect: &DurableExecutionEffectV1,
) -> Result<(), HostExecutionEffectErrorV1> {
    if effect.issue().operation() != EffectOperationV1::Cancel
        || !effect
            .completion()
            .is_some_and(|completion| completion.status() == EffectCompletionStatusV1::Succeeded)
    {
        return Ok(());
    }

    // The guest cancellation is durably complete, but an earlier OpenSSH
    // certificate may still be valid. Close Host route replay and renewal
    // before reporting the cancellation to its authenticated caller.
    let mut routes = HostOpenSshAttachRouteOwnerV1::open()?;
    routes.revoke_execution_route_if_present(*effect.admission().execution().as_bytes())?;
    Ok(())
}

fn agent_dispatch_deadline(
    deadline_boottime_nanoseconds: u64,
) -> Result<Instant, HostExecutionEffectErrorV1> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| HostExecutionEffectErrorV1::Deadline)?;
    let nanoseconds =
        u64::try_from(now.tv_nsec).map_err(|_| HostExecutionEffectErrorV1::Deadline)?;
    let now = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(HostExecutionEffectErrorV1::Deadline)?;
    let remaining = deadline_boottime_nanoseconds
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(HostExecutionEffectErrorV1::Deadline)?;
    Instant::now()
        .checked_add(Duration::from_nanos(remaining))
        .ok_or(HostExecutionEffectErrorV1::Deadline)
}

fn apply_execution(
    claim: &mut DormantRuntimeExecutionClaimV1<'_>,
    request: &ValidatedHostExecutionApplyV1,
) -> Result<DurableExecutionEffectV1, HostExecutionEffectErrorV1> {
    apply_execution_input_v5(claim, ExecutionApplyInputV5::Signed(request))
}

// Only this private projection feeds the existing admission/effect recipe.
// A monitor variant holds its real borrowed ongoing permission continuously.
enum ExecutionApplyInputV5<'input, 'permission> {
    Signed(&'input ValidatedHostExecutionApplyV1),
    Monitor(&'input crate::broker::HostExecutionMonitorRequestV5<'permission>),
}

impl ExecutionApplyInputV5<'_, '_> {
    fn operation_id(&self) -> [u8; 16] {
        match self { Self::Signed(request) => request.operation_id(),
            Self::Monitor(request) => *request.lineage_v5().operation_v5().as_bytes() }
    }

    fn execution_id(&self) -> ExecutionId {
        match self { Self::Signed(request) => request.execution_id(),
            Self::Monitor(request) => request.lineage_v5().execution_v5() }
    }

    fn source_commitment(&self) -> ObjectDigest {
        match self { Self::Signed(request) => request.source_commitment(),
            Self::Monitor(request) => request.lineage_v5().commitment_v5() }
    }

    fn admission_source_commitment(&self) -> Result<ObjectDigest, HostExecutionEffectErrorV1> {
        match self { Self::Signed(request) => Ok(request.source_commitment()),
            Self::Monitor(request) => request.original_source_commitment_v5()
                .map_err(|_| HostExecutionEffectErrorV1::Conflict) }
    }

    fn action(&self) -> EffectOperationV1 {
        match self { Self::Signed(request) => request.action(),
            Self::Monitor(_) => EffectOperationV1::Observe }
    }

    fn specification(&self) -> Option<&aos_sandbox_model::ExecutionSpecV1> {
        match self { Self::Signed(request) => request.specification(), Self::Monitor(_) => None }
    }
}

fn apply_execution_input_v5(
    claim: &mut DormantRuntimeExecutionClaimV1<'_>,
    request: ExecutionApplyInputV5<'_, '_>,
) -> Result<DurableExecutionEffectV1, HostExecutionEffectErrorV1> {
    let operation =
        aos_sandbox_model::runtime_backend::BackendOperationIdV1::new(request.operation_id())
            .map_err(|_| HostExecutionEffectErrorV1::Conflict)?;
    if let Some(effect) = claim.load_effect(&request.operation_id())? {
        let effect = validate_effect_identity(
            effect,
            claim,
            request.operation_id(),
            request.execution_id(),
            request.source_commitment(),
        )?;
        if effect.issue().operation() != request.action() {
            return Err(HostExecutionEffectErrorV1::Conflict);
        }
        return Ok(effect);
    }

    let admission = match claim.load_admission(request.execution_id())? {
        Some(admission) => {
            claim.revalidate_execution_admission_v2(&admission)?;
            if request.action() == EffectOperationV1::Observe
                && admission.idempotency().request_digest() != request.admission_source_commitment()?
            {
                return Err(HostExecutionEffectErrorV1::Conflict);
            }
            if let Some(specification) = request.specification() {
                let proposed = aos_sandbox_model::encode_execution_spec_v1(specification);
                if admission.specification_bytes() != proposed
                    || admission.idempotency().operation() != operation
                    || admission.idempotency().request_digest() != request.source_commitment()
                {
                    return Err(HostExecutionEffectErrorV1::Conflict);
                }
            }
            admission
        }
        None => {
            let specification = request
                .specification()
                .ok_or(HostExecutionEffectErrorV1::MissingAdmission)?;
            let idempotency = AdmissionIdempotencyV1::new(operation, request.source_commitment())?;
            let current = claim.admission_currentness_for_accepted_output_v2(
                specification.execution(), aos_sandbox_model::OperationId::from_bytes(
                    *specification.audit().as_bytes()),
            )?;
            let draft = ExecutionAdmissionDraftV1::new(specification, idempotency, current)?;
            match admit_execution(claim, draft)? {
                ExecutionAdmissionOutcomeV1::Admitted(admission) => admission,
                ExecutionAdmissionOutcomeV1::RecoveryRequired { .. }
                | ExecutionAdmissionOutcomeV1::NotCommitted(_) => {
                    return Err(HostExecutionEffectErrorV1::RecoveryRequired);
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
            return Err(HostExecutionEffectErrorV1::RecoveryRequired);
        }
    };
    Ok(effect)
}

/// Compares a loaded durable effect to the actual retained runtime claim.
///
/// # Errors
/// Preserves the original owner, identity, native route or evidence failure.
pub fn validate_effect_identity(
    effect: DurableExecutionEffectV1,
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    operation_id: [u8; 16],
    execution: ExecutionId,
    source: ObjectDigest,
) -> Result<DurableExecutionEffectV1, HostExecutionEffectErrorV1> {
    claim.revalidate_execution_admission_v2(effect.admission())?;
    if effect.admission().execution() != execution
        || effect.issue().idempotency().operation().as_bytes() != &operation_id
        || effect.issue().idempotency().request_digest() != source
    {
        return Err(HostExecutionEffectErrorV1::Conflict);
    }
    Ok(effect)
}

/// Encodes the actual durable effect and its authenticated terminal evidence.
///
/// # Errors
/// Preserves the original owner, identity, native route or evidence failure.
pub fn outcome(
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    effect: Option<&DurableExecutionEffectV1>,
    claim: &DormantRuntimeExecutionClaimV1<'_>,
) -> Result<HostExecutionOutcomeV1, HostExecutionEffectErrorV1> {
    let mut result = HostExecutionOutcomeV1 {
        operation_id: operation_id.to_vec(),
        execution_id: execution_id.as_bytes().to_vec(),
        source_operation_commitment: source_commitment.as_bytes().to_vec(),
        ..Default::default()
    };
    let Some(effect) = effect else {
        result.phase = HostExecutionPhaseV1::HOST_EXECUTION_PHASE_ABSENT.into();
        return Ok(result);
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
        result.terminal_guest_result = terminal_guest_result(claim, effect, completion)?;
    }
    Ok(result)
}

pub(crate) fn terminal_guest_result(
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    effect: &DurableExecutionEffectV1,
    completion: &aos_sandbox_model::runtime_backend::EffectCompletionV1,
) -> Result<Vec<u8>, HostExecutionEffectErrorV1> {
    if effect.issue().operation() != EffectOperationV1::Observe
        || !matches!(completion.status(), EffectCompletionStatusV1::Succeeded
            | EffectCompletionStatusV1::FailedPermanent)
    {
        return Ok(Vec::new());
    }
    let operation_id = *effect.issue().idempotency().operation().as_bytes();
    let observed = decode_observe_completion_evidence_v1(
        completion.result_bytes(),
        operation_id,
        *effect.issue().idempotency().request_digest().as_bytes(),
        *effect.admission().execution().as_bytes(),
        effect.admission().specification_digest(),
        completion.observation_sequence().get(),
    )
    .map_err(|_| HostExecutionEffectErrorV1::Conflict)?;
    let expected = match observed.phase() {
        BackendExecutionPhaseV1::Exited => AgentExecutionPhaseV1::Exited,
        BackendExecutionPhaseV1::Canceled => AgentExecutionPhaseV1::Canceled,
        BackendExecutionPhaseV1::Failed if completion.status() == EffectCompletionStatusV1::FailedPermanent
            => AgentExecutionPhaseV1::Failed,
        _ => return Ok(Vec::new()),
    };

    // The fixed completion records only a phase and commitment. Recover the
    // original signed Guest packet under the same protected Host operation
    // before returning an exit status to the Controller.
    let committed = claim
        .recover_committed_host_agent_outcome(&operation_id)?
        .ok_or(HostExecutionEffectErrorV1::RecoveryRequired)?;
    let authenticated = committed.authenticated();
    if committed.observation_sequence() != completion.observation_sequence()
        || committed.observation_commitment() != observed.observation_commitment()
        || !matches!(
            authenticated.request().operation(),
            AgentExecutionOperationV1::Observe { execution }
                if *execution == effect.admission().execution()
        )
        || authenticated.outcome().phase() != expected
    {
        return Err(HostExecutionEffectErrorV1::Conflict);
    }
    let bytes = authenticated.outcome().result_bytes();
    let parsed = decode_host_execution_terminal_result_v1(bytes)
        .map_err(|_| HostExecutionEffectErrorV1::Conflict)?;
    if completion.status() != if expected == AgentExecutionPhaseV1::Failed {
        EffectCompletionStatusV1::FailedPermanent
    } else { EffectCompletionStatusV1::Succeeded } || !matches!(
        (expected, parsed),
        (AgentExecutionPhaseV1::Failed, HostExecutionTerminalResultV1::TimedOut(_)) |
        (
            AgentExecutionPhaseV1::Exited,
            HostExecutionTerminalResultV1::Exited(_)
        ) | (
            AgentExecutionPhaseV1::Canceled,
            HostExecutionTerminalResultV1::Canceled
        ) | (
            AgentExecutionPhaseV1::Exited,
            HostExecutionTerminalResultV1::Original {
                canceled: false,
                ..
            }
        ) | (
            AgentExecutionPhaseV1::Canceled,
            HostExecutionTerminalResultV1::Original { canceled: true, .. }
        )
    ) {
        return Err(HostExecutionEffectErrorV1::Conflict);
    }
    Ok(bytes.to_vec())
}


/// Encodes the canonical exact original provisional output receipt or absence.
///
/// This pure codec is shared by the retained native writer and historical
/// readback consumers. It creates no output reservation or currentness proof.
///
/// # Errors
/// Refuses a receipt whose original attempt, source, assignment or boot differs.
pub fn output_reservation_response(
    locator: HostOutputReservationLocatorV1,
    receipt: Option<ProtectedHostOutputReservationV1>,
) -> Result<Vec<u8>, HostExecutionEffectErrorV1> {
    let (status, plan, semantic, correlation, sequence) = match receipt {
        Some(receipt) => {
            if receipt.execution() != locator.execution()
                || receipt.create_operation() != locator.create_operation()
                || receipt.original_request_id() != locator.original_request_id()
                || receipt.preissue_digest() != locator.preissue_digest()
                || receipt.claim_digest() != locator.claim_digest()
                || receipt.carrier_digest() != locator.carrier_digest()
                || receipt.assignment_digest() != locator.assignment_digest()
                || receipt.host_boot_id() != locator.host_boot_id()
            {
                return Err(HostExecutionEffectErrorV1::Conflict);
            }
            (
                HostExecutionOutputReservationStatusV1::HOST_EXECUTION_OUTPUT_RESERVATION_STATUS_COMMITTED,
                receipt.plan_digest().as_bytes().to_vec(),
                receipt.semantic_request_digest().as_bytes().to_vec(),
                receipt.correlation_digest().as_bytes().to_vec(),
                receipt.original_journal_sequence(),
            )
        }
        None => (
            HostExecutionOutputReservationStatusV1::HOST_EXECUTION_OUTPUT_RESERVATION_STATUS_ABSENT,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
        ),
    };
    Ok(HostExecutionOutputReservationV1 {
        status: status.into(),
        execution_id: locator.execution().as_bytes().to_vec(),
        create_operation_id: locator.create_operation().as_bytes().to_vec(),
        original_reserve_request_id: locator.original_request_id().to_vec(),
        preissue_record_digest: locator.preissue_digest().as_bytes().to_vec(),
        output_claim_digest: locator.claim_digest().as_bytes().to_vec(),
        reserve_source_digest: locator.carrier_digest().as_bytes().to_vec(),
        assignment_digest: locator.assignment_digest().as_bytes().to_vec(),
        host_boot_id: locator.host_boot_id().to_vec(),
        original_plan_digest: plan,
        original_semantic_request_digest: semantic,
        host_correlation_record_digest: correlation,
        original_host_journal_sequence: sequence,
        ..Default::default()
    }
    .encode_to_vec())
}
