//! Protected Host execution intent admission and exact outcome readback.
//!
//! The Broker Session ClientRecord authenticates each transport attempt. This
//! owner opens only fixed root-owned Host journals, derives runtime currentness
//! and effect sequence there, and uses the stable controller operation digest
//! solely as an idempotency and readback binding. Provisional output custody
//! remains distinct from execution authority. Pending work never crosses the
//! guest boundary without a separately authenticated AOSAGE route.

use std::time::{Duration, Instant};

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, HostAttachGateReadinessV1, HostExecutionCompletionStatusV1,
    HostExecutionNoApplyStatusV1, HostExecutionOutcomeV1, HostExecutionOutputReservationStatusV1,
    HostExecutionOutputReservationV1, HostExecutionPhaseV1, HostNoApplySettlementStatusV2,
    ObserveHostExecutionArgumentResponseV1, QueryHostExecutionArgumentNoApplyResponseV1,
    QueryHostExecutionArgumentResponseV1, QueryHostExecutionNoApplySettlementResponseV2,
    SettleHostExecutionNoApplyResponseV2, TerminalHostExecutionArgumentNoApplyResponseV1,
};
use aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox::runtime_execution::{
    DormantRuntimeExecutionClaimV1, DormantRuntimeExecutionOwnerErrorV1,
    DormantRuntimeExecutionOwnerV1, ProtectedHostOutputReservationV1,
    decode_observe_completion_evidence_v1,
};
use aos_sandbox_agent::{AgentExecutionOperationV1, AgentExecutionPhaseV1};
use aos_sandbox_core::runtime_backend::{
    AdmissionCommitError, AdmissionIdempotencyV1, BackendExecutionPhaseV1,
    DurableExecutionEffectV1, EffectCommitError, EffectCompletionStatusV1, EffectIdempotencyV1,
    EffectIssueV1, EffectOperationV1, EffectPhaseV1, ExecutionAdmissionDraftV1,
    ExecutionAdmissionOutcomeV1, ExecutionEffectTransitionV1, admit_execution, prepare_effect,
};
use aos_sandbox_core::{ExecutionId, ObjectDigest};
use aos_sandbox_host::DormantHostBrokerCallsiteV1;
use aos_sandbox_host::attach_route::{
    HostOpenSshAttachRouteErrorV1, HostOpenSshAttachRouteOwnerV1, HostOpenSshStaticTrustV1,
};
use aos_sandbox_host::broker::HostAttachReadOnlyRequestV1;
use aos_sandbox_host::broker::HostExecutionGrantRequestV1;
use aos_sandbox_host::live_agent::argument_attempt::HostArgumentAttemptErrorV1;
use aos_sandbox_host::live_agent::{HostAgentLiveErrorV1, HostAgentLiveSessionV1};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::ValidatedHostExecutionApplyV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::host_execution::{
    HOST_EXECUTION_CONTROL_CONTENT_V1, HostExecutionSpecContentFieldsV1,
    HostExecutionTerminalResultV1, decode_host_execution_terminal_result_v1,
};
use aos_sandbox_protocol::host_execution_no_apply::HostNoApplySettlementPhaseV2;
use aos_sandbox_protocol::host_output::HostOutputReservationLocatorV1;
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
    /// The authenticated guest session failed or requires protected recovery.
    #[error(transparent)]
    Agent(#[from] HostAgentLiveErrorV1),
    /// One-shot Host Guest observation custody or historical query failed.
    #[error(transparent)]
    Argument(#[from] HostArgumentAttemptErrorV1),
    /// Protected OpenSSH route installation or signed readback failed.
    #[error(transparent)]
    AttachGate(#[from] HostOpenSshAttachRouteErrorV1),
    /// The broker request deadline expired before guest dispatch.
    #[error("Host execution guest dispatch deadline expired")]
    Deadline,
}

/// Dispatches an authenticated Host execution method into the fixed owner.
///
/// An Apply commits Pending, then dispatches only through an installed signed
/// AOSAGE session. Without a launch-owned session Pending remains the truthful
/// durable outcome. Output reserve commits AOSEOR02 and AOSHOP01 together,
/// without proving physical backing; Query never dispatches or writes the
/// protected runtime-execution journal. A terminal Observe Query recovers the
/// original signed Guest packet and binds its result to the completed effect.
///
/// # Errors
///
/// Rejects stale boot/currentness, a malformed or conflicting request, missing
/// admission, unresolved durability, or unavailable protected Host state.
pub(crate) fn dispatch_host_execution_handoff_v1(
    host: &mut dyn DormantHostBrokerCallsiteV1,
    request: &AuthenticatedBrokerMethodRequestV1,
    execution_spec_content: Option<&[u8]>,
    protected_boot_id: [u8; 16],
    agent: Option<&mut HostAgentLiveSessionV1>,
    deadline_boottime_nanoseconds: u64,
) -> Result<Vec<u8>, HostExecutionHandoffErrorV1> {
    let method = request.method();
    let body = request.exact_body();
    let request_id = request.request_id();
    let peer = request.peer();
    let policy = request.peer_policy();

    check_kernel_boot(protected_boot_id)?;
    let mut owner = DormantRuntimeExecutionOwnerV1::open()?;
    let mut claim = owner.claim()?;
    if claim.host_verifier().boot_id() != protected_boot_id {
        return Err(HostExecutionHandoffErrorV1::KernelBoot);
    }
    if method == BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 {
        if request.authorization().is_some() {
            return Err(HostExecutionHandoffErrorV1::Conflict);
        }
        let record = host
            .commit_no_apply_preliminary_v2(&mut claim, request, protected_boot_id)?
            .ok_or(HostExecutionHandoffErrorV1::RecoveryRequired)?;
        claim.revalidate()?;
        check_kernel_boot(protected_boot_id)?;
        return Ok(SettleHostExecutionNoApplyResponseV2 {
            canonical_record: record,
            ..Default::default()
        }
        .encode_to_vec());
    }
    if method == BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 {
        if request.authorization().is_some() {
            return Err(HostExecutionHandoffErrorV1::Conflict);
        }
        let history = host.query_no_apply_settlement_v2(&claim, request, protected_boot_id)?;
        claim.revalidate()?;
        check_kernel_boot(protected_boot_id)?;
        let preliminary = history
            .as_ref()
            .and_then(|history| history.stage_bytes(HostNoApplySettlementPhaseV2::Preliminary))
            .map_or_else(Vec::new, <[u8]>::to_vec);
        let floor_sealed = history
            .as_ref()
            .and_then(|history| history.stage_bytes(HostNoApplySettlementPhaseV2::FloorSealed))
            .map_or_else(Vec::new, <[u8]>::to_vec);
        let ack_retained = history
            .as_ref()
            .and_then(|history| history.stage_bytes(HostNoApplySettlementPhaseV2::AckRetained))
            .map_or_else(Vec::new, <[u8]>::to_vec);
        let status = if !ack_retained.is_empty() {
            HostNoApplySettlementStatusV2::HOST_NO_APPLY_SETTLEMENT_STATUS_ACK_RETAINED
        } else if !floor_sealed.is_empty() {
            HostNoApplySettlementStatusV2::HOST_NO_APPLY_SETTLEMENT_STATUS_FLOOR_SEALED
        } else if !preliminary.is_empty() {
            HostNoApplySettlementStatusV2::HOST_NO_APPLY_SETTLEMENT_STATUS_PRELIMINARY
        } else {
            HostNoApplySettlementStatusV2::HOST_NO_APPLY_SETTLEMENT_STATUS_ABSENT
        };
        return Ok(QueryHostExecutionNoApplySettlementResponseV2 {
            status: status.into(),
            preliminary,
            floor_sealed,
            ack_retained,
            ..Default::default()
        }
        .encode_to_vec());
    }
    let artifacts = request
        .authorization()
        .ok_or(HostExecutionHandoffErrorV1::Conflict)?;
    if method == BrokerMethod::BROKER_METHOD_HOST_INSTALL_ATTACH_GATE {
        agent
            .as_ref()
            .ok_or(HostExecutionHandoffErrorV1::RecoveryRequired)?
            .validate_claim(&claim)?;
    }
    if matches!(
        method,
        BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_READINESS
            | BrokerMethod::BROKER_METHOD_HOST_QUERY_ATTACH_GATE_ROUTE
    ) {
        let agent = agent.ok_or(HostExecutionHandoffErrorV1::RecoveryRequired)?;
        agent.validate_claim(&claim)?;
        let proof = host.verify_authenticated_attach_query(
            &claim,
            method,
            body,
            request_id,
            artifacts,
            peer,
            policy,
            protected_boot_id,
        )?;
        if !proof.matches_claim(&claim) {
            return Err(HostExecutionHandoffErrorV1::Conflict);
        }
        let binding = *agent.session_binding().digest().as_bytes();
        match proof.request() {
            HostAttachReadOnlyRequestV1::Readiness(_) => {
                let trust = HostOpenSshStaticTrustV1::load_protected()?;
                let runtime = claim.currentness().runtime().currentness();
                let encoded = HostAttachGateReadinessV1 {
                    session_binding: binding.to_vec(),
                    incarnation_id: runtime.incarnation().as_bytes().to_vec(),
                    assignment_epoch: runtime.assignment_epoch().get(),
                    assignment_digest: runtime.assignment_digest().as_bytes().to_vec(),
                    lease_generation: proof.verified_lease().lease().lease_generation(),
                    lease_digest: proof.verified_lease().lease_digest().as_bytes().to_vec(),
                    trust_digest: trust.credential_digest().to_vec(),
                    ..Default::default()
                }
                .encode_to_vec();
                agent.validate_claim(&claim)?;
                if !proof.matches_claim(&claim) {
                    return Err(HostExecutionHandoffErrorV1::Conflict);
                }
                check_kernel_boot(protected_boot_id)?;
                return Ok(encoded);
            }
            HostAttachReadOnlyRequestV1::Route(request) => {
                let execution_id = request.execution_id();
                let operation_id = request.operation_id();
                let runtime = claim.currentness().runtime().currentness();
                let incarnation_id = *runtime.incarnation().as_bytes();
                let assignment_epoch = runtime.assignment_epoch().get();

                // Route readback opens the runtime journal to authenticate
                // the guest peer. Release this claim's exclusive journal
                // lock first, then prove the same Host runtime afterward.
                drop(claim);
                drop(owner);
                let mut routes = HostOpenSshAttachRouteOwnerV1::open()?;
                let evidence = routes.observe_active_on_session(
                    execution_id,
                    incarnation_id,
                    assignment_epoch,
                    binding,
                    agent,
                )?;
                if !evidence.matches_operation_execution(operation_id, execution_id) {
                    return Err(HostExecutionHandoffErrorV1::Conflict);
                }
                drop(routes);

                let mut owner = DormantRuntimeExecutionOwnerV1::open()?;
                let claim = owner.claim()?;
                agent.validate_claim(&claim)?;
                if !proof.matches_claim(&claim) {
                    return Err(HostExecutionHandoffErrorV1::Conflict);
                }
                check_kernel_boot(protected_boot_id)?;
                return Ok(evidence.encode_wire());
            }
        }
    }
    let reservation = host.reserve_authenticated_execution(
        &claim,
        request,
        execution_spec_content,
        protected_boot_id,
    )?;
    if !reservation.matches(method, request_id, body, &claim) {
        return Err(HostExecutionHandoffErrorV1::Conflict);
    }

    let result = match reservation.request() {
        HostExecutionGrantRequestV1::Apply(request) => {
            let effect = apply_execution(&mut claim, request)?;
            let effect = if effect.phase() == EffectPhaseV1::Pending {
                match agent {
                    Some(agent) => {
                        let deadline = agent_dispatch_deadline(deadline_boottime_nanoseconds)?;
                        agent.issue_pending_effect(
                            &mut claim,
                            &effect,
                            deadline,
                            deadline_boottime_nanoseconds,
                        )?
                    }
                    None => effect,
                }
            } else {
                effect
            };
            revoke_route_after_successful_cancel(&effect)?;
            outcome(
                request.operation_id(),
                request.execution_id(),
                request.source_commitment(),
                Some(&effect),
                &claim,
            )?
        }
        HostExecutionGrantRequestV1::Query(request) => {
            let effect = claim.load_effect(&request.operation_id())?;
            let effect = match effect {
                Some(effect) => {
                    let effect = validate_effect_identity(
                        effect,
                        &claim,
                        request.operation_id(),
                        request.execution_id(),
                        request.source_commitment(),
                    )?;
                    verify_query_content(
                        request.content_fields(),
                        effect.issue().operation(),
                        effect.admission().specification_bytes(),
                    )?;
                    Some(effect)
                }
                None => {
                    let admission = claim.load_admission(request.execution_id())?;
                    if let Some(admission) = admission {
                        let same_operation = admission.idempotency().operation().as_bytes()
                            == &request.operation_id()
                            && admission.idempotency().request_digest()
                                == request.source_commitment();
                        if same_operation {
                            verify_query_content(
                                request.content_fields(),
                                EffectOperationV1::AuthorizeExecution,
                                admission.specification_bytes(),
                            )?;
                            return Err(HostExecutionHandoffErrorV1::RecoveryRequired);
                        }
                        // A control query may precede its effect while the
                        // earlier Authorize admission already occupies this ID.
                        if !request.content_fields().is_control_marker() {
                            return Err(HostExecutionHandoffErrorV1::Conflict);
                        }
                    }
                    None
                }
            };
            if let Some(effect) = effect.as_ref() {
                revoke_route_after_successful_cancel(effect)?;
            }
            outcome(
                request.operation_id(),
                request.execution_id(),
                request.source_commitment(),
                effect.as_ref(),
                &claim,
            )?
        }
        HostExecutionGrantRequestV1::AttachGate(request) => {
            let agent = agent.ok_or(HostExecutionHandoffErrorV1::RecoveryRequired)?;
            // The route owner independently opens the protected runtime
            // journal for grant and guest-peer verification. Its lock cannot
            // be reacquired while this handoff still holds a claim.
            drop(claim);
            drop(owner);
            let result = (|| -> Result<Vec<u8>, HostExecutionHandoffErrorV1> {
                let mut routes = HostOpenSshAttachRouteOwnerV1::open()?;
                routes.reserve_from_pending_grant(
                    request.pending_grant(),
                    reservation.verified_lease(),
                )?;
                let grant =
                    HostOpenSshAttachRouteOwnerV1::verify_pending_grant(request.pending_grant())?;
                let binding = *agent.session_binding().digest().as_bytes();
                let evidence = routes.observe_active_on_session(
                    grant.execution_id,
                    grant.incarnation_id,
                    grant.assignment_epoch,
                    binding,
                    agent,
                )?;
                Ok(evidence.encode_wire())
            })();
            let mut owner = DormantRuntimeExecutionOwnerV1::open()?;
            let mut claim = owner.claim()?;
            let encoded = match result {
                Ok(encoded) => encoded,
                Err(error) => {
                    // No certificate is issued after a failed readback. Close
                    // this Host request so an exact grant can be retried with
                    // a new broker request after channel recovery.
                    claim.revalidate()?;
                    host.complete_authenticated_execution(&reservation, &claim, b"AOSHAF01")?;
                    return Err(error);
                }
            };
            agent.validate_claim(&claim)?;
            if !reservation.matches(method, request_id, body, &claim) {
                return Err(HostExecutionHandoffErrorV1::Conflict);
            }
            claim.revalidate()?;
            check_kernel_boot(protected_boot_id)?;
            host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
            return Ok(encoded);
        }
        HostExecutionGrantRequestV1::ReserveOutput(request) => {
            let verified = reservation
                .verified_output_source()
                .ok_or(HostExecutionHandoffErrorV1::Conflict)?;
            let receipt = claim.reserve_host_output_v1(verified)?;
            let encoded = output_reservation_response(request.locator(), Some(receipt))?;
            claim.revalidate()?;
            check_kernel_boot(protected_boot_id)?;
            host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
            return Ok(encoded);
        }
        HostExecutionGrantRequestV1::QueryOutput(request) => {
            let locator = request.locator();
            let receipt = claim.query_host_output_v1(
                locator.execution(),
                locator.create_operation(),
                locator.preissue_digest(),
                locator.claim_digest(),
                locator.carrier_digest(),
                locator.original_request_id(),
                locator.assignment_digest(),
                locator.host_boot_id(),
            )?;
            let encoded = output_reservation_response(locator, receipt)?;
            claim.revalidate()?;
            check_kernel_boot(protected_boot_id)?;
            host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
            return Ok(encoded);
        }
        HostExecutionGrantRequestV1::ObserveArgument(_) => {
            let agent = agent.ok_or(HostExecutionHandoffErrorV1::RecoveryRequired)?;
            agent.validate_claim(&claim)?;
            let deadline = agent_dispatch_deadline(deadline_boottime_nanoseconds)?;
            let receipt = reservation.observe_argument_once(&claim, agent, deadline)?;
            let encoded = ObserveHostExecutionArgumentResponseV1 {
                canonical_receipt: receipt.canonical_bytes(),
                ..Default::default()
            }
            .encode_to_vec();
            claim.revalidate()?;
            agent.validate_claim(&claim)?;
            if !reservation.matches(method, request_id, body, &claim) {
                return Err(HostExecutionHandoffErrorV1::Conflict);
            }
            check_kernel_boot(protected_boot_id)?;
            host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
            return Ok(encoded);
        }
        HostExecutionGrantRequestV1::QueryArgument(_) => {
            let receipt = host.query_authenticated_argument_historical(&reservation, &claim)?;
            let encoded = QueryHostExecutionArgumentResponseV1 {
                canonical_historical_receipt: receipt.canonical_bytes().to_vec(),
                ..Default::default()
            }
            .encode_to_vec();
            claim.revalidate()?;
            if !reservation.matches(method, request_id, body, &claim) {
                return Err(HostExecutionHandoffErrorV1::Conflict);
            }
            check_kernel_boot(protected_boot_id)?;
            host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
            return Ok(encoded);
        }
        HostExecutionGrantRequestV1::TerminalNoApply(terminal) => {
            let source = ControllerExecutionArgumentAttemptV1::decode_canonical(
                terminal.canonical_attempt(),
            )
            .map_err(|_| HostExecutionHandoffErrorV1::Conflict)?;
            // HostBroker is the single owner of its sealed state snapshot. Its
            // original method-37 readback preceded this runtime-journal append;
            // completion below rechecks that snapshot. This is not an atomic
            // cross-store fence against arbitrary same-UID replacement.
            let marker = claim.commit_host_no_apply_v1(
                &source,
                terminal.original_session_binding(),
                terminal.original_signed_request_digest(),
                request,
            )?;
            let encoded = TerminalHostExecutionArgumentNoApplyResponseV1 {
                canonical_record: marker.encode_canonical().to_vec(),
                ..Default::default()
            }
            .encode_to_vec();
            claim.revalidate()?;
            if !reservation.matches(method, request_id, body, &claim) {
                return Err(HostExecutionHandoffErrorV1::Conflict);
            }
            check_kernel_boot(protected_boot_id)?;
            host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
            return Ok(encoded);
        }
        HostExecutionGrantRequestV1::QueryNoApply(query) => {
            let source =
                ControllerExecutionArgumentAttemptV1::decode_canonical(query.canonical_attempt())
                    .map_err(|_| HostExecutionHandoffErrorV1::Conflict)?;
            let marker = claim.query_host_no_apply_v1(
                &source,
                query.original_session_binding(),
                query.original_signed_request_digest(),
            )?;
            let (status, canonical_record) = match marker {
                Some(marker) => (
                    HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_RECORDED,
                    marker.encode_canonical().to_vec(),
                ),
                None => (
                    HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_ABSENT,
                    Vec::new(),
                ),
            };
            let encoded = QueryHostExecutionArgumentNoApplyResponseV1 {
                status: status.into(),
                canonical_record,
                ..Default::default()
            }
            .encode_to_vec();
            claim.revalidate()?;
            if !reservation.matches(method, request_id, body, &claim) {
                return Err(HostExecutionHandoffErrorV1::Conflict);
            }
            check_kernel_boot(protected_boot_id)?;
            host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
            return Ok(encoded);
        }
    };
    claim.revalidate()?;
    check_kernel_boot(protected_boot_id)?;
    let encoded = result.encode_to_vec();
    host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
    Ok(encoded)
}

fn output_reservation_response(
    locator: HostOutputReservationLocatorV1,
    receipt: Option<ProtectedHostOutputReservationV1>,
) -> Result<Vec<u8>, HostExecutionHandoffErrorV1> {
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
                return Err(HostExecutionHandoffErrorV1::Conflict);
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

fn revoke_route_after_successful_cancel(
    effect: &DurableExecutionEffectV1,
) -> Result<(), HostExecutionHandoffErrorV1> {
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

fn check_kernel_boot(expected: [u8; 16]) -> Result<(), HostExecutionHandoffErrorV1> {
    let current = KernelBootId::current()
        .map_err(|_| HostExecutionHandoffErrorV1::KernelBoot)?
        .into_bytes();
    if current != expected {
        return Err(HostExecutionHandoffErrorV1::KernelBoot);
    }
    Ok(())
}

fn agent_dispatch_deadline(
    deadline_boottime_nanoseconds: u64,
) -> Result<Instant, HostExecutionHandoffErrorV1> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| HostExecutionHandoffErrorV1::Deadline)?;
    let nanoseconds =
        u64::try_from(now.tv_nsec).map_err(|_| HostExecutionHandoffErrorV1::Deadline)?;
    let now = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(HostExecutionHandoffErrorV1::Deadline)?;
    let remaining = deadline_boottime_nanoseconds
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(HostExecutionHandoffErrorV1::Deadline)?;
    Instant::now()
        .checked_add(Duration::from_nanos(remaining))
        .ok_or(HostExecutionHandoffErrorV1::Deadline)
}

fn apply_execution(
    claim: &mut DormantRuntimeExecutionClaimV1<'_>,
    request: &ValidatedHostExecutionApplyV1,
) -> Result<DurableExecutionEffectV1, HostExecutionHandoffErrorV1> {
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
        return Ok(effect);
    }

    let admission = match claim.load_admission(request.execution_id())? {
        Some(admission) => {
            if admission.currentness() != claim.currentness() {
                return Err(HostExecutionHandoffErrorV1::Conflict);
            }
            if request.action() == EffectOperationV1::Observe
                && admission.idempotency().request_digest() != request.source_commitment()
            {
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
    Ok(effect)
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

fn verify_query_content(
    requested: HostExecutionSpecContentFieldsV1,
    operation: EffectOperationV1,
    specification_bytes: &[u8],
) -> Result<(), HostExecutionHandoffErrorV1> {
    // The decoder checks Query's request-specific attempt; retained readback
    // compares only the stable content that was persisted for the Apply.
    let content = if operation == EffectOperationV1::AuthorizeExecution {
        specification_bytes
    } else {
        HOST_EXECUTION_CONTROL_CONTENT_V1
    };
    let retained = HostExecutionSpecContentFieldsV1::for_grant(content);
    if requested.bytes() != retained.bytes() || requested.digest() != retained.digest() {
        return Err(HostExecutionHandoffErrorV1::Conflict);
    }
    Ok(())
}

fn outcome(
    operation_id: [u8; 16],
    execution_id: ExecutionId,
    source_commitment: ObjectDigest,
    effect: Option<&DurableExecutionEffectV1>,
    claim: &DormantRuntimeExecutionClaimV1<'_>,
) -> Result<HostExecutionOutcomeV1, HostExecutionHandoffErrorV1> {
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

fn terminal_guest_result(
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    effect: &DurableExecutionEffectV1,
    completion: &aos_sandbox_core::runtime_backend::EffectCompletionV1,
) -> Result<Vec<u8>, HostExecutionHandoffErrorV1> {
    if effect.issue().operation() != EffectOperationV1::Observe
        || completion.status() != EffectCompletionStatusV1::Succeeded
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
    .map_err(|_| HostExecutionHandoffErrorV1::Conflict)?;
    let expected = match observed.phase() {
        BackendExecutionPhaseV1::Exited => AgentExecutionPhaseV1::Exited,
        BackendExecutionPhaseV1::Canceled => AgentExecutionPhaseV1::Canceled,
        _ => return Ok(Vec::new()),
    };

    // The fixed completion records only a phase and commitment. Recover the
    // original signed Guest packet under the same protected Host operation
    // before returning an exit status to the Controller.
    let committed = claim
        .recover_committed_host_agent_outcome(&operation_id)?
        .ok_or(HostExecutionHandoffErrorV1::RecoveryRequired)?;
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
        return Err(HostExecutionHandoffErrorV1::Conflict);
    }
    let bytes = authenticated.outcome().result_bytes();
    let parsed = decode_host_execution_terminal_result_v1(bytes)
        .map_err(|_| HostExecutionHandoffErrorV1::Conflict)?;
    if !matches!(
        (expected, parsed),
        (
            AgentExecutionPhaseV1::Exited,
            HostExecutionTerminalResultV1::Exited(_)
        ) | (
            AgentExecutionPhaseV1::Canceled,
            HostExecutionTerminalResultV1::Canceled
        )
    ) {
        return Err(HostExecutionHandoffErrorV1::Conflict);
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use aos_sandbox_protocol::host_output::{
        HostOutputReservationStatusV1, decode_host_output_reservation_response_v1,
        host_output_locator_from_source_v1,
    };

    use super::*;

    #[test]
    fn output_absence_echoes_exact_original_locator_without_commit_fields() {
        let mut source = [0_u8; 688];
        source[..8].copy_from_slice(b"AOSCIR01");
        source[8..16].copy_from_slice(b"AOSCIP01");
        source[16..32].fill(1);
        source[32..48].fill(2);
        source[104..120].fill(3);
        source[160..192].fill(4);
        source[192..200].copy_from_slice(b"AOSEOR02");
        source[200..216].fill(1);
        source[216..232].fill(2);
        source[624..656].fill(5);
        source[656..688].fill(6);
        let locator = host_output_locator_from_source_v1(&source, [7; 16]).unwrap();

        let body = output_reservation_response(locator, None).unwrap();
        let decoded = decode_host_output_reservation_response_v1(&body, locator, true).unwrap();
        assert_eq!(decoded.status(), HostOutputReservationStatusV1::Absent);
        assert!(decode_host_output_reservation_response_v1(&body, locator, false).is_err());
    }

    #[test]
    fn authorize_query_requires_exact_persisted_spec_content() {
        let persisted = b"canonical admission bytes";
        let matching = HostExecutionSpecContentFieldsV1::for_grant(persisted).bind_query_attempt(
            [1; 16],
            [2; 16],
            ExecutionId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([4; 32]),
        );
        let changed_digest =
            HostExecutionSpecContentFieldsV1::for_grant(b"canonical admission bytex");
        let changed_size = HostExecutionSpecContentFieldsV1::for_grant(b"shorter bytes");

        assert!(
            verify_query_content(matching, EffectOperationV1::AuthorizeExecution, persisted)
                .is_ok()
        );
        assert!(matches!(
            verify_query_content(
                changed_digest,
                EffectOperationV1::AuthorizeExecution,
                persisted,
            ),
            Err(HostExecutionHandoffErrorV1::Conflict)
        ));
        assert!(matches!(
            verify_query_content(
                changed_size,
                EffectOperationV1::AuthorizeExecution,
                persisted
            ),
            Err(HostExecutionHandoffErrorV1::Conflict)
        ));
    }

    #[test]
    fn control_query_requires_fixed_marker_even_with_an_admission_spec() {
        let marker = HostExecutionSpecContentFieldsV1::for_grant(HOST_EXECUTION_CONTROL_CONTENT_V1);
        let persisted = b"canonical admission bytes";
        let specification = HostExecutionSpecContentFieldsV1::for_grant(persisted);
        let operation = EffectOperationV1::ResizeTerminal {
            rows: 24,
            columns: 80,
        };

        assert!(verify_query_content(marker, operation, persisted).is_ok());
        assert!(matches!(
            verify_query_content(specification, operation, persisted),
            Err(HostExecutionHandoffErrorV1::Conflict)
        ));
    }
}
