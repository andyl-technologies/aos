//! Protected Host execution intent admission and exact outcome readback.
//!
//! The Broker Session ClientRecord authenticates each transport attempt. This
//! owner opens only fixed root-owned Host journals, derives runtime currentness
//! and effect sequence there, and uses the stable controller operation digest
//! solely as an idempotency and readback binding. Provisional output custody
//! remains distinct from execution authority. Pending work never crosses the
//! guest boundary without a separately authenticated AOSAGE route.

use aos_sandbox_host::execution_effect::{
    outcome, output_reservation_response, revoke_route_after_successful_cancel, validate_effect_identity,
};

use aos_sandbox_api::aos::sandbox::local::v1::{
    BrokerMethod, HostAttachGateReadinessV1, HostExecutionCompletionStatusV1,
    HostExecutionNoApplyStatusV1, HostExecutionOutcomeV1, HostExecutionPhaseV1, HostNoApplySettlementStatusV2,
    ObserveHostExecutionArgumentResponseV1,
    QueryHostExecutionArgumentNoApplyResponseV1,
    QueryHostExecutionArgumentResponseV1, QueryHostExecutionNoApplySettlementResponseV2,
    SettleHostExecutionNoApplyResponseV2, TerminalHostExecutionArgumentNoApplyResponseV1,
};
use aos_sandbox_controller_domain::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox_controller_domain::runtime_execution::{
    DormantRuntimeExecutionClaimV1, DormantRuntimeExecutionOwnerErrorV1,
    DormantRuntimeExecutionOwnerV1,
    decode_observe_completion_evidence_v1,
};
use aos_sandbox_guest_protocol::{AgentExecutionOperationV1, AgentExecutionPhaseV1};
use aos_sandbox_model::runtime_backend::{
    AdmissionCommitError, AdmissionIdempotencyV1, BackendExecutionPhaseV1,
    DurableExecutionEffectV1, EffectCommitError, EffectCompletionStatusV1, EffectIdempotencyV1,
    EffectIssueV1, EffectOperationV1, EffectPhaseV1, ExecutionAdmissionDraftV1,
    ExecutionAdmissionOutcomeV1, ExecutionEffectTransitionV1, admit_execution, prepare_effect,
};
use aos_sandbox_model::{ExecutionId, ObjectDigest};
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
use buffa::Message as _;

#[cfg(all(test, target_os = "linux"))]
mod method35_custody_tests;

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

impl From<aos_sandbox_host::execution_effect::HostExecutionEffectErrorV1>
    for HostExecutionHandoffErrorV1
{
    fn from(error: aos_sandbox_host::execution_effect::HostExecutionEffectErrorV1) -> Self {
        use aos_sandbox_host::execution_effect::HostExecutionEffectErrorV1 as E;
        match error {
            E::Owner(error) => Self::Owner(error),
            E::Admission(error) => Self::Admission(error),
            E::Effect(error) => Self::Effect(error),
            E::RecoveryRequired => Self::RecoveryRequired,
            E::Conflict => Self::Conflict,
            E::MissingAdmission => Self::MissingAdmission,
            E::Agent(error) => Self::Agent(error),
            E::AttachGate(error) => Self::AttachGate(error),
            E::Deadline => Self::Deadline,
        }
    }
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

    // The early branch requires its actual paid predurable Host owner. The
    // legacy dormant opener below cannot adopt that native interval from DATA.
    if request.host_before_argument_no_apply_data_v2().is_some() {
        return Err(HostExecutionHandoffErrorV1::Conflict);
    }
    // Closed43 must use its genuine already-held lease receiver. The legacy
    // historical opener cannot adopt that owner from comparison DATA.
    if request.host_no_apply_current_lease_query_data_v2().is_some()
        || request.host_held_no_apply_settlement_data_v2().is_some()
    {
        return Err(HostExecutionHandoffErrorV1::Conflict);
    }

    if matches!(method, BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
        | BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2)
    {
        return Err(HostExecutionHandoffErrorV1::Conflict);
    }
    check_kernel_boot(protected_boot_id)?;
    let mut owner = DormantRuntimeExecutionOwnerV1::open()?;
    let mut claim = owner.claim()?;
    if claim.host_verifier().boot_id() != protected_boot_id {
        return Err(HostExecutionHandoffErrorV1::KernelBoot);
    }
    if method == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT {
        return dispatch_host_storage_output_with_claim_v1(
            &claim,
            method,
            request.authorization().is_some(),
            execution_spec_content.is_some(),
            protected_boot_id,
            || host.observe_authenticated_storage_output(&claim, request, protected_boot_id),
            || Ok(()),
        );
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
                let mut routes = HostOpenSshAttachRouteOwnerV1::open()?;
                if routes.has_original_ticket_binding_v2(execution_id)? {
                    let evidence = proof.poll_original_attach_v3(&mut routes, &claim, agent)?;
                    agent.validate_claim(&claim)?;
                    if !proof.matches_claim(&claim) {
                        return Err(HostExecutionHandoffErrorV1::Conflict);
                    }
                    check_kernel_boot(protected_boot_id)?;
                    return Ok(evidence.encode_wire());
                }
                drop(routes);
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
            let effect = aos_sandbox_host::execution_effect::execute_reserved_effect_v1(
                &reservation, &mut claim, agent, deadline_boottime_nanoseconds, None,
            )?;
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
                        request.specification_digest(),
                        effect.issue().operation(),
                        effect.admission().specification_bytes(),
                        effect.admission().specification_digest(),
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
                                request.specification_digest(),
                                EffectOperationV1::AuthorizeExecution,
                                admission.specification_bytes(),
                                admission.specification_digest(),
                            )?;
                            return Err(HostExecutionHandoffErrorV1::RecoveryRequired);
                        }
                        // A control query may precede its effect while the
                        // earlier Authorize admission already occupies this ID.
                        if !request.content_fields().is_control_marker() {
                            return Err(HostExecutionHandoffErrorV1::Conflict);
                        }
                        if request.specification_digest() != admission.specification_digest() {
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
            if request.original_session_control_v5().is_some() {
                agent.validate_claim(&claim)?;
                let mut routes = HostOpenSshAttachRouteOwnerV1::open()?;
                let evidence = reservation.apply_original_control_v5(&mut routes, &claim, agent)?;
                agent.validate_claim(&claim)?;
                if !reservation.matches(method, request_id, body, &claim) {
                    return Err(HostExecutionHandoffErrorV1::Conflict);
                }
                claim.revalidate()?;
                check_kernel_boot(protected_boot_id)?;
                let encoded = evidence.encode_wire();
                host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
                return Ok(encoded);
            }
            if request.original_ticket_consume_v3().is_some() {
                agent.validate_claim(&claim)?;
                let mut routes = HostOpenSshAttachRouteOwnerV1::open()?;
                let evidence =
                    reservation.consume_original_attach_v3(&mut routes, &claim, agent)?;
                agent.validate_claim(&claim)?;
                if !reservation.matches(method, request_id, body, &claim) {
                    return Err(HostExecutionHandoffErrorV1::Conflict);
                }
                claim.revalidate()?;
                check_kernel_boot(protected_boot_id)?;
                let encoded = evidence.encode_wire();
                host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
                return Ok(encoded);
            }
            // The route owner independently opens the protected runtime
            // journal for grant and guest-peer verification. Its lock cannot
            // be reacquired while this handoff still holds a claim.
            drop(claim);
            drop(owner);
            let result = (|| -> Result<Vec<u8>, HostExecutionHandoffErrorV1> {
                let mut routes = HostOpenSshAttachRouteOwnerV1::open()?;
                if let Some(ticket) = request.original_ticket_binding_v2() {
                    // Binding an original ticket measures an existing route;
                    // it must not create or renew a pending grant.
                    let binding = *agent.session_binding().digest().as_bytes();
                    let evidence = routes.bind_original_ticket_on_session_v2(
                        request.pending_grant(),
                        ticket,
                        reservation.verified_lease(),
                        binding,
                        agent,
                    )?;
                    return Ok(evidence.encode_wire());
                }
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
            return Err(HostExecutionHandoffErrorV1::Conflict);
        }
        HostExecutionGrantRequestV1::PrepareArgumentV2(_)
        | HostExecutionGrantRequestV1::AcceptArgumentV2(_) => {
            return Err(HostExecutionHandoffErrorV1::Conflict);
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
        HostExecutionGrantRequestV1::TerminalBeforeArgumentNoApply(_)
            | HostExecutionGrantRequestV1::QueryBeforeArgumentNoApply(_) => {
            return Err(HostExecutionHandoffErrorV1::Conflict);
        }
    };
    claim.revalidate()?;
    check_kernel_boot(protected_boot_id)?;
    let encoded = result.encode_to_vec();
    host.complete_authenticated_execution(&reservation, &claim, &encoded)?;
    Ok(encoded)
}

// Production reaches this path only after opening the fixed protected owner.
// The test-only entry can lend a normally provisioned claim without replacing
// the production opener or weakening the Host grant and lease admission.
fn dispatch_host_storage_output_with_claim_v1<F, R>(
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    method: BrokerMethod,
    authorized: bool,
    descriptor_present: bool,
    protected_boot_id: [u8; 16],
    observe: F,
    mut revalidate: R,
) -> Result<Vec<u8>, HostExecutionHandoffErrorV1>
where
    F: FnOnce() -> Result<Vec<u8>, aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    R: FnMut() -> Result<(), DormantRuntimeExecutionOwnerErrorV1>,
{
    validate_storage_output_claim_v1(claim, protected_boot_id, &mut revalidate)?;
    if method != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
        || !authorized
        || descriptor_present
    {
        return Err(HostExecutionHandoffErrorV1::Conflict);
    }

    let body = observe()?;
    validate_storage_output_claim_v1(claim, protected_boot_id, &mut revalidate)?;
    Ok(body)
}

fn validate_storage_output_claim_v1<R>(
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    protected_boot_id: [u8; 16],
    revalidate: &mut R,
) -> Result<(), HostExecutionHandoffErrorV1>
where
    R: FnMut() -> Result<(), DormantRuntimeExecutionOwnerErrorV1>,
{
    check_kernel_boot(protected_boot_id)?;
    // The injected test validator can only add a failure. The real protected
    // claim is always revalidated before and after the Host observation.
    claim.revalidate()?;
    revalidate()?;
    if claim.host_verifier().boot_id() != protected_boot_id {
        return Err(HostExecutionHandoffErrorV1::KernelBoot);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn dispatch_host_storage_output_with_claim_for_test_v1<F, R>(
    claim: &DormantRuntimeExecutionClaimV1<'_>,
    method: BrokerMethod,
    authorized: bool,
    descriptor_present: bool,
    protected_boot_id: [u8; 16],
    observe: F,
    revalidate: R,
) -> Result<Vec<u8>, HostExecutionHandoffErrorV1>
where
    F: FnOnce() -> Result<Vec<u8>, aos_sandbox_host::DormantHostBrokerCallErrorV1>,
    R: FnMut() -> Result<(), DormantRuntimeExecutionOwnerErrorV1>,
{
    dispatch_host_storage_output_with_claim_v1(
        claim,
        method,
        authorized,
        descriptor_present,
        protected_boot_id,
        observe,
        revalidate,
    )
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







fn verify_query_content(
    requested: HostExecutionSpecContentFieldsV1,
    requested_specification_digest: ObjectDigest,
    operation: EffectOperationV1,
    specification_bytes: &[u8],
    admitted_specification_digest: ObjectDigest,
) -> Result<(), HostExecutionHandoffErrorV1> {
    // The decoder checks Query's request-specific attempt; retained readback
    // compares only the stable content that was persisted for the Apply.
    let content = if operation == EffectOperationV1::AuthorizeExecution {
        specification_bytes
    } else {
        HOST_EXECUTION_CONTROL_CONTENT_V1
    };
    let retained = HostExecutionSpecContentFieldsV1::for_grant(content);
    if requested.bytes() != retained.bytes()
        || requested.digest() != retained.digest()
        || requested_specification_digest != admitted_specification_digest
    {
        return Err(HostExecutionHandoffErrorV1::Conflict);
    }
    Ok(())
}





#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_linux::boot::KernelBootId;
    use aos_sandbox_protocol::host_output::{
        HostOutputReservationStatusV1, decode_host_output_reservation_response_v1,
        host_output_locator_from_source_v1,
    };

    use super::*;

    #[test]
    fn injected_storage_output_owner_rejects_foreign_boot_and_stale_claim_before_observation() {
        let directory = tempfile::TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let mut owner = DormantRuntimeExecutionOwnerV1::provisioned_protected_at_uid_for_test(
            directory.path(),
            uid,
        )
        .unwrap();
        let claim = owner.claim().unwrap();
        let boot = KernelBootId::current().unwrap().into_bytes();
        let method = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT;
        let never_observe = || -> Result<_, aos_sandbox_host::DormantHostBrokerCallErrorV1> {
            panic!("a rejected claim cannot reach Host observation")
        };

        let mut foreign_boot = boot;
        foreign_boot[0] ^= 0x80;
        assert!(matches!(
            dispatch_host_storage_output_with_claim_for_test_v1(
                &claim,
                method,
                true,
                false,
                foreign_boot,
                never_observe,
                || Ok(()),
            ),
            Err(HostExecutionHandoffErrorV1::KernelBoot)
        ));
        assert!(matches!(
            dispatch_host_storage_output_with_claim_for_test_v1(
                &claim,
                method,
                true,
                false,
                boot,
                never_observe,
                || Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness),
            ),
            Err(HostExecutionHandoffErrorV1::Owner(
                DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness
            ))
        ));
    }

    #[test]
    fn injected_storage_output_owner_rejects_stale_claim_after_observation() {
        let directory = tempfile::TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let mut owner = DormantRuntimeExecutionOwnerV1::provisioned_protected_at_uid_for_test(
            directory.path(),
            uid,
        )
        .unwrap();
        let claim = owner.claim().unwrap();
        let boot = KernelBootId::current().unwrap().into_bytes();
        let mut observed = false;
        let mut validation_calls = 0;

        let result = dispatch_host_storage_output_with_claim_for_test_v1(
            &claim,
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT,
            true,
            false,
            boot,
            || {
                observed = true;
                Ok(vec![0x48])
            },
            || {
                validation_calls += 1;
                if validation_calls == 2 {
                    Err(DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness)
                } else {
                    Ok(())
                }
            },
        );

        assert!(observed);
        assert_eq!(validation_calls, 2);
        assert!(matches!(
            result,
            Err(HostExecutionHandoffErrorV1::Owner(
                DormantRuntimeExecutionOwnerErrorV1::StaleCurrentness
            ))
        ));
    }

    #[test]
    fn injected_storage_output_owner_keeps_authorization_and_descriptor_fences() {
        let directory = tempfile::TempDir::new_in(std::env::current_dir().unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let mut owner = DormantRuntimeExecutionOwnerV1::provisioned_protected_at_uid_for_test(
            directory.path(),
            uid,
        )
        .unwrap();
        let claim = owner.claim().unwrap();
        let boot = KernelBootId::current().unwrap().into_bytes();
        let method = BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT;
        let never_observe = || -> Result<_, aos_sandbox_host::DormantHostBrokerCallErrorV1> {
            panic!("a rejected shape cannot reach Host observation")
        };

        for (candidate_method, authorized, descriptor_present) in [
            (
                BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_OUTPUT,
                true,
                false,
            ),
            (method, false, false),
            (method, true, true),
        ] {
            assert!(matches!(
                dispatch_host_storage_output_with_claim_for_test_v1(
                    &claim,
                    candidate_method,
                    authorized,
                    descriptor_present,
                    boot,
                    never_observe,
                    || Ok(()),
                ),
                Err(HostExecutionHandoffErrorV1::Conflict)
            ));
        }
    }

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
            verify_query_content(
                matching,
                ObjectDigest::from_bytes([5; 32]),
                EffectOperationV1::AuthorizeExecution,
                persisted,
                ObjectDigest::from_bytes([5; 32]),
            )
            .is_ok()
        );
        assert!(matches!(
            verify_query_content(
                changed_digest,
                ObjectDigest::from_bytes([5; 32]),
                EffectOperationV1::AuthorizeExecution,
                persisted,
                ObjectDigest::from_bytes([5; 32]),
            ),
            Err(HostExecutionHandoffErrorV1::Conflict)
        ));
        assert!(matches!(
            verify_query_content(
                changed_size,
                ObjectDigest::from_bytes([5; 32]),
                EffectOperationV1::AuthorizeExecution,
                persisted,
                ObjectDigest::from_bytes([5; 32]),
            ),
            Err(HostExecutionHandoffErrorV1::Conflict)
        ));
        assert!(matches!(
            verify_query_content(
                matching,
                ObjectDigest::from_bytes([6; 32]),
                EffectOperationV1::AuthorizeExecution,
                persisted,
                ObjectDigest::from_bytes([5; 32]),
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

        assert!(
            verify_query_content(
                marker,
                ObjectDigest::from_bytes([5; 32]),
                operation,
                persisted,
                ObjectDigest::from_bytes([5; 32]),
            )
            .is_ok()
        );
        assert!(matches!(
            verify_query_content(
                specification,
                ObjectDigest::from_bytes([5; 32]),
                operation,
                persisted,
                ObjectDigest::from_bytes([5; 32]),
            ),
            Err(HostExecutionHandoffErrorV1::Conflict)
        ));
    }
}
