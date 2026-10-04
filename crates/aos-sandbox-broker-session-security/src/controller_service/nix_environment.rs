//! Drives one genuine retained Start through the installed online Resolve50 owner.
//!
//! The SAME Controller worker retains this partial attempt beside its sessions.
//! Short current/input loans borrow the original selector and actual Controller
//! writer. Resolve observes already installed inputs; it cannot produce a build,
//! output publication, completed Start, fresh lease or population-drain result.

use std::path::Path;
use std::sync::Arc;

use aos_proto::aos::sandbox::local::v1::{
    BrokerAuthorizationArtifactsV1, BrokerMethod, BrokerRequestEnvelope, NixBuildResponseV2,
};
use aos_sandbox::production_operation_compiler::{
    ControllerNixStartRecipeSelectorV2, CurrentRetainedNixStartV2,
    NixResolveAuthorizationDraftV2, NixStartAdmissionErrorV2, NixStartContinuationErrorV2,
};
use aos_sandbox::{EffectFailure, EffectObservation, EffectPlan, EffectReceipt, SignedBrokerPlan};
use aos_sandbox_core::OperationId;
use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RetainedSeqpacketAdmissionErrorV1, RetainedSeqpacketReceiveErrorV1,
    SeqpacketError, SeqpacketSocket,
};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2;

use super::nix_inputs::{NixLocalInputCutV2, NixLocalInputErrorV2};
use super::{ControllerResidentCauseV1, ControllerWorkerCustodyV1, ProductionEffectExecutor};
use crate::controller_plan_signer::{ControllerBrokerPlanSignerError, ControllerBrokerPlanSignerV1};
use crate::handshake::{
    ColdClientHandshakeProgressV1, DormantAuthenticatedBrokerSessionV1,
    DormantControllerClientHandshakeV1, OnlineRequestNativeResultV1, OnlineTransportFailureV1,
    OriginalBrokerColdDeadlineV1, RetainedStorageColdOpenV1, begin_online_resolve_client,
    online_resolve_client_hello,
};
use crate::nix_service::floor::{OnlineOriginV1, OnlineProvisionV1};
use crate::{
    BrokerSessionSecurityError, DormantBrokerSessionHandshakeErrorV1,
    ProtectedBrokerOutcomeAdmissionGateV1, ProtectedBrokerOutcomeAdmissionV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerSessionClientV1,
};

const ROOT: &str = "/var/lib/aos/sandboxd/broker-session/nix";
const SOCKET: &str = "/run/aos/sandbox-nix/control.sock";
const RESOLVE: BrokerMethod = BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2;

#[derive(Debug, thiserror::Error)]
pub(super) enum NixResolveFailureV1 {
    #[error("original current Start failed: {0}")]
    Current(#[from] NixStartContinuationErrorV2),
    #[error("original startup floor loan failed: {0}")]
    Startup(#[from] NixStartAdmissionErrorV2),
    #[error("original local input cut failed: {0}")]
    Inputs(#[from] NixLocalInputErrorV2),
    #[error("independent ONLINE058 floor failed: {0}")]
    Floor(#[from] crate::tpm_nv_custody::FloorErrorV1),
    #[error("original protected Session failed: {0}")]
    Protected(#[from] BrokerSessionSecurityError),
    #[error("original HELLO or deadline failed: {0}")]
    Handshake(#[from] DormantBrokerSessionHandshakeErrorV1),
    #[error("selected canonical HELLO failed: {0}")]
    Negotiation(#[from] aos_sandbox_broker_session_protocol::BrokerSessionNegotiationError),
    #[error("original selected transport failed: {0}")]
    Transport(#[from] OnlineTransportFailureV1),
    #[error("selected original response failed: {0}")]
    Response(#[from] aos_sandbox_protocol::ProtocolValidationError),
    #[error("the actual socket admission cause remains in its whole result")]
    Socket,
    #[error("the actual plan-signing cause remains in its whole result")]
    Signer,
    #[error("the exact native target/result remains resident and unconfirmed")]
    Native,
    #[error("selected Resolve attempt is permanently closed")]
    Closed,
}

/// Retains one selected attempt; ordinary None creates no floor or input owner.
pub(super) struct NixResolveAttemptV1 {
    operation: OperationId,
    step: u32,
    provision: Option<OnlineProvisionV1>,
    connected: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    endpoint_custody: Option<ProtectedBrokerSessionClientV1>,
    pending: Option<DormantControllerClientHandshakeV1>,
    cold: Option<RetainedStorageColdOpenV1>,
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    draft: Option<NixResolveAuthorizationDraftV2>,
    signed: Option<Result<SignedBrokerPlan, ControllerBrokerPlanSignerError>>,
    request: Option<Result<(AuthenticatedBrokerMethodRequestV1, bool), BrokerSessionSecurityError>>,
    checked: Option<Result<ValidatedNixBuildRequestV2, aos_sandbox_protocol::ProtocolValidationError>>,
    native_request: Option<OnlineRequestNativeResultV1>,
    dispatch_started: bool,
    send_failure: Option<SeqpacketError>,
    record: Option<ReceivedRecord>,
    receive_failure: Option<RetainedSeqpacketReceiveErrorV1>,
    canonical: Option<Result<
        aos_sandbox_broker_session_protocol::CanonicalBrokerResponseEnvelopeV1,
        aos_sandbox_broker_session_protocol::BrokerSessionProjectionError,
    >>,
    gate: Option<Result<(
        ProtectedBrokerOutcomeAdmissionGateV1,
        aos_sandbox_broker_session_protocol::ProtectedBrokerSessionVerificationContextV1,
    ), BrokerSessionSecurityError>>,
    admitted: Option<Result<ProtectedBrokerOutcomeAdmissionV1, BrokerSessionSecurityError>>,
    response: Option<Result<NixBuildResponseV2, aos_sandbox_protocol::ProtocolValidationError>>,
    native_outcome: Option<ProtectedBrokerOutcomeCommitResultV1>,
    completed: bool,
    first_failure: Option<NixResolveFailureV1>,
}

impl NixResolveAttemptV1 {
    fn new(operation: OperationId, step: u32) -> Self {
        Self {
            operation,
            step,
            provision: None,
            connected: None,
            endpoint_custody: None,
            pending: None,
            cold: None,
            session: None,
            draft: None,
            signed: None,
            request: None,
            checked: None,
            native_request: None,
            dispatch_started: false,
            send_failure: None,
            record: None,
            receive_failure: None,
            canonical: None,
            gate: None,
            admitted: None,
            response: None,
            native_outcome: None,
            completed: false,
            first_failure: None,
        }
    }

    fn terminate(&mut self, worker: &ControllerWorkerCustodyV1, cause: NixResolveFailureV1) -> ! {
        self.first_failure.get_or_insert(cause);
        // The same parent graph already owns this attempt and Controller.
        // Termination occurs before ephemeral current/input loan teardown.
        worker.terminate(ControllerResidentCauseV1::NixResolve)
    }

    fn connect(
        &mut self,
        selector: &Arc<ControllerNixStartRecipeSelectorV2>,
        current: &mut CurrentRetainedNixStartV2<'_>,
        worker: &ControllerWorkerCustodyV1,
        node: [u8; 16],
    ) {
        macro_rules! checked {
            ($value:expr) => {
                match $value {
                    Ok(value) => value,
                    Err(cause) => self.terminate(worker, cause.into()),
                }
            };
        }
        checked!(current.recheck());
        let mut original = Some(Arc::clone(selector));
        let mut loan = Some(checked!(selector.borrow_session_floor_origin_v2()));
        let mut retained = None;
        checked!(aos_sandbox::normal_root::ControllerNixSessionFloorOriginV2::retain_original_into(
            &mut loan, &mut original, &mut retained,
        ));
        drop(loan);
        let origin = match retained {
            Some(origin) => OnlineOriginV1::controller(origin),
            None => self.terminate(worker, NixResolveFailureV1::Closed),
        };
        self.provision = Some(OnlineProvisionV1::new(origin));
        let provision = match self.provision.as_mut() {
            Some(provision) => provision,
            None => self.terminate(worker, NixResolveFailureV1::Closed),
        };
        checked!(provision.admit());
        if checked!(provision.profile()).node() != node {
            self.terminate(worker, NixResolveFailureV1::Closed);
        }
        checked!(current.recheck());

        let deadline = checked!(OriginalBrokerColdDeadlineV1::controller());
        self.connected = Some(SeqpacketSocket::connect_retaining(Path::new(SOCKET)));
        if self.connected.as_ref().is_none_or(Result::is_err) {
            self.terminate(worker, NixResolveFailureV1::Socket);
        }
        checked!(deadline.check());
        checked!(current.recheck());
        self.endpoint_custody = Some(checked!(ProtectedBrokerSessionClientV1::load(Path::new(ROOT))));
        let hello = checked!(online_resolve_client_hello());
        let custody = match self.endpoint_custody.take() {
            Some(custody) => custody,
            None => self.terminate(worker, NixResolveFailureV1::Closed),
        };
        let socket = match self.connected.take() {
            Some(Ok(socket)) => socket,
            original => {
                self.connected = original;
                self.terminate(worker, NixResolveFailureV1::Closed);
            }
        };
        self.pending = Some(checked!(begin_online_resolve_client(custody, socket, hello)));
        loop {
            checked!(current.recheck());
            checked!(deadline.check());
            let pending = match self.pending.as_ref() {
                Some(pending) => pending,
                None => self.terminate(worker, NixResolveFailureV1::Closed),
            };
            checked!(crate::dormant_handshake::wait_for_handshake_readiness(
                checked!(pending.as_fd()), pending.wants_write(), deadline.value(),
            ));
            checked!(current.recheck());
            let pending = match self.pending.take() {
                Some(pending) => pending,
                None => self.terminate(worker, NixResolveFailureV1::Closed),
            };
            match checked!(pending.advance_retaining_storage()) {
                ColdClientHandshakeProgressV1::Pending(pending) => self.pending = Some(pending),
                ColdClientHandshakeProgressV1::Verified(verified) => {
                    let provision = match self.provision.take() {
                        Some(provision) => provision,
                        None => self.terminate(worker, NixResolveFailureV1::Closed),
                    };
                    self.cold = Some(RetainedStorageColdOpenV1::retain_online(verified, deadline, provision));
                    break;
                }
                ColdClientHandshakeProgressV1::Complete(_) => {
                    self.terminate(worker, NixResolveFailureV1::Closed);
                }
            }
        }
        let cold = match self.cold.as_mut() {
            Some(cold) => cold,
            None => self.terminate(worker, NixResolveFailureV1::Closed),
        };
        self.session = Some(checked!(cold.finish(Some(node))));
        checked!(current.recheck());
    }
}

/// Holds the completed observation without calling it an Applied Start Effect.
pub(super) fn observe(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    step: u32,
) -> Result<EffectObservation, EffectFailure> {
    let sessions = executor.sessions.lock()
        .map_err(|_| EffectFailure::Permanent("Nix Session owner lock is poisoned".to_owned()))?;
    if let Some(attempt) = sessions.nix_resolve.as_ref() {
        if attempt.operation != operation || attempt.step != step || attempt.first_failure.is_some() {
            return Err(EffectFailure::Permanent("original Nix Resolve attempt is closed".to_owned()));
        }
        if attempt.completed {
            return Err(EffectFailure::Retryable(
                "Resolve50 is retained; Start still requires the actual Realize51 owner".to_owned(),
            ));
        }
    }
    Ok(EffectObservation::Absent)
}

pub(super) fn resolve(
    executor: &mut ProductionEffectExecutor,
    operation: OperationId,
    step: u32,
    plan: &EffectPlan,
    journal: &mut aos_sandbox::journal::Journal,
) -> Result<EffectReceipt, EffectFailure> {
    let selector = executor.nix_start.as_ref().map(Arc::clone).ok_or_else(|| {
        EffectFailure::Permanent("genuine selected Nix startup is absent".to_owned())
    })?;
    let shared = Arc::clone(&executor.sessions);
    let mut sessions = shared.lock()
        .map_err(|_| EffectFailure::Permanent("Nix Session owner lock is poisoned".to_owned()))?;
    let worker = sessions.storage_terminal.as_ref().and_then(std::sync::Weak::upgrade)
        .ok_or_else(|| EffectFailure::Permanent("selected Nix worker destination is absent".to_owned()))?;
    if sessions.nix_resolve.is_some() {
        return Err(EffectFailure::Permanent("original Nix Resolve cannot be replaced or resent".to_owned()));
    }
    sessions.nix_resolve = Some(NixResolveAttemptV1::new(operation, step));
    let super::ControllerBrokerSessions { nix_resolve, nix_input_source, .. } = &mut *sessions;
    let attempt = match nix_resolve.as_mut() {
        Some(attempt) => attempt,
        None => worker.terminate(ControllerResidentCauseV1::NixResolve),
    };
    macro_rules! checked {
        ($value:expr) => {
            match $value {
                Ok(value) => value,
                Err(cause) => attempt.terminate(&worker, cause.into()),
            }
        };
    }
    let mut current = checked!(selector.borrow_current_retained_start_v2(journal, operation, step, plan));
    let _current_unwind = super::AbortControllerCustodyUnwindV1;
    attempt.connect(&selector, &mut current, &worker, *executor.node.as_bytes());
    *nix_input_source = Some(checked!(super::nix_inputs::open_fixed_input_source_v2(&mut current)));
    let source = match nix_input_source.as_ref() {
        Some(source) => source,
        None => attempt.terminate(&worker, NixResolveFailureV1::Closed),
    };
    let mut cut = checked!(super::nix_inputs::pin_local_inputs_v2(&mut current, source));
    let _cut_unwind = super::AbortControllerCustodyUnwindV1;
    let signer = match executor.broker_plan_signer.as_ref() {
        Some(signer) => signer,
        None => attempt.terminate(&worker, NixResolveFailureV1::Closed),
    };
    if let Err(cause) = exchange(attempt, &mut cut, signer) {
        attempt.terminate(&worker, cause);
    }
    attempt.completed = true;
    drop(cut);
    drop(current);
    // The actual Resolve result/floor stay in SAME sessions. Generic Effect
    // success would falsely complete Start without build/output owners.
    Err(EffectFailure::Retryable(
        "Resolve50 is durably retained; Realize51 and publication remain required".to_owned(),
    ))
}

fn exchange(
    attempt: &mut NixResolveAttemptV1,
    cut: &mut NixLocalInputCutV2<'_, '_>,
    signer: &ControllerBrokerPlanSignerV1,
) -> Result<(), NixResolveFailureV1> {
    let session = attempt.session.as_mut().ok_or(NixResolveFailureV1::Closed)?;
    let (request_id, _, maximum, _, _) = session.client_request_coordinates()?;
    if maximum < aos_sandbox_protocol::nix_build::NIX_RESPONSE_MAXIMUM_BYTES_V2 as u32 {
        return Err(NixResolveFailureV1::Closed);
    }
    cut.retain_authorization_into(request_id, &mut attempt.draft)?;
    let draft = attempt.draft.as_ref().ok_or(NixResolveFailureV1::Closed)?;
    attempt.signed = Some(signer.sign_plan(draft.plan().clone(), draft.observed().wall_seconds()));
    let signed = match attempt.signed.as_ref() {
        Some(Ok(signed)) => signed,
        _ => return Err(NixResolveFailureV1::Signer),
    };
    cut.recheck()?;
    let quartet_size = [signed.canonical_plan(), signed.canonical_signature(),
        draft.lease().canonical_lease(), draft.lease().canonical_signature(), draft.request_bytes()]
        .iter().try_fold(0_usize, |total, bytes| total.checked_add(bytes.len()))
        .ok_or(NixResolveFailureV1::Closed)?;
    if quartet_size > 1_048_576 {
        return Err(NixResolveFailureV1::Closed);
    }
    let artifacts = BrokerAuthorizationArtifactsV1 {
        broker_plan: signed.canonical_plan().to_vec(),
        broker_plan_signature: signed.canonical_signature().to_vec(),
        ownership_lease: draft.lease().canonical_lease().to_vec(),
        ownership_lease_signature: draft.lease().canonical_signature().to_vec(),
        ..Default::default()
    };
    let original_d = cut.original_deadline_boottime_nanoseconds();
    let body = draft.request_bytes().to_vec();
    attempt.request = Some(session.prepare_client_request(BrokerRequestEnvelope {
        method: RESOLVE.into(), body, authorization: Some(artifacts).into(), ..Default::default()
    }, RESOLVE, 0, request_id, original_d,
        aos_sandbox_protocol::nix_build::NIX_RESPONSE_MAXIMUM_BYTES_V2 as u32));
    let (request, initialize) = match attempt.request.as_ref() {
        Some(Ok(result)) => result,
        _ => return Err(NixResolveFailureV1::Native),
    };
    cut.recheck()?;
    session.decode_online_request_into(request, &mut attempt.checked)?;
    let checked = match attempt.checked.as_ref() {
        Some(Ok(checked)) => checked,
        _ => return Err(NixResolveFailureV1::Closed),
    };
    session.retain_online_admission(request, checked)?;
    cut.recheck()?;
    session.retain_online_request_commit_into(request, *initialize, &mut attempt.native_request)?;
    cut.recheck()?;
    session.finish_online_native_step(request)?;
    crate::dormant_handshake::wait_for_handshake_readiness(session.as_fd()?, true, original_d)?;
    cut.recheck()?;
    attempt.dispatch_started = true;
    session.send_online_packet(request, request.canonical_packet(), &mut attempt.send_failure)?;
    cut.recheck()?;
    loop {
        session.require_online_request(request)?;
        crate::dormant_handshake::wait_for_handshake_readiness(session.as_fd()?, false, original_d)?;
        cut.recheck()?;
        if session.receive_online_record_into(&mut attempt.record, &mut attempt.receive_failure)? {
            break;
        }
        cut.recheck()?;
    }
    cut.recheck()?;
    attempt.canonical = Some(aos_sandbox_broker_session_protocol::decode_canonical_response_v1(
        attempt.record.as_ref().ok_or(NixResolveFailureV1::Closed)?.payload(),
    ));
    let canonical = match attempt.canonical.as_ref() {
        Some(Ok(canonical)) => canonical,
        _ => return Err(NixResolveFailureV1::Closed),
    };
    attempt.gate = Some(session.reopen_broker_outcome(request));
    cut.recheck()?;
    let gate = match attempt.gate.take() {
        Some(Ok((gate, _context))) => gate,
        original => {
            attempt.gate = original;
            return Err(NixResolveFailureV1::Native);
        }
    };
    attempt.admitted = Some(gate.admit_outcome(canonical));
    if attempt.admitted.as_ref().is_none_or(Result::is_err) {
        return Err(NixResolveFailureV1::Native);
    }
    attempt.response = Some(aos_sandbox_protocol::nix_build::decode_nix_build_response_v2(
        &canonical.message().body, checked, RESOLVE,
    ));
    let response = match attempt.response.as_ref() {
        Some(Ok(response)) => response,
        _ => return Err(NixResolveFailureV1::Closed),
    };
    if response.recipe_admission != cut.recipe_artifact().canonical_bytes() {
        return Err(NixResolveFailureV1::Closed);
    }
    cut.recheck()?;
    session.require_online_request(request)?;
    let pending = match attempt.admitted.take() {
        Some(Ok(ProtectedBrokerOutcomeAdmissionV1::New { advancement })) => advancement,
        original => {
            attempt.admitted = original;
            return Err(NixResolveFailureV1::Native);
        }
    };
    attempt.native_outcome = Some(session.commit_broker_outcome(pending));
    if !matches!(attempt.native_outcome.as_ref(), Some(ProtectedBrokerOutcomeCommitResultV1::Committed(_))) {
        return Err(NixResolveFailureV1::Native);
    }
    cut.recheck()?;
    session.finish_online_native_step(request)?;
    cut.recheck()?;
    session.require_online_transport(request)?;
    Ok(())
}
