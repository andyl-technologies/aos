//! Owns the selected online Nix service and its independently provisioned floor.
//!
//! The fixed service uses the existing authenticated Session, journal reducer,
//! retained process supervisor and selected upstream Store reader. Resolve50
//! observes already admitted immutable inputs. A separately selected mode
//! realizes only independently enrolled existing outputs with retained real
//! GC roots, then queries those same originals. Missing-output builds, current
//! generation publication, NV initialization and successful Start stay outside
//! this owner; no offline approval substitutes for online custody.

pub(crate) mod floor;
mod store;
mod roots;

use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, BrokerResponseEnvelope, NixBuildResponseV2};
use aos_sandbox::normal_root::{
    NixOwnerPublicSessionFloorOriginV2, NormalRootStartupErrorV1,
    ProductionNixOwnerStartupCaptureV1, ProductionNixOwnerStartupV1,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RecordSubjectListener, RecordSubjectListenerAdmissionAttemptV1,
    RetainedSeqpacketAdmissionErrorV1, RetainedSeqpacketReceiveErrorV1, SeqpacketError,
    SeqpacketSocket,
};
use aos_sandbox_protocol::nix_build::{
    NixBuildObservationV2, NixBuildSchemaErrorV2, ValidatedNixBuildRequestV2,
    VerifiedNixRecipeArtifactV2,
};
use buffa::Message as _;

use crate::handshake::{
    ColdBrokerHandshakeProgressV1, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerEndpointHandshakeV1, OnlineRequestNativeResultV1, OnlineTransportFailureV1,
    OriginalBrokerColdDeadlineV1, RetainedStorageColdOpenV1, begin_online_resolve_broker,
    online_resolve_server_hello, online_existing_output_server_hello,
};
use crate::recovery::ProtectedBrokerReceivedRequestAdmissionV1;
use crate::{
    BrokerSessionSecurityError, DormantBrokerSessionHandshakeErrorV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerOutcomePendingAdvancementV1,
    ProtectedBrokerSessionBrokerV1,
};

const SOCKET: &str = "/run/aos/sandbox-nix/control.sock";
const ROOT: &str = "/var/lib/aos/sandbox-nix/broker-session/controller";
const RESOLVE: BrokerMethod = BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2;

/// Reports an error before the installed owner has returned original custody.
#[derive(Debug, thiserror::Error)]
pub enum OnlineNixServiceError {
    /// The selected unit did not supply its four identities and optional mode.
    #[error("online Nix service expects four nonzero decimal identities and an optional existing-outputs mode")]
    Arguments,
    /// The original complete launch-table capture failed.
    #[error("online Nix original startup capture failed: {0}")]
    Startup(#[from] NormalRootStartupErrorV1),
}

#[derive(Debug, thiserror::Error)]
enum OwnerFailureV1 {
    #[error("original selected startup failed: {0}")]
    Startup(#[from] NormalRootStartupErrorV1),
    #[error("original public startup loan failed: {0}")]
    Public(#[from] aos_sandbox::production_operation_compiler::NixStartAdmissionErrorV2),
    #[error("independent online floor failed: {0}")]
    Floor(#[from] crate::tpm_nv_custody::FloorErrorV1),
    #[error("actual protected Session failed: {0}")]
    Protected(#[from] BrokerSessionSecurityError),
    #[error("original HELLO or deadline failed: {0}")]
    Handshake(#[from] DormantBrokerSessionHandshakeErrorV1),
    #[error("original protected Session handshake failed: {0}")]
    SessionHandshake(#[from] crate::handshake::DormantBrokerSessionHandshakeErrorV1),
    #[error("selected canonical HELLO failed: {0}")]
    Negotiation(#[from] aos_sandbox_broker_session_protocol::BrokerSessionNegotiationError),
    #[error("original direct deadline capture failed: {0}")]
    Deadline(#[from] crate::ProductionBrokerDeadlineErrorV1),
    #[error("original selected transport failed: {0}")]
    Transport(#[from] OnlineTransportFailureV1),
    #[error("selected canonical response failed: {0}")]
    Schema(#[from] NixBuildSchemaErrorV2),
    #[error("the actual listener rejection stays in its original attempt")]
    Listener,
    #[error("the actual accepted-socket rejection stays in its original result")]
    Accepted,
    #[error("the actual Store reader cause and cleanup debt remain resident")]
    Store,
    #[error("selected Store comparison reservation failed: {0}")]
    StorePreparation(#[from] store::StoreFailureV1),
    #[error("the actual GC-root attempt retains its first cause and physical/process debt")]
    Roots,
    #[error("the actual native commit result and full transaction remain resident")]
    Native,
    #[error("online Resolve owner is permanently closed")]
    Closed,
}

/// Owns partial returned originals; no late assembly or replacement is used.
struct OnlineOwnerV1 {
    startup: Option<Arc<ProductionNixOwnerStartupV1>>,
    raw_listener: Option<OwnedFd>,
    listener_attempt: Option<RecordSubjectListenerAdmissionAttemptV1>,
    listener: Option<RecordSubjectListener>,
    accepted: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    endpoint_custody: Option<ProtectedBrokerSessionBrokerV1>,
    provision: Option<floor::OnlineProvisionV1>,
    catalog: Option<Vec<VerifiedNixRecipeArtifactV2>>,
    pending: Option<DormantBrokerEndpointHandshakeV1>,
    cold: Option<RetainedStorageColdOpenV1>,
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    resolve: OnlineRequestPhaseV1,
    first_failure: Option<OwnerFailureV1>,
    realize: Option<OnlineRequestPhaseV1>,
    query: Option<OnlineRequestPhaseV1>,
    roots: Option<roots::ExistingOutputRootsAttemptV1>,
    existing_outputs: bool,
}

// The original Resolve field/drop order, including Store between native
// preparation and response, remains literal inside this phase reservoir.
struct OnlineRequestPhaseV1 {
    record: Option<ReceivedRecord>,
    receive_failure: Option<RetainedSeqpacketReceiveErrorV1>,
    received: Option<Result<ProtectedBrokerReceivedRequestAdmissionV1, BrokerSessionSecurityError>>,
    checked: Option<Result<ValidatedNixBuildRequestV2, aos_sandbox_protocol::ProtocolValidationError>>,
    request_native: Option<OnlineRequestNativeResultV1>,
    store: Option<store::StoreReadbackV1>,
    response: Option<NixBuildResponseV2>,
    response_bytes: Option<Vec<u8>>,
    outcome: Option<Result<ProtectedBrokerOutcomePendingAdvancementV1, BrokerSessionSecurityError>>,
    outcome_native: Option<ProtectedBrokerOutcomeCommitResultV1>,
    send_failure: Option<SeqpacketError>,
    dispatch_started: bool,
    first_failure: Option<OwnerFailureV1>,
    postflight: crate::handshake::OnlinePostflightV1,
}

impl OnlineRequestPhaseV1 {
    const fn new() -> Self {
        Self {
            record: None,
            receive_failure: None,
            received: None,
            checked: None,
            request_native: None,
            store: None,
            response: None,
            response_bytes: None,
            outcome: None,
            outcome_native: None,
            send_failure: None,
            dispatch_started: false,
            first_failure: None,
            postflight: crate::handshake::OnlinePostflightV1::new(),
        }
    }
}

impl OnlineOwnerV1 {
    fn new(listener: OwnedFd) -> Self {
        Self {
            startup: None,
            raw_listener: Some(listener),
            listener_attempt: None,
            listener: None,
            accepted: None,
            endpoint_custody: None,
            provision: None,
            catalog: None,
            pending: None,
            cold: None,
            session: None,
            resolve: OnlineRequestPhaseV1::new(),
            first_failure: None,
            realize: None,
            query: None,
            roots: None,
            existing_outputs: false,
        }
    }

    fn terminate(&mut self, cause: OwnerFailureV1) -> ! {
        self.first_failure.get_or_insert(cause);
        eprintln!("aos-sandbox-nixd: original online Resolve owner closed");
        // No Rust teardown precedes termination. Kernel cleanup at exit is not
        // a population/OFD-drain proof, a retry grant or a successful result.
        std::process::exit(1)
    }

    fn open_session(&mut self) -> Result<(), OwnerFailureV1> {
        let provision = self.provision.as_mut().ok_or(OwnerFailureV1::Closed)?;
        provision.admit()?;
        let (profile, issuer) = provision.snapshot_binding()?;
        self.resolve.store = Some(store::StoreReadbackV1::new(profile, issuer));
        if self.existing_outputs {
            self.resolve.store.as_mut().ok_or(OwnerFailureV1::Closed)?
                .reserve_selected_postflight()?;
        }

        self.listener_attempt = Some(RecordSubjectListenerAdmissionAttemptV1::new(
            self.raw_listener.take().ok_or(OwnerFailureV1::Closed)?,
        ));
        let attempt = self.listener_attempt.as_mut().ok_or(OwnerFailureV1::Closed)?;
        if attempt.admit_once(Path::new(SOCKET)).is_err() {
            return Err(OwnerFailureV1::Listener);
        }
        self.listener = attempt.take_completed_listener();
        let deadline = OriginalBrokerColdDeadlineV1::storage_accept(
            crate::production_deadline_after(Duration::from_secs(30))?,
        );
        let listener = self.listener.as_mut().ok_or(OwnerFailureV1::Closed)?;
        crate::dormant_handshake::wait_for_handshake_readiness(
            listener.as_fd(), false, deadline.value(),
        )?;
        self.accepted = Some(listener.accept_retaining());
        if self.accepted.as_ref().is_none_or(Result::is_err) {
            return Err(OwnerFailureV1::Accepted);
        }
        deadline.check()?;
        self.provision.as_mut().ok_or(OwnerFailureV1::Closed)?.revalidate()?;

        self.endpoint_custody = Some(ProtectedBrokerSessionBrokerV1::load(Path::new(ROOT))?);
        let hello = if self.existing_outputs {
            online_existing_output_server_hello()?
        } else {
            online_resolve_server_hello()?
        };
        let custody = self.endpoint_custody.take().ok_or(OwnerFailureV1::Closed)?;
        let socket = match self.accepted.take() {
            Some(Ok(socket)) => socket,
            _ => return Err(OwnerFailureV1::Closed),
        };
        // The unchanged consuming HELLO constructor and its pre-return
        // frames remain an explicit lower custody gap, not a retained wrapper.
        self.pending = Some(begin_online_resolve_broker(custody, socket, hello)?);
        loop {
            deadline.check()?;
            let pending = self.pending.as_ref().ok_or(OwnerFailureV1::Closed)?;
            crate::dormant_handshake::wait_for_handshake_readiness(
                pending.as_fd()?, pending.wants_write(), deadline.value(),
            )?;
            let pending = self.pending.take().ok_or(OwnerFailureV1::Closed)?;
            match pending.advance_retaining_storage()? {
                ColdBrokerHandshakeProgressV1::Pending(pending) => self.pending = Some(pending),
                ColdBrokerHandshakeProgressV1::Verified(verified) => {
                    self.cold = Some(RetainedStorageColdOpenV1::retain_online(
                        verified, deadline, self.provision.take().ok_or(OwnerFailureV1::Closed)?,
                    ));
                    break;
                }
                ColdBrokerHandshakeProgressV1::Complete(_) => return Err(OwnerFailureV1::Closed),
            }
        }
        self.session = Some(self.cold.as_mut().ok_or(OwnerFailureV1::Closed)?
            .finish(Some(profile.node()))?);
        Ok(())
    }

    fn resolve_one(&mut self) -> Result<(), OwnerFailureV1> {
        // Before the authenticated request is known, only the original accept
        // cutoff bounds receipt. Admission then binds its own original D once.
        let receive_deadline = self.cold.as_ref().ok_or(OwnerFailureV1::Closed)?
            .original_deadline();
        let session = self.session.as_mut().ok_or(OwnerFailureV1::Closed)?;
        serve_phase(
            &mut self.resolve, session,
            self.catalog.as_ref().ok_or(OwnerFailureV1::Closed)?,
            receive_deadline.value(), PhysicalPhaseV1::Resolve,
        )
    }

    fn existing_output_successors(&mut self) -> Result<(), OwnerFailureV1> {
        if !self.existing_outputs || self.realize.is_some() || self.query.is_some() || self.roots.is_some() {
            return Err(OwnerFailureV1::Closed);
        }
        self.realize = Some(OnlineRequestPhaseV1::new());
        self.roots = Some(roots::ExistingOutputRootsAttemptV1::new());
        let session = self.session.as_mut().ok_or(OwnerFailureV1::Closed)?;
        let previous = phase_request(&self.resolve.received)?;
        session.advance_online_nix_terminal(previous)?;
        let prior_checked = phase_checked(&self.resolve.checked)?;
        let prior_response = self.resolve.response.as_ref().ok_or(OwnerFailureV1::Closed)?;
        let original = self.resolve.store.as_mut().ok_or(OwnerFailureV1::Closed)?;
        let realize = self.realize.as_mut().ok_or(OwnerFailureV1::Closed)?;
        realize.store = Some(original.output_destination()?);
        let roots = self.roots.as_mut().ok_or(OwnerFailureV1::Closed)?;
        let catalog = self.catalog.as_ref().ok_or(OwnerFailureV1::Closed)?;
        serve_phase(realize, session, catalog, previous.deadline_boottime_nanoseconds(),
            PhysicalPhaseV1::Realize { original: &mut *original, roots: &mut *roots, prior_checked, prior_response })?;

        self.query = Some(OnlineRequestPhaseV1::new());
        let previous = phase_request(&realize.received)?;
        session.advance_online_nix_terminal(previous)?;
        let prior_checked = phase_checked(&realize.checked)?;
        let prior_response = realize.response.as_ref().ok_or(OwnerFailureV1::Closed)?;
        let output = realize.store.as_mut().ok_or(OwnerFailureV1::Closed)?;
        let query = self.query.as_mut().ok_or(OwnerFailureV1::Closed)?;
        serve_phase(query, session, catalog, previous.deadline_boottime_nanoseconds(),
            PhysicalPhaseV1::Query { original, output, roots, prior_checked, prior_response })
    }
}

fn phase_request(received: &Option<Result<ProtectedBrokerReceivedRequestAdmissionV1, BrokerSessionSecurityError>>) -> Result<
    &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    OwnerFailureV1,
> {
    match received.as_ref() {
        Some(Ok(ProtectedBrokerReceivedRequestAdmissionV1::New { request, .. })) => Ok(request),
        _ => Err(OwnerFailureV1::Closed),
    }
}

fn phase_checked(checked: &Option<Result<ValidatedNixBuildRequestV2, aos_sandbox_protocol::ProtocolValidationError>>)
    -> Result<&ValidatedNixBuildRequestV2, OwnerFailureV1>
{
    match checked.as_ref() {
        Some(Ok(checked)) => Ok(checked),
        _ => Err(OwnerFailureV1::Closed),
    }
}

/// Borrows disjoint original physical fields only for one concrete exchange.
enum PhysicalPhaseV1<'previous> {
    Resolve,
    Realize {
        original: &'previous mut store::StoreReadbackV1,
        roots: &'previous mut roots::ExistingOutputRootsAttemptV1,
        prior_checked: &'previous ValidatedNixBuildRequestV2,
        prior_response: &'previous NixBuildResponseV2,
    },
    Query {
        original: &'previous mut store::StoreReadbackV1,
        output: &'previous mut store::StoreReadbackV1,
        roots: &'previous mut roots::ExistingOutputRootsAttemptV1,
        prior_checked: &'previous ValidatedNixBuildRequestV2,
        prior_response: &'previous NixBuildResponseV2,
    },
}

impl PhysicalPhaseV1<'_> {
    fn observe_selected_postflight(
        &mut self,
        destination: &mut Option<store::StoreReadbackV1>,
    ) -> bool {
        match self {
            Self::Resolve => false,
            Self::Realize { original, roots, .. } => {
                let original_debt = original.observe_selected_postflight();
                let output_debt = match destination.as_mut() {
                    Some(output) => output.observe_selected_postflight(),
                    None => true,
                };
                let roots_debt = roots.observe_selected_postflight(destination.as_ref());
                original_debt || output_debt || roots_debt
            }
            Self::Query { original, output, roots, .. } => {
                let original_debt = original.observe_selected_postflight();
                let output_debt = output.observe_selected_postflight();
                let roots_debt = roots.observe_selected_postflight(Some(output));
                original_debt || output_debt || roots_debt
            }
        }
    }

    fn require_successor(
        &self,
        checked: &ValidatedNixBuildRequestV2,
        artifact: &VerifiedNixRecipeArtifactV2,
    ) -> Result<(), OwnerFailureV1> {
        let (prior, response, method) = match self {
            Self::Resolve => {
                return if checked.method() == RESOLVE { Ok(()) } else { Err(OwnerFailureV1::Closed) };
            }
            Self::Realize { prior_checked, prior_response, .. } =>
                (*prior_checked, *prior_response, BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2),
            Self::Query { prior_checked, prior_response, .. } =>
                (*prior_checked, *prior_response, BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2),
        };
        let (observation, transaction, original) =
            aos_sandbox::production_operation_compiler::CurrentRetainedNixStartV2::
                existing_output_successor_coordinates_v2(prior, response)
                .map_err(|_| OwnerFailureV1::Closed)?;
        if observation.inputs != artifact.recipe().inputs
            || prior.method() != RESOLVE && observation.outputs != artifact.recipe().outputs
            || if prior.method() == RESOLVE { response.recipe_admission != artifact.canonical_bytes() }
                else { !response.recipe_admission.is_empty() }
        {
            return Err(OwnerFailureV1::Closed);
        }
        let mut expected = prior.wire().clone();
        let mut header = prior.wire().header.as_option().ok_or(OwnerFailureV1::Closed)?.clone();
        header.request_id = checked.header().request_id().to_vec();
        expected.header = Some(header).into();
        expected.build_transaction_digest = transaction.to_vec();
        if method == BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2 {
            expected.original_realization_digest = original.to_vec();
        }
        if checked.method() != method || checked.wire() != &expected {
            return Err(OwnerFailureV1::Closed);
        }
        Ok(())
    }

    fn perform(
        &mut self,
        destination: &mut Option<store::StoreReadbackV1>,
        artifact: &VerifiedNixRecipeArtifactV2,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), OwnerFailureV1> {
        match self {
            Self::Resolve => destination.as_mut().ok_or(OwnerFailureV1::Closed)?
                .resolve(artifact.recipe(), session, request).map_err(|_| OwnerFailureV1::Store),
            Self::Realize { original, roots, .. } => {
                let output = destination.as_mut().ok_or(OwnerFailureV1::Closed)?;
                output.read_outputs(original, artifact.recipe(), session, request)
                    .map_err(|_| OwnerFailureV1::Store)?;
                roots.prepare(output, artifact.recipe(), session, request).map_err(|_| OwnerFailureV1::Roots)?;
                roots.register(output, artifact.recipe(), session, request).map_err(|_| OwnerFailureV1::Roots)
            }
            Self::Query { output, roots, .. } => roots.query(output, artifact.recipe(), session, request)
                .map_err(|_| OwnerFailureV1::Roots),
        }
    }

    fn recheck(
        &mut self,
        destination: &mut Option<store::StoreReadbackV1>,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), OwnerFailureV1> {
        match self {
            Self::Resolve => destination.as_mut().ok_or(OwnerFailureV1::Closed)?
                .recheck_completed(session, request).map_err(|_| OwnerFailureV1::Store),
            Self::Realize { original, roots, .. } => {
                let output = destination.as_mut().ok_or(OwnerFailureV1::Closed)?;
                original.recheck_completed(session, request).map_err(|_| OwnerFailureV1::Store)?;
                output.recheck_completed(session, request).map_err(|_| OwnerFailureV1::Store)?;
                roots.recheck_completed(output, session, request).map_err(|_| OwnerFailureV1::Roots)
            }
            Self::Query { original, output, roots, .. } => {
                original.recheck_completed(session, request).map_err(|_| OwnerFailureV1::Store)?;
                output.recheck_completed(session, request).map_err(|_| OwnerFailureV1::Store)?;
                roots.recheck_completed(output, session, request).map_err(|_| OwnerFailureV1::Roots)
            }
        }
    }

    fn response(
        &self,
        artifact: &VerifiedNixRecipeArtifactV2,
        checked: &ValidatedNixBuildRequestV2,
    ) -> Result<NixBuildResponseV2, OwnerFailureV1> {
        match self {
            Self::Resolve => resolve_response(artifact, checked),
            Self::Realize { roots, .. } => observation_response(artifact, checked, Some((
                ObjectDigest::from_bytes(checked.commitment()),
                ObjectDigest::from_bytes(roots.retained_digest().map_err(|_| OwnerFailureV1::Roots)?),
            ))),
            Self::Query { roots, prior_checked, prior_response, .. } => {
                let (original, _, _) =
                    aos_sandbox::production_operation_compiler::CurrentRetainedNixStartV2::
                        existing_output_successor_coordinates_v2(prior_checked, prior_response)
                        .map_err(|_| OwnerFailureV1::Closed)?;
                let retained = ObjectDigest::from_bytes(roots.retained_digest().map_err(|_| OwnerFailureV1::Roots)?);
                if original.retained_roots != Some(retained) {
                    return Err(OwnerFailureV1::Closed);
                }
                observation_response(artifact, checked, Some((
                    original.attempt.ok_or(OwnerFailureV1::Closed)?, retained,
                )))
            }
        }
    }
}

fn serve_phase(
    phase: &mut OnlineRequestPhaseV1,
    session: &mut DormantAuthenticatedBrokerSessionV1,
    catalog: &[VerifiedNixRecipeArtifactV2],
    receive_deadline: u64,
    mut physical: PhysicalPhaseV1<'_>,
) -> Result<(), OwnerFailureV1> {
    if matches!(physical, PhysicalPhaseV1::Resolve) {
        return serve_phase_recipe(phase, session, catalog, receive_deadline, &mut physical);
    }
    let result = serve_phase_recipe(phase, session, catalog, receive_deadline, &mut physical);
    if let Err(cause) = result {
        phase.first_failure.get_or_insert(cause);
    }
    // Response materialization, native prepare/commit, wait and send have all
    // returned. Park their chronological cause before independent observations.
    let physical_debt = physical.observe_selected_postflight(&mut phase.store);
    session.observe_online_postflight(&mut phase.postflight);
    if phase.first_failure.is_some() || physical_debt || phase.postflight.failed() {
        return Err(OwnerFailureV1::Closed);
    }
    Ok(())
}

// The SAME receive/admission/native/response/dispatch recipe keeps ordinary
// method50's error/effect/local-drop order. Only the selected caller adds a
// negative return bookend; no error can resend or restart this recipe.
fn serve_phase_recipe(
    phase: &mut OnlineRequestPhaseV1,
    session: &mut DormantAuthenticatedBrokerSessionV1,
    catalog: &[VerifiedNixRecipeArtifactV2],
    receive_deadline: u64,
    physical: &mut PhysicalPhaseV1<'_>,
) -> Result<(), OwnerFailureV1> {
    loop {
        crate::dormant_handshake::wait_for_handshake_readiness(
            session.as_fd()?, false, receive_deadline,
        )?;
        if session.receive_online_record_into(&mut phase.record, &mut phase.receive_failure)? {
            break;
        }
    }
    session.admit_online_record_into(
        phase.record.as_ref().ok_or(OwnerFailureV1::Closed)?, &mut phase.received,
    )?;
    let (request, initialize) = match phase.received.as_ref() {
        Some(Ok(ProtectedBrokerReceivedRequestAdmissionV1::New { request, requires_initialization })) => {
            (request, *requires_initialization)
        }
        _ => return Err(OwnerFailureV1::Closed),
    };
    session.decode_online_request_into(request, &mut phase.checked)?;
    let checked = match phase.checked.as_ref() {
        Some(Ok(checked)) => checked,
        _ => return Err(OwnerFailureV1::Closed),
    };
    let artifact = catalog.iter()
        .find(|artifact| artifact.digest().as_bytes() == checked.wire().recipe_digest.as_slice())
        .ok_or(OwnerFailureV1::Closed)?;
    require_recipe_coordinates(artifact, checked)?;
    physical.require_successor(checked, artifact)?;
    session.retain_online_admission(request, checked)?;
    session.retain_online_request_commit_into(request, initialize, &mut phase.request_native)?;
    session.finish_online_native_step(request)?;

    physical.perform(&mut phase.store, artifact, session, request)?;
    physical.recheck(&mut phase.store, session, request)?;
    phase.response = Some(physical.response(artifact, checked)?);
    phase.response_bytes = Some(phase.response.as_ref().ok_or(OwnerFailureV1::Closed)?.encode_to_vec());
    let body = phase.response_bytes.as_ref().ok_or(OwnerFailureV1::Closed)?;
    if body.len() > aos_sandbox_protocol::nix_build::NIX_RESPONSE_MAXIMUM_BYTES_V2 {
        return Err(OwnerFailureV1::Closed);
    }
    physical.recheck(&mut phase.store, session, request)?;
    session.require_online_request(request)?;
    phase.outcome = Some(session.prepare_broker_outcome(request, BrokerResponseEnvelope {
        request_id: request.request_id().to_vec(), method: request.method().into(),
        body: body.clone(), ..Default::default()
    }));
    if phase.outcome.as_ref().is_none_or(Result::is_err) {
        return Err(OwnerFailureV1::Native);
    }
    physical.recheck(&mut phase.store, session, request)?;
    session.require_online_request(request)?;
    let pending = match phase.outcome.take() {
        Some(Ok(pending)) => pending,
        original => {
            phase.outcome = original;
            return Err(OwnerFailureV1::Closed);
        }
    };
    phase.outcome_native = Some(session.commit_broker_outcome(pending));
    let committed = match phase.outcome_native.as_ref() {
        Some(ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) => committed,
        _ => return Err(OwnerFailureV1::Native),
    };
    physical.recheck(&mut phase.store, session, request)?;
    session.finish_online_native_step(request)?;
    crate::dormant_handshake::wait_for_handshake_readiness(
        session.as_fd()?, true, request.deadline_boottime_nanoseconds(),
    )?;
    phase.dispatch_started = true;
    session.send_online_packet(request, committed.exact_packet(), &mut phase.send_failure)?;
    physical.recheck(&mut phase.store, session, request)?;
    session.require_online_transport(request)?;
    Ok(())
}

impl Drop for OnlineOwnerV1 {
    fn drop(&mut self) {
        // Prevents ordinary disposal of returned resident originals. A guard
        // after a local loan is needed for its earlier unwind/drop interval;
        // no guard rescues already-unwound callee-local pre-return frames.
        std::process::abort();
    }
}

struct AbortOnlineOwnerUnwindV1;

impl Drop for AbortOnlineOwnerUnwindV1 {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

/// Runs the fixed selected Nix service from its original launch table.
///
/// The unit supplies four comparison identities; the original strict profile
/// validates them and keeps root control UID/GID0 and bounding0xc0. One actual
/// Resolve50 is processed, durably read back and sent. The explicit
/// `existing-outputs` mode then processes one independently granted Realize51
/// and Query52 on that same Session and original cutoff. Only two independently
/// provisioned GC-root subtrees are writable; Store objects and database stay
/// read-only. This is not a missing-output builder or a successful Start.
/// The owner retains its floor, Store, children, packets and outcomes afterward.
///
/// # Errors
/// Returns only argument or original-table capture failure. After returned
/// custody, failure terminates before ordinary Rust owner teardown.
pub fn run_from_environment() -> Result<(), OnlineNixServiceError> {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    let existing_outputs = arguments.len() == 5
        && arguments.last().is_some_and(|mode| mode == "existing-outputs");
    if existing_outputs {
        arguments.pop();
    } else if arguments.len() != 4 {
        return Err(OnlineNixServiceError::Arguments);
    }
    let mut identities = [0; 4];
    for (identity, argument) in identities.iter_mut().zip(arguments) {
        *identity = argument.parse().map_err(|_| OnlineNixServiceError::Arguments)?;
        if *identity == 0 {
            return Err(OnlineNixServiceError::Arguments);
        }
    }
    let (capture, listener) = ProductionNixOwnerStartupCaptureV1::capture()?;
    let mut owner = OnlineOwnerV1::new(listener);
    owner.existing_outputs = existing_outputs;
    owner.startup = Some(Arc::new(match capture.admit_selected(identities) {
        Ok(startup) => startup,
        Err(cause) => owner.terminate(cause.into()),
    }));
    let startup = match owner.startup.as_ref() {
        Some(startup) => Arc::clone(startup),
        None => owner.terminate(OwnerFailureV1::Closed),
    };
    let mut original = Some(Arc::clone(&startup));
    let mut loan = Some(match startup.borrow_public_session_floor_origin_v2() {
        Ok(loan) => loan,
        Err(cause) => owner.terminate(cause.into()),
    });
    let _loan_unwind = AbortOnlineOwnerUnwindV1;
    let mut retained = None;
    if let Err(cause) = NixOwnerPublicSessionFloorOriginV2::retain_original_into(
        &mut loan, &mut original, &mut retained,
    ) {
        owner.terminate(cause.into());
    }
    drop(loan);
    let mut origin = match retained {
        Some(origin) => floor::OnlineOriginV1::owner(origin),
        None => owner.terminate(OwnerFailureV1::Closed),
    };
    let _origin_unwind = AbortOnlineOwnerUnwindV1;
    if let Err(cause) = origin.retain_recipe_catalog_into(&mut owner.catalog) {
        owner.terminate(cause.into());
    }
    owner.provision = Some(floor::OnlineProvisionV1::new(origin));
    if let Err(cause) = owner.open_session() {
        owner.terminate(cause);
    }
    if let Err(cause) = owner.resolve_one() {
        owner.terminate(cause);
    }
    if owner.existing_outputs {
        if let Err(cause) = owner.existing_output_successors() {
            owner.terminate(cause);
        }
    }
    loop {
        std::thread::park();
    }
}

fn require_recipe_coordinates(
    artifact: &VerifiedNixRecipeArtifactV2,
    request: &ValidatedNixBuildRequestV2,
) -> Result<(), OwnerFailureV1> {
    let recipe = artifact.recipe();
    let wire = request.wire();
    let (inputs, outputs) = aos_sandbox::production_operation_compiler::CurrentRetainedNixStartV2::
        recipe_coordinate_digests_v2(recipe)?;
    if artifact.digest().as_bytes() != wire.recipe_digest.as_slice()
        || recipe.domain_commitment.as_bytes() != wire.domain_digest.as_slice()
        || recipe.disclosure.as_bytes() != wire.disclosure_digest.as_slice()
        || recipe.environment.digest().as_bytes() != wire.environment_digest.as_slice()
        || inputs != wire.input_presentation_digest.as_slice()
        || outputs != wire.expected_output_map_digest.as_slice()
    {
        return Err(OwnerFailureV1::Closed);
    }
    Ok(())
}

fn resolve_response(
    artifact: &VerifiedNixRecipeArtifactV2,
    request: &ValidatedNixBuildRequestV2,
) -> Result<NixBuildResponseV2, OwnerFailureV1> {
    observation_response(artifact, request, None)
}

fn observation_response(
    artifact: &VerifiedNixRecipeArtifactV2,
    request: &ValidatedNixBuildRequestV2,
    realization: Option<(ObjectDigest, ObjectDigest)>,
) -> Result<NixBuildResponseV2, OwnerFailureV1> {
    let wire = request.wire();
    let digest = |bytes: &[u8]| -> Result<ObjectDigest, OwnerFailureV1> {
        Ok(ObjectDigest::from_bytes(bytes.try_into().map_err(|_| OwnerFailureV1::Closed)?))
    };
    let observation = NixBuildObservationV2 {
        method: match request.method() {
            RESOLVE => 50,
            BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2 => 51,
            BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2 => 52,
            _ => return Err(OwnerFailureV1::Closed),
        }, request: ObjectDigest::from_bytes(request.commitment()),
        operation: wire.operation_id.as_slice().try_into().map_err(|_| OwnerFailureV1::Closed)?,
        recipe: artifact.digest(), domain: digest(&wire.domain_digest)?,
        disclosure: digest(&wire.disclosure_digest)?, environment: digest(&wire.environment_digest)?,
        parent_admission: digest(&wire.parent_admission_digest)?,
        input_presentation: digest(&wire.input_presentation_digest)?,
        expected_output_map: digest(&wire.expected_output_map_digest)?,
        build_transaction: if realization.is_some() { Some(digest(&wire.build_transaction_digest)?) } else { None },
        original_realization: if request.method() == BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2 {
            Some(digest(&wire.original_realization_digest)?)
        } else { None },
        attempt: realization.map(|(attempt, _)| attempt),
        retained_roots: realization.map(|(_, roots)| roots),
        inputs: artifact.recipe().inputs.clone(),
        outputs: if realization.is_some() { artifact.recipe().outputs.clone() } else { Vec::new() },
    };
    Ok(NixBuildResponseV2 {
        request_id: request.header().request_id().to_vec(),
        recipe_digest: artifact.digest().as_bytes().to_vec(),
        domain_digest: artifact.recipe().domain_commitment.as_bytes().to_vec(),
        recipe_admission: if realization.is_none() { artifact.canonical_bytes().to_vec() } else { Vec::new() },
        observation: observation.canonical_bytes()?, ..Default::default()
    })
}
