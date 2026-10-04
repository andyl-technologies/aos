//! Owns the selected online Nix service and its independently provisioned floor.
//!
//! The fixed service uses the existing authenticated Session, journal reducer,
//! retained process supervisor and selected upstream Store reader. Resolve50
//! observes already admitted immutable inputs; it does not build, import,
//! publish, initialize NV or substitute an offline approval for online custody.

pub(crate) mod floor;
mod store;

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
    online_resolve_server_hello,
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
    /// The selected unit did not supply exactly its four comparison identities.
    #[error("online Nix service expects four nonzero decimal identities")]
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
        self.store = Some(store::StoreReadbackV1::new(profile, issuer));

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
        let hello = online_resolve_server_hello()?;
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
        loop {
            crate::dormant_handshake::wait_for_handshake_readiness(
                session.as_fd()?, false, receive_deadline.value(),
            )?;
            if session.receive_online_record_into(&mut self.record, &mut self.receive_failure)? {
                break;
            }
        }
        session.admit_online_record_into(
            self.record.as_ref().ok_or(OwnerFailureV1::Closed)?, &mut self.received,
        )?;
        let (request, initialize) = match self.received.as_ref() {
            Some(Ok(ProtectedBrokerReceivedRequestAdmissionV1::New { request, requires_initialization })) => {
                (request, *requires_initialization)
            }
            _ => return Err(OwnerFailureV1::Closed),
        };
        session.decode_online_request_into(request, &mut self.checked)?;
        let checked = match self.checked.as_ref() {
            Some(Ok(checked)) => checked,
            _ => return Err(OwnerFailureV1::Closed),
        };
        let artifact = self.catalog.as_ref().ok_or(OwnerFailureV1::Closed)?.iter()
            .find(|artifact| artifact.digest().as_bytes() == checked.wire().recipe_digest.as_slice())
            .ok_or(OwnerFailureV1::Closed)?;
        require_recipe_coordinates(artifact, checked)?;
        session.retain_online_admission(request, checked)?;
        session.retain_online_request_commit_into(request, initialize, &mut self.request_native)?;
        session.finish_online_native_step(request)?;

        let store = self.store.as_mut().ok_or(OwnerFailureV1::Closed)?;
        store.resolve(artifact.recipe(), session, request).map_err(|_| OwnerFailureV1::Store)?;
        store.recheck_completed(session, request).map_err(|_| OwnerFailureV1::Store)?;
        self.response = Some(resolve_response(artifact, checked)?);
        self.response_bytes = Some(self.response.as_ref().ok_or(OwnerFailureV1::Closed)?.encode_to_vec());
        let body = self.response_bytes.as_ref().ok_or(OwnerFailureV1::Closed)?;
        if body.len() > aos_sandbox_protocol::nix_build::NIX_RESPONSE_MAXIMUM_BYTES_V2 {
            return Err(OwnerFailureV1::Closed);
        }
        store.recheck_completed(session, request).map_err(|_| OwnerFailureV1::Store)?;
        session.require_online_request(request)?;
        self.outcome = Some(session.prepare_broker_outcome(request, BrokerResponseEnvelope {
            request_id: request.request_id().to_vec(), method: RESOLVE.into(),
            body: body.clone(), ..Default::default()
        }));
        if self.outcome.as_ref().is_none_or(Result::is_err) {
            return Err(OwnerFailureV1::Native);
        }
        store.recheck_completed(session, request).map_err(|_| OwnerFailureV1::Store)?;
        session.require_online_request(request)?;
        let pending = match self.outcome.take() {
            Some(Ok(pending)) => pending,
            original => {
                self.outcome = original;
                return Err(OwnerFailureV1::Closed);
            }
        };
        self.outcome_native = Some(session.commit_broker_outcome(pending));
        let committed = match self.outcome_native.as_ref() {
            Some(ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) => committed,
            _ => return Err(OwnerFailureV1::Native),
        };
        store.recheck_completed(session, request).map_err(|_| OwnerFailureV1::Store)?;
        session.finish_online_native_step(request)?;
        crate::dormant_handshake::wait_for_handshake_readiness(
            session.as_fd()?, true, request.deadline_boottime_nanoseconds(),
        )?;
        self.dispatch_started = true;
        session.send_online_packet(request, committed.exact_packet(), &mut self.send_failure)?;
        store.recheck_completed(session, request).map_err(|_| OwnerFailureV1::Store)?;
        session.require_online_transport(request)?;
        Ok(())
    }
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

/// Runs the fixed selected Resolve50 service from its original launch table.
///
/// The unit supplies four comparison identities; the original strict profile
/// validates them and keeps root control UID/GID0 and bounding0xc0. One actual
/// request is processed, durably read back and sent. The owner then retains its
/// floor, Store, child, packets and outcome rather than accepting a replacement.
/// This grants neither methods51/52 nor a successful Controller Start.
///
/// # Errors
/// Returns only argument or original-table capture failure. After returned
/// custody, failure terminates before ordinary Rust owner teardown.
pub fn run_from_environment() -> Result<(), OnlineNixServiceError> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.len() != 4 {
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
    let wire = request.wire();
    let digest = |bytes: &[u8]| -> Result<ObjectDigest, OwnerFailureV1> {
        Ok(ObjectDigest::from_bytes(bytes.try_into().map_err(|_| OwnerFailureV1::Closed)?))
    };
    let observation = NixBuildObservationV2 {
        method: 50, request: ObjectDigest::from_bytes(request.commitment()),
        operation: wire.operation_id.as_slice().try_into().map_err(|_| OwnerFailureV1::Closed)?,
        recipe: artifact.digest(), domain: digest(&wire.domain_digest)?,
        disclosure: digest(&wire.disclosure_digest)?, environment: digest(&wire.environment_digest)?,
        parent_admission: digest(&wire.parent_admission_digest)?,
        input_presentation: digest(&wire.input_presentation_digest)?,
        expected_output_map: digest(&wire.expected_output_map_digest)?,
        build_transaction: None, original_realization: None, attempt: None,
        retained_roots: None, inputs: artifact.recipe().inputs.clone(), outputs: Vec::new(),
    };
    Ok(NixBuildResponseV2 {
        request_id: request.header().request_id().to_vec(),
        recipe_digest: artifact.digest().as_bytes().to_vec(),
        domain_digest: artifact.recipe().domain_commitment.as_bytes().to_vec(),
        recipe_admission: artifact.canonical_bytes().to_vec(),
        observation: observation.canonical_bytes()?, ..Default::default()
    })
}
