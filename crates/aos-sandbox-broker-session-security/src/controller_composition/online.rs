//! Owns closed Controller Nix compositions around the original protected engines.
//!
//! Wrappers retain the whole original private owners and native result slots.
//! Fixed HELLO, root, and methods do not expose a mutable protocol selector,
//! signing key, verification context, initialization flag, or arbitrary packet.
//! Controller keeps every currentness bookend and resident failure destination.

use std::os::fd::BorrowedFd;
use std::path::Path;

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerAuthorizationArtifactsV1, BrokerMethod, BrokerRequestEnvelope,
};
use aos_sandbox::normal_root::ControllerNixSessionFloorOriginV2;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionNegotiationError, ProtectedBrokerSessionVerificationContextV1,
    hello_message::BrokerClientHello,
};
use aos_sandbox_core::ProtocolVersion;
use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RetainedSeqpacketReceiveErrorV1, SeqpacketError, SeqpacketSocket,
};
use aos_sandbox_protocol::ProtocolValidationError;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::nix_build::ValidatedNixBuildRequestV2;

use crate::handshake::{
    self, ColdClientHandshakeProgressV1, DormantAuthenticatedBrokerSessionV1,
    DormantControllerClientHandshakeV1, OnlineRequestNativeResultV1, OriginalBrokerColdDeadlineV1,
    RetainedStorageColdOpenV1, VerifiedStorageHandshakeV1,
};
use crate::nix_service::floor::{OnlineOriginV1, OnlineProvisionV1};
use crate::tpm_nv_custody::FloorErrorV1;
use crate::{
    BrokerSessionSecurityError, ProtectedBrokerOutcomeAdmissionGateV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerOutcomePendingAdvancementV1,
    ProtectedBrokerSessionClientV1,
};

/// Reports the original negative HELLO, kernel, or protected-custody failure.
pub use crate::handshake::DormantBrokerSessionHandshakeErrorV1 as ControllerOnlineNixHandshakeErrorV1;
/// Reports the original negative transport failure while native causes remain resident.
pub use crate::handshake::OnlineTransportFailureV1;

/// Owns only the installed Controller's literal Nix endpoint custody.
pub struct ControllerOnlineNixEndpointCustodyV1(ProtectedBrokerSessionClientV1);

impl ControllerOnlineNixEndpointCustodyV1 {
    /// Acquires the original fixed Nix root at the caller's existing frontier.
    ///
    /// # Errors
    /// Returns the original protected-file, manifest, or key-admission error.
    pub fn acquire() -> Result<Self, BrokerSessionSecurityError> {
        ProtectedBrokerSessionClientV1::load(Path::new("/var/lib/aos/sandboxd/broker-session/nix"))
            .map(Self)
    }
}

/// Owns immutable negotiation DATA from the two installed Nix HELLO recipes.
pub struct ControllerOnlineNixHelloV1(BrokerClientHello);

impl ControllerOnlineNixHelloV1 {
    /// Produces the original Resolve50-only HELLO without exposing mutable fields.
    ///
    /// # Errors
    /// Returns the original canonical HELLO construction failure.
    pub fn resolve() -> Result<Self, BrokerSessionNegotiationError> {
        handshake::online_resolve_client_hello().map(Self)
    }

    /// Produces the original existing-output 50/51/52 HELLO.
    ///
    /// # Errors
    /// Returns the original canonical HELLO construction failure.
    pub fn existing_outputs() -> Result<Self, BrokerSessionNegotiationError> {
        handshake::online_existing_output_client_hello().map(Self)
    }
}

/// Retains the genuine original Controller floor origin and its admission owner.
pub struct ControllerOnlineNixProvisionV1(OnlineProvisionV1);

impl ControllerOnlineNixProvisionV1 {
    /// Moves the already retained original into the unchanged floor owner.
    pub fn new_controller(original: ControllerNixSessionFloorOriginV2<'static>) -> Self {
        Self(OnlineProvisionV1::new(OnlineOriginV1::controller(original)))
    }

    /// Runs the original independently supplied floor admission.
    ///
    /// # Errors
    /// Returns the original floor, provisioning, or retained-origin rejection.
    pub fn admit(&mut self) -> Result<(), FloorErrorV1> {
        self.0.admit()
    }

    /// Observes only the original admitted profile's node comparison DATA.
    ///
    /// # Errors
    /// Returns the original unavailable-profile error.
    pub fn node(&self) -> Result<[u8; 16], FloorErrorV1> {
        self.0.profile().map(|profile| profile.node())
    }
}

/// Retains the original client HELLO state without exposing its generic begin.
pub struct ControllerOnlineNixHandshakeV1(DormantControllerClientHandshakeV1);

/// Retains the original verified HELLO for fixed cold-floor admission.
pub struct ControllerOnlineNixVerifiedHandshakeV1(VerifiedStorageHandshakeV1);

/// Carries the original whole pending, verified, or completed HELLO owner.
#[must_use = "retain every returned handshake owner before later currentness gates"]
pub enum ControllerOnlineNixHandshakeProgressV1 {
    /// Retains the same incomplete HELLO flight.
    Pending(ControllerOnlineNixHandshakeV1),
    /// Retains the genuine verified HELLO until cold admission.
    Verified(ControllerOnlineNixVerifiedHandshakeV1),
    /// Retains the original completed session on the caller's closed branch.
    Complete(ControllerOnlineNixSessionV1),
}

impl ControllerOnlineNixHandshakeV1 {
    /// Begins the unchanged fixed Nix HELLO with the original owned operands.
    ///
    /// # Errors
    /// Returns the original endpoint-role, kernel, or HELLO failure.
    pub fn begin(
        custody: ControllerOnlineNixEndpointCustodyV1,
        socket: SeqpacketSocket,
        hello: ControllerOnlineNixHelloV1,
    ) -> Result<Self, ControllerOnlineNixHandshakeErrorV1> {
        handshake::begin_online_resolve_client(custody.0, socket, hello.0).map(Self)
    }

    /// Borrows the original handshake descriptor for readiness observation.
    ///
    /// # Errors
    /// Returns the original descriptor projection failure.
    pub fn as_fd(&self) -> Result<BorrowedFd<'_>, ControllerOnlineNixHandshakeErrorV1> {
        self.0.as_fd()
    }

    /// Observes the original pending flight's readiness direction.
    pub fn wants_write(&self) -> bool {
        self.0.wants_write()
    }

    /// Advances exactly the unchanged original retained-storage HELLO step.
    ///
    /// # Errors
    /// Returns the original protected, kernel, remote, or native transport error.
    pub fn advance_retaining_storage(
        self,
    ) -> Result<ControllerOnlineNixHandshakeProgressV1, ControllerOnlineNixHandshakeErrorV1> {
        self.0
            .advance_retaining_storage()
            .map(|progress| match progress {
                ColdClientHandshakeProgressV1::Pending(pending) => {
                    ControllerOnlineNixHandshakeProgressV1::Pending(Self(pending))
                }
                ColdClientHandshakeProgressV1::Verified(verified) => {
                    ControllerOnlineNixHandshakeProgressV1::Verified(
                        ControllerOnlineNixVerifiedHandshakeV1(verified),
                    )
                }
                ColdClientHandshakeProgressV1::Complete(session) => {
                    ControllerOnlineNixHandshakeProgressV1::Complete(ControllerOnlineNixSessionV1(
                        session,
                    ))
                }
            })
    }
}

impl RetainedStorageColdOpenV1 {
    /// Parks the genuine HELLO and original independently supplied Controller floor.
    pub fn retain_controller_online(
        verified: ControllerOnlineNixVerifiedHandshakeV1,
        deadline: OriginalBrokerColdDeadlineV1,
        provision: ControllerOnlineNixProvisionV1,
    ) -> Self {
        Self::retain_online(verified.0, deadline, provision.0)
    }

    /// Completes the unchanged cold admission against the original expected node.
    ///
    /// # Errors
    /// Preserves the original admission error and all resident cold failure custody.
    pub fn finish_controller_online(
        &mut self,
        expected_node: [u8; 16],
    ) -> Result<ControllerOnlineNixSessionV1, crate::DormantBrokerSessionHandshakeErrorV1> {
        self.finish(Some(expected_node))
            .map(ControllerOnlineNixSessionV1)
    }
}

/// Retains the original protected online session without publishing generic recipes.
pub struct ControllerOnlineNixSessionV1(DormantAuthenticatedBrokerSessionV1);

/// Retains the original authenticated request and private initialization decision.
pub struct ControllerOnlineNixPreparedRequestV1((AuthenticatedBrokerMethodRequestV1, bool));

impl ControllerOnlineNixPreparedRequestV1 {
    /// Borrows the existing authenticated request without exposing its native selector.
    pub fn request(&self) -> &AuthenticatedBrokerMethodRequestV1 {
        &self.0.0
    }
}

/// Retains the original whole native-result slot at the Controller's resident destination.
///
/// Empty construction creates no native target, durability, or permission. The
/// unchanged private engine writes directly into this same slot before postchecks.
#[derive(Default)]
pub struct ControllerOnlineNixNativeRequestCustodyV1(Option<OnlineRequestNativeResultV1>);

/// Retains the original whole native outcome-opening result including hidden context.
pub struct ControllerOnlineNixOutcomeOpeningV1(
    Result<
        (
            ProtectedBrokerOutcomeAdmissionGateV1,
            ProtectedBrokerSessionVerificationContextV1,
        ),
        BrokerSessionSecurityError,
    >,
);

impl ControllerOnlineNixOutcomeOpeningV1 {
    /// Extracts the original gate only at the caller's post-recheck frontier.
    ///
    /// # Errors
    /// Returns the whole original failed opening for reinsertion into its resident slot.
    pub fn into_gate(self) -> Result<ProtectedBrokerOutcomeAdmissionGateV1, Self> {
        match self.0 {
            Ok((gate, _context)) => Ok(gate),
            Err(error) => Err(Self(Err(error))),
        }
    }
}

impl ControllerOnlineNixSessionV1 {
    /// Samples the unchanged client request coordinates.
    ///
    /// # Errors
    /// Returns the original clock or protected request-state failure.
    pub fn client_request_coordinates(
        &mut self,
    ) -> Result<([u8; 16], u64, u32, ProtocolVersion, Audience), BrokerSessionSecurityError> {
        self.0.client_request_coordinates()
    }

    /// Prepares only the original Resolve50 envelope from owned untrusted DATA.
    ///
    /// # Errors
    /// Returns the original clock, signing, request binding, or protected-state error.
    pub fn prepare_resolve(
        &mut self,
        body: Vec<u8>,
        artifacts: BrokerAuthorizationArtifactsV1,
        request_id: [u8; 16],
        deadline: u64,
    ) -> Result<ControllerOnlineNixPreparedRequestV1, BrokerSessionSecurityError> {
        self.prepare_nix_request(
            BrokerMethod::BROKER_METHOD_NIX_RESOLVE_PROTECTED_RECIPE_V2,
            body,
            artifacts,
            request_id,
            deadline,
        )
    }

    /// Prepares only the original existing-output Realize51 envelope.
    ///
    /// # Errors
    /// Returns the original clock, signing, request binding, or protected-state error.
    pub fn prepare_realize(
        &mut self,
        body: Vec<u8>,
        artifacts: BrokerAuthorizationArtifactsV1,
        request_id: [u8; 16],
        deadline: u64,
    ) -> Result<ControllerOnlineNixPreparedRequestV1, BrokerSessionSecurityError> {
        self.prepare_nix_request(
            BrokerMethod::BROKER_METHOD_NIX_REALIZE_AUTHORIZED_DERIVATION_V2,
            body,
            artifacts,
            request_id,
            deadline,
        )
    }

    /// Prepares only the original existing-output Query52 envelope.
    ///
    /// # Errors
    /// Returns the original clock, signing, request binding, or protected-state error.
    pub fn prepare_query_path_info(
        &mut self,
        body: Vec<u8>,
        artifacts: BrokerAuthorizationArtifactsV1,
        request_id: [u8; 16],
        deadline: u64,
    ) -> Result<ControllerOnlineNixPreparedRequestV1, BrokerSessionSecurityError> {
        self.prepare_nix_request(
            BrokerMethod::BROKER_METHOD_NIX_QUERY_AUTHORIZED_PATH_INFO_V2,
            body,
            artifacts,
            request_id,
            deadline,
        )
    }

    fn prepare_nix_request(
        &mut self,
        method: BrokerMethod,
        body: Vec<u8>,
        artifacts: BrokerAuthorizationArtifactsV1,
        request_id: [u8; 16],
        deadline: u64,
    ) -> Result<ControllerOnlineNixPreparedRequestV1, BrokerSessionSecurityError> {
        self.0
            .prepare_client_request(
                BrokerRequestEnvelope {
                    method: method.into(),
                    body,
                    authorization: Some(artifacts).into(),
                    ..Default::default()
                },
                method,
                0,
                request_id,
                deadline,
                aos_sandbox_protocol::nix_build::NIX_RESPONSE_MAXIMUM_BYTES_V2 as u32,
            )
            .map(ControllerOnlineNixPreparedRequestV1)
    }

    /// Parks the unchanged decoder result in the original destination.
    ///
    /// # Errors
    /// Preserves the original decoder, transport, clock, and occupied-slot rejection.
    pub fn decode_online_request_into(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        target: &mut Option<Result<ValidatedNixBuildRequestV2, ProtocolValidationError>>,
    ) -> Result<(), OnlineTransportFailureV1> {
        self.0.decode_online_request_into(request, target)
    }

    /// Retains the original common plan/lease admission on the same session.
    ///
    /// # Errors
    /// Preserves the original transport, paired clock, and admission failure.
    pub fn retain_online_admission(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        checked: &ValidatedNixBuildRequestV2,
    ) -> Result<(), OnlineTransportFailureV1> {
        self.0.retain_online_admission(request, checked)
    }

    /// Parks the native result directly into the original resident slot.
    ///
    /// # Errors
    /// Preserves the original native ambiguity, occupied-slot, and postcheck failures.
    pub fn retain_online_request_commit_into(
        &mut self,
        prepared: &ControllerOnlineNixPreparedRequestV1,
        target: &mut ControllerOnlineNixNativeRequestCustodyV1,
    ) -> Result<(), OnlineTransportFailureV1> {
        self.0
            .retain_online_request_commit_into(&prepared.0.0, prepared.0.1, &mut target.0)
    }

    /// Runs the unchanged final native-step release frontier.
    ///
    /// # Errors
    /// Returns the original transport, effect, or client-currentness error.
    pub fn finish_online_native_step(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.finish_online_native_step(request)
    }

    /// Advances only the original successfully completed Nix terminal.
    ///
    /// # Errors
    /// Returns the original store-readback, terminal, or currentness rejection.
    pub fn advance_online_nix_terminal(
        &mut self,
        previous: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.advance_online_nix_terminal(previous)
    }

    /// Sends only the existing request's canonical packet at the original frontier.
    ///
    /// # Errors
    /// Preserves the original send cause in its slot and all transport postchecks.
    pub fn send_canonical_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        failure: &mut Option<SeqpacketError>,
    ) -> Result<(), OnlineTransportFailureV1> {
        self.0
            .send_online_packet(request, request.canonical_packet(), failure)
    }

    /// Performs the unchanged pending-request currentness checks.
    ///
    /// # Errors
    /// Returns the original request or transport rejection.
    pub fn require_online_request(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.require_online_request(request)
    }

    /// Parks the original received record or owning native error before bookends.
    ///
    /// # Errors
    /// Preserves native receive custody, fatal-close behavior, and transport checks.
    pub fn receive_online_record_into(
        &mut self,
        record: &mut Option<ReceivedRecord>,
        failure: &mut Option<RetainedSeqpacketReceiveErrorV1>,
    ) -> Result<bool, OnlineTransportFailureV1> {
        self.0.receive_online_record_into(record, failure)
    }

    /// Retains the original whole native gate/context opening result.
    pub fn open_outcome(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> ControllerOnlineNixOutcomeOpeningV1 {
        ControllerOnlineNixOutcomeOpeningV1(self.0.reopen_broker_outcome(request))
    }

    /// Commits the original sealed pending outcome through the unchanged engine.
    pub fn commit_broker_outcome(
        &mut self,
        pending: ProtectedBrokerOutcomePendingAdvancementV1,
    ) -> ProtectedBrokerOutcomeCommitResultV1 {
        self.0.commit_broker_outcome(pending)
    }

    /// Performs the unchanged online transport and original-deadline checks.
    ///
    /// # Errors
    /// Returns the original protected, clock, or transport rejection.
    pub fn require_online_transport(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.0.require_online_transport(request)
    }

    /// Borrows the original session descriptor for the caller's readiness wait.
    ///
    /// # Errors
    /// Returns the original descriptor projection failure.
    pub fn as_fd(&self) -> Result<BorrowedFd<'_>, ControllerOnlineNixHandshakeErrorV1> {
        self.0.as_fd()
    }
}
