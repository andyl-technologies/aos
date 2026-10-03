//! Nonterminal preparation controls on the original authenticated FUSE socket.
//!
//! ```text
//! AOSFIC01 || version:u16be=1 || kind:u8 || reserved:u8=0 ||
//! method:u16be=44 || purpose:u32be=57 || major:u16be=3 || minor:u16be=0 ||
//! deadline:u64be || session[32] || signed-request[32] || semantics[32] ||
//! challenge[32] || optional exact reservation coordinates[80]
//!
//! AOSFIH01 || version:u16be=1 || kind:u8=1 || reserved:u8=0 ||
//! same original method/purpose/profile/binding || host-packet-size:u32be ||
//! exact original zero-FD Host ObserveMountScope artifact packet
//! ```
//!
//! These zero-FD controls never advance RequestPrepared into a terminal
//! outcome. The holder borrows the actual session (and therefore its original
//! socket and locked journal) throughout the exchange. Rechecking a temporary
//! journal borrow does not unlock, drop, reopen or replace that writer.
//! Reservation coordinates are comparison data, not a worker/Root read grant.
//! The eventual owner composition must additionally keep its genuine Mount
//! reservation, Controller writer and original Host/kernel custody held.

use aos_proto::aos::sandbox::local::v1::{Audience, BrokerMethod};
use aos_sandbox::attachment_effect_owner::CurrentControllerFuseIntentDispatchV1;
use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox_core::{ProtocolId, RawPairedClockSample};
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_mount::host_scope::{HostMountScopeClient, ObservedMountScope};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::mount_fuse_reserve_intent::decode_fuse_reserve_intent_request_v1;
use aos_sandbox_protocol::mount_scope::decode_mount_scope_request;
use aos_sandbox_protocol::{
    AuthorizationArtifactBytes, PeerCredentials, PeerPolicy, decode_request_envelope,
};

use super::DormantAuthenticatedBrokerSessionV1;
use crate::entropy::{KernelEntropy, nonzero_random};
use crate::{BrokerSessionSecurityError, DormantBrokerSessionHandshakeErrorV1};

const MAGIC: &[u8; 8] = b"AOSFIC01";
const HEADER_BYTES: usize = 158;
const COORDINATE_BYTES: usize = 80;
const MAXIMUM_BYTES: usize = HEADER_BYTES + COORDINATE_BYTES;
const HOST_QUERY_MAGIC: &[u8; 8] = b"AOSFIH01";
const HOST_QUERY_PREFIX_BYTES: usize = HEADER_BYTES + 4;
const MAXIMUM_HOST_QUERY_PACKET_BYTES: usize = 1024 * 1024;
const MAXIMUM_HOST_QUERY_BYTES: usize = HOST_QUERY_PREFIX_BYTES + MAXIMUM_HOST_QUERY_PACKET_BYTES;

mod worker_handoff;
pub(crate) use worker_handoff::OriginalMountHostWorkerDispatchV1;

/// Carries only broker-assigned comparison coordinates for local Host issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FuseIntentReservationCoordinatesV1 {
    /// Carries a structural worker locator, never proof of reservation or reuse safety.
    pub(crate) worker_locator: [u8; 16],
    /// Carries the expected durable reservation/origin commitment for comparison.
    pub(crate) reservation_digest: [u8; 32],
    /// Carries the exact presentation-plan commitment for local request joining.
    pub(crate) presentation_plan_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Control {
    Challenge,
    HeldAcknowledgement,
    Reservation(FuseIntentReservationCoordinatesV1),
    ReservationAcknowledgement(FuseIntentReservationCoordinatesV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Binding {
    deadline: u64,
    session: [u8; 32],
    signed_request: [u8; 32],
    semantics: [u8; 32],
    challenge: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    BrokerChallenge,
    ClientChallenge,
    ClientHeldAck,
    BrokerHeldAck,
    ClientHostQuery,
    BrokerHostQuery,
    BrokerReservation,
    ClientReservation,
    ClientReservationAck(FuseIntentReservationCoordinatesV1),
    BrokerReservationAck(FuseIntentReservationCoordinatesV1),
    Prepared(FuseIntentReservationCoordinatesV1),
    WorkerIssuance(FuseIntentReservationCoordinatesV1),
    WorkerDispatched(FuseIntentReservationCoordinatesV1),
    ReconciliationRequired,
}

/// Holds original pending-request transport custody, never consumer authority.
#[must_use = "retain original session custody through preparation/reconciliation"]
pub(crate) struct HeldFuseIntentTransportV1<'session> {
    session: &'session mut DormantAuthenticatedBrokerSessionV1,
    request: &'session AuthenticatedBrokerMethodRequestV1,
    original_head: [u8; 32],
    binding: Binding,
    stage: Stage,
    // Installed only by Controller-side worker issuance, never from a frame
    // or on Mount's broker direction (whose original peer is Controller).
    worker_mount_verifier: Option<aos_sandbox_host::peer::ControllerPeerVerifier>,
}

impl<'session> HeldFuseIntentTransportV1<'session> {
    /// Completes the original client challenge/query without releasing owners.
    pub(crate) fn complete_original_host_query<T>(
        &mut self,
        controller: &mut CurrentControllerFuseIntentDispatchV1<'_>,
        clock: &mut T,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        loop {
            match self.receive_preparation_control() {
                Ok(()) => break,
                Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                    self.wait_original_socket(false)?;
                }
                Err(error) => return Err(error),
            }
        }
        loop {
            match self.send_preparation_control() {
                Ok(()) => break,
                Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                    self.wait_original_socket(true)?;
                }
                Err(error) => return Err(error),
            }
        }
        loop {
            match self.send_original_host_scope_query(controller, clock) {
                Ok(()) => return Ok(()),
                Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                    self.wait_original_socket(true)?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Holds actual Host and Mount preparation beneath the original broker flight.
    ///
    /// This does not complete the request or release its reservation. The
    /// callback is the subsequent fixed worker/Root owner composition, not a
    /// response-byte or scalar currentness adapter.
    pub(crate) fn with_original_mount_preparation<W, F, R>(
        &mut self,
        mount: &mut aos_sandbox_mount::broker::MountBroker<W>,
        host_cgroup_root: &CgroupV2Root,
        action: F,
    ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>
    where
        W: aos_sandbox_mount::worker::MountWorker,
        F: FnOnce(
            &mut Self,
            &mut aos_sandbox_mount::broker::HeldMountFuseIntentPreparationV1<'_, W>,
        ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>,
    {
        loop {
            match self.send_preparation_control() {
                Ok(()) => break,
                Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                    self.wait_original_socket(true)?;
                }
                Err(error) => return Err(error),
            }
        }
        loop {
            match self.receive_preparation_control() {
                Ok(()) => break,
                Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                    self.wait_original_socket(false)?;
                }
                Err(error) => return Err(error),
            }
        }
        let scope = loop {
            match self.observe_original_host_scope(host_cgroup_root) {
                Ok(scope) => break scope,
                Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                    self.wait_original_socket(false)?;
                }
                Err(error) => return Err(error),
            }
        };
        self.with_mount_preparation(mount, scope, action)
    }

    /// Drives the actual original reservation ACK and one-shot object producer.
    ///
    /// Both the original authenticated session writer and the independently
    /// authenticated physical Mount writer remain held through the callback.
    /// The callback receives original descriptor custody, not a connected
    /// worker/Root read grant. No challenge/INIT is enabled by this exchange.
    pub(crate) fn with_original_worker_handoff<W, F, R>(
        &mut self,
        mount: &mut aos_sandbox_mount::broker::MountBroker<W>,
        host_cgroup_root: &CgroupV2Root,
        action: F,
    ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>
    where
        W: aos_sandbox_mount::worker::MountWorker,
        F: FnOnce(
            &mut aos_sandbox_mount::broker::PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>,
    {
        self.with_original_worker_handoff_transport(mount, host_cgroup_root, |_, handoff| {
            action(handoff)
        })
    }

    /// Lends both genuine original owners to the fixed four-role sender.
    pub(crate) fn with_original_worker_handoff_transport<W, F, R>(
        &mut self,
        mount: &mut aos_sandbox_mount::broker::MountBroker<W>,
        host_cgroup_root: &CgroupV2Root,
        action: F,
    ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>
    where
        W: aos_sandbox_mount::worker::MountWorker,
        F: FnOnce(
            &mut Self,
            &mut aos_sandbox_mount::broker::PreparedMountFuseWorkerHandoffV1<'_, '_, W>,
        ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>,
    {
        let result = self.with_original_mount_preparation(
            mount,
            host_cgroup_root,
            |transport, preparation| {
                preparation
                    .recheck()
                    .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                let coordinates = FuseIntentReservationCoordinatesV1 {
                    worker_locator: preparation.worker_locator(),
                    reservation_digest: preparation
                        .reservation_digest()
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?,
                    presentation_plan_digest: preparation.presentation_plan_digest(),
                };

                loop {
                    preparation
                        .recheck()
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                    match transport.send_reservation_coordinates(coordinates) {
                        Ok(()) => break,
                        Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                            transport.wait_original_socket(true)?;
                        }
                        Err(error) => return Err(error),
                    }
                }
                loop {
                    preparation
                        .recheck()
                        .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                    match transport.receive_preparation_control() {
                        Ok(()) => break,
                        Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                            transport.wait_original_socket(false)?;
                        }
                        Err(error) => return Err(error),
                    }
                }
                if transport.prepared_coordinates()? != coordinates {
                    return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
                }

                // This is the actual owner producer, after the original
                // authenticated ACK, not reconstruction from its wire fields.
                let objects = preparation
                    .prepare_original_worker_objects()
                    .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                let mut handoff = objects
                    .into_original_host_handoff()
                    .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                transport.recheck()?;
                handoff
                    .recheck()
                    .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                let result = action(transport, &mut handoff);
                handoff
                    .recheck()
                    .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
                transport.recheck()?;
                result
            },
        );
        // Neither return nor lost reply is a reusable preparation. Dropping
        // the local objects closes cancellation; durable rows remain occupied.
        self.stage = Stage::ReconciliationRequired;
        result
    }

    fn wait_original_socket(
        &mut self,
        write: bool,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        let result = (|| {
            self.recheck()?;
            crate::dormant_handshake::wait_for_handshake_readiness(
                self.session.as_fd()?,
                write,
                self.binding.deadline,
            )?;
            self.recheck()?;
            Ok(())
        })();
        if result.is_err() {
            self.stage = Stage::ReconciliationRequired;
        }
        result
    }

    /// Sends only the query produced by this genuine held Controller cut.
    ///
    /// The packet carries an existing signed Host grant. It does not authorize
    /// Mount preparation until the broker independently obtains the actual
    /// Host response and retains its original payload descriptors.
    pub(crate) fn send_original_host_scope_query<T>(
        &mut self,
        controller: &mut CurrentControllerFuseIntentDispatchV1<'_>,
        clock: &mut T,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let result = (|| {
            self.recheck()?;
            if self.stage != Stage::ClientHostQuery
                || controller.request_body() != self.request.exact_body()
                || *controller.semantics().commitment().digest().as_bytes()
                    != self.binding.semantics
            {
                return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
            }
            let packet = controller
                .original_host_scope_packet_at(clock)
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            self.validate_host_scope_packet(&packet)?;
            let framed = encode_host_query(self.binding, &packet)?;
            self.session.send_request_packet(&framed)?;
            self.stage = Stage::ClientReservation;
            controller
                .recheck(clock)
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            self.recheck()?;
            Ok(())
        })();
        if result.is_err()
            && !matches!(
                &result,
                Err(DormantBrokerSessionHandshakeErrorV1::Transport)
            )
        {
            // Keep the signed pending flight: the query may already have
            // crossed the socket when local currentness or delivery fails.
            self.stage = Stage::ReconciliationRequired;
        }
        result
    }

    /// Acquires actual Host custody before the lower Mount reservation producer.
    ///
    /// The query is accepted only from the original authenticated Controller
    /// record on this same pending session. The configured Host cgroup comes
    /// from the existing daemon's retained cgroup root, never from the packet.
    /// A lost query/Host reply cannot be retried by manufacturing a new scope.
    pub(crate) fn observe_original_host_scope(
        &mut self,
        host_cgroup_root: &CgroupV2Root,
    ) -> Result<ObservedMountScope, DormantBrokerSessionHandshakeErrorV1> {
        let result = (|| {
            self.recheck()?;
            if self.stage != Stage::BrokerHostQuery {
                return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
            }
            // The common zero-FD receive checks each record's actual subject
            // against the same original authenticated peer before returning.
            let framed = self
                .session
                .receive_response_packet(MAXIMUM_HOST_QUERY_BYTES)?;
            let (binding, packet) = decode_host_query(&framed)?;
            if binding != self.binding {
                return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
            }
            self.validate_host_scope_packet(packet)?;
            let envelope = decode_request_envelope(packet, ProtocolId::HostBroker, 0)
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            let authorization = envelope
                .authorization()
                .ok_or(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            self.recheck()?;
            let scope = HostMountScopeClient::connect(host_cgroup_root)
                .and_then(|client| {
                    client.observe(
                        envelope.body(),
                        AuthorizationArtifactBytes {
                            broker_plan: authorization.broker_plan(),
                            broker_plan_signature: authorization.broker_plan_signature(),
                            ownership_lease: authorization.ownership_lease(),
                            ownership_lease_signature: authorization.ownership_lease_signature(),
                        },
                    )
                })
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            self.recheck()?;
            self.stage = Stage::BrokerReservation;
            Ok(scope)
        })();
        if result.is_err()
            && !matches!(
                &result,
                Err(DormantBrokerSessionHandshakeErrorV1::Transport)
            )
        {
            self.stage = Stage::ReconciliationRequired;
        }
        result
    }

    fn validate_host_scope_packet(
        &self,
        packet: &[u8],
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        let invalid = || DormantBrokerSessionHandshakeErrorV1::RemoteInvalid;
        let now = super::protected_boottime_nanoseconds()?;
        let original = decode_fuse_reserve_intent_request_v1(
            self.request.exact_body(),
            self.request.peer(),
            self.request.peer_policy(),
            now,
        )
        .map_err(|_| invalid())?;
        let envelope =
            decode_request_envelope(packet, ProtocolId::HostBroker, 0).map_err(|_| invalid())?;
        if envelope.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
            || !envelope.descriptors().is_empty()
            || envelope.authorization().is_none()
        {
            return Err(invalid());
        }
        // Fixed decoder coordinates are not sender evidence. Host checks its
        // real RootMount record independently; this only prevents substitution
        // of another query under the original authenticated FUSE flight.
        let query = decode_mount_scope_request(
            envelope.body(),
            PeerCredentials {
                uid: 0,
                gid: 0,
                pid: Some(1),
            },
            PeerPolicy {
                uid: 0,
                gid: Some(0),
                audience: Audience::AUDIENCE_ROOT_MOUNT,
            },
            now,
        )
        .map_err(|_| invalid())?;
        if query.header().request_id() != original.header().request_id()
            || query.header().deadline_boottime_nanoseconds() != self.binding.deadline
            || query.fence() != original.fence()
            || query.runtime_handle() != original.runtime_handle()
            || query.payload_scope_handle() != original.payload_scope_handle()
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Joins the actual Mount writer without releasing original session custody.
    ///
    /// This invokes the real signature/slot/Host reservation producer. The
    /// action keeps both owners borrowed through preparation. No returned
    /// coordinate or ACK becomes a Root/current-worker content grant.
    pub(crate) fn with_mount_preparation<W, F, R>(
        &mut self,
        mount: &mut aos_sandbox_mount::broker::MountBroker<W>,
        scope: aos_sandbox_mount::host_scope::ObservedMountScope,
        action: F,
    ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>
    where
        W: aos_sandbox_mount::worker::MountWorker,
        F: FnOnce(
            &mut Self,
            &mut aos_sandbox_mount::broker::HeldMountFuseIntentPreparationV1<'_, W>,
        ) -> Result<R, DormantBrokerSessionHandshakeErrorV1>,
    {
        let result = (|| {
            self.recheck()?;
            if self.stage != Stage::BrokerReservation {
                return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
            }
            let mut preparation = mount
                .prepare_authenticated_fuse_intent(self.request, scope)
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            self.recheck()?;
            let result = action(self, &mut preparation);
            preparation
                .recheck()
                .map_err(|_| DormantBrokerSessionHandshakeErrorV1::RemoteInvalid)?;
            self.recheck()?;
            result
        })();
        if result.is_err() {
            // A row may have committed or a preparation reply may have been
            // sent. Neither callback error nor lost ACK permits automatic reuse.
            self.stage = Stage::ReconciliationRequired;
        }
        result
    }

    pub(super) fn capture(
        session: &'session mut DormantAuthenticatedBrokerSessionV1,
        request: &'session AuthenticatedBrokerMethodRequestV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        if usize::try_from(request.maximum_response_bytes())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            < MAXIMUM_BYTES
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let original_head = session
            .owner
            .hold_fuse_intent_request(request, &session.transcript, session.socket.peer())?
            .head_commitment();
        let broker = request.direction() == AuthenticatedBrokerRequestDirectionV1::ServerReceive;
        let challenge = if broker {
            nonzero_random(&mut KernelEntropy)?
        } else {
            [0; 32]
        };
        Ok(Self {
            session,
            request,
            original_head,
            binding: Binding {
                deadline: request.deadline_boottime_nanoseconds(),
                session: request.session_binding(),
                signed_request: request.signed_request_digest(),
                semantics: request.semantic_commitment(),
                challenge,
            },
            stage: if broker {
                Stage::BrokerChallenge
            } else {
                Stage::ClientChallenge
            },
            worker_mount_verifier: None,
        })
    }

    /// Reauthenticates the same nonterminal protected head and original peer.
    pub(crate) fn recheck(&mut self) -> Result<(), BrokerSessionSecurityError> {
        let result = self.recheck_original_head();
        if result.is_err() {
            self.stage = Stage::ReconciliationRequired;
        }
        result
    }

    fn recheck_original_head(&mut self) -> Result<(), BrokerSessionSecurityError> {
        if self.stage == Stage::ReconciliationRequired {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut pending = self.session.owner.hold_fuse_intent_request(
            self.request,
            &self.session.transcript,
            self.session.socket.peer(),
        )?;
        if let Some(verifier) = &self.worker_mount_verifier {
            if self.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            pending.recheck_mount_worker_peer(verifier)?;
        } else {
            pending.recheck()?;
        }
        if pending.head_commitment() != self.original_head {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    /// Sends one challenge/ack on the same socket without issuing an outcome.
    pub(crate) fn send_preparation_control(
        &mut self,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        let (control, next) = match self.stage {
            Stage::BrokerChallenge => (Control::Challenge, Stage::BrokerHeldAck),
            Stage::ClientHeldAck => (Control::HeldAcknowledgement, Stage::ClientHostQuery),
            Stage::ClientReservationAck(coordinates) => (
                Control::ReservationAcknowledgement(coordinates),
                Stage::Prepared(coordinates),
            ),
            _ => return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid),
        };
        self.send(control, next)
    }

    /// Sends comparison coordinates only; the caller still owes genuine Mount custody.
    ///
    /// This does not certify the row or mint a guard from these scalar fields.
    /// It is private to the closed owner composition and remains unadvertised.
    pub(crate) fn send_reservation_coordinates(
        &mut self,
        coordinates: FuseIntentReservationCoordinatesV1,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        if self.stage != Stage::BrokerReservation || !coordinates_valid(coordinates) {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        self.send(
            Control::Reservation(coordinates),
            Stage::BrokerReservationAck(coordinates),
        )
    }

    /// Receives only an exact original-peer zero-FD preparation record.
    pub(crate) fn receive_preparation_control(
        &mut self,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.recheck()?;
        // The reused receive path binds every record's SCM credentials/pidfd
        // to the retained original peer, then rechecks live endpoint custody.
        let packet = match self
            .session
            .receive_response_packet(MAXIMUM_BYTES)
            .map_err(DormantBrokerSessionHandshakeErrorV1::from)
        {
            Ok(packet) => packet,
            Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                return Err(DormantBrokerSessionHandshakeErrorV1::Transport);
            }
            Err(error) => {
                self.stage = Stage::ReconciliationRequired;
                return Err(error);
            }
        };
        let result = self.admit_control(&packet);
        if result.is_err() {
            self.stage = Stage::ReconciliationRequired;
        }
        result?;
        self.recheck()?;
        Ok(())
    }

    /// Returns prepared coordinates for comparison/local issuance, not authority.
    pub(crate) fn prepared_coordinates(
        &mut self,
    ) -> Result<FuseIntentReservationCoordinatesV1, BrokerSessionSecurityError> {
        self.recheck()?;
        match self.stage {
            Stage::Prepared(coordinates) => Ok(coordinates),
            _ => Err(BrokerSessionSecurityError::Currentness),
        }
    }

    fn send(
        &mut self,
        control: Control,
        next: Stage,
    ) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        self.recheck()?;
        let packet = encode(self.binding, control);
        match self
            .session
            .send_request_packet(&packet)
            .map_err(DormantBrokerSessionHandshakeErrorV1::from)
        {
            Ok(()) => self.stage = next,
            Err(DormantBrokerSessionHandshakeErrorV1::Transport) => {
                return Err(DormantBrokerSessionHandshakeErrorV1::Transport);
            }
            Err(error) => {
                self.stage = Stage::ReconciliationRequired;
                return Err(error);
            }
        }
        self.recheck()?;
        Ok(())
    }

    fn admit_control(&mut self, packet: &[u8]) -> Result<(), DormantBrokerSessionHandshakeErrorV1> {
        let (binding, control) = decode(packet)?;
        let original = Binding {
            challenge: binding.challenge,
            ..self.binding
        };
        if binding != original
            || binding.challenge == [0; 32]
            || (self.binding.challenge != [0; 32] && binding.challenge != self.binding.challenge)
        {
            return Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid);
        }
        self.stage = next_control_stage(self.stage, control)?;
        self.binding.challenge = binding.challenge;
        Ok(())
    }
}

// Mechanical phase comparison only: callers still owe the original held
// request, per-record subject admission and both genuine writer rechecks.
fn next_control_stage(
    stage: Stage,
    control: Control,
) -> Result<Stage, DormantBrokerSessionHandshakeErrorV1> {
    match (stage, control) {
        (Stage::ClientChallenge, Control::Challenge) => Ok(Stage::ClientHeldAck),
        (Stage::BrokerHeldAck, Control::HeldAcknowledgement) => Ok(Stage::BrokerHostQuery),
        (Stage::ClientReservation, Control::Reservation(coordinates)) => {
            Ok(Stage::ClientReservationAck(coordinates))
        }
        (Stage::BrokerReservationAck(expected), Control::ReservationAcknowledgement(observed))
            if expected == observed =>
        {
            Ok(Stage::Prepared(expected))
        }
        _ => Err(DormantBrokerSessionHandshakeErrorV1::RemoteInvalid),
    }
}

fn coordinates_valid(coordinates: FuseIntentReservationCoordinatesV1) -> bool {
    coordinates.worker_locator != [0; 16]
        && coordinates.reservation_digest != [0; 32]
        && coordinates.presentation_plan_digest != [0; 32]
}

fn encode(binding: Binding, control: Control) -> Vec<u8> {
    let (kind, coordinates) = match control {
        Control::Challenge => (1, None),
        Control::HeldAcknowledgement => (2, None),
        Control::Reservation(coordinates) => (3, Some(coordinates)),
        Control::ReservationAcknowledgement(coordinates) => (4, Some(coordinates)),
    };
    let mut bytes = encode_binding_header(binding, MAGIC, kind);
    if let Some(coordinates) = coordinates {
        bytes.extend_from_slice(&coordinates.worker_locator);
        bytes.extend_from_slice(&coordinates.reservation_digest);
        bytes.extend_from_slice(&coordinates.presentation_plan_digest);
    }
    bytes
}

// Both closed formats share the exact original flight join, not an authority
// constructor. Their distinct magic and kind checks prevent cross-decoding.
fn encode_binding_header(binding: Binding, magic: &[u8; 8], kind: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES);
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[kind, 0]);
    bytes.extend_from_slice(&44_u16.to_be_bytes());
    bytes.extend_from_slice(&57_u32.to_be_bytes());
    bytes.extend_from_slice(&3_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&binding.deadline.to_be_bytes());
    for commitment in [
        binding.session,
        binding.signed_request,
        binding.semantics,
        binding.challenge,
    ] {
        bytes.extend_from_slice(&commitment);
    }
    bytes
}

fn decode(bytes: &[u8]) -> Result<(Binding, Control), DormantBrokerSessionHandshakeErrorV1> {
    let invalid = || DormantBrokerSessionHandshakeErrorV1::RemoteInvalid;
    if !matches!(bytes.len(), HEADER_BYTES | MAXIMUM_BYTES) {
        return Err(invalid());
    }
    let binding = decode_binding_header(bytes, MAGIC)?;
    let control = match (bytes[10], bytes.len()) {
        (1, HEADER_BYTES) => Control::Challenge,
        (2, HEADER_BYTES) => Control::HeldAcknowledgement,
        (kind @ (3 | 4), MAXIMUM_BYTES) => {
            let coordinates = FuseIntentReservationCoordinatesV1 {
                worker_locator: bytes[158..174].try_into().map_err(|_| invalid())?,
                reservation_digest: bytes[174..206].try_into().map_err(|_| invalid())?,
                presentation_plan_digest: bytes[206..238].try_into().map_err(|_| invalid())?,
            };
            if !coordinates_valid(coordinates) {
                return Err(invalid());
            }
            if kind == 3 {
                Control::Reservation(coordinates)
            } else {
                Control::ReservationAcknowledgement(coordinates)
            }
        }
        _ => return Err(invalid()),
    };
    Ok((binding, control))
}

fn decode_binding_header(
    bytes: &[u8],
    magic: &[u8; 8],
) -> Result<Binding, DormantBrokerSessionHandshakeErrorV1> {
    decode_binding_header_version(bytes, magic, 1)
}

fn decode_binding_header_version(
    bytes: &[u8],
    magic: &[u8; 8],
    version: u16,
) -> Result<Binding, DormantBrokerSessionHandshakeErrorV1> {
    let invalid = || DormantBrokerSessionHandshakeErrorV1::RemoteInvalid;
    if bytes.len() < HEADER_BYTES
        || bytes.get(..8) != Some(magic.as_slice())
        || bytes.get(8..10) != Some(version.to_be_bytes().as_slice())
        || bytes[11] != 0
        || bytes.get(12..22) != Some([0, 44, 0, 0, 0, 57, 0, 3, 0, 0].as_slice())
    {
        return Err(invalid());
    }
    let binding = Binding {
        deadline: u64::from_be_bytes(bytes[22..30].try_into().map_err(|_| invalid())?),
        session: bytes[30..62].try_into().map_err(|_| invalid())?,
        signed_request: bytes[62..94].try_into().map_err(|_| invalid())?,
        semantics: bytes[94..126].try_into().map_err(|_| invalid())?,
        challenge: bytes[126..158].try_into().map_err(|_| invalid())?,
    };
    if binding.deadline == 0
        || [
            binding.session,
            binding.signed_request,
            binding.semantics,
            binding.challenge,
        ]
        .contains(&[0; 32])
    {
        return Err(invalid());
    }
    Ok(binding)
}

fn encode_host_query(
    binding: Binding,
    packet: &[u8],
) -> Result<Vec<u8>, DormantBrokerSessionHandshakeErrorV1> {
    let invalid = || DormantBrokerSessionHandshakeErrorV1::RemoteInvalid;
    if packet.is_empty() || packet.len() > MAXIMUM_HOST_QUERY_PACKET_BYTES {
        return Err(invalid());
    }
    let length = u32::try_from(packet.len()).map_err(|_| invalid())?;
    let mut bytes = encode_binding_header(binding, HOST_QUERY_MAGIC, 1);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(packet);
    Ok(bytes)
}

fn decode_host_query(
    bytes: &[u8],
) -> Result<(Binding, &[u8]), DormantBrokerSessionHandshakeErrorV1> {
    let invalid = || DormantBrokerSessionHandshakeErrorV1::RemoteInvalid;
    if bytes.len() <= HOST_QUERY_PREFIX_BYTES || bytes.len() > MAXIMUM_HOST_QUERY_BYTES {
        return Err(invalid());
    }
    let binding = decode_binding_header(bytes, HOST_QUERY_MAGIC)?;
    if bytes[10] != 1 {
        return Err(invalid());
    }
    let length = usize::try_from(u32::from_be_bytes(
        bytes[HEADER_BYTES..HOST_QUERY_PREFIX_BYTES]
            .try_into()
            .map_err(|_| invalid())?,
    ))
    .map_err(|_| invalid())?;
    let packet = &bytes[HOST_QUERY_PREFIX_BYTES..];
    if packet.len() != length {
        return Err(invalid());
    }
    Ok((binding, packet))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::DormantBrokerSessionHandshakeErrorV1 as SessionError;
    use sha2::Digest as _;

    #[test]
    fn only_exact_original_reservation_ack_reaches_the_object_preparation_phase() {
        let original = FuseIntentReservationCoordinatesV1 {
            worker_locator: [1; 16],
            reservation_digest: [2; 32],
            presentation_plan_digest: [3; 32],
        };

        assert_eq!(
            next_control_stage(
                Stage::BrokerReservationAck(original),
                Control::ReservationAcknowledgement(original),
            )
            .unwrap(),
            Stage::Prepared(original),
        );
        for field in 0..3 {
            let mut substituted = original;
            match field {
                0 => substituted.worker_locator[0] ^= 1,
                1 => substituted.reservation_digest[0] ^= 1,
                _ => substituted.presentation_plan_digest[0] ^= 1,
            }
            assert!(
                next_control_stage(
                    Stage::BrokerReservationAck(original),
                    Control::ReservationAcknowledgement(substituted),
                )
                .is_err(),
                "substituted coordinate {field}",
            );
        }
    }

    #[test]
    fn prepared_or_reconciliation_phase_cannot_reenter_original_preparation() {
        let original = FuseIntentReservationCoordinatesV1 {
            worker_locator: [1; 16],
            reservation_digest: [2; 32],
            presentation_plan_digest: [3; 32],
        };
        for stage in [Stage::Prepared(original), Stage::ReconciliationRequired] {
            for control in [
                Control::Challenge,
                Control::HeldAcknowledgement,
                Control::Reservation(original),
                Control::ReservationAcknowledgement(original),
            ] {
                assert!(next_control_stage(stage, control).is_err());
            }
        }
    }

    #[test]
    fn session_error_conversion_preserves_transport_and_fail_closed_classes() {
        // Conversion must happen before the retry branch, not collapse every
        // session error into Transport or an unclassified diagnostic string.
        for (session_error, expected) in [
            (
                SessionError::Transport,
                DormantBrokerSessionHandshakeErrorV1::Transport,
            ),
            (
                SessionError::EndpointRole,
                DormantBrokerSessionHandshakeErrorV1::EndpointRole,
            ),
            (
                SessionError::RemoteInvalid,
                DormantBrokerSessionHandshakeErrorV1::RemoteInvalid,
            ),
            (
                SessionError::KernelEvidence,
                DormantBrokerSessionHandshakeErrorV1::KernelEvidence,
            ),
        ] {
            let actual = DormantBrokerSessionHandshakeErrorV1::from(session_error);

            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
        }

        let actual = DormantBrokerSessionHandshakeErrorV1::from(SessionError::Protected(
            BrokerSessionSecurityError::Poisoned,
        ));

        assert!(matches!(
            actual,
            DormantBrokerSessionHandshakeErrorV1::Protected(BrokerSessionSecurityError::Poisoned)
        ));
    }

    #[test]
    fn original_host_query_has_a_distinct_bounded_frame() {
        let binding = Binding {
            deadline: 100,
            session: [1; 32],
            signed_request: [2; 32],
            semantics: [3; 32],
            challenge: [4; 32],
        };
        // This is only a frame vector, not a signed Host query or live owner.
        let packet = [0x41; 23];
        let bytes = encode_host_query(binding, &packet).unwrap();

        assert_eq!(
            decode_host_query(&bytes).unwrap(),
            (binding, packet.as_slice())
        );
        assert_eq!(&bytes[..8], b"AOSFIH01");
        assert_eq!(bytes.len(), HOST_QUERY_PREFIX_BYTES + packet.len());
        assert!(decode(&bytes).is_err());
        for control in [Control::Challenge, Control::HeldAcknowledgement] {
            assert!(decode_host_query(&encode(binding, control)).is_err());
        }

        for length in 0..bytes.len() {
            assert!(
                decode_host_query(&bytes[..length]).is_err(),
                "truncation {length}"
            );
        }
        for offset in [
            0, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 158, 159, 160, 161,
        ] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(
                decode_host_query(&changed).is_err(),
                "substitution {offset}"
            );
        }
        for range in [22..30, 30..62, 62..94, 94..126, 126..158] {
            let mut changed = bytes.clone();
            changed[range].fill(0);
            assert!(decode_host_query(&changed).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_host_query(&trailing).is_err());
        assert!(encode_host_query(binding, &[]).is_err());
        assert!(encode_host_query(binding, &vec![1; MAXIMUM_HOST_QUERY_PACKET_BYTES + 1]).is_err());
    }

    #[test]
    fn preparation_records_bind_the_original_request_and_refuse_extensions() {
        let binding = Binding {
            deadline: 100,
            session: [1; 32],
            signed_request: [2; 32],
            semantics: [3; 32],
            challenge: [4; 32],
        };
        let coordinates = FuseIntentReservationCoordinatesV1 {
            worker_locator: [5; 16],
            reservation_digest: [6; 32],
            presentation_plan_digest: [7; 32],
        };
        assert_eq!(
            hex::encode(sha2::Sha256::digest(encode(
                binding,
                Control::Reservation(coordinates)
            ))),
            "bab05e80d4f41a124308d26e954092bc0b35e256e2e48b868ea6d55e104ee432"
        );
        for control in [
            Control::Challenge,
            Control::HeldAcknowledgement,
            Control::Reservation(coordinates),
            Control::ReservationAcknowledgement(coordinates),
        ] {
            let bytes = encode(binding, control);
            assert_eq!(decode(&bytes).unwrap(), (binding, control));
            for length in 0..bytes.len() {
                assert!(decode(&bytes[..length]).is_err(), "truncation {length}");
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(decode(&trailing).is_err());
            for offset in [0, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21] {
                let mut changed = bytes.clone();
                changed[offset] ^= 1;
                assert!(decode(&changed).is_err(), "header substitution {offset}");
            }
        }
    }
}
