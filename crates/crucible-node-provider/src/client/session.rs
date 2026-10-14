//! Original controller requests and verified content on an authenticated CNP stream.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use crucible_node_contract::{ContentRef, Extensions, HashRef, Id, U64, canonical};
use serde_json::{Map, Value};

use crate::ProviderError;
use crate::bodies::*;
use crate::connection::{
    BodySchemaVerifier, Connection, ConnectionSupervisor, EndpointRole, ReceivedBody,
};
use crate::envelope::{Envelope, MessageKind, RequestOrigin};
use crate::handshake::{ConnectionAuthority, Handshake, TrustedHandshakeVerifier};
use crate::transport::{FrameReader, write_frame_with_limits};

use super::{ClientContent, DeadlineStream, ExchangeDeadline};

#[path = "session/original_conflict.rs"]
pub(super) mod original_conflict;
#[path = "session/resend.rs"]
mod resend;

#[path = "session/lifecycle_resend.rs"]
mod lifecycle_resend;

#[path = "session/hello_journal.rs"]
mod hello_journal;
pub use hello_journal::OriginalHelloJournal;

/// Binds the actual socket peer to independently measured launch facts.
pub struct ClientPeer {
    /// Names the original retained provider process, never a provider JSON claim.
    pub pid: u32,
    /// Names the locally admitted native process user.
    pub uid: u32,
    /// Commits to the actual source-installed provider executable bytes.
    pub executable: ContentRef,
}

/// Retains one immutable original request and its last authentic transport response.
#[derive(Clone, serde::Serialize)]
pub struct ClientOriginal {
    /// Contains the complete original method, IDs, scope and request body.
    pub request: Envelope,
    /// Commits to the original identity independently of connection sequence.
    pub identity: HashRef,
    /// Retains a received original response, or none after uncertain transport loss.
    pub response: Option<Envelope>,
}

/// Reports unrecycled original journal credit on one actual sealed controller.
///
/// These borrowed numeric facts do not authenticate Capture or grant authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalNative5CustodyFacts {
    /// Limits lifetime originals independently in each request namespace.
    pub maximum_requests_per_namespace: usize,
    /// Counts retained original controller requests, including completed history.
    pub controller_originals: usize,
    /// Counts retained original provider requests, including completed history.
    pub provider_originals: usize,
    /// Limits complete raw request and response journal bytes.
    pub maximum_journal_bytes: usize,
    /// Counts actual retained raw request and response journal bytes.
    pub retained_journal_bytes: usize,
    /// Limits lifetime entries under the same negotiated registration.
    pub negotiated_journal_entries: u64,
}

/// Keeps finite original request and content custody across connection replacement.
pub struct ClientCustody {
    maximum_requests: usize,
    maximum_bytes: usize,
    retained_bytes: usize,
    controller: BTreeMap<Id, ClientOriginal>,
    provider: BTreeMap<Id, ClientOriginal>,
    content: ClientContent,
}

impl ClientCustody {
    pub(super) fn original_native5_custody_facts(
        &self,
        negotiated_journal_entries: u64,
    ) -> OriginalNative5CustodyFacts {
        OriginalNative5CustodyFacts {
            maximum_requests_per_namespace: self.maximum_requests,
            controller_originals: self.controller.len(),
            provider_originals: self.provider.len(),
            maximum_journal_bytes: self.maximum_bytes,
            retained_journal_bytes: self.retained_bytes,
            negotiated_journal_entries,
        }
    }

    pub(super) fn protocol_view(&self) -> impl serde::Serialize + '_ {
        (
            self.maximum_requests,
            self.maximum_bytes,
            self.retained_bytes,
            &self.controller,
            &self.provider,
            self.content.protocol_view(),
        )
    }

    pub(super) fn preflight_response(
        &self,
        controller_requests: usize,
        provider_requests: usize,
        journal_bytes: usize,
        negotiated_entries: usize,
    ) -> Result<(), ProviderError> {
        let maximum = self.maximum_requests.min(negotiated_entries);
        if self
            .controller
            .len()
            .checked_add(controller_requests)
            .is_none_or(|total| total > maximum)
            || self
                .provider
                .len()
                .checked_add(provider_requests)
                .is_none_or(|total| total > maximum)
        {
            return Err(ProviderError::ResourceExhausted(
                "complete source response journal entries",
            ));
        }
        self.ensure_journal_room(journal_bytes)
    }

    /// Creates bounded ledgers before admitting any wire request.
    ///
    /// # Errors
    /// Refuses zero or greater-than4096 original request capacity.
    pub fn new(maximum_requests: usize, content: ClientContent) -> Result<Self, ProviderError> {
        if maximum_requests == 0 || maximum_requests > 4096 {
            return Err(ProviderError::ResourceExhausted(
                "client original request ceiling",
            ));
        }
        Ok(Self {
            maximum_requests,
            maximum_bytes: content.byte_ceiling(),
            retained_bytes: 0,
            controller: BTreeMap::new(),
            provider: BTreeMap::new(),
            content,
        })
    }

    /// Returns the original unrecycled request capacity per endpoint namespace.
    pub fn maximum_requests(&self) -> usize {
        self.maximum_requests
    }

    /// Returns the independently bounded raw journal and content reservations.
    ///
    /// The two stores each retain their original complete bytes, so callers
    /// reserve both extents. This does not describe decoded semantic storage.
    pub fn byte_reservations(&self) -> (usize, usize) {
        (self.maximum_bytes, self.content.byte_ceiling())
    }

    /// Returns retained originals including requests whose effects remain unknown.
    pub fn originals(&self) -> impl Iterator<Item = &ClientOriginal> {
        self.controller.values().chain(self.provider.values())
    }

    /// Returns one original from its explicit endpoint namespace.
    ///
    /// Equal request IDs from opposite endpoints remain independent. A lookup
    /// grants no native authority and does not retry or release the original.
    pub fn original(&self, origin: RequestOrigin, request_id: &Id) -> Option<&ClientOriginal> {
        match origin {
            RequestOrigin::Controller => self.controller.get(request_id),
            RequestOrigin::Provider => self.provider.get(request_id),
        }
    }

    /// Enumerates finite retained originals from one explicit endpoint namespace.
    ///
    /// Enumeration does not infer origin from a method, envelope body, or ID.
    pub fn originals_by_origin(
        &self,
        origin: RequestOrigin,
    ) -> impl Iterator<Item = &ClientOriginal> {
        match origin {
            RequestOrigin::Controller => self.controller.values(),
            RequestOrigin::Provider => self.provider.values(),
        }
    }

    /// Returns immutable byte custody for independent installed receipt verification.
    pub fn content(&self) -> &ClientContent {
        &self.content
    }

    /// Returns mutable byte custody for independently verified installation content.
    pub fn content_mut(&mut self) -> &mut ClientContent {
        &mut self.content
    }

    fn ensure_journal_room(&self, bytes: usize) -> Result<(), ProviderError> {
        if self
            .retained_bytes
            .checked_add(bytes)
            .is_none_or(|total| total > self.maximum_bytes)
        {
            return Err(ProviderError::ResourceExhausted(
                "client original journal bytes",
            ));
        }
        Ok(())
    }

    fn retain_journal_bytes(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.ensure_journal_room(bytes)?;
        self.retained_bytes += bytes;
        Ok(())
    }
}

/// Owns one host-authenticated connection without granting native receipt authority.
pub struct ClientSession {
    connection: Connection<DeadlineStream>,
    authority: ConnectionAuthority,
    deadline: ExchangeDeadline,
    sequence: U64,
    peer_pid: u32,
    peer_executable: ContentRef,
    pub(super) original_response_loss:
        Option<super::reference::original_response_loss::OriginalResponseLossRecorder>,
}

enum InitialDeadline {
    Fresh(Duration),
    Original(ExchangeDeadline),
}

impl From<Duration> for InitialDeadline {
    fn from(budget: Duration) -> Self {
        Self::Fresh(budget)
    }
}

impl From<ExchangeDeadline> for InitialDeadline {
    fn from(deadline: ExchangeDeadline) -> Self {
        Self::Original(deadline)
    }
}

impl ClientSession {
    pub(super) fn prepare_fresh_native5_protocol_mapping(
        &mut self,
        original: &crate::protocol_snapshot::OriginalProtocolSnapshot,
        owner: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    ) -> Result<crate::protocol_snapshot::PreparedFreshProtocolMapping, ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.sequence.get() != 2 {
            return Err(ProviderError::Correlation(
                "fresh native5 session already used",
            ));
        }
        self.connection
            .prepare_fresh_protocol_mapping_for_owner(original, owner)
    }

    pub(super) fn authenticate_fresh_native5_protocol_mapping(
        &self,
        original: &crate::protocol_snapshot::OriginalProtocolSnapshot,
        mapping: &crate::protocol_snapshot::PreparedFreshProtocolMapping,
        owner: &Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        if self.sequence.get() != 2 {
            return Err(ProviderError::Correlation(
                "fresh native5 mapped session already used",
            ));
        }
        self.connection
            .authenticate_fresh_native5_mapping_for_owner(original, mapping, owner)
    }

    pub(super) fn original_native5_codec_owner(
        &self,
    ) -> Option<&Rc<crate::connection::Native5CodecOwner>> {
        self.connection.retained_native5_codec_owner()
    }

    pub(super) fn protocol_original_deadline(
        &self,
    ) -> crate::operational_time::OperationalDeadline {
        self.deadline.original_cut()
    }

    pub(super) fn protocol_capture_preflight(
        &mut self,
        cut: crate::protocol_snapshot::ProtocolCaptureCut,
    ) -> Result<(), ProviderError> {
        if self.original_response_loss.is_some() {
            return Err(ProviderError::Correlation(
                "mutable response-loss callback cannot be captured",
            ));
        }
        self.authority.ensure_live()?;
        self.connection.protocol_capture_preflight(cut)
    }

    pub(super) fn authenticate_native5_source_codec(&self) -> Result<(), ProviderError> {
        if self.original_response_loss.is_some() {
            return Err(ProviderError::Correlation(
                "native5 codec proof refuses mutable loss callback",
            ));
        }
        self.authority.ensure_live()?;
        self.connection.authenticate_native5_source_codec()
    }

    pub(super) fn original_native5_journal_entries(&self) -> Result<u64, ProviderError> {
        self.authenticate_native5_source_codec()?;
        Ok(self.authority.limits().journal_entries.get())
    }

    pub(super) fn original_native5_storage_facts(
        &self,
    ) -> Result<crate::protocol_snapshot::OriginalProtocolStorageFacts, ProviderError> {
        if self.original_response_loss.is_some() {
            return Err(ProviderError::Correlation(
                "native5 storage facts refuse mutable loss callback",
            ));
        }
        self.authority.ensure_live()?;
        self.connection.original_native5_storage_facts()
    }

    pub(super) fn preflight_protocol_reservation(
        &self,
        reservation: &crate::protocol_snapshot::ProtocolSnapshotReservation,
    ) -> Result<(), ProviderError> {
        self.connection.preflight_protocol_reservation(reservation)
    }

    pub(super) fn retain_frozen_protocol_frames(
        &self,
        reservation: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
    ) -> Result<(), ProviderError> {
        self.connection.retain_frozen_protocol_frames(reservation)
    }

    pub(super) fn protocol_view(&self) -> impl serde::Serialize + '_ {
        (
            self.connection.protocol_view(),
            &self.sequence,
            self.peer_pid,
            &self.peer_executable,
            "original-physical-cut-retained-by-source-not-portable-time",
        )
    }

    pub(super) fn install_native5_frame_bank(
        &mut self,
        reservation: crate::transport::original_frames::OriginalFrameReservation,
    ) -> Result<(), ProviderError> {
        if self.sequence.get() != 2 || self.original_response_loss.is_some() {
            return Err(ProviderError::Correlation(
                "native5 bank requires original unused session without callbacks",
            ));
        }
        self.connection.install_native5_frame_bank(reservation)
    }

    pub(super) fn install_native5_source_codec(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: crate::reference_packet::control::PacketControlSelection,
        coordinator: crate::reference_service::InstalledContent,
    ) -> Result<(), ProviderError> {
        if self.sequence.get() != 2 || self.original_response_loss.is_some() {
            return Err(ProviderError::Correlation(
                "native5 codec requires unused original session without callbacks",
            ));
        }
        self.connection
            .install_native5_controller_codec(bank, selection, coordinator)
    }

    pub(super) fn install_native5_connected_frame_bank(
        &mut self,
        reservation: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        binding: &crucible_node_contract::NodeBinding,
        owner: &crucible_node_contract::OwnerBinding,
    ) -> Result<(), ProviderError> {
        if self.sequence.get() != 2 || self.original_response_loss.is_some() {
            return Err(ProviderError::Correlation(
                "connected archive requires unused session without loss callbacks",
            ));
        }
        self.connection
            .install_native5_connected_frame_bank(reservation, binding, owner)
    }

    pub(super) fn install_packet_schema(&mut self) -> Result<(), ProviderError> {
        // The original Hello is sequence 1. No schema replacement is permitted
        // after any control or blob frame has entered this connection.
        if self.sequence != U64::new(2) {
            return Err(ProviderError::Correlation(
                "packet schema must precede original control dispatch",
            ));
        }
        self.connection.install_packet_schema()
    }

    pub(super) fn has_packet_schema(&self) -> bool {
        self.connection.has_packet_schema()
    }

    pub(super) fn install_connected_packet_schema(
        &mut self,
        binding: &crucible_node_contract::NodeBinding,
        owner: &crucible_node_contract::OwnerBinding,
    ) -> Result<(), ProviderError> {
        if self.sequence != U64::new(2) {
            return Err(ProviderError::Correlation(
                "connected packet schema must precede original control dispatch",
            ));
        }
        self.connection
            .install_connected_packet_schema(binding, owner)
    }

    pub(super) fn has_connected_packet_schema(&self) -> bool {
        self.connection.has_connected_packet_schema()
    }

    /// Authenticates actual peer identity and admits a complete original hello exchange.
    ///
    /// The caller retains native child custody and supplies a trusted installation
    /// verifier. Kernel peer checks and measured executable bytes are independent
    /// of the provider's self-advertised manifest. The stream starts at sequence2.
    ///
    /// # Errors
    /// Refuses foreign peers, missing or changed executable measurement, failed
    /// hello authentication, invalid schemas, exhausted limits or transport failure.
    // crucible-lint: allow rust-allow -- separate trusted verifiers and original hello limits are explicit admission dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn negotiate(
        stream: std::os::unix::net::UnixStream,
        peer: &ClientPeer,
        hello: &Envelope,
        connection_id: Id,
        handshake: &mut Handshake,
        verifier: &mut impl TrustedHandshakeVerifier,
        supervisor: Rc<dyn ConnectionSupervisor>,
        schemas: Rc<dyn BodySchemaVerifier>,
        budget: Duration,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<Self, ProviderError> {
        Self::negotiate_with_admission(
            stream,
            peer,
            hello,
            supervisor,
            schemas,
            budget,
            maximum_bytes,
            maximum_nesting,
            None,
            |response| handshake.admit_envelopes(hello, response, connection_id, verifier),
        )
    }

    /// Authenticates ordinary Hello under the original pre-launch physical cut.
    ///
    /// Private bootstrap delivery, socket availability, actual peer measurement
    /// and every Hello byte share the supplied deadline. No semantic coordinate
    /// or authority follows from this operational budget. The duration-based
    /// ordinary negotiation method and its wire representation stay unchanged.
    ///
    /// # Errors
    /// Refuses expiration, foreign peers, changed measured source, failed Hello
    /// authentication, unsupported schemas or original transport uncertainty.
    // crucible-lint: allow rust-allow -- Original peer, source verifier, custody and complete deadline are independent trust dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn negotiate_before(
        stream: std::os::unix::net::UnixStream,
        peer: &ClientPeer,
        hello: &Envelope,
        connection_id: Id,
        handshake: &mut Handshake,
        verifier: &mut impl TrustedHandshakeVerifier,
        supervisor: Rc<dyn ConnectionSupervisor>,
        schemas: Rc<dyn BodySchemaVerifier>,
        deadline: ExchangeDeadline,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<Self, ProviderError> {
        deadline.remaining()?;
        Self::negotiate_with_admission(
            stream,
            peer,
            hello,
            supervisor,
            schemas,
            deadline,
            maximum_bytes,
            maximum_nesting,
            None,
            |response| handshake.admit_envelopes(hello, response, connection_id, verifier),
        )
    }

    /// Retains the actual original Hello body under one pre-launch deadline.
    ///
    /// The caller reserves the journal before Child and retains it on every
    /// error. A complete received JSON body is recorded before envelope decoding
    /// or installed authentication. It carries no qualification or lease authority.
    /// Existing negotiation methods retain their original no-journal behavior.
    ///
    /// # Errors
    /// Refuses a changed or already attempted journal, expired deadline, foreign
    /// peer, original transport uncertainty or failed Hello authentication. Complete
    /// failed reply bodies remain retained; an incomplete frame grants no evidence.
    // crucible-lint: allow rust-allow -- Original kernel peer, source verifier, physical cut and retained Hello journal are separate trust dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn negotiate_recorded_before(
        stream: std::os::unix::net::UnixStream,
        peer: &ClientPeer,
        hello: &Envelope,
        connection_id: Id,
        handshake: &mut Handshake,
        verifier: &mut impl TrustedHandshakeVerifier,
        supervisor: Rc<dyn ConnectionSupervisor>,
        schemas: Rc<dyn BodySchemaVerifier>,
        deadline: ExchangeDeadline,
        maximum_bytes: usize,
        maximum_nesting: usize,
        journal: &mut OriginalHelloJournal,
    ) -> Result<Self, ProviderError> {
        journal.begin(hello, maximum_bytes, maximum_nesting)?;
        deadline.remaining()?;
        Self::negotiate_with_admission(
            stream,
            peer,
            hello,
            supervisor,
            schemas,
            deadline,
            maximum_bytes,
            maximum_nesting,
            Some(journal),
            |response| handshake.admit_envelopes(hello, response, connection_id, verifier),
        )
    }

    /// Authenticates a peer and selects explicit installed extension contracts.
    ///
    /// Uses the same original peer credential checks, complete executable
    /// measurement and whole exchange deadline as legacy negotiation.
    ///
    /// # Errors
    /// Refuses unsupported exact versions/schemas, changed resumed selections,
    /// missing installed policy, or any ordinary peer/transport authentication failure.
    // crucible-lint: allow rust-allow -- The opt-in route retains the same explicit original peer, verifier and transport dependencies as legacy Hello.
    #[allow(clippy::too_many_arguments)]
    pub fn negotiate_extensions(
        stream: std::os::unix::net::UnixStream,
        peer: &ClientPeer,
        hello: &Envelope,
        connection_id: Id,
        handshake: &mut crate::handshake::ExtensionHandshake,
        verifier: &mut impl TrustedHandshakeVerifier,
        supervisor: Rc<dyn ConnectionSupervisor>,
        schemas: Rc<dyn BodySchemaVerifier>,
        budget: Duration,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<Self, ProviderError> {
        Self::negotiate_with_admission(
            stream,
            peer,
            hello,
            supervisor,
            schemas,
            budget,
            maximum_bytes,
            maximum_nesting,
            None,
            |response| handshake.admit_envelopes(hello, response, connection_id, verifier),
        )
    }

    /// Authenticates typed Hello under a previously fixed whole physical deadline.
    ///
    /// Socket availability, actual peer measurement and every Hello byte share
    /// the same original cut. No host coordinate is exported or renewed.
    /// Legacy duration-based negotiation retains its existing deadline behavior.
    ///
    /// # Errors
    /// Refuses an expired deadline, foreign peer, unsupported typed selection,
    /// changed source/registration, or any original authentication/I/O failure.
    // crucible-lint: allow rust-allow -- Original peer, host verifiers, incident custody and physical cut are separate explicit dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn negotiate_extensions_before(
        stream: std::os::unix::net::UnixStream,
        peer: &ClientPeer,
        hello: &Envelope,
        connection_id: Id,
        handshake: &mut crate::handshake::ExtensionHandshake,
        verifier: &mut impl TrustedHandshakeVerifier,
        supervisor: Rc<dyn ConnectionSupervisor>,
        schemas: Rc<dyn BodySchemaVerifier>,
        deadline: ExchangeDeadline,
        maximum_bytes: usize,
        maximum_nesting: usize,
    ) -> Result<Self, ProviderError> {
        deadline.remaining()?;
        Self::negotiate_with_admission(
            stream,
            peer,
            hello,
            supervisor,
            schemas,
            deadline,
            maximum_bytes,
            maximum_nesting,
            None,
            |response| handshake.admit_envelopes(hello, response, connection_id, verifier),
        )
    }

    // crucible-lint: allow rust-allow -- The shared transport path preserves independent peer identity, custody and whole-exchange ceilings.
    #[allow(clippy::too_many_arguments)]
    fn negotiate_with_admission(
        stream: std::os::unix::net::UnixStream,
        peer: &ClientPeer,
        hello: &Envelope,
        supervisor: Rc<dyn ConnectionSupervisor>,
        schemas: Rc<dyn BodySchemaVerifier>,
        budget: impl Into<InitialDeadline>,
        maximum_bytes: usize,
        maximum_nesting: usize,
        journal: Option<&mut OriginalHelloJournal>,
        admit: impl FnOnce(&Envelope) -> Result<ConnectionAuthority, ProviderError>,
    ) -> Result<Self, ProviderError> {
        let credentials =
            rustix::net::sockopt::socket_peercred(&stream).map_err(std::io::Error::from)?;
        let expected_pid = i32::try_from(peer.pid)
            .map_err(|_| ProviderError::Correlation("invalid retained provider PID"))?;
        if expected_pid <= 0
            || credentials.pid.as_raw_nonzero().get() != expected_pid
            || credentials.uid.as_raw() != peer.uid
        {
            return Err(ProviderError::Correlation(
                "CNP peer differs from retained launch",
            ));
        }
        let measured = crate::conformance::measure_executable(&PathBuf::from(format!(
            "/proc/{}/exe",
            peer.pid
        )))?;
        if measured != peer.executable {
            return Err(ProviderError::Correlation(
                "CNP peer executable differs from installation",
            ));
        }
        let (mut writer, deadline) = match budget.into() {
            InitialDeadline::Fresh(budget) => DeadlineStream::new(stream, budget)?,
            InitialDeadline::Original(deadline) => (
                DeadlineStream::with_deadline(stream, deadline.clone())?,
                deadline,
            ),
        };
        let mut reader =
            FrameReader::with_limits(writer.try_clone()?, maximum_bytes, maximum_nesting)?;
        let value = if let Some(original) = journal {
            if let Some(bank) = original.literal_bank() {
                reader.install_originals(bank);
            }
            if !original.publish_literal(&mut writer)? {
                write_frame_with_limits(
                    &mut writer,
                    original.request_value(),
                    maximum_bytes,
                    maximum_nesting,
                )?;
            }
            let frame = reader
                .read_retained()?
                .ok_or(ProviderError::Correlation("CNP hello response unavailable"))?;
            original.retain_response(&frame.bytes)?;
            frame.value
        } else {
            let prepared_hello =
                serde_json::to_value(hello).map_err(crucible_node_contract::ContractError::from)?;
            write_frame_with_limits(&mut writer, &prepared_hello, maximum_bytes, maximum_nesting)?;
            reader
                .read()?
                .ok_or(ProviderError::Correlation("CNP hello response unavailable"))?
        };
        let response = Envelope::decode(&canonical::canonical_json(&value)?, maximum_bytes)?;
        let authority = admit(&response)?;
        let connection = Connection::new(
            writer,
            authority.clone(),
            supervisor,
            schemas,
            EndpointRole::Controller,
        )?;
        Ok(Self {
            connection,
            authority,
            deadline,
            sequence: U64::new(2),
            peer_pid: peer.pid,
            peer_executable: peer.executable.clone(),
            original_response_loss: None,
        })
    }

    /// Returns the original opaque registration lease for separately checked host routing.
    pub fn authority(&self) -> &ConnectionAuthority {
        &self.authority
    }

    /// Returns the actual kernel peer PID checked during this original connection.
    ///
    /// The scalar is diagnostic evidence, not native effect or reclamation authority.
    pub fn peer_pid(&self) -> u32 {
        self.peer_pid
    }

    /// Returns independently measured peer executable bytes committed at negotiation.
    pub fn peer_executable(&self) -> &ContentRef {
        &self.peer_executable
    }

    /// Sends one original request or returns its unchanged retained response.
    ///
    /// Only the transport sequence is updated. The caller supplies immutable IDs,
    /// scope and body from its original admission. The ledger records the original
    /// before publication and keeps it on partial write, EOF or malformed traffic.
    /// Accepted responses discharge transport credit only.
    ///
    /// # Errors
    /// Refuses changed original material, bounded ledger exhaustion, an uncertain
    /// transport, foreign responses or unsupported unsolicited notifications.
    pub fn exchange(
        &mut self,
        custody: &mut ClientCustody,
        mut request: Envelope,
        budget: Duration,
    ) -> Result<Envelope, ProviderError> {
        self.authority.ensure_live()?;
        self.deadline.reset(budget)?;
        request.sequence = self.sequence;
        let id = request
            .request_id
            .0
            .clone()
            .ok_or(ProviderError::Correlation("client request ID missing"))?;
        let identity = request.request_hash(RequestOrigin::Controller)?;
        let response_room = usize::try_from(self.authority.limits().frame_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("client response platform bound"))?;
        if let Some(original) = custody.controller.get(&id) {
            if original.identity != identity {
                return Err(ProviderError::Conflict(
                    "original controller request changed",
                ));
            }
            if let Some(response) = &original.response {
                return Ok(response.clone());
            }
            custody.ensure_journal_room(response_room)?;
        } else {
            if custody.controller.len() >= custody.maximum_requests {
                return Err(ProviderError::ResourceExhausted(
                    "client original request custody",
                ));
            }
            let original_bytes = envelope_bytes(&request)?;
            custody.ensure_journal_room(original_bytes.checked_add(response_room).ok_or(
                ProviderError::ResourceExhausted("client original response reservation"),
            )?)?;
            custody.retain_journal_bytes(original_bytes)?;
            custody.controller.insert(
                id.clone(),
                ClientOriginal {
                    request: request.clone(),
                    identity,
                    response: None,
                },
            );
        }
        let lose_response = if let Some(loss) = &mut self.original_response_loss {
            loss.prepare(&request)?
        } else {
            false
        };
        self.send(request.clone())?;
        if lose_response {
            // Fence before the source action so an unwind cannot resend an unknown original.
            self.close();
            let loss = self
                .original_response_loss
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "original response-loss custody disappeared",
                ))?;
            loss.written_and_fenced()?;
            loss.after_original_write(&request)?;
            return Err(ProviderError::Correlation(
                "original response deliberately unread",
            ));
        }
        loop {
            let frame = self
                .connection
                .receive()?
                .ok_or(ProviderError::Correlation("original CNP response unknown"))?;
            match frame.body {
                ReceivedBody::Response(_) => {
                    request.matches_response(&frame.envelope)?;
                    custody.retain_journal_bytes(envelope_bytes(&frame.envelope)?)?;
                    let original = custody
                        .controller
                        .get_mut(&id)
                        .ok_or(ProviderError::Correlation("original CNP custody missing"))?;
                    original.response = Some(frame.envelope.clone());
                    return Ok(frame.envelope);
                }
                ReceivedBody::Request(body) => {
                    self.receive_transfer(custody, frame.envelope, *body)?
                }
                ReceivedBody::Notification(_) => {
                    return Err(ProviderError::Correlation("unsupported CNP notification"));
                }
            }
        }
    }

    /// Receives actual content until every requested receipt root is in verified byte custody.
    ///
    /// The source-installed provider sends dependencies before their referring
    /// roots. This function verifies hashes and transfer order only; installed
    /// native evidence validation remains the caller's separate responsibility.
    ///
    /// # Errors
    /// Refuses missing, changed, oversized, noncontiguous or mismatched content;
    /// unexpected control traffic; and the whole exchange's absolute deadline.
    pub fn receive_content(
        &mut self,
        custody: &mut ClientCustody,
        roots: &[ContentRef],
        budget: Duration,
    ) -> Result<(), ProviderError> {
        if roots.len() > 4096 {
            return Err(ProviderError::ResourceExhausted(
                "client evidence root count",
            ));
        }
        self.deadline.tighten(budget)?;
        while roots
            .iter()
            .any(|reference| custody.content.get(reference).is_err())
        {
            let frame = self
                .connection
                .receive()?
                .ok_or(ProviderError::Correlation(
                    "promised CNP evidence unavailable",
                ))?;
            let ReceivedBody::Request(body) = frame.body else {
                return Err(ProviderError::Correlation(
                    "expected original content transfer",
                ));
            };
            self.receive_transfer(custody, frame.envelope, *body)?;
        }
        Ok(())
    }

    /// Fences this stream without implying provider termination or operation completion.
    pub fn close(&mut self) {
        self.connection.close();
    }

    fn send(&mut self, envelope: Envelope) -> Result<(), ProviderError> {
        self.connection.send(envelope)?;
        self.sequence = self.sequence.checked_add(U64::new(1))?;
        Ok(())
    }

    fn receive_transfer(
        &mut self,
        custody: &mut ClientCustody,
        request: Envelope,
        body: RequestBody,
    ) -> Result<(), ProviderError> {
        let id = request
            .request_id
            .0
            .clone()
            .ok_or(ProviderError::Correlation("provider transfer ID missing"))?;
        let identity = request.request_hash(RequestOrigin::Provider)?;
        if let Some(original) = custody.provider.get(&id) {
            if original.identity != identity {
                return Err(ProviderError::Conflict("original provider request changed"));
            }
            if let Some(retained) = &original.response {
                let mut response = retained.clone();
                response.sequence = self.sequence;
                return self.send(response);
            }
        } else {
            if custody.provider.len() >= custody.maximum_requests {
                return Err(ProviderError::ResourceExhausted(
                    "client provider request custody",
                ));
            }
            let original_bytes = envelope_bytes(&request)?;
            let response_room = usize::try_from(self.authority.limits().frame_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("client response platform bound"))?;
            custody.ensure_journal_room(original_bytes.checked_add(response_room).ok_or(
                ProviderError::ResourceExhausted("client incoming response reservation"),
            )?)?;
            custody.retain_journal_bytes(original_bytes)?;
            custody.provider.insert(
                id.clone(),
                ClientOriginal {
                    request: request.clone(),
                    identity,
                    response: None,
                },
            );
        }
        let result = match body {
            RequestBody::BlobBegin(body) => object(custody.content.begin(&body)?)?,
            RequestBody::BlobChunk(body) => object(custody.content.chunk(&body)?)?,
            RequestBody::BlobFinish(body) => object(custody.content.finish(&body)?)?,
            _ => {
                return Err(ProviderError::Correlation(
                    "provider originated non-content control",
                ));
            }
        };
        let mut response = request;
        response.message = MessageKind::Response;
        response.sequence = self.sequence;
        response.body = object(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result,
            extensions: Extensions::new(),
        })?;
        custody.retain_journal_bytes(envelope_bytes(&response)?)?;
        custody
            .provider
            .get_mut(&id)
            .ok_or(ProviderError::Correlation("provider custody missing"))?
            .response = Some(response.clone());
        self.send(response)
    }
}

fn envelope_bytes(envelope: &Envelope) -> Result<usize, ProviderError> {
    let value =
        serde_json::to_value(envelope).map_err(crucible_node_contract::ContractError::from)?;
    Ok(canonical::canonical_json(&value)?.len())
}

pub(super) fn object(value: impl serde::Serialize) -> Result<Map<String, Value>, ProviderError> {
    serde_json::to_value(value)
        .map_err(crucible_node_contract::ContractError::from)?
        .as_object()
        .cloned()
        .ok_or(ProviderError::Frame("client body is not an object"))
}

#[cfg(test)]
#[path = "session/controller_fixture.rs"]
mod controller_fixture;
