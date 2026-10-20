//! Authenticated CNP streams with closed bodies and retained failure custody.
//!
//! A [`Connection`] consumes an opaque negotiated authority. Decoded messages
//! still require graph, grant, schema and native-receipt validation before any
//! model effect. EOF, malformed traffic and partial writes fence the stream and
//! notify its trusted supervisor; they never prove native execution stopped.

use std::io::{Read, Write};
use std::rc::Rc;

use crucible_node_format::{Id, Validate, canonical};

use crate::ProviderError;
use crate::bodies::{self, NotificationBody, RequestBody, ResponseBody};
use crate::envelope::{Envelope, MessageKind, Method};
use crate::handshake::ConnectionAuthority;
use crate::session::CorrelationGuard;
use crate::transport::{FrameReader, write_frame_with_limits};

mod capture_prefix;
mod complete_restore_projection;
mod restore_transfer_projection;
pub(crate) use restore_transfer_projection::CompleteRestoreTransferProjection;
mod confirmation_projection;
pub(crate) use complete_restore_projection::CompleteRestoreProjection;
pub(crate) use confirmation_projection::ConfirmationProjection;
mod ack_admission;
mod restore_held_proof;
pub(crate) use restore_held_proof::CompletedHeldProof;
mod restore_identity;
mod restore_input_quote;
mod restore_proof_quote;
pub(crate) use restore_proof_quote::OriginalRestoreHeldProofAllocationQuote;
mod restore_inputs;
mod restore_response;
mod restore_upload;
pub(crate) use ack_admission::{
    OriginalNativeAckConnectionIdentity, OriginalNativeFreshFrontierData,
};
pub(crate) use restore_identity::{
    OriginalNativeRestorationConnectionIdentity, authenticate_original_native_prepare_header_data,
};
pub(crate) use restore_input_quote::NativeRestoreInputAllocationQuote;
pub use restore_input_quote::{
    OriginalNativeRestoreInputConstructionData,
    original_native_restore_input_construction_counter_scratch_data,
    original_native_restore_input_construction_storage_data,
};
pub(crate) use restore_inputs::{
    OriginalCompleteRestoreInputCustody, OriginalCompleteRestoreInputProgress,
};

mod assigned_admit;
mod assigned_restore;
mod confirmation;
mod native5_birth;
pub use native5_birth::{Native5ConnectionBirth, Native5ConnectionBirthRefusal};
mod exchange;
pub(crate) use exchange::{
    OriginalContinuationContentExtent, OriginalContinuationPrefixKind,
    OriginalContinuationPrefixStorageData, OriginalContinuationPrefixStorageInput,
    OriginalNativeObservePreparationStorageData, OriginalPacketPrefixProjectionInput,
    OriginalPacketPrefixProjectionStorageData, OriginalPacketPrefixStorageData,
    OriginalReportQueryReceiveStorageData, PreparedOriginalRestoreHeldProof,
    authenticate_original_report_query_header_data,
    original_native_observe_preparation_counter_scratch_data,
    original_packet_prefix_startup_counter_scratch_data,
    original_report_query_receive_counter_scratch_data, original_report_query_receive_storage_data,
    quote_original_capture17_upload_prefix_startup_storage_data,
    quote_original_native_observe_prefix_startup_storage_data,
    quote_original_packet_baseline_prefix_startup_storage_data,
    quote_original_packet_prefix_startup_storage_data,
    quote_original_restored_input17_prefix_startup_storage_data,
    quote_original_restored_observation17_prefix_startup_storage_data,
};
mod fresh_restore_receive;
mod native5_codec;
mod restored_input17_response;
mod restored_observation17_response;
pub use native5_codec::CanonicalAckCodecMetadataExtent;
pub(crate) use native5_codec::{Native5CodecOwner, ProtocolCodecView};

pub(crate) fn owned_codec_enum_layout() -> usize {
    std::mem::size_of::<Native5CodecOwner>()
}

pub(crate) fn controller_owned_codec_layout() -> usize {
    Native5CodecOwner::controller_owned_layout()
}

mod native_capture_encoding;
mod native_owned11;
mod native_owned12;
pub(crate) use native_capture_encoding::{
    NativeOwned12CaptureBeforeEncodingData, NativeOwned12CaptureEncodingData,
    NativeOwned12CaptureEncodingPlan, NativeOwned12CaptureSuffixData,
};
mod original_frames;
mod original_history;
pub(crate) use native_owned11::NativeOwned11AfterProtocolCapacityFacts;
mod supervisor_state;
pub use original_history::OriginalNative5FrameHistory;
pub use supervisor_state::{
    OriginalProtocolSupervisor, OriginalRetainedSupervisor, OriginalSupervisorCallback,
    OriginalSupervisorProtocolView, OriginalSupervisorState,
};
mod packet_schema;

mod prepared;
pub(crate) use prepared::original_serialized_credit_counter_scratch_data;
pub(crate) use prepared::serialized_credit;
pub(crate) use prepared::{SERIALIZED_CREDIT_FAILURE_MESSAGE, SerializedCreditCounter};

pub(crate) use exchange::OriginalPacketCompletedRecordEncodingData;
pub use exchange::{ExchangeFailure, ExchangeRecord, OriginalSentFrameView, PreparedExchange};
pub use prepared::PreparedSend;

/// Defines an authenticated stream whose whole connection can be fenced.
///
/// Implementations must bound blocking reads/writes through native deadlines
/// or an owning actor. Fencing closes both directions, including any clones;
/// merely dropping one reader cannot authorize a replacement connection.
pub trait ProviderStream: Read + Write {
    /// Revokes this connection's transport without claiming native containment.
    ///
    /// # Errors
    /// Reports a native transport failure. The supervisor retains the incident
    /// even when transport fencing itself cannot be confirmed.
    fn fence(&mut self) -> Result<(), std::io::Error>;
}

#[cfg(unix)]
impl ProviderStream for std::os::unix::net::UnixStream {
    fn fence(&mut self) -> Result<(), std::io::Error> {
        self.shutdown(std::net::Shutdown::Both)
    }
}

/// Classifies connection failure without logging control bodies or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionFailure {
    /// The peer closed the stream or failed to provide a complete frame.
    Read,
    /// An outgoing frame may have been partially delivered.
    Write,
    /// A frame violates its admitted schema, sequence or correlation.
    Protocol,
    /// A surviving incarnation revoked this connection's authority.
    Authority,
    /// The owning controller dropped or explicitly closed the connection.
    Closed,
}

/// Transfers unresolved transport records to the trusted native supervisor.
#[derive(Debug)]
pub struct ConnectionIncident {
    /// Names the authenticated world session.
    pub session: Id,
    /// Names the actual surviving native provider.
    pub incarnation: Id,
    /// Names the fenced connection rather than a replacement lease.
    pub connection: Id,
    /// Classifies uncertainty without implying stop or rollback.
    pub failure: ConnectionFailure,
    /// Reports whether native transport shutdown acknowledged fencing.
    pub transport_fenced: bool,
    /// Retains original outgoing requests whose responses remain unknown.
    pub outgoing: Vec<Envelope>,
    /// Retains original incoming requests whose replies were not published.
    pub incoming: Vec<Envelope>,
}

/// Owns native incarnation custody independently of a transport connection.
///
/// Implementations retain the journal, accepted operations, native owners and
/// output/content pins under the incident's original incarnation. A transport
/// response can discharge correlation credit while its native operation remains
/// outstanding; the supervisor must consult its complete native operation ledger.
pub trait ConnectionSupervisor {
    /// Takes unresolved custody until authentic reconciliation or reclamation.
    fn quarantine(&self, incident: ConnectionIncident);

    /// Lends actual retained supervisor state for a complete protocol snapshot.
    ///
    /// Existing supervisors preserve their ordinary transport behavior and refuse
    /// complete state capture until their measured source implementation supplies
    /// the same original bank through [`OriginalSupervisorState`]. This callback
    /// grants data coverage only, never semantic or fresh-world authority.
    ///
    /// # Errors
    /// Refuses unsupported state families, active callbacks or origin/borrow
    /// failures, and propagates the caller's bounded inspection refusal.
    fn with_original_protocol_state(
        &self,
        _inspect: &mut dyn FnMut(OriginalSupervisorProtocolView<'_>) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation(
            "original supervisor state unsupported",
        ))
    }
}

/// Verifies installed schemas and negotiated extensions after baseline decoding.
///
/// Implementations are trusted local registry code. They resolve selected facet
/// and payload schemas and reject unsupported extensions at their declared
/// scopes. Provider-supplied schema names or executable claims cannot implement
/// this authority across the protocol. Validation grants no execution permission.
pub trait BodySchemaVerifier {
    /// Verifies the selected method body and every required extension contract.
    ///
    /// # Errors
    /// Rejects unsupported schemas, missing authenticated definitions, unknown
    /// extensions, or extension scope/version disagreement.
    fn verify(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        body: &ReceivedBody,
    ) -> Result<(), ProviderError>;
}

/// Contains a structurally validated baseline body without effect authority.
#[derive(Debug)]
pub enum ReceivedBody {
    /// Retains profile-specific bootstrap DATA only in its dedicated actual owner.
    NativeImport18Bootstrap(Box<crate::reference_packet::service::complete_restore::import18::bootstrap_ack::PacketNativeImport18BootstrapReceivedBody>),
    /// Retains a closed request for later host/native admission.
    Request(Box<RequestBody>),
    /// Retains a response validated against the original request's method.
    Response(Box<ResponseBody>),
    /// Retains a bounded unsolicited notification.
    Notification(Box<NotificationBody>),
}

/// Selects the authenticated local endpoint's permitted request direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointRole {
    /// Originates control requests and receives provider content requests/events.
    Controller,
    /// Receives control requests and originates content requests/events.
    Provider,
}

/// Couples validated body data to its original portable correlation metadata.
#[derive(Debug)]
pub struct ReceivedFrame {
    /// Retains the exact original envelope and admitted connection sequence.
    pub envelope: Envelope,
    /// Contains the method-selected closed body.
    pub body: ReceivedBody,
}

/// Owns one negotiated stream and both directions' bounded correlation credit.
pub struct Connection<S: ProviderStream> {
    reader: FrameReader<S>,
    authority: ConnectionAuthority,
    guard: CorrelationGuard,
    supervisor: Rc<dyn ConnectionSupervisor>,
    schemas: Rc<dyn BodySchemaVerifier>,
    protocol_owner: Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    native5_blobs: Option<crate::blob::BlobProtocolOwner>,
    native5_codec: Option<Rc<native5_codec::Native5CodecOwner>>,
    original_restore_inputs: Option<restore_inputs::InstalledCompleteRestoreInputs>,
    original_restore_responses:
        [Option<Rc<std::cell::RefCell<restore_response::AssignedNativeRestoreResponse>>>; 2],
    original_complete_restoration:
        Option<complete_installation::InstalledNativeCompleteRestoration>,
    original_canonical_ack_admission:
        Option<crate::reference_packet::service::ack_emitter::VerifiedCanonicalAckAdmission>,
    packet_schema: bool,
    original_frames: Option<
        std::rc::Rc<
            std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>,
        >,
    >,
    connected_packet_schema: bool,
    fenced: bool,
    role: EndpointRole,
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn authenticate_original_supervisor<T: ConnectionSupervisor>(
        &self,
        supervisor: &Rc<T>,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if !std::ptr::addr_eq(Rc::as_ptr(&self.supervisor), Rc::as_ptr(supervisor)) {
            return Err(ProviderError::Correlation(
                "native original supervisor changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn owned_protocol_view(&self) -> impl serde::Serialize + '_ {
        struct View<'a, S: ProviderStream>(&'a Connection<S>);
        impl<S: ProviderStream> serde::Serialize for View<'_, S> {
            fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
                let original = self.0;
                let bank = original
                    .original_frames
                    .as_ref()
                    .ok_or_else(|| serde::ser::Error::custom("owning literal bank absent"))?
                    .try_borrow()
                    .map_err(|_| serde::ser::Error::custom("owning literal bank borrowed"))?;
                let codec = original
                    .native5_codec
                    .as_ref()
                    .ok_or_else(|| serde::ser::Error::custom("owning codec absent"))?;
                serde::Serialize::serialize(
                    &(
                        "source-private.connection-with-reader/11",
                        original.authority.historical_owned_view(),
                        original.guard.protocol_view(),
                        codec.owned_protocol_view(),
                        bank.protocol_view_with_encoding(true),
                        original
                            .reader
                            .original_owned11_facts(original.original_frames.as_ref().ok_or_else(
                                || serde::ser::Error::custom("original reader bank absent"),
                            )?)
                            .map_err(serde::ser::Error::custom)?,
                        original.packet_schema,
                        original.connected_packet_schema,
                        original.fenced,
                        match original.role {
                            EndpointRole::Controller => "controller",
                            EndpointRole::Provider => "provider",
                        },
                    ),
                    serializer,
                )
            }
        }
        View(self)
    }

    pub(crate) fn observe_owned_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        self.authority.observe_retained_metadata(observer)?;
        self.guard.observe_owned_metadata(observer)?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("owned protocol codec absent"))?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::Codec,
            codec.as_ref(),
        )?;
        codec.observe_retained_metadata(observer)
    }

    pub(crate) fn install_packet_schema(&mut self) -> Result<(), ProviderError> {
        if self.native5_codec.is_some() {
            self.protocol_owner.ensure_current()?;
            return Err(ProviderError::Correlation(
                "native5 immutable codec cannot be replaced",
            ));
        }
        self.check_authority()?;
        if self.connected_packet_schema {
            return Err(ProviderError::Correlation(
                "connected packet schema cannot be replaced",
            ));
        }
        self.schemas = Rc::new(packet_schema::PacketSchema);
        self.packet_schema = true;
        Ok(())
    }

    pub(crate) fn has_packet_schema(&self) -> bool {
        self.packet_schema
    }

    pub(crate) fn install_connected_packet_schema(
        &mut self,
        binding: &crucible_node_format::NodeBinding,
        owner: &crucible_node_format::OwnerBinding,
    ) -> Result<(), ProviderError> {
        if self.native5_codec.is_some() {
            self.protocol_owner.ensure_current()?;
            return Err(ProviderError::Correlation(
                "native5 immutable codec cannot be replaced",
            ));
        }
        self.check_authority()?;
        if self.packet_schema || self.connected_packet_schema || !self.guard.unused() {
            return Err(ProviderError::Correlation(
                "connected packet schema requires original unused connection",
            ));
        }
        let schemas = packet_schema::ConnectedPacketSchema::new(&self.authority, binding, owner)?;
        self.schemas = Rc::new(schemas);
        self.connected_packet_schema = true;
        Ok(())
    }

    pub(crate) fn has_connected_packet_schema(&self) -> bool {
        self.connected_packet_schema
    }

    pub(crate) fn provider_authority(&mut self) -> Result<&ConnectionAuthority, ProviderError> {
        self.check_authority()?;
        if self.role != EndpointRole::Provider {
            return Err(ProviderError::Correlation(
                "native endpoint requires provider direction",
            ));
        }
        Ok(&self.authority)
    }

    /// Installs a completed authenticated hello exchange on its native stream.
    ///
    /// # Errors
    /// Rejects revoked authority or invalid negotiated limits before reading
    /// another frame. The caller retains stream/native custody on refusal.
    pub fn new(
        mut stream: S,
        authority: ConnectionAuthority,
        supervisor: Rc<dyn ConnectionSupervisor>,
        schemas: Rc<dyn BodySchemaVerifier>,
        role: EndpointRole,
    ) -> Result<Self, ProviderError> {
        let preflight = authority.with_live(|| {
            let limits = authority.limits();
            limits.validate()?;
            let guard = CorrelationGuard::new(
                authority.session_id().clone(),
                authority.incarnation_id().clone(),
                allowance(limits.requests.get())?,
                authority.envelope_extensions().clone(),
            )?;
            Ok((
                guard,
                allowance(limits.frame_bytes.get())?,
                allowance(limits.nesting.get())?,
            ))
        });
        let (guard, maximum_bytes, maximum_nesting) = match preflight {
            Ok(prepared) => prepared,
            Err(error) => {
                let transport_fenced = stream.fence().is_ok();
                supervisor.quarantine(ConnectionIncident {
                    session: authority.session_id().clone(),
                    incarnation: authority.incarnation_id().clone(),
                    connection: authority.connection_id().clone(),
                    failure: ConnectionFailure::Authority,
                    transport_fenced,
                    outgoing: Vec::new(),
                    incoming: Vec::new(),
                });
                return Err(error);
            }
        };
        let reader = FrameReader::with_limits(stream, maximum_bytes, maximum_nesting)?;

        Ok(Self {
            reader,
            authority,
            guard,
            supervisor,
            schemas,
            protocol_owner: Rc::new(crate::protocol_snapshot::ProtocolCaptureOwner::new()),
            native5_blobs: None,
            native5_codec: None,
            original_canonical_ack_admission: None,
            original_restore_inputs: None,
            original_restore_responses: [None, None],
            original_complete_restoration: None,
            packet_schema: false,
            original_frames: None,
            connected_packet_schema: false,
            fenced: false,
            role,
        })
    }

    /// Reads a frame and validates its body before releasing correlation credit.
    ///
    /// # Errors
    /// Rejects revoked authority, truncated/malformed frames, foreign scope,
    /// unknown bodies, stale sequences and mismatched responses. Every error
    /// fences and supervises the original connection. Clean EOF returns `None`
    /// after the same containment handoff; EOF is not operation completion.
    pub fn receive(&mut self) -> Result<Option<ReceivedFrame>, ProviderError> {
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        let result = self.receive_inner();
        match &result {
            Ok(None) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    /// Installs the genuine private keyed-admission token on its original actor.
    ///
    /// Validation borrows the caller's original slot before the infallible take.
    /// Data proofs, policy selection and historical tokens cannot call a public
    /// constructor for this token. Refusal preserves the same caller-owned token.
    ///
    /// # Errors
    /// Refuses an absent/already installed token, wrong actor/policy/registration,
    /// revoked source or a changed current original Admit.
    pub(crate) fn install_original_canonical_ack_admission(
        &mut self,
        token: &mut Option<
            crate::reference_packet::service::ack_emitter::VerifiedCanonicalAckAdmission,
        >,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        if self.original_canonical_ack_admission.is_some() {
            return Err(ProviderError::Conflict(
                "native canonical ACK admission already installed",
            ));
        }
        token
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native canonical ACK admission absent",
            ))?
            .authenticate_installation(self)?;
        self.original_canonical_ack_admission = token.take();
        Ok(())
    }

    pub(crate) fn retain_original_canonical_ack_control_admit<'a>(
        &self,
        original: &'a Envelope,
    ) -> Result<
        crate::reference_packet::service::ack_emitter::OriginalCanonicalAckControlAdmit<'a>,
        ProviderError,
    > {
        self.protocol_owner.ensure_current()?;
        self.original_canonical_ack_admission
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native ACK Control token not installed",
            ))?
            .retain_original_control_admit(self, original)
    }

    pub(crate) fn original_canonical_blob_ack_framed_bytes(&self) -> Result<usize, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.original_canonical_ack_admission
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native canonical ACK admission not installed",
            ))?
            .authenticate_current(self)?;
        crate::client::maximum_canonical_ack_framed_bytes()
    }

    fn receive_original_canonical_blob_ack(
        &mut self,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        let framed = self.original_canonical_blob_ack_framed_bytes()?;
        let maximum = framed
            .checked_sub(4)
            .ok_or(ProviderError::Frame("canonical ACK header extent"))?;
        self.check_authority()?;
        let result = self.receive_inner_with_maximum(Some(maximum));
        match &result {
            Ok(None) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    /// Validates and reserves a frame before any bytes can authorize peer work.
    ///
    /// # Errors
    /// Rejects invalid local proposals without consuming sequence or credit.
    /// Once writing starts, I/O failure fences the stream and hands retained
    /// records to the supervisor. Retry uses the original incarnation journal
    /// on an authenticated resumed connection, never a replacement operation.
    pub fn send(&mut self, envelope: Envelope) -> Result<(), ProviderError> {
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        self.validate_body(&envelope, false)?;

        let limits = self.authority.limits();
        let maximum_bytes = allowance(limits.frame_bytes.get())?;
        let maximum_nesting = allowance(limits.nesting.get())?;
        let value =
            serde_json::to_value(&envelope).map_err(crucible_node_format::ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        canonical::parse_json_with_depth(&bytes, maximum_bytes, maximum_nesting)?;

        let original_slot = self.prepare_original_send(&bytes)?;
        self.retain_original_request_id(&envelope, original_slot)?;
        self.authority
            .with_live(|| self.guard.register_outgoing(envelope.clone()))?;
        let result = if self.original_frames.is_some() {
            self.publish_original_send(&bytes, original_slot)
        } else {
            write_frame_with_limits(
                self.reader.stream_mut(),
                &value,
                maximum_bytes,
                maximum_nesting,
            )
        };
        if result.is_err() {
            self.contain(ConnectionFailure::Write);
        } else if envelope.message == MessageKind::Response
            && let Err(error) = self.guard.confirm_response_sent(&envelope)
        {
            self.contain(ConnectionFailure::Protocol);
            return Err(error);
        }
        result
    }

    /// Fences transport and transfers original unresolved custody once.
    pub fn close(&mut self) {
        self.contain(ConnectionFailure::Closed);
    }

    fn receive_inner(&mut self) -> Result<Option<ReceivedFrame>, ProviderError> {
        self.receive_inner_with_maximum(None)
    }

    fn receive_inner_with_maximum(
        &mut self,
        maximum_body_bytes: Option<usize>,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        self.receive_inner_with_capture_filter(maximum_body_bytes, false)
    }

    fn receive_inner_with_capture_filter(
        &mut self,
        maximum_body_bytes: Option<usize>,
        capture_only: bool,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        let value = match maximum_body_bytes {
            None => self.reader.read()?,
            Some(maximum) => self
                .reader
                .read_retained_with_maximum_bytes(maximum)?
                .map(|frame| frame.value),
        };
        let Some(value) = value else {
            return Ok(None);
        };
        let envelope: Envelope =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        if capture_only {
            let Native5CodecOwner::NativePacket(policy) = self
                .native5_codec
                .as_deref()
                .ok_or(ProviderError::Correlation("native Capture codec absent"))?
            else {
                return Err(ProviderError::Correlation("native Capture codec role"));
            };
            policy.authenticate_capture_request_header_data(&envelope)?;
            native_capture_receive::authenticate_capture_scalar_grammar(&envelope)?;
        }
        let body = self.validate_body(&envelope, true)?;
        self.retain_original_request_id(&envelope, self.reader.original_slot())?;
        self.authority.with_live(|| self.guard.receive(&envelope))?;
        Ok(Some(ReceivedFrame { envelope, body }))
    }

    fn validate_body(
        &self,
        envelope: &Envelope,
        incoming: bool,
    ) -> Result<ReceivedBody, ProviderError> {
        if envelope.method == Method::NativeImport18Bootstrap {
            return Err(ProviderError::Conflict(
                "bootstrap18 requires dedicated current service ownership",
            ));
        }
        envelope.validate()?;
        if envelope.method == Method::Hello
            || envelope.session_id.0.as_ref() != Some(self.authority.session_id())
            || envelope.incarnation_id.0.as_ref() != Some(self.authority.incarnation_id())
        {
            return Err(ProviderError::Correlation(
                "frame is outside negotiated connection scope",
            ));
        }

        let provider_origin = incoming == (self.role == EndpointRole::Controller);
        if (envelope.message == MessageKind::Event && !provider_origin)
            || (envelope.message == MessageKind::Request
                && provider_origin
                && !matches!(
                    envelope.method,
                    Method::BlobBegin | Method::BlobChunk | Method::BlobFinish | Method::Retire
                ))
        {
            return Err(ProviderError::Correlation(
                "method is forbidden in this endpoint direction",
            ));
        }

        let body: Result<ReceivedBody, ProviderError> = match envelope.message {
            MessageKind::Request => Ok(ReceivedBody::Request(Box::new(bodies::decode_request(
                envelope.method,
                &envelope.body,
            )?))),
            MessageKind::Event => Ok(ReceivedBody::Notification(Box::new(
                bodies::decode_notification(envelope.method, &envelope.body)?,
            ))),
            MessageKind::Response => {
                let original = if incoming {
                    self.guard
                        .pending_requests()
                        .find(|request| request.request_id == envelope.request_id)
                } else {
                    self.guard
                        .incoming_requests()
                        .find(|request| request.request_id == envelope.request_id)
                }
                .ok_or(ProviderError::Correlation(
                    "response has no retained original",
                ))?;
                original.matches_response(envelope)?;
                restored_input17_response::authenticate_original_class_data(original, envelope)?;
                restored_observation17_response::authenticate_original_class_data(
                    original, envelope,
                )?;
                let request = bodies::decode_request(original.method, &original.body)?;
                let response = bodies::decode_response(&request, &envelope.body)?;
                let operation = match &response.result {
                    Some(bodies::MethodResult::BeginAccepted(result)) => Some(&result.operation_id),
                    Some(bodies::MethodResult::Poll(result)) => Some(&result.operation_id),
                    _ => None,
                };
                if operation.is_some() && operation != envelope.operation_id.0.as_ref() {
                    return Err(ProviderError::Correlation(
                        "response body changed original operation scope",
                    ));
                }
                Ok(ReceivedBody::Response(Box::new(response)))
            }
        };
        let body = body?;
        self.schemas.verify(&self.authority, envelope, &body)?;
        Ok(body)
    }

    fn check_authority(&mut self) -> Result<(), ProviderError> {
        if self.original_frames.is_some() {
            self.protocol_owner.ensure_current()?;
        }
        if self.fenced {
            return Err(ProviderError::Correlation("connection is fenced"));
        }
        let result = self.authority.ensure_live();
        if result.is_err() {
            self.contain(ConnectionFailure::Authority);
        }
        result
    }

    fn contain(&mut self, failure: ConnectionFailure) {
        if self.fenced {
            return;
        }
        self.fenced = true;
        self.guard.fence();
        let incident = ConnectionIncident {
            session: self.authority.session_id().clone(),
            incarnation: self.authority.incarnation_id().clone(),
            connection: self.authority.connection_id().clone(),
            failure,
            transport_fenced: self.reader.stream_mut().fence().is_ok(),
            outgoing: self.guard.pending_requests().cloned().collect(),
            incoming: self.guard.incoming_requests().cloned().collect(),
        };
        self.supervisor.quarantine(incident);
    }
}

impl Connection<crate::client::DeadlineStream> {
    /// Waits between exchanges on the same admitted socket without reading data.
    pub(crate) fn wait_for_request(&mut self) -> Result<(), ProviderError> {
        self.check_authority()?;
        if let Err(error) = self.reader.stream_mut().wait_for_request() {
            self.contain(ConnectionFailure::Read);
            return Err(error.into());
        }

        Ok(())
    }
}

impl<S: ProviderStream> Drop for Connection<S> {
    fn drop(&mut self) {
        self.contain(ConnectionFailure::Closed);
    }
}

fn allowance(value: u64) -> Result<usize, ProviderError> {
    usize::try_from(value)
        .map_err(|_| ProviderError::ResourceExhausted("unrepresentable connection allowance"))
}

#[cfg(all(test, unix))]
mod tests;

impl Connection<crate::client::DeadlineStream> {
    pub(crate) fn authenticate_original_service_deadline(
        &self,
        deadline: &crate::client::ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.reader
            .stream_ref()
            .authenticate_original_deadline(deadline)
    }
}

mod complete_installation;

mod restore_realize;

mod restore_input_protocol;

mod native_capture_quote;
pub(crate) use native_capture_quote::{NativeCaptureSdkCompletedQuote, NativeCaptureSdkStateQuote};

mod native_capture_receive;

mod report_query_original;

mod native_confirmation_receive;

mod native_startup_protocol;

mod native_owned14;

pub(crate) use native_startup_protocol::counter_scratch_data as original_native_startup_protocol_counter_scratch_data;

mod native_birth;

impl Connection<crate::client::DeadlineStream> {
    pub(crate) fn observe_original_host_live_metadata_extras(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.authenticate_native5_source_codec()?;
        let Self {
            reader,
            authority: _,
            guard: _,
            supervisor,
            schemas: _,
            protocol_owner,
            native5_blobs,
            native5_codec,
            original_restore_inputs,
            original_restore_responses,
            original_complete_restoration,
            original_canonical_ack_admission,
            packet_schema,
            original_frames,
            connected_packet_schema,
            fenced,
            role,
        } = self;
        if *role != EndpointRole::Controller
            || native5_blobs.is_some()
            || original_restore_inputs.is_some()
            || original_restore_responses.iter().any(Option::is_some)
            || original_complete_restoration.is_some()
            || original_canonical_ack_admission.is_some()
        {
            return Err(ProviderError::Correlation(
                "live host metadata owner family unsupported",
            ));
        }
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::ProtocolOwner,
            protocol_owner.as_ref(),
        )?;
        // Codec currentness established that the erased schemas field and this
        // typed codec are the SAME allocation. Count that independent edge too.
        let codec = native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("live host codec absent"))?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::Codec,
            codec.as_ref(),
        )?;
        codec.observe_retained_metadata(observer)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::HostSupervisor,
            supervisor.as_ref(),
        )?;
        let bank = original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation("live host frame bank absent"))?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::FrameBank,
            bank.as_ref(),
        )?;
        bank.try_borrow()
            .map_err(|_| ProviderError::Conflict("live host frame bank borrowed"))?
            .observe_owned11_metadata(observer)?;
        reader.observe_original_host_live_metadata(bank, observer)?;
        observer.observe(packet_schema)?;
        observer.observe(connected_packet_schema)?;
        observer.observe(fenced)
    }
}

pub(crate) use native_capture_quote::{
    NativeCaptureSdkSnapshotBankQuote, NativeCaptureSdkStateData,
};
pub(crate) use native_capture_receive::NativeCaptureFutureReceiveQuote;

impl Connection<crate::client::DeadlineStream> {
    pub(crate) fn observe_original_host_startup_metadata(
        &self,
        schemas: &Rc<crate::client::host_startup::hello::InitialHelloSchema>,
        supervisor: &OriginalRetainedSupervisor,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authority.ensure_live()?;
        let Self {
            reader,
            authority,
            guard,
            supervisor: operational,
            schemas: actual_schemas,
            protocol_owner,
            native5_blobs,
            native5_codec,
            original_canonical_ack_admission,
            original_restore_inputs,
            original_restore_responses,
            original_complete_restoration,
            packet_schema,
            original_frames,
            connected_packet_schema,
            fenced,
            role,
        } = self;
        if *role != EndpointRole::Controller
            || *fenced
            || *packet_schema
            || *connected_packet_schema
            || !guard.unused()
            || native5_blobs.is_some()
            || native5_codec.is_some()
            || original_canonical_ack_admission.is_some()
            || original_restore_inputs.is_some()
            || original_restore_responses.iter().any(Option::is_some)
            || original_complete_restoration.is_some()
            || original_frames.is_some()
            || !std::ptr::addr_eq(Rc::as_ptr(actual_schemas), Rc::as_ptr(schemas))
        {
            return Err(ProviderError::Correlation(
                "original host constructor owner changed",
            ));
        }
        supervisor.authenticate_original_handle_data(operational)?;
        authority.observe_retained_metadata(observer)?;
        guard.observe_owned_metadata(observer)?;
        observer.shared_value(protocol_owner.as_ref())?;
        observer.shared_value(schemas.as_ref())?;
        // The enclosing installed holder independently owns and counts the
        // SAME supervisor. The checked Rc edge here allocates no new backing.
        reader.observe_original_host_startup_metadata(observer)?;
        self.protocol_owner.ensure_current()
    }
}

impl Connection<crate::client::DeadlineStream> {
    // The caller retains its original writer and all negotiated inputs until
    // preflight succeeds. No virtual supervisor callback enters construction.
    pub(crate) fn new_original_host_startup_into(
        stream: &mut Option<crate::client::DeadlineStream>,
        authority: &ConnectionAuthority,
        supervisor: Rc<dyn ConnectionSupervisor>,
        schemas: Rc<crate::client::host_startup::hello::InitialHelloSchema>,
        completed: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() || stream.is_none() {
            return Err(ProviderError::Conflict("original host connection occupied"));
        }
        let (guard, maximum_bytes, maximum_nesting) = authority.with_live(|| {
            let limits = authority.limits();
            limits.validate()?;
            Ok((
                CorrelationGuard::new(
                    authority.session_id().clone(),
                    authority.incarnation_id().clone(),
                    allowance(limits.requests.get())?,
                    authority.envelope_extensions().clone(),
                )?,
                allowance(limits.frame_bytes.get())?,
                allowance(limits.nesting.get())?,
            ))
        })?;
        let original = stream
            .take()
            .ok_or(ProviderError::Correlation("original host writer absent"))?;
        let reader = match FrameReader::with_limits_owned(original, maximum_bytes, maximum_nesting)
        {
            Ok(reader) => reader,
            Err((original, error)) => {
                *stream = Some(original);
                return Err(error);
            }
        };
        *completed = Some(Self {
            reader,
            authority: authority.clone(),
            guard,
            supervisor,
            schemas,
            protocol_owner: Rc::new(crate::protocol_snapshot::ProtocolCaptureOwner::new()),
            native5_blobs: None,
            native5_codec: None,
            original_restore_inputs: None,
            original_restore_responses: [None, None],
            original_complete_restoration: None,
            original_canonical_ack_admission: None,
            packet_schema: false,
            original_frames: None,
            connected_packet_schema: false,
            fenced: false,
            role: EndpointRole::Controller,
        });
        authority.ensure_live()
    }
}

#[path = "connection/host_initial_receive.rs"]
mod host_initial_receive;

pub(crate) use native5_codec::original_host_initial_codec_layout_data;

pub(crate) use exchange::original_host_initial_raw_receive_storage_data;

impl Connection<crate::client::DeadlineStream> {
    // A concrete DeadlineStream owns one UnixStream in this actual FrameReader.
    // Raw origin is independent of expiry or protocol failure: dead owners
    // still retain descriptors and must remain visible to the resource census.
    pub(crate) fn original_host_retained_descriptor_count_data(
        &self,
    ) -> Result<usize, ProviderError> {
        self.protocol_owner.ensure_current()?;
        Ok(1)
    }
}

#[path = "connection/capture_allocation_original.rs"]
mod capture_allocation_original;

pub(crate) use native_owned14::NativeOwned14AfterProtocolCapacityFacts;

// Fixed headers for the selected invocation literal-history DATA predicate.
pub(crate) use native_startup_protocol::invocation_history::authenticate_literal_data as authenticate_original_invocation_protocol_literal_data;
pub(crate) use native_startup_protocol::invocation_history::counter_scratch_data as original_native_invocation_history_counter_scratch_data;

#[path = "connection/native_owned15.rs"]
mod native_owned15;

mod restoration_retained;

mod assigned_activation;
mod assigned_observation;

// Borrows the same physical native World original for released continuation.
mod restoration_release;
pub(crate) use restoration_release::original_restoration_release_literal_counter_scratch_data;

// Receives only the separately prepaid, boot-owned restored observation.
mod restoration_observation;
pub(crate) use restoration_observation::original_native_restoration_observation_receive_counter_scratch_data;

mod restored_suffix_observation;
pub(crate) use restored_suffix_observation::original_restored_suffix_observation_receive_counter_scratch_data;

mod restored_response;
pub(crate) use restored_response::{
    original_restored_response_counter_scratch_data, original_restored_response_data,
};

mod restored_producer;
pub(crate) use restored_producer::original_restored_producer_receive_counter_scratch_data;

mod observation_receive;

pub(crate) use exchange::settled17;

mod native_settled17;
pub(crate) use native_settled17::{
    HistoricalAckIdentity17, HistoricalCurrentNativeConnection17, HistoricalRestoreIdentity17,
    NativeConnection17GroupIds, read_native17_connection_data,
    read_native17_connection_fields_data,
};

pub(crate) use native_settled17::{
    HistoricalAckToken17, HistoricalNativeBlobReceiver17, HistoricalNativeFrameRoot17,
    HistoricalOperationPin17, HistoricalPrepareToken17, NativeBlobReceiver17GroupIds,
    read_native17_blob_receiver_data, read_native17_frame_root_data,
    read_native17_operation_pin_data,
};

pub(crate) use native_settled17::authenticate_native17_policy_content_data;

pub(crate) use exchange::HistoricalExchangeRecord17;

/// Reports the defining codec shared payload size and alignment as DATA.
pub(crate) const fn native_codec_shared_layout17_data() -> (usize, usize) {
    (
        std::mem::size_of::<Native5CodecOwner>(),
        std::mem::align_of::<Native5CodecOwner>(),
    )
}

pub(crate) use native_settled17::{
    read_native17_codec_root_data, read_rooted_native17_connection_fields_data,
};

pub(crate) mod current17;

mod native_wholegraph17;
pub(crate) use native_settled17::logical17::bytes as native17_borrowed_bytes;
pub(crate) use native_settled17::logical17::custody as native17_borrowed_custody;
pub(crate) use native_settled17::logical17::native17_logical_projection_scratch_data;
pub(crate) use native_settled17::logical17::{
    BorrowedAdmission17Kind, BorrowedAdmission17Lineage, BorrowedAuthority17Lineage,
    BorrowedCorrelationLedger17, BorrowedNativeConnection17LogicalData,
    borrow_native17_connection_logical_data,
};
pub(crate) use native_settled17::{
    preflight_rooted_native17_connection_authority_data,
    read_rooted_native17_connection_authority_into_data,
};

pub(crate) use native_wholegraph17::NativeConnectionPrelude17;

#[path = "connection/settled_history.rs"]
mod settled_history;
pub(crate) use settled_history::ConnectionSettledHistoryData;

pub(crate) use supervisor_state::{
    ConnectionIncidentHistoryData, connection_incident_settled_history_data,
    observe_settled_connection_incident_metadata_data,
};

pub use supervisor_state::RetainedSupervisorHistoricalData;

pub use original_history::{
    OriginalRestoredInput17LiteralPrefixData, OriginalRestoredInput17LiteralPrefixIdentityData,
};

mod observation17_receive;
pub(crate) use observation17_receive::native_observation17_receive_counter_scratch_data;

pub(crate) use exchange::original_observation17_publication_counter_scratch_data;

mod capture17_receive;
pub(crate) use capture17_receive::native_capture17_receive_counter_scratch_data;

pub(crate) use exchange::original_native17_publication_literal_counter_scratch_data;

#[path = "connection/native_import18.rs"]
pub(crate) mod native_import18;
#[path = "connection/native_import18_provider.rs"]
mod native_import18_provider;
pub(crate) use native_import18_provider::NativeImport18ConnectionIdentity;
