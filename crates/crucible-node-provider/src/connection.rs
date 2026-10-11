//! Authenticated CNP streams with closed bodies and retained failure custody.
//!
//! A [`Connection`] consumes an opaque negotiated authority. Decoded messages
//! still require graph, grant, schema and native-receipt validation before any
//! model effect. EOF, malformed traffic and partial writes fence the stream and
//! notify its trusted supervisor; they never prove native execution stopped.

use std::io::{Read, Write};
use std::rc::Rc;

use crucible_node_contract::{Id, Validate, canonical};

use crate::ProviderError;
use crate::bodies::{self, NotificationBody, RequestBody, ResponseBody};
use crate::envelope::{Envelope, MessageKind, Method};
use crate::handshake::ConnectionAuthority;
use crate::session::CorrelationGuard;
use crate::transport::{FrameReader, write_frame_with_limits};

mod exchange;
mod packet_schema;
mod prepared;
pub(crate) use prepared::serialized_credit;

pub use exchange::{ExchangeFailure, ExchangeRecord, PreparedExchange};
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
    packet_schema: bool,
    fenced: bool,
    role: EndpointRole,
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn install_packet_schema(&mut self) -> Result<(), ProviderError> {
        self.check_authority()?;
        self.schemas = Rc::new(packet_schema::PacketSchema);
        self.packet_schema = true;
        Ok(())
    }

    pub(crate) fn has_packet_schema(&self) -> bool {
        self.packet_schema
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
            packet_schema: false,
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
        self.check_authority()?;
        let result = self.receive_inner();
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
        self.check_authority()?;
        self.validate_body(&envelope, false)?;

        let limits = self.authority.limits();
        let maximum_bytes = allowance(limits.frame_bytes.get())?;
        let maximum_nesting = allowance(limits.nesting.get())?;
        let value =
            serde_json::to_value(&envelope).map_err(crucible_node_contract::ContractError::from)?;
        let bytes = canonical::canonical_json(&value)?;
        canonical::parse_json_with_depth(&bytes, maximum_bytes, maximum_nesting)?;

        self.authority
            .with_live(|| self.guard.register_outgoing(envelope.clone()))?;
        let result = write_frame_with_limits(
            self.reader.stream_mut(),
            &value,
            maximum_bytes,
            maximum_nesting,
        );
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
        let Some(value) = self.reader.read()? else {
            return Ok(None);
        };
        let envelope: Envelope =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        let body = self.validate_body(&envelope, true)?;
        self.authority.with_live(|| self.guard.receive(&envelope))?;
        Ok(Some(ReceivedFrame { envelope, body }))
    }

    fn validate_body(
        &self,
        envelope: &Envelope,
        incoming: bool,
    ) -> Result<ReceivedBody, ProviderError> {
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
                let originals: Box<dyn Iterator<Item = &Envelope> + '_> = if incoming {
                    Box::new(self.guard.pending_requests())
                } else {
                    Box::new(self.guard.incoming_requests())
                };
                let original = originals
                    .into_iter()
                    .find(|request| request.request_id == envelope.request_id)
                    .ok_or(ProviderError::Correlation(
                        "response has no retained original",
                    ))?;
                original.matches_response(envelope)?;
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
