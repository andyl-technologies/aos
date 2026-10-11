//! Owning authenticated packet endpoint with complete prebuilt reply exchanges.
//!
//! This endpoint requires installed source and consuming-schema policy. Neither
//! its constructor nor a published CNP reply supplies behavioral acceptance,
//! common activation authority, native output consumption or preservation.
//! The operator keeps this complete owner outside unwind and contains the same
//! native process on any held error; dropping transport is not native cleanup.

use std::rc::Rc;

use crucible_node_contract::{ContentRef, Id};

use super::control::{PacketControl, PacketControlSelection};
use crate::{
    ProviderError, blob::*, bodies::*, connection::*, envelope::*, handshake::ConnectionAuthority,
};

mod prefix;

const EXCHANGES: usize = 256;
const CONTENT: usize = 65_536;
const STORED_CONTENT: usize = 4 * 1024 * 1024;

/// Authenticates source installation separately from wire syntax and acceptance.
///
/// Implementations belong to the independent local installer. They verify the
/// exact actual peer/implementation/contracts and source-selected semantic
/// schema; a vendor-supplied manifest or callback success cannot install one.
/// Qualification and common admission remain independent mandatory host gates.
pub trait PacketEndpointPolicy: BlobSchemaVerifier {
    /// Checks original negotiated authority against the complete installed source.
    ///
    /// # Errors
    /// Refuses changed implementation, realization, original native peer,
    /// contracts, limits or unsupported source selection.
    fn authenticate_source(
        &self,
        authority: &ConnectionAuthority,
        selection: &PacketControlSelection,
    ) -> Result<(), ProviderError>;

    /// Selects the independently installed consuming schema for an exact upload.
    ///
    /// # Errors
    /// Refuses unavailable or out-of-scope content. Successful digest checks
    /// alone cannot select this schema or grant consuming byte access.
    fn consuming_schema(
        &self,
        content: &ContentRef,
        original: &Envelope,
    ) -> Result<ContentRef, ProviderError>;
}

enum Transport<S: ProviderStream> {
    Connected(Connection<S>),
    Prepared(PreparedExchange<S>, prefix::Acknowledgements),
}

/// Retains one authenticated connection, native packet owner and complete ledger.
///
/// Its borrowed step keeps all originals outside callbacks and unwinds. A held
/// failure forbids another step. Operational supervision must keep this entire
/// capsule until genuine native containment or exact custody reconciliation.
#[must_use = "retain native packet custody independently of transport status"]
pub struct PacketEndpoint<S: ProviderStream> {
    transport: Option<Transport<S>>,
    native: PacketControl,
    authority: ConnectionAuthority,
    policy: Rc<dyn PacketEndpointPolicy>,
    uploads: BlobReceiver,
    pins: Vec<OperationContentPin>,
    records: Vec<ExchangeRecord>,
    next_sequence: u64,
    transport_credit: usize,
    held: bool,
}

/// Returns the same original unopened connection and native owner on refusal.
#[must_use = "retain and authentically contain the refused original native owner"]
pub struct PacketEndpointRefusal<S: ProviderStream> {
    connection: Connection<S>,
    native: PacketControl,
    error: ProviderError,
}

impl<S: ProviderStream> PacketEndpointRefusal<S> {
    /// Borrows the actual refusal without inferring absence of native custody.
    pub fn error(&self) -> &ProviderError {
        &self.error
    }

    /// Moves complete original custody to the operator's retained capsule.
    pub fn into_parts(self) -> (Connection<S>, PacketControl, ProviderError) {
        (self.connection, self.native, self.error)
    }
}

impl<S: ProviderStream> PacketEndpoint<S> {
    /// Takes genuine original native custody and an independently admitted stream.
    ///
    /// The policy is mandatory. Selected source2 and unopened actual native gate
    /// are checked before blob storage or native callbacks. This constructor
    /// cannot issue an acceptance token, common Ready or preserved-world claim.
    ///
    /// # Errors
    /// Returns the complete original owner for a wrong direction/source scope,
    /// revoked authority, changed peer tuple or unavailable finite storage.
    pub fn new(
        mut connection: Connection<S>,
        native: PacketControl,
        policy: Rc<dyn PacketEndpointPolicy>,
        supervisor: Rc<dyn BlobSupervisor>,
    ) -> Result<Self, Box<PacketEndpointRefusal<S>>> {
        let prepare = || -> Result<_, ProviderError> {
            let authority = connection.provider_authority()?;
            policy.authenticate_source(authority, native.endpoint_scope()?)?;
            let chunk = usize::try_from(authority.limits().blob_chunk_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("packet chunk allowance"))?
                .min(4096);
            let uploads = BlobReceiver::new(
                authority.session_id().clone(),
                authority.incarnation_id().clone(),
                BlobLimits {
                    reserved_bytes: STORED_CONTENT,
                    content_bytes: CONTENT,
                    chunk_bytes: chunk,
                    transfers_per_origin: 256,
                    tombstones_per_origin: 256,
                    chunks_per_transfer: 256,
                    operation_pins: EXCHANGES,
                },
                supervisor,
            )?;
            Ok((authority.clone(), uploads))
        };
        let (authority, uploads) = match prepare() {
            Ok(scope) => scope,
            Err(error) => {
                return Err(Box::new(PacketEndpointRefusal {
                    connection,
                    native,
                    error,
                }));
            }
        };
        Ok(Self {
            transport: Some(Transport::Connected(connection)),
            native,
            authority,
            policy,
            uploads,
            pins: Vec::new(),
            records: Vec::new(),
            next_sequence: 2,
            transport_credit: 0,
            held: false,
        })
    }

    /// Borrows the same actual native owner for independent original inspection.
    pub fn native(&self) -> &PacketControl {
        &self.native
    }

    /// Borrows all completed original transport exchanges without cloning them.
    pub fn exchanges(&self) -> &[ExchangeRecord] {
        &self.records
    }

    /// Borrows a retained incomplete exchange without creating retry authority.
    pub fn incomplete_exchange(&self) -> Option<&ExchangeRecord> {
        match &self.transport {
            Some(Transport::Prepared(exchange, _)) => Some(exchange.record()),
            _ => None,
        }
    }

    /// Reports only local dispatch fencing, without claiming native containment.
    pub fn is_held(&self) -> bool {
        self.held
    }

    /// Drives one original request and its complete prebuilt proof prefix.
    ///
    /// The operator invokes this method on the same retained owner outside its
    /// unwind boundary. Every successful native callback is preceded by complete
    /// reply/proof preparation. A partial publication, invalid transfer reply or
    /// callback unwind keeps native custody, original bytes and received prefix.
    /// EOF holds this owner; it is not native EOF, reclamation or future closure.
    ///
    /// # Errors
    /// Refuses held scope, exhausted whole ledger, malformed traffic, unavailable
    /// source content, native disagreement or incomplete original publication.
    pub fn step(&mut self) -> Result<(), ProviderError> {
        if self.held {
            return Err(ProviderError::Conflict("packet endpoint held"));
        }
        // This sticky guard precedes receive, source policy and all callbacks.
        // Only complete publication restores eligibility for the next original.
        self.held = true;
        self.reserve()?;
        let frame = match self.transport.as_mut() {
            Some(Transport::Connected(connection)) => connection
                .receive()?
                .ok_or(ProviderError::Frame("packet endpoint original peer closed"))?,
            _ => {
                return Err(ProviderError::Conflict(
                    "packet original exchange unavailable",
                ));
            }
        };
        let ReceivedBody::Request(body) = frame.body else {
            return Err(ProviderError::Correlation(
                "packet endpoint requires original request",
            ));
        };
        let request = frame.envelope;
        if let Some(reply) = self.upload(&request, body.as_ref())? {
            self.prepare(&request, &reply)?;
        } else {
            let transport = &mut self.transport;
            let sequence = &mut self.next_sequence;
            let credit = &mut self.transport_credit;
            let authority = &self.authority;
            self.native
                .dispatch_with_preflight(&request, &mut |reply| {
                    prefix::prepare(transport, sequence, credit, authority, &request, reply)
                })?;
        }
        let (exchange, acknowledgements) = match self.transport.as_mut() {
            Some(Transport::Prepared(exchange, acknowledgements)) => (exchange, acknowledgements),
            _ => return Err(ProviderError::Conflict("packet prepared prefix absent")),
        };
        exchange
            .publish(&mut |original, received| acknowledgements.validate(original, received))?;
        let Some(Transport::Prepared(exchange, _)) = self.transport.take() else {
            return Err(ProviderError::Conflict(
                "packet original prefix disappeared",
            ));
        };
        let (connection, record) = exchange.into_parts();
        self.records.push(record);
        self.transport = Some(Transport::Connected(connection));
        self.held = false;
        Ok(())
    }

    fn reserve(&mut self) -> Result<(), ProviderError> {
        if self.records.len() >= EXCHANGES || self.pins.len() >= EXCHANGES {
            return Err(ProviderError::ResourceExhausted(
                "packet complete exchange ledger",
            ));
        }
        self.records
            .try_reserve_exact(1)
            .map_err(|_| ProviderError::ResourceExhausted("packet exchange record slot"))?;
        self.pins
            .try_reserve_exact(1)
            .map_err(|_| ProviderError::ResourceExhausted("packet upload pin slot"))?;
        Ok(())
    }

    fn prepare(
        &mut self,
        request: &Envelope,
        reply: &super::control::PacketControlReply,
    ) -> Result<(), ProviderError> {
        prefix::prepare(
            &mut self.transport,
            &mut self.next_sequence,
            &mut self.transport_credit,
            &self.authority,
            request,
            reply,
        )
    }

    fn upload(
        &mut self,
        envelope: &Envelope,
        request: &RequestBody,
    ) -> Result<Option<super::control::PacketControlReply>, ProviderError> {
        let result = match request {
            RequestBody::BlobBegin(begin) => {
                let progress = self
                    .uploads
                    .begin(self.key(&begin.transfer_id), begin.content.clone())?;
                prefix::completed(BlobBeginResult {
                    transfer_id: progress.transfer_id,
                    next_offset: progress.next_offset,
                    maximum_chunk_bytes: progress.maximum_chunk_bytes,
                })?
            }
            RequestBody::BlobChunk(chunk) => {
                let progress = self.uploads.chunk(
                    &self.key(&chunk.transfer_id),
                    chunk.offset,
                    &chunk.bytes,
                )?;
                prefix::completed(BlobChunkResult {
                    transfer_id: progress.transfer_id,
                    next_offset: progress.next_offset,
                })?
            }
            RequestBody::BlobFinish(finish) => {
                let verified = self.uploads.finish(&self.key(&finish.transfer_id))?;
                let content = verified.content().clone();
                let schema = self.policy.consuming_schema(&content, envelope)?;
                let owner = envelope
                    .request_id
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "packet original install identity",
                    ))?
                    .clone();
                let pin =
                    self.uploads
                        .pin_operation(&verified, owner, schema, self.policy.as_ref())?;
                pin.with_bytes(|bytes| self.native.install_content(content.clone(), bytes))??;
                self.pins.push(pin);
                prefix::completed(BlobFinishResult {
                    transfer_id: finish.transfer_id.clone(),
                    content,
                })?
            }
            _ => return Ok(None),
        };
        Ok(Some(super::control::PacketControlReply {
            body: result,
            evidence: Vec::new(),
        }))
    }

    fn key(&self, transfer: &Id) -> TransferKey {
        TransferKey {
            origin: RequestOrigin::Controller,
            session: self.authority.session_id().clone(),
            incarnation: self.authority.incarnation_id().clone(),
            transfer: transfer.clone(),
        }
    }
}
