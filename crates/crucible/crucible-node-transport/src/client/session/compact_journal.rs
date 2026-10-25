//! Retains compact originals and received-envelope quarantine for SDK exchanges.
//!
//! This is a distinct storage path; existing ClientOriginal borrowers keep their
//! original representation. Complete requests are sealed before publication.
//! A received envelope enters its owning pending slot before any fallible byte
//! count or compaction. Refusal leaves that original there and fences the stream.
//! Source construction, allocation admission, native claims and paired archive
//! installation remain separate. No Source constructor selects this path yet.

use super::{ClientContent, ClientSession};
use crate::client::compact_json::CompactJson;
use crate::{
    ProviderError,
    envelope::{Envelope, MessageKind, RequestOrigin},
};
use crucible_node_format::{HashRef, Id};
use serde::Serialize;
use std::collections::BTreeMap;

mod identity;
pub mod physical18;
pub mod physical19;
mod storage;

/// Retains one complete compact original and its last authentic response.
///
/// The immutable banks contain every envelope field and preserve Number variants
/// and bits. Neither their contents nor their identity hash establish Source or
/// native authority. Reading a view never retries the original operation.
pub struct CompactClientOriginal {
    request: CompactJson,
    identity: HashRef,
    response: Option<CompactJson>,
}

impl CompactClientOriginal {
    /// Borrows the immutable original identity independently of wire sequence.
    pub fn identity(&self) -> &HashRef {
        &self.identity
    }

    /// Borrows the complete logical request without decoding a tree.
    pub fn request(&self) -> impl Serialize + '_ {
        self.request.as_serializable()
    }

    /// Borrows the complete request bank in the explicit physical18 DATA grammar.
    ///
    /// Validation and serialization borrow the actual bank without constructing
    /// a logical JSON tree or copying its bytes. The caller separately admits
    /// codec controls and output storage before invoking this operation.
    ///
    /// # Errors
    /// Refuses geometry or field ordering unsupported by the paired reader.
    pub fn physical_request18_data(&self) -> Result<impl Serialize + '_, ProviderError> {
        self.request.physical18_data()
    }

    /// Borrows the complete response bank in the explicit physical18 DATA grammar.
    ///
    /// An unresolved original emits no response. This view preserves no other
    /// custody fields and supplies no Source, retry or installation permission.
    ///
    /// # Errors
    /// Refuses geometry or field ordering unsupported by the paired reader.
    pub fn physical_response18_data(&self) -> Result<Option<impl Serialize + '_>, ProviderError> {
        self.response
            .as_ref()
            .map(CompactJson::physical18_data)
            .transpose()
    }

    /// Reports whether authentic response custody has completed.
    pub fn has_response(&self) -> bool {
        self.response.is_some()
    }

    /// Borrows the complete response without decoding, or none when unresolved.
    pub fn response(&self) -> Option<impl Serialize + '_> {
        self.response.as_ref().map(CompactJson::as_serializable)
    }

    /// Counts actual bank Vec capacities, excluding map, hash and inline headers.
    pub fn retained_bank_bytes(&self) -> usize {
        self.request.retained_bytes()
            + self
                .response
                .as_ref()
                .map_or(0, CompactJson::retained_bytes)
    }

    /// Materializes an independent request under the caller's transient admission.
    ///
    /// This allocating operation constructs the Envelope directly from its
    /// immutable bank. The complete fresh population and its construction work
    /// require separate funding; the persistent bank's bound admits neither.
    ///
    /// # Errors
    /// Refuses bank traversal or typed envelope decoding failure.
    pub fn materialize_request(&self) -> Result<Envelope, ProviderError> {
        materialize(&self.request)
    }

    fn materialize_response(&self) -> Result<Option<Envelope>, ProviderError> {
        self.response.as_ref().map(materialize).transpose()
    }
}

impl Serialize for CompactClientOriginal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut out = serializer.serialize_struct("ClientOriginal", 3)?;
        out.serialize_field("request", &self.request())?;
        out.serialize_field("identity", &self.identity)?;
        out.serialize_field("response", &self.response())?;
        out.end()
    }
}

impl crate::retained_metadata::ObserveMetadata for CompactClientOriginal {
    fn observe_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            request,
            identity,
            response,
        } = self;
        observer.observe(request)?;
        observer.observe(identity)?;
        observer.observe(response)
    }
}

struct PendingEnvelope {
    origin: RequestOrigin,
    envelope: Envelope,
}

/// Owns finite compact journals and complete received-envelope failure custody.
///
/// Request namespaces and canonical-byte credit are independently unrecycled.
/// The content store retains its own full byte reservation. A failed received
/// envelope remains in the pending slot and prevents further exchanges. Cached
/// results and all surviving originals remain readable as DATA after fencing.
///
/// This SDK owner supplies no Source, native phase, allocation or restoration
/// rights. Callers independently fund construction, all received failure
/// prefixes, serialization and transient materialization before invoking it.
pub struct CompactClientCustody {
    maximum_requests: usize,
    maximum_bytes: usize,
    retained_bytes: usize,
    maximum_envelope_bank_bytes: usize,
    controller: BTreeMap<Id, CompactClientOriginal>,
    provider: BTreeMap<Id, CompactClientOriginal>,
    content: ClientContent,
    pending: Option<PendingEnvelope>,
    unexpected: Option<crate::connection::ReceivedFrame>,
}

impl CompactClientCustody {
    /// Counts actual retained banks, trees, hashes, content and pending originals.
    ///
    /// This allocation-free borrowed census creates no capacity reservation or
    /// future-growth credit. The caller admits its fixed controls and traversal
    /// before invocation; independent views receive no alias discount.
    ///
    /// # Errors
    /// Refuses checked census overflow or unsupported retained content metadata.
    pub fn retained_metadata_facts(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        self.observe_owned_metadata(&mut observer)?;
        Ok(observer.finish())
    }

    fn observe_owned_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            maximum_requests,
            maximum_bytes,
            retained_bytes,
            maximum_envelope_bank_bytes,
            controller,
            provider,
            content,
            pending,
            unexpected,
        } = self;
        observer.observe(maximum_requests)?;
        observer.observe(maximum_bytes)?;
        observer.observe(retained_bytes)?;
        observer.observe(maximum_envelope_bank_bytes)?;
        observer.observe(controller)?;
        observer.observe(provider)?;
        content.observe_owned_metadata(observer)?;
        if let Some(PendingEnvelope {
            origin: _,
            envelope,
        }) = pending
        {
            observer.observe(envelope)?;
        }
        if let Some(frame) = unexpected {
            observe_unexpected_frame(frame, observer)?;
        }
        Ok(())
    }

    /// Constructs empty journals under unchanged request and content ceilings.
    ///
    /// The bank restriction is an independent DATA limit, not allocation credit
    /// or permission to change negotiated limits. A complete Source consumer
    /// must separately fund the original owner, future banks, pending received
    /// envelopes and simultaneous constructors before selecting this path.
    ///
    /// # Errors
    /// Refuses zero or more than 4096 originals per namespace, zero bank storage,
    /// or a bank restriction above nine times the existing journal byte ceiling.
    pub fn new(
        maximum_requests: usize,
        content: ClientContent,
        maximum_envelope_bank_bytes: usize,
    ) -> Result<Self, ProviderError> {
        Self::with_journal_byte_ceiling(
            maximum_requests,
            content.byte_ceiling(),
            content,
            maximum_envelope_bank_bytes,
        )
    }

    /// Constructs empty journals with independent journal and content ceilings.
    ///
    /// Moving `content` preserves its complete history, reserved credit and
    /// aliases. The supplied journal ceiling applies only to the new, empty
    /// journals; it neither derives credit from content nor admits migration of
    /// an existing journal. Callers separately fund all future owners and
    /// construction before invoking this SDK operation. Numeric ceilings supply
    /// no Source or allocation authority.
    ///
    /// The physical19 custody grammar preserves these independent ceilings.
    /// Physical18 remains available only when the two ceilings are equal.
    ///
    /// # Errors
    /// Refuses zero or more than 4096 originals per namespace, a zero journal or
    /// bank ceiling, checked bank-bound overflow, or a bank ceiling above nine
    /// times the journal byte ceiling.
    pub fn with_journal_byte_ceiling(
        maximum_requests: usize,
        maximum_bytes: usize,
        content: ClientContent,
        maximum_envelope_bank_bytes: usize,
    ) -> Result<Self, ProviderError> {
        validate_journal_limits(maximum_requests, maximum_bytes, maximum_envelope_bank_bytes)?;
        Ok(Self::empty(
            maximum_requests,
            maximum_bytes,
            content,
            maximum_envelope_bank_bytes,
        ))
    }

    /// Retains independent-ceiling custody directly from original content slots.
    ///
    /// All fallible scalar checks precede the move. Refusal preserves both
    /// input and output owners; success moves the entire existing content store
    /// directly into the output without a callback or later fallible operation.
    /// The new journals are empty. Existing journal history must remain in its
    /// original owner or pass through a separately funded migration.
    ///
    /// The actual Source caller separately authenticates and spends its action
    /// before construction. This SDK operation grants no Source rights, future
    /// storage admission or permission to grow a previous lifetime quota.
    ///
    /// # Errors
    /// Refuses missing content, occupied output or unsupported journal/bank
    /// ceilings, preserving both original slots on every refusal.
    pub fn retain_with_journal_byte_ceiling_into(
        maximum_requests: usize,
        maximum_bytes: usize,
        content: &mut Option<ClientContent>,
        maximum_envelope_bank_bytes: usize,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if content.is_none() || output.is_some() {
            return Err(changed());
        }
        validate_journal_limits(maximum_requests, maximum_bytes, maximum_envelope_bank_bytes)?;
        let content = content.take().ok_or_else(changed)?;
        *output = Some(Self::empty(
            maximum_requests,
            maximum_bytes,
            content,
            maximum_envelope_bank_bytes,
        ));
        Ok(())
    }

    fn empty(
        maximum_requests: usize,
        maximum_bytes: usize,
        content: ClientContent,
        maximum_envelope_bank_bytes: usize,
    ) -> Self {
        Self {
            maximum_requests,
            maximum_bytes,
            retained_bytes: 0,
            maximum_envelope_bank_bytes,
            controller: BTreeMap::new(),
            provider: BTreeMap::new(),
            content,
            pending: None,
            unexpected: None,
        }
    }

    /// Borrows an original from its explicit endpoint namespace.
    pub fn original(&self, origin: RequestOrigin, id: &Id) -> Option<&CompactClientOriginal> {
        self.journal(origin).get(id)
    }

    /// Enumerates both namespaces without materialization or allocation.
    pub fn originals(&self) -> impl Iterator<Item = &CompactClientOriginal> {
        self.controller.values().chain(self.provider.values())
    }

    /// Enumerates one namespace without inferring origin from IDs or methods.
    pub fn originals_by_origin(
        &self,
        origin: RequestOrigin,
    ) -> impl Iterator<Item = &CompactClientOriginal> {
        self.journal(origin).values()
    }

    /// Borrows a received original retained after a failed accounting or copy step.
    ///
    /// The origin names the original request namespace, including a controller
    /// response. This view grants neither settlement nor permission to retry.
    pub fn pending_envelope(&self) -> Option<(RequestOrigin, &Envelope)> {
        self.pending
            .as_ref()
            .map(|pending| (pending.origin, &pending.envelope))
    }

    /// Borrows complete unsupported traffic retained when the stream was fenced.
    ///
    /// The typed body can own backing independently of its envelope. This view
    /// grants no bootstrap, Source or native rights; further exchanges refuse.
    pub fn unexpected_frame(&self) -> Option<&crate::connection::ReceivedFrame> {
        self.unexpected.as_ref()
    }

    /// Reports actual unrecycled canonical request and response bytes.
    pub fn retained_journal_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Borrows immutable content custody independently of journal bank storage.
    pub fn content(&self) -> &ClientContent {
        &self.content
    }

    fn journal(&self, origin: RequestOrigin) -> &BTreeMap<Id, CompactClientOriginal> {
        match origin {
            RequestOrigin::Controller => &self.controller,
            RequestOrigin::Provider => &self.provider,
        }
    }

    fn journal_mut(&mut self, origin: RequestOrigin) -> &mut BTreeMap<Id, CompactClientOriginal> {
        match origin {
            RequestOrigin::Controller => &mut self.controller,
            RequestOrigin::Provider => &mut self.provider,
        }
    }

    fn ensure_room(&self, additional: usize) -> Result<(), ProviderError> {
        self.retained_bytes
            .checked_add(additional)
            .filter(|&bytes| bytes <= self.maximum_bytes)
            .map(|_| ())
            .ok_or_else(credit)
    }

    fn retain_bytes(&mut self, additional: usize) -> Result<(), ProviderError> {
        self.ensure_room(additional)?;
        self.retained_bytes += additional;
        Ok(())
    }

    fn retain_request(
        &mut self,
        origin: RequestOrigin,
        request: &Envelope,
        response_room: usize,
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        let id = request.request_id.0.as_ref().ok_or_else(changed)?;
        let retry = self.journal(origin).contains_key(id);
        let bytes = self.preflight_envelope_with_limit(request, retry, maximum_frame_bytes)?;
        let identity = identity::request_hash(request, origin, bytes)?;
        if let Some(original) = self.journal(origin).get(id) {
            if original.identity != identity {
                return Err(changed());
            }
            if !original.has_response() {
                self.ensure_room(response_room)?;
            }
            return Ok(());
        }
        if self.journal(origin).len() >= self.maximum_requests {
            return Err(credit());
        }
        self.ensure_room(bytes.checked_add(response_room).ok_or_else(credit)?)?;
        let bank = CompactJson::from_envelope(request, self.maximum_envelope_bank_bytes)?;
        self.retain_bytes(bytes)?;
        self.journal_mut(origin).insert(
            id.clone(),
            CompactClientOriginal {
                request: bank,
                identity,
                response: None,
            },
        );
        Ok(())
    }

    fn hold(&mut self, origin: RequestOrigin, envelope: Envelope) -> Result<(), ProviderError> {
        if self.pending.is_some() {
            return Err(changed());
        }
        self.pending = Some(PendingEnvelope { origin, envelope });
        Ok(())
    }

    fn complete_response(&mut self, id: &Id) -> Result<Envelope, ProviderError> {
        let pending = self.pending.as_ref().ok_or_else(changed)?;
        let bytes = self.preflight_envelope(&pending.envelope, false)?;
        self.ensure_room(bytes)?;
        let bank = CompactJson::from_envelope(&pending.envelope, self.maximum_envelope_bank_bytes)?;
        let origin = pending.origin;
        // The exclusive borrow keeps this checked entry present throughout the
        // scalar charge and response installation.
        if !self.journal(origin).contains_key(id) {
            return Err(changed());
        }
        self.retain_bytes(bytes)?;
        self.journal_mut(origin)
            .get_mut(id)
            .ok_or_else(changed)?
            .response = Some(bank);
        self.pending
            .take()
            .map(|pending| pending.envelope)
            .ok_or_else(changed)
    }

    fn preflight_envelope(&self, envelope: &Envelope, retry: bool) -> Result<usize, ProviderError> {
        self.preflight_envelope_with_limit(envelope, retry, self.maximum_bytes)
    }

    fn preflight_envelope_with_limit(
        &self,
        envelope: &Envelope,
        retry: bool,
        maximum_canonical_bytes: usize,
    ) -> Result<usize, ProviderError> {
        // Only sequence is mutable on a same-identity retry. Its decimal U64
        // string can grow to twenty bytes after the original was journaled.
        // This slack bounds preflight work only: no new bank or byte credit is
        // granted, and changed retry bodies still fail the defining hash check.
        let sequence_slack = if retry { 20 } else { 0 };
        let bank = self
            .maximum_envelope_bank_bytes
            .checked_add(sequence_slack)
            .ok_or_else(credit)?;
        let canonical = self
            .maximum_bytes
            .min(maximum_canonical_bytes)
            .checked_add(sequence_slack)
            .ok_or_else(credit)?;
        CompactJson::envelope_extents(envelope, bank, canonical).map(|(_, bytes)| bytes)
    }
}

impl ClientSession {
    /// Prices compact identity work at this actual connection's frame ceiling.
    ///
    /// The row is `[retained, transient, counter]` DATA. It includes borrowed
    /// preflight, canonical ordering and escaping, exact output storage, hashing
    /// and diagnostics. Incoming noncanonical frames retain their independent
    /// raw-to-canonical expansion bound. It constructs no whole-envelope Value.
    ///
    /// Existing journal, content, caller and received owners, connection work,
    /// materialization and observers need separate funding. This row admits no
    /// Source, native phase, specialized import18 codec or quota change. The
    /// caller admits the fixed counter before this query and authenticates both
    /// original owners through its actual Source before consuming the result.
    /// Reading these immutable limits does not authenticate a live connection.
    ///
    /// # Errors
    /// Refuses unsupported frame geometry, checked overflow
    /// or a complete identity row exceeding the independent supplied maximum.
    pub fn compact_request_identity_storage_data(
        &self,
        custody: &CompactClientCustody,
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        let frame =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| credit())?;
        let mut row = identity::storage_data(frame, custody.maximum_bytes)?;
        row[2] = Self::compact_request_identity_counter_scratch_data();
        let peak = row.into_iter().try_fold(0usize, |total, axis| {
            total.checked_add(axis).ok_or_else(credit)
        })?;
        if peak > maximum {
            return Err(credit());
        }
        Ok(row)
    }

    /// Names preflight, identity and prospective-query controls before borrowing.
    ///
    /// These are actual requested control layouts; a physical stack bound,
    /// dynamic backing and other SDK operations require separate admission.
    pub fn compact_request_identity_counter_scratch_data() -> usize {
        use std::mem::size_of;

        identity::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&CompactClientCustody>()
            + size_of::<crate::handshake::Limits>()
            + size_of::<[usize; 3]>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + size_of::<usize>() * 5
            + size_of::<Option<usize>>()
    }

    /// Exchanges one immutable original using compact persistent journals.
    ///
    /// Only the transport sequence of the borrowed request changes. The caller
    /// retains its complete request on every refusal, including pre-publication
    /// compaction failure. Accepted responses enter a pending owning slot before
    /// fallible accounting or copy; errors fence this stream without dropping
    /// that slot. An unresolved wire original remains in the compact journal.
    ///
    /// The actual connection must have no unresolved transport correlation
    /// before journal retention or deadline renewal. Exclusive session access
    /// then permits one controller request and one synchronous provider request
    /// and ACK at a time. Successful return rechecks the empty boundary. This
    /// ordinary path cannot overlap a separately reserved Native18 Prepare.
    /// Lifetime journals and negotiated request ceilings remain independent.
    ///
    /// Cached response materialization and all encoding/receive work require the
    /// caller's independent transient admission. These SDK mechanics establish
    /// no Source lifecycle, allocation permission or native semantic evidence.
    ///
    /// # Errors
    /// Refuses changed originals, exhausted lifetime credit, pending quarantine,
    /// revoked authority, invalid traffic, or uncertain transport. Refusal fences
    /// the stream and retains all surviving compact and pending originals.
    pub fn exchange_compact(
        &mut self,
        custody: &mut CompactClientCustody,
        request: &mut Envelope,
        budget: std::time::Duration,
    ) -> Result<Envelope, ProviderError> {
        let result = self.exchange_compact_inner(custody, request, budget);
        if result.is_err() {
            self.close();
        }
        result
    }

    fn exchange_compact_inner(
        &mut self,
        custody: &mut CompactClientCustody,
        request: &mut Envelope,
        budget: std::time::Duration,
    ) -> Result<Envelope, ProviderError> {
        use crate::connection::ReceivedBody;

        self.authority.ensure_live()?;
        if custody.pending.is_some() || custody.unexpected.is_some() {
            return Err(changed());
        }
        self.connection.authenticate_compact_exchange_idle()?;
        self.deadline.reset(budget)?;
        request.sequence = self.sequence;
        let response_room =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| credit())?;
        custody.retain_request(
            RequestOrigin::Controller,
            request,
            response_room,
            response_room,
        )?;
        let id = request.request_id.0.as_ref().ok_or_else(changed)?;
        if let Some(response) = custody
            .controller
            .get(id)
            .ok_or_else(changed)?
            .materialize_response()?
        {
            return Ok(response);
        }
        let lose_response = if let Some(loss) = &mut self.original_response_loss {
            loss.prepare(request)?
        } else {
            false
        };
        self.send_compact(request)?;
        if lose_response {
            // Keep the same fence-before-effect ordering as ordinary exchange.
            self.close();
            let loss = self.original_response_loss.as_ref().ok_or_else(changed)?;
            loss.written_and_fenced()?;
            loss.after_original_write(request)?;
            return Err(ProviderError::Correlation(
                "original compact response deliberately unread",
            ));
        }
        loop {
            let frame = self
                .connection
                .receive()?
                .ok_or(ProviderError::Correlation(
                    "original compact CNP response unknown",
                ))?;
            match frame.body {
                ReceivedBody::Response(_) => {
                    custody.hold(RequestOrigin::Controller, frame.envelope)?;
                    request.matches_response(
                        &custody.pending.as_ref().ok_or_else(changed)?.envelope,
                    )?;
                    self.connection.authenticate_compact_exchange_idle()?;
                    return custody.complete_response(id);
                }
                ReceivedBody::Request(body) => {
                    self.receive_compact_transfer(custody, frame.envelope, *body)?
                }
                body @ (ReceivedBody::NativeImport18Bootstrap(_)
                | ReceivedBody::Notification(_)) => {
                    custody.unexpected = Some(crate::connection::ReceivedFrame {
                        envelope: frame.envelope,
                        body,
                    });
                    return Err(ProviderError::Correlation(
                        "unsupported compact CNP traffic",
                    ));
                }
            }
        }
    }

    fn receive_compact_transfer(
        &mut self,
        custody: &mut CompactClientCustody,
        request: Envelope,
        body: crate::bodies::RequestBody,
    ) -> Result<(), ProviderError> {
        use crate::bodies::{OperationState, RequestBody, ResponseShape};
        use crucible_node_format::Extensions;

        custody.hold(RequestOrigin::Provider, request)?;
        let pending = custody.pending.as_ref().ok_or_else(changed)?;
        let id = pending
            .envelope
            .request_id
            .0
            .as_ref()
            .ok_or_else(changed)?
            .clone();
        let response_room =
            usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| credit())?;
        // The pending slot owns the received envelope throughout the fallible
        // request copy. Temporarily borrowing it cannot remove failure custody.
        let retry = custody.provider.contains_key(&id);
        let bytes = custody.preflight_envelope(&pending.envelope, retry)?;
        let identity = identity::request_hash(&pending.envelope, RequestOrigin::Provider, bytes)?;
        if let Some(original) = custody.provider.get(&id) {
            if original.identity != identity {
                return Err(changed());
            }
            if let Some(mut response) = original.materialize_response()? {
                custody.pending.take();
                response.sequence = self.sequence;
                return self.send_compact(&response);
            }
        } else {
            if custody.provider.len() >= custody.maximum_requests {
                return Err(credit());
            }
            custody.ensure_room(bytes.checked_add(response_room).ok_or_else(credit)?)?;
            let bank =
                CompactJson::from_envelope(&pending.envelope, custody.maximum_envelope_bank_bytes)?;
            custody.retain_bytes(bytes)?;
            custody.provider.insert(
                id.clone(),
                CompactClientOriginal {
                    request: bank,
                    identity,
                    response: None,
                },
            );
        }

        let result = match body {
            RequestBody::BlobBegin(body) => super::object(custody.content.begin(&body)?)?,
            RequestBody::BlobChunk(body) => super::object(custody.content.chunk(&body)?)?,
            RequestBody::BlobFinish(body) => super::object(custody.content.finish(&body)?)?,
            _ => {
                return Err(ProviderError::Correlation(
                    "provider originated non-content compact control",
                ));
            }
        };
        let response_body = super::object(ResponseShape::Completed {
            operation_state: OperationState::Completed,
            result,
            extensions: Extensions::new(),
        })?;
        let pending = custody.pending.as_mut().ok_or_else(changed)?;
        pending.envelope.message = MessageKind::Response;
        pending.envelope.sequence = self.sequence;
        pending.envelope.body = response_body;
        let response = custody.complete_response(&id)?;
        self.send_compact(&response)?;
        Ok(())
    }

    fn send_compact(&mut self, envelope: &Envelope) -> Result<(), ProviderError> {
        self.connection.send_compact(envelope)?;
        self.sequence = self
            .sequence
            .checked_add(crucible_node_format::U64::new(1))?;
        Ok(())
    }
}

// The original envelope and decoded typed body are independently owning
// populations even when their logical JSON is equal. No value-based discount
// is valid for either the Box allocation or the body's nested backing.
fn observe_unexpected_frame(
    frame: &crate::connection::ReceivedFrame,
    observer: &mut crate::retained_metadata::MetadataObserver,
) -> Result<(), ProviderError> {
    use crate::connection::{ReceivedBody, ReceivedFrame};

    let ReceivedFrame { envelope, body } = frame;
    observer.observe(envelope)?;
    match body {
        ReceivedBody::NativeImport18Bootstrap(body) => {
            observer.boxed_value(body.as_ref())?;
            observer.observe(body.as_ref())
        }
        ReceivedBody::Notification(body) => {
            let crate::bodies::NotificationBody {
                operation_state,
                last_observation_sequence,
                details,
                extensions,
            } = body.as_ref();
            observer.boxed_value(body.as_ref())?;
            observer.observe(operation_state)?;
            observer.observe(last_observation_sequence)?;
            observer.observe(details)?;
            observer.observe(extensions)
        }
        // Only the two variants above enter this slot. A changed producer must
        // extend the defining walk before its new owner can pass any census.
        ReceivedBody::Request(_) | ReceivedBody::Response(_) => Err(changed()),
    }
}

fn materialize(bank: &CompactJson) -> Result<Envelope, ProviderError> {
    bank.materialize_envelope()
}

fn validate_journal_limits(
    maximum_requests: usize,
    maximum_bytes: usize,
    maximum_envelope_bank_bytes: usize,
) -> Result<(), ProviderError> {
    let bank_bound = CompactJson::maximum_storage_bytes(maximum_bytes, usize::MAX)?;
    if maximum_requests == 0
        || maximum_requests > 4096
        || maximum_bytes == 0
        || maximum_envelope_bank_bytes == 0
        || maximum_envelope_bank_bytes > bank_bound
    {
        return Err(credit());
    }
    Ok(())
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("compact original journal credit")
}

fn changed() -> ProviderError {
    ProviderError::Conflict("compact original journal state changed")
}

#[cfg(test)]
mod tests;
