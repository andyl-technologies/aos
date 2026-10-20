//! Borrows exact retained Ownership records for the later canonical B owner.
//!
//! Nothing is encoded, copied, authenticated again or issued here. The actual
//! verified client keeps every native attempt, its immutable claim and Cache
//! borrow resident. A cold QueryCompleted without a retained original Begin is
//! deliberately insufficient until a genuine persistent history owner exists.

use aos_sandbox_ownership_protocol::authenticated::ownership_record_frame_data_v1;
use aos_sandbox_ownership_protocol::protocol::MAXIMUM_OWNERSHIP_REQUEST_BYTES;
use aos_sandbox_ownership_protocol::{MAXIMUM_LEASE_BYTES, MAXIMUM_RECEIPT_BYTES,
    MAXIMUM_SIGNATURE_BYTES};

use super::*;

/// Lends exact raw framing and its borrowed canonical-payload comparison DATA.
pub(in crate::controller_resource_reservation::create_intake::ready)
struct RetainedOwnershipRecordDataV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake::ready) raw: &'held [u8],
    pub(in crate::controller_resource_reservation::create_intake::ready) canonical: &'held [u8],
    pub(in crate::controller_resource_reservation::create_intake::ready) raw_length: u32,
    pub(in crate::controller_resource_reservation::create_intake::ready) canonical_length: u32,
    pub(in crate::controller_resource_reservation::create_intake::ready) sequence: u64,
}

/// Keeps actual transaction/record DATA borrowed from the verified live owner.
pub(in crate::controller_resource_reservation::create_intake::ready)
struct VerifiedOwnershipWireDataV1<'held> {
    pub(in crate::controller_resource_reservation::create_intake::ready)
    begin_request: RetainedOwnershipRecordDataV1<'held>,
    pub(in crate::controller_resource_reservation::create_intake::ready)
    begin_response: Option<RetainedOwnershipRecordDataV1<'held>>,
    pub(in crate::controller_resource_reservation::create_intake::ready)
    completed_request: RetainedOwnershipRecordDataV1<'held>,
    pub(in crate::controller_resource_reservation::create_intake::ready)
    completed_response: RetainedOwnershipRecordDataV1<'held>,
    pub(in crate::controller_resource_reservation::create_intake::ready)
    begin: &'held OwnershipRequestEnvelopeV1,
    pub(in crate::controller_resource_reservation::create_intake::ready)
    completion_request: &'held OwnershipRequestEnvelopeV1,
    pub(in crate::controller_resource_reservation::create_intake::ready)
    completion_response: &'held OwnershipResponseEnvelopeV1,
    pub(in crate::controller_resource_reservation::create_intake::ready)
    transaction: OwnershipTransactionReferenceV1,
    /// Exact canonical manifest, lease, signature, receipt and receipt signature.
    pub(in crate::controller_resource_reservation::create_intake::ready)
    field_lengths: [u32; 5],
}

impl<'held, 'cache> VerifiedCreateStorageOwnershipV1<'held, 'cache> {
    // The returned borrow names the actual retained originals' lifetime, so B
    // can hold their slices after this temporary read-only view is disposed.
    // Root must independently check its actual current assignment/claim and
    // pinned issuer; neither these raw MAC frames nor their sequence DATA do so.
    pub(in crate::controller_resource_reservation::create_intake::ready)
    fn wire_records_v1(&self) -> Result<VerifiedOwnershipWireDataV1<'held>, ResourceReservationErrorV1> {
        self.require_original()?;
        let original: &'held OriginalCreateStorageOwnershipV1 = self.original;
        let transaction = OwnershipTransactionReferenceV1::from_claim(self.claim);
        let index = original.verified.ok_or(ResourceReservationErrorV1::Conflict)?;
        let completed_flight = original.attempts.get(index).ok_or(ResourceReservationErrorV1::Conflict)?;
        let completed_index = completed_flight.completed_response.ok_or(ResourceReservationErrorV1::Conflict)?;
        let completed = completed_flight.exchanges.get(completed_index).ok_or(ResourceReservationErrorV1::Conflict)?;
        let request = successful(&completed.request)?;
        let response = successful(&completed.response)?;
        let session = successful(&completed_flight.negotiation)?.session();
        if request.transaction() != transaction || response.transaction() != transaction
            || request.session_binding() != session.binding()
            || response.session_binding() != session.binding()
            || request.method() != response.method()
            || !matches!(completed.advanced, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let OwnershipResponseOutcomeV1::Status(OwnershipTransactionStatusV1::Completed(artifacts)) = response.outcome() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        if artifacts.lease() != self.lease.canonical_lease()
            || artifacts.signature() != self.lease.canonical_signature()
            || artifacts.receipt() != self.lease.canonical_receipt()
            || artifacts.receipt_signature() != self.lease.canonical_receipt_signature() {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        // A prior uncertain attempt may have reached Begin before this verified
        // Query/Complete result. Select that actual sent request; never rebuild
        // a Begin envelope from the immutable claim after a cold response.
        let (begin_flight, begin_index, begin_exchange, begin) = original.attempts.iter()
            .find_map(|flight| flight.exchanges.iter().enumerate().find_map(|(index, exchange)| {
                let request = exchange.request.as_ref()?.as_ref().ok()?;
                (request.method() == OwnershipMethodV1::Begin
                    && matches!(exchange.encoding, Some(Ok(())))
                    && matches!(exchange.io.sent, Some(Ok(()))))
                    .then_some((flight, index, exchange, request))
            })).ok_or(ResourceReservationErrorV1::Conflict)?;
        let OwnershipRequestBodyV1::Begin(claim) = begin.body() else {
            return Err(ResourceReservationErrorV1::Conflict);
        };
        let begin_session = successful(&begin_flight.negotiation)?.session();
        if claim.as_ref() != self.claim || begin.transaction() != transaction
            || begin.session_binding() != begin_session.binding() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let begin_request = sent_record(begin_exchange, begin_index)?;
        let begin_response = if matches!(begin_exchange.response, Some(Ok(_)))
            && matches!(begin_exchange.advanced, Some(Ok(()))) {
            Some(received_record(begin_exchange, begin_index, begin_session.maximum_response_bytes())?)
        } else { None };
        let completed_request = sent_record(completed, completed_index)?;
        let completed_response = received_record(completed, completed_index, session.maximum_response_bytes())?;
        let field_lengths = [
            checked_length(self.manifest.canonical_bytes(), u32::MAX as usize)?,
            checked_length(self.lease.canonical_lease(), MAXIMUM_LEASE_BYTES)?,
            checked_length(self.lease.canonical_signature(), MAXIMUM_SIGNATURE_BYTES)?,
            checked_length(self.lease.canonical_receipt(), MAXIMUM_RECEIPT_BYTES)?,
            checked_length(self.lease.canonical_receipt_signature(), MAXIMUM_SIGNATURE_BYTES)?,
        ];
        Ok(VerifiedOwnershipWireDataV1 {
            begin_request, begin_response, completed_request, completed_response,
            begin, completion_request: request, completion_response: response,
            transaction, field_lengths,
        })
    }
}

fn sent_record(exchange: &OwnershipExchangeV1, index: usize)
    -> Result<RetainedOwnershipRecordDataV1<'_>, ResourceReservationErrorV1>
{
    if !matches!(exchange.encoding, Some(Ok(()))) || !matches!(exchange.io.sent, Some(Ok(()))) {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    let raw = exchange.io.outgoing.as_deref().ok_or(ResourceReservationErrorV1::Conflict)?;
    record(raw, index, MAXIMUM_OWNERSHIP_REQUEST_BYTES)
}

fn received_record(exchange: &OwnershipExchangeV1, index: usize, maximum: u32)
    -> Result<RetainedOwnershipRecordDataV1<'_>, ResourceReservationErrorV1>
{
    record(successful(&exchange.io.received)?.payload(), index, maximum)
}

fn record(raw: &[u8], index: usize, maximum: u32)
    -> Result<RetainedOwnershipRecordDataV1<'_>, ResourceReservationErrorV1>
{
    let (sequence, canonical) = ownership_record_frame_data_v1(raw, maximum)
        .map_err(|_| ResourceReservationErrorV1::Conflict)?;
    let expected = u64::try_from(index).ok().and_then(|index| index.checked_add(1))
        .ok_or(ResourceReservationErrorV1::Conflict)?;
    if sequence != expected { return Err(ResourceReservationErrorV1::Conflict); }
    Ok(RetainedOwnershipRecordDataV1 {
        raw, canonical, sequence,
        raw_length: checked_length(raw, maximum as usize)?,
        canonical_length: checked_length(canonical, maximum as usize)?,
    })
}

fn checked_length(bytes: &[u8], maximum: usize) -> Result<u32, ResourceReservationErrorV1> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ResourceReservationErrorV1::Conflict);
    }
    u32::try_from(bytes.len()).map_err(|_| ResourceReservationErrorV1::Conflict)
}

fn successful<T, E>(value: &Option<Result<T, E>>) -> Result<&T, ResourceReservationErrorV1> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)
}
