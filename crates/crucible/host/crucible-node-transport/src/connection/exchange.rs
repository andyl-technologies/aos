//! Whole prebuilt reply/proof prefixes with retained transport failure owners.
//!
//! These capsules grant no native execution or content-consumption authority.
//! An installed source retains its native owner beside the returned connection
//! and complete originals, including after publication or acknowledgement fails.

use super::*;

#[path = "exchange_snapshot.rs"]
mod snapshot;

#[path = "exchange_record_projection.rs"]
mod completed_record_projection;
pub(crate) use completed_record_projection::OriginalPacketCompletedRecordEncodingData;

#[path = "restore_proof.rs"]
mod restore_proof;
pub(crate) use restore_proof::PreparedOriginalRestoreHeldProof;

#[path = "exchange_proof_receive.rs"]
mod proof_receive;

#[path = "exchange_storage.rs"]
mod storage;
pub(crate) use storage::{
    OriginalContinuationContentExtent, OriginalContinuationPrefixKind,
    OriginalContinuationPrefixStorageData, OriginalContinuationPrefixStorageInput,
    OriginalNativeObservePreparationStorageData, OriginalPacketPrefixProjectionInput,
    OriginalPacketPrefixProjectionStorageData, OriginalPacketPrefixStorageData,
    OriginalReportQueryReceiveStorageData, authenticate_original_report_query_header_data,
    original_host_initial_raw_receive_storage_data,
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

const MAXIMUM_EXCHANGE_BYTES: usize = 32 * 1024 * 1024;

/// Retains complete planned frames and actual acknowledgement progress.
pub struct ExchangeRecord {
    originals: Vec<Envelope>,
    canonical: Vec<Vec<u8>>,
    acknowledgements: Vec<ReceivedFrame>,
    sent: usize,
    original_slots: Vec<Option<usize>>,
    original_actor: Option<(
        Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
        Rc<std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>>,
    )>,
}

/// Borrows a physically sent original frame under its same connection's bank loan.
///
/// The read guard prevents literal history mutation while the view exists. This
/// authenticates transport correspondence only, never successful native Capture,
/// durable acknowledgement, source settlement or fresh installation.
pub struct OriginalSentFrameView<'a> {
    original: &'a Envelope,
    canonical: &'a [u8],
    bank: std::cell::Ref<'a, crate::transport::original_frames::OriginalFrameReservation>,
    slot: usize,
}

impl OriginalSentFrameView<'_> {
    /// Borrows the actual post-sequence-assignment original envelope.
    pub fn original(&self) -> &Envelope {
        self.original
    }

    /// Borrows the complete planned canonical body matched to physical bytes.
    pub fn canonical_body(&self) -> &[u8] {
        self.canonical
    }

    /// Borrows the actual complete literal header and body under the retained loan.
    pub fn literal(&self) -> crate::transport::original_frames::OriginalFrame<'_> {
        self.bank.borrowed_original_slot(self.slot)
    }
}

impl ExchangeRecord {
    /// Authenticates one actually sent original against its same current connection.
    ///
    /// The native-five preowned record retains the original actor and literal
    /// bank identities before publication. Matching labels or numeric slot
    /// indexes from another connection cannot authenticate this view. The whole
    /// physical header/body must equal the retained planned canonical bytes.
    /// No serialization, allocation, callback or I/O occurs.
    ///
    /// # Errors
    /// Refuses foreign/revoked actors, archive-absent records, unsent or absent
    /// originals, missing slots, changed bytes, partial I/O or a mutably borrowed
    /// bank. The view grants no native execution, settlement or adoption right.
    pub fn original_sent_frame<'a, S: ProviderStream>(
        &'a self,
        connection: &'a Connection<S>,
        index: usize,
    ) -> Result<OriginalSentFrameView<'a>, ProviderError> {
        connection.protocol_owner.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        let (owner, held_bank) = self
            .original_actor
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "sent original has no owning native5 archive",
            ))?;
        owner.ensure_current()?;
        let current_bank =
            connection
                .original_frames
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "sent original current archive absent",
                ))?;
        if !Rc::ptr_eq(owner, &connection.protocol_owner) || !Rc::ptr_eq(held_bank, current_bank) {
            return Err(ProviderError::Correlation(
                "sent original connection owner differs",
            ));
        }
        if index >= self.sent {
            return Err(ProviderError::Correlation(
                "original frame was not fully sent",
            ));
        }
        let original = self
            .originals
            .get(index)
            .ok_or(ProviderError::Correlation("sent original absent"))?;
        let canonical = self
            .canonical
            .get(index)
            .ok_or(ProviderError::Correlation("sent canonical absent"))?;
        let slot = self
            .original_slots
            .get(index)
            .copied()
            .flatten()
            .ok_or(ProviderError::Correlation("sent literal slot absent"))?;
        let bank = current_bank
            .try_borrow()
            .map_err(|_| ProviderError::Correlation("sent original bank in use"))?;
        bank.authenticate_completed_send(slot, canonical)?;
        Ok(OriginalSentFrameView {
            original,
            canonical,
            bank,
            slot,
        })
    }

    /// Borrows every exact original frame, including any unsent suffix.
    pub fn originals(&self) -> &[Envelope] {
        &self.originals
    }

    /// Borrows complete original canonical frame bytes without reencoding.
    pub fn canonical_frames(&self) -> &[Vec<u8>] {
        &self.canonical
    }

    /// Borrows actually received replies, never prospective acknowledgements.
    pub fn acknowledgements(&self) -> &[ReceivedFrame] {
        &self.acknowledgements
    }

    /// Counts whole frame writes without asserting native or durable custody.
    pub fn sent(&self) -> usize {
        self.sent
    }
}

/// Owns one connection and its entire prebuilt response/proof prefix.
///
/// All canonical buffers, original correlation copies and acknowledgement list
/// slots precede any source callback. Native effects must remain under separate
/// source custody; completing this exchange does not acknowledge native output.
#[must_use = "retain the original exchange alongside its independent native owner"]
pub struct PreparedExchange<S: ProviderStream> {
    connection: Connection<S>,
    record: ExchangeRecord,
    phase: Phase,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Unprepared,
    Prepared,
    Publishing,
    Complete,
    Failed,
}

/// Retains a failed exchange and its fenced original connection.
///
/// The source owner must retain this capsule, complete native operations and
/// original body custody until authentic reconciliation or reclamation.
#[must_use = "failed transport preserves original exchange and native uncertainty"]
pub struct ExchangeFailure<S: ProviderStream> {
    connection: Connection<S>,
    record: ExchangeRecord,
    error: ProviderError,
}

impl<S: ProviderStream> ExchangeFailure<S> {
    /// Borrows the actual failure without inferring absence of native effects.
    pub fn error(&self) -> &ProviderError {
        &self.error
    }

    /// Borrows the original complete exchange and actual received prefix.
    pub fn record(&self) -> &ExchangeRecord {
        &self.record
    }

    /// Moves the same fenced connection and originals into a retained owner.
    pub fn into_parts(self) -> (Connection<S>, ExchangeRecord, ProviderError) {
        (self.connection, self.record, self.error)
    }
}

impl<S: ProviderStream> Connection<S> {
    /// Prebuilds and registers a whole original prefix before source effects.
    ///
    /// The input is already owned by the caller. Before additional encoding or
    /// correlation copies, every frame is sized against negotiated limits and
    /// the independent 32 MiB aggregate cap. The complete prefix must fit the
    /// simultaneous outgoing correlation allowance; serial writes cannot borrow
    /// future credit. Existing single-frame send semantics remain unchanged.
    ///
    /// # Errors
    /// Returns the same fenced connection and complete original list for invalid
    /// scope/body/sequence, insufficient whole-prefix credit or revoked authority.
    /// Preparation failure performs no transport write or native callback.
    ///
    /// # Panics
    /// Installed schema verifiers or supervision callbacks may panic. This
    /// consuming helper drops its local capsule on unwind; it does not retain
    /// originals outside the callback. The packet endpoint instead prepares a
    /// preowned capsule by borrow, retaining it across callback unwind.
    pub fn prepare_exchange(
        self,
        originals: Vec<Envelope>,
    ) -> Result<PreparedExchange<S>, Box<ExchangeFailure<S>>> {
        let mut exchange = self.unprepared_exchange(originals);
        if let Err(error) = exchange.prepare_in_place() {
            return Err(exchange.fail(error, ConnectionFailure::Protocol));
        }
        Ok(exchange)
    }

    pub(crate) fn unprepared_exchange(self, originals: Vec<Envelope>) -> PreparedExchange<S> {
        let original_actor = self
            .original_frames
            .as_ref()
            .map(|bank| (self.protocol_owner.clone(), bank.clone()));
        PreparedExchange {
            connection: self,
            record: ExchangeRecord {
                originals,
                canonical: Vec::new(),
                acknowledgements: Vec::new(),
                sent: 0,
                original_slots: Vec::new(),
                original_actor,
            },
            phase: Phase::Unprepared,
        }
    }
}

impl<S: ProviderStream> PreparedExchange<S> {
    /// Borrows complete originals and actual progress under the same owner.
    pub fn record(&self) -> &ExchangeRecord {
        &self.record
    }

    /// Admits after-body capacity while retaining this same unpublished suffix.
    ///
    /// Exact prepared original requests must be the connection's only pending
    /// outgoing correlations beside its original incoming Capture. Counting
    /// neither sends a frame nor converts those correlations into settled state.
    /// The source separately proves its remaining plan and raw ACK bank budget.
    ///
    /// # Errors
    /// Refuses an unprepared/failed or published capsule, foreign actor/archive,
    /// unrelated correlations, mismatched after reservation or encoding credit.
    pub fn preflight_native5_after_protocol_capacity(
        &self,
        reservation: &crate::protocol_snapshot::ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
    ) -> Result<crate::protocol_snapshot::Native5AfterProtocolCapacityFacts, ProviderError> {
        self.connection.protocol_owner.ensure_current()?;
        if self.phase != Phase::Prepared || self.record.sent != 0 {
            return Err(ProviderError::Correlation(
                "after preflight requires unpublished prepared suffix",
            ));
        }
        let (owner, bank) =
            self.record
                .original_actor
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "after prepared suffix has no original actor",
                ))?;
        owner.ensure_current()?;
        if !Rc::ptr_eq(owner, &self.connection.protocol_owner)
            || self
                .connection
                .original_frames
                .as_ref()
                .is_none_or(|current| !Rc::ptr_eq(bank, current))
        {
            return Err(ProviderError::Correlation(
                "after prepared suffix original actor changed",
            ));
        }
        self.connection
            .preflight_native5_after_protocol_capacity_inner(
                reservation,
                blobs,
                Some(&self.record.originals),
            )
    }

    pub(crate) fn prepare_in_place(&mut self) -> Result<(), ProviderError> {
        if self.phase != Phase::Unprepared {
            return Err(ProviderError::Conflict(
                "original exchange preparation already attempted",
            ));
        }
        // Installed schema/supervision code can unwind. The owning endpoint
        // installs this capsule outside the callback before invoking this seam.
        self.phase = Phase::Failed;
        let result = self.prepare();
        if result.is_ok() {
            self.phase = Phase::Prepared;
        } else {
            self.connection.contain(ConnectionFailure::Protocol);
        }
        result
    }

    fn prepare(&mut self) -> Result<(), ProviderError> {
        self.prepare_banks()?;
        for original in &self.record.originals {
            self.connection
                .authority
                .with_live(|| self.connection.guard.register_outgoing(original.clone()))?;
        }
        Ok(())
    }

    fn prepare_banks(&mut self) -> Result<(), ProviderError> {
        self.connection
            .ensure_no_pending_native_restore_response()?;
        self.connection.check_authority()?;
        let limits = self.connection.authority.limits();
        let maximum_frame = allowance(limits.frame_bytes.get())?;
        let maximum_requests = allowance(limits.requests.get())?;
        let count = self.record.originals.len();
        let requests = self
            .record
            .originals
            .iter()
            .filter(|original| original.message == MessageKind::Request)
            .count();
        if count == 0 || count > maximum_requests.saturating_add(1) || requests > maximum_requests {
            return Err(ProviderError::ResourceExhausted(
                "prepared exchange frame count",
            ));
        }

        let mut total = 0usize;
        for original in &self.record.originals {
            let bytes = super::prepared::serialized_credit(original, maximum_frame)?;
            total = total
                .checked_add(bytes)
                .filter(|total| *total <= MAXIMUM_EXCHANGE_BYTES)
                .ok_or(ProviderError::ResourceExhausted(
                    "prepared exchange whole bytes",
                ))?;
        }
        self.record
            .canonical
            .try_reserve_exact(count)
            .map_err(|_| ProviderError::ResourceExhausted("prepared frame slots"))?;
        self.record
            .acknowledgements
            .try_reserve_exact(requests)
            .map_err(|_| ProviderError::ResourceExhausted("prepared acknowledgement slots"))?;

        for original in &self.record.originals {
            self.connection.validate_body(original, false)?;
            let value = serde_json::to_value(original)
                .map_err(crucible_node_format::ContractError::from)?;
            let bytes = canonical::canonical_json(&value)?;
            canonical::parse_json_with_depth(
                &bytes,
                maximum_frame,
                allowance(limits.nesting.get())?,
            )?;
            self.record.canonical.push(bytes);
        }
        self.record
            .original_slots
            .try_reserve_exact(count)
            .map_err(|_| ProviderError::ResourceExhausted("original exchange archive slots"))?;
        for (index, bytes) in self.record.canonical.iter().enumerate() {
            let slot = self.connection.prepare_original_send(bytes)?;
            self.connection
                .retain_original_request_id(&self.record.originals[index], slot)?;
            self.record.original_slots.push(slot);
        }
        Ok(())
    }

    /// Publishes retained bytes and receives each exact original proof response.
    ///
    /// The supplied source validator checks transfer semantics beyond baseline
    /// response correlation. Received replies remain in this borrowed owner even
    /// if validation refuses or unwinds. A scoped guard fences the connection on
    /// every incomplete attempt. Neither retry nor error can resend this prefix.
    /// Remote parsing retains existing finite limits and allocator constraints.
    ///
    /// # Errors
    /// Keeps the complete original owner on I/O, malformed/foreign traffic,
    /// unexpected requests, source disagreement or a second publication attempt.
    ///
    /// # Panics
    /// Source validators, schema verifiers or supervision callbacks may panic.
    /// The borrowed capsule retains received replies and original progress; its
    /// incomplete-attempt guard fences the connection.
    pub fn publish(
        &mut self,
        validate: &mut dyn FnMut(&Envelope, &ReceivedFrame) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        if self.phase != Phase::Prepared {
            return Err(ProviderError::Conflict(
                "prepared exchange already attempted",
            ));
        }
        self.phase = Phase::Publishing;
        let mut attempt = PublicationAttempt {
            connection: &mut self.connection,
            complete: false,
        };
        let result = publish(attempt.connection, &mut self.record, validate);
        if result.is_ok() {
            self.phase = Phase::Complete;
            attempt.complete = true;
        } else {
            self.phase = Phase::Failed;
        }
        result
    }

    /// Publishes selected confirmation proofs under genuine canonical ACK admission.
    ///
    /// The installed native token and exact prepared Poll/proof originals are
    /// rechecked before publication. Every restricted read begins its original
    /// bank at the compiled ACK ceiling before reading the header. Generic
    /// publication retains its complete negotiated allowance.
    ///
    /// # Errors
    /// Refuses absent/replaced admission, unrelated Poll/proofs, repeated phase,
    /// oversized header, malformed ACK or incomplete I/O, retaining this capsule.
    ///
    /// # Panics
    /// Validators or supervision may panic; the borrowed original capsule remains
    /// outside those callbacks and its attempt guard contains uncertainty.
    pub fn publish_original_canonical_blob_acks(
        &mut self,
        original_poll: &Envelope,
        validate: &mut dyn FnMut(&Envelope, &ReceivedFrame) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        if self.phase != Phase::Prepared {
            return Err(ProviderError::Conflict(
                "prepared canonical ACK exchange already attempted",
            ));
        }
        self.connection.original_canonical_blob_ack_framed_bytes()?;
        self.connection
            .authenticate_prepared_canonical_ack_poll(original_poll, &self.record.originals)?;
        self.phase = Phase::Publishing;
        let mut attempt = PublicationAttempt {
            connection: &mut self.connection,
            complete: false,
        };
        let result = (|| {
            let canonical_literals =
                completed_record_projection::original_capture_proof_literals_required(
                    attempt.connection,
                )?;
            publish_with_ack_scope(
                attempt.connection,
                &mut self.record,
                validate,
                true,
                canonical_literals,
                None,
            )
        })();
        if result.is_ok() {
            self.phase = Phase::Complete;
            attempt.complete = true;
        } else {
            self.phase = Phase::Failed;
        }
        result
    }

    pub(crate) fn publish_original_native_birth(
        &mut self,
        scope: &crate::reference_packet::service::ack_emitter::OriginalNativeBirthReadScope<'_>,
        validate: &mut dyn FnMut(&Envelope, &ReceivedFrame) -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        scope.authenticate_connection(&self.connection)?;
        if self.phase != Phase::Prepared {
            return Err(ProviderError::Conflict(
                "native birth prefix already attempted",
            ));
        }
        self.phase = Phase::Publishing;
        let mut attempt = PublicationAttempt {
            connection: &mut self.connection,
            complete: false,
        };
        let result = (|| {
            let canonical_literals =
                completed_record_projection::original_capture_proof_literals_required(
                    attempt.connection,
                )?;
            publish_with_ack_scope(
                attempt.connection,
                &mut self.record,
                validate,
                false,
                canonical_literals,
                Some(scope),
            )
        })();
        if result.is_ok() {
            self.phase = Phase::Complete;
            attempt.complete = true;
        } else {
            self.phase = Phase::Failed;
        }
        result
    }

    /// Moves the same connection and full records into the source's owning ledger.
    ///
    /// Success discharges transport correlation only. A failed or unwound
    /// publication returns its already fenced original connection and progress.
    ///
    /// # Panics
    /// Supervision callbacks may panic while fencing an incomplete exchange.
    /// This consuming method then drops its local records during unwind.
    pub fn into_parts(mut self) -> (Connection<S>, ExchangeRecord) {
        if self.phase != Phase::Complete {
            self.connection.contain(ConnectionFailure::Closed);
        }
        (self.connection, self.record)
    }

    /// Returns a fenced unpublished prefix with its complete originals.
    ///
    /// # Panics
    /// Supervision callbacks may panic while fencing the connection. This
    /// consuming method then drops its local records during unwind.
    pub fn abort(self, error: ProviderError) -> Box<ExchangeFailure<S>> {
        self.fail(error, ConnectionFailure::Closed)
    }

    fn fail(mut self, error: ProviderError, failure: ConnectionFailure) -> Box<ExchangeFailure<S>> {
        self.connection.contain(failure);
        Box::new(ExchangeFailure {
            connection: self.connection,
            record: self.record,
            error,
        })
    }
}

struct PublicationAttempt<'a, S: ProviderStream> {
    connection: &'a mut Connection<S>,
    complete: bool,
}

impl<S: ProviderStream> Drop for PublicationAttempt<'_, S> {
    fn drop(&mut self) {
        if !self.complete {
            self.connection.contain(ConnectionFailure::Protocol);
        }
    }
}

fn publish<S: ProviderStream>(
    connection: &mut Connection<S>,
    record: &mut ExchangeRecord,
    validate: &mut dyn FnMut(&Envelope, &ReceivedFrame) -> Result<(), ProviderError>,
) -> Result<(), ProviderError> {
    let canonical_literals =
        completed_record_projection::original_capture_proof_literals_required(connection)?;
    publish_with_ack_scope(
        connection,
        record,
        validate,
        false,
        canonical_literals,
        None,
    )
}

fn publish_with_ack_scope<S: ProviderStream>(
    connection: &mut Connection<S>,
    record: &mut ExchangeRecord,
    validate: &mut dyn FnMut(&Envelope, &ReceivedFrame) -> Result<(), ProviderError>,
    canonical_ack_scope: bool,
    canonical_literals: bool,
    baseline: Option<
        &crate::reference_packet::service::ack_emitter::OriginalNativeBirthReadScope<'_>,
    >,
) -> Result<(), ProviderError> {
    for index in 0..record.originals.len() {
        connection.check_authority()?;
        let bytes = &record.canonical[index];
        let result = if connection.original_frames.is_some() {
            connection.publish_original_send(bytes, record.original_slots[index])
        } else {
            let length = u32::try_from(bytes.len())
                .map_err(|_| ProviderError::Frame("prepared exchange frame length"))?;
            let stream = connection.reader.stream_mut();
            stream
                .write_all(&length.to_be_bytes())
                .and_then(|()| stream.write_all(bytes))
                .map_err(ProviderError::from)
        };
        if let Err(error) = result {
            connection.contain(ConnectionFailure::Write);
            return Err(error);
        }
        record.sent += 1;
        let original = &record.originals[index];
        if original.message == MessageKind::Response {
            connection.guard.confirm_response_sent(original)?;
        } else if original.message == MessageKind::Request {
            let received = if let Some(scope) = baseline {
                connection.receive_original_prepared_native_birth_proof(record, index, scope)?
            } else if canonical_ack_scope {
                connection.receive_original_canonical_blob_ack()?
            } else if connection.role == EndpointRole::Provider
                && connection.native5_codec.is_some()
                && matches!(
                    original.method,
                    Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
                )
            {
                connection.receive_original_prepared_blob_proof(record, index)?
            } else {
                connection.receive()?
            };
            let reply = received.ok_or(ProviderError::Frame("prepared proof reply missing"))?;
            record.acknowledgements.push(reply);
            let reply = record
                .acknowledgements
                .last()
                .ok_or(ProviderError::Frame("retained proof reply absent"))?;
            if reply.envelope.message != MessageKind::Response {
                return Err(ProviderError::Correlation(
                    "expected original proof response",
                ));
            }
            original.matches_response(&reply.envelope)?;
            if canonical_literals {
                // The raw reply is already in this record and the original
                // frame bank. Refusal retains it and terminates this prefix;
                // only canonical closed successes may reach the next proof.
                completed_record_projection::authenticate_successful_ack(original, reply)?;
                completed_record_projection::authenticate_current_proof_literal(
                    connection,
                    record,
                    index,
                    &reply.envelope,
                )?;
            }
            validate(original, reply)?;
        }
    }
    Ok(())
}

impl PreparedExchange<crate::client::DeadlineStream> {
    pub(crate) fn preflight_native_owned11_after_protocol_capacity(
        &self,
        reservation: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &crate::reference_packet::service::OriginalNativeCaptureContext<'_>,
    ) -> Result<super::native_owned11::NativeOwned11AfterProtocolCapacityFacts, ProviderError> {
        self.connection.protocol_owner.ensure_current()?;
        if self.phase != Phase::Prepared || self.record.sent != 0 {
            return Err(ProviderError::Correlation(
                "native after quote requires unpublished prepared suffix",
            ));
        }
        let (owner, bank) =
            self.record
                .original_actor
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "native prepared suffix actor absent",
                ))?;
        owner.ensure_current()?;
        if !Rc::ptr_eq(owner, &self.connection.protocol_owner)
            || self
                .connection
                .original_frames
                .as_ref()
                .is_none_or(|current| !Rc::ptr_eq(bank, current))
        {
            return Err(ProviderError::Correlation(
                "native prepared suffix actor changed",
            ));
        }
        self.connection
            .preflight_native_owned11_after_protocol_capacity_inner(
                reservation,
                blobs,
                context,
                &self.record.originals,
            )
    }
}

#[path = "exchange/native_startup_after.rs"]
mod native_startup_after;

pub(crate) use snapshot::settled17;

pub(crate) use snapshot::HistoricalExchangeRecord17;

#[path = "exchange_observation17_owner.rs"]
mod observation17_owner;

pub(crate) use observation17_owner::counter_scratch_data as original_observation17_publication_counter_scratch_data;

// Both closed17 families consume the same bounded literal correspondence scan.
pub(crate) use observation17_owner::counter_scratch_data as original_native17_publication_literal_counter_scratch_data;
