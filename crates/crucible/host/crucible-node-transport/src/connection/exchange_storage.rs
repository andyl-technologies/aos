//! Quotes the closed native response/Blob prefix before its owning construction.
//!
//! These are prospective requested-layout data, not observed capacities or a
//! Source allowance. Only the known packet prefix validator is covered: it stops
//! at the first noncompleted/mismatched ACK. Generic publish callbacks are not
//! enrolled. Existing raw framing, correlation and bank limits remain required.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
    actual_serialization_storage_data,
};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use crucible_node_format::{ContentRef, U64};
use serde_json::{Map, Value};
use std::mem::{align_of, size_of};

#[path = "exchange_ack_storage.rs"]
mod acknowledgements;

#[path = "exchange_observe_lifetime.rs"]
mod native_observe_lifetime;
pub(crate) use native_observe_lifetime::OriginalPacketPrefixLifetimeDataExt;

#[path = "exchange_continuation_storage.rs"]
mod continuation;
pub(crate) use continuation::{
    OriginalContinuationContentExtent, OriginalContinuationPrefixKind,
    OriginalContinuationPrefixStorageData, OriginalContinuationPrefixStorageInput,
};

#[path = "exchange_packet_projection.rs"]
mod packet_projection;

#[path = "exchange_restored_input17.rs"]
mod restored_input17;
#[path = "exchange_restored_observation17.rs"]
mod restored_observation17;

#[path = "exchange_capture17_upload.rs"]
mod capture17_upload;
pub(crate) use packet_projection::{
    OriginalNativeObservePreparationStorageData, OriginalPacketPrefixProjectionInput,
    OriginalPacketPrefixProjectionStorageData, OriginalPacketPrefixProjectionStorageDataExt,
    original_native_observe_preparation_counter_scratch_data,
    original_packet_prefix_startup_counter_scratch_data,
    quote_original_capture17_upload_prefix_startup_storage_data,
    quote_original_native_observe_prefix_startup_storage_data,
    quote_original_packet_baseline_prefix_startup_storage_data,
    quote_original_packet_prefix_startup_storage_data,
    quote_original_restored_input17_prefix_startup_storage_data,
    quote_original_restored_observation17_prefix_startup_storage_data,
};

#[path = "exchange_report_query.rs"]
mod report_query;
pub(crate) use report_query::{
    OriginalReportQueryReceiveStorageData, authenticate_original_report_query_header_data,
    original_report_query_receive_counter_scratch_data, original_report_query_receive_storage_data,
};

pub(crate) use crucible_source_birth_data::profile::reference_packet::service::native_startup::packet_prefix::OriginalPacketPrefixStorageData;

/// Keeps live transport and retained-index checks with the actual upper owner.
pub(crate) trait OriginalPacketPrefixStorageDataExt {
    fn preflight_transport_credit_data(&self, retained: usize) -> Result<(), ProviderError>;
    fn reconcile_acknowledgement_index_data(
        &self,
        index: &std::collections::BTreeMap<Id, ContentRef>,
    ) -> Result<(), ProviderError>;
}

impl OriginalPacketPrefixStorageDataExt for OriginalPacketPrefixStorageData {
    fn preflight_transport_credit_data(&self, retained: usize) -> Result<(), ProviderError> {
        if add(retained, self.new_transport_credit_bytes)?
            > crate::reference_packet::endpoint::MAXIMUM_PACKET_TRANSPORT_BYTES
        {
            return Err(credit());
        }
        Ok(())
    }

    fn reconcile_acknowledgement_index_data(
        &self,
        index: &std::collections::BTreeMap<Id, ContentRef>,
    ) -> Result<(), ProviderError> {
        let mut observer = MetadataObserver::new();
        observer.observe(index)?;
        if requested_facts(&observer.finish())? > self.acknowledgement_index_requested_bytes {
            return Err(credit());
        }
        Ok(())
    }
}

impl<S: ProviderStream> Connection<S> {
    /// Binds a storage-backed builder to the quoted original registration.
    pub(crate) fn authenticate_original_packet_prefix_builder_authority_data(
        &self,
        builder: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authority.ensure_live()?;
        builder.ensure_live()?;
        // Registration identity includes the actual revocation/gate owners.
        // Full limits equality covers chunk partitioning, request population
        // and raw ACK accounting as well as the emitted scope IDs.
        if !builder.same_registration(&self.authority)
            || builder.limits() != self.authority.limits()
        {
            return Err(ProviderError::Correlation(
                "packet prefix builder authority changed",
            ));
        }
        Ok(())
    }

    /// Requotes actual inputs on the same current owner before plan construction.
    ///
    /// Scalar storage correspondence is not content or source authority. This
    /// reruns the real actor/codec/sole-original/bank/sequence checks and all
    /// closed projections under the previously admitted byte ceiling, then
    /// refuses changed named obligations before any owning frame is built.
    pub(crate) fn authenticate_requoted_original_packet_prefix_storage_data(
        &self,
        first: u64,
        request: &Envelope,
        body: &Map<String, Value>,
        evidence: &[(ContentRef, Vec<u8>)],
        quoted: &OriginalPacketPrefixStorageData,
    ) -> Result<(), ProviderError> {
        let current = self.quote_original_packet_prefix_storage_data(
            first,
            request,
            body,
            evidence,
            quoted.requested_bytes()?,
        )?;
        if current != *quoted {
            return Err(ProviderError::Correlation(
                "packet prefix storage inputs changed before construction",
            ));
        }
        Ok(())
    }

    pub(crate) fn quote_original_packet_prefix_storage_data(
        &self,
        first: u64,
        request: &Envelope,
        body: &Map<String, Value>,
        evidence: &[(ContentRef, Vec<u8>)],
        maximum: usize,
    ) -> Result<OriginalPacketPrefixStorageData, ProviderError> {
        self.quote_original_packet_prefix_storage_inner_data(
            first, request, body, evidence, maximum, false,
        )
    }

    fn quote_original_packet_prefix_storage_inner_data(
        &self,
        first: u64,
        request: &Envelope,
        body: &Map<String, Value>,
        evidence: &[(ContentRef, Vec<u8>)],
        maximum: usize,
        restored_input17: bool,
    ) -> Result<OriginalPacketPrefixStorageData, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider
            || !matches!(
                self.native5_codec.as_deref(),
                Some(Native5CodecOwner::NativePacket(_))
            )
        {
            return Err(refused());
        }
        if restored_input17 {
            restored_input17::authenticate_actual_inputs_data(self, request, body, evidence)?;
        } else if !matches!(request.method, Method::Observe | Method::Poll)
            && !(request.method == Method::Begin
                && request.body.get("kind").and_then(Value::as_str) == Some("capture"))
        {
            return Err(refused());
        }
        self.quote_original_packet_prefix_accounting_data(
            first,
            request,
            body,
            evidence,
            maximum,
            restored_input17,
        )
    }

    // The live entry point authenticates the exact selected request class.
    // This shared tail only accounts for its retained inputs and future work;
    // a quote never creates an admission, action or publication permission.
    fn quote_original_packet_prefix_accounting_data(
        &self,
        first: u64,
        request: &Envelope,
        body: &Map<String, Value>,
        evidence: &[(ContentRef, Vec<u8>)],
        maximum: usize,
        restored_input17: bool,
    ) -> Result<OriginalPacketPrefixStorageData, ProviderError> {
        let limits = self.authority.limits();
        let chunk = allowance(limits.blob_chunk_bytes.get())?.min(4096);
        let maximum_frame = allowance(limits.frame_bytes.get())?;
        if chunk == 0 || evidence.len() > 256 {
            return Err(credit());
        }
        let mut frames = 1usize;
        let mut whole_content = 0usize;
        for (_, bytes) in evidence {
            if bytes.len() > 65_536 {
                return Err(credit());
            }
            whole_content = add(whole_content, bytes.len())?;
            frames = add(frames, add(2, bytes.len().div_ceil(chunk))?)?;
        }
        if whole_content > 4 * 1024 * 1024 {
            return Err(credit());
        }
        let requests = frames.checked_sub(1).ok_or_else(credit)?;
        self.guard
            .preflight_original_packet_prefix_data(request, first, frames, requests)?;
        let mut data = OriginalPacketPrefixStorageData {
            native_retained_backing_bytes: None,
            frames,
            requests,
            evidence_payload_bytes: whole_content,
            outgoing_framed_bytes: 0,
            incoming_framed_bytes: mul(requests, add(maximum_frame, 4)?)?,
            new_transport_credit_bytes: 0,
            original_plan_requested_bytes: mul(frames, size_of::<Envelope>())?,
            acknowledgement_index_requested_bytes: super::super::restore_input_quote::tree_storage(
                1,
                evidence.len(),
                size_of::<Id>() + size_of::<ContentRef>(),
                align_of::<Id>().max(align_of::<ContentRef>()),
            )?,
            canonical_requested_bytes: 0,
            record_slots_requested_bytes: sum(&[
                mul(frames, size_of::<Vec<u8>>())?,
                mul(frames, size_of::<Option<usize>>())?,
                mul(requests, size_of::<ReceivedFrame>())?,
                size_of::<ExchangeRecord>(),
            ])?,
            outgoing_guard_requested_bytes: super::super::restore_input_quote::tree_storage(
                2,
                frames,
                size_of::<Id>() + size_of::<Envelope>(),
                align_of::<Id>().max(align_of::<Envelope>()),
            )?,
            // validate_body boxes the actual selected correlation iterator for
            // each response. Measure its concrete hidden type through the real
            // borrowed iterator, rather than guessing a trait-object payload.
            response_iterator_requested_bytes: mul(
                add(requests, 1)?,
                std::mem::size_of_val(&self.guard.pending_requests())
                    .max(std::mem::size_of_val(&self.guard.incoming_requests())),
            )?,
            successful_ack_cache_requested_bytes: 0,
            one_open_ack_requested_bytes: if requests == 0 {
                0
            } else {
                acknowledgements::open_ack_storage(maximum_frame)?
            },
            containment_requested_bytes: add(
                current_containment(self)?,
                mul(add(mul(2, requests)?, 8)?, size_of::<Envelope>())?,
            )?,
            construction_transient_requested_bytes: 0,
            preparation_transient_requested_bytes: 0,
            declared_quote_scratch_bytes: Self::original_packet_prefix_quote_scratch_bytes_data(),
            original_literal_required_bytes: mul(requests, add(maximum_frame, 4)?)?,
            original_slots_required: add(frames, requests)?,
        };
        if restored_input17 {
            data.declared_quote_scratch_bytes = add(
                data.declared_quote_scratch_bytes,
                restored_input17::counter_scratch_data(),
            )?;
            data.construction_transient_requested_bytes = add(
                data.construction_transient_requested_bytes,
                restored_input17::validation_transient_storage_data(),
            )?;
        }

        // The old builder first clones the complete request, then replaces its
        // body/extensions with the response. Quote that discarded clone too.
        let mut fields = MetadataObserver::new();
        fields.observe(request)?;
        let request_quote = actual_serialization_storage_data(request, fields.finish(), maximum)?;
        data.construction_transient_requested_bytes = add(
            data.construction_transient_requested_bytes,
            request_quote.requested_total()?,
        )?;
        let response = frame_projection(
            &self.authority,
            Some(request),
            first,
            request.method,
            Body::Response(body),
            maximum,
        )?;
        charge_frame(&mut data, response, false, maximum_frame)?;
        let mut sequence = first.checked_add(1).ok_or_else(credit)?;
        for (reference, bytes) in evidence {
            // The same known hash Strings coexist only during verification.
            reference.verify(bytes)?;
            let transfer_bytes = add("packet-transfer-".len(), decimal_digits(sequence))?;
            let mut fields = MetadataObserver::new();
            fields.observe(reference)?;
            let reference_quote =
                actual_serialization_storage_data(reference, fields.finish(), maximum)?;
            data.acknowledgement_index_requested_bytes = add(
                data.acknowledgement_index_requested_bytes,
                add(
                    reference_quote.dom_and_canonical_scratch_bytes,
                    growth(transfer_bytes)?,
                )?,
            )?;
            charge_frame(
                &mut data,
                frame_projection(
                    &self.authority,
                    None,
                    sequence,
                    Method::BlobBegin,
                    Body::Begin(transfer_bytes, reference),
                    maximum,
                )?,
                true,
                maximum_frame,
            )?;
            sequence = sequence.checked_add(1).ok_or_else(credit)?;
            for (index, payload) in bytes.chunks(chunk).enumerate() {
                let offset = u64::try_from(index.checked_mul(chunk).ok_or_else(credit)?)
                    .map_err(|_| credit())?;
                let encoded_payload = mul(payload.len().div_ceil(3), 4)?;
                data.construction_transient_requested_bytes = add(
                    data.construction_transient_requested_bytes,
                    sum(&[payload.len(), encoded_payload, growth(transfer_bytes)?])?,
                )?;
                charge_frame(
                    &mut data,
                    frame_projection(
                        &self.authority,
                        None,
                        sequence,
                        Method::BlobChunk,
                        Body::Chunk(transfer_bytes, offset, encoded_payload),
                        maximum,
                    )?,
                    true,
                    maximum_frame,
                )?;
                sequence = sequence.checked_add(1).ok_or_else(credit)?;
            }
            charge_frame(
                &mut data,
                frame_projection(
                    &self.authority,
                    None,
                    sequence,
                    Method::BlobFinish,
                    Body::Finish(transfer_bytes),
                    maximum,
                )?,
                true,
                maximum_frame,
            )?;
            sequence = sequence.checked_add(1).ok_or_else(credit)?;
        }
        if sequence
            != first
                .checked_add(u64::try_from(frames).map_err(|_| credit())?)
                .ok_or_else(credit)?
            || data.requested_bytes()? > maximum
        {
            return Err(credit());
        }
        let incoming = data.incoming_framed_bytes;
        let outgoing = data.outgoing_framed_bytes;
        let outgoing_bodies = outgoing.checked_sub(mul(frames, 4)?).ok_or_else(credit)?;
        data.new_transport_credit_bytes = add(
            mul(outgoing_bodies, 3)?,
            mul(mul(requests, maximum_frame)?, 2)?,
        )?;
        data.preflight_transport_credit_data(0)?;
        self.original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?
            .preflight_framed_suffix(frames, outgoing, requests, incoming)?;
        self.authenticate_native5_source_codec()?;
        Ok(data)
    }

    /// Names only local counter/facts/hash scratch, excluding recursive frames.
    pub(crate) const fn original_packet_prefix_quote_scratch_bytes_data() -> usize {
        size_of::<OriginalPacketPrefixStorageData>()
            + size_of::<Projection>()
            + 4 * size_of::<OriginalSerializationStorageData>()
            + 2 * size_of::<MetadataObserver<'static>>()
            + 2 * size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<blake3::Hasher>()
            + size_of::<Body<'static>>()
            + 20
            + "blake3-256".len()
            + "cnp.blob.v1".len()
            + 64
            + acknowledgements::PREFIX_ACK_COUNTER_ADDITIONAL
            + FRAME_CHARGE_ADAPTER_COUNTER_SCRATCH_DATA
    }
}

enum Body<'a> {
    Response(&'a Map<String, Value>),
    Begin(usize, &'a ContentRef),
    Chunk(usize, u64, usize),
    Finish(usize),
}

fn frame_projection(
    authority: &ConnectionAuthority,
    response_to: Option<&Envelope>,
    sequence: u64,
    method: Method,
    body: Body<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut out = Projection::new(maximum)?;
    out.add_object()?;
    for (key, value) in [
        ("protocol", "CNP/1"),
        (
            "message",
            if response_to.is_some() {
                "response"
            } else {
                "request"
            },
        ),
    ] {
        out.add_field(key)?;
        out.add_string(value)?;
    }
    for (key, value) in [
        ("session_id", Some(authority.session_id())),
        ("incarnation_id", Some(authority.incarnation_id())),
    ] {
        out.add_field(key)?;
        out.add_value(&value)?;
    }
    for (key, value) in [
        (
            "node_id",
            response_to.and_then(|value| value.node_id.0.as_ref()),
        ),
        (
            "execution_owner_id",
            response_to.and_then(|value| value.execution_owner_id.0.as_ref()),
        ),
        (
            "capture_owner_id",
            response_to.and_then(|value| value.capture_owner_id.0.as_ref()),
        ),
        (
            "operation_id",
            response_to.and_then(|value| value.operation_id.0.as_ref()),
        ),
    ] {
        out.add_field(key)?;
        out.add_value(&value)?;
    }
    out.add_field("request_id")?;
    if let Some(original) = response_to {
        out.add_value(&original.request_id)?;
    } else {
        out.add_unescaped_ascii_extent(add("packet-proof-".len(), decimal_digits(sequence))?)?;
    }
    out.add_field("sequence")?;
    out.add_value(&U64::new(sequence))?;
    out.add_field("method")?;
    out.add_value(&method)?;
    out.add_field("body")?;
    match body {
        Body::Response(body) => out.add_value(body)?,
        Body::Begin(transfer, reference) => {
            out.add_object()?;
            out.add_field("transfer_id")?;
            out.add_unescaped_ascii_extent(transfer)?;
            out.add_field("content")?;
            out.add_value(reference)?;
            out.add_field("extensions")?;
            out.add_object()?;
        }
        Body::Chunk(transfer, offset, bytes) => {
            out.add_object()?;
            out.add_field("transfer_id")?;
            out.add_unescaped_ascii_extent(transfer)?;
            out.add_field("offset")?;
            out.add_value(&U64::new(offset))?;
            out.add_field("bytes")?;
            out.add_unescaped_ascii_extent(bytes)?;
            out.add_field("extensions")?;
            out.add_object()?;
        }
        Body::Finish(transfer) => {
            out.add_object()?;
            out.add_field("transfer_id")?;
            out.add_unescaped_ascii_extent(transfer)?;
            out.add_field("extensions")?;
            out.add_object()?;
        }
    }
    out.add_field("extensions")?;
    out.add_object()?;
    out.finish(maximum)
}

fn charge_frame(
    data: &mut OriginalPacketPrefixStorageData,
    projected: OriginalSerializationStorageData,
    request: bool,
    maximum_frame: usize,
) -> Result<(), ProviderError> {
    crucible_source_birth_data::profile::reference_packet::service::native_startup::packet_prefix::charge_frame(
        data,
        projected,
        request,
        maximum_frame,
        size_of::<ResponseBody>().max(size_of::<RequestBody>()),
        &acknowledgements::ACK_FIXED_LAYOUT,
    )
}

// Each actual frame charge uses the same sequential adapter window. The old
// quote terms stay intact; these name the actual lower inputs, formed reborrow
// and ACK loan, and the additional returned Result.
const FRAME_CHARGE_ADAPTER_COUNTER_SCRATCH_DATA: usize =
    2 * size_of::<&mut OriginalPacketPrefixStorageData>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<bool>()
        + 2 * size_of::<usize>()
        + 2 * size_of::<&crucible_source_birth_data::profile::reference_packet::service::native_startup::report_ack::AckFixedLayoutData>()
        + size_of::<Result<(), ProviderError>>();

fn current_containment<S: ProviderStream>(
    connection: &Connection<S>,
) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    connection.guard.observe_owned_metadata(&mut observer)?;
    observer.observe(connection.authority.session_id())?;
    observer.observe(connection.authority.incarnation_id())?;
    observer.observe(connection.authority.connection_id())?;
    let facts = observer.finish();
    let count = add(
        connection.guard.pending_requests().count(),
        connection.guard.incoming_requests().count(),
    )?;
    sum(&[
        facts.string_capacity_bytes,
        facts.vector_capacity_bytes,
        facts.boxed_value_bytes,
        super::super::restore_input_quote::tree_storage(
            facts.tree_containers,
            facts.tree_entries,
            facts.maximum_tree_key_value_bytes,
            facts.maximum_tree_entry_alignment.max(1),
        )?,
        mul(add(mul(2, count)?, 8)?, size_of::<Envelope>())?,
        size_of::<ConnectionIncident>(),
    ])
}

fn decimal_digits(mut value: u64) -> usize {
    let mut digits = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}
fn growth(bytes: usize) -> Result<usize, ProviderError> {
    add(mul(bytes, 4)?, 256)
}
fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(credit)
}
fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(credit)
}
fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |sum, value| add(sum, *value))
}
fn refused() -> ProviderError {
    ProviderError::Correlation("original packet prefix storage data")
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("original packet prefix requested storage")
}

impl<S: ProviderStream> PreparedExchange<S> {
    /// Compares actual retained child capacities to the private prefix data.
    ///
    /// The owning native producer must separately conjoin its actual whole
    /// allowance BEFORE constructing any plan. This comparison is data only;
    /// it creates no ability to call a validator, publish, Capture or restore.
    pub(crate) fn reconcile_original_packet_prefix_storage_data(
        &self,
        quote: &OriginalPacketPrefixStorageData,
    ) -> Result<(), ProviderError> {
        self.connection.protocol_owner.ensure_current()?;
        self.connection.authenticate_native5_source_codec()?;
        if !matches!(self.phase, Phase::Unprepared | Phase::Prepared)
            || self.record.sent != 0
            || !self.record.acknowledgements.is_empty()
            || self.record.originals.len() != quote.frames
            || self
                .record
                .originals
                .iter()
                .filter(|frame| frame.message == MessageKind::Request)
                .count()
                != quote.requests
        {
            return Err(refused());
        }
        let (actor, bank) = self.record.original_actor.as_ref().ok_or_else(refused)?;
        if !Rc::ptr_eq(actor, &self.connection.protocol_owner)
            || self
                .connection
                .original_frames
                .as_ref()
                .is_none_or(|current| !Rc::ptr_eq(current, bank))
        {
            return Err(refused());
        }
        let mut observer = MetadataObserver::new();
        observer.observe(&self.record.originals)?;
        let plan = requested_facts(&observer.finish())?;
        if plan > quote.original_plan_requested_bytes {
            return Err(credit());
        }
        let mut observer = MetadataObserver::new();
        observer.observe(&self.record.canonical)?;
        observer.observe(&self.record.original_slots)?;
        observer.vector::<ReceivedFrame>(self.record.acknowledgements.capacity())?;
        let actual = requested_facts(&observer.finish())?;
        if actual
            > add(
                quote.canonical_requested_bytes,
                quote.record_slots_requested_bytes,
            )?
        {
            return Err(credit());
        }
        Ok(())
    }
}

fn requested_facts(facts: &RetainedProtocolMetadataFacts) -> Result<usize, ProviderError> {
    sum(&[
        facts.string_capacity_bytes,
        facts.vector_capacity_bytes,
        facts.boxed_value_bytes,
        facts.shared_value_bytes,
        super::super::restore_input_quote::tree_storage(
            facts.tree_containers,
            facts.tree_entries,
            facts.maximum_tree_key_value_bytes,
            facts.maximum_tree_entry_alignment.max(1),
        )?,
        super::super::restore_input_quote::shared_header_storage(
            facts.shared_backing_views,
            facts.maximum_shared_value_alignment.max(1),
        )?,
    ])
}

#[cfg(test)]
#[path = "exchange_storage_tests.rs"]
mod tests;

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn original_fresh_query_raw_receive_storage_data(
        &self,
    ) -> Result<usize, ProviderError> {
        self.authenticate_native5_source_codec()?;
        acknowledgements::open_ack_storage(allowance(self.authority.limits().frame_bytes.get())?)
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn original_fresh_report_decode_storage_data(&self) -> Result<usize, ProviderError> {
        self.authenticate_native5_source_codec()?;
        acknowledgements::open_ack_storage(crate::reference_packet::service::fresh_restore_allocation::MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES)
    }
}

pub(crate) fn original_host_initial_raw_receive_storage_data(
    bytes: usize,
) -> Result<usize, ProviderError> {
    acknowledgements::open_ack_storage(bytes)
}

#[cfg(test)]
#[path = "exchange_storage/frame_charge_original.rs"]
mod frame_charge_original;

#[cfg(test)]
#[path = "exchange_storage/frame_charge_tests.rs"]
mod frame_charge_tests;

pub use packet_projection::{
    original_packet_prefix_fixed_layout_counter_scratch_data,
    original_packet_prefix_fixed_layout_data,
};
