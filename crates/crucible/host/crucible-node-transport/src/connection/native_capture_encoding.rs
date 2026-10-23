//! Reconciles the actual native12 Capture plan with the same born codec banks.
//!
//! The current three leaves are counted again under their genuine service loan.
//! The native producer supplies the fourth owner's closed prospective fields;
//! no completed owner, report, Capture frame or permission is manufactured here.
//! The live encoder separately requires that real owner and recounts all leaves
//! before binding or copying the original snapshot.

use super::*;
use crate::protocol_snapshot::{
    NativeProtocolMetadataQuote, ProtocolCaptureCut, ProtocolSnapshotReservation,
};
use crate::reference_packet::endpoint::NativeCaptureCandidateOwnerData;
use crate::reference_packet::service::{
    OriginalNativeCaptureContext, capture_allocation::PacketNative5CaptureAllocationSelection,
};
use crate::retained_metadata::{
    aliases::MetadataSharedKind,
    records::{MetadataCapacityRecord, MetadataRecordKind},
};
use std::mem::size_of;

/// Borrows the same actual Observe and its genuine completed SDK association.
pub(crate) struct NativeOwned12CaptureEncodingPlan<'a> {
    pub(crate) sdk: &'a NativeCaptureSdkCompletedQuote,
    pub(crate) candidate: &'a NativeCaptureCandidateOwnerData,
    pub(crate) original_observe: &'a Envelope,
    pub(crate) first_observe_response: u64,
    pub(crate) maximum_requested_bytes: usize,
}

/// Names closed initialized history through one future semantic cut.
///
/// These are encoded/layout bounds from the actual selected publication plan,
/// not bank reservations, observed capacities or allocation permissions.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeOwned12CaptureSuffixData {
    pub(crate) maximum_retained_bytes: usize,
    pub(crate) maximum_incoming_frames: usize,
    pub(crate) maximum_outgoing_frames: usize,
}

/// Contains no after bound before the real Capture prefix has been projected.
pub(crate) struct NativeOwned12CaptureBeforeEncodingData {
    pub(crate) before: NativeOwned12CaptureBankEncodingData,
    pub(crate) requested_owner_fields_bytes: usize,
    pub(crate) declared_counter_scratch_bytes: usize,
}

struct NativeOwned12CapturePhaseEncodingData {
    before: NativeOwned12CaptureBankEncodingData,
    after: Option<NativeOwned12CaptureBankEncodingData>,
    requested_owner_fields_bytes: usize,
    declared_counter_scratch_bytes: usize,
}

/// Names one cut's existing banks and separately derived future encoded terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOwned12CaptureBankEncodingData {
    pub(crate) current_three_leaf_encoded_bytes: usize,
    pub(crate) maximum_fourth_owner_encoded_bytes: usize,
    pub(crate) maximum_original_guard_encoded_growth_bytes: usize,
    pub(crate) maximum_literal_encoded_growth_bytes: usize,
    pub(crate) maximum_descriptor_encoded_growth_bytes: usize,
    pub(crate) maximum_metadata_encoded_growth_bytes: usize,
    pub(crate) maximum_counter_encoded_growth_bytes: usize,
    pub(crate) maximum_record_rows: usize,
    pub(crate) maximum_alias_rows: usize,
    pub(crate) maximum_observed_nodes: usize,
    pub(crate) frame_bank_views: usize,
    pub(crate) maximum_encoded_bytes: usize,
    pub(crate) reserved_encoded_bytes: usize,
    pub(crate) serialization_events: Option<NativeOwned12SerializationEventsData>,
}

/// Counts future serde values and backing events, independently of metadata visits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOwned12SerializationEventsData {
    pub(crate) maximum_value_nodes: usize,
    pub(crate) maximum_capacity_records: usize,
    pub(crate) maximum_serializer_temporary_requested_bytes: usize,
}

/// Retains numeric data for both cuts without binding either original bank.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOwned12CaptureEncodingData {
    pub(crate) before: NativeOwned12CaptureBankEncodingData,
    pub(crate) after: NativeOwned12CaptureBankEncodingData,
    pub(crate) requested_owner_fields_bytes: usize,
    pub(crate) declared_counter_scratch_bytes: usize,
}

impl Connection<crate::client::DeadlineStream> {
    pub(crate) fn quote_original_native_owned12_capture_before_encoding(
        &mut self,
        before: &mut ProtocolSnapshotReservation,
        after: &mut ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
        plan: NativeOwned12CaptureEncodingPlan<'_>,
        before_suffix: NativeOwned12CaptureSuffixData,
    ) -> Result<NativeOwned12CaptureBeforeEncodingData, ProviderError> {
        let phase = self.quote_original_native_owned12_capture_phase_encoding(
            before,
            after,
            blobs,
            context,
            plan,
            before_suffix,
            None,
        )?;
        if phase.after.is_some() {
            return Err(refused());
        }
        Ok(NativeOwned12CaptureBeforeEncodingData {
            before: phase.before,
            requested_owner_fields_bytes: phase.requested_owner_fields_bytes,
            declared_counter_scratch_bytes: phase.declared_counter_scratch_bytes,
        })
    }

    pub(crate) fn quote_original_native_owned12_capture_encoding(
        &mut self,
        before: &mut ProtocolSnapshotReservation,
        after: &mut ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
        plan: NativeOwned12CaptureEncodingPlan<'_>,
        before_suffix: NativeOwned12CaptureSuffixData,
        after_suffix: NativeOwned12CaptureSuffixData,
    ) -> Result<NativeOwned12CaptureEncodingData, ProviderError> {
        let phase = self.quote_original_native_owned12_capture_phase_encoding(
            before,
            after,
            blobs,
            context,
            plan,
            before_suffix,
            Some(after_suffix),
        )?;
        Ok(NativeOwned12CaptureEncodingData {
            before: phase.before,
            after: phase.after.ok_or_else(refused)?,
            requested_owner_fields_bytes: phase.requested_owner_fields_bytes,
            declared_counter_scratch_bytes: phase.declared_counter_scratch_bytes,
        })
    }

    fn quote_original_native_owned12_capture_phase_encoding(
        &mut self,
        before: &mut ProtocolSnapshotReservation,
        after: &mut ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
        plan: NativeOwned12CaptureEncodingPlan<'_>,
        before_suffix: NativeOwned12CaptureSuffixData,
        after_suffix: Option<NativeOwned12CaptureSuffixData>,
    ) -> Result<NativeOwned12CapturePhaseEncodingData, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.check_authority()?;
        self.original_native_owned11_admission()?;
        plan.sdk.authenticate_current(self, blobs, context)?;
        if self.role != EndpointRole::Provider
            || plan.original_observe.method != Method::Observe
            || plan.original_observe.message != MessageKind::Request
            || !plan.candidate.includes_capture_original
        {
            return Err(refused());
        }
        self.guard.preflight_original_packet_prefix_data(
            plan.original_observe,
            plan.first_observe_response,
            1,
            0,
        )?;
        let Some(codec) = self.native5_codec.as_ref() else {
            return Err(refused());
        };
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(refused());
        };
        if policy.capture_allocation_selection()
            != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
            || self
                .native5_blobs
                .as_ref()
                .is_none_or(|owner| !blobs.same_protocol_owner(owner))
        {
            return Err(refused());
        }
        for bank in [&*before, &*after] {
            self.preflight_protocol_reservation(bank)?;
            if !bank.unused_for_after_preflight() || !bank.uses_owned11_encoding() {
                return Err(refused());
            }
        }
        before.validate_source_encoding(
            self.native5_codec.as_ref(),
            ProtocolCaptureCut::NativeIncomingCapture,
            false,
        )?;
        after.validate_source_encoding(
            self.native5_codec.as_ref(),
            ProtocolCaptureCut::HostSettled,
            false,
        )?;
        let selected = self
            .original_native5_protocol_metadata_limits()?
            .ok_or_else(refused)?;
        let (before_growth, after_growth) = {
            let bank = self
                .original_frames
                .as_ref()
                .ok_or_else(refused)?
                .try_borrow()
                .map_err(|_| refused())?;
            let actual = bank.storage_facts(
                usize::try_from(self.authority.limits().frame_bytes.get()).map_err(|_| credit())?,
            );
            if actual != plan.sdk.sdk_data().original_storage || !actual.all_io_complete {
                return Err(refused());
            }
            before.validate_literal_reservation(&bank)?;
            after.validate_literal_reservation(&bank)?;
            let first = bank.selected_initialized_encoding_data(
                before_suffix.maximum_retained_bytes,
                before_suffix.maximum_incoming_frames,
                before_suffix.maximum_outgoing_frames,
            )?;
            let last = after_suffix
                .map(|suffix| {
                    if suffix.maximum_retained_bytes < before_suffix.maximum_retained_bytes
                        || suffix.maximum_incoming_frames < before_suffix.maximum_incoming_frames
                        || suffix.maximum_outgoing_frames < before_suffix.maximum_outgoing_frames
                    {
                        return Err(refused());
                    }
                    bank.selected_initialized_encoding_data(
                        suffix.maximum_retained_bytes,
                        suffix.maximum_incoming_frames,
                        suffix.maximum_outgoing_frames,
                    )
                })
                .transpose()?;
            (first, last)
        };
        let ((before_quote, before_serialization), (after_quote, after_serialization)) = {
            // Registrar/supervisor/bank loans end before the final currentness
            // check. Only borrowed rendering and precharged metadata run here.
            let service = context.borrow_current_original_protocol_data(self, blobs)?;
            let receiver = blobs.borrowed_owned11_protocol_view(&self.authority)?;
            let connection =
                super::native_startup_protocol::NativeCurrentConnectionView::borrow_original(self)?;
            let current = (
                service.current_protocol_format_data(),
                &connection,
                &receiver,
                &service,
            );
            let first = before.quote_original_native_owned11_with_serialization_data(
                &current,
                |observer| {
                    connection.observe(observer)?;
                    receiver.observe_owned11_metadata(observer)?;
                    service.observe_current_protocol_metadata_data(observer)
                },
                plan.maximum_requested_bytes,
            )?;
            let last = after.quote_original_native_owned11_with_serialization_data(
                &current,
                |observer| {
                    connection.observe(observer)?;
                    receiver.observe_owned11_metadata(observer)?;
                    service.observe_current_protocol_metadata_data(observer)
                },
                plan.maximum_requested_bytes,
            )?;
            (first, last)
        };
        for (quote, recorded, rows, bank) in [
            (
                before_quote,
                &plan.sdk.sdk_data().before,
                selected.native_before_rows,
                &*before,
            ),
            (
                after_quote,
                &plan.sdk.sdk_data().after,
                selected.native_after_rows,
                &*after,
            ),
        ] {
            if u64::try_from(quote.selected_rows).ok() != Some(rows.get())
                || quote.required_record_rows != recorded.required_record_rows
                || quote.required_alias_rows != recorded.required_alias_rows
                || quote.encoded_extent != recorded.current_encoded_extent
                || quote.frame_bank_views != plan.sdk.sdk_data().frame_bank_views
                || bank.original_allocation_facts()? != recorded.allocation
                || bank.original_metadata_record_allocation_facts()?.as_ref()
                    != Some(&recorded.records)
                || bank.original_alias_allocation_facts()?.as_ref() != Some(&recorded.aliases)
            {
                return Err(refused());
            }
        }
        let make_bound = |current: &crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
                          quote: NativeProtocolMetadataQuote,
                          growth: (usize, usize),
                          suffix: NativeOwned12CaptureSuffixData,
                          maximum_encoded: usize| {
            let slots = add(suffix.maximum_incoming_frames, suffix.maximum_outgoing_frames)?;
            future_bank_serialization_data(
                current,
                suffix.maximum_retained_bytes,
                future_bank_data(
                    quote, plan.candidate, growth.0, growth.1, slots, maximum_encoded,
                )?,
                plan.candidate,
                quote.selected_rows,
                slots,
            )
        };
        let first = make_bound(
            &before_serialization,
            before_quote,
            before_growth,
            before_suffix,
            before.maximum_bytes(),
        )?;
        let last = after_suffix
            .zip(after_growth)
            .map(|(suffix, growth)| {
                make_bound(
                    &after_serialization,
                    after_quote,
                    growth,
                    suffix,
                    after.maximum_bytes(),
                )
            })
            .transpose()?;
        let result = NativeOwned12CapturePhaseEncodingData {
            before: first,
            after: last,
            requested_owner_fields_bytes: plan.candidate.requested_owner_fields_bytes,
            declared_counter_scratch_bytes: add(
                plan.candidate.declared_counter_scratch_bytes,
                sum(&[
                    size_of::<NativeOwned12CapturePhaseEncodingData>(),
                    size_of::<NativeOwned12CaptureBeforeEncodingData>(),
                    size_of::<NativeOwned12CaptureEncodingData>(),
                    size_of::<NativeOwned12CaptureEncodingPlan<'static>>(),
                    2 * size_of::<NativeOwned12CaptureSuffixData>(),
                    2 * size_of::<NativeProtocolMetadataQuote>(),
                    2 * size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData>(),
                    before_serialization.declared_counter_scratch_bytes.max(after_serialization.declared_counter_scratch_bytes),
                ])?,
            )?,
        };
        plan.sdk.authenticate_current(self, blobs, context)?;
        self.guard.preflight_original_packet_prefix_data(
            plan.original_observe,
            plan.first_observe_response,
            1,
            0,
        )?;
        Ok(result)
    }
}

fn future_bank_data(
    current: NativeProtocolMetadataQuote,
    candidate: &NativeCaptureCandidateOwnerData,
    literal: usize,
    descriptors: usize,
    maximum_slots: usize,
    maximum_encoded: usize,
) -> Result<NativeOwned12CaptureBankEncodingData, ProviderError> {
    if !candidate.includes_capture_original || candidate.frame_bank_views == 0 {
        return Err(refused());
    }
    let views = add(current.frame_bank_views, candidate.frame_bank_views)?;
    // One actual guard key and incoming Envelope can replace Observe. The
    // fourth owner's independently retained Capture is already in candidate.
    let records = sum(&[
        current.required_record_rows,
        candidate.maximum_record_rows,
        candidate.capture_original_capacity_records,
        1,
    ])?;
    let aliases = add(current.required_alias_rows, candidate.maximum_alias_rows)?;
    // The actual Slot walker observes five scalar fields and an Option<usize>
    // (two visits when populated). It never traverses the inline ID byte array.
    // The closed selected suffix counts initialized descriptors in this cut;
    // the whole original descriptor allocation remains separately retained.
    let nodes = sum(&[
        current.observed_nodes,
        candidate.maximum_observed_nodes,
        candidate.capture_original_observed_nodes,
        1,
        mul(mul(maximum_slots, views)?, 7)?,
    ])?;
    if records > current.selected_rows || aliases > current.selected_rows || nodes > 131_072 {
        return Err(credit());
    }
    let record = MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: usize::MAX,
        element_bytes: usize::MAX,
        alignment: usize::MAX,
    };
    let record_width = super::serialized_credit(&record, 128)?;
    let alias_width = current
        .maximum_existing_alias_row_encoded_bytes
        .max(MetadataSharedKind::NativeControlIdentity.maximum_row_encoded_bytes_data()?);
    // The codec serializes initialized record/alias rows; their full spare
    // backing remains charged in the actual born allocation facts. Capacity is
    // a scalar in the wire view, not thousands of invented initialized rows.
    let metadata = sum(&[
        mul(records, add(record_width, 1)?)?,
        mul(aliases, add(alias_width, 1)?)?,
        4,
    ])?;
    let literal = mul(literal, views)?;
    let descriptors = mul(descriptors, views)?;
    // Id::new fixes at most128 printable ASCII bytes. Include the guard map
    // key quotes and tuple/separator punctuation independently of Envelope.
    let original = add(
        candidate.capture_original_maximum_encoded_bytes,
        128 + 2 + 6,
    )?;
    let integer = super::serialized_credit(&u64::MAX, 64)?;
    let index = super::serialized_credit(&usize::MAX, 64)?;
    let counters = add(mul(2, integer)?, mul(add(mul(3, views)?, 1)?, index)?)?;
    // Native-state11/12 tags have equal widths. The extra comma introduces the
    // fourth leaf; all old repeated children and their full capacity growth
    // stay in the sum, with no wire-body alias discount.
    let total = sum(&[
        current.encoded_extent,
        1,
        candidate.maximum_encoded_bytes,
        original,
        literal,
        descriptors,
        metadata,
        counters,
    ])?;
    if total > maximum_encoded {
        return Err(credit());
    }
    Ok(NativeOwned12CaptureBankEncodingData {
        current_three_leaf_encoded_bytes: current.encoded_extent,
        maximum_fourth_owner_encoded_bytes: candidate.maximum_encoded_bytes,
        maximum_original_guard_encoded_growth_bytes: original,
        maximum_literal_encoded_growth_bytes: literal,
        maximum_descriptor_encoded_growth_bytes: descriptors,
        maximum_metadata_encoded_growth_bytes: metadata,
        maximum_counter_encoded_growth_bytes: counters,
        maximum_record_rows: records,
        maximum_alias_rows: aliases,
        maximum_observed_nodes: nodes,
        frame_bank_views: views,
        maximum_encoded_bytes: total,
        reserved_encoded_bytes: maximum_encoded,
        serialization_events: None,
    })
}

fn future_bank_serialization_data(
    current: &crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
    maximum_literal_bytes: usize,
    mut bound: NativeOwned12CaptureBankEncodingData,
    candidate: &NativeCaptureCandidateOwnerData,
    _selected_rows: usize,
    maximum_slots: usize,
) -> Result<NativeOwned12CaptureBankEncodingData, ProviderError> {
    let compact =
        crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::serialization_layout_data(
            maximum_literal_bytes,
        )?;
    let slots = maximum_slots;
    // The real Slot wire tuple has six fields. A populated optional request
    // serializes its inline [u8;128] as an integer array: tuple +five scalar
    // fields +array +128 scalars =135 value events and three backing records.
    // Metadata's seven visits are deliberately not reused as serializer work.
    let bank_value_nodes = sum(&[4, compact.chunk_count, 1, mul(slots, 135)?])?;
    let bank_capacity_records = sum(&[3, compact.chunk_count, 1, mul(slots, 3)?])?;
    // Record rows are (kind String, extent, element bytes, alignment): five
    // value events and two backing records (tuple and kind String).
    // Alias rows are (kind String, first usize): three events/two containers.
    // Closed initialized row bounds come from the same actual walk plus the
    // future fourth owner/guard. Their preallocated spare backing is unchanged;
    // current rows remain conservatively included a second time.
    bound.serialization_events = Some(NativeOwned12SerializationEventsData {
        maximum_value_nodes: sum(&[
            current.serialized_value_nodes,
            candidate.maximum_serialized_value_nodes,
            candidate.capture_original_serialized_value_nodes,
            1, // independent received_requests map key
            mul(bound.frame_bank_views, bank_value_nodes)?,
            2,
            mul(bound.maximum_record_rows, 5)?,
            mul(bound.maximum_alias_rows, 3)?,
        ])?,
        maximum_capacity_records: sum(&[
            current.serialized_capacity_records,
            candidate.maximum_serialized_capacity_records,
            candidate.capture_original_serialized_capacity_records,
            1,
            mul(bound.frame_bank_views, bank_capacity_records)?,
            2,
            mul(bound.maximum_record_rows, 2)?,
            mul(bound.maximum_alias_rows, 2)?,
        ])?,
        maximum_serializer_temporary_requested_bytes: sum(&[
            current.serializer_temporary_requested_bytes,
            candidate.serialization_requested_bytes,
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes(),
        ])?,
    });
    Ok(bound)
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(credit)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(credit)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0, |total, value| add(total, *value))
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native12 current Observe encoding association")
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("native12 prospective complete encoding")
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Assertion panics are the data-control verdict.
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn current_data() -> NativeProtocolMetadataQuote {
        let selected = 64;
        let (alias_row, alias_key) =
            crate::retained_metadata::aliases::original_metadata_alias_layouts();
        NativeProtocolMetadataQuote {
            required_record_rows: 9,
            required_alias_rows: 7,
            maximum_existing_alias_row_encoded_bytes: 47,
            observed_nodes: 40,
            encoded_extent: 100,
            selected_rows: selected,
            record_capacity: selected,
            record_bytes: selected * size_of::<MetadataCapacityRecord>(),
            alias_row_capacity: selected,
            alias_lookup_capacity: selected,
            alias_row_bytes: selected * alias_row,
            alias_lookup_bytes: selected * alias_key,
            frame_bank_views: 3,
        }
    }

    fn candidate_data() -> NativeCaptureCandidateOwnerData {
        // Arithmetic-only data, never a native owner or live codec fixture.
        NativeCaptureCandidateOwnerData {
            maximum_encoded_bytes: 200,
            maximum_record_rows: 12,
            maximum_alias_rows: 5,
            maximum_observed_nodes: 100,
            frame_bank_views: 1,
            includes_capture_original: true,
            requested_owner_fields_bytes: 0,
            requested_observe_owner_fields_bytes: 0,
            typed_report_requested_bytes: 0,
            raw_report_requested_bytes: 0,
            serialization_requested_bytes: 0,
            declared_counter_scratch_bytes: 0,
            capture_original_capacity_records: 3,
            capture_original_observed_nodes: 20,
            capture_original_maximum_encoded_bytes: 80,
            maximum_serialized_value_nodes: 20,
            maximum_serialized_capacity_records: 10,
            capture_original_serialized_value_nodes: 10,
            capture_original_serialized_capacity_records: 5,
        }
    }

    #[test]
    fn future_native12_keeps_all_four_bank_views_and_checks_exact_limit() -> TestResult {
        let current = current_data();
        let candidate = candidate_data();
        let facts = future_bank_data(current, &candidate, 31, 17, 128, usize::MAX)?;
        assert_eq!(facts.frame_bank_views, 4);
        assert_eq!(facts.maximum_literal_encoded_growth_bytes, 4 * 31);
        assert_eq!(facts.maximum_descriptor_encoded_growth_bytes, 4 * 17);
        assert_eq!(facts.maximum_record_rows, 9 + 12 + 3 + 1);
        assert_eq!(facts.maximum_alias_rows, 7 + 5);
        assert_eq!(
            facts.maximum_observed_nodes,
            40 + 100 + 20 + 1 + 2 * 64 * 4 * 7
        );
        assert_eq!(
            facts.maximum_original_guard_encoded_growth_bytes,
            80 + 128 + 2 + 6
        );
        let exact = future_bank_data(
            current,
            &candidate,
            31,
            17,
            128,
            facts.maximum_encoded_bytes,
        )?;
        assert_eq!(exact.maximum_encoded_bytes, facts.maximum_encoded_bytes);
        assert_eq!(exact.reserved_encoded_bytes, facts.maximum_encoded_bytes);
        assert!(
            future_bank_data(
                current,
                &candidate,
                31,
                17,
                128,
                facts.maximum_encoded_bytes - 1
            )
            .is_err()
        );
        assert!(future_bank_data(current, &candidate, usize::MAX, 17, 64, usize::MAX).is_err());
        Ok(())
    }

    #[test]
    fn future_native12_requires_capture_and_separate_record_alias_node_banks() -> TestResult {
        let current = current_data();
        let mut candidate = candidate_data();
        candidate.includes_capture_original = false;
        assert!(future_bank_data(current, &candidate, 31, 17, 128, usize::MAX).is_err());
        candidate.includes_capture_original = true;
        let mut short = current;
        short.selected_rows = 9 + 12 + 3;
        assert!(future_bank_data(short, &candidate, 31, 17, 64, usize::MAX).is_err());
        candidate.maximum_alias_rows = current.selected_rows;
        assert!(future_bank_data(current, &candidate, 31, 17, 128, usize::MAX).is_err());
        candidate.maximum_alias_rows = 5;
        candidate.maximum_observed_nodes = 131_072;
        assert!(future_bank_data(current, &candidate, 31, 17, 128, usize::MAX).is_err());
        Ok(())
    }

    #[test]
    fn actual_literal_slot_walk_uses_seven_visits_with_inline_request_identity() -> TestResult {
        use crate::retained_metadata::MetadataObserver;
        use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};
        let mut bank = OriginalFrameReservation::reserve(512, 2)?;
        let mut observer = MetadataObserver::new();
        bank.observe_owned11_metadata(&mut observer)?;
        let empty = observer.finish();
        let incoming = bank.begin(FrameDirection::Incoming, 5)?;
        bank.append(incoming, &[0, 0, 0, 1, b'0'])?;
        bank.retain_request(incoming, &Id::new("literal-request")?)?;
        bank.finish(incoming)?;
        let mut observer = MetadataObserver::new();
        bank.observe_owned11_metadata(&mut observer)?;
        let populated = observer.finish();
        assert_eq!(populated.observed_nodes - empty.observed_nodes, 7);
        assert_eq!(populated.capacity_records, empty.capacity_records);
        let outgoing = bank.begin(FrameDirection::Outgoing, 5)?;
        bank.append(outgoing, &[0, 0, 0, 1, b'0'])?;
        bank.advance(outgoing, 5)?;
        bank.finish(outgoing)?;
        let mut observer = MetadataObserver::new();
        bank.observe_owned11_metadata(&mut observer)?;
        let no_identity = observer.finish();
        assert_eq!(no_identity.observed_nodes - populated.observed_nodes, 6);
        assert_eq!(no_identity.capacity_records, empty.capacity_records);
        Ok(())
    }

    #[test]
    fn actual_slot_serde_events_include_full_inline_identifier_bytes() -> TestResult {
        use crate::retained_metadata::serialization_storage::actual_serialization_storage_data;
        use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};
        let mut bank = OriginalFrameReservation::reserve(512, 2)?;
        let empty = actual_serialization_storage_data(
            &bank.protocol_view_with_encoding(true),
            Default::default(),
            1024 * 1024,
        )?;
        let slot = bank.begin(FrameDirection::Incoming, 5)?;
        bank.append(slot, &[0, 0, 0, 1, b'0'])?;
        bank.retain_request(slot, &Id::new("x".repeat(128))?)?;
        bank.finish(slot)?;
        let populated = actual_serialization_storage_data(
            &bank.protocol_view_with_encoding(true),
            Default::default(),
            1024 * 1024,
        )?;

        // Slot6 contributes135 logical values; the first compact literal chunk
        // adds one String. This differs from metadata's seven typed visits.
        assert_eq!(
            populated.serialized_value_nodes - empty.serialized_value_nodes,
            135 + 1
        );
        assert_eq!(
            populated.serialized_capacity_records - empty.serialized_capacity_records,
            3 + 1
        );
        Ok(())
    }
}
