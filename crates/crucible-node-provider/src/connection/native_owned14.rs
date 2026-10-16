//! Encodes complete boot6 owners through explicit startup native classes.
//!
//! ```text
//! ["source-private.native-state/13", connection14, blobs11, service14]
//! ["source-private.native-state/14", connection14, blobs11, service14, capture_owner12]
//! ```
//!
//! These methods require the actual completed startup boot and original private
//! Bootstrap. Existing state11/12 callers retain their intrinsic refusal. The
//! outer snapshot12 format still names state12 and cannot carry state14.

use super::native_startup_protocol::NativeStartupConnectionView;
use super::*;
use crate::protocol_snapshot::{ProtocolCaptureCut, ProtocolSnapshotReservation};
use crate::reference_packet::endpoint::OriginalNativeCaptureAllocationOwned12;
use crate::reference_packet::service::{
    OriginalNativeCaptureContext, capture_allocation::PacketNative5CaptureAllocationSelection,
};
use serde_json::Value;

impl Connection<crate::client::DeadlineStream> {
    /// Captures the actual service with complete typed owners and original banks.
    ///
    /// # Errors
    /// Refuses foreign/revoked owners, partial cuts, unsupported service roots,
    /// mismatched selected banks or insufficient exact metadata/byte credit.
    pub(crate) fn capture_original_native_owned13(
        &mut self,
        reservation: &mut ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        cut: ProtocolCaptureCut,
        context: &crate::reference_packet::service::OriginalNativeCaptureContext<'_>,
    ) -> Result<(), ProviderError> {
        self.native_owned11_preflight(cut)?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation("startup codec absent"))?;
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(ProviderError::Correlation("startup codec role differs"));
        };
        if policy.capture_allocation_selection().is_some()
            || policy.fresh_restore_allocation_selection().is_some()
        {
            return Err(ProviderError::Correlation(
                "startup Capture requires four-root class14",
            ));
        }
        self.preflight_protocol_reservation(reservation)?;
        reservation.validate_source_encoding(self.native5_codec.as_ref(), cut, false)?;
        if !reservation.uses_owned11_encoding()
            || self
                .native5_blobs
                .as_ref()
                .is_none_or(|owner| !blobs.same_protocol_owner(owner))
        {
            return Err(ProviderError::Correlation(
                "native complete bank/blob selection changed",
            ));
        }
        {
            // From this point the service loan holds registrar and supervisor guards.
            // No containment, registration callback or transport operation is called.
            let service = context.borrow_original_startup(self, blobs)?;
            let receiver = blobs.borrowed_owned11_protocol_view(&self.authority)?;
            let connection = NativeStartupConnectionView(self);
            let data = (
                "source-private.native-state/13",
                &connection,
                &receiver,
                &service,
            );
            let quote = reservation.quote_original_native_owned11(&data, |observer| {
                connection.observe(observer)?;
                receiver.observe_owned11_metadata(observer)?;
                service.observe_startup_metadata(observer)
            })?;
            let limits = self.original_native5_protocol_metadata_limits()?.ok_or(
                ProviderError::Correlation("native complete metadata selection absent"),
            )?;
            let selected_rows = match cut {
                ProtocolCaptureCut::NativeIncomingCapture => limits.native_before_rows,
                ProtocolCaptureCut::HostSettled => limits.native_after_rows,
            };
            if quote.selected_rows as u64 != selected_rows.get() {
                return Err(ProviderError::Correlation(
                    "native complete physical metadata bank differs from source selection",
                ));
            }
            if quote.encoded_extent > reservation.maximum_bytes() {
                return Err(ProviderError::ResourceExhausted(
                    "native complete encoded credit",
                ));
            }
            reservation.bind(
                &self.authority,
                &self.protocol_owner,
                cut,
                service.original_cut(),
            )?;
            reservation.retain_native5_codec(self.native5_codec.as_ref())?;
            reservation.encode_owned11(&data)?;
        }
        self.retain_frozen_protocol_frames(reservation)
    }
}

impl Connection<crate::client::DeadlineStream> {
    /// Captures the actual selected connection, service and completed quote owner.
    ///
    /// # Errors
    /// Refuses another selected family, stale or foreign owners, partial cuts,
    /// mismatched source banks, or insufficient exact row and encoding capacity.
    pub(crate) fn capture_original_native_owned14(
        &mut self,
        reservation: &mut ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        cut: ProtocolCaptureCut,
        context: &OriginalNativeCaptureContext<'_>,
        allocation: &OriginalNativeCaptureAllocationOwned12<'_>,
    ) -> Result<(), ProviderError> {
        self.native_owned11_preflight(cut)?;
        let codec = self
            .native5_codec
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "selected native Capture codec absent",
            ))?;
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(ProviderError::Correlation(
                "selected native Capture codec role differs",
            ));
        };
        if policy.fresh_restore_allocation_selection().is_some()
            || policy.capture_allocation_selection()
                != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
        {
            return Err(ProviderError::Correlation(
                "selected native Capture owner family differs",
            ));
        }
        allocation.authenticate_original(self, blobs, context)?;
        if cut == ProtocolCaptureCut::NativeIncomingCapture {
            let original =
                self.guard
                    .incoming_requests()
                    .next()
                    .ok_or(ProviderError::Correlation(
                        "selected native Capture original absent",
                    ))?;
            // The cold predecessor requires the same Capture in both fourth
            // leaves. Bind that association before any snapshot bank changes;
            // a completed Observe owner alone is not a Capture owner.
            allocation.authenticate_capture_original_data(original)?;
        }
        self.preflight_protocol_reservation(reservation)?;
        reservation.validate_source_encoding(self.native5_codec.as_ref(), cut, false)?;
        if !reservation.uses_owned11_encoding()
            || self
                .native5_blobs
                .as_ref()
                .is_none_or(|owner| !blobs.same_protocol_owner(owner))
        {
            return Err(ProviderError::Correlation(
                "selected native Capture bank owner differs",
            ));
        }

        {
            // The borrowed registrar, supervisor and literal guards remain
            // inside this scope. No containment or transport runs under them.
            let service = context.borrow_original_startup(self, blobs)?;
            let receiver = blobs.borrowed_owned11_protocol_view(&self.authority)?;
            let connection = NativeStartupConnectionView(self);
            let owner = allocation.borrowed_owned12_protocol_view(self, blobs, context)?;
            let data = (
                "source-private.native-state/14",
                &connection,
                &receiver,
                &service,
                &owner,
            );
            let quote = reservation.quote_original_native_owned11(&data, |observer| {
                connection.observe(observer)?;
                receiver.observe_owned11_metadata(observer)?;
                service.observe_startup_metadata(observer)?;
                allocation.observe_owned12_metadata(self, blobs, context, observer)
            })?;
            let limits = self.original_native5_protocol_metadata_limits()?.ok_or(
                ProviderError::Correlation("selected native Capture metadata selection absent"),
            )?;
            let selected_rows = match cut {
                ProtocolCaptureCut::NativeIncomingCapture => limits.native_before_rows,
                ProtocolCaptureCut::HostSettled => limits.native_after_rows,
            };
            if quote.selected_rows as u64 != selected_rows.get() {
                return Err(ProviderError::Correlation(
                    "selected native Capture row bank differs",
                ));
            }
            if quote.encoded_extent > reservation.maximum_bytes() {
                return Err(ProviderError::ResourceExhausted(
                    "selected native Capture encoded credit",
                ));
            }
            reservation.bind(
                &self.authority,
                &self.protocol_owner,
                cut,
                service.original_cut(),
            )?;
            reservation.retain_native5_codec(self.native5_codec.as_ref())?;
            reservation.encode_owned11(&data)?;
        }
        self.retain_frozen_protocol_frames(reservation)
    }
}

/// Names the actual four-leaf current extent and stable-family suffix bounds.
///
/// These numbers neither bind a snapshot nor admit the suffix's wire or heap
/// allocations. The actual Source and endpoint owners retain those obligations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOwned14AfterProtocolCapacityFacts {
    pub(crate) current_encoded_bytes: usize,
    pub(crate) required_record_rows: usize,
    pub(crate) required_alias_rows: usize,
    pub(crate) frame_bank_views: usize,
    pub(crate) maximum_literal_encoded_bytes: usize,
    pub(crate) maximum_descriptor_encoded_bytes: usize,
    pub(crate) maximum_metadata_growth_bytes: usize,
    pub(crate) maximum_counter_growth_bytes: usize,
    pub(crate) maximum_after_encoded_bytes: usize,
    pub(crate) reserved_after_encoded_bytes: usize,
}

impl Connection<crate::client::DeadlineStream> {
    pub(super) fn preflight_native_owned14_after_protocol_capacity_inner(
        &self,
        reservation: &mut ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
        allocation: &OriginalNativeCaptureAllocationOwned12<'_>,
        prepared: &[Envelope],
        storage: &OriginalContinuationPrefixStorageData,
        maximum_counter_bytes: usize,
    ) -> Result<NativeOwned14AfterProtocolCapacityFacts, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.original_native_owned11_admission()?;
        if self.role != EndpointRole::Provider
            || !reservation.unused_for_after_preflight()
            || !reservation.uses_owned11_encoding()
            || self
                .native5_blobs
                .as_ref()
                .is_none_or(|owner| !blobs.same_protocol_owner(owner))
        {
            return Err(after_refused());
        }
        let Some(codec) = self.native5_codec.as_ref() else {
            return Err(after_refused());
        };
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(after_refused());
        };
        if policy.fresh_restore_allocation_selection().is_some()
            || policy.capture_allocation_selection()
                != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
        {
            return Err(after_refused());
        }
        self.guard.authenticate_prepared_capture_suffix(prepared)?;
        let original = self
            .guard
            .incoming_requests()
            .next()
            .ok_or_else(after_refused)?;
        // The full fourth leaf already retains THIS genuine incoming Capture.
        // No absent->present Capture option or new owner kind is projected here.
        allocation.authenticate_capture_original_data(original)?;
        allocation.authenticate_original(self, blobs, context)?;
        reservation.validate_source_encoding(
            self.native5_codec.as_ref(),
            ProtocolCaptureCut::HostSettled,
            false,
        )?;
        let selected_rows = self
            .original_native5_protocol_metadata_limits()?
            .ok_or_else(after_refused)?
            .native_after_rows;

        let bank_owner = self.original_frames.as_ref().ok_or_else(after_refused)?;
        let bank = bank_owner.try_borrow().map_err(|_| after_refused())?;
        reservation.validate_literal_reservation(&bank)?;
        if storage.kind != OriginalContinuationPrefixKind::Capture {
            return Err(after_refused());
        }
        // Continuing proof ACKs have actual selected canonical-literal checks.
        // Rejected/error frames still use full negotiated R and cannot produce
        // an after owner. The encoded bound follows this real suffix, not B.
        let incoming = self
            .quote_original_continuation_completed_incoming_data(storage, maximum_counter_bytes)?;
        let current = bank.storage_facts(
            usize::try_from(self.authority.limits().frame_bytes.get())
                .map_err(|_| after_credit())?,
        );
        let retained = current
            .retained_bytes
            .checked_add(storage.exchange.outgoing_framed_bytes)
            .and_then(|bytes| bytes.checked_add(incoming))
            .ok_or_else(after_credit)?;
        let maximum_incoming = current
            .incoming_frames
            .checked_add(storage.exchange.requests)
            .ok_or_else(after_credit)?;
        let maximum_outgoing = current
            .outgoing_frames
            .checked_add(storage.exchange.frames)
            .ok_or_else(after_credit)?;
        let (literal, descriptors) =
            bank.selected_initialized_encoding_data(retained, maximum_incoming, maximum_outgoing)?;
        let quote = {
            // Match the exact four-leaf encoder and its SAME record/alias banks.
            // No transport, containment or external callback runs under loans.
            let service = context.borrow_original_startup(self, blobs)?;
            let receiver = blobs.borrowed_owned11_protocol_view(&self.authority)?;
            let connection = NativeStartupConnectionView(self);
            let owner = allocation.borrowed_owned12_protocol_view(self, blobs, context)?;
            let data = (
                "source-private.native-state/14",
                &connection,
                &receiver,
                &service,
                &owner,
            );
            reservation.quote_original_native_owned11(&data, |observer| {
                connection.observe(observer)?;
                receiver.observe_owned11_metadata(observer)?;
                service.observe_startup_metadata(observer)?;
                allocation.observe_owned12_metadata(self, blobs, context, observer)
            })?
        };
        if quote.selected_rows as u64 != selected_rows.get() || quote.frame_bank_views == 0 {
            return Err(after_refused());
        }
        let maximum_slots = maximum_incoming
            .checked_add(maximum_outgoing)
            .ok_or_else(after_credit)?;
        let nodes = quote
            .observed_nodes
            .checked_add(
                maximum_slots
                    .checked_mul(quote.frame_bank_views)
                    .and_then(|slots| slots.checked_mul(7))
                    .ok_or_else(after_credit)?,
            )
            .ok_or_else(after_credit)?;
        if nodes > 131_072 {
            return Err(after_credit());
        }
        let facts = after_growth_data(quote, literal, descriptors, reservation.maximum_bytes())?;
        allocation.authenticate_original(self, blobs, context)?;
        Ok(facts)
    }
}

pub(super) fn after_growth_data(
    quote: crate::protocol_snapshot::NativeProtocolMetadataQuote,
    literal: usize,
    descriptors: usize,
    maximum: usize,
) -> Result<NativeOwned14AfterProtocolCapacityFacts, ProviderError> {
    use crate::retained_metadata::records::{MetadataCapacityRecord, MetadataRecordKind};
    let add = |left: usize, right: usize| left.checked_add(right).ok_or_else(after_credit);
    let multiply = |left: usize, right: usize| left.checked_mul(right).ok_or_else(after_credit);
    // The five current row kinds have names of at most six bytes. Count the
    // ACTUAL serializer with the longest kind and all three maximal integers.
    let row = MetadataCapacityRecord {
        kind: MetadataRecordKind::String,
        extent: usize::MAX,
        element_bytes: usize::MAX,
        alignment: usize::MAX,
    };
    let record_width = crate::connection::serialized_credit(&row, 128)?;
    // This actual full family introduces no new allocating child or shared
    // owner after the prepared Capture. Slot rows contain fixed primitive data;
    // the settled guard removes its incoming original. Keep the complete current
    // record/alias row demand, without converting spare row capacity into rows.
    let metadata = add(
        add(
            multiply(quote.required_record_rows, add(record_width, 1)?)?,
            multiply(
                quote.required_alias_rows,
                add(quote.maximum_existing_alias_row_encoded_bytes, 1)?,
            )?,
        )?,
        4,
    )?;
    let literal = multiply(literal, quote.frame_bank_views)?;
    let descriptors = multiply(descriptors, quote.frame_bank_views)?;
    // Only guard next-sent/received, reader last-slot and three counters per
    // repeated frame-bank body can grow. Descriptor field changes are already
    // included by the full descriptor bound. All owner/report/currency/policy
    // fields stay unchanged in the admitted successful Capture family.
    let integer = crate::connection::serialized_credit(&u64::MAX, 64)?;
    let index = crate::connection::serialized_credit(&usize::MAX, 64)?;
    let counters = add(
        multiply(2, integer)?,
        multiply(add(multiply(3, quote.frame_bank_views)?, 1)?, index)?,
    )?;
    let total = add(
        add(
            add(add(quote.encoded_extent, literal)?, descriptors)?,
            metadata,
        )?,
        counters,
    )?;
    if total > maximum {
        return Err(after_credit());
    }
    Ok(NativeOwned14AfterProtocolCapacityFacts {
        current_encoded_bytes: quote.encoded_extent,
        required_record_rows: quote.required_record_rows,
        required_alias_rows: quote.required_alias_rows,
        frame_bank_views: quote.frame_bank_views,
        maximum_literal_encoded_bytes: literal,
        maximum_descriptor_encoded_bytes: descriptors,
        maximum_metadata_growth_bytes: metadata,
        maximum_counter_growth_bytes: counters,
        maximum_after_encoded_bytes: total,
        reserved_after_encoded_bytes: maximum,
    })
}

fn after_refused() -> ProviderError {
    ProviderError::Correlation("startup native14 after current owner/cut/bank association")
}

fn after_credit() -> ProviderError {
    ProviderError::ResourceExhausted("startup native14 four-leaf after encoded capacity")
}

impl Connection<crate::client::DeadlineStream> {
    pub(crate) fn authenticate_startup_capture_original_data(
        &mut self,
        original: &Envelope,
        sdk: &NativeCaptureSdkCompletedQuote,
        blobs: &crate::blob::BlobReceiver,
        context: &OriginalNativeCaptureContext<'_>,
    ) -> Result<(), ProviderError> {
        // Authority containment can mutate the actual connection and therefore
        // precedes any service/registrar loan held by an encoding view.
        self.native_owned11_preflight(ProtocolCaptureCut::NativeIncomingCapture)?;
        sdk.authenticate_same_target_data(self, blobs, context)?;
        let mut incoming = self.guard.incoming_requests();
        if incoming.next() != Some(original)
            || incoming.next().is_some()
            || original.message != MessageKind::Request
            || original.method != Method::Begin
            || original.body.get("kind").and_then(Value::as_str) != Some("capture")
            || !context.requires_original_native_startup_codec(self, blobs)?
        {
            return Err(after_refused());
        }
        Ok(())
    }
}

#[cfg(test)]
mod startup_after_data_tests {
    use super::*;

    #[test]
    fn actual_after_growth_preserves_all_views_and_exact_limit_without_spare_row_fiction()
    -> Result<(), Box<dyn std::error::Error>> {
        let quote = crate::protocol_snapshot::NativeProtocolMetadataQuote {
            required_record_rows: 9,
            required_alias_rows: 7,
            maximum_existing_alias_row_encoded_bytes: 47,
            observed_nodes: 40,
            encoded_extent: 100,
            selected_rows: 512,
            record_capacity: 512,
            record_bytes: 512
                * std::mem::size_of::<crate::retained_metadata::records::MetadataCapacityRecord>(),
            alias_row_capacity: 512,
            alias_lookup_capacity: 512,
            alias_row_bytes: 512,
            alias_lookup_bytes: 512,
            frame_bank_views: 3,
        };
        let data = after_growth_data(quote, 31, 17, usize::MAX)?;
        assert_eq!(data.maximum_literal_encoded_bytes, 3 * 31);
        assert_eq!(data.maximum_descriptor_encoded_bytes, 3 * 17);
        assert_eq!(
            after_growth_data(quote, 31, 17, data.maximum_after_encoded_bytes)?
                .maximum_after_encoded_bytes,
            data.maximum_after_encoded_bytes
        );
        assert!(after_growth_data(quote, 31, 17, data.maximum_after_encoded_bytes - 1).is_err());
        assert!(after_growth_data(quote, usize::MAX, 17, usize::MAX).is_err());
        let smaller_spare = crate::protocol_snapshot::NativeProtocolMetadataQuote {
            selected_rows: 16,
            ..quote
        };
        assert_eq!(
            after_growth_data(smaller_spare, 31, 17, usize::MAX)?.maximum_metadata_growth_bytes,
            data.maximum_metadata_growth_bytes
        );
        Ok(())
    }
}
