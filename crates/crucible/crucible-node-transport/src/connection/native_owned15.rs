//! Encodes only genuine original-invocation Capture under explicit class15.
//!
//! ```text
//! ["source-private.native-state/15", connection15, blobs11, service15, capture_owner12]
//! ```
//!
//! Each boot15 view owns the explicit original/unspent phase. This writer never
//! accepts a restoration target or settled transfer. Snapshot outer14 and its
//! exact Source definition remain mandatory separate caller/decoder joins.

use super::native_startup_protocol::{NativeCurrentConnectionView, NativeInvocationConnectionView};
use super::*;
use crate::protocol_snapshot::{ProtocolCaptureCut, ProtocolSnapshotReservation};
use crate::reference_packet::endpoint::OriginalNativeCaptureAllocationOwned12;
use crate::reference_packet::service::{
    OriginalNativeCaptureContext, capture_allocation::PacketNative5CaptureAllocationSelection,
    fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
};
use serde_json::Value;

impl Connection<crate::client::DeadlineStream> {
    /// Captures the actual selected connection, service and completed quote owner.
    ///
    /// # Errors
    /// Refuses another selected family, stale or foreign owners, partial cuts,
    /// mismatched source banks, or insufficient exact row and encoding capacity.
    pub(crate) fn capture_original_native_owned15(
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
        if policy.fresh_restore_allocation_selection()
            != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            || policy.capture_allocation_selection()
                != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
        {
            return Err(ProviderError::Correlation(
                "selected native Capture owner family differs",
            ));
        }
        // An immutable view is DATA only; its same full bank scan excludes
        // actual Query/PrepareBinding occurrences before any snapshot writes.
        NativeCurrentConnectionView::borrow_original(self)?;
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
            let service = context.borrow_current_original_protocol_data(self, blobs)?;
            let receiver = blobs.borrowed_owned11_protocol_view(&self.authority)?;
            let connection = NativeInvocationConnectionView(self);
            let owner = allocation.borrowed_owned12_protocol_view(self, blobs, context)?;
            let data = (
                "source-private.native-state/15",
                &connection,
                &receiver,
                &service,
                &owner,
            );
            let quote = reservation.quote_original_native_owned11(&data, |observer| {
                connection.observe(observer)?;
                receiver.observe_owned11_metadata(observer)?;
                service.observe_current_protocol_metadata_data(observer)?;
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

impl Connection<crate::client::DeadlineStream> {
    pub(super) fn preflight_native_owned15_after_protocol_capacity_inner(
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
        if policy.fresh_restore_allocation_selection()
            != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
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
        // An immutable view is DATA only; its same full bank scan excludes
        // actual Query/PrepareBinding occurrences before any snapshot writes.
        NativeCurrentConnectionView::borrow_original(self)?;
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
            let service = context.borrow_current_original_protocol_data(self, blobs)?;
            let receiver = blobs.borrowed_owned11_protocol_view(&self.authority)?;
            let connection = NativeInvocationConnectionView(self);
            let owner = allocation.borrowed_owned12_protocol_view(self, blobs, context)?;
            let data = (
                "source-private.native-state/15",
                &connection,
                &receiver,
                &service,
                &owner,
            );
            reservation.quote_original_native_owned11(&data, |observer| {
                connection.observe(observer)?;
                receiver.observe_owned11_metadata(observer)?;
                service.observe_current_protocol_metadata_data(observer)?;
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
        let facts = super::native_owned14::after_growth_data(
            quote,
            literal,
            descriptors,
            reservation.maximum_bytes(),
        )?;
        allocation.authenticate_original(self, blobs, context)?;
        Ok(facts)
    }
}

fn after_refused() -> ProviderError {
    ProviderError::Correlation("invocation Capture after owner differs")
}

fn after_credit() -> ProviderError {
    ProviderError::ResourceExhausted("invocation Capture after encoding credit")
}

impl Connection<crate::client::DeadlineStream> {
    pub(crate) fn authenticate_invocation_capture_original_data(
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
        self.original_native_owned11_admission()?
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("invocation Capture boot borrowed"))?
            .authenticate_invocation_capture_data()?;
        NativeCurrentConnectionView::borrow_original(self)?;

        let mut incoming = self.guard.incoming_requests();
        if incoming.next() != Some(original)
            || incoming.next().is_some()
            || original.message != MessageKind::Request
            || original.method != Method::Begin
            || original.body.get("kind").and_then(Value::as_str) != Some("capture")
        {
            return Err(after_refused());
        }
        Ok(())
    }
}
