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
