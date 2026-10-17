//! Checks the actual first unpublished startup Capture window before effects.

use super::*;

impl PreparedExchange<crate::client::DeadlineStream> {
    pub(crate) fn preflight_native_owned14_after_protocol_capacity(
        &self,
        after: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &crate::reference_packet::service::OriginalNativeCaptureContext<'_>,
        allocation: &crate::reference_packet::endpoint::OriginalNativeCaptureAllocationOwned12<'_>,
        storage: &crate::connection::OriginalContinuationPrefixStorageData,
        maximum_counter_bytes: usize,
    ) -> Result<
        crate::connection::native_owned14::NativeOwned14AfterProtocolCapacityFacts,
        ProviderError,
    > {
        if self.phase != Phase::Prepared
            || self.record.sent != 0
            || !self.record.acknowledgements.is_empty()
        {
            return Err(ProviderError::Correlation(
                "startup native14 after unpublished window phase",
            ));
        }
        let (actor, bank) =
            self.record
                .original_actor
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "startup native14 after original absent",
                ))?;
        if !Rc::ptr_eq(actor, &self.connection.protocol_owner)
            || self
                .connection
                .original_frames
                .as_ref()
                .is_none_or(|current| !Rc::ptr_eq(current, bank))
        {
            return Err(ProviderError::Correlation(
                "startup native14 after original differs",
            ));
        }
        self.connection
            .preflight_native_owned14_after_protocol_capacity_inner(
                after,
                blobs,
                context,
                allocation,
                &self.record.originals,
                storage,
                maximum_counter_bytes,
            )
    }

    pub(crate) fn preflight_native_owned15_after_protocol_capacity(
        &self,
        after: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &crate::reference_packet::service::OriginalNativeCaptureContext<'_>,
        allocation: &crate::reference_packet::endpoint::OriginalNativeCaptureAllocationOwned12<'_>,
        storage: &crate::connection::OriginalContinuationPrefixStorageData,
        maximum_counter_bytes: usize,
    ) -> Result<
        crate::connection::native_owned14::NativeOwned14AfterProtocolCapacityFacts,
        ProviderError,
    > {
        if self.phase != Phase::Prepared
            || self.record.sent != 0
            || !self.record.acknowledgements.is_empty()
        {
            return Err(ProviderError::Correlation(
                "startup invocation15 after unpublished window phase",
            ));
        }
        let (actor, bank) =
            self.record
                .original_actor
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "startup invocation15 after original absent",
                ))?;
        if !Rc::ptr_eq(actor, &self.connection.protocol_owner)
            || self
                .connection
                .original_frames
                .as_ref()
                .is_none_or(|current| !Rc::ptr_eq(current, bank))
        {
            return Err(ProviderError::Correlation(
                "startup invocation15 after original differs",
            ));
        }
        self.connection
            .preflight_native_owned15_after_protocol_capacity_inner(
                after,
                blobs,
                context,
                allocation,
                &self.record.originals,
                storage,
                maximum_counter_bytes,
            )
    }
}
