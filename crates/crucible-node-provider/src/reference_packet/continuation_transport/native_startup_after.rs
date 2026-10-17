//! Reconciles the genuine startup Capture first window with its after bank.

use super::*;

impl PacketCapturePrefix<crate::client::DeadlineStream> {
    pub(crate) fn preflight_owned14_after_protocol_capacity(
        &self,
        after: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &super::super::service::OriginalNativeCaptureContext<'_>,
        allocation: &super::super::endpoint::OriginalNativeCaptureAllocationOwned12<'_>,
        storage: &crate::connection::OriginalContinuationPrefixStorageData,
        maximum_counter_bytes: usize,
    ) -> Result<crate::connection::NativeOwned14AfterProtocolCapacityFacts, ProviderError> {
        if self.state != PrefixState::Prepared {
            return Err(ProviderError::Conflict(
                "capture startup native14 after preflight phase",
            ));
        }
        let Some(CaptureTransport::Prepared(exchange)) = self.transport.as_ref() else {
            return Err(ProviderError::Conflict(
                "capture startup native14 original window absent",
            ));
        };
        exchange.preflight_native_owned14_after_protocol_capacity(
            after,
            blobs,
            context,
            allocation,
            storage,
            maximum_counter_bytes,
        )
    }

    pub(crate) fn preflight_owned15_after_protocol_capacity(
        &self,
        after: &mut crate::protocol_snapshot::ProtocolSnapshotReservation,
        blobs: &crate::blob::BlobReceiver,
        context: &super::super::service::OriginalNativeCaptureContext<'_>,
        allocation: &super::super::endpoint::OriginalNativeCaptureAllocationOwned12<'_>,
        storage: &crate::connection::OriginalContinuationPrefixStorageData,
        maximum_counter_bytes: usize,
    ) -> Result<crate::connection::NativeOwned14AfterProtocolCapacityFacts, ProviderError> {
        if self.state != PrefixState::Prepared {
            return Err(ProviderError::Conflict(
                "capture startup invocation15 after preflight phase",
            ));
        }
        let Some(CaptureTransport::Prepared(exchange)) = self.transport.as_ref() else {
            return Err(ProviderError::Conflict(
                "capture startup native14 original window absent",
            ));
        };
        exchange.preflight_native_owned15_after_protocol_capacity(
            after,
            blobs,
            context,
            allocation,
            storage,
            maximum_counter_bytes,
        )
    }
}
