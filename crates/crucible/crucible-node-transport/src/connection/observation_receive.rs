//! Fences first-Observe receiver quotation at an actual idle correlation cut.

use super::*;

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn ensure_original_observation_receiver_idle_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.authority.ensure_live()?;
        if self.role != EndpointRole::Controller || self.fenced {
            return Err(ProviderError::Correlation(
                "first Observe receiver is not the same idle Controller",
            ));
        }
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)
    }

    /// Bounds literal history and numeric state at a successful SDK settled cut.
    ///
    /// This quotes the actual immutable lifetime literal-bank geometry. It
    /// grants no suffix slots, transport credit or future completed-cut claim.
    pub(crate) fn capture_history_encoded_growth_data(&self) -> Result<usize, ProviderError> {
        self.ensure_original_observation_receiver_idle_data()?;
        if self.native5_blobs.is_some()
            || self.original_restore_inputs.is_some()
            || self.original_restore_responses.iter().any(Option::is_some)
            || self.original_complete_restoration.is_some()
            || self.original_canonical_ack_admission.is_some()
        {
            return Err(ProviderError::Correlation(
                "SDK Capture encoding has unsupported native Connection owners",
            ));
        }
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "SDK Capture encoding literal bank absent",
            ))?;
        let bank = bank
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("SDK Capture encoding literal bank borrowed"))?;
        // A complete successful cut keeps the three correlation maps empty.
        // Their keys/Envelopes are not an invisible retained journal. Persistent
        // request/response history belongs to ClientCustody's two maps instead.
        let (literals, descriptors) = bank.maximum_encoding_growth(true)?;
        // CurrentConnection.frames incoming/outgoing and reader.last_original_slot
        // use usize decimals; the guard's two sequence counters use quoted U64.
        literals
            .checked_add(descriptors)
            .and_then(|n| n.checked_add(3 * 20 + 2 * 22))
            .ok_or(ProviderError::ResourceExhausted(
                "SDK Capture transport encoding",
            ))
    }

    pub(crate) fn capture_history_encoding_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<
                std::cell::Ref<
                    'static,
                    crate::transport::original_frames::OriginalFrameReservation,
                >,
            >()
            + std::mem::size_of::<
                Result<
                    std::cell::Ref<
                        'static,
                        crate::transport::original_frames::OriginalFrameReservation,
                    >,
                    std::cell::BorrowError,
                >,
            >()
            + std::mem::size_of::<Result<(usize, usize), ProviderError>>()
            + std::mem::size_of::<[u8; 128]>()
            + crate::connection::original_serialized_credit_counter_scratch_data()
    }
}
