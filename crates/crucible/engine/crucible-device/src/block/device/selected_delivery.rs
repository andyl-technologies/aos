//! Exact response publication and associated block-reset commitment.

use super::*;
use crate::{FrameDeliveryKey, SelectedDeliveryOutcome, ShmemDeliveryFailure};

impl BlockDevice {
    /// Advances authorized private storage phases without publishing replies.
    ///
    /// # Errors
    ///
    /// Rejects unresolved opportunities, regressing service state or bounded
    /// arithmetic before replacing any live device state.
    pub fn prepare_delivery_at(&mut self, at: u64) -> Result<(), DeviceError> {
        self.advance_storage_service_before_admission(at)
    }

    /// Publishes one exact computed response without waking the guest.
    ///
    /// Private service phases must already be prepared before selection. This
    /// method does not advance them or clone the entire device. A transport
    /// reset is validated before publication and committed only with its own
    /// selected response. Other replies remain queued, including any
    /// dispositions the reset must apply to them.
    ///
    /// # Errors
    ///
    /// Returns a truthful publication count for invalid source selection,
    /// malformed resets, exhausted queue revisions or ring failures.
    /// A failure after publication retains the consumed response and reset
    /// state; callers must contain it rather than publish that key again.
    pub fn deliver_selected_to_shmem(
        &mut self,
        at: u64,
        selected: FrameDeliveryKey,
        expected_payload: &[u8],
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
    ) -> Result<SelectedDeliveryOutcome, ShmemDeliveryFailure> {
        let before = |source| ShmemDeliveryFailure {
            published: 0,
            source,
        };
        let head = self
            .core
            .next_pending_response()
            .ok_or_else(|| before(DeviceError::SelectedResponseMismatch { key: selected }))?;
        if head.key != selected
            || selected.delivery_icount != at
            || head.response.payload != expected_payload
        {
            return Err(before(DeviceError::SelectedResponseMismatch {
                key: selected,
            }));
        }
        let decoded = BlockResponse::decode(&head.response.payload)
            .map_err(DeviceError::Codec)
            .map_err(before)?;
        let reset = if decoded.status == BlockStatus::TransportReset {
            let directive = decoded
                .transport_reset_directive()
                .map_err(DeviceError::Codec)
                .map_err(before)?;
            Some(
                Self::prepare_transport_reset(
                    &self.core,
                    &self.storage_faults,
                    head,
                    directive,
                    at,
                )
                .map_err(before)?,
            )
        } else {
            None
        };

        let outcome = self.core.deliver_selected_to_shmem(
            at,
            selected,
            expected_payload,
            outbox,
            outbox_entries,
        )?;
        if outcome == SelectedDeliveryOutcome::Backpressured {
            return Ok(outcome);
        }

        // Publication cannot be rolled back. Retain all resulting state even
        // if a post-publication reset commitment reports an invariant failure.
        if let Some(reset) = reset {
            Self::commit_transport_reset(&mut self.core, &mut self.storage_faults, reset).map_err(
                |source| ShmemDeliveryFailure {
                    published: 1,
                    source,
                },
            )?;
        }
        Ok(outcome)
    }
}
