//! Canonical shared-memory ownership commit for delivered inbound frames.

use crucible_shmem::{FrameDeliveryKey, FrameEntry};

use crate::shmem_ordering::PluginShmemOrdering;

use super::{
    InboundFrameBatch, InboundFrameError, InboundFrameRing, PluginInboundFrames, map_ring_error,
    peek_head_frame,
};

impl PluginInboundFrames {
    /// Commits an exact delivered prefix while leaving backpressured frames queued.
    ///
    /// Each expected frame must be the current head of exactly one supplied
    /// ring when it is committed. This lets the guest-delivery backend transfer
    /// ownership frame by frame while shared memory remains canonical for the
    /// first retained frame and every successor.
    ///
    /// # Errors
    ///
    /// Returns [`InboundFrameError::CommittedBatchMismatch`] when an expected
    /// frame is absent or ambiguous, and the normal ring-operation errors when
    /// a matching head cannot be dequeued safely.
    pub fn commit_delivered_prefix<'a>(
        rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
        consumer_current_icount: u64,
        expected_frames: &[FrameEntry],
    ) -> Result<InboundFrameBatch, InboundFrameError> {
        let rings = rings.into_iter().collect::<Vec<_>>();
        let expected_keys = expected_frames
            .iter()
            .map(FrameEntry::delivery_key)
            .collect::<Vec<_>>();
        let mut committed = Vec::with_capacity(expected_frames.len());

        for expected in expected_frames {
            let mut matching_ring = None;
            for ring in &rings {
                if peek_head_frame(*ring)?.as_ref() == Some(expected) {
                    if matching_ring.is_some() {
                        return Err(InboundFrameError::CommittedBatchMismatch {
                            expected: expected_keys,
                            actual: committed.iter().map(FrameEntry::delivery_key).collect(),
                        });
                    }
                    matching_ring = Some(*ring);
                }
            }

            let Some(ring) = matching_ring else {
                return Err(InboundFrameError::CommittedBatchMismatch {
                    expected: expected_keys,
                    actual: committed.iter().map(FrameEntry::delivery_key).collect(),
                });
            };
            let Some(frame) = PluginShmemOrdering::dequeue_inbound_frame(ring.header, ring.entries)
                .map_err(|source| map_ring_error(ring, source))?
            else {
                return Err(InboundFrameError::DequeuedUnexpectedDelivery {
                    ring_index: ring.ring_index,
                    expected: expected.delivery_key(),
                    actual: FrameDeliveryKey {
                        delivery_icount: consumer_current_icount,
                        src_node: 0,
                        seq: 0,
                    },
                });
            };
            if frame != *expected {
                return Err(InboundFrameError::DequeuedUnexpectedDelivery {
                    ring_index: ring.ring_index,
                    expected: expected.delivery_key(),
                    actual: frame.delivery_key(),
                });
            }
            committed.push(frame);
        }

        Ok(InboundFrameBatch {
            current_icount: consumer_current_icount,
            frames: committed,
        })
    }
}
