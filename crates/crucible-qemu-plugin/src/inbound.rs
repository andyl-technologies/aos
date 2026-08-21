//! Inbound frame polling and deterministic injection ordering.
//!
//! The plugin consumes shared-memory SPSC rings owned by executor subnodes. It
//! peeks without consuming, dequeues only due frames, sorts them by their in-band
//! delivery key, and fails loudly behind the idle-pass delivery floor.

use thiserror::Error;

use crucible_shmem::{
    FrameDeliveryKey, FrameDeliveryState, FrameDeliveryStateError, FrameEntry, RingHeader,
    SpscRingError,
};

use crate::shmem_ordering::PluginShmemOrdering;

mod commit;

/// A plugin-owned view of one inbound SPSC ring.
#[derive(Clone, Copy)]
pub struct InboundFrameRing<'a> {
    ring_index: u32,
    header: &'a RingHeader,
    entries: &'a [FrameEntry],
}

impl<'a> InboundFrameRing<'a> {
    /// Builds an inbound ring view from a shared header and backing entries.
    #[must_use]
    pub const fn new(ring_index: u32, header: &'a RingHeader, entries: &'a [FrameEntry]) -> Self {
        Self {
            ring_index,
            header,
            entries,
        }
    }

    /// Returns the shared-memory ring index used in diagnostics.
    #[must_use]
    pub const fn ring_index(self) -> u32 {
        self.ring_index
    }

    /// Returns the shared SPSC ring header.
    #[must_use]
    pub const fn header(self) -> &'a RingHeader {
        self.header
    }

    /// Returns the ring's frame-entry backing storage.
    #[must_use]
    pub const fn entries(self) -> &'a [FrameEntry] {
        self.entries
    }
}

/// A deterministic batch of inbound frames ready for guest injection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundFrameBatch {
    current_icount: u64,
    frames: Vec<FrameEntry>,
}

impl InboundFrameBatch {
    /// Returns the consumer icount used for this drain.
    #[must_use]
    pub const fn current_icount(&self) -> u64 {
        self.current_icount
    }

    /// Returns frames in `(delivery_icount, src_node, seq)` injection order.
    #[must_use]
    pub fn frames(&self) -> &[FrameEntry] {
        &self.frames
    }

    /// Consumes the batch and returns its ordered frames.
    #[must_use]
    pub fn into_frames(self) -> Vec<FrameEntry> {
        self.frames
    }
}

/// Plugin-side inbound frame operations.
#[derive(Debug)]
pub struct PluginInboundFrames;

impl PluginInboundFrames {
    /// Peeks the earliest unattempted delivery icount across inbound ring heads.
    ///
    /// A retained head has already reached its exact delivery boundary and must
    /// not hold the guest at that past coordinate: guest progress is what can
    /// release NIC backpressure. Its whole FIFO is therefore excluded from the
    /// next-wake calculation until the retained head transfers. This method
    /// never consumes a ring entry.
    ///
    /// # Errors
    ///
    /// Returns [`InboundFrameError::RingOperation`] when any ring header reports
    /// invalid capacity or corrupt indices.
    pub fn peek_next_delivery_icount<'a>(
        rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
    ) -> Result<Option<u64>, InboundFrameError> {
        let mut next_delivery: Option<u64> = None;
        for ring in rings {
            if let Some(frame) = peek_head_frame(ring)?
                && delivery_state(&frame)? == FrameDeliveryState::Pending
            {
                let delivery = frame.delivery_icount;
                next_delivery = Some(match next_delivery {
                    Some(current) => current.min(delivery),
                    None => delivery,
                });
            }
        }
        Ok(next_delivery)
    }

    /// Fails if an unretained inbound ring head is already behind
    /// `consumer_current_icount`.
    ///
    /// The check is non-consuming, which lets the idle path reject a scheduler
    /// overshoot before advancing QEMU virtual time.
    ///
    /// # Errors
    ///
    /// Returns [`InboundFrameError::RingOperation`] for invalid ring state, or
    /// [`InboundFrameError::DeliveryAlreadyPassed`] when a head frame's delivery
    /// icount is less than the consumer's current icount.
    pub fn reject_already_passed_ring_heads<'a>(
        rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
        consumer_current_icount: u64,
    ) -> Result<(), InboundFrameError> {
        for ring in rings {
            let head = peek_head_frame(ring)?;
            if let Some(frame) = head
                && frame.delivery_icount < consumer_current_icount
                && delivery_state(&frame)? != FrameDeliveryState::Retained
            {
                return Err(InboundFrameError::DeliveryAlreadyPassed {
                    ring_index: Some(ring.ring_index),
                    consumer_current_icount,
                    frame: frame.delivery_key(),
                });
            }
        }
        Ok(())
    }

    /// Drains every inbound frame due at `consumer_current_icount`.
    ///
    /// This exact-current variant treats frames behind `consumer_current_icount`
    /// as already passed. Idle-jump callers should use
    /// [`Self::drain_deliverable_since`] so frames in the jumped-over window are
    /// injected at the deterministic wake icount.
    ///
    /// # Errors
    ///
    /// Returns [`InboundFrameError::RingOperation`] for invalid ring state,
    /// [`InboundFrameError::DeliveryAlreadyPassed`] for a late ring head, or
    /// [`InboundFrameError::DequeuedUnexpectedDelivery`] if a dequeued frame no
    /// longer matches the peeked due head.
    pub fn drain_deliverable<'a>(
        rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
        consumer_current_icount: u64,
    ) -> Result<InboundFrameBatch, InboundFrameError> {
        Self::drain_deliverable_since(rings, consumer_current_icount, consumer_current_icount)
    }

    /// Previews every inbound frame deliverable in the current idle pass.
    ///
    /// Frames with `delivery_icount < passed_delivery_floor_icount` are late and
    /// fail loudly. Frames with `delivery_icount <= consumer_current_icount` are
    /// returned without consuming the SPSC ring so callers can queue them into QEMU
    /// before committing the shared-memory read index. Future heads remain queued.
    ///
    /// # Errors
    ///
    /// Returns [`InboundFrameError::InvalidDeliveryWindow`] when the delivery floor
    /// is after the current icount, [`InboundFrameError::RingOperation`] for
    /// invalid ring state, or [`InboundFrameError::DeliveryAlreadyPassed`] for a
    /// frame whose delivery icount is behind the idle-pass floor.
    pub fn preview_deliverable_since<'a>(
        rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
        consumer_current_icount: u64,
        passed_delivery_floor_icount: u64,
    ) -> Result<InboundFrameBatch, InboundFrameError> {
        if passed_delivery_floor_icount > consumer_current_icount {
            return Err(InboundFrameError::InvalidDeliveryWindow {
                passed_delivery_floor_icount,
                consumer_current_icount,
            });
        }

        let mut frames = Vec::new();
        for ring in rings {
            frames.extend(collect_ring_deliverable_since(
                ring,
                consumer_current_icount,
                passed_delivery_floor_icount,
            )?);
        }

        frames.sort_by_key(FrameEntry::delivery_key);
        Ok(InboundFrameBatch {
            current_icount: consumer_current_icount,
            frames,
        })
    }

    /// Marks the exact live head retained after real guest backpressure.
    ///
    /// # Errors
    ///
    /// Returns [`InboundFrameError::RetainedHeadMismatch`] when the expected
    /// frame is not the unique current head, or
    /// [`InboundFrameError::InvalidDeliveryState`] for an unknown shared state.
    pub fn mark_retained_head<'a>(
        rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
        expected: FrameDeliveryKey,
    ) -> Result<(), InboundFrameError> {
        let mut matching = None;
        for ring in rings {
            if peek_head_frame(ring)?.is_some_and(|frame| frame.delivery_key() == expected) {
                if matching.is_some() {
                    return Err(InboundFrameError::RetainedHeadMismatch {
                        expected,
                        actual: None,
                    });
                }
                matching = Some(ring);
            }
        }
        let Some(ring) = matching else {
            return Err(InboundFrameError::RetainedHeadMismatch {
                expected,
                actual: None,
            });
        };
        let slot = (PluginShmemOrdering::consumer_read_index(ring.header)
            & (ring.entries.len() as u64 - 1)) as usize;
        let actual = ring.entries[slot].delivery_key();
        if actual != expected {
            return Err(InboundFrameError::RetainedHeadMismatch {
                expected,
                actual: Some(actual),
            });
        }
        ring.entries[slot]
            .mark_delivery_retained()
            .map_err(|source| map_delivery_state_error(expected, source))
    }

    /// Drains every inbound frame deliverable in the current idle pass.
    ///
    /// The delivery window is
    /// `passed_delivery_floor_icount..=consumer_current_icount`. This models an
    /// idle jump: frames that became due in the jumped-over window are consumed and
    /// injected at the deterministic wake icount, while frames older than the
    /// floor fail loudly.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::preview_deliverable_since`], plus
    /// [`InboundFrameError::DequeuedUnexpectedDelivery`] if a dequeued entry no
    /// longer matches the previewed due frame.
    pub fn drain_deliverable_since<'a>(
        rings: impl IntoIterator<Item = InboundFrameRing<'a>>,
        consumer_current_icount: u64,
        passed_delivery_floor_icount: u64,
    ) -> Result<InboundFrameBatch, InboundFrameError> {
        if passed_delivery_floor_icount > consumer_current_icount {
            return Err(InboundFrameError::InvalidDeliveryWindow {
                passed_delivery_floor_icount,
                consumer_current_icount,
            });
        }

        let mut frames = Vec::new();
        for ring in rings {
            let due_frames = collect_ring_deliverable_since(
                ring,
                consumer_current_icount,
                passed_delivery_floor_icount,
            )?;
            for expected in due_frames {
                let Some(frame) =
                    PluginShmemOrdering::dequeue_inbound_frame(ring.header, ring.entries)
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
                if frame.delivery_key() != expected.delivery_key() {
                    return Err(InboundFrameError::DequeuedUnexpectedDelivery {
                        ring_index: ring.ring_index,
                        expected: expected.delivery_key(),
                        actual: frame.delivery_key(),
                    });
                }
                frames.push(frame);
            }
        }

        frames.sort_by_key(FrameEntry::delivery_key);
        Ok(InboundFrameBatch {
            current_icount: consumer_current_icount,
            frames,
        })
    }

    /// Selects already-materialized frames ready at `consumer_current_icount`.
    ///
    /// This helper keeps test-double and callback-adapter paths on the same
    /// fail-loud ordering rule as real shared-memory rings.
    ///
    /// # Errors
    ///
    /// Returns [`InboundFrameError::DeliveryAlreadyPassed`] when a frame's
    /// delivery icount is less than `consumer_current_icount`.
    pub fn select_deliverable_frames(
        frames: impl IntoIterator<Item = FrameEntry>,
        consumer_current_icount: u64,
    ) -> Result<Vec<FrameEntry>, InboundFrameError> {
        Self::select_deliverable_frames_since(
            frames,
            consumer_current_icount,
            consumer_current_icount,
        )
    }

    /// Selects materialized frames deliverable in the current idle pass.
    ///
    /// # Errors
    ///
    /// Returns [`InboundFrameError::InvalidDeliveryWindow`] when the delivery floor
    /// is after the current icount, or [`InboundFrameError::DeliveryAlreadyPassed`]
    /// when a frame's delivery icount is less than `passed_delivery_floor_icount`.
    pub fn select_deliverable_frames_since(
        frames: impl IntoIterator<Item = FrameEntry>,
        consumer_current_icount: u64,
        passed_delivery_floor_icount: u64,
    ) -> Result<Vec<FrameEntry>, InboundFrameError> {
        if passed_delivery_floor_icount > consumer_current_icount {
            return Err(InboundFrameError::InvalidDeliveryWindow {
                passed_delivery_floor_icount,
                consumer_current_icount,
            });
        }

        let mut deliverable = Vec::new();
        let mut retained_head_authorizes_backlog = false;
        for (index, frame) in frames.into_iter().enumerate() {
            let state = delivery_state(&frame)?;
            if index == 0 && state == FrameDeliveryState::Retained {
                retained_head_authorizes_backlog = true;
            } else if state == FrameDeliveryState::Retained {
                return Err(InboundFrameError::RetainedHeadMismatch {
                    expected: frame.delivery_key(),
                    actual: deliverable.first().map(FrameEntry::delivery_key),
                });
            }
            if frame.delivery_icount < passed_delivery_floor_icount
                && !retained_head_authorizes_backlog
            {
                return Err(InboundFrameError::DeliveryAlreadyPassed {
                    ring_index: None,
                    consumer_current_icount,
                    frame: frame.delivery_key(),
                });
            }
            if frame.delivery_icount <= consumer_current_icount {
                deliverable.push(frame);
            }
        }
        deliverable.sort_by_key(FrameEntry::delivery_key);
        Ok(deliverable)
    }
}

/// An error produced while polling or draining inbound frame rings.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum InboundFrameError {
    /// An SPSC ring operation failed.
    #[error("inbound ring {ring_index} operation failed: {source}")]
    RingOperation {
        /// The shared-memory ring index.
        ring_index: u32,
        /// The underlying ring error.
        source: SpscRingError,
    },
    /// A frame became visible only after the consumer had passed its delivery icount.
    #[error(
        "inbound frame {frame:?} from ring {ring_index:?} is already behind consumer icount {consumer_current_icount}"
    )]
    DeliveryAlreadyPassed {
        /// The shared-memory ring index, if the frame came from a real ring.
        ring_index: Option<u32>,
        /// The consumer icount observed while polling or draining.
        consumer_current_icount: u64,
        /// The late frame's deterministic delivery key.
        frame: FrameDeliveryKey,
    },
    /// A dequeued frame did not match the previously peeked due delivery.
    #[error("inbound ring {ring_index} dequeued frame {actual:?} after peeking {expected:?}")]
    DequeuedUnexpectedDelivery {
        /// The shared-memory ring index.
        ring_index: u32,
        /// The head frame key observed before dequeue.
        expected: FrameDeliveryKey,
        /// The dequeued frame key.
        actual: FrameDeliveryKey,
    },
    /// The caller supplied an impossible delivery window.
    #[error(
        "inbound delivery floor {passed_delivery_floor_icount} is after consumer icount {consumer_current_icount}"
    )]
    InvalidDeliveryWindow {
        /// The earliest delivery icount still considered valid for this idle pass.
        passed_delivery_floor_icount: u64,
        /// The consumer icount observed while polling or draining.
        consumer_current_icount: u64,
    },
    /// A shared frame carries a delivery state unknown to this ABI version.
    #[error("inbound frame {frame:?} has invalid delivery state {state}")]
    InvalidDeliveryState {
        /// The affected deterministic frame key.
        frame: FrameDeliveryKey,
        /// The rejected shared-memory state byte.
        state: u8,
    },
    /// The frame reported backpressured is no longer the unique ring head.
    #[error("retained inbound head mismatch: expected {expected:?}, actual {actual:?}")]
    RetainedHeadMismatch {
        /// The frame whose guest delivery returned backpressure.
        expected: FrameDeliveryKey,
        /// A different head, when one was available.
        actual: Option<FrameDeliveryKey>,
    },
    /// A post-injection commit did not consume the same batch that was previewed.
    #[error("inbound commit consumed {actual:?} after previewing {expected:?}")]
    CommittedBatchMismatch {
        /// The deterministic delivery keys queued into QEMU before commit.
        expected: Vec<FrameDeliveryKey>,
        /// The deterministic delivery keys consumed from shared memory during commit.
        actual: Vec<FrameDeliveryKey>,
    },
}

fn map_ring_error(ring: InboundFrameRing<'_>, source: SpscRingError) -> InboundFrameError {
    InboundFrameError::RingOperation {
        ring_index: ring.ring_index,
        source,
    }
}

fn peek_head_frame(ring: InboundFrameRing<'_>) -> Result<Option<FrameEntry>, InboundFrameError> {
    let Some(delivery_icount) =
        PluginShmemOrdering::peek_inbound_delivery_icount(ring.header, ring.entries)
            .map_err(|source| map_ring_error(ring, source))?
    else {
        return Ok(None);
    };

    let slot = (PluginShmemOrdering::consumer_read_index(ring.header)
        & (ring.entries.len() as u64 - 1)) as usize;
    let frame = ring.entries[slot].clone();
    if frame.delivery_icount != delivery_icount {
        return Err(InboundFrameError::DequeuedUnexpectedDelivery {
            ring_index: ring.ring_index,
            expected: FrameDeliveryKey {
                delivery_icount,
                src_node: frame.src_node,
                seq: frame.seq,
            },
            actual: frame.delivery_key(),
        });
    }
    Ok(Some(frame))
}

fn collect_ring_deliverable_since(
    ring: InboundFrameRing<'_>,
    consumer_current_icount: u64,
    passed_delivery_floor_icount: u64,
) -> Result<Vec<FrameEntry>, InboundFrameError> {
    let capacity = inbound_ring_capacity(ring)?;
    let read_idx = PluginShmemOrdering::consumer_read_index(ring.header);
    let write_idx = PluginShmemOrdering::producer_write_index(ring.header);
    let live = inbound_live_count(ring, read_idx, write_idx, capacity)?;
    let mut frames = Vec::new();
    let mut retained_head_authorizes_backlog = false;

    for offset in 0..live {
        let slot = ((read_idx.wrapping_add(offset)) & (capacity - 1)) as usize;
        let frame = ring.entries[slot].clone();
        let state = delivery_state(&frame)?;
        if offset == 0 && state == FrameDeliveryState::Retained {
            retained_head_authorizes_backlog = true;
        } else if state == FrameDeliveryState::Retained {
            return Err(InboundFrameError::RetainedHeadMismatch {
                expected: frame.delivery_key(),
                actual: frames.first().map(FrameEntry::delivery_key),
            });
        }
        if frame.delivery_icount < passed_delivery_floor_icount && !retained_head_authorizes_backlog
        {
            return Err(InboundFrameError::DeliveryAlreadyPassed {
                ring_index: Some(ring.ring_index),
                consumer_current_icount,
                frame: frame.delivery_key(),
            });
        }
        if frame.delivery_icount > consumer_current_icount {
            break;
        }
        frames.push(frame);
    }

    Ok(frames)
}

fn delivery_state(frame: &FrameEntry) -> Result<FrameDeliveryState, InboundFrameError> {
    frame
        .delivery_state()
        .map_err(|source| map_delivery_state_error(frame.delivery_key(), source))
}

fn map_delivery_state_error(
    frame: FrameDeliveryKey,
    source: FrameDeliveryStateError,
) -> InboundFrameError {
    match source {
        FrameDeliveryStateError::UnknownState { state } => {
            InboundFrameError::InvalidDeliveryState { frame, state }
        }
    }
}

fn inbound_ring_capacity(ring: InboundFrameRing<'_>) -> Result<u64, InboundFrameError> {
    if ring.entries.is_empty() || !ring.entries.len().is_power_of_two() {
        Err(map_ring_error(
            ring,
            SpscRingError::InvalidCapacity {
                capacity: ring.entries.len(),
            },
        ))
    } else {
        Ok(ring.entries.len() as u64)
    }
}

fn inbound_live_count(
    ring: InboundFrameRing<'_>,
    read_idx: u64,
    write_idx: u64,
    capacity: u64,
) -> Result<u64, InboundFrameError> {
    let live = write_idx
        .checked_sub(read_idx)
        .ok_or_else(|| corrupt_indices(ring, read_idx, write_idx, capacity))?;
    if live > capacity {
        Err(corrupt_indices(ring, read_idx, write_idx, capacity))
    } else {
        Ok(live)
    }
}

fn corrupt_indices(
    ring: InboundFrameRing<'_>,
    read_idx: u64,
    write_idx: u64,
    capacity: u64,
) -> InboundFrameError {
    map_ring_error(
        ring,
        SpscRingError::CorruptIndices {
            read_idx,
            write_idx,
            capacity,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_frame_peek_uses_minimum_head_delivery_without_consuming() {
        let ring_a = RingHeader::new();
        let ring_b = RingHeader::new();
        let mut entries_a = empty_entries();
        let mut entries_b = empty_entries();
        enqueue(&ring_a, &mut entries_a, frame(30, 1, 0, b"a"));
        enqueue(&ring_b, &mut entries_b, frame(12, 2, 0, b"b"));

        assert_eq!(
            PluginInboundFrames::peek_next_delivery_icount([
                InboundFrameRing::new(0, &ring_a, &entries_a),
                InboundFrameRing::new(1, &ring_b, &entries_b),
            ]),
            Ok(Some(12))
        );
        assert_eq!(ring_a.read_index(), 0);
        assert_eq!(ring_b.read_index(), 0);
    }

    #[test]
    fn inbound_frame_drain_delivers_current_icount_in_total_order() {
        let ring_a = RingHeader::new();
        let ring_b = RingHeader::new();
        let mut entries_a = empty_entries();
        let mut entries_b = empty_entries();
        enqueue(&ring_a, &mut entries_a, frame(20, 9, 4, b"third"));
        enqueue(&ring_a, &mut entries_a, frame(20, 1, 7, b"first"));
        enqueue(&ring_b, &mut entries_b, frame(20, 4, 1, b"second"));
        enqueue(&ring_b, &mut entries_b, frame(25, 0, 0, b"future"));

        let batch = match PluginInboundFrames::drain_deliverable(
            [
                InboundFrameRing::new(4, &ring_a, &entries_a),
                InboundFrameRing::new(5, &ring_b, &entries_b),
            ],
            20,
        ) {
            Ok(batch) => batch,
            Err(error) => panic!("current inbound frames should drain: {error}"),
        };

        assert_eq!(batch.current_icount(), 20);
        assert_eq!(
            batch
                .frames()
                .iter()
                .map(FrameEntry::delivery_key)
                .collect::<Vec<_>>(),
            vec![
                frame(20, 1, 7, b"first").delivery_key(),
                frame(20, 4, 1, b"second").delivery_key(),
                frame(20, 9, 4, b"third").delivery_key(),
            ]
        );
        assert_eq!(ring_a.read_index(), 2);
        assert_eq!(ring_b.read_index(), 1);
        assert_eq!(
            PluginInboundFrames::peek_next_delivery_icount([
                InboundFrameRing::new(4, &ring_a, &entries_a),
                InboundFrameRing::new(5, &ring_b, &entries_b),
            ]),
            Ok(Some(25))
        );
    }

    #[test]
    fn inbound_frame_drain_since_includes_jumped_over_delivery_window() {
        let ring_a = RingHeader::new();
        let ring_b = RingHeader::new();
        let mut entries_a = empty_entries();
        let mut entries_b = empty_entries();
        enqueue(&ring_a, &mut entries_a, frame(12, 9, 4, b"third"));
        enqueue(&ring_a, &mut entries_a, frame(20, 1, 7, b"second"));
        enqueue(&ring_b, &mut entries_b, frame(15, 4, 1, b"first"));
        enqueue(&ring_b, &mut entries_b, frame(25, 4, 2, b"future"));

        let preview = match PluginInboundFrames::preview_deliverable_since(
            [
                InboundFrameRing::new(4, &ring_a, &entries_a),
                InboundFrameRing::new(5, &ring_b, &entries_b),
            ],
            20,
            10,
        ) {
            Ok(batch) => batch,
            Err(error) => panic!("jump-window inbound frames should preview: {error}"),
        };
        assert_eq!(ring_a.read_index(), 0);
        assert_eq!(ring_b.read_index(), 0);
        assert_eq!(
            preview
                .frames()
                .iter()
                .map(FrameEntry::delivery_key)
                .collect::<Vec<_>>(),
            vec![
                frame(12, 9, 4, b"third").delivery_key(),
                frame(15, 4, 1, b"first").delivery_key(),
                frame(20, 1, 7, b"second").delivery_key(),
            ]
        );

        let batch = match PluginInboundFrames::drain_deliverable_since(
            [
                InboundFrameRing::new(4, &ring_a, &entries_a),
                InboundFrameRing::new(5, &ring_b, &entries_b),
            ],
            20,
            10,
        ) {
            Ok(batch) => batch,
            Err(error) => panic!("jump-window inbound frames should drain: {error}"),
        };

        assert_eq!(batch.current_icount(), 20);
        assert_eq!(batch.frames(), preview.frames());
        assert_eq!(ring_a.read_index(), 2);
        assert_eq!(ring_b.read_index(), 1);
        assert_eq!(
            PluginInboundFrames::peek_next_delivery_icount([
                InboundFrameRing::new(4, &ring_a, &entries_a),
                InboundFrameRing::new(5, &ring_b, &entries_b),
            ]),
            Ok(Some(25))
        );
    }

    #[test]
    fn inbound_frame_drain_rejects_late_head_without_consuming() {
        let ring = RingHeader::new();
        let mut entries = empty_entries();
        enqueue(&ring, &mut entries, frame(19, 7, 2, b"late"));

        assert_eq!(
            PluginInboundFrames::drain_deliverable([InboundFrameRing::new(9, &ring, &entries)], 20),
            Err(InboundFrameError::DeliveryAlreadyPassed {
                ring_index: Some(9),
                consumer_current_icount: 20,
                frame: frame(19, 7, 2, b"late").delivery_key(),
            })
        );
        assert_eq!(ring.read_index(), 0);
    }

    #[test]
    fn inbound_frame_drain_since_rejects_before_floor_without_consuming() {
        let ring = RingHeader::new();
        let mut entries = empty_entries();
        enqueue(&ring, &mut entries, frame(9, 7, 2, b"late"));

        assert_eq!(
            PluginInboundFrames::drain_deliverable_since(
                [InboundFrameRing::new(9, &ring, &entries)],
                20,
                10,
            ),
            Err(InboundFrameError::DeliveryAlreadyPassed {
                ring_index: Some(9),
                consumer_current_icount: 20,
                frame: frame(9, 7, 2, b"late").delivery_key(),
            })
        );
        assert_eq!(ring.read_index(), 0);
    }

    #[test]
    fn inbound_retained_head_authorizes_blocked_fifo_backlog() {
        let ring = RingHeader::new();
        let mut entries = empty_entries();
        let retained = frame(8, 7, 2, b"retained");
        let successor = frame(9, 7, 3, b"successor");
        enqueue(&ring, &mut entries, retained.clone());
        enqueue(&ring, &mut entries, successor.clone());

        PluginInboundFrames::mark_retained_head(
            [InboundFrameRing::new(9, &ring, &entries)],
            retained.delivery_key(),
        )
        .unwrap_or_else(|error| panic!("live head should become retained: {error}"));
        let batch = PluginInboundFrames::preview_deliverable_since(
            [InboundFrameRing::new(9, &ring, &entries)],
            20,
            10,
        )
        .unwrap_or_else(|error| panic!("retained backlog should remain deliverable: {error}"));

        assert_eq!(
            batch
                .frames()
                .iter()
                .map(FrameEntry::delivery_key)
                .collect::<Vec<_>>(),
            vec![retained.delivery_key(), successor.delivery_key()]
        );
        assert_eq!(
            batch.frames()[0].delivery_state(),
            Ok(FrameDeliveryState::Retained)
        );
        assert_eq!(
            PluginInboundFrames::peek_next_delivery_icount([InboundFrameRing::new(
                9, &ring, &entries,
            )]),
            Ok(None)
        );
        assert_eq!(ring.read_index(), 0);
    }

    #[test]
    fn inbound_rejects_retained_marker_away_from_ring_head() {
        let ring = RingHeader::new();
        let mut entries = empty_entries();
        let head = frame(10, 7, 2, b"head");
        let invalid = frame(11, 7, 3, b"invalid");
        invalid
            .mark_delivery_retained()
            .unwrap_or_else(|error| panic!("test marker should set: {error}"));
        enqueue(&ring, &mut entries, head.clone());
        enqueue(&ring, &mut entries, invalid.clone());

        assert_eq!(
            PluginInboundFrames::preview_deliverable_since(
                [InboundFrameRing::new(9, &ring, &entries)],
                20,
                10,
            ),
            Err(InboundFrameError::RetainedHeadMismatch {
                expected: invalid.delivery_key(),
                actual: Some(head.delivery_key()),
            })
        );
        assert_eq!(ring.read_index(), 0);
    }

    #[test]
    fn inbound_frame_select_rejects_late_candidate_frame() {
        assert_eq!(
            PluginInboundFrames::select_deliverable_frames([frame(7, 1, 1, b"late")], 8),
            Err(InboundFrameError::DeliveryAlreadyPassed {
                ring_index: None,
                consumer_current_icount: 8,
                frame: frame(7, 1, 1, b"late").delivery_key(),
            })
        );
    }

    #[test]
    fn inbound_frame_ring_errors_are_fail_loud() {
        let ring = RingHeader::new();
        let entries = vec![FrameEntry::default(); 3];

        assert_eq!(
            PluginInboundFrames::peek_next_delivery_icount([InboundFrameRing::new(
                11, &ring, &entries
            )]),
            Err(InboundFrameError::RingOperation {
                ring_index: 11,
                source: SpscRingError::InvalidCapacity { capacity: 3 },
            })
        );
    }

    fn empty_entries() -> Vec<FrameEntry> {
        vec![FrameEntry::default(); 4]
    }

    fn enqueue(header: &RingHeader, entries: &mut [FrameEntry], frame: FrameEntry) {
        if let Err(error) = PluginShmemOrdering::enqueue_outbound_frame(header, entries, &frame) {
            panic!("test frame should enqueue: {error}");
        }
    }

    fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
        match FrameEntry::new(delivery_icount, src_node, seq, payload) {
            Ok(frame) => frame,
            Err(error) => panic!("test frame should fit: {error}"),
        }
    }
}
