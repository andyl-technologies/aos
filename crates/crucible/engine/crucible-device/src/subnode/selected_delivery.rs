//! Exact queue-selected response publication without a consumer wake.
//!
//! This primitive checks device evidence only. Its operational caller must hold
//! and independently authenticate the native fixed-GRID input boundary before
//! selecting a completion and publishing the flags-only notification afterward.

use super::*;

/// Truthful disposition of one exact device-queue publication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedDeliveryOutcome {
    /// One response was release-published and removed from the owned queue.
    Published,
    /// No response was published; the exact queued response remains available.
    Backpressured,
}

impl IoCore {
    /// Publishes exactly the selected queue head at its authentic delivery tick.
    ///
    /// The key and payload must match the current retained queue head. No other
    /// due response is drained, and this method never changes a RUN ceiling or
    /// wakes the consumer. Publication is final even if a later notification
    /// fails; the caller must retain that outcome rather than retry this frame.
    ///
    /// # Errors
    ///
    /// Rejects a missing, different, past/future or reordered selected response,
    /// regressing device clock, invalid frame or corrupt ring. Every returned
    /// failure reports zero publication; ring-full backpressure retains the
    /// response and returns [`SelectedDeliveryOutcome::Backpressured`].
    pub fn deliver_selected_to_shmem(
        &mut self,
        at: u64,
        selected: FrameDeliveryKey,
        expected_payload: &[u8],
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
    ) -> Result<SelectedDeliveryOutcome, ShmemDeliveryFailure> {
        let refusal = || ShmemDeliveryFailure {
            published: 0,
            source: DeviceError::SelectedResponseMismatch { key: selected },
        };
        let pending = self.inflight.entries().first().ok_or_else(refusal)?;
        if pending.key != selected
            || selected.delivery_icount != at
            || pending.response.payload != expected_payload
        {
            return Err(refusal());
        }
        let frame =
            frame_from_pending_response(pending).map_err(|source| ShmemDeliveryFailure {
                published: 0,
                source,
            })?;
        let revision = self
            .next_queue_revision()
            .map_err(|source| ShmemDeliveryFailure {
                published: 0,
                source,
            })?;
        let mut published_clock = self.clock;
        published_clock
            .advance_to(at)
            .map_err(|source| ShmemDeliveryFailure {
                published: 0,
                source,
            })?;

        // Retain the moved response locally until enqueue commits. This has no
        // callback or shared effect and permits exact restoration on refusal.
        let pending = self.inflight.pop_selected(selected).ok_or_else(refusal)?;
        match outbox.enqueue(outbox_entries, &frame) {
            Ok(()) => {
                self.clock = published_clock;
                self.queue_revision = revision;
                Ok(SelectedDeliveryOutcome::Published)
            }
            Err(SpscRingError::QueueFull { .. }) => {
                self.inflight.insert(pending);
                Ok(SelectedDeliveryOutcome::Backpressured)
            }
            Err(error) => {
                self.inflight.insert(pending);
                Err(ShmemDeliveryFailure {
                    published: 0,
                    source: DeviceError::from(error),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AffineLatency, ResponseStatus};

    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| panic!("selected-delivery fixture: {error:?}"))
    }

    struct Echo;

    impl IoSubNode for Echo {
        type Latency = AffineLatency;
        type ComputeCheckpoint = ();

        fn latency_model(&self) -> &AffineLatency {
            &AffineLatency {
                base_ns: 0,
                per_byte_ns: 0,
            }
        }

        fn compute_checkpoint(&self) {}

        fn restore_compute_checkpoint(&mut self, _checkpoint: ()) {}

        fn compute(&mut self, request: &Request) -> Result<ComputedResponse, DeviceError> {
            Ok(ComputedResponse::primary(Response::new(
                request.request_id,
                ResponseStatus::Ok,
                request.payload.clone(),
            )))
        }
    }

    fn computed() -> IoCore {
        let mut core = ok(IoCore::new(37, 4, 4));
        for request_id in [21, 22, 23] {
            ok(core.enqueue_request(Request::new(9, request_id, b"same".to_vec())));
        }
        ok(core.process_inbox(&mut Echo));
        core
    }

    #[test]
    fn only_the_exact_computed_key_is_published_without_bulk_drain() {
        let mut core = computed();
        let original = core.inflight.entries().to_vec();
        let ring = RingHeader::new();
        let mut entries = vec![FrameEntry::default(); 4];

        let outcome =
            ok(core.deliver_selected_to_shmem(9, original[0].key, b"same", &ring, &mut entries));

        assert_eq!(outcome, SelectedDeliveryOutcome::Published);
        assert_eq!(core.inflight.entries(), &original[1..]);
        let frame = ok(ring.dequeue(&entries)).unwrap_or_else(|| panic!("published frame missing"));
        assert_eq!(frame.delivery_icount, original[0].key.delivery_icount);
        assert_eq!(frame.src_node, original[0].key.src_node);
        assert_eq!(frame.seq, original[0].key.seq);
        assert!(ok(ring.dequeue(&entries)).is_none());
    }

    #[test]
    fn equal_payload_does_not_authorize_reordered_wrong_or_future_selection() {
        let mut core = computed();
        let original = core.snapshot();
        let ring = RingHeader::new();
        let mut entries = vec![FrameEntry::default(); 4];
        let first = core.inflight.entries()[0].key;
        let second = core.inflight.entries()[1].key;
        for (at, key, payload) in [
            (9, second, b"same".as_slice()),
            (9, first, b"wrong".as_slice()),
            (10, first, b"same".as_slice()),
        ] {
            let failure = core
                .deliver_selected_to_shmem(at, key, payload, &ring, &mut entries)
                .err()
                .unwrap_or_else(|| panic!("invalid selection accepted"));
            assert_eq!(failure.published, 0);
            assert_eq!(core.snapshot(), original);
            assert!(ok(ring.dequeue(&entries)).is_none());
        }
    }

    #[test]
    fn ring_full_retains_exact_key_and_success_cannot_be_republished() {
        let mut core = computed();
        let original = core.inflight.entries().to_vec();
        let ring = RingHeader::new();
        let mut entries = vec![FrameEntry::default(); 1];
        ok(ring.enqueue(&mut entries, &ok(FrameEntry::new(0, 1, 99, b"occupied"))));

        assert_eq!(
            ok(core.deliver_selected_to_shmem(9, original[0].key, b"same", &ring, &mut entries)),
            SelectedDeliveryOutcome::Backpressured
        );
        assert_eq!(core.inflight.entries(), &original);
        assert_eq!(core.clock.current_icount(), 0);
        assert!(ok(ring.dequeue(&entries)).is_some());
        assert_eq!(
            ok(core.deliver_selected_to_shmem(9, original[0].key, b"same", &ring, &mut entries)),
            SelectedDeliveryOutcome::Published
        );
        assert!(
            core.deliver_selected_to_shmem(9, original[0].key, b"same", &ring, &mut entries)
                .is_err()
        );
        assert_eq!(core.inflight.entries(), &original[1..]);
        assert!(ok(ring.dequeue(&entries)).is_some());
        assert!(ok(ring.dequeue(&entries)).is_none());
    }

    #[test]
    fn repeated_actual_queue_restore_preserves_source_keys_and_selection() {
        let original = computed();
        let encoded = ok(original.snapshot().canonical_bytes());
        let keys = original
            .inflight
            .entries()
            .iter()
            .map(|pending| pending.key)
            .collect::<Vec<_>>();
        for _ in 0..2 {
            let snapshot = ok(IoCoreSnapshot::from_canonical_bytes(&encoded));
            let mut restored = ok(IoCore::restore(&snapshot));
            let ring = RingHeader::new();
            let mut entries = vec![FrameEntry::default(); 4];
            for key in &keys {
                assert_eq!(
                    ok(restored.deliver_selected_to_shmem(9, *key, b"same", &ring, &mut entries)),
                    SelectedDeliveryOutcome::Published
                );
                let frame =
                    ok(ring.dequeue(&entries)).unwrap_or_else(|| panic!("restored frame missing"));
                assert_eq!(
                    (frame.delivery_icount, frame.src_node, frame.seq),
                    (key.delivery_icount, key.src_node, key.seq)
                );
            }
            assert_eq!(restored.inflight_len(), 0);
        }
    }

    #[test]
    fn exhausted_revision_refuses_selected_publication_before_queue_or_ring_effects() {
        let mut core = computed();
        core.queue_revision = std::num::NonZeroU64::new(u64::MAX)
            .unwrap_or_else(|| panic!("nonzero fixture revision"));
        let before = core.snapshot();
        let selected = before.inflight[0].key;
        let ring = RingHeader::new();
        let mut entries = vec![FrameEntry::default(); 4];

        let failure = core
            .deliver_selected_to_shmem(9, selected, b"same", &ring, &mut entries)
            .err()
            .unwrap_or_else(|| panic!("exhausted revision published a selected frame"));

        assert_eq!(failure.published, 0);
        assert_eq!(failure.source, DeviceError::IoQueueRevisionExhausted);
        assert_eq!(core.snapshot(), before);
        assert!(ok(ring.dequeue(&entries)).is_none());
    }
}
