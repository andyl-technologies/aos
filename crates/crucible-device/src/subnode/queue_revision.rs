//! Checked persistent queue transactions and lossless request refusal.
//!
//! Revisions identify actual queue-owner changes across observation, checkpoint
//! and replay. They grant no native execution or stopped-source authority.

use super::*;

/// An enqueue refusal that retains the original unconsumed request.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("I/O request was not enqueued: {source}")]
pub struct IoRequestEnqueueFailure {
    /// Original request returned unchanged for an authorized retry or cleanup.
    pub request: Request,
    /// Full queue or exhausted queue-owner revision that prevented enqueue.
    pub source: DeviceError,
}

impl IoRequestEnqueueFailure {
    /// Returns the original request retained by this pre-enqueue refusal.
    #[must_use]
    pub fn into_item(self) -> Request {
        self.request
    }
}

impl IoCore {
    /// Returns the actual retained revision of the complete queue owner.
    #[must_use]
    pub const fn queue_revision(&self) -> NonZeroU64 {
        self.queue_revision
    }

    pub(crate) fn check_queue_revision_capacity(
        &self,
        transactions: usize,
    ) -> Result<(), DeviceError> {
        let transactions =
            u64::try_from(transactions).map_err(|_| DeviceError::IoQueueRevisionExhausted)?;
        self.queue_revision
            .get()
            .checked_add(transactions)
            .ok_or(DeviceError::IoQueueRevisionExhausted)?;
        Ok(())
    }

    pub(crate) fn check_queue_rewrite_capacity(
        &self,
        responses: &[PendingResponse],
        subsequent: usize,
    ) -> Result<(), DeviceError> {
        let transactions = subsequent
            .checked_add(usize::from(self.inflight.entries() != responses))
            .ok_or(DeviceError::IoQueueRevisionExhausted)?;
        self.check_queue_revision_capacity(transactions)
    }

    pub(super) fn next_queue_revision(&self) -> Result<NonZeroU64, DeviceError> {
        self.queue_revision
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(DeviceError::IoQueueRevisionExhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AffineLatency, ResponseStatus};

    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| panic!("queue revision fixture: {error:?}"))
    }

    #[derive(Default)]
    struct Echo {
        computed: usize,
    }

    impl IoSubNode for Echo {
        type Latency = AffineLatency;
        type ComputeCheckpoint = usize;

        fn latency_model(&self) -> &AffineLatency {
            &AffineLatency {
                base_ns: 0,
                per_byte_ns: 0,
            }
        }

        fn compute_checkpoint(&self) -> usize {
            self.computed
        }

        fn restore_compute_checkpoint(&mut self, checkpoint: usize) {
            self.computed = checkpoint;
        }

        fn compute(&mut self, request: &Request) -> Result<ComputedResponse, DeviceError> {
            self.computed += 1;
            Ok(ComputedResponse::primary(Response::new(
                request.request_id,
                ResponseStatus::Ok,
                request.payload.clone(),
            )))
        }
    }

    fn pending() -> IoCore {
        let mut core = ok(IoCore::new(71, 4, 4));
        ok(core.enqueue_request(Request::new(10, 3, b"pending".to_vec())));
        ok(core.process_inbox(&mut Echo::default()));
        core
    }

    #[test]
    fn actual_queue_changes_advance_revision_without_changing_original_delivery_key() {
        let mut core = ok(IoCore::new(71, 4, 4));
        let initial = core.queue_revision();
        ok(core.enqueue_request(Request::new(10, 3, b"pending".to_vec())));
        assert!(core.queue_revision() > initial);
        let arrived = core.queue_revision();
        ok(core.process_inbox(&mut Echo::default()));
        assert!(core.queue_revision() > arrived);
        let computed = core.queue_revision();
        let key = core.snapshot().inflight[0].key;

        ok(core.advance_to(9));
        assert_eq!(core.queue_revision(), computed);
        assert_eq!(ok(core.advance_to(10)), 1);
        assert!(core.queue_revision() > computed);
        let published = core.queue_revision();
        let response = ok(core.pop_response()).unwrap_or_else(|| panic!("delivered reply missing"));
        assert_eq!(response.key, key);
        assert!(core.queue_revision() > published);
        let consumed = core.queue_revision();
        assert!(ok(core.pop_response()).is_none());
        ok(core.advance_to(20));
        assert_eq!(core.queue_revision(), consumed);
    }

    #[test]
    fn repeated_canonical_restore_retains_pending_keys_and_exact_queue_revision() {
        let core = pending();
        let original = core.snapshot();
        let bytes = ok(original.canonical_bytes());
        let first = ok(IoCore::restore(&ok(IoCoreSnapshot::from_canonical_bytes(
            &bytes,
        ))));
        let second = ok(IoCore::restore(&ok(IoCoreSnapshot::from_canonical_bytes(
            &ok(first.snapshot().canonical_bytes()),
        ))));
        assert_eq!(second.snapshot(), original);
        assert_eq!(second.queue_revision(), core.queue_revision());
        assert_eq!(second.snapshot().inflight[0].key, original.inflight[0].key);
    }

    #[test]
    fn exhausted_revision_refuses_enqueue_compute_discard_and_publication_before_effects() {
        let mut snapshot = pending().snapshot();
        snapshot.queue_revision = NonZeroU64::MAX;
        let mut core = ok(IoCore::restore(&snapshot));
        let original = core.snapshot();
        let ring = RingHeader::new();
        let mut frames = vec![FrameEntry::default(); 4];
        let consumer = NodeSlot::new(crucible_shmem::KIND_VM);
        let failure = core
            .advance_to_shmem_with_commit_status(10, &ring, &mut frames, &consumer)
            .err()
            .unwrap_or_else(|| panic!("exhausted publication accepted"));
        assert_eq!(failure.published, 0);
        assert_eq!(failure.source, DeviceError::IoQueueRevisionExhausted);
        assert_eq!(core.snapshot(), original);
        assert!(ok(ring.dequeue(&frames)).is_none());
        let request = Request::new(10, 4, b"retained".to_vec());
        let failure = core
            .enqueue_request(request.clone())
            .err()
            .unwrap_or_else(|| panic!("exhausted enqueue accepted"));
        assert_eq!(failure.request, request);
        assert_eq!(failure.source, DeviceError::IoQueueRevisionExhausted);
        let mut device = Echo::default();
        assert_eq!(
            core.compute_request(&mut device, request),
            Err(DeviceError::IoQueueRevisionExhausted)
        );
        assert_eq!(device.computed, 0);
        assert_eq!(
            core.discard_inflight(),
            Err(DeviceError::IoQueueRevisionExhausted)
        );
        assert_eq!(
            core.advance_to(10),
            Err(DeviceError::IoQueueRevisionExhausted)
        );
        assert_eq!(core.snapshot(), original);
    }

    #[test]
    fn version_five_requires_nonzero_revision_and_rejects_previous_queue_format() {
        let mut bytes = ok(pending().snapshot().canonical_bytes());
        let offset = b"crucible.io-core-snapshot.v5\0".len() + 20;
        bytes[offset..offset + 8].fill(0);
        assert_eq!(
            IoCoreSnapshot::from_canonical_bytes(&bytes),
            Err(IoCoreSnapshotCodecError::Invalid("zero queue revision"))
        );
        let mut old = ok(pending().snapshot().canonical_bytes());
        old[b"crucible.io-core-snapshot.v".len()] = b'4';
        assert_eq!(
            IoCoreSnapshot::from_canonical_bytes(&old),
            Err(IoCoreSnapshotCodecError::Version)
        );
    }
}
