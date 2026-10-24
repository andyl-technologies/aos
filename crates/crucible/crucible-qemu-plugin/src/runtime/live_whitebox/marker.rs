//! Shared-memory marker publication for the live white-box adapter.

use crucible_qemu_shmem::{RingHeader, SpscRingError, WhiteboxMarkerEntry};

use crate::{
    WhiteboxDoorbellDecodeDiagnostic, WhiteboxMarker, WhiteboxMarkerSink, WhiteboxMarkerSinkError,
};

/// Pinned raw producer view of one ABI-validated white-box marker ring.
#[derive(Debug)]
pub(crate) struct LiveWhiteboxMarkerShmemProducer {
    header: *const RingHeader,
    entries: *mut WhiteboxMarkerEntry,
    capacity: usize,
}

impl LiveWhiteboxMarkerShmemProducer {
    /// Builds a producer retained by the process-lifetime callback owner.
    ///
    /// # Safety
    ///
    /// `header` and the `capacity` entries starting at `entries` must remain
    /// mapped, aligned, and exclusively producer-owned until the callback owner
    /// is destroyed. The host may access them only as the SPSC consumer.
    pub(crate) unsafe fn from_raw_parts(
        header: *const RingHeader,
        entries: *mut WhiteboxMarkerEntry,
        capacity: usize,
    ) -> Self {
        Self {
            header,
            entries,
            capacity,
        }
    }

    fn ring_parts(&mut self) -> (&RingHeader, &mut [WhiteboxMarkerEntry]) {
        // SAFETY: construction requires both raw ranges to remain valid and
        // producer-exclusive. Single-threaded RR serializes trap callbacks.
        unsafe {
            (
                &*self.header,
                std::slice::from_raw_parts_mut(self.entries, self.capacity),
            )
        }
    }

    pub(super) fn record(
        &mut self,
        tick_ps: u64,
        vcpu_index: u32,
        kind: u16,
        payload: &[u8],
    ) -> Result<(), WhiteboxMarkerSinkError> {
        let entry = WhiteboxMarkerEntry::new(tick_ps, vcpu_index, kind, payload)
            .map_err(WhiteboxMarkerSinkError::from_entry_validation)?;
        let (header, entries) = self.ring_parts();
        header
            .enqueue_whitebox_marker(entries, entry)
            .map_err(|error| {
                if matches!(error, SpscRingError::QueueFull { .. }) {
                    WhiteboxMarkerSinkError::from_static("live white-box marker queue is full")
                } else {
                    WhiteboxMarkerSinkError::from_static(
                        "live white-box marker queue rejected an entry",
                    )
                }
            })
    }
}

pub(super) struct LiveMarkerSink {
    pub(super) output: LiveWhiteboxMarkerShmemProducer,
    callback_coordinate: Option<(u64, u64)>,
}

impl LiveMarkerSink {
    pub(super) const fn new(output: LiveWhiteboxMarkerShmemProducer) -> Self {
        Self {
            output,
            callback_coordinate: None,
        }
    }

    pub(super) fn bind_callback_coordinate(&mut self, raw_icount: u64, tick_ps: u64) {
        self.callback_coordinate = Some((raw_icount, tick_ps));
    }

    pub(super) fn clear_callback_coordinate(&mut self) {
        self.callback_coordinate = None;
    }

    fn tick_for_raw_marker(&self, marker_raw_icount: u64) -> Result<u64, WhiteboxMarkerSinkError> {
        match self.callback_coordinate {
            Some((raw_icount, tick_ps)) if raw_icount == marker_raw_icount => Ok(tick_ps),
            Some(_) => Err(WhiteboxMarkerSinkError::from_static(
                "white-box marker raw coordinate differs from its callback",
            )),
            None => Err(WhiteboxMarkerSinkError::from_static(
                "white-box marker has no observed simulation coordinate",
            )),
        }
    }
}

impl WhiteboxMarkerSink for LiveMarkerSink {
    fn record_whitebox_marker(
        &mut self,
        marker: &WhiteboxMarker,
    ) -> Result<(), WhiteboxMarkerSinkError> {
        let tick_ps = self.tick_for_raw_marker(marker.marker_icount())?;
        self.output.record(
            tick_ps,
            marker.vcpu_index(),
            marker.kind(),
            marker.payload(),
        )
    }

    fn record_whitebox_decode_diagnostic(
        &mut self,
        _diagnostic: &WhiteboxDoorbellDecodeDiagnostic,
    ) -> Result<(), WhiteboxMarkerSinkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_fixed_refusal(error: WhiteboxMarkerSinkError, message: &str) {
        assert_eq!(error.message(), message);

        let copied = error.clone();
        assert_eq!(copied, error);
        assert_eq!(copied.message().as_ptr(), error.message().as_ptr());
        assert_eq!(
            error.to_string(),
            format!("white-box marker sink failed: {message}")
        );
    }

    #[test]
    fn live_marker_sink_requires_matching_observed_tick() {
        let header = RingHeader::new();
        let mut entries = vec![WhiteboxMarkerEntry::default()];
        // SAFETY: the test retains the ring storage for the sink's full lifetime.
        let output = unsafe {
            LiveWhiteboxMarkerShmemProducer::from_raw_parts(
                std::ptr::from_ref(&header),
                entries.as_mut_ptr(),
                entries.len(),
            )
        };
        let mut sink = LiveMarkerSink::new(output);
        assert_fixed_refusal(
            sink.tick_for_raw_marker(100).unwrap_err(),
            "white-box marker has no observed simulation coordinate",
        );

        sink.bind_callback_coordinate(100, 1_000_037);
        assert_eq!(sink.tick_for_raw_marker(100), Ok(1_000_037));
        assert_fixed_refusal(
            sink.tick_for_raw_marker(101).unwrap_err(),
            "white-box marker raw coordinate differs from its callback",
        );

        sink.clear_callback_coordinate();
        assert_fixed_refusal(
            sink.tick_for_raw_marker(100).unwrap_err(),
            "white-box marker has no observed simulation coordinate",
        );
    }

    #[test]
    fn live_marker_producer_publishes_exact_entry_to_shmem() {
        let header = RingHeader::new();
        let mut entries = vec![WhiteboxMarkerEntry::default(); 4];
        {
            // SAFETY: the test-owned header and entry array outlive the producer,
            // and no other producer accesses them.
            let mut producer = unsafe {
                LiveWhiteboxMarkerShmemProducer::from_raw_parts(
                    std::ptr::from_ref(&header),
                    entries.as_mut_ptr(),
                    entries.len(),
                )
            };

            if let Err(error) = producer.record(913, 2, 4, b"MARK") {
                panic!("live marker producer should enqueue: {error}");
            }
        }

        let entry = match header.dequeue_whitebox_marker(&entries) {
            Ok(Some(entry)) => entry,
            Ok(None) => panic!("live marker ring should contain one entry"),
            Err(error) => panic!("live marker ring should dequeue: {error}"),
        };
        assert_eq!(entry.current_icount(), 913);
        assert_eq!(entry.vcpu_index(), 2);
        assert_eq!(entry.kind(), 4);
        assert_eq!(entry.payload(), b"MARK");
        assert_eq!(entry.validate(), Ok(entry));
    }

    #[test]
    fn live_marker_producer_fails_loud_when_queue_is_full() {
        let header = RingHeader::new();
        let mut entries = vec![WhiteboxMarkerEntry::default(); 2];
        // SAFETY: the test-owned header and entry array outlive the producer,
        // and no other producer accesses them.
        let mut producer = unsafe {
            LiveWhiteboxMarkerShmemProducer::from_raw_parts(
                std::ptr::from_ref(&header),
                entries.as_mut_ptr(),
                entries.len(),
            )
        };

        if let Err(error) = producer.record(1, 0, 4, b"a") {
            panic!("first marker should enqueue: {error}");
        }
        if let Err(error) = producer.record(2, 0, 4, b"b") {
            panic!("second marker should enqueue: {error}");
        }
        let error = match producer.record(3, 0, 4, b"c") {
            Ok(()) => panic!("full marker ring must reject a third entry"),
            Err(error) => error,
        };
        assert_fixed_refusal(error, "live white-box marker queue is full");

        assert_eq!(
            header
                .dequeue_whitebox_marker(&entries)
                .unwrap()
                .unwrap()
                .payload(),
            b"a"
        );
        assert_eq!(
            header
                .dequeue_whitebox_marker(&entries)
                .unwrap()
                .unwrap()
                .payload(),
            b"b"
        );
        assert_eq!(header.dequeue_whitebox_marker(&entries).unwrap(), None);
    }

    #[test]
    fn live_marker_producer_rejects_invalid_capacity_without_publishing() {
        let header = RingHeader::new();
        let mut entries = [WhiteboxMarkerEntry::default(); 3];
        // SAFETY: the entire deliberately invalid-capacity slice is mapped and
        // producer-exclusive. The real ring validator must reject its geometry.
        let mut producer = unsafe {
            LiveWhiteboxMarkerShmemProducer::from_raw_parts(
                std::ptr::from_ref(&header),
                entries.as_mut_ptr(),
                entries.len(),
            )
        };

        let error = producer.record(3, 0, 4, b"c").unwrap_err();
        assert_fixed_refusal(error, "live white-box marker queue rejected an entry");

        assert_eq!(header.dequeue_whitebox_marker(&entries[..2]).unwrap(), None);
    }

    #[test]
    fn live_marker_producer_retains_oversize_cause_without_publishing() {
        let header = RingHeader::new();
        let mut entries = [WhiteboxMarkerEntry::default(); 2];
        let payload = [0_u8; crucible_qemu_shmem::MAX_FRAME_DATA + 1];
        // SAFETY: the test owns both mapped ranges through the producer's use.
        let mut producer = unsafe {
            LiveWhiteboxMarkerShmemProducer::from_raw_parts(
                std::ptr::from_ref(&header),
                entries.as_mut_ptr(),
                entries.len(),
            )
        };

        let error = producer.record(9, 3, 4, &payload).unwrap_err();
        let expected =
            crucible_qemu_shmem::WhiteboxMarkerEntryError::PayloadLengthExceedsCapacity {
                len: payload.len(),
                capacity: crucible_qemu_shmem::MAX_FRAME_DATA,
            };
        assert_eq!(error.entry_validation_source(), Some(&expected));
        assert_eq!(error.clone().entry_validation_source(), Some(&expected));
        assert_eq!(header.dequeue_whitebox_marker(&entries).unwrap(), None);

        producer.record(10, 3, 4, b"valid").unwrap();
        let published = header.dequeue_whitebox_marker(&entries).unwrap().unwrap();
        assert_eq!(published.current_icount(), 10);
        assert_eq!(published.payload(), b"valid");
        assert_eq!(header.dequeue_whitebox_marker(&entries).unwrap(), None);
    }
}
