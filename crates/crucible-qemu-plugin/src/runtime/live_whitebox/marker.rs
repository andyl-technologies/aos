//! Shared-memory marker publication for the live white-box adapter.

use crucible_shmem::{RingHeader, SpscRingError, WhiteboxMarkerEntry};

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
            .map_err(|error| WhiteboxMarkerSinkError::new(error.to_string()))?;
        let (header, entries) = self.ring_parts();
        header
            .enqueue_whitebox_marker(entries, entry)
            .map_err(|error| {
                if matches!(error, SpscRingError::QueueFull { .. }) {
                    WhiteboxMarkerSinkError::new("live white-box marker queue is full")
                } else {
                    WhiteboxMarkerSinkError::new("live white-box marker queue rejected an entry")
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
            Some(_) => Err(WhiteboxMarkerSinkError::new(
                "white-box marker raw coordinate differs from its callback",
            )),
            None => Err(WhiteboxMarkerSinkError::new(
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
        assert!(sink.tick_for_raw_marker(100).is_err());

        sink.bind_callback_coordinate(100, 1_000_037);
        assert_eq!(sink.tick_for_raw_marker(100), Ok(1_000_037));
        assert!(sink.tick_for_raw_marker(101).is_err());

        sink.clear_callback_coordinate();
        assert!(sink.tick_for_raw_marker(100).is_err());
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
        assert!(error.message().contains("queue is full"));
    }
}
