//! Fixed-capacity coverage-ring FIFO and overflow checks.

use super::*;

pub(super) fn assert_coverage_ring_fifo_and_fails_loud_at_fixed_capacity() {
    let ring = RingHeader::new();
    let mut entries = vec![CoverageEntry::default(); COVERAGE_QUEUE_CAPACITY as usize];
    for map_index in 0..u64::from(COVERAGE_QUEUE_CAPACITY) {
        let entry = CoverageEntry::new(map_index, 0, 0x4000 + map_index, 4, map_index)
            .unwrap_or_else(|error| panic!("fixed-capacity coverage entry should build: {error}"));
        ring.enqueue_coverage(&mut entries, entry)
            .unwrap_or_else(|error| panic!("distinct coverage novelty should enqueue: {error}"));
    }
    let overflow = CoverageEntry::new(99, 0, 0x9000, 4, 0)
        .unwrap_or_else(|error| panic!("overflow probe should build: {error}"));
    assert_eq!(
        ring.enqueue_coverage(&mut entries, overflow),
        Err(SpscRingError::QueueFull {
            capacity: u64::from(COVERAGE_QUEUE_CAPACITY),
        })
    );
    for expected_index in 0..u64::from(COVERAGE_QUEUE_CAPACITY) {
        let observed = ring
            .dequeue_coverage(&entries)
            .unwrap_or_else(|error| panic!("coverage dequeue should succeed: {error}"))
            .unwrap_or_else(|| panic!("coverage entry {expected_index} should remain queued"));
        assert_eq!(observed.map_index(), expected_index);
        assert_eq!(observed.current_icount(), expected_index);
    }
    assert_eq!(
        ring.dequeue_coverage(&entries)
            .unwrap_or_else(|error| panic!("empty coverage dequeue should succeed: {error}")),
        None
    );
}
