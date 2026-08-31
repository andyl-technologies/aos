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

#[test]
fn paused_restore_discards_only_the_queued_coverage_generation() {
    let ring = RingHeader::new();
    let mut entries = vec![CoverageEntry::default(); 8];
    for map_index in 0..4 {
        let entry = CoverageEntry::new(100 + map_index, 0, 0x4000, 4, map_index)
            .unwrap_or_else(|error| panic!("coverage entry should build: {error}"));
        ring.enqueue_coverage(&mut entries, entry)
            .unwrap_or_else(|error| panic!("coverage entry should enqueue: {error}"));
    }
    let consumed = ring
        .dequeue_coverage(&entries)
        .unwrap_or_else(|error| panic!("coverage entry should dequeue: {error}"));
    assert!(consumed.is_some());
    assert_eq!(ring.read_index(), 1);
    assert_eq!(ring.write_index(), 4);

    let cursor = ring
        .discard_coverage_at_restore(&entries)
        .unwrap_or_else(|error| panic!("paused generation should discard: {error}"));
    assert_eq!(cursor, 1);
    assert_eq!(ring.read_index(), 1);
    assert_eq!(ring.write_index(), 1);
    assert_eq!(
        ring.dequeue_coverage(&entries)
            .unwrap_or_else(|error| panic!("reset ring should remain valid: {error}")),
        None
    );

    let replacement = CoverageEntry::new(900, 1, 0x5000, 8, 7)
        .unwrap_or_else(|error| panic!("replacement entry should build: {error}"));
    ring.enqueue_coverage(&mut entries, replacement)
        .unwrap_or_else(|error| panic!("replacement entry should enqueue: {error}"));
    assert_eq!(ring.read_index(), 1);
    assert_eq!(ring.write_index(), 2);
    assert_eq!(
        ring.dequeue_coverage(&entries)
            .unwrap_or_else(|error| panic!("replacement entry should dequeue: {error}")),
        Some(replacement)
    );
}
