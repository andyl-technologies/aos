//! Checks `gate:layer1-injection` SPSC concurrency coverage.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};

use crucible_shmem::{
    COVERAGE_QUEUE_CAPACITY, CoverageEntry, FrameEntry, RingHeader, SpscRingError, SpscRingSnapshot,
};

const RING_SOURCE: &str = concat!(
    include_str!("../src/lib.rs"),
    include_str!("../src/shmem/region.rs"),
    include_str!("../src/shmem/ring_coverage.rs"),
    include_str!("../src/shmem/frame_node.rs"),
    include_str!("../src/shmem/delivery_errors.rs"),
);
const RANDOM_PROPERTY_SEEDS: &[u64] = &[
    0x4352_5543_4942_4c45,
    0x5350_5343_0000_0001,
    0x5350_5343_0000_0002,
    0x5350_5343_0000_0003,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SpscProperty {
    NoLostFrame,
    NoDuplicatedFrame,
    FifoOrder,
    NoTornFrame,
    NoEarlyRead,
    FullEmpty,
    Wraparound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoomStep {
    ProducerWriteFrame,
    ProducerReleaseWriteIndex,
    ConsumerAcquireWriteIndex,
    ConsumerReadFrame,
    ConsumerReadFrameForFree,
    ConsumerReleaseReadIndex,
    ProducerAcquireReadIndex,
    ProducerOverwriteFrame,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelOrdering {
    Relaxed,
    Acquire,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RingOrderings {
    producer_read_idx_load: ModelOrdering,
    producer_write_idx_store: ModelOrdering,
    consumer_write_idx_load: ModelOrdering,
    consumer_read_idx_store: ModelOrdering,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ModelFailure {
    TornFrameAfterPublishedWriteIndex,
    ProducerOverwriteBeforeConsumerReadIsOrdered,
}

#[derive(Clone, Debug)]
struct LoomState {
    failures: BTreeSet<ModelFailure>,
    delivered: Vec<FrameEntry>,
}

#[derive(Clone, Copy, Debug)]
struct SeededPropertyRng {
    state: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedInjection {
    producer_host_tick: u64,
    delivery_icounts: Vec<u64>,
}

#[test]
fn gate_layer1_injection_checks_spsc_ring_concurrency_properties() {
    assert_ring_header_source_uses_rfc_13_6_orderings();
    assert_spsc_ring_loom_model(&[
        SpscProperty::NoLostFrame,
        SpscProperty::NoDuplicatedFrame,
        SpscProperty::FifoOrder,
        SpscProperty::NoTornFrame,
        SpscProperty::NoEarlyRead,
    ]);
    assert_spsc_ring_proptest_properties(&[
        SpscProperty::NoLostFrame,
        SpscProperty::NoDuplicatedFrame,
        SpscProperty::FifoOrder,
        SpscProperty::FullEmpty,
        SpscProperty::Wraparound,
    ]);
    assert_coverage_ring_fifo_and_fails_loud_at_fixed_capacity();

    let producer_skewed = run_two_vm_injection(&[7, 1, 9], false);
    let consumer_skewed = run_two_vm_injection(&[1, 7, 9], false);
    assert_eq!(producer_skewed, consumer_skewed);

    let producer_skewed = run_two_vm_injection(&[7, 1, 9], true);
    let consumer_skewed = run_two_vm_injection(&[1, 7, 9], true);
    assert_ne!(producer_skewed, consumer_skewed);
}

fn assert_spsc_ring_loom_model(required: &[SpscProperty]) {
    let required = required.iter().copied().collect::<BTreeSet<_>>();
    assert!(required.contains(&SpscProperty::NoLostFrame));
    assert!(required.contains(&SpscProperty::NoDuplicatedFrame));
    assert!(required.contains(&SpscProperty::FifoOrder));
    assert!(required.contains(&SpscProperty::NoTornFrame));
    assert!(required.contains(&SpscProperty::NoEarlyRead));

    let rfc_orderings = RingOrderings::rfc_13_6();
    let failures = model_check_publish_before_read(rfc_orderings);
    assert!(
        failures.is_empty(),
        "RFC 13.6 publish/acquire ordering admitted failures: {failures:?}"
    );
    let failures = model_check_free_before_overwrite(rfc_orderings);
    assert!(
        failures.is_empty(),
        "RFC 13.6 free/acquire ordering admitted failures: {failures:?}"
    );

    let relaxed_everywhere = RingOrderings::relaxed_everywhere();
    let relaxed_everywhere_negative_control_failed =
        model_check_publish_before_read(relaxed_everywhere)
            .contains(&ModelFailure::TornFrameAfterPublishedWriteIndex)
            && model_check_free_before_overwrite(relaxed_everywhere)
                .contains(&ModelFailure::ProducerOverwriteBeforeConsumerReadIsOrdered);
    assert!(relaxed_everywhere_negative_control_failed);

    let missing_consumer_acquire_negative_control_failed =
        model_check_publish_before_read(RingOrderings {
            consumer_write_idx_load: ModelOrdering::Relaxed,
            ..rfc_orderings
        })
        .contains(&ModelFailure::TornFrameAfterPublishedWriteIndex);
    assert!(missing_consumer_acquire_negative_control_failed);

    let missing_producer_acquire_negative_control_failed =
        model_check_free_before_overwrite(RingOrderings {
            producer_read_idx_load: ModelOrdering::Relaxed,
            ..rfc_orderings
        })
        .contains(&ModelFailure::ProducerOverwriteBeforeConsumerReadIsOrdered);
    assert!(missing_producer_acquire_negative_control_failed);
}

fn assert_spsc_ring_proptest_properties(required: &[SpscProperty]) {
    let required = required.iter().copied().collect::<BTreeSet<_>>();
    assert!(required.contains(&SpscProperty::NoLostFrame));
    assert!(required.contains(&SpscProperty::NoDuplicatedFrame));
    assert!(required.contains(&SpscProperty::FifoOrder));
    assert!(required.contains(&SpscProperty::FullEmpty));
    assert!(required.contains(&SpscProperty::Wraparound));

    for capacity in [1_usize, 2, 4, 8] {
        assert_full_empty(capacity);
        assert_wraparound(capacity);
        for len in 0..=7 {
            let mut sequence = Vec::with_capacity(len);
            enumerate_operation_sequences(capacity, len, &mut sequence);
        }
    }

    assert_seeded_random_property_corpus();
}

fn run_two_vm_injection(host_ticks: &[u64], include_host_tick: bool) -> ObservedInjection {
    let ring = RingHeader::new();
    let mut entries = blank_entries(4);
    for seq in 0..3 {
        let delivery_icount = 100 + u64::from(seq);
        enqueue_frame(&ring, &mut entries, &frame(delivery_icount, 1, seq, b"p"));
    }

    let mut delivery_icounts = Vec::new();
    while let Some(frame) = dequeue(&ring, &entries) {
        delivery_icounts.push(frame.delivery_icount);
    }

    ObservedInjection {
        producer_host_tick: if include_host_tick { host_ticks[0] } else { 0 },
        delivery_icounts,
    }
}

fn assert_full_empty(capacity: usize) {
    let ring = RingHeader::new();
    let mut entries = blank_entries(capacity);
    for seq in 0..capacity {
        enqueue(&ring, &mut entries, seq as u32);
    }

    assert_eq!(
        ring.enqueue(&mut entries, &frame(100, 1, 999, b"full")),
        Err(SpscRingError::QueueFull {
            capacity: capacity as u64
        })
    );
    for seq in 0..capacity {
        assert_eq!(
            dequeue(&ring, &entries),
            Some(frame(10 + seq as u64, 1, seq as u32, b"p"))
        );
    }
    assert_eq!(dequeue(&ring, &entries), None);
}

fn assert_wraparound(capacity: usize) {
    let ring = RingHeader::new();
    let mut entries = blank_entries(capacity);
    let mut expected = VecDeque::new();

    for seq in 0..(capacity * 3 + 1) {
        let frame = frame(10 + seq as u64, 1, seq as u32, b"p");
        push_expected(&mut expected, frame.clone());
        enqueue_frame(&ring, &mut entries, &frame);
        assert_eq!(dequeue(&ring, &entries), expected.pop_front());
    }

    assert!(ring.write_index() > capacity as u64);
    assert_eq!(ring.read_index(), ring.write_index());
}

fn enumerate_operation_sequences(capacity: usize, remaining: usize, prefix: &mut Vec<bool>) {
    if remaining == 0 {
        assert_operation_sequence(capacity, prefix);
        return;
    }

    prefix.push(true);
    enumerate_operation_sequences(capacity, remaining - 1, prefix);
    prefix.pop();

    prefix.push(false);
    enumerate_operation_sequences(capacity, remaining - 1, prefix);
    prefix.pop();
}

fn assert_operation_sequence(capacity: usize, operations: &[bool]) {
    let ring = RingHeader::new();
    let mut entries = blank_entries(capacity);
    let mut expected = VecDeque::new();
    let mut next_seq = 0_u32;
    let mut delivered = Vec::new();

    for enqueue_op in operations {
        if *enqueue_op {
            let frame = frame(10 + u64::from(next_seq), 1, next_seq, b"p");
            match ring.enqueue(&mut entries, &frame) {
                Ok(()) => {
                    push_expected(&mut expected, frame);
                    next_seq += 1;
                }
                Err(SpscRingError::QueueFull {
                    capacity: full_capacity,
                }) => {
                    assert_eq!(full_capacity, capacity as u64);
                    assert_eq!(expected.len(), capacity);
                }
                Err(error) => panic!("unexpected enqueue error: {error}"),
            }
        } else {
            let actual = dequeue(&ring, &entries);
            let expected_frame = expected.pop_front();
            assert_eq!(actual, expected_frame);
            if let Some(actual) = actual {
                delivered.push(actual);
            }
        }

        assert_eq!(
            ring.peek_delivery_icount(&entries),
            Ok(expected.front().map(|frame| frame.delivery_icount))
        );
    }

    let snapshot = snapshot(&ring, &entries);
    assert_eq!(
        snapshot.frames,
        expected.iter().cloned().collect::<Vec<_>>()
    );
    let restored = RingHeader::new();
    let mut restored_entries = blank_entries(capacity);
    restore(&restored, &mut restored_entries, &snapshot);
    while let Some(expected_frame) = expected.pop_front() {
        assert_eq!(dequeue(&restored, &restored_entries), Some(expected_frame));
    }
    assert_eq!(dequeue(&restored, &restored_entries), None);

    let mut seen = BTreeSet::new();
    for frame in delivered {
        assert!(
            seen.insert(frame.seq),
            "duplicated delivered frame seq {}",
            frame.seq
        );
    }
}

fn assert_seeded_random_property_corpus() {
    for seed in RANDOM_PROPERTY_SEEDS {
        for capacity in [1_usize, 2, 4, 8, 16] {
            let mut rng = SeededPropertyRng::new(*seed ^ capacity as u64);
            for _case_index in 0..64 {
                let len = rng.random_inclusive(16, 96);
                let operations = random_operation_sequence(&mut rng, len);
                assert_operation_sequence(capacity, &operations);
            }
        }
    }
}

fn random_operation_sequence(rng: &mut SeededPropertyRng, len: usize) -> Vec<bool> {
    (0..len)
        .map(|_| {
            let enqueue_bias = rng.random_exclusive(100);
            enqueue_bias < 57
        })
        .collect()
}

fn assert_ring_header_source_uses_rfc_13_6_orderings() {
    assert_function_source_order(
        "pub fn enqueue_coverage(",
        &[
            "let tail = self.write_idx.load(Ordering::Relaxed);",
            "let head = self.read_idx.load(Ordering::Acquire);",
            "entries[slot] = entry;",
            ".store(tail.wrapping_add(1), Ordering::Release);",
        ],
        "coverage enqueue must write the entry before release-publishing write_idx",
    );
    assert_function_source_order(
        "pub fn enqueue(",
        &[
            "let tail = self.write_idx.load(Ordering::Relaxed);",
            "let head = self.read_idx.load(Ordering::Acquire);",
            "entries[slot] = frame.clone();",
            ".store(tail.wrapping_add(1), Ordering::Release);",
        ],
        "enqueue must write the frame before release-publishing write_idx",
    );
    assert_function_source_order(
        "pub fn peek_delivery_icount(",
        &[
            "let head = self.read_idx.load(Ordering::Relaxed);",
            "let tail = self.write_idx.load(Ordering::Acquire);",
            "if live_count(head, tail, capacity)? == 0",
            "Ok(Some(entries[slot].delivery_icount))",
        ],
        "peek_delivery_icount must acquire write_idx before reading delivery_icount",
    );
    assert_function_source_order(
        "pub fn dequeue(&self, entries: &[FrameEntry])",
        &[
            "let head = self.read_idx.load(Ordering::Relaxed);",
            "let tail = self.write_idx.load(Ordering::Acquire);",
            "if live_count(head, tail, capacity)? == 0",
            "let frame = entries[slot].clone();",
            "self.read_idx.store(head.wrapping_add(1), Ordering::Release);",
        ],
        "dequeue must acquire write_idx and reject empty before reading, then release-free read_idx",
    );
    assert_function_source_order(
        "pub fn dequeue_coverage(",
        &[
            "let head = self.read_idx.load(Ordering::Relaxed);",
            "let tail = self.write_idx.load(Ordering::Acquire);",
            "if live_count(head, tail, capacity)? == 0",
            "let entry = entries[slot];",
            "self.read_idx.store(head.wrapping_add(1), Ordering::Release);",
        ],
        "coverage dequeue must acquire write_idx before reading, then release-free read_idx",
    );
}

fn assert_coverage_ring_fifo_and_fails_loud_at_fixed_capacity() {
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

fn assert_function_source_order(signature: &str, needles: &[&str], context: &str) {
    let source = function_source(signature);
    assert_source_order(source, needles, context);
}

fn assert_source_order(source: &str, needles: &[&str], context: &str) {
    let mut offset = 0;
    for needle in needles {
        let remaining = &source[offset..];
        let Some(relative) = remaining.find(needle) else {
            panic!("{context}: missing `{needle}` after byte offset {offset}");
        };
        offset += relative + needle.len();
    }
}

fn function_source(signature: &str) -> &str {
    let Some(start) = RING_SOURCE.find(signature) else {
        panic!("missing RingHeader method signature `{signature}`");
    };
    let after_signature = &RING_SOURCE[start..];
    let Some(open_relative) = after_signature.find('{') else {
        panic!("missing body for RingHeader method signature `{signature}`");
    };
    let open = start + open_relative;
    let mut depth = 0_i32;
    for (relative, ch) in RING_SOURCE[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &RING_SOURCE[start..open + relative + ch.len_utf8()];
                }
            }
            _ => {}
        }
    }

    panic!("unterminated RingHeader method body for `{signature}`");
}

fn model_check_publish_before_read(orderings: RingOrderings) -> BTreeSet<ModelFailure> {
    let producer = [
        LoomStep::ProducerWriteFrame,
        LoomStep::ProducerReleaseWriteIndex,
    ];
    let consumer = [
        LoomStep::ConsumerAcquireWriteIndex,
        LoomStep::ConsumerReadFrame,
    ];
    let mut failures = BTreeSet::new();
    for schedule in loom_schedules(&producer, &consumer) {
        let state = run_publish_before_read_interleaving(&schedule, orderings);
        let torn_frame_after_published_write_index = state
            .failures
            .contains(&ModelFailure::TornFrameAfterPublishedWriteIndex);
        assert!(
            state.delivered.len() <= 1,
            "duplicated frame under schedule {schedule:?}"
        );
        if !torn_frame_after_published_write_index {
            assert!(
                state.delivered.is_empty()
                    || state.delivered == vec![frame(17, 3, 9, b"published")],
                "delivered frame was not the producer-written frame under {schedule:?}"
            );
        }
        failures.extend(state.failures);
    }
    failures
}

fn model_check_free_before_overwrite(orderings: RingOrderings) -> BTreeSet<ModelFailure> {
    let consumer = [
        LoomStep::ConsumerReadFrameForFree,
        LoomStep::ConsumerReleaseReadIndex,
    ];
    let producer = [
        LoomStep::ProducerAcquireReadIndex,
        LoomStep::ProducerOverwriteFrame,
    ];
    let mut failures = BTreeSet::new();
    for schedule in loom_schedules(&consumer, &producer) {
        let state = run_free_before_overwrite_interleaving(&schedule, orderings);
        failures.extend(state.failures);
    }
    failures
}

fn loom_schedules(left: &[LoomStep], right: &[LoomStep]) -> Vec<Vec<LoomStep>> {
    let mut schedules = Vec::new();
    let mut prefix = Vec::new();
    enumerate_actor_interleavings(left, right, &mut prefix, &mut schedules);
    schedules
}

fn enumerate_actor_interleavings(
    producer: &[LoomStep],
    consumer: &[LoomStep],
    prefix: &mut Vec<LoomStep>,
    schedules: &mut Vec<Vec<LoomStep>>,
) {
    if producer.is_empty() && consumer.is_empty() {
        schedules.push(prefix.clone());
        return;
    }

    if let Some((step, rest)) = producer.split_first() {
        prefix.push(*step);
        enumerate_actor_interleavings(rest, consumer, prefix, schedules);
        prefix.pop();
    }
    if let Some((step, rest)) = consumer.split_first() {
        prefix.push(*step);
        enumerate_actor_interleavings(producer, rest, prefix, schedules);
        prefix.pop();
    }
}

fn run_publish_before_read_interleaving(
    schedule: &[LoomStep],
    orderings: RingOrderings,
) -> LoomState {
    let published = frame(17, 3, 9, b"published");
    let stale = frame(0, 0, 0, b"stale");
    let mut slot_written = false;
    let mut write_idx = 0;
    let mut consumer_observed_write_idx = None;
    let mut consumer_synced_with_publish = false;
    let mut delivered = Vec::new();
    let mut failures = BTreeSet::new();

    for step in schedule {
        match step {
            LoomStep::ProducerWriteFrame => slot_written = true,
            LoomStep::ProducerReleaseWriteIndex => {
                assert!(slot_written, "producer cannot publish before writing slot");
                write_idx = 1;
            }
            LoomStep::ConsumerAcquireWriteIndex => {
                consumer_observed_write_idx = Some(write_idx);
                consumer_synced_with_publish = write_idx == 1
                    && orderings.producer_write_idx_store == ModelOrdering::Release
                    && orderings.consumer_write_idx_load == ModelOrdering::Acquire;
            }
            LoomStep::ConsumerReadFrame => {
                if consumer_observed_write_idx == Some(1) {
                    if consumer_synced_with_publish {
                        delivered.push(published.clone());
                    } else {
                        delivered.push(stale.clone());
                        failures.insert(ModelFailure::TornFrameAfterPublishedWriteIndex);
                    }
                }
            }
            LoomStep::ConsumerReadFrameForFree
            | LoomStep::ConsumerReleaseReadIndex
            | LoomStep::ProducerAcquireReadIndex
            | LoomStep::ProducerOverwriteFrame => {
                panic!("unexpected free-before-overwrite step in publish/read model: {step:?}");
            }
        }
    }

    LoomState {
        failures,
        delivered,
    }
}

fn run_free_before_overwrite_interleaving(
    schedule: &[LoomStep],
    orderings: RingOrderings,
) -> LoomState {
    let mut consumer_read_old_frame = false;
    let mut read_idx = 0;
    let mut producer_observed_read_idx = None;
    let mut producer_synced_with_free = false;
    let mut failures = BTreeSet::new();

    for step in schedule {
        match step {
            LoomStep::ConsumerReadFrameForFree => consumer_read_old_frame = true,
            LoomStep::ConsumerReleaseReadIndex => {
                assert!(
                    consumer_read_old_frame,
                    "consumer cannot free a slot before copying its frame"
                );
                read_idx = 1;
            }
            LoomStep::ProducerAcquireReadIndex => {
                producer_observed_read_idx = Some(read_idx);
                producer_synced_with_free = read_idx == 1
                    && orderings.consumer_read_idx_store == ModelOrdering::Release
                    && orderings.producer_read_idx_load == ModelOrdering::Acquire;
            }
            LoomStep::ProducerOverwriteFrame => {
                if producer_observed_read_idx == Some(1) && !producer_synced_with_free {
                    failures.insert(ModelFailure::ProducerOverwriteBeforeConsumerReadIsOrdered);
                }
            }
            LoomStep::ProducerWriteFrame
            | LoomStep::ProducerReleaseWriteIndex
            | LoomStep::ConsumerAcquireWriteIndex
            | LoomStep::ConsumerReadFrame => {
                panic!("unexpected publish/read step in free/overwrite model: {step:?}");
            }
        }
    }

    LoomState {
        failures,
        delivered: Vec::new(),
    }
}

impl RingOrderings {
    const fn rfc_13_6() -> Self {
        Self {
            producer_read_idx_load: ModelOrdering::Acquire,
            producer_write_idx_store: ModelOrdering::Release,
            consumer_write_idx_load: ModelOrdering::Acquire,
            consumer_read_idx_store: ModelOrdering::Release,
        }
    }

    const fn relaxed_everywhere() -> Self {
        Self {
            producer_read_idx_load: ModelOrdering::Relaxed,
            producer_write_idx_store: ModelOrdering::Relaxed,
            consumer_write_idx_load: ModelOrdering::Relaxed,
            consumer_read_idx_store: ModelOrdering::Relaxed,
        }
    }
}

impl SeededPropertyRng {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn random_inclusive(&mut self, start: usize, end: usize) -> usize {
        start + self.random_exclusive(end - start + 1)
    }

    fn random_exclusive(&mut self, end: usize) -> usize {
        let value = self.next_u64();
        (value % end as u64) as usize
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }
}

fn blank_entries(capacity: usize) -> Vec<FrameEntry> {
    vec![frame(0, 0, 0, b""); capacity]
}

fn enqueue(ring: &RingHeader, entries: &mut [FrameEntry], seq: u32) {
    enqueue_frame(ring, entries, &frame(10 + u64::from(seq), 1, seq, b"p"));
}

fn enqueue_frame(ring: &RingHeader, entries: &mut [FrameEntry], frame: &FrameEntry) {
    if let Err(error) = ring.enqueue(entries, frame) {
        panic!("enqueue should succeed: {error}");
    }
}

fn dequeue(ring: &RingHeader, entries: &[FrameEntry]) -> Option<FrameEntry> {
    match ring.dequeue(entries) {
        Ok(frame) => frame,
        Err(error) => panic!("dequeue should succeed: {error}"),
    }
}

fn snapshot(ring: &RingHeader, entries: &[FrameEntry]) -> SpscRingSnapshot {
    match ring.snapshot(entries) {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("snapshot should succeed: {error}"),
    }
}

fn restore(ring: &RingHeader, entries: &mut [FrameEntry], snapshot: &SpscRingSnapshot) {
    if let Err(error) = ring.restore(entries, snapshot) {
        panic!("restore should succeed: {error}");
    }
}

fn push_expected(expected: &mut VecDeque<FrameEntry>, frame: FrameEntry) {
    expected.push_back(frame);
}

fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    match FrameEntry::new(delivery_icount, src_node, seq, payload) {
        Ok(frame) => frame,
        Err(error) => panic!("frame should fit in test payload capacity: {error}"),
    }
}
