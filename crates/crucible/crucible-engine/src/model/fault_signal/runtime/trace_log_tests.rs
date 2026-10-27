//! Unit tests for the segmented resolved-effect trace writer.

use super::*;
use crate::segment_store::{MAX_SEGMENT_BYTES, SharedSegmentStore};

pub(super) fn pass_item(index: u64) -> ResolvedReplayWorkItem {
    let coordinate = FaultCoordinate {
        virtual_ticks: index,
        retired_instructions: None,
    };
    ResolvedReplayWorkItem::new(
        coordinate,
        0,
        None,
        ContentHash::from_bytes(&index.to_be_bytes()),
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("pass item: {error}"))
}

fn writer(store: &SharedSegmentStore) -> ResolvedEffectTraceWriter {
    ResolvedEffectTraceWriter::new(Arc::new(store.clone()), FaultResourceLimits::default())
}

/// Appends pass items until the writer has sealed `segments` segments and
/// holds at least one open item, returning the next item index.
pub(super) fn fill_until_sealed(
    writer: &mut ResolvedEffectTraceWriter,
    segments: usize,
    next: u64,
) -> u64 {
    let mut index = next;
    while writer.position().sealed().len() < segments || writer.position().tail().is_empty() {
        writer
            .append(pass_item(index))
            .unwrap_or_else(|error| panic!("append {index}: {error}"));
        index += 1;
    }
    index
}

fn collect(trace: &ResolvedEffectTrace) -> Vec<ResolvedReplayWorkItem> {
    trace
        .items()
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("trace items: {error}"))
}

fn encoded<T: Serialize>(value: &T) -> u64 {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).unwrap_or_else(|error| panic!("encode: {error}"));
    bytes.len() as u64
}

#[test]
fn an_empty_writer_exports_an_empty_trace() {
    let store = SharedSegmentStore::new();
    let trace = writer(&store)
        .export(FaultReplayMode::LockedEffect)
        .unwrap_or_else(|error| panic!("export: {error}"));

    assert!(trace.is_empty());
    assert!(trace.manifest().segments().is_empty());
    assert_eq!(trace.manifest().chain(), empty_chain());
    assert_eq!(store.len().ok(), Some(0));
}

#[test]
fn export_stores_the_tail_without_moving_the_position() {
    let store = SharedSegmentStore::new();
    let mut writer = writer(&store);
    let items: Vec<_> = (0..3).map(pass_item).collect();
    for item in &items {
        writer
            .append(item.clone())
            .unwrap_or_else(|error| panic!("append: {error}"));
    }
    let before = writer.position().clone();

    let first = writer
        .export(FaultReplayMode::LockedEffect)
        .unwrap_or_else(|error| panic!("first export: {error}"));
    let second = writer
        .export(FaultReplayMode::LockedEffect)
        .unwrap_or_else(|error| panic!("second export: {error}"));

    assert_eq!(writer.position(), &before);
    assert!(writer.position().sealed().is_empty());
    assert_eq!(first, second);
    assert_eq!(first.manifest().segments().len(), 1);
    assert_eq!(collect(&first), items);
}

#[test]
fn the_writer_seals_by_size_and_keeps_every_segment_within_bounds() {
    let store = SharedSegmentStore::new();
    let mut writer = writer(&store);
    let next = fill_until_sealed(&mut writer, 2, 0);

    let sealed = writer.position().sealed();
    assert_eq!(sealed.len(), 2);
    assert_eq!(sealed[0].first_item, 0);
    assert_eq!(sealed[1].first_item, sealed[0].end_item());
    for segment in sealed {
        assert!(segment.encoded_bytes <= MAX_SEGMENT_BYTES as u64);
        assert!(segment.encoded_bytes > (SEGMENT_TARGET_BYTES / 2) as u64);
    }
    assert!(writer.tail_bytes() <= SEGMENT_TARGET_BYTES);
    assert_ne!(writer.position().chain(), empty_chain());

    let trace = writer
        .export(FaultReplayMode::LockedEffect)
        .unwrap_or_else(|error| panic!("export: {error}"));
    assert_eq!(trace.work_items(), next);
    let mut expected = 0_u64;
    for item in trace.items() {
        let item = item.unwrap_or_else(|error| panic!("item: {error}"));
        assert_eq!(item.coordinate.virtual_ticks, expected);
        expected += 1;
    }
    assert_eq!(expected, next);
}

#[test]
fn a_restored_position_produces_the_uninterrupted_trace() {
    // The product must not depend on whether the execution was checkpointed
    // and resumed (RFC-0020 CCOMP-21).
    let uninterrupted_store = SharedSegmentStore::new();
    let mut uninterrupted = writer(&uninterrupted_store);
    let resumed_store = SharedSegmentStore::new();
    let mut first_half = writer(&resumed_store);

    let midpoint = fill_until_sealed(&mut first_half, 1, 0);
    let checkpoint = first_half.position().clone();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&checkpoint, &mut bytes)
        .unwrap_or_else(|error| panic!("position encodes: {error}"));
    let decoded: ResolvedEffectTracePosition = ciborium::de::from_reader(bytes.as_slice())
        .unwrap_or_else(|error| panic!("position decodes: {error}"));
    assert_eq!(decoded, checkpoint);
    drop(first_half);

    let mut resumed = ResolvedEffectTraceWriter::restore(
        Arc::new(resumed_store.clone()),
        FaultResourceLimits::default(),
        decoded,
    )
    .unwrap_or_else(|error| panic!("restore: {error}"));
    let end = fill_until_sealed(&mut resumed, 2, midpoint);
    for index in 0..end {
        uninterrupted
            .append(pass_item(index))
            .unwrap_or_else(|error| panic!("append {index}: {error}"));
    }

    let left = uninterrupted
        .export(FaultReplayMode::LockedEffect)
        .unwrap_or_else(|error| panic!("uninterrupted export: {error}"));
    let right = resumed
        .export(FaultReplayMode::LockedEffect)
        .unwrap_or_else(|error| panic!("resumed export: {error}"));
    assert_eq!(left.manifest(), right.manifest());
    assert_eq!(
        left.manifest().content_id().ok(),
        right.manifest().content_id().ok()
    );
}

#[test]
fn reservations_enforce_the_scenario_counters() {
    let limits = FaultResourceLimits {
        thin_replay_events: 1,
        ..FaultResourceLimits::default()
    };
    let mut writer = ResolvedEffectTraceWriter::new(Arc::new(SharedSegmentStore::new()), limits);
    writer
        .append(pass_item(0))
        .unwrap_or_else(|error| panic!("first append: {error}"));

    assert!(matches!(
        writer.append(pass_item(1)),
        Err(FaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "thin_replay_events",
                current: 1,
                requested: 1,
                ..
            }
        ))
    ));
    assert_eq!(writer.work_items(), 1);
    assert_eq!(writer.position().tail().len(), 1);
}

#[test]
fn the_capacity_shell_measures_an_append_without_a_seal_exactly() {
    let store = SharedSegmentStore::new();
    let mut writer = writer(&store);
    for index in 0..5 {
        writer
            .append(pass_item(index))
            .unwrap_or_else(|error| panic!("append: {error}"));
    }
    let item = pass_item(5);
    let item_bytes = encoded_item_len(&item).unwrap_or_else(|error| panic!("item length: {error}"));

    let shell = writer
        .capacity_shell(item_bytes, 0)
        .unwrap_or_else(|error| panic!("shell: {error}"));
    writer
        .append(item)
        .unwrap_or_else(|error| panic!("append: {error}"));

    assert_eq!(
        shell.encoded_len(encoded(&shell.position)),
        encoded(writer.position())
    );
}

#[test]
fn the_capacity_shell_bounds_a_sealing_append() {
    let store = SharedSegmentStore::new();
    let mut writer = writer(&store);
    let mut index = fill_until_sealed(&mut writer, 1, 0);

    loop {
        let item = pass_item(index);
        let item_bytes =
            encoded_item_len(&item).unwrap_or_else(|error| panic!("item length: {error}"));
        if writer.tail_bytes() + item_bytes <= SEGMENT_TARGET_BYTES {
            writer
                .append(item)
                .unwrap_or_else(|error| panic!("append {index}: {error}"));
            index += 1;
            continue;
        }

        let shell = writer
            .capacity_shell(item_bytes, 0)
            .unwrap_or_else(|error| panic!("sealing shell: {error}"));
        writer
            .append(item)
            .unwrap_or_else(|error| panic!("sealing append: {error}"));
        assert_eq!(writer.position().sealed().len(), 2);
        assert_eq!(writer.position().tail().len(), 1);
        // The unknown chain digest is measured at its widest encoding.
        let measured = shell.encoded_len(encoded(&shell.position));
        let actual = encoded(writer.position());
        assert!(measured >= actual, "{measured} < {actual}");
        assert!(measured <= actual + 32, "{measured} >> {actual}");
        break;
    }
}

#[test]
fn a_restored_position_requires_its_counters_to_agree() {
    let store = SharedSegmentStore::new();
    let mut writer = writer(&store);
    writer
        .append(pass_item(0))
        .unwrap_or_else(|error| panic!("append: {error}"));
    let mut position = writer.position().clone();
    position.work_items += 1;

    assert!(
        ResolvedEffectTraceWriter::restore(
            Arc::new(store.clone()),
            FaultResourceLimits::default(),
            position,
        )
        .is_err()
    );
}
