//! Unit tests for segmented trace handles, bundles, and the replay reader.

use super::*;
use crate::segment_store::SEGMENT_TARGET_BYTES;

const BUNDLE_LIMIT: usize = 64 * 1024 * 1024;

fn pass_item(index: u64) -> ResolvedReplayWorkItem {
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

/// Records `count` pass items into a fresh in-memory store.
fn recorded(count: u64) -> ResolvedEffectTrace {
    let mut writer = ResolvedEffectTraceWriter::new(
        Arc::new(SharedSegmentStore::new()),
        FaultResourceLimits::default(),
    );
    for index in 0..count {
        writer
            .append(pass_item(index))
            .unwrap_or_else(|error| panic!("append {index}: {error}"));
    }
    writer
        .finish(FaultReplayMode::LockedEffect)
        .unwrap_or_else(|error| panic!("finish: {error}"))
}

/// Records pass items until the trace spans two segments.
fn two_segment_trace() -> ResolvedEffectTrace {
    let mut writer = ResolvedEffectTraceWriter::new(
        Arc::new(SharedSegmentStore::new()),
        FaultResourceLimits::default(),
    );
    let mut index = 0;
    while writer.position().sealed().is_empty() {
        writer
            .append(pass_item(index))
            .unwrap_or_else(|error| panic!("append {index}: {error}"));
        index += 1;
    }
    writer
        .finish(FaultReplayMode::LockedEffect)
        .unwrap_or_else(|error| panic!("finish: {error}"))
}

fn coordinate(index: u64) -> FaultCoordinate {
    FaultCoordinate {
        virtual_ticks: index,
        retired_instructions: None,
    }
}

#[test]
fn bundles_round_trip_and_authenticate_every_segment() {
    let trace = recorded(4);
    let bundle = trace
        .to_bundle_bytes(BUNDLE_LIMIT)
        .unwrap_or_else(|error| panic!("bundle: {error}"));

    let decoded = ResolvedEffectTrace::from_bundle_bytes(&bundle, BUNDLE_LIMIT)
        .unwrap_or_else(|error| panic!("decode bundle: {error}"));
    assert_eq!(decoded, trace);
    let items: Vec<_> = decoded
        .items()
        .collect::<Result<_, _>>()
        .unwrap_or_else(|error| panic!("items: {error}"));
    assert_eq!(items, (0..4).map(pass_item).collect::<Vec<_>>());

    let mut tampered = bundle.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    assert!(ResolvedEffectTrace::from_bundle_bytes(&tampered, BUNDLE_LIMIT).is_err());

    let mut trailing = bundle.clone();
    trailing.push(0);
    assert!(ResolvedEffectTrace::from_bundle_bytes(&trailing, BUNDLE_LIMIT).is_err());

    assert!(ResolvedEffectTrace::from_bundle_bytes(&bundle, bundle.len() - 1).is_err());
    assert!(trace.to_bundle_bytes(bundle.len() - 1).is_err());
}

#[test]
fn small_segment_target_seals_many_authenticated_segments() {
    const TARGET: usize = 1024;

    let trace = ResolvedEffectTrace::from_items_with_segment_target(
        FaultReplayMode::LockedEffect,
        (0..64).map(pass_item),
        TARGET,
    )
    .unwrap_or_else(|error| panic!("fixture trace: {error}"));

    let segments = trace.manifest().segments();
    assert!(segments.len() > 4, "a small target seals many segments");
    let items: Vec<_> =
        ResolvedEffectTrace::referencing(trace.manifest().clone(), trace.segments().clone())
            .unwrap_or_else(|error| panic!("authenticate every segment: {error}"))
            .items()
            .collect::<Result<_, _>>()
            .unwrap_or_else(|error| panic!("items: {error}"));
    assert_eq!(items, (0..64).map(pass_item).collect::<Vec<_>>());
}

#[test]
fn a_manifest_without_its_segments_is_refused() {
    let trace = recorded(2);
    let (manifest, _segments) = trace.into_parts();

    assert!(matches!(
        ResolvedEffectTrace::referencing(manifest.clone(), SegmentSources::default()),
        Err(FaultRuntimeError::TraceStorage { .. })
    ));
    assert!(
        ResolvedEffectTraceReader::new(
            ResolvedEffectTrace::new(manifest, SegmentSources::default()),
            FaultResourceLimits::default(),
        )
        .is_err()
    );
}

#[test]
fn manifests_round_trip_and_reject_a_noncurrent_version() {
    let trace = two_segment_trace();
    let bytes = trace
        .manifest()
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("manifest bytes: {error}"));

    assert_eq!(
        ResolvedEffectTraceManifest::from_canonical_bytes(&bytes).as_ref(),
        Ok(trace.manifest())
    );

    let mut noncurrent = bytes;
    let version = noncurrent
        .iter()
        .position(|byte| *byte == b'4')
        .unwrap_or_else(|| panic!("manifest prefix carries its version"));
    noncurrent[version] = b'3';
    assert!(ResolvedEffectTraceManifest::from_canonical_bytes(&noncurrent).is_err());
}

#[test]
fn the_reader_replays_across_segments_and_resumes_from_a_cursor() {
    let trace = two_segment_trace();
    let total = trace.work_items();
    let boundary = trace.manifest().segments()[0].end_item();
    assert!(trace.manifest().segments()[0].encoded_bytes <= SEGMENT_TARGET_BYTES as u64);
    let mut reader = ResolvedEffectTraceReader::new(trace, FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("reader: {error}"));

    // Consume up to the segment boundary and checkpoint the cursor there.
    for index in 0..boundary {
        reader
            .prepare()
            .unwrap_or_else(|error| panic!("prepare {index}: {error}"));
        let item = reader
            .work_item_for_context(coordinate(index), 0, None)
            .unwrap_or_else(|error| panic!("context {index}: {error}"))
            .cloned();
        assert_eq!(item, Some(pass_item(index)));
        reader
            .advance()
            .unwrap_or_else(|error| panic!("advance {index}: {error}"));
    }
    let cursor = reader.replay_cursor();
    assert_eq!(cursor.cursor(), boundary);

    // A reader restored from the cursor continues in the second segment.
    let mut resumed = ResolvedEffectTraceReader::restore(
        &cursor,
        reader.trace().segments().clone(),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("restore: {error}"));
    for index in boundary..total {
        resumed
            .prepare()
            .unwrap_or_else(|error| panic!("prepare {index}: {error}"));
        assert_eq!(resumed.current(), Some(&pass_item(index)));
        resumed
            .advance()
            .unwrap_or_else(|error| panic!("advance {index}: {error}"));
    }
    assert_eq!(resumed.require_exhausted(), Ok(()));
    assert_eq!(
        resumed.work_item_for_context(coordinate(total), 0, None),
        Err(FaultRuntimeError::ReplayExhausted)
    );
}

#[test]
fn the_reader_refuses_a_misaligned_context() {
    let trace = recorded(2);
    let reader = ResolvedEffectTraceReader::new(trace, FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("reader: {error}"));

    assert!(matches!(
        reader.work_item_for_context(coordinate(1), 0, None),
        Err(FaultRuntimeError::ReplayMismatch { index: 0, .. })
    ));
    assert!(matches!(
        reader.require_exhausted(),
        Err(FaultRuntimeError::ReplayMismatch { index: 0, .. })
    ));
}

#[test]
fn a_replay_trace_beyond_the_scenario_counters_is_refused() {
    let trace = recorded(3);
    let limits = FaultResourceLimits {
        thin_replay_events: 2,
        ..FaultResourceLimits::default()
    };

    assert!(matches!(
        ResolvedEffectTraceReader::new(trace, limits),
        Err(FaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "thin_replay_events",
                ..
            }
        ))
    ));
}

#[test]
fn a_segment_decoded_under_the_wrong_reference_is_refused() {
    let trace = two_segment_trace();
    let segments = trace.manifest().segments();
    let second = &segments[1];
    let bytes = trace
        .segments()
        .segment(second.id)
        .unwrap_or_else(|error| panic!("segment: {error}"));

    assert!(decode_resolved_effect_trace_segment(second, &bytes).is_ok());
    let mut shifted = *second;
    shifted.first_item += 1;
    assert!(decode_resolved_effect_trace_segment(&shifted, &bytes).is_err());
    assert!(decode_resolved_effect_trace_segment(&segments[0], &bytes).is_err());
}
