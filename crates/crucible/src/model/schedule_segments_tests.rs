//! Tests for segmented schedule storage, transport, and identity.

use super::*;
use crate::segment_store::SharedSegmentStore;

fn draw(value: u64) -> Decision {
    Decision::RngDraw(RngDecision {
        stream: RngStreamId::for_node("schedule-segments"),
        value,
    })
}

/// Builds a schedule whose decisions each encode to roughly `width` bytes.
fn wide_schedule(decisions: u64, width: usize) -> Schedule {
    Schedule::from_decisions((0..decisions).map(|index| {
        Decision::Override(OverrideDecision {
            point: SchedulingPoint {
                key: format!("{}{index}", "k".repeat(width)),
            },
            choice: ChoiceTag {
                name: String::from("chosen"),
            },
        })
    }))
}

#[test]
fn transport_round_trips_and_keeps_identity() -> Result<(), EngineError> {
    for schedule in [
        Schedule::empty(),
        Schedule::from_decisions((0..17).map(draw)),
    ] {
        let bytes = schedule.to_compact_binary();
        let decoded = Schedule::from_compact_binary(&bytes)?;

        assert_eq!(decoded, schedule);
        assert_eq!(decoded.content_hash(), schedule.content_hash());
        assert_eq!(decoded.to_compact_binary(), bytes);
    }
    Ok(())
}

#[test]
fn streamed_transport_hash_matches_the_written_blob() {
    for schedule in [
        Schedule::empty(),
        wide_schedule(20, 1024 * 1024),
        // Unsegmentable: its transport is the empty-manifest form.
        wide_schedule(1, MAX_SEGMENT_BYTES),
    ] {
        let mut streamed = blake3::Hasher::new();
        hash_schedule_v5_blob(&schedule, &mut streamed);

        let bytes = schedule.to_compact_binary();
        let mut written = blake3::Hasher::new();
        written.update(&(bytes.len() as u64).to_le_bytes());
        written.update(&bytes);

        assert_eq!(streamed.finalize(), written.finalize());
    }
}

#[test]
fn seal_points_follow_only_the_decision_sequence() -> Result<(), EngineError> {
    // Each decision encodes to about 1 MiB, so the 8 MiB target seals every
    // seventh or eighth decision and the schedule spans several segments.
    let schedule = wide_schedule(20, 1024 * 1024);
    let store = SharedSegmentStore::new();
    let manifest = schedule.write_segments(&store)?;

    assert!(manifest.segments().len() >= 3);
    assert_eq!(manifest.decision_count(), 20);
    for segment in manifest.segments() {
        assert!(segment.encoded_bytes <= SEGMENT_TARGET_BYTES as u64);
    }
    assert_eq!(manifest.read_schedule(&store)?, schedule);

    // A prefix seals at the same points as the whole schedule up to its end.
    let prefix = schedule
        .prefix(13)
        .map_err(|error| scenario_serialization_error(format!("prefix: {error}")))?;
    let prefix_manifest = prefix.write_segments(&SharedSegmentStore::new())?;
    let shared = prefix_manifest.segments().len() - 1;
    assert_eq!(
        &prefix_manifest.segments()[..shared],
        &manifest.segments()[..shared]
    );
    Ok(())
}

#[test]
fn resident_segments_match_the_stored_segments() -> Result<(), EngineError> {
    let long = wide_schedule(20, 1024 * 1024);
    let short = Schedule::from_decisions((0..5).map(draw));
    let store = SharedSegmentStore::new();
    let long_manifest = long.write_segments(&store)?;
    let short_manifest = short.write_segments(&store)?;

    let resident = ResidentScheduleSegments::new([&long, &short])?;
    for segment in long_manifest
        .segments()
        .iter()
        .chain(short_manifest.segments())
    {
        let stored = SegmentSource::segment(&store, segment.id)
            .map_err(|error| scenario_serialization_error(error.to_string()))?;
        let encoded = resident
            .segment(segment.id)
            .map_err(|error| scenario_serialization_error(error.to_string()))?;
        assert_eq!(encoded, stored);
    }
    assert_eq!(long_manifest.read_schedule(&resident)?, long);

    let foreign =
        Schedule::from_decisions((10..12).map(draw)).try_for_each_segment(|_, _| Ok(()))?;
    assert!(resident.segment(foreign.segments()[0].id).is_err());
    let mut shifted = short_manifest.segments()[0];
    shifted.first_decision = 1;
    assert!(short.encode_segment(&shifted).is_err());
    Ok(())
}

#[test]
fn manifest_round_trips_and_rejects_altered_totals() -> Result<(), EngineError> {
    let schedule = wide_schedule(12, 1024 * 1024);
    let store = SharedSegmentStore::new();
    let manifest = schedule.write_segments(&store)?;
    let bytes = manifest.to_bytes();

    assert_eq!(ScheduleManifest::from_bytes(&bytes)?, manifest);

    let mut altered = bytes.clone();
    // The decision count follows the magic and the schedule hash.
    altered[MANIFEST_MAGIC.len() + 32] ^= 1;
    assert!(ScheduleManifest::from_bytes(&altered).is_err());
    Ok(())
}

#[test]
fn reader_rejects_a_missing_or_substituted_segment() -> Result<(), EngineError> {
    let schedule = wide_schedule(12, 1024 * 1024);
    let store = SharedSegmentStore::new();
    let manifest = schedule.write_segments(&store)?;

    let partial = SharedSegmentStore::new();
    let first = manifest.segments()[0];
    let bytes = crate::SegmentSource::segment(&store, first.id)
        .map_err(|error| scenario_serialization_error(error.to_string()))?;
    partial
        .put_segment(first.id, &bytes)
        .map_err(|error| scenario_serialization_error(error.to_string()))?;
    assert!(manifest.read_schedule(&partial).is_err());

    let other = wide_schedule(12, 1024 * 1024 + 1);
    let other_manifest = other.write_segments(&store)?;
    let swapped =
        ScheduleManifest::new(manifest.schedule_hash(), other_manifest.segments().to_vec())?;
    assert!(swapped.read_schedule(&store).is_err());
    Ok(())
}

#[test]
fn a_nested_count_cannot_reserve_beyond_its_segment() -> Result<(), EngineError> {
    let schedule = Schedule::from_decisions([Decision::DeliveryOrder(DeliveryOrderDecision {
        at: VirtualTime { ticks: 0 },
        order: Vec::new(),
    })]);
    let mut encoded = Vec::new();
    schedule.try_for_each_segment(|_, bytes| {
        encoded = bytes.to_vec();
        Ok(())
    })?;

    // The segment ends with the delivery order's element count. The altered
    // segment gets its own reference so that only the count is wrong.
    let count_at = encoded.len() - std::mem::size_of::<u64>();
    encoded[count_at..].copy_from_slice(&1_000_000_u64.to_le_bytes());
    let segment = ScheduleSegmentRef {
        id: ContentId::for_bytes(ObjectKind::Trace, SCHEDULE_SEGMENT_SCHEMA, &encoded),
        first_decision: 0,
        decision_count: 1,
        encoded_bytes: encoded.len() as u64,
    };

    let Err(error) = decode_segment(&segment, &encoded) else {
        return Err(scenario_serialization_error(
            "a delivery-order count cannot reserve beyond its encoded input",
        ));
    };
    assert!(error.to_string().contains("remaining binary input"));
    Ok(())
}

#[test]
fn a_decision_beyond_the_segment_bound_is_refused_closed() {
    let schedule = wide_schedule(1, MAX_SEGMENT_BYTES);

    assert!(schedule.write_segments(&SharedSegmentStore::new()).is_err());
    assert!(Schedule::from_compact_binary(&schedule.to_compact_binary()).is_err());
}
