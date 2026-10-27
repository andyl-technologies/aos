//! Segment-referenced resolved-effect traces in finding replay captures.
//!
//! A capture names each side trace by its manifest and publishes the trace's
//! segments as children, so no whole-trace bound applies. These tests use a
//! small segment target, so a trace of many segments stays a few kilobytes.

use super::test_support::*;
use super::*;
use crucible_engine::model::FaultReplayMode;
use crucible_engine::segment_store::{MAX_SEGMENT_BYTES, SegmentSources};
use crucible_campaign::FindingReplayCaptureEvidenceId;
use crucible_store::content_envelope::ContentEnvelope;
use crucible_store::content_store::{BlobHandle, ObjectKind};

/// Fixture seal target, far below the production 8 MiB target.
const FIXTURE_SEGMENT_TARGET_BYTES: usize = 2 * 1024;

/// Segments the removed 64 MiB trace bundle bound held at the 16 MiB
/// per-segment bound; the same ratio applies at the fixture's scale.
const FORMER_BUNDLE_SEGMENTS: u64 = 4;

fn trace_segment_ids(objects: &FindingProductionReplayCaptureObjects) -> BTreeSet<ContentId> {
    objects
        .leaves()
        .iter()
        .filter(|(_, leaf)| {
            leaf.role() == FindingProductionReplayLeafRole::ResolvedEffectTraceSegment
        })
        .map(|(id, _)| *id)
        .collect()
}

fn trace_items(trace: &ResolvedEffectTrace) -> Vec<crucible_engine::model::ResolvedReplayWorkItem> {
    trace
        .items()
        .collect::<Result<_, _>>()
        .expect("trace items stream back")
}

fn decode(
    objects: &FindingProductionReplayCaptureObjects,
    leaves: &BTreeMap<ContentId, BlobHandle>,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<FindingProductionReplayCapture, FindingProductionReplayCaptureError> {
    FindingProductionReplayCapture::from_objects(
        objects.root(),
        objects.manifest_bytes(),
        leaves,
        limits,
    )
}

#[test]
fn capture_round_trips_a_trace_longer_than_the_former_bundle_bound() {
    let trace = segmented_trace(256, FIXTURE_SEGMENT_TARGET_BYTES);
    let segments = trace.manifest().segments();
    let largest = segments
        .iter()
        .map(|segment| segment.encoded_bytes)
        .max()
        .expect("trace has segments");
    let total: u64 = segments.iter().map(|segment| segment.encoded_bytes).sum();
    assert!(segments.len() as u64 > 2 * FORMER_BUNDLE_SEGMENTS);
    assert!(
        total > FORMER_BUNDLE_SEGMENTS * largest,
        "the trace must outgrow a bundle of the former segment ratio"
    );

    let (capture, limits) = traced_capture(trace.clone());
    let objects = capture.prepare_objects().expect("prepare capture objects");

    let expected: BTreeSet<_> = trace.manifest().segment_ids().collect();
    assert_eq!(
        trace_segment_ids(&objects),
        expected,
        "every trace segment is its own capture child"
    );
    assert!(
        objects
            .leaves()
            .values()
            .filter(
                |leaf| leaf.role() == FindingProductionReplayLeafRole::ResolvedEffectTraceSegment
            )
            .all(|leaf| leaf.role().is_run_length() && leaf.length() <= MAX_SEGMENT_BYTES as u64),
        "trace segments are run-length leaves within the per-segment bound"
    );

    let decoded = decode(&objects, &leaf_handles(&objects), limits).expect("decode capture");
    assert_eq!(decoded, capture);
    let decoded_trace = decoded.sides()[0]
        .resolved_effect_trace()
        .expect("decoded side keeps its trace");
    assert_eq!(decoded_trace.manifest(), trace.manifest());
    assert_eq!(trace_items(decoded_trace), trace_items(&trace));
    assert_eq!(
        decoded.prepare_objects().expect("re-prepare").root(),
        objects.root(),
        "a decoded capture derives the same manifest identity"
    );
}

#[test]
fn decode_refuses_a_capture_missing_a_trace_segment() {
    let (capture, limits) = traced_capture(segmented_trace(64, FIXTURE_SEGMENT_TARGET_BYTES));
    let objects = capture.prepare_objects().expect("prepare capture objects");
    let segment = *trace_segment_ids(&objects)
        .iter()
        .nth(1)
        .expect("trace spans several segments");

    let mut leaves = leaf_handles(&objects);
    leaves.remove(&segment);

    assert!(matches!(
        decode(&objects, &leaves, limits),
        Err(FindingProductionReplayCaptureError::MissingLeaf { id }) if id == segment
    ));
}

#[test]
fn decode_refuses_a_trace_segment_whose_bytes_differ_from_its_reference() {
    let (capture, limits) = traced_capture(segmented_trace(64, FIXTURE_SEGMENT_TARGET_BYTES));
    let objects = capture.prepare_objects().expect("prepare capture objects");
    let segment = *trace_segment_ids(&objects)
        .first()
        .expect("trace has a segment");
    let mut leaves = leaf_handles(&objects);
    let mut bytes = leaves[&segment]
        .read_all(MAX_SEGMENT_BYTES as u64)
        .expect("read trace segment");
    let last = bytes.last_mut().expect("nonempty segment");
    *last ^= 1;

    // Equal length passes the declared-length check, so the segment's
    // authentication is what refuses it.
    leaves.insert(segment, BlobHandle::from_bytes(bytes));

    assert!(matches!(
        decode(&objects, &leaves, limits),
        Err(FindingProductionReplayCaptureError::InvalidResolvedEffectTrace)
    ));
}

#[test]
fn decode_refuses_a_trace_manifest_whose_chain_differs_from_its_segments() {
    let (capture, limits) = traced_capture(segmented_trace(64, FIXTURE_SEGMENT_TARGET_BYTES));
    let objects = capture.prepare_objects().expect("prepare capture objects");
    let envelope =
        decode_finding_production_replay_manifest(objects.root(), objects.manifest_bytes())
            .expect("manifest envelope");
    let mut body = manifest::decode_manifest_body(envelope.body()).expect("manifest body");
    body.sides[0]
        .resolved_effect_trace
        .as_mut()
        .expect("side trace")
        .chain = ContentHash::from_bytes(b"forged trace chain");

    // Re-encode under a fresh identity, so only the chain is wrong.
    let mut forged_body = Vec::new();
    ciborium::into_writer(&body, &mut forged_body).expect("encode forged body");
    let forged = ContentEnvelope::new(
        FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA,
        FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA_VERSION,
        envelope.children().clone(),
        forged_body,
    )
    .expect("forged envelope");
    let forged_root = FindingReplayCaptureEvidenceId::from_manifest_content_id(
        forged.content_id(ObjectKind::ExactManifest),
    )
    .expect("forged capture root");

    assert!(matches!(
        FindingProductionReplayCapture::from_objects(
            forged_root,
            &forged.canonical_bytes(),
            &leaf_handles(&objects),
            limits,
        ),
        Err(FindingProductionReplayCaptureError::InvalidManifest {
            reason: "side resolved-effect trace"
        })
    ));
}

#[test]
fn capture_refuses_a_trace_whose_stores_lack_its_segments() {
    let trace = segmented_trace(64, FIXTURE_SEGMENT_TARGET_BYTES);
    let detached = ResolvedEffectTrace::new(trace.manifest().clone(), SegmentSources::default());

    assert!(matches!(
        traced_side(detached),
        Err(FindingProductionReplayCaptureError::ResolvedEffectTraceStore(_))
    ));
}

#[test]
fn empty_trace_publishes_its_manifest_without_segment_children() {
    let trace = ResolvedEffectTrace::empty(FaultReplayMode::RecomputedCause).expect("empty trace");
    let (capture, limits) = traced_capture(trace.clone());
    let objects = capture.prepare_objects().expect("prepare capture objects");

    assert!(trace_segment_ids(&objects).is_empty());
    let decoded = decode(&objects, &leaf_handles(&objects), limits).expect("decode capture");
    assert_eq!(
        decoded.sides()[0].resolved_effect_trace(),
        Some(&trace),
        "an empty trace is still present, by its manifest"
    );
}
