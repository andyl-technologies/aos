//! Regression coverage for by-reference finding replay capture persistence.

// crucible-lint: allow panic-shortcut -- focused storage fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use super::*;
use std::sync::Arc;

use crucible_campaign::{CampaignExecutorStore, CampaignRepository};
use crucible_store::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
};

use crate::FindingProductionReplayCapture;
use crate::finding_production_replay::test_support::{
    segmented_trace, timeout_capture, traced_capture,
};

fn incomplete() -> FindingReplayCaptureInput {
    FindingReplayCaptureInput::Incomplete(
        FindingReplayCaptureIncomplete::MissingTerminalFingerprints,
    )
}

fn complete(capture: &FindingProductionReplayCapture) -> FindingReplayCaptureInput {
    FindingReplayCaptureInput::Complete(Box::new(
        capture.prepare_objects().expect("prepare capture objects"),
    ))
}

fn executor_store(root: &std::path::Path) -> CampaignExecutorStore {
    CampaignExecutorStore::new(Arc::new(repository(root)))
}

fn repository(root: &std::path::Path) -> CampaignRepository {
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "finding-replay-captures",
        root.join("objects"),
    ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(DirectoryRefBackend::new(root.join("refs")));
    CampaignRepository::new(blobs, refs)
}

/// Decodes one loaded complete role back into a capture.
fn decode(
    loaded: &LoadedFindingReplayCapture,
    limits: crate::FindingProductionReplayCaptureLimits,
) -> FindingProductionReplayCapture {
    let LoadedFindingReplayCapture::Complete(objects) = loaded else {
        panic!("role should be complete");
    };
    FindingProductionReplayCapture::from_objects(
        objects.root(),
        objects.manifest(),
        objects.leaves(),
        limits,
    )
    .expect("decode loaded capture")
}

#[test]
fn shared_leaves_are_deduplicated_across_capture_roles() {
    let temporary = tempfile::tempdir().expect("capture directory");
    let executor = executor_store(temporary.path());
    let (first, limits) = timeout_capture(&["first-run"]);
    let (second, _) = timeout_capture(&["second-run"]);
    let first_objects = first.prepare_objects().expect("first objects");
    let second_objects = second.prepare_objects().expect("second objects");

    let prepared = FindingReplayCaptureStore::prepare_set([
        complete(&first),
        complete(&first),
        complete(&second),
        incomplete(),
    ])
    .expect("prepare shared captures");

    // The two captures differ only in their side logs, so every static leaf
    // is shared and each capture contributes its own segment.
    let distinct: BTreeMap<_, _> = first_objects
        .leaves()
        .iter()
        .chain(second_objects.leaves())
        .collect();
    assert_eq!(prepared.manifests.len(), 2);
    assert_eq!(prepared.leaves.len(), distinct.len());
    let segment_bytes: u64 = distinct
        .values()
        .filter(|leaf| leaf.role().is_run_length())
        .map(|leaf| leaf.length())
        .sum();
    let static_bytes: u64 = distinct
        .values()
        .filter(|leaf| !leaf.role().is_run_length())
        .map(|leaf| leaf.length())
        .sum::<u64>()
        + first_objects.manifest_bytes().len() as u64
        + second_objects.manifest_bytes().len() as u64;
    assert_eq!(prepared.unique_segment_bytes(), segment_bytes);
    assert_eq!(prepared.unique_static_bytes(), static_bytes);
    assert_eq!(
        prepared.references().minimization_original(),
        prepared.references().minimization_selected()
    );

    let guard = executor
        .acquire_finding_replay_publication_guard()
        .expect("GC exclusion");
    FindingReplayCaptureStore::publish_set(&guard, &prepared).expect("publish capture set");
    FindingReplayCaptureStore::publish_set(&guard, &prepared).expect("exact retry is idempotent");
    drop(prepared);

    let first_root = FindingReplayCaptureReference::Complete(first_objects.root());
    let loaded = FindingReplayCaptureStore::load_set(
        &guard,
        FindingReplayCaptureSet::new(
            first_root,
            first_root,
            FindingReplayCaptureReference::Complete(second_objects.root()),
            FindingReplayCaptureReference::Incomplete(
                FindingReplayCaptureIncomplete::MissingTerminalFingerprints,
            ),
        ),
    )
    .expect("load capture set");
    assert_eq!(decode(&loaded[0], limits), first);
    assert_eq!(decode(&loaded[1], limits), first);
    assert_eq!(decode(&loaded[2], limits), second);
    assert!(matches!(
        loaded[3],
        LoadedFindingReplayCapture::Incomplete(
            FindingReplayCaptureIncomplete::MissingTerminalFingerprints
        )
    ));

    drop(guard);
    let reopened = repository(temporary.path());
    let imported = FindingReplayCaptureStore::load_set_from_repository(
        &reopened,
        FindingReplayCaptureSet::new(
            FindingReplayCaptureReference::Complete(second_objects.root()),
            FindingReplayCaptureReference::Incomplete(
                FindingReplayCaptureIncomplete::MissingTerminalFingerprints,
            ),
            FindingReplayCaptureReference::Incomplete(
                FindingReplayCaptureIncomplete::MissingTerminalFingerprints,
            ),
            FindingReplayCaptureReference::Incomplete(
                FindingReplayCaptureIncomplete::MissingTerminalFingerprints,
            ),
        ),
    )
    .expect("load retained capture set without publication authority");
    assert_eq!(decode(&imported[0], limits), second);
}

#[test]
fn trace_segments_are_published_and_retained_beside_log_segments() {
    let temporary = tempfile::tempdir().expect("capture directory");
    let executor = executor_store(temporary.path());
    let (capture, limits) = traced_capture(segmented_trace(64, 2 * 1024));
    let side = &capture.sides()[0];
    let trace = side.resolved_effect_trace().expect("side trace");
    let trace_bytes: u64 = trace
        .manifest()
        .segments()
        .iter()
        .map(|segment| segment.encoded_bytes)
        .sum();
    let log_bytes: u64 = side
        .event_log()
        .manifest()
        .segments()
        .iter()
        .map(|segment| segment.encoded_bytes)
        .sum();

    let prepared = FindingReplayCaptureStore::prepare_set([
        complete(&capture),
        incomplete(),
        incomplete(),
        incomplete(),
    ])
    .expect("prepare traced capture");

    // Trace segments grow with the run, so they share the run-length
    // allowance with the side log's segments.
    assert_eq!(prepared.unique_segment_bytes(), trace_bytes + log_bytes);

    let guard = executor
        .acquire_finding_replay_publication_guard()
        .expect("GC exclusion");
    FindingReplayCaptureStore::publish_set(&guard, &prepared).expect("publish capture set");
    drop(prepared);
    let loaded = FindingReplayCaptureStore::load_set(
        &guard,
        FindingReplayCaptureSet::new(
            FindingReplayCaptureReference::Complete(
                capture.prepare_objects().expect("capture objects").root(),
            ),
            FindingReplayCaptureReference::Incomplete(
                FindingReplayCaptureIncomplete::MissingTerminalFingerprints,
            ),
            FindingReplayCaptureReference::Incomplete(
                FindingReplayCaptureIncomplete::MissingTerminalFingerprints,
            ),
            FindingReplayCaptureReference::Incomplete(
                FindingReplayCaptureIncomplete::MissingTerminalFingerprints,
            ),
        ),
    )
    .expect("load traced capture");

    let LoadedFindingReplayCapture::Complete(objects) = &loaded[0] else {
        panic!("traced role should be complete");
    };
    // The manifest roots its trace segments as children, exactly as it
    // roots its log segments, so the store keeps them while it exists.
    for id in trace.manifest().segment_ids() {
        assert!(objects.leaves().contains_key(&id));
    }
    assert_eq!(decode(&loaded[0], limits), capture);
}

#[test]
fn segment_and_static_bytes_are_charged_to_separate_allowances() {
    let mut charges = CaptureCharges::default();

    charges.charge(
        FindingProductionReplayLeafRole::EventLogSegment,
        MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES + 1,
    );
    assert_eq!(charges.static_bytes, 0);
    assert!(
        charges.within_allowances(),
        "run-length segments do not consume the static allowance"
    );

    charges.charge(
        FindingProductionReplayLeafRole::EventLogSegment,
        MAX_FINDING_REPLAY_PUBLICATION_SEGMENT_BYTES,
    );
    assert!(!charges.within_allowances());

    let mut charges = CaptureCharges::default();
    charges.charge(
        FindingProductionReplayLeafRole::GuestAsset,
        MAX_FINDING_REPLAY_PUBLICATION_STATIC_BYTES,
    );
    assert!(charges.within_allowances());
    charges.charge_static(1);
    assert!(!charges.within_allowances());

    let mut charges = CaptureCharges::default();
    charges.charge(FindingProductionReplayLeafRole::EventLogSegment, u64::MAX);
    charges.charge(FindingProductionReplayLeafRole::EventLogSegment, u64::MAX);
    assert!(!charges.within_allowances(), "saturated sums never fit");
}

#[test]
fn load_rejects_a_manifest_with_a_missing_leaf() {
    let temporary = tempfile::tempdir().expect("capture directory");
    let executor = executor_store(temporary.path());
    let (capture, _) = timeout_capture(&["absent-leaf"]);
    let objects = capture.prepare_objects().expect("capture objects");
    let prepared = FindingReplayCaptureStore::prepare_set([
        complete(&capture),
        incomplete(),
        incomplete(),
        incomplete(),
    ])
    .expect("prepare capture");

    let guard = executor
        .acquire_finding_replay_publication_guard()
        .expect("GC exclusion");
    guard
        .put_finding_replay_capture_object(objects.root().content_id(), &objects.manifest_source())
        .expect("publish only the manifest");

    let error = FindingReplayCaptureStore::load_set(&guard, prepared.references())
        .expect_err("missing leaf must fail closed");
    assert!(matches!(
        error,
        FindingReplayCaptureStoreError::Repository(_)
    ));
}
