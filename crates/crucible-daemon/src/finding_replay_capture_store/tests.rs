//! Regression coverage for chunked finding replay capture persistence.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use super::*;
use std::sync::Arc;

use crucible_campaign::{CampaignExecutorStore, CampaignRepository};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
};

fn incomplete() -> FindingReplayCaptureInput {
    FindingReplayCaptureInput::Incomplete(
        FindingReplayCaptureIncomplete::MissingTerminalFingerprints,
    )
}

fn executor_store(root: &std::path::Path) -> CampaignExecutorStore {
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "finding-replay-captures",
        root.join("objects"),
    ));
    let refs: Arc<dyn MutableRefBackend> = Arc::new(DirectoryRefBackend::new(root.join("refs")));
    CampaignExecutorStore::new(Arc::new(CampaignRepository::new(blobs, refs)))
}

#[test]
fn shared_chunks_are_deduplicated_across_capture_roles() {
    let temporary = tempfile::tempdir().expect("capture directory");
    let executor = executor_store(temporary.path());
    let bytes = b"same portable replay capture".to_vec();
    let content_hash = ContentHash::from_bytes(&bytes);
    let prepared = FindingReplayCaptureStore::prepare_set([
        FindingReplayCaptureInput::Complete {
            bytes: bytes.clone(),
            content_hash,
        },
        FindingReplayCaptureInput::Complete {
            bytes: bytes.clone(),
            content_hash,
        },
        incomplete(),
        incomplete(),
    ])
    .expect("prepare shared captures");

    assert_eq!(prepared.chunks.len(), 1);
    assert_eq!(prepared.manifests.len(), 1);
    assert_eq!(prepared.unique_chunk_bytes(), bytes.len() as u64);
    assert_eq!(
        prepared.references().minimization_original(),
        prepared.references().minimization_selected()
    );

    let guard = executor
        .acquire_finding_replay_publication_guard()
        .expect("GC exclusion");
    FindingReplayCaptureStore::publish_set(&guard, &prepared).expect("publish capture set");
    let loaded = FindingReplayCaptureStore::load_set(&guard, prepared.references())
        .expect("load capture set");
    assert_eq!(
        loaded[0],
        LoadedFindingReplayCapture::Complete {
            bytes: bytes.clone(),
            content_hash,
        }
    );
    assert_eq!(loaded[0], loaded[1]);
}

#[test]
fn repeated_full_size_chunk_positions_round_trip_one_shared_blob() {
    let temporary = tempfile::tempdir().expect("capture directory");
    let executor = executor_store(temporary.path());
    let bytes = vec![0x5a; 2 * MAX_CAPTURE_CHUNK_BYTES];
    let content_hash = ContentHash::from_bytes(&bytes);
    let prepared = FindingReplayCaptureStore::prepare_set([
        FindingReplayCaptureInput::Complete {
            bytes,
            content_hash,
        },
        incomplete(),
        incomplete(),
        incomplete(),
    ])
    .expect("prepare repeated chunks");

    assert_eq!(prepared.chunks.len(), 1);
    let root = prepared
        .references()
        .minimization_original()
        .evidence()
        .expect("complete root");
    let manifest = prepared
        .manifests
        .get(&root.content_id())
        .expect("prepared manifest")
        .read_all(MAX_CAPTURE_MANIFEST_BYTES as u64)
        .expect("manifest bytes");
    let manifest = ContentEnvelope::from_canonical_bytes(&manifest).expect("manifest envelope");
    assert_eq!(manifest.children().len(), 2);

    let guard = executor
        .acquire_finding_replay_publication_guard()
        .expect("GC exclusion");
    FindingReplayCaptureStore::publish_set(&guard, &prepared).expect("publish repeated chunks");
    drop(prepared);
    let loaded = FindingReplayCaptureStore::load_set(
        &guard,
        FindingReplayCaptureSet::new(
            FindingReplayCaptureReference::Complete(root),
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
    .expect("load repeated chunks");
    let LoadedFindingReplayCapture::Complete { bytes, .. } = &loaded[0] else {
        panic!("first capture should be complete");
    };
    assert_eq!(bytes.len(), 2 * MAX_CAPTURE_CHUNK_BYTES);
    assert!(bytes.iter().all(|byte| *byte == 0x5a));
}

#[test]
fn load_rejects_a_manifest_with_a_missing_chunk() {
    let temporary = tempfile::tempdir().expect("capture directory");
    let executor = executor_store(temporary.path());
    let bytes = b"capture whose child is deliberately absent".to_vec();
    let prepared = FindingReplayCaptureStore::prepare_set([
        FindingReplayCaptureInput::Complete {
            content_hash: ContentHash::from_bytes(&bytes),
            bytes,
        },
        incomplete(),
        incomplete(),
        incomplete(),
    ])
    .expect("prepare capture");
    let root = prepared
        .references()
        .minimization_original()
        .evidence()
        .expect("complete root");
    let manifest = prepared
        .manifests
        .get(&root.content_id())
        .expect("prepared manifest");

    let guard = executor
        .acquire_finding_replay_publication_guard()
        .expect("GC exclusion");
    guard
        .put_finding_replay_capture_object(root.content_id(), manifest)
        .expect("publish only manifest");

    let error = FindingReplayCaptureStore::load_set(&guard, prepared.references())
        .expect_err("missing child must fail closed");
    assert!(matches!(
        error,
        FindingReplayCaptureStoreError::Repository(_)
    ));
}
