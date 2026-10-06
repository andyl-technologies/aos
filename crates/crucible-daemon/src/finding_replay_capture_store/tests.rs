//! Regression coverage for chunked finding replay capture persistence.

// crucible-lint: allow panic-shortcut -- focused storage fixtures use panic shortcuts for exact failure localization.
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

    drop(guard);
    let reopened = repository(temporary.path());
    let imported =
        FindingReplayCaptureStore::load_set_from_repository(&reopened, prepared.references())
            .expect("load retained capture set without publication authority");
    assert_eq!(imported, loaded);
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

#[test]
fn publication_handoff_keeps_actual_ref_inventory_excluded_until_final_close() {
    use crucible_cas::content_store::RefStoreAdmin;
    use std::sync::mpsc;
    use std::time::Duration;

    let temporary = tempfile::tempdir().expect("actual publication directory");
    let refs = Arc::new(DirectoryRefBackend::new(temporary.path().join("refs")));
    let executor = CampaignExecutorStore::new(Arc::new(CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "publication-handoff",
            temporary.path().join("objects"),
        )),
        refs.clone(),
    )));
    let publication = executor
        .acquire_finding_replay_publication_guard()
        .expect("actual shared inventory exclusion");
    let retained = publication.into_gc_exclusion();
    let (started, observed_start) = mpsc::channel();
    let (finished, observed_finish) = mpsc::channel();
    let inventory = std::thread::spawn(move || {
        started.send(()).expect("notify actual inventory attempt");
        let _exclusive = refs
            .acquire_ref_inventory_fence()
            .expect("actual exclusive ref inventory");
        finished.send(()).expect("notify acquired inventory");
    });

    observed_start
        .recv_timeout(Duration::from_secs(5))
        .expect("inventory thread starts");
    assert!(
        matches!(
            observed_finish.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "converting publication authority must not open an inventory gap"
    );
    drop(retained);

    observed_finish
        .recv_timeout(Duration::from_secs(5))
        .expect("final close permits real inventory");
    inventory.join().expect("bounded inventory worker joined");
}

#[test]
fn original_publication_cancellation_preserves_partial_objects_without_manifest_success() {
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    let directory = tempfile::tempdir().expect("capture publication directory");
    let executor = executor_store(directory.path());
    let bytes = b"actual immutable partial capture".to_vec();
    let prepared = FindingReplayCaptureStore::prepare_set([
        FindingReplayCaptureInput::Complete {
            content_hash: ContentHash::from_bytes(&bytes),
            bytes,
        },
        incomplete(),
        incomplete(),
        incomplete(),
    ])
    .expect("bounded capture candidate");
    let publication = executor
        .acquire_finding_replay_publication_guard()
        .expect("actual GC exclusion");
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(std::time::Duration::from_secs(30)),
    )
    .expect("explicit original component scope");
    let operation = supervisor
        .begin(HostOperationClass::CheckpointPublication)
        .expect("original publication operation");
    let mut boundaries = 0;
    let error =
        FindingReplayCaptureStore::publish_set_with_boundary(&publication, &prepared, &mut || {
            boundaries += 1;
            if boundaries == 3 {
                supervisor
                    .cancel()
                    .expect("cancel original scope after first chunk placement");
            }
            operation
                .wait_slice()
                .map(|_| ())
                .map_err(FindingReplayCaptureStoreError::from)
        })
        .expect_err("post-write cancellation refuses manifest publication success");
    assert!(matches!(
        error,
        FindingReplayCaptureStoreError::Supervision(_)
    ));
    for id in prepared.chunks.keys() {
        publication
            .read_finding_replay_capture_object(*id)
            .expect("placed child remains immutable");
    }
    for id in prepared.manifests.keys() {
        assert!(
            publication.read_finding_replay_capture_object(*id).is_err(),
            "complete manifest must remain unpublished"
        );
    }
    assert!(
        operation.wait_slice().is_err(),
        "retry cannot renew the canceled original cap"
    );
}
