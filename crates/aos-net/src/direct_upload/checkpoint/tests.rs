//! Actual private-file retry, atomic rollback and restart-custody regressions.

use std::os::unix::fs::{PermissionsExt as _, symlink};

use aos_proto_types::direct_upload::*;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::direct_upload::{
    DirectCheckpointStore, DirectGrantAttempt, DirectObservedPart, DirectPartReceipt,
};

fn directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn intent(number: u64) -> DirectUploadIntent {
    DirectUploadIntent {
        version: 1,
        client_operation_id: format!("{number:064x}"),
        target: DirectUploadTarget::CacheObject {
            cache_id: "cache-1".into(),
            path: format!("nar/{number}.nar"),
        },
        expected_sha256: hex::encode(Sha256::digest(b"abc")),
        byte_size: WireInteger::new(3),
        part_size: WireInteger::new(8 * 1024 * 1024),
        dependency_phase: DirectDependencyPhase::Content,
        transfer_mode: DirectTransferMode::DirectRequired,
    }
}

fn status(number: u64) -> DirectSessionStatus {
    DirectSessionStatus {
        session: DirectSessionRef {
            session_id: format!("session-{number}"),
            logical_fingerprint: format!("{number:064x}"),
        },
        resource_version: WireInteger::new(1),
        intent: intent(number),
        placements: vec![DirectPlacementRef {
            placement_id: WireInteger::new(1),
            placement_fingerprint: "ab".repeat(32),
            placement_resource_version: WireInteger::new(1),
            write_spec_version: WireInteger::new(1),
            binding_id: WireInteger::new(1),
            binding_resource_version: WireInteger::new(1),
            binding_write_revision: WireInteger::new(1),
            profile_fingerprint: "cd".repeat(32),
            private_policy_digest: "ef".repeat(32),
            checksum_algorithm: DirectChecksumAlgorithm::Sha256,
        }],
        state: DirectSessionState::Active,
        parts: vec![],
        next_cursor: None,
        outstanding_grants: false,
    }
}

fn part() -> DirectManifestPart {
    let digest = Sha256::digest(b"abc");
    DirectManifestPart {
        part: DirectPart {
            part_number: 1,
            offset: WireInteger::new(0),
            byte_size: WireInteger::new(3),
            sha256: hex::encode(digest),
            checksum: DirectPartChecksum {
                algorithm: DirectChecksumAlgorithm::Sha256,
                value: base64::engine::general_purpose::STANDARD.encode(digest),
            },
        },
        etag: "\"abc\"".into(),
    }
}

async fn admitted(store: &SqliteDirectCheckpoints, number: u64) -> DirectSessionStatus {
    let status = status(number);
    store.admit_intent(&status.intent).await.unwrap();
    store.admit_session(&status).await.unwrap();
    status
}

fn attempt(status: &DirectSessionStatus, refresh: bool) -> DirectGrantAttempt {
    DirectGrantAttempt {
        session: status.session.clone(),
        placement: status.placements[0].clone(),
        part_number: 1,
        refresh,
    }
}

fn complete(status: &DirectSessionStatus) -> DirectCompleteRequest {
    DirectCompleteRequest {
        session: status.session.clone(),
        operation_id: "cc".repeat(32),
        expected_resource_version: WireInteger::new(1),
        manifests: vec![DirectManifestCommitment {
            placement: status.placements[0].clone(),
            manifest_digest: canonical_manifest_digest(
                &status.intent,
                &status.placements[0],
                &[part()],
            )
            .unwrap(),
            part_count: 1,
        }],
    }
}

#[tokio::test]
async fn restart_retains_attempt_receipt_observation_and_original_complete() {
    let directory = directory();
    let path = directory.path().join("direct.sqlite");
    let namespace = "11".repeat(32);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, true)
        .await
        .unwrap();
    let run_id = store.run_id().to_owned();
    let status = admitted(&store, 1).await;
    assert_eq!(
        store
            .grant_attempts(&[attempt(&status, false)])
            .await
            .unwrap(),
        [1]
    );
    assert_eq!(
        store
            .grant_attempts(&[attempt(&status, true)])
            .await
            .unwrap(),
        [2]
    );
    let receipt = DirectPartReceipt {
        session: status.session.clone(),
        placement: status.placements[0].clone(),
        grant_id: "aa".repeat(32),
        grant_revision: WireInteger::new(2),
        observed: part(),
    };
    store.record_receipt(&receipt).await.unwrap();
    store
        .record_server_parts(&[DirectObservedPart {
            session: status.session.clone(),
            placement: status.placements[0].clone(),
            observed: part(),
        }])
        .await
        .unwrap();
    let original = complete(&status);
    store.admit_complete(&original).await.unwrap();
    drop(store);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, false)
        .await
        .unwrap();
    assert_eq!(store.run_id(), run_id);
    assert_eq!(
        store
            .grant_attempts(&[attempt(&status, false)])
            .await
            .unwrap(),
        [2]
    );
    assert_eq!(
        store
            .receipt(&status.session, &status.placements[0], 1)
            .await
            .unwrap(),
        Some(receipt)
    );
    assert_eq!(
        store
            .observed_part(&status.session, &status.placements[0], 1)
            .await
            .unwrap(),
        Some(part())
    );
    let mut progressed = original.clone();
    progressed.expected_resource_version = WireInteger::new(9);
    assert_eq!(store.admit_complete(&progressed).await.unwrap(), original);
    progressed.manifests[0].manifest_digest = "ff".repeat(32);
    assert_eq!(
        store.admit_complete(&progressed).await,
        Err(DirectClientError::Checkpoint)
    );
}

#[tokio::test]
async fn changed_item_rolls_back_entire_intent_wave() {
    let directory = directory();
    let path = directory.path().join("direct.sqlite");
    let store = SqliteDirectCheckpoints::open(&path, &"11".repeat(32), true)
        .await
        .unwrap();
    store.admit_intent(&intent(2)).await.unwrap();
    let mut changed = intent(2);
    changed.target = DirectUploadTarget::CacheObject {
        cache_id: "other".into(),
        path: "nar/2.nar".into(),
    };
    assert_eq!(
        store.admit_intents(&[intent(1), changed]).await,
        Err(DirectClientError::Checkpoint)
    );
    // The first entry was never committed merely because it preceded refusal.
    let mut different = intent(1);
    different.expected_sha256 = "ff".repeat(32);
    store.admit_intent(&different).await.unwrap();
}

#[tokio::test]
async fn grant_wave_rollback_cannot_expose_uncommitted_attempts() {
    let directory = directory();
    let path = directory.path().join("direct.sqlite");
    let store = SqliteDirectCheckpoints::open(&path, &"11".repeat(32), true)
        .await
        .unwrap();
    let first = admitted(&store, 1).await;
    let second = admitted(&store, 2).await;
    assert_eq!(
        store
            .grant_attempts(&[attempt(&first, false)])
            .await
            .unwrap(),
        [1]
    );
    let mut bad = attempt(&second, false);
    bad.placement.binding_write_revision = WireInteger::new(8);
    assert_eq!(
        store.grant_attempts(&[attempt(&first, true), bad]).await,
        Err(DirectClientError::Checkpoint)
    );
    drop(store);
    let store = SqliteDirectCheckpoints::open(&path, &"11".repeat(32), false)
        .await
        .unwrap();
    assert_eq!(
        store
            .grant_attempts(&[attempt(&first, false), attempt(&second, false)])
            .await
            .unwrap(),
        [1, 1]
    );
}

#[tokio::test]
async fn exact_64_intent_wave_replays_and_excessive_wave_refuses() {
    let directory = directory();
    let path = directory.path().join("direct.sqlite");
    let store = SqliteDirectCheckpoints::open(&path, &"11".repeat(32), true)
        .await
        .unwrap();
    let wave: Vec<_> = (1..=64).map(intent).collect();
    store.admit_intents(&wave).await.unwrap();
    store.admit_intents(&wave).await.unwrap();
    let excessive: Vec<_> = (1..=65).map(intent).collect();
    assert_eq!(
        store.admit_intents(&excessive).await,
        Err(DirectClientError::Checkpoint)
    );
}

#[tokio::test]
async fn changed_session_placement_source_and_duplicate_refresh_refuse() {
    let directory = directory();
    let path = directory.path().join("direct.sqlite");
    let store = SqliteDirectCheckpoints::open(&path, &"11".repeat(32), true)
        .await
        .unwrap();
    let original = admitted(&store, 1).await;
    let mut replacement = original.clone();
    replacement.session.session_id = "replacement".into();
    assert_eq!(
        store.admit_session(&replacement).await,
        Err(DirectClientError::Checkpoint)
    );
    let mut changed = original.clone();
    changed.placements[0].profile_fingerprint = "00".repeat(32);
    assert_eq!(
        store.admit_session(&changed).await,
        Err(DirectClientError::Checkpoint)
    );
    let mut changed = original.intent.clone();
    changed.expected_sha256 = "ff".repeat(32);
    assert_eq!(
        store.admit_intent(&changed).await,
        Err(DirectClientError::Checkpoint)
    );
    assert_eq!(
        store
            .grant_attempts(&[attempt(&original, true), attempt(&original, true)])
            .await,
        Err(DirectClientError::Checkpoint)
    );
    assert_eq!(
        store
            .grant_attempts(&[attempt(&original, false)])
            .await
            .unwrap(),
        [1]
    );
}

#[tokio::test]
async fn private_modes_links_and_symlinks_are_not_adopted() {
    let directory = directory();
    let path = directory.path().join("direct.sqlite");
    let namespace = "11".repeat(32);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, true)
        .await
        .unwrap();
    drop(store);
    let alias = directory.path().join("alias");
    symlink(&path, &alias).unwrap();
    assert!(
        SqliteDirectCheckpoints::open(&alias, &namespace, false)
            .await
            .is_err()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(
        SqliteDirectCheckpoints::open(&path, &namespace, false)
            .await
            .is_err()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&path, directory.path().join("hard")).unwrap();
    assert!(
        SqliteDirectCheckpoints::open(&path, &namespace, false)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn missing_unknown_and_wrong_namespace_never_initialize_or_migrate() {
    let directory = directory();
    let path = directory.path().join("direct.sqlite");
    let namespace = "11".repeat(32);
    assert!(
        SqliteDirectCheckpoints::open(&path, &namespace, false)
            .await
            .is_err()
    );
    assert!(!path.exists());
    let store = SqliteDirectCheckpoints::open(&path, &namespace, true)
        .await
        .unwrap();
    drop(store);
    assert!(
        SqliteDirectCheckpoints::open(&path, &"22".repeat(32), false)
            .await
            .is_err()
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("CREATE TABLE unknown(secret TEXT)", [])
        .unwrap();
    drop(connection);
    let before = std::fs::read(&path).unwrap();
    assert!(
        SqliteDirectCheckpoints::open(&path, &namespace, false)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[tokio::test]
async fn retained_file_or_directory_replacement_blocks_future_waves() {
    let directory = directory();
    let path = directory.path().join("direct.sqlite");
    let namespace = "11".repeat(32);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, true)
        .await
        .unwrap();
    std::fs::rename(&path, directory.path().join("old.sqlite")).unwrap();
    std::fs::write(&path, b"foreign-private-canary").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        store.admit_intent(&intent(1)).await,
        Err(DirectClientError::Checkpoint)
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"foreign-private-canary");
}

#[tokio::test]
async fn receipt_wave_is_atomic_and_debug_errors_are_value_free() {
    let directory = directory();
    let path = directory.path().join("direct.sqlite");
    let store = SqliteDirectCheckpoints::open(&path, &"11".repeat(32), true)
        .await
        .unwrap();
    let status = admitted(&store, 1).await;
    store
        .grant_attempts(&[attempt(&status, false)])
        .await
        .unwrap();
    let first = DirectPartReceipt {
        session: status.session.clone(),
        placement: status.placements[0].clone(),
        grant_id: "aa".repeat(32),
        grant_revision: WireInteger::new(1),
        observed: part(),
    };
    let mut changed = first.clone();
    changed.grant_id = "private-signed-url-canary".into();
    let error = store.record_receipts(&[first, changed]).await.unwrap_err();
    assert!(!format!("{store:?} {error:?} {error}").contains("private-signed-url-canary"));
    assert_eq!(
        store
            .receipt(&status.session, &status.placements[0], 1)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn completion_pages_are_bounded_exact_and_exclusive_journal_custody_is_retained() {
    let directory = directory();
    let path = directory.path().join("direct.sqlite");
    let namespace = "11".repeat(32);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, true)
        .await
        .unwrap();
    assert!(
        SqliteDirectCheckpoints::open(&path, &namespace, false)
            .await
            .is_err()
    );
    for number in 1..=65 {
        let status = admitted(&store, number).await;
        store.admit_complete(&complete(&status)).await.unwrap();
    }
    let first = store.completion_page(None, 64).await.unwrap();
    assert_eq!(first.items.len(), 64);
    assert!(first.items.iter().all(|item| {
        item.intent
            == intent(
                item.request
                    .session
                    .session_id
                    .trim_start_matches("session-")
                    .parse()
                    .unwrap(),
            )
    }));
    let second = store
        .completion_page(first.next_after.as_deref(), 64)
        .await
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert!(second.next_after.is_none());
    assert!(
        !first
            .items
            .iter()
            .any(|item| item.request.session == second.items[0].request.session)
    );
    assert!(store.completion_page(None, 65).await.is_err());
    assert!(
        store
            .completion_page(Some("https://private-canary"), 64)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn retained_completion_lookup_preserves_original_identity_after_restart() {
    let directory = directory();
    let path = directory.path().join("direct.sqlite");
    let namespace = "33".repeat(32);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, true)
        .await
        .unwrap();
    let first = admitted(&store, 1).await;
    let original = store.admit_complete(&complete(&first)).await.unwrap();
    let second = intent(2);
    store.admit_intent(&second).await.unwrap();
    drop(store);

    let store = SqliteDirectCheckpoints::open(&path, &namespace, false)
        .await
        .unwrap();
    let found = store
        .retained_completions(&[first.intent.clone(), second.clone()])
        .await
        .unwrap();
    assert_eq!(found[0].as_ref().unwrap().request, original);
    assert_eq!(found[0].as_ref().unwrap().intent, first.intent);
    assert!(found[1].is_none());

    let mut changed = second.clone();
    changed.expected_sha256 = "aa".repeat(32);
    assert!(store.retained_completions(&[changed]).await.is_err());
    assert!(
        store
            .retained_completions(&[second.clone(), second])
            .await
            .is_err()
    );
}

#[test]
fn directory_admission_creates_private_levels_and_refuses_link_or_writable_ancestors() {
    use std::os::unix::fs::MetadataExt as _;

    let directory = directory();
    let path = directory.path().join("run/state");
    let admitted = super::ensure_private_checkpoint_directory(&path);
    let root_owner = std::fs::metadata("/").unwrap().uid();
    if ![0, rustix::process::geteuid().as_raw()].contains(&root_owner) {
        // A foreign sandbox root cannot establish trusted absolute ancestry.
        assert_eq!(admitted, Err(DirectClientError::Checkpoint));
        assert!(!path.exists());
        return;
    }

    admitted.unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let link = directory.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(super::ensure_private_checkpoint_directory(&link.join("child")).is_err());
    let writable = directory.path().join("writable");
    std::fs::create_dir(&writable).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(super::ensure_private_checkpoint_directory(&writable.join("child")).is_err());
    assert!(!writable.join("child").exists());
}

fn publication_header() -> DirectPublicationHeader {
    DirectPublicationHeader {
        registry: "registry-1".into(),
        registry_stable_id: "original-registry-uuid".into(),
        deployment_id: "deployment".into(),
        principal_id: "ee".repeat(32),
        generation: "31".repeat(32),
        refs_digest: "32".repeat(32),
        default_commit: "33".repeat(32),
        parent_publication_id: "previous-publication".into(),
        manifest_digest: "34".repeat(32),
        object_count: 12_535,
    }
}

fn publication_session() -> aos_proto_types::RegistryPublicationManifestSession {
    aos_proto_types::RegistryPublicationManifestSession {
        publication_id: "original-publication".into(),
        lease_token: "private-lease-canary".into(),
        manifest_digest: "34".repeat(32),
        object_count: 12_535,
        admitted_object_count: 64,
        next_chunk_index: 1,
        state: "accepting".into(),
        lease_expires_at: 100,
    }
}

#[tokio::test]
async fn publication_before_effect_header_survives_restart_and_refuses_changed_inventory_parent() {
    let directory = directory();
    let path = directory.path().join("publication.sqlite");
    let namespace = "12".repeat(32);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, true)
        .await
        .unwrap();
    let original = publication_header();
    store.retain_publication_header(&original).await.unwrap();
    drop(store);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, false)
        .await
        .unwrap();
    assert_eq!(
        store.publication_header().await.unwrap(),
        Some(original.clone())
    );
    for changed in [
        DirectPublicationHeader {
            parent_publication_id: "different-parent".into(),
            ..original.clone()
        },
        DirectPublicationHeader {
            manifest_digest: "35".repeat(32),
            ..original.clone()
        },
        DirectPublicationHeader {
            registry: "different-owner".into(),
            ..original.clone()
        },
        DirectPublicationHeader {
            registry_stable_id: "different-registry-incarnation".into(),
            ..original.clone()
        },
        DirectPublicationHeader {
            deployment_id: "different-deployment".into(),
            ..original.clone()
        },
        DirectPublicationHeader {
            principal_id: "ab".repeat(32),
            ..original.clone()
        },
    ] {
        assert!(store.retain_publication_header(&changed).await.is_err());
        assert_eq!(
            store.publication_header().await.unwrap(),
            Some(original.clone())
        );
    }
}

#[tokio::test]
async fn publication_admission_retains_exact_owner_monotonic_progress_private_lease_and_sealed_fence()
 {
    let directory = directory();
    let path = directory.path().join("publication.sqlite");
    let namespace = "13".repeat(32);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, true)
        .await
        .unwrap();
    let initial = publication_session();
    assert!(store.retain_publication_admission(&initial).await.is_err());
    store
        .retain_publication_header(&publication_header())
        .await
        .unwrap();
    let retained = store.retain_publication_admission(&initial).await.unwrap();
    assert!(!format!("{retained:?}").contains("private-lease-canary"));
    let mut progress = initial.clone();
    progress.admitted_object_count = 128;
    progress.next_chunk_index = 2;
    progress.lease_token = "rotated-private-lease-canary".into();
    progress.lease_expires_at = 200;
    store.retain_publication_admission(&progress).await.unwrap();
    drop(store);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, false)
        .await
        .unwrap();
    assert!(store.retain_publication_admission(&initial).await.is_err());
    let changed = aos_proto_types::RegistryPublicationManifestSession {
        publication_id: "second-owner".into(),
        ..progress.clone()
    };
    assert!(store.retain_publication_admission(&changed).await.is_err());
    progress.admitted_object_count = progress.object_count;
    progress.next_chunk_index = 196;
    progress.state = "sealed".into();
    let sealed = store.retain_publication_admission(&progress).await.unwrap();
    assert_eq!(sealed.reply(), progress);
    let changed = aos_proto_types::RegistryPublicationManifestSession {
        lease_token: "replacement-after-seal".into(),
        ..progress.clone()
    };
    assert!(store.retain_publication_admission(&changed).await.is_err());
    assert_eq!(
        store
            .retain_publication_admission(&progress)
            .await
            .unwrap()
            .reply(),
        progress
    );
}

#[tokio::test]
async fn oci_logical_allocation_unknown_reply_reuses_operation_and_refuses_second_owner_or_changed_source()
 {
    let directory = directory();
    let path = directory.path().join("oci.sqlite");
    let namespace = "14".repeat(32);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, true)
        .await
        .unwrap();
    let sha = "45".repeat(32);
    let original = store.prepare_oci_allocation(&sha, 123).await.unwrap();
    assert!(original.upload_id.is_none());
    drop(store);
    let store = SqliteDirectCheckpoints::open(&path, &namespace, false)
        .await
        .unwrap();
    assert_eq!(
        store.prepare_oci_allocation(&sha, 123).await.unwrap(),
        original
    );
    assert!(store.prepare_oci_allocation(&sha, 124).await.is_err());
    let admitted = store
        .retain_oci_allocation(&original, "original-upload")
        .await
        .unwrap();
    assert_eq!(admitted.upload_id.as_deref(), Some("original-upload"));
    assert!(
        store
            .retain_oci_allocation(&original, "second-upload")
            .await
            .is_err()
    );
    assert_eq!(
        store.prepare_oci_allocation(&sha, 123).await.unwrap(),
        admitted
    );
    let changed = DirectOciAllocation {
        operation_id: "ff".repeat(32),
        ..original.clone()
    };
    assert!(
        store
            .retain_oci_allocation(&changed, "original-upload")
            .await
            .is_err()
    );
}
