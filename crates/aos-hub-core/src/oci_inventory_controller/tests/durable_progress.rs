//! Durable single-page recovery through actual controller and SQLite CAS.

use super::*;

#[tokio::test]
async fn second_page_partial_state_survives_database_and_controller_reopen() {
    for limits in [
        NATIVE_OCI_INVENTORY_DISPATCH_BUDGET,
        WORKER_OCI_INVENTORY_DISPATCH_BUDGET,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inventory.db");
        let (pages, objects) = two_page_inventory();
        let first_size = objects[&pages[0].paths[0]].len() as u64;
        let second_size = objects[&pages[1].paths[0]].len() as u64;
        let db = Arc::new(Database::open(&path).await.unwrap());
        let (db, _, placement, provider) = inventory_fixture_with_db(db, pages, objects).await;
        let now = crate::clock::now_unix_secs();
        let controller = OciProviderInventoryController::new(db.clone(), provider.clone());
        let budget = OciInventoryDispatchBudget {
            max_bytes: first_size + 1,
            max_chunk_bytes: first_size + 1,
            max_pages: 2,
            max_objects: 2,
            max_chunks: 2,
            ..limits
        };
        let first = controller
            .run_due_bounded("worker", "restart", now, 1, None, budget)
            .await
            .unwrap();
        assert_eq!(first.completed, 0);
        let current = db
            .active_oci_provider_inventory(placement.id)
            .await
            .unwrap()
            .unwrap();
        let durable = current.object_progress.clone().unwrap();
        assert_eq!(current.checkpoint_ordinal, 1);
        assert_eq!(current.provider_cursor.as_deref(), Some("oci-blobs-v1:1"));
        assert_eq!(durable.object.provider_cursor, current.provider_cursor);
        assert_eq!(durable.object.next_offset, 1);
        assert_eq!(durable.next_provider_cursor, None);
        let generation_id = current.id.clone();
        drop(controller);
        drop(db);

        // The process loses its volatile cursor. SQL reopens the original
        // tagged page under a fresh collector claim after the old lease ends.
        let reopened = Arc::new(Database::open(&path).await.unwrap());
        let controller = OciProviderInventoryController::new(reopened.clone(), provider.clone());
        let resumed = controller
            .run_due_bounded(
                "restarted",
                "new-token",
                now + INVENTORY_CLAIM_LEASE_SECONDS + 1,
                1,
                None,
                limits,
            )
            .await
            .unwrap();
        assert_eq!((resumed.completed, resumed.failed), (1, 0));
        let sealed = reopened
            .oci_provider_inventory_generation(&generation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sealed.checkpoint_ordinal, 2);
        assert_eq!(sealed.object_count, 2);
        assert_eq!(sealed.byte_count, first_size + second_size);
        assert_eq!(sealed.object_progress, None);
        assert_eq!(
            *provider.fetch.requested_cursors.lock().unwrap(),
            vec![None, Some("1".into()), Some("1".into())]
        );
        let ranges = provider.fetch.requested_ranges.lock().unwrap();
        assert_eq!(ranges[2].0, 1);
        assert!(
            provider
                .fetch
                .requested_prefixes
                .lock()
                .unwrap()
                .iter()
                .all(|prefix| prefix == OCI_BLOB_KEY_PREFIX)
        );
    }
}

#[tokio::test]
async fn exact_progress_lost_ack_is_observed_but_stale_heartbeat_and_new_claim_refuse() {
    progress_cas_on(Arc::new(Database::open_in_memory().await.unwrap())).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires a dedicated disposable PostgreSQL 18 inventory database"]
async fn postgres_binary_progress_cas_preserves_exact_postimages_and_claim_fences() {
    let path = std::env::var_os("AOS_PG_INVENTORY_TEST_URL_FILE").expect("private PG URL file");
    let url = std::fs::read_to_string(path).unwrap();
    let db = Arc::new(Database::connect(url.trim()).await.unwrap());
    progress_cas_on(db).await;
}

async fn progress_cas_on(db: Arc<Database>) {
    let bytes = b"durable source".to_vec();
    let digest = Sha256Digest::digest(&bytes);
    let key = format!("oci/blobs/sha256/{}", digest.encoded());
    let pages = vec![SurfaceListPage {
        paths: vec![key.clone()],
        evidence: BTreeMap::new(),
        next_cursor: None,
    }];
    let (db, _, placement, provider) =
        inventory_fixture_with_db(db, pages, BTreeMap::from([(key, bytes.clone())])).await;
    let now = crate::clock::now_unix_secs();
    let controller = OciProviderInventoryController::new(db.clone(), provider);
    controller
        .run_due_bounded(
            "worker",
            "ack",
            now,
            1,
            None,
            test_dispatch_budget(1, 1, 1, Duration::from_secs(5)),
        )
        .await
        .unwrap();
    let prior = db
        .active_oci_provider_inventory(placement.id)
        .await
        .unwrap()
        .unwrap();
    let fresh = db
        .claim_oci_provider_inventory(
            &prior.id,
            "worker",
            &prior.collector_claim_token,
            now + 1,
            60,
        )
        .await
        .unwrap();
    let mut next = fresh.object_progress.clone().unwrap();
    let mut state = next.object.sha_state().unwrap();
    state.update(&bytes[1..2]).unwrap();
    next.object.next_offset = 2;
    next.object.set_sha_state(&state).unwrap();

    assert!(
        db.persist_oci_inventory_progress(&prior, &next, now + 1)
            .await
            .is_err()
    );
    let committed = db
        .persist_oci_inventory_progress(&fresh, &next, now + 1)
        .await
        .unwrap();
    let replayed = db
        .persist_oci_inventory_progress(&fresh, &next, now + 1)
        .await
        .unwrap();
    assert_eq!(replayed, committed);
    assert_eq!(
        replayed.collector_lease_expires_at,
        fresh.collector_lease_expires_at
    );

    db.claim_oci_provider_inventory(&fresh.id, "new-owner", "new-claim", now + 62, 60)
        .await
        .unwrap();
    assert!(
        db.persist_oci_inventory_progress(&fresh, &next, now + 62)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn completed_object_append_atomically_clears_progress_and_replays_exact_page() {
    let bytes = b"durable source".to_vec();
    let digest = Sha256Digest::digest(&bytes);
    let key = format!("oci/blobs/sha256/{}", digest.encoded());
    let pages = vec![SurfaceListPage {
        paths: vec![key.clone()],
        evidence: BTreeMap::new(),
        next_cursor: None,
    }];
    let (db, _, placement, provider) =
        inventory_fixture(pages, BTreeMap::from([(key.clone(), bytes.clone())])).await;
    let now = crate::clock::now_unix_secs();
    let controller = OciProviderInventoryController::new(db.clone(), provider);
    controller
        .run_due_bounded(
            "worker",
            "append",
            now,
            1,
            None,
            test_dispatch_budget(1, 1, 1, Duration::from_secs(5)),
        )
        .await
        .unwrap();
    let prior = db
        .active_oci_provider_inventory(placement.id)
        .await
        .unwrap()
        .unwrap();
    let fresh = db
        .claim_oci_provider_inventory(
            &prior.id,
            "worker",
            &prior.collector_claim_token,
            now + 1,
            60,
        )
        .await
        .unwrap();
    let mut complete = fresh.object_progress.clone().unwrap();
    let mut state = complete.object.sha_state().unwrap();
    state.update(&bytes[1..]).unwrap();
    complete.object.next_offset = bytes.len() as u64;
    complete.object.set_sha_state(&state).unwrap();
    let ready = db
        .persist_oci_inventory_progress(&fresh, &complete, now + 1)
        .await
        .unwrap();
    let input = AppendOciProviderInventoryPage {
        generation_id: ready.id.clone(),
        collector_id: ready.collector_id.clone(),
        collector_claim_token: ready.collector_claim_token.clone(),
        expected_checkpoint_ordinal: 0,
        expected_provider_cursor: None,
        next_provider_cursor: None,
        last_listed_key: Some(key.clone()),
        entries: vec![OciProviderInventoryEntryInput {
            object_key: key,
            object_digest: digest,
            observed_hash: digest,
            byte_size: bytes.len() as u64,
            strong_etag: complete.object.strong_etag.clone(),
            provider_version: None,
        }],
        now: now + 1,
        lease_seconds: 60,
    };
    let mut changed = input.clone();
    changed.next_provider_cursor = Some("oci-blobs-v1:substituted".into());
    assert!(
        db.append_oci_provider_inventory_page(&changed)
            .await
            .is_err()
    );
    assert_eq!(
        db.oci_provider_inventory_generation(&ready.id)
            .await
            .unwrap()
            .unwrap(),
        ready
    );

    let appended = db.append_oci_provider_inventory_page(&input).await.unwrap();
    assert_eq!(appended.object_progress, None);
    assert_eq!(appended.checkpoint_ordinal, 1);
    assert_eq!(appended.object_count, 1);
    assert_eq!(
        db.append_oci_provider_inventory_page(&input).await.unwrap(),
        appended
    );
}

#[tokio::test]
async fn oversized_provider_page_refuses_without_partial_persistence() {
    let (_, objects) = two_page_inventory();
    let keys = objects.keys().cloned().collect();
    let bad_page = SurfaceListPage {
        paths: keys,
        evidence: BTreeMap::new(),
        next_cursor: None,
    };
    let (db, _, placement, provider) = inventory_fixture(vec![bad_page], objects).await;
    let controller = OciProviderInventoryController::new(db.clone(), provider);
    let result = controller
        .run_due("worker", "overflow", crate::clock::now_unix_secs(), 1)
        .await
        .unwrap();

    assert_eq!((result.completed, result.failed), (0, 1));
    assert!(
        db.active_oci_provider_inventory(placement.id)
            .await
            .unwrap()
            .is_none()
    );
}
