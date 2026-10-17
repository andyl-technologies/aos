//! Actual TLS custody RPC counts, independent cohorts and current SQL refusal.

use super::*;

#[tokio::test]
async fn concurrent_reads_coalesce_and_sql_rotation_refuses_cached_acknowledgement() {
    let _gate = TLS_TEST_GATE.lock().await;
    let fixture = fixture().await;
    let binding = fixture
        .db
        .binding(fixture.binding_id)
        .await
        .unwrap()
        .unwrap();
    let (client, _, controls, server) = custody_client(&fixture, CustodyFault::None).await;

    let results = futures_util::future::join_all(
        (0..64).map(|_| client.ensure_remote_binding_snapshot(&fixture.db, &binding)),
    )
    .await;
    assert!(results.into_iter().all(|result| result.is_ok()));
    assert_eq!(controls.adoptions.load(Ordering::SeqCst), 1);
    assert_eq!(controls.peak_adoptions.load(Ordering::SeqCst), 1);

    // A real new, unvalidated head cannot use the still-fresh older proof.
    queue_read(&fixture).await;
    assert!(client
        .ensure_remote_binding_snapshot(&fixture.db, &binding)
        .await
        .is_err());
    assert_eq!(controls.adoptions.load(Ordering::SeqCst), 1);
    assert_eq!(controls.revokes.load(Ordering::SeqCst), 1);
    assert!(client.acknowledged_binding_snapshot(binding.id).is_err());
    server.abort();
    std::env::remove_var("SSL_CERT_FILE");
}

#[tokio::test]
async fn independent_bindings_refresh_concurrently_without_client_wide_gate() {
    let _gate = TLS_TEST_GATE.lock().await;
    let fixture = fixture().await;
    let first = fixture
        .db
        .binding(fixture.binding_id)
        .await
        .unwrap()
        .unwrap();
    let org = fixture
        .db
        .org_by_id(first.org_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    let second_id = fixture
        .db
        .create_topology_binding(
            first.org_id,
            "second-cohort",
            &org.stable_id,
            "Second cohort",
            "s3",
            None,
            Some("fixture-bucket"),
            Some("managed/second"),
            Some("https"),
            Some("dns"),
            Some(b"s3.fleet.test"),
            Some(443),
            Some("fixture-region"),
            Some("private"),
        )
        .await
        .unwrap();
    for purpose in ["presign", "read", "write"] {
        let revision = fixture
            .db
            .set_binding_credential_revision(
                second_id,
                purpose,
                &format!("secret://bootstrap/second/{purpose}/v1"),
                0,
                &hex::encode(Sha256::digest(MATERIAL)),
                "operator",
            )
            .await
            .unwrap();
        fixture
            .db
            .validate_binding_credential_revision(
                second_id,
                purpose,
                revision.generation,
                "valid",
                None,
                revision.head_resource_version,
            )
            .await
            .unwrap();
    }
    let second = fixture.db.binding(second_id).await.unwrap().unwrap();
    let (client, _, controls, server) = custody_client(&fixture, CustodyFault::None).await;

    let (left, right) = tokio::join!(
        client.ensure_remote_binding_snapshot(&fixture.db, &first),
        client.ensure_remote_binding_snapshot(&fixture.db, &second),
    );
    left.unwrap();
    right.unwrap();
    assert_eq!(controls.adoptions.load(Ordering::SeqCst), 2);
    assert_eq!(controls.peak_adoptions.load(Ordering::SeqCst), 2);
    assert_ne!(
        client
            .acknowledged_binding_snapshot(first.id)
            .unwrap()
            .revision()
            .unwrap(),
        client
            .acknowledged_binding_snapshot(second.id)
            .unwrap()
            .revision()
            .unwrap()
    );
    server.abort();
    std::env::remove_var("SSL_CERT_FILE");
}

#[tokio::test]
async fn short_refresh_has_no_stale_fallback_and_explicit_revoke_invalidates_proof() {
    let _gate = TLS_TEST_GATE.lock().await;
    let fixture = fixture().await;
    let binding = fixture
        .db
        .binding(fixture.binding_id)
        .await
        .unwrap()
        .unwrap();
    let (client, _, controls, server) = custody_client(&fixture, CustodyFault::None).await;
    client
        .ensure_remote_binding_snapshot(&fixture.db, &binding)
        .await
        .unwrap();
    let original = client.acknowledged_binding_snapshot(binding.id).unwrap();
    client
        .ensure_remote_binding_snapshot(&fixture.db, &binding)
        .await
        .unwrap();
    assert_eq!(controls.adoptions.load(Ordering::SeqCst), 1);

    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    controls.refuse_adoption.store(true, Ordering::SeqCst);
    let denied = futures_util::future::join_all(
        (0..64).map(|_| client.ensure_remote_binding_snapshot(&fixture.db, &binding)),
    )
    .await;
    assert!(denied.into_iter().all(|result| result.is_err()));
    assert_eq!(controls.adoptions.load(Ordering::SeqCst), 2);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    controls.refuse_adoption.store(false, Ordering::SeqCst);
    client
        .ensure_remote_binding_snapshot(&fixture.db, &binding)
        .await
        .unwrap();
    assert_eq!(controls.adoptions.load(Ordering::SeqCst), 3);
    assert_eq!(
        client.acknowledged_binding_snapshot(binding.id).unwrap(),
        original
    );

    client
        .revoke_binding_snapshot(
            binding.id,
            &original.revision().unwrap(),
            aos_hub_core::clock::now_unix_secs(),
        )
        .await
        .unwrap();
    assert!(client.acknowledged_binding_snapshot(binding.id).is_err());
    assert!(client
        .ensure_remote_binding_snapshot(&fixture.db, &binding)
        .await
        .is_err());
    assert_eq!(controls.adoptions.load(Ordering::SeqCst), 4);
    server.abort();
    std::env::remove_var("SSL_CERT_FILE");
}

#[tokio::test]
async fn snapshot_expiry_margin_forces_fresh_challenge_before_refresh_window() {
    let _gate = TLS_TEST_GATE.lock().await;
    let fixture = fixture().await;
    let binding = fixture
        .db
        .binding(fixture.binding_id)
        .await
        .unwrap()
        .unwrap();
    let (client, _, controls, server) = custody_client(&fixture, CustodyFault::None).await;
    controls.short_lifetime.store(true, Ordering::SeqCst);
    client
        .ensure_remote_binding_snapshot(&fixture.db, &binding)
        .await
        .unwrap();
    client
        .ensure_remote_binding_snapshot(&fixture.db, &binding)
        .await
        .unwrap();
    assert_eq!(controls.adoptions.load(Ordering::SeqCst), 2);
    server.abort();
    std::env::remove_var("SSL_CERT_FILE");
}

#[tokio::test]
async fn explicit_revocation_serializes_with_in_flight_adoption() {
    let _gate = TLS_TEST_GATE.lock().await;
    let fixture = fixture().await;
    let binding = fixture
        .db
        .binding(fixture.binding_id)
        .await
        .unwrap()
        .unwrap();
    let (client, _, controls, server) = custody_client(&fixture, CustodyFault::None).await;
    controls.pause_adoption.store(true, Ordering::SeqCst);
    let adopting = tokio::spawn({
        let client = client.clone();
        let db = fixture.db.clone();
        let binding = binding.clone();
        async move { client.ensure_remote_binding_snapshot(&db, &binding).await }
    });
    controls.adoption_entered.notified().await;
    let original = controls.pending_snapshot.lock().await.clone().unwrap();
    let revoking = tokio::spawn({
        let client = client.clone();
        let revision = original.revision().unwrap();
        let id = binding.id;
        async move {
            client
                .revoke_binding_snapshot(
                    id,
                    &revision,
                    aos_hub_core::clock::now_unix_secs().max(original.issued_at + 1),
                )
                .await
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(!revoking.is_finished());
    assert_eq!(controls.revokes.load(Ordering::SeqCst), 0);
    controls.pause_adoption.store(false, Ordering::SeqCst);
    controls.release_adoption.notify_one();
    adopting.await.unwrap().unwrap();
    revoking.await.unwrap().unwrap();
    assert!(client
        .ensure_remote_binding_snapshot(&fixture.db, &binding)
        .await
        .is_err());
    assert_eq!(controls.revokes.load(Ordering::SeqCst), 1);
    assert!(client.acknowledged_binding_snapshot(binding.id).is_err());
    server.abort();
    std::env::remove_var("SSL_CERT_FILE");
}
