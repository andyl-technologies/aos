//! Database contract for immutable signing-key generations and exact usage pins.

use aos_hub_core::db::Database;

#[tokio::test]
async fn rotation_preserves_exact_usage_until_reviewed_repin() {
    let db = Database::open_in_memory().await.unwrap();
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    db.create_managed_registry(org_id, "", "main", "public", &[], false)
        .await
        .unwrap();
    let registry = db.registry_by_slug("acme/main").await.unwrap().unwrap();

    let key_id = db
        .enroll_signing_key(
            &org.stable_id,
            "release",
            "generation-one-public-key",
            &"1".repeat(64),
            "external",
        )
        .await
        .unwrap();
    let generation_one = db.signing_key_by_stable_id(&key_id).await.unwrap().unwrap();
    assert_eq!(generation_one.generation, 1);
    assert_eq!(generation_one.state, "active");

    let consumer = db
        .resolve_signing_key_consumer(&registry.stable_id, "registry_publication")
        .await
        .unwrap();
    db.set_signing_key_usage(
        None,
        &consumer,
        "registry_publication",
        &key_id,
        1,
        "active",
    )
    .await
    .unwrap();

    db.rotate_signing_key(
        &generation_one,
        "generation-two-public-key",
        &"2".repeat(64),
        "external",
    )
    .await
    .unwrap();
    let generation_two = db.signing_key_by_stable_id(&key_id).await.unwrap().unwrap();
    assert_eq!(generation_two.generation, 2);
    assert_eq!(generation_two.state, "active");

    let still_pinned = db
        .active_signing_key_for_usage(&registry.stable_id, "registry_publication")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_pinned.generation, 1);
    assert_eq!(still_pinned.state, "retired");

    let usage = db
        .signing_key_usage(&registry.stable_id, "registry_publication")
        .await
        .unwrap()
        .unwrap();
    db.set_signing_key_usage(
        Some(&usage),
        &consumer,
        "registry_publication",
        &key_id,
        2,
        "active",
    )
    .await
    .unwrap();
    let repinned = db
        .active_signing_key_for_usage(&registry.stable_id, "registry_publication")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(repinned.generation, 2);

    assert!(db
        .rotate_signing_key(
            &generation_one,
            "uncommitted-public-key",
            &"3".repeat(64),
            "external",
        )
        .await
        .is_err());
    let unchanged = db.signing_key_by_stable_id(&key_id).await.unwrap().unwrap();
    assert_eq!(unchanged.generation, 2);

    db.retire_signing_key(&generation_two).await.unwrap();
    let retired = db.signing_key_by_stable_id(&key_id).await.unwrap().unwrap();
    assert_eq!(retired.generation, 2);
    assert_eq!(retired.state, "retired");
    assert!(retired.retired_at.is_some());
}
