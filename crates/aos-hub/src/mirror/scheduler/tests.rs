//! Current SQL scheduling and nonfatal production executor refusals.

use super::*;

async fn registry(db: &Database, organization: i64, name: &str) -> i64 {
    db.create_managed_registry(organization, "infra/prod", name, "public", &[], true)
        .await
        .unwrap()
}

#[tokio::test]
async fn current_sql_selects_only_due_full_mirrors_using_last_attempt() {
    let db = Database::open_in_memory().await.unwrap();
    let organization = db
        .create_org("mirror-schedule", "Mirror schedule")
        .await
        .unwrap();
    db.create_project(organization, "infra/prod", "Production")
        .await
        .unwrap();
    let mut ids = Vec::new();
    for (name, mode) in [
        ("never", "full"),
        ("recent", "full"),
        ("failed", "full"),
        ("demand", "pullthrough"),
    ] {
        let id = registry(&db, organization, name).await;
        db.create_mirror_source(id, "https://upstream.example.test/", mode, true, 60)
            .await
            .unwrap();
        ids.push(id);
    }
    db.update_mirror_sync(ids[1], 950, "ok", None, Some("retained-frontier"))
        .await
        .unwrap();
    db.update_mirror_sync(ids[2], 940, "failed", Some("verified refusal"), None)
        .await
        .unwrap();

    let sources = db.list_mirror_sources().await.unwrap();
    let due = |now| {
        sources
            .iter()
            .filter(|(_, source)| is_due(source, now))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>()
    };

    // Registry identities are allocated independently of creation order; the
    // production query orders by their actual database identity.
    let mut boundary = vec![ids[0], ids[2]];
    boundary.sort_unstable();
    let mut all_full = vec![ids[0], ids[1], ids[2]];
    all_full.sort_unstable();

    assert_eq!(due(999), vec![ids[0]]);
    assert_eq!(due(1000), boundary);
    assert_eq!(due(1010), all_full);
    assert_eq!(due(900), vec![ids[0]]);
    let failed = sources.iter().find(|(id, _)| *id == ids[2]).unwrap();
    assert_eq!(failed.1.last_sync_status.as_deref(), Some("failed"));
}

#[tokio::test]
async fn genuine_local_and_hybrid_executor_refusals_are_nonfatal_without_sync_success() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let organization = db
        .create_org("mirror-refusal", "Mirror refusal")
        .await
        .unwrap();
    db.create_project(organization, "infra/prod", "Production")
        .await
        .unwrap();
    let id = registry(&db, organization, "unconfigured-writer").await;
    db.create_mirror_source(id, "https://upstream.example.test/", "full", true, 60)
        .await
        .unwrap();
    let registry = db.registry_by_id(id).await.unwrap().unwrap();
    let work = Arc::new(
        crate::storage_work::RemoteStorageWorkClient::new(
            "https://localhost:4673",
            "deployment-1".into(),
            &[11; 32],
        )
        .unwrap(),
    );
    let before = db.mirror_source(id).await.unwrap().unwrap();

    // Both real executors refuse the missing reconciled writer before fetch.
    // The scheduler preserves their nonfatal treatment without recording a
    // successful attempt or pretending provider work completed.
    assert!(
        crate::mirror::sync_full_mirror(&db, &registry)
            .await
            .is_err()
    );
    assert!(
        crate::mirror::hybrid::sync_full_mirror(&db, &work, &registry)
            .await
            .is_err()
    );
    sync_due_mirrors(&db, None, 1000).await;
    sync_due_mirrors(&db, Some(&work), 1000).await;

    assert_eq!(db.mirror_source(id).await.unwrap().unwrap(), before);
}
