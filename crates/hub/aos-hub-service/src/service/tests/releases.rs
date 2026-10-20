//! Releases regression cases and contract checks.

use super::*;

#[tokio::test]
async fn publication_index_refresh_is_safe_to_retry() {
    let reindex_calls = Arc::new(AtomicUsize::new(0));
    let (service, db, _lease, _auth) =
        injected_service_with_reindexer(Arc::new(InjectedReindexer {
            calls: Some(Arc::clone(&reindex_calls)),
        }))
        .await;
    let org_id = db
        .create_org("publication-retry", "Publication retry")
        .await
        .unwrap();
    db.create_managed_registry(org_id, "", "packages", "public", &[], true)
        .await
        .unwrap();
    let registry = db
        .registry_by_slug("publication-retry/packages")
        .await
        .unwrap()
        .unwrap();
    service
        .refresh_registry_index_after_publication(&registry, "ready-publication")
        .await;
    service
        .refresh_registry_index_after_publication(&registry, "ready-publication")
        .await;

    assert_eq!(reindex_calls.load(Ordering::SeqCst), 2);
}
