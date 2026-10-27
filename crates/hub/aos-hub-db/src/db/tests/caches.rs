//! Caches regression cases and contract checks.

use super::*;

#[tokio::test]
async fn native_reference_schema_upgrades_from_released_production_versions() {
    // Released versions 2 through 5 add the channel ledger, private stages, OCI
    // retirement, and namespace routes before native reference migrations.
    for baseline_version in [1, 2, 3, 4, 5] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE schema_version (version INTEGER NOT NULL);")
            .unwrap();
        for migration in &MIGRATIONS[..baseline_version] {
            connection.execute_batch(migration).unwrap();
        }
        connection
            .execute(
                "INSERT INTO schema_version VALUES (?1)",
                [baseline_version as i64],
            )
            .unwrap();
        drop(connection);

        drop(Database::open(&path).await.unwrap());

        let connection = Connection::open(&path).unwrap();
        let version: i64 = connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        let graph_table: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                     WHERE type = 'table' AND name = 'release_ability_graphs'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(version, MIGRATIONS.len() as i64);
        assert_eq!(graph_table, 1);
    }
}

#[tokio::test]
async fn standalone_cache_slugs_cannot_collide_with_stable_ids() {
    let db = Database::open_in_memory().await.unwrap();
    let error = db
        .create_binary_cache(
            None,
            "cache:0123456789abcdef0123456789abcdef",
            "Ambiguous cache",
            "private",
            40,
            "zstd",
            false,
        )
        .await
        .unwrap_err();

    assert!(format!("{error:#}").contains("invalid standalone cache slug"));
}

#[tokio::test]
async fn scope_operation_inventory_includes_only_descendant_scopes() {
    let db = Database::open_in_memory().await.unwrap();
    let acme_id = db
        .create_org("acme-operations", "Acme Operations")
        .await
        .unwrap();
    let other_id = db
        .create_org("other-operations", "Other Operations")
        .await
        .unwrap();
    let acme_scope = db.org_by_id(acme_id).await.unwrap().unwrap().stable_id;

    let acme_registry_id = db
        .create_managed_registry(acme_id, "", "main", "private", &[], false)
        .await
        .unwrap();
    let acme_registry = db.registry_by_id(acme_registry_id).await.unwrap().unwrap();
    let acme_cache_id = db
        .create_binary_cache(
            Some(acme_id),
            "acme-operations/cache",
            "Cache",
            "private",
            0,
            "zstd",
            false,
        )
        .await
        .unwrap();
    let acme_cache = db.binary_cache_by_id(acme_cache_id).await.unwrap().unwrap();
    let other_registry_id = db
        .create_managed_registry(other_id, "", "main", "private", &[], false)
        .await
        .unwrap();
    let other_registry = db.registry_by_id(other_registry_id).await.unwrap().unwrap();

    let now = unix_now();
    let operation = |id: &str, scope: &str, kind: &str, target: &str| {
        Statement::new(
            "INSERT INTO topology_operations
                   (operation_id, operation_kind, authorization_scope_key,
                    control_permission, primary_target_kind, primary_target_stable_id,
                    state, detail_json, created_at)
                 VALUES (?1, 'test_operation', ?2, 'read', ?3, ?4, 'pending', '{}', ?5)",
            vals![id, scope, kind, target, now],
        )
        .expecting(1)
    };
    db.backend
        .checked_batch(&[
            operation(
                "operation-a",
                &acme_registry.scope_key,
                "registry",
                &acme_registry.stable_id,
            ),
            operation(
                "operation-c",
                &acme_cache.scope_key,
                "binary_cache",
                &acme_cache.stable_id,
            ),
            operation(
                "operation-b",
                &other_registry.scope_key,
                "registry",
                &other_registry.stable_id,
            ),
        ])
        .await
        .unwrap();

    let first = db
        .list_scope_topology_operations_page(&acme_scope, None, 1, None)
        .await
        .unwrap();
    assert_eq!(first.records[0].operation_id, "operation-a");
    assert_eq!(first.next_cursor.as_deref(), Some("operation-a"));

    let second = db
        .list_scope_topology_operations_page(&acme_scope, None, 1, first.next_cursor.as_deref())
        .await
        .unwrap();
    assert_eq!(second.records[0].operation_id, "operation-c");
    assert!(second.next_cursor.is_none());

    let instance = db
        .list_scope_topology_operations_page("instance", None, 10, None)
        .await
        .unwrap();
    assert_eq!(instance.records.len(), 3);
    assert!(db
        .list_scope_topology_operations_page(&acme_scope, None, 10, Some("operation-b"),)
        .await
        .is_err());
}

#[tokio::test]
async fn caches_crud_and_servable_filter() {
    let (db, org, _binding) = cache_fixture().await;
    let id = db
        .create_binary_cache(
            Some(org),
            "acme-cache",
            "Acme Cache",
            "public",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
    // Duplicate slug is rejected independently of physical placement.
    assert!(db
        .create_binary_cache(None, "acme-cache", "x", "public", 40, "zstd", true)
        .await
        .is_err());
    let c = db
        .binary_cache_by_slug("acme-cache")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(c.id, id);
    assert_eq!(c.org_id, Some(org));
    assert!(c.want_mass_query);
    assert_eq!(
        db.binary_cache_by_id(id).await.unwrap().unwrap().slug,
        "acme-cache"
    );

    // An instance-level standalone cache (no org).
    db.create_binary_cache(None, "standalone", "Standalone", "public", 30, "xz", false)
        .await
        .unwrap();
    assert_eq!(db.list_binary_caches().await.unwrap().len(), 2);
    assert_eq!(db.list_binary_caches_for_org(org).await.unwrap().len(), 1);

    db.update_binary_cache(id, "Renamed", "private", 10, "none", false)
        .await
        .unwrap();
    let c = db.binary_cache_by_id(id).await.unwrap().unwrap();
    assert_eq!(c.name, "Renamed");
    assert_eq!(c.visibility, "private");
    assert_eq!(c.priority, 10);
    assert!(!c.want_mass_query);

    // Soft-delete drops it from the servable list; hard-delete removes the row.
    assert!(db
        .soft_delete_binary_cache(id, unix_now() + 100)
        .await
        .unwrap());
    assert_eq!(db.list_binary_caches().await.unwrap().len(), 1);
    assert!(db.delete_binary_cache(id).await.unwrap());
    assert!(db.binary_cache_by_id(id).await.unwrap().is_none());
}

#[tokio::test]
async fn list_caches_excludes_soft_deleted_org() {
    let (db, org, _binding) = cache_fixture().await;
    db.create_binary_cache(Some(org), "owned", "Owned", "public", 40, "zstd", true)
        .await
        .unwrap();
    db.create_binary_cache(None, "standalone", "Standalone", "public", 40, "zstd", true)
        .await
        .unwrap();
    assert_eq!(db.list_binary_caches().await.unwrap().len(), 2);
    // Soft-deleting the org drops its cache from the servable list; the
    // instance-level (org_id IS NULL) cache still passes.
    assert!(db.soft_delete_org(org, 86_400).await.unwrap());
    let live = db.list_binary_caches().await.unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].slug, "standalone");
}

#[tokio::test]
async fn registry_publication_inventory_is_stable_and_filter_bound() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db
        .register_registry("publication-history", &[], false)
        .await
        .unwrap();
    for ordinal in 1..=3 {
        db.create_registry_publication(&NewRegistryPublication {
            publication_id: format!("publication-history-{ordinal}"),
            registry_id,
            generation: format!("generation-{ordinal}"),
            manifest_digest: format!("{ordinal:064x}"),
            refs_digest: format!("{:064x}", ordinal + 10),
            default_commit: None,
            parent_publication_id: None,
        })
        .await
        .unwrap();
    }
    db.fail_registry_publication("publication-history-2", unix_now())
        .await
        .unwrap();

    let first = db
        .list_registry_publications_page(registry_id, None, 1, None)
        .await
        .unwrap();
    assert_eq!(first.records[0].ordinal, 3);
    assert_eq!(first.next_cursor, Some(3));
    let second = db
        .list_registry_publications_page(registry_id, None, 1, first.next_cursor)
        .await
        .unwrap();
    assert_eq!(second.records[0].ordinal, 2);

    let failed = db
        .list_registry_publications_page(registry_id, Some("failed"), 10, None)
        .await
        .unwrap();
    assert_eq!(failed.records.len(), 1);
    assert_eq!(failed.records[0].publication_id, "publication-history-2");
    assert!(db
        .list_registry_publications_page(registry_id, Some("failed"), 10, Some(3))
        .await
        .is_err());

    let retried = db
        .retry_failed_registry_publication("publication-history-2", unix_now())
        .await
        .unwrap();
    assert_eq!(retried.state, "preparing");
    assert!(db
        .retry_failed_registry_publication("publication-history-2", unix_now())
        .await
        .is_err());
}
