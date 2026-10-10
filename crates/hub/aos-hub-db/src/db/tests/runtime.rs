//! Runtime regression cases and contract checks.

use super::*;

#[test]
fn generated_relational_ids_are_positive_and_worker_exact() {
    assert_eq!(portable_relational_id(Uuid::from_u128(0)), 1);
    let maximum_source = portable_relational_id(Uuid::from_u128(u128::MAX));
    assert!((1..=PORTABLE_RELATIONAL_ID_MAX).contains(&maximum_source));
    assert_eq!(maximum_source as f64 as i64, maximum_source);
}

#[test]
fn fresh_schema_is_final_and_foreign_key_clean() {
    assert_eq!(
            MIGRATIONS.len(),
            8,
            "released migrations through OCI namespace routes followed by native reference and report projections"
        );
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    for migration in MIGRATIONS {
        connection.execute_batch(migration).unwrap();
    }

    let identity: String = connection
        .query_row("SELECT identity FROM hub_schema_identity", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(identity, SCHEMA_IDENTITY);

    let violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(violations, 0, "fresh baseline violates a foreign key");

    let schema = MIGRATIONS.join("\n");
    for forbidden in [
        "credential_ref",
        "CREATE TABLE frontends",
        "bindings_instance_default_idx",
        " root TEXT",
        " access TEXT",
        " endpoint TEXT",
    ] {
        assert!(
            !schema.contains(forbidden),
            "final topology schema contains removed storage token {forbidden:?}"
        );
    }
    let removed_identity_columns: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('registries')
                 WHERE name IN ('source_url', 'binding_id', 'prefix')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(removed_identity_columns, 0);

    for table in [
        "binary_caches",
        "surface_placements",
        "surface_write_authorities",
        "domains",
        "network_policies",
        "endpoints",
        "gateways",
        "routes",
        "route_configurations",
        "route_advertisements",
        "image_snapshots",
        "image_snapshot_references",
        "image_snapshot_leases",
        "registry_publication_object_evidence",
        "release_ability_graphs",
    ] {
        let present: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(present, 1, "final table {table} is missing");
    }
    for table in ["caches", "frontends", "frontend_probes"] {
        let present: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(present, 0, "legacy table {table} survived the baseline");
    }

    let route_columns: Vec<String> = connection
        .prepare("PRAGMA table_info(routes)")
        .unwrap()
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for required in [
        "id",
        "endpoint_id",
        "endpoint_generation",
        "consumer_scope_key",
        "access_policy_digest",
        "placement_policy_revision_id",
    ] {
        assert!(
            route_columns.iter().any(|column| column == required),
            "final route column {required} is missing"
        );
    }
    for forbidden in ["domain_id", "placement_policy_id", "readiness_state"] {
        assert!(
            route_columns.iter().all(|column| column != forbidden),
            "legacy route column {forbidden} survived the baseline"
        );
    }

    let public_boundary: (i64, String) = connection
        .query_row(
            "SELECT d.revision, d.state
                 FROM network_policy_defaults d
                 WHERE d.boundary_id = 'instance:public'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(public_boundary, (1, "active".to_string()));
}

#[test]
fn mysql_migration_replay_helpers_cover_every_ddl_shape() {
    for sql in migration_statements() {
        if sql.contains("CREATE INDEX ") || sql.contains("CREATE UNIQUE INDEX ") {
            assert!(
                mysql_migration_index_identity(&sql).is_some(),
                "unrecognized MySQL migration index statement: {sql}"
            );
        }
        let replay_safe = mysql_replay_safe_migration_sql(&sql);
        if sql.contains("CREATE TABLE ") {
            assert!(replay_safe.contains("CREATE TABLE IF NOT EXISTS "));
        }
        if sql.contains("CREATE VIEW ") {
            assert!(replay_safe.contains("CREATE OR REPLACE VIEW "));
        }
        if sql.contains("ADD COLUMN ") {
            assert!(replay_safe.contains("ADD COLUMN IF NOT EXISTS "));
        }
        if sql.contains("INSERT INTO ") && !sql.contains("ON CONFLICT") {
            assert!(replay_safe.contains("INSERT IGNORE INTO "));
        }
    }
}

#[test]
fn migration_statements_translate_for_postgres_and_mysql() {
    for sql in migration_statements() {
        for dialect in [Dialect::Postgres, Dialect::Mysql] {
            dialect
                .translate(&sql)
                .unwrap_or_else(|error| panic!("{dialect:?} migration SQL failed: {error}\n{sql}"));
        }
    }
}

#[tokio::test]
async fn production_baseline_rejects_incompatible_ledgers_without_changing_data() {
    for mutation in [
        "UPDATE schema_version SET version = -1",
        "UPDATE schema_version SET version = 9999",
        "INSERT INTO schema_version VALUES (1)",
        "UPDATE hub_schema_identity SET identity = 'aos-hub/topology-hard-cutover/2'",
        "DELETE FROM hub_schema_identity",
        "INSERT INTO hub_schema_identity VALUES ('foreign-lineage')",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hub.db");
        let database = Database::open(&path).await.unwrap();
        database
            .register_registry("preserved", &["anchor".into()], true)
            .await
            .unwrap();
        drop(database);

        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(mutation).unwrap();
        drop(connection);
        assert!(
            Database::open(&path).await.is_err(),
            "accepted corruption: {mutation}"
        );

        let connection = Connection::open(&path).unwrap();
        let anchor: String = connection
            .query_row(
                "SELECT trust_keys FROM registries WHERE slug = 'preserved'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(anchor, "[\"anchor\"]");
    }
}

#[tokio::test]
async fn failed_forward_migration_rolls_back_schema_and_marker() {
    let db = Database::open_in_memory().await.unwrap();
    let current = MIGRATIONS.len() as i64;
    let statements = [
        Statement::new(
            "CREATE TABLE migration_probe (id INTEGER PRIMARY KEY)",
            Vec::new(),
        ),
        Statement::new("UPDATE schema_version SET version = ?1", vals![current + 1]),
        Statement::new(
            "INSERT INTO nonexistent_migration_target VALUES (1)",
            Vec::new(),
        ),
    ];

    assert!(db
        .backend
        .migration_batch(current, current + 1, &statements)
        .await
        .is_err());

    let version: i64 = db
        .backend
        .query_opt("SELECT version FROM schema_version", &[])
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(version, current);
    let probe = db
        .backend
        .query_opt(
            "SELECT name FROM sqlite_master WHERE name = 'migration_probe'",
            &[],
        )
        .await
        .unwrap();
    assert!(probe.is_none(), "failed migration committed partial DDL");
    db.migrate().await.unwrap();
}

#[tokio::test]
async fn production_baseline_concurrent_installation_converges() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hub.db");
    let (left, right) = tokio::join!(Database::open(&path), Database::open(&path));
    drop(left.unwrap());
    drop(right.unwrap());

    let connection = Connection::open(&path).unwrap();
    let version: i64 = connection
        .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, MIGRATIONS.len() as i64);
    let identities: i64 = connection
        .query_row("SELECT COUNT(*) FROM hub_schema_identity", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(identities, 1);
}

#[test]
fn production_baseline_keeps_portable_recovery_columns() {
    let connection = Connection::open_in_memory().unwrap();
    connection.execute_batch(MIGRATIONS[0]).unwrap();

    let cursor: i64 = connection
        .query_row(
            "SELECT after_expires_at FROM write_recovery_cursors WHERE recovery_kind = 'cache'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        cursor,
        aos_hub_model::cache::CACHE_WRITE_RECOVERY_CURSOR_START
    );
    for (table, column) in [
        ("registry_index", "documentation_projection_generation"),
        ("object_placements", "catalog_object_resource_version"),
    ] {
        let present: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
                [table, column],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(present, 1, "missing {table}.{column}");
    }
}

#[tokio::test]
async fn migrate_register_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hub.db");
    {
        let db = Database::open(&path).await.unwrap();
        db.register_registry("demo", &["k".into()], true)
            .await
            .unwrap();
    }
    let db = Database::open(&path).await.unwrap();
    let reg = db.registry_by_slug("demo").await.unwrap().unwrap();
    assert_eq!(reg.trust_keys, vec!["k".to_string()]);
    assert!(reg.require_signatures);
    assert_eq!(
        db.index_status(reg.id).await.unwrap().unwrap().state,
        "empty"
    );
}

#[tokio::test]
async fn migrate_refuses_pre_cutover_version_collision() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE schema_version(version INTEGER NOT NULL);
                 INSERT INTO schema_version(version) VALUES (1);
                 CREATE TABLE registries(id INTEGER PRIMARY KEY, slug TEXT NOT NULL);",
        )
        .unwrap();
    drop(connection);

    let error = match Database::open(&path).await {
        Ok(_) => panic!("pre-cutover schema must be refused"),
        Err(error) => error,
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("predates the first stable production baseline"),
        "{message}"
    );
}

#[tokio::test]
async fn store_backed_images_remain_discoverable_without_legacy_object_roots() {
    let db = Database::open_in_memory().await.unwrap();
    let registry_id = db
        .register_registry("store-images", &[], false)
        .await
        .unwrap();
    let package = store_backed_image_package();
    let snapshot = IndexSnapshot {
        commit: "c".repeat(64),
        name: "AOS system".into(),
        packages: vec![package.clone()],
        releases: vec![ReleaseRow {
            semver: "2026.8.0".into(),
            tag_oid: "a".repeat(64),
            commit_oid: "c".repeat(64),
            signer: Some("release-signer".into()),
            tagged_at: Some(1),
            pack_present: true,
        }],
        release_images: vec![signed_image_release_snapshot(
            &package,
            "2026.8.0",
            &"c".repeat(64),
            &"a".repeat(64),
        )],
        ..Default::default()
    };

    db.apply_snapshot(registry_id, &snapshot).await.unwrap();

    let images = db.list_system_images(registry_id).await.unwrap();
    assert_eq!(images.len(), 2);
    assert!(images.iter().all(|image| image.delivery.is_store_backed()));
    let legacy_root_count: i64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM registry_image_roots WHERE registry_id = ?1",
            &vals![registry_id],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(legacy_root_count, 0);
}

#[tokio::test]
async fn closure_resolution_resolves_refs_and_reverse_deps() {
    let db = Database::open_in_memory().await.unwrap();
    let id = db.register_registry("demo", &[], false).await.unwrap();
    // curl's closure references zlib (zzz) plus an out-of-registry hash
    // (qqq, e.g. a stdenv path); source_drv is recorded per the v19 column.
    let curl: aos_registry_format::manifest::PackageToml = toml::from_str(
        r#"
            [package]
            name = "curl"
            description = "URL transfers"
            license = "MIT"
            maintainer = "aos"
            [[versions]]
            version = "8.5.0"
            [versions.platforms.x86_64-linux]
            store_path = "/var/lib/store/abc-curl-8.5.0"
            nar_hash = "sha256:aa"
            nar_size = 10
            closure_size = 20
            source_drv = "/var/lib/store/dabc-curl-8.5.0.drv"
            source_nar_hash = "sha256:bb"
            references = ["zzz", "qqq"]
            "#,
    )
    .unwrap();
    let zlib: aos_registry_format::manifest::PackageToml = toml::from_str(
        r#"
            [package]
            name = "zlib"
            description = "compression"
            license = "Zlib"
            maintainer = "aos"
            [[versions]]
            version = "1.3.1"
            [versions.platforms.x86_64-linux]
            store_path = "/var/lib/store/zzz-zlib-1.3.1"
            nar_hash = "sha256:cc"
            nar_size = 5
            closure_size = 8
            source_drv = "/var/lib/store/dzzz-zlib-1.3.1.drv"
            source_nar_hash = "sha256:dd"
            references = []
            "#,
    )
    .unwrap();
    let snapshot = IndexSnapshot {
        commit: "c".repeat(64),
        name: "demo".into(),
        packages: vec![curl, zlib],
        ..Default::default()
    };
    db.apply_snapshot(id, &snapshot).await.unwrap();

    // The v19 source_drv column round-trips into PlatformDetail.
    let detail = db.package_detail(id, "curl").await.unwrap().unwrap();
    assert_eq!(
        detail.versions[0].platforms[0].source_drv,
        "/var/lib/store/dabc-curl-8.5.0.drv"
    );

    // resolve_reference_names: zzz resolves to zlib, qqq stays unresolved.
    let resolved = db
        .resolve_reference_names(id, &["zzz".to_string(), "qqq".to_string()])
        .await
        .unwrap();
    assert_eq!(
        resolved,
        vec![
            (
                "zzz".to_string(),
                Some("zlib".to_string()),
                Some("1.3.1".to_string())
            ),
            ("qqq".to_string(), None, None),
        ]
    );

    // reverse_dependencies: curl requires zlib (zzz).
    let reverse = db.reverse_dependencies(id, "zzz").await.unwrap();
    assert_eq!(reverse, vec![("curl".to_string(), "8.5.0".to_string())]);
    // qqq is referenced by curl too (a second closure edge).
    assert_eq!(
        db.reverse_dependencies(id, "qqq").await.unwrap(),
        vec![("curl".to_string(), "8.5.0".to_string())]
    );
    // Nothing references a hash that appears in no closure.
    assert!(db
        .reverse_dependencies(id, "nope")
        .await
        .unwrap()
        .is_empty());

    // primary_store_hash prefers the named platform and falls back.
    assert_eq!(
        db.primary_store_hash(id, "zlib", "x86_64-linux")
            .await
            .unwrap(),
        Some("zzz".to_string())
    );
    assert_eq!(
        db.primary_store_hash(id, "zlib", "aarch64-linux")
            .await
            .unwrap(),
        Some("zzz".to_string()),
        "falls back to the first platform when the requested one is absent"
    );
    assert_eq!(
        db.primary_store_hash(id, "absent", "x86_64-linux")
            .await
            .unwrap(),
        None
    );

    // list_packages carries the latest version's closure size + platforms,
    // now via a single JOIN (no per-package N+1 sub-query).
    let packages = db.list_packages(id).await.unwrap();
    assert_eq!(packages.len(), 2, "both packages, name-ordered");
    assert_eq!(packages[0].name, "curl");
    let curl_row = packages.iter().find(|p| p.name == "curl").unwrap();
    assert_eq!(curl_row.closure_size, Some(20));
    assert_eq!(curl_row.platforms, vec!["x86_64-linux".to_string()]);

    // The capped browse listing returns the same rows under a high cap and
    // reports truncation when the cap is below the package count.
    let (uncapped, trunc) = db.list_packages_capped(id, 1000).await.unwrap();
    assert_eq!(uncapped.len(), 2);
    assert!(!trunc, "two packages are well under the cap");
    let (capped, trunc) = db.list_packages_capped(id, 1).await.unwrap();
    assert_eq!(capped.len(), 1, "cap limits the loaded set");
    assert_eq!(capped[0].name, "curl", "cap takes the name-ordered prefix");
    assert!(trunc, "a registry larger than the cap is flagged truncated");
}

#[tokio::test]
async fn failure_marks_state_without_dropping_index() {
    let db = Database::open_in_memory().await.unwrap();
    let id = db.register_registry("demo", &[], false).await.unwrap();
    let snapshot = IndexSnapshot {
        commit: "c".repeat(64),
        name: "demo".into(),
        ..Default::default()
    };
    db.apply_snapshot(id, &snapshot).await.unwrap();
    db.mark_index_failed(id, "upstream unreachable")
        .await
        .unwrap();
    let status = db.index_status(id).await.unwrap().unwrap();
    assert_eq!(status.state, "failed");
    assert_eq!(status.error.as_deref(), Some("upstream unreachable"));
    // The last good index survives.
    assert_eq!(
        status.last_indexed_commit.as_deref(),
        Some(&*"c".repeat(64))
    );

    db.mark_index_stale(id, "connection refused").await.unwrap();
    let status = db.index_status(id).await.unwrap().unwrap();
    assert_eq!(status.state, "stale");
    assert_eq!(status.error.as_deref(), Some("connection refused"));
    assert_eq!(
        status.last_indexed_commit.as_deref(),
        Some(&*"c".repeat(64))
    );
}

#[test]
fn sanitize_log_text_strips_c0_controls_but_keeps_tab() {
    // CR/LF and other C0 controls collapse to spaces; a tab is preserved.
    assert_eq!(sanitize_log_text("a\r\nb"), "a  b");
    assert_eq!(sanitize_log_text("x\tnice"), "x\tnice");
    assert_eq!(sanitize_log_text("ctrl\x07bell\x7fdel"), "ctrl bell del");
    assert_eq!(sanitize_log_text("clean/path-1.0"), "clean/path-1.0");
}

#[tokio::test]
async fn draft_signing_key_is_generated_once_and_persists() {
    let db = Database::open_in_memory().await.unwrap();
    let sealer = aos_hub_model::auth::seal::dev_sealer();
    let (key1, line1) = db
        .get_or_create_draft_signing_key(sealer.as_ref())
        .await
        .unwrap();
    // A second call returns the same key (persisted seed), not a fresh one.
    let (key2, line2) = db
        .get_or_create_draft_signing_key(sealer.as_ref())
        .await
        .unwrap();
    assert_eq!(key1.to_bytes(), key2.to_bytes());
    assert_eq!(line1, line2);
    assert!(line1.starts_with("aos-hub-draft:Ed25519:"));
    // The stored value is sealed, not the raw seed.
    let stored = db
        .instance_config_get("draft_signing_key")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(stored, hex::encode(key1.to_bytes()));
}

#[tokio::test]
async fn close_reopen_preserves_draft_auto_merge() {
    let db = Database::open_in_memory().await.unwrap();
    db.create_git_changeset(
        "ch-cr",
        "user",
        Some(1),
        "alice@acme.com",
        "instance",
        Some("edit"),
        "refs/hub/changes/ch-cr",
        "draftoid",
        Some("tighten caches"),
        Some("body text"),
    )
    .await
    .unwrap();
    // Title/body round-trip; opens un-closed.
    let cs = db.changeset("ch-cr").await.unwrap().unwrap();
    assert_eq!(cs.title.as_deref(), Some("tighten caches"));
    assert_eq!(cs.body.as_deref(), Some("body text"));
    assert!(cs.closed_at.is_none());

    // Close stamps closed_at but never touches status.
    db.close_changeset("ch-cr").await.unwrap();
    let cs = db.changeset("ch-cr").await.unwrap().unwrap();
    assert_eq!(cs.status, "draft");
    assert!(cs.closed_at.is_some());

    // Reopen clears closed_at.
    db.reopen_changeset("ch-cr").await.unwrap();
    let cs = db.changeset("ch-cr").await.unwrap().unwrap();
    assert!(cs.closed_at.is_none());

    // Auto-merge still flips the reopened draft to applied.
    db.mark_changeset_applied_commit("ch-cr", "rosteroid")
        .await
        .unwrap();
    let cs = db.changeset("ch-cr").await.unwrap().unwrap();
    assert_eq!(cs.status, "applied");
    assert_eq!(cs.git_commit.as_deref(), Some("rosteroid"));
}

#[tokio::test]
async fn change_comments_and_reviews_record_and_list_in_order() {
    let db = Database::open_in_memory().await.unwrap();
    db.create_git_changeset(
        "ch-d",
        "user",
        Some(1),
        "alice@acme.com",
        "instance",
        Some("edit"),
        "refs/hub/changes/ch-d",
        "draftoid",
        None,
        None,
    )
    .await
    .unwrap();
    db.add_change_comment("ch-d", "user", Some(1), "alice@acme.com", "first")
        .await
        .unwrap();
    db.add_change_comment("ch-d", "user", Some(2), "bob@acme.com", "second")
        .await
        .unwrap();
    let comments = db.list_change_comments("ch-d").await.unwrap();
    assert_eq!(comments.len(), 2);
    assert_eq!(comments[0].body, "first");
    assert_eq!(comments[1].body, "second");

    db.add_change_review(
        "ch-d",
        "user",
        Some(2),
        "bob@acme.com",
        "approve",
        Some("lgtm"),
    )
    .await
    .unwrap();
    let reviews = db.list_change_reviews("ch-d").await.unwrap();
    assert_eq!(reviews.len(), 1);
    assert_eq!(reviews[0].verdict, "approve");
    assert_eq!(reviews[0].body.as_deref(), Some("lgtm"));
}

#[tokio::test]
async fn device_flow_full_path_with_scope_clamping() {
    use aos_hub_model::domain::{Permission, Principal, Role, Scope};
    let db = Database::open_in_memory().await.unwrap();
    let approver = db.create_user("admin@acme.com", None).await.unwrap();
    // The approver is a maintainer at the instance: read+publish, but NOT
    // members.manage.
    let grants = vec![(Scope::root(), Role::Maintainer)];
    db.grant_membership("user", approver, "instance", "maintainer")
        .await
        .unwrap();

    // CLI requests read + publish + members.manage at the instance.
    let (device_code, user_code, ttl) = db
        .start_device_authorization(
            "instance",
            &[
                Permission::Read,
                Permission::Publish,
                Permission::MembersManage,
            ],
        )
        .await
        .unwrap();
    assert_eq!(ttl, aos_hub_model::auth::device::DEVICE_CODE_TTL_SECS);
    assert_eq!(user_code.len(), 9);

    // Pending before approval.
    assert!(matches!(
        db.poll_device(&device_code).await.unwrap(),
        DevicePollResult::Pending
    ));

    // Approve as the maintainer.
    assert!(db
        .approve_device(&user_code, Principal::user(approver), &grants)
        .await
        .unwrap());

    // Simulate the client's advertised five-second polling interval.
    db.backend
        .execute(
            "UPDATE device_codes SET last_polled_at = ?1 WHERE user_code = ?2",
            &vals![unix_now() - 5, user_code],
        )
        .await
        .unwrap();

    // Poll returns a live authorization and rotating refresh credential.
    let result = db.poll_device(&device_code).await.unwrap();
    let DevicePollResult::Approved(grant) = result else {
        panic!("expected Approved, got {result:?}");
    };

    // The device code is never an ordinary bearer. The durable authority
    // is owned by the approver and clamped to the requested intersection.
    assert!(db.validate_token(&device_code).await.unwrap().is_none());
    assert_eq!(grant.auth.owner, Principal::user(approver));
    assert_eq!(grant.auth.scope.as_str(), "instance");
    assert!(grant.auth.permissions.contains(&Permission::Read));
    assert!(grant.auth.permissions.contains(&Permission::Publish));
    assert!(!grant.auth.permissions.contains(&Permission::MembersManage));

    // Refresh credentials rotate once. Reuse revokes the complete family,
    // including the credential most recently returned to the client.
    let rotated = db.rotate_refresh_token(&grant.refresh_token).await.unwrap();
    let RefreshTokenResult::Rotated(next) = rotated else {
        panic!("expected refresh rotation, got {rotated:?}");
    };
    assert!(matches!(
        db.rotate_refresh_token(&grant.refresh_token).await.unwrap(),
        RefreshTokenResult::Reused
    ));
    assert!(matches!(
        db.rotate_refresh_token(&next.refresh_token).await.unwrap(),
        RefreshTokenResult::Invalid
    ));
}

#[tokio::test]
async fn device_flow_deny_and_unknown() {
    use aos_hub_model::domain::Permission;
    let db = Database::open_in_memory().await.unwrap();
    let (device_code, user_code, _) = db
        .start_device_authorization("instance", &[Permission::Read])
        .await
        .unwrap();
    assert!(db.deny_device(&user_code).await.unwrap());
    assert!(matches!(
        db.poll_device(&device_code).await.unwrap(),
        DevicePollResult::Denied
    ));

    // An unknown user_code cannot be approved or denied.
    assert!(!db
        .approve_device("ZZZZ-9999", aos_hub_model::domain::Principal::user(1), &[])
        .await
        .unwrap());
    assert!(!db.deny_device("ZZZZ-9999").await.unwrap());
    // An unknown device_code is terminal rather than polling forever.
    assert!(matches!(
        db.poll_device("unknown").await.unwrap(),
        DevicePollResult::Expired
    ));
}

#[tokio::test]
async fn device_flow_expiry_blocks_approval() {
    use aos_hub_model::domain::Permission;
    let db = Database::open_in_memory().await.unwrap();
    let (_device_code, user_code, _) = db
        .start_device_authorization("instance", &[Permission::Read])
        .await
        .unwrap();
    // Force the grant to be expired.
    db.backend
        .execute(
            "UPDATE device_codes SET expires_at = ?1 WHERE user_code = ?2",
            &vals![unix_now() - 1, user_code],
        )
        .await
        .unwrap();
    assert!(!db
        .approve_device(&user_code, aos_hub_model::domain::Principal::user(1), &[])
        .await
        .unwrap());
}

#[tokio::test]
async fn approve_device_after_deny_mints_nothing() {
    use aos_hub_model::domain::{Permission, Principal, Role, Scope};
    let db = Database::open_in_memory().await.unwrap();
    let approver = db.create_user("admin@acme.com", None).await.unwrap();
    let principal = Principal::user(approver);
    let grants = vec![(Scope::root(), Role::Owner)];
    let (_device_code, user_code, _) = db
        .start_device_authorization("instance", &[Permission::Read])
        .await
        .unwrap();
    assert!(db.deny_device(&user_code).await.unwrap());
    assert!(!db
        .approve_device(&user_code, principal, &grants)
        .await
        .unwrap());
    assert!(
        db.list_tokens_for(principal).await.unwrap().is_empty(),
        "a denied grant mints no token"
    );
}

#[tokio::test]
async fn authorization_context_rejects_extraneous_closure_rows() {
    let db = Database::open_in_memory().await.unwrap();
    let left = db.create_org("left-scope", "Left").await.unwrap();
    let right = db.create_org("right-scope", "Right").await.unwrap();
    let left_scope = db.org_by_id(left).await.unwrap().unwrap().stable_id;
    let right_scope = db.org_by_id(right).await.unwrap().unwrap().stable_id;
    db.backend
        .execute(
            "INSERT INTO authorization_scope_ancestors
                   (descendant_scope_key, ancestor_scope_key, depth)
                 VALUES (?1, ?2, 2)",
            &vals![left_scope, right_scope],
        )
        .await
        .unwrap();

    assert!(db.authorization_context(&left_scope).await.is_err());
}

#[tokio::test]
async fn quota_defaults_to_unlimited_and_round_trips() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    // No quota row: every dimension unlimited.
    assert_eq!(db.org_quota(org).await.unwrap(), OrgQuota::default());
    assert!(!db.would_exceed_quota(org, i64::MAX / 2).await.unwrap());

    let quota = OrgQuota {
        max_bytes: Some(1000),
        max_objects: Some(10),
        max_registries: Some(2),
        max_tokens: Some(5),
    };
    db.set_org_quota(org, &quota).await.unwrap();
    assert_eq!(db.org_quota(org).await.unwrap(), quota);
}

#[tokio::test]
async fn usage_accumulates_and_drives_would_exceed_quota() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.set_org_quota(
        org,
        &OrgQuota {
            max_bytes: Some(100),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(db.org_usage(org).await.unwrap(), OrgUsage::default());
    // 60 more fits under 100.
    assert!(!db.would_exceed_quota(org, 60).await.unwrap());
    db.add_org_usage(org, 60, 1).await.unwrap();
    assert_eq!(db.org_usage(org).await.unwrap().used_bytes, 60);
    assert_eq!(db.org_usage(org).await.unwrap().object_count, 1);
    // 60 + 50 = 110 > 100: would exceed.
    assert!(db.would_exceed_quota(org, 50).await.unwrap());
    // 60 + 40 = 100 is not *over* 100.
    assert!(!db.would_exceed_quota(org, 40).await.unwrap());
}

#[tokio::test]
async fn root_crawl_policy_and_overrides_round_trip() {
    use aos_hub_model::crawl::CrawlPolicy;
    let db = Database::open_in_memory().await.unwrap();
    // Defaults to allow-all when unset.
    assert_eq!(db.root_crawl_policy().await.unwrap(), CrawlPolicy::AllowAll);
    db.set_root_crawl_policy(CrawlPolicy::AllowNoAi)
        .await
        .unwrap();
    assert_eq!(
        db.root_crawl_policy().await.unwrap(),
        CrawlPolicy::AllowNoAi
    );
    // A corrupt stored value reads as the permissive default (lenient read).
    db.instance_config_set("root_crawl_policy", "garbage")
        .await
        .unwrap();
    assert_eq!(db.root_crawl_policy().await.unwrap(), CrawlPolicy::AllowAll);

    // Root robots/llms overrides set and clear.
    assert_eq!(db.root_robots_body().await.unwrap(), None);
    db.set_root_robots_body(Some("User-agent: *\n"))
        .await
        .unwrap();
    assert_eq!(
        db.root_robots_body().await.unwrap(),
        Some("User-agent: *\n".to_string())
    );
    db.set_root_robots_body(None).await.unwrap();
    assert_eq!(db.root_robots_body().await.unwrap(), None);

    db.set_root_llms_body(Some("# hub\n")).await.unwrap();
    assert_eq!(
        db.root_llms_body().await.unwrap(),
        Some("# hub\n".to_string())
    );
    db.set_root_llms_body(None).await.unwrap();
    assert_eq!(db.root_llms_body().await.unwrap(), None);
}

#[tokio::test]
async fn soft_delete_excludes_from_serving_then_restore() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.register_owned(org, "acme/cdn").await;
    assert!(db.org_by_slug("acme").await.unwrap().is_some());
    assert_eq!(db.list_orgs().await.unwrap().len(), 1);
    assert_eq!(db.list_registries().await.unwrap().len(), 1);

    assert!(db.soft_delete_org(org, 30 * 86_400).await.unwrap());
    // Excluded from active serving queries...
    assert!(db.org_by_slug("acme").await.unwrap().is_none());
    assert!(db.list_orgs().await.unwrap().is_empty());
    assert!(db.list_registries().await.unwrap().is_empty());
    assert!(!db.org_is_active(org).await.unwrap());
    // ...but still visible to the admin/restore path.
    assert!(db
        .org_by_slug_including_deleted("acme")
        .await
        .unwrap()
        .is_some());

    assert!(db.restore_org(org).await.unwrap());
    assert!(db.org_by_slug("acme").await.unwrap().is_some());
    assert_eq!(db.list_registries().await.unwrap().len(), 1);
}

#[tokio::test]
async fn mirror_creation_rejects_unsafe_targets() {
    // The lib test binary never sets the escape hatch.
    assert!(std::env::var_os("AOS_HUB_ALLOW_LOCAL_REMOTES").is_none());
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_project(org, "infra", "Infrastructure")
        .await
        .unwrap();
    db.create_project(org, "infra/prod", "Production")
        .await
        .unwrap();
    let reg = db
        .create_managed_registry(org, "infra/prod", "cdn", "public", &[], false)
        .await
        .unwrap();

    // A file:// or loopback mirror upstream is rejected at creation.
    assert!(db
        .create_mirror_source(reg, "file:///srv/secret", "full", true, 3600)
        .await
        .is_err());
    assert!(db
        .create_mirror_source(reg, "http://127.0.0.1/", "full", true, 3600)
        .await
        .is_err());
    assert!(db
        .create_mirror_source(reg, "http://169.254.169.254/", "full", true, 3600)
        .await
        .is_err());

    // A public literal mirror passes creation (no DNS needed).
    assert!(db
        .create_mirror_source(reg, "https://93.184.216.34/", "full", true, 3600)
        .await
        .is_ok());
}

#[tokio::test]
async fn purge_only_after_grace_window() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let original_scope = db.org_by_id(org).await.unwrap().unwrap().stable_id;
    let project_id = db.create_project(org, "infra", "Infra").await.unwrap();
    let project = db
        .list_projects(org)
        .await
        .unwrap()
        .into_iter()
        .find(|project| project.id == project_id)
        .unwrap();
    let original_project_scope = project.scope_key.clone();
    let user = db.create_user("member@example.test", None).await.unwrap();
    db.grant_membership("user", user, &original_scope, "viewer")
        .await
        .unwrap();
    db.grant_membership("user", user, &original_project_scope, "viewer")
        .await
        .unwrap();
    db.grant_consumer_scope(
        crate::db::GrantResource::NetworkPolicy {
            id: "instance:public",
        },
        &original_scope,
        "explicit",
        "test",
        "request:purge-test-public-boundary",
    )
    .await
    .unwrap();
    let (_, old_secret) = db
        .create_token(
            aos_hub_model::domain::Principal::user(user),
            &original_project_scope,
            &[aos_hub_model::domain::Permission::Read],
            None,
            None,
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO network_policy_serving_pins
                 (pin_id, boundary_id, revision, consumer_scope_key, grant_generation,
                  grant_state, usage_kind, target_kind, target_stable_id,
                  target_generation_key, target_configuration_digest, acquired_by,
                  acquired_at, resource_version)
                 VALUES ('pin:purge-test', 'instance:public', 1, ?1, 1,
                   'active', 'topology_default', 'topology_default', ?1,
                   0, 'purge-test-digest', 'test', 0, 1)",
            &vals![original_scope],
        )
        .await
        .unwrap();
    db.backend
        .execute(
            "UPDATE network_policy_revision_lifecycle
                 SET consumer_version = consumer_version + 1
                 WHERE boundary_id = 'instance:public' AND revision = 1",
            &[],
        )
        .await
        .unwrap();
    let now = unix_now();
    db.soft_delete_org(org, 100).await.unwrap();
    // Not yet purgeable just after deletion.
    assert!(db.list_purgeable_orgs(now).await.unwrap().is_empty());
    // Past the grace window it is listed and can be purged.
    let purgeable = db.list_purgeable_orgs(now + 200).await.unwrap();
    assert_eq!(purgeable.len(), 1);
    assert!(db.hard_purge_org(org, now + 200).await.unwrap());
    assert!(db
        .org_by_slug_including_deleted("acme")
        .await
        .unwrap()
        .is_none());
    let pin_count: i64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM network_policy_serving_pins
                 WHERE consumer_scope_key = ?1",
            &vals![original_scope],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(pin_count, 0);
    let grant_count: i64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM network_policy_consumer_scopes
                 WHERE boundary_id = 'instance:public'
                   AND consumer_scope_key = ?1",
            &vals![original_scope],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(grant_count, 0);
    let revoke_events: i64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM consumer_scope_grant_events
                 WHERE resource_stable_id = 'instance:public'
                   AND consumer_scope_key = ?1 AND transition = 'revoked'",
            &vals![original_scope],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(revoke_events, 1);
    assert!(db.validate_token(&old_secret).await.unwrap().is_none());
    assert!(db
        .list_memberships_for("user", user)
        .await
        .unwrap()
        .is_empty());
    let recreated = db.create_org("acme", "Acme Recreated").await.unwrap();
    let recreated_scope = db.org_by_id(recreated).await.unwrap().unwrap().stable_id;
    assert_ne!(original_scope, recreated_scope);
    let recreated_project_id = db
        .create_project(recreated, "infra", "Infra")
        .await
        .unwrap();
    let recreated_project_scope = db
        .list_projects(recreated)
        .await
        .unwrap()
        .into_iter()
        .find(|project| project.id == recreated_project_id)
        .unwrap()
        .scope_key;
    assert_ne!(original_project_scope, recreated_project_scope);
    let recreated_grant: i64 = db
        .backend
        .query_opt(
            "SELECT COUNT(*) FROM network_policy_consumer_scopes
                 WHERE boundary_id = 'instance:public'
                   AND consumer_scope_key = ?1 AND state = 'active'",
            &vals![recreated_scope],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(recreated_grant, 0);
}

#[tokio::test]
async fn whole_surface_reads_prefer_the_reconciled_writer() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("reader", "Reader").await.unwrap();
    let binding = create_test_binding(&db, org, "reader", "/tmp/reader").await;
    let registry = db
        .create_managed_registry(org, "", "registry", "public", &[], false)
        .await
        .unwrap();

    let mut replica =
        topology_placement(SurfaceTarget::Registry(registry), "replica", "replica", 0);
    replica.binding_id = binding;
    let replica = db.create_surface_placement(&replica).await.unwrap();
    db.observe_surface_placement(replica.id, "ready", "complete", 1)
        .await
        .unwrap();

    let mut writer = topology_placement(SurfaceTarget::Registry(registry), "writer", "writer", 100);
    writer.binding_id = binding;
    let writer = db.create_surface_placement(&writer).await.unwrap();
    let writer = db
        .observe_surface_placement(writer.id, "ready", "complete", 1)
        .await
        .unwrap();
    let generation =
        create_valid_write_credential(&db, binding, "secret://binding/reader/v1").await;
    let revision = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id: binding,
            write_credential_generation: generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "reader-write-v1".to_string(),
            capability_fingerprint: "reader-writes-and-conditional".to_string(),
        })
        .await
        .unwrap();
    db.observe_binding_write_revision(binding, revision.revision, "valid", None, None)
        .await
        .unwrap();
    db.bind_surface_placement_write_capability(writer.id, revision.revision)
        .await
        .unwrap();
    db.create_surface_write_authority(
        SurfaceTarget::Registry(registry),
        "reader-authority-v1",
        writer.id,
        writer.resource_version,
        writer.write_spec_version,
        revision.revision,
    )
    .await
    .unwrap();

    assert_eq!(
        db.reconciled_surface_reader(SurfaceTarget::Registry(registry))
            .await
            .unwrap()
            .id,
        writer.id,
        "a lower-order replica must not supersede the current mutable surface"
    );
    db.assert_registry_index_mutation_source(registry, Some(writer.id))
        .await
        .unwrap();

    db.observe_surface_placement(writer.id, "offline", "complete", 2)
        .await
        .unwrap();
    assert!(
        db.reconciled_surface_reader(SurfaceTarget::Registry(registry))
            .await
            .is_err(),
        "an unavailable writer must not fall back to an unproven replica"
    );
    assert!(
        db.backend
            .checked_batch(&[Database::registry_index_mutation_guard(
                registry,
                Some(writer.id),
            )])
            .await
            .is_err(),
        "the commit guard must reject authority changes after preflight"
    );
}
