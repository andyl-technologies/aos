//! Database dialect contract tests (RFC-0004 phase 4c "Database abstraction").
//!
//! The same exercise — build the full schema, then drive a representative
//! cross-section of [`Database`](aos_hub::db::Database) methods — is
//! run against every backend the build supports:
//!
//! - **sqlite** always, in-memory and hermetic.
//! - **postgres** when `AOS_HUB_TEST_PG_URL` is set *and* the crate is built
//!   with `--features postgres`.
//! - **mysql** when `AOS_HUB_TEST_MYSQL_URL` is set *and* the crate is built
//!   with `--features mysql`.
//!
//! When an env var is unset (or its feature is off) the corresponding case
//! prints a skip notice and is a no-op, so the suite passes cleanly with no
//! live servers. The pg/mysql cases drop and recreate a clean schema before
//! connecting, so repeated runs against a long-lived server are idempotent.
//!
//! Run the live cases with, e.g.:
//!
//! ```text
//! AOS_HUB_TEST_PG_URL=postgresql://postgres:hub@localhost:55432/hubtest \
//! AOS_HUB_TEST_MYSQL_URL=mysql://root:hub@localhost:55306/hubtest \
//!   cargo test -p aos-hub --features postgres,mysql --test dialect -- --nocapture
//! ```

use aos_hub::db::Database;
use aos_hub::domain::{Permission, Principal};

/// Drives the representative cross-section of the `Database` surface against an
/// already-migrated handle, asserting the parity invariants that must hold on
/// every dialect.
///
/// Covers: org/user/service-account creation, membership grants and effective
/// scope resolution, token mint + validation, managed-registry creation,
/// managed-cache CRUD + link + object index + GC-run lifecycle + metrics, a
/// config change-set apply, audit record + scoped list, and the webhook
/// enqueue/list path.
async fn exercise(db: &Database) {
    // The mirror/frontend creation paths SSRF-validate their target; these
    // contract assertions use placeholder hosts, so opt out of the
    // local/internal-address rejection (the non-HTTP scheme rejection still
    // applies). Production never sets this.
    std::env::set_var("AOS_HUB_ALLOW_LOCAL_REMOTES", "1");

    // -- orgs, projects, users -------------------------------------------------
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    assert_eq!(db.org_by_slug("acme").await.unwrap().unwrap().id, org);
    db.create_project(org, "infra", "Infrastructure")
        .await
        .unwrap();
    assert_eq!(db.list_projects(org).await.unwrap().len(), 1);

    let alice = db
        .create_user("alice@acme.com", Some("Alice"))
        .await
        .unwrap();
    assert_eq!(
        db.user_by_email("alice@acme.com").await.unwrap(),
        Some(alice)
    );
    assert_eq!(
        db.user_email(alice).await.unwrap().as_deref(),
        Some("alice@acme.com")
    );

    let ci = db.create_service_account(org, "ci").await.unwrap();
    assert_eq!(
        db.service_account_by_name(org, "ci").await.unwrap(),
        Some(ci)
    );

    // -- memberships + effective scopes ---------------------------------------
    let principal = Principal::user(alice);
    db.grant_membership(principal.kind.as_str(), principal.id, "acme", "admin")
        .await
        .unwrap();
    db.grant_membership(
        principal.kind.as_str(),
        principal.id,
        "acme/infra/prod/cdn",
        "maintainer",
    )
    .await
    .unwrap();
    let scopes = db.effective_scopes(principal).await.unwrap();
    assert_eq!(scopes.len(), 2, "two grants resolve");
    assert_eq!(
        db.list_memberships_for("user", alice).await.unwrap().len(),
        2
    );
    assert_eq!(db.list_members_of_scope("acme").await.unwrap().len(), 1);

    // -- tokens ----------------------------------------------------------------
    let (token_id, secret) = db
        .create_token(
            principal,
            "acme/infra",
            &[Permission::Read, Permission::Publish],
            Some("ci token"),
            None,
        )
        .await
        .unwrap();
    let auth = db
        .validate_token(&secret)
        .await
        .unwrap()
        .expect("freshly minted token validates");
    assert_eq!(auth.token_id, token_id);
    assert_eq!(auth.owner, principal);
    assert_eq!(auth.scope.as_str(), "acme/infra");
    assert_eq!(
        auth.permissions,
        vec![Permission::Read, Permission::Publish]
    );
    assert!(
        db.validate_token("aos_not_a_real_secret")
            .await
            .unwrap()
            .is_none(),
        "unknown secret rejected"
    );

    // -- storage binding + managed registry -----------------------------------
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", "/srv/aos-hub")
        .await
        .unwrap();
    let reg = db
        .create_managed_registry(
            org,
            "infra/prod",
            "cdn",
            "private",
            Some(binding),
            "infra/prod/cdn",
            &["cdn:Ed25519:AAAA".to_string()],
            true,
        )
        .await
        .unwrap();
    let record = db
        .registry_by_scope("acme", "infra/prod", "cdn")
        .await
        .unwrap()
        .expect("managed registry resolves by scope");
    assert_eq!(record.id, reg);
    assert_eq!(record.visibility, "private");
    assert_eq!(record.storage_binding_id, Some(binding));

    // -- managed caches (v22+) -------------------------------------------------
    // Exercise the cache schema on every dialect: create, link to a registry,
    // index an object, recompute usage, run the GC-run lifecycle, and read the
    // instance-wide metrics aggregate.
    let cache = db
        .create_cache(
            Some(org),
            "acme-cache",
            "Acme Cache",
            Some(binding),
            "cache",
            None,
            "public",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        db.cache_by_slug("acme-cache").await.unwrap().unwrap().id,
        cache
    );
    db.link_cache(cache, reg, true, true).await.unwrap();
    assert_eq!(db.list_cache_links(cache).await.unwrap().len(), 1);
    db.upsert_cache_object(&aos_hub_core::db::CacheObject {
        cache_id: cache,
        store_hash: "cafe".into(),
        store_name: "cafe-hello-1.0".into(),
        nar_url: "nar/aa.nar.zst".into(),
        nar_hash: "sha256:aa".into(),
        nar_size: 200,
        file_hash: "aa".into(),
        file_size: 120,
        compression: "zstd".into(),
        deriver: None,
        refs: vec![],
        sig: None,
        ca: None,
        uploaded_at: 0,
        last_accessed_at: None,
    })
    .await
    .unwrap();
    let usage = db.refresh_cache_usage(cache).await.unwrap();
    assert_eq!(usage.object_count, 1);
    assert_eq!(usage.used_bytes, 120);
    assert_eq!(
        db.search_cache_objects(cache, "hello", 10)
            .await
            .unwrap()
            .len(),
        1
    );
    let run = db.start_cache_gc_run(cache).await.unwrap();
    db.finish_cache_gc_run(run, "ok", None, 1, 1, 0, 0)
        .await
        .unwrap();
    assert_eq!(db.list_cache_gc_runs(cache, 10).await.unwrap().len(), 1);
    let m = db.cache_metrics().await.unwrap();
    assert_eq!(m.cache_count, 1);
    assert_eq!(m.object_count, 1);
    assert_eq!(m.used_bytes, 120);
    assert_eq!(m.gc_runs_ok, 1);

    // -- configuration change-set ---------------------------------------------
    let change_id = "00000000-0000-4000-8000-000000000001";
    db.create_changeset(
        change_id,
        "user",
        Some(alice),
        "alice@acme.com",
        "acme/infra/prod/cdn",
        Some("make cdn public"),
    )
    .await
    .unwrap();
    db.add_revision(
        change_id,
        "registry",
        "acme/infra/prod/cdn",
        "update",
        Some(r#"{"visibility":"private"}"#),
        Some(r#"{"visibility":"public"}"#),
    )
    .await
    .unwrap();
    // Collect the object types touched by the changeset, then apply the live
    // mutation outside the closure: the closure passed to `apply_changeset`
    // returns a `'static`-friendly boxed future, so it must not borrow `db`.
    let touched = std::sync::Arc::new(std::sync::Mutex::new(Vec::<bool>::new()));
    let touched_in = std::sync::Arc::clone(&touched);
    db.apply_changeset(change_id, move |rev| {
        let is_registry = rev.object_type == "registry";
        let touched_in = std::sync::Arc::clone(&touched_in);
        Box::pin(async move {
            touched_in.lock().unwrap().push(is_registry);
            Ok(())
        })
    })
    .await
    .unwrap();
    if touched.lock().unwrap().iter().any(|&r| r) {
        db.set_registry_visibility(reg, "public").await.unwrap();
    }
    assert_eq!(
        db.registry_by_slug("acme/infra/prod/cdn")
            .await
            .unwrap()
            .unwrap()
            .visibility,
        "public",
        "change-set applied the visibility flip"
    );
    assert_eq!(
        db.changeset(change_id).await.unwrap().unwrap().status,
        "applied"
    );
    assert_eq!(db.list_revisions(change_id).await.unwrap().len(), 1);

    // -- audit -----------------------------------------------------------------
    db.record_audit(
        "user",
        Some(alice),
        "alice@acme.com",
        "registry.visibility",
        "acme/infra/prod/cdn",
        Some(change_id),
        None,
        None,
        Some(r#"{"old":"private","new":"public"}"#),
    )
    .await
    .unwrap();
    let org_audit = db.list_audit("acme").await.unwrap();
    assert_eq!(
        org_audit.len(),
        1,
        "org-scoped query surfaces the registry action"
    );
    assert_eq!(org_audit[0].action, "registry.visibility");
    assert!(
        db.list_audit("other").await.unwrap().is_empty(),
        "an unrelated scope sees nothing"
    );

    // -- webhooks --------------------------------------------------------------
    let hook = db
        .create_webhook(
            org,
            "https://ci.acme/hook",
            "shared-secret",
            &["index.completed".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(db.list_webhooks(org).await.unwrap().len(), 1);
    let delivery = db
        .enqueue_delivery(
            hook,
            "index.completed",
            r#"{"registry":"acme/infra/prod/cdn"}"#,
        )
        .await
        .unwrap();
    let due = db.due_deliveries(i64::MAX).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].id, delivery);
    assert_eq!(due[0].url, "https://ci.acme/hook");
    let (pending, delivered, failed) = db.delivery_status_counts().await.unwrap();
    assert_eq!((pending, delivered, failed), (1, 0, 0));

    // -- validation findings + repair jobs (v14) ------------------------------
    // Record a deep run with one missing and one corrupt finding, then assert
    // they round-trip distinctly on every dialect.
    let run_id = db
        .record_validation_run_with_findings(
            reg,
            "file:///srv/cache",
            "deep",
            5,
            &[
                aos_hub::db::ValidationFinding {
                    store_hash: "absent01".into(),
                    status: aos_hub::db::FindingStatus::Missing,
                },
                aos_hub::db::ValidationFinding {
                    store_hash: "tampered1".into(),
                    status: aos_hub::db::FindingStatus::Corrupt,
                },
            ],
            true,
            0,
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        db.validation_missing(run_id).await.unwrap(),
        vec!["absent01"]
    );
    assert_eq!(
        db.validation_corrupt(run_id).await.unwrap(),
        vec!["tampered1"]
    );

    // Record a repair job and read it back.
    db.record_repair_job(
        reg,
        "file:///srv/cache",
        "absent01",
        "file:///srv/good",
        "done",
        None,
        0,
        Some(1),
    )
    .await
    .unwrap();
    let jobs = db.list_repair_jobs(reg, 10).await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, "done");
    assert_eq!(jobs[0].store_hash, "absent01");
    assert_eq!(jobs[0].source_cache_url, "file:///srv/good");

    // -- mirror sources + frontends (v16) -------------------------------------
    // A mirror source round-trips and `is_mirror` flips; the last-sync record
    // updates without clobbering the frontier on a later failure.
    assert!(!db.is_mirror(reg).await.unwrap());
    db.create_mirror_source(reg, "https://upstream.example/", "full", true, 1800)
        .await
        .unwrap();
    assert!(db.is_mirror(reg).await.unwrap());
    let source = db.mirror_source(reg).await.unwrap().expect("mirror source");
    assert_eq!(source.upstream_url, "https://upstream.example/");
    assert_eq!(source.mode, "full");
    assert!(source.verify);
    assert_eq!(source.schedule_secs, 1800);
    db.update_mirror_sync(reg, 100, "ok", None, Some("2.0.0"))
        .await
        .unwrap();
    db.update_mirror_sync(reg, 200, "failed", Some("upstream tampered"), None)
        .await
        .unwrap();
    let source = db.mirror_source(reg).await.unwrap().unwrap();
    assert_eq!(source.last_sync_status.as_deref(), Some("failed"));
    assert_eq!(source.last_sync_error.as_deref(), Some("upstream tampered"));
    // The frontier from the prior OK sync survives the later failure.
    assert_eq!(source.upstream_frontier.as_deref(), Some("2.0.0"));
    assert_eq!(db.list_mirror_sources().await.unwrap().len(), 1);

    // A frontend CRUD round-trip plus a probe upsert.
    let fe = db
        .create_frontend(
            reg,
            "cdn.acme.com",
            "",
            "direct",
            true,
            true,
            false,
            200,
            true,
        )
        .await
        .unwrap();
    let frontends = db.list_frontends(reg).await.unwrap();
    assert_eq!(frontends.len(), 1);
    assert_eq!(frontends[0].domain, "cdn.acme.com");
    assert_eq!(frontends[0].mode, "direct");
    assert!(frontends[0].serves_cache);
    assert!(!frontends[0].serves_web);
    db.upsert_frontend_probe(fe, "ok", Some("8.5.0"), Some(0), 12, 300)
        .await
        .unwrap();
    let probes = db.list_frontend_probes(reg).await.unwrap();
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].status.as_deref(), Some("ok"));
    assert_eq!(probes[0].observed_frontier.as_deref(), Some("8.5.0"));
    assert!(db.delete_frontend(fe).await.unwrap());
    assert!(db.list_frontends(reg).await.unwrap().is_empty());
    // The probe row cascades away with its frontend.
    assert!(db.list_frontend_probes(reg).await.unwrap().is_empty());
}

#[tokio::test]
async fn sqlite_contract() {
    let db = Database::open_in_memory().await.unwrap();
    exercise(&db).await;
    println!("dialect contract: sqlite OK");
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_contract() {
    let Ok(url) = std::env::var("AOS_HUB_TEST_PG_URL") else {
        println!("dialect contract: postgres SKIPPED (AOS_HUB_TEST_PG_URL unset)");
        return;
    };
    reset_pg_schema(&url);
    let db = Database::connect(&url)
        .await
        .expect("connect + migrate postgres");
    exercise(&db).await;
    println!("dialect contract: postgres OK ({url})");
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn mysql_contract() {
    let Ok(url) = std::env::var("AOS_HUB_TEST_MYSQL_URL") else {
        println!("dialect contract: mysql SKIPPED (AOS_HUB_TEST_MYSQL_URL unset)");
        return;
    };
    reset_mysql_schema(&url);
    let db = Database::connect(&url)
        .await
        .expect("connect + migrate mysql");
    exercise(&db).await;
    println!("dialect contract: mysql OK ({url})");
}

/// Drops every table in the target postgres database, so the subsequent
/// connect re-runs all migrations from scratch and the run is idempotent.
#[cfg(feature = "postgres")]
fn reset_pg_schema(url: &str) {
    use postgres::{Client, NoTls};
    let mut client = Client::connect(url, NoTls).expect("connecting to postgres for schema reset");
    // The public schema cascade is the cleanest full reset for a test database.
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .expect("dropping public schema");
}

/// Drops every table in the target mysql database, so the subsequent connect
/// re-runs all migrations from scratch and the run is idempotent.
#[cfg(feature = "mysql")]
fn reset_mysql_schema(url: &str) {
    use mysql::prelude::Queryable;
    use mysql::{Conn, Opts, OptsBuilder};
    let opts = Opts::from_url(url).expect("parsing mysql url for schema reset");
    let db_name = opts.get_db_name().map(str::to_string);
    let mut conn = Conn::new(OptsBuilder::from_opts(opts)).expect("connecting to mysql for reset");
    if let Some(db) = db_name {
        // Drop and recreate the whole database — the simplest idempotent reset.
        conn.query_drop(format!("DROP DATABASE IF EXISTS `{db}`"))
            .expect("dropping mysql database");
        conn.query_drop(format!("CREATE DATABASE `{db}`"))
            .expect("creating mysql database");
        conn.query_drop(format!("USE `{db}`"))
            .expect("selecting mysql database");
    }
}
