//! Cache-repair authorization coverage.
//!
//! An arbitrary HTTP target that is not one of the cache's ready delivery
//! routes remains plan-only and never receives credentials or bytes.

mod common;

use std::path::Path;
use std::sync::Arc;

use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::Database;
use aos_hub::fetch::hardened_client;
use aos_hub::server::HubRepairAuthorizer;
use aos_hub::validation;

/// Deterministic HS256 key so the authorizer's minted JWTs verify against the
/// running hub.
const TEST_JWT_SECRET: &[u8] = b"repair-test-secret-32-byte-key!!!";

/// Create org "acme", a `local_fs` binding rooted at `binding_root`, and a
/// managed registry at `acme/infra/prod/cdn` with surface prefix `cdn` and the
/// given visibility. Returns the registry id.
async fn create_managed_with_visibility(
    db: &Database,
    binding_root: &Path,
    visibility: &str,
) -> i64 {
    create_managed_with_keys(db, binding_root, visibility, &[]).await
}

/// As [`create_managed_with_visibility`], but enrolls a narinfo trust roster so
/// the repair path's mandatory signature gate can be exercised against a signed
/// source object.
async fn create_managed_with_keys(
    db: &Database,
    binding_root: &Path,
    visibility: &str,
    trust_keys: &[String],
) -> i64 {
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    db.create_project(org, "infra/prod", "Production")
        .await
        .unwrap();
    let _binding =
        common::create_local_binding(&db, org, "primary", binding_root.to_str().unwrap()).await;
    db.create_managed_registry(org, "infra/prod", "cdn", visibility, trust_keys, false)
        .await
        .unwrap()
}

/// [`create_managed_with_visibility`] with `private` visibility.
async fn create_managed(db: &Database, binding_root: &Path) -> i64 {
    create_managed_with_visibility(db, binding_root, "private").await
}

#[tokio::test]
async fn http_repair_to_unauthorized_target_is_plan_only() {
    // A file:// source holding the object.
    let source_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        source_dir.path().join("abc.narinfo"),
        b"StorePath: /var/lib/store/abc-curl-8.5.0\n",
    )
    .unwrap();
    let source_url = format!("file://{}", source_dir.path().display());

    // An external HTTP target that is not a ready managed-cache route.
    let target_url = "https://external.example.com/cache".to_string();

    let binding_dir = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let reg_id = create_managed(&db, binding_dir.path()).await;
    let registry = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();

    // Record validation runs directly so the repair plan targets the external
    // cache: the source holds `abc`, the external target is missing it. (We
    // bypass live probing — the external URL is not really reachable.)
    db.record_validation_run(reg_id, &source_url, "presence", 1, &[], true, 0, 1)
        .await
        .unwrap();
    db.record_validation_run(
        reg_id,
        &target_url,
        "presence",
        1,
        &["abc".to_string()],
        true,
        0,
        1,
    )
    .await
    .unwrap();

    // The target does not resolve to a managed cache, so it remains plan-only.
    let authorizer = HubRepairAuthorizer::new(
        Arc::clone(&db),
        JwtKeys::from_secret(TEST_JWT_SECRET),
        "http://hub.test".to_string(),
    );
    let client = hardened_client().await;
    let summary = validation::run_repairs(&db, &client, &registry, &authorizer)
        .await
        .unwrap();
    assert_eq!(summary.done, 0);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.plan_only, 1, "external target left as a plan");

    let jobs = db.list_repair_jobs(reg_id, 10).await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, "plan_only");
    assert_eq!(jobs[0].cache_url, target_url);
}
