//! Consumer-cache freshness probe coverage (RFC-0004 phase-1
//! probes").
//!
//! Builds a registry surface that commits two caches — a reachable `file://`
//! cache (the surface itself, which carries a `nix-cache-info`) and an
//! unreachable HTTP cache — indexes it so `advertised_caches` is populated,
//! probes them, and asserts the recorded statuses plus the health-page table.

mod common;

use std::path::Path;
use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::Database;
use aos_hub::fetch::{hardened_client, LocalFsFetch};
use aos_hub::indexer::index_and_record;
use aos_hub::probe::{probe_caches, ProbeStatus};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Build an [`AppState`] over `db`.
async fn app_state(db: Arc<Database>) -> Arc<AppState> {
    let auth = Arc::new(AuthState {
        db: Arc::clone(&db),
        jwt_keys: JwtKeys::from_secret(b"probe-test-secret-32byte-key!!!!"),
        access_token_ttl: 900,
        ratelimit: aos_hub::ratelimit::RateLimiter::new().into(),
        trusted_proxy: false,
    });
    Arc::new(AppState {
        db,
        external_url: "http://127.0.0.1:8420".into(),
        ratelimit: auth.ratelimit.clone(),
        trusted_proxy: false,
        auth,
        leases: std::sync::Arc::new(aos_hub::facade::LeaseMap::new()),
        sealer: aos_hub::auth::oidc::dev_sealer(),
        secret_versions: aos_hub_core::secret_version::EmptySecretVersionResolver::shared(),
        http: hardened_client().await,
        image_snapshots: None,
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        route_reservation_keyring: None,
    })
}

/// Build a registry surface at `surface` committing the two given caches.
fn build_surface(surface: &Path, caches_toml: &str) -> common::Fixture {
    let fixture = common::Fixture::new(surface);

    let registry_toml = fixture.put_blob(&format!(
        "[registry]\nname = \"demo\"\ndescription = \"Probe fixture\"\n\n{caches_toml}"
    ));
    let keys_toml = fixture.put_blob(&format!(
        "schema = 1\n\n[[keys]]\nid = \"maintainer\"\nkey = \"{}\"\n",
        fixture.trust_key,
    ));
    let curl_toml = fixture.put_blob(
        "[package]\nname = \"curl\"\ndescription = \"URL transfers\"\nlicense = \"MIT\"\n\
         maintainer = \"aos\"\n\n[[versions]]\nversion = \"8.5.0\"\n\n\
         [versions.platforms.x86_64-linux]\nstore_path = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0\"\n\
         nar_hash = \"sha256:aa\"\nnar_size = 10\nclosure_size = 20\n\
         source_drv = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0.drv\"\n\
         source_nar_hash = \"sha256:bb\"\nreferences = []\n",
    );
    let closure_blob = fixture.put_blob("h7j3k8l2m9n4\n");

    let bucket_c = fixture.put_tree(&[("100644", "curl.toml", curl_toml)]);
    let packages = fixture.put_tree(&[("40000", "c", bucket_c)]);
    let closures = fixture.put_tree(&[("100644", "h7j3k8l2m9n4", closure_blob)]);
    let root_tree = fixture.put_tree(&[
        ("100644", "keys.toml", keys_toml),
        ("100644", "registry.toml", registry_toml),
        ("40000", "closures", closures),
        ("40000", "packages", packages),
    ]);

    let commit = fixture.put_signed_commit(root_tree, "release 1.0.0");
    let release_tag = fixture.put_release_tag("1.0.0", commit);
    fixture.put_channel("stable", release_tag);
    fixture.put_refs(
        "stable",
        &[("stable", commit)],
        &[("1.0.0", release_tag, commit)],
    );
    fixture.put_nix_cache();
    fixture
}

#[tokio::test]
async fn probes_record_reachable_and_unreachable_caches() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();

    // Commit a reachable file:// cache (the surface carries a nix-cache-info)
    // and an unreachable HTTP cache (nothing listens there).
    let caches_toml = format!(
        "[caches]\nkind = \"try\"\nmembers = [\n  {{ endpoint = \"file://{}\" }},\n  {{ endpoint = \"http://127.0.0.1:9/\" }},\n]\n",
        surface.display()
    );
    let fixture = build_surface(&surface, &caches_toml);

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let id = db
        .register_registry("demo", std::slice::from_ref(&fixture.trust_key), true)
        .await
        .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    assert_eq!(registry.id, id);

    index_and_record(&db, &LocalFsFetch::new(&surface), &registry)
        .await
        .unwrap();

    // Probe the committed caches.
    let http = hardened_client().await;
    let probes = probe_caches(&db, &http, &registry).await.unwrap();
    let by_url = |needle: &str| {
        probes
            .iter()
            .find(|p| p.cache_url.contains(needle))
            .unwrap_or_else(|| panic!("no probe for {needle}: {probes:?}"))
    };
    assert_eq!(by_url("file://").status, ProbeStatus::Ok);
    assert!(by_url("file://").observed_nix_cache_info);
    assert_eq!(by_url("127.0.0.1:9").status, ProbeStatus::Unreachable);

    // The rows persisted, and the health page surfaces them.
    let rows = db.list_cache_probes(registry.id).await.unwrap();
    assert_eq!(rows.len(), 2);

    let app = router(app_state(Arc::clone(&db)).await).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/demo/-/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Cache freshness"), "{html}");
    assert!(html.contains("unreachable"), "{html}");
}
