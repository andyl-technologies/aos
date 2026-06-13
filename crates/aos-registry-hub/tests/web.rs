//! Web-surface integration tests: security headers, the phase-1 browse
//! pages (search, calculator, health, releases), content negotiation,
//! and the autoindex fallback — all over the real router against a
//! signed fixture surface.

mod common;

use std::path::Path;
use std::sync::Arc;

use aos_registry_hub::db::Database;
use aos_registry_hub::fetch::LocalFsFetch;
use aos_registry_hub::indexer::index_and_record;
use aos_registry_hub::server::{router, AppState};
use aos_registry_hub::validation::validate_presence;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    get_with_accept(app, uri, None).await
}

async fn get_with_accept(
    app: &axum::Router,
    uri: &str,
    accept: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut request = Request::builder().uri(uri);
    if let Some(accept) = accept {
        request = request.header(header::ACCEPT, accept);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

/// Register and index a fixture surface, returning the served app + db.
async fn serve_fixture(surface: &Path, fixture: &common::Fixture) -> (axum::Router, Arc<Database>) {
    let db = Arc::new(Database::open_in_memory().unwrap());
    db.register_registry(
        "demo",
        surface.to_str().unwrap(),
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .unwrap();
    let registry = db.registry_by_slug("demo").unwrap().unwrap();
    index_and_record(&db, &LocalFsFetch::new(surface), &registry)
        .await
        .unwrap();
    let app = router(Arc::new(AppState::new(
        Arc::clone(&db),
        "http://127.0.0.1:8420".into(),
    )));
    (app, db)
}

/// A standard fixture whose `curl.toml` carries a custom homepage.
fn fixture_with_homepage(root: &Path, homepage: &str) -> common::Fixture {
    let fixture = common::Fixture::new(root);

    let registry_toml = fixture.put_blob(
        "[registry]\nname = \"demo\"\ndescription = \"Fixture registry\"\n\n\
         [[caches]]\nurl = \"https://cache.example.com/\"\npriority = 40\n",
    );
    let keys_toml = fixture.put_blob(&format!(
        "schema = 1\n\n[[keys]]\nid = \"maintainer\"\nkey = \"{}\"\n",
        fixture.trust_key,
    ));
    let curl_toml = fixture.put_blob(&format!(
        "[package]\nname = \"curl\"\ndescription = \"URL transfers\"\nlicense = \"MIT\"\n\
         maintainer = \"aos\"\nhomepage = \"{homepage}\"\n\n[[versions]]\nversion = \"8.5.0\"\n\n\
         [versions.platforms.x86_64-linux]\nstore_path = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0\"\n\
         nar_hash = \"sha256:aa\"\nnar_size = 10\nclosure_size = 20\n\
         source_drv = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0.drv\"\n\
         source_nar_hash = \"sha256:bb\"\nreferences = []\n",
    ));
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
async fn security_headers_on_every_route_class() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    for uri in [
        "/",                                               // instance home
        "/demo/",                                          // registry page
        "/demo/-/packages",                                // /-/ page
        "/demo/HEAD",                                      // machine path
        "/_assets/style.css",                              // stylesheet
        "/_assets/jetbrains-mono-regular.woff2",           // embedded font
        "/aos.registry.v1.RegistryService/ListRegistries", // RPC path
        "/demo/does-not-exist",                            // 404s carry the headers too
    ] {
        let (_, headers, _) = get(&app, uri).await;
        assert_eq!(
            headers
                .get("content-security-policy")
                .and_then(|v| v.to_str().ok()),
            Some("default-src 'self'"),
            "CSP missing on {uri}"
        );
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff"),
            "nosniff missing on {uri}"
        );
    }
}

#[tokio::test]
async fn javascript_homepage_is_not_a_link() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = fixture_with_homepage(&surface, "javascript:alert(1)");
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    let (status, _, body) = get(&app, "/demo/-/packages/curl").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("href=\"javascript:"),
        "javascript: homepage must not become a link: {body}"
    );
    assert!(body.contains("javascript:alert(1)"), "shown as plain text");
}

#[tokio::test]
async fn health_page_shows_unreachable_cache_after_validation() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, db) = serve_fixture(&surface, &fixture).await;

    // Before any validation run, the home page says so.
    let (_, _, home) = get(&app, "/demo/").await;
    assert!(home.contains("not yet validated"));

    // The fixture's committed cache (https://cache.example.com) does not
    // resolve, so presence validation records it unreachable.
    let registry = db.registry_by_slug("demo").unwrap().unwrap();
    validate_presence(&db, &registry).await.unwrap();

    let (status, _, body) = get(&app, "/demo/-/health").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("https://cache.example.com/"), "{body}");
    assert!(body.contains("unreachable"), "{body}");
    assert!(body.contains("presence"), "{body}");

    // The registry home's cache table reflects the same run.
    let (_, _, home) = get(&app, "/demo/").await;
    assert!(home.contains("unreachable"), "{home}");
}

#[tokio::test]
async fn channel_calculator_resolves_bucket() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    let (status, _, body) = get(&app, "/demo/-/channels/stable?bucket=0a").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("0x0A"), "{body}");
    assert!(body.contains("release <strong>1.0.0</strong>"), "{body}");
    assert!(body.contains("class=\"hit\""), "{body}");
    // The anti-rollback floor (recorded at index time) is shown.
    assert!(body.contains("floor <strong>1.0.0</strong>"), "{body}");
}

#[tokio::test]
async fn package_search_filters_by_substring() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    let (status, _, body) = get(&app, "/demo/-/packages?q=curl").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("1 of 1 packages match"), "{body}");
    assert!(body.contains("/demo/-/packages/curl"), "{body}");

    let (status, _, body) = get(&app, "/demo/-/packages?q=zzz").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("0 of 1 packages match"), "{body}");
    assert!(!body.contains("/demo/-/packages/curl"), "{body}");

    // The instance home searches registries the same way.
    let (_, _, body) = get(&app, "/?q=fixture").await;
    assert!(body.contains("1 of 1 registries match"), "{body}");
    let (_, _, body) = get(&app, "/?q=zzz").await;
    assert!(body.contains("0 of 1 registries match"), "{body}");
}

#[tokio::test]
async fn autoindex_lists_channel_partitions() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    let (status, headers, body) = get(&app, "/demo/channels/stable/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    assert!(body.contains("Index of /demo/channels/stable/"), "{body}");
    assert!(body.contains("<a href=\"../\">../</a>"), "{body}");
    assert!(body.contains("<a href=\"00\">00</a>"), "{body}");
    assert!(body.contains("<a href=\"ff\">ff</a>"), "{body}");

    // The bare directory path redirects to the trailing-slash form, and
    // partition files themselves still serve bytes.
    let (status, headers, _) = get(&app, "/demo/channels/stable").await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(headers[header::LOCATION], "/demo/channels/stable/");
    let (status, _, body) = get(&app, "/demo/channels/stable/00").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("tag stable"));
}

#[tokio::test]
async fn releases_page_shows_pack_presence() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    // The per-release pack listing must exist *before* indexing — the
    // indexer probes it during the walk.
    std::fs::create_dir_all(surface.join("releases/1/0/0/objects/info")).unwrap();
    std::fs::write(
        surface.join("releases/1/0/0/objects/info/packs"),
        "P pack-aaaa.pack\n",
    )
    .unwrap();
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    let (status, _, body) = get(&app, "/demo/-/releases").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("✓ pack"), "{body}");
    assert!(body.contains("ago"), "tagged column carries a relative age");
    assert!(body.contains("unix 1770000000"), "{body}");
}

#[tokio::test]
async fn registry_home_carries_setup_snippets_and_fingerprints() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    let (status, _, body) = get(&app, "/demo/").await;
    assert_eq!(status, StatusCode::OK);
    // All three setup snippets.
    assert!(
        body.contains("apr add http://127.0.0.1:8420/demo/"),
        "{body}"
    );
    assert!(body.contains("aos.apm.registries.demo"), "{body}");
    assert!(body.contains("trustKeys"), "{body}");
    assert!(body.contains("substituters = http://127.0.0.1:8420/demo/"));
    assert!(body.contains("trusted-public-keys ="), "{body}");
    // The pinned anchor appears in full and as a SHA256: fingerprint.
    assert!(body.contains(&fixture.trust_key), "{body}");
    assert!(body.contains("SHA256:"), "{body}");
    // Frontier freshness is above the fold ("indexed Ns ago" — the index
    // ran moments before this request).
    assert!(body.contains("indexed "), "{body}");
    assert!(body.contains("s ago"), "{body}");
}

#[tokio::test]
async fn registry_root_content_negotiates() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    // Browsers (and Accept-less clients like curl) get the HTML page.
    let (status, _, body) = get_with_accept(&app, "/demo/", Some("text/html")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Fixture registry"));
    let (status, _, _) = get(&app, "/demo/").await;
    assert_eq!(status, StatusCode::OK);

    // A non-HTML Accept without a committed index.html is 406.
    let (status, _, _) = get_with_accept(&app, "/demo/", Some("application/json")).await;
    assert_eq!(status, StatusCode::NOT_ACCEPTABLE);

    // Once the surface ships an index.html, the same request serves it.
    std::fs::write(surface.join("index.html"), "<!DOCTYPE html>static page\n").unwrap();
    let (status, _, body) = get_with_accept(&app, "/demo/", Some("application/json")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("static page"));
}
