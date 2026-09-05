//! Web-surface integration tests: security headers, the phase-1 browse
//! pages (search, calculator, health, releases), content negotiation,
//! and the autoindex fallback — all over the real router against a
//! signed fixture surface.

mod common;

use std::path::Path;
use std::sync::Arc;

use aos_hub::db::{Database, SurfaceTarget};
use aos_hub::fetch::LocalFsFetch;
use aos_hub::indexer::index_and_record;
use aos_hub::server::{router, AppState};
use aos_hub::validation::validate_presence;
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
    let mut request = Request::builder()
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8420");
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
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry("demo", std::slice::from_ref(&fixture.trust_key), true)
        .await
        .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let binding =
        common::create_instance_local_binding(&db, "fixture-origin", surface.to_str().unwrap())
            .await;
    let placement = common::create_ready_placement(
        &db,
        SurfaceTarget::Registry(registry.id),
        binding,
        "fixture-primary",
        "",
    )
    .await;
    common::configure_hub_route(
        &db,
        SurfaceTarget::Registry(registry.id),
        placement.id,
        &registry.owner_scope_key,
        "endpoint:web-fixture",
        "route:web-fixture",
        "/demo",
        "git",
    )
    .await;
    index_and_record(&db, &LocalFsFetch::new(surface), &registry)
        .await
        .unwrap();
    let app = router(Arc::new(
        AppState::new(Arc::clone(&db), "http://127.0.0.1:8420".into()).await,
    ))
    .await;
    (app, db)
}

/// A standard fixture whose `curl.toml` carries a custom homepage.
fn fixture_with_homepage(root: &Path, homepage: &str) -> common::Fixture {
    let fixture = common::Fixture::new(root);

    let registry_toml = fixture.put_blob(
        "[registry]\nname = \"demo\"\ndescription = \"Fixture registry\"\n\n\
         [caches]\nendpoint = \"https://cache.example.com/\"\n",
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

/// The browse pages link `/_assets/style.css` + `/_assets/app.js`; the shared
/// browse router must serve them (so both the native hub and the Worker do, not
/// just the native hub — regression for them 404ing on the deployed Worker).
#[tokio::test]
async fn static_assets_are_served_by_the_shared_router() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    for (uri, ctype) in [
        ("/_assets/style.css", "text/css"),
        ("/_assets/app.js", "text/javascript"),
        ("/_assets/jetbrains-mono-regular.woff2", "font/woff2"),
    ] {
        let (status, headers, body) = get(&app, uri).await;
        assert_eq!(status, StatusCode::OK, "{uri} must be served");
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(ctype),
            "{uri} content-type"
        );
        assert!(!body.is_empty(), "{uri} non-empty");
    }
}

#[tokio::test]
async fn security_headers_on_every_route_class() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    for uri in [
        "/",                                          // instance home
        "/demo/",                                     // registry page
        "/demo/-/packages",                           // /-/ page
        "/demo/HEAD",                                 // machine path
        "/_assets/style.css",                         // stylesheet
        "/_assets/jetbrains-mono-regular.woff2",      // embedded font
        "/aos.hub.v1.RegistryService/ListRegistries", // RPC path
        "/demo/does-not-exist",                       // 404s carry the headers too
    ] {
        let (_, headers, _) = get(&app, uri).await;
        // The default CSP now carries `frame-ancestors 'none'` for
        // anti-clickjacking; `/demo/HEAD` is a non-document machine path, so it
        // keeps the strict default rather than the producer `sandbox` policy.
        assert_eq!(
            headers
                .get("content-security-policy")
                .and_then(|v| v.to_str().ok()),
            Some("default-src 'self'; frame-ancestors 'none'"),
            "CSP missing on {uri}"
        );
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff"),
            "nosniff missing on {uri}"
        );
        // Defense-in-depth framing protection alongside frame-ancestors.
        assert_eq!(
            headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
            Some("DENY"),
            "X-Frame-Options missing on {uri}"
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

    let (status, _, body) = get(&app, "/demo/-/packages/curl?release=1.0.0").await;
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

    // Validation state belongs on the dedicated health page.
    let (_, _, health) = get(&app, "/demo/-/health").await;
    assert!(health.contains("Not yet validated"));

    // The fixture's committed cache (https://cache.example.com) does not
    // resolve, so presence validation records it unreachable.
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    validate_presence(&db, &registry).await.unwrap();

    let (status, _, body) = get(&app, "/demo/-/health").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("https://cache.example.com/"), "{body}");
    assert!(body.contains("unreachable"), "{body}");
    assert!(body.contains("presence"), "{body}");

    // Overview links to Health without duplicating its cache table.
    let (_, _, home) = get(&app, "/demo/").await;
    assert!(!home.contains("unreachable"), "{home}");
    assert!(home.contains("/demo/-/health"), "{home}");
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
    assert!(
        body.contains("release <strong><a href=\"/demo/-/releases/1.0.0\">1.0.0</a></strong>"),
        "{body}"
    );
    assert!(body.contains(" hit\" title=\"bucket 0x0A (10) → 1.0.0\""), "{body}");
    // The anti-rollback floor (recorded at index time) is shown.
    assert!(
        body.contains(
            "<span>Minimum allowed release</span><strong><a href=\"/demo/-/releases/1.0.0\">1.0.0</a></strong>"
        ),
        "{body}"
    );
}

#[tokio::test]
async fn package_search_filters_by_substring() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    // A bare term in the filter expression matches any field (substring).
    let (status, headers, _) = get(&app, "/demo/-/packages?filter=curl").await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    let pinned = headers[header::LOCATION].to_str().unwrap();
    assert!(pinned.contains("release=1.0.0") && pinned.contains("filter=curl"));
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");

    let (status, _, body) = get(&app, "/demo/-/packages?release=1.0.0&filter=curl").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("1 of 1 packages matching"), "{body}");
    assert!(body.contains("/demo/-/packages/curl"), "{body}");

    let (status, _, body) = get(&app, "/demo/-/packages?release=1.0.0&filter=zzz").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("0 of 1 packages matching"), "{body}");
    assert!(!body.contains("/demo/-/packages/curl"), "{body}");

    // A field comparison filters by that attribute; an invalid expression is
    // surfaced as an error rather than applied.
    let (_, _, body) = get(
        &app,
        "/demo/-/packages?release=1.0.0&filter=license+%3D%3D+zzz",
    )
    .await;
    assert!(body.contains("0 of 1 packages matching"), "{body}");
    let (_, _, body) = get(&app, "/demo/-/packages?release=1.0.0&filter=license+%3D%3D").await;
    assert!(body.contains("filter error:"), "{body}");

    // Column sort: the descending closure header links to the ascending state.
    let (_, _, body) = get(&app, "/demo/-/packages?release=1.0.0&sort=closure&dir=desc").await;
    assert!(body.contains("sort=closure&amp;dir=asc"), "{body}");

    // The instance home searches registries the same way.
    let (_, _, body) = get(&app, "/?q=fixture").await;
    assert!(body.contains("1 of 1 registries match"), "{body}");
    let (_, _, body) = get(&app, "/?q=zzz").await;
    assert!(body.contains("0 of 1 registries match"), "{body}");
}

#[tokio::test]
async fn anonymous_browse_is_rate_limited_on_flat_and_nested_paths() {
    use aos_hub::ratelimit::BROWSE_SEARCH;

    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    // One app, two registries indexed from the same surface: an instance-scoped
    // flat slug and an org-scoped registry that reaches the browser through
    // the nested resolver rather than the flat route.
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry("demo", std::slice::from_ref(&fixture.trust_key), true)
        .await
        .unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_managed_registry(
        org,
        "",
        "infra",
        "public",
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap();
    for slug in ["demo", "acme/infra"] {
        let registry = db.registry_by_slug(slug).await.unwrap().unwrap();
        index_and_record(&db, &LocalFsFetch::new(&surface), &registry)
            .await
            .unwrap();
    }
    let app = router(Arc::new(
        AppState::new(Arc::clone(&db), "http://127.0.0.1:8420".into()).await,
    ))
    .await;

    // Tests share one process-wide-free limiter per AppState; with no
    // ConnectInfo every request keys on the same (empty) IP, so the per-IP
    // BrowseSearch budget is shared across the routes below. Exhaust it on the
    // flat packages route, then assert every browse entrypoint is 429'd.
    for _ in 0..BROWSE_SEARCH {
        let (status, _, _) = get(&app, "/demo/-/packages?release=1.0.0").await;
        assert_eq!(status, StatusCode::OK);
    }

    // Flat packages route: over budget now.
    let (status, headers, _) = get(&app, "/demo/-/packages?release=1.0.0").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.contains_key(header::RETRY_AFTER), "Retry-After set");

    // Nested-canonical packages route (org/registry/-/packages) is throttled
    // through the same per-IP budget.
    let (status, _, _) = get(&app, "/acme/infra/-/packages").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // The instance home (anonymous registry scan) shares the budget too.
    let (status, _, _) = get(&app, "/").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn registry_machine_paths_require_a_typed_publication() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    // Indexing is intentionally not publication. Neither a Git directory nor
    // a mutable channel pointer becomes servable merely because bytes happen
    // to exist on a placement; the typed publication transaction must record
    // exact object presence and atomically advance the current generation.
    let (status, _, _) = get(&app, "/demo/channels/stable/").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = get(&app, "/demo/channels/stable/00").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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
    assert!(body.contains("/demo/-/releases/1.0.0"), "{body}");
    assert!(body.contains("ago"), "tagged column carries a relative age");
    let (status, _, detail) = get(&app, "/demo/-/releases/1.0.0").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        detail.contains("Git pack") && detail.contains("Available"),
        "{detail}"
    );
    assert!(detail.contains("unix 1770000000"), "{detail}");
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
        body.contains("apm registry add http://127.0.0.1:8420/demo/"),
        "{body}"
    );
    assert!(
        body.contains("aos.apm.registries.&quot;demo&quot;"),
        "{body}"
    );
    assert!(body.contains("trustKeys"), "{body}");
    // The canonical anonymous delivery facade is also the advertised
    // binary-cache endpoint; the cache remains an implementation behind it.
    assert!(
        body.contains("substituters = http://127.0.0.1:8420/demo"),
        "{body}"
    );
    assert!(body.contains("trusted-public-keys ="), "{body}");
    // The pinned anchor appears in full and as a SHA256: fingerprint.
    assert!(body.contains(&fixture.trust_key), "{body}");
    assert!(body.contains("SHA256:"), "{body}");
    // Index evidence remains in the footer; rollouts describe the live channel.
    assert!(body.contains("indexed at unix "), "{body}");
    assert!(body.contains("256/256 buckets"), "{body}");

    let (status, _, package) = get(&app, "/demo/-/packages/curl?release=1.0.0").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        package.contains("apm registry add http://127.0.0.1:8420/demo/"),
        "{package}"
    );
    assert!(
        package.contains("--tag 1.0.0")
            && package.contains("apm install curl --registry demo-1.0.0"),
        "{package}"
    );
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

    // A loose index.html on a placement does not replace the Hub-owned Web
    // surface. Producer files are never an implicit fallback response.
    std::fs::write(surface.join("index.html"), "<!DOCTYPE html>static page\n").unwrap();
    let (status, _, _) = get_with_accept(&app, "/demo/", Some("application/json")).await;
    assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
}

/// Generated producer files cannot shadow the Hub-owned registry Web surface.
#[tokio::test]
async fn generated_web_surface_cannot_shadow_hub_browse() {
    use aos_package::registry::webgen::{generate_web_surface, WebConfig};

    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    // Build a committed registry tree on disk and generate the web surface
    // straight into the served surface root (origin-only files alongside the
    // git/cache surface), exactly as `apr web generate --output <surface>`
    // would for a file:// binding.
    let committed = dir.path().join("committed");
    std::fs::create_dir_all(committed.join("packages").join("c")).unwrap();
    std::fs::write(
        committed.join("registry.toml"),
        "[registry]\nname = \"demo\"\ndescription = \"Fixture registry\"\n",
    )
    .unwrap();
    std::fs::write(
        committed.join("packages").join("c").join("curl.toml"),
        "[package]\nname = \"curl\"\ndescription = \"URL transfers\"\nlicense = \"MIT\"\n\
         maintainer = \"aos\"\nhomepage = \"https://curl.se\"\n\n[[versions]]\nversion = \"8.5.0\"\n\n\
         [versions.platforms.x86_64-linux]\nstore_path = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0\"\n\
         nar_hash = \"sha256:aa\"\nnar_size = 10\nclosure_size = 20\n\
         source_drv = \"\"\nsource_nar_hash = \"\"\nreferences = []\n",
    )
    .unwrap();
    generate_web_surface(&committed, &surface, WebConfig::default()).unwrap();

    for path in [
        "/demo/index.html",
        "/demo/web/index.json",
        "/demo/browse/curl.html",
    ] {
        let (status, _, _) = get(&app, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "loose producer path {path}");
    }

    // Indexed metadata is still presented by the canonical Hub renderer.
    let (status, headers, body) = get(&app, "/demo/-/packages/curl?release=1.0.0").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    assert!(body.contains("curl"), "{body}");
    assert!(body.contains("x86_64-linux"), "{body}");
}

/// Loose producer JS and colocated cache objects are not registry capabilities.
#[tokio::test]
async fn registry_route_rejects_unpublished_web_and_cache_paths() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    // The fixture wrote a signed narinfo + nix-cache surface; add a producer
    // JS file under the producer-writable `web/` prefix (the exact bytes a
    // `publish`-scoped uploader could PUT through the facade).
    std::fs::create_dir_all(surface.join("web")).unwrap();
    std::fs::write(
        surface.join("web").join("app.js"),
        b"fetch('/account').then(r=>r.text())",
    )
    .unwrap();
    let (app, _db) = serve_fixture(&surface, &fixture).await;

    let (status, _, _) = get(&app, "/demo/web/app.js").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A registry no longer doubles as its associated binary cache. Nix clients
    // use an explicit cache route. Published byte-faithful delivery and range
    // behavior are exercised by the signed-image end-to-end suite.
    let (status, _, _) = get(&app, "/demo/h7j3k8l2m9n4.narinfo").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The no-JS managed-cache home and protocol surface use the final typed route.
#[tokio::test]
async fn cache_browse_and_uninventoried_nar_fail_closed_over_plain_http() {
    let root = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    let binding =
        common::create_local_binding(&db, org, "primary", root.path().to_str().unwrap()).await;
    let cache = db
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
    let placement = common::create_ready_placement(
        &db,
        SurfaceTarget::BinaryCache(cache),
        binding,
        "primary",
        "nix_cache",
    )
    .await;
    let owner_scope = db
        .binary_cache_by_id(cache)
        .await
        .unwrap()
        .unwrap()
        .owner_scope_key;
    common::configure_hub_route(
        &db,
        SurfaceTarget::BinaryCache(cache),
        placement.id,
        &owner_scope,
        "endpoint:cache-web-fixture",
        "route:cache-web-fixture",
        "/acme-cache",
        "nix_cache",
    )
    .await;
    // A loose NAR is deliberately not inventory evidence.
    let nar_dir = root.path().join("cache/nar");
    std::fs::create_dir_all(&nar_dir).unwrap();
    std::fs::write(nar_dir.join("test.nar"), b"unpublished nar bytes").unwrap();

    let app = router(Arc::new(
        AppState::new(Arc::clone(&db), "http://127.0.0.1:8420".into()).await,
    ))
    .await;

    // Home page: a no-JS HTML summary naming the cache.
    let (status, _, home) = get(&app, "/acme-cache/").await;
    assert_eq!(status, StatusCode::OK, "cache home: {home}");
    assert!(
        home.contains("<!DOCTYPE html>") && home.contains("Acme Cache"),
        "{home}"
    );

    // nix-cache-info is generated from the cache config.
    let (status, _, info) = get(&app, "/acme-cache/nix-cache-info").await;
    assert_eq!(status, StatusCode::OK);
    assert!(info.contains("StoreDir: /nix/store"), "{info}");

    // Immutable cache objects require exact inventory presence. A file copied
    // behind the controller's back is not served, with or without a query or
    // Range header.
    let (status, _, _) = get(&app, "/acme-cache/nar/test.nar?explore").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _headers, _) = get(&app, "/acme-cache/nar/test.nar").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme-cache/nar/test.nar")
                .header(header::HOST, "127.0.0.1:8420")
                .header(header::RANGE, "bytes=0-3")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// The unified streaming cache-read path gates a non-public cache: an anonymous
/// machine read of a `private` cache's narinfo is refused (never `200`), the same
/// `require_cache_read` gate the Worker applies — visibility is enforced before
/// any byte streams. (A public cache serves anonymously, asserted above.)
#[tokio::test]
async fn private_cache_machine_read_is_gated_on_the_streaming_path() {
    let root = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    let binding =
        common::create_local_binding(&db, org, "primary", root.path().to_str().unwrap()).await;
    let cache = db
        .create_binary_cache(Some(org), "priv-cache", "Priv", "private", 40, "zstd", true)
        .await
        .unwrap();
    let placement = common::create_ready_placement(
        &db,
        SurfaceTarget::BinaryCache(cache),
        binding,
        "primary",
        "pc",
    )
    .await;
    let owner_scope = db
        .binary_cache_by_id(cache)
        .await
        .unwrap()
        .unwrap()
        .owner_scope_key;
    common::configure_hub_route(
        &db,
        SurfaceTarget::BinaryCache(cache),
        placement.id,
        &owner_scope,
        "endpoint:private-cache-web-fixture",
        "route:private-cache-web-fixture",
        "/priv-cache",
        "nix_cache",
    )
    .await;
    // Put the narinfo on the surface too, so a missing gate would actually serve.
    std::fs::create_dir_all(root.path().join("pc")).unwrap();
    std::fs::write(
        root.path().join("pc/aaaa.narinfo"),
        b"StorePath: /nix/store/aaaa-x-1.0\n",
    )
    .unwrap();

    let app = router(Arc::new(
        AppState::new(Arc::clone(&db), "http://127.0.0.1:8420".into()).await,
    ))
    .await;

    // Anonymous machine read of the private cache's narinfo must NOT serve bytes.
    let (status, _, _) = get(&app, "/priv-cache/aaaa.narinfo").await;
    assert_ne!(
        status,
        StatusCode::OK,
        "private cache must gate anonymous reads"
    );
}
