//! Web-surface integration tests: security headers, the phase-1 browse
//! pages (search, calculator, health, releases), content negotiation,
//! and the autoindex fallback — all over the real router against a
//! signed fixture surface.

mod common;

use std::path::Path;
use std::sync::Arc;

use aos_hub::db::Database;
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
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry(
        "demo",
        surface.to_str().unwrap(),
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
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
        // Legacy belt-and-braces framing protection alongside frame-ancestors.
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
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
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

    // A bare term in the filter expression matches any field (substring).
    let (status, _, body) = get(&app, "/demo/-/packages?filter=curl").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("1 of 1 packages matching"), "{body}");
    assert!(body.contains("/demo/-/packages/curl"), "{body}");

    let (status, _, body) = get(&app, "/demo/-/packages?filter=zzz").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("0 of 1 packages matching"), "{body}");
    assert!(!body.contains("/demo/-/packages/curl"), "{body}");

    // A field comparison filters by that attribute; an invalid expression is
    // surfaced as an error rather than applied.
    let (_, _, body) = get(&app, "/demo/-/packages?filter=license+%3D%3D+zzz").await;
    assert!(body.contains("0 of 1 packages matching"), "{body}");
    let (_, _, body) = get(&app, "/demo/-/packages?filter=license+%3D%3D").await;
    assert!(body.contains("filter error:"), "{body}");

    // Column sort: the descending closure header links to the ascending state.
    let (_, _, body) = get(&app, "/demo/-/packages?sort=closure&dir=desc").await;
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

    // One app, two registries indexed from the same surface: a flat slug and a
    // nested (org-scoped) slug that reaches the browser through the nested
    // resolver rather than the flat route.
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    for slug in ["demo", "acme/infra"] {
        db.register_registry(
            slug,
            surface.to_str().unwrap(),
            std::slice::from_ref(&fixture.trust_key),
            true,
        )
        .await
        .unwrap();
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
        let (status, _, _) = get(&app, "/demo/-/packages").await;
        assert_eq!(status, StatusCode::OK);
    }

    // Flat packages route: over budget now.
    let (status, headers, _) = get(&app, "/demo/-/packages").await;
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
    // substituters point at the advertised binary cache, not the registry URL.
    assert!(
        body.contains("substituters = https://cache.example.com"),
        "{body}"
    );
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

/// A web surface generated by `apr web generate` (the no-JS tier) serves
/// straight through the facade as machine paths: the registry's own bucket
/// answers `index.html`, `web/index.json`, and `browse/<name>.html` with no
/// hub in the serving path. This is the producer-emitted floor the hub
/// serves byte-for-byte.
#[tokio::test]
async fn generated_web_surface_serves_through_facade() {
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

    // index.html — a producer-controlled document, served inert: the bytes
    // are preserved (content type, body), but a `sandbox` CSP plus
    // `Content-Disposition: attachment` keep the same-origin hub from ever
    // running producer script in the authenticated origin (sec H3/M5).
    let (status, headers, body) = get(&app, "/demo/index.html").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    assert_eq!(
        headers
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok()),
        Some("sandbox"),
    );
    assert_eq!(
        headers
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok()),
        Some("attachment"),
    );
    assert!(body.contains("curl"), "{body}");
    assert!(body.contains("browse/curl.html"), "{body}");

    // web/index.json — a non-document machine path: served verbatim with its
    // JSON content type, its mutable cache header, and no inert treatment (the
    // global `default-src 'self'` applies; no per-response sandbox/disposition).
    let (status, headers, body) = get(&app, "/demo/web/index.json").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("application/json"));
    // The global layer applies the strict default CSP; the facade adds no
    // per-response sandbox, and the bytes are not forced to a download.
    assert_eq!(
        headers
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok()),
        Some("default-src 'self'; frame-ancestors 'none'"),
        "data-plane JSON must not be sandboxed",
    );
    assert!(
        headers.get(header::CONTENT_DISPOSITION).is_none(),
        "data-plane JSON must not be forced to a download",
    );
    let snapshot: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(snapshot["packages"][0]["name"], "curl");

    // browse/curl.html — a producer document, likewise inert.
    let (status, headers, body) = get(&app, "/demo/browse/curl.html").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok()),
        Some("sandbox"),
    );
    assert_eq!(
        headers
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok()),
        Some("attachment"),
    );
    assert!(body.contains("x86_64-linux"), "{body}");
    assert!(body.contains("/h7j3k8l2m9n4.narinfo"), "{body}");

    // A non-HTML Accept on the registry root serves the generated index.html.
    let (status, _, body) = get_with_accept(&app, "/demo/", Some("application/json")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("curl"), "{body}");
}

/// Producer-uploaded JS is served inert, but the immutable data plane the
/// same surface carries (narinfos, NARs, objects) is untouched — the inert
/// treatment keys on document kind (provenance), not on a hub allowlist
/// (sec H3/M5 regression guard).
#[tokio::test]
async fn producer_js_is_inert_but_data_plane_is_verbatim() {
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

    // Producer JS: a `sandbox` CSP (no script execution, no same-origin
    // context) and forced to a download. No script-permitting CSP anywhere.
    let (status, headers, _) = get(&app, "/demo/web/app.js").await;
    assert_eq!(status, StatusCode::OK);
    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(csp, "sandbox", "producer JS must be sandboxed: {csp}");
    assert!(!csp.contains("script-src"), "{csp}");
    assert!(!csp.contains("'self'"), "{csp}");
    assert_eq!(
        headers
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok()),
        Some("attachment"),
    );

    // The narinfo data plane: served verbatim with its wire content type and
    // immutable/mutable cache header, never sandboxed or forced to a download.
    let (status, headers, body) = get(&app, "/demo/h7j3k8l2m9n4.narinfo").await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/x-nix-narinfo"));
    assert!(
        headers.get(header::CONTENT_DISPOSITION).is_none(),
        "narinfo must not be forced to a download",
    );
    // The global default CSP applies; the facade never sandboxes data bytes.
    assert_eq!(
        headers
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok()),
        Some("default-src 'self'; frame-ancestors 'none'"),
        "narinfo must not be sandboxed",
    );
    assert!(body.contains("StorePath:"), "verbatim narinfo: {body}");
}

/// Append a NAR length-prefixed, 8-byte-padded string.
fn nar_put(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s);
    let pad = (8 - (s.len() % 8)) % 8;
    out.extend(std::iter::repeat(0u8).take(pad));
}

/// A minimal uncompressed NAR: a directory holding one regular file `hi`.
fn sample_nar() -> Vec<u8> {
    let mut n = Vec::new();
    nar_put(&mut n, b"nix-archive-1");
    nar_put(&mut n, b"(");
    nar_put(&mut n, b"type");
    nar_put(&mut n, b"directory");
    nar_put(&mut n, b"entry");
    nar_put(&mut n, b"(");
    nar_put(&mut n, b"name");
    nar_put(&mut n, b"hi");
    nar_put(&mut n, b"node");
    nar_put(&mut n, b"(");
    nar_put(&mut n, b"type");
    nar_put(&mut n, b"regular");
    nar_put(&mut n, b"contents");
    nar_put(&mut n, b"hello\n");
    nar_put(&mut n, b")");
    nar_put(&mut n, b")");
    nar_put(&mut n, b")");
    n
}

/// The no-JS managed-cache browse surface — home, object list, object page,
/// closure page, `nix-cache-info`, and the NAR explorer — all over plain HTTP
/// against the real router, with no JavaScript required (RFC-0004 "11-caches").
#[tokio::test]
async fn cache_browse_and_nar_explorer_over_plain_http() {
    let root = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", root.path().to_str().unwrap())
        .await
        .unwrap();
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
    db.upsert_cache_object(&aos_hub_core::db::CacheObject {
        cache_id: cache,
        store_hash: "h7j3k8l2m9n4".into(),
        store_name: "h7j3k8l2m9n4-hello-1.0".into(),
        nar_url: "nar/test.nar".into(),
        nar_hash: "sha256:aa".into(),
        nar_size: 64,
        file_hash: "aa".into(),
        file_size: 64,
        compression: "none".into(),
        deriver: None,
        refs: vec![],
        sig: None,
        ca: None,
        uploaded_at: 0,
        last_accessed_at: None,
    })
    .await
    .unwrap();
    // Write the (uncompressed) NAR onto the cache surface for the explorer.
    let nar_dir = root.path().join("cache/nar");
    std::fs::create_dir_all(&nar_dir).unwrap();
    std::fs::write(nar_dir.join("test.nar"), sample_nar()).unwrap();

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

    // Object list: the indexed object's store name shows up.
    let (status, _, objects) = get(&app, "/acme-cache/-/objects").await;
    assert_eq!(status, StatusCode::OK);
    assert!(objects.contains("h7j3k8l2m9n4-hello-1.0"), "{objects}");

    // Object page: narinfo metadata + an explore link.
    let (status, _, object) = get(&app, "/acme-cache/-/objects/h7j3k8l2m9n4").await;
    assert_eq!(status, StatusCode::OK);
    assert!(object.contains("h7j3k8l2m9n4-hello-1.0"), "{object}");

    // Closure page renders (single-node closure for a refs-less object).
    let (status, _, closure) = get(&app, "/acme-cache/-/closure/h7j3k8l2m9n4").await;
    assert_eq!(status, StatusCode::OK, "closure: {closure}");

    // nix-cache-info is generated from the cache config.
    let (status, _, info) = get(&app, "/acme-cache/nix-cache-info").await;
    assert_eq!(status, StatusCode::OK);
    assert!(info.contains("StoreDir: /nix/store"), "{info}");

    // NAR explorer: `?explore` lists the archive's file tree instead of the
    // raw download — the `hi` entry inside the sample NAR appears.
    let (status, _, explore) = get(&app, "/acme-cache/nar/test.nar?explore").await;
    assert_eq!(status, StatusCode::OK, "explore: {explore}");
    assert!(
        explore.contains("hi"),
        "NAR explorer lists entries: {explore}"
    );

    // Without `?explore`, the same path downloads the raw NAR bytes.
    let (status, _headers, _) = get(&app, "/acme-cache/nar/test.nar").await;
    assert_eq!(status, StatusCode::OK);

    // A `Range:` request is answered `206 Partial Content` with a `Content-Range`
    // and exactly the requested slice — the shared streaming `cache_serve` path
    // (the same one the Worker uses) honors ranges.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme-cache/nar/test.nar")
                .header(header::RANGE, "bytes=0-3")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let cr = resp
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(cr.starts_with("bytes 0-3/"), "content-range: {cr}");
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(
        body.len(),
        4,
        "ranged body is exactly the 4 requested bytes"
    );
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
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", root.path().to_str().unwrap())
        .await
        .unwrap();
    let cache = db
        .create_cache(
            Some(org),
            "priv-cache",
            "Priv",
            Some(binding),
            "pc",
            None,
            "private",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
    db.upsert_cache_object(&aos_hub_core::db::CacheObject {
        cache_id: cache,
        store_hash: "aaaa".into(),
        store_name: "aaaa-x-1.0".into(),
        nar_url: "nar/aa.nar".into(),
        nar_hash: "sha256:aa".into(),
        nar_size: 1,
        file_hash: "aa".into(),
        file_size: 1,
        compression: "none".into(),
        deriver: None,
        refs: vec![],
        sig: None,
        ca: None,
        uploaded_at: 0,
        last_accessed_at: None,
    })
    .await
    .unwrap();
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

/// Issue a GET carrying a `Host` header (domain-routed frontend dispatch).
async fn get_with_host(
    app: &axum::Router,
    host: &str,
    uri: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::HOST, host)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

/// A request arriving on a serving frontend's domain is dispatched to the bound
/// cache by `Host` (no slug in the path), and the `serves_cache` subset gate
/// rejects a frontend that does not advertise the cache surface.
#[tokio::test]
async fn frontend_domain_routes_to_bound_cache_and_gates_on_serves_cache() {
    let root = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", root.path().to_str().unwrap())
        .await
        .unwrap();
    // A public cache served by its own domain (prefix `pc`).
    let cache = db
        .create_cache(
            Some(org),
            "ext-cache",
            "Ext",
            Some(binding),
            "pc",
            None,
            "public",
            40,
            "none",
            true,
        )
        .await
        .unwrap();
    std::fs::create_dir_all(root.path().join("pc")).unwrap();
    std::fs::write(
        root.path().join("pc/aaaa.narinfo"),
        b"StorePath: /nix/store/aaaa-x-1.0\n",
    )
    .unwrap();
    // A proxied frontend that serves the cache surface on `cache.example.test`.
    db.create_cache_frontend(cache, "cache.example.test", "/", "proxied", true, 100, true)
        .await
        .unwrap();
    // A second proxied frontend on `nocache.example.test` that does NOT serve
    // the cache surface (serves_cache = false).
    db.create_cache_frontend(
        cache,
        "nocache.example.test",
        "/",
        "proxied",
        false,
        100,
        true,
    )
    .await
    .unwrap();

    let app = router(Arc::new(
        AppState::new(Arc::clone(&db), "http://hub.example.test:8420".into()).await,
    ))
    .await;

    // Host-routed: the narinfo is served off the frontend domain with no slug in
    // the path (rewritten internally to `/ext-cache/aaaa.narinfo`).
    let (status, _, body) = get_with_host(&app, "cache.example.test", "/aaaa.narinfo").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "frontend domain should serve the cache"
    );
    assert!(
        body.contains("StorePath: /nix/store/aaaa-x-1.0"),
        "served the bound cache's narinfo: {body}"
    );

    // The generated nix-cache-info is served off the domain too.
    let (status, _, body) = get_with_host(&app, "cache.example.test", "/nix-cache-info").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("StoreDir: /nix/store"), "{body}");

    // serves_cache = false: the cache surface is gated (404) on that domain.
    let (status, _, _) = get_with_host(&app, "nocache.example.test", "/aaaa.narinfo").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a frontend that does not serve the cache must 404 its surface"
    );

    // An unknown host is not a frontend: it falls through to normal slug routing
    // and is never served the bound cache's bytes (here the single-segment path
    // hits the `/{slug}` -> `/{slug}/` canonical redirect, i.e. not a 200 serve).
    let (status, _, body) = get_with_host(&app, "stranger.example.test", "/aaaa.narinfo").await;
    assert_ne!(
        status,
        StatusCode::OK,
        "unknown host must not serve the cache"
    );
    assert!(
        !body.contains("StorePath: /nix/store/aaaa-x-1.0"),
        "unknown host must not leak the cache's narinfo"
    );

    // The domain match is case-insensitive: a frontend created with mixed case
    // is reached by a lowercase request `Host` (domains are stored lowercased).
    db.create_cache_frontend(cache, "Mixed.Example.Test", "/", "proxied", true, 100, true)
        .await
        .unwrap();
    let (status, _, _) = get_with_host(&app, "mixed.example.test", "/aaaa.narinfo").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "domain match must be case-insensitive"
    );

    // base_path matches on a segment boundary: a frontend at `/v1` does not
    // capture `/v1x/...`.
    db.create_cache_frontend(
        cache,
        "based.example.test",
        "/v1",
        "proxied",
        true,
        100,
        true,
    )
    .await
    .unwrap();
    let (status, _, body) = get_with_host(&app, "based.example.test", "/v1/aaaa.narinfo").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "base_path /v1 should serve /v1/<path>"
    );
    assert!(body.contains("StorePath"), "{body}");
    let (status, _, _) = get_with_host(&app, "based.example.test", "/v1x/aaaa.narinfo").await;
    assert_ne!(
        status,
        StatusCode::OK,
        "base_path /v1 must not capture /v1x/..."
    );
}

/// The `serves_*` subset gate classifies on the *decoded* path, so a
/// percent-encoded token (e.g. `%48EAD` for `HEAD`) cannot dodge the gate and
/// reach the machine surface a downstream extractor would decode and serve.
#[tokio::test]
async fn frontend_subset_gate_resists_percent_encoded_surface_paths() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    let (app, db) = serve_fixture(&surface, &fixture).await;

    // A web-only frontend over the registry: it serves browse pages but NOT the
    // git machine surface (serves_git = false, serves_web = true).
    let reg = db.registry_by_slug("demo").await.unwrap().unwrap();
    db.create_frontend(
        reg.id,
        "reg.example.test",
        "/",
        "proxied",
        false, // serves_git
        false, // serves_cache
        true,  // serves_web
        100,
        true,
    )
    .await
    .unwrap();

    // Browse home is served (serves_web).
    let (status, _, _) = get_with_host(&app, "reg.example.test", "/").await;
    assert_eq!(status, StatusCode::OK, "web-only frontend serves browse");

    // The git surface is gated: `/HEAD` is a machine path → serves_git=false → 404.
    let (status, _, _) = get_with_host(&app, "reg.example.test", "/HEAD").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "git surface must be gated");

    // Regression: the same path percent-encoded (`%48EAD`) must STILL be gated —
    // it must not be misclassified as a web page and bypass `serves_git`.
    let (status, _, body) = get_with_host(&app, "reg.example.test", "/%48EAD").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "encoded machine path must not bypass the serves_git gate"
    );
    assert!(
        !body.contains("ref:"),
        "encoded path must not leak the git HEAD pointer: {body}"
    );
}
