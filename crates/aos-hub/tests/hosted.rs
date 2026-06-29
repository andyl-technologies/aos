//! Integration coverage for hosted signing keys (RFC-0004 phase-4a).
//!
//! Hosted keys let the hub sign channel advances and tag re-signs directly
//! from the web. These tests assert the critical correctness loop: the hub's
//! own signed partitions are accepted by the *same* verification path the
//! indexer uses (`surface::tag::verify_signed_tag`), so a web-driven advance
//! is indistinguishable to consumers from a maintainer's client-side push.
//!
//! Coverage: enrollment (a valid trusted-key line + audit row), the
//! sign→verify→index loop over a real binding-rooted surface where the hosted
//! key is a registry trust anchor, anti-rollback floor refusal, and the
//! console authz/mode matrix (BYO-key shows the prepared op; hosted-key shows
//! the direct form; an advance without `ChannelAdvance` is 403).

mod common;

use std::path::Path;
use std::sync::Arc;

use aos_hub::auth::extract::{mint_csrf_token, AuthState};
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::auth::oidc::dev_sealer;
use aos_hub::auth::session::COOKIE_NAME;
use aos_hub::coreports::{HubReindexer, HubSurfaceWriteProvider};
use aos_hub::db::{Database, RegistryRecord};
use aos_hub::fetch::LocalFsFetch;
use aos_hub::indexer::index_and_record;
use aos_hub::server::{router, AppState};
use aos_hub::signing;
use aos_hub::surface::object::{hash_object, ObjectKind};
use aos_hub::surface::tag::verify_signed_tag;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

const TEST_JWT_SECRET: &[u8] = b"hosted--test-secret-32-byte-key!!";

/// Build a dev-mode [`AppState`] over `db` with deterministic JWT keys.
async fn app_state(db: Arc<Database>) -> Arc<AppState> {
    let auth = Arc::new(AuthState {
        db: Arc::clone(&db),
        jwt_keys: JwtKeys::from_secret(TEST_JWT_SECRET),
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
        sealer: dev_sealer(),
        http: aos_hub::fetch::hardened_client().await,
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
        dev: true,
    })
}

/// A captured HTTP response.
struct Resp {
    status: StatusCode,
    body: String,
}

/// Issue a request with an optional cookie and form body.
async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    form: Option<&str>,
) -> Resp {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    let body = match form {
        Some(form) => {
            req = req.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(form.to_string())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    Resp {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// Sign in `email` via a minted magic link; returns the session cookie header.
async fn login(app: &axum::Router, db: &Database, email: &str) -> String {
    let secret = db.create_magic_link(email).await.unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/auth/magic?token={secret}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let set = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("magic consume sets a cookie")
        .to_string();
    let value = set
        .strip_prefix(&format!("{COOKIE_NAME}="))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    format!("{COOKIE_NAME}={value}")
}

/// The CSRF token bound to a session cookie header.
fn csrf_for(cookie: &str) -> String {
    mint_csrf_token(cookie.strip_prefix(&format!("{COOKIE_NAME}=")).unwrap())
}

/// Build a two-release fixture surface on disk (releases `1.0.0` and `1.1.0`),
/// with the `stable` channel fully rolled out to `1.0.0`.
///
/// Returns the fixture (carrying the maintainer key and trust line).
fn two_release_surface(surface: &Path) -> common::Fixture {
    let fixture = common::standard_registry_versioned(surface, "1.0.0");

    // A second release `1.1.0`: a fresh signed commit over a trivial tree, its
    // signed release tag object, and updated info/refs advertising both tags
    // (the indexer needs the tag advertised to record it as a release).
    let tree = fixture.put_tree(&[("100644", "marker", fixture.put_blob("v1.1.0\n"))]);
    let commit_110 = fixture.put_signed_commit(tree, "release 1.1.0");
    let tag_110 = fixture.put_release_tag("1.1.0", commit_110);

    // Recover the 1.0.0 release commit/tag oids the standard fixture wrote so
    // refs can re-advertise both. The standard builder commits the root tree
    // and tags it as 1.0.0; reconstruct those oids the same way it did.
    let registry_toml = fixture.put_blob(
        "[registry]\nname = \"demo\"\ndescription = \"Fixture registry\"\n\n\
         [caches]\nendpoint = \"https://cache.example.com/\"\n",
    );
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
    let commit_100 = fixture.put_signed_commit(root_tree, "release 1.0.0");
    // The 1.0.0 tag object content is deterministic from the fixture's signed
    // payload; reconstruct its oid by re-signing the same payload.
    let tag_100_payload = fixture.signed_tag_payload("1.0.0", commit_100, "commit");
    let tag_100 = hash_object(ObjectKind::Tag, &tag_100_payload);

    fixture.put_refs(
        "stable",
        &[("stable", commit_100)],
        &[
            ("1.0.0", tag_100, commit_100),
            ("1.1.0", tag_110, commit_110),
        ],
    );
    fixture
}

/// Seed org "acme", a binding over the surface's parent, a hosted key whose
/// public line is pinned as a registry trust anchor, and a managed registry at
/// `acme/infra/prod/cdn` indexed from the surface with the hosted key attached.
async fn serve_hosted(
    surface: &Path,
    fixture: &common::Fixture,
) -> (Arc<Database>, RegistryRecord) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    let parent = surface.parent().unwrap().to_str().unwrap();
    let dir_name = surface.file_name().unwrap().to_str().unwrap();
    let binding = db
        .create_storage_binding(org, "primary", "local_fs", parent)
        .await
        .unwrap();

    // Enroll the hosted key and pin its public line: the hub's re-signed
    // partitions must verify against a registry trust anchor.
    let hosted_public = db
        .create_hosted_key(dev_sealer().as_ref(), org, "acme-release")
        .await
        .unwrap();
    let trust = vec![fixture.trust_key.clone(), hosted_public];

    db.create_managed_registry(
        org,
        "infra/prod",
        "cdn",
        "public",
        Some(binding),
        dir_name,
        &trust,
        true,
    )
    .await
    .unwrap();
    let registry = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();
    let key = db
        .hosted_key_by_name(org, "acme-release")
        .await
        .unwrap()
        .unwrap();
    db.set_registry_hosted_key(registry.id, Some(key.id))
        .await
        .unwrap();

    index_and_record(&db, &LocalFsFetch::new(surface), &registry)
        .await
        .unwrap();
    // Reload to pick up hosted_key_id.
    let registry = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();
    (db, registry)
}

#[tokio::test]
async fn enrollment_returns_a_valid_trusted_key_line_and_audits() {
    let db = Database::open_in_memory().await.unwrap();
    let org = db.create_org("acme", "Acme").await.unwrap();
    let line = db
        .create_hosted_key(dev_sealer().as_ref(), org, "acme-release")
        .await
        .unwrap();

    // A valid registry trusted-key line: name:Ed25519:<ssh-blob-base64>.
    assert!(line.starts_with("acme-release:Ed25519:"));
    let b64 = line.rsplit(':').next().unwrap();
    assert!(
        b64.starts_with("AAAAC3NzaC1lZDI1NTE5"),
        "ssh-ed25519 blob prefix"
    );

    // The key loads back to a signing key whose public line matches.
    let key = db
        .hosted_key_by_name(org, "acme-release")
        .await
        .unwrap()
        .unwrap();
    let (key_id, signing, public) = db
        .load_hosted_signing_key(dev_sealer().as_ref(), key.id)
        .await
        .unwrap();
    assert_eq!(key_id, "acme-release");
    assert_eq!(public, line);
    // The unsealed key's public line round-trips to the stored anchor.
    let derived =
        aos_hub::surface::sshsig::trusted_key_line("acme-release", &signing.verifying_key());
    assert_eq!(derived, line);

    // A duplicate key id in the same org is rejected.
    assert!(db
        .create_hosted_key(dev_sealer().as_ref(), org, "acme-release")
        .await
        .is_err());
}

#[tokio::test]
async fn hosted_advance_signs_writes_and_reindexes_verifiably() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = two_release_surface(&surface);
    let (db, registry) = serve_hosted(&surface, &fixture).await;

    // Both releases indexed; channel `stable` starts fully at 1.0.0.
    let releases = db.list_releases(registry.id).await.unwrap();
    assert!(releases.iter().any(|r| r.semver == "1.1.0"));
    let before = db.list_channels(registry.id).await.unwrap();
    let stable = before.iter().find(|c| c.name == "stable").unwrap();
    assert_eq!(stable.frontier.as_deref(), Some("1.0.0"));
    assert_eq!(
        stable
            .partitions
            .iter()
            .flatten()
            .filter(|s| *s == "1.0.0")
            .count(),
        256
    );

    // Advance 10 partitions of `stable` to 1.1.0, signed by the hosted key.
    let surface_write = HubSurfaceWriteProvider::new(Arc::clone(&db));
    let reindexer = HubReindexer::new(Arc::clone(&db));
    let outcome = signing::advance_channel(
        &db,
        dev_sealer().as_ref(),
        &surface_write,
        &reindexer,
        &registry,
        "stable",
        "1.1.0",
        10,
        1_770_100_000,
    )
    .await
    .unwrap();
    assert_eq!(outcome.moved, 10);
    assert_eq!(outcome.at_target, 10);

    // The index reflects the advance: 10 buckets now point at 1.1.0, the
    // frontier is 1.1.0, and the rest still at 1.0.0.
    let after = db.list_channels(registry.id).await.unwrap();
    let stable = after.iter().find(|c| c.name == "stable").unwrap();
    assert_eq!(stable.frontier.as_deref(), Some("1.1.0"));
    let at_110 = stable
        .partitions
        .iter()
        .flatten()
        .filter(|s| *s == "1.1.0")
        .count();
    assert_eq!(at_110, 10, "10 partitions advanced");

    // Critical loop: the hub-signed partitions on disk verify against the
    // registry's trust anchors (the hosted key included) under the channel
    // name binding — the same check the indexer runs.
    let trust = registry.trust_keys.clone();
    let mut verified_hub_signed = 0;
    for bucket in 0u16..=255 {
        let path = surface
            .join("channels/stable")
            .join(format!("{bucket:02x}"));
        let payload = std::fs::read(&path).unwrap();
        let signed = verify_signed_tag(&payload, "stable", &trust)
            .unwrap_or_else(|e| panic!("partition {bucket:02x} must verify: {e:#}"));
        if signed.tag.tagger_when == Some(1_770_100_000) {
            verified_hub_signed += 1;
        }
    }
    assert_eq!(verified_hub_signed, 10, "10 freshly hub-signed partitions");

    // An audit row records the hosted-key advance.
    let audit = db.list_audit("acme/infra/prod/cdn").await.unwrap();
    assert!(
        audit
            .iter()
            .any(|a| a.action == "channel.advance" && a.actor_label == "hosted-key:acme-release"),
        "channel.advance audited under the hosted key"
    );
}

#[tokio::test]
async fn advance_below_the_floor_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = two_release_surface(&surface);
    let (db, registry) = serve_hosted(&surface, &fixture).await;

    // The indexer raised the `stable` floor to 1.0.0. Advancing to a *lower*
    // release than the floor is refused (anti-rollback).
    db.set_channel_floor(registry.id, "stable", "1.0.5")
        .await
        .unwrap();
    let surface_write = HubSurfaceWriteProvider::new(Arc::clone(&db));
    let reindexer = HubReindexer::new(Arc::clone(&db));
    let err = signing::advance_channel(
        &db,
        dev_sealer().as_ref(),
        &surface_write,
        &reindexer,
        &registry,
        "stable",
        "1.0.0",
        4,
        1_770_100_000,
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("floor"),
        "refused below floor: {err:#}"
    );
}

/// A [`Reindexer`](aos_hub_core::reindex::Reindexer) that does nothing,
/// modelling the Cloudflare Worker's deferred (Cron-driven) re-index.
struct NoopReindexer;

#[async_trait::async_trait]
impl aos_hub_core::reindex::Reindexer for NoopReindexer {
    async fn reindex(&self, _registry: &RegistryRecord) -> anyhow::Result<Option<String>> {
        Ok(None)
    }
}

/// Anti-rollback holds even when the re-index is deferred (the Worker case).
///
/// Regression for the H4 review's CRITICAL: the anti-rollback floor must be
/// raised *synchronously* by `advance_channel`, not by the (on the Worker,
/// deferred) re-index. With a no-op reindexer, advancing `stable` to `1.1.0`
/// then attempting `1.0.0` must still be refused — otherwise a second advance in
/// one Cron window would read a stale floor and roll the channel back below a
/// version already served live from the surface.
#[tokio::test]
async fn deferred_reindex_still_refuses_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = two_release_surface(&surface);
    let (db, registry) = serve_hosted(&surface, &fixture).await;

    let surface_write = HubSurfaceWriteProvider::new(Arc::clone(&db));
    let reindexer = NoopReindexer;

    // Advance the whole channel to 1.1.0. The re-index is a no-op, so only
    // advance_channel's synchronous floor raise records 1.1.0.
    signing::advance_channel(
        &db,
        dev_sealer().as_ref(),
        &surface_write,
        &reindexer,
        &registry,
        "stable",
        "1.1.0",
        256,
        1_770_100_000,
    )
    .await
    .unwrap();
    assert_eq!(
        db.channel_floor(registry.id, "stable")
            .await
            .unwrap()
            .as_deref(),
        Some("1.1.0"),
        "the advance must raise the floor synchronously, without a re-index"
    );

    // A lower advance is now a rollback and must be refused — even though the
    // index was never updated.
    let err = signing::advance_channel(
        &db,
        dev_sealer().as_ref(),
        &surface_write,
        &reindexer,
        &registry,
        "stable",
        "1.0.0",
        256,
        1_770_100_001,
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("floor"),
        "deferred-reindex rollback must be refused: {err:#}"
    );
}

#[tokio::test]
async fn advance_to_unknown_release_errors_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = two_release_surface(&surface);
    let (db, registry) = serve_hosted(&surface, &fixture).await;

    let surface_write = HubSurfaceWriteProvider::new(Arc::clone(&db));
    let reindexer = HubReindexer::new(Arc::clone(&db));
    let err = signing::advance_channel(
        &db,
        dev_sealer().as_ref(),
        &surface_write,
        &reindexer,
        &registry,
        "stable",
        "9.9.9",
        1,
        1_770_100_000,
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("no indexed release"), "{err:#}");
}

#[tokio::test]
async fn console_shows_hosted_form_and_advances_directly() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = two_release_surface(&surface);
    let (db, _registry) = serve_hosted(&surface, &fixture).await;

    // A maintainer at the registry scope (has ChannelAdvance).
    let user = db.find_or_create_user("maint@acme.com").await.unwrap();
    db.grant_membership("user", user, "acme/infra/prod/cdn", "maintainer")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "maint@acme.com").await;
    let csrf = csrf_for(&cookie);

    // The console renders the hosted-key mode banner and a direct advance form.
    let console_uri = "/acme/infra/prod/cdn/-/channels/stable/console";
    let resp = send(&app, "GET", console_uri, Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(
        resp.body.contains("Signing with hosted key"),
        "hosted-key mode banner: {}",
        resp.body
    );
    assert!(
        resp.body.contains("/channels/stable/advance"),
        "direct advance form action: {}",
        resp.body
    );

    // POST the direct advance form: the hub signs and applies it.
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/channels/stable/advance",
        Some(&cookie),
        Some(&format!("csrf={csrf}&release=1.1.0&partitions=8")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(
        resp.body.contains("Advanced stable to 1.1.0"),
        "{}",
        resp.body
    );

    let after = db.list_channels(_registry.id).await.unwrap();
    let stable = after.iter().find(|c| c.name == "stable").unwrap();
    assert_eq!(
        stable
            .partitions
            .iter()
            .flatten()
            .filter(|s| *s == "1.1.0")
            .count(),
        8
    );
}

#[tokio::test]
async fn console_advance_without_permission_is_forbidden() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = two_release_surface(&surface);
    let (db, _registry) = serve_hosted(&surface, &fixture).await;

    // A read-only viewer at the org scope: no ChannelAdvance.
    let user = db.find_or_create_user("viewer@acme.com").await.unwrap();
    db.grant_membership("user", user, "acme", "viewer")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "viewer@acme.com").await;
    let csrf = csrf_for(&cookie);

    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/channels/stable/advance",
        Some(&cookie),
        Some(&format!("csrf={csrf}&release=1.1.0&partitions=8")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
}

#[tokio::test]
async fn byo_key_console_shows_prepared_op_not_the_direct_form() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = two_release_surface(&surface);
    let (db, registry) = serve_hosted(&surface, &fixture).await;

    // Detach the hosted key: the registry reverts to BYO-key (prepared-op)
    // behavior even though the org still has a key enrolled.
    db.set_registry_hosted_key(registry.id, None).await.unwrap();

    let user = db.find_or_create_user("maint@acme.com").await.unwrap();
    db.grant_membership("user", user, "acme/infra/prod/cdn", "maintainer")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "maint@acme.com").await;
    let csrf = csrf_for(&cookie);

    // The console renders the prepared-for-CLI-signing banner, not the hosted
    // form (its action posts to .../console, not .../advance).
    let resp = send(
        &app,
        "GET",
        "/acme/infra/prod/cdn/-/channels/stable/console",
        Some(&cookie),
        None,
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(
        resp.body.contains("Prepared for CLI signing"),
        "prepared mode banner: {}",
        resp.body
    );
    assert!(
        !resp.body.contains("Signing with hosted key"),
        "no hosted banner when detached"
    );

    // The console POST records a prepared operation (a draft change-set) and
    // renders the apr command — no partitions move on disk.
    let resp = send(
        &app,
        "POST",
        "/acme/infra/prod/cdn/-/channels/stable/console",
        Some(&cookie),
        Some(&format!("csrf={csrf}&release=1.1.0&partitions=8")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(
        resp.body.contains("apr channel advance --from-hub"),
        "prepared apr command: {}",
        resp.body
    );
    let after = db.list_channels(registry.id).await.unwrap();
    let stable = after.iter().find(|c| c.name == "stable").unwrap();
    assert_eq!(
        stable
            .partitions
            .iter()
            .flatten()
            .filter(|s| *s == "1.1.0")
            .count(),
        0,
        "prepared op writes nothing to the surface"
    );
}

#[tokio::test]
async fn org_keys_enrollment_page_creates_and_attaches() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = two_release_surface(&surface);
    let (db, registry) = serve_hosted(&surface, &fixture).await;
    // Detach so the attach form has work to do.
    db.set_registry_hosted_key(registry.id, None).await.unwrap();

    // An org owner has KeysManage.
    let user = db.find_or_create_user("owner@acme.com").await.unwrap();
    db.grant_membership("user", user, "acme", "owner")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "owner@acme.com").await;
    let csrf = csrf_for(&cookie);

    // Create a second hosted key through the page.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/keys",
        Some(&cookie),
        Some(&format!("csrf={csrf}&op=create&key_id=acme-edge")),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(
        resp.body.contains("acme-edge:Ed25519:"),
        "shows the new public line: {}",
        resp.body
    );
    let edge = db.hosted_key_by_name(1, "acme-edge").await.unwrap();
    assert!(edge.is_some(), "key persisted");
    let edge = edge.unwrap();

    // Attach it to the registry through the page.
    let resp = send(
        &app,
        "POST",
        "/-/org/acme/keys",
        Some(&cookie),
        Some(&format!(
            "csrf={csrf}&op=attach&registry=acme/infra/prod/cdn&hosted_key_id={}",
            edge.id
        )),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let reloaded = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.hosted_key_id, Some(edge.id));

    // Both create and attach are audited.
    let audit = db.list_audit("acme").await.unwrap();
    assert!(audit.iter().any(|a| a.action == "hosted_key.create"));
    assert!(audit.iter().any(|a| a.action == "hosted_key.attach"));
}

#[tokio::test]
async fn org_keys_page_requires_keys_manage() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = two_release_surface(&surface);
    let (db, _registry) = serve_hosted(&surface, &fixture).await;

    // A bare viewer is a member but lacks KeysManage: 403 (org is known).
    let user = db.find_or_create_user("viewer@acme.com").await.unwrap();
    db.grant_membership("user", user, "acme", "viewer")
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let cookie = login(&app, &db, "viewer@acme.com").await;
    let resp = send(&app, "GET", "/-/org/acme/keys", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);

    // A non-member gets 404 (existence undisclosed).
    let outsider = db.find_or_create_user("nobody@example.com").await.unwrap();
    let _ = outsider;
    let cookie = login(&app, &db, "nobody@example.com").await;
    let resp = send(&app, "GET", "/-/org/acme/keys", Some(&cookie), None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
}
