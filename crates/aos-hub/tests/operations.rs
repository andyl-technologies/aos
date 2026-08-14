//! Operations-chapter integration coverage (RFC-0004 "Operations:
//! migrations, backup, quotas, observability, offboarding").
//!
//! Drives the real router and database for the operations surface:
//!
//! - staged publication accounting and concurrent-generation exclusion;
//! - the per-endpoint rate limiter returning `429` with `Retry-After` on the
//!   magic-link issuance and device-authorization paths;
//! - the instance signup policy gating `OrganizationService.CreateOrg`;
//! - org export — a redacted SoR manifest plus a round-trippable surface copy;
//! - org soft-delete excluding a registry from serving, restore, and the
//!   grace-window purge job.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{Database, NewSurfacePlacementSpec, SignupPolicy, SurfaceTarget, TokenAuth};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::server::{router, AppState};
use aos_hub_core::service::{ReadAuthorization, RpcError, RpcService};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

/// Deterministic HS256 key so tests can mint matching JWTs.
const TEST_JWT_SECRET: &[u8] = b"operations-test-secret-32byte!!!";

/// Build an [`AppState`] over `db` with deterministic JWT keys and a shared
/// rate limiter.
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
        leases: std::sync::Arc::new(aos_hub_core::lease::InMemoryLease::new()),
        sealer: aos_hub::auth::oidc::dev_sealer(),
        secret_versions: aos_hub_core::secret_version::EmptySecretVersionResolver::shared(),
        http: aos_hub::fetch::hardened_client().await,
        image_snapshots: None,
        mailer: std::sync::Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        identity_domain_verifier: None,
        route_reservation_keyring: None,
    })
}

/// Build the native shared service over the exact ports held by `state`.
fn machine_service(state: &Arc<AppState>) -> RpcService {
    RpcService::new(
        Arc::clone(&state.db),
        state.auth.jwt_keys.clone(),
        state.external_url.clone(),
        Arc::clone(&state.ratelimit) as Arc<dyn aos_hub_core::ratelimit::RateLimiter>,
        Arc::new(
            aos_hub::coreports::HubSurfaceProvider::new(
                Arc::clone(&state.db),
                state.http.clone(),
                state.image_snapshots.clone(),
            )
            .with_credentials(Arc::clone(&state.secret_versions)),
        ),
        Arc::new(
            aos_hub::coreports::HubSurfaceWriteProvider::new(
                Arc::clone(&state.db),
                state.http.clone(),
            )
            .with_credentials(Arc::clone(&state.secret_versions)),
        ),
        Arc::clone(&state.leases) as Arc<dyn aos_hub_core::lease::PublishLease>,
        Arc::new(aos_hub::coreports::HubReindexer::new(
            Arc::clone(&state.db),
            state.image_snapshots.clone(),
        )),
        Arc::new(
            aos_hub_core::topology_probe::DatabaseTopologyProbeScheduler::new(Arc::clone(
                &state.db,
            )),
        ),
        Some(Arc::clone(&state.sealer)),
    )
}

/// Mint a bearer JWT for `principal` scoped to `scope` with `perms`.
fn bearer(principal: Principal, scope: &str, perms: &[Permission]) -> String {
    JwtKeys::from_secret(TEST_JWT_SECRET)
        .mint(
            &TokenAuth {
                token_id: "test-token".into(),
                owner: principal,
                scope: Scope::parse(scope),
                permissions: perms.to_vec(),
            },
            900,
        )
        .unwrap()
}

/// GET one machine path with optional native-session and bearer credentials.
async fn machine_get(
    app: &axum::Router,
    uri: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
) -> (StatusCode, axum::body::Bytes) {
    let mut request = Request::builder()
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8420");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(bearer) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    (status, body)
}

/// Create org "acme", a `local_fs` binding over an empty dir, and a managed
/// registry at `acme/infra/prod/cdn` bound to it (prefix `cdn`). Returns
/// `(db, surface_root, binding_id, placement_id)`.
async fn empty_managed() -> (Arc<Database>, PathBuf, i64, i64) {
    let root = tempfile::tempdir().unwrap().keep();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    db.create_project(org, "infra/prod", "Production")
        .await
        .unwrap();
    let binding = common::create_local_binding(&db, org, "primary", root.to_str().unwrap()).await;
    let registry_id = db
        .create_managed_registry(org, "infra/prod", "cdn", "public", &[], false)
        .await
        .unwrap();
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let publisher = db
        .create_service_account(org, "fixture-publisher")
        .await
        .unwrap();
    db.grant_membership(
        "service_account",
        publisher,
        &common::org_scope(&db, "acme").await,
        "maintainer",
    )
    .await
    .unwrap();
    let placement = common::create_ready_placement(
        &db,
        SurfaceTarget::Registry(registry_id),
        binding,
        "primary",
        "cdn",
    )
    .await;
    common::configure_write_authority(
        &db,
        SurfaceTarget::Registry(registry_id),
        binding,
        &placement,
        "operations-publication",
    )
    .await;
    db.grant_consumer_scope(
        aos_hub::db::GrantResource::NetworkBoundary {
            id: "instance:public",
        },
        &registry.owner_scope_key,
        "explicit",
        "test",
        "request:operations-boundary-grant",
    )
    .await
    .unwrap();
    common::configure_hub_delivery_route(
        &db,
        SurfaceTarget::Registry(registry_id),
        placement.id,
        &registry.owner_scope_key,
        "endpoint:operations-fixture",
        "route:operations-fixture",
        "/acme/infra/prod/cdn",
        "git",
    )
    .await;
    (db, root.join("cdn"), binding, placement.id)
}

#[tokio::test]
async fn cache_route_serves_through_the_selected_placement() {
    let root = tempfile::tempdir().unwrap().keep();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org_id = db.create_org("acme", "Acme").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding =
        common::create_local_binding(&db, org.id, "primary", root.to_str().unwrap()).await;
    let cache = db
        .create_binary_cache(
            Some(org.id),
            "range-cache",
            "Range Cache",
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
        "range-cache",
        "range-cache",
    )
    .await;
    common::configure_hub_delivery_route(
        &db,
        SurfaceTarget::BinaryCache(cache),
        placement.id,
        &org.stable_id,
        "endpoint:range-cache",
        "route:range-cache",
        "/range-cache",
        "nix_cache",
    )
    .await;
    let cache_root = root.join("range-cache");
    std::fs::create_dir_all(&cache_root).unwrap();
    std::fs::write(cache_root.join("nix-cache-info"), b"0123456789").unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/range-cache/nix-cache-info")
                .header(header::HOST, "127.0.0.1:8420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64)
        .await
        .unwrap();
    assert!(body.starts_with(b"StoreDir: /nix/store\n"));
}

#[tokio::test]
async fn native_cache_streams_preserve_session_and_bearer_authorization() {
    let root = tempfile::tempdir().unwrap().keep();
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("private-org", "Private Org").await.unwrap();
    let binding = common::create_local_binding(&db, org, "primary", root.to_str().unwrap()).await;
    let cache_id = db
        .create_binary_cache(
            Some(org),
            "private-cache",
            "Private Cache",
            "private",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
    let private_scope = common::org_scope(&db, "private-org").await;
    let surface = SurfaceTarget::BinaryCache(cache_id);
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface,
            name: "cache".to_string(),
            storage_binding_id: binding,
            prefix: "cache".to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    db.observe_surface_placement(placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    common::configure_hub_delivery_route(
        &db,
        surface,
        placement.id,
        &private_scope,
        "endpoint:private-fixture",
        "route:private-cache",
        "/private-cache",
        "nix_cache",
    )
    .await;
    std::fs::create_dir_all(root.join("cache")).unwrap();
    std::fs::write(root.join("cache/nix-cache-info"), b"cache-private").unwrap();

    let member = db
        .create_user("member@private.invalid", None)
        .await
        .unwrap();
    db.grant_membership("user", member, &private_scope, "viewer")
        .await
        .unwrap();
    let session = db.create_session(member, 3600, 0).await.unwrap();
    let cookie = format!("__Host-aos_session={session}");
    let token = bearer(Principal::user(member), &private_scope, &[Permission::Read]);
    let stale_cache = db.binary_cache_by_id(cache_id).await.unwrap().unwrap();
    let state = app_state(Arc::clone(&db)).await;
    let service = machine_service(&state);
    let app = router(state).await;

    let generated_cache_info = b"StoreDir: /nix/store\n".as_slice();
    for (uri, expected) in [("/private-cache/nix-cache-info", generated_cache_info)] {
        for denied_cookie in [None, Some("__Host-aos_session=invalid")] {
            let (status, _) = machine_get(&app, uri, denied_cookie, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "protected route {uri}");
        }

        let (status, body) = machine_get(&app, uri, Some(&cookie), None).await;
        assert_eq!(status, StatusCode::OK, "session path {uri}");
        assert!(body.starts_with(expected));

        let (status, body) = machine_get(&app, uri, None, Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "bearer path {uri}");
        assert!(body.starts_with(expected));

        let (status, _) = machine_get(&app, uri, None, Some("invalid")).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "invalid bearer path {uri}"
        );
    }

    // Cache soft-delete leaves both its row and placement intact, making this a
    // stronger regression: the freshly reloaded tombstone must stop the read
    // before placement selection or generated/fallback serving.
    assert!(db
        .soft_delete_binary_cache(cache_id, i64::MAX)
        .await
        .unwrap());
    match service
        .cache_serve(
            ReadAuthorization::PreauthorizedSession,
            &stale_cache,
            "nix-cache-info",
            None,
        )
        .await
    {
        Err(RpcError::NotFound(_)) => {}
        _ => panic!("soft-deleted cache must not serve from a stale record"),
    }
}

/// Uploads one admitted publication object, returning `(status, retry_after)`.
async fn upload_publication_object(
    app: &axum::Router,
    upload_url: &str,
    auth: &str,
    body: Vec<u8>,
) -> (StatusCode, Option<String>) {
    let uri = url::Url::parse(upload_url).unwrap().path().to_string();
    let req = Request::builder()
        .method("PUT")
        .uri(&uri)
        .header(header::HOST, "127.0.0.1:8420")
        .header(header::AUTHORIZATION, format!("Bearer {auth}"))
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let retry = resp
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (resp.status(), retry)
}

/// Admits one exact publication manifest through the typed API.
async fn begin_publication(
    app: &axum::Router,
    auth: &str,
    registry: &str,
    generation: &str,
    objects: &[(&str, &[u8], &str)],
) -> (StatusCode, serde_json::Value) {
    let refs = objects
        .iter()
        .find(|(path, _, _)| *path == "info/refs")
        .map_or(&[][..], |(_, bytes, _)| *bytes);
    rpc(
        app,
        "PublishService/BeginRegistryPublication",
        serde_json::json!({
            "registry": registry,
            "generation": generation,
            "refsDigest": hex::encode(Sha256::digest(refs)),
            "objects": objects.iter().map(|(path, bytes, kind)| serde_json::json!({
                "path": path,
                "sha256": hex::encode(Sha256::digest(bytes)),
                "byteSize": bytes.len(),
                "kind": kind,
                "mediaType": aos_hub_core::keymap::content_type(path),
            })).collect::<Vec<_>>(),
        }),
        Some(auth),
    )
    .await
}

/// Returns the typed upload URL for one path in an admitted publication.
fn publication_upload_url<'a>(publication: &'a serde_json::Value, path: &str) -> &'a str {
    publication["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["path"] == path)
        .and_then(|object| object["uploadUrl"].as_str())
        .unwrap()
}

/// POST a form body, returning `(status, retry_after)`.
async fn post_form(
    app: &axum::Router,
    uri: &str,
    body: &str,
    forwarded_for: Option<&str>,
) -> (StatusCode, Option<String>) {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8420")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(xff) = forwarded_for {
        req = req.header("x-forwarded-for", xff);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let retry = resp
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (resp.status(), retry)
}

/// POST a Connect-JSON RPC body, returning `(status, body)`.
async fn rpc(
    app: &axum::Router,
    method: &str,
    json: serde_json::Value,
    auth: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/aos.hub.v1.{method}"))
        .header(header::HOST, "127.0.0.1:8420")
        .header(header::CONTENT_TYPE, "application/json")
        .header("connect-protocol-version", "1");
    if let Some(auth) = auth {
        req = req.header(header::AUTHORIZATION, format!("Bearer {auth}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(json.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn planned_rpc(
    app: &axum::Router,
    plan_method: &str,
    apply_method: &str,
    mut plan_body: serde_json::Value,
    auth: Option<&str>,
    key: &str,
) -> (StatusCode, serde_json::Value) {
    plan_body["idempotencyKey"] = serde_json::Value::String(format!("{key}-plan"));
    let (status, plan) = rpc(app, plan_method, plan_body, auth).await;
    if status != StatusCode::OK {
        return (status, plan);
    }
    rpc(
        app,
        apply_method,
        serde_json::json!({
            "planId": plan["plan"]["planId"],
            "idempotencyKey": format!("{key}-apply"),
            "confirmationHash": plan["plan"]["confirmationHash"],
        }),
        auth,
    )
    .await
}

#[tokio::test]
async fn staged_publication_bytes_remain_unaccounted_until_commit() {
    let (db, _surface, _binding, _placement) = empty_managed().await;
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(
        Principal::service_account(1),
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
        &[Permission::Publish],
    );

    let first = [
        ("objects/ab/cd", b"data".as_slice(), "immutable"),
        ("info/refs", b"".as_slice(), "mutable_pointer"),
    ];
    let (status, publication) =
        begin_publication(&app, &token, "acme/infra/prod/cdn", "staging-v1", &first).await;
    assert_eq!(status, StatusCode::OK, "{publication}");
    let (status, _) = upload_publication_object(
        &app,
        publication_upload_url(&publication, "objects/ab/cd"),
        &token,
        b"data".to_vec(),
    )
    .await;
    assert!(status.is_success(), "{status}");
    assert_eq!(db.org_usage(org.id).await.unwrap().used_bytes, 0);
    assert_eq!(db.org_usage(org.id).await.unwrap().object_count, 0);
}

#[tokio::test]
async fn concurrent_pointer_uploads_share_the_phase_transition() {
    let (db, _surface, _binding, _placement) = empty_managed().await;
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(
        Principal::service_account(1),
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
        &[Permission::Publish],
    );

    let objects = [
        ("objects/ab/cd", b"data".as_slice(), "immutable"),
        ("info/refs", b"".as_slice(), "mutable_pointer"),
        (
            "nix-cache-info",
            b"StoreDir: /nix/store\n".as_slice(),
            "mutable_pointer",
        ),
    ];
    let (status, publication) =
        begin_publication(&app, &token, "acme/infra/prod/cdn", "pointer-race", &objects)
            .await;
    assert_eq!(status, StatusCode::OK, "{publication}");

    let (status, _) = upload_publication_object(
        &app,
        publication_upload_url(&publication, "objects/ab/cd"),
        &token,
        b"data".to_vec(),
    )
    .await;
    assert!(status.is_success(), "{status}");

    let refs = upload_publication_object(
        &app,
        publication_upload_url(&publication, "info/refs"),
        &token,
        Vec::new(),
    );
    let cache_info = upload_publication_object(
        &app,
        publication_upload_url(&publication, "nix-cache-info"),
        &token,
        b"StoreDir: /nix/store\n".to_vec(),
    );
    let ((refs_status, _), (cache_info_status, _)) = tokio::join!(refs, cache_info);
    assert!(refs_status.is_success(), "{refs_status}");
    assert!(cache_info_status.is_success(), "{cache_info_status}");
}

#[tokio::test]
async fn concurrent_publication_generation_is_rejected() {
    let (db, _surface, _binding, _placement) = empty_managed().await;
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(
        Principal::service_account(1),
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
        &[Permission::Publish],
    );

    let first = [
        ("objects/ab/cd", b"data".as_slice(), "immutable"),
        ("info/refs", b"".as_slice(), "mutable_pointer"),
    ];
    let (status, publication) =
        begin_publication(&app, &token, "acme/infra/prod/cdn", "immutable-v1", &first).await;
    assert_eq!(status, StatusCode::OK, "{publication}");
    let (status, _) = upload_publication_object(
        &app,
        publication_upload_url(&publication, "objects/ab/cd"),
        &token,
        b"data".to_vec(),
    )
    .await;
    assert!(status.is_success(), "{status}");
    assert_eq!(db.org_usage(org.id).await.unwrap().used_bytes, 0);
    assert_eq!(db.org_usage(org.id).await.unwrap().object_count, 0);

    // A later generation cannot start while the preceding publication is
    // incomplete. Admission fails before any additional write or usage change.
    let changed = [
        ("objects/ab/cd", b"ten-bytes!".as_slice(), "immutable"),
        ("info/refs", b"".as_slice(), "mutable_pointer"),
    ];
    let (status, _) = begin_publication(
        &app,
        &token,
        "acme/infra/prod/cdn",
        "immutable-v2",
        &changed,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(db.org_usage(org.id).await.unwrap().used_bytes, 0);
    assert_eq!(db.org_usage(org.id).await.unwrap().object_count, 0);
}

#[tokio::test]
async fn magic_link_issuance_is_rate_limited_per_email() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(db).await).await;
    let body = "email=victim%40acme.com";
    // The first MAGIC_LINK_PER_EMAIL requests succeed (200 "check your email").
    for _ in 0..aos_hub::ratelimit::MAGIC_LINK_PER_EMAIL {
        let (status, _) = post_form(&app, "/login", body, Some("203.0.113.7")).await;
        assert_eq!(status, StatusCode::OK, "within-budget magic link");
    }
    // The next one for the same email is 429 with a Retry-After.
    let (status, retry) = post_form(&app, "/login", body, Some("203.0.113.7")).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry.is_some(), "Retry-After present on 429");
}

#[tokio::test]
async fn device_authorization_is_rate_limited_per_ip() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(app_state(db).await).await;
    let ip = "198.51.100.4";
    let body = "client_id=aos-cli";
    for _ in 0..aos_hub::ratelimit::DEVICE_AUTH_PER_IP {
        let (status, _) = post_form(&app, "/oauth2/device_authorization", body, Some(ip)).await;
        assert_eq!(status, StatusCode::OK, "within-budget device auth");
    }
    let (status, retry) = post_form(&app, "/oauth2/device_authorization", body, Some(ip)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(retry.is_some());
}

#[tokio::test]
async fn signup_policy_gates_create_org() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    // Default policy is invite-only.
    let fresh = db.create_user("nobody@acme.com", None).await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(Principal::user(fresh), "instance", &[]);

    // invite_only blocks a fresh, unaffiliated user.
    let (status, _) = rpc(
        &app,
        "OrganizationService/PlanCreateOrganization",
        serde_json::json!({"slug": "acme", "displayName": "Acme", "idempotencyKey": "invite-only"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Switch to open: the same user may now create an org.
    db.set_signup_policy(SignupPolicy::Open).await.unwrap();
    let (status, value) = planned_rpc(
        &app,
        "OrganizationService/PlanCreateOrganization",
        "OrganizationService/CreateOrganization",
        serde_json::json!({"slug": "acme", "displayName": "Acme"}),
        Some(&token),
        "open-signup",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
}

#[tokio::test]
async fn invite_only_allows_existing_member() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    // A user who is already a member of *some* org may create another, even
    // under invite-only.
    let member = db.create_user("dev@acme.com", None).await.unwrap();
    db.create_org("existing", "Existing").await.unwrap();
    db.grant_membership(
        "user",
        member,
        &common::org_scope(&db, "existing").await,
        "developer",
    )
    .await
    .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(Principal::user(member), "instance", &[]);
    let (status, value) = planned_rpc(
        &app,
        "OrganizationService/PlanCreateOrganization",
        "OrganizationService/CreateOrganization",
        serde_json::json!({"slug": "second", "displayName": "Second"}),
        Some(&token),
        "member-signup",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
}

#[tokio::test]
async fn org_export_manifest_redacts_secrets_and_surface_round_trips() {
    let (db, surface, _binding_id, _placement) = empty_managed().await;
    let org = db.org_by_slug("acme").await.unwrap().unwrap();
    // A managed cache so the manifest's cache slice has something to carry.
    db.create_binary_cache(
        Some(org.id),
        "acme-cache",
        "Acme Cache",
        "public",
        40,
        "zstd",
        true,
    )
    .await
    .unwrap();
    // Members and a token (its hash must never appear in the export).
    let alice = db.create_user("alice@acme.com", None).await.unwrap();
    db.grant_membership(
        "user",
        alice,
        &common::org_scope(&db, "acme").await,
        "owner",
    )
    .await
    .unwrap();
    let sa = db
        .create_service_account(org.id, "publisher")
        .await
        .unwrap();
    db.grant_membership(
        "service_account",
        sa,
        &common::org_scope(&db, "acme").await,
        "maintainer",
    )
    .await
    .unwrap();
    let (_id, secret) = db
        .create_token(
            Principal::service_account(sa),
            &common::registry_scope(&db, "acme/infra/prod/cdn").await,
            &[Permission::Publish],
            Some("ci"),
            None,
        )
        .await
        .unwrap();

    // Upload an admitted immutable object so the surface copy has something to
    // round-trip. The typed publication remains intentionally uncommitted: the
    // export test concerns physical-byte copying, not signed-index promotion.
    let app = router(app_state(Arc::clone(&db)).await).await;
    let token = bearer(
        Principal::service_account(sa),
        &common::registry_scope(&db, "acme/infra/prod/cdn").await,
        &[Permission::Publish],
    );
    let objects = [
        ("objects/ab/cd", b"surface-bytes".as_slice(), "immutable"),
        ("info/refs", b"".as_slice(), "mutable_pointer"),
    ];
    let (status, publication) = begin_publication(
        &app,
        &token,
        "acme/infra/prod/cdn",
        "export-fixture-v1",
        &objects,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{publication}");
    let (status, _) = upload_publication_object(
        &app,
        publication_upload_url(&publication, "objects/ab/cd"),
        &token,
        b"surface-bytes".to_vec(),
    )
    .await;
    assert!(status.is_success());
    assert!(surface.join("objects/ab/cd").exists());

    // The manifest carries the registry + members + token metadata, but no
    // hash/secret.
    let manifest = aos_hub::export::export_org(&db, "acme").await.unwrap();
    let json = serde_json::to_string(&manifest).unwrap();
    assert!(manifest
        .registries
        .iter()
        .any(|r| r.slug == "acme/infra/prod/cdn"));
    assert!(
        manifest
            .caches
            .iter()
            .any(|c| c.slug == "acme-cache" && c.compression == "zstd"),
        "managed cache missing from export manifest"
    );
    assert!(manifest
        .memberships
        .iter()
        .any(|m| m.scope == org.stable_id && m.role == "owner"));
    assert_eq!(manifest.tokens.len(), 1);
    assert_eq!(
        manifest.tokens[0].scope,
        common::registry_scope(&db, "acme/infra/prod/cdn").await
    );
    // No secret, no hash anywhere in the serialized manifest.
    let hash = aos_hub::auth::token::sha256_hex(&secret);
    assert!(!json.contains(&secret), "raw secret leaked into manifest");
    assert!(!json.contains(&hash), "token hash leaked into manifest");

    // The surface copy round-trips the uploaded object byte-for-byte.
    let dest = tempfile::tempdir().unwrap();
    let registry = db
        .registry_by_slug("acme/infra/prod/cdn")
        .await
        .unwrap()
        .unwrap();
    let copied = aos_hub::export::export_registry_surface(&db, registry.id, dest.path())
        .await
        .unwrap();
    assert!(copied >= 1);
    assert_eq!(
        std::fs::read(dest.path().join("objects/ab/cd")).unwrap(),
        b"surface-bytes"
    );
}

#[tokio::test]
async fn soft_deleted_org_stops_serving_and_purges_after_grace() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("cdn");
    let fixture = common::standard_registry(&surface);
    let _ = &fixture;

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let _binding =
        common::create_local_binding(&db, org, "primary", dir.path().to_str().unwrap()).await;
    db.create_managed_registry(org, "", "cdn", "public", &[], false)
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Before deletion the registry home serves.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme/cdn/")
                .header(header::HOST, "127.0.0.1:8420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Soft-delete: the registry now 404s (tombstoned, non-disclosing).
    assert!(db.soft_delete_org(org, 100).await.unwrap());
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme/cdn/")
                .header(header::HOST, "127.0.0.1:8420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Restore brings it back.
    assert!(db.restore_org(org).await.unwrap());
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/acme/cdn/")
                .header(header::HOST, "127.0.0.1:8420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Re-delete and purge past the grace window.
    assert!(db.soft_delete_org(org, 100).await.unwrap());
    let now = unix_now();
    assert!(
        aos_hub::export::purge_expired_orgs(&db, now)
            .await
            .unwrap()
            .is_empty(),
        "not purgeable inside the grace window"
    );
    let purged = aos_hub::export::purge_expired_orgs(&db, now + 200)
        .await
        .unwrap();
    assert_eq!(purged, vec!["acme".to_string()]);
    // The org (and its cascade) are gone.
    assert!(db
        .org_by_slug_including_deleted("acme")
        .await
        .unwrap()
        .is_none());
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The hard-cutover API has no combined cache-link route.
#[tokio::test]
async fn legacy_link_cache_route_is_absent_and_creates_no_integration() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    common::create_local_binding(&db, org, "primary", "/srv").await;
    db.create_managed_registry(org, "", "pub", "public", &[], false)
        .await
        .unwrap();
    db.create_binary_cache(Some(org), "priv-cache", "Priv", "private", 40, "zstd", true)
        .await
        .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;
    let (status, body) = rpc(
        &app,
        "BinaryCacheService/LinkCache",
        serde_json::json!({
            "cacheSlug": "priv-cache", "registrySlug": "acme/pub", "advertised": true
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{body}");

    let registry = db.registry_by_slug("acme/pub").await.unwrap().unwrap();
    assert!(db
        .registry_cache_stack_entries(registry.id)
        .await
        .unwrap()
        .is_empty());
    assert!(db
        .list_registry_retention_subscriptions_topology(registry.id)
        .await
        .unwrap()
        .is_empty());
    assert!(db
        .list_registry_population_targets(registry.id)
        .await
        .unwrap()
        .is_empty());
}
