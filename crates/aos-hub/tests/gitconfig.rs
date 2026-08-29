//! Git-backed configuration change requests (RFC-0004 "Configuration
//! management", git-backed path).
//!
//! Covers the hub side end to end: [`propose_config_change`] writes a
//! draft-signed change-request commit and ref and records a change-set +
//! revision + audit row; the indexer's `AOS-Change-Id` trailer matching marks a
//! promoted change request applied and synthesizes an idempotent `external`
//! audit entry for out-of-band commits; and the `GitService` RPCs surface the
//! committed log, config diffs, and change-request list.

mod common;

use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{Database, RegistryRecord, TokenAuth};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::fetch::LocalFsFetch;
use aos_hub::server::{router, AppState};
use aos_hub::surface::object::{decode_loose, parse_commit, ObjectKind, Oid};
use aos_hub::{gitwrite, indexer};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

const TEST_JWT_SECRET: &[u8] = b"gitconfig-test-secret-32-byte!!!";

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
        container_rollout: aos_hub_core::container_rollout::ContainerRollout::all_enabled(),
    })
}

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

/// Build a fixture surface bound to a managed `public` registry at `acme/cdn`,
/// indexed, with signatures verified against the fixture key. Returns the db,
/// the binding root, and the registry record.
async fn managed_indexed(message: &str) -> (Arc<Database>, tempfile::TempDir, RegistryRecord) {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("cdn");
    let fixture = common::standard_registry_with_commit_message(&surface, "1.0.0", message);

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding =
        common::create_local_binding(&db, org, "primary", dir.path().to_str().unwrap()).await;
    db.create_managed_registry(
        org,
        "",
        "cdn",
        "public",
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap();
    let registry = db.registry_by_slug("acme/cdn").await.unwrap().unwrap();
    let placement = common::create_ready_placement(
        &db,
        aos_hub::db::SurfaceTarget::Registry(registry.id),
        binding,
        "primary",
        "cdn",
    )
    .await;
    common::configure_write_authority(
        &db,
        aos_hub::db::SurfaceTarget::Registry(registry.id),
        binding,
        &placement,
        "gitconfig-fixture-writer",
    )
    .await;

    let fetch = LocalFsFetch::new(&surface);
    indexer::index_and_record(&db, &fetch, &registry)
        .await
        .unwrap();
    (db, dir, registry)
}

/// Resolve the core surface read/write ports for a registry, the way the shared
/// `propose_config_change` flow is wired in `server.rs`.
async fn surface_ports(
    db: &Arc<Database>,
    registry: &RegistryRecord,
) -> (
    Box<dyn aos_hub_core::fetch::SurfaceFetch>,
    Box<dyn aos_hub_core::surface_write::SurfaceWrite>,
) {
    use aos_hub_core::fetch::SurfaceProvider as _;
    use aos_hub_core::surface_write::SurfaceWriteProvider as _;
    let http = aos_hub::fetch::hardened_client().await;
    let placement = db
        .list_surface_placements(aos_hub::db::SurfaceTarget::Registry(registry.id))
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let fetch = aos_hub::coreports::HubSurfaceProvider::new(Arc::clone(db), http.clone(), None)
        .placement_fetcher(&placement)
        .await
        .unwrap();
    let writer = aos_hub::coreports::HubSurfaceWriteProvider::new(Arc::clone(db), http)
        .placement_writer(&placement)
        .await
        .unwrap();
    (fetch, writer)
}

// -- propose_config_change: records change-set + ref + audit, signed commit ---

#[tokio::test]
async fn propose_writes_signed_draft_commit_ref_and_records() {
    let (db, dir, registry) = managed_indexed("release 1.0.0").await;
    let surface = dir.path().join("cdn");
    let sealer = aos_hub::auth::oidc::dev_sealer();

    let new_toml = "[registry]\nname = \"demo\"\ndescription = \"edited via change request\"\n";
    let (fetch, writer) = surface_ports(&db, &registry).await;
    let proposed = gitwrite::propose_config_change(
        &db,
        sealer.as_ref(),
        fetch.as_ref(),
        writer.as_ref(),
        &registry,
        "registry.toml",
        new_toml,
        "user",
        Some(7),
        "alice@acme.com",
        1_770_000_100,
        gitwrite::ProposeMeta::default(),
    )
    .await
    .unwrap();

    // The change-set is recorded as a git-backed draft with the ref + commit.
    let cs = db
        .changeset(proposed.change_id.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cs.status, "draft");
    assert_eq!(cs.git_ref.as_deref(), Some(proposed.git_ref.as_str()));
    assert_eq!(cs.git_commit.as_deref(), Some(proposed.commit_oid.as_str()));

    // The revision carries the old and new file contents.
    let revisions = db
        .list_revisions(proposed.change_id.as_str())
        .await
        .unwrap();
    assert_eq!(revisions.len(), 1);
    assert_eq!(revisions[0].object_type, "registry_file");
    assert_eq!(revisions[0].object_id, "registry.toml");
    assert_eq!(revisions[0].new_json.as_deref(), Some(new_toml));
    assert!(revisions[0]
        .old_json
        .as_deref()
        .unwrap()
        .contains("Fixture registry"));

    // An audit row ties the change request to the draft commit.
    let audit = db
        .list_audit(&common::org_scope(&db, "acme").await)
        .await
        .unwrap();
    let cr = audit
        .iter()
        .find(|r| r.action == "config.change_request")
        .expect("a config.change_request audit row");
    assert_eq!(cr.change_id.as_deref(), Some(proposed.change_id.as_str()));
    assert_eq!(
        cr.result_commit.as_deref(),
        Some(proposed.commit_oid.as_str())
    );

    // The draft ref file was written (a ref, not a branch consumers follow).
    let ref_path = surface.join(&proposed.git_ref);
    let ref_contents = std::fs::read_to_string(&ref_path).unwrap();
    assert_eq!(ref_contents.trim(), proposed.commit_oid);

    // The signed draft commit object hash-verifies and its gpgsig verifies
    // against the draft-signing key; parse_commit recovers tree + trailer.
    let oid = Oid::from_hex(&proposed.commit_oid).unwrap();
    let loose = std::fs::read(surface.join(oid.loose_path())).unwrap();
    let (kind, content) = decode_loose(&loose, Some(oid)).unwrap();
    assert_eq!(kind, ObjectKind::Commit);
    let commit = parse_commit(&content).unwrap();
    assert_eq!(
        commit.parents.len(),
        1,
        "draft is a child of the base commit"
    );
    let message = String::from_utf8_lossy(&content);
    let trailer = gitwrite::extract_change_id_trailer(&message);
    assert_eq!(trailer.as_deref(), Some(proposed.change_id.as_str()));

    let (_signing_key, draft_line) = db
        .get_or_create_draft_signing_key(sealer.as_ref())
        .await
        .unwrap();
    let signature = commit.signature.expect("draft commit is signed");
    aos_hub::surface::sshsig::verify_armored(
        &signature,
        &commit.signed_payload,
        std::slice::from_ref(&draft_line),
    )
    .expect("draft signature verifies against the draft-signing key");

    // The new committed tree carries the edited registry.toml.
    let fetch = LocalFsFetch::new(&surface);
    let edited = gitwrite::load_committed_file(&fetch, oid, "registry.toml")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(edited, new_toml);
}

// -- indexer: AOS-Change-Id trailer marks a change request applied -----------

#[tokio::test]
async fn indexer_trailer_marks_known_change_request_applied() {
    // Pre-create a draft change-set whose id will appear as the HEAD commit's
    // AOS-Change-Id trailer (simulating a maintainer who promoted the draft).
    let change_id = "01JCHANGEAPPLIEDTEST";
    let message = format!("release 1.0.0\n\nAOS-Change-Id: {change_id}\n");

    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("cdn");
    let fixture = common::standard_registry_with_commit_message(&surface, "1.0.0", &message);

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding =
        common::create_local_binding(&db, org, "primary", dir.path().to_str().unwrap()).await;
    db.create_managed_registry(
        org,
        "",
        "cdn",
        "public",
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap();
    let registry = db.registry_by_slug("acme/cdn").await.unwrap().unwrap();
    let registry_scope = db.registry_authorization_scope(registry.id).await.unwrap();
    db.create_git_changeset(
        change_id,
        "user",
        Some(7),
        "alice@acme.com",
        &registry_scope,
        Some("edit registry.toml"),
        &format!("refs/hub/changes/{change_id}"),
        "draftoid",
        None,
        None,
    )
    .await
    .unwrap();

    let fetch = LocalFsFetch::new(&surface);
    let outcome = indexer::index_and_record(&db, &fetch, &registry)
        .await
        .unwrap();

    // The trailer matched the draft, marking it applied and linking the commit.
    let cs = db.changeset(change_id).await.unwrap().unwrap();
    assert_eq!(cs.status, "applied");
    assert!(cs.applied_at.is_some());
    assert_eq!(cs.git_commit.as_deref(), Some(outcome.commit.as_str()));

    // No external-commit audit row is synthesized when a trailer matched.
    assert!(!db
        .audit_exists_for_commit("index.external_commit", &outcome.commit)
        .await
        .unwrap());
}

// -- indexer: a foreign-scoped change-id trailer does NOT mark applied --------

#[tokio::test]
async fn indexer_ignores_change_id_scoped_to_another_registry() {
    // Registry B (acme/cdn) is indexed; its HEAD commit carries a change-id
    // whose change-set is scoped to a *different* registry (acme/other).
    let change_id = "01JCROSSSCOPETEST";
    let message = format!("release 1.0.0\n\nAOS-Change-Id: {change_id}\n");

    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("cdn");
    let fixture = common::standard_registry_with_commit_message(&surface, "1.0.0", &message);

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let binding =
        common::create_local_binding(&db, org, "primary", dir.path().to_str().unwrap()).await;
    db.create_managed_registry(
        org,
        "",
        "cdn",
        "public",
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap();
    db.create_project(org, "other", "Other").await.unwrap();
    let other_scope = common::project_scope(&db, "acme", "other").await;
    // The change-set targets registry A (acme/other), not the registry being
    // indexed. A commit on B must not mark A's change request applied.
    db.create_git_changeset(
        change_id,
        "user",
        Some(7),
        "alice@acme.com",
        &other_scope,
        Some("edit a different registry"),
        &format!("refs/hub/changes/{change_id}"),
        "draftoid",
        None,
        None,
    )
    .await
    .unwrap();

    let registry = db.registry_by_slug("acme/cdn").await.unwrap().unwrap();
    let fetch = LocalFsFetch::new(&surface);
    let outcome = indexer::index_and_record(&db, &fetch, &registry)
        .await
        .unwrap();

    // The foreign-scoped change-set is left untouched (still a draft).
    let cs = db.changeset(change_id).await.unwrap().unwrap();
    assert_eq!(
        cs.status, "draft",
        "foreign change request must not be applied"
    );
    assert!(cs.applied_at.is_none());
    assert!(cs.git_commit.as_deref() != Some(outcome.commit.as_str()));

    // The commit is instead treated as external (an audit row is synthesized).
    assert!(db
        .audit_exists_for_commit("index.external_commit", &outcome.commit)
        .await
        .unwrap());
}

// -- indexer: external-audit synthesis for a no-trailer commit (idempotent) ---

#[tokio::test]
async fn indexer_synthesizes_external_audit_once() {
    let (db, dir, registry) = managed_indexed("release 1.0.0").await;
    let surface = dir.path().join("cdn");

    let commit = db
        .index_status(registry.id)
        .await
        .unwrap()
        .unwrap()
        .last_indexed_commit
        .unwrap();

    // The first index synthesized exactly one external-commit audit row.
    let externals = db
        .list_audit(&db.registry_authorization_scope(registry.id).await.unwrap())
        .await
        .unwrap()
        .into_iter()
        .filter(|r| {
            r.action == "index.external_commit" && r.result_commit.as_deref() == Some(&commit)
        })
        .count();
    assert_eq!(externals, 1, "exactly one external-commit audit row");

    // The actor resolves to the fixture's roster id (the commit signer).
    let row = db
        .list_audit(&db.registry_authorization_scope(registry.id).await.unwrap())
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.action == "index.external_commit")
        .unwrap();
    assert_eq!(row.actor_label, "roster:maintainer");

    // Re-indexing the same surface must NOT duplicate the row. Force a full
    // re-walk by clearing the refs digest so the incremental fast path is
    // skipped (a no-op surface change would otherwise short-circuit).
    db.mark_index_failed(registry.id, "force re-walk")
        .await
        .unwrap();
    let fetch = LocalFsFetch::new(&surface);
    indexer::index_and_record(&db, &fetch, &registry)
        .await
        .unwrap();

    let externals = db
        .list_audit(&common::org_scope(&db, "acme").await)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| {
            r.action == "index.external_commit" && r.result_commit.as_deref() == Some(&commit)
        })
        .count();
    assert_eq!(
        externals, 1,
        "re-index must not duplicate the external audit row"
    );
}

// -- GitService RPCs: log, diff, change-request list -------------------------

#[tokio::test]
async fn git_service_log_diff_and_change_requests() {
    let (db, _dir, registry) = managed_indexed("release 1.0.0").await;
    let sealer = aos_hub::auth::oidc::dev_sealer();

    // Create a change request so ListChangeRequests has something to return.
    let new_toml = "[registry]\nname = \"demo\"\ndescription = \"changed\"\n";
    let (fetch, writer) = surface_ports(&db, &registry).await;
    let proposed = gitwrite::propose_config_change(
        &db,
        sealer.as_ref(),
        fetch.as_ref(),
        writer.as_ref(),
        &registry,
        "registry.toml",
        new_toml,
        "user",
        Some(7),
        "alice@acme.com",
        1_770_000_100,
        gitwrite::ProposeMeta::default(),
    )
    .await
    .unwrap();

    let app = router(app_state(Arc::clone(&db)).await).await;

    // GitLog (public registry → anonymous read): the committed history.
    let (status, value) = rpc(
        &app,
        "GitService/GitLog",
        serde_json::json!({"slug": "acme/cdn"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert!(!value["commits"].as_array().unwrap().is_empty());
    // The fixture HEAD is the root commit; Connect-JSON omits an empty
    // repeated field, so `parents` is absent rather than `[]`.
    assert!(value["commits"][0]["parents"]
        .as_array()
        .is_none_or(|p| p.is_empty()));

    // GitDiff between the base HEAD and the draft commit shows the edit.
    let head = db
        .index_status(registry.id)
        .await
        .unwrap()
        .unwrap()
        .last_indexed_commit
        .unwrap();
    let (status, value) = rpc(
        &app,
        "GitService/GitDiff",
        serde_json::json!({"slug": "acme/cdn", "fromOid": head, "toOid": proposed.commit_oid}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let diff = value["diff"].as_str().unwrap();
    assert!(diff.contains("+description = \"changed\""), "diff: {diff}");

    // ListChangeRequests requires audit.read; anonymous is rejected.
    let (status, _) = rpc(
        &app,
        "GitService/ListChangeRequests",
        serde_json::json!({"slug": "acme/cdn"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // With audit.read (intersected with a live Owner grant), it lists the draft.
    let user = db.create_user("alice@acme.com", None).await.unwrap();
    db.grant_membership(
        "user",
        user,
        &common::org_scope(&db, "acme").await,
        aos_hub::domain::Role::Owner.as_str(),
    )
    .await
    .unwrap();
    let token = bearer(
        Principal::user(user),
        &common::registry_scope(&db, "acme/cdn").await,
        &[Permission::AuditRead],
    );
    let (status, value) = rpc(
        &app,
        "GitService/ListChangeRequests",
        serde_json::json!({"slug": "acme/cdn"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let crs = value["changeRequests"].as_array().unwrap();
    assert_eq!(crs.len(), 1);
    assert_eq!(crs[0]["changeId"], proposed.change_id.as_str());
    assert_eq!(crs[0]["status"], "draft");
    assert!(crs[0]["mergeCommand"]
        .as_str()
        .unwrap()
        .contains("apr change merge"));
    let file_diff = crs[0]["fileDiffs"][0]["diff"].as_str().unwrap();
    assert!(
        file_diff.contains("+description = \"changed\""),
        "{file_diff}"
    );
}
