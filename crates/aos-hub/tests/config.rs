//! Phase-3a integration coverage: the SQL-backed configuration change-set
//! engine and the audit log, both at the engine level and over the
//! Connect-JSON `AuditService`/`RegistryConfigurationService` RPCs.
//!
//! Exercises the full lifecycle — open draft, stage, review (semantic
//! diffs), apply (live mutation + audit row), and snapshot-targeted forward
//! revert with conflict detection and the security-object exemptions — plus
//! the RPC authz mirror (audit.read / registry.configure on the scope).

mod common;

use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::config::{self, ConfigOp, MembershipChange};
use aos_hub::db::{Database, TokenAuth};
use aos_hub::domain::{Permission, Principal, Role, Scope};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

/// Deterministic HS256 key so tests can mint matching JWTs.
const TEST_JWT_SECRET: &[u8] = b"config-test-secret-32-byte-key!!";

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

fn bearer(principal: Principal, scope: &str, perms: &[Permission]) -> String {
    let keys = JwtKeys::from_secret(TEST_JWT_SECRET);
    keys.mint(
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

/// Create org "acme" with a managed (unindexed) registry at
/// `acme/infra/prod/cdn`, returning the registry id.
async fn managed_registry(db: &Database, visibility: &str) -> i64 {
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    db.create_project(org, "infra/prod", "Production")
        .await
        .unwrap();
    db.create_managed_registry(org, "infra/prod", "cdn", visibility, &[], true)
        .await
        .unwrap()
}

async fn update_registry_visibility(
    db: &Database,
    registry_id: i64,
    visibility: &str,
    actor_id: i64,
) -> config::ChangeId {
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let change_id = config::ChangeId(uuid::Uuid::new_v4().to_string());
    assert!(db
        .seed_registry_configuration_for_test(
            registry_id,
            registry.resource_version,
            visibility,
            &registry.crawl_policy,
            registry.llms_txt_body.as_deref(),
            &registry.trust_keys,
            change_id.as_str(),
            "user",
            Some(actor_id),
            "alice@acme.com",
        )
        .await
        .unwrap());
    change_id
}

// -- engine: open -> stage -> review -> apply -------------------------------

#[tokio::test]
async fn engine_open_stage_review_apply_writes_audit() {
    let db = Database::open_in_memory().await.unwrap();
    let id = managed_registry(&db, "public").await;
    let actor = Principal::user(7);
    let scope_key = db.registry_authorization_scope(id).await.unwrap();

    let change_id = config::open_draft(
        &db,
        &actor,
        "alice@acme.com",
        &Scope::parse(&scope_key),
        "flip cdn private",
    )
    .await
    .unwrap();
    config::stage(
        &db,
        &change_id,
        "registry",
        "acme/infra/prod/cdn",
        ConfigOp::Update,
        Some(serde_json::json!({"visibility": "public"})),
        Some(serde_json::json!({"visibility": "private"})),
    )
    .await
    .unwrap();

    // Review renders the semantic diff.
    let review = config::review(&db, &change_id).await.unwrap();
    assert_eq!(review.len(), 1);
    let (revision, diffs) = &review[0];
    assert_eq!(revision.op, ConfigOp::Update);
    assert_eq!(diffs.len(), 1);
    assert_eq!(diffs[0].field, "visibility");
    assert_eq!(diffs[0].old.as_deref(), Some("public"));
    assert_eq!(diffs[0].new.as_deref(), Some("private"));

    // Apply runs the live mutation and writes one audit row.
    config::apply(&db, &change_id, "registry.visibility", |_rev| async move {
        Ok(())
    })
    .await
    .unwrap();

    let cs = db.changeset(change_id.as_str()).await.unwrap().unwrap();
    assert_eq!(cs.status, "applied");
    assert!(cs.applied_at.is_some());

    let audit = db
        .list_audit(&common::org_scope(&db, "acme").await)
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].change_id.as_deref(), Some(change_id.as_str()));
    assert_eq!(audit[0].action, "registry.visibility");
    assert_eq!(audit[0].actor_label, "alice@acme.com");
}

// -- real consumer + revert round trip --------------------------------------

#[tokio::test]
async fn visibility_change_and_revert_round_trip() {
    let db = Database::open_in_memory().await.unwrap();
    let id = managed_registry(&db, "public").await;
    let actor = Principal::user(7);

    let change_id = update_registry_visibility(&db, id, "private", 7).await;
    assert_eq!(
        db.registry_by_slug("acme/infra/prod/cdn")
            .await
            .unwrap()
            .unwrap()
            .visibility,
        "private"
    );

    // Revert drafts a forward change-set that flips it back; no conflict.
    let draft = config::revert(&db, &change_id, &actor, "alice@acme.com", |t, oid| {
        let is_registry = t == "registry";
        let oid = oid.to_string();
        let db = &db;
        async move {
            if is_registry {
                db.registry_by_id(id)
                    .await
                    .ok()
                    .flatten()
                    .filter(|registry| registry.stable_id == oid)
                    .map(|registry| {
                        serde_json::json!({
                            "stableId": registry.stable_id,
                            "slug": registry.slug,
                            "visibility": registry.visibility,
                            "crawlPolicy": registry.crawl_policy,
                            "llmsTxtBody": registry.llms_txt_body,
                            "trustKeys": registry.trust_keys,
                            "resourceVersion": registry.resource_version,
                        })
                    })
            } else {
                None
            }
        }
    })
    .await
    .unwrap();
    assert!(draft.conflicts.is_empty(), "{:?}", draft.conflicts);

    // The original is now marked reverted_by the new draft.
    let original = db.changeset(change_id.as_str()).await.unwrap().unwrap();
    assert_eq!(
        original.reverted_by_change_id.as_deref(),
        Some(draft.change_id.as_str())
    );

    // Apply the revert: live visibility is restored to public.
    config::apply(&db, &draft.change_id, "changeset.revert", |rev| {
        let visibility = rev
            .new_json
            .as_ref()
            .and_then(|v| v.get("visibility"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let db = &db;
        async move {
            if let Some(v) = visibility {
                update_registry_visibility(db, id, &v, 7).await;
            }
            Ok(())
        }
    })
    .await
    .unwrap();
    assert_eq!(
        db.registry_by_slug("acme/infra/prod/cdn")
            .await
            .unwrap()
            .unwrap()
            .visibility,
        "public"
    );
}

#[tokio::test]
async fn revert_flags_conflict_when_object_diverged() {
    let db = Database::open_in_memory().await.unwrap();
    let id = managed_registry(&db, "public").await;
    let actor = Principal::user(7);

    let change_id = update_registry_visibility(&db, id, "private", 7).await;

    // Someone changes the registry out-of-band after the change-set applied.
    update_registry_visibility(&db, id, "internal", 7).await;

    let draft = config::revert(&db, &change_id, &actor, "alice@acme.com", |t, oid| {
        let is_registry = t == "registry";
        let oid = oid.to_string();
        let db = &db;
        async move {
            if is_registry {
                db.registry_by_id(id)
                    .await
                    .ok()
                    .flatten()
                    .filter(|registry| registry.stable_id == oid)
                    .map(|registry| {
                        serde_json::json!({
                            "stableId": registry.stable_id,
                            "slug": registry.slug,
                            "visibility": registry.visibility,
                            "crawlPolicy": registry.crawl_policy,
                            "llmsTxtBody": registry.llms_txt_body,
                            "trustKeys": registry.trust_keys,
                            "resourceVersion": registry.resource_version,
                        })
                    })
            } else {
                None
            }
        }
    })
    .await
    .unwrap();
    // Live state ("internal") != original new_json ("private") -> conflict.
    assert_eq!(draft.conflicts.len(), 1);
    assert!(draft.conflicts[0].contains("registry"));
}

// -- security-object exemptions ---------------------------------------------

#[tokio::test]
async fn token_revert_renders_as_issue_replacement_not_a_live_token() {
    let db = Database::open_in_memory().await.unwrap();
    let actor = Principal::user(7);

    // Stage a change-set that "revoked" a token (a delete revision).
    let change_id = config::open_draft(
        &db,
        &actor,
        "alice@acme.com",
        &Scope::parse("instance"),
        "revoke ci token",
    )
    .await
    .unwrap();
    config::stage(
        &db,
        &change_id,
        "token",
        "tok-123",
        ConfigOp::Delete,
        Some(serde_json::json!({"id": "tok-123", "scope": "instance"})),
        None,
    )
    .await
    .unwrap();
    config::apply(
        &db,
        &change_id,
        "token.revoke",
        |_rev| async move { Ok(()) },
    )
    .await
    .unwrap();

    let draft = config::revert(
        &db,
        &change_id,
        &actor,
        "alice@acme.com",
        |_, _| async move { None },
    )
    .await
    .unwrap();
    let revisions = config::review(&db, &draft.change_id).await.unwrap();
    assert_eq!(revisions.len(), 1);
    let (rev, _) = &revisions[0];
    // The revert is a no-op create carrying an issue-replacement note, never
    // a resurrected credential.
    assert_eq!(rev.object_type, "token");
    assert_eq!(rev.op, ConfigOp::Create);
    let note = rev.new_json.as_ref().unwrap();
    assert_eq!(note["note"], "issue replacement token");
    assert!(note.get("secret").is_none(), "no secret in revision");
}

#[tokio::test]
async fn membership_revoke_revert_produces_invitation_not_silent_regrant() {
    let db = Database::open_in_memory().await.unwrap();
    let actor_id = db.create_user("actor@acme.test", None).await.unwrap();
    let member_id = db.create_user("member@acme.test", None).await.unwrap();
    let actor = Principal::user(actor_id);
    let member = Principal::user(member_id);
    let org = db.create_org("acme", "Acme").await.unwrap();
    let scope_key = db.org_by_id(org).await.unwrap().unwrap().stable_id;
    let scope = Scope::parse(&scope_key);
    // The actor must hold authority over the scope to grant: the engine's
    // privilege ceiling (H1) rejects a grant exceeding the actor's own rank.
    db.grant_membership("user", actor_id, &scope_key, "owner")
        .await
        .unwrap();

    // Grant, then revoke through the engine (so the revoke records old_json).
    config::change_membership(
        &db,
        &actor,
        "alice@acme.com",
        MembershipChange::Grant,
        &member,
        &scope,
        Role::Developer,
    )
    .await
    .unwrap();
    let revoke_id = config::change_membership(
        &db,
        &actor,
        "alice@acme.com",
        MembershipChange::Revoke,
        &member,
        &scope,
        Role::Developer,
    )
    .await
    .unwrap();
    // The grant is gone after the revoke.
    assert!(db
        .list_memberships_for("user", member_id)
        .await
        .unwrap()
        .is_empty());

    // Revert the revoke: it must NOT silently re-grant; it produces an
    // invitation revision instead.
    let draft = config::revert(
        &db,
        &revoke_id,
        &actor,
        "alice@acme.com",
        |_, _| async move { None },
    )
    .await
    .unwrap();
    let revisions = config::review(&db, &draft.change_id).await.unwrap();
    assert_eq!(revisions.len(), 1);
    let (rev, _) = &revisions[0];
    assert_eq!(rev.object_type, "invitation");
    assert_eq!(rev.op, ConfigOp::Create);
    let invite = rev.new_json.as_ref().unwrap();
    assert_eq!(invite["role"], "developer");

    // Applying the revert (records-only for invitation) leaves no live grant.
    config::apply(
        &db,
        &draft.change_id,
        "changeset.revert",
        |_rev| async move { Ok(()) },
    )
    .await
    .unwrap();
    assert!(db
        .list_memberships_for("user", member_id)
        .await
        .unwrap()
        .is_empty());
}

// -- RPC: ListAudit / GetChangeset ------------------------------------------

#[tokio::test]
async fn rpc_audit_and_config_authorized_and_rejected() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let id = managed_registry(&db, "public").await;
    // A user with Owner on the org, so its live memberships cover both
    // audit.read and registry.configure (require_permission intersects the
    // JWT grant with current memberships).
    let user = db.create_user("alice@acme.com", None).await.unwrap();
    db.grant_membership(
        "user",
        user,
        &common::org_scope(&db, "acme").await,
        Role::Owner.as_str(),
    )
    .await
    .unwrap();
    let actor = Principal::user(user);
    // Produce a real change-set + audit row by flipping visibility.
    let change_id = update_registry_visibility(&db, id, "private", user).await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    let scope = db.registry_authorization_scope(id).await.unwrap();
    let audit_token = bearer(actor, &scope, &[Permission::AuditRead]);

    // ListAudit (authorized): surfaces the entry.
    let (status, value) = rpc(
        &app,
        "AuditService/ListAudit",
        serde_json::json!({"scope": scope}),
        Some(&audit_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(
        value["entries"][0]["action"],
        "registry.configuration.updated"
    );
    assert_eq!(value["entries"][0]["changeId"], change_id.as_str());

    // ListAudit (unauthorized: only Read, not AuditRead): denied.
    let weak = bearer(actor, &scope, &[Permission::Read]);
    let (status, _) = rpc(
        &app,
        "AuditService/ListAudit",
        serde_json::json!({"scope": scope}),
        Some(&weak),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // ListAudit (unauthenticated): 401.
    let (status, _) = rpc(
        &app,
        "AuditService/ListAudit",
        serde_json::json!({"scope": scope}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // GetChangeset (authorized via audit.read): returns revisions + diffs.
    let (status, value) = rpc(
        &app,
        "RegistryConfigurationService/GetChangeset",
        serde_json::json!({"changeId": change_id.as_str()}),
        Some(&audit_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["changeset"]["status"], "applied");
    assert_eq!(value["revisions"][0]["objectType"], "registry");
    let visibility = value["revisions"][0]["diffs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diff| diff["field"] == "visibility")
        .unwrap();
    assert_eq!(visibility["new"], "private");
}
