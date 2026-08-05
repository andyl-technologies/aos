//! Tenancy read and topology-write authorization for the `aos.hub.v1` RPCs.
//!
//! Drives the real axum router with Connect-JSON `POST`s, with and without a
//! bearer JWT, to prove the read-path services do not disclose another tenant's
//! data to a caller who could not open the corresponding browse page:
//!
//! - **H-2** — `ListPackages`/`GetPackage`/`ListChannels`/`GetChannel`/`GetRegistry`
//!   gate non-public registries through `require_read`, so an anonymous read of a
//!   `private`/`internal` registry is denied (and its data never returned) while a
//!   `public` registry still reads anonymously. `ListRegistries` visibility-filters
//!   its page (dropping records the caller may not read, not erroring the call).
//! - **H-3** — `ListProjects`/`ListBindings`/`ListOrgs` require an authenticated
//!   member; an anonymous caller is denied/empty, a member sees their org's data,
//!   and a binding's `root` host path is redacted from a non-admin member.

mod common;

use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{
    ChannelSummary, Database, DeliveryEndpointHostInput, DeliveryEndpointRevisionSpec,
    DeliveryRouteSpec, IndexSnapshot, NewStorageBindingWriteRevision, NewSurfacePlacementSpec,
    SurfaceTarget, TokenAuth,
};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sha2::{Digest as _, Sha256};
use tower::ServiceExt;

/// Deterministic HS256 key so tests can mint matching JWTs.
const TEST_JWT_SECRET: &[u8] = b"tenancy-test-secret-32byte-key!!";

/// Build an [`AppState`] over `db` with deterministic JWT keys.
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
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        route_reservation_keyring: None,
    })
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

/// Seed one package and one channel into `registry_id` so a successful read
/// returns observable data (and a denied read can be proven to return none).
async fn seed_inventory(db: &Database, registry_id: i64) {
    let package: aos_package::registry::parse::PackageToml = toml::from_str(
        r#"
        [package]
        name = "curl"
        description = "URL transfers"
        license = "MIT"
        maintainer = "aos"
        [[versions]]
        version = "8.5.0"
        [versions.platforms.x86_64-linux]
        store_path = "/var/lib/store/secret-curl-8.5.0"
        nar_hash = "sha256:aa"
        nar_size = 10
        closure_size = 20
        source_drv = "/var/lib/store/secret-curl-8.5.0.drv"
        source_nar_hash = "sha256:bb"
        "#,
    )
    .unwrap();
    let snapshot = IndexSnapshot {
        commit: "c".repeat(64),
        name: "secret".into(),
        description: None,
        readme: None,
        caches: Vec::new(),
        roster: Vec::new(),
        packages: vec![package],
        releases: Vec::new(),
        release_artifact_snapshots: Vec::new(),
        release_images: Vec::new(),
        channels: vec![ChannelSummary {
            name: "stable".into(),
            frontier: Some("8.5.0".into()),
            partitions: vec![Some("8.5.0".into()); 256],
        }],
        refs_digest: None,
        cache_stack: None,
    };
    db.apply_snapshot(registry_id, &snapshot).await.unwrap();
}

/// Connect maps `PermissionDenied`/`Unauthenticated` to 403/401 and `NotFound`
/// to 404 — any of these is a valid "denied" outcome for a hidden registry.
fn is_denied(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED
    )
}

/// Creates one ready complete placement for a registry or binary cache.
async fn seed_placement(
    db: &Database,
    surface: SurfaceTarget,
    binding_id: i64,
    name: &str,
    prefix: &str,
) {
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface,
            name: name.to_string(),
            storage_binding_id: binding_id,
            prefix: prefix.to_string(),
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
}

// -- H-2: package / channel / registry read gating --------------------------

#[tokio::test]
async fn private_registry_inventory_is_denied_to_anonymous() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("victim", "Victim").await.unwrap();
    db.create_project(org, "internal", "Internal")
        .await
        .unwrap();
    let binding = common::create_local_binding(&db, org, "b", "/var/lib/aos/storage/victim").await;
    let id = db
        .create_managed_registry(org, "internal", "secret", "private", &[], false)
        .await
        .unwrap();
    seed_inventory(&db, id).await;
    let slug = db.registry_by_id(id).await.unwrap().unwrap().slug;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Every package/channel/registry read of the private registry is denied,
    // and no inventory leaks in the body.
    for (method, extra) in [
        ("PackageService/ListPackages", serde_json::Map::new()),
        ("ChannelService/ListChannels", serde_json::Map::new()),
        ("RegistryService/GetRegistry", serde_json::Map::new()),
    ] {
        let mut body = serde_json::Map::new();
        body.insert("slug".into(), slug.clone().into());
        body.extend(extra);
        let (status, resp) = rpc(&app, method, serde_json::Value::Object(body), None).await;
        assert!(
            is_denied(status),
            "{method} anon must be denied, got {status}"
        );
        let text = resp.to_string();
        assert!(
            !text.contains("curl") && !text.contains("secret-curl"),
            "{method} must not leak inventory: {text}"
        );
    }

    let (status, resp) = rpc(
        &app,
        "PackageService/GetPackage",
        serde_json::json!({ "slug": slug, "name": "curl" }),
        None,
    )
    .await;
    assert!(is_denied(status), "GetPackage anon denied, got {status}");
    assert!(
        !resp.to_string().contains("/var/lib/store/secret"),
        "GetPackage must not leak a store path: {resp}"
    );

    let (status, _resp) = rpc(
        &app,
        "ChannelService/GetChannel",
        serde_json::json!({ "slug": slug, "name": "stable" }),
        None,
    )
    .await;
    assert!(is_denied(status), "GetChannel anon denied, got {status}");

    // A member with Read on the registry's org scope CAN read it.
    let member_id = db.create_user("member@victim.test", None).await.unwrap();
    let victim_scope = common::org_scope(&db, "victim").await;
    db.grant_membership("user", member_id, &victim_scope, "viewer")
        .await
        .unwrap();
    let member = bearer(
        Principal::user(member_id),
        &victim_scope,
        &[Permission::Read],
    );
    let (status, resp) = rpc(
        &app,
        "PackageService/ListPackages",
        serde_json::json!({ "slug": slug }),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member read: {resp}");
    assert_eq!(resp["packages"][0]["name"], "curl");
}

#[tokio::test]
async fn public_registry_inventory_reads_anonymously() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let id = db
        .create_managed_registry(org, "", "cdn", "public", &[], false)
        .await
        .unwrap();
    seed_inventory(&db, id).await;
    let slug = db.registry_by_id(id).await.unwrap().unwrap().slug;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous public reads still work and return the data.
    let (status, resp) = rpc(
        &app,
        "PackageService/ListPackages",
        serde_json::json!({ "slug": slug }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "anon public ListPackages: {resp}");
    assert_eq!(resp["packages"][0]["name"], "curl");

    let (status, resp) = rpc(
        &app,
        "ChannelService/ListChannels",
        serde_json::json!({ "slug": slug }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "anon public ListChannels: {resp}");
    assert_eq!(resp["channels"][0]["name"], "stable");

    let (status, resp) = rpc(
        &app,
        "RegistryService/GetRegistry",
        serde_json::json!({ "slug": slug }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "anon public GetRegistry: {resp}");
}

#[tokio::test]
async fn topology_placements_use_typed_camel_case_refs_and_surface_read_auth() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("topology", "Topology").await.unwrap();
    let binding = common::create_local_binding(&db, org, "origin", "/var/lib/aos/topology").await;
    let public_registry = db
        .create_managed_registry(org, "", "public", "public", &[], false)
        .await
        .unwrap();
    let private_registry = db
        .create_managed_registry(org, "", "private", "private", &[], false)
        .await
        .unwrap();
    seed_placement(
        &db,
        SurfaceTarget::Registry(public_registry),
        binding,
        "primary",
        "registry/public",
    )
    .await;
    seed_placement(
        &db,
        SurfaceTarget::Registry(private_registry),
        binding,
        "primary",
        "registry/private",
    )
    .await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    let (status, resp) = rpc(
        &app,
        "TopologyService/ListPlacements",
        serde_json::json!({ "surface": { "registrySlug": "topology/public" } }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "public placement list: {resp}");
    let placement = &resp["placements"][0];
    assert_eq!(placement["name"], "primary");
    assert_eq!(placement["storageBindingName"], "origin");
    assert_eq!(placement["spec"]["kind"], "complete");
    assert_eq!(placement["spec"]["desiredState"], "active");
    assert_eq!(placement["spec"]["desiredReadEnabled"], true);
    assert_eq!(placement["observation"]["state"], "ready");
    assert_eq!(placement["observation"]["completeness"], "complete");
    assert_eq!(placement["status"]["derivedRole"], "replica");
    assert_eq!(placement["status"]["effectiveReadEnabled"], true);
    assert_eq!(placement["status"]["effectiveWriteEnabled"], false);
    assert!(placement["resourceVersion"].is_string());
    assert!(placement.get("id").is_none());
    assert!(placement.get("storageBindingId").is_none());
    assert!(placement.get("partitionRuleJson").is_none());

    let (status, _) = rpc(
        &app,
        "TopologyService/GetPlacement",
        serde_json::json!({
            "surface": { "registrySlug": "topology/public" },
            "name": "missing"
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = rpc(
        &app,
        "TopologyService/GetPlacement",
        serde_json::json!({
            "surface": { "registrySlug": "topology/private" },
            "name": "primary"
        }),
        None,
    )
    .await;
    assert!(
        is_denied(status),
        "anonymous private placement read: {status}"
    );

    let member_id = db.create_user("member@topology.test", None).await.unwrap();
    let topology_scope = common::org_scope(&db, "topology").await;
    db.grant_membership("user", member_id, &topology_scope, "viewer")
        .await
        .unwrap();
    let member = bearer(
        Principal::user(member_id),
        &topology_scope,
        &[Permission::Read],
    );
    let (status, resp) = rpc(
        &app,
        "TopologyService/GetPlacement",
        serde_json::json!({
            "surface": { "registrySlug": "topology/private" },
            "name": "primary"
        }),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member placement read: {resp}");
    assert_eq!(resp["placement"]["prefix"], "registry/private");

    let authority_request = serde_json::json!({
        "surface": { "registrySlug": "topology/public" }
    });
    let (status, _) = rpc(
        &app,
        "TopologyService/GetWriteAuthority",
        authority_request.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = rpc(
        &app,
        "TopologyService/GetWriteAuthority",
        authority_request,
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn topology_placement_mutations_enforce_tenancy_cas_and_plan_apply() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db
        .create_org("placement-owner", "Placement Owner")
        .await
        .unwrap();
    let other_org = db
        .create_org("placement-other", "Placement Other")
        .await
        .unwrap();
    let binding = common::create_local_binding(&db, org, "origin", "/var/lib/aos/placements").await;
    let registry = db
        .create_managed_registry(org, "", "private", "private", &[], false)
        .await
        .unwrap();
    db.create_binary_cache(
        Some(org),
        "private-cache-write",
        "Private cache write target",
        "private",
        40,
        "zstd",
        true,
    )
    .await
    .unwrap();
    seed_placement(
        &db,
        SurfaceTarget::Registry(registry),
        binding,
        "primary",
        "registry/private",
    )
    .await;
    let owner_scope = common::org_scope(&db, "placement-owner").await;
    let other_scope = common::org_scope(&db, "placement-other").await;
    let owner_admin_id = db.create_user("admin@placement.test", None).await.unwrap();
    db.grant_membership("user", owner_admin_id, &owner_scope, "admin")
        .await
        .unwrap();
    let owner_admin = bearer(
        Principal::user(owner_admin_id),
        &owner_scope,
        &[Permission::Read, Permission::StorageManage],
    );
    let wrong_org_id = db
        .create_user("admin@other-placement.test", None)
        .await
        .unwrap();
    db.grant_membership("user", wrong_org_id, &other_scope, "admin")
        .await
        .unwrap();
    let wrong_org = bearer(
        Principal::user(wrong_org_id),
        &other_scope,
        &[Permission::StorageManage],
    );
    let viewer_id = db.create_user("viewer@placement.test", None).await.unwrap();
    db.grant_membership("user", viewer_id, &owner_scope, "viewer")
        .await
        .unwrap();
    let viewer = bearer(
        Principal::user(viewer_id),
        &owner_scope,
        &[Permission::Read],
    );
    let controller_id = db
        .create_service_account(org, "topology-controller")
        .await
        .unwrap();
    db.grant_membership("service_account", controller_id, &owner_scope, "admin")
        .await
        .unwrap();
    let controller = bearer(
        Principal::service_account(controller_id),
        &owner_scope,
        &[Permission::StorageManage, Permission::TopologyReconcile],
    );
    let write_generation =
        common::create_valid_write_credential(&db, binding, "secret://placement-owner/origin/v1")
            .await;
    let binding_revision = db
        .create_storage_binding_write_revision(&NewStorageBindingWriteRevision {
            storage_binding_id: binding,
            write_credential_generation: write_generation,
            writes_supported: true,
            conditional_writes_supported: true,
            revision_fingerprint: "placement-owner-origin-v1".to_string(),
            capability_fingerprint: "object-write-v1".to_string(),
        })
        .await
        .unwrap();
    db.observe_storage_binding_write_revision(
        binding,
        binding_revision.revision,
        "valid",
        None,
        None,
    )
    .await
    .unwrap();
    let binding_state = db
        .storage_binding_write_state(binding)
        .await
        .unwrap()
        .unwrap();
    db.set_current_storage_binding_write_revision(
        binding,
        binding_revision.revision,
        binding_state.resource_version,
    )
    .await
    .unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    let no_writes_generation =
        common::create_valid_write_credential(&db, binding, "secret://placement-owner/origin/v2")
            .await;
    let no_writes = db
        .create_storage_binding_write_revision(&NewStorageBindingWriteRevision {
            storage_binding_id: binding,
            write_credential_generation: no_writes_generation,
            writes_supported: false,
            conditional_writes_supported: false,
            revision_fingerprint: "placement-owner-origin-no-writes".to_string(),
            capability_fingerprint: "read-only".to_string(),
        })
        .await
        .unwrap();
    db.observe_storage_binding_write_revision(binding, no_writes.revision, "valid", None, None)
        .await
        .unwrap();
    let write_state = db
        .storage_binding_write_state(binding)
        .await
        .unwrap()
        .unwrap();
    let write_state = db
        .set_current_storage_binding_write_revision(
            binding,
            no_writes.revision,
            write_state.resource_version,
        )
        .await
        .unwrap();
    let (status, resp) = rpc(
        &app,
        "TopologyService/PlanPromotePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "candidatePlacementName": "primary"
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "no writes: {resp}");

    let ordinary_generation =
        common::create_valid_write_credential(&db, binding, "secret://placement-owner/origin/v3")
            .await;
    let ordinary_only = db
        .create_storage_binding_write_revision(&NewStorageBindingWriteRevision {
            storage_binding_id: binding,
            write_credential_generation: ordinary_generation,
            writes_supported: true,
            conditional_writes_supported: false,
            revision_fingerprint: "placement-owner-origin-ordinary".to_string(),
            capability_fingerprint: "ordinary-writes".to_string(),
        })
        .await
        .unwrap();
    db.observe_storage_binding_write_revision(binding, ordinary_only.revision, "valid", None, None)
        .await
        .unwrap();
    let write_state = db
        .set_current_storage_binding_write_revision(
            binding,
            ordinary_only.revision,
            write_state.resource_version,
        )
        .await
        .unwrap();
    let conditional = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry),
            name: "conditional".to_string(),
            storage_binding_id: binding,
            prefix: "registry/conditional".to_string(),
            kind: "complete".to_string(),
            desired_state: "active".to_string(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 30,
            requires_conditional_writes: true,
        })
        .await
        .unwrap();
    db.observe_surface_placement(conditional.id, "ready", "complete", 1)
        .await
        .unwrap();
    let (status, resp) = rpc(
        &app,
        "TopologyService/PlanPromotePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "candidatePlacementName": "conditional"
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PRECONDITION_FAILED,
        "conditional writes: {resp}"
    );
    db.set_current_storage_binding_write_revision(
        binding,
        binding_revision.revision,
        write_state.resource_version,
    )
    .await
    .unwrap();

    let (status, resp) = rpc(
        &app,
        "TopologyService/PlanPromotePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "candidatePlacementName": "primary"
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "plan initial authority: {resp}");
    assert_eq!(resp["plan"]["createsInitialAuthority"], true);
    let initial_plan_id = resp["plan"]["planId"].as_str().unwrap();
    let (status, resp) = rpc(
        &app,
        "TopologyService/PromotePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "planId": initial_plan_id
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create initial authority: {resp}");
    assert_eq!(resp["authority"]["desiredPlacementName"], "primary");
    assert_eq!(resp["authority"]["observedPlacementName"], "primary");
    assert_eq!(resp["authority"]["reconciliationState"], "ready");

    let create = serde_json::json!({
        "surface": { "registrySlug": "placement-owner/private" },
        "name": "replica-west",
        "storageBindingName": "origin",
        "prefix": "registry/private-west",
        "kind": "complete",
        "desiredState": "active",
        "desiredReadEnabled": true,
        "readOrder": 20,
        "requiresConditionalWrites": false
    });
    let (status, _) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        create.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        create.clone(),
        Some(&viewer),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        create.clone(),
        Some(&wrong_org),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, resp) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        create.clone(),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create placement: {resp}");
    let created = &resp["placement"];
    assert_eq!(created["storageBindingName"], "origin");
    assert_eq!(created["spec"]["kind"], "complete");
    assert_eq!(created["spec"]["desiredState"], "active");
    assert_eq!(created["spec"]["desiredReadEnabled"], true);
    assert_eq!(created["status"]["effectiveReadEnabled"], false);
    assert_eq!(created["status"]["effectiveWriteEnabled"], false);
    assert_eq!(created["observation"]["state"], "provisioning");
    assert_eq!(created["observation"]["completeness"], "unknown");
    assert!(created.get("id").is_none());
    assert!(created.get("storageBindingId").is_none());
    assert!(created.get("partitionRuleJson").is_none());
    let version = created["resourceVersion"].as_str().unwrap().to_string();

    let (status, resp) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        create,
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate name: {resp}");

    let (status, resp) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "same-location",
            "storageBindingName": "origin",
            "prefix": "registry/private-west",
            "kind": "complete",
            "desiredState": "active",
            "desiredReadEnabled": true,
            "readOrder": 20,
            "requiresConditionalWrites": false
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PRECONDITION_FAILED,
        "physical-location conflict: {resp}"
    );

    let (status, resp) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        serde_json::json!({
            "surface": { "cacheSlug": "private-cache-write" },
            "name": "cache-replica",
            "storageBindingName": "origin",
            "prefix": "cache/private-replica",
            "kind": "complete",
            "desiredState": "active",
            "desiredReadEnabled": true,
            "readOrder": 20,
            "requiresConditionalWrites": false
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "private cache placement: {resp}");
    assert_eq!(resp["placement"]["name"], "cache-replica");

    let (status, resp) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "cold-archive",
            "storageBindingName": "origin",
            "prefix": "registry/cold-archive",
            "kind": "archive",
            "desiredState": "active",
            "desiredReadEnabled": false,
            "readOrder": 100,
            "requiresConditionalWrites": false
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create archive: {resp}");
    let archive_version = resp["placement"]["resourceVersion"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, resp) = rpc(
        &app,
        "TopologyService/UpdatePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "cold-archive",
            "expectedResourceVersion": archive_version,
            "desiredState": "active",
            "desiredReadEnabled": true,
            "readOrder": 100
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "archive read enable must be a stable client error, never 500: {resp}"
    );
    assert_eq!(resp["message"], "archive placements cannot be read-enabled");

    let update = |expected: &str| {
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "replica-west",
            "expectedResourceVersion": expected,
            "desiredState": "active",
            "desiredReadEnabled": true,
            "readOrder": 30
        })
    };
    let (status, resp) = rpc(
        &app,
        "TopologyService/UpdatePlacement",
        update("999999"),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "stale CAS: {resp}");

    let (status, resp) = rpc(
        &app,
        "TopologyService/UpdatePlacement",
        update(&version),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "update placement: {resp}");
    assert_eq!(resp["placement"]["spec"]["desiredState"], "active");
    assert_eq!(resp["placement"]["spec"]["readOrder"], 30);
    assert_eq!(resp["placement"]["observation"]["state"], "provisioning");
    assert_eq!(resp["placement"]["observation"]["completeness"], "unknown");
    // Simulate the scanner recording readiness; observed lifecycle fields are
    // intentionally not client-settable through UpdatePlacement.
    let current = db
        .list_surface_placements(SurfaceTarget::Registry(registry))
        .await
        .unwrap()
        .into_iter()
        .find(|placement| placement.name == "replica-west")
        .unwrap();
    let observed = db
        .observe_surface_placement(current.id, "ready", "complete", 1)
        .await
        .unwrap();
    let updated_version = observed.resource_version.to_string();

    let (status, resp) = rpc(
        &app,
        "TopologyService/PlanPromotePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "candidatePlacementName": "replica-west"
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "plan promotion: {resp}");
    assert_eq!(resp["plan"]["createsInitialAuthority"], false);
    assert_eq!(resp["plan"]["observedPlacementName"], "primary");
    let promotion_plan_id = resp["plan"]["planId"].as_str().unwrap();
    let (status, resp) = rpc(
        &app,
        "TopologyService/PromotePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "planId": promotion_plan_id
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "apply promotion: {resp}");
    assert_eq!(resp["authority"]["desiredPlacementName"], "replica-west");
    assert_eq!(resp["authority"]["observedPlacementName"], "primary");
    assert_eq!(resp["authority"]["reconciliationState"], "pending");
    let promoted_incarnation = resp["authority"]["incarnationId"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, replay) = rpc(
        &app,
        "TopologyService/PromotePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "planId": promotion_plan_id
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "replay promotion: {replay}");
    assert_eq!(replay["authority"]["incarnationId"], promoted_incarnation);
    assert_eq!(
        replay["authority"]["desiredGeneration"],
        resp["authority"]["desiredGeneration"]
    );
    let authority_version = resp["authority"]["resourceVersion"]
        .as_str()
        .unwrap()
        .to_string();
    let desired_generation = resp["authority"]["desiredGeneration"].as_i64().unwrap();
    let reconciliation = serde_json::json!({
        "surface": { "registrySlug": "placement-owner/private" },
        "expectedResourceVersion": authority_version.clone(),
        "desiredGeneration": desired_generation,
        "state": "ready"
    });
    for error in ["   ".to_string(), "x".repeat(4097)] {
        let (status, resp) = rpc(
            &app,
            "TopologyService/ReconcileWriteAuthority",
            serde_json::json!({
                "surface": { "registrySlug": "placement-owner/private" },
                "expectedResourceVersion": authority_version.clone(),
                "desiredGeneration": desired_generation,
                "state": "failed",
                "error": error
            }),
            Some(&controller),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "invalid controller diagnostic: {resp}"
        );
    }
    let (status, resp) = rpc(
        &app,
        "TopologyService/ReconcileWriteAuthority",
        reconciliation.clone(),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "human admin must not assert controller evidence: {resp}"
    );
    let (status, resp) = rpc(
        &app,
        "TopologyService/ReconcileWriteAuthority",
        reconciliation.clone(),
        Some(&controller),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reconcile promotion: {resp}");
    assert_eq!(resp["authority"]["observedPlacementName"], "replica-west");
    assert_eq!(resp["authority"]["reconciliationState"], "ready");
    let (status, resp) = rpc(
        &app,
        "TopologyService/ReconcileWriteAuthority",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "expectedResourceVersion": authority_version,
            "desiredGeneration": desired_generation,
            "state": "ready"
        }),
        Some(&controller),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "retry reconciliation: {resp}");
    assert_eq!(resp["authority"]["reconciliationState"], "ready");

    let (status, resp) = rpc(
        &app,
        "TopologyService/PlanRemoveWriteAuthority",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" }
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "plan read-only transition: {resp}");
    let read_only_plan_id = resp["plan"]["planId"].as_str().unwrap();
    let (status, resp) = rpc(
        &app,
        "TopologyService/RemoveWriteAuthority",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "planId": read_only_plan_id
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "apply read-only transition: {resp}");
    assert_eq!(resp["removed"], true);
    let (status, resp) = rpc(
        &app,
        "TopologyService/RemoveWriteAuthority",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "planId": read_only_plan_id
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "replay read-only transition: {resp}"
    );
    assert_eq!(resp["removed"], true);
    let (status, resp) = rpc(
        &app,
        "TopologyService/GetWriteAuthority",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" }
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get read-only authority: {resp}");
    assert!(resp["authority"].is_null());

    db.create_delivery_endpoint(
        "endpoint:placement-route-test",
        &owner_scope,
        Some(org),
        "https",
        &DeliveryEndpointHostInput::Ipv4([192, 0, 2, 44]),
        443,
        "instance:public",
        &DeliveryEndpointRevisionSpec {
            boundary_revision: 1,
            ingress_kind: "hub".into(),
            listener_configuration: "listener:placement-route-test".into(),
            tls_configuration: "{\"certificate_ref\":\"secret:test\",\"provider\":\"external\",\"require_client_certificate\":false}".into(),
            probe_configuration: "{\"provider\":\"native_file\",\"signerSecretRef\":\"test-probe-key\",\"publicKey\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}".into(),
        },
        None,
        "test",
        "request:placement-route-endpoint",
    )
        .await
        .unwrap();
    let access_policy_json = "{}".to_string();
    let route = db
        .create_delivery_route(
            "route:placement-pin-test",
            SurfaceTarget::Registry(registry),
            &DeliveryRouteSpec {
                consumer_scope_key: owner_scope.clone(),
                endpoint_id: "endpoint:placement-route-test".into(),
                endpoint_generation: 1,
                endpoint_ingress_kind: "hub".into(),
                base_path: "/replica".into(),
                mode: "hub_proxy".into(),
                access_policy_kind: "public".into(),
                access_policy_digest: hex::encode(Sha256::digest(access_policy_json.as_bytes())),
                access_policy_json,
                access_boundary_id: None,
                access_boundary_revision: None,
                external_provider_kind: None,
                external_provider_resource_id: None,
                external_provider_revision: None,
                storage_gateway_id: None,
                gateway_generation: None,
                target_storage_binding_id: None,
                gateway_client_base_path: None,
                target_placement_prefix: None,
                placement_id: Some(observed.id),
                placement_policy_revision_id: None,
                serves_git: true,
                serves_cache: false,
                serves_web: false,
                enabled: false,
            },
            "https://192.0.2.44/replica",
            1,
            &[7_u8; 32],
            &[(1, vec![7_u8; 32])],
            None,
            "test",
        )
        .await
        .unwrap();

    let (status, resp) = rpc(
        &app,
        "TopologyService/DrainPlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "replica-west",
            "expectedResourceVersion": updated_version.clone(),
            "apply": false
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PRECONDITION_FAILED,
        "route-pinned drain: {resp}"
    );
    assert_eq!(
        resp["message"],
        "placement is pinned by a direct delivery route"
    );
    assert!(db
        .delete_delivery_route(&route.id, route.resource_version, "user", None, "test")
        .await
        .unwrap());

    let drain = |apply: bool, expected: &str| {
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "replica-west",
            "expectedResourceVersion": expected,
            "apply": apply
        })
    };
    let (status, resp) = rpc(
        &app,
        "TopologyService/DrainPlacement",
        drain(false, &updated_version),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "drain plan: {resp}");
    assert_eq!(resp["applied"], false);
    assert_eq!(resp["placement"]["observation"]["state"], "ready");
    assert_eq!(resp["plan"]["currentResourceVersion"], updated_version);

    let (status, resp) = rpc(
        &app,
        "TopologyService/DrainPlacement",
        drain(true, &updated_version),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "drain apply: {resp}");
    assert_eq!(resp["applied"], true);
    assert_eq!(resp["placement"]["spec"]["desiredState"], "draining");
    assert_eq!(resp["placement"]["spec"]["desiredReadEnabled"], false);
    let drained_version = resp["placement"]["resourceVersion"]
        .as_str()
        .unwrap()
        .to_string();

    let delete = |apply: bool| {
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "replica-west",
            "expectedResourceVersion": drained_version.clone(),
            "apply": apply
        })
    };
    let (status, resp) = rpc(
        &app,
        "TopologyService/DeletePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "replica-west",
            "expectedResourceVersion": "1",
            "apply": false
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PRECONDITION_FAILED,
        "stale delete CAS: {resp}"
    );
    let (status, resp) = rpc(
        &app,
        "TopologyService/DeletePlacement",
        delete(false),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "delete plan: {resp}");
    assert_eq!(resp["applied"], false);
    assert!(resp["plan"]["effects"]
        .as_array()
        .unwrap()
        .iter()
        .any(|effect| effect.as_str() == Some("leave backing storage objects unchanged")));

    let (status, resp) = rpc(
        &app,
        "TopologyService/DeletePlacement",
        delete(true),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "delete apply: {resp}");
    assert_eq!(resp["applied"], true);

    let (status, _) = rpc(
        &app,
        "TopologyService/GetPlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "replica-west"
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let shard = serde_json::json!({
        "surface": { "registrySlug": "placement-owner/private" },
        "name": "shard-a",
        "storageBindingName": "origin",
        "prefix": "registry/shard-a",
        "kind": "shard",
        "desiredState": "active",
        "desiredReadEnabled": true,
        "readOrder": 40,
        "requiresConditionalWrites": false
    });
    let (status, resp) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        shard,
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        resp["message"],
        "shard placements require a non-empty 16-bit hashRange"
    );

    let (status, resp) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "shard-invalid-range",
            "storageBindingName": "origin",
            "prefix": "registry/shard-invalid-range",
            "kind": "shard",
            "desiredState": "active",
            "desiredReadEnabled": true,
            "readOrder": 40,
            "hashRange": { "start": 4096, "end": 4096 },
            "requiresConditionalWrites": false
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        resp["message"],
        "shard placements require a non-empty 16-bit hashRange"
    );

    let (status, resp) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "shard-valid-range",
            "storageBindingName": "origin",
            "prefix": "registry/shard-valid-range",
            "kind": "shard",
            "desiredState": "active",
            "desiredReadEnabled": true,
            "readOrder": 40,
            "hashRange": { "start": 0, "end": 32768 },
            "requiresConditionalWrites": false
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create typed shard: {resp}");
    assert_eq!(resp["placement"]["spec"]["kind"], "shard");
    assert_eq!(resp["placement"]["spec"]["hashRange"]["start"], 0);
    assert_eq!(resp["placement"]["spec"]["hashRange"]["end"], 32768);

    let (status, _) = rpc(
        &app,
        "TopologyService/CreatePlacement",
        serde_json::json!({
            "surface": { "registrySlug": "placement-owner/private" },
            "name": "missing-read-flag",
            "storageBindingName": "origin",
            "prefix": "registry/missing-read-flag",
            "kind": "complete",
            "desiredState": "active",
            "readOrder": 50,
            "requiresConditionalWrites": false
        }),
        Some(&owner_admin),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Keep the second org observably in scope so the wrong-org membership is
    // not an accidental grant on a missing tenant.
    assert!(db.org_by_id(other_org).await.unwrap().is_some());
}

#[tokio::test]
async fn topology_cache_placements_enforce_visibility_and_org_tenancy() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("cache-owner", "Cache Owner").await.unwrap();
    let other_org = db.create_org("other-org", "Other Org").await.unwrap();
    let binding =
        common::create_local_binding(&db, org, "cache-origin", "/var/lib/aos/caches").await;
    let public_cache = db
        .create_binary_cache(
            Some(org),
            "public-cache",
            "Public cache",
            "public",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
    let private_cache = db
        .create_binary_cache(
            Some(org),
            "private-cache",
            "Private cache",
            "private",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
    seed_placement(
        &db,
        SurfaceTarget::BinaryCache(public_cache),
        binding,
        "primary",
        "cache/public",
    )
    .await;
    seed_placement(
        &db,
        SurfaceTarget::BinaryCache(private_cache),
        binding,
        "primary",
        "cache/private",
    )
    .await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    let (status, resp) = rpc(
        &app,
        "TopologyService/ListPlacements",
        serde_json::json!({ "surface": { "cacheSlug": "public-cache" } }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "public cache placements: {resp}");
    assert_eq!(resp["placements"][0]["prefix"], "cache/public");

    let private_request = serde_json::json!({
        "surface": { "cacheSlug": "private-cache" },
        "name": "primary"
    });
    let (status, _) = rpc(
        &app,
        "TopologyService/GetPlacement",
        private_request.clone(),
        None,
    )
    .await;
    assert!(is_denied(status), "anonymous private cache read: {status}");

    let owner_member_id = db.create_user("member@cache.test", None).await.unwrap();
    let owner_scope = common::org_scope(&db, "cache-owner").await;
    db.grant_membership("user", owner_member_id, &owner_scope, "viewer")
        .await
        .unwrap();
    let owner_member = bearer(
        Principal::user(owner_member_id),
        &owner_scope,
        &[Permission::Read],
    );
    let (status, resp) = rpc(
        &app,
        "TopologyService/GetPlacement",
        private_request.clone(),
        Some(&owner_member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cache owner read: {resp}");
    assert_eq!(resp["placement"]["prefix"], "cache/private");

    let other_scope = common::org_scope(&db, "other-org").await;
    let other_member_id = db
        .create_user("member@other-cache.test", None)
        .await
        .unwrap();
    db.grant_membership("user", other_member_id, &other_scope, "viewer")
        .await
        .unwrap();
    let other_member = bearer(
        Principal::user(other_member_id),
        &other_scope,
        &[Permission::Read],
    );
    let (status, _) = rpc(
        &app,
        "TopologyService/GetPlacement",
        private_request,
        Some(&other_member),
    )
    .await;
    assert!(is_denied(status), "cross-org private cache read: {status}");
}

#[tokio::test]
async fn list_registries_filters_private_and_soft_deleted() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_managed_registry(org, "", "cdn", "public", &[], false)
        .await
        .unwrap();
    db.create_managed_registry(org, "", "secret", "private", &[], false)
        .await
        .unwrap();
    // A second org whose registry is hidden once the org is soft-deleted.
    let gone = db.create_org("gone", "Gone").await.unwrap();
    db.create_managed_registry(gone, "", "pub", "public", &[], false)
        .await
        .unwrap();
    db.soft_delete_org(gone, 30 * 86_400).await.unwrap();

    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous: only the live public registry is listed.
    let (status, resp) = rpc(
        &app,
        "RegistryService/ListRegistries",
        serde_json::json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "anon ListRegistries: {resp}");
    let slugs: Vec<&str> = resp["registries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, vec!["acme/cdn"], "only the live public registry");

    // A member of acme additionally sees acme's private registry, but never the
    // soft-deleted org's registry.
    let org_scope = common::org_scope(&db, "acme").await;
    let member_id = db
        .create_user("registry-member@acme.test", None)
        .await
        .unwrap();
    db.grant_membership("user", member_id, &org_scope, "viewer")
        .await
        .unwrap();
    let member = bearer(Principal::user(member_id), &org_scope, &[Permission::Read]);
    let (status, resp) = rpc(
        &app,
        "RegistryService/ListRegistries",
        serde_json::json!({}),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member ListRegistries: {resp}");
    let mut slugs: Vec<&str> = resp["registries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["slug"].as_str().unwrap())
        .collect();
    slugs.sort_unstable();
    assert_eq!(slugs, vec!["acme/cdn", "acme/secret"]);
    assert!(
        !slugs.iter().any(|s| s.starts_with("gone/")),
        "soft-deleted org's registry must never appear"
    );
}

// -- H-3: project / binding / org listing gating ----------------------------

#[tokio::test]
async fn list_orgs_requires_membership_and_filters() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.create_org("acme", "Acme").await.unwrap();
    db.create_org("globex", "Globex").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous enumeration is denied (was the per-slug harvest primitive).
    let (status, _resp) = rpc(
        &app,
        "OrganizationService/ListOrganizations",
        serde_json::json!({}),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "anonymous organization enumeration must be denied"
    );

    // A member of acme sees only acme, never globex.
    let org_scope = common::org_scope(&db, "acme").await;
    let member_id = db.create_user("org-member@acme.test", None).await.unwrap();
    db.grant_membership("user", member_id, &org_scope, "viewer")
        .await
        .unwrap();
    let member = bearer(Principal::user(member_id), &org_scope, &[Permission::Read]);
    let (status, resp) = rpc(
        &app,
        "OrganizationService/ListOrganizations",
        serde_json::json!({}),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member organizations: {resp}");
    let slugs: Vec<&str> = resp["organizations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, vec!["acme"], "only the caller's org");
}

#[tokio::test]
async fn list_projects_requires_membership() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    db.create_project(org, "team", "team").await.unwrap();
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous is denied — the project tree never leaks.
    let (status, resp) = rpc(
        &app,
        "ProjectService/ListProjects",
        serde_json::json!({ "orgSlug": "acme" }),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "anon ListProjects denied: {resp}"
    );

    // A member sees the org's projects.
    let org_scope = common::org_scope(&db, "acme").await;
    let member_id = db
        .create_user("project-member@acme.test", None)
        .await
        .unwrap();
    db.grant_membership("user", member_id, &org_scope, "viewer")
        .await
        .unwrap();
    let member = bearer(Principal::user(member_id), &org_scope, &[Permission::Read]);
    let (status, resp) = rpc(
        &app,
        "ProjectService/ListProjects",
        serde_json::json!({ "orgSlug": "acme" }),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "member ListProjects: {resp}");
    assert_eq!(resp["projects"][0]["path"], "team");
}

#[tokio::test]
async fn list_storage_bindings_requires_storage_management_authority() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("acme", "Acme").await.unwrap();
    let org_scope = db.org_by_id(org).await.unwrap().unwrap().stable_id;
    common::create_local_binding(&db, org, "primary", "/var/lib/aos/storage/acme").await;
    let app = router(app_state(Arc::clone(&db)).await).await;

    // Anonymous is denied — the host path never leaks.
    let (status, resp) = rpc(
        &app,
        "StorageBindingService/ListStorageBindings",
        serde_json::json!({ "ownerScopeKey": org_scope }),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "anonymous storage inventory denied: {resp}"
    );

    // A read-only member cannot enumerate infrastructure configuration.
    let member_id = db
        .create_user("storage-viewer@acme.test", None)
        .await
        .unwrap();
    db.grant_membership("user", member_id, &org_scope, "viewer")
        .await
        .unwrap();
    let member = bearer(Principal::user(member_id), &org_scope, &[Permission::Read]);
    let (status, resp) = rpc(
        &app,
        "StorageBindingService/ListStorageBindings",
        serde_json::json!({ "ownerScopeKey": org_scope }),
        Some(&member),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "read-only member: {resp}");

    // A storage manager sees the normalized binding spec.
    let admin_id = db
        .create_user("storage-admin@acme.test", None)
        .await
        .unwrap();
    db.grant_membership("user", admin_id, &org_scope, "admin")
        .await
        .unwrap();
    let admin = bearer(
        Principal::user(admin_id),
        &org_scope,
        &[Permission::StorageManage],
    );
    let (status, resp) = rpc(
        &app,
        "StorageBindingService/ListStorageBindings",
        serde_json::json!({ "ownerScopeKey": org_scope }),
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "storage manager: {resp}");
    assert_eq!(
        resp["storageBindings"][0]["spec"]["localRootPath"], "/var/lib/aos/storage/acme",
        "storage manager sees the normalized local root"
    );
}
