//! Integration coverage for scoped settings workflow selectors.
//!
//! A delivery workflow may select an instance-owned gateway only when its
//! current generation has an active grant to the workflow's consumer scope.
//! These tests drive the public Connect router so the database selector and
//! authorization boundary are verified together.

mod common;

use std::sync::Arc;

use aos_hub::auth::extract::AuthState;
use aos_hub::auth::jwt::JwtKeys;
use aos_hub::db::{
    Database, EndpointHostInput, EndpointRevisionSpec, GatewayGrantCarryForward,
    GatewayRevisionSpec, GrantResource, TokenAuth,
};
use aos_hub::domain::{Permission, Principal, Scope};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt as _;

/// Uses a deterministic signing key for Connect authentication fixtures.
const TEST_JWT_SECRET: &[u8] = b"settings-workflow-test-secret-key";

/// Builds the native router used by the browser application.
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
        deployment_id: None,
        ratelimit: Arc::clone(&auth.ratelimit),
        trusted_proxy: false,
        auth,
        leases: Arc::new(aos_hub_core::lease::InMemoryLease::new()),
        sealer: aos_hub::auth::oidc::dev_sealer(),
        secret_versions: aos_hub_core::secret_version::EmptySecretVersionResolver::shared(),
        http: aos_hub::fetch::hardened_client().await,
        image_snapshots: None,
        mailer: Arc::new(aos_hub::auth::magic::LogMailer),
        dev: false,
        delivery_attestation_verifier: None,
        domain_probe_terminator: None,
        identity_domain_verifier: None,
        route_reservation_keyring: None,
        container_rollout: aos_hub_core::container_rollout::ContainerRollout::all_enabled(),
        release_evidence: None,
    })
}

/// Mints a test bearer for one exact authorization scope.
fn bearer(principal: Principal, scope: &str, permissions: &[Permission]) -> String {
    JwtKeys::from_secret(TEST_JWT_SECRET)
        .mint(
            &TokenAuth {
                token_id: "settings-workflow-test-token".into(),
                owner: principal,
                scope: Scope::parse(scope),
                permissions: permissions.to_vec(),
            },
            900,
        )
        .unwrap()
}

/// Calls a Connect-JSON route with an optional bearer token.
async fn rpc(
    app: &axum::Router,
    method: &str,
    json: serde_json::Value,
    auth: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/aos.hub.v1.{method}"))
        .header(header::HOST, "127.0.0.1:8420")
        .header(header::CONTENT_TYPE, "application/json")
        .header("connect-protocol-version", "1");
    if let Some(auth) = auth {
        request = request.header(header::AUTHORIZATION, format!("Bearer {auth}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(json.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let response = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, response)
}

/// Creates a gateway whose endpoint and binding are usable by `owner_scope`.
async fn create_gateway(
    db: &Database,
    owner_id: i64,
    owner_scope: &str,
    binding_id: i64,
    id: &str,
    path: &str,
) -> (aos_hub::db::GatewayRecord, GatewayRevisionSpec) {
    let spec = GatewayRevisionSpec {
        binding_id,
        endpoint_id: "endpoint:settings-selector".into(),
        endpoint_generation: 1,
        client_base_path: path.into(),
        origin_prefix: "/objects".into(),
        access_policy_kind: "public".into(),
        access_boundary_id: None,
        access_boundary_revision: None,
        external_provider_kind: None,
        external_provider_resource_id: None,
        external_provider_revision: None,
        access_policy_json: r#"{"public":true}"#.into(),
    };
    let gateway = db
        .create_gateway(id, owner_scope, Some(owner_id), &spec, "test")
        .await
        .unwrap();
    (gateway, spec)
}

#[tokio::test]
async fn scoped_gateway_selector_requires_current_active_grants() {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let owner_id = db
        .create_org("delivery-owner", "Delivery owner")
        .await
        .unwrap();
    db.create_org("delivery-consumer", "Delivery consumer")
        .await
        .unwrap();
    db.create_org("delivery-foreign", "Delivery foreign")
        .await
        .unwrap();
    let owner_scope = common::org_scope(&db, "delivery-owner").await;
    let consumer_scope = common::org_scope(&db, "delivery-consumer").await;
    let foreign_scope = common::org_scope(&db, "delivery-foreign").await;
    let root = tempfile::tempdir().unwrap();
    let binding_id = common::create_local_binding(
        &db,
        owner_id,
        "settings-selector",
        root.path().to_str().unwrap(),
    )
    .await;

    db.grant_consumer_scope(
        GrantResource::NetworkPolicy {
            id: "instance:public",
        },
        &owner_scope,
        "explicit",
        "test",
        "request:settings-selector-boundary",
    )
    .await
    .unwrap();
    db.create_endpoint(
        "endpoint:settings-selector",
        &owner_scope,
        Some(owner_id),
        "http",
        &EndpointHostInput::Ipv4([127, 0, 0, 1]),
        8443,
        "instance:public",
        &EndpointRevisionSpec {
            boundary_revision: 1,
            ingress_kind: "external".into(),
            listener_configuration: "settings-selector-listener".into(),
            tls_configuration: "{}".into(),
            probe_configuration: "{\"provider\":\"native_file\",\"signerSecretRef\":\"test-probe-key\",\"publicKey\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}".into(),
        },
        Some(1),
        "test",
        "request:settings-selector-endpoint",
    )
    .await
    .unwrap();

    let (allowed, _) = create_gateway(
        &db,
        owner_id,
        &owner_scope,
        binding_id,
        "gateway:selector-allowed",
        "/allowed",
    )
    .await;
    db.grant_consumer_scope(
        GrantResource::Gateway {
            id: &allowed.id,
            generation: 1,
        },
        &consumer_scope,
        "explicit",
        "test",
        "request:settings-selector-allowed",
    )
    .await
    .unwrap();

    let (_ungranted, _) = create_gateway(
        &db,
        owner_id,
        &owner_scope,
        binding_id,
        "gateway:selector-ungranted",
        "/ungranted",
    )
    .await;

    let (revoked, _) = create_gateway(
        &db,
        owner_id,
        &owner_scope,
        binding_id,
        "gateway:selector-revoked",
        "/revoked",
    )
    .await;
    let revoked_grant = db
        .grant_consumer_scope(
            GrantResource::Gateway {
                id: &revoked.id,
                generation: 1,
            },
            &consumer_scope,
            "explicit",
            "test",
            "request:settings-selector-revoked",
        )
        .await
        .unwrap();
    db.revoke_consumer_scope(
        GrantResource::Gateway {
            id: &revoked.id,
            generation: 1,
        },
        &consumer_scope,
        revoked_grant.resource_version,
        "test",
        "request:settings-selector-revoke",
    )
    .await
    .unwrap();

    let (historical, spec) = create_gateway(
        &db,
        owner_id,
        &owner_scope,
        binding_id,
        "gateway:selector-historical",
        "/historical",
    )
    .await;
    db.grant_consumer_scope(
        GrantResource::Gateway {
            id: &historical.id,
            generation: 1,
        },
        &consumer_scope,
        "explicit",
        "test",
        "request:settings-selector-historical",
    )
    .await
    .unwrap();
    let owner_grant = db
        .list_consumer_scope_grants(GrantResource::Gateway {
            id: &historical.id,
            generation: 1,
        })
        .await
        .unwrap()
        .into_iter()
        .find(|grant| grant.consumer_scope_key == owner_scope)
        .unwrap();
    db.revise_gateway(
        &historical.id,
        &spec,
        &GatewayGrantCarryForward {
            consumer_scope_key: owner_scope.clone(),
            grant_generation: owner_grant.grant_generation,
            resource_version: owner_grant.resource_version,
        },
        &[],
        historical.resource_version,
        "test",
        "request:settings-selector-historical-successor",
    )
    .await
    .unwrap();

    let selector_id = db
        .create_user("selector@delivery-consumer.test", None)
        .await
        .unwrap();
    db.grant_membership("user", selector_id, &consumer_scope, "viewer")
        .await
        .unwrap();
    let selector = bearer(
        Principal::user(selector_id),
        &consumer_scope,
        &[Permission::GatewayRead],
    );
    let app = router(app_state(Arc::clone(&db)).await).await;

    let (status, response) = rpc(
        &app,
        "DeliveryService/ListGateways",
        serde_json::json!({
            "ownerScopeKey": consumer_scope,
            "includeGranted": true,
            "pageSize": 50,
        }),
        Some(&selector),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "granted selector: {response}");
    assert_eq!(
        response["gateways"]
            .as_array()
            .unwrap()
            .iter()
            .map(|gateway| gateway["stableId"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["gateway:selector-allowed"]
    );
    assert_eq!(response["gateways"][0]["ownerScopeKey"], owner_scope);

    let (status, response) = rpc(
        &app,
        "DeliveryService/ListGateways",
        serde_json::json!({
            "ownerScopeKey": consumer_scope,
            "includeGranted": false,
        }),
        Some(&selector),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owned-only selector: {response}");
    assert!(
        response["gateways"].as_array().map_or(true, Vec::is_empty),
        "owned-only selector returned a gateway: {response}"
    );

    let (status, response) = rpc(
        &app,
        "DeliveryService/ListGateways",
        serde_json::json!({
            "ownerScopeKey": foreign_scope,
            "includeGranted": true,
        }),
        Some(&selector),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "foreign scope: {response}");
}
