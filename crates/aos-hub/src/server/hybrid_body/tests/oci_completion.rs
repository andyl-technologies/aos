//! Current-actor OCI completion refusal at the actual ingress body boundary.

use super::*;
use aos_hub_core::{
    auth::jwt::JwtKeys,
    db::{
        EndpointHostInput, EndpointRevisionSpec, GrantResource, NewSurfacePlacementSpec, RouteSpec,
        SurfaceTarget,
    },
    domain::{Permission, Principal},
};
use sha2::{Digest as _, Sha256};

async fn current_registry() -> (Arc<Database>, String) {
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("completion", "Completion").await.unwrap();
    let owner = db.org_by_id(org).await.unwrap().unwrap();
    let binding = db
        .ensure_instance_default_binding("deployment_r2", None, Some("PRIVATE_OBJECTS"))
        .await
        .unwrap();
    db.grant_consumer_scope(
        GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        &owner.stable_id,
        "explicit",
        "test",
        "completion-binding",
    )
    .await
    .unwrap();
    let registry = db
        .create_managed_registry(org, "", "main", "private", &[], false)
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "completion/main".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    db.grant_consumer_scope(
        GrantResource::NetworkPolicy {
            id: "instance:public",
        },
        &owner.stable_id,
        "explicit",
        "test",
        "completion-network",
    )
    .await
    .unwrap();
    let endpoint_spec = EndpointRevisionSpec {
        boundary_revision: 1,
        ingress_kind: "layer7".into(),
        listener_configuration: "listener:completion".into(),
        tls_configuration: r#"{"provider":"external","certificate_ref":"secret:test","require_client_certificate":false}"#.into(),
        probe_configuration: r#"{"provider":"native_file","signerSecretRef":"test-probe-key","publicKey":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#.into(),
    };
    db.create_endpoint(
        "endpoint:completion",
        &owner.stable_id,
        Some(org),
        "https",
        &EndpointHostInput::Ipv4([127, 0, 0, 1]),
        443,
        "instance:public",
        &endpoint_spec,
        Some(1),
        "test",
        "completion-endpoint",
    )
    .await
    .unwrap();
    db.reconcile_endpoint("endpoint:completion", 1, 1, "healthy", true, true, None, 1)
        .await
        .unwrap();
    let policy = "{}";
    let policy_digest = hex::encode(Sha256::digest(policy));
    let endpoint = db.endpoint("endpoint:completion").await.unwrap().unwrap();
    let identity = hex::decode(&endpoint.endpoint_identity_digest).unwrap();
    let url = "https://127.0.0.1";
    let reservation = Database::route_reservation_digest(&[17; 32], &identity, "", url).unwrap();
    let route = db
        .create_route(
            "route:completion",
            SurfaceTarget::Registry(registry),
            &RouteSpec {
                consumer_scope_key: owner.stable_id.clone(),
                endpoint_id: endpoint.id,
                endpoint_generation: 1,
                endpoint_ingress_kind: "layer7".into(),
                base_path: String::new(),
                mode: "hub_proxy".into(),
                access_policy_kind: "public".into(),
                access_policy_json: policy.into(),
                access_policy_digest: policy_digest.clone(),
                access_boundary_id: None,
                access_boundary_revision: None,
                external_provider_kind: None,
                external_provider_resource_id: None,
                external_provider_revision: None,
                gateway_id: None,
                gateway_generation: None,
                target_binding_id: None,
                gateway_client_base_path: None,
                target_placement_prefix: None,
                placement_id: Some(placement.id),
                placement_policy_revision_id: None,
                serves_git: false,
                serves_cache: false,
                serves_web: false,
                serves_oci: true,
                enabled: true,
            },
            url,
            1,
            &reservation,
            &[(1, reservation.to_vec())],
            None,
            "test",
        )
        .await
        .unwrap();
    db.reconcile_route(
        &route.id,
        route.configuration_generation.unwrap(),
        route.configuration_digest.as_deref().unwrap(),
        &policy_digest,
        "healthy",
        "verified",
        None,
        None,
        1,
    )
    .await
    .unwrap();
    let user = db
        .create_user("completion@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (token_id, _) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    let auth = db
        .current_token_authority(&token_id)
        .await
        .unwrap()
        .unwrap();
    let keys = JwtKeys::from_secret(b"completion-current-key");
    let bearer = keys.mint(&auth, 900).unwrap();
    let claims = keys.verify(&bearer).unwrap();
    let scope = db.registry_authorization_scope(registry).await.unwrap();
    assert!(!db
        .direct_iam_statements(
            &claims,
            &scope,
            Permission::Publish,
            aos_hub_core::clock::now_unix_secs()
        )
        .await
        .unwrap()
        .is_empty());
    let registry = db.registry_by_id(registry).await.unwrap().unwrap();
    let repository = aos_oci_types::RepositoryName::parse("repo").unwrap();
    let oci = keys
        .mint_oci(
            &aos_hub_core::auth::jwt::OciTokenGrant {
                subject: format!("token:{token_id}"),
                owner_kind: Some("user".into()),
                owner_incarnation: auth.owner_incarnation,
                authority: "127.0.0.1".into(),
                registry_stable_id: registry.stable_id.clone(),
                grants: vec![aos_hub_core::auth::jwt::OciRepositoryGrant {
                    repository: repository.clone(),
                    actions: vec!["push".into()],
                }],
            },
            900,
        )
        .unwrap();
    keys.verify_oci(&oci, "127.0.0.1", &registry.stable_id, &repository, "push")
        .unwrap();
    (db, format!("Bearer {oci}"))
}
fn completion_router(key: Arc<HybridIngressKey>, db: Arc<Database>) -> Router {
    Router::new()
        .fallback(|body: Bytes| async move {
            assert_eq!(body.as_ref(), b"{}");
            StatusCode::NO_CONTENT
        })
        .layer(axum::middleware::from_fn(move |request, next| {
            let key = key.clone();
            let db = db.clone();
            async move {
                super::super::super::verify_hybrid_ingress(
                    key,
                    "guard-deployment".into(),
                    "https://guard.example.test".into(),
                    Some(db),
                    request,
                    next,
                )
                .await
            }
        }))
}

#[tokio::test]
async fn current_publish_actor_raw_completion_is_refused_without_polling() {
    let (db, bearer) = current_registry().await;
    let key = Arc::new(HybridIngressKey::new([31; 32]).unwrap());
    let uri =
        "/v2/repo/manifests/latest?aos_hybrid_manifest_upload=0123456789abcdef0123456789abcdef";
    for (committed, declared) in [
        (
            b"{\"schemaVersion\":2,\"manifests\":[]}".as_slice(),
            Some(34),
        ),
        (b"{}".as_slice(), Some(128)),
        (b"{\"schemaVersion\":2}".as_slice(), None),
    ] {
        let mut signed = assertion(Method::PUT, uri, Some("complete"), committed);
        signed.authority = "127.0.0.1".into();
        let mut request = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header(HYBRID_INGRESS_HEADER, key.sign(&signed).unwrap())
            .header(HYBRID_UPLOAD_PHASE_HEADER, "complete")
            .header(header::AUTHORIZATION, &bearer);
        if let Some(length) = declared {
            request = request.header(header::CONTENT_LENGTH, length);
        }
        let response = completion_router(key.clone(), db.clone())
            .oneshot(request.body(never_poll_body()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let mut signed = assertion(Method::PUT, uri, Some("complete"), b"{}");
    signed.authority = "127.0.0.1".into();
    let request = axum::http::Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header(HYBRID_INGRESS_HEADER, key.sign(&signed).unwrap())
        .header(HYBRID_UPLOAD_PHASE_HEADER, "complete")
        .header(header::AUTHORIZATION, bearer)
        .header(header::CONTENT_LENGTH, 2)
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        completion_router(key, db)
            .oneshot(request)
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
}
