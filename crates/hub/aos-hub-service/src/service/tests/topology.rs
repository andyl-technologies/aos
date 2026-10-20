//! Topology regression cases and contract checks.

use super::*;

#[tokio::test]
async fn registry_without_a_canonical_route_has_no_consumer_url() {
    let (service, db, _lease, _auth) = injected_service(vec![], vec![]).await;
    let binding = db
        .ensure_instance_default_binding(
            "deployment_r2",
            None,
            Some(aos_hub_model::binding::DEPLOYMENT_R2_ATTACHMENT),
        )
        .await
        .unwrap();
    let org_id = db.create_org("automatic", "Automatic").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    db.grant_consumer_scope(
        aos_hub_db::db::GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        &org.stable_id,
        "explicit",
        "test",
        "request:automatic-binding-grant",
    )
    .await
    .unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "main", "public", &[], false)
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "automatic/main".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
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
    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();

    assert!(matches!(
        service.registry_consumer_url(&registry).await,
        Err(RpcError::FailedPrecondition(message))
            if message.contains("canonical Git route")
    ));
}

#[tokio::test]
async fn who_am_i_separates_live_grants_from_bearer_authority() {
    let (service, _db, _lease, auth) = injected_service(vec![], vec![]).await;

    let identity = service
        .who_am_i(Some(&auth), pb::WhoAmIRequest {})
        .await
        .unwrap();

    assert_eq!(identity.principal_kind, "user");
    assert_eq!(identity.principal_ref, "writer@example.test");
    assert_eq!(identity.email, "writer@example.test");
    assert_eq!(
        identity.grants,
        vec![pb::IdentityGrant {
            scope: "instance".into(),
            role: "owner".into(),
        }]
    );
    assert_eq!(identity.access_scope, "instance");
    assert_eq!(
        identity.access_permissions,
        vec![
            "registry.configure",
            "publish",
            "tokens.manage",
            "iam.admin",
            "members.manage"
        ]
    );
    assert!(identity.access_expires_at > aos_hub_model::clock::now_unix_secs());
}

#[test]
fn unset_topology_defaults_return_editable_empty_resources() {
    let instance = RpcService::topology_defaults_or_empty("instance", None);
    let organization = RpcService::topology_defaults_or_empty("org:defaults", None);

    assert_eq!(instance.scope_key, "instance");
    assert!(instance.resource_version.is_empty());
    assert!(instance.binding_id.is_empty());
    assert_eq!(organization.scope_key, "org:defaults");
    assert!(organization.resource_version.is_empty());
    assert!(organization.binding_id.is_empty());
}

#[test]
fn streamed_topology_read_does_not_expose_the_placement() {
    let response = RpcService::streamed_surface_response(
        "nar/example.nar",
        StreamedRead {
            body: axum::body::Body::from("data"),
            total: 4,
            range: None,
            strong_etag: None,
            snapshot_lease_id: None,
        },
    )
    .unwrap();
    assert!(!response.headers().contains_key("x-aos-placement"));
}

#[test]
fn blocker_errors_are_stable_topology_preconditions() {
    let direct = RpcService::placement_route_pin_error(SurfacePlacementBlockers {
        direct_route: true,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(direct.code(), "failed_precondition");
    assert_eq!(direct.http_status(), 400);
    assert_eq!(direct.message(), "placement is pinned by a direct route");

    let routed = RpcService::placement_route_pin_error(SurfacePlacementBlockers {
        routed_policy: true,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        routed.message(),
        "placement is pinned by a delivery-route placement policy"
    );

    let cases = [
        (
            SurfacePlacementBlockers {
                direct_route: true,
                ..Default::default()
            },
            "placement is referenced by a direct route",
        ),
        (
            SurfacePlacementBlockers {
                policy_member: true,
                ..Default::default()
            },
            "placement is referenced by a placement policy",
        ),
        (
            SurfacePlacementBlockers {
                object_presence: true,
                ..Default::default()
            },
            "placement has object-presence inventory",
        ),
        (
            SurfacePlacementBlockers {
                publication: true,
                ..Default::default()
            },
            "placement has registry-publication state",
        ),
        (
            SurfacePlacementBlockers {
                active_publication: true,
                ..Default::default()
            },
            "placement has active registry-publication state",
        ),
        (
            SurfacePlacementBlockers {
                deletion_job: true,
                ..Default::default()
            },
            "placement has object-deletion jobs",
        ),
        (
            SurfacePlacementBlockers {
                topology_operation: true,
                ..Default::default()
            },
            "placement has topology operations",
        ),
    ];
    for (blockers, expected) in cases {
        let error = RpcService::placement_delete_blocker_error(blockers, false).unwrap();
        assert_eq!(error.code(), "failed_precondition");
        assert_eq!(error.message(), expected);
        assert!(!error.message().contains("FOREIGN KEY"));
    }

    assert!(RpcService::placement_delete_blocker_error(
        SurfacePlacementBlockers {
            object_presence: true,
            publication: true,
            ..Default::default()
        },
        true,
    )
    .is_none());
    assert_eq!(
        RpcService::placement_delete_blocker_error(
            SurfacePlacementBlockers {
                active_publication: true,
                ..Default::default()
            },
            true,
        )
        .unwrap()
        .message(),
        "placement has active registry-publication state"
    );
}

#[tokio::test]
async fn hybrid_private_registry_grant_disables_shared_caching() {
    use crate::service::ReadAuthorization;
    use crate::service::RegistryServeOutcome;
    use aos_hub_db::hybrid_ingress::HybridDeliveryTarget;
    use aos_hub_db::hybrid_ingress::HYBRID_DELIVERY_HEADER;
    use aos_hub_model::delivery_http::DeliveryMethod;

    let bytes = b"registry object bytes".to_vec();
    let (service, db, _lease, _auth) = injected_service(
        vec![FetchBehavior::Evidence {
            bytes: bytes.clone(),
            strong_etag: "\"registry-version\"".into(),
        }],
        vec![],
    )
    .await;
    let service = service.with_hybrid_delivery();
    let binding = db
        .ensure_instance_default_binding(
            "deployment_r2",
            None,
            Some(aos_hub_model::binding::DEPLOYMENT_R2_ATTACHMENT),
        )
        .await
        .unwrap();
    let org_id = db.create_org("hybrid-serve", "Hybrid serve").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    db.grant_consumer_scope(
        aos_hub_db::db::GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        &org.stable_id,
        "explicit",
        "test",
        "request:hybrid-serve-binding-grant",
    )
    .await
    .unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "main", "private", &[], false)
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "hybrid-serve/main".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
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
    db.set_registry_mirror(
        registry_id,
        "https://example.org/source",
        "refs/heads/*",
        "",
        "pull_through",
        "allow_unsigned",
        0,
        None,
    )
    .await
    .unwrap();

    let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
    let path = format!("objects/aa/{}", "0".repeat(62));
    assert!(service
        .registry_serve(
            ReadAuthorization::AuthorizationHeader(None),
            &registry,
            &path,
            image_http_request(DeliveryMethod::Get, None),
        )
        .await
        .is_err());
    let response = service
        .registry_serve(
            ReadAuthorization::PreauthorizedSession,
            &registry,
            &path,
            image_http_request(DeliveryMethod::Get, None),
        )
        .await
        .unwrap();
    let RegistryServeOutcome::Response(response) = response else {
        panic!("hybrid registry object should produce a delivery grant");
    };
    let encoded = response.headers()[HYBRID_DELIVERY_HEADER].to_str().unwrap();
    let target: HybridDeliveryTarget = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(target.object_key, format!("hybrid-serve/main/{path}"));
    assert_eq!(target.object_size, bytes.len() as u64);
    assert_eq!(target.object_etag, "\"registry-version\"");
    assert_eq!(target.cache_control, "private, no-store");
    assert!(axum::body::to_bytes(response.into_body(), 1)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn private_cache_info_disables_shared_caching() {
    use crate::service::ReadAuthorization;

    let (service, db, _lease, _auth) = injected_service(vec![], vec![]).await;
    let org_id = db.create_org("private-info", "Private info").await.unwrap();
    let cache_id = db
        .create_binary_cache(
            Some(org_id),
            "private-info/cache",
            "Private cache",
            "private",
            40,
            "zstd",
            true,
        )
        .await
        .unwrap();
    let cache = db.binary_cache_by_id(cache_id).await.unwrap().unwrap();

    assert!(service
        .cache_serve(
            ReadAuthorization::AuthorizationHeader(None),
            &cache,
            "nix-cache-info",
            None,
        )
        .await
        .is_err());
    let response = service
        .cache_serve(
            ReadAuthorization::PreauthorizedSession,
            &cache,
            "nix-cache-info",
            None,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        response.headers()[axum::http::header::CACHE_CONTROL],
        "private, no-store"
    );
    assert_eq!(
        response.headers()[axum::http::header::VARY],
        "Authorization, Cookie"
    );
}

#[test]
fn private_surface_response_disables_shared_caching() {
    let response = RpcService::streamed_surface_response(
        "nar/example.nar",
        StreamedRead {
            body: axum::body::Body::from("data"),
            total: 4,
            range: None,
            strong_etag: None,
            snapshot_lease_id: None,
        },
    )
    .unwrap();
    let response = RpcService::private_delivery_response(response);

    assert_eq!(
        response.headers()[axum::http::header::CACHE_CONTROL],
        "private, no-store"
    );
    assert_eq!(
        response.headers()[axum::http::header::VARY],
        "Authorization, Cookie"
    );
}
