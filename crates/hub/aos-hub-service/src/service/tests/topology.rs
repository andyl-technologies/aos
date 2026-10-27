//! Topology regression cases and contract checks.

use super::*;

#[tokio::test]
async fn viewer_operation_reads_expose_only_redacted_provider_failures() {
    let (service, db, _lease, _admin_auth) = injected_service(vec![], vec![]).await;
    let org_id = db
        .create_org("operation-reader", "Operation reader")
        .await
        .unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    let viewer_id = db
        .create_user("operation-reader@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", viewer_id, &org.stable_id, Role::Viewer.as_str())
        .await
        .unwrap();
    let (_, token_secret) = db
        .create_token(
            Principal::user(viewer_id),
            &org.stable_id,
            &[Permission::Read, Permission::PlacementRead],
            None,
            None,
        )
        .await
        .unwrap();
    let viewer_token = db.validate_token(&token_secret).await.unwrap().unwrap();
    let viewer_auth = format!(
        "Bearer {}",
        service.jwt_keys.mint(&viewer_token, 3_600).unwrap()
    );
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            &uuid::Uuid::new_v4().simple().to_string(),
            &org.stable_id,
            "primary",
            "r2",
            None,
            Some("test-bucket"),
            Some("operation-reader/registry"),
            Some("https"),
            Some("dns"),
            Some(b"storage.example.invalid"),
            Some(443),
            Some("auto"),
            Some("private"),
        )
        .await
        .unwrap();
    let registry_id = db
        .create_managed_registry(org_id, "", "operation-reader", "public", &[], false)
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry_id),
            name: "primary".into(),
            binding_id,
            prefix: "operation-reader/registry".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    let operation = db
        .create_topology_operation(&aos_hub_db::db::NewTopologyOperation {
            operation_id: "viewer-redacted-provider-failure".into(),
            operation_kind: "scan_placement".into(),
            control_permission: Permission::StorageManage,
            targets: vec![aos_hub_db::db::NewTopologyOperationTarget {
                role: "primary".into(),
                target: aos_hub_db::db::NewTopologyOperationTargetRef::Placement(placement.id),
                generation_key: placement.resource_version,
                configuration_digest: String::new(),
            }],
            detail_json: serde_json::json!({"phase":"failed"}).to_string(),
            progress_total: None,
        })
        .await
        .unwrap();
    let marker = "signed-capability-marker";
    let failure = crate::jobs::redacted_operation_failure(&format!(
        "provider request failed: https://storage.example/object?X-Amz-Signature={marker}"
    ));
    let claimed = db
        .claim_surface_placement_scan_operation(
            &operation.operation_id,
            operation.resource_version,
            "viewer-redaction-claim",
            600,
        )
        .await
        .unwrap()
        .unwrap();
    db.update_topology_operation(
        &claimed.operation_id,
        claimed.resource_version,
        "failed",
        0,
        None,
        &claimed.detail_json,
        Some(&failure),
        claimed.started_at,
        Some(claimed.created_at),
    )
    .await
    .unwrap();

    let response = service
        .get_operation(
            Some(&viewer_auth),
            pb::GetOperationRequest {
                operation_id: operation.operation_id,
            },
        )
        .await
        .unwrap();
    let error = response.operation.unwrap().error;
    assert!(error.starts_with("operation failed; detail redacted; fingerprint="));
    assert!(!error.contains(marker));
    assert!(!error.contains("storage.example"));
}

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
        true,
    )
    .unwrap();
    assert!(!response.headers().contains_key("x-aos-placement"));
    assert_eq!(
        response.headers()[axum::http::header::CACHE_CONTROL],
        aos_hub_model::keymap::IMMUTABLE_CACHE_CONTROL
    );
    assert!(!response.headers().contains_key(axum::http::header::VARY));
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
