//! Regression tests for durable workflow replay and atomic verified activation.

use super::*;
use crate::db::{GatewayRevisionSpec, NewRegistryPublication};

#[tokio::test]
async fn endpoint_selector_does_not_expose_an_ungranted_successor_generation() {
    let (db, _, spec, _, _) = crate::db::topology::tests::route_fixture().await;
    let consumer_id = db
        .create_org("endpoint-selector", "Endpoint selector")
        .await
        .unwrap();
    let consumer = db.org_by_id(consumer_id).await.unwrap().unwrap();
    db.grant_consumer_scope(
        crate::db::GrantResource::Endpoint {
            id: &spec.endpoint_id,
            generation: 1,
        },
        &consumer.stable_id,
        "explicit",
        "test",
        "request:selector-endpoint",
    )
    .await
    .unwrap();
    let visible = db
        .list_endpoints_page(&consumer.stable_id, 10, None, true)
        .await
        .unwrap();
    assert_eq!(visible.records.len(), 1);
    assert_eq!(visible.records[0].desired_generation, Some(1));
    db.backend
        .execute(
            "UPDATE endpoints SET desired_generation = 2 WHERE id = ?1",
            &vals![spec.endpoint_id],
        )
        .await
        .unwrap();
    assert!(db
        .list_endpoints_page(&consumer.stable_id, 10, None, true)
        .await
        .unwrap()
        .records
        .is_empty());
}

async fn verified_fixture() -> (Database, DeliveryWorkflowRecord, DeliveryActivationRoute) {
    let (db, registry_id, mut spec, mut url, reservation) =
        crate::db::topology::tests::route_fixture().await;
    let surface = SurfaceTarget::Registry(registry_id);
    let owner = db.org_by_slug("route-probes").await.unwrap().unwrap();
    let placement = db
        .surface_placement(spec.placement_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    db.backend
        .execute(
            "UPDATE endpoint_revisions SET ingress_kind = 'layer7' WHERE endpoint_id = ?1",
            &vals![spec.endpoint_id.clone()],
        )
        .await
        .unwrap();
    let gateway = db
        .create_gateway(
            "gateway:workflow-test",
            &owner.stable_id,
            Some(owner.id),
            &GatewayRevisionSpec {
                binding_id: placement.binding_id,
                endpoint_id: spec.endpoint_id.clone(),
                endpoint_generation: 1,
                client_base_path: spec.base_path.clone(),
                origin_prefix: format!("/{}", placement.prefix),
                access_policy_kind: "public".into(),
                access_boundary_id: None,
                access_boundary_revision: None,
                external_provider_kind: None,
                external_provider_resource_id: None,
                external_provider_revision: None,
                access_policy_json: spec.access_policy_json.clone(),
            },
            "test",
        )
        .await
        .unwrap();
    let gateway = db
        .observe_gateway(&gateway.id, 1, "ready", None, gateway.resource_version)
        .await
        .unwrap();
    db.set_gateway_enabled(
        &gateway.id,
        true,
        gateway.resource_version,
        "user",
        Some(1),
        "test",
    )
    .await
    .unwrap();
    let endpoint = db.endpoint(&spec.endpoint_id).await.unwrap().unwrap();
    db.reconcile_endpoint(
        &endpoint.id,
        1,
        1,
        "healthy",
        true,
        true,
        None,
        endpoint.resource_version,
    )
    .await
    .unwrap();
    spec.endpoint_ingress_kind = "layer7".into();
    spec.mode = "direct".into();
    spec.gateway_id = Some(gateway.id);
    spec.gateway_generation = Some(1);
    spec.target_binding_id = Some(placement.binding_id);
    spec.gateway_client_base_path = Some(spec.base_path.clone());
    spec.base_path = crate::db::join_route_segments(&spec.base_path, &placement.prefix).unwrap();
    url = format!("{url}/{}", placement.prefix);
    spec.target_placement_prefix = Some(placement.prefix);
    let route = db
        .create_route(
            "route:workflow-test",
            surface,
            &spec,
            &url,
            1,
            &reservation,
            &[(1, reservation.to_vec())],
            None,
            "test",
        )
        .await
        .unwrap();
    db.create_registry_publication(&NewRegistryPublication {
        publication_id: "workflow-publication".into(),
        registry_id,
        generation: "workflow-generation".into(),
        manifest_digest: "a".repeat(64),
        refs_digest: "b".repeat(64),
        default_commit: Some("c".repeat(64)),
        parent_publication_id: None,
    })
    .await
    .unwrap();
    db.backend.batch(&[
        Statement::new("INSERT INTO placement_delivery_manifests (manifest_id, placement_id, registry_id, kind, registry_publication_id, content_digest, published_at)
            VALUES ('workflow-manifest', ?1, ?2, 'registry_publication', 'workflow-publication', ?3, 1)", vals![placement.id, registry_id, "d".repeat(64)]),
        Statement::new("INSERT INTO placement_delivery_manifest_heads (placement_id, registry_id, manifest_id, updated_at) VALUES (?1, ?2, 'workflow-manifest', 1)", vals![placement.id, registry_id]),
    ]).await.unwrap();
    let route = DeliveryActivationRoute {
        route_id: route.id,
        generation: route.configuration_generation.unwrap(),
        digest: route.configuration_digest.unwrap(),
        resource_version: route.resource_version,
    };
    db.reconcile_route(
        &route.route_id,
        route.generation,
        &route.digest,
        &spec.access_policy_digest,
        "healthy",
        "verified",
        None,
        Some("workflow-manifest"),
        2,
    )
    .await
    .unwrap();
    let workflow = db
        .create_delivery_workflow(
            "workflow:test",
            &owner.stable_id,
            surface,
            "reviewed-intent",
            "preparing",
        )
        .await
        .unwrap();
    (db, workflow, route)
}

#[tokio::test]
async fn public_object_delivery_requires_current_route_and_exact_publication_evidence() {
    use crate::db::{
        SetRegistryPublicationObject, SetRegistryPublicationPlacement, SetSurfaceObject,
    };

    let (db, workflow, route) = verified_fixture().await;
    let SurfaceTarget::Registry(registry_id) = workflow.surface else {
        panic!("registry fixture required");
    };
    let snapshot = db.route_snapshot(&route.route_id).await.unwrap().unwrap();
    let placement_id = snapshot.spec.placement_id.unwrap();
    let placement = db.surface_placement(placement_id).await.unwrap().unwrap();
    db.observe_surface_placement(
        placement_id,
        "ready",
        "complete",
        placement.observation_version.unwrap(),
    )
    .await
    .unwrap();
    db.activate_delivery_workflow(
        &workflow,
        &route,
        &[DeliveryAudienceBaseline {
            audience: "nix_cache".into(),
            resource_version: None,
        }],
        "active",
    )
    .await
    .unwrap();

    let hash = "a".repeat(64);
    let key = format!("oci/blobs/sha256/{hash}");
    let object = db
        .create_surface_object(&SetSurfaceObject {
            surface: workflow.surface,
            object_key: key.clone(),
            content_hash: Some(hash.clone()),
            size: Some(42),
            object_kind: "immutable".into(),
            mutable_publication_id: None,
        })
        .await
        .unwrap();
    db.backend
        .execute(
            "INSERT INTO object_placements (surface_object_id, registry_id, placement_id, state,
         observed_hash, observed_size, observed_inventory_generation, observed_at)
         VALUES (?1, ?2, ?3, 'present', ?4, 42, 1, 1)",
            &vals![object.id, registry_id, placement_id, hash],
        )
        .await
        .unwrap();
    db.set_registry_publication_placement(&SetRegistryPublicationPlacement {
        publication_id: "workflow-publication".into(),
        placement_id,
        required: true,
        state: "preparing".into(),
        observed_at: 1,
    })
    .await
    .unwrap();
    db.set_registry_publication_object(&SetRegistryPublicationObject {
        publication_id: "workflow-publication".into(),
        surface_object_id: object.id,
        object_kind: "immutable".into(),
        expected_hash: hash.clone(),
        expected_size: 42,
    })
    .await
    .unwrap();
    db.record_registry_publication_object_presence(
        "workflow-publication",
        object.id,
        placement_id,
        &hash,
        42,
        Some("\"object-etag\""),
        1,
    )
    .await
    .unwrap();

    assert_eq!(
        db.public_object_delivery_url(registry_id, &key, &hash, 42)
            .await
            .unwrap(),
        None
    );
    db.backend.execute("UPDATE registry_publications SET state = 'ready', completed_at = created_at WHERE publication_id = 'workflow-publication'", &[]).await.unwrap();
    db.backend.execute("UPDATE registry_publication_placements SET state = 'ready' WHERE publication_id = 'workflow-publication'", &[]).await.unwrap();
    assert_eq!(
        db.public_object_delivery_url(registry_id, &key, &hash, 42)
            .await
            .unwrap(),
        Some(format!("{}/{key}", snapshot.canonical_url))
    );
    assert_eq!(
        db.public_object_delivery_url(registry_id, &key, &"b".repeat(64), 42)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        db.public_object_delivery_url(registry_id, &key, &hash, 43)
            .await
            .unwrap(),
        None
    );

    db.backend
        .execute(
            "UPDATE object_placements SET state = 'missing' WHERE surface_object_id = ?1",
            &vals![object.id],
        )
        .await
        .unwrap();
    assert_eq!(
        db.public_object_delivery_url(registry_id, &key, &hash, 42)
            .await
            .unwrap(),
        None
    );
    db.backend
        .execute(
            "UPDATE object_placements SET state = 'present' WHERE surface_object_id = ?1",
            &vals![object.id],
        )
        .await
        .unwrap();
    db.backend
        .execute("UPDATE gateways SET enabled = 0", &[])
        .await
        .unwrap();
    assert_eq!(
        db.public_object_delivery_url(registry_id, &key, &hash, 42)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn activation_rolls_back_every_audience_when_a_later_baseline_is_stale() {
    let (db, workflow, route) = verified_fixture().await;
    assert!(db.delivery_workflow_route_ready(&route).await.unwrap());
    let audiences = [
        DeliveryAudienceBaseline {
            audience: "git".into(),
            resource_version: None,
        },
        DeliveryAudienceBaseline {
            audience: "nix_cache".into(),
            resource_version: Some(99),
        },
    ];
    assert!(db
        .activate_delivery_workflow(&workflow, &route, &audiences, "active")
        .await
        .is_err());
    assert!(db
        .route_advertisement(workflow.surface, "git")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.delivery_workflow(&workflow.workflow_id)
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        workflow.resource_version
    );
    let audiences = audiences.map(|baseline| DeliveryAudienceBaseline {
        resource_version: None,
        ..baseline
    });
    db.activate_delivery_workflow(&workflow, &route, &audiences, "active")
        .await
        .unwrap();
    for audience in ["git", "nix_cache"] {
        assert_eq!(
            db.route_advertisement(workflow.surface, audience)
                .await
                .unwrap()
                .unwrap()
                .route_id,
            route.route_id
        );
    }
    assert_eq!(
        db.delivery_workflow(&workflow.workflow_id)
            .await
            .unwrap()
            .unwrap()
            .progress_json,
        "active"
    );
}

#[tokio::test]
async fn activation_rechecks_route_evidence_inside_the_transaction() {
    let (db, workflow, route) = verified_fixture().await;
    assert!(db.delivery_workflow_route_ready(&route).await.unwrap());
    db.backend.execute("UPDATE route_access_observations SET state = 'failed', error = 'verification revoked' WHERE route_id = ?1", &vals![route.route_id.clone()]).await.unwrap();
    let audiences = [DeliveryAudienceBaseline {
        audience: "git".into(),
        resource_version: None,
    }];
    assert!(db
        .activate_delivery_workflow(&workflow, &route, &audiences, "active")
        .await
        .is_err());
    assert!(db
        .route_advertisement(workflow.surface, "git")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.delivery_workflow(&workflow.workflow_id)
            .await
            .unwrap()
            .unwrap()
            .progress_json,
        "preparing"
    );
}

#[tokio::test]
async fn activation_rechecks_network_policy_posture_inside_the_transaction() {
    let (db, workflow, route) = verified_fixture().await;
    assert!(db.delivery_workflow_route_ready(&route).await.unwrap());
    db.backend.execute("UPDATE network_policy_observations SET state = 'degraded' WHERE boundary_id = 'instance:public'", &[]).await.unwrap();
    let audiences = [DeliveryAudienceBaseline {
        audience: "git".into(),
        resource_version: None,
    }];
    assert!(db
        .activate_delivery_workflow(&workflow, &route, &audiences, "active")
        .await
        .is_err());
    assert!(db
        .route_advertisement(workflow.surface, "git")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn resume_replays_after_progress_changes_and_rejects_different_input() {
    let (db, workflow, _) = verified_fixture().await;
    assert!(!db
        .begin_delivery_resumption(
            "user",
            1,
            "retry",
            &workflow.workflow_id,
            workflow.resource_version
        )
        .await
        .unwrap());
    let updated = db
        .update_delivery_workflow(&workflow.workflow_id, workflow.resource_version, "prepared")
        .await
        .unwrap();
    assert!(!db
        .begin_delivery_resumption(
            "user",
            1,
            "retry",
            &workflow.workflow_id,
            workflow.resource_version
        )
        .await
        .unwrap());
    db.complete_delivery_resumption("user", 1, "retry")
        .await
        .unwrap();
    assert!(db
        .begin_delivery_resumption(
            "user",
            1,
            "retry",
            &workflow.workflow_id,
            workflow.resource_version
        )
        .await
        .unwrap());
    assert!(db
        .begin_delivery_resumption(
            "user",
            1,
            "retry",
            &workflow.workflow_id,
            updated.resource_version
        )
        .await
        .is_err());
    assert!(db
        .begin_delivery_resumption(
            "user",
            1,
            "retry",
            "workflow:other",
            workflow.resource_version
        )
        .await
        .is_err());
    assert!(db
        .create_delivery_workflow(
            &workflow.workflow_id,
            &workflow.owner_scope_key,
            workflow.surface,
            "changed-intent",
            "prepared"
        )
        .await
        .is_err());
}
