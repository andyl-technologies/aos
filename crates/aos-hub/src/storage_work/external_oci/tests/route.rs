//! Actual SQL Distribution endpoint and route for the controlled TLS listener.

use aos_hub_core::db::{
    Database, EndpointHostInput, EndpointRevisionSpec, GrantResource, RouteSpec,
    SurfacePlacementRecord, SurfaceTarget,
};
use sha2::{Digest as _, Sha256};

pub(super) async fn install(db: &Database, placement: &SurfacePlacementRecord, port: u16) {
    let registry = placement.registry_id.unwrap();
    let org = db
        .org_by_id(
            db.registry_by_id(registry)
                .await
                .unwrap()
                .unwrap()
                .org_id
                .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let owner = org;
    let org = owner.id;
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
    let domain = db
        .create_delivery_domain(
            &owner.stable_id,
            Some(org),
            "s3.fleet.test",
            "oci-runtime-domain",
        )
        .await
        .unwrap();
    db.create_endpoint(
        "endpoint:completion",
        &owner.stable_id,
        Some(org),
        "https",
        &EndpointHostInput::Domain(domain.stable_id.clone()),
        port,
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
    let url = format!("https://s3.fleet.test:{port}");
    let reservation = Database::route_reservation_digest(&[17; 32], &identity, "", &url).unwrap();
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
            &url,
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
}
