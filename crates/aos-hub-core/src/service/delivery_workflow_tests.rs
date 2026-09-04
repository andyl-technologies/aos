//! End-to-end service regressions for reviewed, resumable delivery preparation.

use super::*;
use crate::db::{GrantResource, NewSurfacePlacementSpec, TokenAuth};
use base64::Engine as _;

async fn fixture() -> (RpcService, String, pb::DeliveryDestinationIntent, i64) {
    let (service, db) = super::cache_upload_tests::delivery_test_service().await;
    let keyring = ConfiguredRouteReservationKeyring::from_json(&serde_json::json!({
        "activeVersion": 1,
        "keys": [{"version": 1, "keyBase64": base64::engine::general_purpose::STANDARD.encode([7_u8; 32])}],
    }).to_string()).unwrap();
    let service = service.with_route_reservation_keyring(Arc::new(keyring));
    let org_id = db
        .create_org("delivery-workflow", "Delivery workflow")
        .await
        .unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding = db
        .ensure_instance_default_binding(
            "deployment_r2",
            None,
            Some(crate::binding::DEPLOYMENT_R2_ATTACHMENT),
        )
        .await
        .unwrap();
    for resource in [
        GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        GrantResource::NetworkPolicy {
            id: "instance:public",
        },
    ] {
        db.grant_consumer_scope(
            resource,
            &org.stable_id,
            "explicit",
            "test",
            &format!("grant:{resource:?}"),
        )
        .await
        .unwrap();
    }
    let registry_id = db
        .create_managed_registry(org_id, "", "main", "public", &[], false)
        .await
        .unwrap();
    db.create_surface_placement(&NewSurfacePlacementSpec {
        surface: SurfaceTarget::Registry(registry_id),
        name: "primary".into(),
        binding_id: binding.id,
        prefix: "delivery-workflow/main".into(),
        kind: "complete".into(),
        desired_state: "active".into(),
        hash_range: None,
        desired_read_enabled: true,
        read_order: 0,
        requires_conditional_writes: false,
    })
    .await
    .unwrap();
    let user = db.create_user("delivery@example.test", None).await.unwrap();
    db.grant_membership("user", user, &org.stable_id, Role::Owner.as_str())
        .await
        .unwrap();
    let token = service
        .jwt_keys
        .mint(
            &TokenAuth {
                token_id: "delivery-token".into(),
                owner: Principal::user(user),
                scope: Scope::try_parse(&org.stable_id).unwrap(),
                permissions: vec![
                    Permission::Read,
                    Permission::RouteRead,
                    Permission::RouteManage,
                    Permission::GatewayRead,
                    Permission::GatewayManage,
                    Permission::BindingRead,
                    Permission::DomainRead,
                    Permission::DomainManage,
                    Permission::EndpointRead,
                    Permission::EndpointManage,
                    Permission::NetworkPolicyRead,
                    Permission::PlacementRead,
                ],
            },
            3600,
        )
        .unwrap();
    let intent = pb::DeliveryDestinationIntent {
        surface: Some(pb::SurfaceRef { target: Some(pb::surface_ref::Target::RegistrySlug("delivery-workflow/main".into())) }),
        owner_scope_key: org.stable_id,
        endpoint: Some(pb::delivery_destination_intent::Endpoint::NewEndpoint(pb::DeliveryEndpointInput {
            hostname_source: Some(pb::delivery_endpoint_input::HostnameSource::Hostname("cdn.workflow.example.test".into())),
            network_policy_id: "instance:public".into(),
            revision: Some(pb::EndpointRevisionSpec {
                boundary_revision: 1, ingress_kind: pb::EndpointIngressKind::External as i32,
                listener_configuration_ref: "listener:delivery-test".into(),
                tls: Some(pb::TlsConfiguration { provider: "external".into(), certificate_ref: "secret:delivery-test".into(), require_client_certificate: false }),
                probe_configuration_ref: r#"{"provider":"native_file","signerSecretRef":"test-probe-key","publicKey":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#.into(),
            }),
        })), placement_name: "primary".into(), client_base_path: "/cache".into(),
        access_policy: Some(pb::DeliveryAccessPolicy { policy: Some(pb::delivery_access_policy::Policy::Public(true)) }),
        capabilities: Some(pb::RouteCapabilities { serves_cache: true, ..Default::default() }), audiences: vec!["nix_cache".into()],
    };
    (service, format!("Bearer {token}"), intent, user)
}

fn apply_request(plan: pb::TopologyPlan, key: &str) -> pb::ApplyDeliveryDestinationRequest {
    pb::ApplyDeliveryDestinationRequest {
        plan_id: plan.plan_id,
        confirmation_hash: plan.confirmation_hash,
        idempotency_key: key.into(),
    }
}

#[tokio::test]
async fn shared_storage_workflow_resumes_child_plans_without_owner_authority() {
    let (service, auth, intent, _) = fixture().await;
    let plan = service
        .plan_delivery_destination(
            Some(&auth),
            pb::PlanDeliveryDestinationRequest {
                intent: Some(intent.clone()),
                idempotency_key: "plan-workflow".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let request = apply_request(plan, "apply-workflow");
    let prepared = service
        .apply_delivery_destination(Some(&auth), request.clone())
        .await
        .unwrap()
        .workflow
        .unwrap();
    assert_eq!(prepared.state, "blocked", "{:?}", prepared.blockers);
    assert!(
        prepared
            .blockers
            .iter()
            .any(|value| value.contains("gateway must be reconciled")),
        "{:?}",
        prepared.blockers
    );
    assert!(prepared
        .steps
        .iter()
        .find(|step| step.key == "endpoint")
        .unwrap()
        .operation
        .is_some());
    let persisted = service
        .db
        .delivery_workflow(&prepared.workflow_id)
        .await
        .unwrap()
        .unwrap();
    let before: serde_json::Value = serde_json::from_str(&persisted.progress_json).unwrap();
    assert_eq!(before["plans"].as_object().unwrap().len(), 3);
    assert!(service
        .db
        .route(&prepared.route_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        service
            .apply_delivery_destination(Some(&auth), request)
            .await
            .unwrap()
            .workflow
            .unwrap()
            .workflow_id,
        prepared.workflow_id
    );
    let gateway = service
        .db
        .gateway(&prepared.gateway_id)
        .await
        .unwrap()
        .unwrap();
    service
        .db
        .observe_gateway(&gateway.id, 1, "ready", None, gateway.resource_version)
        .await
        .unwrap();
    let resume = pb::ResumeDeliveryDestinationRequest {
        workflow_id: prepared.workflow_id.clone(),
        expected_resource_version: prepared.resource_version,
        idempotency_key: "resume-workflow".into(),
    };
    let (first_retry, second_retry) = tokio::join!(
        service.resume_delivery_destination(Some(&auth), resume.clone()),
        service.resume_delivery_destination(Some(&auth), resume.clone()),
    );
    first_retry.unwrap();
    second_retry.unwrap();
    let resumed = service
        .get_delivery_workflow(
            Some(&auth),
            pb::GetDeliveryWorkflowRequest {
                workflow_id: prepared.workflow_id,
            },
        )
        .await
        .unwrap()
        .workflow
        .unwrap();
    assert_eq!(
        resumed.state, "awaiting_verification",
        "{:?}",
        resumed.blockers
    );
    assert_eq!(
        resumed.canonical_url,
        "https://cdn.workflow.example.test/cache/delivery-workflow/main"
    );
    let route = service
        .get_route(
            Some(&auth),
            pb::GetTopologyResourceRequest {
                stable_id: resumed.route_id.clone(),
            },
        )
        .await
        .unwrap()
        .route
        .unwrap();
    assert_eq!(route.canonical_rendered_url, resumed.canonical_url);
    let replayed = service
        .resume_delivery_destination(Some(&auth), resume)
        .await
        .unwrap()
        .workflow
        .unwrap();
    assert_eq!(replayed.resource_version, resumed.resource_version);
    let after: serde_json::Value = serde_json::from_str(
        &service
            .db
            .delivery_workflow(&resumed.workflow_id)
            .await
            .unwrap()
            .unwrap()
            .progress_json,
    )
    .unwrap();
    for step in ["domain", "endpoint", "gateway"] {
        let old_plan: pb::TopologyPlan =
            serde_json::from_value(before["plans"][step].clone()).unwrap();
        let new_plan: pb::TopologyPlan =
            serde_json::from_value(after["plans"][step].clone()).unwrap();
        assert!(!old_plan.plan_id.is_empty());
        assert_eq!(old_plan.plan_id, new_plan.plan_id);
    }
    let surface = service
        .readable_topology_surface(Some(&auth), intent.surface)
        .await
        .unwrap();
    assert!(service
        .db
        .route_advertisement(surface, "nix_cache")
        .await
        .unwrap()
        .is_none());
    assert!(service
        .plan_activate_delivery_destination(
            Some(&auth),
            pb::PlanActivateDeliveryDestinationRequest {
                workflow_id: resumed.workflow_id,
                expected_resource_version: resumed.resource_version,
                idempotency_key: "premature-activation".into()
            }
        )
        .await
        .is_err());
}

#[tokio::test]
async fn plan_replay_normalizes_hostname_path_and_duplicate_audiences() {
    let (service, auth, mut intent, _) = fixture().await;
    intent.client_base_path = "/".into();
    intent.audiences = vec!["nix_cache".into(), "nix_cache".into()];
    if let Some(pb::delivery_destination_intent::Endpoint::NewEndpoint(input)) =
        intent.endpoint.as_mut()
    {
        input.hostname_source = Some(pb::delivery_endpoint_input::HostnameSource::Hostname(
            "CDN.Workflow.Example.Test".into(),
        ));
    }
    let request = pb::PlanDeliveryDestinationRequest {
        intent: Some(intent),
        idempotency_key: "normalized-replay".into(),
        ..Default::default()
    };
    let first = service
        .plan_delivery_destination(Some(&auth), request.clone())
        .await
        .unwrap()
        .plan
        .unwrap();
    let second = service
        .plan_delivery_destination(Some(&auth), request)
        .await
        .unwrap()
        .plan
        .unwrap();
    assert_eq!(first.plan_id, second.plan_id);
    assert_eq!(first.confirmation_hash, second.confirmation_hash);
}

#[tokio::test]
async fn domain_observation_updates_do_not_change_reviewed_attachment_intent() {
    let (service, auth, mut intent, _) = fixture().await;
    let org = service
        .db
        .org_by_slug("delivery-workflow")
        .await
        .unwrap()
        .unwrap();
    let domain = service
        .db
        .create_delivery_domain(
            &org.stable_id,
            Some(org.id),
            "existing.workflow.example.test",
            "existing-domain-plan",
        )
        .await
        .unwrap();
    if let Some(pb::delivery_destination_intent::Endpoint::NewEndpoint(input)) =
        intent.endpoint.as_mut()
    {
        input.hostname_source = Some(pb::delivery_endpoint_input::HostnameSource::DomainId(
            domain.stable_id,
        ));
    }
    let plan = service
        .plan_delivery_destination(
            Some(&auth),
            pb::PlanDeliveryDestinationRequest {
                intent: Some(intent),
                idempotency_key: "observed-domain".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    service.db.backend.execute("UPDATE domains SET observed_at = 1, resource_version = resource_version + 1 WHERE hostname = 'existing.workflow.example.test'", &[]).await.unwrap();
    let response = service
        .apply_delivery_destination(Some(&auth), apply_request(plan, "observed-domain-apply"))
        .await
        .unwrap()
        .workflow
        .unwrap();
    assert!(
        response
            .steps
            .iter()
            .any(|step| step.key == "endpoint" && step.state == "complete"),
        "{:?}",
        response.blockers
    );
}

#[tokio::test]
async fn changed_policy_blocks_preparation_before_creating_resources() {
    let (service, auth, intent, _) = fixture().await;
    let plan = service
        .plan_delivery_destination(
            Some(&auth),
            pb::PlanDeliveryDestinationRequest {
                intent: Some(intent),
                idempotency_key: "policy-plan".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    service.db.backend.execute("UPDATE network_policies SET resource_version = resource_version + 1 WHERE id = 'instance:public'", &[]).await.unwrap();
    let result = service
        .apply_delivery_destination(Some(&auth), apply_request(plan, "policy-apply"))
        .await
        .unwrap()
        .workflow
        .unwrap();
    assert_eq!(result.state, "blocked");
    assert!(result
        .blockers
        .iter()
        .any(|blocker| blocker.contains("prerequisites changed")));
    assert!(service
        .db
        .delivery_domain_by_hostname("cdn.workflow.example.test")
        .await
        .unwrap()
        .is_none());
    assert!(service
        .db
        .endpoint(&result.endpoint_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn revoked_operator_cannot_apply_a_previously_reviewed_workflow() {
    let (service, auth, intent, user) = fixture().await;
    let plan = service
        .plan_delivery_destination(
            Some(&auth),
            pb::PlanDeliveryDestinationRequest {
                intent: Some(intent.clone()),
                idempotency_key: "revoke-plan".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let other_owner = service
        .db
        .create_user("replacement@example.test", None)
        .await
        .unwrap();
    service
        .db
        .grant_membership(
            "user",
            other_owner,
            &intent.owner_scope_key,
            Role::Owner.as_str(),
        )
        .await
        .unwrap();
    service
        .db
        .revoke_membership("user", user, &intent.owner_scope_key)
        .await
        .unwrap();
    assert!(service
        .apply_delivery_destination(Some(&auth), apply_request(plan, "revoke-apply"))
        .await
        .is_err());
    assert!(service
        .db
        .delivery_domain_by_hostname("cdn.workflow.example.test")
        .await
        .unwrap()
        .is_none());
}
