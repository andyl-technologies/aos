//! Runtime regression cases and contract checks.

use super::*;

#[tokio::test]
async fn deployment_reports_require_the_exact_live_enrollment() {
    let (service, db, _lease, reporter_auth) = injected_service(vec![], vec![]).await;
    let org_id = db
        .create_org("deployment-auth", "Deployment auth")
        .await
        .unwrap();
    db.create_managed_registry(org_id, "", "packages", "private", &[], true)
        .await
        .unwrap();

    let enrollment_plan = service
        .plan_configure_ability_deployment_reporter(
            Some(&reporter_auth),
            pb::PlanConfigureAbilityDeploymentReporterRequest {
                registry: "deployment-auth/packages".into(),
                deployment: "production".into(),
                principal_kind: "user".into(),
                principal_ref: "writer@example.test".into(),
                enabled: true,
                expected_resource_version: 0,
                idempotency_key: "plan-enroll-production".into(),
            },
        )
        .await
        .unwrap();
    let enrollment_plan = enrollment_plan.plan.unwrap();
    let enrollment = service
        .configure_ability_deployment_reporter(
            Some(&reporter_auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: enrollment_plan.plan_id,
                idempotency_key: "apply-enroll-production".into(),
                confirmation_hash: enrollment_plan.confirmation_hash,
            },
        )
        .await
        .unwrap();

    let other_user = db
        .create_user("other-reporter@example.test", None)
        .await
        .unwrap();
    let other_token = JwtKeys::from_secret(b"injected-write-flow-test-key")
        .mint(
            &TokenAuth {
                token_id: "other-reporter".into(),
                owner: Principal::user(other_user),
                scope: Scope::root(),
                permissions: Vec::new(),
            },
            3600,
        )
        .unwrap();
    let other_auth = format!("Bearer {other_token}");
    let report = pb::ReportPackageAbilityDeploymentRequest {
        registry: "deployment-auth/packages".into(),
        deployment: "production".into(),
        reporter_resource_version: enrollment.resource_version,
        canonical_json: b"not canonical JSON".to_vec(),
    };

    assert!(matches!(
        service
            .report_package_ability_deployment(Some(&other_auth), report.clone())
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
    assert!(matches!(
        service
            .report_package_ability_deployment(Some(&reporter_auth), report.clone())
            .await,
        Err(RpcError::InvalidArgument(_))
    ));

    let revoke_plan = service
        .plan_configure_ability_deployment_reporter(
            Some(&reporter_auth),
            pb::PlanConfigureAbilityDeploymentReporterRequest {
                registry: "deployment-auth/packages".into(),
                deployment: "production".into(),
                principal_kind: "user".into(),
                principal_ref: "writer@example.test".into(),
                enabled: false,
                expected_resource_version: enrollment.resource_version,
                idempotency_key: "plan-revoke-production".into(),
            },
        )
        .await
        .unwrap();
    let revoke_plan = revoke_plan.plan.unwrap();
    service
        .configure_ability_deployment_reporter(
            Some(&reporter_auth),
            pb::ApplyTopologyPlanRequest {
                plan_id: revoke_plan.plan_id,
                idempotency_key: "apply-revoke-production".into(),
                confirmation_hash: revoke_plan.confirmation_hash,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        service
            .report_package_ability_deployment(Some(&reporter_auth), report)
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
}

#[tokio::test]
async fn image_head_unsatisfied_range_and_auth_gate_never_fetch_storage_bytes() {
    use crate::service::{ReadAuthorization, RegistryServeOutcome};
    use aos_hub_model::delivery_http::DeliveryMethod;
    use axum::http::StatusCode;

    let (service, registry, object_key, calls) = image_metadata_service("public").await;
    let head = service
        .registry_serve(
            ReadAuthorization::AuthorizationHeader(None),
            &registry,
            &object_key,
            image_http_request(DeliveryMethod::Head, Some(b"bytes=0-1")),
        )
        .await
        .unwrap();
    let RegistryServeOutcome::Response(head) = head else {
        panic!("signed image HEAD must return metadata response");
    };
    assert_eq!(head.status(), StatusCode::OK);
    assert!(!head
        .headers()
        .contains_key(axum::http::header::CONTENT_RANGE));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let unsatisfied = service
        .registry_serve(
            ReadAuthorization::AuthorizationHeader(None),
            &registry,
            &object_key,
            image_http_request(DeliveryMethod::Get, Some(b"bytes=9999-")),
        )
        .await
        .unwrap();
    let RegistryServeOutcome::Response(unsatisfied) = unsatisfied else {
        panic!("unsatisfied image range must return metadata response");
    };
    assert_eq!(unsatisfied.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (service, registry, object_key, calls) = image_metadata_service("private").await;
    assert!(service
        .registry_serve(
            ReadAuthorization::AuthorizationHeader(None),
            &registry,
            &object_key,
            image_http_request(DeliveryMethod::Get, None),
        )
        .await
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn streamed_producer_document_is_inert() {
    let response = RpcService::streamed_surface_response(
        "index.html",
        StreamedRead {
            body: axum::body::Body::from("<script>bad()</script>"),
            total: 22,
            range: None,
            strong_etag: None,
            snapshot_lease_id: None,
        },
    )
    .unwrap();
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some("sandbox")
    );
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_DISPOSITION)
            .and_then(|value| value.to_str().ok()),
        Some("attachment")
    );
}

#[test]
fn unclassified_create_failures_remain_internal() {
    let error = RpcService::placement_create_error(anyhow::anyhow!("database unavailable"));
    assert!(matches!(error, RpcError::Internal));
    assert_eq!(error.message(), "internal error");
}

#[test]
fn unclassified_authority_failures_remain_internal() {
    let error = RpcService::authority_mutation_error(anyhow::anyhow!("database unavailable"));
    assert!(matches!(error, RpcError::Internal));
    assert_eq!(error.message(), "internal error");
}

#[test]
fn typed_pin_impacts_are_closed_deduplicated_and_canonical() {
    let input = serde_json::json!({
        "pin_resolutions": [
            {
                "source": {
                    "pin_id": "pin:route",
                    "target_kind": "route",
                    "target_stable_id": "route:old",
                    "target_generation_key": 7,
                    "target_configuration_digest": "a".repeat(64),
                    "target_resource_version": 9
                },
                "action_kind": "replace_route"
            },
            {
                "source": {
                    "pin_id": "pin:route",
                    "target_kind": "route",
                    "target_stable_id": "route:old",
                    "target_generation_key": 7,
                    "target_configuration_digest": "a".repeat(64),
                    "target_resource_version": 9
                },
                "action_kind": "release"
            },
            {
                "source": {
                    "pin_id": "pin:unknown",
                    "target_kind": "arbitrary",
                    "target_stable_id": "unknown",
                    "target_generation_key": 1,
                    "target_configuration_digest": "b".repeat(64),
                    "target_resource_version": 1
                },
                "action_kind": "release"
            }
        ]
    });
    let mut impacts = BTreeMap::new();
    collect_plan_pin_impacts(&input, &mut impacts);
    assert_eq!(impacts.len(), 1);
    let impact = impacts.get("pin:route").unwrap();
    assert_eq!(
        impact.allowed_actions,
        [
            pb::PinResolutionAction::ReplaceRoute as i32,
            pb::PinResolutionAction::Release as i32,
        ]
    );
    assert!(!impact
        .allowed_actions
        .contains(&(pb::PinResolutionAction::Unspecified as i32)));
}

#[tokio::test]
async fn signing_usage_enforces_authz_cas_and_apply_replay() {
    let (service, db, _lease, underprivileged_auth) = injected_service(vec![], vec![]).await;
    let org_id = db.create_org("usage-auth", "Usage Auth").await.unwrap();
    let org = db.org_by_id(org_id).await.unwrap().unwrap();
    db.create_managed_registry(org_id, "", "packages", "private", &[], true)
        .await
        .unwrap();
    let registry = db
        .registry_by_slug("usage-auth/packages")
        .await
        .unwrap()
        .unwrap();
    let public_key_bytes = [19_u8; 32];
    let public_key = base64::engine::general_purpose::STANDARD_NO_PAD.encode(public_key_bytes);
    let fingerprint = hex::encode(Sha256::digest(public_key_bytes));
    let key_id = db
        .enroll_signing_key(
            &org.stable_id,
            "publication",
            &public_key,
            &fingerprint,
            "external",
        )
        .await
        .unwrap();
    let request = pb::PlanSigningKeyUsageRequest {
        consumer_stable_id: registry.stable_id.clone(),
        purpose: "registry_publication".into(),
        signing_key_stable_id: key_id,
        signing_key_generation: 1,
        state: "active".into(),
        expected_resource_version: "absent".into(),
        idempotency_key: "plan-signing-usage".into(),
    };
    assert!(matches!(
        service
            .plan_set_signing_key_usage(Some(&underprivileged_auth), request.clone())
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
    assert!(matches!(
        service
            .get_signing_key_usage(
                Some(&underprivileged_auth),
                pb::GetSigningKeyUsageRequest {
                    consumer_stable_id: registry.stable_id.clone(),
                    purpose: "registry_publication".into(),
                },
            )
            .await,
        Err(RpcError::PermissionDenied(_))
    ));

    let jwt_keys = JwtKeys::from_secret(b"injected-write-flow-test-key");
    let user_id = db
        .user_by_email("writer@example.test")
        .await
        .unwrap()
        .unwrap();
    let token = jwt_keys
        .mint(
            &TokenAuth {
                token_id: "keys-manager".into(),
                owner: Principal::user(user_id),
                scope: Scope::root(),
                permissions: vec![Permission::KeysManage],
            },
            3600,
        )
        .unwrap();
    let auth = format!("Bearer {token}");
    assert!(matches!(
        service
            .get_signing_key_usage(
                Some(&auth),
                pb::GetSigningKeyUsageRequest {
                    consumer_stable_id: registry.stable_id.clone(),
                    purpose: "registry_publication".into(),
                },
            )
            .await,
        Err(RpcError::NotFound(_))
    ));
    let plan = service
        .plan_set_signing_key_usage(Some(&auth), request.clone())
        .await
        .unwrap()
        .plan
        .unwrap();
    let apply = pb::ApplyTopologyPlanRequest {
        plan_id: plan.plan_id,
        confirmation_hash: plan.confirmation_hash,
        idempotency_key: "apply-signing-usage".into(),
    };
    let first = service
        .apply_set_signing_key_usage(Some(&auth), apply.clone())
        .await
        .unwrap();
    let replay = service
        .apply_set_signing_key_usage(Some(&auth), apply)
        .await
        .unwrap();
    assert_eq!(first, replay);
    let observed = service
        .get_signing_key_usage(
            Some(&auth),
            pb::GetSigningKeyUsageRequest {
                consumer_stable_id: registry.stable_id.clone(),
                purpose: "registry_publication".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(observed, first);
    assert!(matches!(
        service
            .plan_set_signing_key_usage(
                Some(&auth),
                pb::PlanSigningKeyUsageRequest {
                    idempotency_key: "stale-signing-usage".into(),
                    ..request
                },
            )
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
}
