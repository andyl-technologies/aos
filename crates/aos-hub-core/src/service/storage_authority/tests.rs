//! Operator authorization, typed decision persistence and exact replay behavior.

use super::*;
use crate::db::{NewBindingWriteRevision, TokenAuth};
use crate::domain::{Principal, Role};

const AUTHORITY: &str = "00000000-0000-4000-8000-000000000001";

async fn fixture() -> (RpcService, String, i64) {
    let (service, db) = super::super::cache_upload_tests::delivery_test_service().await;
    let user = db
        .user_by_email("writer@example.test")
        .await
        .unwrap()
        .unwrap();
    let auth = token(&service, user, Scope::root());
    (service, auth, user)
}

fn token(service: &RpcService, user: i64, scope: Scope) -> String {
    let jwt = service
        .jwt_keys
        .mint(
            &TokenAuth {
                token_id: format!("authority-operator-{user}"),
                owner: Principal::user(user),
                scope,
                permissions: vec![Permission::StorageManage],
            },
            3600,
        )
        .unwrap();
    format!("Bearer {jwt}")
}

fn create() -> pb::StorageAuthorityDecision {
    pb::StorageAuthorityDecision {
        input: Some(pb::storage_authority_decision::Input::Create(
            pb::CreatePhysicalStorageAuthorityDecision {
                authority_id: AUTHORITY.into(),
                guard_namespace_id: "actual-account/configured-namespace".into(),
                physical_resource_evidence_digest: "1".repeat(64),
                qualification_digest: "2".repeat(64),
                qualified_managed_prefix: Some("fresh".into()),
            },
        )),
    }
}

async fn plan(
    service: &RpcService,
    auth: &str,
    input: pb::StorageAuthorityDecision,
    key: &str,
) -> pb::StorageAuthorityPlanResponse {
    service
        .plan_storage_authority_decision(
            Some(auth),
            pb::PlanStorageAuthorityDecisionRequest {
                decision: Some(input),
                idempotency_key: key.into(),
            },
        )
        .await
        .unwrap()
}

fn apply_request(
    plan: &pb::StorageAuthorityPlanResponse,
    key: &str,
) -> pb::ApplyStorageAuthorityDecisionRequest {
    let control = plan.plan.as_ref().unwrap();
    pb::ApplyStorageAuthorityDecisionRequest {
        plan_id: control.plan_id.clone(),
        confirmation_hash: control.confirmation_hash.clone(),
        idempotency_key: key.into(),
        decision: plan.decision.clone(),
    }
}

async fn apply(
    service: &RpcService,
    auth: &str,
    input: pb::StorageAuthorityDecision,
    key: &str,
) -> pb::StorageAuthorityDecisionResponse {
    let plan = plan(service, auth, input, key).await;
    service
        .apply_storage_authority_decision(Some(auth), apply_request(&plan, key))
        .await
        .unwrap()
}

#[tokio::test]
async fn authority_operator_requires_instance_root_permission_for_plan_apply_and_read() {
    let (service, root, _) = fixture().await;
    let org_id = service
        .db
        .create_org("authority-org", "Authority org")
        .await
        .unwrap();
    let org = service.db.org_by_id(org_id).await.unwrap().unwrap();
    let user = service
        .db
        .create_user("org-operator@example.test", None)
        .await
        .unwrap();
    service
        .db
        .grant_membership("user", user, &org.stable_id, Role::Owner.as_str())
        .await
        .unwrap();
    let org_token = token(&service, user, Scope::parse(&org.stable_id));
    let broad_token = token(&service, user, Scope::root());
    let approved = plan(&service, &root, create(), "root-plan").await;

    for auth in [None, Some(org_token.as_str()), Some(broad_token.as_str())] {
        let denied = service
            .plan_storage_authority_decision(
                auth,
                pb::PlanStorageAuthorityDecisionRequest {
                    decision: Some(create()),
                    idempotency_key: "denied-plan".into(),
                },
            )
            .await;
        assert!(matches!(
            denied,
            Err(RpcError::PermissionDenied(_) | RpcError::Unauthenticated(_))
        ));
        let denied = service
            .apply_storage_authority_decision(auth, apply_request(&approved, "denied-apply"))
            .await;
        assert!(matches!(
            denied,
            Err(RpcError::PermissionDenied(_) | RpcError::Unauthenticated(_))
        ));
        let denied = service
            .get_storage_authority(
                auth,
                pb::GetStorageAuthorityRequest {
                    authority_id: AUTHORITY.into(),
                },
            )
            .await;
        assert!(matches!(
            denied,
            Err(RpcError::PermissionDenied(_) | RpcError::Unauthenticated(_))
        ));
    }
    assert!(
        service
            .db
            .physical_storage_authority(&conversion::authority_id(AUTHORITY).unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn authority_operator_reauthorizes_revoked_role_before_apply_and_result_replay() {
    let (service, root, user) = fixture().await;
    let backup = service
        .db
        .create_user("backup-root@example.test", None)
        .await
        .unwrap();
    service
        .db
        .grant_membership("user", backup, "instance", Role::Owner.as_str())
        .await
        .unwrap();
    let approved = plan(&service, &root, create(), "revoked-plan").await;
    let request = apply_request(&approved, "revoked-apply");
    service
        .db
        .revoke_membership("user", user, "instance")
        .await
        .unwrap();
    assert!(matches!(
        service
            .apply_storage_authority_decision(Some(&root), request.clone())
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
    assert!(
        service
            .db
            .physical_storage_authority(&conversion::authority_id(AUTHORITY).unwrap())
            .await
            .unwrap()
            .is_none()
    );

    service
        .db
        .grant_membership("user", user, "instance", Role::Owner.as_str())
        .await
        .unwrap();
    service
        .apply_storage_authority_decision(Some(&root), request.clone())
        .await
        .unwrap();
    service
        .db
        .revoke_membership("user", user, "instance")
        .await
        .unwrap();
    assert!(matches!(
        service
            .apply_storage_authority_decision(Some(&root), request)
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
    assert!(matches!(
        service
            .plan_storage_authority_decision(
                Some(&root),
                pb::PlanStorageAuthorityDecisionRequest {
                    decision: Some(create()),
                    idempotency_key: "revoked-plan".into()
                }
            )
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
}

#[tokio::test]
async fn authority_operator_binds_request_replay_actor_input_confirmation_and_apply_key() {
    let (service, root, _) = fixture().await;
    let approved = plan(&service, &root, create(), "exact-plan").await;
    assert_eq!(
        plan(&service, &root, create(), "exact-plan").await,
        approved
    );
    let mut changed = create();
    if let Some(pb::storage_authority_decision::Input::Create(value)) = &mut changed.input {
        value.guard_namespace_id = "another-namespace".into();
    }
    assert!(matches!(
        service
            .plan_storage_authority_decision(
                Some(&root),
                pb::PlanStorageAuthorityDecisionRequest {
                    decision: Some(changed.clone()),
                    idempotency_key: "exact-plan".into()
                }
            )
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));

    let request = apply_request(&approved, "exact-apply");
    let other = service
        .db
        .create_user("another-root@example.test", None)
        .await
        .unwrap();
    service
        .db
        .grant_membership("user", other, "instance", Role::Owner.as_str())
        .await
        .unwrap();
    assert!(matches!(
        service
            .apply_storage_authority_decision(
                Some(&token(&service, other, Scope::root())),
                request.clone()
            )
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
    let mut wrong_input = request.clone();
    wrong_input.decision = Some(changed);
    assert!(matches!(
        service
            .apply_storage_authority_decision(Some(&root), wrong_input)
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
    let mut wrong_confirmation = request.clone();
    wrong_confirmation.confirmation_hash = "0".repeat(64);
    assert!(matches!(
        service
            .apply_storage_authority_decision(Some(&root), wrong_confirmation)
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));

    service
        .db
        .begin_topology_plan_apply(&request.plan_id, "exact-apply")
        .await
        .unwrap();
    let mut wrong_key = request.clone();
    wrong_key.idempotency_key = "another-apply".into();
    assert!(matches!(
        service
            .apply_storage_authority_decision(Some(&root), wrong_key.clone())
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
    let (first, retry) = tokio::join!(
        service.apply_storage_authority_decision(Some(&root), request.clone()),
        service.apply_storage_authority_decision(Some(&root), request.clone())
    );
    let first = first.unwrap();
    assert_eq!(retry.unwrap(), first);
    assert!(first.pending_reconciliation);
    assert_eq!(
        service
            .apply_storage_authority_decision(Some(&root), request.clone())
            .await
            .unwrap(),
        first
    );
    assert!(matches!(
        service
            .apply_storage_authority_decision(Some(&root), wrong_key)
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));

    let mut wrong_input = request;
    wrong_input.decision = None;
    assert!(matches!(
        service
            .apply_storage_authority_decision(Some(&root), wrong_input)
            .await,
        Err(RpcError::InvalidArgument(_))
    ));
}

#[tokio::test]
async fn authority_operator_rejects_expired_unreserved_plan_and_preserves_begun_retry() {
    let (service, root, _) = fixture().await;
    let approved = plan(&service, &root, create(), "expiry-plan").await;
    let request = apply_request(&approved, "expiry-apply");
    service
        .db
        .backend
        .execute(
            "UPDATE topology_plans SET created_at = ?2 - 60, expires_at = ?2 WHERE plan_id = ?1",
            &[
                crate::value::Value::Text(request.plan_id.clone()),
                crate::value::Value::Int(clock::now_unix_secs() - 1),
            ],
        )
        .await
        .unwrap();
    assert!(matches!(
        service
            .apply_storage_authority_decision(Some(&root), request.clone())
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
    assert!(
        service
            .db
            .topology_plan(&request.plan_id)
            .await
            .unwrap()
            .unwrap()
            .apply_idempotency_key
            .is_none()
    );
    // Seed the reservation retained by an attempt begun before plan expiry.
    service
        .db
        .begin_topology_plan_apply(&request.plan_id, &request.idempotency_key)
        .await
        .unwrap();
    let response = service
        .apply_storage_authority_decision(Some(&root), request)
        .await
        .unwrap();
    assert!(response.pending_reconciliation);
}

#[tokio::test]
async fn authority_operator_roundtrips_all_families_and_projects_desired_pending_admission() {
    use pb::storage_authority_decision::Input;
    let (service, root, _) = fixture().await;
    apply(&service, &root, create(), "create").await;
    apply(
        &service,
        &root,
        pb::StorageAuthorityDecision {
            input: Some(Input::ApproveAlias(
                pb::ApproveStorageAuthorityAliasDecision {
                    alias_id: "alias-one".into(),
                    authority_id: AUTHORITY.into(),
                    address: Some(pb::StorageAuthorityAddress {
                        host: Some(pb::storage_authority_address::Host::DnsName(
                            "storage.example.invalid".into(),
                        )),
                        port: 443,
                        bucket: "exclusive-bucket".into(),
                    }),
                    equivalence_evidence_digest: "3".repeat(64),
                },
            )),
        },
        "alias",
    )
    .await;
    let org_id = service
        .db
        .create_org("association-owner", "Association owner")
        .await
        .unwrap();
    let org = service.db.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = service
        .db
        .create_topology_binding(
            Some(org_id),
            "operator-binding",
            &org.stable_id,
            "exclusive",
            "s3",
            None,
            Some("exclusive-bucket"),
            Some("fresh/root"),
            Some("https"),
            Some("dns"),
            Some(b"storage.example.invalid"),
            Some(443),
            Some("fixture-region"),
            Some("private"),
        )
        .await
        .unwrap();
    let credential = service
        .db
        .set_binding_credential_revision(
            binding_id,
            "write",
            "secret://operator/write/v1",
            0,
            &"4".repeat(64),
            "fixture",
        )
        .await
        .unwrap();
    let credential = service
        .db
        .validate_binding_credential_revision(
            binding_id,
            "write",
            credential.generation,
            "valid",
            None,
            credential.head_resource_version,
        )
        .await
        .unwrap();
    let writer = service
        .db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id,
            write_credential_generation: credential.generation,
            writes_supported: true,
            conditional_writes_supported: false,
            revision_fingerprint: "operator-writer".into(),
            capability_fingerprint: "unconditional-write".into(),
        })
        .await
        .unwrap();
    let binding = service.db.binding(binding_id).await.unwrap().unwrap();
    apply(
        &service,
        &root,
        pb::StorageAuthorityDecision {
            input: Some(Input::AssociateBinding(
                pb::AssociateStorageAuthorityBindingDecision {
                    association_id: "association-one".into(),
                    authority_id: AUTHORITY.into(),
                    alias_id: "alias-one".into(),
                    binding_id: binding_id.to_string(),
                    binding_stable_id: binding.stable_id,
                    binding_resource_version: binding.resource_version.to_string(),
                    binding_write_revision: writer.revision.to_string(),
                    binding_prefix: "fresh/root".into(),
                },
            )),
        },
        "association",
    )
    .await;
    let attestation = plan(
        &service,
        &root,
        pb::StorageAuthorityDecision {
            input: Some(Input::Attest(
                pb::AttestStorageAuthorityExclusivityDecision {
                    attestation_id: "attestation-one".into(),
                    authority_id: AUTHORITY.into(),
                    managed_prefix: "fresh".into(),
                    qualification_digest: "2".repeat(64),
                    provider_policy_evidence_digest: "5".repeat(64),
                    executor_identity: "configured-executor".into(),
                    credentials: vec![pb::StorageAuthorityCredentialMember {
                        association_id: "association-one".into(),
                        purpose: "write".into(),
                        generation: credential.generation.to_string(),
                        secret_version_ref: credential.secret_version_ref,
                        credential_fingerprint: credential.credential_fingerprint,
                    }],
                    valid_until: clock::now_unix_secs() + 300,
                },
            )),
        },
        "attestation",
    )
    .await;
    service
        .apply_storage_authority_decision(
            Some(&root),
            apply_request(&attestation, "attestation-apply"),
        )
        .await
        .unwrap();
    let response = apply(
        &service,
        &root,
        pb::StorageAuthorityDecision {
            input: Some(Input::SetAdmission(
                pb::SetStorageAuthorityAdmissionDecision {
                    authority_id: AUTHORITY.into(),
                    expected_generation: "0".into(),
                    expected_digest: None,
                    guard_namespace_id: "actual-account/configured-namespace".into(),
                    state: pb::StorageAuthorityDesiredState::Admitted as i32,
                    attestation_id: Some("attestation-one".into()),
                    association_ids: vec!["association-one".into()],
                },
            )),
        },
        "admission",
    )
    .await;
    assert_eq!(response.desired_generation.as_deref(), Some("1"));
    assert!(response.pending_reconciliation);
    let projection = service
        .get_storage_authority(
            Some(&root),
            pb::GetStorageAuthorityRequest {
                authority_id: AUTHORITY.into(),
            },
        )
        .await
        .unwrap();
    assert!(projection.pending_reconciliation);
    assert_eq!(
        projection
            .authority
            .as_ref()
            .unwrap()
            .qualified_managed_prefix
            .as_deref(),
        Some("fresh")
    );
    let desired = projection.desired_admission.unwrap();
    assert_eq!(desired.desired_generation, "1");
    assert_eq!(
        desired.decision.unwrap().state,
        pb::StorageAuthorityDesiredState::Admitted as i32
    );
    assert!(
        service
            .db
            .storage_authority_admission_for_remote(
                &crate::storage_authority::StorageAuthorityRemoteWatermark {
                    authority_id: conversion::authority_id(AUTHORITY).unwrap(),
                    guard_namespace_id: "actual-account/configured-namespace".into(),
                    generation: 1,
                    digest: desired.digest
                }
            )
            .await
            .is_err()
    );
}

#[test]
fn authority_operator_protojson_preserves_unknown_state_then_conversion_rejects_it() {
    let input = pb::StorageAuthorityDecision {
        input: Some(pb::storage_authority_decision::Input::SetAdmission(
            pb::SetStorageAuthorityAdmissionDecision {
                authority_id: AUTHORITY.into(),
                expected_generation: "0".into(),
                expected_digest: None,
                guard_namespace_id: "actual-account/configured-namespace".into(),
                state: 99,
                attestation_id: None,
                association_ids: vec![],
            },
        )),
    };
    let json = serde_json::to_value(&input).unwrap();
    assert_eq!(json["setAdmission"]["state"], 99);
    let decoded: pb::StorageAuthorityDecision = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, input);
    assert!(matches!(
        conversion::decision(Some(decoded)),
        Err(RpcError::InvalidArgument(_))
    ));

    let mut conflicting = serde_json::to_value(create()).unwrap();
    conflicting["setAdmission"] = serde_json::json!({"authorityId": AUTHORITY});
    assert!(serde_json::from_value::<pb::StorageAuthorityDecision>(conflicting).is_err());
}

#[test]
fn authority_operator_requires_an_explicit_canonical_immutable_prefix_ceiling() {
    let mut input = create();
    let Some(pb::storage_authority_decision::Input::Create(value)) = &mut input.input else {
        panic!("fixture is a create decision");
    };
    value.qualified_managed_prefix = None;
    assert!(matches!(
        conversion::decision(Some(input)),
        Err(RpcError::InvalidArgument(_))
    ));

    let mut input = create();
    let Some(pb::storage_authority_decision::Input::Create(value)) = &mut input.input else {
        panic!("fixture is a create decision");
    };
    value.qualified_managed_prefix = Some("fresh/../outside".into());
    assert!(matches!(
        conversion::decision(Some(input)),
        Err(RpcError::InvalidArgument(_))
    ));

    let mut input = create();
    let Some(pb::storage_authority_decision::Input::Create(value)) = &mut input.input else {
        panic!("fixture is a create decision");
    };
    value.qualified_managed_prefix = Some(String::new());
    let StorageAuthorityDecisionInput::Create(value) = conversion::decision(Some(input)).unwrap()
    else {
        panic!("fixture is a create decision");
    };
    assert!(value.qualified_managed_prefix.is_empty());
}

#[test]
fn authority_operator_preserves_historical_attestation_input_for_exact_result_replay() {
    let input = pb::StorageAuthorityDecision {
        input: Some(pb::storage_authority_decision::Input::Attest(
            pb::AttestStorageAuthorityExclusivityDecision {
                attestation_id: "historical-attestation".into(),
                authority_id: AUTHORITY.into(),
                managed_prefix: "fresh".into(),
                qualification_digest: "2".repeat(64),
                provider_policy_evidence_digest: "5".repeat(64),
                executor_identity: "configured-executor".into(),
                credentials: vec![pb::StorageAuthorityCredentialMember {
                    association_id: "association-one".into(),
                    purpose: "write".into(),
                    generation: "1".into(),
                    secret_version_ref: "secret://historical/write/v1".into(),
                    credential_fingerprint: "4".repeat(64),
                }],
                valid_until: 1,
            },
        )),
    };
    let StorageAuthorityDecisionInput::Attest(specification) =
        conversion::decision(Some(input)).unwrap()
    else {
        panic!("fixture is an attestation decision");
    };
    assert_eq!(specification.valid_until, 1);
}
