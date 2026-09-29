//! Operator authorization, typed decision persistence and exact replay behavior.

use super::*;
use crate::db::NewBindingWriteRevision;
use crate::domain::{Principal, Role};

const AUTHORITY: &str = "00000000-0000-4000-8000-000000000001";

async fn fixture() -> (RpcService, String, i64) {
    let (service, db) = super::super::cache_upload_tests::delivery_test_service().await;
    let user = db
        .user_by_email("writer@example.test")
        .await
        .unwrap()
        .unwrap();
    let auth = token(&service, user, Scope::root()).await;
    (service, auth, user)
}

async fn token(service: &RpcService, user: i64, scope: Scope) -> String {
    let auth = if scope == Scope::root() {
        super::super::authentication::browser_test_auth(
            &service.db,
            user,
            vec![Permission::StorageManage],
        )
        .await
    } else {
        super::super::authentication::provisioned_test_auth(
            &service.db,
            Principal::user(user),
            scope,
            &[Permission::StorageManage],
        )
        .await
    };
    let jwt = service.jwt_keys.mint(&auth, 3600).unwrap();
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
) -> pb::TopologyPlanResponse {
    let expected_resource_version = service
        .storage_authority_resource_version(&conversion::decision(Some(input.clone())).unwrap())
        .await
        .unwrap();
    let denied = service
        .plan_storage_authority_decision(
            Some(auth),
            pb::PlanStorageAuthorityDecisionRequest {
                decision: Some(input.clone()),
                idempotency_key: format!("{key}-wrong-version"),
                expected_resource_version: format!("wrong-{expected_resource_version}"),
            },
        )
        .await;
    assert!(matches!(denied, Err(RpcError::FailedPrecondition(_))));

    service
        .plan_storage_authority_decision(
            Some(auth),
            pb::PlanStorageAuthorityDecisionRequest {
                decision: Some(input),
                idempotency_key: key.into(),
                expected_resource_version,
            },
        )
        .await
        .unwrap()
}

fn apply_request(
    plan: &pb::TopologyPlanResponse,
    key: &str,
) -> pb::ApplyStorageAuthorityDecisionRequest {
    let control = plan.plan.as_ref().unwrap();
    pb::ApplyStorageAuthorityDecisionRequest {
        plan_id: control.plan_id.clone(),
        confirmation_hash: control.confirmation_hash.clone(),
        idempotency_key: key.into(),
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
    let org_token = token(&service, user, Scope::parse(&org.stable_id)).await;
    let broad_token = token(&service, user, Scope::root()).await;
    let approved = plan(&service, &root, create(), "root-plan").await;

    for auth in [None, Some(org_token.as_str()), Some(broad_token.as_str())] {
        let denied = service
            .plan_storage_authority_decision(
                auth,
                pb::PlanStorageAuthorityDecisionRequest {
                    decision: Some(create()),
                    idempotency_key: "denied-plan".into(),
                    expected_resource_version: String::new(),
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
    assert!(service
        .db
        .physical_storage_authority(&conversion::authority_id(AUTHORITY).unwrap())
        .await
        .unwrap()
        .is_none());
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
    assert!(service
        .db
        .physical_storage_authority(&conversion::authority_id(AUTHORITY).unwrap())
        .await
        .unwrap()
        .is_none());

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
                    idempotency_key: "revoked-plan".into(),
                    expected_resource_version: String::new(),
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
                    idempotency_key: "exact-plan".into(),
                    expected_resource_version: String::new(),
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
                Some(&token(&service, other, Scope::root()).await),
                request.clone()
            )
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
    // Apply has no mutable intent field. Even a corrupt stored review cannot
    // change the applied input while keeping the operator confirmation.
    let stored = service
        .db
        .topology_plan(&request.plan_id)
        .await
        .unwrap()
        .unwrap();
    let mut changed_review: StorageAuthorityReviewedPlanInput =
        serde_json::from_str(&stored.input_versions_json).unwrap();
    changed_review.decision = conversion::decision(Some(changed)).unwrap();
    service
        .db
        .backend
        .execute(
            "UPDATE topology_plans SET input_versions_json = ?2 WHERE plan_id = ?1",
            &[
                crate::value::Value::Text(request.plan_id.clone()),
                crate::value::Value::Text(serde_json::to_string(&changed_review).unwrap()),
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
    service
        .db
        .backend
        .execute(
            "UPDATE topology_plans SET input_versions_json = ?2 WHERE plan_id = ?1",
            &[
                crate::value::Value::Text(request.plan_id.clone()),
                crate::value::Value::Text(stored.input_versions_json),
            ],
        )
        .await
        .unwrap();
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

    // Exact request replay remains available after creation now exists.
    assert_eq!(
        plan(&service, &root, create(), "exact-plan").await,
        approved
    );
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
    assert!(service
        .db
        .topology_plan(&request.plan_id)
        .await
        .unwrap()
        .unwrap()
        .apply_idempotency_key
        .is_none());
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
    let admission_input = pb::StorageAuthorityDecision {
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
    };
    let admission_plan = plan(&service, &root, admission_input.clone(), "admission").await;
    let response = service
        .apply_storage_authority_decision(
            Some(&root),
            apply_request(&admission_plan, "admission-apply"),
        )
        .await
        .unwrap();
    assert_eq!(
        plan(&service, &root, admission_input.clone(), "admission").await,
        admission_plan
    );

    let stale = service
        .plan_storage_authority_decision(
            Some(&root),
            pb::PlanStorageAuthorityDecisionRequest {
                decision: Some(admission_input),
                idempotency_key: "new-stale-admission".into(),
                expected_resource_version: "0".into(),
            },
        )
        .await;
    assert!(matches!(stale, Err(RpcError::FailedPrecondition(_))));
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
        projection.resource_version,
        canonical_digest(
            &service
                .db
                .physical_storage_authority(&conversion::authority_id(AUTHORITY).unwrap())
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap()
    );
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
    assert!(service
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
        .is_err());
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

#[tokio::test]
async fn authority_operator_freezes_parent_version_across_restore_and_replay() {
    let (service, root, _) = fixture().await;
    apply(&service, &root, create(), "create-for-parent-review").await;
    let decision = pb::StorageAuthorityDecision {
        input: Some(pb::storage_authority_decision::Input::ApproveAlias(
            pb::ApproveStorageAuthorityAliasDecision {
                alias_id: "restored-parent-alias".into(),
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
    };
    let reviewed = plan(&service, &root, decision.clone(), "frozen-parent-plan").await;
    let original = service
        .db
        .physical_storage_authority(&conversion::authority_id(AUTHORITY).unwrap())
        .await
        .unwrap()
        .unwrap();
    let original_version = canonical_digest(&original).unwrap();
    let mut restored = original.clone();
    restored.physical_resource_evidence_digest = "9".repeat(64);
    let restored_version = canonical_digest(&restored).unwrap();
    service.db.backend.execute(
        "UPDATE physical_storage_authorities SET specification_json = ?2, specification_digest = ?3 WHERE authority_id = ?1",
        &[crate::value::Value::Text(AUTHORITY.into()),
          crate::value::Value::Text(serde_json::to_string(&restored).unwrap()),
          crate::value::Value::Text(restored_version.clone())],
    ).await.unwrap();

    // Original request replay returns its frozen review without rederivation.
    let replay = service
        .plan_storage_authority_decision(
            Some(&root),
            pb::PlanStorageAuthorityDecisionRequest {
                decision: Some(decision.clone()),
                idempotency_key: "frozen-parent-plan".into(),
                expected_resource_version: original_version,
            },
        )
        .await
        .unwrap();
    assert_eq!(replay, reviewed);
    let changed_version = service
        .plan_storage_authority_decision(
            Some(&root),
            pb::PlanStorageAuthorityDecisionRequest {
                decision: Some(decision),
                idempotency_key: "frozen-parent-plan".into(),
                expected_resource_version: restored_version,
            },
        )
        .await;
    assert!(matches!(
        changed_version,
        Err(RpcError::FailedPrecondition(_))
    ));
    assert!(matches!(
        service
            .apply_storage_authority_decision(
                Some(&root),
                apply_request(&reviewed, "frozen-parent-apply")
            )
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
    assert!(service
        .db
        .physical_storage_alias("restored-parent-alias")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn authority_operator_canonical_apply_rejects_unknown_duplicate_and_legacy_reviews() {
    let (service, root, _) = fixture().await;
    let approved = plan(&service, &root, create(), "closed-review").await;
    let request = apply_request(&approved, "closed-review-apply");
    let stored = service
        .db
        .topology_plan(&request.plan_id)
        .await
        .unwrap()
        .unwrap();
    let valid: serde_json::Value = serde_json::from_str(&stored.input_versions_json).unwrap();
    let mut unknown = valid.clone();
    unknown["schema_version"] = serde_json::json!(2);
    let legacy = valid["decision"].clone();
    let duplicate = stored
        .input_versions_json
        .replacen("{", "{\"schema_version\":1,", 1);
    for json in [unknown.to_string(), legacy.to_string(), duplicate] {
        service
            .db
            .backend
            .execute(
                "UPDATE topology_plans SET input_versions_json = ?2 WHERE plan_id = ?1",
                &[
                    crate::value::Value::Text(request.plan_id.clone()),
                    crate::value::Value::Text(json),
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
        assert!(service
            .db
            .topology_plan(&request.plan_id)
            .await
            .unwrap()
            .unwrap()
            .apply_idempotency_key
            .is_none());
    }
    assert!(service
        .db
        .physical_storage_authority(&conversion::authority_id(AUTHORITY).unwrap())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn authority_operator_replacement_uuid_cannot_apply_or_replay_original_plan() {
    use crate::value::Value;

    let (service, original, user) = fixture().await;
    let reviewed = plan(&service, &original, create(), "original-incarnation-plan").await;
    let request = apply_request(&reviewed, "original-incarnation-apply");
    let result = service
        .apply_storage_authority_decision(Some(&original), request.clone())
        .await
        .unwrap();
    assert_eq!(result.authority_id, AUTHORITY);

    service.db.delete_user(user).await.unwrap();
    service
        .db
        .backend
        .execute("DELETE FROM users WHERE id = ?1", &[Value::Int(user)])
        .await
        .unwrap();
    let replacement = service
        .db
        .create_user("authority-replacement@example.test", None)
        .await
        .unwrap();
    assert_eq!(replacement, user);
    service
        .db
        .grant_membership("user", replacement, "instance", Role::Owner.as_str())
        .await
        .unwrap();
    let replacement_bearer = token(&service, replacement, Scope::root()).await;
    // A genuine current root token can read the shared authority, but cannot
    // inherit a former account's reviewed input or completed apply receipt.
    service
        .get_storage_authority(
            Some(&replacement_bearer),
            pb::GetStorageAuthorityRequest {
                authority_id: AUTHORITY.into(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        service
            .apply_storage_authority_decision(Some(&replacement_bearer), request)
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
    assert!(matches!(
        service
            .plan_storage_authority_decision(
                Some(&replacement_bearer),
                pb::PlanStorageAuthorityDecisionRequest {
                    decision: Some(create()),
                    idempotency_key: "original-incarnation-plan".into(),
                    expected_resource_version: String::new(),
                },
            )
            .await,
        Err(RpcError::FailedPrecondition(_))
    ));
}
