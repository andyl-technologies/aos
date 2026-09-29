//! Exercises immutable physical authority and admission on each live SQL dialect.

use aos_hub::db::Database;
use aos_hub_core::db::{
    NewBindingWriteRevision, NewTopologyPlan, ReviewedStorageAuthorityDecision,
    StorageAuthorityDecisionResult,
};
use aos_hub_core::storage_authority::{
    ApproveStorageAuthorityAlias, AssociateStorageAuthorityBinding,
    AttestStorageAuthorityExclusivity, CreatePhysicalStorageAuthority, PhysicalStorageAuthorityId,
    SetStorageAuthorityAdmission, StorageAuthorityAdmissionState, StorageAuthorityAliasSpec,
    StorageAuthorityCredentialMember, StorageAuthorityDecisionInput, StorageAuthorityHost,
    StorageAuthorityRemoteWatermark,
};
use sha2::{Digest, Sha256};

async fn review(
    db: &Database,
    input: &StorageAuthorityDecisionInput,
) -> ReviewedStorageAuthorityDecision {
    let plan_id = uuid::Uuid::new_v4().to_string();
    let confirmation_hash = hex::encode(Sha256::digest(serde_json::to_vec(input).unwrap()));

    db.create_topology_plan(&NewTopologyPlan {
        plan_id: plan_id.clone(),
        plan_kind: input.plan_kind().into(),
        actor_kind: "user".into(),
        actor_id: Some(7),
        actor_label: "dialect root operator".into(),
        scope: "instance".into(),
        input_versions_json: serde_json::to_string(input).unwrap(),
        effects_json: "[]".into(),
        warnings_json: "[]".into(),
        confirmation_hash: Some(confirmation_hash.clone()),
        request_idempotency_key: Some(plan_id.clone()),
        expires_at: aos_hub_core::clock::now_unix_secs() + 300,
    })
    .await
    .unwrap();

    db.begin_topology_plan_apply(&plan_id, "authority-dialect-apply")
        .await
        .unwrap();

    ReviewedStorageAuthorityDecision {
        plan_id,
        confirmation_hash,
        apply_idempotency_key: "authority-dialect-apply".into(),
        actor_kind: "user".into(),
        actor_id: 7,
    }
}

async fn apply(
    db: &Database,
    input: StorageAuthorityDecisionInput,
) -> StorageAuthorityDecisionResult {
    let decision = review(db, &input).await;
    db.apply_storage_authority_decision(&decision, &input)
        .await
        .unwrap()
}

pub(super) async fn exercise(db: &Database) {
    let authority = CreatePhysicalStorageAuthority {
        authority_id: PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000003")
            .unwrap(),
        guard_namespace_id: "dialect/external-guard-namespace".into(),
        physical_resource_evidence_digest: "1".repeat(64),
        qualification_digest: "2".repeat(64),
    };
    let create = StorageAuthorityDecisionInput::Create(authority.clone());
    let decision = review(db, &create).await;

    let created = db
        .apply_storage_authority_decision(&decision, &create)
        .await
        .unwrap();
    assert_eq!(
        db.apply_storage_authority_decision(&decision, &create)
            .await
            .unwrap(),
        created
    );
    assert_eq!(
        db.physical_storage_authority(&authority.authority_id)
            .await
            .unwrap(),
        Some(authority.clone())
    );

    let alias = ApproveStorageAuthorityAlias {
        alias_id: "dialect-physical-alias".into(),
        authority_id: authority.authority_id.clone(),
        spec: StorageAuthorityAliasSpec {
            host: StorageAuthorityHost::Dns("physical-dialect.example.invalid".into()),
            port: 443,
            bucket: "dialect-exclusive-bucket".into(),
        },
        equivalence_evidence_digest: "3".repeat(64),
    };
    apply(
        db,
        StorageAuthorityDecisionInput::ApproveAlias(alias.clone()),
    )
    .await;

    // One actual executor namespace can host separate physical bucket domains.
    let mut another = authority.clone();
    another.authority_id =
        PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000004").unwrap();
    another.physical_resource_evidence_digest = "9".repeat(64);
    apply(db, StorageAuthorityDecisionInput::Create(another.clone())).await;

    let mut conflicting_alias = alias.clone();
    conflicting_alias.alias_id = "dialect-conflicting-alias".into();
    conflicting_alias.authority_id = another.authority_id;
    let conflict = StorageAuthorityDecisionInput::ApproveAlias(conflicting_alias.clone());
    let conflicting_plan = review(db, &conflict).await;
    assert!(db
        .apply_storage_authority_decision(&conflicting_plan, &conflict)
        .await
        .is_err());
    assert!(db
        .physical_storage_alias(&conflicting_alias.alias_id)
        .await
        .unwrap()
        .is_none());
    assert!(db
        .topology_plan(&conflicting_plan.plan_id)
        .await
        .unwrap()
        .unwrap()
        .applied_at
        .is_none());

    let org_id = db
        .create_org("physical-authority-dialect", "Physical authority dialect")
        .await
        .unwrap();
    let owner = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            "dialect-physical-binding",
            &owner.stable_id,
            "exclusive",
            "s3",
            None,
            Some(&alias.spec.bucket),
            Some("fresh/root"),
            Some("https"),
            Some("dns"),
            Some(b"physical-dialect.example.invalid"),
            Some(443),
            Some("fixture-region"),
            Some("private"),
        )
        .await
        .unwrap();
    let credential = db
        .set_binding_credential_revision(
            binding_id,
            "write",
            "secret://physical-dialect/write/v1",
            0,
            &"4".repeat(64),
            "fixture",
        )
        .await
        .unwrap();
    let credential = db
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
    let writer = db
        .create_binding_write_revision(&NewBindingWriteRevision {
            binding_id,
            write_credential_generation: credential.generation,
            writes_supported: true,
            conditional_writes_supported: false,
            revision_fingerprint: "physical-dialect-writer".into(),
            capability_fingerprint: "physical-dialect-write".into(),
        })
        .await
        .unwrap();
    let binding = db.binding(binding_id).await.unwrap().unwrap();
    let association = AssociateStorageAuthorityBinding {
        association_id: "dialect-physical-association".into(),
        authority_id: authority.authority_id.clone(),
        alias_id: alias.alias_id,
        binding_id,
        binding_stable_id: binding.stable_id,
        binding_resource_version: binding.resource_version,
        binding_write_revision: writer.revision,
        binding_prefix: "fresh/root".into(),
    };
    apply(
        db,
        StorageAuthorityDecisionInput::AssociateBinding(association.clone()),
    )
    .await;
    let attestation = AttestStorageAuthorityExclusivity {
        attestation_id: "dialect-physical-attestation".into(),
        authority_id: authority.authority_id.clone(),
        managed_prefix: "fresh".into(),
        qualification_digest: authority.qualification_digest,
        provider_policy_evidence_digest: "5".repeat(64),
        executor_identity: "dialect-external-executor".into(),
        credentials: vec![StorageAuthorityCredentialMember {
            association_id: association.association_id.clone(),
            purpose: "write".into(),
            generation: credential.generation,
            secret_version_ref: credential.secret_version_ref,
            credential_fingerprint: credential.credential_fingerprint,
        }],
        valid_until: aos_hub_core::clock::now_unix_secs() + 600,
    };
    apply(
        db,
        StorageAuthorityDecisionInput::Attest(attestation.clone()),
    )
    .await;
    let admission = SetStorageAuthorityAdmission {
        authority_id: authority.authority_id.clone(),
        expected_generation: 0,
        expected_digest: None,
        guard_namespace_id: authority.guard_namespace_id.clone(),
        state: StorageAuthorityAdmissionState::Admitted,
        attestation_id: Some(attestation.attestation_id),
        association_ids: vec![association.association_id],
    };
    apply(db, StorageAuthorityDecisionInput::SetAdmission(admission)).await;

    let desired = db
        .desired_storage_authority_admission(&authority.authority_id)
        .await
        .unwrap()
        .unwrap();
    let remote = StorageAuthorityRemoteWatermark {
        authority_id: authority.authority_id.clone(),
        guard_namespace_id: authority.guard_namespace_id.clone(),
        generation: desired.generation,
        digest: desired.digest.clone(),
    };
    assert!(db
        .storage_authority_admission_for_remote(&remote)
        .await
        .is_err());
    db.reconcile_storage_authority_watermark(&remote)
        .await
        .unwrap();
    assert_eq!(
        db.storage_authority_admission_for_remote(&remote)
            .await
            .unwrap(),
        desired
    );

    let retired = SetStorageAuthorityAdmission {
        authority_id: authority.authority_id.clone(),
        expected_generation: desired.generation,
        expected_digest: Some(desired.digest),
        guard_namespace_id: authority.guard_namespace_id,
        state: StorageAuthorityAdmissionState::Retired,
        attestation_id: None,
        association_ids: Vec::new(),
    };
    apply(db, StorageAuthorityDecisionInput::SetAdmission(retired)).await;
    assert!(db
        .reconcile_storage_authority_watermark(&remote)
        .await
        .is_err());
    assert!(db
        .storage_authority_admission_for_remote(&remote)
        .await
        .is_err());

    // Retirement keeps the exact endpoint alias reserved indefinitely.
    assert_eq!(
        db.physical_storage_alias("dialect-physical-alias")
            .await
            .unwrap()
            .unwrap()
            .authority_id,
        authority.authority_id
    );
}
