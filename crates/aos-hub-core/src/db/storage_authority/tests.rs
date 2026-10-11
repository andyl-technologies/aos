//! Public database behavior for reviewed physical identity and reconciliation.

use super::*;
use crate::db::{NewBindingWriteRevision, NewTopologyPlan, MIGRATIONS};
use crate::storage_authority::{
    GuardIncarnation, StorageAuthorityAliasSpec, StorageAuthorityCredentialMember,
    StorageGuardStamp,
};

fn authority() -> CreatePhysicalStorageAuthority {
    CreatePhysicalStorageAuthority {
        authority_id: PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000001")
            .unwrap(),
        guard_namespace_id: "account-one/namespace-one".into(),
        physical_resource_evidence_digest: "1".repeat(64),
        qualification_digest: "2".repeat(64),
        qualified_managed_prefix: "fresh".into(),
    }
}

#[test]
fn qualification_prefix_containment_requires_component_boundaries() {
    for prefix in ["foo/", "/foo", "foo//root", "foo/../root"] {
        assert!(validate_prefix(prefix).is_err());
    }

    for (candidate, expected) in [
        ("foo/root", true),
        ("foo/root/object", true),
        ("foo", false),
        ("foo/root-other", false),
        ("foobar/root", false),
        ("", false),
    ] {
        validate_prefix(candidate).unwrap();
        assert_eq!(within_prefix(candidate, "foo/root"), expected);
        assert!(within_prefix(candidate, ""));
    }
}

#[tokio::test]
async fn qualification_ceiling_is_required_canonical_and_frozen_in_creation() {
    let db = Database::open_in_memory().await.unwrap();
    let mut legacy = serde_json::to_value(authority()).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("qualified_managed_prefix");
    assert!(serde_json::from_value::<CreatePhysicalStorageAuthority>(legacy).is_err());

    let mut whole_bucket = authority();
    whole_bucket.authority_id =
        PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000099").unwrap();
    whole_bucket.qualified_managed_prefix.clear();
    apply(
        &db,
        StorageAuthorityDecisionInput::Create(whole_bucket.clone()),
    )
    .await;
    assert_eq!(
        db.physical_storage_authority(&whole_bucket.authority_id)
            .await
            .unwrap(),
        Some(whole_bucket)
    );

    for prefix in ["/fresh", "fresh/", "fresh//root", "fresh/../root", " fresh"] {
        let mut changed = authority();
        changed.qualified_managed_prefix = prefix.into();
        let input = StorageAuthorityDecisionInput::Create(changed);
        let decision = review(&db, &input).await;
        assert!(db
            .apply_storage_authority_decision(&decision, &input)
            .await
            .is_err());
    }
    apply(&db, StorageAuthorityDecisionInput::Create(authority())).await;
    let mut widened = authority();
    widened.qualified_managed_prefix.clear();
    assert_ne!(
        canonical_digest(&widened).unwrap(),
        canonical_digest(&authority()).unwrap()
    );
    let input = StorageAuthorityDecisionInput::Create(widened);
    let decision = review(&db, &input).await;
    assert!(db
        .apply_storage_authority_decision(&decision, &input)
        .await
        .is_err());
    assert_eq!(
        db.physical_storage_authority(&authority().authority_id)
            .await
            .unwrap(),
        Some(authority())
    );

    let mut changed = authority();
    changed.qualified_managed_prefix = "fresh/root".into();
    db.backend.execute(
        "UPDATE physical_storage_authorities SET specification_json = ?2 WHERE authority_id = ?1",
        &vals![authority().authority_id.as_str(), serde_json::to_string(&changed).unwrap()],
    ).await.unwrap();
    assert!(db
        .physical_storage_authority(&authority().authority_id)
        .await
        .is_err());
}

#[tokio::test]
async fn qualified_ceiling_allows_narrowing_and_reopening_without_expansion() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("qualified.db");
    let restored_path = directory.path().join("restored.db");
    let db = Database::open(&path).await.unwrap();
    let (association, initial) = setup(&db).await;
    // The first attestation delivered to the executor may already be narrow.
    // Its scope does not replace the independently frozen creation ceiling.
    let mut narrow = initial.clone();
    narrow.attestation_id = "attestation-narrow".into();
    narrow.managed_prefix = association.binding_prefix.clone();
    apply(&db, StorageAuthorityDecisionInput::Attest(narrow.clone())).await;
    db.backend
        .query("PRAGMA wal_checkpoint(TRUNCATE)", &[])
        .await
        .unwrap();
    std::fs::copy(&path, &restored_path).unwrap();
    apply(&db, StorageAuthorityDecisionInput::Attest(initial.clone())).await;

    let mut reopened = initial.clone();
    reopened.attestation_id = "attestation-reopened".into();
    for (index, attestation) in [narrow, reopened].into_iter().enumerate() {
        if index == 1 {
            apply(
                &db,
                StorageAuthorityDecisionInput::Attest(attestation.clone()),
            )
            .await;
        }
        let current = db
            .desired_storage_authority_admission(&authority().authority_id)
            .await
            .unwrap();
        let desired = SetStorageAuthorityAdmission {
            authority_id: authority().authority_id,
            expected_generation: current.as_ref().map_or(0, |current| current.generation),
            expected_digest: current.map(|current| current.digest),
            guard_namespace_id: authority().guard_namespace_id,
            state: StorageAuthorityAdmissionState::Admitted,
            attestation_id: Some(attestation.attestation_id),
            association_ids: vec![association.association_id.clone()],
        };
        apply(&db, StorageAuthorityDecisionInput::SetAdmission(desired)).await;
        let current = db
            .desired_storage_authority_admission(&authority().authority_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.generation, i64::try_from(index + 1).unwrap());
    }

    for prefix in ["", "fre", "fresh-other"] {
        let mut expanded = initial.clone();
        expanded.attestation_id = format!("attestation-expanded-{}", prefix.len());
        expanded.managed_prefix = prefix.into();
        let input = StorageAuthorityDecisionInput::Attest(expanded.clone());
        let decision = review(&db, &input).await;
        assert!(db
            .apply_storage_authority_decision(&decision, &input)
            .await
            .is_err());
        assert!(db
            .storage_authority_attestation(&expanded.attestation_id)
            .await
            .unwrap()
            .is_none());
    }
    let restored = Database::open(&restored_path).await.unwrap();
    assert_eq!(
        restored
            .physical_storage_authority(&authority().authority_id)
            .await
            .unwrap(),
        Some(authority())
    );
    apply(&restored, StorageAuthorityDecisionInput::Attest(initial)).await;
}

fn alias() -> ApproveStorageAuthorityAlias {
    ApproveStorageAuthorityAlias {
        alias_id: "alias-one".into(),
        authority_id: authority().authority_id,
        spec: StorageAuthorityAliasSpec {
            host: StorageAuthorityHost::Dns("storage.example.invalid".into()),
            port: 443,
            bucket: "exclusive-bucket".into(),
        },
        equivalence_evidence_digest: "3".repeat(64),
    }
}

async fn review(
    db: &Database,
    input: &StorageAuthorityDecisionInput,
) -> ReviewedStorageAuthorityDecision {
    let plan_id = uuid::Uuid::new_v4().to_string();
    let confirmation_hash = canonical_digest(input).unwrap();
    db.create_topology_plan(&NewTopologyPlan {
        plan_id: plan_id.clone(),
        plan_kind: input.plan_kind().into(),
        actor_kind: "user".into(),
        actor_id: Some(7),
        actor_incarnation: None,
        actor_label: "root operator".into(),
        scope: "instance".into(),
        input_versions_json: serde_json::to_string(input).unwrap(),
        effects_json: "[]".into(),
        warnings_json: "[]".into(),
        confirmation_hash: Some(confirmation_hash.clone()),
        request_idempotency_key: Some(plan_id.clone()),
        expires_at: unix_now() + 300,
    })
    .await
    .unwrap();
    db.begin_topology_plan_apply(&plan_id, "apply-one")
        .await
        .unwrap();
    ReviewedStorageAuthorityDecision {
        plan_id,
        confirmation_hash,
        apply_idempotency_key: "apply-one".into(),
        actor_kind: "user".into(),
        actor_id: 7,
        actor_incarnation: None,
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

async fn setup(
    db: &Database,
) -> (
    AssociateStorageAuthorityBinding,
    AttestStorageAuthorityExclusivity,
) {
    apply(db, StorageAuthorityDecisionInput::Create(authority())).await;
    apply(db, StorageAuthorityDecisionInput::ApproveAlias(alias())).await;

    let org_id = db
        .create_org("authority-owner", "Authority owner")
        .await
        .unwrap();
    let owner = db.org_by_id(org_id).await.unwrap().unwrap();
    let binding_id = db
        .create_topology_binding(
            Some(org_id),
            "binding-one",
            &owner.stable_id,
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
    let credential = db
        .set_binding_credential_revision(
            binding_id,
            "write",
            "secret://authority/write/v1",
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
            revision_fingerprint: "authority-writer-one".into(),
            capability_fingerprint: "unconditional-write".into(),
        })
        .await
        .unwrap();
    let binding = db.binding(binding_id).await.unwrap().unwrap();
    let association = AssociateStorageAuthorityBinding {
        association_id: "association-one".into(),
        authority_id: authority().authority_id,
        alias_id: alias().alias_id,
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
        attestation_id: "attestation-one".into(),
        authority_id: authority().authority_id,
        managed_prefix: "fresh".into(),
        qualification_digest: authority().qualification_digest,
        provider_policy_evidence_digest: "5".repeat(64),
        executor_identity: "approved-executor-one".into(),
        credentials: vec![StorageAuthorityCredentialMember {
            association_id: association.association_id.clone(),
            purpose: "write".into(),
            generation: credential.generation,
            secret_version_ref: credential.secret_version_ref,
            credential_fingerprint: credential.credential_fingerprint,
        }],
        valid_until: unix_now() + 600,
    };
    (association, attestation)
}

async fn admit(db: &Database) -> StorageAuthorityRemoteWatermark {
    let (association, attestation) = setup(db).await;
    apply(
        db,
        StorageAuthorityDecisionInput::Attest(attestation.clone()),
    )
    .await;
    apply(
        db,
        StorageAuthorityDecisionInput::SetAdmission(SetStorageAuthorityAdmission {
            authority_id: authority().authority_id,
            expected_generation: 0,
            expected_digest: None,
            guard_namespace_id: authority().guard_namespace_id,
            state: StorageAuthorityAdmissionState::Admitted,
            attestation_id: Some(attestation.attestation_id),
            association_ids: vec![association.association_id],
        }),
    )
    .await;
    let desired = db
        .desired_storage_authority_admission(&authority().authority_id)
        .await
        .unwrap()
        .unwrap();
    StorageAuthorityRemoteWatermark {
        authority_id: authority().authority_id,
        guard_namespace_id: authority().guard_namespace_id,
        generation: desired.generation,
        digest: desired.digest,
    }
}

#[tokio::test]
async fn authority_decision_requires_root_scope_exact_actor_input_and_reservation() {
    let db = Database::open_in_memory().await.unwrap();
    let input = StorageAuthorityDecisionInput::Create(authority());
    let decision = review(&db, &input).await;
    let mut other_actor = decision.clone();
    other_actor.actor_id = 8;
    assert!(db
        .apply_storage_authority_decision(&other_actor, &input)
        .await
        .is_err());

    let mut wrong_hash = decision.clone();
    wrong_hash.confirmation_hash = "0".repeat(64);
    assert!(db
        .apply_storage_authority_decision(&wrong_hash, &input)
        .await
        .is_err());
    let mut changed = authority();
    changed.guard_namespace_id = "another-namespace".into();
    assert!(db
        .apply_storage_authority_decision(
            &decision,
            &StorageAuthorityDecisionInput::Create(changed)
        )
        .await
        .is_err());

    db.backend
        .execute(
            "UPDATE topology_plans SET scope = 'org:untrusted' WHERE plan_id = ?1",
            &vals![decision.plan_id],
        )
        .await
        .unwrap();
    assert!(db
        .apply_storage_authority_decision(&decision, &input)
        .await
        .is_err());
    db.backend.execute("UPDATE topology_plans SET scope = 'instance', apply_idempotency_key = NULL WHERE plan_id = ?1", &vals![decision.plan_id]).await.unwrap();
    assert!(db
        .apply_storage_authority_decision(&decision, &input)
        .await
        .is_err());
    db.begin_topology_plan_apply(&decision.plan_id, &decision.apply_idempotency_key)
        .await
        .unwrap();

    let (first, concurrent_retry) = tokio::join!(
        db.apply_storage_authority_decision(&decision, &input),
        db.apply_storage_authority_decision(&decision, &input),
    );
    let result = first.unwrap();
    assert_eq!(concurrent_retry.unwrap(), result);
    assert_eq!(
        db.apply_storage_authority_decision(&decision, &input)
            .await
            .unwrap(),
        result
    );
    assert_eq!(
        db.physical_storage_authority(&authority().authority_id)
            .await
            .unwrap(),
        Some(authority())
    );
}

#[tokio::test]
async fn authority_identity_and_canonical_alias_ownership_are_permanent() {
    let db = Database::open_in_memory().await.unwrap();
    apply(&db, StorageAuthorityDecisionInput::Create(authority())).await;
    apply(&db, StorageAuthorityDecisionInput::ApproveAlias(alias())).await;

    let mut changed_authority = authority();
    changed_authority.guard_namespace_id = "changed-namespace".into();
    let input = StorageAuthorityDecisionInput::Create(changed_authority);
    let decision = review(&db, &input).await;
    assert!(db
        .apply_storage_authority_decision(&decision, &input)
        .await
        .is_err());
    assert!(db
        .topology_plan(&decision.plan_id)
        .await
        .unwrap()
        .unwrap()
        .applied_at
        .is_none());

    let mut second_authority = authority();
    second_authority.authority_id =
        PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000002").unwrap();
    // One actual executor namespace can retain multiple physical domains.
    // The permanent authority ID keeps their guards separate, while exact
    // aliases remain globally reserved to one root-approved authority.
    apply(
        &db,
        StorageAuthorityDecisionInput::Create(second_authority.clone()),
    )
    .await;
    assert_eq!(
        db.physical_storage_authority(&second_authority.authority_id)
            .await
            .unwrap(),
        Some(second_authority.clone())
    );
    let mut stolen_alias = alias();
    stolen_alias.alias_id = "alias-two".into();
    stolen_alias.authority_id = second_authority.authority_id;
    let input = StorageAuthorityDecisionInput::ApproveAlias(stolen_alias);
    let decision = review(&db, &input).await;
    assert!(db
        .apply_storage_authority_decision(&decision, &input)
        .await
        .is_err());
    assert_eq!(
        db.physical_storage_alias("alias-one").await.unwrap(),
        Some(alias())
    );
    assert!(db
        .physical_storage_alias("alias-two")
        .await
        .unwrap()
        .is_none());

    let mut noncanonical = alias().spec;
    noncanonical.host = StorageAuthorityHost::Dns("Storage.Example.Invalid".into());
    assert!(noncanonical.digest().is_err());
}

#[tokio::test]
async fn binding_associations_retain_exact_revision_prefix_and_alias() {
    let db = Database::open_in_memory().await.unwrap();
    let (association, _) = setup(&db).await;
    for mutate in ["prefix", "version", "writer", "identity", "alias"] {
        let mut changed = association.clone();
        changed.association_id = format!("bad-{mutate}");
        match mutate {
            "prefix" => changed.binding_prefix = "another/root".into(),
            "version" => changed.binding_resource_version += 1,
            "writer" => changed.binding_write_revision += 1,
            "identity" => changed.binding_stable_id = "another-binding".into(),
            "alias" => changed.alias_id = "another-alias".into(),
            _ => unreachable!(),
        }
        let input = StorageAuthorityDecisionInput::AssociateBinding(changed.clone());
        let decision = review(&db, &input).await;
        assert!(db
            .apply_storage_authority_decision(&decision, &input)
            .await
            .is_err());
        assert!(db
            .binding_storage_authority_association(&changed.association_id)
            .await
            .unwrap()
            .is_none());
        assert!(db
            .topology_plan(&decision.plan_id)
            .await
            .unwrap()
            .unwrap()
            .applied_at
            .is_none());
    }

    db.backend.execute("UPDATE bindings SET resource_version = resource_version + 1, object_prefix = 'next/root' WHERE id = ?1", &vals![association.binding_id]).await.unwrap();
    assert_eq!(
        db.binding_storage_authority_association(&association.association_id)
            .await
            .unwrap(),
        Some(association)
    );
}

#[tokio::test]
async fn attestation_binds_initial_qualification_exact_credentials_and_scope() {
    let db = Database::open_in_memory().await.unwrap();
    let (_, attestation) = setup(&db).await;
    for mutate in ["credential", "scope", "qualification", "expired"] {
        let mut changed = attestation.clone();
        changed.attestation_id = format!("bad-{mutate}");
        match mutate {
            "credential" => changed.credentials[0].credential_fingerprint = "6".repeat(64),
            "scope" => changed.managed_prefix = "fresh/root-other".into(),
            "qualification" => changed.qualification_digest = "7".repeat(64),
            "expired" => changed.valid_until = unix_now() - 1,
            _ => unreachable!(),
        }
        let input = StorageAuthorityDecisionInput::Attest(changed.clone());
        let decision = review(&db, &input).await;
        assert!(db
            .apply_storage_authority_decision(&decision, &input)
            .await
            .is_err());
        assert!(db
            .storage_authority_attestation(&changed.attestation_id)
            .await
            .unwrap()
            .is_none());
        assert!(db
            .topology_plan(&decision.plan_id)
            .await
            .unwrap()
            .unwrap()
            .applied_at
            .is_none());
    }
    apply(
        &db,
        StorageAuthorityDecisionInput::Attest(attestation.clone()),
    )
    .await;
    assert_eq!(
        db.storage_authority_attestation(&attestation.attestation_id)
            .await
            .unwrap(),
        Some(attestation)
    );
}

#[tokio::test]
async fn admission_requires_remote_reconciliation_and_monotonic_immutable_namespace() {
    let db = Database::open_in_memory().await.unwrap();
    let remote = admit(&db).await;
    assert!(db
        .storage_authority_admission_for_remote(&remote)
        .await
        .is_err());
    db.reconcile_storage_authority_watermark(&remote)
        .await
        .unwrap();
    let current = db
        .storage_authority_admission_for_remote(&remote)
        .await
        .unwrap();

    let mut changed = current.specification.clone();
    changed.expected_generation = current.generation;
    changed.expected_digest = Some(current.digest.clone());
    changed.guard_namespace_id = "changed-namespace".into();
    let input = StorageAuthorityDecisionInput::SetAdmission(changed);
    let decision = review(&db, &input).await;
    assert!(db
        .apply_storage_authority_decision(&decision, &input)
        .await
        .is_err());

    let blocked = SetStorageAuthorityAdmission {
        authority_id: authority().authority_id,
        expected_generation: current.generation,
        expected_digest: Some(current.digest),
        guard_namespace_id: authority().guard_namespace_id,
        state: StorageAuthorityAdmissionState::Blocked,
        attestation_id: None,
        association_ids: Vec::new(),
    };
    apply(
        &db,
        StorageAuthorityDecisionInput::SetAdmission(blocked.clone()),
    )
    .await;
    assert!(db
        .storage_authority_admission_for_remote(&remote)
        .await
        .is_err());
    assert!(db
        .reconcile_storage_authority_watermark(&remote)
        .await
        .is_err());
    let input = StorageAuthorityDecisionInput::SetAdmission(blocked);
    let decision = review(&db, &input).await;
    assert!(db
        .apply_storage_authority_decision(&decision, &input)
        .await
        .is_err());

    let current = db
        .desired_storage_authority_admission(&authority().authority_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.generation, 2);
    let mut retired = current.specification;
    retired.expected_generation = current.generation;
    retired.expected_digest = Some(current.digest);
    retired.state = StorageAuthorityAdmissionState::Retired;
    apply(&db, StorageAuthorityDecisionInput::SetAdmission(retired)).await;
    let current = db
        .desired_storage_authority_admission(&authority().authority_id)
        .await
        .unwrap()
        .unwrap();
    let mut resurrect = current.specification;
    resurrect.expected_generation = current.generation;
    resurrect.expected_digest = Some(current.digest);
    resurrect.state = StorageAuthorityAdmissionState::Blocked;
    let input = StorageAuthorityDecisionInput::SetAdmission(resurrect);
    let decision = review(&db, &input).await;
    assert!(db
        .apply_storage_authority_decision(&decision, &input)
        .await
        .is_err());
}

#[tokio::test]
async fn restored_sql_acknowledgement_cannot_reopen_remote_revocation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hub.db");
    let restored_path = directory.path().join("restored.db");
    let db = Database::open(&path).await.unwrap();
    let admitted = admit(&db).await;
    db.reconcile_storage_authority_watermark(&admitted)
        .await
        .unwrap();
    db.storage_authority_admission_for_remote(&admitted)
        .await
        .unwrap();
    db.backend
        .query("PRAGMA wal_checkpoint(TRUNCATE)", &[])
        .await
        .unwrap();
    std::fs::copy(&path, &restored_path).unwrap();

    apply(
        &db,
        StorageAuthorityDecisionInput::SetAdmission(SetStorageAuthorityAdmission {
            authority_id: admitted.authority_id.clone(),
            expected_generation: admitted.generation,
            expected_digest: Some(admitted.digest),
            guard_namespace_id: admitted.guard_namespace_id.clone(),
            state: StorageAuthorityAdmissionState::Blocked,
            attestation_id: None,
            association_ids: Vec::new(),
        }),
    )
    .await;
    let current = db
        .desired_storage_authority_admission(&admitted.authority_id)
        .await
        .unwrap()
        .unwrap();
    let remote_revoked = StorageAuthorityRemoteWatermark {
        authority_id: admitted.authority_id,
        guard_namespace_id: admitted.guard_namespace_id,
        generation: current.generation,
        digest: current.digest,
    };
    db.reconcile_storage_authority_watermark(&remote_revoked)
        .await
        .unwrap();

    let restored = Database::open(&restored_path).await.unwrap();
    assert_eq!(
        restored
            .desired_storage_authority_admission(&remote_revoked.authority_id)
            .await
            .unwrap()
            .unwrap()
            .generation,
        1
    );
    assert!(restored
        .storage_authority_admission_for_remote(&remote_revoked)
        .await
        .is_err());
    assert!(restored
        .reconcile_storage_authority_watermark(&remote_revoked)
        .await
        .is_err());
}

#[test]
fn guard_stamp_is_distinct_exact_and_rejects_invalid_generations() {
    let stamp = StorageGuardStamp {
        physical_authority_id: authority().authority_id,
        incarnation: GuardIncarnation::parse("9007199254740991").unwrap(),
    };
    let encoded = serde_json::to_string(&stamp).unwrap();
    assert!(encoded.contains("\"incarnation\":\"9007199254740991\""));
    assert!(!encoded.contains("provider_version"));
    assert_eq!(
        serde_json::from_str::<StorageGuardStamp>(&encoded).unwrap(),
        stamp
    );
    for invalid in ["0", "-1", "01", "9007199254740992"] {
        assert!(GuardIncarnation::parse(invalid).is_err());
    }
    assert!(
        serde_json::from_str::<StorageGuardStamp>(&encoded.replace("9007199254740991", "0"))
            .is_err()
    );
}

#[test]
fn authority_migration_preserves_baseline_and_does_not_adopt_legacy_storage() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection.execute_batch(MIGRATIONS[0]).unwrap();
    connection
        .execute_batch(
            "INSERT INTO bindings(id, name, kind, is_instance_default, instance_default_key,
          created_at, stable_id, owner_scope_key, local_root_path, updated_at)
         VALUES(123, 'legacy', 'local_fs', 1, 'singleton', 1, 'legacy-binding',
                'instance', '/legacy/root', 1);",
        )
        .unwrap();
    connection.execute_batch(MIGRATIONS[1]).unwrap();
    let old_binding_count: i64 = connection
        .query_row("SELECT count(*) FROM bindings", [], |r| r.get(0))
        .unwrap();
    connection.execute_batch(MIGRATIONS[2]).unwrap();
    let authority_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM physical_storage_authorities",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let association_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM binding_storage_authority_revisions",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let binding_count: i64 = connection
        .query_row("SELECT count(*) FROM bindings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(authority_count, 0);
    assert_eq!(association_count, 0);
    assert_eq!(old_binding_count, 1);
    assert_eq!(binding_count, old_binding_count);
}

#[tokio::test]
async fn association_transaction_rechecks_stable_identity_and_physical_coordinates() {
    for field in [
        "stable_id",
        "object_bucket",
        "endpoint_host_bytes",
        "endpoint_port",
    ] {
        let db = Database::open_in_memory().await.unwrap();
        let (mut association, _) = setup(&db).await;
        association.association_id = format!("racing-{field}");
        association.binding_resource_version += 1;
        db.backend
            .execute(
                "UPDATE bindings SET resource_version = resource_version + 1 WHERE id = ?1",
                &vals![association.binding_id],
            )
            .await
            .unwrap();
        let input = StorageAuthorityDecisionInput::AssociateBinding(association.clone());
        let decision = review(&db, &input).await;
        let plan = db.reviewed_authority_plan(&decision, &input).await.unwrap();
        let (_, mutations) = db
            .prepare_association(&association, &plan, unix_now())
            .await
            .unwrap();

        // Simulate coordinate drift between the precheck and transaction without
        // a new resource version. The atomic predicate independently retains
        // the exact reviewed identity rather than trusting the earlier read.
        let mutation = match field {
            "stable_id" => "UPDATE bindings SET stable_id = 'reused-binding-id' WHERE id = ?1",
            "object_bucket" => "UPDATE bindings SET object_bucket = 'another-bucket' WHERE id = ?1",
            "endpoint_host_bytes" => "UPDATE bindings SET endpoint_host_bytes = ?2 WHERE id = ?1",
            "endpoint_port" => "UPDATE bindings SET endpoint_port = 8443 WHERE id = ?1",
            _ => unreachable!(),
        };
        let parameters = if field == "endpoint_host_bytes" {
            vals![
                association.binding_id,
                b"another.example.invalid".as_slice()
            ]
        } else {
            vals![association.binding_id]
        };
        db.backend.execute(mutation, &parameters).await.unwrap();

        assert!(
            db.backend.checked_batch(&mutations).await.is_err(),
            "drifted {field} was accepted"
        );
        assert!(db
            .binding_storage_authority_association(&association.association_id)
            .await
            .unwrap()
            .is_none());
    }
}

struct AdmissionReadPause {
    armed: std::sync::atomic::AtomicBool,
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

struct PausingAdmissionBackend {
    inner: Box<dyn crate::backend::Backend>,
    pause: std::sync::Arc<AdmissionReadPause>,
}

#[async_trait::async_trait]
impl crate::backend::Backend for PausingAdmissionBackend {
    fn dialect(&self) -> crate::dialect::Dialect {
        self.inner.dialect()
    }

    async fn migrate_schema(&self) -> anyhow::Result<()> {
        self.inner.migrate_schema().await
    }

    async fn execute(&self, sql: &str, params: &[crate::value::Value]) -> Result<u64> {
        self.inner.execute(sql, params).await
    }

    async fn execute_insert(&self, sql: &str, params: &[crate::value::Value]) -> Result<i64> {
        self.inner.execute_insert(sql, params).await
    }

    async fn query(
        &self,
        sql: &str,
        params: &[crate::value::Value],
    ) -> Result<Vec<crate::value::Row>> {
        if sql.contains("FROM storage_authority_admission_heads head")
            && self
                .pause
                .armed
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.pause.reached.notify_one();
            self.pause.resume.notified().await;
        }
        self.inner.query(sql, params).await
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        self.inner.execute_batch(sql).await
    }

    async fn batch(&self, statements: &[Statement]) -> Result<()> {
        self.inner.batch(statements).await
    }

    async fn checked_batch(&self, statements: &[CheckedStatement]) -> Result<()> {
        self.inner.checked_batch(statements).await
    }
}

#[tokio::test]
async fn exact_admission_retry_recovers_commit_during_preparation() {
    let original = Database::open_in_memory().await.unwrap();
    apply(
        &original,
        StorageAuthorityDecisionInput::Create(authority()),
    )
    .await;
    let input = StorageAuthorityDecisionInput::SetAdmission(SetStorageAuthorityAdmission {
        authority_id: authority().authority_id,
        expected_generation: 0,
        expected_digest: None,
        guard_namespace_id: authority().guard_namespace_id,
        state: StorageAuthorityAdmissionState::Blocked,
        attestation_id: None,
        association_ids: Vec::new(),
    });
    let decision = review(&original, &input).await;
    let different_plan = review(&original, &input).await;
    let pause = std::sync::Arc::new(AdmissionReadPause {
        armed: std::sync::atomic::AtomicBool::new(true),
        reached: tokio::sync::Notify::new(),
        resume: tokio::sync::Notify::new(),
    });
    let db = std::sync::Arc::new(Database::attach(Box::new(PausingAdmissionBackend {
        inner: original.backend,
        pause: pause.clone(),
    })));
    let retry_db = db.clone();
    let retry_decision = decision.clone();
    let retry_input = input.clone();
    let retry = tokio::spawn(async move {
        retry_db
            .apply_storage_authority_decision(&retry_decision, &retry_input)
            .await
    });

    // The retry has read the unapplied plan but has not read the current head.
    // Commit the exact same decision before releasing that preparation read.
    tokio::time::timeout(std::time::Duration::from_secs(5), pause.reached.notified())
        .await
        .unwrap();
    let committed = db
        .apply_storage_authority_decision(&decision, &input)
        .await
        .unwrap();
    pause.resume.notify_one();
    let recovered = tokio::time::timeout(std::time::Duration::from_secs(5), retry)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(recovered, committed);
    assert_eq!(committed.admission_generation, Some(1));

    // The same stale input under a different plan retains its CAS failure.
    assert!(db
        .apply_storage_authority_decision(&different_plan, &input)
        .await
        .is_err());
    assert!(db
        .topology_plan(&different_plan.plan_id)
        .await
        .unwrap()
        .unwrap()
        .applied_at
        .is_none());
    assert_eq!(
        db.desired_storage_authority_admission(&authority().authority_id)
            .await
            .unwrap()
            .unwrap()
            .generation,
        1
    );
}

mod publication;
