//! Full immutable membership and current metadata refusal tests.

use super::*;

#[tokio::test]
async fn publication_retains_non_admitted_attestation_members_and_deduplicates_aliases() {
    let db = Database::open_in_memory().await.unwrap();
    let (first, mut attestation) = setup(&db).await;
    let binding = db.binding(first.binding_id).await.unwrap().unwrap();
    let owner = db
        .org_by_id(binding.org_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    let second_id = db
        .create_topology_binding(
            Some(owner.id),
            "binding-two",
            &owner.stable_id,
            "second",
            "s3",
            None,
            Some("exclusive-bucket"),
            Some("fresh/secondary"),
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
            second_id,
            "write",
            "secret://unresolved/second/v1",
            0,
            &"6".repeat(64),
            "fixture",
        )
        .await
        .unwrap();
    let credential = db
        .validate_binding_credential_revision(
            second_id,
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
            binding_id: second_id,
            write_credential_generation: credential.generation,
            writes_supported: true,
            conditional_writes_supported: false,
            revision_fingerprint: "second-writer".into(),
            capability_fingerprint: "write".into(),
        })
        .await
        .unwrap();
    let second = db.binding(second_id).await.unwrap().unwrap();
    let association = AssociateStorageAuthorityBinding {
        association_id: "association-two".into(),
        authority_id: authority().authority_id,
        alias_id: alias().alias_id,
        binding_id: second_id,
        binding_stable_id: second.stable_id,
        binding_resource_version: second.resource_version,
        binding_write_revision: writer.revision,
        binding_prefix: "fresh/secondary".into(),
    };
    apply(
        &db,
        StorageAuthorityDecisionInput::AssociateBinding(association.clone()),
    )
    .await;
    attestation
        .credentials
        .push(StorageAuthorityCredentialMember {
            association_id: association.association_id,
            purpose: "write".into(),
            generation: credential.generation,
            secret_version_ref: credential.secret_version_ref,
            credential_fingerprint: credential.credential_fingerprint,
        });
    apply(
        &db,
        StorageAuthorityDecisionInput::Attest(attestation.clone()),
    )
    .await;
    apply(
        &db,
        StorageAuthorityDecisionInput::SetAdmission(SetStorageAuthorityAdmission {
            authority_id: authority().authority_id,
            expected_generation: 0,
            expected_digest: None,
            guard_namespace_id: authority().guard_namespace_id,
            state: StorageAuthorityAdmissionState::Admitted,
            attestation_id: Some(attestation.attestation_id.clone()),
            association_ids: vec![first.association_id.clone()],
        }),
    )
    .await;

    let publication = db
        .storage_authority_publication(
            &authority().authority_id,
            &authority().guard_namespace_id,
            "approved-executor-one",
        )
        .await
        .unwrap();
    assert_eq!(publication.attestation, Some(attestation));
    assert_eq!(publication.associations.len(), 2);
    assert_eq!(publication.aliases, vec![alias()]);
    assert_eq!(
        publication.admission.association_ids,
        vec![first.association_id]
    );

    // Non-admitted membership is part of exclusivity, so its rotation blocks
    // delivery just as an admitted credential's rotation would.
    db.set_binding_credential_revision(
        second_id,
        "write",
        "secret://unresolved/second/v2",
        credential.generation,
        &"7".repeat(64),
        "fixture",
    )
    .await
    .unwrap();
    let error = db
        .storage_authority_publication(
            &authority().authority_id,
            &authority().guard_namespace_id,
            "approved-executor-one",
        )
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("no longer current and validated"));
}

#[tokio::test]
async fn publication_refuses_stale_coordinates_scope_expiry_and_after_transport_rotation() {
    let db = Database::open_in_memory().await.unwrap();
    let remote = admit(&db).await;
    let publication = db
        .storage_authority_publication(
            &remote.authority_id,
            &remote.guard_namespace_id,
            "approved-executor-one",
        )
        .await
        .unwrap();
    assert!(db
        .storage_authority_publication(
            &remote.authority_id,
            "other-namespace",
            "approved-executor-one"
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("configured executor"));
    assert!(db
        .storage_authority_publication(
            &remote.authority_id,
            &remote.guard_namespace_id,
            "other-executor"
        )
        .await
        .is_err());

    let member = &publication.attestation.as_ref().unwrap().credentials[0];
    let binding_id = publication.associations[0].binding_id;
    let credential = db
        .current_binding_credential(binding_id, "write")
        .await
        .unwrap()
        .unwrap();
    db.validate_binding_credential_revision(
        binding_id,
        "write",
        member.generation,
        "invalid",
        Some("qualification revoked"),
        credential.head_resource_version,
    )
    .await
    .unwrap();
    let error = db
        .reconcile_storage_authority_publication(
            &publication,
            &remote,
            &remote.guard_namespace_id,
            "approved-executor-one",
        )
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("no longer current and validated"));
    let acknowledged: Option<i64> = db
        .backend
        .query_opt(
            "SELECT acknowledged_generation FROM storage_authority_admission_heads
         WHERE authority_id = ?1",
            &vals![remote.authority_id.as_str()],
        )
        .await
        .unwrap()
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(acknowledged, None);

    db.validate_binding_credential_revision(
        binding_id,
        "write",
        member.generation,
        "valid",
        None,
        credential.head_resource_version + 1,
    )
    .await
    .unwrap();
    db.backend
        .execute(
            "UPDATE bindings SET endpoint_port = 8443 WHERE id = ?1",
            &vals![binding_id],
        )
        .await
        .unwrap();
    assert!(db
        .storage_authority_publication(
            &remote.authority_id,
            &remote.guard_namespace_id,
            "approved-executor-one"
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("physical coordinates"));
    db.backend
        .execute(
            "UPDATE bindings SET endpoint_port = 443 WHERE id = ?1",
            &vals![binding_id],
        )
        .await
        .unwrap();
    let mut expired = publication.attestation.clone().unwrap();
    expired.valid_until = unix_now() - 1;
    db.backend
        .execute(
            "UPDATE storage_authority_attestations SET specification_json = ?2
         WHERE attestation_id = ?1",
            &vals![
                expired.attestation_id,
                serde_json::to_string(&expired).unwrap()
            ],
        )
        .await
        .unwrap();
    assert!(db
        .storage_authority_publication(
            &remote.authority_id,
            &remote.guard_namespace_id,
            "approved-executor-one"
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("expired"));
}

struct PausingAcknowledgementBackend {
    inner: Box<dyn crate::backend::Backend>,
    pause: std::sync::Arc<AdmissionReadPause>,
}

#[async_trait::async_trait]
impl crate::backend::Backend for PausingAcknowledgementBackend {
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
        self.inner.query(sql, params).await
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        self.inner.execute_batch(sql).await
    }

    async fn batch(&self, statements: &[Statement]) -> Result<()> {
        self.inner.batch(statements).await
    }

    async fn checked_batch(&self, statements: &[CheckedStatement]) -> Result<()> {
        if statements[0]
            .statement
            .sql
            .starts_with("UPDATE storage_authority_admission_heads SET acknowledged_generation")
            && self
                .pause
                .armed
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.pause.reached.notify_one();
            self.pause.resume.notified().await;
        }
        self.inner.checked_batch(statements).await
    }
}

#[tokio::test]
async fn watermark_acknowledgement_rolls_back_when_sql_advances_after_precheck() {
    for change_digest in [false, true] {
        let original = Database::open_in_memory().await.unwrap();
        let remote = admit(&original).await;
        let pause = std::sync::Arc::new(AdmissionReadPause {
            armed: std::sync::atomic::AtomicBool::new(true),
            reached: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        });
        let db = std::sync::Arc::new(Database::attach(Box::new(PausingAcknowledgementBackend {
            inner: original.backend,
            pause: pause.clone(),
        })));
        let pending_db = db.clone();
        let pending_remote = remote.clone();
        let pending = tokio::spawn(async move {
            pending_db
                .reconcile_storage_authority_watermark(&pending_remote)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), pause.reached.notified())
            .await
            .unwrap();
        if change_digest {
            db.backend
                .execute(
                    "UPDATE storage_authority_admission_revisions SET specification_digest = ?2
                 WHERE authority_id = ?1",
                    &vals![remote.authority_id.as_str(), "f".repeat(64)],
                )
                .await
                .unwrap();
        } else {
            apply(
                &db,
                StorageAuthorityDecisionInput::SetAdmission(SetStorageAuthorityAdmission {
                    authority_id: remote.authority_id.clone(),
                    expected_generation: remote.generation,
                    expected_digest: Some(remote.digest.clone()),
                    guard_namespace_id: remote.guard_namespace_id,
                    state: StorageAuthorityAdmissionState::Blocked,
                    attestation_id: None,
                    association_ids: vec![],
                }),
            )
            .await;
        }
        pause.resume.notify_one();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(5), pending)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(
            db.backend
                .query_opt(
                    "SELECT acknowledged_generation FROM storage_authority_admission_heads
         WHERE authority_id = ?1",
                    &vals![remote.authority_id.as_str()]
                )
                .await
                .unwrap()
                .unwrap()
                .get::<Option<i64>>(0)
                .unwrap(),
            None
        );
        assert_eq!(
            db.backend
                .query_opt(
                    "SELECT acknowledged_at FROM storage_authority_control_requests
             WHERE authority_id = ?1 AND generation = 1",
                    &vals![remote.authority_id.as_str()]
                )
                .await
                .unwrap()
                .unwrap()
                .get::<Option<i64>>(0)
                .unwrap(),
            None
        );
    }
}
