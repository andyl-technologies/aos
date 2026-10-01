//! Atomic current-target fences for controller-owned credential probe results.

use anyhow::{ensure, Context as _, Result};

use super::{BindingCredentialRevisionRecord, BindingRecord, Database, TopologyOperationRecord};
use crate::backend::Statement;

impl Database {
    /// Selects measured write capability under the original probe target and claim.
    ///
    /// # Errors
    /// Rejects a changed binding, queued claim, validated credential head or
    /// original write-state CAS, or a missing positive write observation.
    pub async fn select_probed_binding_write_revision(
        &self,
        binding: &BindingRecord,
        credential: &BindingCredentialRevisionRecord,
        claim: &TopologyOperationRecord,
        revision: i64,
    ) -> Result<()> {
        let detail: serde_json::Value = serde_json::from_str(&claim.detail_json)?;
        let version = detail
            .get("bindingWriteStateResourceVersion")
            .and_then(serde_json::Value::as_i64)
            .context("original write-state version absent")?;
        let original_revision = detail
            .get("bindingWriteRevision")
            .and_then(serde_json::Value::as_i64)
            .context("original write revision absent")?;
        let validated_head_version = detail
            .get("credentialHeadResourceVersion")
            .and_then(serde_json::Value::as_i64)
            .context("original credential-head version absent")?
            .checked_add(1)
            .context("validated credential-head version overflowed")?;
        ensure!(
            claim.operation_kind == "storage_credential_probe"
                && claim.state == "running"
                && claim.primary_target_kind == "binding"
                && claim.primary_target_stable_id == binding.stable_id
                && claim.primary_target_generation_key == binding.resource_version
                && credential.binding_id == binding.id
                && credential.purpose == "write"
                && detail.get("purpose").and_then(serde_json::Value::as_str) == Some("write")
                && detail
                    .get("credentialGeneration")
                    .and_then(serde_json::Value::as_i64)
                    == Some(credential.generation)
                && detail
                    .get("probeResult")
                    .and_then(serde_json::Value::as_str)
                    == Some("valid")
                && detail
                    .get("validationCommitted")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                && detail
                    .get("validatedCredentialHeadResourceVersion")
                    .and_then(serde_json::Value::as_i64)
                    == Some(validated_head_version)
                && version > 0
                && original_revision >= 0,
            "write probe original target or result differs"
        );
        self.backend
            .checked_batch(&[
                Statement::new(
                    "UPDATE topology_operations SET progress_current = progress_current
                 WHERE operation_id = ?1 AND resource_version = ?2
                   AND state = 'running' AND detail_json = ?3
                   AND operation_kind = 'storage_credential_probe'",
                    vals![
                        &claim.operation_id,
                        claim.resource_version,
                        &claim.detail_json
                    ]
                    .to_vec(),
                )
                .expecting(1),
                Statement::new(
                    "UPDATE bindings SET updated_at = updated_at
                 WHERE id = ?1 AND stable_id = ?2 AND resource_version = ?3",
                    vals![binding.id, &binding.stable_id, binding.resource_version].to_vec(),
                )
                .expecting(1),
                Statement::new(
                    "UPDATE binding_credential_heads SET updated_at = updated_at
                 WHERE binding_id = ?1 AND purpose = 'write'
                   AND current_generation = ?2 AND resource_version = ?3",
                    vals![binding.id, credential.generation, validated_head_version].to_vec(),
                )
                .expecting(1),
                Statement::new(
                    "UPDATE binding_credential_revisions SET validation_state = validation_state
                 WHERE binding_id = ?1 AND purpose = 'write' AND generation = ?2
                   AND secret_version_ref = ?3 AND credential_fingerprint = ?4
                   AND validation_state = 'valid'",
                    vals![
                        binding.id,
                        credential.generation,
                        &credential.secret_version_ref,
                        &credential.credential_fingerprint
                    ]
                    .to_vec(),
                )
                .expecting(1),
                Statement::new(
                    "UPDATE binding_write_state
                 SET current_write_revision = ?2, resource_version = resource_version + 1,
                     updated_at = ?3
                 WHERE binding_id = ?1 AND resource_version = ?4
                   AND COALESCE(current_write_revision, 0) = ?5
                   AND EXISTS (SELECT 1 FROM binding_write_observations o
                     JOIN binding_write_revisions r ON r.binding_id = o.binding_id
                       AND r.revision = o.revision
                     WHERE o.binding_id = ?1 AND o.revision = ?2 AND o.state = 'valid'
                       AND r.write_credential_generation = ?6)
                   AND EXISTS (SELECT 1 FROM binding_credential_heads h
                     JOIN binding_credential_revisions c ON c.binding_id = h.binding_id
                       AND c.purpose = h.purpose AND c.generation = h.current_generation
                     WHERE h.binding_id = ?1 AND h.purpose = 'write'
                       AND h.current_generation = ?6 AND h.resource_version = ?7
                       AND c.secret_version_ref = ?8 AND c.credential_fingerprint = ?9
                       AND c.validation_state = 'valid')",
                    vals![
                        binding.id,
                        revision,
                        super::unix_now(),
                        version,
                        original_revision,
                        credential.generation,
                        validated_head_version,
                        &credential.secret_version_ref,
                        &credential.credential_fingerprint
                    ]
                    .to_vec(),
                )
                .expecting(1),
            ])
            .await
    }

    /// Records a probe result only while its original queued target remains current.
    ///
    /// The same transaction locks the original write-state and binding rows,
    /// checks the claimed operation and exact credential reference, and records
    /// validation under the original credential-head CAS. No remote await occurs
    /// inside this transaction.
    ///
    /// # Errors
    /// Rejects missing original pins, a changed claim, binding, write revision,
    /// credential head or immutable reference, or a database failure.
    pub async fn validate_probed_binding_credential_revision(
        &self,
        binding: &BindingRecord,
        credential: &BindingCredentialRevisionRecord,
        claim: &TopologyOperationRecord,
        state: &str,
        validation_error: Option<&str>,
    ) -> Result<BindingCredentialRevisionRecord> {
        let detail: serde_json::Value = serde_json::from_str(&claim.detail_json)?;
        let write_state_version = detail
            .get("bindingWriteStateResourceVersion")
            .and_then(serde_json::Value::as_i64)
            .context("probe original write-state version absent")?;
        let write_revision = detail
            .get("bindingWriteRevision")
            .and_then(serde_json::Value::as_i64)
            .context("probe original write revision absent")?;
        let token = detail
            .get("probeToken")
            .and_then(serde_json::Value::as_str)
            .context("probe original token absent")?;
        ensure!(
            claim.operation_kind == "storage_credential_probe"
                && claim.state == "running"
                && claim.primary_target_kind == "binding"
                && claim.primary_target_stable_id == binding.stable_id
                && claim.primary_target_generation_key == binding.resource_version
                && credential.binding_id == binding.id
                && detail.get("purpose").and_then(serde_json::Value::as_str)
                    == Some(credential.purpose.as_str())
                && detail
                    .get("credentialGeneration")
                    .and_then(serde_json::Value::as_i64)
                    == Some(credential.generation)
                && detail
                    .get("credentialHeadResourceVersion")
                    .and_then(serde_json::Value::as_i64)
                    == Some(credential.head_resource_version)
                && detail
                    .get("probeResult")
                    .and_then(serde_json::Value::as_str)
                    == Some(state)
                && detail.get("validationCommitted").is_none()
                && write_state_version > 0
                && write_revision >= 0
                && token.len() == 64
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "probe original target or result differs"
        );

        // No-op updates acquire row locks across the following validation writes.
        // The scheduler creates a real write-state singleton before capturing it,
        // so an absent-row predicate cannot admit a concurrent writer insertion.
        let mut committed_detail = detail.clone();
        committed_detail["validationCommitted"] = serde_json::json!(true);
        committed_detail["validatedCredentialHeadResourceVersion"] = serde_json::json!(credential
            .head_resource_version
            .checked_add(1)
            .context("validated head overflowed")?);
        let fences = vec![
            Statement::new(
                "UPDATE topology_operations SET progress_current = progress_current
                 WHERE operation_id = ?1 AND resource_version = ?2
                   AND state = 'running' AND operation_kind = 'storage_credential_probe'
                   AND detail_json = ?3 AND primary_target_kind = 'binding'
                   AND primary_target_stable_id = ?4 AND primary_target_generation_key = ?5",
                vals![
                    &claim.operation_id,
                    claim.resource_version,
                    &claim.detail_json,
                    &binding.stable_id,
                    binding.resource_version
                ]
                .to_vec(),
            )
            .expecting(1),
            Statement::new(
                "UPDATE binding_write_state SET updated_at = updated_at
                 WHERE binding_id = ?1 AND resource_version = ?2
                   AND COALESCE(current_write_revision, 0) = ?3",
                vals![binding.id, write_state_version, write_revision].to_vec(),
            )
            .expecting(1),
            Statement::new(
                "UPDATE bindings SET updated_at = updated_at
                 WHERE id = ?1 AND stable_id = ?2 AND resource_version = ?3
                   AND EXISTS (SELECT 1 FROM topology_operations o
                     WHERE o.operation_id = ?4 AND o.resource_version = ?5
                       AND o.state = 'running' AND o.operation_kind = 'storage_credential_probe'
                       AND o.detail_json = ?6)
                   AND EXISTS (SELECT 1 FROM binding_credential_heads h
                     JOIN binding_credential_revisions c ON c.binding_id = h.binding_id
                       AND c.purpose = h.purpose AND c.generation = h.current_generation
                     WHERE h.binding_id = ?1 AND h.purpose = ?7
                       AND h.current_generation = ?8 AND h.resource_version = ?9
                       AND c.secret_version_ref = ?10 AND c.credential_fingerprint = ?11)",
                vals![
                    binding.id,
                    &binding.stable_id,
                    binding.resource_version,
                    &claim.operation_id,
                    claim.resource_version,
                    &claim.detail_json,
                    &credential.purpose,
                    credential.generation,
                    credential.head_resource_version,
                    &credential.secret_version_ref,
                    &credential.credential_fingerprint
                ]
                .to_vec(),
            )
            .expecting(1),
            Statement::new(
                "UPDATE binding_credential_heads SET updated_at = updated_at
                 WHERE binding_id = ?1 AND purpose = ?2
                   AND current_generation = ?3 AND resource_version = ?4",
                vals![
                    binding.id,
                    &credential.purpose,
                    credential.generation,
                    credential.head_resource_version
                ]
                .to_vec(),
            )
            .expecting(1),
            Statement::new(
                "UPDATE binding_credential_revisions SET validation_state = validation_state
                 WHERE binding_id = ?1 AND purpose = ?2 AND generation = ?3
                   AND secret_version_ref = ?4 AND credential_fingerprint = ?5",
                vals![
                    binding.id,
                    &credential.purpose,
                    credential.generation,
                    &credential.secret_version_ref,
                    &credential.credential_fingerprint
                ]
                .to_vec(),
            )
            .expecting(1),
            // The checkpoint and validation share one transaction. A mere head
            // increment from credential rotation cannot impersonate completion.
            Statement::new(
                "UPDATE topology_operations SET detail_json = ?4,
                     resource_version = resource_version + 1
                 WHERE operation_id = ?1 AND resource_version = ?2
                   AND state = 'running' AND detail_json = ?3",
                vals![
                    &claim.operation_id,
                    claim.resource_version,
                    &claim.detail_json,
                    committed_detail.to_string()
                ]
                .to_vec(),
            )
            .expecting(1),
        ];
        self.validate_binding_credential_with_fence(
            binding.id,
            &credential.purpose,
            credential.generation,
            state,
            validation_error,
            credential.head_resource_version,
            fences,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::topology_probe::{
        DatabaseTopologyProbeScheduler, TopologyProbe, TopologyProbeScheduler,
    };

    use super::*;

    async fn queued(
        db: Arc<Database>,
        purpose: &str,
    ) -> (
        BindingRecord,
        BindingCredentialRevisionRecord,
        TopologyOperationRecord,
    ) {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let org = db.create_org(&unique, "Probe fence").await.unwrap();
        let owner = db.org_by_id(org).await.unwrap().unwrap();
        let id = db
            .create_topology_binding(
                Some(org),
                &unique,
                &owner.stable_id,
                "Probe",
                "s3",
                None,
                Some("fixture-bucket"),
                Some("isolated"),
                Some("https"),
                Some("dns"),
                Some(b"s3.example.test"),
                Some(443),
                Some("fixture-region"),
                Some("private"),
            )
            .await
            .unwrap();
        let binding = db.binding(id).await.unwrap().unwrap();
        let credential = db
            .set_binding_credential_revision(
                id,
                purpose,
                &format!("secret://probe/{purpose}/v1"),
                0,
                &"a".repeat(64),
                "operator",
            )
            .await
            .unwrap();
        let operation = DatabaseTopologyProbeScheduler::new(db.clone())
            .schedule(
                &unique,
                TopologyProbe::StorageCredential {
                    stable_id: binding.stable_id.clone(),
                    binding_id: id,
                    binding_resource_version: binding.resource_version,
                    purpose: credential.purpose.clone(),
                    generation: credential.generation,
                    credential_head_resource_version: credential.head_resource_version,
                },
            )
            .await
            .unwrap();
        let claim = db
            .claim_storage_credential_probe_operation(
                &operation.operation_id,
                operation.resource_version,
                120,
            )
            .await
            .unwrap()
            .unwrap();
        let mut detail: serde_json::Value = serde_json::from_str(&claim.detail_json).unwrap();
        detail["probeResult"] = serde_json::json!("valid");
        let claim = db
            .update_topology_operation(
                &claim.operation_id,
                claim.resource_version,
                "running",
                0,
                Some(1),
                &detail.to_string(),
                None,
                claim.started_at,
                None,
            )
            .await
            .unwrap();
        (binding, credential, claim)
    }

    async fn races(db: Arc<Database>) {
        for change in [
            "none",
            "binding",
            "stable_id",
            "head",
            "write_state",
            "claim",
            "token",
            "reference",
        ] {
            let (binding, credential, claim) = queued(db.clone(), "read").await;
            match change {
                "binding" => {
                    db.backend.execute("UPDATE bindings SET resource_version = resource_version + 1 WHERE id = ?1", &vals![binding.id]).await.unwrap();
                }
                "stable_id" => {
                    db.backend
                        .execute(
                            "UPDATE bindings SET stable_id = ?2 WHERE id = ?1",
                            &vals![binding.id, uuid::Uuid::new_v4().to_string()],
                        )
                        .await
                        .unwrap();
                }
                "head" => {
                    db.set_binding_credential_revision(
                        binding.id,
                        "read",
                        "secret://probe/read/v2",
                        credential.head_resource_version,
                        &"b".repeat(64),
                        "operator",
                    )
                    .await
                    .unwrap();
                }
                "write_state" => {
                    db.backend.execute("UPDATE binding_write_state SET resource_version = resource_version + 1 WHERE binding_id = ?1", &vals![binding.id]).await.unwrap();
                }
                "claim" => {
                    db.update_topology_operation(
                        &claim.operation_id,
                        claim.resource_version,
                        "cancelled",
                        0,
                        Some(1),
                        &claim.detail_json,
                        None,
                        claim.started_at,
                        Some(super::super::unix_now()),
                    )
                    .await
                    .unwrap();
                }
                "token" => {
                    let mut detail: serde_json::Value =
                        serde_json::from_str(&claim.detail_json).unwrap();
                    detail["probeToken"] = serde_json::json!("b".repeat(64));
                    db.backend.execute("UPDATE topology_operations SET detail_json = ?2 WHERE operation_id = ?1", &vals![&claim.operation_id, detail.to_string()]).await.unwrap();
                }
                "reference" => {
                    db.backend.execute("UPDATE binding_credential_revisions SET credential_fingerprint = ?2 WHERE binding_id = ?1 AND purpose = 'read'", &vals![binding.id, "b".repeat(64)]).await.unwrap();
                }
                _ => {}
            }

            let result = db
                .validate_probed_binding_credential_revision(
                    &binding,
                    &credential,
                    &claim,
                    "valid",
                    None,
                )
                .await;
            let retained = db
                .binding_credential_revision(binding.id, "read", credential.generation)
                .await
                .unwrap()
                .unwrap();
            if change == "none" {
                assert!(result.is_ok(), "{result:?}");
                let committed = db
                    .topology_operation(&claim.operation_id)
                    .await
                    .unwrap()
                    .unwrap();
                let detail: serde_json::Value =
                    serde_json::from_str(&committed.detail_json).unwrap();
                assert_eq!(detail["validationCommitted"], true);
                assert_eq!(committed.resource_version, claim.resource_version + 1);
                assert_eq!(retained.validation_state, "valid");
                assert_eq!(
                    retained.head_resource_version,
                    credential.head_resource_version + 1
                );
            } else {
                assert!(result.is_err(), "race {change} admitted");
                assert_eq!(
                    retained.validation_state, "unknown",
                    "race {change} mutated validation"
                );
                assert!(retained.validated_at.is_none());
                let refused = db
                    .topology_operation(&claim.operation_id)
                    .await
                    .unwrap()
                    .unwrap();
                let detail: serde_json::Value = serde_json::from_str(&refused.detail_json).unwrap();
                assert!(detail.get("validationCommitted").is_none());
            }
        }
    }

    async fn write_restart_fences(db: Arc<Database>) {
        for race in ["none", "head", "write_state", "binding", "claim"] {
            let (binding, credential, claim) = queued(db.clone(), "write").await;
            db.validate_probed_binding_credential_revision(
                &binding,
                &credential,
                &claim,
                "valid",
                None,
            )
            .await
            .unwrap();
            let claim = db
                .topology_operation(&claim.operation_id)
                .await
                .unwrap()
                .unwrap();
            let validated = db
                .current_binding_credential(binding.id, "write")
                .await
                .unwrap()
                .unwrap();
            let revision = db
                .create_binding_write_revision(&super::super::NewBindingWriteRevision {
                    binding_id: binding.id,
                    write_credential_generation: credential.generation,
                    writes_supported: true,
                    conditional_writes_supported: true,
                    revision_fingerprint: "actual-write-measurement".into(),
                    capability_fingerprint: "conditional-write-measurement".into(),
                })
                .await
                .unwrap();
            db.observe_binding_write_revision(binding.id, revision.revision, "valid", None, None)
                .await
                .unwrap();
            match race {
                "head" => {
                    db.set_binding_credential_revision(
                        binding.id,
                        "write",
                        "secret://probe/write/v2",
                        validated.generation,
                        &"b".repeat(64),
                        "operator",
                    )
                    .await
                    .unwrap();
                }
                "write_state" => {
                    db.backend.execute("UPDATE binding_write_state SET resource_version = resource_version + 1 WHERE binding_id = ?1", &vals![binding.id]).await.unwrap();
                }
                "binding" => {
                    db.backend.execute("UPDATE bindings SET resource_version = resource_version + 1 WHERE id = ?1", &vals![binding.id]).await.unwrap();
                }
                "claim" => {
                    db.update_topology_operation(
                        &claim.operation_id,
                        claim.resource_version,
                        "cancelled",
                        0,
                        Some(1),
                        &claim.detail_json,
                        None,
                        claim.started_at,
                        Some(super::super::unix_now()),
                    )
                    .await
                    .unwrap();
                }
                _ => {}
            }

            // A restarted controller loads the advanced head while retaining the
            // original queued CAS. Only that exact one-step validation is accepted.
            let result = db
                .select_probed_binding_write_revision(
                    &binding,
                    &validated,
                    &claim,
                    revision.revision,
                )
                .await;
            let pointer = db.binding_write_state(binding.id).await.unwrap().unwrap();
            if race == "none" {
                assert!(result.is_ok(), "{result:?}");
                assert_eq!(pointer.current_write_revision, Some(revision.revision));
            } else {
                assert!(result.is_err(), "write restart race {race} admitted");
                assert_eq!(pointer.current_write_revision, None);
            }
        }
    }

    #[tokio::test]
    async fn sqlite_original_probe_claim_and_all_current_target_fences_roll_back() {
        let db = Arc::new(Database::open_in_memory().await.unwrap());
        races(db.clone()).await;
        write_restart_fences(db).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn postgres_original_probe_claim_and_all_current_target_fences_roll_back() {
        let Ok(url) = std::env::var("AOS_HUB_BOOTSTRAP_TEST_PG_URL") else {
            return;
        };
        let db = Arc::new(Database::connect(&url).await.unwrap());
        races(db.clone()).await;
        write_restart_fences(db).await;
    }
}
