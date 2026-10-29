//! Credential probe originals across current SQL and controller races.

use std::sync::Arc;

use crate::topology_probe::DatabaseTopologyProbeScheduler;
use crate::topology_probe::TopologyProbe;
use crate::topology_probe::TopologyProbeScheduler;

use anyhow::{Context as _, Result};
use aos_hub_db::db::*;
macro_rules! vals {
    ($($value:expr),* $(,)?) => {
        vec![$(aos_hub_db::value::ToValue::to_value(&$value)),*]
    };
}

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
                db.fixture_backend()
                    .execute(
                        "UPDATE bindings SET resource_version = resource_version + 1 WHERE id = ?1",
                        &vals![binding.id],
                    )
                    .await
                    .unwrap();
            }
            "stable_id" => {
                db.fixture_backend()
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
                db.fixture_backend().execute("UPDATE binding_write_state SET resource_version = resource_version + 1 WHERE binding_id = ?1", &vals![binding.id]).await.unwrap();
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
                    Some(aos_hub_model::clock::now_unix_secs()),
                )
                .await
                .unwrap();
            }
            "token" => {
                let mut detail: serde_json::Value =
                    serde_json::from_str(&claim.detail_json).unwrap();
                detail["probeToken"] = serde_json::json!("b".repeat(64));
                db.fixture_backend()
                    .execute(
                        "UPDATE topology_operations SET detail_json = ?2 WHERE operation_id = ?1",
                        &vals![&claim.operation_id, detail.to_string()],
                    )
                    .await
                    .unwrap();
            }
            "reference" => {
                db.fixture_backend().execute("UPDATE binding_credential_revisions SET credential_fingerprint = ?2 WHERE binding_id = ?1 AND purpose = 'read'", &vals![binding.id, "b".repeat(64)]).await.unwrap();
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
            let detail: serde_json::Value = serde_json::from_str(&committed.detail_json).unwrap();
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
            .create_binding_write_revision(&NewBindingWriteRevision {
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
                db.fixture_backend().execute("UPDATE binding_write_state SET resource_version = resource_version + 1 WHERE binding_id = ?1", &vals![binding.id]).await.unwrap();
            }
            "binding" => {
                db.fixture_backend()
                    .execute(
                        "UPDATE bindings SET resource_version = resource_version + 1 WHERE id = ?1",
                        &vals![binding.id],
                    )
                    .await
                    .unwrap();
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
                    Some(aos_hub_model::clock::now_unix_secs()),
                )
                .await
                .unwrap();
            }
            _ => {}
        }

        // A restarted controller loads the advanced head while retaining the
        // original queued CAS. Only that exact one-step validation is accepted.
        let result = db
            .select_probed_binding_write_revision(&binding, &validated, &claim, revision.revision)
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
