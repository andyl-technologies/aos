//! Operator-only material staging for a real queued credential probe.

use aos_hub_core::db::{BindingCredentialRevisionRecord, TopologyOperationRecord};
use aos_hub_core::storage_work::binding_custody::{
    StorageCredentialCustodyProbe, StorageCredentialCustodyStageReply,
    StorageFrozenCleanupCredentialStageReply,
};

use super::*;

struct QueuedCredential {
    binding: BindingRecord,
    credential: BindingCredentialRevisionRecord,
    operation: TopologyOperationRecord,
    probe_token: String,
}

async fn queued_credential(db: &Database, operation_id: &str) -> Result<QueuedCredential> {
    let operation = db
        .topology_operation(operation_id)
        .await?
        .context("queued credential operation absent")?;
    ensure!(
        operation.operation_kind == "storage_credential_probe"
            && operation.primary_target_kind == "binding"
            && matches!(operation.state.as_str(), "pending" | "running" | "failed"),
        "operation is not an unsettled queued credential probe"
    );
    let binding = db
        .binding_by_stable_id(&operation.primary_target_stable_id)
        .await?
        .context("queued credential binding absent")?;
    ensure!(
        binding.resource_version == operation.primary_target_generation_key
            && binding.owner_scope_key == operation.authorization_scope_key,
        "queued credential binding or owner changed"
    );
    let detail: serde_json::Value = serde_json::from_str(&operation.detail_json)?;
    let purpose = detail
        .get("purpose")
        .and_then(serde_json::Value::as_str)
        .context("queued credential purpose absent")?;
    let credential = db
        .current_binding_credential(binding.id, purpose)
        .await?
        .context("queued credential head absent")?;
    let write_state = db
        .binding_write_state(binding.id)
        .await?
        .context("queued binding write state absent")?;
    ensure!(
        detail
            .get("credentialGeneration")
            .and_then(serde_json::Value::as_i64)
            == Some(credential.generation)
            && detail
                .get("credentialHeadResourceVersion")
                .and_then(serde_json::Value::as_i64)
                == Some(credential.head_resource_version)
            && detail
                .get("bindingWriteStateResourceVersion")
                .and_then(serde_json::Value::as_i64)
                == Some(write_state.resource_version)
            && detail
                .get("bindingWriteRevision")
                .and_then(serde_json::Value::as_i64)
                == Some(write_state.current_write_revision.unwrap_or(0)),
        "queued credential or write-state pins changed"
    );
    let probe_token = detail
        .get("probeToken")
        .and_then(serde_json::Value::as_str)
        .context("queued credential token absent")?
        .to_owned();
    Ok(QueuedCredential {
        binding,
        credential,
        operation,
        probe_token,
    })
}

/// Stages exact current queued material on Worker without validating any SQL row.
///
/// A failed task may be staged before its owner resumes the original operation
/// through the ordinary authenticated control API. The original identity and
/// token remain unchanged; this command cannot resume or settle that task.
///
/// # Errors
/// Rejects absent or changed queued targets, unresolved material, bad Worker
/// acknowledgements or changes to original SQL pins during staging.
pub async fn stage_queued_credential(
    db: &Database,
    client: &RemoteStorageWorkClient,
    operation_id: &str,
    resolver: &dyn SecretVersionResolver,
    retention_seconds: i64,
) -> Result<StorageCredentialCustodyStageReply> {
    db.validate_binding_identity_reservations().await?;
    let original = queued_credential(db, operation_id).await?;
    let now = aos_hub_core::clock::now_unix_secs();
    let request = StorageCredentialCustodyProbe {
        version: 1,
        nonce: hex::encode(rand::random::<[u8; 32]>()),
        issued_at: now,
        expires_at: now.checked_add(30).context("stage deadline overflowed")?,
        operation_id: original.operation.operation_id.clone(),
        probe_token: original.probe_token.clone(),
        head_resource_version: original.credential.head_resource_version,
        snapshot: StorageBindingSnapshot::for_credential_probe(
            client.deployment_id().into(),
            &original.binding,
            &original.credential,
            now,
        )?,
    };
    request.validate(client.deployment_id(), now)?;
    ensure!(
        retention_seconds > 0
            && retention_seconds
                <= aos_hub_core::storage_work::binding_custody::MAX_CREDENTIAL_CUSTODY_SECONDS,
        "material custody retention must be within twenty-four hours"
    );
    let reply = client
        .stage_credential_custody(
            request.clone(),
            resolver,
            now.checked_add(retention_seconds)
                .context("material retention overflowed")?,
        )
        .await?;
    db.validate_binding_identity_reservations().await?;
    let latest = queued_credential(db, operation_id).await?;
    ensure!(
        latest.credential == original.credential
            && latest.probe_token == original.probe_token
            && StorageBindingSnapshot::for_credential_probe(
                client.deployment_id().into(),
                &latest.binding,
                &latest.credential,
                now
            )? == request.snapshot,
        "queued originals changed during material staging"
    );
    Ok(reply)
}

/// Publishes a bounded private material-free acknowledgement directory.
///
/// # Errors
/// Rejects unsafe custody, oversized encoding, or an existing output directory.
pub fn write_stage_receipt(
    path: &Path,
    receipt: &StorageCredentialCustodyStageReply,
) -> Result<()> {
    custody::publish_directory(
        path,
        &[("credential-stage.json", serde_json::to_vec(receipt)?)],
    )
}

/// Publishes an owner-private acknowledgement of exact historical recovery.
///
/// # Errors
/// Rejects unsafe custody, excessive encoding or an existing output directory.
pub fn write_cleanup_stage_receipt(
    path: &Path,
    receipt: &StorageFrozenCleanupCredentialStageReply,
) -> Result<()> {
    custody::publish_directory(
        path,
        &[(
            "cleanup-credential-stage.json",
            serde_json::to_vec(receipt)?,
        )],
    )
}
