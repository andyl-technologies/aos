//! Cache-only readback, durable original Abort and terminal pointer retirement.

use aos_proto_types::direct_upload::*;

use crate::cache_upload_lifecycle_model::{validate_status, AbortRecord};
use crate::direct_upload_model::{operation_id, ResumeHead};
use crate::transport::ApiClient;

use super::{
    checkpoint::Checkpoint,
    driver::{control, one_status},
};

/// User-facing progress for one retained original, without provider coordinates.
pub(crate) struct Observation {
    /// Plain logical progress; it never claims provider resource settlement.
    pub message: String,
    /// True only when original logical terminal state permits explicit retirement.
    pub can_start_new: bool,
    /// Exact retained source identity; absent when no original is selected.
    pub source: Option<(String, u64)>,
}

struct Original {
    client: ApiClient,
    checkpoint: Checkpoint,
    active_key: String,
    head: ResumeHead,
}

impl Original {
    async fn open(
        client: ApiClient,
        cache_id: String,
        path: String,
    ) -> Result<Option<Self>, String> {
        let owner = DirectCapabilitiesTarget::Cache {
            cache_id: cache_id.clone(),
        };
        let capabilities = client
            .discover_upload(&owner)
            .await
            .map_err(|_| "Upload policy could not be checked; progress remains saved".to_string())?
            .ok_or_else(|| {
                "This upload route does not support saved direct-upload controls".to_string()
            })?;

        let target = DirectUploadTarget::CacheObject { cache_id, path };
        target
            .validate()
            .map_err(|_| "Choose a valid cache-relative path".to_string())?;
        let scope = operation_id(
            "scope",
            &capabilities.deployment_id,
            &(&capabilities.principal_id, &target),
        )?;
        let active_key = format!("{scope}:active");
        let checkpoint = Checkpoint::open().await?;
        let Some(head) = checkpoint.get::<ResumeHead>(&active_key).await? else {
            return Ok(None);
        };
        if head.scope != scope
            || !valid_direct_digest(&head.run_nonce)
            || head.intent.target != target
            || head.deployment_id != capabilities.deployment_id
            || head.principal_id != capabilities.principal_id
        {
            return Err("The saved upload belongs to another original or account".into());
        }

        Ok(Some(Self {
            client: client.with_direct_upload_capabilities(capabilities),
            checkpoint,
            active_key,
            head,
        }))
    }

    async fn refresh(&mut self) -> Result<(), String> {
        let status = self.head.session.as_ref().ok_or_else(|| {
            "Admission is unresolved. Choose the original file to resume before stopping it"
                .to_string()
        })?;

        let query = DirectStatusQuery {
            session: status.session.clone(),
            after: None,
            maximum_parts: 1,
        };
        let request = DirectBatch {
            operation_id: operation_id("lifecycle-status", &self.head.run_nonce, &query)?,
            items: vec![query],
        };
        let reply = control(
            &self.client,
            &self.head,
            aos_proto_types::DIRECT_UPLOAD_SERVICE_STATUS_BATCH_PATH,
            &request,
            &request.operation_id,
        )
        .await?;

        let status = one_status(&reply)?;
        validate_status(&self.head, &status)?;
        self.head.session = Some(status);
        self.head = self.checkpoint.put(&self.active_key, &self.head).await?;
        Ok(())
    }

    fn observation(&self) -> Observation {
        let state = self.head.session.as_ref().map(|status| status.state);
        let (message, can_start_new) = match state {
            Some(DirectSessionState::Aborted) => (
                "The original upload was stopped. Its saved history will be kept",
                true,
            ),
            Some(DirectSessionState::Committed) => (
                "The original upload completed. Its saved history will be kept",
                true,
            ),
            Some(DirectSessionState::Aborting | DirectSessionState::BlockedUnknown) => (
                "The original upload is still unresolved. Its progress remains saved",
                false,
            ),
            _ => (
                "Original progress is saved. Choose the same file to resume",
                false,
            ),
        };
        Observation {
            message: message.into(),
            can_start_new,
            source: Some((
                self.head.intent.expected_sha256.clone(),
                self.head.intent.byte_size.get(),
            )),
        }
    }
}

/// Reads the exact original under current authenticated cache policy.
///
/// # Errors
/// Refuses changed policy/actor/original, unknown admission or failed readback.
pub(crate) async fn inspect(
    client: ApiClient,
    cache_id: String,
    path: String,
) -> Result<Observation, String> {
    let Some(mut original) = Original::open(client, cache_id, path).await? else {
        return Ok(Observation {
            message: "No unfinished upload is saved for this path".into(),
            can_start_new: false,
            source: None,
        });
    };

    original.refresh().await?;
    Ok(original.observation())
}

/// Stops only the exact admitted original after its locally owned task has ended.
///
/// # Errors
/// Refuses missing original, pending admission/completion, changed identity or
/// unknown/refused controls. A lost acknowledgment preserves the exact request.
pub(crate) async fn abort(
    client: ApiClient,
    cache_id: String,
    path: String,
) -> Result<Observation, String> {
    let mut original = Original::open(client, cache_id, path)
        .await?
        .ok_or_else(|| "No unfinished upload is saved for this path".to_string())?;
    original.refresh().await?;
    if original.observation().can_start_new {
        return Ok(original.observation());
    }

    let key = format!("{}:{}:abort", original.head.scope, original.head.run_nonce);
    let record = match original.checkpoint.get::<AbortRecord>(&key).await? {
        Some(record) => {
            record.validate_for(&original.head)?;
            record
        }
        None => AbortRecord::new(&original.head)?,
    };
    let record = original.checkpoint.put(&key, &record).await?;
    record.validate_for(&original.head)?;

    let reply = control(
        &original.client,
        &original.head,
        aos_proto_types::DIRECT_UPLOAD_SERVICE_ABORT_PATH,
        &record.request,
        &record.request.operation_id,
    )
    .await?;
    let status = one_status(&reply)?;
    validate_status(&original.head, &status)?;
    original.head.session = Some(status);
    original.head = original
        .checkpoint
        .put(&original.active_key, &original.head)
        .await?;
    Ok(original.observation())
}

/// Archives a terminal original before enabling an explicitly selected new file.
///
/// # Errors
/// Refuses unresolved effects, changed actor/run or a concurrent pointer update.
pub(crate) async fn start_new(
    client: ApiClient,
    cache_id: String,
    path: String,
) -> Result<(), String> {
    let mut original = Original::open(client, cache_id, path)
        .await?
        .ok_or_else(|| "No retained terminal upload is selected".to_string())?;
    original.refresh().await?;
    original
        .checkpoint
        .retire_active(&original.active_key, &original.head)
        .await
}
