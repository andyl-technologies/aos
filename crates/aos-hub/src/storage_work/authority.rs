//! Fresh authenticated authority control over the existing paired Worker client.
//!
//! These methods transport root-reviewed SQL decisions and verify nonce-bound
//! executor state. They never infer admission from a persisted acknowledgement
//! and never execute provider cleanup. Callers still reconcile exact SQL state.

use anyhow::{ensure, Context, Result};
use aos_hub_core::storage_authority::control::{
    sign_authority_message, verify_authority_message, StorageAuthorityDeniedTransition,
    StorageAuthorityOperation, StorageAuthorityPublication, StorageAuthorityRequest,
    StorageAuthorityResponse, MAX_AUTHORITY_CONTROL_BYTES, STORAGE_AUTHORITY_CONTROL_PATH,
};
use aos_hub_core::storage_authority::{
    PhysicalStorageAuthorityId, StorageAuthorityRemoteWatermark,
};
use aos_hub_core::storage_work::STORAGE_WORK_SIGNATURE_HEADER;
use rand::TryRngCore as _;

use super::RemoteStorageWorkClient;

mod reconcile;

pub use reconcile::StorageAuthorityControlSynchronization;

impl RemoteStorageWorkClient {
    /// Delivers the current reviewed denial from an exact fresh remote observation.
    ///
    /// This closes new metadata admission without delivering historical admitted
    /// generations or settling pending provider effects. The caller must load the
    /// exact current SQL publication and authenticate its remote CAS freshly.
    ///
    /// # Errors
    /// Returns an error for conflicting control, unavailable or unauthenticated
    /// evidence, or an oversized request. Response loss requires fresh lookup.
    pub async fn deny_storage_authority_from_watermark(
        &self,
        transition: StorageAuthorityDeniedTransition,
    ) -> Result<StorageAuthorityRemoteWatermark> {
        let namespace = transition.publication.authority.guard_namespace_id.clone();
        self.authority_request(
            namespace,
            StorageAuthorityOperation::DenyFromWatermark(transition),
        )
        .await?
        .watermark
        .context("denied authority has no durable remote watermark")
    }

    /// Publishes an exact root-reviewed desired generation and reads latest state.
    ///
    /// The caller must load immutable facts from the authenticated operator/SQL
    /// decision path. A historical control receipt does not authorize replaying
    /// its generation: this method always returns the latest remote watermark.
    ///
    /// # Errors
    /// Returns an error for unavailable, stale, uncorrelated or unauthenticated
    /// executor evidence. Response loss requires a new nonce with the same facts.
    pub async fn publish_storage_authority(
        &self,
        publication: StorageAuthorityPublication,
    ) -> Result<StorageAuthorityRemoteWatermark> {
        let namespace = publication.authority.guard_namespace_id.clone();
        let response = self
            .authority_request(namespace, StorageAuthorityOperation::Publish(publication))
            .await?;
        response
            .watermark
            .context("published authority has no durable remote watermark")
    }

    /// Obtains current executor state with a new cryptographic nonce.
    ///
    /// Absence is not admission or provider absence. A returned value must pass
    /// exact desired SQL reconciliation before any authority becomes usable.
    ///
    /// # Errors
    /// Returns an error for unavailable, stale, uncorrelated or unauthenticated
    /// executor evidence; SQL snapshots cannot replace this exchange.
    pub async fn fresh_storage_authority_watermark(
        &self,
        authority: PhysicalStorageAuthorityId,
        guard_namespace_id: String,
    ) -> Result<Option<StorageAuthorityRemoteWatermark>> {
        Ok(self
            .authority_request(
                guard_namespace_id,
                StorageAuthorityOperation::Watermark(authority),
            )
            .await?
            .watermark)
    }

    async fn authority_request(
        &self,
        guard_namespace_id: String,
        operation: StorageAuthorityOperation,
    ) -> Result<StorageAuthorityResponse> {
        let now = aos_hub_core::clock::now_unix_secs();
        let mut nonce = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| anyhow::anyhow!("authority nonce generation failed"))?;
        let request = StorageAuthorityRequest {
            version: 1,
            deployment_id: self.deployment_id.clone(),
            guard_namespace_id,
            nonce: hex::encode(nonce),
            issued_at: now,
            expires_at: now
                .checked_add(30)
                .context("authority request deadline overflowed")?,
            operation,
        };
        request.validate(&self.deployment_id, &request.guard_namespace_id, now)?;
        let body = serde_json::to_vec(&request)?;
        let signature = sign_authority_message(&self.key, false, &body)?;
        let mut endpoint = url::Url::parse(&self.endpoint)?;
        endpoint.set_path(STORAGE_AUTHORITY_CONTROL_PATH);

        let _permit = self
            .in_flight
            .acquire()
            .await
            .context("storage client is closed")?;
        let mut response = self
            .http
            .post(endpoint.as_str())
            .header("content-type", "application/json")
            .header(STORAGE_WORK_SIGNATURE_HEADER, signature)
            .body(body)
            .send()
            .await
            .context("requesting fresh authority control evidence")?;
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "authority control returned status {}",
            response.status()
        );
        let signature = response
            .headers()
            .get(STORAGE_WORK_SIGNATURE_HEADER)
            .context("authority response signature is missing")?
            .to_str()?
            .to_owned();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                chunk.len() <= MAX_AUTHORITY_CONTROL_BYTES.saturating_sub(bytes.len()),
                "authority response exceeds its wire bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        verify_authority_message(&self.key, true, &signature, &bytes)?;
        let reply: StorageAuthorityResponse = serde_json::from_slice(&bytes)?;
        reply.validate_for(&request, aos_hub_core::clock::now_unix_secs())?;
        Ok(reply)
    }
}
