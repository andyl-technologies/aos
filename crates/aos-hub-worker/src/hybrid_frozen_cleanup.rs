//! Exact-claim external cleanup HEAD admission and bounded metadata replies.
//!
//! Retained credentials exist only within this request. This seam never reads
//! or publishes current binding state and cannot authorize provider mutations.

use anyhow::{Context as _, Result};

use aos_hub_core::s3surface::{Method, S3Surface};
use aos_hub_core::storage_work::{
    StorageCredentialSelector, StorageFrozenCleanupHeadResult, StorageFrozenCleanupOperation,
    StorageFrozenCleanupRequest, StorageObjectIdentity, StorageWorkKey, MAX_FROZEN_CLEANUP_BYTES,
};

/// An authenticated exact-key HEAD request with request-local credentials.
pub(crate) struct FrozenCleanupHead {
    request: StorageFrozenCleanupRequest,
    signed_url: String,
}

impl FrozenCleanupHead {
    /// Authenticates the dedicated envelope before selecting retained access.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid grant, unsupported operation, or invalid
    /// retained credential or provider coordinates.
    pub(crate) fn authorize(
        key: &StorageWorkKey,
        signature: &str,
        body: &[u8],
        deployment_id: &str,
        now: i64,
    ) -> Result<Self> {
        let request = key.verify_frozen_cleanup(signature, body, deployment_id, now)?;
        anyhow::ensure!(
            request.operation == StorageFrozenCleanupOperation::Head,
            "frozen cleanup currently permits only HEAD"
        );
        let selector = StorageCredentialSelector {
            purpose: "delete".into(),
            generation: request.access.delete_credential_generation,
        };
        let credential = request
            .publication
            .credential_text(&selector, deployment_id, now)?;
        let surface = S3Surface::from_snapshot(
            &request.publication.snapshot,
            deployment_id,
            &request.access.placement_prefix,
            Some(credential.as_str()),
            now,
        )?;
        let signed_url = surface.object_url(Method::Head, &request.path, now)?;
        Ok(Self {
            request,
            signed_url,
        })
    }

    /// Borrows retained coordinates for independently configured alias refusal.
    pub(crate) fn snapshot(&self) -> &aos_hub_core::storage_work::StorageBindingSnapshot {
        &self.request.publication.snapshot
    }

    /// Returns the one signed provider URL; callers must issue HEAD only.
    pub(crate) fn signed_url(&self) -> &str {
        &self.signed_url
    }

    /// Encodes correlated metadata, treating only an exact HEAD 404 as absence.
    ///
    /// # Errors
    ///
    /// Returns an error for a provider failure, malformed metadata, or an
    /// oversized result. Redirects never establish exact-key absence.
    pub(crate) fn result(
        &self,
        status: u16,
        content_length: Option<&str>,
        etag: Option<&str>,
    ) -> Result<Vec<u8>> {
        let object = match status {
            404 => None,
            200 => {
                let size = content_length
                    .context("cleanup HEAD has no Content-Length")?
                    .parse::<u64>()
                    .context("cleanup HEAD has an invalid Content-Length")?;
                let etag = aos_hub_core::surface_write::strong_if_match_etag(
                    etag.context("cleanup HEAD has no ETag")?,
                )?;
                Some(StorageObjectIdentity {
                    key: self.request.object_key()?,
                    size,
                    etag,
                    provider_version: None,
                })
            }
            _ => anyhow::bail!("cleanup HEAD did not return object metadata or absence"),
        };
        let result = StorageFrozenCleanupHeadResult {
            version: 1,
            request_id: self.request.request_id.clone(),
            action_id: self.request.action_id.clone(),
            claim_token: self.request.claim_token.clone(),
            claim_fingerprint: self.request.claim_fingerprint()?,
            object,
        };
        result.validate_for(&self.request)?;
        let bytes = serde_json::to_vec(&result)?;
        anyhow::ensure!(
            bytes.len() <= MAX_FROZEN_CLEANUP_BYTES,
            "cleanup HEAD result exceeds its limit"
        );
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
