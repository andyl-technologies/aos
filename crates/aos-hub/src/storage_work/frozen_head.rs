//! Native issuance and acceptance of exact-key, claimed external cleanup HEADs.
//!
//! Retained delete references travel only in a short-lived metadata challenge;
//! provider material remains in Worker custody. SQL claim admission is
//! rechecked before issuance and after the bounded metadata response. This
//! module grants neither object-body access nor provider mutations.

use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use aos_hub_core::db::{Database, OciGcPlacementActionClaim};
use aos_hub_core::fetch::SurfaceFetch;
use aos_hub_core::storage_work::binding_custody::*;
use aos_hub_core::storage_work::{
    StorageBindingSnapshot, StorageFrozenCleanupAccess, StorageFrozenCleanupOperation,
    StorageObjectIdentity, MAX_FROZEN_CLEANUP_BYTES, STORAGE_WORK_SIGNATURE_HEADER,
};
use aos_hub_core::surface_write::FrozenSurfaceAccess;
use async_trait::async_trait;

use super::{read_bounded_response, RemoteStorageWorkClient};

impl RemoteStorageWorkClient {
    /// Observes one external object's metadata using its live durable cleanup claim.
    ///
    /// The exact retained delete generation is used even after credential-head
    /// rotation. No current read credential or placement publication is selected.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale or altered claim, expired lease, invalid or
    /// missing retained credential, unsupported binding, Worker rejection, or
    /// response whose request, stable action fingerprint, or key does not match.
    pub async fn frozen_cleanup_head(
        &self,
        db: &Database,
        claim: &OciGcPlacementActionClaim,
    ) -> Result<Option<StorageObjectIdentity>> {
        // Queue before issuing the short-lived grant so local backpressure does
        // not consume its lifetime or admit an expired claim.
        let _permit = self
            .in_flight
            .acquire()
            .await
            .context("storage Worker concurrency gate closed")?;
        let request = self.frozen_cleanup_request(db, claim).await?;
        let signed = sign_storage_frozen_cleanup_custody(&self.key, &request)?;
        let response = self
            .http
            .post(&self.frozen_cleanup_endpoint)
            .header(STORAGE_WORK_SIGNATURE_HEADER, signed.signature)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(signed.body)
            .send()
            .await
            .context("observing claimed external object through storage Worker")?;
        anyhow::ensure!(
            response.status() == reqwest::StatusCode::OK,
            "storage Worker returned HTTP {} for claimed cleanup HEAD",
            response.status()
        );
        let signature = response
            .headers()
            .get(STORAGE_WORK_SIGNATURE_HEADER)
            .context("frozen cleanup reply signature absent")?
            .to_str()?
            .to_owned();
        let body = read_bounded_response(response, MAX_FROZEN_CLEANUP_BYTES).await?;
        let now = aos_hub_core::clock::now_unix_secs();
        let reply = verify_storage_frozen_cleanup_custody_reply(
            &self.key, &signature, &body, &request, now,
        )?;
        load_matching_claim(db, claim, now).await?;
        self.check_frozen_snapshot(db, &request).await?;
        Ok(reply.result.object)
    }

    /// Builds a fresh metadata challenge from a genuine active SQL cleanup claim.
    ///
    /// # Errors
    /// Rejects changed or expired claims, missing held revisions, invalid access,
    /// or a changed binding. It resolves no private provider material.
    pub async fn frozen_cleanup_request(
        &self,
        db: &Database,
        claim: &OciGcPlacementActionClaim,
    ) -> Result<StorageFrozenCleanupCustodyRequest> {
        let now = aos_hub_core::clock::now_unix_secs();
        load_matching_claim(db, claim, now).await?;

        let binding = db
            .binding(claim.binding_id)
            .await?
            .context("frozen cleanup binding disappeared")?;
        anyhow::ensure!(
            !binding.is_instance_default
                && matches!(binding.kind.as_str(), "s3" | "r2")
                && binding.resource_version == claim.binding_resource_version,
            "frozen cleanup requires the unchanged external binding"
        );
        anyhow::ensure!(
            claim.delete_credential_purpose.as_deref() == Some("delete"),
            "frozen cleanup requires a retained delete credential"
        );
        let generation = claim
            .delete_credential_generation
            .context("frozen cleanup delete generation is missing")?;
        let credential = db
            .binding_credential_revision(binding.id, "delete", generation)
            .await?
            .context("frozen cleanup delete credential disappeared")?;

        let now = aos_hub_core::clock::now_unix_secs();
        load_matching_claim(db, claim, now).await?;
        let expires_at = now
            .checked_add(30)
            .context("cleanup grant expiry overflowed")?
            .min(claim.lease_expires_at);
        let snapshot = StorageBindingSnapshot::from_binding(
            self.deployment_id.clone(),
            &binding,
            std::slice::from_ref(&credential),
            now,
            expires_at,
        )?;
        let request = StorageFrozenCleanupCustodyRequest {
            version: 1,
            nonce: hex::encode(rand::random::<[u8; 32]>()),
            issued_at: now,
            expires_at,
            request_id: uuid::Uuid::new_v4().simple().to_string(),
            action_id: claim.action_id.clone(),
            claim_token: claim.claim_token.clone(),
            lease_expires_at: claim.lease_expires_at,
            access: StorageFrozenCleanupAccess::from_access(&claim.frozen_access())?,
            snapshot,
            path: claim.object_key.clone(),
            expected_hash: claim.expected_hash,
            expected_size: claim.expected_size,
            expected_etag: claim.expected_strong_etag.clone(),
            operation: StorageFrozenCleanupOperation::Head,
        };
        request.validate(&self.deployment_id, now)?;
        self.check_frozen_snapshot(db, &request).await?;
        Ok(request)
    }

    pub(super) async fn check_frozen_snapshot(
        &self,
        db: &Database,
        request: &StorageFrozenCleanupCustodyRequest,
    ) -> Result<()> {
        let binding = db
            .binding(request.snapshot.binding_id)
            .await?
            .context("frozen binding disappeared")?;
        let credential = db
            .binding_credential_revision(
                binding.id,
                "delete",
                request.access.delete_credential_generation,
            )
            .await?
            .context("held cleanup credential disappeared")?;
        let current = StorageBindingSnapshot::from_binding(
            self.deployment_id.clone(),
            &binding,
            &[credential],
            request.snapshot.issued_at,
            request.snapshot.expires_at,
        )?;
        anyhow::ensure!(
            current == request.snapshot,
            "frozen cleanup SQL snapshot changed"
        );
        Ok(())
    }
}

async fn load_matching_claim(
    db: &Database,
    expected: &OciGcPlacementActionClaim,
    now: i64,
) -> Result<()> {
    let actual = db
        .active_oci_gc_placement_action_claim(&expected.action_id, &expected.claim_token, now)
        .await?
        .context("frozen cleanup claim is no longer authorized")?;
    anyhow::ensure!(
        actual == *expected,
        "frozen cleanup claim changed or was altered"
    );
    Ok(())
}

/// Restricts the controller's absence observation to its exact claimed OCI key.
pub(super) struct FrozenClaimSurface {
    db: Arc<Database>,
    work: Arc<RemoteStorageWorkClient>,
    claim: OciGcPlacementActionClaim,
}

impl FrozenClaimSurface {
    pub(super) async fn open(
        db: Arc<Database>,
        work: Arc<RemoteStorageWorkClient>,
        access: &FrozenSurfaceAccess,
        claim: &OciGcPlacementActionClaim,
    ) -> Result<Self> {
        access.validate()?;
        anyhow::ensure!(
            *access == claim.frozen_access(),
            "frozen cleanup access does not match its exact claim"
        );
        load_matching_claim(&db, claim, aos_hub_core::clock::now_unix_secs()).await?;
        Ok(Self {
            db,
            work,
            claim: claim.clone(),
        })
    }

    async fn head(&self, path: &str) -> Result<Option<StorageObjectIdentity>> {
        anyhow::ensure!(
            path == self.claim.object_key,
            "frozen cleanup surface authorizes only its exact claimed key"
        );
        self.work.frozen_cleanup_head(&self.db, &self.claim).await
    }
}

#[async_trait]
impl SurfaceFetch for FrozenClaimSurface {
    fn describe(&self) -> String {
        format!("claimed hybrid Worker cleanup {}", self.claim.action_id)
    }

    async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
        bail!("claimed hybrid cleanup authorizes metadata observations only")
    }

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        Ok(self.head(path).await?.map(|object| object.size))
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        Ok(self.head(path).await?.map(|object| object.etag))
    }
}

#[cfg(test)]
mod tests;
