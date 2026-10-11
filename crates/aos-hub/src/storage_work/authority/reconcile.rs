//! Metadata delivery and exact SQL reconciliation for the paired authority ledger.
//!
//! A synchronized control plane does not establish provider exclusivity, object
//! readiness, or deletion authorization. A current denial can bridge undelivered
//! history using an exact fresh remote CAS; admission keeps a strict predecessor.

use anyhow::{ensure, Context, Result};
use aos_hub_core::db::Database;
use aos_hub_core::storage_authority::control::StorageAuthorityDeniedTransition;
use aos_hub_core::storage_authority::{
    PhysicalStorageAuthorityId, StorageAuthorityAdmissionState, StorageAuthorityRemoteWatermark,
};
use serde::Serialize;

use super::RemoteStorageWorkClient;

/// Metadata acknowledgement from one authenticated control exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StorageAuthorityControlSynchronization {
    /// Exact permanent physical authority whose reviewed metadata was delivered.
    pub authority_id: PhysicalStorageAuthorityId,
    /// Desired generation agreed by current SQL and the fresh remote ledger.
    pub desired_generation: i64,
    /// Canonical digest of the exact desired admission specification.
    pub desired_digest: String,
    /// True only after the exact SQL acknowledgement commits.
    pub control_synchronized: bool,
    /// Always false: metadata control does not probe or qualify provider I/O.
    pub provider_readiness_evaluated: bool,
}

impl RemoteStorageWorkClient {
    /// Synchronizes one reviewed desired authority generation with its paired ledger.
    ///
    /// Reads only metadata and the client's existing control signing key. Both
    /// observations use fresh signed nonces. A response-loss retry republishes
    /// identical facts; SQL restored behind the ledger remains blocked. This
    /// method does not activate provider capabilities or settle pending effects.
    ///
    /// # Errors
    /// Returns an error for stale or oversized metadata, missing predecessor
    /// history, remote advance/rollback, unauthenticated replies, SQL changes
    /// during the exchange, or atomic acknowledgement failure. Desired SQL state
    /// remains pending reconciliation on failure.
    pub async fn synchronize_storage_authority(
        &self,
        db: &Database,
        authority_id: &PhysicalStorageAuthorityId,
        namespace: &str,
        executor: &str,
    ) -> Result<StorageAuthorityControlSynchronization> {
        let publication = db
            .storage_authority_publication(authority_id, namespace, executor)
            .await?;
        let before = self
            .fresh_storage_authority_watermark(authority_id.clone(), namespace.to_owned())
            .await?;
        let exact_history = match &before {
            None => publication.admission.expected_generation == 0,
            Some(remote) => {
                let exact_replay = remote.generation == publication.generation
                    && remote.digest == publication.digest;
                let exact_predecessor = remote.generation
                    == publication.admission.expected_generation
                    && Some(remote.digest.as_str())
                        == publication.admission.expected_digest.as_deref();
                exact_replay || exact_predecessor
            }
        };
        let deny_gap = !exact_history
            && matches!(
                publication.admission.state,
                StorageAuthorityAdmissionState::Blocked | StorageAuthorityAdmissionState::Retired
            )
            && before.as_ref().map_or(0, |remote| remote.generation)
                < publication.admission.expected_generation;
        ensure!(exact_history || deny_gap,
            "authority remote watermark differs from desired state or exact predecessor; reconciliation is blocked");

        // The preflight itself awaits remote I/O. Refuse a decision superseded
        // during that exchange before sending any publication.
        ensure!(
            db.storage_authority_publication(authority_id, namespace, executor)
                .await?
                == publication,
            "authority facts changed during control preflight"
        );
        let published = if deny_gap {
            self.deny_storage_authority_from_watermark(StorageAuthorityDeniedTransition {
                publication: publication.clone(),
                expected_remote: before,
            })
            .await?
        } else {
            self.publish_storage_authority(publication.clone()).await?
        };
        require_exact_watermark(&published, &publication)?;
        let fresh = self
            .fresh_storage_authority_watermark(authority_id.clone(), namespace.to_owned())
            .await?
            .context("authority ledger disappeared after publication")?;
        require_exact_watermark(&fresh, &publication)?;
        db.reconcile_storage_authority_publication(&publication, &fresh, namespace, executor)
            .await?;

        Ok(StorageAuthorityControlSynchronization {
            authority_id: authority_id.clone(),
            desired_generation: publication.generation,
            desired_digest: publication.digest,
            control_synchronized: true,
            provider_readiness_evaluated: false,
        })
    }
}

fn require_exact_watermark(
    remote: &StorageAuthorityRemoteWatermark,
    publication: &aos_hub_core::storage_authority::control::StorageAuthorityPublication,
) -> Result<()> {
    ensure!(
        remote.authority_id == publication.authority.authority_id
            && remote.guard_namespace_id == publication.authority.guard_namespace_id
            && remote.generation == publication.generation
            && remote.digest == publication.digest,
        "authority latest remote watermark differs from reviewed desired generation"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
