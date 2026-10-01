//! Frozen deployment-R2 access for reviewed, durable OCI cleanup claims.
//!
//! Cleanup retains the original physical address even when the current
//! placement or capability observation advances. Only its binding identity and
//! immutable write revision are reopened; object bodies stay beside storage.

use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use aos_hub_core::db::{BindingRecord, Database};
use aos_hub_core::fetch::SurfaceFetch;
use aos_hub_core::storage_work::{StorageWorkOperation, StorageWorkOutcome, StorageWorkPlan};
use aos_hub_core::surface_write::{
    FrozenSurfaceAccess, SurfaceDeleteOutcome, SurfaceDeletePrecondition, SurfaceWrite,
};
use async_trait::async_trait;

use super::RemoteStorageWorkClient;

/// Retains the physical address and binding fence of one durable cleanup claim.
pub(super) struct FrozenR2Surface {
    db: Arc<Database>,
    work: Arc<RemoteStorageWorkClient>,
    access: FrozenSurfaceAccess,
}

impl FrozenR2Surface {
    /// Opens an exact deployment-R2 address without selecting today's placement.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid claim fence, external credential, changed
    /// binding, or missing immutable write revision.
    pub(super) async fn open(
        db: Arc<Database>,
        work: Arc<RemoteStorageWorkClient>,
        access: &FrozenSurfaceAccess,
    ) -> Result<Self> {
        access.validate()?;
        let surface = Self {
            db,
            work,
            access: access.clone(),
        };
        surface.binding().await?;
        Ok(surface)
    }

    async fn binding(&self) -> Result<BindingRecord> {
        let access = &self.access;
        anyhow::ensure!(
            access.delete_credential_purpose.is_none()
                && access.delete_credential_generation.is_none(),
            "deployment R2 has no external delete credential"
        );
        let binding = self
            .db
            .binding(access.binding_id)
            .await?
            .context("frozen hybrid binding disappeared")?;
        anyhow::ensure!(
            binding.kind == "deployment_r2"
                && binding.is_instance_default
                && binding.resource_version == access.binding_resource_version,
            "frozen hybrid binding changed or is unsupported"
        );
        let revision = self
            .db
            .binding_write_revision(access.binding_id, access.binding_write_revision)
            .await?
            .context("frozen hybrid write revision disappeared")?;
        anyhow::ensure!(
            revision.writes_supported,
            "frozen hybrid binding revision cannot write"
        );
        Ok(binding)
    }

    async fn execute(&self, operation: StorageWorkOperation) -> Result<StorageWorkOutcome> {
        let binding = self.binding().await?;
        let now = aos_hub_core::clock::now_unix_secs();
        // The durable controller already validated the claim. Consulting a
        // current placement or capability here could redirect or wedge its IO.
        let plan = StorageWorkPlan {
            version: 1,
            plan_id: uuid::Uuid::new_v4().simple().to_string(),
            deployment_id: self.work.deployment_id.clone(),
            issued_at: now,
            expires_at: now
                .checked_add(30)
                .context("storage work expiry overflowed")?,
            placement_id: self.access.placement_id,
            placement_resource_version: self.access.placement_resource_version,
            binding_id: binding.id,
            binding_resource_version: binding.resource_version,
            binding_kind: binding.kind,
            binding_snapshot_revision: None,
            credential_references: Vec::new(),
            placement_prefix: self.access.placement_prefix.clone(),
            operation,
        };
        Ok(self.work.execute(&plan).await?.outcome)
    }

    async fn head(
        &self,
        path: &str,
    ) -> Result<Option<aos_hub_core::storage_work::StorageObjectIdentity>> {
        match self
            .execute(StorageWorkOperation::Head { path: path.into() })
            .await?
        {
            StorageWorkOutcome::NotFound => Ok(None),
            StorageWorkOutcome::Head { object } => Ok(Some(object)),
            _ => bail!("storage Worker returned an unexpected frozen head result"),
        }
    }
}

#[async_trait]
impl SurfaceFetch for FrozenR2Surface {
    fn describe(&self) -> String {
        format!(
            "frozen hybrid Worker placement {}",
            self.access.placement_id
        )
    }

    async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
        bail!("frozen hybrid cleanup supports metadata observations, not object bodies")
    }

    async fn size(&self, path: &str) -> Result<Option<u64>> {
        Ok(self.head(path).await?.map(|object| object.size))
    }

    async fn inventory_strong_etag(&self, path: &str) -> Result<Option<String>> {
        Ok(self.head(path).await?.map(|object| object.etag))
    }
}

#[async_trait]
impl SurfaceWrite for FrozenR2Surface {
    async fn write(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
        bail!("frozen hybrid cleanup does not authorize writes")
    }

    async fn delete(&self, _path: &str) -> Result<()> {
        bail!("frozen hybrid cleanup requires a durable claim and object precondition")
    }

    async fn delete_if_matches_claimed(
        &self,
        path: &str,
        expected: &SurfaceDeletePrecondition,
        claim_id: &str,
    ) -> Result<SurfaceDeleteOutcome> {
        let etag = expected
            .etag
            .as_ref()
            .context("frozen hybrid deletion requires a strong ETag")?;
        let size = expected
            .size
            .context("frozen hybrid deletion requires a reviewed size")?;
        let outcome = self
            .execute(StorageWorkOperation::DeleteIfMatches {
                path: path.into(),
                claim_id: claim_id.into(),
                expected_etag: etag.clone(),
                expected_size: u64::try_from(size)?,
                delete_binding_write_revision: None,
                expected_hash: expected.content_hash.clone(),
                expected_provider_version: expected.expected_provider_version.clone(),
            })
            .await?;
        match outcome {
            StorageWorkOutcome::ObjectDeleted { etag } => {
                Ok(SurfaceDeleteOutcome::ConditionalDeleteAcknowledged { etag })
            }
            StorageWorkOutcome::NotFound => Ok(SurfaceDeleteOutcome::NotFound),
            StorageWorkOutcome::DeletePreconditionFailed => {
                Ok(SurfaceDeleteOutcome::PreconditionFailed {
                    detail: "R2 object identity changed".into(),
                })
            }
            _ => bail!("storage Worker returned an unexpected frozen deletion result"),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod absence_tests;
