//! Writes closed external registry controls under current SQL publication scope.
//!
//! Artifact bodies use direct upload grants. This writer sends only prepared
//! controls to the Worker, which parses companions and owns provider dispatch.

use std::sync::Arc;

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    db::{BindingRecord, BindingWriteRevisionRecord, Database, SurfacePlacementRecord},
    storage_work::{prepared_control, StorageWorkOperation},
    surface_write::SurfaceWrite,
};
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use super::{HybridSurfaceFetch, RemoteStorageWorkClient};

/// Holds the exact external registry writer selected at construction.
pub(super) struct ExternalRegistryControlWriter {
    fetch: HybridSurfaceFetch,
    revision: BindingWriteRevisionRecord,
}

impl ExternalRegistryControlWriter {
    /// Opens the current validated registry writer without exposing credentials.
    ///
    /// # Errors
    /// Refuses missing or changed placement, binding, write revision or snapshot.
    pub(super) async fn open(
        db: Arc<Database>,
        work: Arc<RemoteStorageWorkClient>,
        placement: &SurfacePlacementRecord,
        binding: &BindingRecord,
    ) -> Result<Self> {
        ensure!(
            !binding.is_instance_default && matches!(binding.kind.as_str(), "s3" | "r2"),
            "registry control writer requires an external binding"
        );
        let revision = db
            .placement_publication_write_revision(placement.id)
            .await?
            .context("external registry has no current write revision")?;
        let writer = Self {
            fetch: HybridSurfaceFetch {
                db,
                work,
                placement: placement.clone(),
                binding: binding.clone(),
            },
            revision,
        };
        writer.recheck().await?;
        writer
            .fetch
            .work
            .ensure_remote_binding_snapshot(&writer.fetch.db, &writer.fetch.binding)
            .await?;
        writer.recheck().await?;
        Ok(writer)
    }

    async fn recheck(&self) -> Result<()> {
        let placement = self
            .fetch
            .db
            .surface_placement(self.fetch.placement.id)
            .await?
            .context("external registry placement disappeared")?;
        let binding = self
            .fetch
            .db
            .binding(self.fetch.binding.id)
            .await?
            .context("external registry binding disappeared")?;
        let revision = self
            .fetch
            .db
            .placement_publication_write_revision(placement.id)
            .await?
            .context("external registry write revision disappeared")?;
        ensure!(
            placement.resource_version == self.fetch.placement.resource_version
                && placement.binding_id == binding.id
                && placement.prefix == self.fetch.placement.prefix
                && placement.effective_write_enabled
                && binding.resource_version == self.fetch.binding.resource_version
                && revision == self.revision
                && revision.binding_id == binding.id
                && revision.writes_supported,
            "external registry SQL publication authority changed"
        );
        Ok(())
    }
}

#[async_trait]
impl SurfaceWrite for ExternalRegistryControlWriter {
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()> {
        ensure!(
            prepared_control::admitted_path(path)
                && bytes.len() <= prepared_control::maximum_body_bytes(path),
            "external registry writer accepts only bounded prepared controls"
        );
        self.recheck().await?;
        let plan = self.fetch.work.plan_for_placement(
            &self.fetch.placement,
            &self.fetch.binding,
            StorageWorkOperation::PutPreparedControl {
                path: path.into(),
                sha256: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        self.fetch.execute_with_control(&plan, Some(bytes)).await?;
        self.recheck().await
    }

    async fn delete(&self, _path: &str) -> Result<()> {
        anyhow::bail!("external registry deletion requires a retained conditional claim")
    }
}
