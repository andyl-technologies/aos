//! Managed document composition under its immutable accepted effect scope.

use anyhow::{bail, Context as _, Result};
use aos_hub_core::{
    db::{BindingWriteRevisionRecord, OciUploadChunkRecord, SurfacePlacementRecord},
    fetch::SurfaceObjectEvidence,
    storage_work::{StorageOciChunkSource, StorageWorkOperation, StorageWorkOutcome},
};

use super::HybridSurfaceWrites;

impl HybridSurfaceWrites {
    pub(super) async fn compose_managed_oci(
        &self,
        destination: &SurfacePlacementRecord,
        revision: &BindingWriteRevisionRecord,
        staging: Option<&SurfacePlacementRecord>,
        path: &str,
        chunks: &[OciUploadChunkRecord],
        expected_digest: aos_oci_types::Sha256Digest,
        expected_size: u64,
        managed_effect: Option<&aos_hub_core::hybrid_ingress::OciDocumentEffect>,
    ) -> Result<Option<SurfaceObjectEvidence>> {
        anyhow::ensure!(
            destination.binding_id == revision.binding_id,
            "OCI destination differs from its frozen write revision"
        );
        let staging_prefix = match staging {
            Some(staging) => {
                anyhow::ensure!(
                    staging.binding_id == destination.binding_id,
                    "OCI staging and destination use different R2 bindings"
                );
                staging.prefix.clone()
            }
            None if chunks.is_empty() && expected_size == 0 => String::new(),
            None => bail!("OCI staging placement is missing"),
        };
        let binding = self
            .db
            .binding(destination.binding_id)
            .await?
            .context("OCI destination binding is missing")?;
        let chunks = chunks
            .iter()
            .map(|chunk| StorageOciChunkSource {
                path: chunk.staging_object_key.clone(),
                size: chunk.byte_size,
                sha256: chunk.digest.encoded(),
            })
            .collect();
        let plan = self.work.plan_for_placement(
            destination,
            &binding,
            StorageWorkOperation::ComposeOciBlob {
                managed_effect: managed_effect.cloned(),
                path: path.to_string(),
                staging_prefix,
                chunks,
                expected_size,
                expected_sha256: expected_digest.encoded(),
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.work.execute(&plan).await?;
        let StorageWorkOutcome::OciBlobComposed { object, sha256 } = result.outcome else {
            bail!("storage Worker returned no OCI composition evidence");
        };
        anyhow::ensure!(
            sha256 == expected_digest.encoded(),
            "storage Worker composed a different OCI digest"
        );
        let digest = hex::decode(sha256)?;
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| anyhow::anyhow!("storage Worker returned an invalid OCI digest"))?;
        Ok(Some(SurfaceObjectEvidence {
            provider_version: object.provider_version,
            sha256: digest,
            size: i64::try_from(object.size)?,
            strong_etag: Some(object.etag),
        }))
    }
}
