//! Bounded OCI range observations retaining their physical source identity.
//!
//! The public streaming adapter returns only bytes and ordinary response facts.
//! Native control collectors additionally retain the exact guarded incarnation
//! across every page; no extra provider body route is introduced.

use anyhow::{bail, Context as _, Result};
use aos_hub_core::{
    fetch::StreamedRead,
    storage_work::{
        protected_inspection::ProtectedInspectionSource, StorageWorkOperation, StorageWorkOutcome,
    },
};
use base64::Engine as _;

use super::HybridSurfaceFetch;

impl HybridSurfaceFetch {
    pub(super) async fn inspect_oci_range_source(
        &self,
        path: &str,
        (start, end): (u64, u64),
    ) -> Result<Option<(StreamedRead, Option<ProtectedInspectionSource>)>> {
        anyhow::ensure!(
            aos_hub_core::storage_work::admitted_oci_blob_path(path),
            "hybrid range reads require a canonical OCI blob"
        );
        let plan = self.work.plan_for_placement(
            &self.placement,
            &self.binding,
            StorageWorkOperation::InspectOciRange {
                path: path.into(),
                start,
                end,
            },
            aos_hub_core::clock::now_unix_secs(),
        )?;
        let result = self.execute(&plan).await?;
        match result.outcome {
            StorageWorkOutcome::NotFound => Ok(None),
            StorageWorkOutcome::OciRange {
                source,
                content_base64,
                guarded_source,
                ..
            } => Ok(Some((
                StreamedRead {
                    body: axum::body::Body::from(
                        base64::engine::general_purpose::STANDARD
                            .decode(content_base64)
                            .context("decoding OCI range from storage Worker")?,
                    ),
                    total: source.size,
                    range: Some((start, end)),
                    strong_etag: Some(source.etag),
                    snapshot_lease_id: None,
                },
                guarded_source,
            ))),
            _ => bail!("storage Worker returned an unexpected OCI range result"),
        }
    }
}
