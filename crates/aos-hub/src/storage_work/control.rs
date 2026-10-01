//! Bounded control documents retrieved through storage-local Worker queries.
//!
//! OCI configs and manifests cross the runtime boundary as small ranges with
//! one frozen size and strong ETag. Public object delivery remains on Workers.

use anyhow::{Context as _, Result};
use aos_hub_core::fetch::SurfaceFetch as _;
use aos_hub_core::storage_work::{MAX_OCI_RANGE_BYTES, admitted_oci_blob_path};

use super::HybridSurfaceFetch;

// Configs and manifests are control data. Even a permissive caller cannot turn
// this port into unbounded cross-cloud delivery of a layer or another object.
const MAX_CONTROL_BYTES: usize = 4 * 1024 * 1024;

/// Retrieves a small control document without enabling full object streaming.
///
/// # Errors
///
/// Returns an error for an unsupported path, exceeded size limit, changed
/// object version, malformed Worker result, or failed storage work.
pub(super) async fn fetch_bounded(
    surface: &HybridSurfaceFetch,
    path: &str,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    if !admitted_oci_blob_path(path) {
        let bytes = surface.fetch(path).await?;
        anyhow::ensure!(
            bytes.as_ref().is_none_or(|bytes| bytes.len() <= max_bytes),
            "hybrid metadata exceeds its semantic byte limit"
        );
        return Ok(bytes);
    }

    let Some(head) = surface.head(path).await? else {
        return Ok(None);
    };
    let size = usize::try_from(head.size).context("OCI control object size exceeds usize")?;
    anyhow::ensure!(
        size <= max_bytes.min(MAX_CONTROL_BYTES),
        "OCI control object exceeds its semantic byte limit"
    );
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .context("allocating bounded OCI control object")?;

    let mut start = 0_u64;
    while start < head.size {
        let end = (start + MAX_OCI_RANGE_BYTES as u64 - 1).min(head.size - 1);
        let read = surface
            .inspect_oci_range(path, (start, end))
            .await?
            .context("OCI control object disappeared during inspection")?;
        anyhow::ensure!(
            read.total == head.size
                && read.range == Some((start, end))
                && read.strong_etag.as_deref() == Some(head.etag.as_str()),
            "OCI control object changed during inspection"
        );
        let chunk = axum::body::to_bytes(read.body, MAX_OCI_RANGE_BYTES).await?;
        anyhow::ensure!(
            chunk.len() as u64 == end - start + 1,
            "OCI control object range has an unexpected length"
        );
        bytes.extend_from_slice(&chunk);
        start = end + 1;
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests;
