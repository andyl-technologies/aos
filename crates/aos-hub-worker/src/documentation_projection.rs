//! Canonical documentation query output parsed beside its physical storage.
//!
//! The executor verifies the complete signed NAR once. Only the closed document
//! model crosses the Native boundary; source NAR and narinfo bytes stay here.

use std::sync::Mutex;

use anyhow::{bail, Context as _, Result};
use aos_hub_core::{fetch::SurfaceFetch, storage_work::StorageWorkOutcome};

/// Parses an admitted documentation NAR once and reports its exact query output.
///
/// # Errors
/// Returns an error for missing, oversized or inconsistent source objects,
/// invalid canonical content, or source-accounting overflow.
pub(crate) async fn inspect_content(
    fetcher: &dyn SurfaceFetch,
    package_name: &str,
    package_version: &str,
    platform: &str,
    artifact: &aos_registry_surface::manifest::DocumentationArtifactMeta,
) -> Result<(StorageWorkOutcome, u64)> {
    let reads = SourceReads {
        fetcher,
        bytes: Mutex::new(0),
    };
    let document = aos_hub_core::indexer::fetch_package_documentation(
        &reads,
        package_name,
        package_version,
        platform,
        artifact,
    )
    .await?;
    let source_bytes = *reads
        .bytes
        .lock()
        .map_err(|_| anyhow::anyhow!("documentation source accounting lock failed"))?;
    Ok((
        StorageWorkOutcome::DocumentationContent { document },
        source_bytes,
    ))
}

/// Counts the exact bodies consumed by the shared bounded NAR parser.
struct SourceReads<'a> {
    fetcher: &'a dyn SurfaceFetch,
    bytes: Mutex<u64>,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl SurfaceFetch for SourceReads<'_> {
    async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
        bail!("documentation source reads require an explicit size bound")
    }

    async fn fetch_bounded(&self, path: &str, maximum: usize) -> Result<Option<Vec<u8>>> {
        // Preserve the adapter's bounded read, including its streaming cutoff.
        let body = self.fetcher.fetch_bounded(path, maximum).await?;
        if let Some(body) = &body {
            let mut count = self
                .bytes
                .lock()
                .map_err(|_| anyhow::anyhow!("documentation source accounting lock failed"))?;
            *count = count
                .checked_add(body.len() as u64)
                .context("documentation content source accounting overflowed")?;
        }
        Ok(body)
    }

    fn describe(&self) -> String {
        self.fetcher.describe()
    }
}

#[cfg(test)]
mod tests;
