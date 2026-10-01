//! Parallel metadata inspection over the selected R2 or S3 storage adapter.
//!
//! Reads remain bounded per object. Shared protocol code packs an exact,
//! paginated prefix, leaving signature and rollback decisions to Native.

use anyhow::Result;
use base64::Engine as _;

use aos_hub_core::fetch::SurfaceFetch;
use aos_hub_core::storage_work::{
    paged_metadata_result, StorageMetadataDocument, StorageMetadataObject, StorageWorkPlan,
    StorageWorkResult, MAX_METADATA_BYTES, MAX_METADATA_INSPECTION_BATCH,
};

/// Reads an ordered batch and packs one bounded metadata page.
///
/// # Errors
///
/// Returns an error for an invalid cursor, provider failure, oversized object,
/// or metadata observations that cannot fit the result contract.
pub(super) async fn inspect(
    fetcher: &dyn SurfaceFetch,
    plan: &StorageWorkPlan,
    paths: &[String],
    cursor: usize,
) -> Result<StorageWorkResult> {
    anyhow::ensure!(
        cursor < paths.len() && paths.len() <= MAX_METADATA_INSPECTION_BATCH,
        "metadata inspection cursor is outside its path set"
    );
    let objects =
        futures_util::future::try_join_all(paths[cursor..].iter().map(|path| async move {
            let document = super::read_bounded_source(fetcher, plan, path, MAX_METADATA_BYTES)
                .await?
                .map(|(bytes, source)| StorageMetadataDocument {
                    source,
                    content_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
                });
            Ok::<_, anyhow::Error>(StorageMetadataObject {
                path: path.clone(),
                document,
            })
        }))
        .await?;
    paged_metadata_result(plan, objects)
}
