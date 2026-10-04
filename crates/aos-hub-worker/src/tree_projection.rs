//! Storage-local verified tree selection for both R2 and external S3 adapters.
//!
//! Provider bodies stay in this executor. Native receives only bounded matching
//! rows and their exact source snapshot; shard fallback never becomes a raw
//! object response across the control boundary.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    fetch::SurfaceFetch,
    storage_work::{StorageObjectIdentity, StorageWorkOutcome, StorageWorkPlan},
    tree_projection::{self, GitTreeCursor, MAX_TREE_INFLATED_BYTES},
};
use aos_registry_surface::{
    object::{self, ObjectKind},
    object_bundle,
};
use futures_util::TryStreamExt as _;

/// Executes one exact tree predicate after verifying the selected Git identity.
///
/// # Errors
/// Returns an error for stale cursor/source identity, malformed or excessive
/// tree data, invalid provider metadata or a failed bounded source read.
pub(crate) async fn inspect(
    fetcher: &dyn SurfaceFetch,
    plan: &StorageWorkPlan,
    oid: &str,
    names: &[String],
    cursor: Option<&GitTreeCursor>,
) -> Result<(StorageWorkOutcome, u64)> {
    inspect_with_reader(&OrdinaryReader { fetcher, plan }, plan, oid, names, cursor).await
}

/// Carries verified encoded bytes and an optional permanent source incarnation.
pub(crate) struct VerifiedSource {
    pub(crate) bytes: Vec<u8>,
    pub(crate) identity: StorageObjectIdentity,
    pub(crate) guarded: Option<aos_hub_core::storage_work::protected_inspection::ProtectedInspectionSource>,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub(crate) trait SourceReader: aos_hub_core::backend::BackendBounds {
    async fn read(&self, path: &str, maximum: usize) -> Result<Option<VerifiedSource>>;
}

struct OrdinaryReader<'a> {
    fetcher: &'a dyn SurfaceFetch,
    plan: &'a StorageWorkPlan,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl SourceReader for OrdinaryReader<'_> {
    async fn read(&self, path: &str, maximum: usize) -> Result<Option<VerifiedSource>> {
        Ok(read_source(self.fetcher, self.plan, path, maximum).await?
            .map(|(bytes, identity)| VerifiedSource { bytes, identity, guarded: None }))
    }
}

/// Projects an exact tree with its reader-supplied source incarnation.
///
/// # Errors
/// Refuses malformed Git content, stale cursors or mismatched source evidence.
pub(crate) async fn inspect_with_reader(
    reader: &dyn SourceReader,
    plan: &StorageWorkPlan,
    oid: &str,
    names: &[String],
    cursor: Option<&GitTreeCursor>,
) -> Result<(StorageWorkOutcome, u64)> {
    tree_projection::validate_request(oid, names, cursor)?;
    let selected_oid = object::Oid::from_hex(oid)?;
    let shard = &oid[..2];
    let shard_path = object_bundle::shard_path(shard)?;
    let bundle = reader.read(&shard_path, object_bundle::MAX_BUNDLE_BYTES).await?;
    let bundle_bytes = bundle.as_ref().map_or(0, |source| source.identity.size);
    let selected =
        bundle
            .as_ref()
            .and_then(|source| match object_bundle::decode(shard, &source.bytes) {
                Ok(entries) => entries
                    .into_iter()
                    .find(|(entry, _)| *entry == selected_oid),
                Err(error) => {
                    tracing::warn!(error = %error, "ignoring invalid optional Git tree bundle");
                    None
                }
            }).filter(|(_, loose)| {
                // Optional shards are an accelerator. A malformed selected
                // member must retain the canonical loose-path compatibility.
                object::decode_loose_with_limit(loose, Some(selected_oid), MAX_TREE_INFLATED_BYTES).is_ok()
            });
    let (loose, source, guarded_source, source_bytes) = match selected {
        Some((_, loose)) => {
            let source = bundle
                .as_ref()
                .map(|source| (source.identity.clone(), source.guarded.clone()))
                .context("selected tree bundle source disappeared")?;
            (loose, source.0, source.1, bundle_bytes)
        }
        None => {
            let Some(read) = reader.read(
                &selected_oid.loose_path(),
                object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES as usize,
            )
            .await?
            else {
                return Ok((StorageWorkOutcome::NotFound, bundle_bytes));
            };
            let total = bundle_bytes
                .checked_add(read.identity.size)
                .context("tree inspection source accounting overflowed")?;
            (read.bytes, read.identity, read.guarded, total)
        }
    };
    let (kind, content) =
        object::decode_loose_with_limit(&loose, Some(selected_oid), MAX_TREE_INFLATED_BYTES)?;
    ensure!(
        kind == ObjectKind::Tree,
        "selected Git object is not a tree"
    );
    let commitment = tree_projection::guarded_source_commitment(&source, guarded_source.as_ref())?;
    let page = tree_projection::project_tree(oid, &content, names, cursor, &commitment)?;
    Ok((
        StorageWorkOutcome::GitTreeEntries { guarded_source, source, page },
        source_bytes,
    ))
}

async fn read_source(
    fetcher: &dyn SurfaceFetch,
    plan: &StorageWorkPlan,
    path: &str,
    maximum: usize,
) -> Result<Option<(Vec<u8>, StorageObjectIdentity)>> {
    let Some(read) = fetcher.fetch_stream(path, None).await? else {
        return Ok(None);
    };
    ensure!(
        read.range.is_none() && read.total <= maximum as u64,
        "tree source exceeded its admitted read bound"
    );
    let etag = read
        .strong_etag
        .context("tree source has no strong provider identity")?;
    aos_hub_core::surface_write::strong_if_match_etag(&etag)?;
    let size = read.total;
    let mut stream = read.body.into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.try_next().await? {
        let length = bytes
            .len()
            .checked_add(chunk.len())
            .context("tree source size overflowed")?;
        ensure!(
            length <= maximum && length as u64 <= size,
            "tree source exceeded its declared size"
        );
        bytes.extend_from_slice(&chunk);
    }
    ensure!(
        bytes.len() as u64 == size,
        "tree source ended before its declared size"
    );
    Ok(Some((
        bytes,
        StorageObjectIdentity {
            key: plan.object_key(path)?,
            size,
            etag,
            provider_version: None,
        },
    )))
}

#[cfg(test)]
mod tests;
