//! Native correlation of storage-local Git-tree selection and source evidence.
//!
//! Only selected entry rows cross this boundary. Hash verification occurs in
//! the authenticated executor; Native retains the verified commit/tree graph
//! and rejects changed source snapshots, predicates or page positions.

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::{
    storage_work::*,
    tree_projection::{self, GitTreeCursor, GitTreeEntriesPage},
};
use aos_registry_surface::{object, object_bundle};

use super::HybridSurfaceFetch;

pub(super) async fn inspect(
    fetch: &HybridSurfaceFetch,
    oid: object::Oid,
    names: &[String],
    cursor: Option<&GitTreeCursor>,
) -> Result<Option<GitTreeEntriesPage>> {
    tree_projection::validate_request(&oid.to_hex(), names, cursor)?;
    let plan = fetch.work.plan_for_placement(
        &fetch.placement,
        &fetch.binding,
        StorageWorkOperation::FilterGitTreeEntries {
            oid: oid.to_hex(),
            names: names.to_vec(),
            cursor: cursor.cloned(),
        },
        aos_hub_core::clock::now_unix_secs(),
    )?;
    match fetch.execute(&plan).await?.outcome {
        StorageWorkOutcome::GitTreeEntries { page, .. } => Ok(Some(page)),
        StorageWorkOutcome::NotFound => fetch.inspect_packed_tree(oid, names, cursor).await,
        _ => anyhow::bail!("storage Worker returned another tree projection result"),
    }
}

pub(super) fn validate(
    plan: &StorageWorkPlan,
    oid: &str,
    names: &[String],
    cursor: Option<&GitTreeCursor>,
    source: &StorageObjectIdentity,
    page: &GitTreeEntriesPage,
    source_bytes: u64,
) -> Result<()> {
    let oid_value = object::Oid::from_hex(oid)?;
    let shard_path = object_bundle::shard_path(&oid[..2])?;
    let is_shard = source.key == plan.object_key(&shard_path)?;
    let is_loose = source.key == plan.object_key(&oid_value.loose_path())?;
    let limit = if is_shard {
        object_bundle::MAX_BUNDLE_BYTES as u64
    } else {
        object::MAX_PUBLISHED_LOOSE_OBJECT_BYTES
    };
    aos_hub_core::surface_write::strong_if_match_etag(&source.etag)?;
    ensure!(
        (is_shard || is_loose)
            && source.size <= limit
            && source
                .provider_version
                .as_deref()
                .is_none_or(valid_provider_version)
            && source_bytes >= source.size
            && source_bytes
                <= source
                    .size
                    .checked_add(object_bundle::MAX_BUNDLE_BYTES as u64)
                    .context("tree source accounting overflowed")?
            && (!is_shard || source_bytes == source.size),
        "storage Worker tree projection names another source or invalid byte count"
    );
    page.validate(
        oid,
        names,
        cursor,
        &tree_projection::source_commitment(source)?,
    )
}
