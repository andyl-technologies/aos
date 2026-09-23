//! Joins a rechecked public Cache consumer to authenticated View source data.

use aos_filesystem_view_core::{
    ProjectionError, ValidatedViewProjection, ValidatedViewSourceObject,
};
use aos_sandbox::production_operation_compiler::RecheckedCacheConsumerV1;

/// Reports why an exact View source cannot authorize a requested Cache pin.
#[derive(Debug, thiserror::Error)]
pub enum CacheSourceMembershipErrorV1 {
    /// A release-only consumer cannot authorize a new pin.
    #[error("cache consumer has no current acquisition fence")]
    ReleaseOnly,
    /// The authenticated source does not match the current desired View.
    #[error("authenticated View source is stale")]
    StaleView,
    /// The requested object is absent from the authenticated source tree.
    #[error("object is absent from the authenticated View source")]
    Absent,
    /// Validated source-index traversal failed closed.
    #[error("authenticated View source could not be inspected: {0}")]
    Projection(#[from] ProjectionError),
}

/// Borrows source membership for one exactly rechecked public Cache consumer.
///
/// The caller must obtain `projection` from independently authenticated View
/// bytes and a validated structural index, then recheck the consumer's desired
/// state at the protected pin commit. This join is not itself pin or read
/// authority, and it cannot authorize a replacement View revision.
///
/// # Errors
///
/// Returns an error for release-only consumers, mismatched View identity or
/// generation, an absent source object, or invalid authenticated index data.
pub fn join_cache_source_membership_v1<'projection, 'index, 'bytes>(
    consumer: &'projection RecheckedCacheConsumerV1,
    projection: &'projection ValidatedViewProjection<'index, 'bytes>,
) -> Result<ValidatedViewSourceObject<'projection, 'index, 'bytes>, CacheSourceMembershipErrorV1> {
    let fence = consumer
        .acquisition_fence()
        .ok_or(CacheSourceMembershipErrorV1::ReleaseOnly)?;
    let (view, revision) = projection.view_identity();
    if view != consumer.view()
        || projection.view_descriptor() != fence.view_revision()
        || revision.get() != fence.view_generation()
    {
        return Err(CacheSourceMembershipErrorV1::StaleView);
    }

    projection
        .prove_source_object(consumer.object())?
        .ok_or(CacheSourceMembershipErrorV1::Absent)
}
