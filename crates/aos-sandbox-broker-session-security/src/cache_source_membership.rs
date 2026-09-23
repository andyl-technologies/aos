//! Joins a rechecked public Cache consumer to authenticated View source data.

use aos_filesystem_view_core::{
    IndexError, IndexExpectation, ProjectionError, ProjectionLimits, ValidatedViewProjection,
    ValidatedViewSourceObject, compile_view_projection, validate_index,
};
use aos_sandbox::production_operation_compiler::RecheckedCacheConsumerV1;
use aos_sandbox_core::Revision;

/// Bounds structural-index validation and View projection for a public Cache pin.
#[derive(Clone, Copy, Debug)]
pub struct CacheSourceMembershipLimitsV1 {
    /// Maximum bytes retained for the authenticated structural index.
    pub maximum_index_bytes: u64,
    /// Maximum modeled working bytes while validating that index.
    pub maximum_index_working_bytes: u64,
    /// Limits for canonical View decoding and projected namespace expansion.
    pub projection: ProjectionLimits,
}

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
    /// Authenticated index bytes failed structural or semantic validation.
    #[error("authenticated View index could not be validated: {0}")]
    Index(#[from] IndexError),
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

/// Validates exact View and sealed-index bytes before using source membership.
///
/// `index_expectation` must come from an independently authenticated, sealed
/// index publication. Never construct it from the candidate index bytes or
/// their header: an index can be well formed without faithfully representing
/// the View's portable source tree. The callback retains the borrowed proof
/// only while both validated inputs are alive. The caller must recheck desired
/// state at the protected pin commit.
///
/// # Errors
///
/// Returns an error for release-only consumers, invalid or stale View/index
/// data, an absent source object, or exceeded validation limits.
pub fn with_cache_source_membership_v1<R>(
    consumer: &RecheckedCacheConsumerV1,
    view_bytes: &[u8],
    index_bytes: &[u8],
    index_expectation: &IndexExpectation<'_>,
    limits: CacheSourceMembershipLimitsV1,
    use_membership: impl FnOnce(&ValidatedViewSourceObject<'_, '_, '_>) -> R,
) -> Result<R, CacheSourceMembershipErrorV1> {
    let fence = consumer
        .acquisition_fence()
        .ok_or(CacheSourceMembershipErrorV1::ReleaseOnly)?;
    let index = validate_index(
        index_bytes,
        limits.maximum_index_bytes,
        limits.maximum_index_working_bytes,
        index_expectation,
    )?;
    let projection = compile_view_projection(
        view_bytes,
        fence.view_revision(),
        consumer.view(),
        Revision::new(fence.view_generation()),
        &index,
        limits.projection,
    )?;
    let membership = join_cache_source_membership_v1(consumer, &projection)?;

    Ok(use_membership(&membership))
}
