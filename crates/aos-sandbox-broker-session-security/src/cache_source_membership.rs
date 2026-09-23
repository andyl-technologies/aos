//! Joins a rechecked public Cache consumer to authenticated View source data.

use std::io::Cursor;

use aos_filesystem_view_core::{
    CompileError, INDEX_MEDIA_TYPE, IndexError, IndexExpectation, IndexStaging, ObjectSource,
    ProjectionError, ProjectionLimits, SourceError, TreeCompileLimits, TreeCompiler,
    ValidatedViewProjection, ValidatedViewSourceObject, compile_view_projection, load_exact,
    validate_index,
};
use aos_sandbox::production_operation_compiler::RecheckedCacheConsumerV1;
use aos_sandbox_core::model::ViewSource;
use aos_sandbox_core::{
    CanonicalCborError, MediaType, Revision, decode_view, descriptor_for_bytes,
};

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

/// Reports failure to compile source membership from exact portable objects.
#[derive(Debug, thiserror::Error)]
pub enum CompiledCacheSourceMembershipErrorV1<E: std::error::Error + 'static> {
    /// A release-only consumer cannot acquire a source pin.
    #[error("cache consumer has no current acquisition fence")]
    ReleaseOnly,
    /// The exact View object could not be loaded.
    #[error(transparent)]
    ViewSource(#[from] SourceError<E>),
    /// The View object failed canonical decoding.
    #[error(transparent)]
    ViewFormat(#[from] CanonicalCborError),
    /// This helper only compiles immutable portable tree sources.
    #[error("cache source is not an immutable portable tree")]
    NonImmutableSource,
    /// The portable tree could not be compiled from exact source objects.
    #[error(transparent)]
    Compile(#[from] CompileError<E>),
    /// The fixed index media type was not valid.
    #[error("internal structural-index media type is invalid")]
    InvalidIndexMediaType,
    /// The compiled index did not prove the requested object's membership.
    #[error(transparent)]
    Membership(#[from] CacheSourceMembershipErrorV1),
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

/// Validates exact View and authenticated-index bytes before using source membership.
///
/// For an externally supplied index, `index_expectation` must come from an
/// independently authenticated, sealed publication. A private index compiled
/// from exact source objects may use compiler-owned commitments instead.
/// Never construct the expectation from untrusted candidate bytes or their
/// header: a well-formed index need not faithfully represent the source tree.
/// The callback retains the borrowed proof only while both validated inputs
/// are alive. The caller must recheck desired state at the protected pin commit.
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

/// Compiles exact portable source objects into a private membership proof.
///
/// The index and its expected commitments are both produced by the trusted
/// compiler. This differs from validating an externally supplied index: no
/// untrusted index header or candidate bytes supply the expectation. The
/// caller must still recheck desired state at the protected pin commit.
///
/// # Errors
///
/// Returns an error when the consumer cannot acquire a pin, exact source
/// loading or graph compilation fails, a limit is exceeded, or the requested
/// object is absent from the compiled View source.
pub fn with_compiled_cache_source_membership_v1<S, R>(
    consumer: &RecheckedCacheConsumerV1,
    source: &mut S,
    compiler_abi: [u8; 32],
    tree_limits: TreeCompileLimits,
    membership_limits: CacheSourceMembershipLimitsV1,
    use_membership: impl FnOnce(&ValidatedViewSourceObject<'_, '_, '_>) -> R,
) -> Result<R, CompiledCacheSourceMembershipErrorV1<S::Error>>
where
    S: ObjectSource,
{
    let fence = consumer
        .acquisition_fence()
        .ok_or(CompiledCacheSourceMembershipErrorV1::ReleaseOnly)?;
    let maximum_view_bytes = tree_limits
        .object_bytes
        .min(membership_limits.projection.decode.maximum_bytes);
    let view_object = load_exact(source, fence.view_revision(), maximum_view_bytes)?;
    let view = decode_view(view_object.bytes(), membership_limits.projection.decode)?;
    let ViewSource::ImmutableTree { tree } = view.source() else {
        return Err(CompiledCacheSourceMembershipErrorV1::NonImmutableSource);
    };

    let staging = IndexStaging::new(
        Cursor::new(Vec::new()),
        tree_limits
            .index_bytes
            .min(membership_limits.maximum_index_bytes),
        tree_limits.index_record_bytes,
    );
    let (_, staged) =
        TreeCompiler::new(tree_limits).compile(source, staging, tree, compiler_abi)?;
    let (writer, _, binding) = staged.into_parts_with_binding();
    let index_bytes = writer.into_inner();
    let index_media = MediaType::new(INDEX_MEDIA_TYPE)
        .map_err(|_| CompiledCacheSourceMembershipErrorV1::InvalidIndexMediaType)?;
    let index_descriptor = descriptor_for_bytes(index_media, &index_bytes);
    let expectation = binding.expectation(&index_descriptor);

    with_cache_source_membership_v1(
        consumer,
        view_object.bytes(),
        &index_bytes,
        &expectation,
        membership_limits,
        use_membership,
    )
    .map_err(CompiledCacheSourceMembershipErrorV1::Membership)
}
