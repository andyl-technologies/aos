//! Joins a rechecked public Cache consumer to authenticated View source data.

use aos_filesystem_view_core::{
    CompileError, INDEX_MEDIA_TYPE, IndexError, IndexExpectation, IndexStaging, ObjectSource,
    ProjectionError, ProjectionLimits, SourceError, TreeCompileLimits, TreeCompiler,
    ValidatedViewProjection, ValidatedViewSourceObject, compile_view_projection, load_exact,
    validate_index,
};
use aos_sandbox::filesystem_view_state::{
    DurableFilesystemViewRevisionV1, FilesystemViewRevisionPresenceV1,
};
use aos_sandbox::production_operation_compiler::RecheckedCacheConsumerV1;
use aos_sandbox_core::model::ViewSource;
use aos_sandbox_core::{
    CanonicalCborError, MediaType, Revision, decode_view, descriptor_for_bytes,
};

use crate::cache_index_buffer::CacheIndexBuffer;

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

/// Bounds private tree compilation and its aggregate live memory envelope.
#[derive(Clone, Copy, Debug)]
pub struct CacheCompiledSourceLimitsV1 {
    /// Exact-object and graph-wide compiler limits.
    pub tree: TreeCompileLimits,
    /// Limits for index validation and View projection.
    pub membership: CacheSourceMembershipLimitsV1,
    /// Maximum modeled live heap across View, index, compiler, and projection.
    pub maximum_memory_bytes: u64,
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
    /// The combined View, compiler, index, and projection budgets exceed memory.
    #[error("private Cache source compilation exceeds its memory budget")]
    MemoryBudgetExceeded,
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
/// The aggregate preflight models up to twice the View and index byte lengths
/// for `Vec` capacity, plus compiler or validation/projection working memory.
/// It is not an allocator-exact cgroup guarantee; callers must leave headroom.
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
    limits: CacheCompiledSourceLimitsV1,
    use_membership: impl FnOnce(&ValidatedViewSourceObject<'_, '_, '_>) -> R,
) -> Result<R, CompiledCacheSourceMembershipErrorV1<S::Error>>
where
    S: ObjectSource,
{
    let tree_limits = limits.tree;
    let membership_limits = limits.membership;
    let fence = consumer
        .acquisition_fence()
        .ok_or(CompiledCacheSourceMembershipErrorV1::ReleaseOnly)?;
    let maximum_view_bytes = tree_limits
        .object_bytes
        .min(membership_limits.projection.decode.maximum_bytes);
    let maximum_index_bytes = tree_limits
        .index_bytes
        .min(membership_limits.maximum_index_bytes);
    preflight_compilation_memory(
        fence.view_revision().encoded_size(),
        maximum_index_bytes,
        limits,
    )?;
    let view_object = load_exact(source, fence.view_revision(), maximum_view_bytes)?;

    compile_authenticated_cache_source_membership_v1(
        consumer,
        source,
        view_object.bytes(),
        compiler_abi,
        limits,
        use_membership,
    )
}

/// Compiles source membership using canonical bytes from a durable View revision.
///
/// The protected revision supplies the View bytes, so the project source only
/// needs the exact immutable tree objects. The revision must still match the
/// consumer's current desired-state fence; released or stale revisions cannot
/// authorize a new pin.
///
/// # Errors
///
/// Returns an error for a release-only consumer, stale or released revision,
/// exceeded compilation limits, invalid tree source, or absent object.
pub fn with_compiled_cache_source_membership_from_revision_v1<S, R>(
    consumer: &RecheckedCacheConsumerV1,
    source: &mut S,
    revision: &DurableFilesystemViewRevisionV1,
    compiler_abi: [u8; 32],
    limits: CacheCompiledSourceLimitsV1,
    use_membership: impl FnOnce(&ValidatedViewSourceObject<'_, '_, '_>) -> R,
) -> Result<R, CompiledCacheSourceMembershipErrorV1<S::Error>>
where
    S: ObjectSource,
{
    let fence = consumer
        .acquisition_fence()
        .ok_or(CompiledCacheSourceMembershipErrorV1::ReleaseOnly)?;
    if revision.presence() != FilesystemViewRevisionPresenceV1::Available
        || revision.view_id() != consumer.view()
        || revision.descriptor() != fence.view_revision()
        || revision.revision().get() != fence.view_generation()
    {
        return Err(CompiledCacheSourceMembershipErrorV1::Membership(
            CacheSourceMembershipErrorV1::StaleView,
        ));
    }

    let maximum_view_bytes = limits
        .tree
        .object_bytes
        .min(limits.membership.projection.decode.maximum_bytes);
    let view_bytes = revision.canonical_bytes();
    if view_bytes.len() > maximum_view_bytes {
        return Err(CompiledCacheSourceMembershipErrorV1::ViewFormat(
            CanonicalCborError::ObjectTooLarge,
        ));
    }
    preflight_compilation_memory(
        view_bytes.len() as u64,
        limits
            .tree
            .index_bytes
            .min(limits.membership.maximum_index_bytes),
        limits,
    )?;

    compile_authenticated_cache_source_membership_v1(
        consumer,
        source,
        view_bytes,
        compiler_abi,
        limits,
        use_membership,
    )
}

fn compile_authenticated_cache_source_membership_v1<S, R>(
    consumer: &RecheckedCacheConsumerV1,
    source: &mut S,
    view_bytes: &[u8],
    compiler_abi: [u8; 32],
    limits: CacheCompiledSourceLimitsV1,
    use_membership: impl FnOnce(&ValidatedViewSourceObject<'_, '_, '_>) -> R,
) -> Result<R, CompiledCacheSourceMembershipErrorV1<S::Error>>
where
    S: ObjectSource,
{
    let tree_limits = limits.tree;
    let membership_limits = limits.membership;
    let view = decode_view(view_bytes, membership_limits.projection.decode)?;
    let ViewSource::ImmutableTree { tree } = view.source() else {
        return Err(CompiledCacheSourceMembershipErrorV1::NonImmutableSource);
    };

    let maximum_index_bytes = tree_limits
        .index_bytes
        .min(membership_limits.maximum_index_bytes);

    let staging = IndexStaging::new(
        CacheIndexBuffer::new(maximum_index_bytes)
            .ok_or(CompiledCacheSourceMembershipErrorV1::MemoryBudgetExceeded)?,
        maximum_index_bytes,
        tree_limits.index_record_bytes,
    );
    let (_, staged) =
        TreeCompiler::new(tree_limits).compile(source, staging, tree, compiler_abi)?;
    let (writer, _, binding) = staged.into_parts_with_binding();
    let index_bytes = writer.into_bytes();
    let index_media = MediaType::new(INDEX_MEDIA_TYPE)
        .map_err(|_| CompiledCacheSourceMembershipErrorV1::InvalidIndexMediaType)?;
    let index_descriptor = descriptor_for_bytes(index_media, &index_bytes);
    let expectation = binding.expectation(&index_descriptor);

    with_cache_source_membership_v1(
        consumer,
        view_bytes,
        &index_bytes,
        &expectation,
        membership_limits,
        use_membership,
    )
    .map_err(CompiledCacheSourceMembershipErrorV1::Membership)
}

fn preflight_compilation_memory<E: std::error::Error + 'static>(
    view_bytes: u64,
    maximum_index_bytes: u64,
    limits: CacheCompiledSourceLimitsV1,
) -> Result<(), CompiledCacheSourceMembershipErrorV1<E>> {
    let tree_limits = limits.tree;
    let membership_limits = limits.membership;
    let budget = limits.maximum_memory_bytes;
    let view_capacity = view_bytes
        .checked_mul(2)
        .ok_or(CompiledCacheSourceMembershipErrorV1::MemoryBudgetExceeded)?;
    let index_capacity = maximum_index_bytes
        .checked_mul(2)
        .ok_or(CompiledCacheSourceMembershipErrorV1::MemoryBudgetExceeded)?;
    let common = view_capacity
        .checked_add(index_capacity)
        .ok_or(CompiledCacheSourceMembershipErrorV1::MemoryBudgetExceeded)?;
    let compiler_peak = common
        .checked_add(tree_limits.working_bytes)
        .ok_or(CompiledCacheSourceMembershipErrorV1::MemoryBudgetExceeded)?;
    let projection_peak = common
        .checked_add(membership_limits.maximum_index_working_bytes)
        .and_then(|bytes| bytes.checked_add(membership_limits.projection.maximum_working_bytes))
        .ok_or(CompiledCacheSourceMembershipErrorV1::MemoryBudgetExceeded)?;
    if budget == 0 || compiler_peak.max(projection_peak) > budget {
        return Err(CompiledCacheSourceMembershipErrorV1::MemoryBudgetExceeded);
    }
    Ok(())
}
