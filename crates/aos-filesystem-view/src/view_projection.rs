//! Canonical, bounded compilation of portable View presentation programs.
//!
//! A projection is a derived authorization artifact, not a portable object.
//! It binds exact canonical View bytes and identity to one validated source
//! index and records every presented path's source record. Destination parents
//! introduced by an include are represented as synthetic directories and never
//! acquire source-record authority by accident.

use std::cmp::Ordering;
use std::mem::size_of;

use aos_sandbox_core::model::{
    CacheDomain, PresentationAction, View, ViewConsistency, ViewMutation, ViewSource,
};
use aos_sandbox_core::{
    DecodeLimits, DescriptorRole, FeatureRef, MediaType, ObjectDescriptor, ObjectDigest, PathName,
    RelativePath, Revision, ViewId, decode_view, descriptor_for_bytes, validate_canonical_cbor,
    validate_descriptor_role,
};
use sha2::{Digest, Sha256};

use crate::{IndexError, IndexNodeKind, IndexNodeView, ValidatedIndex};

/// Bounds projection decoding, namespace expansion, and retained memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionLimits {
    /// Limits applied while decoding the canonical portable View object.
    pub decode: DecodeLimits,
    /// Maximum ordered presentation actions.
    pub maximum_actions: usize,
    /// Maximum source records inspected.
    pub maximum_source_records: u64,
    /// Maximum projected candidates retained at any step, including synthetic directories.
    pub maximum_projected_nodes: usize,
    /// Maximum components in one projected or source path.
    pub maximum_path_components: usize,
    /// Maximum aggregate name bytes and nested component-vector bytes.
    pub maximum_path_bytes: u64,
    /// Maximum modeled heap bytes retained by compilation and its result.
    pub maximum_working_bytes: u64,
}

/// Classifies how a projected namespace node obtains its semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectedNodeKind {
    /// The node delegates metadata and content to one authenticated source record.
    Source {
        /// Artifact-local record ID in the bound source index.
        record_id: u64,
        /// Authenticated source node kind.
        kind: IndexNodeKind,
    },
    /// The compiler introduced an otherwise absent destination parent.
    SyntheticDirectory,
}

/// Stores one canonical projected-path mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedNode {
    path: RelativePath,
    kind: ProjectedNodeKind,
    inode_identity: [u8; 32],
    link_count: u64,
}

impl ProjectedNode {
    /// Returns the byte-component projected path.
    #[must_use]
    pub const fn path(&self) -> &RelativePath {
        &self.path
    }

    /// Returns the authenticated source mapping or synthetic-directory marker.
    #[must_use]
    pub const fn kind(&self) -> ProjectedNodeKind {
        self.kind
    }

    /// Returns presentation inode identity derived from View revision and path or hard link.
    #[must_use]
    pub const fn inode_identity(&self) -> [u8; 32] {
        self.inode_identity
    }

    /// Returns the link count recomputed from the projected namespace.
    #[must_use]
    pub const fn link_count(&self) -> u64 {
        self.link_count
    }
}

/// Binds one validated identity-profile action to its exact projected path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionProfile {
    path: RelativePath,
    profile: FeatureRef,
}

/// Defines canonical portable metadata for directories synthesized by View policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticDirectoryMetadata {
    mode: u16,
    uid: u32,
    gid: u32,
    mtime_seconds: i64,
    mtime_nanos: u32,
}

impl SyntheticDirectoryMetadata {
    /// Returns read-and-search directory permissions without file-type bits.
    #[must_use]
    pub const fn mode(self) -> u16 {
        self.mode
    }

    /// Returns the portable owner translated by the connection plan.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }

    /// Returns the portable group translated by the connection plan.
    #[must_use]
    pub const fn gid(self) -> u32 {
        self.gid
    }

    /// Returns the normalized modification-time seconds.
    #[must_use]
    pub const fn mtime_seconds(self) -> i64 {
        self.mtime_seconds
    }

    /// Returns the normalized modification-time nanoseconds.
    #[must_use]
    pub const fn mtime_nanos(self) -> u32 {
        self.mtime_nanos
    }
}

const SYNTHETIC_DIRECTORY_V1: SyntheticDirectoryMetadata = SyntheticDirectoryMetadata {
    mode: 0o555,
    uid: 0,
    gid: 0,
    mtime_seconds: 0,
    mtime_nanos: 0,
};

impl ProjectionProfile {
    /// Returns the profiled destination path.
    #[must_use]
    pub const fn path(&self) -> &RelativePath {
        &self.path
    }

    /// Returns the exact registered presentation profile.
    #[must_use]
    pub const fn profile(&self) -> &FeatureRef {
        &self.profile
    }
}

/// Reports failure to authenticate or compile a View projection.
#[derive(Debug, thiserror::Error)]
pub enum ProjectionError {
    /// A configured admission ceiling is zero or internally inconsistent.
    #[error("invalid projection limit: {0}")]
    InvalidLimit(&'static str),
    /// Canonical View decoding failed.
    #[error("portable View decoding failed: {0}")]
    Decode(#[source] aos_sandbox_core::CanonicalCborError),
    /// The allocation preflight found a malformed or unsupported View shape.
    #[error("portable View allocation preflight failed: {0}")]
    DecodePreflight(&'static str),
    /// The supplied descriptor is not the exact canonical View object.
    #[error("portable View descriptor does not match the supplied bytes")]
    ViewDescriptorMismatch,
    /// Logical View identity or revision uses a forbidden zero sentinel.
    #[error("portable View identity or revision is a zero sentinel")]
    InvalidViewIdentity,
    /// The source index does not match the View's immutable source.
    #[error("View source does not match the validated structural index")]
    SourceMismatch,
    /// This immutable FUSE projection cannot realize the View's semantics.
    #[error("unsupported immutable FUSE View semantic: {0}")]
    Unsupported(&'static str),
    /// A caller-controlled projection ceiling was exceeded.
    #[error("View projection exceeds its admitted {0} ceiling")]
    LimitExceeded(&'static str),
    /// A presentation source or destination cannot be resolved exactly.
    #[error("View presentation path cannot be resolved exactly")]
    UnresolvedPath,
    /// Two presentation paths claim the same final destination.
    #[error("View presentation produces a destination collision")]
    DestinationCollision,
    /// An admitted allocation was refused.
    #[error("View projection allocation was refused")]
    AllocationRefused,
    /// The authenticated structural index failed reauthentication.
    #[error("View projection index validation failed: {0}")]
    Index(#[from] IndexError),
}

/// Proves one complete, canonical View namespace against exact immutable inputs.
///
/// This value deliberately does not implement `Clone`. Detached mappings or a
/// digest alone are not authority to serve a different View or index.
pub struct ValidatedViewProjection<'index, 'bytes> {
    view: View,
    view_descriptor: ObjectDescriptor,
    view_id: ViewId,
    view_revision: Revision,
    index: &'index ValidatedIndex<'bytes>,
    nodes: Vec<ProjectedNode>,
    source_nodes: Vec<Option<IndexNodeView<'bytes>>>,
    profiles: Vec<ProjectionProfile>,
    synthetic_directory: SyntheticDirectoryMetadata,
    commitment: [u8; 32],
}

impl<'index, 'bytes> ValidatedViewProjection<'index, 'bytes> {
    /// Returns the decoded View covered by the exact descriptor proof.
    #[must_use]
    pub const fn view(&self) -> &View {
        &self.view
    }

    /// Returns the exact portable View descriptor.
    #[must_use]
    pub const fn view_descriptor(&self) -> &ObjectDescriptor {
        &self.view_descriptor
    }

    /// Returns the durable logical View identity and exact revision.
    #[must_use]
    pub const fn view_identity(&self) -> (ViewId, Revision) {
        (self.view_id, self.view_revision)
    }

    /// Returns the exact validated source index.
    #[must_use]
    pub const fn index(&self) -> &'index ValidatedIndex<'bytes> {
        self.index
    }

    /// Reports whether this exact View's immutable source references an object.
    ///
    /// Compilation authenticated the View descriptor and bound its source tree
    /// to the retained index. An object may be hidden by presentation actions;
    /// source membership is a retention proof, not permission to read a path.
    /// Callers authorizing a cache pin must still establish current View and
    /// consumer authority, physical partition, and pin-acquisition authority.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::Index`] if an authenticated index record
    /// cannot be decoded, which safe callers cannot cause.
    pub fn references_source_object(
        &self,
        object: &ObjectDescriptor,
    ) -> Result<bool, ProjectionError> {
        self.index
            .references_portable_object(object)
            .map_err(ProjectionError::Index)
    }

    /// Returns all mappings in byte-component path order.
    #[must_use]
    pub fn nodes(&self) -> &[ProjectedNode] {
        &self.nodes
    }

    /// Returns all bound metadata profiles in byte-component path order.
    #[must_use]
    pub fn profiles(&self) -> &[ProjectionProfile] {
        &self.profiles
    }

    /// Returns the derived commitment used in connection-authority binding.
    #[must_use]
    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Returns canonical metadata for View-created directory ancestors.
    #[must_use]
    pub const fn synthetic_directory(&self) -> SyntheticDirectoryMetadata {
        self.synthetic_directory
    }

    /// Resolves one exact projected path without allocating.
    #[must_use]
    pub fn lookup(&self, path: &RelativePath) -> Option<&ProjectedNode> {
        self.nodes
            .binary_search_by(|candidate| compare_path(candidate.path(), path))
            .ok()
            .map(|position| &self.nodes[position])
    }

    /// Returns the stable ordinal and node for one exact projected path.
    #[must_use]
    pub fn lookup_with_ordinal(&self, path: &RelativePath) -> Option<(usize, &ProjectedNode)> {
        self.nodes
            .binary_search_by(|candidate| compare_path(candidate.path(), path))
            .ok()
            .map(|position| (position, &self.nodes[position]))
    }

    /// Returns a retained projected node by its stable canonical ordinal.
    #[must_use]
    pub fn node(&self, ordinal: usize) -> Option<&ProjectedNode> {
        self.nodes.get(ordinal)
    }

    /// Resolves a byte-exact immediate child while inspecting projected entries only.
    #[must_use]
    pub fn child(&self, parent: usize, name: &[u8]) -> Option<(usize, &ProjectedNode)> {
        let parent = self.nodes.get(parent)?;
        self.nodes.iter().enumerate().find(|(_, candidate)| {
            candidate.path.components().len() == parent.path.components().len() + 1
                && candidate
                    .path
                    .components()
                    .starts_with(parent.path.components())
                && candidate
                    .path
                    .components()
                    .last()
                    .is_some_and(|component| component.as_bytes() == name)
        })
    }

    /// Iterates immediate children in canonical byte-component order.
    pub fn children(&self, parent: usize) -> impl Iterator<Item = (usize, &ProjectedNode)> + '_ {
        let parent_path = self.nodes.get(parent).map(ProjectedNode::path);
        self.nodes.iter().enumerate().filter(move |(_, candidate)| {
            parent_path.is_some_and(|path| is_immediate_child(path, candidate.path()))
        })
    }

    /// Returns the profile bound to an exact projected ordinal, when present.
    #[must_use]
    pub fn profile(&self, ordinal: usize) -> Option<&ProjectionProfile> {
        let path = self.nodes.get(ordinal)?.path();
        self.profiles
            .binary_search_by(|candidate| compare_path(candidate.path(), path))
            .ok()
            .map(|position| &self.profiles[position])
    }

    /// Reauthenticates a projected source mapping against the retained index.
    ///
    /// Synthetic directories return `None`. The lookup is linear in source
    /// record ID because V1 intentionally exposes no unauthenticated direct
    /// record-offset constructor; workers should retain their lazy inode entry.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::Index`] if retained index bytes no longer
    /// reproduce the mapping, which safe immutable owners cannot cause.
    pub fn source_node(
        &self,
        projected: &ProjectedNode,
    ) -> Result<Option<IndexNodeView<'bytes>>, ProjectionError> {
        let ordinal = self
            .lookup_with_ordinal(projected.path())
            .filter(|(_, candidate)| *candidate == projected)
            .map(|(ordinal, _)| ordinal)
            .ok_or(ProjectionError::UnresolvedPath)?;
        let retained = *self
            .source_nodes
            .get(ordinal)
            .ok_or(ProjectionError::UnresolvedPath)?;
        let ProjectedNodeKind::Source { record_id, kind } = projected.kind else {
            if retained.is_some() {
                return Err(ProjectionError::UnresolvedPath);
            }
            return Ok(None);
        };
        let node = retained.ok_or(ProjectionError::UnresolvedPath)?;
        if node.record_id() != record_id || node.kind() != kind {
            return Err(ProjectionError::UnresolvedPath);
        }
        Ok(Some(self.index.authenticate_node(&node)?))
    }
}

struct SourceNode<'bytes> {
    path: RelativePath,
    record_id: u64,
    kind: IndexNodeKind,
    hardlink_group: Option<ObjectDigest>,
    record: IndexNodeView<'bytes>,
}

/// Authenticates and compiles one immutable, read-only View projection.
///
/// Compilation starts from the source tree's identity mapping. `Exclude`
/// removes a destination subtree, `Include` adds an exact source subtree at a
/// destination, and `Present` reasserts the View's exact negotiated identity
/// profile on an existing result. Other profile semantics require a registered
/// resolver and are rejected rather than treated as an identity operation.
/// Include-created destination parents are explicit synthetic directories.
/// Every final destination is unique and the result is sorted canonically.
///
/// # Errors
///
/// Returns [`ProjectionError`] for invalid limits, a noncanonical or mismatched
/// View object, unsupported live or mutable semantics, source/index mismatch,
/// unresolved actions, namespace collisions, index corruption, allocation
/// refusal, or any exceeded work/output ceiling.
pub fn compile_view_projection<'index, 'bytes>(
    view_bytes: &[u8],
    view_descriptor: &ObjectDescriptor,
    view_id: ViewId,
    view_revision: Revision,
    index: &'index ValidatedIndex<'bytes>,
    limits: ProjectionLimits,
) -> Result<ValidatedViewProjection<'index, 'bytes>, ProjectionError> {
    validate_limits(limits)?;
    if view_id.as_bytes() == &[0; 16] || view_revision.get() == 0 {
        return Err(ProjectionError::InvalidViewIdentity);
    }
    if view_bytes.len() > limits.decode.maximum_bytes {
        return Err(ProjectionError::LimitExceeded("View byte"));
    }
    if validate_descriptor_role(DescriptorRole::FilesystemViewRevision, view_descriptor).is_err() {
        return Err(ProjectionError::ViewDescriptorMismatch);
    }

    let verified_descriptor =
        descriptor_for_bytes(clone_media_type(view_descriptor.media_type())?, view_bytes);
    if verified_descriptor != *view_descriptor {
        return Err(ProjectionError::ViewDescriptorMismatch);
    }

    let core_decode_heap_bytes = preflight_view_allocations(view_bytes, limits)?;
    let (view, decoded_view_heap_bytes) = {
        let decoded = decode_view(view_bytes, limits.decode).map_err(ProjectionError::Decode)?;
        let (view, retained_heap_bytes) = clone_view_fallibly(&decoded)?;
        let transient_decode_bytes = core_decode_heap_bytes
            .checked_add(retained_heap_bytes)
            .and_then(|bytes| {
                bytes.checked_add(verified_descriptor.media_type().as_str().len() as u64)
            })
            .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
        if transient_decode_bytes > limits.maximum_working_bytes {
            return Err(ProjectionError::LimitExceeded("decoded View heap"));
        }
        (view, retained_heap_bytes)
    };
    if view.presentation().len() > limits.maximum_actions {
        return Err(ProjectionError::LimitExceeded("action"));
    }
    if view.consistency() != ViewConsistency::Immutable {
        return Err(ProjectionError::Unsupported("non-immutable consistency"));
    }
    if view.mutation() != ViewMutation::ReadOnly {
        return Err(ProjectionError::Unsupported("mutable presentation"));
    }
    let ViewSource::ImmutableTree { tree } = view.source() else {
        return Err(ProjectionError::Unsupported("live source"));
    };
    if tree != &index.crosslinks().tree {
        return Err(ProjectionError::SourceMismatch);
    }
    if index.summary().records > limits.maximum_source_records {
        return Err(ProjectionError::LimitExceeded("source record"));
    }

    let source = collect_source_nodes(index, limits)?;
    let mut nodes = identity_projection(&source, view_id, view_revision, limits)?;
    let mut node_path_bytes = total_path_bytes(nodes.iter().map(ProjectedNode::path))?;
    let mut profile_path_bytes = 0_u64;
    nodes.sort_by(|left, right| compare_path(left.path(), right.path()));
    reject_collisions(&nodes)?;
    let mut profiles = Vec::new();
    profiles
        .try_reserve_exact(view.presentation().len())
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if profiles.capacity() > view.presentation().len() {
        return Err(ProjectionError::LimitExceeded("profile heap"));
    }
    for action in view.presentation() {
        match action {
            PresentationAction::Exclude { destination } => {
                nodes.retain(|node| !destination.contains(node.path()));
                profiles
                    .retain(|profile: &ProjectionProfile| !destination.contains(profile.path()));
                node_path_bytes = total_path_bytes(nodes.iter().map(ProjectedNode::path))?;
                profile_path_bytes =
                    total_path_bytes(profiles.iter().map(ProjectionProfile::path))?;
            }
            PresentationAction::Include {
                source_prefix,
                destination,
            } => {
                apply_include(
                    source_prefix,
                    destination,
                    &source,
                    &mut nodes,
                    view_id,
                    view_revision,
                    limits,
                    &mut node_path_bytes,
                    profile_path_bytes,
                )?;
                add_synthetic_parents(
                    &mut nodes,
                    view_id,
                    view_revision,
                    limits,
                    &mut node_path_bytes,
                    profile_path_bytes,
                )?;
            }
            PresentationAction::Present {
                destination,
                presentation_profile,
            } => {
                if presentation_profile != view.identity_presentation()
                    || nodes
                        .binary_search_by(|node| compare_path(node.path(), destination))
                        .is_err()
                    || profiles.iter().any(|profile| profile.path() == destination)
                {
                    return Err(ProjectionError::Unsupported(
                        "unresolved or duplicate non-identity Present profile",
                    ));
                }
                let next_profile_bytes = profile_path_bytes
                    .checked_add(path_byte_len(destination)?)
                    .ok_or(ProjectionError::LimitExceeded("path byte"))?;
                let Some(total_path_bytes) = node_path_bytes.checked_add(next_profile_bytes) else {
                    return Err(ProjectionError::LimitExceeded("path byte"));
                };
                if total_path_bytes > limits.maximum_path_bytes {
                    return Err(ProjectionError::LimitExceeded("path byte"));
                }
                profiles.push(ProjectionProfile {
                    path: clone_path(destination)?,
                    profile: clone_feature(presentation_profile)?,
                });
                profile_path_bytes = next_profile_bytes;
            }
        }
    }
    add_synthetic_parents(
        &mut nodes,
        view_id,
        view_revision,
        limits,
        &mut node_path_bytes,
        profile_path_bytes,
    )?;
    nodes.sort_by(|left, right| compare_path(left.path(), right.path()));
    reject_collisions(&nodes)?;
    reject_non_directory_ancestors(&nodes)?;
    recompute_link_counts(&mut nodes)?;

    profiles.sort_by(|left, right| compare_path(left.path(), right.path()));
    let descriptor_heap_bytes = u64::try_from(view_descriptor.media_type().as_str().len())
        .map_err(|_| ProjectionError::LimitExceeded("working byte"))?;
    let source_nodes = resolve_projected_sources(&nodes, &source, limits)?;
    enforce_result_limits(
        &nodes,
        nodes.capacity(),
        &source_nodes,
        &profiles,
        profiles.capacity(),
        decoded_view_heap_bytes,
        descriptor_heap_bytes,
        limits,
    )?;
    let commitment = projection_commitment(
        &verified_descriptor,
        view_id,
        view_revision,
        index,
        &view,
        &nodes,
        &profiles,
        SYNTHETIC_DIRECTORY_V1,
    );

    Ok(ValidatedViewProjection {
        view,
        view_descriptor: verified_descriptor,
        view_id,
        view_revision,
        index,
        nodes,
        source_nodes,
        profiles,
        synthetic_directory: SYNTHETIC_DIRECTORY_V1,
        commitment,
    })
}

fn validate_limits(limits: ProjectionLimits) -> Result<(), ProjectionError> {
    if limits.maximum_actions == 0 {
        return Err(ProjectionError::InvalidLimit("actions"));
    }
    if limits.maximum_source_records == 0 {
        return Err(ProjectionError::InvalidLimit("source records"));
    }
    if limits.maximum_projected_nodes == 0 {
        return Err(ProjectionError::InvalidLimit("projected nodes"));
    }
    if limits.maximum_path_components == 0
        || limits.maximum_path_components > RelativePath::MAX_COMPONENTS
    {
        return Err(ProjectionError::InvalidLimit("path components"));
    }
    if limits.maximum_path_bytes == 0 || limits.maximum_working_bytes == 0 {
        return Err(ProjectionError::InvalidLimit("working bytes"));
    }
    let maximum_source = limits
        .maximum_source_records
        .checked_mul(size_of::<SourceNode<'static>>() as u64)
        .ok_or(ProjectionError::InvalidLimit("working bytes"))?;
    let maximum_projected = (limits.maximum_projected_nodes as u64)
        .checked_mul(size_of::<ProjectedNode>() as u64)
        .ok_or(ProjectionError::InvalidLimit("working bytes"))?;
    let maximum_projected_sources = (limits.maximum_projected_nodes as u64)
        .checked_mul(size_of::<Option<IndexNodeView<'static>>>() as u64)
        .ok_or(ProjectionError::InvalidLimit("working bytes"))?;
    let maximum_profiles = (limits.maximum_actions as u64)
        .checked_mul(size_of::<ProjectionProfile>() as u64)
        .ok_or(ProjectionError::InvalidLimit("working bytes"))?;
    let maximum_identity_work = (limits.maximum_projected_nodes as u64)
        .checked_mul(size_of::<([u8; 32], usize)>() as u64)
        .ok_or(ProjectionError::InvalidLimit("working bytes"))?;
    let maximum_decoded = u64::try_from(limits.decode.maximum_bytes)
        .map_err(|_| ProjectionError::InvalidLimit("working bytes"))?;
    let maximum_decoded_items = u64::try_from(limits.decode.maximum_total_items)
        .map_err(|_| ProjectionError::InvalidLimit("working bytes"))?;
    let maximum_decoded_item_bytes = size_of::<PresentationAction>()
        .max(size_of::<FeatureRef>())
        .max(size_of::<PathName>()) as u64;
    let maximum_decoded_expansion = maximum_decoded_items
        .checked_mul(maximum_decoded_item_bytes)
        .and_then(|bytes| bytes.checked_add(maximum_decoded))
        // The core decoder's bounded value and the exact-capacity retained
        // clone coexist briefly before the core value is dropped.
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or(ProjectionError::InvalidLimit("working bytes"))?;
    let maximum_profile_strings = (limits.maximum_actions as u64)
        .checked_mul(255)
        .ok_or(ProjectionError::InvalidLimit("working bytes"))?;
    let maximum_modeled = maximum_source
        .checked_add(maximum_projected)
        .and_then(|bytes| bytes.checked_add(maximum_projected_sources))
        .and_then(|bytes| bytes.checked_add(maximum_profiles))
        .and_then(|bytes| bytes.checked_add(maximum_identity_work))
        // Source paths, result paths, and one transient parent/path clone.
        .and_then(|bytes| bytes.checked_add(limits.maximum_path_bytes.checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(maximum_decoded_expansion))
        .and_then(|bytes| bytes.checked_add(maximum_profile_strings))
        .and_then(|bytes| bytes.checked_add(255))
        .ok_or(ProjectionError::InvalidLimit("working bytes"))?;
    if maximum_modeled > limits.maximum_working_bytes {
        return Err(ProjectionError::InvalidLimit("working bytes"));
    }
    Ok(())
}

/// Inspects the exact View schema without allocating before the core decoder.
///
/// The core canonical decoder bounds collection lengths but uses infallible
/// standard-library allocation for its short-lived owned value. This pass
/// rejects action/path lengths against the tighter projection ceilings and
/// computes every requested vector, path-component, descriptor, and feature
/// string byte before that decoder runs. The decoded value is subsequently
/// copied into exact-capacity fallible storage and immediately dropped.
fn preflight_view_allocations(
    bytes: &[u8],
    limits: ProjectionLimits,
) -> Result<u64, ProjectionError> {
    validate_canonical_cbor(bytes, limits.decode).map_err(ProjectionError::Decode)?;

    let mut cursor = AllocationPreflightCursor::new(bytes);
    cursor.array(8)?;
    cursor.unsigned()?;

    let mut heap_bytes = 0_u64;
    preflight_view_source(&mut cursor, &mut heap_bytes)?;

    let action_count = cursor.array_len()?;
    if action_count > limits.maximum_actions {
        return Err(ProjectionError::LimitExceeded("action"));
    }
    add_allocation(
        &mut heap_bytes,
        action_count,
        size_of::<PresentationAction>(),
    )?;
    for _ in 0..action_count {
        preflight_presentation_action(&mut cursor, limits, &mut heap_bytes)?;
    }

    cursor.unsigned()?;
    cursor.unsigned()?;
    preflight_feature(&mut cursor, &mut heap_bytes)?;
    cursor.array(2)?;
    cursor.unsigned()?;
    cursor.byte_string()?;

    let required_count = cursor.array_len()?;
    add_allocation(&mut heap_bytes, required_count, size_of::<FeatureRef>())?;
    for _ in 0..required_count {
        preflight_feature(&mut cursor, &mut heap_bytes)?;
    }
    cursor.finish()?;

    if heap_bytes > limits.maximum_working_bytes {
        return Err(ProjectionError::LimitExceeded("decoded View heap"));
    }
    Ok(heap_bytes)
}

fn preflight_view_source(
    cursor: &mut AllocationPreflightCursor<'_>,
    heap_bytes: &mut u64,
) -> Result<(), ProjectionError> {
    let length = cursor.array_len()?;
    match (cursor.unsigned()?, length) {
        (0, 2) => preflight_descriptor(cursor, heap_bytes),
        (1, 4) => {
            cursor.byte_string()?;
            cursor.byte_string()?;
            cursor.unsigned()?;
            Ok(())
        }
        _ => Err(ProjectionError::DecodePreflight("invalid View source")),
    }
}

fn preflight_descriptor(
    cursor: &mut AllocationPreflightCursor<'_>,
    heap_bytes: &mut u64,
) -> Result<(), ProjectionError> {
    cursor.array(4)?;
    let media_bytes = cursor.text_string()?;
    *heap_bytes = heap_bytes
        .checked_add(media_bytes as u64)
        .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
    cursor.unsigned()?;
    cursor.byte_string()?;
    cursor.unsigned()?;
    Ok(())
}

fn preflight_presentation_action(
    cursor: &mut AllocationPreflightCursor<'_>,
    limits: ProjectionLimits,
    heap_bytes: &mut u64,
) -> Result<(), ProjectionError> {
    let length = cursor.array_len()?;
    match (cursor.unsigned()?, length) {
        (0, 3) => {
            preflight_path(cursor, limits, heap_bytes)?;
            preflight_path(cursor, limits, heap_bytes)
        }
        (1, 2) => preflight_path(cursor, limits, heap_bytes),
        (2, 3) => {
            preflight_path(cursor, limits, heap_bytes)?;
            preflight_feature(cursor, heap_bytes)
        }
        _ => Err(ProjectionError::DecodePreflight(
            "invalid presentation action",
        )),
    }
}

fn preflight_path(
    cursor: &mut AllocationPreflightCursor<'_>,
    limits: ProjectionLimits,
    heap_bytes: &mut u64,
) -> Result<(), ProjectionError> {
    let component_count = cursor.array_len()?;
    if component_count > limits.maximum_path_components {
        return Err(ProjectionError::LimitExceeded("path component"));
    }
    add_allocation(heap_bytes, component_count, size_of::<PathName>())?;
    for _ in 0..component_count {
        let name_bytes = cursor.byte_string()?;
        if name_bytes > 255 {
            return Err(ProjectionError::DecodePreflight("oversized path name"));
        }
        *heap_bytes = heap_bytes
            .checked_add(name_bytes as u64)
            .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
    }
    Ok(())
}

fn preflight_feature(
    cursor: &mut AllocationPreflightCursor<'_>,
    heap_bytes: &mut u64,
) -> Result<(), ProjectionError> {
    cursor.array(3)?;
    let namespace_bytes = cursor.text_string()?;
    if namespace_bytes > 255 {
        return Err(ProjectionError::DecodePreflight(
            "oversized feature namespace",
        ));
    }
    *heap_bytes = heap_bytes
        .checked_add(namespace_bytes as u64)
        .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
    cursor.unsigned()?;
    cursor.unsigned()?;
    Ok(())
}

fn add_allocation(total: &mut u64, count: usize, item_bytes: usize) -> Result<(), ProjectionError> {
    let allocation = (count as u64)
        .checked_mul(item_bytes as u64)
        .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
    *total = total
        .checked_add(allocation)
        .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
    Ok(())
}

struct AllocationPreflightCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> AllocationPreflightCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn array(&mut self, expected: usize) -> Result<(), ProjectionError> {
        let actual = self.array_len()?;
        if actual == expected {
            Ok(())
        } else {
            Err(ProjectionError::DecodePreflight("invalid array length"))
        }
    }

    fn array_len(&mut self) -> Result<usize, ProjectionError> {
        let (major, argument) = self.head()?;
        if major != 4 {
            return Err(ProjectionError::DecodePreflight("expected array"));
        }
        usize::try_from(argument)
            .map_err(|_| ProjectionError::DecodePreflight("array length overflow"))
    }

    fn unsigned(&mut self) -> Result<u64, ProjectionError> {
        let (major, argument) = self.head()?;
        if major == 0 {
            Ok(argument)
        } else {
            Err(ProjectionError::DecodePreflight(
                "expected unsigned integer",
            ))
        }
    }

    fn byte_string(&mut self) -> Result<usize, ProjectionError> {
        self.string(2)
    }

    fn text_string(&mut self) -> Result<usize, ProjectionError> {
        self.string(3)
    }

    fn string(&mut self, expected_major: u8) -> Result<usize, ProjectionError> {
        let (major, argument) = self.head()?;
        if major != expected_major {
            return Err(ProjectionError::DecodePreflight("unexpected string type"));
        }
        let length = usize::try_from(argument)
            .map_err(|_| ProjectionError::DecodePreflight("string length overflow"))?;
        self.take(length)?;
        Ok(length)
    }

    fn head(&mut self) -> Result<(u8, u64), ProjectionError> {
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let argument = match initial & 0x1f {
            value @ 0..=23 => u64::from(value),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(self.take_array()?)),
            26 => u64::from(u32::from_be_bytes(self.take_array()?)),
            27 => u64::from_be_bytes(self.take_array()?),
            _ => return Err(ProjectionError::DecodePreflight("invalid CBOR head")),
        };
        Ok((major, argument))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProjectionError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ProjectionError::DecodePreflight("CBOR offset overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ProjectionError::DecodePreflight("truncated CBOR"))?;
        self.position = end;
        Ok(value)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ProjectionError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProjectionError::DecodePreflight("truncated CBOR argument"))
    }

    fn finish(self) -> Result<(), ProjectionError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ProjectionError::DecodePreflight("trailing CBOR bytes"))
        }
    }
}

fn collect_source_nodes<'bytes>(
    index: &ValidatedIndex<'bytes>,
    limits: ProjectionLimits,
) -> Result<Vec<SourceNode<'bytes>>, ProjectionError> {
    let capacity = usize::try_from(index.summary().records)
        .map_err(|_| ProjectionError::LimitExceeded("source record"))?;
    let mut result: Vec<SourceNode<'bytes>> = Vec::new();
    result
        .try_reserve_exact(capacity)
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if result.capacity() > capacity {
        return Err(ProjectionError::LimitExceeded("source heap"));
    }

    let mut path_bytes = 0_u64;
    for record in index.retained_records() {
        let record = record?;
        let expected_id = result.len() as u64;
        if record.record_id() != expected_id {
            return Err(ProjectionError::Index(IndexError::InvalidRecord));
        }
        let path = if record.record_id() == 0 {
            RelativePath::default()
        } else {
            let parent = usize::try_from(record.parent_record_id())
                .ok()
                .and_then(|parent| result.get(parent))
                .ok_or(ProjectionError::Index(IndexError::InvalidRecord))?;
            let mut components = clone_components(parent.path.components())?;
            if components.len() == limits.maximum_path_components {
                return Err(ProjectionError::LimitExceeded("path component"));
            }
            components
                .try_reserve_exact(1)
                .map_err(|_| ProjectionError::AllocationRefused)?;
            if components.capacity() > components.len() + 1 {
                return Err(ProjectionError::LimitExceeded("path component heap"));
            }
            components.push(clone_name(record.name())?);
            RelativePath::new(components)
                .map_err(|_| ProjectionError::LimitExceeded("path component"))?
        };
        path_bytes = path_bytes
            .checked_add(path_byte_len(&path)?)
            .ok_or(ProjectionError::LimitExceeded("path byte"))?;
        if path_bytes > limits.maximum_path_bytes {
            return Err(ProjectionError::LimitExceeded("path byte"));
        }
        result.push(SourceNode {
            path,
            record_id: record.record_id(),
            kind: record.kind(),
            hardlink_group: record.hardlink_group()?,
            record,
        });
    }
    Ok(result)
}

fn identity_projection(
    source: &[SourceNode<'_>],
    view_id: ViewId,
    view_revision: Revision,
    limits: ProjectionLimits,
) -> Result<Vec<ProjectedNode>, ProjectionError> {
    if source.len() > limits.maximum_projected_nodes {
        return Err(ProjectionError::LimitExceeded("projected node"));
    }
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(limits.maximum_projected_nodes)
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if nodes.capacity() > limits.maximum_projected_nodes {
        return Err(ProjectionError::LimitExceeded("projected node heap"));
    }
    for node in source {
        let path = clone_path(&node.path)?;
        nodes.push(ProjectedNode {
            inode_identity: presentation_inode_identity(
                view_id,
                view_revision,
                &path,
                node.hardlink_group,
            ),
            link_count: 0,
            path,
            kind: ProjectedNodeKind::Source {
                record_id: node.record_id,
                kind: node.kind,
            },
        });
    }
    Ok(nodes)
}

fn resolve_projected_sources<'bytes>(
    nodes: &[ProjectedNode],
    source: &[SourceNode<'bytes>],
    limits: ProjectionLimits,
) -> Result<Vec<Option<IndexNodeView<'bytes>>>, ProjectionError> {
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(nodes.len())
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if retained.capacity() > nodes.len() {
        return Err(ProjectionError::LimitExceeded("projected source heap"));
    }
    for node in nodes {
        let record = match node.kind() {
            ProjectedNodeKind::SyntheticDirectory => None,
            ProjectedNodeKind::Source { record_id, kind } => {
                let position = usize::try_from(record_id)
                    .map_err(|_| ProjectionError::Index(IndexError::InvalidRecord))?;
                let source = source
                    .get(position)
                    .filter(|source| source.record_id == record_id && source.kind == kind)
                    .ok_or(ProjectionError::Index(IndexError::InvalidRecord))?;
                Some(source.record)
            }
        };
        retained.push(record);
    }
    Ok(retained)
}

fn apply_include(
    source_prefix: &RelativePath,
    destination: &RelativePath,
    source: &[SourceNode<'_>],
    nodes: &mut Vec<ProjectedNode>,
    view_id: ViewId,
    view_revision: Revision,
    limits: ProjectionLimits,
    node_path_bytes: &mut u64,
    profile_path_bytes: u64,
) -> Result<(), ProjectionError> {
    let before = nodes.len();
    for source_node in source
        .iter()
        .filter(|node| source_prefix.contains(&node.path))
    {
        if nodes.len() == limits.maximum_projected_nodes {
            return Err(ProjectionError::LimitExceeded("projected node"));
        }
        let suffix = &source_node.path.components()[source_prefix.components().len()..];
        let component_count = destination
            .components()
            .len()
            .checked_add(suffix.len())
            .ok_or(ProjectionError::LimitExceeded("path component"))?;
        if component_count > limits.maximum_path_components {
            return Err(ProjectionError::LimitExceeded("path component"));
        }
        let added_path_bytes = component_byte_len(destination.components())?
            .checked_add(component_byte_len(suffix)?)
            .ok_or(ProjectionError::LimitExceeded("path byte"))?;
        let next_path_bytes = node_path_bytes
            .checked_add(added_path_bytes)
            .ok_or(ProjectionError::LimitExceeded("path byte"))?;
        if !combined_path_bytes_within(
            next_path_bytes,
            profile_path_bytes,
            limits.maximum_path_bytes,
        ) {
            return Err(ProjectionError::LimitExceeded("path byte"));
        }
        let mut components = clone_components(destination.components())?;
        components
            .try_reserve_exact(suffix.len())
            .map_err(|_| ProjectionError::AllocationRefused)?;
        if components.capacity() > component_count {
            return Err(ProjectionError::LimitExceeded("path component heap"));
        }
        for component in suffix {
            components.push(clone_path_name(component)?);
        }
        let path = RelativePath::new(components)
            .map_err(|_| ProjectionError::LimitExceeded("path component"))?;
        nodes.push(ProjectedNode {
            inode_identity: presentation_inode_identity(
                view_id,
                view_revision,
                &path,
                source_node.hardlink_group,
            ),
            link_count: 0,
            path,
            kind: ProjectedNodeKind::Source {
                record_id: source_node.record_id,
                kind: source_node.kind,
            },
        });
        *node_path_bytes = next_path_bytes;
    }
    if nodes.len() == before {
        return Err(ProjectionError::UnresolvedPath);
    }
    Ok(())
}

fn add_synthetic_parents(
    nodes: &mut Vec<ProjectedNode>,
    view_id: ViewId,
    view_revision: Revision,
    limits: ProjectionLimits,
    node_path_bytes: &mut u64,
    profile_path_bytes: u64,
) -> Result<(), ProjectionError> {
    nodes
        .try_reserve_exact(limits.maximum_projected_nodes.saturating_sub(nodes.len()))
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if nodes.capacity() > limits.maximum_projected_nodes {
        return Err(ProjectionError::LimitExceeded("projected node heap"));
    }

    if nodes.is_empty() {
        let root = RelativePath::default();
        nodes.push(ProjectedNode {
            inode_identity: presentation_inode_identity(view_id, view_revision, &root, None),
            link_count: 0,
            path: root,
            kind: ProjectedNodeKind::SyntheticDirectory,
        });
        return Ok(());
    }

    // Each bounded-depth pass adds only immediate parents absent at its start.
    // The spare region is checked too, so duplicate parents never consume
    // projected-node or path-byte admission credit.
    loop {
        merge_projected_nodes(nodes)?;
        *node_path_bytes = total_path_bytes(nodes.iter().map(ProjectedNode::path))?;
        let initial = nodes.len();
        let mut added = false;
        for position in 0..initial {
            let components = nodes[position].path.components();
            let Some(parent_len) = components.len().checked_sub(1) else {
                continue;
            };
            let parent = path_from_components(&components[..parent_len])?;
            if nodes[..initial]
                .binary_search_by(|candidate| compare_path(candidate.path(), &parent))
                .is_ok()
                || nodes[initial..].iter().any(|node| node.path() == &parent)
            {
                continue;
            }
            let added_path_bytes = component_byte_len(&components[..parent_len])?;
            let next_path_bytes = node_path_bytes
                .checked_add(added_path_bytes)
                .ok_or(ProjectionError::LimitExceeded("path byte"))?;
            if !combined_path_bytes_within(
                next_path_bytes,
                profile_path_bytes,
                limits.maximum_path_bytes,
            ) {
                return Err(ProjectionError::LimitExceeded("path byte"));
            }
            if nodes.len() == limits.maximum_projected_nodes {
                return Err(ProjectionError::LimitExceeded("projected node"));
            }
            nodes.push(ProjectedNode {
                inode_identity: presentation_inode_identity(view_id, view_revision, &parent, None),
                link_count: 0,
                path: parent,
                kind: ProjectedNodeKind::SyntheticDirectory,
            });
            *node_path_bytes = next_path_bytes;
            added = true;
        }
        if !added {
            break;
        }
    }

    Ok(())
}

fn merge_projected_nodes(nodes: &mut Vec<ProjectedNode>) -> Result<(), ProjectionError> {
    nodes.sort_by(|left, right| compare_path(left.path(), right.path()));
    let mut write = 0_usize;
    for read in 0..nodes.len() {
        if write != 0 && nodes[write - 1].path == nodes[read].path {
            match (nodes[write - 1].kind, nodes[read].kind) {
                (ProjectedNodeKind::SyntheticDirectory, ProjectedNodeKind::SyntheticDirectory)
                | (ProjectedNodeKind::Source { .. }, ProjectedNodeKind::SyntheticDirectory) => {}
                (ProjectedNodeKind::SyntheticDirectory, ProjectedNodeKind::Source { .. }) => {
                    nodes.swap(write - 1, read);
                }
                (ProjectedNodeKind::Source { .. }, ProjectedNodeKind::Source { .. }) => {
                    return Err(ProjectionError::DestinationCollision);
                }
            }
            continue;
        }
        nodes.swap(write, read);
        write += 1;
    }
    nodes.truncate(write);
    Ok(())
}

fn reject_collisions(nodes: &[ProjectedNode]) -> Result<(), ProjectionError> {
    if nodes
        .windows(2)
        .any(|pair| compare_path(pair[0].path(), pair[1].path()) == Ordering::Equal)
    {
        return Err(ProjectionError::DestinationCollision);
    }
    Ok(())
}

fn reject_non_directory_ancestors(nodes: &[ProjectedNode]) -> Result<(), ProjectionError> {
    for node in nodes {
        let components = node.path().components();
        for parent_len in 0..components.len() {
            let parent = path_from_components(&components[..parent_len])?;
            let Some(candidate) = nodes
                .binary_search_by(|candidate| compare_path(candidate.path(), &parent))
                .ok()
                .map(|position| &nodes[position])
            else {
                return Err(ProjectionError::UnresolvedPath);
            };
            if !matches!(
                candidate.kind(),
                ProjectedNodeKind::SyntheticDirectory
                    | ProjectedNodeKind::Source {
                        kind: IndexNodeKind::Directory,
                        ..
                    }
            ) {
                return Err(ProjectionError::Unsupported(
                    "file or symlink used as a projected ancestor",
                ));
            }
        }
    }
    Ok(())
}

fn recompute_link_counts(nodes: &mut [ProjectedNode]) -> Result<(), ProjectionError> {
    let mut file_identities = Vec::new();
    file_identities
        .try_reserve_exact(nodes.len())
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if file_identities.capacity() > nodes.len() {
        return Err(ProjectionError::LimitExceeded("identity heap"));
    }
    for (position, node) in nodes.iter().enumerate() {
        if matches!(
            node.kind,
            ProjectedNodeKind::Source {
                kind: IndexNodeKind::File,
                ..
            }
        ) {
            file_identities.push((node.inode_identity, position));
        }
    }
    file_identities.sort_unstable_by_key(|(identity, _)| *identity);
    let mut start = 0_usize;
    while start < file_identities.len() {
        let mut end = start + 1;
        while end < file_identities.len() && file_identities[end].0 == file_identities[start].0 {
            end += 1;
        }
        let count =
            u64::try_from(end - start).map_err(|_| ProjectionError::LimitExceeded("link count"))?;
        for (_, position) in &file_identities[start..end] {
            nodes[*position].link_count = count;
        }
        start = end;
    }

    for position in 0..nodes.len() {
        let count = match nodes[position].kind {
            ProjectedNodeKind::Source {
                kind: IndexNodeKind::File,
                ..
            } => continue,
            ProjectedNodeKind::Source {
                kind: IndexNodeKind::Symlink,
                ..
            } => 1,
            ProjectedNodeKind::Source {
                kind: IndexNodeKind::Directory,
                ..
            }
            | ProjectedNodeKind::SyntheticDirectory => 2,
        };
        nodes[position].link_count = count;
    }
    for position in 0..nodes.len() {
        if nodes[position].path.components().is_empty()
            || !matches!(
                nodes[position].kind,
                ProjectedNodeKind::Source {
                    kind: IndexNodeKind::Directory,
                    ..
                } | ProjectedNodeKind::SyntheticDirectory
            )
        {
            continue;
        }
        let components = nodes[position].path.components();
        let parent = path_from_components(&components[..components.len() - 1])?;
        let parent = nodes
            .binary_search_by(|node| compare_path(node.path(), &parent))
            .map_err(|_| ProjectionError::UnresolvedPath)?;
        nodes[parent].link_count = nodes[parent]
            .link_count
            .checked_add(1)
            .ok_or(ProjectionError::LimitExceeded("link count"))?;
    }
    Ok(())
}

fn is_immediate_child(parent: &RelativePath, candidate: &RelativePath) -> bool {
    candidate.components().len() == parent.components().len() + 1
        && candidate.components().starts_with(parent.components())
}

fn enforce_result_limits(
    nodes: &[ProjectedNode],
    node_capacity: usize,
    source_nodes: &[Option<IndexNodeView<'_>>],
    profiles: &[ProjectionProfile],
    profile_capacity: usize,
    decoded_view_heap_bytes: u64,
    descriptor_heap_bytes: u64,
    limits: ProjectionLimits,
) -> Result<(), ProjectionError> {
    let mut path_bytes = 0_u64;
    for path in nodes
        .iter()
        .map(ProjectedNode::path)
        .chain(profiles.iter().map(ProjectionProfile::path))
    {
        path_bytes = path_bytes
            .checked_add(path_byte_len(path)?)
            .ok_or(ProjectionError::LimitExceeded("path byte"))?;
    }
    if path_bytes > limits.maximum_path_bytes {
        return Err(ProjectionError::LimitExceeded("path byte"));
    }
    let node_storage = (node_capacity as u64)
        .checked_mul(size_of::<ProjectedNode>() as u64)
        .ok_or(ProjectionError::LimitExceeded("working byte"))?;
    let profile_storage = (profile_capacity as u64)
        .checked_mul(size_of::<ProjectionProfile>() as u64)
        .ok_or(ProjectionError::LimitExceeded("working byte"))?;
    let source_storage = (source_nodes.len() as u64)
        .checked_mul(size_of::<Option<IndexNodeView<'static>>>() as u64)
        .ok_or(ProjectionError::LimitExceeded("working byte"))?;
    let modeled = node_storage
        .checked_add(profile_storage)
        .and_then(|bytes| bytes.checked_add(source_storage))
        .and_then(|bytes| bytes.checked_add(path_bytes))
        .and_then(|bytes| bytes.checked_add(decoded_view_heap_bytes))
        .and_then(|bytes| bytes.checked_add(descriptor_heap_bytes))
        .and_then(|bytes| bytes.checked_add(profile_namespace_bytes(profiles).ok()?))
        .ok_or(ProjectionError::LimitExceeded("working byte"))?;
    if modeled > limits.maximum_working_bytes {
        return Err(ProjectionError::LimitExceeded("working byte"));
    }
    Ok(())
}

fn view_heap_bytes(view: &View) -> Result<u64, ProjectionError> {
    let mut bytes = (view.presentation().len() as u64)
        .checked_mul(size_of::<PresentationAction>() as u64)
        .and_then(|value| {
            value.checked_add(
                (view.required_features().len() as u64)
                    .checked_mul(size_of::<FeatureRef>() as u64)?,
            )
        })
        .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
    bytes = bytes
        .checked_add(view.identity_presentation().namespace().len() as u64)
        .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
    for feature in view.required_features() {
        bytes = bytes
            .checked_add(feature.namespace().len() as u64)
            .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
    }
    for action in view.presentation() {
        match action {
            PresentationAction::Include {
                source_prefix,
                destination,
            } => {
                bytes = bytes
                    .checked_add(path_byte_len(source_prefix)?)
                    .and_then(|value| value.checked_add(path_byte_len(destination).ok()?))
                    .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
            }
            PresentationAction::Exclude { destination } => {
                bytes = bytes
                    .checked_add(path_byte_len(destination)?)
                    .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
            }
            PresentationAction::Present {
                destination,
                presentation_profile,
            } => {
                bytes = bytes
                    .checked_add(path_byte_len(destination)?)
                    .and_then(|value| {
                        value.checked_add(presentation_profile.namespace().len() as u64)
                    })
                    .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
            }
        }
    }
    if let ViewSource::ImmutableTree { tree } = view.source() {
        bytes = bytes
            .checked_add(tree.media_type().as_str().len() as u64)
            .ok_or(ProjectionError::LimitExceeded("decoded View heap"))?;
    }
    Ok(bytes)
}

fn profile_namespace_bytes(profiles: &[ProjectionProfile]) -> Result<u64, ProjectionError> {
    profiles.iter().try_fold(0_u64, |bytes, profile| {
        bytes
            .checked_add(profile.profile.namespace().len() as u64)
            .ok_or(ProjectionError::LimitExceeded("profile heap"))
    })
}

fn path_byte_len(path: &RelativePath) -> Result<u64, ProjectionError> {
    component_byte_len(path.components())
}

fn component_byte_len(components: &[PathName]) -> Result<u64, ProjectionError> {
    components.iter().try_fold(0_u64, |total, name| {
        total
            .checked_add(name.as_bytes().len() as u64)
            .and_then(|bytes| bytes.checked_add(size_of::<PathName>() as u64))
            .ok_or(ProjectionError::LimitExceeded("path byte"))
    })
}

fn clone_name(bytes: &[u8]) -> Result<PathName, ProjectionError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if owned.capacity() > bytes.len() {
        return Err(ProjectionError::LimitExceeded("path name heap"));
    }
    owned.extend_from_slice(bytes);
    PathName::new(owned).map_err(|_| ProjectionError::Index(IndexError::InvalidRecord))
}

fn clone_path_name(name: &PathName) -> Result<PathName, ProjectionError> {
    clone_name(name.as_bytes())
}

fn clone_components(components: &[PathName]) -> Result<Vec<PathName>, ProjectionError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(components.len())
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if cloned.capacity() > components.len() {
        return Err(ProjectionError::LimitExceeded("path component heap"));
    }
    for component in components {
        cloned.push(clone_path_name(component)?);
    }
    Ok(cloned)
}

fn path_from_components(components: &[PathName]) -> Result<RelativePath, ProjectionError> {
    RelativePath::new(clone_components(components)?)
        .map_err(|_| ProjectionError::LimitExceeded("path component"))
}

fn clone_path(path: &RelativePath) -> Result<RelativePath, ProjectionError> {
    path_from_components(path.components())
}

fn clone_view_fallibly(view: &View) -> Result<(View, u64), ProjectionError> {
    let source = match view.source() {
        ViewSource::ImmutableTree { tree } => ViewSource::ImmutableTree {
            tree: clone_descriptor(tree)?,
        },
        ViewSource::LiveExport {
            owner_sandbox,
            export,
            source_generation,
        } => ViewSource::LiveExport {
            owner_sandbox: *owner_sandbox,
            export: *export,
            source_generation: *source_generation,
        },
    };

    let mut presentation = Vec::new();
    presentation
        .try_reserve_exact(view.presentation().len())
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if presentation.capacity() > view.presentation().len() {
        return Err(ProjectionError::LimitExceeded("decoded action heap"));
    }
    for action in view.presentation() {
        presentation.push(clone_presentation_action(action)?);
    }

    let identity_presentation = clone_feature(view.identity_presentation())?;
    let mut required_features = Vec::new();
    required_features
        .try_reserve_exact(view.required_features().len())
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if required_features.capacity() > view.required_features().len() {
        return Err(ProjectionError::LimitExceeded("decoded feature heap"));
    }
    for feature in view.required_features() {
        required_features.push(clone_feature(feature)?);
    }

    let cloned = View::new(
        source,
        presentation,
        view.consistency(),
        view.mutation(),
        identity_presentation,
        view.disclosure(),
        required_features,
    )
    .map_err(|_| ProjectionError::DecodePreflight("decoded View invariant changed"))?;
    let retained_heap_bytes = view_heap_bytes(&cloned)?;
    Ok((cloned, retained_heap_bytes))
}

fn clone_presentation_action(
    action: &PresentationAction,
) -> Result<PresentationAction, ProjectionError> {
    match action {
        PresentationAction::Include {
            source_prefix,
            destination,
        } => Ok(PresentationAction::Include {
            source_prefix: clone_path(source_prefix)?,
            destination: clone_path(destination)?,
        }),
        PresentationAction::Exclude { destination } => Ok(PresentationAction::Exclude {
            destination: clone_path(destination)?,
        }),
        PresentationAction::Present {
            destination,
            presentation_profile,
        } => Ok(PresentationAction::Present {
            destination: clone_path(destination)?,
            presentation_profile: clone_feature(presentation_profile)?,
        }),
    }
}

fn clone_feature(feature: &FeatureRef) -> Result<FeatureRef, ProjectionError> {
    let mut namespace = String::new();
    namespace
        .try_reserve_exact(feature.namespace().len())
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if namespace.capacity() > feature.namespace().len() {
        return Err(ProjectionError::LimitExceeded("profile heap"));
    }
    namespace.push_str(feature.namespace());
    FeatureRef::new(namespace, feature.major(), feature.minor())
        .map_err(|_| ProjectionError::Unsupported("invalid presentation profile"))
}

fn clone_descriptor(descriptor: &ObjectDescriptor) -> Result<ObjectDescriptor, ProjectionError> {
    Ok(ObjectDescriptor::new(
        clone_media_type(descriptor.media_type())?,
        descriptor.digest(),
        descriptor.encoded_size(),
    ))
}

fn clone_media_type(media_type: &MediaType) -> Result<MediaType, ProjectionError> {
    let media = media_type.as_str();
    let mut cloned_media = String::new();
    cloned_media
        .try_reserve_exact(media.len())
        .map_err(|_| ProjectionError::AllocationRefused)?;
    if cloned_media.capacity() > media.len() {
        return Err(ProjectionError::LimitExceeded("descriptor heap"));
    }
    cloned_media.push_str(media);
    MediaType::new(cloned_media)
        .map_err(|_| ProjectionError::Unsupported("invalid View descriptor media type"))
}

fn total_path_bytes<'a>(
    mut paths: impl Iterator<Item = &'a RelativePath>,
) -> Result<u64, ProjectionError> {
    paths.try_fold(0_u64, |total, path| {
        total
            .checked_add(path_byte_len(path)?)
            .ok_or(ProjectionError::LimitExceeded("path byte"))
    })
}

fn combined_path_bytes_within(nodes: u64, profiles: u64, maximum: u64) -> bool {
    matches!(nodes.checked_add(profiles), Some(total) if total <= maximum)
}

fn compare_path(left: &RelativePath, right: &RelativePath) -> Ordering {
    left.components()
        .iter()
        .map(PathName::as_bytes)
        .cmp(right.components().iter().map(PathName::as_bytes))
}

#[allow(clippy::too_many_arguments)]
fn projection_commitment(
    view_descriptor: &ObjectDescriptor,
    view_id: ViewId,
    view_revision: Revision,
    index: &ValidatedIndex<'_>,
    view: &View,
    nodes: &[ProjectedNode],
    profiles: &[ProjectionProfile],
    synthetic_directory: SyntheticDirectoryMetadata,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos-filesystem-view-projection-v1\0");
    hash_descriptor(&mut hasher, view_descriptor);
    hasher.update(view_id.as_bytes());
    hasher.update(view_revision.get().to_be_bytes());
    hash_descriptor(&mut hasher, index.descriptor());
    hasher.update(index.crosslinks().compiler_abi);
    hash_descriptor(&mut hasher, &index.crosslinks().tree);
    hash_view_semantics(&mut hasher, view);
    hasher.update((nodes.len() as u64).to_be_bytes());
    for node in nodes {
        hash_path(&mut hasher, node.path());
        hasher.update(node.inode_identity());
        hasher.update(node.link_count().to_be_bytes());
        match node.kind() {
            ProjectedNodeKind::Source { record_id, kind } => {
                hasher.update([0]);
                hasher.update(record_id.to_be_bytes());
                hasher.update([kind_code(kind)]);
            }
            ProjectedNodeKind::SyntheticDirectory => hasher.update([1]),
        }
    }
    hasher.update((profiles.len() as u64).to_be_bytes());
    for profile in profiles {
        hash_path(&mut hasher, profile.path());
        hash_feature(&mut hasher, profile.profile());
    }
    hasher.update(b"synthetic-directory-v1\0");
    hasher.update(synthetic_directory.mode.to_be_bytes());
    hasher.update(synthetic_directory.uid.to_be_bytes());
    hasher.update(synthetic_directory.gid.to_be_bytes());
    hasher.update(synthetic_directory.mtime_seconds.to_be_bytes());
    hasher.update(synthetic_directory.mtime_nanos.to_be_bytes());
    hasher.finalize().into()
}

fn hash_view_semantics(hasher: &mut Sha256, view: &View) {
    hasher.update([match view.consistency() {
        ViewConsistency::Immutable => 0,
        ViewConsistency::LocalLive => 1,
        ViewConsistency::ExternalVersioned => 2,
    }]);
    hasher.update([match view.mutation() {
        ViewMutation::ReadOnly => 0,
        ViewMutation::ReadWrite => 1,
        ViewMutation::PrivateCow => 2,
        ViewMutation::AppendOnly => 3,
        ViewMutation::Service => 4,
    }]);
    hash_feature(hasher, view.identity_presentation());
    hash_cache_domain(hasher, view.disclosure());
    hasher.update((view.required_features().len() as u64).to_be_bytes());
    for feature in view.required_features() {
        hash_feature(hasher, feature);
    }
}

fn hash_cache_domain(hasher: &mut Sha256, domain: CacheDomain) {
    hasher.update([match domain.kind() {
        aos_sandbox_core::model::CacheDomainKind::Private => 0,
        aos_sandbox_core::model::CacheDomainKind::Project => 1,
        aos_sandbox_core::model::CacheDomainKind::TrustDomain => 2,
        aos_sandbox_core::model::CacheDomainKind::Public => 3,
    }]);
    hasher.update(domain.domain_id().as_bytes());
}

fn hash_descriptor(hasher: &mut Sha256, descriptor: &ObjectDescriptor) {
    hasher.update((descriptor.media_type().as_str().len() as u64).to_be_bytes());
    hasher.update(descriptor.media_type().as_str().as_bytes());
    hasher.update(descriptor.digest().as_bytes());
    hasher.update(descriptor.encoded_size().to_be_bytes());
}

fn hash_feature(hasher: &mut Sha256, feature: &FeatureRef) {
    hasher.update((feature.namespace().len() as u64).to_be_bytes());
    hasher.update(feature.namespace().as_bytes());
    hasher.update(feature.major().to_be_bytes());
    hasher.update(feature.minor().to_be_bytes());
}

fn hash_path(hasher: &mut Sha256, path: &RelativePath) {
    hasher.update((path.components().len() as u64).to_be_bytes());
    for component in path.components() {
        hasher.update((component.as_bytes().len() as u64).to_be_bytes());
        hasher.update(component.as_bytes());
    }
}

fn presentation_inode_identity(
    view_id: ViewId,
    view_revision: Revision,
    path: &RelativePath,
    hardlink_group: Option<ObjectDigest>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos-filesystem-presentation-inode-v1\0");
    hasher.update(view_id.as_bytes());
    hasher.update(view_revision.get().to_be_bytes());
    match hardlink_group {
        Some(group) => {
            hasher.update([0]);
            hasher.update(group.as_bytes());
        }
        None => {
            hasher.update([1]);
            hash_path(&mut hasher, path);
        }
    }
    hasher.finalize().into()
}

const fn kind_code(kind: IndexNodeKind) -> u8 {
    match kind {
        IndexNodeKind::File => 0,
        IndexNodeKind::Directory => 1,
        IndexNodeKind::Symlink => 2,
    }
}
