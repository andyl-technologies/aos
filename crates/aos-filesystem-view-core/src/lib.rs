//! Portable filesystem-view source validation and presentation semantics.
//!
//! This crate compiles hostile source trees into bounded structural indexes,
//! validates those indexes, and binds a canonical View to its authenticated
//! source. It owns no worker, broker session, Linux descriptor, or cache effect.
//! Controllers and workers can therefore use the same source-membership proof
//! without introducing a dependency cycle through broker-session security.

mod graph;
mod index;
mod limits;
mod presentation;
mod remote_source;
mod source;
mod view_projection;

pub use graph::{CompileError, CompileSummary, TreeCompiler};
pub use index::{
    CompiledIndexBinding, DirectoryEntries, DirectoryEntryView, DirectoryRange, INDEX_MEDIA_TYPE,
    IndexAclEntries, IndexAclRange, IndexContentView, IndexCrosslinks, IndexError,
    IndexExpectation, IndexExtentRange, IndexExtentView, IndexExtents, IndexFileView,
    IndexNodeBodyView, IndexNodeKind, IndexNodeSemantics, IndexNodeView, IndexObjectDescriptorView,
    IndexRecords, IndexSparseContentView, IndexStaging, IndexSummary, IndexXattrRange,
    IndexXattrView, IndexXattrs, StagedIndex, ValidatedIndex, validate_index,
};
pub use limits::TreeCompileLimits;
pub use presentation::{
    AclCapability, IdMapExtent, IdentityMap, IdentityMapError, MetadataTransportError,
    MetadataTransportLimits, PreparedPresentation, PresentationError, PresentationLimits,
    PresentationPlan, PresentedAclEntries, PresentedAclRange, PresentedInodeAttributes,
    PresentedMetadata,
};
pub use remote_source::{
    DormantRemoteSource, FetchAmbiguity, FetchAttempt, FetchBeginPoll, FetchControl,
    FetchControlState, FetchLimits, FetchRead, FetchReceipt, FetchRecovery, FetchRecoveryError,
    FetchRecoveryPoll, ImmutableFetchTransport, RemoteFetchError,
};
pub use source::{ExactObject, ObjectSource, SourceError, load_exact};
pub use view_projection::{
    ProjectedNode, ProjectedNodeKind, ProjectionError, ProjectionLimits, ProjectionProfile,
    SyntheticDirectoryMetadata, ValidatedViewProjection, ValidatedViewSourceObject,
    compile_view_projection,
};

#[cfg(feature = "test-fixtures")]
#[doc(hidden)]
pub mod test_fixtures {
    //! Index fixtures for downstream worker and protocol qualification.

    pub use crate::index::{IndexNode, IndexRecord, StructuralIndexBuilder};
}
