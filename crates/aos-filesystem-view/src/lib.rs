//! Backend-neutral compilation of immutable filesystem views.
//!
//! This crate validates hostile portable tree graphs, translates portable
//! identities for one presentation connection, and builds a replaceable
//! architecture-neutral structural index. It owns no mount, network, cache,
//! or publication authority. Callers supply exact objects and a private
//! staging writer; privileged publication and FUSE realization remain separate.

mod graph;
mod index;
mod inode;
mod limits;
mod presentation;
mod source;

pub use graph::{CompileError, CompileSummary, TreeCompiler};
pub use index::{
    DirectoryEntries, DirectoryEntryView, DirectoryRange, INDEX_MEDIA_TYPE, INDEX_MEDIA_TYPE_V1,
    INDEX_MEDIA_TYPE_V2, INDEX_MEDIA_TYPE_V3, IndexAclEntries, IndexAclRange, IndexContentView,
    IndexCrosslinks, IndexError, IndexExpectation, IndexExtentRange, IndexExtentView, IndexExtents,
    IndexFileView, IndexNodeBodyView, IndexNodeKind, IndexNodeSemantics, IndexNodeView,
    IndexObjectDescriptorView, IndexRecords, IndexSparseContentView, IndexStaging, IndexSummary,
    IndexXattrRange, IndexXattrView, IndexXattrs, StagedIndex, ValidatedIndex, validate_index,
};
pub use inode::{
    DirectoryCookie, DirectoryHandleId, DirectoryHandleLimits, DirectoryReadEntries,
    DirectoryReadEntry, DirectoryReadKind, DirectoryReservation, ForgetRequest, ForgetSummary,
    InodeAttributes, InodeError, InodeLookup, InodeTable, InodeTableLimits, LiveInode,
    OpenHandleId, OpenReservation, ROOT_NODE_ID,
};
pub use limits::TreeCompileLimits;
pub use presentation::{
    AclCapability, IdMapExtent, IdentityMap, IdentityMapError, PreparedPresentation,
    PresentationError, PresentationLimits, PresentationPlan, PresentedAclEntries,
    PresentedAclRange, PresentedInodeAttributes, PresentedMetadata,
};
pub use source::{ExactObject, ObjectSource, SourceError, load_exact};
