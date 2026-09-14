//! Backend-neutral compilation of immutable filesystem views.
//!
//! This crate validates hostile portable tree graphs, translates portable
//! identities, compiles canonical View projections, joins connection authority,
//! plans bounded immutable reads, and builds a replaceable architecture-neutral
//! structural index. Pure worker lifecycle reducers cover restart, quarantine,
//! repair, and attachment reconciliation. The crate owns no mount, network,
//! cache, OS descriptor, or publication effect; privileged realization remains
//! separate.

mod graph;
mod index;
mod inode;
mod limits;
mod presentation;
mod source;
mod view_projection;
mod worker;

pub use graph::{CompileError, CompileSummary, TreeCompiler};
pub use index::{
    DirectoryEntries, DirectoryEntryView, DirectoryRange, INDEX_MEDIA_TYPE, IndexAclEntries,
    IndexAclRange, IndexContentView, IndexCrosslinks, IndexError, IndexExpectation,
    IndexExtentRange, IndexExtentView, IndexExtents, IndexFileView, IndexNodeBodyView,
    IndexNodeKind, IndexNodeSemantics, IndexNodeView, IndexObjectDescriptorView, IndexRecords,
    IndexSparseContentView, IndexStaging, IndexSummary, IndexXattrRange, IndexXattrView,
    IndexXattrs, StagedIndex, ValidatedIndex, validate_index,
};
pub use inode::{
    DirectoryCookie, DirectoryHandleId, DirectoryHandleLimits, DirectoryReadEntries,
    DirectoryReadEntry, DirectoryReadKind, DirectoryReservation, ForgetRequest, ForgetSummary,
    InodeAttributes, InodeError, InodeLookup, InodeTable, InodeTableLimits, LiveInode,
    OpenHandleId, OpenReservation, ROOT_NODE_ID,
};
pub use limits::TreeCompileLimits;
pub use presentation::{
    AclCapability, IdMapExtent, IdentityMap, IdentityMapError, MetadataTransportError,
    MetadataTransportLimits, PreparedPresentation, PresentationError, PresentationLimits,
    PresentationPlan, PresentedAclEntries, PresentedAclRange, PresentedInodeAttributes,
    PresentedMetadata,
};
pub use source::{ExactObject, ObjectSource, SourceError, load_exact};
pub use view_projection::{
    ProjectedNode, ProjectedNodeKind, ProjectionError, ProjectionLimits, ProjectionProfile,
    SyntheticDirectoryMetadata, ValidatedViewProjection, compile_view_projection,
};
pub use worker::{
    AttachmentHealth, AuthenticatedConnectionJoin, BackingDisposition, BackingIdentity,
    ConnectionAuthorityError, ConnectionLease, ConsumerEvidence, DataError, DataOpenPolicy,
    DataPlane, DataPlaneLimits, DataReadRequest, DataReadResult, DataReadScratch,
    DurableLifecycleEvent, DurableRegistrationRecord, DurableStateCodec, DurableStateError,
    DurableStateLimits, FileAccessMode, FileContentAuthority, FileOpenRequest, FrozenFeatureSet,
    FuseCapabilities, InitReply, InitRequest, InventoryEvidence, LifecycleError, LookupReply,
    MetadataConnection, MonotonicClock, MountPolicy, ObjectReadRequest, ObjectReadResult,
    OpenDirectoryReply, OpenFileReply, PassthroughRegistrations, PendingDirectoryReply,
    PendingFileReply, PreparedDataOpen, PreparedFuseConnection, ProcessEvidence, PublicationHealth,
    ReadDirEntry, ReadDirPage, ReadDirPageEntries, ReadSegment, ReadlinkReply,
    ReconciliationAction, RegistrationAction, RegistrationLimits, RegistrationOperation,
    RegistrationPhase, RejectedOperation, ReleaseDisposition, RepairEvidence, ReplyScratch,
    RequestBudget, RequestCheckpoint, RequestControl, RequestControlState, TeardownSummary,
    Uninterrupted, UserNamespaceIdentity, VerifiedBackingEvidence, VerifiedObjectReader,
    WorkerAttributes, WorkerError, WorkerLifecycle, WorkerLifecycleSnapshot, WorkerLimits,
    WorkerPhase,
};
