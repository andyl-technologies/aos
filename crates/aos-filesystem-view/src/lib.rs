//! Backend-neutral compilation of immutable filesystem views.
//!
//! This crate validates hostile portable tree graphs, translates portable
//! identities, compiles canonical View projections, joins connection authority,
//! plans bounded immutable reads and extended-attribute replies, and builds a
//! replaceable architecture-neutral structural index. Pure worker lifecycle
//! reducers cover restart, quarantine, repair, and attachment reconciliation.
//! The crate activates no mount, network, cache, service, or publication
//! effect. It does expose explicit dormant effect-owner seams for a future
//! immutable transport, worker supervisor, and Linux fs-verity mmap index
//! catalog. Its portable worker API is unconditional; Linux descriptor
//! ownership and protected FUSE qualification compile only on Linux.

mod graph;
mod index;
#[cfg(target_os = "linux")]
mod index_owner;
mod inode;
mod limits;
mod presentation;
mod remote_source;
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
pub use worker::{
    AttachmentHealth, AuthenticatedConnectionJoin, BackingDisposition, BackingIdentity,
    CallbackReducerBinding, CallbackReducerBrand, ConnectionAuthorityError, ConnectionLease,
    ConsumerEvidence, DataError, DataOpenPolicy, DataPlane, DataPlaneLimits, DataReadRequest,
    DataReadResult, DataReadScratch, DurableLifecycleEvent, DurableRegistrationRecord,
    DurableStateCodec, DurableStateError, DurableStateLimits, ExtendedAttributeError,
    ExtendedAttributeLimits, ExtendedAttributeReply, ExtendedAttributeScratch,
    ExtendedAttributeSize, ExtendedAttributeState, FileAccessMode, FileContentAuthority,
    FileOpenRequest, FrozenFeatureSet, FuseCapabilities, InitReply, InitRequest, InventoryEvidence,
    LifecycleError, LookupReply, MetadataConnection, MonotonicClock, MountPolicy,
    ObjectReadRequest, ObjectReadResult, OpenDirectoryReply, OpenFileReply,
    PassthroughRegistrations, PendingDirectoryReply, PendingFileReply, PreparedDataOpen,
    PreparedFuseConnection, ProcessEvidence, PublicationHealth, ReadDirEntry, ReadDirPage,
    ReadDirPageEntries, ReadSegment, ReadlinkReply, ReconciliationAction, RegistrationAction,
    RegistrationLimits, RegistrationOperation, RegistrationPhase, RejectedOperation,
    ReleaseDisposition, RepairEvidence, ReplyScratch, RequestBudget, RequestCheckpoint,
    RequestControl, RequestControlState, TeardownSummary, Uninterrupted, UserNamespaceIdentity,
    VerifiedBackingEvidence, VerifiedObjectReader, WorkerAttributes, WorkerError, WorkerLifecycle,
    WorkerLifecycleSnapshot, WorkerLimits, WorkerPhase,
};

#[cfg(target_os = "linux")]
pub use index_owner::{
    AmbiguousIndexReplacement, DormantIndexOwner, IndexCurrentness, IndexOwnerError,
    IndexPublication, IndexRecoveryFailure,
};
#[cfg(target_os = "linux")]
pub use worker::{
    DormantFilesystemWorkerPreparation, DormantReconciliationAdapter,
    PendingFuseConnectionQualification, ProtectedFuseConnectionQualification,
    ProtectedFuseKernelClockV1, QualificationAdmission, QualificationError, ReapEffectResult,
    ReconciliationAdapterError, ReconciliationEffectExecutor, ReconciliationObservation,
    SealedEffectReceipt, admit_fuse_connection_qualification,
};
