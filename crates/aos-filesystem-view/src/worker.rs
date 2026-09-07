//! Bounded backend-neutral metadata request execution for one connection.
//!
//! This module is the logic seam for a narrow FUSE transport adapter. It does
//! not parse a kernel wire format, own a kernel connection, or claim support
//! for kernel interruption. Every reply is a typed value, and variable-sized
//! directory output uses explicitly admitted caller-owned scratch storage.

use std::mem::size_of;

use crate::presentation::MetadataTransportCheckpoint;
use crate::{
    DirectoryHandleId, DirectoryHandleLimits, DirectoryReadKind, DirectoryReservation,
    ForgetRequest, ForgetSummary, IndexError, IndexNodeBodyView, IndexNodeKind, InodeError,
    InodeLookup, InodeTable, InodeTableLimits, MetadataTransportError, MetadataTransportLimits,
    PreparedPresentation, PresentationError, PresentedInodeAttributes, ValidatedIndex,
};

mod scratch;

pub use scratch::{ReadDirEntry, ReadDirPage, ReadDirPageEntries, ReplyScratch};
use scratch::{ReadDirRecord, usize_u64};

const ATTRIBUTE_REPLY_BYTES: u64 = size_of::<WorkerAttributes>() as u64;
const LOOKUP_REPLY_BYTES: u64 = size_of::<LookupReply>() as u64;
const HANDLE_REPLY_BYTES: u64 = size_of::<OpenDirectoryReply>() as u64;
const DIRECTORY_ENTRY_BYTES: u64 = size_of::<ReadDirRecord>() as u64;
const DIRECTORY_PAGE_BYTES: u64 = size_of::<ReadDirPage<'static>>() as u64;
const INIT_REPLY_BYTES: u64 = size_of::<InitReply>() as u64;
const READLINK_REPLY_BYTES: u64 = size_of::<ReadlinkReply<'static>>() as u64;

/// Bounds every request and the reusable output storage available to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerLimits {
    /// Maximum bytes charged for typed reply storage in one request.
    ///
    /// This uses the target-local Rust layout and padding of these reply types.
    /// It is backend-neutral accounting, never a portable or FUSE wire-size claim.
    pub maximum_output_bytes: u64,
    /// Maximum directory entries accepted for one request.
    pub maximum_directory_entries: usize,
    /// Maximum aggregate directory-name or symlink-target bytes per request.
    pub maximum_variable_bytes: usize,
    /// Maximum FORGET entries accepted before sorting one request.
    pub maximum_forget_entries: usize,
    /// Maximum heap bytes retained by one reply scratch allocation.
    pub maximum_scratch_heap_bytes: u64,
}

impl WorkerLimits {
    /// Creates explicit per-request and scratch ceilings.
    ///
    /// FORGET is fail-closed until [`Self::with_maximum_forget_entries`] sets
    /// its distinct entry ceiling.
    #[must_use]
    pub const fn new(
        maximum_output_bytes: u64,
        maximum_directory_entries: usize,
        maximum_variable_bytes: usize,
        maximum_scratch_heap_bytes: u64,
    ) -> Self {
        Self {
            maximum_output_bytes,
            maximum_directory_entries,
            maximum_variable_bytes,
            maximum_forget_entries: 0,
            maximum_scratch_heap_bytes,
        }
    }

    /// Sets the explicit per-request FORGET entry ceiling.
    #[must_use]
    pub const fn with_maximum_forget_entries(mut self, maximum: usize) -> Self {
        self.maximum_forget_entries = maximum;
        self
    }
}

/// Narrows the connection ceilings for one request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBudget {
    /// Maximum bytes charged for typed reply storage in this request.
    pub output_bytes: u64,
    /// Maximum entries in this directory reply.
    pub directory_entries: usize,
    /// Maximum aggregate name or symlink-target bytes in this request.
    pub variable_bytes: usize,
    /// Maximum caller-admitted FORGET entries in this request.
    pub forget_entries: usize,
}

impl RequestBudget {
    /// Creates one explicit request budget.
    ///
    /// FORGET is fail-closed until [`Self::with_forget_entries`] is applied.
    #[must_use]
    pub const fn new(output_bytes: u64, directory_entries: usize, variable_bytes: usize) -> Self {
        Self {
            output_bytes,
            directory_entries,
            variable_bytes,
            forget_entries: 0,
        }
    }

    /// Sets the explicit FORGET entry budget for this request.
    #[must_use]
    pub const fn with_forget_entries(mut self, maximum: usize) -> Self {
        self.forget_entries = maximum;
        self
    }
}

/// Identifies an explicit cooperative cancellation or deadline checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestCheckpoint {
    /// Before authenticated request work begins.
    BeforeWork,
    /// During potentially long but nonmutating iteration.
    DuringReadOnlyWork,
    /// After nonmutating validation and presentation.
    AfterReadOnlyWork,
    /// Immediately before a state transition.
    BeforeCommit,
}

/// Reports the caller's state at a cooperative checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestControlState {
    /// Processing may continue.
    Continue,
    /// The caller has cancelled the request.
    Cancelled,
    /// The caller's deadline has expired.
    DeadlineExpired,
}

/// Supplies backend-owned cancellation and deadline observations.
///
/// A transport may connect this trait to its own scheduling state. This core
/// makes no claim that a kernel interruption mechanism is currently wired.
pub trait RequestControl {
    /// Returns the current state at `checkpoint` without blocking.
    fn state(&self, checkpoint: RequestCheckpoint) -> RequestControlState;
}

/// Never cancels and has no deadline.
#[derive(Clone, Copy, Debug, Default)]
pub struct Uninterrupted;

impl RequestControl for Uninterrupted {
    fn state(&self, _checkpoint: RequestCheckpoint) -> RequestControlState {
        RequestControlState::Continue
    }
}

/// Closed backend-neutral errno classes exposed to transport adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorkerError {
    /// The request or cookie is malformed.
    #[error("invalid request")]
    InvalidArgument,
    /// A connection-scoped inode or handle is stale or foreign.
    #[error("stale connection identity")]
    Stale,
    /// A directory operation targeted a non-directory.
    #[error("not a directory")]
    NotDirectory,
    /// A symlink operation targeted a non-symlink.
    #[error("not a symbolic link")]
    NotSymlink,
    /// A configured count, byte, or heap limit was exceeded.
    #[error("request exceeds an admitted resource ceiling")]
    ResourceExhausted,
    /// Allocation inside explicitly admitted scratch storage was refused.
    #[error("bounded allocation was refused")]
    AllocationRefused,
    /// Cooperative cancellation was observed before a state transition.
    #[error("request cancelled")]
    Interrupted,
    /// A cooperative deadline check expired before a state transition.
    #[error("request deadline expired")]
    TimedOut,
    /// The operation is a mutation forbidden by the immutable filesystem.
    #[error("read-only filesystem")]
    ReadOnlyFilesystem,
    /// The immutable metadata worker deliberately does not implement this operation.
    #[error("operation not supported")]
    OperationNotSupported,
    /// Authenticated internal state failed closed.
    #[error("metadata worker integrity failure")]
    IntegrityFailure,
}

/// Describes transport feature requests without encoding a wire-level INIT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitRequest {
    /// Requests batched FORGET dispatch.
    pub batch_forget: bool,
    /// Requests directory-handle operations.
    pub directory_handles: bool,
    /// Requests READDIRPLUS, which this core never negotiates.
    pub readdir_plus: bool,
}

/// Reports the conservative feature intersection for this worker core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitReply {
    /// Whether batched FORGET was negotiated.
    pub batch_forget: bool,
    /// Whether directory handles were negotiated.
    pub directory_handles: bool,
    /// Always false because children are not interned during READDIR.
    pub readdir_plus: bool,
    /// Always true for this immutable worker.
    pub read_only: bool,
}

/// Owns copied, target-presented attributes for a typed reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerAttributes {
    /// Connection-scoped inode number.
    pub node_id: u64,
    /// Artifact-scoped record identity.
    pub record_id: u64,
    /// Presented node kind.
    pub kind: IndexNodeKind,
    /// Permission and special bits without file-type encoding.
    pub mode: u16,
    /// Presented UID.
    pub uid: u32,
    /// Presented GID.
    pub gid: u32,
    /// Exact target-ABI link count.
    pub nlink: u32,
    /// Logical file or symlink size, or zero for directories.
    pub size: u64,
    /// Normalized modification-time seconds.
    pub mtime_seconds: i64,
    /// Normalized modification-time nanoseconds.
    pub mtime_nanos: u32,
}

/// Returns either a negative lookup or a committed positive lookup reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupReply {
    /// The byte-exact child does not exist.
    Negative,
    /// The child exists and its lookup reference was committed.
    Positive {
        /// Presented attributes for the assigned connection inode.
        attributes: WorkerAttributes,
        /// Total retained lookup references for that inode after this lookup.
        lookup_references: u64,
    },
}

/// Borrows a checked symlink-target copy from caller-owned reply scratch.
///
/// ```compile_fail
/// use aos_filesystem_view::{
///     MetadataConnection, ReadlinkReply, ReplyScratch, RequestBudget, Uninterrupted, WorkerError,
/// };
///
/// fn target_cannot_escape(
///     worker: &MetadataConnection<'_, '_, '_, '_>,
///     scratch: &mut ReplyScratch,
/// ) -> Result<ReadlinkReply<'static>, WorkerError> {
///     worker.readlink(1, RequestBudget::new(4096, 0, 1024), scratch, &Uninterrupted)
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadlinkReply<'a> {
    target: &'a [u8],
}

impl<'a> ReadlinkReply<'a> {
    /// Returns the byte-exact target without a terminating NUL.
    #[must_use]
    pub const fn target(&self) -> &'a [u8] {
        self.target
    }
}

/// Holds an OPENDIR reservation until reply publication is committed or aborted.
#[must_use = "publish or abort the pending OPENDIR reply"]
pub struct PendingDirectoryReply {
    reservation: DirectoryReservation,
    attributes: WorkerAttributes,
}

impl PendingDirectoryReply {
    /// Returns the raw handle that a transport may encode into its prospective reply.
    #[must_use]
    pub const fn raw_handle(&self) -> u64 {
        self.reservation.raw_protocol_handle()
    }

    /// Returns the presented directory attributes validated before reservation.
    #[must_use]
    pub const fn attributes(&self) -> WorkerAttributes {
        self.attributes
    }
}

/// Identifies an activated OPENDIR reply and its presented attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenDirectoryReply {
    /// Typed connection authority for subsequent directory operations.
    pub handle: DirectoryHandleId,
    /// Presented attributes for the opened directory.
    pub attributes: WorkerAttributes,
}

/// Classifies deliberately unsupported request families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectedOperation {
    /// Any namespace or metadata mutation.
    Mutation,
    /// File open, read, write, flush, or synchronization.
    FileData,
    /// READDIRPLUS child interning.
    ReadDirPlus,
    /// Any xattr retrieval or mutation.
    ExtendedAttribute,
}

/// Summarizes in-memory handle state discarded during connection teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TeardownSummary {
    /// Pending and active file-open records discarded.
    pub file_handles: u64,
    /// Pending file-open records included in `file_handles`.
    pub pending_file_handles: u64,
    /// Pending and active directory-handle records discarded.
    pub directory_handles: u64,
    /// Pending directory records included in `directory_handles`.
    pub pending_directory_handles: u64,
}

/// Executes bounded immutable metadata operations for one logical connection.
///
/// Dropping this value releases only its in-memory inode, reservation, and
/// handle state. External transports remain responsible for their own kernel
/// or libfuse resources and for aborting a pending reply when publication fails.
pub struct MetadataConnection<'prepared, 'index, 'bytes, 'plan> {
    presentation: &'prepared PreparedPresentation<'index, 'bytes, 'plan>,
    inodes: InodeTable<'index, 'bytes>,
    limits: WorkerLimits,
    directory_enabled: bool,
    features: Option<InitReply>,
}

impl<'prepared, 'index, 'bytes, 'plan> MetadataConnection<'prepared, 'index, 'bytes, 'plan> {
    /// Creates one uninitialized worker bound to the presentation's exact V3 index.
    ///
    /// # Errors
    ///
    /// Returns a closed worker error when inode-table construction or admission fails.
    pub fn new(
        presentation: &'prepared PreparedPresentation<'index, 'bytes, 'plan>,
        connection_key: [u8; 32],
        inode_limits: InodeTableLimits,
        directory_limits: DirectoryHandleLimits,
        limits: WorkerLimits,
    ) -> Result<Self, WorkerError> {
        let directory_enabled = directory_limits.maximum_directory_handles != 0
            && directory_limits.maximum_total_handles != 0;
        let inodes = InodeTable::new_with_directory_limits(
            presentation.index(),
            connection_key,
            inode_limits,
            directory_limits,
        )
        .map_err(map_inode)?;
        Ok(Self {
            presentation,
            inodes,
            limits,
            directory_enabled,
            features: None,
        })
    }

    /// Returns the exact validated index shared by presentation and inode state.
    #[must_use]
    pub const fn index(&self) -> &'index ValidatedIndex<'bytes> {
        self.presentation.index()
    }

    /// Returns the connection inode table for read-only diagnostics.
    #[must_use]
    pub const fn inode_table(&self) -> &InodeTable<'index, 'bytes> {
        &self.inodes
    }

    /// Validates all immutable metadata against one transport profile.
    ///
    /// The scan observes cooperative cancellation before work, during every
    /// record, and after the final record. Connection-local node and handle
    /// identifiers are assigned dynamically and remain subject to independent
    /// runtime conversion checks.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataTransportError`] when the profile is invalid, the
    /// bounded scan cannot be admitted, control interrupts or expires, or any
    /// exposed index metadata is not exactly representable.
    pub fn validate_transport_representation(
        &self,
        limits: MetadataTransportLimits,
        control: &impl RequestControl,
    ) -> Result<(), MetadataTransportError> {
        self.presentation
            .validate_transport_representation_with(limits, |checkpoint| {
                let checkpoint = match checkpoint {
                    MetadataTransportCheckpoint::BeforeScan => RequestCheckpoint::BeforeWork,
                    MetadataTransportCheckpoint::DuringScan => {
                        RequestCheckpoint::DuringReadOnlyWork
                    }
                    MetadataTransportCheckpoint::Complete => RequestCheckpoint::BeforeCommit,
                };
                match control.state(checkpoint) {
                    RequestControlState::Continue => Ok(()),
                    RequestControlState::Cancelled => Err(MetadataTransportError::Interrupted),
                    RequestControlState::DeadlineExpired => Err(MetadataTransportError::TimedOut),
                }
            })
    }

    /// Negotiates the conservative metadata feature intersection exactly once.
    ///
    /// # Errors
    ///
    /// Returns an invalid-request, budget, cancellation, or deadline error.
    pub fn initialize(
        &mut self,
        request: InitRequest,
        budget: RequestBudget,
        control: &impl RequestControl,
    ) -> Result<InitReply, WorkerError> {
        self.check_budget(budget)?;
        require_output(budget, INIT_REPLY_BYTES)?;
        check(control, RequestCheckpoint::BeforeWork)?;
        if self.features.is_some() {
            return Err(WorkerError::InvalidArgument);
        }
        check(control, RequestCheckpoint::BeforeCommit)?;
        let reply = InitReply {
            batch_forget: request.batch_forget && self.limits.maximum_forget_entries != 0,
            directory_handles: request.directory_handles && self.directory_enabled,
            readdir_plus: false,
            read_only: true,
        };
        self.features = Some(reply);
        Ok(reply)
    }

    /// Performs a byte-exact LOOKUP with all fallible reply work before commit.
    ///
    /// # Errors
    ///
    /// Returns a closed validation, presentation, budget, cancellation, or
    /// admission error. No lookup reference is added on error.
    pub fn lookup(
        &mut self,
        parent: u64,
        name: &[u8],
        budget: RequestBudget,
        control: &impl RequestControl,
    ) -> Result<LookupReply, WorkerError> {
        self.ready_budget(budget)?;
        require_output(budget, LOOKUP_REPLY_BYTES)?;
        check(control, RequestCheckpoint::BeforeWork)?;

        let parent_live = self.inodes.live_inode(parent).map_err(map_inode)?;
        if parent_live.attributes().kind != IndexNodeKind::Directory {
            return Err(WorkerError::NotDirectory);
        }
        let child = self
            .index()
            .lookup_child_bytes(parent_live.record(), name)
            .map_err(map_index)?;
        let Some(child) = child else {
            check(control, RequestCheckpoint::AfterReadOnlyWork)?;
            return Ok(LookupReply::Negative);
        };
        let template = AttributeTemplate::from_presented(
            &self
                .presentation
                .present(&child)
                .map_err(map_presentation)?,
        );
        check(control, RequestCheckpoint::AfterReadOnlyWork)?;
        check(control, RequestCheckpoint::BeforeCommit)?;

        match self.inodes.lookup_bytes(parent, name).map_err(map_inode)? {
            InodeLookup::Negative => Err(WorkerError::IntegrityFailure),
            InodeLookup::Positive {
                attributes,
                lookup_references,
            } => Ok(LookupReply::Positive {
                attributes: template.with_node(attributes.node_id),
                lookup_references,
            }),
        }
    }

    /// Applies one bounded batch FORGET atomically.
    ///
    /// Connection and request entry ceilings are checked before the caller's
    /// batch is sorted. Later preflight errors may leave the caller's batch
    /// reordered, exactly matching [`InodeTable::forget`], but table state is
    /// unchanged until the final cancellation checkpoint succeeds.
    ///
    /// # Errors
    ///
    /// Returns a closed initialization, cancellation, deadline, or inode-state error.
    pub fn forget(
        &mut self,
        requests: &mut [ForgetRequest],
        budget: RequestBudget,
        control: &impl RequestControl,
    ) -> Result<ForgetSummary, WorkerError> {
        self.ready_budget(budget)?;
        if !self.ready()?.batch_forget {
            return Err(WorkerError::OperationNotSupported);
        }
        self.forget_checked(requests, budget, control)
    }

    /// Releases lookup references from one ordinary FORGET request.
    ///
    /// Ordinary FORGET does not require batched dispatch negotiation. It still
    /// requires INIT and an admitted connection and request entry budget.
    ///
    /// # Errors
    ///
    /// Returns initialization, budget, cancellation, deadline, or inode-state
    /// errors without releasing any references. A transport with no FORGET
    /// error reply must terminate the connection on failure.
    pub fn forget_one(
        &mut self,
        request: ForgetRequest,
        budget: RequestBudget,
        control: &impl RequestControl,
    ) -> Result<ForgetSummary, WorkerError> {
        self.ready_budget(budget)?;
        self.forget_checked(&mut [request], budget, control)
    }

    fn forget_checked(
        &mut self,
        requests: &mut [ForgetRequest],
        budget: RequestBudget,
        control: &impl RequestControl,
    ) -> Result<ForgetSummary, WorkerError> {
        if requests.len() > self.limits.maximum_forget_entries
            || requests.len() > budget.forget_entries
        {
            return Err(WorkerError::ResourceExhausted);
        }
        check(control, RequestCheckpoint::BeforeWork)?;
        check(control, RequestCheckpoint::DuringReadOnlyWork)?;
        let transaction = self.inodes.prepare_forget(requests).map_err(map_inode)?;
        check(control, RequestCheckpoint::DuringReadOnlyWork)?;
        check(control, RequestCheckpoint::BeforeCommit)?;
        Ok(transaction.commit())
    }

    /// Returns target-presented attributes without mutating connection state.
    ///
    /// # Errors
    ///
    /// Returns a closed stale, presentation, budget, cancellation, or deadline error.
    pub fn getattr(
        &self,
        node_id: u64,
        budget: RequestBudget,
        control: &impl RequestControl,
    ) -> Result<WorkerAttributes, WorkerError> {
        self.ready_budget(budget)?;
        require_output(budget, ATTRIBUTE_REPLY_BYTES)?;
        check(control, RequestCheckpoint::BeforeWork)?;
        let live = self.inodes.live_inode(node_id).map_err(map_inode)?;
        let presented = self
            .presentation
            .present(live.record())
            .map_err(map_presentation)?;
        let reply = AttributeTemplate::from_presented(&presented).with_node(node_id);
        check(control, RequestCheckpoint::AfterReadOnlyWork)?;
        Ok(reply)
    }

    /// Copies a checked symlink target into reusable admitted scratch storage.
    ///
    /// # Errors
    ///
    /// Returns a closed stale, wrong-kind, index, budget, cancellation, or deadline error.
    pub fn readlink<'scratch>(
        &self,
        node_id: u64,
        budget: RequestBudget,
        scratch: &'scratch mut ReplyScratch,
        control: &impl RequestControl,
    ) -> Result<ReadlinkReply<'scratch>, WorkerError> {
        self.ready_budget(budget)?;
        if budget.output_bytes > scratch.limits.maximum_output_bytes
            || budget.variable_bytes > scratch.limits.maximum_variable_bytes
        {
            return Err(WorkerError::ResourceExhausted);
        }
        check(control, RequestCheckpoint::BeforeWork)?;
        let live = self.inodes.live_inode(node_id).map_err(map_inode)?;
        let semantics = live.semantics().map_err(map_inode)?;
        let IndexNodeBodyView::Symlink { target } = semantics.body() else {
            return Err(WorkerError::NotSymlink);
        };
        let output_bytes = READLINK_REPLY_BYTES
            .checked_add(usize_u64(target.len())?)
            .ok_or(WorkerError::ResourceExhausted)?;
        require_output(budget, output_bytes)?;
        if target.len() > budget.variable_bytes {
            return Err(WorkerError::ResourceExhausted);
        }
        check(control, RequestCheckpoint::AfterReadOnlyWork)?;
        scratch.clear();
        scratch.names.extend_from_slice(target);
        Ok(ReadlinkReply {
            target: &scratch.names,
        })
    }

    /// Prepares and pins an OPENDIR reply without activating its raw handle.
    ///
    /// # Errors
    ///
    /// Returns a closed stale, kind, presentation, budget, cancellation, or
    /// handle-admission error. The returned token must be published or aborted.
    pub fn prepare_opendir(
        &mut self,
        node_id: u64,
        budget: RequestBudget,
        control: &impl RequestControl,
    ) -> Result<PendingDirectoryReply, WorkerError> {
        self.ready_budget(budget)?;
        if !self.ready()?.directory_handles {
            return Err(WorkerError::OperationNotSupported);
        }
        require_output(budget, HANDLE_REPLY_BYTES)?;
        check(control, RequestCheckpoint::BeforeWork)?;
        let live = self.inodes.live_inode(node_id).map_err(map_inode)?;
        if live.attributes().kind != IndexNodeKind::Directory {
            return Err(WorkerError::NotDirectory);
        }
        let attributes = AttributeTemplate::from_presented(
            &self
                .presentation
                .present(live.record())
                .map_err(map_presentation)?,
        )
        .with_node(node_id);
        check(control, RequestCheckpoint::AfterReadOnlyWork)?;
        check(control, RequestCheckpoint::BeforeCommit)?;
        let reservation = self.inodes.reserve_directory(node_id).map_err(map_inode)?;
        Ok(PendingDirectoryReply {
            reservation,
            attributes,
        })
    }

    /// Activates a prepared OPENDIR immediately before transport publication.
    ///
    /// If transport publication subsequently fails, the caller must invoke
    /// [`Self::rollback_opendir`] with the returned handle. Connection teardown
    /// also releases the in-memory state without external callbacks.
    /// A synchronous adapter that sends its reply before activation instead
    /// uses [`Self::commit_opendir_after_reply`]. These are alternative contracts;
    /// a reservation is activated exactly once.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a foreign, stale, or consumed reservation.
    pub fn publish_opendir(
        &mut self,
        pending: &mut PendingDirectoryReply,
    ) -> Result<OpenDirectoryReply, WorkerError> {
        self.activate_opendir(pending)
    }

    /// Commits a prepared OPENDIR after its synchronous reply succeeds.
    ///
    /// The caller first publishes [`PendingDirectoryReply::raw_handle`] using
    /// its transport's synchronous responder. It calls this method only when
    /// that responder reports success, and before dispatching another request
    /// or returning from the transport callback. The reservation remains pending
    /// throughout publication; success makes it available to the next request.
    /// The core cannot verify the external reply, so the adapter owns this
    /// ordering contract.
    ///
    /// This final transition has no cancellation or deadline checkpoint: after
    /// successful publication the peer already owns the handle. Cancellation
    /// observed then must not skip activation. If publication fails, the caller
    /// instead uses [`Self::abort_opendir`] and follows its transport's terminal
    /// reply-failure policy. It must never call both activation methods for one
    /// reservation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a foreign, stale, consumed, or corrupted
    /// reservation. Any error after a successful reply requires fatal connection
    /// teardown before another request is dispatched. The adapter must not send
    /// a second reply, retry activation, or expose this error as an ordinary
    /// request failure.
    pub fn commit_opendir_after_reply(
        &mut self,
        pending: &mut PendingDirectoryReply,
    ) -> Result<OpenDirectoryReply, WorkerError> {
        self.activate_opendir(pending)
    }

    fn activate_opendir(
        &mut self,
        pending: &mut PendingDirectoryReply,
    ) -> Result<OpenDirectoryReply, WorkerError> {
        let handle = self
            .inodes
            .activate_directory(&mut pending.reservation)
            .map_err(map_inode)?;
        Ok(OpenDirectoryReply {
            handle,
            attributes: pending.attributes,
        })
    }

    /// Aborts an OPENDIR reply that was not externally published.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a foreign, stale, consumed, or corrupted reservation.
    pub fn abort_opendir(
        &mut self,
        pending: &mut PendingDirectoryReply,
    ) -> Result<(), WorkerError> {
        self.inodes
            .abort_directory(&mut pending.reservation)
            .map_err(map_inode)
    }

    /// Rolls back an activated handle after external reply publication fails.
    ///
    /// # Errors
    ///
    /// Returns a closed stale, foreign, wrong-kind, or integrity error.
    pub fn rollback_opendir(&mut self, reply: OpenDirectoryReply) -> Result<(), WorkerError> {
        self.inodes
            .release_directory(reply.handle)
            .map_err(map_inode)
    }

    /// Produces a complete-entry READDIR page in reusable admitted scratch.
    ///
    /// The iterator is resumed at `cookie`. If the next complete entry exceeds
    /// any request budget, the page stops before it and returns the cookie of
    /// the last emitted entry (or the input cookie for an empty page).
    ///
    /// # Errors
    ///
    /// Returns a closed handle, cookie, budget, scratch, cancellation, deadline,
    /// index, or integrity error. Children are never interned.
    pub fn readdir<'scratch>(
        &self,
        raw_handle: u64,
        cookie: u64,
        budget: RequestBudget,
        scratch: &'scratch mut ReplyScratch,
        control: &impl RequestControl,
    ) -> Result<ReadDirPage<'scratch>, WorkerError> {
        self.ready_budget(budget)?;
        validate_scratch(budget, scratch)?;
        require_output(budget, DIRECTORY_PAGE_BYTES)?;
        check(control, RequestCheckpoint::BeforeWork)?;
        scratch.clear();
        let handle = self
            .inodes
            .resolve_active_directory(raw_handle)
            .map_err(map_inode)?;
        let source = self
            .inodes
            .directory_entries_raw(handle, cookie)
            .map_err(map_inode)?;
        let mut output_bytes = DIRECTORY_PAGE_BYTES;
        let mut continuation = cookie;
        let mut eof = true;

        for entry in source {
            check(control, RequestCheckpoint::DuringReadOnlyWork)
                .inspect_err(|_| scratch.clear())?;
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    scratch.clear();
                    return Err(map_inode(error));
                }
            };
            let name = entry.name();
            let next_names = scratch
                .names
                .len()
                .checked_add(name.len())
                .ok_or(WorkerError::ResourceExhausted)?;
            let charged = DIRECTORY_ENTRY_BYTES
                .checked_add(usize_u64(name.len())?)
                .ok_or(WorkerError::ResourceExhausted)?;
            let next_output = output_bytes
                .checked_add(charged)
                .ok_or(WorkerError::ResourceExhausted)?;
            if scratch.entries.len() == budget.directory_entries
                || next_names > budget.variable_bytes
                || next_output > budget.output_bytes
            {
                eof = false;
                break;
            }
            let start = scratch.names.len();
            scratch.names.extend_from_slice(name);
            let end = scratch.names.len();
            let (node_kind, node_id) = match entry.kind() {
                DirectoryReadKind::Dot => {
                    (IndexNodeKind::Directory, entry.inode().map(|a| a.node_id))
                }
                DirectoryReadKind::DotDot => (IndexNodeKind::Directory, None),
                DirectoryReadKind::Child => {
                    let Some(child) = entry.child() else {
                        scratch.clear();
                        return Err(WorkerError::IntegrityFailure);
                    };
                    (child.node().kind(), None)
                }
            };
            continuation = entry.next_cookie().get();
            scratch.entries.push(ReadDirRecord {
                name_start: start,
                name_end: end,
                kind: entry.kind(),
                node_kind,
                node_id,
                next_cookie: continuation,
            });
            output_bytes = next_output;
        }
        check(control, RequestCheckpoint::AfterReadOnlyWork).inspect_err(|_| scratch.clear())?;
        Ok(ReadDirPage {
            names: &scratch.names,
            entries: &scratch.entries,
            continuation_cookie: continuation,
            eof,
        })
    }

    /// Produces a directory page after validating the request's inode and handle pair.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::readdir`], or [`WorkerError::Stale`] when
    /// the handle belongs to a different inode. No directory contents are read
    /// before this association is checked.
    pub fn readdir_for_node<'scratch>(
        &self,
        node_id: u64,
        raw_handle: u64,
        cookie: u64,
        budget: RequestBudget,
        scratch: &'scratch mut ReplyScratch,
        control: &impl RequestControl,
    ) -> Result<ReadDirPage<'scratch>, WorkerError> {
        self.ready_budget(budget)?;
        check(control, RequestCheckpoint::BeforeWork)?;
        self.inodes
            .resolve_active_directory_for_node(raw_handle, node_id)
            .map_err(map_inode)?;
        self.readdir(raw_handle, cookie, budget, scratch, control)
    }

    /// Releases an active directory handle after validating its request inode.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::releasedir`], or [`WorkerError::Stale`]
    /// when the handle belongs to a different inode. Errors preserve the handle.
    pub fn releasedir_for_node(
        &mut self,
        node_id: u64,
        raw_handle: u64,
        control: &impl RequestControl,
    ) -> Result<(), WorkerError> {
        self.ready()?;
        check(control, RequestCheckpoint::BeforeWork)?;
        self.inodes
            .resolve_active_directory_for_node(raw_handle, node_id)
            .map_err(map_inode)?;
        self.releasedir(raw_handle, control)
    }

    /// Releases one active raw directory handle.
    ///
    /// # Errors
    ///
    /// Returns a closed stale, pending, wrong-kind, or integrity error.
    pub fn releasedir(
        &mut self,
        raw_handle: u64,
        control: &impl RequestControl,
    ) -> Result<(), WorkerError> {
        self.ready()?;
        check(control, RequestCheckpoint::BeforeWork)?;
        let handle = self
            .inodes
            .resolve_active_directory(raw_handle)
            .map_err(map_inode)?;
        check(control, RequestCheckpoint::AfterReadOnlyWork)?;
        check(control, RequestCheckpoint::BeforeCommit)?;
        self.inodes.release_directory(handle).map_err(map_inode)
    }

    /// Deterministically rejects operations outside the immutable metadata surface.
    ///
    /// # Errors
    ///
    /// Before INIT, returns [`WorkerError::InvalidArgument`]. After INIT, always
    /// returns read-only-filesystem for mutation and operation-not-supported for
    /// file data, READDIRPLUS, and xattr operations.
    pub fn reject(&self, operation: RejectedOperation) -> Result<(), WorkerError> {
        self.ready()?;
        match operation {
            RejectedOperation::Mutation => Err(WorkerError::ReadOnlyFilesystem),
            RejectedOperation::FileData
            | RejectedOperation::ReadDirPlus
            | RejectedOperation::ExtendedAttribute => Err(WorkerError::OperationNotSupported),
        }
    }

    /// Consumes the connection and discards every in-memory pending or active handle.
    ///
    /// This performs no callback and owns no external transport resource. A bridge
    /// remains responsible for closing its kernel or libfuse connection resources.
    #[must_use]
    pub fn teardown(self) -> TeardownSummary {
        TeardownSummary {
            file_handles: self.inodes.live_open_handles(),
            pending_file_handles: self.inodes.pending_open_handles(),
            directory_handles: self.inodes.live_directory_handles(),
            pending_directory_handles: self.inodes.pending_directory_handles(),
        }
    }

    fn ready(&self) -> Result<InitReply, WorkerError> {
        self.features.ok_or(WorkerError::InvalidArgument)
    }

    fn ready_budget(&self, budget: RequestBudget) -> Result<(), WorkerError> {
        self.ready()?;
        self.check_budget(budget)
    }

    fn check_budget(&self, budget: RequestBudget) -> Result<(), WorkerError> {
        if budget.output_bytes > self.limits.maximum_output_bytes
            || budget.directory_entries > self.limits.maximum_directory_entries
            || budget.variable_bytes > self.limits.maximum_variable_bytes
            || budget.forget_entries > self.limits.maximum_forget_entries
        {
            return Err(WorkerError::ResourceExhausted);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct AttributeTemplate {
    record_id: u64,
    kind: IndexNodeKind,
    mode: u16,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    mtime_seconds: i64,
    mtime_nanos: u32,
}

impl AttributeTemplate {
    fn from_presented(value: &PresentedInodeAttributes<'_>) -> Self {
        Self {
            record_id: value.record_id(),
            kind: value.kind(),
            mode: value.mode(),
            uid: value.uid(),
            gid: value.gid(),
            nlink: value.nlink(),
            size: value.size(),
            mtime_seconds: value.mtime_seconds(),
            mtime_nanos: value.mtime_nanos(),
        }
    }

    fn with_node(self, node_id: u64) -> WorkerAttributes {
        WorkerAttributes {
            node_id,
            record_id: self.record_id,
            kind: self.kind,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            nlink: self.nlink,
            size: self.size,
            mtime_seconds: self.mtime_seconds,
            mtime_nanos: self.mtime_nanos,
        }
    }
}

fn check(control: &impl RequestControl, checkpoint: RequestCheckpoint) -> Result<(), WorkerError> {
    match control.state(checkpoint) {
        RequestControlState::Continue => Ok(()),
        RequestControlState::Cancelled => Err(WorkerError::Interrupted),
        RequestControlState::DeadlineExpired => Err(WorkerError::TimedOut),
    }
}

fn require_output(budget: RequestBudget, bytes: u64) -> Result<(), WorkerError> {
    (bytes <= budget.output_bytes)
        .then_some(())
        .ok_or(WorkerError::ResourceExhausted)
}

fn validate_scratch(budget: RequestBudget, scratch: &ReplyScratch) -> Result<(), WorkerError> {
    if budget.directory_entries > scratch.limits.maximum_directory_entries
        || budget.variable_bytes > scratch.limits.maximum_variable_bytes
        || budget.output_bytes > scratch.limits.maximum_output_bytes
    {
        return Err(WorkerError::ResourceExhausted);
    }
    Ok(())
}

fn map_index(error: IndexError) -> WorkerError {
    match error {
        IndexError::InvalidPathName(_) => WorkerError::InvalidArgument,
        IndexError::PointLookupUnavailable | IndexError::DirectoryIterationUnavailable => {
            WorkerError::OperationNotSupported
        }
        IndexError::LimitExceeded => WorkerError::ResourceExhausted,
        IndexError::AllocationRefused => WorkerError::AllocationRefused,
        _ => WorkerError::IntegrityFailure,
    }
}

fn map_presentation(error: PresentationError) -> WorkerError {
    match error {
        PresentationError::LimitExceeded(_) => WorkerError::ResourceExhausted,
        PresentationError::Identity(_) | PresentationError::LinkCountOverflow => {
            WorkerError::IntegrityFailure
        }
        PresentationError::VersionUnsupported => WorkerError::OperationNotSupported,
        PresentationError::Index(error) => map_index(error),
    }
}

fn map_inode(error: InodeError) -> WorkerError {
    match error {
        InodeError::Index(error) => map_index(error),
        InodeError::LimitExceeded(_) => WorkerError::ResourceExhausted,
        InodeError::AllocationRefused => WorkerError::AllocationRefused,
        InodeError::StaleNode
        | InodeError::InvalidOpenReservation
        | InodeError::OpenStillPending
        | InodeError::StaleOpenHandle
        | InodeError::ForeignOpenHandle
        | InodeError::InvalidDirectoryReservation
        | InodeError::DirectoryHandleStillPending
        | InodeError::StaleDirectoryHandle
        | InodeError::ForeignDirectoryHandle
        | InodeError::WrongHandleKind => WorkerError::Stale,
        InodeError::ParentNotDirectory | InodeError::DirectoryTargetNotDirectory => {
            WorkerError::NotDirectory
        }
        InodeError::ZeroForgetCount
        | InodeError::ForgetUnderflow
        | InodeError::InvalidDirectoryCookie => WorkerError::InvalidArgument,
        InodeError::DirectoryHandlesDisabled => WorkerError::OperationNotSupported,
        InodeError::OpenTargetNotFile | InodeError::InternalInvariant => {
            WorkerError::IntegrityFailure
        }
    }
}

#[cfg(test)]
#[path = "worker/tests.rs"]
mod tests;
