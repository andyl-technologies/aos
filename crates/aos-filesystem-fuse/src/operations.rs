//! Dormant immutable file and extended-attribute operation profile.
//!
//! This module normalizes Linux FUSE scalar requests into backend-neutral worker
//! operations. It accepts only connection-scoped inode and handle identities;
//! raw paths and borrowed OS descriptors are deliberately absent. The installed
//! V1 callback table does not reference this module, so constructing this state
//! cannot advertise or activate file-data or xattr support.

use aos_filesystem_view::{
    BackingIdentity, DataError, DataPlane, DataReadRequest, DataReadResult, DataReadScratch,
    ExtendedAttributeError, ExtendedAttributeLimits, ExtendedAttributeReply,
    ExtendedAttributeScratch, ExtendedAttributeState, MonotonicClock, PassthroughRegistrations,
    ReleaseDisposition, RequestBudget, RequestControl, VerifiedObjectReader, WorkerError,
};

use crate::file_callbacks::{
    BackingCloseReceipt, BackingOpenReceipt, FileCallbackError, FileCallbackState, OpenCompletion,
    OpenFinishFailure, OpenPublication, PendingCallbackOpen, RegisteredBacking,
    RejectedOpenCleanup, RejectedWorkerCleanup, ReleasePlan, WorkerReleasePermit,
};

/// Bounds dormant file and xattr adapter state independently of kernel buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImmutableOperationLimits {
    /// Maximum simultaneous pending and active file handles.
    pub maximum_file_handles: usize,
    /// Maximum bytes accepted in one READ request.
    pub maximum_read_bytes: usize,
    /// Complete extended-attribute limits.
    pub extended_attributes: ExtendedAttributeLimits,
}

impl ImmutableOperationLimits {
    fn validate(self) -> Result<Self, OperationError> {
        if self.maximum_file_handles == 0 || self.maximum_read_bytes == 0 {
            return Err(OperationError::InvalidRequest);
        }
        self.extended_attributes.validate()?;
        Ok(self)
    }
}

/// Identifies one active connection-scoped file handle request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileHandleRequest {
    /// Connection-scoped inode number from the request header.
    pub node_id: u64,
    /// Connection-scoped handle returned by OPEN.
    pub handle: u64,
}

impl FileHandleRequest {
    fn validate(self) -> Result<Self, OperationError> {
        if self.node_id == 0 || self.handle == 0 {
            return Err(OperationError::Stale);
        }
        Ok(self)
    }
}

/// Describes one normalized Linux FUSE READ request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadRequest {
    /// Exact active inode/handle pair.
    pub file: FileHandleRequest,
    /// Nonnegative logical file offset.
    pub offset: i64,
    /// Requested reply size from the kernel ABI.
    pub size: u32,
    /// Exclusive absolute monotonic deadline.
    pub deadline_ns: u64,
}

/// Describes one normalized Linux FUSE RELEASE request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseRequest {
    /// Exact active inode/handle pair.
    pub file: FileHandleRequest,
    /// Open flags echoed by the kernel.
    pub flags: i32,
    /// Kernel release flags; this profile negotiates no flush or lock-owner mode.
    pub release_flags: u32,
    /// Lock owner, which must be zero when lock release was not negotiated.
    pub lock_owner: u64,
}

impl ReleaseRequest {
    fn validate(self) -> Result<FileHandleRequest, OperationError> {
        let file = self.file.validate()?;
        crate::file_callbacks::normalize_open_flags(self.flags)?;
        if self.release_flags != 0 || self.lock_owner != 0 {
            return Err(OperationError::InvalidRequest);
        }
        Ok(file)
    }
}

/// Reports adapter validation, worker, data, or xattr failure.
#[derive(Debug, thiserror::Error)]
pub enum OperationError {
    /// A request scalar or configured limit is invalid.
    #[error("invalid immutable FUSE operation request")]
    InvalidRequest,
    /// A request exceeds the admitted bounded operation profile.
    #[error("immutable FUSE operation exceeds its resource ceiling")]
    ResourceExhausted,
    /// A node or handle identity is zero, foreign, stale, or generation-mismatched.
    #[error("stale immutable FUSE operation identity")]
    Stale,
    /// This connection is terminally faulted or failed an integrity invariant.
    #[error("immutable FUSE operation failed connection integrity checks")]
    Integrity,
    /// The connection did not admit this optional dormant operation family.
    #[error("immutable FUSE operation family was not admitted")]
    Unsupported,
    /// File callback sequencing failed.
    #[error("immutable FUSE file callback failed: {0}")]
    File(#[from] FileCallbackError),
    /// Extended-attribute lookup or sizing failed.
    #[error("immutable FUSE extended-attribute callback failed: {0}")]
    ExtendedAttribute(#[from] ExtendedAttributeError),
}

impl OperationError {
    /// Returns the positive Linux errno for a recoverable request failure.
    ///
    /// Integrity failures map to `EIO`; the caller must additionally terminate
    /// a connection when the underlying callback state marked it faulted.
    #[must_use]
    pub fn errno(&self) -> i32 {
        match self {
            Self::InvalidRequest => libc::EINVAL,
            Self::ResourceExhausted => libc::ENOMEM,
            Self::Stale => libc::ESTALE,
            Self::Integrity => libc::EIO,
            Self::Unsupported => libc::EOPNOTSUPP,
            Self::File(error) => file_errno(error),
            Self::ExtendedAttribute(error) => xattr_errno(error),
        }
    }
}

/// Owns all bounded dormant operation state for one exact connection generation.
pub(crate) struct ImmutableOperations {
    connection_binding: [u8; 32],
    worker_brand: u64,
    limits: ImmutableOperationLimits,
    files: FileCallbackState,
    xattrs: Option<ExtendedAttributeState>,
}

impl ImmutableOperations {
    /// Preallocates file state and binds admitted optional xattrs to one connection.
    ///
    /// This does not install callbacks, negotiate kernel features, open an FD,
    /// or alter the production metadata runner.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for invalid bounds, allocation refusal, or a
    /// foreign registration reducer.
    pub fn for_connection(
        connection: &mut aos_filesystem_view::MetadataConnection<'_, '_, '_, '_>,
        registrations: PassthroughRegistrations,
        limits: ImmutableOperationLimits,
    ) -> Result<Self, OperationError> {
        let limits = limits.validate()?;
        let connection_binding = connection.connection_binding();
        let worker_brand = connection.callback_instance_brand();
        if connection_binding == [0; 32] || worker_brand == 0 {
            return Err(OperationError::Stale);
        }
        let xattrs = if connection.extended_attributes_admitted() {
            Some(ExtendedAttributeState::for_connection(
                connection,
                limits.extended_attributes,
            )?)
        } else {
            None
        };
        let reducer_brand = connection
            .mint_callback_reducer_brand()
            .map_err(FileCallbackError::from)?;
        let files = FileCallbackState::for_connection(
            connection,
            registrations,
            reducer_brand,
            limits.maximum_file_handles,
        )?;
        Ok(Self {
            connection_binding,
            worker_brand,
            limits,
            files,
            xattrs,
        })
    }

    /// Normalizes and prepares one immutable OPEN without publishing a reply.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for foreign connection state, unsupported
    /// flags, exhausted handles, worker admission, or unavailable realization.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_open<'index>(
        &mut self,
        connection: &mut aos_filesystem_view::MetadataConnection<'_, 'index, '_, '_>,
        data_plane: &DataPlane,
        node_id: u64,
        flags: i32,
        backing: Option<BackingIdentity>,
        budget: RequestBudget,
        clock: &impl MonotonicClock,
        control: &impl RequestControl,
    ) -> Result<PendingCallbackOpen<'index>, OperationError> {
        self.validate_connection(connection)?;
        if node_id == 0 {
            return Err(OperationError::Stale);
        }
        Ok(self.files.prepare_open(
            connection, data_plane, node_id, flags, backing, budget, clock, control,
        )?)
    }

    /// Completes one synchronous OPEN publication transition.
    ///
    /// # Errors
    ///
    /// Returns [`OpenFinishFailure`] with the still-owned pending token when the
    /// failure is recoverable, or a terminal outcome after ambiguous publication.
    pub(crate) fn finish_open<'index>(
        &mut self,
        connection: &mut aos_filesystem_view::MetadataConnection<'_, 'index, '_, '_>,
        pending: PendingCallbackOpen<'index>,
        publication: OpenPublication,
    ) -> Result<OpenCompletion<'index>, OpenFinishFailure<'index>> {
        self.files.finish_open(connection, pending, publication)
    }

    /// Records a completed passthrough backing registration before OPEN reply.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for stale pending state or mismatched broker receipt.
    pub(crate) fn record_backing_opened(
        &mut self,
        pending: &mut PendingCallbackOpen<'_>,
        receipt: BackingOpenReceipt,
    ) -> Result<RegisteredBacking, OperationError> {
        Ok(self.files.record_backing_opened(pending, receipt)?)
    }

    /// Records close completion for a definitely rejected OPEN.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] unless the cleanup token, close receipt,
    /// connection generation, operation, and selector all match.
    pub(crate) fn record_rejected_backing_closed<'index>(
        &mut self,
        cleanup: RejectedOpenCleanup<'index>,
        receipt: BackingCloseReceipt,
    ) -> Result<RejectedWorkerCleanup<'index>, OperationError> {
        Ok(self
            .files
            .record_rejected_backing_closed(cleanup, receipt)?)
    }

    /// Aborts rejected worker state after durable registration cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for a foreign cleanup token or stale worker state.
    pub(crate) fn finish_rejected_open_cleanup<'index>(
        &mut self,
        connection: &mut aos_filesystem_view::MetadataConnection<'_, 'index, '_, '_>,
        cleanup: RejectedWorkerCleanup<'index>,
    ) -> Result<OpenCompletion<'index>, OperationError> {
        self.validate_connection(connection)?;
        Ok(self
            .files
            .finish_rejected_open_cleanup(connection, cleanup)?)
    }

    /// Recreates a rejected-OPEN close plan after a definite external failure.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] unless the token remains in the exact durable
    /// closing phase for this connection generation.
    pub(crate) fn retry_rejected_open_close(
        &self,
        cleanup: &RejectedOpenCleanup<'_>,
    ) -> Result<ReleasePlan, OperationError> {
        Ok(self.files.retry_rejected_open_close(cleanup)?)
    }

    /// Records an ambiguous rejected-OPEN close and faults the connection.
    ///
    /// # Errors
    ///
    /// Always returns the terminal ambiguity error after exact validation, or a
    /// stale error without accepting mismatched state.
    pub(crate) fn record_rejected_close_ambiguity(
        &mut self,
        connection: &mut aos_filesystem_view::MetadataConnection<'_, '_, '_, '_>,
        cleanup: RejectedOpenCleanup<'_>,
    ) -> Result<(), OperationError> {
        self.validate_connection(connection)?;
        Ok(self
            .files
            .record_rejected_close_ambiguity(connection, cleanup)?)
    }

    /// Executes one fully verified fallback READ.
    ///
    /// Negative offsets are rejected. The requested size is bounded before
    /// conversion, EOF may shorten the reply, and provider bytes remain private
    /// until whole-object integrity validation completes.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for invalid scalars, stale handles, passthrough
    /// ownership, cancellation/deadline, bounded retry exhaustion, or integrity
    /// failure.
    #[allow(clippy::too_many_arguments)]
    pub fn read<'scratch>(
        &self,
        connection: &aos_filesystem_view::MetadataConnection<'_, '_, '_, '_>,
        data_plane: &DataPlane,
        request: ReadRequest,
        scratch: &'scratch mut DataReadScratch,
        provider: &mut impl VerifiedObjectReader,
        clock: &impl MonotonicClock,
        control: &impl RequestControl,
    ) -> Result<DataReadResult<'scratch>, OperationError> {
        self.validate_connection(connection)?;
        let file = request.file.validate()?;
        let offset = u64::try_from(request.offset).map_err(|_| OperationError::InvalidRequest)?;
        let length = usize::try_from(request.size).map_err(|_| OperationError::InvalidRequest)?;
        if request.deadline_ns == 0 {
            return Err(OperationError::InvalidRequest);
        }
        if length > self.limits.maximum_read_bytes {
            return Err(OperationError::ResourceExhausted);
        }
        Ok(self.files.read(
            connection,
            data_plane,
            file.node_id,
            file.handle,
            DataReadRequest {
                offset,
                length,
                deadline_ns: request.deadline_ns,
            },
            scratch,
            provider,
            clock,
            control,
        )?)
    }

    /// Begins exact RELEASE cleanup for one active handle.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for unsupported release flags, stale or
    /// generation-mismatched handles, or an inconsistent backing registration.
    pub(crate) fn prepare_release(
        &mut self,
        connection: &aos_filesystem_view::MetadataConnection<'_, '_, '_, '_>,
        data_plane: &DataPlane,
        request: ReleaseRequest,
    ) -> Result<(ReleaseDisposition, ReleasePlan), OperationError> {
        self.validate_connection(connection)?;
        let file = request.validate()?;
        Ok(self
            .files
            .prepare_release(connection, data_plane, file.node_id, file.handle)?)
    }

    /// Recreates the exact close-before-release plan after a definite failure.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] unless the inode/handle pair and durable
    /// registration remain in their pending-release generation.
    pub(crate) fn retry_release(
        &self,
        connection: &aos_filesystem_view::MetadataConnection<'_, '_, '_, '_>,
        file: FileHandleRequest,
    ) -> Result<ReleasePlan, OperationError> {
        self.validate_connection(connection)?;
        let file = file.validate()?;
        Ok(self
            .files
            .retry_release(connection, file.node_id, file.handle)?)
    }

    /// Records a confirmed final backing close before worker-handle release.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] unless the receipt matches the exact
    /// pending handle, connection generation, and durable close operation.
    pub(crate) fn record_backing_closed(
        &mut self,
        file: FileHandleRequest,
        receipt: BackingCloseReceipt,
    ) -> Result<WorkerReleasePermit, OperationError> {
        let file = file.validate()?;
        Ok(self
            .files
            .record_backing_closed(file.node_id, file.handle, receipt)?)
    }

    /// Removes worker state after required external backing cleanup completed.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for stale state or a missing/mismatched final
    /// close permit. Cleanup remains identity-checked after lease expiry.
    pub(crate) fn finish_release(
        &mut self,
        connection: &mut aos_filesystem_view::MetadataConnection<'_, '_, '_, '_>,
        file: FileHandleRequest,
        permit: Option<WorkerReleasePermit>,
    ) -> Result<(), OperationError> {
        self.validate_connection(connection)?;
        let file = file.validate()?;
        Ok(self
            .files
            .finish_release(connection, file.node_id, file.handle, permit)?)
    }

    /// Records an indeterminate final close and faults the connection.
    ///
    /// # Errors
    ///
    /// Always returns the terminal ambiguity error after exact validation, or a
    /// stale error without consuming a mismatched handle.
    pub(crate) fn record_close_ambiguity(
        &mut self,
        connection: &mut aos_filesystem_view::MetadataConnection<'_, '_, '_, '_>,
        file: FileHandleRequest,
    ) -> Result<(), OperationError> {
        self.validate_connection(connection)?;
        let file = file.validate()?;
        Ok(self
            .files
            .record_close_ambiguity(connection, file.node_id, file.handle)?)
    }

    /// Performs GETXATTR with exact zero-size query and `ERANGE` semantics.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for malformed names, stale inode identities,
    /// absent attributes, insufficient capacity, or bounded worker failure.
    pub fn getxattr<'index>(
        &self,
        connection: &aos_filesystem_view::MetadataConnection<'_, 'index, '_, '_>,
        node_id: u64,
        name: &[u8],
        size: u32,
        budget: RequestBudget,
        control: &impl RequestControl,
    ) -> Result<ExtendedAttributeReply<'index>, OperationError> {
        self.validate_connection(connection)?;
        if node_id == 0 {
            return Err(OperationError::Stale);
        }
        let reply_capacity = usize::try_from(size).map_err(|_| OperationError::InvalidRequest)?;
        let xattrs = self.xattrs.as_ref().ok_or(OperationError::Unsupported)?;
        Ok(xattrs.get(connection, node_id, name, reply_capacity, budget, control)?)
    }

    /// Performs LISTXATTR with exact zero-size query and `ERANGE` semantics.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for stale inode identities, insufficient
    /// capacity, allocation ceilings, cancellation, or authenticated corruption.
    pub fn listxattr<'scratch>(
        &self,
        connection: &aos_filesystem_view::MetadataConnection<'_, '_, '_, '_>,
        node_id: u64,
        size: u32,
        budget: RequestBudget,
        scratch: &'scratch mut ExtendedAttributeScratch,
        control: &impl RequestControl,
    ) -> Result<ExtendedAttributeReply<'scratch>, OperationError> {
        self.validate_connection(connection)?;
        if node_id == 0 {
            return Err(OperationError::Stale);
        }
        let reply_capacity = usize::try_from(size).map_err(|_| OperationError::InvalidRequest)?;
        let xattrs = self.xattrs.as_ref().ok_or(OperationError::Unsupported)?;
        Ok(xattrs.list(
            connection,
            node_id,
            reply_capacity,
            budget,
            scratch,
            control,
        )?)
    }

    /// Returns canonical durable passthrough-registration state.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] if live registration state violates its bounds.
    pub fn registration_snapshot(
        &self,
    ) -> Result<Vec<aos_filesystem_view::DurableRegistrationRecord>, OperationError> {
        Ok(self.files.registration_snapshot()?)
    }

    /// Returns the diagnostic commitment that scopes callback reducer state.
    ///
    /// Every nonempty [`Self::registration_snapshot`] already authenticates this
    /// value. It does not authorize construction of another operation reducer.
    #[must_use]
    pub const fn reducer_commitment(&self) -> [u8; 32] {
        self.files.reducer_commitment()
    }

    fn validate_connection(
        &self,
        connection: &aos_filesystem_view::MetadataConnection<'_, '_, '_, '_>,
    ) -> Result<(), OperationError> {
        if connection.connection_binding() != self.connection_binding
            || connection.callback_instance_brand() != self.worker_brand
        {
            return Err(OperationError::Stale);
        }
        if connection.is_faulted() {
            return Err(OperationError::Integrity);
        }
        Ok(())
    }
}

fn file_errno(error: &FileCallbackError) -> i32 {
    match error {
        FileCallbackError::InvalidOpenFlags => libc::EINVAL,
        FileCallbackError::ReadOnlyFilesystem => libc::EROFS,
        FileCallbackError::HandleLimit => libc::EMFILE,
        FileCallbackError::Stale => libc::ESTALE,
        FileCallbackError::AmbiguousPublication
        | FileCallbackError::DispositionMismatch
        | FileCallbackError::ReplyHandleMismatch => libc::EIO,
        FileCallbackError::Worker(error) => worker_errno(error),
        FileCallbackError::Data(error) => data_errno(error),
    }
}

fn xattr_errno(error: &ExtendedAttributeError) -> i32 {
    match error {
        ExtendedAttributeError::InvalidLimit | ExtendedAttributeError::InvalidName => libc::EINVAL,
        ExtendedAttributeError::UnsupportedNamespace => libc::EOPNOTSUPP,
        ExtendedAttributeError::NotFound => libc::ENODATA,
        ExtendedAttributeError::Range => libc::ERANGE,
        ExtendedAttributeError::ResourceExhausted | ExtendedAttributeError::AllocationRefused => {
            libc::ENOMEM
        }
        ExtendedAttributeError::Worker(error) => worker_errno(error),
    }
}

fn worker_errno(error: &WorkerError) -> i32 {
    match error {
        WorkerError::InvalidArgument => libc::EINVAL,
        WorkerError::Stale => libc::ESTALE,
        WorkerError::NotDirectory => libc::ENOTDIR,
        WorkerError::NotSymlink => libc::EINVAL,
        WorkerError::NotFile => libc::EISDIR,
        WorkerError::ResourceExhausted | WorkerError::AllocationRefused => libc::ENOMEM,
        WorkerError::Interrupted => libc::EINTR,
        WorkerError::TimedOut => libc::ETIMEDOUT,
        WorkerError::ReadOnlyFilesystem => libc::EROFS,
        WorkerError::OperationNotSupported => libc::EOPNOTSUPP,
        WorkerError::IntegrityFailure => libc::EIO,
    }
}

fn data_errno(error: &DataError) -> i32 {
    match error {
        DataError::InvalidLimit | DataError::InvalidRequest => libc::EINVAL,
        DataError::ResourceExhausted | DataError::AllocationRefused => libc::ENOMEM,
        DataError::Cancelled => libc::EINTR,
        DataError::DeadlineExpired => libc::ETIMEDOUT,
        DataError::PassthroughRequired => libc::EOPNOTSUPP,
        DataError::RealizationUnavailable | DataError::IntegrityFailure => libc::EIO,
    }
}
