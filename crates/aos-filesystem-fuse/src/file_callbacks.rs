//! Dormant source-level FUSE OPEN, READ, and RELEASE callback sequencing.
//!
//! This module intentionally is not part of the installed C ABI. It normalizes
//! Linux open flags and defines reply-publication ordering around the
//! backend-neutral worker data plane. A future transport revision must adapt
//! these typed outcomes without manufacturing descriptors or backing IDs.
//! Before executing a returned backing effect or publishing a selector, that
//! adapter must durably persist [`FileCallbackState::registration_snapshot`].

use aos_filesystem_view::{
    BackingDisposition, BackingIdentity, CallbackReducerBrand, DataError, DataPlane,
    DataReadRequest, DataReadResult, DataReadScratch, FileAccessMode, FileOpenRequest,
    MetadataConnection, MonotonicClock, PassthroughRegistrations, PendingFileReply,
    PreparedDataOpen, RegistrationAction, RegistrationOperation, RegistrationPhase,
    ReleaseDisposition, RequestBudget, RequestControl, VerifiedObjectReader, WorkerError,
};
use sha2::{Digest as _, Sha256};

pub(crate) mod broker_receipts;

/// Reports flag normalization, worker, data, or publication failure.
#[derive(Debug, thiserror::Error)]
pub enum FileCallbackError {
    /// Raw open flags request unsupported or mutable semantics.
    #[error("unsupported immutable FUSE OPEN flags")]
    InvalidOpenFlags,
    /// Raw open flags request a write or another filesystem mutation.
    #[error("immutable FUSE OPEN requests a filesystem mutation")]
    ReadOnlyFilesystem,
    /// The callback-state handle ceiling was exhausted.
    #[error("FUSE file callback handle ceiling exhausted")]
    HandleLimit,
    /// A raw handle or inode pair is stale or foreign.
    #[error("stale FUSE file callback identity")]
    Stale,
    /// Reply publication was ambiguous and the whole connection was faulted.
    #[error("ambiguous FUSE OPEN reply publication")]
    AmbiguousPublication,
    /// The reply selected a disposition different from the prepared plan.
    #[error("FUSE OPEN reply disposition differs from prepared data authority")]
    DispositionMismatch,
    /// The transport reported a raw handle different from the prepared reply.
    #[error("FUSE OPEN reply handle differs from prepared worker identity")]
    ReplyHandleMismatch,
    /// Backend-neutral worker validation failed.
    #[error("FUSE file worker failed: {0}")]
    Worker(#[from] WorkerError),
    /// Immutable data-plane validation failed.
    #[error("FUSE immutable data plane failed: {0}")]
    Data(#[from] DataError),
}

/// Describes the reply that a transport may attempt to publish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenReplyPlan {
    /// Publish an ordinary userspace-served handle.
    Fallback {
        /// Pending raw worker handle.
        handle: u64,
    },
    /// Register this backing, then publish its returned selector with the handle.
    Passthrough {
        /// Pending raw worker handle.
        handle: u64,
        /// Exact qualified immutable backing.
        backing: BackingIdentity,
        /// Durable registration operation which owns the selector.
        operation: RegistrationOperation,
        /// Existing coalesced selector, or `None` when `BACKING_OPEN` is required.
        backing_id: Option<u64>,
    },
}

/// Records the exact disposition encoded in a successful transport reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenReplySelection {
    /// The reply selected userspace fallback.
    Fallback,
    /// The reply selected one nonzero broker-created backing selector.
    Passthrough {
        /// Opaque successful broker registration.
        registration: RegisteredBacking,
    },
}

/// Opaque broker-owned evidence of one completed backing registration.
///
/// Only the crate's future Linux broker boundary can construct this token from
/// a completed descriptor-owning operation. Portable callback callers cannot
/// turn a scalar selector into success evidence.
#[must_use = "consume the completed backing-open receipt in callback state"]
pub(crate) struct BackingOpenReceipt {
    authority_binding: [u8; 32],
    worker_brand: u64,
    reducer_identity: [u8; 32],
    callback_request_identity: [u8; 32],
    raw_handle: u64,
    broker_execution: [u8; 32],
    operation: RegistrationOperation,
    backing_id: u64,
    backing: BackingIdentity,
    broker_generation: u64,
    broker_sequence: u64,
    publication_generation: u64,
    currentness_commitment: [u8; 32],
    descriptor_commitment: [u8; 32],
}

/// Opaque successful registration of one verified backing on this connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredBacking {
    worker_brand: u64,
    reducer_commitment: [u8; 32],
    operation: RegistrationOperation,
    backing_id: u64,
    backing: BackingIdentity,
}

impl RegisteredBacking {
    fn from_durable_registration(
        worker_brand: u64,
        reducer_commitment: [u8; 32],
        operation: RegistrationOperation,
        backing_id: u64,
        backing: BackingIdentity,
    ) -> Result<Self, FileCallbackError> {
        if worker_brand == 0 || reducer_commitment == [0; 32] || backing_id == 0 {
            return Err(FileCallbackError::Stale);
        }
        Ok(Self {
            worker_brand,
            reducer_commitment,
            operation,
            backing_id,
            backing,
        })
    }

    /// Returns the durable operation that owns this selector.
    #[must_use]
    pub const fn operation(&self) -> RegistrationOperation {
        self.operation
    }

    /// Returns the connection-local selector recorded by the reducer.
    #[must_use]
    pub const fn backing_id(&self) -> u64 {
        self.backing_id
    }
}

/// Reports whether a synchronous reply became externally visible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenPublication {
    /// The transport proved that this exact handle and selection became visible.
    Published {
        /// Exact raw file handle encoded in the successful reply.
        raw_handle: u64,
        /// Exact fallback or passthrough selection encoded in the reply.
        selection: OpenReplySelection,
    },
    /// The transport proved no reply became visible.
    Rejected,
    /// The transport cannot prove whether the reply became visible.
    Ambiguous,
}

/// Reports the committed result of one unambiguous OPEN callback.
pub(crate) enum OpenCompletion<'index> {
    /// The kernel-visible reply was committed under this raw handle.
    Published {
        /// Active connection-scoped file handle.
        handle: u64,
    },
    /// No reply became visible and the worker reservation was aborted.
    Rejected,
    /// No reply became visible and durable rollback precedes worker abort.
    RejectedCleanupRequired {
        /// Opaque worker cleanup permit retained across journal persistence.
        cleanup: RejectedWorkerCleanup<'index>,
    },
    /// No reply became visible, but the successful backing open must close first.
    RejectedCloseRequired {
        /// Durable registration operation authorizing `BACKING_CLOSE`.
        operation: RegistrationOperation,
        /// Exact selector to pass to `BACKING_CLOSE`.
        backing_id: u64,
        /// Opaque pending cleanup retained until close confirmation.
        cleanup: RejectedOpenCleanup<'index>,
    },
}

/// Reports whether a failed OPEN finish returned or terminally consumed its token.
pub(crate) enum OpenFinishFailure<'index> {
    /// No terminal fault was established, so the caller retains exact ownership.
    OwnershipReturned {
        /// Failure that prevented the requested transition.
        error: FileCallbackError,
        /// Original pending token, still charged in [`FileCallbackState`].
        pending: PendingCallbackOpen<'index>,
    },
    /// The connection is terminally faulted and teardown owns the retained pin.
    Terminal {
        /// Failure that forced terminal connection reconciliation.
        error: FileCallbackError,
    },
}

impl OpenFinishFailure<'_> {
    /// Returns the underlying callback failure.
    #[must_use]
    pub const fn error(&self) -> &FileCallbackError {
        match self {
            Self::OwnershipReturned { error, .. } | Self::Terminal { error } => error,
        }
    }

    /// Reports whether connection teardown owns the consumed token and pin.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal { .. })
    }
}

impl<'index> OpenFinishFailure<'index> {
    /// Separates the error from an ownership-returned token, when present.
    #[must_use]
    pub fn into_parts(self) -> (FileCallbackError, Option<PendingCallbackOpen<'index>>) {
        match self {
            Self::OwnershipReturned { error, pending } => (error, Some(pending)),
            Self::Terminal { error } => (error, None),
        }
    }
}

/// Opaque broker observation that one connection-local backing close completed.
#[must_use = "consume the completed backing-close receipt in callback state"]
pub(crate) struct BackingCloseReceipt {
    authority_binding: [u8; 32],
    worker_brand: u64,
    reducer_identity: [u8; 32],
    callback_request_identity: [u8; 32],
    raw_handle: u64,
    broker_execution: [u8; 32],
    operation: RegistrationOperation,
    backing_id: u64,
    backing: BackingIdentity,
    broker_generation: u64,
    broker_sequence: u64,
    publication_generation: u64,
    currentness_commitment: [u8; 32],
    descriptor_commitment: [u8; 32],
}

/// Retains a rejected pending OPEN until its successful registration is closed.
#[must_use = "confirm or reconcile the backing close before dropping worker state"]
pub(crate) struct RejectedOpenCleanup<'index> {
    worker: PendingFileReply<'index>,
    operation: RegistrationOperation,
    worker_brand: u64,
    reducer_identity: [u8; 32],
    callback_request_identity: [u8; 32],
    descriptor_commitment: [u8; 32],
}

/// Proves registration state was updated after a rejected-OPEN close.
#[must_use = "persist registration state before aborting the worker reservation"]
pub struct RejectedWorkerCleanup<'index> {
    worker: PendingFileReply<'index>,
    worker_brand: u64,
    reducer_commitment: [u8; 32],
}

/// Proves registration state was updated after an active-handle close.
#[must_use = "persist registration state before releasing the worker handle"]
pub(crate) struct WorkerReleasePermit {
    worker_brand: u64,
    reducer_commitment: [u8; 32],
    node_id: u64,
    raw_handle: u64,
}

/// Describes the only next effect allowed for a pending RELEASE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleasePlan {
    /// No backing close is required before worker cleanup.
    ReleaseWorker,
    /// The final registration reference must close before worker cleanup.
    CloseBacking {
        /// Durable registration operation authorizing the close.
        operation: RegistrationOperation,
        /// Exact qualified immutable backing whose descriptor is closing.
        backing: BackingIdentity,
        /// Exact connection-local selector to close.
        backing_id: u64,
        /// Diagnostic commitment to the worker-minted callback-reducer brand.
        reducer_commitment: [u8; 32],
        /// Exact active or rejected callback request authorizing this close.
        callback_request_identity: [u8; 32],
        /// Exact pending or active worker handle bound to the descriptor.
        raw_handle: u64,
        /// Exact descriptor identity retained from authenticated OPEN.
        descriptor_commitment: [u8; 32],
    },
}

/// Holds a worker reservation and resolved data disposition before reply publication.
#[must_use = "finish the OPEN publication transition"]
pub(crate) struct PendingCallbackOpen<'index> {
    worker: PendingFileReply<'index>,
    data: PreparedDataOpen,
    worker_brand: u64,
    reducer_identity: [u8; 32],
    callback_request_identity: [u8; 32],
    registration: Option<RegistrationOperation>,
    backing_id: Option<u64>,
    descriptor_commitment: Option<[u8; 32]>,
}

impl PendingCallbackOpen<'_> {
    /// Returns the only reply plan authorized for this pending open.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError::Stale`] if a passthrough disposition lacks
    /// the durable registration operation created with it.
    pub(crate) fn reply_plan(&self) -> Result<OpenReplyPlan, FileCallbackError> {
        match self.data.disposition() {
            BackingDisposition::VerifiedFallback => Ok(OpenReplyPlan::Fallback {
                handle: self.worker.raw_handle(),
            }),
            BackingDisposition::Passthrough(backing) => {
                let operation = self.registration.ok_or(FileCallbackError::Stale)?;
                Ok(OpenReplyPlan::Passthrough {
                    handle: self.worker.raw_handle(),
                    backing,
                    operation,
                    backing_id: self.backing_id,
                })
            }
        }
    }
}

struct ActiveCallbackOpen {
    node_id: u64,
    raw_handle: u64,
    data: PreparedDataOpen,
    reducer_commitment: [u8; 32],
    callback_request_identity: [u8; 32],
    registration: Option<RegistrationOperation>,
    descriptor_commitment: Option<[u8; 32]>,
    release_pending: bool,
    release_requires_close: bool,
    release_close_recorded: bool,
}

/// Owns bounded adapter state for active data dispositions.
pub(crate) struct FileCallbackState {
    active: Vec<ActiveCallbackOpen>,
    pending_handles: usize,
    maximum_handles: usize,
    authority_binding: [u8; 32],
    worker_brand: u64,
    reducer_identity: [u8; 32],
    registrations: PassthroughRegistrations,
}

impl FileCallbackState {
    /// Preallocates the complete adapter handle ceiling before dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError::HandleLimit`] for zero capacity or an
    /// allocation refusal. No reply may be attempted before this succeeds.
    pub fn for_connection(
        connection: &MetadataConnection<'_, '_, '_, '_>,
        registrations: PassthroughRegistrations,
        reducer_brand: CallbackReducerBrand,
        maximum_handles: usize,
    ) -> Result<Self, FileCallbackError> {
        if maximum_handles == 0 {
            return Err(FileCallbackError::HandleLimit);
        }
        let mut active = Vec::new();
        active
            .try_reserve_exact(maximum_handles)
            .map_err(|_| FileCallbackError::HandleLimit)?;
        if active.capacity() > maximum_handles {
            return Err(FileCallbackError::HandleLimit);
        }
        let authority_binding = connection.connection_binding();
        let worker_brand = connection.callback_instance_brand();
        if authority_binding == [0; 32] || worker_brand == 0 {
            return Err(FileCallbackError::Stale);
        }
        let reducer_binding = reducer_brand.bind_registrations(connection, registrations)?;
        let reducer_identity = reducer_binding.commitment();
        let registrations = reducer_binding.into_registrations();
        Ok(Self {
            active,
            pending_handles: 0,
            maximum_handles,
            authority_binding,
            worker_brand,
            reducer_identity,
            registrations,
        })
    }

    /// Normalizes flags and prepares worker/data authority before a reply.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] for unsupported flags, exhausted adapter
    /// capacity, worker admission failure, or unavailable data realization.
    pub(crate) fn prepare_open<'index>(
        &mut self,
        connection: &mut MetadataConnection<'_, 'index, '_, '_>,
        data_plane: &DataPlane,
        node_id: u64,
        raw_flags: i32,
        backing: Option<BackingIdentity>,
        budget: RequestBudget,
        clock: &impl MonotonicClock,
        control: &impl RequestControl,
    ) -> Result<PendingCallbackOpen<'index>, FileCallbackError> {
        self.validate_connection(connection)?;
        let Some(charged_handles) = self.active.len().checked_add(self.pending_handles) else {
            return Err(FileCallbackError::HandleLimit);
        };
        if charged_handles >= self.maximum_handles {
            return Err(FileCallbackError::HandleLimit);
        }
        let request = normalize_open_flags(raw_flags)?;
        let mut worker = connection.prepare_open(node_id, request, budget, control)?;
        let callback_request_identity = derive_callback_request_identity(
            self.reducer_identity,
            self.worker_brand,
            node_id,
            worker.raw_handle(),
        );
        if callback_request_identity == [0; 32] {
            connection.abort_open(&mut worker)?;
            return Err(FileCallbackError::Stale);
        }
        let data = match data_plane.prepare_open(&worker, backing, clock.now_ns()) {
            Ok(data) => data,
            Err(error) => {
                connection.abort_open(&mut worker)?;
                return Err(error.into());
            }
        };
        let (registration, backing_id, descriptor_commitment) = match data.disposition() {
            BackingDisposition::VerifiedFallback => (None, None, None),
            BackingDisposition::Passthrough(backing) => {
                let action = match self.registrations.begin_open(backing, clock.now_ns()) {
                    Ok(action) => action,
                    Err(error) => {
                        connection.abort_open(&mut worker)?;
                        return Err(error.into());
                    }
                };
                match action {
                    RegistrationAction::OpenBacking { operation } => (Some(operation), None, None),
                    RegistrationAction::PublishCoalesced { operation } => {
                        let backing_id = self.registrations.backing_id(operation)?;
                        let descriptor_commitment =
                            self.registrations.descriptor_commitment(operation)?;
                        (
                            Some(operation),
                            Some(backing_id),
                            Some(descriptor_commitment),
                        )
                    }
                    _ => {
                        connection.abort_open(&mut worker)?;
                        return Err(FileCallbackError::Stale);
                    }
                }
            }
        };
        self.pending_handles = self
            .pending_handles
            .checked_add(1)
            .ok_or(FileCallbackError::HandleLimit)?;
        Ok(PendingCallbackOpen {
            worker,
            data,
            worker_brand: self.worker_brand,
            reducer_identity: self.reducer_identity,
            callback_request_identity,
            registration,
            backing_id,
            descriptor_commitment,
        })
    }

    /// Records a successful `BACKING_OPEN` before its selector can be published.
    ///
    /// The caller must durably persist [`Self::registration_snapshot`] before
    /// encoding the returned registration into a FUSE reply.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] unless `pending` owns the exact pending
    /// registration named by nonforgeable broker completion evidence.
    pub(crate) fn record_backing_opened(
        &mut self,
        pending: &mut PendingCallbackOpen<'_>,
        receipt: BackingOpenReceipt,
    ) -> Result<RegisteredBacking, FileCallbackError> {
        self.validate_pending(pending)?;
        let operation = pending.registration.ok_or(FileCallbackError::Stale)?;
        let backing = match pending.data.disposition() {
            BackingDisposition::Passthrough(backing) => backing,
            BackingDisposition::VerifiedFallback => return Err(FileCallbackError::Stale),
        };
        if pending.backing_id.is_some()
            || self.registrations.phase(operation)? != RegistrationPhase::Pending
            || receipt.authority_binding != self.authority_binding
            || receipt.worker_brand != self.worker_brand
            || receipt.reducer_identity != self.reducer_identity
            || receipt.callback_request_identity != pending.callback_request_identity
            || receipt.raw_handle != pending.worker.raw_handle()
            || receipt.broker_execution == [0; 32]
            || receipt.operation != operation
            || receipt.backing != backing
            || receipt.backing_id == 0
            || receipt.broker_generation == 0
            || receipt.broker_sequence == 0
            || receipt.publication_generation == 0
            || receipt.currentness_commitment == [0; 32]
            || receipt.descriptor_commitment == [0; 32]
        {
            return Err(FileCallbackError::Stale);
        }
        self.registrations.record_opened(
            operation,
            receipt.backing_id,
            receipt.descriptor_commitment,
        )?;
        pending.backing_id = Some(receipt.backing_id);
        pending.descriptor_commitment = Some(receipt.descriptor_commitment);
        self.registered_backing(pending)
    }

    /// Returns the reducer-authenticated selector for an OPEN reply.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] unless the pending callback and durable
    /// active registration agree on connection, operation, backing, and selector.
    pub fn registered_backing(
        &self,
        pending: &PendingCallbackOpen<'_>,
    ) -> Result<RegisteredBacking, FileCallbackError> {
        self.validate_pending(pending)?;
        let operation = pending.registration.ok_or(FileCallbackError::Stale)?;
        let backing_id = pending.backing_id.ok_or(FileCallbackError::Stale)?;
        let backing = match pending.data.disposition() {
            BackingDisposition::Passthrough(backing) => backing,
            BackingDisposition::VerifiedFallback => return Err(FileCallbackError::Stale),
        };
        if self.registrations.phase(operation)? != RegistrationPhase::Active
            || self.registrations.backing(operation)? != backing
            || self.registrations.backing_id(operation)? != backing_id
            || self.registrations.descriptor_commitment(operation)?
                != pending
                    .descriptor_commitment
                    .ok_or(FileCallbackError::Stale)?
        {
            return Err(FileCallbackError::Stale);
        }
        RegisteredBacking::from_durable_registration(
            self.worker_brand,
            self.reducer_identity,
            operation,
            backing_id,
            backing,
        )
    }

    /// Completes a synchronous OPEN reply transition exactly once.
    ///
    /// Published replies activate and retain their disposition. Definite
    /// rejection first returns a cleanup token so registration rollback can be
    /// persisted before the pending worker reservation is aborted. Ambiguity
    /// faults the connection and retains its inode pin until teardown.
    ///
    /// # Errors
    ///
    /// Returns [`OpenFinishFailure::OwnershipReturned`] when no terminal fault
    /// was established, preserving the token and its pending charge. Returns
    /// [`OpenFinishFailure::Terminal`] only after the charge is consumed exactly
    /// once and connection teardown owns the retained inode pin. A published
    /// mismatch is terminal because kernel-visible authority cannot be guessed.
    pub(crate) fn finish_open<'index>(
        &mut self,
        connection: &mut MetadataConnection<'_, 'index, '_, '_>,
        mut pending: PendingCallbackOpen<'index>,
        publication: OpenPublication,
    ) -> Result<OpenCompletion<'index>, OpenFinishFailure<'index>> {
        if let Err(error) = self.validate_connection(connection) {
            return Err(OpenFinishFailure::OwnershipReturned { error, pending });
        }
        if let Err(error) = self.validate_pending(&pending) {
            return Err(OpenFinishFailure::OwnershipReturned { error, pending });
        }
        if connection.is_faulted() {
            return Err(
                self.consume_terminal_pending(pending, FileCallbackError::AmbiguousPublication)
            );
        }

        match publication {
            OpenPublication::Rejected => self.finish_rejected_open(connection, pending),
            OpenPublication::Ambiguous => Err(self.fault_and_consume_pending(
                connection,
                pending,
                FileCallbackError::AmbiguousPublication,
            )),
            OpenPublication::Published {
                raw_handle,
                selection,
            } => {
                if raw_handle != pending.worker.raw_handle() {
                    return Err(self.fault_and_consume_pending(
                        connection,
                        pending,
                        FileCallbackError::ReplyHandleMismatch,
                    ));
                }
                match self.selection_matches(&pending, selection) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(self.fault_and_consume_pending(
                            connection,
                            pending,
                            FileCallbackError::DispositionMismatch,
                        ));
                    }
                    Err(error) => {
                        return Err(self.fault_and_consume_pending(connection, pending, error));
                    }
                }
                let open = match connection.commit_open_after_reply(&mut pending.worker) {
                    Ok(open) => open,
                    Err(error) => {
                        // The worker transition already terminally faulted the
                        // connection. Only adapter accounting and durable
                        // registration ambiguity remain; a second fault call
                        // would be rejected and could strand this charge.
                        return Err(self.fault_and_consume_pending(
                            connection,
                            pending,
                            error.into(),
                        ));
                    }
                };
                let raw_handle = open.raw_handle();
                self.consume_pending_charge();
                self.active.push(ActiveCallbackOpen {
                    node_id: open.node_id(),
                    raw_handle,
                    data: pending.data,
                    reducer_commitment: pending.reducer_identity,
                    callback_request_identity: pending.callback_request_identity,
                    registration: pending.registration,
                    descriptor_commitment: pending.descriptor_commitment,
                    release_pending: false,
                    release_requires_close: false,
                    release_close_recorded: false,
                });
                Ok(OpenCompletion::Published { handle: raw_handle })
            }
        }
    }

    /// Records close confirmation for a rejected OPEN.
    ///
    /// The caller must durably persist [`Self::registration_snapshot`] before
    /// passing the returned permit to [`Self::finish_rejected_open_cleanup`].
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] unless the receipt matches the exact
    /// connection, operation, and selector retained by `cleanup`.
    pub(crate) fn record_rejected_backing_closed<'index>(
        &mut self,
        cleanup: RejectedOpenCleanup<'index>,
        receipt: BackingCloseReceipt,
    ) -> Result<RejectedWorkerCleanup<'index>, FileCallbackError> {
        if cleanup.worker_brand != self.worker_brand
            || cleanup.reducer_identity != self.reducer_identity
            || receipt.authority_binding != self.authority_binding
            || receipt.worker_brand != self.worker_brand
            || receipt.reducer_identity != cleanup.reducer_identity
            || receipt.callback_request_identity != cleanup.callback_request_identity
            || receipt.raw_handle != cleanup.worker.raw_handle()
            || receipt.broker_execution == [0; 32]
            || receipt.operation != cleanup.operation
            || self.registrations.backing(cleanup.operation)? != receipt.backing
            || receipt.broker_generation == 0
            || receipt.broker_sequence == 0
            || receipt.publication_generation == 0
            || receipt.currentness_commitment == [0; 32]
            || receipt.descriptor_commitment != cleanup.descriptor_commitment
            || receipt.descriptor_commitment
                != self
                    .registrations
                    .descriptor_commitment(cleanup.operation)?
            || receipt.backing_id != self.registrations.closing_backing_id(cleanup.operation)?
        {
            return Err(FileCallbackError::Stale);
        }
        self.registrations
            .record_rejected_open_closed(cleanup.operation)?;
        Ok(RejectedWorkerCleanup {
            worker: cleanup.worker,
            worker_brand: self.worker_brand,
            reducer_commitment: self.reducer_identity,
        })
    }

    /// Aborts rejected worker state after the registration update is durable.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] for a foreign permit or stale worker state.
    pub(crate) fn finish_rejected_open_cleanup<'index>(
        &mut self,
        connection: &mut MetadataConnection<'_, 'index, '_, '_>,
        mut cleanup: RejectedWorkerCleanup<'index>,
    ) -> Result<OpenCompletion<'index>, FileCallbackError> {
        self.validate_connection(connection)?;
        if cleanup.worker_brand != self.worker_brand
            || cleanup.reducer_commitment != self.reducer_identity
        {
            return Err(FileCallbackError::Stale);
        }
        connection.abort_open(&mut cleanup.worker)?;
        Ok(OpenCompletion::Rejected)
    }

    /// Reissues the exact close plan retained for a rejected OPEN.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError::Stale`] unless `cleanup` belongs to this
    /// connection and its durable registration remains `Closing`.
    pub(crate) fn retry_rejected_open_close(
        &self,
        cleanup: &RejectedOpenCleanup<'_>,
    ) -> Result<ReleasePlan, FileCallbackError> {
        if cleanup.worker_brand != self.worker_brand
            || cleanup.reducer_identity != self.reducer_identity
            || cleanup.callback_request_identity == [0; 32]
            || cleanup.descriptor_commitment == [0; 32]
            || cleanup.descriptor_commitment
                != self
                    .registrations
                    .descriptor_commitment(cleanup.operation)?
            || self.registrations.retry_close(cleanup.operation)?
                != (RegistrationAction::CloseBeforeRelease {
                    operation: cleanup.operation,
                })
        {
            return Err(FileCallbackError::Stale);
        }
        Ok(ReleasePlan::CloseBacking {
            operation: cleanup.operation,
            backing: self.registrations.backing(cleanup.operation)?,
            backing_id: self.registrations.closing_backing_id(cleanup.operation)?,
            reducer_commitment: cleanup.reducer_identity,
            callback_request_identity: cleanup.callback_request_identity,
            raw_handle: cleanup.worker.raw_handle(),
            descriptor_commitment: cleanup.descriptor_commitment,
        })
    }

    /// Records an indeterminate rejected-OPEN close and faults the connection.
    ///
    /// The pending worker open remains pinned for connection-generation teardown.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] for stale state or after recording the
    /// terminal ambiguity.
    pub(crate) fn record_rejected_close_ambiguity<'index>(
        &mut self,
        connection: &mut MetadataConnection<'_, 'index, '_, '_>,
        cleanup: RejectedOpenCleanup<'index>,
    ) -> Result<(), FileCallbackError> {
        self.validate_connection(connection)?;
        if cleanup.worker_brand != self.worker_brand
            || cleanup.reducer_identity != self.reducer_identity
            || cleanup.callback_request_identity == [0; 32]
            || cleanup.descriptor_commitment == [0; 32]
            || cleanup.descriptor_commitment
                != self
                    .registrations
                    .descriptor_commitment(cleanup.operation)?
        {
            return Err(FileCallbackError::Stale);
        }
        self.registrations.record_ambiguous(cleanup.operation)?;
        connection.fault_pending_open_reply_ambiguity(&cleanup.worker)?;
        Err(FileCallbackError::AmbiguousPublication)
    }

    /// Executes one bounded fallback READ for an active inode/handle pair.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] for a stale pair, passthrough-owned read,
    /// worker error, cancellation/deadline, retry exhaustion, or integrity error.
    #[allow(clippy::too_many_arguments)]
    pub fn read<'scratch>(
        &self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        data_plane: &DataPlane,
        node_id: u64,
        raw_handle: u64,
        request: DataReadRequest,
        scratch: &'scratch mut DataReadScratch,
        provider: &mut impl VerifiedObjectReader,
        clock: &impl MonotonicClock,
        control: &impl RequestControl,
    ) -> Result<DataReadResult<'scratch>, FileCallbackError> {
        self.validate_connection(connection)?;
        let active = self.active(node_id, raw_handle)?;
        if active.release_pending {
            return Err(FileCallbackError::Stale);
        }
        let open = connection.resolve_open_for_node(node_id, raw_handle, control)?;
        Ok(data_plane.read(
            &open,
            &active.data,
            request,
            scratch,
            provider,
            clock,
            control,
        )?)
    }

    /// Prepares RELEASE without dropping worker state before backing close.
    ///
    /// The returned plan is derived from the durable registration reducer. A
    /// selector is exposed only for the final reference after the reducer enters
    /// `Closing`; a coalesced nonfinal release never closes the shared selector.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] for a stale pair or data/open mismatch.
    /// Errors preserve adapter state for teardown.
    pub(crate) fn prepare_release(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        data_plane: &DataPlane,
        node_id: u64,
        raw_handle: u64,
    ) -> Result<(ReleaseDisposition, ReleasePlan), FileCallbackError> {
        self.validate_connection(connection)?;
        let position = self.active_position(node_id, raw_handle)?;
        if self.active[position].release_pending {
            return Err(FileCallbackError::Stale);
        }
        let open = connection.resolve_open_for_release(node_id, raw_handle)?;
        let cleanup = data_plane.prepare_release(&open, &self.active[position].data)?;
        let registration = self.active[position].registration;
        if let Some(operation) = registration {
            let descriptor_commitment = self.active[position]
                .descriptor_commitment
                .ok_or(FileCallbackError::Stale)?;
            let BackingDisposition::Passthrough(backing) = self.active[position].data.disposition()
            else {
                return Err(FileCallbackError::Stale);
            };
            if backing != self.registrations.backing(operation)?
                || descriptor_commitment != self.registrations.descriptor_commitment(operation)?
            {
                return Err(FileCallbackError::Stale);
            }
        }
        let plan = match registration {
            None => ReleasePlan::ReleaseWorker,
            Some(operation) => match self.registrations.begin_release(operation)? {
                RegistrationAction::ReleaseWorkerOpen { .. } => ReleasePlan::ReleaseWorker,
                RegistrationAction::CloseBeforeRelease { .. } => {
                    let descriptor_commitment = self.active[position]
                        .descriptor_commitment
                        .ok_or(FileCallbackError::Stale)?;
                    ReleasePlan::CloseBacking {
                        operation,
                        backing: self.registrations.backing(operation)?,
                        backing_id: self.registrations.closing_backing_id(operation)?,
                        reducer_commitment: self.reducer_identity,
                        callback_request_identity: self.active[position].callback_request_identity,
                        raw_handle,
                        descriptor_commitment,
                    }
                }
                _ => return Err(FileCallbackError::Stale),
            },
        };
        self.active[position].release_pending = true;
        self.active[position].release_requires_close =
            matches!(plan, ReleasePlan::CloseBacking { .. });
        self.active[position].release_close_recorded = false;
        let cleanup = match (cleanup, plan) {
            (ReleaseDisposition::CloseBacking(_), ReleasePlan::ReleaseWorker) => {
                ReleaseDisposition::SharedBackingRetained
            }
            (cleanup, _) => cleanup,
        };
        Ok((cleanup, plan))
    }

    /// Repeats the exact close-before-release plan after a definite retryable failure.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError::Stale`] unless the connection, inode,
    /// handle, and pending-release phase all match.
    pub(crate) fn retry_release(
        &self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        node_id: u64,
        raw_handle: u64,
    ) -> Result<ReleasePlan, FileCallbackError> {
        self.validate_connection(connection)?;
        let active = self.active(node_id, raw_handle)?;
        connection.resolve_open_for_release(node_id, raw_handle)?;
        if !active.release_pending {
            return Err(FileCallbackError::Stale);
        }
        let Some(operation) = active.registration else {
            return Ok(ReleasePlan::ReleaseWorker);
        };
        if !active.release_requires_close {
            return Ok(ReleasePlan::ReleaseWorker);
        }
        if active.release_close_recorded {
            return Ok(ReleasePlan::ReleaseWorker);
        }
        if self.registrations.retry_close(operation)?
            != (RegistrationAction::CloseBeforeRelease { operation })
        {
            return Err(FileCallbackError::Stale);
        }
        let descriptor_commitment = active
            .descriptor_commitment
            .ok_or(FileCallbackError::Stale)?;
        if descriptor_commitment != self.registrations.descriptor_commitment(operation)? {
            return Err(FileCallbackError::Stale);
        }
        Ok(ReleasePlan::CloseBacking {
            operation,
            backing: self.registrations.backing(operation)?,
            backing_id: self.registrations.closing_backing_id(operation)?,
            reducer_commitment: self.reducer_identity,
            callback_request_identity: active.callback_request_identity,
            raw_handle,
            descriptor_commitment,
        })
    }

    /// Records final backing-close completion without releasing worker state.
    ///
    /// The caller must durably persist [`Self::registration_snapshot`] before
    /// passing the returned permit to [`Self::finish_release`].
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] for foreign, stale, nonfinal, or mismatched
    /// close evidence.
    pub(crate) fn record_backing_closed(
        &mut self,
        node_id: u64,
        raw_handle: u64,
        receipt: BackingCloseReceipt,
    ) -> Result<WorkerReleasePermit, FileCallbackError> {
        let position = self.active_position(node_id, raw_handle)?;
        let active = &self.active[position];
        let operation = active.registration.ok_or(FileCallbackError::Stale)?;
        if !active.release_pending
            || !active.release_requires_close
            || active.release_close_recorded
            || receipt.authority_binding != self.authority_binding
            || receipt.worker_brand != self.worker_brand
            || receipt.reducer_identity != self.reducer_identity
            || receipt.callback_request_identity != active.callback_request_identity
            || receipt.raw_handle != raw_handle
            || receipt.broker_execution == [0; 32]
            || receipt.operation != operation
            || self.registrations.backing(operation)? != receipt.backing
            || receipt.broker_generation == 0
            || receipt.broker_sequence == 0
            || receipt.publication_generation == 0
            || receipt.currentness_commitment == [0; 32]
            || active.descriptor_commitment != Some(receipt.descriptor_commitment)
            || receipt.descriptor_commitment
                != self.registrations.descriptor_commitment(operation)?
            || receipt.backing_id != self.registrations.closing_backing_id(operation)?
        {
            return Err(FileCallbackError::Stale);
        }
        self.registrations.record_closed(operation)?;
        self.active[position].release_close_recorded = true;
        Ok(WorkerReleasePermit {
            worker_brand: self.worker_brand,
            reducer_commitment: self.reducer_identity,
            node_id,
            raw_handle,
        })
    }

    /// Releases worker state after fallback/nonfinal release or a durable close.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] for foreign or stale state, absent or
    /// mismatched release permission, or worker release failure. Lease expiry does
    /// not block identity-checked cleanup.
    pub(crate) fn finish_release(
        &mut self,
        connection: &mut MetadataConnection<'_, '_, '_, '_>,
        node_id: u64,
        raw_handle: u64,
        close_permit: Option<WorkerReleasePermit>,
    ) -> Result<(), FileCallbackError> {
        self.validate_connection(connection)?;
        let position = self.active_position(node_id, raw_handle)?;
        let active = &self.active[position];
        if !active.release_pending {
            return Err(FileCallbackError::Stale);
        }
        match (
            active.release_requires_close,
            active.release_close_recorded,
            close_permit,
        ) {
            (false, false, None) => {}
            (true, true, Some(permit))
                if permit.worker_brand == self.worker_brand
                    && permit.reducer_commitment == self.reducer_identity
                    && permit.node_id == node_id
                    && permit.raw_handle == raw_handle => {}
            _ => return Err(FileCallbackError::Stale),
        }
        connection.release_open_for_cleanup(node_id, raw_handle)?;
        self.active.swap_remove(position);
        Ok(())
    }

    /// Records an indeterminate final close and terminally faults the connection.
    ///
    /// The active worker handle and ambiguous registration remain retained for
    /// generation-scoped teardown and journal reconciliation.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] for stale state or after marking the
    /// connection terminally faulted due to the ambiguous external effect.
    pub(crate) fn record_close_ambiguity(
        &mut self,
        connection: &mut MetadataConnection<'_, '_, '_, '_>,
        node_id: u64,
        raw_handle: u64,
    ) -> Result<(), FileCallbackError> {
        self.validate_connection(connection)?;
        let active = self.active(node_id, raw_handle)?;
        if !active.release_pending
            || !active.release_requires_close
            || active.release_close_recorded
        {
            return Err(FileCallbackError::Stale);
        }
        let operation = active.registration.ok_or(FileCallbackError::Stale)?;
        if active.descriptor_commitment
            != Some(self.registrations.descriptor_commitment(operation)?)
        {
            return Err(FileCallbackError::Stale);
        }
        self.registrations.record_ambiguous(operation)?;
        let open = connection.resolve_open_for_release(node_id, raw_handle)?;
        connection.fault_active_open_reply_ambiguity(&open)?;
        Err(FileCallbackError::AmbiguousPublication)
    }

    /// Copies canonical registration state for the broker's durable journal.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError::Data`] if exact bounded allocation or live
    /// reducer validation fails.
    pub fn registration_snapshot(
        &self,
    ) -> Result<Vec<aos_filesystem_view::DurableRegistrationRecord>, FileCallbackError> {
        Ok(self.registrations.snapshot()?)
    }

    /// Returns the diagnostic commitment that scopes this callback reducer.
    ///
    /// Every nonempty [`Self::registration_snapshot`] already authenticates this
    /// value. It does not authorize construction of another reducer.
    #[must_use]
    pub const fn reducer_commitment(&self) -> [u8; 32] {
        self.reducer_identity
    }

    /// Returns the number of active adapter dispositions.
    #[must_use]
    pub fn active_handles(&self) -> usize {
        self.active.len()
    }

    /// Returns pending plus active adapter dispositions charged to the ceiling.
    #[must_use]
    pub fn charged_handles(&self) -> usize {
        self.active.len() + self.pending_handles
    }

    fn active(
        &self,
        node_id: u64,
        raw_handle: u64,
    ) -> Result<&ActiveCallbackOpen, FileCallbackError> {
        self.active
            .iter()
            .find(|open| {
                open.node_id == node_id
                    && open.raw_handle == raw_handle
                    && open.reducer_commitment == self.reducer_identity
            })
            .ok_or(FileCallbackError::Stale)
    }

    fn active_position(&self, node_id: u64, raw_handle: u64) -> Result<usize, FileCallbackError> {
        self.active
            .iter()
            .position(|open| {
                open.node_id == node_id
                    && open.raw_handle == raw_handle
                    && open.reducer_commitment == self.reducer_identity
            })
            .ok_or(FileCallbackError::Stale)
    }

    fn validate_connection(
        &self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
    ) -> Result<(), FileCallbackError> {
        (connection.connection_binding() == self.authority_binding
            && connection.callback_instance_brand() == self.worker_brand)
            .then_some(())
            .ok_or(FileCallbackError::Stale)
    }

    fn validate_pending(&self, pending: &PendingCallbackOpen<'_>) -> Result<(), FileCallbackError> {
        if pending.worker_brand != self.worker_brand
            || pending.reducer_identity != self.reducer_identity
            || pending.callback_request_identity == [0; 32]
            || self.pending_handles == 0
        {
            return Err(FileCallbackError::Stale);
        }
        Ok(())
    }

    fn selection_matches(
        &self,
        pending: &PendingCallbackOpen<'_>,
        selection: OpenReplySelection,
    ) -> Result<bool, FileCallbackError> {
        Ok(match (pending.data.disposition(), selection) {
            (BackingDisposition::VerifiedFallback, OpenReplySelection::Fallback) => {
                pending.registration.is_none() && pending.backing_id.is_none()
            }
            (
                BackingDisposition::Passthrough(expected),
                OpenReplySelection::Passthrough { registration },
            ) => {
                let Some(operation) = pending.registration else {
                    return Ok(false);
                };
                registration.worker_brand == self.worker_brand
                    && registration.reducer_commitment == self.reducer_identity
                    && registration.operation == operation
                    && registration.backing == expected
                    && pending.backing_id == Some(registration.backing_id)
                    && pending.descriptor_commitment
                        == Some(self.registrations.descriptor_commitment(operation)?)
                    && self.registrations.phase(operation)? == RegistrationPhase::Active
                    && self.registrations.backing(operation)? == expected
                    && self.registrations.backing_id(operation)? == registration.backing_id
            }
            _ => false,
        })
    }

    fn mark_registration_ambiguous(
        &mut self,
        pending: &PendingCallbackOpen<'_>,
    ) -> Result<(), FileCallbackError> {
        if let Some(operation) = pending.registration {
            self.registrations.record_ambiguous(operation)?;
        }
        Ok(())
    }

    fn finish_rejected_open<'index>(
        &mut self,
        connection: &mut MetadataConnection<'_, 'index, '_, '_>,
        pending: PendingCallbackOpen<'index>,
    ) -> Result<OpenCompletion<'index>, OpenFinishFailure<'index>> {
        let Some(operation) = pending.registration else {
            self.consume_pending_charge();
            return Ok(OpenCompletion::RejectedCleanupRequired {
                cleanup: RejectedWorkerCleanup {
                    worker: pending.worker,
                    worker_brand: self.worker_brand,
                    reducer_commitment: self.reducer_identity,
                },
            });
        };
        let phase = match self.registrations.phase(operation) {
            Ok(phase) => phase,
            Err(error) => {
                return Err(OpenFinishFailure::OwnershipReturned {
                    error: error.into(),
                    pending,
                });
            }
        };
        match phase {
            RegistrationPhase::Pending => {
                if let Err(error) = self.registrations.record_open_failed(operation) {
                    return Err(OpenFinishFailure::OwnershipReturned {
                        error: error.into(),
                        pending,
                    });
                }
                self.consume_pending_charge();
                Ok(OpenCompletion::RejectedCleanupRequired {
                    cleanup: RejectedWorkerCleanup {
                        worker: pending.worker,
                        worker_brand: self.worker_brand,
                        reducer_commitment: self.reducer_identity,
                    },
                })
            }
            RegistrationPhase::Active => {
                let descriptor_commitment = match pending.descriptor_commitment {
                    Some(commitment) => commitment,
                    None => {
                        return Err(OpenFinishFailure::OwnershipReturned {
                            error: FileCallbackError::Stale,
                            pending,
                        });
                    }
                };
                let backing_id = match self.registrations.backing_id(operation) {
                    Ok(backing_id) => backing_id,
                    Err(error) => {
                        return Err(OpenFinishFailure::OwnershipReturned {
                            error: error.into(),
                            pending,
                        });
                    }
                };
                let action = match self.registrations.begin_release(operation) {
                    Ok(action) => action,
                    Err(error) => {
                        return Err(OpenFinishFailure::OwnershipReturned {
                            error: error.into(),
                            pending,
                        });
                    }
                };
                match action {
                    RegistrationAction::ReleaseWorkerOpen { .. } => {
                        self.consume_pending_charge();
                        Ok(OpenCompletion::RejectedCleanupRequired {
                            cleanup: RejectedWorkerCleanup {
                                worker: pending.worker,
                                worker_brand: self.worker_brand,
                                reducer_commitment: self.reducer_identity,
                            },
                        })
                    }
                    RegistrationAction::CloseBeforeRelease { .. } => {
                        self.consume_pending_charge();
                        Ok(OpenCompletion::RejectedCloseRequired {
                            operation,
                            backing_id,
                            cleanup: RejectedOpenCleanup {
                                worker: pending.worker,
                                operation,
                                worker_brand: self.worker_brand,
                                reducer_identity: self.reducer_identity,
                                callback_request_identity: pending.callback_request_identity,
                                descriptor_commitment,
                            },
                        })
                    }
                    _ => Err(self.fault_and_consume_pending(
                        connection,
                        pending,
                        FileCallbackError::Stale,
                    )),
                }
            }
            RegistrationPhase::Closing | RegistrationPhase::Ambiguous => Err(self
                .fault_and_consume_pending(
                    connection,
                    pending,
                    FileCallbackError::AmbiguousPublication,
                )),
        }
    }

    fn fault_and_consume_pending<'index>(
        &mut self,
        connection: &mut MetadataConnection<'_, 'index, '_, '_>,
        pending: PendingCallbackOpen<'index>,
        error: FileCallbackError,
    ) -> OpenFinishFailure<'index> {
        if !connection.is_faulted()
            && let Err(fault_error) = connection.fault_pending_open_reply_ambiguity(&pending.worker)
        {
            return OpenFinishFailure::OwnershipReturned {
                error: fault_error.into(),
                pending,
            };
        }
        self.consume_terminal_pending(pending, error)
    }

    fn consume_terminal_pending<'index>(
        &mut self,
        pending: PendingCallbackOpen<'index>,
        error: FileCallbackError,
    ) -> OpenFinishFailure<'index> {
        self.consume_pending_charge();
        let error = match self.mark_registration_ambiguous(&pending) {
            Ok(()) => error,
            Err(registration_error) => registration_error,
        };
        OpenFinishFailure::Terminal { error }
    }

    fn consume_pending_charge(&mut self) {
        // Every caller has already passed `validate_pending`, so this decrement
        // cannot underflow and is the single consumption point for that token.
        self.pending_handles -= 1;
    }
}

fn derive_callback_request_identity(
    reducer_identity: [u8; 32],
    worker_brand: u64,
    node_id: u64,
    raw_handle: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos-filesystem-callback-request-v1\0");
    hasher.update(reducer_identity);
    hasher.update(worker_brand.to_be_bytes());
    hasher.update(node_id.to_be_bytes());
    hasher.update(raw_handle.to_be_bytes());
    hasher.finalize().into()
}

/// Converts raw Linux open flags to the immutable worker profile.
///
/// # Errors
///
/// Returns [`FileCallbackError::ReadOnlyFilesystem`] for writes, creation,
/// truncation, or append. Returns [`FileCallbackError::InvalidOpenFlags`] for
/// path-only/directory opens and unknown semantic bits.
pub fn normalize_open_flags(raw: i32) -> Result<FileOpenRequest, FileCallbackError> {
    if raw < 0 {
        return Err(FileCallbackError::InvalidOpenFlags);
    }
    let access = raw & libc::O_ACCMODE;
    if access != libc::O_RDONLY {
        return Err(FileCallbackError::ReadOnlyFilesystem);
    }
    let mutations = libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC | libc::O_APPEND;
    if raw & mutations != 0 {
        return Err(FileCallbackError::ReadOnlyFilesystem);
    }
    if raw & libc::O_DIRECTORY != 0 {
        return Err(FileCallbackError::InvalidOpenFlags);
    }
    let admitted =
        libc::O_ACCMODE | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_LARGEFILE;
    if raw & !admitted != 0 {
        return Err(FileCallbackError::InvalidOpenFlags);
    }
    Ok(FileOpenRequest::new(
        FileAccessMode::ReadOnly,
        false,
        false,
        false,
    ))
}
