//! Dormant source-level FUSE OPEN, READ, and RELEASE callback sequencing.
//!
//! This module intentionally is not part of the installed C ABI. It normalizes
//! Linux open flags and defines reply-publication ordering around the
//! backend-neutral worker data plane. A future transport revision must adapt
//! these typed outcomes without manufacturing descriptors or backing IDs.
//! Before executing a returned backing effect or publishing a selector, that
//! adapter must durably persist [`FileCallbackState::registration_snapshot`].

use aos_filesystem_view::{
    BackingDisposition, BackingIdentity, DataError, DataPlane, DataReadRequest, DataReadResult,
    DataReadScratch, FileAccessMode, FileOpenRequest, MetadataConnection, MonotonicClock,
    PassthroughRegistrations, PendingFileReply, PreparedDataOpen, RegistrationAction,
    RegistrationOperation, RegistrationPhase, ReleaseDisposition, RequestBudget, RequestControl,
    VerifiedObjectReader, WorkerError,
};

/// Reports flag normalization, worker, data, or publication failure.
#[derive(Debug, thiserror::Error)]
pub enum FileCallbackError {
    /// Raw open flags request unsupported or mutable semantics.
    #[error("unsupported immutable FUSE OPEN flags")]
    InvalidOpenFlags,
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
pub enum OpenReplySelection {
    /// The reply selected userspace fallback.
    Fallback,
    /// The reply selected one nonzero broker-created backing selector.
    Passthrough {
        /// Opaque successful broker registration.
        registration: RegisteredBacking,
    },
}

/// Opaque successful registration of one verified backing on this connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredBacking {
    connection_brand: [u8; 32],
    operation: RegistrationOperation,
    backing_id: u64,
    backing: BackingIdentity,
}

impl RegisteredBacking {
    fn from_durable_registration(
        connection_brand: [u8; 32],
        operation: RegistrationOperation,
        backing_id: u64,
        backing: BackingIdentity,
    ) -> Result<Self, FileCallbackError> {
        if connection_brand == [0; 32] || backing_id == 0 {
            return Err(FileCallbackError::Stale);
        }
        Ok(Self {
            connection_brand,
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
pub enum OpenPublication {
    /// The transport proved that this exact selection became visible.
    Published(OpenReplySelection),
    /// The transport proved no reply became visible.
    Rejected,
    /// The transport cannot prove whether the reply became visible.
    Ambiguous,
}

/// Reports the committed result of one unambiguous OPEN callback.
pub enum OpenCompletion<'index> {
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
pub enum OpenFinishFailure<'index> {
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
pub struct BackingCloseConfirmation {
    connection_brand: [u8; 32],
    operation: RegistrationOperation,
    backing_id: u64,
}

impl BackingCloseConfirmation {
    fn from_broker_observation(
        connection_brand: [u8; 32],
        operation: RegistrationOperation,
        backing_id: u64,
    ) -> Result<Self, FileCallbackError> {
        if connection_brand == [0; 32] || backing_id == 0 {
            return Err(FileCallbackError::Stale);
        }
        Ok(Self {
            connection_brand,
            operation,
            backing_id,
        })
    }
}

/// Retains a rejected pending OPEN until its successful registration is closed.
#[must_use = "confirm or reconcile the backing close before dropping worker state"]
pub struct RejectedOpenCleanup<'index> {
    worker: PendingFileReply<'index>,
    operation: RegistrationOperation,
    connection_brand: [u8; 32],
}

/// Proves registration state was updated after a rejected-OPEN close.
#[must_use = "persist registration state before aborting the worker reservation"]
pub struct RejectedWorkerCleanup<'index> {
    worker: PendingFileReply<'index>,
    connection_brand: [u8; 32],
}

/// Proves registration state was updated after an active-handle close.
#[must_use = "persist registration state before releasing the worker handle"]
pub struct WorkerReleasePermit {
    connection_brand: [u8; 32],
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
        /// Exact connection-local selector to close.
        backing_id: u64,
    },
}

/// Holds a worker reservation and resolved data disposition before reply publication.
#[must_use = "finish the OPEN publication transition"]
pub struct PendingCallbackOpen<'index> {
    worker: PendingFileReply<'index>,
    data: PreparedDataOpen,
    connection_brand: [u8; 32],
    registration: Option<RegistrationOperation>,
    backing_id: Option<u64>,
}

impl PendingCallbackOpen<'_> {
    /// Returns the only reply plan authorized for this pending open.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError::Stale`] if a passthrough disposition lacks
    /// the durable registration operation created with it.
    pub fn reply_plan(&self) -> Result<OpenReplyPlan, FileCallbackError> {
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
    registration: Option<RegistrationOperation>,
    release_pending: bool,
    release_requires_close: bool,
    release_close_recorded: bool,
}

/// Owns bounded adapter state for active data dispositions.
pub struct FileCallbackState {
    active: Vec<ActiveCallbackOpen>,
    pending_handles: usize,
    maximum_handles: usize,
    connection_brand: [u8; 32],
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
        let connection_brand = connection.connection_binding();
        if connection_brand == [0; 32] {
            return Err(FileCallbackError::Stale);
        }
        if registrations.authority_binding() != connection_brand {
            return Err(FileCallbackError::Stale);
        }
        Ok(Self {
            active,
            pending_handles: 0,
            maximum_handles,
            connection_brand,
            registrations,
        })
    }

    /// Normalizes flags and prepares worker/data authority before a reply.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] for unsupported flags, exhausted adapter
    /// capacity, worker admission failure, or unavailable data realization.
    pub fn prepare_open<'index>(
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
        let data = match data_plane.prepare_open(&worker, backing, clock.now_ns()) {
            Ok(data) => data,
            Err(error) => {
                connection.abort_open(&mut worker)?;
                return Err(error.into());
            }
        };
        let (registration, backing_id) = match data.disposition() {
            BackingDisposition::VerifiedFallback => (None, None),
            BackingDisposition::Passthrough(backing) => {
                let action = match self.registrations.begin_open(backing, clock.now_ns()) {
                    Ok(action) => action,
                    Err(error) => {
                        connection.abort_open(&mut worker)?;
                        return Err(error.into());
                    }
                };
                match action {
                    RegistrationAction::OpenBacking { operation } => (Some(operation), None),
                    RegistrationAction::PublishCoalesced { operation } => {
                        let backing_id = self.registrations.backing_id(operation)?;
                        (Some(operation), Some(backing_id))
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
            connection_brand: self.connection_brand,
            registration,
            backing_id,
        })
    }

    /// Records a successful `BACKING_OPEN` before its selector can be published.
    ///
    /// The caller must durably persist [`Self::registration_snapshot`] before
    /// encoding the returned registration into a FUSE reply.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] unless `pending` owns an exact pending
    /// registration on this connection and `backing_id` is nonzero.
    pub fn record_backing_opened(
        &mut self,
        pending: &mut PendingCallbackOpen<'_>,
        backing_id: u64,
    ) -> Result<RegisteredBacking, FileCallbackError> {
        self.validate_pending(pending)?;
        let operation = pending.registration.ok_or(FileCallbackError::Stale)?;
        if pending.backing_id.is_some()
            || self.registrations.phase(operation)? != RegistrationPhase::Pending
        {
            return Err(FileCallbackError::Stale);
        }
        self.registrations.record_opened(operation, backing_id)?;
        pending.backing_id = Some(backing_id);
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
        {
            return Err(FileCallbackError::Stale);
        }
        RegisteredBacking::from_durable_registration(
            self.connection_brand,
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
    pub fn finish_open<'index>(
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
            OpenPublication::Published(selection) => {
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
                    registration: pending.registration,
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
    /// Returns [`FileCallbackError`] unless the confirmation matches the exact
    /// connection, operation, and selector retained by `cleanup`.
    pub fn record_rejected_backing_closed<'index>(
        &mut self,
        cleanup: RejectedOpenCleanup<'index>,
        confirmation: BackingCloseConfirmation,
    ) -> Result<RejectedWorkerCleanup<'index>, FileCallbackError> {
        if cleanup.connection_brand != self.connection_brand
            || confirmation.connection_brand != self.connection_brand
            || confirmation.operation != cleanup.operation
            || confirmation.backing_id
                != self.registrations.closing_backing_id(cleanup.operation)?
        {
            return Err(FileCallbackError::Stale);
        }
        self.registrations
            .record_rejected_open_closed(cleanup.operation)?;
        Ok(RejectedWorkerCleanup {
            worker: cleanup.worker,
            connection_brand: self.connection_brand,
        })
    }

    /// Aborts rejected worker state after the registration update is durable.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError`] for a foreign permit or stale worker state.
    pub fn finish_rejected_open_cleanup<'index>(
        &mut self,
        connection: &mut MetadataConnection<'_, 'index, '_, '_>,
        mut cleanup: RejectedWorkerCleanup<'index>,
    ) -> Result<OpenCompletion<'index>, FileCallbackError> {
        self.validate_connection(connection)?;
        if cleanup.connection_brand != self.connection_brand {
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
    pub fn retry_rejected_open_close(
        &self,
        cleanup: &RejectedOpenCleanup<'_>,
    ) -> Result<ReleasePlan, FileCallbackError> {
        if cleanup.connection_brand != self.connection_brand
            || self.registrations.retry_close(cleanup.operation)?
                != (RegistrationAction::CloseBeforeRelease {
                    operation: cleanup.operation,
                })
        {
            return Err(FileCallbackError::Stale);
        }
        Ok(ReleasePlan::CloseBacking {
            operation: cleanup.operation,
            backing_id: self.registrations.closing_backing_id(cleanup.operation)?,
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
    pub fn record_rejected_close_ambiguity(
        &mut self,
        connection: &mut MetadataConnection<'_, '_, '_, '_>,
        cleanup: RejectedOpenCleanup<'_>,
    ) -> Result<(), FileCallbackError> {
        self.validate_connection(connection)?;
        if cleanup.connection_brand != self.connection_brand {
            return Err(FileCallbackError::Stale);
        }
        self.registrations.record_ambiguous(cleanup.operation)?;
        connection.fault_pending_open_reply_ambiguity(&cleanup.worker)?;
        Err(FileCallbackError::AmbiguousPublication)
    }

    /// Converts a definite broker close observation into opaque cleanup evidence.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError::Stale`] for a zero or foreign selector.
    pub fn observe_backing_close(
        &self,
        operation: RegistrationOperation,
        backing_id: u64,
    ) -> Result<BackingCloseConfirmation, FileCallbackError> {
        if self.registrations.closing_backing_id(operation)? != backing_id {
            return Err(FileCallbackError::Stale);
        }
        BackingCloseConfirmation::from_broker_observation(
            self.connection_brand,
            operation,
            backing_id,
        )
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
    pub fn prepare_release(
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
        let plan = match self.active[position].registration {
            None => ReleasePlan::ReleaseWorker,
            Some(operation) => match self.registrations.begin_release(operation)? {
                RegistrationAction::ReleaseWorkerOpen { .. } => ReleasePlan::ReleaseWorker,
                RegistrationAction::CloseBeforeRelease { .. } => ReleasePlan::CloseBacking {
                    operation,
                    backing_id: self.registrations.closing_backing_id(operation)?,
                },
                _ => return Err(FileCallbackError::Stale),
            },
        };
        self.active[position].release_pending = true;
        self.active[position].release_requires_close =
            matches!(plan, ReleasePlan::CloseBacking { .. });
        self.active[position].release_close_recorded = false;
        Ok((cleanup, plan))
    }

    /// Repeats the exact close-before-release plan after a definite retryable failure.
    ///
    /// # Errors
    ///
    /// Returns [`FileCallbackError::Stale`] unless the connection, inode,
    /// handle, and pending-release phase all match.
    pub fn retry_release(
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
        Ok(ReleasePlan::CloseBacking {
            operation,
            backing_id: self.registrations.closing_backing_id(operation)?,
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
    pub fn record_backing_closed(
        &mut self,
        node_id: u64,
        raw_handle: u64,
        confirmation: BackingCloseConfirmation,
    ) -> Result<WorkerReleasePermit, FileCallbackError> {
        let position = self.active_position(node_id, raw_handle)?;
        let active = &self.active[position];
        let operation = active.registration.ok_or(FileCallbackError::Stale)?;
        if !active.release_pending
            || !active.release_requires_close
            || active.release_close_recorded
            || confirmation.connection_brand != self.connection_brand
            || confirmation.operation != operation
            || confirmation.backing_id != self.registrations.closing_backing_id(operation)?
        {
            return Err(FileCallbackError::Stale);
        }
        self.registrations.record_closed(operation)?;
        self.active[position].release_close_recorded = true;
        Ok(WorkerReleasePermit {
            connection_brand: self.connection_brand,
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
    pub fn finish_release(
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
                if permit.connection_brand == self.connection_brand
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
    pub fn record_close_ambiguity(
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
            .find(|open| open.node_id == node_id && open.raw_handle == raw_handle)
            .ok_or(FileCallbackError::Stale)
    }

    fn active_position(&self, node_id: u64, raw_handle: u64) -> Result<usize, FileCallbackError> {
        self.active
            .iter()
            .position(|open| open.node_id == node_id && open.raw_handle == raw_handle)
            .ok_or(FileCallbackError::Stale)
    }

    fn validate_connection(
        &self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
    ) -> Result<(), FileCallbackError> {
        (connection.connection_binding() == self.connection_brand)
            .then_some(())
            .ok_or(FileCallbackError::Stale)
    }

    fn validate_pending(&self, pending: &PendingCallbackOpen<'_>) -> Result<(), FileCallbackError> {
        if pending.connection_brand != self.connection_brand || self.pending_handles == 0 {
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
                registration.connection_brand == self.connection_brand
                    && registration.operation == operation
                    && registration.backing == expected
                    && pending.backing_id == Some(registration.backing_id)
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
                    connection_brand: self.connection_brand,
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
                        connection_brand: self.connection_brand,
                    },
                })
            }
            RegistrationPhase::Active => {
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
                                connection_brand: self.connection_brand,
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
                                connection_brand: self.connection_brand,
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

/// Converts raw Linux open flags to the immutable worker profile.
///
/// # Errors
///
/// Returns [`FileCallbackError::InvalidOpenFlags`] for writes, creation,
/// truncation, append, path-only/directory opens, or unknown semantic bits.
pub fn normalize_open_flags(raw: i32) -> Result<FileOpenRequest, FileCallbackError> {
    if raw < 0 {
        return Err(FileCallbackError::InvalidOpenFlags);
    }
    let access = raw & libc::O_ACCMODE;
    if access != libc::O_RDONLY {
        return Err(FileCallbackError::InvalidOpenFlags);
    }
    let forbidden =
        libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC | libc::O_APPEND | libc::O_DIRECTORY;
    if raw & forbidden != 0 {
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
