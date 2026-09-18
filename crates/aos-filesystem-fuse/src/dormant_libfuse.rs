//! Session-bound but uninstalled libfuse data and xattr callback adapter.
//!
//! This adapter gives a future libfuse operations owner concrete callsites for
//! OPEN, READ, RELEASE, GETXATTR, and LISTXATTR while preserving the existing
//! bounded reducers and protected receipt ordering. Only the private live
//! session context can construct it, so request time, cancellation, and reply
//! publication cannot be supplied by a public caller. [`crate::run_metadata`]
//! neither constructs nor installs it.

use crate::control::Control;
use crate::file_callbacks::{
    OpenCompletion, OpenFinishFailure, OpenPublication, PendingCallbackOpen, WorkerReleasePermit,
};
use crate::operations::ImmutableOperations;
use aos_filesystem_view::{
    BackingIdentity, DataPlane, DataReadResult, DataReadScratch, DurableStateError,
    DurableStateLimits, ExtendedAttributeReply, ExtendedAttributeScratch, MetadataConnection,
    PassthroughRegistrations, ReleaseDisposition, RequestBudget, VerifiedObjectReader,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

mod broker;
mod registration_journal;

pub use crate::file_callbacks::{
    FileCallbackError, OpenReplyPlan, RegisteredBacking, RejectedWorkerCleanup, ReleasePlan,
};
pub use crate::operations::{
    FileHandleRequest, ImmutableOperationLimits, OperationError, ReadRequest, ReleaseRequest,
};
pub use broker::{
    DormantCloseBrokerCommitResultV2, DormantCloseReceiptApplicationV2,
    DormantCommittedCloseBrokerCompletionV2, DormantCommittedOpenBrokerCompletionV2,
    DormantOpenBrokerCommitResultV2, DormantOpenReceiptApplicationV2,
    DormantPendingCloseBrokerCompletionRecoveryV2, DormantPendingCloseBrokerCompletionV2,
    DormantPendingOpenBrokerCompletionRecoveryV2, DormantPendingOpenBrokerCompletionV2,
    DormantRejectedOpenCloseApplicationV2, DormantVerifiedCloseBrokerCompletionV2,
    DormantVerifiedOpenBrokerCompletionV2,
};
pub use registration_journal::{
    ProtectedFuseRegistrationCommitResultV2, ProtectedFuseRegistrationErrorV2,
    ProtectedFuseRegistrationOwnerV2, ProtectedFuseRegistrationReadbackV2,
    ProtectedFuseRegistrationRecoveryV2,
};

/// Retains an OPEN reservation without exposing its unauthenticated reply plan.
#[must_use = "authorize and finish the pending OPEN"]
pub struct DormantPendingOpenV2<'index> {
    pending: PendingCallbackOpen<'index>,
    request: DormantFuseRequestDeadlineV2,
}

impl DormantPendingOpenV2<'_> {
    /// Issues persistence custody for this request's exact absolute deadline.
    #[must_use]
    pub const fn registration_persistence_authority(
        &self,
    ) -> DormantRegistrationPersistenceAuthorityV2 {
        DormantRegistrationPersistenceAuthorityV2 {
            request: self.request,
        }
    }
}

/// Authorizes one exact OPEN reply or broker registration attempt.
///
/// The capability is minted only by consuming current protected registration
/// readback. It is intentionally neither cloneable nor constructible by callers.
#[must_use = "consume this one-shot authority in OPEN completion or publication"]
pub struct DormantAuthorizedOpenPlanV2<'owner> {
    plan: OpenReplyPlan,
    durable_limits: DurableStateLimits,
    current: ProtectedFuseRegistrationReadbackV2<'owner>,
    request: DormantFuseRequestDeadlineV2,
}

/// Retains one exact kernel reply observation with its protected worker authority.
///
/// Only the crate-owned session transport can construct this receipt. Its
/// fields intentionally expose neither raw reply state nor a self-sealing path.
#[must_use = "consume this transport observation in OPEN completion"]
pub struct DormantOpenPublicationReceiptV2<'owner> {
    publication: OpenPublication,
    authorization: DormantAuthorizedOpenPlanV2<'owner>,
    connection_binding: [u8; 32],
    reducer_commitment: [u8; 32],
}

impl DormantAuthorizedOpenPlanV2<'_> {
    /// Returns the exact plan that a future transport may attempt.
    #[must_use]
    pub const fn plan(&self) -> OpenReplyPlan {
        self.plan
    }
}

/// Retains recoverable OPEN ownership without exposing a raw pending token.
pub enum DormantOpenFinishFailureV2<'index> {
    /// The OPEN may be retried after a fresh protected authorization.
    OwnershipReturned {
        /// Failure that prevented the requested transition.
        error: FileCallbackError,
        /// Still-owned OPEN reservation.
        pending: DormantPendingOpenV2<'index>,
    },
    /// Connection teardown owns the consumed reservation.
    Terminal {
        /// Failure that terminally faulted the connection.
        error: FileCallbackError,
    },
}

impl DormantOpenFinishFailureV2<'_> {
    /// Returns the underlying callback failure.
    #[must_use]
    pub const fn error(&self) -> &FileCallbackError {
        match self {
            Self::OwnershipReturned { error, .. } | Self::Terminal { error } => error,
        }
    }
}

/// Reports an OPEN result without exposing rejected-backing close coordinates.
#[must_use = "persist and finish any retained rejected-OPEN cleanup"]
pub enum DormantOpenCompletionV2<'index> {
    /// The kernel-visible reply was committed under this raw worker handle.
    Published {
        /// Active connection-scoped file handle.
        handle: u64,
    },
    /// No reply became visible and no durable cleanup remains.
    Rejected,
    /// Durable registration cleanup must be persisted before worker abort.
    RejectedCleanupRequired {
        /// Opaque worker cleanup retained across protected persistence.
        cleanup: DormantRejectedWorkerCleanupV2<'index>,
    },
    /// A backing close is pending, but its selector remains concealed.
    RejectedClosePending(DormantRejectedOpenCloseV2<'index>),
}

/// Retains rejected worker cleanup with its originating request deadline.
#[must_use = "finish this cleanup before its originating request expires"]
pub struct DormantRejectedWorkerCleanupV2<'index> {
    cleanup: RejectedWorkerCleanup<'index>,
    request: DormantFuseRequestDeadlineV2,
}

impl DormantRejectedWorkerCleanupV2<'_> {
    /// Issues persistence custody for this request's exact absolute deadline.
    #[must_use]
    pub const fn registration_persistence_authority(
        &self,
    ) -> DormantRegistrationPersistenceAuthorityV2 {
        DormantRegistrationPersistenceAuthorityV2 {
            request: self.request,
        }
    }
}

/// Retains rejected-OPEN cleanup without exposing its close selector or operation.
#[must_use = "persist Closing state and authorize its exact backing close"]
pub struct DormantRejectedOpenCloseV2<'index> {
    cleanup: crate::file_callbacks::RejectedOpenCleanup<'index>,
    close_authorized: bool,
    request: DormantFuseRequestDeadlineV2,
}

/// Retains one RELEASE transition and any exact broker-close permission.
#[must_use = "authorize and finish or reconcile the pending RELEASE"]
pub struct DormantPendingReleaseV2 {
    file: FileHandleRequest,
    disposition: ReleaseDisposition,
    plan: ReleasePlan,
    permit: Option<WorkerReleasePermit>,
    request: DormantFuseRequestDeadlineV2,
}

impl DormantPendingReleaseV2 {
    /// Returns the data-plane disposition associated with this release.
    #[must_use]
    pub const fn disposition(&self) -> ReleaseDisposition {
        self.disposition
    }

    /// Issues persistence custody for this request's exact absolute deadline.
    #[must_use]
    pub const fn registration_persistence_authority(
        &self,
    ) -> DormantRegistrationPersistenceAuthorityV2 {
        DormantRegistrationPersistenceAuthorityV2 {
            request: self.request,
        }
    }
}

/// Authorizes one exact RELEASE cleanup or broker close attempt.
///
/// The capability is minted only by consuming current protected registration
/// readback. It is intentionally neither cloneable nor constructible by callers.
#[must_use = "consume this one-shot authority in close verification or final cleanup"]
pub struct DormantAuthorizedReleasePlanV2<'owner> {
    plan: ReleasePlan,
    durable_limits: DurableStateLimits,
    current: ProtectedFuseRegistrationReadbackV2<'owner>,
    request: DormantFuseRequestDeadlineV2,
}

impl DormantAuthorizedReleasePlanV2<'_> {
    /// Returns the exact plan that a future transport may attempt.
    #[must_use]
    pub const fn plan(&self) -> ReleasePlan {
        self.plan
    }
}

/// Authorizes one exact broker close for a definitely rejected OPEN.
#[must_use = "consume this one-shot authority in close verification or ambiguity handling"]
pub struct DormantAuthorizedRejectedOpenCloseV2<'owner> {
    plan: ReleasePlan,
    durable_limits: DurableStateLimits,
    current: ProtectedFuseRegistrationReadbackV2<'owner>,
    request: DormantFuseRequestDeadlineV2,
}

impl DormantAuthorizedRejectedOpenCloseV2<'_> {
    /// Returns the exact close plan that a future transport may attempt.
    #[must_use]
    pub const fn plan(&self) -> ReleasePlan {
        self.plan
    }
}

/// Owns callback state prepared for a future libfuse operations table.
///
/// The wrapper performs no registration by itself and exposes no raw callback
/// context pointer or public constructor. A crate-owned session must retain it.
#[must_use = "retain the session-bound dormant adapter"]
pub struct DormantLibfuseOperationsAdapterV2 {
    operations: ImmutableOperations,
    request_owner: DormantFuseRequestOwnerV2,
    registration_head: [u8; 32],
}

struct DormantFuseRequestOwnerV2 {
    cancellation: OwnedFd,
    timeout_seconds: u16,
    boot_id: [u8; 16],
    monotonic_floor_ns: u64,
    connection_binding: [u8; 32],
    reducer_commitment: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct DormantFuseRequestDeadlineV2 {
    absolute_deadline_ns: u64,
    connection_binding: [u8; 32],
    reducer_commitment: [u8; 32],
}

/// Carries one request's immutable deadline into registration persistence.
///
/// It has no public constructor and reveals no scalar deadline.
#[must_use = "consume this request authority in registration persistence"]
pub struct DormantRegistrationPersistenceAuthorityV2 {
    request: DormantFuseRequestDeadlineV2,
}

impl DormantFuseRequestOwnerV2 {
    fn from_session_transport(
        connection: &MetadataConnection<'_, '_, '_, '_>,
        reducer_commitment: [u8; 32],
        cancellation: libc::c_int,
        timeout_seconds: u16,
    ) -> Result<Self, OperationError> {
        let connection_binding = connection.connection_binding();
        if connection_binding == [0; 32]
            || reducer_commitment == [0; 32]
            || cancellation < 0
            || !(1..=300).contains(&timeout_seconds)
        {
            return Err(OperationError::Integrity);
        }
        let boot_id = current_boot_id()?;
        let monotonic_floor_ns = kernel_boottime_ns()?;
        // SAFETY: `cancellation` remains transport-owned for this call. F_DUPFD_CLOEXEC
        // returns an independent descriptor which this owner alone adopts.
        let duplicated = unsafe { libc::fcntl(cancellation, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated < 0 {
            return Err(OperationError::Integrity);
        }
        // SAFETY: Successful F_DUPFD_CLOEXEC returned a fresh owned descriptor.
        let cancellation = unsafe { OwnedFd::from_raw_fd(duplicated) };

        Ok(Self {
            cancellation,
            timeout_seconds,
            boot_id,
            monotonic_floor_ns,
            connection_binding,
            reducer_commitment,
        })
    }

    fn request_control(
        &mut self,
        request: DormantFuseRequestDeadlineV2,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        reducer_commitment: [u8; 32],
    ) -> Result<Control, OperationError> {
        self.revalidate(request, connection, reducer_commitment)?;
        Control::from_absolute_deadline(self.cancellation.as_raw_fd(), request.absolute_deadline_ns)
            .map_err(|_| OperationError::Integrity)
    }

    fn admit_request(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        reducer_commitment: [u8; 32],
    ) -> Result<DormantFuseRequestDeadlineV2, OperationError> {
        let now = self.revalidate_session(connection, reducer_commitment)?;
        let timeout_ns = u64::from(self.timeout_seconds)
            .checked_mul(1_000_000_000)
            .ok_or(OperationError::Integrity)?;
        let absolute_deadline_ns = now
            .checked_add(timeout_ns)
            .ok_or(OperationError::Integrity)?;
        Ok(DormantFuseRequestDeadlineV2 {
            absolute_deadline_ns,
            connection_binding: self.connection_binding,
            reducer_commitment: self.reducer_commitment,
        })
    }

    fn revalidate(
        &mut self,
        request: DormantFuseRequestDeadlineV2,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        reducer_commitment: [u8; 32],
    ) -> Result<(), OperationError> {
        if request.connection_binding != self.connection_binding
            || request.reducer_commitment != self.reducer_commitment
        {
            return Err(OperationError::Integrity);
        }
        let now = self.revalidate_session(connection, reducer_commitment)?;
        if now >= request.absolute_deadline_ns {
            return Err(OperationError::Integrity);
        }
        Ok(())
    }

    fn revalidate_session(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        reducer_commitment: [u8; 32],
    ) -> Result<u64, OperationError> {
        if connection.connection_binding() != self.connection_binding
            || reducer_commitment != self.reducer_commitment
            || current_boot_id()? != self.boot_id
        {
            return Err(OperationError::Integrity);
        }
        let mut cancellation = libc::pollfd {
            fd: self.cancellation.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: One initialized pollfd is writable for this nonblocking call.
        let poll_result = unsafe { libc::poll(&mut cancellation, 1, 0) };
        if poll_result < 0 || cancellation.revents != 0 {
            return Err(OperationError::Integrity);
        }
        let now = kernel_boottime_ns()?;
        if now < self.monotonic_floor_ns {
            return Err(OperationError::Integrity);
        }
        self.monotonic_floor_ns = now;
        Ok(now)
    }
}

impl DormantLibfuseOperationsAdapterV2 {
    pub(crate) fn from_session_transport(
        connection: &mut MetadataConnection<'_, '_, '_, '_>,
        registrations: PassthroughRegistrations,
        limits: ImmutableOperationLimits,
        registration_head: [u8; 32],
        cancellation: libc::c_int,
        timeout_seconds: u16,
    ) -> Result<Self, OperationError> {
        let operations = ImmutableOperations::for_connection(connection, registrations, limits)?;
        let request_owner = DormantFuseRequestOwnerV2::from_session_transport(
            connection,
            operations.reducer_commitment(),
            cancellation,
            timeout_seconds,
        )?;
        Ok(Self {
            operations,
            request_owner,
            registration_head,
        })
    }

    /// Prepares one immutable OPEN without publishing a reply.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for foreign connection state, unsupported
    /// flags, exhausted handles, worker admission, or unavailable realization.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_open<'index>(
        &mut self,
        connection: &mut MetadataConnection<'_, 'index, '_, '_>,
        data_plane: &DataPlane,
        node_id: u64,
        flags: i32,
        backing: Option<BackingIdentity>,
        budget: RequestBudget,
    ) -> Result<DormantPendingOpenV2<'index>, OperationError> {
        let request = self
            .request_owner
            .admit_request(connection, self.operations.reducer_commitment())?;
        let control = self.request_owner.request_control(
            request,
            connection,
            self.operations.reducer_commitment(),
        )?;
        let pending = self.operations.prepare_open(
            connection, data_plane, node_id, flags, backing, budget, &control, &control,
        )?;
        Ok(DormantPendingOpenV2 { pending, request })
    }

    /// Authorizes one exact OPEN plan after protected snapshot readback.
    ///
    /// # Errors
    ///
    /// Returns an error unless the readback is current and the reservation can
    /// still derive its exact reply or broker-registration plan.
    pub fn authorize_open_plan<'owner>(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        durable_limits: DurableStateLimits,
        pending: &DormantPendingOpenV2<'_>,
        persisted_current: ProtectedFuseRegistrationReadbackV2<'owner>,
    ) -> Result<DormantAuthorizedOpenPlanV2<'owner>, DormantLibfuseCallbackErrorV2> {
        let current = self.require_registration_readback(
            pending.request,
            connection,
            durable_limits,
            persisted_current,
        )?;
        let plan = pending.pending.reply_plan().map_err(OperationError::from)?;
        Ok(DormantAuthorizedOpenPlanV2 {
            plan,
            durable_limits,
            current,
            request: pending.request,
        })
    }

    pub(crate) fn observe_open_publication<'owner>(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        pending: &DormantPendingOpenV2<'_>,
        publication: OpenPublication,
        authorization: DormantAuthorizedOpenPlanV2<'owner>,
    ) -> Result<DormantOpenPublicationReceiptV2<'owner>, DormantLibfuseCallbackErrorV2> {
        if pending.pending.reply_plan().map_err(OperationError::from)? != authorization.plan
            || pending.request != authorization.request
        {
            return Err(OperationError::Stale.into());
        }
        self.request_owner.revalidate(
            authorization.request,
            connection,
            self.operations.reducer_commitment(),
        )?;
        let DormantAuthorizedOpenPlanV2 {
            plan,
            durable_limits,
            current,
            request,
        } = authorization;
        let current =
            self.require_registration_readback(request, connection, durable_limits, current)?;
        Ok(DormantOpenPublicationReceiptV2 {
            publication,
            authorization: DormantAuthorizedOpenPlanV2 {
                plan,
                durable_limits,
                current,
                request,
            },
            connection_binding: connection.connection_binding(),
            reducer_commitment: self.operations.reducer_commitment(),
        })
    }

    /// Completes one OPEN after its current registration snapshot was read back.
    ///
    /// # Errors
    ///
    /// Returns a callback error when the readback is stale. State-machine
    /// ownership failures retain the original [`OpenFinishFailure`].
    pub fn finish_open<'index>(
        &mut self,
        connection: &mut MetadataConnection<'_, 'index, '_, '_>,
        pending: DormantPendingOpenV2<'index>,
        receipt: DormantOpenPublicationReceiptV2<'_>,
    ) -> Result<
        Result<DormantOpenCompletionV2<'index>, DormantOpenFinishFailureV2<'index>>,
        DormantLibfuseCallbackErrorV2,
    > {
        if receipt.connection_binding != connection.connection_binding()
            || receipt.reducer_commitment != self.operations.reducer_commitment()
            || pending.pending.reply_plan().map_err(OperationError::from)?
                != receipt.authorization.plan
            || pending.request != receipt.authorization.request
        {
            return Err(OperationError::Stale.into());
        }
        self.request_owner.revalidate(
            pending.request,
            connection,
            self.operations.reducer_commitment(),
        )?;
        self.consume_open_authorization(connection, &pending, receipt.authorization)?;
        let request = pending.request;
        Ok(
            match self
                .operations
                .finish_open(connection, pending.pending, receipt.publication)
            {
                Ok(completion) => Ok(conceal_open_completion(completion, request)),
                Err(OpenFinishFailure::OwnershipReturned { error, pending }) => {
                    Err(DormantOpenFinishFailureV2::OwnershipReturned {
                        error,
                        pending: DormantPendingOpenV2 { pending, request },
                    })
                }
                Err(OpenFinishFailure::Terminal { error }) => {
                    Err(DormantOpenFinishFailureV2::Terminal { error })
                }
            },
        )
    }

    /// Aborts rejected worker state after exact registration readback.
    ///
    /// # Errors
    ///
    /// Returns an error unless the snapshot is current and the cleanup token
    /// matches the retained worker reservation.
    pub fn finish_rejected_open_cleanup<'index>(
        &mut self,
        connection: &mut MetadataConnection<'_, 'index, '_, '_>,
        durable_limits: DurableStateLimits,
        cleanup: DormantRejectedWorkerCleanupV2<'index>,
        persisted_current: ProtectedFuseRegistrationReadbackV2<'_>,
    ) -> Result<DormantOpenCompletionV2<'index>, DormantLibfuseCallbackErrorV2> {
        let _ = self.require_registration_readback(
            cleanup.request,
            connection,
            durable_limits,
            persisted_current,
        )?;
        self.operations
            .finish_rejected_open_cleanup(connection, cleanup.cleanup)
            .map(|completion| conceal_open_completion(completion, cleanup.request))
            .map_err(Into::into)
    }

    /// Authorizes a rejected-OPEN close after exact protected Closing readback.
    ///
    /// # Errors
    ///
    /// Returns an error unless the cleanup remains exact and Closing and the
    /// namespace-50 snapshot is its fresh current protected representation.
    /// One holder can mint this authority only once; losing it fails closed
    /// rather than permitting the close effect to be issued again.
    pub fn authorize_rejected_open_close<'owner>(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        durable_limits: DurableStateLimits,
        cleanup: &mut DormantRejectedOpenCloseV2<'_>,
        persisted_closing: ProtectedFuseRegistrationReadbackV2<'owner>,
    ) -> Result<DormantAuthorizedRejectedOpenCloseV2<'owner>, DormantLibfuseCallbackErrorV2> {
        if cleanup.close_authorized {
            return Err(OperationError::Stale.into());
        }
        let current = self.require_registration_readback(
            cleanup.request,
            connection,
            durable_limits,
            persisted_closing,
        )?;
        let plan = self
            .operations
            .retry_rejected_open_close(&cleanup.cleanup)?;
        cleanup.close_authorized = true;
        Ok(DormantAuthorizedRejectedOpenCloseV2 {
            plan,
            durable_limits,
            current,
            request: cleanup.request,
        })
    }

    /// Records an indeterminate rejected-OPEN close and faults the connection.
    ///
    /// # Errors
    ///
    /// Returns the terminal ambiguity error after exact cleanup validation.
    pub fn record_rejected_close_ambiguity<'index>(
        &mut self,
        connection: &mut MetadataConnection<'_, 'index, '_, '_>,
        cleanup: DormantRejectedOpenCloseV2<'index>,
        authorization: DormantAuthorizedRejectedOpenCloseV2<'_>,
    ) -> Result<(), DormantLibfuseCallbackErrorV2> {
        if !cleanup.close_authorized
            || self
                .operations
                .retry_rejected_open_close(&cleanup.cleanup)?
                != authorization.plan
        {
            return Err(OperationError::Stale.into());
        }
        self.consume_rejected_open_close_authorization(connection, &cleanup, authorization)?;
        self.operations
            .record_rejected_close_ambiguity(connection, cleanup.cleanup)
            .map_err(Into::into)
    }

    /// Executes the bounded fallback READ callback path.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for invalid request scalars, stale handles,
    /// passthrough ownership, cancellation, exhaustion, or integrity failure.
    #[allow(clippy::too_many_arguments)]
    pub fn read<'scratch>(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        data_plane: &DataPlane,
        request: ReadRequest,
        scratch: &'scratch mut DataReadScratch,
        provider: &mut impl VerifiedObjectReader,
        durable_limits: DurableStateLimits,
        persisted_current: ProtectedFuseRegistrationReadbackV2<'_>,
    ) -> Result<DataReadResult<'scratch>, OperationError> {
        let deadline = self
            .request_owner
            .admit_request(connection, self.operations.reducer_commitment())?;
        let _current = self
            .require_registration_readback(deadline, connection, durable_limits, persisted_current)
            .map_err(|_| OperationError::Integrity)?;
        let control = self.request_owner.request_control(
            deadline,
            connection,
            self.operations.reducer_commitment(),
        )?;
        self.operations.read(
            connection, data_plane, request, scratch, provider, &control, &control,
        )
    }

    /// Begins RELEASE and returns any required broker-close plan.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for invalid flags, stale handles, or an
    /// inconsistent passthrough registration.
    pub fn prepare_release(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        data_plane: &DataPlane,
        request: ReleaseRequest,
    ) -> Result<DormantPendingReleaseV2, OperationError> {
        let deadline = self
            .request_owner
            .admit_request(connection, self.operations.reducer_commitment())?;
        let file = request.file;
        let (disposition, plan) = self
            .operations
            .prepare_release(connection, data_plane, request)?;
        Ok(DormantPendingReleaseV2 {
            file,
            disposition,
            plan,
            permit: None,
            request: deadline,
        })
    }

    /// Reconstructs the exact close-before-release plan after a definite retry.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] unless the same handle remains pending close.
    pub fn authorize_release_plan<'owner>(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        durable_limits: DurableStateLimits,
        pending: &mut DormantPendingReleaseV2,
        persisted_current: ProtectedFuseRegistrationReadbackV2<'owner>,
    ) -> Result<DormantAuthorizedReleasePlanV2<'owner>, DormantLibfuseCallbackErrorV2> {
        let current = self.require_registration_readback(
            pending.request,
            connection,
            durable_limits,
            persisted_current,
        )?;
        let plan = self.operations.retry_release(connection, pending.file)?;
        pending.plan = plan;
        Ok(DormantAuthorizedReleasePlanV2 {
            plan,
            durable_limits,
            current,
            request: pending.request,
        })
    }

    /// Completes RELEASE after any exact broker-close receipt was recorded.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for stale state or absent close permission.
    pub fn finish_release(
        &mut self,
        connection: &mut MetadataConnection<'_, '_, '_, '_>,
        pending: DormantPendingReleaseV2,
        authorization: DormantAuthorizedReleasePlanV2<'_>,
    ) -> Result<(), DormantLibfuseCallbackErrorV2> {
        if authorization.plan != ReleasePlan::ReleaseWorker || pending.plan != authorization.plan {
            return Err(OperationError::Stale.into());
        }
        self.consume_release_authorization(connection, &pending, authorization)?;
        self.operations
            .finish_release(connection, pending.file, pending.permit)
            .map_err(Into::into)
    }

    /// Records an indeterminate backing close and faults the connection.
    ///
    /// # Errors
    ///
    /// Returns the terminal ambiguity error after validating the exact handle.
    pub fn record_close_ambiguity(
        &mut self,
        connection: &mut MetadataConnection<'_, '_, '_, '_>,
        pending: DormantPendingReleaseV2,
        authorization: DormantAuthorizedReleasePlanV2<'_>,
    ) -> Result<(), DormantLibfuseCallbackErrorV2> {
        if pending.plan != authorization.plan
            || !matches!(authorization.plan, ReleasePlan::CloseBacking { .. })
        {
            return Err(OperationError::Stale.into());
        }
        self.consume_release_authorization(connection, &pending, authorization)?;
        self.operations
            .record_close_ambiguity(connection, pending.file)
            .map_err(Into::into)
    }

    /// Executes GETXATTR zero-size sizing or exact value reply semantics.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for unsupported xattrs, malformed names,
    /// stale inodes, insufficient capacity, or bounded worker failure.
    pub fn getxattr<'index>(
        &mut self,
        connection: &MetadataConnection<'_, 'index, '_, '_>,
        node_id: u64,
        name: &[u8],
        size: u32,
        budget: RequestBudget,
        durable_limits: DurableStateLimits,
        persisted_current: ProtectedFuseRegistrationReadbackV2<'_>,
    ) -> Result<ExtendedAttributeReply<'index>, OperationError> {
        let deadline = self
            .request_owner
            .admit_request(connection, self.operations.reducer_commitment())?;
        let _current = self
            .require_registration_readback(deadline, connection, durable_limits, persisted_current)
            .map_err(|_| OperationError::Integrity)?;
        let control = self.request_owner.request_control(
            deadline,
            connection,
            self.operations.reducer_commitment(),
        )?;
        self.operations
            .getxattr(connection, node_id, name, size, budget, &control)
    }

    /// Executes LISTXATTR zero-size sizing or canonical list reply semantics.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] for unsupported xattrs, stale inodes,
    /// insufficient capacity, cancellation, or bounded worker failure.
    pub fn listxattr<'scratch>(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        node_id: u64,
        size: u32,
        budget: RequestBudget,
        scratch: &'scratch mut ExtendedAttributeScratch,
        durable_limits: DurableStateLimits,
        persisted_current: ProtectedFuseRegistrationReadbackV2<'_>,
    ) -> Result<ExtendedAttributeReply<'scratch>, OperationError> {
        let deadline = self
            .request_owner
            .admit_request(connection, self.operations.reducer_commitment())?;
        let _current = self
            .require_registration_readback(deadline, connection, durable_limits, persisted_current)
            .map_err(|_| OperationError::Integrity)?;
        let control = self.request_owner.request_control(
            deadline,
            connection,
            self.operations.reducer_commitment(),
        )?;
        self.operations
            .listxattr(connection, node_id, size, budget, scratch, &control)
    }

    /// Persists and verifies the exact current registration snapshot.
    ///
    /// The fixed owner atomically replaces its connection-scoped record under
    /// an exact predecessor CAS and returns only confirmed protected readback.
    /// This method performs no persistence unless explicitly called.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid reducer state or canonical codec failure.
    /// Protected commit ambiguity is returned with exact recovery ownership.
    pub fn persist_registration_snapshot<'owner>(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        durable_limits: DurableStateLimits,
        owner: &'owner mut ProtectedFuseRegistrationOwnerV2,
        authority: DormantRegistrationPersistenceAuthorityV2,
    ) -> Result<
        ProtectedFuseRegistrationCommitResultV2<'owner>,
        DormantRegistrationPersistenceErrorV2,
    > {
        self.request_owner.revalidate(
            authority.request,
            connection,
            self.operations.reducer_commitment(),
        )?;
        let records = self.operations.registration_snapshot()?;
        let codec = connection.durable_state_codec(durable_limits)?;
        let canonical = codec.encode_registrations(&records)?;
        codec.decode_registrations(&canonical)?;
        self.request_owner.revalidate(
            authority.request,
            connection,
            self.operations.reducer_commitment(),
        )?;
        Ok(owner.replace(
            &mut self.registration_head,
            authority.request,
            connection.connection_binding(),
            self.operations.reducer_commitment(),
            canonical,
        ))
    }

    /// Reconciles an ambiguous exact registration CAS after fixed-owner reopen.
    ///
    /// Exact target readback remains available after request expiry because it
    /// performs no new effect. Any unresolved read, deadline, currentness, or
    /// encoding failure returns `RecoveryRequired` with the original custody.
    pub fn recover_registration_snapshot<'owner>(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        durable_limits: DurableStateLimits,
        owner: &'owner mut ProtectedFuseRegistrationOwnerV2,
        recovery: ProtectedFuseRegistrationRecoveryV2,
    ) -> ProtectedFuseRegistrationCommitResultV2<'owner> {
        match owner.recovery_target_is_current(&recovery) {
            Ok(true) => return owner.confirm_recovery_readback(recovery),
            Ok(false) => {}
            Err(error) => {
                return ProtectedFuseRegistrationCommitResultV2::RecoveryRequired {
                    error,
                    recovery,
                };
            }
        }

        let request = recovery.request();
        if self
            .request_owner
            .revalidate(request, connection, self.operations.reducer_commitment())
            .is_err()
        {
            return ProtectedFuseRegistrationCommitResultV2::RecoveryRequired {
                error: ProtectedFuseRegistrationErrorV2::Currentness,
                recovery,
            };
        }
        let records = match self.operations.registration_snapshot() {
            Ok(records) => records,
            Err(_) => {
                return ProtectedFuseRegistrationCommitResultV2::RecoveryRequired {
                    error: ProtectedFuseRegistrationErrorV2::Currentness,
                    recovery,
                };
            }
        };
        let codec = match connection.durable_state_codec(durable_limits) {
            Ok(codec) => codec,
            Err(_) => {
                return ProtectedFuseRegistrationCommitResultV2::RecoveryRequired {
                    error: ProtectedFuseRegistrationErrorV2::Currentness,
                    recovery,
                };
            }
        };
        let canonical = match codec.encode_registrations(&records) {
            Ok(canonical) => canonical,
            Err(_) => {
                return ProtectedFuseRegistrationCommitResultV2::RecoveryRequired {
                    error: ProtectedFuseRegistrationErrorV2::Currentness,
                    recovery,
                };
            }
        };
        if codec.decode_registrations(&canonical).is_err() {
            return ProtectedFuseRegistrationCommitResultV2::RecoveryRequired {
                error: ProtectedFuseRegistrationErrorV2::Currentness,
                recovery,
            };
        }
        if !recovery.matches(
            connection.connection_binding(),
            self.operations.reducer_commitment(),
            &canonical,
        ) || recovery.replacement_head() != self.registration_head
        {
            return ProtectedFuseRegistrationCommitResultV2::RecoveryRequired {
                error: ProtectedFuseRegistrationErrorV2::Currentness,
                recovery,
            };
        }
        if self
            .request_owner
            .revalidate(request, connection, self.operations.reducer_commitment())
            .is_err()
        {
            return ProtectedFuseRegistrationCommitResultV2::RecoveryRequired {
                error: ProtectedFuseRegistrationErrorV2::Currentness,
                recovery,
            };
        }
        owner.recover(recovery)
    }

    fn require_registration_readback<'owner>(
        &mut self,
        request: DormantFuseRequestDeadlineV2,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        durable_limits: DurableStateLimits,
        readback: ProtectedFuseRegistrationReadbackV2<'owner>,
    ) -> Result<ProtectedFuseRegistrationReadbackV2<'owner>, DormantLibfuseCallbackErrorV2> {
        self.request_owner
            .revalidate(request, connection, self.operations.reducer_commitment())?;
        let records = self.operations.registration_snapshot()?;
        let codec = connection.durable_state_codec(durable_limits)?;
        let canonical = codec.encode_registrations(&records)?;
        let readback = readback.validate(
            connection.connection_binding(),
            self.operations.reducer_commitment(),
            &canonical,
        )?;
        self.request_owner
            .revalidate(request, connection, self.operations.reducer_commitment())?;
        Ok(readback)
    }

    fn consume_open_authorization<'owner>(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        pending: &DormantPendingOpenV2<'_>,
        authorization: DormantAuthorizedOpenPlanV2<'owner>,
    ) -> Result<(), DormantLibfuseCallbackErrorV2> {
        if pending.pending.reply_plan().map_err(OperationError::from)? != authorization.plan
            || pending.request != authorization.request
        {
            return Err(OperationError::Stale.into());
        }
        self.revalidate_authorization(
            authorization.request,
            connection,
            authorization.durable_limits,
            authorization.current,
        )
    }

    fn consume_release_authorization<'owner>(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        pending: &DormantPendingReleaseV2,
        authorization: DormantAuthorizedReleasePlanV2<'owner>,
    ) -> Result<(), DormantLibfuseCallbackErrorV2> {
        if pending.plan != authorization.plan || pending.request != authorization.request {
            return Err(OperationError::Stale.into());
        }
        self.revalidate_authorization(
            authorization.request,
            connection,
            authorization.durable_limits,
            authorization.current,
        )
    }

    fn consume_rejected_open_close_authorization<'owner>(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        cleanup: &DormantRejectedOpenCloseV2<'_>,
        authorization: DormantAuthorizedRejectedOpenCloseV2<'owner>,
    ) -> Result<(), DormantLibfuseCallbackErrorV2> {
        if !cleanup.close_authorized
            || cleanup.request != authorization.request
            || self
                .operations
                .retry_rejected_open_close(&cleanup.cleanup)?
                != authorization.plan
        {
            return Err(OperationError::Stale.into());
        }
        self.revalidate_authorization(
            authorization.request,
            connection,
            authorization.durable_limits,
            authorization.current,
        )
    }

    fn revalidate_authorization(
        &mut self,
        request: DormantFuseRequestDeadlineV2,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        durable_limits: DurableStateLimits,
        current: ProtectedFuseRegistrationReadbackV2<'_>,
    ) -> Result<(), DormantLibfuseCallbackErrorV2> {
        self.request_owner
            .revalidate(request, connection, self.operations.reducer_commitment())?;
        let records = self.operations.registration_snapshot()?;
        let codec = connection.durable_state_codec(durable_limits)?;
        let canonical = codec.encode_registrations(&records)?;
        let _ = current.validate(
            connection.connection_binding(),
            self.operations.reducer_commitment(),
            &canonical,
        )?;
        self.request_owner
            .revalidate(request, connection, self.operations.reducer_commitment())?;
        Ok(())
    }

    /// Calls one explicit future libfuse installer.
    ///
    /// No installer implementation is registered in this crate.
    pub(crate) fn install_with<Installer>(
        self,
        installer: Installer,
    ) -> DormantInstalledLibfuseOperationsV2<Installer::Installed>
    where
        Installer: DormantLibfuseOperationsInstallerV2,
    {
        let mut operations = self;
        let installed = installer.install(&mut operations);
        DormantInstalledLibfuseOperationsV2 {
            operations,
            installed,
        }
    }
}

fn conceal_open_completion(
    completion: OpenCompletion<'_>,
    request: DormantFuseRequestDeadlineV2,
) -> DormantOpenCompletionV2<'_> {
    match completion {
        OpenCompletion::Published { handle } => DormantOpenCompletionV2::Published { handle },
        OpenCompletion::Rejected => DormantOpenCompletionV2::Rejected,
        OpenCompletion::RejectedCleanupRequired { cleanup } => {
            DormantOpenCompletionV2::RejectedCleanupRequired {
                cleanup: DormantRejectedWorkerCleanupV2 { cleanup, request },
            }
        }
        OpenCompletion::RejectedCloseRequired { cleanup, .. } => {
            DormantOpenCompletionV2::RejectedClosePending(DormantRejectedOpenCloseV2 {
                cleanup,
                close_authorized: false,
                request,
            })
        }
    }
}

/// Reports snapshot construction, persistence, or exact-readback failure.
#[derive(Debug, thiserror::Error)]
pub enum DormantRegistrationPersistenceErrorV2 {
    /// Live callback registration state is invalid.
    #[error("invalid live FUSE registration state: {0}")]
    Operation(#[from] OperationError),
    /// Connection-keyed canonical encoding or verification failed.
    #[error("invalid canonical FUSE registration state: {0}")]
    Durable(#[from] DurableStateError),
    /// Fixed protected persistence or exact currentness failed.
    #[error("protected FUSE registration journal failed: {0}")]
    Protected(#[from] ProtectedFuseRegistrationErrorV2),
}

/// Reports a callback-state or durable-readback validation failure.
#[derive(Debug, thiserror::Error)]
pub enum DormantLibfuseCallbackErrorV2 {
    /// Callback reducer validation failed.
    #[error("dormant libfuse callback failed: {0}")]
    Operation(#[from] OperationError),
    /// Connection-keyed snapshot encoding failed.
    #[error("dormant libfuse durable state failed: {0}")]
    Durable(#[from] DurableStateError),
    /// Fixed protected persistence or exact currentness failed.
    #[error("dormant libfuse protected registration failed: {0}")]
    Protected(#[from] ProtectedFuseRegistrationErrorV2),
}

/// Defines the future ownership boundary that may install the dormant callbacks.
///
/// Production transport code intentionally provides no implementation.
pub(crate) trait DormantLibfuseOperationsInstallerV2 {
    /// Transport-owned registration state retained beside the adapter.
    type Installed;

    /// Installs an explicitly chosen operations table around the borrowed adapter.
    fn install(self, adapter: &mut DormantLibfuseOperationsAdapterV2) -> Self::Installed;
}

/// Retains the adapter after a future operations-table installation.
///
/// The crate-owned holder makes the exact adapter passed to the installer
/// available for serialized dispatch. No production code constructs it.
#[must_use = "retain both installed transport state and its callback adapter"]
pub(crate) struct DormantInstalledLibfuseOperationsV2<Installed> {
    operations: DormantLibfuseOperationsAdapterV2,
    installed: Installed,
}

impl<Installed> DormantInstalledLibfuseOperationsV2<Installed> {
    /// Returns the installed adapter for serialized callback dispatch.
    pub(crate) const fn operations(&mut self) -> &mut DormantLibfuseOperationsAdapterV2 {
        &mut self.operations
    }

    /// Returns transport-owned installation state without separating its adapter.
    pub(crate) const fn installed(&self) -> &Installed {
        &self.installed
    }
}

fn current_boot_id() -> Result<[u8; 16], OperationError> {
    aos_sandbox_linux::boot::KernelBootId::current()
        .map(aos_sandbox_linux::boot::KernelBootId::into_bytes)
        .map_err(|_| OperationError::Integrity)
}

fn kernel_boottime_ns() -> Result<u64, OperationError> {
    let mut sample = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `sample` is a valid writable timespec for this synchronous call.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } != 0 {
        return Err(OperationError::Integrity);
    }
    let seconds = u64::try_from(sample.tv_sec).map_err(|_| OperationError::Integrity)?;
    let nanoseconds = u64::try_from(sample.tv_nsec).map_err(|_| OperationError::Integrity)?;
    if nanoseconds >= 1_000_000_000 {
        return Err(OperationError::Integrity);
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(OperationError::Integrity)
}
