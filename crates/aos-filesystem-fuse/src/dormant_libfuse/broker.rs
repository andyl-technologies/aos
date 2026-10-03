//! Protected Broker Session receipt bridge for dormant libfuse callbacks.
//!
//! Verification consumes a protected outcome gate, commit/recovery stays with
//! the fixed broker-session owner, and only confirmed protected readback can
//! reach the private backing-receipt constructors. No broker effect, service,
//! socket, descriptor, callback table, or registration store is installed.

use aos_filesystem_view::MetadataConnection;
use aos_sandbox_broker_session_protocol::CanonicalBrokerResponseEnvelopeV1;
use aos_sandbox_broker_session_security::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    DormantBrokerOutcomeVerificationV1, ProtectedBrokerOutcomeCommitRecoveryV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerOutcomeCommittedAdvancementV1,
    ProtectedBrokerOutcomeReplayV1,
};

use super::{
    DormantAuthorizedOpenPlanV2, DormantAuthorizedRejectedOpenCloseV2,
    DormantAuthorizedReleasePlanV2, DormantFuseRequestDeadlineV2, DormantLibfuseCallbackErrorV2,
    DormantLibfuseOperationsAdapterV2, DormantPendingOpenV2, DormantPendingReleaseV2,
    DormantRejectedOpenCloseV2, DormantRejectedWorkerCleanupV2,
};
use crate::file_callbacks::broker_receipts::dormant_adapter::{
    finish_pending_close_completion, finish_pending_open_completion,
    verify_pending_close_completion, verify_pending_open_completion,
};
use crate::file_callbacks::broker_receipts::{
    BrokerCompletionAdmission, CommittedBrokerReceipt, PendingBackingCloseReceipt,
    PendingBackingOpenReceipt,
};
use crate::file_callbacks::{OpenReplyPlan, RegisteredBacking, ReleasePlan};
use crate::operations::OperationError;

/// Classifies protected OPEN completion verification without minting a receipt.
#[must_use = "commit new protected progress or reconcile exact replay"]
pub enum DormantVerifiedOpenBrokerCompletionV2 {
    /// A new authenticated outcome awaits protected journal commit/readback.
    New(DormantPendingOpenBrokerCompletionV2),
    /// The outcome was already terminal and authorizes no duplicate receipt.
    ExactReplay(ProtectedBrokerOutcomeReplayV1),
}

/// Retains a verified OPEN completion until protected journal confirmation.
#[must_use = "commit this exact outcome before applying its backing receipt"]
pub struct DormantPendingOpenBrokerCompletionV2 {
    pending: PendingBackingOpenReceipt,
    advancement: aos_sandbox_broker_session_security::ProtectedBrokerOutcomePendingAdvancementV1,
    request: DormantFuseRequestDeadlineV2,
}

/// Classifies protected OPEN outcome persistence.
#[must_use = "apply committed receipt authority or retain recovery ownership"]
pub enum DormantOpenBrokerCommitResultV2 {
    /// Exact protected CAS and full readback confirmed the OPEN outcome.
    Committed(DormantCommittedOpenBrokerCompletionV2),
    /// Protected progress committed, but the local receipt binding was stale.
    ReceiptRejected {
        /// Exact callback receipt failure.
        error: OperationError,
        /// Confirmed traffic advancement, which must not be silently discarded.
        advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
    },
    /// Commit state is ambiguous and must be reopened against the same owner.
    RecoveryRequired {
        /// Redacted protected-journal error.
        error: BrokerSessionSecurityError,
        /// Paired receipt and journal recovery ownership.
        recovery: DormantPendingOpenBrokerCompletionRecoveryV2,
    },
}

/// Retains OPEN receipt verification across ambiguous protected persistence.
#[must_use = "recover through a freshly current authenticated session"]
pub struct DormantPendingOpenBrokerCompletionRecoveryV2 {
    pending: PendingBackingOpenReceipt,
    recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
    request: DormantFuseRequestDeadlineV2,
}

/// Holds an OPEN receipt unlocked by exact protected journal readback.
#[must_use = "apply the receipt to the same pending OPEN"]
pub struct DormantCommittedOpenBrokerCompletionV2 {
    committed: CommittedBrokerReceipt<crate::file_callbacks::BackingOpenReceipt>,
    request: DormantFuseRequestDeadlineV2,
}

/// Reports whether the committed OPEN receipt entered callback state.
#[must_use = "retain committed traffic authority even after terminal mismatch"]
pub enum DormantOpenReceiptApplicationV2 {
    /// The selector entered reducer state and may be snapshotted before reply.
    Applied {
        /// Reducer-authenticated selector for the future OPEN reply.
        registration: RegisteredBacking,
        /// Confirmed broker traffic advancement retained for its next use.
        advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
    },
    /// Callback state rejected the receipt; connection reconciliation is required.
    Rejected {
        /// Exact reducer failure.
        error: OperationError,
        /// Confirmed traffic advancement, which must not be silently discarded.
        advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
    },
}

impl DormantPendingOpenBrokerCompletionV2 {
    /// Commits this exact outcome through the authenticated adopted session.
    #[must_use]
    pub fn commit(
        self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> DormantOpenBrokerCommitResultV2 {
        finish_open_commit(
            connection,
            self.pending,
            session.commit_broker_outcome(self.advancement),
            self.request,
        )
    }
}

impl DormantPendingOpenBrokerCompletionRecoveryV2 {
    /// Resolves the ambiguous commit against a freshly current fixed owner.
    #[must_use]
    pub fn recover(
        self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> DormantOpenBrokerCommitResultV2 {
        finish_open_commit(
            connection,
            self.pending,
            session.recover_broker_outcome_commit(self.recovery),
            self.request,
        )
    }
}

impl DormantCommittedOpenBrokerCompletionV2 {
    /// Applies the protected receipt to the exact pending OPEN.
    #[must_use]
    pub fn apply(
        self,
        adapter: &mut DormantLibfuseOperationsAdapterV2,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        pending: &mut DormantPendingOpenV2<'_>,
    ) -> DormantOpenReceiptApplicationV2 {
        if self.request != pending.request
            || adapter
                .request_owner
                .revalidate(
                    self.request,
                    connection,
                    adapter.operations.reducer_commitment(),
                )
                .is_err()
        {
            let CommittedBrokerReceipt { advancement, .. } = self.committed;
            return DormantOpenReceiptApplicationV2::Rejected {
                error: OperationError::Stale,
                advancement,
            };
        }
        let CommittedBrokerReceipt {
            receipt,
            advancement,
        } = self.committed;
        match adapter
            .operations
            .record_backing_opened(&mut pending.pending, receipt)
        {
            Ok(registration) => DormantOpenReceiptApplicationV2::Applied {
                registration,
                advancement,
            },
            Err(error) => DormantOpenReceiptApplicationV2::Rejected { error, advancement },
        }
    }
}

/// Classifies protected CLOSE completion verification without minting a receipt.
#[must_use = "commit new protected progress or reconcile exact replay"]
pub enum DormantVerifiedCloseBrokerCompletionV2 {
    /// A new authenticated outcome awaits protected journal commit/readback.
    New(DormantPendingCloseBrokerCompletionV2),
    /// The outcome was already terminal and authorizes no duplicate receipt.
    ExactReplay(ProtectedBrokerOutcomeReplayV1),
}

/// Retains a verified CLOSE completion until protected journal confirmation.
#[must_use = "commit this exact outcome before applying its backing receipt"]
pub struct DormantPendingCloseBrokerCompletionV2 {
    pending: PendingBackingCloseReceipt,
    advancement: aos_sandbox_broker_session_security::ProtectedBrokerOutcomePendingAdvancementV1,
    request: DormantFuseRequestDeadlineV2,
}

/// Classifies protected CLOSE outcome persistence.
#[must_use = "apply committed receipt authority or retain recovery ownership"]
pub enum DormantCloseBrokerCommitResultV2 {
    /// Exact protected CAS and full readback confirmed the CLOSE outcome.
    Committed(DormantCommittedCloseBrokerCompletionV2),
    /// Protected progress committed, but the local receipt binding was stale.
    ReceiptRejected {
        /// Exact callback receipt failure.
        error: OperationError,
        /// Confirmed traffic advancement, which must not be silently discarded.
        advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
    },
    /// Commit state is ambiguous and must be reopened against the same owner.
    RecoveryRequired {
        /// Redacted protected-journal error.
        error: BrokerSessionSecurityError,
        /// Paired receipt and journal recovery ownership.
        recovery: DormantPendingCloseBrokerCompletionRecoveryV2,
    },
}

/// Retains CLOSE receipt verification across ambiguous protected persistence.
#[must_use = "recover through a freshly current authenticated session"]
pub struct DormantPendingCloseBrokerCompletionRecoveryV2 {
    pending: PendingBackingCloseReceipt,
    recovery: ProtectedBrokerOutcomeCommitRecoveryV1,
    request: DormantFuseRequestDeadlineV2,
}

/// Holds a CLOSE receipt unlocked by exact protected journal readback.
#[must_use = "apply the receipt to the same pending RELEASE"]
pub struct DormantCommittedCloseBrokerCompletionV2 {
    committed: CommittedBrokerReceipt<crate::file_callbacks::BackingCloseReceipt>,
    request: DormantFuseRequestDeadlineV2,
}

/// Reports whether the committed CLOSE receipt entered callback state.
#[must_use = "retain committed traffic authority even after terminal mismatch"]
pub enum DormantCloseReceiptApplicationV2 {
    /// The close entered reducer state and must be persisted before RELEASE.
    Applied {
        /// Confirmed broker traffic advancement retained for its next use.
        advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
    },
    /// Callback state rejected the receipt; connection reconciliation is required.
    Rejected {
        /// Exact reducer failure.
        error: OperationError,
        /// Confirmed traffic advancement, which must not be silently discarded.
        advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
    },
}

/// Reports whether a committed rejected-OPEN close entered cleanup state.
#[must_use = "persist applied cleanup or retain committed traffic authority"]
pub enum DormantRejectedOpenCloseApplicationV2<'index> {
    /// Registration cleanup entered reducer state and must be persisted.
    Applied {
        /// Worker cleanup authority gated by subsequent snapshot readback.
        cleanup: DormantRejectedWorkerCleanupV2<'index>,
        /// Confirmed broker traffic advancement retained for its next use.
        advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
    },
    /// Callback state rejected the receipt; connection reconciliation is required.
    Rejected {
        /// Exact reducer failure.
        error: OperationError,
        /// Confirmed traffic advancement, which must not be silently discarded.
        advancement: ProtectedBrokerOutcomeCommittedAdvancementV1,
    },
}

impl DormantPendingCloseBrokerCompletionV2 {
    /// Commits this exact outcome through the authenticated adopted session.
    #[must_use]
    pub fn commit(
        self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> DormantCloseBrokerCommitResultV2 {
        finish_close_commit(
            connection,
            self.pending,
            session.commit_broker_outcome(self.advancement),
            self.request,
        )
    }
}

impl DormantPendingCloseBrokerCompletionRecoveryV2 {
    /// Resolves the ambiguous commit against a freshly current fixed owner.
    #[must_use]
    pub fn recover(
        self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> DormantCloseBrokerCommitResultV2 {
        finish_close_commit(
            connection,
            self.pending,
            session.recover_broker_outcome_commit(self.recovery),
            self.request,
        )
    }
}

impl DormantCommittedCloseBrokerCompletionV2 {
    /// Applies the protected receipt to the exact pending RELEASE.
    #[must_use]
    pub fn apply(
        self,
        adapter: &mut DormantLibfuseOperationsAdapterV2,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        pending: &mut DormantPendingReleaseV2,
    ) -> DormantCloseReceiptApplicationV2 {
        if self.request != pending.request
            || adapter
                .request_owner
                .revalidate(
                    self.request,
                    connection,
                    adapter.operations.reducer_commitment(),
                )
                .is_err()
        {
            let CommittedBrokerReceipt { advancement, .. } = self.committed;
            return DormantCloseReceiptApplicationV2::Rejected {
                error: OperationError::Stale,
                advancement,
            };
        }
        let CommittedBrokerReceipt {
            receipt,
            advancement,
        } = self.committed;
        match adapter
            .operations
            .record_backing_closed(pending.file, receipt)
        {
            Ok(permit) => {
                pending.permit = Some(permit);
                pending.plan = ReleasePlan::ReleaseWorker;
                DormantCloseReceiptApplicationV2::Applied { advancement }
            }
            Err(error) => DormantCloseReceiptApplicationV2::Rejected { error, advancement },
        }
    }

    /// Applies the protected receipt to rejected-OPEN registration cleanup.
    #[must_use]
    pub fn apply_rejected_open<'index>(
        self,
        adapter: &mut DormantLibfuseOperationsAdapterV2,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        cleanup: DormantRejectedOpenCloseV2<'index>,
    ) -> DormantRejectedOpenCloseApplicationV2<'index> {
        if self.request != cleanup.request
            || adapter
                .request_owner
                .revalidate(
                    self.request,
                    connection,
                    adapter.operations.reducer_commitment(),
                )
                .is_err()
        {
            let CommittedBrokerReceipt { advancement, .. } = self.committed;
            return DormantRejectedOpenCloseApplicationV2::Rejected {
                error: OperationError::Stale,
                advancement,
            };
        }
        let CommittedBrokerReceipt {
            receipt,
            advancement,
        } = self.committed;
        if !cleanup.close_authorized {
            return DormantRejectedOpenCloseApplicationV2::Rejected {
                error: OperationError::Stale,
                advancement,
            };
        }
        match adapter
            .operations
            .record_rejected_backing_closed(cleanup.cleanup, receipt)
        {
            Ok(cleanup) => DormantRejectedOpenCloseApplicationV2::Applied {
                cleanup: DormantRejectedWorkerCleanupV2 {
                    cleanup,
                    request: self.request,
                },
                advancement,
            },
            Err(error) => DormantRejectedOpenCloseApplicationV2::Rejected { error, advancement },
        }
    }
}

impl DormantLibfuseOperationsAdapterV2 {
    /// Verifies a broker-authenticated OPEN completion under persisted pending state.
    ///
    /// # Errors
    ///
    /// Returns an error unless snapshot readback, protected gate, canonical
    /// outcome, and exact pending OPEN all agree.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_open_broker_completion(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        pending: &DormantPendingOpenV2<'_>,
        authorization: DormantAuthorizedOpenPlanV2<'_>,
        verification: DormantBrokerOutcomeVerificationV1,
        canonical_completion: &[u8],
        outcome: &CanonicalBrokerResponseEnvelopeV1,
    ) -> Result<DormantVerifiedOpenBrokerCompletionV2, DormantLibfuseCallbackErrorV2> {
        if pending.pending.reply_plan().map_err(OperationError::from)? != authorization.plan
            || pending.request != authorization.request
            || !matches!(
                authorization.plan,
                OpenReplyPlan::Passthrough {
                    backing_id: None,
                    ..
                }
            )
        {
            return Err(OperationError::Stale.into());
        }
        let request = authorization.request;
        self.consume_open_authorization(connection, pending, authorization)?;
        let (gate, context) = verification.into_parts();
        match verify_pending_open_completion(
            connection,
            &pending.pending,
            gate,
            &context,
            canonical_completion,
            outcome,
        )
        .map_err(OperationError::from)?
        {
            BrokerCompletionAdmission::New {
                pending,
                advancement,
            } => Ok(DormantVerifiedOpenBrokerCompletionV2::New(
                DormantPendingOpenBrokerCompletionV2 {
                    pending,
                    advancement,
                    request,
                },
            )),
            BrokerCompletionAdmission::ExactReplay { replay } => {
                Ok(DormantVerifiedOpenBrokerCompletionV2::ExactReplay(replay))
            }
        }
    }

    /// Verifies a broker-authenticated CLOSE completion under persisted closing state.
    ///
    /// # Errors
    ///
    /// Returns an error unless snapshot readback, protected gate, canonical
    /// outcome, and exact release plan all agree.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_close_broker_completion(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        pending: &DormantPendingReleaseV2,
        authorization: DormantAuthorizedReleasePlanV2<'_>,
        verification: DormantBrokerOutcomeVerificationV1,
        canonical_completion: &[u8],
        outcome: &CanonicalBrokerResponseEnvelopeV1,
    ) -> Result<DormantVerifiedCloseBrokerCompletionV2, DormantLibfuseCallbackErrorV2> {
        if pending.plan != authorization.plan
            || pending.request != authorization.request
            || !matches!(authorization.plan, ReleasePlan::CloseBacking { .. })
        {
            return Err(OperationError::Stale.into());
        }
        let plan = authorization.plan;
        let request = authorization.request;
        self.consume_release_authorization(connection, pending, authorization)?;
        let (gate, context) = verification.into_parts();
        match verify_pending_close_completion(
            connection,
            plan,
            gate,
            &context,
            canonical_completion,
            outcome,
        )
        .map_err(OperationError::from)?
        {
            BrokerCompletionAdmission::New {
                pending,
                advancement,
            } => Ok(DormantVerifiedCloseBrokerCompletionV2::New(
                DormantPendingCloseBrokerCompletionV2 {
                    pending,
                    advancement,
                    request,
                },
            )),
            BrokerCompletionAdmission::ExactReplay { replay } => {
                Ok(DormantVerifiedCloseBrokerCompletionV2::ExactReplay(replay))
            }
        }
    }

    /// Verifies a rejected-OPEN close under its protected one-shot plan.
    ///
    /// # Errors
    ///
    /// Returns an error unless snapshot readback, protected gate, canonical
    /// outcome, and exact rejected-OPEN close plan all agree.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_rejected_open_close_broker_completion(
        &mut self,
        connection: &MetadataConnection<'_, '_, '_, '_>,
        authorization: DormantAuthorizedRejectedOpenCloseV2<'_>,
        verification: DormantBrokerOutcomeVerificationV1,
        canonical_completion: &[u8],
        outcome: &CanonicalBrokerResponseEnvelopeV1,
    ) -> Result<DormantVerifiedCloseBrokerCompletionV2, DormantLibfuseCallbackErrorV2> {
        if !matches!(authorization.plan, ReleasePlan::CloseBacking { .. }) {
            return Err(OperationError::Stale.into());
        }
        let plan = authorization.plan;
        let request = authorization.request;
        self.revalidate_authorization(
            request,
            connection,
            authorization.durable_limits,
            authorization.current,
        )?;
        let (gate, context) = verification.into_parts();
        match verify_pending_close_completion(
            connection,
            plan,
            gate,
            &context,
            canonical_completion,
            outcome,
        )
        .map_err(OperationError::from)?
        {
            BrokerCompletionAdmission::New {
                pending,
                advancement,
            } => Ok(DormantVerifiedCloseBrokerCompletionV2::New(
                DormantPendingCloseBrokerCompletionV2 {
                    pending,
                    advancement,
                    request,
                },
            )),
            BrokerCompletionAdmission::ExactReplay { replay } => {
                Ok(DormantVerifiedCloseBrokerCompletionV2::ExactReplay(replay))
            }
        }
    }
}

fn finish_open_commit(
    connection: &MetadataConnection<'_, '_, '_, '_>,
    pending: PendingBackingOpenReceipt,
    result: ProtectedBrokerOutcomeCommitResultV1,
    request: DormantFuseRequestDeadlineV2,
) -> DormantOpenBrokerCommitResultV2 {
    match result {
        ProtectedBrokerOutcomeCommitResultV1::Committed(advancement) => {
            match finish_pending_open_completion(connection, pending, advancement) {
                Ok(committed) => DormantOpenBrokerCommitResultV2::Committed(
                    DormantCommittedOpenBrokerCompletionV2 { committed, request },
                ),
                Err((error, advancement)) => DormantOpenBrokerCommitResultV2::ReceiptRejected {
                    error: error.into(),
                    advancement,
                },
            }
        }
        ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, recovery } => {
            DormantOpenBrokerCommitResultV2::RecoveryRequired {
                error,
                recovery: DormantPendingOpenBrokerCompletionRecoveryV2 {
                    pending,
                    recovery,
                    request,
                },
            }
        }
    }
}

fn finish_close_commit(
    connection: &MetadataConnection<'_, '_, '_, '_>,
    pending: PendingBackingCloseReceipt,
    result: ProtectedBrokerOutcomeCommitResultV1,
    request: DormantFuseRequestDeadlineV2,
) -> DormantCloseBrokerCommitResultV2 {
    match result {
        ProtectedBrokerOutcomeCommitResultV1::Committed(advancement) => {
            match finish_pending_close_completion(connection, pending, advancement) {
                Ok(committed) => DormantCloseBrokerCommitResultV2::Committed(
                    DormantCommittedCloseBrokerCompletionV2 { committed, request },
                ),
                Err((error, advancement)) => DormantCloseBrokerCommitResultV2::ReceiptRejected {
                    error: error.into(),
                    advancement,
                },
            }
        }
        ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, recovery } => {
            DormantCloseBrokerCommitResultV2::RecoveryRequired {
                error,
                recovery: DormantPendingCloseBrokerCompletionRecoveryV2 {
                    pending,
                    recovery,
                    request,
                },
            }
        }
    }
}
