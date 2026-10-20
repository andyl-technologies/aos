//! Completes fixed local issuance under the original history and native writer.
//!
//! Unlike an external issuer call, no local signature escapes before this
//! same writer commits it. A lost invocation replays the actual Journal first;
//! it never recreates a positive owner from the response or a recovery row.

use super::*;
use crate::ownership_component::funding::OwnershipOperationFundingLoanV1;
use crate::local_ownership::{LocalOwnershipSigningOriginalV1, ProtectedLeaseClockV1};

/// Retains the actual captured Journal when semantic history authentication fails.
pub(crate) struct LocalHistoryCaptureFailureV1 {
    journal: Journal,
    pub(super) cause: DurableOwnershipAuthorityError,
}

impl std::fmt::Debug for LocalHistoryCaptureFailureV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("LocalHistoryCaptureFailureV1").field("cause", &self.cause).finish_non_exhaustive()
    }
}

impl std::fmt::Display for LocalHistoryCaptureFailureV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("captured local ownership history failed authentication")
    }
}

impl std::error::Error for LocalHistoryCaptureFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.cause) }
}

impl DurableOwnershipAuthority {
    /// Authenticates the domain model while retaining a refused original Journal.
    ///
    /// # Errors
    /// Returns the owning Journal and exact semantic cause for malformed,
    /// unauthenticated, disconnected or inconsistent authority history.
    pub(crate) fn from_local_original_journal(
        journal: Journal,
        verifier: OwnershipAuthorityVerifier,
    ) -> Result<Self, LocalHistoryCaptureFailureV1> {
        if !journal.ownership_namespaces_are_exact_v1() {
            return Err(LocalHistoryCaptureFailureV1 { journal,
                cause: DurableOwnershipAuthorityError::CorruptState });
        }
        let observed = OwnershipHistory::from_records(
            verifier,
            journal.records(RecordNamespace::Operation),
            journal.records(RecordNamespace::DesiredState),
            journal.records(RecordNamespace::Effect),
            journal.records(RecordNamespace::Idempotency),
        );
        match observed {
            Ok(history) => Ok(Self { journal, history, local_native: LocalNativeCustody::new() }),
            Err(cause) => Err(LocalHistoryCaptureFailureV1 { journal, cause: cause.into() }),
        }
    }
}

pub(super) struct LocalNativeCustody {
    attempts: Vec<NativeAppend>,
    pending: Option<NativeAppend>,
    closed: bool,
    growth: Option<Result<(), std::collections::TryReserveError>>,
}

struct NativeAppend {
    transaction: JournalTransaction,
    before: Option<Result<(), JournalError>>,
    prehistory: Option<Result<(), crate::journal::LocalOwnershipNativeHistoryErrorV1>>,
    native: Option<Result<crate::journal::CommitResult, JournalError>>,
    history: Option<Result<(), crate::journal::LocalOwnershipNativeHistoryErrorV1>>,
    readback: Option<Result<(), JournalError>>,
    post: Option<Result<(), JournalError>>,
    before_names: crate::ProtectedJournalCurrentnessOriginalsV1,
    prehistory_names: crate::ProtectedJournalCurrentnessOriginalsV1,
    history_names: crate::ProtectedJournalCurrentnessOriginalsV1,
    post_names: crate::ProtectedJournalCurrentnessOriginalsV1,
}

impl LocalNativeCustody {
    pub(super) fn new() -> Self {
        Self { attempts: Vec::new(), pending: None, closed: false, growth: None }
    }

    // Called only after the same prepared semantic transition was published.
    // Native success alone never disposes the fresh name descriptions.
    fn retire_published_names(&mut self) {
        if self.closed { return; }
        if let Some(attempt) = self.attempts.last_mut() {
            if matches!(attempt.before, Some(Ok(()))) && matches!(attempt.prehistory, Some(Ok(())))
                && matches!(attempt.native, Some(Ok(_))) && matches!(attempt.history, Some(Ok(())))
                && matches!(attempt.readback, Some(Ok(()))) && matches!(attempt.post, Some(Ok(())))
            {
                attempt.before_names.settle_positive_once_v1();
                attempt.prehistory_names.settle_positive_once_v1();
                attempt.history_names.settle_positive_once_v1();
                attempt.post_names.settle_positive_once_v1();
            }
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.growth.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.attempts.iter().find_map(|attempt| {
            attempt.before.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| attempt.before_names.failure().unwrap_or(cause))
                .or_else(|| attempt.prehistory.as_ref().and_then(|value| value.as_ref().err())
                    .map(|cause| cause.first_cause(&attempt.prehistory_names)))
                .or_else(|| attempt.native.as_ref().and_then(|value| value.as_ref().err())
                    .map(|cause| cause as &(dyn std::error::Error + 'static)))
                .or_else(|| attempt.history.as_ref().and_then(|value| value.as_ref().err())
                    .map(|cause| cause.first_cause(&attempt.history_names)))
                .or_else(|| attempt.readback.as_ref().and_then(|value| value.as_ref().err())
                    .map(|cause| cause as &(dyn std::error::Error + 'static)))
                .or_else(|| attempt.post.as_ref().and_then(|value| value.as_ref().err())
                    .map(|cause| attempt.post_names.failure().unwrap_or(cause)))
        }))
    }
}

fn append_local(
    journal: &mut Journal,
    custody: &mut LocalNativeCustody,
    transaction: JournalTransaction,
    funding: &mut OwnershipOperationFundingLoanV1<'_>,
) -> Result<(), DurableOwnershipAuthorityError> {
    if custody.closed {
        return Err(DurableOwnershipAuthorityError::LocalNativeClosed);
    }
    custody.pending = Some(NativeAppend {
        transaction, before: None, prehistory: None, native: None, history: None, readback: None, post: None,
        before_names: Default::default(), prehistory_names: Default::default(),
        history_names: Default::default(), post_names: Default::default(),
    });
    if custody.attempts.len() >= MAXIMUM_DURABLE_TRANSACTIONS {
        custody.closed = true;
        return Err(DurableOwnershipAuthorityError::ResourceExhausted);
    }
    let pending = custody.pending.as_ref().ok_or(DurableOwnershipAuthorityError::LocalNativeClosed)?;
    if funding.before_append_v1(journal, &pending.transaction).is_err() {
        custody.closed = true;
        return Err(DurableOwnershipAuthorityError::ResourceExhausted);
    }
    let Some(carriers) = custody.attempts.len().checked_add(1)
        .and_then(|count| count.checked_mul(std::mem::size_of::<NativeAppend>()))
        .and_then(|bytes| bytes.checked_mul(2)) else {
            custody.closed = true;
            return Err(DurableOwnershipAuthorityError::ResourceExhausted);
        };
    if funding.retain_append_v1(&pending.transaction, carriers).is_err() {
        custody.closed = true;
        return Err(DurableOwnershipAuthorityError::ResourceExhausted);
    }
    custody.growth = Some(custody.attempts.try_reserve_exact(1));
    if !matches!(custody.growth, Some(Ok(()))) {
        custody.closed = true;
        return Err(DurableOwnershipAuthorityError::ResourceExhausted);
    }
    // Park the owning transaction/slots before any append; native results are
    // placed in this original destination before readback or independent posts.
    let pending = custody.pending.take().ok_or(DurableOwnershipAuthorityError::LocalNativeClosed)?;
    custody.attempts.push(pending);
    let Some(attempt) = custody.attempts.last_mut() else {
        custody.closed = true;
        return Err(DurableOwnershipAuthorityError::LocalNativeClosed);
    };
    let mut interval = match journal.begin_local_append_interval_v1() {
        Ok(interval) => interval,
        Err(cause) => {
            attempt.before = Some(Err(cause));
            custody.closed = true;
            return Err(DurableOwnershipAuthorityError::LocalNativeClosed);
        }
    };
    attempt.before = Some(interval.observe_names(&mut attempt.before_names));
    if matches!(attempt.before, Some(Ok(()))) {
        attempt.prehistory = Some(interval.observe_history(&mut attempt.prehistory_names));
    }
    if matches!(attempt.prehistory, Some(Ok(()))) {
        attempt.native = Some(interval.append(&attempt.transaction));
        attempt.history = Some(interval.observe_history(&mut attempt.history_names));
        attempt.readback = Some(interval.require_readback(&attempt.transaction,
            attempt.native.as_ref().and_then(|value| value.as_ref().ok())));
    }
    // A Native Err does not suppress this independent held-name observation.
    attempt.post = Some(interval.observe_names(&mut attempt.post_names));
    if !matches!(attempt.before, Some(Ok(())))
        || !matches!(attempt.prehistory, Some(Ok(())))
        || !matches!(attempt.native, Some(Ok(_)))
        || !matches!(attempt.history, Some(Ok(())))
        || !matches!(attempt.readback, Some(Ok(())))
        || !matches!(attempt.post, Some(Ok(())))
    {
        custody.closed = true;
        return Err(DurableOwnershipAuthorityError::LocalNativeClosed);
    }
    Ok(())
}

impl DurableOwnershipAuthority {
    pub(crate) fn query_local(
        &mut self,
        funding: &mut OwnershipOperationFundingLoanV1<'_>,
        reference: OwnershipTransactionReferenceV1,
    ) -> Result<DurableOwnershipQueryOutcome, DurableOwnershipAuthorityError> {
        if self.local_native.closed {
            return Err(DurableOwnershipAuthorityError::LocalNativeClosed);
        }
        funding.audit_history_v1(&self.journal)
            .map_err(|_| DurableOwnershipAuthorityError::ResourceExhausted)?;
        self.query(reference)
    }

    pub(crate) fn begin_local(
        &mut self,
        funding: &mut OwnershipOperationFundingLoanV1<'_>,
        claim: &OwnershipClaimV1,
    ) -> Result<DurableOwnershipBeginOutcome, DurableOwnershipAuthorityError> {
        if self.local_native.closed {
            return Err(DurableOwnershipAuthorityError::LocalNativeClosed);
        }
        funding.audit_history_v1(&self.journal)
            .map_err(|_| DurableOwnershipAuthorityError::ResourceExhausted)?;
        match self.history.prepare_begin(claim)? {
            OwnershipHistoryBegin::Pending => Ok(DurableOwnershipBeginOutcome::Pending),
            OwnershipHistoryBegin::Replay(response) => Ok(DurableOwnershipBeginOutcome::Replay(response)),
            OwnershipHistoryBegin::Prepared(prepared, transaction) => {
                append_local(&mut self.journal, &mut self.local_native,
                    native_ownership_transaction(transaction)?, funding)?;
                prepared.publish();
                self.local_native.retire_published_names();
                Ok(DurableOwnershipBeginOutcome::Pending)
            }
        }
    }

    pub(crate) fn complete_local(
        &mut self,
        funding: &mut OwnershipOperationFundingLoanV1<'_>,
        request_id: [u8; 16],
        signer: &mut LocalOwnershipSigningOriginalV1,
        clock: &mut ProtectedLeaseClockV1,
        signing: &mut crate::local_ownership::LocalOwnershipSigningAttemptV1,
    ) -> Result<UnverifiedOwnershipLeaseResponse, DurableOwnershipAuthorityError> {
        if self.local_native.closed {
            return Err(DurableOwnershipAuthorityError::LocalNativeClosed);
        }
        funding.before_history_v1(&self.journal)
            .map_err(|_| DurableOwnershipAuthorityError::ResourceExhausted)?;
        if let Err(error) = signing.observe_native_once(&self.journal) {
            self.local_native.closed = true;
            return Err(error);
        }
        let pending = match self.history.prepare_completion(request_id)? {
            OwnershipHistoryCompletion::Replay(response) => return Ok(response),
            OwnershipHistoryCompletion::Pending(pending) => pending,
        };
        signing.capture_once(signer, &pending, clock);
        let response = match signing.response() {
            Ok(response) => response,
            Err(error) => { self.local_native.closed = true; return Err(error); }
        };
        let after = signing.after_clock()?;
        let (prepared, transaction) = match pending.authenticate(response, after) {
            Ok(prepared) => prepared,
            Err(error) => { self.local_native.closed = true; return Err(error.into()); }
        };
        append_local(&mut self.journal, &mut self.local_native,
            native_ownership_transaction(transaction)?, funding)?;
        let response = prepared.publish();
        self.local_native.retire_published_names();
        signing.retire_committed_native_names_v1();
        clock.retire_committed_clock_observations();
        Ok(response)
    }
}

