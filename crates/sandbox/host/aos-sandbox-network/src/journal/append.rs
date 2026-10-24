//! Retains Network's same captured append body through independently owed posts.
//!
//! Framing, projection, durable write, per-record application and publication
//! remain the canonical lower stages on the same common held owner. Network
//! retains the captured sink, native interval and semantic admission frontier.

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Cause;
use aos_sandbox_broker::canonical_journal::captured::CapturedAppendPostsV1;
use aos_sandbox_broker::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendDataV1, CanonicalCoordinatorAppendV1,
};
use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryAppendStageV1;
use aos_sandbox_journal::protected_storage::ProtectedFailure;
use aos_sandbox_protocol::domain_ledger::readonly::validate_idempotency_changes;
use aos_sandbox_protocol::domain_ledger::transaction::validate_transaction;

use super::{CommitResult, Journal, JournalError, JournalTransaction};

// Only the upper role error projection remains here. The shared stage owns
// ordinary disposal or sticky captured parking before either error escapes.
fn stage_failure(stage: &mut CanonicalOrdinaryAppendStageV1<'_>, captured: bool) -> JournalError {
    if captured {
        stage
            .take_captured_failure_v1()
            .map(JournalError::CapturedAppendOriginal)
            .unwrap_or(JournalError::BOUNDARY)
    } else {
        stage
            .take_ordinary_error_v1()
            .ok()
            .flatten()
            .map(Cause::from)
            .map(JournalError::from)
            .unwrap_or(JournalError::BOUNDARY)
    }
}

pub(super) struct JournalNativeIntervalOriginalV1 {
    posts: CapturedAppendPostsV1<JournalError>,
    primary: Option<Result<CommitResult, JournalError>>,
    after: Option<Result<(), JournalError>>,
    stage_disposition: Option<Result<(), JournalError>>,
    post_disposition: Option<Result<(), JournalError>>,
}

impl JournalNativeIntervalOriginalV1 {
    pub(super) fn receiving_construction_bytes_v1() -> Option<usize> {
        // Actual interval construction, Arc return/control and common stage
        // carriers. Canonical transaction/frame backing has its own
        // shared retained-DATA supplier; no Source/Root context is constructed.
        std::mem::size_of::<Self>()
            .checked_mul(3)?
            .checked_add(CanonicalOrdinaryAppendStageV1::receiving_construction_bytes_v1()?)?
            .checked_add(std::mem::size_of::<Result<CommitResult, JournalError>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Arc<Self>>().checked_mul(3)?)?
            .checked_add(2 * std::mem::size_of::<usize>())?
            .checked_add(2 * std::mem::align_of::<Self>())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.posts
            .before_failure()
            .or_else(|| {
                self.primary
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.posts.failure())
            .or_else(|| {
                self.after
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.stage_disposition
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.post_disposition
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }
}

/// Borrows the same failed body/post while its Journal retains the original Arc.
pub struct JournalNativePostFailureOriginalV1 {
    original: Arc<JournalNativeIntervalOriginalV1>,
}

impl std::fmt::Debug for JournalNativePostFailureOriginalV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkJournalNativePostFailureOriginalV1")
            .field("failure", &self.original.failure())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for JournalNativePostFailureOriginalV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.original.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, f),
            None => f.write_str("the original Network native interval remains closed"),
        }
    }
}

impl Error for JournalNativePostFailureOriginalV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

impl Journal {
    pub(crate) fn commit(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        self.ensure_healthy()?;
        self.schema
            .before_append(self.read_view().state(), transaction)?;
        validate_transaction(transaction, self.read_view().limits())?;
        if self
            .read_view()
            .transaction_ids()
            .contains(transaction.id())
        {
            return Err(Cause::DuplicateTransaction.into());
        }
        if self.read_view().committed_transactions()
            >= self.read_view().limits().maximum_transactions
        {
            return Err(Cause::LimitExceeded("committed transaction count").into());
        }
        validate_idempotency_changes(self.read_view().idempotency_index(), transaction.records())
            .map_err(Cause::from)?;

        if let Some(owner) = &self.captured {
            self.interval = Some(Arc::new(JournalNativeIntervalOriginalV1 {
                posts: owner.arm(),
                primary: None,
                after: None,
                stage_disposition: None,
                post_disposition: None,
            }));
        }
        let mut stage = None;
        let primary = self.commit_body(transaction, &mut stage);
        if self.interval.is_none() {
            // The ordinary adapter keeps its old immediate temporary drop.
            drop(stage);
            return primary;
        }

        let view = self.held.read_view_v1();
        let original = self.interval.as_mut().ok_or(JournalError::BOUNDARY)?;
        let body = Arc::get_mut(original).ok_or(JournalError::BOUNDARY)?;
        body.posts.mark_primary_return_v1();
        body.primary = Some(primary);
        // Always owed, including after native poison or a before/body refusal.
        body.after = Some(body.posts.after_once(view));
        if body.failure().is_none() {
            body.stage_disposition = Some(match stage.as_mut() {
                Some(stage) => self
                    .held
                    .finish_append_after_posts_once(stage)
                    .map_err(|_| stage_failure(stage, true)),
                None => Err(JournalError::BOUNDARY),
            });
        }
        // A failed captured stage parks on the same permanent sink before
        // the first diagnostic can escape; a failed post keeps the whole body.
        drop(stage);
        if body.failure().is_none() {
            body.post_disposition = Some(body.posts.dispose());
        }
        if body.failure().is_some() {
            self.held.poison();
            return Err(JournalError::NativePostOriginal(
                JournalNativePostFailureOriginalV1 {
                    original: Arc::clone(original),
                },
            ));
        }
        let result = body
            .primary
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(JournalError::BOUNDARY)?;
        self.interval = None;
        Ok(result)
    }

    fn commit_body<'transaction>(
        &mut self,
        transaction: &'transaction JournalTransaction,
        stage: &mut Option<CanonicalOrdinaryAppendStageV1<'transaction>>,
    ) -> Result<CommitResult, JournalError> {
        if self.interval.is_some() {
            let view = self.held.read_view_v1();
            let body = self
                .interval
                .as_mut()
                .and_then(Arc::get_mut)
                .ok_or(JournalError::BOUNDARY)?;
            body.posts.before_once(view)?;
        }
        *stage = Some(match &self.captured {
            Some(owner) => self
                .held
                .prepare_captured_append_v1(owner.data_custody_v1(), transaction)
                .map_err(|_| JournalError::BOUNDARY)?,
            None => self
                .held
                .prepare_append_once(transaction)
                .map_err(|_| JournalError::BOUNDARY)?,
        });
        let stage = stage.as_mut().ok_or(JournalError::BOUNDARY)?;
        let captured = self.captured.is_some();
        if stage.failure().is_some() {
            return Err(stage_failure(stage, captured));
        }
        let (commit_sequence, _) = self
            .held
            .append_coordinates_once(stage)
            .map_err(|_| stage_failure(stage, captured))?;
        let _ = self
            .held
            .expected_append_length_once(stage)
            .map_err(|_| stage_failure(stage, captured))?;
        let durable_bytes = self
            .held
            .append_prepared_once(stage)
            .map_err(|_| stage_failure(stage, captured))?;
        while self
            .held
            .apply_next_record_once(stage)
            .map_err(|_| stage_failure(stage, captured))?
        {}
        let _ = self
            .held
            .publish_append_once(stage)
            .map_err(|_| stage_failure(stage, captured))?;
        if self.interval.is_none() {
            self.held.finish_append_after_posts_once(stage)
                .map_err(|_| stage_failure(stage, captured))?;
        }
        Ok(CommitResult {
            commit_sequence,
            durable_bytes,
        })
    }
}
