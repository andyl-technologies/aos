//! Retains Policy's entered same-Root append through independent owed posts.
//!
//! The complete interval, context and return carriers are admitted before the
//! existing post is armed or any Arc is allocated. An error parks the complete
//! primary result before owed native work; the journal keeps that same original
//! after its diagnostic is dropped. Ordinary fixed storage adds no interval.

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_broker::canonical_journal::coordinator::CanonicalCoordinatorAppendV1;
use aos_sandbox_broker::canonical_journal::{CanonicalJournalMechanicalErrorV1, CommitResult};
use aos_sandbox_broker::receiving::{RootAppendPostAdmissionErrorV1, RootJournalFinancialBorrowV1, RootWriterPostOriginalV1};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use super::super::PolicyNativeJournalErrorV1 as JournalError;
use super::append_stage::PolicyAppendStageV1;
use super::{PolicyJournalStorageV1, RootPolicyJournalV1};

pub(super) struct PolicyNativeIntervalOriginalV1 {
    post: RootWriterPostOriginalV1,
    primary: Option<Result<CommitResult, JournalError>>,
    after: Option<Result<(), JournalError>>,
    stage_disposition: Option<Result<(), JournalError>>,
    post_disposition: Option<Result<(), JournalError>>,
}

impl PolicyNativeIntervalOriginalV1 {
    // The Arc, owning errors and context are concrete compiled representations.
    // Native append/post destinations are separately supplied by the same Root
    // prepayment entry; this upper invoice does not substitute for those terms.
    fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(3)?
            .checked_add(
                super::super::append::PolicyAppendContextV1::receiving_construction_bytes_v1()?,
            )?
            .checked_add(std::mem::size_of::<usize>().checked_mul(2)?)?
            .checked_add(std::mem::align_of::<Self>().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Arc<Self>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Option<&RootJournalFinancialBorrowV1<'_>>>()
                .checked_mul(3)?)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.primary
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.post.failure())
            .or_else(|| error(&self.after))
            .or_else(|| error(&self.stage_disposition))
            .or_else(|| error(&self.post_disposition))
    }
}

impl Drop for PolicyNativeIntervalOriginalV1 {
    fn drop(&mut self) {
        // Partial or refused native work retains its original post/result graph
        // through termination. Unwind before result parking is also negative.
        if !matches!(self.primary, Some(Ok(_)))
            || !matches!(self.after, Some(Ok(())))
            || !matches!(self.stage_disposition, Some(Ok(())))
            || !matches!(self.post_disposition, Some(Ok(())))
        {
            std::process::abort();
        }
    }
}

fn error(result: &Option<Result<(), JournalError>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

/// Borrows the actual primary and owed post from the journal's retained owner.
///
/// The journal retains the same Arc. Dropping this diagnostic cannot dispose
/// the only post, erase the first cause or permit healthy append reentry.
pub struct PolicyNativePostFailureOriginalV1 {
    original: Arc<PolicyNativeIntervalOriginalV1>,
}

impl std::fmt::Debug for PolicyNativePostFailureOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("PolicyNativePostFailureOriginalV1")
            .field("failure", &self.original.failure())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for PolicyNativePostFailureOriginalV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.original.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, output),
            None => output.write_str("Policy native append interval is closed"),
        }
    }
}

impl Error for PolicyNativePostFailureOriginalV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

impl RootPolicyJournalV1 {
    pub(in crate::native) fn begin_native_append_interval_v1(
        &mut self,
        transaction: &JournalTransaction,
        borrowed_financial: Option<&RootJournalFinancialBorrowV1<'_>>,
    ) -> Result<(), JournalError> {
        if self.native_interval.is_some() {
            return Err(CanonicalJournalMechanicalErrorV1::Poisoned.into());
        }
        let PolicyJournalStorageV1::Selected { writer, financial } = &self.storage else {
            return Ok(());
        };
        let bytes = PolicyNativeIntervalOriginalV1::receiving_construction_bytes_v1()
            .ok_or_else(JournalError::geometry)?;
        let post = writer
            .prepay_native_append_post_once_v1(transaction, bytes, Some(financial), borrowed_financial)
            .map_err(|cause| match cause {
                RootAppendPostAdmissionErrorV1::Mechanical(cause) => {
                    JournalError::Mechanical(cause)
                }
                RootAppendPostAdmissionErrorV1::Native(cause) => JournalError::Root(cause),
                RootAppendPostAdmissionErrorV1::Financial(original) => {
                    JournalError::Financial(original)
                }
            })?;
        self.native_interval = Some(Arc::new(PolicyNativeIntervalOriginalV1 {
            post,
            primary: None,
            after: None,
            stage_disposition: None,
            post_disposition: None,
        }));
        Ok(())
    }

    pub(in crate::native) fn finish_native_append_interval_v1(
        &mut self,
        primary: Result<CommitResult, JournalError>,
        mut stage: Option<PolicyAppendStageV1<'_>>,
    ) -> Result<CommitResult, JournalError> {
        let Some(original) = self.native_interval.as_mut() else {
            drop(stage);
            return primary;
        };
        let body = Arc::get_mut(original).ok_or_else(JournalError::boundary)?;
        body.primary = Some(primary);

        // This is independently owed work. A primary refusal does not require
        // another healthy-entry check, loan, debit or currentness permission.
        body.after = Some(match &self.storage {
            PolicyJournalStorageV1::Selected { writer, .. } => writer
                .finish_native_post_once_v1(&mut body.post)
                .map_err(JournalError::Root),
            PolicyJournalStorageV1::Ordinary { .. } => Err(JournalError::boundary()),
        });
        if body.failure().is_none() {
            body.stage_disposition = Some(match stage.as_mut() {
                Some(stage) => self.storage.finish_append_after_posts(stage),
                None => Err(JournalError::boundary()),
            });
        }

        // A negative Root stage parks in its same native sink before exposing
        // the diagnostic. Only completed work may retire the upper interval.
        drop(stage);
        if body.failure().is_none() {
            body.post_disposition = Some(if body.post.is_complete() {
                Ok(())
            } else {
                Err(JournalError::boundary())
            });
        }
        if body.failure().is_some() {
            match &mut self.storage {
                PolicyJournalStorageV1::Selected { writer, .. } => writer.poison(),
                PolicyJournalStorageV1::Ordinary { writer } => writer.poison(),
            }
            return Err(JournalError::NativePost(
                PolicyNativePostFailureOriginalV1 {
                    original: Arc::clone(original),
                },
            ));
        }
        let value = body
            .primary
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or_else(JournalError::boundary)?;
        self.native_interval = None;
        Ok(value)
    }

    pub(super) fn retained_append_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.native_interval.as_ref()?.failure()
    }
}
