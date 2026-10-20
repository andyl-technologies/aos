//! Keeps the sole indexed replay inside the actual Root invocation interval.
//!
//! The real upper semantic loop runs between these unchanged mechanical stages.
//! It explicitly finishes this native interval only after its complete original
//! final checks. An unfinished return or unwind closes the SAME Root fence.

use crate::canonical_journal::{CanonicalCommitReadViewV1, CanonicalReplayPrefixReadViewV1};
use crate::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1,
};
use crate::receiving::root_invocation::RootNativeInvocationGuardV1;

use super::RootWriterErrorV1;

/// Borrows the original Root cursor and same invocation guard through semantics.
///
/// This has no public constructor or raw physical projection. Completion is
/// mechanical disposition only; it mints no RootOpen, Q04 or policy success.
pub struct RootWriterReplayV1<'owner, 'original> {
    guard: RootNativeInvocationGuardV1<'owner>,
    inner: CanonicalIndexedReplayV1<'owner, 'original>,
    finished: bool,
}

impl<'owner, 'original> RootWriterReplayV1<'owner, 'original> {
    pub(super) fn from_initial(
        guard: RootNativeInvocationGuardV1<'owner>,
        inner: CanonicalIndexedReplayV1<'owner, 'original>,
    ) -> Self {
        Self { guard, inner, finished: false }
    }

    fn project<T>(&mut self, result: Result<T, CanonicalIndexedReplayErrorV1>)
        -> Result<T, RootWriterErrorV1>
    {
        match result {
            Ok(value) => Ok(value),
            Err(cause) => {
                self.guard.refuse();
                Err(cause.into())
            }
        }
    }

    /// Advances the same canonical parser to its next actual COMMIT.
    ///
    /// # Errors
    /// Retains native/parser failure and closes the same invocation before exit.
    pub fn advance_once(&mut self) -> Result<bool, RootWriterErrorV1> {
        let result = self.inner.advance_once();
        self.project(result)
    }

    /// Borrows actual current transaction and native prior-state DATA.
    pub fn current_commit(&self) -> Option<CanonicalCommitReadViewV1<'_>> {
        self.inner.current_commit()
    }

    /// Borrows the complete native prefix for the actual final semantic checks.
    pub fn completed_prefix(&self) -> Option<CanonicalReplayPrefixReadViewV1<'_>> {
        self.inner.completed_prefix()
    }

    /// Runs the same original compaction predicate after earlier semantic gates.
    ///
    /// # Errors
    /// Keeps native/order refusal in its original capture and closes invocation.
    pub fn validate_compaction_once(&mut self) -> Result<(), RootWriterErrorV1> {
        let result = self.inner.validate_compaction_once();
        self.project(result)
    }

    /// Registers the actual transaction before its same resident index check.
    ///
    /// # Errors
    /// Preserves exact native/index causes, closing before any further entry.
    pub fn register_and_compare_index_once(&mut self) -> Result<(), RootWriterErrorV1> {
        let result = self.inner.register_and_compare_index_once();
        self.project(result)
    }

    /// Prepares actual native materialization at its original ordered frontier.
    ///
    /// # Errors
    /// Retains missing/failed comparison or native materialization refusal.
    pub fn prepare_change_once(&mut self) -> Result<(), RootWriterErrorV1> {
        let result = self.inner.prepare_change_once();
        self.project(result)
    }

    /// Applies one original native record before its same actual index update.
    ///
    /// # Errors
    /// Keeps the native/index failure resident before closing invocation.
    pub fn apply_next_record_once(&mut self) -> Result<bool, RootWriterErrorV1> {
        let result = self.inner.apply_next_record_once();
        self.project(result)
    }

    /// Finishes accounting while keeping the actual COMMIT for upper checks.
    ///
    /// # Errors
    /// Preserves the original count, sequence or incomplete-record refusal.
    pub fn finish_commit_accounting_once(&mut self) -> Result<(), RootWriterErrorV1> {
        let result = self.inner.finish_commit_accounting_once();
        self.project(result)
    }

    /// Disposes the accounted COMMIT after its real upper final checks.
    ///
    /// # Errors
    /// Preserves native/order failure; it never finishes the enclosing window.
    pub fn finish_commit_once(&mut self) -> Result<(), RootWriterErrorV1> {
        let result = self.inner.finish_commit_once();
        self.project(result)
    }

    /// Ends the native borrow after the sole upper loop's complete final checks.
    ///
    /// This carries no semantic receipt or caller success value. The trusted
    /// coordinator calls it at its actual positive final window; only native
    /// complete-prefix/failure checks are repeated here as local disposition.
    ///
    /// # Errors
    /// Refuses missing/failed/incomplete native prefix or repeated disposition.
    pub fn finish_semantic_window_once(&mut self) -> Result<(), RootWriterErrorV1> {
        if self.finished || self.inner.failure().is_some() || self.inner.completed_prefix().is_none() {
            self.guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        self.finished = true;
        Ok(())
    }

    /// Borrows the first actual shared parser/index cause without resampling.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.failure()
    }
}

impl Drop for RootWriterReplayV1<'_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            self.guard.refuse();
        }
    }
}
