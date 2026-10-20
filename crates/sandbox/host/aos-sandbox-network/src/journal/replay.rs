//! Drives the same canonical parser at Network's existing semantic frontiers.

use std::error::Error;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Cause;
use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

use super::schema::Schema;

pub(super) struct NetworkReplayOriginalV1 {
    native: Option<Result<(), CanonicalIndexedReplayErrorV1>>,
    semantic: Option<Result<(), Cause>>,
    native_selected: bool,
    entered: bool,
}

impl NetworkReplayOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            native: None,
            semantic: None,
            native_selected: false,
            entered: false,
        }
    }

    pub(super) fn observe_once(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        schema: Schema,
        limits: JournalLimits,
    ) -> Result<(), ()> {
        if self.entered {
            return Err(());
        }
        self.entered = true;
        self.semantic = Some(self.observe_body(cursor, schema, limits));
        // Latch now: a later independent name/tail post cannot replace a
        // preceding semantic refusal with its own newly retained cause.
        self.native_selected = cursor.failure().is_some();
        if matches!(self.semantic, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn native_step<T>(
        &mut self,
        result: Result<T, CanonicalIndexedReplayErrorV1>,
    ) -> Result<T, Cause> {
        match result {
            Ok(value) => {
                self.native = Some(Ok(()));
                Ok(value)
            }
            Err(cause) => {
                self.native = Some(Err(cause));
                Err(Cause::ProtectedBoundary)
            }
        }
    }

    fn observe_body(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        schema: Schema,
        limits: JournalLimits,
    ) -> Result<(), Cause> {
        let mut compacted_prefix = false;
        loop {
            let reached = self.native_step(cursor.advance_once())?;
            if !reached {
                break;
            }
            let current = cursor.current_commit().ok_or(Cause::ProtectedBoundary)?;
            schema.require_transaction(current.transaction())?;
            let compacted = current
                .compaction_candidate_before_validation()
                .ok_or(Cause::ProtectedBoundary)?;

            // Closed Network keys exclude Delete/Root/Bank selectors, except
            // raw32 lifecycle keys covered by the canonical Source predicates.
            // Full MAC/model replay remains at the old typed-catalog frontier.
            if compacted {
                self.native_step(cursor.validate_compaction_once())?;
                compacted_prefix = true;
            } else {
                let current = cursor.current_commit().ok_or(Cause::ProtectedBoundary)?;
                if compacted_prefix {
                    schema.finish_prefix(current.prior_state(), true)?;
                    compacted_prefix = false;
                }
                schema.before_logical(current.prior_state(), current.transaction(), limits)?;
                self.native_step(cursor.validate_compaction_once())?;
            }

            self.native_step(cursor.register_and_compare_index_once())?;
            self.native_step(cursor.prepare_change_once())?;
            // Query/first-Source capacity after-materialization hooks are
            // unreachable under these checked keys. Apply each actual record
            // before its existing idempotency index update, then account COMMIT.
            while self.native_step(cursor.apply_next_record_once())? {}
            self.native_step(cursor.finish_commit_accounting_once())?;
            // Bank/provisioning companion selectors are excluded at this same
            // COMMIT; no whole-model MAC check is moved into this native stage.
            self.native_step(cursor.finish_commit_once())?;
        }
        let complete = cursor.completed_prefix().ok_or(Cause::ProtectedBoundary)?;
        schema.finish_prefix(complete.state(), compacted_prefix)
    }

    pub(super) fn into_ordinary_error(self) -> Option<Cause> {
        self.native
            .and_then(Result::err)
            .and_then(|cause| match cause {
                CanonicalIndexedReplayErrorV1::Native(cause) => {
                    Some(Cause::from_ordinary_native_v1(cause))
                }
                CanonicalIndexedReplayErrorV1::Closed => None,
            })
            .or_else(|| self.semantic.and_then(Result::err))
    }

    pub(super) fn is_complete(&self) -> bool {
        self.entered && matches!(self.semantic, Some(Ok(())))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.native_selected {
            self.native
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _)
        } else {
            self.semantic
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _)
        }
    }
}
