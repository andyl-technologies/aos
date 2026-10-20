//! Keeps the same captured append and independent posts through disposition.
//!
//! The finite Mount semantic caller completes its guards before this schedule.
//! Every byte operation is a short borrow of the existing canonical held owner;
//! an unfinished captured stage parks in that owner's already-paid DATA sink.

use std::error::Error;
use std::sync::Arc;

use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryAppendStageV1;
use aos_sandbox_broker::canonical_journal::captured::CapturedAppendPostsV1;
use aos_sandbox_broker::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendDataV1, CanonicalCoordinatorAppendV1,
};

use super::*;

pub(super) struct MountAppendIntervalOriginalV1 {
    posts: CapturedAppendPostsV1<JournalError>,
    primary: Option<Result<CommitResult, JournalError>>,
    after: Option<Result<(), JournalError>>,
    stage_disposition: Option<Result<(), JournalError>>,
    post_disposition: Option<Result<(), JournalError>>,
}

impl MountAppendIntervalOriginalV1 {
    pub(super) fn construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(3)?
            // Shared stage construction, prepare Result, retained Option and
            // both typed diagnostic returns use their canonical sole supplier.
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

/// Borrows the original body and posts while the same writer retains custody.
pub struct MountAppendFailureOriginalV1 {
    original: Arc<MountAppendIntervalOriginalV1>,
}

impl std::fmt::Debug for MountAppendFailureOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MountAppendFailureOriginalV1")
            .field("failure", &self.original.failure())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for MountAppendFailureOriginalV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.original.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the original Mount append interval is closed"),
        }
    }
}

impl Error for MountAppendFailureOriginalV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

fn take_stage_failure(
    stage: &mut CanonicalOrdinaryAppendStageV1<'_>,
    captured: bool,
) -> JournalError {
    if captured {
        return stage
            .take_captured_failure_v1()
            .map(JournalError::CapturedAppendOriginal)
            .unwrap_or(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
    }
    stage
        .take_ordinary_error_v1()
        .ok()
        .flatten()
        .map(crate::journal::MechanicalError::from)
        .map(JournalError::from)
        .unwrap_or(JournalError::Mechanical(
            crate::journal::MechanicalError::ProtectedBoundary,
        ))
}

impl MountJournalV1 {
    // The role's semantic caller invokes this only after its exact private
    // append scope and original row/floor guards have passed. There is no public
    // native commit port and no completion DATA parameter.
    pub(super) fn append_after_semantics_once_v1(
        &mut self,
        transaction: &JournalTransaction,
        scope: semantic_append::AppendScope,
    ) -> Result<CommitResult, JournalError> {
        if self.interval.is_some() {
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::Poisoned,
            ));
        }
        if let Some(owner) = &self.captured {
            self.interval = Some(Arc::new(MountAppendIntervalOriginalV1 {
                posts: owner.arm(),
                primary: None,
                after: None,
                stage_disposition: None,
                post_disposition: None,
            }));
        }

        let mut stage = None;
        let primary = self.append_body_once_v1(transaction, scope, &mut stage);
        let Some(original) = self.interval.as_mut() else {
            drop(stage);
            return primary;
        };

        let body = Arc::get_mut(original).ok_or(JournalError::Mechanical(
            crate::journal::MechanicalError::ProtectedBoundary,
        ))?;
        body.posts.mark_primary_return_v1();
        body.primary = Some(primary);
        // Independently owed work bypasses healthy-entry and semantic gates.
        body.after = Some(body.posts.after_once(self.native.read_view_v1()));
        if body.failure().is_none() {
            body.stage_disposition = Some(match stage.as_mut() {
                Some(stage) => self
                    .native
                    .finish_append_after_posts_once(stage)
                    .map_err(|_| take_stage_failure(stage, true)),
                None => Err(JournalError::Mechanical(
                    crate::journal::MechanicalError::ProtectedBoundary,
                )),
            });
        }
        drop(stage);
        if body.failure().is_none() {
            body.post_disposition = Some(body.posts.dispose());
        }
        if body.failure().is_some() {
            self.native.poison();
            return Err(JournalError::NativePostOriginal(
                MountAppendFailureOriginalV1 {
                    original: Arc::clone(original),
                },
            ));
        }

        let result = body
            .primary
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ))?;
        self.interval = None;
        Ok(result)
    }

    fn append_body_once_v1<'transaction>(
        &mut self,
        transaction: &'transaction JournalTransaction,
        scope: semantic_append::AppendScope,
        original_stage: &mut Option<CanonicalOrdinaryAppendStageV1<'transaction>>,
    ) -> Result<CommitResult, JournalError> {
        if let Some(body) = self.interval.as_mut().and_then(Arc::get_mut) {
            body.posts.before_once(self.native.read_view_v1())?;
        }
        let captured = self.captured.is_some();
        *original_stage = Some(
            match &self.captured {
                Some(owner) => self
                    .native
                    .prepare_captured_append_v1(owner.data_custody_v1(), transaction),
                None => self.native.prepare_append_once(transaction),
            }
            .map_err(|_| {
                JournalError::Mechanical(crate::journal::MechanicalError::ProtectedBoundary)
            })?,
        );
        let stage = original_stage.as_mut().ok_or(JournalError::Mechanical(
            crate::journal::MechanicalError::ProtectedBoundary,
        ))?;
        if stage.projected_materialized_bytes().is_none() {
            return Err(take_stage_failure(stage, captured));
        }

        let (commit_sequence, next_sequence) = self
            .native
            .append_coordinates_once(stage)
            .map_err(|_| take_stage_failure(stage, captured))?;
        let expected_length = self
            .native
            .expected_append_length_once(stage)
            .map_err(|_| take_stage_failure(stage, captured))?;
        // The same all-family debt fold runs after actual frame/length capture
        // and before the only durable write, just as in the original recipe.
        self.require_append_capacity_v1(
            transaction,
            scope,
            stage
                .projected_materialized_bytes()
                .ok_or(JournalError::Mechanical(
                    crate::journal::MechanicalError::ProtectedBoundary,
                ))?,
            expected_length,
            next_sequence,
        )?;
        let durable_bytes = self
            .native
            .append_prepared_once(stage)
            .map_err(|_| take_stage_failure(stage, captured))?;
        while self
            .native
            .apply_next_record_once(stage)
            .map_err(|_| take_stage_failure(stage, captured))?
        {}
        let _ = self
            .native
            .publish_append_once(stage)
            .map_err(|_| take_stage_failure(stage, captured))?;
        if !captured {
            self.native
                .finish_append_after_posts_once(stage)
                .map_err(|_| take_stage_failure(stage, false))?;
        }
        Ok(CommitResult {
            commit_sequence,
            durable_bytes,
        })
    }
}
