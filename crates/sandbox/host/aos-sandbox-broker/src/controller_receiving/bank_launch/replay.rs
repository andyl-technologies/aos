//! Projects the shared indexed cursor into the actual fixed Controller owner.
//!
//! The canonical cursor/index engine owns every native stage once. This wrapper
//! retains Controller construction privacy and its existing error projection;
//! it creates no Bank, live launch, completed purpose or caller-supplied index.

use std::collections::BTreeMap;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1;

use crate::canonical_journal::{
    CanonicalCommitReadViewV1, CanonicalReplayCursorV1, CanonicalReplayExtentDataV1,
    CanonicalReplayPrefixReadViewV1,
};
use crate::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1,
    CanonicalReplayIndexOriginalsV1,
};

use super::ControllerBankLaunchErrorV1;

type Index = BTreeMap<Vec<u8>, IdempotencyDecisionV1>;

pub(super) struct ControllerReplayIndexOriginalV1 {
    inner: CanonicalReplayIndexOriginalsV1,
}

impl ControllerReplayIndexOriginalV1 {
    pub(super) const fn new() -> Self {
        Self { inner: CanonicalReplayIndexOriginalsV1::new() }
    }

    pub(super) const fn receiving_metadata_cells_v1() -> u64 {
        // These wrappers add only byte representation, not resident namespace
        // entries. Their actual construction widths remain in the byte demand.
        CanonicalReplayIndexOriginalsV1::receiving_metadata_cells_v1()
    }

    pub(super) fn dynamic_demand_v1(
        extent: CanonicalReplayExtentDataV1,
    ) -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let invalid = || ControllerBankLaunchErrorV1::Conflict;
        let additional = std::mem::size_of::<ControllerWriterReplayV1<'_, '_>>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(2)?))
            .ok_or_else(invalid)?;
        let wrappers = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(additional).map_err(|_| invalid())?);
        CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(extent)
            .map_err(project_error)?
            .checked_add(wrappers)
            .map_err(|_| invalid())
    }

    pub(super) fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.failure()
    }
}

/// Borrows the actual fixed opening through the sole shared indexed cursor.
///
/// Its constructor stays private to the fixed Controller opening. Completing
/// this mechanical replay cannot enroll a Bank or construct a live role loan.
pub struct ControllerWriterReplayV1<'file, 'original> {
    inner: CanonicalIndexedReplayV1<'file, 'original>,
}

impl<'file, 'original> ControllerWriterReplayV1<'file, 'original> {
    pub(super) fn new(
        cursor: CanonicalReplayCursorV1<'file, 'original>,
        index: &'original mut Index,
        originals: &'original mut ControllerReplayIndexOriginalV1,
    ) -> Self {
        Self {
            inner: CanonicalIndexedReplayV1::from_supplied_data_v1(
                cursor, index, &mut originals.inner,
            ),
        }
    }

    /// Advances the same parser to its next canonical COMMIT.
    ///
    /// # Errors
    /// Preserves the original native or indexed-stage boundary classification.
    pub fn advance_once(&mut self) -> Result<bool, ControllerBankLaunchErrorV1> {
        self.inner.advance_once().map_err(project_error)
    }

    /// Borrows the actual current transaction and prior materialized map.
    pub fn current_commit(&self) -> Option<CanonicalCommitReadViewV1<'_>> {
        self.inner.current_commit()
    }

    /// Borrows the completed native prefix before the final upper semantic gate.
    pub fn completed_prefix(&self) -> Option<CanonicalReplayPrefixReadViewV1<'_>> {
        self.inner.completed_prefix()
    }

    /// Applies the original native compaction check at the same stage.
    ///
    /// # Errors
    /// Preserves native failure or indexed-stage ordering refusal.
    pub fn validate_compaction_once(&mut self) -> Result<(), ControllerBankLaunchErrorV1> {
        self.inner.validate_compaction_once().map_err(project_error)
    }

    /// Registers the actual transaction before comparing its resident index.
    ///
    /// # Errors
    /// Keeps duplicate/native/index causes in their original shared captures.
    pub fn register_and_compare_index_once(&mut self) -> Result<(), ControllerBankLaunchErrorV1> {
        self.inner.register_and_compare_index_once().map_err(project_error)
    }

    /// Prepares native materialization after the actual successful index check.
    ///
    /// # Errors
    /// Preserves missing comparison, native materialization or ordering refusal.
    pub fn prepare_change_once(&mut self) -> Result<(), ControllerBankLaunchErrorV1> {
        self.inner.prepare_change_once().map_err(project_error)
    }

    /// Applies one actual native record before its same resident index update.
    ///
    /// # Errors
    /// Retains the first native/index refusal in the actual shared original.
    pub fn apply_next_record_once(&mut self) -> Result<bool, ControllerBankLaunchErrorV1> {
        self.inner.apply_next_record_once().map_err(project_error)
    }

    /// Completes accounting while leaving the actual COMMIT resident.
    ///
    /// # Errors
    /// Preserves count, sequence and unfinished-record failures.
    pub fn finish_commit_accounting_once(&mut self) -> Result<(), ControllerBankLaunchErrorV1> {
        self.inner.finish_commit_accounting_once().map_err(project_error)
    }

    /// Disposes a completed COMMIT only after the original upper final checks.
    ///
    /// # Errors
    /// Preserves incomplete, failed or repeated disposal refusal.
    pub fn finish_commit_once(&mut self) -> Result<(), ControllerBankLaunchErrorV1> {
        self.inner.finish_commit_once().map_err(project_error)
    }

    /// Borrows the first concrete parser or index cause without reentry.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.failure()
    }
}

fn project_error(error: CanonicalIndexedReplayErrorV1) -> ControllerBankLaunchErrorV1 {
    match error {
        CanonicalIndexedReplayErrorV1::Native(cause) => ControllerBankLaunchErrorV1::Native(cause),
        CanonicalIndexedReplayErrorV1::Closed => ControllerBankLaunchErrorV1::Conflict,
    }
}
