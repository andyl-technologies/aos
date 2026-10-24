//! Checks complete selected Source auxiliary history from Root's own native walk.
//!
//! Source's signed Batch2 observation is intentionally narrower. This owner
//! independently applies the existing full Operation/Batch atomic-join engine
//! to actual native transaction groups and compares its final accepted facts.

use aos_sandbox_policy::native::RootFinalityReadOriginalV1 as Target;
use crate::journal::historical_observation::root_readonly_error_v1 as project_read;
use crate::journal::JournalError;
use crate::lifecycle::{
    LifecycleAuxiliaryDecodeOriginalV1, LifecycleAuxiliaryHistoryV1, LifecycleAuxiliaryRecordV1,
    LifecycleHistoricalReadOriginalV1, LifecycleOperationV1, LifecyclePhaseV1,
    LifecycleSemanticCommitFactV1, retained_lifecycle_replay_receiving_demand_v1,
};

use aos_sandbox_model::{OperationId, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::lifecycle_auxiliary::borrow_lifecycle_auxiliary_member_data_v1;
use std::{error::Error, mem::size_of};

#[derive(Default)]
pub(in crate::policy_compiler::delete_root) struct RootDeletePreparationSourceModelsV3 {
    current: Option<LifecycleHistoricalReadOriginalV1>,
    auxiliary: LifecycleAuxiliaryDecodeOriginalV1,
    history: Option<LifecycleAuxiliaryHistoryV1>,
    pending: Vec<LifecycleAuxiliaryRecordV1>,
    join: Option<
        Result<(), aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError>,
    >,
    returned: Option<Result<(), Box<dyn Error>>>,
    entered: bool,
}

impl RootDeletePreparationSourceModelsV3 {
    pub(in crate::policy_compiler::delete_root) fn receiving_demand_v3(
        reader: &Target,
    ) -> Result<ResourceVector, JournalError> {
        let current = reader.completed_rows_data_v3().map_err(project_read)?;
        let mut demand = retained_lifecycle_replay_receiving_demand_v1(current.all_records())
            .ok_or(JournalError::JournalTooLarge)?;
        let rows = reader.completed_delete_auxiliary_rows_v3().map_err(project_read)?;
        if rows.len() > crate::lifecycle::MAXIMUM_LIFECYCLE_AUXILIARY_RECORDS {
            return Err(JournalError::JournalTooLarge);
        }
        // The history retains each incoming model in records/latest/operation
        // indices. Sum the same complete canonical model quote per actual row;
        // a latest-row peak would lose replaced readiness graphs here.
        for row in rows {
            let model = retained_lifecycle_replay_receiving_demand_v1(std::iter::once((
                crate::RecordNamespace::DesiredState,
                row.key.as_slice(),
                row.value.as_slice(),
            )))
            .ok_or(JournalError::JournalTooLarge)?;
            demand = demand
                .checked_add(model)
                .map_err(|_| JournalError::JournalTooLarge)?;
        }
        let fixed = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * size_of::<LifecycleAuxiliaryHistoryV1>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        demand
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn observe_once_v3(
        &mut self,
        reader: &Target,
        parent: OperationId,
        expected_batch: &[u8],
        accepted_controller: &[u8; 64],
        source_native: &[u8; 64],
    ) -> Result<(), JournalError> {
        if self.entered {
            return Err(JournalError::ProtectedBoundary);
        }
        self.entered = true;
        self.returned = Some(self.observe_inner_v3(
            reader,
            parent,
            expected_batch,
            accepted_controller,
            source_native,
            None,
        ));
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn observe_inner_v3(
        &mut self,
        reader: &Target,
        parent: OperationId,
        expected_batch: &[u8],
        accepted_controller: &[u8; 64],
        source_native: &[u8; 64],
        terminal: Option<(&Self, [u8; 32])>,
    ) -> Result<(), Box<dyn Error>> {
        let invalid = || JournalError::StaleAuthoritySnapshot;
        let rows = reader.completed_delete_auxiliary_rows_v3().map_err(project_read)?;
        if rows.is_empty()
            || rows.last().map(|row| &row.native) != Some(source_native)
            || reader.delete_preparation_native_data_v3().map_err(project_read)? != *source_native
        {
            return Err(invalid().into());
        }
        self.current = Some(LifecycleHistoricalReadOriginalV1::new());
        self.current
            .as_mut()
            .ok_or_else(invalid)?
            .observe_rows_projection_once_v3(reader.completed_rows_data_v3().map_err(project_read)?)?;
        let (projection, verifier) = self
            .current
            .as_ref()
            .ok_or_else(invalid)?
            .projection_ready_v1()?;
        let _ = projection;
        self.history = Some(LifecycleAuxiliaryHistoryV1::under_verification(
            verifier.replay(),
        ));
        let mut transaction = None;
        for row in rows {
            if transaction.is_some_and(|saved| saved != row.transaction) {
                self.finish_join_v3()?;
            }
            transaction = Some(row.transaction);
            let frame =
                borrow_lifecycle_auxiliary_member_data_v1(&row.key, &row.value, &row.transaction)?;
            // The complete decoder still owns replay-brand/model checks. Native
            // membership is independently fixed by the real captured COMMIT.
            let (_, verifier) = self
                .current
                .as_ref()
                .ok_or_else(invalid)?
                .projection_ready_v1()?;
            self.auxiliary
                .decode_from_protected_envelope_once(frame.encoded_bytes_v1(), verifier.replay())?;
            let record = self.auxiliary.take_completed_once().ok_or_else(invalid)?;
            if record.atomic_join().as_bytes() != &row.transaction || frame.operation != parent {
                return Err(invalid().into());
            }
            self.pending.push(record);
            // Only a wholly successful pure leaf is reused. Its actual complete
            // model remains in the pending group until the same full join checks.
            self.auxiliary = LifecycleAuxiliaryDecodeOriginalV1::new();
        }
        self.finish_join_v3()?;
        let current = self.operation_v3(parent)?;
        let Some(commit) = current.method_semantic_commit() else {
            return Err(invalid().into());
        };
        let LifecycleSemanticCommitFactV1::DeleteBatch { batch, .. } = commit.facts() else {
            return Err(invalid().into());
        };
        if (terminal.is_none() && current.phase() != LifecyclePhaseV1::Committed)
            || !current.has_delete_batch_layout()
            || batch.state() != 2
            || batch.batch().as_bytes() != expected_batch
            || batch.native_proof() != accepted_controller
        {
            return Err(invalid().into());
        }
        if let Some((accepted, physical)) = terminal {
            crate::lifecycle::delete_pending::require_terminal_operation_data_v4(
                accepted.operation_v3(parent)?, current, physical)?;
        }
        Ok(())
    }

    pub(in crate::policy_compiler::delete_root) fn observe_terminal_once_v4(
        &mut self,
        reader: &Target,
        parent: OperationId,
        expected_batch: &[u8],
        accepted_controller: &[u8; 64],
        source_native: &[u8; 64],
        accepted: &Self,
        physical: [u8; 32],
    ) -> Result<(), JournalError> {
        if self.entered { return Err(JournalError::ProtectedBoundary); }
        self.entered = true;
        self.returned = Some(self.observe_inner_v3(reader, parent, expected_batch,
            accepted_controller, source_native, Some((accepted, physical))));
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    fn finish_join_v3(&mut self) -> Result<(), JournalError> {
        self.pending
            .sort_unstable_by_key(LifecycleAuxiliaryRecordV1::kind);
        let history = self
            .history
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.join = Some(history.apply_atomic_join(&self.pending));
        if !matches!(self.join, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.pending.clear();
        Ok(())
    }

    fn operation_v3(&self, parent: OperationId) -> Result<&LifecycleOperationV1, JournalError> {
        self.history
            .as_ref()
            .and_then(|history| history.operations().operation(parent))
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(in crate::policy_compiler::delete_root) fn current_lifecycle_data_v5(&self)
        -> Result<&LifecycleHistoricalReadOriginalV1, JournalError> {
        if self.failure().is_some() || !matches!(self.returned, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let current = self.current.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        current.projection_ready_v1()?;
        Ok(current)
    }

    pub(in crate::policy_compiler::delete_root) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.current
            .as_ref()
            .and_then(|current| current.failure())
            .or_else(|| self.auxiliary.failure_view_v1())
            .or_else(|| {
                self.join
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.returned
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause.as_ref())
            })
    }
}
