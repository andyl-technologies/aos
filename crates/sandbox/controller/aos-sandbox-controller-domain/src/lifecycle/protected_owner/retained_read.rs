//! Retains a paid read of the actual Source Lifecycle schema and selections.
//!
//! The caller admits the shared graph and these retained carriers before this
//! owner is constructed. All rows come from the actual final rooted Source
//! reader. No mutable Source owner or current-operation capability is created.

use std::error::Error;

use aos_sandbox_model::OperationId;
use aos_sandbox_protocol::domain_ledger::records::{
    ReplayProjectionRecordsCaptureV1, replay_projection_records_with_schema_capture_v1,
};
use crate::journal::JournalError;
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2;
use crate::lifecycle::protected_journal::{
    LifecycleProtectedJournalSchemaV1, LifecycleSchemaReplayCaptureV1,
};
use crate::lifecycle::{
    LifecycleCurrentOperationSelectionOriginalV1, LifecycleVerifierRecoveryOriginalV1,
};
use crate::lifecycle::{LifecycleOperationV1, LifecycleRecordDigestV1};

type Cause = Box<dyn Error + Send + Sync>;

mod stop_dispatch;
pub(crate) mod completed_stop;

pub(crate) struct LifecycleHistoricalReadOriginalV1 {
    recovery: LifecycleVerifierRecoveryOriginalV1,
    projection: ReplayProjectionRecordsCaptureV1<LifecycleProtectedJournalSchemaV1>,
    schema: LifecycleSchemaReplayCaptureV1,
    selected: LifecycleCurrentOperationSelectionOriginalV1,
    historical: LifecycleCurrentOperationSelectionOriginalV1,
    historical_result: Option<Result<(), JournalError>>,
    stop_dispatch: stop_dispatch::StopDispatchReadOriginalV1,
    returned: Option<Result<(), Cause>>,
    reentered: bool,
}

impl LifecycleHistoricalReadOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { recovery: LifecycleVerifierRecoveryOriginalV1::new(),
            projection: ReplayProjectionRecordsCaptureV1::new(),
            schema: LifecycleSchemaReplayCaptureV1::new(),
            selected: LifecycleCurrentOperationSelectionOriginalV1::new(),
            historical: LifecycleCurrentOperationSelectionOriginalV1::new(),
            historical_result: None,
            stop_dispatch: stop_dispatch::StopDispatchReadOriginalV1::new(),
            returned: None, reentered: false }
    }

    pub(crate) fn observe_once_v1(
        &mut self,
        rows: HistoricalLedgerRowsDataV2<'_>,
        parent: OperationId,
    ) -> Result<(), JournalError> {
        self.observe_rows_engine_v3(rows, Some(parent), true)?;
        self.operation_v1().map(|_|())
    }

    // Initial Stop admission can truthfully observe no Source row. Selection
    // still runs through the same owning decoder; absence is not an error or
    // an effect grant, and every malformed matching prefix remains retained.
    pub(crate) fn observe_optional_operation_once_v4(
        &mut self,
        rows: HistoricalLedgerRowsDataV2<'_>,
        parent: OperationId,
    ) -> Result<(), JournalError> {
        self.observe_rows_engine_v3(rows, Some(parent), false)
    }

    pub(crate) fn optional_operation_v4(
        &self,
    ) -> Result<Option<(&LifecycleOperationV1, LifecycleRecordDigestV1)>, JournalError> {
        self.projection_ready_v1()?;
        Ok(self.selected.completed_v1().map(|(_, operation, digest)| (operation, *digest)))
    }

    pub(crate) fn optional_selection_v4(
        &self,
    ) -> Result<Option<(&crate::lifecycle::LifecycleProtectedJournalKeyV1,
        &LifecycleOperationV1, LifecycleRecordDigestV1)>, JournalError> {
        self.projection_ready_v1()?;
        Ok(self.selected.completed_v1().map(|(key, operation, digest)| (key, operation, *digest)))
    }

    pub(crate) fn observe_rows_projection_once_v3(&mut self,
        rows: aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
    ) -> Result<(), JournalError> {
        self.observe_rows_engine_v3(rows, None, true)?;
        self.projection_ready_v1().map(|_| ())
    }

    fn observe_rows_engine_v3(&mut self,
        rows: aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
        parent: Option<OperationId>, required: bool,
    ) -> Result<(), JournalError> {
        if self.returned.is_some() {
            self.reentered=true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.returned=Some((|| {
            self.recovery.recover_from_records_once_v1(rows.all_records())?;
            let verifier=self.recovery.completed_v1().ok_or(JournalError::ProtectedBoundary)?;
            replay_projection_records_with_schema_capture_v1::<LifecycleProtectedJournalSchemaV1>(
                rows.all_records(),verifier,&mut self.projection,&mut self.schema)?;
            if let Some(parent)=parent {
                let projection=self.projection.projection().ok_or(JournalError::ProtectedBoundary)?;
                self.selected.select_once_v1(projection,verifier,parent)?;
                if required {
                    self.selected.completed_v1().ok_or(JournalError::ProtectedBoundary)?;
                }
            }
            Ok(())
        })());
        self.projection_ready_v1().map(|_|())
    }

    pub(crate) fn projection_ready_v1(&self)->Result<(
        &crate::lifecycle::protected_journal::LifecycleProtectedJournalProjectionV1,
        &crate::lifecycle::LifecycleJournalVerifierV1),JournalError> {
        if self.reentered || !matches!(self.returned,Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok((self.projection.projection().ok_or(JournalError::ProtectedBoundary)?,
            self.recovery.completed_v1().ok_or(JournalError::ProtectedBoundary)?))
    }

    /// Selects one current operation from this already paid canonical replay.
    pub(crate) fn select_current_operation_once_v3(
        &mut self,
        parent: OperationId,
    ) -> Result<(), JournalError> {
        self.projection_ready_v1()?;
        let projection = self.projection.projection().ok_or(CLOSED)?;
        let verifier = self.recovery.completed_v1().ok_or(CLOSED)?;
        self.selected.select_once_v1(projection, verifier, parent)
            .map_err(|_| CLOSED)?;
        self.operation_v1().map(|_| ())
    }

    pub(crate) fn operation_v1(&self)
        -> Result<(&LifecycleOperationV1, LifecycleRecordDigestV1), JournalError>
    {
        if self.reentered || !matches!(self.returned, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let (_, operation, digest) = self.selected.completed_v1().ok_or(JournalError::ProtectedBoundary)?;
        Ok((operation, *digest))
    }

    pub(crate) fn historical_once_v1(&mut self, parent: OperationId,
        key: &crate::lifecycle::protected_journal::LifecycleProtectedJournalKeyV1,
    ) -> Result<(), JournalError> {
        self.operation_v1()?;
        if self.historical_result.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.historical_result = Some((|| {
            let verifier = self.recovery.completed_v1().ok_or(JournalError::ProtectedBoundary)?;
            let projection = self.projection.projection().ok_or(JournalError::ProtectedBoundary)?;
            self.historical.select_key_once_v1(projection, verifier, parent, key)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            self.historical.completed_v1().ok_or(JournalError::ProtectedBoundary)?;
            Ok(())
        })());
        self.historical_operation_v1().map(|_| ())
    }

    pub(crate) fn historical_operation_v1(&self)
        -> Result<(&LifecycleOperationV1, LifecycleRecordDigestV1), JournalError> {
        if self.reentered || !matches!(self.returned, Some(Ok(())))
            || !matches!(self.historical_result, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        let (_, operation, digest) = self.historical.completed_v1().ok_or(JournalError::ProtectedBoundary)?;
        Ok((operation, *digest))
    }

    pub(crate) fn carrier_receiving_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<crate::lifecycle::LifecycleAuxiliaryRecordV1>()
                .checked_mul(2)?)?
            .checked_add(Self::observe_rows_interface_control_bytes_v2()?)
    }

    // Each actual carrier payer precedes its required/optional Rows entry.
    // This names the widened outer interface without attributing it to the
    // retired Journal relay, resident padding or dynamic replay backing.
    pub(crate) fn observe_rows_interface_control_bytes_v2() -> Option<usize> {
        std::mem::size_of::<(&mut Self, HistoricalLedgerRowsDataV2<'_>, OperationId)>()
            .checked_mul(3)?
            .checked_add(std::mem::size_of::<Result<(), JournalError>>().checked_mul(3)?)?
            .checked_add(std::mem::size_of::<Option<usize>>().checked_mul(3)?)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.recovery.failure_v1()
            .or_else(|| self.schema.failure_view_v1())
            .or_else(|| self.projection.failure().map(|cause| cause as _))
            .or_else(|| self.selected.failure_v1())
            .or_else(|| self.historical.failure_v1())
            .or_else(|| self.stop_dispatch.failure())
            .or_else(|| self.historical_result.as_ref().and_then(|value|value.as_ref().err()).map(|cause|cause as _))
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as &(dyn Error + 'static)))
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Journal;

    #[test]
    fn empty_projection_cannot_select_an_operation_and_reentry_closes_the_reader() {
        let directory = tempfile::tempdir().unwrap();
        let (journal, _) = Journal::open(directory.path().join("source-data"),
            crate::JournalLimits::default()).unwrap();
        let mut original = LifecycleHistoricalReadOriginalV1::new();

        original.observe_rows_projection_once_v3(journal.historical_read_view_v1().rows_data_v2()).unwrap();
        assert!(original.projection_ready_v1().is_ok());
        assert!(original.operation_v1().is_err());

        // An empty schema is valid historical DATA, but cannot select a parent.
        // A second observation still closes this single-use reader.
        assert!(original.observe_rows_projection_once_v3(journal.historical_read_view_v1().rows_data_v2()).is_err());
        let failure = original.failure().unwrap().to_string();
        assert!(original.observe_rows_projection_once_v3(journal.historical_read_view_v1().rows_data_v2()).is_err());

        assert_eq!(original.failure().unwrap().to_string(), failure);
        assert!(original.projection_ready_v1().is_err());
        assert!(original.operation_v1().is_err());
    }

    #[test]
    fn optional_initial_absence_is_positive_data_but_reentry_invalidates_it() {
        let directory = tempfile::tempdir().unwrap();
        let (journal, _) = Journal::open(directory.path().join("source-data"),
            crate::JournalLimits::default()).unwrap();
        let parent = OperationId::from_bytes([13; 16]);
        let mut optional = LifecycleHistoricalReadOriginalV1::new();
        let mut required = LifecycleHistoricalReadOriginalV1::new();

        optional.observe_optional_operation_once_v4(journal.historical_read_view_v1().rows_data_v2(), parent).unwrap();
        assert!(optional.optional_operation_v4().unwrap().is_none());
        assert!(optional.optional_selection_v4().unwrap().is_none());
        assert!(optional.operation_v1().is_err());
        assert!(required.observe_once_v1(journal.historical_read_view_v1().rows_data_v2(), parent).is_err());

        assert!(optional.observe_optional_operation_once_v4(journal.historical_read_view_v1().rows_data_v2(), parent).is_err());
        assert!(optional.optional_operation_v4().is_err());
        assert!(optional.optional_selection_v4().is_err());
        assert!(optional.failure().is_some());
    }

    #[test]
    fn missing_operation_and_reentry_keep_the_original_refusal() {
        let directory=tempfile::tempdir().unwrap();
        let (journal,_)=Journal::open(directory.path().join("source-data"),
            crate::JournalLimits::default()).unwrap();
        let mut original=LifecycleHistoricalReadOriginalV1::new();
        let parent=OperationId::from_bytes([11;16]);

        assert!(original.observe_once_v1(journal.historical_read_view_v1().rows_data_v2(),parent).is_err());
        let failure=original.failure().unwrap().to_string();
        assert!(original.operation_v1().is_err());
        assert!(original.observe_once_v1(journal.historical_read_view_v1().rows_data_v2(),OperationId::from_bytes([12;16])).is_err());

        assert_eq!(original.failure().unwrap().to_string(),failure);
        assert!(original.operation_v1().is_err());
    }
}
