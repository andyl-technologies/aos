//! Retains Delete replay DATA through the actual enclosing purpose bookends.
//!
//! The same private fixed reader performs replay and every owed native post.
//! Its real consuming factory alone retires native prefixes after the upper
//! purpose's clocks and posts. Supplied rows, a phase or a completed model can
//! never enter this owner. These mechanical DATA ports grant no native role.

use super::{ReadError, Reader, ResourceVector, RootFinalityReadOriginalV1,
    RootFixedNativeReadbackV1};
use super::super::completed::RootFixedCompletedReadDataV2 as Completed;
use std::mem::size_of;
use super::super::audit::{DeleteAdmissionAuditInputsDataV3 as AdmissionInputs,
    RootDeleteAuxiliaryRowDataV3 as AuxiliaryRow};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_ledger_replay::{cache_current::CacheRawJournalDataV1 as CacheRows,
    delete_graph::{DeleteDependencyGraphBaseDataV2 as GraphBase,
        DeleteGraphCapabilityDataV2 as GraphCapability},
    delete_pending::DeleteSourcePredecessorDataV2 as PredecessorData};
use aos_sandbox_protocol::{cache_state::fixed_journals::CacheJournalRecipeRoleV1 as CacheRole,
    domain_ledger::{readonly::HistoricalLedgerRowsDataV2 as HistoricalRows,
        delete_root::source_current::SourceDeleteCurrentQueryDataV1 as SourceQuery}};
use std::collections::BTreeMap;

type RowMap = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

impl RootFinalityReadOriginalV1 {
    // The containing actual owner already pays its compiled resident layout
    // and construction planes. Only these distinct new interfaces are added.
    pub(super) fn completed_transfer_control_bytes_v2() -> Option<usize> {
        let retirement_arguments = size_of::<&Self>().checked_mul(2)?
            .checked_add(size_of::<&mut Self>().checked_mul(2)?)?;
        let retirement_returns = size_of::<Result<(), ReadError>>().checked_mul(3)?
            .checked_mul(2)?;
        let boxed_transfer = size_of::<Box<Reader>>().checked_mul(3)?
            .checked_add(size_of::<Result<Completed, Box<Reader>>>().checked_mul(3)?)?
            // take/ok_or precede the factory; neither is its returned Result.
            .checked_add(size_of::<Option<Box<Reader>>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<Box<Reader>, ReadError>>().checked_mul(3)?)?;
        let completed_rows = size_of::<&Self>().checked_mul(2)?
            .checked_add(size_of::<Result<HistoricalRows<'_>, ReadError>>().checked_mul(3)?)?;
        let completed_readback = size_of::<&Self>().checked_mul(2)?
            .checked_add(size_of::<Result<RootFixedNativeReadbackV1<'_>, ReadError>>().checked_mul(3)?)?;
        let completed_raw = size_of::<&Self>().checked_mul(2)?
            .checked_add(size_of::<Result<CacheRows<'_>, ReadError>>().checked_mul(3)?)?;
        let completed_cache_quote = size_of::<(&Self, CacheRole)>().checked_mul(2)?
            .checked_add(size_of::<Result<ResourceVector, ReadError>>().checked_mul(3)?)?;
        let retired_data = size_of::<&Self>().checked_mul(2)?
            .checked_add(size_of::<bool>().checked_mul(3)?)?;
        // Each completed getter first builds its actual private Option/Result
        // borrower. These controls do not reacquire native custody.
        let completed_loans = size_of::<Option<&Completed>>().checked_mul(3)?
            .checked_add(size_of::<Result<&Completed, ReadError>>().checked_mul(3)?)?
            .checked_mul(6)?
            .checked_add(size_of::<Option<&mut Completed>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&mut Completed, ReadError>>().checked_mul(3)?)?;
        retirement_arguments.checked_add(retirement_returns)?
            .checked_add(boxed_transfer)?
            .checked_add(completed_rows)?
            .checked_add(completed_readback)?
            .checked_add(completed_raw)?
            .checked_add(completed_cache_quote)?
            .checked_add(retired_data)?
            .checked_add(completed_loans)

    }

    /// Requires the same actual reader's complete native consuming frontier.
    ///
    /// # Errors
    /// Retains incomplete native posts, failure or an earlier model transfer.
    pub fn require_reader_can_retire_v2(&self) -> Result<(), ReadError> {
        if self.completed.is_some() {
            return Err(ReadError::ProtectedBoundary);
        }
        self.reader()?.require_completed_data_v2()
    }

    /// Retires only this target's actual completed native prefixes.
    ///
    /// The actual purpose calls this after its own independently owed clocks
    /// and posts. On refusal the exact same Reader Box and every native owner
    /// are restored; no reboxing, reopening or replacement reader occurs.
    ///
    /// # Errors
    /// Refuses repetition, absent custody, incomplete posts or transferred inputs.
    pub fn retire_completed_reader_once_v2(&mut self) -> Result<(), ReadError> {
        if self.completed.is_some() {
            return Err(ReadError::ProtectedBoundary);
        }
        let reader = self.reader.take().ok_or(ReadError::ProtectedBoundary)?;
        match reader.into_completed_data_v2() {
            Ok(completed) => {
                self.completed = Some(completed);
                Ok(())
            }
            Err(reader) => {
                self.reader = Some(reader);
                Err(ReadError::ProtectedBoundary)
            }
        }
    }

    /// Reports actual native prefix disposal as accounting DATA only.
    ///
    /// This derived state is neither purpose currentness nor effect permission.
    #[must_use]
    pub fn native_prefixes_retired_data_v2(&self) -> bool {
        self.completed.is_some() && self.reader.is_none()
    }

    /// Borrows exact same-cut rows after actual native prefix disposal.
    ///
    /// # Errors
    /// Refuses absent completed DATA; performs no new observation.
    pub fn completed_historical_rows_data_v2(&self)
        -> Result<HistoricalRows<'_>, ReadError>
    {
        self.completed.as_ref().ok_or(ReadError::ProtectedBoundary)?
            .historical_rows_data_v2()
    }

    /// Borrows saved names, rows and coordinates after native disposal.
    ///
    /// # Errors
    /// Refuses absent completed DATA; does not create current native custody.
    pub fn completed_readback_v2(&self) -> Result<RootFixedNativeReadbackV1<'_>, ReadError> {
        self.completed.as_ref().ok_or(ReadError::ProtectedBoundary)?.readback_v2()
    }

    /// Borrows the exact completed Cache state without reacquiring files.
    ///
    /// # Errors
    /// Refuses absent completed state, namespaces or replay report.
    pub fn completed_cache_raw_view_v2(&self)
        -> Result<CacheRows<'_>, ReadError>
    {
        self.completed.as_ref().ok_or(ReadError::ProtectedBoundary)?.cache_raw_view_v2()
    }

    /// Prices the disposed actual Cache role's same fixed recipe.
    ///
    /// # Errors
    /// Refuses another actual role or checked native receiving overflow.
    pub fn completed_cache_fixed_demand_v2(&self,
        role: CacheRole,
    ) -> Result<ResourceVector, ReadError> {
        self.completed.as_ref().ok_or(ReadError::ProtectedBoundary)?.cache_fixed_demand_v2(role)
    }
}

impl RootFinalityReadOriginalV1 {
    /// Captures this already constructed real fixed reader at its actual UID.
    pub fn capture_once(&mut self, uid: u32) {
        match self.reader.as_mut() {
            Some(reader) => reader.capture_once(uid),
            None => { self.replay.get_or_insert(Err(ReadError::ProtectedBoundary)); }
        }
    }

    /// Audits this same reader at the actual containing purpose's frontier.
    pub fn audit_once(&mut self) {
        match self.reader.as_mut() {
            Some(reader) => reader.audit_once(),
            None => { self.replay.get_or_insert(Err(ReadError::ProtectedBoundary)); }
        }
    }

    /// Replays the same native reader without adopting or disposing its model.
    pub fn replay_once(&mut self) {
        if self.replay.is_some() {
            // The actual reader retains its original repeated-entry diagnosis.
            if let Some(reader) = self.reader.as_mut() { reader.replay_once(); }
            return;
        }
        self.replay = Some(self.replay_reader_inner_v2(None));
    }

    /// Runs the same independently owed native post at the old caller slot.
    pub fn finish_post_once(&mut self) {
        if let Some(reader) = self.reader.as_mut() { reader.finish_post_once(); }
    }

    /// Borrows the same actual reader's independently retained native post cause.
    pub fn post_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.reader.as_ref().and_then(|reader| reader.post_failure())
    }

    /// Borrows the already captured native extent's exact byte count as DATA.
    ///
    /// # Errors
    /// Refuses the same absent or failed capture without observing anything new.
    pub fn captured_prefix_native_bytes_v1(&self) -> Result<u64, ReadError> {
        Ok(self.reader()?.captured_extent_v1()?.native_bytes)
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn require_captured_v1(&self) -> Result<(), ReadError> {
        self.reader()?.require_captured_v1()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn replay_demand_v1(&self) -> Result<ResourceVector, ReadError> {
        self.reader()?.replay_demand_v1()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn additional_semantic_demand_v1(&self) -> Result<ResourceVector, ReadError> {
        self.reader()?.additional_semantic_demand_v1()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn additional_delete_graph_predecessor_demand_v2(&self)
        -> Result<ResourceVector, ReadError>
    {
        self.reader()?.additional_delete_graph_predecessor_demand_v2()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn additional_delete_preparation_semantic_demand_v3(&self) -> Result<ResourceVector, ReadError> {
        self.reader()?.additional_delete_preparation_semantic_demand_v3()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn prepare_delete_accepted_observation_v3(&mut self, expected: [u8;64]) -> Result<(), ReadError> {
        self.reader_mut()?.prepare_delete_accepted_observation_v3(expected)
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn delete_admission_comparison_demand_v3(&self, batch: &[u8], input: &[u8]) -> Result<ResourceVector, ReadError> {
        self.reader()?.delete_admission_comparison_demand_v3(batch, input)
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn prepare_delete_admission_comparison_v3(&mut self, inputs: AdmissionInputs)
        -> Result<(), ReadError> {
        self.reader_mut()?.prepare_delete_admission_comparison_v3(inputs)
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn require_delete_admission_comparison_v3(&self) -> Result<(), ReadError> {
        self.reader()?.require_delete_admission_comparison_v3()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn prepare_delete_preparation_session_observation_v3(&mut self, expected: [u8;64]) -> Result<(), ReadError> {
        self.reader_mut()?.prepare_delete_preparation_session_observation_v3(expected)
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn prepare_delete_cleanup_session_observation_v4(&mut self, expected: [u8;64]) -> Result<(), ReadError> {
        self.reader_mut()?.prepare_delete_cleanup_session_observation_v4(expected)
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn prepare_delete_completion_session_observation_v4(&mut self, expected: [u8; 64])
        -> Result<(), ReadError> {
        self.reader_mut()?.prepare_delete_completion_session_observation_v4(expected)
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn prepare_delete_current_observation_v3(&mut self,
        query: SourceQuery,
    ) -> Result<(), ReadError> {
        self.reader_mut()?.prepare_delete_current_observation_v3(query)
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn prepare_delete_terminal_observation_v4(&mut self,
        query: SourceQuery,
    ) -> Result<(), ReadError> {
        self.reader_mut()?.prepare_delete_terminal_observation_v4(query)
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn delete_preparation_native_data_v3(&self) -> Result<[u8;64], ReadError> {
        self.reader()?.delete_preparation_native_data_v3()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn delete_terminal_historical_source_native_v4(&self) -> Result<[u8;64], ReadError> {
        self.reader()?.delete_terminal_historical_source_native_v4()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn completed_delete_storage_history_rows_v3(&self)
        -> Result<(&[u8], &[u8], &[u8]), ReadError>
    {
        self.reader()?.completed_delete_storage_history_rows_v3()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn completed_delete_cleanup_history_rows_v4(&self)
        -> Result<(&[u8], &[u8], &[u8]), ReadError>
    {
        self.reader()?.completed_delete_cleanup_history_rows_v4()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn completed_delete_auxiliary_rows_v3(&self)
        -> Result<&[AuxiliaryRow], ReadError>
    {
        self.reader()?.completed_delete_auxiliary_rows_v3()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn completed_rows_data_v3(&self)
        -> Result<HistoricalRows<'_>, ReadError>
    {
        self.reader()?.completed_rows_data_v3()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn terminal_native_v1(&self) -> Result<RootFixedNativeReadbackV1<'_>, ReadError> {
        self.reader()?.terminal_native_v1()
    }

    /// Preserves the same actual reader's finite historical comparison.
    ///
    /// # Errors
    /// Retains the original native, checked representation or stage refusal.
    pub fn replay_native_v1(&self) -> Result<RootFixedNativeReadbackV1<'_>, ReadError> {
        self.reader()?.replay_native_v1()
    }

    /// Audits the same Source reader against the actual Controller comparison.
    pub fn audit_delete_graph_once_v2(&mut self,
        controller: &RowMap,
    ) {
        match self.reader.as_mut() {
            Some(reader) => reader.audit_delete_graph_once_v2(controller),
            None => { self.replay.get_or_insert(Err(ReadError::ProtectedBoundary)); }
        }
    }

    /// Transfers the actual graph census to the same original Source replay.
    ///
    /// # Errors
    /// Returns that same census after the original mismatched or repeated setup.
    pub fn replay_delete_graph_predecessor_once_v2(&mut self,
        query: SourceQuery,
        signed_native: [u8; 64],
        controller: &RowMap,
        capabilities: Vec<GraphCapability>,
    ) -> Result<(), Vec<GraphCapability>> {
        match self.reader.as_mut() {
            Some(reader) => reader.replay_delete_graph_predecessor_once_v2(
                query, signed_native, controller, capabilities,
            ),
            None => Err(capabilities),
        }
    }

    /// Borrows the same actually replayed predecessor before or after disposal.
    ///
    /// # Errors
    /// Retains the original missing or failed predecessor observation.
    pub fn delete_predecessor_data_v2(&self)
        -> Result<PredecessorData, ReadError>
    {
        match self.completed.as_ref() {
            Some(data) => data.delete_predecessor_data_v2(),
            None => self.reader()?.delete_predecessor_data_v2(),
        }
    }

    /// Prices only the graph request retained by this actual disposed Source.
    ///
    /// # Errors
    /// Refuses absent or failed actual predecessor DATA.
    pub fn completed_delete_graph_request_receiving_bytes_v2(&self) -> Result<usize, ReadError> {
        self.completed.as_ref().ok_or(ReadError::ProtectedBoundary)?
            .delete_graph_request_receiving_bytes_v2()
    }

    /// Moves only this disposed Source's own original replayed graph base.
    ///
    /// # Errors
    /// Refuses missing completion, failed comparison or repeated transfer.
    pub fn take_completed_delete_graph_base_data_v2(&mut self)
        -> Result<GraphBase, ReadError>
    {
        self.completed.as_mut().ok_or(ReadError::ProtectedBoundary)?
            .take_delete_graph_base_data_v2()
    }
}

impl RootFinalityReadOriginalV1 {
    pub(super) fn delete_port_control_bytes_v2() -> Option<usize> {
        // Every row names its concrete wrapper's argument/receiver source and
        // destination, then constructor/ABI/caller return planes. No backing
        // map, canonical engine or actual native file is billed again.
        macro_rules! planes {
            ($arguments:ty => $returned:ty) => {
                size_of::<$arguments>().checked_mul(2)?
                    .checked_add(size_of::<$returned>().checked_mul(3)?)?
            };
        }
        // The finite ports also enter the existing private reader getters;
        // these new borrowed Results are distinct from each public return.
        let reader_loans = size_of::<Result<&Reader, ReadError>>().checked_mul(3)?
            .checked_mul(18)?
            .checked_add(size_of::<Result<&mut Reader, ReadError>>().checked_mul(3)?
                .checked_mul(7)?)?
            .checked_add(size_of::<&Self>().checked_mul(2)?.checked_mul(18)?)?
            .checked_add(size_of::<&mut Self>().checked_mul(2)?.checked_mul(7)?)?;
        // post_failure's immediate predicate borrows the same Box, with no
        // captured environment; its argument and returned borrowed cause are
        // separate from the containing public getter.
        let native_cause = size_of::<&Box<Reader>>().checked_mul(2)?
            .checked_add(size_of::<Option<&(dyn std::error::Error + 'static)>>().checked_mul(3)?)?;
        // capture, audit, repeated replay, post, graph audit and graph replay
        // each create their own direct Box borrower before selecting a branch.
        let direct_reader_options = size_of::<Option<&mut Box<Reader>>>().checked_mul(3)?
            .checked_add(size_of::<&mut Box<Reader>>().checked_mul(3)?)?
            .checked_mul(6)?
            // post_failure's as_ref precedes its distinct predicate argument.
            .checked_add(size_of::<Option<&Box<Reader>>>().checked_mul(3)?)?;
        // The three missing-reader arms retain an actual Err and the separate
        // mutable Result reference returned by get_or_insert.
        let missing_reader_dispositions = size_of::<Result<(), ReadError>>().checked_mul(3)?
            .checked_add(size_of::<&mut Result<(), ReadError>>().checked_mul(3)?)?
            .checked_mul(3)?;
        let capture_once = planes!((&mut Self, u32) => ());
        let audit_once = planes!((&mut Self,) => ());
        let replay_once = planes!((&mut Self,) => ());
        let finish_post_once = planes!((&mut Self,) => ());
        let post_failure = planes!((&Self,) => Option<&(dyn std::error::Error + 'static)>);
        let captured_prefix_native_bytes_v1 = planes!((&Self,) => Result<u64, ReadError>);
        let require_captured_v1 = planes!((&Self,) => Result<(), ReadError>);
        let replay_demand_v1 = planes!((&Self,) => Result<ResourceVector, ReadError>);
        let additional_semantic_demand_v1 = planes!((&Self,) => Result<ResourceVector, ReadError>);
        let additional_delete_graph_predecessor_demand_v2 = planes!((&Self,) => Result<ResourceVector, ReadError>);
        let additional_delete_preparation_semantic_demand_v3 = planes!((&Self,) => Result<ResourceVector, ReadError>);
        let prepare_delete_accepted_observation_v3 = planes!((&mut Self, [u8;64]) => Result<(), ReadError>);
        let delete_admission_comparison_demand_v3 = planes!((&Self, &[u8], &[u8]) => Result<ResourceVector, ReadError>);
        let prepare_delete_admission_comparison_v3 = planes!((&mut Self, AdmissionInputs) => Result<(), ReadError>);
        let require_delete_admission_comparison_v3 = planes!((&Self,) => Result<(), ReadError>);
        let prepare_delete_preparation_session_observation_v3 = planes!((&mut Self, [u8;64]) => Result<(), ReadError>);
        let prepare_delete_cleanup_session_observation_v4 = planes!((&mut Self, [u8;64]) => Result<(), ReadError>);
        let prepare_delete_completion_session_observation_v4 = planes!((&mut Self, [u8; 64]) => Result<(), ReadError>);
        let prepare_delete_current_observation_v3 = planes!((&mut Self, SourceQuery) => Result<(), ReadError>);
        let prepare_delete_terminal_observation_v4 = planes!((&mut Self, SourceQuery) => Result<(), ReadError>);
        let delete_preparation_native_data_v3 = planes!((&Self,) => Result<[u8;64], ReadError>);
        let delete_terminal_historical_source_native_v4 = planes!((&Self,) => Result<[u8;64], ReadError>);
        let completed_delete_storage_history_rows_v3 = planes!((&Self,) => Result<(&[u8], &[u8], &[u8]), ReadError>);
        let completed_delete_cleanup_history_rows_v4 = planes!((&Self,) => Result<(&[u8], &[u8], &[u8]), ReadError>);
        let completed_delete_auxiliary_rows_v3 = planes!((&Self,) => Result<&[AuxiliaryRow], ReadError>);
        let completed_rows_data_v3 = planes!((&Self,) => Result<HistoricalRows<'_>, ReadError>);
        let terminal_native_v1 = planes!((&Self,) => Result<RootFixedNativeReadbackV1<'_>, ReadError>);
        let replay_native_v1 = planes!((&Self,) => Result<RootFixedNativeReadbackV1<'_>, ReadError>);
        let audit_delete_graph_once_v2 = planes!((&mut Self, &RowMap) => ());
        let replay_delete_graph_predecessor_once_v2 = planes!((&mut Self, SourceQuery, [u8; 64], &RowMap, Vec<GraphCapability>) => Result<(), Vec<GraphCapability>>);
        let delete_predecessor_data_v2 = planes!((&Self,) => Result<PredecessorData, ReadError>);
        let completed_delete_graph_request_receiving_bytes_v2 = planes!((&Self,) => Result<usize, ReadError>);
        let take_completed_delete_graph_base_data_v2 = planes!((&mut Self,) => Result<GraphBase, ReadError>);
        capture_once
            .checked_add(reader_loans)?
            .checked_add(native_cause)?
            .checked_add(direct_reader_options)?
            .checked_add(missing_reader_dispositions)?
            .checked_add(audit_once)?
            .checked_add(replay_once)?
            .checked_add(finish_post_once)?
            .checked_add(post_failure)?
            .checked_add(captured_prefix_native_bytes_v1)?
            .checked_add(require_captured_v1)?
            .checked_add(replay_demand_v1)?
            .checked_add(additional_semantic_demand_v1)?
            .checked_add(additional_delete_graph_predecessor_demand_v2)?
            .checked_add(additional_delete_preparation_semantic_demand_v3)?
            .checked_add(prepare_delete_accepted_observation_v3)?
            .checked_add(delete_admission_comparison_demand_v3)?
            .checked_add(prepare_delete_admission_comparison_v3)?
            .checked_add(require_delete_admission_comparison_v3)?
            .checked_add(prepare_delete_preparation_session_observation_v3)?
            .checked_add(prepare_delete_cleanup_session_observation_v4)?
            .checked_add(prepare_delete_completion_session_observation_v4)?
            .checked_add(prepare_delete_current_observation_v3)?
            .checked_add(prepare_delete_terminal_observation_v4)?
            .checked_add(delete_preparation_native_data_v3)?
            .checked_add(delete_terminal_historical_source_native_v4)?
            .checked_add(completed_delete_storage_history_rows_v3)?
            .checked_add(completed_delete_cleanup_history_rows_v4)?
            .checked_add(completed_delete_auxiliary_rows_v3)?
            .checked_add(completed_rows_data_v3)?
            .checked_add(terminal_native_v1)?
            .checked_add(replay_native_v1)?
            .checked_add(audit_delete_graph_once_v2)?
            .checked_add(replay_delete_graph_predecessor_once_v2)?
            .checked_add(delete_predecessor_data_v2)?
            .checked_add(completed_delete_graph_request_receiving_bytes_v2)?
            .checked_add(take_completed_delete_graph_base_data_v2)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }
}
