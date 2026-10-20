//! Captures and replays fixed Root journal views through one native engine.
//!
//! Root retains its own read-only files and names under the same R. This is
//! receiving and replay DATA only: it takes no writer lock and cannot
//! authenticate an outcome, issue U or grant a live Session.

use std::collections::BTreeMap;
use std::error::Error;
use aos_sandbox_ledger_replay::cold::{ColdReplayOriginalV1, ColdReplayClosedV1};
use aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1;
use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryReadonlyOpeningV1, CanonicalOrdinaryReadonlyReplayDataV1,
};
use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::{CanonicalIndexedReplayV1,
    CanonicalIndexedReplayErrorV1, CanonicalReplayIndexOriginalsV1};
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1;
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use aos_sandbox_model::RecordNamespace;
use std::fs::Metadata;
use std::path::Path;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::{
    ReadOnlyJournalNameWitness, ReadOnlyJournalNamesOriginalsV1,
};
use crate::journal::{JournalError, ProtectedJournalPreopenReplayExtentV1,
    protected_journal_preopen_replay_extent_for_prefix_v1};


use aos_sandbox_linux::signer_mount::{RootReadonlyViewV1,
    SignerMountReadbackAttemptV1, SignerMountReadbackClosedV1};

mod completed;
mod stopped_history;
pub(crate) use stopped_history::RootCreateStoppedHistoricalOriginalV2;
use stopped_history::RootStoppedHistoryOriginalV2;
pub(crate) use completed::RootFixedCompletedReadDataV2;

enum DeletePreparationObservationV3 {
    Controller(aos_sandbox_ledger_replay::delete_pending::DeleteSelectedCommitReplayDataV3),
    Storage(aos_sandbox_ledger_replay::delete_pending::DeleteSelectedCommitReplayDataV3),
    Source {
        query: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1,
        purpose: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentPurposeDataV3,
        observer: aos_sandbox_ledger_replay::delete_pending::SourceDeletePendingReplayDataV1,
    },
}

impl DeletePreparationObservationV3 {
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self { Self::Controller(observer) | Self::Storage(observer) => observer.failure_v3(),
            Self::Source {observer,..} => observer.failure() }
    }
}

type Slot<T> = Option<Result<T, JournalError>>;

pub(crate) struct RootFixedNativeReadOriginalsV1 {
    target: RootFixedNativeTargetV1,
    original_uid: u32,
    mount_before: SignerMountReadbackAttemptV1,
    mount_before_result: Option<Result<(), SignerMountReadbackClosedV1>>,
    mount_after: SignerMountReadbackAttemptV1,
    mount_after_result: Option<Result<(), SignerMountReadbackClosedV1>>,
    mount_binding: Slot<()>,
    audit: crate::journal::RootControllerReadonlyGeometryAuditV1,
    cold: ColdReplayOriginalV1,
    cold_result: Option<Result<(), ColdReplayClosedV1>>,
    stopped_history: Option<RootStoppedHistoryOriginalV2>,
    delete_preparation: Option<DeletePreparationObservationV3>,
    delete_predecessor: Option<aos_sandbox_ledger_replay::delete_pending::DeleteSourcePredecessorReplayDataV2>,
    opening: CanonicalOrdinaryReadonlyOpeningV1<JournalError>,
    witness: Option<ReadOnlyJournalNameWitness>,
    before: ReadOnlyJournalNamesOriginalsV1<JournalError>,
    extent: Slot<ProtectedJournalPreopenReplayExtentV1>,
    primary: Slot<()>,
    replay_result: Option<Result<(), CanonicalIndexedReplayErrorV1>>,
    replay_position: Option<(u64, u64)>,
    marked_transaction: Option<crate::journal::JournalTransaction>,
    after: ReadOnlyJournalNamesOriginalsV1<JournalError>,
    after_metadata: Option<std::io::Result<Metadata>>,
    after_length: Slot<()>,
    entered: bool,
    model_transferred: bool,
    closed: bool,
}

impl Default for RootFixedNativeReadOriginalsV1 {
    fn default() -> Self {
        Self {
            target: RootFixedNativeTargetV1::StorageSession,
            original_uid: 0,
            mount_before: SignerMountReadbackAttemptV1::new(), mount_before_result: None,
            mount_after: SignerMountReadbackAttemptV1::new(), mount_after_result: None,
            mount_binding: None,
            audit: crate::journal::RootControllerReadonlyGeometryAuditV1::new(),
            cold: ColdReplayOriginalV1::new(), cold_result: None, stopped_history: None, delete_preparation: None, delete_predecessor: None,
            opening: CanonicalOrdinaryReadonlyOpeningV1::new(),
            witness: Default::default(),
            before: Default::default(),
            extent: Default::default(),
            primary: Default::default(),
            replay_result: Default::default(),
            replay_position: Default::default(),
            marked_transaction: None,
            after: Default::default(),
            after_metadata: Default::default(),
            after_length: Default::default(),
            entered: Default::default(),
            model_transferred: false,
            closed: Default::default(),
        }
    }
}

impl RootFixedNativeReadOriginalsV1 {
    // Selects fixed mechanical DATA only; each actual R purpose owns admission.
    pub(crate) fn controller_current_v1() -> Self {
        Self { target: RootFixedNativeTargetV1::ControllerCurrent, ..Self::default() }
    }

    pub(crate) fn controller_current_fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        Self::fixed_target_demand_v1(RootFixedNativeTargetV1::ControllerCurrent)
    }

    pub(crate) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        Self::fixed_target_demand_v1(RootFixedNativeTargetV1::StorageSession)
    }

    pub(crate) fn host_session_v2() -> Self {
        Self {
            target: RootFixedNativeTargetV1::HostSession,
            ..Self::default()
        }
    }

    pub(crate) fn host_session_fixed_demand_v2() -> Result<ResourceVector, JournalError> {
        Self::fixed_target_demand_v1(RootFixedNativeTargetV1::HostSession)
    }

    pub(crate) fn mount_session_v2() -> Self {
        Self {
            target: RootFixedNativeTargetV1::MountSession,
            ..Self::default()
        }
    }

    pub(crate) fn mount_session_fixed_demand_v2() -> Result<ResourceVector, JournalError> {
        Self::fixed_target_demand_v1(RootFixedNativeTargetV1::MountSession)
    }

    pub(crate) fn network_session_v2() -> Self {
        Self {
            target: RootFixedNativeTargetV1::NetworkSession,
            ..Self::default()
        }
    }

    pub(crate) fn network_session_fixed_demand_v2() -> Result<ResourceVector, JournalError> {
        Self::fixed_target_demand_v1(RootFixedNativeTargetV1::NetworkSession)
    }

    // This selects only the fixed Source native recipe. The genuine current
    // R purpose still pays, validates its models and owns all independent posts.
    pub(crate) fn source_current_v1() -> Self {
        Self { target: RootFixedNativeTargetV1::SourceCurrent, ..Self::default() }
    }

    pub(crate) fn source_current_fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        Self::fixed_target_demand_v1(RootFixedNativeTargetV1::SourceCurrent)
    }

    pub(crate) fn source_release_fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        Self::fixed_target_demand_v1(RootFixedNativeTargetV1::SourceRelease)
    }

    pub(crate) fn cache_release_fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        Self::fixed_target_demand_v1(RootFixedNativeTargetV1::CacheRelease)
    }

    pub(crate) fn source_release_v1() -> Self {
        Self { target: RootFixedNativeTargetV1::SourceRelease, ..Self::default() }
    }

    pub(crate) fn cache_release_v1() -> Self {
        Self { target: RootFixedNativeTargetV1::CacheRelease, ..Self::default() }
    }

    pub(crate) fn cache_current_v1(role: aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1) -> Self {
        Self { target: RootFixedNativeTargetV1::CacheCurrent(role), ..Self::default() }
    }

    pub(crate) fn cache_current_fixed_demand_v1(role: aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1)
        -> Result<ResourceVector, JournalError> {
        Self::fixed_target_demand_v1(RootFixedNativeTargetV1::CacheCurrent(role))
    }

    fn fixed_target_demand_v1(target: RootFixedNativeTargetV1) -> Result<ResourceVector, JournalError> {
        let (root, name, _) = target.recipe();
        let invalid = || JournalError::JournalTooLarge;
        let anchors = Path::new(root).components()
            .filter(|part| matches!(part, std::path::Component::Normal(_)))
            .count().checked_add(1).ok_or_else(invalid)?;
        // Initial acquisition and two independent rooted name probes retain
        // their entire reached prefixes. The resolver reserves exact ancestry
        // capacity before opening; no geometric Vec-growth credit is assumed.
        let files = anchors.checked_add(2).and_then(|files| files.checked_mul(3))
            .and_then(|files| files.checked_add(2)).ok_or_else(invalid)?;
        // The three native acquisitions resolve the same ancestry and pair of
        // journal names. Their descriptor copies do not create more names.
        let names = anchors.checked_add(2).ok_or_else(invalid)?;
        // The containing readonly State pays its actual inline/constructor
        // widths. Only these additional native and backing owners are added.
        let mount_bytes = SignerMountReadbackAttemptV1::receiving_memory_bound_v1()
            .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(invalid)?;
        let bytes = files.checked_mul(4096)
            .and_then(|bytes| bytes.checked_add(mount_bytes))
            .and_then(|bytes| bytes.checked_add(anchors.checked_mul(9 * std::mem::size_of::<std::fs::File>())?))
            .and_then(|bytes| bytes.checked_add((root.len() + name.len() + 5).checked_mul(8)?))
            .and_then(|bytes| bytes.checked_add((root.len() + name.len()).checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(crate::journal::RootReadonlyJournalModelOriginalsV1::
                native_opening_receiving_bytes_v1()?)).ok_or_else(invalid)?;
        let fixed = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| invalid())?);
        if target.uses_full_semantics() {
            let cold = ColdReplayOriginalV1::fixed_demand_with_release_observer_v1().map_err(|_| invalid())?;
            let audit = crate::journal::RootControllerReadonlyGeometryAuditV1::fixed_demand_v1()?;
            fixed.checked_add(cold).and_then(|value| value.checked_add(audit))
                .map_err(|_| invalid())
        } else { Ok(fixed) }
    }

    pub(crate) fn capture_once(&mut self, uid: u32) {
        if self.entered { self.closed = true; return; }
        self.entered = true;
        self.primary = Some(self.capture_inner(uid));
    }

    fn capture_inner(&mut self, uid: u32) -> Result<(), JournalError> {
        let (root, name, limits) = self.target.recipe();
        self.original_uid = uid;
        self.mount_before_result = Some(self.mount_before.observe_root_readonly_once(
            self.target.view_v1(), uid, rustix::process::getegid().as_raw(), None));
        positive(&self.mount_before_result)?;
        let uid = 0;
        // The common acquisition uses this actual fixed recipe. Its own
        // first identities bind the existing mount and both name snapshots.
        self.opening.prepare_rooted_once_v1(Path::new(root), name, limits, uid)?;
        let (directory, file, lock) = self.opening.identities_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.mount_before.witness().is_none_or(|mount| mount.root_identity() != directory.physical_pair()) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.witness = Some(ReadOnlyJournalNameWitness::from_original_parts((
            Path::new(root).to_path_buf(), name.to_owned(), uid, directory, file, lock,
        )));
        self.opening.capture_readonly_names_once_v1(&self.before,
            self.witness.as_ref().ok_or(JournalError::ProtectedBoundary)?);
        if !self.before.is_complete() { return Err(JournalError::ProtectedBoundary); }
        let bytes = self.opening.capture_metadata_once_v1()?;
        self.extent = Some(protected_journal_preopen_replay_extent_for_prefix_v1(
            limits, bytes,
        ));
        positive(&self.extent).map(|_| ())
    }

    // The caller admits this actual captured-prefix demand from the same R
    // before entering replay. No configured-size product or Rust-field metadata
    // charge substitutes for the native map/index cardinality providers.
    pub(crate) fn replay_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        self.require_captured_v1()?;
        let bytes = self.opening.captured_length_data_v1().ok_or(JournalError::ProtectedBoundary)?;
        let extent = CanonicalReplayExtentDataV1::new(self.target.recipe().2, bytes)
            .map_err(|_| JournalError::JournalTooLarge)?;
        let marked = if self.target.uses_full_semantics() { 0 } else {
            bytes.checked_mul(4)
                .and_then(|bytes| bytes.checked_add((3 * std::mem::size_of::<crate::journal::JournalTransaction>()) as u64))
                .ok_or(JournalError::JournalTooLarge)?
        };
        let native = extent.dominant_native_receiving_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?;
        let codec = extent.dominant_semantic_receiving_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?;
        let index = CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(extent)
            .map_err(|_| JournalError::JournalTooLarge)?;
        let mut native = native.checked_add(codec).map_err(|_| JournalError::JournalTooLarge)?;
        if self.target.uses_full_semantics() {
            // The native-only geometry pass and later complete semantic pass
            // coexist. Their actual-prefix owners are separately admitted.
            native = native.checked_add(native).map_err(|_| JournalError::JournalTooLarge)?;
        }
        let native = native.checked_add(self.audit.delete_auxiliary_capture_receiving_demand_v3(bytes)?)
            .map_err(|_| JournalError::JournalTooLarge)?;
        let native = if matches!(self.delete_preparation, Some(DeletePreparationObservationV3::Storage(_))) {
            native.checked_add(aos_sandbox_ledger_replay::delete_pending::DeleteSelectedCommitReplayDataV3::storage_capture_demand_v3(bytes)?)
                .map_err(|_| JournalError::JournalTooLarge)?
        } else { native };
        native.checked_add(index)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, marked)))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn audit_once(&mut self) {
        self.audit_with_graph_once_v2(None);
    }

    pub(crate) fn audit_delete_graph_once_v2(&mut self,
        controller: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) {
        if !matches!(self.target, RootFixedNativeTargetV1::SourceCurrent) {
            self.closed = true;
            return;
        }
        self.audit_with_graph_once_v2(Some(controller));
    }

    fn audit_with_graph_once_v2(&mut self,
        controller: Option<&BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>>,
    ) {
        if !self.target.uses_full_semantics() || self.require_captured_v1().is_err() {
            self.closed = true; return;
        }
        if let Some(Ok(extent)) = &self.extent {
            self.audit.observe_fixed_opening_once_v1(&self.opening, *extent, controller);
        } else { self.closed = true; }
    }

    pub(crate) fn suffix_failure_is_selected_v1(&self) -> bool {
        self.cold.suffix_failure_is_selected_v1()
    }

    pub(crate) fn additional_semantic_demand_v1(&self) -> Result<ResourceVector, JournalError> {
        if !self.target.uses_full_semantics() || self.closed { return Err(JournalError::ProtectedBoundary); }
        let ordinary = self.audit.additional_semantic_demand_v1()?;
        match self.stopped_history.as_ref() {
            Some(history) => ordinary.checked_add(history.receiving_demand_v2(&self.audit)?)
                .map_err(|_| JournalError::JournalTooLarge),
            None => Ok(ordinary),
        }
    }

    // The same actual all-COMMIT audit bounds the additional complete prior
    // Tree/Lineage/policy fold and canonical Tree encoding before replay growth.
    // This is a second temporary model byte peak, not new namespace cardinality.
    pub(crate) fn additional_delete_predecessor_demand_v2(&self) -> Result<ResourceVector, JournalError> {
        let ordinary = self.additional_semantic_demand_v1()?;
        ordinary.checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
            ordinary.get(D::MemoryBytes))).map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn additional_delete_graph_predecessor_demand_v2(&self)
        -> Result<ResourceVector, JournalError>
    {
        self.additional_delete_predecessor_demand_v2()?
            .checked_add(self.audit.additional_graph_demand_v2()?)
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn additional_delete_preparation_semantic_demand_v3(&self) -> Result<ResourceVector, JournalError> {
        let ordinary = match self.delete_preparation.as_ref() {
            Some(DeletePreparationObservationV3::Source {..}) => self.additional_delete_predecessor_demand_v2()?,
            _ => self.additional_semantic_demand_v1()?,
        };
        match self.delete_preparation.as_ref() {
            Some(DeletePreparationObservationV3::Source { observer, .. }) => ordinary.checked_add(
                observer.captured_observation_receiving_demand_v3(self.audit.maximum_desired_state_value_bytes_v2()?)?)
                .map_err(|_| JournalError::JournalTooLarge),
            Some(DeletePreparationObservationV3::Controller(_)) => Ok(ordinary),
            Some(DeletePreparationObservationV3::Storage(_)) => Err(JournalError::ProtectedBoundary),
            None => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn prepare_delete_accepted_observation_v3(&mut self, expected: [u8;64]) -> Result<(), JournalError> {
        if !matches!(self.target, RootFixedNativeTargetV1::ControllerCurrent)
            || self.delete_preparation.is_some() || self.replay_result.is_some()
            || self.stopped_history.is_some() || self.delete_predecessor.is_some()
        { self.closed = true; return Err(JournalError::ProtectedBoundary); }
        self.delete_preparation = Some(DeletePreparationObservationV3::Controller(
            aos_sandbox_ledger_replay::delete_pending::DeleteSelectedCommitReplayDataV3::new(expected)));
        Ok(())
    }

    pub(crate) fn delete_admission_comparison_demand_v3(&self, batch: &[u8], input: &[u8]) -> Result<ResourceVector, JournalError> {
        crate::journal::DeleteAdmissionAuditInputsDataV3::receiving_demand_v3(self.captured_extent_v1()?, batch, input)
    }

    pub(crate) fn prepare_delete_admission_comparison_v3(&mut self, inputs: crate::journal::DeleteAdmissionAuditInputsDataV3)
        -> Result<(), JournalError> {
        if !matches!(self.target, RootFixedNativeTargetV1::ControllerCurrent)
            || !matches!(self.delete_preparation, Some(DeletePreparationObservationV3::Controller(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.audit.prepare_delete_admission_comparison_v3(inputs)
    }

    pub(crate) fn require_delete_admission_comparison_v3(&self) -> Result<(), JournalError> {
        self.terminal_native_v1()?;
        let actual = self.terminal_native_v1()?;
        self.audit.require_delete_admission_current_rows_v3(actual.state)
    }

    pub(crate) fn prepare_delete_preparation_session_observation_v3(&mut self, expected: [u8;64]) -> Result<(), JournalError> {
        if !matches!(self.target, RootFixedNativeTargetV1::StorageSession)
        { self.closed = true; return Err(JournalError::ProtectedBoundary); }
        self.prepare_delete_session_observation_inner_v4(expected)
    }

    pub(crate) fn prepare_delete_cleanup_session_observation_v4(&mut self, expected: [u8;64]) -> Result<(), JournalError> {
        if !matches!(self.target, RootFixedNativeTargetV1::NetworkSession | RootFixedNativeTargetV1::HostSession)
        { self.closed = true; return Err(JournalError::ProtectedBoundary); }
        self.prepare_delete_session_observation_inner_v4(expected)
    }

    fn prepare_delete_session_observation_inner_v4(&mut self, expected: [u8;64]) -> Result<(), JournalError> {
        if self.closed
            || self.delete_preparation.is_some() || self.replay_result.is_some()
            || self.stopped_history.is_some() || self.delete_predecessor.is_some()
        { self.closed = true; return Err(JournalError::ProtectedBoundary); }
        self.delete_preparation = Some(DeletePreparationObservationV3::Storage(
            aos_sandbox_ledger_replay::delete_pending::DeleteSelectedCommitReplayDataV3::new_session_boundary_v4(expected)
                .map_err(|_| JournalError::ProtectedBoundary)?));
        Ok(())
    }

    pub(crate) fn prepare_delete_completion_session_observation_v4(&mut self, expected: [u8; 64])
        -> Result<(), JournalError> {
        if !matches!(self.target, RootFixedNativeTargetV1::MountSession | RootFixedNativeTargetV1::StorageSession) {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.prepare_delete_session_observation_inner_v4(expected)
    }

    pub(crate) fn prepare_delete_current_observation_v3(&mut self,
        query: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1,
    ) -> Result<(), JournalError> {
        self.prepare_delete_source_observation_for_purpose_v4(query,
            aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentPurposeDataV3::ControllerCommitted)
    }

    pub(crate) fn prepare_delete_terminal_observation_v4(&mut self,
        query: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1,
    ) -> Result<(), JournalError> {
        self.prepare_delete_source_observation_for_purpose_v4(query,
            aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentPurposeDataV3::Terminal4)
    }

    fn prepare_delete_source_observation_for_purpose_v4(&mut self,
        query: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1,
        purpose: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentPurposeDataV3,
    ) -> Result<(), JournalError> {
        if !matches!(self.target, RootFixedNativeTargetV1::SourceCurrent)
            || self.delete_preparation.is_some() || self.replay_result.is_some()
            || self.stopped_history.is_some() || self.delete_predecessor.is_some()
        { self.closed = true; return Err(JournalError::ProtectedBoundary); }
        self.audit.prepare_delete_auxiliary_capture_v3(aos_sandbox_model::ProjectId::from_bytes(query.project),
            aos_sandbox_model::OperationId::from_bytes(query.operation))?;
        self.delete_preparation = Some(DeletePreparationObservationV3::Source { query, purpose,
            observer: aos_sandbox_ledger_replay::delete_pending::SourceDeletePendingReplayDataV1::new_for_purpose_v3(
                query, purpose) });
        Ok(())
    }

    pub(crate) fn delete_preparation_native_data_v3(&self) -> Result<[u8;64], JournalError> {
        let actual = self.terminal_native_v1()?;
        match self.delete_preparation.as_ref().ok_or(JournalError::ProtectedBoundary)? {
            DeletePreparationObservationV3::Controller(observer) => observer.data_v3(),
            DeletePreparationObservationV3::Storage(observer) => observer.session_boundary_data_v4(
                actual.names, actual.next, actual.end),
            DeletePreparationObservationV3::Source {query, purpose, observer} => observer.proof_for_purpose_v3(*query, *purpose),
        }.map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn delete_terminal_historical_source_native_v4(&self) -> Result<[u8;64], JournalError> {
        self.terminal_native_v1()?;
        match self.delete_preparation.as_ref() {
            Some(DeletePreparationObservationV3::Source { query, purpose, observer })
                if *purpose == aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentPurposeDataV3::Terminal4 =>
                    observer.historical_controller_committed_native_data_v4(*query)
                        .map_err(|_| JournalError::ProtectedBoundary),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn completed_delete_storage_history_rows_v3(&self)
        -> Result<(&[u8], &[u8], &[u8]), JournalError>
    {
        self.terminal_native_v1()?;
        match self.delete_preparation.as_ref() {
            Some(DeletePreparationObservationV3::Storage(observer)) =>
                observer.storage_history_rows_v3().map_err(|_| JournalError::ProtectedBoundary),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(crate) fn completed_delete_cleanup_history_rows_v4(&self)
        -> Result<(&[u8], &[u8], &[u8]), JournalError>
    {
        if !matches!(self.target, RootFixedNativeTargetV1::NetworkSession | RootFixedNativeTargetV1::HostSession) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.completed_delete_storage_history_rows_v3()
    }

    pub(crate) fn completed_delete_auxiliary_rows_v3(&self)
        -> Result<&[crate::journal::RootDeleteAuxiliaryRowDataV3], JournalError>
    {
        self.terminal_native_v1()?;
        self.audit.delete_auxiliary_rows_v3()
    }

    // This view borrows only the actual same completed native map/index. It
    // supplies no Journal constructor, currentness capability or receiving loan.
    pub(crate) fn completed_rows_data_v3(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>, JournalError>
    {
        let native = self.terminal_native_v1()?;
        Ok(aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2::new(native.state, self.opening.index_data_v1()))
    }

    pub(crate) fn replay_delete_graph_predecessor_once_v2(&mut self,
        query: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1,
        signed_native: [u8; 64], controller: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        capabilities: Vec<aos_sandbox_ledger_replay::delete_graph::DeleteGraphCapabilityDataV2>,
    ) -> Result<(), Vec<aos_sandbox_ledger_replay::delete_graph::DeleteGraphCapabilityDataV2>> {
        if !matches!(self.target, RootFixedNativeTargetV1::SourceCurrent)
            || self.delete_predecessor.is_some() || self.replay_result.is_some()
        { self.closed = true; return Err(capabilities); }
        self.delete_predecessor = Some(aos_sandbox_ledger_replay::delete_pending::
            DeleteSourcePredecessorReplayDataV2::with_graph_census_data_v2(query, signed_native, capabilities));
        self.replay_with_options_once(None, None, Some(controller));
        Ok(())
    }

    pub(crate) fn replay_delete_predecessor_once_v2(&mut self,
        query: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1,
        signed_native: [u8; 64],
    ) {
        if !matches!(self.target, RootFixedNativeTargetV1::SourceCurrent)
            || self.delete_predecessor.is_some() || self.replay_result.is_some()
        { self.closed = true; return; }
        self.delete_predecessor = Some(aos_sandbox_ledger_replay::delete_pending::
            DeleteSourcePredecessorReplayDataV2::new(query, signed_native));
        self.replay_with_options_once(None, None, None);
    }

    pub(crate) fn delete_predecessor_data_v2(&self)
        -> Result<aos_sandbox_ledger_replay::delete_pending::DeleteSourcePredecessorDataV2, JournalError>
    {
        // A pure observation cannot be borrowed before the actual same-file,
        // rooted-name and mount afters and whole full-semantic replay succeed.
        self.terminal_native_v1()?;
        self.delete_predecessor.as_ref().ok_or(JournalError::ProtectedBoundary)?
            .data_v2().map_err(JournalError::from)
    }

    pub(crate) fn replay_once(&mut self) { self.replay_with_options_once(None, None, None); }

    pub(crate) fn replay_marked_once_v1(&mut self, position: (u64, u64)) {
        self.replay_with_options_once(Some(position), None, None);
    }

    pub(crate) fn replay_suffix_once(&mut self,
        suffix: &mut crate::journal::create_storage_history::HistoryPairNativeSuffixV1<'_, '_>,
    ) { self.replay_with_options_once(None, Some(suffix), None); }

    fn replay_with_options_once(&mut self, mark: Option<(u64, u64)>,
        suffix: Option<&mut crate::journal::create_storage_history::HistoryPairNativeSuffixV1<'_, '_>>,
        graph_controller: Option<&BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>>,
    ) {
        if self.replay_result.is_some() { self.closed = true; return; }
        if self.require_captured_v1().is_err() { self.closed = true; return; }
        let Some(bytes) = self.opening.captured_length_data_v1() else { self.closed = true; return; };
        if self.target.uses_full_semantics() {
            if mark.is_some() || self.audit.additional_semantic_demand_v1().is_err() {
                self.closed = true; return;
            }
            let identity = match self.opening.identities_data_v1() {
                Some((_, identity, _)) => identity,
                None => { self.closed = true; return; }
            };
            self.cold_result = Some((|| {
                let mut cursor = self.opening.begin_indexed_replay_once_v1()
                    .map_err(|_| ColdReplayClosedV1)?;
                if let Some(observation) = self.delete_preparation.as_mut() {
                    if suffix.is_some() || self.delete_predecessor.is_some() || self.stopped_history.is_some() {
                        return Err(ColdReplayClosedV1);
                    }
                    match observation {
                        DeletePreparationObservationV3::Controller(observer) => self.cold.observe_indexed_with_delete_accepted_once_v3(
                            &mut cursor, identity, self.target.recipe().2, observer)?,
                        DeletePreparationObservationV3::Source {observer,..} => self.cold.observe_indexed_with_delete_current_once_v3(
                            &mut cursor, identity, self.target.recipe().2, observer)?,
                        DeletePreparationObservationV3::Storage(_) => return Err(ColdReplayClosedV1),
                    }
                } else if let Some(history) = self.stopped_history.as_mut() {
                    if suffix.is_some() || self.delete_predecessor.is_some()
                        || !matches!(self.target, RootFixedNativeTargetV1::ControllerCurrent) {
                        return Err(ColdReplayClosedV1);
                    }
                    let mut observation = history.prepare_v2(&self.audit)?;
                    self.cold.observe_indexed_with_create_stopped_once_v2(&mut cursor, identity,
                        self.target.recipe().2, &mut observation, &mut history.observation_error)?;
                    history.complete = true;
                } else if let Some(predecessor) = self.delete_predecessor.as_mut() {
                    if suffix.is_some() { return Err(ColdReplayClosedV1); }
                    match graph_controller {
                        Some(controller) => self.cold.observe_indexed_with_delete_graph_predecessor_once_v2(
                            &mut cursor, identity, self.target.recipe().2, predecessor, controller)?,
                        None => self.cold.observe_indexed_with_delete_predecessor_once_v2(&mut cursor, identity,
                            self.target.recipe().2, predecessor)?,
                    }
                } else {
                    self.cold.observe_indexed_with_release_observer_once(&mut cursor, identity,
                        self.target.recipe().2, suffix)?;
                }
                let actual = cursor.completed_prefix().ok_or(ColdReplayClosedV1)?.coordinates();
                if actual.durable_end != bytes { return Err(ColdReplayClosedV1); }
                self.replay_position = Some((actual.durable_next_sequence, actual.durable_end));
                Ok(())
            })());
            self.replay_result = Some(if matches!(self.cold_result, Some(Ok(()))) {
                Ok(())
            } else { Err(CanonicalIndexedReplayErrorV1::Closed) });
            return;
        }
        let selected = match self.delete_preparation.as_mut() {
            Some(DeletePreparationObservationV3::Storage(observer)) => Some(observer),
            None => None,
            _ => { self.closed = true; return; }
        };
        let cursor = match self.opening.begin_indexed_replay_once_v1() {
            Ok(cursor) => cursor,
            Err(_) => {
                self.replay_result = Some(Err(CanonicalIndexedReplayErrorV1::Closed));
                return;
            }
        };
        self.replay_result = Some(replay_cursor(cursor, bytes, &mut self.replay_position,
            mark, &mut self.marked_transaction, suffix, selected));
    }

    // This handoff is available only after full semantic replay and all native
    // posts. The same actual descriptors/maps move into the existing readonly
    // Journal model. Mount/name posts stay here; acquisition probes remain in
    // the same opaque opening as it moves through any refused conversion.
    pub(crate) fn captured_model_post_geometry_v1(&self) -> Result<(usize, usize), JournalError> {
        self.require_captured_v1()?;
        if !self.target.uses_full_semantics() {
            return Err(JournalError::ProtectedBoundary);
        }
        let (root, name, _) = self.target.recipe();
        let bytes = root.len().checked_add(name.len()).and_then(|bytes| bytes.checked_add(1))
            .ok_or(JournalError::JournalTooLarge)?;
        let files = Path::new(root).components()
            .filter(|part| matches!(part, std::path::Component::Normal(_))).count()
            .checked_add(3).ok_or(JournalError::JournalTooLarge)?;
        Ok((bytes, files))
    }

    pub(crate) fn take_completed_model_inputs_v1(&mut self)
        -> Result<crate::journal::RootReadonlyJournalModelInputsV1, JournalError> {
        if self.model_transferred || !self.target.uses_full_semantics() {
            self.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.terminal_native_v1()?;
        let report = self.opening.replay_data_v1().report().ok_or(JournalError::ProtectedBoundary)?.1;
        self.model_transferred = true;
        let (root, name, _) = self.target.recipe();
        Ok(crate::journal::RootReadonlyJournalModelInputsV1 {
            root, name, view: self.target.view_v1(), original_uid: self.original_uid,
            witness: self.witness.take(), report,
            opening: Some(std::mem::replace(&mut self.opening, CanonicalOrdinaryReadonlyOpeningV1::new())),
            remainder: self.cold.take_remainder_once(),
        })
    }

    pub(crate) fn cache_raw_view_v1(&self)
        -> Result<aos_sandbox_ledger_replay::cache_current::CacheRawJournalDataV1<'_>, JournalError> {
        self.replay_native_v1()?;
        Ok(aos_sandbox_ledger_replay::cache_current::CacheRawJournalDataV1 {
            state: self.opening.replay_data_v1().state().ok_or(JournalError::ProtectedBoundary)?,
            namespaces: self.opening.replay_data_v1().committed_namespaces().ok_or(JournalError::ProtectedBoundary)?,
            report: self.opening.replay_data_v1().report().ok_or(JournalError::ProtectedBoundary)?.1,
        })
    }

    pub(crate) fn terminal_native_v1(&self) -> Result<RootFixedNativeReadbackV1<'_>, JournalError> {
        self.extent_v1()?;
        self.replay_native_v1()
    }

    pub(crate) fn replay_native_v1(&self) -> Result<RootFixedNativeReadbackV1<'_>, JournalError> {
        self.require_captured_v1()?;
        if !matches!(self.replay_result, Some(Ok(()))) || !self.opening.indexed_replay_complete_data_v1() {
            return Err(JournalError::ProtectedBoundary);
        }
        let (next, end) = self.replay_position.ok_or(JournalError::ProtectedBoundary)?;
        if end != self.opening.captured_length_data_v1().ok_or(JournalError::ProtectedBoundary)? { return Err(JournalError::ProtectedBoundary); }
        let (directory, file, lock) = self.opening.identities_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        let names = ProtectedJournalNamesV1::from_historical_fields(
            directory.physical_pair(), file.physical_pair(), lock.physical_pair());
        Ok(RootFixedNativeReadbackV1 { marked_transaction: self.marked_transaction.as_ref(), state: self.opening.replay_data_v1().state()
            .ok_or(JournalError::ProtectedBoundary)?, names, next, end })
    }

    pub(crate) fn finish_post_once(&mut self) {
        if !self.entered || self.after_length.is_some() { return; }
        self.mount_after_result = Some(self.mount_after.observe_root_readonly_once(
            self.target.view_v1(), self.original_uid, rustix::process::getegid().as_raw(), None));
        self.mount_binding = Some(match (self.mount_before.witness(), self.mount_after.witness()) {
            (Some(before), Some(after)) if before == after => Ok(()),
            _ => Err(JournalError::ProtectedBoundary),
        });
        if self.opening.has_native_file_data_v1() {
            if let Some(witness) = &self.witness {
                self.opening.capture_readonly_names_once_v1(&self.after, witness);
            }
            self.after_metadata = Some(self.opening.observe_metadata_v1());
        }
        self.after_length = Some((|| {
            if !self.after.is_complete() { return Err(JournalError::ProtectedBoundary); }
            let before = self.opening.captured_length_data_v1().ok_or(JournalError::ProtectedBoundary)?;
            let after = positive(&self.after_metadata)?;
            if before != after.len() { return Err(JournalError::ProtectedBoundary); }
            Ok(())
        })());
    }

    pub(crate) fn require_captured_v1(&self) -> Result<(), JournalError> {
        if self.closed || !matches!(self.primary, Some(Ok(()))) || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        positive(&self.extent).map(|_| ())
    }

    pub(crate) fn captured_extent_v1(&self) -> Result<&ProtectedJournalPreopenReplayExtentV1, JournalError> {
        self.require_captured_v1()?;
        positive(&self.extent)
    }

    pub(crate) fn extent_v1(&self) -> Result<&ProtectedJournalPreopenReplayExtentV1, JournalError> {
        if self.closed || !matches!(self.primary, Some(Ok(())))
            || !matches!(self.after_length, Some(Ok(()))) || self.failure().is_some()
            || self.post_failure().is_some() { return Err(JournalError::ProtectedBoundary); }
        positive(&self.extent)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.mount_before.failure().or_else(|| cause(&self.mount_before_result))
            .or_else(|| self.opening.acquisition_failure_v1())
            .or_else(|| self.before.failure().map(|cause| cause as _))
            .or_else(|| cause(&self.extent))
            .or_else(|| cause(&self.primary))
            .or_else(|| self.audit.failure())
            .or_else(|| self.stopped_history.as_ref().and_then(|history| history.recipe_error.as_ref()).map(|cause| cause as _))
            .or_else(|| self.stopped_history.as_ref().and_then(|history| history.selector_error.as_ref()).map(|cause| cause as _))
            .or_else(|| match self.delete_preparation.as_ref() {
                Some(DeletePreparationObservationV3::Storage(observer)) => observer.failure_v3(),
                _ => None,
            })
            .or_else(|| if self.cold.delete_preparation_failure_is_selected_v3() {
                self.delete_preparation.as_ref().and_then(|observer| observer.failure())
            } else { None })
            .or_else(|| if self.cold.native_failure_is_selected_v1() { self.opening.replay_failure_v1() } else { None })
            .or_else(|| if self.cold.create_stopped_failure_is_selected_v2() {
                self.stopped_history.as_ref().and_then(|history| history.failure())
            } else { None })
            .or_else(|| if self.cold.predecessor_failure_is_selected_v2() {
                self.delete_predecessor.as_ref().and_then(|original| original.failure())
            } else { None })
            .or_else(|| if self.cold.suffix_failure_is_selected_v1() { None } else { self.cold.failure() })
            .or_else(|| if self.cold.suffix_failure_is_selected_v1() { None } else { cause(&self.cold_result) })
            .or_else(|| self.opening.replay_failure_v1().map(|cause| cause as _))
            .or_else(|| self.opening.index_failure_v1())
            .or_else(|| if self.cold.suffix_failure_is_selected_v1() { None } else { cause(&self.replay_result) })
            .or_else(|| self.opening.order_failure_v1())
            .or_else(|| self.closed.then_some(&READ_CLOSED as &(dyn Error + 'static)))
    }

    pub(crate) fn post_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.mount_after.failure().or_else(|| cause(&self.mount_after_result))
            .or_else(|| cause(&self.mount_binding))
            .or_else(|| self.after.failure().map(|cause| cause as _))
            .or_else(|| cause(&self.after_metadata)).or_else(|| cause(&self.after_length))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

/// Borrows only the actual completed native map, names and durable coordinates.
/// This private comparison view carries no Session or effect authority.
pub(crate) struct RootFixedNativeReadbackV1<'a> {
    pub(crate) marked_transaction: Option<&'a crate::journal::JournalTransaction>,
    pub(crate) state: &'a BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    pub(crate) names: ProtectedJournalNamesV1,
    pub(crate) next: u64,
    pub(crate) end: u64,
}

fn replay_cursor(mut cursor: CanonicalIndexedReplayV1<'_, '_>, bytes: u64,
    position: &mut Option<(u64, u64)>, mark: Option<(u64, u64)>,
    marked: &mut Option<crate::journal::JournalTransaction>,
    mut suffix: Option<&mut crate::journal::create_storage_history::HistoryPairNativeSuffixV1<'_, '_>>,
    mut selected: Option<&mut aos_sandbox_ledger_replay::delete_pending::DeleteSelectedCommitReplayDataV3>,
) -> Result<(), CanonicalIndexedReplayErrorV1> {
    while cursor.advance_once()? {
        let view = cursor.current_commit().ok_or(CanonicalIndexedReplayErrorV1::Closed)?;
        if let Some(suffix) = suffix.as_deref_mut() {
            let (begin, start) = view.begin_position();
            suffix.observe(view.transaction(), begin, view.commit_sequence(), start,
                view.coordinates().offset).map_err(|_| CanonicalIndexedReplayErrorV1::Closed)?;
        }
        if let Some(selected) = selected.as_deref_mut() {
            selected.observe_commit_v3(&view).map_err(|_| CanonicalIndexedReplayErrorV1::Closed)?;
        }
        let next = view.commit_sequence().checked_add(1).ok_or(CanonicalIndexedReplayErrorV1::Closed)?;
        if mark == Some((next, view.coordinates().offset)) {
            if marked.is_some() { return Err(CanonicalIndexedReplayErrorV1::Closed); }
            *marked = Some(view.transaction().clone());
        }
        cursor.validate_compaction_once()?;
        cursor.register_and_compare_index_once()?;
        cursor.prepare_change_once()?;
        while cursor.apply_next_record_once()? {}
        cursor.finish_commit_accounting_once()?;
        cursor.finish_commit_once()?;
    }
    let actual = cursor.completed_prefix().ok_or(CanonicalIndexedReplayErrorV1::Closed)?.coordinates();
    if actual.durable_end != bytes { return Err(CanonicalIndexedReplayErrorV1::Closed); }
    if let Some(suffix) = suffix {
        suffix.finish(actual.durable_next_sequence, actual.durable_end, bytes)
            .map_err(|_| CanonicalIndexedReplayErrorV1::Closed)?;
    }
    if let Some(selected) = selected {
        selected.finish_prefix_v3(cursor.completed_prefix().ok_or(CanonicalIndexedReplayErrorV1::Closed)?, bytes)
            .map_err(|_| CanonicalIndexedReplayErrorV1::Closed)?;
    }
    if mark.is_some() && marked.is_none() { return Err(CanonicalIndexedReplayErrorV1::Closed); }
    *position = Some((actual.durable_next_sequence, actual.durable_end));
    Ok(())
}

#[cfg(test)]
fn replay_file(
    file: &std::fs::File, limits: crate::journal::JournalLimits, bytes: u64,
    original: &mut aos_sandbox_broker::canonical_journal::CanonicalReplayOriginalV1,
    index: &mut BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    index_originals: &mut CanonicalReplayIndexOriginalsV1,
    position: &mut Option<(u64, u64)>, mark: Option<(u64, u64)>,
    marked: &mut Option<crate::journal::JournalTransaction>,
    suffix: Option<&mut crate::journal::create_storage_history::HistoryPairNativeSuffixV1<'_, '_>>,
    selected: Option<&mut aos_sandbox_ledger_replay::delete_pending::DeleteSelectedCommitReplayDataV3>,
) -> Result<(), CanonicalIndexedReplayErrorV1> {
    let cursor = original.begin_semantic_cursor_once(file, limits, bytes)?;
    replay_cursor(CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, index, index_originals),
        bytes, position, mark, marked, suffix, selected)
}

// Only the finite fixed Root reader recipes exist. Selection remains private
// to actual stage owners; this enum lends no funding or native authority.
#[derive(Clone, Copy)]
enum RootFixedNativeTargetV1 {
    StorageSession, HostSession, MountSession, NetworkSession,
    ControllerCurrent, SourceRelease, SourceCurrent, CacheRelease,
    CacheCurrent(aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1),
}

impl RootFixedNativeTargetV1 {
    fn uses_full_semantics(self) -> bool { matches!(self, Self::ControllerCurrent | Self::SourceRelease | Self::SourceCurrent | Self::CacheRelease | Self::CacheCurrent(_)) }

    fn view_v1(self) -> RootReadonlyViewV1 {
        use aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1 as Cache;
        match self {
            Self::StorageSession => RootReadonlyViewV1::StorageSession,
            Self::HostSession => RootReadonlyViewV1::HostSession,
            Self::MountSession => RootReadonlyViewV1::MountSession,
            Self::NetworkSession => RootReadonlyViewV1::NetworkSession,
            Self::ControllerCurrent => RootReadonlyViewV1::Controller,
            Self::SourceRelease | Self::SourceCurrent => RootReadonlyViewV1::Source,
            Self::CacheCurrent(Cache::Bootstrap) => RootReadonlyViewV1::CacheBootstrap,
            Self::CacheCurrent(_) | Self::CacheRelease => RootReadonlyViewV1::CacheJournals,
        }
    }

    fn recipe(self) -> (&'static str, &'static str, crate::journal::JournalLimits) {
        match self {
            Self::ControllerCurrent => (
                self.view_v1().view_path_v1(), crate::journal::ROOT_CONTROLLER_JOURNAL_V1,
                crate::journal::controller::production_journal_limits()),
            Self::StorageSession | Self::HostSession | Self::MountSession | Self::NetworkSession => (
                self.view_v1().view_path_v1(),
                crate::journal::broker_session_receiving::PROTECTED_SESSION_JOURNAL_V1,
                crate::journal::broker_session_receiving::protected_session_journal_limits_v1()),
            Self::SourceRelease | Self::SourceCurrent => (self.view_v1().view_path_v1(),
                aos_sandbox_broker::source_receiving::SOURCE_DOMAIN_JOURNAL_V1,
                aos_sandbox_broker::source_receiving::source_journal_limits_v1()),
            Self::CacheCurrent(role) => (self.view_v1().view_path_v1(), role.basename_v1(), role.limits_v1()),
            Self::CacheRelease => {
                let role = aos_sandbox_protocol::cache_state::fixed_journals::CacheJournalRecipeRoleV1::Hold;
                (self.view_v1().view_path_v1(), role.basename_v1(), role.limits_v1())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use aos_sandbox_broker::canonical_journal::CanonicalReplayOriginalV1;
    use std::io::Write as _;
    use crate::journal::{JournalRecord, JournalTransaction, JournalLimits};
    use aos_sandbox_protocol::domain_ledger::transaction::encode_transaction;

    fn encoded_file() -> (File, JournalTransaction, u64) {
        let transaction = JournalTransaction::new([7; 16], vec![JournalRecord::put(
            RecordNamespace::Effect, b"actual-row".to_vec(), b"actual-value".to_vec())]).unwrap();
        let frames = encode_transaction(&transaction, 1).unwrap();
        let next = frames.len() as u64 + 1;
        let mut file = tempfile::tempfile().unwrap();
        for frame in frames { file.write_all(&frame).unwrap(); }
        (file, transaction, next)
    }

    #[test]
    fn marked_readback_is_the_actual_canonical_commit_and_native_position() {
        let (file, expected, next) = encoded_file();
        let length = file.metadata().unwrap().len();
        let mut raw = CanonicalReplayOriginalV1::new();
        let mut index = BTreeMap::new();
        let mut index_originals = CanonicalReplayIndexOriginalsV1::new();
        let mut position = None;
        let mut marked = None;

        replay_file(&file, JournalLimits::default(), length, &mut raw, &mut index,
            &mut index_originals, &mut position, Some((next, length)), &mut marked, None, None).unwrap();

        assert_eq!(position, Some((next, length)));
        assert_eq!(marked.as_ref().unwrap().id(), expected.id());
        assert_eq!(marked.as_ref().unwrap().records(), expected.records());
        assert_eq!(raw.state().unwrap().get(&(RecordNamespace::Effect, b"actual-row".to_vec())),
            Some(&b"actual-value".to_vec()));
    }

    #[test]
    fn a_late_malformed_native_frame_keeps_its_original_cause_on_reentry() {
        let (mut file, _, _) = encoded_file();
        // A short header is a torn EOF, not a native malformed-frame error.
        // Reach the parser's full-header invalid-magic refusal after the commit.
        file.write_all(&[0; aos_sandbox_journal::framing::HEADER_BYTES]).unwrap();
        let length = file.metadata().unwrap().len();
        let mut raw = CanonicalReplayOriginalV1::new();
        let mut index = BTreeMap::new();
        let mut index_originals = CanonicalReplayIndexOriginalsV1::new();
        let mut position = None;
        let mut marked = None;

        assert!(replay_file(&file, JournalLimits::default(), length, &mut raw, &mut index,
            &mut index_originals, &mut position, None, &mut marked, None, None).is_err());
        assert!(matches!(raw.failure().unwrap()
            .downcast_ref::<aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1>(),
            Some(aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1::Frame(
                aos_sandbox_journal::framing::FrameError::MalformedTransaction("invalid frame magic"),
            ))));
        let first = raw.failure().unwrap() as *const dyn Error;
        assert!(replay_file(&file, JournalLimits::default(), length, &mut raw, &mut index,
            &mut index_originals, &mut position, None, &mut marked, None, None).is_err());

        assert!(std::ptr::eq(first, raw.failure().unwrap() as *const dyn Error));
        assert!(raw.report().is_none());
        assert!(position.is_none());
    }
}

const READ_CLOSED: JournalError = JournalError::ProtectedBoundary;
