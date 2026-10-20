//! Keeps readonly Source receiving in the same genuine original ledger.
//!
//! The connection owner alone enters this resident peak and completes it after
//! actual response, peer/currentness/name posts, clean shutdown and disposal.
//! Native replay borrows this same context at its existing semantic boundaries;
//! no callback, account copy or caller-provided ResourceVector funds an entry.

use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};

use super::{SourceReceivingClosedV1, CLOSED};
use aos_sandbox_broker::receiving::RepresentationDemandDebitV1;
use aos_sandbox_broker::canonical_journal::{CanonicalJournalMechanicalErrorV1 as JournalError,
    CanonicalReplayExtentDataV1 as ProtectedJournalPreopenReplayExtentV1,
    coordinator::indexed_replay::CanonicalReplayIndexOriginalsV1};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::HistoryPairNativeSuffixV1;
use aos_sandbox_ledger_replay::replay::tree_lineage::retained::SourceCurrentTreeOriginalsV1;
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;
type CurrentTree = SourceCurrentTreeOriginalsV1<DomainLedgerDataError>;

type State = std::collections::BTreeMap<(aos_sandbox_core::RecordNamespace, Vec<u8>), Vec<u8>>;

pub(super) struct SourceReadonlyPeakV1 {
    reserved: ResourceVector,
    active: bool,
    closed: bool,
    geometry: Option<Result<ResourceVector, SourceReadonlyDemandErrorV1>>,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SourceReadonlyDemandErrorV1 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Native(#[from] aos_sandbox_broker::canonical_journal::NativeJournalDataErrorV1),
    #[error(transparent)]
    Index(#[from] aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1),
}

impl SourceReadonlyPeakV1 {
    pub(super) const fn new() -> Self {
        Self { reserved: ResourceVector::ZERO, active: false, closed: false, geometry: None }
    }

    pub(super) fn begin(&mut self) -> Result<(), SourceReceivingClosedV1> {
        if self.active || self.closed || matches!(self.geometry, Some(Err(_))) {
            self.closed = true;
            return Err(CLOSED);
        }
        self.active = true;
        Ok(())
    }

    // Only the same private native connection owner can call this after it has
    // actually disposed the wholly positive lane. A Boolean or caller Result
    // cannot supply a substitute completion proof. Charges are never refunded.
    pub(super) fn finish_after_actual_positive_disposal(&mut self) {
        if !self.active || self.closed || matches!(self.geometry, Some(Err(_))) {
            self.closed = true;
            return;
        }
        self.active = false;
    }

    pub(super) fn retain_failed_lane(&mut self) {
        self.closed = true;
    }

    pub(super) fn failure(&self) -> Option<&SourceReadonlyDemandErrorV1> {
        self.geometry.as_ref().and_then(|result| result.as_ref().err())
    }

    fn reserve_peak(
        &mut self,
        ledger: &mut dyn RepresentationDemandDebitV1,
        demand: ResourceVector,
    ) -> Result<(), JournalError> {
        if !self.active || self.closed || matches!(self.geometry, Some(Err(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let mut next = self.reserved;
        for dimension in [D::MemoryBytes, D::MetadataEntries, D::OpenFiles] {
            next = next.with(dimension, next.get(dimension).max(demand.get(dimension)));
        }
        self.geometry = Some(next.checked_sub(self.reserved).map_err(Into::into));
        let increment = self.geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        // Context is the genuine typed loan returned only by the Original's
        // checked private borrow_context. That entry proves actual F3, native
        // hard limits and the SAME ledger's permanent H+N descriptor charge.
        // Keep full descriptor geometry above; spending it again would count
        // that same permanently charged table twice. No other dimension or
        // other role's ledger receives this closed Source-only normalization.
        let financial_increment = increment.with(D::OpenFiles, 0);
        if ledger.reserve(financial_increment).is_err() {
            self.closed = true;
            return Err(JournalError::LimitExceeded("Source readonly receiving allowance"));
        }
        self.reserved = next;
        Ok(())
    }
}

pub(crate) struct SourceReadonlyReceivingContextV1<'source, 'expected> {
    ledger: &'source mut dyn RepresentationDemandDebitV1,
    peak: &'source mut SourceReadonlyPeakV1,
    native: ResourceVector,
    fixed_admitted: bool,
    captured_admitted: bool,
    captured_file_end: Option<u64>,
    history_pair: Option<HistoryPairNativeSuffixV1<'expected, 'source>>,
    history_pair_finished: bool,
    current_query: Option<[u8; 32]>,
    current_project: Option<aos_sandbox_core::ProjectId>,
}

impl<'source, 'expected> SourceReadonlyReceivingContextV1<'source, 'expected> {
    pub(super) fn new(
        ledger: &'source mut dyn RepresentationDemandDebitV1,
        peak: &'source mut SourceReadonlyPeakV1,
    ) -> Result<Self, SourceReceivingClosedV1> {
        if !peak.active || peak.closed || matches!(peak.geometry, Some(Err(_)))
            || ledger.failure().is_some()
        {
            return Err(CLOSED);
        }
        Ok(Self { ledger, peak, native: ResourceVector::ZERO,
            fixed_admitted: false, captured_admitted: false,
            captured_file_end: None, history_pair: None, history_pair_finished: false, current_query: None, current_project: None })
    }

    // The checked Original-private current-cut entry alone attaches this borrowed
    // DATA facade. It already owns/funds the expected transaction and complete
    // progress in disjoint resident fields. This context temporarily owns only
    // their borrows, avoiding self-reference or loss on a handler return.
    pub(super) fn attach_history_pair_once(
        &mut self,
        suffix: HistoryPairNativeSuffixV1<'expected, 'source>,
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.fixed_admitted || self.captured_admitted || self.history_pair.is_some()
            || self.peak.closed || self.ledger.failure().is_some()
        {
            self.peak.closed = true;
            return Err(CLOSED);
        }
        self.history_pair = Some(suffix);
        Ok(())
    }

    // Only the authenticated Source connection can lend this same-original
    // context. Query bytes remain comparison DATA; exact suffix replay must
    // complete independently before the new signing purpose may use the view.
    pub(super) fn attach_current_query_once(
        &mut self,
        suffix: HistoryPairNativeSuffixV1<'expected, 'source>,
        query: &[u8; aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::SOURCE_CURRENT_QUERY_BYTES_V1],
    ) -> Result<(), SourceReceivingClosedV1> {
        if self.current_query.is_some() { return Err(CLOSED); }
        let query = aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::SourceCurrentQueryDataV1::decode(query)
            .map_err(|_| CLOSED)?;
        let digest = query.digest_v1().map_err(|_| CLOSED)?;
        let root = query.root_body().map_err(|_| CLOSED)?;
        let source = query.source_receipt().and_then(|receipt| receipt.body(root.open.lane)).map_err(|_| CLOSED)?;
        self.attach_history_pair_once(suffix)?;
        self.current_query = Some(digest);
        self.current_project = Some(aos_sandbox_core::ProjectId::from_bytes(source.project));
        Ok(())
    }

    // A distinct closed Delete query uses the same selected-project dynamic
    // model supplier, without attaching or rearming a Create Held suffix.
    pub(in crate::signer) fn attach_delete_project_once(&mut self, project: aos_sandbox_core::ProjectId)
        -> Result<(), JournalError> {
        if !self.fixed_admitted || self.captured_admitted || self.current_project.is_some()
            || self.history_pair.is_some() || self.current_query.is_some() || project.as_bytes() == &[0; 16] {
            return Err(JournalError::ProtectedBoundary);
        }
        self.current_project = Some(project);
        Ok(())
    }

    pub(crate) fn require_current_query_complete_v1(&self, digest: [u8; 32], expected_end: u64)
        -> Result<(), JournalError>
    {
        self.require_history_pair_finished()?;
        if self.current_query != Some(digest) || self.captured_file_end != Some(expected_end) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Admits the actual fixed attempt and its four retained mount observations.
    ///
    /// # Errors
    /// Rejects reentry, representation overflow, or the genuine ledger's refusal.
    pub(crate) fn admit_fixed(&mut self) -> Result<(), JournalError> {
        if self.fixed_admitted || self.captured_admitted {
            self.peak.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.fixed_admitted = true;
        self.peak.geometry = Some(Self::fixed_demand());
        let demand = self.peak.geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        self.native = demand;
        self.peak.reserve_peak(self.ledger, demand)
    }

    // Closed actual types and fixed paths supply only representation DATA.
    // This shares production arithmetic with offline native-parser regressions;
    // it neither constructs an Original nor establishes permanent FD coverage.
    pub(super) fn fixed_demand() -> Result<ResourceVector, SourceReadonlyDemandErrorV1> {
        let native = super::readonly_native::SourceReadonlyNativeOriginalV1::
            fixed_receiving_demand_v1::<super::readonly_view::SourceReadonlyAttemptV1>()
            .ok_or(JournalError::LimitExceeded("Source readonly fixed geometry"))?;
        // Initial, post-signature, post-response and post-shutdown mount owners
        // coexist. Their partial Strings/files and this actual context stay
        // funded; no earlier owner is dropped just to reuse a cheaper peak.
        let retained_bytes = aos_sandbox_linux::signer_mount::SignerMountReadbackAttemptV1::receiving_memory_bound_v1()
            .and_then(|bytes| bytes.checked_mul(4))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::LimitExceeded("Source retained mount receiving geometry"))?;
        let (current_bytes, current_cells, current_files) =
            super::readonly_view::SourceReadonlyAttemptV1::current_cut_fixed_obligations_v1()
                .ok_or(JournalError::LimitExceeded("Source current-cut fixed geometry"))?;
        let current = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(current_bytes).map_err(|_| JournalError::ProtectedBoundary)?)
            .with(D::MetadataEntries, u64::try_from(current_cells.checked_add(3).ok_or(JournalError::ProtectedBoundary)?)
                .map_err(|_| JournalError::ProtectedBoundary)?)
            .with(D::OpenFiles, u64::try_from(current_files).map_err(|_| JournalError::ProtectedBoundary)?);
        let (family_bytes, family_cells) = aos_sandbox_ledger_replay::replay::source_tree_successor::SourceReplayFamilyOriginalsV1::<
            JournalError, DomainLedgerDataError, aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1,
        >::fixed_footprint_v1().and_then(|(family, cells)| {
            let (transition, more) = aos_sandbox_ledger_replay::replay::source_tree_successor::SourceReplayTransactionOriginalsV1::<
                JournalError, DomainLedgerDataError, aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1,
            >::fixed_footprint_v1()?;
            Some((family.checked_add(transition)?, cells.checked_add(more)?))
        }).ok_or(JournalError::LimitExceeded("Source Native family geometry"))?;
        let family = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(family_bytes).map_err(|_| JournalError::ProtectedBoundary)?)
            .with(D::MetadataEntries, u64::try_from(family_cells).map_err(|_| JournalError::ProtectedBoundary)?);
        native.checked_add(current)?.checked_add(family)?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, retained_bytes).with(D::OpenFiles, 4)
            .with(D::MetadataEntries, 4 * 12))
            .map_err(Into::into)
    }

    /// Requires this same original's paid fixed stage before arming name custody.
    ///
    /// # Errors
    /// Refuses missing payment, later-stage reentry or any retained original debt.
    pub(crate) fn require_fixed_named_preparation(&mut self) -> Result<(), JournalError> {
        if !self.fixed_admitted || self.captured_admitted || self.peak.closed
            || matches!(self.peak.geometry, Some(Err(_))) || self.ledger.failure().is_some()
        {
            self.peak.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Admits Native representations from the same original's captured extent.
    ///
    /// # Errors
    /// Rejects wrong stage, inconsistent extent, overflow, or ledger refusal.
    pub(crate) fn admit_captured_native(
        &mut self,
        extent: &ProtectedJournalPreopenReplayExtentV1,
    ) -> Result<(), JournalError> {
        if !self.fixed_admitted || self.captured_admitted {
            self.peak.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.captured_admitted = true;
        self.captured_file_end = Some(extent.native_bytes());
        self.peak.geometry = Some((|| {
            let native = extent.dominant_native_receiving_demand_v1()?;
            let keys = extent.dominant_semantic_receiving_demand_v1()?;
            let index = CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(*extent)?;
            let history = aos_sandbox_ledger_replay::geometry::retained_challenge_history_demand_v1(extent.native_bytes())?;
            Ok::<_, SourceReadonlyDemandErrorV1>(native.checked_add(keys)?.checked_add(index)?.checked_add(history)?)
        })());
        let demand = self.peak.geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        self.peak.geometry = Some(self.native.checked_add(demand).map_err(Into::into));
        self.native = self.peak.geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        self.peak.reserve_peak(self.ledger, self.native)
    }

    /// Joins the held capture length to this same loan's admitted extent.
    ///
    /// Only the shared retained opener supplies this actual captured length,
    /// before the existing parser acquires replay or model representations.
    ///
    /// # Errors
    /// Refuses missing admission or a different extent and closes the peak on
    /// mismatch, preventing later growth or reuse of the failed attempt.
    pub(crate) fn require_captured_file_end(&mut self, actual_end: u64) -> Result<(), JournalError> {
        self.require_replay_admitted()?;
        if self.captured_file_end != Some(actual_end) {
            self.peak.closed = true;
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Observes exact COMMIT DATA from the same existing Native parser.
    ///
    /// # Errors
    /// Refuses unpaid/closed replay or the retained exact suffix comparison.
    /// The actual typed comparison cause stays on its borrowed connection owner.
    pub(crate) fn observe_native_commit(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), JournalError> {
        self.require_replay_admitted()?;
        if let Some(suffix) = self.history_pair.as_mut() {
            suffix.observe(transaction, begin_sequence, commit_sequence, begin_offset, end_offset)
                .map_err(|_| JournalError::ProtectedBoundary)?;
        }
        Ok(())
    }

    /// Joins final durable coordinates to the same actually admitted file end.
    ///
    /// # Errors
    /// Refuses missing admission, absent/extra/partial suffix, or reentry while
    /// preserving the exact comparison cause on the same borrowed observer.
    pub(crate) fn finish_native_replay(
        &mut self,
        durable_next: u64,
        durable_end: u64,
    ) -> Result<(), JournalError> {
        self.require_replay_admitted()?;
        if let Some(suffix) = self.history_pair.as_mut() {
            suffix.finish(durable_next, durable_end,
                self.captured_file_end.ok_or(JournalError::ProtectedBoundary)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            self.history_pair_finished = true;
        }
        Ok(())
    }

    /// Requires the actual CurrentCut branch's completed attached suffix.
    ///
    /// # Errors
    /// Refuses absent or incomplete comparison; selected signing cannot stand in
    /// for the distinct CurrentCut proof. This Boolean state grants no authority.
    pub(crate) fn require_history_pair_finished(&self) -> Result<(), JournalError> {
        self.require_replay_admitted()?;
        if !self.history_pair_finished || self.history_pair.as_ref().is_none_or(|suffix| suffix.failure().is_some()) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn require_replay_admitted(&self) -> Result<(), JournalError> {
        if !self.captured_admitted || self.captured_file_end.is_none()
            || self.peak.closed || matches!(self.peak.geometry, Some(Err(_)))
            || self.ledger.failure().is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn before_delete_current_commit_v3(&mut self,
        pending: &aos_sandbox_ledger_replay::delete_pending::SourceDeletePendingReplayDataV1,
        commit: &aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>,
    ) -> Result<(), JournalError> {
        self.admit_delete_observation_demand_v3(pending.commit_observation_receiving_demand_v3(commit))
    }

    pub(crate) fn before_delete_current_prefix_v3(&mut self,
        pending: &aos_sandbox_ledger_replay::delete_pending::SourceDeletePendingReplayDataV1,
        prefix: &aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>,
    ) -> Result<(), JournalError> {
        self.admit_delete_observation_demand_v3(pending.prefix_observation_receiving_demand_v3(prefix))
    }

    fn admit_delete_observation_demand_v3(&mut self, selected: Result<ResourceVector, JournalError>)
        -> Result<(), JournalError>
    {
        if !self.captured_admitted || matches!(self.peak.geometry, Some(Err(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let base = self.peak.geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        self.peak.geometry = Some(selected.map_err(SourceReadonlyDemandErrorV1::from)
            .and_then(|selected| base.checked_add(selected).map_err(Into::into)));
        let total = self.peak.geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        self.peak.reserve_peak(self.ledger, total)
    }

    /// Admits the actual raw current/proposed semantic carriers before reducers.
    ///
    /// # Errors
    /// Rejects an unpaid capture, sticky geometry failure, overflow, or refusal
    /// from the same original ledger before typed collection growth.
    pub(crate) fn before_semantic_replay(
        &mut self,
        state: &State,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(), JournalError> {
        if !self.captured_admitted || matches!(self.peak.geometry, Some(Err(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.peak.geometry = Some((|| {
            let mut demand = aos_sandbox_ledger_replay::geometry::complete_replay_demand_v1(state, transaction)?;
            if let Some(project) = self.current_project {
                let current = state.iter().map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice()));
                let reached = CurrentTree::receiving_dynamic_demand_v1(current, project)?;
                demand = demand.checked_add(reached).map_err(SourceReadonlyDemandErrorV1::from)?;
                if let Some(transaction) = transaction {
                    let proposed = transaction.records().iter().map(|record| {
                        (record.namespace(), record.key(), record.value().unwrap_or_default())
                    });
                    let reached = CurrentTree::receiving_dynamic_demand_v1(proposed, project)?;
                    demand = demand.checked_add(reached).map_err(SourceReadonlyDemandErrorV1::from)?;
                }
            }
            Ok::<_, SourceReadonlyDemandErrorV1>(demand)
        })());
        let demand = self.peak.geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        self.peak.geometry = Some(self.native.checked_add(demand).map_err(Into::into));
        let total = self.peak.geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        self.peak.reserve_peak(self.ledger, total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_lane_cannot_reenter_or_finish_into_a_reusable_peak() {
        let mut peak = SourceReadonlyPeakV1::new();
        peak.begin().unwrap();
        peak.retain_failed_lane();

        peak.finish_after_actual_positive_disposal();

        assert!(peak.begin().is_err());
        assert!(peak.active);
        assert!(peak.closed);
    }

    #[test]
    fn exact_geometry_error_survives_reentry_and_attempted_completion() {
        let mut peak = SourceReadonlyPeakV1::new();
        peak.begin().unwrap();
        peak.geometry = Some(Err(SourceReadonlyDemandErrorV1::Journal(
            JournalError::LimitExceeded("retained native geometry fixture"),
        )));
        let before = peak.failure().unwrap() as *const SourceReadonlyDemandErrorV1;

        assert!(peak.begin().is_err());
        peak.finish_after_actual_positive_disposal();

        assert_eq!(peak.failure().unwrap() as *const SourceReadonlyDemandErrorV1, before);
        assert!(peak.active);
        assert!(peak.closed);
    }
}

#[cfg(test)]
mod history_suffix_tests;
