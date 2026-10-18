//! Retains post-owner verifier commitments without retaining disposable DTO caches.
//!
//! An inline pending row precedes each ledger allocation. Genuine full owner
//! observation admits the next bank and prewalk, then its actual constructor
//! row, before their respective work. Earlier commitments are never refunded.

use super::*;
use crate::node_contract::{OriginalLineageWorldCapture, RestoredCollectingCaptureScope17};
use crate::node_state::{
    NativeArchiveRecord, RestoredArchive17ValidationConstructionData,
    RestoredArchive17ValidationPrewalkData, RestoredArchive17ValidationStage,
    RestoredArchive17ValidationStep,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Phase {
    #[default]
    Empty,
    PendingBank,
    PrewalkAdmitted,
    RowCommitted,
    Constructing,
    StageCompleted,
    Completed,
    Failed,
}

struct StageCommitment {
    prewalk: RestoredArchive17ValidationPrewalkData,
    constructor: Option<RestoredArchive17ValidationConstructionData>,
    bank_work: (usize, usize, usize),
    completed_cache: Option<usize>,
}

impl StageCommitment {
    fn future_requested_bytes_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let mut total = checked_sum(
            &[
                self.bank_work.0,
                self.bank_work.1,
                self.bank_work.2,
                self.prewalk
                    .outer_transient_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            ],
            maximum,
        )?;
        if let Some(row) = &self.constructor {
            total = checked_sum(
                &[
                    total,
                    row.outer_transient_bytes_data()
                        .map_err(|_| RuntimeError::ResourceLimit)?,
                ],
                maximum,
            )?;
        }
        Ok(total)
    }
}

/// Retains actual numeric rows and spent occurrences beneath the capture attempt.
#[derive(Default)]
pub(super) struct RetainedTerminal17 {
    phase: Cell<Phase>,
    pending: RefCell<Option<StageCommitment>>,
    rows: RefCell<Vec<StageCommitment>>,
}

impl RetainedTerminal17 {
    /// Counts actual allocated history backing beyond the containing inline root.
    ///
    /// # Errors
    /// Refuses busy custody or requested-layout overflow.
    pub(super) fn retained_requested_backing_data(&self) -> Result<usize, RuntimeError> {
        self.rows
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .capacity()
            .checked_mul(size_of::<StageCommitment>())
            .ok_or(RuntimeError::ResourceLimit)
    }

    /// Preserves every prewalk, bank and constructor commitment independently.
    ///
    /// # Errors
    /// Refuses busy custody, layout overflow or the unchanged global ceiling.
    pub(super) fn future_requested_bytes_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let pending = self
            .pending
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let rows = self
            .rows
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let mut total = 0usize;
        for row in pending.iter().chain(rows.iter()) {
            total = checked_sum(&[total, row.future_requested_bytes_data(maximum)?], maximum)?;
        }
        Ok(total)
    }

    /// Refuses a failed terminal occurrence without inventing a completion grant.
    ///
    /// # Errors
    /// Refuses a failed constructor, row, reserve or completed-writer attempt.
    pub(super) fn authenticate_current_data(&self) -> Result<(), RuntimeError> {
        if self.phase.get() == Phase::Failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    /// Retains failure independently of the disposable parser cache's lifetime.
    pub(super) fn fail_data(&self) {
        self.phase.set(Phase::Failed);
    }

    /// Requires the full ordered finite verifier conjunction before publication.
    ///
    /// # Errors
    /// Refuses unfinished stages or a failed terminal occurrence.
    pub(super) fn require_completed_data(&self) -> Result<(), RuntimeError> {
        if self.phase.get() != Phase::Completed {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

/// Poisons refusal and unwind while preserving every pending and appended row.
struct MutationGuard<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    attempt: &'a Attempt,
    completed: bool,
}

impl<'a> MutationGuard<'a> {
    fn new(window: &'a CompleteOriginalRestorationWindow, attempt: &'a Attempt) -> Self {
        Self {
            window,
            attempt,
            completed: false,
        }
    }

    fn finish_data(&mut self) {
        self.completed = true;
    }
}

impl Drop for MutationGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.attempt.terminal.fail_data();
            self.attempt.stage.set(Stage::Failed);
            self.window.whole_observation.require_observation();
        }
    }
}

impl CompleteOriginalRestorationWindow {
    /// Authenticates all completed real owner outputs before terminal accounting.
    fn authenticate_terminal_context_data(
        &self,
        attempt: &Attempt,
        scope: &RestoredCollectingCaptureScope17<'_>,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
    ) -> Result<(), RuntimeError> {
        scope.authenticate_runtime_data(runtime)?;
        let manifest = archive.manifest();
        if !scope.same_window_data(self)
            || attempt.stage.get() != Stage::Admitted
            || !std::ptr::eq(attempt.runtime, runtime)
            || attempt.capture_id != *scope.capture_id_data()
            || attempt.capture_id != manifest.capture_id
            || attempt.cut != manifest.cut
            || attempt.ordinal != manifest.event_ordinal
            || attempt.members.iter().any(|member| member.get() != 2)
            || attempt.writer_join.get() != checkpoint::WriterJoinStage::Verified
            || !self
                .activation_world
                .get()
                .is_some_and(|actual| actual.same_authority(scope.world_data()))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        attempt.terminal.authenticate_current_data()?;
        attempt.host.with_prepared_writing_data(|prepared| {
            capture.authenticate_restored_terminal_data(runtime, scope, archive, prepared)
        })
    }

    /// Authenticates terminal failure custody without borrowing the parser cache.
    ///
    /// # Errors
    /// Refuses another capture slot, busy custody or a failed terminal occurrence.
    pub(crate) fn authenticate_restored_terminal17_phase_data(
        &self,
        slot: usize,
    ) -> Result<(), RuntimeError> {
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        ledger.active(slot)?.terminal.authenticate_current_data()
    }

    /// Retains the next bank and real prewalk row before either can allocate.
    ///
    /// # Errors
    /// Refuses incomplete actual outputs, stale custody, duplicate or out-of-order
    /// stages, busy owner loans, arithmetic overflow or independent policy excess.
    pub(crate) fn retain_terminal_validation_prewalk_data(
        &self,
        slot: usize,
        scope: &RestoredCollectingCaptureScope17<'_>,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
        prewalk: RestoredArchive17ValidationPrewalkData,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        self.authenticate_terminal_context_data(attempt, scope, runtime, capture, archive)?;
        let terminal = &attempt.terminal;
        let mut guard = MutationGuard::new(self, attempt);
        if !matches!(terminal.phase.get(), Phase::Empty | Phase::StageCompleted) {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut pending = terminal
            .pending
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let rows = terminal
            .rows
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if pending.is_some() || rows.last().is_some_and(|row| row.completed_cache.is_none()) {
            return Err(RuntimeError::OutstandingObligations);
        }
        authenticate_next_step_data(&rows, prewalk.step_data())?;
        let next_count = rows
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        let next_bank = next_count
            .checked_mul(size_of::<StageCommitment>())
            .ok_or(RuntimeError::ResourceLimit)?;
        let old_bank = rows
            .capacity()
            .checked_mul(size_of::<StageCommitment>())
            .ok_or(RuntimeError::ResourceLimit)?;
        let bank_work = (
            next_bank,
            old_bank
                .checked_add(next_bank)
                .ok_or(RuntimeError::ResourceLimit)?,
            counter_scratch_data(),
        );
        *pending = Some(StageCommitment {
            prewalk,
            constructor: None,
            bank_work,
            completed_cache: None,
        });
        terminal.phase.set(Phase::PendingBank);
        self.whole_observation.require_observation();
        let pending = pending.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        pending.future_requested_bytes_data(self.policy.maximum_requested_bytes)?;
        if prewalk.counter_scratch_bytes_data() > self.policy.declared_observer_scratch_bytes
            || bank_work.2 > self.policy.declared_observer_scratch_bytes
        {
            return Err(RuntimeError::ResourceLimit);
        }
        guard.finish_data();
        Ok(())
    }

    /// Appends the independently observed pending row to its funded ledger bank.
    ///
    /// # Errors
    /// Refuses missing credit, reuse, failed allocation or an allocator extent
    /// beyond the exact declared next bank; all initialized backing is retained.
    pub(crate) fn append_terminal_validation_phase_data(
        &self,
        slot: usize,
        scope: &RestoredCollectingCaptureScope17<'_>,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        self.authenticate_terminal_context_data(attempt, scope, runtime, capture, archive)?;
        let terminal = &attempt.terminal;
        let mut guard = MutationGuard::new(self, attempt);
        if terminal.phase.get() != Phase::PendingBank {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut pending = terminal
            .pending
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let mut rows = terminal
            .rows
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let row = pending.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        authenticate_next_step_data(&rows, row.prewalk.step_data())?;
        let next_count = rows
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        let maximum_bank = row.bank_work.0;
        // The pending row remains the actual owner if reservation refuses.
        // The previous bank and its spare capacity are never discarded on error.
        self.whole_observation.require_observation();
        rows.try_reserve_exact(1)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        if rows
            .capacity()
            .checked_mul(size_of::<StageCommitment>())
            .ok_or(RuntimeError::ResourceLimit)?
            > maximum_bank
            || rows.capacity() < next_count
        {
            return Err(RuntimeError::ResourceLimit);
        }
        rows.push(pending.take().ok_or(RuntimeError::OwnerUnavailable)?);
        terminal.phase.set(Phase::PrewalkAdmitted);
        guard.finish_data();
        Ok(())
    }

    /// Retains one actual constructor row as independent outer transient work.
    ///
    /// # Errors
    /// Refuses a changed step or prior-cache census, reuse, unfinished prewalk,
    /// stale completed-output custody or insufficient independently declared axes.
    pub(crate) fn retain_terminal_validation_row_data(
        &self,
        slot: usize,
        scope: &RestoredCollectingCaptureScope17<'_>,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
        row: RestoredArchive17ValidationConstructionData,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        self.authenticate_terminal_context_data(attempt, scope, runtime, capture, archive)?;
        let terminal = &attempt.terminal;
        let mut guard = MutationGuard::new(self, attempt);
        if terminal.phase.get() != Phase::PrewalkAdmitted {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut rows = terminal
            .rows
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let last = rows.last_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        if last.constructor.is_some() || last.completed_cache.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Save even a refused numeric row. No earlier whole observation covers
        // this new commitment, and a malformed result cannot renew its phase.
        last.constructor = Some(row);
        terminal.phase.set(Phase::RowCommitted);
        self.whole_observation.require_observation();
        if row.step_data() != last.prewalk.step_data()
            || row.prior_cache_retained_bytes_data()
                != last.prewalk.prior_cache_retained_bytes_data()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        last.future_requested_bytes_data(self.policy.maximum_requested_bytes)?;
        if row.counter_scratch_bytes_data() > self.policy.declared_observer_scratch_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        guard.finish_data();
        Ok(())
    }

    /// Starts the actual constructor only after its complete row was observed.
    ///
    /// # Errors
    /// Refuses unobserved credit, stale output custody, another step or reuse.
    pub(crate) fn begin_terminal_validation_constructor_data(
        &self,
        slot: usize,
        scope: &RestoredCollectingCaptureScope17<'_>,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
        step: RestoredArchive17ValidationStep,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        self.authenticate_terminal_context_data(attempt, scope, runtime, capture, archive)?;
        let terminal = &attempt.terminal;
        let mut guard = MutationGuard::new(self, attempt);
        if terminal.phase.get() != Phase::RowCommitted {
            return Err(RuntimeError::OutstandingObligations);
        }
        let rows = terminal
            .rows
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let last = rows.last().ok_or(RuntimeError::OwnerUnavailable)?;
        if last.prewalk.step_data() != step
            || last.constructor.is_none()
            || last.completed_cache.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        terminal.phase.set(Phase::Constructing);
        // This once transition allocates no bank and adds no new commitment.
        // Actual constructor failure is retained by the enclosing Host RAII guard.
        guard.finish_data();
        Ok(())
    }

    /// Retains the actual completed cache census and spends this constructor once.
    ///
    /// # Errors
    /// Refuses another step, reuse, missing actual output custody or actual cache
    /// backing beyond the independently admitted prior-plus-new retained bound.
    pub(crate) fn finish_terminal_validation_stage_data(
        &self,
        slot: usize,
        scope: &RestoredCollectingCaptureScope17<'_>,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
        step: RestoredArchive17ValidationStep,
        actual_cache_retained: usize,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        self.authenticate_terminal_context_data(attempt, scope, runtime, capture, archive)?;
        let terminal = &attempt.terminal;
        let mut guard = MutationGuard::new(self, attempt);
        if terminal.phase.get() != Phase::Constructing {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut rows = terminal
            .rows
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let last = rows.last_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        let row = last
            .constructor
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if last.prewalk.step_data() != step || last.completed_cache.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        last.completed_cache = Some(actual_cache_retained);
        self.whole_observation.require_observation();
        if actual_cache_retained
            > row
                .maximum_cache_retained_bytes_data()
                .map_err(|_| RuntimeError::ResourceLimit)?
        {
            return Err(RuntimeError::ResourceLimit);
        }
        terminal.phase.set(
            if step.stage_data() == RestoredArchive17ValidationStage::FinalConjunction {
                Phase::Completed
            } else {
                Phase::StageCompleted
            },
        );
        guard.finish_data();
        Ok(())
    }

    /// Requires the actual ordered terminal conjunction before signing.
    ///
    /// # Errors
    /// Refuses incomplete verification, stale real owner outputs or pending census.
    pub(crate) fn require_terminal_validation_completed_data(
        &self,
        slot: usize,
        scope: &RestoredCollectingCaptureScope17<'_>,
        runtime: &NodeRuntime,
        capture: &OriginalLineageWorldCapture,
        archive: &NativeArchiveRecord,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        self.authenticate_terminal_context_data(attempt, scope, runtime, capture, archive)?;
        attempt.terminal.require_completed_data()
    }
}

fn authenticate_next_step_data(
    rows: &[StageCommitment],
    step: RestoredArchive17ValidationStep,
) -> Result<(), RuntimeError> {
    let previous = rows.last().map(|row| row.prewalk.step_data());
    step.authenticate_transition_data(previous)
        .map_err(|_| RuntimeError::ForeignAuthority)?;
    let slot = step.stage_data().slot_data();
    if slot >= RestoredArchive17ValidationStage::STAGE_COUNT {
        return Err(RuntimeError::ForeignAuthority);
    }
    match previous {
        Some(previous) => {
            let previous_slot = previous.stage_data().slot_data();
            if slot != previous_slot && previous_slot.checked_add(1) != Some(slot) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        None if slot != 0 => return Err(RuntimeError::ForeignAuthority),
        None => {}
    }
    if rows.iter().any(|row| row.prewalk.step_data() == step) {
        return Err(RuntimeError::DuplicateOperation);
    }
    Ok(())
}

/// Names actual numeric owners, vector/option iterators and borrowed stage views.
pub(super) fn counter_scratch_data() -> usize {
    use std::cell::{Ref, RefMut};
    type Rows = Vec<StageCommitment>;
    type Pending = Option<StageCommitment>;
    size_of::<RetainedTerminal17>()
        + size_of::<StageCommitment>()
        + size_of::<Phase>()
        + size_of::<MutationGuard<'static>>()
        + size_of::<RestoredArchive17ValidationPrewalkData>()
        + size_of::<RestoredArchive17ValidationConstructionData>()
        + size_of::<RestoredArchive17ValidationStep>()
        + size_of::<Option<RestoredArchive17ValidationStep>>()
        + size_of::<Result<usize, crate::node_state::StateError>>()
        + size_of::<Ref<'static, Rows>>()
        + size_of::<RefMut<'static, Rows>>()
        + size_of::<Ref<'static, Pending>>()
        + size_of::<RefMut<'static, Pending>>()
        + size_of::<Result<Ref<'static, Rows>, std::cell::BorrowError>>()
        + size_of::<Result<RefMut<'static, Rows>, std::cell::BorrowMutError>>()
        + size_of::<Result<Ref<'static, Pending>, std::cell::BorrowError>>()
        + size_of::<Result<RefMut<'static, Pending>, std::cell::BorrowMutError>>()
        + size_of::<
            std::iter::Chain<
                std::option::Iter<'static, StageCommitment>,
                std::slice::Iter<'static, StageCommitment>,
            >,
        >()
        + size_of::<Option<&'static StageCommitment>>()
        + size_of::<Option<&'static mut StageCommitment>>()
        + size_of::<[usize; 3]>()
        + size_of::<usize>()
        + OriginalLineageWorldCapture::restored_terminal_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numeric_row(stage: RestoredArchive17ValidationStage) -> StageCommitment {
        numeric_step(RestoredArchive17ValidationStep::ordinary_data(stage).unwrap())
    }

    fn numeric_step(step: RestoredArchive17ValidationStep) -> StageCommitment {
        StageCommitment {
            prewalk: RestoredArchive17ValidationPrewalkData::new_data(step, 19, 23, 29).unwrap(),
            constructor: Some(
                RestoredArchive17ValidationConstructionData::new_data(step, 19, 31, 37, 41)
                    .unwrap(),
            ),
            bank_work: (11, 13, 17),
            completed_cache: Some(50),
        }
    }

    #[test]
    fn failed_terminal_keeps_both_independent_rows_and_actual_history_backing() {
        let terminal = RetainedTerminal17::default();
        terminal
            .rows
            .borrow_mut()
            .push(numeric_row(RestoredArchive17ValidationStage::MetadataDag));
        let backing = terminal.retained_requested_backing_data().unwrap();
        assert!(backing >= size_of::<StageCommitment>());
        assert_eq!(terminal.future_requested_bytes_data(240).unwrap(), 240);

        terminal.fail_data();

        assert_eq!(terminal.retained_requested_backing_data().unwrap(), backing);
        assert_eq!(terminal.future_requested_bytes_data(240).unwrap(), 240);
        assert!(terminal.future_requested_bytes_data(239).is_err());
        assert!(terminal.authenticate_current_data().is_err());
        assert!(terminal.require_completed_data().is_err());
    }

    #[test]
    fn inline_pending_row_stays_counted_when_no_history_bank_exists() {
        let terminal = RetainedTerminal17::default();
        *terminal.pending.borrow_mut() =
            Some(numeric_row(RestoredArchive17ValidationStage::MetadataDag));

        terminal.fail_data();

        assert_eq!(terminal.retained_requested_backing_data().unwrap(), 0);
        assert_eq!(terminal.future_requested_bytes_data(240).unwrap(), 240);
        assert!(terminal.pending.borrow().is_some());
        assert!(terminal.rows.borrow().is_empty());
    }

    #[test]
    fn terminal_order_rejects_duplicate_and_skipped_constructor_buckets() {
        let rows = [numeric_row(RestoredArchive17ValidationStage::MetadataDag)];
        let next = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::ContentClosure,
        )
        .unwrap();
        let skipped = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::Administrative,
        )
        .unwrap();

        assert!(authenticate_next_step_data(&rows, next).is_ok());
        assert!(authenticate_next_step_data(&rows, skipped).is_err());
        assert!(authenticate_next_step_data(&rows, rows[0].prewalk.step_data()).is_err());
        assert!(authenticate_next_step_data(&[], next).is_err());
    }

    #[test]
    fn parent_rows_reject_repeated_full_keys_and_wrong_source_buckets() {
        use crate::node_state::{RestoredArchive17ParentWork, RestoredArchive17SourceIndex};
        let source = RestoredArchive17SourceIndex::from_data(0).unwrap();
        let foreign = RestoredArchive17SourceIndex::from_data(1).unwrap();
        let reference = crucible_node_contract::canonical::content_ref(
            b"actual parent DATA",
            "application/vnd.crucible.native-signed-index-body.v3+json",
        )
        .unwrap();
        let parent = RestoredArchive17ValidationStep::parent_data(
            source,
            0,
            &reference,
            RestoredArchive17ParentWork::IndexDecode,
        )
        .unwrap();
        let inventory = RestoredArchive17ValidationStep::parent_data(
            source,
            0,
            &reference,
            RestoredArchive17ParentWork::Inventory,
        )
        .unwrap();
        let wrong_source = RestoredArchive17ValidationStep::parent_data(
            foreign,
            0,
            &reference,
            RestoredArchive17ParentWork::IndexDecode,
        )
        .unwrap();
        let last_first_observation_source = RestoredArchive17SourceIndex::from_data(2).unwrap();
        let previous = numeric_row(RestoredArchive17ValidationStage::Node(
            last_first_observation_source,
        ));
        assert!(authenticate_next_step_data(std::slice::from_ref(&previous), parent).is_ok());
        assert!(
            authenticate_next_step_data(std::slice::from_ref(&previous), wrong_source).is_err()
        );

        let rows = [previous, numeric_step(parent)];

        assert!(authenticate_next_step_data(&rows, parent).is_err());
        assert!(authenticate_next_step_data(&rows, inventory).is_ok());
        assert!(RestoredArchive17SourceIndex::from_data(3).is_err());
    }

    #[test]
    fn native_rows_follow_real_subwork_and_cannot_leave_a_partial_pair() {
        use crate::node_state::RestoredArchive17SourceIndex;
        use crucible_node_provider::protocol_snapshot::restored_settled17::NativeCold17Work;
        let source = RestoredArchive17SourceIndex::from_data(0).unwrap();
        let foreign = RestoredArchive17SourceIndex::from_data(1).unwrap();
        let mut rows = vec![numeric_row(RestoredArchive17ValidationStage::SdkCapture(
            source,
        ))];
        let after = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::SemanticEnvelope(source),
        )
        .unwrap();
        let skipped =
            RestoredArchive17ValidationStep::native_data(source, NativeCold17Work::RawInputs);
        assert!(authenticate_next_step_data(&rows, skipped).is_err());
        assert!(
            RestoredArchive17ValidationStep::ordinary_data(
                RestoredArchive17ValidationStage::Native(source),
            )
            .is_err()
        );

        for work in [
            NativeCold17Work::Framing,
            NativeCold17Work::RawInputs,
            NativeCold17Work::BeforeGraphBanks,
            NativeCold17Work::BeforeGraphTargets,
            NativeCold17Work::AfterGraphBanks,
            NativeCold17Work::AfterGraphTargets,
            NativeCold17Work::OutputPairQuote,
            NativeCold17Work::OutputPair,
            NativeCold17Work::RestorationHoldQuote,
            NativeCold17Work::RestorationHold,
        ] {
            let step = RestoredArchive17ValidationStep::native_data(source, work);
            assert!(authenticate_next_step_data(&rows, step).is_ok());
            rows.push(numeric_step(step));
            assert!(authenticate_next_step_data(&rows, step).is_err());
            assert!(
                authenticate_next_step_data(
                    &rows,
                    RestoredArchive17ValidationStep::native_data(foreign, work),
                )
                .is_err()
            );
            assert_eq!(
                authenticate_next_step_data(&rows, after).is_ok(),
                work.is_final_data()
            );
        }
    }

    #[test]
    fn held_numeric_bank_loan_cannot_hide_retained_or_future_storage() {
        let terminal = RetainedTerminal17::default();
        let loan = terminal.rows.borrow_mut();

        assert!(matches!(
            terminal.retained_requested_backing_data(),
            Err(RuntimeError::OwnerBusy)
        ));
        assert!(matches!(
            terminal.future_requested_bytes_data(usize::MAX),
            Err(RuntimeError::OwnerBusy)
        ));

        drop(loan);
        assert_eq!(terminal.retained_requested_backing_data().unwrap(), 0);
        assert_eq!(terminal.future_requested_bytes_data(usize::MAX).unwrap(), 0);
    }
}
