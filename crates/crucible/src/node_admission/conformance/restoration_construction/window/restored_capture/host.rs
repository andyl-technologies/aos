//! Retains the same admitted Host17 occurrence across independently observed phases.
//!
//! Fixed prewalk work precedes its serializer. The actual returned construction
//! row precedes every constructor allocation. Full observation runs outside all
//! private mutable loans; failures retain partial producers and spent phases.

use super::*;
use crate::node_contract::{
    HostSchedulingContinuationLimits, HostSchedulingRestoredCaptureAttempt17,
    HostSchedulingRestoredContinuation17, HostSchedulingSource, PreparedRestoredHost17Capture,
    RestoredHost17CaptureConstructionData,
};
use crate::node_scheduling::SchedulingSnapshot;
use crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentCheckpoint17;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum HostPhase {
    #[default]
    Empty,
    PrewalkAdmitted,
    Quoting,
    Quoted,
    Constructing,
    Constructed,
    Preparing,
    Ready,
    Writing,
    Spent,
    Failed,
}

#[derive(Default)]
struct Host17Owners {
    limits: Option<HostSchedulingContinuationLimits>,
    row: Option<RestoredHost17CaptureConstructionData>,
    pending: Option<HostSchedulingRestoredCaptureAttempt17>,
    output: Option<HostSchedulingRestoredContinuation17>,
    prepared: Option<Rc<PreparedRestoredHost17Capture>>,
}

/// Owns one distinct current17 Host preparation beneath the actual Window attempt.
#[derive(Default)]
pub(super) struct RetainedHost17Capture {
    phase: Cell<HostPhase>,
    prewalk: Cell<Option<(usize, usize, usize)>>,
    owners: RefCell<Host17Owners>,
}

impl RetainedHost17Capture {
    /// Counts only backing beyond the enclosing attempt's already counted slots.
    ///
    /// # Errors
    /// Refuses busy private custody or checked storage-layout overflow.
    pub(super) fn retained_requested_backing_data(&self) -> Result<usize, RuntimeError> {
        let owners = self
            .owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let mut total = 0usize;
        if let Some(pending) = &owners.pending {
            total = total
                .checked_add(
                    pending
                        .retained_requested_storage_data()?
                        .checked_sub(size_of::<HostSchedulingRestoredCaptureAttempt17>())
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(output) = &owners.output {
            total = total
                .checked_add(
                    output
                        .retained_requested_storage_data()?
                        .checked_sub(size_of::<HostSchedulingRestoredContinuation17>())
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        if let Some(prepared) = &owners.prepared {
            total = total
                .checked_add(prepared.retained_requested_storage_data()?)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        Ok(total)
    }

    /// Preserves earlier commitments even after their temporary work has ended.
    ///
    /// # Errors
    /// Refuses busy private custody, layout overflow or the independent limit.
    pub(super) fn future_requested_bytes_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let owners = self
            .owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let prewalk = self.prewalk.get().unwrap_or((0, 0, 0));
        let mut total = checked_sum(&[prewalk.0, prewalk.1, prewalk.2], maximum)?;
        if let Some(row) = &owners.row {
            total = checked_sum(
                &[
                    total,
                    row.retained_requested_bytes_data(),
                    row.maximum_simultaneous_transient_bytes_data(),
                    row.declared_counter_scratch_bytes_data(),
                ],
                maximum,
            )?;
        }
        Ok(total)
    }

    /// Requires the actual enclosing writer loan before a Source effect claim.
    ///
    /// # Errors
    /// Refuses every phase except the live writer occurrence.
    pub(super) fn require_writing_data(&self) -> Result<(), RuntimeError> {
        if self.phase.get() != HostPhase::Writing {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    /// Lends the actual writer-owned capsule without copying its shared handle.
    ///
    /// # Errors
    /// Refuses another phase, busy ownership or an absent prepared occurrence.
    pub(super) fn with_prepared_writing_data<R>(
        &self,
        inspect: impl FnOnce(&Rc<PreparedRestoredHost17Capture>) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.require_writing_data()?;
        let owners = self
            .owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let prepared = owners
            .prepared
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        inspect(prepared)
    }

    /// Requires a successfully consumed Host producer before final publication.
    ///
    /// # Errors
    /// Refuses incomplete, failed or still executing writer occurrences.
    pub(super) fn require_spent_data(&self) -> Result<(), RuntimeError> {
        if self.phase.get() != HostPhase::Spent {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    /// Allows an already consumed producer between owners, never a failed phase.
    fn authenticate_current_data(&self) -> Result<(), RuntimeError> {
        match self.phase.get() {
            HostPhase::Quoting
            | HostPhase::Constructing
            | HostPhase::Preparing
            | HostPhase::Failed => Err(RuntimeError::OutstandingObligations),
            _ => Ok(()),
        }
    }
}

/// Poisons a failed or unwound phase without discarding any initialized owner.
struct HostMutationGuard<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    attempt: &'a Attempt,
    completed: bool,
}

impl<'a> HostMutationGuard<'a> {
    fn begin_data(
        window: &'a CompleteOriginalRestorationWindow,
        attempt: &'a Attempt,
        expected: HostPhase,
        active: HostPhase,
    ) -> Result<Self, RuntimeError> {
        if attempt.host.phase.get() != expected {
            attempt.host.phase.set(HostPhase::Failed);
            attempt.terminal.fail_data();
            attempt.stage.set(Stage::Failed);
            window.whole_observation.require_observation();
            return Err(RuntimeError::OutstandingObligations);
        }
        attempt.host.phase.set(active);
        Ok(Self {
            window,
            attempt,
            completed: false,
        })
    }

    fn finish_data(&mut self, phase: HostPhase) {
        self.attempt.host.phase.set(phase);
        self.completed = true;
    }
}

impl Drop for HostMutationGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.attempt.host.phase.set(HostPhase::Failed);
            self.attempt.terminal.fail_data();
            self.attempt.stage.set(Stage::Failed);
            self.window.whole_observation.require_observation();
        }
    }
}

impl CompleteOriginalRestorationWindow {
    /// Validates local current owners before entering a private Host bank loan.
    fn authenticate_restored_host17_attempt_data(
        &self,
        attempt: &Attempt,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        host: &HostSchedulingSource,
    ) -> Result<(), RuntimeError> {
        if attempt.stage.get() != Stage::Admitted
            || !std::ptr::eq(attempt.runtime, runtime)
            || attempt.members.iter().any(|member| member.get() != 0)
            || attempt.writer_join.get() != checkpoint::WriterJoinStage::Waiting
            || !self
                .activation_world
                .get()
                .is_some_and(|actual| actual.same_authority(world))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        attempt
            .boundary
            .authenticate_runtime_data(runtime, world, host)?;
        attempt.runtime_row.authenticate_original_data(
            runtime,
            world,
            attempt.cut,
            attempt.ordinal,
        )?;
        let (runtime_object, _) = attempt.checkpoint_inputs.objects_data()?;
        attempt.checkpoint.object_for_runtime_data(runtime_object)?;
        Ok(())
    }

    /// Retains fixed Host prewalk credit before the actual counting serializer.
    ///
    /// The caller performs a full owner observation after this mutation and
    /// before requesting the actual row. Refusal never renews the phase.
    ///
    /// # Errors
    /// Refuses stale owners, unfinished observation, reuse or insufficient credit.
    pub(crate) fn retain_restored_host17_prewalk_data(
        &self,
        slot: usize,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        host: &HostSchedulingSource,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        self.authenticate_restored_host17_attempt_data(attempt, runtime, world, host)?;
        let mut phase =
            HostMutationGuard::begin_data(self, attempt, HostPhase::Empty, HostPhase::Quoting)?;
        let work = (
            0,
            RestoredHost17CaptureConstructionData::counter_transient_bytes_data(),
            RestoredHost17CaptureConstructionData::counter_scratch_data(),
        );
        attempt.host.prewalk.set(Some(work));
        self.whole_observation.require_observation();
        checked_sum(
            &[work.0, work.1, work.2],
            self.policy.maximum_requested_bytes,
        )?;
        if work.2 > self.policy.declared_observer_scratch_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        phase.finish_data(HostPhase::PrewalkAdmitted);
        Ok(())
    }

    /// Retains the real independent row before any Host constructor allocation.
    ///
    /// Its immutable limits are saved with the row and reused by construction.
    /// Whole observation must follow before the next phase can execute.
    ///
    /// # Errors
    /// Refuses stale owners, missing prewalk credit, invalid limits or quote failure.
    pub(crate) fn quote_restored_host17_data(
        &self,
        slot: usize,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        host: &HostSchedulingSource,
        limits: HostSchedulingContinuationLimits,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        self.authenticate_restored_host17_attempt_data(attempt, runtime, world, host)?;
        let mut phase = HostMutationGuard::begin_data(
            self,
            attempt,
            HostPhase::PrewalkAdmitted,
            HostPhase::Quoting,
        )?;
        let result = (|| {
            let mut owners = attempt
                .host
                .owners
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            if owners.row.is_some() || owners.limits.is_some() {
                return Err(RuntimeError::OutstandingObligations);
            }
            owners.limits = Some(limits);
            let (runtime_record, scheduling_record) = attempt.checkpoint_inputs.records_data()?;
            let (runtime_object, _) = attempt.checkpoint_inputs.objects_data()?;
            let observation = runtime.restored_host17_observation_data(host)?;
            owners.row = Some(RestoredHost17CaptureConstructionData::quote_data(
                &observation,
                world,
                &attempt.boundary,
                runtime_record,
                scheduling_record,
                runtime_object,
                limits,
                self.policy.maximum_requested_bytes,
            )?);
            let row = owners.row.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            checked_row_total_data(row, self.policy.maximum_requested_bytes)?;
            if row.declared_counter_scratch_bytes_data()
                > self.policy.declared_observer_scratch_bytes
            {
                return Err(RuntimeError::ResourceLimit);
            }
            Ok(())
        })();
        self.whole_observation.require_observation();
        if result.is_ok() {
            phase.finish_data(HostPhase::Quoted);
        }
        result
    }

    /// Constructs into the actual retained pending and output slots once.
    ///
    /// The full graph census follows after the private mutable loan ends.
    ///
    /// # Errors
    /// Refuses unobserved credit, stale custody, reuse or actual construction failure.
    pub(crate) fn construct_restored_host17_data(
        &self,
        slot: usize,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        host: &HostSchedulingSource,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        self.authenticate_restored_host17_attempt_data(attempt, runtime, world, host)?;
        let mut phase = HostMutationGuard::begin_data(
            self,
            attempt,
            HostPhase::Quoted,
            HostPhase::Constructing,
        )?;
        let result = (|| {
            let mut owners = attempt
                .host
                .owners
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let Host17Owners {
                limits,
                row,
                pending,
                output,
                prepared: _,
            } = &mut *owners;
            let limits = limits.ok_or(RuntimeError::OwnerUnavailable)?;
            let row = row.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            let maximum = checked_row_total_data(row, self.policy.maximum_requested_bytes)?;
            let observation = runtime.restored_host17_observation_data(host)?;
            HostSchedulingRestoredCaptureAttempt17::capture_into(
                &observation,
                world,
                &attempt.boundary,
                limits,
                maximum,
                pending,
                output,
            )
        })();
        self.whole_observation.require_observation();
        result?;
        authenticate_host_retained_row_data(&attempt.host)?;
        phase.finish_data(HostPhase::Constructed);
        Ok(())
    }

    /// Retains the genuine same-source prepared capsule before later guards.
    ///
    /// Both success and failure release the mutable Host loan before the caller
    /// reobserves all owners, including the actual Source dependency-plan growth.
    ///
    /// # Errors
    /// Refuses unobserved construction, changed owners, reuse or preparation failure.
    pub(crate) fn prepare_restored_host17_data(
        &self,
        slot: usize,
        graph: &crate::node_admission::AdmittedGraph,
        runtime: &NodeRuntime,
        world: &WorldActivation,
        host: &HostSchedulingSource,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        self.authenticate_restored_host17_attempt_data(attempt, runtime, world, host)?;
        let mut phase = HostMutationGuard::begin_data(
            self,
            attempt,
            HostPhase::Constructed,
            HostPhase::Preparing,
        )?;
        let result = (|| {
            let mut owners = attempt
                .host
                .owners
                .try_borrow_mut()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let Host17Owners {
                row,
                output,
                prepared,
                ..
            } = &mut *owners;
            let row = row.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            let maximum = checked_row_total_data(row, self.policy.maximum_requested_bytes)?;
            let (runtime_record, scheduling_record) = attempt.checkpoint_inputs.records_data()?;
            let (runtime_object, _) = attempt.checkpoint_inputs.objects_data()?;
            runtime.prepare_restored_host17_capture_into_data(
                graph,
                host,
                world,
                &attempt.boundary,
                runtime_record,
                scheduling_record,
                runtime_object,
                maximum,
                output,
                prepared,
            )
        })();
        self.whole_observation.require_observation();
        result?;
        authenticate_host_retained_row_data(&attempt.host)?;
        phase.finish_data(HostPhase::Ready);
        Ok(())
    }

    /// Authenticates a phase without requiring a spent snapshot to reappear.
    ///
    /// # Errors
    /// Refuses a foreign attempt, busy custody or failed/in-progress construction.
    pub(crate) fn authenticate_restored_host17_phase_data(
        &self,
        slot: usize,
    ) -> Result<(), RuntimeError> {
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        ledger.active(slot)?.host.authenticate_current_data()
    }

    /// Lends retained checkpoints and the actual prepared producer exactly once.
    ///
    /// The callback owns the mutable Runtime loan. It performs genuine full
    /// observations between owner claims; this method does not reenter a census
    /// before the callback can release its Source/SDK/native owner loans.
    ///
    /// # Errors
    /// Refuses stale custody, unfinished preparation, changed checkpoints, reuse,
    /// an unconsumed terminal producer, callback failure or private-owner contention.
    pub(crate) fn with_restored_host17_checkpoint_data<R>(
        &self,
        slot: usize,
        graph: &crate::node_admission::ConformanceGraph,
        runtime: &mut NodeRuntime,
        world: &WorldActivation,
        host: &HostSchedulingSource,
        inspect: impl FnOnce(
            &mut NodeRuntime,
            &OriginalLineageRuntimeRecord,
            &SchedulingSnapshot,
            &InputPayload,
            &InputPayload,
            &CoordinatorCommitmentCheckpoint17,
            &InputPayload,
            &Rc<PreparedRestoredHost17Capture>,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        self.authenticate_restored_host17_attempt_data(attempt, runtime, world, host)?;
        self.authenticate_restored_capture_archive_identity_data(
            graph.plan(),
            world,
            slot,
            &attempt.capture_id,
            runtime,
        )?;
        let mut phase =
            HostMutationGuard::begin_data(self, attempt, HostPhase::Ready, HostPhase::Writing)?;
        let owners = attempt
            .host
            .owners
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let prepared = owners
            .prepared
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let (runtime_record, scheduling_record) = attempt.checkpoint_inputs.records_data()?;
        let (runtime_object, scheduling_object) = attempt.checkpoint_inputs.objects_data()?;
        let coordinator = attempt.checkpoint.record_for_runtime_data(runtime_object)?;
        let coordinator_object = attempt.checkpoint.object_for_runtime_data(runtime_object)?;
        if coordinator.safe_point.scheduling != scheduling_object.reference {
            return Err(RuntimeError::ForeignAuthority);
        }
        prepared.authenticate_runtime_data(runtime, world, runtime_object)?;
        prepared.authenticate_host_data(host)?;
        prepared.with_snapshot_data(|snapshot| {
            if &snapshot.record_data().runtime != runtime_record
                || &snapshot.record_data().scheduling != scheduling_record
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(())
        })?;
        let result = inspect(
            runtime,
            runtime_record,
            scheduling_record,
            runtime_object,
            scheduling_object,
            coordinator,
            coordinator_object,
            prepared,
        );
        if result.is_ok() {
            attempt.terminal.require_completed_data()?;
            prepared.authenticate_spent_data()?;
            prepared.authenticate_runtime_data(runtime, world, runtime_object)?;
            phase.finish_data(HostPhase::Spent);
        }
        result
    }
}

fn checked_row_total_data(
    row: &RestoredHost17CaptureConstructionData,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    checked_sum(
        &[
            row.retained_requested_bytes_data(),
            row.maximum_simultaneous_transient_bytes_data(),
            row.declared_counter_scratch_bytes_data(),
        ],
        maximum,
    )
}

fn authenticate_host_retained_row_data(host: &RetainedHost17Capture) -> Result<(), RuntimeError> {
    let retained = host.retained_requested_backing_data()?;
    let owners = host
        .owners
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    let row = owners.row.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
    if retained > row.retained_requested_bytes_data() {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(())
}

/// Names actual phase, owner loans, construction rows and callback DATA views.
pub(super) fn counter_scratch_data() -> usize {
    use std::cell::{Ref, RefMut};
    size_of::<RetainedHost17Capture>()
        + size_of::<Host17Owners>()
        + size_of::<HostPhase>()
        + size_of::<HostMutationGuard<'static>>()
        + size_of::<Ref<'static, Host17Owners>>()
        + size_of::<RefMut<'static, Host17Owners>>()
        + size_of::<Result<Ref<'static, Host17Owners>, std::cell::BorrowError>>()
        + size_of::<Result<RefMut<'static, Host17Owners>, std::cell::BorrowMutError>>()
        + size_of::<Option<HostSchedulingContinuationLimits>>()
        + size_of::<Option<RestoredHost17CaptureConstructionData>>()
        + size_of::<Result<RestoredHost17CaptureConstructionData, RuntimeError>>()
        + size_of::<&OriginalLineageRuntimeRecord>()
        + size_of::<&SchedulingSnapshot>()
        + size_of::<&CoordinatorCommitmentCheckpoint17>()
        + size_of::<[&InputPayload; 3]>()
        + size_of::<&Rc<PreparedRestoredHost17Capture>>()
        + RestoredHost17CaptureConstructionData::counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_host_keeps_previously_committed_axes() {
        let host = RetainedHost17Capture::default();
        host.prewalk.set(Some((7, 11, 13)));
        host.phase.set(HostPhase::Failed);

        assert!(host.authenticate_current_data().is_err());
        assert!(host.require_writing_data().is_err());
        assert!(host.require_spent_data().is_err());
        assert_eq!(host.future_requested_bytes_data(31).unwrap(), 31);
        assert!(host.future_requested_bytes_data(30).is_err());
        assert_eq!(host.retained_requested_backing_data().unwrap(), 0);
    }

    #[test]
    fn busy_private_owners_cannot_be_reported_as_an_empty_census() {
        let host = RetainedHost17Capture::default();
        let loan = host.owners.borrow_mut();

        assert!(matches!(
            host.retained_requested_backing_data(),
            Err(RuntimeError::OwnerBusy)
        ));
        assert!(matches!(
            host.future_requested_bytes_data(usize::MAX),
            Err(RuntimeError::OwnerBusy)
        ));

        drop(loan);
        assert_eq!(host.retained_requested_backing_data().unwrap(), 0);
        assert_eq!(host.future_requested_bytes_data(usize::MAX).unwrap(), 0);
    }

    #[test]
    fn spent_scope_phase_is_distinct_from_a_new_writing_occurrence() {
        let host = RetainedHost17Capture::default();
        host.phase.set(HostPhase::Spent);

        assert!(host.authenticate_current_data().is_ok());
        assert!(host.require_spent_data().is_ok());
        assert!(host.require_writing_data().is_err());
        assert!(host.owners.borrow().prepared.is_none());
    }
}
