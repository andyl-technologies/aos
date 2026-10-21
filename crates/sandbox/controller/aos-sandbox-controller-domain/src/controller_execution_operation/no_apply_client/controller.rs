//! Captures the whole native Controller cut on the continuously held C18 loan.
//!
//! The actual writer stays exclusively borrowed by the parent throughout Root
//! IO and the later prepare/CAS/ACK programme. Its weak identity stamp is only
//! one comparison: names, global NEXT, native end and the complete ordered map
//! are independently sampled. Six unchanged target rows never waive that cut.
//! No decoded Root floor, attestation or raw coordinates construct this owner.

use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2;

use crate::journal::{
    JournalAuthorityComparisonStampV1, JournalError, ProtectedJournalCurrentnessOriginalsV1,
    ProtectedJournalNamesV1,
};
use aos_sandbox_protocol::domain_ledger::create_failure::ClosedCreateFailurePlanDataV2;

use super::*;
type Acquisition = aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::RootNoApplyRecoveryAcquisitionFieldsV2;
type CleanupHorizon = (Acquisition, RawPairedClockSample, i64);

type Witness = aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1<JournalError>;

#[derive(Clone, Copy)]
enum First {
    Before,
    Clock,
    Plan,
    Body,
    After,
    Final,
}

pub(super) struct ControllerCutOriginalV2 {
    first: Option<First>,
    names: [ProtectedJournalCurrentnessOriginalsV1; 2],
    witness: [Witness; 2],
    observed: [Option<Result<ProtectedJournalNamesV1, JournalError>>; 2],
    clock: ControllerExecutionClockOriginalV1,
    sample: Option<
        Result<
            RawPairedClockSample,
            aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError,
        >,
    >,
    plan: Option<Result<ClosedCreateFailurePlanDataV2, ReconcilerError>>,
    stamp: Option<JournalAuthorityComparisonStampV1>,
    cut: Option<RootExecutionNoApplyControllerCutDataV2>,
    body: Option<Result<(), JournalError>>,
    final_binding: Option<Result<(), JournalError>>,
}

impl ControllerCutOriginalV2 {
    fn new() -> Self {
        Self {
            first: None,
            names: std::array::from_fn(|_| Default::default()),
            witness: std::array::from_fn(|_| Default::default()),
            observed: std::array::from_fn(|_| None),
            clock: ControllerExecutionClockOriginalV1::new(),
            sample: None,
            plan: None,
            stamp: None,
            cut: None,
            body: None,
            final_binding: None,
        }
    }

    fn receiving_demand(controller: &Journal) -> Result<ResourceVector, JournalError> {
        let one = controller.held_names_receiving_demand_v2()?;
        let witness = Witness::receiving_footprint_v1().ok_or(JournalError::JournalTooLarge)?;
        let bytes = size_of::<Self>()
            .checked_mul(3)
            .and_then(|n| n.checked_add(witness.memory_bytes.checked_mul(2)?))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let models = crate::reconciler::closed_create_failure_receiving_demand_from_observation_v2(crate::journal::historical_observation::HistoricalObservationV1::from_journal_v1(controller))
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let clock = ControllerExecutionClockOriginalV1::fixed_demand_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(one
            .checked_add(one)?
            .checked_add(models)?
            .checked_add(clock)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
    }

    fn observe_cut(
        &self,
        controller: &Journal,
        index: usize,
    ) -> Result<RootExecutionNoApplyControllerCutDataV2, JournalError> {
        controller.ensure_protected_authority()?;
        let names = self.observed[index]
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        let (_, _, end) = self.names[index]
            .completed_held_file_boundary_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        RootExecutionNoApplyControllerCutDataV2::from_rows_data_v2(
            names,
            controller.snapshot_sequence(),
            end,
            controller.all_records(),
        )
        .map_err(|_| JournalError::ProtectedBoundary)
    }

    fn capture(
        &mut self,
        controller: &Journal,
        terminal: ClosedHostTerminalArchiveDataV2,
        cutoff: u64,
        recovery: Option<CleanupHorizon>,
    ) {
        // Destinations for both independent name observations were paid before
        // entry. The after observation remains owed after every body failure.
        self.observed[0] = Some(
            controller
                .observe_held_physical_names_retaining_v1(&mut self.names[0], &mut self.witness[0]),
        );
        if !matches!(self.observed[0], Some(Ok(_))) {
            self.first.get_or_insert(First::Before);
        }
        self.body = Some(self.capture_body(controller, terminal, cutoff, recovery));
        if matches!(self.body, Some(Err(_))) {
            self.first.get_or_insert(First::Body);
        }
        self.observed[1] = Some(
            controller
                .observe_held_physical_names_retaining_v1(&mut self.names[1], &mut self.witness[1]),
        );
        if !matches!(self.observed[1], Some(Ok(_))) {
            self.first.get_or_insert(First::After);
        }
        self.final_binding = Some((|| {
            if self.observe_cut(controller, 1)?
                != self.cut.ok_or(JournalError::ProtectedBoundary)?
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            self.require_unchanged(controller)
        })());
        if matches!(self.final_binding, Some(Err(_))) {
            self.first.get_or_insert(First::Final);
        }
    }

    fn capture_body(
        &mut self,
        controller: &Journal,
        terminal: ClosedHostTerminalArchiveDataV2,
        cutoff: u64,
        recovery: Option<CleanupHorizon>,
    ) -> Result<(), JournalError> {
        self.cut = Some(self.observe_cut(controller, 0)?);
        self.stamp = Some(controller.authority_comparison_stamp_v1());
        self.sample = Some(self.clock.sample_v1());
        if !matches!(self.sample, Some(Ok(_))) {
            self.first.get_or_insert(First::Clock);
        }
        let sample = self
            .sample
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        if sample.host_boot_id() != recovery.map(|entry| entry.0.host_boot)
            .unwrap_or(terminal.marker().fields().source.fields().host_boot)
            || sample.boottime_nanoseconds() >= cutoff
        {
            return Err(JournalError::ProtectedBoundary);
        }
        if let Some((_, first, expiry)) = recovery {
            if first.validate_later_sample(sample).is_err() || sample.wall_seconds() >= expiry {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        self.plan = Some(crate::reconciler::plan_closed_create_failure_rows_from_observation_v2(crate::journal::historical_observation::HistoricalObservationV1::from_journal_v1(controller),
            terminal.marker(),
            terminal.archive_head(),
            terminal.signed_terminal_outcome(),
            recovery.and_then(|entry| entry.0.history.map(|history| history.prepare.wall_seconds))
                .unwrap_or(sample.wall_seconds()),
        ));
        if !matches!(self.plan, Some(Ok(_))) {
            self.first.get_or_insert(First::Plan);
        }
        let plan = self
            .plan
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        // Active execution cannot adopt a historical prepared or settled C
        // owner. Those cases require the separate fresh cleanup receiver.
        if recovery.is_none() && (plan.prepared_data_v2().is_some() || plan.settled_data_v2()) {
            return Err(JournalError::ProtectedBoundary);
        }
        if let Some((acquisition, _, _)) = recovery {
            use aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::RootNoApplyRecoveryPhaseV2 as Phase;
            if Some(acquisition.controller_cut) != self.cut {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            let valid = match acquisition.phase {
                Phase::BeforeFloor | Phase::FloorAnchored => plan.prepared_data_v2().is_none() && !plan.settled_data_v2(),
                Phase::Prepared | Phase::Settled => acquisition.history.is_some_and(|history|
                    plan.prepared_data_v2() == Some(history.prepare)
                    && plan.settled_data_v2() == (acquisition.phase == Phase::Settled)),
            };
            if !valid { return Err(JournalError::ProtectedBoundary); }
        }
        self.require_unchanged(controller)
    }

    fn require_unchanged(&self, controller: &Journal) -> Result<(), JournalError> {
        let stamp = self.stamp.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let cut = self.cut.ok_or(JournalError::ProtectedBoundary)?;
        controller.ensure_protected_authority()?;
        if !controller.matches_authority_comparison_stamp_v1(stamp)
            || controller.snapshot_sequence() != cut.next()
            || RootExecutionNoApplyControllerCutDataV2::from_rows_data_v2(
                cut.names(),
                controller.snapshot_sequence(),
                cut.end(),
                controller.all_records(),
            )
            .map_err(|_| JournalError::ProtectedBoundary)?
                != cut
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(super) fn completed(
        &self,
        controller: &Journal,
    ) -> Result<
        (
            &ClosedCreateFailurePlanDataV2,
            RootExecutionNoApplyControllerCutDataV2,
        ),
        JournalError,
    > {
        if self.first.is_some()
            || !matches!(self.body, Some(Ok(())))
            || !matches!(self.final_binding, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.require_unchanged(controller)?;
        let plan = self
            .plan
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok((plan, self.cut.ok_or(JournalError::ProtectedBoundary)?))
    }

    pub(super) fn captured_plan_v2(&self) -> Result<&ClosedCreateFailurePlanDataV2, JournalError> {
        // Only the enclosing prepared native owner uses this historical plan
        // after its own exact X+3 cut check. It supplies no writer permission.
        if self.first.is_some()
            || !matches!(self.body, Some(Ok(())))
            || !matches!(self.final_binding, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Before => self.names[0]
                .failure()
                .or_else(|| self.witness[0].failure())
                .or_else(|| error(&self.observed[0])),
            First::Clock => self.clock.failure().or_else(|| error(&self.sample)),
            First::Plan => error(&self.plan),
            First::Body => error(&self.body),
            First::After => self.names[1]
                .failure()
                .or_else(|| self.witness[1].failure())
                .or_else(|| error(&self.observed[1])),
            First::Final => error(&self.final_binding),
        }
    }
}

impl ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    /// Borrows the actual posted42/43 lease retained by this same native loan.
    ///
    /// This is comparison DATA for the genuine Root client. Its actual Root
    /// peer, Source-funded transport and independent journal readers establish
    /// authority; an arbitrary decoded lease cannot enter this borrower.
    ///
    /// # Errors
    /// Refuses an unfinished preliminary exchange, a failed original or a stale C cut.
    #[doc(hidden)]
    pub fn root_owned_host_lease_data_v2(
        &self,
    ) -> Result<CurrentHostNoApplyLeaseDataV2, ResourceReservationErrorV1> {
        self.controller_cut_data_v2()?;
        let native = self.native()?;
        if !matches!(native.active, 2 | 3) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        native.lease.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the actual paid Controller paired sample and unchanged native cutoff.
    ///
    /// # Errors
    /// Refuses incomplete, failed or globally stale native Controller capture.
    #[doc(hidden)]
    pub fn root_original_clock_data_v2(
        &self,
    ) -> Result<(RawPairedClockSample, u64), ResourceReservationErrorV1> {
        if let Some(cleanup) = self.native()?.cleanup.as_deref() {
            if self.native.active >= 2 { self.controller_cut_data_v2()?; }
            return Ok((cleanup.first, self.native.cutoff));
        }
        self.controller_cut_data_v2()?;
        let native = self.native()?;
        let sample = native.controller.as_deref()
            .and_then(|original| original.sample.as_ref())
            .and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((sample, native.cutoff))
    }

    /// Captures the actual whole C cut and sole three-row plan before Root IO.
    ///
    /// The same writer and concrete Source loan remain borrowed afterward.
    /// The paired native sample supplies the successor wall second. This does
    /// not accept Root DATA or issue a prepared/CAS/positive-disposal token.
    ///
    /// # Errors
    /// Retains reentry, Source funding, currentness, clock or canonical-plan
    /// failure, including the separately owed native after observation.
    pub fn prepare_controller_cut_once_v2(&mut self) -> Result<(), ResourceReservationErrorV1> {
        self.native()?;
        if self.native.active != 2 || self.native.controller_geometry.is_some() {
            self.reentry
                .get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.native.controller_geometry =
            Some(ControllerCutOriginalV2::receiving_demand(self.controller));
        let demand = self
            .native
            .controller_geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let complete = self.complete_transport_base_v2(demand)?;
        self.native.controller_funding = Some(self.require_transport_complete_v2(complete));
        if !matches!(self.native.controller_funding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // Future Host subturn invoices must include this still-resident cut,
        // rather than taking a maximum of two disjoint retained prefixes.
        self.base = self.base.checked_add(demand)?;
        let terminal = self
            .native
            .terminal
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let cutoff = self.no_apply_cutoff_data_v2()?;
        self.native.controller = Some(Box::new(ControllerCutOriginalV2::new()));
        let original = self
            .native
            .controller
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let recovery = if let Some(cleanup) = self.native.cleanup.as_deref() {
            let acquisition = cleanup.acquisition_fields.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            Some((*acquisition, cleanup.first, cleanup.admission.wall_expiry.min(acquisition.policy_expires_at)))
        } else { None };
        original.capture(self.controller, terminal, cutoff, recovery);
        original
            .completed(self.controller)
            .map(|_| ())
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Borrows nonauthorizing whole-C comparison DATA while its native loan stays held.
    ///
    /// # Errors
    /// Refuses incomplete/failed capture or any unrelated global C advance.
    pub fn controller_cut_data_v2(
        &self,
    ) -> Result<RootExecutionNoApplyControllerCutDataV2, ResourceReservationErrorV1> {
        self.native()?
            .controller
            .as_deref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .completed(self.controller)
            .map(|(_, cut)| cut)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the native successor wall and exact six planned row digests as DATA.
    ///
    /// # Errors
    /// Refuses failed or stale native capture; the returned values grant no append.
    pub fn controller_rows_data_v2(
        &self,
    ) -> Result<(i64, [[u8; 32]; 3], [[u8; 32]; 3]), ResourceReservationErrorV1> {
        let (plan, _) = self
            .native()?
            .controller
            .as_deref()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .completed(self.controller)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let (predecessor, successor) = plan.row_digests_data_v2();
        Ok((plan.wall_seconds_data_v2(), predecessor, successor))
    }
}
