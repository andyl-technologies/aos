//! Releases only redundant decoded native/registry imports after installation.
//!
//! Host remains retained for its genuine Capture terminal; all original archive
//! bytes and live native/SDK/Source/Node/deferred owners remain unchanged. This
//! explicit local administration is never invoked by Capture or a decoder.

use super::continuation_suffix::SeedStage;
use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold;

impl CompleteOriginalRestorationWindow {
    pub(super) fn authenticate_original_import_boundary_data(
        &self,
        selected: usize,
        source: &Rc<PacketCompleteSemanticSource>,
        held: &PacketNativeRestoredCommitHold,
        row: &crate::node_state::CompleteOriginalArchivedValidationConstructionData,
        maximum_record: usize,
        additional: usize,
    ) -> Result<(), RuntimeError> {
        let ticket = self
            .targets
            .get(selected)
            .and_then(OnceCell::get)
            .ok_or(RuntimeError::OwnerUnavailable)?
            .ticket_data()?;
        self.cold
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_installed_import_boundary_data(
                selected,
                source,
                ticket,
                held,
                row,
                maximum_record,
                additional,
                self.policy.maximum_requested_bytes,
            )
    }

    pub(crate) fn authenticate_installed_import_release_current_data(
        &self,
        plan: &InstalledConformancePlan,
        runtime: &NodeRuntime,
    ) -> Result<(), RuntimeError> {
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.validate_original_installed_context_current_data(
            plan,
            runtime,
            self.archive.runtime_object(),
            self.archive.original_runtime_record_data()?,
            scope,
            self.archive.content(),
        )
    }

    fn authenticate_import_release_phase_data(&self) -> Result<(), RuntimeError> {
        self.origin()?;
        if !self.context_issued.get()
            || self.phase_in_flight.get()
            || self.suffix_in_flight.get()
            || self.restored_capture_in_flight.get()
            || self.stage.get() != WindowStage::TransactionAdmitted
            || self.producer_grant_started.iter().any(Cell::get)
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        // This first increment is selected immediately after initial seeding;
        // existing action/deferred owners are neither retired nor rewritten.
        if self.producer_next_slot.get() != 0 {
            return Err(RuntimeError::OutstandingObligations);
        }
        for index in 0..3 {
            if !self.observation_phases[index].is_verified() {
                return Err(RuntimeError::OutstandingObligations);
            }
            self.suffix_seeds[index].authenticate(SeedStage::Verified)?;
            self.current_observations[index]
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .authenticate_no_pending_data()?;
            self.producer_executions[index]
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .require_available_data()?;
        }
        Ok(())
    }

    /// Releases only native-before/native-after/registry import duplicates.
    ///
    /// This once-attempt local administration authenticates the real installed
    /// four-owner World and all three first Observes/seeds. It makes no protocol
    /// request, retires no journal, changes no schema/binding and grants no Capture
    /// or action permission. The verified archive and decoded Host stay owned.
    /// Returns the same ColdGroup's conservative backing census before and after
    /// removal; policy, future rows and lifetime credit are unchanged.
    ///
    /// # Errors
    /// Refuses incomplete/foreign installation, pending work, previous action or
    /// release attempt, live decoded loans, stale proof, or a full owning census
    /// failure. Failure before the no-fail removal retains every decoded owner.
    /// A post-release census failure retains the witness and all other custody.
    pub fn release_original_installed_import_duplicates(
        &self,
        plan: &InstalledConformancePlan,
        sdks: [&crate::node_adapters::cnp::PacketCompleteOriginalHostSdk; 3],
        launches: &[crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch;
             3],
        raw5: [&[u8]; 3],
        runtime: &ConformanceRuntime,
        activation: &ActivationRecord,
    ) -> Result<(usize, usize), RuntimeError> {
        self.authenticate_import_release_phase_data()?;
        runtime.authenticate_original_installed_runtime_data(
            self,
            &self.archive,
            plan,
            activation,
        )?;
        let cold = self.cold.get().ok_or(RuntimeError::OwnerUnavailable)?;
        cold.begin_installed_import_release_data()?;
        let result = (|| {
            // The enlarged inline owner/static counters were funded before cold
            // construction. This full census counts old graphs and all new fixed
            // witness slots before any repeated immutable validator runs.
            self.recheck_original_transaction_inputs_data(
                plan, sdks, launches, raw5, runtime, activation,
            )?;
            let scope = self
                .complete_scope
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .scope_data()?;
            runtime.authenticate_installed_import_release_current_data(self, plan)?;
            self.authenticate_import_release_phase_data()?;
            self.authenticate_original_complete_identity_data(plan, scope)?;
            let before = cold.retained_storage_data(self.policy.maximum_requested_bytes)?;
            cold.finish_installed_import_release_data()?;
            self.whole_observation.require_observation();
            // A smaller observed owner total is reported only by a genuine
            // post-release whole census; saved future rows and policy stay exact.
            self.recheck_original_transaction_inputs_data(
                plan, sdks, launches, raw5, runtime, activation,
            )?;
            let after = cold.retained_storage_data(self.policy.maximum_requested_bytes)?;
            Ok((before, after))
        })();
        if result.is_err() {
            cold.fail_installed_import_release_data();
        }
        result
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<[usize; 2]>()
        + size_of::<(usize, usize)>()
        + size_of::<Result<(usize, usize), RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<&ConformanceRuntime>()
        + size_of::<&NodeRuntime>()
        + size_of::<&InstalledConformancePlan>()
        + size_of::<&ActivationRecord>()
        + size_of::<[&crate::node_adapters::cnp::PacketCompleteOriginalHostSdk; 3]>()
        + size_of::<[&[u8]; 3]>()
        + size_of::<std::cell::Ref<'static, super::current_observation::CurrentObservationLedger>>()
        + size_of::<std::cell::Ref<'static, super::producer_execution::ProducerExecutionLedger>>()
        + size_of::<std::array::IntoIter<&'static Cell<bool>, 3>>()
}
