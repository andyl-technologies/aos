//! Runs a separately admitted current Observe on the installed native runtime.
//!
//! Whole-owner admission precedes the mutable Runtime/node loan. The caller
//! supplies the same original group loans already used by the installed census;
//! no SDK, native handle or admission can be recovered from a DTO or byte limit.

use super::*;
use crate::node_adapters::cnp::PacketCompleteOriginalHostSdk;
use crate::node_admission::{CompleteOriginalRestorationWindow, InstalledConformancePlan};
use crate::node_contract::RuntimePollFailure;
use crucible_node_format::NodeId;
use crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch;

impl ConformanceRuntime {
    /// Prepares one fresh restored scheduling inspection under its full owning census.
    ///
    /// This operation inspects the unchanged current native model. It creates
    /// no Begin, input, retirement or Capture permission, and never renews the
    /// immutable first Observe. Failed custody remains in the actual Window,
    /// node, Source, SDK and native reservation owners.
    ///
    /// # Errors
    /// Refuses foreign originals, missing initial observation/seed, exhausted
    /// rows, a failed whole census, stale native proof or incomplete publication.
    pub fn prepare_original_installed_restored_scheduling(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        canonical_launch5: [&[u8]; 3],
        node: &NodeId,
    ) -> Result<crate::node_admission::OriginalRestoredSchedulingObservationAdmission, RuntimeError>
    {
        let world = self.activation.as_ref().ok_or(RuntimeError::NotActivated)?;
        window.authenticate_current_observation_runtime_data(self, plan, world)?;
        let (maximum, scratch) = window.current_observation_policy_data()?;
        let fixed = crate::node_admission::OriginalRestoredSchedulingObservationConstructionData::counter_scratch_data();
        if fixed > scratch {
            return Err(RuntimeError::ResourceLimit);
        }
        let selected = window.current_observation_source_index_data(node)?;
        let ordinal = window.next_current_observation_ordinal_data(node)?;
        let row = self
            .runtime
            .quote_original_restored_scheduling_observation_data(
                world,
                node,
                &launches[selected],
                canonical_launch5[selected],
                ordinal,
                maximum,
            )?;
        window.retain_current_observation_quote_data(&self.runtime, plan, world, node, row)?;

        // The mutable Runtime/Controller is not borrowed during this genuine
        // complete observation. Every original future row remains in its sum.
        window.recheck_original_transaction_inputs_data(
            plan,
            sdks,
            launches,
            canonical_launch5,
            self,
            world.record(),
        )?;
        crate::node_admission::OriginalRestoredSchedulingObservationAdmission::after_original_census_data(
            window, &self.runtime, selected, ordinal,
        )
    }

    /// Consumes one completed original admission and returns a real current Observe.
    ///
    /// The holder must end its immutable capsule loan after preparation and
    /// before this call. No complete census or mutable-owner extractor runs
    /// inside the node callback. Native ACK/proof and Source terminal fences
    /// complete before Runtime accepts the actual scheduling result.
    ///
    /// # Errors
    /// Refuses a foreign, stale or spent admission before effects. Native and
    /// post-publication failures retain partial owners and report uncertainty.
    pub fn observe_original_installed_restored_scheduling(
        &mut self,
        admission: &mut crate::node_admission::OriginalRestoredSchedulingObservationAdmission,
        launch: &PacketNative5SourceLaunch,
        canonical_launch5: &[u8],
        node: &NodeId,
    ) -> Result<crate::node_scheduling::ValidatedSchedulingObservation, RuntimePollFailure> {
        let world = self
            .activation
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?;
        let claim = admission
            .begin_original_data(&self.runtime, world, launch, canonical_launch5, node)
            .map_err(RuntimePollFailure::Admission)?;
        let observation = self
            .runtime
            .observe_scheduling_with_original_claim(world, node, &claim)?;
        claim.complete_runtime_data(&self.runtime).map_err(|_| RuntimePollFailure::Native(
            crate::node_contract::OperationFailure {
                effects: crate::node_contract::EffectKnowledge::Unknown,
                reason: crate::node_admission::OriginalRestoredSchedulingObservationClaim::COMPLETION_FAILURE.into(),
            },
        ))?;
        Ok(observation)
    }
}

impl ConformanceRuntime {
    /// Admits the additional Runtime work before the genuine first Observe.
    ///
    /// # Errors
    /// Refuses a foreign installed group, repeated first work, incomplete World,
    /// unavailable actual route or the full unchanged owning policy/census.
    pub fn prepare_original_installed_initial_scheduling(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        sdks: [&PacketCompleteOriginalHostSdk; 3],
        launches: &[PacketNative5SourceLaunch; 3],
        canonical_launch5: [&[u8]; 3],
        node: &NodeId,
    ) -> Result<crate::node_admission::OriginalRestoredInitialSchedulingAdmission, RuntimeError>
    {
        let world = self.activation.as_ref().ok_or(RuntimeError::NotActivated)?;
        window.authenticate_current_observation_runtime_data(self, plan, world)?;
        let (maximum, scratch) = window.current_observation_policy_data()?;
        if crate::node_admission::OriginalRestoredSchedulingObservationConstructionData::counter_scratch_data() > scratch {
            return Err(RuntimeError::ResourceLimit);
        }
        let selected = window.current_observation_source_index_data(node)?;
        let work = self
            .runtime
            .quote_initial_current_scheduling_work_data(world, node, maximum)?;
        crate::node_admission::OriginalRestoredInitialSchedulingAdmission::retain_work_data(
            window,
            &self.runtime,
            selected,
            work,
        )?;
        window.recheck_original_transaction_inputs_data(
            plan,
            sdks,
            launches,
            canonical_launch5,
            self,
            world.record(),
        )?;
        crate::node_admission::OriginalRestoredInitialSchedulingAdmission::after_census_data(
            window,
            &self.runtime,
            selected,
        )
    }

    /// Consumes the retained first-observation admission without copying its World.
    ///
    /// # Errors
    /// Refuses a foreign/spent admission or a failed real first proof/ACK fence.
    pub fn observe_original_installed_initial_scheduling(
        &mut self,
        admission: &mut crate::node_admission::OriginalRestoredInitialSchedulingAdmission,
        node: &NodeId,
    ) -> Result<(), RuntimePollFailure> {
        let world = self
            .activation
            .as_ref()
            .ok_or(RuntimePollFailure::Admission(RuntimeError::NotActivated))?;
        admission
            .begin_data(&self.runtime, world, node)
            .map_err(RuntimePollFailure::Admission)?;
        self.runtime
            .observe_original_installed_first_scheduling(world, node)
    }

    /// Seeds a separate current checkpoint after all original first observations.
    ///
    /// # Errors
    /// Refuses another installed runtime, missing census, incomplete first
    /// observations, stale Source proof or a spent/failed genuine seed claim.
    pub fn seed_original_installed_restored_suffix(
        &self,
        window: &Rc<CompleteOriginalRestorationWindow>,
        plan: &InstalledConformancePlan,
        node: &NodeId,
    ) -> Result<(), RuntimeError> {
        let world = self.activation.as_ref().ok_or(RuntimeError::NotActivated)?;
        window.authenticate_current_observation_runtime_data(self, plan, world)?;
        window.authenticate_initial_scheduling_identity_data(&self.runtime, world, node)?;
        self.runtime
            .seed_original_installed_restored_suffix_data(world, node)
    }
}
