//! Authenticates the first separately admitted observation after all three Worlds.
//!
//! The World ledger and opaque publication establish the actual chronology.
//! They do not grant observation allocation. Every selected peer retains its
//! own independently admitted row, planned original ID and sticky phase.

use super::super::{
    activation::OriginalInstalledRestorationActivationPhase,
    observation::{
        OriginalInstalledRestorationObservationClaim,
        OriginalInstalledRestorationObservationSigningInputs,
        authenticate_original_observation_worlds_data,
    },
};
use super::*;

impl CompleteOriginalRestorationWindow {
    pub(super) fn authenticate_original_retained_observation_identity_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        proof_identity: [u8; 32],
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        self.world_roster.authenticate_complete()?;
        authenticate_original_observation_worlds_data(&self.activation_phases)?;
        if !self.context_issued.get()
            || self.phase_in_flight.get()
            || !std::ptr::eq(
                source,
                self.sources
                    .get(selected)
                    .ok_or(RuntimeError::ForeignAuthority)?
                    .as_ref(),
            )
            || self.original_complete_scope_proof_identity_data()? != proof_identity
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.observation_phases
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .authenticate_retained()?;
        let plan = self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        let world = self
            .activation_world
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        self.runtime
            .authenticate_world_activation_data(world, &scope.target)?;
        self.authenticate_original_complete_identity_data(&plan, scope)
    }

    fn authenticate_original_observation_identity_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        proof_identity: [u8; 32],
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_retained_observation_identity_data(
            selected,
            source,
            proof_identity,
        )?;
        self.observation_phases
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .authenticate_started()
    }

    pub(in super::super) fn authenticate_original_observation_member_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        proof_identity: [u8; 32],
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_observation_identity_data(selected, source, proof_identity)?;
        let plan = self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let member = OriginalRestorationMemberScope {
            plan: &plan,
            window: self,
            sources: &self.sources,
            publisher: None,
        };
        plan.0
            .authority
            .authenticate_original_restoration_construction_member(&plan.evidence(), &member)?;
        // The erased callback cannot reset a failed or reentered phase.
        self.authenticate_original_observation_identity_data(selected, source, proof_identity)
    }

    pub(in super::super) fn with_original_observation_signing_inputs_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        proof_identity: [u8; 32],
        inspect: impl FnOnce(
            &OriginalInstalledRestorationObservationSigningInputs<'_>,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_retained_observation_identity_data(
            selected,
            source,
            proof_identity,
        )?;
        let node = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let observation_data = node
            .installed_custody
            .as_ref()
            .and_then(|custody| custody.observation_construction_data())
            .ok_or(RuntimeError::UnsupportedFacet)?;
        let source_construction = node
            .source_observation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let request_id = self
            .observation_request_ids
            .get(selected)
            .and_then(OnceCell::get)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        self.with_original_activation_signing_inputs_data(
            selected,
            source,
            OriginalInstalledRestorationActivationPhase::WorldActivate,
            proof_identity,
            |activation| {
                let inputs = OriginalInstalledRestorationObservationSigningInputs {
                    activation,
                    observation_data,
                    source_construction,
                    request_id,
                };
                inspect(&inputs)
            },
        )?;
        // Source already invoked the final member inside SourceRead. Only the
        // same bank-free identities follow its final kernel/registrar fence.
        self.authenticate_original_retained_observation_identity_data(
            selected,
            source,
            proof_identity,
        )
    }

    pub(crate) fn begin_original_installed_observation_claim_data(
        self: &Rc<Self>,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &crucible_node_transport::client::CnpController,
        read_owner: *const (),
        world: &crate::node_contract::WorldActivation,
    ) -> Result<OriginalInstalledRestorationObservationClaim, RuntimeError> {
        self.origin()?;
        self.whole_observation.authenticate_dispatch_data()?;
        self.world_roster.authenticate_complete()?;
        authenticate_original_observation_worlds_data(&self.activation_phases)?;
        if self.phase_in_flight.get()
            || !self.context_issued.get()
            || self.original_installed_source_index_data(source)? != selected
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let original_world = self
            .activation_world
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !original_world.same_authority(world) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let original_source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !original_source.is_original_restoration_observation_declaration_data()? {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let node = self
            .node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if node.source_observation.is_none()
            || node
                .installed_custody
                .as_ref()
                .and_then(|custody| custody.observation_construction_data())
                .is_none()
            || self
                .observation_request_ids
                .get(selected)
                .and_then(OnceCell::get)
                .is_none()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let proof_identity = self.original_complete_scope_proof_identity_data()?;
        self.observation_phases
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .begin()?;
        // This same owned guard exists before the first fallible/currentness
        // callback, survives Source effects, and stays in effect evidence until
        // Core authenticates the retained Node handoff. Error/unwind drops it.
        let claim = OriginalInstalledRestorationObservationClaim::from_original_window(
            self,
            selected,
            proof_identity,
        );
        // Spend before opening the Source callback. Reentry poisons this same
        // started phase even if the callback swallows the inner refusal.
        // The guard remains local until full currentness passes; no caller can
        // use it during these checks.
        self.with_original_installed_node_custody_data(
            selected,
            source,
            controller,
            read_owner,
            |_, _, _| Ok(()),
        )?;
        self.authenticate_original_observation_member_data(
            selected,
            original_source.as_ref(),
            proof_identity,
        )?;
        Ok(claim)
    }

    pub(crate) fn original_installed_source_observation_data(
        &self,
        selected: usize,
    ) -> Result<
        crate::node_adapters::cnp::OriginalSourceRestorationObservationConstructionData,
        RuntimeError,
    > {
        self.origin()?;
        self.node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .and_then(|row| row.source_observation)
            .ok_or(RuntimeError::OwnerUnavailable)
    }
}
