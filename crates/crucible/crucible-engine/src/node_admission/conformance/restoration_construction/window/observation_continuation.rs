//! Revalidates completed Observe originals without renewing the once claim.
//!
//! Initial Node copies and later comparisons both borrow the actual Source
//! observation under its read fence. The same saved archive-validation row
//! independently funds the strict historical predicates while Source retains
//! its current proof owners. No decoded owner or context escapes these loans.

use super::super::observation::OriginalInstalledRestorationObservationSigningInputs;
use super::*;
use crate::node_contract::{
    OriginalLineageNativeScope, OriginalLineageRuntimeRecord, WorldActivation,
};
use crate::node_scheduling::NativeSchedulingObservation;
use crate::node_state::VerifiedStateContent;
use crucible_node_transport::client::CnpController;
use crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold;

impl CompleteOriginalRestorationWindow {
    pub(in super::super) fn interrupt_original_observation_data(&self, selected: usize) {
        if self
            .observation_phases
            .get(selected)
            .is_some_and(|phase| phase.interrupt_started())
        {
            self.whole_observation.require_observation();
        }
    }

    pub(in super::super) fn authenticate_original_observed_hold_data(
        &self,
        selected: usize,
        scope: &OriginalLineageNativeScope,
        held: &PacketNativeRestoredCommitHold,
        reference: &ContentRef,
    ) -> Result<(), RuntimeError> {
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let proof = self.original_complete_scope_proof_identity_data()?;
        self.authenticate_original_retained_observation_identity_data(selected, source, proof)?;
        self.authenticate_original_activation_hold_data(selected, scope, held, reference)?;
        let target = self
            .targets
            .get(selected)
            .and_then(OnceCell::get)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let ticket = target.ticket_data()?;
        let row = ticket
            .native_restoration_construction_data()?
            .original_archived_validation_construction_data()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        // This SAME independent row remains in every Transaction/Installed
        // whole-window sum. It is not borrowed from Source's evidence budget.
        self.authenticate_original_import_boundary_data(
            selected,
            source,
            held,
            row,
            self.archive
                .original_archive_limits_data()?
                .state
                .maximum_record_bytes,
            self.observed_other_retained
                .get()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )?;
        // Temporary semantics/model owners above are gone before Node's
        // actual copy/comparison callback. Source still owns its read fence.
        self.authenticate_original_retained_observation_identity_data(selected, source, proof)
    }

    pub(super) fn with_original_observed_node_custody_data(
        &self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        inspect: impl FnOnce(
            &OriginalLineageRuntimeRecord,
            &OriginalLineageNativeScope,
            &VerifiedStateContent,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let source =
            self.authenticate_original_observed_owner_data(selected, source, read_owner)?;
        let proof = self.original_complete_scope_proof_identity_data()?;
        self.with_original_observation_signing_inputs_data(selected, source, proof, |inputs| {
            let evidence = source.original_verified_restoration_observation_data(
                controller,
                inputs,
                inputs.source_construction,
            )?;
            evidence.authenticate_continuation_data(
                inputs,
                inputs.source_construction,
                |held, reference| {
                    inputs.authenticate_original_observation_hold_data(held, reference)?;
                    inspect(
                        self.archive.original_runtime_record_data()?,
                        inputs.activation.scope,
                        self.archive.content(),
                    )
                },
                || {
                    self.authenticate_original_verified_observation_member_data(
                        selected, source, proof,
                    )
                },
            )
        })
    }

    pub(crate) fn with_original_observation_scheduling_data(
        &self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        evidence: &crate::node_adapters::cnp::OriginalSourceRestorationObservationVerifiedPhase<'_>,
        inspect: impl FnOnce(&NativeSchedulingObservation) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        if self.original_installed_source_index_data(source)? != selected {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let proof = self.original_complete_scope_proof_identity_data()?;
        // A read-only inspection has no owned guard and cannot enter this
        // completion path, even when its underlying saved response is genuine.
        evidence
            .original_effect_claim_data()?
            .authenticate_original_handoff_data(self, selected, source, proof)?;
        self.with_original_observation_signing_inputs_data(selected, source, proof, |inputs| {
            // Native's defining evidence method repeats actual Observe/World/
            // Hold checks, invokes the full saved-row predicate above, then
            // lends its SAME retained observation before the final Source fence.
            evidence.with_scheduling_observation_data(
                inputs,
                inputs.source_construction,
                inspect,
                || self.authenticate_original_observation_member_data(selected, source, proof),
            )
        })?;
        // All Node copies and Source/kernel completion precede this transition.
        // The effect evidence retains its owned claim until this point; an
        // earlier error or unwind drops that guard while still Started.
        self.observation_phases
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?
            .complete_verified()?;
        if self
            .observation_phases
            .iter()
            .all(|phase| phase.is_verified())
        {
            self.whole_observation.require_observation();
        }
        Ok(())
    }

    pub(crate) fn with_original_current_observation_scheduling_data(
        &self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        controller: &CnpController,
        read_owner: *const (),
        world: &WorldActivation,
        inspect: impl FnOnce(&NativeSchedulingObservation) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let source =
            self.authenticate_original_observed_owner_data(selected, source, read_owner)?;
        let proof = self.original_complete_scope_proof_identity_data()?;
        if !self
            .activation_world
            .get()
            .is_some_and(|actual| actual.same_authority(world))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.with_original_observation_signing_inputs_data(selected, source, proof, |inputs| {
            self.runtime
                .authenticate_world_activation_data(world, &inputs.activation.scope.target)?;
            let evidence = source.original_verified_restoration_observation_data(
                controller,
                inputs,
                inputs.source_construction,
            )?;
            evidence.with_scheduling_observation_data(
                inputs,
                inputs.source_construction,
                inspect,
                || {
                    self.authenticate_original_verified_observation_member_data(
                        selected, source, proof,
                    )
                },
            )
        })
    }

    fn authenticate_original_observed_owner_data<'a>(
        &'a self,
        selected: usize,
        source: &dyn crate::node_adapters::cnp::CnpSemanticSource,
        read_owner: *const (),
    ) -> Result<&'a PacketCompleteSemanticSource, RuntimeError> {
        self.origin()?;
        if self.original_installed_source_index_data(source)? != selected
            || !self
                .observation_phases
                .get(selected)
                .is_some_and(|phase| phase.is_verified())
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let source = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.node_rows
            .get()
            .and_then(|rows| rows.get(selected))
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original_owner_data(source, read_owner)?;
        Ok(source.as_ref())
    }

    fn authenticate_original_verified_observation_member_data(
        &self,
        selected: usize,
        source: &PacketCompleteSemanticSource,
        proof: [u8; 32],
    ) -> Result<(), RuntimeError> {
        self.authenticate_original_retained_observation_identity_data(selected, source, proof)?;
        if !self
            .observation_phases
            .get(selected)
            .is_some_and(|phase| phase.is_verified())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let plan = self
            .plan
            .upgrade()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        let scope = self
            .complete_scope
            .get()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .scope_data()?;
        self.authenticate_original_complete_member_data(&plan, scope)?;
        self.authenticate_original_retained_observation_identity_data(selected, source, proof)?;
        if !self
            .observation_phases
            .get(selected)
            .is_some_and(|phase| phase.is_verified())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

pub(super) fn counter_scratch_data() -> Result<usize, RuntimeError> {
    checked_sum(
        &[
            size_of::<[usize; 16]>(),
            size_of::<&OriginalInstalledRestorationObservationSigningInputs<'static>>(),
            size_of::<&NativeSchedulingObservation>(),
            size_of::<&PacketNativeRestoredCommitHold>(),
            size_of::<&ContentRef>(),
            size_of::<&PacketCompleteSemanticSource>(),
            size_of::<Result<&PacketCompleteSemanticSource, RuntimeError>>(),
            size_of::<&dyn crate::node_adapters::cnp::CnpSemanticSource>(),
            size_of::<&CnpController>(),
            size_of::<*const ()>(),
            size_of::<Option<&super::scope_owner::OriginalRestorationScopeOwner>>(),
            size_of::<Result<&super::scope_owner::OriginalRestorationScopeOwner, RuntimeError>>(),
            size_of::<crate::node_adapters::cnp::OriginalRestorationColdOwnerView<'static>>(),
            size_of::<
                Result<
                    crate::node_adapters::cnp::OriginalRestorationColdOwnerView<'static>,
                    RuntimeError,
                >,
            >(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<(), crate::node_contract::OperationFailure>>(),
        ],
        usize::MAX,
    )
}
