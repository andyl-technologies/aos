//! Sends separately signed actual Arm and World phases under the same association.
//!
//! Ready is assembled only after the genuine Source evidence and Core once
//! ledger authenticate the actual native staged receipt. World uploads occur
//! inside that Source action before reserving its final assigned request.

use super::*;
use crate::node_admission::OriginalInstalledRestorationActivationPhase as CorePhase;
use crate::node_contract::ReadyAttestation;
use crucible_node_format::{ActivationManifest, Extensions, PreparedOwner, Validate, canonical};
use crucible_node_transport::{
    bodies::*, reference_packet::service::complete_restore::activation::*,
};

impl super::super::super::CnpSemanticNode {
    pub(in crate::node_adapters::cnp::semantic) fn arm_installed_restoration(
        &mut self,
        world: &ActivationRecord,
    ) -> Result<ReadyAttestation, OperationFailure> {
        self.current()?;
        if self.state()?.arm_attempt.is_some() {
            let ready =
                self.state()?.ready.as_ref().ok_or_else(|| {
                    super::super::super::unknown("selected Arm remains unresolved")
                })?;
            self.validate_installed_ready(world, ready)?;
            return Ok(ready.clone());
        }
        let source = self.source()?;
        let installation = source.installation();
        if world.world_binding_hash != installation.world_binding_hash
            || self.route.owners.len() != 1
            || !world.owners.contains(&self.route.owners[0])
            || self.state()?.active.is_some()
        {
            return Err(super::super::super::refused(
                "selected Arm changed actual target custody",
            ));
        }
        let request = ActivateRequest {
            admission_id: installation.admission.clone(),
            activation_id: world.activation_id.clone(),
            world_generation: world.generation,
            prepared_token: self.preparation.realization.prepared_token.clone(),
            world_binding_hash: world.world_binding_hash.clone(),
            gate_id: installation.gate.clone(),
            extensions: Extensions::new(),
        };
        self.state_mut()?.arm_attempt = Some(world.clone());
        self.call_installed_phase(
            CorePhase::Arm,
            PacketRestorationActivationCommand::Arm(request),
            None,
        )?;
        let result = {
            let selected = self
                .state()?
                .installed_restoration
                .as_ref()
                .ok_or_else(|| super::super::super::refused("selected association absent"))?;
            let Some(MethodResult::Activate(result)) = selected.completed[0]
                .as_ref()
                .and_then(|body| body.result.as_ref())
            else {
                return Err(super::super::super::unknown(
                    "selected native Arm did not complete",
                ));
            };
            result.validate().map_err(super::super::super::unknown)?;
            if result.gate_id != installation.gate
                || result.staged_owner_ids != [self.route.owners[0].owner.clone()]
                || result.activation_receipt.media_type != "application/json"
            {
                return Err(super::super::super::refused(
                    "selected native Arm receipt changed actual owner or gate",
                ));
            }
            result.activation_receipt.clone()
        };
        let ready = ReadyAttestation {
            owners: self.route.owners.clone(),
            boundary: world.boundary,
            state_inventory: result.clone(),
            ready_receipt: result,
        };
        // Actual completed phase evidence precedes these copied public views.
        self.state_mut()?.ready = Some(ready);
        let owner = PreparedOwner {
            owner_id: self.route.owners[0].owner.clone(),
            incarnation_id: self.route.owners[0].incarnation.clone(),
            owner_generation: self.route.owners[0].generation,
            prepared_token: self.preparation.realization.prepared_token.clone(),
            binding_hashes: vec![
                self.preparation
                    .binding()
                    .identity()
                    .map_err(super::super::super::unknown)?,
            ],
            ready_receipt: self
                .state()?
                .ready
                .as_ref()
                .ok_or_else(|| super::super::super::refused("selected Ready absent"))?
                .ready_receipt
                .clone(),
            extensions: Extensions::new(),
        };
        self.check_owner(
            &owner,
            self.state()?
                .ready
                .as_ref()
                .ok_or_else(|| super::super::super::refused("selected Ready absent"))?,
        )?;
        self.state_mut()?.prepared_owner = Some(owner);
        let ready = self
            .state()?
            .ready
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected Ready absent"))?;
        self.validate_installed_ready(world, ready)?;
        Ok(ready.clone())
    }

    pub(in crate::node_adapters::cnp::semantic) fn validate_installed_ready(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        self.authenticate_installed_restoration_current_data()?;
        if self.state()?.arm_attempt.as_ref() != Some(world)
            || self.state()?.ready.as_ref() != Some(ready)
            || self.state()?.active.is_some()
            || ready.owners != self.route.owners
            || ready.boundary != world.boundary
            || ready.ready_receipt != ready.state_inventory
            || ready.ready_receipt.media_type != "application/json"
        {
            return Err(super::super::super::refused(
                "selected Ready changed actual staged native receipt",
            ));
        }
        let selected = self
            .state()?
            .installed_restoration
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected association absent"))?;
        let Some(MethodResult::Activate(result)) = selected.completed[0]
            .as_ref()
            .and_then(|body| body.result.as_ref())
        else {
            return Err(super::super::super::refused(
                "selected native Arm terminal absent",
            ));
        };
        if result.activation_receipt != ready.ready_receipt {
            return Err(super::super::super::refused(
                "selected Ready receipt changed",
            ));
        }
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic) fn activate_installed_restoration(
        &mut self,
        world: &WorldActivation,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        if let Some(active) = &self.state()?.active {
            if !active.same_authority(world) {
                return Err(super::super::super::refused(
                    "selected active world authority changed",
                ));
            }
            return self.authenticate_installed_restoration_current_data();
        }
        if self.state()?.activation_attempt.is_some() {
            return Err(super::super::super::unknown(
                "selected World activation is spent or unresolved",
            ));
        }
        let ready = self
            .state()?
            .ready
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected native Ready absent"))?;
        self.validate_installed_ready(world.record(), ready)?;
        let source = self.source()?;
        let installation = source.installation();
        let owners = world
            .prepared_owners()
            .ok_or_else(|| super::super::super::refused("real complete prepared owners absent"))?;
        let coordinator = world
            .coordinator_snapshot()
            .ok_or_else(|| super::super::super::refused("real prepared coordinator absent"))?;
        let own = self
            .state()?
            .prepared_owner
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected prepared owner absent"))?;
        if owners.len() != world.record().owners.len() || !owners.contains(own) {
            return Err(super::super::super::refused(
                "selected world omitted actual prepared owner",
            ));
        }
        self.state_mut()?.activation_attempt = Some(world.clone());
        let manifest = ActivationManifest {
            schema_version: 1,
            transaction_id: installation.transaction.clone(),
            activation_id: world.record().activation_id.clone(),
            world_generation: world.record().generation,
            gate_id: installation.gate.clone(),
            world_binding_hash: world.record().world_binding_hash.clone(),
            owners: owners.to_vec(),
            coordinator_state_ref: coordinator.reference.clone(),
            extensions: Extensions::new(),
        };
        let selected = self
            .state_mut()?
            .installed_restoration
            .as_mut()
            .ok_or_else(|| super::super::super::refused("selected association absent"))?;
        selected.world_manifest = Some(manifest);
        selected.world_value = Some(
            serde_json::to_value(
                selected
                    .world_manifest
                    .as_ref()
                    .ok_or_else(|| super::super::super::refused("selected manifest absent"))?,
            )
            .map_err(super::super::super::unknown)?,
        );
        selected.world_bytes =
            Some(
                canonical::canonical_json(selected.world_value.as_ref().ok_or_else(|| {
                    super::super::super::refused("selected manifest Value absent")
                })?)
                .map_err(super::super::super::unknown)?,
            );
        let reference = canonical::content_ref(
            selected
                .world_bytes
                .as_ref()
                .ok_or_else(|| super::super::super::refused("selected manifest bytes absent"))?,
            "application/json",
        )
        .map_err(super::super::super::unknown)?;
        let request = WorldActivateRequest {
            transaction_id: installation.transaction.clone(),
            activation_id: world.record().activation_id.clone(),
            world_generation: world.record().generation,
            prepared_token: self.preparation.realization.prepared_token.clone(),
            world_binding_hash: world.record().world_binding_hash.clone(),
            gate_id: installation.gate.clone(),
            activation_manifest: reference,
            extensions: Extensions::new(),
        };
        self.call_installed_phase(
            CorePhase::WorldActivate,
            PacketRestorationActivationCommand::WorldActivate(request),
            Some(world),
        )?;
        let selected = self
            .state()?
            .installed_restoration
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected association absent"))?;
        let Some(MethodResult::WorldActivate(result)) = selected.completed[1]
            .as_ref()
            .and_then(|body| body.result.as_ref())
        else {
            return Err(super::super::super::unknown(
                "selected World terminal absent",
            ));
        };
        if result.gate_id != installation.gate
            || result.armed_owner_ids != [self.route.owners[0].owner.clone()]
        {
            return Err(super::super::super::refused(
                "selected World changed native gate or owners",
            ));
        }
        let result = result.clone();
        self.state_mut()?.activate_response = Some(result);
        self.state_mut()?.active = Some(world.clone());
        self.authenticate_installed_restoration_current_data()
    }

    fn call_installed_phase(
        &mut self,
        phase: CorePhase,
        command: PacketRestorationActivationCommand,
        world: Option<&WorldActivation>,
    ) -> Result<(), OperationFailure> {
        let native = self
            .preparation
            .guard
            .custody
            .as_mut()
            .ok_or_else(|| super::super::super::refused("selected native capsule absent"))?;
        let source = native
            .source
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected Source absent"))?;
        let controller = native
            .controller
            .as_mut()
            .ok_or_else(|| super::super::super::refused("selected Controller absent"))?;
        let selected = native
            .runtime
            .as_mut()
            .and_then(|state| state.installed_restoration.as_mut())
            .ok_or_else(|| super::super::super::refused("selected association absent"))?;
        let index = match phase {
            CorePhase::Arm => 0,
            CorePhase::WorldActivate => 1,
        };
        if selected.commands[index].is_some() || selected.completed[index].is_some() {
            return Err(super::super::super::refused("selected phase is spent"));
        }
        let admitted = selected
            .association
            .admitted_source_activation_data()
            .map_err(super::super::super::refused_display)?;
        let claim = selected
            .association
            .begin_original_activation_claim_data(
                source.as_ref(),
                controller,
                Rc::as_ptr(&native.read_owner).cast(),
                phase,
                world,
            )
            .map_err(super::super::super::refused_display)?;
        selected.commands[index] = Some(command);
        let command = selected.commands[index]
            .as_ref()
            .ok_or_else(|| super::super::super::refused("selected command absent"))?
            .clone();
        let evidence = source
            .call_original_installed_restoration_activation_into(
                controller,
                claim,
                command,
                &admitted,
                &mut selected.completed[index],
            )
            .map_err(super::super::super::unknown)?;
        selected
            .association
            .authenticate_original_activation_evidence_data(source.as_ref(), phase, &evidence)
            .map_err(super::super::super::unknown)
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    crate::node_adapters::cnp::semantic::PacketCompleteSemanticSource::original_restoration_activation_source_construction_counter_scratch_data()
        + size_of::<crate::node_contract::ReadyAttestation>()
        + size_of::<crucible_node_format::PreparedOwner>()
        + size_of::<Result<crate::node_contract::ReadyAttestation, OperationFailure>>()
        + size_of::<Rc<dyn crate::node_adapters::cnp::semantic::CnpSemanticSource>>()
        + size_of::<Result<Rc<dyn crate::node_adapters::cnp::semantic::CnpSemanticSource>, OperationFailure>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Option<&[u8]>>() + size_of::<Result<&[u8], RuntimeError>>()
        + size_of::<Option<&OriginalInstalledRestorationCustodyConstructionData>>()
        + size_of::<Result<&OriginalInstalledRestorationCustodyConstructionData, RuntimeError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<Result<crucible_node_format::HashRef, crucible_node_format::ContractError>>()
        + size_of::<blake3::Hasher>()
        + size_of::<PacketRestorationActivationCommand>()
        + size_of::<[Option<ResponseBody>; 2]>()
        + size_of::<ActivationManifest>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
        + size_of::<Result<crucible_node_format::ContentRef, crucible_node_format::ContractError>>(
        )
        + size_of::<crate::node_admission::OriginalInstalledRestorationActivationClaim>()
        + size_of::<
            Result<
                crate::node_admission::OriginalInstalledRestorationActivationClaim,
                RuntimeError,
            >,
        >()
        + size_of::<crate::node_adapters::cnp::OriginalSourceRestorationActivationConstructionData>(
        )
        + size_of::<
            Result<
                crate::node_adapters::cnp::OriginalSourceRestorationActivationConstructionData,
                RuntimeError,
            >,
        >()
        + size_of::<Result<(), OperationFailure>>()
        + size_of::<Result<(), RuntimeError>>()
}
