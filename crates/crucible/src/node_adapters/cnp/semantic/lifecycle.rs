//! Original nonexecuting preparation and complete all-owner activation custody.

use crucible_node_contract::{ActivationManifest, Extensions, PreparedOwner, Validate, canonical};
use crucible_node_provider::{bodies::*, envelope::Method};

use crate::node_contract::{ActivationRecord, OperationFailure, ReadyAttestation, WorldActivation};

use super::{CnpSemanticNode, after_effect, preparation::request_id, refused, unknown};

impl CnpSemanticNode {
    pub(super) fn arm_original(
        &mut self,
        world: &ActivationRecord,
    ) -> Result<ReadyAttestation, OperationFailure> {
        self.current()?;
        if let Some(original) = &self.state()?.arm_attempt {
            if original != world {
                return Err(refused("generic arm changed original world preparation"));
            }
            let ready = self
                .state()?
                .ready
                .as_ref()
                .ok_or_else(|| unknown("generic original arm remains unresolved"))?;
            self.source()?
                .validate_readiness(self.scope()?, world, ready)?;
            return Ok(ready.clone());
        }
        let source = self.source()?;
        let install = source.installation();
        if world.world_binding_hash != install.world_binding_hash
            || !world.owners.contains(&self.route.owners[0])
            || self.state()?.active.is_some()
            || !self.state()?.operations.is_empty()
            || !self.state()?.inputs.is_empty()
        {
            return Err(refused(
                "generic initial arm changed installed whole-world custody",
            ));
        }
        source.preflight_transition(
            self.scope()?.native,
            super::CnpSemanticTransition::Readiness,
        )?;
        let request = ActivateRequest {
            admission_id: install.admission.clone(),
            activation_id: world.activation_id.clone(),
            world_generation: world.generation,
            prepared_token: self.preparation.realization.prepared_token.clone(),
            world_binding_hash: world.world_binding_hash.clone(),
            gate_id: install.gate.clone(),
            extensions: Extensions::new(),
        };
        let id = request_id("activate", &world.activation_id)?;
        self.state_mut()?.credit.reserve(
            &(
                world.generation,
                &world.activation_id,
                &world.world_binding_hash,
                &world.owners,
                world.boundary,
            ),
            install.maximum_semantic_bytes,
        )?;
        let result_credit = install
            .maximum_result_bytes
            .checked_mul(2)
            .ok_or_else(|| refused("generic original preparation result credit overflows"))?;
        self.state_mut()?
            .credit
            .reserve_bytes(result_credit, install.maximum_semantic_bytes)?;
        self.state_mut()?.arm_attempt = Some(world.clone());
        let response = self.call(id, None, Method::Activate, false, request)?;
        let Some(MethodResult::Activate(result)) = response.result else {
            return Err(unknown("generic original arm did not complete"));
        };
        if result.gate_id != install.gate
            || !result.staged
            || result.staged_owner_ids != [install.owner.owner.id.clone()]
        {
            return Err(unknown(
                "generic original arm changed actual preparation owner/gate",
            ));
        }
        let ready = source
            .readiness(self.scope()?, world, &result)
            .map_err(after_effect)?;
        source
            .validate_readiness(self.scope()?, world, &ready)
            .map_err(after_effect)?;
        let owner = source
            .prepared_owner(self.scope()?, world, &ready)
            .map_err(after_effect)?;
        self.check_owner(&owner, &ready).map_err(after_effect)?;
        super::budget::serialized_size(&ready, install.maximum_result_bytes)
            .map_err(after_effect)?;
        super::budget::serialized_size(&owner, install.maximum_result_bytes)
            .map_err(after_effect)?;
        self.state_mut()?.ready = Some(ready.clone());
        self.state_mut()?.prepared_owner = Some(owner);
        Ok(ready)
    }

    pub(super) fn validate_ready(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        if self.state()?.arm_attempt.as_ref() != Some(world)
            || self.state()?.ready.as_ref() != Some(ready)
            || self.state()?.active.is_some()
        {
            return Err(refused(
                "generic readiness changed original retained preparation",
            ));
        }
        self.source()?
            .validate_readiness(self.scope()?, world, ready)
    }

    pub(super) fn check_owner(
        &self,
        owner: &PreparedOwner,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        owner.validate().map_err(unknown)?;
        let actual = &self.route.owners[0];
        if owner.owner_id != actual.owner
            || owner.incarnation_id != actual.incarnation
            || owner.owner_generation != actual.generation
            || owner.ready_receipt != ready.ready_receipt
            || owner.prepared_token != self.preparation.realization.prepared_token
            || owner.binding_hashes != [self.preparation.binding().identity().map_err(unknown)?]
            || ready.owners != self.route.owners
        {
            return Err(refused(
                "generic public owner mapping differs from original native preparation",
            ));
        }
        Ok(())
    }

    pub(super) fn activate_original(
        &mut self,
        world: &WorldActivation,
    ) -> Result<(), OperationFailure> {
        self.current()?;
        if let Some(original) = &self.state()?.activation_attempt {
            if !original.same_authority(world) {
                return Err(refused(
                    "generic activation changed original opaque common authority",
                ));
            }
            let response = self
                .state()?
                .activate_response
                .as_ref()
                .ok_or_else(|| unknown("generic original activation remains unresolved"))?;
            self.source()?
                .validate_world_activation(self.scope()?, world, response)?;
            if self
                .state()?
                .active
                .as_ref()
                .is_none_or(|active| !active.same_authority(world))
            {
                return Err(unknown(
                    "generic original activated capsule remains unresolved",
                ));
            }
            return Ok(());
        }
        if self.state()?.arm_attempt.as_ref() != Some(world.record()) {
            return Err(refused(
                "generic activation differs from original prepared world",
            ));
        }
        let owners = world
            .prepared_owners()
            .ok_or_else(|| refused("generic complete public owner preparation is absent"))?;
        let coordinator = world
            .coordinator_snapshot()
            .ok_or_else(|| refused("generic durable complete coordinator is absent"))?;
        let own = self
            .state()?
            .prepared_owner
            .as_ref()
            .ok_or_else(|| refused("generic original prepared owner is absent"))?;
        if owners.len() != world.record().owners.len()
            || !owners.contains(own)
            || owners.iter().any(|owner| {
                !world.record().owners.iter().any(|native| {
                    owner.owner_id == native.owner
                        && owner.incarnation_id == native.incarnation
                        && owner.owner_generation == native.generation
                })
            })
        {
            return Err(refused(
                "generic publication omitted or changed actual owner preparation",
            ));
        }
        let source = self.source()?;
        let install = source.installation();
        source.preflight_world_activation(self.scope()?, world)?;
        // Count the complete borrowed owner roster before its first owned copy.
        self.state_mut()?
            .credit
            .reserve(&owners, install.maximum_semantic_bytes)?;
        self.state_mut()?
            .credit
            .reserve(&coordinator.bytes, install.maximum_semantic_bytes)?;
        let manifest = ActivationManifest {
            schema_version: 1,
            transaction_id: install.transaction.clone(),
            activation_id: world.record().activation_id.clone(),
            world_generation: world.record().generation,
            gate_id: install.gate.clone(),
            world_binding_hash: world.record().world_binding_hash.clone(),
            owners: owners.to_vec(),
            coordinator_state_ref: coordinator.reference.clone(),
            extensions: Extensions::new(),
        };
        self.state_mut()?
            .credit
            .reserve(&manifest, install.maximum_semantic_bytes)?;
        let bytes = canonical::canonical_json(&serde_json::to_value(&manifest).map_err(unknown)?)
            .map_err(unknown)?;
        let reference = canonical::content_ref(&bytes, "application/json").map_err(unknown)?;
        let request = WorldActivateRequest {
            transaction_id: install.transaction.clone(),
            activation_id: world.record().activation_id.clone(),
            world_generation: world.record().generation,
            prepared_token: self.preparation.realization.prepared_token.clone(),
            world_binding_hash: world.record().world_binding_hash.clone(),
            gate_id: install.gate.clone(),
            activation_manifest: reference.clone(),
            extensions: Extensions::new(),
        };
        let id = request_id("world-activate", &world.record().activation_id)?;
        self.state_mut()?.activation_attempt = Some(world.clone());
        self.upload(&coordinator.reference, &coordinator.bytes)?;
        self.upload(&reference, &bytes)?;
        let response = self.call(id, None, Method::WorldActivate, false, request)?;
        let Some(MethodResult::WorldActivate(result)) = response.result else {
            return Err(unknown(
                "generic original complete activation did not finish",
            ));
        };
        if result.gate_id != install.gate
            || result.armed_owner_ids != [install.owner.owner.id.clone()]
        {
            return Err(unknown(
                "generic original activation changed native owner/gate",
            ));
        }
        source
            .validate_world_activation(self.scope()?, world, &result)
            .map_err(after_effect)?;
        self.state_mut()?.activate_response = Some(result);
        self.state_mut()?.active = Some(world.clone());
        Ok(())
    }
}
