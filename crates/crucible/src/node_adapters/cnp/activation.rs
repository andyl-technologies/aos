//! Complete committed-world publication consumed before remote native input.

use crucible_node_contract::*;
use crucible_node_provider::{bodies::*, envelope::Method};

use crate::node_contract::{OperationFailure, WorldActivation};

use super::{
    control::{CnpControlledReference, content, original_id},
    readiness::{refused, unknown},
};

impl CnpControlledReference {
    pub(super) fn activate_world(
        &mut self,
        world: &WorldActivation,
    ) -> Result<(), OperationFailure> {
        self.verify_native_custody().map_err(unknown)?;
        if let Some(original) = &self.active {
            if original != world.record() {
                return Err(refused(
                    "public provider belongs to another committed world",
                ));
            }
            return Ok(());
        }
        let prepared = self
            .prepared
            .as_ref()
            .ok_or_else(|| refused("public readiness is unavailable"))?;
        if prepared.record != *world.record() {
            return Err(refused(
                "committed world differs from original prepared native scope",
            ));
        }
        let owners = world
            .prepared_owners()
            .ok_or_else(|| refused("complete public owner preparation is unsupported"))?;
        let coordinator = world
            .coordinator_snapshot()
            .ok_or_else(|| refused("complete durable coordinator state is unsupported"))?;
        if owners.len() != world.record().owners.len()
            || owners.iter().any(|public| {
                !world.record().owners.iter().any(|native| {
                    public.owner_id == native.owner
                        && public.incarnation_id == native.incarnation
                        && public.owner_generation == native.generation
                })
            })
            || !owners.contains(&prepared.owner)
        {
            return Err(refused(
                "complete world publication changed authentic original owner preparation",
            ));
        }
        let bootstrap = self.controller().map_err(unknown)?.bootstrap.clone();
        let manifest = ActivationManifest {
            schema_version: 1,
            transaction_id: bootstrap.transaction_id.clone(),
            activation_id: world.record().activation_id.clone(),
            world_generation: world.record().generation,
            gate_id: bootstrap.gate_id.clone(),
            world_binding_hash: world.record().world_binding_hash.clone(),
            owners: owners.to_vec(),
            coordinator_state_ref: coordinator.reference.clone(),
            extensions: Extensions::new(),
        };
        manifest.validate().map_err(|error| unknown(error.into()))?;
        let (manifest_ref, manifest_bytes) = content(&manifest).map_err(unknown)?;
        let request =
            original_id("world-activate", &world.record().activation_id).map_err(unknown)?;
        let controller = self.controller_mut().map_err(unknown)?;
        controller
            .upload(&coordinator.reference, &coordinator.bytes)
            .map_err(unknown)?;
        controller
            .upload(&manifest_ref, &manifest_bytes)
            .map_err(unknown)?;
        let response = controller
            .call(
                request.clone(),
                None,
                Method::WorldActivate,
                false,
                WorldActivateRequest {
                    transaction_id: bootstrap.transaction_id,
                    activation_id: world.record().activation_id.clone(),
                    world_generation: world.record().generation,
                    prepared_token: bootstrap.prepared_token,
                    world_binding_hash: world.record().world_binding_hash.clone(),
                    gate_id: bootstrap.gate_id.clone(),
                    activation_manifest: manifest_ref,
                    extensions: Extensions::new(),
                },
            )
            .map_err(unknown)?;
        let Some(MethodResult::WorldActivate(result)) = response.result else {
            return Err(unknown(crucible_node_provider::ProviderError::Correlation(
                "original public world activation did not complete",
            )));
        };
        let receipt: ControlReceipt = self
            .controller()
            .map_err(unknown)?
            .record(&result.activation_receipt)
            .map_err(unknown)?;
        let own = self
            .prepared
            .as_ref()
            .ok_or_else(|| refused("original prepared owner unavailable"))?;
        let ready: ControlReceipt = self
            .controller()
            .map_err(unknown)?
            .record(&own.owner.ready_receipt)
            .map_err(unknown)?;
        if result.gate_id != bootstrap.gate_id
            || result.armed_owner_ids != [bootstrap.owner_id.clone()]
            || receipt.kind != ControlReceiptKind::ActivationReady
            || receipt.issuer != ReceiptIssuer::Provider
            || receipt.session_id != bootstrap.authority.session_id
            || receipt.incarnation_id != bootstrap.authority.incarnation_id
            || receipt.request_id != request
            || receipt.operation_id.is_some()
            || receipt.owner_ids != [bootstrap.owner_id]
            || receipt.world_generation != world.record().generation
            || receipt.record_ref != ready.record_ref
            || !receipt.extensions.is_empty()
        {
            return Err(unknown(crucible_node_provider::ProviderError::Correlation(
                "public activation changed original native preparation",
            )));
        }
        self.verify_native_custody().map_err(unknown)?;
        self.active = Some(world.record().clone());
        self.probe_adopted_lifecycle(
            super::lifecycle_resend::CnpCompletedLifecyclePhase::WorldActivated,
            request,
            None,
            None,
            vec![result.activation_receipt.clone()],
            MethodResult::WorldActivate(result),
        )
        .map_err(unknown)?;
        Ok(())
    }
}
