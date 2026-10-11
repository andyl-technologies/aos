//! Actual nonexecuting public preparation and original owner-ready evidence.

use crucible_node_contract::*;
use crucible_node_provider::{ProviderError, bodies::*, envelope::Method};

use crate::node_contract::{
    ActivationRecord, EffectKnowledge, OperationFailure, OwnerIdentity, ReadyAttestation,
};

use super::control::{CnpControlledReference, PreparedActivation, original_id};

impl CnpControlledReference {
    pub(super) fn prepare_activation(
        &mut self,
        record: &ActivationRecord,
    ) -> Result<ReadyAttestation, OperationFailure> {
        self.verify_native_custody().map_err(unknown)?;
        if self
            .preparation_attempt
            .as_ref()
            .is_some_and(|original| original != record)
        {
            return Err(refused(
                "public activation retry changed original world preparation",
            ));
        }
        if let Some(prepared) = &self.prepared {
            if prepared.record != *record {
                return Err(refused("public preparation already retains another world"));
            }
            if !prepared.registry_complete {
                return Err(unknown(ProviderError::Correlation(
                    "original public readiness registry remains unresolved",
                )));
            }
            return Ok(prepared.ready.clone());
        }
        if self.preparation_attempt.is_some() {
            return Err(unknown(ProviderError::Correlation(
                "original public activation attempt remains unresolved",
            )));
        }
        let bootstrap = self.controller().map_err(unknown)?.bootstrap.clone();
        let owner = OwnerIdentity {
            owner: bootstrap.owner_id.clone(),
            incarnation: bootstrap.authority.incarnation_id.clone(),
            generation: bootstrap.authority.owner_generation,
        };
        if record.activation_id != bootstrap.activation_id
            || record.generation != bootstrap.world_generation
            || record.world_binding_hash != bootstrap.world_binding_hash
            || !record.owners.contains(&owner)
            || record.boundary != Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
        {
            return Err(refused(
                "public preparation differs from private admitted initial world",
            ));
        }
        let request_id = original_id("prepare-activate", &record.activation_id).map_err(unknown)?;
        // Retain the complete original world proposal before any remote effect.
        // The public request alone omits the other owners' host barrier data.
        self.preparation_attempt = Some(record.clone());
        let response = self
            .controller_mut()
            .map_err(unknown)?
            .call(
                request_id.clone(),
                None,
                Method::Activate,
                false,
                ActivateRequest {
                    admission_id: bootstrap.admission_id.clone(),
                    activation_id: record.activation_id.clone(),
                    world_generation: record.generation,
                    prepared_token: bootstrap.prepared_token.clone(),
                    world_binding_hash: record.world_binding_hash.clone(),
                    gate_id: bootstrap.gate_id.clone(),
                    extensions: Extensions::new(),
                },
            )
            .map_err(unknown)?;
        let Some(MethodResult::Activate(result)) = response.result else {
            return Err(unknown(ProviderError::Correlation(
                "original public activation preparation remains unresolved",
            )));
        };
        let probe_result = result.clone();
        if !result.staged
            || result.gate_id != bootstrap.gate_id
            || result.staged_owner_ids != [owner.owner.clone()]
        {
            return Err(unknown(ProviderError::Correlation(
                "public ready scope changed",
            )));
        }
        let receipt: ControlReceipt = self
            .controller()
            .map_err(unknown)?
            .record(&result.activation_receipt)
            .map_err(unknown)?;
        let ready_record: ActivationReadyRecord = self
            .controller()
            .map_err(unknown)?
            .record(&receipt.record_ref)
            .map_err(unknown)?;
        let (gate_ref, _) = super::control::content(&self.gate).map_err(unknown)?;
        if receipt.kind != ControlReceiptKind::ActivationReady
            || receipt.issuer != ReceiptIssuer::Provider
            || receipt.session_id != bootstrap.authority.session_id
            || receipt.incarnation_id != owner.incarnation
            || receipt.request_id != request_id
            || receipt.operation_id.is_some()
            || receipt.owner_ids != [owner.owner.clone()]
            || receipt.world_generation.get() != 0
            || !receipt.extensions.is_empty()
            || ready_record.activation_id != record.activation_id
            || ready_record.world_generation != record.generation
            || ready_record.gate_id != bootstrap.gate_id
            || ready_record.prepared_token != bootstrap.prepared_token
            || ready_record.world_binding_hash != record.world_binding_hash
            || ready_record.owner_ids != [owner.owner.clone()]
            || !ready_record.gate_closed
            || ready_record.evidence_refs != [gate_ref.clone()]
            || !ready_record.extensions.is_empty()
        {
            return Err(unknown(ProviderError::Correlation(
                "public preparation evidence changed original closed gate",
            )));
        }
        self.verify_native_custody().map_err(unknown)?;
        let ready = ReadyAttestation {
            owners: vec![owner.clone()],
            boundary: record.boundary,
            state_inventory: self
                .controller()
                .map_err(unknown)?
                .profile
                .descriptor
                .initialization_ref
                .clone(),
            ready_receipt: result.activation_receipt.clone(),
        };
        let prepared_owner = PreparedOwner {
            owner_id: owner.owner,
            incarnation_id: owner.incarnation,
            owner_generation: owner.generation,
            prepared_token: bootstrap.prepared_token,
            binding_hashes: vec![
                self.binding
                    .identity()
                    .map_err(|error| unknown(error.into()))?,
            ],
            ready_receipt: result.activation_receipt,
            extensions: Extensions::new(),
        };
        self.prepared = Some(PreparedActivation {
            record: record.clone(),
            ready: ready.clone(),
            registry_complete: false,
            owner: prepared_owner,
        });
        let gate_record: ClosedGateRecord = self
            .controller()
            .map_err(unknown)?
            .record(&self.gate.record_ref)
            .map_err(unknown)?;
        self.retain_boundary_record(&gate_record.physical_status_ref, Vec::new())
            .map_err(after_native_effect)?;
        self.retain_boundary_record(
            &self.gate.record_ref.clone(),
            vec![gate_record.physical_status_ref],
        )
        .map_err(after_native_effect)?;
        self.retain_boundary_record(&gate_ref, vec![self.gate.record_ref.clone()])
            .map_err(after_native_effect)?;
        self.retain_boundary_record(&receipt.record_ref, ready_record.evidence_refs)
            .map_err(after_native_effect)?;
        self.retain_boundary_record(&ready.ready_receipt, vec![receipt.record_ref])
            .map_err(after_native_effect)?;
        self.prepared
            .as_mut()
            .ok_or_else(|| {
                unknown(ProviderError::Correlation(
                    "original public preparation custody lost",
                ))
            })?
            .registry_complete = true;
        self.probe_adopted_lifecycle(
            super::lifecycle_resend::CnpCompletedLifecyclePhase::Prepared,
            request_id,
            None,
            None,
            vec![ready.ready_receipt.clone()],
            MethodResult::Activate(probe_result),
        )
        .map_err(unknown)?;
        Ok(ready)
    }

    pub(super) fn validate_activation(
        &self,
        record: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        self.verify_native_custody().map_err(unknown)?;
        if self.prepared.as_ref().is_none_or(|prepared| {
            prepared.record != *record || prepared.ready != *ready || !prepared.registry_complete
        }) || self.preparation_attempt.as_ref() != Some(record)
            || self.active.is_some()
            || self.input.is_some()
            || !self.windows.is_empty()
        {
            return Err(refused("original public readiness custody changed"));
        }
        Ok(())
    }
}

pub(super) fn unknown(error: ProviderError) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: error.to_string(),
    }
}

/// Keeps local bookkeeping refusal from claiming absence of an earlier native effect.
pub(super) fn after_native_effect(mut error: OperationFailure) -> OperationFailure {
    error.effects = EffectKnowledge::Unknown;
    error
}

pub(super) fn refused(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}
