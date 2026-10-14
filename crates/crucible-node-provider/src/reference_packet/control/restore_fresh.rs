//! Quotes the actual fresh Control/model owners and their existing gate proof.
//!
//! The opaque quote is valid only while the endpoint's selected transfer guard
//! prevents ordinary dispatch. It retains the real original allocation identity;
//! its measured capacities and receipt are data, not a restored-world permit.

use super::*;
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use serde::Deserialize;
use std::rc::Rc;

pub(crate) struct PacketFreshRestoreControlAllocation {
    creator: u32,
    identity: Rc<()>,
    policy: Rc<super::super::Native5Policy>,
    facts: RetainedProtocolMetadataFacts,
    endpoint: super::super::endpoint::PacketEndpointRestoreAllocation,
    gate: ContentRef,
}

impl PacketFreshRestoreControlAllocation {
    pub(crate) fn authenticate_original(
        &self,
        policy: &Rc<super::super::Native5Policy>,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || !Rc::ptr_eq(&self.policy, policy) {
            return Err(ProviderError::Correlation(
                "restore actual fresh Control quote",
            ));
        }
        self.endpoint.authenticate_original(policy)
    }
    pub(crate) fn endpoint_facts(&self) -> RetainedProtocolMetadataFacts {
        self.endpoint.facts()
    }
    pub(crate) fn endpoint_header_bytes(&self) -> usize {
        self.endpoint.owner_header_bytes()
    }
    pub(crate) fn facts(&self) -> RetainedProtocolMetadataFacts {
        self.facts
    }
}

impl PacketControl {
    pub(crate) fn quote_original_fresh_restore_control(
        &self,
        policy: &Rc<super::super::Native5Policy>,
        endpoint: super::super::endpoint::PacketEndpointRestoreAllocation,
    ) -> Result<PacketFreshRestoreControlAllocation, ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation("restore Control origin"));
        }
        policy.authenticate_original_control_selection(&self.selection)?;
        if !self.realized || !self.admitted || self.fenced || self.native_effect_attempted
            || self.staged.is_some() || self.active.is_some() || self.current_operation.is_some()
            || !self.begins.is_empty() || !self.begin_requests.is_empty() || !self.terminals.is_empty()
            || self.common_coordinator.is_some() || self.world_coordinator.is_some() || self.connected_coordinator.is_some()
            || self.complete_coordinator.is_none()
            || self.complete_restore_selection != Some(super::super::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return Err(ProviderError::Correlation("restore Control is not an untouched selected owner"));
        }
        let mut observer = MetadataObserver::new();
        observer.observe(&self.selection)?;
        observer.shared_value(self.capture_identity.as_ref())?;
        observer.tree::<Id, (HashRef, PacketControlReply)>(self.originals.len())?;
        let mut gate = None;
        for (id, (hash, reply)) in &self.originals {
            observer.observe(id)?;
            observer.observe(hash)?;
            observer.observe(&reply.body)?;
            observer.vector::<(ContentRef, Vec<u8>)>(reply.evidence.capacity())?;
            for (reference, bytes) in &reply.evidence {
                observer.observe(reference)?;
                observer.observe(bytes)?;
            }
            // Only Realize constructs this exact closed result in the private
            // original cache. The SDK separately checks its actual literal pair.
            if let Some(result) = reply.body.get("result").and_then(Value::as_object)
                && result.len() == 3
                && result.contains_key("realization_manifest")
                && result.get("prepared_token").and_then(Value::as_str)
                    == Some(self.selection.prepared_token.as_str())
                && let Some(reference) = result.get("closed_gate_receipt")
            {
                let reference = ContentRef::deserialize(reference).map_err(ContractError::from)?;
                let bytes = reply
                    .evidence
                    .iter()
                    .find_map(|(actual, bytes)| (actual == &reference).then_some(bytes))
                    .ok_or(ProviderError::Correlation(
                        "restore original gate proof absent",
                    ))?;
                reference.verify(bytes)?;
                if gate.replace(reference).is_some() {
                    return Err(ProviderError::Correlation(
                        "restore original Realize is not unique",
                    ));
                }
            }
        }
        observer.tree::<Id, BeginRequest>(self.begins.len())?;
        observer.tree::<Id, Id>(self.begin_requests.len())?;
        observer.tree::<Id, Map<String, Value>>(self.terminals.len())?;
        observer.observe(&self.content)?;
        observer.observe(
            self.complete_coordinator
                .as_ref()
                .ok_or(ProviderError::Correlation("restore coordinator absent"))?,
        )?;
        match &self.program {
            NativeProgram::OutputOnly(program) => {
                program.observe_fresh_restore_metadata(&mut observer)?
            }
            NativeProgram::Connected(program) => {
                program.observe_fresh_restore_metadata(&mut observer)?
            }
            NativeProgram::RestorationInProgress => {
                return Err(ProviderError::Conflict("packet restored model incomplete"));
            }
        }
        let gate = gate.ok_or(ProviderError::Correlation(
            "restore original Realize proof absent",
        ))?;
        observer.observe(&gate)?;
        observer.shared_value(self.capture_identity.as_ref())?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativePolicy,
            policy.as_ref(),
        )?;
        policy.observe_owned11_metadata(&mut observer)?;
        Ok(PacketFreshRestoreControlAllocation {
            creator: self.capture_creator,
            identity: Rc::clone(&self.capture_identity),
            policy: Rc::clone(policy),
            facts: observer.finish(),
            endpoint,
            gate,
        })
    }

    pub(crate) fn original_restore_prepare_result_data(
        &self,
        quote: &PacketFreshRestoreControlAllocation,
        request: &super::super::service::complete_restore::transfer::PacketCompleteRestorePrepareRequest,
    ) -> Result<PrepareRestoreResult, ProviderError> {
        if self.capture_creator != std::process::id()
            || !Rc::ptr_eq(&self.capture_identity, &quote.identity)
            || self.fenced
            || self.staged.is_some()
            || self.active.is_some()
            || self.current_operation.is_some()
        {
            return Err(ProviderError::Correlation("restore fresh gate changed"));
        }
        quote.authenticate_original(&quote.policy)?;
        let target = &request.restoration;
        let owner = self
            .selection
            .realization
            .owner_bindings
            .first()
            .ok_or(ProviderError::Correlation("restore owner absent"))?;
        if target.target_world != self.selection.world
            || target.target_owner_binding != owner.identity()?
            || target.target_owner != owner.owner.id
        {
            return Err(ProviderError::Correlation("restore target owner changed"));
        }
        Ok(PrepareRestoreResult {
            transaction_id: request.transaction_id.clone(),
            prepared_token: self.selection.prepared_token.clone(),
            world_binding_hash: self.selection.world.clone(),
            owner_binding_hash: target.target_owner_binding.clone(),
            staged_owner_ids: std::iter::once(target.target_owner.clone()).collect(),
            closed_gate_receipt: quote.gate.clone(),
            validated_manifest: target.capture_manifest.clone(),
        })
    }
}
