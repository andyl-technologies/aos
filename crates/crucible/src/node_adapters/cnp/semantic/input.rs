//! Complete original input cuts staged once without semantic consumption.

use std::rc::Rc;

use crucible_node_contract::{Extensions, U64, Validate};
use crucible_node_provider::{bodies::*, envelope::Method};

use crate::{
    node_contract::OperationFailure,
    node_scheduling::{NativeInputAcknowledgement, RuntimeInputBatch},
};

use super::{
    CnpSemanticNode, after_effect, preparation::request_id, refused, state::OriginalInput, unknown,
};

impl CnpSemanticNode {
    pub(super) fn stage_original(
        &mut self,
        batch: &RuntimeInputBatch,
    ) -> Result<NativeInputAcknowledgement, OperationFailure> {
        self.current()?;
        if batch.node() != &self.route.node || batch.owners() != self.route.owners {
            return Err(refused(
                "generic native staging has foreign input owner scope",
            ));
        }
        if let Some(original) = self.state()?.inputs.get(batch.stage_operation()) {
            if original.original.batch() != batch.batch()
                || original.original.inventory() != batch.inventory()
                || original.original.cutoff() != batch.cutoff()
                || original.original.deliveries() != batch.deliveries()
                || original.original.payloads() != batch.payloads()
                || !original
                    .original
                    .activation()
                    .same_authority(batch.activation())
            {
                return Err(refused(
                    "generic staging retry changed the complete original cut",
                ));
            }
            let response = original
                .response
                .as_ref()
                .ok_or_else(|| unknown("generic original native input remains unresolved"))?;
            let ack = self
                .source()?
                .input_acknowledgement(self.scope()?, batch, response)?;
            if original.acknowledgement.as_ref() != Some(&ack) {
                return Err(unknown(
                    "generic retained input acknowledgement changed native staging",
                ));
            }
            return Ok(ack);
        }
        let source = self.source()?;
        let install = source.installation();
        if self.state()?.inputs.len() >= install.maximum_operations
            || self
                .state()?
                .operations
                .values()
                .any(|original| !original.acknowledged)
        {
            return Err(refused(
                "generic staging credit or current owner reservation is unavailable",
            ));
        }
        let sequence = U64::new(
            self.state()?
                .watermark
                .get()
                .checked_add(1)
                .ok_or_else(|| refused("generic original native input sequence exhausted"))?,
        );
        let public = source.input_batch(batch, sequence)?;
        public.validate().map_err(unknown)?;
        if public.batch_id != *batch.batch()
            || public.batch_sequence != sequence
            || public.input_epoch != install.binding.authority.input_epoch
            || public.execution_owner_id != install.owner.owner.id
        {
            return Err(refused(
                "generic source input mapping changed original owner stream",
            ));
        }
        // Credit all repeated ownership before the first retained batch copy.
        let maximum = install.maximum_semantic_bytes;
        self.state_mut()?
            .credit
            .reserve(&batch.deliveries(), maximum)?;
        self.state_mut()?
            .credit
            .reserve(&batch.payloads(), maximum)?;
        self.state_mut()?.credit.reserve(&public, maximum)?;
        let request = InputRequest {
            binding_hash: install.owner.identity().map_err(unknown)?,
            owner_generation: install.binding.authority.owner_generation,
            batch_id: public.batch_id.clone(),
            batch_sequence: public.batch_sequence,
            input_epoch: public.input_epoch.clone(),
            batch_hash: crucible_node_contract::canonical::json_hash("cnp.input-batch.v1", &public)
                .map_err(unknown)?,
            events: public.events,
            extensions: Extensions::new(),
        };
        let id = request_id("input", batch.stage_operation())?;
        self.state_mut()?
            .credit
            .reserve_bytes(install.maximum_result_bytes, maximum)?;
        self.activate_original(batch.activation())?;
        self.state_mut()?.inputs.insert(
            batch.stage_operation().clone(),
            OriginalInput {
                original: Rc::new(batch.retained_copy()),
                acknowledgement: None,
                response: None,
                watermark: sequence,
            },
        );
        for payload in batch.payloads() {
            payload.reference.verify(&payload.bytes).map_err(unknown)?;
            self.upload(&payload.reference, &payload.bytes)?;
        }
        let response = self.call(id, None, Method::Input, true, request)?;
        let Some(MethodResult::Input(result)) = response.result else {
            return Err(unknown(
                "generic original native input staging did not complete",
            ));
        };
        let ack = source
            .input_acknowledgement(self.scope()?, batch, &result)
            .map_err(after_effect)?;
        self.check_ack(batch, &ack).map_err(after_effect)?;
        super::budget::serialized_size(&ack, install.maximum_result_bytes).map_err(after_effect)?;
        let original = self
            .state_mut()?
            .inputs
            .get_mut(batch.stage_operation())
            .ok_or_else(|| unknown("generic original input custody disappeared"))?;
        original.acknowledgement = Some(ack.clone());
        original.response = Some(result);
        self.state_mut()?.watermark = sequence;
        Ok(ack)
    }

    pub(super) fn check_ack(
        &self,
        batch: &RuntimeInputBatch,
        ack: &NativeInputAcknowledgement,
    ) -> Result<(), OperationFailure> {
        if ack.stage_operation != *batch.stage_operation()
            || ack.batch != *batch.batch()
            || ack.node != self.route.node
            || ack.owners != self.route.owners
            || ack.cutoff != batch.cutoff()
            || ack.inventory != *batch.inventory()
        {
            return Err(refused(
                "generic input ACK changed original complete staging population",
            ));
        }
        Ok(())
    }
}
