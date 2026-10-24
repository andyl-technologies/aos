//! Walks actual retained Clock restore preparation without re-decoding its wire.

use crate::node_contract::{RuntimeError, runtime_owned_counter::RetainedRuntimeCounter};

use super::*;

impl PreparedHostContinuation {
    pub(in crate::node_adapters::host) fn charge_clock_requested_backing(
        &self,
        counter: &mut RetainedRuntimeCounter,
    ) -> Result<(), RuntimeError> {
        let Self {
            target,
            source,
            captured,
            fresh_acknowledgements,
            fresh_acknowledgement_bodies,
        } = self;
        let SourceScope {
            generation: _,
            activation_id,
            world_hash,
            cut: _,
            ordinal: _,
            operations,
            inputs,
        } = source;
        let Captured {
            schema_version: _,
            profile,
            boundary: _,
            native,
            native_sequence: _,
            staged,
            input_history,
            pending_causes,
            operations: captured_operations,
            recorded_ingress,
            producer_observations,
        } = captured;
        if !inputs.is_empty()
            || staged.is_some()
            || !input_history.is_empty()
            || !pending_causes.is_empty()
            || recorded_ingress.is_some()
            || producer_observations.is_some()
            || !fresh_acknowledgements.is_empty()
            || !fresh_acknowledgement_bodies.is_empty()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        counter.owned(target)?;
        counter.owned(activation_id)?;
        counter.owned(world_hash)?;
        counter.owned(operations)?;
        counter.slots(inputs)?;
        counter.owned(profile)?;
        counter.owned(native)?;
        counter.slots(input_history)?;
        counter.slots(pending_causes)?;
        counter.slots(captured_operations)?;
        for captured in captured_operations {
            let CapturedOperation {
                operation,
                request,
                outcome,
                acknowledged: _,
                capture,
                evidence,
            } = captured;
            counter.owned(operation)?;
            counter.owned(request)?;
            counter.owned(outcome)?;
            counter.owned(capture)?;
            counter.owned(evidence)?;
        }
        counter.map(fresh_acknowledgements)?;
        counter.map(fresh_acknowledgement_bodies)
    }
}
