//! Observes requested backing of the same actual timer-free Clock adapter.
//!
//! Every retained field is either walked under its original immutable loan or
//! explicitly refused. The enclosing Box charges the inline adapter/model. This
//! observer allocates no inventory, serializes no records and creates no source,
//! execution, allocation or restoration permission. The pinned compiler's tree
//! and shared-header accounting is distinct from allocator residency, native
//! memory, kernel objects and compiler frames.

use std::mem::size_of;

use crate::node_contract::{
    opaque_owner_counter_scratch_data, runtime_owned_counter::RetainedRuntimeCounter,
};

use super::*;

impl HostModelNode {
    /// Checks the actual constructor origin before borrowing any retained owner.
    pub(super) fn original_clock_storage_origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Names simultaneous explicit counter and borrowed descriptor scratch.
    ///
    /// The containing runtime's own counter remains a separate live term. This
    /// does not estimate recursive/compiler frames or physical allocation peaks.
    pub fn original_clock_requested_backing_scratch_data() -> usize {
        size_of::<RetainedRuntimeCounter>() + opaque_owner_counter_scratch_data()
    }

    /// Walks the closed Clock owner's actual backing, excluding its inline Box.
    ///
    /// This data read does not issue permission or invoke an erased adapter.
    ///
    /// # Errors
    /// Refuses foreign origin, busy/unsupported retained fields or the bound.
    pub fn original_clock_requested_backing_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.original_clock_storage_origin()?;
        let Self {
            descriptor,
            binding,
            route,
            model,
            role_definition,
            retired_model,
            graceful_retirement: _,
            initial,
            boundary: _,
            thread: _,
            process: _,
            facets,
            preservation,
            fault_injection,
            condition_debug,
            pause,
            world_hash,
            limits: _,
            readiness,
            completed,
            condition_objects,
            condition_operation_objects,
            failed,
            reclamations,
            quarantined: _,
            activation_authority,
            execution,
            terminal,
            terminal_inventory,
            input_endpoint,
            output_endpoint,
            maximum_microsteps: _,
            staged,
            input_history,
            pending_causes,
            native_sequence: _,
            scheduling_observation,
            prepared_continuation,
            readiness_inventory,
            original_model_session,
            preparation_origin: _,
            public_preparation,
            public_model_preparation,
            public_model_history,
            public_continuation: _,
            recorded_ingress,
            condition_preservation,
            producer_observations,
        } = self;
        // These are actual retained fields, not profile labels. Another model,
        // erased input owner or optional family remains unsupported even when
        // its portable record happens to look like an empty Clock.
        if !matches!(role_definition, roles::HostRoleDefinition::Clock)
            || !matches!(
                (model, retired_model),
                (Some(HostModel::Clock(_)), None) | (None, Some(HostModel::Clock(_)))
            )
            || input_endpoint.is_some()
            || output_endpoint.is_some()
            || staged.is_some()
            || !input_history.is_empty()
            || !pending_causes.is_empty()
            || !condition_objects.is_empty()
            || !condition_operation_objects.is_empty()
            || public_model_preparation.is_some()
            || public_model_history.is_some()
            || recorded_ingress.is_some()
            || *condition_preservation
            || !producer_observations.is_empty()
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut counter = RetainedRuntimeCounter::new(maximum);
        counter.owned(descriptor)?;
        counter.owned(binding)?;
        counter.owned(route)?;
        if counter.rc(initial)? {
            counter.owned(initial.as_ref())?;
        }
        counter.slots(facets)?;
        for facet in [
            preservation,
            fault_injection,
            condition_debug,
            pause,
            execution,
            terminal,
            terminal_inventory,
        ] {
            counter.owned(&facet.0)?;
        }
        counter.owned(world_hash)?;
        if let Some((activation, attestation)) = readiness {
            counter.owned(activation)?;
            counter.owned(attestation)?;
        }
        counter.map(completed)?;
        for (operation, value) in completed {
            let Completed {
                original,
                outcome,
                capture,
                acknowledged: _,
                evidence,
            } = value;
            counter.owned(operation)?;
            let facts = original.retained_requested_storage_data(maximum)?;
            counter.views(
                facts.independent_bytes(),
                facts
                    .shared_allocations()
                    .map(|entry| (entry.identity(), entry.requested_bytes())),
            )?;
            counter.owned(outcome)?;
            if let Some(capture) = capture {
                if counter.rc(capture)? {
                    counter.owned(capture.as_ref())?;
                }
            }
            counter.owned(evidence)?;
        }
        counter.map(failed)?;
        for (operation, (admission, failure)) in failed {
            counter.owned(operation)?;
            let facts = admission.retained_requested_storage_data(maximum)?;
            counter.views(
                facts.independent_bytes(),
                facts
                    .shared_allocations()
                    .map(|entry| (entry.identity(), entry.requested_bytes())),
            )?;
            counter.owned(failure)?;
        }
        counter.map(reclamations)?;
        for (owner, receipt) in reclamations {
            counter.owned(owner)?;
            counter.owned(receipt)?;
        }
        if let Some(authority) = activation_authority {
            counter.rc(authority)?;
        }
        // Empty maps and vectors can retain backing after their last element
        // was removed. Refusing nonempty unsupported fields does not erase it.
        counter.map(condition_objects)?;
        counter.map(condition_operation_objects)?;
        counter.map(input_history)?;
        counter.map(pending_causes)?;
        counter.slots(producer_observations)?;
        if let Some((activation, observation)) = scheduling_observation {
            counter.activation(activation)?;
            counter.owned(observation)?;
        }
        if let Some(prepared) = prepared_continuation {
            prepared.charge_clock_requested_backing(&mut counter)?;
        }
        counter.owned(readiness_inventory)?;
        counter.rc(original_model_session)?;
        if let Some(preparation) = public_preparation {
            let HostPublicPreparation {
                anchor,
                token,
                session,
                session_bytes,
                native_ready,
                native_ready_bytes,
                ready,
                history,
                previous,
            } = preparation;
            counter.rc(anchor)?;
            counter.owned(token)?;
            counter.owned(session)?;
            counter.owned(session_bytes)?;
            counter.owned(native_ready)?;
            counter.owned(native_ready_bytes)?;
            if let Some((activation, attestation, bytes)) = ready {
                counter.owned(activation)?;
                counter.owned(attestation)?;
                counter.owned(bytes)?;
            }
            counter.owned(history)?;
            counter.owned(previous)?;
        }
        self.original_clock_storage_origin()?;
        Ok(counter.bytes())
    }
}

#[cfg(test)]
#[path = "host_requested_storage_tests.rs"]
mod tests;
