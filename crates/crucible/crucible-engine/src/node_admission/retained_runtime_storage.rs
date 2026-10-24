//! Observes the actual admitted graph retained by an original collecting runtime.
//!
//! Referenced content is a separate owning bank. This visitor counts actual
//! graph clones and typed policies without reparsing or serializing them.

use super::*;
use crate::node_contract::{RuntimeError, runtime_owned_counter::RetainedRuntimeCounter};

impl AdmittedGraph {
    /// Observes complete actual graph backing without serializing its policies.
    ///
    /// The enclosing inline slot is separate; referenced content banks are
    /// independent owners. This data walk grants no admission or execution.
    ///
    /// # Errors
    /// Refuses unsupported fields, checked overflow or the requested bound.
    pub fn original_retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let mut counter = RetainedRuntimeCounter::new(maximum);
        self.charge_original_retained_storage(&mut counter)?;
        Ok(counter.bytes())
    }

    /// Names the actual fixed graph counter, excluding compiler recursion frames.
    pub fn original_retained_requested_storage_precredit_scratch_data() -> usize {
        std::mem::size_of::<RetainedRuntimeCounter>()
    }

    pub(crate) fn charge_original_retained_storage(
        &self,
        counter: &mut RetainedRuntimeCounter,
    ) -> Result<(), RuntimeError> {
        let Self {
            collecting: _,
            world,
            world_hash,
            descriptors,
            bindings,
            owners,
            guarantees,
            effective_repeatability,
            world_repeatability: _,
            ownership,
            coordinator,
            port_policies,
            connection_policies,
            operating_policies,
            requirements,
            owner_conflicts,
            selected_extensions,
            capability_requirements,
        } = self;
        if let Some(selection) = capability_requirements {
            counter.owned(&selection.selection)?;
            counter.owned(&selection.requirements)?;
            counter.map(&selection.objects)?;
            for (reference, bytes) in &selection.objects {
                counter.owned(reference)?;
                counter.owned(bytes)?;
            }
        }
        counter.world(world)?;
        counter.owned(world_hash)?;
        counter.map(descriptors)?;
        for (key, value) in descriptors {
            counter.owned(key)?;
            counter.owned(value)?;
        }
        counter.map(bindings)?;
        for (key, value) in bindings {
            counter.owned(key)?;
            counter.owned(value)?;
        }
        counter.map(owners)?;
        for (key, value) in owners {
            counter.owned(key)?;
            counter.owned(value)?;
        }
        counter.map(guarantees)?;
        for (key, value) in guarantees {
            counter.owned(key)?;
            counter.owned(value)?;
        }
        counter.map(effective_repeatability)?;
        for key in effective_repeatability.keys() {
            counter.owned(key)?;
        }
        charge_ownership(ownership, counter)?;
        charge_coordinator(coordinator, counter)?;
        counter.map(port_policies)?;
        for ((node, port), value) in port_policies {
            counter.owned(node)?;
            counter.owned(port)?;
            charge_port(value, counter)?;
        }
        counter.map(connection_policies)?;
        for (key, value) in connection_policies {
            counter.owned(key)?;
            counter.connection_policy(value)?;
        }
        counter.map(operating_policies)?;
        for (key, value) in operating_policies {
            counter.owned(key)?;
            counter.owned(value)?;
        }
        charge_requirements(requirements, counter)?;
        counter.map(owner_conflicts)?;
        for (key, values) in owner_conflicts {
            counter.owned(key)?;
            counter.set(values)?;
            for value in values {
                counter.owned(value)?;
            }
        }
        selected_extensions.charge_original_retained_storage(counter)
    }
}

fn charge_ownership(
    value: &OwnershipPolicy,
    counter: &mut RetainedRuntimeCounter,
) -> Result<(), RuntimeError> {
    let OwnershipPolicy {
        schema_version: _,
        domains,
        objects,
        internal_dependencies,
        capture_owners,
        inventory_proof_ref,
    } = value;
    counter.slots(domains)?;
    for domain in domains {
        let StateDomain {
            id,
            capture_owner_id,
            execution_owner_ids,
            future_affecting: _,
        } = domain;
        counter.owned(id)?;
        counter.owned(capture_owner_id)?;
        counter.owned(execution_owner_ids)?;
    }
    counter.slots(objects)?;
    for object in objects {
        let StateObject {
            id,
            node_ids,
            future_affecting: _,
            state,
        } = object;
        counter.owned(id)?;
        counter.owned(node_ids)?;
        match state {
            ObjectState::Mutable { domain_id } => counter.owned(domain_id)?,
            ObjectState::Immutable { content_ref } => counter.owned(content_ref)?,
            ObjectState::OutsideScope => {}
        }
    }
    counter.slots(internal_dependencies)?;
    for dependency in internal_dependencies {
        let InternalDependency {
            id,
            producer_node_id,
            consumer_node_id,
            minimum_latency_ps: _,
            proof_ref,
        } = dependency;
        counter.owned(id)?;
        counter.owned(producer_node_id)?;
        counter.owned(consumer_node_id)?;
        counter.owned(proof_ref)?;
    }
    counter.slots(capture_owners)?;
    for owner in capture_owners {
        let OwnerCapturePolicy {
            owner_id,
            complete_model: _,
            unchanged_cut: _,
            exact_continuation: _,
            durable_restart: _,
            isolated_fork: _,
            dependencies,
            cut_procedure_ref,
        } = owner;
        counter.owned(owner_id)?;
        counter.owned(dependencies)?;
        counter.owned(cut_procedure_ref)?;
    }
    counter.owned(inventory_proof_ref)
}

fn charge_coordinator(
    value: &CoordinatorPolicy,
    counter: &mut RetainedRuntimeCounter,
) -> Result<(), RuntimeError> {
    let CoordinatorPolicy {
        schema_version: _,
        state_closure_ref,
        maximum_microsteps_per_instant: _,
        same_time_closure,
        operational_policy_ref,
        external_inputs,
    } = value;
    counter.owned(state_closure_ref)?;
    counter.slots(same_time_closure)?;
    for closure in same_time_closure {
        let SameTimeClosure {
            execution_owner_id,
            proof_ref,
        } = closure;
        counter.owned(execution_owner_id)?;
        counter.owned(proof_ref)?;
    }
    counter.owned(operational_policy_ref)?;
    counter.owned(external_inputs)
}

fn charge_port(
    value: &PortPolicy,
    counter: &mut RetainedRuntimeCounter,
) -> Result<(), RuntimeError> {
    let PortPolicy {
        schema_version: _,
        lanes,
        maximum_producers: _,
        maximum_consumers: _,
        arbitration_ref,
        execution_owner_id,
        state_domain_ids,
        internal: _,
    } = value;
    counter.slots(lanes)?;
    for lane in lanes {
        let LanePolicy {
            lane_id,
            ordering_ref,
            correlation_ref,
            flow_control: _,
            maximum_pending_bytes: _,
            visibility,
            effect_phases,
            minimum_lookahead_ps: _,
        } = lane;
        counter.owned(lane_id)?;
        counter.owned(ordering_ref)?;
        counter.owned(correlation_ref)?;
        match visibility {
            LaneVisibility::Exact => {}
            LaneVisibility::Quantized {
                quantum_ps: _,
                phase_ps: _,
                contract_ref,
            } => counter.owned(contract_ref)?,
        }
        counter.owned(effect_phases)?;
    }
    counter.owned(arbitration_ref)?;
    counter.owned(execution_owner_id)?;
    counter.owned(state_domain_ids)
}

fn charge_requirements(
    value: &ScenarioRequirements,
    counter: &mut RetainedRuntimeCounter,
) -> Result<(), RuntimeError> {
    let ScenarioRequirements {
        deterministic: _,
        exact_capture: _,
        exact_continuation: _,
        durable_restart: _,
        isolated_fork: _,
        accepted_quantized_nodes,
        accepted_nondeterministic_nodes,
        accepted_limited_state_nodes,
        accepted_visibility_conversions,
    } = value;
    counter.owned(accepted_quantized_nodes)?;
    counter.owned(accepted_nondeterministic_nodes)?;
    counter.owned(accepted_limited_state_nodes)?;
    counter.owned(accepted_visibility_conversions)
}
