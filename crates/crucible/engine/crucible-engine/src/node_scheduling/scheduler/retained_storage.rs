//! Observes actual scheduler queues, lifetime IDs and payload banks in place.
//!
//! No SchedulingSnapshot is constructed. Ordered maps retain their actual
//! independent key/value heap capacities and supported requested node bounds,
//! including empty-root storage after removals. The parent owns root inline.

use super::*;
use crate::node_contract::{RuntimeError, runtime_owned_counter::RetainedRuntimeCounter};

impl CausalScheduler {
    pub(crate) fn charge_original_retained_storage(
        &self,
        counter: &mut RetainedRuntimeCounter,
    ) -> Result<(), RuntimeError> {
        let Self {
            activation,
            node_owners,
            node_routes,
            input_batches,
            used_input_batches,
            owners,
            bounds,
            pending,
            operations,
            used_operations,
            sequences,
            routing,
            output_endpoints,
            external_roots,
            external_closed_prefixes,
            closed_prefixes,
            native_sequences,
            payloads,
            maximum_pending_payload_bytes: _,
            maximum_microsteps: _,
            restored_epochs,
        } = self;
        counter.owned(restored_epochs)?;
        counter.activation(activation)?;
        counter.map(node_owners)?;
        for (node, owner) in node_owners {
            counter.owned(node)?;
            counter.owned(owner)?;
        }
        counter.map(node_routes)?;
        for (node, route) in node_routes {
            counter.owned(node)?;
            counter.owned(route)?;
        }
        counter.map(input_batches)?;
        for (key, value) in input_batches {
            let InputBatchState {
                batch,
                acknowledgement,
                consumer_committed: _,
                activated_by,
                consumed,
            } = value;
            counter.owned(key)?;
            let facts = batch.retained_requested_storage_data(counter.maximum())?;
            counter.views(
                facts.independent_bytes(),
                facts
                    .shared_allocations()
                    .map(|row| (row.identity(), row.requested_bytes())),
            )?;
            counter.owned(acknowledgement)?;
            counter.owned(activated_by)?;
            counter.owned(consumed)?;
        }
        counter.set(used_input_batches)?;
        for identity in used_input_batches {
            counter.owned(identity)?;
        }
        counter.map(owners)?;
        for (key, value) in owners {
            let OwnerSchedule {
                grid: _,
                policy,
                cursor: _,
                inputs,
                reserved,
            } = value;
            counter.owned(key)?;
            counter.owned(policy)?;
            counter.slots(inputs)?;
            for input in inputs {
                let InputPath {
                    producer,
                    latency_ps: _,
                    external: _,
                    external_endpoint,
                } = input;
                counter.owned(producer)?;
                counter.owned(external_endpoint)?;
            }
            counter.owned(reserved)?;
        }
        counter.map(bounds)?;
        for owner in bounds.keys() {
            counter.owned(owner)?;
        }
        counter.map(pending)?;
        for (key, delivery) in pending {
            let crucible_node_format::EventKey {
                position: _,
                consumer_node_id,
                producer_node_id,
                source_sequence: _,
            } = key;
            counter.owned(consumer_node_id)?;
            counter.owned(producer_node_id)?;
            counter.owned(delivery)?;
        }
        counter.map(operations)?;
        for (key, reservation) in operations {
            let Reservation {
                node,
                owner,
                request,
                input_batch,
            } = reservation;
            counter.owned(key)?;
            counter.owned(node)?;
            counter.owned(owner)?;
            counter.owned(request)?;
            counter.owned(input_batch)?;
        }
        counter.set(used_operations)?;
        for identity in used_operations {
            counter.owned(identity)?;
        }
        sequences.charge_original_retained_storage(counter)?;
        counter.map(routing)?;
        for (key, value) in routing {
            counter.owned(key)?;
            let RoutingConnection { descriptor, policy } = value;
            counter.connection(descriptor)?;
            counter.connection_policy(policy)?;
        }
        counter.map(output_endpoints)?;
        for endpoint in output_endpoints.keys() {
            counter.owned(endpoint)?;
        }
        counter.map(external_roots)?;
        for (endpoint, policy) in external_roots {
            let ExternalRootPolicy {
                maximum_payload_bytes: _,
                maximum_pending_bytes: _,
                grid: _,
            } = policy;
            counter.owned(endpoint)?;
        }
        counter.map(external_closed_prefixes)?;
        for endpoint in external_closed_prefixes.keys() {
            counter.owned(endpoint)?;
        }
        counter.map(closed_prefixes)?;
        for owner in closed_prefixes.keys() {
            counter.owned(owner)?;
        }
        counter.map(native_sequences)?;
        for endpoint in native_sequences.keys() {
            counter.owned(endpoint)?;
        }
        counter.map(payloads)?;
        for (reference, body) in payloads {
            counter.owned(reference)?;
            counter.owned(body)?;
        }
        Ok(())
    }
}
