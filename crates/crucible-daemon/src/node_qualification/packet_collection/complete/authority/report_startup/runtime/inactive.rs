//! Transfers the same four original nodes and reserved slot into an inactive runtime.

use super::*;
use crucible::{
    node_adapters::cnp::{CnpSemanticConformanceWorldProvider, CnpSemanticExactWorldReservation},
    node_contract::{NodeRuntime, SimulationNode},
};
use std::panic::{AssertUnwindSafe, catch_unwind};

pub(super) fn quote(
    held: &PacketCompleteReportStartupHolder,
    maximum: usize,
) -> Result<(usize, usize, usize), RuntimeError> {
    let owners = held
        .runtime_owners
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    let graph = owners
        .graph
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let scene = held
        .original_scene
        .get()
        .ok_or(RuntimeError::OwnerUnavailable)?
        .try_borrow()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    let [a, b, c] = owners
        .nodes
        .each_ref()
        .map(|n| n.as_ref().ok_or(RuntimeError::OwnerUnavailable));
    let (a, b, c) = (a?, b?, c?);
    let host = owners.host.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
    let data = NodeRuntime::original_fixed_four_construction_storage_data(
        graph,
        [
            a.original_conformance_route_data(),
            b.original_conformance_route_data(),
            c.original_conformance_route_data(),
            host.route(),
        ],
        [
            a.original_conformance_facets_data(&held.authority.roster.sources[0])?,
            b.original_conformance_facets_data(&held.authority.roster.sources[1])?,
            c.original_conformance_facets_data(&held.authority.roster.sources[2])?,
            host.facets(),
        ],
        &scene.inputs.activation,
        scene.inputs.runtime_limits,
        maximum,
    )?;
    let provider = CnpSemanticExactConformanceWorldProvider::original_construction_storage_data(
        graph,
        &scene.inputs.activation,
        maximum,
    )?;
    Ok((
        add(data.retained_requested_bytes, provider.0, maximum)?,
        add(
            data.maximum_simultaneous_transient_bytes,
            provider.1,
            maximum,
        )?,
        add(data.declared_counter_scratch_bytes, provider.2, maximum)?,
    ))
}

pub(super) fn construct(held: &PacketCompleteReportStartupHolder) -> Result<(), RuntimeError> {
    let mut owners = held
        .runtime_owners
        .try_borrow_mut()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    let mut scene = held
        .original_scene
        .get()
        .ok_or(RuntimeError::OwnerUnavailable)?
        .try_borrow_mut()
        .map_err(|_| RuntimeError::OwnerBusy)?;
    owners
        .node_vector
        .try_reserve_exact(3)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    owners
        .native
        .try_reserve_exact(4)
        .map_err(|_| RuntimeError::ResourceLimit)?;
    if owners.node_vector.capacity() != 3 || owners.native.capacity() != 4 {
        return Err(RuntimeError::ResourceLimit);
    }

    // Validate every fixed source slot before removing the first original.
    if owners.nodes.iter().any(Option::is_none)
        || owners.host.is_none()
        || owners.graph.is_none()
        || scene.runtime_slot.is_none()
        || owners.provider.is_some()
        || owners.actor.is_none()
    {
        return Err(RuntimeError::OutstandingObligations);
    }
    for i in 0..3 {
        let node = owners.nodes[i]
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        owners.node_vector.push(node);
    }
    // No fallible callback occurs between taking the remaining originals and
    // placing the entire request in the provider's failure-retaining constructor.
    let request = CnpSemanticExactWorldReservation {
        nodes: std::mem::take(&mut owners.node_vector),
        native: std::mem::take(&mut owners.native),
        host: owners.host.take().ok_or(RuntimeError::OwnerUnavailable)?,
        source: Rc::clone(&held.authority.host_source()),
        activation: scene.inputs.activation.clone(),
        graph: owners.graph.take().ok_or(RuntimeError::OwnerUnavailable)?,
        runtime_custody: scene
            .runtime_slot
            .take()
            .ok_or(RuntimeError::OwnerUnavailable)?,
    };
    match CnpSemanticConformanceWorldProvider::reserve_exact_inputs(request) {
        Ok(provider) => owners.provider = Some(provider),
        Err(failure) => {
            owners.provider_failure = Some(failure);
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    let limits = scene.inputs.runtime_limits;
    drop(scene);
    let provider = owners
        .provider
        .as_mut()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let result = catch_unwind(AssertUnwindSafe(|| {
        provider.prepare_conformance_exact_inputs(limits, Rc::clone(held.authority.host_source()))
    }));
    match result {
        Ok(Ok(runtime)) => owners.runtime = Some(runtime),
        Ok(Err(failure)) => {
            owners.preparation_failure = Some(failure);
            return Err(RuntimeError::InvalidReceipt);
        }
        Err(original) => {
            owners.unwinds[2] = Some(original);
            return Err(RuntimeError::OwnerUnavailable);
        }
    }
    let runtime = owners
        .runtime
        .take()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    match owners
        .actor
        .as_mut()
        .ok_or(RuntimeError::OwnerUnavailable)?
        .attach(runtime)
    {
        Ok(()) => Ok(()),
        Err(failure) => {
            owners.attachment_failure = Some(failure);
            Err(RuntimeError::InvalidReceipt)
        }
    }
}
