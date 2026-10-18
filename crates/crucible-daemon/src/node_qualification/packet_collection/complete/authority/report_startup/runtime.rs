//! Retains each same-owner inactive runtime construction phase before callbacks.
//!
//! Core alone issues the resource members. Original reader, supervisor, native
//! slot and preparations move through fixed holder slots; no ordinary Accepted
//! source, controller extractor, fresh queue reservation or replay is introduced.

mod shared_owner;
pub(super) use shared_owner::OriginalSharedOwner;
pub use shared_owner::PacketCompleteOriginalSceneSupervisor;
mod action;
mod family;
mod fresh;
pub(super) use fresh::FreshRuntimeOwners;
pub(super) use fresh::counter_scratch_data as fresh_counter_scratch_data;
mod content_limits;
mod graph;
mod inactive;
mod inputs;
mod lifecycle;
mod storage;
pub(super) use lifecycle::counter_scratch_data as lifecycle_counter_scratch_data;

use super::*;
use crate::node_qualification::packet_collection::{
    PacketWorldHostSupervisor,
    complete::{
        PacketCompleteCaptureFactory, PacketCompleteExecutionActor, PacketCompleteExecutionScene,
        PacketCompleteNativeOracle, PacketCompleteRuntimeAttachmentFailure,
    },
    connected::PacketConnectedSchedule,
};
use crucible::{
    node_adapters::cnp::{
        CnpSemanticConformanceNode, CnpSemanticExactConformanceWorldProvider,
        CnpSemanticExactWorldReservationFailure, CnpSemanticWorldPreparationFailure,
        PacketCompleteOriginalHostSdk,
    },
    node_admission::{
        CompleteOriginalRuntimeConstructionMember, ConformanceGraph,
        OriginalRuntimeConstructionPhase, OriginalRuntimeConstructionPolicy,
        OriginalRuntimeConstructionScope, OriginalRuntimeConstructionStorage,
    },
    node_contract::{ConformanceRuntime, PreparedHostSchedulingNode, RuntimeError},
};
use crucible_node_contract::{NodeBinding, NodeDescriptor, OwnerBinding};
use crucible_node_provider::reference_packet::service::PacketConnectedSourceProgram;

pub(super) struct OriginalRuntimeOwners {
    programmes: [Option<PacketConnectedSourceProgram>; 3],
    paths: [Option<std::path::PathBuf>; 3],
    schedule: Option<PacketConnectedSchedule>,
    capture_bootstrap: Option<super::super::super::execution::schedule::Bootstrap>,
    requirements: Option<crucible::node_admission::ScenarioRequirements>,
    oracle: Option<Rc<PacketCompleteNativeOracle>>,
    scene: Option<Rc<PacketCompleteExecutionScene>>,
    factory: Option<Rc<PacketCompleteCaptureFactory>>,
    actor: Option<Box<PacketCompleteExecutionActor>>,
    graph: Option<ConformanceGraph>,
    descriptors: Vec<NodeDescriptor>,
    bindings: Vec<NodeBinding>,
    owners: Vec<OwnerBinding>,
    nodes: [Option<CnpSemanticConformanceNode>; 3],
    host: Option<PreparedHostSchedulingNode>,
    node_vector: Vec<CnpSemanticConformanceNode>,
    native: Vec<Box<dyn crucible::node_contract::SimulationNode>>,
    provider: Option<CnpSemanticExactConformanceWorldProvider>,
    provider_failure: Option<CnpSemanticExactWorldReservationFailure>,
    preparation_failure: Option<CnpSemanticWorldPreparationFailure>,
    runtime: Option<ConformanceRuntime>,
    attachment_failure: Option<PacketCompleteRuntimeAttachmentFailure>,
    node_failures: [Option<crucible::node_contract::OperationFailure>; 3],
    unwinds: [Option<Box<dyn std::any::Any + Send>>; 3],
    complete: bool,
}

impl OriginalRuntimeOwners {
    pub(super) fn new() -> Self {
        Self {
            programmes: std::array::from_fn(|_| None),
            paths: std::array::from_fn(|_| None),
            schedule: None,
            capture_bootstrap: None,
            requirements: None,
            oracle: None,
            scene: None,
            factory: None,
            actor: None,
            graph: None,
            descriptors: Vec::new(),
            bindings: Vec::new(),
            owners: Vec::new(),
            nodes: std::array::from_fn(|_| None),
            host: None,
            node_vector: Vec::new(),
            native: Vec::new(),
            provider: None,
            provider_failure: None,
            preparation_failure: None,
            runtime: None,
            attachment_failure: None,
            node_failures: std::array::from_fn(|_| None),
            unwinds: std::array::from_fn(|_| None),
            complete: false,
        }
    }
}

fn index(phase: OriginalRuntimeConstructionPhase) -> usize {
    match phase {
        OriginalRuntimeConstructionPhase::InputOwners => 0,
        OriginalRuntimeConstructionPhase::CollectingGraph => 1,
        OriginalRuntimeConstructionPhase::InactiveRuntime => 2,
    }
}

fn storage_error(_: QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}

fn add(a: usize, b: usize, max: usize) -> Result<usize, RuntimeError> {
    a.checked_add(b)
        .filter(|n| *n <= max)
        .ok_or(RuntimeError::ResourceLimit)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
impl PacketCompleteReportStartupHolder {
    /// Reports retained construction failures before the native control retires them.
    ///
    /// Closed data inspectors observe the existing owners before retirement
    /// revokes their witnesses. No constructor, transport request or owner
    /// transfer occurs. A busy diagnostic loan preserves the original failure.
    pub(in crate::node_qualification::packet_collection::complete) fn report_original_runtime_failure_for_test(
        original: &Rc<RefCell<Self>>,
    ) {
        let Ok(held) = original.try_borrow() else {
            eprintln!("retained runtime failure: holder borrowed");
            return;
        };
        let Ok(owners) = held.runtime_owners.try_borrow() else {
            eprintln!("retained runtime failure: construction owners borrowed");
            return;
        };

        eprintln!(
            "retained runtime construction: attempted={:?} members={:?} graph={} nodes={:?} host={} provider_failure={} preparation_failure={} attachment_failure={}",
            held.runtime_attempted.each_ref().map(Cell::get),
            held.runtime_members
                .each_ref()
                .map(|member| member.get().is_some()),
            owners.graph.is_some(),
            owners.nodes.each_ref().map(Option::is_some),
            owners.host.is_some(),
            owners.provider_failure.is_some(),
            owners.preparation_failure.is_some(),
            owners.attachment_failure.is_some(),
        );
        for (index, failure) in owners.node_failures.iter().enumerate() {
            if let Some(failure) = failure {
                eprintln!(
                    "retained node failure: index={index} effects={:?} reason={}",
                    failure.effects, failure.reason,
                );
            }
            if owners.unwinds[index].is_some() {
                eprintln!("retained node failure: index={index} unwind retained");
            }
        }

        if let Some(host) = &owners.host {
            let storage =
                crucible::node_contract::SimulationNode::retained_requested_storage_precredit_data(
                    host,
                    usize::MAX,
                );
            eprintln!("retained host diagnostic: storage={storage:?}");
        }

        let Ok(preparations) = held.preparations.try_borrow() else {
            eprintln!("retained runtime failure: preparation owners borrowed");
            return;
        };
        for (index, node) in owners.nodes.iter().enumerate() {
            let Some(node) = node else {
                continue;
            };
            let source = &held.authority.roster.sources[index];
            let identity = preparations
                .original_initial_query_attempted_for_test(index)
                .and_then(|queried| {
                    if queried {
                        let ticket = preparations.original_initial_ticket_data(index)?;
                        node.inspect_original_initial_preparation_data(&ticket, source, &held.plan)
                    } else {
                        preparations.authenticate_original_admitted_peer_data(index)?;
                        node.inspect_original_admitted_preparation_data(source, &held.plan)
                    }
                });
            eprintln!("retained node diagnostic: index={index} identity={identity:?}");

            if let Some(scratch) = preparations.original_initial_scratch_for_test() {
                let storage = node.retained_original_initial_requested_storage_precredit_data(
                    source,
                    scratch,
                    usize::MAX,
                );
                eprintln!("retained node diagnostic: index={index} storage={storage:?}");
            }
        }
    }

    /// Checks that the real initial constructor retained an attached inactive actor.
    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_original_inactive_actor_for_test(
        original: &Rc<RefCell<Self>>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if !held.runtime_attempted.iter().all(Cell::get)
            || held
                .runtime_members
                .iter()
                .any(|member| member.get().is_none())
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let mut owners = held
            .runtime_owners
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if !owners.complete {
            return Err(RuntimeError::OutstandingObligations);
        }
        owners
            .actor
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .authenticate_original_inactive_for_test()
            .map_err(|_| RuntimeError::OutstandingObligations)
    }
}

mod initial_preparation;
pub(super) use initial_preparation::counter_scratch_data as initial_preparation_counter_scratch_data;
