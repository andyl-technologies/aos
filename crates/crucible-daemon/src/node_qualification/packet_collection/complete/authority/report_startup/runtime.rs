//! Retains each same-owner inactive runtime construction phase before callbacks.
//!
//! Core alone issues the resource members. Original reader, supervisor, native
//! slot and preparations move through fixed holder slots; no ordinary Accepted
//! source, controller extractor, fresh queue reservation or replay is introduced.

mod shared_owner;
pub(super) use shared_owner::OriginalSharedOwner;
pub use shared_owner::PacketCompleteOriginalSceneSupervisor;
mod inputs;
mod graph;
mod inactive;
mod storage;
mod action;

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
