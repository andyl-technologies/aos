//! Regenerates one source-installed ordinary Clock and gem5 live preparation selection.
//!
//! The selected profile admits exact live work and complete public initial
//! readiness. It explicitly declines capture, durable restart and fork until a
//! preparation-bearing native codec is independently qualified. Portable ISA
//! selection supplies no executable paths, native certificates or owner seals.

use std::rc::Rc;

use crucible_campaign::ExecutionId;
use crucible_node_contract::Id;

use super::super::{
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, InstalledPreparedWorld,
    NodeObservedError, execution_text, measure_executable, refused,
};
use super::{control::InstalledGem5Isa, installed::InstalledMixedEngine, profile::MixedProfile};
use crate::node_scenario::NodeScenario;

pub(super) fn selected_isa(
    selections: &[InstalledNodeSelection],
) -> Result<InstalledGem5Isa, NodeObservedError> {
    let [clock, cpu] = selections else {
        return Err(refused(
            "closed gem5 initial edition requires exactly its Clock and CPU owners",
        ));
    };
    if clock.node.as_str() != "clock"
        || clock.owner.as_str() != "owner/clock"
        || !matches!(clock.kind, InstalledNodeKind::HostClock)
        || cpu.node.as_str() != "cpu"
        || cpu.owner.as_str() != "owner/cpu"
    {
        return Err(refused(
            "closed gem5 selection differs from its source-installed owner roster",
        ));
    }
    match cpu.kind {
        InstalledNodeKind::Gem5Closed { isa } => Ok(isa),
        _ => Err(refused(
            "closed gem5 original native model selection is absent",
        )),
    }
}

pub(in super::super) fn scenario(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
) -> Result<NodeScenario, NodeObservedError> {
    let isa = selected_isa(selections)?;
    if measure_executable(&catalog.host_executable)? != catalog.host_identity {
        return Err(refused(
            "actual catalog host changed before closed gem5 selection",
        ));
    }
    Ok(MixedProfile::build_public(
        super::super::InstalledGem5ClosedProfile::built_in()?,
        &catalog.host_identity,
        isa.name(),
    )?
    .scenario)
}

pub(in super::super) fn prepare(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    authored: NodeScenario,
    execution: ExecutionId,
) -> Result<InstalledPreparedWorld, NodeObservedError> {
    let isa = selected_isa(selections)?;
    let expected = scenario(catalog, selections)?;
    if authored.canonical_bytes()? != expected.canonical_bytes()?
        || measure_executable(&catalog.device_executable)? != catalog.device_identity
    {
        return Err(refused(
            "authored closed gem5 world or installed catalog source differs",
        ));
    }
    let engine =
        InstalledMixedEngine::with_runtime(catalog.socket_parent.clone(), catalog.custody.clone())?;
    let live = engine.prepare_public_initial(
        isa.name(),
        Id::new(format!("activation/{}", execution_text(execution)))?,
    )?;
    if live.profile.scenario.canonical_bytes()? != expected.canonical_bytes()? {
        return Err(refused(
            "native preparation changed its independently regenerated selection",
        ));
    }
    let graph = Rc::try_unwrap(live.graph)
        .map_err(|_| refused("closed gem5 graph retained unexpected preparation aliases"))?;
    Ok(InstalledPreparedWorld {
        scenario: live.profile.scenario.clone(),
        graph,
        realization: live.realization,
    })
}

/// Couples durable publication knowledge to the already reserved native owner.
pub(in super::super) fn publisher(
    stored: crate::node_observed_executor::StoredWorldActivationPublisher,
) -> Result<Box<dyn crucible::node_contract::ActivationPublisher>, NodeObservedError> {
    Ok(Box::new(super::publication::NativeCustodyPublisher {
        stored,
        queue: super::custody::Gem5CustodyQueue::installed(8)
            .map_err(|error| refused(&error.to_string()))?,
    }))
}
