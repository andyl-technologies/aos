//! Regenerates distinct source-installed live and preparation-bearing Clock/gem5 selections.
//!
//! The selected profile admits exact live work and complete public initial
//! readiness. The live-only edition declines capture and continuation. Its
//! preserving sibling explicitly selects both native preparation-bearing codecs;
//! their source history never substitutes for actual fresh native qualification. Portable ISA
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

/// Owns an actual inactive public native world and its installed capture policy.
pub struct InstalledPreparedNativeWorld {
    /// Retains the complete inactive graph and pre-reserved native resources.
    pub world: InstalledPreparedWorld,
    /// Retains the source-installed signer and original native codec policy.
    pub preservation: InstalledNativePreservation,
}

/// Retains installed policy; current native custody remains in the owning runtime.
pub struct InstalledNativePreservation {
    pub(super) factory: Rc<super::factory::MixedNativeFactory>,
    #[cfg(test)]
    pub(super) namespace: std::path::PathBuf,
}

impl InstalledNativePreservation {
    /// Returns immutable source policy without manufacturing native capture seals.
    pub fn factory(&self) -> Rc<dyn crucible::node_state::NativeWorldFactory> {
        self.factory.clone()
    }

    /// Returns exact installed bytes and their explicitly qualified dependencies.
    pub fn immutable(&self) -> Box<dyn crucible::node_state::CaptureEvidence> {
        Box::new(self.factory.immutable())
    }
}

/// Keeps signer policy from the same actual ordinary installed preparation.
pub(in super::super) fn prepare_native(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    authored: NodeScenario,
    execution: ExecutionId,
) -> Result<InstalledPreparedNativeWorld, NodeObservedError> {
    selected_isa(selections)?;
    if !matches!(
        selections[1].kind,
        InstalledNodeKind::Gem5ClosedPreserving { .. }
            | InstalledNodeKind::Gem5ClosedEpochPreserving { .. }
    ) {
        return Err(refused(
            "native preservation requires its distinct installed owner codec",
        ));
    }
    let live = prepare_source(catalog, selections, authored, execution)?;
    let factory = Rc::new(super::factory::MixedNativeFactory::for_live(
        &live,
        super::custody::Gem5CustodyQueue::installed(8)
            .map_err(|error| refused(&error.to_string()))?,
    ));
    let graph = Rc::try_unwrap(live.graph)
        .map_err(|_| refused("installed native graph retained unexpected source aliases"))?;
    Ok(InstalledPreparedNativeWorld {
        world: InstalledPreparedWorld {
            scenario: live.profile.scenario.clone(),
            graph,
            realization: live.realization,
        },
        preservation: InstalledNativePreservation {
            factory,
            #[cfg(test)]
            namespace: live.namespace,
        },
    })
}

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
        InstalledNodeKind::Gem5Closed { isa }
        | InstalledNodeKind::Gem5ClosedPreserving { isa }
        | InstalledNodeKind::Gem5ClosedEpochPreserving { isa } => Ok(isa),
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
    let installed = super::super::InstalledGem5ClosedProfile::built_in()?;
    let preserving = matches!(
        selections[1].kind,
        InstalledNodeKind::Gem5ClosedPreserving { .. }
            | InstalledNodeKind::Gem5ClosedEpochPreserving { .. }
    );
    let profile = if matches!(
        selections[1].kind,
        InstalledNodeKind::Gem5ClosedEpochPreserving { .. }
    ) {
        MixedProfile::build_public_epoch_preserving(installed, &catalog.host_identity, isa.name())?
    } else if preserving {
        MixedProfile::build_public_preserving(installed, &catalog.host_identity, isa.name())?
    } else {
        MixedProfile::build_public(installed, &catalog.host_identity, isa.name())?
    };
    Ok(profile.scenario)
}

pub(in super::super) fn prepare(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    authored: NodeScenario,
    execution: ExecutionId,
) -> Result<InstalledPreparedWorld, NodeObservedError> {
    let live = prepare_source(catalog, selections, authored, execution)?;
    let graph = Rc::try_unwrap(live.graph)
        .map_err(|_| refused("closed gem5 graph retained unexpected preparation aliases"))?;
    Ok(InstalledPreparedWorld {
        scenario: live.profile.scenario.clone(),
        graph,
        realization: live.realization,
    })
}

/// Retains actual inactive owners beneath the regenerated authored capability world.
pub(in super::super) fn prepare_capability(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    resolved: &super::super::ResolvedCapabilityWorld,
    execution: ExecutionId,
) -> Result<
    (
        InstalledPreparedWorld,
        crucible::node_contract::ActivationRecord,
    ),
    NodeObservedError,
> {
    let isa = selected_isa(selections)?;
    let expected = resolved.gem5_scenario(&scenario(catalog, selections)?)?;
    if !matches!(selections[1].kind, InstalledNodeKind::Gem5Closed { .. })
        || measure_executable(&catalog.device_executable)? != catalog.device_identity
    {
        return Err(refused(
            "capability preparation requires the unchanged live closed native selection",
        ));
    }
    let engine =
        InstalledMixedEngine::with_runtime(catalog.socket_parent.clone(), catalog.custody.clone())?;
    let activation = Id::new(format!("activation/{}", execution_text(execution)))?;
    let live = engine.prepare_public_capability(isa.name(), activation, resolved)?;
    if live.profile.scenario.canonical_bytes()? != expected.canonical_bytes()? {
        return Err(refused(
            "actual native capability preparation changed its independently regenerated world",
        ));
    }
    let graph = Rc::try_unwrap(live.graph)
        .map_err(|_| refused("capability native graph retained unexpected preparation aliases"))?;
    Ok((
        InstalledPreparedWorld {
            scenario: live.profile.scenario.clone(),
            graph,
            realization: live.realization,
        },
        live.target,
    ))
}

/// Keeps the source-owned sealed evidence available for native archive custody.
pub(super) fn prepare_source(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    authored: NodeScenario,
    execution: ExecutionId,
) -> Result<super::installed::MixedLiveWorld, NodeObservedError> {
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
    let activation = Id::new(format!("activation/{}", execution_text(execution)))?;
    let live = if matches!(
        selections[1].kind,
        InstalledNodeKind::Gem5ClosedEpochPreserving { .. }
    ) {
        engine.prepare_public_epoch_preserving(isa.name(), activation)?
    } else if matches!(
        selections[1].kind,
        InstalledNodeKind::Gem5ClosedPreserving { .. }
            | InstalledNodeKind::Gem5ClosedEpochPreserving { .. }
    ) {
        engine.prepare_public_preserving(isa.name(), activation)?
    } else {
        engine.prepare_public_initial(isa.name(), activation)?
    };
    if live.profile.scenario.canonical_bytes()? != expected.canonical_bytes()? {
        return Err(refused(
            "native preparation changed its independently regenerated selection",
        ));
    }
    Ok(live)
}

/// Couples durable publication knowledge to the already reserved native owner.
pub(in super::super) fn publisher(
    stored: crate::node_observed_executor::StoredWorldActivationPublisher,
) -> Result<Box<dyn crucible::node_contract::ActivationPublisher>, NodeObservedError> {
    Ok(Box::new(super::publication::NativeCustodyPublisher {
        stored,
        restored: None,
        queue: super::custody::Gem5CustodyQueue::installed(8)
            .map_err(|error| refused(&error.to_string()))?,
    }))
}
