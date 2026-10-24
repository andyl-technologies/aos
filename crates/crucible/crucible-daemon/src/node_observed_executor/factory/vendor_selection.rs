//! Dispatches portable vendor names through a trusted complete-world installation.
//!
//! The retained definition is data, not qualification. Registry source, normal
//! accepted classes, native preparation and common activation remain distinct
//! gates. A singleton installation cannot authorize another mixed topology.

use crucible_campaign::ExecutionId;
use crucible_engine::node_contract::{
    ActivationRecord, ProviderPlanningRequest, ProviderRegistryLimits, RuntimeLimits,
};
use crucible_node_format::{Id, ResourceLimits};

use super::{
    InstalledNodeCatalog, InstalledNodeKind, InstalledNodeSelection, InstalledPreparedWorld,
    NodeObservedError, refused,
};
use crate::node_scenario::NodeScenario;

#[cfg(test)]
#[path = "vendor_selection_tests.rs"]
mod tests;

pub(super) struct InstalledVendorWorld {
    pub(super) execution: ExecutionId,
    pub(super) selection: InstalledNodeSelection,
    pub(super) scenario: NodeScenario,
    pub(super) activation: ActivationRecord,
    pub(super) resources: ResourceLimits,
    pub(super) runtime_limits: RuntimeLimits,
    pub(super) cleanup: super::reference_public::ReferenceVendorCleanup,
}

pub(super) fn is_selected(selections: &[InstalledNodeSelection]) -> bool {
    selections
        .iter()
        .any(|selection| matches!(selection.kind, InstalledNodeKind::InstalledVendor { .. }))
}

fn selected<'a>(
    catalog: &'a InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
) -> Result<&'a InstalledVendorWorld, NodeObservedError> {
    let [selection] = selections else {
        return Err(refused(
            "installed reference vendor requires its complete singleton world",
        ));
    };
    let InstalledNodeKind::InstalledVendor {
        provider,
        profile,
        configuration,
    } = &selection.kind
    else {
        return Err(refused("foreign installed vendor selector"));
    };
    let original = catalog
        .vendor_worlds
        .get(provider)
        .ok_or_else(|| refused("vendor world is not installed"))?;
    let InstalledNodeKind::InstalledVendor {
        provider: expected_provider,
        profile: expected_profile,
        configuration: expected_configuration,
    } = &original.selection.kind
    else {
        return Err(refused("installed vendor definition is inconsistent"));
    };
    if provider != expected_provider
        || profile != expected_profile
        || configuration != expected_configuration
        || selection.node != original.selection.node
        || selection.owner != original.selection.owner
    {
        return Err(refused(
            "portable vendor selector differs from trusted installation",
        ));
    }
    Ok(original)
}

pub(super) fn scenario(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
) -> Result<NodeScenario, NodeObservedError> {
    let original = selected(catalog, selections)?;
    // The original complete canonical body was bounded at installation.
    drop(original.scenario.canonical_bytes()?);
    Ok(original.scenario.clone())
}

pub(super) fn prepare(
    catalog: &mut InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    scenario: NodeScenario,
    execution: ExecutionId,
) -> Result<InstalledPreparedWorld, NodeObservedError> {
    let original = selected(catalog, selections)?;
    if execution != original.execution
        || scenario.canonical_bytes()? != original.scenario.canonical_bytes()?
    {
        return Err(refused(
            "vendor execution or complete authored scenario differs",
        ));
    }
    let InstalledNodeKind::InstalledVendor {
        provider,
        profile,
        configuration,
    } = &original.selection.kind
    else {
        return Err(refused("installed vendor selector is inconsistent"));
    };
    let provider = provider.clone();
    let profile = profile.clone();
    let configuration = configuration.clone();
    let nodes: [Id; 1] = [original.selection.node.clone()];
    let resources = original.resources.clone();
    let activation = original.activation.clone();
    let limits = original.runtime_limits;
    catalog.prepare_vendor_world(
        &provider,
        ProviderPlanningRequest {
            profile: &profile,
            configuration: &configuration,
            nodes: &nodes,
            resources: &resources,
            limits: ProviderRegistryLimits::default(),
        },
        scenario,
        &activation,
        limits,
    )
}

pub(super) fn publisher(
    catalog: &InstalledNodeCatalog,
    selections: &[InstalledNodeSelection],
    stored: crate::node_observed_executor::StoredWorldActivationPublisher,
) -> Result<Box<dyn crucible_engine::node_contract::ActivationPublisher>, NodeObservedError> {
    Ok(selected(catalog, selections)?.cleanup.publisher(stored))
}

impl InstalledNodeCatalog {
    pub(crate) fn poll_vendor_reclamation(&self) -> Result<(), NodeObservedError> {
        for original in self.vendor_worlds.values() {
            original.cleanup.poll().map_err(super::native)?;
        }
        Ok(())
    }

    pub(crate) fn retained_vendor_peers(&self) -> usize {
        self.vendor_worlds
            .values()
            .map(|world| world.cleanup.retained())
            .sum()
    }
}
