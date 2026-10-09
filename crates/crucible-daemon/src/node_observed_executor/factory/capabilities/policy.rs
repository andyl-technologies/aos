//! Source-owned operation interpretation for regenerated native profiles.

use super::super::{InstalledNodeKind, InstalledNodeSelection, NodeObservedError, refused};
use crate::node_scenario::NodeScenario;
use crucible::node_admission::{CapabilityRequirements, NodeCapabilityRequirement};
use crucible_node_contract::{CapabilityProfile, GuaranteeProfile, canonical};
use serde::de::DeserializeOwned;

pub(in crate::node_observed_executor::factory) fn matches(
    selections: &[InstalledNodeSelection],
    scenario: &NodeScenario,
    requirements: &CapabilityRequirements,
) -> Result<(), NodeObservedError> {
    requirements
        .validate()
        .map_err(|error| refused(&error.to_string()))?;
    if requirements.nodes.len() != scenario.compatibility.len() {
        return Err(refused(
            "mandatory requirements must cover the complete candidate node roster",
        ));
    }
    for demand in &requirements.nodes {
        let binding = scenario
            .compatibility
            .iter()
            .find(|binding| binding.node_id == demand.node)
            .ok_or_else(|| refused("capability demand names a foreign node"))?;
        let descriptor = scenario
            .descriptors
            .iter()
            .find(|node| node.id == demand.node)
            .ok_or_else(|| refused("candidate omitted actual demanded descriptor"))?;
        let selected = selections
            .iter()
            .find(|node| node.node == demand.node)
            .ok_or_else(|| refused("candidate omitted source-owned implementation selection"))?;
        let capabilities: CapabilityProfile = object(scenario, &binding.capabilities_ref)?;
        let guarantees: GuaranteeProfile = object(scenario, &binding.guarantees_ref)?;
        demand
            .match_contract(descriptor, binding, &capabilities, &guarantees)
            .map_err(|error| refused(&error.to_string()))?;
        qualify_kind(&selected.kind, demand, standalone_clock(selections))?;
    }
    Ok(())
}

pub(super) fn qualify_kind(
    kind: &InstalledNodeKind,
    demand: &NodeCapabilityRequirement,
    clock_preservation: bool,
) -> Result<(), NodeObservedError> {
    // Each table belongs to the actual adapters used by this catalog. A new
    // operation needs a source policy and native witness, not an advertised ID.
    if demand.compute.is_some() || !demand.extensions.is_empty() {
        return Err(refused(
            "no enrolled architecture or semantic extension policy for this catalog candidate",
        ));
    }
    // The native codecs remain unchanged, but the current installed archive
    // factories remain legacy except the source-qualified standalone Clock
    // factory. Its complete-world scope excludes ingress and other owners.
    if demand.guarantees.isolated_fork
        || demand.guarantees.conditional_replay
        || (demand.guarantees.durable_restart && !clock_preservation)
    {
        return Err(refused(
            "no enrolled capability-bearing preservation or replay factory",
        ));
    }
    for operation in &demand.operations {
        let supported = match kind {
            InstalledNodeKind::HostClock => match operation.operation.as_str() {
                "exact_run" | "boundary_settle" => operation.facet.id.as_str() == "host/exact-v1",
                "physical_pause" => operation.facet.id.as_str() == "host/physical-pause-v1",
                "capture" | "durable_restart" => {
                    clock_preservation && operation.facet.id.as_str() == "host/preservation-v1"
                }
                _ => false,
            },
            InstalledNodeKind::ReferenceDevice { .. }
            | InstalledNodeKind::ReferenceNativeLinked { .. } => {
                matches!(
                    operation.operation.as_str(),
                    "quantum_begin" | "quantum_close"
                ) && operation.facet.id.as_str() == "reference-device/quantized-v1"
            }
            _ => false,
        };
        if !supported || operation.facet.version != 1 {
            return Err(refused(
                "required operation has no installed semantic implementation in this complete candidate",
            ));
        }
    }
    Ok(())
}

pub(super) fn standalone_clock(selections: &[InstalledNodeSelection]) -> bool {
    matches!(selections, [selection] if matches!(selection.kind, InstalledNodeKind::HostClock))
}

pub(super) fn object<T: DeserializeOwned + crucible_node_contract::Validate>(
    scenario: &NodeScenario,
    reference: &crucible_node_contract::ContentRef,
) -> Result<T, NodeObservedError> {
    let object = scenario
        .content
        .iter()
        .find(|object| object.reference == *reference)
        .ok_or_else(|| refused("complete installed candidate omitted capability policy bytes"))?;
    if canonical::content_ref(&object.bytes, &reference.media_type)? != *reference {
        return Err(refused(
            "candidate policy bytes differ from full immutable reference",
        ));
    }
    Ok(canonical::decode(&object.bytes, 4 * 1024 * 1024)?)
}
