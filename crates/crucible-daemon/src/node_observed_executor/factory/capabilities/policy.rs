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
        qualify_kind(
            &selected.kind,
            demand,
            standalone_clock(selections),
            condition_preservation(selections),
            gem5_ordinary(selections),
        )?;
    }
    Ok(())
}

pub(super) fn qualify_kind(
    kind: &InstalledNodeKind,
    demand: &NodeCapabilityRequirement,
    clock_preservation: bool,
    condition_preservation: bool,
    gem5_ordinary: bool,
) -> Result<(), NodeObservedError> {
    // Each table belongs to the actual adapters used by this catalog. A new
    // operation needs a source policy and native witness, not an advertised ID.
    if demand.compute.is_some() || !demand.extensions.is_empty() {
        return Err(refused(
            "no enrolled architecture or semantic extension policy for this catalog candidate",
        ));
    }
    // Preservation is qualified for a complete source-installed candidate.
    // A condition selection captures only its original ACKed, unresumed Stop;
    // its operations do not imply replay, fork or physical-device capture.
    if demand.guarantees.isolated_fork
        || demand.guarantees.conditional_replay
        || (demand.guarantees.durable_restart && !clock_preservation && !condition_preservation)
    {
        return Err(refused(
            "no enrolled capability-bearing preservation or replay factory",
        ));
    }
    for operation in &demand.operations {
        if gem5_ordinary
            && !matches!(
                operation.operation.as_str(),
                "exact_run" | "boundary_settle"
            )
        {
            return Err(refused(
                "closed mixed capability selection qualifies only ordinary exact execution and boundary settlement",
            ));
        }
        let supported = match kind {
            InstalledNodeKind::HostClock => match operation.operation.as_str() {
                "exact_run" | "boundary_settle" => operation.facet.id.as_str() == "host/exact-v1",
                "physical_pause" => operation.facet.id.as_str() == "host/physical-pause-v1",
                "capture" | "durable_restart" => {
                    clock_preservation && operation.facet.id.as_str() == "host/preservation-v1"
                }
                _ => false,
            },
            InstalledNodeKind::HostIo { .. }
            | InstalledNodeKind::HostScripted { .. }
            | InstalledNodeKind::HostNetLink { .. }
            | InstalledNodeKind::HostSemantics { .. } => {
                // These source-installed models use the same exact operation
                // facade. Full configuration, schema and facet bodies were
                // matched above; richer control and archive policies stay separate.
                match operation.operation.as_str() {
                    "exact_run" | "boundary_settle" => {
                        operation.facet.id.as_str() == "host/exact-v1"
                    }
                    "capture" | "durable_restart" => {
                        condition_preservation
                            && matches!(
                                kind,
                                InstalledNodeKind::HostIo { .. }
                                    | InstalledNodeKind::HostScripted { .. }
                            )
                            && operation.facet.id.as_str() == "host/condition-preservation-v1"
                    }
                    _ => false,
                }
            }
            InstalledNodeKind::HostConditionDebugPreserving { .. } => {
                condition_preservation
                    && match operation.operation.as_str() {
                        "condition_stop" | "condition_resume" => {
                            operation.facet.id.as_str() == "host/condition-debug-v1"
                        }
                        "capture" | "durable_restart" => {
                            operation.facet.id.as_str() == "host/condition-preservation-v1"
                        }
                        "exact_run" | "boundary_settle" => {
                            operation.facet.id.as_str() == "host/exact-v1"
                        }
                        _ => false,
                    }
            }
            InstalledNodeKind::Gem5Closed { .. } => {
                gem5_ordinary
                    && matches!(
                        operation.operation.as_str(),
                        "exact_run" | "boundary_settle"
                    )
                    && operation.facet.id.as_str()
                        == crucible::node_adapters::gem5::GEM5_CLOSED_EXACT_PROFILE
            }
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

// This is the independently qualified operator topology. Larger condition
// rosters and other native models require a separately measured conjunction.
pub(super) fn condition_preservation(selections: &[InstalledNodeSelection]) -> bool {
    if selections.len() != 3 {
        return false;
    }
    let mut observer = 0;
    let mut source_consumer = None;
    let mut block = None;
    for selected in selections {
        match &selected.kind {
            InstalledNodeKind::HostConditionDebugPreserving { .. } => observer += 1,
            InstalledNodeKind::HostScripted { profile } if source_consumer.is_none() => {
                source_consumer = Some(&profile.consumer)
            }
            InstalledNodeKind::HostIo {
                profile: super::super::InstalledHostIoProfile::Block { .. },
            } if block.is_none() => block = Some(&selected.node),
            _ => return false,
        }
    }
    observer == 1 && block.is_some() && source_consumer == block
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

// This live conjunction uses the independently qualified fixed native capsule.
// Preserving and epoch editions retain their separate default refusals here.
pub(super) fn gem5_ordinary(selections: &[InstalledNodeSelection]) -> bool {
    if selections.len() < 2
        || super::super::native_state::host_clocks::validate(&selections[2..]).is_err()
    {
        return false;
    }
    if selections.len() > 2
        && !matches!(
            selections[1].kind,
            InstalledNodeKind::Gem5Closed {
                isa: super::super::InstalledGem5Isa::X86_64
            }
        )
    {
        return false;
    }
    let selected = &selections[..2];
    matches!(selected, [clock, cpu]
        if clock.node.as_str() == "clock"
            && clock.owner.as_str() == "owner/clock"
            && matches!(clock.kind, InstalledNodeKind::HostClock)
            && cpu.node.as_str() == "cpu"
            && cpu.owner.as_str() == "owner/cpu"
            && matches!(cpu.kind, InstalledNodeKind::Gem5Closed { .. }))
}
