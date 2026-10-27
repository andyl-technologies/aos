//! Explicit installed terminal codecs for closed assertion programs and clocks.

use super::*;

pub(super) fn selected(
    selections: &[InstalledNodeSelection],
    artifacts: &BTreeMap<String, super::super::InstalledIoArtifact>,
) -> Result<bool, NodeObservedError> {
    let mut semantic = 0;
    for selection in selections {
        match &selection.kind {
            InstalledNodeKind::HostClock => {}
            InstalledNodeKind::HostSemantics { profile } => {
                let (definition, _) = super::super::semantics::read_program(profile, artifacts)?;
                if definition.version != 2 || !definition.inputs.is_empty() {
                    return Ok(false);
                }
                semantic += 1;
            }
            _ => return Ok(false),
        }
    }
    Ok(semantic == 1)
}

pub(super) fn install_inventory(
    descriptor: &NodeDescriptor,
    binding: &mut BindingCompatibility,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(), NodeObservedError> {
    let mut inventory = binding
        .operating_contract
        .facets
        .first()
        .cloned()
        .ok_or_else(|| refused("installed host preservation facet absent"))?;
    inventory.id = Id::new("host/terminal-inventory-v1")?;
    inventory.version = 1;
    inventory.extensions = Extensions::new();
    binding.operating_contract.facets.push(inventory);
    binding
        .operating_contract
        .facets
        .sort_by(|left, right| left.id.cmp(&right.id));
    let mut capabilities: CapabilityProfile =
        serde_json::from_slice(&contents[&binding.capabilities_ref.hash.digest].bytes)?;
    capabilities.facets = binding.operating_contract.facets.clone();
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    let guarantees: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version": 2,
            "descriptor": descriptor,
            "implementation": binding.implementation,
            "operating_contract": binding.operating_contract,
            "capabilities": capabilities,
            "guarantees": guarantees,
            "coordinator_codec": "crucible.host-terminal-coordinator-v2",
            "runtime_codec": "crucible.runtime-terminal-v3",
            "scope": "closed_assertion_programs_and_integer_clocks",
        }),
    )?;
    Ok(())
}
