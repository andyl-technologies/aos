//! Distinct complete stopped-condition preservation selection and measured policy.
//!
//! Live condition controls retain their original capture refusal. This scope
//! selects native/coordinator six and scheduler four only at an acknowledged,
//! unresumed original Stop; it never derives native authority from a marker.

use super::*;
use crucible_node_contract::SchemaRef;

pub(super) fn selected(selections: &[InstalledNodeSelection]) -> bool {
    selections.iter().any(|selected| {
        matches!(
            selected.kind,
            InstalledNodeKind::HostConditionDebugPreserving { .. }
        )
    })
}

pub(super) fn install_scope(
    descriptor: &NodeDescriptor,
    binding: &mut BindingCompatibility,
    contents: &mut BTreeMap<String, ScenarioContent>,
) -> Result<(), NodeObservedError> {
    let definition = put(
        contents,
        super::super::condition_debug::PRESERVATION_SCHEMA.to_vec(),
        "text/plain",
    )?;
    binding
        .implementation
        .formats
        .retain(|schema| !schema.id.as_str().starts_with("host/native-"));
    binding.implementation.formats.push(SchemaRef {
        id: Id::new("host/native-condition-continuation-v1")?,
        version: 1,
        definition: definition.clone(),
        extensions: Extensions::new(),
    });
    binding
        .implementation
        .formats
        .sort_by(|left, right| left.id.cmp(&right.id));
    let mut guarantees: GuaranteeProfile =
        serde_json::from_slice(&contents[&binding.guarantees_ref.hash.digest].bytes)?;
    guarantees.capture_scope = CaptureScope::CompleteModel;
    guarantees.continuation = Continuation::Exact;
    guarantees.durable_restart = true;
    guarantees.limitations_ref = definition;
    binding.guarantees_ref = put_json(contents, &guarantees)?;
    let mut facet = binding
        .operating_contract
        .facets
        .first()
        .cloned()
        .ok_or_else(|| refused("condition preserving operation template absent"))?;
    facet.id = Id::new("host/condition-preservation-v1")?;
    facet.version = 1;
    binding.operating_contract.facets.push(facet);
    binding
        .operating_contract
        .facets
        .sort_by(|left, right| left.id.cmp(&right.id));
    for facet in &mut binding.operating_contract.facets {
        facet.configuration_ref = descriptor.configuration_ref.clone();
        facet.guarantees_ref = binding.guarantees_ref.clone();
    }
    let mut capabilities: CapabilityProfile =
        serde_json::from_slice(&contents[&binding.capabilities_ref.hash.digest].bytes)?;
    capabilities.facets = binding.operating_contract.facets.clone();
    if descriptor
        .roles
        .iter()
        .any(|role| role.as_str() == "condition_observer")
    {
        let mut devices: serde_json::Value =
            serde_json::from_slice(&contents[&capabilities.devices_ref.hash.digest].bytes)?;
        let fields = devices
            .as_object_mut()
            .ok_or_else(|| refused("condition device scope is not an object"))?;
        fields.insert(
            "capture".into(),
            "original_acknowledged_unresumed_stop_only".into(),
        );
        fields.insert("native_continuation_edition".into(), 6.into());
        capabilities.devices_ref = put_json(contents, &devices)?;
    }
    binding.capabilities_ref = put_json(contents, &capabilities)?;
    binding.profile_ref = put_json(
        contents,
        &serde_json::json!({
            "schema_version": 1, "descriptor": descriptor,
            "implementation": binding.implementation,
            "operating_contract": binding.operating_contract,
            "capabilities": capabilities, "guarantees": guarantees,
            "scope": "qualified_original_acknowledged_unresumed_condition_stop",
        }),
    )?;
    Ok(())
}
