//! Authenticates authored demands at the whole-graph sealing boundary.

use super::{
    AdmittedCapabilitySelection, CAPABILITY_SELECTION_FORMAT, CapabilityRequirements,
    CapabilitySelection, failure, node_failure,
};
use crate::node_admission::{
    AdmissionRequest, AdmittedExtensionSet, GuaranteeProfile, evidence::VerifiedContent,
};
use crucible_node_contract::Id;
use crucible_node_contract::{CapabilityProfile, canonical};
use std::collections::BTreeMap;

pub(in crate::node_admission) fn check_selection(
    request: &AdmissionRequest<'_>,
    guarantees: &BTreeMap<Id, GuaranteeProfile>,
    extensions: &AdmittedExtensionSet,
    bytes: Vec<u8>,
    content: &mut VerifiedContent<'_>,
) -> Result<Option<AdmittedCapabilitySelection>, crate::node_admission::AdmissionError> {
    // A separate content type selects the new root interpretation. Legacy
    // opaque/JSON roots retain their original bytes, accounting and semantics.
    if request.world.scenario_ref.media_type != super::CAPABILITY_SELECTION_MEDIA_TYPE {
        return Ok(None);
    }
    let value = canonical::parse_json(&bytes, content.limits.maximum_content_bytes)
        .map_err(crate::node_admission::nodes::schema_error)?;
    let selection: CapabilitySelection = serde_json::from_value(value)
        .map_err(|_| failure("closed capability-selection wrapper"))?;
    if selection.format != CAPABILITY_SELECTION_FORMAT
        || selection.requirements_ref.media_type != super::CAPABILITY_REQUIREMENTS_MEDIA_TYPE
        || selection.schema_version != 1
        || selection.bindings.len() != request.bindings.len()
        || selection
            .bindings
            .windows(2)
            .any(|pair| pair[0].node >= pair[1].node)
        || selection.base_scenario_ref == request.world.scenario_ref
    {
        return Err(failure(
            "complete sorted resolution and nonrecursive baseline scenario",
        ));
    }
    let base_bytes = content.read(&selection.base_scenario_ref)?;
    for (selected, actual) in selection.bindings.iter().zip(request.bindings) {
        if selected.node != actual.compatibility.node_id
            || selected.compatibility_hash
                != actual
                    .compatibility
                    .identity()
                    .map_err(crate::node_admission::nodes::schema_error)?
        {
            return Err(failure(
                "exact complete compatibility hashes for this whole resolution",
            ));
        }
    }
    let requirement_bytes = content.read(&selection.requirements_ref)?;
    let requirements: CapabilityRequirements = serde_json::from_value(
        canonical::parse_json(&requirement_bytes, content.limits.maximum_content_bytes)
            .map_err(crate::node_admission::nodes::schema_error)?,
    )
    .map_err(|_| failure("closed mandatory capability requirements document"))?;
    requirements.validate()?;
    if requirements.nodes.len() != request.bindings.len() {
        return Err(failure(
            "mandatory requirements for the complete node roster",
        ));
    }
    for demand in &requirements.nodes {
        let descriptor = request
            .descriptors
            .iter()
            .find(|node| node.id == demand.node)
            .ok_or_else(|| node_failure(demand, "demanded node present in complete world"))?;
        let binding = request
            .bindings
            .iter()
            .find(|node| node.compatibility.node_id == demand.node)
            .ok_or_else(|| node_failure(demand, "actual demanded binding"))?;
        let capabilities: CapabilityProfile =
            content.policy(&binding.compatibility.capabilities_ref)?;
        let guarantee = guarantees
            .get(&demand.node)
            .ok_or_else(|| node_failure(demand, "actual authenticated guarantee profile"))?;
        demand.match_contract(descriptor, &binding.compatibility, &capabilities, guarantee)?;
        for required in &demand.extensions {
            if !extensions.applications().any(|application| {
                application.scope().node() == Some(&demand.node)
                    && application.scope().record_kind().is_durable()
                    && &application.selected().selection == required
            }) {
                return Err(node_failure(
                    demand,
                    "exact directly selected durable semantic extension",
                ));
            }
        }
        content
            .source
            .qualify_capability(request.world, binding, demand)
            .map_err(|error| {
                crate::node_admission::error::refuse(
                    crate::node_admission::AdmissionStage::Authenticate,
                    crate::node_admission::AdmissionSubject::Node(demand.node.clone()),
                    crate::node_admission::AdmissionCode::QualificationUnavailable,
                    "installed operation and architecture semantics for actual enrolled scope",
                    error.message,
                )
            })?;
    }
    let mut objects = BTreeMap::new();
    objects.insert(request.world.scenario_ref.clone(), bytes);
    objects.insert(selection.requirements_ref.clone(), requirement_bytes);
    objects.insert(selection.base_scenario_ref.clone(), base_bytes);
    Ok(Some(AdmittedCapabilitySelection {
        selection,
        requirements,
        objects,
    }))
}
