//! Installed source verification before any conditional replay realization.
//!
//! Signed transcripts remain source observations. This verifier independently
//! regenerates the accepted native profile and reads actual retained enrollment
//! bodies; it grants no fresh native authority or counterfactual replay license.

use crucible::node_adapters::transcript::AuthenticatedTranscript;
use crucible_node_contract::NodeBinding;
use serde::Deserialize;

use super::*;

const CONTEXT_MEDIA_TYPE: &str =
    "application/vnd.crucible.installed-reference-recording-context+json";

/// Owns the exact accepted recorded pair before a fresh cursor allocation.
#[derive(Clone)]
pub(super) struct VerifiedRecordedWorld {
    pub(super) sources: BTreeMap<Id, AuthenticatedTranscript>,
    pub(super) scenario: NodeScenario,
    pub(super) configuration: NodeRunConfiguration,
    pub(super) selections: Vec<InstalledNodeSelection>,
    pub(super) source_bindings: BTreeMap<Id, NodeBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    format: String,
    version: u16,
    execution: String,
    host: ContentRef,
    device: ContentRef,
}

pub(super) fn verify_original_world(
    catalog: &InstalledNodeCatalog,
    sources: BTreeMap<Id, AuthenticatedTranscript>,
    expected_configuration: &NodeRunConfiguration,
) -> Result<VerifiedRecordedWorld, NodeObservedError> {
    if sources.len() != 2
        || measure_executable(&catalog.host_executable)? != catalog.host_identity
        || measure_executable(&catalog.device_executable)? != catalog.device_identity
    {
        return Err(refused(
            "recorded pair or installed source executable differs",
        ));
    }
    let first = sources
        .values()
        .next()
        .ok_or_else(|| refused("recorded native pair is empty"))?;
    let declared = declared_context(first)?;
    if declared.schema_version != 1
        || !same_json(&declared.configuration, expected_configuration)?
        || declared.selections.len() != 2
        || declared.selections.iter().any(|selection| {
            !matches!(
                selection.kind,
                InstalledNodeKind::ReferenceNativeLinked { .. }
            )
        })
    {
        return Err(refused(
            "recorded native source context is outside installed pair policy",
        ));
    }
    let regenerated = super::super::profile::build_world(
        &declared.selections,
        &catalog.host_identity,
        &catalog.device_identity,
        &catalog.artifacts,
    )?
    .scenario;
    if !same_json(&regenerated, &declared.scenario)?
        || first.transcript().origin.activation.world_binding_hash
            != regenerated.world.identity()?
    {
        return Err(refused(
            "recorded native world differs from installed complete definition",
        ));
    }
    let activation = &first.transcript().origin.activation;
    let attempt = &first.transcript().origin.attempt;
    let mut bindings = BTreeMap::new();
    for selection in &declared.selections {
        let source = sources
            .get(&selection.node)
            .ok_or_else(|| refused("recorded pair lacks original selected actor"))?;
        let origin = &source.transcript().origin;
        if origin.route.node != selection.node
            || &origin.activation != activation
            || &origin.attempt != attempt
            || !same_json(&declared_context(source)?, &declared)?
        {
            return Err(refused(
                "recorded actors do not share the complete original world",
            ));
        }
        let binding_object = origin
            .context
            .iter()
            .find(|object| object.reference == origin.source_binding)
            .ok_or_else(|| refused("original native binding body is absent"))?;
        let binding: NodeBinding = serde_json::from_slice(&binding_object.bytes)?;
        let expected = regenerated
            .compatibility
            .iter()
            .find(|binding| binding.node_id == selection.node)
            .ok_or_else(|| refused("installed source profile omits original actor"))?;
        if &binding.compatibility != expected
            || origin.route.owners.len() != 1
            || origin.route.owners[0].owner != selection.owner
            || binding.authority.incarnation_id != origin.route.owners[0].incarnation
            || binding.authority.owner_generation != origin.route.owners[0].generation
        {
            return Err(refused(
                "original native selected profile or owner scope changed",
            ));
        }
        let receipt = origin
            .context
            .iter()
            .find(|object| object.reference == binding.authority.host_receipt)
            .ok_or_else(|| refused("actual native enrollment receipt body is absent"))?;
        let enrolled: Enrollment = serde_json::from_slice(&receipt.bytes)?;
        if enrolled.format != "crucible.local-node-enrollment"
            || enrolled.version != 1
            || format!("observed/{}", enrolled.execution) != attempt.as_str()
            || enrolled.host != catalog.host_identity
            || enrolled.device != catalog.device_identity
        {
            return Err(refused(
                "original native enrollment does not bind installed source code",
            ));
        }
        bindings.insert(selection.node.clone(), binding);
    }
    Ok(VerifiedRecordedWorld {
        sources,
        scenario: declared.scenario,
        configuration: declared.configuration,
        selections: declared.selections,
        source_bindings: bindings,
    })
}

fn declared_context(
    source: &AuthenticatedTranscript,
) -> Result<recording::InstalledRecordingContext, NodeObservedError> {
    let objects = &source.transcript().origin.context;
    let declaration = if let Some(object) = objects
        .iter()
        .find(|object| object.reference.media_type == CONTEXT_MEDIA_TYPE)
    {
        object.clone()
    } else {
        let manifests = objects
            .iter()
            .filter(|object| object.reference.media_type == context_fragments::FRAGMENT_MEDIA_TYPE)
            .collect::<Vec<_>>();
        if manifests.len() != 1 {
            return Err(refused(
                "original installed context has no unique selected encoding",
            ));
        }
        context_fragments::reconstruct_source_object(manifests[0], objects, 64 * 1024 * 1024)?
    };
    if declaration.reference.media_type != CONTEXT_MEDIA_TYPE {
        return Err(refused(
            "original fragment manifest names another source context role",
        ));
    }
    declaration.reference.verify(&declaration.bytes)?;
    Ok(serde_json::from_slice(&declaration.bytes)?)
}

fn same_json(left: &impl Serialize, right: &impl Serialize) -> Result<bool, NodeObservedError> {
    Ok(serde_json::to_value(left)? == serde_json::to_value(right)?)
}
