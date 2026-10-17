//! Projects closed original installation envelopes and actual semantic bodies.
//!
//! These rows classify only roles already named by the measured installation and
//! authenticated original binding. Historical paths and image/source identities
//! are attestations: conditional callbacks never reopen them. The exact current
//! host reconstruction executable and operational semantic bodies remain positive.

use std::{collections::BTreeMap, path::PathBuf};

use crucible_node_contract::{ContentRef, ExtensionDependency, Validate, canonical};
use serde::Deserialize;

use super::{
    InstalledReaderPackage, conditional_capture_records::insert,
    conditional_profile::ConditionalProfile, conditional_source::InspectionError,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: PathBuf,
    content: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageDocument {
    schema: String,
    policy_id: String,
    policy_version: u16,
    artifacts: BTreeMap<String, Artifact>,
    source_artifacts: BTreeMap<String, Artifact>,
    limitations: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handler {
    schema: String,
    source_policy: String,
    provider: ContentRef,
    device: ContentRef,
    source: ContentRef,
    recipe: ContentRef,
    contract: ContentRef,
    runtime_closure: ContentRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    schema: String,
    installed_package: ContentRef,
    actual_host_executable: ContentRef,
    namespace_policy: String,
    dynamic_input: String,
    cohort: serde_json::Value,
    transport_limits: serde_json::Value,
    class_accepted: bool,
    live_recording: serde_json::Value,
    adverse_source_inspection: String,
    observation_limits: serde_json::Value,
    sources: BTreeMap<String, String>,
}

/// Adds only named, complete original installation records to the closure.
pub(super) fn install(
    target: &mut ConditionalProfile,
    package: &InstalledReaderPackage,
) -> Result<(), InspectionError> {
    let first = target
        .history
        .bindings
        .values()
        .next()
        .ok_or("original candidate roster absent")?;
    if target.history.bindings.len() != 3
        || first.compatibility.qualification_refs.len() != 1
        || target.history.bindings.values().any(|binding| {
            binding.compatibility.qualification_refs != first.compatibility.qualification_refs
        })
    {
        return Err("original candidate qualification roster differs".into());
    }

    let document: PackageDocument = decode(package.document(), 1_048_576)?;
    if document.policy_id != "public-original-input-lineage-reader-v1"
        || document.policy_version != 1
        || document.schema != "crucible.reference.installed-lineage-reader-implementation.v1"
        || document.limitations.is_empty()
        || !document
            .artifacts
            .keys()
            .map(String::as_str)
            .eq(["device", "provider"])
        || !document.source_artifacts.keys().map(String::as_str).eq([
            "build_closure",
            "contract",
            "event",
            "handler",
            "input",
            "namespace_publication",
            "reader_definition",
            "recipe",
            "source",
            "stop",
        ])
        || document
            .artifacts
            .values()
            .chain(document.source_artifacts.values())
            .any(|artifact| !artifact.path.starts_with("/nix/store"))
    {
        return Err("historical package envelope differs from measured installation".into());
    }
    // The initial installed loader measured every role and parsed real runtime
    // graphs. This retained document is not a future path loader or code lease.
    row(target, package.identity(), package.document(), Vec::new())?;

    let definition = package.definition().regenerated();
    let handler_bytes = package
        .definition()
        .objects()
        .get(definition.handler())
        .ok_or("installed original handler body absent")?;
    let handler: Handler = decode(handler_bytes, 65_536)?;
    let source = |name: &str| {
        document
            .source_artifacts
            .get(name)
            .map(|artifact| &artifact.content)
            .ok_or("measured original source role absent")
    };
    if handler.schema != "crucible.reference.original-input-reader-handler.v1"
        || handler.source_policy != "public-original-input-lineage-reader-v1"
        || handler.provider != package.provider().content
        || handler.device != package.device().content
        || &handler.source != source("source")?
        || &handler.recipe != source("recipe")?
        || &handler.contract != source("contract")?
        || &handler.runtime_closure != source("build_closure")?
    {
        return Err("original handler identities differ from measured package".into());
    }
    // All six Handler fields are exact historical identity comparisons in this
    // codec. Later replay/policy/factory paths use retained inspected history;
    // none opens these native executables, recipe, archive or runtime graph.
    row(target, definition.handler(), handler_bytes, Vec::new())?;

    let namespace = source("namespace_publication")?;
    let namespace_bytes = package
        .definition()
        .objects()
        .get(namespace)
        .ok_or("original namespace body absent")?;
    // This published namespace edition is a fixed raw source literal, including
    // its field order and newline. No sorting/normalization changes its identity.
    let expected_namespace = b"{\"schema\":\"crucible.reference.lineage-reader.namespace-origin.v1\",\"namespace\":\"org.andyl.reference\",\"source_policy\":\"public-original-input-lineage-reader-v1\",\"authority\":\"unqualified installation data; independent source namespace authority required\"}\n";
    if namespace_bytes.as_slice() != expected_namespace {
        return Err("original namespace publication is not its closed source codec".into());
    }
    row(target, namespace, namespace_bytes, Vec::new())?;

    // Generated text contracts and the exact core source definitions have no
    // deferred object lookup in this installed codec. The declaration still
    // carries positive edges to each actual full body; no text/media wildcard.
    for reference in package.definition().axes().values() {
        let bytes = package
            .definition()
            .objects()
            .get(reference)
            .ok_or("original semantic axis body absent")?;
        row(target, reference, bytes, Vec::new())?;
    }
    for dependency in &definition.declaration().dependencies {
        match dependency {
            ExtensionDependency::Core {
                definition: reference,
                ..
            } => {
                let bytes = package
                    .definition()
                    .objects()
                    .get(reference)
                    .ok_or("original core definition body absent")?;
                row(target, reference, bytes, Vec::new())?;
            }
            ExtensionDependency::Extension { .. } => {
                return Err("historical nested installed extension refused".into());
            }
        }
    }

    // Original bindings name exactly this candidate, not a namespace authority
    // or a generic qualification leaf. Its source strings are signed inline
    // data, never executable reconstruction references or current source code.
    // The entry check precedes all package/body allocations and row mutations.
    let reference = &target
        .history
        .bindings
        .values()
        .next()
        .ok_or("original candidate roster absent")?
        .compatibility
        .qualification_refs[0];
    let bytes = target
        .history
        .objects
        .get(reference)
        .ok_or("original binding qualification body absent")?;
    let candidate: Candidate = decode(bytes, 1_048_576)?;
    validate_candidate(&candidate, package)?;
    reference
        .verify(bytes)
        .map_err(InspectionError::from_error)?;
    if target.content.get(reference) != Some(bytes) {
        return Err("original candidate body differs from retained signed closure".into());
    }
    insert(
        &mut target.construction_rows,
        reference.clone(),
        vec![candidate.installed_package],
    )
    .map_err(InspectionError::from_error)?;
    Ok(())
}

fn validate_candidate(
    candidate: &Candidate,
    package: &InstalledReaderPackage,
) -> Result<(), InspectionError> {
    // This signed historical host pin never substitutes for current measurement
    // or authorizes the original native source. No historical host image is opened.
    candidate
        .actual_host_executable
        .validate()
        .map_err(InspectionError::from_error)?;
    let expected_sources = [
        "definition",
        "fixture",
        "graph",
        "namespace",
        "native",
        "owning_cleanup",
        "package",
        "policy",
        "recording_adapter",
        "recording_canonical_codec",
        "recording_capture",
        "recording_context_fragments",
        "recording_envelope_codec",
        "recording_envelope_models",
        "recording_fixture",
        "recording_models",
        "recording_module",
        "recording_original_lineage",
        "recording_replay",
        "runtime_original_assembly",
        "runtime_original_geometry",
        "runtime_original_lineage",
        "selected_boundary",
        "selected_input",
        "selected_native_rows",
        "selected_publication",
    ];
    if candidate.schema != "crucible.reference.reader-three-peer.candidate.v1"
        || &candidate.installed_package != package.identity()
        || candidate.actual_host_executable.length.get() == 0
        || candidate.actual_host_executable.length.get() > 512 * 1024 * 1024
        || candidate.actual_host_executable.media_type != "application/octet-stream"
        || candidate.class_accepted
        || candidate.namespace_policy
            != "exact predeclared installed package and regenerated durable facet/compat only"
        || candidate.dynamic_input
            != "owning selected source reader under sealed runtime original input capability"
        || !candidate
            .sources
            .keys()
            .map(String::as_str)
            .eq(expected_sources)
        || candidate.sources.values().any(String::is_empty)
        || candidate.adverse_source_inspection.is_empty()
        || candidate.live_recording != super::recording::declared_scope()
        || candidate.cohort
            != serde_json::json!({
                "quanta_per_peer":3,"initial_quantum_order":["source","link","disk"],
                "subsequent_quantum_order":["disk","link","source"],"route_latency_ps":0,
                "maximum_pending_events_per_route":1,"maximum_pending_bytes_per_route":4096
            })
        || candidate.transport_limits
            != serde_json::json!({
                "journal_entries":4096,"maximum_outstanding_requests":32,"frame_bytes":1048576,
                "host_original_request_entries_per_lane":4096,"host_content_objects":4096,
                "host_content_bytes":16777216
            })
        || candidate.observation_limits
            != serde_json::json!({
                "maximum_requests":4096,"maximum_objects":4096,"maximum_bytes":33554432
            })
    {
        return Err("original candidate qualification is outside its closed recorded scope".into());
    }
    Ok(())
}

fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, InspectionError> {
    let value = canonical::parse_json(bytes, maximum).map_err(InspectionError::from_error)?;
    if canonical::canonical_json(&value).map_err(InspectionError::from_error)? != bytes {
        return Err("historical installation body is not canonical".into());
    }
    if let Some(sources) = value.get("sources")
        && sources
            .as_object()
            .is_none_or(|sources| sources.len() != 26)
    {
        return Err("original inline source inventory credit differs".into());
    }
    serde_json::from_value(value).map_err(InspectionError::from_error)
}

fn row(
    target: &mut ConditionalProfile,
    reference: &ContentRef,
    bytes: &[u8],
    dependencies: Vec<ContentRef>,
) -> Result<(), InspectionError> {
    reference
        .verify(bytes)
        .map_err(InspectionError::from_error)?;
    if target.content.get(reference).map(Vec::as_slice) != Some(bytes) {
        return Err("original installation body absent or changed in signed closure".into());
    }
    insert(
        &mut target.construction_rows,
        reference.clone(),
        dependencies,
    )
    .map_err(InspectionError::from_error)
}
