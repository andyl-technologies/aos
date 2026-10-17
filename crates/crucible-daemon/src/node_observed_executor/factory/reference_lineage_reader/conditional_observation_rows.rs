//! Validates the fixed historical observation envelope without reopening images.
//!
//! Requests and objects are embedded exact bytes. Original executable and
//! compatibility identities are historical attestations. Replay and restoration
//! use the separately authenticated selected native rows, not this snapshot as
//! a content resolver or an authority to dispatch controls.

use std::collections::BTreeSet;

use crucible_node_contract::{
    BindingCompatibility, Bytes, ContentRef, HashRef, Id, IdSet, U64, canonical,
};
use crucible_node_provider::envelope::{Envelope, Nullable, RequestOrigin};
use serde::{Deserialize, Serialize};

use super::{
    InstalledReaderPackage,
    conditional_capture_records::insert,
    conditional_profile::{ConditionalProfile, encode},
    conditional_source::InspectionError,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedObservation {
    recording_complete: bool,
    observed_unknown: bool,
    recording_failure: Nullable<String>,
    evidence: Snapshot,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u16,
    encoding: String,
    scope: Scope,
    requests: Vec<Request>,
    objects: Vec<Content>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    provider_pid: U64,
    provider_executable: ContentRef,
    session_id: Id,
    incarnation_id: Id,
    connection_id: Id,
    connection_epoch: U64,
    selected_features: IdSet,
    compatibility: BindingCompatibility,
    binding_hash: HashRef,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Content {
    reference: ContentRef,
    bytes: Bytes,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    key: Key,
    identity: HashRef,
    request: Content,
    response: Nullable<Content>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    origin: String,
    request_id: Id,
}

/// Registers only the exact closed, scoped historical observation edition.
pub(super) fn install(
    target: &mut ConditionalProfile,
    package: &InstalledReaderPackage,
) -> Result<(), InspectionError> {
    let history = std::rc::Rc::clone(&target.history);
    let mut references = BTreeSet::new();
    let mut occurrences = 0usize;
    for source in history.originals.values() {
        for object in &source.transcript().origin.context {
            let edges = if object.reference.media_type
                == crate::node_observed_executor::factory::transcript::ORIGINAL_CONTEXT_FRAGMENT_MEDIA_TYPE
            {
                Some(target.construction_rows.get(&object.reference)
                    .ok_or("original context fragment projection absent")?)
            } else {
                None
            };
            occurrences = occurrences
                .checked_add(1 + edges.map_or(0, Vec::len))
                .filter(|total| *total <= 4096)
                .ok_or("historical context role credit exceeded")?;
            references.insert(object.reference.clone());
            if let Some(edges) = edges {
                // The verified fragment projection contains only the original
                // semantic body and raw byte chunks. Payload/evidence objects
                // outside the signed context never select this codec.
                references.extend(edges.iter().cloned());
            }
        }
    }
    for reference in &references {
        let bytes = history
            .objects
            .get(reference)
            .or_else(|| target.content.get(reference))
            .ok_or("original context codec body absent")?;
        if reference.media_type != "application/json" || bytes.len() > 64 * 1024 * 1024 {
            continue;
        }
        // This explicit edition tag selects the one installed codec. Other
        // JSON objects get no row, even if their shapes superficially resemble it.
        let Ok(value) = canonical::parse_json(bytes, 64 * 1024 * 1024) else {
            continue;
        };
        // The source publishes RecordedReferenceObservation, whose known
        // snapshot edition is nested under evidence. This tag is examined only
        // among exact signed Origin.context/verified fragment commitments.
        let Some(evidence) = value.get("evidence") else {
            continue;
        };
        if evidence.get("encoding").and_then(serde_json::Value::as_str)
            != Some("retained-canonical-envelope-v1")
        {
            continue;
        }
        if value
            .get("recording_complete")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
            || value
                .get("observed_unknown")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
            || !value
                .get("recording_failure")
                .is_some_and(serde_json::Value::is_null)
        {
            return Err("original recording snapshot is incomplete or unknown".into());
        }
        reference
            .verify(bytes)
            .map_err(InspectionError::from_error)?;
        let mut encoded_bytes = 0usize;
        for name in ["requests", "objects"] {
            let entries = evidence
                .get(name)
                .and_then(serde_json::Value::as_array)
                .filter(|entries| entries.len() <= 4096)
                .ok_or("historical snapshot entry credit exceeded")?;
            for entry in entries {
                let bodies: Vec<&serde_json::Value> = if name == "objects" {
                    vec![entry]
                } else {
                    let mut bodies = vec![entry.get("request").ok_or("snapshot request absent")?];
                    if let Some(response) = entry.get("response").filter(|value| !value.is_null()) {
                        bodies.push(response);
                    }
                    bodies
                };
                for body in bodies {
                    let length = body
                        .get("bytes")
                        .and_then(serde_json::Value::as_str)
                        .ok_or("snapshot bytes are not the original bounded byte encoding")?
                        .len();
                    encoded_bytes = encoded_bytes
                        .checked_add(length)
                        .filter(|total| *total <= 64 * 1024 * 1024)
                        .ok_or("historical snapshot aggregate byte credit exceeded")?;
                }
            }
        }
        let recorded: RecordedObservation =
            serde_json::from_value(value).map_err(InspectionError::from_error)?;
        if !recorded.recording_complete
            || recorded.observed_unknown
            || recorded.recording_failure.0.is_some()
            || encode(&recorded)? != *bytes
        {
            return Err("original observation wrapper differs from its source constructor".into());
        }
        let snapshot = recorded.evidence;
        if snapshot.schema_version != 1
            || snapshot.scope.provider_pid.get() == 0
            || snapshot.scope.provider_executable
                != *package
                    .artifact_content("provider")
                    .map_err(InspectionError::from_error)?
        {
            return Err("historical snapshot codec or measured provider pin differs".into());
        }
        let binding = history
            .bindings
            .get(&snapshot.scope.compatibility.node_id)
            .ok_or("historical snapshot original node absent")?;
        if snapshot.scope.compatibility != binding.compatibility
            || snapshot.scope.binding_hash
                != binding.identity().map_err(InspectionError::from_error)?
            || snapshot.scope.session_id != binding.authority.session_id
            || snapshot.scope.incarnation_id != binding.authority.incarnation_id
        {
            return Err("historical snapshot scope differs from authenticated original".into());
        }
        let mut prior_key = None;
        for original in &snapshot.requests {
            let origin = match original.key.origin.as_str() {
                "controller" => RequestOrigin::Controller,
                "provider" => RequestOrigin::Provider,
                _ => return Err("unknown historical request origin".into()),
            };
            let key = (original.key.origin.as_str(), &original.key.request_id);
            if prior_key.is_some_and(|prior| prior >= key) {
                return Err("historical request identities are not strictly ordered".into());
            }
            prior_key = Some(key);
            let request = envelope(&original.request)?;
            if request.request_id.0.as_ref() != Some(&original.key.request_id)
                || request.session_id.0.as_ref() != Some(&snapshot.scope.session_id)
                || request.incarnation_id.0.as_ref() != Some(&snapshot.scope.incarnation_id)
                || request
                    .request_hash(origin)
                    .map_err(InspectionError::from_error)?
                    != original.identity
            {
                return Err("historical original request identity differs".into());
            }
            if let Some(response) = &original.response.0 {
                request
                    .matches_response(&envelope(response)?)
                    .map_err(InspectionError::from_error)?;
            }
        }
        let mut prior_object = None;
        for object in &snapshot.objects {
            if prior_object.is_some_and(|prior| prior >= &object.reference) {
                return Err("historical snapshot full references are not strictly ordered".into());
            }
            prior_object = Some(&object.reference);
            object
                .reference
                .verify(object.bytes.as_slice())
                .map_err(InspectionError::from_error)?;
        }
        // All nested controls/content are inline authenticated data. This row
        // grants no external content lookup or current executable dependency.
        insert(&mut target.construction_rows, reference.clone(), Vec::new())
            .map_err(InspectionError::from_error)?;
    }
    Ok(())
}

fn envelope(content: &Content) -> Result<Envelope, InspectionError> {
    content
        .reference
        .verify(content.bytes.as_slice())
        .map_err(InspectionError::from_error)?;
    let envelope: Envelope = serde_json::from_value(
        canonical::parse_json(content.bytes.as_slice(), 1024 * 1024)
            .map_err(InspectionError::from_error)?,
    )
    .map_err(InspectionError::from_error)?;
    envelope.validate().map_err(InspectionError::from_error)?;
    if encode(&envelope)? != content.bytes.as_slice() {
        return Err("historical original envelope encoding differs".into());
    }
    Ok(envelope)
}
