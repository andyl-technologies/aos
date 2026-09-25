//! Typed observation of the storage-provisioning GPT marker.
//!
//! This provider owns Linux block-device inspection for the durable marker.
//! Generic metadata evaluation receives only the checked typed observation.

use std::collections::BTreeMap;
use std::io::{self, Read as _, Write as _};
use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, AccessMode, LocalKey, MethodSemantics, ResourceReference,
};
use aos_provider_protocol::{
    ADMISSION_REQUEST_SCHEMA, ADMISSION_SCHEMA, AdmissionDisposition, AdmissionRequest,
    AdmissionResult, AdmissionRevision, HANDLER_ABI_ARGUMENT, INVOCATION_SCHEMA, Invocation,
    InvocationDisposition, InvocationPurpose, InvocationResult, MAX_HANDLER_RESULT_BYTES,
    RESULT_SCHEMA, ResourceContext, SupportedPurposes, resource_set_digest,
    validate_admission_resource, validate_resource_context, validate_resource_contexts,
};
use aos_storage_provisioning::{
    CanonicalProvisioningSource, ProvisioningIntent, ProvisioningMarkerObservation,
    ProvisioningMarkerState, normalize_marker_uuid, validate_provisioning_intent,
    validate_provisioning_marker_observation,
};
use serde::{Deserialize, Serialize};

use crate::engine::ability_value;
use crate::process::{Executable, ExecutableReference};
use crate::root_observation::{BlockStorageRootRole, observe_root};

const CONTEXT_SCHEMA: &str = "aos.storage.provisioning-marker-context/v1";
const EVIDENCE_SCHEMA: &str = "aos.storage.provisioning-marker-evidence/v1";
const OBSERVATION_SCHEMA: &str = "aos.storage.provisioning-marker-observation/v1";
const PENDING_LABEL: &str = "aos-provisioning-pending-v1";
const OPERATOR_LABEL: &str = "aos-provenance-operator-v1";
const FALLBACK_LABEL: &str = "aos-provenance-fallback-v1";
const MARKER_TYPE_GUID: &str = "163bea60-58c7-46e7-b69a-6846a5a688af";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkerParameters {
    request: ProvisioningIntent,
    lsblk: ExecutableReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MarkerContext {
    schema: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct MarkerEvidence {
    schema: &'static str,
    state: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LsblkDocument {
    blockdevices: Vec<LsblkDevice>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LsblkDevice {
    #[serde(rename = "type")]
    device_type: String,
    #[serde(default)]
    parttype: Option<String>,
    #[serde(default)]
    partlabel: Option<String>,
    #[serde(default)]
    partuuid: Option<String>,
    #[serde(default)]
    children: Vec<LsblkDevice>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MarkerPartition {
    label: String,
    partition_type: String,
    part_uuid: String,
}

/// Runs the provisioning-marker provider from process arguments and streams.
///
/// # Errors
///
/// Returns an error when the ABI, authority, typed request, exact executable,
/// block-device output, or canonical provider result is invalid.
pub fn run_from_process() -> Result<()> {
    let arguments = std::env::args().collect::<Vec<_>>();
    ensure!(
        arguments.len() == 3 && arguments[1] == HANDLER_ABI_ARGUMENT,
        "expected --aos-primitive-v1 and one purpose"
    );

    let mut input = Vec::new();
    io::stdin()
        .take(ABILITY_LIMITS_V1.max_document_bytes + 1)
        .read_to_end(&mut input)
        .context("reading bounded marker invocation")?;
    ensure!(
        input.len() as u64 <= ABILITY_LIMITS_V1.max_document_bytes,
        "marker invocation exceeds the canonical document bound"
    );

    let output = match arguments[2].as_str() {
        "observe-root" => serde_json::to_value(observe_root(
            BlockStorageRootRole::ProvisioningMarker,
            &input,
        )?)?,
        "admit" => {
            let request = aos_contract::canonical::from_slice(&input, "marker admission")?;
            serde_json::to_value(admit(request)?)?
        }
        "effect" => {
            let invocation = aos_contract::canonical::from_slice(&input, "marker invocation")?;
            serde_json::to_value(invoke(invocation)?)?
        }
        purpose => bail!("unsupported marker provider purpose {purpose:?}"),
    };
    let bytes = aos_contract::canonical::canonical_json(&output)?;
    ensure!(
        bytes.len() <= MAX_HANDLER_RESULT_BYTES,
        "marker response exceeds the handler result bound"
    );
    io::stdout().write_all(&bytes).context("writing response")
}

fn admit(request: AdmissionRequest) -> Result<AdmissionResult> {
    ensure!(
        request.schema == ADMISSION_REQUEST_SCHEMA,
        "unsupported admission schema"
    );
    validate_admission_resource(&request)?;
    validate_resource_contexts(&request.resources)?;
    validate_method(
        request.method.method.as_str(),
        &request.semantics,
        &request.target,
    )?;
    let intent: ProvisioningIntent = decode(&request.resource_spec.value)?;
    validate_provisioning_intent(&intent)?;

    Ok(AdmissionResult {
        schema: ADMISSION_SCHEMA.into(),
        disposition: AdmissionDisposition::Admitted,
        revision: AdmissionRevision::Absent,
        incarnation: Some(request.assignment.incarnation),
        observation: evidence("ready")?,
        native_context: ability_value(serde_json::to_value(MarkerContext {
            schema: CONTEXT_SCHEMA.into(),
        })?)?,
        supported_purposes: SupportedPurposes::from_ordered(vec![InvocationPurpose::Effect])
            .context("constructing marker purpose set")?,
    })
}

fn invoke(invocation: Invocation) -> Result<InvocationResult> {
    ensure!(
        invocation.schema == INVOCATION_SCHEMA && invocation.purpose == InvocationPurpose::Effect,
        "marker provider accepts only effect invocations"
    );
    ensure!(
        invocation.method_is_bound(),
        "marker invocation method is not durably bound"
    );
    validate_resource_contexts(&invocation.request.resources)?;
    ensure!(
        resource_set_digest(&invocation.request.resources)?
            == invocation.request.native_context_digest,
        "marker resource contexts differ from their authenticated digest"
    );
    validate_method(
        invocation.method.method.as_str(),
        &invocation.semantics,
        &invocation.request.target,
    )?;
    validate_method(
        invocation.request.method.method.as_str(),
        &invocation.request.semantics,
        &invocation.request.target,
    )?;
    ensure!(
        invocation.method.interface == invocation.request.method.interface
            && invocation.method.interface == invocation.request.target.interface,
        "marker invocation interface differs from its checked target"
    );
    if invocation.control.cancelled {
        return Ok(InvocationResult {
            schema: RESULT_SCHEMA.into(),
            disposition: InvocationDisposition::RejectedBeforeEffect,
            evidence: evidence("ready")?,
            outputs: BTreeMap::new(),
            native_context_digest: invocation.request.native_context_digest,
        });
    }
    let target = exact_context(&invocation.request.target, &invocation.request.resources)?;
    let bound = validate_resource_context(target)?;
    let context: MarkerContext = decode(&bound.provider_context)?;
    ensure!(
        context.schema == CONTEXT_SCHEMA,
        "unsupported provisioning-marker provider context"
    );
    let intent: ProvisioningIntent = decode(&bound.resource_spec.value)?;
    validate_provisioning_intent(&intent)?;
    let parameters: MarkerParameters = decode(&invocation.request.inputs)?;
    ensure!(
        parameters.request == intent,
        "marker request differs from the checked provisioning resource"
    );
    let marker = observe_marker(
        &parameters.lsblk.resolve()?,
        &parameters.request.root_device,
        invocation.control.attempt_remaining_millis,
    )?;

    let mut outputs = BTreeMap::new();
    outputs.insert(
        LocalKey::new("marker")?,
        ability_value(serde_json::to_value(marker)?)?,
    );
    Ok(InvocationResult {
        schema: RESULT_SCHEMA.into(),
        disposition: InvocationDisposition::Completed,
        evidence: evidence("observed")?,
        outputs,
        native_context_digest: invocation.request.native_context_digest,
    })
}

fn observe_marker(
    lsblk: &Executable,
    root_device: &str,
    remaining_millis: u64,
) -> Result<ProvisioningMarkerObservation> {
    let root_disk = root_disk(lsblk, root_device, remaining_millis)?;
    let output = lsblk.run(
        &[
            "-J",
            "-p",
            "-o",
            "TYPE,PARTTYPE,PARTLABEL,PARTUUID",
            "--",
            &root_disk,
        ],
        remaining_millis,
    )?;
    ensure!(
        output.status.success(),
        "lsblk could not inspect the root disk"
    );
    let document: LsblkDocument =
        serde_json::from_slice(&output.stdout).context("decoding root-disk lsblk output")?;
    let mut partitions = Vec::new();
    for device in &document.blockdevices {
        collect_markers(device, &mut partitions)?;
    }
    classify_markers(&partitions)
}

fn root_disk(lsblk: &Executable, root_device: &str, remaining_millis: u64) -> Result<String> {
    let canonical = std::fs::canonicalize(root_device).context("resolving root device")?;
    let output = lsblk.run(
        &["-ndo", "PKNAME", "--", path_text(&canonical)?],
        remaining_millis,
    )?;
    ensure!(
        output.status.success(),
        "lsblk could not identify the root disk"
    );
    let parent = String::from_utf8(output.stdout)?;
    let parent = parent.trim();
    ensure!(
        !parent.is_empty()
            && parent
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "lsblk returned an invalid root-disk name"
    );
    Ok(format!("/dev/{parent}"))
}

fn collect_markers(device: &LsblkDevice, output: &mut Vec<MarkerPartition>) -> Result<()> {
    if device.device_type == "part"
        && let Some(label) = device.partlabel.as_deref()
        && matches!(label, PENDING_LABEL | OPERATOR_LABEL | FALLBACK_LABEL)
    {
        output.push(MarkerPartition {
            label: label.into(),
            partition_type: device
                .parttype
                .clone()
                .unwrap_or_default()
                .to_ascii_lowercase(),
            part_uuid: device
                .partuuid
                .clone()
                .unwrap_or_default()
                .to_ascii_lowercase(),
        });
    }
    for child in &device.children {
        collect_markers(child, output)?;
    }
    Ok(())
}

fn classify_markers(markers: &[MarkerPartition]) -> Result<ProvisioningMarkerObservation> {
    if markers.iter().any(|marker| marker.label == PENDING_LABEL) {
        return marker_observation(ProvisioningMarkerState::Pending, None, None);
    }
    let committed = markers
        .iter()
        .filter(|marker| matches!(marker.label.as_str(), OPERATOR_LABEL | FALLBACK_LABEL))
        .collect::<Vec<_>>();
    if committed.is_empty() {
        return marker_observation(ProvisioningMarkerState::Absent, None, None);
    }
    if committed.len() != 1 || committed[0].partition_type != MARKER_TYPE_GUID {
        return marker_observation(ProvisioningMarkerState::Indeterminate, None, None);
    }
    let marker = committed[0];
    let source = match marker.label.as_str() {
        OPERATOR_LABEL => CanonicalProvisioningSource::Operator,
        FALLBACK_LABEL => CanonicalProvisioningSource::Fallback,
        _ => return marker_observation(ProvisioningMarkerState::Indeterminate, None, None),
    };
    let marker_uuid = match normalize_marker_uuid(&marker.part_uuid) {
        Ok(uuid) if uuid == marker.part_uuid => uuid,
        _ => return marker_observation(ProvisioningMarkerState::Indeterminate, None, None),
    };
    marker_observation(
        ProvisioningMarkerState::Completed,
        Some(source),
        Some(marker_uuid),
    )
}

fn marker_observation(
    state: ProvisioningMarkerState,
    source: Option<CanonicalProvisioningSource>,
    marker_uuid: Option<String>,
) -> Result<ProvisioningMarkerObservation> {
    let observation = ProvisioningMarkerObservation {
        schema: OBSERVATION_SCHEMA.into(),
        state,
        source,
        marker_uuid,
    };
    validate_provisioning_marker_observation(&observation)?;
    Ok(observation)
}

fn validate_method(
    method: &str,
    semantics: &MethodSemantics,
    target: &ResourceReference,
) -> Result<()> {
    ensure!(method == "observe", "unsupported marker method");
    ensure!(
        *semantics == MethodSemantics::ordinary(AccessMode::Read),
        "marker method carries mismatched semantics"
    );
    ensure!(
        target
            .operations
            .binary_search(&LocalKey::new("observe")?)
            .is_ok(),
        "marker target does not authorize observation"
    );
    Ok(())
}

fn exact_context<'a>(
    reference: &ResourceReference,
    resources: &'a [ResourceContext],
) -> Result<&'a ResourceContext> {
    let matches = resources
        .iter()
        .filter(|context| context.reference == *reference)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "marker target has no exact unique runtime context"
    );
    Ok(matches[0])
}

fn evidence(state: &'static str) -> Result<AbilityValue> {
    ability_value(serde_json::to_value(MarkerEvidence {
        schema: EVIDENCE_SCHEMA,
        state,
    })?)
}

fn decode<T: serde::de::DeserializeOwned>(value: &AbilityValue) -> Result<T> {
    serde_json::from_value(value.as_json().clone()).context("decoding marker provider value")
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str().context("root-device path is not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(label: &str, partition_type: &str, part_uuid: &str) -> MarkerPartition {
        MarkerPartition {
            label: label.into(),
            partition_type: partition_type.into(),
            part_uuid: part_uuid.into(),
        }
    }

    #[test]
    fn pending_marker_always_requires_recovery() {
        let markers = vec![
            marker(PENDING_LABEL, MARKER_TYPE_GUID, ""),
            marker(
                OPERATOR_LABEL,
                MARKER_TYPE_GUID,
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            ),
        ];

        let observed = classify_markers(&markers).expect("typed pending observation");

        assert_eq!(observed.state, ProvisioningMarkerState::Pending);
        assert_eq!(observed.source, None);
        assert_eq!(observed.marker_uuid, None);
    }

    #[test]
    fn one_valid_committed_marker_carries_its_source_and_uuid() {
        let markers = vec![marker(
            FALLBACK_LABEL,
            MARKER_TYPE_GUID,
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        )];

        let observed = classify_markers(&markers).expect("typed completed observation");

        assert_eq!(observed.state, ProvisioningMarkerState::Completed);
        assert_eq!(observed.source, Some(CanonicalProvisioningSource::Fallback));
        assert_eq!(
            observed.marker_uuid.as_deref(),
            Some("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        );
    }

    #[test]
    fn conflicting_or_malformed_committed_markers_are_indeterminate() {
        let conflicting = vec![
            marker(
                OPERATOR_LABEL,
                MARKER_TYPE_GUID,
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            ),
            marker(
                FALLBACK_LABEL,
                MARKER_TYPE_GUID,
                "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
            ),
        ];
        assert_eq!(
            classify_markers(&conflicting)
                .expect("typed ambiguous observation")
                .state,
            ProvisioningMarkerState::Indeterminate
        );

        let malformed = vec![marker(
            OPERATOR_LABEL,
            "00000000-0000-0000-0000-000000000000",
            "not-a-uuid",
        )];
        assert_eq!(
            classify_markers(&malformed)
                .expect("typed malformed observation")
                .state,
            ProvisioningMarkerState::Indeterminate
        );
    }
}
