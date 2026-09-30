//! Native typed observation of the selected root disk's durable GPT marker.

use crate::process::run_native;
use anyhow::{Context as _, Result, ensure};
use aos_ability_runtime::activation::{Action, Invocation};
use aos_storage_provisioning::{
    CanonicalProvisioningSource, ProvisioningMarkerObservation, ProvisioningMarkerState,
    normalize_marker_uuid, validate_provisioning_marker_observation,
};
use serde::Deserialize;
use serde_json::json;
use std::path::{Component, Path, PathBuf};

const OBSERVATION_SCHEMA: &str = "aos.storage.provisioning-marker-observation/v1";
const PENDING_LABEL: &str = "aos-provisioning-pending-v1";
const OPERATOR_LABEL: &str = "aos-provenance-operator-v1";
const FALLBACK_LABEL: &str = "aos-provenance-fallback-v1";
const MARKER_TYPE_GUID: &str = "163bea60-58c7-46e7-b69a-6846a5a688af";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    root_device: String,
    lsblk: PathBuf,
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

/// Executes a fresh native GPT marker observation.
///
/// # Errors
/// Returns an error for invalid device paths, failed immutable inspection tools,
/// malformed block-device output, or conflicting marker evidence.
pub fn handle(action: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let invocation: Invocation = serde_json::from_slice(bytes)?;
    ensure!(
        matches!(action, "apply" | "remove" | "observe"),
        "unsupported marker action"
    );
    ensure!(
        action == "observe"
            || matches!(
                (action, invocation.action),
                ("apply", Action::Apply) | ("remove", Action::Remove)
            ),
        "action differs from invocation"
    );
    let input: Input = serde_json::from_value(invocation.input)?;
    let path = Path::new(&input.root_device);
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "marker root device is not normalized absolute path"
    );
    let result = match action {
        "remove" => json!({}),
        "observe" => {
            json!({"status":if invocation.action==Action::Remove {"absent"}else{"retry-safe"}})
        }
        _ => {
            json!({"marker":observe_marker(&input.lsblk,&input.root_device,invocation.effect.timeout_ms)?})
        }
    };
    Ok(serde_json::to_vec(&result)?)
}

fn observe_marker(
    lsblk: &Path,
    root_device: &str,
    remaining_millis: u64,
) -> Result<ProvisioningMarkerObservation> {
    let root_disk = root_disk(lsblk, root_device, remaining_millis)?;
    let output = run_native(
        lsblk,
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

fn root_disk(lsblk: &Path, root_device: &str, remaining_millis: u64) -> Result<String> {
    let canonical = std::fs::canonicalize(root_device).context("resolving root device")?;
    let output = run_native(
        lsblk,
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
