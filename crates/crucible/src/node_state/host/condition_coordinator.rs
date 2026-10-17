//! Explicit source-selected stopped-condition coordinator grammar.
//!
//! Edition six retains the unchanged original condition Runtime6 body indexes
//! and exact Scheduler4 FIFO/ACK context. Selection alone grants no authority;
//! the signed archive and installed whole-world native factory remain required.
//! Legacy readers preserve their early Runtime6 refusal and original grammars.
//!
//! ```text
//! {"schema_version":6,"scheduler":{"schema_version":4,...},
//!  "runtime":{"schema_version":6,...},"world_repeatability":"deterministic"}
//! ```

use super::super::{StateError, schema};
use super::capture::Coordinator;
use crate::node_contract::RuntimeSnapshot;
use crate::node_scheduling::SchedulingSnapshot;
use crucible_node_contract::{CaptureManifest, Repeatability};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
#[serde(remote = "Coordinator", deny_unknown_fields)]
struct Selected {
    #[serde(deserialize_with = "edition")]
    schema_version: u32,
    scheduler: SchedulingSnapshot,
    #[serde(deserialize_with = "RuntimeSnapshot::deserialize_condition")]
    runtime: RuntimeSnapshot,
    world_repeatability: Repeatability,
}

#[derive(Deserialize)]
struct Header {
    schema_version: u32,
    scheduler: Version,
    runtime: Version,
}

#[derive(Deserialize)]
struct Version {
    schema_version: u16,
}

pub(super) fn selected_manifest(manifest: &CaptureManifest) -> bool {
    !manifest.owners.is_empty()
        && manifest.owners.iter().all(|owner| {
            owner.state_schema.id.as_str() == "host/native-condition-continuation-v1"
                && owner.state_schema.version == 1
        })
}

pub(super) fn serialize<S: Serializer>(
    coordinator: &Coordinator,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if coordinator.schema_version != 6
        || coordinator.scheduler.schema_version != 4
        || coordinator.runtime.schema_version != 6
    {
        return Err(serde::ser::Error::custom(
            "condition coordinator requires scheduler4/runtime6",
        ));
    }
    Selected::serialize(coordinator, serializer)
}

pub(super) fn decode_selected(
    bytes: &[u8],
    manifest: &CaptureManifest,
) -> Result<Coordinator, StateError> {
    if !selected_manifest(manifest) {
        return super::recorded_coordinator::decode(bytes);
    }
    let header: Header = serde_json::from_slice(bytes).map_err(schema)?;
    if header.schema_version != 6
        || header.scheduler.schema_version != 4
        || header.runtime.schema_version != 6
    {
        return Err(schema(
            "selected condition coordinator requires scheduler4/runtime6",
        ));
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let coordinator = Selected::deserialize(&mut decoder).map_err(schema)?;
    decoder.end().map_err(schema)?;
    if coordinator.runtime.terminal.is_some()
        || coordinator.runtime.condition_stop.is_none()
        || coordinator.scheduler.original_epochs.is_some()
    {
        return Err(schema(
            "selected condition coordinator contains unsupported mixed custody",
        ));
    }
    Ok(coordinator)
}

fn edition<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    match u32::deserialize(deserializer)? {
        6 => Ok(6),
        _ => Err(serde::de::Error::custom(
            "condition coordinator edition differs",
        )),
    }
}
