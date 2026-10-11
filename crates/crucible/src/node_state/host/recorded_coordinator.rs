//! Selected portable coordinator bytes for authenticated recorded Block custody.
//!
//! Edition five changes only provenance body encoding to unpadded URL-safe
//! base64. Exact full content references and decoded bodies remain unchanged.
//! Legacy coordinator editions retain their original serde representations.
//!
//! ```json
//! {"reference":{"hash":{}},"bytes":"AA"}
//! ```

use super::super::{StateError, schema};
use super::capture::Coordinator;
use crate::node_contract::{
    OperationFailure, OwnerIdentity, RuntimeSnapshot, SavedInputProvenance, SavedRuntimeActivation,
    SavedRuntimeInput, SavedRuntimeOperation, SavedRuntimeOwner, SavedWorldTerminal,
};
use crate::node_scheduling::event::Delivery;
use crate::node_scheduling::{InputPayload, NativeInputAcknowledgement, SchedulingSnapshot};
use crucible_node_contract::{Bytes, ContentRef, Id, Position, Repeatability, U64};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
#[serde(remote = "Coordinator", deny_unknown_fields)]
struct Legacy {
    #[serde(deserialize_with = "legacy_edition")]
    schema_version: u32,
    scheduler: SchedulingSnapshot,
    runtime: RuntimeSnapshot,
    world_repeatability: Repeatability,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Coordinator", deny_unknown_fields)]
struct Portable {
    #[serde(deserialize_with = "portable_edition")]
    schema_version: u32,
    scheduler: SchedulingSnapshot,
    #[serde(with = "Runtime")]
    runtime: RuntimeSnapshot,
    world_repeatability: Repeatability,
}

impl Serialize for Coordinator {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.schema_version == 6 {
            super::condition_coordinator::serialize(self, serializer)
        } else if self.schema_version == 5 {
            Portable::serialize(self, serializer)
        } else {
            Legacy::serialize(self, serializer)
        }
    }
}

#[cfg(test)]
#[derive(Deserialize)]
#[serde(untagged)]
enum Selected {
    Portable(#[serde(with = "Portable")] Coordinator),
    Legacy(#[serde(with = "Legacy")] Coordinator),
}

#[cfg(test)]
impl<'de> Deserialize<'de> for Coordinator {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Selected::deserialize(deserializer)? {
            Selected::Portable(value) | Selected::Legacy(value) => Ok(value),
        }
    }
}

// This scalar header skips other values without building a serde Content tree.
// The selected closed decoder still authenticates the complete original grammar.
#[derive(Deserialize)]
struct EditionHeader {
    schema_version: u32,
}

/// Decodes bounded coordinator bytes with the original edition-specific grammar.
///
/// The runtime probe refuses unsupported condition custody before either branch
/// constructs input indexes. Direct branch dispatch avoids an additional whole
/// numeric-body buffer for accepted legacy records. Archive byte and aggregate
/// ceilings remain the caller's responsibility; this parser grants no authority.
///
/// # Errors
/// Refuses unsupported editions, malformed closed records, or trailing input.
pub(super) fn decode(bytes: &[u8]) -> Result<Coordinator, StateError> {
    let header: EditionHeader = super::runtime_header::decode_supported_coordinator(bytes)?;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let coordinator = match header.schema_version {
        1..=3 => Legacy::deserialize(&mut decoder),
        5 => Portable::deserialize(&mut decoder),
        _ => return Err(schema("unsupported host coordinator edition")),
    }
    .map_err(schema)?;
    decoder.end().map_err(schema)?;

    Ok(coordinator)
}

fn legacy_edition<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let value = u32::deserialize(deserializer)?;
    if matches!(value, 1..=3) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "legacy coordinator edition differs",
        ))
    }
}

fn portable_edition<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let value = u32::deserialize(deserializer)?;
    if value == 5 {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "portable coordinator edition differs",
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "RuntimeSnapshot", deny_unknown_fields)]
struct Runtime {
    #[serde(deserialize_with = "recorded_runtime_edition")]
    schema_version: u16,
    source_activation: SavedRuntimeActivation,
    capture_cut: Position,
    capture_ordinal: U64,
    owners: Vec<SavedRuntimeOwner>,
    operations: Vec<SavedRuntimeOperation>,
    #[serde(with = "inputs")]
    inputs: Vec<SavedRuntimeInput>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "absent_scope"
    )]
    terminal: Option<SavedWorldTerminal>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "absent_scope"
    )]
    condition_stop: Option<crate::node_contract::SavedConditionStop>,
}

fn recorded_runtime_edition<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
    let edition = u16::deserialize(deserializer)?;
    if edition == 2 {
        Ok(edition)
    } else {
        Err(serde::de::Error::custom(
            "portable recorded coordinator requires runtime two",
        ))
    }
}

fn absent_scope<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
{
    if Option::<serde::de::IgnoredAny>::deserialize(deserializer)?.is_some() {
        Err(serde::de::Error::custom(
            "portable recorded coordinator excludes terminal and condition custody",
        ))
    } else {
        Ok(None)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "SavedRuntimeInput", deny_unknown_fields)]
struct Input {
    node: Id,
    stage_operation: Id,
    batch: Id,
    owners: Vec<OwnerIdentity>,
    cutoff: Position,
    inventory: ContentRef,
    deliveries: Vec<Delivery>,
    payloads: Vec<InputPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "provenance")]
    provenance: Option<SavedInputProvenance>,
    #[serde(deserialize_with = "required_nullable")]
    acknowledgement: Option<NativeInputAcknowledgement>,
    #[serde(deserialize_with = "required_nullable")]
    failure: Option<OperationFailure>,
    committed: bool,
    coordinator_committed: bool,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "SavedInputProvenance", deny_unknown_fields)]
struct Provenance {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    node: Id,
    stage_operation: Id,
    batch: Id,
    inventory: ContentRef,
    roots: Vec<ContentRef>,
    #[serde(with = "objects")]
    objects: Vec<InputPayload>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableObject {
    reference: ContentRef,
    bytes: Bytes,
}

mod inputs {
    use super::*;

    #[derive(Serialize)]
    struct Borrowed<'a>(#[serde(with = "Input")] &'a SavedRuntimeInput);

    #[derive(Deserialize)]
    struct Owned(#[serde(with = "Input")] SavedRuntimeInput);

    pub(super) fn serialize<S: Serializer>(
        items: &[SavedRuntimeInput],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(items.len()))?;
        for item in items {
            sequence.serialize_element(&Borrowed(item))?;
        }
        sequence.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<SavedRuntimeInput>, D::Error> {
        Vec::<Owned>::deserialize(deserializer)
            .map(|items| items.into_iter().map(|item| item.0).collect())
    }
}

mod provenance {
    use super::*;

    #[derive(Serialize)]
    struct Borrowed<'a>(#[serde(with = "Provenance")] &'a SavedInputProvenance);

    #[derive(Deserialize)]
    struct Owned(#[serde(with = "Provenance")] SavedInputProvenance);

    pub(super) fn serialize<S: Serializer>(
        item: &Option<SavedInputProvenance>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        item.as_ref().map(Borrowed).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SavedInputProvenance>, D::Error> {
        Option::<Owned>::deserialize(deserializer).map(|item| item.map(|item| item.0))
    }
}

mod objects {
    use super::*;

    pub(super) fn serialize<S: Serializer>(
        items: &[InputPayload],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(items.len()))?;
        for item in items {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(item.bytes.len())
                .map_err(serde::ser::Error::custom)?;
            bytes.extend_from_slice(&item.bytes);
            sequence.serialize_element(&PortableObject {
                reference: item.reference.clone(),
                bytes: Bytes::new(bytes),
            })?;
        }
        sequence.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<InputPayload>, D::Error> {
        Vec::<PortableObject>::deserialize(deserializer).map(|items| {
            items
                .into_iter()
                .map(|item| InputPayload {
                    reference: item.reference,
                    bytes: item.bytes.into_vec(),
                })
                .collect()
        })
    }
}

#[cfg(test)]
#[path = "recorded_coordinator_tests.rs"]
mod tests;
