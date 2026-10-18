//! Edition-specific authenticated index grammar with exact typed role adjacency.
//!
//! Edition one retains its original outer `objects` field. Edition two requires
//! `typed_inventory` and an explicitly nullable selected-extension root. The
//! Edition three requires a separate original administrative capture journal.
//! It retains typed inventory two without admitting that edition through legacy
//! transcript restoration. The
//! byte store remains digest-addressed; typed rows authorize metadata roles and
//! their individual dependency inventories without retagging original objects.
//!
//! ```json
//! {"schema_version":2,"artifact":{},"typed_inventory":{"schema_version":2,"objects":[]},"owners":[],"selected_extensions":null}
//! ```

use crucible_node_contract::ContentRef;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::storage::{Index, NativeOwnerState, Object, pages};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyIndex {
    schema_version: u16,
    artifact: ContentRef,
    #[serde(with = "pages")]
    objects: Vec<Object>,
    owners: Vec<NativeOwnerState>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypedInventory {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    #[serde(with = "pages")]
    objects: Vec<Object>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypedIndex {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    artifact: ContentRef,
    typed_inventory: TypedInventory,
    owners: Vec<NativeOwnerState>,
    #[serde(deserialize_with = "required_nullable")]
    selected_extensions: Option<ContentRef>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteOriginalIndex {
    #[serde(deserialize_with = "crucible_node_contract::deserialize_version")]
    schema_version: u16,
    artifact: ContentRef,
    typed_inventory: TypedInventory,
    owners: Vec<NativeOwnerState>,
    original_capture_journal: ContentRef,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WireIndex {
    CompleteOriginal(CompleteOriginalIndex),
    Legacy(LegacyIndex),
    Typed(TypedIndex),
}

fn required_nullable<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ContentRef>, D::Error> {
    Option::<ContentRef>::deserialize(deserializer)
}

#[derive(Serialize)]
struct LegacyIndexRef<'a> {
    schema_version: u16,
    artifact: &'a ContentRef,
    #[serde(with = "pages")]
    objects: &'a [Object],
    owners: &'a [NativeOwnerState],
}

#[derive(Serialize)]
struct TypedInventoryRef<'a> {
    schema_version: u16,
    #[serde(with = "pages")]
    objects: &'a [Object],
}

#[derive(Serialize)]
struct TypedIndexRef<'a> {
    schema_version: u16,
    artifact: &'a ContentRef,
    typed_inventory: TypedInventoryRef<'a>,
    owners: &'a [NativeOwnerState],
    selected_extensions: &'a Option<ContentRef>,
}

#[derive(Serialize)]
struct CompleteOriginalIndexRef<'a> {
    schema_version: u16,
    artifact: &'a ContentRef,
    typed_inventory: TypedInventoryRef<'a>,
    owners: &'a [NativeOwnerState],
    original_capture_journal: &'a ContentRef,
}

impl Serialize for Index {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.schema_version {
            1 if self.selected_extensions.is_none() && self.original_capture_journal.is_none() => {
                LegacyIndexRef {
                    schema_version: 1,
                    artifact: &self.artifact,
                    objects: &self.objects,
                    owners: &self.owners,
                }
                .serialize(serializer)
            }
            2 if self.original_capture_journal.is_none() => TypedIndexRef {
                schema_version: 2,
                artifact: &self.artifact,
                typed_inventory: TypedInventoryRef {
                    schema_version: 2,
                    objects: &self.objects,
                },
                owners: &self.owners,
                selected_extensions: &self.selected_extensions,
            }
            .serialize(serializer),
            3 if self.selected_extensions.is_none() => {
                let journal = self.original_capture_journal.as_ref().ok_or_else(|| {
                    serde::ser::Error::custom(
                        "complete original index lacks administrative journal",
                    )
                })?;
                CompleteOriginalIndexRef {
                    schema_version: 3,
                    artifact: &self.artifact,
                    typed_inventory: TypedInventoryRef {
                        schema_version: 2,
                        objects: &self.objects,
                    },
                    owners: &self.owners,
                    original_capture_journal: journal,
                }
                .serialize(serializer)
            }
            _ => Err(serde::ser::Error::custom(
                "unsupported native index edition or legacy extension",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for Index {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match WireIndex::deserialize(deserializer)? {
            WireIndex::Legacy(wire) if wire.schema_version == 1 => Ok(Self {
                schema_version: 1,
                artifact: wire.artifact,
                objects: wire.objects,
                owners: wire.owners,
                selected_extensions: None,
                original_capture_journal: None,
            }),
            WireIndex::Typed(wire)
                if wire.schema_version == 2 && wire.typed_inventory.schema_version == 2 =>
            {
                Ok(Self {
                    schema_version: 2,
                    artifact: wire.artifact,
                    objects: wire.typed_inventory.objects,
                    owners: wire.owners,
                    selected_extensions: wire.selected_extensions,
                    original_capture_journal: None,
                })
            }
            WireIndex::CompleteOriginal(wire)
                if wire.schema_version == 3 && wire.typed_inventory.schema_version == 2 =>
            {
                Ok(Self {
                    schema_version: 3,
                    artifact: wire.artifact,
                    objects: wire.typed_inventory.objects,
                    owners: wire.owners,
                    selected_extensions: None,
                    original_capture_journal: Some(wire.original_capture_journal),
                })
            }
            _ => Err(serde::de::Error::custom(
                "unsupported native index or typed inventory edition",
            )),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteEnvelope {
    body: CompleteOriginalIndex,
    authentication: [u8; 32],
}

/// Decodes the selected edition directly, without allocating legacy retry trees.
pub(super) fn decode_complete_envelope(
    value: serde_json::Value,
) -> Result<(Index, [u8; 32]), super::StateError> {
    let wire: CompleteEnvelope = serde_json::from_value(value).map_err(super::super::schema)?;
    if wire.body.schema_version != 3 || wire.body.typed_inventory.schema_version != 2 {
        return Err(super::refused(
            "complete loader requires index three/inventory two",
        ));
    }
    Ok((
        Index {
            schema_version: 3,
            artifact: wire.body.artifact,
            objects: wire.body.typed_inventory.objects,
            owners: wire.body.owners,
            selected_extensions: None,
            original_capture_journal: Some(wire.body.original_capture_journal),
        },
        wire.authentication,
    ))
}

/// Decodes only an immutable complete Index3 body, without an archive receipt.
///
/// The caller independently admits the retained DOM, typed owner and validation
/// work. Reachability under its genuine signed closure supplies provenance; this
/// operation deliberately issues no local-load admission or live target.
pub(super) fn decode_complete_body_data(
    value: &serde_json::Value,
) -> Result<Index, super::StateError> {
    let wire = CompleteOriginalIndex::deserialize(value).map_err(super::super::schema)?;
    if wire.schema_version != 3 || wire.typed_inventory.schema_version != 2 {
        return Err(super::refused(
            "historical parent requires Index3/inventory2",
        ));
    }
    Ok(Index {
        schema_version: 3,
        artifact: wire.artifact,
        objects: wire.typed_inventory.objects,
        owners: wire.owners,
        selected_extensions: None,
        original_capture_journal: Some(wire.original_capture_journal),
    })
}
