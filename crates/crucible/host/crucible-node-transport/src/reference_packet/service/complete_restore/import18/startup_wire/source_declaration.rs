//! Binds unchanged pre-report Source birth fields to their actual launch.
//!
//! ```text
//! {schema:"source-owned.packet-native-import-source-declaration/18",
//!  source_birth:<Bytes of unchanged canonical pre-report SourceBirth6..12 JSON>,
//!  fresh_restore_allocation_selection:<same Launch5 option or null>}
//! ```
//!
//! This declaration contains no report or native startup allocation. The real
//! initial/full recipe producers own every new18 phase allocation independently.
//! Matching DATA does not create a Source purpose, private Birth or native grant.

use super::*;
use crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection;
use crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection;
use serde::ser::SerializeStruct;

#[path = "source_declaration/projection.rs"]
mod projection;

#[path = "source_declaration/decoder_partials.rs"]
mod decoder_partials;

pub use projection::{
    native_import18_source_declaration_encoding_construction_data,
    native_import18_source_declaration_encoding_counter_scratch_data,
};

pub(in crate::reference_packet) use projection::{
    native_import18_source_declaration_formatter_requested_data,
    native_import18_source_declaration_projection_counter_scratch_data,
    native_import18_source_declaration_projection_data,
    native_import18_source_declaration_serialization_data,
};

/// Identifies the closed new declaration independently of its Source wrapper.
pub const NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA: &str =
    "source-owned.packet-native-import-source-declaration/18";

#[derive(Serialize, Deserialize)]
enum DeclarationSchema {
    #[serde(rename = "source-owned.packet-native-import-source-declaration/18")]
    Import18,
}

/// Borrows the unchanged Source birth and the one additional launch selection.
///
/// The checked constructor validates a borrowed pre-report Value roster. A
/// separate bank serializer lets a genuine isolated producer lend its original
/// bytes without parsing. Native raw-bank correspondence and whole semantic
/// validation retain their independently funded checks; this view issues no row.
#[derive(Clone, Copy, Serialize)]
pub struct PacketNativeImport18SourceDeclarationView<'a> {
    schema: &'static str,
    #[serde(serialize_with = "serialize_source_birth")]
    source_birth: &'a [u8],
    fresh_restore_allocation_selection: Option<PacketNative5FreshRestoreAllocationSelection>,
}

// Use the defining Bytes codec over the original bank without cloning a Vec.
fn serialize_source_birth<S: Serializer>(
    source_birth: &&[u8],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    Bytes::borrowed_serialization_data(source_birth).serialize(serializer)
}

/// Retains the exact declaration without recreating a live Source or Birth.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18SourceDeclarationWireData {
    schema: DeclarationSchema,
    source_birth: Bytes,
    #[serde(deserialize_with = "required_fresh")]
    fresh_restore_allocation_selection: Option<PacketNative5FreshRestoreAllocationSelection>,
}

// The explicit deserialize hook has no default. A present null remains valid,
// while a missing required nullable field is rejected by the derived visitor.
fn required_fresh<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PacketNative5FreshRestoreAllocationSelection>, D::Error> {
    Option::deserialize(deserializer)
}

impl Serialize for PacketNativeImport18SourceDeclarationWireData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("SourceDeclaration18", 3)?;
        fields.serialize_field("schema", &self.schema)?;
        fields.serialize_field("source_birth", &self.source_birth)?;
        fields.serialize_field(
            "fresh_restore_allocation_selection",
            &self.fresh_restore_allocation_selection,
        )?;
        fields.end()
    }
}

/// Borrows a genuine pre-report Source birth without copying or merging its DOM.
///
/// Actual immutable Source/Birth/launch guards precede this helper. Its roster
/// check allocates nothing. Callers quote and admit the real view's serializer,
/// Value constructor, base64 formatter bank and canonical encoder separately
/// before invoking them. No existing body ceiling is enlarged by this encoding.
///
/// The raw bank and parsed Value come from the same genuine BodyPlan producer;
/// this helper does not reparse or establish that custody.
///
/// # Errors
/// Refuses another launch edition, old startup/report rows or altered Source
/// birth fields/schema. Full semantic field equality is a separate operation.
pub fn native_import18_source_declaration_wire_data<'a>(
    source_birth: &'a Bytes,
    parsed_source_birth: &Value,
    launch: &PacketNative5SourceLaunch,
) -> Result<PacketNativeImport18SourceDeclarationView<'a>, ProviderError> {
    if launch.schema_version != 5 {
        return Err(invalid());
    }
    if source_birth.as_slice().is_empty() {
        return Err(invalid());
    }
    source_birth_roster(parsed_source_birth)?;
    Ok(PacketNativeImport18SourceDeclarationView {
        schema: NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA,
        source_birth: source_birth.as_slice(),
        fresh_restore_allocation_selection: launch.fresh_restore_allocation_selection,
    })
}

/// Borrows a pre-report bank for serialization without parsing or validating it.
///
/// The isolated Source producer authenticates its original accepted completion,
/// unchanged launch and private Birth before lending this DATA view. This helper
/// checks only the launch edition and nonempty bank; it cannot establish that
/// provenance or validate any Source fields. The native wire reader still checks
/// the complete pre-report roster and semantic correspondence independently.
/// Serializer, formatter and output construction require separate admission.
///
/// # Errors
/// Refuses an empty bank or a launch edition other than five.
pub fn native_import18_source_declaration_bank_view_data<'a>(
    source_birth: &'a [u8],
    launch: &PacketNative5SourceLaunch,
) -> Result<PacketNativeImport18SourceDeclarationView<'a>, ProviderError> {
    if launch.schema_version != 5 || source_birth.is_empty() {
        return Err(invalid());
    }
    Ok(PacketNativeImport18SourceDeclarationView {
        schema: NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA,
        source_birth,
        fresh_restore_allocation_selection: launch.fresh_restore_allocation_selection,
    })
}

impl PacketNativeImport18SourceDeclarationWireData {
    /// Observes the actual declaration backing without parsing its opaque bank.
    ///
    /// # Errors
    /// Refuses checked capacity or population overflow.
    pub(super) fn observe_backing_data(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            source_birth,
            fresh_restore_allocation_selection,
        } = self;
        const {
            assert!(!std::mem::needs_drop::<(
                DeclarationSchema,
                Option<PacketNative5FreshRestoreAllocationSelection>
            )>());
        }
        let _ = (schema, fresh_restore_allocation_selection);
        observer.observe(source_birth)
    }

    /// Borrows the exact original canonical pre-report Source birth bytes.
    pub fn source_birth_data(&self) -> &Bytes {
        &self.source_birth
    }

    /// Checks every original Source field against the same complete actual launch.
    ///
    /// The manual parser retains a temporary complete original Source DOM. Each
    /// typed-to-Value comparison constructs another temporary DOM and drops it
    /// before the next field. The coordinator canonical output is a separate
    /// temporary bank. Callers must admit these actual serializer/DOM/JCS/parser
    /// and formatter windows independently; the fixed counter below is only its
    /// direct controls. No launch factory or live Source authority is inferred.
    ///
    /// # Errors
    /// Refuses changed or missing fields, a different selected branch or complete
    /// coordinator bytes, another launch edition or changed fresh selection.
    pub fn authenticate_launch_data(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), ProviderError> {
        // The defining manual parser preserves literal RawValue-looking maps
        // and applies the original source's depth bound without wrapper layers.
        let source_birth = canonical::parse_json(
            self.source_birth.as_slice(),
            self.source_birth.as_slice().len(),
        )?;
        source_birth_roster(&source_birth)?;
        let canonical_source = canonical::canonical_json(&source_birth)?;
        if canonical_source.as_slice() != self.source_birth.as_slice() {
            return Err(invalid());
        }
        drop(canonical_source);
        if launch.schema_version != 5
            || self.fresh_restore_allocation_selection != launch.fresh_restore_allocation_selection
            || source_birth.get("schema").and_then(Value::as_str) != Some(expected_schema(launch))
        {
            return Err(invalid());
        }

        equal(&source_birth, "selection", &launch.selection)?;
        equal(&source_birth, "program", &launch.program)?;
        equal(&source_birth, "limits", &launch.limits)?;
        equal(&source_birth, "storage", &launch.storage)?;
        equal(&source_birth, "capture_profile", &launch.capture_profile)?;
        equal(
            &source_birth,
            "confirmation_selection",
            &launch.confirmation_selection,
        )?;
        equal(
            &source_birth,
            "ack_emitter_selection",
            &launch.ack_emitter_selection,
        )?;
        equal(
            &source_birth,
            "codec_metadata_extent",
            &crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB,
        )?;

        let capture = launch.capture_allocation_selection.is_some();
        optional(
            &source_birth,
            "native_codec_metadata_extent",
            &launch.native_codec_metadata_extent,
            capture,
        )?;
        optional(
            &source_birth,
            "protocol_metadata_limits",
            &launch.protocol_metadata_limits,
            capture,
        )?;
        optional(
            &source_birth,
            "complete_restore_selection",
            &launch.complete_restore_selection,
            capture,
        )?;
        optional(
            &source_birth,
            "restore_input_emitter_selection",
            &launch.restore_input_emitter_selection,
            capture,
        )?;
        optional(
            &source_birth,
            "capture_allocation_selection",
            &launch.capture_allocation_selection,
            false,
        )?;

        let coordinator = source_birth.get("coordinator").ok_or_else(invalid)?;
        let canonical = canonical::canonical_json(coordinator)?;
        if canonical.as_slice() != launch.initial_coordinator.bytes.as_slice() {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn authenticate_value_data(&self, expected: &Value) -> Result<(), ProviderError> {
        declaration_roster(expected)?;
        equal(expected, "source_birth", &self.source_birth)?;
        let expected_fresh = expected
            .get("fresh_restore_allocation_selection")
            .ok_or_else(invalid)?;
        let actual = serde_json::to_value(self.fresh_restore_allocation_selection)
            .map_err(ContractError::from)?;
        if expected_fresh != &actual {
            return Err(invalid());
        }
        Ok(())
    }
}

fn equal<T: Serialize>(source: &Value, key: &str, expected: &T) -> Result<(), ProviderError> {
    let actual = source.get(key).ok_or_else(invalid)?;
    let expected = serde_json::to_value(expected).map_err(ContractError::from)?;
    if actual != &expected {
        return Err(invalid());
    }
    Ok(())
}

fn optional<T: Serialize>(
    source: &Value,
    key: &str,
    expected: &Option<T>,
    required: bool,
) -> Result<(), ProviderError> {
    match expected {
        Some(value) => equal(source, key, value),
        None if required => equal(source, key, &()),
        None if source.get(key).is_none() => Ok(()),
        None => Err(invalid()),
    }
}

fn expected_schema(launch: &PacketNative5SourceLaunch) -> &'static str {
    if launch.capture_allocation_selection.is_some() {
        SOURCE_SCHEMAS[6]
    } else if launch.restore_input_emitter_selection.is_some() {
        SOURCE_SCHEMAS[5]
    } else if launch.complete_restore_selection
        == Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
    {
        SOURCE_SCHEMAS[4]
    } else if launch.complete_restore_selection.is_some() {
        SOURCE_SCHEMAS[3]
    } else if launch.protocol_metadata_limits.is_some() {
        SOURCE_SCHEMAS[2]
    } else if launch.native_codec_metadata_extent.is_some() {
        SOURCE_SCHEMAS[1]
    } else {
        SOURCE_SCHEMAS[0]
    }
}

const SOURCE_SCHEMAS: [&str; 7] = [
    "source-owned.packet-canonical-ack-source-binding/6",
    "source-owned.packet-canonical-ack-source-binding/7",
    "source-owned.packet-canonical-ack-source-binding/8",
    "source-owned.packet-canonical-ack-source-binding/9",
    "source-owned.packet-canonical-ack-source-binding/10",
    "source-owned.packet-canonical-ack-source-binding/11",
    "source-owned.packet-canonical-ack-source-binding/12",
];
const BASE: [&str; 10] = [
    "schema",
    "selection",
    "program",
    "coordinator",
    "limits",
    "storage",
    "capture_profile",
    "confirmation_selection",
    "ack_emitter_selection",
    "codec_metadata_extent",
];
const EXTRA: [&str; 5] = [
    "native_codec_metadata_extent",
    "protocol_metadata_limits",
    "complete_restore_selection",
    "restore_input_emitter_selection",
    "capture_allocation_selection",
];

fn source_birth_roster(source: &Value) -> Result<(), ProviderError> {
    let object = source.as_object().ok_or_else(invalid)?;
    let schema = object
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let branch = SOURCE_SCHEMAS
        .iter()
        .position(|candidate| *candidate == schema)
        .ok_or_else(invalid)?;
    let extra = match branch {
        0 => 0,
        1 => 1,
        2 => 2,
        3 | 4 => 3,
        5 => 4,
        6 => 5,
        _ => return Err(invalid()),
    };
    if object.len() != BASE.len() + extra
        || BASE.iter().any(|key| !object.contains_key(*key))
        || EXTRA[..extra].iter().any(|key| !object.contains_key(*key))
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn declaration_roster(value: &Value) -> Result<(), ProviderError> {
    exact_object(
        value,
        &[
            "schema",
            "source_birth",
            "fresh_restore_allocation_selection",
        ],
        NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA,
    )?;
    if value.get("source_birth").and_then(Value::as_str).is_none() {
        return Err(invalid());
    }
    Ok(())
}

/// Names direct declaration view, branch, comparison and returned DOM headers.
///
/// Recursive serde/JCS/parser controls, real nested Value backing, canonical
/// output and each actual custom formatter are separately admitted by callers.
pub fn native_import18_source_declaration_counter_scratch_data() -> usize {
    size_of::<PacketNativeImport18SourceDeclarationView<'static>>()
        + size_of::<Result<PacketNativeImport18SourceDeclarationView<'static>, ProviderError>>()
        + size_of::<&PacketNativeImport18SourceDeclarationWireData>()
        + size_of::<&[u8]>()
        + size_of::<&&[u8]>()
        + Bytes::borrowed_serialization_counter_scratch_data()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&Value>() * 4
        + size_of::<Bytes>()
        + size_of::<Result<Bytes, serde_json::Error>>()
        + size_of::<Value>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<Vec<u8>, ContractError>>()
        + size_of::<&serde_json::Map<String, Value>>()
        + size_of::<Option<&serde_json::Map<String, Value>>>()
        + size_of::<DeclarationSchema>()
        + size_of::<Result<Option<PacketNative5FreshRestoreAllocationSelection>, serde_json::Error>>(
        )
        + size_of::<Option<&Value>>()
        + size_of::<Option<&str>>()
        + size_of::<&str>() * 3
        + size_of::<&&str>()
        + size_of::<&[&str]>()
        + size_of::<[&str; 10]>()
        + size_of::<[&str; 5]>()
        + size_of::<[&str; 7]>()
        + size_of::<[&str; 3]>()
        + size_of::<std::slice::Iter<'static, &'static str>>() * 3
        + size_of::<Option<usize>>()
        + size_of::<usize>() * 3
        + size_of::<Option<PacketNative5FreshRestoreAllocationSelection>>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(branch: usize) -> Value {
        let mut object = serde_json::Map::new();
        for key in BASE {
            object.insert(key.to_owned(), Value::Null);
        }
        let extra = match branch {
            0 => 0,
            1 => 1,
            2 => 2,
            3 | 4 => 3,
            5 => 4,
            _ => 5,
        };
        for key in &EXTRA[..extra] {
            object.insert((*key).to_owned(), Value::Null);
        }
        object.insert(
            "schema".to_owned(),
            Value::String(SOURCE_SCHEMAS[branch].to_owned()),
        );
        Value::Object(object)
    }

    #[test]
    fn pre_report_rosters_refuse_both_old_allocation_fields() {
        for branch in 0..7 {
            let original = source(branch);
            source_birth_roster(&original).unwrap();
            for key in [
                "report_startup_allocation",
                "native_startup_allocation",
                "fresh_restore_allocation_selection",
            ] {
                let mut altered = original.clone();
                altered[key] = Value::Null;
                assert!(source_birth_roster(&altered).is_err());
            }
        }
    }

    #[test]
    fn explicit_null_fresh_field_is_required_and_source_is_unchanged() {
        let original = source(6);
        let value = serde_json::json!({"schema":NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA,"source_birth":Bytes::new(canonical::canonical_json(&original).unwrap()),"fresh_restore_allocation_selection":null});
        let parsed: PacketNativeImport18SourceDeclarationWireData =
            serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            canonical::parse_json(parsed.source_birth_data().as_slice(), usize::MAX).unwrap(),
            original
        );
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
        let mut missing = value.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("fresh_restore_allocation_selection");
        assert!(
            serde_json::from_value::<PacketNativeImport18SourceDeclarationWireData>(missing)
                .is_err()
        );
        let mut extra = value;
        extra["native_startup_allocation"] = Value::Null;
        assert!(
            serde_json::from_value::<PacketNativeImport18SourceDeclarationWireData>(extra).is_err()
        );
    }

    #[test]
    fn raw_leaf_preserves_rawvalue_looking_maps_and_original_depth() {
        let literal = serde_json::json!({"$serde_json::private::RawValue":"{\"changed\":true}"});
        let mut original = source(6);
        original["selection"] = literal.clone();
        let raw = Bytes::new(canonical::canonical_json(&original).unwrap());
        let view = PacketNativeImport18SourceDeclarationView {
            schema: NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA,
            source_birth: raw.as_slice(),
            fresh_restore_allocation_selection: None,
        };
        let encoded = serde_json::to_vec(&view).unwrap();
        let parsed: PacketNativeImport18SourceDeclarationWireData =
            serde_json::from_slice(&encoded).unwrap();
        assert_eq!(parsed.source_birth_data(), &raw);
        let decoded =
            canonical::parse_json(parsed.source_birth_data().as_slice(), usize::MAX).unwrap();
        assert_eq!(decoded["selection"], literal);

        // The raw leaf adds no JSON containers around the original parser's
        // accepted terminal scalar at the full sixty-four-container boundary.
        let deep = format!("{}0{}", "[".repeat(64), "]".repeat(64));
        canonical::parse_json(deep.as_bytes(), usize::MAX).unwrap();
        let raw = Bytes::new(deep.as_bytes().to_vec());
        let view = PacketNativeImport18SourceDeclarationView {
            schema: NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA,
            source_birth: raw.as_slice(),
            fresh_restore_allocation_selection: None,
        };
        let parsed: PacketNativeImport18SourceDeclarationWireData =
            serde_json::from_slice(&serde_json::to_vec(&view).unwrap()).unwrap();
        assert_eq!(parsed.source_birth_data().as_slice(), deep.as_bytes());
        canonical::parse_json(parsed.source_birth_data().as_slice(), usize::MAX).unwrap();
    }
}
