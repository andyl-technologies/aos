//! Separates planned registration9 from actual authority-history edition11.
//!
//! The planned object exists before Hello. The historical view is an array of
//! ten fields produced from an actual authority after Hello; eleven names its
//! edition, not its arity. Prospective DATA never creates that authority, epoch,
//! registry or a Source/native occurrence.

use super::*;
use crate::profile::serialization_storage::{
    OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};
use crucible_node_format::U64;
use serde_json::Value;

/// Names the unchanged registration grammar identifier.
pub const PLANNED_SCHEMA: &str = "source-owned.packet-canonical-ack-registration/5";
/// Names the unchanged registration grammar identifier.
pub const HISTORICAL_SCHEMA: &str = "source-private.connection-authority/11";
/// Names the unchanged registration grammar identifier.
pub const BACKING_MARKER: &str = "original-registration-backing-retained-by-opaque-source";
const FIELDS: [&str; 9] = [
    "schema",
    "role",
    "connection_id",
    "session_id",
    "incarnation_id",
    "limits",
    "features",
    "extensions",
    "envelope_extensions",
];
const LIMIT_FIELDS: [&str; 5] = [
    "frame_bytes",
    "nesting",
    "requests",
    "journal_entries",
    "blob_chunk_bytes",
];

/// Selects a role-normalized comparison without supplying the actual endpoint role.
///
/// The private issuer independently proves its actual Connection role and live
/// actor. This selector only describes which connection Id that comparison uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketNativeImport18RegistrationSideData {
    /// Compares the real Host authority's connection Id directly with its plan.
    Controller,
    /// Checks the real native connection Id, then normalizes its peer role/Id.
    Native,
}

/// Retains prospective edition11 history geometry bound to one complete planned object.
///
/// No Deserialize, epoch, actual historical DTO or live registration is returned.
#[derive(Clone, Copy)]
pub struct PacketNativeImport18ProspectiveHostRegistrationData {
    planned: [u8; 32],
    maximum_encoded_bytes: usize,
}

impl PacketNativeImport18ProspectiveHostRegistrationData {
    /// Returns the retained complete-plan identity as inert comparison DATA.
    ///
    /// This digest cannot create a planned projection, registration, original
    /// authority or Source occurrence. Full field checks remain independent.
    pub const fn planned_identity_data(&self) -> [u8; 32] {
        self.planned
    }

    /// Returns the defining prospective array10 encoded extent only.
    pub const fn maximum_encoded_bytes_data(&self) -> usize {
        self.maximum_encoded_bytes
    }

    /// Checks the same complete actual plan and immutable target declaration.
    ///
    /// # Errors
    /// Refuses changed planned fields, target IDs/limits, registry or Hello roster.
    pub fn authenticate_planned_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        declaration: &PacketNativeImport18HelloDeclarationData,
        planned: &Value,
    ) -> Result<(), ProviderError> {
        let fields = PacketNative5LaunchValidationFields::from_launch_data(launch);
        self.authenticate_planned_from_fields_data(&fields, declaration, planned)
    }

    /// Checks the same planned object using inert borrowed launch fields.
    ///
    /// This preserves the ordinary plan checks before comparing the retained
    /// planned identity. Success grants no registration or Source authority.
    ///
    /// # Errors
    /// Refuses changed planned fields, target, limits, roster or saved identity.
    pub fn authenticate_planned_from_fields_data(
        &self,
        fields: &PacketNative5LaunchValidationFields<'_>,
        declaration: &PacketNativeImport18HelloDeclarationData,
        planned: &Value,
    ) -> Result<(), ProviderError> {
        authenticate_plan_from_fields_data(fields, declaration, planned)?;
        if self.planned != planned_identity(planned)? {
            return Err(refused());
        }
        Ok(())
    }
}

/// Projects the actual historical array10 grammar from a validated planned object9.
///
/// The genuine Source/BodyPlan supplies its same immutable planned bank. Actual
/// SDK/native producers must later pass the independent current registration
/// comparison before using the real historical view in normalization35. The
/// epoch uses U64's twenty-byte declaration; the installed new private Hello
/// constructor selects Some(empty typed extensions), represented by an empty
/// array, and retains its real registration roots independently.
///
/// # Errors
/// Refuses changed planned grammar/target/roster, a nonempty typed extension
/// selection, checked projection overflow or demand above the restriction.
pub fn native_import18_prospective_host_registration_data(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
    maximum: usize,
) -> Result<PacketNativeImport18ProspectiveHostRegistrationData, ProviderError> {
    let fields = PacketNative5LaunchValidationFields::from_launch_data(launch);
    native_import18_prospective_host_registration_from_fields_data(
        &fields,
        declaration,
        planned,
        maximum,
    )
}

/// Projects the original prospective registration from nonsecret launch fields.
///
/// The same complete plan, target, limits and closed Hello roster are checked in
/// the ordinary order. This DATA supplies no actual authority, epoch, Source
/// occurrence or permission to construct a historical registration.
///
/// # Errors
/// Preserves the ordinary plan/target/roster, projection overflow and maximum
/// refusals, including the empty typed-extension requirement.
pub fn native_import18_prospective_host_registration_from_fields_data(
    fields: &PacketNative5LaunchValidationFields<'_>,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
    maximum: usize,
) -> Result<PacketNativeImport18ProspectiveHostRegistrationData, ProviderError> {
    authenticate_plan_from_fields_data(fields, declaration, planned)?;
    let mut projection = Projection::new(maximum)?;
    projection.add_array_extent(10)?;
    projection.add_string(HISTORICAL_SCHEMA)?;
    for key in ["connection_id", "session_id", "incarnation_id"] {
        projection.add_value(planned.get(key).ok_or_else(refused)?)?;
    }
    projection.add_unescaped_ascii_extent(20)?;
    projection.add_value(fields.limits)?;
    projection.add_value(planned.get("features").ok_or_else(refused)?)?;
    projection.add_value(planned.get("envelope_extensions").ok_or_else(refused)?)?;
    projection.add_array_extent(0)?;
    projection.add_string(BACKING_MARKER)?;
    let projected = projection.finish(maximum)?;
    Ok(PacketNativeImport18ProspectiveHostRegistrationData {
        planned: planned_identity(planned)?,
        maximum_encoded_bytes: projected.maximum_encoded_bytes,
    })
}

/// Borrows the original required string field.
///
/// # Errors
/// Preserves the original malformed field or correspondence refusal.
pub fn text_data<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProviderError> {
    value.get(key).and_then(Value::as_str).ok_or_else(refused)
}

/// Checks the complete planned object from the same launch DATA.
///
/// # Errors
/// Preserves the original malformed field or correspondence refusal.
pub fn authenticate_plan_data(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
) -> Result<(), ProviderError> {
    let fields = PacketNative5LaunchValidationFields::from_launch_data(launch);
    authenticate_plan_from_fields_data(&fields, declaration, planned)
}

/// Checks every original plan field and exact Hello roster.
///
/// # Errors
/// Preserves the original malformed field or correspondence refusal.
pub fn authenticate_plan_from_fields_data(
    fields: &PacketNative5LaunchValidationFields<'_>,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
) -> Result<(), ProviderError> {
    if *declaration != native_import18_hello_declaration_from_fields_data(fields)? {
        return Err(refused());
    }
    let [binding] = fields.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let object = planned.as_object().ok_or_else(refused)?;
    if object.len() != FIELDS.len()
        || FIELDS.iter().any(|key| !object.contains_key(*key))
        || text_data(planned, "schema")? != PLANNED_SCHEMA
        || text_data(planned, "role")? != "controller"
        || text_data(planned, "session_id")? != binding.authority.session_id.as_str()
        || text_data(planned, "incarnation_id")? != binding.authority.incarnation_id.as_str()
        || !Id::is_valid_str(text_data(planned, "connection_id")?)
    {
        return Err(refused());
    }
    let limits = planned
        .get("limits")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    let actual = [
        fields.limits.frame_bytes,
        fields.limits.nesting,
        fields.limits.requests,
        fields.limits.journal_entries,
        fields.limits.blob_chunk_bytes,
    ];
    if limits.len() != LIMIT_FIELDS.len() {
        return Err(refused());
    }
    for (key, expected) in LIMIT_FIELDS.into_iter().zip(actual) {
        let encoded = limits
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(refused)?;
        if encoded.is_empty()
            || encoded.len() > 20
            || (encoded.len() > 1 && encoded.starts_with('0'))
            || !encoded.bytes().all(|byte| byte.is_ascii_digit())
            || encoded.parse::<u64>().ok() != Some(expected.get())
        {
            return Err(refused());
        }
    }
    let features = planned
        .get("features")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    let keys = planned
        .get("envelope_extensions")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    if features.len() != declaration.feature_count
        || keys.len() != declaration.key_count
        || planned
            .get("extensions")
            .and_then(Value::as_array)
            .is_none_or(|values| !values.is_empty())
    {
        return Err(refused());
    }
    sorted_strings_data(features)?;
    sorted_strings_data(keys)?;
    for feature in features {
        let name = feature.as_str().ok_or_else(refused)?;
        if !declaration
            .features
            .iter()
            .flatten()
            .any(|expected| *expected == name)
        {
            return Err(refused());
        }
    }
    for key in keys {
        let name = key.as_str().ok_or_else(refused)?;
        if !declaration
            .keys
            .iter()
            .flatten()
            .any(|(expected, _)| *expected == name)
        {
            return Err(refused());
        }
    }
    Ok(())
}

/// Checks strictly increasing original string elements.
///
/// # Errors
/// Preserves the original malformed field or correspondence refusal.
pub fn sorted_strings_data(values: &[Value]) -> Result<(), ProviderError> {
    let mut previous = None;
    for value in values {
        let current = value.as_str().ok_or_else(refused)?;
        if previous.is_some_and(|previous| previous >= current) {
            return Err(refused());
        }
        previous = Some(current);
    }
    Ok(())
}

// Only known validated strings/arrays participate. Each length-delimited field
// is committed in its defining order; no canonical DOM/formatter is allocated.
fn planned_identity(planned: &Value) -> Result<[u8; 32], ProviderError> {
    let mut hash = blake3::Hasher::new_derive_key("native-import18.planned-registration/1");
    for key in [
        "schema",
        "role",
        "connection_id",
        "session_id",
        "incarnation_id",
    ] {
        include(&mut hash, text_data(planned, key)?.as_bytes())?;
    }
    for key in LIMIT_FIELDS {
        include(
            &mut hash,
            planned
                .get("limits")
                .and_then(|limits| limits.get(key))
                .and_then(Value::as_str)
                .ok_or_else(refused)?
                .as_bytes(),
        )?;
    }
    for key in ["features", "envelope_extensions", "extensions"] {
        let values = planned
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(refused)?;
        hash.update(
            &u64::try_from(values.len())
                .map_err(|_| refused())?
                .to_be_bytes(),
        );
        for value in values {
            include(&mut hash, value.as_str().ok_or_else(refused)?.as_bytes())?;
        }
    }
    Ok(*hash.finalize().as_bytes())
}

fn include(hash: &mut blake3::Hasher, value: &[u8]) -> Result<(), ProviderError> {
    hash.update(
        &u64::try_from(value.len())
            .map_err(|_| refused())?
            .to_be_bytes(),
    );
    hash.update(value);
    Ok(())
}

// Fixed headers introduced by the real prospective/authentication wrappers.
// No old plan, serializer, hash or declaration term pays for this new input.
const REAL_PLAN_INPUT_HEADERS: usize = size_of::<PacketNative5LaunchValidationFields<'static>>()
    + size_of::<PacketNative5LaunchValidationFields<'static>>()
    + size_of::<PacketNative5LaunchValidationFields<'static>>()
    + size_of::<&'static PacketNative5SourceLaunch>()
    + size_of::<&'static PacketNative5LaunchValidationFields<'static>>()
    + size_of::<&'static PacketNative5LaunchValidationFields<'static>>()
    + size_of::<Result<PacketNativeImport18ProspectiveHostRegistrationData, ProviderError>>()
    + size_of::<Result<(), ProviderError>>()
    + size_of::<Result<(), ProviderError>>();

/// Names direct role-normalized registration and prospective view controls.
pub fn native_import18_registration_counter_scratch_data() -> usize {
    REAL_PLAN_INPUT_HEADERS
        + size_of::<PacketNativeImport18ProspectiveHostRegistrationData>()
        + size_of::<Result<PacketNativeImport18ProspectiveHostRegistrationData, ProviderError>>()
        + size_of::<Projection>()
        + size_of::<crate::profile::serialization_storage::OriginalSerializationStorageData>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&PacketNativeImport18HelloDeclarationData>()
        + size_of::<&Value>()
        + size_of::<&serde_json::Map<String, Value>>()
        + size_of::<Option<&serde_json::Map<String, Value>>>()
        + size_of::<&[Value]>()
        + size_of::<&Vec<Value>>()
        + size_of::<Option<&Vec<Value>>>()
        + size_of::<std::slice::Iter<'static, Value>>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<std::array::IntoIter<&'static str, 9>>()
        + size_of::<std::array::IntoIter<&'static str, 5>>()
        + size_of::<std::array::IntoIter<&'static str, 3>>()
        + size_of::<std::array::IntoIter<U64, 5>>()
        + size_of::<
            std::iter::Zip<std::array::IntoIter<&'static str, 5>, std::array::IntoIter<U64, 5>>,
        >()
        + size_of::<[U64; 5]>()
        + size_of::<[&str; 9]>()
        + size_of::<[&str; 5]>()
        + size_of::<[&str; 3]>()
        + size_of::<Option<&str>>()
        + size_of::<Result<&str, ProviderError>>()
        + size_of::<Option<u64>>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>()
        + size_of::<[u8; 8]>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<PacketNativeImport18RegistrationSideData>()
        + size_of::<PacketNativeImport18HelloDeclarationData>()
        + size_of::<Result<PacketNativeImport18HelloDeclarationData, ProviderError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<&Id>()
        + size_of::<Option<&Id>>()
        + size_of::<Option<&[crucible_node_format::ExtensionSelection]>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<&'static str>>>>()
        + size_of::<
            std::iter::Flatten<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>,
        >()
        + size_of::<std::slice::Iter<'static, Option<&'static str>>>()
        + size_of::<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>()
        + size_of::<&str>() * 3
        + size_of::<&&str>()
        + size_of::<usize>()
        + size_of::<u64>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<(), ProviderError>>()
        + original_serialization_counter_scratch_data()
        + PacketNativeImport18HelloDeclarationData::declaration_counter_scratch_data()
}

/// Projects Registration9 from the exact declared native roster and real target.
///
/// This never creates an authority, epoch, registration or future PID. The real
/// native producer separately checks its actual current registration against
/// the same launch declaration before consuming its independently funded row.
pub fn prospective_native_registration_projection_data(
    out: &mut Projection,
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
) -> Result<(), ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    out.add_object()?;
    for field in FIELDS {
        out.add_field(field)?;
    }
    out.add_string(PLANNED_SCHEMA)?;
    out.add_string("native")?;
    out.add_string(super::NATIVE_IMPORT18_CONNECTION_ID)?;
    out.add_value(&binding.authority.session_id)?;
    out.add_value(&binding.authority.incarnation_id)?;
    out.add_value(&launch.limits)?;
    super::materialization::project_features_data(out, declaration)?;
    out.add_array_extent(0)?;
    super::materialization::project_keys_data(out, declaration)
}
