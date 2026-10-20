//! Separates planned registration9 from actual authority-history edition11.
//!
//! The planned object exists before Hello. The historical view is an array of
//! ten fields produced from an actual authority after Hello; eleven names its
//! edition, not its arity. Prospective DATA never creates that authority, epoch,
//! registry or a Source/native occurrence.

use super::*;
use crate::handshake::{ConnectionAuthority, Limits};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};
use serde::Serialize;
use serde_json::Value;

const PLANNED_SCHEMA: &str = "source-owned.packet-canonical-ack-registration/5";
const HISTORICAL_SCHEMA: &str = "source-private.connection-authority/11";
const BACKING_MARKER: &str = "original-registration-backing-retained-by-opaque-source";
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
        authenticate_plan(launch, declaration, planned)?;
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
    authenticate_plan(launch, declaration, planned)?;
    let mut projection = Projection::new(maximum)?;
    projection.add_array_extent(10)?;
    projection.add_string(HISTORICAL_SCHEMA)?;
    for key in ["connection_id", "session_id", "incarnation_id"] {
        projection.add_value(planned.get(key).ok_or_else(refused)?)?;
    }
    projection.add_unescaped_ascii_extent(20)?;
    projection.add_value(&launch.limits)?;
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

/// Compares the same complete plan with an independently guarded actual authority.
///
/// Every selected feature/key/typed extension and receiving coordinate is
/// checked; the native role first proves its own defining connection Id before
/// projecting the peer's controller role. Kernel/Hello/Source/Connection custody
/// remains the private caller's independent conjunction. Success is DATA only.
///
/// # Errors
/// Refuses stale authority, a different target/plan, unknown feature/key, nonempty
/// typed extensions, changed limits or another actual role's connection Id.
pub fn authenticate_native_import18_current_host_registration_data(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
    authority: &ConnectionAuthority,
    side: PacketNativeImport18RegistrationSideData,
) -> Result<(), ProviderError> {
    authenticate_plan(launch, declaration, planned)?;
    declaration.authenticate_authority_data(authority)?;
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    if authority.session_id() != &binding.authority.session_id
        || authority.incarnation_id() != &binding.authority.incarnation_id
        || authority.limits() != launch.limits
        || authority
            .selected_extensions()
            .is_none_or(|extensions| !extensions.is_empty())
    {
        return Err(refused());
    }
    let expected = match side {
        PacketNativeImport18RegistrationSideData::Controller => text(planned, "connection_id")?,
        PacketNativeImport18RegistrationSideData::Native => NATIVE_IMPORT18_CONNECTION_ID,
    };
    if authority.connection_id().as_str() != expected {
        return Err(refused());
    }
    authority.ensure_live()
}

#[derive(Serialize)]
struct Registration<'a> {
    schema: &'static str,
    role: &'static str,
    connection_id: &'a Id,
    session_id: &'a Id,
    incarnation_id: &'a Id,
    limits: Limits,
    features: &'a IdSet,
    extensions: &'a [crucible_node_format::ExtensionSelection],
    envelope_extensions: &'a std::collections::BTreeSet<String>,
}

/// Borrows the complete current registration9 DATA without copying its children.
///
/// The actual issuer first proves its same Connection/Hello/Source and role.
/// The Host connection Id is independently obtained from the retained original
/// plan; the native-role normalization does not create that Host authority.
///
/// # Errors
/// Refuses revoked authority or an absent actual typed extension registration.
pub fn native_import18_current_registration_wire_data<'a>(
    authority: &'a ConnectionAuthority,
    controller_connection_id: Option<&'a Id>,
) -> Result<impl Serialize + 'a, ProviderError> {
    authority.ensure_live()?;
    Ok(Registration {
        schema: PLANNED_SCHEMA,
        role: if controller_connection_id.is_some() {
            "controller"
        } else {
            "native"
        },
        connection_id: controller_connection_id.unwrap_or(authority.connection_id()),
        session_id: authority.session_id(),
        incarnation_id: authority.incarnation_id(),
        limits: authority.limits(),
        features: authority.selected_features(),
        extensions: authority.selected_extensions().ok_or_else(refused)?,
        envelope_extensions: authority.envelope_extensions(),
    })
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProviderError> {
    value.get(key).and_then(Value::as_str).ok_or_else(refused)
}

fn authenticate_plan(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
) -> Result<(), ProviderError> {
    if *declaration != native_import18_hello_declaration_data(launch)? {
        return Err(refused());
    }
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let object = planned.as_object().ok_or_else(refused)?;
    if object.len() != FIELDS.len()
        || FIELDS.iter().any(|key| !object.contains_key(*key))
        || text(planned, "schema")? != PLANNED_SCHEMA
        || text(planned, "role")? != "controller"
        || text(planned, "session_id")? != binding.authority.session_id.as_str()
        || text(planned, "incarnation_id")? != binding.authority.incarnation_id.as_str()
        || !Id::is_valid_str(text(planned, "connection_id")?)
    {
        return Err(refused());
    }
    let limits = planned
        .get("limits")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    let actual = [
        launch.limits.frame_bytes,
        launch.limits.nesting,
        launch.limits.requests,
        launch.limits.journal_entries,
        launch.limits.blob_chunk_bytes,
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
    sorted_strings(features)?;
    sorted_strings(keys)?;
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

fn sorted_strings(values: &[Value]) -> Result<(), ProviderError> {
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
        include(&mut hash, text(planned, key)?.as_bytes())?;
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

/// Names direct role-normalized registration and prospective view controls.
pub fn native_import18_registration_counter_scratch_data() -> usize {
    size_of::<Registration<'static>>()
        + size_of::<PacketNativeImport18ProspectiveHostRegistrationData>()
        + size_of::<Result<PacketNativeImport18ProspectiveHostRegistrationData, ProviderError>>()
        + size_of::<Projection>()
        + size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData>(
        )
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&PacketNativeImport18HelloDeclarationData>()
        + size_of::<&ConnectionAuthority>()
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
        + size_of::<Result<Registration<'static>, ProviderError>>()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_strings_refuse_duplicates_nonstrings_and_reordered_keys() {
        sorted_strings(&[Value::String("a".into()), Value::String("b".into())]).unwrap();
        assert!(sorted_strings(&[Value::String("a".into()), Value::String("a".into())]).is_err());
        assert!(sorted_strings(&[Value::String("b".into()), Value::String("a".into())]).is_err());
        assert!(sorted_strings(&[Value::Null]).is_err());
    }

    #[test]
    fn actual_historical_schema_eleven_is_the_defining_array_of_ten_fields() {
        let (_handshake, authority, _, _) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let historical = serde_json::to_value(authority.historical_owned_view()).unwrap();
        let fields = historical.as_array().unwrap();
        assert_eq!(fields.len(), 10);
        assert_eq!(fields[0], HISTORICAL_SCHEMA);
        assert_eq!(fields[9], BACKING_MARKER);
        assert_eq!(fields[1], authority.connection_id().as_str());
        assert_eq!(fields[2], authority.session_id().as_str());
        assert_eq!(fields[3], authority.incarnation_id().as_str());
        assert!(fields[4].as_str().unwrap().parse::<u64>().is_ok());
    }
}

/// Projects Registration9 from the exact declared native roster and real target.
///
/// This never creates an authority, epoch, registration or future PID. The real
/// native producer separately checks its actual current registration against
/// the same launch declaration before consuming its independently funded row.
pub(super) fn prospective_native_registration_projection_data(
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

// A changed private serializer field roster must also update the prospective
// producer. This witness constructs neither registration DATA nor authority.
const _: fn(&Registration<'static>) = |value| {
    let Registration {
        schema: _,
        role: _,
        connection_id: _,
        session_id: _,
        incarnation_id: _,
        limits: _,
        features: _,
        extensions: _,
        envelope_extensions: _,
    } = value;
};
