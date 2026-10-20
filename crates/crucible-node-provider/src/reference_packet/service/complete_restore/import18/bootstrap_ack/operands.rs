//! Defines the same four normalized bootstrap operands for Source and native.
//!
//! These borrowed views describe complete bytes, not provenance. Actual Source,
//! private Bootstrap, kernel/Hello/Connection and full-definition guards precede
//! their use; the real callers separately admit DOM/JCS/formatter construction.
//! No normalized value or matching digest creates an ACK occurrence or grant.

use super::*;
use crate::handshake::{ConnectionAuthority, Limits};
use crucible_node_contract::IdSet;
use std::collections::BTreeSet;
use std::mem::size_of;

#[path = "operands/prospective.rs"]
mod prospective;

pub(in crate::reference_packet) use prospective::{
    NativeImport18BootstrapProspectiveOperands,
    native_import18_bootstrap_prospective_operands_counter_scratch_data,
    native_import18_bootstrap_prospective_operands_data,
};

/// Borrows the complete new Source/Birth association without cloning its children.
#[derive(Serialize)]
pub struct PacketNativeImport18BootstrapBirthView<'a> {
    schema: &'static str,
    birth_id: &'a Bytes,
    private_launch: &'a Id,
    host_executable: &'a ContentRef,
    source_binding: &'a serde_json::Value,
    expected_host_registration: &'a serde_json::Value,
}

/// Borrows one actually measured process identity without asserting its provenance.
#[derive(Serialize)]
pub struct PacketNativeImport18BootstrapProcessView<'a> {
    pid: U64,
    uid: U64,
    executable: &'a ContentRef,
}

/// Borrows the unchanged role-normalized kernel-binding5 DATA grammar.
#[derive(Serialize)]
pub struct PacketNativeImport18BootstrapKernelView<'a> {
    schema: &'static str,
    controller: PacketNativeImport18BootstrapProcessView<'a>,
    native: PacketNativeImport18BootstrapProcessView<'a>,
}

/// Borrows the three independently authenticated full selected definitions.
#[derive(Serialize)]
pub struct PacketNativeImport18BootstrapDefinitionsView<'a> {
    mechanism: PacketNativeImport18Selection,
    import: &'a SchemaRef,
    stage: &'a SchemaRef,
    record: &'a SchemaRef,
}

/// Borrows every selected negotiation coordinate from the actual live authority.
#[derive(Serialize)]
pub struct PacketNativeImport18BootstrapNegotiatedView<'a> {
    limits: Limits,
    features: &'a IdSet,
    extensions: &'a [crucible_node_contract::ExtensionSelection],
    envelope_extensions: &'a BTreeSet<String>,
}

/// Borrows the complete new policy preimage with full definitions and same recipe.
#[derive(Serialize)]
pub struct PacketNativeImport18BootstrapPolicyView<'a> {
    schema: &'static str,
    source_binding: &'a serde_json::Value,
    recipe_identity: &'a Bytes,
    definitions: PacketNativeImport18BootstrapDefinitionsView<'a>,
    negotiated: PacketNativeImport18BootstrapNegotiatedView<'a>,
}

/// Borrows normalized role zero from the same retained full Source binding.
///
/// The Host plan remains the genuine closed object9, independently compared
/// with current authority by the shared registration guard before signing.
///
/// # Errors
/// Refuses a non-32-byte birth or changed new Source wrapper roster/schema.
pub fn native_import18_bootstrap_birth_wire_data<'a>(
    birth_id: &'a Bytes,
    private_launch: &'a Id,
    host_executable: &'a ContentRef,
    source_binding: &'a serde_json::Value,
    expected_host_registration: &'a serde_json::Value,
) -> Result<PacketNativeImport18BootstrapBirthView<'a>, ProviderError> {
    digest32(birth_id)?;
    source_binding_shape(source_binding)?;
    Ok(PacketNativeImport18BootstrapBirthView {
        schema: "source-owned.packet-native-import-bootstrap-birth-association/18",
        birth_id,
        private_launch,
        host_executable,
        source_binding,
        expected_host_registration,
    })
}

/// Borrows normalized role one using both actual guarded process measurements.
///
/// # Errors
/// Refuses a non-process PID or a UID outside the defining kernel coordinate.
pub fn native_import18_bootstrap_kernel_wire_data<'a>(
    controller_pid: U64,
    controller_uid: U64,
    controller_executable: &'a ContentRef,
    native_pid: U64,
    native_uid: U64,
    native_executable: &'a ContentRef,
) -> Result<PacketNativeImport18BootstrapKernelView<'a>, ProviderError> {
    for (pid, uid) in [(controller_pid, controller_uid), (native_pid, native_uid)] {
        if pid.get() == 0 || pid.get() > i32::MAX as u64 || uid.get() > u32::MAX as u64 {
            return Err(invalid());
        }
    }
    Ok(PacketNativeImport18BootstrapKernelView {
        schema: "source-owned.packet-canonical-ack-kernel-binding/5",
        controller: PacketNativeImport18BootstrapProcessView {
            pid: controller_pid,
            uid: controller_uid,
            executable: controller_executable,
        },
        native: PacketNativeImport18BootstrapProcessView {
            pid: native_pid,
            uid: native_uid,
            executable: native_executable,
        },
    })
}

/// Borrows normalized role two, including all full selected contract definitions.
///
/// The caller independently authenticates each complete SchemaRef against the
/// genuine full selected provider/binding rosters and compiled definition. This
/// helper checks their editions and includes every supplied field in the MAC
/// preimage; no reference is inferred from a tag or the other schema's digest.
///
/// # Errors
/// Refuses revoked authority, missing typed extensions, a changed full-schema
/// edition, another Source roster or a recipe different from its announcement.
pub fn native_import18_bootstrap_policy_wire_data<'a>(
    source_binding: &'a serde_json::Value,
    recipe_identity: &'a Bytes,
    import: &'a SchemaRef,
    stage: &'a SchemaRef,
    record: &'a SchemaRef,
    authority: &'a ConnectionAuthority,
) -> Result<PacketNativeImport18BootstrapPolicyView<'a>, ProviderError> {
    authority.ensure_live()?;
    digest32(recipe_identity)?;
    source_binding_shape(source_binding)?;
    for (reference, expected) in [
        (import, "source-owned.packet-native-import/18"),
        (stage, "source-owned.packet-native-import-stage/18"),
        (record, "source-owned.packet-restored-native/18"),
    ] {
        if reference.id.as_str() != expected || reference.version != 18 {
            return Err(invalid());
        }
    }
    let identity = source_binding
        .get("prebirth_recipe")
        .and_then(|recipe| recipe.get("identity"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(invalid)?;
    if identity.len() != 32 {
        return Err(invalid());
    }
    for (value, byte) in identity.iter().zip(recipe_identity.as_slice()) {
        if value.as_u64() != Some(u64::from(*byte)) {
            return Err(invalid());
        }
    }
    Ok(PacketNativeImport18BootstrapPolicyView {
        schema: "source-owned.packet-native-import-bootstrap-policy-binding/18",
        source_binding,
        recipe_identity,
        definitions: PacketNativeImport18BootstrapDefinitionsView {
            mechanism: PacketNativeImport18Selection::SourceSignedImport18,
            import,
            stage,
            record,
        },
        negotiated: PacketNativeImport18BootstrapNegotiatedView {
            limits: authority.limits(),
            features: authority.selected_features(),
            extensions: authority.selected_extensions().ok_or_else(invalid)?,
            envelope_extensions: authority.envelope_extensions(),
        },
    })
}

fn source_binding_shape(value: &serde_json::Value) -> Result<(), ProviderError> {
    let object = value.as_object().ok_or_else(invalid)?;
    let fields = [
        "schema",
        "declaration",
        "mechanism",
        "prebirth_recipe",
        "initial_funding",
    ];
    if object.len() != fields.len()
        || fields.iter().any(|field| !object.contains_key(*field))
        || object.get("schema").and_then(serde_json::Value::as_str)
            != Some("source-owned.packet-canonical-ack-source-binding/18")
        || object.get("mechanism").and_then(serde_json::Value::as_str)
            != Some("SourceSignedImport18")
    {
        return Err(invalid());
    }
    Ok(())
}

/// Names direct borrowed view/result, full-reference and fixed comparison controls.
///
/// Actual field serialization, dynamic backing, custom Bytes/decimal formatters,
/// recursive serde/JCS and private Source/kernel/currentness work are separate.
pub fn native_import18_bootstrap_operands_counter_scratch_data() -> usize {
    size_of::<PacketNativeImport18BootstrapBirthView<'static>>()
        + size_of::<Result<PacketNativeImport18BootstrapBirthView<'static>, ProviderError>>()
        + size_of::<PacketNativeImport18BootstrapKernelView<'static>>()
        + size_of::<Result<PacketNativeImport18BootstrapKernelView<'static>, ProviderError>>()
        + size_of::<PacketNativeImport18BootstrapPolicyView<'static>>()
        + size_of::<Result<PacketNativeImport18BootstrapPolicyView<'static>, ProviderError>>()
        + size_of::<PacketNativeImport18BootstrapDefinitionsView<'static>>()
        + size_of::<PacketNativeImport18BootstrapNegotiatedView<'static>>()
        + size_of::<PacketNativeImport18BootstrapProcessView<'static>>() * 2
        + size_of::<&serde_json::Value>() * 2
        + size_of::<&Bytes>()
        + size_of::<&ConnectionAuthority>()
        + size_of::<&SchemaRef>() * 3
        + size_of::<Option<&serde_json::Map<String, serde_json::Value>>>()
        + size_of::<&serde_json::Map<String, serde_json::Value>>()
        + size_of::<Option<&serde_json::Value>>()
        + size_of::<Option<&str>>()
        + size_of::<&[u8; 32]>()
        + size_of::<&[u8]>()
        + size_of::<[(U64, U64); 2]>()
        + size_of::<std::array::IntoIter<(U64, U64), 2>>()
        + size_of::<[(&SchemaRef, &str); 3]>()
        + size_of::<std::array::IntoIter<(&SchemaRef, &str), 3>>()
        + size_of::<[&str; 5]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<std::slice::Iter<'static, serde_json::Value>>()
        + size_of::<std::slice::Iter<'static, u8>>()
        + size_of::<
            std::iter::Zip<
                std::slice::Iter<'static, serde_json::Value>,
                std::slice::Iter<'static, u8>,
            >,
        >()
        + size_of::<Option<u64>>()
        + size_of::<U64>() * 4
        + size_of::<&PacketNativeImport18BootstrapBirthView<'static>>()
        + size_of::<&PacketNativeImport18BootstrapKernelView<'static>>()
        + size_of::<&PacketNativeImport18BootstrapPolicyView<'static>>()
        + size_of::<Projection>()
        + size_of::<OriginalSerializationStorageData>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<&[&str]>()
        + size_of::<&&str>()
        + size_of::<[&str; 6]>()
        + size_of::<usize>()
        + size_of::<&Vec<serde_json::Value>>()
        + size_of::<Option<&Vec<serde_json::Value>>>()
        + size_of::<Result<(), ProviderError>>()
}

use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
};

fn object(projection: &mut Projection, fields: &[&str]) -> Result<(), ProviderError> {
    projection.add_object()?;
    for field in fields {
        projection.add_field(field)?;
    }
    Ok(())
}

/// Projects the exact defining birth view without invoking its Bytes formatter.
pub(in crate::reference_packet) fn native_import18_bootstrap_birth_serialization_data(
    view: &PacketNativeImport18BootstrapBirthView<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let PacketNativeImport18BootstrapBirthView {
        schema,
        birth_id: _,
        private_launch,
        host_executable,
        source_binding,
        expected_host_registration,
    } = view;
    let mut projection = Projection::new(maximum)?;
    object(
        &mut projection,
        &[
            "schema",
            "birth_id",
            "private_launch",
            "host_executable",
            "source_binding",
            "expected_host_registration",
        ],
    )?;
    projection.add_string(schema)?;
    projection.add_unescaped_ascii_extent(43)?;
    projection.add_value(private_launch)?;
    projection.add_value(host_executable)?;
    projection.add_value(source_binding)?;
    projection.add_value(expected_host_registration)?;
    projection.finish(maximum)
}

/// Projects the exact defining kernel view with no allocating Bytes formatter.
pub(in crate::reference_packet) fn native_import18_bootstrap_kernel_serialization_data(
    view: &PacketNativeImport18BootstrapKernelView<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let PacketNativeImport18BootstrapKernelView {
        schema: _,
        controller: _,
        native: _,
    } = view;
    let mut projection = Projection::new(maximum)?;
    projection.add_value(view)?;
    projection.finish(maximum)
}

/// Projects the exact defining policy view without invoking its Bytes formatter.
pub(in crate::reference_packet) fn native_import18_bootstrap_policy_serialization_data(
    view: &PacketNativeImport18BootstrapPolicyView<'_>,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let PacketNativeImport18BootstrapPolicyView {
        schema,
        source_binding,
        recipe_identity: _,
        definitions,
        negotiated,
    } = view;
    let mut projection = Projection::new(maximum)?;
    object(
        &mut projection,
        &[
            "schema",
            "source_binding",
            "recipe_identity",
            "definitions",
            "negotiated",
        ],
    )?;
    projection.add_string(schema)?;
    projection.add_value(source_binding)?;
    projection.add_unescaped_ascii_extent(43)?;
    projection.add_value(definitions)?;
    projection.add_value(negotiated)?;
    projection.finish(maximum)
}
