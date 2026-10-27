//! Native systemd property-manifest conformance tests.
//!
//! The native helper consumes an X-macro inventory rather than Rust source.
//! These tests keep that inventory byte-for-byte strict and prove that every
//! interpreted field remains equivalent to the Rust protocol table.

use sha2::{Digest, Sha256};

use super::{
    MANAGER_INTERFACE, MANAGER_PROPERTY_TABLE_V1, MANAGER_QUERY_SCHEMA_DIGEST_V1,
    ManagerPropertyBindingV1, ManagerPropertyShapeV1, ManagerQueryObjectV1, SERVICE_INTERFACE,
    SOCKET_INTERFACE, UNIT_INTERFACE,
};

const PROPERTY_MANIFEST: &str = include_str!("systemd_v259_properties.def");
const MANIFEST_PREAMBLE: &str = "\
/*
 * Closed systemd 259 property manifest.
 *
 * Define AOS_SYSTEMD_V259_PROPERTY before including this file.
 * Fields: id, object, interface, property, signature, binding, shape.
 */
";
const ENTRY_PREFIX: &str = "AOS_SYSTEMD_V259_PROPERTY(";
#[derive(Debug, Eq, PartialEq)]
struct ManifestProperty<'a> {
    id: u16,
    object: ManagerQueryObjectV1,
    interface: &'static str,
    property: &'a str,
    signature: &'a str,
    binding: ManagerPropertyBindingV1,
    shape: ManagerPropertyShapeV1,
}

fn parse_manifest(source: &str) -> Result<Vec<ManifestProperty<'_>>, String> {
    if source.contains('\r') {
        return Err("manifest contains a carriage return".to_owned());
    }

    let body = source
        .strip_prefix(MANIFEST_PREAMBLE)
        .ok_or_else(|| "manifest preamble differs from its canonical form".to_owned())?;
    let body = body
        .strip_suffix('\n')
        .ok_or_else(|| "manifest must end with exactly one line feed".to_owned())?;
    if body.is_empty() {
        return Err("manifest has no property entries".to_owned());
    }

    body.split('\n')
        .enumerate()
        .map(|(line_index, line)| parse_manifest_row(line_index + 7, line))
        .collect()
}

fn parse_manifest_row(line_number: usize, line: &str) -> Result<ManifestProperty<'_>, String> {
    let fields = line
        .strip_prefix(ENTRY_PREFIX)
        .and_then(|row| row.strip_suffix(')'))
        .ok_or_else(|| format!("line {line_number} is not a canonical property entry"))?
        .split(", ")
        .collect::<Vec<_>>();
    if fields.len() != 7 {
        return Err(format!(
            "line {line_number} has {} fields rather than 7",
            fields.len()
        ));
    }

    let id = fields[0]
        .parse::<u16>()
        .map_err(|error| format!("line {line_number} has an invalid id: {error}"))?;
    if id.to_string() != fields[0] {
        return Err(format!("line {line_number} has a noncanonical id"));
    }

    Ok(ManifestProperty {
        id,
        object: parse_object(line_number, fields[1])?,
        interface: parse_interface(line_number, fields[2])?,
        property: parse_quoted_field(line_number, "property", fields[3])?,
        signature: parse_quoted_field(line_number, "signature", fields[4])?,
        binding: parse_binding(line_number, fields[5])?,
        shape: parse_shape(line_number, fields[6])?,
    })
}

fn parse_object(line_number: usize, field: &str) -> Result<ManagerQueryObjectV1, String> {
    match field {
        "MANAGER" => Ok(ManagerQueryObjectV1::Manager),
        "INSPECTOR_SERVICE" => Ok(ManagerQueryObjectV1::InspectorService),
        "INSPECTOR_SOCKET" => Ok(ManagerQueryObjectV1::InspectorSocket),
        _ => Err(format!("line {line_number} has an unknown object token")),
    }
}

fn parse_interface(line_number: usize, field: &str) -> Result<&'static str, String> {
    match field {
        "MANAGER" => Ok(MANAGER_INTERFACE),
        "UNIT" => Ok(UNIT_INTERFACE),
        "SERVICE" => Ok(SERVICE_INTERFACE),
        "SOCKET" => Ok(SOCKET_INTERFACE),
        _ => Err(format!("line {line_number} has an unknown interface token")),
    }
}

fn parse_quoted_field<'a>(
    line_number: usize,
    field_name: &str,
    field: &'a str,
) -> Result<&'a str, String> {
    let value = field
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| format!("line {line_number} has an unquoted {field_name}"))?;
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'"' | b'\\'))
    {
        return Err(format!(
            "line {line_number} has a noncanonical {field_name}"
        ));
    }

    Ok(value)
}

fn parse_binding(line_number: usize, field: &str) -> Result<ManagerPropertyBindingV1, String> {
    match field {
        "STATIC_CONTRACT" => Ok(ManagerPropertyBindingV1::StaticContract),
        "DYNAMIC_ACTIVATION" => Ok(ManagerPropertyBindingV1::DynamicActivation),
        _ => Err(format!("line {line_number} has an unknown binding token")),
    }
}

fn parse_shape(line_number: usize, field: &str) -> Result<ManagerPropertyShapeV1, String> {
    match field {
        "SCALAR" => Ok(ManagerPropertyShapeV1::Scalar),
        "ORDERED_ARRAY" => Ok(ManagerPropertyShapeV1::OrderedArray),
        "UNORDERED_SET" => Ok(ManagerPropertyShapeV1::UnorderedSet),
        _ => Err(format!("line {line_number} has an unknown shape token")),
    }
}

fn manifest_digest(properties: &[ManifestProperty<'_>]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for property in properties {
        digest.update(property.id.to_le_bytes());
        digest.update([property.object as u8]);
        digest.update(property.interface.as_bytes());
        digest.update([0]);
        digest.update(property.property.as_bytes());
        digest.update([0]);
        digest.update(property.signature.as_bytes());
        digest.update([property.binding as u8, property.shape as u8]);
    }

    digest.finalize().into()
}

#[test]
fn native_manifest_matches_rust_property_table_exactly() {
    let manifest = parse_manifest(PROPERTY_MANIFEST).unwrap();

    assert_eq!(manifest.len(), 126);
    assert_eq!(manifest.len(), MANAGER_PROPERTY_TABLE_V1.len());
    for (expected_id, (native, rust)) in manifest.iter().zip(MANAGER_PROPERTY_TABLE_V1).enumerate()
    {
        assert_eq!(usize::from(native.id), expected_id);
        assert_eq!(native.id, rust.id);
        assert_eq!(native.object, rust.object);
        assert_eq!(native.interface, rust.interface);
        assert_eq!(native.property, rust.property);
        assert_eq!(native.signature, rust.signature);
        assert_eq!(native.binding, rust.binding);
        assert_eq!(native.shape, rust.shape);
    }
}

#[test]
fn native_manifest_retains_reviewed_property_table_digest() {
    let manifest = parse_manifest(PROPERTY_MANIFEST).unwrap();

    assert_eq!(
        manifest_digest(&manifest),
        *MANAGER_QUERY_SCHEMA_DIGEST_V1.as_bytes()
    );
}

#[test]
fn manifest_parser_rejects_noncanonical_text() {
    let invalid_manifests = [
        PROPERTY_MANIFEST.trim_end_matches('\n').to_owned(),
        format!("{PROPERTY_MANIFEST}\n"),
        PROPERTY_MANIFEST.replacen(", MANAGER", ",  MANAGER", 1),
        PROPERTY_MANIFEST.replacen("DYNAMIC_ACTIVATION", "DYNAMIC", 1),
    ];

    for invalid_manifest in invalid_manifests {
        assert!(parse_manifest(&invalid_manifest).is_err());
    }
}
