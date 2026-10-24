//! Checks the original startup DTO's fallible spellings before owned copying.
//!
//! ```text
//! boot = {schema, private_key, birth_id, source_birth,
//!         expected_host_registration, private_launch, host_executable}
//! host_executable = {hash: {algorithm, domain, digest}, length, media_type}
//! ```
//!
//! This borrows an already retained strict Value. It checks representation only:
//! schema identities, hashes, key widths and native claims remain with their
//! original authenticators. No Source, Recipe, Initial or permission is created.

use base64::Engine;
use crucible_node_format::{Bytes, ContentRef, ContractError, Id};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::mem::size_of;

use crate::ProviderError;

const BOOT_FIELDS: [&str; 7] = [
    "schema",
    "private_key",
    "birth_id",
    "source_birth",
    "expected_host_registration",
    "private_launch",
    "host_executable",
];
const CONTENT_FIELDS: [&str; 3] = ["hash", "length", "media_type"];
const HASH_FIELDS: [&str; 3] = ["algorithm", "domain", "digest"];

/// Borrows the original immutable inputs after their representation checks.
pub(super) struct BootShape<'a> {
    schema: &'a str,
    private_key: &'a Value,
    birth_id: &'a Value,
    source_birth: &'a Value,
    expected_host_registration: &'a Value,
    private_launch: &'a Value,
    host_executable: &'a Value,
}

impl BootShape<'_> {
    /// Copies validated fields while preserving the actual opaque JSON children.
    ///
    /// # Errors
    /// Propagates a scalar/reference codec error if its representation differs
    /// from the checks performed by the defining borrowed inspector.
    pub(super) fn copy_data(self) -> Result<super::BootData, ProviderError> {
        // These immutable scalar/reference inputs passed the exact codec
        // spelling checks before the first owned copy. Keep the SDK's codecs
        // for the actual typed values and leave semantic validation unchanged.
        let private_key = Bytes::deserialize(self.private_key).map_err(ContractError::from)?;
        let birth_id = Bytes::deserialize(self.birth_id).map_err(ContractError::from)?;
        let private_launch = Id::deserialize(self.private_launch).map_err(ContractError::from)?;
        let host_executable =
            ContentRef::deserialize(self.host_executable).map_err(ContractError::from)?;

        // Value's generic deserializer can interpret reserved Serde keys as a
        // second encoded JSON document. Clone the actual retained JSON children
        // directly so their literal objects never enter that fallible parser.
        Ok(super::BootData {
            schema: self.schema.to_owned(),
            private_key,
            birth_id,
            source_birth: self.source_birth.clone(),
            expected_host_registration: self.expected_host_registration.clone(),
            private_launch,
            host_executable,
        })
    }
}

/// Checks closed DTO spellings without copying children or issuing a claim.
///
/// # Errors
/// Refuses missing, unknown or incorrectly typed fields, noncanonical base64,
/// malformed identifiers and noncanonical or out-of-range decimal lengths.
pub(super) fn inspect_data(value: &Value) -> Result<BootShape<'_>, ProviderError> {
    let boot = object(value, &BOOT_FIELDS)?;
    text(boot, "schema")?;
    octets(text(boot, "private_key")?)?;
    octets(text(boot, "birth_id")?)?;
    if !Id::is_valid_str(text(boot, "private_launch")?) {
        return Err(refused());
    }

    let content = object(
        boot.get("host_executable").ok_or_else(refused)?,
        &CONTENT_FIELDS,
    )?;
    let hash = object(content.get("hash").ok_or_else(refused)?, &HASH_FIELDS)?;
    for field in HASH_FIELDS {
        text(hash, field)?;
    }
    text(content, "media_type")?;
    decimal(text(content, "length")?)?;
    Ok(BootShape {
        schema: text(boot, "schema")?,
        private_key: field(boot, "private_key")?,
        birth_id: field(boot, "birth_id")?,
        source_birth: field(boot, "source_birth")?,
        expected_host_registration: field(boot, "expected_host_registration")?,
        private_launch: field(boot, "private_launch")?,
        host_executable: field(boot, "host_executable")?,
    })
}

fn field<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a Value, ProviderError> {
    object.get(field).ok_or_else(refused)
}

fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, ProviderError> {
    let object = value.as_object().ok_or_else(refused)?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(refused());
    }
    Ok(object)
}

fn text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, ProviderError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(refused)
}

fn octets(encoded: &str) -> Result<(), ProviderError> {
    // Four encoded symbols form an independent quantum. Checking each quantum
    // uses the same pinned decoder as Bytes without its String or Vec copies.
    // Only the final quantum can be short; its original trailing-bit and
    // no-padding checks remain in that decoder.
    let mut decoded = [0; 3];
    for quantum in encoded.as_bytes().chunks(4) {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode_slice(quantum, &mut decoded)
            .map_err(|_| refused())?;
    }
    Ok(())
}

fn decimal(encoded: &str) -> Result<(), ProviderError> {
    // Match U64's representation without allocating its diagnostic on failure.
    if encoded.is_empty()
        || encoded.len() > 1 && encoded.starts_with('0')
        || !encoded.bytes().all(|byte| byte.is_ascii_digit())
        || encoded.parse::<u64>().is_err()
    {
        return Err(refused());
    }
    Ok(())
}

fn refused() -> ProviderError {
    ProviderError::Frame("original native startup boot representation")
}

/// Names independent inspection/copy controls beside the unchanged DTO quote.
///
/// The root/content/hash loans coexist through nested inspections. Each helper
/// keeps its own controls; the enclosing counter retains all old Serde terms.
pub(super) fn counter_scratch_data() -> usize {
    Bytes::slice_decoding_counter_scratch_data()
        + size_of::<BootShape<'static>>() * 2
        + size_of::<Result<BootShape<'static>, ProviderError>>() * 2
        + size_of::<Result<&Value, ProviderError>>() * 2
        + size_of::<Result<Bytes, serde_json::Error>>() * 2
        + size_of::<Result<Id, serde_json::Error>>()
        + size_of::<Result<ContentRef, serde_json::Error>>()
        + size_of::<Result<super::BootData, ProviderError>>()
        + size_of::<&String>()
        + size_of::<&Value>() * 2
        + size_of::<Value>() * 2
        + 4 * size_of::<&Value>()
        + 4 * size_of::<Option<&Value>>()
        + 5 * size_of::<&Map<String, Value>>()
        + size_of::<&&Map<String, Value>>()
        + size_of::<Option<&Map<String, Value>>>()
        + size_of::<Result<&Map<String, Value>, ProviderError>>() * 2
        + 4 * size_of::<&str>()
        + size_of::<Option<&str>>()
        + size_of::<Result<&str, ProviderError>>() * 2
        + size_of::<&[&str]>()
        + size_of::<[&str; 7]>()
        + size_of::<[&str; 3]>() * 3
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<&&str>()
        + size_of::<std::array::IntoIter<&str, 3>>()
        + size_of::<std::str::Bytes<'static>>() * 2
        + size_of::<std::slice::Iter<'static, u8>>()
        + size_of::<Option<u8>>()
        + size_of::<u8>() * 2
        + size_of::<std::slice::Chunks<'static, u8>>()
        + size_of::<&[u8]>() * 2
        + size_of::<&mut [u8]>()
        + size_of::<[u8; 3]>()
        + size_of::<Result<usize, base64::DecodeSliceError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + size_of::<std::num::ParseIntError>()
        + size_of::<ProviderError>()
        + size_of::<Result<(), ProviderError>>() * 5
        + size_of::<usize>() * 4
        + size_of::<bool>() * 4
}

/// Names additional borrowed/result and owned initializer construction headers.
pub(super) const fn construction_transient_data() -> usize {
    size_of::<BootShape<'static>>() * 2
        + size_of::<Result<BootShape<'static>, ProviderError>>()
        + size_of::<super::BootData>()
        + size_of::<Result<super::BootData, ProviderError>>()
}

#[cfg(test)]
#[path = "boot_shape_tests.rs"]
mod tests;
