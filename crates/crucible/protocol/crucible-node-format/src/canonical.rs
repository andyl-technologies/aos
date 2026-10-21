//! Strict JSON decoding, RFC 8785 canonicalization, and CNP/1 identities.
//!
//! ```text
//! CNP/1 || 00 || u32be(domain_length) || domain || u64be(payload_length) || payload
//! ```

use std::collections::BTreeMap;

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Number, Value};

use crate::{
    ContentRef, ContractError, HashRef, MAX_ARRAY_ELEMENTS, U64, Validate, invalid,
    values::validate_domain,
};

/// Decodes strict JSON with a byte ceiling and bounded nested arrays.
///
/// # Errors
/// Rejects oversized input, duplicate keys, invalid Unicode, nonfinite numbers,
/// excessive nesting, and arrays larger than the baseline limit.
pub fn parse_json(bytes: &[u8], maximum_bytes: usize) -> Result<Value, ContractError> {
    parse_json_with_depth(bytes, maximum_bytes, 64)
}

/// Decodes strict JSON under a negotiated nesting limit no greater than 64.
///
/// # Errors
/// Rejects zero or excessive depth limits and all malformed, oversized, or
/// excessively nested values rejected by [`parse_json`].
pub fn parse_json_with_depth(
    bytes: &[u8],
    maximum_bytes: usize,
    maximum_depth: usize,
) -> Result<Value, ContractError> {
    strict_parser::check_limits(bytes, maximum_bytes, maximum_depth)?;
    let mut state = CursorState {
        cursor: 0,
        maximum_depth,
    };
    let mut parser = Parser {
        bytes,
        state: &mut state,
    };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.state.cursor != bytes.len() {
        return Err(parser.error(strict_parser::Reason::TrailingContent));
    }
    Ok(value)
}

/// Decodes and validates a closed portable object.
///
/// # Errors
/// Rejects malformed or oversized JSON, unknown fields, noncanonical scalars,
/// and local schema invariant violations. Referenced content remains unresolved.
pub fn decode<T: DeserializeOwned + Validate>(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<T, ContractError> {
    let value = serde_json::from_value::<T>(parse_json(bytes, maximum_bytes)?)?;
    value.validate()?;
    Ok(value)
}

#[path = "canonical/strict_parser.rs"]
mod strict_parser;
use strict_parser::{CursorState, Parser};
pub use strict_parser::{
    STRICT_JSON_DIAGNOSTIC_TEXT_BYTES_DATA, STRICT_JSON_KEY_LOOKUP_STORAGE_DATA,
};

/// Encodes RFC 8785 JSON without changing Unicode string values.
///
/// # Errors
/// Rejects numeric values outside the finite IEEE-754 JCS representation and
/// arrays beyond the portable bound. Object keys sort by UTF-16 code units.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, ContractError> {
    let mut output = Vec::new();
    write_canonical(value, &mut output, 0)?;
    Ok(output)
}

/// Writes the authoritative canonical JSON to a caller-owned sink.
///
/// The sink can enforce an allocation or byte allowance before accepting each
/// write. This is the same RFC 8785 algorithm as [`canonical_json`]; partial
/// output on error must remain with its original operational owner.
///
/// # Errors
/// Refuses the same numeric, array and nesting violations as [`canonical_json`]
/// and propagates sink errors without restarting or replacing partial output.
pub fn canonical_json_to_writer(
    value: &Value,
    output: &mut impl std::io::Write,
) -> Result<(), ContractError> {
    write_canonical(value, output, 0)
}

fn write_canonical(
    value: &Value,
    output: &mut impl std::io::Write,
    depth: usize,
) -> Result<(), ContractError> {
    match value {
        Value::Null => output.write_all(b"null").map_err(serde_json::Error::io)?,
        Value::Bool(true) => output.write_all(b"true").map_err(serde_json::Error::io)?,
        Value::Bool(false) => output.write_all(b"false").map_err(serde_json::Error::io)?,
        Value::String(value) => output
            .write_all(serde_json::to_string(value)?.as_bytes())
            .map_err(serde_json::Error::io)?,
        Value::Number(number) => {
            // JCS uses the ECMAScript number algorithm even for JSON integer
            // tokens. Typed counters are strings, so they retain all 64 bits.
            let number = number
                .as_f64()
                .filter(|value| value.is_finite())
                .ok_or_else(|| invalid("number", "not a finite JCS number"))?;
            let mut buffer = ryu_js::Buffer::new();
            output
                .write_all(buffer.format(number).as_bytes())
                .map_err(serde_json::Error::io)?;
        }
        Value::Array(values) => {
            if depth >= 64 {
                return Err(invalid("json_depth", "nesting exceeds 64 containers"));
            }
            if values.len() > MAX_ARRAY_ELEMENTS {
                return Err(invalid("array", "exceeds 65536 elements"));
            }
            output.write_all(b"[").map_err(serde_json::Error::io)?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.write_all(b",").map_err(serde_json::Error::io)?;
                }
                write_canonical(value, output, depth + 1)?;
            }
            output.write_all(b"]").map_err(serde_json::Error::io)?;
        }
        Value::Object(values) => {
            if depth >= 64 {
                return Err(invalid("json_depth", "nesting exceeds 64 containers"));
            }
            let ordered: BTreeMap<Vec<u16>, (&str, &Value)> = values
                .iter()
                .map(|(key, value)| (key.encode_utf16().collect(), (key.as_str(), value)))
                .collect();
            output.write_all(b"{").map_err(serde_json::Error::io)?;
            for (index, (key, value)) in ordered.values().enumerate() {
                if index != 0 {
                    output.write_all(b",").map_err(serde_json::Error::io)?;
                }
                output
                    .write_all(serde_json::to_string(key)?.as_bytes())
                    .map_err(serde_json::Error::io)?;
                output.write_all(b":").map_err(serde_json::Error::io)?;
                write_canonical(value, output, depth + 1)?;
            }
            output.write_all(b"}").map_err(serde_json::Error::io)?;
        }
    }
    Ok(())
}

/// Builds the normative domain and payload length framing.
///
/// # Errors
/// Rejects invalid domains and unrepresentable payload or allocation lengths.
pub fn frame(domain: &str, payload: &[u8]) -> Result<Vec<u8>, ContractError> {
    validate_domain(domain)?;
    let domain_length = u32::try_from(domain.len()).map_err(|_| ContractError::Overflow)?;
    let payload_length = u64::try_from(payload.len()).map_err(|_| ContractError::Overflow)?;
    let capacity = 18usize
        .checked_add(domain.len())
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or(ContractError::Overflow)?;
    let mut framed = Vec::new();
    framed
        .try_reserve_exact(capacity)
        .map_err(|_| invalid("frame", "allocation refused"))?;
    framed.extend_from_slice(b"CNP/1\0");
    framed.extend_from_slice(&domain_length.to_be_bytes());
    framed.extend_from_slice(domain.as_bytes());
    framed.extend_from_slice(&payload_length.to_be_bytes());
    framed.extend_from_slice(payload);
    Ok(framed)
}

/// Computes an ordinary unkeyed BLAKE3-256 CNP/1 identity.
///
/// # Errors
/// Rejects invalid domains and unrepresentable payload lengths.
pub fn hash(domain: &str, payload: &[u8]) -> Result<HashRef, ContractError> {
    validate_domain(domain)?;
    let domain_length = u32::try_from(domain.len()).map_err(|_| ContractError::Overflow)?;
    let payload_length = u64::try_from(payload.len()).map_err(|_| ContractError::Overflow)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&domain_length.to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&payload_length.to_be_bytes());
    hasher.update(payload);
    Ok(HashRef {
        algorithm: "blake3-256".to_owned(),
        domain: domain.to_owned(),
        digest: hasher.finalize().to_hex().to_string(),
    })
}

/// Computes an identity over a value's UTF-8 JCS representation.
///
/// # Errors
/// Rejects serialization, canonicalization, domain, or length errors. Callers
/// must validate the selected schema before using its identity for admission.
pub fn json_hash(domain: &str, value: &impl Serialize) -> Result<HashRef, ContractError> {
    hash(domain, &canonical_json(&serde_json::to_value(value)?)?)
}

/// Describes exact opaque bytes as portable content.
///
/// # Errors
/// Rejects an invalid media type or an unrepresentable byte length.
pub fn content_ref(payload: &[u8], media_type: &str) -> Result<ContentRef, ContractError> {
    let reference = ContentRef {
        hash: hash("cnp.blob.v1", payload)?,
        length: U64::new(u64::try_from(payload.len()).map_err(|_| ContractError::Overflow)?),
        media_type: media_type.to_owned(),
    };
    reference.validate()?;
    Ok(reference)
}

/// Reports fixed controls of the scalar-number JCS writer.
///
/// The number branch borrows its input and writes Ryu's inline buffer directly;
/// it creates no whole-value DOM, string bank or ordering tree. Callers separately
/// price their own input value, sink and serializer frames.
pub fn canonical_number_counter_scratch_bytes_data() -> usize {
    use std::mem::size_of;
    size_of::<ryu_js::Buffer>()
        + size_of::<f64>()
        + size_of::<Option<f64>>()
        + size_of::<&serde_json::Number>()
        + size_of::<&[u8]>()
        + size_of::<Result<(), std::io::Error>>()
        + size_of::<Result<(), serde_json::Error>>()
        + size_of::<Result<(), ContractError>>()
}

#[path = "canonical/json_counter.rs"]
mod json_counter;
pub use json_counter::canonical_json_counter_scratch_bytes_data;

/// Names the strict JSON parser's fixed borrowed and container controls.
///
/// This declaration covers the actual Parser and each possible recursive
/// container frame under parse_json_with_depth's unchanged maximum of 64.
/// Container backing, parsed strings, errors and returned JSON trees require
/// an independently admitted constructor extent; this getter supplies none.
/// It is a requested-layout declaration, not a physical machine stack bound.
pub fn json_parse_counter_scratch_bytes_data() -> usize {
    use std::mem::size_of;

    let container = size_of::<&mut Parser<'static, 'static>>()
        + size_of::<usize>()
        + size_of::<Vec<Value>>()
        + size_of::<Map<String, Value>>()
        + size_of::<String>()
        + size_of::<Option<Value>>()
        + size_of::<Option<u8>>();
    let returned_value = size_of::<Value>() + size_of::<Result<Value, ContractError>>();

    strict_parser::TRANSITION_COUNTER_SCRATCH_BYTES
        + strict_parser::diagnostics::counter_scratch_data()
        + size_of::<CursorState>() // actual source-free cursor local
        + size_of::<Parser<'static, 'static>>()
        + 64 * container
        + 65 * returned_value
        // string() delegates one complete quoted token to this exact serde
        // slice decoder. It never recursively invokes another Parser::string.
        + size_of::<serde_json::Deserializer<serde_json::de::SliceRead<'static>>>()
        + size_of::<Result<String, serde_json::Error>>()
        + size_of::<ryu_js::Buffer>()
        + size_of::<Number>()
        + size_of::<Option<Number>>()
        + size_of::<&str>() * 2
        + size_of::<&[u8]>()
        + size_of::<usize>() * 2
        + size_of::<bool>() * 2
        + size_of::<f64>()
        + size_of::<Result<i64, std::num::ParseIntError>>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + size_of::<Result<f64, std::num::ParseFloatError>>()
        + size_of::<Result<&str, std::str::Utf8Error>>()
        + size_of::<ContractError>()
}
