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
    if maximum_depth == 0 || maximum_depth > 64 {
        return Err(invalid(
            "json_depth",
            "require a nesting limit between 1 and 64",
        ));
    }
    if bytes.len() > maximum_bytes {
        return Err(invalid("json", "frame exceeds admitted byte limit"));
    }
    let mut parser = Parser {
        bytes,
        cursor: 0,
        maximum_depth,
    };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.cursor != bytes.len() {
        return Err(parser.error("trailing JSON content"));
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

// CNP numbers use Rust's correctly rounded decimal-to-binary conversion.
// Enabling serde_json's float_roundtrip feature would change legacy consumers
// through Cargo feature unification, so this parser owns numeric tokenization.
struct Parser<'a> {
    bytes: &'a [u8],
    cursor: usize,
    maximum_depth: usize,
}

impl Parser<'_> {
    fn error(&self, reason: &str) -> ContractError {
        invalid("json", format!("{reason} at byte {}", self.cursor))
    }

    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.cursor)
            .is_some_and(|byte| b" \n\r\t".contains(byte))
        {
            self.cursor += 1;
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.cursor) == Some(&byte) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ContractError> {
        self.whitespace();
        match self.bytes.get(self.cursor).copied() {
            Some(b'"') => self.string().map(Value::String),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.error("expected JSON value")),
        }
    }

    fn literal(&mut self, literal: &[u8], value: Value) -> Result<Value, ContractError> {
        if !self.bytes[self.cursor..].starts_with(literal) {
            return Err(self.error("invalid JSON literal"));
        }
        self.cursor += literal.len();
        Ok(value)
    }

    fn string(&mut self) -> Result<String, ContractError> {
        let start = self.cursor;
        if !self.take(b'"') {
            return Err(self.error("expected JSON string"));
        }
        while let Some(byte) = self.bytes.get(self.cursor).copied() {
            self.cursor += 1;
            match byte {
                b'"' => return Ok(serde_json::from_slice(&self.bytes[start..self.cursor])?),
                b'\\' => {
                    // Skip the escaped byte when finding the closing quote;
                    // serde validates escapes, UTF-8, and surrogate pairing.
                    if self.cursor == self.bytes.len() {
                        break;
                    }
                    self.cursor += 1;
                }
                _ => {}
            }
        }
        Err(self.error("unterminated JSON string"))
    }

    fn array(&mut self, depth: usize) -> Result<Value, ContractError> {
        if depth >= self.maximum_depth {
            return Err(self.error("JSON nesting limit exceeded"));
        }
        self.cursor += 1;
        self.whitespace();
        let mut values = Vec::new();
        if self.take(b']') {
            return Ok(Value::Array(values));
        }
        loop {
            if values.len() == MAX_ARRAY_ELEMENTS {
                return Err(self.error("array exceeds 65536 elements"));
            }
            values.push(self.value(depth + 1)?);
            self.whitespace();
            if self.take(b']') {
                return Ok(Value::Array(values));
            }
            if !self.take(b',') {
                return Err(self.error("expected array comma or close"));
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ContractError> {
        if depth >= self.maximum_depth {
            return Err(self.error("JSON nesting limit exceeded"));
        }
        self.cursor += 1;
        self.whitespace();
        let mut values = Map::new();
        if self.take(b'}') {
            return Ok(Value::Object(values));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            if values.contains_key(&key) {
                return Err(self.error("duplicate object key"));
            }
            self.whitespace();
            if !self.take(b':') {
                return Err(self.error("expected object colon"));
            }
            values.insert(key, self.value(depth + 1)?);
            self.whitespace();
            if self.take(b'}') {
                return Ok(Value::Object(values));
            }
            if !self.take(b',') {
                return Err(self.error("expected object comma or close"));
            }
        }
    }

    fn digits(&mut self) -> bool {
        let start = self.cursor;
        while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
            self.cursor += 1;
        }
        self.cursor != start
    }

    fn number(&mut self) -> Result<Value, ContractError> {
        let start = self.cursor;
        let negative = self.take(b'-');
        match self.bytes.get(self.cursor).copied() {
            Some(b'0') => {
                self.cursor += 1;
            }
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.error("invalid integer part")),
        }
        let mut fractional = false;
        if self.take(b'.') {
            fractional = true;
            if !self.digits() {
                return Err(self.error("missing fractional digits"));
            }
        }
        if self.take(b'e') || self.take(b'E') {
            fractional = true;
            if !self.take(b'+') {
                self.take(b'-');
            }
            if !self.digits() {
                return Err(self.error("missing exponent digits"));
            }
        }
        let token = std::str::from_utf8(&self.bytes[start..self.cursor])
            .map_err(|_| self.error("invalid number encoding"))?;
        if !fractional {
            if negative {
                if let Ok(value) = token.parse::<i64>() {
                    return Ok(Value::Number(value.into()));
                }
            } else if let Ok(value) = token.parse::<u64>() {
                return Ok(Value::Number(value.into()));
            }
        }
        let float = token
            .parse::<f64>()
            .map_err(|_| self.error("invalid finite number"))?;
        // JSON Schema integer fields accept integral decimal/exponent tokens.
        // Normalize their correctly rounded value locally; enabling a global
        // serde feature would change legacy formats outside the CNP boundary.
        if float.is_finite() {
            let mut buffer = ryu_js::Buffer::new();
            let integral = buffer.format(float);
            if let Ok(value) = integral.parse::<u64>() {
                return Ok(Value::Number(value.into()));
            }
            if let Ok(value) = integral.parse::<i64>() {
                return Ok(Value::Number(value.into()));
            }
        }
        Number::from_f64(float)
            .map(Value::Number)
            .ok_or_else(|| self.error("nonfinite number"))
    }
}

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

fn write_canonical(value: &Value, output: &mut Vec<u8>, depth: usize) -> Result<(), ContractError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::String(value) => output.extend_from_slice(serde_json::to_string(value)?.as_bytes()),
        Value::Number(number) => {
            // JCS uses the ECMAScript number algorithm even for JSON integer
            // tokens. Typed counters are strings, so they retain all 64 bits.
            let number = number
                .as_f64()
                .filter(|value| value.is_finite())
                .ok_or_else(|| invalid("number", "not a finite JCS number"))?;
            let mut buffer = ryu_js::Buffer::new();
            output.extend_from_slice(buffer.format(number).as_bytes());
        }
        Value::Array(values) => {
            if depth >= 64 {
                return Err(invalid("json_depth", "nesting exceeds 64 containers"));
            }
            if values.len() > MAX_ARRAY_ELEMENTS {
                return Err(invalid("array", "exceeds 65536 elements"));
            }
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(value, output, depth + 1)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            if depth >= 64 {
                return Err(invalid("json_depth", "nesting exceeds 64 containers"));
            }
            let ordered: BTreeMap<Vec<u16>, (&str, &Value)> = values
                .iter()
                .map(|(key, value)| (key.encode_utf16().collect(), (key.as_str(), value)))
                .collect();
            output.push(b'{');
            for (index, (key, value)) in ordered.values().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                output.push(b':');
                write_canonical(value, output, depth + 1)?;
            }
            output.push(b'}');
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
