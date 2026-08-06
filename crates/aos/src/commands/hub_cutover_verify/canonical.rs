//! Strict JSON parsing, integer JCS, SHA-256, and Ed25519 primitives.
//!
//! The cutover dialect rejects duplicate members, floating-point values, and
//! integers outside the exact I-JSON range before canonicalization.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use ed25519_dalek::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// Parses closed cutover JSON without silently accepting duplicate keys.
pub(super) fn parse_json(bytes: &[u8], label: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueValue::deserialize(&mut deserializer)
        .with_context(|| format!("invalid {label} JSON"))?;
    deserializer
        .end()
        .with_context(|| format!("trailing data in {label} JSON"))?;
    Ok(value.0)
}

/// Produces the cutover dialect's exact integer-only RFC 8785 encoding.
pub(super) fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    reject_non_i_json_numbers(value, "")?;
    let mut output = Vec::new();
    write_canonical(value, &mut output)?;
    Ok(output)
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                output.extend_from_slice(integer.to_string().as_bytes());
            } else if let Some(integer) = number.as_u64() {
                output.extend_from_slice(integer.to_string().as_bytes());
            } else {
                bail!("JCS rejects non-integer numbers in cutover v1");
            }
        }
        Value::String(text) => {
            output.extend_from_slice(serde_json::to_string(text)?.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, child) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(child, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            let mut members: Vec<_> = object.iter().collect();
            if members.iter().any(|(name, _)| !name.is_ascii()) {
                bail!("cutover v1 requires ASCII object member names");
            }
            members.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            output.push(b'{');
            for (index, (name, child)) in members.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(serde_json::to_string(name)?.as_bytes());
                output.push(b':');
                write_canonical(child, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn reject_non_i_json_numbers(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Number(number) => {
            const MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_991;
            let exact = number
                .as_i64()
                .map(|integer| integer.unsigned_abs() <= MAX_EXACT_INTEGER)
                .or_else(|| number.as_u64().map(|integer| integer <= MAX_EXACT_INTEGER))
                .unwrap_or(false);
            if !exact {
                bail!("non_i_json_number at {path}");
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_non_i_json_numbers(child, &format!("{path}/{index}"))?;
            }
        }
        Value::Object(object) => {
            for (name, child) in object {
                reject_non_i_json_numbers(child, &format!("{path}/{name}"))?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

/// Computes a domain-separated digest over canonical bytes.
pub(super) fn separated_digest(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(payload);
    digest.finalize().into()
}

/// Computes SHA-256 over exact bytes.
pub(super) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Encodes bytes as lowercase hexadecimal.
pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(*byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(*byte & 0x0f)]));
    }
    output
}

/// Parses an exact 32-byte lowercase or uppercase hexadecimal digest.
pub(super) fn parse_sha256(value: &str, label: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{label} SHA-256 must contain exactly 64 hexadecimal digits");
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).context("decoding SHA-256 text")?;
        digest[index] = u8::from_str_radix(pair, 16).context("decoding SHA-256 text")?;
    }
    Ok(digest)
}

/// Parses raw, hexadecimal, base64, or PKCS#8 PEM Ed25519 public-key bytes.
pub(super) fn parse_public_key(bytes: &[u8]) -> Result<VerifyingKey> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if text.trim_start().starts_with("-----BEGIN PUBLIC KEY-----") {
            let encoded: String = text
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .map(str::trim)
                .collect();
            let der = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .context("invalid public-key PEM base64")?;
            return VerifyingKey::from_public_key_der(&der)
                .context("invalid Ed25519 public key DER");
        }
    }
    let decoded = decode_fixed_material(bytes, 32, "Ed25519 public key")?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("Ed25519 public key must contain 32 bytes"))?;
    VerifyingKey::from_bytes(&key).context("invalid Ed25519 public key")
}

/// Parses an Ed25519 PKCS#8 DER or PEM private key.
pub(super) fn parse_signing_key(bytes: &[u8]) -> Result<SigningKey> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if text.trim_start().starts_with("-----BEGIN PRIVATE KEY-----") {
            let encoded: String = text
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .map(str::trim)
                .collect();
            let der = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .context("invalid signing-key PEM base64")?;
            return SigningKey::from_pkcs8_der(&der).context("invalid Ed25519 PKCS#8 signing key");
        }
    }
    SigningKey::from_pkcs8_der(bytes).context("invalid Ed25519 PKCS#8 signing key")
}

fn decode_fixed_material(bytes: &[u8], length: usize, label: &str) -> Result<Vec<u8>> {
    if bytes.len() == length {
        return Ok(bytes.to_vec());
    }
    let text = std::str::from_utf8(bytes)
        .with_context(|| format!("{label} is neither raw bytes nor UTF-8"))?
        .trim();
    if text.len() == length * 2 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let mut decoded = Vec::with_capacity(length);
        for chunk in text.as_bytes().chunks_exact(2) {
            let pair = std::str::from_utf8(chunk).context("decoding hexadecimal key material")?;
            decoded.push(u8::from_str_radix(pair, 16).context("decoding key material")?);
        }
        return Ok(decoded);
    }
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(decoded) = engine.decode(text) {
            if decoded.len() == length {
                return Ok(decoded);
            }
        }
    }
    bail!("{label} does not contain exactly {length} bytes")
}

/// Verifies an Ed25519 signature over an already separated digest.
pub(super) fn verify_detached(
    key: &VerifyingKey,
    digest: &[u8; 32],
    signature_bytes: &[u8],
    label: &str,
) -> Result<()> {
    let decoded = decode_fixed_material(signature_bytes, 64, &format!("{label} signature"))?;
    let signature =
        Signature::from_slice(&decoded).context("invalid Ed25519 signature encoding")?;
    key.verify(digest, &signature)
        .with_context(|| format!("{label}_signature_invalid"))
}

/// Rejects obvious placeholder-pattern digests recursively.
pub(super) fn reject_placeholder_hashes(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (name, child) in object {
                reject_placeholder_hashes(child, &format!("{path}/{name}"))?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_placeholder_hashes(child, &format!("{path}/{index}"))?;
            }
        }
        Value::String(text)
            if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            let unique: BTreeSet<_> = text.bytes().collect();
            if unique.len() <= 2 {
                bail!("placeholder-pattern hash rejected at {path}");
            }
        }
        _ => {}
    }
    Ok(())
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object members or floating-point values")
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("cutover v1 rejects floating-point JSON numbers"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = serde_json::Map::new();
        while let Some((name, value)) = map.next_entry::<String, UniqueValue>()? {
            if object.insert(name.clone(), value.0).is_some() {
                return Err(de::Error::custom(format!("duplicate JSON member: {name}")));
            }
        }
        Ok(UniqueValue(Value::Object(object)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_member_order_is_stable() -> Result<()> {
        let left = serde_json::json!({"b": 2, "a": 1});
        let right = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(canonical_json(&left)?, canonical_json(&right)?);
        Ok(())
    }

    #[test]
    fn parser_rejects_duplicate_members_and_floats() {
        assert!(parse_json(br#"{"a":1,"a":2}"#, "duplicate").is_err());
        assert!(parse_json(br#"{"value":1.5}"#, "float").is_err());
    }

    #[test]
    fn ascii_dialect_rejects_non_ascii_member_names() {
        let value = serde_json::json!({"é": 1});
        assert!(canonical_json(&value).is_err());
    }
}
