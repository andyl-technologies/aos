//! Strict JSON parsing, integer JCS, SHA-256, and Ed25519 primitives.
//!
//! The cutover dialect rejects duplicate members, floating-point values, and
//! integers outside the exact I-JSON range before canonicalization.

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use ed25519_dalek::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// Parses closed cutover JSON without silently accepting duplicate keys.
pub(super) fn parse_json(bytes: &[u8], label: &str) -> Result<Value> {
    aos_release::canonical::parse_json(bytes, label)
}

/// Produces the cutover dialect's exact integer-only RFC 8785 encoding.
pub(super) fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    aos_release::canonical::canonical_json(value)
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
    aos_release::canonical::reject_placeholder_hashes(value, path)
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
