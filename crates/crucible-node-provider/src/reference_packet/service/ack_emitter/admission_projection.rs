//! Borrows the fixed assigned-Admit proof grammar without issuing admission.
//!
//! The native issuer separately authenticates its original key and context.

use crate::ProviderError;
use serde_json::Value;

// A 32-byte unpadded base64 value has 43 characters and two zero trailing bits.
// The fixed alphabet check also rejects noncanonical alternate encodings.
pub(crate) fn validate_proof_value(value: &Value) -> Result<(), ProviderError> {
    let invalid = || ProviderError::Correlation("canonical ACK borrowed proof grammar");
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != 4
        || object.get("schema").and_then(Value::as_str)
            != Some(super::PACKET_CANONICAL_ACK_ADMISSION_FEATURE)
        || object.get("algorithm").and_then(Value::as_str)
            != Some(super::PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM)
    {
        return Err(invalid());
    }
    for field in ["context_digest", "mac"] {
        let encoded = object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if encoded.len() != 43
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !encoded.as_bytes().last().is_some_and(|byte| {
                matches!(
                    byte,
                    b'A' | b'E'
                        | b'I'
                        | b'M'
                        | b'Q'
                        | b'U'
                        | b'Y'
                        | b'c'
                        | b'g'
                        | b'k'
                        | b'o'
                        | b's'
                        | b'w'
                        | b'0'
                        | b'4'
                        | b'8'
                )
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_admission_proof_refuses_unknown_fields_and_noncanonical_octets() {
        let mut proof = serde_json::json!({
            "schema": super::super::PACKET_CANONICAL_ACK_ADMISSION_FEATURE,
            "algorithm": super::super::PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM,
            "context_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "mac": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        });
        assert!(validate_proof_value(&proof).is_ok());

        proof["mac"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB");
        assert!(validate_proof_value(&proof).is_err());
        proof["mac"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        assert!(validate_proof_value(&proof).is_err());
        proof["mac"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        proof["authority"] = serde_json::json!(true);
        assert!(validate_proof_value(&proof).is_err());
    }
}
