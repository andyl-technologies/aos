//! Canonical versioned JSON and fixed-handle keys for protected catalog maps.
//!
//! The journal validates frames but leaves each catalog's payload schema to its
//! owner. These helpers reject alternate spellings of the same typed head or
//! record, so recovery cannot admit a noncanonical durable representation.

use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

/// Reports an invalid or unencodable canonical catalog payload.
#[derive(Debug, thiserror::Error)]
#[error("canonical catalog payload is invalid")]
pub struct CanonicalMapError;

#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeadEnvelope<T> {
    version: u16,
    head: T,
}

#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordEnvelope<T> {
    version: u16,
    record: T,
}

/// Encodes a versioned catalog head without imposing a publication size limit.
///
/// # Errors
///
/// Returns [`CanonicalMapError`] if the head cannot be serialized.
pub fn encode_head<T: Serialize>(head: &T, version: u16) -> Result<Vec<u8>, CanonicalMapError> {
    serde_json::to_vec(&HeadEnvelope { version, head }).map_err(|_| CanonicalMapError)
}

/// Decodes a head only when its bytes have the exact canonical representation.
///
/// # Errors
///
/// Returns [`CanonicalMapError`] for empty, oversized, malformed, unknown-version,
/// or noncanonical input.
pub fn decode_head<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    version: u16,
    maximum_bytes: usize,
) -> Result<T, CanonicalMapError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(CanonicalMapError);
    }

    let envelope: HeadEnvelope<T> = serde_json::from_slice(bytes).map_err(|_| CanonicalMapError)?;
    if envelope.version != version || encode_head(&envelope.head, version)? != bytes {
        return Err(CanonicalMapError);
    }
    Ok(envelope.head)
}

/// Encodes a versioned catalog record within its publication size bound.
///
/// # Errors
///
/// Returns [`CanonicalMapError`] if serialization fails or exceeds `maximum_bytes`.
pub fn encode_record<T: Serialize>(
    record: &T,
    version: u16,
    maximum_bytes: usize,
) -> Result<Vec<u8>, CanonicalMapError> {
    let bytes =
        serde_json::to_vec(&RecordEnvelope { version, record }).map_err(|_| CanonicalMapError)?;
    if bytes.len() > maximum_bytes {
        return Err(CanonicalMapError);
    }
    Ok(bytes)
}

/// Decodes a record only when its bytes have the exact canonical representation.
///
/// # Errors
///
/// Returns [`CanonicalMapError`] for empty, oversized, malformed, unknown-version,
/// or noncanonical input.
pub fn decode_record<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    version: u16,
    maximum_bytes: usize,
) -> Result<T, CanonicalMapError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(CanonicalMapError);
    }

    let envelope: RecordEnvelope<T> =
        serde_json::from_slice(bytes).map_err(|_| CanonicalMapError)?;
    if envelope.version != version
        || encode_record(&envelope.record, version, maximum_bytes)? != bytes
    {
        return Err(CanonicalMapError);
    }
    Ok(envelope.record)
}

/// Appends one fixed-size handle to its catalog-specific key prefix.
#[must_use]
pub fn record_key(prefix: &[u8], handle: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + handle.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(handle);
    key
}

/// Decodes one nonzero fixed-size handle from its exact key prefix.
#[must_use]
pub fn decode_record_key(prefix: &[u8], key: &[u8]) -> Option<[u8; 32]> {
    key.strip_prefix(prefix)
        .and_then(|suffix| suffix.try_into().ok())
        .filter(|handle| *handle != [0; 32])
}

/// Derives a nonzero transaction ID from a catalog-specific domain and parts.
#[must_use]
pub fn transaction_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update(part);
    }
    let digest: [u8; 32] = digest.finalize().into();
    let mut transaction_id = [0; 16];
    transaction_id.copy_from_slice(&digest[..16]);
    if transaction_id == [0; 16] {
        transaction_id[15] = 1;
    }
    transaction_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq, serde::Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        id: u8,
    }

    #[test]
    fn rejects_alternate_head_and_record_encodings() {
        let sample = Sample { id: 7 };
        let head = encode_head(&sample, 1).unwrap();
        let record = encode_record(&sample, 1, 100).unwrap();
        assert_eq!(head, br#"{"version":1,"head":{"id":7}}"#);
        assert_eq!(record, br#"{"version":1,"record":{"id":7}}"#);

        for hostile in [
            br#"{"version":2,"head":{"id":7}}"#.as_slice(),
            br#"{"head":{"id":7},"version":1}"#,
            br#"{"version":1,"head":{"id":7},"extra":0}"#,
            br#"{"version":1,"version":1,"head":{"id":7}}"#,
            b"",
        ] {
            assert!(decode_head::<Sample>(hostile, 1, 100).is_err());
        }
        for hostile in [
            br#"{"version":2,"record":{"id":7}}"#.as_slice(),
            br#"{"record":{"id":7},"version":1}"#,
            br#"{"version":1,"record":{"id":7,"extra":0}}"#,
            br#"{"version":1,"record":{"id":7,"id":7}}"#,
            b"",
        ] {
            assert!(decode_record::<Sample>(hostile, 1, 100).is_err());
        }

        assert_eq!(decode_head::<Sample>(&head, 1, head.len()).unwrap(), sample);
        assert_eq!(
            decode_record::<Sample>(&record, 1, record.len()).unwrap(),
            sample
        );
        assert!(decode_head::<Sample>(&head, 1, head.len() - 1).is_err());
        assert!(decode_record::<Sample>(&record, 1, record.len() - 1).is_err());
        assert!(encode_record(&sample, 1, record.len() - 1).is_err());
    }

    #[test]
    fn fixed_handle_key_rejects_wrong_prefix_length_and_zero() {
        let prefix = b"catalog\0";
        let handle = [7; 32];
        let key = record_key(prefix, &handle);

        assert_eq!(decode_record_key(prefix, &key), Some(handle));
        assert_eq!(decode_record_key(b"other\0", &key), None);
        assert_eq!(decode_record_key(prefix, &key[..key.len() - 1]), None);
        assert_eq!(
            decode_record_key(prefix, &record_key(prefix, &[0; 32])),
            None
        );
    }
}
