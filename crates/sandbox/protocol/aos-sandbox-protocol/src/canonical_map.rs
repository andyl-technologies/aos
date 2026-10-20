//! Canonical versioned JSON and fixed-handle keys for protected catalog maps.
//!
//! The journal validates frames but leaves each catalog's payload schema to its
//! owner. These helpers reject alternate spellings of the same typed head or
//! record, so recovery cannot admit a noncanonical durable representation.
//!
//! The versioned envelopes retain the typed value's serialization:
//!
//! ```text
//! {"version":1,"head":<typed head>}
//! {"version":1,"record":<typed record>}
//! ```
//! Schema validation, admission, and durable publication remain with each
//! catalog owner; these encodings and keys do not establish authority.

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

/// Reports canonical serialization or prepaid byte admission failure.
///
/// The accounting marker refers to the supplied ledger's retained first cause;
/// it does not replace that error or confer any publication authority.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalMapReceivingErrorV1 {
    /// Preserves the actual local byte-count arithmetic refusal.
    #[error(transparent)]
    Arithmetic(#[from] aos_sandbox_model::AccountingError),
    /// Indicates the supplied ledger retains the exact refused reservation.
    #[error("canonical catalog receiving account is closed")]
    Accounting,
    /// Preserves the ordinary canonical payload error.
    #[error(transparent)]
    Canonical(#[from] CanonicalMapError),
}

#[derive(Default)]
struct EncodedByteCount {
    bytes: usize,
}

impl std::io::Write for EncodedByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn payload_encoding_demand_v1<T: Serialize>(payload: &T)
    -> Result<aos_sandbox_model::ResourceVector, CanonicalMapReceivingErrorV1>
{
    use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
    let mut count = EncodedByteCount::default();
    serde_json::to_writer(&mut count, payload).map_err(|_| CanonicalMapError)?;
    let bytes = count.bytes.max(128).checked_mul(3)
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<Vec<u8>>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<EncodedByteCount>()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
}

/// Counts a head's reached serialization peak without allocating its buffer.
///
/// The returned portable DATA establishes no payment or publication authority.
///
/// # Errors
/// Returns serialization failure or checked byte-count overflow.
pub fn head_encoding_demand_v1<T: Serialize>(head: &T, version: u16)
    -> Result<aos_sandbox_model::ResourceVector, CanonicalMapReceivingErrorV1>
{
    payload_encoding_demand_v1(&HeadEnvelope { version, head })
}

/// Counts a record's reached serialization peak without allocating its buffer.
///
/// The returned portable DATA establishes no payment or publication authority.
///
/// # Errors
/// Returns serialization failure or checked byte-count overflow. The ordinary
/// encoder still performs its existing maximum-size check after serialization.
pub fn record_encoding_demand_v1<T: Serialize>(record: &T, version: u16)
    -> Result<aos_sandbox_model::ResourceVector, CanonicalMapReceivingErrorV1>
{
    payload_encoding_demand_v1(&RecordEnvelope { version, record })
}

// Ordinary and selected calls use this one serializer. Only selected DATA
// receives an allocation-free pass and charges its SAME borrowed ledger before
// Vec growth; actual typed value/envelope models are paid by their owner.
fn encode_payload_v1<T: Serialize>(
    payload: &T,
    maximum_bytes: Option<usize>,
    ledger: Option<&mut aos_sandbox_model::component_receiving::ComponentServiceReceivingLedgerV1>,
) -> Result<Vec<u8>, CanonicalMapReceivingErrorV1> {
    if let Some(ledger) = ledger {
        let demand = payload_encoding_demand_v1(payload)?;
        ledger.reserve(demand)
            .map_err(|_| CanonicalMapReceivingErrorV1::Accounting)?;
    }
    let bytes = serde_json::to_vec(payload).map_err(|_| CanonicalMapError)?;
    if maximum_bytes.is_some_and(|maximum| bytes.len() > maximum) {
        return Err(CanonicalMapError.into());
    }
    Ok(bytes)
}

/// Encodes a head after charging its reached byte peak on the supplied ledger.
///
/// This is portable DATA, not a receiving original or permission to publish.
///
/// # Errors
/// Returns the canonical payload failure, arithmetic overflow or a marker for
/// the ledger's original retained reservation refusal.
pub fn encode_head_receiving_v1<T: Serialize>(
    head: &T,
    version: u16,
    ledger: &mut aos_sandbox_model::component_receiving::ComponentServiceReceivingLedgerV1,
) -> Result<Vec<u8>, CanonicalMapReceivingErrorV1> {
    encode_payload_v1(&HeadEnvelope { version, head }, None, Some(ledger))
}

/// Encodes a record after charging its reached byte peak on the supplied ledger.
///
/// This is portable DATA; publication still requires the owner's native stage.
///
/// # Errors
/// Returns the original canonical size/serialization error, arithmetic overflow
/// or a marker for the supplied ledger's exact retained reservation refusal.
pub fn encode_record_receiving_v1<T: Serialize>(
    record: &T,
    version: u16,
    maximum_bytes: usize,
    ledger: &mut aos_sandbox_model::component_receiving::ComponentServiceReceivingLedgerV1,
) -> Result<Vec<u8>, CanonicalMapReceivingErrorV1> {
    encode_payload_v1(&RecordEnvelope { version, record }, Some(maximum_bytes), Some(ledger))
}

/// Encodes a versioned catalog head without imposing a publication size limit.
///
/// # Errors
///
/// Returns [`CanonicalMapError`] if the head cannot be serialized.
pub fn encode_head<T: Serialize>(head: &T, version: u16) -> Result<Vec<u8>, CanonicalMapError> {
    encode_payload_v1(&HeadEnvelope { version, head }, None, None).map_err(|_| CanonicalMapError)
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
    encode_payload_v1(&RecordEnvelope { version, record }, Some(maximum_bytes), None)
        .map_err(|_| CanonicalMapError)
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
    fn prepaid_encoding_preserves_bytes_limits_and_same_ledger_failure() {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_model::component_receiving::ComponentServiceReceivingLedgerV1;
        let sample = Sample { id: 7 };
        let mut paid = ComponentServiceReceivingLedgerV1::new(
            ResourceVector::ZERO.with(D::MemoryBytes, 4096),
        );
        let ordinary = encode_record(&sample, 1, 100).unwrap();
        let selected = encode_record_receiving_v1(&sample, 1, 100, &mut paid).unwrap();
        assert_eq!(selected, ordinary);
        assert_eq!(paid.charged(), record_encoding_demand_v1(&sample, 1).unwrap());
        assert!(paid.charged().get(D::MemoryBytes) >= selected.len() as u64);
        let mut head_paid = ComponentServiceReceivingLedgerV1::new(
            ResourceVector::ZERO.with(D::MemoryBytes, 4096),
        );
        assert_eq!(encode_head_receiving_v1(&sample, 1, &mut head_paid).unwrap(),
            encode_head(&sample, 1).unwrap());
        assert_eq!(head_paid.charged(), head_encoding_demand_v1(&sample, 1).unwrap());
        assert!(matches!(encode_record_receiving_v1(&sample, 1, ordinary.len() - 1, &mut paid),
            Err(CanonicalMapReceivingErrorV1::Canonical(_))));

        let mut refused = ComponentServiceReceivingLedgerV1::new(ResourceVector::ZERO);
        assert!(matches!(encode_head_receiving_v1(&sample, 1, &mut refused),
            Err(CanonicalMapReceivingErrorV1::Accounting)));
        let first = refused.failure().unwrap() as *const _;
        assert!(matches!(encode_record_receiving_v1(&sample, 1, 100, &mut refused),
            Err(CanonicalMapReceivingErrorV1::Accounting)));
        assert_eq!(first, refused.failure().unwrap() as *const _);
        assert_eq!(refused.charged(), ResourceVector::ZERO);
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
