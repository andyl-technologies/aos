//! Owns bounded, domain-separated compiler commitment consistency DATA.
//!
//! The canonical frame is:
//!
//! ```text
//! u64be(domain length) | domain | u64be(JSON length) | JSON
//! ```
//!
//! These encodings and hashes establish byte consistency, never authenticated
//! input provenance, current publication, or a native effect permit.

use std::io::{self, Write};

use aos_sandbox_model::{ObjectDescriptor, ObjectDigest};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// Maximum bytes accepted by the existing canonical object encoding.
pub const MAXIMUM_CANONICAL_OBJECT_BYTES: usize = 8 * 1024 * 1024;

const BYTE_COUNT_OVERFLOW: &str = "canonical byte count overflow";
const BYTE_CAP_EXCEEDED: &str = "canonical byte cap exceeded";
const ALLOCATION_FAILED: &str = "canonical allocation failed";

/// Reports a bounded canonical consistency encoding failure.
#[derive(Debug, thiserror::Error)]
pub enum PolicyCanonicalDataErrorV1 {
    /// The deterministic serializer rejected the supplied DATA.
    #[error("normalized semantics could not be encoded")]
    CanonicalEncoding,
    /// The complete object exceeds its existing byte ceiling.
    #[error("canonical object exceeds its byte cap")]
    CanonicalObjectTooLarge,
}

/// Encodes bounded, domain-separated canonical consistency DATA.
///
/// The encoding grants no input provenance, publication currentness or effect
/// authority, even when a caller serializes proof-shaped claims.
///
/// # Errors
///
/// Returns [`PolicyCanonicalDataErrorV1`] if encoding fails or exceeds the existing
/// canonical-object bound.
pub fn canonical_bytes<T: Serialize>(
    domain: &'static [u8],
    value: &T,
) -> Result<Vec<u8>, PolicyCanonicalDataErrorV1> {
    let mut writer = BoundedCanonicalWriter::new(MAXIMUM_CANONICAL_OBJECT_BYTES);
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.exceeded {
            PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge
        } else {
            PolicyCanonicalDataErrorV1::CanonicalEncoding
        }
    })?;
    let payload = writer.bytes;
    let capacity = domain
        .len()
        .checked_add(payload.len())
        .and_then(|length| length.checked_add(16))
        .ok_or(PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge)?;
    if capacity > MAXIMUM_CANONICAL_OBJECT_BYTES {
        return Err(PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge)?;
    bytes.extend_from_slice(
        &u64::try_from(domain.len())
            .map_err(|_| PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(
        &u64::try_from(payload.len())
            .map_err(|_| PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

/// Bounds writer-IO error backing for the actual closed typed policy serializers.
///
/// The caller pays this before the counting pass, whose fixed controls do not
/// contain the error allocations. This is not a bound for arbitrary `T: Serialize`:
/// a custom serializer may create an unbounded Message. The actual Explanation
/// and strict decoded claims use closed derived serialization; the only failure
/// source is the existing writer. The pinned serde JSON error holds one boxed
/// code plus line/column; its code has only IO and boxed-text payload variants.
/// The pinned Rust IO custom owner holds its kind, erased error and two drop
/// function pointers. String conversion adds one boxed String and its bytes.
/// These concrete field envelopes bound those private layouts without naming
/// unstable dependency internals. They create no error or allocation here.
///
/// Returns `None` on checked arithmetic overflow.
#[doc(hidden)]
#[must_use]
pub fn canonical_serialization_failure_backing_bytes_v1() -> Option<usize> {
    use std::{error::Error, mem::size_of, ptr::NonNull};

    let serde_error = serde_error_heap_bytes_v1();
    let io_custom = size_of::<(io::ErrorKind, NonNull<dyn Error + Send + Sync>, fn(), fn())>();
    let message = BYTE_COUNT_OVERFLOW.len()
        .max(BYTE_CAP_EXCEEDED.len())
        .max(ALLOCATION_FAILED.len());
    serde_error.checked_add(io_custom)?
        .checked_add(size_of::<String>())?
        .checked_add(message)
}

// The private serde ErrorCode has only IO and Box<str> payload alternatives.
// Including both plus an aligned tag bounds its boxed code/line/column layout.
fn serde_error_heap_bytes_v1() -> usize {
    std::mem::size_of::<(io::Error, Box<str>, usize, usize, usize)>()
}

/// Bounds one reached strict JSON decoder's separately owned error message.
///
/// The actual schema owns the static expected-field/variant/visitor roster.
/// Untrusted names and numeric spellings consume the actual encoded extent.
/// String construction/growth and shrink-to-Box<str> are separate from decoded
/// model/path/escape backing. This geometry parses and authenticates nothing.
///
/// Returns `None` on checked arithmetic overflow.
#[doc(hidden)]
#[must_use]
pub fn canonical_json_decode_error_receiving_bytes_v1(
    encoded_bytes: usize,
    static_context_bytes: usize,
) -> Option<usize> {
    // Rust/Serde's Unexpected::Str uses Debug escaping. The longest
    // single-byte spelling is DEL as \u{7f}; longer Unicode scalars consume
    // more input bytes. This is scalar error spelling, separate from growth.
    let escaped_scalar = encoded_bytes.checked_mul(b"\\u{7f}".len())?;
    let message = escaped_scalar.checked_add(static_context_bytes)?;
    serde_error_heap_bytes_v1()
        .checked_add(message.max(8).checked_mul(4)?)?
        .checked_add(std::mem::size_of::<String>().checked_mul(2)?)
}

/// Bounds the existing canonical serializer's bytes and concrete controls.
///
/// `payload_bytes` is a source-derived upper bound for the actual typed JSON
/// payload, including omitted optional fields reintroduced by serialization.
/// It is not the configured object ceiling. The geometric writer and exact
/// framed destination coexist; digest controls are streaming and add no bytes.
/// No encoding, allocation, validation or authority is performed here.
///
/// Returns `None` on checked arithmetic overflow.
#[doc(hidden)]
#[must_use]
pub fn canonical_model_receiving_bytes_v1(
    payload_bytes: usize,
    domain_bytes: usize,
) -> Option<usize> {
    use std::mem::size_of;

    let frame = payload_bytes.checked_add(domain_bytes)?.checked_add(16)?;
    let backing = payload_bytes.max(1).checked_mul(4)?.checked_add(frame)?;
    let controls = size_of::<BoundedCanonicalWriter>().checked_mul(2)?
        .checked_add(size_of::<serde_json::Serializer<&mut BoundedCanonicalWriter>>().checked_mul(2)?)?
        .checked_add(size_of::<Vec<u8>>().checked_mul(3)?)?
        .checked_add(size_of::<Result<Vec<u8>, PolicyCanonicalDataErrorV1>>())?
        .checked_add(size_of::<CountingCanonicalWriter>().checked_mul(2)?)?
        .checked_add(size_of::<serde_json::Serializer<&mut CountingCanonicalWriter>>().checked_mul(2)?)?
        .checked_add(size_of::<Sha256>().checked_mul(2)?)?
        .checked_add(size_of::<DigestCanonicalWriter<'_>>().checked_mul(2)?)?
        .checked_add(size_of::<serde_json::Serializer<DigestCanonicalWriter<'_>>>().checked_mul(2)?)?
        .checked_add(size_of::<Result<ObjectDigest, PolicyCanonicalDataErrorV1>>())?;
    backing.checked_add(controls)?
        .checked_add(canonical_serialization_failure_backing_bytes_v1()?)
}

/// Counts the bounded canonical JSON payload without allocating its bytes.
///
/// # Errors
/// Returns an encoding or byte-cap refusal from the same canonical writer.
pub fn canonical_payload_size_v1<T: Serialize>(
    value: &T,
) -> Result<usize, PolicyCanonicalDataErrorV1> {
    let mut writer = CountingCanonicalWriter::new(MAXIMUM_CANONICAL_OBJECT_BYTES);
    serde_json::to_writer(&mut writer, value).map_err(|_| {
        if writer.exceeded {
            PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge
        } else {
            PolicyCanonicalDataErrorV1::CanonicalEncoding
        }
    })?;
    Ok(writer.length)
}

/// Bounds the fixed counter, serializer and returned control representations.
///
/// This measures Memory-only DATA for the existing counting operation. The
/// supplied value's model, serializer error backing and any later encoded
/// output remain separate receiving terms. A width grants no admission.
#[must_use]
pub fn canonical_payload_count_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;

    // Constructed, returned and caller-retained representations are distinct;
    // no optimizer or spare-padding credit is assumed between these planes.
    size_of::<CountingCanonicalWriter>()
        .checked_add(size_of::<serde_json::Serializer<&mut CountingCanonicalWriter>>())?
        .checked_add(size_of::<Result<(), serde_json::Error>>())?
        .checked_add(size_of::<io::Result<usize>>())?
        .checked_add(size_of::<Result<usize, PolicyCanonicalDataErrorV1>>())?
        .checked_add(size_of::<Option<usize>>())?
        .checked_mul(3)
}

struct CountingCanonicalWriter {
    length: usize,
    maximum: usize,
    exceeded: bool,
}

impl CountingCanonicalWriter {
    const fn new(maximum: usize) -> Self {
        Self {
            length: 0,
            maximum,
            exceeded: false,
        }
    }
}

impl Write for CountingCanonicalWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .length
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other(BYTE_COUNT_OVERFLOW))?;
        if length > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other(BYTE_CAP_EXCEEDED));
        }
        self.length = length;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BoundedCanonicalWriter {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
}

impl BoundedCanonicalWriter {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            exceeded: false,
        }
    }
}

impl Write for BoundedCanonicalWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other(BYTE_COUNT_OVERFLOW))?;
        if length > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other(BYTE_CAP_EXCEEDED));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other(ALLOCATION_FAILED))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Hashes bounded canonical DATA with the supplied existing domain separator.
///
/// A matching hash establishes byte consistency only, not authenticated input,
/// protected publication currentness or runtime authority.
///
/// # Errors
///
/// Returns [`PolicyCanonicalDataErrorV1`] if encoding fails or exceeds the existing
/// canonical-object bound.
pub fn digest<T: Serialize>(
    domain: &'static [u8],
    value: &T,
) -> Result<ObjectDigest, PolicyCanonicalDataErrorV1> {
    let payload_length = canonical_payload_size_v1(value)?;
    let total_length = domain
        .len()
        .checked_add(payload_length)
        .and_then(|length| length.checked_add(16))
        .ok_or(PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge)?;
    if total_length > MAXIMUM_CANONICAL_OBJECT_BYTES {
        return Err(PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge);
    }

    let mut hasher = Sha256::new();
    hasher.update(
        u64::try_from(domain.len())
            .map_err(|_| PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge)?
            .to_be_bytes(),
    );
    hasher.update(domain);
    hasher.update(
        u64::try_from(payload_length)
            .map_err(|_| PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge)?
            .to_be_bytes(),
    );
    serde_json::to_writer(DigestCanonicalWriter(&mut hasher), value)
        .map_err(|_| PolicyCanonicalDataErrorV1::CanonicalEncoding)?;
    Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
}

struct DigestCanonicalWriter<'a>(&'a mut Sha256);

impl Write for DigestCanonicalWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Computes the existing nine-member compiled-candidate commitment.
///
/// Plans are authority, namespace, hard resources, advisory and explanation.
/// Outputs are Policy, Optimization, namespace and advisory descriptors. The
/// explanation remains last in the preimage. These are untrusted consistency
/// DATA, not proof of compilation, input ownership, or current publication.
///
/// # Errors
/// Returns an encoding or byte-cap refusal from the canonical digest writer.
pub fn compiled_policy_candidate_digest_v1(
    plans: [ObjectDigest; 5],
    outputs: [&ObjectDescriptor; 4],
) -> Result<ObjectDigest, PolicyCanonicalDataErrorV1> {
    digest(
        b"aos.sandbox.compiled-policy-candidate.v2",
        &(
            plans[0], plans[1], plans[2], plans[3], outputs[0], outputs[1], outputs[2], outputs[3],
            plans[4],
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::MediaType;

    #[test]
    fn canonical_frame_and_digest_preserve_the_length_prefixed_golden() {
        let bytes = canonical_bytes(b"data", &[1_u8, 2]).unwrap();
        let expected = b"\0\0\0\0\0\0\0\x04data\0\0\0\0\0\0\0\x05[1,2]";

        assert_eq!(bytes, expected);
        assert_eq!(canonical_payload_size_v1(&[1_u8, 2]).unwrap(), 5);
        assert_eq!(
            digest(b"data", &[1_u8, 2]).unwrap().to_string(),
            "sha256:96efabe2aa020c60b44ea084d4fc1fdc521ea0f9de5e8f0d8cab238e2b66c981"
        );
        assert_ne!(
            digest(b"data", &[1_u8, 2]).unwrap(),
            digest(b"other", &[1_u8, 2]).unwrap()
        );
    }

    #[test]
    fn candidate_digest_preserves_all_nine_golden_tuple_members() {
        let plans = std::array::from_fn(|index| ObjectDigest::from_bytes([index as u8 + 1; 32]));
        let outputs = std::array::from_fn::<_, 4, _>(|index| {
            let value = index as u8 + 6;
            ObjectDescriptor::new(
                MediaType::new("application/test").unwrap(),
                ObjectDigest::from_bytes([value; 32]),
                u64::from(value),
            )
        });

        let actual = compiled_policy_candidate_digest_v1(plans, outputs.each_ref()).unwrap();

        assert_eq!(
            actual.to_string(),
            "sha256:98a351af2b9cc7c2288210ab3091fb26814741fb6a7233482a086b5d3f90f9ef"
        );
        for index in 0..5 {
            let mut changed = plans;
            changed[index] = ObjectDigest::from_bytes([99; 32]);
            assert_ne!(
                actual,
                compiled_policy_candidate_digest_v1(changed, outputs.each_ref()).unwrap()
            );
        }
        for index in 0..4 {
            let mut changed = outputs.clone();
            changed[index] = ObjectDescriptor::new(
                MediaType::new("application/test").unwrap(),
                ObjectDigest::from_bytes([99; 32]),
                99,
            );
            assert_ne!(
                actual,
                compiled_policy_candidate_digest_v1(plans, changed.each_ref()).unwrap()
            );
        }
    }

    #[test]
    fn complete_frame_bound_and_serializer_failures_preserve_error_classes() {
        let payload = "x".repeat(MAXIMUM_CANONICAL_OBJECT_BYTES - 16 - b"data".len() - 2);
        let bytes = canonical_bytes(b"data", &payload).unwrap();

        assert_eq!(bytes.len(), MAXIMUM_CANONICAL_OBJECT_BYTES);
        assert_eq!(
            digest(b"data", &payload).unwrap().as_bytes(),
            &<[u8; 32]>::from(Sha256::digest(&bytes))
        );
        let oversized = format!("{payload}x");
        assert!(matches!(
            canonical_bytes(b"data", &oversized),
            Err(PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge)
        ));
        assert!(matches!(
            digest(b"data", &oversized),
            Err(PolicyCanonicalDataErrorV1::CanonicalObjectTooLarge)
        ));

        struct Refused;

        impl Serialize for Refused {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("retained serializer refusal"))
            }
        }

        assert!(matches!(
            canonical_bytes(b"data", &Refused),
            Err(PolicyCanonicalDataErrorV1::CanonicalEncoding)
        ));
        assert!(matches!(
            digest(b"data", &Refused),
            Err(PolicyCanonicalDataErrorV1::CanonicalEncoding)
        ));
    }
}
