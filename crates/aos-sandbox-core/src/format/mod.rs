//! Canonical portable-object encoding, validation, and identity.
//!
//! The low-level validator implements the RFC-0020 deterministic CBOR subset
//! independently of Serde. Schema codecs build only fixed arrays from these
//! primitives, while arbitrary input is rejected for indefinite values,
//! non-shortest integers, tags, floating point, duplicate/noncanonical map
//! keys, excess nesting, or an allocation claim beyond caller limits.

mod assignment;
mod broker_authorization;
mod cbor;
mod ownership_lease;
mod policy;
mod snapshot;
mod spec;
mod tree;
mod trust;
mod view;

use sha2::{Digest, Sha256};

use crate::{MediaType, ObjectDescriptor, ObjectDigest};

pub use assignment::{decode_assignment_manifest_v1, encode_assignment_manifest_v1};
pub use broker_authorization::{
    decode_broker_authorization_plan, encode_broker_authorization_plan,
};
pub use cbor::{CanonicalCborError, DecodeLimits, validate_canonical_cbor};
pub use ownership_lease::{decode_ownership_lease, encode_ownership_lease};
pub use policy::{decode_optimization, decode_policy, encode_optimization, encode_policy};
pub use snapshot::{decode_snapshot, encode_snapshot};
pub use spec::{decode_sandbox_spec, encode_sandbox_spec};
pub use tree::{
    StreamingDirectory, decode_delta, decode_directory, decode_tree, encode_delta,
    encode_directory, encode_tree, hardlink_group_digest,
};
pub use trust::{
    decode_signature, decode_signature_statement, decode_trust_policy, encode_signature,
    encode_signature_statement, encode_trust_policy,
};
pub use view::{decode_environment, decode_view, encode_environment, encode_view};

const OBJECT_DOMAIN: &[u8] = b"aos-sandbox-object-v1\0";

/// Reports failure to match a streamed payload to its expected object descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ObjectDescriptorVerificationError {
    /// The cumulative streamed byte count cannot be represented as a `u64`.
    #[error("streamed object byte count overflowed")]
    LengthOverflow,
    /// More bytes were supplied than the descriptor admits.
    #[error("streamed object is longer than its expected descriptor")]
    TooLong,
    /// Fewer bytes were supplied than the descriptor requires.
    #[error("streamed object is shorter than its expected descriptor")]
    TooShort,
    /// The exact-length payload did not match the descriptor digest.
    #[error("streamed object digest does not match its expected descriptor")]
    DigestMismatch,
}

/// Incrementally verifies stored bytes against one exact v1 object descriptor.
///
/// The expected encoded size is committed to the SHA-256 preimage before any
/// payload bytes. It is also the admission bound: an update that would exceed
/// it is rejected before those bytes are hashed. The verifier retains only the
/// expected descriptor, a fixed-size hash state, and counters; it never retains
/// the payload.
pub struct ObjectDescriptorVerifier {
    expected: ObjectDescriptor,
    hasher: Sha256,
    received_bytes: u64,
    terminal_error: Option<ObjectDescriptorVerificationError>,
}

impl ObjectDescriptorVerifier {
    /// Constructs a verifier for one independently authenticated descriptor.
    #[must_use]
    pub fn new(expected: ObjectDescriptor) -> Self {
        let hasher = object_hasher(expected.media_type(), expected.encoded_size());
        Self {
            expected,
            hasher,
            received_bytes: 0,
            terminal_error: None,
        }
    }

    /// Adds the next contiguous payload bytes.
    ///
    /// Empty chunks are accepted. A length failure poisons the verifier so a
    /// caller cannot ignore it and later obtain a successful result.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectDescriptorVerificationError::LengthOverflow`] when the
    /// cumulative byte count cannot fit in `u64`, or
    /// [`ObjectDescriptorVerificationError::TooLong`] before hashing bytes
    /// beyond the expected encoded size. Once either failure occurs, later
    /// updates return the same error.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), ObjectDescriptorVerificationError> {
        if let Some(error) = self.terminal_error {
            return Err(error);
        }

        let byte_count = u64::try_from(bytes.len()).map_err(|_| {
            self.terminal_error = Some(ObjectDescriptorVerificationError::LengthOverflow);
            ObjectDescriptorVerificationError::LengthOverflow
        })?;
        let next_received = self.received_bytes.checked_add(byte_count).ok_or_else(|| {
            self.terminal_error = Some(ObjectDescriptorVerificationError::LengthOverflow);
            ObjectDescriptorVerificationError::LengthOverflow
        })?;
        if next_received > self.expected.encoded_size() {
            self.terminal_error = Some(ObjectDescriptorVerificationError::TooLong);
            return Err(ObjectDescriptorVerificationError::TooLong);
        }

        self.hasher.update(bytes);
        self.received_bytes = next_received;
        Ok(())
    }

    /// Finishes verification after the complete payload has been supplied.
    ///
    /// # Errors
    ///
    /// Returns the retained length failure, reports
    /// [`ObjectDescriptorVerificationError::TooShort`] when fewer than the
    /// expected bytes were supplied, or reports
    /// [`ObjectDescriptorVerificationError::DigestMismatch`] when an
    /// exact-length payload has different bytes.
    pub fn finish(self) -> Result<(), ObjectDescriptorVerificationError> {
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        if self.received_bytes < self.expected.encoded_size() {
            return Err(ObjectDescriptorVerificationError::TooShort);
        }

        let actual = ObjectDigest::from_bytes(self.hasher.finalize().into());
        if actual != self.expected.digest() {
            return Err(ObjectDescriptorVerificationError::DigestMismatch);
        }
        Ok(())
    }
}

fn object_hasher(media_type: &MediaType, encoded_size: u64) -> Sha256 {
    let media_type_len = media_type.as_str().len() as u16;
    let mut hasher = Sha256::new();
    hasher.update(OBJECT_DOMAIN);
    hasher.update(media_type_len.to_be_bytes());
    hasher.update(media_type.as_str().as_bytes());
    hasher.update(encoded_size.to_be_bytes());
    hasher
}

/// Computes the exact v1 descriptor for already encoded stored-object bytes.
///
/// Raw content bytes and canonical CBOR object bytes use the same framing. The
/// media type and encoded size are included in the SHA-256 preimage, so equal
/// bytes under different roles do not alias.
///
#[must_use]
pub fn descriptor_for_bytes(media_type: MediaType, stored_bytes: &[u8]) -> ObjectDescriptor {
    let encoded_size = stored_bytes.len() as u64;

    let mut hasher = object_hasher(&media_type, encoded_size);
    hasher.update(stored_bytes);
    let digest = ObjectDigest::from_bytes(hasher.finalize().into());

    ObjectDescriptor::new(media_type, digest, encoded_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn media_type(value: &str) -> MediaType {
        MediaType::new(value).unwrap_or_else(|error| panic!("test media type failed: {error}"))
    }

    #[test]
    fn raw_content_golden_descriptor_matches_rfc() {
        let descriptor = descriptor_for_bytes(
            media_type("application/vnd.aos.sandbox.content.v1"),
            b"hello",
        );

        assert_eq!(
            descriptor.digest().to_string(),
            "sha256:a40bf7a4525f9711f56ba2f9a4e91cf0ee0fe60a01f7716c9eb6d03dde09d903"
        );
        assert_eq!(descriptor.encoded_size(), 5);
    }

    #[test]
    fn streaming_verifier_matches_one_shot_across_chunk_partitions() {
        let bytes = b"a payload split at every possible boundary";
        let expected =
            descriptor_for_bytes(media_type("application/vnd.aos.sandbox.content.v1"), bytes);

        for split in 0..=bytes.len() {
            let mut verifier = ObjectDescriptorVerifier::new(expected.clone());
            assert_eq!(verifier.update(&bytes[..split]), Ok(()));
            assert_eq!(verifier.update(&[]), Ok(()));
            assert_eq!(verifier.update(&bytes[split..]), Ok(()));
            assert_eq!(verifier.finish(), Ok(()));
        }
    }

    #[test]
    fn streaming_verifier_accepts_an_empty_object() {
        let expected = descriptor_for_bytes(media_type("application/octet-stream"), b"");
        let mut verifier = ObjectDescriptorVerifier::new(expected);
        assert_eq!(verifier.update(&[]), Ok(()));
        assert_eq!(verifier.finish(), Ok(()));
    }

    #[test]
    fn streaming_verifier_rejects_short_and_long_payloads() {
        let expected = descriptor_for_bytes(media_type("application/octet-stream"), b"exact");

        let mut short = ObjectDescriptorVerifier::new(expected.clone());
        assert_eq!(short.update(b"exac"), Ok(()));
        assert_eq!(
            short.finish(),
            Err(ObjectDescriptorVerificationError::TooShort)
        );

        let mut long = ObjectDescriptorVerifier::new(expected);
        assert_eq!(
            long.update(b"exacts"),
            Err(ObjectDescriptorVerificationError::TooLong)
        );
        assert_eq!(
            long.update(b"exact"),
            Err(ObjectDescriptorVerificationError::TooLong)
        );
        assert_eq!(
            long.finish(),
            Err(ObjectDescriptorVerificationError::TooLong)
        );
    }

    #[test]
    fn streaming_verifier_rejects_wrong_bytes_and_media_type() {
        let expected = descriptor_for_bytes(media_type("application/octet-stream"), b"first");
        let mut wrong_bytes = ObjectDescriptorVerifier::new(expected.clone());
        assert_eq!(wrong_bytes.update(b"other"), Ok(()));
        assert_eq!(
            wrong_bytes.finish(),
            Err(ObjectDescriptorVerificationError::DigestMismatch)
        );

        let forged_media = ObjectDescriptor::new(
            media_type("text/plain"),
            expected.digest(),
            expected.encoded_size(),
        );
        let mut wrong_media = ObjectDescriptorVerifier::new(forged_media);
        assert_eq!(wrong_media.update(b"first"), Ok(()));
        assert_eq!(
            wrong_media.finish(),
            Err(ObjectDescriptorVerificationError::DigestMismatch)
        );

        let raw_digest = ObjectDigest::from_bytes(Sha256::digest(b"first").into());
        assert_ne!(expected.digest(), raw_digest);
    }

    #[test]
    fn streaming_verifier_rejects_counter_overflow_and_remains_poisoned() {
        let expected = ObjectDescriptor::new(
            media_type("application/octet-stream"),
            ObjectDigest::from_bytes([1; 32]),
            u64::MAX,
        );
        let mut verifier = ObjectDescriptorVerifier::new(expected);
        verifier.received_bytes = u64::MAX;

        assert_eq!(
            verifier.update(b"x"),
            Err(ObjectDescriptorVerificationError::LengthOverflow)
        );
        assert_eq!(
            verifier.update(&[]),
            Err(ObjectDescriptorVerificationError::LengthOverflow)
        );
        assert_eq!(
            verifier.finish(),
            Err(ObjectDescriptorVerificationError::LengthOverflow)
        );
    }
}
