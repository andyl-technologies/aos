//! Canonical portable-object encoding, validation, and identity.
//!
//! The low-level validator implements the RFC-0019 deterministic CBOR subset
//! independently of Serde. Schema codecs build only fixed arrays from these
//! primitives, while arbitrary input is rejected for indefinite values,
//! non-shortest integers, tags, floating point, duplicate/noncanonical map
//! keys, excess nesting, or an allocation claim beyond caller limits.

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

pub use broker_authorization::{
    decode_broker_authorization_plan, encode_broker_authorization_plan,
};
pub use cbor::{CanonicalCborError, DecodeLimits, validate_canonical_cbor};
pub use ownership_lease::{decode_ownership_lease, encode_ownership_lease};
pub use policy::{decode_optimization, decode_policy, encode_optimization, encode_policy};
pub use snapshot::{decode_snapshot, encode_snapshot};
pub use spec::{decode_sandbox_spec, encode_sandbox_spec};
pub use tree::{
    decode_delta, decode_directory, decode_tree, encode_delta, encode_directory, encode_tree,
};
pub use trust::{
    decode_signature, decode_signature_statement, decode_trust_policy, encode_signature,
    encode_signature_statement, encode_trust_policy,
};
pub use view::{decode_environment, decode_view, encode_environment, encode_view};

const OBJECT_DOMAIN: &[u8] = b"aos-sandbox-object-v1\0";

/// Computes the exact v1 descriptor for already encoded stored-object bytes.
///
/// Raw content bytes and canonical CBOR object bytes use the same framing. The
/// media type and encoded size are included in the SHA-256 preimage, so equal
/// bytes under different roles do not alias.
///
#[must_use]
pub fn descriptor_for_bytes(media_type: MediaType, stored_bytes: &[u8]) -> ObjectDescriptor {
    let media_type_len = media_type.as_str().len() as u16;
    let encoded_size = stored_bytes.len() as u64;

    let mut hasher = Sha256::new();
    hasher.update(OBJECT_DOMAIN);
    hasher.update(media_type_len.to_be_bytes());
    hasher.update(media_type.as_str().as_bytes());
    hasher.update(encoded_size.to_be_bytes());
    hasher.update(stored_bytes);
    let digest = ObjectDigest::from_bytes(hasher.finalize().into());

    ObjectDescriptor::new(media_type, digest, encoded_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_content_golden_descriptor_matches_rfc() {
        let descriptor = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.content.v1")
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            b"hello",
        );

        assert_eq!(
            descriptor.digest().to_string(),
            "sha256:a40bf7a4525f9711f56ba2f9a4e91cf0ee0fe60a01f7716c9eb6d03dde09d903"
        );
        assert_eq!(descriptor.encoded_size(), 5);
    }
}
