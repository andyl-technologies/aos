//! Canonical content commitment for a native held-snapshot selection claim.
//!
//! The `AOSPCZ01` read-only content digest is SHA-256 over the following
//! exact preimage, where the descriptor has the registered portable tree media
//! type and is encoded by the portable v1 canonical descriptor codec:
//!
//! ```text
//! ASCII "aos.sandbox.source-provider.held-snapshot-portable-tree.v1\0"
//! || canonical-CBOR([tree-media-type, 1, tree-object-digest, tree-object-size])
//! ```
//!
//! This module only commits a supplied descriptor. It neither measures a ZFS
//! snapshot nor verifies any referenced directory or file-content bytes.

use aos_sandbox_core::{
    DescriptorRole, ObjectDescriptor, ObjectDigest, encode_object_descriptor,
    validate_descriptor_role,
};
use sha2::{Digest as _, Sha256};

const DOMAIN: &[u8] = b"aos.sandbox.source-provider.held-snapshot-portable-tree.v1\0";

/// Reports a descriptor that cannot identify a complete portable tree object.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("held-snapshot content requires a non-sentinel portable tree descriptor")]
pub struct HeldSnapshotContentErrorV1;

/// Commits the exact portable tree descriptor selected for a held snapshot.
///
/// A trusted physical producer must first hash every referenced file byte,
/// verify each content descriptor, and validate the complete tree graph. This
/// deterministic operation alone is not a Storage observation or Acquire proof.
///
/// # Errors
///
/// Rejects non-tree media types, zero descriptor size, or a zero digest.
pub fn held_snapshot_content_digest_v1(
    tree_descriptor: &ObjectDescriptor,
) -> Result<ObjectDigest, HeldSnapshotContentErrorV1> {
    if validate_descriptor_role(DescriptorRole::ImmutableViewSource, tree_descriptor).is_err()
        || tree_descriptor.digest().as_bytes() == &[0; 32]
        || tree_descriptor.encoded_size() == 0
    {
        return Err(HeldSnapshotContentErrorV1);
    }

    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(encode_object_descriptor(tree_descriptor));
    Ok(ObjectDigest::from_bytes(digest.finalize().into()))
}

#[cfg(test)]
mod tests {
    use aos_sandbox_core::{MediaType, PortableMediaType};

    use super::*;

    fn descriptor(media: PortableMediaType, digest: [u8; 32], size: u64) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(media.as_str()).unwrap(),
            ObjectDigest::from_bytes(digest),
            size,
        )
    }

    #[test]
    fn canonical_tree_descriptor_has_a_fixed_golden_commitment() {
        let tree = descriptor(PortableMediaType::Tree, [0x11; 32], 42);
        let encoded = encode_object_descriptor(&tree);
        assert_eq!(&encoded[..3], &[0x84, 0x78, 0x28]);
        assert_eq!(&encoded[3..43], PortableMediaType::Tree.as_str().as_bytes());
        assert_eq!(&encoded[43..47], &[0x01, 0x58, 0x20, 0x11]);
        assert_eq!(&encoded[78..], &[0x18, 0x2a]);
        assert_eq!(encoded.len(), 80);

        assert_eq!(
            held_snapshot_content_digest_v1(&tree).unwrap().to_string(),
            "sha256:f20226842c9d1ec0deaf51ac9906756d905ef6e7de86a5556e03de72d9228eb1"
        );
    }

    #[test]
    fn commitment_changes_with_tree_digest_or_encoded_size() {
        let original = descriptor(PortableMediaType::Tree, [0x11; 32], 42);
        let changed_digest = descriptor(PortableMediaType::Tree, [0x12; 32], 42);
        let changed_size = descriptor(PortableMediaType::Tree, [0x11; 32], 43);

        let commitment = held_snapshot_content_digest_v1(&original).unwrap();
        assert_ne!(
            held_snapshot_content_digest_v1(&changed_digest),
            Ok(commitment)
        );
        assert_ne!(
            held_snapshot_content_digest_v1(&changed_size),
            Ok(commitment)
        );
    }

    #[test]
    fn non_tree_and_sentinel_descriptors_fail_closed() {
        for invalid in [
            descriptor(PortableMediaType::Content, [0x11; 32], 42),
            descriptor(PortableMediaType::Tree, [0; 32], 42),
            descriptor(PortableMediaType::Tree, [0x11; 32], 0),
        ] {
            assert_eq!(
                held_snapshot_content_digest_v1(&invalid),
                Err(HeldSnapshotContentErrorV1)
            );
        }
    }
}
