//! Canonical assignment-bound evidence for one populated guest workspace root.
//!
//! ```text
//! AOSGRP01 | sandbox[16] | incarnation[16] | epoch:u64be
//!          | assignment_digest[32] | creation_operation[16]
//!          | workspace_handle[32] | dataset_guid:u64be
//!          | root_image_digest[32] | package_binding[32]
//!          | root_tree_digest[32] | feature_mask:u16be | sha256[32]
//! ```
//!
//! The checksum detects torn or noncanonical markers; it is not an
//! authorization signature. Only a protected publisher may write the marker,
//! and every consumer must independently verify root ownership, the mounted
//! dataset, and the exact template tree before accepting it.

use sha2::{Digest as _, Sha256};

const MAGIC: &[u8; 8] = b"AOSGRP01";
const CANONICAL_BYTES: usize = 266;
const CHECKSUM_OFFSET: usize = CANONICAL_BYTES - 32;
const CONCRETE_FEATURE_MASK: u16 = 0x003f;

/// Names the exact concrete guest features implemented by the pinned package.
pub const CONCRETE_GUEST_FEATURE_MASK_V1: u16 = CONCRETE_FEATURE_MASK;

/// Carries a physically checked, assignment-bound guest root publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestRootPublicationProofV1 {
    /// Sandbox whose root was populated.
    pub sandbox: [u8; 16],
    /// Sandbox incarnation whose root was populated.
    pub incarnation: [u8; 16],
    /// Signed assignment epoch.
    pub assignment_epoch: u64,
    /// Digest of the signed broker assignment.
    pub assignment_digest: [u8; 32],
    /// Storage operation that created this workspace.
    pub creation_operation: [u8; 16],
    /// Opaque fixed workspace pin handle.
    pub workspace_handle: [u8; 32],
    /// Observed exact ZFS dataset GUID.
    pub dataset_guid: u64,
    /// Authenticated SandboxRootView object digest.
    pub root_image_digest: [u8; 32],
    /// Protected AOS guest-template package binding.
    pub package_binding: [u8; 32],
    /// Measured complete populated tree, including the package closure.
    pub root_tree_digest: [u8; 32],
    /// Closed six-feature mask implemented by this concrete package.
    pub feature_mask: u16,
}

impl GuestRootPublicationProofV1 {
    /// Encodes the fixed 266-byte `AOSGRP01` record.
    ///
    /// # Errors
    ///
    /// Returns an error if an identity, digest, GUID, or feature mask is invalid.
    pub fn encode(self) -> Result<[u8; CANONICAL_BYTES], GuestRootPublicationErrorV1> {
        self.validate()?;
        let mut bytes = [0_u8; CANONICAL_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&self.sandbox);
        bytes[24..40].copy_from_slice(&self.incarnation);
        bytes[40..48].copy_from_slice(&self.assignment_epoch.to_be_bytes());
        bytes[48..80].copy_from_slice(&self.assignment_digest);
        bytes[80..96].copy_from_slice(&self.creation_operation);
        bytes[96..128].copy_from_slice(&self.workspace_handle);
        bytes[128..136].copy_from_slice(&self.dataset_guid.to_be_bytes());
        bytes[136..168].copy_from_slice(&self.root_image_digest);
        bytes[168..200].copy_from_slice(&self.package_binding);
        bytes[200..232].copy_from_slice(&self.root_tree_digest);
        bytes[232..234].copy_from_slice(&self.feature_mask.to_be_bytes());
        let checksum: [u8; 32] = Sha256::digest(&bytes[..CHECKSUM_OFFSET]).into();
        bytes[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decodes and validates one exact canonical `AOSGRP01` record.
    ///
    /// # Errors
    ///
    /// Returns an error for incorrect length, magic, checksum, or fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, GuestRootPublicationErrorV1> {
        if bytes.len() != CANONICAL_BYTES || &bytes[..8] != MAGIC {
            return Err(GuestRootPublicationErrorV1::InvalidRecord);
        }
        let checksum: [u8; 32] = Sha256::digest(&bytes[..CHECKSUM_OFFSET]).into();
        if bytes[CHECKSUM_OFFSET..] != checksum {
            return Err(GuestRootPublicationErrorV1::InvalidRecord);
        }
        let proof = Self {
            sandbox: field(bytes, 8),
            incarnation: field(bytes, 24),
            assignment_epoch: u64::from_be_bytes(field(bytes, 40)),
            assignment_digest: field(bytes, 48),
            creation_operation: field(bytes, 80),
            workspace_handle: field(bytes, 96),
            dataset_guid: u64::from_be_bytes(field(bytes, 128)),
            root_image_digest: field(bytes, 136),
            package_binding: field(bytes, 168),
            root_tree_digest: field(bytes, 200),
            feature_mask: u16::from_be_bytes(field(bytes, 232)),
        };
        proof.validate()?;
        Ok(proof)
    }

    fn validate(self) -> Result<(), GuestRootPublicationErrorV1> {
        if self.sandbox == [0; 16]
            || self.incarnation == [0; 16]
            || self.assignment_epoch == 0
            || self.assignment_digest == [0; 32]
            || self.creation_operation == [0; 16]
            || self.workspace_handle == [0; 32]
            || self.dataset_guid == 0
            || self.root_image_digest == [0; 32]
            || self.package_binding == [0; 32]
            || self.root_tree_digest == [0; 32]
            || self.feature_mask != CONCRETE_FEATURE_MASK
        {
            return Err(GuestRootPublicationErrorV1::InvalidRecord);
        }
        Ok(())
    }
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut value = [0_u8; N];
    value.copy_from_slice(&bytes[offset..offset + N]);
    value
}

/// Reports malformed or unsupported guest-root publication evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GuestRootPublicationErrorV1 {
    /// The record is truncated, substituted, noncanonical, or unsupported.
    #[error("guest-root publication record is invalid")]
    InvalidRecord,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> GuestRootPublicationProofV1 {
        GuestRootPublicationProofV1 {
            sandbox: [1; 16],
            incarnation: [2; 16],
            assignment_epoch: 3,
            assignment_digest: [4; 32],
            creation_operation: [5; 16],
            workspace_handle: [6; 32],
            dataset_guid: 7,
            root_image_digest: [8; 32],
            package_binding: [9; 32],
            root_tree_digest: [10; 32],
            feature_mask: CONCRETE_FEATURE_MASK,
        }
    }

    #[test]
    fn round_trip_and_tamper_rejection() {
        let encoded = example().encode().unwrap();
        assert_eq!(GuestRootPublicationProofV1::decode(&encoded), Ok(example()));
        let mut tampered = encoded;
        tampered[151] ^= 1;
        assert_eq!(
            GuestRootPublicationProofV1::decode(&tampered),
            Err(GuestRootPublicationErrorV1::InvalidRecord)
        );
    }

    #[test]
    fn feature_substitution_is_rejected() {
        let mut proof = example();
        proof.feature_mask = 0x0003;
        assert_eq!(
            proof.encode(),
            Err(GuestRootPublicationErrorV1::InvalidRecord)
        );
    }
}
