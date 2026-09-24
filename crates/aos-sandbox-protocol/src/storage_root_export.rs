//! Exact one-operation Storage-to-Host detached-root descriptor contract.
//!
//! This codec carries no authority by itself. Storage accepts a request only
//! from the live Host broker service and independently matches its AOSGRP01
//! proof to current authenticated inventory before exporting one mount FD.
//!
//! ```text
//! request  = AOSRME01 | version:u16 | reserved:u16 | nonce[32]
//!            | deadline_boottime_ns:u64be | AOSGRP01[266]
//! response = AOSRMR01 | version:u16 | reserved:u16 | nonce[32]
//!            | SHA256(request)[32] | device:u64be | inode:u64be
//!            | detached_mount_id:u64be
//! ```

use aos_sandbox_agent::guest_root_publication::GuestRootPublicationProofV1;
use sha2::{Digest as _, Sha256};

const REQUEST_MAGIC: &[u8; 8] = b"AOSRME01";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSRMR01";
const VERSION: u16 = 1;
const REQUEST_BYTES: usize = 8 + 2 + 2 + 32 + 8 + 266;
const RESPONSE_BYTES: usize = 8 + 2 + 2 + 32 + 32 + 8 + 8 + 8;
const REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.root-mount-export.v1\0";

/// Exact byte length of one AOSRME01 request packet.
pub const STORAGE_ROOT_EXPORT_REQUEST_BYTES_V1: usize = REQUEST_BYTES;

/// Exact byte length of one AOSRMR01 descriptor reply packet.
pub const STORAGE_ROOT_EXPORT_RESPONSE_BYTES_V1: usize = RESPONSE_BYTES;

/// Names one exact published root and bounded Host request session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageRootExportRequestV1 {
    /// Fresh request nonce selected by Host.
    pub nonce: [u8; 32],
    /// Absolute kernel boottime deadline for this one transfer.
    pub deadline_boottime_nanoseconds: u64,
    /// Exact proof independently rederived from current Storage inventory.
    pub proof: GuestRootPublicationProofV1,
}

/// Binds a single returned descriptor to its exact request and physical root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageRootExportResponseV1 {
    /// Nonce from the accepted request.
    pub nonce: [u8; 32],
    /// Domain-separated digest of the complete canonical request.
    pub request_digest: [u8; 32],
    /// Root device measured from the exported detached mount.
    pub root_device: u64,
    /// Root inode measured from the exported detached mount.
    pub root_inode: u64,
    /// Kernel-unique identity of the detached mount object.
    pub detached_mount_id: u64,
}

/// Reports a malformed or noncanonical root-export record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Storage root-export record is invalid")]
pub struct StorageRootExportProtocolErrorV1;

impl StorageRootExportRequestV1 {
    /// Encodes the exact bounded request.
    ///
    /// # Errors
    ///
    /// Returns an error for a sentinel nonce/deadline or invalid proof.
    pub fn encode(self) -> Result<[u8; REQUEST_BYTES], StorageRootExportProtocolErrorV1> {
        if self.nonce == [0; 32] || self.deadline_boottime_nanoseconds == 0 {
            return Err(StorageRootExportProtocolErrorV1);
        }
        let proof = self
            .proof
            .encode()
            .map_err(|_| StorageRootExportProtocolErrorV1)?;
        let mut bytes = [0_u8; REQUEST_BYTES];
        bytes[..8].copy_from_slice(REQUEST_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[12..44].copy_from_slice(&self.nonce);
        bytes[44..52].copy_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes[52..].copy_from_slice(&proof);
        Ok(bytes)
    }

    /// Decodes only the exact canonical request shape.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong length, magic, version, reserved byte, or proof.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageRootExportProtocolErrorV1> {
        if bytes.len() != REQUEST_BYTES
            || &bytes[..8] != REQUEST_MAGIC
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[10..12] != [0; 2]
        {
            return Err(StorageRootExportProtocolErrorV1);
        }
        let request = Self {
            nonce: bytes[12..44]
                .try_into()
                .map_err(|_| StorageRootExportProtocolErrorV1)?,
            deadline_boottime_nanoseconds: u64::from_be_bytes(
                bytes[44..52]
                    .try_into()
                    .map_err(|_| StorageRootExportProtocolErrorV1)?,
            ),
            proof: GuestRootPublicationProofV1::decode(&bytes[52..])
                .map_err(|_| StorageRootExportProtocolErrorV1)?,
        };
        if request.encode()?.as_slice() != bytes {
            return Err(StorageRootExportProtocolErrorV1);
        }
        Ok(request)
    }

    /// Commits to every canonical request byte under the export domain.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be canonically encoded.
    pub fn digest(self) -> Result<[u8; 32], StorageRootExportProtocolErrorV1> {
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DIGEST_DOMAIN);
        hasher.update(self.encode()?);
        Ok(hasher.finalize().into())
    }
}

impl StorageRootExportResponseV1 {
    /// Encodes one descriptor-bound reply.
    ///
    /// # Errors
    ///
    /// Returns an error for any sentinel identity or digest.
    pub fn encode(self) -> Result<[u8; RESPONSE_BYTES], StorageRootExportProtocolErrorV1> {
        if self.nonce == [0; 32]
            || self.request_digest == [0; 32]
            || self.root_device == 0
            || self.root_inode == 0
            || self.detached_mount_id == 0
        {
            return Err(StorageRootExportProtocolErrorV1);
        }
        let mut bytes = [0_u8; RESPONSE_BYTES];
        bytes[..8].copy_from_slice(RESPONSE_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[12..44].copy_from_slice(&self.nonce);
        bytes[44..76].copy_from_slice(&self.request_digest);
        bytes[76..84].copy_from_slice(&self.root_device.to_be_bytes());
        bytes[84..92].copy_from_slice(&self.root_inode.to_be_bytes());
        bytes[92..100].copy_from_slice(&self.detached_mount_id.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes only the exact canonical reply shape.
    ///
    /// # Errors
    ///
    /// Returns an error for any truncated, extended, or invalid field.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageRootExportProtocolErrorV1> {
        if bytes.len() != RESPONSE_BYTES
            || &bytes[..8] != RESPONSE_MAGIC
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[10..12] != [0; 2]
        {
            return Err(StorageRootExportProtocolErrorV1);
        }
        let response = Self {
            nonce: bytes[12..44]
                .try_into()
                .map_err(|_| StorageRootExportProtocolErrorV1)?,
            request_digest: bytes[44..76]
                .try_into()
                .map_err(|_| StorageRootExportProtocolErrorV1)?,
            root_device: u64::from_be_bytes(
                bytes[76..84]
                    .try_into()
                    .map_err(|_| StorageRootExportProtocolErrorV1)?,
            ),
            root_inode: u64::from_be_bytes(
                bytes[84..92]
                    .try_into()
                    .map_err(|_| StorageRootExportProtocolErrorV1)?,
            ),
            detached_mount_id: u64::from_be_bytes(
                bytes[92..100]
                    .try_into()
                    .map_err(|_| StorageRootExportProtocolErrorV1)?,
            ),
        };
        if response.encode()?.as_slice() != bytes {
            return Err(StorageRootExportProtocolErrorV1);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_agent::guest_root_publication::CONCRETE_GUEST_FEATURE_MASK_V1;

    fn request() -> StorageRootExportRequestV1 {
        StorageRootExportRequestV1 {
            nonce: [1; 32],
            deadline_boottime_nanoseconds: 42,
            proof: GuestRootPublicationProofV1 {
                sandbox: [2; 16],
                incarnation: [3; 16],
                assignment_epoch: 4,
                assignment_digest: [5; 32],
                creation_operation: [6; 16],
                workspace_handle: [7; 32],
                dataset_guid: 8,
                root_image_digest: [9; 32],
                package_binding: [10; 32],
                root_tree_digest: [11; 32],
                feature_mask: CONCRETE_GUEST_FEATURE_MASK_V1,
            },
        }
    }

    #[test]
    fn exact_request_and_descriptor_reply_round_trip() {
        let request = request();
        let bytes = request.encode().unwrap();
        assert_eq!(bytes.len(), REQUEST_BYTES);
        assert_eq!(StorageRootExportRequestV1::decode(&bytes).unwrap(), request);

        let response = StorageRootExportResponseV1 {
            nonce: request.nonce,
            request_digest: request.digest().unwrap(),
            root_device: 12,
            root_inode: 13,
            detached_mount_id: 14,
        };
        let response_bytes = response.encode().unwrap();
        assert_eq!(response_bytes.len(), RESPONSE_BYTES);
        assert_eq!(
            StorageRootExportResponseV1::decode(&response_bytes).unwrap(),
            response
        );

        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(StorageRootExportRequestV1::decode(&trailing).is_err());
        let mut changed_proof = bytes;
        changed_proof[100] ^= 1;
        assert!(StorageRootExportRequestV1::decode(&changed_proof).is_err());
        let mut changed_response = response_bytes;
        changed_response[10] = 1;
        assert!(StorageRootExportResponseV1::decode(&changed_response).is_err());
    }
}
