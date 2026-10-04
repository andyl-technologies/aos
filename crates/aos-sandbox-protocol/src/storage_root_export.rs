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

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], StorageRootExportProtocolErrorV1> {
    bytes
        .get(offset..offset + N)
        .ok_or(StorageRootExportProtocolErrorV1)?
        .try_into()
        .map_err(|_| StorageRootExportProtocolErrorV1)
}

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
            nonce: read_array(bytes, 12)?,
            deadline_boottime_nanoseconds: u64::from_be_bytes(read_array(bytes, 44)?),
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
            nonce: read_array(bytes, 12)?,
            request_digest: read_array(bytes, 44)?,
            root_device: u64::from_be_bytes(read_array(bytes, 76)?),
            root_inode: u64::from_be_bytes(read_array(bytes, 84)?),
            detached_mount_id: u64::from_be_bytes(read_array(bytes, 92)?),
        };
        if response.encode()?.as_slice() != bytes {
            return Err(StorageRootExportProtocolErrorV1);
        }
        Ok(response)
    }
}


/// Exact byte length of one private measured-prefix request.
pub const STORAGE_CANARY_EXPORT_REQUEST_BYTES_V1: usize = 402;

/// Exact byte length of one private measured-prefix response.
pub const STORAGE_CANARY_EXPORT_RESPONSE_BYTES_V1: usize = 240;

/// Exact byte length of one private generation-zero acknowledgment.
pub const STORAGE_CANARY_EXPORT_ACK_BYTES_V1: usize = 192;

/// Exact byte length of one private settled confirmation.
pub const STORAGE_CANARY_EXPORT_CONFIRMATION_BYTES_V1: usize = 184;

const CANARY_REQUEST_MAGIC: &[u8; 8] = b"AOSRCQ01";
const CANARY_RESPONSE_MAGIC: &[u8; 8] = b"AOSRCR01";
const CANARY_ACK_MAGIC: &[u8; 8] = b"AOSRCA01";
const CANARY_CONFIRMATION_MAGIC: &[u8; 8] = b"AOSRCS01";
const CANARY_REQUEST_DOMAIN: &[u8] = b"aos.sandbox.host-canary.root-request.v1\0";
const CANARY_RESPONSE_DOMAIN: &[u8] = b"aos.sandbox.host-canary.root-response.v1\0";

/// Describes the original private canary export without authorizing its effect.
///
/// The actual Host job, incarnation, deadline and complete authenticated native
/// baseline remain independently retained by their genuine owners. This frame
/// cannot create those owners or substitute for writer exclusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCanaryExportRequestV1 {
    /// Original Host-selected nonce for this one retained exchange.
    pub nonce: [u8; 32],
    /// Digest of the complete independently approved canary job.
    pub job_digest: [u8; 32],
    /// Original absolute kernel boottime deadline; never renewed on recovery.
    pub deadline_boottime_nanoseconds: u64,
    /// Publication proof independently matched to current Storage inventory.
    pub proof: GuestRootPublicationProofV1,
    /// Original boot identity from the genuine Host startup.
    pub boot_id: [u8; 16],
    /// Digest of the actual complete authenticated Host baseline.
    pub baseline_digest: [u8; 32],
}

/// Carries complete-root measurement DATA and one independently bound root FD.
///
/// The quantities describe this bounded traversal only. They do not prove
/// physical funding, future writable growth, full-project accounting or Drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCanaryExportResponseV1 {
    /// Nonce from the original request.
    pub nonce: [u8; 32],
    /// Domain-separated digest of the complete original request.
    pub request_digest: [u8; 32],
    /// Private continuity identity of the durable Storage export hold.
    pub held_identity: [u8; 32],
    /// Digest of the complete ordinary authenticated catalog observation.
    pub catalog_observation_digest: [u8; 32],
    /// Digest of every destination-root entry observed under exclusion.
    pub tree_digest: [u8; 32],
    /// Device observed from the actual detached root descriptor.
    pub root_device: u64,
    /// Inode observed from the actual detached root descriptor.
    pub root_inode: u64,
    /// Kernel mount identity of that same detached root descriptor.
    pub detached_mount_id: u64,
    /// Sum of the logical lengths of all regular-file names.
    pub regular_bytes: u64,
    /// Sum of the byte lengths of all symlink targets.
    pub symlink_bytes: u64,
    /// Complete entry count including the destination root.
    pub namespace_entries: u64,
    /// Conservative per-name inode charge, including hard-linked names.
    pub conservative_inodes: u64,
    /// Actual peak descriptors retained by this traversal.
    pub retained_peak_descriptors: u32,
    /// Actual peak admitted bytes in its live name arena.
    pub peak_name_arena_bytes: u32,
}

/// Describes an actual protected generation-zero readback, not an ACK permit.
///
/// Only the genuine same Host bank owner may produce an accepted acknowledgment
/// after its complete component admission, native write and protected readback.
/// Public construction and canonical decoding remain nonauthorizing DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCanaryExportAcknowledgmentV1 {
    /// Nonce from the original request.
    pub nonce: [u8; 32],
    /// Digest of the complete original request.
    pub request_digest: [u8; 32],
    /// Continuity identity of the same Storage export hold.
    pub held_identity: [u8; 32],
    /// Domain-separated digest of the actual measured response.
    pub measured_response_digest: [u8; 32],
    /// Digest of the actual protected generation-zero Host envelope.
    pub generation_zero_digest: [u8; 32],
    /// Same original absolute boottime deadline.
    pub deadline_boottime_nanoseconds: u64,
}

/// Describes durable settlement after the same worker and fixed scopes quiesce.
///
/// This frame cannot release a gate by itself. The retained owner must first
/// authenticate the exact named history and actual population observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCanaryExportConfirmationV1 {
    /// Nonce from the original request.
    pub nonce: [u8; 32],
    /// Digest of the complete original request.
    pub request_digest: [u8; 32],
    /// Continuity identity of the same Storage export hold.
    pub held_identity: [u8; 32],
    /// Digest of the actual protected generation-zero Host envelope.
    pub generation_zero_digest: [u8; 32],
    /// Digest of the completed Gen0Accepted native cut, avoiding a fixpoint.
    pub accepted_native_cut_digest: [u8; 32],
    /// Same original absolute boottime deadline.
    pub deadline_boottime_nanoseconds: u64,
}

fn encode_canary_header<const N: usize>(magic: &[u8; 8]) -> [u8; N] {
    let mut bytes = [0; N];
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[12..16].copy_from_slice(&(N as u32).to_be_bytes());
    bytes
}

fn require_canary_header<const N: usize>(
    bytes: &[u8],
    magic: &[u8; 8],
) -> Result<(), StorageRootExportProtocolErrorV1> {
    if bytes.len() != N
        || bytes[..8] != magic[..]
        || bytes[8..10] != VERSION.to_be_bytes()
        || bytes[10..12] != [0; 2]
        || bytes[12..16] != (N as u32).to_be_bytes()
    {
        return Err(StorageRootExportProtocolErrorV1);
    }
    Ok(())
}

impl StorageCanaryExportRequestV1 {
    /// Encodes the exact private request DATA.
    ///
    /// # Errors
    ///
    /// Refuses sentinel original identifiers or an invalid publication proof.
    pub fn encode(
        self,
    ) -> Result<[u8; STORAGE_CANARY_EXPORT_REQUEST_BYTES_V1], StorageRootExportProtocolErrorV1> {
        if self.nonce == [0; 32]
            || self.job_digest == [0; 32]
            || self.deadline_boottime_nanoseconds == 0
            || self.boot_id == [0; 16]
            || self.baseline_digest == [0; 32]
        {
            return Err(StorageRootExportProtocolErrorV1);
        }
        let proof = self.proof.encode().map_err(|_| StorageRootExportProtocolErrorV1)?;

        let mut bytes = encode_canary_header::<STORAGE_CANARY_EXPORT_REQUEST_BYTES_V1>(
            CANARY_REQUEST_MAGIC,
        );
        bytes[16..48].copy_from_slice(&self.nonce);
        bytes[48..80].copy_from_slice(&self.job_digest);
        bytes[80..88].copy_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes[88..354].copy_from_slice(&proof);
        bytes[354..370].copy_from_slice(&self.boot_id);
        bytes[370..402].copy_from_slice(&self.baseline_digest);
        Ok(bytes)
    }

    /// Decodes the exact private request without producing live authority.
    ///
    /// # Errors
    ///
    /// Refuses noncanonical framing, fields or publication proof.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageRootExportProtocolErrorV1> {
        require_canary_header::<STORAGE_CANARY_EXPORT_REQUEST_BYTES_V1>(
            bytes,
            CANARY_REQUEST_MAGIC,
        )?;
        let value = Self {
            nonce: read_array(bytes, 16)?,
            job_digest: read_array(bytes, 48)?,
            deadline_boottime_nanoseconds: u64::from_be_bytes(read_array(bytes, 80)?),
            proof: GuestRootPublicationProofV1::decode(&bytes[88..354])
                .map_err(|_| StorageRootExportProtocolErrorV1)?,
            boot_id: read_array(bytes, 354)?,
            baseline_digest: read_array(bytes, 370)?,
        };
        if value.encode()?.as_slice() != bytes {
            return Err(StorageRootExportProtocolErrorV1);
        }
        Ok(value)
    }

    /// Digests all canonical original request bytes under the private domain.
    ///
    /// # Errors
    ///
    /// Refuses a request that cannot be canonically encoded.
    pub fn digest(self) -> Result<[u8; 32], StorageRootExportProtocolErrorV1> {
        let mut digest = Sha256::new();
        digest.update(CANARY_REQUEST_DOMAIN);
        digest.update(self.encode()?);
        Ok(digest.finalize().into())
    }
}

impl StorageCanaryExportResponseV1 {
    /// Encodes one complete-root measurement DATA record.
    ///
    /// # Errors
    ///
    /// Refuses sentinel bindings, impossible entry charges or scanner bounds.
    pub fn encode(
        self,
    ) -> Result<[u8; STORAGE_CANARY_EXPORT_RESPONSE_BYTES_V1], StorageRootExportProtocolErrorV1> {
        if self.nonce == [0; 32]
            || self.request_digest == [0; 32]
            || self.held_identity == [0; 32]
            || self.catalog_observation_digest == [0; 32]
            || self.tree_digest == [0; 32]
            || self.root_device == 0
            || self.root_inode == 0
            || self.detached_mount_id == 0
            || self.namespace_entries == 0
            || self.namespace_entries > 250_000
            || self.conservative_inodes != self.namespace_entries
            || self.retained_peak_descriptors == 0
            || self.retained_peak_descriptors > 66
            || self.peak_name_arena_bytes > 16 * 1_048_576
            || self.regular_bytes.checked_add(self.symlink_bytes).is_none()
        {
            return Err(StorageRootExportProtocolErrorV1);
        }

        let mut bytes = encode_canary_header::<STORAGE_CANARY_EXPORT_RESPONSE_BYTES_V1>(
            CANARY_RESPONSE_MAGIC,
        );
        bytes[16..48].copy_from_slice(&self.nonce);
        bytes[48..80].copy_from_slice(&self.request_digest);
        bytes[80..112].copy_from_slice(&self.held_identity);
        bytes[112..144].copy_from_slice(&self.catalog_observation_digest);
        bytes[144..176].copy_from_slice(&self.tree_digest);
        bytes[176..184].copy_from_slice(&self.root_device.to_be_bytes());
        bytes[184..192].copy_from_slice(&self.root_inode.to_be_bytes());
        bytes[192..200].copy_from_slice(&self.detached_mount_id.to_be_bytes());
        bytes[200..208].copy_from_slice(&self.regular_bytes.to_be_bytes());
        bytes[208..216].copy_from_slice(&self.symlink_bytes.to_be_bytes());
        bytes[216..224].copy_from_slice(&self.namespace_entries.to_be_bytes());
        bytes[224..232].copy_from_slice(&self.conservative_inodes.to_be_bytes());
        bytes[232..236].copy_from_slice(&self.retained_peak_descriptors.to_be_bytes());
        bytes[236..240].copy_from_slice(&self.peak_name_arena_bytes.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes the exact measurement frame without trusting its quantities.
    ///
    /// # Errors
    ///
    /// Refuses malformed framing, bindings or mechanical scanner limits.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageRootExportProtocolErrorV1> {
        require_canary_header::<STORAGE_CANARY_EXPORT_RESPONSE_BYTES_V1>(
            bytes,
            CANARY_RESPONSE_MAGIC,
        )?;
        let value = Self {
            nonce: read_array(bytes, 16)?,
            request_digest: read_array(bytes, 48)?,
            held_identity: read_array(bytes, 80)?,
            catalog_observation_digest: read_array(bytes, 112)?,
            tree_digest: read_array(bytes, 144)?,
            root_device: u64::from_be_bytes(read_array(bytes, 176)?),
            root_inode: u64::from_be_bytes(read_array(bytes, 184)?),
            detached_mount_id: u64::from_be_bytes(read_array(bytes, 192)?),
            regular_bytes: u64::from_be_bytes(read_array(bytes, 200)?),
            symlink_bytes: u64::from_be_bytes(read_array(bytes, 208)?),
            namespace_entries: u64::from_be_bytes(read_array(bytes, 216)?),
            conservative_inodes: u64::from_be_bytes(read_array(bytes, 224)?),
            retained_peak_descriptors: u32::from_be_bytes(read_array(bytes, 232)?),
            peak_name_arena_bytes: u32::from_be_bytes(read_array(bytes, 236)?),
        };
        if value.encode()?.as_slice() != bytes {
            return Err(StorageRootExportProtocolErrorV1);
        }
        Ok(value)
    }

    /// Digests the complete actual response under the private response domain.
    ///
    /// # Errors
    ///
    /// Refuses a response that cannot be canonically encoded.
    pub fn digest(self) -> Result<[u8; 32], StorageRootExportProtocolErrorV1> {
        let mut digest = Sha256::new();
        digest.update(CANARY_RESPONSE_DOMAIN);
        digest.update(self.encode()?);
        Ok(digest.finalize().into())
    }
}

impl StorageCanaryExportAcknowledgmentV1 {
    /// Encodes readback DATA for exactly generation zero.
    ///
    /// # Errors
    ///
    /// Refuses sentinel original bindings or deadline.
    pub fn encode(
        self,
    ) -> Result<[u8; STORAGE_CANARY_EXPORT_ACK_BYTES_V1], StorageRootExportProtocolErrorV1> {
        if self.nonce == [0; 32]
            || self.request_digest == [0; 32]
            || self.held_identity == [0; 32]
            || self.measured_response_digest == [0; 32]
            || self.generation_zero_digest == [0; 32]
            || self.deadline_boottime_nanoseconds == 0
        {
            return Err(StorageRootExportProtocolErrorV1);
        }

        let mut bytes = encode_canary_header::<STORAGE_CANARY_EXPORT_ACK_BYTES_V1>(
            CANARY_ACK_MAGIC,
        );
        bytes[16..48].copy_from_slice(&self.nonce);
        bytes[48..80].copy_from_slice(&self.request_digest);
        bytes[80..112].copy_from_slice(&self.held_identity);
        bytes[112..144].copy_from_slice(&self.measured_response_digest);
        bytes[144..176].copy_from_slice(&self.generation_zero_digest);
        bytes[176..184].copy_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes exact generation-zero acknowledgment DATA.
    ///
    /// # Errors
    ///
    /// Refuses malformed framing, a nonzero generation or sentinel fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageRootExportProtocolErrorV1> {
        require_canary_header::<STORAGE_CANARY_EXPORT_ACK_BYTES_V1>(bytes, CANARY_ACK_MAGIC)?;
        if bytes[184..192] != [0; 8] {
            return Err(StorageRootExportProtocolErrorV1);
        }
        let value = Self {
            nonce: read_array(bytes, 16)?,
            request_digest: read_array(bytes, 48)?,
            held_identity: read_array(bytes, 80)?,
            measured_response_digest: read_array(bytes, 112)?,
            generation_zero_digest: read_array(bytes, 144)?,
            deadline_boottime_nanoseconds: u64::from_be_bytes(read_array(bytes, 176)?),
        };
        if value.encode()?.as_slice() != bytes {
            return Err(StorageRootExportProtocolErrorV1);
        }
        Ok(value)
    }
}

impl StorageCanaryExportConfirmationV1 {
    /// Encodes exact native settlement DATA.
    ///
    /// # Errors
    ///
    /// Refuses sentinel original bindings, accepted cut or deadline.
    pub fn encode(
        self,
    ) -> Result<[u8; STORAGE_CANARY_EXPORT_CONFIRMATION_BYTES_V1], StorageRootExportProtocolErrorV1> {
        if self.nonce == [0; 32]
            || self.request_digest == [0; 32]
            || self.held_identity == [0; 32]
            || self.generation_zero_digest == [0; 32]
            || self.accepted_native_cut_digest == [0; 32]
            || self.deadline_boottime_nanoseconds == 0
        {
            return Err(StorageRootExportProtocolErrorV1);
        }

        let mut bytes = encode_canary_header::<STORAGE_CANARY_EXPORT_CONFIRMATION_BYTES_V1>(
            CANARY_CONFIRMATION_MAGIC,
        );
        bytes[16..48].copy_from_slice(&self.nonce);
        bytes[48..80].copy_from_slice(&self.request_digest);
        bytes[80..112].copy_from_slice(&self.held_identity);
        bytes[112..144].copy_from_slice(&self.generation_zero_digest);
        bytes[144..176].copy_from_slice(&self.accepted_native_cut_digest);
        bytes[176..184].copy_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes exact settled-confirmation DATA.
    ///
    /// # Errors
    ///
    /// Refuses noncanonical framing or sentinel fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageRootExportProtocolErrorV1> {
        require_canary_header::<STORAGE_CANARY_EXPORT_CONFIRMATION_BYTES_V1>(
            bytes,
            CANARY_CONFIRMATION_MAGIC,
        )?;
        let value = Self {
            nonce: read_array(bytes, 16)?,
            request_digest: read_array(bytes, 48)?,
            held_identity: read_array(bytes, 80)?,
            generation_zero_digest: read_array(bytes, 112)?,
            accepted_native_cut_digest: read_array(bytes, 144)?,
            deadline_boottime_nanoseconds: u64::from_be_bytes(read_array(bytes, 176)?),
        };
        if value.encode()?.as_slice() != bytes {
            return Err(StorageRootExportProtocolErrorV1);
        }
        Ok(value)
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

    fn canary_request() -> StorageCanaryExportRequestV1 {
        StorageCanaryExportRequestV1 {
            nonce: [1; 32],
            job_digest: [12; 32],
            deadline_boottime_nanoseconds: 42,
            proof: request().proof,
            boot_id: [13; 16],
            baseline_digest: [14; 32],
        }
    }

    #[test]
    fn private_canary_frames_are_exact_data_and_do_not_accept_legacy_framing() {
        let request = canary_request();
        let bytes = request.encode().unwrap();

        assert_eq!(bytes.len(), 402);
        assert_eq!(
            StorageCanaryExportRequestV1::decode(&bytes).unwrap(),
            request,
        );
        assert!(StorageRootExportRequestV1::decode(&bytes).is_err());
        assert!(
            StorageCanaryExportRequestV1::decode(&self::request().encode().unwrap()).is_err(),
        );

        let response = StorageCanaryExportResponseV1 {
            nonce: request.nonce,
            request_digest: request.digest().unwrap(),
            held_identity: [15; 32],
            catalog_observation_digest: [16; 32],
            tree_digest: [17; 32],
            root_device: 18,
            root_inode: 19,
            detached_mount_id: 20,
            regular_bytes: 21,
            symlink_bytes: 22,
            namespace_entries: 23,
            conservative_inodes: 23,
            retained_peak_descriptors: 3,
            peak_name_arena_bytes: 24,
        };
        let acknowledgment = StorageCanaryExportAcknowledgmentV1 {
            nonce: request.nonce,
            request_digest: response.request_digest,
            held_identity: response.held_identity,
            measured_response_digest: response.digest().unwrap(),
            generation_zero_digest: [25; 32],
            deadline_boottime_nanoseconds: request.deadline_boottime_nanoseconds,
        };
        let confirmation = StorageCanaryExportConfirmationV1 {
            nonce: request.nonce,
            request_digest: response.request_digest,
            held_identity: response.held_identity,
            generation_zero_digest: acknowledgment.generation_zero_digest,
            accepted_native_cut_digest: [26; 32],
            deadline_boottime_nanoseconds: request.deadline_boottime_nanoseconds,
        };

        assert_eq!(response.encode().unwrap().len(), 240);
        assert_eq!(acknowledgment.encode().unwrap().len(), 192);
        assert_eq!(confirmation.encode().unwrap().len(), 184);
        assert_eq!(
            StorageCanaryExportResponseV1::decode(&response.encode().unwrap()).unwrap(),
            response,
        );
        assert_eq!(
            StorageCanaryExportAcknowledgmentV1::decode(&acknowledgment.encode().unwrap()).unwrap(),
            acknowledgment,
        );
        assert_eq!(
            StorageCanaryExportConfirmationV1::decode(&confirmation.encode().unwrap()).unwrap(),
            confirmation,
        );

        let mut wrong_generation = acknowledgment.encode().unwrap();
        wrong_generation[191] = 1;
        assert!(StorageCanaryExportAcknowledgmentV1::decode(&wrong_generation).is_err());
        let mut wrong_length = bytes;
        wrong_length[15] ^= 1;
        assert!(StorageCanaryExportRequestV1::decode(&wrong_length).is_err());
        let mut wrong_reserved = confirmation.encode().unwrap();
        wrong_reserved[11] = 1;
        assert!(StorageCanaryExportConfirmationV1::decode(&wrong_reserved).is_err());
    }

    #[test]
    fn private_measurement_refuses_overflow_or_unbounded_scanner_data() {
        let request = canary_request();
        let mut response = StorageCanaryExportResponseV1 {
            nonce: request.nonce,
            request_digest: request.digest().unwrap(),
            held_identity: [15; 32],
            catalog_observation_digest: [16; 32],
            tree_digest: [17; 32],
            root_device: 18,
            root_inode: 19,
            detached_mount_id: 20,
            regular_bytes: u64::MAX,
            symlink_bytes: 1,
            namespace_entries: 1,
            conservative_inodes: 1,
            retained_peak_descriptors: 1,
            peak_name_arena_bytes: 0,
        };

        assert!(response.encode().is_err());
        response.regular_bytes = 0;
        response.namespace_entries = 250_001;
        response.conservative_inodes = response.namespace_entries;
        assert!(response.encode().is_err());
        response.namespace_entries = 1;
        response.conservative_inodes = 2;
        assert!(response.encode().is_err());
        response.conservative_inodes = 1;
        response.retained_peak_descriptors = 67;
        assert!(response.encode().is_err());
        response.retained_peak_descriptors = 1;
        response.peak_name_arena_bytes = 16 * 1_048_576 + 1;
        assert!(response.encode().is_err());
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
