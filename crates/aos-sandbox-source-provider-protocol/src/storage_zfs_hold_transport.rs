//! Descriptor-free Provider challenge carrier for a native ZFS hold readback.
//!
//! ```text
//! AOSZHQ01 | version:u16be=1 | reserved[6]=0 | sequence:u64be |
//! challenge[32] | attempt-digest[32] | provider-id[16] | holder-id[16] |
//! session-binding[32] | acquisition-id[32] | binding-digest[32] |
//! publication-head[32] | issued-seconds:i64be | valid-until-seconds:i64be |
//! catalog-length:u32be | canonical-AOSPCZ01[catalog-length]
//! AOSZHU01 | version:u16be=1 | reserved[6]=0 | sequence:u64be |
//! challenge[32] | request-digest[32] | status:u8=1 | reserved[7]=0
//! ```
//!
//! These bytes carry Provider assertions only. The receiver must authenticate
//! the exact live Provider process and independently map every selected native
//! row field to protected Storage state before issuing an AOSZHR01 receipt.
//! The only response in this protocol is descriptor-free Unavailable.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::ProviderHeldSnapshotCatalogV1;

const REQUEST_MAGIC: &[u8; 8] = b"AOSZHQ01";
const RESPONSE_MAGIC: &[u8; 8] = b"AOSZHU01";
const VERSION: u16 = 1;
const REQUEST_HEADER_BYTES: usize = 268;
const RESPONSE_BYTES: usize = 96;
const MAXIMUM_CATALOG_BYTES: usize = 54 + 64 * 328;
const REQUEST_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.storage.zfs-hold.transport-request.v1\0";

/// Maximum accepted descriptor-free native hold request packet size.
pub const MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1: usize =
    REQUEST_HEADER_BYTES + MAXIMUM_CATALOG_BYTES;

/// Rejects invalid native hold transport bytes or mismatched responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageZfsHoldTransportErrorV1 {
    /// The packet or its nested native catalog is not canonical.
    #[error("Storage ZFS hold transport packet is noncanonical")]
    Noncanonical,
    /// The connection-local sequence did not advance.
    #[error("Storage ZFS hold transport sequence was replayed")]
    Replay,
    /// The response does not identify the exact request.
    #[error("Storage ZFS hold transport response does not match request")]
    ResponseMismatch,
}

/// Carries one exact, untrusted Provider challenge and native selection claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageZfsHoldTransportRequestV1 {
    sequence: u64,
    challenge: [u8; 32],
    attempt_digest: ObjectDigest,
    provider_id: [u8; 16],
    holder_id: [u8; 16],
    session_binding: ObjectDigest,
    acquisition_id: ObjectDigest,
    binding_digest: ObjectDigest,
    publication_head: ObjectDigest,
    issued_seconds: i64,
    valid_until_seconds: i64,
    catalog: ProviderHeldSnapshotCatalogV1,
}

impl StorageZfsHoldTransportRequestV1 {
    /// Constructs a bounded packet for one selected native catalog row.
    ///
    /// This constructor checks format only. It does not prove that the
    /// challenge was issued, the holder session is live, or the row is true.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities, a validity window longer than 60 seconds,
    /// or a catalog without the named logical binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        challenge: [u8; 32],
        attempt_digest: ObjectDigest,
        provider_id: [u8; 16],
        holder_id: [u8; 16],
        session_binding: ObjectDigest,
        acquisition_id: ObjectDigest,
        binding_digest: ObjectDigest,
        publication_head: ObjectDigest,
        issued_seconds: i64,
        valid_until_seconds: i64,
        catalog: ProviderHeldSnapshotCatalogV1,
    ) -> Result<Self, StorageZfsHoldTransportErrorV1> {
        if sequence == 0
            || challenge == [0; 32]
            || provider_id == [0; 16]
            || holder_id == [0; 16]
            || [
                attempt_digest,
                session_binding,
                acquisition_id,
                binding_digest,
                publication_head,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
            || issued_seconds <= 0
            || valid_until_seconds
                .checked_sub(issued_seconds)
                .is_none_or(|duration| duration == 0 || duration > 60)
            || catalog
                .select_under_head(
                    catalog.generation(),
                    catalog.digest(),
                    catalog.namespace_digest(),
                    binding_digest,
                )
                .is_err()
        {
            return Err(StorageZfsHoldTransportErrorV1::Noncanonical);
        }

        Ok(Self {
            sequence,
            challenge,
            attempt_digest,
            provider_id,
            holder_id,
            session_binding,
            acquisition_id,
            binding_digest,
            publication_head,
            issued_seconds,
            valid_until_seconds,
            catalog,
        })
    }

    /// Decodes the exact packet and nested canonical AOSPCZ01 catalog.
    ///
    /// # Errors
    ///
    /// Rejects malformed framing, length, native rows, or attempt fields.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageZfsHoldTransportErrorV1> {
        if bytes.len() < REQUEST_HEADER_BYTES
            || bytes.len() > MAXIMUM_STORAGE_ZFS_HOLD_REQUEST_PACKET_BYTES_V1
            || bytes.get(..8) != Some(REQUEST_MAGIC.as_slice())
            || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
            || bytes.get(10..16) != Some([0; 6].as_slice())
        {
            return Err(StorageZfsHoldTransportErrorV1::Noncanonical);
        }

        let catalog_length = u32::from_be_bytes(array(bytes, 264)?) as usize;
        if catalog_length == 0
            || catalog_length > MAXIMUM_CATALOG_BYTES
            || bytes.len() != REQUEST_HEADER_BYTES + catalog_length
        {
            return Err(StorageZfsHoldTransportErrorV1::Noncanonical);
        }
        let catalog =
            ProviderHeldSnapshotCatalogV1::from_canonical_bytes(&bytes[REQUEST_HEADER_BYTES..])
                .map_err(|_| StorageZfsHoldTransportErrorV1::Noncanonical)?;
        let request = Self::new(
            u64::from_be_bytes(array(bytes, 16)?),
            array(bytes, 24)?,
            ObjectDigest::from_bytes(array(bytes, 56)?),
            array(bytes, 88)?,
            array(bytes, 104)?,
            ObjectDigest::from_bytes(array(bytes, 120)?),
            ObjectDigest::from_bytes(array(bytes, 152)?),
            ObjectDigest::from_bytes(array(bytes, 184)?),
            ObjectDigest::from_bytes(array(bytes, 216)?),
            i64::from_be_bytes(array(bytes, 248)?),
            i64::from_be_bytes(array(bytes, 256)?),
            catalog,
        )?;
        if request.to_canonical_bytes() != bytes {
            return Err(StorageZfsHoldTransportErrorV1::Noncanonical);
        }
        Ok(request)
    }

    /// Encodes the sole accepted packet representation.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let catalog = self.catalog.to_canonical_bytes();
        let mut bytes = Vec::with_capacity(REQUEST_HEADER_BYTES + catalog.len());
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.challenge);
        bytes.extend_from_slice(self.attempt_digest.as_bytes());
        bytes.extend_from_slice(&self.provider_id);
        bytes.extend_from_slice(&self.holder_id);
        bytes.extend_from_slice(self.session_binding.as_bytes());
        bytes.extend_from_slice(self.acquisition_id.as_bytes());
        bytes.extend_from_slice(self.binding_digest.as_bytes());
        bytes.extend_from_slice(self.publication_head.as_bytes());
        bytes.extend_from_slice(&self.issued_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until_seconds.to_be_bytes());
        bytes.extend_from_slice(&(catalog.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&catalog);
        bytes
    }

    /// Commits the exact request bytes for response matching and replay state.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(REQUEST_DIGEST_DOMAIN)
                .chain_update(self.to_canonical_bytes())
                .finalize()
                .into(),
        )
    }

    /// Returns the connection-local sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the Provider challenge and committed attempt digest.
    #[must_use]
    pub const fn attempt(&self) -> ([u8; 32], ObjectDigest) {
        (self.challenge, self.attempt_digest)
    }

    /// Returns the claimed holder and exact session binding.
    #[must_use]
    pub const fn holder_session(&self) -> ([u8; 16], ObjectDigest) {
        (self.holder_id, self.session_binding)
    }

    /// Returns the claimed Provider authority and acquisition identity.
    #[must_use]
    pub const fn provider_acquisition(&self) -> ([u8; 16], ObjectDigest) {
        (self.provider_id, self.acquisition_id)
    }

    /// Returns the named logical binding and asserted publication head.
    #[must_use]
    pub const fn selection(&self) -> (ObjectDigest, ObjectDigest) {
        (self.binding_digest, self.publication_head)
    }

    /// Returns the inclusive issue and exclusive expiry second.
    #[must_use]
    pub const fn validity(&self) -> (i64, i64) {
        (self.issued_seconds, self.valid_until_seconds)
    }

    /// Returns the untrusted native row set for independent Storage readback.
    #[must_use]
    pub const fn catalog(&self) -> &ProviderHeldSnapshotCatalogV1 {
        &self.catalog
    }

    /// Requires a strictly advancing sequence on the same live connection.
    ///
    /// # Errors
    ///
    /// Rejects equal or lower sequence values.
    pub fn validate_next_sequence(
        &self,
        previous_sequence: u64,
    ) -> Result<(), StorageZfsHoldTransportErrorV1> {
        if self.sequence <= previous_sequence {
            return Err(StorageZfsHoldTransportErrorV1::Replay);
        }
        Ok(())
    }
}

/// Acknowledges the exact request while withholding every native authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageZfsHoldUnavailableV1 {
    sequence: u64,
    challenge: [u8; 32],
    request_digest: ObjectDigest,
}

impl StorageZfsHoldUnavailableV1 {
    /// Constructs the sole response for a decoded request.
    #[must_use]
    pub fn for_request(request: &StorageZfsHoldTransportRequestV1) -> Self {
        Self {
            sequence: request.sequence,
            challenge: request.challenge,
            request_digest: request.digest(),
        }
    }

    /// Decodes an exact descriptor-free unavailable response.
    ///
    /// # Errors
    ///
    /// Rejects a wrong length, magic, version, status, or reserved byte.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StorageZfsHoldTransportErrorV1> {
        if bytes.len() != RESPONSE_BYTES
            || bytes.get(..8) != Some(RESPONSE_MAGIC.as_slice())
            || bytes.get(8..10) != Some(VERSION.to_be_bytes().as_slice())
            || bytes.get(10..16) != Some([0; 6].as_slice())
            || bytes[88] != 1
            || bytes[89..96] != [0; 7]
        {
            return Err(StorageZfsHoldTransportErrorV1::Noncanonical);
        }
        let response = Self {
            sequence: u64::from_be_bytes(array(bytes, 16)?),
            challenge: array(bytes, 24)?,
            request_digest: ObjectDigest::from_bytes(array(bytes, 56)?),
        };
        if response.sequence == 0
            || response.challenge == [0; 32]
            || response.request_digest.as_bytes() == &[0; 32]
        {
            return Err(StorageZfsHoldTransportErrorV1::Noncanonical);
        }
        Ok(response)
    }

    /// Encodes the exact unavailable response.
    #[must_use]
    pub fn to_canonical_bytes(self) -> [u8; RESPONSE_BYTES] {
        let mut bytes = [0; RESPONSE_BYTES];
        bytes[..8].copy_from_slice(RESPONSE_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[24..56].copy_from_slice(&self.challenge);
        bytes[56..88].copy_from_slice(self.request_digest.as_bytes());
        bytes[88] = 1;
        bytes
    }

    /// Matches the exact request, including all native catalog bytes.
    ///
    /// # Errors
    ///
    /// Rejects a response for another sequence, challenge, or request body.
    pub fn verify_for(
        self,
        request: &StorageZfsHoldTransportRequestV1,
    ) -> Result<(), StorageZfsHoldTransportErrorV1> {
        if self != Self::for_request(request) {
            return Err(StorageZfsHoldTransportErrorV1::ResponseMismatch);
        }
        Ok(())
    }
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], StorageZfsHoldTransportErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(StorageZfsHoldTransportErrorV1::Noncanonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProviderHeldSnapshotRowV1, ZfsHeldSnapshotProofV1};

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn request() -> StorageZfsHoldTransportRequestV1 {
        let proof = ZfsHeldSnapshotProofV1::new(
            [1; 32],
            2,
            3,
            4,
            5,
            [6; 16],
            7,
            digest(8),
            digest(9),
            digest(10),
        )
        .unwrap();
        let row = ProviderHeldSnapshotRowV1::new(
            digest(11),
            [12; 32],
            13,
            digest(14),
            15,
            digest(16),
            proof,
        )
        .unwrap();
        let catalog = ProviderHeldSnapshotCatalogV1::new(17, digest(18), vec![row]).unwrap();
        StorageZfsHoldTransportRequestV1::new(
            1,
            [19; 32],
            digest(20),
            [21; 16],
            [22; 16],
            digest(23),
            digest(24),
            digest(11),
            digest(25),
            100,
            150,
            catalog,
        )
        .unwrap()
    }

    #[test]
    fn canonical_request_and_unavailable_bind_every_byte() {
        let request = request();
        let bytes = request.to_canonical_bytes();
        assert_eq!(
            StorageZfsHoldTransportRequestV1::from_canonical_bytes(&bytes).unwrap(),
            request
        );
        let unavailable = StorageZfsHoldUnavailableV1::for_request(&request);
        assert_eq!(
            StorageZfsHoldUnavailableV1::from_canonical_bytes(&unavailable.to_canonical_bytes())
                .unwrap(),
            unavailable
        );
        unavailable.verify_for(&request).unwrap();

        let mut changed = bytes.clone();
        changed[REQUEST_HEADER_BYTES + 200] ^= 1;
        let other = StorageZfsHoldTransportRequestV1::from_canonical_bytes(&changed).unwrap();
        assert_eq!(
            unavailable.verify_for(&other),
            Err(StorageZfsHoldTransportErrorV1::ResponseMismatch)
        );

        let mut changed_response = unavailable.to_canonical_bytes();
        changed_response[56] ^= 1;
        let changed_response =
            StorageZfsHoldUnavailableV1::from_canonical_bytes(&changed_response).unwrap();
        assert_eq!(
            changed_response.verify_for(&request),
            Err(StorageZfsHoldTransportErrorV1::ResponseMismatch)
        );
    }

    #[test]
    fn rejects_missing_session_selection_and_malformed_frames() {
        let request = request();
        let bytes = request.to_canonical_bytes();
        for (start, end) in [
            (16, 24),
            (24, 56),
            (56, 88),
            (88, 104),
            (104, 120),
            (120, 152),
            (152, 184),
            (184, 216),
            (216, 248),
        ] {
            let mut changed = bytes.clone();
            changed[start..end].fill(0);
            assert!(
                StorageZfsHoldTransportRequestV1::from_canonical_bytes(&changed).is_err(),
                "field at {start}"
            );
        }
        for index in [0, 8, 10, 264] {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(StorageZfsHoldTransportRequestV1::from_canonical_bytes(&changed).is_err());
        }
        let mut changed = bytes.clone();
        changed[184..216].fill(12);
        assert!(StorageZfsHoldTransportRequestV1::from_canonical_bytes(&changed).is_err());
        let mut bytes = bytes;
        bytes.extend_from_slice(&[0]);
        assert!(StorageZfsHoldTransportRequestV1::from_canonical_bytes(&bytes).is_err());

        let mut malformed_response =
            StorageZfsHoldUnavailableV1::for_request(&request).to_canonical_bytes();
        malformed_response[88] = 2;
        assert!(StorageZfsHoldUnavailableV1::from_canonical_bytes(&malformed_response).is_err());
        assert_eq!(
            request.validate_next_sequence(1),
            Err(StorageZfsHoldTransportErrorV1::Replay)
        );
    }
}
