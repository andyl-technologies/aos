//! Length-delimited codec for exact Mount source-acquisition snapshots.
//!
//! ```text
//! AOSCSI01 | state:1 | flags:1 | reserved:2 | request-id:16 |
//! controller-state:32 | response-digest:32 |
//! request-bytes:4 | response-bytes:4 |
//! request | response | digest:32
//! ```
//!
//! Integers and lengths are big endian. The final SHA-256 digest covers a
//! domain separator and every preceding byte, including both exact wire bodies.

use aos_sandbox_core::bounded_codec::BoundedReader;
use sha2::{Digest as _, Sha256};

use super::{MountSourceAcquisitionInventoryError, SnapshotRecord};

const MAGIC: &[u8; 8] = b"AOSCSI01";
const DOMAIN: &[u8] = b"aos.sandbox.mount-source-acquisition-inventory.v1\0";
const STATE_COMPLETE: u8 = 1;
const PREFIX_BYTES: usize = 100;
const DIGEST_BYTES: usize = 32;
pub(super) const FIXED_RECORD_BYTES: usize = PREFIX_BYTES + DIGEST_BYTES;

impl SnapshotRecord {
    fn body_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(STATE_COMPLETE);
        bytes.push(0);
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.controller_state_digest);
        bytes.extend_from_slice(&self.response_digest);
        bytes.extend_from_slice(
            &u32::try_from(self.request_body.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.response_body.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.request_body);
        bytes.extend_from_slice(&self.response_body);
        bytes
    }

    pub(super) fn compute_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(self.body_bytes())
            .finalize()
            .into()
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body_bytes();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, MountSourceAcquisitionInventoryError> {
        let mut reader = BoundedReader::new(bytes, |_| {
            MountSourceAcquisitionInventoryError::CorruptState
        });

        if bytes.len() < FIXED_RECORD_BYTES || reader.array::<8>()? != *MAGIC {
            return Err(MountSourceAcquisitionInventoryError::CorruptState);
        }
        if reader.array::<1>()? != [STATE_COMPLETE]
            || reader.array::<1>()? != [0]
            || reader.array::<2>()? != [0; 2]
        {
            return Err(MountSourceAcquisitionInventoryError::CorruptState);
        }

        let request_id = reader.array()?;
        let controller_state_digest = reader.array()?;
        let response_digest = reader.array()?;
        let request_bytes = length(&mut reader)?;
        let response_bytes = length(&mut reader)?;
        let variable_bytes = request_bytes
            .checked_add(response_bytes)
            .ok_or(MountSourceAcquisitionInventoryError::CorruptState)?;
        if reader.remaining() != variable_bytes.saturating_add(DIGEST_BYTES) {
            return Err(MountSourceAcquisitionInventoryError::CorruptState);
        }
        let request_body = reader.bytes(request_bytes)?.to_vec();
        let response_body = reader.bytes(response_bytes)?.to_vec();
        let digest = reader.array()?;
        let record = Self {
            request_id,
            controller_state_digest,
            response_digest,
            request_body,
            response_body,
            digest,
        };
        if !reader.is_empty() || record.compute_digest() != record.digest {
            return Err(MountSourceAcquisitionInventoryError::CorruptState);
        }
        Ok(record)
    }
}

fn length(
    reader: &mut BoundedReader<'_, MountSourceAcquisitionInventoryError>,
) -> Result<usize, MountSourceAcquisitionInventoryError> {
    usize::try_from(u32::from_be_bytes(reader.array()?))
        .map_err(|_| MountSourceAcquisitionInventoryError::CorruptState)
}
