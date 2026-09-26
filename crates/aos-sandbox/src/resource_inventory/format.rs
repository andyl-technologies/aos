//! Length-delimited codec for authenticated Storage and Network snapshots.
//!
//! ```text
//! AOSBRI01 | state:1 | domain:1 | reserved:2 | request-id:16 |
//! controller-state:32 | request-bytes:4 | response-bytes:4 |
//! request | response | digest:32
//! ```
//!
//! Integers and lengths are big endian. The final SHA-256 digest covers a
//! domain separator and every preceding byte, including the broker domain and
//! both exact wire bodies.

use sha2::{Digest as _, Sha256};

use super::{InventoryDomain, ResourceInventoryError, SnapshotRecord};

const MAGIC: &[u8; 8] = b"AOSBRI01";
const DOMAIN: &[u8] = b"aos.sandbox.resource-inventory.v1\0";
const STATE_COMPLETE: u8 = 1;
const PREFIX_BYTES: usize = 68;
const DIGEST_BYTES: usize = 32;
pub(super) const FIXED_RECORD_BYTES: usize = PREFIX_BYTES + DIGEST_BYTES;

impl SnapshotRecord {
    fn body_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(STATE_COMPLETE);
        bytes.push(self.domain as u8);
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.controller_state_digest);
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

    pub(super) fn decode(mut bytes: &[u8]) -> Result<Self, ResourceInventoryError> {
        if bytes.len() < FIXED_RECORD_BYTES || take::<8>(&mut bytes)? != *MAGIC {
            return Err(ResourceInventoryError::CorruptState);
        }
        if take::<1>(&mut bytes)? != [STATE_COMPLETE] {
            return Err(ResourceInventoryError::CorruptState);
        }
        let domain = InventoryDomain::from_byte(take::<1>(&mut bytes)?[0])?;
        if take::<2>(&mut bytes)? != [0; 2] {
            return Err(ResourceInventoryError::CorruptState);
        }

        let request_id = take(&mut bytes)?;
        let controller_state_digest = take(&mut bytes)?;
        let request_bytes = length(&mut bytes)?;
        let response_bytes = length(&mut bytes)?;
        let variable_bytes = request_bytes
            .checked_add(response_bytes)
            .ok_or(ResourceInventoryError::CorruptState)?;
        if bytes.len() != variable_bytes.saturating_add(DIGEST_BYTES) {
            return Err(ResourceInventoryError::CorruptState);
        }
        let request_body = take_vec(&mut bytes, request_bytes)?;
        let response_body = take_vec(&mut bytes, response_bytes)?;
        let digest = take(&mut bytes)?;
        let record = Self {
            domain,
            request_id,
            controller_state_digest,
            request_body,
            response_body,
            digest,
        };
        if !bytes.is_empty() || record.compute_digest() != record.digest {
            return Err(ResourceInventoryError::CorruptState);
        }

        Ok(record)
    }
}

fn length(bytes: &mut &[u8]) -> Result<usize, ResourceInventoryError> {
    usize::try_from(u32::from_be_bytes(take(bytes)?))
        .map_err(|_| ResourceInventoryError::CorruptState)
}

fn take_vec(bytes: &mut &[u8], length: usize) -> Result<Vec<u8>, ResourceInventoryError> {
    let (prefix, remaining) = bytes
        .split_at_checked(length)
        .ok_or(ResourceInventoryError::CorruptState)?;
    *bytes = remaining;

    Ok(prefix.to_vec())
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], ResourceInventoryError> {
    let (prefix, remaining) = bytes
        .split_at_checked(N)
        .ok_or(ResourceInventoryError::CorruptState)?;
    let value = prefix
        .try_into()
        .map_err(|_| ResourceInventoryError::CorruptState)?;
    *bytes = remaining;

    Ok(value)
}
