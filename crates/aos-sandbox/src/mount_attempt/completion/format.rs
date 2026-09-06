//! Length-delimited codec for successful controller Mount receipts.
//!
//! ```text
//! AOSMTC01 | state:1 | flags:1 | reserved:2 | request-id:16 |
//! attempt-digest:32 | receipt-bytes:4 | receipt | digest:32
//! ```
//!
//! Integers and lengths are big endian. The final SHA-256 digest covers a
//! domain separator and every preceding byte, including the receipt.

use sha2::{Digest as _, Sha256};

use super::CompletionRecord;
use crate::mount_attempt::MountAttemptError;

const MAGIC: &[u8; 8] = b"AOSMTC01";
const DOMAIN: &[u8] = b"aos.sandbox.mount-completion.v1\0";
const STATE_SUCCEEDED: u8 = 1;
const PREFIX_BYTES: usize = 64;
const DIGEST_BYTES: usize = 32;
pub(super) const FIXED_RECORD_BYTES: usize = PREFIX_BYTES + DIGEST_BYTES;

impl CompletionRecord {
    fn body_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(STATE_SUCCEEDED);
        bytes.push(0);
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.attempt_digest);
        bytes.extend_from_slice(
            &u32::try_from(self.receipt.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.receipt);
        bytes
    }

    pub(in crate::mount_attempt) fn compute_digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(self.body_bytes())
            .finalize()
            .into()
    }

    pub(in crate::mount_attempt) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body_bytes();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub(in crate::mount_attempt) fn decode(mut bytes: &[u8]) -> Result<Self, MountAttemptError> {
        if bytes.len() < FIXED_RECORD_BYTES || take::<8>(&mut bytes)? != *MAGIC {
            return Err(MountAttemptError::CorruptState);
        }
        if take::<1>(&mut bytes)? != [STATE_SUCCEEDED]
            || take::<1>(&mut bytes)? != [0]
            || take::<2>(&mut bytes)? != [0; 2]
        {
            return Err(MountAttemptError::CorruptState);
        }

        let request_id = take(&mut bytes)?;
        let attempt_digest = take(&mut bytes)?;
        let receipt_bytes = usize::try_from(u32::from_be_bytes(take(&mut bytes)?))
            .map_err(|_| MountAttemptError::CorruptState)?;
        if bytes.len() != receipt_bytes.saturating_add(DIGEST_BYTES) {
            return Err(MountAttemptError::CorruptState);
        }
        let receipt = take_vec(&mut bytes, receipt_bytes)?;
        let digest = take(&mut bytes)?;
        let record = Self {
            request_id,
            attempt_digest,
            receipt,
            digest,
        };
        if !bytes.is_empty() || record.compute_digest() != record.digest {
            return Err(MountAttemptError::CorruptState);
        }
        Ok(record)
    }
}

fn take_vec(bytes: &mut &[u8], length: usize) -> Result<Vec<u8>, MountAttemptError> {
    let (prefix, remaining) = bytes
        .split_at_checked(length)
        .ok_or(MountAttemptError::CorruptState)?;
    *bytes = remaining;
    Ok(prefix.to_vec())
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], MountAttemptError> {
    let (prefix, remaining) = bytes
        .split_at_checked(N)
        .ok_or(MountAttemptError::CorruptState)?;
    let value = prefix
        .try_into()
        .map_err(|_| MountAttemptError::CorruptState)?;
    *bytes = remaining;
    Ok(value)
}
