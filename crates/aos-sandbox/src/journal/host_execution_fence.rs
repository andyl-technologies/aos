//! Durable, nonauthorizing Host Effect writer fence for a failed Create.
//!
//! ```text
//! Effect["\0aos-host-execution-fence-v1\0"] =
//! AOSCHF01 | version:u16be | held:u8 | reserved[5]=0 |
//! store-binding[32] | execution[16] | preliminary-digest[32] |
//! pre-fence-epoch:u64be | pre-fence-cut[32] |
//! fence-commit-sequence:u64be | SHA256(domain || preceding)[32]
//! ```
//!
//! This version has no release transition. A retained fence quarantines the
//! Effect journal until a separately qualified cross-owner recovery exists.

use std::collections::BTreeMap;

use aos_sandbox_core::{ExecutionId, ObjectDigest};
use sha2::{Digest as _, Sha256};

use super::{JournalError, JournalTransaction, RecordNamespace};

pub(crate) const KEY: &[u8] = b"\0aos-host-execution-fence-v1\0";
pub(crate) const RUNTIME_OWNER_MARKER_KEY: &[u8] = b"runtime-execution-owner-v1";
const MAGIC: &[u8; 8] = b"AOSCHF01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.host-execution-fence.v1\0";
const EFFECT_CUT_DOMAIN: &[u8] = b"aos.sandbox.host-settlement-protected-cut.v1\0";
const RECORD_BYTES: usize = 176;

/// Pins one preliminary Host settlement record to an immutable Effect cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostExecutionFenceV1 {
    pub(crate) store_binding: ObjectDigest,
    pub(crate) execution: ExecutionId,
    pub(crate) preliminary_digest: ObjectDigest,
    /// Next-begin sequence at the protected pre-fence snapshot.
    pub(crate) pre_fence_epoch: u64,
    pub(crate) pre_fence_cut: ObjectDigest,
    /// Commit-frame sequence; the post-append snapshot is this value plus one.
    pub(crate) commit_sequence: u64,
}

impl HostExecutionFenceV1 {
    pub(crate) fn encode(self) -> Result<[u8; RECORD_BYTES], JournalError> {
        if self.store_binding.as_bytes() == &[0; 32]
            || self.execution.as_bytes() == &[0; 16]
            || self.preliminary_digest.as_bytes() == &[0; 32]
            || self.pre_fence_epoch == 0
            || self.pre_fence_cut.as_bytes() == &[0; 32]
            || self.commit_sequence <= self.pre_fence_epoch
        {
            return Err(JournalError::ProtectedBoundary);
        }

        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..48].copy_from_slice(self.store_binding.as_bytes());
        bytes[48..64].copy_from_slice(self.execution.as_bytes());
        bytes[64..96].copy_from_slice(self.preliminary_digest.as_bytes());
        bytes[96..104].copy_from_slice(&self.pre_fence_epoch.to_be_bytes());
        bytes[104..136].copy_from_slice(self.pre_fence_cut.as_bytes());
        bytes[136..144].copy_from_slice(&self.commit_sequence.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..144])
            .finalize();
        bytes[144..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let fence = Self {
            store_binding: ObjectDigest::from_bytes(
                bytes[16..48]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            execution: ExecutionId::from_bytes(
                bytes[48..64]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            preliminary_digest: ObjectDigest::from_bytes(
                bytes[64..96]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            pre_fence_epoch: u64::from_be_bytes(
                bytes[96..104]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            pre_fence_cut: ObjectDigest::from_bytes(
                bytes[104..136]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
            commit_sequence: u64::from_be_bytes(
                bytes[136..144]
                    .try_into()
                    .map_err(|_| JournalError::ProtectedBoundary)?,
            ),
        };
        if fence.encode()?.as_slice() != bytes {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(fence)
    }
}

/// Hashes exactly the bytewise-ordered materialized Effect view and snapshot.
pub(crate) fn effect_cut_v1<'a>(
    records: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    store_binding: ObjectDigest,
    sequence: u64,
    exclude_fence: bool,
) -> Result<ObjectDigest, JournalError> {
    let mut hash = Sha256::new()
        .chain_update(EFFECT_CUT_DOMAIN)
        .chain_update([RecordNamespace::Effect as u8])
        .chain_update(store_binding.as_bytes())
        .chain_update(sequence.to_be_bytes());
    let mut count = 0_u64;

    for (key, value) in records {
        if exclude_fence && key == KEY {
            continue;
        }
        let key_len = u64::try_from(key.len()).map_err(|_| JournalError::ProtectedBoundary)?;
        let value_len = u64::try_from(value.len()).map_err(|_| JournalError::ProtectedBoundary)?;
        hash.update(key_len.to_be_bytes());
        hash.update(key);
        hash.update(value_len.to_be_bytes());
        hash.update(value);
        count = count
            .checked_add(1)
            .ok_or(JournalError::ProtectedBoundary)?;
    }
    hash.update(count.to_be_bytes());
    Ok(ObjectDigest::from_bytes(hash.finalize().into()))
}

fn current(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<HostExecutionFenceV1>, JournalError> {
    state
        .get(&(RecordNamespace::Effect, KEY.to_vec()))
        .map(|bytes| HostExecutionFenceV1::decode(bytes))
        .transpose()
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    allow_acquisition: bool,
) -> Result<(), JournalError> {
    if current(state)?.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    let touches_fence = transaction
        .records()
        .iter()
        .any(|record| record.namespace() == RecordNamespace::Effect && record.key() == KEY);
    if !touches_fence {
        return Ok(());
    }
    if !allow_acquisition || transaction.records().len() != 1 {
        return Err(JournalError::ProtectedBoundary);
    }
    let record = &transaction.records()[0];
    let bytes = record.value().ok_or(JournalError::ProtectedBoundary)?;
    HostExecutionFenceV1::decode(bytes)?;
    Ok(())
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    if current(state)?.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fence_record_rejects_corrupt_and_noncanonical_bytes() {
        let fence = HostExecutionFenceV1 {
            store_binding: ObjectDigest::from_bytes([1; 32]),
            execution: ExecutionId::from_bytes([2; 16]),
            preliminary_digest: ObjectDigest::from_bytes([3; 32]),
            pre_fence_epoch: 7,
            pre_fence_cut: ObjectDigest::from_bytes([4; 32]),
            commit_sequence: 9,
        };
        let bytes = fence.encode().expect("canonical fence");
        assert_eq!(
            HostExecutionFenceV1::decode(&bytes).expect("round trip"),
            fence
        );

        for offset in [0, 8, 10, 11, 16, 48, 64, 96, 104, 136, 144] {
            let mut corrupt = bytes;
            corrupt[offset] ^= 1;
            assert!(HostExecutionFenceV1::decode(&corrupt).is_err());
        }
        assert!(HostExecutionFenceV1::decode(&bytes[..175]).is_err());
    }
}
