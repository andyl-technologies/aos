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

use aos_sandbox_model::{ExecutionId, ObjectDigest};
use sha2::{Digest as _, Sha256};

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as MechanicalError;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

/// Names the existing reserved historical fence key.
pub const KEY: &[u8] = b"\0aos-host-execution-fence-v1\0";
/// Names the existing protected native-owner comparison key set.
pub const RUNTIME_OWNER_MARKER_KEY: &[u8] = b"runtime-execution-owner-v1";
const MAGIC: &[u8; 8] = b"AOSCHF01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.host-execution-fence.v1\0";
const EFFECT_CUT_DOMAIN: &[u8] = b"aos.sandbox.host-settlement-protected-cut.v1\0";
const RECORD_BYTES: usize = 176;

/// Pins one preliminary Host settlement record to an immutable Effect cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostExecutionFenceV1 {
    /// Binds the historical physical store.
    pub store_binding: ObjectDigest,
    /// Names the historical failed execution.
    pub execution: ExecutionId,
    /// Commits the preliminary settlement record.
    pub preliminary_digest: ObjectDigest,
    /// Next-begin sequence at the protected pre-fence snapshot.
    pub pre_fence_epoch: u64,
    /// Commits the original pre-fence materialized records.
    pub pre_fence_cut: ObjectDigest,
    /// Commit-frame sequence; the post-append snapshot is this value plus one.
    pub commit_sequence: u64,
}

impl HostExecutionFenceV1 {
    /// Encodes this exact historical fence without native authority.
    ///
    /// # Errors
    /// Refuses malformed fields, framing, checksum or canonical bytes.
    pub fn encode(self) -> Result<[u8; RECORD_BYTES], MechanicalError> {
        if self.store_binding.as_bytes() == &[0; 32]
            || self.execution.as_bytes() == &[0; 16]
            || self.preliminary_digest.as_bytes() == &[0; 32]
            || self.pre_fence_epoch == 0
            || self.pre_fence_cut.as_bytes() == &[0; 32]
            || self.commit_sequence <= self.pre_fence_epoch
        {
            return Err(MechanicalError::ProtectedBoundary);
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

    /// Decodes one exact historical fence without asserting current custody.
    ///
    /// # Errors
    /// Refuses malformed fields, framing, checksum or canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, MechanicalError> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(MechanicalError::ProtectedBoundary);
        }
        let fence = Self {
            store_binding: ObjectDigest::from_bytes(
                bytes[16..48]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            execution: ExecutionId::from_bytes(
                bytes[48..64]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            preliminary_digest: ObjectDigest::from_bytes(
                bytes[64..96]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            pre_fence_epoch: u64::from_be_bytes(
                bytes[96..104]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            pre_fence_cut: ObjectDigest::from_bytes(
                bytes[104..136]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            commit_sequence: u64::from_be_bytes(
                bytes[136..144]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
        };
        if fence.encode()?.as_slice() != bytes {
            return Err(MechanicalError::ProtectedBoundary);
        }
        Ok(fence)
    }
}

/// Hashes exactly the bytewise-ordered materialized Effect view and snapshot.
///
/// # Errors
/// Refuses unrepresentable key/value widths or record-count overflow.
pub fn effect_cut_v1<'a>(
    records: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    store_binding: ObjectDigest,
    sequence: u64,
    exclude_fence: bool,
) -> Result<ObjectDigest, MechanicalError> {
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
        let key_len = u64::try_from(key.len()).map_err(|_| MechanicalError::ProtectedBoundary)?;
        let value_len =
            u64::try_from(value.len()).map_err(|_| MechanicalError::ProtectedBoundary)?;
        hash.update(key_len.to_be_bytes());
        hash.update(key);
        hash.update(value_len.to_be_bytes());
        hash.update(value);
        count = count
            .checked_add(1)
            .ok_or(MechanicalError::ProtectedBoundary)?;
    }
    hash.update(count.to_be_bytes());
    Ok(ObjectDigest::from_bytes(hash.finalize().into()))
}

/// Reads the sole canonical fence from the actual supplied historical map.
///
/// # Errors
/// Refuses a noncanonical retained fence. This comparison supplies no custody.
pub fn current_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<HostExecutionFenceV1>, MechanicalError> {
    state
        .get(&(RecordNamespace::Effect, KEY.to_vec()))
        .map(|bytes| HostExecutionFenceV1::decode(bytes))
        .transpose()
}

/// Refuses retained fences and any ordinary mutation of the reserved key.
///
/// This deny-only DATA predicate has no native acquisition exception.
/// # Errors
/// Refuses a retained/malformed fence or an attempted fence-key mutation.
pub fn require_no_mutation_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), MechanicalError> {
    if current_v1(state)?.is_some() {
        return Err(MechanicalError::ProtectedBoundary);
    }
    if transaction
        .records()
        .iter()
        .any(|record| record.namespace() == RecordNamespace::Effect && record.key() == KEY)
    {
        return Err(MechanicalError::ProtectedBoundary);
    }
    Ok(())
}

/// Refuses compaction while the actual supplied map retains a fence.
///
/// # Errors
/// Refuses a retained or malformed historical fence.
pub fn require_no_compaction_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), MechanicalError> {
    if current_v1(state)?.is_some() {
        return Err(MechanicalError::ProtectedBoundary);
    }
    Ok(())
}
