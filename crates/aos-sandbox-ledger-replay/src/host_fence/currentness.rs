//! Durable HostState writer quarantine paired with a Host Effect fence.
//!
//! ```text
//! HostExecution["\0aos-host-currentness-fence-v1\0"] =
//! AOSHCF01 | version:u16be | held:u8 | reserved[5]=0 |
//! execution-store-binding[32] | Effect-fence-record-digest[32] |
//! HostState-pre-fence-epoch:u64be | HostState-pre-fence-cut[32] |
//! hold-commit-sequence:u64be | SHA256(domain || preceding)[32]
//! ```
//!
//! A hold has no release transition. It is a nonauthorizing crash-recovery
//! anchor for one Effect fence, not an independent anti-rollback root.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as MechanicalError;
use aos_sandbox_core::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

/// Names the existing reserved historical fence key.
pub const KEY: &[u8] = b"\0aos-host-currentness-fence-v1\0";
/// Names the existing protected native-owner comparison key set.
pub const PEER_CURRENT_KEY: &[u8] = b"dormant-agent-peer-current-v1";
/// Names the existing protected native-owner comparison key set.
pub const CURRENTNESS_KEY: &[u8] = b"runtime-execution-currentness-v1";
/// Names the existing protected native-owner comparison key set.
pub const CAPABILITIES_KEY: &[u8] = b"runtime-backend-capabilities-v1";
/// Names the existing protected native-owner comparison key set.
pub const HOST_EVIDENCE_KEY: &[u8] = b"runtime-host-evidence-v1";
/// Names the existing protected native-owner comparison key set.
pub const PLAN_CATALOG_KEY: &[u8] = b"runtime-plan-catalog-v1";
/// Names the existing protected native-owner comparison key set.
pub const OWNER_KEYS: [&[u8]; 5] = [
    PEER_CURRENT_KEY,
    CURRENTNESS_KEY,
    CAPABILITIES_KEY,
    HOST_EVIDENCE_KEY,
    PLAN_CATALOG_KEY,
];

const MAGIC: &[u8; 8] = b"AOSHCF01";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.host-currentness-fence.v1\0";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.host-currentness-protected-cut.v1\0";
const RECORD_BYTES: usize = 160;

/// Pins the original HostState epoch and records to one Effect-fence record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCurrentnessFenceV1 {
    /// Binds the historical physical store.
    pub store_binding: ObjectDigest,
    /// Commits the paired Effect fence record.
    pub effect_fence_digest: ObjectDigest,
    /// Next-begin sequence before the HostState hold append.
    pub pre_hold_epoch: u64,
    /// Commits the original pre-hold materialized HostState records.
    pub pre_hold_cut: ObjectDigest,
    /// Commit-frame sequence; the retained snapshot is this value plus one.
    pub commit_sequence: u64,
}

impl HostCurrentnessFenceV1 {
    /// Encodes this exact historical fence without native authority.
    ///
    /// # Errors
    /// Refuses malformed fields, framing, checksum or canonical bytes.
    pub fn encode(self) -> Result<[u8; RECORD_BYTES], MechanicalError> {
        if self.store_binding.as_bytes() == &[0; 32]
            || self.effect_fence_digest.as_bytes() == &[0; 32]
            || self.pre_hold_epoch == 0
            || self.pre_hold_cut.as_bytes() == &[0; 32]
            || self.pre_hold_epoch.checked_add(2) != Some(self.commit_sequence)
        {
            return Err(MechanicalError::ProtectedBoundary);
        }

        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..48].copy_from_slice(self.store_binding.as_bytes());
        bytes[48..80].copy_from_slice(self.effect_fence_digest.as_bytes());
        bytes[80..88].copy_from_slice(&self.pre_hold_epoch.to_be_bytes());
        bytes[88..120].copy_from_slice(self.pre_hold_cut.as_bytes());
        bytes[120..128].copy_from_slice(&self.commit_sequence.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..128])
            .finalize();
        bytes[128..].copy_from_slice(&checksum);
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
            effect_fence_digest: ObjectDigest::from_bytes(
                bytes[48..80]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            pre_hold_epoch: u64::from_be_bytes(
                bytes[80..88]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            pre_hold_cut: ObjectDigest::from_bytes(
                bytes[88..120]
                    .try_into()
                    .map_err(|_| MechanicalError::ProtectedBoundary)?,
            ),
            commit_sequence: u64::from_be_bytes(
                bytes[120..128]
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

/// Hashes the exact materialized HostState records at one protected epoch.
///
/// # Errors
/// Refuses unrepresentable key/value widths or record-count overflow.
pub fn cut_v1<'a>(
    records: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    store_binding: ObjectDigest,
    epoch: u64,
    exclude_fence: bool,
) -> Result<ObjectDigest, MechanicalError> {
    let mut hash = Sha256::new()
        .chain_update(CUT_DOMAIN)
        .chain_update([RecordNamespace::HostExecution as u8])
        .chain_update(store_binding.as_bytes())
        .chain_update(epoch.to_be_bytes());
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
) -> Result<Option<HostCurrentnessFenceV1>, MechanicalError> {
    state
        .get(&(RecordNamespace::HostExecution, KEY.to_vec()))
        .map(|bytes| HostCurrentnessFenceV1::decode(bytes))
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
        .any(|record| record.namespace() == RecordNamespace::HostExecution && record.key() == KEY)
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
