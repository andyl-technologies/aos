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
use super::{JournalError, JournalTransaction, RecordNamespace};
use aos_sandbox_ledger_replay::host_fence::currentness as canonical;
pub(crate) use canonical::{KEY, PEER_CURRENT_KEY, CURRENTNESS_KEY, CAPABILITIES_KEY, HOST_EVIDENCE_KEY, PLAN_CATALOG_KEY, OWNER_KEYS, HostCurrentnessFenceV1};

/// Hashes the same ordered historical records through the sole DATA recipe.
pub(crate) fn cut_v1<'a>(
    records: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    store_binding: ObjectDigest,
    epoch: u64,
    exclude_fence: bool,
) -> Result<ObjectDigest, JournalError> {
    canonical::cut_v1(records, store_binding, epoch, exclude_fence)
        .map_err(JournalError::from)
}

fn current(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<HostCurrentnessFenceV1>, JournalError> {
    canonical::current_v1(state).map_err(JournalError::from)
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    allow_acquisition: bool,
) -> Result<(), JournalError> {
    if !allow_acquisition {
        return canonical::require_no_mutation_v1(state, transaction).map_err(JournalError::from);
    }

    if current(state)?.is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    let touches_fence = transaction
        .records()
        .iter()
        .any(|record| record.namespace() == RecordNamespace::HostExecution && record.key() == KEY);
    if !touches_fence {
        return Ok(());
    }
    if !allow_acquisition || transaction.records().len() != 1 {
        return Err(JournalError::ProtectedBoundary);
    }
    let bytes = transaction.records()[0]
        .value()
        .ok_or(JournalError::ProtectedBoundary)?;
    HostCurrentnessFenceV1::decode(bytes).map_err(JournalError::from)?;
    Ok(())
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    canonical::require_no_compaction_v1(state).map_err(JournalError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_currentness_fence_codec_rejects_corruption() {
        let fence = HostCurrentnessFenceV1 {
            store_binding: ObjectDigest::from_bytes([1; 32]),
            effect_fence_digest: ObjectDigest::from_bytes([2; 32]),
            pre_hold_epoch: 7,
            pre_hold_cut: ObjectDigest::from_bytes([3; 32]),
            commit_sequence: 9,
        };
        let bytes = fence.encode().expect("canonical fence");
        assert_eq!(
            HostCurrentnessFenceV1::decode(&bytes).expect("round trip"),
            fence
        );
        for offset in [0, 8, 10, 11, 16, 48, 80, 88, 120, 128] {
            let mut corrupt = bytes;
            corrupt[offset] ^= 1;
            assert!(HostCurrentnessFenceV1::decode(&corrupt).is_err());
        }
    }
}
