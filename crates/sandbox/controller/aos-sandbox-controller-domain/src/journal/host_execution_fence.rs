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
use aos_sandbox_model::ObjectDigest;
use super::{JournalError, JournalTransaction, RecordNamespace};
#[cfg(test)]
use aos_sandbox_model::ExecutionId;
use aos_sandbox_ledger_replay::host_fence::execution as canonical;
pub(crate) use canonical::{KEY, RUNTIME_OWNER_MARKER_KEY, HostExecutionFenceV1};

/// Hashes the same ordered historical records through the sole DATA recipe.
pub(crate) fn effect_cut_v1<'a>(
    records: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    store_binding: ObjectDigest,
    sequence: u64,
    exclude_fence: bool,
) -> Result<ObjectDigest, JournalError> {
    canonical::effect_cut_v1(records, store_binding, sequence, exclude_fence)
        .map_err(JournalError::from)
}

fn current(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<HostExecutionFenceV1>, JournalError> {
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
        .any(|record| record.namespace() == RecordNamespace::Effect && record.key() == KEY);
    if !touches_fence {
        return Ok(());
    }
    if !allow_acquisition || transaction.records().len() != 1 {
        return Err(JournalError::ProtectedBoundary);
    }
    let record = &transaction.records()[0];
    let bytes = record.value().ok_or(JournalError::ProtectedBoundary)?;
    HostExecutionFenceV1::decode(bytes).map_err(JournalError::from)?;
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
