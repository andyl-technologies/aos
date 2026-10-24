//! Reserved protected Effect key for admission-time settlement witnesses.
//!
//! Generic append, replacement, deletion, and compaction cannot manufacture
//! or erase an AOSCHA01 witness. Only the exact typed one-row append may use
//! this key; later historical recovery still needs independent signer and
//! currentness checks.

use std::collections::BTreeMap;

use super::{JournalError, JournalTransaction, RecordNamespace};

use aos_sandbox_ledger_replay::host_fence::settlement_admission as canonical;
pub(crate) use canonical::KEY_PREFIX;

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    allow_exact_append: bool,
) -> Result<(), JournalError> {
    if !allow_exact_append {
        return canonical::require_no_mutation_v1(state, transaction).map_err(JournalError::from);
    }

    let reserved = transaction.records().iter().filter(|record| {
        record.namespace() == RecordNamespace::Effect && record.key().first() == Some(&KEY_PREFIX)
    });
    for record in reserved {
        if !allow_exact_append
            || transaction.records().len() != 1
            || record.key().len() != 17
            || record.value().is_none()
            || state.contains_key(&(RecordNamespace::Effect, record.key().to_vec()))
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    Ok(())
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    canonical::require_no_compaction_v1(state).map_err(JournalError::from)
}
