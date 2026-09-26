//! Reserved protected Effect key for admission-time settlement witnesses.
//!
//! Generic append, replacement, deletion, and compaction cannot manufacture
//! or erase an AOSCHA01 witness. Only the exact typed one-row append may use
//! this key; later historical recovery still needs independent signer and
//! currentness checks.

use std::collections::BTreeMap;

use super::{JournalError, JournalTransaction, RecordNamespace};

pub(crate) const KEY_PREFIX: u8 = b'w';

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    allow_exact_append: bool,
) -> Result<(), JournalError> {
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
    if state.keys().any(|(namespace, key)| {
        *namespace == RecordNamespace::Effect && key.first() == Some(&KEY_PREFIX)
    }) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}
