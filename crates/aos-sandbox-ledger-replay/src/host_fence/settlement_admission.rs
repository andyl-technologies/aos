//! Reserved protected Effect key for admission-time settlement witnesses.
//!
//! Generic append, replacement, deletion, and compaction cannot manufacture
//! or erase an AOSCHA01 witness. Only the exact typed one-row append may use
//! this key; later historical recovery still needs independent signer and
//! currentness checks.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as MechanicalError;
use aos_sandbox_core::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use std::collections::BTreeMap;

/// Names the existing reserved Effect witness prefix.
pub const KEY_PREFIX: u8 = b'w';

/// Refuses any ordinary mutation of the reserved settlement-witness family.
///
/// # Errors
/// Refuses a proposed reserved witness key. It grants no typed append exception.
pub fn require_no_mutation_v1(
    _state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), MechanicalError> {
    if transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::Effect && record.key().first() == Some(&KEY_PREFIX)
    }) {
        return Err(MechanicalError::ProtectedBoundary);
    }

    Ok(())
}

/// Refuses compaction of an existing settlement-witness family.
///
/// # Errors
/// Refuses any retained reserved Effect key.
pub fn require_no_compaction_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), MechanicalError> {
    if state.keys().any(|(namespace, key)| {
        *namespace == RecordNamespace::Effect && key.first() == Some(&KEY_PREFIX)
    }) {
        return Err(MechanicalError::ProtectedBoundary);
    }
    Ok(())
}
