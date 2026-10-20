//! Prepares the existing record/head transaction as passive format DATA.
//!
//! These helpers allocate the same ordered pair after the same canonical
//! envelope/head comparisons. They perform no IO, authenticate no live owner,
//! and grant no append, replay, receiving or effect authority.

use aos_sandbox_core::RecordNamespace;
use super::{HEAD_BYTES, KeyV1, LatestHeadV1, PhaseV1, RecordEnvelopeV1};
use super::native_suffix::history_pair_transaction_id_v1;
use crate::domain_ledger::transaction::{JournalRecord, JournalTransaction};

/// Preserves format refusal separately from the actual transaction constructor.
#[derive(Debug, thiserror::Error)]
pub enum HistoryPairPreparationErrorV1 {
    /// A supplied envelope and latest-head pair failed the original comparison.
    #[error("protected journal storage boundary is invalid")]
    Envelope,
    /// The original shared transaction DATA constructor refused the pair.
    #[error(transparent)]
    Transaction(#[from] crate::domain_ledger::JournalTransactionDataError),
}

/// Prepares exactly one ordered record/head pair without admitting its append.
///
/// # Errors
/// Rejects malformed envelopes, substituted heads, or native transaction limits.
pub fn prepare_history_pair_v1(
    key: KeyV1,
    phase: PhaseV1,
    record: &[u8],
    head: &[u8; HEAD_BYTES],
) -> Result<JournalTransaction, HistoryPairPreparationErrorV1> {
    let envelope = RecordEnvelopeV1::decode(record, key, phase)
        .map_err(|_| HistoryPairPreparationErrorV1::Envelope)?;
    let latest = KeyV1::new(key.lane(), key.owner(), 0)
        .map_err(|_| HistoryPairPreparationErrorV1::Envelope)?;
    LatestHeadV1::decode(head, latest)
        .and_then(|observed| observed.check_record(latest, envelope))
        .map_err(|_| HistoryPairPreparationErrorV1::Envelope)?;

    let id = history_pair_transaction_id_v1(key.owner(), envelope.checksum());

    JournalTransaction::new(id, vec![
        JournalRecord::put(RecordNamespace::CreateStorageHistory, key.encode().to_vec(), record.to_vec()),
        JournalRecord::put(RecordNamespace::CreateStorageHistory, latest.encode().to_vec(), head.to_vec()),
    ]).map_err(Into::into)
}
