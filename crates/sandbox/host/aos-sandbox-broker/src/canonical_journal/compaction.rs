//! Shares canonical sorted snapshot batching without compaction admission.
//!
//! Role owners retain eligibility, original locks/files, protected replacement,
//! publication and semantic replay. This helper only encodes supplied DATA.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use aos_sandbox_journal::materialized::RecordMutationRef;
use aos_sandbox_journal::geometry::EncodedRecordLayout;
use aos_sandbox_journal::framing::FrameError;
use aos_sandbox_protocol::domain_ledger::JournalTransactionDataError;
use super::{data, RecordNamespace, JournalLimits, JournalRecord, JournalTransaction};

/// Preserves the original ordered compaction encoder's error vocabulary.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalCompactionErrorV1 {
    /// Preserves an actual write or flush error.
    #[error(transparent)] Io(#[from] std::io::Error),
    /// Preserves the shared native geometry/encoder refusal.
    #[error(transparent)] Frame(#[from] FrameError),
    /// Preserves the sole canonical transaction validator refusal.
    #[error(transparent)] Transaction(#[from] JournalTransactionDataError),
    /// Refuses a configured count or representation bound.
    #[error("journal limit exceeded: {0}")] LimitExceeded(&'static str),
    /// Refuses unrepresentable sequence progression.
    #[error("journal sequence exhausted")] SequenceExhausted,
}

/// Writes supplied sorted materialized DATA using the original native batching.
///
/// # Errors
/// Preserves lookahead-width, prior-batch count/schema, write and final flush
/// order. Success proves no protected compaction, publication or role admission.
pub fn write_compacted_data(
    file: &mut File,
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    limits: JournalLimits,
) -> Result<(), CanonicalCompactionErrorV1> {
    let mut first_sequence = 1_u64;
    let mut transaction_index = 0_u64;
    let mut chunk = Vec::new();
    let mut chunk_bytes = 0_usize;
    for ((namespace, key), value) in state {
        let record = RecordMutationRef {
            namespace: *namespace,
            key,
            value: Some(value.as_slice()),
        };
        // Preserve lookahead representation refusal before flushing the prior chunk.
        let record_bytes =
            EncodedRecordLayout::new(key.len(), Some(value.len()))?.payload_bytes;
        if !chunk.is_empty()
            && (chunk.len() == limits.maximum_records_per_transaction
                || chunk_bytes.saturating_add(record_bytes) > limits.maximum_transaction_bytes)
        {
            if transaction_index >= limits.maximum_transactions as u64 {
                return Err(CanonicalCompactionErrorV1::LimitExceeded("committed transaction count"));
            }
            first_sequence = write_compaction_transaction(
                file,
                &chunk,
                transaction_index,
                first_sequence,
                limits,
            )?;
            transaction_index = transaction_index
                .checked_add(1)
                .ok_or(CanonicalCompactionErrorV1::SequenceExhausted)?;
            chunk.clear();
            chunk_bytes = 0;
        }
        chunk_bytes = chunk_bytes
            .checked_add(record_bytes)
            .ok_or(CanonicalCompactionErrorV1::LimitExceeded("transaction bytes"))?;
        chunk.push(record);
    }
    if !chunk.is_empty() {
        if transaction_index >= limits.maximum_transactions as u64 {
            return Err(CanonicalCompactionErrorV1::LimitExceeded("committed transaction count"));
        }
        write_compaction_transaction(file, &chunk, transaction_index, first_sequence, limits)?;
    }
    file.flush()?;
    Ok(())
}

fn write_compaction_transaction(
    file: &mut File,
    records: &[RecordMutationRef<'_, RecordNamespace>],
    transaction_index: u64,
    first_sequence: u64,
    limits: JournalLimits,
) -> Result<u64, CanonicalCompactionErrorV1> {
    let mut id = [0_u8; 16];
    id[..8].copy_from_slice(&(transaction_index + 1).to_le_bytes());
    id[8..].copy_from_slice(b"compact1");
    let records = records
        .iter()
        .map(|record| {
            let namespace = record.namespace;
            let key = record.key.to_vec();
            match record.value {
                Some(value) => JournalRecord::put(namespace, key, value.to_vec()),
                None => JournalRecord::delete(namespace, key),
            }
        })
        .collect();
    let transaction = JournalTransaction::new(id, records)?;
    data::validate_transaction(&transaction, limits)?;
    let frames = data::encode_transaction(&transaction, first_sequence)?;
    for frame in &frames {
        file.write_all(frame)?;
    }
    first_sequence
        .checked_add(frames.len() as u64)
        .ok_or(CanonicalCompactionErrorV1::SequenceExhausted)
}
