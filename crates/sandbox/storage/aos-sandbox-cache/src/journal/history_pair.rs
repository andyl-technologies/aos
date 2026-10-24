//! Binds canonical passive pair comparisons to the same private Cache writer.

use aos_sandbox_protocol::domain_ledger::create_storage_history::HEAD_BYTES;
use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::{
    HistoryPairReadbackDataV1, HistoryPairReadbackBytesDataV1,
};
use super::{CommitResult, Journal, JournalError, JournalTransaction, RecordNamespace};

pub(crate) fn readback_history_pair_v1<const RECORD: usize>(
    journal: &Journal,
    transaction: &JournalTransaction,
    record: &[u8; RECORD],
    head: &[u8; HEAD_BYTES],
    before_next: u64,
    committed: &CommitResult,
) -> Result<HistoryPairReadbackDataV1<RECORD>, JournalError> {
    let observed = readback_history_pair_bytes_v1(journal, transaction, record, head, before_next, committed)?;
    Ok(HistoryPairReadbackDataV1 {
        record: observed.record.try_into().map_err(|_| JournalError::boundary())?,
        head: observed.head,
        next: observed.next,
    })
}

pub(crate) fn readback_history_pair_bytes_v1<'journal>(
    journal: &'journal Journal,
    transaction: &JournalTransaction,
    record: &[u8],
    head: &[u8; HEAD_BYTES],
    before_next: u64,
    committed: &CommitResult,
) -> Result<HistoryPairReadbackBytesDataV1<'journal>, JournalError> {
    aos_sandbox_protocol::readback_create_storage_history_pair_bytes_data_v1! {
        journal: journal,
        transaction: transaction,
        record: record,
        head: head,
        before_next: before_next,
        committed: committed,
        namespace: RecordNamespace::CreateStorageHistory,
        boundary: JournalError::boundary(),
        result: HistoryPairReadbackBytesDataV1,
    }
}
