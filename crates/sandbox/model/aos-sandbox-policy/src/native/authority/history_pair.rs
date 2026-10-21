//! Compares the actual Authority's committed history pair as passive DATA.
//!
//! The real owner remains borrowed throughout its original map/NEXT readback.
//! This comparison performs no native observation and does not replace the
//! caller's full suffix validation, admission or independently owed posts.

use aos_sandbox_broker::canonical_journal::CommitResult;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HEAD_BYTES,
    readback::{HistoryPairReadbackBytesDataV1, HistoryPairReadbackDataV1},
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use super::RootAuthorityOriginalV1;
use crate::native::PolicyNativeJournalErrorV1;

impl RootAuthorityOriginalV1 {
    /// Compares the exact pair and returned NEXT in this same actual owner.
    ///
    /// This reads only resident historical rows. It grants no append, phase,
    /// native currentness or successful full-prefix acceptance.
    ///
    /// # Errors
    /// Refuses substituted transaction members, missing or differing bytes,
    /// differing fixed widths, or a returned COMMIT/NEXT outside the same pair.
    pub fn readback_history_pair_v1<const RECORD: usize>(
        &self,
        transaction: &JournalTransaction,
        record: &[u8; RECORD],
        head: &[u8; HEAD_BYTES],
        before_next: u64,
        committed: &CommitResult,
    ) -> Result<HistoryPairReadbackDataV1<RECORD>, PolicyNativeJournalErrorV1> {
        let journal = &self.journal;
        let observed: Result<HistoryPairReadbackBytesDataV1<'_>, PolicyNativeJournalErrorV1> =
            aos_sandbox_protocol::readback_create_storage_history_pair_bytes_data_v1! {
            journal: journal,
            transaction: transaction,
            record: record,
            head: head,
            before_next: before_next,
            committed: committed,
            namespace: RecordNamespace::CreateStorageHistory,
            boundary: PolicyNativeJournalErrorV1::boundary(),
            result: HistoryPairReadbackBytesDataV1,
        };
        let observed = observed?;
        Ok(HistoryPairReadbackDataV1 {
            record: observed.record.try_into()
                .map_err(|_| PolicyNativeJournalErrorV1::boundary())?,
            head: observed.head,
            next: observed.next,
        })
    }
}
