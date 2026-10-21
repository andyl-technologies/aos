//! Binds the canonical Delete batch DATA recipe to Cache's private preview.
//!
//! Replay and append use the same transaction view and schema. This adapter
//! supplies no native owner, exception, paid role or Delete authority.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use super::{JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};

fn validate_transaction(transaction: &JournalTransaction, limits: JournalLimits) -> Result<(), JournalError> {
    aos_sandbox_protocol::domain_ledger::transaction::validate_transaction(transaction, limits).map_err(JournalError::from)
}
use std::collections::BTreeMap;
use aos_sandbox_protocol::domain_ledger::{
    controller_history_relation::validate_delete_batch_admission_records_v1,
    delete_batch::{self as codec, DeleteBatchViewV1},
};

pub(super) enum PreflightTransactionViewV1<'a> {
    Ordinary(&'a [JournalTransaction]),
}

impl PreflightTransactionViewV1<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Ordinary(rows) => rows.len(),
        }
    }

    fn transaction(&self, index: usize) -> &JournalTransaction {
        match self {
            Self::Ordinary(rows) => &rows[index],
        }
    }
}

aos_sandbox_ledger_replay::define_delete_replay_data_recipe_v1!();
