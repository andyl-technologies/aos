//! Binds the canonical Delete batch DATA recipe to Source's private preview.
//!
//! Replay and append use the same transaction view and schema. This adapter
//! supplies no native owner, exception, paid role or Delete authority.

use super::validate_transaction;
use super::{JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::{
    controller_history_relation::validate_delete_batch_admission_records_v1,
    delete_batch::{self as codec, DeleteBatchViewV1},
};
use std::collections::BTreeMap;

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
