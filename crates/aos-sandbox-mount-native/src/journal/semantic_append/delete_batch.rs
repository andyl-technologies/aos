//! Applies the canonical saved Delete prior-state comparisons without a grant.

use std::collections::BTreeMap;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_core::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::{
    controller_history_relation::validate_delete_batch_admission_records_v1,
    delete_batch::{self as codec, DeleteBatchViewV1},
    transaction::{validate_transaction, JournalLimits, JournalRecord, JournalTransaction},
};

enum PreflightTransactionViewV1<'transactions> {
    Ordinary(&'transactions [JournalTransaction]),
}

impl PreflightTransactionViewV1<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Ordinary(transactions) => transactions.len(),
        }
    }

    fn transaction(&self, index: usize) -> &JournalTransaction {
        match self {
            Self::Ordinary(transactions) => &transactions[index],
        }
    }
}

aos_sandbox_ledger_replay::define_delete_replay_data_recipe_v1!();
