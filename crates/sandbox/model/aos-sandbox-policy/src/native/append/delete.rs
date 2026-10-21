//! Instantiates the sole saved Delete DATA guards on the same complete rows.

use std::collections::BTreeMap;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalLimits, JournalRecord, JournalTransaction, validate_transaction,
};
use aos_sandbox_protocol::domain_ledger::controller_history_relation::validate_delete_batch_admission_records_v1;
use aos_sandbox_protocol::domain_ledger::delete_batch::{self as codec, DeleteBatchViewV1};

enum PreflightTransactionViewV1<'a> { Ordinary(&'a [JournalTransaction]) }

impl PreflightTransactionViewV1<'_> {
    fn len(&self) -> usize { match self { Self::Ordinary(transactions) => transactions.len() } }
    fn transaction(&self, index: usize) -> &JournalTransaction {
        match self { Self::Ordinary(transactions) => &transactions[index] }
    }
}

aos_sandbox_ledger_replay::define_delete_replay_data_recipe_v1!();
