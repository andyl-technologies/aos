//! Bounded Source genesis rows and the exact pending-floor mutation fence.
//!
//! Receipt bytes are immutable data. Only the genuine Source owner may use
//! the private append/anchor transitions after rechecking live Controller and
//! Root borrows. Ordinary appends cannot write these keys, and a pending row
//! excludes every unrelated mutation and compaction, including after reopen.
//!
//! ```text
//! pending = AOSSGP01 | version:u16be | reserved[6]=0 | instance[32] |
//! project[16] | Root-intent[32] | receipt[32] | Root-nonce[16] |
//! fixed directory/journal/lock(device,inode)[48] | checksum[32]
//! ACK = AOSSGA01 | version:u16be | reserved[6]=0 | instance[32] |
//! project[16] | receipt[32] | Root-floor[32] | Controller-floor[32] |
//! checksum[32]
//! ```

use crate::journal::{CacheMutationGateV1, PreflightTransactionViewV1};
use crate::journal::semantic_append::{AppendScope, PreflightScope};

mod retained;
mod classification;
pub(crate) use retained::SourceGenesisRowsOriginalsV1;
pub(super) use retained::SourceGenesisMutationOriginalsV1;
#[cfg(test)]
pub(in crate::journal) use retained::mutation_tests::receipt as genesis_receipt_data_for_test;

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, ProjectId};
use sha2::{Digest as _, Sha256};

use super::{
    Journal, JournalError, JournalRecord, JournalTransaction, ProtectedJournalNamesV1,
    RecordNamespace,
};
use aos_sandbox_ledger_replay::replay::hierarchy_records::{
    HierarchyProtectedJournalKeyV1, HierarchyProtectedRecordKindV1,
};
use aos_sandbox_ledger_replay::genesis::SourceTreeGenesisReceiptV1;

pub(crate) const PENDING_KEY: &[u8] = b"\0aos-source-tree-genesis-pending-v1\0";
const KEY_FAMILY_PREFIX: &[u8] = b"\0aos-source-tree-genesis-";
const RECEIPT_PREFIX: &[u8] = b"\0aos-source-tree-genesis-receipt-v1\0";
const ACK_PREFIX: &[u8] = b"\0aos-source-tree-genesis-ack-v1\0";

pub(crate) use aos_sandbox_ledger_replay::replay::source_tree_genesis::SourceGenesisTransitionV1;

use aos_sandbox_ledger_replay::replay::source_tree_genesis::{SourceGenesisPendingV1, SourceGenesisAckV1, SourceGenesisRowsV1};

fn fixed_row_decode_peak_bytes_v1() -> Option<usize> {
    aos_sandbox_ledger_replay::replay::source_tree_genesis::fixed_row_decode_peak_bytes_v1::<JournalError>()
}

pub(crate) fn current_rows(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<SourceGenesisRowsV1, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_genesis::current_rows::<JournalError>(state)
}

pub(super) fn decode_receipt_with_originals(
    bytes: &[u8], destination: Option<&mut Option<aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDecodeOriginalsV1<crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>>,
) -> Result<SourceTreeGenesisReceiptV1, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_genesis::decode_receipt_with_originals::<JournalError, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>(bytes, destination)
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: SourceGenesisTransitionV1,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_genesis::require_no_mutation(state, transaction, transition)
        .map_err(JournalError::from)
}

pub(super) fn require_no_mutation_with_originals(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: SourceGenesisTransitionV1,
    originals: Option<&mut SourceGenesisMutationOriginalsV1>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_genesis::require_no_mutation_with_originals(state, transaction, transition, originals)
}

fn require_no_mutation_engine(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: SourceGenesisTransitionV1,
    originals: Option<&mut SourceGenesisMutationOriginalsV1>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_genesis::require_no_mutation_engine(state, transaction, transition, originals)
}

fn protected_record(record: &JournalRecord, rows: &SourceGenesisRowsV1) -> bool {
    aos_sandbox_ledger_replay::replay::source_tree_genesis::classification::protected_record(record, rows)
}

fn protected_record_engine(
    record: &JournalRecord,
    rows: &SourceGenesisRowsV1,
    originals: Option<&mut Option<classification::HierarchyKeyCaptureV1>>,
) -> bool {
    aos_sandbox_ledger_replay::replay::source_tree_genesis::classification::protected_record_engine(record, rows, originals)
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_genesis::require_no_compaction(state)
        .map_err(JournalError::from)
}

pub(super) fn recognize_replayed_transition(
    transaction: &JournalTransaction,
) -> Result<SourceGenesisTransitionV1, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_genesis::recognize_replayed_transition(transaction)
        .map_err(JournalError::from)
}

impl Journal {
    pub(crate) fn source_tree_genesis_rows_v1(&self) -> Result<SourceGenesisRowsV1, JournalError> {
        self.ensure_healthy()?;
        current_rows(self.native.state())
    }

    pub(crate) fn commit_source_tree_genesis_v1(
        &mut self,
        transaction: &JournalTransaction,
        transition: SourceGenesisTransitionV1,
    ) -> Result<(), JournalError> {
        self.commit_in_scope(
            transaction,
            AppendScope {
                source_genesis_transition: transition,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        Ok(())
    }

    pub(crate) fn preflight_source_tree_genesis_v1(
        &self,
        transactions: &[JournalTransaction],
        transitions: &[SourceGenesisTransitionV1],
    ) -> Result<(), JournalError> {
        self.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(transactions),
            PreflightScope {
                genesis_transitions: Some(transitions),
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )
    }
}

pub(crate) use aos_sandbox_ledger_replay::replay::source_tree_genesis::{receipt_key, ack_key};
