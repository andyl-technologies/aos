//! Owns the five Cache writers through the sole canonical native/index bundle.
//!
//! Cache's captured constructor keeps the real financial and native bookends.
//! This private owner retains that original bundle, semantic remainder and
//! captured append prefixes; no public map, File, Arc or success-DATA adopter
//! constructs it. Instance-bound Cache capabilities remain in the private
//! transaction adapter, and the actual Cache gate retains the final crossing.

pub(crate) mod append;
mod cache_held_observation;
mod create_storage_position;
mod authority;
mod delete_batch;
mod gate;
mod git_prefix;
mod native_audit;
mod ordinary_guards;
mod ordinary_opening;
pub(crate) use ordinary_opening::CacheOrdinaryOpenV1;
#[cfg(test)]
pub(crate) use ordinary_opening::CacheOrdinaryFixtureV1;
mod ordinary_readonly;
pub(crate) mod policy;
mod preflight;
mod q04;
mod q04_loans;
mod readonly;
mod captured_readonly;
pub(crate) mod readonly_receiving;
mod construction;
mod construction_stage;
mod currentness;
mod opening;
mod semantics;
mod shape;

pub(crate) use shape::JournalShape;
pub(crate) use cache_held_observation::CacheHeldWriterShapeV1;
pub(crate) use create_storage_position::CreateStorageWriterPositionOriginalV1;
pub(crate) use aos_sandbox_journal::protected_storage::FileIdentity;
pub(crate) use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
pub(crate) use aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1 as ProtectedJournalPreopenReplayExtentV1;
pub(crate) use crate::error::CacheJournalErrorV1 as JournalError;
pub(crate) use aos_sandbox_broker::canonical_journal::{CommitResult, RecoveryReport};
pub(crate) use aos_sandbox_model::RecordNamespace;
pub(crate) use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalLimits, JournalRecord, JournalTransaction,
};
pub(crate) use authority::{ProtectedJournalAuthority, ProtectedJournalPreflight, ProtectedJournalSnapshot};
pub(crate) use gate::CacheGitCoverageObservationV1;
pub(crate) use gate::{BorrowedCacheMutationGateV1, CacheMutationGateV1, HeldCacheMutationGateV1, HeldCachePolicyObservationV1};
pub use q04::CacheQ04TransactionRecipesV1;
pub(crate) use q04_loans::{Q04CachePrepareNativeLoanV1, Q04CacheTerminalNativeLoanV1};
pub(crate) use readonly::{ReadOnlyJournalNameWitness, ReadOnlyProtectedJournal};
pub(crate) use captured_readonly::ReadOnlyJournalOpenOriginalsV1;
pub(crate) use aos_sandbox_journal::protected_storage::ProtectedWriterNameWitness;
pub(crate) use construction::{ConstructionLoanV1, ConstructionOwnerV1};
pub(crate) use construction_stage::{CacheNativeStageV1, CacheConstructionStageErrorV1};
pub(crate) use currentness::CacheWriterCurrentnessOriginalV1;

use aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1;
use aos_sandbox_broker::canonical_journal::{
    CanonicalJournalInstanceDataV1, CanonicalOrdinaryHeldJournalV1,
};
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;

use semantics::CacheSemanticRemainderV1;
use aos_sandbox_protocol::domain_ledger::transaction::validate_transaction;

// None of Cache's five compiled names is a Runtime deployment main/sidecar
// journal. Preserve the old actual compaction selection without exposing a
// replacement operation or claiming permission to compact a shared journal.
#[derive(Clone, Copy)]
pub(super) enum CacheCompactionSelectionV1 {
    Other,
}

pub(super) struct CacheJournalInstanceV1;

pub(super) type HeldCacheJournalV1 =
    CanonicalOrdinaryHeldJournalV1<CacheCompactionSelectionV1, CacheJournalInstanceV1>;

pub(crate) struct Journal {
    native: HeldCacheJournalV1,
    cache_policy_gate: Option<(std::path::PathBuf, u32)>,
    // The old outer alias retains this SAME actual allocation through its
    // original field/drop position. It is not a second identity allocation.
    instance: CanonicalJournalInstanceDataV1<CacheJournalInstanceV1>,
    remainder: CacheSemanticRemainderV1,
}

impl Journal {
    pub(super) fn read_view(&self) -> CanonicalWriterReadViewV1<'_, CacheCompactionSelectionV1> {
        self.native.read_view_v1()
    }

    pub(crate) fn historical_read_view_v1(&self) -> HistoricalLedgerReadViewV1<'_> {
        self.read_view().historical_view()
    }

    pub(crate) fn ensure_healthy(&self) -> Result<(), JournalError> {
        if self.read_view().is_poisoned() {
            Err(JournalError::poisoned())
        } else {
            Ok(())
        }
    }

    pub(crate) fn ensure_protected_authority(&self) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if self.read_view().is_protected() {
            Ok(())
        } else {
            Err(JournalError::boundary())
        }
    }

    pub(crate) fn get(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.historical_read_view_v1().get(namespace, key)
    }

    pub(crate) fn records(
        &self,
        namespace: RecordNamespace,
    ) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.historical_read_view_v1().records(namespace)
    }

    pub(crate) fn all_records(&self) -> impl Iterator<Item = (RecordNamespace, &[u8], &[u8])> {
        self.historical_read_view_v1().all_records()
    }

    pub(crate) const fn snapshot_sequence(&self) -> u64 {
        self.native.next_sequence_data_v1()
    }

    pub(crate) const fn limits(&self) -> JournalLimits {
        self.native.limits_data_v1()
    }
}

fn authority_preflight_digest(transactions: &[JournalTransaction]) -> [u8; 32] {
    aos_sandbox_protocol::domain_ledger::transaction::transaction_preflight_comparison_digest_v1(transactions)
}

// The canonical extent is passive DATA from the actual observed prefix. It
// creates no parser entry, read-only native owner or funding permission.
pub(crate) fn protected_journal_preopen_replay_extent_for_prefix_v1(
    limits: JournalLimits,
    prefix: u64,
) -> Result<ProtectedJournalPreopenReplayExtentV1, JournalError> {
    ProtectedJournalPreopenReplayExtentV1::new(limits, prefix)
        .map_err(JournalError::from_ordinary_native_v1)
}

pub(crate) mod history_pair;
