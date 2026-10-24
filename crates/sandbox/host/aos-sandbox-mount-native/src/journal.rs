//! Keeps Mount's actual native/index/location and finite semantic authorities.
//!
//! Only completed canonical opening transfers construct this owner. Its private
//! comparison allocation is shared with opaque snapshots; supplied state maps,
//! descriptors, locations and successful replay DATA cannot create a writer.

mod append;
mod authority;
mod currentness;
mod error;
mod git_coverage;
pub(crate) mod mount_manager_startup;
mod mount_source_consumption;
mod opening;
mod receiving;
mod root_local_recovery;
mod root_original_inventory;
mod root_original_native;
mod semantic_append;

pub use append::MountAppendFailureOriginalV1;
use authority::ProtectedAuthorityScope;
pub use authority::{
    MountSourceAcquisitionJournalAuthorityV2, ProtectedJournalAuthority, ProtectedJournalPreflight,
    ProtectedJournalSnapshot,
};
pub use currentness::MountJournalCurrentnessOriginalsV1;
pub use error::MountJournalErrorV1;
use error::MountJournalErrorV1 as JournalError;
pub use git_coverage::{GitCoverageNativeHistoryErrorV1, GitCoverageNativePrefixLoanV1};
pub use opening::{
    MountCapturedJournalOpenModeV1, MountInventoryJournalCurrentnessOriginalV2,
    MountStateCapturedJournalOpenV4,
};
pub use receiving::{MountJournalAppendReceivingDemandErrorV1, MountJournalReplayExtentV1};

pub use mount_manager_startup::MountManagerStartupPolicyReceiptV1;
pub(crate) use mount_manager_startup::{
    MountManagerStartupCapturePreflightV1, MountManagerStartupCaptureReceiptV1,
    MountManagerStartupCaptureRecoveryV1,
};
pub use mount_source_consumption::{
    MountSourceConsumptionCommitReceipt, MountSourceConsumptionCompanionProjectionV2,
    MountSourceConsumptionJournalAuthorityV1, MountSourceConsumptionPreflight,
};
pub use root_local_recovery::{
    Kind2ProtectedReadbackV4, Kind5ProtectedReadbackV4,
    MountBarrierIdleReplacementJournalAuthorityV4, MountDeadReplacementJournalAuthorityV4,
    PreparedBarrierIdleReplacementV4, PreparedDeadReplacementV4,
};
pub use root_original_inventory::{
    MountOriginalInventoryJournalAuthorityV6, OriginalInventoryProtectedReadbackV6,
    PreparedOriginalInventoryAppendV6,
};
pub use root_original_native::{
    MountOriginalNativeJournalAuthorityV5, OriginalRootProtectedReadbackV5,
    PreparedOriginalRootAppendV5,
};

use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use crate::Journal;

pub(crate) use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as MechanicalError;
use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryHeldJournalV1;
use aos_sandbox_broker::canonical_journal::captured::CapturedAppendDataOwnerV1;
use aos_sandbox_broker::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendV1, CanonicalCoordinatorReadV1,
};
pub use aos_sandbox_broker::canonical_journal::{CommitResult, RecoveryReport};
pub use aos_sandbox_model::RecordNamespace;
pub use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyOutcome;
use aos_sandbox_protocol::domain_ledger::transaction::validate_transaction;
pub use aos_sandbox_protocol::domain_ledger::transaction::{
    IdempotencyKey, JournalLimits, JournalRecord, JournalTransaction,
    encoded_transaction_append_bytes,
};
use semantic_append::validate_reserved_capacity;

#[derive(Clone, Copy)]
enum RootOwnerEdge {
    Local(root_local_recovery::Edge),
    OriginalNative([u8; 32]),
    OriginalInventory {
        root: [u8; 32], query: [u8; 32],
        kind: aos_sandbox_protocol::mount_source_acquisition_state::native_held_completion::OriginalInventoryTransitionKindV6,
    },
}

enum PreflightTransactionViewV1<'transactions> {
    Ordinary(&'transactions [JournalTransaction]),
}

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

// The only fixed Mount file is not either runtime-deployment compaction file.
// This preserves the old OriginalCompactionSelection::Other branch.
#[derive(Clone, Copy)]
enum MountSelection {
    Other,
}

struct JournalAuthorityInstance;

/// Owns the same fixed Mount state writer, index and protected location.
pub struct MountJournalV1 {
    native: CanonicalOrdinaryHeldJournalV1<MountSelection, JournalAuthorityInstance>,
    captured: Option<CapturedAppendDataOwnerV1<JournalError>>,
    interval: Option<Arc<append::MountAppendIntervalOriginalV1>>,
    semantic: aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1,
    authority_instance: Arc<JournalAuthorityInstance>,
    mount_git_coverage_denied: bool,
}

impl MountJournalV1 {
    fn poison_native_v1(&mut self) {
        self.native.poison();
    }

    /// Borrows the current materialized bytes as diagnostic DATA.
    #[must_use]
    pub fn get(&self, namespace: RecordNamespace, key: &[u8]) -> Option<&[u8]> {
        self.native
            .read_view_v1()
            .historical_view()
            .get(namespace, key)
    }

    /// Iterates one materialized namespace without granting currentness.
    pub fn records(&self, namespace: RecordNamespace) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.native
            .read_view_v1()
            .state()
            .iter()
            .filter_map(move |((actual, key), value)| {
                (*actual == namespace).then_some((key.as_slice(), value.as_slice()))
            })
    }

    /// Iterates this writer's complete materialized records as diagnostic DATA.
    pub fn all_records(&self) -> impl Iterator<Item = (RecordNamespace, &[u8], &[u8])> {
        self.native
            .read_view_v1()
            .state()
            .iter()
            .map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice()))
    }

    /// Resolves the same resident request identity without granting currentness.
    #[must_use]
    pub fn check_idempotency(
        &self,
        key: &IdempotencyKey,
        request_digest: [u8; 32],
    ) -> IdempotencyOutcome {
        self.native
            .read_view_v1()
            .historical_view()
            .check_idempotency(key, request_digest)
    }

    /// Reports whether this same native materialization contains no rows.
    #[must_use]
    pub fn is_materialized_empty(&self) -> bool {
        self.native.read_view_v1().state().is_empty()
    }

    /// Returns the next sequence of the actual held writer as comparison DATA.
    #[must_use]
    pub fn snapshot_sequence(&self) -> u64 {
        self.native.read_view_v1().next_sequence()
    }

    /// Requires this same native writer and retained append custody to be healthy.
    ///
    /// # Errors
    /// Refuses native poison or any entered, failed or undisposed append prefix.
    pub fn ensure_healthy(&self) -> Result<(), JournalError> {
        if self.native.read_view_v1().is_poisoned()
            || self.interval.is_some()
            || self
                .captured
                .as_ref()
                .is_some_and(CapturedAppendDataOwnerV1::is_closed)
        {
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::Poisoned,
            ));
        }
        Ok(())
    }

    fn ensure_protected_authority(&self) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if !self.native.read_view_v1().is_protected() {
            return Err(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
        }
        Ok(())
    }

    /// Borrows the actual captured native refusal without disposing its owner.
    #[must_use]
    pub fn retained_native_append_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.interval
            .as_ref()
            .and_then(|original| original.failure())
            .or_else(|| {
                self.captured
                    .as_ref()
                    .and_then(CapturedAppendDataOwnerV1::failure)
            })
    }

    /// Reports whether this same writer retains captured append custody.
    #[must_use]
    pub fn has_captured_append_custody_v1(&self) -> bool {
        self.captured.is_some()
    }
}

fn authority_preflight_digest(transactions: &[JournalTransaction]) -> [u8; 32] {
    aos_sandbox_protocol::domain_ledger::transaction::transaction_preflight_comparison_digest_v1(
        transactions,
    )
}
