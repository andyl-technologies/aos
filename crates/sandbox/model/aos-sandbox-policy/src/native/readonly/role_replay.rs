//! Retains either the existing comparison replay or a genuine current-role replay.
//!
//! The variant is selected only by a private fixed native constructor. Current
//! replay always borrows its concrete purpose receiving context; Common keeps
//! the original comparison-only cursor entries. Neither branch opens a file,
//! adopts a completed model or supplies financial or semantic role authority.

mod current;

use std::error::Error;
use std::mem::size_of;
use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_ledger_replay::cold::{
    ColdReplayClosedV1, ColdReplayOriginalV1, ColdReplayRemainderDataV1,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;
use super::error::RootReadonlyErrorV1;
use current::CurrentRoleReplayOriginalV1;

pub(crate) struct RootReadonlySemanticOriginalV1 {
    branch: SemanticBranchV1,
}

enum SemanticBranchV1 {
    Common(ColdReplayOriginalV1),
    Current(CurrentRoleReplayOriginalV1),
}

impl RootReadonlySemanticOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { branch: SemanticBranchV1::Common(ColdReplayOriginalV1::new()) }
    }

    pub(super) fn current_v1() -> Self {
        Self { branch: SemanticBranchV1::Current(CurrentRoleReplayOriginalV1::new()) }
    }

    // Enum growth is paid in addition to whichever actual branch's original
    // driver/borrow/remainder controls run. No discarded Common original is
    // constructed when the real native purpose selects Current.
    fn dispatch_control_bytes_v1() -> Option<usize> {
        size_of::<Option<usize>>().checked_mul(2)?
            .checked_add(size_of::<(usize, usize, Option<usize>)>().checked_mul(2)?)?
            .checked_add(size_of::<Result<(), ColdReplayClosedV1>>().checked_mul(2)?)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(2)?)?
            // These actual new wrapper constructor/return and error-forwarding
            // interfaces are additional to the branch's resident driver planes.
            .checked_add(size_of::<(
                Self,
                CurrentRoleReplayOriginalV1,
                Option<ColdReplayRemainderDataV1>,
                Result<ResourceVector, aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1>,
                Result<ResourceVector, RootReadonlyErrorV1>,
            )>().checked_mul(2)?)
    }

    pub(crate) fn receiving_construction_bytes_v1() -> Option<usize> {
        let common = ColdReplayOriginalV1::receiving_construction_with_release_observer_bytes_v1()?
            .checked_add(size_of::<Self>()
                .checked_sub(size_of::<ColdReplayOriginalV1>())?.checked_mul(2)?)?;
        let current = CurrentRoleReplayOriginalV1::receiving_construction_bytes_v1()?
            .checked_add(size_of::<Self>()
                .checked_sub(size_of::<CurrentRoleReplayOriginalV1>())?.checked_mul(2)?)?;
        // Normalize BOTH actual branch owners before selecting their peak; the
        // larger control quote need not belong to the larger inline variant.
        common.max(current).checked_add(Self::dispatch_control_bytes_v1()?)
    }

    pub(crate) fn fixed_demand_with_release_observer_v1()
        -> Result<ResourceVector, RootReadonlyErrorV1>
    {
        let common = ColdReplayOriginalV1::fixed_demand_with_release_observer_v1()?;
        let common_header = ColdReplayOriginalV1::receiving_construction_with_release_observer_bytes_v1()
            .ok_or(RootReadonlyErrorV1::JournalTooLarge)?;
        // The unchanged Common fixed supplier predates these two new passive
        // header-return slots; keep them in this caller's additional envelope.
        let old_common_header = common_header
            .checked_sub(size_of::<Option<usize>>().checked_mul(2)
                .ok_or(RootReadonlyErrorV1::JournalTooLarge)?)
            .ok_or(RootReadonlyErrorV1::JournalTooLarge)?;
        let envelope = Self::receiving_construction_bytes_v1()
            .and_then(|bytes| bytes.checked_sub(old_common_header))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(RootReadonlyErrorV1::JournalTooLarge)?;
        common.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, envelope))
            .map_err(RootReadonlyErrorV1::from)
    }

    pub(super) fn observe_current_once(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        receiving: &mut crate::native::root_current::readonly_receiving::RootCurrentReadonlyReceivingContextV1<'_, '_, '_>,
    ) -> Result<(), ColdReplayClosedV1> {
        match &mut self.branch {
            SemanticBranchV1::Current(original) => original.observe_once(cursor, identity, limits, receiving),
            SemanticBranchV1::Common(_) => Err(ColdReplayClosedV1),
        }
    }

    pub(crate) fn observe_indexed_with_release_observer_once(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        suffix: Option<&mut aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::HistoryPairNativeSuffixV1<'_, '_>>,
    ) -> Result<(), ColdReplayClosedV1> {
        match &mut self.branch {
            SemanticBranchV1::Common(original) => original.observe_indexed_with_release_observer_once(
                cursor, identity, limits, suffix,
            ),
            SemanticBranchV1::Current(_) => Err(ColdReplayClosedV1),
        }
    }

    pub(crate) fn observe_indexed_with_delete_accepted_once_v3(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        comparison: &mut aos_sandbox_ledger_replay::delete_pending::DeleteSelectedCommitReplayDataV3,
    ) -> Result<(), ColdReplayClosedV1> {
        match &mut self.branch {
            SemanticBranchV1::Common(original) => original.observe_indexed_with_delete_accepted_once_v3(
                cursor, identity, limits, comparison,
            ),
            SemanticBranchV1::Current(_) => Err(ColdReplayClosedV1),
        }
    }

    pub(crate) fn observe_indexed_with_delete_current_once_v3(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        comparison: &mut aos_sandbox_ledger_replay::delete_pending::SourceDeletePendingReplayDataV1,
    ) -> Result<(), ColdReplayClosedV1> {
        match &mut self.branch {
            SemanticBranchV1::Common(original) => original.observe_indexed_with_delete_current_once_v3(
                cursor, identity, limits, comparison,
            ),
            SemanticBranchV1::Current(_) => Err(ColdReplayClosedV1),
        }
    }

    pub(crate) fn observe_indexed_with_create_stopped_once_v2(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        observation: &mut aos_sandbox_protocol::domain_ledger::effect_history::CreateStoppedNativeObservationDataV2<'_>,
        failure: &mut Option<aos_sandbox_protocol::domain_ledger::effect_history::CreateStoppedNativeObservationErrorV2>,
    ) -> Result<(), ColdReplayClosedV1> {
        match &mut self.branch {
            SemanticBranchV1::Common(original) => original.observe_indexed_with_create_stopped_once_v2(
                cursor, identity, limits, observation, failure,
            ),
            SemanticBranchV1::Current(_) => Err(ColdReplayClosedV1),
        }
    }

    pub(crate) fn observe_indexed_with_delete_graph_predecessor_once_v2(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        predecessor: &mut aos_sandbox_ledger_replay::delete_pending::DeleteSourcePredecessorReplayDataV2,
        controller: &std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<(), ColdReplayClosedV1> {
        match &mut self.branch {
            SemanticBranchV1::Common(original) => original.observe_indexed_with_delete_graph_predecessor_once_v2(
                cursor, identity, limits, predecessor, controller,
            ),
            SemanticBranchV1::Current(_) => Err(ColdReplayClosedV1),
        }
    }

    pub(crate) fn observe_indexed_with_delete_predecessor_once_v2(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        predecessor: &mut aos_sandbox_ledger_replay::delete_pending::DeleteSourcePredecessorReplayDataV2,
    ) -> Result<(), ColdReplayClosedV1> {
        match &mut self.branch {
            SemanticBranchV1::Common(original) => original.observe_indexed_with_delete_predecessor_once_v2(
                cursor, identity, limits, predecessor,
            ),
            SemanticBranchV1::Current(_) => Err(ColdReplayClosedV1),
        }
    }

    pub(crate) fn delete_preparation_failure_is_selected_v3(&self) -> bool {
        match &self.branch {
            SemanticBranchV1::Common(original) => original.delete_preparation_failure_is_selected_v3(),
            SemanticBranchV1::Current(_) => false,
        }
    }

    pub(crate) fn create_stopped_failure_is_selected_v2(&self) -> bool {
        match &self.branch {
            SemanticBranchV1::Common(original) => original.create_stopped_failure_is_selected_v2(),
            SemanticBranchV1::Current(_) => false,
        }
    }

    pub(crate) fn predecessor_failure_is_selected_v2(&self) -> bool {
        match &self.branch {
            SemanticBranchV1::Common(original) => original.predecessor_failure_is_selected_v2(),
            SemanticBranchV1::Current(_) => false,
        }
    }

    pub(crate) fn suffix_failure_is_selected_v1(&self) -> bool {
        match &self.branch {
            SemanticBranchV1::Common(original) => original.suffix_failure_is_selected_v1(),
            SemanticBranchV1::Current(_) => false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match &self.branch {
            SemanticBranchV1::Common(original) => original.failure(),
            SemanticBranchV1::Current(original) => original.failure(),
        }
    }

    pub(crate) fn source_failure_cause_v1(&self) -> Option<&(dyn Error + 'static)> {
        match &self.branch {
            SemanticBranchV1::Common(original) => original.source_failure_cause_v1(),
            SemanticBranchV1::Current(original) => original.source_failure_cause_v1(),
        }
    }

    pub(crate) fn native_failure_is_selected_v1(&self) -> bool {
        match &self.branch {
            SemanticBranchV1::Common(original) => original.native_failure_is_selected_v1(),
            SemanticBranchV1::Current(original) => original.native_failure_is_selected_v1(),
        }
    }

    pub(crate) fn take_remainder_once(&mut self) -> Option<ColdReplayRemainderDataV1> {
        match &mut self.branch {
            SemanticBranchV1::Common(original) => original.take_remainder_once(),
            SemanticBranchV1::Current(original) => original.take_remainder_once(),
        }
    }
}
