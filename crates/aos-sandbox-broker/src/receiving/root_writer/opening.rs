//! Retains fixed Root acquisition and actual resident index before handoff.

use std::collections::BTreeMap;
use std::sync::Arc;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::recovery::RecoveryTailMode;
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1;

use crate::canonical_journal::{
    CanonicalReplayExtentDataV1,
    CanonicalWriterOpeningOriginalsV1,
};
use crate::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1,
};
use crate::receiving::root_permanent::RootPermanentNativeOriginalV1;

use super::recipe::RootWriterRecipeV1;
use super::{RootWriterErrorV1, RootWriterReplayV1};

/// Retains one closed Root opening from its same original enrollment and fence.
///
/// Upper Root's actual fixed/native/semantic permits remain continuously held.
/// This owner accepts no caller path, vector, file or successful replay import.
/// It cannot mint policy success, RootOpen, Q04 or a receiving-purpose loan.
pub struct RootWriterOpeningOriginalV1 {
    original: Arc<RootPermanentNativeOriginalV1>,
    recipe: RootWriterRecipeV1,
    opening: CanonicalWriterOpeningOriginalsV1,
    preparation: Option<Result<(), crate::canonical_journal::NativeJournalDataErrorV1>>,
    extent: Option<Result<CanonicalReplayExtentDataV1, crate::canonical_journal::NativeJournalDataErrorV1>>,
    index: BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    replay: CanonicalReplayIndexOriginalsV1,
    names_before: crate::writer_currentness::WriterCurrentnessOriginalsV1<crate::canonical_journal::NativeJournalDataErrorV1>,
    names_after: crate::writer_currentness::WriterCurrentnessOriginalsV1<crate::canonical_journal::NativeJournalDataErrorV1>,
    owed_names: bool,
    names_finished: bool,
    tail: Option<Result<(), crate::canonical_journal::NativeJournalDataErrorV1>>,
    attempted: bool,
    identity_ready: bool,
    report: Option<crate::canonical_journal::RecoveryReport>,
    taken: bool,
}

impl RootWriterOpeningOriginalV1 {
    pub(in crate::receiving) fn from_initial(
        original: Arc<RootPermanentNativeOriginalV1>, recipe: RootWriterRecipeV1,
    ) -> Result<Self, RootWriterErrorV1> {
        original.claim_writer_once(recipe.index())?;
        Ok(Self {
            original, recipe, opening: CanonicalWriterOpeningOriginalsV1::new(),
            preparation: None, extent: None, index: BTreeMap::new(),
            replay: CanonicalReplayIndexOriginalsV1::new(), tail: None,
            names_before: crate::writer_currentness::WriterCurrentnessOriginalsV1::new(),
            names_after: crate::writer_currentness::WriterCurrentnessOriginalsV1::new(),
            owed_names: false, names_finished: false,
            attempted: false, identity_ready: false, report: None, taken: false,
        })
    }

    /// Bounds the actual closed opening representation before construction.
    ///
    /// # Errors
    /// Refuses checked byte/descriptor geometry overflow; this DATA pays nothing.
    pub(super) fn fixed_demand_v1(recipe: RootWriterRecipeV1) -> Result<ResourceVector, RootWriterErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RootWriterReplayV1<'_, '_>>().checked_mul(3)?))
            .ok_or(RootWriterErrorV1::Closed)?;
        let parent = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| RootWriterErrorV1::Closed)?);
        let names = crate::writer_currentness::WriterCurrentnessOriginalsV1::<
            crate::canonical_journal::NativeJournalDataErrorV1,
        >::fixed_demand_v1(recipe.directory(), recipe.name())?;
        parent.checked_add(CanonicalWriterOpeningOriginalsV1::additional_fixed_receiving_demand_v1(
            recipe.directory(), recipe.name(),
        )?).and_then(|demand| demand.checked_add(names))
            .and_then(|demand| demand.checked_add(names))
            .map_err(|_| RootWriterErrorV1::Closed)
    }

    /// Bounds the exact startup authority opening before construction or IO.
    ///
    /// # Errors
    /// Refuses checked geometry overflow; the returned DATA grants no budget.
    pub fn startup_authority_fixed_demand_v1() -> Result<ResourceVector, RootWriterErrorV1> {
        Self::fixed_demand_v1(RootWriterRecipeV1::StartupAuthority)
    }

    /// Bounds the current authority opening before construction or IO.
    ///
    /// # Errors
    /// Refuses checked geometry overflow; actual Root admission remains upper.
    pub fn current_authority_fixed_demand_v1() -> Result<ResourceVector, RootWriterErrorV1> {
        Self::fixed_demand_v1(RootWriterRecipeV1::CurrentAuthority)
    }

    /// Bounds the compiler-state opening before construction or IO.
    ///
    /// # Errors
    /// Refuses checked geometry overflow; actual Root admission remains upper.
    pub fn current_policy_fixed_demand_v1() -> Result<ResourceVector, RootWriterErrorV1> {
        Self::fixed_demand_v1(RootWriterRecipeV1::CurrentPolicy)
    }

    /// Acquires only its original compiled Root recipe at the paid fixed frontier.
    ///
    /// # Errors
    /// Retains real native preparation/extent failures and closes the same fence.
    pub fn prepare_once(&mut self) -> Result<(), RootWriterErrorV1> {
        let mut guard = self.original.enter_native()?;
        if self.attempted || self.taken {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        self.attempted = true;
        self.owed_names = true;
        self.preparation = Some(self.opening.prepare_once(
            self.recipe.directory(), self.recipe.name(), self.recipe.limits(), 0,
            self.recipe.allows_creation(),
        ));
        if !matches!(self.preparation, Some(Ok(()))) {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        self.extent = Some(self.opening.prepared_extent());
        if !matches!(self.extent, Some(Ok(_))) {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        Ok(())
    }

    /// Rechecks fixed names at the original upper pre-parser frontier.
    ///
    /// The trusted Root caller first admits the held extent and rechecks its
    /// actual service original. Fixed preparation has already paid this sampler
    /// and armed the independent after post, including on later refusal.
    ///
    /// # Errors
    /// Retains actual name partials; refuses absent preparation or repeated entry.
    pub fn observe_names_before_once(&mut self) -> Result<(), RootWriterErrorV1> {
        let mut guard = self.original.enter_native()?;
        if !matches!(self.preparation, Some(Ok(()))) || self.identity_ready || self.taken {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        if self.opening.observe_names_retaining_v1(self.recipe.directory(), self.recipe.name(), 0, &mut self.names_before).is_err() {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        Ok(())
    }

    /// Borrows its actual held-file extent for upper cumulative byte admission.
    #[must_use]
    pub fn prepared_extent(&self) -> Option<&CanonicalReplayExtentDataV1> {
        self.extent.as_ref()?.as_ref().ok()
    }

    /// Samples the same held parser identity at its original pre-parser frontier.
    ///
    /// # Errors
    /// Keeps the real metadata/identity partials in the common opening original;
    /// failed or repeated sampling closes the same invocation before returning.
    pub fn prepare_semantic_identity_once(
        &mut self,
    ) -> Result<aos_sandbox_journal::protected_storage::FileIdentity, RootWriterErrorV1> {
        let mut guard = self.original.enter_native()?;
        if !self.names_before.is_complete() {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        match self.opening.prepare_selected_parser_identity_once() {
            Ok(identity) => {
                self.identity_ready = true;
                Ok(identity)
            },
            Err(cause) => {
                guard.refuse();
                Err(cause.into())
            }
        }
    }

    /// Enters the same canonical parser only after real upper variable admission.
    ///
    /// # Errors
    /// Retains native parser/refusal in the actual original; no new file opens.
    pub fn begin_replay_once(&mut self) -> Result<RootWriterReplayV1<'_, '_>, RootWriterErrorV1> {
        let mut guard = self.original.enter_native()?;
        if !self.identity_ready {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        let cursor = match self.opening.begin_semantic_replay_once() {
            Ok(cursor) => cursor,
            Err(cause) => {
                guard.refuse();
                return Err(cause.into());
            }
        };
        Ok(RootWriterReplayV1::from_initial(
            guard, CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut self.index, &mut self.replay),
        ))
    }

    /// Attempts the already-paid independent name post even after native refusal.
    ///
    /// This uses the SAME held directory/file/lock and the same invocation's
    /// observation interval. It never grants a fresh writer or parser entry.
    ///
    /// # Errors
    /// Retains native/name partials; refuses unarmed, repeated or ended entry.
    pub fn finish_names_once(&mut self) -> Result<(), RootWriterErrorV1> {
        let mut guard = self.original.enter_observation()?;
        if !self.owed_names || self.names_finished || self.taken {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        self.names_finished = true;
        if self.opening.observe_names_retaining_v1(self.recipe.directory(), self.recipe.name(), 0, &mut self.names_after).is_err() {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        Ok(())
    }

    /// Finishes the original tail policy after the complete upper semantic loop.
    ///
    /// Authority currentness rejects incomplete tails; the two existing create
    /// recipes retain their original repair policy. No caller selects that mode.
    ///
    /// # Errors
    /// Keeps exact tail/truncate/sync/seek errors and closes this invocation.
    pub fn finish_tail_once(&mut self) -> Result<(), RootWriterErrorV1> {
        let mut guard = self.original.enter_native()?;
        if !self.replay.is_complete() || self.tail.is_some() {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        let mode = if self.recipe.allows_creation() {
            RecoveryTailMode::RepairIncomplete
        } else {
            RecoveryTailMode::RejectIncomplete
        };
        self.tail = Some(self.opening.finish_replayed_tail_once(mode));
        if !matches!(self.tail, Some(Ok(()))) {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        Ok(())
    }

    /// Moves the actual opened writer after upper semantic and independent posts.
    ///
    /// The trusted coordinator calls this at its existing successful handoff;
    /// semantic success and receiving debt remain owned above this native port.
    ///
    /// # Errors
    /// Refuses incomplete replay/tail or repeat take without replacing custody.
    pub fn take_coordinator_after_semantic_replay_once<P>(
        &mut self,
        compaction: P,
    ) -> Result<super::RootCoordinatorWriterV1<P>, RootWriterErrorV1> {
        let original = Arc::clone(&self.original);
        let mut guard = original.enter_native()?;
        if self.taken || !self.replay.is_complete() || !matches!(self.tail, Some(Ok(())))
            || !self.names_before.is_complete() || !self.names_after.is_complete()
        {
            guard.refuse();
            return Err(RootWriterErrorV1::Closed);
        }
        let opened = match self.opening.take_opened_parts_once() {
            Some(opened) => opened,
            None => {
                guard.refuse();
                return Err(RootWriterErrorV1::Closed);
            }
        };
        self.report = Some(opened.recovery_report());
        let durable_end = self.prepared_extent().map(|extent| extent.native_bytes())
            .and_then(|bytes| bytes.checked_sub(opened.recovery_report().truncated_bytes))
            .ok_or(RootWriterErrorV1::Closed)?;
        let writer = super::RootCoordinatorWriterV1::from_fixed_opening(
            opened, std::mem::take(&mut self.index), compaction, Arc::clone(&self.original), durable_end,
        );
        self.taken = true;
        // The actual upper semantic/service/name interval has completed before
        // this trusted handoff. Keep completion DATA, retire fresh descriptions
        // only at this final borrower, and grant no refund or new admission.
        self.names_before.settle_positive_once_v1();
        self.names_after.settle_positive_once_v1();
        Ok(writer)
    }

    /// Copies the original completed native report without a role success grant.
    #[must_use]
    pub fn recovery_report(&self) -> Option<crate::canonical_journal::RecoveryReport> {
        self.report
    }

    /// Prices the actual resident index backing from this held-file extent.
    ///
    /// The caller adds the same canonical native and complete semantic suppliers
    /// under its actual Root R admission before entering replay. Namespace
    /// entries count resident index decisions, never Rust control fields.
    ///
    /// # Errors
    /// Refuses missing extent or checked node/key/backing geometry overflow.
    pub fn additional_index_demand_v1(&self) -> Result<ResourceVector, RootWriterErrorV1> {
        let extent = self.prepared_extent().ok_or(RootWriterErrorV1::Closed)?;
        CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(*extent)
            .map_err(RootWriterErrorV1::from)
    }

    /// Borrows actual acquisition or parser failures before the owed names post.
    ///
    /// This excludes the shared invocation refusal marker so an upper semantic
    /// cause can remain ahead of a later independent names failure.
    #[must_use]
    pub fn prefix_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.opening.failure().or_else(|| self.names_before.failure())
            .or_else(|| self.replay.failure())
    }

    /// Borrows the actual independent names-post failure without a fence marker.
    #[must_use]
    pub fn names_post_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.names_after.failure()
    }

    /// Borrows reached native failures without projecting invocation refusal.
    #[must_use]
    pub fn concrete_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.prefix_failure_v1().or_else(|| self.names_post_failure_v1())
    }

    /// Borrows the earliest actual acquisition/parser/index failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.concrete_failure_v1()
            .or_else(|| self.original.invocation().failure().map(|cause| cause as _))
    }
}

impl Drop for RootWriterOpeningOriginalV1 {
    fn drop(&mut self) {
        if !self.taken {
            // A genuine claimed destination must remain in its upper negative
            // owner; abandonment cannot free actual reached protected custody.
            self.original.invocation().latch_refusal();
            std::process::abort();
        }
    }
}
