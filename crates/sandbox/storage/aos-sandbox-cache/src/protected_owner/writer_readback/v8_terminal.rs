//! Keeps the exact ordinary Cache V8 writer cut across finite upper seams.
//!
//! No caller-selected mode, result flag, journal, descriptor or paid receipt is
//! accepted. Factories select only the actual held/released/settlement recipes.
//! Release consumes genuine fixed-peer R8X evidence; settlement consumes the
//! existing genuine Root settlement grant. Controller/Source semantics remain
//! upper and no paid selected programme is inferred from this local owner.

use super::*;
use crate::clock::{CacheClockWriterReadbackGuard, ProtectedCacheClockV1};
use crate::physical::CacheOwnerHeldSnapshotV1;
use crate::protected_journal::{
    CacheV8InspectionGuardV1, ProtectedCacheResidencyReplayAuthorityV1,
};
use std::cell::Cell;

/// Retains the actual owner and shared clock before its original native entry.
///
/// This ordinary/library carrier is not a financial borrower or effect grant.
/// Its short context can be entered once, while this same carrier remains held.
#[doc(hidden)]
pub struct CacheV8TerminalOriginalV1<'owner> {
    owner: &'owner mut CacheResidencyProtectedOwnerV1,
    physical: &'owner DormantCacheOwnerV1,
    clock: Arc<ProtectedCacheClockV1>,
    mode: CacheTerminalCutV1,
    entered: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum V8TerminalStageV1 {
    BeforeInspect,
    InspectEntered,
    AfterInspect,
    AfterFinish,
    FinalPost,
    CommitEntered,
    Committed,
    Complete,
}

/// Retains clock, physical snapshot and the same protected hold writer.
///
/// No public method yields a writer or adopts a successful upper result.
/// The native inspection separately retains its same authority claim. Named
/// stages preserve the original postflight positions, including negative posts.
/// Native refusals and incomplete/abandoned inspections stay sticky even when
/// an external library caller ignores a returned error.
#[doc(hidden)]
pub struct CacheV8TerminalContextV1<'capture> {
    physical: CacheOwnerHeldSnapshotV1<'capture>,
    hold_journal: Journal,
    hold_witness: ProtectedWriterNameWitness,
    state_witness: ProtectedWriterNameWitness,
    authority_witness: ProtectedWriterNameWitness,
    hold: CachePolicyHoldV1,
    historical_held: Option<CachePolicyHoldV1>,
    pending: bool,
    mode: CacheTerminalCutV1,
    quota: Option<ObjectDigest>,
    stage: V8TerminalStageV1,
    inspection_complete: Cell<bool>,
    native_refused: Cell<bool>,
    state: &'capture mut Journal,
    authority: &'capture ProtectedCacheResidencyReplayAuthorityV1,
    limits: crate::CacheOwnerLimitsV1,
    owner_uid: u32,
    // The old local held this guard beyond the hold writer and physical cut.
    clock_guard: CacheClockWriterReadbackGuard<'capture>,
}

impl CacheResidencyProtectedOwnerV1 {
    pub(super) fn borrow_v8_terminal_v1<'owner>(
        &'owner mut self,
        physical: &'owner DormantCacheOwnerV1,
        mode: CacheTerminalCutV1,
    ) -> Result<CacheV8TerminalOriginalV1<'owner>, CacheResidencyProtectedJournalErrorV1> {
        reject_legacy_cache_journals()?;
        let clock = Arc::clone(
            self.clock
                .as_ref()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?,
        );
        Ok(CacheV8TerminalOriginalV1 {
            owner: self,
            physical,
            clock,
            mode,
            entered: false,
        })
    }

    /// Borrows the actual held Cache cut for the existing V8 release programme.
    ///
    /// # Errors
    /// Preserves the original legacy-name and unavailable-clock refusals.
    pub fn borrow_v8_held_release_v1<'owner>(
        &'owner mut self,
        physical: &'owner DormantCacheOwnerV1,
    ) -> Result<CacheV8TerminalOriginalV1<'owner>, CacheResidencyProtectedJournalErrorV1> {
        self.borrow_v8_terminal_v1(physical, CacheTerminalCutV1::HeldRelease)
    }

    /// Borrows the actual released hold and pending settlement for readback.
    ///
    /// # Errors
    /// Preserves the original legacy-name and unavailable-clock refusals.
    pub fn borrow_v8_released_readback_v1<'owner>(
        &'owner mut self,
        physical: &'owner DormantCacheOwnerV1,
    ) -> Result<CacheV8TerminalOriginalV1<'owner>, CacheResidencyProtectedJournalErrorV1> {
        self.borrow_v8_terminal_v1(physical, CacheTerminalCutV1::ReleasedReadback)
    }

    /// Borrows only the settlement named by the actual fixed-Root grant.
    ///
    /// # Errors
    /// Preserves the original legacy-name and unavailable-clock refusals.
    pub fn borrow_v8_settlement_clear_v1<'owner>(
        &'owner mut self,
        physical: &'owner DormantCacheOwnerV1,
        grant: RootV8SettledGrantV1,
    ) -> Result<CacheV8TerminalOriginalV1<'owner>, CacheResidencyProtectedJournalErrorV1> {
        self.borrow_v8_terminal_v1(physical, CacheTerminalCutV1::ReleasedSettlement(grant))
    }
}

impl CacheV8TerminalOriginalV1<'_> {
    /// Enters this original's sole native clock/hold/name/physical context.
    ///
    /// # Errors
    /// Preserves the exact original native-entry order and errors; refuses
    /// reentry. No clone/reopen or currentness window can replace this context.
    pub fn borrow_context_once_v1(
        &mut self,
    ) -> Result<CacheV8TerminalContextV1<'_>, CacheResidencyProtectedJournalErrorV1> {
        if self.entered {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.entered = true;
        let clock_guard = self.clock.hold_writer_for_readback()?;
        let root = Path::new(super::super::PROTECTED_CACHE_ROOT);
        let (mut hold_journal, _) = Journal::open_cache_ordinary_role_v1(
            root,
            CACHE_POLICY_HOLD_JOURNAL,
            Journal::cache_policy_hold_limits(),
            self.owner.owner_uid,
            crate::journal::CacheOrdinaryOpenV1::Creating,
        )?;
        let hold_witness = hold_journal.protected_writer_name_witness()?;
        let (hold, historical_held, pending) = self.mode.read(&mut hold_journal)?;
        let state_witness = self
            .owner
            .state_journal
            .as_ref()
            .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?
            .protected_writer_name_witness()?;
        let authority_witness = self.owner.authority.writer_name_witness()?;
        let physical = self
            .physical
            .held_snapshot()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if physical.owner_uid() != self.owner.owner_uid {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        let limits = self.physical.limits();
        clock_guard.revalidate()?;
        self.owner
            .check_held_writer_names(&state_witness, &authority_witness)?;
        hold_journal.require_protected_named_location(
            root,
            CACHE_POLICY_HOLD_JOURNAL,
            self.owner.owner_uid,
            Journal::cache_policy_hold_limits(),
        )?;
        hold_journal.validate_protected_writer_name_witness(&hold_witness)?;
        Ok(CacheV8TerminalContextV1 {
            physical,
            hold_journal,
            hold_witness,
            state_witness,
            authority_witness,
            hold,
            historical_held,
            pending,
            mode: self.mode,
            quota: None,
            stage: V8TerminalStageV1::BeforeInspect,
            inspection_complete: Cell::new(false),
            native_refused: Cell::new(false),
            state: self
                .owner
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?,
            authority: &self.owner.authority,
            limits,
            owner_uid: self.owner.owner_uid,
            clock_guard,
        })
    }
}

impl CacheV8TerminalContextV1<'_> {
    /// Borrows one inspection while its actual authority Mutex stays held.
    ///
    /// # Errors
    /// Preserves original time/lock errors and refuses repeated entry.
    pub fn borrow_inspection_once_v1(
        &mut self,
    ) -> Result<CacheV8InspectionGuardV1<'_>, CacheResidencyProtectedJournalErrorV1> {
        if self.stage != V8TerminalStageV1::BeforeInspect {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.stage = V8TerminalStageV1::InspectEntered;
        let returned = self.authority.borrow_v8_inspection_v1(
            self.state,
            &self.physical,
            &mut self.quota,
            self.limits,
            self.hold,
            &self.native_refused,
            &self.inspection_complete,
        );
        if returned.is_err() {
            self.native_refused.set(true);
        }
        returned
    }

    /// Returns the exact historical held row already read from the same writer.
    #[must_use]
    pub fn historical_held_v1(&self) -> Option<CachePolicyHoldV1> {
        self.historical_held
    }

    fn revalidate(
        &mut self,
        expected_pending: bool,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let returned = self.revalidate_inner(expected_pending);
        if returned.is_err() {
            self.native_refused.set(true);
        }
        returned
    }

    fn revalidate_inner(
        &mut self,
        expected_pending: bool,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.clock_guard.revalidate()?;
        let root = Path::new(super::super::PROTECTED_CACHE_ROOT);
        self.state.require_protected_named_location(
            root,
            CACHE_STATE_JOURNAL,
            self.owner_uid,
            cache_state_journal_limits(),
        )?;
        self.state
            .validate_protected_writer_name_witness(&self.state_witness)?;
        self.authority.check_named_location(|journal| {
            journal.require_protected_named_location(
                root,
                CACHE_AUTHORITY_JOURNAL,
                self.owner_uid,
                cache_authority_journal_limits(),
            )?;
            journal.validate_protected_writer_name_witness(&self.authority_witness)
        })?;
        self.hold_journal.require_protected_named_location(
            root,
            CACHE_POLICY_HOLD_JOURNAL,
            self.owner_uid,
            Journal::cache_policy_hold_limits(),
        )?;
        self.hold_journal
            .validate_protected_writer_name_witness(&self.hold_witness)?;
        let (current, prior, pending) = self.mode.read(&mut self.hold_journal)?;
        if current != self.hold || prior != self.historical_held || pending != expected_pending {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.physical
            .revalidate()
            .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        reject_legacy_cache_journals()?;
        Ok(())
    }

    /// Runs the independently owed Cache post after inspection returned.
    ///
    /// # Errors
    /// Preserves the original Cache-post precedence even when inspect refused.
    pub fn postflight_after_inspect_v1(
        &mut self,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        if self.stage != V8TerminalStageV1::InspectEntered {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.stage = V8TerminalStageV1::AfterInspect;
        self.revalidate(self.pending)
    }

    /// Runs the original Cache post after the upper finish, including refusal.
    ///
    /// # Errors
    /// Preserves native post refusal before the earlier upper finish is selected.
    pub fn postflight_after_finish_v1(
        &mut self,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        if self.native_refused.get()
            || !self.inspection_complete.get()
            || self.stage != V8TerminalStageV1::AfterInspect
        {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.stage = V8TerminalStageV1::AfterFinish;
        self.revalidate(self.pending)
    }

    /// Runs the original extra postflight before release or settlement commit.
    ///
    /// # Errors
    /// Runs even after upper finalize refused; cannot itself commit or grant.
    pub fn postflight_before_commit_v1(
        &mut self,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        if self.native_refused.get()
            || !self.inspection_complete.get()
            || self.stage != V8TerminalStageV1::AfterFinish
            || matches!(
                self.mode,
                CacheTerminalCutV1::HeldReadback | CacheTerminalCutV1::ReleasedReadback
            )
        {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.stage = V8TerminalStageV1::FinalPost;
        self.revalidate(self.pending)
    }

    /// Releases the same hold using actual fixed-peer released Root evidence.
    ///
    /// # Errors
    /// Refuses a different native cut/proof or failed original durable release.
    /// The upper Controller/Source/floor checks remain independently required.
    pub fn release_after_root_original_v1(
        &mut self,
        root: &crate::RootV8ReleasedProofV1,
    ) -> Result<CachePolicyHoldV1, CacheResidencyProtectedJournalErrorV1> {
        if self.native_refused.get()
            || !self.inspection_complete.get()
            || self.stage != V8TerminalStageV1::FinalPost
            || !matches!(self.mode, CacheTerminalCutV1::HeldRelease)
        {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        let Some(quota) = self.quota else {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        };
        if let Err(cause) = root.require_cache_hold_v1(self.hold, quota) {
            self.native_refused.set(true);
            return Err(cause);
        }
        self.stage = V8TerminalStageV1::CommitEntered;
        let released = match self
            .hold_journal
            .release_v8_held_cache_policy_hold_for_writer(self.hold)
        {
            Ok(released) => released,
            Err(cause) => {
                self.native_refused.set(true);
                return Err(cause.into());
            }
        };
        self.stage = V8TerminalStageV1::Complete;
        Ok(released)
    }

    /// Completes the actual readback without release or settlement mutation.
    ///
    /// # Errors
    /// Refuses incomplete or mutating recipes. Returned hold is historical DATA.
    pub fn finish_readback_v1(
        mut self,
    ) -> Result<CachePolicyHoldV1, CacheResidencyProtectedJournalErrorV1> {
        if self.native_refused.get()
            || !self.inspection_complete.get()
            || self.stage != V8TerminalStageV1::AfterFinish
            || !matches!(
                self.mode,
                CacheTerminalCutV1::HeldReadback | CacheTerminalCutV1::ReleasedReadback
            )
        {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.stage = V8TerminalStageV1::Complete;
        Ok(self.hold)
    }

    /// Clears only the pending settlement named by the original Root grant.
    ///
    /// # Errors
    /// Preserves the original grant/hold checks and durable clear/refusal.
    pub fn clear_settlement_once_v1(
        &mut self,
    ) -> Result<CacheV8SettledClearV1, CacheResidencyProtectedJournalErrorV1> {
        if self.native_refused.get()
            || !self.inspection_complete.get()
            || self.stage != V8TerminalStageV1::FinalPost
        {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        let CacheTerminalCutV1::ReleasedSettlement(grant) = self.mode else {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        };
        self.stage = V8TerminalStageV1::CommitEntered;
        let _released = match self
            .hold_journal
            .clear_v8_pending_cache_settlement_for_writer(grant)
        {
            Ok(released) => released,
            Err(cause) => {
                self.native_refused.set(true);
                return Err(cause.into());
            }
        };
        self.stage = V8TerminalStageV1::Committed;
        Ok(CacheV8SettledClearV1 {
            predecessor: grant.predecessor(),
            epoch: grant.epoch(),
            cache_released: grant.cache_released(),
            settlement: grant.settlement(),
        })
    }

    /// Runs the independently owed final Cache post after upper Source clear.
    ///
    /// # Errors
    /// Preserves final-post precedence even when that upper clear refused.
    pub fn postflight_after_settlement_clear_v1(
        &mut self,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        if self.native_refused.get()
            || !self.inspection_complete.get()
            || self.stage != V8TerminalStageV1::Committed
        {
            self.native_refused.set(true);
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
        }
        self.stage = V8TerminalStageV1::Complete;
        self.revalidate(false)
    }
}
