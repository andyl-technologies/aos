//! Borrows the actual Cache Hold and pins the two original target writers.
//!
//! Prepare/terminal observations retain exact native names, allocations,
//! sequences and the complete canonical Q04 suffix. They cannot escape a
//! mutable gate, select a transaction or supply Root release authority.

use std::{path::Path, sync::Arc};

use aos_sandbox_protocol::{
    cache_state::hold_state::q04_recipes::Q04CacheTerminalPhaseV1,
    domain_ledger::{cache_policy_hold::CachePolicyHoldV1, create_q04_history::Q04CutIdentityV1},
};

use super::{
    Journal, JournalError, JournalLimits, CacheJournalInstanceV1,
    CacheQ04TransactionRecipesV1, ProtectedJournalAuthority,
    ProtectedWriterNameWitness, RecordNamespace,
};
use crate::error::CacheQ04ErrorV1;

#[cfg(target_os = "linux")]
struct Q04OriginalCacheTargetV1 {
    instance: Arc<CacheJournalInstanceV1>,
    sequence: u64,
    limits: JournalLimits,
    name: &'static str,
    uid: u32,
    witness: ProtectedWriterNameWitness,
}

#[cfg(target_os = "linux")]
impl Q04OriginalCacheTargetV1 {
    fn capture(journal: &Journal, name: &'static str, uid: u32) -> Result<Self, JournalError> {
        journal.require_protected_named_location(
            Path::new(crate::PROTECTED_CACHE_ROOT), name, uid, journal.limits(),
        )?;
        Ok(Self {
            instance: Arc::clone(journal.instance.comparison_arc_v1()),
            sequence: journal.snapshot_sequence(),
            limits: journal.limits(),
            name,
            uid,
            witness: journal.protected_writer_name_witness()?,
        })
    }

    fn require(&self, journal: &Journal) -> Result<(), JournalError> {
        if !Arc::ptr_eq(&self.instance, journal.instance.comparison_arc_v1())
            || self.sequence != journal.snapshot_sequence()
            || self.limits != journal.limits()
        {
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
        }
        journal.require_protected_named_location(
            Path::new(crate::PROTECTED_CACHE_ROOT), self.name, self.uid, self.limits,
        )?;
        journal.validate_protected_writer_name_witness(&self.witness)
    }
}

// The actual resident initialization lends this original hold writer. The
// other targets are pinned to their exact allocations, names, limits and
// sequences; neither their Journals nor a mutable gate can escape this loan.
#[cfg(target_os = "linux")]
pub(crate) struct Q04CacheTerminalNativeLoanV1<'hold, 'recipes, 'cut> {
    hold: &'hold mut Journal,
    recipes: &'recipes CacheQ04TransactionRecipesV1<'cut>,
    phase: Q04CacheTerminalPhaseV1,
    targets: [Q04OriginalCacheTargetV1; 2],
}

// This is an existing-only observation before Root is opened. The original
// hold remains mutably borrowed, but no mutable gate or transaction escapes.
#[cfg(target_os = "linux")]
pub(crate) struct Q04CachePrepareNativeLoanV1<'hold> {
    hold: &'hold mut Journal,
    prior: Option<CachePolicyHoldV1>,
    targets: [Q04OriginalCacheTargetV1; 2],
    original_hold: Q04OriginalCacheTargetV1,
}

#[cfg(target_os = "linux")]
impl Q04CachePrepareNativeLoanV1<'_> {
    pub(crate) fn require_current(
        &self,
        state: &Journal,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), CacheQ04ErrorV1> {
        if authority.namespace != RecordNamespace::DesiredState
            || self.hold.require_q04_cache_prepare_v1()? != self.prior
        {
            return Err(JournalError::boundary().into());
        }
        self.original_hold.require(self.hold)?;
        self.targets[0].require(state)?;
        self.targets[1].require(authority.journal)?;
        self.hold.require_q04_native_recipes_v1(&[])?;
        state.preflight_q04_cache_read_only_base_v1(self.hold)?;
        authority.journal.preflight_q04_cache_read_only_base_v1(self.hold)?;
        self.original_hold.require(self.hold)?;
        self.targets[0].require(state)?;
        self.targets[1].require(authority.journal)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Q04CacheTerminalNativeLoanV1<'_, '_, '_> {
    pub(crate) fn identity(&self) -> &Q04CutIdentityV1 {
        self.recipes.identity()
    }

    pub(crate) fn hold(&self) -> CachePolicyHoldV1 {
        self.recipes.terminal_hold(self.phase)
    }

    pub(crate) fn require_current(
        &mut self,
        state: &Journal,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), CacheQ04ErrorV1> {
        if authority.namespace != RecordNamespace::DesiredState
        {
            return Err(JournalError::foreign_namespace().into());
        }
        self.targets[0].require(state)?;
        self.targets[1].require(authority.journal)?;
        // Zero selections still run the sole whole native parser and complete
        // replay comparison. Cache state/authority may not append in this cut.
        state.require_q04_native_recipes_v1(&[])?;
        authority.journal.require_q04_native_recipes_v1(&[])?;
        self.recipes.require_fixed_journal(self.hold)?;
        self.recipes.require_prefix(self.hold.read_view().state(), self.phase.prefix())?;
        self.hold.require_q04_native_recipe_prefix_v1(
            &self.recipes.transactions()[..self.phase.prefix()], self.recipes.original_next(),
        )?;
        self.targets[0].require(state)?;
        self.targets[1].require(authority.journal)?;
        self.recipes.require_fixed_journal(self.hold)?;
        self.recipes.require_prefix(self.hold.read_view().state(), self.phase.prefix())?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    pub(crate) fn borrow_q04_cache_prepare_native_v1<'hold>(
        state: &Journal,
        authority: &Journal,
        hold: &'hold mut Journal,
    ) -> Result<Q04CachePrepareNativeLoanV1<'hold>, CacheQ04ErrorV1> {
        let root = Path::new(crate::PROTECTED_CACHE_ROOT);
        let uid = hold.protected_owner_uid()?;
        if state.cache_policy_gate.as_ref().is_none_or(|(directory, owner)| {
            directory.as_path() != root || *owner != uid
        }) || authority.cache_policy_gate != state.cache_policy_gate
        {
            return Err(JournalError::boundary().into());
        }
        let prior = hold.require_q04_cache_prepare_v1()?;
        let original_hold = Q04OriginalCacheTargetV1::capture(hold, super::gate::NAME, uid)?;
        let targets = [
            Q04OriginalCacheTargetV1::capture(state, "state.journal", uid)?,
            Q04OriginalCacheTargetV1::capture(authority, "authority.journal", uid)?,
        ];
        Ok(Q04CachePrepareNativeLoanV1 { hold, prior, targets, original_hold })
    }

    pub(super) fn require_q04_cache_read_only_base_v1(&self, hold: &Journal) -> Result<(), JournalError> {
        let uid = hold.protected_owner_uid()?;
        hold.require_q04_cache_prepare_v1()?;
        let location = self
            .read_view().protected_view()
            .ok_or(JournalError::boundary())?;
        let fixed_target = match location.name() {
            "clock.journal" => self.cache_policy_gate.is_none(),
            "authority.journal" | "state.journal" => self.cache_policy_gate.as_ref().is_some_and(|(root, owner)| {
                root.as_path() == Path::new(crate::PROTECTED_CACHE_ROOT) && *owner == uid
            }),
            _ => false,
        };
        if !fixed_target
        {
            return Err(JournalError::boundary());
        }
        self.require_protected_named_location(
            Path::new(crate::PROTECTED_CACHE_ROOT),
            &location.name(),
            uid,
            self.limits(),
        )?;
        self.require_q04_native_recipes_v1(&[])
            .map_err(|cause| JournalError::Q04Original(Box::new(cause)))?;
        hold.require_q04_native_recipes_v1(&[])
            .map_err(|cause| JournalError::Q04Original(Box::new(cause)))?;
        Ok(())
    }

    pub(crate) fn borrow_q04_cache_terminal_native_v1<'hold, 'recipes, 'cut>(
        state: &Journal,
        authority: &Journal,
        hold: &'hold mut Journal,
        recipes: &'recipes CacheQ04TransactionRecipesV1<'cut>,
        phase: Q04CacheTerminalPhaseV1,
    ) -> Result<Q04CacheTerminalNativeLoanV1<'hold, 'recipes, 'cut>, CacheQ04ErrorV1> {
        let root = Path::new(crate::PROTECTED_CACHE_ROOT);
        let uid = hold.protected_owner_uid()?;
        if state.cache_policy_gate.as_ref().is_none_or(|(directory, owner)| {
            directory.as_path() != root || *owner != uid
        }) || authority.cache_policy_gate != state.cache_policy_gate
        {
            return Err(JournalError::boundary().into());
        }
        recipes.require_fixed_journal(hold)?;
        recipes.require_prefix(hold.read_view().state(), phase.prefix())?;
        let targets = [
            Q04OriginalCacheTargetV1::capture(state, "state.journal", uid)?,
            Q04OriginalCacheTargetV1::capture(authority, "authority.journal", uid)?,
        ];
        Ok(Q04CacheTerminalNativeLoanV1 { hold, recipes, phase, targets })
    }
}
