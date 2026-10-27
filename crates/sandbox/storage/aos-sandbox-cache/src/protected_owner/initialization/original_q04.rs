//! Holds actual Cache Q04 writers, clock, physical custody and reached results.
//!
//! The upper Controller retains its ledger, protected signer and Source/Root
//! semantic orchestration. This owner keeps only Cache-native originals and
//! accepts the genuine same-wire Broker Root borrower at every native phase.
//! No phase DATA, descriptor, Journal or supplied map can construct this cut.

mod append;
pub use append::{CacheQ04AppendContextV1, CacheQ04AppendGateV1, CacheQ04AppendGuardV1};
pub(super) use append::receiving_control_bytes_v1 as append_receiving_control_bytes_v1;

use aos_sandbox_protocol::cache_state::hold_state::q04_recipes::Q04CacheTerminalPhaseV1;

use super::*;
use crate::error::CacheQ04ErrorV1;
use aos_sandbox_broker::controller_receiving::profile::root_flight::{
    ControllerRootQ04CacheLoanV1, ControllerRootQ04FinalObservationLoanV1,
};
use aos_sandbox_protocol::cache_owner_readback::{
    CLOSED_CACHE_OWNER_READBACK_BYTES_V2, CacheOwnerReadbackChallengeV1,
};
use aos_sandbox_protocol::domain_ledger::create_q04_history::Q04CutIdentityV1;
#[derive(Default)]
pub(super) struct Q04ResidentCacheProgressV1 {
    cut: Option<[u8; aos_sandbox_protocol::domain_ledger::create_q04_history::IDENTITY_BYTES]>,
    prepare: Option<Result<super::super::Q04CachePrepareReadbackV1, CacheQ04ErrorV1>>,
    prepare_coordinates: Option<[(crate::journal::ProtectedJournalNamesV1, u64); 4]>,
    readbacks: [Option<Result<super::super::CacheResidencyWriterReadbackV2, CacheQ04ErrorV1>>; 3],
    commits: [Option<Result<crate::journal::CommitResult, CacheQ04ErrorV1>>; 3],
    signed: Option<
        Result<
            [u8; aos_sandbox_protocol::cache_owner_readback::CLOSED_CACHE_OWNER_READBACK_BYTES_V2],
            CacheQ04ErrorV1,
        >,
    >,
    failed_commit: Option<usize>,
    first: Option<CacheQ04ErrorV1>,
    postcheck: Option<CacheQ04ErrorV1>,
    started: bool,
    // Set only after the genuine original Root/Native terminal checks succeed.
    // Complete-looking historical rows or a new initializer cannot set it.
    cleared_original_complete: bool,
}

// This short construction fence is created after the actual clock guard. It
// therefore ends first on unwind and cannot let that guard unfreeze a partial
// pair. Its loans end before the infallible final owner-loan assembly.
#[cfg(target_os = "linux")]
struct Q04CacheLoanAssemblyFenceV1<'slots> {
    first: &'slots mut Option<CacheQ04ErrorV1>,
    owner_failure: &'slots mut Option<InitializationCauseV1>,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl Q04CacheLoanAssemblyFenceV1<'_> {
    fn fail(&mut self, cause: CacheQ04ErrorV1) -> ! {
        self.first.get_or_insert(cause);
        self.owner_failure.get_or_insert(InitializationCauseV1::Q04);
        std::process::exit(1);
    }

    fn finish(mut self) {
        self.armed = false;
    }
}

#[cfg(target_os = "linux")]
impl Drop for Q04CacheLoanAssemblyFenceV1<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.first.get_or_insert(CacheQ04ErrorV1::Unwind);
            self.owner_failure.get_or_insert(InitializationCauseV1::Q04);
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
impl Q04ResidentCacheProgressV1 {
    /// Borrows completed original progression and returns only its cut DATA.
    ///
    /// This checks the actual retained Native and terminal owners. It grants
    /// no fresh Q04, Cache, append, receiving, or currentness authority.
    pub(super) fn identity_after_original_clearance(
        &self,
        original_hold: Option<Option<CachePolicyHoldV1>>,
    ) -> Result<Q04CutIdentityV1, CacheQ04ErrorV1> {
        if !self.started
            || !self.cleared_original_complete
            || self.failure().is_some()
            || self
                .commits
                .iter()
                .any(|result| !matches!(result, Some(Ok(_))))
            || self
                .readbacks
                .iter()
                .any(|result| !matches!(result, Some(Ok(_))))
            || !matches!(self.signed, Some(Ok(_)))
        {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        let terminal = self.readbacks[2]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(CacheQ04ErrorV1::ChangedCut)?;
        if terminal.hold().is_held() || original_hold != Some(Some(terminal.hold())) {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        let cut = self.cut.as_ref().ok_or(CacheQ04ErrorV1::ChangedCut)?;
        Q04CutIdentityV1::decode(cut).map_err(Into::into)
    }

    // This passive state view lets sibling pricing refuse reentry without
    // exposing mutable progress or reconstructing a Q04 stage.
    pub(super) const fn has_started(&self) -> bool {
        self.started
    }

    pub(super) fn failure(&self) -> Option<&CacheQ04ErrorV1> {
        self.first
            .as_ref()
            .or_else(|| {
                self.failed_commit
                    .and_then(|index| self.commits[index].as_ref())
                    .and_then(|result| result.as_ref().err())
            })
            .or_else(|| {
                self.signed
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
            })
            .or(self.postcheck.as_ref())
    }
}

// This borrows the existing initialization/physical originals in their fixed
// order. The actual coordinator opens Root only after this guard exists. It
// exposes no Journal, FD, authority session, arbitrary callback or pin method.
#[cfg(target_os = "linux")]
/// Borrows the original five Cache writers, physical owner and held Clock.
///
/// Only the prepared native capture constructs this owner. Dropping an
/// unfinished cut fences the process before the actual Clock guard releases.
pub struct OriginalQ04CacheOwnerCutV1<'original> {
    source: &'original mut CacheReplayControllerBootstrapOwnerV1,
    hold: &'original mut Journal,
    original_hold: &'original mut Option<Option<CachePolicyHoldV1>>,
    state: &'original mut Journal,
    authority: &'original Arc<ProtectedCacheResidencyReplayAuthorityV1>,
    clock: CacheClockWriterReadbackGuard<'original>,
    physical: &'original crate::DormantCacheOwnerV1,
    physical_identity: crate::physical::CacheOwnerHeldIdentityV1,
    uid: u32,
    progress: &'original mut Q04ResidentCacheProgressV1,
    complete: &'original mut bool,
    first_failure: &'original mut Option<InitializationCauseV1>,
    finished: bool,
}

#[cfg(target_os = "linux")]
impl<'owner> OriginalQ04CacheOwnerCutV1<'owner> {
    fn prepare_coordinates(
        &self,
    ) -> Result<[(crate::journal::ProtectedJournalNamesV1, u64); 4], CacheQ04ErrorV1> {
        self.hold.require_q04_cache_prepare_v1()?;
        self.hold.require_q04_native_recipes_v1(&[])?;
        let targets =
            self.authority
                .q04_prepare_target_coordinates_v1(self.state, self.hold, &self.clock)?;
        Ok([
            (
                self.hold.protected_writer_physical_names_v1()?,
                self.hold.snapshot_sequence(),
            ),
            targets[0],
            targets[1],
            targets[2],
        ])
    }

    /// Captures the complete existing project Cache selection once.
    ///
    /// # Errors
    /// Retains native replay, physical limits or changed original failures.
    pub fn capture_prepare_readback(&mut self, project: ProjectId) -> Result<(), ()> {
        let returned = (|| {
            if self.progress.prepare.is_some()
                || self.progress.prepare_coordinates.is_some()
                || self.progress.cut.is_some()
                || self.progress.failure().is_some()
                || self.finished
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            self.recheck_owned()?;
            let original = self.prepare_coordinates()?;
            self.authority.capture_borrowed_q04_prepare_readback_v1(
                self.state,
                self.hold,
                &self.clock,
                project,
                self.physical,
                &mut self.progress.prepare,
                &mut self.progress.first,
                &mut self.progress.postcheck,
            )?;
            if self.prepare_coordinates()? != original {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            self.progress.prepare_coordinates = Some(original);
            self.recheck_owned()
        })();
        if let Err(cause) = returned {
            self.progress.first.get_or_insert(cause);
            self.first_failure.get_or_insert(InitializationCauseV1::Q04);
            return Err(());
        }
        Ok(())
    }

    /// Borrows the actual positive prehold Cache selection.
    ///
    /// # Errors
    /// Refuses an earlier native failure or an absent completed selection.
    pub fn prepare_readback(
        &self,
    ) -> Result<&super::super::Q04CachePrepareReadbackV1, CacheQ04ErrorV1> {
        if self.progress.failure().is_some() || self.finished {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        match self.progress.prepare.as_ref() {
            Some(Ok(readback)) => Ok(readback),
            _ => Err(CacheQ04ErrorV1::ChangedCut),
        }
    }

    // Called only before C1. These are the actual six named-writer records
    // in the signed prehold DATA packet, not a hidden currentness certificate.
    /// Writes the exact observed Cache coordinates into the fixed metadata body.
    ///
    /// # Errors
    /// Retains absent readback, changed coordinates or native currentness failure.
    pub fn write_prepare_metadata(
        &mut self,
        metadata: &mut [u8; aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::PREHOLD_METADATA_BYTES],
    ) -> Result<(), ()> {
        let returned = (|| {
            self.prepare_readback()?;
            let original = self
                .progress
                .prepare_coordinates
                .ok_or(CacheQ04ErrorV1::ChangedCut)?;
            self.recheck_owned()?;
            if self.prepare_coordinates()? != original {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            for (index, (names, next)) in original.iter().enumerate() {
                let name_offset = 272 + index * 48;
                let next_offset = 480 + index * 8;
                metadata[name_offset..name_offset + 48].copy_from_slice(&names.to_bytes());
                metadata[next_offset..next_offset + 8].copy_from_slice(&next.to_be_bytes());
            }
            self.recheck_owned()
        })();
        if let Err(cause) = returned {
            self.progress.first.get_or_insert(cause);
            self.first_failure.get_or_insert(InitializationCauseV1::Q04);
            return Err(());
        }
        Ok(())
    }

    /// Prepares the same Cache capture before the upper Controller identity check.
    ///
    /// # Errors
    /// Retains changed original, quota, coordinates or native currentness failures.
    pub fn prepare_transaction_recipe_capture_v1<'capture, 'cut>(
        &'capture mut self,
        identity: &'cut Q04CutIdentityV1,
    ) -> Result<CacheQ04RecipeCaptureBorrowV1<'capture, 'owner, 'cut>, ()> {
        let returned = (|| {
            self.require_progress(identity)?;
            self.recheck_owned()?;
            let readback = self.prepare_readback()?;
            if readback.quota_digest() != identity.cache_quota()
                || Some(self.prepare_coordinates()?) != self.progress.prepare_coordinates
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            Ok(readback.selected())
        })();
        match returned {
            Ok(selected) => Ok(CacheQ04RecipeCaptureBorrowV1 {
                cache: self,
                identity,
                selected,
            }),
            Err(cause) => {
                self.progress.first.get_or_insert(cause);
                self.first_failure.get_or_insert(InitializationCauseV1::Q04);
                Err(())
            }
        }
    }

    fn recheck_owned(&mut self) -> Result<(), CacheQ04ErrorV1> {
        self.source.recheck_existing()?;
        self.recheck_borrowed_targets()
    }

    fn recheck_borrowed_targets(&self) -> Result<(), CacheQ04ErrorV1> {
        require_cache_named_writer(
            self.hold,
            Path::new(PROTECTED_CACHE_ROOT),
            CACHE_POLICY_HOLD_JOURNAL,
            self.uid,
            Journal::cache_policy_hold_limits(),
        )?;
        require_cache_named_writer(
            self.state,
            Path::new(PROTECTED_CACHE_ROOT),
            CACHE_STATE_JOURNAL,
            self.uid,
            cache_state_journal_limits(),
        )?;
        self.authority
            .require_q04_original_cache_targets_v1(self.state, &self.clock)?;
        self.authority.check_named_location(|journal| {
            require_cache_named_writer(
                journal,
                Path::new(PROTECTED_CACHE_ROOT),
                CACHE_AUTHORITY_JOURNAL,
                self.uid,
                cache_authority_journal_limits(),
            )?;
            journal
                .require_q04_native_recipes_v1(&[])
                .map_err(|first| JournalError::Q04Original(Box::new(first)))?;
            Ok(())
        })?;
        self.state.require_q04_native_recipes_v1(&[])?;
        self.physical
            .require_held_identity(self.physical_identity)?;
        self.clock.revalidate()?;
        Ok(())
    }

    /// Prepares the release binding up to the actual upper Root frontier.
    ///
    /// # Errors
    /// Retains changed phase, prior recipe binding or native currentness errors.
    pub fn prepare_release_binding_v1<'step, 'flight, 'profile, 'cut>(
        &'step mut self,
        root: &'step ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut>,
        recipes: &'step mut crate::journal::CacheQ04TransactionRecipesV1<'cut>,
    ) -> Result<CacheQ04ReleaseBindingBorrowV1<'step, 'owner, 'flight, 'profile, 'cut>, ()> {
        let returned = (|| {
            self.require_progress(root.identity())?;
            if !matches!(self.progress.commits[0], Some(Ok(_)))
                || self.progress.commits[1].is_some()
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            self.recheck_owned()?;
            if recipes.release_authorization().is_some()
                || !std::ptr::eq(root.identity(), recipes.identity())
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            Ok(())
        })();
        if let Err(cause) = returned {
            self.progress.first.get_or_insert(cause);
            return Err(());
        }
        Ok(CacheQ04ReleaseBindingBorrowV1 {
            cache: self,
            root,
            recipes,
            entered: false,
        })
    }

    fn require_progress(&self, identity: &Q04CutIdentityV1) -> Result<(), CacheQ04ErrorV1> {
        if self.finished
            || self.progress.first.is_some()
            || self.progress.postcheck.is_some()
            || self.progress.failed_commit.is_some()
            || self
                .progress
                .cut
                .as_ref()
                .is_some_and(|cut| cut != identity.bytes())
        {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        Ok(())
    }

    /// Prepares the actual native append up to the upper Root semantic frontier.
    ///
    /// # Errors
    /// Retains changed sequence/order, native custody or prior phase failure.
    pub fn prepare_append_original_phase_v1<'step, 'flight, 'profile, 'cut>(
        &'step mut self,
        root: &'step ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut>,
        recipes: &'step crate::journal::CacheQ04TransactionRecipesV1<'cut>,
        index: usize,
    ) -> Result<CacheQ04AppendOriginalBorrowV1<'step, 'owner, 'flight, 'profile, 'cut>, ()> {
        let prepared = (|| {
            self.require_progress(root.identity())?;
            if index >= 3
                || self.progress.commits[index].is_some()
                || self.progress.commits[..index]
                    .iter()
                    .any(|prior| !matches!(prior, Some(Ok(_))))
                || !std::ptr::eq(root.identity(), recipes.identity())
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            self.progress.cut = Some(*root.identity().bytes());
            self.recheck_owned()?;
            Ok(())
        })();
        if let Err(cause) = prepared {
            self.progress.first.get_or_insert(cause);
            return Err(());
        }

        Ok(CacheQ04AppendOriginalBorrowV1 {
            cache: self,
            root,
            recipes,
            index,
            entered: false,
            context_started: false,
            readback_entered: false,
            native_post_complete: false,
        })
    }

    /// Prepares the terminal observation up to the upper Root semantic check.
    ///
    /// # Errors
    /// Retains prior failure, changed order, original identity or native errors.
    pub fn prepare_terminal_readback_v1<'step, 'flight, 'profile, 'cut>(
        &'step mut self,
        root: &'step ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut>,
        recipes: &'step crate::journal::CacheQ04TransactionRecipesV1<'cut>,
        phase: Q04CacheTerminalPhaseV1,
    ) -> Result<CacheQ04TerminalBorrowV1<'step, 'owner, 'flight, 'profile, 'cut>, ()> {

        let index = match phase {
            Q04CacheTerminalPhaseV1::Held => 0,
            Q04CacheTerminalPhaseV1::Released => 1,
            Q04CacheTerminalPhaseV1::Cleared => 2,
        };
        let returned = (|| {
            if self.finished
                || self.progress.first.is_some()
                || self.progress.postcheck.is_some()
                || self.progress.failed_commit.is_some()
                || self.progress.readbacks[index].is_some()
                || self.progress.readbacks[..index]
                    .iter()
                    .any(|prior| !matches!(prior, Some(Ok(_))))
                || root.identity().controller_uid() != self.uid
                || !std::ptr::eq(root.identity(), recipes.identity())
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            match self.progress.cut {
                None if index == 0 => {
                    self.progress.cut = Some(*root.identity().bytes());
                }
                Some(original) if &original == root.identity().bytes() => {}
                _ => return Err(CacheQ04ErrorV1::ChangedCut),
            }
            self.recheck_owned()?;
            Ok(())
        })();
        if let Err(cause) = returned {
            self.progress.first.get_or_insert(cause);
        }
        Ok(CacheQ04TerminalBorrowV1 {
            cache: self,
            root,
            recipes,
            phase,
            index,
            provider_stage: Q04TerminalProviderStageV1::Request,
        })
    }

    /// Borrows the actual completed terminal readback for the fixed phase.
    ///
    /// # Errors
    /// Refuses absent phase completion or any earlier retained native failure.
    pub fn terminal_readback(
        &self,
        phase: Q04CacheTerminalPhaseV1,
    ) -> Result<&super::super::CacheResidencyWriterReadbackV2, CacheQ04ErrorV1> {
        let index = match phase {
            Q04CacheTerminalPhaseV1::Held => 0,
            Q04CacheTerminalPhaseV1::Released => 1,
            Q04CacheTerminalPhaseV1::Cleared => 2,
        };
        if self.progress.first.is_some()
            || self.progress.postcheck.is_some()
            || self.progress.failed_commit.is_some()
        {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        match self.progress.readbacks[index].as_ref() {
            Some(Ok(readback)) => Ok(readback),
            _ => Err(CacheQ04ErrorV1::ChangedCut),
        }
    }

    /// Prepares signing up to the upper credential and Root challenge frontier.
    ///
    /// # Errors
    /// Retains a changed original, earlier phase failure or native readback error.
    pub fn prepare_signed_held_readback_v1<'step, 'flight, 'profile, 'cut>(
        &'step mut self,
        root: &'step ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut>,
        recipes: &'step crate::journal::CacheQ04TransactionRecipesV1<'cut>,
    ) -> Result<CacheQ04SigningBorrowV1<'step, 'owner, 'flight, 'profile, 'cut>, ()> {
        let prepared = (|| {
            self.require_progress(root.identity())?;
            if self.progress.signed.is_some()
                || !std::ptr::eq(root.identity(), recipes.identity())
                || !matches!(self.progress.commits[0], Some(Ok(_)))
                || self.progress.commits[1].is_some()
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            self.recheck_owned()?;
            self.hold.readback_cache_q04_original_v1(recipes, 1)?;
            self.terminal_readback(Q04CacheTerminalPhaseV1::Held)?
                .require_original_q04_physical_limits(self.physical.limits())?;
            Ok(())
        })();
        if let Err(cause) = prepared {
            self.progress.first.get_or_insert(cause);
            return Err(());
        }
        Ok(CacheQ04SigningBorrowV1 { cache: self, root })
    }

    // The upper credential post precedes this same independent native post,
    // including a failed packet/signing result; no healthy-progress gate hides it.
    /// Runs the independent native signing after checks on the original owner.
    ///
    /// # Errors
    /// Retains native names, physical, Clock or genuine Root after failures.
    pub fn finish_signed_held_native_post_v1(
        &mut self,
        recipes: &crate::journal::CacheQ04TransactionRecipesV1<'_>,
    ) -> Result<(), ()> {
        let checked = (|| {
            self.recheck_owned()?;
            self.hold.readback_cache_q04_original_v1(recipes, 1)?;
            Ok(())
        })();
        let post_failed = checked.is_err();
        if let Err(cause) = checked {
            self.progress.postcheck.get_or_insert(cause);
        }
        if self.progress.failure().is_some() {
            self.first_failure.get_or_insert(InitializationCauseV1::Q04);
        }
        // This status belongs only to this post. An earlier signing failure
        // cannot suppress the later Root check when these native posts passed.
        if post_failed {
            return Err(());
        }
        Ok(())
    }

    /// Borrows the actual completed canonical signed Cache packet.
    ///
    /// # Errors
    /// Refuses absent signing, a finished loan or an earlier native failure.
    pub fn signed_held_readback(
        &self,
    ) -> Result<
        &[u8; aos_sandbox_protocol::cache_owner_readback::CLOSED_CACHE_OWNER_READBACK_BYTES_V2],
        CacheQ04ErrorV1,
    > {
        if self.finished || self.progress.failure().is_some() {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        match self.progress.signed.as_ref() {
            Some(Ok(packet)) => Ok(packet),
            _ => Err(CacheQ04ErrorV1::ChangedCut),
        }
    }

    /// Checks the actual final Cache destinations before the upper Root check.
    ///
    /// # Errors
    /// Retains any earlier failure or incomplete original commit/readback/signature.
    pub fn prepare_final_clearance_v1(
        &mut self,
        recipes: &crate::journal::CacheQ04TransactionRecipesV1<'_>,
        root: &ControllerRootQ04FinalObservationLoanV1<'_, '_, '_>,
    ) -> Result<(), ()> {
        let returned = (|| {
            self.require_progress(root.identity())?;
            if !std::ptr::eq(root.identity(), recipes.identity())
                || self
                    .progress
                    .commits
                    .iter()
                    .any(|result| !matches!(result, Some(Ok(_))))
                || self
                    .progress
                    .readbacks
                    .iter()
                    .any(|result| !matches!(result, Some(Ok(_))))
                || !matches!(self.progress.signed, Some(Ok(_)))
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            Ok(())
        })();
        if let Err(cause) = returned {
            self.progress.first.get_or_insert(cause);
            return Err(());
        }
        Ok(())
    }

    /// Prepares native completion before the final full upper Root check.
    ///
    /// # Errors
    /// Retains incomplete original destinations, changed native prefix or final flight failure.
    pub fn prepare_clearance_completion_v1<'step, 'flight, 'profile, 'cut>(
        &'step mut self,
        recipes: &'step crate::journal::CacheQ04TransactionRecipesV1<'cut>,
        root: &'step ControllerRootQ04FinalObservationLoanV1<'flight, 'profile, 'cut>,
    ) -> Result<CacheQ04FinalCompletionBorrowV1<'step, 'owner, 'flight, 'profile, 'cut>, ()> {
        let checked = (|| {
            self.require_progress(root.identity())?;
            if !std::ptr::eq(root.identity(), recipes.identity())
                || self
                    .progress
                    .commits
                    .iter()
                    .any(|result| !matches!(result, Some(Ok(_))))
                || self
                    .progress
                    .readbacks
                    .iter()
                    .any(|result| !matches!(result, Some(Ok(_))))
                || !matches!(self.progress.signed, Some(Ok(_)))
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            root.require_completed_affinity_data_v1()?;
            self.recheck_owned()?;
            self.hold.readback_cache_q04_original_v1(recipes, 3)?;
            let result = self.progress.commits[2]
                .as_ref()
                .and_then(|returned| returned.as_ref().ok())
                .ok_or(CacheQ04ErrorV1::ChangedCut)?;
            self.hold.require_q04_returned_commit_v1(result)?;
            self.terminal_readback(Q04CacheTerminalPhaseV1::Cleared)?
                .require_original_q04_physical_limits(self.physical.limits())?;
            if *self.original_hold
                != Some(Some(recipes.terminal_hold(
                    Q04CacheTerminalPhaseV1::Cleared,
                )))
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            self.recheck_owned()?;
            root.require_completed_affinity_data_v1()
                .map_err(CacheQ04ErrorV1::from)
        })();
        if let Err(cause) = checked {
            self.progress.postcheck.get_or_insert(cause);
            self.first_failure.get_or_insert(InitializationCauseV1::Q04);
            return Err(());
        }

        Ok(CacheQ04FinalCompletionBorrowV1 { cache: self, root })
    }

    /// Checks the actual cleared Cache prefix before the upper Source clearance.
    ///
    /// # Errors
    /// Preserves native names, physical limits, Clock and genuine Root failures.
    pub fn require_source_clearance_native_v1(
        &mut self,
        root: &ControllerRootQ04CacheLoanV1<'_, '_, '_>,
        recipes: &crate::journal::CacheQ04TransactionRecipesV1<'_>,
    ) -> Result<(), CacheQ04ErrorV1> {
        self.require_progress(root.identity())?;
        self.recheck_owned()?;
        self.terminal_readback(Q04CacheTerminalPhaseV1::Cleared)?;
        self.hold.readback_cache_q04_original_v1(recipes, 3)?;
        Ok(())
    }

    /// Rechecks the same five native originals for an upper Source boundary.
    ///
    /// # Errors
    /// Moves the genuine native cause to the actual upper retained destination.
    pub fn recheck_original_owned_v1(&mut self) -> Result<(), CacheQ04ErrorV1> {
        self.recheck_owned()
    }

    /// Checks the actual native cleared prefix at the Source append frontier.
    ///
    /// # Errors
    /// Preserves exact progress, name, native-prefix and same-wire Root causes.
    pub fn recheck_source_clearance_at_append_v1(
        &self,
        root: &ControllerRootQ04CacheLoanV1<'_, '_, '_>,
        recipes: &crate::journal::CacheQ04TransactionRecipesV1<'_>,
    ) -> Result<(), CacheQ04ErrorV1> {
        self.require_progress(root.identity())?;
        if !std::ptr::eq(root.identity(), recipes.identity())
            || !matches!(self.progress.commits[2], Some(Ok(_)))
            || !matches!(self.progress.readbacks[2], Some(Ok(_)))
        {
            return Err(CacheQ04ErrorV1::ChangedCut);
        }
        self.recheck_borrowed_targets()?;
        self.hold.readback_cache_q04_original_v1(recipes, 3)?;
        Ok(())
    }

    /// Borrows the retained native cause at the same actual failure frontier.
    #[must_use]
    pub fn failure(&self) -> Option<&CacheQ04ErrorV1> {
        self.progress.failure()
    }
}

#[cfg(target_os = "linux")]
impl Drop for OriginalQ04CacheOwnerCutV1<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.progress.first.get_or_insert(CacheQ04ErrorV1::Unwind);
            self.first_failure.get_or_insert(InitializationCauseV1::Q04);
            // Fence before the actual protected-clock guard or any borrowed
            // caller original can drop. Logical release is not disposal.
            std::process::exit(1);
        }
    }
}

impl CacheResidentInitializationV1 {
    #[cfg(target_os = "linux")]
    pub(super) fn begin_original_q04<'original>(
        &'original mut self,
        owner: &'original mut CacheResidencyProtectedOwnerV1,
        physical: &'original crate::DormantCacheOwnerV1,
    ) -> Result<OriginalQ04CacheOwnerCutV1<'original>, CacheResidentUnavailableV1> {
        self.recheck(owner)?;
        if self.q04.started {
            return Err(CacheResidentUnavailableV1);
        }
        self.q04.started = true;
        self.complete = false;
        let Some(clock) = self.clock.as_ref() else {
            self.q04.first = Some(CacheQ04ErrorV1::ChangedCut);
            self.first_failure.get_or_insert(InitializationCauseV1::Q04);
            return Err(CacheResidentUnavailableV1);
        };
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.q04.first = Some(cause.into());
                self.first_failure.get_or_insert(InitializationCauseV1::Q04);
                return Err(CacheResidentUnavailableV1);
            }
        };
        let mut assembly = Q04CacheLoanAssemblyFenceV1 {
            first: &mut self.q04.first,
            owner_failure: &mut self.first_failure,
            armed: true,
        };
        let returned = (|| {
            if owner
                .clock
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(clock, current))
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            let snapshot = physical.held_snapshot()?;
            if snapshot.owner_uid() != owner.owner_uid
                || self.physical_limits != Some(physical.limits())
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            Ok(snapshot.identity())
        })();
        let physical_identity = match returned {
            Ok(identity) => identity,
            Err(cause) => {
                // This same actual clock guard has already been acquired.
                // Exit here, before its destructor could unfreeze the clock
                // while the rest of a failed original pair remains held.
                assembly.fail(cause);
            }
        };
        let (Some(source), Some(hold), Some(state)) = (
            self.source.as_mut(),
            self.hold.as_mut(),
            owner.state_journal.as_mut(),
        ) else {
            assembly.fail(CacheQ04ErrorV1::ChangedCut);
        };
        assembly.finish();
        Ok(OriginalQ04CacheOwnerCutV1 {
            source,
            hold: &mut hold.0,
            original_hold: &mut self.original_hold,
            state,
            authority: &owner.authority,
            clock: guard,
            physical,
            physical_identity,
            uid: owner.owner_uid,
            progress: &mut self.q04,
            complete: &mut self.complete,
            first_failure: &mut self.first_failure,
            finished: false,
        })
    }
}

/// Keeps the actual held Cache borrow across the upper Controller identity check.
///
/// Only the native owner's complete preparation can construct this borrower.
/// It contains no payer, Root permission or public Journal accessor.
pub struct CacheQ04RecipeCaptureBorrowV1<'capture, 'owner, 'cut> {
    cache: &'capture mut OriginalQ04CacheOwnerCutV1<'owner>,
    identity: &'cut Q04CutIdentityV1,
    selected: crate::CurrentProjectPhysicalCacheHeadV1,
}

impl<'cut> CacheQ04RecipeCaptureBorrowV1<'_, '_, 'cut> {
    /// Captures the actual held recipe after the upper's immediate ledger check.
    ///
    /// # Errors
    /// Retains the exact Cache capture/preflight cause in the resident owner.
    pub fn capture_after_controller_identity_v1(
        self,
    ) -> Result<crate::journal::CacheQ04TransactionRecipesV1<'cut>, ()> {
        let returned = (|| {
            let recipes =
                crate::journal::CacheQ04TransactionRecipesV1::capture_after_controller_identity_v1(
                    self.cache.hold,
                    self.identity,
                    self.selected,
                )?;
            self.cache.hold.preflight_cache_q04_suffix_v1(&recipes)?;
            self.cache.recheck_owned()?;
            Ok(recipes)
        })();
        match returned {
            Ok(recipes) => Ok(recipes),
            Err(cause) => {
                self.cache.progress.first.get_or_insert(cause);
                self.cache
                    .first_failure
                    .get_or_insert(InitializationCauseV1::Q04);
                Err(())
            }
        }
    }
}

fn q04_readback_preparation_error_v1(cause: crate::CacheOwnerReadbackErrorV1) -> CacheQ04ErrorV1 {
    match cause {
        crate::CacheOwnerReadbackErrorV1::Owner(cause) => CacheQ04ErrorV1::Physical(cause),
        cause => CacheQ04ErrorV1::Packet(cause),
    }
}

impl CacheResidentInitializationV1 {
    /// Borrows the actual Q04 cause without another native observation.
    #[must_use]
    pub fn original_q04_failure_v1(&self) -> Option<&CacheQ04ErrorV1> {
        self.q04.failure()
    }

    /// Borrows completed original-clearance identity DATA from the same owner.
    ///
    /// # Errors
    /// Refuses incomplete native/physical/readback progression or changed hold.
    pub fn original_q04_clearance_identity_data_v1(
        &self,
    ) -> Result<Q04CutIdentityV1, CacheQ04ErrorV1> {
        self.q04
            .identity_after_original_clearance(self.original_hold)
    }
}

/// Keeps the exact actual append originals across the upper Root check.
///
/// Only the native prepare operation constructs this borrower. Every effect
/// still requires the genuine Root phase at the final native crossing.
pub struct CacheQ04AppendOriginalBorrowV1<'step, 'owner, 'flight, 'profile, 'cut> {
    cache: &'step mut OriginalQ04CacheOwnerCutV1<'owner>,
    root: &'step ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut>,
    recipes: &'step crate::journal::CacheQ04TransactionRecipesV1<'cut>,
    index: usize,
    entered: bool,
    context_started: bool,
    readback_entered: bool,
    native_post_complete: bool,
}

impl CacheQ04AppendOriginalBorrowV1<'_, '_, '_, '_, '_> {
    /// Checks the original journal-entry recipe affinity before its Root gate.
    ///
    /// # Errors
    /// Retains reentry or exact pointer mismatch as the actual COMMIT failure.
    pub fn validate_journal_entry_once_v1(&mut self) -> Result<(), ()> {
        if self.entered {
            self.cache.progress.first.get_or_insert(CacheQ04ErrorV1::ChangedCut);
            return Err(());
        }
        self.entered = true;
        if !std::ptr::eq(self.recipes.identity(), self.root.identity()) {
            self.cache.progress.commits[self.index] = Some(Err(CacheQ04ErrorV1::ChangedCut));
            self.cache.progress.failed_commit = Some(self.index);
            return Err(());
        }
        Ok(())
    }

    /// Fences the actual entered COMMIT after the upper journal Root refusal.
    ///
    /// The upper retains the whole semantic Root error; this marker cannot
    /// authorize append or replace the actual upper first-cause selection.
    pub fn refuse_journal_entry_after_upper_root_v1(&mut self) {
        self.context_started = true;
        self.cache.progress.commits[self.index].get_or_insert(Err(JournalError::boundary().into()));
        self.cache.progress.failed_commit = Some(self.index);
    }

    /// Runs the original returned-COMMIT/native readback closure after entry.
    ///
    /// # Errors
    /// Preserves the real append error and the reached readback post failure.
    pub fn finish_native_readback_once_v1(&mut self) -> Result<(), ()> {
        if !self.entered || self.readback_entered {
            self.cache.progress.first.get_or_insert(CacheQ04ErrorV1::ChangedCut);
            return Err(());
        }
        self.readback_entered = true;
        let index = self.index;
        let readback = (|| {
            let result = self.cache.progress.commits[index]
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheQ04ErrorV1::ChangedCut)?;
            self.cache
                .hold
                .readback_cache_q04_original_v1(self.recipes, index + 1)?;
            self.cache.hold.require_q04_returned_commit_v1(result)?;
            self.cache.recheck_owned()?;
            Ok(())
        })();
        if let Err(cause) = readback {
            self.cache.progress.postcheck.get_or_insert(cause);
        } else {
            self.native_post_complete = true;
        }
        if self.cache.progress.failure().is_some() {
            return Err(());
        }
        Ok(())
    }

    /// Completes the native marker after the actual upper Root postcheck.
    ///
    /// # Errors
    /// Refuses an unentered/failed native phase or changed same-wire Root cut.
    pub fn finish_after_root_check_v1(self) -> Result<(), ()> {
        let checked = (|| {
            if !self.entered
                || !self.readback_entered
                || !self.native_post_complete
                || self.cache.progress.failure().is_some()
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            let phase = match self.index {
                0 => Q04CacheTerminalPhaseV1::Held,
                1 => Q04CacheTerminalPhaseV1::Released,
                2 => Q04CacheTerminalPhaseV1::Cleared,
                _ => return Err(CacheQ04ErrorV1::ChangedCut),
            };
            *self.cache.original_hold = Some(Some(self.recipes.terminal_hold(phase)));
            Ok(())
        })();
        if let Err(cause) = checked {
            self.cache.progress.postcheck.get_or_insert(cause);
            return Err(());
        }
        Ok(())
    }
}

/// Borrows the same prepared native signing owner across upper-only checks.
///
/// Its private construction performs the native prefix checks first. It lends
/// no packet, Journal or signer and cannot manufacture a Root flight.
pub struct CacheQ04SigningBorrowV1<'step, 'owner, 'flight, 'profile, 'cut> {
    cache: &'step mut OriginalQ04CacheOwnerCutV1<'owner>,
    root: &'step ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut>,
}

impl<'step, 'owner, 'flight, 'profile, 'cut>
    CacheQ04SigningBorrowV1<'step, 'owner, 'flight, 'profile, 'cut>
{
    /// Prepares the physical packet before the upper Root signing check.
    ///
    /// # Errors
    /// Retains the actual physical snapshot or canonical packet failure.
    pub fn prepare_packet_once_v1(
        self,
        challenge: CacheOwnerReadbackChallengeV1,
        generation: u64,
    ) -> Result<CacheQ04UnsignedSigningBorrowV1<'step, 'owner, 'flight, 'profile, 'cut>, ()> {
        let packet = {
            let returned = (|| {
                let readback = self.cache.progress.readbacks[0]
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(CacheQ04ErrorV1::ChangedCut)?;
                let snapshot = self.cache.physical.held_snapshot()?;
                snapshot
                    .prepare_held_readback_data_v2(readback, challenge, generation)
                    .map_err(q04_readback_preparation_error_v1)
            })();
            match returned {
                Ok(packet) => packet,
                Err(cause) => {
                    self.cache.progress.signed = Some(Err(cause));
                    return Err(());
                }
            }
        };
        let preimage = aos_sandbox_protocol::cache_owner_readback::cache_owner_readback_signing_preimage_data_v2(
            &packet[..aos_sandbox_protocol::cache_owner_readback::CLOSED_CACHE_OWNER_READBACK_BODY_BYTES_V2],
        );
        Ok(CacheQ04UnsignedSigningBorrowV1 {
            cache: self.cache,
            root: self.root,
            preimage,
            packet,
        })
    }
}

/// Keeps the actual unsigned packet private across the upper signing frontier.
///
/// The preimage drops before its packet on an unsuccessful boundary, matching
/// the original signing closure. No prepared bytes or descriptor escape.
pub struct CacheQ04UnsignedSigningBorrowV1<'step, 'owner, 'flight, 'profile, 'cut> {
    cache: &'step mut OriginalQ04CacheOwnerCutV1<'owner>,
    root: &'step ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut>,
    preimage: Vec<u8>,
    packet: [u8; aos_sandbox_protocol::cache_owner_readback::CLOSED_CACHE_OWNER_READBACK_BYTES_V2],
}

impl CacheQ04UnsignedSigningBorrowV1<'_, '_, '_, '_, '_> {
    /// Signs at the upper full Root frontier with the same native loan held.
    ///
    /// # Errors
    /// Refuses an earlier retained native failure; the upper original owns the
    /// full semantic and native signing-boundary check immediately before entry.
    pub fn sign_native_once_v1(self, signer: &ed25519_dalek::SigningKey) -> Result<(), ()> {
        let Self {
            cache,
            root: _root,
            preimage,
            mut packet,
        } = self;
        cache.progress.signed = Some((|| {
            use ed25519_dalek::Signer as _;
            let signature = signer.sign(&preimage);
            drop(preimage);
            aos_sandbox_protocol::cache_owner_readback::cache_owner_readback_signature_data_v2(
                &mut packet,
                &signature,
            );
            Ok(packet)
        })());
        if cache.progress.failure().is_some() {
            return Err(());
        }
        Ok(())
    }
}

/// Holds the prepared same-writer release across the upper Root semantic check.
pub struct CacheQ04ReleaseBindingBorrowV1<'step, 'owner, 'flight, 'profile, 'cut> {
    cache: &'step mut OriginalQ04CacheOwnerCutV1<'owner>,
    root: &'step ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut>,
    recipes: &'step mut crate::journal::CacheQ04TransactionRecipesV1<'cut>,
    entered: bool,
}

impl CacheQ04ReleaseBindingBorrowV1<'_, '_, '_, '_, '_> {
    /// Binds the actual native recipe up to the second upper Root frontier.
    ///
    /// # Errors
    /// Retains reentry, native prefix, preflight or genuine Root refusal.
    pub fn bind_recipe_native_once_v1(&mut self) -> Result<(), ()> {
        if self.entered {
            self.cache
                .progress
                .first
                .get_or_insert(CacheQ04ErrorV1::ChangedCut);
            return Err(());
        }
        self.entered = true;
        if let Err(cause) = self
            .recipes
            .bind_observed_release_data_after_root_v1(self.cache.hold, self.root)
        {
            self.cache.progress.first.get_or_insert(cause);
            return Err(());
        }
        Ok(())
    }

    /// Performs outer Cache currentness only after the second upper Root check.
    ///
    /// # Errors
    /// Retains incomplete binding, prior failure or the actual native after cause.
    pub fn finish_after_root_check_v1(self) -> Result<(), ()> {
        let returned = (|| {
            if !self.entered || self.cache.progress.failure().is_some() {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            self.cache.recheck_owned()?;
            Ok(())
        })();
        if let Err(cause) = returned {
            self.cache.progress.first.get_or_insert(cause);
            return Err(());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Q04TerminalProviderStageV1 {
    Request,
    Validated,
    Opened,
}

/// Holds the exact terminal phase while the upper Root check remains borrowed.
pub struct CacheQ04TerminalBorrowV1<'step, 'owner, 'flight, 'profile, 'cut> {
    cache: &'step mut OriginalQ04CacheOwnerCutV1<'owner>,
    root: &'step ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut>,
    recipes: &'step crate::journal::CacheQ04TransactionRecipesV1<'cut>,
    phase: Q04CacheTerminalPhaseV1,
    index: usize,
    provider_stage: Q04TerminalProviderStageV1,
}

impl<'cut> CacheQ04TerminalBorrowV1<'_, '_, '_, '_, 'cut> {
    /// Reports whether the original native prefix permits the upper body check.
    #[must_use]
    pub fn body_ready_v1(&self) -> bool {
        self.cache.progress.failure().is_none()
    }

    /// Checks the fixed provider request before its first full upper Root check.
    ///
    /// # Errors
    /// Retains repeated entry, occupied destination or changed exact recipe identity.
    pub fn validate_provider_request_once_v1(&mut self) -> Result<(), ()> {
        let returned = (|| {
            if self.provider_stage != Q04TerminalProviderStageV1::Request {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            self.provider_stage = Q04TerminalProviderStageV1::Validated;
            if self.cache.progress.readbacks[self.index].is_some()
                || self.cache.progress.first.is_some()
                || self.cache.progress.postcheck.is_some()
                || !std::ptr::eq(self.root.identity(), self.recipes.identity())
            {
                return Err(CacheQ04ErrorV1::ChangedCut);
            }
            Ok(())
        })();
        if let Err(cause) = returned {
            self.cache.progress.first.get_or_insert(cause);
            return Err(());
        }
        Ok(())
    }

    /// Holds the same native provider through its remaining full Root seams.
    ///
    /// # Errors
    /// Parks native time, physical, lock or target failure without reopening.
    pub fn begin_provider_readback_once_v1<'capture>(
        &'capture mut self,
    ) -> Result<crate::CacheQ04ReadbackGuardV1<'capture, 'cut>, ()> {
        if self.provider_stage != Q04TerminalProviderStageV1::Validated {
            self.cache.progress.first.get_or_insert(CacheQ04ErrorV1::ChangedCut);
            return Err(());
        }
        self.provider_stage = Q04TerminalProviderStageV1::Opened;
        self.cache.authority.begin_borrowed_q04_terminal_readback_v1(
            self.cache.state, self.cache.hold, &self.cache.clock, self.recipes,
            self.phase, self.cache.physical,
            &mut self.cache.progress.readbacks[self.index],
            &mut self.cache.progress.first, &mut self.cache.progress.postcheck,
        )
    }

    /// Runs the independently owed outer native afters after the provider scope.
    ///
    /// # Errors
    /// Retains native name, physical and Clock after failures separately.
    pub fn finish_native_posts_v1(self) -> Result<(), ()> {
        if let Err(cause) = self.cache.recheck_owned() {
            self.cache.progress.postcheck.get_or_insert(cause);
        }
        if self.cache.progress.failure().is_some() {
            return Err(());
        }
        Ok(())
    }
}

/// Holds successful native completion before the final full upper Root check.
///
/// Only the same actual native owner constructs this borrower. Dropping it
/// never completes or releases its parent cut; the original fence stays armed.
pub struct CacheQ04FinalCompletionBorrowV1<'step, 'owner, 'flight, 'profile, 'cut> {
    cache: &'step mut OriginalQ04CacheOwnerCutV1<'owner>,
    root: &'step ControllerRootQ04FinalObservationLoanV1<'flight, 'profile, 'cut>,
}

impl CacheQ04FinalCompletionBorrowV1<'_, '_, '_, '_, '_> {
    /// Marks completion only after the upper's final whole semantic Root check.
    ///
    /// # Errors
    /// Retains changed same-flight identity, wire completion or native EOF affinity.
    pub fn complete_after_root_check_v1(self) -> Result<(), ()> {
        if let Err(cause) = self.root.require_completed_affinity_data_v1() {
            self.cache.progress.postcheck.get_or_insert(cause.into());
            self.cache
                .first_failure
                .get_or_insert(InitializationCauseV1::Q04);
            return Err(());
        }
        // The original full upper Root checks own the exact six terminal
        // observations. This final bookkeeping compares only the actual held
        // same-wire completion/EOF affinity; it adds no peer or clock sampling.
        // The Cache owner remained exclusive, and other debt stays resident.
        self.cache.progress.cleared_original_complete = true;
        *self.cache.complete = true;
        self.cache.finished = true;
        Ok(())
    }
}
