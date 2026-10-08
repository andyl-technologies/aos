//! Existing-only fixed Cache initialization with resident partial originals.
//!
//! No missing journal, clock floor, or partition is created by this route.
//! Keeping the policy-hold writer also forbids legacy reopen-based mutation.

use super::*;
use crate::cache_residency::controller_bootstrap::open_existing_controller_cache_source;
use crate::cache_residency::{
    CacheReplayControllerBootstrapErrorV1, CacheReplayControllerBootstrapOwnerV1,
};
use crate::journal::JournalError;
#[cfg(target_os = "linux")]
use aos_sandbox_core::format::git_upload_enrollment::{
    GitCoverageCatalogV1, GitCoverageDataErrorV1, GitCoverageEnrollmentV1,
    GitCoverageBirthFieldsV1, GitCoverageBirthV1, GitCoverageFenceFieldsV1,
    GitCoverageJournalProfileV1,
};
#[cfg(target_os = "linux")]
use crate::journal::CacheGitCoverageObservationV1;
#[cfg(target_os = "linux")]
use crate::public_api_session::GitCoverageCredentialCustodyV1;

/// Classifies resident initialization failure without moving its actual cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheResidentUnavailableV1;

impl std::fmt::Display for CacheResidentUnavailableV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("existing resident Cache initialization is unavailable")
    }
}

impl std::error::Error for CacheResidentUnavailableV1 {}

#[derive(Debug, thiserror::Error)]
enum InitializationCauseV1 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Source(#[from] CacheReplayControllerBootstrapErrorV1),
    #[error(transparent)]
    Target(#[from] CacheResidencyProtectedJournalErrorV1),
    #[error("existing Cache provisioning is required")]
    ProvisioningRequired,
    #[error("resident Cache initialization is closed")]
    Closed,
    #[error("resident Cache replay failed")]
    Replay,
    #[error("resident Cache authority observation failed")]
    Evidence,
    #[error("resident Cache currentness postcheck failed")]
    TargetPostcheck,
    #[error("legacy Cache transition is unsupported under resident custody")]
    UnsupportedTransition,
    #[cfg(target_os = "linux")]
    #[error("resident Cache pin mutation is unresolved")]
    Mutation,
    #[cfg(target_os = "linux")]
    #[error("resident physical Cache capture failed")]
    PhysicalOpen,
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Physical(#[from] super::super::CacheOwnerErrorV1),
    #[cfg(target_os = "linux")]
    #[error("resident Q04 Cache continuation is unresolved")]
    Q04,
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    CoverageData(#[from] GitCoverageDataErrorV1),
    #[cfg(target_os = "linux")]
    #[error("the original fixed Git coverage inputs are unavailable")]
    CoverageInputs,
    #[cfg(target_os = "linux")]
    #[error("the original Cache cohort has unclassified or retained tenant state")]
    CoverageResidual,
    #[cfg(target_os = "linux")]
    #[error("the original Cache coverage append has unresolved custody")]
    CoverageAppend,
    #[cfg(target_os = "linux")]
    #[error("the original Git read metadata crossing has unresolved custody")]
    ReadMetadata,
}

#[cfg(target_os = "linux")]

// These comparison coordinates are derived only inside the fixed Controller
// credential recipe. They never replace the retained files or Root deployment.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
struct CacheGitCoverageInputsV1 {
    project: ProjectId,
    node: [u8; 16],
    epoch: [u8; 16],
    generation: u64,
    issued_seconds: u64,
    expires_seconds: u64,
    enrollment: [u8; 32],
    catalog: [u8; 32],
}

#[cfg(target_os = "linux")]
impl CacheGitCoverageInputsV1 {
    fn capture(
        original: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<Self, InitializationCauseV1> {
        original.recheck_controller_inputs_v1()
            .map_err(|_| InitializationCauseV1::CoverageInputs)?;
        let data = original.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
        let enrollment = GitCoverageEnrollmentV1::decode(data.enrollment())?;
        let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
        let (project_pin, deployment_pin) = data.role_pins();
        enrollment.verify_role_credentials(project_pin, deployment_pin)?;
        catalog.compare_enrollment(&enrollment)?;

        let (node, epoch) = enrollment.node_epoch();
        let (generation, issued_seconds, expires_seconds) = enrollment.generation_interval();
        Ok(Self {
            project: enrollment.project(),
            node,
            epoch,
            generation,
            issued_seconds,
            expires_seconds,
            enrollment: enrollment.digest(),
            catalog: catalog.digest(),
        })
    }

    fn require_observation(
        self,
        observation: CacheGitCoverageObservationV1,
    ) -> Result<(), InitializationCauseV1> {
        let (birth, fence, _, _) = observation.original_coordinates();
        if birth.project != self.project
            || birth.node != self.node
            || birth.epoch != self.epoch
            || birth.enrollment != self.enrollment
            || birth.catalog != self.catalog
            || fence.generation != self.generation
        {
            return Err(InitializationCauseV1::CoverageInputs);
        }
        Ok(())
    }
}

#[derive(Default)]
struct Q04ResidentCacheProgressV1 {
    cut: Option<[u8; crate::policy_compiler::create_q04::IDENTITY_BYTES]>,
    prepare: Option<Result<super::Q04CachePrepareReadbackV1, crate::policy_compiler::create_q04::CreateQ04ErrorV1>>,
    prepare_coordinates: Option<[(crate::journal::ProtectedJournalNamesV1, u64); 4]>,
    readbacks: [Option<Result<super::CacheResidencyWriterReadbackV2, crate::policy_compiler::create_q04::CreateQ04ErrorV1>>; 3],
    commits: [Option<Result<crate::journal::CommitResult, crate::policy_compiler::create_q04::CreateQ04ErrorV1>>; 3],
    signed: Option<Result<[u8; super::super::CLOSED_CACHE_OWNER_READBACK_BYTES_V2], crate::policy_compiler::create_q04::CreateQ04ErrorV1>>,
    failed_commit: Option<usize>,
    first: Option<crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    postcheck: Option<crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    started: bool,
}

// This short construction fence is created after the actual clock guard. It
// therefore ends first on unwind and cannot let that guard unfreeze a partial
// pair. Its loans end before the infallible final owner-loan assembly.
#[cfg(target_os = "linux")]
struct Q04CacheLoanAssemblyFenceV1<'slots> {
    first: &'slots mut Option<crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    owner_failure: &'slots mut Option<InitializationCauseV1>,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl Q04CacheLoanAssemblyFenceV1<'_> {
    fn fail(&mut self, cause: crate::policy_compiler::create_q04::CreateQ04ErrorV1) -> ! {
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
            self.first.get_or_insert(crate::policy_compiler::create_q04::CreateQ04ErrorV1::Unwind);
            self.owner_failure.get_or_insert(InitializationCauseV1::Q04);
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
impl Q04ResidentCacheProgressV1 {
    fn failure(&self) -> Option<&crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.first.as_ref().or_else(|| self.failed_commit
            .and_then(|index| self.commits[index].as_ref())
            .and_then(|result| result.as_ref().err()))
            .or_else(|| self.signed.as_ref().and_then(|result| result.as_ref().err()))
            .or(self.postcheck.as_ref())
    }
}

// This non-Clone loan is created only from the actual Cache clear/readback in
// the existing initialization. Source consumes it on the same original Root
// cut; it cannot outlive or release the retained Cache/clock/physical owners.
#[cfg(target_os = "linux")]
pub(crate) struct OriginalQ04CacheClearanceLoanV1<'cache, 'owner, 'flight, 'profile, 'cut> {
    cache: &'cache mut OriginalQ04CacheOwnerCutV1<'owner>,
    recipes: &'cache crate::journal::CacheQ04TransactionRecipesV1<'cut>,
    root: &'cache crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'flight, 'profile, 'cut>,
}

#[cfg(target_os = "linux")]
impl OriginalQ04CacheClearanceLoanV1<'_, '_, '_, '_, '_> {
    pub(crate) fn recheck_at_append(
        &self,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        self.cache.require_progress(identity)?;
        if !std::ptr::eq(identity, self.recipes.identity()) || !std::ptr::eq(identity, self.root.identity())
            || !matches!(self.cache.progress.commits[2], Some(Ok(_)))
            || !matches!(self.cache.progress.readbacks[2], Some(Ok(_)))
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.cache.recheck_borrowed_targets()?;
        self.cache.hold.readback_cache_q04_original_v1(self.recipes, 3)?;
        self.root.require_lower_transition(2, self.recipes.release_authorization())
    }

    // The destination belongs to the actual enclosing Source invocation.
    // No consuming helper can erase an ambiguous returned append, and no
    // postcheck replaces its first typed cause. Consuming self ends this loan,
    // not the actual retained Cache owner or its unfinished final settlement.
    pub(crate) fn capture_source_clear(
        mut self,
        source: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        recipes: &crate::journal::SourceQ04TransactionRecipesV1<'_>,
        destination: &mut Option<Result<crate::journal::CommitResult, crate::policy_compiler::create_q04::CreateQ04ErrorV1>>,
        first: &mut Option<crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
        postcheck: &mut Option<crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    ) -> Result<(), ()> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        let prepared = (|| {
            if destination.is_some() || first.is_some() || postcheck.is_some() {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            self.cache.recheck_owned()?;
            self.recheck_at_append(recipes.identity())?;
            recipes.require_named_owner(source)?;
            source.journal().preflight_source_q04_remaining_v1(recipes, 2)
        })();
        if let Err(cause) = prepared {
            first.get_or_insert(cause);
            return Err(());
        }
        *destination = Some(source.journal().commit_source_q04_original_v1(
            recipes, 2, self.root, Some(&self),
        ));
        if matches!(destination, Some(Err(_))) {
            match destination.take() {
                Some(Err(cause)) => { *first = Some(cause); }
                returned => { *destination = returned; }
            }
        }
        let readback = (|| {
            let result = destination.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            source.journal().readback_source_q04_original_v1(recipes, 3)?;
            source.journal().require_q04_returned_commit_v1(result)?;
            recipes.require_named_owner(source)?;
            self.cache.recheck_owned()?;
            self.recheck_at_append(recipes.identity())
        })();
        if let Err(cause) = readback {
            postcheck.get_or_insert(cause);
        }
        if first.is_some() || postcheck.is_some() || !matches!(destination, Some(Ok(_))) {
            return Err(());
        }
        Ok(())
    }
}

// This borrows the existing initialization/physical originals in their fixed
// order. The actual coordinator opens Root only after this guard exists. It
// exposes no Journal, FD, authority session, arbitrary callback or pin method.
#[cfg(target_os = "linux")]
pub(crate) struct OriginalQ04CacheOwnerCutV1<'original> {
    source: &'original mut CacheReplayControllerBootstrapOwnerV1,
    hold: &'original mut Journal,
    original_hold: &'original mut Option<Option<CachePolicyHoldV1>>,
    state: &'original mut Journal,
    authority: &'original Arc<ProtectedCacheResidencyReplayAuthorityV1>,
    clock: CacheClockWriterReadbackGuard<'original>,
    physical: &'original super::super::DormantCacheOwnerV1,
    physical_identity: super::super::effect_owner::CacheOwnerHeldIdentityV1,
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
    ) -> Result<[(crate::journal::ProtectedJournalNamesV1, u64); 4], crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.hold.require_q04_cache_prepare_v1()?;
        self.hold.require_q04_native_recipes_v1(&[])?;
        let targets = self.authority.q04_prepare_target_coordinates_v1(self.state, self.hold, &self.clock)?;
        Ok([
            (self.hold.protected_writer_physical_names_v1()?, self.hold.snapshot_sequence()),
            targets[0], targets[1], targets[2],
        ])
    }

    pub(crate) fn capture_prepare_readback(&mut self, project: ProjectId) -> Result<(), ()> {
        let returned = (|| {
            if self.progress.prepare.is_some() || self.progress.prepare_coordinates.is_some()
                || self.progress.cut.is_some() || self.progress.failure().is_some()
                || self.finished
            {
                return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
            }
            self.recheck_owned()?;
            let original = self.prepare_coordinates()?;
            self.authority.capture_borrowed_q04_prepare_readback_v1(
                self.state, self.hold, &self.clock, project, self.physical,
                &mut self.progress.prepare, &mut self.progress.first, &mut self.progress.postcheck,
            )?;
            if self.prepare_coordinates()? != original {
                return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
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

    pub(crate) fn prepare_readback(
        &self,
    ) -> Result<&super::Q04CachePrepareReadbackV1, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if self.progress.failure().is_some() || self.finished {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        match self.progress.prepare.as_ref() {
            Some(Ok(readback)) => Ok(readback),
            _ => Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut),
        }
    }

    // Called only before C1. These are the actual six named-writer records
    // in the signed prehold DATA packet, not a hidden currentness certificate.
    pub(crate) fn write_prepare_metadata(
        &mut self,
        metadata: &mut [u8; crate::policy_compiler::create_q04::PREHOLD_METADATA_BYTES],
    ) -> Result<(), ()> {
        let returned = (|| {
            self.prepare_readback()?;
            let original = self.progress.prepare_coordinates
                .ok_or(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut)?;
            self.recheck_owned()?;
            if self.prepare_coordinates()? != original {
                return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
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

    pub(crate) fn capture_transaction_recipes<'cut>(
        &mut self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        identity: &'cut crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> Result<crate::journal::CacheQ04TransactionRecipesV1<'cut>, ()> {
        let returned = (|| {
            self.require_progress(identity)?;
            self.recheck_owned()?;
            let readback = self.prepare_readback()?;
            if readback.quota_digest() != identity.cache_quota()
                || Some(self.prepare_coordinates()?) != self.progress.prepare_coordinates
            {
                return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
            }
            let selected = readback.selected();
            let recipes = crate::journal::CacheQ04TransactionRecipesV1::capture(
                self.hold, ledger, identity, selected,
            )?;
            self.hold.preflight_cache_q04_suffix_v1(&recipes)?;
            self.recheck_owned()?;
            Ok(recipes)
        })();
        match returned {
            Ok(recipes) => Ok(recipes),
            Err(cause) => {
                self.progress.first.get_or_insert(cause);
                self.first_failure.get_or_insert(InitializationCauseV1::Q04);
                Err(())
            }
        }
    }

    fn recheck_owned(&mut self) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.source.recheck_existing()?;
        self.recheck_borrowed_targets()
    }

    fn recheck_borrowed_targets(&self) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        require_cache_named_writer(
            self.hold, Path::new(PROTECTED_CACHE_ROOT), CACHE_POLICY_HOLD_JOURNAL,
            self.uid, Journal::cache_policy_hold_limits(),
        )?;
        require_cache_named_writer(
            self.state, Path::new(PROTECTED_CACHE_ROOT), CACHE_STATE_JOURNAL,
            self.uid, cache_state_journal_limits(),
        )?;
        self.authority.require_q04_original_cache_targets_v1(self.state, &self.clock)?;
        self.authority.check_named_location(|journal| {
            require_cache_named_writer(
                journal, Path::new(PROTECTED_CACHE_ROOT), CACHE_AUTHORITY_JOURNAL,
                self.uid, cache_authority_journal_limits(),
            )?;
            journal.require_q04_native_recipes_v1(&[])
                .map_err(|first| JournalError::Q04RootOriginal(Box::new(first)))?;
            Ok(())
        })?;
        self.state.require_q04_native_recipes_v1(&[])?;
        self.physical.require_held_identity(self.physical_identity)?;
        self.clock.revalidate()?;
        Ok(())
    }

    pub(crate) fn bind_observed_release(
        &mut self,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
        recipes: &mut crate::journal::CacheQ04TransactionRecipesV1<'_>,
    ) -> Result<(), ()> {
        let returned = (|| {
            self.require_progress(root.identity())?;
            if !matches!(self.progress.commits[0], Some(Ok(_)))
                || self.progress.commits[1].is_some()
            {
                return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
            }
            self.recheck_owned()?;
            recipes.bind_observed_release(self.hold, root)?;
            self.recheck_owned()?;
            root.recheck()
        })();
        if let Err(cause) = returned {
            self.progress.first.get_or_insert(cause);
            return Err(());
        }
        Ok(())
    }

    fn require_progress(
        &self,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if self.finished || self.progress.first.is_some() || self.progress.postcheck.is_some()
            || self.progress.failed_commit.is_some()
            || self.progress.cut.as_ref().is_some_and(|cut| cut != identity.bytes())
        {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        Ok(())
    }

    pub(crate) fn append_original_phase(
        &mut self,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
        recipes: &crate::journal::CacheQ04TransactionRecipesV1<'_>,
        index: usize,
    ) -> Result<(), ()> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        let prepared = (|| {
            self.require_progress(root.identity())?;
            if index >= 3 || self.progress.commits[index].is_some()
                || self.progress.commits[..index].iter().any(|prior| !matches!(prior, Some(Ok(_))))
                || !std::ptr::eq(root.identity(), recipes.identity())
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            self.progress.cut = Some(*root.identity().bytes());
            self.recheck_owned()?;
            root.require_lower_transition(index, recipes.release_authorization())
        })();
        if let Err(cause) = prepared {
            self.progress.first.get_or_insert(cause);
            return Err(());
        }
        self.progress.commits[index] = Some(self.hold.commit_cache_q04_original_v1(recipes, index, root));
        if matches!(self.progress.commits[index], Some(Err(_))) {
            self.progress.failed_commit = Some(index);
        }
        let readback = (|| {
            let result = self.progress.commits[index].as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            self.hold.readback_cache_q04_original_v1(recipes, index + 1)?;
            self.hold.require_q04_returned_commit_v1(result)?;
            self.recheck_owned()?;
            root.require_lower_transition(index, recipes.release_authorization())?;
            let phase = match index {
                0 => crate::journal::Q04CacheTerminalPhaseV1::Held,
                1 => crate::journal::Q04CacheTerminalPhaseV1::Released,
                _ => crate::journal::Q04CacheTerminalPhaseV1::Cleared,
            };
            // Only this exact successful original CAS/native readback can
            // advance the resident initializer's comparison. Ambiguity never
            // adopts a caller-selected or merely decoded baseline.
            *self.original_hold = Some(Some(recipes.terminal_hold(phase)));
            Ok(())
        })();
        if let Err(cause) = readback {
            self.progress.postcheck.get_or_insert(cause);
        }
        if self.progress.failed_commit.is_some() || self.progress.postcheck.is_some() {
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn capture_terminal_readback(
        &mut self,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
        recipes: &crate::journal::CacheQ04TransactionRecipesV1<'_>,
        phase: crate::journal::Q04CacheTerminalPhaseV1,
    ) -> Result<(), ()> {
        use crate::journal::Q04CacheTerminalPhaseV1;
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        let index = match phase {
            Q04CacheTerminalPhaseV1::Held => 0,
            Q04CacheTerminalPhaseV1::Released => 1,
            Q04CacheTerminalPhaseV1::Cleared => 2,
        };
        let returned = (|| {
            if self.finished || self.progress.first.is_some() || self.progress.postcheck.is_some()
                || self.progress.failed_commit.is_some()
                || self.progress.readbacks[index].is_some()
                || self.progress.readbacks[..index].iter().any(|prior| !matches!(prior, Some(Ok(_))))
                || root.identity().controller_uid() != self.uid
                || !std::ptr::eq(root.identity(), recipes.identity())
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            match self.progress.cut {
                None if index == 0 => { self.progress.cut = Some(*root.identity().bytes()); }
                Some(original) if &original == root.identity().bytes() => {}
                _ => return Err(CreateQ04ErrorV1::ChangedCut),
            }
            self.recheck_owned()?;
            root.recheck()?;
            self.authority.capture_borrowed_q04_terminal_readback_v1(
                self.state, self.hold, &self.clock, root, recipes, phase, self.physical,
                &mut self.progress.readbacks[index], &mut self.progress.first,
                &mut self.progress.postcheck,
            )
        })();
        if let Err(cause) = returned {
            self.progress.first.get_or_insert(cause);
        }
        // A failed reconstruction cannot suppress later physical/name/clock
        // debt; those errors never replace the already parked first cause.
        if let Err(cause) = self.recheck_owned() {
            self.progress.postcheck.get_or_insert(cause);
        }
        if let Err(cause) = root.recheck() {
            self.progress.postcheck.get_or_insert(cause);
        }
        if self.progress.first.is_some() || self.progress.postcheck.is_some() {
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn terminal_readback(
        &self,
        phase: crate::journal::Q04CacheTerminalPhaseV1,
    ) -> Result<&super::CacheResidencyWriterReadbackV2, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::journal::Q04CacheTerminalPhaseV1;
        let index = match phase {
            Q04CacheTerminalPhaseV1::Held => 0,
            Q04CacheTerminalPhaseV1::Released => 1,
            Q04CacheTerminalPhaseV1::Cleared => 2,
        };
        if self.progress.first.is_some() || self.progress.postcheck.is_some() || self.progress.failed_commit.is_some() {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        match self.progress.readbacks[index].as_ref() {
            Some(Ok(readback)) => Ok(readback),
            _ => Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut),
        }
    }

    pub(crate) fn capture_signed_held_readback(
        &mut self,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
        recipes: &crate::journal::CacheQ04TransactionRecipesV1<'_>,
        staged: crate::policy_compiler::StagedClosedPolicyRootBaseV2,
        proposed: &[u8],
        credentials: &mut crate::public_api_session::ControllerQ04CredentialCustodyV1,
    ) -> Result<(), ()> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        let prepared = (|| {
            self.require_progress(root.identity())?;
            if self.progress.signed.is_some() || !std::ptr::eq(root.identity(), recipes.identity())
                || !matches!(self.progress.commits[0], Some(Ok(_)))
                || self.progress.commits[1].is_some()
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            self.recheck_owned()?;
            self.hold.readback_cache_q04_original_v1(recipes, 1)?;
            self.terminal_readback(crate::journal::Q04CacheTerminalPhaseV1::Held)?
                .require_original_q04_physical_limits(self.physical.limits())?;
            credentials.recheck().map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
            root.cache_signing_challenge(staged, proposed)
        })();
        let challenge = match prepared {
            Ok(challenge) => challenge,
            Err(cause) => {
                self.progress.first.get_or_insert(cause);
                return Err(());
            }
        };

        // Both the physical snapshot and role loan borrow actual retained
        // originals. Their complete signing result is assigned before any
        // later credential, named writer, physical, clock or Root observation.
        self.progress.signed = Some((|| {
            let readback = self.progress.readbacks[0].as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let (generation, signer) = credentials.cache_signer()
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let snapshot = self.physical.held_snapshot()?;
            snapshot.sign_original_q04_readback_v2(readback, challenge, generation, signer, root)
        })());

        let checked = (|| {
            credentials.recheck().map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
            self.recheck_owned()?;
            self.hold.readback_cache_q04_original_v1(recipes, 1)?;
            root.recheck()
        })();
        if let Err(cause) = checked {
            self.progress.postcheck.get_or_insert(cause);
        }
        if self.progress.failure().is_some() {
            self.first_failure.get_or_insert(InitializationCauseV1::Q04);
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn signed_held_readback(
        &self,
    ) -> Result<&[u8; super::super::CLOSED_CACHE_OWNER_READBACK_BYTES_V2], crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if self.finished || self.progress.failure().is_some() {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        match self.progress.signed.as_ref() {
            Some(Ok(packet)) => Ok(packet),
            _ => Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut),
        }
    }

    pub(crate) fn finish_original_clearance(
        &mut self,
        recipes: &crate::journal::CacheQ04TransactionRecipesV1<'_>,
        root: &crate::policy_compiler::create_q04::OriginalQ04FinalRootObservationV1<'_, '_, '_>,
    ) -> Result<(), ()> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        let checked = (|| {
            self.require_progress(root.identity())?;
            if !std::ptr::eq(root.identity(), recipes.identity())
                || self.progress.commits.iter().any(|result| !matches!(result, Some(Ok(_))))
                || self.progress.readbacks.iter().any(|result| !matches!(result, Some(Ok(_))))
                || !matches!(self.progress.signed, Some(Ok(_)))
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            root.recheck()?;
            self.recheck_owned()?;
            self.hold.readback_cache_q04_original_v1(recipes, 3)?;
            let result = self.progress.commits[2].as_ref()
                .and_then(|returned| returned.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            self.hold.require_q04_returned_commit_v1(result)?;
            self.terminal_readback(crate::journal::Q04CacheTerminalPhaseV1::Cleared)?
                .require_original_q04_physical_limits(self.physical.limits())?;
            if *self.original_hold != Some(Some(recipes.terminal_hold(
                crate::journal::Q04CacheTerminalPhaseV1::Cleared,
            ))) {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            self.recheck_owned()?;
            root.recheck()
        })();
        if let Err(cause) = checked {
            self.progress.postcheck.get_or_insert(cause);
            self.first_failure.get_or_insert(InitializationCauseV1::Q04);
            return Err(());
        }

        // Return the already initialized originals only after their exact
        // original terminal cut. This neither grants mutation nor clears the
        // durable Q04 release history, other debt, or any physical owner.
        *self.complete = true;
        self.finished = true;
        Ok(())
    }

    pub(crate) fn clearance_loan<'cache, 'flight, 'profile, 'cut>(
        &'cache mut self,
        root: &'cache crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'flight, 'profile, 'cut>,
        recipes: &'cache crate::journal::CacheQ04TransactionRecipesV1<'cut>,
    ) -> Result<OriginalQ04CacheClearanceLoanV1<'cache, 'owner, 'flight, 'profile, 'cut>, ()> {
        let prepared = (|| {
            self.require_progress(root.identity())?;
            self.recheck_owned()?;
            self.terminal_readback(crate::journal::Q04CacheTerminalPhaseV1::Cleared)?;
            self.hold.readback_cache_q04_original_v1(recipes, 3)?;
            root.require_lower_transition(2, recipes.release_authorization())
        })();
        if let Err(cause) = prepared {
            self.progress.first.get_or_insert(cause);
            return Err(());
        }
        Ok(OriginalQ04CacheClearanceLoanV1 { cache: self, recipes, root })
    }
}

#[cfg(target_os = "linux")]
impl Drop for OriginalQ04CacheOwnerCutV1<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.progress.first.get_or_insert(crate::policy_compiler::create_q04::CreateQ04ErrorV1::Unwind);
            self.first_failure.get_or_insert(InitializationCauseV1::Q04);
            // Fence before the actual protected-clock guard or any borrowed
            // caller original can drop. Logical release is not disposal.
            std::process::exit(1);
        }
    }
}

#[derive(Default)]
struct CacheResidentTargetsV1 {
    authority_journal: Option<Journal>,
    authority_report: Option<RecoveryReport>,
    authority: Option<Arc<ProtectedCacheResidencyReplayAuthorityV1>>,
    state_journal: Option<Journal>,
    state_report: Option<RecoveryReport>,
    replay: Option<Result<CacheResidencyProtectedJournalProjectionV1, CacheResidencyProtectedJournalErrorV1>>,
    evidence: Option<Result<Vec<CacheResidencyReplayPartitionEvidenceV1>, CacheResidencyProtectedJournalErrorV1>>,
    postcheck: Option<CacheResidencyProtectedJournalErrorV1>,
}

/// Retains every returned fixed initialization original through failure.
///
/// This produces partition-local observation DATA, never a global project
/// account, operation permission, physical funding or drain evidence.
#[derive(Default)]
pub struct CacheResidentInitializationV1 {
    #[cfg(target_os = "linux")]
    coverage_inputs: Option<CacheGitCoverageInputsV1>,
    #[cfg(target_os = "linux")]
    original_coverage: Option<Option<CacheGitCoverageObservationV1>>,
    #[cfg(target_os = "linux")]
    coverage_append_started: bool,
    #[cfg(target_os = "linux")]
    coverage_account_capture_started: bool,
    #[cfg(target_os = "linux")]
    read_metadata: CacheClockReadMetadataProgressV1,
    #[cfg(target_os = "linux")]
    read_metadata_active: bool,
    #[cfg(target_os = "linux")]
    coverage_transaction: Option<JournalTransaction>,
    #[cfg(target_os = "linux")]
    coverage_commit: Option<Result<crate::journal::CommitResult, JournalError>>,
    #[cfg(target_os = "linux")]
    coverage_readback: Option<Result<CacheGitCoverageObservationV1, JournalError>>,

    source_open: Option<(Journal, RecoveryReport)>,
    source: Option<CacheReplayControllerBootstrapOwnerV1>,
    source_report: Option<RecoveryReport>,
    hold: Option<(Journal, RecoveryReport)>,
    original_hold: Option<Option<CachePolicyHoldV1>>,
    clock_open: Option<(Journal, RecoveryReport)>,
    clock: Option<Arc<ProtectedCacheClockV1>>,
    clock_report: Option<RecoveryReport>,
    targets: CacheResidentTargetsV1,
    first_failure: Option<InitializationCauseV1>,
    postcheck: Option<InitializationCauseV1>,
    started: bool,
    complete: bool,
    #[cfg(target_os = "linux")]
    physical_open: super::super::effect_owner::ResidentCachePhysicalOpenV1,
    #[cfg(target_os = "linux")]
    physical_limits: Option<CacheOwnerLimitsV1>,
    #[cfg(target_os = "linux")]
    mutations: Vec<ResidentCachePinMutationV1>,
    #[cfg(target_os = "linux")]
    pin_inventory: Option<Result<Vec<CacheRecoveryInventoryV1>, CacheResidencyProtectedJournalErrorV1>>,
    #[cfg(target_os = "linux")]
    q04: Q04ResidentCacheProgressV1,
}

impl CacheResidentInitializationV1 {
    /// Runs the fixed read crossing under this SAME original held clock.
    ///
    /// Both writers are preflighted before the first effect. Returned native
    /// causes stay in their original request or clock progress; later Source,
    /// credential, name and clock debt cannot replace them.
    ///
    /// # Errors
    /// Refuses changed originals, unsupported profiles or interrupted/failed
    /// prior work. This lends no clock, writer, effect or funding authority.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn run_existing_git_coverage_read_metadata_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &super::super::DormantCacheOwnerV1,
        source_domains: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        controller: &mut Journal,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        operation: &mut crate::reconciler::GitCoverageReadMetadataOperationV1<'_, '_>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.read_metadata_active || self.read_metadata.failure().is_some()
            || self.failure().is_some() || !self.complete
        {
            return Err(CacheResidentUnavailableV1);
        }
        self.audit_empty_git_coverage_v1(owner, physical, original_inputs)?;
        self.read_metadata_active = true;
        self.read_metadata = CacheClockReadMetadataProgressV1::default();
        // Share only the SAME allocation so the guard can stay local while
        // this owner parks disjoint action and independent observation slots.
        let clock = Arc::clone(self.clock.as_ref().ok_or(CacheResidentUnavailableV1)?);
        let mut guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };

        let returned = (|| {
            Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs)?;
            operation.compare_source(source_domains, original_inputs)
                .map_err(|_| InitializationCauseV1::ReadMetadata)?;
            let data = original_inputs.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            let sampled = match operation.prepare(controller, &catalog) {
                Ok(Some(sampled)) => sampled,
                Ok(None) => return Ok(()),
                Err(cause) => {
                    operation.refuse(cause);
                    return Err(InitializationCauseV1::ReadMetadata);
                }
            };
            let seconds = u64::try_from(sampled.wall_seconds())
                .map_err(|_| InitializationCauseV1::ReadMetadata)?;
            let inputs = self.coverage_inputs.ok_or(InitializationCauseV1::CoverageInputs)?;
            if seconds < inputs.issued_seconds || seconds >= inputs.expires_seconds {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            // Controller preparation has parked its all-eight-bound preflight.
            // Cache preparation parks its own, while the same guard stays held.
            guard.prepare_git_read_metadata(&mut self.read_metadata, seconds)
                .map_err(|_| InitializationCauseV1::ReadMetadata)?;
            operation.compare_source(source_domains, original_inputs)
                .map_err(|_| InitializationCauseV1::ReadMetadata)?;
            Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs)?;
            if let Err(cause) = operation.check_original_crossing() {
                operation.refuse(cause);
                return Err(InitializationCauseV1::ReadMetadata);
            }
            guard.commit_git_read_metadata(&mut self.read_metadata)
                .map_err(|_| InitializationCauseV1::ReadMetadata)?;
            if let Err(cause) = operation.commit_and_evaluate(controller) {
                operation.refuse(cause);
                return Err(InitializationCauseV1::ReadMetadata);
            }
            Ok::<(), InitializationCauseV1>(())
        })();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
            self.complete = false;
        }

        // Run independent observations even after a primary action failure.
        if operation.compare_source(source_domains, original_inputs).is_err() {
            self.postcheck.get_or_insert(InitializationCauseV1::ReadMetadata);
        }
        if let Err(cause) = Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs) {
            self.postcheck.get_or_insert(cause);
        }
        if let Some(source) = self.source.as_mut() {
            if let Err(cause) = source.recheck_existing() {
                self.postcheck.get_or_insert(cause.into());
            }
        }
        if let Some(hold) = self.hold.as_mut() {
            if let Err(cause) = require_original_hold(
                &mut hold.0, self.original_hold, self.coverage_inputs, self.original_coverage,
            ) {
                self.postcheck.get_or_insert(cause);
            }
        }
        let cache_names = (|| {
            let state = owner.state_journal.as_ref().ok_or(InitializationCauseV1::Closed)?;
            require_cache_named_writer(
                state, Path::new(PROTECTED_CACHE_ROOT), CACHE_STATE_JOURNAL,
                owner.owner_uid, cache_state_journal_limits(),
            )?;
            owner.authority.check_named_location(|journal| {
                require_cache_named_writer(
                    journal, Path::new(PROTECTED_CACHE_ROOT), CACHE_AUTHORITY_JOURNAL,
                    owner.owner_uid, cache_authority_journal_limits(),
                )
            })?;
            Ok::<(), InitializationCauseV1>(())
        })();
        if let Err(cause) = cache_names {
            self.postcheck.get_or_insert(cause);
        }
        if let Err(cause) = guard.current_unix_seconds().and_then(|seconds| {
            let inputs = self.coverage_inputs.ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            if seconds < inputs.issued_seconds || seconds >= inputs.expires_seconds {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            Ok(())
        }) {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if operation.postcheck().is_err() {
            self.postcheck.get_or_insert(InitializationCauseV1::ReadMetadata);
        }
        drop(guard);
        if self.first_failure.is_some() || self.postcheck.is_some() {
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        self.read_metadata_active = false;
        Ok(())
    }

    /// Captures the fixed local account cut under the SAME private clock loan.
    ///
    /// Global Source and CacheBootstrap are distinct original writers. All
    /// owning observations stay in the attempt; the private clock guard never
    /// enters policy_compiler or returns through a public getter.
    ///
    /// # Errors
    /// Refuses residual state, changed originals or any previous failure. The
    /// actual causes remain in their resident attempt/credential/Cache owners.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn capture_existing_git_coverage_account_cut_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &super::super::DormantCacheOwnerV1,
        source_domains: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        controller: &mut Journal,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        original_bootstrap: &crate::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &crate::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.coverage_account_capture_started {
            self.first_failure.get_or_insert(InitializationCauseV1::CoverageAppend);
            return Err(CacheResidentUnavailableV1);
        }
        self.coverage_account_capture_started = true;
        self.audit_empty_git_coverage_v1(owner, physical, original_inputs)?;
        self.complete = false;
        let clock = self.clock.as_ref().ok_or(CacheResidentUnavailableV1)?;
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };

        let returned = (|| {
            Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs)?;
            original_bootstrap_credentials.recheck()
                .map_err(|_| InitializationCauseV1::CoverageInputs)?;
            let inputs = original_inputs.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
            let catalog = GitCoverageCatalogV1::decode(inputs.catalog())?;
            attempt.capture_original_source_cut_v1(source_domains, original_inputs)
                .map_err(|_| InitializationCauseV1::CoverageAppend)?;
            let source = self.source.as_mut().ok_or(InitializationCauseV1::Closed)?;
            attempt.capture_cache_bootstrap_cut(source, &catalog)
                .map_err(|_| InitializationCauseV1::CoverageAppend)?;
            let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
            require_original_hold(
                &mut hold.0, self.original_hold, self.coverage_inputs, self.original_coverage,
            )?;
            attempt.park_original_cache_cuts(capture_account_cache_native_cuts(
                owner, &hold.0, clock, &guard, &catalog,
            )).map_err(|_| InitializationCauseV1::CoverageAppend)?;

            let observed_seconds = guard.current_unix_seconds()?;
            let expected = self.coverage_inputs.ok_or(InitializationCauseV1::CoverageInputs)?;
            if observed_seconds < expected.issued_seconds || observed_seconds >= expected.expires_seconds {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            let now = i64::try_from(observed_seconds)
                .map_err(|_| InitializationCauseV1::CoverageInputs)?;
            attempt.capture_controller_account_cut(
                controller, original_inputs, original_bootstrap, original_source,
                original_capacity, original_bootstrap_credentials, now,
            ).map_err(|_| InitializationCauseV1::CoverageAppend)
        })();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }

        // Parked action failures do not skip independent genuine bookends.
        // The guard stays live through all of these, so no clock reopen occurs.
        if attempt.compare_original_source_cut(source_domains, original_inputs).is_err() {
            self.postcheck.get_or_insert(InitializationCauseV1::CoverageAppend);
        }
        if let Some(source) = self.source.as_mut() {
            if let Err(cause) = source.recheck_existing() {
                self.postcheck.get_or_insert(cause.into());
            }
        }
        let local_postcheck = (|| {
            Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs)?;
            let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
            require_original_hold(
                &mut hold.0, self.original_hold, self.coverage_inputs, self.original_coverage,
            )?;
            let state = owner.state_journal.as_ref().ok_or(InitializationCauseV1::Closed)?;
            require_cache_named_writer(
                state, Path::new(PROTECTED_CACHE_ROOT), CACHE_STATE_JOURNAL,
                owner.owner_uid, cache_state_journal_limits(),
            )?;
            owner.authority.check_named_location(|journal| {
                require_cache_named_writer(
                    journal, Path::new(PROTECTED_CACHE_ROOT), CACHE_AUTHORITY_JOURNAL,
                    owner.owner_uid, cache_authority_journal_limits(),
                )
            })?;
            original_bootstrap_credentials.recheck()
                .map_err(|_| InitializationCauseV1::CoverageInputs)?;
            Ok::<(), InitializationCauseV1>(())
        })();
        if let Err(cause) = local_postcheck {
            self.postcheck.get_or_insert(cause);
        }
        if let Err(cause) = guard.current_unix_seconds().and_then(|observed_seconds| {
            let expected = self.coverage_inputs.ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            if observed_seconds < expected.issued_seconds || observed_seconds >= expected.expires_seconds {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            Ok(())
        }) {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        drop(guard);

        if self.first_failure.is_some() || self.postcheck.is_some() {
            self.complete = false;
            self.postcheck.get_or_insert(InitializationCauseV1::CoverageAppend);
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.audit_empty_git_coverage_v1(owner, physical, original_inputs)
    }

    /// Co-commits the covered successor under the original private clock loan.
    ///
    /// The SAME local capture, external-profile Root flight and original
    /// Source/Cache owners are compared again. Every action result stays in
    /// its attempt before independent bookends; failed/ambiguous work is never
    /// reset, reopened, or made ordinary by a later successful observation.
    ///
    /// # Errors
    /// Refuses missing or changed coverage, first-cause/debt, late signed
    /// inputs, changed native cuts or a failed exact-predecessor CAS/readback.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn commit_existing_git_coverage_account_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &super::super::DormantCacheOwnerV1,
        source_domains: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        controller: &mut Journal,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        original_bootstrap: &crate::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &crate::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.audit_empty_git_coverage_v1(owner, physical, original_inputs)?;
        self.complete = false;
        let clock = self.clock.as_ref().ok_or(CacheResidentUnavailableV1)?;
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };

        let returned = (|| {
            Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs)?;
            original_bootstrap_credentials.recheck()
                .map_err(|_| InitializationCauseV1::CoverageInputs)?;
            let inputs = original_inputs.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
            let catalog = GitCoverageCatalogV1::decode(inputs.catalog())?;
            attempt.compare_original_source_cut(source_domains, original_inputs)
                .map_err(|_| InitializationCauseV1::CoverageAppend)?;
            let source = self.source.as_mut().ok_or(InitializationCauseV1::Closed)?;
            attempt.compare_cache_bootstrap_cut(source, &catalog)
                .map_err(|_| InitializationCauseV1::CoverageAppend)?;
            let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
            require_original_hold(
                &mut hold.0, self.original_hold, self.coverage_inputs, self.original_coverage,
            )?;
            attempt.compare_original_cache_cuts(capture_account_cache_native_cuts(
                owner, &hold.0, clock, &guard, &catalog,
            )).map_err(|_| InitializationCauseV1::CoverageAppend)?;

            let observed_seconds = guard.current_unix_seconds()?;
            let expected = self.coverage_inputs.ok_or(InitializationCauseV1::CoverageInputs)?;
            if observed_seconds < expected.issued_seconds || observed_seconds >= expected.expires_seconds {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            let now = i64::try_from(observed_seconds)
                .map_err(|_| InitializationCauseV1::CoverageInputs)?;
            attempt.commit_controller_account(
                controller, original_inputs, original_bootstrap, original_source,
                original_capacity, original_bootstrap_credentials, now,
            ).map_err(|_| InitializationCauseV1::CoverageAppend)
        })();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }

        if attempt.compare_original_source_cut(source_domains, original_inputs).is_err() {
            self.postcheck.get_or_insert(InitializationCauseV1::CoverageAppend);
        }
        let local_postcheck = (|| {
            Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs)?;
            let inputs = original_inputs.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
            let catalog = GitCoverageCatalogV1::decode(inputs.catalog())?;
            let source = self.source.as_mut().ok_or(InitializationCauseV1::Closed)?;
            attempt.compare_cache_bootstrap_cut(source, &catalog)
                .map_err(|_| InitializationCauseV1::CoverageAppend)?;
            let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
            require_original_hold(
                &mut hold.0, self.original_hold, self.coverage_inputs, self.original_coverage,
            )?;
            attempt.compare_original_cache_cuts(capture_account_cache_native_cuts(
                owner, &hold.0, clock, &guard, &catalog,
            )).map_err(|_| InitializationCauseV1::CoverageAppend)?;
            original_bootstrap_credentials.recheck()
                .map_err(|_| InitializationCauseV1::CoverageInputs)?;
            let observed_seconds = guard.current_unix_seconds()?;
            let expected = self.coverage_inputs.ok_or(InitializationCauseV1::CoverageInputs)?;
            if observed_seconds < expected.issued_seconds || observed_seconds >= expected.expires_seconds {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            Ok::<(), InitializationCauseV1>(())
        })();
        if let Err(cause) = local_postcheck {
            self.postcheck.get_or_insert(cause);
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        drop(guard);

        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.audit_empty_git_coverage_v1(owner, physical, original_inputs)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn begin_original_q04<'original>(
        &'original mut self,
        owner: &'original mut CacheResidencyProtectedOwnerV1,
        physical: &'original super::super::DormantCacheOwnerV1,
    ) -> Result<OriginalQ04CacheOwnerCutV1<'original>, CacheResidentUnavailableV1> {
        self.recheck(owner)?;
        if self.q04.started {
            return Err(CacheResidentUnavailableV1);
        }
        self.q04.started = true;
        self.complete = false;
        let Some(clock) = self.clock.as_ref() else {
            self.q04.first = Some(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
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
            if owner.clock.as_ref().is_none_or(|current| !Arc::ptr_eq(clock, current)) {
                return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
            }
            let snapshot = physical.held_snapshot()?;
            if snapshot.owner_uid() != owner.owner_uid
                || self.physical_limits != Some(physical.limits())
            {
                return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
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
            self.source.as_mut(), self.hold.as_mut(), owner.state_journal.as_mut(),
        ) else {
            assembly.fail(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        };
        assembly.finish();
        Ok(OriginalQ04CacheOwnerCutV1 {
            source, hold: &mut hold.0, original_hold: &mut self.original_hold, state,
            authority: &owner.authority, clock: guard, physical, physical_identity,
            uid: owner.owner_uid, progress: &mut self.q04, complete: &mut self.complete,
            first_failure: &mut self.first_failure,
            finished: false,
        })
    }

    /// Creates only an empty destination, before any fixed open or observation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reports whether the selected fixed attempt has begun, including failure.
    #[must_use]
    pub const fn started(&self) -> bool {
        self.started
    }

    /// Borrows complete current partition DATA under the original clock and hold.
    ///
    /// The result grants neither pin authority nor a physical effect. Every
    /// partition, including release tombstones, remains available to selection.
    ///
    /// # Errors
    /// Retains replay failures and refuses changed or incomplete originals.
    #[cfg(target_os = "linux")]
    pub fn existing_pin_inventories(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
    ) -> Result<&[CacheRecoveryInventoryV1], CacheResidentUnavailableV1> {
        self.recheck(owner)?;
        self.complete = false;
        let clock = self.clock.as_ref().ok_or(CacheResidentUnavailableV1)?;
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let hold = self.hold.as_mut().ok_or(CacheResidentUnavailableV1)?;
        let state = owner.state_journal.as_mut().ok_or(CacheResidentUnavailableV1)?;
        let returned = owner.authority.with_borrowed_mutable_authority_v1(
            state, &mut hold.0, &guard,
            |session, state| session.while_current_records(&[], |_, _, _, validator, refresh| {
                self.pin_inventory = Some((|| {
                    let projection = CacheResidencyProtectedJournalV1::claim(state, validator.clone())?.replay()?;
                    reconstruct_cache_history(projection.records(), &validator)
                })());
                refresh()?;
                Ok(())
            }),
        );
        if let Err(cause) = returned {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        drop(guard);
        if !matches!(self.pin_inventory.as_ref(), Some(Ok(_))) || self.postcheck.is_some() {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.recheck(owner)?;
        match self.pin_inventory.as_ref() {
            Some(Ok(inventories)) => Ok(inventories),
            _ => Err(CacheResidentUnavailableV1),
        }
    }

    /// Reconciles the original acquisition without selecting another partition.
    ///
    /// Returns `false` only for canonical state-only history; `true` requires
    /// actual protected-event and physical-manifest agreement.
    ///
    /// # Errors
    /// Retains the complete cold and physical results on ambiguity or failure.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_existing_public_pin(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        consumer: &crate::production_operation_compiler::RecheckedCacheConsumerV1,
        operation: OperationId,
        transaction_id: [u8; 16],
        source_journal: &Journal,
        request: &aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1,
    ) -> Result<bool, CacheResidentUnavailableV1> {
        if consumer.acquisition_fence().is_none() {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            progress.reconcile(session, state, transaction_id, consumer, operation, None, source_journal, request, physical)
        })?;
        Ok(self.mutations.last().is_some_and(|progress| !progress.cold_state_only()))
    }

    /// Reconciles one exact retained release tombstone under the same cut.
    ///
    /// # Errors
    /// Refuses foreign consumers, absent tombstones, state-only history or an
    /// unresolved physical release. Other partitions remain independent debt.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_existing_public_unpin(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        consumer: &crate::production_operation_compiler::RecheckedCacheConsumerV1,
        pin: &super::super::CachePinV1,
        operation: OperationId,
        transaction_id: [u8; 16],
        source_journal: &Journal,
        request: &aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let inventories = self.existing_pin_inventories(owner)?;
        let retained = inventories.iter().flat_map(|inventory| &inventory.reconstructed)
            .flat_map(|payload| &payload.released_pins)
            .any(|tombstone| &tombstone.pin == pin);
        if consumer.acquisition_fence().is_some() || !retained
            || !pin_lookup::logical_pin_matches_consumer(pin, pin.partition, consumer.object(), consumer.project(), consumer.view(), consumer.attachment())
        {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            progress.reconcile(session, state, transaction_id, consumer, operation, Some(pin), source_journal, request, physical)
        })?;
        if self.mutations.last().is_none_or(ResidentCachePinMutationV1::cold_state_only) {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    /// Captures only a healthy, provisioned physical owner under these originals.
    ///
    /// All seven limits are derived from the complete protected partition set.
    /// Changed limits fence the existing owner; this route never drops or
    /// reopens it, initializes a missing manifest, or performs orphan recovery.
    ///
    /// # Errors
    /// Keeps returned fixed descriptors and the first typed capture failure.
    #[cfg(target_os = "linux")]
    pub fn prepare_existing_physical_owner(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        destination: &mut Option<super::super::DormantCacheOwnerV1>,
        node: aos_sandbox_core::NodeId,
        maximum_memory_bytes: u64,
    ) -> Result<(), CacheResidentUnavailableV1> {
        // Derive quotas from the complete selected inventory already retained
        // under the original clock/gate recipe, not another legacy full query.
        self.existing_pin_inventories(owner)?;
        self.complete = false;
        let Some(clock) = self.clock.as_ref() else {
            self.first_failure.get_or_insert(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        };
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let returned = (|| {
            let quotas = match self.pin_inventory.as_ref() {
                Some(Ok(inventories)) => inventories
                    .iter()
                    .map(|inventory| inventory.global.node_quota)
                    .collect::<Vec<_>>(),
                _ => return Err(InitializationCauseV1::Mutation),
            };
            if quotas.iter().any(|quota| quota.partition.node().as_bytes() != node.as_bytes()) {
                return Err(InitializationCauseV1::Physical(super::super::CacheOwnerErrorV1::InvalidLimits));
            }
            let limits = CacheOwnerLimitsV1::from_node_quotas(maximum_memory_bytes, quotas)?;
            if let Some(physical) = destination.as_ref() {
                if self.physical_limits != Some(limits) || physical.limits() != limits {
                    return Err(InitializationCauseV1::Physical(super::super::CacheOwnerErrorV1::InvalidLimits));
                }
                physical.held_snapshot()?;
                return Ok(());
            }
            if self.physical_limits.is_some() {
                return Err(InitializationCauseV1::Closed);
            }
            self.physical_limits = Some(limits);
            if self.physical_open.open_once(destination, limits).is_err() {
                return Err(InitializationCauseV1::PhysicalOpen);
            }
            Ok(())
        })();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        drop(guard);
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.recheck(owner)
    }

    /// Pins one genuinely validated logical consumer without reopening writers.
    ///
    /// The actual acquisition proof, signed-source compiler inputs and current
    /// Controller request remain borrowed from the installed caller. Complete
    /// protected and physical results stay resident through final bookends.
    ///
    /// # Errors
    /// Permanently refuses changed originals, failed issuance, ambiguous
    /// protected append or incomplete physical settlement; no error is Drain.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn pin_existing_logical_consumer(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        acquisition: &super::super::ValidatedPublicLogicalPinAcquisitionV1<'_, '_, '_, '_>,
        operation: OperationId,
        transaction_id: [u8; 16],
        source_journal: &crate::Journal,
        request: &aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            CacheResidencyProtectedOwnerV1::pin_existing_under_cut(
                session, state, progress, acquisition, operation, transaction_id,
                source_journal, request, physical,
            )
        })
    }

    /// Releases one exact retained pin; the caller must select every partition.
    ///
    /// # Errors
    /// Keeps unresolved protected and physical results instead of permission to
    /// retry, release other pins or report consumer-wide completion.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn unpin_existing_logical_consumer(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        consumer: &crate::production_operation_compiler::RecheckedCacheConsumerV1,
        pin: &super::super::CachePinV1,
        operation: OperationId,
        transaction_id: [u8; 16],
        source_journal: &crate::Journal,
        request: &aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.with_pin_mutation(owner, physical, operation, |session, state, progress, physical| {
            CacheResidencyProtectedOwnerV1::unpin_existing_under_cut(
                session, state, progress, consumer, pin, operation, transaction_id,
                source_journal, request, physical,
            )
        })
    }

    #[cfg(target_os = "linux")]
    fn with_pin_mutation(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        operation: OperationId,
        action: impl for<'session, 'claim, 'journal, 'gate, 'clock> FnOnce(
            &mut super::super::protected_journal::RetainedCacheAuthoritySessionV1<'claim, 'journal, 'gate, 'clock>,
            &mut Journal,
            &mut ResidentCachePinMutationV1,
            &mut super::super::DormantCacheOwnerV1,
        ) -> Result<(), CacheResidencyProtectedJournalErrorV1>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.recheck(owner)?;
        if self.original_coverage.is_some_and(|observed| observed.is_some()) {
            // The first profile requires empty-owner audit before fencing;
            // this readback alone does not establish it. No pin action creates a new
            // protected or physical step after a read-only bookend succeeds.
            self.complete = false;
            self.first_failure.get_or_insert(InitializationCauseV1::UnsupportedTransition);
            return Err(CacheResidentUnavailableV1);
        }
        if self.mutations.iter().any(|progress| progress.operation != Some(operation) || !progress.complete) {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = false;
        let maximum = owner.state_journal.as_ref()
            .ok_or(CacheResidentUnavailableV1)?.configured_limits().maximum_materialized_bytes;
        let retained = self.mutations.iter().try_fold(0_usize, |bytes, progress| {
            bytes.checked_add(progress.retained_payload_bytes())
        });
        let Some(headroom) = retained.and_then(|bytes| maximum.checked_sub(bytes)) else {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        };
        for progress in &mut self.mutations {
            progress.release_completed_inventory();
        }
        self.mutations.push(ResidentCachePinMutationV1::for_operation(operation));
        let progress = self.mutations.last_mut().ok_or(CacheResidentUnavailableV1)?;
        progress.set_payload_headroom(headroom);
        let clock = self.clock.as_ref().ok_or(CacheResidentUnavailableV1)?;
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let returned = (|| {
            if owner.clock.as_ref().is_none_or(|current| !Arc::ptr_eq(clock, current)) {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            let hold = self.hold.as_mut().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let state = owner.state_journal.as_mut().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            owner.authority.with_borrowed_mutable_authority_v1(
                state, &mut hold.0, &guard,
                |session, state| {
                    let result = action(session, state, progress, physical);
                    if let Err(cause) = result {
                        progress.first_failure.get_or_insert(cause);
                        return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
                    }
                    Ok(())
                },
            )
        })();
        if let Err(cause) = returned {
            progress.postcheck.get_or_insert(cause);
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = physical.held_snapshot() {
            self.postcheck.get_or_insert(cause.into());
        }
        drop(guard);
        if self.first_failure.is_some() || self.postcheck.is_some() || !progress.complete {
            self.first_failure.get_or_insert(InitializationCauseV1::Mutation);
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.recheck(owner)?;
        if let Err(cause) = physical.finish_resident_pin_step() {
            self.complete = false;
            self.postcheck.get_or_insert(cause.into());
            return Err(CacheResidentUnavailableV1);
        }
        self.recheck(owner)
    }

    /// Releases completed operation DATA only after the same owners recheck.
    ///
    /// # Errors
    /// Refuses another operation, any unresolved leg or any changed original.
    #[cfg(target_os = "linux")]
    pub fn finish_existing_pin_operation(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &mut super::super::DormantCacheOwnerV1,
        operation: OperationId,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.recheck(owner)?;
        if self.mutations.iter().any(|progress| progress.operation != Some(operation) || !progress.complete) {
            return Err(CacheResidentUnavailableV1);
        }
        if let Err(cause) = physical.finish_resident_pin_operation() {
            self.postcheck.get_or_insert(cause.into());
            self.complete = false;
            return Err(CacheResidentUnavailableV1);
        }
        self.recheck(owner)?;

        // Both archives survive every fallible bookend. Only completed DATA
        // is released here; the original writers, clock and physical owner stay.
        physical.release_completed_resident_pin_data();
        self.mutations.clear();
        Ok(())
    }

    /// Initializes the exact existing source and Cache owners once.
    ///
    /// The configured service UID follows the existing fixed-owner contract.
    /// No caller path, journal, evidence, clock or factory is accepted.
    ///
    /// # Errors
    /// Permanently refuses failed reuse, occupied destinations, missing or
    /// malformed provisioning, changed originals, or incomplete reconciliation.
    pub fn initialize_once(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        owner_uid: u32,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.started {
            return Err(CacheResidentUnavailableV1);
        }
        self.started = true;
        // `complete` remains false on every early return and unwind.
        if destination.is_some() {
            self.first_failure = Some(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        }
        self.initialize_after_prearm(destination, owner_uid)
    }

    /// Initializes the same existing owners for fixed exclusive-cohort readback.
    ///
    /// The original credential owner remains with the installed caller. This
    /// operation checks its fixed Controller role and complete signed carriers;
    /// it grants neither enrollment, allocation nor a complete account. A
    /// persisted fence must match those original carriers exactly.
    ///
    /// # Errors
    /// Retains all returned Cache originals and permanently refuses changed
    /// inputs, failed reuse, missing provisioning or unresolved owner checks.
    #[cfg(target_os = "linux")]
    pub fn initialize_git_coverage_once(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        owner_uid: u32,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.started {
            return Err(CacheResidentUnavailableV1);
        }
        self.started = true;
        if destination.is_some() {
            self.first_failure = Some(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        }
        match CacheGitCoverageInputsV1::capture(original_inputs) {
            Ok(inputs) => self.coverage_inputs = Some(inputs),
            Err(cause) => {
                self.first_failure = Some(cause);
                return Err(CacheResidentUnavailableV1);
            }
        }

        let returned = self.initialize_after_prearm(destination, owner_uid)
            .and_then(|()| match destination.as_mut() {
                Some(owner) => self.compare_fixed_git_coverage_catalog(owner, original_inputs),
                None => {
                    self.complete = false;
                    self.first_failure.get_or_insert(InitializationCauseV1::Closed);
                    Err(CacheResidentUnavailableV1)
                }
            });
        if let Err(cause) = Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs) {
            self.complete = false;
            self.postcheck.get_or_insert(cause);
        }
        returned?;
        if self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    // Both wrappers prearm their own disposition before this original engine.
    // Ordinary capture and its old effect/error/drop order remain unchanged.
    fn initialize_after_prearm(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        owner_uid: u32,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if let Err(cause) = self.capture_before_clock(owner_uid) {
            self.first_failure = Some(cause);
            return Err(CacheResidentUnavailableV1);
        }
        let Some(clock) = self.clock.as_ref() else {
            self.first_failure = Some(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        };
        let held_clock = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure = Some(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let returned = (|| {
            #[cfg(target_os = "linux")]
            if let Some(inputs) = self.coverage_inputs {
                self.source.as_mut().ok_or(InitializationCauseV1::Closed)?
                    .recheck_existing()?;
                let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
                require_original_hold(
                    &mut hold.0, self.original_hold,
                    self.coverage_inputs, self.original_coverage,
                )?;
                let now = held_clock.current_unix_seconds()?;
                if now < inputs.issued_seconds || now >= inputs.expires_seconds {
                    return Err(InitializationCauseV1::CoverageInputs);
                }
            }
            self.targets.capture_existing(
                destination, clock, self.source.as_mut(), owner_uid,
            )
        })();
        // Park the action's first cause before any final clock or source check.
        if let Err(cause) = returned {
            self.first_failure = Some(cause);
        }
        if let Err(cause) = held_clock.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Some(source) = self.source.as_mut() {
            if let Err(cause) = source.recheck_existing() {
                self.postcheck.get_or_insert(cause.into());
            }
        }
        if let Some((hold, _report)) = self.hold.as_mut() {
            if let Err(cause) = require_original_hold(
                hold, self.original_hold,
                #[cfg(target_os = "linux")]
                self.coverage_inputs,
                #[cfg(target_os = "linux")]
                self.original_coverage,
            ) {
                self.postcheck.get_or_insert(cause);
            }
        }
        if self.first_failure.is_some()
            || self.postcheck.is_some()
            || self.targets.postcheck.is_some()
        {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        Ok(())
    }

    fn capture_before_clock(&mut self, owner_uid: u32) -> Result<(), InitializationCauseV1> {
        self.source_open = Some(open_existing_controller_cache_source(owner_uid)?);
        self.source_report = self.source_open.as_ref().map(|(_journal, report)| *report);
        CacheReplayControllerBootstrapOwnerV1::capture_existing(
            &mut self.source_open, &mut self.source, owner_uid,
        )?;
        reject_legacy_cache_journals()?;
        let root = Path::new(PROTECTED_CACHE_ROOT);
        self.hold = Some(open_cache_journal_file(
            root, CACHE_POLICY_HOLD_JOURNAL, Journal::cache_policy_hold_limits(),
            owner_uid, CacheOpenProfileV1::ExistingOnly,
        )?);
        let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
        #[cfg(target_os = "linux")]
        if let Some(inputs) = self.coverage_inputs {
            let observed = hold.0.cache_git_coverage_observation_for_writer_v1()?;
            if let Some(observation) = observed {
                inputs.require_observation(observation)?;
            }
            self.original_coverage = Some(observed);
        } else {
            self.original_hold = Some(hold.0.cache_policy_hold_for_writer()?);
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.original_hold = Some(hold.0.cache_policy_hold_for_writer()?);
        }

        self.clock_open = Some(open_cache_journal_file(
            root, CACHE_CLOCK_JOURNAL, cache_clock_journal_limits(),
            owner_uid, CacheOpenProfileV1::ExistingOnly,
        )?);
        let opened = self.clock_open.as_mut().ok_or(InitializationCauseV1::Closed)?;
        let retained = read_cache_clock_floor(&mut opened.0)?;
        #[cfg(target_os = "linux")]
        if self.coverage_inputs.is_some() {
            self.source.as_mut().ok_or(InitializationCauseV1::Closed)?
                .recheck_existing()?;
            let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
            require_original_hold(
                &mut hold.0, self.original_hold,
                self.coverage_inputs, self.original_coverage,
            )?;
        }
        let sampled = sample_wall_clock()?;
        let floor = match retained {
            Some(floor) if floor.owner_scope == cache_owner_scope()
                && floor.observed_unix_seconds <= sampled =>
            {
                floor
            }
            Some(_) => return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into()),
            None => return Err(InitializationCauseV1::ProvisioningRequired),
        };
        let Some((journal, report)) = self.clock_open.take() else {
            return Err(InitializationCauseV1::Closed);
        };
        self.clock_report = Some(report);
        // Same original Journal, parked before any time authority is called.
        self.clock = Some(Arc::new(ProtectedCacheClockV1::from_validated_floor(
            journal, root, cache_owner_scope(), owner_uid, floor,
        )));
        Ok(())
    }

    /// Rechecks all retained fixed originals without reopening their writers.
    ///
    /// # Errors
    /// Permanently refuses changed source, hold, clock, state or authority names.
    pub fn recheck(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if !self.complete || self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = false;
        let Some(clock) = self.clock.as_ref() else {
            self.first_failure = Some(InitializationCauseV1::Closed);
            return Err(CacheResidentUnavailableV1);
        };
        let held_clock = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure = Some(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };
        let returned = (|| {
            let owner_clock = owner.clock.as_ref().ok_or(InitializationCauseV1::Closed)?;
            if !Arc::ptr_eq(clock, owner_clock) {
                return Err(InitializationCauseV1::Closed);
            }
            #[cfg(target_os = "linux")]
            if self.coverage_inputs.is_some() {
                // Selected callbacks cannot sample through a changed Source
                // or exclusive writer; the ordinary check order stays below.
                self.source.as_mut().ok_or(InitializationCauseV1::Closed)?
                    .recheck_existing()?;
                let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
                require_original_hold(
                    &mut hold.0, self.original_hold,
                    self.coverage_inputs, self.original_coverage,
                )?;
            }
            let observed_seconds = held_clock.current_unix_seconds()?;
            #[cfg(target_os = "linux")]
            if let Some(inputs) = self.coverage_inputs {
                if observed_seconds < inputs.issued_seconds
                    || observed_seconds >= inputs.expires_seconds
                {
                    return Err(InitializationCauseV1::CoverageInputs);
                }
            }
            #[cfg(not(target_os = "linux"))]
            let _ = observed_seconds;
            self.source.as_mut().ok_or(InitializationCauseV1::Closed)?.recheck_existing()?;
            let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
            require_original_hold(
                &mut hold.0, self.original_hold,
                #[cfg(target_os = "linux")]
                self.coverage_inputs,
                #[cfg(target_os = "linux")]
                self.original_coverage,
            )?;
            let state = owner.state_journal.as_ref().ok_or(InitializationCauseV1::Closed)?;
            require_cache_named_writer(state, Path::new(PROTECTED_CACHE_ROOT), CACHE_STATE_JOURNAL,
                owner.owner_uid, cache_state_journal_limits())?;
            owner.authority.check_named_location(|journal| {
                require_cache_named_writer(journal, Path::new(PROTECTED_CACHE_ROOT),
                    CACHE_AUTHORITY_JOURNAL, owner.owner_uid, cache_authority_journal_limits())
            })?;
            Ok::<(), InitializationCauseV1>(())
        })();
        if let Err(cause) = returned {
            self.first_failure = Some(cause);
        }
        if let Err(cause) = held_clock.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        Ok(())
    }

    /// Bookends the selected component with the same actual credential owner.
    ///
    /// # Errors
    /// Permanently retains credential-change or original-owner failure; the
    /// returned success is component readback DATA, never admission authority.
    #[cfg(target_os = "linux")]
    pub fn recheck_git_coverage(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if let Err(cause) = Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs) {
            self.complete = false;
            self.first_failure.get_or_insert(cause);
            return Err(CacheResidentUnavailableV1);
        }
        let returned = self.compare_fixed_git_coverage_catalog(owner, original_inputs)
            .and_then(|()| self.recheck(owner));
        if let Err(cause) = Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs) {
            self.complete = false;
            self.postcheck.get_or_insert(cause);
        }
        returned?;
        if self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        Ok(())
    }

    /// Bookends Cache Read with the original completed global Source cut.
    ///
    /// A later worker Read carries the SAME locally completed account attempt.
    /// `None` selects only the initial pre-capture recipe, never a fallback.
    ///
    /// # Errors
    /// Retains changed original Source or Cache causes and permanently refuses
    /// missing, failed or noncompleted account custody after capture started.
    #[cfg(target_os = "linux")]
    #[doc(hidden)]
    pub fn bookend_existing_git_coverage_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        source_domains: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        original_account: Option<&mut crate::policy_compiler::GitCoverageAccountAttemptV1<'_>>,
    ) -> Result<(), CacheResidentUnavailableV1> {
        let source_checked = match original_account {
            Some(attempt) if self.coverage_account_capture_started => {
                attempt.compare_completed_original_source_cut(source_domains, original_inputs)
            }
            None if !self.coverage_account_capture_started => Ok(()),
            _ => Err(()),
        };
        // Core has already parked the actual source cause. Even that error
        // receives the independent Cache/hold/name/clock/credential bookend.
        let cache_checked = self.recheck_git_coverage(owner, original_inputs);
        if source_checked.is_err() {
            self.first_failure.get_or_insert(InitializationCauseV1::CoverageAppend);
            self.complete = false;
        }
        source_checked.map_err(|_| CacheResidentUnavailableV1)?;
        cache_checked
    }

    /// Compares the genuinely empty logical and physical Cache cohort.
    ///
    /// The complete existing replay supplies every partition, including
    /// checkpoint-only state. Signed catalog bytes alone, absent projects and
    /// absent current keys never prove emptiness. This result is comparison
    /// DATA, not enrollment, a complete account, funding or an effect permit.
    ///
    /// # Errors
    /// Permanently retains changed originals, unknown or historical tenant
    /// state, disjoint quotas, physical debt or failed independent bookends.
    #[cfg(target_os = "linux")]
    pub fn audit_empty_git_coverage_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &super::super::DormantCacheOwnerV1,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        self.recheck_git_coverage(owner, original_inputs)?;
        let project = match self.coverage_inputs {
            Some(inputs) => inputs.project,
            None => {
                self.complete = false;
                self.first_failure.get_or_insert(InitializationCauseV1::CoverageInputs);
                return Err(CacheResidentUnavailableV1);
            }
        };
        let inventories = self.existing_pin_inventories(owner)?;
        let residual = inventories.is_empty() || inventories.iter().any(|inventory| {
            inventory.authority_poisoned
                || !inventory.work.is_empty()
                || !inventory.reconstructed.is_empty()
                || !inventory.family_heads.is_empty()
                || !inventory.global.watermarks.is_empty()
                || !inventory.global.idempotency.is_empty()
                || inventory.global.pin_floor.is_some()
                || inventory.global.idempotency_floor.is_some()
                || !inventory.global.handoffs.is_empty()
                || !inventory.global.lookups.is_empty()
                || inventory.global.poison.is_some()
                || inventory.global.project_quotas.len() != 1
                || inventory.global.project_quotas.iter().any(|quota| {
                    quota.project != project
                        || quota.partition != inventory.global.node_quota.partition
                })
        });
        self.complete = false;

        let returned = (|| {
            if residual {
                return Err(InitializationCauseV1::CoverageResidual);
            }
            let evidence = self.targets.evidence.as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(InitializationCauseV1::Evidence)?;
            let inventories = self.pin_inventory.as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(InitializationCauseV1::Mutation)?;
            if inventories.len() != evidence.len() {
                return Err(InitializationCauseV1::CoverageResidual);
            }
            for item in evidence {
                if item.prior_typed_checkpoint.is_some() {
                    return Err(InitializationCauseV1::CoverageResidual);
                }
                validate_genesis_checkpoint(
                    item.partition, &item.typed_checkpoint, item.floor,
                    CacheRecoveryLimitsV1::default(),
                )?;
                if inventories.iter().filter(|inventory| {
                    inventory.global.node_quota.partition == item.partition
                }).count() != 1
                {
                    return Err(InitializationCauseV1::CoverageResidual);
                }
            }

            let data = original_inputs.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            let snapshot = physical.compare_empty_git_coverage_catalog_v1(&catalog, evidence)?;
            if snapshot.owner_uid() != owner.owner_uid {
                return Err(InitializationCauseV1::CoverageResidual);
            }
            snapshot.revalidate()?;
            Ok::<(), InitializationCauseV1>(())
        })();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }

        // Keep the owning census result before independent original-name and
        // credential checks. No later success clears an earlier failure.
        if let Err(cause) = physical.held_snapshot() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Some(source) = self.source.as_mut() {
            if let Err(cause) = source.recheck_existing() {
                self.postcheck.get_or_insert(cause.into());
            }
        }
        if let Some((hold, _)) = self.hold.as_mut() {
            if let Err(cause) = require_original_hold(
                hold, self.original_hold, self.coverage_inputs, self.original_coverage,
            ) {
                self.postcheck.get_or_insert(cause);
            }
        }
        if let Err(cause) = Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs) {
            self.postcheck.get_or_insert(cause);
        }
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        self.recheck_git_coverage(owner, original_inputs)
    }

    /// Persists the original permanent denial fence for the audited Cache cohort.
    ///
    /// The nonce is only the original enrollment-flight correlation DATA.
    /// Actual fixed signed inputs and every same-owner census/bookend remain
    /// required. This creates no allocation, account, remote receipt or Drain.
    /// Cancellation, an error or a later expired input never permits retry.
    ///
    /// # Errors
    /// Retains the actual transaction, commit Result and native readback on
    /// failed reuse, nonempty owners, bounds/CAS failure or ambiguous custody.
    #[cfg(target_os = "linux")]
    pub fn enroll_empty_git_coverage_once_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &super::super::DormantCacheOwnerV1,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
        original_prepare_nonce: [u8; 16],
    ) -> Result<(), CacheResidentUnavailableV1> {
        if self.coverage_append_started {
            return Err(CacheResidentUnavailableV1);
        }
        self.coverage_append_started = true;
        self.audit_empty_git_coverage_v1(owner, physical, original_inputs)?;
        self.complete = false;

        let clock = match self.clock.as_ref() {
            Some(clock) => clock,
            None => {
                self.first_failure.get_or_insert(InitializationCauseV1::Closed);
                return Err(CacheResidentUnavailableV1);
            }
        };
        let held_clock = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };

        let returned = (|| {
            if original_prepare_nonce == [0; 16]
                || self.original_coverage != Some(None)
                || self.coverage_transaction.is_some()
            {
                return Err(InitializationCauseV1::CoverageAppend);
            }
            let inputs = self.coverage_inputs.ok_or(InitializationCauseV1::CoverageInputs)?;
            self.source.as_mut().ok_or(InitializationCauseV1::Closed)?
                .recheck_existing()?;
            let hold = self.hold.as_mut().ok_or(InitializationCauseV1::Closed)?;
            require_original_hold(
                &mut hold.0, self.original_hold, self.coverage_inputs, self.original_coverage,
            )?;
            let observed_seconds = held_clock.current_unix_seconds()?;
            if observed_seconds < inputs.issued_seconds || observed_seconds >= inputs.expires_seconds {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            let native = hold.0.cache_coverage_native_prefix_v1()
                .map_err(|cause| JournalError::GitCoverageNativeHistory(Box::new(cause)))?;
            let predecessor_prefix = native.prefix_digest();
            let provision_origin = native.provision_origin_digest();
            let data = original_inputs.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
            let enrollment = GitCoverageEnrollmentV1::decode(data.enrollment())?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            let birth = enrollment.fixed_owner_birth_recipe_v1(
                &catalog, GitCoverageJournalProfileV1::CachePolicyHold, original_prepare_nonce,
            )?;
            if birth.predecessor_prefix != predecessor_prefix
                || birth.provision_origin != provision_origin
                || hold.0.snapshot_sequence().checked_add(3) != Some(birth.commit_sequence)
            {
                return Err(InitializationCauseV1::CoverageAppend);
            }
            drop(native);
            let transaction = birth.transaction;
            let birth_bytes = birth.encode()?;
            let fence = GitCoverageFenceFieldsV1 {
                owner: birth.owner,
                project: inputs.project,
                node: inputs.node,
                epoch: inputs.epoch,
                generation: inputs.generation,
                enrollment: inputs.enrollment,
                birth: GitCoverageBirthV1::decode(&birth_bytes)?.digest(),
                catalog: inputs.catalog,
                transaction,
                predecessor_prefix,
                prepare_nonce: original_prepare_nonce,
            };
            self.coverage_transaction = Some(
                hold.0.prepare_cache_git_coverage_append_v1(birth, fence)?,
            );
            let transaction = self.coverage_transaction.as_ref()
                .ok_or(InitializationCauseV1::CoverageAppend)?;
            hold.0.preflight_transactions(std::slice::from_ref(transaction))?;

            // Encoding and native preflight do not renew the original signed
            // interval. Check the same owners immediately before the append.
            self.source.as_mut().ok_or(InitializationCauseV1::Closed)?
                .recheck_existing()?;
            require_original_hold(
                &mut hold.0, self.original_hold, self.coverage_inputs, self.original_coverage,
            )?;
            if CacheGitCoverageInputsV1::capture(original_inputs)? != inputs {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            let observed_seconds = held_clock.current_unix_seconds()?;
            if observed_seconds < inputs.issued_seconds || observed_seconds >= inputs.expires_seconds {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            self.coverage_commit = Some(hold.0.commit(transaction));
            let commit = match self.coverage_commit.as_ref() {
                Some(Ok(commit)) => *commit,
                _ => return Err(InitializationCauseV1::CoverageAppend),
            };
            self.coverage_readback = Some(
                hold.0.cache_git_coverage_observation_for_writer_v1()
                    .and_then(|observed| observed.ok_or(JournalError::ProtectedBoundary)),
            );
            let observed = match self.coverage_readback.as_ref() {
                Some(Ok(observed)) => *observed,
                _ => return Err(InitializationCauseV1::CoverageAppend),
            };
            let (actual_birth, actual_fence, _, sequence) = observed.original_coordinates();
            if actual_birth != birth || actual_fence != fence || sequence != commit.commit_sequence {
                return Err(InitializationCauseV1::CoverageAppend);
            }
            // Advance only to the exact successful durable successor. The
            // final bookends can still fail permanently, retaining this DATA
            // and every owning result rather than rebasing or erasing debt.
            self.original_coverage = Some(Some(observed));
            Ok::<(), InitializationCauseV1>(())
        })();
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }

        if let Err(cause) = held_clock.current_unix_seconds().and_then(|observed_seconds| {
            let inputs = self.coverage_inputs
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            if observed_seconds < inputs.issued_seconds || observed_seconds >= inputs.expires_seconds {
                return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
            }
            Ok(())
        }) {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = held_clock.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Err(cause) = physical.held_snapshot() {
            self.postcheck.get_or_insert(cause.into());
        }
        if let Some(source) = self.source.as_mut() {
            if let Err(cause) = source.recheck_existing() {
                self.postcheck.get_or_insert(cause.into());
            }
        }
        if let Some((hold, _)) = self.hold.as_mut() {
            if let Err(cause) = require_original_hold(
                hold, self.original_hold, self.coverage_inputs, self.original_coverage,
            ) {
                self.postcheck.get_or_insert(cause);
            }
        }
        if let Err(cause) = Self::require_same_coverage_inputs(self.coverage_inputs, original_inputs) {
            self.postcheck.get_or_insert(cause);
        }
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        drop(held_clock);
        self.complete = true;
        self.recheck_git_coverage(owner, original_inputs)
    }

    /// Observes the current enrolled Cache coordinates under every original owner.
    ///
    /// This repeats the actual empty-cohort census and fixed-input bookends.
    /// The returned coordinates are DATA, not a held cross-owner loan or
    /// permission to allocate. A consumer must independently bookend its
    /// intervening work through these same retained owners.
    ///
    /// # Errors
    /// Permanently refuses incomplete enrollment, unknown residual state,
    /// changed originals, prior append ambiguity or expired signed inputs.
    #[cfg(target_os = "linux")]
    pub fn current_git_coverage_coordinates_v1(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        physical: &super::super::DormantCacheOwnerV1,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(
        GitCoverageBirthFieldsV1,
        GitCoverageFenceFieldsV1,
        [u8; 32],
        u64,
    ), CacheResidentUnavailableV1> {
        self.audit_empty_git_coverage_v1(owner, physical, original_inputs)?;
        match self.original_coverage {
            Some(Some(observation)) => Ok(observation.original_coordinates()),
            _ => {
                self.complete = false;
                self.first_failure.get_or_insert(InitializationCauseV1::CoverageAppend);
                Err(CacheResidentUnavailableV1)
            }
        }
    }

    // The signed catalog is borrowed from the same fixed credential owner;
    // neither an arbitrary catalog nor an externally prepared success is an
    // input. Actual partition state and physical census remain separate checks.
    #[cfg(target_os = "linux")]
    fn compare_fixed_git_coverage_catalog(
        &mut self,
        owner: &mut CacheResidencyProtectedOwnerV1,
        original_inputs: &GitCoverageCredentialCustodyV1,
    ) -> Result<(), CacheResidentUnavailableV1> {
        if !self.complete || self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = false;

        let clock = match self.clock.as_ref() {
            Some(clock) => clock,
            None => {
                self.first_failure.get_or_insert(InitializationCauseV1::Closed);
                return Err(CacheResidentUnavailableV1);
            }
        };
        let guard = match clock.hold_writer_for_readback() {
            Ok(guard) => guard,
            Err(cause) => {
                self.first_failure.get_or_insert(cause.into());
                return Err(CacheResidentUnavailableV1);
            }
        };

        let returned = (|| {
            let data = original_inputs.ready().ok_or(InitializationCauseV1::CoverageInputs)?;
            let catalog = GitCoverageCatalogV1::decode(data.catalog())?;
            let source = self.source.as_mut().ok_or(InitializationCauseV1::Closed)?;
            source.compare_git_coverage_catalog_v1(&catalog)?;
            let evidence = self.targets.evidence.as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(InitializationCauseV1::Evidence)?;
            let partitions = source.partitions().count();
            if partitions == 0 || evidence.len() != partitions {
                return Err(InitializationCauseV1::CoverageInputs);
            }
            for profile in [
                GitCoverageJournalProfileV1::CacheAuthority,
                GitCoverageJournalProfileV1::CacheState,
                GitCoverageJournalProfileV1::CachePhysical,
            ] {
                if catalog.members().filter(|member| member.profile() == profile).count() != partitions {
                    return Err(InitializationCauseV1::CoverageInputs);
                }
                for partition in source.partitions() {
                    catalog.fixed_member(profile, *partition.as_bytes())?;
                    if !evidence.iter().any(|item| item.partition.digest() == partition) {
                        return Err(InitializationCauseV1::CoverageInputs);
                    }
                }
            }

            let state_journal = owner.state_journal.as_ref().ok_or(InitializationCauseV1::Closed)?;
            require_cache_named_writer(
                state_journal, Path::new(PROTECTED_CACHE_ROOT), CACHE_STATE_JOURNAL,
                owner.owner_uid, cache_state_journal_limits(),
            )?;
            let mut state_prefix = state_journal.cache_state_coverage_native_prefix_v1(&catalog)
                .map_err(|cause| JournalError::GitCoverageNativeHistory(Box::new(cause)))?;
            state_prefix.recheck()?;

            owner.authority.check_named_location(|journal| {
                require_cache_named_writer(
                    journal, Path::new(PROTECTED_CACHE_ROOT), CACHE_AUTHORITY_JOURNAL,
                    owner.owner_uid, cache_authority_journal_limits(),
                )?;
                for (namespace, key, _value) in journal.all_records() {
                    if namespace != RecordNamespace::DesiredState
                        || !evidence.iter().any(|item| {
                            key == item.record_key.as_slice()
                                || key.strip_prefix(CACHE_MANIFEST_KEY_PREFIX)
                                    == Some(item.partition.digest().as_bytes().as_slice())
                        })
                    {
                        return Err(JournalError::ProtectedBoundary);
                    }
                }
                for row in catalog.infrastructure() {
                    let attributed = evidence.iter().any(|item| {
                        catalog.fixed_member(
                            GitCoverageJournalProfileV1::CacheAuthority,
                            *item.partition.digest().as_bytes(),
                        ).is_ok_and(|member| {
                            row.attribution() == member.digest()
                                && (row.key() == item.record_key.as_slice()
                                    || row.key().strip_prefix(CACHE_MANIFEST_KEY_PREFIX)
                                        == Some(item.partition.digest().as_bytes().as_slice()))
                        })
                    });
                    if catalog.members().any(|member| {
                        member.profile() == GitCoverageJournalProfileV1::CacheAuthority
                            && member.digest() == row.attribution()
                    }) && !attributed
                    {
                        return Err(JournalError::ProtectedBoundary);
                    }
                }
                let mut prefix = journal.cache_authority_coverage_native_prefix_v1(&catalog)
                    .map_err(|cause| JournalError::GitCoverageNativeHistory(Box::new(cause)))?;
                prefix.recheck()
            })?;

            let hold = self.hold.as_ref().ok_or(InitializationCauseV1::Closed)?;
            let mut hold_prefix = hold.0.cache_hold_coverage_native_prefix_v1(&catalog)
                .map_err(|cause| JournalError::GitCoverageNativeHistory(Box::new(cause)))?;
            hold_prefix.recheck()?;

            let state = clock.state.lock()
                .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
            if !state.readback_held {
                return Err(InitializationCauseV1::Closed);
            }
            let journal = state.journal.as_ref().ok_or(InitializationCauseV1::Closed)?;
            clock.check_named_journal(journal)?;
            journal.validate_protected_writer_name_witness(&guard.witness)?;
            let encoded_floor = encode_cache_clock_floor(state.floor);
            let mut current = journal.all_records();
            let Some((namespace, key, value)) = current.next() else {
                return Err(InitializationCauseV1::Closed);
            };
            if namespace != RecordNamespace::DesiredState
                || key != CACHE_CLOCK_KEY
                || value != encoded_floor.as_slice()
                || current.next().is_some()
            {
                return Err(InitializationCauseV1::Closed);
            }
            let mut clock_prefix = journal.cache_clock_coverage_native_prefix_v1(&catalog)
                .map_err(|cause| JournalError::GitCoverageNativeHistory(Box::new(cause)))?;
            clock_prefix.recheck()?;
            Ok::<(), InitializationCauseV1>(())
        })();

        // Returned native errors are owned before the independent clock
        // bookend. Rejected comparison or unwind cannot reopen this attempt.
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }
        if let Err(cause) = guard.revalidate() {
            self.postcheck.get_or_insert(cause.into());
        }
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(CacheResidentUnavailableV1);
        }
        self.complete = true;
        Ok(())
    }

    // Use only comparison coordinates, leaving the same clock guard live
    // while callers mutate disjoint resident fields and park observations.
    #[cfg(target_os = "linux")]
    fn require_same_coverage_inputs(
        coverage_inputs: Option<CacheGitCoverageInputsV1>,
        original_inputs: &mut GitCoverageCredentialCustodyV1,
    ) -> Result<(), InitializationCauseV1> {
        if coverage_inputs != Some(CacheGitCoverageInputsV1::capture(original_inputs)?) {
            return Err(InitializationCauseV1::CoverageInputs);
        }
        Ok(())
    }

    /// Terminally fences a legacy transition that would reopen retained writers.
    pub fn fence_unsupported_transition(&mut self) {
        self.complete = false;
        self.first_failure.get_or_insert(InitializationCauseV1::UnsupportedTransition);
    }

    /// Borrows the first genuine failure; separate postcheck debt stays resident.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause = self.first_failure.as_ref().or(self.postcheck.as_ref());
        match cause {
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::ReadMetadata) => self.read_metadata.failure()
                .or_else(|| cause.map(|cause| cause as &(dyn std::error::Error + 'static))),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::Q04) => self.q04.failure()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::CoverageAppend) => self.coverage_commit.as_ref()
                .and_then(|result| result.as_ref().err())
                .or_else(|| self.coverage_readback.as_ref().and_then(|result| result.as_ref().err()))
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| cause.map(|cause| cause as &(dyn std::error::Error + 'static))),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::Mutation) => self.pin_inventory.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| self.mutations.iter().find_map(|progress| progress.failure()))
                .or_else(|| self.first_failure.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))),
            #[cfg(target_os = "linux")]
            Some(InitializationCauseV1::PhysicalOpen) => self.physical_open.failure()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(InitializationCauseV1::Replay) => self.targets.replay.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(InitializationCauseV1::Evidence) => self.targets.evidence.as_ref()?.as_ref().err()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(InitializationCauseV1::TargetPostcheck) => self.targets.postcheck.as_ref()
                .map(|cause| cause as &(dyn std::error::Error + 'static)),
            Some(cause) => Some(cause),
            None => self.targets.postcheck.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static)),
        }
    }
}

fn require_original_hold(
    hold: &mut Journal,
    original_hold: Option<Option<CachePolicyHoldV1>>,
    #[cfg(target_os = "linux")] coverage_inputs: Option<CacheGitCoverageInputsV1>,
    #[cfg(target_os = "linux")] original_coverage: Option<Option<CacheGitCoverageObservationV1>>,
) -> Result<(), InitializationCauseV1> {
    #[cfg(target_os = "linux")]
    if let Some(inputs) = coverage_inputs {
        let current = hold.cache_git_coverage_observation_for_writer_v1()?;
        if let Some(observation) = current {
            inputs.require_observation(observation)?;
        }
        if Some(current) != original_coverage {
            return Err(InitializationCauseV1::Closed);
        }
        return Ok(());
    }

    if Some(hold.cache_policy_hold_for_writer()?) != original_hold {
        return Err(InitializationCauseV1::Closed);
    }
    Ok(())
}

impl CacheResidentTargetsV1 {
    fn capture_existing(
        &mut self,
        destination: &mut Option<CacheResidencyProtectedOwnerV1>,
        clock: &Arc<ProtectedCacheClockV1>,
        source: Option<&mut CacheReplayControllerBootstrapOwnerV1>,
        owner_uid: u32,
    ) -> Result<(), InitializationCauseV1> {
        let source = source.ok_or(InitializationCauseV1::Closed)?;
        let root = Path::new(PROTECTED_CACHE_ROOT);
        let (journal, report) = open_cache_journal_file(
            root, CACHE_AUTHORITY_JOURNAL, cache_authority_journal_limits(),
            owner_uid, CacheOpenProfileV1::ExistingOnly,
        )?;
        self.authority_journal = Some(journal);
        self.authority_report = Some(report);
        let journal = self.authority_journal.as_mut().ok_or(InitializationCauseV1::Closed)?;
        enable_cache_journal_gate(journal, root, CACHE_AUTHORITY_JOURNAL, owner_uid)?;
        let evidence = recover_cache_replay_evidence(
            journal, cache_owner_scope(), CacheRecoveryLimitsV1::default(),
        )?;
        let current_time: Arc<dyn CacheResidencyCurrentTimeAuthorityV1> = clock.clone();
        ProtectedCacheResidencyReplayAuthorityV1::capture_existing(
            &mut self.authority_journal, &mut self.authority, cache_owner_scope(),
            MAXIMUM_AUTHORITY_RECORD_BYTES, evidence, CacheRecoveryLimitsV1::default(), current_time,
        )?;
        let (journal, report) = open_cache_journal_file(
            root, CACHE_STATE_JOURNAL, cache_state_journal_limits(),
            owner_uid, CacheOpenProfileV1::ExistingOnly,
        )?;
        self.state_journal = Some(journal);
        self.state_report = Some(report);
        enable_cache_journal_gate(
            self.state_journal.as_mut().ok_or(InitializationCauseV1::Closed)?,
            root, CACHE_STATE_JOURNAL, owner_uid,
        )?;
        let Some(state_journal) = self.state_journal.take() else {
            return Err(InitializationCauseV1::Closed);
        };
        let Some(authority) = self.authority.take() else {
            return Err(InitializationCauseV1::Closed);
        };
        *destination = Some(CacheResidencyProtectedOwnerV1 {
            state_journal: Some(state_journal),
            authority,
            clock: Some(clock.clone()),
            owner_uid,
            project_usage: project_usage::CacheProjectUsageProgressV1::default(),
        });
        let target = destination.as_mut().ok_or(InitializationCauseV1::Closed)?;
        let state = target.state_journal.as_mut().ok_or(InitializationCauseV1::Closed)?;
        target.authority.while_authority_current_resident(
            &mut self.replay, &mut self.postcheck,
            |_owner, _now, validator| CacheResidencyProtectedJournalV1::claim(state, validator)?.replay(),
        );
        if !matches!(self.replay, Some(Ok(_))) {
            return Err(InitializationCauseV1::Replay);
        }
        if self.postcheck.is_some() {
            return Err(InitializationCauseV1::TargetPostcheck);
        }
        target.authority.capture_current_replay_partition_evidence(&mut self.evidence, &mut self.postcheck);
        let existing = self.evidence.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(InitializationCauseV1::Evidence)?;
        if self.postcheck.is_some() {
            return Err(InitializationCauseV1::TargetPostcheck);
        }
        if !source.reconcile_existing_replayed_partitions(target, existing)? {
            return Err(InitializationCauseV1::ProvisioningRequired);
        }
        Ok(())
    }
}

// These four DATA observations are returned only under the initializer's
// original held clock. There is no public writer getter or callback crossing.
// The containing attempt parks the whole Result before independent bookends.
#[cfg(target_os = "linux")]
fn capture_account_cache_native_cuts(
    owner: &CacheResidencyProtectedOwnerV1,
    hold: &Journal,
    clock: &ProtectedCacheClockV1,
    guard: &CacheClockWriterReadbackGuard<'_>,
    catalog: &GitCoverageCatalogV1<'_>,
) -> Result<Vec<crate::policy_compiler::GitCoverageNativeCutDataV1>, CacheResidencyProtectedJournalErrorV1> {
    use crate::policy_compiler::GitCoverageNativeCutDataV1;

    let state = owner.state_journal.as_ref()
        .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
    require_cache_named_writer(
        state, Path::new(PROTECTED_CACHE_ROOT), CACHE_STATE_JOURNAL,
        owner.owner_uid, cache_state_journal_limits(),
    )?;
    let mut cuts = Vec::with_capacity(4);
    owner.authority.check_named_location(|journal| {
        require_cache_named_writer(
            journal, Path::new(PROTECTED_CACHE_ROOT), CACHE_AUTHORITY_JOURNAL,
            owner.owner_uid, cache_authority_journal_limits(),
        )?;
        let mut native = journal.cache_authority_coverage_native_prefix_v1(catalog)
            .map_err(|cause| JournalError::GitCoverageNativeHistory(Box::new(cause)))?;
        native.recheck()?;
        cuts.push(GitCoverageNativeCutDataV1::from_original_loan(
            GitCoverageJournalProfileV1::CacheAuthority, &native,
        ));
        Ok(())
    })?;
    let mut native = state.cache_state_coverage_native_prefix_v1(catalog)
        .map_err(|cause| JournalError::GitCoverageNativeHistory(Box::new(cause)))?;
    native.recheck()?;
    cuts.push(GitCoverageNativeCutDataV1::from_original_loan(
        GitCoverageJournalProfileV1::CacheState, &native,
    ));
    drop(native);

    let mut native = hold.cache_hold_coverage_native_prefix_v1(catalog)
        .map_err(|cause| JournalError::GitCoverageNativeHistory(Box::new(cause)))?;
    native.recheck()?;
    cuts.push(GitCoverageNativeCutDataV1::from_original_loan(
        GitCoverageJournalProfileV1::CachePolicyHold, &native,
    ));
    drop(native);

    let held_clock = clock.state.lock()
        .map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
    if !held_clock.readback_held {
        return Err(ProtectedDomainJournalErrorV1::StaleAuthority.into());
    }
    let journal = held_clock.journal.as_ref()
        .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
    clock.check_named_journal(journal)?;
    journal.validate_protected_writer_name_witness(&guard.witness)?;
    let mut native = journal.cache_clock_coverage_native_prefix_v1(catalog)
        .map_err(|cause| JournalError::GitCoverageNativeHistory(Box::new(cause)))?;
    native.recheck()?;
    cuts.push(GitCoverageNativeCutDataV1::from_original_loan(
        GitCoverageJournalProfileV1::CacheClock, &native,
    ));
    Ok(cuts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_destination_has_no_owner_or_completed_observation() {
        let attempt = CacheResidentInitializationV1::new();

        assert!(!attempt.started());
        assert!(!attempt.complete);
        assert!(attempt.source.is_none());
        assert!(attempt.hold.is_none());
        assert!(attempt.clock.is_none());
        assert!(attempt.failure().is_none());
    }

    #[test]
    fn prearmed_failure_refuses_reuse_without_an_open() {
        let mut attempt = CacheResidentInitializationV1::new();
        attempt.started = true;
        attempt.first_failure = Some(InitializationCauseV1::Closed);
        let mut destination = None;

        let returned = attempt.initialize_once(&mut destination, 0);

        assert_eq!(returned, Err(CacheResidentUnavailableV1));
        assert!(destination.is_none());
        assert!(attempt.source_open.is_none());
        assert!(matches!(attempt.first_failure, Some(InitializationCauseV1::Closed)));
    }

    #[test]
    fn unsupported_transition_keeps_the_first_original_cause() {
        let mut attempt = CacheResidentInitializationV1::new();
        attempt.started = true;
        attempt.first_failure = Some(InitializationCauseV1::ProvisioningRequired);

        attempt.fence_unsupported_transition();

        assert!(!attempt.complete);
        assert!(matches!(attempt.first_failure, Some(InitializationCauseV1::ProvisioningRequired)));
    }

    #[test]
    fn classified_failure_does_not_format_original_paths_or_causes() {
        assert_eq!(CacheResidentUnavailableV1.to_string(),
            "existing resident Cache initialization is unavailable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inventory_failure_survives_an_independent_postcheck_debt() {
        let mut attempt = CacheResidentInitializationV1::new();
        attempt.pin_inventory = Some(Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord));
        attempt.first_failure = Some(InitializationCauseV1::Mutation);
        attempt.postcheck = Some(InitializationCauseV1::Closed);

        let cause = attempt.failure().unwrap();

        assert_eq!(cause.to_string(), ProtectedDomainJournalErrorV1::NonCanonicalRecord.to_string());
        assert!(attempt.postcheck.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unfinished_operation_is_not_a_completed_empty_destination() {
        let mut attempt = CacheResidentInitializationV1::new();
        let operation = OperationId::from_bytes([92; 16]);
        attempt.mutations.push(ResidentCachePinMutationV1::for_operation(operation));

        assert!(!attempt.mutations[0].complete);
        assert_eq!(attempt.mutations[0].operation, Some(operation));
        assert!(!attempt.complete);
    }
}
