//! Original Q04 Cache owner loans and retained transition progress.
//!
//! This private child owns the original Cache/clock/physical cut, its Source
//! clearance loan, and the assembly/unwind fences. Initialization keeps the
//! same resident fields; this partition does not create an independent Cache
//! crate or detach any Root, writer, credential, or physical-owner borrow.

use super::*;

#[derive(Default)]
pub(super) struct Q04ResidentCacheProgressV1 {
    cut: Option<[u8; crate::policy_compiler::create_q04::IDENTITY_BYTES]>,
    prepare: Option<
        Result<
            super::super::Q04CachePrepareReadbackV1,
            crate::policy_compiler::create_q04::CreateQ04ErrorV1,
        >,
    >,
    prepare_coordinates: Option<[(crate::journal::ProtectedJournalNamesV1, u64); 4]>,
    readbacks: [Option<
        Result<
            super::super::CacheResidencyWriterReadbackV2,
            crate::policy_compiler::create_q04::CreateQ04ErrorV1,
        >,
    >; 3],
    commits: [Option<
        Result<crate::journal::CommitResult, crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    >; 3],
    signed: Option<
        Result<
            [u8; super::super::super::CLOSED_CACHE_OWNER_READBACK_BYTES_V2],
            crate::policy_compiler::create_q04::CreateQ04ErrorV1,
        >,
    >,
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
            self.first
                .get_or_insert(crate::policy_compiler::create_q04::CreateQ04ErrorV1::Unwind);
            self.owner_failure.get_or_insert(InitializationCauseV1::Q04);
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "linux")]
impl Q04ResidentCacheProgressV1 {
    pub(super) fn failure(&self) -> Option<&crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
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

// This non-Clone loan is created only from the actual Cache clear/readback in
// the existing initialization. Source consumes it on the same original Root
// cut; it cannot outlive or release the retained Cache/clock/physical owners.
#[cfg(target_os = "linux")]
pub(crate) struct OriginalQ04CacheClearanceLoanV1<'cache, 'owner, 'flight, 'profile, 'cut> {
    cache: &'cache mut OriginalQ04CacheOwnerCutV1<'owner>,
    recipes: &'cache crate::journal::CacheQ04TransactionRecipesV1<'cut>,
    root: &'cache crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<
        'flight,
        'profile,
        'cut,
    >,
}

#[cfg(target_os = "linux")]
impl OriginalQ04CacheClearanceLoanV1<'_, '_, '_, '_, '_> {
    pub(crate) fn recheck_at_append(
        &self,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        self.cache.require_progress(identity)?;
        if !std::ptr::eq(identity, self.recipes.identity())
            || !std::ptr::eq(identity, self.root.identity())
            || !matches!(self.cache.progress.commits[2], Some(Ok(_)))
            || !matches!(self.cache.progress.readbacks[2], Some(Ok(_)))
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.cache.recheck_borrowed_targets()?;
        self.cache
            .hold
            .readback_cache_q04_original_v1(self.recipes, 3)?;
        self.root
            .require_lower_transition(2, self.recipes.release_authorization())
    }

    // The destination belongs to the actual enclosing Source invocation.
    // No consuming helper can erase an ambiguous returned append, and no
    // postcheck replaces its first typed cause. Consuming self ends this loan,
    // not the actual retained Cache owner or its unfinished final settlement.
    pub(crate) fn capture_source_clear(
        mut self,
        source: &mut crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1,
        recipes: &crate::journal::SourceQ04TransactionRecipesV1<'_>,
        destination: &mut Option<
            Result<
                crate::journal::CommitResult,
                crate::policy_compiler::create_q04::CreateQ04ErrorV1,
            >,
        >,
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
            source
                .journal()
                .preflight_source_q04_remaining_v1(recipes, 2)
        })();
        if let Err(cause) = prepared {
            first.get_or_insert(cause);
            return Err(());
        }
        *destination = Some(source.journal().commit_source_q04_original_v1(
            recipes,
            2,
            self.root,
            Some(&self),
        ));
        if matches!(destination, Some(Err(_))) {
            match destination.take() {
                Some(Err(cause)) => {
                    *first = Some(cause);
                }
                returned => {
                    *destination = returned;
                }
            }
        }
        let readback = (|| {
            let result = destination
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            source
                .journal()
                .readback_source_q04_original_v1(recipes, 3)?;
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
    physical: &'original super::super::super::DormantCacheOwnerV1,
    physical_identity: super::super::super::effect_owner::CacheOwnerHeldIdentityV1,
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
    ) -> Result<
        [(crate::journal::ProtectedJournalNamesV1, u64); 4],
        crate::policy_compiler::create_q04::CreateQ04ErrorV1,
    > {
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

    pub(crate) fn capture_prepare_readback(&mut self, project: ProjectId) -> Result<(), ()> {
        let returned = (|| {
            if self.progress.prepare.is_some()
                || self.progress.prepare_coordinates.is_some()
                || self.progress.cut.is_some()
                || self.progress.failure().is_some()
                || self.finished
            {
                return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
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
    ) -> Result<
        &super::super::Q04CachePrepareReadbackV1,
        crate::policy_compiler::create_q04::CreateQ04ErrorV1,
    > {
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
            let original = self
                .progress
                .prepare_coordinates
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

    fn recheck_owned(
        &mut self,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.source.recheck_existing()?;
        self.recheck_borrowed_targets()
    }

    fn recheck_borrowed_targets(
        &self,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
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
                .map_err(|first| JournalError::Q04RootOriginal(Box::new(first)))?;
            Ok(())
        })?;
        self.state.require_q04_native_recipes_v1(&[])?;
        self.physical
            .require_held_identity(self.physical_identity)?;
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
            if index >= 3
                || self.progress.commits[index].is_some()
                || self.progress.commits[..index]
                    .iter()
                    .any(|prior| !matches!(prior, Some(Ok(_))))
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
        self.progress.commits[index] =
            Some(self.hold.commit_cache_q04_original_v1(recipes, index, root));
        if matches!(self.progress.commits[index], Some(Err(_))) {
            self.progress.failed_commit = Some(index);
        }
        let readback = (|| {
            let result = self.progress.commits[index]
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            self.hold
                .readback_cache_q04_original_v1(recipes, index + 1)?;
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
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            match self.progress.cut {
                None if index == 0 => {
                    self.progress.cut = Some(*root.identity().bytes());
                }
                Some(original) if &original == root.identity().bytes() => {}
                _ => return Err(CreateQ04ErrorV1::ChangedCut),
            }
            self.recheck_owned()?;
            root.recheck()?;
            self.authority.capture_borrowed_q04_terminal_readback_v1(
                self.state,
                self.hold,
                &self.clock,
                root,
                recipes,
                phase,
                self.physical,
                &mut self.progress.readbacks[index],
                &mut self.progress.first,
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
    ) -> Result<
        &super::super::CacheResidencyWriterReadbackV2,
        crate::policy_compiler::create_q04::CreateQ04ErrorV1,
    > {
        use crate::journal::Q04CacheTerminalPhaseV1;
        let index = match phase {
            Q04CacheTerminalPhaseV1::Held => 0,
            Q04CacheTerminalPhaseV1::Released => 1,
            Q04CacheTerminalPhaseV1::Cleared => 2,
        };
        if self.progress.first.is_some()
            || self.progress.postcheck.is_some()
            || self.progress.failed_commit.is_some()
        {
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
            if self.progress.signed.is_some()
                || !std::ptr::eq(root.identity(), recipes.identity())
                || !matches!(self.progress.commits[0], Some(Ok(_)))
                || self.progress.commits[1].is_some()
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            self.recheck_owned()?;
            self.hold.readback_cache_q04_original_v1(recipes, 1)?;
            self.terminal_readback(crate::journal::Q04CacheTerminalPhaseV1::Held)?
                .require_original_q04_physical_limits(self.physical.limits())?;
            credentials
                .recheck()
                .map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
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
            let readback = self.progress.readbacks[0]
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let (generation, signer) = credentials
                .cache_signer()
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let snapshot = self.physical.held_snapshot()?;
            snapshot.sign_original_q04_readback_v2(readback, challenge, generation, signer, root)
        })());

        let checked = (|| {
            credentials
                .recheck()
                .map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
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
    ) -> Result<
        &[u8; super::super::super::CLOSED_CACHE_OWNER_READBACK_BYTES_V2],
        crate::policy_compiler::create_q04::CreateQ04ErrorV1,
    > {
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
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            root.recheck()?;
            self.recheck_owned()?;
            self.hold.readback_cache_q04_original_v1(recipes, 3)?;
            let result = self.progress.commits[2]
                .as_ref()
                .and_then(|returned| returned.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            self.hold.require_q04_returned_commit_v1(result)?;
            self.terminal_readback(crate::journal::Q04CacheTerminalPhaseV1::Cleared)?
                .require_original_q04_physical_limits(self.physical.limits())?;
            if *self.original_hold
                != Some(Some(recipes.terminal_hold(
                    crate::journal::Q04CacheTerminalPhaseV1::Cleared,
                )))
            {
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
        root: &'cache crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<
            'flight,
            'profile,
            'cut,
        >,
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
        Ok(OriginalQ04CacheClearanceLoanV1 {
            cache: self,
            recipes,
            root,
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for OriginalQ04CacheOwnerCutV1<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.progress
                .first
                .get_or_insert(crate::policy_compiler::create_q04::CreateQ04ErrorV1::Unwind);
            self.first_failure.get_or_insert(InitializationCauseV1::Q04);
            // Fence before the actual protected-clock guard or any borrowed
            // caller original can drop. Logical release is not disposal.
            std::process::exit(1);
        }
    }
}

impl CacheResidentInitializationV1 {
    #[cfg(target_os = "linux")]
    pub(crate) fn begin_original_q04<'original>(
        &'original mut self,
        owner: &'original mut CacheResidencyProtectedOwnerV1,
        physical: &'original super::super::super::DormantCacheOwnerV1,
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
            if owner
                .clock
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(clock, current))
            {
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
            self.source.as_mut(),
            self.hold.as_mut(),
            owner.state_journal.as_mut(),
        ) else {
            assembly.fail(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
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
