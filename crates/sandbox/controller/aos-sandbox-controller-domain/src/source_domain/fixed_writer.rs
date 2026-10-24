//! Retains the live fixed Source writer, paid construction and original Q04 loan.
//!
//! Protected opens and append/readback methods use the original Native Journal.
//! The paid constructor parks primary and independent postcheck causes, while
//! Q04 retains actual returned commits and terminates on unfinished custody.
//! No field or construction scope grants new policy or effect authority.

use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;

use std::path::Path;

#[cfg(target_os = "linux")]
use aos_sandbox_model::ProjectId;

#[cfg(target_os = "linux")]
use aos_sandbox_cache::CacheV8SettledClearV1;
use crate::journal::{
    Journal,
    JournalError,
    JournalLimits,
    RecoveryReport,
};
#[cfg(target_os = "linux")]
use aos_sandbox_broker::root_settlement::RootV8SettledGrantV1;

use super::{
    PROTECTED_SOURCE_DOMAIN_JOURNAL, PROTECTED_SOURCE_DOMAIN_ROOT, source_domain_journal_limits,
};

/// Owns the fixed protected journal shared by the Source domain families.
///
/// Its journal is private and can enter Environment, Git, lifecycle, hierarchy,
/// or cross-domain claim only through crate-controlled adapters.
pub struct ProtectedSourceDomainJournalOwnerV1 {
    journal: Journal,
}

/// Retains the actual fixed Source construction through the same pre-Bank loan.
#[cfg(target_os = "linux")]
pub struct ControllerSourceJournalConstructionV1 {
    original: crate::journal::SourceJournalConstructionOriginalsV1,
    source: Option<ProtectedSourceDomainJournalOwnerV1>,
    finished: bool,
}

#[cfg(target_os = "linux")]
impl ControllerSourceJournalConstructionV1 {
    /// Creates empty partial custody without entering the fixed Source interval.
    pub const fn new() -> Self {
        Self { original: crate::journal::SourceJournalConstructionOriginalsV1::new(), source: None, finished: false }
    }

    /// Opens the same fixed Source writer under the genuine pre-Bank loan.
    ///
    /// # Errors
    /// Retains native acquisition and complete semantic replay failure.
    pub fn open_once(
        &mut self,
        loan: &mut aos_sandbox_broker::controller_receiving::ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Result<(), ()> {
        self.open_with_recipe_once(loan, false)
    }

    /// Opens existing fixed Source state under the same genuine C loan.
    ///
    /// Missing journals and interrupted tails refuse; no genesis or repair is
    /// inferred from this administrative invocation.
    ///
    /// # Errors
    /// Retains the same first acquisition/semantic cause and owed native posts.
    pub fn open_existing_once(
        &mut self,
        loan: &mut aos_sandbox_broker::controller_receiving::ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Result<(), ()> {
        self.open_with_recipe_once(loan, true)
    }

    fn open_with_recipe_once(
        &mut self,
        loan: &mut aos_sandbox_broker::controller_receiving::ControllerSourcePreBankConstructionLoanV1<'_>,
        existing_only: bool,
    ) -> Result<(), ()> {
        if existing_only { self.original.open_existing_once(loan)?; }
        else { self.original.open_once(loan)?; }
        let journal = self.original.take_for_recovery_once().ok_or(())?;
        self.source = Some(ProtectedSourceDomainJournalOwnerV1 { journal });
        Ok(())
    }

    /// Borrows the same actual writer for existing lifecycle/project recovery.
    pub fn source_mut(&mut self) -> Option<&mut ProtectedSourceDomainJournalOwnerV1> {
        if self.primary_failure().is_some() { None } else { self.source.as_mut() }
    }

    /// Performs the actual names and independently armed Source/C posts.
    ///
    /// # Errors
    /// Retains every post failure and refuses a missing or repeated construction.
    pub fn finish_posts(
        &mut self,
        loan: &mut aos_sandbox_broker::controller_receiving::ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Result<(), ()> {
        if self.finished { return Err(()); }
        self.finished = true;
        let result = self.original.finish_posts(self.source.as_ref().map(|source| &source.journal), loan);
        if result.is_err() || self.source.is_none() { Err(()) } else { Ok(()) }
    }

    /// Moves the original fixed owner only after its successful actual posts.
    pub fn take_source(&mut self) -> Option<ProtectedSourceDomainJournalOwnerV1> {
        if !self.finished || self.failure().is_some() { None } else { self.source.take() }
    }

    /// Borrows the actual first construction or post failure.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.primary_failure().or_else(|| self.postcheck_debt())
    }

    /// Borrows the actual primary native/semantic failure.
    pub fn primary_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.primary_failure()
    }

    /// Borrows later name/profile debt without changing primary chronology.
    pub fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.postcheck_debt()
    }

    /// Resolves a selected loan marker to its actual retained native cause.
    pub fn primary_failure_with_loan<'cause>(
        &'cause self,
        loan: &'cause aos_sandbox_broker::controller_receiving::ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        self.original.primary_failure_with_loan(loan)
    }

    /// Preserves names-before-profile chronology through the still-held loan.
    pub fn postcheck_debt_with_loan<'cause>(
        &'cause self,
        loan: &'cause aos_sandbox_broker::controller_receiving::ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        self.original.postcheck_debt_with_loan(loan)
    }
}

// The actual installed Q04 caller borrows this SAME Source owner before Root
// is opened. This private negative guard exposes only fixed Q04 actions and
// comparison DATA, never a Journal/FD or an authority constructor.
#[cfg(target_os = "linux")]
pub(crate) struct OriginalQ04SourceOwnerCutV1<'source> {
    source: &'source mut ProtectedSourceDomainJournalOwnerV1,
    cut: Option<[u8; crate::policy_compiler::create_q04::IDENTITY_BYTES]>,
    commits: [Option<
        Result<crate::journal::CommitResult, crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    >; 3],
    first: Option<crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    postcheck: Option<crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    finished: bool,
}

#[cfg(target_os = "linux")]
impl<'source> OriginalQ04SourceOwnerCutV1<'source> {
    pub(crate) fn park(source: &'source mut ProtectedSourceDomainJournalOwnerV1) -> Self {
        Self {
            source,
            cut: None,
            commits: [None, None, None],
            first: None,
            postcheck: None,
            finished: false,
        }
    }

    pub(crate) fn capture_recipes<'cut>(
        &mut self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        identity: &'cut crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> Result<crate::journal::SourceQ04TransactionRecipesV1<'cut>, ()> {
        let returned =
            crate::journal::SourceQ04TransactionRecipesV1::capture(self.source, ledger, identity);
        match returned {
            Ok(recipes)
                if self.first.is_none() && self.postcheck.is_none() && self.cut.is_none() =>
            {
                self.cut = Some(*identity.bytes());
                Ok(recipes)
            }
            Ok(_) => {
                self.first.get_or_insert(
                    crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut,
                );
                Err(())
            }
            Err(cause) => {
                self.first.get_or_insert(cause);
                Err(())
            }
        }
    }

    pub(crate) fn preflight_original_suffix(
        &mut self,
        recipes: &crate::journal::SourceQ04TransactionRecipesV1<'_>,
    ) -> Result<(), ()> {
        let returned = (|| {
            self.require_cut(recipes.identity())?;
            recipes.require_named_owner(self.source)?;
            self.source.journal.preflight_source_q04_suffix_v1(recipes)
        })();
        self.park_failure(returned)
    }

    pub(crate) fn bind_observed_release(
        &mut self,
        recipes: &mut crate::journal::SourceQ04TransactionRecipesV1<'_>,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
    ) -> Result<(), ()> {
        let returned = (|| {
            self.require_cut(recipes.identity())?;
            if !matches!(self.commits[0], Some(Ok(_))) || self.commits[1].is_some() {
                return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
            }
            recipes.bind_observed_release(self.source, root)
        })();
        self.park_failure(returned)
    }

    pub(crate) fn append_original_phase(
        &mut self,
        recipes: &crate::journal::SourceQ04TransactionRecipesV1<'_>,
        index: usize,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
    ) -> Result<(), ()> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        let prepared = (|| {
            self.require_cut(recipes.identity())?;
            if index >= 2
                || self.commits[index].is_some()
                || self.commits[..index]
                    .iter()
                    .any(|prior| !matches!(prior, Some(Ok(_))))
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            recipes.require_named_owner(self.source)?;
            root.require_lower_transition(index, recipes.release_authorization())
        })();
        self.park_failure(prepared)?;
        self.commits[index] = Some(
            self.source
                .journal
                .commit_source_q04_original_v1(recipes, index, root, None),
        );
        if matches!(self.commits[index], Some(Err(_))) {
            match self.commits[index].take() {
                Some(Err(cause)) => {
                    self.first = Some(cause);
                }
                returned => {
                    self.commits[index] = returned;
                }
            }
        }
        let readback = (|| {
            let result = self.commits[index]
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            self.source
                .journal
                .readback_source_q04_original_v1(recipes, index + 1)?;
            self.source.journal.require_q04_returned_commit_v1(result)?;
            recipes.require_named_owner(self.source)?;
            root.require_lower_transition(index, recipes.release_authorization())
        })();
        if let Err(cause) = readback {
            self.postcheck.get_or_insert(cause);
        }
        if self.first.is_some() || self.postcheck.is_some() {
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn clear_after_original_cache(
        &mut self,
        recipes: &crate::journal::SourceQ04TransactionRecipesV1<'_>,
        clearance: crate::cache_programmes::OriginalQ04CacheClearanceLoanV1<'_, '_, '_, '_, '_>,
    ) -> Result<(), ()> {
        let prepared = (|| {
            self.require_cut(recipes.identity())?;
            if !matches!(self.commits[1], Some(Ok(_))) || self.commits[2].is_some() {
                return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
            }
            Ok(())
        })();
        self.park_failure(prepared)?;
        clearance.capture_source_clear(
            self.source,
            recipes,
            &mut self.commits[2],
            &mut self.first,
            &mut self.postcheck,
        )
    }

    pub(crate) fn connect_original_root(
        &mut self,
        invocation: &mut crate::policy_compiler::create_q04::OriginalCreateQ04InvocationV1<'_>,
        journal: &mut Journal,
        project: ProjectId,
        signer_generation: u64,
        signer: &ed25519_dalek::SigningKey,
    ) -> Result<(), ()> {
        if self.first.is_some() || self.postcheck.is_some() || self.finished {
            return Err(());
        }
        invocation.connect_existing_gen1(journal, self.source, project, signer_generation, signer)
    }

    pub(crate) fn capture_controller_preparation(
        &mut self,
        invocation: &crate::policy_compiler::create_q04::OriginalCreateQ04InvocationV1<'_>,
        journal: &mut Journal,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        cache: &mut crate::cache_programmes::OriginalQ04CacheOwnerCutV1<'_>,
        credentials: &crate::public_api_session::ControllerQ04CredentialCustodyV1,
        destination: &mut Option<
            Result<
                crate::policy_compiler::create_q04::Q04ControllerPreparationV1,
                crate::policy_compiler::create_q04::CreateQ04ErrorV1,
            >,
        >,
    ) -> Result<(), ()> {
        if destination.is_some()
            || self.first.is_some()
            || self.postcheck.is_some()
            || self.finished
        {
            return self.park_failure(Err(
                crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut,
            ));
        }
        *destination = Some(invocation.form_controller_preparation(
            journal,
            self.source,
            ledger,
            cache,
            credentials,
        ));
        let prepared = match destination.as_ref() {
            Some(Ok(prepared)) => prepared,
            // The exact original cause remains in the caller's resident Result.
            // No postcheck can consume or replace it with this negative marker.
            _ => return Err(()),
        };
        let postcheck = invocation.recheck_controller_preparation(
            journal,
            self.source,
            ledger,
            cache,
            prepared,
        );
        if let Err(cause) = postcheck {
            self.postcheck.get_or_insert(cause);
            return Err(());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recheck_controller_preparation(
        &mut self,
        invocation: &crate::policy_compiler::create_q04::OriginalCreateQ04InvocationV1<'_>,
        journal: &mut Journal,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        cache: &mut crate::cache_programmes::OriginalQ04CacheOwnerCutV1<'_>,
        prepared: &crate::policy_compiler::create_q04::Q04ControllerPreparationV1,
    ) -> Result<(), ()> {
        let checked = invocation.recheck_controller_preparation(
            journal,
            self.source,
            ledger,
            cache,
            prepared,
        );
        if let Err(cause) = checked {
            self.postcheck.get_or_insert(cause);
            return Err(());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn refresh_original_root(
        &mut self,
        invocation: &mut crate::policy_compiler::create_q04::OriginalCreateQ04InvocationV1<'_>,
        journal: &mut Journal,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        transitions: &[crate::journal::ControllerQ04TransitionV1<'_>],
        project: ProjectId,
        signer_generation: u64,
        signer: &ed25519_dalek::SigningKey,
    ) -> Result<(), ()> {
        if self.first.is_some() || self.postcheck.is_some() || self.finished {
            return Err(());
        }
        invocation.refresh_after_selfwrite(
            journal,
            self.source,
            ledger,
            transitions,
            project,
            signer_generation,
            signer,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finish_original_clearance(
        &mut self,
        invocation: &mut crate::policy_compiler::create_q04::OriginalCreateQ04InvocationV1<'_>,
        journal: &mut Journal,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        transitions: &[crate::journal::ControllerQ04TransitionV1<'_>],
        recipes: &crate::journal::SourceQ04TransactionRecipesV1<'_>,
        cache: &mut crate::cache_programmes::OriginalQ04CacheOwnerCutV1<'_>,
        cache_recipes: &crate::journal::CacheQ04TransactionRecipesV1<'_>,
    ) -> Result<(), ()> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        let prepared = (|| {
            self.require_cut(recipes.identity())?;
            if self
                .commits
                .iter()
                .any(|result| !matches!(result, Some(Ok(_))))
                || !std::ptr::eq(recipes.identity(), cache_recipes.identity())
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            self.source
                .journal
                .readback_source_q04_original_v1(recipes, 3)?;
            let result = self.commits[2]
                .as_ref()
                .and_then(|returned| returned.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            self.source.journal.require_q04_returned_commit_v1(result)?;
            recipes
                .require_named_owner(self.source)
                .map_err(CreateQ04ErrorV1::Journal)
        })();
        self.park_failure(prepared)?;
        invocation.finish_original_clearance(
            journal,
            self.source,
            ledger,
            transitions,
            recipes,
            cache,
            cache_recipes,
            recipes.identity(),
        )?;

        // The invocation just checked the same Source native suffix and final
        // current generation-one cut under the Cache guard. There is no
        // fallible operation between that check and returning this loan.
        self.finished = true;
        Ok(())
    }

    fn require_cut(
        &self,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if self.finished
            || self.first.is_some()
            || self.postcheck.is_some()
            || self.cut.as_ref() != Some(identity.bytes())
        {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        self.source.require_fixed_named_writer_v1()?;
        Ok(())
    }

    fn park_failure(
        &mut self,
        returned: Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1>,
    ) -> Result<(), ()> {
        match returned {
            Ok(()) if self.first.is_none() && self.postcheck.is_none() => Ok(()),
            Ok(()) => Err(()),
            Err(cause) => {
                self.first.get_or_insert(cause);
                Err(())
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for OriginalQ04SourceOwnerCutV1<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.first
                .get_or_insert(crate::policy_compiler::create_q04::CreateQ04ErrorV1::Unwind);
            std::process::exit(1);
        }
    }
}

impl ProtectedSourceDomainJournalOwnerV1 {
    #[cfg(test)]
    pub(crate) fn from_test_journal(journal: Journal) -> Self {
        Self { journal }
    }

    /// Opens and cold-replays the fixed shared source-domain journal.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when fixed-root protection or journal replay
    /// fails. Callers must not fall back to a generic journal opener.
    pub fn open_fixed_protected() -> Result<(Self, RecoveryReport), JournalError> {
        let (journal, report) = Journal::open_protected_at(
            Path::new(PROTECTED_SOURCE_DOMAIN_ROOT),
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            source_domain_journal_limits(),
        )?;
        Ok((Self { journal }, report))
    }

    /// Opens and cold-replays the fixed shared journal for one service UID.
    ///
    /// The fixed path remains part of the lifecycle replay-authority
    /// commitment. `expected_uid` only selects the exact filesystem owner that
    /// the protected opener accepts; callers cannot redirect durable state to
    /// another location.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] when the fixed root is absent or unsafe, its
    /// ownership differs from `expected_uid`, or bounded cold replay fails.
    pub fn open_fixed_protected_for_uid(
        expected_uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let (journal, report) = Journal::open_protected_at_for_uid(
            Path::new(PROTECTED_SOURCE_DOMAIN_ROOT),
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            source_domain_journal_limits(),
            expected_uid,
        )?;
        Ok((Self { journal }, report))
    }

    /// Opens only an existing fixed Source writer for administrative issuance.
    ///
    /// This preserves the same path, limits, UID and protected replay engine.
    /// It never initializes missing state or repairs interrupted history.
    ///
    /// # Errors
    /// Rejects missing or unsafe fixed storage, changed ownership, stale
    /// compaction, interrupted tails, corrupt replay or an unavailable lock.
    pub fn open_existing_fixed_protected_for_uid(
        expected_uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let (journal, report) = Journal::open_existing_protected_at_for_uid(
            Path::new(PROTECTED_SOURCE_DOMAIN_ROOT),
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            source_domain_journal_limits(),
            expected_uid,
        )?;
        Ok((Self { journal }, report))
    }

    // This same held writer's in-memory sequence is comparison DATA only;
    // original object/name joins remain at the actual receiving caller.
    pub(crate) const fn snapshot_sequence_v1(&self) -> u64 {
        self.journal.snapshot_sequence()
    }

    // Borrows the same held writer for observation; no mutable writer escapes.
    pub(crate) fn journal_ref_v1(&self) -> &Journal {
        &self.journal
    }

    pub(crate) fn journal(&mut self) -> &mut Journal {
        &mut self.journal
    }

    /// Freezes every source-domain writer for one exact closed Q04 proposal.
    ///
    /// This is custody, not ancestry or publication authority. The caller
    /// must already hold Controller and retain this owner through root CAS.
    ///
    /// # Errors
    ///
    /// Rejects stale, malformed, or already-held custody and failed durable
    /// acquisition or exact readback.
    pub fn acquire_closed_policy_source_hold_v1(
        &mut self,
        hold: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        self.journal.acquire_source_domain_policy_hold_v1(hold)
    }

    /// Reads retained source-domain custody under its protected writer.
    ///
    /// This observation is not a root or Cache currentness claim.
    ///
    /// # Errors
    ///
    /// Rejects unsafe or malformed protected custody.
    pub fn closed_policy_source_hold_v1(
        &self,
    ) -> Result<Option<SourceDomainPolicyHoldV1>, JournalError> {
        self.journal.source_domain_policy_hold_v1()
    }

    /// Reads the exact pending V8 Source settlement marker under this writer.
    ///
    /// The marker is nonauthorizing and remains until a future verified Root
    /// successor grant retires it; this readback never clears custody.
    ///
    /// # Errors
    ///
    /// Rejects malformed or mismatched protected Source state.
    pub fn pending_closed_policy_source_v8_settlement_v1(
        &self,
    ) -> Result<Option<aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyV8PendingSettlementV1>, JournalError> {
        self.journal.source_domain_policy_v8_pending_settlement_v1()
    }

    /// Reads the exact V8 predecessor and release under retained Source custody.
    ///
    /// The historical held row is derived only from the canonical pending
    /// marker and released row, never from current ancestry after retirement.
    ///
    /// # Errors
    ///
    /// Rejects absent or mismatched V8 release evidence.
    pub(crate) fn closed_policy_source_v8_release_pair_v1(
        &self,
    ) -> Result<(SourceDomainPolicyHoldV1, SourceDomainPolicyHoldV1), JournalError> {
        self.journal.source_domain_policy_v8_release_pair_v1()
    }

    /// Rechecks the fixed journal and lock names against this retained writer.
    pub(crate) fn require_fixed_named_writer_v1(&self) -> Result<(), JournalError> {
        self.require_named_writer_at(
            Path::new(PROTECTED_SOURCE_DOMAIN_ROOT),
            source_domain_journal_limits(),
        )
    }

    /// Returns the fixed Source directory, journal, and lock inode identities.
    ///
    /// The caller must retain this writer and compare the result to a
    /// Source-signed read-only view while the same Root challenge is active.
    /// The identities alone grant no policy or effect authority.
    ///
    /// # Errors
    ///
    /// Rejects a replaced fixed name or unhealthy protected writer.
    pub fn fixed_physical_names_v1(
        &self,
    ) -> Result<crate::journal::ProtectedJournalNamesV1, JournalError> {
        self.require_fixed_named_writer_v1()?;
        self.journal.protected_writer_physical_names_v1()
    }

    fn require_named_writer_at(
        &self,
        directory: &Path,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        let uid = self.journal.protected_owner_uid()?;
        self.journal.require_protected_named_location(
            directory,
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            uid,
            limits,
        )
    }

    #[cfg(test)]
    pub(crate) fn require_named_writer_for_test(&self) -> Result<(), JournalError> {
        self.journal.require_protected_names_current_for_test()
    }

    pub(crate) fn release_closed_policy_source_hold_after_root_readback_v1(
        &mut self,
        expected: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        self.journal
            .release_source_domain_policy_hold_after_root_readback_v1(expected)
    }

    /// Records only the Source journal's exact V8 retirement transition.
    ///
    /// A future held cross-owner caller must verify Root and Cache release
    /// before invoking this private method. This wrapper grants no release
    /// authority by itself and is not connected to public Create or Apply.
    ///
    /// # Errors
    ///
    /// Rejects stale or mismatched Source custody and failed durability.
    #[allow(dead_code)]
    pub(crate) fn retire_closed_policy_source_hold_v8(
        &mut self,
        expected: SourceDomainPolicyHoldV1,
    ) -> Result<(), JournalError> {
        self.journal.retire_source_domain_policy_hold_v8(expected)
    }

    /// Clears the Source V8 pending marker after the exact Cache settlement.
    ///
    /// The Cache proof establishes the required final-owner ordering. Root's
    /// authenticated grant and the local released row must name the same
    /// predecessor and canonical Source digest on initial clear and replay.
    ///
    /// # Errors
    ///
    /// Rejects a foreign grant, missing Cache clearance, changed Source row,
    /// unsafe fixed writer names, or failed durable marker removal.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    pub(crate) fn clear_closed_policy_source_v8_settlement_v1(
        &mut self,
        expected_released: SourceDomainPolicyHoldV1,
        grant: RootV8SettledGrantV1,
        cache_clear: CacheV8SettledClearV1,
    ) -> Result<(), JournalError> {
        if expected_released.is_held()
            || expected_released.binding() != grant.predecessor()
            || expected_released.epoch() != grant.epoch()
            || expected_released.record_digest()? != grant.source_released()
            || !cache_clear.matches_grant(grant)
        {
            return Err(JournalError::ProtectedBoundary);
        }

        self.require_fixed_named_writer_v1()?;
        self.journal
            .clear_source_domain_policy_v8_pending_settlement_v1(expected_released)?;
        self.require_fixed_named_writer_v1()?;
        Ok(())
    }
}
