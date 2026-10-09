use std::path::Path;
use std::sync::Arc;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest, Sha256};

use super::{
    CACHE_POLICY_HOLD_JOURNAL, CachePolicyHoldV1, CacheQ04TransactionRecipesV1, CommitResult,
    ControllerPolicyHoldV1, ControllerQ04TransitionV1, DeploymentHistoryObserverV1, Journal,
    JournalAuthorityInstance, JournalError, JournalLimits, JournalTransaction,
    PreflightTransactionViewV1, ProtectedAuthorityScope, ProtectedJournalAuthority,
    ProtectedJournalNamesV1, ProtectedWriterNameWitness, RecordNamespace,
    SourceQ04TransactionRecipesV1, controller_policy_hold, encode_record_fields,
    encoded_transaction_append_bytes, replay_original_observed, runtime_deployment_history,
};

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum Q04ControllerBookendPurposeV1<'recipes> {
    Original,
    HeldSigner(&'recipes [ControllerQ04TransitionV1<'recipes>]),
    Gen1Refresh(&'recipes [ControllerQ04TransitionV1<'recipes>]),
}

// These closed phases select observation only. They never select the mutable
// Cache gate, waive a pin check or authorize an own-successor authority append.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Q04CacheTerminalPhaseV1 {
    Held,
    Released,
    Cleared,
}

#[cfg(target_os = "linux")]
impl Q04CacheTerminalPhaseV1 {
    fn prefix(self) -> usize {
        match self {
            Self::Held => 1,
            Self::Released => 2,
            Self::Cleared => 3,
        }
    }
}

#[cfg(target_os = "linux")]
struct Q04OriginalCacheTargetV1 {
    instance: Arc<JournalAuthorityInstance>,
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
            Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT), name, uid, journal.native.limits(),
        )?;
        Ok(Self {
            instance: Arc::clone(&journal.authority_instance),
            sequence: journal.snapshot_sequence(),
            limits: journal.native.limits(),
            name,
            uid,
            witness: journal.protected_writer_name_witness()?,
        })
    }

    fn require(&self, journal: &Journal) -> Result<(), JournalError> {
        if !Arc::ptr_eq(&self.instance, &journal.authority_instance)
            || self.sequence != journal.snapshot_sequence()
            || self.limits != journal.native.limits()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        journal.require_protected_named_location(
            Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT), self.name, self.uid, self.limits,
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
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if authority.namespace != RecordNamespace::DesiredState
            || authority.scope != ProtectedAuthorityScope::SingleNamespace
            || self.hold.require_q04_cache_prepare_v1()? != self.prior
        {
            return Err(JournalError::ProtectedBoundary.into());
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
    pub(crate) fn identity(&self) -> &crate::policy_compiler::create_q04::Q04CutIdentityV1 {
        self.recipes.identity()
    }

    pub(crate) fn hold(&self) -> CachePolicyHoldV1 {
        self.recipes.terminal_hold(self.phase)
    }

    pub(crate) fn require_current(
        &mut self,
        state: &Journal,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if authority.namespace != RecordNamespace::DesiredState
            || authority.scope != ProtectedAuthorityScope::SingleNamespace
        {
            return Err(JournalError::ForeignAuthorityNamespace.into());
        }
        self.targets[0].require(state)?;
        self.targets[1].require(authority.journal)?;
        // Zero selections still run the sole whole native parser and complete
        // replay comparison. Cache state/authority may not append in this cut.
        state.require_q04_native_recipes_v1(&[])?;
        authority.journal.require_q04_native_recipes_v1(&[])?;
        self.recipes.require_fixed_journal(self.hold)?;
        self.recipes.require_prefix(self.hold.native.state(), self.phase.prefix())?;
        self.hold.require_q04_native_recipe_prefix_v1(
            &self.recipes.transactions()[..self.phase.prefix()], self.recipes.original_next(),
        )?;
        self.targets[0].require(state)?;
        self.targets[1].require(authority.journal)?;
        self.recipes.require_fixed_journal(self.hold)?;
        self.recipes.require_prefix(self.hold.native.state(), self.phase.prefix())?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    pub(crate) fn borrow_q04_cache_prepare_native_v1<'hold>(
        state: &Journal,
        authority: &Journal,
        hold: &'hold mut Journal,
    ) -> Result<Q04CachePrepareNativeLoanV1<'hold>, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        let root = Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT);
        let uid = hold.protected_owner_uid()?;
        if state.cache_policy_gate.as_ref().is_none_or(|(directory, owner)| {
            directory.as_path() != root || *owner != uid
        }) || authority.cache_policy_gate != state.cache_policy_gate
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let prior = hold.require_q04_cache_prepare_v1()?;
        let original_hold = Q04OriginalCacheTargetV1::capture(hold, CACHE_POLICY_HOLD_JOURNAL, uid)?;
        let targets = [
            Q04OriginalCacheTargetV1::capture(state, "state.journal", uid)?,
            Q04OriginalCacheTargetV1::capture(authority, "authority.journal", uid)?,
        ];
        Ok(Q04CachePrepareNativeLoanV1 { hold, prior, targets, original_hold })
    }

    pub(super) fn require_q04_cache_read_only_base_v1(&self, hold: &Journal) -> Result<(), JournalError> {
        let uid = hold.protected_owner_uid()?;
        hold.require_q04_cache_prepare_v1()?;
        let location = self.protected.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let fixed_target = match location.name.as_str() {
            "clock.journal" => self.cache_policy_gate.is_none(),
            "authority.journal" | "state.journal" => self.cache_policy_gate.as_ref().is_some_and(|(root, owner)| {
                root.as_path() == Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT) && *owner == uid
            }),
            _ => false,
        };
        if !fixed_target
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.require_protected_named_location(
            Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT), &location.name, uid, self.native.limits(),
        )?;
        self.require_q04_native_recipes_v1(&[])
            .map_err(|cause| JournalError::Q04RootOriginal(Box::new(cause)))?;
        hold.require_q04_native_recipes_v1(&[])
            .map_err(|cause| JournalError::Q04RootOriginal(Box::new(cause)))?;
        Ok(())
    }

    pub(crate) fn borrow_q04_cache_terminal_native_v1<'hold, 'recipes, 'cut>(
        state: &Journal,
        authority: &Journal,
        hold: &'hold mut Journal,
        recipes: &'recipes CacheQ04TransactionRecipesV1<'cut>,
        phase: Q04CacheTerminalPhaseV1,
    ) -> Result<Q04CacheTerminalNativeLoanV1<'hold, 'recipes, 'cut>, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        let root = Path::new(crate::cache_residency::PROTECTED_CACHE_ROOT);
        let uid = hold.protected_owner_uid()?;
        if state.cache_policy_gate.as_ref().is_none_or(|(directory, owner)| {
            directory.as_path() != root || *owner != uid
        }) || authority.cache_policy_gate != state.cache_policy_gate
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        recipes.require_fixed_journal(hold)?;
        recipes.require_prefix(hold.native.state(), phase.prefix())?;
        let targets = [
            Q04OriginalCacheTargetV1::capture(state, "state.journal", uid)?,
            Q04OriginalCacheTargetV1::capture(authority, "authority.journal", uid)?,
        ];
        Ok(Q04CacheTerminalNativeLoanV1 { hold, recipes, phase, targets })
    }
}

// Only validated COMMIT calls reach this observer. Matching an ID without its
// complete ordered records and original physical boundary is insufficient.
// The recipes are DATA retained by a closed Q04 owner, not commit permissions.
#[cfg(target_os = "linux")]
pub(super) struct Q04NativeRecipeAuditV1<'recipes> {
    recipes: PreflightTransactionViewV1<'recipes>,
    matched: usize,
    previous_end: u64,
    previous_next: u64,
    original_next: Option<u64>,
    bank_history: Option<crate::controller_resource_reservation::ResourceNativeHistoryV1<'recipes>>,
}

#[cfg(target_os = "linux")]
impl Q04NativeRecipeAuditV1<'_> {
    pub(super) fn observe(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), JournalError> {
        if let Some(history) = self.bank_history.as_mut() {
            history.observe(transaction, begin_sequence, commit_sequence, begin_offset, end_offset)?;
        }
        let next = commit_sequence.checked_add(1).ok_or(JournalError::SequenceExhausted)?;
        let frames = u64::try_from(transaction.records().len())
            .map_err(|_| JournalError::LimitExceeded("Q04 native record count"))?
            .checked_add(2).ok_or(JournalError::SequenceExhausted)?;
        if begin_sequence != self.previous_next
            || next.checked_sub(begin_sequence) != Some(frames)
            || begin_offset != self.previous_end
            || end_offset.checked_sub(begin_offset)
                != Some(encoded_transaction_append_bytes(transaction)?)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.previous_end = end_offset;
        self.previous_next = next;

        if let Some(original_next) = self.original_next {
            if begin_sequence < original_next {
                if next > original_next || (0..self.recipes.len()).any(|index| {
                    self.recipes.transaction(index).id() == transaction.id()
                }) {
                    return Err(JournalError::ProtectedBoundary);
                }
                return Ok(());
            }
            // A terminal readback compares the entire in-cut suffix, not a
            // selected subsequence separated by unobserved foreign appends.
            if self.matched >= self.recipes.len()
                || (self.matched == 0 && begin_sequence != original_next)
                || transaction != self.recipes.transaction(self.matched)
            {
                return Err(JournalError::ProtectedBoundary);
            }
            self.matched += 1;
            return Ok(());
        }

        if self.matched < self.recipes.len() {
            let expected = self.recipes.transaction(self.matched);
            if transaction.id() == expected.id() {
                if transaction != expected {
                    return Err(JournalError::ProtectedBoundary);
                }
                self.matched += 1;
            } else if (0..self.recipes.len()).any(|index| {
                self.recipes.transaction(index).id() == transaction.id()
            }) {
                return Err(JournalError::ProtectedBoundary);
            }
        } else if (0..self.recipes.len()).any(|index| {
            self.recipes.transaction(index).id() == transaction.id()
        }) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    pub(crate) fn require_root_q04_materialized_prefix_v1(
        &self,
        history: &crate::policy_compiler::create_q04::Q04RootAuthorityHistoryV1,
        prefix: usize,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        history.require_prefix_rows(self.native.state().iter().map(|((namespace, key), value)| {
            (*namespace, key.as_slice(), value.as_slice())
        }), prefix)?;
        Ok(())
    }

    // This observes the actual whole Controller ledger/native file under its
    // original mutable borrow. The copied tuple is equality DATA only; every
    // signer calls this again after parking its returned packet or first cause.
    pub(crate) fn q04_controller_signing_bookend_v1(
        &mut self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        transitions: Option<&[ControllerQ04TransitionV1<'_>]>,
    ) -> Result<(u64, ProtectedJournalNamesV1, Option<ControllerPolicyHoldV1>), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        let purpose = match transitions {
            None => Q04ControllerBookendPurposeV1::Original,
            Some(transitions) => Q04ControllerBookendPurposeV1::HeldSigner(transitions),
        };
        self.q04_controller_ledger_bookend_v1(ledger, purpose)
    }

    // Released Q04 history is observable for genuine gen1 refresh, not for
    // the held signer. Exact native membership and all original rows remain.
    pub(crate) fn q04_controller_refresh_bookend_v1(
        &mut self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        transitions: &[ControllerQ04TransitionV1<'_>],
    ) -> Result<(u64, ProtectedJournalNamesV1, Option<ControllerPolicyHoldV1>), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.q04_controller_ledger_bookend_v1(ledger, Q04ControllerBookendPurposeV1::Gen1Refresh(transitions))
    }

    fn q04_controller_ledger_bookend_v1(
        &mut self,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        purpose: Q04ControllerBookendPurposeV1<'_>,
    ) -> Result<(u64, ProtectedJournalNamesV1, Option<ControllerPolicyHoldV1>), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        crate::policy_compiler::validate_current_create_controller_journal_v1(self)?;
        ledger.require_original(self)?;
        match purpose {
            Q04ControllerBookendPurposeV1::Original => {
                controller_policy_hold::require_q04_signing_original(self.native.state())?;
                self.require_q04_native_recipes_v1(&[])?;
                if self.snapshot_sequence() != ledger.original_next() {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
            }
            Q04ControllerBookendPurposeV1::HeldSigner(transitions)
                | Q04ControllerBookendPurposeV1::Gen1Refresh(transitions) => {
                let prefix = if matches!(purpose, Q04ControllerBookendPurposeV1::HeldSigner(_)) {
                    controller_policy_hold::require_q04_signing_prefix(self.native.state(), transitions)?
                } else {
                    controller_policy_hold::require_q04_refresh_prefix(self.native.state(), transitions)?
                };
                if !std::ptr::eq(ledger, transitions[0].ledger()) {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
                for transition in transitions {
                    transition.require_fixed_owner(self)?;
                }
                self.require_q04_native_recipe_view_at_original_v1(
                    PreflightTransactionViewV1::ControllerQ04(&transitions[..prefix]),
                    Some(ledger.original_next()),
                )?;
                transitions[prefix - 1].require_current_readback(self)?;
            }
        }
        ledger.require_original(self)?;
        crate::policy_compiler::validate_current_create_controller_journal_v1(self)?;
        Ok((
            self.snapshot_sequence(),
            self.protected_writer_physical_names_v1()?,
            self.controller_policy_hold_v1()?,
        ))
    }

    // A pre-envelope seed uses the complete actual old native row recipe,
    // names and sequence. It excludes every Q04 future transaction/phase/head
    // and provides comparison DATA only, never a floor or writer certificate.
    pub(crate) fn q04_root_before_rows_v1(
        &self,
    ) -> Result<(u64, ProtectedJournalNamesV1, ObjectDigest), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.require_q04_native_recipes_v1(&[])?;
        self.validate_held_protected_names()?;
        let sequence = self.snapshot_sequence();
        let names = self.protected_writer_physical_names_v1()?;
        let mut digest = Sha256::new();
        digest.update(b"aos.sandbox.create-q04.root-before-rows.v1\0");
        digest.update(names.to_bytes());
        digest.update(sequence.to_be_bytes());
        for (namespace, key, value) in self.all_records() {
            digest.update(encode_record_fields(namespace, key, Some(value))?);
        }
        self.require_q04_native_recipes_v1(&[])?;
        self.validate_held_protected_names()?;
        if self.snapshot_sequence() != sequence || self.protected_writer_physical_names_v1()? != names {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        Ok((sequence, names, ObjectDigest::from_bytes(digest.finalize().into())))
    }

    /// Checks retained Q04 recipe DATA against this same original native file.
    ///
    /// This private observation issues no authority or reusable current token.
    /// Its real owning caller separately validates purpose, exact ledger,
    /// eligible suffix, other owners and the unchanged original cutoff.
    pub(crate) fn require_q04_native_recipes_v1(
        &self,
        recipes: &[JournalTransaction],
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.require_q04_native_recipe_view_v1(PreflightTransactionViewV1::Ordinary(recipes))
    }

    // Closed bank observation reuses the same native parser and complete
    // replay/name bookends. Terminal rows alone cannot prove their origins.
    pub(crate) fn require_controller_resource_history_v1(
        &self,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.require_q04_native_recipes_v1(&[])
    }

    pub(crate) fn require_controller_resource_q04_prefix_v1(
        &self,
        recipes: &[ControllerQ04TransitionV1<'_>],
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        let first = recipes.first()
            .ok_or(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut)?;
        self.require_q04_native_recipe_view_at_original_v1(
            PreflightTransactionViewV1::ControllerQ04(recipes),
            Some(first.ledger().original_next()),
        )
    }

    fn require_q04_native_recipe_view_v1(
        &self,
        recipes: PreflightTransactionViewV1<'_>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.require_q04_native_recipe_view_at_original_v1(recipes, None)
    }

    // Original NEXT is comparison DATA captured before the first logical
    // hold. This reads through the sole native parser; it does not establish
    // currentness or authorize a commit from a sequence scalar.
    pub(crate) fn require_q04_native_recipe_prefix_v1(
        &self,
        recipes: &[JournalTransaction],
        original_next: u64,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if original_next == 0 {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.require_q04_native_recipe_view_at_original_v1(
            PreflightTransactionViewV1::Ordinary(recipes), Some(original_next),
        )
    }

    pub(super) fn require_q04_native_recipe_view_at_original_v1(
        &self,
        recipes: PreflightTransactionViewV1<'_>,
        original_next: Option<u64>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        self.ensure_protected_authority()?;
        let witness = self.protected_writer_name_witness()?;
        let result = (|| {
            // Before any Q04 selfwrite there are no selected recipes yet.
            // An empty selection still audits the entire original native
            // history and compares its complete replay to this same owner.
            if recipes.len() > self.native.limits().maximum_transactions
                || (0..recipes.len()).any(|index| {
                    (0..index).any(|prior| {
                        recipes.transaction(prior).id() == recipes.transaction(index).id()
                    })
                })
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let recipe_count = recipes.len();
            let mut history = Q04NativeRecipeAuditV1 {
                recipes,
                matched: 0,
                previous_end: 0,
                previous_next: 1,
                original_next,
                bank_history: crate::controller_resource_reservation::ResourceNativeHistoryV1::new(self.native.state()),
            };
            let mut reader = runtime_deployment_history::ReadAtCursorV1::new(
                self.native.file(), witness.file.size,
            );
            let replayed = replay_original_observed(
                &mut reader, self.native.limits(), None,
                Some(DeploymentHistoryObserverV1::Q04(&mut history)),
            )?;
            if let Some(history) = history.bank_history.as_ref() {
                history.finish(&replayed.transaction_ids, self.protected_writer_physical_names_v1()?)?;
            }
            if history.matched != recipe_count
                || (recipe_count == 0 && original_next.is_some_and(|next| next != self.native.next_sequence()))
                || history.previous_end != witness.file.size
                || history.previous_next != self.native.next_sequence()
                || replayed.durable_end != witness.file.size
                || replayed.next_sequence != self.native.next_sequence()
                || replayed.committed_transactions != self.native.committed_transactions()
                || replayed.transaction_ids != *self.native.transaction_ids()
                || replayed.committed_namespaces != *self.native.committed_namespaces()
                || replayed.state != *self.native.state()
                || replayed.materialized_bytes != self.native.materialized_bytes()
                || replayed.idempotency != self.idempotency
                || !replayed.source_challenge_history.is_empty()
                || !self.source_challenge_history.is_empty()
                || replayed.source_original_replay.has_dependencies()
                || self.source_original_replay.has_dependencies()
                || replayed.source_history_compacted != self.source_history_compacted
                || replayed.q04_lower_history_present != self.q04_lower_history_present
            {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })();
        let bookend = self.validate_protected_writer_name_witness(&witness);
        match (result, bookend) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(first), final_bookend) => Err(CreateQ04ErrorV1::NativeHistory {
                first,
                final_bookend: final_bookend.err(),
            }),
            (Ok(()), Err(first)) => Err(CreateQ04ErrorV1::NativeHistory {
                first,
                final_bookend: None,
            }),
        }
    }

    pub(crate) fn readback_controller_q04_phase_v1(
        &mut self,
        transitions: &[ControllerQ04TransitionV1<'_>],
        index: usize,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        let transition = transitions.get(index).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if transitions.len() != 8 {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let readback = (|| {
            transition.ledger().require_original(self)?;
            self.require_q04_native_recipe_view_at_original_v1(
                PreflightTransactionViewV1::ControllerQ04(&transitions[..=index]),
                Some(transition.ledger().original_next()),
            )?;
            transition.require_current_readback(self)?;
            Ok(())
        })();
        if let Err(error) = readback {
            self.native.poison();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn readback_source_q04_original_v1(
        &mut self,
        recipes: &SourceQ04TransactionRecipesV1<'_>,
        committed: usize,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if committed == 0 || committed > 3 {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), committed)?;
        self.require_q04_native_recipe_prefix_v1(&recipes.transactions()[..committed], recipes.original_next())?;
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), committed)?;
        Ok(())
    }

    pub(crate) fn readback_cache_q04_original_v1(
        &self,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
        committed: usize,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if committed == 0 || committed > 3 {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), committed)?;
        self.require_q04_native_recipe_prefix_v1(&recipes.transactions()[..committed], recipes.original_next())?;
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), committed)?;
        Ok(())
    }

    pub(crate) fn require_q04_returned_commit_v1(
        &self,
        result: &CommitResult,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.validate_held_protected_names()?;
        if self.native.next_sequence() != result.commit_sequence.checked_add(1).ok_or(JournalError::SequenceExhausted)?
            || self.native.file().metadata()?.len() != result.durable_bytes
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        self.validate_held_protected_names()?;
        Ok(())
    }
}
